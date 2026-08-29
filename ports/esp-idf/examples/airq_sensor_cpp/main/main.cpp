// ESP-IDF C++17 参照実装: simple-matter C FFI シム(simple_matter コンポーネント)を
// 使った AirQ センサ(Air Quality Sensor)。docs/design/airq-idf-port.md W2。
//
// onoff_light_cpp(WiFi + BLE 構成)を土台に、データモデルを composition blob で
// 3 EP(Air Quality / Temperature / Humidity センサ)へ置き換え、SEN55 + SCD40 の
// 実センサ値を周期的に sm_attr_set_value で注入する。
//
//   1. esp_wifi 接続 → IP 取得で sm_set_addrs(A/AAAA 反映)。**起動時自動接続は
//      しない**(BLE コミッショニングで投入された資格情報のみ join、NVS 保存・再 join)。
//   2. UDP ソケット 2 本: Matter :5540(dual-stack)と mDNS :5353(v4/v6 join)。
//   3. 単一タスクのポンプループ: select 待ち → sm_udp_rx/sm_mdns_rx → while(sm_poll)。
//      周期センサ読み(SEN55 10s / SCD40 30s)→ sm_attr_set_value + sm_attr_mark_dirty。
//   4. NVS を kvs_* コールバックへ配線(namespace "smatter")。
//   5. 時刻は esp_timer_get_time()/1000。RNG は esp_fill_random。
//
// 単一インスタンス・単線アクセス契約: すべての sm_* 呼び出しは matter_task から
// 行う(WiFi/IP・BLE イベントはキュー経由で matter_task に渡す)。

#include "sm_wrapper.hpp"

#include "app_cmd.hpp"
#include "ble.hpp"
#include "sensors.hpp"

#include <cstring>
#include <vector>

#include "sdkconfig.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "airq_cpp";

// ---- 設定(Kconfig) --------------------------------------------------------

#define SM_WIFI_SSID CONFIG_SM_WIFI_SSID
#define SM_WIFI_PASS CONFIG_SM_WIFI_PASSWORD
#define SM_NVS_NAMESPACE "smatter"

#ifdef CONFIG_SM_FACTORY_PARTITION
#define SM_FACTORY_PARTITION CONFIG_SM_FACTORY_PARTITION
#else
#define SM_FACTORY_PARTITION "nvs_factory"
#endif

// センサ配線(airq-port.md §2、Rust 版と同じ)。
#define SM_I2C_SDA CONFIG_SM_I2C_SDA_GPIO
#define SM_I2C_SCL CONFIG_SM_I2C_SCL_GPIO
#define SM_SEN55_POWER CONFIG_SM_SEN55_POWER_GPIO
#define SM_POWER_HOLD CONFIG_SM_POWER_HOLD_GPIO

static constexpr uint16_t kMatterPort = 5540;
static constexpr uint16_t kMdnsPort = 5353;

// センサエンドポイント / クラスタ(composition blob と一致させる)。
static constexpr uint16_t kEpAirQuality = 1;
static constexpr uint16_t kEpTemp = 2;
static constexpr uint16_t kEpHum = 3;
static constexpr uint32_t kClAirQuality = 0x005B;
static constexpr uint32_t kClCo2 = 0x040D;
static constexpr uint32_t kClPm1 = 0x042C;
static constexpr uint32_t kClPm25 = 0x042A;
static constexpr uint32_t kClPm10 = 0x042D;
static constexpr uint32_t kClTemp = 0x0402;
static constexpr uint32_t kClHum = 0x0405;
static constexpr uint32_t kAttrMeasured = 0x0000;

// ---- 時刻 ------------------------------------------------------------------

static uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- KVS コールバック(NVS namespace "smatter") ----------------------------

extern "C" int32_t kvs_get(void *, const char *key, uint8_t *buf, size_t cap) {
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
    return -1;
  }
  size_t len = 0;
  esp_err_t err = nvs_get_blob(h, key, nullptr, &len);
  if (err != ESP_OK) {
    nvs_close(h);
    return -1;
  }
  if (len <= cap) {
    size_t rd = cap;
    if (nvs_get_blob(h, key, buf, &rd) != ESP_OK) {
      nvs_close(h);
      return -1;
    }
    len = rd;
  }
  nvs_close(h);
  return (int32_t)len;
}

extern "C" int32_t kvs_set(void *, const char *key, const uint8_t *val, size_t len) {
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
    return -1;
  }
  esp_err_t err = nvs_set_blob(h, key, val, len);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return (err == ESP_OK) ? 0 : -1;
}

extern "C" int32_t kvs_delete(void *, const char *key) {
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
    return -1;
  }
  esp_err_t err = nvs_erase_key(h, key);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) ? 0 : -1;
}

// ---- RNG コールバック ------------------------------------------------------

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) { esp_fill_random(buf, len); }

// ---- WiFi 資格情報の永続化(BLE プロビジョン後の再起動で自動 join) -----------

#if CONFIG_SM_ENABLE_BLE
static void save_wifi_creds(const uint8_t *ssid, size_t sl, const uint8_t *pass, size_t pl) {
  nvs_handle_t h;
  if (nvs_open("smwifi", NVS_READWRITE, &h) != ESP_OK) {
    return;
  }
  nvs_set_blob(h, "ssid", ssid, sl);
  nvs_set_blob(h, "pass", pass, pl);
  nvs_commit(h);
  nvs_close(h);
}

static bool load_wifi_creds(uint8_t *ssid, size_t *sl, uint8_t *pass, size_t *pl) {
  nvs_handle_t h;
  if (nvs_open("smwifi", NVS_READONLY, &h) != ESP_OK) {
    return false;
  }
  size_t s = *sl, p = *pl;
  esp_err_t e1 = nvs_get_blob(h, "ssid", ssid, &s);
  esp_err_t e2 = nvs_get_blob(h, "pass", pass, &p);
  nvs_close(h);
  if (e1 == ESP_OK && e2 == ESP_OK) {
    *sl = s;
    *pl = p;
    return true;
  }
  return false;
}
#endif

// ---- 工場出荷 factory データ(esp-matter-mfg-tool 互換) --------------------
// onoff_light_cpp と同一。base64 salt/verifier、DAC/PAI/key blob を chip-factory から読む。

static int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  uint32_t acc = 0;
  int nbits = 0;
  size_t w = 0;
  for (size_t i = 0; i < in_len; i++) {
    char c = in[i];
    if (c == '=' || c == '\0') break;
    int v = val(c);
    if (v < 0) return -1;
    acc = (acc << 6) | (uint32_t)v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      if (w >= out_cap) return -1;
      out[w++] = (uint8_t)(acc >> nbits);
    }
  }
  return (int)w;
}

struct FactoryBuffers {
  std::vector<uint8_t> dac, pai, key;
  uint8_t salt[32];
  size_t salt_len = 0;
  uint8_t w0l[97];
};

[[maybe_unused]] static bool try_load_factory(sm_config_t &cfg, FactoryBuffers &fb) {
  const char *part = SM_FACTORY_PARTITION;
  esp_err_t err = nvs_flash_init_partition(part);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "factory: partition '%s' not available (%s); using dev creds", part,
             esp_err_to_name(err));
    return false;
  }
  nvs_handle_t h;
  if (nvs_open_from_partition(part, "chip-factory", NVS_READONLY, &h) != ESP_OK) {
    ESP_LOGW(TAG, "factory: chip-factory namespace not found; using dev creds");
    return false;
  }

  bool ok = true;
  uint32_t u32 = 0;
  if (nvs_get_u32(h, "discriminator", &u32) == ESP_OK) cfg.discriminator = (uint16_t)(u32 & 0x0FFF);
  uint32_t iters = 0;
  if (nvs_get_u32(h, "iteration-count", &iters) != ESP_OK) ok = false;
  if (nvs_get_u32(h, "vendor-id", &u32) == ESP_OK) cfg.vendor_id = (uint16_t)u32;
  if (nvs_get_u32(h, "product-id", &u32) == ESP_OK) cfg.product_id = (uint16_t)u32;

  char b64[256];
  size_t bl = sizeof(b64);
  if (nvs_get_str(h, "salt", b64, &bl) == ESP_OK) {
    int n = b64_decode(b64, bl, fb.salt, sizeof(fb.salt));
    if (n > 0) fb.salt_len = (size_t)n;
    else ok = false;
  } else ok = false;
  bl = sizeof(b64);
  if (nvs_get_str(h, "verifier", b64, &bl) == ESP_OK) {
    int n = b64_decode(b64, bl, fb.w0l, sizeof(fb.w0l));
    if (n != 97) ok = false;
  } else ok = false;

  auto read_blob = [&](const char *key, std::vector<uint8_t> &dst) -> bool {
    size_t n = 0;
    if (nvs_get_blob(h, key, nullptr, &n) != ESP_OK || n == 0) return false;
    dst.resize(n);
    return nvs_get_blob(h, key, dst.data(), &n) == ESP_OK;
  };
  if (!read_blob("dac-cert", fb.dac)) ok = false;
  if (!read_blob("pai-cert", fb.pai)) ok = false;
  if (!read_blob("dac-key", fb.key) || fb.key.size() != 32) ok = false;
  nvs_close(h);

  if (!ok) {
    ESP_LOGW(TAG, "factory: incomplete chip-factory data; using dev creds");
    return false;
  }

  cfg.verifier_iterations = iters;
  cfg.verifier_salt = fb.salt;
  cfg.verifier_salt_len = fb.salt_len;
  cfg.verifier_w0_l = fb.w0l;
  cfg.dac_der = fb.dac.data();
  cfg.dac_der_len = fb.dac.size();
  cfg.pai_der = fb.pai.data();
  cfg.pai_der_len = fb.pai.size();
  cfg.cd_der = nullptr;
  cfg.cd_der_len = 0;
  cfg.dac_privkey = fb.key.data();
  ESP_LOGI(TAG, "factory: loaded VID=0x%04x PID=0x%04x discriminator=%u (DAC %u B, PAI %u B)",
           cfg.vendor_id, cfg.product_id, cfg.discriminator, (unsigned)fb.dac.size(),
           (unsigned)fb.pai.size());
  return true;
}

// ---- composition blob(Matter TLV 手組み) ---------------------------------
//
// docs/design/generic-firmware.md §9.1 / compose.rs のスキーマ:
//   anonymous list of struct { ctx0: ep u16, ctx1: device-type u32, ctx2: rev u8,
//                              ctx3: array of cluster-id u32 }
// 3 EP を宣言する(W1 の air_quality_composition_values_and_descriptor と同一構成):
//   EP1 = Air Quality Sensor(0x002C): Identify + AirQuality + CO2 + PM1 + PM2.5 + PM10
//   EP2 = Temperature Sensor(0x0302): Temperature
//   EP3 = Humidity Sensor(0x0307): RelativeHumidity

namespace tlv {
// Matter TLV element type(下位 5bit)。tlv.rs の T_* と一致。
static constexpr uint8_t T_U8 = 0x04, T_U16 = 0x05, T_U32 = 0x06;
static constexpr uint8_t T_STRUCT = 0x15, T_ARRAY = 0x16, T_LIST = 0x17, T_END = 0x18;
static constexpr uint8_t TAG_CTX = 0x20; // context-specific(1 オクテットタグ)

struct Buf {
  uint8_t *p;
  size_t cap;
  size_t len = 0;
  bool put(uint8_t v) {
    if (len >= cap) return false;
    p[len++] = v;
    return true;
  }
};

// コンテナ開始。ctx<0 は匿名タグ。
static void start(Buf &b, uint8_t type, int ctx) {
  if (ctx < 0) {
    b.put(type);
  } else {
    b.put(TAG_CTX | type);
    b.put((uint8_t)ctx);
  }
}
static void end(Buf &b) { b.put(T_END); }

// 符号なし整数を最小幅で書く(tlv.rs write_u* と同じ最小幅方針)。
static void write_uint(Buf &b, uint64_t v, int ctx) {
  uint8_t type;
  int nbytes;
  if (v <= 0xFF) {
    type = T_U8;
    nbytes = 1;
  } else if (v <= 0xFFFF) {
    type = T_U16;
    nbytes = 2;
  } else {
    type = T_U32;
    nbytes = 4;
  }
  if (ctx < 0) {
    b.put(type);
  } else {
    b.put(TAG_CTX | type);
    b.put((uint8_t)ctx);
  }
  for (int i = 0; i < nbytes; i++) {
    b.put((uint8_t)(v >> (8 * i))); // little-endian
  }
}
} // namespace tlv

// 3 EP の composition blob を buf へ構築し、長さを返す。
static size_t build_airq_composition(uint8_t *buf, size_t cap) {
  using namespace tlv;
  Buf b{buf, cap};
  start(b, T_LIST, -1); // anonymous list

  // EP1 = Air Quality Sensor(0x002C)。
  start(b, T_STRUCT, -1);
  write_uint(b, kEpAirQuality, 0);
  write_uint(b, 0x002C, 1); // device-type
  write_uint(b, 1, 2);      // dt-rev
  start(b, T_ARRAY, 3);
  for (uint32_t id : {0x0003u, 0x005Bu, 0x040Du, 0x042Cu, 0x042Au, 0x042Du}) {
    write_uint(b, id, -1);
  }
  end(b); // array
  end(b); // struct

  // EP2 = Temperature Sensor(0x0302)。
  start(b, T_STRUCT, -1);
  write_uint(b, kEpTemp, 0);
  write_uint(b, 0x0302, 1);
  write_uint(b, 2, 2);
  start(b, T_ARRAY, 3);
  write_uint(b, 0x0402, -1);
  end(b);
  end(b);

  // EP3 = Humidity Sensor(0x0307)。
  start(b, T_STRUCT, -1);
  write_uint(b, kEpHum, 0);
  write_uint(b, 0x0307, 1);
  write_uint(b, 2, 2);
  start(b, T_ARRAY, 3);
  write_uint(b, 0x0405, -1);
  end(b);
  end(b);

  end(b); // list
  return b.len;
}

// ---- センサ値注入ヘルパ ----------------------------------------------------

static void set_f32(uint16_t ep, uint32_t cl, float v) {
  sm_attr_value_t val;
  memset(&val, 0, sizeof(val));
  val.type = SM_T_F32;
  val.v.f = v;
  sm_attr_set_value(ep, cl, kAttrMeasured, &val);
  sm_attr_mark_dirty(ep, cl, kAttrMeasured);
}

static void set_u8(uint16_t ep, uint32_t cl, uint8_t v) {
  sm_attr_value_t val;
  memset(&val, 0, sizeof(val));
  val.type = SM_T_U8;
  val.v.u = v;
  sm_attr_set_value(ep, cl, kAttrMeasured, &val);
  sm_attr_mark_dirty(ep, cl, kAttrMeasured);
}

// Temp: i16 ×0.01℃。Hum: u16 ×0.01%(compose.rs の CL_TEMP/CL_HUM set 経路に合わせる)。
static void set_temp_c(float c) {
  sm_attr_value_t val;
  memset(&val, 0, sizeof(val));
  val.type = SM_T_I16;
  val.v.i = (int16_t)(c * 100.0f);
  sm_attr_set_value(kEpTemp, kClTemp, kAttrMeasured, &val);
  sm_attr_mark_dirty(kEpTemp, kClTemp, kAttrMeasured);
}
static void set_hum_pct(float pct) {
  sm_attr_value_t val;
  memset(&val, 0, sizeof(val));
  val.type = SM_T_U16;
  val.v.u = (uint16_t)(pct * 100.0f);
  sm_attr_set_value(kEpHum, kClHum, kAttrMeasured, &val);
  sm_attr_mark_dirty(kEpHum, kClHum, kAttrMeasured);
}

// 現行スナップショットを全 EP のクラスタへ反映する。
static void inject_snapshot() {
  const SensorSnapshot &s = sensors_snapshot();
  if (s.has_co2) set_f32(kEpAirQuality, kClCo2, s.co2_ppm);
  if (s.has_pm1) set_f32(kEpAirQuality, kClPm1, s.pm1);
  if (s.has_pm25) set_f32(kEpAirQuality, kClPm25, s.pm25);
  if (s.has_pm10) set_f32(kEpAirQuality, kClPm10, s.pm10);
  set_u8(kEpAirQuality, kClAirQuality, sensors_air_quality(s));
  if (s.has_temp) set_temp_c(s.temp_c);
  if (s.has_rh) set_hum_pct(s.rh);
}

// ---- sockaddr <-> sm_addr_t ------------------------------------------------

static void smaddr_to_sockaddr(const sm_addr_t &a, sockaddr_storage &ss, socklen_t &len) {
  memset(&ss, 0, sizeof(ss));
  if (a.is_v6) {
    auto *s6 = (sockaddr_in6 *)&ss;
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(a.port);
    memcpy(&s6->sin6_addr, a.ip, 16);
    s6->sin6_scope_id = a.scope_id;
    len = sizeof(sockaddr_in6);
  } else {
    auto *s4 = (sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(a.port);
    memcpy(&s4->sin_addr, a.ip, 4);
    len = sizeof(sockaddr_in);
  }
}

static sm_addr_t sockaddr_to_smaddr(const sockaddr_storage &ss) {
  sm_addr_t a;
  memset(&a, 0, sizeof(a));
  if (ss.ss_family == AF_INET6) {
    auto *s6 = (const sockaddr_in6 *)&ss;
    a.is_v6 = true;
    memcpy(a.ip, &s6->sin6_addr, 16);
    a.port = ntohs(s6->sin6_port);
    a.scope_id = s6->sin6_scope_id;
  } else {
    auto *s4 = (const sockaddr_in *)&ss;
    a.is_v6 = false;
    memcpy(a.ip, &s4->sin_addr, 4);
    a.port = ntohs(s4->sin_port);
  }
  return a;
}

// ---- ソケット --------------------------------------------------------------

static int open_matter_udp() {
  int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    ESP_LOGE(TAG, "socket(matter): errno=%d", errno);
    return -1;
  }
  int off = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_addr = in6addr_any;
  a.sin6_port = htons(kMatterPort);
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    ESP_LOGE(TAG, "bind(:5540): errno=%d", errno);
    close(fd);
    return -1;
  }
  return fd;
}

static int open_mdns_socket() {
  int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    ESP_LOGE(TAG, "socket(mdns): errno=%d", errno);
    return -1;
  }
  int off = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_addr = in6addr_any;
  a.sin6_port = htons(kMdnsPort);
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    ESP_LOGE(TAG, "bind(:5353): errno=%d", errno);
    close(fd);
    return -1;
  }
  ip_mreq mreq4{};
  inet_pton(AF_INET, "224.0.0.251", &mreq4.imr_multiaddr);
  mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) != 0) {
    ESP_LOGW(TAG, "IP_ADD_MEMBERSHIP (v4) failed: errno=%d (ignored)", errno);
  }
  ipv6_mreq mreq6{};
  inet_pton(AF_INET6, "ff02::fb", &mreq6.ipv6mr_multiaddr);
  mreq6.ipv6mr_interface = 0;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) != 0) {
    ESP_LOGW(TAG, "IPV6_ADD_MEMBERSHIP (v6) failed: errno=%d (ignored)", errno);
  }
  return fd;
}

// ---- タスク間メッセージ ----------------------------------------------------

static QueueHandle_t g_cmd_queue = nullptr;

// ---- WiFi ------------------------------------------------------------------

static esp_netif_t *g_sta_netif = nullptr;
static volatile bool g_wifi_connected = false;
static volatile bool g_wifi_joining = false;

static void on_wifi_event(void *, esp_event_base_t base, int32_t id, void *) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
#if CONFIG_SM_ENABLE_BLE
    // BLE 有効時は起動時 join をしない。ConnectNetwork(sm_take_wifi_request)駆動。
#else
    esp_wifi_connect();
#endif
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    if (g_wifi_connected) {
      esp_wifi_connect();
    } else if (g_wifi_joining) {
      g_wifi_joining = false;
#if CONFIG_SM_ENABLE_BLE
      Cmd c{};
      c.kind = CmdKind::WifiFailed;
      if (g_cmd_queue) {
        xQueueSend(g_cmd_queue, &c, 0);
      }
#endif
    } else {
#if !CONFIG_SM_ENABLE_BLE
      ESP_LOGW(TAG, "wifi disconnected, retrying");
      esp_wifi_connect();
#endif
    }
  }
}

static void on_got_ip4(void *, esp_event_base_t, int32_t, void *event_data) {
  auto *ev = (ip_event_got_ip_t *)event_data;
  g_wifi_connected = true;
  g_wifi_joining = false;
  Cmd c{};
  c.kind = CmdKind::IpV4;
  uint32_t ip = ev->ip_info.ip.addr;
  memcpy(c.v4, &ip, 4);
  ESP_LOGI(TAG, "got IPv4: " IPSTR, IP2STR(&ev->ip_info.ip));
  if (g_cmd_queue) {
    xQueueSend(g_cmd_queue, &c, 0);
  }
  esp_netif_create_ip6_linklocal(g_sta_netif);
}

static void on_got_ip6(void *, esp_event_base_t, int32_t, void *event_data) {
  auto *ev = (ip_event_got_ip6_t *)event_data;
  Cmd c{};
  c.kind = CmdKind::IpV6;
  memcpy(c.v6, ev->ip6_info.ip.addr, 16);
  ESP_LOGI(TAG, "got IPv6: " IPV6STR, IPV62STR(ev->ip6_info.ip));
  if (g_cmd_queue) {
    xQueueSend(g_cmd_queue, &c, 0);
  }
}

static void wifi_init_sta() {
  g_sta_netif = esp_netif_create_default_wifi_sta();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi_event, nullptr, nullptr));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ip4, nullptr, nullptr));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_GOT_IP6, &on_got_ip6, nullptr, nullptr));

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
#if !CONFIG_SM_ENABLE_BLE
  wifi_config_t wc{};
  strncpy((char *)wc.sta.ssid, SM_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
  strncpy((char *)wc.sta.password, SM_WIFI_PASS, sizeof(wc.sta.password) - 1);
  wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
#endif
  ESP_ERROR_CHECK(esp_wifi_start());
  // 省電力を無効化(mDNS QU 応答 / CASE UDP の取りこぼし防止。BLE coex で顕著)。
  esp_wifi_set_ps(WIFI_PS_NONE);
  ESP_LOGI(TAG, "wifi station started (ps=none)");
}

#if CONFIG_SM_ENABLE_BLE
static void wifi_join(const uint8_t *ssid, size_t ssid_len, const uint8_t *pass, size_t pass_len) {
  wifi_config_t wc{};
  size_t sn = ssid_len < sizeof(wc.sta.ssid) ? ssid_len : sizeof(wc.sta.ssid) - 1;
  memcpy(wc.sta.ssid, ssid, sn);
  size_t pn = pass_len < sizeof(wc.sta.password) ? pass_len : sizeof(wc.sta.password) - 1;
  memcpy(wc.sta.password, pass, pn);
  wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  esp_wifi_set_config(WIFI_IF_STA, &wc);
  g_wifi_joining = true;
  esp_err_t err = esp_wifi_connect();
  ESP_LOGI(TAG, "wifi join requested (ssid=%.*s) err=%d", (int)sn, (const char *)wc.sta.ssid, err);
}
#endif

// 既接続 WiFi を NetworkCommissioning へ反映する(airq-port.md §9)。got_ip 毎に冪等。
static void report_wifi_link_and_seed() {
  wifi_ap_record_t ap{};
  if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
    ESP_LOGI(TAG, "wifi link: ch=%u rssi=%d", ap.primary, ap.rssi);
    sm_wifi_set_link_info(ap.bssid, ap.primary, ap.rssi);
  }
  wifi_config_t wc{};
  if (esp_wifi_get_config(WIFI_IF_STA, &wc) == ESP_OK) {
    size_t sl = strnlen((const char *)wc.sta.ssid, sizeof(wc.sta.ssid));
    size_t pl = strnlen((const char *)wc.sta.password, sizeof(wc.sta.password));
    if (sl > 0) {
      sm_wifi_seed_network(wc.sta.ssid, sl, wc.sta.password, pl);
    }
  }
}

// ---- pump タスク -----------------------------------------------------------

static void matter_task(void *) {
  // 開発用 dev SPAKE2+ verifier(passcode 20202021 相当)。デバイスは passcode を保持しない。
  static const uint8_t kDevSalt[16] = {'S', 'P', 'A', 'K', 'E', '2', 'P', ' ',
                                       'K', 'e', 'y', ' ', 'S', 'a', 'l', 't'};
  static const uint8_t kDevVerifierW0L[97] = {
      0x7d, 0x04, 0x77, 0x6b, 0xb4, 0x69, 0xc4, 0x94, 0x92, 0x28, 0x30, 0x14,
      0x4f, 0x3f, 0xa2, 0xf1, 0x9c, 0xfd, 0x82, 0xc0, 0x4d, 0x10, 0x8d, 0x8b,
      0xa6, 0x35, 0x3f, 0xdd, 0x92, 0xc0, 0x1f, 0x93, 0x04, 0x51, 0x1b, 0x6c,
      0x47, 0x65, 0xba, 0xb1, 0x47, 0x94, 0x9d, 0xd9, 0x42, 0xc4, 0x3b, 0x3d,
      0x8d, 0xc6, 0x32, 0x30, 0x89, 0xca, 0x31, 0x89, 0xd9, 0xe4, 0xa5, 0x63,
      0x6e, 0x16, 0xd8, 0x2f, 0x1a, 0xef, 0x72, 0x8b, 0x0d, 0x90, 0x2c, 0x1a,
      0x9b, 0x0f, 0x7e, 0x96, 0x52, 0xab, 0x7f, 0x65, 0x78, 0x61, 0xb6, 0xbb,
      0xac, 0xd6, 0xbf, 0xdf, 0x04, 0xf8, 0x07, 0x09, 0x24, 0x8b, 0x83, 0xde,
      0xc7,
  };

  // composition blob を構築する(sm_init が参照する。sm_init 完了まで生存させる)。
  static uint8_t compose_blob[256];
  size_t compose_len = build_airq_composition(compose_blob, sizeof(compose_blob));

  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3300; // AirQ 用(onoff の 2560 と別。同一環境の混信回避)
  cfg.passcode = 0;
  cfg.verifier_iterations = 2000;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.verifier_w0_l = kDevVerifierW0L;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "AirQSensor";
  esp_read_mac(cfg.mac, ESP_MAC_WIFI_STA);
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.kvs_ctx = nullptr;
  cfg.rng_fill = rng_fill;
  cfg.rng_ctx = nullptr;
  cfg.network = SM_NET_WIFI;
  cfg.composition = compose_blob;
  cfg.composition_len = compose_len;

  FactoryBuffers fb;
  (void)fb;
#if CONFIG_SM_FACTORY_DATA
  if (try_load_factory(cfg, fb)) {
    ESP_LOGI(TAG, "using factory data credentials");
  } else {
    ESP_LOGI(TAG, "using dev credentials (no factory data)");
  }
#endif

  SmStack stack(cfg, now_ms());
  if (!stack.ok()) {
    ESP_LOGE(TAG, "sm_init failed: rc=%d (composition_len=%u)", stack.rc(), (unsigned)compose_len);
    vTaskDelete(nullptr);
    return;
  }
  ESP_LOGI(TAG, "sm_init ok: fabrics=%u compose=%uB", stack.fabric_count(), (unsigned)compose_len);
  ESP_LOGI(TAG, "free heap after sm_init: %u", (unsigned)esp_get_free_heap_size());

  stack.on_event([](const sm_event_t &ev) {
    ESP_LOGI(TAG, "EVENT kind=%d arg=%u", (int)ev.kind, (unsigned)ev.arg);
    switch (ev.kind) {
#if CONFIG_SM_ENABLE_BLE
    case SM_EV_BLE_ADV_CHANGED: {
      uint8_t adv[31];
      size_t n = sm_ble_adv_data(adv, sizeof(adv));
      sm_ble_set_adv(adv, n);
      break;
    }
    case SM_EV_WIFI_CONNECT_REQUEST: {
      uint8_t ssid[33];
      uint8_t pass[65];
      size_t plen = 0;
      size_t sn = sm_take_wifi_request(ssid, sizeof(ssid), pass, sizeof(pass), &plen);
      if (sn > 0) {
        wifi_join(ssid, sn, pass, plen);
        save_wifi_creds(ssid, sn, pass, plen);
      }
      break;
    }
#endif
    default:
      break;
    }
  });

#if CONFIG_SM_ENABLE_BLE
  {
    uint8_t adv[31];
    size_t n = sm_ble_adv_data(adv, sizeof(adv));
    sm_ble_set_adv(adv, n);
  }
  // コミッショニング済み(fabric 復元)なら保存済み WiFi 資格情報で自動 join。
  if (stack.fabric_count() > 0) {
    uint8_t ssid[33];
    uint8_t pass[65];
    size_t sl = sizeof(ssid), pl = sizeof(pass);
    if (load_wifi_creds(ssid, &sl, pass, &pl)) {
      ESP_LOGI(TAG, "fabric restored; auto-joining saved WiFi (%.*s)", (int)sl, (const char *)ssid);
      wifi_join(ssid, sl, pass, pl);
    }
  }
#endif

  // センサ初期化(I2C + SEN55/SCD40)。失敗しても Matter は動く(値は None)。
  sensors_init(SM_I2C_SDA, SM_I2C_SCL, SM_SEN55_POWER, SM_POWER_HOLD);

  int udp_fd = open_matter_udp();
  int mdns_fd = open_mdns_socket();
  if (udp_fd < 0 || mdns_fd < 0) {
    ESP_LOGE(TAG, "socket open failed");
    vTaskDelete(nullptr);
    return;
  }

  auto make_sender = [](int fd) {
    return [fd](const uint8_t *buf, size_t len, const sm_addr_t &dst) {
      sockaddr_storage ss;
      socklen_t sl;
      smaddr_to_sockaddr(dst, ss, sl);
      sendto(fd, buf, len, 0, (sockaddr *)&ss, sl);
    };
  };
  SmStack::Sender udp_send = make_sender(udp_fd);
  SmStack::Sender mdns_send = make_sender(mdns_fd);

  static uint8_t rx[2048];
  bool ble_conn_active = false;
  for (;;) {
    uint64_t now = now_ms();

    // 周期センサ読み → 値注入(スナップショット更新時のみ)。
    if (sensors_poll(now)) {
      inject_snapshot();
    }

    Cmd c;
    while (g_cmd_queue && xQueueReceive(g_cmd_queue, &c, 0) == pdTRUE) {
      switch (c.kind) {
      case CmdKind::IpV4:
        stack.set_addrs(c.v4, nullptr);
        report_wifi_link_and_seed();
#if CONFIG_SM_ENABLE_BLE
        sm_wifi_status(true, now);
#endif
        break;
      case CmdKind::IpV6:
        stack.set_addrs(nullptr, c.v6);
        break;
#if CONFIG_SM_ENABLE_BLE
      case CmdKind::BleConnected:
        sm_ble_event(SM_BLE_CONNECTED, c.mtu, nullptr, 0, now);
        ble_conn_active = true;
        break;
      case CmdKind::BleDisconnected:
        sm_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now);
        ble_conn_active = false;
        break;
      case CmdKind::BleC1Write:
        sm_ble_event(SM_BLE_C1_WRITE, 0, c.frag, c.frag_len, now);
        break;
      case CmdKind::BleC2Subscribed:
        sm_ble_event(SM_BLE_C2_SUBSCRIBED, 0, nullptr, 0, now);
        break;
      case CmdKind::WifiFailed:
        sm_wifi_status(false, now);
        break;
#endif
      default:
        break;
      }
    }

    uint64_t cap_ms = ble_conn_active ? 20 : 1000;
    uint64_t dl = stack.next_deadline(now);
    struct timeval tv;
    if (dl == SM_NO_DEADLINE) {
      tv.tv_sec = cap_ms / 1000;
      tv.tv_usec = (cap_ms % 1000) * 1000;
    } else {
      uint64_t wait = (dl > now) ? (dl - now) : 0;
      if (wait > cap_ms) {
        wait = cap_ms;
      }
      tv.tv_sec = wait / 1000;
      tv.tv_usec = (wait % 1000) * 1000;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp_fd, &rfds);
    int maxfd = udp_fd;
    FD_SET(mdns_fd, &rfds);
    if (mdns_fd > maxfd) {
      maxfd = mdns_fd;
    }
    int r = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
    now = now_ms();

    if (r > 0 && FD_ISSET(udp_fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(udp_fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        stack.udp_rx(rx, (size_t)n, sa, now, udp_send);
      }
    }
    if (r > 0 && FD_ISSET(mdns_fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(mdns_fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        stack.mdns_rx(rx, (size_t)n, sa, mdns_send);
      }
    }

    stack.pump(now, udp_send);

    {
      static uint64_t s_last_pool_log = 0;
      if (now - s_last_pool_log >= 30000) {
        s_last_pool_log = now;
        sm_pool_stats_t st = {};
        sm_pool_stats(&st);
        ESP_LOGI(TAG, "pools: ex=%u/%u sess=%u/%u hs=%u/%u tx=%u/%u heap=%lu", st.exchanges,
                 st.exchanges_cap, st.sessions, st.sessions_cap, st.handshakes, st.handshakes_cap,
                 st.tx_bufs, st.tx_bufs_cap, (unsigned long)esp_get_free_heap_size());
      }
    }
#if CONFIG_SM_ENABLE_BLE
    {
      static uint8_t frag[256];
      size_t fn;
      while ((fn = sm_ble_poll(now, frag, sizeof(frag))) > 0) {
        if (!sm_ble_indicate(frag, fn)) {
          break;
        }
      }
    }
#endif
    stack.mdns_poll(now, mdns_send);
  }
}

// ---- app_main --------------------------------------------------------------

extern "C" void app_main() {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
  }
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  g_cmd_queue = xQueueCreate(8, sizeof(Cmd));

  wifi_init_sta();

#if CONFIG_SM_ENABLE_BLE
  sm_ble_init(g_cmd_queue);
#endif

  // sm_* を単線で扱う pump タスク(sans-IO 契約)。スタック 128KB 必須級
  // (sm_init のスタック構築 + コミッショニング中の P-256 署名チェーンが深い)。
  xTaskCreate(&matter_task, "matter", 128 * 1024, nullptr, 5, nullptr);
}
