// generic_matter_cpp — 設定駆動の汎用 Matter ファームウェア(Phase B = G1 + G2)。
// docs/design/generic-firmware.md §9.2。ベースは onoff_light_cpp(§9.2「ベース」)。
//
// onoff_light_cpp との違いは 3 点だけで、Matter の配線(WiFi/BLE/Thread、UDP/mDNS、
// KVS、128KB スタック pump タスク)は同一:
//
//   A. 起動時に NVS namespace "smgen" の blob(`comp` = composition TLV §9.1 /
//      `bind` = binding TLV §9.2)を読み、`sm_config_t.composition` に渡して合成する。
//      どちらも無ければ既定構成(EP1 = OnOff light + gpio_out)で起動する。
//   B. `sm_config_t.on_cluster_change` を HAL バインディング層(bindings.cpp)へ配線し、
//      OnOff → gpio_out/ledc、LevelControl → ledc duty を dispatch する。入力系
//      (gpio_in / i2c_sht30)は pump ループの `bindings_poll` で `sm_attr_set_value` へ push。
//   C. esp_console(USB-Serial-JTAG)で `cfg-comp` / `cfg-bind` / `cfg-show` /
//      `cfg-clear` / `restart`(cfg_store.cpp)。設定変更は再起動で反映する。
//
// 単一インスタンス・単線アクセス契約: すべての sm_* 呼び出しは matter_task から
// 行う(WiFi/IP/BLE イベントはキュー経由、コンソールタスクは NVS しか触らない)。
//
// 注意: WiFi SSID/PASS はビルドを通すためのプレースホルダ(menuconfig /
// sdkconfig.local で上書き)。本 example のゲートはビルドまで(実機 flash は別途)。

#include "sm_wrapper.hpp"

#include "app_cmd.hpp"
#include "bind_tlv.hpp"
#include "bindings.hpp"
#include "ble.hpp"
#include "cfg_store.hpp"
#include "ot_thread.hpp"
#include "script_host.hpp"
#include "script_store.hpp"

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

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "generic_cpp";

// ---- 設定(Kconfig) --------------------------------------------------------

#define SM_WIFI_SSID CONFIG_SM_WIFI_SSID
#define SM_WIFI_PASS CONFIG_SM_WIFI_PASSWORD
// 既定バインディング(NVS に `bind` が無いとき)の gpio_out ピン。
#define SM_DEFAULT_GPIO CONFIG_SM_DEFAULT_GPIO
// Matter コア(fabric/ACL/resumption)の KVS。設定 blob の "smgen" とは別 namespace。
#define SM_NVS_NAMESPACE "smatter"

// 工場出荷 factory データパーティションのラベル(未定義時は既定 "nvs_factory")。
#ifdef CONFIG_SM_FACTORY_PARTITION
#define SM_FACTORY_PARTITION CONFIG_SM_FACTORY_PARTITION
#else
#define SM_FACTORY_PARTITION "nvs_factory"
#endif

static constexpr uint16_t kMatterPort = 5540;
static constexpr uint16_t kMdnsPort = 5353;

// ---- 時刻 ------------------------------------------------------------------

static uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- KVS コールバック(NVS namespace "smatter") ----------------------------
//
// コアのキーは 4 文字の NUL 終端文字列(fabm/fab0..fab9/aclt/grpt/rsmp)で、
// NVS のキー長上限(15)に収まる。値は blob。

extern "C" int32_t kvs_get(void *, const char *key, uint8_t *buf, size_t cap) {
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
    return -1;
  }
  size_t len = 0;
  esp_err_t err = nvs_get_blob(h, key, nullptr, &len); // 実長取得
  if (err != ESP_OK) {
    nvs_close(h);
    return -1; // 無し
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
  return (int32_t)len; // cap 不足でも実長を返す(呼び出し側が NoSpace 検出)
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
  // 既に無いキーの削除は成功扱い(冪等)。
  return (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) ? 0 : -1;
}

// ---- RNG コールバック ------------------------------------------------------

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) { esp_fill_random(buf, len); }

// ---- WiFi 資格情報の永続化(BLE プロビジョン後の再起動で自動 join) -----------
//
// BLE 有効時は起動時 join を止め ConnectNetwork 駆動にするが、コミッショニング済み
// (fabric 復元)デバイスは再起動後も運用 mDNS/CASE のため WiFi に居る必要がある。
// コアの NetworkCommissioningWifi は資格情報を RAM にしか持たないため、C++ 側で
// sm_take_wifi_request の値を NVS に保存し、起動時 fabric>0 なら復元して join する
// (e5-light.rs と同じ方式)。
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

// ---- Thread dataset の永続化(BLE プロビジョン後の再起動で自動 attach) ----------
//
// WiFi 資格情報と同じ流儀(§10.1)。sm_take_thread_dataset で得た dataset TLV を NVS に
// 保存し、起動時 fabric>0 なら復元して sm_ot_apply_dataset で attach する。
#if CONFIG_SM_NETWORK_THREAD
static void save_thread_dataset(const uint8_t *tlv, size_t len) {
  nvs_handle_t h;
  if (nvs_open("smthr", NVS_READWRITE, &h) != ESP_OK) {
    return;
  }
  nvs_set_blob(h, "ds", tlv, len);
  nvs_commit(h);
  nvs_close(h);
}

static bool load_thread_dataset(uint8_t *tlv, size_t *len) {
  nvs_handle_t h;
  if (nvs_open("smthr", NVS_READONLY, &h) != ESP_OK) {
    return false;
  }
  size_t n = *len;
  esp_err_t e = nvs_get_blob(h, "ds", tlv, &n);
  nvs_close(h);
  if (e == ESP_OK) {
    *len = n;
    return true;
  }
  return false;
}
#endif

// ---- 工場出荷 factory データ(esp-matter-mfg-tool 互換) --------------------
//
// esp-matter-mfg-tool 生成の factory NVS パーティション(namespace "chip-factory")を
// IDF 標準 nvs API で読み、sm_config_t に DAC/PAI/DAC 鍵・SPAKE2+ verifier・
// discriminator・VID/PID を供給する(docs/design/factory-data.md §5)。
//
// - salt / verifier は **base64 文字列**(mfg-tool の格納形式)なのでデコードして生バイトに戻す。
// - dac-cert / pai-cert / dac-key は blob。CD は factory に無いのが一般的なので、
//   cfg.cd_der は NULL のままにして shim 側の埋め込み dev CD を使う。
// - パーティション未 flash / 読み取り失敗時は false を返し、呼び出し側は dev 定数を使う。
//
// バッファ(out_* / dac/pai/key)は sm_init まで生存する呼び出し側所有。

// 標準 base64 デコード(パディング対応)。out に書いた長さを返す。失敗時は -1。
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

// factory パーティションから cfg を埋める。成功で true(cfg を上書き)。
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
  // discriminator / iteration-count / vendor-id / product-id。
  if (nvs_get_u32(h, "discriminator", &u32) == ESP_OK) cfg.discriminator = (uint16_t)(u32 & 0x0FFF);
  uint32_t iters = 0;
  if (nvs_get_u32(h, "iteration-count", &iters) != ESP_OK) ok = false;
  if (nvs_get_u32(h, "vendor-id", &u32) == ESP_OK) cfg.vendor_id = (uint16_t)u32;
  if (nvs_get_u32(h, "product-id", &u32) == ESP_OK) cfg.product_id = (uint16_t)u32;

  // salt / verifier は base64 文字列。
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

  // dac-cert / pai-cert / dac-key(blob)。
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

  // cfg に供給(verifier + DAC。CD は shim の埋め込み dev CD を使う = cd_der NULL)。
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
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)); // dual-stack
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

// mDNS のマルチキャスト join(224.0.0.251 / ff02::fb)。
//
// STA netif に IP が付く「前」に join すると IGMP/MLD が無効のまま残り、リブート後
// (fabric 復元 → 自動 WiFi join)の運用 mDNS クエリを一切受信できない(実機 P6 で
// 発覚。初回コミッショニングのセッションはコミッショニング中の announce で解決が
// 成立してしまうため潜在化する)。got IPv4 のタイミングで drop → 再 join する。
static void join_mdns_groups(int fd) {
  ip_mreq mreq4{};
  inet_pton(AF_INET, "224.0.0.251", &mreq4.imr_multiaddr);
  mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
  setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq4, sizeof(mreq4)); // best effort
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) != 0) {
    ESP_LOGW(TAG, "IP_ADD_MEMBERSHIP (v4) failed: errno=%d (ignored)", errno);
  }
  ipv6_mreq mreq6{};
  inet_pton(AF_INET6, "ff02::fb", &mreq6.ipv6mr_multiaddr);
  mreq6.ipv6mr_interface = 0; // 既定 netif
  setsockopt(fd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq6, sizeof(mreq6)); // best effort
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) != 0) {
    ESP_LOGW(TAG, "IPV6_ADD_MEMBERSHIP (v6) failed: errno=%d (ignored)", errno);
  }
}

// mDNS ソケット: :5353 を dual-stack で bind し 224.0.0.251 / ff02::fb に join。
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
  // マルチキャスト join(IP 取得後に IpV4 イベントで再 join する。join_mdns_groups 参照)。
  join_mdns_groups(fd);
  return fd;
}

// ---- タスク間メッセージ(app_cmd.hpp)--------------------------------------

static QueueHandle_t g_cmd_queue = nullptr;

// ---- WiFi ------------------------------------------------------------------

static esp_netif_t *g_sta_netif = nullptr;
// WiFi 状態(STA_DISCONNECTED の扱いを分岐する)。
static volatile bool g_wifi_connected = false; // 一度でも got_ip したか
static volatile bool g_wifi_joining = false;   // esp_wifi_connect 発行〜結果待ち

static void on_wifi_event(void *, esp_event_base_t base, int32_t id, void *) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
#if CONFIG_SM_ENABLE_BLE
    // BLE 有効時は起動時 join をしない。ConnectNetwork(sm_take_wifi_request)駆動。
#else
    esp_wifi_connect(); // 従来: 固定 SSID を起動時に join(F2 経路)。
#endif
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    if (g_wifi_connected) {
      // 運用中の切断: 再接続を試みる。
      esp_wifi_connect();
    } else if (g_wifi_joining) {
      // プロビジョン中の join 失敗 → sm へ報告(コアがリトライ契機にする)。
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
  uint32_t ip = ev->ip_info.ip.addr; // network byte order (lwIP)
  memcpy(c.v4, &ip, 4);
  ESP_LOGI(TAG, "got IPv4: " IPSTR, IP2STR(&ev->ip_info.ip));
  if (g_cmd_queue) {
    xQueueSend(g_cmd_queue, &c, 0);
  }
  // link-local IPv6 も要求しておく(取得は GOT_IP6 で通知)。
  esp_netif_create_ip6_linklocal(g_sta_netif);
}

static void on_got_ip6(void *, esp_event_base_t, int32_t, void *event_data) {
  auto *ev = (ip_event_got_ip6_t *)event_data;
  Cmd c{};
  c.kind = CmdKind::IpV6;
  // esp_ip6_addr_t.addr は 4 x u32(network order の 32bit ワード)。
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
  // 従来(F2)経路: 固定 SSID を設定して起動時に join する。
  wifi_config_t wc{};
  strncpy((char *)wc.sta.ssid, SM_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
  strncpy((char *)wc.sta.password, SM_WIFI_PASS, sizeof(wc.sta.password) - 1);
  wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
#endif
  ESP_ERROR_CHECK(esp_wifi_start());
  // 省電力(modem-sleep)を無効化する。有効だと STA が DTIM 間欠受信になり、mDNS の
  // ユニキャスト QU 応答や CASE の UDP が取りこぼされ operational 解決に失敗しやすい
  // (BLE coex 併用で顕著)。運用トランスポート = UDP なので常時受信にする。
  esp_wifi_set_ps(WIFI_PS_NONE);
  ESP_LOGI(TAG, "wifi station started (ps=none)");
}

#if CONFIG_SM_ENABLE_BLE
// ConnectNetwork(sm_take_wifi_request)で得た SSID/pass を設定して join を開始する。
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

// ---- 設定 blob(composition / binding)の読み出し ----------------------------
//
// NVS namespace "smgen"(cfg_store.cpp)から起動時に 1 度だけ読む。無ければ既定構成:
//   comp = EP1(device type 0x0100 = On/Off Light、rev 2)に Identify/Groups/OnOff
//   bind = EP1 の OnOff を gpio_out(pin = CONFIG_SM_DEFAULT_GPIO、invert=false)へ
//
// 既定 composition は scripts/smgen-tlv.py の例 ① と**同一のバイト列**(README 参照)。
// バイト列を直書きしているのは、TLV エンコーダをファーム側に持たないため。

static const uint8_t kDefaultComposition[] = {
    0x17,                                           // anonymous list
    0x15,                                           //   struct(endpoint)
    0x25, 0x00, 0x01, 0x00,                         //     0: ep = 1 (u16)
    0x26, 0x01, 0x00, 0x01, 0x00, 0x00,             //     1: device-type = 0x0100 (u32)
    0x24, 0x02, 0x02,                               //     2: device-type-rev = 2 (u8)
    0x36, 0x03,                                     //     3: cluster array
    0x06, 0x03, 0x00, 0x00, 0x00,                   //        Identify (0x0003)
    0x06, 0x04, 0x00, 0x00, 0x00,                   //        Groups   (0x0004)
    0x06, 0x06, 0x00, 0x00, 0x00,                   //        OnOff    (0x0006)
    0x18,                                           //     end(array)
    0x18,                                           //   end(struct)
    0x18,                                           // end(list)
};

// 設定 blob の保持(sm_init 後も composition バッファは触らないが、静的に持っておく)。
static uint8_t g_comp_blob[smgen::kMaxBlob];
static size_t g_comp_len = 0;
static uint8_t g_bind_blob[smgen::kMaxBlob];
static smgen::BindingTable g_bindings;

// NVS から composition を読む(無ければ既定 blob を使う)。
static void load_composition() {
  g_comp_len = smgen::cfg_load("comp", g_comp_blob, sizeof(g_comp_blob));
  if (g_comp_len == 0) {
    memcpy(g_comp_blob, kDefaultComposition, sizeof(kDefaultComposition));
    g_comp_len = sizeof(kDefaultComposition);
    ESP_LOGI(TAG, "composition: default (EP1 = OnOff light, %u B)", (unsigned)g_comp_len);
  } else {
    ESP_LOGI(TAG, "composition: from NVS smgen/comp (%u B)", (unsigned)g_comp_len);
  }
}

// NVS から binding 表を読む(無ければ既定 = OnOff → gpio_out)。
static void load_bindings() {
  const size_t n = smgen::cfg_load("bind", g_bind_blob, sizeof(g_bind_blob));
  if (n > 0) {
    const int rc = smgen::parse_bindings(g_bind_blob, n, g_bindings);
    if (rc == smgen::BIND_OK) {
      ESP_LOGI(TAG, "bindings: from NVS smgen/bind (%u B, %u entries)", (unsigned)n,
               (unsigned)g_bindings.n);
      return;
    }
    ESP_LOGE(TAG, "bindings: NVS blob invalid (rc=%d); falling back to default", rc);
  }
  g_bindings = smgen::BindingTable{};
  smgen::Binding &b = g_bindings.items[0];
  b.ep = 1;
  b.cluster = smgen::kClOnOff;
  b.drv = smgen::DRV_GPIO_OUT;
  b.p[0] = (uint64_t)SM_DEFAULT_GPIO; // pin
  b.has[0] = true;
  b.p[1] = 0; // invert
  b.has[1] = true;
  g_bindings.n = 1;
  ESP_LOGI(TAG, "bindings: default (EP1 OnOff -> gpio_out pin %d)", (int)SM_DEFAULT_GPIO);
}

// ---- on_cluster_change(§9.1)-> HAL バインディング dispatch ------------------
//
// IM write / コマンドで合成クラスタの値が変わると shim が呼ぶ(pump タスク内、同期)。
// `sm_attr_set_value` 由来(= センサ push)では発火しないのでループしない。

extern "C" void on_cluster_change(void *, uint16_t ep, uint32_t cluster, uint32_t attr,
                                  const sm_attr_value_t *value) {
  ESP_LOGI(TAG, "change ep=%u cluster=0x%04x attr=0x%04x", ep, (unsigned)cluster, (unsigned)attr);
  smgen::bindings_on_change(ep, cluster, attr, value);
  // スクリプト(§9.3): on_attr_write フックへ通知する。HAL の dispatch より後に呼ぶので
  // 「ハードウェアに反映済みの値」をスクリプトが読める(戻り値による拒否は観測のみ)。
  smgen::script_notify_attr_write(ep, cluster, attr);
}


// ---- SRP 登録(Thread 運用広告)-------------------------------------------
//
// fabric 確定後、運用インスタンス名 <compressedFabricId>-<nodeId>(shim が生成)で
// _matter._tcp を SRP 登録する(§10.1)。fresh コミッション(SM_EV_COMMISSIONED)と
// 再起動後の attach(ThreadRole)の双方から呼ぶ。二重登録は ot_thread 側で抑止。
#if CONFIG_SM_NETWORK_THREAD
static void maybe_register_srp() {
  if (sm_fabric_count() == 0) {
    return; // fabric 未確定。
  }
  char inst[40];
  size_t n = sm_operational_instance_name((uint8_t *)inst, sizeof(inst));
  if (n == 0) {
    return; // インスタンス名がまだ得られない。
  }
  sm_ot_srp_register(inst);
}
#endif

// ---- pump タスク -----------------------------------------------------------

static void matter_task(void *) {
  // 開発用 dev SPAKE2+ verifier(passcode 20202021 相当)。デバイスは passcode を保持せず
  // verifier だけを受け取る(Matter セキュリティ要件)。工場では passcode ごとに
  //   smctl pase-verifier 20202021 --salt 5350414b453250204b65792053616c74 --iterations 2000
  // で生成した w0‖L を書き込む。
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

  // sm_config を組む。
  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  // passcode はデバイスに置かない(verifier 指定時は無視される)。
  cfg.passcode = 0;
  cfg.verifier_iterations = 2000;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.verifier_w0_l = kDevVerifierW0L;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "GenericMatter";
  esp_read_mac(cfg.mac, ESP_MAC_WIFI_STA);
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.kvs_ctx = nullptr;
  cfg.rng_fill = rng_fill;
  cfg.rng_ctx = nullptr;
  // プリセット NetworkCommissioning の種別(§10.1)。ble 無効ビルドは種別によらず
  // Ethernet にフォールバックする(shim 側。後方互換)。
#if CONFIG_SM_NETWORK_THREAD
  cfg.network = SM_NET_THREAD;
#else
  cfg.network = SM_NET_WIFI;
#endif

  // 工場出荷 factory データを有効化していれば、chip-factory パーティションから
  // DAC/verifier 等を読んで上書きする(未 flash / 失敗時は上の dev 定数のまま)。
  // buffers は sm_init まで生存させる(この関数スコープ)。
  FactoryBuffers fb;
  (void)fb;
#if CONFIG_SM_FACTORY_DATA
  if (try_load_factory(cfg, fb)) {
    ESP_LOGI(TAG, "using factory data credentials");
  } else {
    ESP_LOGI(TAG, "using dev credentials (no factory data)");
  }
#endif

  // 設定 blob(§9.2 A): composition を sm_init に渡し、binding 表を作る。
  load_composition();
  load_bindings();
  cfg.composition = g_comp_blob;
  cfg.composition_len = g_comp_len;
  cfg.on_cluster_change = on_cluster_change;
  cfg.cluster_change_ctx = nullptr;

  // ScriptStore(§9.4): vendor クラスタ 0xFFF1FC01 を CustomCluster(F4b)で登録する。
  // **sm_init より前**でなければならない(登録はステージング方式)。
#if CONFIG_SM_SCRIPTSTORE_ENABLE
  smgen::script_store_init((uint16_t)CONFIG_SM_SCRIPTSTORE_EP);
#endif

  SmStack stack(cfg, now_ms());
  if (!stack.ok()) {
    // -7 = composition TLV 不正、-8 = 容量超過/未対応クラスタ(§9.1)。既定構成へ
    // 落として起動し直す(壊れた blob で永久に立ち上がらないのを避ける)。
    ESP_LOGE(TAG, "sm_init failed: rc=%d (composition %u B)", stack.rc(), (unsigned)g_comp_len);
    ESP_LOGE(TAG, "use 'cfg-clear' + 'restart' on the console to boot the default composition");
    vTaskDelete(nullptr);
    return;
  }
  ESP_LOGI(TAG, "sm_init ok: fabrics=%u", stack.fabric_count());
  ESP_LOGI(TAG, "free heap after sm_init: %u", (unsigned)esp_get_free_heap_size());

  // HAL バインディング層を初期化し、合成クラスタの現在値をハードウェアへ反映する(§9.2 B)。
  smgen::bindings_init(g_bindings);
  smgen::bindings_log();
  smgen::bindings_apply_initial();

  // スクリプト VM(§9.3): smscript パーティションの active slot をロードして on_boot。
  // スクリプトが無ければ何もしない(従来どおり動く)。
  smgen::script_init();
  smgen::script_log_status();
  smgen::script_store_log_status();

  stack.on_event([](const sm_event_t &ev) {
    ESP_LOGI(TAG, "EVENT kind=%d arg=%u", (int)ev.kind, (unsigned)ev.arg);
    switch (ev.kind) {
#if CONFIG_SM_ENABLE_BLE
    case SM_EV_BLE_ADV_CHANGED: {
      // 広告内容が変わった → 再取得して NimBLE に反映(n==0 は広告停止)。
      uint8_t adv[31];
      size_t n = sm_ble_adv_data(adv, sizeof(adv));
      sm_ble_set_adv(adv, n);
      break;
    }
    case SM_EV_WIFI_CONNECT_REQUEST: {
      // ConnectNetwork 受理 → 資格情報を取り出して esp_wifi で join。
      uint8_t ssid[33];
      uint8_t pass[65];
      size_t plen = 0;
      size_t sn = sm_take_wifi_request(ssid, sizeof(ssid), pass, sizeof(pass), &plen);
      if (sn > 0) {
        wifi_join(ssid, sn, pass, plen);
        save_wifi_creds(ssid, sn, pass, plen); // 再起動後の自動 join 用に永続化。
      }
      break;
    }
#endif
#if CONFIG_SM_NETWORK_THREAD
    case SM_EV_THREAD_ATTACH_REQUEST: {
      // ConnectNetwork 受理 → dataset TLV を取り出して esp_openthread へ投入・attach 開始。
      uint8_t ds[256];
      size_t n = sm_take_thread_dataset(ds, sizeof(ds));
      if (n > 0) {
        sm_ot_apply_dataset(ds, n);
        save_thread_dataset(ds, n); // 再起動後の自動 attach 用に永続化。
      }
      break;
    }
    case SM_EV_COMMISSIONED:
      // fabric 確定 → SRP 登録(運用発見。attach 済みなら即、未 attach でも OT が queue する)。
      maybe_register_srp();
      break;
#endif
    default:
      break;
    }
  });

#if CONFIG_SM_ENABLE_BLE
  // 起動時の広告ブートストラップ(初期 SM_EV_BLE_ADV_CHANGED は抑止されているため)。
  {
    uint8_t adv[31];
    size_t n = sm_ble_adv_data(adv, sizeof(adv));
    sm_ble_set_adv(adv, n);
  }
  // コミッショニング済み(fabric 復元)なら、保存済み WiFi 資格情報で自動 join する
  // (再起動後も運用 mDNS / CASE over UDP に到達できるように)。
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

#if CONFIG_SM_NETWORK_THREAD
  // コミッショニング済みなら保存済み dataset で自動 attach(再起動後の運用復帰)。
  if (stack.fabric_count() > 0) {
    uint8_t ds[256];
    size_t n = sizeof(ds);
    if (load_thread_dataset(ds, &n)) {
      ESP_LOGI(TAG, "fabric restored; auto-attaching saved Thread dataset (%u B)", (unsigned)n);
      sm_ot_apply_dataset(ds, n);
    }
  }
#endif

  int udp_fd = open_matter_udp();
#if CONFIG_SM_NETWORK_THREAD
  // Thread は SRP(OTBR advertising proxy)で運用発見するため mDNS ソケットを開かない
  // (§10.1)。OT netif は lwIP に統合されるので UDP :5540 はそのまま使える。
  int mdns_fd = -1;
  bool socket_ok = (udp_fd >= 0);
#else
  int mdns_fd = open_mdns_socket();
  bool socket_ok = (udp_fd >= 0 && mdns_fd >= 0);
#endif
  if (!socket_ok) {
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

    // 入力系ドライバ(gpio_in ポーリング + デバウンス、i2c_sht30 計測)。値の push は
    // sm_attr_set_value 経由なので on_cluster_change は鳴らない(§9.1)。
    smgen::bindings_poll(now);
    // スクリプトタイマ(timer_after / timer_every)の満了 → on_timer フック。
    smgen::script_poll(now);
    // ScriptStore の Commit で保留した VM 再ロード(invoke ハンドラの外で実行する。§9.4)。
    smgen::script_store_poll();

    // WiFi/IP・BLE・ローカル操作のコマンドを排出(同一タスクで sm_* を呼ぶ)。
    Cmd c;
    while (g_cmd_queue && xQueueReceive(g_cmd_queue, &c, 0) == pdTRUE) {
      switch (c.kind) {
      case CmdKind::IpV4:
        stack.set_addrs(c.v4, nullptr);
        if (mdns_fd >= 0) {
          join_mdns_groups(mdns_fd); // netif up 後の再 join(リブート経路の必須処置)
        }
#if CONFIG_SM_ENABLE_BLE
        sm_wifi_status(true, now); // 遅延 ConnectNetworkResponse を Success で確定。
#endif
        break;
      case CmdKind::IpV6:
        stack.set_addrs(nullptr, c.v6);
        break;
      case CmdKind::LocalToggle:
        // ローカル操作(物理ボタン等)。合成モードでは最小 EP の OnOff が対象。
        // 反映は on_cluster_change ではなくここで直接(アプリ発の変化なので)。
        stack.onoff_set(!stack.onoff_get(), now);
        smgen::bindings_apply_initial();
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
        sm_wifi_status(false, now); // コアが残リトライで再要求する(SM_EV_WIFI_CONNECT_REQUEST)。
        // 自動 join(コミッショニング済みで保存資格情報から join)している場合、AP の
        // 一過性拒否(auth→init 0x600 を実機で観測)で 1 回失敗すると誰も再試行しない
        // まま沈黙する(P6)。3 秒後に再 join を仕掛ける。
        {
          esp_timer_handle_t t = nullptr;
          const esp_timer_create_args_t targs = {
              .callback = [](void *) { esp_wifi_connect(); },
              .arg = nullptr,
              .dispatch_method = ESP_TIMER_TASK,
              .name = "smgen_rejoin",
              .skip_unhandled_events = false,
          };
          if (esp_timer_create(&targs, &t) == ESP_OK) {
            ESP_LOGW(TAG, "wifi join failed; retrying in 3s");
            g_wifi_joining = true;
            esp_timer_start_once(t, 3000 * 1000);
          }
        }
        break;
#endif
#if CONFIG_SM_NETWORK_THREAD
      case CmdKind::ThreadRole:
        // OT role 変化 → 遅延 ConnectNetworkResponse を確定 + attach 済みなら SRP 登録。
        sm_thread_status(c.thread_attached, now);
        if (c.thread_attached) {
          maybe_register_srp();
        }
        break;
#endif
      default:
        // BLE 無効ビルドでは Ble*/WifiFailed は生成されない(-Werror=switch 対策)。
        break;
      }
    }

    // 待ち時間 = sm_next_deadline と mDNS announce の近い方。BLE 接続中は queue イベントへの
    // 追従のため上限を短く(select は queue で起きないので 20ms 周期で拾う)。
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
    if (mdns_fd >= 0) {
      FD_SET(mdns_fd, &rfds);
      if (mdns_fd > maxfd) {
        maxfd = mdns_fd;
      }
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
    if (mdns_fd >= 0 && r > 0 && FD_ISSET(mdns_fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(mdns_fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        stack.mdns_rx(rx, (size_t)n, sa, mdns_send);
      }
    }

    // 時間駆動の送出・イベント・mDNS announce。
    stack.pump(now, udp_send);
#if CONFIG_SM_ENABLE_BLE
    // BLE 宛の下りフラグメント(handshake resp / データ / 遅延 ConnectNetworkResponse /
    // keep-alive ACK)を C2 indication で直列排出する(indicate 完了まで待つ)。
    {
      static uint8_t frag[256];
      size_t fn;
      while ((fn = sm_ble_poll(now, frag, sizeof(frag))) > 0) {
        if (!sm_ble_indicate(frag, fn)) {
          break; // リンク断等: 打ち切り(切断イベントで BTP はリセットされる)。
        }
      }
    }
#endif
    if (mdns_fd >= 0) {
      stack.mdns_poll(now, mdns_send);
    }
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

  // スクリプト VM のロード(線形メモリ 64KB + 実行スレッド 12KB はヒープから)。
  // WiFi ドライバ init の**前**に行う(後だと断片化で 64KB が取れない)。逆に
  // スクリプト側を太らせすぎると esp_wifi_init が ESP_ERR_NO_MEM で落ちるので、
  // 実行スレッドは 12KB・WiFi バッファは sdkconfig.defaults.esp32c6 で削っている
  // (P6 の実測バランス)。on_boot は pump 側の script_init が実行スレッド経由で呼ぶ。
  smgen::script_preload();

  g_cmd_queue = xQueueCreate(8, sizeof(Cmd));

  // 設定コンソール(USB-Serial-JTAG)。NVS しか触らないので matter_task と独立に動く。
  smgen::console_start();

#if CONFIG_SM_NETWORK_THREAD
  // esp_openthread(15.4 radio + lwIP 統合 netif + mainloop タスク)。WiFi は使わない。
  // role 変化は g_cmd_queue 経由で matter_task へ。
  sm_ot_init(g_cmd_queue);
#else
  wifi_init_sta();
#endif

#if CONFIG_SM_ENABLE_BLE
  // NimBLE を起動(GATT 0xFFF6 / 広告)。BLE イベントは g_cmd_queue 経由で matter_task へ。
  //
  // ただし**コミッショニング済み(保存済み WiFi 資格情報あり)なら起動しない**:
  // commissionable 広告は不要で、NimBLE の常駐 RAM(数十 KB)が WASM プール
  // (SM_SCRIPT_POOL_KB、遅延ヒープ確保)を押し出してスクリプトが載らなくなる
  // (C6 実機で確定: BLE 常駐時の定常 free ≈30KB < 96KB プール)。factory reset
  // (nvs 消去)で資格情報が消えれば次回起動から再び BLE 広告する。
  {
    uint8_t ssid[33];
    uint8_t pass[65];
    size_t sl = sizeof(ssid), pl = sizeof(pass);
    if (load_wifi_creds(ssid, &sl, pass, &pl)) {
      ESP_LOGI(TAG, "commissioned (saved WiFi creds); skipping BLE to free RAM for scripts");
    } else {
      sm_ble_init(g_cmd_queue);
    }
  }
#endif


  // sm_* を単線で扱う pump タスク(sans-IO 契約: 全 API を同一タスクから)。
  // スタック 128KB 必須級(NanoC6 実機で確定): sm_init はスタック構築 → static へ
  // move のため一時コピーが多段に積まれ 80KB でも Stack protection fault、さらに
  // コミッショニング中の P-256 署名チェーンも深い(ベアメタル実測 ~70KB)。
  // 8KB だと WiFi 開始直後に即リセットループになる。
  //
  // スタックは**静的確保**(P6): ヒープから 128KB を取ると、スクリプト VM の
  // 線形メモリ(64KB、WAMR が os_mmap = システムヒープから取る)と連続ブロックを
  // 取り合い、確保順のどちらかが必ず負ける。静的にすればヒープの大口需要は
  // 線形メモリだけになる。
  static StaticTask_t s_matter_tcb;
  alignas(8) static StackType_t s_matter_stack[128 * 1024 / sizeof(StackType_t)];
  xTaskCreateStatic(&matter_task, "matter", sizeof(s_matter_stack) / sizeof(StackType_t), nullptr,
                    5, s_matter_stack, &s_matter_tcb);
}
