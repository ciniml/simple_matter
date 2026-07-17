// ESP-IDF C++17 参照実装: simple-matter C FFI シム(simple_matter コンポーネント)を
// 使った OnOff ライト。docs/design/c-ffi-shim.md §3 の 5 項目を実装する。
//
//   1. esp_wifi 接続 → IP 取得で sm_set_addrs(A/AAAA 反映)。
//   2. UDP ソケット 2 本: Matter :5540(dual-stack)と mDNS :5353(v4/v6 join)。
//   3. 単一タスクのポンプループ: select 待ち → sm_udp_rx/sm_mdns_rx →
//      while(sm_poll) → sm_take_event で LED 反映。待ちは sm_next_deadline と
//      mDNS announce の近い方(上限 1s)。ローカル操作は FreeRTOS queue で
//      同一タスクへ直列化する。
//   4. NVS を kvs_* コールバックへ配線(namespace "smatter")。
//   5. 時刻は esp_timer_get_time()/1000。RNG は esp_fill_random。
//
// 単一インスタンス・単線アクセス契約: すべての sm_* 呼び出しは matter_task から
// 行う(WiFi/IP イベントはキュー経由で matter_task に渡す)。
//
// 注意: WiFi SSID/PASS はビルドを通すためのプレースホルダ(menuconfig /
// Kconfig で上書き)。本 example のゲートはビルドまで(実機 flash は別途)。

#include "sm_wrapper.hpp"

#include "app_cmd.hpp"
#include "ble.hpp"
#include "ot_thread.hpp"

#include <cstring>

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

static const char *TAG = "onoff_cpp";

// ---- 設定(Kconfig) --------------------------------------------------------

#define SM_WIFI_SSID CONFIG_SM_WIFI_SSID
#define SM_WIFI_PASS CONFIG_SM_WIFI_PASSWORD
#define SM_LED_GPIO CONFIG_SM_LED_GPIO
#define SM_NVS_NAMESPACE "smatter"

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
  // IPv4 マルチキャスト join(IGMP)。
  ip_mreq mreq4{};
  inet_pton(AF_INET, "224.0.0.251", &mreq4.imr_multiaddr);
  mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) != 0) {
    ESP_LOGW(TAG, "IP_ADD_MEMBERSHIP (v4) failed: errno=%d (ignored)", errno);
  }
  // IPv6 マルチキャスト join(MLD): ff02::fb。
  ipv6_mreq mreq6{};
  inet_pton(AF_INET6, "ff02::fb", &mreq6.ipv6mr_multiaddr);
  mreq6.ipv6mr_interface = 0; // 既定 netif
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) != 0) {
    ESP_LOGW(TAG, "IPV6_ADD_MEMBERSHIP (v6) failed: errno=%d (ignored)", errno);
  }
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

// ---- LED -------------------------------------------------------------------

static void led_init() {
  gpio_config_t io{};
  io.pin_bit_mask = 1ULL << SM_LED_GPIO;
  io.mode = GPIO_MODE_OUTPUT;
  gpio_config(&io);
  gpio_set_level((gpio_num_t)SM_LED_GPIO, 0);
}

static void led_set(bool on) { gpio_set_level((gpio_num_t)SM_LED_GPIO, on ? 1 : 0); }

// ---- カスタムクラスタ(F4b、EP2、vendor 領域クラスタ)-----------------------
//
// docs/design/c-ffi-shim.md §8。sm_init より前に登録する。値の所有はここ(C++ 側)。
// 周期更新 Counter は sm_attr_mark_dirty で購読へ流す。

static constexpr uint16_t kCustomEp = 2;
static constexpr uint32_t kCustomCluster = 0xFFF1FC01u; // vendor 0xFFF1 の MS クラスタ
static constexpr uint32_t kCustomDeviceType = 0xFFF10055u;

static struct {
  uint16_t writable = 100;
  bool flag = false;
  uint16_t counter = 0;
} g_custom;

extern "C" uint8_t custom_read(void *, uint32_t attr_id, sm_attr_value_t *out) {
  switch (attr_id) {
  case 0x0000:
    out->type = SM_T_U16;
    out->v.u = g_custom.writable;
    return 0;
  case 0x0001:
    out->type = SM_T_BOOL;
    out->v.b = g_custom.flag;
    return 0;
  case 0x0004:
    out->type = SM_T_U16;
    out->v.u = g_custom.counter;
    return 0;
  default:
    return 0x86; // UnsupportedAttribute
  }
}

extern "C" uint8_t custom_write(void *, uint32_t attr_id, const sm_attr_value_t *val) {
  if (attr_id == 0x0000) {
    g_custom.writable = (uint16_t)val->v.u;
    return 0;
  }
  return 0x88; // UnsupportedWrite
}

extern "C" uint8_t custom_invoke(void *, uint32_t cmd_id, const sm_attr_value_t *args,
                                 size_t n_args, uint64_t) {
  if (cmd_id == 0x0000 && n_args == 2) {
    g_custom.flag = (((uint8_t)args[0].v.u) != 0);
    g_custom.writable = (uint16_t)args[1].v.u;
    return 0;
  }
  return 0x85; // InvalidCommand
}

static void register_custom() {
  static const sm_attr_def_t attrs[] = {
      {0x0000, SM_T_U16, SM_ATTR_WRITABLE},
      {0x0001, SM_T_BOOL, 0},
      {0x0004, SM_T_U16, 0},
  };
  static const sm_cmd_def_t cmds[] = {{0x0000, 0}};
  sm_cluster_def_t def;
  memset(&def, 0, sizeof(def));
  def.endpoint = kCustomEp;
  def.cluster_id = kCustomCluster;
  def.revision = 1;
  def.attrs = attrs;
  def.n_attrs = sizeof(attrs) / sizeof(attrs[0]);
  def.cmds = cmds;
  def.n_cmds = sizeof(cmds) / sizeof(cmds[0]);
  def.read = custom_read;
  def.write = custom_write;
  def.invoke = custom_invoke;
  sm_endpoint_register(kCustomEp, kCustomDeviceType, 1);
  sm_cluster_register(&def);
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
  // sm_config を組む。
  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.passcode = 20202021;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "OnOffLight";
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

  // カスタムクラスタ(EP2)は sm_init より前に登録する(F4b、§8)。
  register_custom();

  SmStack stack(cfg, now_ms());
  if (!stack.ok()) {
    ESP_LOGE(TAG, "sm_init failed: rc=%d", stack.rc());
    vTaskDelete(nullptr);
    return;
  }
  ESP_LOGI(TAG, "sm_init ok: fabrics=%u onoff=%d", stack.fabric_count(), stack.onoff_get());
  ESP_LOGI(TAG, "free heap after sm_init: %u", (unsigned)esp_get_free_heap_size());
  led_set(stack.onoff_get());

  stack.on_event([](const sm_event_t &ev) {
    ESP_LOGI(TAG, "EVENT kind=%d arg=%u", (int)ev.kind, (unsigned)ev.arg);
    switch (ev.kind) {
    case SM_EV_ONOFF_CHANGED:
      led_set(ev.arg != 0);
      break;
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
  uint64_t last_counter_ms = 0;
  bool ble_conn_active = false;
  for (;;) {
    uint64_t now = now_ms();

    // カスタム Counter(EP2/0x0004)を 2 秒ごとに更新 → 購読へ(mark_dirty)。
    if (now - last_counter_ms >= 2000) {
      last_counter_ms = now;
      g_custom.counter++;
      sm_attr_mark_dirty(kCustomEp, kCustomCluster, 0x0004);
    }

    // WiFi/IP・BLE・ローカル操作のコマンドを排出(同一タスクで sm_* を呼ぶ)。
    Cmd c;
    while (g_cmd_queue && xQueueReceive(g_cmd_queue, &c, 0) == pdTRUE) {
      switch (c.kind) {
      case CmdKind::IpV4:
        stack.set_addrs(c.v4, nullptr);
#if CONFIG_SM_ENABLE_BLE
        sm_wifi_status(true, now); // 遅延 ConnectNetworkResponse を Success で確定。
#endif
        break;
      case CmdKind::IpV6:
        stack.set_addrs(nullptr, c.v6);
        break;
      case CmdKind::LocalToggle:
        stack.onoff_set(!stack.onoff_get(), now);
        led_set(stack.onoff_get());
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

  g_cmd_queue = xQueueCreate(8, sizeof(Cmd));

  led_init();
#if CONFIG_SM_NETWORK_THREAD
  // esp_openthread(15.4 radio + lwIP 統合 netif + mainloop タスク)。WiFi は使わない。
  // role 変化は g_cmd_queue 経由で matter_task へ。
  sm_ot_init(g_cmd_queue);
#else
  wifi_init_sta();
#endif

#if CONFIG_SM_ENABLE_BLE
  // NimBLE を起動(GATT 0xFFF6 / 広告)。BLE イベントは g_cmd_queue 経由で matter_task へ。
  sm_ble_init(g_cmd_queue);
#endif

  // sm_* を単線で扱う pump タスク(sans-IO 契約: 全 API を同一タスクから)。
  // スタック 128KB 必須級(NanoC6 実機で確定): sm_init はスタック構築 → static へ
  // move のため一時コピーが多段に積まれ 80KB でも Stack protection fault、さらに
  // コミッショニング中の P-256 署名チェーンも深い(ベアメタル実測 ~70KB)。
  // 8KB だと WiFi 開始直後に即リセットループになる。
  xTaskCreate(&matter_task, "matter", 128 * 1024, nullptr, 5, nullptr);
}
