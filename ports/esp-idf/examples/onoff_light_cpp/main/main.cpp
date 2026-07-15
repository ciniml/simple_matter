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

#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
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

// ---- タスク間メッセージ(WiFi/IP イベント → matter_task) -------------------

enum class CmdKind { IpV4, IpV6, LocalToggle };
struct Cmd {
  CmdKind kind;
  uint8_t v4[4];
  uint8_t v6[16];
};

static QueueHandle_t g_cmd_queue = nullptr;

// ---- WiFi ------------------------------------------------------------------

static esp_netif_t *g_sta_netif = nullptr;

static void on_wifi_event(void *, esp_event_base_t base, int32_t id, void *) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    ESP_LOGW(TAG, "wifi disconnected, retrying");
    esp_wifi_connect();
  }
}

static void on_got_ip4(void *, esp_event_base_t, int32_t, void *event_data) {
  auto *ev = (ip_event_got_ip_t *)event_data;
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

  wifi_config_t wc{};
  strncpy((char *)wc.sta.ssid, SM_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
  strncpy((char *)wc.sta.password, SM_WIFI_PASS, sizeof(wc.sta.password) - 1);
  wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_LOGI(TAG, "wifi station started (ssid=%s)", SM_WIFI_SSID);
}

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

  // カスタムクラスタ(EP2)は sm_init より前に登録する(F4b、§8)。
  register_custom();

  SmStack stack(cfg, now_ms());
  if (!stack.ok()) {
    ESP_LOGE(TAG, "sm_init failed: rc=%d", stack.rc());
    vTaskDelete(nullptr);
    return;
  }
  ESP_LOGI(TAG, "sm_init ok: fabrics=%u onoff=%d", stack.fabric_count(), stack.onoff_get());
  led_set(stack.onoff_get());

  stack.on_event([](const sm_event_t &ev) {
    ESP_LOGI(TAG, "EVENT kind=%d arg=%u", (int)ev.kind, (unsigned)ev.arg);
    if (ev.kind == SM_EV_ONOFF_CHANGED) {
      led_set(ev.arg != 0);
    }
  });

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
  uint64_t last_counter_ms = 0;
  for (;;) {
    uint64_t now = now_ms();

    // カスタム Counter(EP2/0x0004)を 2 秒ごとに更新 → 購読へ(mark_dirty)。
    if (now - last_counter_ms >= 2000) {
      last_counter_ms = now;
      g_custom.counter++;
      sm_attr_mark_dirty(kCustomEp, kCustomCluster, 0x0004);
    }

    // WiFi/IP・ローカル操作のコマンドを排出(同一タスクで sm_* を呼ぶ)。
    Cmd c;
    while (g_cmd_queue && xQueueReceive(g_cmd_queue, &c, 0) == pdTRUE) {
      switch (c.kind) {
      case CmdKind::IpV4:
        stack.set_addrs(c.v4, nullptr);
        break;
      case CmdKind::IpV6:
        stack.set_addrs(nullptr, c.v6);
        break;
      case CmdKind::LocalToggle:
        stack.onoff_set(!stack.onoff_get(), now);
        led_set(stack.onoff_get());
        break;
      }
    }

    // 待ち時間 = sm_next_deadline と mDNS announce の近い方(上限 1s)。
    uint64_t dl = stack.next_deadline(now);
    struct timeval tv;
    if (dl == SM_NO_DEADLINE) {
      tv.tv_sec = 1;
      tv.tv_usec = 0;
    } else {
      uint64_t wait = (dl > now) ? (dl - now) : 0;
      if (wait > 1000) {
        wait = 1000;
      }
      tv.tv_sec = wait / 1000;
      tv.tv_usec = (wait % 1000) * 1000;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp_fd, &rfds);
    FD_SET(mdns_fd, &rfds);
    int maxfd = (udp_fd > mdns_fd ? udp_fd : mdns_fd) + 1;
    int r = select(maxfd, &rfds, nullptr, nullptr, &tv);
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

    // 時間駆動の送出・イベント・mDNS announce。
    stack.pump(now, udp_send);
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

  led_init();
  wifi_init_sta();

  // sm_* を単線で扱う pump タスク(sans-IO 契約: 全 API を同一タスクから)。
  xTaskCreate(&matter_task, "matter", 8192, nullptr, 5, nullptr);
}
