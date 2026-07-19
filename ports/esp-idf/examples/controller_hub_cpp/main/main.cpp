// controller_hub_cpp — simple-matter コントローラ C FFI(sm_ctrl_*)の ESP-IDF C++17
// 参照実装(ESP32-S3、供給メモリ = PSRAM)。F7a、docs/design/c-ffi-shim.md §11。
//
// フロー(K4 風の最小骨格。ビルド検証用):
//   1. WiFi 接続(esp_wifi station、SSID/PASS は Kconfig)→ got_ip。
//   2. 供給メモリを heap_caps_malloc(PSRAM 優先、無ければ internal)で確保 → sm_ctrl_init。
//      必要サイズ/アラインは sm_ctrl_context_size()/sm_ctrl_context_align()。
//   3. CA/ノード帳/resumption は NVS(namespace "smctl")へ配線。
//   4. 対象ノードが未コミッショニングなら pairing(UDP 直接 PASE)、済みなら resumption。
//   5. 定常: 30 秒毎に OnOff Toggle(EP1/0x0006/cmd 0x02)。
//
// 実機フラッシュは対象外(このコミットの範囲はビルド green まで)。

#include "simple_matter.h"

#include "ble_central.hpp"

#include <cstdint>
#include <cstring>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace {

constexpr const char *TAG = "ctrl_hub";
constexpr const char *SM_NVS_NAMESPACE = "smctl";

uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- KVS コールバック(NVS namespace "smctl"、cast/nods/rsm*) ----
// NVS キーは 15 文字以内。ca-state="cast"、nodes="nods"、resumption="rsm<16hex>" は
// 19 文字で超過するため、SHA なしで短縮する: "r"+末尾 6 hex(衝突は運用ノード数上限で回避)。
void short_key(const char *key, char out[16]) {
  size_t n = strlen(key);
  if (n <= 15) {
    strcpy(out, key);
    return;
  }
  // "rsm<16hex>" → "r" + 末尾 12 文字(node_id 下位 48bit 相当)。
  out[0] = 'r';
  strncpy(out + 1, key + (n - 12), 12);
  out[13] = 0;
}

extern "C" int32_t kvs_get(void *, const char *key, uint8_t *buf, size_t cap) {
  char k[16];
  short_key(key, k);
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
    return -1;
  }
  size_t len = 0;
  esp_err_t err = nvs_get_blob(h, k, nullptr, &len);
  if (err != ESP_OK) {
    nvs_close(h);
    return -1;
  }
  if (len <= cap) {
    size_t rd = len;
    if (nvs_get_blob(h, k, buf, &rd) != ESP_OK) {
      nvs_close(h);
      return -1;
    }
  }
  nvs_close(h);
  return (int32_t)len;
}

extern "C" int32_t kvs_set(void *, const char *key, const uint8_t *val, size_t len) {
  char k[16];
  short_key(key, k);
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
    return -1;
  }
  esp_err_t err = nvs_set_blob(h, k, val, len);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK ? 0 : -1;
}

extern "C" int32_t kvs_delete(void *, const char *key) {
  char k[16];
  short_key(key, k);
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
    return -1;
  }
  esp_err_t err = nvs_erase_key(h, k);
  if (err == ESP_OK) {
    nvs_commit(h);
  }
  nvs_close(h);
  return (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) ? 0 : -1;
}

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) { esp_fill_random(buf, len); }

// ---- WiFi station ----
volatile bool g_got_ip = false;

void on_wifi_event(void *, esp_event_base_t base, int32_t id, void *) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    g_got_ip = false;
    esp_wifi_connect();
  }
}

void on_got_ip(void *, esp_event_base_t, int32_t, void *event_data) {
  auto *ev = (ip_event_got_ip_t *)event_data;
  ESP_LOGI(TAG, "got ip: " IPSTR, IP2STR(&ev->ip_info.ip));
  g_got_ip = true;
}

void wifi_init_sta() {
  esp_netif_create_default_wifi_sta();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                      &on_wifi_event, nullptr, nullptr));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ip,
                                                      nullptr, nullptr));
  wifi_config_t wc = {};
  strncpy((char *)wc.sta.ssid, CONFIG_SM_WIFI_SSID, sizeof(wc.sta.ssid) - 1);
  strncpy((char *)wc.sta.password, CONFIG_SM_WIFI_PASS, sizeof(wc.sta.password) - 1);
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
  ESP_ERROR_CHECK(esp_wifi_start());
}

// ---- UDP(コントローラはエフェメラルポート、dual-stack) ----
int g_udp = -1;

int open_udp() {
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    ESP_LOGE(TAG, "socket() failed");
    return -1;
  }
  int off = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
  struct sockaddr_in6 a = {};
  a.sin6_family = AF_INET6;
  a.sin6_port = 0;
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    ESP_LOGE(TAG, "bind() failed");
    close(fd);
    return -1;
  }
  return fd;
}

void send_sm(int fd, const uint8_t *buf, size_t len, const sm_addr_t &dst) {
  struct sockaddr_in6 m = {};
  m.sin6_family = AF_INET6;
  m.sin6_port = htons(dst.port);
  if (dst.is_v6) {
    memcpy(&m.sin6_addr, dst.ip, 16);
    m.sin6_scope_id = dst.scope_id;
  } else {
    // v4-mapped v6(dual-stack)。
    m.sin6_addr.un.u8_addr[10] = 0xff;
    m.sin6_addr.un.u8_addr[11] = 0xff;
    memcpy(&m.sin6_addr.un.u8_addr[12], dst.ip, 4);
  }
  sendto(fd, buf, len, 0, (struct sockaddr *)&m, sizeof(m));
}

sm_addr_t sockaddr_to_smaddr(const struct sockaddr_in6 &s6) {
  sm_addr_t a = {};
  // v4-mapped を検出して v4 として返す(コントローラは v4 対向を主に扱う)。
  const uint8_t *ip = s6.sin6_addr.un.u8_addr;
  bool mapped = true;
  for (int i = 0; i < 10; ++i) {
    if (ip[i] != 0) {
      mapped = false;
      break;
    }
  }
  if (mapped && ip[10] == 0xff && ip[11] == 0xff) {
    a.is_v6 = false;
    memcpy(a.ip, ip + 12, 4);
  } else {
    a.is_v6 = true;
    memcpy(a.ip, ip, 16);
    a.scope_id = s6.sin6_scope_id;
  }
  a.port = ntohs(s6.sin6_port);
  return a;
}

void drain_tx(int fd) {
  uint8_t tx[1500];
  sm_addr_t dst;
  for (;;) {
    size_t n = sm_ctrl_poll(now_ms(), tx, sizeof(tx), &dst);
    if (n == 0) {
      break;
    }
    send_sm(fd, tx, n, dst);
  }
}

// 1 コマンド(pair/toggle 発行済み)を終端イベントまで駆動する。成功=true。
bool run_until(int fd, uint64_t timeout_ms, sm_ctrl_event_t &out_ev,
               bool (*is_terminal)(const sm_ctrl_event_t &)) {
  uint64_t until = now_ms() + timeout_ms;
  uint8_t rx[1500];
  drain_tx(fd);
  for (;;) {
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (is_terminal(ev)) {
        out_ev = ev;
        // 残 ACK を流し切る。
        for (int i = 0; i < 50; ++i) {
          drain_tx(fd);
          if (sm_ctrl_next_deadline(now_ms()) == SM_NO_DEADLINE) {
            break;
          }
          vTaskDelay(pdMS_TO_TICKS(20));
        }
        return true;
      }
    }
    if (now_ms() > until) {
      return false;
    }
    uint64_t now = now_ms();
    uint64_t dl = sm_ctrl_next_deadline(now);
    uint64_t wait = (dl == SM_NO_DEADLINE) ? 100 : (dl > now ? dl - now : 0);
    if (wait > 200) {
      wait = 200;
    }
    struct timeval tv = {(time_t)(wait / 1000), (suseconds_t)((wait % 1000) * 1000)};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (r > 0 && FD_ISSET(fd, &rfds)) {
      struct sockaddr_in6 src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(fd, rx, sizeof(rx), 0, (struct sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        uint8_t tx[1500];
        sm_addr_t dst;
        size_t tn = sm_ctrl_udp_rx(rx, (size_t)n, &sa, now_ms(), tx, sizeof(tx), &dst);
        if (tn > 0) {
          send_sm(fd, tx, tn, dst);
        }
      }
    }
    drain_tx(fd);
  }
}

bool term_pair(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_PAIR_COMPLETE || e.kind == SM_CTRL_EV_PAIR_FAILED;
}
bool term_invoke(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_INVOKE_DONE || e.kind == SM_CTRL_EV_INVOKE_FAILED;
}

#ifdef CONFIG_SM_HUB_BLE_PAIR
// ---- BLE pairing(NimBLE central、F7b、docs/design/c-ffi-shim.md §11.4) ----

QueueHandle_t g_ble_q = nullptr;

// 運用 mDNS(_matter._tcp)でデバイスを解決する(QU ユニキャスト + マルチキャスト join)。
// BLE 切断後、デバイスが WiFi 参加して得た運用アドレスを見つける。成功=true。
bool resolve_operational(int fd, uint64_t node_id, uint64_t timeout_ms) {
  struct ip_mreq mreq = {};
  mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)); // best effort

  uint64_t until = now_ms() + timeout_ms;
  uint64_t last_q = 0;
  uint8_t rx[1500];
  while (now_ms() < until) {
    if (now_ms() - last_q > 2000) {
      uint8_t q[512];
      sm_addr_t qdst;
      size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
      if (qn > 0) {
        send_sm(fd, q, qn, qdst);
      }
      last_q = now_ms();
    }
    struct timeval tv = {0, 200000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(fd, &rfds)) {
      struct sockaddr_in6 src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(fd, rx, sizeof(rx), 0, (struct sockaddr *)&src, &sl);
      if (n > 0 && sm_ctrl_mdns_rx(rx, (size_t)n, nullptr, now_ms()) == 0) {
        sm_ctrl_event_t ev;
        while (sm_ctrl_take_event(&ev)) {
          if (ev.kind == SM_CTRL_EV_RESOLVE_DONE) return true;
        }
      }
    }
  }
  return false;
}

// BLE(BTP)central でコミッショニングを BLE_DONE まで駆動する。成功=true。
bool ble_pair(uint64_t node_id) {
  const uint8_t *ssid = (const uint8_t *)CONFIG_SM_WIFI_SSID;
  const uint8_t *pass = (const uint8_t *)CONFIG_SM_WIFI_PASS;
  int rc = sm_ctrl_ble_pair_start(node_id, CONFIG_SM_TARGET_PASSCODE, 0 /*wifi*/, ssid,
                                  strlen(CONFIG_SM_WIFI_SSID), pass, strlen(CONFIG_SM_WIFI_PASS),
                                  now_ms());
  if (rc != 0) {
    ESP_LOGE(TAG, "sm_ctrl_ble_pair_start rc=%d", rc);
    return false;
  }
  ESP_LOGI(TAG, "BLE scan+pair start (discriminator=%d)", CONFIG_SM_TARGET_DISCRIMINATOR);
  sm_ble_central_start(CONFIG_SM_TARGET_DISCRIMINATOR);

  uint64_t until = now_ms() + 90000;
  uint8_t frag[256];
  bool ble_done = false;
  bool subscribed = false; // C2 subscribe(= C1 発見済み)まで C1 write を保留する。
  while (now_ms() < until && !ble_done) {
    // NimBLE central のイベントを sm_ctrl_ble_event へ給餌する。
    BleCentralMsg m;
    while (xQueueReceive(g_ble_q, &m, 0) == pdTRUE) {
      switch (m.kind) {
      case BleCentralEvent::Connected:
        sm_ctrl_ble_event(SM_BLE_CONNECTED, m.mtu, nullptr, 0, now_ms());
        break;
      case BleCentralEvent::Subscribed:
        sm_ctrl_ble_event(SM_BLE_C2_SUBSCRIBED, 0, nullptr, 0, now_ms());
        subscribed = true;
        break;
      case BleCentralEvent::Indication:
        sm_ctrl_ble_event(SM_BLE_C1_WRITE, 0, m.frag, m.frag_len, now_ms());
        break;
      case BleCentralEvent::Disconnected:
        sm_ctrl_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());
        break;
      }
    }
    // コントローラが積んだ BTP フラグメントを C1 write で送る(C1 handle 確定 =
    // C2 subscribe 完了後のみ。CONNECTED 直後の handshake request は shim が退避しており、
    // subscribe 前に排出すると C1 handle 未確定で write が落ちるため)。
    size_t n;
    while (subscribed && (n = sm_ctrl_ble_poll(now_ms(), frag, sizeof(frag))) > 0) {
      sm_ble_central_write_c1(frag, n);
    }
    // フェーズイベント確認。
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (ev.kind == SM_CTRL_EV_PAIR_PHASE) {
        ESP_LOGI(TAG, "  BLE phase %u", ev.phase);
      } else if (ev.kind == SM_CTRL_EV_BLE_DONE) {
        ESP_LOGI(TAG, "BLE_DONE (AddNOC + WiFi + ConnectNetwork over BTP)");
        ble_done = true;
      } else if (ev.kind == SM_CTRL_EV_PAIR_FAILED) {
        ESP_LOGW(TAG, "BLE pairing FAILED phase=%u status=%u", ev.phase, ev.status);
        return false;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  if (!ble_done) {
    ESP_LOGW(TAG, "BLE phase timed out");
    return false;
  }
  // BLE 切断 → 運用 UDP へ handoff。
  sm_ble_central_disconnect();
  sm_ctrl_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());
  return true;
}
#endif // CONFIG_SM_HUB_BLE_PAIR

} // namespace

extern "C" void app_main(void) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  wifi_init_sta();

  ESP_LOGI(TAG, "waiting for WiFi/IP...");
  while (!g_got_ip) {
    vTaskDelay(pdMS_TO_TICKS(200));
  }

  // --- 供給メモリ経路: PSRAM(無ければ internal)に context を確保して sm_ctrl_init へ ---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_SPIRAM);
  if (!mem) {
    mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_DEFAULT);
  }
  if (!mem) {
    ESP_LOGE(TAG, "failed to allocate %zu bytes for sm_ctrl context", rounded);
    return;
  }
  ESP_LOGI(TAG, "sm_ctrl context: size=%zu align=%zu (supplied from %s)", need, align,
           esp_ptr_external_ram(mem) ? "PSRAM" : "internal");

  sm_ctrl_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.fabric_id = 0xFAB0000000000001ull;
  cfg.controller_node_id = 0x0000000011223344ull;
  cfg.vendor_id = 0xFFF1;
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.rng_fill = rng_fill;

  int rc = sm_ctrl_init((uint8_t *)mem, rounded, &cfg, now_ms());
  if (rc != 0) {
    ESP_LOGE(TAG, "sm_ctrl_init rc=%d", rc);
    heap_caps_free(mem);
    return;
  }
  ESP_LOGI(TAG, "controller ready: nodes=%zu", sm_ctrl_node_count());

  g_udp = open_udp();
  if (g_udp < 0) {
    sm_ctrl_deinit();
    heap_caps_free(mem);
    return;
  }

  const uint64_t node_id = CONFIG_SM_TARGET_NODE_ID;

  // 未コミッショニングなら pairing、済みなら以降 toggle が resumption で CASE 確立する。
  if (sm_ctrl_node_count() == 0) {
#ifdef CONFIG_SM_HUB_BLE_PAIR
    // --- BLE pairing(F7b): BLE で AddNOC/WiFi 投入 → BLE 切断 → mDNS 解決 → CASE over UDP ---
    g_ble_q = xQueueCreate(8, sizeof(BleCentralMsg));
    sm_ble_central_init(g_ble_q);
    if (ble_pair(node_id)) {
      ESP_LOGI(TAG, "resolving operational node %#llx via mDNS ...", (unsigned long long)node_id);
      if (resolve_operational(g_udp, node_id, 30000)) {
        sm_addr_t na;
        if (sm_ctrl_node_addr(node_id, &na)) {
          char ip[48] = {0};
          inet_ntop(na.is_v6 ? AF_INET6 : AF_INET, na.ip, ip, sizeof(ip));
          ESP_LOGI(TAG, "resolved %s:%u -> CASE over UDP", ip, na.port);
        }
        sm_ctrl_event_t ev;
        if (run_until(g_udp, 60000, ev, term_pair) && ev.kind == SM_CTRL_EV_PAIR_COMPLETE) {
          ESP_LOGI(TAG, "PAIR COMPLETE (BLE→UDP handoff) node=%#llx", (unsigned long long)node_id);
        } else {
          ESP_LOGW(TAG, "handoff CASE failed (phase=%u)", ev.phase);
        }
      } else {
        ESP_LOGW(TAG, "operational mDNS resolve failed");
      }
    }
#else
    // --- UDP 直接 PASE(F7a、回帰維持): 対象アドレスは Kconfig の固定 IPv4 ---
    sm_addr_t addr = {};
    addr.is_v6 = false;
    inet_pton(AF_INET, CONFIG_SM_TARGET_IP, addr.ip);
    addr.port = CONFIG_SM_TARGET_PORT;
    ESP_LOGI(TAG, "pairing node %#llx at %s:%d ...", (unsigned long long)node_id,
             CONFIG_SM_TARGET_IP, CONFIG_SM_TARGET_PORT);
    if (sm_ctrl_pair_start(node_id, CONFIG_SM_TARGET_PASSCODE, &addr, now_ms()) == 0) {
      sm_ctrl_event_t ev;
      if (run_until(g_udp, 60000, ev, term_pair) && ev.kind == SM_CTRL_EV_PAIR_COMPLETE) {
        ESP_LOGI(TAG, "PAIR COMPLETE node=%#llx", (unsigned long long)node_id);
      } else {
        ESP_LOGW(TAG, "pairing failed (phase=%u)", ev.phase);
      }
    }
#endif
  }

  // 定常: 30 秒毎に OnOff Toggle(live セッションが無ければ内部で CASE = resumption)。
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(30000));
    ESP_LOGI(TAG, "toggle node=%#llx", (unsigned long long)node_id);
    if (sm_ctrl_invoke(node_id, 1, 0x0006, 0x02, now_ms()) == 0) {
      sm_ctrl_event_t ev;
      if (run_until(g_udp, 20000, ev, term_invoke) && ev.kind == SM_CTRL_EV_INVOKE_DONE) {
        ESP_LOGI(TAG, "toggle OK status=%u", ev.status);
      } else {
        ESP_LOGW(TAG, "toggle failed");
      }
    }
  }
}
