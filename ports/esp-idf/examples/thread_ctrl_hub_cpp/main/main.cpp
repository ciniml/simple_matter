// thread_ctrl_hub_cpp — ESP32-P4(ホスト)+ ESP32-H2(ot_rcp、UART)で動く
// 「Thread ネットワーク主宰(leader)兼 SRP サーバ兼 Matter コントローラ」。
// docs/design/p4-thread-controller.md(F8)。
//
// フロー:
//   1. OT を RCP over UART で起動 → dataset 復元/生成 → leader 化 → SRP サーバ有効化。
//      (active dataset TLV hex をログに出す。デバイス側にプリセットする素材。)
//   2. 供給メモリ(PSRAM 優先、無ければ internal)に sm_ctrl の context を確保 → sm_ctrl_init。
//      CA/ノード帳/resumption は NVS(namespace "smctl")へ配線。
//   3. 未コミッショニングなら CONFIG_SM_TARGET_IPV6(デバイスの ML-EID/OMR)へ
//      on-network PASE(BLE なし。デバイスは同 dataset で Thread に参加済みが前提)。
//   4. 定常: 30 秒毎に OnOff Toggle。失敗が続いたら SRP サーバ帳からアドレスを引いて
//      sm_ctrl_set_node_addr(F8b)で更新 → 1 回リトライ。
//
// 実機フラッシュは対象外(本フェーズのゲートはビルド green まで)。

#include "simple_matter.h"


#include "ot_hub.hpp"

#include <cstdint>
#include <cstring>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_memory_utils.h" // esp_ptr_external_ram
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace {

constexpr const char *TAG = "thr_hub";
constexpr const char *SM_NVS_NAMESPACE = "smctl";

uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- KVS コールバック(NVS namespace "smctl"、cast/nods/rsm*) ----
// NVS キーは 15 文字以内。"rsm<16hex>" は 19 文字で超過するため短縮する
// (controller_hub_cpp と同一実装。ノード帳/CA/resumption はキー互換)。
void short_key(const char *key, char out[16]) {
  size_t n = strlen(key);
  if (n <= 15) {
    strcpy(out, key);
    return;
  }
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

// ---- UDP(コントローラはエフェメラルポート。Thread は IPv6 のみ)----
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
    // リンクローカル宛は scope_id(OT netif index)が要る。
    m.sin6_scope_id = dst.scope_id != 0 ? dst.scope_id : sm_ot_hub_netif_index();
  } else {
    // v4-mapped v6(Thread 構成では通常使わないが対称性のため維持)。
    m.sin6_addr.un.u8_addr[10] = 0xff;
    m.sin6_addr.un.u8_addr[11] = 0xff;
    memcpy(&m.sin6_addr.un.u8_addr[12], dst.ip, 4);
  }
  sendto(fd, buf, len, 0, (struct sockaddr *)&m, sizeof(m));
}

sm_addr_t sockaddr_to_smaddr(const struct sockaddr_in6 &s6) {
  sm_addr_t a = {};
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
      if (ev.kind == SM_CTRL_EV_PAIR_PHASE) {
        ESP_LOGI(TAG, "  pair phase %u", ev.phase);
      }
      if (is_terminal(ev)) {
        out_ev = ev;
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

// SRP サーバ帳からデバイスの運用アドレスを引き、ノード帳へ反映する(F8b)。成功=true。
bool refresh_addr_from_srp(uint64_t node_id) {
  uint8_t ip[16];
  if (!sm_ot_hub_srp_lookup(node_id, ip)) {
    ESP_LOGW(TAG, "SRP lookup: node %#llx not registered", (unsigned long long)node_id);
    sm_ot_hub_dump_srp();
    return false;
  }
  sm_addr_t a = {};
  a.is_v6 = true;
  memcpy(a.ip, ip, 16);
  a.port = 5540;
  a.scope_id = sm_ot_hub_netif_index();
  int rc = sm_ctrl_set_node_addr(node_id, &a);
  char buf[64] = {0};
  inet_ntop(AF_INET6, ip, buf, sizeof(buf));
  ESP_LOGI(TAG, "SRP lookup -> %s (sm_ctrl_set_node_addr rc=%d)", buf, rc);
  // RESOLVE_DONE を吸い出す(定常ループのイベント読みを汚さない)。
  sm_ctrl_event_t ev;
  while (sm_ctrl_take_event(&ev)) {
  }
  return rc == 0;
}

// 1 回の toggle を実行する。成功=true。
bool do_toggle(uint64_t node_id) {
  if (sm_ctrl_invoke(node_id, 1, 0x0006, 0x02, now_ms()) != 0) {
    return false;
  }
  sm_ctrl_event_t ev;
  if (run_until(g_udp, 20000, ev, term_invoke) && ev.kind == SM_CTRL_EV_INVOKE_DONE) {
    ESP_LOGI(TAG, "toggle OK status=%u", ev.status);
    return true;
  }
  return false;
}

} // namespace

// ハブ本体。スタック 128KB 必須級(sm_ctrl_init のスタック構築一時コピー +
// P-256 署名チェーン。S3 実機で確定)。P4 では起動直後の main タスク 128KB 生成が
// heap 未整備で assert する(実機 P9)ため、静的スタックの専用タスクで動かす。
static void hub_task(void *) {
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  // --- 1. OT(RCP over UART)を起動して Thread ネットワークを主宰する ---
  sm_ot_hub_init();
  if (!sm_ot_hub_wait_ready(10000)) {
    ESP_LOGE(TAG, "openthread did not come up (check RCP UART wiring / H2 firmware)");
    vTaskDelete(nullptr);
    return;
  }
  if (!sm_ot_hub_form_network()) {
    ESP_LOGE(TAG, "failed to form/restore Thread network");
    vTaskDelete(nullptr);
    return;
  }
  sm_ot_hub_wait_leader(30000);

  // --- 2. 供給メモリ(PSRAM 優先)に context を確保して sm_ctrl_init ---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_SPIRAM);
  if (!mem) {
    mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_DEFAULT);
  }
  if (!mem) {
    ESP_LOGE(TAG, "failed to allocate %zu bytes for sm_ctrl context", rounded);
    vTaskDelete(nullptr);
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
    vTaskDelete(nullptr);
    return;
  }
  ESP_LOGI(TAG, "controller ready: nodes=%zu", sm_ctrl_node_count());

  g_udp = open_udp();
  if (g_udp < 0) {
    sm_ctrl_deinit();
    heap_caps_free(mem);
    vTaskDelete(nullptr);
    return;
  }

  const uint64_t node_id = CONFIG_SM_TARGET_NODE_ID;

  // --- 3. 未コミッショニングなら on-network PASE over Thread UDP ---
  if (sm_ctrl_node_count() == 0) {
    sm_addr_t addr = {};
    addr.is_v6 = true;
    if (inet_pton(AF_INET6, CONFIG_SM_TARGET_IPV6, addr.ip) != 1) {
      ESP_LOGE(TAG, "CONFIG_SM_TARGET_IPV6 ('%s') is not a valid IPv6 address. "
                    "Set it to the device ML-EID/OMR (see device log) and rebuild.",
               CONFIG_SM_TARGET_IPV6);
    } else {
      addr.port = CONFIG_SM_TARGET_PORT;
      addr.scope_id = sm_ot_hub_netif_index();
      ESP_LOGI(TAG, "pairing node %#llx at [%s]:%d ...", (unsigned long long)node_id,
               CONFIG_SM_TARGET_IPV6, CONFIG_SM_TARGET_PORT);
      if (sm_ctrl_pair_start(node_id, CONFIG_SM_TARGET_PASSCODE, &addr, now_ms()) == 0) {
        sm_ctrl_event_t ev;
        if (run_until(g_udp, 90000, ev, term_pair) && ev.kind == SM_CTRL_EV_PAIR_COMPLETE) {
          ESP_LOGI(TAG, "PAIR COMPLETE node=%#llx", (unsigned long long)node_id);
        } else {
          ESP_LOGW(TAG, "pairing failed (phase=%u status=%u)", ev.phase, ev.status);
        }
      }
    }
  }

  // --- 4. 定常: 30 秒毎 toggle。連続失敗時は SRP からアドレスを引き直して 1 回リトライ ---
  int fail_streak = 0;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(30000));
    ESP_LOGI(TAG, "toggle node=%#llx", (unsigned long long)node_id);
    if (do_toggle(node_id)) {
      fail_streak = 0;
      continue;
    }
    ++fail_streak;
    ESP_LOGW(TAG, "toggle failed (streak=%d)", fail_streak);
    if (fail_streak >= 2) {
      // デバイス再起動で OMR が変わった等 → SRP サーバ帳から現行アドレスを引き直す。
      if (refresh_addr_from_srp(node_id) && do_toggle(node_id)) {
        ESP_LOGI(TAG, "toggle OK after SRP re-resolve");
        fail_streak = 0;
      }
    }
  }
}

extern "C" void app_main(void) {
  static StaticTask_t s_hub_tcb;
  alignas(8) static StackType_t s_hub_stack[128 * 1024 / sizeof(StackType_t)];
  xTaskCreateStatic(&hub_task, "hub", sizeof(s_hub_stack) / sizeof(StackType_t), nullptr, 5,
                    s_hub_stack, &s_hub_tcb);
}
