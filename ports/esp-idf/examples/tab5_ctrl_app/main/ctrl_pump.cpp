// pump タスク — sm_ctrl_* を専有し、UI の操作キューを 1 件ずつ処理する。
// docs/design/p4-thread-controller.md §9.1。
//
// thread_ctrl_hub_cpp/main/main.cpp(F8c、実機 P9 で確定)の KVS/UDP/run_until を
// そのまま持ってきて、固定シナリオ(起動時 pairing + 30 秒毎 toggle)の代わりに
// UI からのコマンド処理ループを載せたもの。
//
// 契約:
//   - sm_ctrl_* を呼ぶのはこのタスクだけ(LVGL タスクからは絶対に呼ばない)
//   - UI への出力は sm_app_lock()/sm_app_unlock() のスナップショット経由だけ
//   - スタックは静的 128KB(P4 は起動直後の main タスク 128KB 生成が assert する。
//     実機 P9 の発見。xTaskCreateStatic の形は hub と同じ)

#include "ctrl_pump.hpp"

#include "simple_matter.h"

#include "app_state.hpp"
#include "node_book.hpp"
#include "ot_hub.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_memory_utils.h" // esp_ptr_external_ram
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs.h"

namespace {

constexpr const char *TAG = "pump";
constexpr const char *SM_NVS_NAMESPACE = "smctl";

// OnOff クラスタ。
constexpr uint16_t EP_ONOFF = 1;
constexpr uint32_t CL_ONOFF = 0x0006;
constexpr uint32_t CMD_TOGGLE = 0x02;
constexpr uint32_t ATTR_ONOFF = 0x0000;

uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- KVS コールバック(NVS namespace "smctl"、cast/nods/rsm*)----
// thread_ctrl_hub_cpp と同一実装。キー互換なので hub で作った CA / ノード帳 /
// resumption 素材をそのまま引き継げる(= 実機の 0xaabbccdd が一覧に出る)。
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

// 受信を 1 回だけ待って給餌する(戻り値 = 何か受けたか)。
bool pump_once(int fd, uint32_t wait_ms) {
  uint8_t rx[1500];
  struct timeval tv = {(time_t)(wait_ms / 1000), (suseconds_t)((wait_ms % 1000) * 1000)};
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
  bool got = false;
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
      got = true;
    }
  }
  drain_tx(fd);
  return got;
}

// 1 コマンド(pair/toggle/read 発行済み)を終端イベントまで駆動する。成功=true。
// PAIR_PHASE はスナップショットへ流す(ダイアログの進捗表示)。
bool run_until(int fd, uint64_t timeout_ms, sm_ctrl_event_t &out_ev,
               bool (*is_terminal)(const sm_ctrl_event_t &)) {
  uint64_t until = now_ms() + timeout_ms;
  drain_tx(fd);
  for (;;) {
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (ev.kind == SM_CTRL_EV_PAIR_PHASE) {
        ESP_LOGI(TAG, "  pair phase %u", ev.phase);
        sm_ui_snapshot_t *s = sm_app_lock();
        s->pair_phase = ev.phase;
        sm_app_unlock();
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
    pump_once(fd, (uint32_t)wait);
  }
}

bool term_pair(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_PAIR_COMPLETE || e.kind == SM_CTRL_EV_PAIR_FAILED;
}
bool term_invoke(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_INVOKE_DONE || e.kind == SM_CTRL_EV_INVOKE_FAILED;
}
bool term_read(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_READ_DONE || e.kind == SM_CTRL_EV_READ_FAILED;
}

// ---- スナップショット更新ヘルパ ----

// ノード帳のインデックスを引く(見つからなければ SM_UI_MAX_NODES)。
size_t node_index(const sm_ui_snapshot_t *s, uint64_t node_id) {
  for (size_t i = 0; i < s->node_count; ++i) {
    if (s->nodes[i].node_id == node_id) {
      return i;
    }
  }
  return SM_UI_MAX_NODES;
}

void set_node_busy(uint64_t node_id, bool busy) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].busy = busy ? 1 : 0;
  }
  sm_app_unlock();
}

void set_node_note(uint64_t node_id, const char *note) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    snprintf(s->nodes[i].note, sizeof(s->nodes[i].note), "%s", note);
  }
  sm_app_unlock();
}

void set_node_onoff(uint64_t node_id, int8_t v) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].onoff = v;
  }
  sm_app_unlock();
}

// sm_addr_t を "[addr]:port" の表示文字列にする。
void format_addr(const sm_addr_t &a, char *out, size_t cap) {
  char ip[64] = {0};
  if (a.is_v6) {
    inet_ntop(AF_INET6, a.ip, ip, sizeof(ip));
    snprintf(out, cap, "[%s]:%u", ip, (unsigned)a.port);
  } else {
    inet_ntop(AF_INET, a.ip, ip, sizeof(ip));
    snprintf(out, cap, "%s:%u", ip, (unsigned)a.port);
  }
}

void refresh_node_addr_view(uint64_t node_id) {
  sm_addr_t a = {};
  bool known = sm_ctrl_node_addr(node_id, &a);
  char buf[64];
  if (known) {
    format_addr(a, buf, sizeof(buf));
  } else {
    snprintf(buf, sizeof(buf), "-");
  }
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    snprintf(s->nodes[i].addr, sizeof(s->nodes[i].addr), "%s", buf);
  }
  sm_app_unlock();
}

// ノード一覧をノード帳(NVS "nods")+ sm_ctrl_node_addr から作り直す。
void rebuild_node_list() {
  uint64_t ids[SM_UI_MAX_NODES];
  size_t n = sm_node_ids_from_nvs(ids, SM_UI_MAX_NODES);
  size_t known = sm_ctrl_node_count();
  if (n == 0 && known > 0) {
    // NVS の "nods" が読めない/形式違いだが、シムはノードを持っている。
    // 最後の手段として Kconfig の既知 NodeId を試す(実機の NanoC6 = 0xaabbccdd)。
    uint64_t fallback = (uint64_t)CONFIG_SM_UI_FALLBACK_NODE_ID;
    sm_addr_t a = {};
    if (sm_ctrl_node_addr(fallback, &a)) {
      ids[0] = fallback;
      n = 1;
      ESP_LOGW(TAG, "node book blob unreadable; using fallback node %#llx",
               (unsigned long long)fallback);
    }
  }

  sm_ui_snapshot_t *s = sm_app_lock();
  // 既存行の on/off と note は NodeId が同じなら引き継ぐ。
  sm_ui_node_t old[SM_UI_MAX_NODES];
  memcpy(old, s->nodes, sizeof(old));
  size_t old_count = s->node_count;
  memset(s->nodes, 0, sizeof(s->nodes));
  s->node_count = 0;
  for (size_t i = 0; i < n; ++i) {
    sm_addr_t a = {};
    bool present = sm_ctrl_node_addr(ids[i], &a);
    sm_ui_node_t &row = s->nodes[s->node_count];
    row.node_id = ids[i];
    row.onoff = -1;
    row.busy = 0;
    if (present) {
      format_addr(a, row.addr, sizeof(row.addr));
    } else {
      snprintf(row.addr, sizeof(row.addr), "-");
    }
    for (size_t j = 0; j < old_count; ++j) {
      if (old[j].node_id == ids[i]) {
        row.onoff = old[j].onoff;
        memcpy(row.note, old[j].note, sizeof(row.note));
        break;
      }
    }
    ++s->node_count;
  }
  sm_app_unlock();
  ESP_LOGI(TAG, "node list: %u shown / %u in controller node book", (unsigned)n, (unsigned)known);
}

void refresh_thread_status() {
  sm_ot_status_t st;
  sm_ot_hub_get_status(&st);
  sm_ui_snapshot_t *s = sm_app_lock();
  s->role = st.role;
  s->rloc16 = st.rloc16;
  s->channel = st.channel;
  s->panid = st.panid;
  s->srp_enabled = st.srp_enabled;
  s->srp_hosts = st.srp_hosts;
  memcpy(s->netname, st.netname, sizeof(s->netname));
  s->free_internal = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
  s->free_internal_min = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
  s->free_psram = (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
  sm_app_unlock();
}

// ---- 操作ハンドラ ----

// quiet = 周期ポーリング(ステータス行を汚さない)。timeout_ms は CASE 込みの上限。
bool do_read_onoff(uint64_t node_id, bool quiet, uint64_t timeout_ms) {
  if (sm_ctrl_read_scalar(node_id, EP_ONOFF, CL_ONOFF, ATTR_ONOFF, now_ms()) != 0) {
    if (!quiet) {
      sm_app_set_status("read %016llx: rejected (busy / unknown node)",
                        (unsigned long long)node_id);
    }
    return false;
  }
  sm_ctrl_event_t ev;
  if (run_until(g_udp, timeout_ms, ev, term_read) && ev.kind == SM_CTRL_EV_READ_DONE) {
    int8_t v = ev.value_is_null ? (int8_t)-1 : (int8_t)(ev.value_u64 != 0 ? 1 : 0);
    set_node_onoff(node_id, v);
    if (!quiet) {
      sm_app_set_status("read %016llx OnOff = %s", (unsigned long long)node_id,
                        v < 0 ? "null" : (v ? "On" : "Off"));
    }
    return true;
  }
  set_node_onoff(node_id, -1);
  if (!quiet) {
    sm_app_set_status("read %016llx failed", (unsigned long long)node_id);
  }
  return false;
}

void do_toggle(uint64_t node_id) {
  sm_app_set_status("toggle %016llx ...", (unsigned long long)node_id);
  if (sm_ctrl_invoke(node_id, EP_ONOFF, CL_ONOFF, CMD_TOGGLE, now_ms()) != 0) {
    set_node_note(node_id, "toggle rejected");
    sm_app_set_status("toggle %016llx: rejected", (unsigned long long)node_id);
    return;
  }
  sm_ctrl_event_t ev;
  if (run_until(g_udp, 20000, ev, term_invoke) && ev.kind == SM_CTRL_EV_INVOKE_DONE) {
    set_node_note(node_id, "toggle OK");
    sm_app_set_status("toggle %016llx OK (status=%u)", (unsigned long long)node_id, ev.status);
    // 直後に読み直してバッジを合わせる。
    do_read_onoff(node_id, true, 20000);
  } else {
    set_node_note(node_id, "toggle FAILED");
    sm_app_set_status("toggle %016llx failed", (unsigned long long)node_id);
  }
}

// SRP サーバ帳からデバイスの運用アドレスを引き、ノード帳へ反映する(F8b)。
void do_refresh_addr(uint64_t node_id) {
  sm_app_set_status("SRP lookup for %016llx ...", (unsigned long long)node_id);
  uint8_t ip[16];
  if (!sm_ot_hub_srp_lookup(node_id, ip)) {
    sm_ot_hub_dump_srp();
    set_node_note(node_id, "not in SRP");
    sm_app_set_status("SRP: node %016llx is not registered", (unsigned long long)node_id);
    return;
  }
  sm_addr_t a = {};
  a.is_v6 = true;
  memcpy(a.ip, ip, 16);
  a.port = CONFIG_SM_TARGET_PORT;
  a.scope_id = sm_ot_hub_netif_index();
  int rc = sm_ctrl_set_node_addr(node_id, &a);
  // RESOLVE_DONE を吸い出す(次の run_until のイベント読みを汚さない)。
  sm_ctrl_event_t ev;
  while (sm_ctrl_take_event(&ev)) {
  }
  refresh_node_addr_view(node_id);
  set_node_note(node_id, rc == 0 ? "addr updated" : "set_node_addr failed");
  char buf[64] = {0};
  inet_ntop(AF_INET6, ip, buf, sizeof(buf));
  sm_app_set_status("SRP -> %s (set_node_addr rc=%d)", buf, rc);
}

void do_pair(const sm_ui_op_t &op) {
  sm_addr_t addr = {};
  addr.is_v6 = true;
  if (inet_pton(AF_INET6, op.ipv6, addr.ip) != 1) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    sm_app_unlock();
    sm_app_set_status("pair: '%s' is not a valid IPv6 address", op.ipv6);
    return;
  }
  addr.port = CONFIG_SM_TARGET_PORT;
  addr.scope_id = sm_ot_hub_netif_index();

  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 1;
    s->pair_phase = 0;
    sm_app_unlock();
  }
  sm_app_set_status("pairing %016llx at [%s]:%d ...", (unsigned long long)op.node_id, op.ipv6,
                    CONFIG_SM_TARGET_PORT);

  if (sm_ctrl_pair_start(op.node_id, op.passcode, &addr, now_ms()) != 0) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    sm_app_unlock();
    sm_app_set_status("pair_start rejected (busy?)");
    return;
  }
  sm_ctrl_event_t ev;
  bool ok = run_until(g_udp, 120000, ev, term_pair) && ev.kind == SM_CTRL_EV_PAIR_COMPLETE;
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = ok ? 2 : 3;
    sm_app_unlock();
  }
  if (ok) {
    sm_app_set_status("PAIR COMPLETE node=%016llx", (unsigned long long)op.node_id);
    rebuild_node_list();
    do_read_onoff(op.node_id, true, 20000);
  } else {
    sm_app_set_status("pairing failed (phase=%u status=%u)", ev.phase, ev.status);
  }
}

// ---- タスク本体 ----

void pump_task(void *) {
  // --- 1. OT(RCP over UART)を起動して Thread ネットワークを主宰する ---
  sm_app_set_status("starting OpenThread (RCP over UART%d) ...", CONFIG_SM_OT_UART_PORT);
  sm_ot_hub_init();
  if (!sm_ot_hub_wait_ready(10000)) {
    sm_app_set_status("openthread did not come up (check RCP UART wiring / H2 firmware)");
    vTaskDelete(nullptr);
    return;
  }
  if (!sm_ot_hub_form_network()) {
    sm_app_set_status("failed to form/restore the Thread network");
    vTaskDelete(nullptr);
    return;
  }
  {
    // active dataset TLV(デバイス側プリセット用。ネットワーク情報タブと QR の素材)。
    char hex[SM_UI_DATASET_HEX_CAP];
    size_t n = sm_ot_hub_dataset_hex(hex, sizeof(hex));
    sm_ui_snapshot_t *s = sm_app_lock();
    memcpy(s->dataset_hex, hex, n + 1);
    sm_app_unlock();
  }
  refresh_thread_status();
  sm_app_set_status("thread up; waiting for leader/router role ...");
  sm_ot_hub_wait_leader(30000);
  refresh_thread_status();

  // --- 2. 供給メモリ(PSRAM 優先)に context を確保して sm_ctrl_init ---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_SPIRAM);
  if (!mem) {
    mem = heap_caps_aligned_alloc(align, rounded, MALLOC_CAP_DEFAULT);
  }
  if (!mem) {
    sm_app_set_status("failed to allocate %u bytes for the sm_ctrl context", (unsigned)rounded);
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
    sm_app_set_status("sm_ctrl_init failed (rc=%d)", rc);
    heap_caps_free(mem);
    vTaskDelete(nullptr);
    return;
  }

  g_udp = open_udp();
  if (g_udp < 0) {
    sm_app_set_status("failed to open the controller UDP socket");
    sm_ctrl_deinit();
    heap_caps_free(mem);
    vTaskDelete(nullptr);
    return;
  }

  // --- 3. ノード帳から一覧を作る(実機に既に居る NanoC6 等)---
  rebuild_node_list();
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->ctrl_ready = true;
    sm_app_unlock();
  }
  sm_app_set_status("controller ready: %u node(s) in the node book",
                    (unsigned)sm_ctrl_node_count());

  // --- 4. 定常ループ: UI の操作を 1 件ずつ + 周期タスク ---
  uint64_t next_status = 0;
  uint64_t next_poll = now_ms() + 5000; // 起動直後の read は 5 秒待ってから
  size_t poll_index = 0;
  for (;;) {
    sm_ui_op_t op;
    if (sm_app_take_op(&op, 100)) {
      switch (op.kind) {
      case SM_UI_OP_TOGGLE:
        set_node_busy(op.node_id, true);
        do_toggle(op.node_id);
        set_node_busy(op.node_id, false);
        break;
      case SM_UI_OP_READ_ONOFF:
        set_node_busy(op.node_id, true);
        do_read_onoff(op.node_id, false, 20000);
        set_node_busy(op.node_id, false);
        break;
      case SM_UI_OP_REFRESH_ADDR:
        set_node_busy(op.node_id, true);
        do_refresh_addr(op.node_id);
        set_node_busy(op.node_id, false);
        break;
      case SM_UI_OP_PAIR:
        do_pair(op);
        break;
      }
      refresh_thread_status();
      continue;
    }

    // 操作が無い間も UDP は回す(MRP の ACK / 再送で無音にならないように)。
    pump_once(g_udp, 50);

    uint64_t now = now_ms();
    if (now >= next_status) {
      next_status = now + 2000;
      refresh_thread_status();
      if (sm_ctrl_node_count() != 0) {
        sm_ui_snapshot_t *s = sm_app_lock();
        size_t shown = s->node_count;
        sm_app_unlock();
        if (shown == 0) {
          rebuild_node_list();
        }
      }
    }
    // 10 秒周期でノードを 1 件ずつ read して on/off バッジを更新する。
    if (now >= next_poll) {
      next_poll = now + 10000;
      sm_ui_snapshot_t *s = sm_app_lock();
      size_t count = s->node_count;
      uint64_t id = count ? s->nodes[poll_index % count].node_id : 0;
      sm_app_unlock();
      if (count > 0) {
        poll_index = (poll_index + 1) % count;
        set_node_busy(id, true);
        do_read_onoff(id, true, 10000);
        set_node_busy(id, false);
      }
    }
  }
}

} // namespace

void sm_ctrl_pump_start() {
  // スタック 128KB 必須級(sm_ctrl_init のスタック構築一時コピー + P-256 署名チェーン)。
  // P4 では起動直後の動的 128KB タスク生成が heap 未整備で assert する(実機 P9)ため、
  // hub と同じく静的スタックで作る。
  static StaticTask_t s_pump_tcb;
  alignas(8) static StackType_t s_pump_stack[128 * 1024 / sizeof(StackType_t)];
  xTaskCreateStatic(&pump_task, "ctrl_pump", sizeof(s_pump_stack) / sizeof(StackType_t), nullptr,
                    5, s_pump_stack, &s_pump_tcb);
}
