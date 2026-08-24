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
#include "ble_central.hpp"
#include "node_book.hpp"
#include "ot_hub.hpp"
#include "wifi_sta.hpp"

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
    // リンクローカル宛は scope_id が要る。scope 未指定の fe80 は **WiFi netif を優先**
    // (Thread ノードの実用アドレスは ML/OMR の fd:: で、fe80 で届く相手は実質 WiFi。
    //  nodes.tlv / mDNS 給餌は scope を持たないので、ここが唯一の補完点)。
    uint32_t fallback = sm_ot_hub_netif_index();
    if (dst.ip[0] == 0xfe && (dst.ip[1] & 0xc0) == 0x80) {
      uint32_t widx = sm_wifi_netif_index();
      if (widx != 0) {
        fallback = widx;
      }
    }
    m.sin6_scope_id = dst.scope_id != 0 ? dst.scope_id : fallback;
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

// WiFi の状態をスナップショットへ写す(UI は wifi_sta.hpp を直接見ない)。
void refresh_wifi_status() {
  sm_wifi_status_t w = {};
  sm_wifi_get_status(&w);
  sm_ui_snapshot_t *s = sm_app_lock();
  s->wifi_state = w.state;
  memcpy(s->wifi_ssid, w.ssid, sizeof(s->wifi_ssid));
  memcpy(s->wifi_ll, w.ll_addr, sizeof(s->wifi_ll));
  memcpy(s->wifi_ip4, w.ip4, sizeof(s->wifi_ip4));
  s->wifi_netif = w.netif_index;
  s->ble_host = sm_ble_central_state();
  sm_app_unlock();
}

// ---- 操作ハンドラ ----

// 前方宣言(実体は「運用アドレス解決」節。T3 で追加した mDNS 解決)。
bool resolve_via_mdns(uint64_t node_id, uint32_t netif_index, uint64_t timeout_ms);

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
    // SRP に居ない = Thread ノードではない可能性。WiFi が上がっていれば mDNS で引く
    // (T3 で追加。WiFi ノードのリブート後再解決もこれで効く)。
    uint32_t widx = sm_wifi_netif_index();
    if (widx != 0) {
      sm_app_set_status("not in SRP; trying mDNS over WiFi for %016llx ...",
                        (unsigned long long)node_id);
      bool ok = resolve_via_mdns(node_id, widx, 8000);
      sm_ctrl_event_t ev;
      while (sm_ctrl_take_event(&ev)) {
      }
      refresh_node_addr_view(node_id);
      set_node_note(node_id, ok ? "addr updated (mDNS)" : "not found");
      sm_app_set_status(ok ? "mDNS resolved %016llx" : "neither SRP nor mDNS knows %016llx",
                        (unsigned long long)node_id);
      return;
    }
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

  // scope_id はリンクローカル(fe80::/10)宛のときだけ意味を持つ。
  // ULA / グローバル宛は 0 のままにして lwIP の経路選択に任せる
  // (Thread の OMR も WiFi の GUA/ULA もこちら)。
  const bool is_ll = (addr.ip[0] == 0xfe) && ((addr.ip[1] & 0xc0) == 0x80);
  const bool via_wifi = (op.via == SM_UI_VIA_WIFI);
  if (is_ll) {
    addr.scope_id = via_wifi ? sm_wifi_netif_index() : sm_ot_hub_netif_index();
    if (addr.scope_id == 0) {
      sm_ui_snapshot_t *s = sm_app_lock();
      s->pair_state = 3;
      sm_app_unlock();
      sm_app_set_status("pair: the %s netif is not up (link-local target needs a scope)",
                        via_wifi ? "WiFi" : "Thread");
      return;
    }
  }

  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 1;
    s->pair_phase = 0;
    sm_app_unlock();
  }
  sm_app_set_status("pairing %016llx at [%s]:%d via %s%s ...", (unsigned long long)op.node_id,
                    op.ipv6, CONFIG_SM_TARGET_PORT, via_wifi ? "WiFi" : "Thread",
                    is_ll ? " (link-local)" : "");

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

// ---- 運用アドレス解決(BLE コミッショニング後の handoff、T3 §11.1)----
//
// シムは **`sm_ctrl_mdns_rx` が解決に成功したときだけ** BLE→UDP handoff を再開する
// (`Activity::BleHandoff` → `set_peer` + `resume` → `Activity::Pairing`。
//  crates/simple-matter-cffi/src/controller.rs の `sm_ctrl_mdns_rx`)。
// `sm_ctrl_set_node_addr` はノード帳のアドレスを差し替えるだけで **再開しない**ので、
// Thread(SRP 由来)の handoff も「mDNS 応答の形」でシムへ渡す必要がある。

// mDNS で `node_id` の運用アドレスを解決してシムへ給餌する(WiFi ノードの handoff)。
// 成功 = シムが RESOLVE_DONE を立て、BLE handoff なら CASE へ再開した。
//
// **鍵は「デバイスの announce を拾う」こと**(実機 T3 + PC 側パケット観測で確定):
// 我々のデバイスは ConnectNetwork 直後に operational 広告(PTR/SRV/TXT/A の
// announce)を数回マルチキャストするが、**個別 SRV クエリには応答しない**
// (generic-firmware.md の既知の穴。announce で解決が成立するため潜伏していた)。
// announce の宛先は 224.0.0.251:5353 なので、受けるには **5353 に bind + IGMP join
// した AF_INET ソケット**が必須(エフェメラルポートの g_udp には決して届かない)。
// join は AF_INET ソケットで行う(AF_INET6 dual ソケットへの v4 join は lwIP で
// 効かないことがある)。IGMP の egress/membership は WiFi の IPv4 を明示する
// (W3 の学び: IF 未指定のマルチキャストは既定 IF に飛ぶ)。
// クエリ(SRV QU)も同ソケットから送り続ける(応答する実装なら :5353 に
// ユニキャストで返ってくるので、これもマルチキャスト RX に依存しない)。
// 5353 に bind + 224.0.0.251 join した AF_INET ソケットを開く(IF = WiFi の IPv4)。
int open_mdns_5353() {
  sm_wifi_status_t w = {};
  sm_wifi_get_status(&w);
  struct in_addr wifi_ip4 = {};
  if (w.ip4[0] == 0 || inet_pton(AF_INET, w.ip4, &wifi_ip4) != 1) {
    ESP_LOGW(TAG, "mdns: WiFi IPv4 is not up");
    return -1;
  }
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return -1;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_port = htons(5353);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    ESP_LOGE(TAG, "mdns bind(5353) failed errno=%d", errno);
    close(fd);
    return -1;
  }
  struct ip_mreq m4 = {};
  m4.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
  m4.imr_interface = wifi_ip4;
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m4, sizeof(m4)) != 0) {
    ESP_LOGW(TAG, "IGMP join 224.0.0.251 on %s failed errno=%d", w.ip4, errno);
  }
  setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &wifi_ip4, sizeof(wifi_ip4));
  return fd;
}

// BLE フェーズ中に 5353 ソケットへ届いたパケットのキャッシュ(announce 捕獲用)。
// デバイスの operational announce は **ConnectNetwork 成功〜BLE_DONE の間**に流れる
// (遅延 ConnectNetworkResponse より早い。実機 + PC 側パケット観測で確定)ので、
// 解決開始まで取っておいて後からシムへリプレイする。
struct MdnsCached {
  uint16_t len;
  uint8_t buf[600];
};
MdnsCached g_mdns_cache[8];
size_t g_mdns_cache_n = 0;
int g_mdns_fd = -1;

void drain_mdns_to_cache() {
  if (g_mdns_fd < 0) {
    return;
  }
  for (;;) {
    struct timeval tv = {0, 0};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(g_mdns_fd, &rfds);
    if (select(g_mdns_fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) {
      return;
    }
    uint8_t rx[1500];
    int n = recv(g_mdns_fd, rx, sizeof(rx), 0);
    if (n <= 0) {
      return;
    }
    // 応答(QR=1)かつフルレコードが載るサイズだけキャッシュする(クエリや小物で
    // 8 枠を潰さない。announce は SRV+TXT+A 込みで 400B 超)。
    const bool is_response = (n > 12) && (rx[2] & 0x80);
    if (is_response && n >= 150 && (size_t)n <= sizeof(g_mdns_cache[0].buf) &&
        g_mdns_cache_n < 8) {
      memcpy(g_mdns_cache[g_mdns_cache_n].buf, rx, (size_t)n);
      g_mdns_cache[g_mdns_cache_n].len = (uint16_t)n;
      g_mdns_cache_n++;
      ESP_LOGI(TAG, "mdns cached %d B during BLE phase (%u total)", n, (unsigned)g_mdns_cache_n);
    }
  }
}

// キャッシュした announce をシムへ流す。RESOLVE_DONE が立てば true。
bool replay_mdns_cache() {
  for (size_t i = 0; i < g_mdns_cache_n; ++i) {
    if (sm_ctrl_mdns_rx(g_mdns_cache[i].buf, g_mdns_cache[i].len, nullptr, now_ms()) == 0) {
      sm_ctrl_event_t ev;
      while (sm_ctrl_take_event(&ev)) {
        if (ev.kind == SM_CTRL_EV_RESOLVE_DONE) {
          ESP_LOGI(TAG, "resolved from a cached announce (#%u)", (unsigned)i);
          return true;
        }
      }
    }
  }
  return false;
}

bool resolve_via_mdns(uint64_t node_id, uint32_t netif_index, uint64_t timeout_ms) {
  (void)netif_index;
  const bool own_fd = (g_mdns_fd < 0);
  int fd = own_fd ? open_mdns_5353() : g_mdns_fd;
  if (fd < 0) {
    return false;
  }

  struct sockaddr_in mdst = {};
  mdst.sin_family = AF_INET;
  mdst.sin_port = htons(5353);
  mdst.sin_addr.s_addr = inet_addr("224.0.0.251");

  uint64_t until = now_ms() + timeout_ms;
  uint64_t next_q = 0;
  uint8_t rx[1500];
  bool ok = false;
  while (!ok && now_ms() < until) {
    if (now_ms() >= next_q) {
      next_q = now_ms() + 2000;
      uint8_t q[512];
      sm_addr_t qdst = {};
      size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
      if (qn > 0) {
        sendto(fd, q, qn, 0, (struct sockaddr *)&mdst, sizeof(mdst));
        ESP_LOGI(TAG, "mdns query %u B -> 224.0.0.251:5353 (from :5353)", (unsigned)qn);
      }
    }
    struct timeval tv = {0, 200000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0 && FD_ISSET(fd, &rfds)) {
      struct sockaddr_in src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(fd, rx, sizeof(rx), 0, (struct sockaddr *)&src, &sl);
      if (n > 0) {
        int32_t rc = sm_ctrl_mdns_rx(rx, (size_t)n, nullptr, now_ms());
        char sip[20] = {0};
        inet_ntop(AF_INET, &src.sin_addr, sip, sizeof(sip));
        ESP_LOGI(TAG, "mdns rx %d B from %s:%u -> rc=%ld", n, sip, ntohs(src.sin_port), (long)rc);
        if (rc == 0) {
          sm_ctrl_event_t ev;
          while (sm_ctrl_take_event(&ev)) {
            if (ev.kind == SM_CTRL_EV_RESOLVE_DONE) {
              ok = true;
            }
          }
        }
      }
    }
  }
  if (own_fd) {
    close(fd);
  }
  return ok;
}

// SRP で引いたアドレスを「mDNS 応答」に仕立ててシムへ渡す(Thread ノードの handoff)。
//
// シムの照合はインスタンス名 `<compressed-fabric-hex>-<node-id-hex>._matter._tcp.local` に
// 対する SRV + そのターゲットの AAAA。compressed fabric は C++ からは見えないが、
// `sm_ctrl_resolve_start` が作るクエリの QNAME がまさにそれなので、**それを借りて**
// 応答を組み立てる(パケット合成はここだけ。DNS 圧縮ポインタは使わない)。
bool feed_addr_as_mdns(uint64_t node_id, const uint8_t ip[16], uint16_t port) {
  uint8_t q[256];
  sm_addr_t qdst = {};
  size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
  (void)qdst; // 合成応答なので送信先は使わない
  if (qn <= 12 + 4) {
    return false;
  }
  const uint8_t *qname = q + 12;
  const size_t qname_len = qn - 12 - 4; // 末尾の QTYPE(2)+ QCLASS(2)を除く

  // SRV ターゲット = "smsrp.local"(このホスト名は SRV/AAAA の紐付けにしか使わない)。
  static const uint8_t kTarget[] = {5, 's', 'm', 's', 'r', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0};

  uint8_t r[512];
  size_t n = 0;
  auto put = [&](const void *p, size_t len) {
    if (n + len <= sizeof(r)) {
      memcpy(r + n, p, len);
      n += len;
    }
  };
  auto put16 = [&](uint16_t v) {
    uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    put(b, 2);
  };
  auto put32 = [&](uint32_t v) {
    uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    put(b, 4);
  };

  // ヘッダ: ID=0 / FLAGS=0x8400(QR+AA)/ QD=0 / AN=2 / NS=0 / AR=0。
  put16(0);
  put16(0x8400);
  put16(0);
  put16(2);
  put16(0);
  put16(0);
  // 1) SRV <instance>._matter._tcp.local -> smsrp.local:port
  put(qname, qname_len);
  put16(33);  // T_SRV
  put16(1);   // IN
  put32(120); // TTL
  put16((uint16_t)(6 + sizeof(kTarget)));
  put16(0); // priority
  put16(0); // weight
  put16(port);
  put(kTarget, sizeof(kTarget));
  // 2) AAAA smsrp.local -> ip
  put(kTarget, sizeof(kTarget));
  put16(28); // T_AAAA
  put16(1);
  put32(120);
  put16(16);
  put(ip, 16);

  if (n > sizeof(r)) {
    return false;
  }
  return sm_ctrl_mdns_rx(r, n, nullptr, now_ms()) == 0;
}

// ---- BLE コミッショニング(T3、§11.1)----

// 直近の BLE 接続相手の BT MAC(印字順)。EUI-64 フォールバックに使う。
uint8_t g_ble_peer_mac[6] = {};
bool g_ble_peer_mac_ok = false;

// ESP32 ファミリの MAC 割当(base=WiFi STA、+2=BT)を逆算して、BLE ピアの
// WiFi 側 IPv6 インターフェース ID(EUI-64)を作る。48bit 減算で桁借りも処理。
void derive_wifi_eui64(const uint8_t bt_mac[6], uint8_t eui64_out[8]) {
  uint8_t mac[6];
  memcpy(mac, bt_mac, 6);
  uint64_t v = 0;
  for (int i = 0; i < 6; ++i) {
    v = (v << 8) | mac[i];
  }
  v -= 2; // BT = base + 2 → WiFi STA = BT - 2
  for (int i = 5; i >= 0; --i) {
    mac[i] = (uint8_t)v;
    v >>= 8;
  }
  eui64_out[0] = mac[0] ^ 0x02;
  eui64_out[1] = mac[1];
  eui64_out[2] = mac[2];
  eui64_out[3] = 0xff;
  eui64_out[4] = 0xfe;
  eui64_out[5] = mac[3];
  eui64_out[6] = mac[4];
  eui64_out[7] = mac[5];
}

void set_ble_stage(uint8_t stage) {
  sm_ui_snapshot_t *s = sm_app_lock();
  s->ble_stage = stage;
  sm_app_unlock();
}

// BTP 給餌ループ。BLE_DONE まで進めば true。
bool drive_ble_phase(const sm_ui_op_t &op, uint64_t timeout_ms) {
  QueueHandle_t q = sm_ble_central_queue();
  if (q == nullptr) {
    return false;
  }
  uint64_t until = now_ms() + timeout_ms;
  uint8_t frag[256];
  bool subscribed = false;
  bool done = false;
  while (now_ms() < until && !done) {
    BleCentralMsg m;
    while (xQueueReceive(q, &m, 0) == pdTRUE) {
      switch (m.kind) {
      case BleCentralEvent::Connected:
        sm_ctrl_ble_event(SM_BLE_CONNECTED, m.mtu, nullptr, 0, now_ms());
        set_ble_stage(SM_UI_BLE_CONNECTED);
        if (m.peer_mac_valid) {
          memcpy(g_ble_peer_mac, m.peer_mac, 6);
          g_ble_peer_mac_ok = true;
        }
        sm_app_set_status("BLE connected (MTU=%u); discovering the Matter GATT service",
                          (unsigned)m.mtu);
        break;
      case BleCentralEvent::Subscribed:
        sm_ctrl_ble_event(SM_BLE_C2_SUBSCRIBED, 0, nullptr, 0, now_ms());
        subscribed = true;
        set_ble_stage(SM_UI_BLE_SUBSCRIBED);
        sm_app_set_status("BLE C2 subscribed; running BTP + PASE");
        break;
      case BleCentralEvent::Indication:
        sm_ctrl_ble_event(SM_BLE_C1_WRITE, 0, m.frag, m.frag_len, now_ms());
        break;
      case BleCentralEvent::Disconnected:
        sm_ctrl_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());
        subscribed = false;
        sm_app_set_status("BLE link dropped during commissioning");
        break;
      case BleCentralEvent::ScanTimeout:
        sm_app_set_status("no device advertising discriminator %u", (unsigned)op.discriminator);
        return false;
      }
    }
    drain_mdns_to_cache(); // announce は ConnectNetwork 成功直後に流れる(取り逃し防止)
    // シムが積んだ BTP フラグメントを C1 write で送る。
    // **C2 subscribe 完了まで write しない**(C1 handle は GATT 発見の完了で確定する。
    //  CONNECTED 直後の handshake request はシムが退避しているので取りこぼさない。F7b 実機バグ)。
    size_t n;
    while (subscribed && (n = sm_ctrl_ble_poll(now_ms(), frag, sizeof(frag))) > 0) {
      if (!sm_ble_central_write_c1(frag, n)) {
        ESP_LOGW(TAG, "C1 write failed (%u bytes)", (unsigned)n);
      }
    }
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (ev.kind == SM_CTRL_EV_PAIR_PHASE) {
        ESP_LOGI(TAG, "  BLE phase %u", ev.phase);
        sm_ui_snapshot_t *s = sm_app_lock();
        s->pair_phase = ev.phase;
        s->ble_stage = SM_UI_BLE_COMMISSIONING;
        sm_app_unlock();
      } else if (ev.kind == SM_CTRL_EV_BLE_DONE) {
        ESP_LOGI(TAG, "BLE_DONE (AddNOC + network credentials + ConnectNetwork over BTP)");
        done = true;
      } else if (ev.kind == SM_CTRL_EV_PAIR_FAILED) {
        sm_app_set_status("BLE commissioning failed (phase=%u status=%u)", ev.phase, ev.status);
        return false;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  if (!done) {
    sm_app_set_status("BLE commissioning timed out (stage kept in the log)");
  }
  return done;
}

void do_pair_ble(const sm_ui_op_t &op) {
  const bool thread_kind = (op.via == SM_UI_VIA_BLE_THREAD);
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 1;
    s->pair_phase = 0;
    s->ble_stage = SM_UI_BLE_SCANNING;
    sm_app_unlock();
  }
  if (sm_ble_central_state() != SM_BLE_HOST_READY) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    sm_app_set_status("BLE host is not ready (state=%u): check the C6 firmware / SDIO link",
                      (unsigned)sm_ble_central_state());
    return;
  }

  // --- 資格情報(ダイアログでは入力させない。Tab5 が既に持っているものを使う)---
  uint8_t dataset[254];
  size_t dataset_len = 0;
  if (thread_kind) {
    char hex[SM_UI_DATASET_HEX_CAP];
    size_t hn = sm_ot_hub_dataset_hex(hex, sizeof(hex));
    if (hn == 0 || (hn % 2) != 0 || hn / 2 > sizeof(dataset)) {
      sm_ui_snapshot_t *s = sm_app_lock();
      s->pair_state = 3;
      s->ble_stage = SM_UI_BLE_FAILED;
      sm_app_unlock();
      sm_app_set_status("no active Thread dataset to hand to the device");
      return;
    }
    for (size_t i = 0; i < hn / 2; ++i) {
      auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
      };
      int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
      if (hi < 0 || lo < 0) {
        sm_app_set_status("the active dataset hex is malformed");
        return;
      }
      dataset[i] = (uint8_t)((hi << 4) | lo);
    }
    dataset_len = hn / 2;
  } else if (CONFIG_SM_WIFI_SSID[0] == '\0') {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    sm_app_set_status("BLE->WiFi needs CONFIG_SM_WIFI_SSID (the device joins the same AP)");
    return;
  }

  // シムが直前の操作(周期 read の CASE 等)を畳み終えるまで busy(rc=-2)になり得る。
  // 30 秒までポンプを回しながらリトライする(実機 livelock の学び)。
  int rc = -1;
  const uint64_t start_until = now_ms() + 30000;
  for (;;) {
    if (thread_kind) {
      rc = sm_ctrl_ble_pair_start(op.node_id, op.passcode, 1 /*thread*/, dataset, dataset_len,
                                  nullptr, 0, now_ms());
    } else {
      rc = sm_ctrl_ble_pair_start(op.node_id, op.passcode, 0 /*wifi*/,
                                  (const uint8_t *)CONFIG_SM_WIFI_SSID, strlen(CONFIG_SM_WIFI_SSID),
                                  (const uint8_t *)CONFIG_SM_WIFI_PASSWORD,
                                  strlen(CONFIG_SM_WIFI_PASSWORD), now_ms());
    }
    if (rc == 0 || now_ms() >= start_until) {
      break;
    }
    sm_app_set_status("controller busy; waiting to start BLE pairing ...");
    pump_once(g_udp, 200); // 進行中の交換を進めて畳ませる
    sm_ctrl_event_t drop;
    while (sm_ctrl_take_event(&drop)) {
    }
  }
  if (rc != 0) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    sm_app_set_status("sm_ctrl_ble_pair_start rejected (rc=%d; busy?)", rc);
    return;
  }

  // 前回セッションの残骸イベント(Disconnected 等)を捨てる。ドレインしないと
  // 新しいペアリングの直後に古い DISCONNECTED がシムへ流れて即死する(実機で発覚)。
  {
    QueueHandle_t q = sm_ble_central_queue();
    BleCentralMsg stale;
    while (q != nullptr && xQueueReceive(q, &stale, 0) == pdTRUE) {
    }
  }

  // WiFi kind: mDNS ソケットを **BLE 開始前**に開いて join しておく。デバイスの
  // operational announce は ConnectNetwork 成功直後(= BLE_DONE より前)に流れるので、
  // BLE フェーズ中から聞いていないと取り逃す(実機 + PC 側パケット観測で確定)。
  g_mdns_cache_n = 0;
  g_mdns_fd = thread_kind ? -1 : open_mdns_5353();

  sm_app_set_status("BLE scan for discriminator %u (node %016llx, %s credentials) ...",
                    (unsigned)op.discriminator, (unsigned long long)op.node_id,
                    thread_kind ? "Thread" : "WiFi");
  bool ok = sm_ble_central_start(op.discriminator, 60000);
  if (ok) {
    ok = drive_ble_phase(op, 120000);
  } else {
    sm_app_set_status("failed to start the BLE scan");
  }

  // BLE は用済み(成功でも失敗でも切る)。
  sm_ble_central_disconnect();
  sm_ble_central_stop();
  sm_ctrl_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());

  if (!ok) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    if (g_mdns_fd >= 0) {
      close(g_mdns_fd);
      g_mdns_fd = -1;
    }
    return;
  }

  // --- handoff: 運用アドレスを解決してシムを CASE over UDP へ載せ替える ---
  set_ble_stage(SM_UI_BLE_HANDOFF);
  bool resolved = false;
  if (thread_kind) {
    sm_app_set_status("BLE done; waiting for the device to register in SRP ...");
    uint8_t ip[16];
    for (int i = 0; i < 60 && !resolved; ++i) { // 最大 ~120 秒
      if (sm_ot_hub_srp_lookup(op.node_id, ip)) {
        resolved = feed_addr_as_mdns(op.node_id, ip, CONFIG_SM_TARGET_PORT);
        if (!resolved) {
          // 最低限ノード帳だけでも直す(handoff は再開しない = 既知の制約)。
          sm_addr_t a = {};
          a.is_v6 = true;
          memcpy(a.ip, ip, 16);
          a.port = CONFIG_SM_TARGET_PORT;
          a.scope_id = sm_ot_hub_netif_index();
          sm_ctrl_set_node_addr(op.node_id, &a);
          ESP_LOGE(TAG, "SRP address found but the shim did not resume the handoff");
          break;
        }
      } else {
        vTaskDelay(pdMS_TO_TICKS(2000));
      }
    }
  } else {
    uint32_t idx = sm_wifi_netif_index();
    sm_app_set_status("BLE done; resolving the device over mDNS (WiFi) ...");
    drain_mdns_to_cache(); // BLE フェーズの取りこぼしを最終回収
    resolved = replay_mdns_cache();
    if (!resolved) {
      resolved = resolve_via_mdns(op.node_id, idx, 20000);
    }
    // 最終フォールバック(ESP32 ファミリ限定の割り切り): BLE ピアの BT MAC から
    // WiFi MAC(-2)→ EUI-64 を導出し、運用アドレスを直接与える。SLAAC(EUI-64)
    // 前提。Tab5 自身が GUA を持っていれば同一 prefix の GUA(再起動後も有効)、
    // 無ければリンクローカル(send_sm の fe80 → WiFi netif 補完で届く)。
    if (!resolved && g_ble_peer_mac_ok) {
      uint8_t eui[8];
      derive_wifi_eui64(g_ble_peer_mac, eui);
      sm_wifi_status_t w = {};
      sm_wifi_get_status(&w);
      uint8_t ip[16] = {};
      if (w.gua[0] != 0 && inet_pton(AF_INET6, w.gua, ip) == 1) {
        memcpy(ip + 8, eui, 8); // 自分の GUA の上位 64bit + ピアの EUI-64
      } else {
        ip[0] = 0xfe;
        ip[1] = 0x80;
        memcpy(ip + 8, eui, 8);
      }
      char ips[48] = {0};
      inet_ntop(AF_INET6, ip, ips, sizeof(ips));
      ESP_LOGW(TAG, "mDNS silent; trying the derived address %s (EUI-64 from the BLE peer MAC)",
               ips);
      sm_app_set_status("mDNS silent; trying derived address %s", ips);
      resolved = feed_addr_as_mdns(op.node_id, ip, CONFIG_SM_TARGET_PORT);
    }
  }
  if (g_mdns_fd >= 0) {
    close(g_mdns_fd);
    g_mdns_fd = -1;
  }

  if (!resolved) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    sm_app_set_status("handoff failed: could not resolve the operational address of %016llx",
                      (unsigned long long)op.node_id);
    // **シムの詰まり解消**(実機で発見): 解決に失敗すると Activity::BleHandoff が
    // 保留のまま残り、以降の pair/invoke が rc=-2 で永久に弾かれる(abort API が無い)。
    // ダミーの運用アドレス(::1)を「解決成功」として給餌し、CASE を即失敗させて
    // 状態機械を畳ませる。PAIR_FAILED は run_until で回収して捨てる。
    static const uint8_t kLoopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (feed_addr_as_mdns(op.node_id, kLoopback, CONFIG_SM_TARGET_PORT)) {
      sm_ctrl_event_t ev2;
      run_until(g_udp, 30000, ev2, term_pair);
      ESP_LOGW(TAG, "handoff aborted via loopback CASE (shim unwedged)");
    } else {
      ESP_LOGE(TAG, "could not unwedge the shim; further ops will be rejected until reboot");
    }
    return;
  }

  // --- CASE over UDP + CommissioningComplete(ここから先は既存の UDP pump)---
  set_ble_stage(SM_UI_BLE_CASE);
  refresh_node_addr_view(op.node_id);
  sm_app_set_status("operational address resolved; running CASE over UDP");
  sm_ctrl_event_t ev;
  bool complete = run_until(g_udp, 120000, ev, term_pair) && ev.kind == SM_CTRL_EV_PAIR_COMPLETE;
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = complete ? 2 : 3;
    s->ble_stage = complete ? SM_UI_BLE_DONE : SM_UI_BLE_FAILED;
    sm_app_unlock();
  }
  if (complete) {
    sm_app_set_status("PAIR COMPLETE (BLE -> %s) node=%016llx", thread_kind ? "Thread" : "WiFi",
                      (unsigned long long)op.node_id);
    rebuild_node_list();
    do_read_onoff(op.node_id, true, 20000);
  } else {
    sm_app_set_status("BLE handoff CASE failed (phase=%u status=%u)", ev.phase, ev.status);
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
      case SM_UI_OP_PAIR_BLE:
        do_pair_ble(op);
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
      refresh_wifi_status();
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
    //
    // **落ちているノードには 2 分のバックオフ**を入れる(実機で発見した livelock:
    // 死んだノードへの read は CASE 確立を毎回試み、MRP が諦めるまで ~20 秒シムを
    // 塞ぐ。10 秒周期でそれを繰り返すとシムがほぼ常時 busy になり、UI の操作
    // (特に sm_ctrl_ble_pair_start)が rc=-2 で弾かれ続ける)。
    if (now >= next_poll) {
      next_poll = now + 10000;
      static uint64_t backoff_until[SM_UI_MAX_NODES] = {};
      sm_ui_snapshot_t *s = sm_app_lock();
      size_t count = s->node_count;
      sm_app_unlock();
      if (count > 0) {
        // バックオフ中でないノードを 1 件選ぶ(全員バックオフ中ならスキップ)。
        uint64_t id = 0;
        size_t slot = 0;
        for (size_t tries = 0; tries < count; ++tries) {
          size_t idx = poll_index % count;
          poll_index = (poll_index + 1) % count;
          if (idx < SM_UI_MAX_NODES && now < backoff_until[idx]) {
            continue;
          }
          sm_ui_snapshot_t *s2 = sm_app_lock();
          id = idx < s2->node_count ? s2->nodes[idx].node_id : 0;
          sm_app_unlock();
          slot = idx;
          break;
        }
        if (id != 0) {
          set_node_busy(id, true);
          bool ok = do_read_onoff(id, true, 10000);
          set_node_busy(id, false);
          if (slot < SM_UI_MAX_NODES) {
            backoff_until[slot] = ok ? 0 : now + 120000;
            if (!ok) {
              set_node_note(id, "unreachable (retry in 2min)");
            }
          }
        }
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
