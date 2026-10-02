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

// BTP handshake の MTU 上書き(-1 = リンク MTU をそのまま使う)。コンソール blemtu で設定。
int g_ble_hs_mtu_override = -1;
#include <errno.h>
#include <lwip/inet.h>

#include "simple_matter.h"

#include "app_state.hpp"
#include "ble_central.hpp"
#include "esp_system.h"
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

// --- pump 停滞の計測(docs/design/p4-thread-controller.md §16.6 の追記) ---
// 定常ループの各ステップ所要時間を測り、閾値超過で WARN する。実機で観測された
// 「191 秒間 pump が無反応」の犯人をログから特定するための足場。
// オーバーヘッドは 1 ステップあたり esp_timer_get_time() 2 回 + 数命令。
struct LoopProfile {
  uint64_t start_us = 0;
  uint64_t worst_us = 0;
  const char *worst_step = "-";
  char detail[112] = {0}; // 1ms 以上のステップの内訳 "name=ms,..."
  size_t detail_len = 0;

  void begin() {
    worst_us = 0;
    worst_step = "-";
    detail[0] = '\0';
    detail_len = 0;
    start_us = (uint64_t)esp_timer_get_time();
  }
  void add(const char *name, uint64_t us) {
    if (us > worst_us) {
      worst_us = us;
      worst_step = name;
    }
    if (us < 1000 || detail_len + 1 >= sizeof(detail)) {
      return;
    }
    int n = snprintf(detail + detail_len, sizeof(detail) - detail_len, "%s%s=%llu",
                     detail_len != 0 ? "," : "", name, (unsigned long long)(us / 1000));
    if (n < 0) {
      return;
    }
    detail_len += (size_t)n;
    if (detail_len >= sizeof(detail)) {
      detail_len = sizeof(detail) - 1; // 切り詰められた
    }
  }
};

LoopProfile g_loop_prof;

// 個々のステップ。スコープを抜けた時点(continue / break 経由でも)で計測される。
class StepTimer {
public:
  StepTimer(const char *name, uint32_t warn_ms)
      : name_(name), warn_us_((uint64_t)warn_ms * 1000ULL),
        t0_((uint64_t)esp_timer_get_time()) {}
  ~StepTimer() {
    uint64_t us = (uint64_t)esp_timer_get_time() - t0_;
    g_loop_prof.add(name_, us);
    if (us > warn_us_) {
      ESP_LOGW(TAG, "pump: slow step=%s ms=%llu", name_, (unsigned long long)(us / 1000));
    }
  }
  StepTimer(const StepTimer &) = delete;
  StepTimer &operator=(const StepTimer &) = delete;

private:
  const char *name_;
  uint64_t warn_us_;
  uint64_t t0_;
};

// 1 周回全体。5 秒超なら内訳付きでまとめて WARN。
class LoopTimer {
public:
  LoopTimer() { g_loop_prof.begin(); }
  ~LoopTimer() {
    uint64_t us = (uint64_t)esp_timer_get_time() - g_loop_prof.start_us;
    if (us > 5000000ULL) {
      ESP_LOGW(TAG, "pump: slow loop ms=%llu worst=%s ms=%llu steps=[%s]",
               (unsigned long long)(us / 1000), g_loop_prof.worst_step,
               (unsigned long long)(g_loop_prof.worst_us / 1000), g_loop_prof.detail);
    }
  }
  LoopTimer(const LoopTimer &) = delete;
  LoopTimer &operator=(const LoopTimer &) = delete;
};

// ステップの警告閾値。UI op は run_until で秒単位かかるのが正常なので緩める。
constexpr uint32_t STEP_WARN_MS = 1000;
constexpr uint32_t OP_WARN_MS = 20000;

const char *op_step_name(uint8_t kind) {
  switch (kind) {
  case SM_UI_OP_TOGGLE:
    return "op:toggle";
  case SM_UI_OP_READ_ONOFF:
    return "op:read";
  case SM_UI_OP_REFRESH_ADDR:
    return "op:refresh_addr";
  case SM_UI_OP_PAIR:
    return "op:pair";
  case SM_UI_OP_PAIR_BLE:
    return "op:pair_ble";
  case SM_UI_OP_SET_ADDR:
    return "op:set_addr";
  case SM_UI_OP_OPEN_WINDOW:
    return "op:open_window";
  case SM_UI_OP_REVOKE_WINDOW:
    return "op:revoke_window";
  case SM_UI_OP_FORGET:
    return "op:forget";
  case SM_UI_OP_DNS_LOOKUP:
    return "op:dns_lookup";
  default:
    return "op:?";
  }
}
constexpr const char *SM_NVS_NAMESPACE = "smctl";
// ノード種別のキャッシュ(T4、§12.3 の 1)。key = NodeId の hex(下位 60bit、15 桁 =
// NVS のキー長上限)、値 = 下位 4bit が sm_ui_node_kind_t、上位 4bit が
// sm_ui_transport_t(トランスポート追加前のエントリは上位 0 = UNKNOWN → 再取得)。
constexpr const char *SM_UI_NVS_NAMESPACE = "smui";

// NetworkCommissioning(EP0 / 0x0031)の FeatureMap。bit0=WiFi bit1=Thread bit2=Ethernet。
constexpr uint16_t EP_ROOT = 0;
constexpr uint32_t CL_NETWORK_COMMISSIONING = 0x0031;
constexpr uint32_t ATTR_FEATURE_MAP = 0xFFFC;

// OnOff クラスタ。
constexpr uint16_t EP_ONOFF = 1;
constexpr uint32_t CL_ONOFF = 0x0006;
constexpr uint32_t CMD_TOGGLE = 0x02;
constexpr uint32_t ATTR_ONOFF = 0x0000;

// AdministratorCommissioning(EP0 / 0x003C。T9、§17.3)。WindowStatus は
// 0=閉 1=ECM 2=BC。窓を開く / 閉じるのはシムの専用 API 経由(timed invoke が要る)。
constexpr uint32_t CL_ADMIN_COMM = 0x003C;
constexpr uint32_t ATTR_WINDOW_STATUS = 0x0000;

// 空気質センサ(airq-sensor、docs/design/airq-port.md §A1)の読み出しパス。
// **f32 の 2 本(CO2 / PM2.5)は value_u64 の下位 32bit にビットパターンが載る**
// (シム §12.2。型情報は ABI に無いので「このパスは f32」を C++ 側が知っている前提)。
struct SensorAttrPath {
  uint16_t ep;
  uint32_t cluster;
  uint32_t attr;
  const char *name;
};
constexpr SensorAttrPath SENSOR_ATTRS[SM_UI_SLOT_COUNT] = {
    {1, 0x005B, 0x0000, "AirQuality"}, // enum8 0..6
    {1, 0x040D, 0x0000, "CO2"},        // f32 ppm
    {1, 0x042A, 0x0000, "PM2.5"},      // f32 µg/m³
    {2, 0x0402, 0x0000, "Temp"},       // i16 ×0.01 ℃
    {3, 0x0405, 0x0000, "Humidity"},   // u16 ×0.01 %
};

// value_u64 の下位 32bit を f32 に戻す(§12.2 の C++ 側契約。memcpy 経由)。
float f32_from_value(uint64_t v) {
  uint32_t bits = (uint32_t)v;
  float f;
  memcpy(&f, &bits, sizeof(f));
  return f;
}

uint64_t now_ms() { return (uint64_t)esp_timer_get_time() / 1000ull; }

// ---- T8: ノード別の購読状態(§16.3)----
//
// 添字は **スナップショットの行 index**(g_backoff_until と同じ流儀)。
// ACTIVE の行は周期 read を止め、表示はデバイス発レポート(SM_CTRL_EV_REPORT)で
// 更新する。購読が切れたら(SM_CTRL_EV_SUBSCRIPTION_LOST)NONE に戻り、次の
// poll tick で再購読を試みつつ従来 read で表示を賄う。
enum SubState : uint8_t {
  SUB_NONE = 0,
  SUB_ACTIVE = 1,
};
uint8_t g_sub[SM_UI_MAX_NODES] = {};
// 購読の再試行を控える時刻(失敗時 2 分。read のバックオフとは独立)。
uint64_t g_sub_retry_until[SM_UI_MAX_NODES] = {};

// ---- T8b/P5(§16.6): 購読喪失を受けたノードの「即再購読」キュー ----
//
// SM_CTRL_EV_SUBSCRIPTION_LOST を受けた時点で node_id を積み、定常ループの
// 次の周回(UI op が無いとき)で 10 秒 tick を待たずに再購読する。行 index は
// ノード表の増減で動くので **添字ではなく node_id** を持つ(0 = 空きスロット)。
// 1 周につき 1 ノードだけ処理する(do_subscribe_node は CASE 込みで数秒かかる)。
uint64_t g_resub_now[SM_UI_MAX_NODES] = {};

void resub_now_push(uint64_t node_id) {
  if (node_id == 0) {
    return;
  }
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_resub_now[i] == node_id) {
      return; // 既に積んである
    }
  }
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_resub_now[i] == 0) {
      g_resub_now[i] = node_id;
      return;
    }
  }
  // 満杯(= 全ノードが LOST)。従来の 10 秒 tick が拾うので落として構わない。
}

// 先頭の 1 件を取り出す(無ければ 0)。
uint64_t resub_now_pop() {
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_resub_now[i] != 0) {
      uint64_t id = g_resub_now[i];
      g_resub_now[i] = 0;
      return id;
    }
  }
  return 0;
}

void resub_now_clear(uint64_t node_id) {
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_resub_now[i] == node_id) {
      g_resub_now[i] = 0;
    }
  }
}

// 非同期イベント(REPORT / SUBSCRIPTION_LOST)をスナップショットへ反映する。
// **イベントを捨てる全ての場所からこれを通す**(op 進行中に届いたレポートを落とさない)。
// 実体は「スナップショット更新ヘルパ」節の後(set_node_* を使うため)。
bool consume_async_event(const sm_ctrl_event_t &ev);

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
  int rc = sendto(fd, buf, len, 0, (struct sockaddr *)&m, sizeof(m));
  if (rc < 0) {
    // 送信失敗は握りつぶさない(2026-08-25 不達調査: 宛先・scope・errno を残す)。
    char ip[48] = {0};
    inet_ntop(AF_INET6, &m.sin6_addr, ip, sizeof(ip));
    ESP_LOGW(TAG, "sendto %u B -> [%s]:%u scope=%lu failed: errno=%d", (unsigned)len, ip,
             (unsigned)dst.port, (unsigned long)m.sin6_scope_id, errno);
  }
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
      // T8(§16.3): op 進行中に届いた購読レポート / 購読喪失は捨てない。
      // 終端判定は kind ベースなので REPORT が混ざっても壊れない。
      consume_async_event(ev);
      if (is_terminal(ev)) {
        out_ev = ev;
        if (ev.kind == SM_CTRL_EV_INVOKE_FAILED || ev.kind == SM_CTRL_EV_READ_FAILED ||
            ev.kind == SM_CTRL_EV_PAIR_FAILED) {
          ESP_LOGW(TAG, "run_until: terminal FAILED kind=%d status=%u phase=%u node=%016llx",
                   (int)ev.kind, (unsigned)ev.status, (unsigned)ev.phase,
                   (unsigned long long)ev.node_id);
        }
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
      // pump が諦めるならシム側の進行中 op も畳む(不達ノード宛 CASE が内部で
      // 60 秒粘って全操作を busy にする実機症状の対処)。
      int32_t ab = sm_ctrl_abort_op();
      if (ab > 0) {
        ESP_LOGW(TAG, "run_until timeout: aborted the in-flight controller op");
      }
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
// T9(§17.4): コミッショニングウィンドウを開く op の終端。
bool term_window(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_WINDOW_OPENED || e.kind == SM_CTRL_EV_WINDOW_FAILED;
}
// T8: 購読確立の終端(プライミングの REPORT 群はこの前に流れてくる)。
bool term_subscribe(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_SUBSCRIBE_DONE || e.kind == SM_CTRL_EV_SUBSCRIBE_FAILED;
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

// ---- ノード種別(T4)----

uint8_t node_kind(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  uint8_t k = i < SM_UI_MAX_NODES ? s->nodes[i].kind : (uint8_t)SM_UI_KIND_UNKNOWN;
  sm_app_unlock();
  return k;
}

void set_node_kind(uint64_t node_id, uint8_t kind) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].kind = kind;
  }
  sm_app_unlock();
}

// NVS キー(15 文字上限)。NodeId 下位 60bit の hex。
void kind_key(uint64_t node_id, char out[16]) {
  snprintf(out, 16, "%015llx", (unsigned long long)(node_id & 0x0FFFFFFFFFFFFFFFull));
}

// キャッシュ 1 バイト = (transport << 4) | kind。無い / 壊れている項目は UNKNOWN。
void node_cache_get(uint64_t node_id, uint8_t *kind, uint8_t *transport) {
  *kind = SM_UI_KIND_UNKNOWN;
  *transport = SM_UI_TRANSPORT_UNKNOWN;
  char k[16];
  kind_key(node_id, k);
  nvs_handle_t h;
  if (nvs_open(SM_UI_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
    return;
  }
  uint8_t v = 0;
  if (nvs_get_u8(h, k, &v) != ESP_OK) {
    v = 0;
  }
  nvs_close(h);
  const uint8_t kd = (uint8_t)(v & 0x0F);
  const uint8_t tp = (uint8_t)(v >> 4);
  if (kd == SM_UI_KIND_UNKNOWN || kd > SM_UI_KIND_SENSOR) {
    return; // 種別が無いエントリは丸ごと無効(トランスポートだけは持たない)
  }
  *kind = kd;
  *transport = tp > SM_UI_TRANSPORT_ETH ? (uint8_t)SM_UI_TRANSPORT_UNKNOWN : tp;
}

// kind == UNKNOWN ならエントリを消す(⟳ の再検出 / forget)。
void node_cache_set(uint64_t node_id, uint8_t kind, uint8_t transport) {
  char k[16];
  kind_key(node_id, k);
  nvs_handle_t h;
  if (nvs_open(SM_UI_NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
    return;
  }
  if (kind == SM_UI_KIND_UNKNOWN) {
    nvs_erase_key(h, k);
  } else {
    nvs_set_u8(h, k, (uint8_t)((transport << 4) | (kind & 0x0F)));
  }
  nvs_commit(h);
  nvs_close(h);
}

// ---- トランスポート(WiFi / Thread / Ethernet)----

uint8_t node_transport(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  uint8_t t = i < SM_UI_MAX_NODES ? s->nodes[i].transport : (uint8_t)SM_UI_TRANSPORT_UNKNOWN;
  sm_app_unlock();
  return t;
}

void set_node_transport(uint64_t node_id, uint8_t transport) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].transport = transport;
  }
  sm_app_unlock();
}

// トランスポート取得の再試行を控える時刻(行 index 別。読めないデバイスへ毎 tick
// 打たないため。rebuild_node_list で 0 に戻る)。
uint64_t g_transport_retry_until[SM_UI_MAX_NODES] = {};

// センサ値 1 件を書き込む(has_* も併せて更新。null / 失敗は has=false)。
void set_node_sensor(uint64_t node_id, uint8_t slot, bool has, uint64_t raw) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    sm_ui_node_t &n = s->nodes[i];
    switch (slot) {
    case SM_UI_SLOT_AQ:
      n.has_aq = has ? 1 : 0;
      n.aq = has ? (uint8_t)(raw & 0xFF) : 0;
      break;
    case SM_UI_SLOT_CO2:
      n.has_co2 = has ? 1 : 0;
      n.co2 = has ? f32_from_value(raw) : 0.0f;
      break;
    case SM_UI_SLOT_PM25:
      n.has_pm25 = has ? 1 : 0;
      n.pm25 = has ? f32_from_value(raw) : 0.0f;
      break;
    case SM_UI_SLOT_TEMP:
      // i16 ×0.01 ℃(u64 に符号拡張済みの値が載る)。
      n.has_temp = has ? 1 : 0;
      n.temp_c100 = has ? (int32_t)(int16_t)(raw & 0xFFFF) : 0;
      break;
    case SM_UI_SLOT_HUM:
      n.has_hum = has ? 1 : 0;
      n.hum_p100 = has ? (int32_t)(uint16_t)(raw & 0xFFFF) : 0;
      break;
    default:
      break;
    }
  }
  sm_app_unlock();
}

// センサ値の最終成功時刻を打つ(T6 §14.2。UI は snapshot の now_ms との差を表示する)。
void mark_node_updated(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].last_update_ms = now_ms();
  }
  sm_app_unlock();
}

// ---- T8: 購読状態(§16.3)----

// 行 index を引く(見つからなければ SM_UI_MAX_NODES)。
size_t slot_of(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  sm_app_unlock();
  return i;
}

void set_node_subscribed(uint64_t node_id, bool on) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    s->nodes[i].subscribed = on ? 1 : 0;
  }
  sm_app_unlock();
}

// 購読状態を NONE に落とす(喪失 / ⟳ / 明示解除)。
void mark_unsubscribed(uint64_t node_id, uint64_t retry_until) {
  size_t slot = slot_of(node_id);
  if (slot < SM_UI_MAX_NODES) {
    g_sub[slot] = SUB_NONE;
    g_sub_retry_until[slot] = retry_until;
  }
  set_node_subscribed(node_id, false);
}

// SM_CTRL_EV_REPORT / SM_CTRL_EV_SUBSCRIPTION_LOST をスナップショットへ反映する。
// 戻り値 = このイベントを購読の文脈で消費したか(ログ用。呼び出し側は無視してよい)。
bool consume_async_event(const sm_ctrl_event_t &ev) {
  if (ev.kind == SM_CTRL_EV_SUBSCRIPTION_LOST) {
    ESP_LOGW(TAG, "sub: lost node=%016llx id=%llu", (unsigned long long)ev.node_id,
             (unsigned long long)ev.value_u64);
    mark_unsubscribed(ev.node_id, 0); // 次の poll tick で即再試行してよい
    set_node_note(ev.node_id, "subscription lost");
    // T8b/P5(§16.6): tick を待たず、次の周回で再購読する。
    resub_now_push(ev.node_id);
    return true;
  }
  if (ev.kind != SM_CTRL_EV_REPORT) {
    return false;
  }
  // OnOff(照明)。
  if (ev.endpoint == EP_ONOFF && ev.cluster == CL_ONOFF && ev.attribute == ATTR_ONOFF) {
    int8_t v = ev.value_is_null ? (int8_t)-1 : (int8_t)(ev.value_u64 != 0 ? 1 : 0);
    set_node_onoff(ev.node_id, v);
    mark_node_updated(ev.node_id);
    ESP_LOGI(TAG, "sub: report node=%016llx OnOff=%s", (unsigned long long)ev.node_id,
             v < 0 ? "null" : (v ? "On" : "Off"));
    return true;
  }
  // センサ 5 属性(f32 の 2 本は set_node_sensor が f32_from_value で戻す)。
  for (uint8_t slot = 0; slot < SM_UI_SLOT_COUNT; ++slot) {
    const SensorAttrPath &p = SENSOR_ATTRS[slot];
    if (ev.endpoint == p.ep && ev.cluster == p.cluster && ev.attribute == p.attr) {
      set_node_sensor(ev.node_id, slot, !ev.value_is_null, ev.value_u64);
      mark_node_updated(ev.node_id);
      ESP_LOGI(TAG, "sub: report node=%016llx %s raw=0x%llx%s", (unsigned long long)ev.node_id,
               p.name, (unsigned long long)ev.value_u64, ev.value_is_null ? " (null)" : "");
      return true;
    }
  }
  ESP_LOGW(TAG, "sub: report for an unknown path ep%u/0x%04lx/0x%04lx (node=%016llx)",
           (unsigned)ev.endpoint, (unsigned long)ev.cluster, (unsigned long)ev.attribute,
           (unsigned long long)ev.node_id);
  return true;
}

void clear_node_sensors(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  if (i < SM_UI_MAX_NODES) {
    sm_ui_node_t &n = s->nodes[i];
    n.has_aq = n.has_co2 = n.has_pm25 = n.has_temp = n.has_hum = 0;
    n.last_update_ms = 0;
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
    // 種別は NVS キャッシュから引く(無ければ UNKNOWN = 初回 poll で検出する)。
    node_cache_get(ids[i], &row.kind, &row.transport);
    if (present) {
      format_addr(a, row.addr, sizeof(row.addr));
    } else {
      snprintf(row.addr, sizeof(row.addr), "-");
    }
    for (size_t j = 0; j < old_count; ++j) {
      if (old[j].node_id == ids[i]) {
        // 既知の表示状態(on/off・note・センサ値)は NodeId が同じなら引き継ぐ。
        uint64_t id = row.node_id;
        char addr[64];
        memcpy(addr, row.addr, sizeof(addr));
        uint8_t kind = row.kind != SM_UI_KIND_UNKNOWN ? row.kind : old[j].kind;
        uint8_t transport =
            row.transport != SM_UI_TRANSPORT_UNKNOWN ? row.transport : old[j].transport;
        row = old[j];
        row.node_id = id;
        memcpy(row.addr, addr, sizeof(addr));
        row.kind = kind;
        row.transport = transport;
        row.busy = 0;
        break;
      }
    }
    ++s->node_count;
  }
  // T8: 行 index が動きうるので、購読状態はシムに聞き直して張り直す
  //(g_sub / g_sub_retry_until は行 index 添字。§16.3)。
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    bool active = i < s->node_count && sm_ctrl_is_subscribed(s->nodes[i].node_id);
    g_sub[i] = active ? (uint8_t)SUB_ACTIVE : (uint8_t)SUB_NONE;
    g_sub_retry_until[i] = 0;
    g_transport_retry_until[i] = 0;
    if (i < s->node_count) {
      s->nodes[i].subscribed = active ? 1 : 0;
    }
  }
  sm_app_unlock();
  ESP_LOGI(TAG, "node list: %u shown / %u in controller node book", (unsigned)n, (unsigned)known);
}

void refresh_thread_status() {
  sm_ot_status_t st;
  sm_ot_hub_get_status(&st);
  sm_ui_snapshot_t *s = sm_app_lock();
  s->now_ms = now_ms(); // T6: UI の「updated N s ago」の基準時刻
  s->ot_mode = st.mode;
  s->ot_started = st.started;
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
bool operational_label(uint64_t node_id, char *out, size_t cap);

// quiet = 周期ポーリング(ステータス行を汚さない)。timeout_ms は CASE 込みの上限。
// 周期 poll の失敗バックオフ(行 index 別)。成功した操作はこれを解除する。
uint64_t g_backoff_until[SM_UI_MAX_NODES] = {};

void clear_backoff(uint64_t node_id) {
  sm_ui_snapshot_t *s = sm_app_lock();
  size_t i = node_index(s, node_id);
  sm_app_unlock();
  if (i < SM_UI_MAX_NODES) {
    g_backoff_until[i] = 0;
  }
}

// 操作開始の共通手順: シムのイベント残骸を捨ててから開始し、busy(-10)なら
// 最大 5 秒ポンプを回して再試行する(残骸イベント誤認 + 直前 op の畳み待ち。実機の学び)。
template <typename F> int32_t start_op_clean(F start) {
  int32_t rc = -10;
  const uint64_t until = now_ms() + 5000;
  for (;;) {
    sm_ctrl_event_t stale;
    while (sm_ctrl_take_event(&stale)) {
      consume_async_event(stale); // T8: 残骸に混ざった購読レポートは捨てない
    }
    rc = start();
    if (rc != -10 || now_ms() >= until) {
      return rc;
    }
    pump_once(g_udp, 200);
  }
}

bool do_read_onoff(uint64_t node_id, bool quiet, uint64_t timeout_ms) {
  if (start_op_clean([&] {
        return sm_ctrl_read_scalar(node_id, EP_ONOFF, CL_ONOFF, ATTR_ONOFF, now_ms());
      }) != 0) {
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

// 任意パスのスカラ read。成功なら *out に生の value_u64、*out_null に null 判定。
bool do_read_scalar(uint64_t node_id, const SensorAttrPath &p, uint64_t timeout_ms, uint64_t *out,
                    bool *out_null) {
  // **開始前にシムのイベント残骸を捨てる**(実機で発覚): pump が run_until の
  // タイムアウトで諦めた後にシム内の read が完了すると READ_DONE がキューに残り、
  // 次の read がそれを自分の結果と誤認する(その裏で本物の read は進行中 → 続く
  // 開始が -10 busy)。Idle でないと開始できないので、ここで捨てて良いのは残骸だけ。
  int32_t src = -10;
  const uint64_t until = now_ms() + 5000;
  for (;;) {
    sm_ctrl_event_t stale;
    while (sm_ctrl_take_event(&stale)) {
      consume_async_event(stale); // T8: 同上
    }
    src = sm_ctrl_read_scalar(node_id, p.ep, p.cluster, p.attr, now_ms());
    if (src != -10 || now_ms() >= until) {
      break;
    }
    pump_once(g_udp, 200); // 進行中の op を畳ませてから再試行
  }
  if (src != 0) {
    ESP_LOGW(TAG, "read ep%u/0x%04lx/0x%04lx: start rejected rc=%ld", (unsigned)p.ep,
             (unsigned long)p.cluster, (unsigned long)p.attr, (long)src);
    return false;
  }
  sm_ctrl_event_t ev;
  if (!run_until(g_udp, timeout_ms, ev, term_read) || ev.kind != SM_CTRL_EV_READ_DONE) {
    ESP_LOGW(TAG, "read ep%u/0x%04lx/0x%04lx: %s (kind=%d status=%u)", (unsigned)p.ep,
             (unsigned long)p.cluster, (unsigned long)p.attr,
             ev.kind == SM_CTRL_EV_READ_FAILED ? "READ_FAILED" : "timeout/other", (int)ev.kind,
             ev.status);
    return false;
  }
  *out = ev.value_u64;
  *out_null = ev.value_is_null;
  return true;
}

// センサ属性 1 件を読んでスナップショットへ書く(§12.3 の 2)。戻り値 = 通信が成立したか
// (null 応答も「成立」扱い。has_* は false になる)。
bool do_read_sensor_slot(uint64_t node_id, uint8_t slot, bool quiet, uint64_t timeout_ms) {
  if (slot >= SM_UI_SLOT_COUNT) {
    return false;
  }
  const SensorAttrPath &p = SENSOR_ATTRS[slot];
  uint64_t raw = 0;
  bool is_null = false;
  if (!do_read_scalar(node_id, p, timeout_ms, &raw, &is_null)) {
    set_node_sensor(node_id, slot, false, 0);
    ESP_LOGW(TAG, "sensor slot %s (ep%u cluster 0x%04lx attr 0x%04lx) read failed for %016llx",
             p.name, (unsigned)p.ep, (unsigned long)p.cluster, (unsigned long)p.attr,
             (unsigned long long)node_id);
    if (!quiet) {
      sm_app_set_status("read %s of %016llx failed", p.name, (unsigned long long)node_id);
    }
    return false;
  }
  ESP_LOGI(TAG, "sensor slot %s = raw 0x%llx%s", p.name, (unsigned long long)raw,
           is_null ? " (null)" : "");
  set_node_sensor(node_id, slot, !is_null, raw);
  mark_node_updated(node_id); // 鮮度は「通信が成立した時刻」(null 応答も成立扱い。T6)
  if (!quiet) {
    sm_app_set_status("read %s of %016llx OK", p.name, (unsigned long long)node_id);
  }
  return true;
}

// センサの全属性を先頭から読み直す(UI の Read ボタン / ペア直後)。
bool do_read_sensor_all(uint64_t node_id, bool quiet, uint64_t timeout_ms) {
  bool all = true;
  for (uint8_t slot = 0; slot < SM_UI_SLOT_COUNT; ++slot) {
    if (!do_read_sensor_slot(node_id, slot, true, timeout_ms)) {
      all = false;
      break; // 1 本落ちたら以降も落ちる(死んだノードで 5 回 CASE を試さない)
    }
  }
  if (all) {
    clear_backoff(node_id);
    set_node_note(node_id, "sensors OK");
  }
  if (!quiet) {
    sm_app_set_status(all ? "refreshed all sensor attributes of %016llx"
                          : "sensor refresh of %016llx failed",
                      (unsigned long long)node_id);
  }
  return all;
}

// ノード種別を実機に問い合わせる(§12.3 の 1)。
//
// AirQuality(EP1 0x005B/0)が読めれば SENSOR、駄目なら OnOff(EP1 0x0006/0)を試して
// 読めれば LIGHT。**両方落ちたら UNKNOWN**(= ノードが不達なだけの可能性があるので
// キャッシュしない)。読めた値はそのまま表示にも反映する。
uint8_t probe_node_kind(uint64_t node_id, uint64_t timeout_ms) {
  uint64_t raw = 0;
  bool is_null = false;
  if (do_read_scalar(node_id, SENSOR_ATTRS[SM_UI_SLOT_AQ], timeout_ms, &raw, &is_null)) {
    set_node_sensor(node_id, SM_UI_SLOT_AQ, !is_null, raw);
    return SM_UI_KIND_SENSOR;
  }
  static constexpr SensorAttrPath kOnOff = {EP_ONOFF, CL_ONOFF, ATTR_ONOFF, "OnOff"};
  if (do_read_scalar(node_id, kOnOff, timeout_ms, &raw, &is_null)) {
    set_node_onoff(node_id, is_null ? (int8_t)-1 : (int8_t)(raw != 0 ? 1 : 0));
    return SM_UI_KIND_LIGHT;
  }
  return SM_UI_KIND_UNKNOWN;
}

// トランスポートを実機に問い合わせる: EP0 NetworkCommissioning の FeatureMap(u32)。
// bit0 = WiFi / bit1 = Thread / bit2 = Ethernet(複数立っていたら下位ビット優先)。
// 読めない / null / どのビットも無い → UNKNOWN。
uint8_t probe_node_transport(uint64_t node_id, uint64_t timeout_ms) {
  static constexpr SensorAttrPath kFeatureMap = {EP_ROOT, CL_NETWORK_COMMISSIONING,
                                                 ATTR_FEATURE_MAP, "NetCommFeatureMap"};
  uint64_t raw = 0;
  bool is_null = false;
  if (!do_read_scalar(node_id, kFeatureMap, timeout_ms, &raw, &is_null) || is_null) {
    return SM_UI_TRANSPORT_UNKNOWN;
  }
  if (raw & 0x1) {
    return SM_UI_TRANSPORT_WIFI;
  }
  if (raw & 0x2) {
    return SM_UI_TRANSPORT_THREAD;
  }
  if (raw & 0x4) {
    return SM_UI_TRANSPORT_ETH;
  }
  return SM_UI_TRANSPORT_UNKNOWN;
}

// トランスポートを取得して表示 + キャッシュへ反映する。**種別が確定しているノードに
// だけ呼ぶ**(キャッシュは種別と同じエントリ)。失敗しても種別には触れず、2 分は
// 再試行しない。
uint8_t resolve_node_transport(uint64_t node_id, uint8_t kind, uint64_t timeout_ms) {
  uint8_t transport = probe_node_transport(node_id, timeout_ms);
  size_t slot = slot_of(node_id);
  if (transport == SM_UI_TRANSPORT_UNKNOWN) {
    if (slot < SM_UI_MAX_NODES) {
      g_transport_retry_until[slot] = now_ms() + 120000;
    }
    return transport;
  }
  set_node_transport(node_id, transport);
  node_cache_set(node_id, kind, transport);
  ESP_LOGI(TAG, "node %016llx transport = %s", (unsigned long long)node_id,
           sm_ui_transport_label(transport));
  return transport;
}

// 通信が成立した直後に呼ぶ: トランスポート未取得(= 旧キャッシュ / 前回読めなかった)
// なら 1 回だけ取りに行く。既知 / 種別未確定 / 再試行待ちなら何もしない。
void ensure_node_transport(uint64_t node_id) {
  uint8_t kind = node_kind(node_id);
  size_t slot = slot_of(node_id);
  if (kind == SM_UI_KIND_UNKNOWN || slot >= SM_UI_MAX_NODES ||
      node_transport(node_id) != SM_UI_TRANSPORT_UNKNOWN ||
      now_ms() < g_transport_retry_until[slot]) {
    return;
  }
  resolve_node_transport(node_id, kind, 10000);
}

// 種別を確定させてキャッシュへ書く。確定できなければ UNKNOWN のまま(次の poll で再挑戦)。
// 種別が確定したら続けてトランスポートも取る(こちらの失敗は種別判定に影響しない)。
uint8_t resolve_node_kind(uint64_t node_id, uint64_t timeout_ms) {
  uint8_t kind = probe_node_kind(node_id, timeout_ms);
  set_node_kind(node_id, kind);
  if (kind != SM_UI_KIND_UNKNOWN) {
    node_cache_set(node_id, kind, node_transport(node_id));
    ESP_LOGI(TAG, "node %016llx detected as %s", (unsigned long long)node_id,
             kind == SM_UI_KIND_SENSOR ? "air-quality sensor" : "on/off light");
    if (node_transport(node_id) == SM_UI_TRANSPORT_UNKNOWN) {
      resolve_node_transport(node_id, kind, timeout_ms);
    }
  }
  return kind;
}

// ---- T8: 属性 Subscribe(§16.3)----

// ノード 1 台に購読を張る(CASE 込みで数秒かかるので run_until で直列に駆動する)。
// 種別 LIGHT: OnOff 1 パス(min=0/max=60)。SENSOR: SENSOR_ATTRS 5 パス(min=1/max=60)。
// プライミングのレポートは run_until 経由で consume_async_event に入るので、
// 購読確立の時点で表示は最新になっている。
bool do_subscribe_node(uint64_t node_id, uint8_t kind, uint64_t timeout_ms) {
  sm_attr_path_t paths[SM_UI_SLOT_COUNT];
  size_t n = 0;
  uint16_t min_i = 0;
  uint16_t max_i = 60;
  if (kind == SM_UI_KIND_SENSOR) {
    for (uint8_t slot = 0; slot < SM_UI_SLOT_COUNT; ++slot) {
      paths[n].endpoint = SENSOR_ATTRS[slot].ep;
      paths[n].cluster = SENSOR_ATTRS[slot].cluster;
      paths[n].attribute = SENSOR_ATTRS[slot].attr;
      ++n;
    }
    min_i = 1; // センサはバースト抑制のため最小 1 秒
  } else if (kind == SM_UI_KIND_LIGHT) {
    paths[n].endpoint = EP_ONOFF;
    paths[n].cluster = CL_ONOFF;
    paths[n].attribute = ATTR_ONOFF;
    ++n;
    min_i = 0; // ボタン押下を即座に受けたい
  } else {
    return false; // 種別未確定のノードには張らない
  }

  ESP_LOGI(TAG, "sub: subscribing node=%016llx kind=%u paths=%u min=%u max=%u",
           (unsigned long long)node_id, (unsigned)kind, (unsigned)n, (unsigned)min_i,
           (unsigned)max_i);
  int32_t rc = start_op_clean(
      [&] { return sm_ctrl_subscribe_paths(node_id, paths, n, min_i, max_i, now_ms()); });
  if (rc != 0) {
    ESP_LOGW(TAG, "sub: start rejected node=%016llx rc=%ld", (unsigned long long)node_id,
             (long)rc);
    return false;
  }
  sm_ctrl_event_t ev;
  if (!run_until(g_udp, timeout_ms, ev, term_subscribe) ||
      ev.kind != SM_CTRL_EV_SUBSCRIBE_DONE) {
    ESP_LOGW(TAG, "sub: failed node=%016llx (kind=%d status=%u)", (unsigned long long)node_id,
             (int)ev.kind, (unsigned)ev.status);
    return false;
  }
  ESP_LOGI(TAG, "sub: active node=%016llx id=%llu", (unsigned long long)node_id,
           (unsigned long long)ev.value_u64);
  return true;
}

// 購読を捨てる(デバイスへは何も送らない。⟳ / 種別再検出の前に呼ぶ)。
void drop_subscription(uint64_t node_id) {
  int32_t dropped = sm_ctrl_unsubscribe(node_id);
  if (dropped > 0) {
    ESP_LOGI(TAG, "sub: dropped %ld subscription(s) of node=%016llx", (long)dropped,
             (unsigned long long)node_id);
  }
  mark_unsubscribed(node_id, 0);
}

// ペア完了直後の初期化(§12.3 の 1: 「ペア完了時に判定」)。行が既にある前提。
void after_pair_complete(uint64_t node_id) {
  uint8_t kind = resolve_node_kind(node_id, 20000);
  if (kind == SM_UI_KIND_SENSOR) {
    do_read_sensor_all(node_id, true, 20000);
  }
  // LIGHT は probe_node_kind が OnOff を読んだ時点でバッジが埋まっている。
}

// ---- forget: ノードを Tab5 の帳簿からだけ消す ----
//
// デバイスへは何も送らない(RemoveFabric しない = 不達の残骸ノードでも即終わる)。
// シム(crates/、無改造)にノード削除の入口が無いので、
//   1. 購読を捨てる  2. NVS の "nods" blob から該当エントリを抜く
//   3. 種別 / トランスポートのキャッシュと resumption 素材(rsm<node>)を消す
//   4. sm_ctrl_deinit → sm_ctrl_init で KVS から読み直させる
// の順で行う。4 で他ノードのセッション / 購読も落ちるが、次の poll tick で
// CASE(resumption)+ 再購読が自動で張り直される。
uint8_t *g_ctx_mem = nullptr;
size_t g_ctx_len = 0;
sm_ctrl_config_t g_ctx_cfg;

void do_forget(uint64_t node_id) {
  sm_addr_t a = {};
  if (!sm_ctrl_node_addr(node_id, &a)) {
    sm_app_set_status("forget %016llx: not in the node book", (unsigned long long)node_id);
    return;
  }
  drop_subscription(node_id);
  resub_now_clear(node_id);
  if (!sm_node_book_remove_from_nvs(node_id)) {
    sm_app_set_status("forget %016llx: could not rewrite the node book",
                      (unsigned long long)node_id);
    return;
  }
  node_cache_set(node_id, SM_UI_KIND_UNKNOWN, SM_UI_TRANSPORT_UNKNOWN);
  char rsm[24];
  snprintf(rsm, sizeof(rsm), "rsm%016llX", (unsigned long long)node_id);
  kvs_delete(nullptr, rsm);

  sm_ctrl_deinit();
  int rc = sm_ctrl_init(g_ctx_mem, g_ctx_len, &g_ctx_cfg, now_ms());
  if (rc != 0) {
    // 帳簿は書き換え済みなので、再起動すれば整合した状態で上がる。
    ESP_LOGE(TAG, "forget: sm_ctrl_init failed (rc=%d); restarting", rc);
    sm_app_set_status("forget: controller re-init failed (rc=%d); restarting", rc);
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
  }
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    if (s->window.node_id == node_id) {
      s->window = sm_ui_window_t{};
    }
    sm_app_unlock();
  }
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    g_backoff_until[i] = 0; // 行 index が詰まるので持ち越さない
    g_resub_now[i] = 0;     // 再 init で購読は全て消えた(poll tick が張り直す)
  }
  rebuild_node_list();
  sm_app_set_status("forgot node %016llx (local only; %u node(s) left)",
                    (unsigned long long)node_id, (unsigned)sm_ctrl_node_count());
}

void do_toggle(uint64_t node_id) {
  sm_app_set_status("toggle %016llx ...", (unsigned long long)node_id);
  if (start_op_clean([&] {
        return sm_ctrl_invoke(node_id, EP_ONOFF, CL_ONOFF, CMD_TOGGLE, now_ms());
      }) != 0) {
    set_node_note(node_id, "toggle rejected");
    sm_app_set_status("toggle %016llx: rejected", (unsigned long long)node_id);
    return;
  }
  sm_ctrl_event_t ev;
  if (run_until(g_udp, 20000, ev, term_invoke) && ev.kind == SM_CTRL_EV_INVOKE_DONE) {
    set_node_note(node_id, "toggle OK");
    clear_backoff(node_id);
    sm_app_set_status("toggle %016llx OK (status=%u)", (unsigned long long)node_id, ev.status);
    // 直後に読み直してバッジを合わせる。
    do_read_onoff(node_id, true, 20000);
  } else {
    set_node_note(node_id, "toggle FAILED");
    sm_app_set_status("toggle %016llx failed", (unsigned long long)node_id);
  }
}

// ---- T9(§17.4): コミッショニングウィンドウ ----
//
// UI(Share ボタン / console `openwindow`)→ シムの
// `sm_ctrl_open_commissioning_window` を叩き、WINDOW_OPENED / WINDOW_FAILED を
// 終端として run_until で駆動する。成功したら `sm_ctrl_last_window` の
// manual code / QR をスナップショットの `window` 欄へ写す(Share ダイアログの素材)。

// 開いた窓の WindowStatus を確認する周期(§17.4「10 秒ごと」)。
constexpr uint64_t WINDOW_POLL_MS = 10000;

void do_open_window(const sm_ui_op_t &op) {
  uint16_t timeout_s = op.timeout_s != 0 ? op.timeout_s : 300;
  if (timeout_s < 180) {
    timeout_s = 180;
  }
  if (timeout_s > 900) {
    timeout_s = 900;
  }
  // discriminator 0xFFFF / passcode 0 は「シム側で乱数生成」(§17.3)。
  const uint16_t disc = op.discriminator;
  const uint32_t passcode = op.passcode;

  {
    sm_ui_snapshot_t *s = sm_app_lock();
    memset(&s->window, 0, sizeof(s->window));
    s->window.node_id = op.node_id;
    s->window.status = SM_UI_WINDOW_OPENING;
    sm_app_unlock();
  }
  sm_app_set_status("open commissioning window on %016llx (%u s) ...",
                    (unsigned long long)op.node_id, (unsigned)timeout_s);
  set_node_busy(op.node_id, true);

  int32_t rc = start_op_clean([&] {
    return sm_ctrl_open_commissioning_window(op.node_id, timeout_s, disc, passcode, now_ms());
  });
  if (rc != 0) {
    set_node_busy(op.node_id, false);
    set_node_note(op.node_id, "open window rejected");
    sm_ui_snapshot_t *s = sm_app_lock();
    s->window.status = SM_UI_WINDOW_FAILED;
    s->window.fail_status = 0;
    s->window.fail_phase = 0;
    sm_app_unlock();
    sm_app_set_status("open window %016llx: rejected (rc=%ld)", (unsigned long long)op.node_id,
                      (long)rc);
    return;
  }

  sm_ctrl_event_t ev;
  // VID read → PID read → timed invoke の 3 段をシムが直列に進めるので、
  // 通常の invoke より長めに待つ(§17.3)。
  const bool ok = run_until(g_udp, 30000, ev, term_window) && ev.kind == SM_CTRL_EV_WINDOW_OPENED;
  set_node_busy(op.node_id, false);
  if (!ok) {
    char note[40];
    snprintf(note, sizeof(note), "open window failed (status %u)", (unsigned)ev.status);
    set_node_note(op.node_id, note);
    sm_ui_snapshot_t *s = sm_app_lock();
    s->window.status = SM_UI_WINDOW_FAILED;
    s->window.fail_status = ev.status;
    s->window.fail_phase = ev.phase;
    sm_app_unlock();
    sm_app_set_status("open window %016llx failed (status=%u phase=%u)",
                      (unsigned long long)op.node_id, (unsigned)ev.status, (unsigned)ev.phase);
    return;
  }

  sm_ctrl_window_t w;
  memset(&w, 0, sizeof(w));
  const bool have = sm_ctrl_last_window(&w);
  // timeout は WINDOW_OPENED の attribute に載る(§17.3)。取れなければ要求値。
  const uint32_t granted = ev.attribute != 0 ? ev.attribute : (uint32_t)timeout_s;
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->window.node_id = op.node_id;
    s->window.passcode = have ? w.passcode : (uint32_t)ev.value_u64;
    s->window.discriminator = have ? w.discriminator : (uint16_t)ev.endpoint;
    // シムのバッファが NUL 終端でなくても読み過ぎないよう精度を切る。
    snprintf(s->window.manual_code, sizeof(s->window.manual_code), "%.11s",
             have ? w.manual_code : "");
    snprintf(s->window.qr, sizeof(s->window.qr), "%.31s", have ? w.qr_payload : "");
    s->window.expires_ms = now_ms() + (uint64_t)granted * 1000ull;
    s->window.status = SM_UI_WINDOW_OPEN;
    s->window.fail_status = 0;
    s->window.fail_phase = 0;
    sm_app_unlock();
  }
  set_node_note(op.node_id, "window open");
  sm_app_set_status("window open on %016llx: code %.11s (disc %u, %u s)",
                    (unsigned long long)op.node_id, have ? w.manual_code : "?",
                    (unsigned)(have ? w.discriminator : 0), (unsigned)granted);
}

void do_revoke_window(uint64_t node_id) {
  sm_app_set_status("revoke commissioning window on %016llx ...", (unsigned long long)node_id);
  set_node_busy(node_id, true);
  int32_t rc = start_op_clean([&] { return sm_ctrl_revoke_commissioning(node_id, now_ms()); });
  if (rc != 0) {
    set_node_busy(node_id, false);
    set_node_note(node_id, "revoke rejected");
    sm_app_set_status("revoke %016llx: rejected (rc=%ld)", (unsigned long long)node_id, (long)rc);
    return;
  }
  sm_ctrl_event_t ev;
  const bool ok = run_until(g_udp, 30000, ev, term_invoke) && ev.kind == SM_CTRL_EV_INVOKE_DONE;
  set_node_busy(node_id, false);
  if (ok) {
    set_node_note(node_id, "window revoked");
    sm_ui_snapshot_t *s = sm_app_lock();
    if (s->window.node_id == node_id) {
      s->window.status = SM_UI_WINDOW_CLOSED;
      s->window.expires_ms = 0;
    }
    sm_app_unlock();
    sm_app_set_status("window revoked on %016llx", (unsigned long long)node_id);
  } else {
    char note[40];
    snprintf(note, sizeof(note), "revoke failed (status %u)", (unsigned)ev.status);
    set_node_note(node_id, note);
    // WindowNotOpen(=4)は「既に閉じている」なので閉扱いにする。
    if (ev.status == 4) {
      sm_ui_snapshot_t *s = sm_app_lock();
      if (s->window.node_id == node_id) {
        s->window.status = SM_UI_WINDOW_CLOSED;
        s->window.expires_ms = 0;
      }
      sm_app_unlock();
    }
    sm_app_set_status("revoke %016llx failed (status=%u)", (unsigned long long)node_id,
                      (unsigned)ev.status);
  }
}

// 開いている窓の WindowStatus(EP0/0x003C/0x0000)を read して、閉じていたら
// スナップショットへ反映する(§17.4。10 秒 tick から呼ぶ)。
void poll_window_status() {
  uint64_t node_id = 0;
  {
    sm_ui_snapshot_t *s = sm_app_lock();
    if (s->window.status == SM_UI_WINDOW_OPEN) {
      node_id = s->window.node_id;
    }
    sm_app_unlock();
  }
  if (node_id == 0) {
    return;
  }
  static constexpr SensorAttrPath WINDOW_STATUS_PATH = {EP_ROOT, CL_ADMIN_COMM,
                                                        ATTR_WINDOW_STATUS, "WindowStatus"};
  uint64_t raw = 0;
  bool is_null = false;
  set_node_busy(node_id, true);
  const bool ok = do_read_scalar(node_id, WINDOW_STATUS_PATH, 10000, &raw, &is_null);
  set_node_busy(node_id, false);
  if (!ok) {
    return; // 到達不能。期限切れ側の判定に任せる(窓を勝手に閉じたことにしない)。
  }
  if (!is_null && raw == 0) {
    sm_ui_snapshot_t *s = sm_app_lock();
    if (s->window.node_id == node_id && s->window.status == SM_UI_WINDOW_OPEN) {
      s->window.status = SM_UI_WINDOW_CLOSED;
      s->window.expires_ms = 0;
    }
    sm_app_unlock();
    set_node_note(node_id, "window closed");
    sm_app_set_status("window on %016llx is closed", (unsigned long long)node_id);
  }
}

// SRP サーバ帳からデバイスの運用アドレスを引き、ノード帳へ反映する(F8b)。
// 運用アドレスの直接指定(T5a `setaddr`)。v4 リテラルも受ける(is_v6=false)。
// WiFi デバイスの IPv6 近隣解決が成立しない環境(esp-radio が NS を受信しない等)で
// v4 に切り替える実験・運用の入口。
void do_set_addr(const sm_ui_op_t &op) {
  sm_addr_t a = {};
  uint8_t v4[4];
  if (inet_pton(AF_INET6, op.ipv6, a.ip) == 1) {
    a.is_v6 = true;
    if (a.ip[0] == 0xfe && (a.ip[1] & 0xc0) == 0x80) {
      a.scope_id = (op.via == SM_UI_VIA_WIFI) ? sm_wifi_netif_index() : sm_ot_hub_netif_index();
    }
  } else if (inet_pton(AF_INET, op.ipv6, v4) == 1) {
    a.is_v6 = false;
    memcpy(a.ip, v4, 4);
  } else {
    sm_app_set_status("setaddr: '%s' is not an IP literal", op.ipv6);
    return;
  }
  a.port = CONFIG_SM_TARGET_PORT;
  int rc = sm_ctrl_set_node_addr(op.node_id, &a);
  sm_ctrl_event_t ev;
  while (sm_ctrl_take_event(&ev)) {
    consume_async_event(ev); // T8
  }
  refresh_node_addr_view(op.node_id);
  set_node_note(op.node_id, rc == 0 ? "addr set" : "setaddr failed");
  sm_app_set_status("setaddr %016llx -> %s rc=%d", (unsigned long long)op.node_id, op.ipv6, rc);
}

void do_refresh_addr(uint64_t node_id) {
  // T8(§16.3): 旧アドレス / 旧セッションに紐づく購読の残骸を先に切る。
  drop_subscription(node_id);
  // FORM: 自分の SRP サーバ帳 → WiFi mDNS。
  // JOIN(§18.3-2 / P2): OTBR の DNS-SD サーバへ OT DNS client → WiFi mDNS → **保存アドレス維持**。
  // 既に WiFi / Ethernet と分かっているノードは DNS を飛ばして mDNS へ(Thread 網の DNS に
  // 居ない。OTBR の discovery proxy が infra 側のアドレスを返しても Thread 側からは使わない)。
  const bool join = sm_ot_hub_mode() == SM_OT_MODE_JOIN;
  uint8_t ip[16];
  bool hit = false;
  char dns_msg[160] = {0};
  if (join) {
    const uint8_t tr = node_transport(node_id);
    char label[64];
    if (tr == SM_UI_TRANSPORT_WIFI || tr == SM_UI_TRANSPORT_ETH) {
      snprintf(dns_msg, sizeof(dns_msg), "skipped (non-Thread node)");
    } else if (!operational_label(node_id, label, sizeof(label))) {
      snprintf(dns_msg, sizeof(dns_msg), "no instance label");
    } else {
      sm_app_set_status("DNS lookup for %016llx ...", (unsigned long long)node_id);
      hit = sm_ot_hub_resolve(node_id, label, ip, 6000, dns_msg, sizeof(dns_msg));
      const bool ll = hit && ip[0] == 0xfe && (ip[1] & 0xc0) == 0x80;
      if (ll) {
        hit = false; // Thread 越しに使えないリンクローカルしか返らなかった
        snprintf(dns_msg, sizeof(dns_msg), "only a link-local address");
      }
      ESP_LOGI(TAG, "refresh %016llx: DNS %s: %s", (unsigned long long)node_id,
               hit ? "ok" : "failed", dns_msg);
    }
  } else {
    sm_app_set_status("SRP lookup for %016llx ...", (unsigned long long)node_id);
    hit = sm_ot_hub_srp_lookup(node_id, ip);
  }
  if (!hit) {
    if (!join) {
      sm_ot_hub_dump_srp();
    }
    // SRP / DNS に居ない = Thread ノードではない可能性。WiFi が上がっていれば mDNS で引く
    // (T3 で追加。WiFi ノードのリブート後再解決もこれで効く)。
    uint32_t widx = sm_wifi_netif_index();
    if (widx != 0) {
      sm_app_set_status("%s%s; trying mDNS over WiFi for %016llx ...",
                        join ? "DNS: " : "not in SRP", join ? dns_msg : "",
                        (unsigned long long)node_id);
      bool ok = resolve_via_mdns(node_id, widx, 8000);
      sm_ctrl_event_t ev;
      while (sm_ctrl_take_event(&ev)) {
        consume_async_event(ev); // T8
      }
      refresh_node_addr_view(node_id);
      if (join && !ok) {
        set_node_note(node_id, "addr kept");
        sm_app_set_status("JOIN: neither DNS (%s) nor mDNS resolved %016llx; keeping the stored "
                          "address",
                          dns_msg, (unsigned long long)node_id);
        return;
      }
      set_node_note(node_id, ok ? "addr updated (mDNS)" : "not found");
      sm_app_set_status(ok ? "mDNS resolved %016llx" : "neither SRP nor mDNS knows %016llx",
                        (unsigned long long)node_id);
      return;
    }
    if (join) {
      set_node_note(node_id, "addr kept");
      sm_app_set_status("JOIN: DNS failed for %016llx (%s); keeping the stored address",
                        (unsigned long long)node_id, dns_msg);
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
    consume_async_event(ev); // T8
  }
  refresh_node_addr_view(node_id);
  set_node_note(node_id, rc == 0 ? (join ? "addr updated (DNS)" : "addr updated")
                                 : "set_node_addr failed");
  char buf[64] = {0};
  inet_ntop(AF_INET6, ip, buf, sizeof(buf));
  sm_app_set_status("%s -> %s (set_node_addr rc=%d)", join ? "DNS" : "SRP", buf, rc);
}

void do_pair(const sm_ui_op_t &op) {
  sm_addr_t addr = {};
  addr.is_v6 = true;
  uint8_t v4[4];
  if (inet_pton(AF_INET6, op.ipv6, addr.ip) == 1) {
    addr.is_v6 = true;
  } else if (inet_pton(AF_INET, op.ipv6, v4) == 1) {
    // IPv4 リテラルも受ける。WiFi デバイス(特に esp-radio の Rust FW)は IPv6 の
    // 近隣解決が成立しないことがあり、v4 で組んだ方が運用が安定する(T5 実機)。
    addr.is_v6 = false;
    memcpy(addr.ip, v4, 4);
  } else {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    sm_app_unlock();
    sm_app_set_status("pair: '%s' is not an IPv6/IPv4 address", op.ipv6);
    return;
  }
  addr.port = CONFIG_SM_TARGET_PORT;

  // scope_id はリンクローカル(fe80::/10)宛のときだけ意味を持つ。
  // ULA / グローバル宛は 0 のままにして lwIP の経路選択に任せる
  // (Thread の OMR も WiFi の GUA/ULA もこちら)。
  const bool is_ll = addr.is_v6 && (addr.ip[0] == 0xfe) && ((addr.ip[1] & 0xc0) == 0x80);
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
    after_pair_complete(op.node_id);
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
int g_mdns_fd6 = -1;

// IPv6 側の mDNS ソケット(:5353 bind + ff02::fb を WiFi netif で MLD join)。
// **v4 と v6 の両方で聞く**のが肝(実機 T4/T5 で確定):
//   - C++ デバイス(NanoC6 等)は v6 join に失敗する(errno=125)→ v4 でしか届かない
//   - Rust デバイス(AirQ)は v6 MLD join が生きている一方、v4 マルチキャストの
//     受信/到達が不安定 → v6 なら確実
//   - Tab5 自身も IPv6 マルチキャスト RX は安定(RA/GUA 取得が毎回通る)
int open_mdns6_5353(uint32_t netif_index) {
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    return -1;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
  struct sockaddr_in6 a = {};
  a.sin6_family = AF_INET6;
  a.sin6_port = htons(5353);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    ESP_LOGW(TAG, "mdns6 bind(5353) failed errno=%d", errno);
    close(fd);
    return -1;
  }
  struct ipv6_mreq m6 = {};
  inet_pton(AF_INET6, "ff02::fb", &m6.ipv6mr_multiaddr);
  m6.ipv6mr_interface = netif_index;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &m6, sizeof(m6)) != 0) {
    ESP_LOGW(TAG, "MLD join ff02::fb on netif %u failed errno=%d", (unsigned)netif_index, errno);
  }
  return fd;
}

// v6 側でクエリを送る(ff02::fb%netif 宛)。
void send_mdns6_query(int fd, const uint8_t *q, size_t qn, uint32_t netif_index) {
  struct sockaddr_in6 m = {};
  m.sin6_family = AF_INET6;
  m.sin6_port = htons(5353);
  inet_pton(AF_INET6, "ff02::fb", &m.sin6_addr);
  m.sin6_scope_id = netif_index;
  sendto(fd, q, qn, 0, (struct sockaddr *)&m, sizeof(m));
}

void drain_one_to_cache(int fd) {
  if (fd < 0) {
    return;
  }
  for (;;) {
    struct timeval tv = {0, 0};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    if (select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) {
      return;
    }
    uint8_t rx[1500];
    int n = recv(fd, rx, sizeof(rx), 0);
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

void drain_mdns_to_cache() {
  drain_one_to_cache(g_mdns_fd);
  drain_one_to_cache(g_mdns_fd6);
}

// キャッシュした announce をシムへ流す。RESOLVE_DONE が立てば true。
bool replay_mdns_cache() {
  for (size_t i = 0; i < g_mdns_cache_n; ++i) {
    if (sm_ctrl_mdns_rx(g_mdns_cache[i].buf, g_mdns_cache[i].len, nullptr, now_ms()) == 0) {
      sm_ctrl_event_t ev;
      while (sm_ctrl_take_event(&ev)) {
        consume_async_event(ev); // T8
        if (ev.kind == SM_CTRL_EV_RESOLVE_DONE) {
          ESP_LOGI(TAG, "resolved from a cached announce (#%u)", (unsigned)i);
          return true;
        }
      }
    }
  }
  return false;
}

// 受信 1 回分をシムへ給餌する。RESOLVE_DONE で true。
bool feed_rx_once(int fd) {
  uint8_t rx[1500];
  struct sockaddr_storage src = {};
  socklen_t sl = sizeof(src);
  int n = recvfrom(fd, rx, sizeof(rx), 0, (struct sockaddr *)&src, &sl);
  if (n <= 0) {
    return false;
  }
  int32_t rc = sm_ctrl_mdns_rx(rx, (size_t)n, nullptr, now_ms());
  ESP_LOGI(TAG, "mdns rx %d B (%s) -> rc=%ld", n,
           src.ss_family == AF_INET6 ? "v6" : "v4", (long)rc);
  if (rc == 0) {
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      consume_async_event(ev); // T8
      if (ev.kind == SM_CTRL_EV_RESOLVE_DONE) {
        // **WiFi デバイスは IPv4 を運用アドレスにする**(T5 実機で確定):
        // esp-radio(Rust FW)は NS/マルチキャストを受信できず IPv6 の近隣解決が
        // 成立しないため、AAAA(fe80)を採ると近隣キャッシュが冷えた時点で不達になる。
        // v4 ソケットへ応答が来たなら応答元 v4 がそのままデバイスの運用アドレス。
        if (src.ss_family == AF_INET) {
          const auto *s4 = (const struct sockaddr_in *)&src;
          sm_addr_t a = {};
          a.is_v6 = false;
          memcpy(a.ip, &s4->sin_addr, 4);
          a.port = CONFIG_SM_TARGET_PORT;
          sm_ctrl_set_node_addr(ev.node_id, &a);
          char ip[20] = {0};
          inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
          ESP_LOGI(TAG, "operational address pinned to IPv4 %s (responder source)", ip);
          sm_ctrl_event_t drop;
          while (sm_ctrl_take_event(&drop)) {
            consume_async_event(drop); // T8
          }
        }
        return true;
      }
    }
  }
  return false;
}

bool resolve_via_mdns(uint64_t node_id, uint32_t netif_index, uint64_t timeout_ms) {
  const bool own4 = (g_mdns_fd < 0);
  const bool own6 = (g_mdns_fd6 < 0);
  int fd4 = own4 ? open_mdns_5353() : g_mdns_fd;
  int fd6 = own6 ? open_mdns6_5353(netif_index) : g_mdns_fd6;
  if (fd4 < 0 && fd6 < 0) {
    return false;
  }

  struct sockaddr_in mdst = {};
  mdst.sin_family = AF_INET;
  mdst.sin_port = htons(5353);
  mdst.sin_addr.s_addr = inet_addr("224.0.0.251");

  uint64_t until = now_ms() + timeout_ms;
  uint64_t next_q = 0;
  bool ok = false;
  while (!ok && now_ms() < until) {
    if (now_ms() >= next_q) {
      next_q = now_ms() + 2000;
      uint8_t q[512];
      sm_addr_t qdst = {};
      size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
      if (qn > 0) {
        if (fd4 >= 0) {
          sendto(fd4, q, qn, 0, (struct sockaddr *)&mdst, sizeof(mdst));
        }
        if (fd6 >= 0) {
          send_mdns6_query(fd6, q, qn, netif_index);
        }
        ESP_LOGI(TAG, "mdns query %u B -> v4/v6 mcast (from :5353)", (unsigned)qn);
        // **ユニキャスト掃引(最終手段だが決定打)**: esp_hosted 経由の Tab5 は
        // 既定グループ(ff02::1 等)以外のマルチキャスト受信が当てにならず、
        // デバイスの announce/QM 応答が届かないことがある(実機 T4/T5 で確定。
        // PC では同じ announce が受信できているのに Tab5 だけ無音)。
        // 我々のデバイスは **直接ユニキャストの mDNS クエリに応答する**(PC probe で
        // 実証)ので、自分の /24 全ホストへ QU クエリを直送する。応答はユニキャストで
        // 返るためマルチキャスト受信に一切依存しない。1 周 ≈ 254 パケット(18KB)。
        if (fd4 >= 0) {
          sm_wifi_status_t w = {};
          sm_wifi_get_status(&w);
          struct in_addr self = {};
          if (w.ip4[0] != 0 && inet_pton(AF_INET, w.ip4, &self) == 1) {
            struct sockaddr_in u = {};
            u.sin_family = AF_INET;
            u.sin_port = htons(5353);
            for (uint32_t host = 1; host <= 254; ++host) {
              u.sin_addr.s_addr = (self.s_addr & htonl(0xFFFFFF00u)) | htonl(host);
              if (u.sin_addr.s_addr == self.s_addr) {
                continue;
              }
              sendto(fd4, q, qn, 0, (struct sockaddr *)&u, sizeof(u));
              if ((host & 0x1F) == 0) {
                vTaskDelay(pdMS_TO_TICKS(10)); // バーストを少し均す
              }
            }
          }
        }
      }
    }
    struct timeval tv = {0, 200000};
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxfd = -1;
    if (fd4 >= 0) {
      FD_SET(fd4, &rfds);
      maxfd = fd4 > maxfd ? fd4 : maxfd;
    }
    if (fd6 >= 0) {
      FD_SET(fd6, &rfds);
      maxfd = fd6 > maxfd ? fd6 : maxfd;
    }
    if (select(maxfd + 1, &rfds, nullptr, nullptr, &tv) > 0) {
      if (fd4 >= 0 && FD_ISSET(fd4, &rfds) && feed_rx_once(fd4)) {
        ok = true;
      }
      if (!ok && fd6 >= 0 && FD_ISSET(fd6, &rfds) && feed_rx_once(fd6)) {
        ok = true;
      }
    }
  }
  if (own4 && fd4 >= 0) {
    close(fd4);
  }
  if (own6 && fd6 >= 0) {
    close(fd6);
  }
  return ok;
}

// operational インスタンス名の先頭ラベル `<compressed-fabric-hex>-<node-id-hex>` を得る
// (JOIN の DNS 解決用。§18.3-2)。compressed fabric は C++ から見えないので、
// `sm_ctrl_resolve_start`(副作用なし)が作るクエリの QNAME 先頭ラベルを借りる。
bool operational_label(uint64_t node_id, char *out, size_t cap) {
  uint8_t q[256];
  sm_addr_t qdst = {};
  size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
  if (qn <= 12 + 1) {
    return false;
  }
  const size_t len = q[12];
  if (len == 0 || len >= 64 || 13 + len > qn || len + 1 > cap) {
    return false;
  }
  memcpy(out, q + 13, len);
  out[len] = 0;
  return true;
}

// JOIN の `dns <node>` コンソール操作(§18 / P2): 解決してログへ出すだけ(ノード帳は触らない)。
void do_dns_lookup(uint64_t node_id) {
  char label[64];
  if (!operational_label(node_id, label, sizeof(label))) {
    sm_app_set_status("DNS %016llx: no instance label (controller not ready?)",
                      (unsigned long long)node_id);
    return;
  }
  char msg[160] = {0};
  uint8_t ip[16];
  uint16_t port = 0;
  char srv[96] = {0};
  bool have_srv = sm_ot_hub_dns_server(srv, sizeof(srv));
  ESP_LOGI(TAG, "dns %016llx: instance %s; server %s%s", (unsigned long long)node_id, label,
           have_srv ? "" : "not found: ", srv);
  bool ok = sm_ot_hub_dns_resolve(label, ip, &port, 6000, msg, sizeof(msg));
  sm_app_set_status("DNS %016llx %s: %s", (unsigned long long)node_id, ok ? "OK" : "FAILED", msg);
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
  bool discovered = false;     // C1/C2/CCCD のハンドル確定
  bool subscribe_sent = false; // handshake request を書いた後に C2 subscribe を開始したか
  bool done = false;
  while (now_ms() < until && !done) {
    BleCentralMsg m;
    while (xQueueReceive(q, &m, 0) == pdTRUE) {
      switch (m.kind) {
      case BleCentralEvent::Connected: {
        // BTP handshake に載せる ATT MTU。コンソール blemtu で上書きできる(相互運用の切り分け用:
        // PC(BlueZ、MTU 不明 = 既定 20 バイト)からは応答する市販デバイスが、Tab5 の MTU 247 では
        // handshake に応答しない事例の検証)。
        uint16_t hs_mtu = g_ble_hs_mtu_override >= 0 ? (uint16_t)g_ble_hs_mtu_override : m.mtu;
        if (hs_mtu != m.mtu) {
          ESP_LOGI(TAG, "BTP handshake MTU override: %u (link MTU %u)", (unsigned)hs_mtu, (unsigned)m.mtu);
        }
        sm_ctrl_ble_event(SM_BLE_CONNECTED, hs_mtu, nullptr, 0, now_ms());
      }
        set_ble_stage(SM_UI_BLE_CONNECTED);
        if (m.peer_mac_valid) {
          memcpy(g_ble_peer_mac, m.peer_mac, 6);
          g_ble_peer_mac_ok = true;
        }
        sm_app_set_status("BLE connected (MTU=%u); discovering the Matter GATT service",
                          (unsigned)m.mtu);
        break;
      case BleCentralEvent::Discovered:
        discovered = true;
        sm_app_set_status("BLE GATT discovered; sending BTP handshake");
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
        // BLE_DONE 前の切断はこのセッションでは回復できない(GATT 未発見・
        // ペリフェラル都合の切断など)。タイムアウトまで待たず即失敗にする。
        return false;
        break;
      case BleCentralEvent::ScanTimeout:
        sm_app_set_status("no device advertising discriminator %u", (unsigned)op.discriminator);
        return false;
      }
    }
    drain_mdns_to_cache(); // announce は ConnectNetwork 成功直後に流れる(取り逃し防止)
    // シムが積んだ BTP フラグメントを C1 write で送る。
    // GATT 発見(C1 handle 確定)まで write しない(CONNECTED 直後の handshake request はシムが
    // 退避しているので取りこぼさない。F7b 実機バグ)。BTP の確立順序は「handshake request を C1 に
    // 書く → C2 を subscribe → 相手が handshake response を indicate」。subscribe を先にすると
    // chip 系の市販デバイス(TP-Link Tapo P110M)は handshake に応答しない(実機、2026-10-03)。
    size_t n;
    while ((subscribed || (discovered && !subscribe_sent)) &&
           (n = sm_ctrl_ble_poll(now_ms(), frag, sizeof(frag))) > 0) {
      if (!sm_ble_central_write_c1(frag, n)) {
        ESP_LOGW(TAG, "C1 write failed (%u bytes)", (unsigned)n);
      }
      if (!subscribed && !subscribe_sent) {
        // handshake request(最初の C1 write)の直後に C2 を subscribe する。
        subscribe_sent = true;
        if (!sm_ble_central_subscribe_c2()) {
          ESP_LOGW(TAG, "C2 subscribe could not be started");
        }
        break;
      }
    }
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      consume_async_event(ev); // T8
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

  // JOIN(§18.3-4): ble-thread の handoff は自分の SRP サーバ帳待ちなので成立しない
  // (デバイスを半端にコミッションしたまま 120 秒待って失敗する)。P2(OT DNS client)まで
  // 入口で断る。JOIN での Thread デバイスは on-network(`pair <ipv6> ...`)で組む。
  if (thread_kind && sm_ot_hub_mode() == SM_OT_MODE_JOIN) {
    sm_ui_snapshot_t *s = sm_app_lock();
    s->pair_state = 3;
    s->ble_stage = SM_UI_BLE_FAILED;
    sm_app_unlock();
    sm_app_set_status("BLE->Thread pairing is not available in JOIN mode yet; "
                      "pair on-network by IPv6 address");
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
  // 不達ノードへの CASE は initiator の HANDSHAKE_TIMEOUT(60 秒)まで内部で
  // 粘るので、それを跨げる **90 秒**までポンプを回しながらリトライする(実機の学び)。
  int rc = -1;
  const uint64_t start_until = now_ms() + 90000;
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
      consume_async_event(drop); // T8
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
  // シム側のイベント残骸も捨てる(前回切断時の PAIR_FAILED が残っていると、
  // 新しい試行の drive_ble_phase が最初の take_event で拾って即失敗する。実機で発覚)。
  {
    sm_ctrl_event_t stale;
    while (sm_ctrl_take_event(&stale)) {
      consume_async_event(stale); // T8
    }
  }

  // WiFi kind: mDNS ソケットを **BLE 開始前**に開いて join しておく。デバイスの
  // operational announce は ConnectNetwork 成功直後(= BLE_DONE より前)に流れるので、
  // BLE フェーズ中から聞いていないと取り逃す(実機 + PC 側パケット観測で確定)。
  g_mdns_cache_n = 0;
  g_mdns_fd = thread_kind ? -1 : open_mdns_5353();
  g_mdns_fd6 = thread_kind ? -1 : open_mdns6_5353(sm_wifi_netif_index());

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
    if (g_mdns_fd6 >= 0) {
      close(g_mdns_fd6);
      g_mdns_fd6 = -1;
    }
    return;
  }

  // --- handoff: 運用アドレスを解決してシムを CASE over UDP へ載せ替える ---
  set_ble_stage(SM_UI_BLE_HANDOFF);
  bool resolved = false;
  if (thread_kind) {
    sm_app_set_status("BLE done; waiting for the device to register in SRP ...");
    uint8_t ip[16];
    // FORM = 自分の SRP サーバ帳 / JOIN = OTBR の DNS-SD(§18 / P2)。
    char label[64] = {0};
    operational_label(op.node_id, label, sizeof(label));
    const uint64_t handoff_until = now_ms() + 120000; // 最大 ~120 秒
    while (!resolved && now_ms() < handoff_until) {
      char rmsg[160];
      if (sm_ot_hub_resolve(op.node_id, label, ip, 4000, rmsg, sizeof(rmsg))) {
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
      // EUI-64 導出が使える相手(public アドレス)は 20 秒で切り上げて導出へ。
      // 使えない相手(TrouBLE 等の static random)は 60 秒待つ —
      // AirQ(Rust FW)は WiFi join 後の DHCP + mDNS 開始に 20 秒以上かかる実測。
      resolved = resolve_via_mdns(op.node_id, idx, g_ble_peer_mac_ok ? 20000 : 60000);
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
  if (g_mdns_fd6 >= 0) {
    close(g_mdns_fd6);
    g_mdns_fd6 = -1;
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
    after_pair_complete(op.node_id);
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
  const bool join = sm_ot_hub_mode() == SM_OT_MODE_JOIN;
  const bool thread_up = sm_ot_hub_start_network();
  if (!thread_up && !join) {
    sm_app_set_status("failed to form/restore the Thread network");
    vTaskDelete(nullptr);
    return;
  }
  if (!thread_up) {
    // JOIN で dataset が無い / 適用失敗: Thread は起動しない(勝手に新規ネットワークを
    // 作らない)。コントローラ自体は WiFi デバイス用に動かし続ける。
    refresh_thread_status();
    sm_app_set_status("JOIN mode: no usable dataset; Thread is NOT started "
                      "(console: otmode join <dataset-hex>)");
    vTaskDelay(pdMS_TO_TICKS(3000)); // 画面/ログで読める時間だけ残す
  }
  if (thread_up) {
    // active dataset TLV(デバイス側プリセット用。ネットワーク情報タブと QR の素材)。
    char hex[SM_UI_DATASET_HEX_CAP];
    size_t n = sm_ot_hub_dataset_hex(hex, sizeof(hex));
    sm_ui_snapshot_t *s = sm_app_lock();
    memcpy(s->dataset_hex, hex, n + 1);
    sm_app_unlock();
  }
  refresh_thread_status();
  if (thread_up && join) {
    sm_app_set_status("thread up (JOIN); waiting to attach to the external network ...");
    if (!sm_ot_hub_wait_attached(60000)) {
      sm_app_set_status("JOIN: not attached yet (still trying in the background)");
    }
  } else if (thread_up) {
    sm_app_set_status("thread up; waiting for leader/router role ...");
    sm_ot_hub_wait_leader(30000);
  }
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
  g_ctx_mem = (uint8_t *)mem; // forget の再 init 用に覚えておく
  g_ctx_len = rounded;
  g_ctx_cfg = cfg;
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
  uint64_t next_clock = 0;
  uint64_t next_window = 0;                // T9: 開いた窓の WindowStatus 確認(10 秒)
  uint64_t next_poll = now_ms() + 30000; // 起動直後は WiFi/Thread 収束待ち(5 秒だと初回が必ず落ちて 2 分退避)
  size_t poll_index = 0;
  for (;;) {
    LoopTimer loop_timer;
    sm_ui_op_t op;
    bool have_op;
    {
      StepTimer st("take_op", STEP_WARN_MS);
      have_op = sm_app_take_op(&op, 100);
    }
    if (have_op) {
      {
        // UI op は run_until で秒単位かかるのが正常なので閾値を大きく取る。
        StepTimer st(op_step_name(op.kind), OP_WARN_MS);
        switch (op.kind) {
        case SM_UI_OP_TOGGLE:
          set_node_busy(op.node_id, true);
          do_toggle(op.node_id);
          set_node_busy(op.node_id, false);
          break;
        case SM_UI_OP_READ_ONOFF:
          set_node_busy(op.node_id, true);
          // 種別で分岐。センサ行の Read は「全属性の再読込」(§12.3 の 3)。
          if (node_kind(op.node_id) == SM_UI_KIND_SENSOR) {
            do_read_sensor_all(op.node_id, false, 20000);
          } else {
            do_read_onoff(op.node_id, false, 20000);
          }
          set_node_busy(op.node_id, false);
          break;
        case SM_UI_OP_REFRESH_ADDR:
          set_node_busy(op.node_id, true);
          do_refresh_addr(op.node_id);
          // ⟳ は種別の再検出も兼ねる(誤判別からの復帰導線。§12.3 の 1)。
          // トランスポートも同じキャッシュエントリなので一緒に取り直す。
          node_cache_set(op.node_id, SM_UI_KIND_UNKNOWN, SM_UI_TRANSPORT_UNKNOWN);
          set_node_kind(op.node_id, SM_UI_KIND_UNKNOWN);
          set_node_transport(op.node_id, SM_UI_TRANSPORT_UNKNOWN);
          if (size_t tslot = slot_of(op.node_id); tslot < SM_UI_MAX_NODES) {
            g_transport_retry_until[tslot] = 0;
          }
          clear_node_sensors(op.node_id);
          resolve_node_kind(op.node_id, 15000);
          set_node_busy(op.node_id, false);
          break;
        case SM_UI_OP_PAIR:
          do_pair(op);
          break;
        case SM_UI_OP_PAIR_BLE:
          do_pair_ble(op);
          break;
        case SM_UI_OP_SET_ADDR:
          do_set_addr(op);
          break;
        case SM_UI_OP_OPEN_WINDOW: // T9(§17.4)
          do_open_window(op);
          break;
        case SM_UI_OP_REVOKE_WINDOW:
          do_revoke_window(op.node_id);
          break;
        case SM_UI_OP_FORGET:
          do_forget(op.node_id);
          break;
        case SM_UI_OP_DNS_LOOKUP:
          do_dns_lookup(op.node_id);
          break;
        }
      }
      {
        StepTimer st("refresh_thread", STEP_WARN_MS);
        refresh_thread_status();
      }
      continue;
    }

    // 操作が無い間も UDP は回す(MRP の ACK / 再送で無音にならないように)。
    {
      StepTimer st("pump_once", STEP_WARN_MS);
      pump_once(g_udp, 50);
    }
    // T8(§16.3): デバイス発の購読レポート / 購読喪失をここで拾う。
    {
      StepTimer st("events", STEP_WARN_MS);
      sm_ctrl_event_t aev;
      while (sm_ctrl_take_event(&aev)) {
        consume_async_event(aev);
      }
    }

    uint64_t now = now_ms();
    // T6: 鮮度表示の基準時刻だけは細かく進める(500ms。lock は取るが中身は 1 語)。
    if (now >= next_clock) {
      next_clock = now + 500;
      StepTimer st("clock", STEP_WARN_MS); // lock 待ちが伸びていないかも見る
      sm_ui_snapshot_t *s = sm_app_lock();
      s->now_ms = now;
      sm_app_unlock();
    }
    if (now >= next_status) {
      next_status = now + 2000;
      {
        StepTimer st("refresh_thread", STEP_WARN_MS);
        refresh_thread_status();
      }
      {
        StepTimer st("refresh_wifi", STEP_WARN_MS);
        refresh_wifi_status();
      }
      if (sm_ctrl_node_count() != 0) {
        sm_ui_snapshot_t *s = sm_app_lock();
        size_t shown = s->node_count;
        sm_app_unlock();
        if (shown == 0) {
          StepTimer st("rebuild_nodes", STEP_WARN_MS);
          rebuild_node_list();
        }
      }
    }
    // T9(§17.4): 開いた窓の寿命管理。期限を過ぎたら閉じた扱いにし、開いている
    // 間は 10 秒ごとに WindowStatus を read して実際に閉じたかを確かめる
    // (ダイアログの「closes in N s」/「window closed」表示の素)。
    {
      bool open_now = false;
      sm_ui_snapshot_t *s = sm_app_lock();
      if (s->window.status == SM_UI_WINDOW_OPEN) {
        if (s->window.expires_ms != 0 && now >= s->window.expires_ms) {
          s->window.status = SM_UI_WINDOW_CLOSED;
          s->window.expires_ms = 0;
        } else {
          open_now = true;
        }
      }
      sm_app_unlock();
      if (open_now && now >= next_window) {
        next_window = now + WINDOW_POLL_MS;
        StepTimer st("window_poll", STEP_WARN_MS);
        poll_window_status();
        continue; // read で 1 秒級かかるので、次の周回で通常 tick に戻る
      }
      if (!open_now) {
        // 窓が無い間は「開いた直後の 10 秒」を先に確保しておく(開いてすぐ
        // read しに行かない)。
        next_window = now + WINDOW_POLL_MS;
      }
    }

    // T8b/P5(§16.6): 購読喪失を受けたノードは 10 秒 tick を待たずここで再購読する
    // (UI op はこの周回に無い = 上の op 処理を抜けてきている)。同一周回で複数
    // ノードが LOST でも **1 周 1 ノード**だけ処理し、UDP のポンプを止めない。
    if (uint64_t resub_id = resub_now_pop()) {
      size_t slot = slot_of(resub_id);
      uint8_t kind = node_kind(resub_id);
      if (slot >= SM_UI_MAX_NODES || kind == SM_UI_KIND_UNKNOWN) {
        // ノード表から消えた / 種別未確定。従来の 10 秒 tick に任せる。
      } else if (g_sub[slot] == SUB_ACTIVE || now < g_sub_retry_until[slot]) {
        // 既に張り直された / バックオフ中。
      } else {
        ESP_LOGI(TAG, "sub: resubscribe-now node=%016llx", (unsigned long long)resub_id);
        StepTimer st("resub_now", STEP_WARN_MS);
        set_node_busy(resub_id, true);
        bool sub_ok = do_subscribe_node(resub_id, kind, 20000);
        set_node_busy(resub_id, false);
        // do_subscribe_node 中の LOST で積み直された分は捨てる(今の結果が最新)。
        resub_now_clear(resub_id);
        // 行 index は購読中に動きうるので取り直す。
        slot = slot_of(resub_id);
        if (slot < SM_UI_MAX_NODES) {
          g_sub[slot] = sub_ok ? (uint8_t)SUB_ACTIVE : (uint8_t)SUB_NONE;
          g_sub_retry_until[slot] = sub_ok ? 0 : now + 120000;
          if (sub_ok) {
            g_backoff_until[slot] = 0; // 通信は成立している
          }
        }
        set_node_subscribed(resub_id, sub_ok);
        set_node_note(resub_id, sub_ok ? "subscribed" : "subscribe failed");
        if (sub_ok) {
          ensure_node_transport(resub_id);
        }
        continue; // 次の周回で UI op / 通常 tick に戻る
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
      StepTimer st("poll_tick", STEP_WARN_MS);
      sm_ui_snapshot_t *s = sm_app_lock();
      size_t count = s->node_count;
      sm_app_unlock();
      if (count > 0) {
        // T8(§16.3): 購読の生死をシムに合わせ直す(喪失イベントを取りこぼしても
        // ここで NONE に戻り、次の tick から従来 read + 再購読に落ちる)。
        {
          sm_ui_snapshot_t *s2 = sm_app_lock();
          for (size_t i = 0; i < s2->node_count && i < SM_UI_MAX_NODES; ++i) {
            bool active = sm_ctrl_is_subscribed(s2->nodes[i].node_id);
            if (!active && g_sub[i] == SUB_ACTIVE) {
              g_sub_retry_until[i] = 0;
            }
            g_sub[i] = active ? (uint8_t)SUB_ACTIVE : (uint8_t)SUB_NONE;
            s2->nodes[i].subscribed = active ? 1 : 0;
          }
          sm_app_unlock();
        }
        // バックオフ中でない **未購読の** ノードを 1 件選ぶ(購読中のノードは
        // 周期 read しない = keep-alive はコア任せ。全員対象外ならスキップ)。
        uint64_t id = 0;
        size_t slot = 0;
        for (size_t tries = 0; tries < count; ++tries) {
          size_t idx = poll_index % count;
          poll_index = (poll_index + 1) % count;
          if (idx < SM_UI_MAX_NODES && g_sub[idx] == SUB_ACTIVE) {
            continue;
          }
          if (idx < SM_UI_MAX_NODES && now < g_backoff_until[idx]) {
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
          // 種別で分岐(T4、§12.3 の 2)。未判定なら **この 1 周期を検出に使う**
          // (AirQuality → OnOff の 2 read。以後は NVS キャッシュで再判定しない)。
          bool ok;
          uint8_t kind = node_kind(id);
          // T8(§16.3): 種別が確定していて未購読なら、**この 1 周期を購読確立に使う**。
          // 成立すれば以後の周期 read は止まり、表示はレポートで更新される。
          // 失敗したら 2 分は再試行を控え、その間の表示は従来 read が賄う。
          if (kind != SM_UI_KIND_UNKNOWN && slot < SM_UI_MAX_NODES &&
              g_sub[slot] == SUB_NONE && now >= g_sub_retry_until[slot]) {
            bool sub_ok = do_subscribe_node(id, kind, 20000);
            g_sub[slot] = sub_ok ? (uint8_t)SUB_ACTIVE : (uint8_t)SUB_NONE;
            g_sub_retry_until[slot] = sub_ok ? 0 : now + 120000;
            set_node_subscribed(id, sub_ok);
            set_node_note(id, sub_ok ? "subscribed" : "subscribe failed");
            if (sub_ok) {
              g_backoff_until[slot] = 0; // 通信は成立している
              ensure_node_transport(id); // 旧キャッシュ(トランスポート無し)の補完
            }
            set_node_busy(id, false);
            continue; // read はしない(成功ならプライミング、失敗なら次の tick で read)
          }
          if (kind == SM_UI_KIND_UNKNOWN) {
            ok = resolve_node_kind(id, 10000) != SM_UI_KIND_UNKNOWN;
          } else if (kind == SM_UI_KIND_SENSOR) {
            // T6(§14.2): ダッシュボードの 5 タイルを同時に進めたいので、順繰り 1 属性
            // ではなく **1 周期で 5 属性まとめ読み**する(CASE 済みなら ≈1 秒)。
            // 1 本落ちたら do_read_sensor_all が打ち切るので、死んだノードでの
            // CASE 再試行は 1 回で済む(バックオフ契約は不変)。
            ok = do_read_sensor_all(id, true, 10000);
          } else {
            ok = do_read_onoff(id, true, 10000);
          }
          if (ok) {
            ensure_node_transport(id);
          }
          set_node_busy(id, false);
          if (slot < SM_UI_MAX_NODES) {
            g_backoff_until[slot] = ok ? 0 : now + 120000;
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
