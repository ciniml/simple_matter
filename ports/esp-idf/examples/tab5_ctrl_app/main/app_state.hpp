// UI(LVGL タスク)と pump(sm_ctrl 専有タスク)の間の唯一の連絡路。
// docs/design/p4-thread-controller.md §9.1「タスク構成(単線契約の維持)」。
//
//   UI → pump : 操作キュー(sm_ui_op_t を FreeRTOS キューで 1 件ずつ)
//   pump → UI : mutex 保護のスナップショット(sm_ui_snapshot_t)+ 世代カウンタ
//
// **sm_ctrl_* / ot_* を LVGL タスクから呼ばないこと**(例外なし)。UI が触ってよいのは
// このヘッダの関数だけ。逆に pump は lv_* を一切呼ばない。

#pragma once

#include <cstddef>
#include <cstdint>

// 画面に載せるノードの上限(コントローラのノード帳はこれより多く持てるが、
// v1 の一覧は 8 行までで打ち切る)。
inline constexpr size_t SM_UI_MAX_NODES = 8;
// active dataset TLV(最大 254 バイト)の hex + NUL。
inline constexpr size_t SM_UI_DATASET_HEX_CAP = 2 * 254 + 1;

// UI → pump の操作種別。
enum sm_ui_op_kind_t : uint8_t {
  SM_UI_OP_TOGGLE = 0,       // OnOff Toggle(cluster 0x0006 cmd 0x02)
  SM_UI_OP_READ_ONOFF = 1,   // OnOff.OnOff 読み(cluster 0x0006 attr 0x0000)
  SM_UI_OP_PAIR = 2,         // on-network PASE コミッショニング
  SM_UI_OP_REFRESH_ADDR = 3, // SRP 列挙(→ WiFi なら mDNS)→ アドレス更新
  SM_UI_OP_PAIR_BLE = 4      // BLE コミッショニング(T3、§11)
};

// PAIR の経路。0/1 は on-network(リンクローカル宛の sin6_scope_id をどちらの
// netif にするかだけの違いで、グローバル / ULA 宛では効かない。§10.3 の 5)。
// 2/3 は BLE コミッショニング(T3、§11)で、投入するネットワーク資格情報の種別を兼ねる。
enum sm_ui_via_t : uint8_t {
  SM_UI_VIA_THREAD = 0,
  SM_UI_VIA_WIFI = 1,
  SM_UI_VIA_BLE_WIFI = 2,  // BLE 経由 → デバイスを WiFi(Tab5 と同じ AP)へ
  SM_UI_VIA_BLE_THREAD = 3 // BLE 経由 → デバイスを Thread(Tab5 の dataset)へ
};

struct sm_ui_op_t {
  sm_ui_op_kind_t kind;
  uint64_t node_id;
  uint32_t passcode;      // PAIR / PAIR_BLE のみ
  char ipv6[46];          // PAIR のみ(NUL 終端の IPv6 リテラル)
  uint8_t via;            // PAIR / PAIR_BLE のみ(sm_ui_via_t)
  uint16_t discriminator; // PAIR_BLE のみ(広告照合。既定 3840)
};

// BLE コミッショニングの進捗(スナップショットの ble_stage)。UI はこれを文字列にする。
enum sm_ui_ble_stage_t : uint8_t {
  SM_UI_BLE_IDLE = 0,
  SM_UI_BLE_SCANNING = 1,  // discriminator 一致の 0xFFF6 広告を探している
  SM_UI_BLE_CONNECTED = 2, // 接続 + MTU 交換済み(GATT 発見中)
  SM_UI_BLE_SUBSCRIBED = 3, // C2 subscribe 完了(= BTP 給餌開始)
  SM_UI_BLE_COMMISSIONING = 4, // BTP 上で PASE → AddNOC → ネットワーク投入
  SM_UI_BLE_HANDOFF = 5,   // BLE_DONE。運用アドレス解決(SRP / mDNS)待ち
  SM_UI_BLE_CASE = 6,      // CASE over UDP + CommissioningComplete
  SM_UI_BLE_DONE = 7,      //
  SM_UI_BLE_FAILED = 8     //
};

// ノード 1 件の表示状態。
struct sm_ui_node_t {
  uint64_t node_id;
  char addr[64];  // "[fd..]:5540"(未解決なら "-")
  int8_t onoff;   // -1=不明 0=Off 1=On
  uint8_t busy;   // 1 = このノードに対する操作が進行中
  char note[40];  // 直近の結果("toggle OK" / "invoke failed" 等)
};

// pump → UI のスナップショット(丸ごとコピーして使う)。
struct sm_ui_snapshot_t {
  uint32_t seq; // 更新のたびに増える(UI は変化検知に使ってよい)

  // --- Thread ---
  int role;         // otDeviceRole
  uint16_t rloc16;
  uint8_t channel;
  uint16_t panid;
  bool srp_enabled;
  uint32_t srp_hosts;
  char netname[17];
  char dataset_hex[SM_UI_DATASET_HEX_CAP];

  // --- コントローラ ---
  bool ctrl_ready;
  size_t node_count;
  sm_ui_node_t nodes[SM_UI_MAX_NODES];

  // --- WiFi(T2、§10。pump が sm_wifi_get_status() をコピーする)---
  uint8_t wifi_state;    // sm_wifi_state_t: 0=off 1=connecting 2=connected 3=failed
  char wifi_ssid[33];    //
  char wifi_ll[46];      // リンクローカル(未取得なら "")
  char wifi_ip4[16];     // IPv4(未取得なら "")
  uint32_t wifi_netif;   // lwIP netif index(0 = 未確立)

  // --- BLE(T3、§11。pump が sm_ble_central_state() をコピーする)---
  uint8_t ble_host;  // sm_ble_host_state_t: 0=off 1=starting 2=ready 3=failed
  uint8_t ble_stage; // sm_ui_ble_stage_t(BLE コミッショニングの進捗)

  // --- pairing ---
  uint8_t pair_state; // 0=idle 1=進行中 2=成功 3=失敗
  uint8_t pair_phase; // sm_ctrl_event_t::phase(0..11)

  // --- その他 ---
  char status[160]; // 直近のイベント文字列(ステータスバー下段)
  uint32_t free_internal;
  uint32_t free_psram;
  uint32_t free_internal_min;
};

// 起動時に 1 回(app_main から。キューと mutex を作る)。
void sm_app_state_init();

// --- UI 側(LVGL タスク)---

// 操作を pump へ投げる(非ブロッキング。キュー満杯なら false)。
bool sm_app_post_op(const sm_ui_op_t *op);
// 現在のスナップショットを丸ごとコピーする。
void sm_app_snapshot_get(sm_ui_snapshot_t *out);

// --- pump 側 ---

// 操作を 1 件受け取る(wait_ms までブロック)。
bool sm_app_take_op(sm_ui_op_t *out, uint32_t wait_ms);
// スナップショットを書き換えるための排他区間。lock/unlock は必ず対で使う。
// unlock 時に seq が進む。
sm_ui_snapshot_t *sm_app_lock();
void sm_app_unlock();
// ステータス行を printf 形式で差し替える(内部で lock を取るので lock 中に呼ばない)。
void sm_app_set_status(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
