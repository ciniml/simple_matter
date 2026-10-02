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
  SM_UI_OP_READ_ONOFF = 1,   // Read(照明 = OnOff 1 発 / センサ = 全属性の再読込。T4)
  SM_UI_OP_PAIR = 2,         // on-network PASE コミッショニング
  SM_UI_OP_REFRESH_ADDR = 3, // SRP 列挙(→ WiFi なら mDNS)→ アドレス更新 + 種別再検出
  SM_UI_OP_PAIR_BLE = 4,     // BLE コミッショニング(T3、§11)
  SM_UI_OP_SET_ADDR = 5,     // 運用アドレスを直接指定(ipv6 欄に v4/v6 リテラル。T5a)
  SM_UI_OP_OPEN_WINDOW = 6,  // ECM コミッショニングウィンドウを開く(T9、§17.4)
  SM_UI_OP_REVOKE_WINDOW = 7 // 開いたウィンドウを閉じる(RevokeCommissioning。T9)
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
  uint16_t discriminator; // PAIR_BLE(広告照合。既定 3840)/ OPEN_WINDOW(0xFFFF = 乱数)
  uint16_t timeout_s;     // OPEN_WINDOW のみ(180..900。0 なら既定 300)
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

// ノード種別(T4、§12.3 の 1)。EP1 の AirQuality(0x005B)read が通れば SENSOR、
// OnOff(0x0006)が通れば LIGHT。判定結果は pump 側で NVS("smui")にキャッシュする。
enum sm_ui_node_kind_t : uint8_t {
  SM_UI_KIND_UNKNOWN = 0,
  SM_UI_KIND_LIGHT = 1,
  SM_UI_KIND_SENSOR = 2
};

// センサ属性のスロット(周期 poll はこの順に 1 周期 1 属性ずつ回す。§12.3 の 2)。
enum sm_ui_sensor_slot_t : uint8_t {
  SM_UI_SLOT_AQ = 0,   // EP1 0x005B/0 (u8, AirQualityEnum 0..6)
  SM_UI_SLOT_CO2 = 1,  // EP1 0x040D/0 (f32, ppm)
  SM_UI_SLOT_PM25 = 2, // EP1 0x042A/0 (f32, µg/m³)
  SM_UI_SLOT_TEMP = 3, // EP2 0x0402/0 (i16, ×0.01 ℃)
  SM_UI_SLOT_HUM = 4,  // EP3 0x0405/0 (u16, ×0.01 %)
  SM_UI_SLOT_COUNT = 5
};

// ノード 1 件の表示状態。
struct sm_ui_node_t {
  uint64_t node_id;
  char addr[64];  // "[fd..]:5540"(未解決なら "-")
  int8_t onoff;   // -1=不明 0=Off 1=On(照明のみ)
  uint8_t busy;   // 1 = このノードに対する操作が進行中
  char note[40];  // 直近の結果("toggle OK" / "invoke failed" 等)

  // --- T4: ノード種別とセンサ値(§12.3 の 4)---
  uint8_t kind; // sm_ui_node_kind_t

  // --- T8: 属性 Subscribe(§16.3)---
  // 1 = このノードへの購読が生きている(= 周期 read を止めており、表示は
  // デバイス発レポートで更新される)。0 = 未購読(従来の交互 read)。
  uint8_t subscribed;

  // 「未取得 / null」は has_* = 0 で表す(値そのものに番兵を使わない)。
  uint8_t aq;         // AirQualityEnum 0..6(0 = Unknown)
  uint8_t has_aq;     //
  float co2;          // ppm
  uint8_t has_co2;    //
  float pm25;         // µg/m³
  uint8_t has_pm25;   //
  int32_t temp_c100;  // ℃ ×100
  uint8_t has_temp;   //
  int32_t hum_p100;   // % ×100
  uint8_t has_hum;    //

  // --- T6: ダッシュボードの鮮度表示(§14.2)---
  // センサ値の read が最後に成立した時刻(pump の now_ms 基準。0 = 一度も成功していない)。
  // UI は snapshot の `now_ms` との差を「updated N s ago」に使う。
  uint64_t last_update_ms;
};

// --- T9(§17.4): コミッショニングウィンドウ ---
//
// 直近に開いた(あるいは開こうとした)窓 1 件。pump が
// `sm_ctrl_open_commissioning_window` → `sm_ctrl_last_window` の結果を書き、
// UI(Share ダイアログ)と console の `window` が読む。
enum sm_ui_window_status_t : uint8_t {
  SM_UI_WINDOW_NONE = 0,    // 一度も開いていない
  SM_UI_WINDOW_OPENING = 1, // 要求済み(WINDOW_OPENED 待ち)
  SM_UI_WINDOW_OPEN = 2,    // 開いている(expires_ms まで)
  SM_UI_WINDOW_CLOSED = 3,  // 閉じた(Revoke / 期限切れ / WindowStatus=0 を観測)
  SM_UI_WINDOW_FAILED = 4   // 開けなかった(status に理由)
};

struct sm_ui_window_t {
  uint64_t node_id;
  uint32_t passcode;
  uint16_t discriminator;
  char manual_code[12]; // 11 桁 + NUL(区切りは UI 側で入れる)
  char qr[32];          // "MT:..." + NUL
  uint64_t expires_ms;  // pump の now_ms 基準(0 = 未オープン)
  uint8_t status;       // sm_ui_window_status_t
  uint8_t fail_status;  // FAILED のときのクラスタ / IM ステータス
  uint8_t fail_phase;   // FAILED のときの失敗段階(1=VID 2=PID 3=invoke)
};

// pump → UI のスナップショット(丸ごとコピーして使う)。
struct sm_ui_snapshot_t {
  uint32_t seq; // 更新のたびに増える(UI は変化検知に使ってよい)

  // pump の現在時刻(esp_timer 由来の ms)。UI は last_update_ms との差で鮮度を出す(T6)。
  uint64_t now_ms;

  // --- Thread ---
  uint8_t ot_mode;  // sm_ot_mode_t(0=FORM 主宰 / 1=JOIN 外部ネットワークへ参加、§18)
  bool ot_started;  // Thread を起動したか(JOIN で dataset 無しなら false)
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

  // --- T9: コミッショニングウィンドウ(§17.4)---
  sm_ui_window_t window;

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
