// LVGL の画面(Tab5 = 1280x720 横向き)。docs/design/p4-thread-controller.md §9.1。
//
// 画面構成(v1):
//   1. ステータスバー   : Thread role / RLOC16 / channel / PAN / SRP / ノード数 / free heap
//   2. Dashboard タブ   : センサ 1 台 = 1 カード(5 タイル)+ 下段に照明の小タイル(T6 §14)
//   2. Devices タブ     : ノード一覧(NodeId・アドレス・On/Off バッジ・Toggle/Read/Addr)
//                         + 「Pair new device」でダイアログ
//   3. Pair ダイアログ  : IPv6 / NodeId / passcode をオンスクリーンキーボードで入力
//   4. Network タブ     : Thread の詳細 + active dataset TLV hex + その QR
//
// 契約(絶対): このファイルは sm_ctrl_* / ot_* を呼ばない。pump への依頼は
// sm_app_post_op()、pump からの状態取得は sm_app_snapshot_get() のみ。
// タッチ操作は「キューに積むだけ」で即座に返るので、LVGL タスクは決してブロックしない。

#include "ui.hpp"

#include "app_state.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_log.h"
#include "lvgl.h"
#include "sdkconfig.h"

namespace {

constexpr const char *TAG = "ui";

// 指で押せるサイズ(§9.1「ボタン高さ 60px 以上」)。
constexpr int32_t BTN_H = 64;
constexpr int32_t ROW_H = 96;
constexpr int32_t STATUSBAR_H = 96;
constexpr int32_t TABBAR_H = 64;

// 配色(暗色ベース。プロジェクタ/写真映え重視)。
constexpr uint32_t COL_BG = 0x11151c;
constexpr uint32_t COL_PANEL = 0x1b2130;
constexpr uint32_t COL_ROW = 0x232b3d;
constexpr uint32_t COL_ACCENT = 0x2f81f7;
constexpr uint32_t COL_ON = 0x27ae60;
constexpr uint32_t COL_OFF = 0x4a5163;
constexpr uint32_t COL_WARN = 0xe67e22;
constexpr uint32_t COL_TEXT = 0xe6edf3;
constexpr uint32_t COL_DIM = 0x8b98a9;

const char *ROLE_NAME[] = {"Disabled", "Detached", "Child", "Router", "Leader"};
const char *PHASE_NAME[] = {"Idle",        "PASE",  "ArmFailSafe",    "Attestation",
                            "CSR",         "AddTrustedRoot", "AddNOC", "CASE",
                            "Complete",    "Done",  "AddWiFi",        "ConnectNetwork"};

// AirQualityEnum(0..6)の表示(T4、§12.3 の 3)。0 = Unknown / 未取得はグレーの "?"。
struct AqStyle {
  const char *name;
  uint32_t color;
};
const AqStyle AQ_STYLE[] = {
    {"?", 0x4a5163},         // 0 Unknown
    {"Good", 0x27ae60},      // 1
    {"Fair", 0x7fb800},      // 2
    {"Moderate", 0xd4b106},  // 3
    {"Poor", 0xe67e22},      // 4
    {"VeryPoor", 0xd94f2b},  // 5
    {"ExtPoor", 0xc0392b},   // 6 ExtremelyPoor
};

// --- Dashboard タブ(T6、§14.1)---
//
// 1280 幅の内訳: タブ本体 pad 12×2 → 1256、カード pad 10×2 → 1236、
// タイル 236×5 + 隙間 12×4 = 1228 ≤ 1236。
constexpr int32_t TILE_W = 236;
constexpr int32_t TILE_H = 210;
constexpr int32_t TILE_GAP = 12;
constexpr int32_t CARD_HEAD_H = 34;
constexpr int32_t CARD_H = CARD_HEAD_H + 8 + TILE_H + 20; // pad_all 10 の上下込み
constexpr int32_t LIGHT_TILE_W = 400;
constexpr int32_t LIGHT_TILE_H = 92;

// タイルの地色。しきい値色は下の *_color()、中立(温湿度)と未取得はこの 2 色。
constexpr uint32_t COL_TILE_NEUTRAL = 0x2b3448;
constexpr uint32_t COL_TILE_NONE = 0x394155; // 未取得(グレー)
constexpr uint32_t COL_LVL_GOOD = 0x27ae60;
constexpr uint32_t COL_LVL_FAIR = 0xd4b106;
constexpr uint32_t COL_LVL_POOR = 0xe67e22;
constexpr uint32_t COL_LVL_BAD = 0xc0392b;

// §14.1 のしきい値。CO2: <800 / <1000 / <1500 / それ以上。
uint32_t co2_color(float v) {
  if (v < 800.0f) {
    return COL_LVL_GOOD;
  }
  if (v < 1000.0f) {
    return COL_LVL_FAIR;
  }
  if (v < 1500.0f) {
    return COL_LVL_POOR;
  }
  return COL_LVL_BAD;
}
// PM2.5: <12 / <35 / <55 / それ以上(µg/m³)。
uint32_t pm25_color(float v) {
  if (v < 12.0f) {
    return COL_LVL_GOOD;
  }
  if (v < 35.0f) {
    return COL_LVL_FAIR;
  }
  if (v < 55.0f) {
    return COL_LVL_POOR;
  }
  return COL_LVL_BAD;
}

// タイル(名前 / 値 / 単位の 3 段)。**値は必ずラベルウィジェット**にする
// (canvas に描くと ui-dump で拾えない。§14.3 のゲート 2)。
struct SensorTile {
  lv_obj_t *root = nullptr;
  lv_obj_t *lbl_value = nullptr;
  lv_obj_t *lbl_unit = nullptr;
};

struct SensorCard {
  lv_obj_t *root = nullptr;
  lv_obj_t *lbl_title = nullptr;
  lv_obj_t *lbl_age = nullptr;
  SensorTile tiles[SM_UI_SLOT_COUNT];
};

struct LightTile {
  lv_obj_t *root = nullptr;
  lv_obj_t *lbl_id = nullptr;
  lv_obj_t *badge = nullptr;
  lv_obj_t *lbl_badge = nullptr;
};

// --- ウィジェット一式 ---
struct NodeRowWidgets {
  lv_obj_t *root = nullptr;
  lv_obj_t *lbl_id = nullptr;
  lv_obj_t *lbl_addr = nullptr;
  lv_obj_t *lbl_sensor = nullptr; // センサ行の 2 行目サマリ(照明行では隠す)
  lv_obj_t *badge = nullptr;
  lv_obj_t *lbl_sub = nullptr; // T8: 購読中マーカ("* sub")
  lv_obj_t *lbl_note = nullptr;
  lv_obj_t *btn_toggle = nullptr;
};

struct Ui {
  // ステータスバー
  lv_obj_t *lbl_thread = nullptr;
  lv_obj_t *lbl_heap = nullptr;
  lv_obj_t *lbl_status = nullptr;
  lv_obj_t *lbl_wifi = nullptr;
  // Dashboard タブ(T6)
  lv_obj_t *dash = nullptr;            // スクロールするカラム(タブ本体)
  lv_obj_t *lbl_dash_empty = nullptr;  // センサ 0 台のときのメッセージ
  lv_obj_t *lights_panel = nullptr;    // 下段(照明の小タイル)
  lv_obj_t *lights_wrap = nullptr;     // 小タイルを並べる wrap 行
  SensorCard cards[SM_UI_MAX_NODES];
  size_t card_count = 0;
  uint64_t card_ids[SM_UI_MAX_NODES] = {};
  LightTile lights[SM_UI_MAX_NODES];
  size_t light_count = 0;
  uint64_t light_ids[SM_UI_MAX_NODES] = {};
  // Devices タブ
  lv_obj_t *list = nullptr;
  lv_obj_t *lbl_empty = nullptr;
  NodeRowWidgets rows[SM_UI_MAX_NODES];
  uint64_t row_ids[SM_UI_MAX_NODES] = {};
  size_t row_count = 0;
  // Network タブ
  lv_obj_t *lbl_net = nullptr;
  lv_obj_t *lbl_dataset = nullptr;
  lv_obj_t *qr = nullptr;
  char qr_data[SM_UI_DATASET_HEX_CAP] = {};
  // Pair ダイアログ
  lv_obj_t *modal = nullptr;
  lv_obj_t *ta_ipv6 = nullptr;
  lv_obj_t *ta_node = nullptr;
  lv_obj_t *ta_pass = nullptr;
  lv_obj_t *dd_via = nullptr;      // 経路(sm_ui_via_t、4 択)
  lv_obj_t *lbl_addr_cap = nullptr; // 1 番目の欄のキャプション("IPv6" / "Discriminator")
  lv_obj_t *lbl_hint = nullptr;     // ダイアログの説明文(経路で書き換える)
  lv_obj_t *lbl_pair = nullptr;
  lv_obj_t *kb = nullptr;
  bool pair_open = false;
  bool pair_started = false; // Start を押してから結果表示を始める
  // --- T9(§17.4): Share ダイアログ ---
  lv_obj_t *share_modal = nullptr;
  lv_obj_t *lbl_share_head = nullptr;
  lv_obj_t *lbl_share_code = nullptr; // manual pairing code(montserrat 48)
  lv_obj_t *lbl_share_sub = nullptr;  // passcode / discriminator
  lv_obj_t *lbl_share_state = nullptr; // "closes in N s" / "window closed"
  lv_obj_t *share_qr = nullptr;
  uint64_t share_node = 0;
  char share_qr_data[40] = {};

  bool pair_ble = false;     // 1 番目の欄が discriminator になっているか
  char saved_ipv6[46] = {};  // BLE へ切り替えたときに退避する IPv6
  char saved_disc[8] = {};   // on-network へ戻したときに退避する discriminator
};

Ui g_ui;
sm_ui_snapshot_t g_snap; // タイマ内でだけ触る(LVGL タスク専有)
int32_t g_scr_w = 1280;  // 回転後の画面サイズ(sm_ui_create で実測値に差し替える)
int32_t g_scr_h = 720;

// --- 小物 ---

void style_panel(lv_obj_t *o, uint32_t color) {
  lv_obj_set_style_bg_color(o, lv_color_hex(color), 0);
  lv_obj_set_style_bg_opa(o, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(o, 0, 0);
  lv_obj_set_style_radius(o, 10, 0);
  lv_obj_set_style_pad_all(o, 10, 0);
}

lv_obj_t *make_label(lv_obj_t *parent, const lv_font_t *font, uint32_t color, const char *text) {
  lv_obj_t *l = lv_label_create(parent);
  lv_obj_set_style_text_font(l, font, 0);
  lv_obj_set_style_text_color(l, lv_color_hex(color), 0);
  lv_label_set_text(l, text);
  return l;
}

lv_obj_t *make_button(lv_obj_t *parent, const char *text, int32_t w, uint32_t color,
                      lv_event_cb_t cb, void *user_data) {
  lv_obj_t *b = lv_button_create(parent);
  lv_obj_set_size(b, w, BTN_H);
  lv_obj_set_style_bg_color(b, lv_color_hex(color), 0);
  lv_obj_set_style_radius(b, 8, 0);
  lv_obj_t *l = lv_label_create(b);
  lv_obj_set_style_text_font(l, &lv_font_montserrat_20, 0);
  lv_label_set_text(l, text);
  lv_obj_center(l);
  if (cb != nullptr) {
    lv_obj_add_event_cb(b, cb, LV_EVENT_CLICKED, user_data);
  }
  return b;
}

// 行インデックス(user_data)から NodeId を引く。
uint64_t row_node_id(lv_event_t *e) {
  size_t idx = (size_t)(uintptr_t)lv_event_get_user_data(e);
  return idx < g_ui.row_count ? g_ui.row_ids[idx] : 0;
}

void post(sm_ui_op_kind_t kind, uint64_t node_id) {
  if (node_id == 0) {
    return;
  }
  sm_ui_op_t op = {};
  op.kind = kind;
  op.node_id = node_id;
  if (!sm_app_post_op(&op)) {
    lv_label_set_text(g_ui.lbl_status, "busy: the pump queue is full, try again");
  }
}

// --- Pair ダイアログ ---

void close_pair_dialog() {
  if (g_ui.modal != nullptr) {
    lv_obj_delete(g_ui.modal);
    g_ui.modal = nullptr;
    g_ui.ta_ipv6 = g_ui.ta_node = g_ui.ta_pass = g_ui.lbl_pair = g_ui.kb = nullptr;
    g_ui.dd_via = g_ui.lbl_addr_cap = g_ui.lbl_hint = nullptr;
  }
  g_ui.pair_open = false;
}

void on_pair_close(lv_event_t *) { close_pair_dialog(); }

// テキストエリアにフォーカスが来たらキーボードを繋ぎ替える。
void on_ta_focus(lv_event_t *e) {
  lv_obj_t *ta = (lv_obj_t *)lv_event_get_target(e);
  if (g_ui.kb == nullptr) {
    return;
  }
  lv_keyboard_set_textarea(g_ui.kb, ta);
  lv_keyboard_set_mode(g_ui.kb, ta == g_ui.ta_pass ? LV_KEYBOARD_MODE_NUMBER
                                                   : LV_KEYBOARD_MODE_TEXT_LOWER);
}

// "0x..." / "..." の 16 進文字列を u64 に(不正なら false)。
bool parse_hex_u64(const char *s, uint64_t *out) {
  if (s == nullptr) {
    return false;
  }
  while (*s == ' ') {
    ++s;
  }
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
    s += 2;
  }
  if (*s == 0) {
    return false;
  }
  uint64_t v = 0;
  for (; *s; ++s) {
    uint8_t d;
    if (*s >= '0' && *s <= '9') {
      d = (uint8_t)(*s - '0');
    } else if (*s >= 'a' && *s <= 'f') {
      d = (uint8_t)(*s - 'a' + 10);
    } else if (*s >= 'A' && *s <= 'F') {
      d = (uint8_t)(*s - 'A' + 10);
    } else if (*s == ' ') {
      continue;
    } else {
      return false;
    }
    v = (v << 4) | d;
  }
  *out = v;
  return true;
}

// via の選択(0..3)。sm_ui_via_t と同じ並びにしてある。
uint8_t selected_via() {
  if (g_ui.dd_via == nullptr) {
    return SM_UI_VIA_THREAD;
  }
  uint32_t sel = lv_dropdown_get_selected(g_ui.dd_via);
  return (uint8_t)(sel <= SM_UI_VIA_BLE_THREAD ? sel : SM_UI_VIA_THREAD);
}

bool via_is_ble(uint8_t via) {
  return via == SM_UI_VIA_BLE_WIFI || via == SM_UI_VIA_BLE_THREAD;
}

// 経路を切り替えたら 1 番目の欄を IPv6 ⇄ Discriminator で付け替える(§11.1 の UI)。
void on_via_changed(lv_event_t *) {
  const bool ble = via_is_ble(selected_via());
  if (ble == g_ui.pair_ble || g_ui.ta_ipv6 == nullptr) {
    return;
  }
  const char *cur = lv_textarea_get_text(g_ui.ta_ipv6);
  if (ble) {
    snprintf(g_ui.saved_ipv6, sizeof(g_ui.saved_ipv6), "%s", cur);
    char dbuf[8];
    snprintf(dbuf, sizeof(dbuf), "%d", CONFIG_SM_UI_DEFAULT_DISCRIMINATOR);
    lv_textarea_set_text(g_ui.ta_ipv6, g_ui.saved_disc[0] ? g_ui.saved_disc : dbuf);
    lv_label_set_text(g_ui.lbl_addr_cap, "Discriminator");
    lv_label_set_text(g_ui.lbl_hint,
                      "The device must be advertising its Matter commissionable service\n"
                      "(0xFFF6) over BLE. No address needed: the Tab5 hands over its own\n"
                      "WiFi credentials or Thread dataset, then resolves the node over\n"
                      "mDNS (WiFi) / SRP (Thread) and finishes with CASE over UDP.");
  } else {
    snprintf(g_ui.saved_disc, sizeof(g_ui.saved_disc), "%s", cur);
    lv_textarea_set_text(g_ui.ta_ipv6, g_ui.saved_ipv6[0] ? g_ui.saved_ipv6 : "fd00::1");
    lv_label_set_text(g_ui.lbl_addr_cap, "IPv6");
    lv_label_set_text(g_ui.lbl_hint,
                      "The device must already be on the selected network with a commissioning\n"
                      "window open. Copy its ML-EID / OMR (Thread) or LAN address (WiFi) from\n"
                      "its log. \"via\" only picks the scope for fe80::/10 targets -- prefer a\n"
                      "routable ULA/GUA for WiFi, since the node book does not persist scopes.");
  }
  g_ui.pair_ble = ble;
  if (g_ui.kb != nullptr) {
    lv_keyboard_set_textarea(g_ui.kb, g_ui.ta_ipv6);
    lv_keyboard_set_mode(g_ui.kb, ble ? LV_KEYBOARD_MODE_NUMBER : LV_KEYBOARD_MODE_TEXT_LOWER);
  }
}

void on_pair_start(lv_event_t *) {
  if (g_ui.ta_ipv6 == nullptr) {
    return;
  }
  sm_ui_op_t op = {};
  op.via = selected_via();
  const bool ble = via_is_ble(op.via);
  op.kind = ble ? SM_UI_OP_PAIR_BLE : SM_UI_OP_PAIR;
  if (ble) {
    long d = strtol(lv_textarea_get_text(g_ui.ta_ipv6), nullptr, 10);
    if (d <= 0 || d > 4095) {
      lv_label_set_text(g_ui.lbl_pair, "#e67e22 discriminator must be 1..4095 #");
      return;
    }
    op.discriminator = (uint16_t)d;
  } else {
    snprintf(op.ipv6, sizeof(op.ipv6), "%s", lv_textarea_get_text(g_ui.ta_ipv6));
  }
  uint64_t node = 0;
  if (!parse_hex_u64(lv_textarea_get_text(g_ui.ta_node), &node) || node == 0) {
    lv_label_set_text(g_ui.lbl_pair, "#e67e22 NodeId must be a non-zero hex value #");
    return;
  }
  op.node_id = node;
  op.passcode = (uint32_t)strtoul(lv_textarea_get_text(g_ui.ta_pass), nullptr, 10);
  if (op.passcode == 0) {
    lv_label_set_text(g_ui.lbl_pair, "#e67e22 passcode must be a decimal number #");
    return;
  }
  if (!sm_app_post_op(&op)) {
    lv_label_set_text(g_ui.lbl_pair, "#e67e22 pump is busy; try again #");
    return;
  }
  g_ui.pair_started = true;
  lv_label_set_text(g_ui.lbl_pair, ble ? "starting BLE scan ..." : "starting on-network PASE ...");
}

// 既存 NodeId と衝突しない初期値を作る。
uint64_t suggest_node_id() {
  uint64_t id = (uint64_t)CONFIG_SM_UI_DEFAULT_NODE_ID;
  for (int guard = 0; guard < 64; ++guard) {
    bool used = false;
    for (size_t i = 0; i < g_snap.node_count; ++i) {
      if (g_snap.nodes[i].node_id == id) {
        used = true;
        break;
      }
    }
    if (!used) {
      return id;
    }
    ++id;
  }
  return id;
}

void open_pair_dialog(lv_event_t *) {
  if (g_ui.modal != nullptr) {
    return;
  }
  lv_obj_t *scr = lv_screen_active();
  lv_obj_t *modal = lv_obj_create(scr);
  g_ui.modal = modal;
  lv_obj_remove_style_all(modal);
  lv_obj_set_size(modal, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(modal, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(modal, LV_OPA_70, 0);
  lv_obj_remove_flag(modal, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *card = lv_obj_create(modal);
  style_panel(card, COL_PANEL);
  lv_obj_set_size(card, g_scr_w - 160, 384);
  lv_obj_set_pos(card, 80, 16);
  lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(card, 10, 0);

  make_label(card, &lv_font_montserrat_24, COL_TEXT, "Pair a device");
  g_ui.lbl_hint =
      make_label(card, &lv_font_montserrat_14, COL_DIM,
                 "The device must already be on the selected network with a commissioning\n"
                 "window open. Copy its ML-EID / OMR (Thread) or LAN address (WiFi) from\n"
                 "its log. \"via\" only picks the scope for fe80::/10 targets -- prefer a\n"
                 "routable ULA/GUA for WiFi, since the node book does not persist scopes.");

  lv_obj_t *first_cap = nullptr;
  auto add_field = [&](const char *caption, const char *initial, int32_t width) {
    lv_obj_t *row = lv_obj_create(card);
    lv_obj_remove_style_all(row);
    lv_obj_set_size(row, LV_PCT(100), BTN_H);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(row, 12, 0);
    lv_obj_t *cap = make_label(row, &lv_font_montserrat_20, COL_DIM, caption);
    lv_obj_set_width(cap, 180);
    if (first_cap == nullptr) {
      first_cap = cap;
    }
    lv_obj_t *ta = lv_textarea_create(row);
    lv_textarea_set_one_line(ta, true);
    lv_textarea_set_text(ta, initial);
    lv_obj_set_size(ta, width, BTN_H);
    lv_obj_set_style_text_font(ta, &lv_font_montserrat_20, 0);
    lv_obj_add_event_cb(ta, on_ta_focus, LV_EVENT_FOCUSED, nullptr);
    lv_obj_add_event_cb(ta, on_ta_focus, LV_EVENT_CLICKED, nullptr);
    return ta;
  };

  g_ui.ta_ipv6 = add_field("IPv6", "fd00::1", 700);
  g_ui.lbl_addr_cap = first_cap;
  char idbuf[24];
  snprintf(idbuf, sizeof(idbuf), "%016llx", (unsigned long long)suggest_node_id());
  g_ui.ta_node = add_field("NodeId (hex)", idbuf, 360);
  char pcbuf[16];
  snprintf(pcbuf, sizeof(pcbuf), "%d", CONFIG_SM_UI_DEFAULT_PASSCODE);
  g_ui.ta_pass = add_field("Passcode", pcbuf, 240);

  // 経路の選択(§10.3 の 6 / §11.1)。Passcode と同じ行に相乗りさせてカード高を保つ。
  // 並びは sm_ui_via_t と一致させること(selected_via() がそのまま使う)。
  {
    lv_obj_t *row = lv_obj_get_parent(g_ui.ta_pass);
    lv_obj_t *cap = make_label(row, &lv_font_montserrat_20, COL_DIM, "via");
    lv_obj_set_width(cap, 60);
    g_ui.dd_via = lv_dropdown_create(row);
    lv_dropdown_set_options_static(
        g_ui.dd_via, "On-network Thread\nOn-network WiFi\nBLE - WiFi\nBLE - Thread");
    lv_dropdown_set_selected(g_ui.dd_via, SM_UI_VIA_THREAD); // 既定は on-network Thread
    lv_obj_set_size(g_ui.dd_via, 360, BTN_H);
    lv_obj_set_style_text_font(g_ui.dd_via, &lv_font_montserrat_20, 0);
    lv_obj_add_event_cb(g_ui.dd_via, on_via_changed, LV_EVENT_VALUE_CHANGED, nullptr);
  }

  lv_obj_t *btns = lv_obj_create(card);
  lv_obj_remove_style_all(btns);
  lv_obj_set_size(btns, LV_PCT(100), BTN_H);
  lv_obj_set_flex_flow(btns, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(btns, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(btns, 16, 0);
  make_button(btns, "Start pairing", 260, COL_ACCENT, on_pair_start, nullptr);
  make_button(btns, "Close", 180, COL_OFF, on_pair_close, nullptr);
  g_ui.lbl_pair = make_label(btns, &lv_font_montserrat_20, COL_TEXT, "");
  lv_label_set_recolor(g_ui.lbl_pair, true);

  g_ui.kb = lv_keyboard_create(modal);
  lv_obj_set_size(g_ui.kb, g_scr_w, g_scr_h - 424);
  // lv_keyboard のコンストラクタは BOTTOM_MID アラインを設定するので、set_pos の
  // y はそのアンカーからのオフセットになり画面外へ飛ぶ(実機で発見)。align で置く。
  lv_obj_align(g_ui.kb, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_keyboard_set_textarea(g_ui.kb, g_ui.ta_ipv6);
  lv_keyboard_set_mode(g_ui.kb, LV_KEYBOARD_MODE_TEXT_LOWER);

  g_ui.pair_open = true;
  g_ui.pair_started = false;
  g_ui.pair_ble = false;
}

// --- Devices タブ ---

// --- T9(§17.4): Share ダイアログ(コミッショニングウィンドウ)---
//
// pair ダイアログと同じ作法(全画面の半透明モーダル + カード)。表示内容は
// スナップショットの `window` 欄だけを見る(pump が埋める)。

// 11 桁の manual pairing code を "XXXX-XXX-XXXX" に整形する。
void format_manual_code(const char *src, char *out, size_t cap) {
  const size_t n = (src != nullptr) ? strlen(src) : 0;
  if (n != 11) {
    snprintf(out, cap, "%s", (n != 0) ? src : "-");
    return;
  }
  snprintf(out, cap, "%.4s-%.3s-%.4s", src, src + 4, src + 7);
}

void close_share_dialog() {
  if (g_ui.share_modal != nullptr) {
    lv_obj_delete(g_ui.share_modal);
    g_ui.share_modal = nullptr;
    g_ui.lbl_share_head = g_ui.lbl_share_code = g_ui.lbl_share_sub = nullptr;
    g_ui.lbl_share_state = g_ui.share_qr = nullptr;
    g_ui.share_qr_data[0] = '\0';
  }
  g_ui.share_node = 0;
}

void on_share_close(lv_event_t *) { close_share_dialog(); }

void on_share_revoke(lv_event_t *) {
  if (g_ui.share_node != 0) {
    post(SM_UI_OP_REVOKE_WINDOW, g_ui.share_node);
    if (g_ui.lbl_share_state != nullptr) {
      lv_label_set_text(g_ui.lbl_share_state, "revoking ...");
    }
  }
}

void open_share_dialog(uint64_t node_id) {
  close_share_dialog();
  g_ui.share_node = node_id;

  lv_obj_t *scr = lv_screen_active();
  lv_obj_t *modal = lv_obj_create(scr);
  g_ui.share_modal = modal;
  lv_obj_remove_style_all(modal);
  lv_obj_set_size(modal, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(modal, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(modal, LV_OPA_70, 0);
  lv_obj_remove_flag(modal, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *card = lv_obj_create(modal);
  style_panel(card, COL_PANEL);
  lv_obj_set_size(card, g_scr_w - 160, 560);
  lv_obj_set_pos(card, 80, 60);
  lv_obj_remove_flag(card, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(card, 10, 0);

  char head[80];
  snprintf(head, sizeof(head), "Share 0x%016llx with another controller",
           (unsigned long long)node_id);
  g_ui.lbl_share_head = make_label(card, &lv_font_montserrat_24, COL_TEXT, head);
  make_label(card, &lv_font_montserrat_14, COL_DIM,
             "Enter the code below on the second controller (chip-tool / smctl \"pairing code\",\n"
             "or scan the QR with a phone app). The window closes automatically when it expires.");

  lv_obj_t *body = lv_obj_create(card);
  lv_obj_remove_style_all(body);
  lv_obj_set_size(body, LV_PCT(100), 300);
  lv_obj_set_flex_flow(body, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(body, 24, 0);

  lv_obj_t *left = lv_obj_create(body);
  lv_obj_remove_style_all(left);
  lv_obj_set_size(left, g_scr_w - 160 - 20 - 220 - 24, 300);
  lv_obj_set_flex_flow(left, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(left, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_row(left, 14, 0);
  make_label(left, &lv_font_montserrat_16, COL_ACCENT, "Manual pairing code");
  g_ui.lbl_share_code = make_label(left, &lv_font_montserrat_48, COL_TEXT, "----------- ");
  g_ui.lbl_share_sub = make_label(left, &lv_font_montserrat_20, COL_DIM, "");
  g_ui.lbl_share_state = make_label(left, &lv_font_montserrat_24, COL_WARN, "opening window ...");

  lv_obj_t *right = lv_obj_create(body);
  lv_obj_remove_style_all(right);
  lv_obj_set_size(right, 240, 300);
  lv_obj_set_flex_flow(right, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(right, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(right, 8, 0);
#if LV_USE_QRCODE
  g_ui.share_qr = lv_qrcode_create(right);
  lv_qrcode_set_size(g_ui.share_qr, 220);
  lv_qrcode_set_dark_color(g_ui.share_qr, lv_color_hex(0x000000));
  lv_qrcode_set_light_color(g_ui.share_qr, lv_color_hex(0xffffff));
  lv_obj_set_style_border_width(g_ui.share_qr, 8, 0);
  lv_obj_set_style_border_color(g_ui.share_qr, lv_color_hex(0xffffff), 0);
#else
  make_label(right, &lv_font_montserrat_14, COL_DIM, "(LV_USE_QRCODE is disabled)");
#endif

  lv_obj_t *btns = lv_obj_create(card);
  lv_obj_remove_style_all(btns);
  lv_obj_set_size(btns, LV_PCT(100), BTN_H);
  lv_obj_set_flex_flow(btns, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(btns, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(btns, 16, 0);
  make_button(btns, "Revoke", 220, COL_WARN, on_share_revoke, nullptr);
  make_button(btns, "Close", 180, COL_OFF, on_share_close, nullptr);
}

void on_share(lv_event_t *e) {
  const uint64_t node_id = row_node_id(e);
  if (node_id == 0) {
    return;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_OPEN_WINDOW;
  op.node_id = node_id;
  op.timeout_s = 300;      // 既定 5 分(§17.4)
  op.discriminator = 0xFFFF; // シムで乱数生成(12bit)
  op.passcode = 0;           // 同上(仕様の禁止値を避けた乱数)
  if (!sm_app_post_op(&op)) {
    lv_label_set_text(g_ui.lbl_status, "busy: the pump queue is full, try again");
    return;
  }
  open_share_dialog(node_id);
}

void on_toggle(lv_event_t *e) { post(SM_UI_OP_TOGGLE, row_node_id(e)); }
void on_read(lv_event_t *e) { post(SM_UI_OP_READ_ONOFF, row_node_id(e)); }
void on_refresh_addr(lv_event_t *e) { post(SM_UI_OP_REFRESH_ADDR, row_node_id(e)); }

void build_node_row(size_t idx) {
  NodeRowWidgets &w = g_ui.rows[idx];
  w.root = lv_obj_create(g_ui.list);
  style_panel(w.root, COL_ROW);
  lv_obj_set_size(w.root, LV_PCT(100), ROW_H);
  lv_obj_remove_flag(w.root, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(w.root, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(w.root, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(w.root, 12, 0);

  // 左カラム: NodeId / アドレス /(センサ行のみ)計測値サマリの 3 段。
  // ROW_H は 96 のまま(20+14+16 の 3 行 = 約 60px < ROW_H-20)。
  lv_obj_t *col = lv_obj_create(w.root);
  lv_obj_remove_style_all(col);
  // 幅は行の総和が画面に収まるように: 370 + 150(badge) + 40(sub) + 120(note) +
  // 130 + 120 + 150 + 110(ボタン)+ 隙間 12×7 = 1274 ≤ 1280
  // (T9 §17.4 で Share ボタン 110 を足すぶん、名前列を 480 → 370 に詰めた)。
  lv_obj_set_size(col, 370, ROW_H - 20);
  lv_obj_set_flex_flow(col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(col, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  w.lbl_id = make_label(col, &lv_font_montserrat_20, COL_TEXT, "-");
  w.lbl_addr = make_label(col, &lv_font_montserrat_14, COL_DIM, "-");
  w.lbl_sensor = make_label(col, &lv_font_montserrat_16, COL_ACCENT, "");
  lv_obj_add_flag(w.lbl_sensor, LV_OBJ_FLAG_HIDDEN);

  // バッジ: 照明は ON/OFF、センサは AirQuality の 6 段階(色 + 名前)。
  w.badge = lv_obj_create(w.root);
  style_panel(w.badge, COL_OFF);
  lv_obj_set_size(w.badge, 150, 56);
  lv_obj_remove_flag(w.badge, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *bl = make_label(w.badge, &lv_font_montserrat_16, 0xffffff, "?");
  lv_obj_center(bl);
  lv_obj_set_user_data(w.badge, bl);

  // T8(§16.3): 購読中の行に小さなマーカを出す(未購読なら空)。
  w.lbl_sub = make_label(w.root, &lv_font_montserrat_14, COL_ACCENT, "");
  lv_obj_set_width(w.lbl_sub, 40);

  w.lbl_note = make_label(w.root, &lv_font_montserrat_14, COL_DIM, "");
  lv_obj_set_width(w.lbl_note, 120);

  void *ud = (void *)(uintptr_t)idx;
  w.btn_toggle = make_button(w.root, "Toggle", 130, COL_ACCENT, on_toggle, ud);
  make_button(w.root, "Read", 120, COL_OFF, on_read, ud);
  make_button(w.root, LV_SYMBOL_REFRESH " Addr", 150, COL_OFF, on_refresh_addr, ud);
  // T9(§17.4): 別のコントローラへ渡すためのコミッショニングウィンドウを開く。
  make_button(w.root, "Share", 110, COL_WARN, on_share, ud);
}

void on_reload(lv_event_t *) {
  // pump 側の一覧再構築は周期処理に任せているので、UI は行を作り直させるだけ。
  g_ui.row_count = 0;
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_ui.rows[i].root != nullptr) {
      lv_obj_delete(g_ui.rows[i].root);
      g_ui.rows[i] = NodeRowWidgets{};
    }
  }
}

// --- 反映(500ms タイマ)---

void refresh_status_bar() {
  const char *role = (g_snap.role >= 0 && g_snap.role <= 4) ? ROLE_NAME[g_snap.role] : "?";
  lv_label_set_text_fmt(g_ui.lbl_thread,
                        LV_SYMBOL_WIFI " Thread %s   net=%s  ch=%u  pan=0x%04x  rloc=0x%04x   "
                                       "SRP:%s(%u)   nodes:%u",
                        role, g_snap.netname[0] ? g_snap.netname : "-", (unsigned)g_snap.channel,
                        (unsigned)g_snap.panid, (unsigned)g_snap.rloc16,
                        g_snap.srp_enabled ? "on" : "off", (unsigned)g_snap.srp_hosts,
                        (unsigned)g_snap.node_count);
  lv_label_set_text_fmt(g_ui.lbl_heap, "heap %ukB (min %ukB)  psram %ukB",
                        (unsigned)(g_snap.free_internal / 1024),
                        (unsigned)(g_snap.free_internal_min / 1024),
                        (unsigned)(g_snap.free_psram / 1024));
  lv_label_set_text(g_ui.lbl_status, g_snap.status);

  // WiFi + BLE 1 項目(どちらも基板上の C6 = esp_hosted 経由)。
  char wifi[96];
  uint32_t col = COL_DIM;
  switch (g_snap.wifi_state) {
  case 1:
    snprintf(wifi, sizeof(wifi), "WiFi connecting (%s)",
             g_snap.wifi_ssid[0] ? g_snap.wifi_ssid : "-");
    col = COL_WARN;
    break;
  case 2:
    snprintf(wifi, sizeof(wifi), "WiFi %s  if=%u  %s",
             g_snap.wifi_ssid[0] ? g_snap.wifi_ssid : "-", (unsigned)g_snap.wifi_netif,
             g_snap.wifi_ll[0] ? "LL ok" : "no LL");
    col = COL_ON;
    break;
  case 3:
    snprintf(wifi, sizeof(wifi), "WiFi failed (C6 / SDIO)");
    col = COL_WARN;
    break;
  default:
    snprintf(wifi, sizeof(wifi), "WiFi off");
    break;
  }
  static const char *BLE_HOST_NAME[] = {"off", "starting", "ready", "failed"};
  const char *ble = g_snap.ble_host < 4 ? BLE_HOST_NAME[g_snap.ble_host] : "?";
  lv_label_set_text_fmt(g_ui.lbl_wifi, "%s   BLE %s", wifi, ble);
  lv_obj_set_style_text_color(g_ui.lbl_wifi, lv_color_hex(col), 0);
}

bool node_set_changed() {
  if (g_ui.row_count != g_snap.node_count) {
    return true;
  }
  for (size_t i = 0; i < g_ui.row_count; ++i) {
    if (g_ui.row_ids[i] != g_snap.nodes[i].node_id) {
      return true;
    }
  }
  return false;
}

void refresh_devices() {
  if (node_set_changed()) {
    for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
      if (g_ui.rows[i].root != nullptr) {
        lv_obj_delete(g_ui.rows[i].root);
        g_ui.rows[i] = NodeRowWidgets{};
      }
    }
    g_ui.row_count = g_snap.node_count;
    for (size_t i = 0; i < g_ui.row_count; ++i) {
      g_ui.row_ids[i] = g_snap.nodes[i].node_id;
      build_node_row(i);
    }
  }
  lv_obj_set_flag(g_ui.lbl_empty, LV_OBJ_FLAG_HIDDEN, g_ui.row_count != 0);

  for (size_t i = 0; i < g_ui.row_count; ++i) {
    const sm_ui_node_t &n = g_snap.nodes[i];
    NodeRowWidgets &w = g_ui.rows[i];
    const bool sensor = (n.kind == SM_UI_KIND_SENSOR);
    lv_label_set_text_fmt(w.lbl_id, "Node 0x%016llx%s", (unsigned long long)n.node_id,
                          sensor ? "   [air quality]" : "");
    lv_label_set_text(w.lbl_addr, n.addr);
    lv_obj_t *bl = (lv_obj_t *)lv_obj_get_user_data(w.badge);
    if (sensor) {
      // AirQuality の 6 段階(未取得 / Unknown はグレーの "?")。
      const uint8_t aq = (n.has_aq && n.aq <= 6) ? n.aq : 0;
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(AQ_STYLE[aq].color), 0);
      lv_label_set_text(bl, AQ_STYLE[aq].name);
    } else if (n.onoff > 0) {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_ON), 0);
      lv_label_set_text(bl, "ON");
    } else if (n.onoff == 0) {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_OFF), 0);
      lv_label_set_text(bl, "OFF");
    } else {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_WARN), 0);
      lv_label_set_text(bl, "?");
    }

    // 2 行目のサマリ(センサ行のみ)。未取得の項目は "-"。
    if (sensor) {
      // %f は使わない(lv_snprintf は既定で float 非対応。整数演算で桁を作る)。
      // 値域はクランプする(異常値で桁溢れさせない = -Wformat-truncation 対策も兼ねる)。
      auto clamp = [](int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); };
      char co2[24], pm25[24], temp[24], hum[24];
      if (n.has_co2) {
        snprintf(co2, sizeof(co2), "%dppm", clamp((int)(n.co2 + 0.5f), 0, 99999));
      } else {
        snprintf(co2, sizeof(co2), "-");
      }
      if (n.has_pm25) {
        int t = clamp((int)(n.pm25 * 10.0f + 0.5f), 0, 99999);
        snprintf(pm25, sizeof(pm25), "%d.%dug/m3", t / 10, t % 10);
      } else {
        snprintf(pm25, sizeof(pm25), "-");
      }
      if (n.has_temp) {
        int t = clamp((int)(n.temp_c100 / 10), -9999, 9999); // 0.1 ℃ 単位
        snprintf(temp, sizeof(temp), "%s%d.%dC", (t < 0 ? "-" : ""), abs(t) / 10, abs(t) % 10);
      } else {
        snprintf(temp, sizeof(temp), "-");
      }
      if (n.has_hum) {
        snprintf(hum, sizeof(hum), "%d%%", clamp((int)(n.hum_p100 / 100), 0, 100));
      } else {
        snprintf(hum, sizeof(hum), "-");
      }
      lv_label_set_text_fmt(w.lbl_sensor, "CO2 %s   PM2.5 %s   %s   %s", co2, pm25, temp, hum);
      lv_obj_remove_flag(w.lbl_sensor, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(w.lbl_sensor, LV_OBJ_FLAG_HIDDEN);
    }
    // Toggle は照明行だけ(センサに OnOff は無い)。隠した要素は flex 配置から外れる。
    lv_obj_set_flag(w.btn_toggle, LV_OBJ_FLAG_HIDDEN, sensor);

    lv_label_set_text(w.lbl_sub, n.subscribed ? "* sub" : "");
    // T9(§17.4): 窓が開いているノードは note を残り秒つきの表示で上書きする。
    if (!n.busy && g_snap.window.status == SM_UI_WINDOW_OPEN &&
        g_snap.window.node_id == n.node_id) {
      const long long left = (g_snap.window.expires_ms > g_snap.now_ms)
                                 ? (long long)((g_snap.window.expires_ms - g_snap.now_ms) / 1000ull)
                                 : 0;
      lv_label_set_text_fmt(w.lbl_note, "window open (%lld s)", left);
    } else {
      lv_label_set_text(w.lbl_note, n.busy ? "working ..." : n.note);
    }
  }
}

// --- Dashboard タブ(T6、§14.1)---

// 照明の小タイル(user_data = g_ui.light_ids のインデックス。Devices タブの
// row_ids とは別配列にして、片方の作り直しがもう片方に波及しないようにする)。
void on_dash_toggle(lv_event_t *e) {
  size_t i = (size_t)(uintptr_t)lv_event_get_user_data(e);
  post(SM_UI_OP_TOGGLE, i < g_ui.light_count ? g_ui.light_ids[i] : 0);
}

void build_tile(lv_obj_t *parent, SensorTile &t, const char *name, const lv_font_t *value_font) {
  t.root = lv_obj_create(parent);
  style_panel(t.root, COL_TILE_NONE);
  lv_obj_set_size(t.root, TILE_W, TILE_H);
  lv_obj_remove_flag(t.root, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(t.root, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(t.root, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(t.root, 4, 0);
  make_label(t.root, &lv_font_montserrat_20, 0xe6edf3, name);
  t.lbl_value = make_label(t.root, value_font, 0xffffff, "-");
  t.lbl_unit = make_label(t.root, &lv_font_montserrat_20, 0xd6dde6, "");
}

void build_sensor_card(size_t i) {
  SensorCard &c = g_ui.cards[i];
  c.root = lv_obj_create(g_ui.dash);
  style_panel(c.root, COL_PANEL);
  lv_obj_set_size(c.root, LV_PCT(100), CARD_H);
  lv_obj_remove_flag(c.root, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(c.root, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(c.root, 8, 0);

  lv_obj_t *head = lv_obj_create(c.root);
  lv_obj_remove_style_all(head);
  lv_obj_set_size(head, LV_PCT(100), CARD_HEAD_H);
  lv_obj_set_flex_flow(head, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(head, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  c.lbl_title = make_label(head, &lv_font_montserrat_24, COL_TEXT, "-");
  c.lbl_age = make_label(head, &lv_font_montserrat_20, COL_DIM, "-");

  lv_obj_t *row = lv_obj_create(c.root);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, LV_PCT(100), TILE_H);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(row, TILE_GAP, 0);
  // AirQuality は名称("ExtPoor" 等)なので 32px、数値の 4 枚は 48px。
  build_tile(row, c.tiles[SM_UI_SLOT_AQ], "Air Quality", &lv_font_montserrat_32);
  build_tile(row, c.tiles[SM_UI_SLOT_CO2], "CO2", &lv_font_montserrat_48);
  build_tile(row, c.tiles[SM_UI_SLOT_PM25], "PM2.5", &lv_font_montserrat_48);
  build_tile(row, c.tiles[SM_UI_SLOT_TEMP], "Temperature", &lv_font_montserrat_48);
  build_tile(row, c.tiles[SM_UI_SLOT_HUM], "Humidity", &lv_font_montserrat_48);
}

void build_light_tile(size_t i) {
  LightTile &t = g_ui.lights[i];
  t.root = lv_obj_create(g_ui.lights_wrap);
  style_panel(t.root, COL_ROW);
  lv_obj_set_size(t.root, LIGHT_TILE_W, LIGHT_TILE_H);
  lv_obj_remove_flag(t.root, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(t.root, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(t.root, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(t.root, 12, 0);

  t.lbl_id = make_label(t.root, &lv_font_montserrat_20, COL_TEXT, "-");
  lv_obj_set_width(t.lbl_id, 120);

  t.badge = lv_obj_create(t.root);
  style_panel(t.badge, COL_OFF);
  lv_obj_set_size(t.badge, 80, 52);
  lv_obj_remove_flag(t.badge, LV_OBJ_FLAG_SCROLLABLE);
  t.lbl_badge = make_label(t.badge, &lv_font_montserrat_20, 0xffffff, "?");
  lv_obj_center(t.lbl_badge);

  make_button(t.root, "Toggle", 140, COL_ACCENT, on_dash_toggle, (void *)(uintptr_t)i);
}

// 値を 1 タイルに流す(色 + 文字列。未取得は "-" + グレー)。
void set_tile(SensorTile &t, const char *value, const char *unit, uint32_t color) {
  lv_obj_set_style_bg_color(t.root, lv_color_hex(color), 0);
  lv_label_set_text(t.lbl_value, value);
  lv_label_set_text(t.lbl_unit, unit);
}

int clamp_i(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

// スナップショットのノード集合(NodeId + 種別)が変わったか。
bool dash_set_changed() {
  size_t sensors = 0, lights = 0;
  for (size_t i = 0; i < g_snap.node_count; ++i) {
    const sm_ui_node_t &n = g_snap.nodes[i];
    if (n.kind == SM_UI_KIND_SENSOR) {
      if (sensors >= g_ui.card_count || g_ui.card_ids[sensors] != n.node_id) {
        return true;
      }
      ++sensors;
    } else {
      // UNKNOWN も照明扱いで下段に出す(種別が確定したらここで作り直しになる)。
      if (lights >= g_ui.light_count || g_ui.light_ids[lights] != n.node_id) {
        return true;
      }
      ++lights;
    }
  }
  return sensors != g_ui.card_count || lights != g_ui.light_count;
}

void rebuild_dashboard() {
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    if (g_ui.cards[i].root != nullptr) {
      lv_obj_delete(g_ui.cards[i].root);
      g_ui.cards[i] = SensorCard{};
    }
    if (g_ui.lights[i].root != nullptr) {
      lv_obj_delete(g_ui.lights[i].root);
      g_ui.lights[i] = LightTile{};
    }
  }
  g_ui.card_count = 0;
  g_ui.light_count = 0;
  for (size_t i = 0; i < g_snap.node_count; ++i) {
    const sm_ui_node_t &n = g_snap.nodes[i];
    if (n.kind == SM_UI_KIND_SENSOR) {
      g_ui.card_ids[g_ui.card_count] = n.node_id;
      build_sensor_card(g_ui.card_count);
      ++g_ui.card_count;
    } else {
      g_ui.light_ids[g_ui.light_count] = n.node_id;
      build_light_tile(g_ui.light_count);
      ++g_ui.light_count;
    }
  }
  // 照明パネルは常に最後(カードは dash に後から足されるので押し出される)。
  lv_obj_move_to_index(g_ui.lights_panel, -1);
}

void refresh_dashboard() {
  if (dash_set_changed()) {
    rebuild_dashboard();
  }
  lv_obj_set_flag(g_ui.lbl_dash_empty, LV_OBJ_FLAG_HIDDEN, g_ui.card_count != 0);
  lv_obj_set_flag(g_ui.lights_panel, LV_OBJ_FLAG_HIDDEN, g_ui.light_count == 0);

  size_t ci = 0, li = 0;
  for (size_t i = 0; i < g_snap.node_count; ++i) {
    const sm_ui_node_t &n = g_snap.nodes[i];
    if (n.kind == SM_UI_KIND_SENSOR) {
      if (ci >= g_ui.card_count) {
        continue;
      }
      SensorCard &c = g_ui.cards[ci++];
      lv_label_set_text_fmt(c.lbl_title, "AirQ 0x..%04x",
                            (unsigned)(uint16_t)(n.node_id & 0xFFFFull));
      if (n.last_update_ms == 0 || g_snap.now_ms < n.last_update_ms) {
        lv_label_set_text(c.lbl_age, n.busy ? "reading ..." : "never updated");
      } else {
        uint32_t age = (uint32_t)((g_snap.now_ms - n.last_update_ms) / 1000ull);
        lv_label_set_text_fmt(c.lbl_age, "updated %us ago", (unsigned)(age > 99999 ? 99999 : age));
      }

      // AirQuality(既存 AQ_STYLE を流用。未取得 / Unknown はグレーの "-")。
      const uint8_t aq = (n.has_aq && n.aq <= 6) ? n.aq : 0;
      set_tile(c.tiles[SM_UI_SLOT_AQ], aq != 0 ? AQ_STYLE[aq].name : "-", "",
               aq != 0 ? AQ_STYLE[aq].color : COL_TILE_NONE);

      // 数値 4 枚。**%f は使わない**(整数演算で桁を作る。§12.5 と同じ流儀)。
      char buf[16];
      if (n.has_co2) {
        snprintf(buf, sizeof(buf), "%d", clamp_i((int)(n.co2 + 0.5f), 0, 99999));
        set_tile(c.tiles[SM_UI_SLOT_CO2], buf, "ppm", co2_color(n.co2));
      } else {
        set_tile(c.tiles[SM_UI_SLOT_CO2], "-", "ppm", COL_TILE_NONE);
      }
      if (n.has_pm25) {
        int t = clamp_i((int)(n.pm25 * 10.0f + 0.5f), 0, 99999);
        snprintf(buf, sizeof(buf), "%d.%d", t / 10, t % 10);
        set_tile(c.tiles[SM_UI_SLOT_PM25], buf, "ug/m3", pm25_color(n.pm25));
      } else {
        set_tile(c.tiles[SM_UI_SLOT_PM25], "-", "ug/m3", COL_TILE_NONE);
      }
      if (n.has_temp) {
        int t = clamp_i((int)(n.temp_c100 / 10), -9999, 9999); // 0.1 ℃ 単位
        int a = t < 0 ? -t : t;
        snprintf(buf, sizeof(buf), "%s%d.%d", t < 0 ? "-" : "", a / 10, a % 10);
        set_tile(c.tiles[SM_UI_SLOT_TEMP], buf, "C", COL_TILE_NEUTRAL);
      } else {
        set_tile(c.tiles[SM_UI_SLOT_TEMP], "-", "C", COL_TILE_NONE);
      }
      if (n.has_hum) {
        snprintf(buf, sizeof(buf), "%d", clamp_i((int)(n.hum_p100 / 100), 0, 100));
        set_tile(c.tiles[SM_UI_SLOT_HUM], buf, "%", COL_TILE_NEUTRAL);
      } else {
        set_tile(c.tiles[SM_UI_SLOT_HUM], "-", "%", COL_TILE_NONE);
      }
    } else {
      if (li >= g_ui.light_count) {
        continue;
      }
      LightTile &t = g_ui.lights[li++];
      lv_label_set_text_fmt(t.lbl_id, "0x..%04x", (unsigned)(uint16_t)(n.node_id & 0xFFFFull));
      if (n.onoff > 0) {
        lv_obj_set_style_bg_color(t.badge, lv_color_hex(COL_ON), 0);
        lv_label_set_text(t.lbl_badge, "ON");
      } else if (n.onoff == 0) {
        lv_obj_set_style_bg_color(t.badge, lv_color_hex(COL_OFF), 0);
        lv_label_set_text(t.lbl_badge, "OFF");
      } else {
        lv_obj_set_style_bg_color(t.badge, lv_color_hex(COL_WARN), 0);
        lv_label_set_text(t.lbl_badge, "?");
      }
    }
  }
}

void refresh_network_tab() {
  const char *role = (g_snap.role >= 0 && g_snap.role <= 4) ? ROLE_NAME[g_snap.role] : "?";
  lv_label_set_text_fmt(g_ui.lbl_net,
                        "Role        %s\n"
                        "Network     %s\n"
                        "Channel     %u\n"
                        "PAN ID      0x%04x\n"
                        "RLOC16      0x%04x\n"
                        "SRP server  %s (%u host(s) registered)\n"
                        "Controller  %s",
                        role, g_snap.netname[0] ? g_snap.netname : "-", (unsigned)g_snap.channel,
                        (unsigned)g_snap.panid, (unsigned)g_snap.rloc16,
                        g_snap.srp_enabled ? "enabled" : "disabled", (unsigned)g_snap.srp_hosts,
                        g_snap.ctrl_ready ? "ready" : "starting ...");
  if (strcmp(g_ui.qr_data, g_snap.dataset_hex) != 0) {
    snprintf(g_ui.qr_data, sizeof(g_ui.qr_data), "%s", g_snap.dataset_hex);
    lv_label_set_text(g_ui.lbl_dataset,
                      g_ui.qr_data[0] ? g_ui.qr_data : "(no active dataset yet)");
#if LV_USE_QRCODE
    if (g_ui.qr != nullptr && g_ui.qr_data[0] != 0) {
      lv_qrcode_update(g_ui.qr, g_ui.qr_data, (uint32_t)strlen(g_ui.qr_data));
    }
#endif
  }
}

void refresh_pair_dialog() {
  if (!g_ui.pair_open || !g_ui.pair_started || g_ui.lbl_pair == nullptr) {
    return;
  }
  const char *phase =
      g_snap.pair_phase < (sizeof(PHASE_NAME) / sizeof(PHASE_NAME[0])) ? PHASE_NAME[g_snap.pair_phase] : "?";
  // BLE 経路は「どこまで進んだか」がフェーズより先に動くので stage も出す。
  static const char *BLE_STAGE_NAME[] = {"idle",     "scanning", "connected", "subscribed",
                                         "BTP+PASE", "handoff",  "CASE",      "done",
                                         "failed"};
  const char *stage = g_snap.ble_stage < (sizeof(BLE_STAGE_NAME) / sizeof(BLE_STAGE_NAME[0]))
                          ? BLE_STAGE_NAME[g_snap.ble_stage]
                          : "?";
  switch (g_snap.pair_state) {
  case 1:
    if (g_ui.pair_ble) {
      lv_label_set_text_fmt(g_ui.lbl_pair, "BLE: %s (%s)", stage, phase);
    } else {
      lv_label_set_text_fmt(g_ui.lbl_pair, "commissioning ... (%s)", phase);
    }
    break;
  case 2:
    lv_label_set_text(g_ui.lbl_pair, "#27ae60 PAIR COMPLETE #");
    break;
  case 3:
    if (g_ui.pair_ble) {
      lv_label_set_text_fmt(g_ui.lbl_pair, "#e67e22 failed at %s / %s #", stage, phase);
    } else {
      lv_label_set_text_fmt(g_ui.lbl_pair, "#e67e22 failed at %s #", phase);
    }
    break;
  default:
    break;
  }
}

// T9(§17.4): Share ダイアログの反映(500ms タイマ)。表示はスナップショットの
// `window` 欄だけを見る。残り秒は snapshot の now_ms と expires_ms の差。
void refresh_share_dialog() {
  if (g_ui.share_modal == nullptr || g_ui.lbl_share_state == nullptr) {
    return;
  }
  const sm_ui_window_t &w = g_snap.window;
  // 別のノードの窓を開き直した(= 他行の Share を押した)場合は自分の表示を止める。
  if (w.node_id != g_ui.share_node) {
    lv_label_set_text(g_ui.lbl_share_state, "superseded by another node");
    return;
  }
  char code[20];
  format_manual_code(w.manual_code, code, sizeof(code));
  lv_label_set_text(g_ui.lbl_share_code, code);
  lv_label_set_text_fmt(g_ui.lbl_share_sub, "passcode %lu    discriminator %u",
                        (unsigned long)w.passcode, (unsigned)w.discriminator);

  switch (w.status) {
  case SM_UI_WINDOW_OPENING:
    lv_label_set_text(g_ui.lbl_share_state, "opening window ...");
    lv_obj_set_style_text_color(g_ui.lbl_share_state, lv_color_hex(COL_WARN), 0);
    break;
  case SM_UI_WINDOW_OPEN: {
    const long long left =
        (w.expires_ms > g_snap.now_ms) ? (long long)((w.expires_ms - g_snap.now_ms) / 1000ull) : 0;
    lv_label_set_text_fmt(g_ui.lbl_share_state, "closes in %lld s", left);
    lv_obj_set_style_text_color(g_ui.lbl_share_state, lv_color_hex(COL_ON), 0);
    break;
  }
  case SM_UI_WINDOW_CLOSED:
    lv_label_set_text(g_ui.lbl_share_state, "window closed");
    lv_obj_set_style_text_color(g_ui.lbl_share_state, lv_color_hex(COL_DIM), 0);
    break;
  case SM_UI_WINDOW_FAILED:
    lv_label_set_text_fmt(g_ui.lbl_share_state, "failed (status %u, phase %u)",
                          (unsigned)w.fail_status, (unsigned)w.fail_phase);
    lv_obj_set_style_text_color(g_ui.lbl_share_state, lv_color_hex(COL_WARN), 0);
    break;
  default:
    break;
  }

#if LV_USE_QRCODE
  if (g_ui.share_qr != nullptr && w.qr[0] != 0 && strcmp(g_ui.share_qr_data, w.qr) != 0) {
    snprintf(g_ui.share_qr_data, sizeof(g_ui.share_qr_data), "%s", w.qr);
    lv_qrcode_update(g_ui.share_qr, g_ui.share_qr_data, (uint32_t)strlen(g_ui.share_qr_data));
  }
#endif
}

void tick_cb(lv_timer_t *) {
  sm_app_snapshot_get(&g_snap);
  refresh_status_bar();
  refresh_dashboard();
  refresh_devices();
  refresh_network_tab();
  refresh_pair_dialog();
  refresh_share_dialog();
}

} // namespace

void sm_ui_create() {
  lv_display_t *disp = lv_display_get_default();
  if (disp != nullptr) {
    g_scr_w = lv_display_get_horizontal_resolution(disp);
    g_scr_h = lv_display_get_vertical_resolution(disp);
  }
  lv_obj_t *scr = lv_screen_active();
  lv_obj_set_style_bg_color(scr, lv_color_hex(COL_BG), 0);
  lv_obj_set_style_text_color(scr, lv_color_hex(COL_TEXT), 0);
  lv_obj_remove_flag(scr, LV_OBJ_FLAG_SCROLLABLE);

  // --- 1. ステータスバー ---
  lv_obj_t *bar = lv_obj_create(scr);
  style_panel(bar, COL_PANEL);
  lv_obj_set_style_radius(bar, 0, 0);
  lv_obj_set_size(bar, LV_PCT(100), STATUSBAR_H);
  lv_obj_set_pos(bar, 0, 0);
  lv_obj_remove_flag(bar, LV_OBJ_FLAG_SCROLLABLE);

  g_ui.lbl_thread = make_label(bar, &lv_font_montserrat_20, COL_TEXT, "Thread starting ...");
  lv_obj_align(g_ui.lbl_thread, LV_ALIGN_TOP_LEFT, 0, 0);
  g_ui.lbl_heap = make_label(bar, &lv_font_montserrat_14, COL_DIM, "");
  lv_obj_align(g_ui.lbl_heap, LV_ALIGN_TOP_RIGHT, 0, 4);
  g_ui.lbl_status = make_label(bar, &lv_font_montserrat_16, COL_ACCENT, "booting ...");
  lv_obj_align(g_ui.lbl_status, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_label_set_long_mode(g_ui.lbl_status, LV_LABEL_LONG_DOT);
  lv_obj_set_width(g_ui.lbl_status, g_scr_w - 460);
  g_ui.lbl_wifi = make_label(bar, &lv_font_montserrat_16, COL_DIM, "WiFi off");
  lv_obj_align(g_ui.lbl_wifi, LV_ALIGN_BOTTOM_RIGHT, 0, 0);

  // --- 2. タブ ---
  lv_obj_t *tv = lv_tabview_create(scr);
  lv_tabview_set_tab_bar_size(tv, TABBAR_H);
  lv_obj_set_size(tv, LV_PCT(100), g_scr_h - STATUSBAR_H);
  lv_obj_set_pos(tv, 0, STATUSBAR_H);
  lv_obj_set_style_bg_color(tv, lv_color_hex(COL_BG), 0);
  lv_obj_set_style_text_font(lv_tabview_get_tab_bar(tv), &lv_font_montserrat_24, 0);

  // Dashboard を **先頭**に足す(= 既定表示。T6 §14.1)。Devices / Network は現状維持。
  lv_obj_t *tab_dash = lv_tabview_add_tab(tv, "Dashboard");
  lv_obj_t *tab_dev = lv_tabview_add_tab(tv, "Devices");
  lv_obj_t *tab_net = lv_tabview_add_tab(tv, "Network");
  lv_obj_t *tabs[] = {tab_dash, tab_dev, tab_net};
  for (lv_obj_t *t : tabs) {
    lv_obj_set_style_bg_color(t, lv_color_hex(COL_BG), 0);
    lv_obj_set_style_bg_opa(t, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(t, 12, 0);
  }

  // --- 2a. Dashboard タブ ---
  g_ui.dash = tab_dash;
  lv_obj_set_flex_flow(tab_dash, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(tab_dash, 12, 0);
  lv_obj_set_scroll_dir(tab_dash, LV_DIR_VER); // センサ 3 台以上でスクロール

  g_ui.lbl_dash_empty =
      make_label(tab_dash, &lv_font_montserrat_24, COL_DIM,
                 "No sensor yet - pair one from the Devices tab.\n"
                 "An air-quality node is detected automatically (AirQuality cluster on EP1).");

  g_ui.lights_panel = lv_obj_create(tab_dash);
  style_panel(g_ui.lights_panel, COL_PANEL);
  lv_obj_set_size(g_ui.lights_panel, LV_PCT(100), LIGHT_TILE_H + 34 + 8 + 20);
  lv_obj_remove_flag(g_ui.lights_panel, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(g_ui.lights_panel, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(g_ui.lights_panel, 8, 0);
  make_label(g_ui.lights_panel, &lv_font_montserrat_24, COL_TEXT, "Lights");
  g_ui.lights_wrap = lv_obj_create(g_ui.lights_panel);
  lv_obj_remove_style_all(g_ui.lights_wrap);
  lv_obj_set_size(g_ui.lights_wrap, LV_PCT(100), LIGHT_TILE_H);
  lv_obj_set_flex_flow(g_ui.lights_wrap, LV_FLEX_FLOW_ROW_WRAP);
  lv_obj_set_flex_align(g_ui.lights_wrap, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_column(g_ui.lights_wrap, 12, 0);
  lv_obj_add_flag(g_ui.lights_panel, LV_OBJ_FLAG_HIDDEN);

  // --- 2b. Devices タブ ---
  lv_obj_set_flex_flow(tab_dev, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(tab_dev, 12, 0);

  lv_obj_t *toolbar = lv_obj_create(tab_dev);
  lv_obj_remove_style_all(toolbar);
  lv_obj_set_size(toolbar, LV_PCT(100), BTN_H);
  lv_obj_set_flex_flow(toolbar, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(toolbar, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(toolbar, 16, 0);
  make_button(toolbar, LV_SYMBOL_PLUS " Pair new device", 340, COL_ACCENT, open_pair_dialog,
              nullptr);
  make_button(toolbar, LV_SYMBOL_REFRESH " Redraw list", 260, COL_OFF, on_reload, nullptr);
  make_label(toolbar, &lv_font_montserrat_14, COL_DIM,
             "Commands run on the controller pump task; the UI never calls sm_ctrl_* itself.");

  lv_obj_t *listwrap = lv_obj_create(tab_dev);
  lv_obj_remove_style_all(listwrap);
  lv_obj_set_size(listwrap, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(listwrap, 1);
  g_ui.list = listwrap;
  lv_obj_set_flex_flow(listwrap, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(listwrap, 10, 0);
  lv_obj_set_scroll_dir(listwrap, LV_DIR_VER);

  g_ui.lbl_empty = make_label(listwrap, &lv_font_montserrat_20, COL_DIM,
                              "No commissioned device yet.\n"
                              "Attach a device to this Thread network (see the Network tab for\n"
                              "the active dataset), then use \"Pair new device\".");

  // --- 2c. Network タブ ---
  lv_obj_set_flex_flow(tab_net, LV_FLEX_FLOW_ROW);
  lv_obj_set_style_pad_column(tab_net, 16, 0);

  lv_obj_t *left = lv_obj_create(tab_net);
  style_panel(left, COL_PANEL);
  lv_obj_set_size(left, g_scr_w - 390, LV_PCT(100));
  lv_obj_set_flex_flow(left, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_style_pad_row(left, 10, 0);
  g_ui.lbl_net = make_label(left, &lv_font_montserrat_20, COL_TEXT, "Thread starting ...");
  make_label(left, &lv_font_montserrat_16, COL_ACCENT,
             "Active dataset TLV (preset this on the devices):");
  g_ui.lbl_dataset = make_label(left, &lv_font_montserrat_14, COL_TEXT, "(no active dataset yet)");
  lv_label_set_long_mode(g_ui.lbl_dataset, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(g_ui.lbl_dataset, g_scr_w - 430);

  lv_obj_t *right = lv_obj_create(tab_net);
  style_panel(right, COL_PANEL);
  lv_obj_set_size(right, 330, LV_PCT(100));
  lv_obj_set_flex_flow(right, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(right, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(right, 10, 0);
  make_label(right, &lv_font_montserrat_16, COL_ACCENT, "dataset QR");
#if LV_USE_QRCODE
  g_ui.qr = lv_qrcode_create(right);
  lv_qrcode_set_size(g_ui.qr, 280);
  lv_qrcode_set_dark_color(g_ui.qr, lv_color_hex(0x000000));
  lv_qrcode_set_light_color(g_ui.qr, lv_color_hex(0xffffff));
  lv_obj_set_style_border_width(g_ui.qr, 8, 0);
  lv_obj_set_style_border_color(g_ui.qr, lv_color_hex(0xffffff), 0);
#else
  make_label(right, &lv_font_montserrat_14, COL_DIM, "(LV_USE_QRCODE is disabled)");
#endif
  make_label(right, &lv_font_montserrat_14, COL_DIM, "scan to copy the\nactive dataset TLV");

  // --- 3. 反映タイマ ---
  lv_timer_create(tick_cb, 500, nullptr);
  ESP_LOGI(TAG, "ui created (%dx%d)", (int)lv_obj_get_width(scr), (int)lv_obj_get_height(scr));
}
