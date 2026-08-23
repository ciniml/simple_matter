// LVGL の画面(Tab5 = 1280x720 横向き)。docs/design/p4-thread-controller.md §9.1。
//
// 画面構成(v1):
//   1. ステータスバー   : Thread role / RLOC16 / channel / PAN / SRP / ノード数 / free heap
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

// --- ウィジェット一式 ---
struct NodeRowWidgets {
  lv_obj_t *root = nullptr;
  lv_obj_t *lbl_id = nullptr;
  lv_obj_t *lbl_addr = nullptr;
  lv_obj_t *badge = nullptr;
  lv_obj_t *lbl_note = nullptr;
  lv_obj_t *btn_toggle = nullptr;
};

struct Ui {
  // ステータスバー
  lv_obj_t *lbl_thread = nullptr;
  lv_obj_t *lbl_heap = nullptr;
  lv_obj_t *lbl_status = nullptr;
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
  lv_obj_t *lbl_pair = nullptr;
  lv_obj_t *kb = nullptr;
  bool pair_open = false;
  bool pair_started = false; // Start を押してから結果表示を始める
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

void on_pair_start(lv_event_t *) {
  if (g_ui.ta_ipv6 == nullptr) {
    return;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_PAIR;
  snprintf(op.ipv6, sizeof(op.ipv6), "%s", lv_textarea_get_text(g_ui.ta_ipv6));
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
  lv_label_set_text(g_ui.lbl_pair, "starting on-network PASE ...");
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

  make_label(card, &lv_font_montserrat_24, COL_TEXT,
             "Pair a Thread device (on-network PASE, no BLE)");
  make_label(card, &lv_font_montserrat_14, COL_DIM,
             "The device must already be attached to this Thread network with a\n"
             "commissioning window open. Copy its ML-EID / OMR address from its log.");

  auto add_field = [&](const char *caption, const char *initial, int32_t width) {
    lv_obj_t *row = lv_obj_create(card);
    lv_obj_remove_style_all(row);
    lv_obj_set_size(row, LV_PCT(100), BTN_H);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(row, 12, 0);
    lv_obj_t *cap = make_label(row, &lv_font_montserrat_20, COL_DIM, caption);
    lv_obj_set_width(cap, 180);
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
  char idbuf[24];
  snprintf(idbuf, sizeof(idbuf), "%016llx", (unsigned long long)suggest_node_id());
  g_ui.ta_node = add_field("NodeId (hex)", idbuf, 360);
  char pcbuf[16];
  snprintf(pcbuf, sizeof(pcbuf), "%d", CONFIG_SM_UI_DEFAULT_PASSCODE);
  g_ui.ta_pass = add_field("Passcode", pcbuf, 240);

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
  lv_obj_set_pos(g_ui.kb, 0, 424);
  lv_keyboard_set_textarea(g_ui.kb, g_ui.ta_ipv6);
  lv_keyboard_set_mode(g_ui.kb, LV_KEYBOARD_MODE_TEXT_LOWER);

  g_ui.pair_open = true;
  g_ui.pair_started = false;
}

// --- Devices タブ ---

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

  lv_obj_t *col = lv_obj_create(w.root);
  lv_obj_remove_style_all(col);
  lv_obj_set_size(col, 470, ROW_H - 20);
  lv_obj_set_flex_flow(col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(col, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
  w.lbl_id = make_label(col, &lv_font_montserrat_20, COL_TEXT, "-");
  w.lbl_addr = make_label(col, &lv_font_montserrat_14, COL_DIM, "-");

  w.badge = lv_obj_create(w.root);
  style_panel(w.badge, COL_OFF);
  lv_obj_set_size(w.badge, 96, 56);
  lv_obj_remove_flag(w.badge, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_t *bl = make_label(w.badge, &lv_font_montserrat_20, 0xffffff, "?");
  lv_obj_center(bl);
  lv_obj_set_user_data(w.badge, bl);

  w.lbl_note = make_label(w.root, &lv_font_montserrat_14, COL_DIM, "");
  lv_obj_set_width(w.lbl_note, 150);

  void *ud = (void *)(uintptr_t)idx;
  w.btn_toggle = make_button(w.root, "Toggle", 160, COL_ACCENT, on_toggle, ud);
  make_button(w.root, "Read", 120, COL_OFF, on_read, ud);
  make_button(w.root, LV_SYMBOL_REFRESH " Addr", 150, COL_OFF, on_refresh_addr, ud);
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
    lv_label_set_text_fmt(w.lbl_id, "Node 0x%016llx", (unsigned long long)n.node_id);
    lv_label_set_text(w.lbl_addr, n.addr);
    lv_obj_t *bl = (lv_obj_t *)lv_obj_get_user_data(w.badge);
    if (n.onoff > 0) {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_ON), 0);
      lv_label_set_text(bl, "ON");
    } else if (n.onoff == 0) {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_OFF), 0);
      lv_label_set_text(bl, "OFF");
    } else {
      lv_obj_set_style_bg_color(w.badge, lv_color_hex(COL_WARN), 0);
      lv_label_set_text(bl, "?");
    }
    lv_label_set_text(w.lbl_note, n.busy ? "working ..." : n.note);
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
  switch (g_snap.pair_state) {
  case 1:
    lv_label_set_text_fmt(g_ui.lbl_pair, "commissioning ... (%s)", phase);
    break;
  case 2:
    lv_label_set_text(g_ui.lbl_pair, "#27ae60 PAIR COMPLETE #");
    break;
  case 3:
    lv_label_set_text_fmt(g_ui.lbl_pair, "#e67e22 failed at %s #", phase);
    break;
  default:
    break;
  }
}

void tick_cb(lv_timer_t *) {
  sm_app_snapshot_get(&g_snap);
  refresh_status_bar();
  refresh_devices();
  refresh_network_tab();
  refresh_pair_dialog();
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
  lv_obj_set_width(g_ui.lbl_status, g_scr_w - 40);

  // --- 2. タブ ---
  lv_obj_t *tv = lv_tabview_create(scr);
  lv_tabview_set_tab_bar_size(tv, TABBAR_H);
  lv_obj_set_size(tv, LV_PCT(100), g_scr_h - STATUSBAR_H);
  lv_obj_set_pos(tv, 0, STATUSBAR_H);
  lv_obj_set_style_bg_color(tv, lv_color_hex(COL_BG), 0);
  lv_obj_set_style_text_font(lv_tabview_get_tab_bar(tv), &lv_font_montserrat_24, 0);

  lv_obj_t *tab_dev = lv_tabview_add_tab(tv, "Devices");
  lv_obj_t *tab_net = lv_tabview_add_tab(tv, "Network");
  lv_obj_set_style_bg_color(tab_dev, lv_color_hex(COL_BG), 0);
  lv_obj_set_style_bg_opa(tab_dev, LV_OPA_COVER, 0);
  lv_obj_set_style_bg_color(tab_net, lv_color_hex(COL_BG), 0);
  lv_obj_set_style_bg_opa(tab_net, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(tab_dev, 12, 0);
  lv_obj_set_style_pad_all(tab_net, 12, 0);

  // --- 2a. Devices タブ ---
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

  // --- 2b. Network タブ ---
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
