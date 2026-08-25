// デバッグ用コンソール(T5a、docs/design/p4-thread-controller.md §13.1)。
//
// USB-Serial-JTAG の esp_console REPL に、UI と同じ操作キュー(sm_app_post_op)へ
// 投げるコマンドを載せる。**sm_ctrl_* / lv_* は呼ばない**(単線契約は不変。
// pump から見れば GUI のタップと区別がつかない = 実機で GUI と同一経路の検証になる)。
// 出力は 1 行 1 レコード + OK/ERR 終端(スクリプトから grep できる安定書式)。

#include "console_dbg.hpp"

#include "app_state.hpp"
#include "display_gfx.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_console.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "lwip/sockets.h"
#include "esp_log.h"

namespace {

uint64_t parse_hex(const char *s) { return strtoull(s, nullptr, 16); }

int cmd_nodes(int, char **) {
  // スナップショットは数 KB あるので REPL タスクのスタックに置かない(実機で
  // console_repl の stack protection fault → リブート)。コンソールは単一タスク。
  static sm_ui_snapshot_t snap;
  sm_app_snapshot_get(&snap);
  printf("NODES %u\n", (unsigned)snap.node_count);
  for (size_t i = 0; i < snap.node_count && i < SM_UI_MAX_NODES; ++i) {
    const sm_ui_node_t &n = snap.nodes[i];
    printf("NODE %016llx kind=%u onoff=%d aq=%u addr=%s note=\"%s\"\n",
           (unsigned long long)n.node_id, n.kind, (int)n.onoff, n.aq, n.addr, n.note);
    if (n.kind == 2) {
      printf("SENSOR %016llx co2=%s%.1f pm25=%s%.1f temp_c100=%s%ld hum_p100=%s%ld\n",
             (unsigned long long)n.node_id, n.has_co2 ? "" : "-", n.has_co2 ? n.co2 : 0.0f,
             n.has_pm25 ? "" : "-", n.has_pm25 ? n.pm25 : 0.0f, n.has_temp ? "" : "-",
             n.has_temp ? (long)n.temp_c100 : 0L, n.has_hum ? "" : "-",
             n.has_hum ? (long)n.hum_p100 : 0L);
      // T6: ダッシュボードの鮮度と同じ値(pump の now_ms との差、秒)。
      printf("SENSORAGE %016llx %lld\n", (unsigned long long)n.node_id,
             n.last_update_ms == 0 || snap.now_ms < n.last_update_ms
                 ? -1LL
                 : (long long)((snap.now_ms - n.last_update_ms) / 1000ull));
    }
  }
  printf("OK\n");
  return 0;
}

int cmd_status(int, char **) {
  // スナップショットは数 KB あるので REPL タスクのスタックに置かない(実機で
  // console_repl の stack protection fault → リブート)。コンソールは単一タスク。
  static sm_ui_snapshot_t snap;
  sm_app_snapshot_get(&snap);
  printf("STATUS thread_role=%d wifi_state=%u wifi_ip4=%s wifi_ll=%s wifi_gua_ok=%d ble=%u "
         "pair_state=%u pair_phase=%u ble_stage=%u nodes=%u\n",
         snap.role, snap.wifi_state, snap.wifi_ip4[0] ? snap.wifi_ip4 : "-",
         snap.wifi_ll[0] ? snap.wifi_ll : "-", 0, snap.ble_host, snap.pair_state, snap.pair_phase,
         snap.ble_stage, (unsigned)snap.node_count);
  printf("LAST \"%s\"\n", snap.status);
  printf("OK\n");
  return 0;
}

int cmd_toggle(int argc, char **argv) {
  if (argc < 2) {
    printf("ERR usage: toggle <node_hex>\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_TOGGLE;
  op.node_id = parse_hex(argv[1]);
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_read(int argc, char **argv) {
  if (argc < 2) {
    printf("ERR usage: read <node_hex>\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_READ_ONOFF;
  op.node_id = parse_hex(argv[1]);
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_pairble(int argc, char **argv) {
  // pairble <disc> <node_hex> [wifi|thread] [passcode]
  if (argc < 3) {
    printf("ERR usage: pairble <disc> <node_hex> [wifi|thread] [passcode]\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_PAIR_BLE;
  op.discriminator = (uint16_t)atoi(argv[1]);
  op.node_id = parse_hex(argv[2]);
  op.via = (argc >= 4 && strcmp(argv[3], "thread") == 0) ? SM_UI_VIA_BLE_THREAD : SM_UI_VIA_BLE_WIFI;
  op.passcode = (argc >= 5) ? (uint32_t)strtoul(argv[4], nullptr, 10) : 20202021u;
  if (op.node_id == 0) {
    printf("ERR node id must be non-zero\n");
    return 1;
  }
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_pair(int argc, char **argv) {
  // pair <ipv6> <node_hex> [thread|wifi] [passcode]
  if (argc < 3) {
    printf("ERR usage: pair <ipv6> <node_hex> [thread|wifi] [passcode]\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_PAIR;
  snprintf(op.ipv6, sizeof(op.ipv6), "%s", argv[1]);
  op.node_id = parse_hex(argv[2]);
  op.via = (argc >= 4 && strcmp(argv[3], "wifi") == 0) ? SM_UI_VIA_WIFI : SM_UI_VIA_THREAD;
  op.passcode = (argc >= 5) ? (uint32_t)strtoul(argv[4], nullptr, 10) : 20202021u;
  if (op.node_id == 0) {
    printf("ERR node id must be non-zero\n");
    return 1;
  }
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_refresh(int argc, char **argv) {
  if (argc < 2) {
    printf("ERR usage: refresh <node_hex>\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_REFRESH_ADDR;
  op.node_id = parse_hex(argv[1]);
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_setaddr(int argc, char **argv) {
  // setaddr <node_hex> <ip literal (v4/v6)> [wifi|thread]
  if (argc < 3) {
    printf("ERR usage: setaddr <node_hex> <ip> [wifi|thread]\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_SET_ADDR;
  op.node_id = parse_hex(argv[1]);
  snprintf(op.ipv6, sizeof(op.ipv6), "%s", argv[2]);
  op.via = (argc >= 4 && strcmp(argv[3], "thread") == 0) ? SM_UI_VIA_THREAD : SM_UI_VIA_WIFI;
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

// RX 切り分け実験: 指定ポートに bind(+224.0.0.251 join)して数秒間の受信を数える。
// 使い方: udptest <port> <secs>。PC から unicast / multicast を打って比較する。
int cmd_udptest(int argc, char **argv) {
  if (argc < 3) {
    printf("ERR usage: udptest <port> <secs>\n");
    return 1;
  }
  uint16_t port = (uint16_t)atoi(argv[1]);
  int secs = atoi(argv[2]);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    printf("ERR socket\n");
    return 1;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    printf("ERR bind errno=%d\n", errno);
    close(fd);
    return 1;
  }
  struct ip_mreq m = {};
  m.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
  m.imr_interface.s_addr = htonl(INADDR_ANY);
  int jr = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
  printf("LISTEN port=%u join_rc=%d for %ds\n", port, jr, secs);
  uint64_t until = (uint64_t)secs * 1000;
  uint32_t got = 0;
  for (uint64_t t = 0; t < until; t += 200) {
    struct timeval tv = {0, 200000};
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    if (select(fd + 1, &rf, nullptr, nullptr, &tv) > 0) {
      uint8_t buf[1500];
      struct sockaddr_in src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
      if (n > 0) {
        char ip[20];
        inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
        printf("RX %d B from %s:%u\n", n, ip, ntohs(src.sin_port));
        got++;
      }
    }
  }
  close(fd);
  printf("DONE rx=%u\nOK\n", (unsigned)got);
  return 0;
}

// ===== T5b: GUI リモート操作(§13.1)=========================================
//
// tap/swipe は display_gfx の合成ポインタ注入(indev read_cb 内の状態機械)へ
// 投げるだけ。ui-dump は sm_display_lock() を取ってから lv_* を触る
// (= LVGL タスクと排他。§13.2 の契約どおりコンソールから素の lv_* は呼ばない)。

// 注入の完了を待つ(最大 timeout_ms)。完了後は LVGL がクリックイベントを
// 処理し切るまで少し置く(直後の ui-dump が新しい画面を映すように)。
void wait_inject_done(uint32_t timeout_ms) {
  for (uint32_t t = 0; t < timeout_ms && sm_display_inject_busy(); t += 10) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  vTaskDelay(pdMS_TO_TICKS(150));
}

int cmd_tap(int argc, char **argv) {
  if (argc < 3) {
    printf("ERR usage: tap <x> <y>\n");
    return 1;
  }
  const int x = atoi(argv[1]);
  const int y = atoi(argv[2]);
  if (!sm_display_inject_pointer(x, y, x, y, 80)) {
    printf("ERR inject busy or lvgl not started\n");
    return 1;
  }
  wait_inject_done(1500);
  printf("TAP %d %d\n", x, y);
  printf("OK\n");
  return 0;
}

int cmd_swipe(int argc, char **argv) {
  if (argc < 5) {
    printf("ERR usage: swipe <x1> <y1> <x2> <y2> [ms]\n");
    return 1;
  }
  const int x1 = atoi(argv[1]);
  const int y1 = atoi(argv[2]);
  const int x2 = atoi(argv[3]);
  const int y2 = atoi(argv[4]);
  uint32_t ms = (argc >= 6) ? (uint32_t)strtoul(argv[5], nullptr, 10) : 300u;
  if (ms > 5000) {
    ms = 5000;
  }
  if (!sm_display_inject_pointer(x1, y1, x2, y2, ms)) {
    printf("ERR inject busy or lvgl not started\n");
    return 1;
  }
  wait_inject_done(ms + 1500);
  printf("SWIPE %d %d %d %d %u\n", x1, y1, x2, y2, (unsigned)ms);
  printf("OK\n");
  return 0;
}

// クラス名。lv_obj_class_t の中身は private ヘッダなので、公開 API の
// lv_obj_check_type() で既知クラスに当てる(派生 → 基底の順に見る)。
const char *ui_class_name(lv_obj_t *o) {
#if LV_USE_QRCODE
  if (lv_obj_check_type(o, &lv_qrcode_class)) {
    return "qrcode";
  }
#endif
#if LV_USE_KEYBOARD
  if (lv_obj_check_type(o, &lv_keyboard_class)) {
    return "keyboard";
  }
#endif
#if LV_USE_DROPDOWN
  if (lv_obj_check_type(o, &lv_dropdownlist_class)) {
    return "dropdownlist";
  }
  if (lv_obj_check_type(o, &lv_dropdown_class)) {
    return "dropdown";
  }
#endif
#if LV_USE_TEXTAREA
  if (lv_obj_check_type(o, &lv_textarea_class)) {
    return "textarea";
  }
#endif
#if LV_USE_TABVIEW
  if (lv_obj_check_type(o, &lv_tabview_class)) {
    return "tabview";
  }
#endif
#if LV_USE_BUTTONMATRIX
  if (lv_obj_check_type(o, &lv_buttonmatrix_class)) {
    return "buttonmatrix";
  }
#endif
#if LV_USE_BUTTON
  if (lv_obj_check_type(o, &lv_button_class)) {
    return "button";
  }
#endif
#if LV_USE_LABEL
  if (lv_obj_check_type(o, &lv_label_class)) {
    return "label";
  }
#endif
#if LV_USE_IMAGE
  if (lv_obj_check_type(o, &lv_image_class)) {
    return "image";
  }
#endif
  return "obj";
}

// 1 行 1 レコードを壊さないよう、改行と '"' を潰して詰める。
void sanitize_text(const char *src, char *dst, size_t dst_len) {
  size_t j = 0;
  if (src == nullptr) {
    dst[0] = '\0';
    return;
  }
  for (size_t i = 0; src[i] != '\0' && j + 1 < dst_len; ++i) {
    unsigned char c = (unsigned char)src[i];
    if (c == '"') {
      c = '\'';
    } else if (c < 0x20 || c == 0x7f) {
      c = ' ';
    }
    dst[j++] = (char)c;
  }
  dst[j] = '\0';
}

// ウィジェットの表示文字列(あれば)を取り出す。
void ui_text_of(lv_obj_t *o, char *out, size_t out_len) {
  out[0] = '\0';
#if LV_USE_LABEL
  if (lv_obj_check_type(o, &lv_label_class)) {
    sanitize_text(lv_label_get_text(o), out, out_len);
    return;
  }
#endif
#if LV_USE_TEXTAREA
  if (lv_obj_check_type(o, &lv_textarea_class)) {
    sanitize_text(lv_textarea_get_text(o), out, out_len);
    return;
  }
#endif
#if LV_USE_DROPDOWN
  if (lv_obj_check_type(o, &lv_dropdown_class)) {
    char sel[64];
    sel[0] = '\0';
    lv_dropdown_get_selected_str(o, sel, sizeof(sel));
    sanitize_text(sel, out, out_len);
    return;
  }
#endif
}

constexpr int kUiMaxDepth = 8;
constexpr uint32_t kUiMaxChildren = 64;

void ui_dump_obj(lv_obj_t *o, int depth) {
  // REPL スタックは 16KB。再帰なので 1 段あたりの自動変数は小さく保つ
  // (文字列バッファはコンソール単一タスク前提の static。§13.5 の罠)。
  static char text[112];
  lv_area_t a;
  lv_obj_get_coords(o, &a);
  ui_text_of(o, text, sizeof(text));
  printf("UI %d %s x=%d y=%d w=%d h=%d hidden=%d text=\"%s\"\n", depth, ui_class_name(o),
         (int)a.x1, (int)a.y1, (int)lv_area_get_width(&a), (int)lv_area_get_height(&a),
         lv_obj_has_flag(o, LV_OBJ_FLAG_HIDDEN) ? 1 : 0, text);
  if (depth >= kUiMaxDepth) {
    return;
  }
  uint32_t n = lv_obj_get_child_count(o);
  if (n > kUiMaxChildren) {
    n = kUiMaxChildren;
  }
  for (uint32_t i = 0; i < n; ++i) {
    lv_obj_t *c = lv_obj_get_child(o, (int32_t)i);
    if (c != nullptr) {
      ui_dump_obj(c, depth + 1);
    }
  }
}

int cmd_ui_dump(int, char **) {
  if (!sm_display_lock(5000)) {
    printf("ERR lvgl lock timeout\n");
    return 1;
  }
  lv_obj_t *scr = lv_screen_active();
  if (scr != nullptr) {
    ui_dump_obj(scr, 0);
  }
  sm_display_unlock();
  if (scr == nullptr) {
    printf("ERR no active screen\n");
    return 1;
  }
  printf("OK\n");
  return 0;
}

// ===== T5c: スクリーンショット(§13.1)=======================================

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// n(<=57)バイトを base64 の 1 行(<=76 桁)にして印字する。
void b64_emit_line(const uint8_t *src, size_t n, uint32_t line_no) {
  // 各行に `B<連番 hex4>:` 接頭辞。転送中に混ざるログ行が**行の途中に癒着する**/
  // 行が丸ごと落ちることがある(実機で観測)ので、PC 側は行内から正規表現で抽出し、
  // 連番で欠落を検出する。
  char line[92];
  int pre = snprintf(line, sizeof(line), "B%04x:", (unsigned)(line_no & 0xffff));
  size_t j = (size_t)pre;
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    const uint32_t v = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1] << 8) | src[i + 2];
    line[j++] = kB64[(v >> 18) & 0x3f];
    line[j++] = kB64[(v >> 12) & 0x3f];
    line[j++] = kB64[(v >> 6) & 0x3f];
    line[j++] = kB64[v & 0x3f];
  }
  const size_t rem = n - i;
  if (rem == 1) {
    const uint32_t v = (uint32_t)src[i] << 16;
    line[j++] = kB64[(v >> 18) & 0x3f];
    line[j++] = kB64[(v >> 12) & 0x3f];
    line[j++] = '=';
    line[j++] = '=';
  } else if (rem == 2) {
    const uint32_t v = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1] << 8);
    line[j++] = kB64[(v >> 18) & 0x3f];
    line[j++] = kB64[(v >> 12) & 0x3f];
    line[j++] = kB64[(v >> 6) & 0x3f];
    line[j++] = '=';
  }
  line[j++] = '\n';
  // printf/puts(VFS 経由)は USB-Serial-JTAG の TX バッファが満ちると**捨てる**
  // (実機で 267 行 ≈ 22KB の連続欠落を観測)。ドライバへ直接書き、空き待ちでブロックする。
  size_t off = 0;
  while (off < j) {
    int w = usb_serial_jtag_write_bytes(line + off, j - off, pdMS_TO_TICKS(2000));
    if (w <= 0) {
      break; // ホストが 2 秒読まない = 諦める(PC 側は連番の欠落として検出する)
    }
    off += (size_t)w;
  }
}

int cmd_screenshot(int argc, char **argv) {
  int div = (argc >= 2) ? atoi(argv[1]) : 1;
  if (div != 1 && div != 2) {
    printf("ERR usage: screenshot [1|2]\n");
    return 1;
  }
  lv_display_t *disp = lv_display_get_default();
  if (disp == nullptr) {
    printf("ERR lvgl not started\n");
    return 1;
  }
  const int32_t W = lv_display_get_horizontal_resolution(disp);
  const int32_t H = lv_display_get_vertical_resolution(disp);
  if (W <= 0 || H <= 0) {
    printf("ERR bad resolution\n");
    return 1;
  }

  // 1280x720x2B ≒ 1.8MB。内蔵 RAM には置けないので PSRAM から取る。
  const size_t align = 64;
  const size_t raw = (size_t)W * (size_t)H * 2u + align;
  uint8_t *mem = (uint8_t *)heap_caps_malloc(raw, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (mem == nullptr) {
    printf("ERR psram alloc %u failed\n", (unsigned)raw);
    return 1;
  }
  uint8_t *buf = (uint8_t *)(((uintptr_t)mem + (align - 1)) & ~(uintptr_t)(align - 1));
  const size_t buf_size = raw - (size_t)(buf - mem);

  // 撮影は lock 内(LVGL タスクと排他)。転送は lock 外で行うので UI は固まらない。
  lv_draw_buf_t db;
  bool ok = false;
  if (sm_display_lock(10000)) {
    if (lv_draw_buf_init(&db, 1, 1, LV_COLOR_FORMAT_RGB565, (uint32_t)buf_size, buf,
                         (uint32_t)buf_size) == LV_RESULT_OK) {
      lv_obj_t *scr = lv_screen_active();
      ok = (scr != nullptr) &&
           (lv_snapshot_take_to_draw_buf(scr, LV_COLOR_FORMAT_RGB565, &db) == LV_RESULT_OK);
    }
    sm_display_unlock();
  } else {
    printf("ERR lvgl lock timeout\n");
    heap_caps_free(mem);
    return 1;
  }
  if (!ok) {
    printf("ERR snapshot failed\n");
    heap_caps_free(mem);
    return 1;
  }

  const int32_t sw = (int32_t)db.header.w;
  const int32_t sh = (int32_t)db.header.h;
  const size_t stride = db.header.stride;
  const int32_t ow = sw / div;
  const int32_t oh = sh / div;
  const size_t total = (size_t)ow * (size_t)oh * 2u;
  const unsigned b64len = (unsigned)(4u * ((total + 2u) / 3u));

  printf("SCREENSHOT %d %d RGB565 %u\n", (int)ow, (int)oh, b64len);
  uint8_t acc[57];
  size_t accn = 0;
  uint32_t line_no = 0;
  for (int32_t y = 0; y < oh; ++y) {
    const uint8_t *row = db.data + (size_t)(y * div) * stride;
    for (int32_t x = 0; x < ow; ++x) {
      const uint8_t *px = row + (size_t)(x * div) * 2u;
      acc[accn++] = px[0];
      if (accn == sizeof(acc)) {
        b64_emit_line(acc, accn, line_no++);
        accn = 0;
      }
      acc[accn++] = px[1];
      if (accn == sizeof(acc)) {
        b64_emit_line(acc, accn, line_no++);
        accn = 0;
      }
    }
  }
  if (accn > 0) {
    b64_emit_line(acc, accn, line_no++);
  }
  heap_caps_free(mem);
  printf("END\n");
  printf("OK\n");
  return 0;
}

void reg(const char *name, const char *help, esp_console_cmd_func_t fn) {
  const esp_console_cmd_t c = {
      .command = name,
      .help = help,
      .hint = nullptr,
      .func = fn,
      .argtable = nullptr,
      .func_w_context = nullptr,
      .context = nullptr,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&c));
}

} // namespace

void sm_console_start() {
  esp_console_repl_t *repl = nullptr;
  esp_console_repl_config_t repl_cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
  repl_cfg.prompt = "tab5>";
  repl_cfg.max_cmdline_length = 128;
  // float printf + ソケット操作(udptest)を REPL タスクで行うので余裕を持たせる。
  repl_cfg.task_stack_size = 16384;
  esp_console_dev_usb_serial_jtag_config_t hw = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
  if (esp_console_new_repl_usb_serial_jtag(&hw, &repl_cfg, &repl) != ESP_OK) {
    ESP_LOGW("con", "console repl init failed (continuing without it)");
    return;
  }
  reg("nodes", "list nodes", cmd_nodes);
  reg("status", "controller status", cmd_status);
  reg("toggle", "toggle <node_hex>", cmd_toggle);
  reg("read", "read <node_hex>", cmd_read);
  reg("pairble", "pairble <disc> <node_hex> [wifi|thread] [passcode]", cmd_pairble);
  reg("pair", "pair <ipv6> <node_hex> [thread|wifi] [passcode]", cmd_pair);
  reg("udptest", "udptest <port> <secs>", cmd_udptest);
  reg("setaddr", "setaddr <node_hex> <ip> [wifi|thread]", cmd_setaddr);
  reg("refresh", "refresh <node_hex> (SRP/mDNS re-resolve + kind re-detect)", cmd_refresh);
  // T5b / T5c
  reg("tap", "tap <x> <y> (synthetic touch)", cmd_tap);
  reg("swipe", "swipe <x1> <y1> <x2> <y2> [ms]", cmd_swipe);
  reg("ui-dump", "dump the active screen widget tree", cmd_ui_dump);
  reg("screenshot", "screenshot [1|2] (RGB565 base64 frame)", cmd_screenshot);
  ESP_ERROR_CHECK(esp_console_start_repl(repl));
  ESP_LOGI("con", "debug console ready (nodes/status/toggle/read/pair/pairble/tap/ui-dump/screenshot)");
}
