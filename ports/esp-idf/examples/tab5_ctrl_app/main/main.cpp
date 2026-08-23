// tab5_ctrl_app — M5Stack Tab5(ESP32-P4)+ Unit Gateway H2(ot_rcp、UART)で動く
// 「Thread ネットワーク主宰(leader)兼 SRP サーバ兼 Matter コントローラ」の GUI 版。
// docs/design/p4-thread-controller.md §9(T1)。
//
// thread_ctrl_hub_cpp(F8/P9、実機で動作確定)の OT + コントローラ配線はそのまま、
// 「固定ターゲットへ 30 秒毎 toggle」の代わりに 5 インチタッチ画面から操作する。
//
// タスク構成(単線契約):
//   - app_main          : NVS / netif / event loop → BSP(表示 + タッチ + LVGL)→ UI 構築
//                         → pump タスク起動 → 終了(LVGL は esp_lvgl_port のタスクが回す)
//   - "ctrl_pump"       : sm_ctrl_* を専有する唯一のタスク(静的スタック 128KB)
//   - "ot_main"         : esp_openthread のメインループ
//   - esp_lvgl_port の LVGL タスク: lv_* を回す。sm_ctrl_* は絶対に呼ばない
//
// UI ↔ pump は app_state.hpp の操作キュー + スナップショットのみで結ぶ。

#include "app_state.hpp"
#include "ctrl_pump.hpp"
#include "ui.hpp"

#include "bsp/esp-bsp.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"

namespace {
constexpr const char *TAG = "tab5_ctrl";

// --- タッチ座標の回転(重要な罠)---
//
// LVGL 9.5 も esp_lvgl_port 2.9 も **ポインタ入力を画面回転に合わせて変換しない**
// (lv_indev.c に rotation の処理は無く、esp_lvgl_port_touch.c もタッチ ICの生値を
// そのまま渡す)。パネルは 720x1280(縦)、画面は回転後 1280x720(横)なので、
// 何もしないとタッチが 90 度ずれる。
//
// esp_lvgl_port の read_cb を lv_indev_get_read_cb() で取り出して包み、
// 画面回転に応じて座標を変換する(全て LVGL の公開 API のみ)。
lv_indev_read_cb_t g_touch_read_orig = nullptr;
int g_touch_log_left = 5; // 実機ブリングアップ用に最初の数点だけログに出す

void rotated_touch_read(lv_indev_t *indev, lv_indev_data_t *data) {
  g_touch_read_orig(indev, data);
  lv_display_t *disp = lv_indev_get_display(indev);
  if (disp == nullptr) {
    return;
  }
  const int32_t w = lv_display_get_horizontal_resolution(disp); // 回転後(= 1280)
  const int32_t h = lv_display_get_vertical_resolution(disp);   // 回転後(= 720)
  const int32_t px = data->point.x;                             // パネル生座標
  const int32_t py = data->point.y;
  int32_t sx = px;
  int32_t sy = py;
  switch (lv_display_get_rotation(disp)) {
  case LV_DISPLAY_ROTATION_90:
    sx = py;
    sy = h - 1 - px;
    break;
  case LV_DISPLAY_ROTATION_180:
    sx = w - 1 - px;
    sy = h - 1 - py;
    break;
  case LV_DISPLAY_ROTATION_270:
    sx = w - 1 - py;
    sy = px;
    break;
  default:
    break;
  }
#if CONFIG_SM_UI_TOUCH_MIRROR_X
  sx = w - 1 - sx;
#endif
#if CONFIG_SM_UI_TOUCH_MIRROR_Y
  sy = h - 1 - sy;
#endif
  data->point.x = sx;
  data->point.y = sy;
  if (data->state == LV_INDEV_STATE_PRESSED && g_touch_log_left > 0) {
    --g_touch_log_left;
    // 実機で「押した場所とカーソルがずれていないか」を判定する材料。
    ESP_LOGI(TAG, "touch: panel(%d,%d) -> screen(%d,%d) [screen %dx%d]", (int)px, (int)py, (int)sx,
             (int)sy, (int)w, (int)h);
  }
}

void install_touch_rotation() {
  lv_indev_t *indev = bsp_display_get_input_dev();
  if (indev == nullptr) {
    ESP_LOGW(TAG, "no touch indev; skipping the rotation shim");
    return;
  }
  g_touch_read_orig = lv_indev_get_read_cb(indev);
  if (g_touch_read_orig == nullptr) {
    ESP_LOGW(TAG, "touch indev has no read_cb; skipping the rotation shim");
    return;
  }
  lv_indev_set_read_cb(indev, rotated_touch_read);
  ESP_LOGI(TAG, "touch rotation shim installed");
}

// PORT.A(Grove)の 5V 給電を有効にする(実機 T1 の重要な罠)。
//
// Tab5 の外部 5V は IO エキスパンダ **#0(PI4IOE5V6408、addr low = 0x43)の P2** で
// 制御される(M5Tab5-UserDemo の bsp_set_ext_5v_en。同デモの「PI4IOE1」= addr low)。Espressif BSP はエキスパンダを
// 初期化時にチップリセットするだけで P2 を立て直さないため、一度でも BSP を初期化
// すると Grove 5V が落ち、**Unit Gateway H2 が無電源のままブートループ**する
// (残留電流で ROM ログを 115200 で吐き続け、spinel(460800)には Parse ゴミに見える)。
// 電源系の状態は P4 のリセットを跨いで保持されるため、必ず起動時に明示的に入れる。
void enable_ext_5v() {
  esp_io_expander_handle_t exp0 = bsp_io_expander_init();
  if (exp0 == nullptr) {
    ESP_LOGE(TAG, "io expander #0 init failed; PORT.A 5V may be off");
    return;
  }
  esp_io_expander_set_dir(exp0, IO_EXPANDER_PIN_NUM_2, IO_EXPANDER_OUTPUT);
  esp_io_expander_set_level(exp0, IO_EXPANDER_PIN_NUM_2, 1);
  esp_io_expander_set_output_mode(exp0, IO_EXPANDER_PIN_NUM_2, IO_EXPANDER_OUTPUT_MODE_PUSH_PULL);
  ESP_LOGI(TAG, "PORT.A 5V enabled (io expander #0 P2)");
}

lv_display_rotation_t configured_rotation() {
  switch (CONFIG_SM_UI_ROTATION) {
  case 0:
    return LV_DISPLAY_ROTATION_0;
  case 180:
    return LV_DISPLAY_ROTATION_180;
  case 270:
    return LV_DISPLAY_ROTATION_270;
  default:
    return LV_DISPLAY_ROTATION_90;
  }
}

} // namespace

extern "C" void app_main(void) {
  // --- 1. 永続化とネットワークスタックの土台(OT より前に済ませる)---
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    // ノード帳を消してしまうので通常はここに来ない(来たら nvs が壊れている)。
    ESP_LOGW(TAG, "nvs_flash_init: %s -> erasing", esp_err_to_name(err));
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  sm_app_state_init();

  // --- 1.5 PORT.A の 5V を入れて H2(RCP)へ給電し、ブート完了を待つ ---
  enable_ext_5v();
  vTaskDelay(pdMS_TO_TICKS(500)); // H2 の ot_rcp 起動待ち(ROM+app で数百 ms)

  // --- 2. コントローラ pump を先に起動し、spinel(RCP)同期を待つ ---
  //
  // 表示(MIPI-DSI + LVGL)の初期描画は PSRAM/DMA 負荷が大きく、その最中に
  // OT の spinel UART(460800)を開くと RX が取りこぼされて "dropping radio
  // frame: Parse" → 初期リセット失敗 assert で再起動ループになる(実機 T1)。
  // OT の初期同期(リセット応答)だけ先に済ませれば、以降の HDLC は再送で
  // 回復するため表示と共存できる。
  sm_ctrl_pump_start();
  for (int i = 0; i < 100; i++) {
    sm_ui_snapshot_t snap{};
    sm_app_snapshot_get(&snap);
    if (snap.role >= 1) { // detached 以上 = spinel 同期済み(OT 起動完了)
      ESP_LOGI(TAG, "openthread up (role=%d); starting display", snap.role);
      break;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  // --- 3. 表示(BSP: MIPI-DSI 1280x720 + GT911/ST7123 タッチ + esp_lvgl_port)---
  // 描画バッファの確保方針は BSP 既定に従う(bsp_display_start)。
  lv_display_t *disp = bsp_display_start();
  if (disp == nullptr) {
    ESP_LOGE(TAG, "bsp_display_start() failed");
    return;
  }
  // パネルは 720x1280(縦)。既定では横向き 1280x720 で使う(CONFIG_SM_UI_ROTATION)。
  bsp_display_lock(0);
  bsp_display_rotate(disp, configured_rotation());
  install_touch_rotation();
  bsp_display_unlock();
  bsp_display_backlight_on();
  ESP_LOGI(TAG, "display up: %dx%d", (int)lv_display_get_horizontal_resolution(disp),
           (int)lv_display_get_vertical_resolution(disp));

  // --- 3. UI(LVGL ロック必須)---
  bsp_display_lock(0);
  sm_ui_create();
  bsp_display_unlock();

  ESP_LOGI(TAG, "app_main done; ui + pump are running");
}
