// tab5_ctrl_app — M5Stack Tab5(ESP32-P4)+ Unit Gateway H2(ot_rcp、UART)で動く
// 「Thread ネットワーク主宰(leader)兼 SRP サーバ兼 Matter コントローラ」の GUI 版。
// docs/design/p4-thread-controller.md §9(T1)/ §9.5(T1b: 表示層を M5GFX へ)。
//
// thread_ctrl_hub_cpp(F8/P9、実機で動作確定)の OT + コントローラ配線はそのまま、
// 「固定ターゲットへ 30 秒毎 toggle」の代わりに 5 インチタッチ画面から操作する。
//
// タスク構成(単線契約):
//   - app_main          : NVS / netif / event loop → M5.begin(電源 + パネル + タッチ)
//                         → pump タスク起動 → spinel 同期待ち → LVGL 起動 → UI 構築 → 終了
//   - "ctrl_pump"       : sm_ctrl_* を専有する唯一のタスク(静的スタック 128KB)
//   - "ot_main"         : esp_openthread のメインループ
//   - "lvgl"            : lv_* を回す(display_gfx.cpp)。sm_ctrl_* は絶対に呼ばない
//
// UI ↔ pump は app_state.hpp の操作キュー + スナップショットのみで結ぶ。

#include "app_state.hpp"
#include "ble_central.hpp"
#include "console_dbg.hpp"
#include "ctrl_pump.hpp"
#include "display_gfx.hpp"
#include "ui.hpp"
#include "wifi_sta.hpp"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

namespace {
constexpr const char *TAG = "tab5_ctrl";
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

  // --- 1.5 M5Unified の初期化(PORT.A 5V + MIPI-DSI パネル + タッチ)---
  //
  // 順序の要点(実機 T1 / T1b):
  //   a) PORT.A(Grove)の 5V は Tab5 の IO エキスパンダ #0(PI4IOE5V6408 @0x43)の
  //      P2(EXT5V_EN)。**H2(RCP)の電源そのもの**なので spinel を開くより前に
  //      入れないと H2 が無電源ブートループになる(残留電流の 115200 ROM ログが
  //      spinel 460800 に Parse ゴミとして流れ込む)。
  //   b) M5Unified は Power.begin() でこのエキスパンダを初期化し直す
  //      (OUT_SET = 0b01110000 → EXT5V_EN が一旦 0)→ 直後に
  //      setExtOutput(cfg.output_power) で入れ直す。つまり M5.begin() は
  //      **PORT.A 5V を一瞬切る**。よって M5.begin() は pump(spinel)より前に
  //      置くしかない。ここでパネル初期化(MIPI-DSI)も済んでしまう。
  //   c) 一方 T1 で踏んだ「表示の初期描画中に spinel を開くと RX 取りこぼしで
  //      OT の初期リセットが assert ループ」は **LVGL の描画** が原因。そこで
  //      「パネル初期化はここ、LVGL(描画)は spinel 同期後」に分割してある。
  if (!sm_display_hw_init()) {
    ESP_LOGE(TAG, "display hw init failed");
    // 表示なしでも Thread/コントローラは動かす価値があるので続行する。
  }
  vTaskDelay(pdMS_TO_TICKS(500)); // H2 の ot_rcp 起動待ち(ROM+app で数百 ms)

  // --- 2. コントローラ pump を起動し、spinel(RCP)同期を待つ ---
  sm_ctrl_pump_start();
  for (int i = 0; i < 100; i++) {
    sm_ui_snapshot_t snap{};
    sm_app_snapshot_get(&snap);
    if (snap.role >= 1) { // detached 以上 = spinel 同期済み(OT 起動完了)
      ESP_LOGI(TAG, "openthread up (role=%d); starting lvgl", snap.role);
      break;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  // --- 2.5 WiFi(基板上の C6 / SDIO)を起動する。完了は待たない ---
  //
  // spinel 同期の **後**、LVGL の **前**(§10.3 の 4)。SDIO は PORT.A の
  // UART54/53 とは無関係だが、§9.4 の 2 罠(PORT.A 5V 断 / spinel RX 取りこぼし)を
  // 避けるため OT が立ってからにする。SSID 未設定なら即 return する。
  sm_wifi_start();

  // --- 2.6 BLE(NimBLE host-only + esp_hosted VHCI)。完了は待たない ---
  //
  // **WiFi の後**(§11.1)。BLE の HCI は WiFi と同じ SDIO リンク(esp_hosted)を通るので、
  // トランスポート(`esp_hosted_init`)の初期化が二重に走らないよう、ble_up タスクの中で
  // WiFi の初期化が落ち着くのを待ってから hosted / C6 BT controller / NimBLE を上げる。
  // SSID 未設定(WiFi 無効)のときは ble_up タスク自身が `esp_hosted_init()` を持つので、
  // **BLE だけ使う構成でも動く**。
  sm_ble_central_boot();

  // --- 3. LVGL(display + touch indev + LVGL タスク)---
  lv_display_t *disp = sm_display_lvgl_start();
  if (disp == nullptr) {
    ESP_LOGE(TAG, "sm_display_lvgl_start() failed");
    return;
  }
  ESP_LOGI(TAG, "display up: %dx%d", (int)lv_display_get_horizontal_resolution(disp),
           (int)lv_display_get_vertical_resolution(disp));

  // --- 4. UI(LVGL ロック必須)---
  sm_display_lock(0);
  sm_ui_create();
  sm_display_unlock();

  // --- 5. デバッグコンソール(T5a、§13.1。ログと同じ USB-Serial-JTAG に REPL)---
  sm_console_start();

  ESP_LOGI(TAG, "app_main done; ui + pump are running");
}
