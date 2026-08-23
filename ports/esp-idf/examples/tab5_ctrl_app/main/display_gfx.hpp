// 表示層(M5Unified / M5GFX + 自前 LVGL ポート)。
// docs/design/p4-thread-controller.md §9.5(T1b)。
//
// Espressif BSP(espressif/m5stack_tab5 + esp_lvgl_port)は実機で
// 「初期化ログ全て正常・バックライト点灯・画面真っ黒」だったため廃止し、
// 同一個体で表示が実証済みの M5GFX へ差し替えた(§9.5 参照)。
//
// 契約:
//   - lv_* を触るのは LVGL タスクと、sm_display_lock() を取った区間だけ。
//   - sm_ctrl_* / ot_* はこのファイルからは一切呼ばない。

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lvgl.h"

// M5Unified を初期化する(電源 = PORT.A 5V / MIPI-DSI パネル / タッチ)。
// LVGL にはまだ触らない。app_main の最初期に 1 回だけ呼ぶ。
// 戻り値: 成功したら true。
bool sm_display_hw_init(void);

// LVGL を初期化し、lv_display / lv_indev を作って LVGL タスクを起動する。
// sm_display_hw_init() の後、OT(spinel)同期が済んでから呼ぶ。
// 戻り値: 既定 display(失敗時 nullptr)。
lv_display_t *sm_display_lvgl_start(void);

// LVGL ロック(esp_lvgl_port の bsp_display_lock/unlock 相当)。
// timeout_ms = 0 は無限待ち。
bool sm_display_lock(uint32_t timeout_ms);
void sm_display_unlock(void);
