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

// --- 合成ポインタ注入(T5b、§13.1)-------------------------------------------
//
// デバッグコンソール(main/console_dbg.cpp)から「タップ / スワイプ」を注入する。
// 実体は indev の read_cb 内の状態機械で、LVGL タスクが自分の文脈で拾う
// (= コンソールタスクから lv_* を呼ばない。§13.2 の契約)。
// 注入中は実タッチを無視する(合成と実指の混線を防ぐ)。
//
// (x1,y1) で押下 → ms かけて (x2,y2) へ線形移動 → 離す。
// tap は x1==x2 / y1==y2 / ms=80 の縮退形。
// 戻り値: 受け付けたら true(前の注入が未完了 = busy、または LVGL 未起動なら false)。
bool sm_display_inject_pointer(int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint32_t ms);

// 注入が進行中(まだ「離す」が LVGL に届いていない)なら true。
bool sm_display_inject_busy(void);
