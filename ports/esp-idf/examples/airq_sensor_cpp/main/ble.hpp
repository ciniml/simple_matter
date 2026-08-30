// NimBLE 配線(GATT 0xFFF6 / C1 write / C2 indicate + commissionable 広告)。
// docs/design/c-ffi-shim.md §9.3。CONFIG_SM_ENABLE_BLE のときのみ実体を持つ。
//
// NimBLE のコールバック(別タスク)は Cmd queue 経由で matter_task に給餌し、送出
// (indicate)・広告更新は matter_task から本 API を叩く(NimBLE host 関数は他タスクから
// 呼んでも内部ロックで安全)。
#pragma once

#include "app_cmd.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <cstddef>
#include <cstdint>

// NimBLE を初期化し、GATT サービス登録 + host タスク起動。BLE イベントは `q` に載る。
void sm_ble_init(QueueHandle_t q);

// コミッショニング完了後に BLE/BT を停止し無線を WiFi へ明け渡す(coex 排除)。
void sm_ble_stop();

// commissionable 広告データを設定する(`sm_ble_adv_data` の出力をそのまま渡す)。
// len==0 は広告停止。接続中は広告しない(切断時に再開)。
void sm_ble_set_adv(const uint8_t *adv, size_t len);

// C2 indication で 1 BTP フラグメントを送る。確認(EDONE)まで待ってから返る
// (indicate 完了で次フラグメントを直列送出するため)。失敗は false。
bool sm_ble_indicate(const uint8_t *frag, size_t len);
