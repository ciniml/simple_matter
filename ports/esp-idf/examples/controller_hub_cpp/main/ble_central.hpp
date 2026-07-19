// NimBLE central 配線(F7b、docs/design/c-ffi-shim.md §11.4)。
//
// コントローラ側(central)の BLE: scan(0xFFF6 commissionable を discriminator で照合)→
// connect → MTU 交換 → C1(write)/ C2(indicate)発見 → C2 subscribe → C1 write /
// C2 indication 受信。NimBLE のコールバック(host タスク)は queue 経由で matter タスクへ
// 給餌し、C1 write は matter タスクから本 API を叩く(sm_ctrl_ble_poll の出力)。
//
// CONFIG_SM_HUB_BLE_PAIR のときのみ実体を持つ。デバイス側 onoff_light_cpp の ble.cpp
// (peripheral)の鏡像。
#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <cstddef>
#include <cstdint>

// central イベント種別(matter タスクへ queue で渡す)。
enum class BleCentralEvent : uint8_t {
  Connected,   // arg = ATT MTU
  Disconnected,
  Subscribed,  // C2 indication の subscribe 完了
  Indication,  // frag = 受信 1 BTP フラグメント
};

struct BleCentralMsg {
  BleCentralEvent kind;
  uint16_t mtu;
  uint16_t frag_len;
  uint8_t frag[256];
};

// NimBLE を初期化し host タスクを起動する。イベントは `q` に BleCentralMsg で載る。
void sm_ble_central_init(QueueHandle_t q);

// discriminator 照合でスキャン → 接続 → MTU 交換 → C1/C2 発見 → C2 subscribe を開始する。
// 進行は queue の Connected / Subscribed で観測する。
void sm_ble_central_start(uint16_t discriminator);

// C1(write without response)で 1 BTP フラグメントを送る。失敗は false。
bool sm_ble_central_write_c1(const uint8_t *frag, size_t len);

// 現在の接続を切断する(コミッショニング BLE フェーズ完了後の handoff)。
void sm_ble_central_disconnect();
