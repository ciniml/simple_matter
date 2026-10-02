// NimBLE central 配線(T3、docs/design/p4-thread-controller.md §11)。
//
// controller_hub_cpp(F7b、S3 実機検証済み)の main/ble_central.{hpp,cpp} の移植。
// Tab5(ESP32-P4)には BT controller が無いので、**NimBLE はホストだけ** を P4 で走らせ、
// HCI を esp_hosted の VHCI 経由(WiFi と同じ SDIO リンク)で基板上の C6 に流す。
//
// central の役割: scan(0xFFF6 commissionable を discriminator で照合)→ connect →
// MTU 交換 → C1(write)/ C2(indicate)発見 → C2 subscribe → C1 write / C2 indication 受信。
//
// 単線契約(§9.1): NimBLE のコールバックは **NimBLE host タスク** で走る。そこからは
// `sm_ctrl_*` を 1 つも呼ばず、FreeRTOS キューに BleCentralMsg を積むだけにする。
// キューを読んで `sm_ctrl_ble_event` / `sm_ctrl_ble_poll` を叩くのは pump タスクだけ。
#pragma once

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <cstddef>
#include <cstdint>

// central イベント種別(pump タスクへ queue で渡す)。
enum class BleCentralEvent : uint8_t {
  Connected,    // arg = ATT MTU
  Disconnected, //
  Discovered,   // C1 / C2 / C2 CCCD のハンドル確定(この後 handshake を C1 に書き、C2 を subscribe する)
  Subscribed,   // C2 indication の subscribe 完了
  Indication,   // frag = 受信 1 BTP フラグメント
  ScanTimeout,  // discriminator 一致の広告が見つからないままスキャンが終わった
};

struct BleCentralMsg {
  BleCentralEvent kind;
  uint16_t mtu;
  uint16_t frag_len;
  uint8_t frag[256];
  // Connected のみ: ピアの BT MAC(印字順)。public アドレスのときだけ valid。
  // ESP32 ファミリは WiFi STA MAC = BT MAC - 2 なので、mDNS が全滅した環境での
  // 運用アドレス導出(EUI-64)に使える(ctrl_pump の最終フォールバック)。
  uint8_t peer_mac[6];
  uint8_t peer_mac_valid;
};

// BLE ホストの起動状態(UI のステータス表示用)。
enum sm_ble_host_state_t : uint8_t {
  SM_BLE_HOST_OFF = 0,      // 未起動(CONFIG_BT_ENABLED 無し)
  SM_BLE_HOST_STARTING = 1, // esp_hosted / C6 の BT controller / NimBLE を起動中
  SM_BLE_HOST_READY = 2,    // ble_hs sync 済み。scan できる
  SM_BLE_HOST_FAILED = 3    // 起動に失敗(C6 の FW が BT 無効 / SDIO が上がらない等)
};

// BLE ホストを **非同期で** 起動する(app_main から 1 回。sm_wifi_start() の後)。
//
// 内部で "ble_up" タスクを起こし、そこで
//   (WiFi 有効なら)WiFi の初期化が落ち着くのを待つ  ← esp_hosted_init の二重呼び防止
//   → esp_hosted_init()(WiFi 無効時はここが SDIO/RPC の初期化そのもの)
//   → esp_hosted_connect_to_slave()
//   → esp_hosted_bt_controller_init() / _enable()   ← C6 側 controller を立てる
//   → nimble_port_init() + NimBLE host タスク
// を順に行う。app_main も LVGL も待たない。
void sm_ble_central_boot();

// 起動状態(sm_ble_host_state_t)。pump がスナップショットへ写す。
uint8_t sm_ble_central_state();

// central イベントのキュー(sm_ble_central_boot が作る。未起動なら nullptr)。
QueueHandle_t sm_ble_central_queue();

// discriminator 照合でスキャンを開始する(接続 → MTU → C1/C2 発見 → C2 subscribe まで自動)。
// 進行は queue の Connected / Subscribed で観測する。戻り値 = スキャンを開始できたか。
bool sm_ble_central_start(uint16_t discriminator, uint32_t scan_ms);

// スキャン中止 + 接続状態のリセット(次の pairing のため)。切断はしない。
void sm_ble_central_stop();

// C1(write without response)で 1 BTP フラグメントを送る。失敗は false。
bool sm_ble_central_write_c1(const uint8_t *frag, size_t len);

// C2 の CCCD に indication 有効化を書く(完了で Subscribed イベント)。BTP は「handshake request を
// C1 に書く → C2 を subscribe → 相手が handshake response を indicate」の順序が必須(chip 系の
// ペリフェラルは subscribe を受けた時点で handshake request が無いと応答しない)。
bool sm_ble_central_subscribe_c2();

// 現在の接続を切断する(BLE フェーズ完了後の handoff)。
void sm_ble_central_disconnect();
