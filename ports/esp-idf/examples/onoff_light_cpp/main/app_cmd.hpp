// タスク間メッセージ(WiFi/IP イベント・BLE コールバック → matter_task)。
//
// NimBLE のホストタスク / WiFi イベントハンドラは別コンテキストで走るため、sm_* を直接
// 呼ばず、この Cmd を FreeRTOS queue に載せて matter_task(単線)に直列化する
// (docs/design/c-ffi-shim.md §9.3)。
#pragma once

#include <cstdint>

enum class CmdKind {
  IpV4,             // got IPv4 → sm_set_addrs(+ BLE 時は sm_wifi_status(true))
  IpV6,             // got IPv6 link-local
  LocalToggle,      // 物理ボタン等のローカル OnOff トグル
  BleConnected,     // GATT 接続確立(mtu = 交渉済み ATT MTU、0=不明)
  BleDisconnected,  // GATT 切断
  BleC1Write,       // C1 write 受信(frag[..frag_len] = 1 BTP フラグメント)
  BleC2Subscribed,  // C2 CCCD subscribe 完了
  WifiFailed,       // WiFi join 失敗(BLE プロビジョン中の再試行契機)
  ThreadRole,       // OT role 変化(thread_attached = child/router/leader なら true)
  SrpResync,        // SRP サービス削除完了 → 枠が空いたので fabric ごとの登録を再同期
};

struct Cmd {
  CmdKind kind;
  uint8_t v4[4];
  uint8_t v6[16];
  uint16_t mtu;         // BleConnected
  uint16_t frag_len;    // BleC1Write の有効バイト数
  bool thread_attached; // ThreadRole: attach 済みか
  uint8_t frag[256];    // BleC1Write の 1 フラグメント(BTP は ATT_MTU-3 以内)
};
