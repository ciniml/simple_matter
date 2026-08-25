// WiFi STA(基板上の ESP32-C6 を SDIO 経由で使う)。
// docs/design/p4-thread-controller.md §10(T2)。
//
// Tab5 の P4 には radio が無いので、WiFi は基板上の ESP32-C6 に
// `espressif/esp_hosted` + `espressif/esp_wifi_remote` 経由で丸投げする
// (標準の `esp_wifi_*` API がそのまま C6 に転送される)。
//
// 契約:
//   - `sm_wifi_start()` は **ノンブロッキング**。接続はイベント駆動で進み、
//     切断されたら自動でリトライする。UI も app_main も待たない。
//   - ステータス取得(`sm_wifi_get_status` / `sm_wifi_netif_index`)は
//     スレッドセーフ。pump タスクのループから読んでスナップショットへ書く
//     (UI から直接呼ばないこと = 単線契約)。

#pragma once

#include <cstdint>

// 接続状態。
enum sm_wifi_state_t : uint8_t {
  SM_WIFI_OFF = 0,        // Kconfig の SSID が空 = WiFi 無効
  SM_WIFI_CONNECTING = 1, // 起動〜接続待ち / 再接続中
  SM_WIFI_CONNECTED = 2,  // AP に接続済み(IPv4 or IPv6 のいずれかを取得)
  SM_WIFI_FAILED = 3      // 初期化に失敗(SDIO / C6 が居ない等。リトライしない)
};

struct sm_wifi_status_t {
  uint8_t state;    // sm_wifi_state_t
  char ssid[33];    // 設定された SSID(空 = 無効)
  char ll_addr[46]; // WiFi netif のリンクローカル(未取得なら "")
  char gua[46];     // グローバル/ULA の IPv6(SLAAC。未取得なら "")
  char ip4[16];     // 取得した IPv4(未取得なら "")
  uint32_t netif_index;
  uint32_t retries;
};

// WiFi を起動する(1 回だけ。SSID が空なら何もせず戻る)。
// 呼び出し元は完了を待たない。spinel 同期の**後**、LVGL 開始の**前**に呼ぶこと
// (§10.3 の 4。§9.4 の 2 罠 = PORT.A 5V 断 / spinel RX 取りこぼし を避けるため)。
void sm_wifi_start();

// WiFi netif の lwIP netif index(リンクローカル宛の sin6_scope_id 用)。
// netif がまだ無ければ 0。
uint32_t sm_wifi_netif_index();

// 現在の状態を丸ごとコピーする(スレッドセーフ)。
void sm_wifi_get_status(sm_wifi_status_t *out);
