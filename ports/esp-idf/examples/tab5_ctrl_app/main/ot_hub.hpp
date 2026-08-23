// OT ホスト(M5Stack Tab5 = ESP32-P4 + Unit Gateway H2 の RCP over UART)の配線。
// docs/design/p4-thread-controller.md §3 F8c / §9 T1。
//
// thread_ctrl_hub_cpp/main/ot_hub.{hpp,cpp}(実機 P9 で確定した配線)のコピーに、
// GUI 用のステータス取得(sm_ot_hub_get_status / sm_ot_hub_dataset_hex)を足したもの。
// F8e(border router)の足場は本アプリには持ち込んでいない。
//
// 責務: esp_openthread の初期化(RADIO_MODE_UART_RCP)、Thread ネットワークの
// 生成/復元と leader 化、SRP サーバの有効化、SRP サーバ帳からのデバイス
// アドレス逆引き(F8b `sm_ctrl_set_node_addr` の実戦配線)。
//
// 注意: ここの関数は全て内部で esp_openthread_lock_acquire/release を取る。
// LVGL タスクから呼んでも安全だが、実際の呼び出しは pump タスクに集約している
//(sm_ctrl_* の単線契約と足並みを揃えるため)。

#pragma once

#include <cstddef>
#include <cstdint>

// OT スタックを起動する(専用タスク + eventfd 登録)。戻ると OT インスタンスは
// まだ準備中の可能性がある(sm_ot_hub_wait_ready を使う)。
void sm_ot_hub_init();

// OT インスタンスが使えるようになるまで待つ。timeout_ms で諦める。
bool sm_ot_hub_wait_ready(uint32_t timeout_ms);

// Thread ネットワークを用意して起動する:
//   1. NVS に active dataset があればそれを使う(OT の settings は "nvs" パーティション)
//   2. なければ CONFIG_SM_THREAD_DATASET_TLV_HEX(非空)を適用
//   3. それも空なら otDatasetCreateNewNetwork で新規生成
// いずれの場合も active dataset の TLV を hex でログ出力する(デバイス側プリセット用)。
bool sm_ot_hub_form_network();

// attach 済み(child/router/leader)か。
bool sm_ot_hub_is_attached();

// leader になるまで待つ(戻り値 = leader になれたか)。
bool sm_ot_hub_wait_leader(uint32_t timeout_ms);

// OT netif の実装インデックス(IPv6 リンクローカル宛の sin6_scope_id に使う)。
uint32_t sm_ot_hub_netif_index();

// SRP サーバに登録されているホストから、インスタンス名に `node_id` の 16 hex を
// 含むサービスを探し、そのホストの IPv6 アドレスを out_ip[16] へ書く。
// Thread では mDNS ではなく SRP がデバイスの運用アドレスの出所になる(F8b)。
bool sm_ot_hub_srp_lookup(uint64_t node_id, uint8_t out_ip[16]);

// SRP サーバの登録内容をログに出す(デバッグ補助)。
void sm_ot_hub_dump_srp();

// --- GUI 用のステータス取得(T1)---

// Thread の現況(ステータスバー表示用)。
struct sm_ot_status_t {
  int role;         // otDeviceRole(0=disabled 1=detached 2=child 3=router 4=leader)
  uint16_t rloc16;  // RLOC16(attach 前は不定)
  uint8_t channel;  // 802.15.4 チャネル
  uint16_t panid;   // PAN ID
  bool srp_enabled; // SRP サーバが動いているか
  uint32_t srp_hosts;   // SRP に登録されているホスト数
  char netname[17]; // ネットワーク名(NUL 終端)
};

// 現況を読む(OT ロックは内部で取る)。
void sm_ot_hub_get_status(sm_ot_status_t *out);

// active dataset の TLV を hex(小文字、NUL 終端)で `out` へ書く。
// 戻り値 = 書いた文字数(0 = dataset 未設定 / バッファ不足)。cap は 2*254+1 あれば十分。
size_t sm_ot_hub_dataset_hex(char *out, size_t cap);
