// OT ホスト(ESP32-P4 + ESP32-H2 RCP over UART)の配線。
// docs/design/p4-thread-controller.md §3 F8c。
//
// 責務: esp_openthread の初期化(RADIO_MODE_UART_RCP)、Thread ネットワークの
// 生成/復元と leader 化、SRP サーバの有効化、SRP サーバ帳からのデバイス
// アドレス逆引き(F8b `sm_ctrl_set_node_addr` の実戦配線)。

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
