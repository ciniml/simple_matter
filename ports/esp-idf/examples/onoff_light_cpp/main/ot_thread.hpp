// esp_openthread 配線(Thread スタック初期化 + OT netif(lwIP 統合)+ role 監視 +
// SRP client 登録(fabric ごと))。docs/design/c-ffi-shim.md §10。CONFIG_SM_NETWORK_THREAD のときのみ
// 実体を持つ(それ以外は空スタブ)。
//
// esp_openthread は自前の mainloop タスクを走らせる(15.4 radio + lwIP netif)。
// role 変化イベントは Cmd queue 経由で matter_task(単線)へ給餌し、dataset 投入 /
// SRP 登録は matter_task から本 API を叩く(内部で OT lock を取る)。
#pragma once

#include "app_cmd.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

#include <cstddef>
#include <cstdint>

// esp_openthread を初期化し netif(lwIP 統合)+ mainloop タスクを起動する。
// role 変化は `q` に CmdKind::ThreadRole として載る。
void sm_ot_init(QueueHandle_t q);

// dataset TLV を OT に投入(otDatasetSetActiveTlvs)して IPv6/Thread を有効化し attach を
// 開始する(SM_EV_THREAD_ATTACH_REQUEST 契機)。成功で true。
bool sm_ot_apply_dataset(const uint8_t *tlv, size_t len);

// SRP サービス枠の数(= fabric テーブル容量 SM_MAX_FABRICS)。
#define SM_OT_SRP_MAX_SERVICES 5

// SRP client の `_matter._tcp`(port 5540、TXT SII/SAI/T)サービス集合を、現在の全 fabric の
// 運用インスタンス名 `names[0..n)`(sm_operational_instance_name_at の NUL 終端出力)に
// 同期する(マルチ admin、docs/design/p4-thread-controller.md §18.4 D1)。
//   - 未登録の名前  → otSrpClientAddService
//   - 消えた名前    → otSrpClientRemoveService(サーバ未送信なら otSrpClientClearService)
// host 名 = SM<MAC>・host address = auto・SRP サーバ(OTBR)は autostart で netdata から
// 自動発見(初回の追加時に 1 度だけ設定)。冪等なので SM_EV_COMMISSIONED /
// SM_EV_FABRIC_REMOVED / attach / CmdKind::SrpResync のたびに呼んでよい。
// 削除はサーバ応答まで枠を保持し、完了時に `q` へ CmdKind::SrpResync を載せる。
void sm_ot_srp_sync(const char *const *names, size_t n);

// 現在 attach 済みか(role = child/router/leader)。
bool sm_ot_is_attached();
