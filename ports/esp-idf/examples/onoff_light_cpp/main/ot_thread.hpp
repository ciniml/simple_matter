// esp_openthread 配線(Thread スタック初期化 + OT netif(lwIP 統合)+ role 監視 +
// SRP client 登録)。docs/design/c-ffi-shim.md §10。CONFIG_SM_NETWORK_THREAD のときのみ
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

// SRP client で `_matter._tcp`(port 5540、TXT SII/SAI/T)を登録する。
// host 名 = SM<MAC>、instance 名 = `instance_name`(sm_operational_instance_name の
// NUL 終端出力)。SRP サーバ(OTBR)は autostart で netdata から自動発見する。
void sm_ot_srp_register(const char *instance_name);

// 現在 attach 済みか(role = child/router/leader)。
bool sm_ot_is_attached();
