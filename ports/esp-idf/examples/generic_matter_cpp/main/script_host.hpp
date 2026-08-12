// スクリプト VM の ESP-IDF 側の受け皿(§9.3)。
//
//   - `smscript` パーティションの active slot(script_img.hpp のヘッダ)から .wasm を読む
//   - module "sm" の実体(sm_attr_* / gpio / ledc / NVS "smscr")を script_vm へ注入する
//   - フック実行の壁時計上限を esp_timer ワンショットで監視する
//
// 全て matter pump タスク(単線)から呼ぶこと。CONFIG_SM_SCRIPT_ENABLE=n のときは
// 全関数が no-op(WAMR もリンクされない)。
#pragma once

#include <cstddef>
#include <cstdint>

namespace smgen {

// パーティションからスクリプトをロードして VM を起動し、on_boot を呼ぶ。
// スクリプトが無い / 壊れている場合は false(ファームはスクリプト無しで通常動作する)。
bool script_init();

// pump ループから毎周回(スクリプトタイマの駆動)。
void script_poll(uint64_t now_ms);

// on_cluster_change から(IM write / コマンド由来の属性変化 → on_attr_write フック)。
void script_notify_attr_write(uint16_t ep, uint32_t cluster, uint32_t attr);

// バインディング(script ドライバ / センサ poll)から(→ on_sensor フック)。
void script_notify_sensor(int32_t bind_index);

// 現在の状態をログに出す(起動時 / cfg-show)。
void script_log_status();

} // namespace smgen
