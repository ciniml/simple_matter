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

// WAMR プールをブート直後(ヒープ断片化前)に確保する。app_main 冒頭で呼ぶこと
// (唯一の例外的に pump タスク外から呼べる関数)。稼働後の遅延確保は総 free が
// 足りても連続ブロック不足でほぼ失敗する(実機 P6)。POOL_STATIC=y では no-op。
void script_pool_reserve();

// プール確保 + VM ロードを app_main 冒頭で行う(pump スタック確保前でないと
// WAMR 線形メモリ 64KB の連続ブロックが取れない。実機 P6)。on_boot は呼ばない
// (pump の script_init が実行する)。pool_reserve を内包する。
void script_preload();

// パーティションからスクリプトをロードして VM を起動し、on_boot を呼ぶ。
// スクリプトが無い / 壊れている場合は false(ファームはスクリプト無しで通常動作する)。
bool script_init();

// pump ループから毎周回(スクリプトタイマの駆動)。
void script_poll(uint64_t now_ms);

// on_cluster_change から(IM write / コマンド由来の属性変化 → on_attr_write フック)。
void script_notify_attr_write(uint16_t ep, uint32_t cluster, uint32_t attr);

// バインディング(script ドライバ / センサ poll)から(→ on_sensor フック)。
void script_notify_sensor(int32_t bind_index);

// カスタムクラスタ(ScriptStore 等)の invoke から(→ on_command フック、§9.4)。
// 戻り値は見ない(壊れたスクリプトが ScriptStore を塞げないようにするため)。
void script_notify_command(uint16_t ep, uint32_t cluster, uint32_t cmd);

// VM を落として active slot から読み直す(ScriptStore の Commit / ロールバック)。
// スクリプトが無い / ロードできない場合は false(ファームはスクリプト無しで動く)。
bool script_reload();

// 現在の状態をログに出す(起動時 / cfg-show)。
void script_log_status();

} // namespace smgen
