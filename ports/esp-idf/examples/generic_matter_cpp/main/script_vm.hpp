// WASM(WAMR)スクリプト VM。docs/design/generic-firmware.md §9.3。
//
// **ESP-IDF 非依存**(wasm_export.h と libc しか使わない)。ハードウェア・属性アクセス・
// 暴走監視タイマは `ScriptHostOps` の関数ポインタでプラットフォームから注入する:
//
//   - ファーム   : script_host.cpp(sm_attr_*、gpio/ledc、NVS "smscr"、esp_timer)
//   - ホスト検証 : tools/wasm-harness/harness.cpp(メモリ上のモック)
//
// 実行モデル: フックは Matter ポンプと**同一タスクで同期実行**する(単線契約)。
// 呼び出し直前に `watchdog_arm(hook_budget_ms)`、復帰で `watchdog_disarm()`。
// 満了時はプラットフォームが別コンテキストから `script_vm_terminate()` を呼び、
// WAMR が実行中のインスタンスに trap を上げてフックから抜ける。
#pragma once

#include <cstddef>
#include <cstdint>

#include "script_abi.hpp"

namespace smgen {

// ホスト機能(module "sm" の実体)。NULL メンバは「未対応」= SCRIPT_ERR_UNSUPPORTED。
struct ScriptHostOps {
  void *user = nullptr;
  // 16B 値レコード(script_abi.hpp)を out に書く。戻り値 >=0 = 書いた全長。
  int32_t (*attr_get)(void *user, int32_t ep, int32_t cluster, int32_t attr, uint8_t *out,
                      uint32_t cap) = nullptr;
  int32_t (*attr_set)(void *user, int32_t ep, int32_t cluster, int32_t attr, const uint8_t *val,
                      uint32_t len) = nullptr;
  int32_t (*gpio_write)(void *user, int32_t pin, int32_t value) = nullptr;
  int32_t (*gpio_read)(void *user, int32_t pin) = nullptr;
  int32_t (*pwm_set)(void *user, int32_t ch, int32_t duty) = nullptr;
  void (*log)(void *user, const char *msg, uint32_t len) = nullptr;
  int32_t (*kvs_get)(void *user, const char *key, uint32_t key_len, uint8_t *out,
                     uint32_t cap) = nullptr;
  int32_t (*kvs_set)(void *user, const char *key, uint32_t key_len, const uint8_t *val,
                     uint32_t len) = nullptr;
  // 暴走監視。arm(ms) から ms 経過しても disarm されなければ script_vm_terminate() を呼ぶ。
  void (*watchdog_arm)(void *user, uint32_t ms) = nullptr;
  void (*watchdog_disarm)(void *user) = nullptr;
};

struct ScriptVmConfig {
  // WAMR のヒーププール(静的確保。線形メモリ・モジュール・実行スタックが全てここから出る)。
  uint8_t *heap_pool = nullptr;
  uint32_t heap_pool_size = 0;
  // WASM 実行スタック(既定 8KB)。
  uint32_t stack_size = 8 * 1024;
  // WASM アプリヒープ(malloc を使わない no_std スクリプトは 0 でよい)。
  uint32_t app_heap_size = 0;
  // 1 フックあたりの壁時計上限(ms)。0 = 無効。
  uint32_t hook_budget_ms = 50;
  // 同時に張れるスクリプトタイマの数(実装上限 kScriptMaxTimers)。
  uint32_t max_timers = 8;
};

static constexpr size_t kScriptMaxTimers = 8;

// VM を起動する(既に起動していれば停止してから)。`wasm` の内容は内部でプールへ複製する
// ので、呼び出し後に解放してよい。失敗時は err に理由を書いて false。
bool script_vm_start(const uint8_t *wasm, size_t len, const ScriptVmConfig &cfg,
                     const ScriptHostOps &ops, char *err, size_t err_cap);

// VM を落とす(インスタンス・モジュール・ランタイムを解放。プールは呼び出し側の所有)。
// フックを実行するネイティブタスク側で 1 回呼ぶ(WAMR の thread env 初期化)。
// LIB_PTHREAD 有効の WAMR は wasm 実行時に pthread_self を呼ぶため、素の FreeRTOS
// タスクからだと ESP-IDF の pthread 層が assert する(実機 P6)。
void script_vm_attach_thread();

void script_vm_stop();

// VM が動いているか(スクリプト未搭載なら false = 全フックが no-op)。
bool script_vm_active();

// 実行中のフックに trap を上げる(暴走監視から。別コンテキスト/タイマから呼んでよい)。
void script_vm_terminate();

// ---- フック(未 export のフックは no-op / 既定値を返す)-----------------------

void script_on_boot();
// 0 = 承認。非 0 は拒否の意思表示だが**現状は観測のみ**(README / §9.3)。
int32_t script_on_attr_write(int32_t ep, int32_t cluster, int32_t attr);
int32_t script_on_command(int32_t ep, int32_t cluster, int32_t cmd);
void script_on_sensor(int32_t bind);
void script_on_timer(int32_t id);

// スクリプトタイマの駆動(pump ループから毎周回呼ぶ。now_ms は単調増加)。
void script_vm_poll(uint64_t now_ms);

// 統計(ログ・テスト用)。
struct ScriptVmStats {
  uint32_t calls = 0;    // フック呼び出し回数
  uint32_t traps = 0;    // trap(例外)で終わった回数
  uint32_t timeouts = 0; // 壁時計上限で terminate した回数
};
const ScriptVmStats &script_vm_stats();

// 直近の例外文字列("" = 無し)。
const char *script_vm_last_error();

} // namespace smgen
