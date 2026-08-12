// WASM(WAMR)スクリプト VM の実装。script_vm.hpp のコメントを参照。
// ESP-IDF 非依存(wasm_export.h + libc のみ)。

#include "script_vm.hpp"

#include <cstdio>
#include <cstring>

#include "wasm_export.h"

namespace smgen {
namespace {

struct Timer {
  bool active = false;
  bool periodic = false;
  int32_t id = 0;
  uint32_t period_ms = 0;
  uint64_t due_ms = 0;
};

struct Vm {
  bool inited = false;               // wasm_runtime_full_init 済み
  wasm_module_t module = nullptr;    // ロード済みモジュール
  wasm_module_inst_t inst = nullptr; // インスタンス
  wasm_exec_env_t env = nullptr;     // 実行環境(単線なので 1 本)
  uint8_t *code = nullptr;           // プール上のバイトコード(インスタンス生存中は保持)
  ScriptHostOps ops;
  ScriptVmConfig cfg;
  ScriptVmStats stats;
  uint64_t now_ms = 0;
  Timer timers[kScriptMaxTimers];
  bool in_hook = false; // 再入防止(フックからフックは呼ばない)
  char last_error[128] = {0};
};

Vm g_vm;

// ---- 線形メモリのアクセス補助 -----------------------------------------------

// [off, off+size) が線形メモリ内なら native ポインタを返す。範囲外は nullptr。
void *app_ptr(uint32_t off, uint32_t size) {
  if (g_vm.inst == nullptr) {
    return nullptr;
  }
  if (size == 0) {
    // 長さ 0 は「有効なポインタ扱い」だが実体は触らない。
    return wasm_runtime_validate_app_addr(g_vm.inst, off, 1)
               ? wasm_runtime_addr_app_to_native(g_vm.inst, off)
               : nullptr;
  }
  if (!wasm_runtime_validate_app_addr(g_vm.inst, off, size)) {
    return nullptr;
  }
  return wasm_runtime_addr_app_to_native(g_vm.inst, off);
}

// ---- ホスト import(module "sm")---------------------------------------------
//
// 引数は全て i32(線形メモリ内オフセットと整数)。ポインタ引数は必ず範囲検証してから
// native ポインタに変換する(スクリプトからのメモリ脱出を防ぐ)。

int32_t ni_attr_get(wasm_exec_env_t, int32_t ep, int32_t cluster, int32_t attr, int32_t out_off,
                    int32_t cap) {
  if (g_vm.ops.attr_get == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  if (cap < 0) {
    return SCRIPT_ERR_ARG;
  }
  uint8_t *p = (uint8_t *)app_ptr((uint32_t)out_off, (uint32_t)cap);
  if (p == nullptr) {
    return SCRIPT_ERR_ARG;
  }
  return g_vm.ops.attr_get(g_vm.ops.user, ep, cluster, attr, p, (uint32_t)cap);
}

int32_t ni_attr_set(wasm_exec_env_t, int32_t ep, int32_t cluster, int32_t attr, int32_t val_off,
                    int32_t len) {
  if (g_vm.ops.attr_set == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  if (len < (int32_t)kScriptValueSize) {
    return SCRIPT_ERR_ARG;
  }
  const uint8_t *p = (const uint8_t *)app_ptr((uint32_t)val_off, (uint32_t)len);
  if (p == nullptr) {
    return SCRIPT_ERR_ARG;
  }
  return g_vm.ops.attr_set(g_vm.ops.user, ep, cluster, attr, p, (uint32_t)len);
}

int32_t ni_gpio_write(wasm_exec_env_t, int32_t pin, int32_t value) {
  if (g_vm.ops.gpio_write == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  return g_vm.ops.gpio_write(g_vm.ops.user, pin, value);
}

int32_t ni_gpio_read(wasm_exec_env_t, int32_t pin) {
  if (g_vm.ops.gpio_read == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  return g_vm.ops.gpio_read(g_vm.ops.user, pin);
}

int32_t ni_pwm_set(wasm_exec_env_t, int32_t ch, int32_t duty) {
  if (g_vm.ops.pwm_set == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  return g_vm.ops.pwm_set(g_vm.ops.user, ch, duty);
}

// タイマは VM 内で管理する(ホストは now_ms を script_vm_poll で供給するだけ)。
int32_t timer_set(int32_t ms, int32_t id, bool periodic) {
  if (ms < 0) {
    return SCRIPT_ERR_ARG;
  }
  const uint32_t cap = g_vm.cfg.max_timers < kScriptMaxTimers ? g_vm.cfg.max_timers
                                                              : (uint32_t)kScriptMaxTimers;
  int free_slot = -1;
  for (uint32_t i = 0; i < cap; i++) {
    Timer &t = g_vm.timers[i];
    if (t.active && t.id == id) {
      free_slot = (int)i; // 同一 id は張り替え
      break;
    }
    if (!t.active && free_slot < 0) {
      free_slot = (int)i;
    }
  }
  if (free_slot < 0) {
    return SCRIPT_ERR_NOSPACE;
  }
  Timer &t = g_vm.timers[free_slot];
  t.active = true;
  t.periodic = periodic;
  t.id = id;
  t.period_ms = (uint32_t)ms;
  t.due_ms = g_vm.now_ms + (uint64_t)ms;
  return SCRIPT_OK;
}

int32_t ni_timer_after(wasm_exec_env_t, int32_t ms, int32_t id) { return timer_set(ms, id, false); }
int32_t ni_timer_every(wasm_exec_env_t, int32_t ms, int32_t id) { return timer_set(ms, id, true); }

int32_t ni_timer_cancel(wasm_exec_env_t, int32_t id) {
  int32_t n = 0;
  for (size_t i = 0; i < kScriptMaxTimers; i++) {
    if (g_vm.timers[i].active && g_vm.timers[i].id == id) {
      g_vm.timers[i].active = false;
      n++;
    }
  }
  return n > 0 ? SCRIPT_OK : SCRIPT_ERR_NOTFOUND;
}

void ni_log(wasm_exec_env_t, int32_t ptr, int32_t len) {
  if (g_vm.ops.log == nullptr || len < 0) {
    return;
  }
  const char *p = (const char *)app_ptr((uint32_t)ptr, (uint32_t)len);
  if (p == nullptr) {
    return;
  }
  g_vm.ops.log(g_vm.ops.user, p, (uint32_t)len);
}

int32_t ni_kvs_get(wasm_exec_env_t, int32_t key_ptr, int32_t key_len, int32_t out_ptr,
                   int32_t cap) {
  if (g_vm.ops.kvs_get == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  if (key_len <= 0 || cap < 0) {
    return SCRIPT_ERR_ARG;
  }
  const char *k = (const char *)app_ptr((uint32_t)key_ptr, (uint32_t)key_len);
  uint8_t *o = (uint8_t *)app_ptr((uint32_t)out_ptr, (uint32_t)cap);
  if (k == nullptr || o == nullptr) {
    return SCRIPT_ERR_ARG;
  }
  return g_vm.ops.kvs_get(g_vm.ops.user, k, (uint32_t)key_len, o, (uint32_t)cap);
}

int32_t ni_kvs_set(wasm_exec_env_t, int32_t key_ptr, int32_t key_len, int32_t val_ptr,
                   int32_t val_len) {
  if (g_vm.ops.kvs_set == nullptr) {
    return SCRIPT_ERR_UNSUPPORTED;
  }
  if (key_len <= 0 || val_len < 0) {
    return SCRIPT_ERR_ARG;
  }
  const char *k = (const char *)app_ptr((uint32_t)key_ptr, (uint32_t)key_len);
  const uint8_t *v = (const uint8_t *)app_ptr((uint32_t)val_ptr, (uint32_t)val_len);
  if (k == nullptr || v == nullptr) {
    return SCRIPT_ERR_ARG;
  }
  return g_vm.ops.kvs_set(g_vm.ops.user, k, (uint32_t)key_len, v, (uint32_t)val_len);
}

// WAMR のシグネチャ文字列は "(引数)戻り値"、i = i32。ポインタも i32 として受け、
// 上の関数内で範囲検証する(*~ を使わないのは cap/len の意味付けを自前で持つため)。
NativeSymbol g_natives[] = {
    {"attr_get", (void *)ni_attr_get, "(iiiii)i", nullptr},
    {"attr_set", (void *)ni_attr_set, "(iiiii)i", nullptr},
    {"gpio_write", (void *)ni_gpio_write, "(ii)i", nullptr},
    {"gpio_read", (void *)ni_gpio_read, "(i)i", nullptr},
    {"pwm_set", (void *)ni_pwm_set, "(ii)i", nullptr},
    {"timer_after", (void *)ni_timer_after, "(ii)i", nullptr},
    {"timer_every", (void *)ni_timer_every, "(ii)i", nullptr},
    {"timer_cancel", (void *)ni_timer_cancel, "(i)i", nullptr},
    {"log", (void *)ni_log, "(ii)", nullptr},
    {"kvs_get", (void *)ni_kvs_get, "(iiii)i", nullptr},
    {"kvs_set", (void *)ni_kvs_set, "(iiii)i", nullptr},
};

// ---- フック呼び出し ----------------------------------------------------------

// export を引いて argc 引数で呼ぶ。戻り値がある場合は argv[0] に入る。
// 戻り値 true = 正常終了(argv[0] 有効)、false = 未 export / trap。
bool call_hook(const char *name, uint32_t argc, uint32_t *argv) {
  if (g_vm.inst == nullptr || g_vm.env == nullptr || g_vm.in_hook) {
    return false;
  }
  wasm_function_inst_t fn = wasm_runtime_lookup_function(g_vm.inst, name);
  if (fn == nullptr) {
    return false; // optional フック = 未実装
  }
  g_vm.in_hook = true;
  g_vm.stats.calls++;
  if (g_vm.ops.watchdog_arm != nullptr && g_vm.cfg.hook_budget_ms > 0) {
    g_vm.ops.watchdog_arm(g_vm.ops.user, g_vm.cfg.hook_budget_ms);
  }
  const bool ok = wasm_runtime_call_wasm(g_vm.env, fn, argc, argv);
  if (g_vm.ops.watchdog_disarm != nullptr) {
    g_vm.ops.watchdog_disarm(g_vm.ops.user);
  }
  g_vm.in_hook = false;
  if (!ok) {
    const char *ex = wasm_runtime_get_exception(g_vm.inst);
    snprintf(g_vm.last_error, sizeof(g_vm.last_error), "%s: %s", name, ex ? ex : "trap");
    g_vm.stats.traps++;
    // 例外を残すと以降の呼び出しが全て失敗するのでクリアして次のフックに備える
    // (スクリプトの状態は壊れている可能性があるが、Matter 本体は動かし続ける)。
    wasm_runtime_clear_exception(g_vm.inst);
    return false;
  }
  return true;
}

} // namespace

// ---- 公開 API ---------------------------------------------------------------

bool script_vm_start(const uint8_t *wasm, size_t len, const ScriptVmConfig &cfg,
                     const ScriptHostOps &ops, char *err, size_t err_cap) {
  auto fail = [&](const char *msg) {
    if (err != nullptr && err_cap > 0) {
      snprintf(err, err_cap, "%s", msg);
    }
    script_vm_stop();
    return false;
  };

  script_vm_stop();
  if (wasm == nullptr || len == 0) {
    return fail("no script");
  }
  if (cfg.heap_pool == nullptr || cfg.heap_pool_size == 0) {
    return fail("no heap pool");
  }

  g_vm.cfg = cfg;
  g_vm.ops = ops;
  g_vm.last_error[0] = '\0';

  RuntimeInitArgs init;
  memset(&init, 0, sizeof(init));
  init.mem_alloc_type = Alloc_With_Pool;
  init.mem_alloc_option.pool.heap_buf = cfg.heap_pool;
  init.mem_alloc_option.pool.heap_size = cfg.heap_pool_size;
  init.native_module_name = kScriptModuleName;
  init.native_symbols = g_natives;
  init.n_native_symbols = (uint32_t)(sizeof(g_natives) / sizeof(g_natives[0]));
  init.max_thread_num = 1;
  if (!wasm_runtime_full_init(&init)) {
    return fail("wasm_runtime_full_init failed");
  }
  g_vm.inited = true;

  // WAMR のローダはバイトコードバッファを保持し、書き換えもする(labels-as-values の
  // opcode 置換)。フラッシュ上の読み取り専用領域を直接渡せないので、プールへ複製する。
  g_vm.code = (uint8_t *)wasm_runtime_malloc((uint32_t)len);
  if (g_vm.code == nullptr) {
    return fail("pool too small for script bytes");
  }
  memcpy(g_vm.code, wasm, len);

  char buf[128] = {0};
  g_vm.module = wasm_runtime_load(g_vm.code, (uint32_t)len, buf, sizeof(buf));
  if (g_vm.module == nullptr) {
    return fail(buf[0] ? buf : "load failed");
  }
  g_vm.inst = wasm_runtime_instantiate(g_vm.module, cfg.stack_size, cfg.app_heap_size, buf,
                                       sizeof(buf));
  if (g_vm.inst == nullptr) {
    return fail(buf[0] ? buf : "instantiate failed");
  }
  g_vm.env = wasm_runtime_create_exec_env(g_vm.inst, cfg.stack_size);
  if (g_vm.env == nullptr) {
    return fail("create_exec_env failed");
  }
  for (size_t i = 0; i < kScriptMaxTimers; i++) {
    g_vm.timers[i] = Timer{};
  }
  g_vm.stats = ScriptVmStats{};
  return true;
}

void script_vm_stop() {
  if (g_vm.env != nullptr) {
    wasm_runtime_destroy_exec_env(g_vm.env);
    g_vm.env = nullptr;
  }
  if (g_vm.inst != nullptr) {
    wasm_runtime_deinstantiate(g_vm.inst);
    g_vm.inst = nullptr;
  }
  if (g_vm.module != nullptr) {
    wasm_runtime_unload(g_vm.module);
    g_vm.module = nullptr;
  }
  if (g_vm.code != nullptr) {
    wasm_runtime_free(g_vm.code);
    g_vm.code = nullptr;
  }
  if (g_vm.inited) {
    wasm_runtime_destroy();
    g_vm.inited = false;
  }
  for (size_t i = 0; i < kScriptMaxTimers; i++) {
    g_vm.timers[i] = Timer{};
  }
  g_vm.in_hook = false;
}

bool script_vm_active() { return g_vm.inst != nullptr; }

void script_vm_terminate() {
  if (g_vm.inst != nullptr) {
    g_vm.stats.timeouts++;
    wasm_runtime_terminate(g_vm.inst);
  }
}

void script_on_boot() {
  uint32_t argv[1] = {0};
  call_hook(kHookOnBoot, 0, argv);
}

int32_t script_on_attr_write(int32_t ep, int32_t cluster, int32_t attr) {
  uint32_t argv[3] = {(uint32_t)ep, (uint32_t)cluster, (uint32_t)attr};
  if (!call_hook(kHookOnAttrWrite, 3, argv)) {
    return 0; // 未実装 / trap = 承認扱い
  }
  return (int32_t)argv[0];
}

int32_t script_on_command(int32_t ep, int32_t cluster, int32_t cmd) {
  uint32_t argv[3] = {(uint32_t)ep, (uint32_t)cluster, (uint32_t)cmd};
  if (!call_hook(kHookOnCommand, 3, argv)) {
    return 0;
  }
  return (int32_t)argv[0];
}

void script_on_sensor(int32_t bind) {
  uint32_t argv[1] = {(uint32_t)bind};
  call_hook(kHookOnSensor, 1, argv);
}

void script_on_timer(int32_t id) {
  uint32_t argv[1] = {(uint32_t)id};
  call_hook(kHookOnTimer, 1, argv);
}

void script_vm_poll(uint64_t now_ms) {
  g_vm.now_ms = now_ms;
  if (g_vm.inst == nullptr || g_vm.in_hook) {
    return;
  }
  for (size_t i = 0; i < kScriptMaxTimers; i++) {
    Timer &t = g_vm.timers[i];
    if (!t.active || now_ms < t.due_ms) {
      continue;
    }
    const int32_t id = t.id;
    if (t.periodic) {
      t.due_ms = now_ms + (t.period_ms ? t.period_ms : 1);
    } else {
      t.active = false;
    }
    script_on_timer(id);
  }
}

const ScriptVmStats &script_vm_stats() { return g_vm.stats; }

const char *script_vm_last_error() { return g_vm.last_error; }

} // namespace smgen
