// momentary-toggle(AssemblyScript 版のサンプル)。
//
// Rust 版(crates/sm-script-api/examples-wasm/momentary-toggle)と**同一 ABI・同一動作**の
// スクリプト。Phase E(Web Configurator)でブラウザ内 asc コンパイルに載せる想定で、
// このリポジトリでは**コンパイルしない**(宣言とサンプルのみ。docs §9.3)。
//
// コンパイル(参考。asc は Phase E で vendor する):
//
//   asc momentary-toggle.ts -o momentary-toggle.wasm \
//       --optimize --runtime stub --exportRuntime false --use abort=
//
// 注意:
//   - `--runtime stub` で GC/アロケータを最小化する(線形メモリ 64KB 前提)。
//   - ホスト import は module 名 `"sm"`(@external の第 1 引数)。
//   - フックは `export function` で出す。未 export のフックは「未実装」扱いになる。

// ---- ホスト import(module "sm")---------------------------------------------

@external("sm", "attr_get")
declare function attr_get(ep: i32, cluster: i32, attr: i32, out: usize, cap: i32): i32;
@external("sm", "attr_set")
declare function attr_set(ep: i32, cluster: i32, attr: i32, val: usize, len: i32): i32;
@external("sm", "timer_after")
declare function timer_after(ms: i32, id: i32): i32;
@external("sm", "timer_cancel")
declare function timer_cancel(id: i32): i32;
@external("sm", "log")
declare function log_raw(ptr: usize, len: i32): void;
@external("sm", "kvs_get")
declare function kvs_get(key: usize, key_len: i32, out: usize, cap: i32): i32;
@external("sm", "kvs_set")
declare function kvs_set(key: usize, key_len: i32, val: usize, len: i32): i32;

// ---- 値の 16B レコード -------------------------------------------------------
//
// レイアウトは web/sdk/sm.d.ts と main/script_abi.hpp を参照。
// AssemblyScript では線形メモリを直接組み立てる(固定アドレスの作業領域を使う)。

const VALUE_SIZE: i32 = 16;
const TYPE_BOOL: u8 = 0;

// 作業領域(--runtime stub なので低位アドレスを自前で使い分ける)。
const SCRATCH: usize = 1024;
const KEYBUF: usize = 1100;
const LOGBUF: usize = 1200;

function encodeBool(ptr: usize, v: bool): void {
  memory.fill(ptr, 0, VALUE_SIZE);
  store<u8>(ptr, TYPE_BOOL);
  store<u64>(ptr + 8, v ? 1 : 0);
}

function decodeBool(ptr: usize): bool {
  return (load<u64>(ptr + 8) & 1) != 0;
}

function logStr(s: string): void {
  const buf = String.UTF8.encode(s);
  const len = buf.byteLength;
  memory.copy(LOGBUF, changetype<usize>(buf), len);
  log_raw(LOGBUF, len);
}

function attrGetBool(ep: i32, cluster: i32, attr: i32): i32 {
  const rc = attr_get(ep, cluster, attr, SCRATCH, VALUE_SIZE);
  if (rc < 0) return -1;
  return decodeBool(SCRATCH) ? 1 : 0;
}

function attrSetBool(ep: i32, cluster: i32, attr: i32, v: bool): void {
  encodeBool(SCRATCH, v);
  attr_set(ep, cluster, attr, SCRATCH, VALUE_SIZE);
}

// ---- スクリプト本体 ----------------------------------------------------------

const EP: i32 = 1;
const CL_ON_OFF: i32 = 0x0006;
const CL_BOOLEAN_STATE: i32 = 0x0045;
const ATTR_VALUE: i32 = 0x0000;
const TIMER_LONG_PRESS: i32 = 1;
const LONG_PRESS_MS: i32 = 1000;

let pressed: bool = false;
let count: u32 = 0;

export function on_boot(): void {
  store<u8>(KEYBUF, 0x63); // 'c'
  store<u8>(KEYBUF + 1, 0x6e); // 'n'
  store<u8>(KEYBUF + 2, 0x74); // 't'
  const n = kvs_get(KEYBUF, 3, SCRATCH, 4);
  count = n == 4 ? load<u32>(SCRATCH) : 0;
  const s = attrGetBool(EP, CL_BOOLEAN_STATE, ATTR_VALUE);
  pressed = s == 1;
  logStr("momentary-toggle ready (AS)");
}

export function on_sensor(bind: i32): void {
  const s = attrGetBool(EP, CL_BOOLEAN_STATE, ATTR_VALUE);
  if (s < 0) return;
  const now = s == 1;
  if (now == pressed) return;
  pressed = now;
  if (now) {
    const on = attrGetBool(EP, CL_ON_OFF, ATTR_VALUE) == 1;
    attrSetBool(EP, CL_ON_OFF, ATTR_VALUE, !on);
    count += 1;
    store<u32>(SCRATCH, count);
    kvs_set(KEYBUF, 3, SCRATCH, 4);
    timer_after(LONG_PRESS_MS, TIMER_LONG_PRESS);
    logStr(on ? "press: on -> off" : "press: off -> on");
  } else {
    timer_cancel(TIMER_LONG_PRESS);
  }
}

export function on_timer(id: i32): void {
  if (id == TIMER_LONG_PRESS && pressed) {
    attrSetBool(EP, CL_ON_OFF, ATTR_VALUE, false);
    logStr("long press: forced off");
  }
}

export function on_attr_write(ep: i32, cluster: i32, attr: i32): i32 {
  if (cluster == CL_ON_OFF) logStr("on_off changed by controller");
  return 0; // 承認(非 0 は現状「観測のみ」)
}
