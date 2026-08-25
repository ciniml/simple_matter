// simple-matter 汎用ファームウェア: WASM スクリプトの型宣言(AssemblyScript / TypeScript)。
//
// docs/design/generic-firmware.md §9.3。Phase E(Web Configurator)のブラウザ内
// AssemblyScript コンパイル(asc)で `--use` せずに import 宣言として読み込む想定。
// **このファイルはコンパイルしない**(宣言のみ)。実装は crates/sm-script-api(Rust)と
// 同一 ABI。
//
// 使い方(AssemblyScript):
//
//   import { attr_get, attr_set, log } from "./sm";
//   export function on_sensor(bind: i32): void { ... }
//
// asc では `declare module "sm"` ではなく、`env` 以外の import module 名を
// `--use` / `@external("sm", "attr_get")` で指定する。sm.ts(サンプル)を参照。

/** ホスト関数の戻り値(負値 = エラー)。 */
export declare const enum SmRc {
  /** 引数不正(ポインタが線形メモリ外、長さ不正)。 */
  Arg = -1,
  /** 対象(クラスタ / キー)が無い。 */
  NotFound = -2,
  /** 未対応(属性が非公開、ホスト機能が無い)。 */
  Unsupported = -3,
  /** 型不一致。 */
  Type = -4,
  /** 出力バッファ不足。 */
  NoSpace = -5,
  /** ハードウェア操作失敗。 */
  Hw = -6,
}

/** 値の型タグ(16B レコードの offset 0)。 */
export declare const enum SmValType {
  Bool = 0,
  U8 = 1,
  U16 = 2,
  U32 = 3,
  U64 = 4,
  I8 = 5,
  I16 = 6,
  I32 = 7,
  I64 = 8,
  F32 = 9,
  String = 10,
  Octets = 11,
}

// ---- 値の 16B 固定バイナリ表現 ----------------------------------------------
//
//   offset size 内容
//   0      1    type   SmValType
//   1      1    flags  bit0 = is_null
//   2      2    len    STRING/OCTETS の後続バイト数(u16 LE。スカラは 0)
//   4      4    予約   0
//   8      8    val    u64 LE(BOOL 0/1 / U* ゼロ拡張 / I* 符号拡張 / F32 は下位 32bit)
//
// スカラはちょうど 16 バイト、文字列/オクテット列は 16 + len バイト。

/** 16B 固定部のサイズ。 */
export declare const SM_VALUE_SIZE: i32;

// ---- ホスト import(WASM module 名 "sm")-------------------------------------

/**
 * 属性を読む。`out` に 16B レコード(+ 本体)を書き、**書いた全長**を返す。
 * 負値は {@link SmRc}。
 */
export declare function attr_get(
  ep: i32,
  cluster: i32,
  attr: i32,
  out: usize,
  cap: i32
): i32;

/** 属性を書く。`val` は 16B レコード(+ 本体)。0 = OK、負値は {@link SmRc}。 */
export declare function attr_set(
  ep: i32,
  cluster: i32,
  attr: i32,
  val: usize,
  len: i32
): i32;

/** GPIO 出力(value != 0 で High)。 */
export declare function gpio_write(pin: i32, value: i32): i32;

/** GPIO 入力(0/1、負値はエラー)。 */
export declare function gpio_read(pin: i32): i32;

/** LEDC チャネルの duty(0..1023)。チャネルは binding TLV で設定済みであること。 */
export declare function pwm_set(ch: i32, duty: i32): i32;

/** `ms` 後に 1 回 `on_timer(id)` を呼ぶ。 */
export declare function timer_after(ms: i32, id: i32): i32;

/** `ms` ごとに `on_timer(id)` を呼ぶ。 */
export declare function timer_every(ms: i32, id: i32): i32;

/** タイマを取り消す(0 = OK、-2 = そんな id は無い)。 */
export declare function timer_cancel(id: i32): i32;

/** ログ出力(UTF-8 バイト列)。 */
export declare function log(ptr: usize, len: i32): void;

/** スクリプト用 KVS(NVS namespace `smscr`)から読む。書いた長さ、または実長を返す。 */
export declare function kvs_get(
  key: usize,
  key_len: i32,
  out: usize,
  cap: i32
): i32;

/** スクリプト用 KVS へ書く(0 = OK)。 */
export declare function kvs_set(
  key: usize,
  key_len: i32,
  val: usize,
  len: i32
): i32;

// ---- フック(スクリプト側が export する。いずれも optional)-------------------

/** VM ロード直後に 1 回。 */
export declare function on_boot(): void;
/** {@link timer_after} / {@link timer_every} の満了。 */
export declare function on_timer(id: i32): void;
/** IM write / コマンド由来の属性変化。0 = 承認(非 0 は現状**観測のみ**)。 */
export declare function on_attr_write(ep: i32, cluster: i32, attr: i32): i32;
/** コマンド受信。0 = 承認(発火元は Phase D)。 */
export declare function on_command(ep: i32, cluster: i32, cmd: i32): i32;
/** 入力/センサ binding の更新、`script` binding の周期発火。 */
export declare function on_sensor(bind: i32): void;
