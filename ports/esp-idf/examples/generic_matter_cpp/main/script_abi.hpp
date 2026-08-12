// スクリプト(WASM)⇔ ホストの ABI 定義。docs/design/generic-firmware.md §9.3。
//
// **ESP-IDF 非依存のヘッダオンリー**にしてある(ホスト検証ハーネス tools/wasm-harness と
// ファームで同一定義を使うため)。
//
// ---- 値の 16B 固定バイナリ表現(`sm_attr_value_t` のワイヤ形式)------------------
//
//   offset size  内容
//   0      1     type   sm_attr_type_t(0=BOOL 1=U8 2=U16 3=U32 4=U64 5=I8 6=I16
//                       7=I32 8=I64 9=F32 10=STRING 11=OCTETS)
//   1      1     flags  bit0 = is_null(NULLABLE 属性のみ意味を持つ)。他は 0。
//   2      2     len    STRING/OCTETS の**続くバイト数**(u16 LE)。スカラは 0。
//   4      4     予約   0(8B 境界揃え)
//   8      8     val    u64 LE。
//                        BOOL      0/1
//                        U8..U64   ゼロ拡張した値
//                        I8..I64   符号拡張した値の 2 の補数表現
//                        F32       IEEE754 の 32bit パターンを下位 32bit に格納
//                        STRING/OCTETS 0(本体は 16B の直後に len バイト続く)
//
// つまり **スカラは常にちょうど 16 バイト**、STRING/OCTETS は 16+len バイト。
// `attr_get(.., out_ptr, cap)` は書き込んだ全長を返すので、cap は 16(スカラ)/
// 16+len(バイト列)以上が必要。
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace smgen {

// 値レコードの固定部サイズ。
static constexpr size_t kScriptValueSize = 16;

// 型タグ(simple_matter.h の sm_attr_type_t と同じ並び。シムに依存しないよう再掲)。
enum ScriptValType : uint8_t {
  SV_BOOL = 0,
  SV_U8 = 1,
  SV_U16 = 2,
  SV_U32 = 3,
  SV_U64 = 4,
  SV_I8 = 5,
  SV_I16 = 6,
  SV_I32 = 7,
  SV_I64 = 8,
  SV_F32 = 9,
  SV_STRING = 10,
  SV_OCTETS = 11,
};

// 16B 固定部のデコード済み表現。
struct ScriptValue {
  uint8_t type = SV_BOOL;
  bool is_null = false;
  uint16_t len = 0; // STRING/OCTETS の追従バイト数
  uint64_t bits = 0;
};

// 16B 固定部を書く(呼び出し側が cap >= 16 を保証すること)。
inline void script_value_encode(uint8_t *out, const ScriptValue &v) {
  memset(out, 0, kScriptValueSize);
  out[0] = v.type;
  out[1] = v.is_null ? 1 : 0;
  out[2] = (uint8_t)(v.len & 0xFF);
  out[3] = (uint8_t)(v.len >> 8);
  for (int i = 0; i < 8; i++) {
    out[8 + i] = (uint8_t)((v.bits >> (8 * i)) & 0xFF);
  }
}

// 16B 固定部を読む(len < 16 なら false)。
inline bool script_value_decode(const uint8_t *in, size_t len, ScriptValue &out) {
  if (in == nullptr || len < kScriptValueSize) {
    return false;
  }
  out.type = in[0];
  out.is_null = (in[1] & 1) != 0;
  out.len = (uint16_t)((uint16_t)in[2] | ((uint16_t)in[3] << 8));
  out.bits = 0;
  for (int i = 0; i < 8; i++) {
    out.bits |= (uint64_t)in[8 + i] << (8 * i);
  }
  return true;
}

// ---- フック名(WASM export。いずれも optional)-------------------------------
//
//   on_boot()                                     VM ロード直後に 1 回
//   on_timer(id: i32)                             timer_after / timer_every の満了
//   on_attr_write(ep, cluster, attr) -> i32       IM write / コマンド由来の属性変化
//                                                 (0 = 承認。**非 0 は観測のみ**: 現行
//                                                  シム API に拒否の口が無い。README 参照)
//   on_command(ep, cluster, cmd) -> i32           コマンド受信(発火元は Phase D)
//   on_sensor(bind: i32)                          センサ/入力バインディングの更新
static constexpr const char *kHookOnBoot = "on_boot";
static constexpr const char *kHookOnTimer = "on_timer";
static constexpr const char *kHookOnAttrWrite = "on_attr_write";
static constexpr const char *kHookOnCommand = "on_command";
static constexpr const char *kHookOnSensor = "on_sensor";

// ---- ホスト import(WASM module 名 "sm")-------------------------------------
//
//   attr_get(ep,cluster,attr, out_ptr, cap) -> i32   >=0 = 書いた全長、<0 = エラー
//   attr_set(ep,cluster,attr, ptr, len)     -> i32   0 = OK、<0 = エラー
//   gpio_write(pin, value)                  -> i32
//   gpio_read(pin)                          -> i32   0/1、<0 = エラー
//   pwm_set(ch, duty)                       -> i32   duty は 0..1023(10bit)
//   timer_after(ms, id)                     -> i32   ワンショット
//   timer_every(ms, id)                     -> i32   周期
//   timer_cancel(id)                        -> i32
//   log(ptr, len)                           -> void
//   kvs_get(key_ptr,key_len, out_ptr, cap)  -> i32   >=0 = 実長、<0 = 無し/エラー
//   kvs_set(key_ptr,key_len, ptr, len)      -> i32   0 = OK
static constexpr const char *kScriptModuleName = "sm";

// ホスト関数の戻り値(負値)。
enum ScriptRc : int32_t {
  SCRIPT_OK = 0,
  SCRIPT_ERR_ARG = -1,      // ポインタ/長さが線形メモリ外、引数不正
  SCRIPT_ERR_NOTFOUND = -2, // 対象クラスタ/キーが無い
  SCRIPT_ERR_UNSUPPORTED = -3,
  SCRIPT_ERR_TYPE = -4,   // 型不一致
  SCRIPT_ERR_NOSPACE = -5, // 出力バッファ不足
  SCRIPT_ERR_HW = -6,     // ハードウェア操作失敗
};

} // namespace smgen
