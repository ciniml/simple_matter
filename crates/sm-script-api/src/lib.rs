//! simple-matter 汎用ファームウェア(`generic_matter_cpp`)の WASM スクリプト SDK。
//!
//! 仕様は `docs/design/generic-firmware.md` §9.3。デバイス側 VM は WAMR(interp)で、
//! スクリプトは **module `"sm"` の import** を通してのみ外界に触れる(能力ベース)。
//!
//! # フック(export、いずれも optional)
//!
//! | export | 発火元 | 戻り値 |
//! |---|---|---|
//! | `on_boot()` | VM ロード直後に 1 回 | — |
//! | `on_timer(id: i32)` | [`timer_after`] / [`timer_every`] の満了 | — |
//! | `on_attr_write(ep, cluster, attr) -> i32` | IM write / コマンド由来の属性変化 | 0 = 承認(非 0 は**観測のみ**) |
//! | `on_command(ep, cluster, cmd) -> i32` | コマンド受信(発火元は Phase D) | 0 = 承認 |
//! | `on_sensor(bind: i32)` | 入力/センサ binding の更新、`script` binding の周期 | — |
//!
//! [`sm_script!`] マクロで宣言するか、素の `#[no_mangle] pub extern "C" fn` で書く。
//!
//! # 値の 16B 表現
//!
//! 属性値は 16 バイト固定のレコード(+ 文字列/オクテット列は本体が後続)でやり取りする。
//! レイアウトは [`Value::encode_into`] のドキュメントと `main/script_abi.hpp` を参照。
//!
//! # ビルド
//!
//! ```sh
//! cargo build --release --target wasm32-unknown-unknown
//! ```
//!
//! `Cargo.toml` の profile は `opt-level = "z"` / `panic = "abort"` / `lto = true` /
//! `strip = true`(examples-wasm/momentary-toggle が実例)。
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

// ---- ホスト import(module "sm")---------------------------------------------

/// wasm32 では実 import、それ以外(ホストのテスト/clippy)は「未対応」を返すスタブ。
#[cfg(target_arch = "wasm32")]
mod sys {
    #[link(wasm_import_module = "sm")]
    extern "C" {
        pub fn attr_get(ep: i32, cluster: i32, attr: i32, out: *mut u8, cap: i32) -> i32;
        pub fn attr_set(ep: i32, cluster: i32, attr: i32, val: *const u8, len: i32) -> i32;
        pub fn gpio_write(pin: i32, value: i32) -> i32;
        pub fn gpio_read(pin: i32) -> i32;
        pub fn pwm_set(ch: i32, duty: i32) -> i32;
        pub fn timer_after(ms: i32, id: i32) -> i32;
        pub fn timer_every(ms: i32, id: i32) -> i32;
        pub fn timer_cancel(id: i32) -> i32;
        pub fn log(ptr: *const u8, len: i32);
        pub fn kvs_get(key: *const u8, key_len: i32, out: *mut u8, cap: i32) -> i32;
        pub fn kvs_set(key: *const u8, key_len: i32, val: *const u8, len: i32) -> i32;
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::missing_safety_doc)]
mod sys {
    use super::rc;
    /// # Safety
    /// ホスト向けスタブ。ポインタには触れない。
    pub unsafe fn attr_get(_: i32, _: i32, _: i32, _: *mut u8, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn attr_set(_: i32, _: i32, _: i32, _: *const u8, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn gpio_write(_: i32, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn gpio_read(_: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn pwm_set(_: i32, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn timer_after(_: i32, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn timer_every(_: i32, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn timer_cancel(_: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn log(_: *const u8, _: i32) {}
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn kvs_get(_: *const u8, _: i32, _: *mut u8, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
    /// # Safety
    /// ホスト向けスタブ。
    pub unsafe fn kvs_set(_: *const u8, _: i32, _: *const u8, _: i32) -> i32 {
        rc::UNSUPPORTED
    }
}

/// ホスト関数の戻り値(負値 = エラー)。
pub mod rc {
    /// 引数不正(ポインタが線形メモリ外、長さ不正)。
    pub const ARG: i32 = -1;
    /// 対象(クラスタ / キー)が無い。
    pub const NOTFOUND: i32 = -2;
    /// 未対応(属性が非公開、ホスト機能が無い)。
    pub const UNSUPPORTED: i32 = -3;
    /// 型不一致。
    pub const TYPE: i32 = -4;
    /// 出力バッファ不足。
    pub const NOSPACE: i32 = -5;
    /// ハードウェア操作失敗。
    pub const HW: i32 = -6;
}

/// よく使う Matter クラスタ ID。
pub mod cluster {
    /// Identify。
    pub const IDENTIFY: i32 = 0x0003;
    /// Groups。
    pub const GROUPS: i32 = 0x0004;
    /// On/Off。
    pub const ON_OFF: i32 = 0x0006;
    /// Level Control。
    pub const LEVEL_CONTROL: i32 = 0x0008;
    /// Color Control。
    pub const COLOR_CONTROL: i32 = 0x0300;
    /// Switch。
    pub const SWITCH: i32 = 0x003B;
    /// Boolean State。
    pub const BOOLEAN_STATE: i32 = 0x0045;
    /// Occupancy Sensing。
    pub const OCCUPANCY: i32 = 0x0406;
    /// Temperature Measurement。
    pub const TEMPERATURE: i32 = 0x0402;
    /// Relative Humidity Measurement。
    pub const HUMIDITY: i32 = 0x0405;
    /// Illuminance Measurement。
    pub const ILLUMINANCE: i32 = 0x0400;
}

/// よく使う属性 ID。
pub mod attr {
    /// OnOff / BooleanState StateValue / 各計測クラスタの MeasuredValue。
    pub const VALUE: i32 = 0x0000;
    /// LevelControl CurrentLevel。
    pub const CURRENT_LEVEL: i32 = 0x0000;
    /// Switch CurrentPosition。
    pub const CURRENT_POSITION: i32 = 0x0001;
}

// ---- 値表現 ------------------------------------------------------------------

/// 値の型タグ(`sm_attr_type_t` と同じ並び)。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ValType {
    /// bool。
    Bool = 0,
    /// u8。
    U8 = 1,
    /// u16。
    U16 = 2,
    /// u32。
    U32 = 3,
    /// u64。
    U64 = 4,
    /// i8。
    I8 = 5,
    /// i16。
    I16 = 6,
    /// i32。
    I32 = 7,
    /// i64。
    I64 = 8,
    /// f32。
    F32 = 9,
    /// UTF-8 文字列。
    String = 10,
    /// オクテット列。
    Octets = 11,
}

impl ValType {
    /// タグ値から型を復元する。
    pub fn from_u8(v: u8) -> Option<ValType> {
        Some(match v {
            0 => ValType::Bool,
            1 => ValType::U8,
            2 => ValType::U16,
            3 => ValType::U32,
            4 => ValType::U64,
            5 => ValType::I8,
            6 => ValType::I16,
            7 => ValType::I32,
            8 => ValType::I64,
            9 => ValType::F32,
            10 => ValType::String,
            11 => ValType::Octets,
            _ => return None,
        })
    }
}

/// 16B 固定部のサイズ。
pub const VALUE_SIZE: usize = 16;

/// 属性値。
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Value<'a> {
    /// bool。
    Bool(bool),
    /// 符号なし整数(型タグ付き)。
    Uint(ValType, u64),
    /// 符号付き整数(型タグ付き)。
    Int(ValType, i64),
    /// f32。
    F32(f32),
    /// UTF-8 文字列。
    Str(&'a [u8]),
    /// オクテット列。
    Octets(&'a [u8]),
    /// null(NULLABLE 属性)。型タグを保つ。
    Null(ValType),
}

impl<'a> Value<'a> {
    /// u8 値(型タグ `U8`)。
    pub fn u8(v: u8) -> Self {
        Value::Uint(ValType::U8, v as u64)
    }
    /// u16 値。
    pub fn u16(v: u16) -> Self {
        Value::Uint(ValType::U16, v as u64)
    }
    /// i16 値。
    pub fn i16(v: i16) -> Self {
        Value::Int(ValType::I16, v as i64)
    }

    /// 型タグ。
    pub fn val_type(&self) -> ValType {
        match self {
            Value::Bool(_) => ValType::Bool,
            Value::Uint(t, _) | Value::Int(t, _) | Value::Null(t) => *t,
            Value::F32(_) => ValType::F32,
            Value::Str(_) => ValType::String,
            Value::Octets(_) => ValType::Octets,
        }
    }

    /// 整数として読む(bool は 0/1、null は `None`)。
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Bool(b) => Some(*b as i64),
            Value::Uint(_, u) => Some(*u as i64),
            Value::Int(_, i) => Some(*i),
            _ => None,
        }
    }

    /// bool として読む(整数は != 0)。
    pub fn as_bool(&self) -> Option<bool> {
        self.as_i64().map(|v| v != 0)
    }

    /// 16B 固定部(+ 文字列/オクテット列本体)を `out` に書き、書いた長さを返す。
    ///
    /// レイアウト(リトルエンディアン):
    ///
    /// ```text
    /// 0      1  type   ValType
    /// 1      1  flags  bit0 = is_null
    /// 2      2  len    STRING/OCTETS の後続バイト数(スカラは 0)
    /// 4      4  予約   0
    /// 8      8  val    BOOL 0/1 / U* ゼロ拡張 / I* 符号拡張 / F32 は下位 32bit にビット列
    /// ```
    pub fn encode_into(&self, out: &mut [u8]) -> Option<usize> {
        let (bytes, bits): (&[u8], u64) = match self {
            Value::Bool(b) => (&[], *b as u64),
            Value::Uint(_, u) => (&[], *u),
            Value::Int(_, i) => (&[], *i as u64),
            Value::F32(f) => (&[], f.to_bits() as u64),
            Value::Str(b) | Value::Octets(b) => (b, 0),
            Value::Null(_) => (&[], 0),
        };
        let total = VALUE_SIZE + bytes.len();
        if out.len() < total || bytes.len() > u16::MAX as usize {
            return None;
        }
        out[..VALUE_SIZE].fill(0);
        out[0] = self.val_type() as u8;
        out[1] = u8::from(matches!(self, Value::Null(_)));
        out[2..4].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        out[8..16].copy_from_slice(&bits.to_le_bytes());
        out[VALUE_SIZE..total].copy_from_slice(bytes);
        Some(total)
    }

    /// 16B 固定部(+ 本体)をデコードする。
    pub fn decode(buf: &'a [u8]) -> Option<Value<'a>> {
        if buf.len() < VALUE_SIZE {
            return None;
        }
        let ty = ValType::from_u8(buf[0])?;
        let is_null = buf[1] & 1 != 0;
        let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let bits = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        if is_null {
            return Some(Value::Null(ty));
        }
        Some(match ty {
            ValType::Bool => Value::Bool(bits & 1 != 0),
            ValType::U8 | ValType::U16 | ValType::U32 | ValType::U64 => Value::Uint(ty, bits),
            ValType::I8 | ValType::I16 | ValType::I32 | ValType::I64 => Value::Int(ty, bits as i64),
            ValType::F32 => Value::F32(f32::from_bits(bits as u32)),
            ValType::String | ValType::Octets => {
                let body = buf.get(VALUE_SIZE..VALUE_SIZE + len)?;
                if ty == ValType::String {
                    Value::Str(body)
                } else {
                    Value::Octets(body)
                }
            }
        })
    }
}

// ---- safe wrapper ------------------------------------------------------------

/// 属性を読む(スカラ専用)。文字列/オクテット列は [`attr_get_into`] を使う。
pub fn attr_get(ep: i32, cluster: i32, attr: i32) -> Result<Value<'static>, i32> {
    let mut buf = [0u8; VALUE_SIZE];
    let n = unsafe { sys::attr_get(ep, cluster, attr, buf.as_mut_ptr(), VALUE_SIZE as i32) };
    if n < 0 {
        return Err(n);
    }
    // スカラは 16B ちょうど。バイト列は cap 不足で NOSPACE になる。
    match Value::decode(&buf) {
        Some(Value::Str(_)) | Some(Value::Octets(_)) | None => Err(rc::TYPE),
        // スカラ型は借用を持たないので 'static へ格上げできる。
        Some(v) => Ok(match v {
            Value::Bool(b) => Value::Bool(b),
            Value::Uint(t, u) => Value::Uint(t, u),
            Value::Int(t, i) => Value::Int(t, i),
            Value::F32(f) => Value::F32(f),
            Value::Null(t) => Value::Null(t),
            _ => return Err(rc::TYPE),
        }),
    }
}

/// 属性を読んで生レコード(16B + 本体)を `buf` に書く。書いた長さを返す。
pub fn attr_get_into(ep: i32, cluster: i32, attr: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let n = unsafe { sys::attr_get(ep, cluster, attr, buf.as_mut_ptr(), buf.len() as i32) };
    if n < 0 {
        Err(n)
    } else {
        Ok(n as usize)
    }
}

/// 属性を書く。
pub fn attr_set(ep: i32, cluster: i32, attr: i32, value: &Value<'_>) -> Result<(), i32> {
    // 文字列/オクテット列も収まる作業バッファ(SDK の上限 = シムの STR_CAP 64B)。
    let mut buf = [0u8; VALUE_SIZE + 64];
    let n = value.encode_into(&mut buf).ok_or(rc::NOSPACE)?;
    let r = unsafe { sys::attr_set(ep, cluster, attr, buf.as_ptr(), n as i32) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// OnOff の現在値を読む(便宜関数)。
pub fn on_off_get(ep: i32) -> Result<bool, i32> {
    attr_get(ep, cluster::ON_OFF, attr::VALUE)?
        .as_bool()
        .ok_or(rc::TYPE)
}

/// OnOff を書く(便宜関数)。
pub fn on_off_set(ep: i32, on: bool) -> Result<(), i32> {
    attr_set(ep, cluster::ON_OFF, attr::VALUE, &Value::Bool(on))
}

/// GPIO 出力。
pub fn gpio_write(pin: i32, value: bool) -> Result<(), i32> {
    let r = unsafe { sys::gpio_write(pin, i32::from(value)) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// GPIO 入力。
pub fn gpio_read(pin: i32) -> Result<bool, i32> {
    let r = unsafe { sys::gpio_read(pin) };
    if r < 0 {
        Err(r)
    } else {
        Ok(r != 0)
    }
}

/// LEDC チャネルの duty(0..=1023)。チャネルは binding TLV で設定済みであること。
pub fn pwm_set(ch: i32, duty: i32) -> Result<(), i32> {
    let r = unsafe { sys::pwm_set(ch, duty) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// `ms` 後に 1 回 `on_timer(id)` を呼ぶ。
pub fn timer_after(ms: i32, id: i32) -> Result<(), i32> {
    let r = unsafe { sys::timer_after(ms, id) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// `ms` ごとに `on_timer(id)` を呼ぶ。
pub fn timer_every(ms: i32, id: i32) -> Result<(), i32> {
    let r = unsafe { sys::timer_every(ms, id) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// タイマを取り消す。
pub fn timer_cancel(id: i32) -> Result<(), i32> {
    let r = unsafe { sys::timer_cancel(id) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// ログ出力(デバイス側は `ESP_LOGI`)。
pub fn log(msg: &str) {
    unsafe { sys::log(msg.as_ptr(), msg.len() as i32) };
}

/// スクリプト用 KVS(NVS namespace `smscr`)から読む。書いた長さを返す。
pub fn kvs_get(key: &[u8], out: &mut [u8]) -> Result<usize, i32> {
    let r = unsafe {
        sys::kvs_get(
            key.as_ptr(),
            key.len() as i32,
            out.as_mut_ptr(),
            out.len() as i32,
        )
    };
    if r < 0 {
        Err(r)
    } else {
        Ok(r as usize)
    }
}

/// スクリプト用 KVS へ書く。
pub fn kvs_set(key: &[u8], val: &[u8]) -> Result<(), i32> {
    let r = unsafe {
        sys::kvs_set(
            key.as_ptr(),
            key.len() as i32,
            val.as_ptr(),
            val.len() as i32,
        )
    };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

// ---- フック宣言マクロ --------------------------------------------------------

/// フック(`on_boot` / `on_timer` / `on_attr_write` / `on_command` / `on_sensor`)を
/// `#[no_mangle] extern "C"` export として宣言する。
///
/// 書かなかったフックは export されない(= VM 側で「未実装」扱い)。
///
/// ```ignore
/// sm_script! {
///     boot: || sm_script_api::log("hello"),
///     sensor: |bind: i32| { let _ = bind; },
/// }
/// ```
#[macro_export]
macro_rules! sm_script {
    (@one boot: $f:expr) => {
        /// `on_boot` フック(VM ロード直後に 1 回)。
        #[no_mangle]
        pub extern "C" fn on_boot() {
            let f: fn() = $f;
            f()
        }
    };
    (@one timer: $f:expr) => {
        /// `on_timer` フック。
        #[no_mangle]
        pub extern "C" fn on_timer(id: i32) {
            let f: fn(i32) = $f;
            f(id)
        }
    };
    (@one sensor: $f:expr) => {
        /// `on_sensor` フック。
        #[no_mangle]
        pub extern "C" fn on_sensor(bind: i32) {
            let f: fn(i32) = $f;
            f(bind)
        }
    };
    (@one attr_write: $f:expr) => {
        /// `on_attr_write` フック(戻り値 0 = 承認)。
        #[no_mangle]
        pub extern "C" fn on_attr_write(ep: i32, cluster: i32, attr: i32) -> i32 {
            let f: fn(i32, i32, i32) -> i32 = $f;
            f(ep, cluster, attr)
        }
    };
    (@one command: $f:expr) => {
        /// `on_command` フック(戻り値 0 = 承認)。
        #[no_mangle]
        pub extern "C" fn on_command(ep: i32, cluster: i32, cmd: i32) -> i32 {
            let f: fn(i32, i32, i32) -> i32 = $f;
            f(ep, cluster, cmd)
        }
    };
    ($($name:ident : $f:expr),* $(,)?) => {
        $( $crate::sm_script!(@one $name: $f); )*
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_roundtrip_is_16_bytes() {
        let mut buf = [0u8; 32];
        for v in [
            Value::Bool(true),
            Value::u8(200),
            Value::u16(0xBEEF),
            Value::Uint(ValType::U64, u64::MAX),
            Value::i16(-4500),
            Value::Int(ValType::I64, i64::MIN),
            Value::F32(1.5),
            Value::Null(ValType::U16),
        ] {
            let n = v.encode_into(&mut buf).unwrap();
            assert_eq!(n, VALUE_SIZE, "{v:?}");
            assert_eq!(Value::decode(&buf[..n]).unwrap(), v);
        }
    }

    #[test]
    fn layout_matches_spec() {
        let mut buf = [0u8; 16];
        Value::i16(-1).encode_into(&mut buf).unwrap();
        assert_eq!(buf[0], ValType::I16 as u8);
        assert_eq!(buf[1], 0);
        assert_eq!(&buf[2..4], &[0, 0]);
        assert_eq!(&buf[4..8], &[0, 0, 0, 0]);
        assert_eq!(&buf[8..16], &[0xFF; 8]); // -1 を符号拡張した 2 の補数
    }

    #[test]
    fn bytes_follow_the_header() {
        let mut buf = [0u8; 32];
        let n = Value::Str(b"hi").encode_into(&mut buf).unwrap();
        assert_eq!(n, VALUE_SIZE + 2);
        assert_eq!(buf[0], ValType::String as u8);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 2);
        assert_eq!(&buf[16..18], b"hi");
        assert_eq!(Value::decode(&buf[..n]).unwrap(), Value::Str(b"hi"));
    }

    #[test]
    fn null_keeps_its_type() {
        let mut buf = [0u8; 16];
        Value::Null(ValType::U8).encode_into(&mut buf).unwrap();
        assert_eq!(buf[1], 1);
        assert_eq!(Value::decode(&buf), Some(Value::Null(ValType::U8)));
    }

    #[test]
    fn decode_rejects_short_and_bad_type() {
        assert_eq!(Value::decode(&[0u8; 15]), None);
        let mut buf = [0u8; 16];
        buf[0] = 99;
        assert_eq!(Value::decode(&buf), None);
    }

    #[test]
    fn host_stubs_report_unsupported() {
        assert_eq!(
            attr_get(1, cluster::ON_OFF, attr::VALUE),
            Err(rc::UNSUPPORTED)
        );
        assert_eq!(gpio_read(3), Err(rc::UNSUPPORTED));
    }
}
