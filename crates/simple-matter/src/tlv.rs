//! Matter TLV (Tag-Length-Value) コーデック。
//!
//! Matter Core Specification Appendix A のエンコーディングを実装する。
//! IM ペイロードと運用証明書(Matter Certificate)の両方で使う基盤であり、
//! 固定バッファ上のストリーミング Reader/Writer として実装する。
//! ヒープ確保・中間コピーを行わず、文字列・バイト列は借用スライスで返す。
//!
//! # エンコーディング概要
//!
//! 各要素は 1 オクテットの制御バイトで始まる。上位 3bit がタグ制御、
//! 下位 5bit が要素型を表す。制御バイトの後にタグ(0/1/2/4/6/8 オクテット)、
//! 可変長要素では長さフィールド(1/2/4/8 オクテット)、続いて値が並ぶ。
//! 数値はすべてリトルエンディアン。整数は書き込み時に「値を表現できる
//! 最小オクテット数」でエンコードする(Matter 仕様の推奨)。
//!
//! # 使用例
//!
//! ```
//! use simple_matter::tlv::{TlvReader, TlvWriter, TlvTag, TlvValue, ContainerType};
//!
//! let mut buf = [0u8; 32];
//! let mut w = TlvWriter::new(&mut buf);
//! w.start_struct(&TlvTag::Anonymous).unwrap();
//! w.write_u64(&TlvTag::ContextSpecific(1), 42).unwrap();
//! w.end_container().unwrap();
//! let encoded_len = w.len();
//!
//! let mut r = TlvReader::new(&buf[..encoded_len]);
//! let head = r.read_next().unwrap().unwrap();
//! assert_eq!(head.value, TlvValue::ContainerStart(ContainerType::Structure));
//! let field = r.read_next().unwrap().unwrap();
//! assert_eq!(field.tag, TlvTag::ContextSpecific(1));
//! assert_eq!(field.value, TlvValue::UnsignedInteger(42));
//! ```

use crate::error::{Error, Result};

// --- 制御バイトのビット配置 ---

/// タグ制御(制御バイト上位 3bit)を取り出すためのシフト量。
const TAG_SHIFT: u8 = 5;
/// 要素型(制御バイト下位 5bit)を取り出すためのマスク。
const TYPE_MASK: u8 = 0x1f;

// --- 要素型(制御バイト下位 5bit)---

const T_S8: u8 = 0x00;
const T_S16: u8 = 0x01;
const T_S32: u8 = 0x02;
const T_S64: u8 = 0x03;
const T_U8: u8 = 0x04;
const T_U16: u8 = 0x05;
const T_U32: u8 = 0x06;
const T_U64: u8 = 0x07;
const T_BOOL_FALSE: u8 = 0x08;
const T_BOOL_TRUE: u8 = 0x09;
const T_F32: u8 = 0x0a;
const T_F64: u8 = 0x0b;
const T_UTF8_1: u8 = 0x0c;
const T_UTF8_2: u8 = 0x0d;
const T_UTF8_4: u8 = 0x0e;
const T_UTF8_8: u8 = 0x0f;
const T_BYTES_1: u8 = 0x10;
const T_BYTES_2: u8 = 0x11;
const T_BYTES_4: u8 = 0x12;
const T_BYTES_8: u8 = 0x13;
const T_NULL: u8 = 0x14;
const T_STRUCT: u8 = 0x15;
const T_ARRAY: u8 = 0x16;
const T_LIST: u8 = 0x17;
const T_END: u8 = 0x18;

// --- タグ制御(制御バイト上位 3bit の値)---

const TC_ANONYMOUS: u8 = 0;
const TC_CONTEXT: u8 = 1;
const TC_COMMON_16: u8 = 2;
const TC_COMMON_32: u8 = 3;
const TC_IMPLICIT_16: u8 = 4;
const TC_IMPLICIT_32: u8 = 5;
const TC_FULL_48: u8 = 6;
const TC_FULL_64: u8 = 7;

/// TLV 要素のタグ。
///
/// タグ制御ビットが表す 6 形式に対応する。プロファイル系タグは
/// フィールドが実際のプロファイル/タグ番号を保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvTag {
    /// タグなし(配列要素・単一値のトップレベル等)。
    Anonymous,
    /// コンテキスト固有タグ(1 オクテット)。struct/list 内で使う。
    ContextSpecific(u8),
    /// コモンプロファイルタグ(2 オクテットのタグ番号)。
    CommonProfile16(u16),
    /// コモンプロファイルタグ(4 オクテットのタグ番号)。
    CommonProfile32(u32),
    /// 暗黙プロファイルタグ(2 オクテットのタグ番号)。
    ImplicitProfile16(u16),
    /// 暗黙プロファイルタグ(4 オクテットのタグ番号)。
    ImplicitProfile32(u32),
    /// 完全修飾タグ(ベンダ ID + プロファイル + 2 オクテットタグ)。
    FullyQualified48 {
        /// ベンダ ID。
        vendor_id: u16,
        /// プロファイル番号。
        profile: u16,
        /// タグ番号(2 オクテット)。
        tag: u16,
    },
    /// 完全修飾タグ(ベンダ ID + プロファイル + 4 オクテットタグ)。
    FullyQualified64 {
        /// ベンダ ID。
        vendor_id: u16,
        /// プロファイル番号。
        profile: u16,
        /// タグ番号(4 オクテット)。
        tag: u32,
    },
}

impl TlvTag {
    /// タグ制御ビット(制御バイト上位 3bit)の値を返す。
    const fn control_bits(&self) -> u8 {
        match self {
            TlvTag::Anonymous => TC_ANONYMOUS,
            TlvTag::ContextSpecific(_) => TC_CONTEXT,
            TlvTag::CommonProfile16(_) => TC_COMMON_16,
            TlvTag::CommonProfile32(_) => TC_COMMON_32,
            TlvTag::ImplicitProfile16(_) => TC_IMPLICIT_16,
            TlvTag::ImplicitProfile32(_) => TC_IMPLICIT_32,
            TlvTag::FullyQualified48 { .. } => TC_FULL_48,
            TlvTag::FullyQualified64 { .. } => TC_FULL_64,
        }
    }
}

/// コンテナ要素の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerType {
    /// structure(0x15)。順不同・タグ付きフィールドの集合。
    Structure,
    /// array(0x16)。同型・タグなし要素の並び。
    Array,
    /// list(0x17)。タグ付き/なし混在の並び。
    List,
}

/// TLV 要素の値。
///
/// 整数はワイヤ上の幅に依らず論理値(`i64`/`u64`)として返す。
/// 文字列・バイト列は入力バッファを借用したスライスで返す(コピーなし)。
/// コンテナは開始/終了を別々のトークンとして表現する。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlvValue<'a> {
    /// 符号付き整数(1/2/4/8 オクテットを論理値へ符号拡張)。
    SignedInteger(i64),
    /// 符号なし整数(1/2/4/8 オクテット)。
    UnsignedInteger(u64),
    /// 真偽値。
    Boolean(bool),
    /// 単精度浮動小数点数。
    Float(f32),
    /// 倍精度浮動小数点数。
    Double(f64),
    /// UTF-8 文字列(入力バッファの借用)。
    Utf8String(&'a str),
    /// バイト列(入力バッファの借用)。
    ByteString(&'a [u8]),
    /// null。
    Null,
    /// コンテナ開始。以降の `read_next` 呼び出しが子要素を返す。
    ContainerStart(ContainerType),
    /// コンテナ終了(end-of-container, 0x18)。
    ContainerEnd,
}

impl<'a> TlvValue<'a> {
    /// 符号なし整数値を取り出す。型が一致しなければ `Error::Decode`。
    pub fn as_unsigned(&self) -> Result<u64> {
        match self {
            TlvValue::UnsignedInteger(v) => Ok(*v),
            _ => Err(Error::Decode),
        }
    }

    /// 符号付き整数値を取り出す。型が一致しなければ `Error::Decode`。
    pub fn as_signed(&self) -> Result<i64> {
        match self {
            TlvValue::SignedInteger(v) => Ok(*v),
            _ => Err(Error::Decode),
        }
    }

    /// 真偽値を取り出す。型が一致しなければ `Error::Decode`。
    pub fn as_bool(&self) -> Result<bool> {
        match self {
            TlvValue::Boolean(v) => Ok(*v),
            _ => Err(Error::Decode),
        }
    }

    /// UTF-8 文字列を取り出す。型が一致しなければ `Error::Decode`。
    pub fn as_str(&self) -> Result<&'a str> {
        match self {
            TlvValue::Utf8String(v) => Ok(v),
            _ => Err(Error::Decode),
        }
    }

    /// バイト列を取り出す。型が一致しなければ `Error::Decode`。
    pub fn as_bytes(&self) -> Result<&'a [u8]> {
        match self {
            TlvValue::ByteString(v) => Ok(v),
            _ => Err(Error::Decode),
        }
    }

    /// コンテナ開始であればその種別を返す。そうでなければ `Error::Decode`。
    pub fn as_container(&self) -> Result<ContainerType> {
        match self {
            TlvValue::ContainerStart(t) => Ok(*t),
            _ => Err(Error::Decode),
        }
    }
}

/// TLV 要素(タグと値の組)。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TlvElement<'a> {
    /// 要素のタグ。
    pub tag: TlvTag,
    /// 要素の値。
    pub value: TlvValue<'a>,
}

/// `&[u8]` 上を走査するストリーミング TLV リーダ。
///
/// `read_next` を繰り返し呼ぶと、現在位置の要素を先頭から順にトークンとして返す。
/// コンテナ開始/終了もそれぞれ 1 トークンとして返るため、`read_next` を呼び続ける
/// ことがそのままコンテナへの「enter」になり、`ContainerEnd` トークンの消費が
/// 「exit」になる。途中で子要素を読み飛ばす場合は [`exit_container`] を使う。
///
/// すべてのアクセスは境界チェック済みで、不正入力に対しては `panic` せず
/// `Error::Decode` を返す。
///
/// [`exit_container`]: TlvReader::exit_container
#[derive(Debug, Clone)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    /// バッファ全体を対象とするリーダを生成する。
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// 現在の読み取り位置(バッファ先頭からのオフセット)を返す。
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// 未消費のバイトが残っていなければ `true`。
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// バッファ内の絶対オフセット `start` から `len` バイトの部分スライスを返す。
    /// 範囲外なら `Error::Decode`。
    fn take(&self, start: usize, len: usize) -> Result<&'a [u8]> {
        let end = start.checked_add(len).ok_or(Error::Decode)?;
        self.buf.get(start..end).ok_or(Error::Decode)
    }

    /// 次の要素を 1 つ読み、読み取り位置を進める。
    ///
    /// バッファ終端に達している場合は `Ok(None)` を返す。要素として
    /// コンテナ開始・終了もそれぞれ返る。不正なエンコードは `Error::Decode`。
    pub fn read_next(&mut self) -> Result<Option<TlvElement<'a>>> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }

        // pos < buf.len() が保証されているので添字アクセスは安全。
        let control = self.buf[self.pos];
        let tag_control = control >> TAG_SHIFT;
        let elem_type = control & TYPE_MASK;

        let mut p = self.pos + 1;
        let tag = self.read_tag(tag_control, &mut p)?;
        let value = self.read_value(elem_type, &mut p)?;

        self.pos = p;
        Ok(Some(TlvElement { tag, value }))
    }

    /// タグ制御ビットに従ってタグを読み、`p` を進める。
    fn read_tag(&self, tag_control: u8, p: &mut usize) -> Result<TlvTag> {
        let tag = match tag_control {
            TC_ANONYMOUS => TlvTag::Anonymous,
            TC_CONTEXT => {
                let b = self.take(*p, 1)?;
                *p += 1;
                TlvTag::ContextSpecific(b[0])
            }
            TC_COMMON_16 => {
                let v = read_u16(self.take(*p, 2)?);
                *p += 2;
                TlvTag::CommonProfile16(v)
            }
            TC_COMMON_32 => {
                let v = read_u32(self.take(*p, 4)?);
                *p += 4;
                TlvTag::CommonProfile32(v)
            }
            TC_IMPLICIT_16 => {
                let v = read_u16(self.take(*p, 2)?);
                *p += 2;
                TlvTag::ImplicitProfile16(v)
            }
            TC_IMPLICIT_32 => {
                let v = read_u32(self.take(*p, 4)?);
                *p += 4;
                TlvTag::ImplicitProfile32(v)
            }
            TC_FULL_48 => {
                let b = self.take(*p, 6)?;
                *p += 6;
                TlvTag::FullyQualified48 {
                    vendor_id: read_u16(&b[0..2]),
                    profile: read_u16(&b[2..4]),
                    tag: read_u16(&b[4..6]),
                }
            }
            TC_FULL_64 => {
                let b = self.take(*p, 8)?;
                *p += 8;
                TlvTag::FullyQualified64 {
                    vendor_id: read_u16(&b[0..2]),
                    profile: read_u16(&b[2..4]),
                    tag: read_u32(&b[4..8]),
                }
            }
            // tag_control は u8 >> 5 なので 0..=7 に収まる。
            _ => return Err(Error::Decode),
        };
        Ok(tag)
    }

    /// 要素型に従って値を読み、`p` を進める。
    fn read_value(&self, elem_type: u8, p: &mut usize) -> Result<TlvValue<'a>> {
        let value = match elem_type {
            T_S8 | T_S16 | T_S32 | T_S64 => {
                let width = 1usize << (elem_type - T_S8);
                let raw = self.take(*p, width)?;
                *p += width;
                TlvValue::SignedInteger(read_signed(raw))
            }
            T_U8 | T_U16 | T_U32 | T_U64 => {
                let width = 1usize << (elem_type - T_U8);
                let raw = self.take(*p, width)?;
                *p += width;
                TlvValue::UnsignedInteger(read_unsigned(raw))
            }
            T_BOOL_FALSE => TlvValue::Boolean(false),
            T_BOOL_TRUE => TlvValue::Boolean(true),
            T_F32 => {
                let raw = self.take(*p, 4)?;
                *p += 4;
                TlvValue::Float(f32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
            }
            T_F64 => {
                let raw = self.take(*p, 8)?;
                *p += 8;
                TlvValue::Double(f64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]))
            }
            T_UTF8_1 | T_UTF8_2 | T_UTF8_4 | T_UTF8_8 => {
                let len_width = 1usize << (elem_type - T_UTF8_1);
                let bytes = self.read_var_bytes(len_width, p)?;
                let s = core::str::from_utf8(bytes).map_err(|_| Error::Decode)?;
                TlvValue::Utf8String(s)
            }
            T_BYTES_1 | T_BYTES_2 | T_BYTES_4 | T_BYTES_8 => {
                let len_width = 1usize << (elem_type - T_BYTES_1);
                TlvValue::ByteString(self.read_var_bytes(len_width, p)?)
            }
            T_NULL => TlvValue::Null,
            T_STRUCT => TlvValue::ContainerStart(ContainerType::Structure),
            T_ARRAY => TlvValue::ContainerStart(ContainerType::Array),
            T_LIST => TlvValue::ContainerStart(ContainerType::List),
            T_END => TlvValue::ContainerEnd,
            // 0x19..=0x1f は予約(未定義)。
            _ => return Err(Error::Decode),
        };
        Ok(value)
    }

    /// 長さフィールド(`len_width` オクテット)を読み、その長さぶんの値スライスを
    /// 返して `p` を進める。
    fn read_var_bytes(&self, len_width: usize, p: &mut usize) -> Result<&'a [u8]> {
        let len_raw = self.take(*p, len_width)?;
        *p += len_width;
        let len = read_unsigned(len_raw);
        // usize に収まらない長さは不正入力として扱う(32bit ターゲット対策)。
        let len: usize = len.try_into().map_err(|_| Error::Decode)?;
        let bytes = self.take(*p, len)?;
        *p += len;
        Ok(bytes)
    }

    /// 直前に開始したコンテナの残りを読み飛ばし、対応する `ContainerEnd` を消費する。
    ///
    /// コンテナ開始トークンを既に `next` で読み終えた状態から呼び出す想定。
    /// ネストは正しく数える。終端に達しても閉じられない場合(閉じ忘れ)は
    /// `Error::Decode`。
    pub fn exit_container(&mut self) -> Result<()> {
        let mut depth = 1usize;
        while depth > 0 {
            match self.read_next()? {
                None => return Err(Error::Decode),
                Some(elem) => match elem.value {
                    TlvValue::ContainerStart(_) => depth += 1,
                    TlvValue::ContainerEnd => depth -= 1,
                    _ => {}
                },
            }
        }
        Ok(())
    }

    /// 次の要素がコンテナ開始であることを確認して種別を返す。
    /// コンテナ開始でなければ `Error::Decode`。
    pub fn enter_container(&mut self) -> Result<ContainerType> {
        match self.read_next()? {
            Some(elem) => elem.value.as_container(),
            None => Err(Error::Decode),
        }
    }

    /// 直前に読んだ要素 `elem` を読み飛ばす。コンテナ開始であれば
    /// その全内容(ネスト含む)と終端まで読み飛ばす。
    pub fn skip(&mut self, elem: &TlvElement<'a>) -> Result<()> {
        if matches!(elem.value, TlvValue::ContainerStart(_)) {
            self.exit_container()?;
        }
        Ok(())
    }
}

/// `&mut [u8]` に書き込むストリーミング TLV ライタ。
///
/// 整数は「値を表現できる最小オクテット数」でエンコードする(Matter 推奨)。
/// 文字列・バイト列の長さフィールドも長さに応じて最小幅を選ぶ。
/// バッファが不足した場合は `Error::NoSpace` を返し、`panic` しない。
#[derive(Debug)]
pub struct TlvWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    depth: usize,
}

impl<'a> TlvWriter<'a> {
    /// 出力先バッファを与えてライタを生成する。
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    /// これまでに書き込んだバイト列を返す。
    pub fn written(&self) -> &[u8] {
        // pos は常に buf 長以内に保たれる。
        &self.buf[..self.pos]
    }

    /// 書き込み済みバイト数を返す。
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// まだ何も書き込んでいなければ `true`。
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// 生バイト列を末尾へ追記する。空きが足りなければ `Error::NoSpace`。
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::NoSpace)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(Error::NoSpace)?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    /// 制御バイトとタグ本体を書き込む。
    fn write_header(&mut self, tag: &TlvTag, elem_type: u8) -> Result<()> {
        let control = (tag.control_bits() << TAG_SHIFT) | elem_type;
        self.put(&[control])?;
        match *tag {
            TlvTag::Anonymous => Ok(()),
            TlvTag::ContextSpecific(v) => self.put(&[v]),
            TlvTag::CommonProfile16(v) | TlvTag::ImplicitProfile16(v) => self.put(&v.to_le_bytes()),
            TlvTag::CommonProfile32(v) | TlvTag::ImplicitProfile32(v) => self.put(&v.to_le_bytes()),
            TlvTag::FullyQualified48 {
                vendor_id,
                profile,
                tag,
            } => {
                self.put(&vendor_id.to_le_bytes())?;
                self.put(&profile.to_le_bytes())?;
                self.put(&tag.to_le_bytes())
            }
            TlvTag::FullyQualified64 {
                vendor_id,
                profile,
                tag,
            } => {
                self.put(&vendor_id.to_le_bytes())?;
                self.put(&profile.to_le_bytes())?;
                self.put(&tag.to_le_bytes())
            }
        }
    }

    /// 符号付き整数を最小幅でエンコードして書き込む。
    pub fn write_i64(&mut self, tag: &TlvTag, value: i64) -> Result<()> {
        if i8::try_from(value).is_ok() {
            self.write_header(tag, T_S8)?;
            self.put(&(value as i8).to_le_bytes())
        } else if i16::try_from(value).is_ok() {
            self.write_header(tag, T_S16)?;
            self.put(&(value as i16).to_le_bytes())
        } else if i32::try_from(value).is_ok() {
            self.write_header(tag, T_S32)?;
            self.put(&(value as i32).to_le_bytes())
        } else {
            self.write_header(tag, T_S64)?;
            self.put(&value.to_le_bytes())
        }
    }

    /// `i8` を書き込む(最小幅エンコード)。
    pub fn write_i8(&mut self, tag: &TlvTag, value: i8) -> Result<()> {
        self.write_i64(tag, value as i64)
    }

    /// `i16` を書き込む(最小幅エンコード)。
    pub fn write_i16(&mut self, tag: &TlvTag, value: i16) -> Result<()> {
        self.write_i64(tag, value as i64)
    }

    /// `i32` を書き込む(最小幅エンコード)。
    pub fn write_i32(&mut self, tag: &TlvTag, value: i32) -> Result<()> {
        self.write_i64(tag, value as i64)
    }

    /// 符号なし整数を最小幅でエンコードして書き込む。
    pub fn write_u64(&mut self, tag: &TlvTag, value: u64) -> Result<()> {
        if u8::try_from(value).is_ok() {
            self.write_header(tag, T_U8)?;
            self.put(&(value as u8).to_le_bytes())
        } else if u16::try_from(value).is_ok() {
            self.write_header(tag, T_U16)?;
            self.put(&(value as u16).to_le_bytes())
        } else if u32::try_from(value).is_ok() {
            self.write_header(tag, T_U32)?;
            self.put(&(value as u32).to_le_bytes())
        } else {
            self.write_header(tag, T_U64)?;
            self.put(&value.to_le_bytes())
        }
    }

    /// `u8` を書き込む(最小幅エンコード)。
    pub fn write_u8(&mut self, tag: &TlvTag, value: u8) -> Result<()> {
        self.write_u64(tag, value as u64)
    }

    /// `u16` を書き込む(最小幅エンコード)。
    pub fn write_u16(&mut self, tag: &TlvTag, value: u16) -> Result<()> {
        self.write_u64(tag, value as u64)
    }

    /// `u32` を書き込む(最小幅エンコード)。
    pub fn write_u32(&mut self, tag: &TlvTag, value: u32) -> Result<()> {
        self.write_u64(tag, value as u64)
    }

    /// 真偽値を書き込む。
    pub fn write_bool(&mut self, tag: &TlvTag, value: bool) -> Result<()> {
        self.write_header(tag, if value { T_BOOL_TRUE } else { T_BOOL_FALSE })
    }

    /// 単精度浮動小数点数を書き込む。
    pub fn write_f32(&mut self, tag: &TlvTag, value: f32) -> Result<()> {
        self.write_header(tag, T_F32)?;
        self.put(&value.to_le_bytes())
    }

    /// 倍精度浮動小数点数を書き込む。
    pub fn write_f64(&mut self, tag: &TlvTag, value: f64) -> Result<()> {
        self.write_header(tag, T_F64)?;
        self.put(&value.to_le_bytes())
    }

    /// null を書き込む。
    pub fn write_null(&mut self, tag: &TlvTag) -> Result<()> {
        self.write_header(tag, T_NULL)
    }

    /// UTF-8 文字列を書き込む。長さフィールドは長さに応じ最小幅を選ぶ。
    pub fn write_utf8(&mut self, tag: &TlvTag, value: &str) -> Result<()> {
        self.write_var(tag, value.as_bytes(), T_UTF8_1)
    }

    /// バイト列を書き込む。長さフィールドは長さに応じ最小幅を選ぶ。
    pub fn write_bytes(&mut self, tag: &TlvTag, value: &[u8]) -> Result<()> {
        self.write_var(tag, value, T_BYTES_1)
    }

    /// 可変長要素(UTF-8/バイト列)を最小長フィールドで書き込む共通処理。
    /// `base_type` は 1 オクテット長フィールド版の要素型(`T_UTF8_1`/`T_BYTES_1`)。
    fn write_var(&mut self, tag: &TlvTag, value: &[u8], base_type: u8) -> Result<()> {
        let len = value.len();
        if let Ok(l) = u8::try_from(len) {
            self.write_header(tag, base_type)?;
            self.put(&l.to_le_bytes())?;
        } else if let Ok(l) = u16::try_from(len) {
            self.write_header(tag, base_type + 1)?;
            self.put(&l.to_le_bytes())?;
        } else if let Ok(l) = u32::try_from(len) {
            self.write_header(tag, base_type + 2)?;
            self.put(&l.to_le_bytes())?;
        } else {
            self.write_header(tag, base_type + 3)?;
            self.put(&(len as u64).to_le_bytes())?;
        }
        self.put(value)
    }

    /// 指定種別のコンテナを開始する。対応する [`end_container`] が必要。
    ///
    /// [`end_container`]: TlvWriter::end_container
    pub fn start_container(&mut self, tag: &TlvTag, container: ContainerType) -> Result<()> {
        let elem_type = match container {
            ContainerType::Structure => T_STRUCT,
            ContainerType::Array => T_ARRAY,
            ContainerType::List => T_LIST,
        };
        self.write_header(tag, elem_type)?;
        self.depth += 1;
        Ok(())
    }

    /// structure コンテナを開始する。
    pub fn start_struct(&mut self, tag: &TlvTag) -> Result<()> {
        self.start_container(tag, ContainerType::Structure)
    }

    /// array コンテナを開始する。
    pub fn start_array(&mut self, tag: &TlvTag) -> Result<()> {
        self.start_container(tag, ContainerType::Array)
    }

    /// list コンテナを開始する。
    pub fn start_list(&mut self, tag: &TlvTag) -> Result<()> {
        self.start_container(tag, ContainerType::List)
    }

    /// 直近に開始したコンテナを終了する。
    /// 開いているコンテナが無い場合は `Error::InvalidState`。
    pub fn end_container(&mut self) -> Result<()> {
        if self.depth == 0 {
            return Err(Error::InvalidState);
        }
        // end-of-container は常に anonymous タグ。
        self.put(&[T_END])?;
        self.depth -= 1;
        Ok(())
    }
}

// --- リトルエンディアン読み出しヘルパ ---
// いずれも引数スライスはちょうど所定長であることを呼び出し側が保証する。

/// 2 オクテットを `u16`(LE)として読む。
fn read_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// 4 オクテットを `u32`(LE)として読む。
fn read_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// 1/2/4/8 オクテットの符号なし整数(LE)を `u64` として読む。
fn read_unsigned(b: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr[..b.len()].copy_from_slice(b);
    u64::from_le_bytes(arr)
}

/// 1/2/4/8 オクテットの符号付き整数(LE)を符号拡張して `i64` として読む。
fn read_signed(b: &[u8]) -> i64 {
    match b.len() {
        1 => b[0] as i8 as i64,
        2 => i16::from_le_bytes([b[0], b[1]]) as i64,
        4 => i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as i64,
        8 => i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        // read_value からは 1/2/4/8 のみで呼ばれる。
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与えたクロージャで書き込み、書き込み済みスライスを検証する補助。
    fn encode(f: impl FnOnce(&mut TlvWriter)) -> ([u8; 256], usize) {
        let mut buf = [0u8; 256];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            f(&mut w);
            w.len()
        };
        (buf, len)
    }

    fn assert_encodes(expected: &[u8], f: impl FnOnce(&mut TlvWriter)) {
        let (buf, len) = encode(f);
        assert_eq!(&buf[..len], expected);
    }

    // --- Matter Core Spec Appendix A の既知ベクタ(rs-matter テストと突合)---

    #[test]
    fn spec_scalars() {
        assert_encodes(&[0x08], |w| {
            w.write_bool(&TlvTag::Anonymous, false).unwrap()
        });
        assert_encodes(&[0x09], |w| w.write_bool(&TlvTag::Anonymous, true).unwrap());
        // 符号付き 1 オクテット 42
        assert_encodes(&[0x00, 0x2a], |w| {
            w.write_i8(&TlvTag::Anonymous, 42).unwrap()
        });
        // 符号付き 1 オクテット -17(i32 で与えても最小幅 S8)
        assert_encodes(&[0x00, 0xef], |w| {
            w.write_i32(&TlvTag::Anonymous, -17).unwrap()
        });
        // 符号なし 1 オクテット 42
        assert_encodes(&[0x04, 0x2a], |w| {
            w.write_u8(&TlvTag::Anonymous, 42).unwrap()
        });
        // 符号付き 2 オクテット 422
        assert_encodes(&[0x01, 0xa6, 0x01], |w| {
            w.write_i16(&TlvTag::Anonymous, 422).unwrap()
        });
        // 符号付き 4 オクテット -170000
        assert_encodes(&[0x02, 0xf0, 0x67, 0xfd, 0xff], |w| {
            w.write_i32(&TlvTag::Anonymous, -170000).unwrap()
        });
        // 符号付き 8 オクテット 40000000000
        assert_encodes(
            &[0x03, 0x00, 0x90, 0x2f, 0x50, 0x09, 0x00, 0x00, 0x00],
            |w| w.write_i64(&TlvTag::Anonymous, 40000000000).unwrap(),
        );
        // null
        assert_encodes(&[0x14], |w| w.write_null(&TlvTag::Anonymous).unwrap());
    }

    #[test]
    fn spec_floats() {
        assert_encodes(&[0x0a, 0x00, 0x00, 0x00, 0x00], |w| {
            w.write_f32(&TlvTag::Anonymous, 0.0).unwrap()
        });
        assert_encodes(&[0x0a, 0x33, 0x33, 0x8f, 0x41], |w| {
            w.write_f32(&TlvTag::Anonymous, 17.9).unwrap()
        });
        assert_encodes(
            &[0x0b, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6, 0x31, 0x40],
            |w| w.write_f64(&TlvTag::Anonymous, 17.9).unwrap(),
        );
    }

    #[test]
    fn spec_strings() {
        // UTF-8 "Hello!"
        assert_encodes(&[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21], |w| {
            w.write_utf8(&TlvTag::Anonymous, "Hello!").unwrap()
        });
        // UTF-8 "Tschüs"(マルチバイト)
        assert_encodes(
            &[0x0c, 0x07, 0x54, 0x73, 0x63, 0x68, 0xc3, 0xbc, 0x73],
            |w| w.write_utf8(&TlvTag::Anonymous, "Tschüs").unwrap(),
        );
        // オクテット列 00 01 02 03 04
        assert_encodes(&[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04], |w| {
            w.write_bytes(&TlvTag::Anonymous, &[0, 1, 2, 3, 4]).unwrap()
        });
    }

    #[test]
    fn spec_containers() {
        assert_encodes(&[0x15, 0x18], |w| {
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.end_container().unwrap();
        });
        assert_encodes(&[0x16, 0x18], |w| {
            w.start_array(&TlvTag::Anonymous).unwrap();
            w.end_container().unwrap();
        });
        assert_encodes(&[0x17, 0x18], |w| {
            w.start_list(&TlvTag::Anonymous).unwrap();
            w.end_container().unwrap();
        });
        // struct { 0 = 42s8, 1 = -17 }
        assert_encodes(&[0x15, 0x20, 0x00, 0x2a, 0x20, 0x01, 0xef, 0x18], |w| {
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_i8(&TlvTag::ContextSpecific(0), 42).unwrap();
            w.write_i32(&TlvTag::ContextSpecific(1), -17).unwrap();
            w.end_container().unwrap();
        });
        // array [0,1,2,3,4] (s8)
        assert_encodes(
            &[
                0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x18,
            ],
            |w| {
                w.start_array(&TlvTag::Anonymous).unwrap();
                for i in 0..5i8 {
                    w.write_i8(&TlvTag::Anonymous, i).unwrap();
                }
                w.end_container().unwrap();
            },
        );
    }

    #[test]
    fn spec_tag_forms() {
        // context tag 1, u8 42
        assert_encodes(&[0x24, 0x01, 0x2a], |w| {
            w.write_u8(&TlvTag::ContextSpecific(1), 42).unwrap()
        });
        // common profile 16 tag 1, u8 42
        assert_encodes(&[0x44, 0x01, 0x00, 0x2a], |w| {
            w.write_u8(&TlvTag::CommonProfile16(1), 42).unwrap()
        });
        // common profile 32 tag 100000, u8 42
        assert_encodes(&[0x64, 0xa0, 0x86, 0x01, 0x00, 0x2a], |w| {
            w.write_u8(&TlvTag::CommonProfile32(100000), 42).unwrap()
        });
        // fully qualified 48
        assert_encodes(&[0xc4, 0xf1, 0xff, 0xed, 0xde, 0x01, 0x00, 0x2a], |w| {
            w.write_u8(
                &TlvTag::FullyQualified48 {
                    vendor_id: 65521,
                    profile: 57069,
                    tag: 1,
                },
                42,
            )
            .unwrap()
        });
        // fully qualified 64
        assert_encodes(
            &[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a],
            |w| {
                w.write_u8(
                    &TlvTag::FullyQualified64 {
                        vendor_id: 65521,
                        profile: 57069,
                        tag: 2857762541,
                    },
                    42,
                )
                .unwrap()
            },
        );
    }

    // --- デコードの既知ベクタ ---

    #[test]
    fn decode_known_vectors() {
        // context 1, u8 42
        let mut r = TlvReader::new(&[0x24, 0x01, 0x2a]);
        let e = r.read_next().unwrap().unwrap();
        assert_eq!(e.tag, TlvTag::ContextSpecific(1));
        assert_eq!(e.value, TlvValue::UnsignedInteger(42));
        assert!(r.read_next().unwrap().is_none());

        // 符号付き -17(S8)
        let mut r = TlvReader::new(&[0x00, 0xef]);
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::SignedInteger(-17)
        );

        // 符号付き 4 オクテット -170000
        let mut r = TlvReader::new(&[0x02, 0xf0, 0x67, 0xfd, 0xff]);
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::SignedInteger(-170000)
        );

        // UTF-8 "Hello!"
        let mut r = TlvReader::new(&[0x0c, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]);
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::Utf8String("Hello!")
        );

        // オクテット列
        let mut r = TlvReader::new(&[0x10, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ByteString(&[0, 1, 2, 3, 4])
        );

        // fully qualified 64
        let mut r = TlvReader::new(&[0xe4, 0xf1, 0xff, 0xed, 0xde, 0xed, 0xfe, 0x55, 0xaa, 0x2a]);
        let e = r.read_next().unwrap().unwrap();
        assert_eq!(
            e.tag,
            TlvTag::FullyQualified64 {
                vendor_id: 65521,
                profile: 57069,
                tag: 2857762541,
            }
        );
        assert_eq!(e.value, TlvValue::UnsignedInteger(42));
    }

    #[test]
    fn decode_nested_structure_iteration() {
        // { 0 = 2u8, 2 = 135246u32, 3 = "smar" }
        let data = &[
            0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72, 0x18,
        ];
        let mut r = TlvReader::new(data);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        let a = r.read_next().unwrap().unwrap();
        assert_eq!(a.tag, TlvTag::ContextSpecific(0));
        assert_eq!(a.value, TlvValue::UnsignedInteger(2));
        let b = r.read_next().unwrap().unwrap();
        assert_eq!(b.tag, TlvTag::ContextSpecific(2));
        assert_eq!(b.value, TlvValue::UnsignedInteger(135246));
        let c = r.read_next().unwrap().unwrap();
        assert_eq!(c.tag, TlvTag::ContextSpecific(3));
        assert_eq!(c.value, TlvValue::ByteString(&[0x73, 0x6d, 0x61, 0x72]));
        // end-of-container
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerEnd
        );
        assert!(r.read_next().unwrap().is_none());
    }

    // --- 往復(round-trip)---

    #[test]
    fn round_trip_mixed() {
        let (buf, len) = encode(|w| {
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u64(&TlvTag::ContextSpecific(0), 0xDEAD_BEEF)
                .unwrap();
            w.write_i64(&TlvTag::ContextSpecific(1), -170000).unwrap();
            w.write_bool(&TlvTag::ContextSpecific(2), true).unwrap();
            w.write_utf8(&TlvTag::ContextSpecific(3), "matter").unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(4), &[1, 2, 3])
                .unwrap();
            w.write_f64(&TlvTag::ContextSpecific(5), 17.9).unwrap();
            w.write_null(&TlvTag::ContextSpecific(6)).unwrap();
            w.start_array(&TlvTag::ContextSpecific(7)).unwrap();
            w.write_u8(&TlvTag::Anonymous, 1).unwrap();
            w.write_u8(&TlvTag::Anonymous, 2).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
        });

        let mut r = TlvReader::new(&buf[..len]);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_unsigned().unwrap(),
            0xDEAD_BEEF
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_signed().unwrap(),
            -170000
        );
        assert!(r.read_next().unwrap().unwrap().value.as_bool().unwrap());
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_str().unwrap(),
            "matter"
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_bytes().unwrap(),
            &[1, 2, 3]
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::Double(17.9)
        );
        assert_eq!(r.read_next().unwrap().unwrap().value, TlvValue::Null);
        // 配列に入る
        let arr = r.read_next().unwrap().unwrap();
        assert_eq!(arr.tag, TlvTag::ContextSpecific(7));
        assert_eq!(arr.value, TlvValue::ContainerStart(ContainerType::Array));
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::UnsignedInteger(1)
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::UnsignedInteger(2)
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerEnd
        ); // 配列終了
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerEnd
        ); // struct 終了
        assert!(r.read_next().unwrap().is_none());
    }

    #[test]
    fn round_trip_all_tag_forms() {
        let tags = [
            TlvTag::Anonymous,
            TlvTag::ContextSpecific(9),
            TlvTag::CommonProfile16(0x1234),
            TlvTag::CommonProfile32(0x1234_5678),
            TlvTag::ImplicitProfile16(0x4321),
            TlvTag::ImplicitProfile32(0x8765_4321),
            TlvTag::FullyQualified48 {
                vendor_id: 0xFFF1,
                profile: 0xDEED,
                tag: 0xAA55,
            },
            TlvTag::FullyQualified64 {
                vendor_id: 0xFFF1,
                profile: 0xDEED,
                tag: 0xAA55_FEED,
            },
        ];
        for tag in tags {
            let (buf, len) = encode(|w| w.write_u64(&tag, 0x0102_0304_0506_0708).unwrap());
            let mut r = TlvReader::new(&buf[..len]);
            let e = r.read_next().unwrap().unwrap();
            assert_eq!(e.tag, tag);
            assert_eq!(e.value, TlvValue::UnsignedInteger(0x0102_0304_0506_0708));
        }
    }

    #[test]
    fn exit_container_skips_nested() {
        // { 0 = { 1 = 2 }, 3 = 4 }
        let (buf, len) = encode(|w| {
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.start_struct(&TlvTag::ContextSpecific(0)).unwrap();
            w.write_u8(&TlvTag::ContextSpecific(1), 2).unwrap();
            w.end_container().unwrap();
            w.write_u8(&TlvTag::ContextSpecific(3), 4).unwrap();
            w.end_container().unwrap();
        });
        let mut r = TlvReader::new(&buf[..len]);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        // 内側 struct をスキップ
        let inner = r.read_next().unwrap().unwrap();
        assert_eq!(inner.tag, TlvTag::ContextSpecific(0));
        r.skip(&inner).unwrap();
        // 次は 3 = 4
        let e = r.read_next().unwrap().unwrap();
        assert_eq!(e.tag, TlvTag::ContextSpecific(3));
        assert_eq!(e.value, TlvValue::UnsignedInteger(4));
    }

    // --- 不正入力 ---

    #[test]
    fn err_truncated_scalar() {
        // U16 だが値バイトが無い
        let mut r = TlvReader::new(&[0x05]);
        assert_eq!(r.read_next(), Err(Error::Decode));
    }

    #[test]
    fn err_invalid_element_type() {
        // 0x1f は予約(未定義の要素型)
        let mut r = TlvReader::new(&[0x1f]);
        assert_eq!(r.read_next(), Err(Error::Decode));
    }

    #[test]
    fn err_truncated_string() {
        // UTF-8 長さ 5 だが 1 バイトしか無い
        let mut r = TlvReader::new(&[0x0c, 0x05, 0x41]);
        assert_eq!(r.read_next(), Err(Error::Decode));
    }

    #[test]
    fn err_invalid_utf8() {
        // 長さ 1、値 0xFF は不正な UTF-8
        let mut r = TlvReader::new(&[0x0c, 0x01, 0xff]);
        assert_eq!(r.read_next(), Err(Error::Decode));
    }

    #[test]
    fn err_truncated_tag() {
        // context タグだがタグバイトが無い
        let mut r = TlvReader::new(&[0x24]);
        assert_eq!(r.read_next(), Err(Error::Decode));
    }

    #[test]
    fn err_unclosed_container() {
        // struct を開始したが end-of-container が無い
        let mut r = TlvReader::new(&[0x15, 0x24, 0x01, 0x2a]);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        // 中身を読み切ってから exit しようとすると閉じ忘れで Decode
        assert_eq!(r.exit_container(), Err(Error::Decode));
    }

    #[test]
    fn err_writer_overflow_returns_nospace() {
        let mut buf = [0u8; 2];
        let mut w = TlvWriter::new(&mut buf);
        // [0x24, 0x01, 0x0d] の 3 バイトが必要。制御+タグは書けるが値で溢れる。
        assert_eq!(
            w.write_u8(&TlvTag::ContextSpecific(1), 13),
            Err(Error::NoSpace)
        );
    }

    #[test]
    fn err_end_container_without_start() {
        let mut buf = [0u8; 8];
        let mut w = TlvWriter::new(&mut buf);
        assert_eq!(w.end_container(), Err(Error::InvalidState));
    }

    #[test]
    fn empty_reader_returns_none() {
        let mut r = TlvReader::new(&[]);
        assert!(r.read_next().unwrap().is_none());
    }
}
