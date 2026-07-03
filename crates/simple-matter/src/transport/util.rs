//! ヘッダの固定レイアウト読み書きに用いる軽量なバイト列カーソル。
//!
//! [`crate::tlv`] の `TlvReader`/`TlvWriter` はスキーマ付き TLV 用であり、
//! メッセージヘッダのような固定レイアウトのバイト列にはオーバースペックである。
//! ここでは借用スライス上でリトルエンディアン整数を順に読み書きするだけの
//! 最小ユーティリティ([`ParseBuf`] / [`WriteBuf`])を提供する
//! (rs-matter `utils::storage::{ParseBuf, WriteBuf}` に相当)。
//!
//! いずれも境界チェック済みで、範囲を越える読み書きは `panic` せず
//! [`Error::Decode`](crate::Error::Decode) / [`Error::NoSpace`](crate::Error::NoSpace)
//! を返す。ヒープ確保・中間コピーは行わない。

use crate::error::{Error, Result};

/// 借用したバイト列を先頭から順に読み進めるパースカーソル。
///
/// 復号をその場(in-place)で行うため内部バッファは可変参照で保持する。
/// 「消費済み(先頭側)」「未処理(残り)」「末尾から切り取った分」を
/// オフセットで管理し、スライスのコピーを避ける。
pub struct ParseBuf<'a> {
    buf: &'a mut [u8],
    /// 消費済みバイト数(先頭からのオフセット)。
    read_off: usize,
    /// 未処理バイト数(`read_off` から続く有効長)。
    left: usize,
}

impl<'a> ParseBuf<'a> {
    /// バッファ全体を未処理領域とするカーソルを生成する。
    pub fn new(buf: &'a mut [u8]) -> Self {
        let left = buf.len();
        Self {
            buf,
            read_off: 0,
            left,
        }
    }

    /// 先頭から `size` バイトを消費し、クロージャ `f` にその配列を渡して値を得る。
    /// 残量が足りなければ [`Error::Decode`] を返し、状態は変化しない。
    fn take_head<const N: usize, R>(&mut self, f: impl FnOnce([u8; N]) -> R) -> Result<R> {
        if self.left < N {
            return Err(Error::Decode);
        }
        let start = self.read_off;
        // left >= N を確認済みなので添字は範囲内。
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.buf[start..start + N]);
        self.read_off += N;
        self.left -= N;
        Ok(f(arr))
    }

    /// 先頭 1 バイトを `u8` として読む。
    pub fn le_u8(&mut self) -> Result<u8> {
        self.take_head(|[b]| b)
    }

    /// 先頭 2 バイトを `u16`(リトルエンディアン)として読む。
    pub fn le_u16(&mut self) -> Result<u16> {
        self.take_head(u16::from_le_bytes)
    }

    /// 先頭 4 バイトを `u32`(リトルエンディアン)として読む。
    pub fn le_u32(&mut self) -> Result<u32> {
        self.take_head(u32::from_le_bytes)
    }

    /// 先頭 8 バイトを `u64`(リトルエンディアン)として読む。
    pub fn le_u64(&mut self) -> Result<u64> {
        self.take_head(u64::from_le_bytes)
    }

    /// 既に消費した先頭側のバイト列(AAD として使うヘッダ部)を返す。
    pub fn parsed_as_slice(&self) -> &[u8] {
        &self.buf[..self.read_off]
    }

    /// 未処理の残りバイト列を不変スライスで返す。
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.read_off..self.read_off + self.left]
    }

    /// 未処理の残りバイト列を可変スライスで返す(その場復号に用いる)。
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.read_off..self.read_off + self.left]
    }

    /// 未処理領域の末尾 `size` バイトを切り離して返す(MIC タグの除去に用いる)。
    ///
    /// 残量が `size` 未満なら [`Error::Decode`]。
    pub fn tail(&mut self, size: usize) -> Result<&[u8]> {
        if size > self.left {
            return Err(Error::Decode);
        }
        let end = self.read_off + self.left;
        let tail = &self.buf[end - size..end];
        self.left -= size;
        Ok(tail)
    }

    /// 未処理バイト数を返す。
    pub const fn remaining(&self) -> usize {
        self.left
    }
}

/// 借用したバイト列へ、中央から前後に伸ばして書き込むライタ。
///
/// メッセージ生成では「payload を中央に書き、暗号化後にヘッダを左へ前置する」
/// 必要があるため、先頭に headroom を空けて開始し、[`append`](WriteBuf::append) で
/// 末尾へ、[`prepend`](WriteBuf::prepend) で先頭へ伸ばす。
/// 溢れる場合は `panic` せず [`Error::NoSpace`] を返す。
pub struct WriteBuf<'a> {
    buf: &'a mut [u8],
    /// 書き込み済み領域の先頭オフセット。
    start: usize,
    /// 書き込み済み領域の末尾オフセット(次の追記位置)。
    end: usize,
}

impl<'a> WriteBuf<'a> {
    /// バッファ全体を対象に、先頭 `headroom` バイトを前置用に空けて生成する。
    ///
    /// `headroom` がバッファ長を超える場合は [`Error::NoSpace`]。
    pub fn new(buf: &'a mut [u8], headroom: usize) -> Result<Self> {
        if headroom > buf.len() {
            return Err(Error::NoSpace);
        }
        Ok(Self {
            buf,
            start: headroom,
            end: headroom,
        })
    }

    /// 末尾へ生バイト列を追記する。空きが足りなければ [`Error::NoSpace`]。
    pub fn append(&mut self, src: &[u8]) -> Result<()> {
        let new_end = self.end.checked_add(src.len()).ok_or(Error::NoSpace)?;
        if new_end > self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.end..new_end].copy_from_slice(src);
        self.end = new_end;
        Ok(())
    }

    /// 先頭へ生バイト列を前置する。空けてある headroom が足りなければ [`Error::NoSpace`]。
    pub fn prepend(&mut self, src: &[u8]) -> Result<()> {
        if src.len() > self.start {
            return Err(Error::NoSpace);
        }
        let new_start = self.start - src.len();
        self.buf[new_start..self.start].copy_from_slice(src);
        self.start = new_start;
        Ok(())
    }

    /// 末尾へ 1 バイト追記する。
    pub fn le_u8(&mut self, v: u8) -> Result<()> {
        self.append(&[v])
    }

    /// 末尾へ `u16`(リトルエンディアン)を追記する。
    pub fn le_u16(&mut self, v: u16) -> Result<()> {
        self.append(&v.to_le_bytes())
    }

    /// 末尾へ `u32`(リトルエンディアン)を追記する。
    pub fn le_u32(&mut self, v: u32) -> Result<()> {
        self.append(&v.to_le_bytes())
    }

    /// 末尾へ `u64`(リトルエンディアン)を追記する。
    pub fn le_u64(&mut self, v: u64) -> Result<()> {
        self.append(&v.to_le_bytes())
    }

    /// 書き込み済み領域([`start`, `end`))を不変スライスで返す。
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// 書き込み済み領域([`start`, `end`))を可変スライスで返す(その場暗号化に用いる)。
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    /// 書き込み済み領域の長さ(バイト数)を返す。
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// まだ何も書き込んでいなければ `true`。
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_le_and_slices() {
        let mut data = [0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca, 0xa, 0xb];
        let mut p = ParseBuf::new(&mut data);
        assert_eq!(p.le_u8().unwrap(), 0x01);
        assert_eq!(p.le_u16().unwrap(), 65);
        assert_eq!(p.le_u32().unwrap(), 0xcafe_babe);
        assert_eq!(p.parsed_as_slice(), &[0x01, 65, 0, 0xbe, 0xba, 0xfe, 0xca]);
        assert_eq!(p.as_slice(), &[0xa, 0xb]);
        assert_eq!(p.remaining(), 2);
    }

    #[test]
    fn parse_overrun_is_decode_error() {
        let mut data = [0x01, 65];
        let mut p = ParseBuf::new(&mut data);
        assert_eq!(p.le_u8().unwrap(), 0x01);
        assert_eq!(p.le_u32(), Err(Error::Decode));
        // 失敗後も状態は保たれ、残りを読める。
        assert_eq!(p.le_u8().unwrap(), 65);
    }

    #[test]
    fn tail_strips_from_end() {
        let mut data = [1, 2, 3, 4, 5];
        let mut p = ParseBuf::new(&mut data);
        assert_eq!(p.tail(2).unwrap(), &[4, 5]);
        assert_eq!(p.as_slice(), &[1, 2, 3]);
        assert_eq!(p.tail(9), Err(Error::Decode));
    }

    #[test]
    fn write_append_and_prepend() {
        let mut data = [0u8; 16];
        let mut w = WriteBuf::new(&mut data, 4).unwrap();
        w.le_u16(65).unwrap();
        w.append(&[0xaa, 0xbb]).unwrap();
        assert_eq!(w.as_slice(), &[65, 0, 0xaa, 0xbb]);
        w.prepend(&[0xde, 0xad]).unwrap();
        assert_eq!(w.as_slice(), &[0xde, 0xad, 65, 0, 0xaa, 0xbb]);
        assert_eq!(w.len(), 6);
    }

    #[test]
    fn write_overflow_and_headroom_errors() {
        let mut data = [0u8; 4];
        assert!(WriteBuf::new(&mut data, 5).is_err());
        let mut w = WriteBuf::new(&mut data, 2).unwrap();
        // 残り 2 バイトに 4 バイトは入らない。
        assert_eq!(w.le_u32(0), Err(Error::NoSpace));
        // headroom は 2 バイトなので 3 バイト前置は不可。
        assert_eq!(w.prepend(&[1, 2, 3]), Err(Error::NoSpace));
    }
}
