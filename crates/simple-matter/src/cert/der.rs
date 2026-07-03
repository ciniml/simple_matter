//! 固定バッファ上に構築する最小 DER(ASN.1 Distinguished Encoding Rules)ライタ。
//!
//! Matter TLV 証明書から X.509 TBSCertificate を再構築するために必要な最小限の
//! DER プリミティブのみを提供する。ヒープを確保せず、呼び出し側が与えた
//! `&mut [u8]` にストリーミングで書き込む。
//!
//! # 長さ前置の方式
//!
//! DER は TLV(Tag-Length-Value)構造であり、SEQUENCE / SET など合成型は
//! 中身を書き終えるまで長さが確定しない。本ライタは rs-matter の `ASN1Writer` と
//! 同じ **後方詰め(reserve-and-shift)** 方式を採る:
//!
//! 1. 合成型の開始時にタグを書き、長さ用に固定 3 バイトを予約する。
//! 2. 中身を予約領域の直後から書き込む。
//! 3. 合成型の終了時に実際の長さ(短形式 1 バイト・長形式 2〜3 バイト)を
//!    予約領域先頭に書き、必要なら中身を前方へ詰め直す(予約 3 バイトとの差分)。
//!
//! この方式は 2 パス走査を要さず、ネストした合成型を素直に扱える。
//!
//! # panic しない
//!
//! 出力バッファ超過・ネスト超過はいずれも [`Error::NoSpace`] を返し、
//! スライス範囲外アクセスは行わない。

use crate::error::{Error, Result};

/// 合成型の長さ用に予約するバイト数(長形式 `0x82 hi lo` の最大 3 バイト)。
const RESERVE_LEN_BYTES: usize = 3;

/// 合成型ネストの最大深さ。X.509 TBSCertificate の再構築に十分な深さ。
const MAX_DEPTH: usize = 12;

/// 固定バッファへ DER を書き込むライタ。
pub(super) struct DerWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
    /// 各深さの合成型の「中身開始オフセット」(予約領域の直後)。
    depth: [usize; MAX_DEPTH],
    current_depth: usize,
}

impl<'a> DerWriter<'a> {
    /// `buf` を出力先とするライタを生成する。
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            offset: 0,
            depth: [0; MAX_DEPTH],
            current_depth: 0,
        }
    }

    /// 現在の書き込み長。
    pub fn len(&self) -> usize {
        self.offset
    }

    /// 長さ `len` の符号化に要するバイト数(タグ長オクテットを含む)。
    fn bytes_to_encode_len(len: usize) -> Result<usize> {
        if len < 0x80 {
            Ok(1)
        } else if len < 0x100 {
            Ok(2)
        } else if len < 0x1_0000 {
            Ok(3)
        } else {
            Err(Error::NoSpace)
        }
    }

    fn put(&mut self, b: u8) -> Result<()> {
        *self.buf.get_mut(self.offset).ok_or(Error::NoSpace)? = b;
        self.offset += 1;
        Ok(())
    }

    fn put_slice(&mut self, s: &[u8]) -> Result<()> {
        let end = self.offset.checked_add(s.len()).ok_or(Error::NoSpace)?;
        self.buf
            .get_mut(self.offset..end)
            .ok_or(Error::NoSpace)?
            .copy_from_slice(s);
        self.offset = end;
        Ok(())
    }

    /// `at` から長さ `len` を DER 符号化し、次のオフセットを返す。
    fn encode_len(&mut self, mut at: usize, len: usize) -> Result<usize> {
        let mut n = Self::bytes_to_encode_len(len)?;
        if n > 1 {
            *self.buf.get_mut(at).ok_or(Error::NoSpace)? = 0x80 | (n as u8 - 1);
            at += 1;
            n -= 1;
        }
        let mut octet = n - 1;
        loop {
            *self.buf.get_mut(at).ok_or(Error::NoSpace)? = ((len >> (octet * 8)) & 0xff) as u8;
            at += 1;
            if octet == 0 {
                break;
            }
            octet -= 1;
        }
        Ok(at)
    }

    /// タグ `tag`・内容 `content` のプリミティブ TLV を書き込む。
    fn primitive(&mut self, tag: u8, content: &[u8]) -> Result<()> {
        self.put(tag)?;
        let at = self.encode_len(self.offset, content.len())?;
        self.offset = at;
        self.put_slice(content)
    }

    /// 合成型を開始する(タグを書き、長さ用に予約する)。
    fn start(&mut self, tag: u8) -> Result<()> {
        self.put(tag)?;
        let end = self
            .offset
            .checked_add(RESERVE_LEN_BYTES)
            .ok_or(Error::NoSpace)?;
        if end > self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.offset = end;
        if self.current_depth >= MAX_DEPTH {
            return Err(Error::NoSpace);
        }
        self.depth[self.current_depth] = self.offset;
        self.current_depth += 1;
        Ok(())
    }

    /// 直近の合成型を終了する(実際の長さを書き、中身を前方に詰める)。
    fn end(&mut self) -> Result<()> {
        if self.current_depth == 0 {
            return Err(Error::Decode);
        }
        self.current_depth -= 1;
        let content_start = self.depth[self.current_depth];
        let content_len = self.offset - content_start;
        let len_at = content_start - RESERVE_LEN_BYTES;
        let write_end = self.encode_len(len_at, content_len)?;
        let shift = content_start - write_end;
        if shift > 0 {
            for i in 0..content_len {
                self.buf[write_end + i] = self.buf[content_start + i];
            }
            self.offset -= shift;
        }
        Ok(())
    }

    // --- 合成型 ---

    /// SEQUENCE を開始する。
    pub fn start_seq(&mut self) -> Result<()> {
        self.start(0x30)
    }

    /// SET を開始する。
    pub fn start_set(&mut self) -> Result<()> {
        self.start(0x31)
    }

    /// context-specific 構築タグ `[id]` を開始する。
    pub fn start_ctx(&mut self, id: u8) -> Result<()> {
        self.start(0xA0 | id)
    }

    /// OCTET STRING を合成型として開始する(中身に DER を格納する用途)。
    pub fn start_octet_string(&mut self) -> Result<()> {
        self.start(0x04)
    }

    /// 直近の合成型を終了する。
    pub fn end_container(&mut self) -> Result<()> {
        self.end()
    }

    // --- プリミティブ ---

    /// INTEGER(内容バイトはそのまま書く)。
    pub fn integer(&mut self, content: &[u8]) -> Result<()> {
        self.primitive(0x02, content)
    }

    /// OBJECT IDENTIFIER(内容は符号化済みの OID バイト列)。
    pub fn oid(&mut self, oid: &[u8]) -> Result<()> {
        self.primitive(0x06, oid)
    }

    /// BOOLEAN。
    pub fn boolean(&mut self, v: bool) -> Result<()> {
        self.primitive(0x01, &[if v { 0xFF } else { 0x00 }])
    }

    /// OCTET STRING(プリミティブ)。
    pub fn octet_string(&mut self, s: &[u8]) -> Result<()> {
        self.primitive(0x04, s)
    }

    /// UTF8String。
    pub fn utf8_string(&mut self, s: &[u8]) -> Result<()> {
        self.primitive(0x0C, s)
    }

    /// PrintableString。
    pub fn printable_string(&mut self, s: &[u8]) -> Result<()> {
        self.primitive(0x13, s)
    }

    /// UTCTime / GeneralizedTime(タグを明示指定する)。
    pub fn time(&mut self, tag: u8, s: &[u8]) -> Result<()> {
        self.primitive(tag, s)
    }

    /// context-specific プリミティブタグ `[id]`(authority-key-id 等で使用)。
    pub fn ctx_primitive(&mut self, id: u8, val: &[u8]) -> Result<()> {
        self.primitive(0x80 | id, val)
    }

    /// 事前符号化済みの生 DER バイト列をそのまま書き込む(future-extensions)。
    pub fn raw(&mut self, data: &[u8]) -> Result<()> {
        self.put_slice(data)
    }

    /// BIT STRING。`truncate` が真なら末尾の 0 ビットを詰め、未使用ビット数を計算する
    /// (key-usage 用)。偽なら未使用ビット 0 として内容をそのまま格納する(公開鍵用)。
    pub fn bit_string(&mut self, truncate: bool, s: &[u8]) -> Result<()> {
        if s.is_empty() {
            return self.primitive(0x03, &[0x00]);
        }
        let mut last = s.len() - 1;
        let mut unused = 0u8;
        if truncate {
            while last > 0 && s[last] == 0 {
                last -= 1;
            }
            unused = if s[last] == 0 {
                0
            } else {
                s[last].trailing_zeros() as u8
            };
        }
        let s = &s[..=last];
        self.put(0x03)?;
        let at = self.encode_len(self.offset, s.len() + 1)?;
        self.offset = at;
        self.put(unused)?;
        self.put_slice(s)
    }
}
