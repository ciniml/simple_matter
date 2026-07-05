//! 最小限の DNS メッセージ(RFC 1035)エンコーダ / デコーダ。
//!
//! mDNS(RFC 6762)応答の生成に必要な範囲だけを実装する。送信側は圧縮ポインタを
//! **使わず**にフルネームを書く(実装が単純で、受信側の圧縮展開は別途対応)。受信側
//! (クエリ解析)は圧縮ポインタを追跡してクエリ名を展開できる。
//!
//! 対応リソースレコード種別: `A` / `PTR` / `TXT` / `AAAA` / `SRV`。いずれも
//! `no_std`・ヒープ非依存で、境界外書き込みは panic せず [`Error::NoSpace`] を、
//! 不正入力のデコードは `None` を返す。

use crate::error::{Error, Result};

/// リソースレコード種別: A(IPv4 アドレス)。
pub const T_A: u16 = 1;
/// リソースレコード種別: PTR(ポインタ)。
pub const T_PTR: u16 = 12;
/// リソースレコード種別: TXT(テキスト)。
pub const T_TXT: u16 = 16;
/// リソースレコード種別: AAAA(IPv6 アドレス)。
pub const T_AAAA: u16 = 28;
/// リソースレコード種別: SRV(サービス位置)。
pub const T_SRV: u16 = 33;
/// クエリ種別: ANY(全種別)。
pub const T_ANY: u16 = 255;

/// DNS クラス: IN(インターネット)。
pub const C_IN: u16 = 1;
/// mDNS のキャッシュフラッシュビット(RFC 6762 §10.2)。権威を持つレコードに立てる。
pub const CACHE_FLUSH: u16 = 0x8000;

/// 応答ヘッダのフラグ: QR=1(応答)・AA=1(権威)。
const FLAGS_RESPONSE: u16 = 0x8400;
/// ヘッダの QR ビット。
const FLAG_QR: u16 = 0x8000;
/// DNS メッセージヘッダ長(バイト)。
const HEADER_LEN: usize = 12;

/// レコードを書き込むセクション。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// 回答セクション。
    Answer,
    /// 追加情報セクション。
    Additional,
}

/// `&mut [u8]` 上に DNS 応答メッセージを組み立てるライタ。
///
/// ヘッダ 12 バイトを先頭に予約し、[`Section::Answer`] のレコードを先に、
/// [`Section::Additional`] のレコードを後に書くこと(ワイヤ順 = 書き込み順)。
/// [`finish`](Self::finish) でカウンタを含むヘッダを確定する。
pub struct MsgWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    an: u16,
    ar: u16,
}

impl<'a> MsgWriter<'a> {
    /// バッファ全体を対象にライタを生成する(ヘッダ分の 12 バイトが必要)。
    pub fn new(buf: &'a mut [u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::NoSpace);
        }
        Ok(Self {
            buf,
            pos: HEADER_LEN,
            an: 0,
            ar: 0,
        })
    }

    fn put_u8(&mut self, v: u8) -> Result<()> {
        if self.pos >= self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }

    fn put_u16(&mut self, v: u16) -> Result<()> {
        self.put_slice(&v.to_be_bytes())
    }

    fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put_slice(&v.to_be_bytes())
    }

    fn put_slice(&mut self, src: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(src.len()).ok_or(Error::NoSpace)?;
        if end > self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.pos..end].copy_from_slice(src);
        self.pos = end;
        Ok(())
    }

    /// ラベル列としてドメイン名を書く(各ラベル 1..=63 バイト、末尾に 0)。
    fn put_name(&mut self, labels: &[&[u8]]) -> Result<()> {
        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return Err(Error::NoSpace);
            }
            self.put_u8(label.len() as u8)?;
            self.put_slice(label)?;
        }
        self.put_u8(0)
    }

    fn bump(&mut self, sec: Section) {
        match sec {
            Section::Answer => self.an = self.an.saturating_add(1),
            Section::Additional => self.ar = self.ar.saturating_add(1),
        }
    }

    /// レコードの共通前置き(name / type / class / ttl)を書き、RDLENGTH の位置を返す。
    fn rr_head(&mut self, name: &[&[u8]], rtype: u16, class: u16, ttl: u32) -> Result<usize> {
        self.put_name(name)?;
        self.put_u16(rtype)?;
        self.put_u16(class)?;
        self.put_u32(ttl)?;
        let rdlen_pos = self.pos;
        self.put_u16(0)?; // RDLENGTH プレースホルダ
        Ok(rdlen_pos)
    }

    /// `rdlen_pos` の 2 バイトへ、そこから現在位置までの RDATA 長を書き込む。
    fn patch_rdlen(&mut self, rdlen_pos: usize) -> Result<()> {
        let rdata_len = self.pos - (rdlen_pos + 2);
        let rdata_len = u16::try_from(rdata_len).map_err(|_| Error::NoSpace)?;
        self.buf[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdata_len.to_be_bytes());
        Ok(())
    }

    /// PTR レコードを書く(`name` PTR `target`)。
    pub fn rr_ptr(
        &mut self,
        sec: Section,
        name: &[&[u8]],
        class: u16,
        ttl: u32,
        target: &[&[u8]],
    ) -> Result<()> {
        let rdlen_pos = self.rr_head(name, T_PTR, class, ttl)?;
        self.put_name(target)?;
        self.patch_rdlen(rdlen_pos)?;
        self.bump(sec);
        Ok(())
    }

    /// SRV レコードを書く。
    #[allow(clippy::too_many_arguments)]
    pub fn rr_srv(
        &mut self,
        sec: Section,
        name: &[&[u8]],
        class: u16,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: &[&[u8]],
    ) -> Result<()> {
        let rdlen_pos = self.rr_head(name, T_SRV, class, ttl)?;
        self.put_u16(priority)?;
        self.put_u16(weight)?;
        self.put_u16(port)?;
        self.put_name(target)?;
        self.patch_rdlen(rdlen_pos)?;
        self.bump(sec);
        Ok(())
    }

    /// TXT レコードを書く。各 `(key, value)` は `key=value` の 1 文字列として符号化する。
    /// 空の場合は DNS-SD 慣習に従い長さ 0 の 1 文字列(1 バイトのゼロ)を書く。
    pub fn rr_txt(
        &mut self,
        sec: Section,
        name: &[&[u8]],
        class: u16,
        ttl: u32,
        kvs: &[(&[u8], &[u8])],
    ) -> Result<()> {
        let rdlen_pos = self.rr_head(name, T_TXT, class, ttl)?;
        if kvs.is_empty() {
            self.put_u8(0)?;
        } else {
            for (k, v) in kvs {
                let len = k.len() + 1 + v.len();
                if len > 255 {
                    return Err(Error::NoSpace);
                }
                self.put_u8(len as u8)?;
                self.put_slice(k)?;
                self.put_u8(b'=')?;
                self.put_slice(v)?;
            }
        }
        self.patch_rdlen(rdlen_pos)?;
        self.bump(sec);
        Ok(())
    }

    /// A レコード(IPv4)を書く。
    pub fn rr_a(
        &mut self,
        sec: Section,
        name: &[&[u8]],
        class: u16,
        ttl: u32,
        addr: [u8; 4],
    ) -> Result<()> {
        let rdlen_pos = self.rr_head(name, T_A, class, ttl)?;
        self.put_slice(&addr)?;
        self.patch_rdlen(rdlen_pos)?;
        self.bump(sec);
        Ok(())
    }

    /// AAAA レコード(IPv6)を書く。
    pub fn rr_aaaa(
        &mut self,
        sec: Section,
        name: &[&[u8]],
        class: u16,
        ttl: u32,
        addr: [u8; 16],
    ) -> Result<()> {
        let rdlen_pos = self.rr_head(name, T_AAAA, class, ttl)?;
        self.put_slice(&addr)?;
        self.patch_rdlen(rdlen_pos)?;
        self.bump(sec);
        Ok(())
    }

    /// 回答レコード数(現時点)。
    pub fn answer_count(&self) -> u16 {
        self.an
    }

    /// メッセージを確定し、書き込んだ総バイト数を返す。
    ///
    /// 回答が 1 件も無い場合は `0` を返す(送るべき応答なし)。
    pub fn finish(self) -> usize {
        if self.an == 0 && self.ar == 0 {
            return 0;
        }
        let buf = self.buf;
        buf[0..2].copy_from_slice(&0u16.to_be_bytes()); // ID = 0
        buf[2..4].copy_from_slice(&FLAGS_RESPONSE.to_be_bytes());
        buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // QDCOUNT = 0
        buf[6..8].copy_from_slice(&self.an.to_be_bytes());
        buf[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf[10..12].copy_from_slice(&self.ar.to_be_bytes());
        self.pos
    }
}

/// 展開したドメイン名 1 個(ラベル列)。case-insensitive 比較用。
///
/// 圧縮ポインタは展開済み。ラベル数・総バイト数の上限を超える名前は切り詰められ、
/// [`eq_ci`](Self::eq_ci) では単に一致しなくなる(panic しない)。
pub struct Name {
    data: [u8; Self::DATA_CAP],
    /// 各ラベルの `data` 内 `(start, len)`。
    marks: [(u16, u16); Self::MAX_LABELS],
    n: usize,
}

impl Name {
    const DATA_CAP: usize = 256;
    const MAX_LABELS: usize = 16;

    fn new() -> Self {
        Self {
            data: [0u8; Self::DATA_CAP],
            marks: [(0, 0); Self::MAX_LABELS],
            n: 0,
        }
    }

    /// ラベル数。
    pub fn len(&self) -> usize {
        self.n
    }

    /// ラベルが無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// `i` 番目のラベルのバイト列(範囲外は空スライス)。
    pub fn label(&self, i: usize) -> &[u8] {
        if i >= self.n {
            return &[];
        }
        let (s, l) = self.marks[i];
        &self.data[s as usize..s as usize + l as usize]
    }

    /// 期待するラベル列と ASCII 大文字小文字を無視して一致するか。
    pub fn eq_ci(&self, expected: &[&[u8]]) -> bool {
        if self.n != expected.len() {
            return false;
        }
        for (i, exp) in expected.iter().enumerate() {
            if !self.label(i).eq_ignore_ascii_case(exp) {
                return false;
            }
        }
        true
    }

    fn push_label(&mut self, label: &[u8]) -> bool {
        if self.n >= Self::MAX_LABELS {
            return false;
        }
        // 直前ラベルの末尾を次の start にする(先頭なら 0)。
        let start = if self.n == 0 {
            0
        } else {
            let (s, l) = self.marks[self.n - 1];
            s as usize + l as usize
        };
        if start + label.len() > Self::DATA_CAP {
            return false;
        }
        self.data[start..start + label.len()].copy_from_slice(label);
        self.marks[self.n] = (start as u16, label.len() as u16);
        self.n += 1;
        true
    }
}

/// 受信 DNS メッセージ(クエリ)を読むパーサ。
pub struct Query<'a> {
    pkt: &'a [u8],
    qdcount: u16,
}

impl<'a> Query<'a> {
    /// パケットを検証してクエリとして解釈する。応答(QR=1)や短すぎる入力は `None`。
    pub fn parse(pkt: &'a [u8]) -> Option<Self> {
        if pkt.len() < HEADER_LEN {
            return None;
        }
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        if flags & FLAG_QR != 0 {
            return None; // 応答は無視
        }
        let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
        Some(Self { pkt, qdcount })
    }

    /// 質問セクションのイテレータ。
    pub fn questions(&self) -> Questions<'a> {
        Questions {
            pkt: self.pkt,
            pos: HEADER_LEN,
            left: self.qdcount,
        }
    }
}

/// 質問 1 件。
pub struct Question {
    /// 展開済みの質問名。
    pub name: Name,
    /// 質問種別(`T_*`)。
    pub qtype: u16,
    /// QCLASS の QU ビット(RFC 6762 §5.4)。querier がユニキャスト応答を要求している。
    pub unicast: bool,
}

/// 質問セクションのイテレータ。
pub struct Questions<'a> {
    pkt: &'a [u8],
    pos: usize,
    left: u16,
}

impl Iterator for Questions<'_> {
    type Item = Question;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let mut name = Name::new();
        let after = read_name(self.pkt, self.pos, &mut name)?;
        // 質問名の後に qtype(2) qclass(2)。
        if after + 4 > self.pkt.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([self.pkt[after], self.pkt[after + 1]]);
        let qclass = u16::from_be_bytes([self.pkt[after + 2], self.pkt[after + 3]]);
        self.pos = after + 4;
        self.left -= 1;
        Some(Question {
            name,
            qtype,
            unicast: qclass & 0x8000 != 0,
        })
    }
}

/// 応答メッセージのレコードを走査するリーダ(回答 + 追加情報)。
///
/// 主にテスト・検証用途。権威セクション(NS)は Matter 応答で常に空のため読み飛ばす。
pub struct Response<'a> {
    pkt: &'a [u8],
    ancount: u16,
    arcount: u16,
}

impl<'a> Response<'a> {
    /// パケットを応答として解釈する。短すぎる入力は `None`。
    pub fn parse(pkt: &'a [u8]) -> Option<Self> {
        if pkt.len() < HEADER_LEN {
            return None;
        }
        let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
        // 質問セクションを読み飛ばして最初のレコード位置を求める。
        let mut pos = HEADER_LEN;
        for _ in 0..qdcount {
            let mut n = Name::new();
            pos = read_name(pkt, pos, &mut n)?;
            pos = pos.checked_add(4)?;
        }
        let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
        let arcount = u16::from_be_bytes([pkt[10], pkt[11]]);
        Some(Self {
            pkt,
            ancount,
            arcount,
        })
    }

    /// 回答レコード数。
    pub fn answer_count(&self) -> u16 {
        self.ancount
    }

    /// 追加情報レコード数。
    pub fn additional_count(&self) -> u16 {
        self.arcount
    }

    /// 全レコード(回答 + 追加情報)を走査する。
    pub fn records(&self) -> Records<'a> {
        // 最初のレコード位置を再計算する。
        let qdcount = u16::from_be_bytes([self.pkt[4], self.pkt[5]]);
        let mut pos = HEADER_LEN;
        for _ in 0..qdcount {
            let mut n = Name::new();
            match read_name(self.pkt, pos, &mut n) {
                Some(p) => pos = p + 4,
                None => break,
            }
        }
        Records {
            pkt: self.pkt,
            pos,
            left: self.ancount as u32 + self.arcount as u32,
        }
    }
}

/// 1 リソースレコード。
pub struct Record<'a> {
    /// 展開済みのオーナ名。
    pub name: Name,
    /// レコード種別(`T_*`)。
    pub rtype: u16,
    /// クラス(下位ビットが IN、`CACHE_FLUSH` ビットを含みうる)。
    pub class: u16,
    /// TTL(秒)。
    pub ttl: u32,
    /// RDATA バイト列。
    pub rdata: &'a [u8],
    /// パケット先頭からの RDATA 開始オフセット(RDATA 内の名前展開に使う)。
    pub rdata_offset: usize,
    pkt: &'a [u8],
}

impl Record<'_> {
    /// RDATA を(圧縮を追跡して)ドメイン名として展開する(PTR の対象名など)。
    pub fn rdata_name(&self) -> Option<Name> {
        let mut n = Name::new();
        read_name(self.pkt, self.rdata_offset, &mut n)?;
        Some(n)
    }

    /// SRV RDATA の `(priority, weight, port)` とターゲット名を返す。
    pub fn srv(&self) -> Option<(u16, u16, u16, Name)> {
        if self.rdata.len() < 6 {
            return None;
        }
        let priority = u16::from_be_bytes([self.rdata[0], self.rdata[1]]);
        let weight = u16::from_be_bytes([self.rdata[2], self.rdata[3]]);
        let port = u16::from_be_bytes([self.rdata[4], self.rdata[5]]);
        let mut n = Name::new();
        read_name(self.pkt, self.rdata_offset + 6, &mut n)?;
        Some((priority, weight, port, n))
    }

    /// TXT RDATA に `key=value` 文字列が含まれるか(case-sensitive な完全一致)。
    pub fn txt_contains(&self, entry: &[u8]) -> bool {
        let mut i = 0;
        while i < self.rdata.len() {
            let len = self.rdata[i] as usize;
            i += 1;
            if i + len > self.rdata.len() {
                return false;
            }
            if &self.rdata[i..i + len] == entry {
                return true;
            }
            i += len;
        }
        false
    }
}

/// [`Response::records`] のイテレータ。
pub struct Records<'a> {
    pkt: &'a [u8],
    pos: usize,
    left: u32,
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let mut name = Name::new();
        let after = read_name(self.pkt, self.pos, &mut name)?;
        if after + 10 > self.pkt.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([self.pkt[after], self.pkt[after + 1]]);
        let class = u16::from_be_bytes([self.pkt[after + 2], self.pkt[after + 3]]);
        let ttl = u32::from_be_bytes([
            self.pkt[after + 4],
            self.pkt[after + 5],
            self.pkt[after + 6],
            self.pkt[after + 7],
        ]);
        let rdlen = u16::from_be_bytes([self.pkt[after + 8], self.pkt[after + 9]]) as usize;
        let rdata_offset = after + 10;
        if rdata_offset + rdlen > self.pkt.len() {
            return None;
        }
        let rdata = &self.pkt[rdata_offset..rdata_offset + rdlen];
        self.pos = rdata_offset + rdlen;
        self.left -= 1;
        Some(Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
            rdata_offset,
            pkt: self.pkt,
        })
    }
}

/// `pkt` の `start` からドメイン名を読み、`out` に展開する。圧縮ポインタを追跡する。
///
/// 戻り値は「元ストリーム上で名前の直後に続く位置」(質問カーソルの前進に使う)。
/// 不正(範囲外・ラベル長超過・ポインタループ)は `None`。
fn read_name(pkt: &[u8], start: usize, out: &mut Name) -> Option<usize> {
    let mut pos = start;
    let mut after: Option<usize> = None;
    // ループ検出: ポインタ追跡の総回数に上限を設ける。
    let mut guard = 0usize;
    let max_guard = pkt.len() + 16;

    loop {
        guard += 1;
        if guard > max_guard {
            return None;
        }
        let b = *pkt.get(pos)?;
        if b & 0xC0 == 0xC0 {
            // 圧縮ポインタ(2 バイト)。
            let b2 = *pkt.get(pos + 1)?;
            let ptr = (((b & 0x3F) as usize) << 8) | b2 as usize;
            if after.is_none() {
                after = Some(pos + 2);
            }
            if ptr >= pkt.len() {
                return None;
            }
            pos = ptr;
        } else if b == 0 {
            if after.is_none() {
                after = Some(pos + 1);
            }
            break;
        } else {
            let len = b as usize;
            if len > 63 {
                return None;
            }
            let s = pos + 1;
            let e = s + len;
            if e > pkt.len() {
                return None;
            }
            if !out.push_label(&pkt[s..e]) {
                return None;
            }
            pos = e;
        }
    }
    after
}

// ==========================================================================
// クエリ生成 / 型付きレコードアクセサ(`controller` feature 専用の追加)
//
// `docs/design/controller.md` §5.2 に基づく discovery クライアント向けの拡張。
// 既存の [`MsgWriter`](応答専用・QR=1)には一切手を入れず、別ビルダ [`QueryWriter`]
// と [`Record`] への追加メソッドだけで実現する(§2.3 の cfg 規律:「既存関数の
// オブジェクトコードを変えない」ため、応答専用ビルダの分岐化ではなく型追加を採る)。
// ==========================================================================

/// 質問(Question)セクションの QU ビット(RFC 6762 §5.4)。unicast 応答を要求する。
#[cfg(feature = "controller")]
pub const QU_UNICAST: u16 = 0x8000;

/// `&mut [u8]` 上に DNS **クエリ**メッセージ(QR=0)を組み立てるライタ。
///
/// [`MsgWriter`](応答専用)の鏡像。ヘッダ 12 バイトを予約し、[`question`](Self::question)
/// で質問を追記、[`finish`](Self::finish) で QDCOUNT を含むヘッダを確定する。境界外書き込みは
/// panic せず [`Error::NoSpace`] を返す。
#[cfg(feature = "controller")]
pub struct QueryWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    qd: u16,
}

#[cfg(feature = "controller")]
impl<'a> QueryWriter<'a> {
    /// バッファ全体を対象にクエリライタを生成する(ヘッダ分の 12 バイトが必要)。
    pub fn new(buf: &'a mut [u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(Error::NoSpace);
        }
        Ok(Self {
            buf,
            pos: HEADER_LEN,
            qd: 0,
        })
    }

    fn put_u8(&mut self, v: u8) -> Result<()> {
        if self.pos >= self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.pos] = v;
        self.pos += 1;
        Ok(())
    }

    fn put_u16(&mut self, v: u16) -> Result<()> {
        self.put_slice(&v.to_be_bytes())
    }

    fn put_slice(&mut self, src: &[u8]) -> Result<()> {
        let end = self.pos.checked_add(src.len()).ok_or(Error::NoSpace)?;
        if end > self.buf.len() {
            return Err(Error::NoSpace);
        }
        self.buf[self.pos..end].copy_from_slice(src);
        self.pos = end;
        Ok(())
    }

    fn put_name(&mut self, labels: &[&[u8]]) -> Result<()> {
        for label in labels {
            if label.is_empty() || label.len() > 63 {
                return Err(Error::NoSpace);
            }
            self.put_u8(label.len() as u8)?;
            self.put_slice(label)?;
        }
        self.put_u8(0)
    }

    /// 質問を 1 件書く(`name` QTYPE=`qtype` QCLASS=IN)。
    ///
    /// `unicast_response` が `true` なら QCLASS の QU ビット([`QU_UNICAST`])を立てる。
    pub fn question(&mut self, name: &[&[u8]], qtype: u16, unicast_response: bool) -> Result<()> {
        self.put_name(name)?;
        self.put_u16(qtype)?;
        let qclass = if unicast_response {
            C_IN | QU_UNICAST
        } else {
            C_IN
        };
        self.put_u16(qclass)?;
        self.qd = self.qd.saturating_add(1);
        Ok(())
    }

    /// 質問数(現時点)。
    pub fn question_count(&self) -> u16 {
        self.qd
    }

    /// メッセージを確定し、書き込んだ総バイト数を返す。
    ///
    /// 質問が 1 件も無い場合は `0` を返す(送るべきクエリなし)。
    pub fn finish(self) -> usize {
        if self.qd == 0 {
            return 0;
        }
        let buf = self.buf;
        buf[0..2].copy_from_slice(&0u16.to_be_bytes()); // ID = 0
        buf[2..4].copy_from_slice(&0u16.to_be_bytes()); // FLAGS = 0(QR=0, 標準クエリ)
        buf[4..6].copy_from_slice(&self.qd.to_be_bytes()); // QDCOUNT
        buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        buf[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        buf[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
        self.pos
    }
}

/// TXT RDATA を `key`/`value` ペアとして走査するイテレータ([`Record::txt_entries`])。
///
/// 各文字列を最初の `=` で分割する。`=` を含まない文字列は `(全体, &[])` を返す。
/// 空文字列(長さ 0)は読み飛ばす。
#[cfg(feature = "controller")]
pub struct TxtEntries<'a> {
    rdata: &'a [u8],
    pos: usize,
}

#[cfg(feature = "controller")]
impl<'a> Iterator for TxtEntries<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.rdata.len() {
            let len = self.rdata[self.pos] as usize;
            self.pos += 1;
            let end = self.pos.checked_add(len)?;
            if end > self.rdata.len() {
                return None;
            }
            let s = &self.rdata[self.pos..end];
            self.pos = end;
            if s.is_empty() {
                continue;
            }
            return match s.iter().position(|&b| b == b'=') {
                Some(eq) => Some((&s[..eq], &s[eq + 1..])),
                None => Some((s, &[])),
            };
        }
        None
    }
}

#[cfg(feature = "controller")]
impl<'a> Record<'a> {
    /// A レコード(TYPE=1)の IPv4 アドレス 4 バイトを返す。種別違い/長さ不足は `None`。
    pub fn a(&self) -> Option<[u8; 4]> {
        if self.rtype != T_A || self.rdata.len() < 4 {
            return None;
        }
        let mut o = [0u8; 4];
        o.copy_from_slice(&self.rdata[..4]);
        Some(o)
    }

    /// AAAA レコード(TYPE=28)の IPv6 アドレス 16 バイトを返す。種別違い/長さ不足は `None`。
    pub fn aaaa(&self) -> Option<[u8; 16]> {
        if self.rtype != T_AAAA || self.rdata.len() < 16 {
            return None;
        }
        let mut o = [0u8; 16];
        o.copy_from_slice(&self.rdata[..16]);
        Some(o)
    }

    /// TXT RDATA を `key`/`value` ペアとして走査する([`txt_contains`](Self::txt_contains) の一般化)。
    pub fn txt_entries(&self) -> TxtEntries<'a> {
        TxtEntries {
            rdata: self.rdata,
            pos: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ptr_and_parse_question() {
        // PTR 応答を書き、質問メッセージを別途作ってパースする往復。
        let mut buf = [0u8; 512];
        let mut w = MsgWriter::new(&mut buf).unwrap();
        w.rr_ptr(
            Section::Answer,
            &[b"_matterc", b"_udp", b"local"],
            C_IN,
            120,
            &[b"ABCD", b"_matterc", b"_udp", b"local"],
        )
        .unwrap();
        let len = w.finish();
        assert!(len > HEADER_LEN);
        // ヘッダ: QR=1, AA=1, ANCOUNT=1。
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), FLAGS_RESPONSE);
        assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1);
    }

    /// 固定バッファに DNS メッセージを組み立てる小さなヘルパ。
    struct Pkt {
        buf: [u8; 256],
        len: usize,
    }
    impl Pkt {
        fn new() -> Self {
            Self {
                buf: [0u8; 256],
                len: 0,
            }
        }
        fn push(&mut self, b: u8) {
            self.buf[self.len] = b;
            self.len += 1;
        }
        fn extend(&mut self, s: &[u8]) {
            self.buf[self.len..self.len + s.len()].copy_from_slice(s);
            self.len += s.len();
        }
        fn as_slice(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    #[test]
    fn parses_question_name_and_type() {
        // 手組みのクエリ: header + 1 question (_matterc._udp.local PTR)。
        let mut pkt = Pkt::new();
        pkt.extend(&[0, 0]); // id
        pkt.extend(&0u16.to_be_bytes()); // flags QR=0
        pkt.extend(&1u16.to_be_bytes()); // qd=1
        pkt.extend(&[0, 0, 0, 0, 0, 0]); // an/ns/ar
        for label in [b"_matterc".as_ref(), b"_udp", b"local"] {
            pkt.push(label.len() as u8);
            pkt.extend(label);
        }
        pkt.push(0);
        pkt.extend(&T_PTR.to_be_bytes());
        pkt.extend(&C_IN.to_be_bytes());

        let q = Query::parse(pkt.as_slice()).unwrap();
        let mut it = q.questions();
        let question = it.next().unwrap();
        assert_eq!(question.qtype, T_PTR);
        assert!(question.name.eq_ci(&[b"_matterc", b"_udp", b"local"]));
        assert!(!question.name.eq_ci(&[b"_matter", b"_tcp", b"local"]));
        assert!(it.next().is_none());
    }

    #[test]
    fn rejects_response_messages() {
        let mut pkt = [0u8; 12];
        pkt[2..4].copy_from_slice(&FLAG_QR.to_be_bytes());
        assert!(Query::parse(&pkt).is_none());
    }

    #[test]
    fn follows_compression_pointer() {
        // 質問1 = "local"(offset 12)。質問2 = "x" + 質問1 の "local" へのポインタ。
        let mut pkt = Pkt::new();
        pkt.extend(&[0, 0]);
        pkt.extend(&0u16.to_be_bytes()); // flags QR=0
        pkt.extend(&2u16.to_be_bytes()); // qd=2
        pkt.extend(&[0, 0, 0, 0, 0, 0]); // header 12 bytes total
        let local_at = pkt.len; // 12: "local" ラベルの位置
        pkt.push(5);
        pkt.extend(b"local");
        pkt.push(0);
        pkt.extend(&T_A.to_be_bytes());
        pkt.extend(&C_IN.to_be_bytes());
        // 質問2: "x" then pointer to local_at
        pkt.push(1);
        pkt.push(b'x');
        pkt.push(0xC0);
        pkt.push(local_at as u8);
        pkt.extend(&T_SRV.to_be_bytes());
        pkt.extend(&C_IN.to_be_bytes());

        let q = Query::parse(pkt.as_slice()).unwrap();
        let mut it = q.questions();
        let q1 = it.next().unwrap();
        assert!(q1.name.eq_ci(&[b"local"]));
        let q2 = it.next().unwrap();
        assert!(q2.name.eq_ci(&[b"x", b"local"]));
        assert_eq!(q2.qtype, T_SRV);
        assert!(it.next().is_none());
    }

    #[test]
    fn malformed_names_do_not_panic() {
        // ラベル長がバッファを超えるケース。
        let mut pkt = [0u8; 20];
        pkt[4..6].copy_from_slice(&1u16.to_be_bytes()); // qd=1
        pkt[12] = 60; // 長さ 60 だが後続が足りない
        let q = Query::parse(&pkt).unwrap();
        assert!(q.questions().next().is_none());
    }

    #[test]
    fn writer_reports_nospace() {
        let mut small = [0u8; 8];
        assert!(MsgWriter::new(&mut small).is_err());
    }
}
