//! ESP-IDF NVS パーティション形式の **読み取り専用** パーサ(no_std・ヒープレス)。
//!
//! フラッシュ内容の `&[u8]` スライスから、指定 namespace / キーの値を **ゼロコピー**で
//! 引く(可変長値は元スライスへの `&[u8]` を返す)。工場データ(`chip-factory`
//! namespace)の読み出しを想定する。
//!
//! # 対応範囲
//!
//! - ページ状態 ACTIVE / FULL のエントリを走査する(UNINITIALIZED はスキップ)。
//! - エントリ状態は written のみ採用(erased / empty は無視)。
//! - 固定長型: `U8/U16/U32/U64/I8/I16/I32/I64`。
//! - 可変長型: `SZ`(文字列)・`BLOB_DATA`(単一チャンク)。
//!
//! # 非対応(割り切り)
//!
//! - **暗号化 NVS はスコープ外**(平文パーティションのみ)。
//! - 複数チャンクに分割された BLOB(> 約 4000 バイト)は非対応
//!   ([`NvsReader::get_bytes`] は先頭チャンクのみ返す)。工場データの証明書は
//!   いずれも単一チャンク(< 600 バイト)に収まる。
//! - エントリ CRC32 は検証しない(フラッシュ健全性は下位層の責務とする割り切り)。
//!
//! # フォーマット要点(実 `esp-matter-mfg-tool` 生成物で裏取り)
//!
//! - ページ = 4096 バイト。先頭 32 バイトがページヘッダ(先頭 u32 が状態)、続く 32
//!   バイトがエントリ状態ビットマップ(2 ビット × 126 エントリ)、以降 126 個の
//!   32 バイトエントリ。
//! - エントリ: `[0]=NsIndex [1]=Type [2]=Span [3]=ChunkIndex [4..8]=CRC32`
//!   `[8..24]=Key(NUL 詰め 16B) [24..32]=Data`。可変長型は Data の `[0..2]` が
//!   サイズ(u16 LE)で、本体は後続エントリ領域に連続配置される。
//! - namespace は `NsIndex=0 / Type=U8` のエントリが「名前 → インデックス」を定義する。

/// NVS ページサイズ(バイト)。
const PAGE_SIZE: usize = 4096;
/// ページヘッダ長(バイト)。
const PAGE_HEADER_LEN: usize = 32;
/// エントリ状態ビットマップ長(バイト)。
const ENTRY_BITMAP_LEN: usize = 32;
/// 1 エントリのサイズ(バイト)。
const ENTRY_SIZE: usize = 32;
/// 1 ページあたりのエントリ数。
const ENTRIES_PER_PAGE: usize = 126;
/// エントリ領域の先頭オフセット(ヘッダ + ビットマップ)。
const ENTRY_DATA_OFFSET: usize = PAGE_HEADER_LEN + ENTRY_BITMAP_LEN;

/// ページ状態: ACTIVE(書き込み中の現行ページ)。
const PAGE_STATE_ACTIVE: u32 = 0xFFFF_FFFE;
/// ページ状態: FULL(満杯で確定済み)。
const PAGE_STATE_FULL: u32 = 0xFFFF_FFF8;

/// エントリ状態: written。
const ENTRY_WRITTEN: u8 = 0b10;

/// NVS エントリ型コード。
#[allow(dead_code)]
mod ty {
    pub const U8: u8 = 0x01;
    pub const U16: u8 = 0x02;
    pub const U32: u8 = 0x04;
    pub const U64: u8 = 0x08;
    pub const I8: u8 = 0x11;
    pub const I16: u8 = 0x12;
    pub const I32: u8 = 0x14;
    pub const I64: u8 = 0x18;
    /// null 終端文字列。
    pub const SZ: u8 = 0x21;
    /// BLOB の単一データチャンク。
    pub const BLOB_DATA: u8 = 0x42;
    /// BLOB のインデックス(チャンク数・総サイズ)。本パーサでは読み飛ばす。
    pub const BLOB_IDX: u8 = 0x48;
}

/// 走査中の 1 エントリ(ヘッダ + Data フィールド + 可変長本体スライス)。
struct RawEntry<'a> {
    ns_index: u8,
    type_code: u8,
    chunk_index: u8,
    key: &'a [u8],
    /// エントリの 8 バイト Data フィールド。
    data_field: &'a [u8],
    /// 可変長型のときの本体スライス(固定長型では空)。
    payload: &'a [u8],
}

/// ESP-IDF NVS パーティションの読み取り専用ビュー。
///
/// `data` はパーティション先頭からのフラッシュ内容。ページ境界(4096)に整列している
/// 前提。末尾が満たない場合、そのページは無視する。
#[derive(Clone, Copy)]
pub struct NvsReader<'a> {
    data: &'a [u8],
}

impl<'a> NvsReader<'a> {
    /// パーティション内容からリーダを作る。
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// 書き込み済みエントリを走査し、`f` が `Some` を返した時点で終了する。
    fn scan<T>(&self, mut f: impl FnMut(&RawEntry<'a>) -> Option<T>) -> Option<T> {
        let mut page_start = 0;
        while page_start + PAGE_SIZE <= self.data.len() {
            let page = &self.data[page_start..page_start + PAGE_SIZE];
            let state = u32::from_le_bytes([page[0], page[1], page[2], page[3]]);
            if state == PAGE_STATE_ACTIVE || state == PAGE_STATE_FULL {
                if let Some(v) = self.scan_page(page, &mut f) {
                    return Some(v);
                }
            }
            page_start += PAGE_SIZE;
        }
        None
    }

    /// 1 ページ内のエントリを走査する。
    fn scan_page<T>(
        &self,
        page: &'a [u8],
        f: &mut impl FnMut(&RawEntry<'a>) -> Option<T>,
    ) -> Option<T> {
        let bitmap = &page[PAGE_HEADER_LEN..PAGE_HEADER_LEN + ENTRY_BITMAP_LEN];
        let mut i = 0;
        while i < ENTRIES_PER_PAGE {
            let st = (bitmap[i / 4] >> ((i % 4) * 2)) & 0b11;
            if st != ENTRY_WRITTEN {
                i += 1;
                continue;
            }
            let off = ENTRY_DATA_OFFSET + i * ENTRY_SIZE;
            let e = &page[off..off + ENTRY_SIZE];
            let type_code = e[1];
            let span = e[2].max(1) as usize;
            let chunk_index = e[3];
            let key_full = &e[8..24];
            let key_len = key_full.iter().position(|&b| b == 0).unwrap_or(key_full.len());
            let data_field = &e[24..32];

            // 可変長型は Data[0..2] がサイズ。本体は後続エントリ領域に連続配置。
            let payload: &[u8] = if matches!(type_code, ty::SZ | ty::BLOB_DATA) {
                let size = u16::from_le_bytes([data_field[0], data_field[1]]) as usize;
                let body_start = off + ENTRY_SIZE;
                let body_end = body_start + size;
                if body_end <= page.len() {
                    &page[body_start..body_end]
                } else {
                    &[]
                }
            } else {
                &[]
            };

            let entry = RawEntry {
                ns_index: e[0],
                type_code,
                chunk_index,
                key: &key_full[..key_len],
                data_field,
                payload,
            };
            if let Some(v) = f(&entry) {
                return Some(v);
            }
            i += span;
        }
        None
    }

    /// namespace 名からインデックスを解決する(`NsIndex=0 / Type=U8` エントリ)。
    fn namespace_index(&self, name: &str) -> Option<u8> {
        self.scan(|e| {
            if e.ns_index == 0 && e.type_code == ty::U8 && e.key == name.as_bytes() {
                Some(e.data_field[0])
            } else {
                None
            }
        })
    }

    /// 指定 namespace / キーの u32 値を返す(固定長型)。
    pub fn get_u32(&self, namespace: &str, key: &str) -> Option<u32> {
        let ns = self.namespace_index(namespace)?;
        self.scan(|e| {
            if e.ns_index == ns && e.type_code == ty::U32 && e.key == key.as_bytes() {
                Some(u32::from_le_bytes([
                    e.data_field[0],
                    e.data_field[1],
                    e.data_field[2],
                    e.data_field[3],
                ]))
            } else {
                None
            }
        })
    }

    /// 指定 namespace / キーの文字列値(SZ)を返す。末尾 NUL は除く。
    pub fn get_str(&self, namespace: &str, key: &str) -> Option<&'a [u8]> {
        let ns = self.namespace_index(namespace)?;
        self.scan(|e| {
            if e.ns_index == ns && e.type_code == ty::SZ && e.key == key.as_bytes() {
                // 末尾 NUL を除去。
                let s = e.payload;
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                Some(&s[..end])
            } else {
                None
            }
        })
    }

    /// 指定 namespace / キーの BLOB(単一チャンク)を返す。
    ///
    /// `BLOB_DATA`(型 0x42)の先頭チャンク(chunk 0)本体をゼロコピーで返す。
    /// `BLOB_IDX`(型 0x48)は読み飛ばす。複数チャンク分割は非対応(先頭のみ)。
    pub fn get_blob(&self, namespace: &str, key: &str) -> Option<&'a [u8]> {
        let ns = self.namespace_index(namespace)?;
        self.scan(|e| {
            if e.ns_index == ns
                && e.type_code == ty::BLOB_DATA
                && e.chunk_index == 0
                && e.key == key.as_bytes()
            {
                Some(e.payload)
            } else {
                None
            }
        })
    }

    /// 指定 namespace が存在するか。
    pub fn has_namespace(&self, name: &str) -> bool {
        self.namespace_index(name).is_some()
    }
}
