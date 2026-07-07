//! CASE session resumption の状態保持(`docs/design/secure-channel.md` §7.4)。
//!
//! フル CASE で確立した `SharedSecret` と `resumptionID` を固定容量ストアに保持し、
//! 再接続時の Sigma2_Resume 経路(Matter 仕様 §4.14.4)に供する。
//!
//! - **キー**: `(fabric_index, peer_node_id)` で upsert(同一ピアは常に 1 レコード)。
//! - **容量と追い出し**: 既定 [`RESUMPTION_CACHE_LEN`] = 4 レコード。満杯時は挿入順が
//!   最も古いレコードを追い出す(FIFO。u32 単調 seq で判定)。追い出されたピアはフル CASE
//!   へフォールバックするだけで機能劣化はない。
//! - `shared_secret` は [`Zeroizing`] で drop 時にゼロ化する。
//!
//! # KVS 永続化(設計 §7.4)
//!
//! [`ResumptionStore::save_to`] / [`ResumptionStore::load_from`] で KVS に versioned TLV
//! で書き出し・復元する(単一キー `b"rsmp"`)。分業は fabric 永続化
//! ([`crate::fabric::FabricTable::save_to`])と同じ: **いつ・どこに保存するかはアプリ層**
//! (コアは export/import のみ)。アプリ層は [`ResumptionStore::generation`] の変化を検知して
//! `save_to` を呼ぶ。永続化しなくてもプロセス再起動でフル CASE へフォールバックするだけで
//! 機能劣化はない(永続化は resumption によるハンドシェイク削減を再起動後も効かせるため)。
//!
//! **セキュリティ注記**: `shared_secret` を flash に平文で置くと、物理アクセスで CASE
//! セッションを再確立できる素材になる。ただし同じ flash に NOC 運用秘密鍵・IPK も置いており
//! (fabric 永続化)、脅威モデル上の追加露出は限定的。プラットフォームの flash 暗号化
//! (ESP32 Flash Encryption 等)での保護を推奨する。

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kvs::Kvs;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::fixed::FixedVec;

use super::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};

/// 既定のレコード容量(設計 §7.4。1 レコード ≈ 60 B)。
pub const RESUMPTION_CACHE_LEN: usize = 4;

/// 永続化フォーマットの schema version(外側 struct cx0)。
pub const RESUMPTION_SCHEMA_VERSION: u8 = 1;

/// 永続化キー(単一キー・全レコードを 1 レコードの TLV 配列で持つ)。
const RESUMPTION_KEY: &[u8] = b"rsmp";

/// 1 レコードの TLV エンコード上限(バイト)。
///
/// struct 開始/終了(2)+ fabric_index(2)+ peer_node_id(9)+ resumption_id(18)
/// + shared_secret(34)に余裕を持たせた値。
pub const MAX_RESUMPTION_RECORD_LEN: usize = 72;

/// ストア全体の TLV エンコード上限(外側 struct + [`RESUMPTION_CACHE_LEN`] レコード分)。
///
/// `save_to` / `load_from` の固定長スタックバッファのサイズに使う。既定容量
/// [`RESUMPTION_CACHE_LEN`] を前提にサイズする(それより大きい `N` を使う場合は
/// エンコードが [`Error::NoSpace`] になり得る)。
pub const RESUMPTION_STORE_BUF_LEN: usize = 16 + RESUMPTION_CACHE_LEN * MAX_RESUMPTION_RECORD_LEN;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// 1 ピアぶんの resumption レコード。
pub struct ResumptionRecord {
    /// 所属 fabric(fabric が削除された場合、照合時に無効化される)。
    pub fabric_index: NonZeroU8,
    /// 相手の operational NodeId(fabric スコープ)。
    pub peer_node_id: u64,
    /// 現行 resumptionID(セッション確立ごとにローテートする)。
    pub resumption_id: [u8; CASE_RESUMPTION_ID_LEN],
    /// フル CASE の ECDH SharedSecret(resumption を繰り返しても不変)。
    pub shared_secret: Zeroizing<[u8; SHARED_SECRET_LEN]>,
    /// 挿入順(FIFO 追い出し判定)。
    seq: u32,
}

/// 固定容量の resumption レコードストア(メモリ内のみ)。
pub struct ResumptionStore<const N: usize = RESUMPTION_CACHE_LEN> {
    records: FixedVec<ResumptionRecord, N>,
    next_seq: u32,
    /// 内容変化のたびに単調増加する世代番号(永続化のトリガ判定用)。
    /// [`FabricTable::generation`](crate::fabric::FabricTable::generation) と同じ用途。
    generation: u32,
}

impl<const N: usize> Default for ResumptionStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ResumptionStore<N> {
    /// 空のストアを生成する。
    pub const fn new() -> Self {
        Self {
            records: FixedVec::new(),
            next_seq: 0,
            generation: 0,
        }
    }

    /// 内容変化のたびに単調増加する世代番号。
    ///
    /// アプリ層はこの値の変化を検知して [`ResumptionStore::save_to`] を呼ぶ
    /// (`save` / `remove_fabric` / `load_from` で内容が変わったときに増える)。
    /// [`load_from`](Self::load_from) は復元 1 件ごとに `save` を通すため generation を
    /// 進める。したがってアプリ層は **復元後の** `generation()` を保存トリガの基準値に取ること
    /// (復元直後に不要な再保存が走らないように)。
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// 保持レコード数。
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// レコードが 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// `(fabric_index, peer_node_id)` で upsert する。
    ///
    /// 既存レコードがあれば resumptionID / SharedSecret を差し替える(ローテート)。
    /// 満杯なら挿入順が最も古いレコードを追い出して入れる(FIFO)。
    pub fn save(
        &mut self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
        resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
        shared_secret: &[u8; SHARED_SECRET_LEN],
    ) {
        // 内容が変わる(upsert は常に ID/secret/seq を差し替える)ので generation を進める。
        self.generation = self.generation.wrapping_add(1);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let existing = self
            .records
            .iter()
            .position(|r| r.fabric_index == fabric_index && r.peer_node_id == peer_node_id);
        if let Some(r) = existing.and_then(|i| self.records.get_mut(i)) {
            r.resumption_id = *resumption_id;
            *r.shared_secret = *shared_secret;
            r.seq = seq;
            return;
        }
        let record = ResumptionRecord {
            fabric_index,
            peer_node_id,
            resumption_id: *resumption_id,
            shared_secret: Zeroizing::new(*shared_secret),
            seq,
        };
        if self.records.push(record).is_err() {
            // 満杯: 挿入順が最も古い(seq が next_seq から最も遠い)レコードを追い出す。
            // wrapping 距離で比較するため u32 ラップ後も正しく最古を選ぶ。
            if let Some(oldest) =
                (0..self.records.len()).max_by_key(|&i| seq.wrapping_sub(self.records[i].seq))
            {
                self.records[oldest] = ResumptionRecord {
                    fabric_index,
                    peer_node_id,
                    resumption_id: *resumption_id,
                    shared_secret: Zeroizing::new(*shared_secret),
                    seq,
                };
            }
        }
    }

    /// resumptionID でレコードを引く(responder の Sigma1 入口照合)。
    pub fn find_by_id(
        &self,
        resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    ) -> Option<&ResumptionRecord> {
        self.records
            .iter()
            .find(|r| r.resumption_id == *resumption_id)
    }

    /// `(fabric_index, peer_node_id)` でレコードを引く(initiator の `start_case`)。
    pub fn find_by_peer(
        &self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
    ) -> Option<&ResumptionRecord> {
        self.records
            .iter()
            .find(|r| r.fabric_index == fabric_index && r.peer_node_id == peer_node_id)
    }

    /// `fabric_index` に属するレコードをすべて破棄する(fabric 削除時の後始末用)。
    pub fn remove_fabric(&mut self, fabric_index: NonZeroU8) {
        loop {
            let pos = self
                .records
                .iter()
                .position(|r| r.fabric_index == fabric_index);
            match pos {
                Some(i) => {
                    let _ = self.records.swap_remove(i);
                    // 内容が変わったので永続化トリガ用の generation を進める。
                    self.generation = self.generation.wrapping_add(1);
                }
                None => break,
            }
        }
    }

    /// ストア全体を `kvs` へ versioned TLV で保存する(単一キー `b"rsmp"`)。
    ///
    /// レコードが 0 件のときはキーを削除する(削除済みレコードがリブート後に復活しない
    /// ように。fabric 永続化の空スロット削除と同じ発想)。呼び出しタイミングはアプリ層の
    /// 責務: [`generation`](Self::generation) の変化を検知して呼ぶ(設計 §7.4)。
    ///
    /// エンコードバッファ([`RESUMPTION_STORE_BUF_LEN`] バイト)は `shared_secret` を
    /// 平文で載せるため、スコープ抜けで [`Zeroizing`] によりゼロ化する。
    pub fn save_to<K: Kvs>(&self, kvs: &mut K) -> Result<()> {
        if self.records.is_empty() {
            return kvs.remove(RESUMPTION_KEY);
        }
        let mut buf = Zeroizing::new([0u8; RESUMPTION_STORE_BUF_LEN]);
        let len = {
            let mut w = TlvWriter::new(&mut buf[..]);
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), RESUMPTION_SCHEMA_VERSION)?;
            w.start_array(&cx(1))?;
            for rec in self.records.iter() {
                w.start_struct(&TlvTag::Anonymous)?;
                w.write_u8(&cx(1), rec.fabric_index.get())?;
                w.write_u64(&cx(2), rec.peer_node_id)?;
                w.write_bytes(&cx(3), &rec.resumption_id)?;
                w.write_bytes(&cx(4), &rec.shared_secret[..])?;
                w.end_container()?;
            }
            w.end_container()?;
            w.end_container()?;
            w.len()
        };
        kvs.set(RESUMPTION_KEY, &buf[..len])
    }

    /// `kvs` からストアを復元し、復元件数を返す(空ストアにのみ呼べる)。
    ///
    /// - 非空ストアには [`Error::InvalidState`](空でなければ復元しない。fabric 同様)。
    /// - キーが無ければ「初回起動 / 未保存」として `Ok(0)`。
    /// - schema version 不一致・レコード破損は [`Error::Decode`]。
    /// - 復元は [`save`](Self::save) を通す(FIFO seq を配列順で振り直す)。そのため
    ///   復元後の [`generation`](Self::generation) は進んでいる — アプリ層はこの値を保存
    ///   トリガの基準値に取ること(復元直後に再保存が走らないように)。
    ///
    /// デコードバッファは `shared_secret` を平文で載せるため [`Zeroizing`] でゼロ化する。
    pub fn load_from<K: Kvs>(&mut self, kvs: &mut K) -> Result<usize> {
        if !self.records.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut buf = Zeroizing::new([0u8; RESUMPTION_STORE_BUF_LEN]);
        let len = match kvs.get(RESUMPTION_KEY, &mut buf[..])? {
            Some(l) => l,
            None => return Ok(0),
        };
        let mut r = TlvReader::new(&buf[..len]);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut version: Option<u8> = None;
        let mut restored = 0usize;
        loop {
            let e = r.read_next()?.ok_or(Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => {
                    version = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                    if version != Some(RESUMPTION_SCHEMA_VERSION) {
                        return Err(Error::Decode);
                    }
                }
                (TlvTag::ContextSpecific(1), TlvValue::ContainerStart(ContainerType::Array)) => {
                    loop {
                        let el = r.read_next()?.ok_or(Error::Decode)?;
                        match el.value {
                            TlvValue::ContainerEnd => break,
                            TlvValue::ContainerStart(ContainerType::Structure) => {
                                let (fabric_index, peer_node_id, rid, secret) =
                                    decode_record(&mut r)?;
                                self.save(fabric_index, peer_node_id, &rid, &secret);
                                restored += 1;
                            }
                            _ => return Err(Error::Decode),
                        }
                    }
                }
                _ => r.skip(&e)?,
            }
        }
        if version.is_none() {
            return Err(Error::Decode);
        }
        Ok(restored)
    }
}

/// 配列内 1 レコードの struct 本体をデコードする(struct 開始は呼び出し側が消費済み)。
///
/// `shared_secret` はスタック上のローカルにコピーする(呼び出し側が [`save`] へ渡すと
/// [`ResumptionRecord`] 内で [`Zeroizing`] に包まれる)。
type DecodedRecord = (
    NonZeroU8,
    u64,
    [u8; CASE_RESUMPTION_ID_LEN],
    [u8; SHARED_SECRET_LEN],
);

fn decode_record(r: &mut TlvReader<'_>) -> Result<DecodedRecord> {
    let mut fabric_index: Option<u8> = None;
    let mut peer_node_id: Option<u64> = None;
    let mut rid: Option<[u8; CASE_RESUMPTION_ID_LEN]> = None;
    let mut secret: Option<[u8; SHARED_SECRET_LEN]> = None;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => {
                fabric_index = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(2), v) => peer_node_id = Some(v.as_unsigned()?),
            (TlvTag::ContextSpecific(3), v) => {
                rid = Some(v.as_bytes()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(4), v) => {
                secret = Some(v.as_bytes()?.try_into().map_err(|_| Error::Decode)?)
            }
            _ => r.skip(&e)?,
        }
    }
    let fabric_index = NonZeroU8::new(fabric_index.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    Ok((
        fabric_index,
        peer_node_id.ok_or(Error::Decode)?,
        rid.ok_or(Error::Decode)?,
        secret.ok_or(Error::Decode)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).unwrap()
    }

    #[test]
    fn save_find_and_rotate() {
        let mut store: ResumptionStore<2> = ResumptionStore::new();
        assert!(store.is_empty());
        store.save(fx(1), 0x1111, &[0xAA; 16], &[0x01; 32]);
        assert_eq!(store.len(), 1);
        let r = store.find_by_id(&[0xAA; 16]).unwrap();
        assert_eq!(r.peer_node_id, 0x1111);
        assert_eq!(&r.shared_secret[..], &[0x01; 32]);

        // 同一ピアの保存はローテート(件数不変・ID 差し替え)。
        store.save(fx(1), 0x1111, &[0xBB; 16], &[0x01; 32]);
        assert_eq!(store.len(), 1);
        assert!(store.find_by_id(&[0xAA; 16]).is_none());
        assert!(store.find_by_id(&[0xBB; 16]).is_some());
        assert!(store.find_by_peer(fx(1), 0x1111).is_some());
        assert!(store.find_by_peer(fx(2), 0x1111).is_none());
    }

    #[test]
    fn fifo_eviction_on_full() {
        let mut store: ResumptionStore<2> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        store.save(fx(1), 2, &[0x02; 16], &[0x02; 32]);
        // 3 件目で最古(peer=1)が追い出される。
        store.save(fx(1), 3, &[0x03; 16], &[0x03; 32]);
        assert_eq!(store.len(), 2);
        assert!(store.find_by_peer(fx(1), 1).is_none());
        assert!(store.find_by_peer(fx(1), 2).is_some());
        assert!(store.find_by_peer(fx(1), 3).is_some());
        // peer=2 をローテート(seq 更新)してから 4 件目 → 追い出しは peer=3。
        store.save(fx(1), 2, &[0x22; 16], &[0x02; 32]);
        store.save(fx(1), 4, &[0x04; 16], &[0x04; 32]);
        assert!(store.find_by_peer(fx(1), 3).is_none());
        assert!(store.find_by_peer(fx(1), 2).is_some());
        assert!(store.find_by_peer(fx(1), 4).is_some());
    }

    #[test]
    fn remove_fabric_clears_records() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        store.save(fx(2), 2, &[0x02; 16], &[0x02; 32]);
        store.save(fx(1), 3, &[0x03; 16], &[0x03; 32]);
        store.remove_fabric(fx(1));
        assert_eq!(store.len(), 1);
        assert!(store.find_by_peer(fx(2), 2).is_some());
    }

    /// テスト用インメモリ KVS(単一キー `rsmp` のみ扱う。ヒープ不使用)。
    struct MemKvs {
        used: bool,
        key: [u8; 8],
        klen: usize,
        val: [u8; RESUMPTION_STORE_BUF_LEN],
        vlen: usize,
    }

    impl MemKvs {
        fn new() -> Self {
            Self {
                used: false,
                key: [0; 8],
                klen: 0,
                val: [0; RESUMPTION_STORE_BUF_LEN],
                vlen: 0,
            }
        }
        fn matches(&self, key: &[u8]) -> bool {
            self.used && &self.key[..self.klen] == key
        }
    }

    impl Kvs for MemKvs {
        fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
            if !self.matches(key) {
                return Ok(None);
            }
            if buf.len() < self.vlen {
                return Err(Error::NoSpace);
            }
            buf[..self.vlen].copy_from_slice(&self.val[..self.vlen]);
            Ok(Some(self.vlen))
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
            assert!(key.len() <= 8 && value.len() <= RESUMPTION_STORE_BUF_LEN);
            self.used = true;
            self.klen = key.len();
            self.key[..key.len()].copy_from_slice(key);
            self.vlen = value.len();
            self.val[..value.len()].copy_from_slice(value);
            Ok(())
        }
        fn remove(&mut self, key: &[u8]) -> Result<()> {
            if self.matches(key) {
                self.used = false;
            }
            Ok(())
        }
    }

    #[test]
    fn save_load_round_trip() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 0x1111, &[0xA1; 16], &[0x01; 32]);
        store.save(fx(2), 0x2222_3333_4444_5555, &[0xB2; 16], &[0x02; 32]);
        let mut kvs = MemKvs::new();
        store.save_to(&mut kvs).unwrap();

        let mut restored: ResumptionStore<4> = ResumptionStore::new();
        let n = restored.load_from(&mut kvs).unwrap();
        assert_eq!(n, 2);
        assert_eq!(restored.len(), 2);
        let a = restored.find_by_peer(fx(1), 0x1111).unwrap();
        assert_eq!(a.resumption_id, [0xA1; 16]);
        assert_eq!(&a.shared_secret[..], &[0x01; 32]);
        let b = restored
            .find_by_id(&[0xB2; 16])
            .expect("peer 2 by resumption id");
        assert_eq!(b.peer_node_id, 0x2222_3333_4444_5555);
        assert_eq!(&b.shared_secret[..], &[0x02; 32]);
    }

    #[test]
    fn load_from_rejects_non_empty_store() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        let mut kvs = MemKvs::new();
        store.save_to(&mut kvs).unwrap();
        // 非空ストアへの復元は拒否する(fabric/acl と同じ約束)。
        assert!(matches!(
            store.load_from(&mut kvs),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn load_from_missing_key_is_zero() {
        let mut kvs = MemKvs::new();
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        assert_eq!(store.load_from(&mut kvs).unwrap(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn empty_store_removes_key() {
        let mut kvs = MemKvs::new();
        // まず 1 件保存 → その後 fabric 削除で空に → save_to でキー削除。
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        store.save_to(&mut kvs).unwrap();
        store.remove_fabric(fx(1));
        assert!(store.is_empty());
        store.save_to(&mut kvs).unwrap();
        // キーが消えているので復元は 0 件。
        let mut restored: ResumptionStore<4> = ResumptionStore::new();
        assert_eq!(restored.load_from(&mut kvs).unwrap(), 0);
    }

    #[test]
    fn version_mismatch_is_rejected() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        let mut kvs = MemKvs::new();
        store.save_to(&mut kvs).unwrap();
        // 保存済み TLV の version(外側 struct cx0 の値バイト)を破壊する。
        // レイアウト: 0x15(struct) 0x24 0x00 <version> ... なので index 3 が version 値。
        assert_eq!(kvs.val[2], 0x00); // cx0 の u8 タグ(control 0x24, tag 0x00)
        kvs.val[3] = 0x02; // version=2 に改竄
        let mut restored: ResumptionStore<4> = ResumptionStore::new();
        assert!(matches!(restored.load_from(&mut kvs), Err(Error::Decode)));
    }

    #[test]
    fn generation_advances_on_change() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        let g0 = store.generation();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        let g1 = store.generation();
        assert_ne!(g1, g0);
        store.save(fx(1), 2, &[0x02; 16], &[0x02; 32]);
        let g2 = store.generation();
        assert_ne!(g2, g1);
        // remove_fabric で実際に削除が起きたら generation が進む。
        store.remove_fabric(fx(1));
        assert_ne!(store.generation(), g2);
        // 何も削除しない remove_fabric は generation を動かさない。
        let g3 = store.generation();
        store.remove_fabric(fx(9));
        assert_eq!(store.generation(), g3);
    }
}
