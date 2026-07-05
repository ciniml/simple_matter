//! fabric テーブルの永続化(KVS への TLV 保存/復元)。
//!
//! `docs/design/port-esp32-device.md` §E4.2 / §E4.4 の実装。[`FabricTable`] の内容を
//! [`Kvs`] へ versioned TLV で書き出し([`FabricTable::save_to`])、リブート後に
//! 復元する([`FabricTable::load_from`])。エンコーディングは既存の Matter TLV
//! コーデック([`crate::tlv`])を再利用する(パーサの二重化を避ける)。
//!
//! # レコードレイアウト(schema version 1)
//!
//! - メタ(キー `b"fabm"`): `struct { cx0: version(u8)=1, cx1: last_known_good_epoch(u32) }`
//! - fabric スロット(キー `b"fab0"`..`b"fab9"`、スロット位置 = テーブル内順序):
//!   `struct { cx1: fabric_index(u8), cx2: fabric_id(u64), cx3: node_id(u64),
//!   cx4: vendor_id(u16), cx5: ipk_epoch_key(bytes16), cx6: 運用秘密鍵(bytes32),
//!   cx7: RCAC TLV(bytes), cx8: ICAC TLV(bytes, 無ければ省略), cx9: NOC TLV(bytes),
//!   cx10: label(utf8), cx11: compressed_fabric_id(bytes8) }`
//!
//! 保存するのは「素材」であり、導出値(root public key / operational IPK)は復元時に
//! 再計算する。cx11 の CompressedFabricId は照合用で、再導出値と不一致なら flash 破損
//! として復元を拒否する(§E4.2)。
//!
//! # 復元時の検証(§E4.4)
//!
//! 復元は [`FabricTable::add`] と同水準の検証を行う: チェーン検証(検証時刻は
//! `max(now, 保存済み LKGT, チェーンの notBefore)`)・NOC subject の識別子一致・
//! NOC 公開鍵と運用鍵ペアの一致。fabric_index は保存値をそのまま採用する
//! (採番し直さない。remove 後の非連続 index を保存どおり保つ)。
//!
//! # 呼び出しタイミング
//!
//! いつ保存するかはコアは知らない(sans-IO 維持)。統合層が
//! [`FabricTable::generation`] の変化を検知して `save_to` を呼ぶ。

use core::num::NonZeroU8;

use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_SECRET_KEY_LEN};
use crate::error::{Error, Result};
use crate::kvs::Kvs;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

use super::{
    compute_compressed_fabric_id, derive_operational_ipk, CertBuf, FabricEntry, FabricTable,
    COMPRESSED_FABRIC_ID_LEN, IPK_LEN, MAX_FABRIC_LABEL_LEN, ROOT_PUBLIC_KEY_LEN,
};
use crate::cert::{verify_chain, MatterCert};

/// 永続化フォーマットの schema version(メタレコード cx0)。
pub const FABRIC_SCHEMA_VERSION: u8 = 1;

/// 1 fabric レコードの TLV エンコード上限(バイト)。
///
/// 証明書 3 通(各 ≤ [`super::MAX_CERT_TLV_LEN`])+ 鍵素材 + 識別子 + タグ類の合計に
/// 余裕を持たせた値。KVS 実装・呼び出し側のバッファサイジングに使う。
pub const MAX_FABRIC_RECORD_LEN: usize = 1440;

/// メタレコードのキー。
const META_KEY: &[u8] = b"fabm";

/// メタレコードの TLV エンコード上限。
const META_RECORD_LEN: usize = 16;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// スロット `slot` のキー(`b"fab0"`..)。スロット 10 以上は非対応(`NoSpace`)。
fn slot_key(slot: usize) -> Result<[u8; 4]> {
    if slot >= 10 {
        return Err(Error::NoSpace);
    }
    Ok([b'f', b'a', b'b', b'0' + slot as u8])
}

impl<C: Crypto, const N: usize> FabricTable<C, N> {
    /// テーブル全体を `kvs` へ保存する(メタ + 全スロット)。
    ///
    /// 空きスロットのキーは削除する(削除済み fabric がリブート後に復活しないように)。
    /// 呼び出しタイミングは統合層の責務: [`FabricTable::generation`] の変化を検知して
    /// 呼ぶ(`docs/design/port-esp32-device.md` §E4.4)。
    pub fn save_to<K: Kvs>(&self, kvs: &mut K) -> Result<()> {
        // メタ(schema version + LKGT)。
        let mut meta = [0u8; META_RECORD_LEN];
        let meta_len = {
            let mut w = TlvWriter::new(&mut meta);
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), FABRIC_SCHEMA_VERSION)?;
            w.write_u32(&cx(1), self.last_known_good_epoch)?;
            w.end_container()?;
            w.len()
        };
        kvs.set(META_KEY, &meta[..meta_len])?;

        // 各スロット。エントリが有ればレコードを書き、無ければキーを消す。
        let mut record = [0u8; MAX_FABRIC_RECORD_LEN];
        for slot in 0..N {
            match self.entries.get(slot) {
                Some(entry) => {
                    let key = slot_key(slot)?;
                    let len = encode_entry(entry, &mut record)?;
                    kvs.set(&key, &record[..len])?;
                }
                None => {
                    // スロット 10 以上は書けないが、エントリも存在し得ないので
                    // キー削除も不要(slot_key が失敗するだけ)。
                    if let Ok(key) = slot_key(slot) {
                        kvs.remove(&key)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// `kvs` からテーブルを復元し、復元した fabric 数を返す。
    ///
    /// - 空テーブルにのみ呼べる(非空は [`Error::InvalidState`])。
    /// - メタレコードが無ければ「初回起動」として `Ok(0)`(テーブルは空のまま)。
    /// - schema version 不一致・レコード破損・チェーン検証失敗は [`Error`] を返し、
    ///   その時点で復元を中断する(部分復元されたエントリは巻き戻さない — 呼び出し側は
    ///   エラー時にテーブルを作り直すこと)。
    /// - `now` は Matter epoch 秒(壁時計を持たないデバイスは 0 でよい。検証時刻は
    ///   `max(now, 保存済み LKGT, チェーンの notBefore)` に持ち上げる)。
    pub fn load_from<K: Kvs>(&mut self, kvs: &mut K, crypto: &C, now: u32) -> Result<usize> {
        if !self.entries.is_empty() {
            return Err(Error::InvalidState);
        }

        // メタ(無ければ初回起動)。
        let mut meta = [0u8; META_RECORD_LEN];
        let meta_len = match kvs.get(META_KEY, &mut meta)? {
            Some(l) => l,
            None => return Ok(0),
        };
        let stored_lkgt = decode_meta(&meta[..meta_len])?;
        self.last_known_good_epoch = self.last_known_good_epoch.max(stored_lkgt);

        let mut record = [0u8; MAX_FABRIC_RECORD_LEN];
        let mut restored = 0usize;
        for slot in 0..N.min(10) {
            let key = slot_key(slot)?;
            let len = match kvs.get(&key, &mut record)? {
                Some(l) => l,
                None => continue,
            };
            let entry = decode_and_verify_entry(crypto, &record[..len], self, now)?;
            // fabric_index の重複は破損として拒否する。
            if self.get(entry.fabric_index).is_some() {
                return Err(Error::Duplicate);
            }
            self.entries.push(entry).map_err(|_| Error::NoSpace)?;
            restored += 1;
        }
        Ok(restored)
    }
}

/// 1 エントリを TLV レコードへエンコードする(§E4.2 のレイアウト)。
fn encode_entry<C: Crypto>(entry: &FabricEntry<C>, out: &mut [u8]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_u8(&cx(1), entry.fabric_index.get())?;
    w.write_u64(&cx(2), entry.fabric_id)?;
    w.write_u64(&cx(3), entry.node_id)?;
    w.write_u16(&cx(4), entry.vendor_id)?;
    w.write_bytes(&cx(5), &entry.ipk_epoch_key)?;
    w.write_bytes(&cx(6), &entry.operational_key_bytes())?;
    w.write_bytes(&cx(7), entry.rcac())?;
    if let Some(icac) = entry.icac() {
        w.write_bytes(&cx(8), icac)?;
    }
    w.write_bytes(&cx(9), entry.noc())?;
    w.write_utf8(&cx(10), entry.label())?;
    w.write_bytes(&cx(11), &entry.compressed_fabric_id)?;
    w.end_container()?;
    Ok(w.len())
}

/// メタレコードをデコードし、LKGT を返す。version 不一致は [`Error::Decode`]。
fn decode_meta(record: &[u8]) -> Result<u32> {
    let mut r = TlvReader::new(record);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut version: Option<u8> = None;
    let mut lkgt: Option<u32> = None;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => {
                version = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(1), v) => {
                lkgt = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            _ => r.skip(&e)?,
        }
    }
    if version != Some(FABRIC_SCHEMA_VERSION) {
        return Err(Error::Decode);
    }
    lkgt.ok_or(Error::Decode)
}

/// デコード途中の生フィールド(検証前)。
struct RawRecord<'a> {
    fabric_index: NonZeroU8,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    ipk_epoch_key: [u8; IPK_LEN],
    op_key: [u8; P256_SECRET_KEY_LEN],
    rcac: &'a [u8],
    icac: Option<&'a [u8]>,
    noc: &'a [u8],
    label: &'a str,
    compressed: [u8; COMPRESSED_FABRIC_ID_LEN],
}

/// 1 レコードをデコードする(フィールド存在・長さの検査のみ。暗号検証は呼び出し側)。
fn decode_record(record: &[u8]) -> Result<RawRecord<'_>> {
    let mut r = TlvReader::new(record);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut fabric_index: Option<u8> = None;
    let mut fabric_id: Option<u64> = None;
    let mut node_id: Option<u64> = None;
    let mut vendor_id: Option<u16> = None;
    let mut ipk: Option<[u8; IPK_LEN]> = None;
    let mut op_key: Option<[u8; P256_SECRET_KEY_LEN]> = None;
    let mut rcac: Option<&[u8]> = None;
    let mut icac: Option<&[u8]> = None;
    let mut noc: Option<&[u8]> = None;
    let mut label: Option<&str> = None;
    let mut compressed: Option<[u8; COMPRESSED_FABRIC_ID_LEN]> = None;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => {
                fabric_index = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(2), v) => fabric_id = Some(v.as_unsigned()?),
            (TlvTag::ContextSpecific(3), v) => node_id = Some(v.as_unsigned()?),
            (TlvTag::ContextSpecific(4), v) => {
                vendor_id = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(5), v) => {
                ipk = Some(v.as_bytes()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(6), v) => {
                op_key = Some(v.as_bytes()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(7), v) => rcac = Some(v.as_bytes()?),
            (TlvTag::ContextSpecific(8), v) => icac = Some(v.as_bytes()?),
            (TlvTag::ContextSpecific(9), v) => noc = Some(v.as_bytes()?),
            (TlvTag::ContextSpecific(10), v) => label = Some(v.as_str()?),
            (TlvTag::ContextSpecific(11), v) => {
                compressed = Some(v.as_bytes()?.try_into().map_err(|_| Error::Decode)?)
            }
            _ => r.skip(&e)?,
        }
    }
    let fabric_index =
        NonZeroU8::new(fabric_index.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    let label = label.ok_or(Error::Decode)?;
    if label.len() > MAX_FABRIC_LABEL_LEN {
        return Err(Error::Decode);
    }
    Ok(RawRecord {
        fabric_index,
        fabric_id: fabric_id.ok_or(Error::Decode)?,
        node_id: node_id.ok_or(Error::Decode)?,
        vendor_id: vendor_id.ok_or(Error::Decode)?,
        ipk_epoch_key: ipk.ok_or(Error::Decode)?,
        op_key: op_key.ok_or(Error::Decode)?,
        rcac: rcac.ok_or(Error::Decode)?,
        icac,
        noc: noc.ok_or(Error::Decode)?,
        label,
        compressed: compressed.ok_or(Error::Decode)?,
    })
}

/// レコードをデコードし、[`FabricTable::add`] と同水準の検証を行ってエントリを再構築する。
fn decode_and_verify_entry<C: Crypto, const N: usize>(
    crypto: &C,
    record: &[u8],
    table: &mut FabricTable<C, N>,
    now: u32,
) -> Result<FabricEntry<C>> {
    let raw = decode_record(record)?;

    // 1. チェーン検証(add と同じ時刻の持ち上げ)。
    let rcac_cert = MatterCert::parse(raw.rcac)?;
    let noc_cert = MatterCert::parse(raw.noc)?;
    let icac_cert = match raw.icac {
        Some(bytes) => Some(MatterCert::parse(bytes)?),
        None => None,
    };
    let mut effective = table.effective_time(now).max(noc_cert.not_before());
    effective = effective.max(rcac_cert.not_before());
    if let Some(ic) = &icac_cert {
        effective = effective.max(ic.not_before());
    }
    verify_chain(crypto, &noc_cert, icac_cert.as_ref(), &rcac_cert, effective)?;
    table.last_known_good_epoch = table.last_known_good_epoch.max(effective);

    // 2. NOC subject と保存済み識別子の一致(破損検出)。
    let node_id = noc_cert.subject().node_id()?.ok_or(Error::CertInvalid)?;
    let fabric_id = noc_cert.subject().fabric_id()?.ok_or(Error::CertInvalid)?;
    if node_id != raw.node_id || fabric_id != raw.fabric_id {
        return Err(Error::CertInvalid);
    }

    // 3. 運用鍵ペアの復元と NOC 公開鍵の一致。
    let keypair = crypto.p256_keypair_from_bytes(&raw.op_key)?;
    let kp_pub = keypair.public_key().to_bytes();
    if noc_cert.public_key() != &kp_pub[..] {
        return Err(Error::Crypto);
    }

    // 4. 導出値の再計算と保存済み CompressedFabricId の照合。
    let mut root_public_key = [0u8; ROOT_PUBLIC_KEY_LEN];
    root_public_key.copy_from_slice(rcac_cert.public_key());
    let compressed = compute_compressed_fabric_id(crypto, &root_public_key, fabric_id)?;
    if compressed != raw.compressed {
        return Err(Error::Decode);
    }
    let operational_ipk = derive_operational_ipk(crypto, &raw.ipk_epoch_key, &compressed)?;

    // 5. エントリ再構築(fabric_index は保存値を採用)。
    let mut label_bytes = [0u8; MAX_FABRIC_LABEL_LEN];
    label_bytes[..raw.label.len()].copy_from_slice(raw.label.as_bytes());
    Ok(FabricEntry {
        fabric_index: raw.fabric_index,
        node_id,
        fabric_id,
        vendor_id: raw.vendor_id,
        compressed_fabric_id: compressed,
        root_public_key,
        ipk_epoch_key: raw.ipk_epoch_key,
        operational_ipk,
        keypair,
        rcac: CertBuf::set(raw.rcac)?,
        icac: match raw.icac {
            Some(bytes) => CertBuf::set(bytes)?,
            None => CertBuf::empty(),
        },
        noc: CertBuf::set(raw.noc)?,
        label: label_bytes,
        label_len: raw.label.len(),
    })
}
