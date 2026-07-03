//! fabric / credentials 管理(`FabricTable`)。
//!
//! `docs/ARCHITECTURE.md` レイヤ構成の `fabric` 層(ロードマップ第4段階)。コミッショニング
//! で確立した各 fabric の運用証明書(RCAC / ICAC / NOC)・運用鍵ペア・IPK・識別子を
//! 固定容量テーブルで保持し、CASE responder(第5段階以降)へ読み取り素材を提供する。
//!
//! # trait 境界の構成(判断)
//!
//! `docs/design/secure-channel.md` §8 は「CASE が触る fabric 側の面を 3 つの読み取り
//! 専用 trait([`FabricStore`] / [`Fabric`] / [`NocResolver`])に集約し、trait を
//! `sc/case/creds.rs` に定義、`fabric` モジュールが実装する」構成を求める(依存性逆転)。
//! 本モジュールはこの構成に従い、[`crate::sc::case::creds`] の 3 trait を実装する:
//!
//! - [`Fabric`] は暗号を要しない読み取りアクセサ + 運用鍵署名で構成されるため、
//!   [`FabricEntry`] に直接実装する。
//! - [`FabricStore`] も暗号非依存の走査/逆引きなので [`FabricTable`] に直接実装する。
//! - [`NocResolver::verify_peer_noc`] はチェーン検証([`crate::cert::verify_chain`])に
//!   crypto と検証時刻を要するが、設計のシグネチャはそれらを取らない。そこで
//!   「テーブル・crypto・時刻」を束ねたコンテキスト型 [`FabricCredentials`] にこの trait を
//!   実装する(CASE responder はハンドシェイクごとにこのコンテキストを構築する想定)。
//!   同等のチェーン検証は [`FabricTable::verify_peer_noc`] としても直接呼べる。
//!
//! CASE 本体が未実装の現状に合わせた最小の調整であり、trait そのものの形は設計どおり。
//!
//! # 鍵素材 vs 鍵ペアの保持(判断)
//!
//! [`Fabric::sign`] は crypto backend 参照を取らないシグネチャ(設計 §8)であり、
//! fabric 自身が署名能力を持つ必要がある。よって運用鍵は 32 バイトのスカラではなく、
//! 既存 [`P256Keypair`](crate::crypto::P256Keypair) の**鍵ペアオブジェクトをそのまま
//! 保持**する。これにより [`Fabric::sign`] は crypto 参照なしで署名でき、HW セキュア
//! エレメント上の鍵(エクスポート不可)にも将来対応できる。
//!
//! # alloc / サイジング方針
//!
//! `no_std`・定常パス no-alloc。証明書 TLV は固定バッファ [`MAX_CERT_TLV_LEN`] に
//! **その場コピー**して保持する(Matter TLV 証明書の上限は約 400 バイト。DER 化後の
//! 約 600 バイト級は署名検証時に呼び出し側バッファで一時再構築するのみで、格納は TLV の
//! まま。[`crate::cert`] の `MAX_TBS_DER_LEN`=600 と対を成す。rs-matter の
//! `MAX_CERT_TLV_LEN`=400 と同値)。テーブル容量は const generic `N`(Matter 必須下限は
//! 5 fabric)。不正入力で panic せず [`crate::Error`] を返す。
//!
//! # 鍵導出の出典(テストベクタ)
//!
//! - **CompressedFabricId** = `HKDF-SHA256(salt = FabricId(BE 8), ikm = RootPublicKey の
//!   先頭 1 バイト(0x04)を除いた 64 バイト, info = "CompressedFabric", L = 8)`。
//!   Matter Core Spec §4.3.2.2、connectedhomeip
//!   `Crypto::GenerateCompressedFabricId`、rs-matter `Fabric::compute_compressed_fabric_id`
//!   と一致。既知ベクタは chip `TestGroupDataProvider` の
//!   `kExampleOperationalRootPublicKey` / `kFabricId1` → `kCompressedFabricIdBuffer1`。
//! - **operational IPK(GroupKey v1.0)** = `HKDF-SHA256(salt = CompressedFabricId(8),
//!   ikm = EpochKey(16), info = "GroupKey v1.0", L = 16)`。
//!   Matter Core Spec §4.15.2、chip `Crypto::DeriveGroupOperationalCredentials`、
//!   rs-matter `KeySet::update` と一致。既知ベクタは chip
//!   `TestGroupOperationalCredentials`(`kGroupKeys0` の `encryption_key`)。
//!
//! # 永続化フック(方針・実装はスコープ外)
//!
//! 本ピースは in-memory のみ。将来の platform KVS 連携に向け、テーブルは**変更通知**
//! として単調増加する世代番号 [`FabricTable::generation`] を持つ。永続化層はこの値の
//! 変化を検知して差分を KVS へ書き出せる(fabric ごとの TLV シリアライズ・KVS I/O は
//! 第5/6段階の platform 統合で追加)。各 [`FabricEntry`] は移送に必要な素材
//! (証明書 TLV バイト列・運用鍵・IPK epoch key・識別子)を全て保持しており、
//! シリアライズ可能な形を意識した構造とする。

use core::num::NonZeroU8;

use crate::cert::{verify_chain, MatterCert};
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_PUBLIC_KEY_LEN};
use crate::error::{Error, Result};
use crate::transport::session::fixed::FixedVec;

pub use crate::sc::case::creds::{
    Fabric, FabricStore, NocResolver, PeerIdentity, IPK_LEN, MAX_PEER_CATS, ROOT_PUBLIC_KEY_LEN,
    SIGNATURE_LEN,
};

/// 格納する Matter TLV 証明書 1 通あたりの最大バイト数。
///
/// Matter 運用証明書(NOC/ICAC/RCAC)の TLV エンコーディング上限は約 400 バイト
/// ([`crate::cert`] モジュールドキュメント / rs-matter `MAX_CERT_TLV_LEN` と同値)。
/// 署名検証時に一時再構築する DER は約 600 バイト級だが、テーブルには TLV のまま格納する。
pub const MAX_CERT_TLV_LEN: usize = 400;

/// fabric ラベルの最大バイト長(Matter 仕様: 最大 32 文字)。
pub const MAX_FABRIC_LABEL_LEN: usize = 32;

/// CompressedFabricId のバイト長(64 ビット)。
pub const COMPRESSED_FABRIC_ID_LEN: usize = 8;

/// CompressedFabricId 導出の HKDF info(`"CompressedFabric"`, 16 バイト)。
const COMPRESSED_FABRIC_ID_INFO: &[u8] = b"CompressedFabric";

/// operational group key(IPK)導出の HKDF info(`"GroupKey v1.0"`, 13 バイト)。
const OPERATIONAL_GROUP_KEY_INFO: &[u8] = b"GroupKey v1.0";

/// fabric index に使える最大値(Matter 仕様: 1..=254。0 と 255 は予約)。
const MAX_FABRIC_INDEX: u8 = 254;

/// 固定バッファに格納した Matter TLV 証明書。
///
/// 空(`len == 0`)は「証明書なし」を表す(ICAC を持たない fabric で使う)。
#[derive(Clone)]
struct CertBuf {
    bytes: [u8; MAX_CERT_TLV_LEN],
    len: usize,
}

impl CertBuf {
    const fn empty() -> Self {
        Self {
            bytes: [0u8; MAX_CERT_TLV_LEN],
            len: 0,
        }
    }

    /// `src` を格納する。容量超過は [`Error::NoSpace`]。
    fn set(src: &[u8]) -> Result<Self> {
        if src.len() > MAX_CERT_TLV_LEN {
            return Err(Error::NoSpace);
        }
        let mut bytes = [0u8; MAX_CERT_TLV_LEN];
        bytes[..src.len()].copy_from_slice(src);
        Ok(Self {
            bytes,
            len: src.len(),
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// 1 fabric のエントリ。
///
/// 証明書 TLV・運用鍵ペア・事前計算済みの導出値(root public key / CompressedFabricId /
/// operational IPK)・識別子・ラベルを保持する。`C` は運用鍵ペア型を提供する暗号 backend。
pub struct FabricEntry<C: Crypto> {
    fabric_index: NonZeroU8,
    node_id: u64,
    fabric_id: u64,
    vendor_id: u16,
    compressed_fabric_id: [u8; COMPRESSED_FABRIC_ID_LEN],
    root_public_key: [u8; ROOT_PUBLIC_KEY_LEN],
    /// IPK epoch key(現行 1 本)。ローテーション時に operational IPK を再導出する。
    ipk_epoch_key: [u8; IPK_LEN],
    operational_ipk: [u8; IPK_LEN],
    keypair: C::Keypair,
    rcac: CertBuf,
    icac: CertBuf,
    noc: CertBuf,
    label: [u8; MAX_FABRIC_LABEL_LEN],
    label_len: usize,
}

impl<C: Crypto> FabricEntry<C> {
    /// fabric index(1..=254)。
    pub fn fabric_index(&self) -> NonZeroU8 {
        self.fabric_index
    }

    /// FabricId。
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// 自ノードの operational NodeId。
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Vendor ID。
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// CompressedFabricId(64 ビット, ビッグエンディアン解釈)。
    pub fn compressed_fabric_id(&self) -> u64 {
        u64::from_be_bytes(self.compressed_fabric_id)
    }

    /// CompressedFabricId の生バイト列(8 バイト)。
    pub fn compressed_fabric_id_bytes(&self) -> &[u8; COMPRESSED_FABRIC_ID_LEN] {
        &self.compressed_fabric_id
    }

    /// RCAC の root public key(SEC1 非圧縮 65 バイト)。
    pub fn root_public_key(&self) -> &[u8; ROOT_PUBLIC_KEY_LEN] {
        &self.root_public_key
    }

    /// operational IPK(16 バイト)。
    pub fn ipk(&self) -> &[u8; IPK_LEN] {
        &self.operational_ipk
    }

    /// 現在の IPK epoch key(16 バイト)。
    pub fn ipk_epoch_key(&self) -> &[u8; IPK_LEN] {
        &self.ipk_epoch_key
    }

    /// fabric ラベル。
    pub fn label(&self) -> &str {
        // label_len バイトは常に有効 UTF-8(set 時に検証済み)。
        core::str::from_utf8(&self.label[..self.label_len]).unwrap_or("")
    }

    /// RCAC の TLV バイト列。
    pub fn rcac(&self) -> &[u8] {
        self.rcac.as_slice()
    }

    /// NOC の TLV バイト列。
    pub fn noc(&self) -> &[u8] {
        self.noc.as_slice()
    }

    /// ICAC の TLV バイト列。持たない場合は `None`。
    pub fn icac(&self) -> Option<&[u8]> {
        if self.icac.len == 0 {
            None
        } else {
            Some(self.icac.as_slice())
        }
    }

    /// 運用鍵で `msg` に ECDSA 署名し `out` に生 `r || s`(64 バイト)を書く。
    pub fn sign(&self, msg: &[u8], out: &mut [u8; SIGNATURE_LEN]) -> Result<()> {
        self.keypair.sign(msg, out)
    }

    /// この fabric・対象ノード `target_node_id` に対する CASE destination identifier を
    /// 計算し `out`(32 バイト)に書く。
    ///
    /// `destinationMessage = initiatorRandom || rootPublicKey(65) || fabricId(LE 8) ||
    /// nodeId(LE 8)`、`destinationIdentifier = HMAC-SHA256(key = IPK, destinationMessage)`
    /// (`docs/design/secure-channel.md` §7.3、rs-matter `Fabric::compute_dest_id`)。
    /// `random` は 32 バイト以下でなければならない(通常は 32)。
    pub fn compute_destination_id<Cr: Crypto>(
        &self,
        crypto: &Cr,
        random: &[u8],
        target_node_id: u64,
        out: &mut [u8; 32],
    ) -> Result<()> {
        const RANDOM_MAX: usize = 32;
        const MSG_MAX: usize = RANDOM_MAX + P256_PUBLIC_KEY_LEN + 8 + 8;
        if random.len() > RANDOM_MAX {
            return Err(Error::Decode);
        }
        let mut msg = [0u8; MSG_MAX];
        let mut off = 0;
        msg[off..off + random.len()].copy_from_slice(random);
        off += random.len();
        msg[off..off + ROOT_PUBLIC_KEY_LEN].copy_from_slice(&self.root_public_key);
        off += ROOT_PUBLIC_KEY_LEN;
        msg[off..off + 8].copy_from_slice(&self.fabric_id.to_le_bytes());
        off += 8;
        msg[off..off + 8].copy_from_slice(&target_node_id.to_le_bytes());
        off += 8;
        crypto.hmac_sha256(&self.operational_ipk, &msg[..off], out)
    }
}

impl<C: Crypto> Fabric for FabricEntry<C> {
    fn fabric_index(&self) -> NonZeroU8 {
        self.fabric_index()
    }
    fn fabric_id(&self) -> u64 {
        self.fabric_id()
    }
    fn node_id(&self) -> u64 {
        self.node_id()
    }
    fn ipk(&self) -> &[u8; IPK_LEN] {
        self.ipk()
    }
    fn root_public_key(&self) -> &[u8; ROOT_PUBLIC_KEY_LEN] {
        self.root_public_key()
    }
    fn noc(&self) -> &[u8] {
        self.noc()
    }
    fn icac(&self) -> Option<&[u8]> {
        self.icac()
    }
    fn sign(&self, msg: &[u8], out: &mut [u8; SIGNATURE_LEN]) -> Result<()> {
        self.sign(msg, out)
    }
}

/// 固定容量 `N` の fabric テーブル。
///
/// `C` は運用鍵ペア型を提供する暗号 backend。`N` は Matter 必須下限 5 を満たす値を選ぶ。
pub struct FabricTable<C: Crypto, const N: usize> {
    entries: FixedVec<FabricEntry<C>, N>,
    generation: u32,
    /// Last Known Good UTC Time(Matter epoch 秒、仕様 §6.5.6.1 の最小実装)。
    ///
    /// 壁時計を持たないデバイスの証明書有効期間検証のための時刻下限。fabric 追加時に
    /// 受理した証明書チェーンの notBefore で単調に前進させ、検証時刻には
    /// `max(now, last_known_good_epoch)` を用いる。
    last_known_good_epoch: u32,
}

impl<C: Crypto, const N: usize> Default for FabricTable<C, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Crypto, const N: usize> FabricTable<C, N> {
    /// 空のテーブルを生成する。
    pub const fn new() -> Self {
        Self {
            entries: FixedVec::new(),
            generation: 0,
            last_known_good_epoch: 0,
        }
    }

    /// Last Known Good UTC Time(Matter epoch 秒)を返す。
    pub const fn last_known_good_epoch(&self) -> u32 {
        self.last_known_good_epoch
    }

    /// 証明書有効期間検証に使う実効時刻(`max(now, LKGT)`)を返す。
    pub fn effective_time(&self, now: u32) -> u32 {
        now.max(self.last_known_good_epoch)
    }

    /// 現在の fabric 数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// fabric が 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// テーブル容量(`N`)。
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 変更世代番号(永続化フック)。add / remove / update_label / rotate_ipk で増加する。
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// 全 fabric を走査する。
    pub fn iter(&self) -> impl Iterator<Item = &FabricEntry<C>> {
        self.entries.iter()
    }

    /// fabric index で引く。
    pub fn get(&self, fabric_index: NonZeroU8) -> Option<&FabricEntry<C>> {
        self.entries.iter().find(|e| e.fabric_index == fabric_index)
    }

    /// FabricId + NodeId で引く(CASE セッションの逆引き等)。
    pub fn find_by_fabric_and_node(&self, fabric_id: u64, node_id: u64) -> Option<&FabricEntry<C>> {
        self.entries
            .iter()
            .find(|e| e.fabric_id == fabric_id && e.node_id == node_id)
    }

    /// コミッショニングで確立した fabric を追加する。
    ///
    /// 手順(いずれの失敗も panic せずエラーを返す):
    /// 1. RCAC / (ICAC) / NOC を TLV パースし、[`verify_chain`] でチェーン検証する
    ///    (`now` は Matter epoch 秒)。
    /// 2. NOC subject から NodeId / FabricId を抽出する(欠落は [`Error::CertInvalid`])。
    /// 3. NOC の公開鍵と `keypair` の公開鍵の一致を確認する(不一致は [`Error::Crypto`])。
    /// 4. root public key を RCAC から抽出し、CompressedFabricId と operational IPK を
    ///    導出する。
    /// 5. fabric index を採番し、証明書 TLV を固定バッファへ格納する。
    ///
    /// 成功時は採番した fabric index を返す。容量満杯・証明書過大は [`Error::NoSpace`]。
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        crypto: &C,
        rcac: &[u8],
        icac: Option<&[u8]>,
        noc: &[u8],
        keypair: C::Keypair,
        ipk_epoch_key: &[u8; IPK_LEN],
        vendor_id: u16,
        now: u32,
        label: &str,
    ) -> Result<NonZeroU8> {
        if self.entries.is_full() {
            return Err(Error::NoSpace);
        }
        if label.len() > MAX_FABRIC_LABEL_LEN {
            return Err(Error::NoSpace);
        }

        // 1. チェーン検証。壁時計を持たないデバイス(now が小さい)でも受理できるよう、
        //    検証時刻は「現在時刻・LKGT・チェーンの notBefore」の最大値を使う
        //    (LKGT の初期化に相当。chip の FabricTable も同等の扱い)。
        let rcac_cert = MatterCert::parse(rcac)?;
        let noc_cert = MatterCert::parse(noc)?;
        let icac_cert = match icac {
            Some(bytes) => Some(MatterCert::parse(bytes)?),
            None => None,
        };
        let mut effective = self.effective_time(now).max(noc_cert.not_before());
        effective = effective.max(rcac_cert.not_before());
        if let Some(ic) = &icac_cert {
            effective = effective.max(ic.not_before());
        }
        verify_chain(crypto, &noc_cert, icac_cert.as_ref(), &rcac_cert, effective)?;
        // 受理したチェーンの notBefore は「過去に実在した時刻」なので LKGT を前進させる。
        self.last_known_good_epoch = self.last_known_good_epoch.max(effective);

        // 2. NodeId / FabricId 抽出。
        let node_id = noc_cert.subject().node_id()?.ok_or(Error::CertInvalid)?;
        let fabric_id = noc_cert.subject().fabric_id()?.ok_or(Error::CertInvalid)?;

        // 3. NOC 公開鍵と運用鍵ペアの一致。
        let kp_pub = keypair.public_key().to_bytes();
        if noc_cert.public_key() != &kp_pub[..] {
            return Err(Error::Crypto);
        }

        // 4. root public key 抽出と導出。
        let mut root_public_key = [0u8; ROOT_PUBLIC_KEY_LEN];
        root_public_key.copy_from_slice(rcac_cert.public_key());
        let compressed_fabric_id =
            compute_compressed_fabric_id(crypto, &root_public_key, fabric_id)?;
        let operational_ipk = derive_operational_ipk(crypto, ipk_epoch_key, &compressed_fabric_id)?;

        // 5. index 採番 + 証明書格納。
        let fabric_index = self.next_index()?;
        let rcac_buf = CertBuf::set(rcac)?;
        let noc_buf = CertBuf::set(noc)?;
        let icac_buf = match icac {
            Some(bytes) => CertBuf::set(bytes)?,
            None => CertBuf::empty(),
        };
        let mut label_bytes = [0u8; MAX_FABRIC_LABEL_LEN];
        label_bytes[..label.len()].copy_from_slice(label.as_bytes());

        let entry = FabricEntry {
            fabric_index,
            node_id,
            fabric_id,
            vendor_id,
            compressed_fabric_id,
            root_public_key,
            ipk_epoch_key: *ipk_epoch_key,
            operational_ipk,
            keypair,
            rcac: rcac_buf,
            icac: icac_buf,
            noc: noc_buf,
            label: label_bytes,
            label_len: label.len(),
        };

        // is_full を先頭で弾いているので push は成功する。
        self.entries.push(entry).map_err(|_| Error::NoSpace)?;
        self.generation = self.generation.wrapping_add(1);
        Ok(fabric_index)
    }

    /// fabric を削除する。存在しなければ [`Error::NotFound`]。
    pub fn remove(&mut self, fabric_index: NonZeroU8) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.fabric_index == fabric_index)
            .ok_or(Error::NotFound)?;
        self.entries.swap_remove(pos);
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// fabric ラベルを更新する。
    ///
    /// ラベルは他 fabric と重複してはならない(空ラベルは重複判定の対象外)。重複は
    /// [`Error::Duplicate`]、過大は [`Error::NoSpace`]、対象なしは [`Error::NotFound`]。
    pub fn update_label(&mut self, fabric_index: NonZeroU8, label: &str) -> Result<()> {
        if label.len() > MAX_FABRIC_LABEL_LEN {
            return Err(Error::NoSpace);
        }
        if !label.is_empty()
            && self
                .entries
                .iter()
                .any(|e| e.fabric_index != fabric_index && e.label() == label)
        {
            return Err(Error::Duplicate);
        }
        let pos = self
            .entries
            .iter()
            .position(|e| e.fabric_index == fabric_index)
            .ok_or(Error::NotFound)?;
        let entry = self.entries.get_mut(pos).ok_or(Error::NotFound)?;
        entry.label = [0u8; MAX_FABRIC_LABEL_LEN];
        entry.label[..label.len()].copy_from_slice(label.as_bytes());
        entry.label_len = label.len();
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// IPK epoch key をローテーションし operational IPK を再導出する。
    ///
    /// CompressedFabricId は不変なので保持済みの値から再計算する。対象なしは
    /// [`Error::NotFound`]。
    pub fn rotate_ipk(
        &mut self,
        crypto: &C,
        fabric_index: NonZeroU8,
        new_epoch_key: &[u8; IPK_LEN],
    ) -> Result<()> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.fabric_index == fabric_index)
            .ok_or(Error::NotFound)?;
        let compressed = self
            .entries
            .get(pos)
            .ok_or(Error::NotFound)?
            .compressed_fabric_id;
        let ipk = derive_operational_ipk(crypto, new_epoch_key, &compressed)?;
        let entry = self.entries.get_mut(pos).ok_or(Error::NotFound)?;
        entry.ipk_epoch_key = *new_epoch_key;
        entry.operational_ipk = ipk;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// destination identifier に一致する fabric の index を返す(CASE Sigma1 の総当り)。
    ///
    /// 各 fabric について自ノード宛の destination id を計算し `target`(32 バイト)と
    /// 照合する。一致がなければ `None`。
    pub fn find_by_dest_id(&self, crypto: &C, random: &[u8], target: &[u8]) -> Option<NonZeroU8> {
        if target.len() != 32 {
            return None;
        }
        for e in self.entries.iter() {
            let mut out = [0u8; 32];
            if e.compute_destination_id(crypto, random, e.node_id, &mut out)
                .is_ok()
                && &out[..] == target
            {
                return Some(e.fabric_index);
            }
        }
        None
    }

    /// 相手 NOC/ICAC を `fabric_index` の fabric の RCAC で検証し identity を返す。
    ///
    /// [`NocResolver::verify_peer_noc`] の実体。crypto と検証時刻 `now`(Matter epoch 秒)を
    /// 明示的に受け取る。
    pub fn verify_peer_noc(
        &self,
        crypto: &C,
        fabric_index: NonZeroU8,
        noc_tlv: &[u8],
        icac_tlv: Option<&[u8]>,
        now: u32,
    ) -> Result<PeerIdentity> {
        let entry = self.get(fabric_index).ok_or(Error::NotFound)?;
        let rcac = MatterCert::parse(entry.rcac())?;
        let noc = MatterCert::parse(noc_tlv)?;
        let icac = match icac_tlv {
            Some(bytes) => Some(MatterCert::parse(bytes)?),
            None => None,
        };
        // 壁時計を持たないデバイスでも検証できるよう LKGT で時刻を下支えする。
        verify_chain(crypto, &noc, icac.as_ref(), &rcac, self.effective_time(now))?;

        let node_id = noc.subject().node_id()?.ok_or(Error::CertInvalid)?;
        let fabric_id = noc.subject().fabric_id()?.ok_or(Error::CertInvalid)?;
        if fabric_id != entry.fabric_id {
            return Err(Error::CertInvalid);
        }
        let mut public_key = [0u8; ROOT_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(noc.public_key());
        let mut cats = [0u32; MAX_PEER_CATS];
        let cat_count = noc.subject().cats(&mut cats)?;
        Ok(PeerIdentity::new(
            node_id, fabric_id, public_key, cats, cat_count,
        ))
    }

    /// 未使用の最小 fabric index(1..=254)を返す。空きが無ければ [`Error::NoSpace`]。
    ///
    /// 最小空きを選ぶことで remove 後に解放された index が再利用される。
    fn next_index(&self) -> Result<NonZeroU8> {
        for i in 1..=MAX_FABRIC_INDEX {
            if let Some(idx) = NonZeroU8::new(i) {
                if self.get(idx).is_none() {
                    return Ok(idx);
                }
            }
        }
        Err(Error::NoSpace)
    }
}

impl<C: Crypto, const N: usize> FabricStore for FabricTable<C, N> {
    type Fabric<'a>
        = &'a FabricEntry<C>
    where
        Self: 'a;

    fn iter(&self) -> impl Iterator<Item = &FabricEntry<C>> {
        self.entries.iter()
    }

    fn get(&self, idx: NonZeroU8) -> Option<&FabricEntry<C>> {
        FabricTable::get(self, idx)
    }
}

/// [`NocResolver`] を実装するため、テーブル・crypto・検証時刻を束ねたコンテキスト。
///
/// CASE responder はハンドシェイクごとに現在時刻でこれを構築し、Sigma3 の相手 NOC 検証に
/// 用いる。読み取りのみで、テーブルを可変には触らない。
pub struct FabricCredentials<'a, C: Crypto, const N: usize> {
    table: &'a FabricTable<C, N>,
    crypto: &'a C,
    now: u32,
}

impl<'a, C: Crypto, const N: usize> FabricCredentials<'a, C, N> {
    /// テーブル・crypto・検証時刻(Matter epoch 秒)からコンテキストを構築する。
    pub fn new(table: &'a FabricTable<C, N>, crypto: &'a C, now: u32) -> Self {
        Self { table, crypto, now }
    }

    /// 背後の fabric テーブルへの参照。
    pub fn table(&self) -> &FabricTable<C, N> {
        self.table
    }
}

impl<C: Crypto, const N: usize> NocResolver for FabricCredentials<'_, C, N> {
    fn verify_peer_noc(
        &self,
        fabric_index: NonZeroU8,
        noc_tlv: &[u8],
        icac_tlv: Option<&[u8]>,
    ) -> Result<PeerIdentity> {
        self.table
            .verify_peer_noc(self.crypto, fabric_index, noc_tlv, icac_tlv, self.now)
    }
}

/// CompressedFabricId = `HKDF-SHA256(salt = FabricId(BE), ikm = rootPubKey[1..], info =
/// "CompressedFabric", L = 8)`(Matter Core Spec §4.3.2.2)。
fn compute_compressed_fabric_id<C: Crypto>(
    crypto: &C,
    root_public_key: &[u8; ROOT_PUBLIC_KEY_LEN],
    fabric_id: u64,
) -> Result<[u8; COMPRESSED_FABRIC_ID_LEN]> {
    let mut out = [0u8; COMPRESSED_FABRIC_ID_LEN];
    crypto.hkdf_sha256(
        &fabric_id.to_be_bytes(),
        &root_public_key[1..],
        COMPRESSED_FABRIC_ID_INFO,
        &mut out,
    )?;
    Ok(out)
}

/// operational IPK = `HKDF-SHA256(salt = CompressedFabricId, ikm = epochKey, info =
/// "GroupKey v1.0", L = 16)`(Matter Core Spec §4.15.2)。
fn derive_operational_ipk<C: Crypto>(
    crypto: &C,
    epoch_key: &[u8; IPK_LEN],
    compressed_fabric_id: &[u8; COMPRESSED_FABRIC_ID_LEN],
) -> Result<[u8; IPK_LEN]> {
    let mut out = [0u8; IPK_LEN];
    crypto.hkdf_sha256(
        compressed_fabric_id,
        epoch_key,
        OPERATIONAL_GROUP_KEY_INFO,
        &mut out,
    )?;
    Ok(out)
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests;
