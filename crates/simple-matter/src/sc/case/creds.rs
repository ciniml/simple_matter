//! 第4段階(fabric/credentials)へ切り出す **読み取り専用 trait 境界**。
//!
//! `docs/design/secure-channel.md` §8 に基づく。CASE responder が必要とする
//! fabric / 証明書側の前提を、3 つの trait に集約する:
//!
//! - [`FabricStore`] — fabric テーブルの読み取りビュー(destination-id 総当り・
//!   fabric index 逆引き)。
//! - [`Fabric`] — 1 fabric が CASE に提供する素材(root public key・IPK・自 NOC/ICAC・
//!   運用鍵での署名)。
//! - [`NocResolver`] — 相手 NOC/ICAC を fabric の信頼根で検証し identity を取り出す。
//!
//! これらは [`crate::fabric`] が実装する(依存性逆転)。trait 定義自体は暗号 backend に
//! 依存せず、`--no-default-features` でも常時コンパイルできる。
//!
//! # CASE 未実装の現状に合わせた調整(判断)
//!
//! 設計の [`NocResolver::verify_peer_noc`] はシグネチャに crypto / 時刻を取らない。
//! チェーン検証([`crate::cert::verify_chain`])は crypto と検証時刻を要するため、
//! この trait は「crypto と時刻を束ねたコンテキスト型」に実装する
//! ([`crate::fabric::FabricCredentials`] を参照)。[`FabricStore`] / [`Fabric`] は
//! 暗号を要しない読み取りアクセサのみで構成されるため、[`crate::fabric::FabricTable`] /
//! [`crate::fabric::FabricEntry`] に直接実装する。

use core::num::NonZeroU8;

use crate::error::Result;

/// [`NocResolver`] が返す相手 NOC の identity に含める CAT(CASE Authenticated Tag)の
/// 最大件数。Matter 仕様上、1 つの NOC に付与できる CAT は最大 3 個。
pub const MAX_PEER_CATS: usize = 3;

/// operational IPK(Identity Protection Key)のバイト長。AES-128 鍵と同じ 16 バイト。
pub const IPK_LEN: usize = 16;

/// SEC1 非圧縮 P-256 公開鍵のバイト長(`0x04 || X || Y`)。
pub const ROOT_PUBLIC_KEY_LEN: usize = 65;

/// P-256 ECDSA 署名(生 `r || s`)のバイト長。
pub const SIGNATURE_LEN: usize = 64;

/// 相手 NOC を fabric の信頼根で検証して得た identity。
///
/// [`NocResolver::verify_peer_noc`] が返す。CASE responder はこの値から相手の
/// operational NodeId / FabricId / 公開鍵・CAT を得て、Sigma3 の署名検証や ACL 判定に
/// 用いる。ヒープを確保しないよう固定長で保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    node_id: u64,
    fabric_id: u64,
    public_key: [u8; ROOT_PUBLIC_KEY_LEN],
    cats: [u32; MAX_PEER_CATS],
    cat_count: usize,
}

impl PeerIdentity {
    /// フィールドから [`PeerIdentity`] を構築する。
    ///
    /// `cat_count` は `cats` の先頭有効件数で、[`MAX_PEER_CATS`] 以下でなければならない。
    /// 超過する場合は先頭 [`MAX_PEER_CATS`] 件に丸める(panic しない)。
    pub fn new(
        node_id: u64,
        fabric_id: u64,
        public_key: [u8; ROOT_PUBLIC_KEY_LEN],
        cats: [u32; MAX_PEER_CATS],
        cat_count: usize,
    ) -> Self {
        Self {
            node_id,
            fabric_id,
            public_key,
            cats,
            cat_count: cat_count.min(MAX_PEER_CATS),
        }
    }

    /// 相手の operational NodeId。
    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    /// 相手の FabricId(検証に用いた fabric のものと一致する)。
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// 相手 NOC の subject 公開鍵(SEC1 非圧縮 65 バイト)。Sigma3 署名検証に用いる。
    pub fn public_key(&self) -> &[u8; ROOT_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// 相手 NOC の CAT(CASE Authenticated Tag)群。0..=[`MAX_PEER_CATS`] 件。
    pub fn cats(&self) -> &[u32] {
        &self.cats[..self.cat_count]
    }
}

/// 1 fabric が CASE responder に提供する読み取り素材。
///
/// 全アクセサは事前計算済みの値(add 時に確定)を返し、暗号 backend を要さない。
/// [`sign`](Fabric::sign) のみ運用鍵ペアを用いるが、鍵素材を外へ出さない。
pub trait Fabric {
    /// fabric index(1..=254)。
    fn fabric_index(&self) -> NonZeroU8;

    /// この fabric の FabricId。
    fn fabric_id(&self) -> u64;

    /// この fabric における自ノードの operational NodeId。
    fn node_id(&self) -> u64;

    /// operational IPK(destination-id 照合・CASE 鍵導出の salt に用いる 16 バイト)。
    fn ipk(&self) -> &[u8; IPK_LEN];

    /// RCAC の root public key(SEC1 非圧縮 65 バイト。destination-id 照合に用いる)。
    fn root_public_key(&self) -> &[u8; ROOT_PUBLIC_KEY_LEN];

    /// 自 NOC の TLV バイト列(Sigma2 の TBEData2 に載せる)。
    fn noc(&self) -> &[u8];

    /// 自 ICAC の TLV バイト列。ICAC を持たない fabric では `None`。
    fn icac(&self) -> Option<&[u8]>;

    /// 運用秘密鍵で `msg` に ECDSA 署名し、生 `r || s`(64 バイト)を `out` に書く。
    ///
    /// 鍵は外に出さない。署名失敗時は panic せず [`crate::Error::Crypto`] を返す。
    fn sign(&self, msg: &[u8], out: &mut [u8; SIGNATURE_LEN]) -> Result<()>;
}

impl<T: Fabric + ?Sized> Fabric for &T {
    fn fabric_index(&self) -> NonZeroU8 {
        (**self).fabric_index()
    }
    fn fabric_id(&self) -> u64 {
        (**self).fabric_id()
    }
    fn node_id(&self) -> u64 {
        (**self).node_id()
    }
    fn ipk(&self) -> &[u8; IPK_LEN] {
        (**self).ipk()
    }
    fn root_public_key(&self) -> &[u8; ROOT_PUBLIC_KEY_LEN] {
        (**self).root_public_key()
    }
    fn noc(&self) -> &[u8] {
        (**self).noc()
    }
    fn icac(&self) -> Option<&[u8]> {
        (**self).icac()
    }
    fn sign(&self, msg: &[u8], out: &mut [u8; SIGNATURE_LEN]) -> Result<()> {
        (**self).sign(msg, out)
    }
}

/// fabric テーブルの読み取りビュー(CASE が触る最小面)。
pub trait FabricStore {
    /// 1 fabric の読み取りビュー型。
    type Fabric<'a>: Fabric
    where
        Self: 'a;

    /// 全 fabric を走査する(destination-id 総当りに使う)。
    fn iter(&self) -> impl Iterator<Item = Self::Fabric<'_>>;

    /// fabric index(1-origin)で引く。
    fn get(&self, idx: NonZeroU8) -> Option<Self::Fabric<'_>>;
}

/// 相手 NOC/ICAC を fabric の信頼根で検証し、[`PeerIdentity`] を取り出す。
///
/// 証明書チェーン検証(ヒープレス TLV/DER パース)は [`crate::fabric`] の実装が
/// [`crate::cert::verify_chain`] 越しに行う。
pub trait NocResolver {
    /// `fabric_index` の fabric の RCAC を信頼根として、相手 NOC(+ICAC)を検証する。
    ///
    /// 成功時は相手の identity を返す。チェーン検証や整合性検査に失敗した場合は
    /// panic せず [`crate::Error`] を返す。
    fn verify_peer_noc(
        &self,
        fabric_index: NonZeroU8,
        noc_tlv: &[u8],
        icac_tlv: Option<&[u8]>,
    ) -> Result<PeerIdentity>;
}
