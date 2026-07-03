//! Matter が必要とする暗号プリミティブの抽象(trait)と、RustCrypto 系クレートに
//! よる単一バックエンド。
//!
//! # 設計方針
//!
//! `docs/ARCHITECTURE.md` の設計原則 9「プラットフォーム抽象は最小 trait + 単一
//! バックエンド」に従い、抽象は薄く保つ。rs-matter のように鍵長・ハッシュ長を
//! const generic で表現する発想は借りるが、trait 数と型パラメータの伝播を最小化する。
//!
//! - [`Crypto`] を単一の暗号プロバイダ trait とし、上位レイヤは `C: Crypto` 一つの
//!   型パラメータのみを伝播させる(connectedhomeip の「暗号境界は 1 点」に相当)。
//! - [`Rng`] は乱数(エントロピー源)をプラットフォームから注入するための trait。
//!   コアはエントロピー源を保持しない。
//! - 鍵長・ハッシュ長は本モジュールの定数(例: [`SHA256_LEN`])で表現し、公開 API の
//!   引数は固定長配列で受け渡してヒープ確保を避ける。
//!
//! # alloc 方針
//!
//! trait 定義自体は依存ゼロで、`rustcrypto` feature が無効でも常時コンパイルできる。
//! バックエンド([`rustcrypto`])は `rustcrypto` feature(既定で有効)で有効化する。
//! 定常データパス(AES-CCM のメッセージ暗号化/復号、SHA-256 / HMAC / HKDF)は
//! ヒープを確保しない。
//!
//! # 対応プリミティブ
//!
//! SHA-256 / HMAC-SHA256 / HKDF-SHA256 / AES-128-CCM(nonce 13B・tag 16B)/
//! P-256(ECDH・ECDSA・鍵ペア生成)/ CSPRNG 抽象。
//! Spake2+(PASE)は本段階ではスコープ外。

use crate::error::Result;

#[cfg(feature = "rustcrypto")]
pub mod rustcrypto;

/// SHA-256 ハッシュ長(バイト)。HMAC-SHA256 の出力長でもある。
pub const SHA256_LEN: usize = 32;

/// AES-128-CCM の鍵長(バイト)。
pub const AES_CCM_KEY_LEN: usize = 16;

/// AES-128-CCM の nonce 長(バイト)。Matter のメッセージ暗号化で用いる。
pub const AES_CCM_NONCE_LEN: usize = 13;

/// AES-128-CCM の認証タグ(MIC)長(バイト)。
pub const AES_CCM_TAG_LEN: usize = 16;

/// P-256 公開鍵の長さ(バイト)。SEC1 非圧縮形式 `0x04 || X || Y`。
pub const P256_PUBLIC_KEY_LEN: usize = 65;

/// P-256 秘密鍵(スカラ)の長さ(バイト)。ビッグエンディアン。
pub const P256_SECRET_KEY_LEN: usize = 32;

/// P-256 ECDSA 署名の長さ(バイト)。生の `r || s` 形式。
pub const P256_SIGNATURE_LEN: usize = 64;

/// P-256 ECDH 共有秘密の長さ(バイト)。共有点の X 座標。
pub const P256_SHARED_SECRET_LEN: usize = 32;

/// 暗号論的に安全な乱数生成器(CSPRNG)の抽象。
///
/// エントロピー源はコアで保持せず、プラットフォームから実装を注入する。
/// 鍵ペア生成など乱数を要する操作は [`Crypto`] を通じてこの trait を利用する。
pub trait Rng {
    /// `dest` 全体を暗号論的に安全な乱数で満たす。
    ///
    /// エントロピー源の取得に失敗した場合は panic せず [`crate::Error::Crypto`] を返す。
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()>;
}

impl<T: Rng + ?Sized> Rng for &mut T {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        (**self).fill_bytes(dest)
    }
}

/// インクリメンタルな SHA-256 ハッシャ。
///
/// トランスクリプトハッシュ(CASE/PASE 等)のように、データを分割して逐次投入し
/// 最後に確定させる用途に用いる。一括ハッシュは [`Crypto::sha256_oneshot`] を使う。
pub trait Sha256: Sized {
    /// ハッシュ計算に `data` を追加する。
    fn update(&mut self, data: &[u8]);

    /// ハッシュを確定し、結果 32 バイトを `out` に書き込む。
    fn finish(self, out: &mut [u8; SHA256_LEN]);
}

/// P-256 公開鍵。
///
/// 内部表現はバックエンド依存だが、SEC1 非圧縮形式との相互変換が可能である。
pub trait P256PublicKey: Sized {
    /// SEC1 非圧縮形式(65 バイト, `0x04 || X || Y`)へ書き出す。
    fn to_bytes(&self) -> [u8; P256_PUBLIC_KEY_LEN];

    /// この公開鍵で `msg` に対する ECDSA 署名(生 `r || s`, 64 バイト)を検証する。
    ///
    /// メッセージは内部で SHA-256 によりハッシュされる(ECDSA-with-SHA256)。
    ///
    /// # 戻り値
    /// - 署名が有効なら `Ok(true)`、無効なら `Ok(false)`。
    /// - 署名の形式が不正など操作自体が失敗した場合は `Err`。検証の成否では panic しない。
    fn verify(&self, msg: &[u8], signature: &[u8; P256_SIGNATURE_LEN]) -> Result<bool>;
}

/// P-256 鍵ペア(秘密鍵とそれに対応する公開鍵)。
///
/// ECDSA 署名・ECDH 鍵合意に用いる。内部表現はバックエンド依存で、ハードウェア
/// セキュアエレメント上の鍵など、秘密鍵をエクスポートできない実装も許容する
/// (その場合 [`to_bytes`](P256Keypair::to_bytes) は失敗を返してよい)。
pub trait P256Keypair: Sized {
    /// この鍵ペアに対応する公開鍵型。
    type PublicKey: P256PublicKey;

    /// 対応する公開鍵を返す。
    fn public_key(&self) -> Self::PublicKey;

    /// 秘密スカラを 32 バイトのビッグエンディアン表現で書き出す。
    fn to_bytes(&self) -> [u8; P256_SECRET_KEY_LEN];

    /// `msg` に対する ECDSA 署名(生 `r || s`, 64 バイト)を生成し `signature` に書き込む。
    ///
    /// メッセージは内部で SHA-256 によりハッシュされる(ECDSA-with-SHA256)。
    /// 署名の nonce は決定的(RFC 6979)に導出するため乱数は不要。
    fn sign(&self, msg: &[u8], signature: &mut [u8; P256_SIGNATURE_LEN]) -> Result<()>;

    /// 相手の公開鍵 `peer` との ECDH 共有秘密(共有点の X 座標, 32 バイト)を
    /// `shared` に書き込む。
    fn ecdh(&self, peer: &Self::PublicKey, shared: &mut [u8; P256_SHARED_SECRET_LEN])
        -> Result<()>;
}

/// Matter が必要とする暗号プリミティブを束ねる単一のプロバイダ trait。
///
/// 上位レイヤはこの trait を実装した型を `C: Crypto` として保持し、暗号処理を
/// この 1 点に集約する。既定の実装は [`rustcrypto::RustCrypto`]。
///
/// ハードウェアアクセラレーションを行う場合は、この trait を実装した別バックエンドに
/// 差し替える(あるいは関連型・メソッドの一部のみを差し替える)ことができる。
pub trait Crypto {
    /// インクリメンタル SHA-256 ハッシャ型。
    type Sha256: Sha256;

    /// P-256 公開鍵型。
    type PublicKey: P256PublicKey;

    /// P-256 鍵ペア型。
    type Keypair: P256Keypair<PublicKey = Self::PublicKey>;

    /// 新しいインクリメンタル SHA-256 ハッシャを生成する。
    fn sha256(&self) -> Self::Sha256;

    /// `data` の SHA-256 を一括計算し `out` に書き込む。
    fn sha256_oneshot(&self, data: &[u8], out: &mut [u8; SHA256_LEN]) {
        let mut h = self.sha256();
        h.update(data);
        h.finish(out);
    }

    /// `key` を鍵として `data` の HMAC-SHA256 を計算し `out`(32 バイト)に書き込む。
    fn hmac_sha256(&self, key: &[u8], data: &[u8], out: &mut [u8; SHA256_LEN]) -> Result<()>;

    /// HKDF-SHA256(抽出+展開)で鍵導出を行う。
    ///
    /// `salt`(空スライス可)・`ikm`(入力鍵材料)・`info`(コンテキスト)から
    /// `out` の長さぶんの出力鍵材料を導出して `out` に書き込む。
    ///
    /// `out` の長さが HKDF の上限(255 * 32 バイト)を超える場合は `Err` を返す。
    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()>;

    /// AES-128-CCM でメッセージをその場暗号化する(MIC 付き)。
    ///
    /// `buffer` の先頭 `pt_len` バイトを平文とみなして暗号化し、続く
    /// [`AES_CCM_TAG_LEN`] バイトに認証タグ(MIC)を書き込む。
    /// `buffer` は少なくとも `pt_len + AES_CCM_TAG_LEN` バイトの容量が必要。
    ///
    /// # 戻り値
    /// - 成功時は暗号文 + タグ(`pt_len + 16` バイト)のスライス。
    /// - `buffer` の容量が不足する場合は [`crate::Error::NoSpace`]。
    fn aes_ccm_encrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
        pt_len: usize,
    ) -> Result<&'m [u8]>;

    /// AES-128-CCM でメッセージをその場復号する(MIC 検証付き)。
    ///
    /// `buffer` は「暗号文 || タグ(16 バイト)」とみなす。復号後、平文が
    /// `buffer` の先頭に上書きされる。
    ///
    /// # 戻り値
    /// - 成功時は平文(`buffer.len() - 16` バイト)のスライス。
    /// - タグ不一致・入力長不正などの場合は [`crate::Error::Crypto`](認証失敗)。
    ///   検証失敗で panic しない。
    fn aes_ccm_decrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
    ) -> Result<&'m [u8]>;

    /// 新しい P-256 鍵ペアを乱数から生成する。
    fn p256_generate_keypair(&self) -> Result<Self::Keypair>;

    /// 32 バイトのビッグエンディアン秘密スカラから P-256 鍵ペアを復元する。
    ///
    /// スカラが範囲外(0 または群位数以上)の場合は [`crate::Error::Crypto`]。
    fn p256_keypair_from_bytes(&self, bytes: &[u8; P256_SECRET_KEY_LEN]) -> Result<Self::Keypair>;

    /// SEC1 形式のバイト列から P-256 公開鍵を復元する。
    ///
    /// 非圧縮(65 バイト)・圧縮(33 バイト)いずれも受け付ける。曲線上にない点や
    /// 無限遠点など不正な入力は [`crate::Error::Crypto`] を返し panic しない。
    fn p256_public_key_from_bytes(&self, bytes: &[u8]) -> Result<Self::PublicKey>;
}

impl<T: Crypto> Crypto for &T {
    type Sha256 = T::Sha256;
    type PublicKey = T::PublicKey;
    type Keypair = T::Keypair;

    fn sha256(&self) -> Self::Sha256 {
        (**self).sha256()
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out: &mut [u8; SHA256_LEN]) -> Result<()> {
        (**self).hmac_sha256(key, data, out)
    }

    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        (**self).hkdf_sha256(salt, ikm, info, out)
    }

    fn aes_ccm_encrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
        pt_len: usize,
    ) -> Result<&'m [u8]> {
        (**self).aes_ccm_encrypt(key, nonce, aad, buffer, pt_len)
    }

    fn aes_ccm_decrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
    ) -> Result<&'m [u8]> {
        (**self).aes_ccm_decrypt(key, nonce, aad, buffer)
    }

    fn p256_generate_keypair(&self) -> Result<Self::Keypair> {
        (**self).p256_generate_keypair()
    }

    fn p256_keypair_from_bytes(&self, bytes: &[u8; P256_SECRET_KEY_LEN]) -> Result<Self::Keypair> {
        (**self).p256_keypair_from_bytes(bytes)
    }

    fn p256_public_key_from_bytes(&self, bytes: &[u8]) -> Result<Self::PublicKey> {
        (**self).p256_public_key_from_bytes(bytes)
    }
}
