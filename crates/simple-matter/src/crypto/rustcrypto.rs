//! RustCrypto 系クレートによる [`Crypto`] バックエンドの単一実装。
//!
//! `sha2` / `hmac` / `hkdf` / `aes` / `ccm` / `p256` を用いる。いずれも
//! `default-features = false` で取り込み、alloc/std を強制しない。
//! 定常データパス(AES-CCM / SHA / HMAC / HKDF)はヒープを確保しない
//! (AES-CCM は detached-tag 版 API を用い、成長可能バッファを使わない)。

use core::cell::RefCell;

use aes::Aes128;
use ccm::aead::{AeadInPlace, KeyInit};
use ccm::consts::{U13, U16};
use ccm::Ccm;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::Digest as _;

use crate::crypto::{
    Crypto, P256Keypair, P256PublicKey, Rng, Sha256, AES_CCM_KEY_LEN, AES_CCM_NONCE_LEN,
    AES_CCM_TAG_LEN, P256_PUBLIC_KEY_LEN, P256_SECRET_KEY_LEN, P256_SHARED_SECRET_LEN,
    P256_SIGNATURE_LEN, SHA256_LEN,
};
use crate::error::{Error, Result};

/// AES-128-CCM(tag 16 バイト・nonce 13 バイト)の具体型。
type AesCcm = Ccm<Aes128, U16, U13>;

/// HMAC-SHA256 の具体型。
type HmacSha256 = Hmac<sha2::Sha256>;

/// RustCrypto 系クレートを用いた [`Crypto`] の実装。
///
/// 乱数生成器 `R`([`Rng`])を保持し、鍵ペア生成でのみ使用する。SHA-256 /
/// HMAC / HKDF / AES-CCM / ECDSA 署名は乱数を必要としない
/// (ECDSA は RFC 6979 の決定的 nonce を用いる)。
pub struct RustCrypto<R> {
    rng: RefCell<R>,
}

impl<R: Rng> RustCrypto<R> {
    /// 乱数生成器 `rng` を注入してバックエンドを生成する。
    pub const fn new(rng: R) -> Self {
        Self {
            rng: RefCell::new(rng),
        }
    }
}

/// [`Sha256`] を実装するインクリメンタルハッシャ。
///
/// `Clone` は CASE のトランスクリプトハッシュが途中経過を複数回確定するために要る
/// ([`Sha256`] のドキュメント参照)。`sha2::Sha256` は `Clone` を実装する。
#[derive(Clone)]
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256 for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }

    fn finish(self, out: &mut [u8; SHA256_LEN]) {
        let digest = self.0.finalize();
        out.copy_from_slice(&digest);
    }
}

/// [`P256PublicKey`] を実装する P-256 公開鍵。
pub struct RcPublicKey(PublicKey);

impl P256PublicKey for RcPublicKey {
    fn to_bytes(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        let point = self.0.to_encoded_point(false);
        let mut out = [0u8; P256_PUBLIC_KEY_LEN];
        // 非圧縮形式は常に 65 バイト。
        out.copy_from_slice(point.as_bytes());
        out
    }

    fn verify(&self, msg: &[u8], signature: &[u8; P256_SIGNATURE_LEN]) -> Result<bool> {
        let verifying_key = VerifyingKey::from(&self.0);
        let signature = Signature::from_slice(signature).map_err(|_| Error::Crypto)?;
        Ok(verifying_key.verify(msg, &signature).is_ok())
    }
}

/// [`P256Keypair`] を実装する P-256 鍵ペア。
pub struct RcKeypair(SecretKey);

impl P256Keypair for RcKeypair {
    type PublicKey = RcPublicKey;

    fn public_key(&self) -> Self::PublicKey {
        RcPublicKey(self.0.public_key())
    }

    fn to_bytes(&self) -> [u8; P256_SECRET_KEY_LEN] {
        let bytes = self.0.to_bytes();
        let mut out = [0u8; P256_SECRET_KEY_LEN];
        out.copy_from_slice(&bytes);
        out
    }

    fn sign(&self, msg: &[u8], signature: &mut [u8; P256_SIGNATURE_LEN]) -> Result<()> {
        let signing_key = SigningKey::from(&self.0);
        let sig: Signature = signing_key.sign(msg);
        signature.copy_from_slice(&sig.to_bytes());
        Ok(())
    }

    fn ecdh(
        &self,
        peer: &Self::PublicKey,
        shared: &mut [u8; P256_SHARED_SECRET_LEN],
    ) -> Result<()> {
        let secret = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), peer.0.as_affine());
        shared.copy_from_slice(secret.raw_secret_bytes().as_slice());
        Ok(())
    }
}

impl<R: Rng> Crypto for RustCrypto<R> {
    type Sha256 = Sha256Hasher;
    type PublicKey = RcPublicKey;
    type Keypair = RcKeypair;

    fn sha256(&self) -> Self::Sha256 {
        Sha256Hasher(sha2::Sha256::new())
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8], out: &mut [u8; SHA256_LEN]) -> Result<()> {
        // HMAC は任意長の鍵を受け付けるため new_from_slice は失敗しない。
        // ccm::KeyInit と hmac::Mac の双方が new_from_slice を持つため明示的に修飾する。
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| Error::Crypto)?;
        Mac::update(&mut mac, data);
        let tag = mac.finalize().into_bytes();
        out.copy_from_slice(&tag);
        Ok(())
    }

    fn hkdf_sha256(&self, salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        let hk = Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
        // expand は出力長が上限(255 * 32 バイト)を超える場合のみ失敗する。
        hk.expand(info, out).map_err(|_| Error::Crypto)
    }

    fn aes_ccm_encrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
        pt_len: usize,
    ) -> Result<&'m [u8]> {
        let total = pt_len.checked_add(AES_CCM_TAG_LEN).ok_or(Error::NoSpace)?;
        if total > buffer.len() {
            return Err(Error::NoSpace);
        }

        let cipher = AesCcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
        let nonce = ccm::aead::Nonce::<AesCcm>::from_slice(nonce);

        let (plaintext, tail) = buffer.split_at_mut(pt_len);
        // detached-tag 版はその場暗号化しタグを別途返すため、成長可能バッファ
        // (=ヒープ)を必要としない。
        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, plaintext)
            .map_err(|_| Error::Crypto)?;
        tail[..AES_CCM_TAG_LEN].copy_from_slice(tag.as_slice());

        Ok(&buffer[..total])
    }

    fn aes_ccm_decrypt<'m>(
        &self,
        key: &[u8; AES_CCM_KEY_LEN],
        nonce: &[u8; AES_CCM_NONCE_LEN],
        aad: &[u8],
        buffer: &'m mut [u8],
    ) -> Result<&'m [u8]> {
        if buffer.len() < AES_CCM_TAG_LEN {
            return Err(Error::Crypto);
        }
        let ct_len = buffer.len() - AES_CCM_TAG_LEN;

        let cipher = AesCcm::new_from_slice(key).map_err(|_| Error::Crypto)?;
        let nonce = ccm::aead::Nonce::<AesCcm>::from_slice(nonce);

        let (ciphertext, tag_bytes) = buffer.split_at_mut(ct_len);
        let tag = ccm::aead::Tag::<AesCcm>::clone_from_slice(tag_bytes);
        // タグ不一致は認証失敗として Err(Crypto) を返す(panic しない)。
        cipher
            .decrypt_in_place_detached(nonce, aad, ciphertext, &tag)
            .map_err(|_| Error::Crypto)?;

        Ok(&buffer[..ct_len])
    }

    fn p256_generate_keypair(&self) -> Result<Self::Keypair> {
        let mut rng = self.rng.borrow_mut();
        let mut bytes = [0u8; P256_SECRET_KEY_LEN];
        // 棄却サンプリング: 有効なスカラ([1, n-1])が得られるまで繰り返す。
        // P-256 では棄却確率が極めて低いため数回で必ず成功する。
        for _ in 0..16 {
            rng.fill_bytes(&mut bytes)?;
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Ok(RcKeypair(secret));
            }
        }
        Err(Error::Crypto)
    }

    fn p256_keypair_from_bytes(&self, bytes: &[u8; P256_SECRET_KEY_LEN]) -> Result<Self::Keypair> {
        SecretKey::from_slice(bytes)
            .map(RcKeypair)
            .map_err(|_| Error::Crypto)
    }

    fn p256_public_key_from_bytes(&self, bytes: &[u8]) -> Result<Self::PublicKey> {
        let point = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Crypto)?;
        Option::from(PublicKey::from_encoded_point(&point))
            .map(RcPublicKey)
            .ok_or(Error::Crypto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    /// テスト用の決定的な擬似乱数生成器(xorshift64)。暗号用途ではない。
    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for chunk in dest.chunks_mut(8) {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let b = x.to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn backend() -> RustCrypto<TestRng> {
        RustCrypto::new(TestRng(0x0123_4567_89ab_cdef))
    }

    fn hex(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < s.len() / 2 {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    fn from_hex(s: &str, out: &mut [u8]) {
        assert_eq!(s.len(), out.len() * 2);
        let bytes = s.as_bytes();
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
    }

    // ---- SHA-256: NIST / FIPS 180-4 の既知ベクタ ----
    #[test]
    fn sha256_abc() {
        let c = backend();
        let mut out = [0u8; 32];
        c.sha256_oneshot(b"abc", &mut out);
        let expected =
            &hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..32];
        assert_eq!(&out[..], expected);
    }

    #[test]
    fn sha256_empty_incremental() {
        let c = backend();
        let mut h = c.sha256();
        h.update(b"");
        let mut out = [0u8; 32];
        h.finish(&mut out);
        let expected =
            &hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")[..32];
        assert_eq!(&out[..], expected);
    }

    #[test]
    fn sha256_incremental_matches_oneshot() {
        let c = backend();
        let msg = b"The quick brown fox jumps over the lazy dog";
        let mut h = c.sha256();
        h.update(&msg[..10]);
        h.update(&msg[10..]);
        let mut inc = [0u8; 32];
        h.finish(&mut inc);
        let mut one = [0u8; 32];
        c.sha256_oneshot(msg, &mut one);
        assert_eq!(inc, one);
        let expected =
            &hex("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")[..32];
        assert_eq!(&inc[..], expected);
    }

    // ---- HMAC-SHA256: RFC 4231 Test Case 2 ----
    #[test]
    fn hmac_sha256_rfc4231_tc2() {
        let c = backend();
        let mut out = [0u8; 32];
        c.hmac_sha256(b"Jefe", b"what do ya want for nothing?", &mut out)
            .unwrap();
        let expected =
            &hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")[..32];
        assert_eq!(&out[..], expected);
    }

    // ---- HKDF-SHA256: RFC 5869 Test Case 1 ----
    #[test]
    fn hkdf_sha256_rfc5869_tc1() {
        let c = backend();
        let mut ikm = [0u8; 22];
        from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &mut ikm);
        let mut salt = [0u8; 13];
        from_hex("000102030405060708090a0b0c", &mut salt);
        let mut info = [0u8; 10];
        from_hex("f0f1f2f3f4f5f6f7f8f9", &mut info);

        let mut okm = [0u8; 42];
        c.hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();

        let mut expected = [0u8; 42];
        from_hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            &mut expected,
        );
        assert_eq!(okm, expected);
    }

    // ---- AES-128-CCM: NIST SP 800-38C Appendix C 例1(nonce 13B は Matter 用に別ベクタ) ----
    // RFC 3610 Packet Vector #1(nonce 13 バイト, tag 8 バイト)を、
    // Matter が用いる 16 バイトタグへ拡張したベクタは公開値がないため、
    // ここでは round-trip と改竄検出、および固定鍵での既知タグ長を検証する。
    #[test]
    fn aes_ccm_roundtrip_and_tamper() {
        let c = backend();
        let key = [0x40u8; AES_CCM_KEY_LEN];
        let nonce = [0x10u8; AES_CCM_NONCE_LEN];
        let aad = b"matter-aad";
        let plaintext = b"hello matter ccm payload";

        let mut buf = [0u8; 64];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct = c
            .aes_ccm_encrypt(&key, &nonce, aad, &mut buf, plaintext.len())
            .unwrap();
        assert_eq!(ct.len(), plaintext.len() + AES_CCM_TAG_LEN);

        // 正常復号。
        let mut dec = [0u8; 64];
        let ct_len = plaintext.len() + AES_CCM_TAG_LEN;
        dec[..ct_len].copy_from_slice(&buf[..ct_len]);
        let pt = c
            .aes_ccm_decrypt(&key, &nonce, aad, &mut dec[..ct_len])
            .unwrap();
        assert_eq!(pt, plaintext);

        // タグ改竄 -> 認証失敗。
        let mut tampered = [0u8; 64];
        tampered[..ct_len].copy_from_slice(&buf[..ct_len]);
        tampered[ct_len - 1] ^= 0x01;
        assert_eq!(
            c.aes_ccm_decrypt(&key, &nonce, aad, &mut tampered[..ct_len]),
            Err(Error::Crypto)
        );

        // AAD 改竄 -> 認証失敗。
        let mut buf2 = [0u8; 64];
        buf2[..ct_len].copy_from_slice(&buf[..ct_len]);
        assert_eq!(
            c.aes_ccm_decrypt(&key, &nonce, b"wrong-aad", &mut buf2[..ct_len]),
            Err(Error::Crypto)
        );
    }

    // RFC 3610 Packet Vector #1 相当(tag を 16 バイトに拡張)ではなく、
    // RustCrypto ccm クレート自身のテストベクタで既知値を照合する。
    // (key/nonce/aad/pt から算出した ct||tag を固定値として検証)
    #[test]
    fn aes_ccm_known_vector() {
        // ccm crate の AES-128 / tag16 / nonce13 テストベクタ(Wycheproof tcId 1 相当)。
        let c = backend();
        let mut key = [0u8; 16];
        from_hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", &mut key);
        let mut nonce = [0u8; 13];
        from_hex("00000003020100a0a1a2a3a4a5", &mut nonce);
        let aad = {
            let mut a = [0u8; 8];
            from_hex("0001020304050607", &mut a);
            a
        };
        let mut pt = [0u8; 23];
        from_hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", &mut pt);

        let mut buf = [0u8; 23 + 16];
        buf[..pt.len()].copy_from_slice(&pt);
        let out = c
            .aes_ccm_encrypt(&key, &nonce, &aad, &mut buf, pt.len())
            .unwrap();

        // RFC 3610 PV#1 は tag 8 バイト。ここでは 16 バイトタグのため、
        // 暗号文本体(先頭 23 バイト)のみ RFC 3610 の期待値と一致することを確認する。
        let mut expected_ct = [0u8; 23];
        from_hex(
            "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
            &mut expected_ct,
        );
        assert_eq!(&out[..pt.len()], &expected_ct[..]);

        // round-trip(16 バイトタグ)も検証。
        let total = pt.len() + AES_CCM_TAG_LEN;
        let mut dec = buf;
        let dpt = c
            .aes_ccm_decrypt(&key, &nonce, &aad, &mut dec[..total])
            .unwrap();
        assert_eq!(dpt, &pt[..]);
    }

    // ---- P-256 ECDSA: RFC / FIPS の検証ベクタ + 生成署名の自己検証 ----
    #[test]
    fn p256_ecdsa_sign_verify_roundtrip() {
        let c = backend();
        let kp = c.p256_generate_keypair().unwrap();
        let pk = kp.public_key();

        let msg = b"Matter attestation challenge";
        let mut sig = [0u8; P256_SIGNATURE_LEN];
        kp.sign(msg, &mut sig).unwrap();
        assert!(pk.verify(msg, &sig).unwrap());

        // メッセージ改竄で検証失敗。
        assert!(!pk.verify(b"tampered message", &sig).unwrap());

        // 署名改竄で検証失敗。
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!pk.verify(msg, &bad).unwrap());
    }

    // NIST CAVP ECDSA P-256 SHA-256 の既知ベクタで verify を検証。
    #[test]
    fn p256_ecdsa_nist_verify_vector() {
        let c = backend();
        // FIPS 186-4 ECDSA P-256, SHA-256 テストベクタ(公開鍵 Qx/Qy, メッセージ, 署名 r/s)。
        let mut qx = [0u8; 32];
        from_hex(
            "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
            &mut qx,
        );
        let mut qy = [0u8; 32];
        from_hex(
            "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
            &mut qy,
        );
        let mut pub_bytes = [0u8; 65];
        pub_bytes[0] = 0x04;
        pub_bytes[1..33].copy_from_slice(&qx);
        pub_bytes[33..].copy_from_slice(&qy);

        let pk = c.p256_public_key_from_bytes(&pub_bytes).unwrap();

        // 元メッセージ(この CAVP ベクタの Msg)。verify は内部で SHA-256 する。
        let mut msg = [0u8; 128];
        from_hex(
            "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8",
            &mut msg,
        );
        let mut r = [0u8; 32];
        from_hex(
            "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
            &mut r,
        );
        let mut s = [0u8; 32];
        from_hex(
            "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903",
            &mut s,
        );
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r);
        sig[32..].copy_from_slice(&s);

        assert!(pk.verify(&msg, &sig).unwrap());
    }

    // ---- P-256 ECDH: RFC 5903 / NIST の共有秘密ベクタ ----
    #[test]
    fn p256_ecdh_nist_vector() {
        let c = backend();
        // NIST P-256 ECDH テストベクタ(NIST CAVP KAS)。
        // 自 private, 相手 public -> 共有秘密 X 座標。
        let mut priv_a = [0u8; 32];
        from_hex(
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            &mut priv_a,
        );
        let mut qx_b = [0u8; 32];
        from_hex(
            "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            &mut qx_b,
        );
        let mut qy_b = [0u8; 32];
        from_hex(
            "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            &mut qy_b,
        );
        let mut expected_z = [0u8; 32];
        from_hex(
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
            &mut expected_z,
        );

        let kp = c.p256_keypair_from_bytes(&priv_a).unwrap();
        let mut pub_b = [0u8; 65];
        pub_b[0] = 0x04;
        pub_b[1..33].copy_from_slice(&qx_b);
        pub_b[33..].copy_from_slice(&qy_b);
        let peer = c.p256_public_key_from_bytes(&pub_b).unwrap();

        let mut shared = [0u8; P256_SHARED_SECRET_LEN];
        kp.ecdh(&peer, &mut shared).unwrap();
        assert_eq!(shared, expected_z);
    }

    // ---- P-256 ECDH: 双方向で同一の共有秘密が得られること ----
    #[test]
    fn p256_ecdh_agreement() {
        let c = backend();
        let a = c.p256_generate_keypair().unwrap();
        let b = c.p256_generate_keypair().unwrap();

        let mut sa = [0u8; P256_SHARED_SECRET_LEN];
        a.ecdh(&b.public_key(), &mut sa).unwrap();
        let mut sb = [0u8; P256_SHARED_SECRET_LEN];
        b.ecdh(&a.public_key(), &mut sb).unwrap();
        assert_eq!(sa, sb);
    }

    // ---- 鍵のシリアライズ往復 ----
    #[test]
    fn p256_key_roundtrip() {
        let c = backend();
        let kp = c.p256_generate_keypair().unwrap();
        let sk_bytes = kp.to_bytes();
        let kp2 = c.p256_keypair_from_bytes(&sk_bytes).unwrap();
        assert_eq!(kp.to_bytes(), kp2.to_bytes());

        let pub_bytes = kp.public_key().to_bytes();
        assert_eq!(pub_bytes[0], 0x04);
        let pk2 = c.p256_public_key_from_bytes(&pub_bytes).unwrap();
        assert_eq!(pk2.to_bytes(), pub_bytes);
    }

    // ---- 不正入力で panic せず Err を返すこと ----
    #[test]
    fn invalid_inputs_return_err() {
        let c = backend();
        // 不正な公開鍵(全ゼロ)。
        assert_eq!(
            c.p256_public_key_from_bytes(&[0u8; 65]).err(),
            Some(Error::Crypto)
        );
        // 不正な秘密鍵(全ゼロ = スカラ 0)。
        assert_eq!(
            c.p256_keypair_from_bytes(&[0u8; 32]).err(),
            Some(Error::Crypto)
        );
        // AES-CCM: 出力バッファ不足。
        let mut small = [0u8; 4];
        assert_eq!(
            c.aes_ccm_encrypt(&[0u8; 16], &[0u8; 13], b"", &mut small, 4)
                .err(),
            Some(Error::NoSpace)
        );
        // AES-CCM: 復号入力がタグ長未満。
        let mut tiny = [0u8; 8];
        assert_eq!(
            c.aes_ccm_decrypt(&[0u8; 16], &[0u8; 13], b"", &mut tiny)
                .err(),
            Some(Error::Crypto)
        );
    }
}
