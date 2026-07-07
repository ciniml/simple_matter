//! 最小 X.509 (DER) リーダとチェーン署名検証(device attestation 用、§2)。
//!
//! `docs/design/attestation.md` §2 に基づき、DAC / PAI / PAA の X.509 DER 証明書から
//! チェーン検証に必要な最小フィールド(TBSCertificate、署名、subject 公開鍵、
//! issuer / subject Name の DER バイト列)を **借用ビュー**として取り出す。DER は
//! [`super::issue::der_tlv`] のトップダウン走査で読み、不正入力でも panic しない。
//!
//! 署名アルゴリズムは ecdsa-with-SHA256(P-256)のみ想定する。チェーン検証は
//! `issuer(child) == subject(parent)` の DER バイト一致 + 署名検証で行い、AKID/SKID
//! 照合は必須にしない(chip のテスト証明書は Name 一致で足りる、§2)。

use crate::crypto::{Crypto, P256PublicKey, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN};
use crate::error::{Error, Result};

use super::issue::{der_ecdsa_to_raw, der_tlv};

/// X.509 証明書のチェーン検証に必要な借用ビュー(§2)。
pub struct X509Cert<'a> {
    /// TBSCertificate(署名対象、SEQUENCE ヘッダ込みの DER バイト列)。
    pub tbs: &'a [u8],
    /// ECDSA-Sig-Value → 生 `r || s`(64 バイト)。
    pub sig: [u8; P256_SIGNATURE_LEN],
    /// subjectPublicKey(SEC1 非圧縮 P-256、65 バイト)。
    pub spki_pubkey: [u8; P256_PUBLIC_KEY_LEN],
    /// issuer Name(DER そのまま。親の subject との一致比較に使う)。
    pub issuer: &'a [u8],
    /// subject Name(DER そのまま)。
    pub subject: &'a [u8],
}

/// subjectPublicKeyInfo(SEQUENCE の内容オクテット)から SEC1 非圧縮公開鍵を取り出す。
fn spki_to_sec1(spki: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_LEN]> {
    // SubjectPublicKeyInfo = SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
    let (t, _, _, after_algo) = der_tlv(spki, 0)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let (t, bs_cs, bs_cl, _) = der_tlv(spki, after_algo)?;
    if t != 0x03 {
        return Err(Error::Decode);
    }
    // BIT STRING 内容 = [unused_bits(0x00), 0x04, X(32), Y(32)]。
    let bits = &spki[bs_cs..bs_cs + bs_cl];
    let pk = bits.get(1..).ok_or(Error::Decode)?;
    if pk.len() != P256_PUBLIC_KEY_LEN || pk[0] != 0x04 {
        return Err(Error::Decode);
    }
    let mut out = [0u8; P256_PUBLIC_KEY_LEN];
    out.copy_from_slice(pk);
    Ok(out)
}

/// X.509 証明書(DER)を [`X509Cert`] へパースする。不正入力は [`Error::Decode`]。
///
/// 署名は ecdsa-with-SHA256 のみ想定。validity(notBefore/notAfter)は読み飛ばし、
/// 有効期間検証は行わない(コアは clock を持たない sans-IO、§1)。
pub fn parse_x509(der: &[u8]) -> Result<X509Cert<'_>> {
    // Certificate = SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tag, cs, cl, _) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return Err(Error::Decode);
    }
    let body = &der[cs..cs + cl];

    // tbsCertificate(SEQUENCE、署名対象。ヘッダ込みで捕捉)。
    let (t, tbs_cs, tbs_cl, after_tbs) = der_tlv(body, 0)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let tbs = &body[..after_tbs];
    let tbs_content = &body[tbs_cs..tbs_cs + tbs_cl];

    // signatureAlgorithm(SEQUENCE、読み飛ばし)。
    let (t, _, _, after_alg) = der_tlv(body, after_tbs)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    // signatureValue(BIT STRING; 内容 = [unused_bits, DER ECDSA-Sig-Value])。
    let (t, sig_cs, sig_cl, _) = der_tlv(body, after_alg)?;
    if t != 0x03 {
        return Err(Error::Decode);
    }
    let der_sig = body[sig_cs..sig_cs + sig_cl]
        .get(1..)
        .ok_or(Error::Decode)?;
    let sig = der_ecdsa_to_raw(der_sig)?;

    // TBSCertificate = SEQUENCE {
    //   [0] version(EXPLICIT、任意), serialNumber INTEGER, signature AlgId,
    //   issuer Name, validity, subject Name, subjectPublicKeyInfo, ... }
    let (t, _, _, after_ver) = der_tlv(tbs_content, 0)?;
    // version [0] があれば読み飛ばす。無ければ位置 0 が serialNumber。
    let pos = if t == 0xA0 { after_ver } else { 0 };

    let (t, _, _, after_serial) = der_tlv(tbs_content, pos)?;
    if t != 0x02 {
        return Err(Error::Decode);
    }
    let (t, _, _, after_sigalg) = der_tlv(tbs_content, after_serial)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    // issuer Name(SEQUENCE、ヘッダ込みで捕捉)。
    let (t, _, _, after_issuer) = der_tlv(tbs_content, after_sigalg)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let issuer = &tbs_content[after_sigalg..after_issuer];
    // validity(SEQUENCE、読み飛ばし)。
    let (t, _, _, after_validity) = der_tlv(tbs_content, after_issuer)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    // subject Name(SEQUENCE、ヘッダ込みで捕捉)。
    let (t, _, _, after_subject) = der_tlv(tbs_content, after_validity)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let subject = &tbs_content[after_validity..after_subject];
    // subjectPublicKeyInfo(SEQUENCE)。
    let (t, spki_cs, spki_cl, _) = der_tlv(tbs_content, after_subject)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let spki_pubkey = spki_to_sec1(&tbs_content[spki_cs..spki_cs + spki_cl])?;

    Ok(X509Cert {
        tbs,
        sig,
        spki_pubkey,
        issuer,
        subject,
    })
}

/// `child` の TBSCertificate が `issuer_pubkey`(SEC1)の秘密鍵で署名されているか検証する。
///
/// SHA-256 ハッシュ + P-256 ECDSA。検証成功で `Ok(true)`、不一致で `Ok(false)`。
/// 鍵復元・検証の内部エラーは [`Error::Crypto`]。
pub fn verify_signed_by<C: Crypto>(
    crypto: &C,
    child: &X509Cert<'_>,
    issuer_pubkey: &[u8; P256_PUBLIC_KEY_LEN],
) -> Result<bool> {
    let key = crypto.p256_public_key_from_bytes(issuer_pubkey)?;
    key.verify(child.tbs, &child.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::{P256Keypair, Rng};
    use crate::dm::clusters::operational_credentials::dev_creds::{
        DEV_DAC_CERT_FFF1_8001, DEV_DAC_PRIVKEY_FFF1_8001, DEV_PAI_CERT_FFF1, TEST_PAA_CERT_FFF1,
    };

    struct DummyRng;
    impl Rng for DummyRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            dest.iter_mut().for_each(|b| *b = 7);
            Ok(())
        }
    }
    fn backend() -> RustCrypto<DummyRng> {
        RustCrypto::new(DummyRng)
    }

    #[test]
    fn parses_real_dev_certs() {
        // DAC / PAI / PAA が全部パースでき、subject/issuer の DER 一致で連鎖する。
        let dac = parse_x509(&DEV_DAC_CERT_FFF1_8001).expect("DAC parse");
        let pai = parse_x509(&DEV_PAI_CERT_FFF1).expect("PAI parse");
        let paa = parse_x509(&TEST_PAA_CERT_FFF1).expect("PAA parse");
        assert_eq!(dac.spki_pubkey[0], 0x04);
        // DAC.issuer == PAI.subject、PAI.issuer == PAA.subject(バイト一致)。
        assert_eq!(dac.issuer, pai.subject);
        assert_eq!(pai.issuer, paa.subject);
        assert_ne!(dac.subject, pai.subject);
    }

    #[test]
    fn chain_verifies_positive() {
        let crypto = backend();
        let dac = parse_x509(&DEV_DAC_CERT_FFF1_8001).unwrap();
        let pai = parse_x509(&DEV_PAI_CERT_FFF1).unwrap();
        let paa = parse_x509(&TEST_PAA_CERT_FFF1).unwrap();
        assert!(
            verify_signed_by(&crypto, &dac, &pai.spki_pubkey).unwrap(),
            "DAC<-PAI"
        );
        assert!(
            verify_signed_by(&crypto, &pai, &paa.spki_pubkey).unwrap(),
            "PAI<-PAA"
        );
    }

    #[test]
    fn chain_verifies_negative_wrong_key() {
        let crypto = backend();
        let dac = parse_x509(&DEV_DAC_CERT_FFF1_8001).unwrap();
        let pai = parse_x509(&DEV_PAI_CERT_FFF1).unwrap();
        let paa = parse_x509(&TEST_PAA_CERT_FFF1).unwrap();
        // DAC を PAA 鍵で(誤って)検証すると不一致。
        assert!(!verify_signed_by(&crypto, &dac, &paa.spki_pubkey).unwrap());
        // PAI を DAC 鍵で検証すると不一致。
        assert!(!verify_signed_by(&crypto, &pai, &dac.spki_pubkey).unwrap());
    }

    #[test]
    fn rejects_truncated_der() {
        assert!(parse_x509(&DEV_DAC_CERT_FFF1_8001[..100]).is_err());
        assert!(parse_x509(&[]).is_err());
        assert!(parse_x509(&[0x30, 0x02, 0x00]).is_err());
    }

    // attestation 署名スキーム(elements ‖ challenge を DAC 鍵で ECDSA-P256)の固定検証。
    // コミッショナの検証ロジックと同一のプリミティブ(DAC 公開鍵 + verify)を用いる。
    #[test]
    fn attestation_signature_scheme() {
        let crypto = backend();
        let kp = crypto
            .p256_keypair_from_bytes(&DEV_DAC_PRIVKEY_FFF1_8001)
            .unwrap();
        let dac = parse_x509(&DEV_DAC_CERT_FFF1_8001).unwrap();
        let dac_key = crypto.p256_public_key_from_bytes(&dac.spki_pubkey).unwrap();

        let elements = b"\x15\x30\x01\x03CD\x18"; // 任意の疑似 elements
        let challenge = [0xABu8; 16];
        let mut tbs = [0u8; 64];
        tbs[..elements.len()].copy_from_slice(elements);
        tbs[elements.len()..elements.len() + 16].copy_from_slice(&challenge);
        let total = elements.len() + 16;

        let mut sig = [0u8; P256_SIGNATURE_LEN];
        kp.sign(&tbs[..total], &mut sig).unwrap();

        // 正: 一致。
        assert!(dac_key.verify(&tbs[..total], &sig).unwrap());
        // 改竄 elements: 失敗。
        let mut t2 = tbs;
        t2[0] ^= 0xFF;
        assert!(!dac_key.verify(&t2[..total], &sig).unwrap());
        // 別 challenge: 失敗(challenge を丸ごと差し替え)。
        let mut t3 = tbs;
        t3[elements.len()] ^= 0xFF;
        assert!(!dac_key.verify(&t3[..total], &sig).unwrap());
        // 署名バイト改竄: 失敗。
        let mut s2 = sig;
        s2[63] ^= 0xFF;
        assert!(!dac_key.verify(&tbs[..total], &s2).unwrap());
    }

    #[test]
    fn tampered_tbs_fails_verification() {
        let crypto = backend();
        let pai = parse_x509(&DEV_PAI_CERT_FFF1).unwrap();
        let mut bad = DEV_DAC_CERT_FFF1_8001;
        // 署名(ECDSA-Sig-Value)の末尾 s 整数の 1 バイトを反転。DER 構造は保つが
        // 署名値が変わるため検証が失敗するはず。
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        let dac = parse_x509(&bad).unwrap();
        assert!(!verify_signed_by(&crypto, &dac, &pai.spki_pubkey).unwrap());
    }
}
