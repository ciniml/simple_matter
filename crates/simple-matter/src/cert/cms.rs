//! CMS SignedData(RFC 5652)の最小リーダと CD(Certification Declaration)検証。
//!
//! `docs/design/attestation.md` §7 に基づき、CD の CMS(PKCS#7)SignedData を
//! **chip の CD 形状に必要な範囲だけ**読む: 署名者 1 名、sid = subjectKeyIdentifier、
//! digest = SHA-256、signature = ecdsa-with-SHA256(P-256)、signedAttrs 無し
//! (署名対象は eContent そのもの)。DER は [`super::issue::der_tlv`] の
//! トップダウン走査で読み、不正入力でも panic しない。
//!
//! 既知署名者([`KNOWN_CD_SIGNERS`])は chip `gCdSigningKeys` と同じ集合: テスト CD 署名鍵
//! ([`TEST_CD_SIGNER_PUBKEY`]、"Matter Test CD Signing Authority")と CSA 公式 CD 署名鍵
//! "Signing Key 001"〜"005"(001 は chip の example CD が使用、市販製品は 001〜005)。
//! CD 署名 CA チェーンの動的検証は割り切り(attestation.md §7)。

use crate::crypto::{Crypto, P256PublicKey, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN};
use crate::error::{Error, Result};

use super::issue::{der_ecdsa_to_raw, der_tlv};

/// chip テスト CD 署名者の公開鍵(SEC1 非圧縮 P-256)。
///
/// chip `DefaultDeviceAttestationVerifier.cpp` の `gTestCdPubkeyBytes`
/// ("Matter Test CD Signing Authority"、開発専用鍵)と同値。
pub const TEST_CD_SIGNER_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x3c, 0x39, 0x89, 0x22, 0x45, 0x2b, 0x55, 0xca, 0xf3, 0x89, 0xc2, 0x5b, 0xd1, 0xbc, 0xa4,
    0x65, 0x69, 0x52, 0xcc, 0xb9, 0x0e, 0x88, 0x69, 0x24, 0x9a, 0xd8, 0x47, 0x46, 0x53, 0x01, 0x4c,
    0xbf, 0x95, 0xd6, 0x87, 0x96, 0x5e, 0x03, 0x6b, 0x52, 0x1c, 0x51, 0x03, 0x7e, 0x6b, 0x8c, 0xed,
    0xef, 0xca, 0x1e, 0xb4, 0x40, 0x46, 0x69, 0x4f, 0xa0, 0x88, 0x82, 0xee, 0xd6, 0x51, 0x9d, 0xec,
    0xba,
];

/// chip テスト CD 署名者の subjectKeyIdentifier(20 バイト)。
///
/// chip `gTestCdPubkeyKid` と同値。CMS SignerInfo の sid と照合する。
pub const TEST_CD_SIGNER_KID: [u8; 20] = [
    0x62, 0xfa, 0x82, 0x33, 0x59, 0xac, 0xfa, 0xa9, 0x96, 0x3e, 0x1c, 0xfa, 0x14, 0x0a, 0xdd, 0xf5,
    0x04, 0xf3, 0x71, 0x60,
];

/// CSA 公式 CD 署名鍵 "Signing Key 001" の公開鍵(chip `gCdSigningKey001PubkeyBytes`)。
///
/// chip の `DeviceAttestationCredsExample` 埋め込み CD(本実装の
/// `DEV_CD_FOR_ALL_EXAMPLES`)はこの鍵で署名されている。市販製品の CD は 001〜005 の
/// いずれかで署名される(実機: 市販 Thread デバイスの CD が 001 以外で CdSignerUnknown になった)。
pub const CSA_CD_SIGNER_001_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0xcd, 0xee, 0xe9, 0x3e, 0x44, 0xf8, 0xb7, 0x2b, 0xe3, 0xd1, 0xa9, 0xc0, 0x7e, 0x21, 0x96,
    0x8b, 0x9a, 0xff, 0xf3, 0xb4, 0x03, 0xf0, 0x5e, 0x16, 0x69, 0xd7, 0xb1, 0xe5, 0xca, 0xee, 0x6f,
    0xc7, 0x71, 0x4b, 0x42, 0xe7, 0xe2, 0x36, 0x95, 0xe9, 0x2c, 0xd7, 0x63, 0x54, 0x73, 0xa2, 0x80,
    0xae, 0x68, 0x8f, 0x37, 0xbb, 0x94, 0x89, 0xe1, 0x16, 0x29, 0xb9, 0xb9, 0x4f, 0xf7, 0xb0, 0x99,
    0x29,
];

/// CSA 公式 CD 署名鍵 "Signing Key 001" の subjectKeyIdentifier(chip `gCdSigningKey001Kid`)。
pub const CSA_CD_SIGNER_001_KID: [u8; 20] = [
    0xFE, 0x34, 0x3F, 0x95, 0x99, 0x47, 0x76, 0x3B, 0x61, 0xEE, 0x45, 0x39, 0x13, 0x13, 0x38, 0x49,
    0x4F, 0xE6, 0x7D, 0x8E,
];

/// CSA 公式 CD 署名鍵 "Signing Key 002" の公開鍵(chip `gCdSigningKey002PubkeyBytes`)。
pub const CSA_CD_SIGNER_002_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x03, 0x19, 0x37, 0xe8, 0xf9, 0x42, 0x51, 0x04, 0x5d, 0xf2, 0x74, 0x57, 0xbb, 0x46, 0x25,
    0x3e, 0xe3, 0x75, 0x4e, 0x8c, 0x12, 0xae, 0x28, 0x55, 0x7d, 0x80, 0x27, 0xb9, 0xd4, 0xc3, 0x56,
    0xd9, 0x1b, 0x40, 0x8c, 0xff, 0x32, 0x27, 0x50, 0x17, 0xb2, 0x5f, 0x8c, 0x8b, 0xa2, 0x05, 0x16,
    0xd5, 0xc8, 0x3a, 0xf2, 0xb7, 0x24, 0x12, 0x80, 0x13, 0xdf, 0xcc, 0x8f, 0x95, 0xd2, 0x00, 0xa9,
    0x0b,
];

/// CSA 公式 CD 署名鍵 "Signing Key 002" の subjectKeyIdentifier(chip `gCdSigningKey002Kid`)。
pub const CSA_CD_SIGNER_002_KID: [u8; 20] = [
    0xdd, 0x04, 0xdb, 0x58, 0x5b, 0x21, 0x4c, 0x1c, 0x58, 0x15, 0x87, 0xe6, 0x56, 0x8d, 0xf4, 0x87,
    0xb6, 0xdd, 0xc7, 0x01,
];

/// CSA 公式 CD 署名鍵 "Signing Key 003" の公開鍵(chip `gCdSigningKey003PubkeyBytes`)。
pub const CSA_CD_SIGNER_003_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x9f, 0x57, 0x5c, 0xd5, 0xfd, 0xb7, 0x52, 0x1f, 0x10, 0xa4, 0xdf, 0x31, 0xf0, 0x73, 0x91,
    0x2b, 0x61, 0x47, 0x28, 0xf2, 0xd3, 0x7f, 0x5b, 0x6b, 0x96, 0xbc, 0x2c, 0xbf, 0x7c, 0x0b, 0x11,
    0x96, 0x90, 0x57, 0x7d, 0x55, 0x5d, 0x21, 0xa0, 0x96, 0x60, 0xa8, 0xb0, 0x82, 0xa3, 0x39, 0xea,
    0x53, 0x0f, 0x7a, 0x81, 0x2d, 0x86, 0x93, 0xb5, 0x6f, 0xd7, 0x64, 0x18, 0x5f, 0xab, 0xcd, 0x32,
    0xf5,
];

/// CSA 公式 CD 署名鍵 "Signing Key 003" の subjectKeyIdentifier(chip `gCdSigningKey003Kid`)。
pub const CSA_CD_SIGNER_003_KID: [u8; 20] = [
    0x47, 0x10, 0x35, 0xe7, 0xc0, 0x4e, 0xaa, 0xa8, 0xbe, 0x7c, 0x4d, 0x4c, 0x13, 0xe3, 0xe4, 0xc2,
    0x09, 0x95, 0xa8, 0x4b,
];

/// CSA 公式 CD 署名鍵 "Signing Key 004" の公開鍵(chip `gCdSigningKey004PubkeyBytes`)。
pub const CSA_CD_SIGNER_004_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x7c, 0xfc, 0x8d, 0x88, 0x10, 0xa8, 0x9c, 0xf4, 0xfa, 0x19, 0x17, 0x78, 0xf2, 0xaf, 0xec,
    0x78, 0xf8, 0x51, 0x7a, 0x97, 0xa3, 0xe5, 0x7f, 0xc2, 0x13, 0xba, 0xd8, 0x88, 0xe3, 0x61, 0x1e,
    0x74, 0xff, 0xb6, 0x84, 0xbd, 0xeb, 0xa8, 0xa6, 0x8b, 0x25, 0x23, 0x4a, 0x5c, 0x35, 0x8f, 0x37,
    0x3b, 0xab, 0x9b, 0x6d, 0x30, 0x4e, 0x13, 0x06, 0xdd, 0x76, 0x20, 0xa5, 0x28, 0xd1, 0x16, 0x1c,
    0x0b,
];

/// CSA 公式 CD 署名鍵 "Signing Key 004" の subjectKeyIdentifier(chip `gCdSigningKey004Kid`)。
pub const CSA_CD_SIGNER_004_KID: [u8; 20] = [
    0xf6, 0x86, 0x03, 0xa3, 0x69, 0x2e, 0x98, 0x10, 0x72, 0x41, 0x9e, 0xa1, 0xe1, 0xab, 0x38, 0x54,
    0xbd, 0x77, 0x95, 0xd3,
];

/// CSA 公式 CD 署名鍵 "Signing Key 005" の公開鍵(chip `gCdSigningKey005PubkeyBytes`)。
pub const CSA_CD_SIGNER_005_PUBKEY: [u8; P256_PUBLIC_KEY_LEN] = [
    0x04, 0x43, 0x8a, 0x52, 0xc6, 0x62, 0xa2, 0xa6, 0xd7, 0x26, 0x47, 0xf9, 0x5e, 0xb7, 0x53, 0x13,
    0x6e, 0xe4, 0xae, 0x0f, 0xdb, 0x3a, 0xa9, 0xc1, 0x69, 0x31, 0x42, 0x6b, 0x3d, 0x08, 0x67, 0xf9,
    0x10, 0x3a, 0xe7, 0xd7, 0xa1, 0xb8, 0x87, 0xe9, 0xf8, 0x13, 0xa6, 0xf2, 0x6f, 0x76, 0xbb, 0xcd,
    0xa9, 0x35, 0x93, 0x78, 0x7c, 0x12, 0x77, 0x8c, 0xa8, 0xf2, 0x97, 0x5d, 0xc4, 0x5a, 0x20, 0x42,
    0xf9,
];

/// CSA 公式 CD 署名鍵 "Signing Key 005" の subjectKeyIdentifier(chip `gCdSigningKey005Kid`)。
pub const CSA_CD_SIGNER_005_KID: [u8; 20] = [
    0x63, 0x7f, 0x26, 0x34, 0xad, 0x62, 0xea, 0xfe, 0x6a, 0xf6, 0x62, 0xef, 0xb9, 0x6f, 0x6f, 0xd2,
    0xfc, 0xbf, 0xfc, 0x2f,
];

/// 既知の CD 署名者テーブル(KID → 公開鍵)。chip `gCdSigningKeys` と同じ集合(テスト鍵 + CSA 公式鍵 001〜005)。
pub const KNOWN_CD_SIGNERS: &[(&[u8; 20], &[u8; P256_PUBLIC_KEY_LEN])] = &[
    (&TEST_CD_SIGNER_KID, &TEST_CD_SIGNER_PUBKEY),
    (&CSA_CD_SIGNER_001_KID, &CSA_CD_SIGNER_001_PUBKEY),
    (&CSA_CD_SIGNER_002_KID, &CSA_CD_SIGNER_002_PUBKEY),
    (&CSA_CD_SIGNER_003_KID, &CSA_CD_SIGNER_003_PUBKEY),
    (&CSA_CD_SIGNER_004_KID, &CSA_CD_SIGNER_004_PUBKEY),
    (&CSA_CD_SIGNER_005_KID, &CSA_CD_SIGNER_005_PUBKEY),
];

/// OID: 1.2.840.113549.1.7.2(pkcs7 signedData)。
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// OID: 1.2.840.113549.1.7.1(pkcs7 data)。
const OID_PKCS7_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// OID: 2.16.840.1.101.3.4.2.1(sha256)。
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// OID: 1.2.840.10045.4.3.2(ecdsa-with-SHA256)。
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// CMS SignedData の借用ビュー(chip CD 形状、§7)。
pub struct CmsSignedData<'a> {
    /// eContent(= CD の Matter TLV バイト列)。
    pub econtent: &'a [u8],
    /// SignerInfo の sid(subjectKeyIdentifier、通常 20 バイト)。
    pub signer_kid: &'a [u8],
    /// 署名(DER ECDSA → 生 `r || s`)。署名対象は `econtent`。
    pub sig: [u8; P256_SIGNATURE_LEN],
}

/// `der` から CMS SignedData(chip CD 形状)をパースする。
///
/// 期待形状から外れる入力(複数署名者、signedAttrs 付き、sid が
/// issuerAndSerialNumber、他アルゴリズム等)は [`Error::Decode`] を返す。
pub fn parse_cms_signed_data(der: &[u8]) -> Result<CmsSignedData<'_>> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT }
    let (tag, cs, cl, _) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return Err(Error::Decode);
    }
    let ci = &der[cs..cs + cl];
    let (t, s, l, next) = der_tlv(ci, 0)?;
    if t != 0x06 || &ci[s..s + l] != OID_SIGNED_DATA {
        return Err(Error::Decode);
    }
    let (t, s, l, _) = der_tlv(ci, next)?;
    if t != 0xa0 {
        return Err(Error::Decode);
    }
    let content = &ci[s..s + l];

    // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
    //                           [0] certs?, [1] crls?, signerInfos SET }
    let (t, s, l, _) = der_tlv(content, 0)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let sd = &content[s..s + l];
    let (t, _, _, mut pos) = der_tlv(sd, 0)?; // version INTEGER(スキップ)
    if t != 0x02 {
        return Err(Error::Decode);
    }
    let (t, _, _, next) = der_tlv(sd, pos)?; // digestAlgorithms SET(スキップ)
    if t != 0x31 {
        return Err(Error::Decode);
    }
    pos = next;

    // encapContentInfo ::= SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
    let (t, s, l, next) = der_tlv(sd, pos)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let eci = &sd[s..s + l];
    pos = next;
    let (t, s2, l2, enext) = der_tlv(eci, 0)?;
    if t != 0x06 || &eci[s2..s2 + l2] != OID_PKCS7_DATA {
        return Err(Error::Decode);
    }
    let (t, s2, l2, _) = der_tlv(eci, enext)?;
    if t != 0xa0 {
        return Err(Error::Decode);
    }
    let inner = &eci[s2..s2 + l2];
    let (t, s3, l3, _) = der_tlv(inner, 0)?;
    if t != 0x04 {
        return Err(Error::Decode);
    }
    let econtent = &inner[s3..s3 + l3];

    // [0] certificates / [1] crls はあればスキップ(chip の CD には無い)。
    let mut si_set = None;
    while pos < sd.len() {
        let (t, s, l, next) = der_tlv(sd, pos)?;
        match t {
            0xa0 | 0xa1 => pos = next,
            0x31 => {
                si_set = Some(&sd[s..s + l]);
                break;
            }
            _ => return Err(Error::Decode),
        }
    }
    let si_set = si_set.ok_or(Error::Decode)?;

    // SignerInfo ::= SEQUENCE { version(3), sid [0] IMPLICIT skid, digestAlgorithm,
    //                           signatureAlgorithm, signature OCTET STRING }
    let (t, s, l, after_si) = der_tlv(si_set, 0)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    if after_si != si_set.len() {
        // 複数署名者は非対応(chip CD は 1 名)。
        return Err(Error::Decode);
    }
    let si = &si_set[s..s + l];
    let (t, _, _, next) = der_tlv(si, 0)?; // version
    if t != 0x02 {
        return Err(Error::Decode);
    }
    let (t, s, l, next2) = der_tlv(si, next)?; // sid: [0] IMPLICIT subjectKeyIdentifier
    if t != 0x80 {
        return Err(Error::Decode);
    }
    let signer_kid = &si[s..s + l];
    // digestAlgorithm ::= SEQUENCE { OID sha256 }
    let (t, s, l, next3) = der_tlv(si, next2)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    {
        let alg = &si[s..s + l];
        let (t, s2, l2, _) = der_tlv(alg, 0)?;
        if t != 0x06 || &alg[s2..s2 + l2] != OID_SHA256 {
            return Err(Error::Decode);
        }
    }
    // signedAttrs([0])があれば非対応(署名対象が変わる。chip CD には無い)。
    let (t, s, l, next4) = der_tlv(si, next3)?;
    if t == 0xa0 {
        return Err(Error::Decode);
    }
    // signatureAlgorithm ::= SEQUENCE { OID ecdsa-with-SHA256 }
    if t != 0x30 {
        return Err(Error::Decode);
    }
    {
        let alg = &si[s..s + l];
        let (t, s2, l2, _) = der_tlv(alg, 0)?;
        if t != 0x06 || &alg[s2..s2 + l2] != OID_ECDSA_SHA256 {
            return Err(Error::Decode);
        }
    }
    // signature OCTET STRING(DER ECDSA)
    let (t, s, l, _) = der_tlv(si, next4)?;
    if t != 0x04 {
        return Err(Error::Decode);
    }
    let sig = der_ecdsa_to_raw(&si[s..s + l])?;

    Ok(CmsSignedData {
        econtent,
        signer_kid,
        sig,
    })
}

/// CMS の署名を `signer_pubkey` で検証する(署名対象 = eContent、signedAttrs 無し形状)。
pub fn verify_cms_signature<C: Crypto>(
    crypto: &C,
    cms: &CmsSignedData<'_>,
    signer_pubkey: &[u8; P256_PUBLIC_KEY_LEN],
) -> Result<bool> {
    let key = crypto.p256_public_key_from_bytes(signer_pubkey)?;
    key.verify(cms.econtent, &cms.sig)
}

/// CD 本文(eContent の Matter TLV)から `vendor_id` を読み、`product_id` が
/// `product_id_array` に含まれるかを返す(§7 の VID/PID クロスチェック)。
///
/// CD 構造(Core Spec §6.3.1): anonymous struct
/// `{ 0: format_version, 1: vendor_id(u16), 2: product_id_array(array of u16), ... }`。
pub fn cd_matches_vid_pid(econtent: &[u8], vendor_id: u16, product_id: u16) -> Result<bool> {
    use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};
    let mut r = TlvReader::new(econtent);
    let first = r.read_next()?.ok_or(Error::Decode)?;
    if !matches!(
        first.value,
        TlvValue::ContainerStart(ContainerType::Structure)
    ) {
        return Err(Error::Decode);
    }
    let mut vid_ok = false;
    let mut pid_ok = false;
    let mut depth = 1usize;
    // 深さ 1 で product_id_array(cx2)に入っている間だけ PID を照合する
    // (dac_origin 等、他の入れ子と混同しない)。
    let mut in_pid_array = false;
    while let Some(e) = r.read_next()? {
        match e.value {
            TlvValue::ContainerStart(_) => {
                if depth == 1 {
                    in_pid_array = e.tag == TlvTag::ContextSpecific(2);
                }
                depth += 1;
                continue;
            }
            TlvValue::ContainerEnd => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                if depth == 1 {
                    in_pid_array = false;
                }
                continue;
            }
            _ => {}
        }
        if depth == 1 {
            if e.tag == TlvTag::ContextSpecific(1) {
                vid_ok = e.value.as_unsigned()? == u64::from(vendor_id);
            }
        } else if depth == 2
            && in_pid_array
            && e.value.as_unsigned().ok() == Some(u64::from(product_id))
        {
            pid_ok = true;
        }
    }
    Ok(vid_ok && pid_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::Rng;
    use crate::dm::clusters::operational_credentials::dev_creds::{
        DEV_CD_FOR_ALL_EXAMPLES, DEV_DAC_CERT_FFF1_8001,
    };

    struct DummyRng;
    impl Rng for DummyRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
            dest.fill(0x42);
            Ok(())
        }
    }

    fn crypto() -> RustCrypto<DummyRng> {
        RustCrypto::new(DummyRng)
    }

    /// 埋め込み開発 CD(chip DeviceAttestationCredsExample、FFF1)を chip テスト
    /// CD 署名鍵で検証できる。
    #[test]
    fn parse_and_verify_dev_cd() {
        let cms = parse_cms_signed_data(&DEV_CD_FOR_ALL_EXAMPLES).expect("parse CMS");
        // 埋め込み CD は CSA 公式 "Signing Key 001" 署名(chip DeviceAttestationCredsExample)。
        assert_eq!(cms.signer_kid, CSA_CD_SIGNER_001_KID, "signer KID matches");
        assert!(
            verify_cms_signature(&crypto(), &cms, &CSA_CD_SIGNER_001_PUBKEY).unwrap(),
            "CMS signature verifies with CSA CD Signing Key 001"
        );
    }

    /// eContent(CD 本文)を 1 バイト改竄すると署名検証が失敗する。
    #[test]
    fn tampered_cd_fails_signature() {
        let mut cd = DEV_CD_FOR_ALL_EXAMPLES;
        // eContent 内(openssl asn1parse 実測でオフセット 64.. が CD TLV 本文)を反転。
        cd[80] ^= 0x01;
        let cms = parse_cms_signed_data(&cd).expect("parse still succeeds");
        assert!(
            !verify_cms_signature(&crypto(), &cms, &CSA_CD_SIGNER_001_PUBKEY).unwrap(),
            "tampered CD must fail signature verification"
        );
    }

    /// 署名バイトの改竄も検証失敗(または decode 失敗)になる。
    #[test]
    fn tampered_signature_fails() {
        let mut cd = DEV_CD_FOR_ALL_EXAMPLES;
        let n = cd.len();
        cd[n - 1] ^= 0x01;
        // DER として壊れた場合(Err)も失敗扱いで OK。
        if let Ok(cms) = parse_cms_signed_data(&cd) {
            assert!(
                !verify_cms_signature(&crypto(), &cms, &CSA_CD_SIGNER_001_PUBKEY).unwrap_or(false)
            );
        }
    }

    /// CD の VID/PID クロスチェック: FFF1/8001 は含まれ、他 VID / 範囲外 PID は弾く。
    #[test]
    fn cd_vid_pid_crosscheck() {
        let cms = parse_cms_signed_data(&DEV_CD_FOR_ALL_EXAMPLES).unwrap();
        // 開発 CD は VID=0xFFF1、PID 0x8000..=0x8063 の 100 件。
        assert!(cd_matches_vid_pid(cms.econtent, 0xFFF1, 0x8001).unwrap());
        assert!(cd_matches_vid_pid(cms.econtent, 0xFFF1, 0x8063).unwrap());
        assert!(!cd_matches_vid_pid(cms.econtent, 0xFFF2, 0x8001).unwrap());
        assert!(!cd_matches_vid_pid(cms.econtent, 0xFFF1, 0x9000).unwrap());
    }

    /// DAC subject から Matter VID/PID DN 属性を読める(クロスチェックの DAC 側)。
    #[test]
    fn dac_subject_vid_pid() {
        let dac = crate::cert::parse_x509(&DEV_DAC_CERT_FFF1_8001).unwrap();
        assert_eq!(
            crate::cert::x509::matter_vid_pid(dac.subject),
            (Some(0xFFF1), Some(0x8001))
        );
    }
}
