//! [`crate::cert`] のユニットテスト。
//!
//! パース系のテストは rs-matter(`research/rs-matter/rs-matter/src/cert.rs`)の
//! 埋め込み証明書テストデータ(実 chip-cert が生成した NOC/ICAC/RCAC バイト列)を
//! 用い、全フィールド値を照合する。これらは Matter 仕様の実バイト列であり、
//! パーサの正当性を検証するのに適する。
//!
//! 署名・チェーン検証系のテストは 2 系統ある:
//!
//! 1. **実 Matter 互換の証明**: 上記 rs-matter 由来の実証明書(chip-cert 生成の
//!    NOC1 → ICAC1 → RCA1)チェーンに対し、DER-TBS 方式の [`MatterCert::verify_signature`]
//!    と [`verify_chain`] が実際に通ることを確認する。これらの証明書の署名は X.509
//!    DER の TBSCertificate に対して計算されており、本モジュールが仕様準拠であることの
//!    直接の証拠になる。
//! 2. **意味的な検証ロジック**: 有効期間・fabric-id 整合・authority-key-id 連鎖などの
//!    否定系は、DER-TBS 方式で自己整合的に署名したテスト証明書を生成して確認する
//!    (プレースホルダ署名で TLV を組み立て、パース後に DER TBS を再構築して署名し直す)。

use super::*;

// ---------------------------------------------------------------------------
// rs-matter 由来の実証明書テストデータ(パース照合用)
// 出典: research/rs-matter/rs-matter/src/cert.rs の tests モジュール
// ---------------------------------------------------------------------------

const NOC1_SUCCESS: &[u8] = &[
    0x15, 0x30, 0x1, 0x1, 0x1, 0x24, 0x2, 0x1, 0x37, 0x3, 0x24, 0x13, 0x1, 0x24, 0x15, 0x1, 0x18,
    0x26, 0x4, 0x80, 0x22, 0x81, 0x27, 0x26, 0x5, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x6, 0x26, 0x11,
    0x2, 0x5c, 0xbc, 0x0, 0x24, 0x15, 0x1, 0x18, 0x24, 0x7, 0x1, 0x24, 0x8, 0x1, 0x30, 0x9, 0x41,
    0x4, 0xba, 0x22, 0x56, 0x43, 0x4f, 0x59, 0x98, 0x32, 0x8d, 0xb8, 0xcb, 0x3f, 0x24, 0x90, 0x9a,
    0x96, 0x94, 0x43, 0x46, 0x67, 0xc2, 0x11, 0xe3, 0x80, 0x26, 0x65, 0xfc, 0x65, 0x37, 0x77, 0x3,
    0x25, 0x18, 0xd8, 0xdc, 0x85, 0xfa, 0xe6, 0x42, 0xe7, 0x55, 0xc9, 0x37, 0xcc, 0xb, 0x78, 0x84,
    0x3d, 0x2f, 0xac, 0x81, 0x88, 0x2e, 0x69, 0x0, 0xa5, 0xfc, 0xcd, 0xe0, 0xad, 0xb2, 0x69, 0xca,
    0x73, 0x37, 0xa, 0x35, 0x1, 0x28, 0x1, 0x18, 0x24, 0x2, 0x1, 0x36, 0x3, 0x4, 0x2, 0x4, 0x1,
    0x18, 0x30, 0x4, 0x14, 0x39, 0x68, 0x16, 0x1e, 0xb5, 0x56, 0x6d, 0xd3, 0xf8, 0x61, 0xf2, 0x95,
    0xf3, 0x55, 0xa0, 0xfb, 0xd2, 0x82, 0xc2, 0x29, 0x30, 0x5, 0x14, 0xce, 0x60, 0xb4, 0x28, 0x96,
    0x72, 0x27, 0x64, 0x81, 0xbc, 0x4f, 0x0, 0x78, 0xa3, 0x30, 0x48, 0xfe, 0x6e, 0x65, 0x86, 0x18,
    0x30, 0xb, 0x40, 0x2, 0x88, 0x42, 0x0, 0x6f, 0xcc, 0xe0, 0xf0, 0x6c, 0xd9, 0xf9, 0x5e, 0xe4,
    0xc2, 0xaa, 0x1f, 0x57, 0x71, 0x62, 0xdb, 0x6b, 0x4e, 0xe7, 0x55, 0x3f, 0xc6, 0xc7, 0x9f, 0xf8,
    0x30, 0xeb, 0x16, 0x6e, 0x6d, 0xc6, 0x9c, 0xb, 0xb7, 0xe2, 0xb8, 0xe3, 0xe7, 0x57, 0x88, 0x7b,
    0xda, 0xe5, 0x79, 0x39, 0x6d, 0x2c, 0x37, 0xb2, 0x7f, 0xc3, 0x63, 0x2f, 0x7e, 0x70, 0xab, 0x5a,
    0x2c, 0xf7, 0x5b, 0x18,
];

const ICAC1_SUCCESS: &[u8] = &[
    21, 48, 1, 1, 0, 36, 2, 1, 55, 3, 36, 20, 0, 36, 21, 1, 24, 38, 4, 128, 34, 129, 39, 38, 5,
    128, 37, 77, 58, 55, 6, 36, 19, 1, 36, 21, 1, 24, 36, 7, 1, 36, 8, 1, 48, 9, 65, 4, 86, 25,
    119, 24, 63, 212, 255, 43, 88, 61, 233, 121, 52, 102, 223, 233, 0, 251, 109, 161, 239, 224,
    204, 220, 119, 48, 192, 111, 182, 45, 255, 190, 84, 160, 149, 117, 11, 139, 7, 188, 85, 219,
    156, 182, 85, 19, 8, 184, 223, 2, 227, 64, 107, 174, 52, 245, 12, 186, 201, 242, 191, 241, 231,
    80, 55, 10, 53, 1, 41, 1, 24, 36, 2, 96, 48, 4, 20, 206, 96, 180, 40, 150, 114, 39, 100, 129,
    188, 79, 0, 120, 163, 48, 72, 254, 110, 101, 134, 48, 5, 20, 212, 86, 147, 190, 112, 121, 244,
    156, 112, 107, 7, 111, 17, 28, 109, 229, 100, 164, 68, 116, 24, 48, 11, 64, 243, 8, 190, 128,
    155, 254, 245, 21, 205, 241, 217, 246, 204, 182, 247, 41, 81, 91, 33, 155, 230, 223, 212, 116,
    33, 162, 208, 148, 100, 89, 175, 253, 78, 212, 7, 69, 207, 140, 45, 129, 249, 64, 104, 70, 68,
    43, 164, 19, 126, 114, 138, 79, 104, 238, 20, 226, 88, 118, 105, 56, 12, 92, 31, 171, 24,
];

const RCA1_SUCCESS: &[u8] = &[
    0x15, 0x30, 0x1, 0x1, 0x0, 0x24, 0x2, 0x1, 0x37, 0x3, 0x24, 0x14, 0x0, 0x24, 0x15, 0x1, 0x18,
    0x26, 0x4, 0x80, 0x22, 0x81, 0x27, 0x26, 0x5, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x6, 0x24, 0x14,
    0x0, 0x24, 0x15, 0x1, 0x18, 0x24, 0x7, 0x1, 0x24, 0x8, 0x1, 0x30, 0x9, 0x41, 0x4, 0x6d, 0x70,
    0x7e, 0x4b, 0x98, 0xf6, 0x2b, 0xab, 0x44, 0xd6, 0xfe, 0xa3, 0x2e, 0x39, 0xd8, 0xc3, 0x0, 0xa0,
    0xe, 0xa8, 0x6c, 0x83, 0xff, 0x69, 0xd, 0xe8, 0x42, 0x1, 0xeb, 0xd, 0xaa, 0x68, 0x5d, 0xcb,
    0x97, 0x2, 0x80, 0x1d, 0xa8, 0x50, 0x2, 0x2e, 0x5a, 0xa2, 0x5a, 0x2e, 0x51, 0x26, 0x4, 0xd2,
    0x39, 0x62, 0xcd, 0x82, 0x38, 0x63, 0x28, 0xbf, 0x15, 0x1c, 0xa6, 0x27, 0xe0, 0xd7, 0x37, 0xa,
    0x35, 0x1, 0x29, 0x1, 0x18, 0x24, 0x2, 0x60, 0x30, 0x4, 0x14, 0xd4, 0x56, 0x93, 0xbe, 0x70,
    0x79, 0xf4, 0x9c, 0x70, 0x6b, 0x7, 0x6f, 0x11, 0x1c, 0x6d, 0xe5, 0x64, 0xa4, 0x44, 0x74, 0x30,
    0x5, 0x14, 0xd4, 0x56, 0x93, 0xbe, 0x70, 0x79, 0xf4, 0x9c, 0x70, 0x6b, 0x7, 0x6f, 0x11, 0x1c,
    0x6d, 0xe5, 0x64, 0xa4, 0x44, 0x74, 0x18, 0x30, 0xb, 0x40, 0x3, 0xd, 0x77, 0xe1, 0x9e, 0xea,
    0x9c, 0x5, 0x5c, 0xcc, 0x47, 0xe8, 0xb3, 0x18, 0x1a, 0xd1, 0x74, 0xee, 0xc6, 0x2e, 0xa1, 0x20,
    0x16, 0xbd, 0x20, 0xb4, 0x3d, 0xac, 0x24, 0xbe, 0x17, 0xf9, 0xe, 0xb7, 0x9a, 0x98, 0xc8, 0xbc,
    0x6a, 0xce, 0x99, 0x2a, 0x2e, 0x63, 0x4c, 0x76, 0x6, 0x45, 0x93, 0xd3, 0x7c, 0x4, 0x0, 0xe4,
    0xc7, 0x78, 0xe9, 0x83, 0x5b, 0xc, 0x33, 0x61, 0x5c, 0x2e, 0x18,
];

// ---------------------------------------------------------------------------
// パース照合
// ---------------------------------------------------------------------------

#[test]
fn parse_noc_fields() {
    let c = MatterCert::parse(NOC1_SUCCESS).unwrap();

    assert_eq!(c.serial_number(), &[0x01]);
    assert_eq!(c.signature_algorithm(), SignatureAlgorithm::EcdsaWithSha256);
    assert_eq!(c.public_key_algorithm(), PublicKeyAlgorithm::EcPublicKey);
    assert_eq!(c.ec_curve_id(), EcCurveId::Prime256v1);

    assert_eq!(c.not_before(), u32::from_le_bytes([0x80, 0x22, 0x81, 0x27]));
    assert_eq!(c.not_after(), u32::from_le_bytes([0x80, 0x25, 0x4d, 0x3a]));

    // issuer は ICAC(icac-id=1, fabric-id=1)。
    assert_eq!(c.issuer().icac_id().unwrap(), Some(1));
    assert_eq!(c.issuer().fabric_id().unwrap(), Some(1));

    // subject は NOC(node-id, fabric-id)。
    assert_eq!(
        c.subject().node_id().unwrap(),
        Some(u64::from(u32::from_le_bytes([0x02, 0x5c, 0xbc, 0x00])))
    );
    assert_eq!(c.subject().fabric_id().unwrap(), Some(1));

    // 公開鍵は SEC1 非圧縮 65 バイト。
    assert_eq!(c.public_key().len(), 65);
    assert_eq!(c.public_key()[0], 0x04);
    assert_eq!(c.public_key()[1], 0xba);

    // 拡張。
    let ext = c.extensions();
    let bc = ext.basic_constraints().unwrap();
    assert!(!bc.is_ca);
    assert_eq!(bc.path_len_constraint, None);
    assert_eq!(ext.key_usage(), Some(key_usage::DIGITAL_SIGNATURE));
    assert!(ext
        .extended_key_usage_has_all(&[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH])
        .unwrap());
    assert_eq!(ext.subject_key_id().unwrap().len(), 20);
    assert_eq!(ext.subject_key_id().unwrap()[0], 0x39);
    assert_eq!(ext.authority_key_id().unwrap().len(), 20);
    assert_eq!(ext.authority_key_id().unwrap()[0], 0xce);

    assert_eq!(c.signature().len(), 64);
    assert_eq!(c.signature()[0], 0x02);

    assert_eq!(c.cert_type().unwrap(), CertType::Noc);
    // NOC は自己署名でない(akid != skid)。
    assert!(!c.is_self_signed().unwrap());
}

#[test]
fn parse_icac_fields() {
    let c = MatterCert::parse(ICAC1_SUCCESS).unwrap();
    assert_eq!(c.serial_number(), &[0x00]);
    assert_eq!(c.cert_type().unwrap(), CertType::Icac);
    // subject: icac-id=1, fabric-id=1。issuer: rcac-id=0。
    assert_eq!(c.subject().icac_id().unwrap(), Some(1));
    assert_eq!(c.subject().fabric_id().unwrap(), Some(1));
    assert_eq!(c.issuer().rcac_id().unwrap(), Some(0));

    let bc = c.extensions().basic_constraints().unwrap();
    assert!(bc.is_ca);
    assert_ne!(
        c.extensions().key_usage().unwrap() & key_usage::KEY_CERT_SIGN,
        0
    );
    assert!(!c.is_self_signed().unwrap());
}

#[test]
fn parse_rcac_fields() {
    let c = MatterCert::parse(RCA1_SUCCESS).unwrap();
    assert_eq!(c.serial_number(), &[0x00]);
    assert_eq!(c.cert_type().unwrap(), CertType::Rcac);
    assert_eq!(c.subject().rcac_id().unwrap(), Some(0));
    assert_eq!(c.subject().fabric_id().unwrap(), Some(1));

    let bc = c.extensions().basic_constraints().unwrap();
    assert!(bc.is_ca);
    assert_eq!(
        c.extensions().key_usage(),
        Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
    );
    // RCAC は自己署名(akid == skid)。
    assert!(c.is_self_signed().unwrap());
}

#[test]
fn dn_iteration_yields_all_attributes() {
    let c = MatterCert::parse(NOC1_SUCCESS).unwrap();
    let mut attrs = 0;
    let mut saw_node = false;
    let mut saw_fabric = false;
    for a in c.subject().iter() {
        let a = a.unwrap();
        attrs += 1;
        match a.attr_type {
            dn_attr::MATTER_NODE_ID => saw_node = true,
            dn_attr::MATTER_FABRIC_ID => saw_fabric = true,
            _ => {}
        }
    }
    assert_eq!(attrs, 2);
    assert!(saw_node && saw_fabric);
}

// ---------------------------------------------------------------------------
// 不正 TLV(panic せず Err)
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_is_err() {
    assert!(matches!(MatterCert::parse(&[]), Err(Error::Decode)));
}

#[test]
fn parse_not_a_struct_is_err() {
    // トップレベルが u8。
    assert!(matches!(
        MatterCert::parse(&[0x04, 0x01]),
        Err(Error::Decode)
    ));
}

#[test]
fn parse_truncated_is_err() {
    // NOC を途中で切る。パニックせず Decode。
    let truncated = &NOC1_SUCCESS[..40];
    assert!(matches!(MatterCert::parse(truncated), Err(Error::Decode)));
}

#[test]
fn parse_missing_fields_is_err() {
    // 空の struct(必須フィールド欠落)。
    assert!(matches!(
        MatterCert::parse(&[0x15, 0x18]),
        Err(Error::Decode)
    ));
}

#[test]
fn parse_wrong_pubkey_len_is_err() {
    // 公開鍵長フィールド(0x30, 0x09, 0x41=65)を 0x40=64 に潰すと長さ検査で Decode。
    let mut buf = [0u8; 256];
    buf[..NOC1_SUCCESS.len()].copy_from_slice(NOC1_SUCCESS);
    let mut idx = 0;
    for i in 0..NOC1_SUCCESS.len() - 2 {
        if buf[i] == 0x30 && buf[i + 1] == 0x09 && buf[i + 2] == 0x41 {
            idx = i;
            break;
        }
    }
    buf[idx + 2] = 0x40; // 65 -> 64
    assert!(matches!(
        MatterCert::parse(&buf[..NOC1_SUCCESS.len()]),
        Err(Error::Decode)
    ));
}

// ---------------------------------------------------------------------------
// 署名・チェーン検証(自己生成証明書。rustcrypto backend が必要)
// ---------------------------------------------------------------------------

#[cfg(feature = "rustcrypto")]
mod signed {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::{P256Keypair, Rng};
    use crate::tlv::{TlvTag, TlvWriter};

    struct DummyRng;
    impl Rng for DummyRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
            dest.iter_mut().for_each(|b| *b = 7);
            Ok(())
        }
    }

    fn backend() -> RustCrypto<DummyRng> {
        RustCrypto::new(DummyRng)
    }

    fn cx(n: u8) -> TlvTag {
        TlvTag::ContextSpecific(n)
    }

    #[derive(Clone, Copy)]
    struct DnInt {
        tag: u8,
        val: u64,
    }

    fn write_dn(w: &mut TlvWriter, ctx: u8, attrs: &[DnInt]) {
        w.start_list(&cx(ctx)).unwrap();
        for a in attrs {
            w.write_u64(&cx(a.tag), a.val).unwrap();
        }
        w.end_container().unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn write_cert<C: crate::crypto::Crypto>(
        out: &mut [u8],
        serial: &[u8],
        issuer: &[DnInt],
        not_before: u32,
        not_after: u32,
        subject: &[DnInt],
        subject_pub: &[u8; 65],
        is_ca: bool,
        path_len: Option<u8>,
        key_usage_bits: u16,
        eku: &[u8],
        skid: &[u8; 20],
        akid: &[u8; 20],
        issuer_kp: &C::Keypair,
    ) -> usize {
        // まずプレースホルダ署名(全 0)で TLV 証明書を組み立てる。
        let len = {
            let mut w = TlvWriter::new(out);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), serial).unwrap(); // serial-num
            w.write_u8(&cx(2), 1).unwrap(); // sig-algo = ECDSAWithSHA256
            write_dn(&mut w, 3, issuer);
            w.write_u32(&cx(4), not_before).unwrap();
            w.write_u32(&cx(5), not_after).unwrap();
            write_dn(&mut w, 6, subject);
            w.write_u8(&cx(7), 1).unwrap(); // pubkey-algo
            w.write_u8(&cx(8), 1).unwrap(); // curve-id
            w.write_bytes(&cx(9), subject_pub).unwrap();
            // extensions
            w.start_list(&cx(10)).unwrap();
            w.start_struct(&cx(1)).unwrap(); // basic-constraints
            w.write_bool(&cx(1), is_ca).unwrap();
            if let Some(p) = path_len {
                w.write_u8(&cx(2), p).unwrap();
            }
            w.end_container().unwrap();
            w.write_u16(&cx(2), key_usage_bits).unwrap(); // key-usage
            if !eku.is_empty() {
                w.start_array(&cx(3)).unwrap(); // extended-key-usage
                for e in eku {
                    w.write_u8(&TlvTag::Anonymous, *e).unwrap();
                }
                w.end_container().unwrap();
            }
            w.write_bytes(&cx(4), skid).unwrap(); // subject-key-id
            w.write_bytes(&cx(5), akid).unwrap(); // authority-key-id
            w.end_container().unwrap(); // extensions
            w.write_bytes(&cx(11), &[0u8; 64]).unwrap(); // signature(プレースホルダ)
            w.end_container().unwrap(); // struct
            w.len()
        };

        // パースして DER TBSCertificate を再構築し、それに対して署名する。
        let mut tbs = [0u8; super::MAX_TBS_DER_LEN];
        let tbs_len = {
            let cert = MatterCert::parse(&out[..len]).unwrap();
            cert.to_be_signed(&mut tbs).unwrap()
        };
        let mut sig = [0u8; 64];
        issuer_kp.sign(&tbs[..tbs_len], &mut sig).unwrap();
        // 署名フィールドの 64 バイトは、末尾の struct 終端(0x18)の直前に位置する。
        out[len - 65..len - 1].copy_from_slice(&sig);
        len
    }

    const FABRIC_ID: u64 = 0x1122_3344_5566_7788;
    const NODE_ID: u64 = 0x0000_0000_0000_AABB;
    const RCAC_ID: u64 = 0xAAAA;
    const ICAC_ID: u64 = 0xBBBB;

    const RCAC_SKID: [u8; 20] = [0xA0; 20];
    const ICAC_SKID: [u8; 20] = [0xB0; 20];
    const NOC_SKID: [u8; 20] = [0xC0; 20];

    const NOW: u32 = 500;
    const NOT_BEFORE: u32 = 100;
    const NOT_AFTER: u32 = 1000;

    /// テスト用の 3 段チェーンを生成する。
    /// 返すバッファ長を out に書き、鍵はスカラ固定で決定的に生成する。
    struct Chain {
        rcac: [u8; 400],
        rcac_len: usize,
        icac: [u8; 400],
        icac_len: usize,
        noc: [u8; 400],
        noc_len: usize,
    }

    fn build_chain(crypto: &RustCrypto<DummyRng>) -> Chain {
        use crate::crypto::Crypto;
        let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
        let icac_kp = crypto.p256_keypair_from_bytes(&[0x22; 32]).unwrap();
        let noc_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
        let rcac_pub = rcac_kp.public_key().to_bytes();
        let icac_pub = icac_kp.public_key().to_bytes();
        let noc_pub = noc_kp.public_key().to_bytes();

        let mut c = Chain {
            rcac: [0; 400],
            rcac_len: 0,
            icac: [0; 400],
            icac_len: 0,
            noc: [0; 400],
            noc_len: 0,
        };

        // RCAC(自己署名)。
        c.rcac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut c.rcac,
            &[0x00],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &rcac_pub,
            true,
            None,
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            &[],
            &RCAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );

        // ICAC(RCAC が署名)。
        c.icac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut c.icac,
            &[0x01],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &icac_pub,
            true,
            Some(0),
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            &[],
            &ICAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );

        // NOC(ICAC が署名)。
        c.noc_len = write_cert::<RustCrypto<DummyRng>>(
            &mut c.noc,
            &[0x02],
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_NODE_ID,
                    val: NODE_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &noc_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &ICAC_SKID,
            &icac_kp,
        );

        c
    }

    #[test]
    fn generated_cert_roundtrips_and_verifies() {
        let crypto = backend();
        let c = build_chain(&crypto);
        let rcac = MatterCert::parse(&c.rcac[..c.rcac_len]).unwrap();
        // フィールドが往復する。
        assert_eq!(rcac.subject().fabric_id().unwrap(), Some(FABRIC_ID));
        assert_eq!(rcac.subject().rcac_id().unwrap(), Some(RCAC_ID));
        assert!(rcac.is_self_signed().unwrap());
        // 自己署名の検証成功。
        rcac.verify_signature(&crypto, rcac.public_key()).unwrap();
    }

    #[test]
    fn signature_tamper_fails() {
        let crypto = backend();
        let mut c = build_chain(&crypto);
        // 署名バイトの 1 つを反転(末尾の 0x18 の直前が署名の最終バイト)。
        c.noc[c.noc_len - 2] ^= 0x01;
        let noc = MatterCert::parse(&c.noc[..c.noc_len]).unwrap();
        // 親(ICAC)公開鍵で検証すると失敗。
        let icac = MatterCert::parse(&c.icac[..c.icac_len]).unwrap();
        assert_eq!(
            noc.verify_signature(&crypto, icac.public_key()),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn chain_with_icac_verifies() {
        let crypto = backend();
        let c = build_chain(&crypto);
        let noc = MatterCert::parse(&c.noc[..c.noc_len]).unwrap();
        let icac = MatterCert::parse(&c.icac[..c.icac_len]).unwrap();
        let rcac = MatterCert::parse(&c.rcac[..c.rcac_len]).unwrap();
        verify_chain(&crypto, &noc, Some(&icac), &rcac, NOW).unwrap();
    }

    #[test]
    fn chain_without_icac_verifies() {
        let crypto = backend();
        use crate::crypto::Crypto;
        let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
        let noc_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
        let rcac_pub = rcac_kp.public_key().to_bytes();
        let noc_pub = noc_kp.public_key().to_bytes();

        let mut rcac_buf = [0u8; 400];
        let rcac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut rcac_buf,
            &[0x00],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &rcac_pub,
            true,
            None,
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            &[],
            &RCAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );

        let mut noc_buf = [0u8; 400];
        let noc_len = write_cert::<RustCrypto<DummyRng>>(
            &mut noc_buf,
            &[0x02],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_NODE_ID,
                    val: NODE_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &noc_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );

        let noc = MatterCert::parse(&noc_buf[..noc_len]).unwrap();
        let rcac = MatterCert::parse(&rcac_buf[..rcac_len]).unwrap();
        verify_chain(&crypto, &noc, None, &rcac, NOW).unwrap();
    }

    #[test]
    fn chain_expired_fails() {
        let crypto = backend();
        let c = build_chain(&crypto);
        let noc = MatterCert::parse(&c.noc[..c.noc_len]).unwrap();
        let icac = MatterCert::parse(&c.icac[..c.icac_len]).unwrap();
        let rcac = MatterCert::parse(&c.rcac[..c.rcac_len]).unwrap();
        // now が not_after を超過。
        assert_eq!(
            verify_chain(&crypto, &noc, Some(&icac), &rcac, NOT_AFTER + 1),
            Err(Error::CertInvalid)
        );
    }

    #[test]
    fn chain_bad_signature_fails() {
        let crypto = backend();
        let mut c = build_chain(&crypto);
        // ICAC の署名を破壊。チェーンの ICAC->RCAC リンクで失敗する。
        c.icac[c.icac_len - 2] ^= 0x01;
        let noc = MatterCert::parse(&c.noc[..c.noc_len]).unwrap();
        let icac = MatterCert::parse(&c.icac[..c.icac_len]).unwrap();
        let rcac = MatterCert::parse(&c.rcac[..c.rcac_len]).unwrap();
        assert_eq!(
            verify_chain(&crypto, &noc, Some(&icac), &rcac, NOW),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn chain_fabric_mismatch_fails() {
        let crypto = backend();
        use crate::crypto::Crypto;
        let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
        let icac_kp = crypto.p256_keypair_from_bytes(&[0x22; 32]).unwrap();
        let noc_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
        let rcac_pub = rcac_kp.public_key().to_bytes();
        let icac_pub = icac_kp.public_key().to_bytes();
        let noc_pub = noc_kp.public_key().to_bytes();

        let mut rcac_buf = [0u8; 400];
        let rcac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut rcac_buf,
            &[0x00],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &rcac_pub,
            true,
            None,
            key_usage::KEY_CERT_SIGN,
            &[],
            &RCAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        let mut icac_buf = [0u8; 400];
        let icac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut icac_buf,
            &[0x01],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &icac_pub,
            true,
            Some(0),
            key_usage::KEY_CERT_SIGN,
            &[],
            &ICAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        // NOC の fabric-id を別値にする。
        let mut noc_buf = [0u8; 400];
        let noc_len = write_cert::<RustCrypto<DummyRng>>(
            &mut noc_buf,
            &[0x02],
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_NODE_ID,
                    val: NODE_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: 0xDEAD,
                },
            ],
            &noc_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &ICAC_SKID,
            &icac_kp,
        );

        let noc = MatterCert::parse(&noc_buf[..noc_len]).unwrap();
        let icac = MatterCert::parse(&icac_buf[..icac_len]).unwrap();
        let rcac = MatterCert::parse(&rcac_buf[..rcac_len]).unwrap();
        assert_eq!(
            verify_chain(&crypto, &noc, Some(&icac), &rcac, NOW),
            Err(Error::CertInvalid)
        );
    }

    #[test]
    fn chain_wrong_authority_key_fails() {
        let crypto = backend();
        use crate::crypto::Crypto;
        let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
        let icac_kp = crypto.p256_keypair_from_bytes(&[0x22; 32]).unwrap();
        let noc_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
        let rcac_pub = rcac_kp.public_key().to_bytes();
        let icac_pub = icac_kp.public_key().to_bytes();
        let noc_pub = noc_kp.public_key().to_bytes();

        let mut rcac_buf = [0u8; 400];
        let rcac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut rcac_buf,
            &[0x00],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &rcac_pub,
            true,
            None,
            key_usage::KEY_CERT_SIGN,
            &[],
            &RCAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        let mut icac_buf = [0u8; 400];
        let icac_len = write_cert::<RustCrypto<DummyRng>>(
            &mut icac_buf,
            &[0x01],
            &[
                DnInt {
                    tag: dn_attr::MATTER_RCAC_ID,
                    val: RCAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &icac_pub,
            true,
            Some(0),
            key_usage::KEY_CERT_SIGN,
            &[],
            &ICAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        // NOC の authority-key-id を誤った値にする(ICAC の skid と不一致)。
        let mut noc_buf = [0u8; 400];
        let noc_len = write_cert::<RustCrypto<DummyRng>>(
            &mut noc_buf,
            &[0x02],
            &[
                DnInt {
                    tag: dn_attr::MATTER_ICAC_ID,
                    val: ICAC_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            NOT_BEFORE,
            NOT_AFTER,
            &[
                DnInt {
                    tag: dn_attr::MATTER_NODE_ID,
                    val: NODE_ID,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ],
            &noc_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &[0xFF; 20],
            &icac_kp,
        );

        let noc = MatterCert::parse(&noc_buf[..noc_len]).unwrap();
        let icac = MatterCert::parse(&icac_buf[..icac_len]).unwrap();
        let rcac = MatterCert::parse(&rcac_buf[..rcac_len]).unwrap();
        assert_eq!(
            verify_chain(&crypto, &noc, Some(&icac), &rcac, NOW),
            Err(Error::CertInvalid)
        );
    }

    // -----------------------------------------------------------------------
    // 実 Matter 互換の証明: chip-cert 生成の実証明書チェーンの署名/チェーン検証
    // -----------------------------------------------------------------------

    /// NOC1 の not-before(0x2781_2280)< この時刻 < not-after(0x3a4d_2580)。
    const REAL_NOW: u32 = 800_000_000;

    #[test]
    fn real_chain_signatures_verify() {
        let crypto = backend();
        let noc = MatterCert::parse(NOC1_SUCCESS).unwrap();
        let icac = MatterCert::parse(ICAC1_SUCCESS).unwrap();
        let rcac = MatterCert::parse(RCA1_SUCCESS).unwrap();
        // 各リンクの署名を親の公開鍵(RCAC は自身)で検証する。
        // 実証明書の署名は X.509 DER TBSCertificate に対して計算されており、
        // これが通ることが実 Matter 互換の直接の証拠になる。
        noc.verify_signature(&crypto, icac.public_key()).unwrap();
        icac.verify_signature(&crypto, rcac.public_key()).unwrap();
        rcac.verify_signature(&crypto, rcac.public_key()).unwrap();
    }

    #[test]
    fn real_chain_verifies() {
        let crypto = backend();
        let noc = MatterCert::parse(NOC1_SUCCESS).unwrap();
        let icac = MatterCert::parse(ICAC1_SUCCESS).unwrap();
        let rcac = MatterCert::parse(RCA1_SUCCESS).unwrap();
        verify_chain(&crypto, &noc, Some(&icac), &rcac, REAL_NOW).unwrap();
    }

    #[test]
    fn real_chain_wrong_issuer_key_fails() {
        let crypto = backend();
        let noc = MatterCert::parse(NOC1_SUCCESS).unwrap();
        let rcac = MatterCert::parse(RCA1_SUCCESS).unwrap();
        // NOC は ICAC が発行しており、RCAC の公開鍵では署名検証に失敗する。
        assert_eq!(
            noc.verify_signature(&crypto, rcac.public_key()),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn real_noc_signature_tamper_fails() {
        let crypto = backend();
        let icac = MatterCert::parse(ICAC1_SUCCESS).unwrap();
        let mut buf = [0u8; NOC1_SUCCESS.len()];
        buf.copy_from_slice(NOC1_SUCCESS);
        let n = buf.len();
        buf[n - 2] ^= 0x01; // 署名の末尾バイトを反転。
        let noc = MatterCert::parse(&buf).unwrap();
        assert_eq!(
            noc.verify_signature(&crypto, icac.public_key()),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn real_chain_expired_fails() {
        let crypto = backend();
        let noc = MatterCert::parse(NOC1_SUCCESS).unwrap();
        let icac = MatterCert::parse(ICAC1_SUCCESS).unwrap();
        let rcac = MatterCert::parse(RCA1_SUCCESS).unwrap();
        // not-after(0x3a4d_2580)を超過した時刻。
        assert_eq!(
            verify_chain(&crypto, &noc, Some(&icac), &rcac, 0x3a4d_2580 + 1),
            Err(Error::CertInvalid)
        );
    }
}

// 実機回帰: Alexa(Echo Pop、2026-09-27)が AddNOC で送った実チェーン(RCAC/ICAC/NOC)。
// 拡張の TLV 出現順が正準順(BC, KU, EKU, SKID, AKID)と異なる(RCAC: BC, SKID, KU, AKID /
// ICAC・NOC: BC, AKID, SKID, KU[, EKU])。DER 再構築を正準順に並べ替えると TBS が変わり
// 全署名が Crypto エラー → AddNOC が InvalidPublicKey になっていた。
mod alexa_echo_pop {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::Rng;
    struct DummyRng;
    impl Rng for DummyRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
            dest.iter_mut().for_each(|b| *b = 7);
            Ok(())
        }
    }
    const RCAC: &[u8] = include_bytes!("testdata_alexa/alexa_rcac.tlv");
    const ICAC: &[u8] = include_bytes!("testdata_alexa/alexa_icac.tlv");
    const NOC: &[u8] = include_bytes!("testdata_alexa/alexa_noc.tlv");

    #[test]
    fn alexa_chain_with_noncanonical_extension_order_verifies() {
        let crypto = RustCrypto::new(DummyRng);
        let rcac = MatterCert::parse(RCAC).unwrap();
        let icac = MatterCert::parse(ICAC).unwrap();
        let noc = MatterCert::parse(NOC).unwrap();
        rcac.verify_signature(&crypto, rcac.public_key()).unwrap();
        icac.verify_signature(&crypto, rcac.public_key()).unwrap();
        noc.verify_signature(&crypto, icac.public_key()).unwrap();
        let eff = noc
            .not_before()
            .max(icac.not_before())
            .max(rcac.not_before());
        verify_chain(&crypto, &noc, Some(&icac), &rcac, eff).unwrap();
        // ICAC は fabric-id を持たず、NOC の subject は fabric-id → node-id の順。
        assert_eq!(icac.subject().fabric_id().unwrap(), None);
        assert_eq!(
            noc.subject().node_id().unwrap(),
            Some(0x077a_4e9c_937f_9660)
        );
        assert_eq!(
            noc.subject().fabric_id().unwrap(),
            Some(0x02f4_1a62_b891_da02)
        );
    }
}
