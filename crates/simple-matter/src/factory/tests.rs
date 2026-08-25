//! `esp-matter-mfg-tool` 実生成の factory NVS バイナリをフィクスチャに用いた単体テスト。
//!
//! フィクスチャ `tests/fixtures/factory-fff1-8001.bin` は次のコマンド相当で生成した
//! 実パーティション(VID=0xFFF1 / PID=0x8001 / passcode=20202021 / discriminator=3840 /
//! iteration-count=10000、PAA 自己署名の DAC/PAI チェーン付き):
//!
//! ```text
//! esp-matter-mfg-tool -v 0xFFF1 -p 0x8001 --passcode 20202021 --discriminator 3840 \
//!   --hw-ver 1 --hw-ver-str HW1 --serial-num SM-ONOFF-0001 --paa -c paa.pem -k paa_key.pem
//! ```

use super::*;

/// mfg-tool 実生成の factory パーティション(平文 NVS、24 KiB)。
const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/factory-fff1-8001.bin");

fn fd() -> FactoryData<'static> {
    FactoryData::parse(FIXTURE).expect("chip-factory namespace present")
}

#[test]
fn parses_commissionable_data() {
    let fd = fd();
    assert_eq!(fd.discriminator().unwrap(), 3840);
    assert_eq!(fd.iteration_count().unwrap(), 10000);
    assert_eq!(fd.vendor_id().unwrap(), 0xFFF1);
    assert_eq!(fd.product_id().unwrap(), 0x8001);
}

#[test]
fn salt_base64_decodes_to_32_bytes() {
    let fd = fd();
    let mut salt = [0u8; 32];
    let n = fd.salt(&mut salt).unwrap();
    assert_eq!(n, 32);
    assert_eq!(
        salt,
        [
            0xbb, 0x67, 0xb0, 0x5a, 0xa5, 0x30, 0x23, 0x46, 0x11, 0xb4, 0xe4, 0x44, 0x71, 0x6d,
            0x38, 0x6b, 0x20, 0x98, 0x78, 0x73, 0xa6, 0x4a, 0x5a, 0xdf, 0x7f, 0x44, 0x6b, 0x23,
            0xc6, 0xfe, 0xde, 0x80,
        ]
    );
}

#[test]
fn verifier_base64_decodes_to_97_bytes() {
    let fd = fd();
    let mut w0l = [0u8; 97];
    fd.verifier(&mut w0l).unwrap();
    // w0 の先頭 32 バイト。
    assert_eq!(
        &w0l[..32],
        &[
            0x87, 0x3c, 0x6f, 0x3e, 0xc7, 0xd9, 0x32, 0x37, 0x14, 0xbd, 0xd0, 0x8d, 0x55, 0x98,
            0xf5, 0xca, 0x36, 0x14, 0xcc, 0x66, 0x98, 0x9e, 0x9c, 0xaa, 0x77, 0xaa, 0xd3, 0x2c,
            0xeb, 0x26, 0x15, 0xb4,
        ]
    );
    // L は SEC1 非圧縮点(0x04 始まり)。
    assert_eq!(w0l[32], 0x04);
}

#[test]
fn dac_pai_certs_are_der() {
    let fd = fd();
    let dac = fd.dac_cert().unwrap();
    assert_eq!(dac.len(), 518);
    assert_eq!(&dac[..4], &[0x30, 0x82, 0x02, 0x02]); // SEQUENCE, len 0x0202
    let pai = fd.pai_cert().unwrap();
    assert_eq!(pai.len(), 466);
    assert_eq!(&pai[..2], &[0x30, 0x82]);
}

#[test]
fn dac_private_key_is_32_raw_bytes() {
    let fd = fd();
    let key = fd.dac_key().unwrap();
    assert_eq!(
        key,
        [
            0xe7, 0xce, 0x7a, 0xbb, 0xcd, 0x3e, 0x8c, 0x9a, 0x22, 0xde, 0x1b, 0x85, 0x9e, 0x1e,
            0x8d, 0x88, 0x99, 0xb6, 0xd8, 0x9e, 0x1f, 0x30, 0x60, 0x4e, 0x0d, 0xe3, 0xb0, 0x80,
            0xba, 0x2d, 0x96, 0x1b,
        ]
    );
}

#[test]
fn factory_has_no_cert_declaration() {
    // mfg-tool を -cd 無しで実行したため CD は factory に含まれない(呼び出し側供給)。
    assert!(fd().cert_declaration().is_none());
}

// --- Web Configurator(web/configurator)が生成した factory NVS ---

/// `node web/configurator/tools/gen-test-fixture.js` が生成した factory パーティション。
///
/// ブラウザ側 JS(`web/configurator/js/nvs.js`)の NVS ライタが mfg-tool 互換であり、
/// 本パーサでそのまま読めることを確認する(docs/design/generic-firmware.md §9.5)。
/// 個体情報は固定値: discriminator=2748 / passcode=43708557 / iteration-count=10000 /
/// salt 32 B / DAC は同梱の開発用テスト鍵(fixture `factory-fff1-8001.bin` と同じもの)。
const WEBCFG: &[u8] = include_bytes!("../../tests/fixtures/factory-webconfig.bin");

fn webcfg() -> FactoryData<'static> {
    FactoryData::parse(WEBCFG).expect("web configurator NVS has the chip-factory namespace")
}

#[test]
fn web_configurator_nvs_parses() {
    let fd = webcfg();
    assert_eq!(fd.discriminator().unwrap(), 2748);
    assert_eq!(fd.iteration_count().unwrap(), 10000);
    assert_eq!(fd.vendor_id().unwrap(), 0xFFF1);
    assert_eq!(fd.product_id().unwrap(), 0x8001);

    let mut salt = [0u8; 32];
    assert_eq!(fd.salt(&mut salt).unwrap(), 32);
    assert_eq!(
        salt,
        [
            0x55, 0xa3, 0xcb, 0x8b, 0x1e, 0xd2, 0xb5, 0xb1, 0xc0, 0xfd, 0xa2, 0xb9, 0xd9, 0xa3,
            0xd0, 0xe2, 0xf1, 0xc4, 0xb7, 0xa6, 0x8d, 0x5e, 0x3f, 0x20, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88,
        ]
    );

    let mut w0l = [0u8; 97];
    fd.verifier(&mut w0l).unwrap();
    assert_eq!(w0l[32], 0x04, "L は SEC1 非圧縮点");

    // DAC 一式(同梱の開発用テスト鍵)も blob として読める。
    assert_eq!(fd.dac_cert().unwrap().len(), 518);
    assert_eq!(fd.pai_cert().unwrap().len(), 466);
    assert_eq!(fd.dac_key().unwrap().len(), 32);
}

// --- rustcrypto backend が要るテスト ---

#[cfg(feature = "rustcrypto")]
mod with_crypto {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::spake2p::compute_verifier;
    use crate::crypto::{P256PublicKey, Rng};
    use crate::dm::clusters::DacProvider;

    /// テスト用の決定的でない RNG は不要(鍵復元・署名は RFC6979 で決定的)。
    struct ZeroRng;
    impl Rng for ZeroRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
            dest.fill(0);
            Ok(())
        }
    }

    /// stored verifier が passcode 20202021 + factory salt/iter から導出した値と一致する
    /// (= コミッショナの passcode 導出とデバイスの factory verifier が整合)。
    #[test]
    fn stored_verifier_matches_passcode_derivation() {
        let fd = fd();
        let mut salt = [0u8; 32];
        let n = fd.salt(&mut salt).unwrap();
        let iters = fd.iteration_count().unwrap();
        let derived = compute_verifier(20202021, &salt[..n], iters).unwrap();
        let mut w0l = [0u8; 97];
        fd.verifier(&mut w0l).unwrap();
        assert_eq!(&derived.w0, &w0l[..32], "w0 mismatch");
        assert_eq!(&derived.l, &w0l[32..], "L mismatch");
    }

    /// Web Configurator(ブラウザ JS)が計算した verifier が、コアの
    /// [`compute_verifier`] と**同一**であること(JS の SPAKE2+ 実装の検算)。
    #[test]
    fn web_configurator_verifier_matches_passcode_derivation() {
        let fd = webcfg();
        let mut salt = [0u8; 32];
        let n = fd.salt(&mut salt).unwrap();
        let derived =
            compute_verifier(43708557, &salt[..n], fd.iteration_count().unwrap()).unwrap();
        let mut w0l = [0u8; 97];
        fd.verifier(&mut w0l).unwrap();
        assert_eq!(&derived.w0, &w0l[..32], "w0 mismatch");
        assert_eq!(&derived.l, &w0l[32..], "L mismatch");
    }

    /// Web Configurator 生成 NVS から PaseConfig と DacProvider が構築できる
    /// (= 実機の `sm_config_t` へそのまま供給できる形になっている)。
    #[test]
    fn web_configurator_builds_pase_and_dac() {
        let fd = webcfg();
        let _cfg = fd.pase_config().expect("pase config");
        let crypto = RustCrypto::new(ZeroRng);
        let provider = fd.dac_provider(&crypto, &[]).expect("dac provider");
        assert_eq!(provider.dac_der().len(), 518);

        let msg = b"attestation-tbs-example";
        let mut sig = [0u8; 64];
        provider.sign_with_dac(msg, &mut sig).unwrap();
        use crate::crypto::Crypto;
        let pub_raw = fd.nvs.get_blob(NS, "dac-pub-key").expect("dac-pub-key");
        let pubkey = crypto.p256_public_key_from_bytes(pub_raw).expect("pubkey");
        assert!(pubkey.verify(msg, &sig).unwrap(), "signature verifies");
    }

    /// factory の verifier / salt / iter から PaseConfig が構築できる。
    #[test]
    fn builds_pase_config() {
        let _cfg = fd().pase_config().expect("pase config");
    }

    /// BorrowedDacProvider(factory 由来 DAC 鍵)の署名を、factory の dac-pub-key で検証できる。
    #[test]
    fn dac_provider_signs_verifiably() {
        let fd = fd();
        let crypto = RustCrypto::new(ZeroRng);
        // CD は factory に無いので空スライスをダミー供給(署名検証には無関係)。
        let provider = fd.dac_provider(&crypto, &[]).expect("dac provider");
        assert_eq!(provider.dac_der().len(), 518);

        let msg = b"attestation-tbs-example";
        let mut sig = [0u8; 64];
        provider.sign_with_dac(msg, &mut sig).unwrap();

        // factory の dac-pub-key(SEC1 非圧縮 65B)を取り出して検証。
        use crate::crypto::Crypto;
        let pub_raw = fd.nvs.get_blob(NS, "dac-pub-key").expect("dac-pub-key");
        assert_eq!(pub_raw.len(), 65);
        let pubkey = crypto.p256_public_key_from_bytes(pub_raw).expect("pubkey");
        assert!(pubkey.verify(msg, &sig).unwrap(), "signature verifies");
    }
}
