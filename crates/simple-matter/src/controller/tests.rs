//! コントローラ CA / CSR 解析のユニットテスト。
//!
//! フルコミッショニングの縦通し(`controller_end_to_end`)は既存デバイス構築ヘルパを再利用する
//! ため `stack/tests.rs` に併設する(`docs/design/controller.md` §9.1)。本モジュールは CA の
//! 自己整合(発行した証明書が自分の検証器を通る)と `parse_csr` の往復のみを検証する。

use crate::cert::write_csr;
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use crate::fabric::FabricTable;

use super::ca::Ca;

type Result<T> = crate::error::Result<T>;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

type Crb = RustCrypto<SeqRng>;

const FABRIC_ID: u64 = 0xFAB1_2345;
const COMM_NODE: u64 = 0x0000_0000_1122_3344;
const DEVICE_NODE: u64 = 0x0000_0000_AABB_CCDD;
const VENDOR: u16 = 0xFFF1;

fn crypto() -> Crb {
    RustCrypto::new(SeqRng(0xC0DE_0000_1111_2222))
}

#[test]
fn ca_generate_is_self_consistent() {
    let crypto = crypto();
    // Ca::generate 自体が FabricTable::add(= verify_chain)を内部で行う。成功 = 自 NOC が
    // 自 RCAC のチェーン検証を通ること。
    let ca = Ca::<Crb>::generate(
        &crypto,
        &mut SeqRng(0x1111),
        FABRIC_ID,
        COMM_NODE,
        VENDOR,
        0,
    )
    .expect("Ca::generate");
    assert_eq!(ca.fabric_id(), FABRIC_ID);
    assert_eq!(ca.controller_node_id(), COMM_NODE);
    assert_eq!(ca.creds().len(), 1);
    let entry = ca.creds().iter().next().unwrap();
    assert_eq!(entry.node_id(), COMM_NODE);
    assert_eq!(entry.fabric_id(), FABRIC_ID);
    assert!(!ca.rcac().is_empty());
}

#[test]
fn issued_device_noc_verifies_against_ca_root() {
    let crypto = crypto();
    let ca = Ca::<Crb>::generate(
        &crypto,
        &mut SeqRng(0x2222),
        FABRIC_ID,
        COMM_NODE,
        VENDOR,
        0,
    )
    .expect("Ca::generate");

    // デバイス運用鍵ペア → その公開鍵に対して NOC を発行。
    let dev_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
    let dev_pub = dev_kp.public_key().to_bytes();
    let mut noc = [0u8; 512];
    let noc_len = ca
        .issue_noc(&crypto, &dev_pub, DEVICE_NODE, &mut noc)
        .expect("issue_noc");

    // デバイス側 fabric テーブルへ RCAC(信頼根)+ 発行 NOC + 運用鍵 + 同じ IPK epoch key で
    // 追加できる = チェーン検証(verify_chain)を通る。
    let mut table: FabricTable<Crb, 5> = FabricTable::new();
    let idx = table
        .add(
            &crypto,
            ca.rcac(),
            None,
            &noc[..noc_len],
            dev_kp,
            ca.ipk_epoch_key(),
            VENDOR,
            0,
            "dev",
        )
        .expect("device fabric add (chain verify)");
    let entry = table.get(idx).unwrap();
    assert_eq!(entry.node_id(), DEVICE_NODE);
    assert_eq!(entry.fabric_id(), FABRIC_ID);

    // コントローラ自身の fabric(comm NOC)とデバイス fabric は同じ root/IPK epoch key から
    // 同一の operational IPK を導出する(CASE 鍵一致の前提)。
    assert_eq!(entry.ipk(), ca.creds().iter().next().unwrap().ipk());
}

#[test]
fn issue_noc_serials_are_distinct() {
    let crypto = crypto();
    let ca = Ca::<Crb>::generate(
        &crypto,
        &mut SeqRng(0x3333),
        FABRIC_ID,
        COMM_NODE,
        VENDOR,
        0,
    )
    .unwrap();
    let kp = crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap();
    let pk = kp.public_key().to_bytes();
    let mut a = [0u8; 512];
    let mut b = [0u8; 512];
    let la = ca.issue_noc(&crypto, &pk, 1, &mut a).unwrap();
    let lb = ca.issue_noc(&crypto, &pk, 2, &mut b).unwrap();
    // 異なる node-id / serial のため 2 通は異なるバイト列になる。
    assert!(la > 0 && lb > 0);
    assert_ne!(&a[..la], &b[..lb]);
}

#[test]
fn parse_csr_round_trips_write_csr() {
    let crypto = crypto();
    let kp = crypto.p256_keypair_from_bytes(&[0x55; 32]).unwrap();
    let expected = kp.public_key().to_bytes();
    let mut csr = [0u8; 320];
    let csr_len = write_csr(&kp, &mut csr).expect("write_csr");

    let got = crate::cert::parse_csr(&crypto, &csr[..csr_len]).expect("parse_csr");
    assert_eq!(
        got, expected,
        "parse_csr recovers the CSR subject public key"
    );
}

#[test]
fn parse_csr_rejects_corrupted_signature() {
    let crypto = crypto();
    let kp = crypto.p256_keypair_from_bytes(&[0x66; 32]).unwrap();
    let mut csr = [0u8; 320];
    let csr_len = write_csr(&kp, &mut csr).unwrap();
    // 末尾(署名 BIT STRING 内)を反転 → 自己署名検証が失敗する。
    csr[csr_len - 1] ^= 0xFF;
    assert!(crate::cert::parse_csr(&crypto, &csr[..csr_len]).is_err());
}

#[test]
fn parse_csr_rejects_garbage() {
    let crypto = crypto();
    assert!(crate::cert::parse_csr(&crypto, &[]).is_err());
    assert!(crate::cert::parse_csr(&crypto, &[0x30, 0x02, 0x00, 0x00]).is_err());
}
