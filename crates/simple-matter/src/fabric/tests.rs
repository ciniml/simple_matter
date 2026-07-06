//! [`crate::fabric`] のユニットテスト(`rustcrypto` backend が必要)。
//!
//! - 導出値([`compute_compressed_fabric_id`] / [`derive_operational_ipk`])は
//!   connectedhomeip の既知テストベクタと照合する
//!   (`TestGroupDataProvider` の CompressedFabricId、`TestGroupOperationalCredentials`
//!   の operational group key)。
//! - add / lookup / accessor / 各種失敗系 / index 再利用 / 署名往復は、cert のユニット
//!   テストと同じ「DER-TBS で自己整合的に署名した実 Matter 互換チェーン」(運用鍵の
//!   スカラが既知)で確認する。運用鍵の一致検査(NOC 公開鍵 == 運用鍵ペア公開鍵)を
//!   検証するには NOC の秘密鍵が必要なため、埋め込みの実 chip-cert チェーンは秘密鍵を
//!   持たず success パスには使えない。実 chip-cert チェーンは add のチェーン検証段が
//!   実バイト列を受理することの確認に用いる。

use super::*;
use crate::cert::{dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::{Crypto, P256Keypair, Rng};
use crate::tlv::{TlvTag, TlvWriter};

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

type Table<const N: usize> = FabricTable<RustCrypto<DummyRng>, N>;

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

/// cert のテストと同じ方式で、TLV 証明書を組み立て DER-TBS を親鍵で署名して返す。
#[allow(clippy::too_many_arguments)]
fn write_cert(
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
    issuer_kp: &<RustCrypto<DummyRng> as Crypto>::Keypair,
) -> usize {
    let len = {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), serial).unwrap();
        w.write_u8(&cx(2), 1).unwrap();
        write_dn(&mut w, 3, issuer);
        w.write_u32(&cx(4), not_before).unwrap();
        w.write_u32(&cx(5), not_after).unwrap();
        write_dn(&mut w, 6, subject);
        w.write_u8(&cx(7), 1).unwrap();
        w.write_u8(&cx(8), 1).unwrap();
        w.write_bytes(&cx(9), subject_pub).unwrap();
        w.start_list(&cx(10)).unwrap();
        w.start_struct(&cx(1)).unwrap();
        w.write_bool(&cx(1), is_ca).unwrap();
        if let Some(p) = path_len {
            w.write_u8(&cx(2), p).unwrap();
        }
        w.end_container().unwrap();
        w.write_u16(&cx(2), key_usage_bits).unwrap();
        if !eku.is_empty() {
            w.start_array(&cx(3)).unwrap();
            for e in eku {
                w.write_u8(&TlvTag::Anonymous, *e).unwrap();
            }
            w.end_container().unwrap();
        }
        w.write_bytes(&cx(4), skid).unwrap();
        w.write_bytes(&cx(5), akid).unwrap();
        w.end_container().unwrap();
        w.write_bytes(&cx(11), &[0u8; 64]).unwrap();
        w.end_container().unwrap();
        w.len()
    };

    let mut tbs = [0u8; MAX_TBS_DER_LEN];
    let tbs_len = {
        let cert = MatterCert::parse(&out[..len]).unwrap();
        cert.to_be_signed(&mut tbs).unwrap()
    };
    let mut sig = [0u8; 64];
    issuer_kp.sign(&tbs[..tbs_len], &mut sig).unwrap();
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
const EPOCH_KEY: [u8; 16] = [0x5a; 16];

/// 自己整合的な RCAC / ICAC / NOC チェーンと NOC 運用鍵を作る。
struct Chain {
    rcac: [u8; 400],
    rcac_len: usize,
    icac: [u8; 400],
    icac_len: usize,
    noc: [u8; 400],
    noc_len: usize,
    rcac_pub: [u8; 65],
    noc_kp: <RustCrypto<DummyRng> as Crypto>::Keypair,
}

fn build_chain(crypto: &RustCrypto<DummyRng>, node_id: u64, noc_scalar: u8) -> Chain {
    let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
    let icac_kp = crypto.p256_keypair_from_bytes(&[0x22; 32]).unwrap();
    let noc_kp = crypto.p256_keypair_from_bytes(&[noc_scalar; 32]).unwrap();
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
        rcac_pub,
        noc_kp,
    };

    c.rcac_len = write_cert(
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

    c.icac_len = write_cert(
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

    c.noc_len = write_cert(
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
                val: node_id,
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

impl Chain {
    fn rcac(&self) -> &[u8] {
        &self.rcac[..self.rcac_len]
    }
    fn icac(&self) -> &[u8] {
        &self.icac[..self.icac_len]
    }
    fn noc(&self) -> &[u8] {
        &self.noc[..self.noc_len]
    }
}

// ---------------------------------------------------------------------------
// 導出値の既知ベクタ照合(connectedhomeip)
// ---------------------------------------------------------------------------

/// spec §4.3.2.2 の例。chip `kExampleOperationalRootPublicKey` / `kFabricId1`。
const VEC_ROOT_PUBKEY: [u8; 65] = [
    0x04, 0x4a, 0x9f, 0x42, 0xb1, 0xca, 0x48, 0x40, 0xd3, 0x72, 0x92, 0xbb, 0xc7, 0xf6, 0xa7, 0xe1,
    0x1e, 0x22, 0x20, 0x0c, 0x97, 0x6f, 0xc9, 0x00, 0xdb, 0xc9, 0x8a, 0x7a, 0x38, 0x3a, 0x64, 0x1c,
    0xb8, 0x25, 0x4a, 0x2e, 0x56, 0xd4, 0xe2, 0x95, 0xa8, 0x47, 0x94, 0x3b, 0x4e, 0x38, 0x97, 0xc4,
    0xa7, 0x73, 0xe9, 0x30, 0x27, 0x7b, 0x4d, 0x9f, 0xbe, 0xde, 0x8a, 0x05, 0x26, 0x86, 0xbf, 0xac,
    0xfa,
];
const VEC_FABRIC_ID: u64 = 0x2906_C908_D115_D362;
const VEC_COMPRESSED: [u8; 8] = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];

#[test]
fn compressed_fabric_id_matches_chip_vector() {
    let crypto = backend();
    let got = compute_compressed_fabric_id(&crypto, &VEC_ROOT_PUBKEY, VEC_FABRIC_ID).unwrap();
    assert_eq!(got, VEC_COMPRESSED);
}

#[test]
fn operational_ipk_matches_chip_vectors() {
    let crypto = backend();
    // chip TestGroupOperationalCredentials: kEpochKeys0 / kGroupKeys0[].encryption_key
    let vectors: [([u8; 16], [u8; 16]); 3] = [
        (
            [0x00; 16],
            [
                0xc5, 0xf2, 0x69, 0x01, 0x87, 0x11, 0x51, 0x50, 0xc3, 0x56, 0xad, 0x93, 0xb3, 0x85,
                0xbb, 0x0f,
            ],
        ),
        (
            [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
            [
                0xae, 0xd9, 0x56, 0x95, 0xf3, 0x75, 0xd2, 0xce, 0x78, 0x55, 0x6a, 0x41, 0x73, 0x0c,
                0x3f, 0x43,
            ],
        ),
        (
            [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ],
            [
                0x35, 0xca, 0x34, 0x6e, 0x5e, 0x24, 0xbb, 0xbe, 0x88, 0x9c, 0xf4, 0xd3, 0x5c, 0x5e,
                0x82, 0x0a,
            ],
        ),
    ];
    for (epoch, expected) in vectors {
        let got = derive_operational_ipk(&crypto, &epoch, &VEC_COMPRESSED).unwrap();
        assert_eq!(got, expected);
    }
}

// ---------------------------------------------------------------------------
// add / lookup / accessors / 署名往復 / destination id
// ---------------------------------------------------------------------------

#[test]
fn add_lookup_accessors_and_sign_roundtrip() {
    use crate::sc::case::creds::{Fabric, FabricStore};

    let crypto = backend();
    let c = build_chain(&crypto, NODE_ID, 0x33);
    let noc_pub = c.noc_kp.public_key().to_bytes();

    let mut table: Table<5> = FabricTable::new();
    assert!(table.is_empty());
    let idx = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "living-room",
        )
        .expect("add should succeed");
    assert_eq!(idx.get(), 1);
    assert_eq!(table.len(), 1);
    assert_eq!(table.generation(), 1);

    // lookup by index。
    let f = table.get(idx).unwrap();
    assert_eq!(f.fabric_id(), FABRIC_ID);
    assert_eq!(f.node_id(), NODE_ID);
    assert_eq!(f.vendor_id(), 0x8000);
    assert_eq!(f.label(), "living-room");
    assert_eq!(f.root_public_key(), &c.rcac_pub);
    assert_eq!(f.noc(), c.noc());
    assert_eq!(f.icac(), Some(c.icac()));
    assert_eq!(f.rcac(), c.rcac());

    // lookup by fabric+node。
    assert!(table.find_by_fabric_and_node(FABRIC_ID, NODE_ID).is_some());
    assert!(table.find_by_fabric_and_node(FABRIC_ID, 0x999).is_none());

    // 導出値の自己整合。
    let compressed = compute_compressed_fabric_id(&crypto, &c.rcac_pub, FABRIC_ID).unwrap();
    let ipk = derive_operational_ipk(&crypto, &EPOCH_KEY, &compressed).unwrap();
    assert_eq!(f.ipk(), &ipk);
    assert_eq!(f.compressed_fabric_id(), u64::from_be_bytes(compressed));

    // FabricStore trait 経由。
    assert!(FabricStore::get(&table, idx).is_some());
    assert_eq!(FabricStore::iter(&table).count(), 1);

    // 運用鍵署名の往復(Fabric::sign → NOC 公開鍵で検証)。
    let msg = b"case sigma3 tbs";
    let mut sig = [0u8; 64];
    Fabric::sign(f, msg, &mut sig).unwrap();
    let pk = crypto.p256_public_key_from_bytes(&noc_pub).unwrap();
    assert!(pk.verify(msg, &sig).unwrap());

    // destination id の往復。
    let random = [0xAB; 32];
    let mut dest = [0u8; 32];
    f.compute_destination_id(&crypto, &random, NODE_ID, &mut dest)
        .unwrap();
    assert_eq!(table.find_by_dest_id(&crypto, &random, &dest), Some(idx));
    // 別 random では一致しない。
    let other = [0xCD; 32];
    assert_eq!(table.find_by_dest_id(&crypto, &other, &dest), None);
}

#[test]
fn add_rejects_tampered_chain() {
    let crypto = backend();
    let mut c = build_chain(&crypto, NODE_ID, 0x33);
    // NOC 署名を破壊。
    c.noc[c.noc_len - 2] ^= 0x01;
    let mut table: Table<5> = FabricTable::new();
    let err = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "",
        )
        .unwrap_err();
    assert_eq!(err, Error::Crypto);
    assert!(table.is_empty());
}

#[test]
fn add_rejects_keypair_mismatch() {
    let crypto = backend();
    let c = build_chain(&crypto, NODE_ID, 0x33);
    let mut table: Table<5> = FabricTable::new();
    // 運用鍵ペアが NOC 公開鍵と一致しない(別スカラ)。
    let err = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x77; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "",
        )
        .unwrap_err();
    assert_eq!(err, Error::Crypto);
    assert!(table.is_empty());
}

#[test]
fn add_rejects_expired_chain() {
    let crypto = backend();
    let c = build_chain(&crypto, NODE_ID, 0x33);
    let mut table: Table<5> = FabricTable::new();
    let err = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOT_AFTER + 1,
            "",
        )
        .unwrap_err();
    assert_eq!(err, Error::CertInvalid);
}

#[test]
fn add_capacity_full() {
    let crypto = backend();
    let mut table: Table<1> = FabricTable::new();
    let c0 = build_chain(&crypto, NODE_ID, 0x33);
    table
        .add(
            &crypto,
            c0.rcac(),
            Some(c0.icac()),
            c0.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "a",
        )
        .unwrap();
    // 2 本目(容量超過)。異なる node_id/鍵で作っても容量で弾かれる。
    let c1 = build_chain(&crypto, NODE_ID + 1, 0x44);
    let err = table
        .add(
            &crypto,
            c1.rcac(),
            Some(c1.icac()),
            c1.noc(),
            crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "b",
        )
        .unwrap_err();
    assert_eq!(err, Error::NoSpace);
}

#[test]
fn remove_reuses_index() {
    let crypto = backend();
    let mut table: Table<5> = FabricTable::new();
    let c0 = build_chain(&crypto, NODE_ID, 0x33);
    let c1 = build_chain(&crypto, NODE_ID + 1, 0x44);

    let i0 = table
        .add(
            &crypto,
            c0.rcac(),
            Some(c0.icac()),
            c0.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "a",
        )
        .unwrap();
    let i1 = table
        .add(
            &crypto,
            c1.rcac(),
            Some(c1.icac()),
            c1.noc(),
            crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "b",
        )
        .unwrap();
    assert_eq!(i0.get(), 1);
    assert_eq!(i1.get(), 2);

    // index 1 を削除 → 再追加で最小空き = 1 が再利用される。
    table.remove(i0).unwrap();
    assert_eq!(table.remove(i0), Err(Error::NotFound));
    assert_eq!(table.len(), 1);

    let c2 = build_chain(&crypto, NODE_ID + 2, 0x55);
    let i2 = table
        .add(
            &crypto,
            c2.rcac(),
            Some(c2.icac()),
            c2.noc(),
            crypto.p256_keypair_from_bytes(&[0x55; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "c",
        )
        .unwrap();
    assert_eq!(i2.get(), 1);
    assert_eq!(table.len(), 2);
}

#[test]
fn update_label_and_duplicate() {
    let crypto = backend();
    let mut table: Table<5> = FabricTable::new();
    let c0 = build_chain(&crypto, NODE_ID, 0x33);
    let c1 = build_chain(&crypto, NODE_ID + 1, 0x44);
    let i0 = table
        .add(
            &crypto,
            c0.rcac(),
            Some(c0.icac()),
            c0.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "one",
        )
        .unwrap();
    let i1 = table
        .add(
            &crypto,
            c1.rcac(),
            Some(c1.icac()),
            c1.noc(),
            crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "two",
        )
        .unwrap();

    table.update_label(i0, "renamed").unwrap();
    assert_eq!(table.get(i0).unwrap().label(), "renamed");

    // 他 fabric と同一ラベルは拒否。
    assert_eq!(table.update_label(i1, "renamed"), Err(Error::Duplicate));
    // 過大は NoSpace。
    let too_long = "x".repeat(MAX_FABRIC_LABEL_LEN + 1);
    assert_eq!(table.update_label(i0, &too_long), Err(Error::NoSpace));
    // 未知 index。
    let bogus = NonZeroU8::new(200).unwrap();
    assert_eq!(table.update_label(bogus, "z"), Err(Error::NotFound));
}

#[test]
fn rotate_ipk_rederives() {
    let crypto = backend();
    let mut table: Table<5> = FabricTable::new();
    let c = build_chain(&crypto, NODE_ID, 0x33);
    let idx = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "a",
        )
        .unwrap();
    let before = *table.get(idx).unwrap().ipk();

    let new_epoch = [0x99; 16];
    table.rotate_ipk(&crypto, idx, &new_epoch).unwrap();
    let after = *table.get(idx).unwrap().ipk();
    assert_ne!(before, after);

    let compressed = *table.get(idx).unwrap().compressed_fabric_id_bytes();
    let expected = derive_operational_ipk(&crypto, &new_epoch, &compressed).unwrap();
    assert_eq!(after, expected);
    assert_eq!(table.get(idx).unwrap().ipk_epoch_key(), &new_epoch);
}

#[test]
fn verify_peer_noc_returns_identity() {
    use crate::sc::case::creds::NocResolver;

    let crypto = backend();
    let mut table: Table<5> = FabricTable::new();
    // fabric 本体(node NODE_ID, 鍵 0x33)。
    let c = build_chain(&crypto, NODE_ID, 0x33);
    let idx = table
        .add(
            &crypto,
            c.rcac(),
            Some(c.icac()),
            c.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            1,
            NOW,
            "a",
        )
        .unwrap();

    // 同一 fabric の別ノードの NOC(peer)。同じ ICAC が署名する。
    let peer_node = 0xCCDD_u64;
    let peer = build_chain(&crypto, peer_node, 0x66);
    let peer_pub = peer.noc_kp.public_key().to_bytes();

    // コンテキスト経由(NocResolver trait)で検証。
    let creds = FabricCredentials::new(&table, &crypto, NOW);
    let id = creds
        .verify_peer_noc(idx, peer.noc(), Some(peer.icac()))
        .expect("peer noc should verify");
    assert_eq!(id.node_id(), peer_node);
    assert_eq!(id.fabric_id(), FABRIC_ID);
    assert_eq!(id.public_key(), &peer_pub);
    assert!(id.cats().is_empty());

    // 未知 fabric index。
    let bogus = NonZeroU8::new(9).unwrap();
    assert_eq!(
        table.verify_peer_noc(&crypto, bogus, peer.noc(), Some(peer.icac()), NOW),
        Err(Error::NotFound)
    );
}

// ---------------------------------------------------------------------------
// 永続化(save_to / load_from、fabric/persist.rs)
// ---------------------------------------------------------------------------

/// テスト用インメモリ KVS(固定スロット、ヒープ不使用)。
struct MemKvs {
    slots: [MemSlot; 8],
}

struct MemSlot {
    used: bool,
    key: [u8; 8],
    klen: usize,
    val: [u8; MAX_FABRIC_RECORD_LEN],
    vlen: usize,
}

impl MemKvs {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| MemSlot {
                used: false,
                key: [0; 8],
                klen: 0,
                val: [0; MAX_FABRIC_RECORD_LEN],
                vlen: 0,
            }),
        }
    }

    fn find(&self, key: &[u8]) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.used && &s.key[..s.klen] == key)
    }

    /// 保存済み値を直接改竄する(破損シミュレーション)。
    fn corrupt(&mut self, key: &[u8], at: usize) {
        let i = self.find(key).expect("key must exist");
        let vlen = self.slots[i].vlen;
        self.slots[i].val[at.min(vlen - 1)] ^= 0x01;
    }
}

impl crate::kvs::Kvs for MemKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
        match self.find(key) {
            Some(i) => {
                let s = &self.slots[i];
                if buf.len() < s.vlen {
                    return Err(Error::NoSpace);
                }
                buf[..s.vlen].copy_from_slice(&s.val[..s.vlen]);
                Ok(Some(s.vlen))
            }
            None => Ok(None),
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        assert!(key.len() <= 8 && value.len() <= MAX_FABRIC_RECORD_LEN);
        let i = match self.find(key) {
            Some(i) => i,
            None => self
                .slots
                .iter()
                .position(|s| !s.used)
                .ok_or(Error::NoSpace)?,
        };
        let s = &mut self.slots[i];
        s.used = true;
        s.key = [0; 8];
        s.key[..key.len()].copy_from_slice(key);
        s.klen = key.len();
        s.val[..value.len()].copy_from_slice(value);
        s.vlen = value.len();
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> Result<()> {
        if let Some(i) = self.find(key) {
            self.slots[i].used = false;
        }
        Ok(())
    }
}

/// ICAC を持たない 2 通チェーン(RCAC が直接 NOC を署名)。icac 省略パスの検証用。
fn build_chain_no_icac(crypto: &RustCrypto<DummyRng>, node_id: u64, noc_scalar: u8) -> Chain {
    let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
    let noc_kp = crypto.p256_keypair_from_bytes(&[noc_scalar; 32]).unwrap();
    let rcac_pub = rcac_kp.public_key().to_bytes();
    let noc_pub = noc_kp.public_key().to_bytes();

    let mut c = Chain {
        rcac: [0; 400],
        rcac_len: 0,
        icac: [0; 400],
        icac_len: 0,
        noc: [0; 400],
        noc_len: 0,
        rcac_pub,
        noc_kp,
    };
    let rcac_dn = [
        DnInt {
            tag: dn_attr::MATTER_RCAC_ID,
            val: RCAC_ID,
        },
        DnInt {
            tag: dn_attr::MATTER_FABRIC_ID,
            val: FABRIC_ID,
        },
    ];
    c.rcac_len = write_cert(
        &mut c.rcac,
        &[0x00],
        &rcac_dn,
        NOT_BEFORE,
        NOT_AFTER,
        &rcac_dn,
        &rcac_pub,
        true,
        None,
        key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
        &[],
        &RCAC_SKID,
        &RCAC_SKID,
        &rcac_kp,
    );
    c.noc_len = write_cert(
        &mut c.noc,
        &[0x02],
        &rcac_dn,
        NOT_BEFORE,
        NOT_AFTER,
        &[
            DnInt {
                tag: dn_attr::MATTER_NODE_ID,
                val: node_id,
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
    c
}

/// 2 fabric(ICAC あり/なし)を入れたテーブルを作る共通ヘルパ。
fn populated_table(crypto: &RustCrypto<DummyRng>) -> (Table<5>, Chain, Chain) {
    let c0 = build_chain(crypto, NODE_ID, 0x33);
    let c1 = build_chain_no_icac(crypto, NODE_ID + 1, 0x44);
    let mut table: Table<5> = FabricTable::new();
    table
        .add(
            crypto,
            c0.rcac(),
            Some(c0.icac()),
            c0.noc(),
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            NOW,
            "living-room",
        )
        .unwrap();
    table
        .add(
            crypto,
            c1.rcac(),
            None,
            c1.noc(),
            crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap(),
            &[0x77; 16],
            0x8001,
            NOW,
            "",
        )
        .unwrap();
    (table, c0, c1)
}

#[test]
fn persist_save_load_roundtrip_preserves_case_material() {
    use crate::sc::case::creds::Fabric;

    let crypto = backend();
    let (table, c0, c1) = populated_table(&crypto);
    let mut kvs = MemKvs::new();
    table.save_to(&mut kvs).unwrap();

    // 新テーブル(リブート想定、now=0 = 壁時計なし)へ復元する。
    let mut restored: Table<5> = FabricTable::new();
    let n = restored.load_from(&mut kvs, &crypto, 0).unwrap();
    assert_eq!(n, 2);
    assert_eq!(restored.len(), 2);
    // LKGT が復元される(now=0 でも証明書検証が通ったのはこのため)。
    assert_eq!(
        restored.last_known_good_epoch(),
        table.last_known_good_epoch()
    );

    // CASE 再確立に必要な素材が保存前と等価であること。
    for (orig, chain) in [(1u8, &c0), (2u8, &c1)] {
        let idx = NonZeroU8::new(orig).unwrap();
        let a = table.get(idx).unwrap();
        let b = restored.get(idx).unwrap();
        assert_eq!(a.fabric_id(), b.fabric_id());
        assert_eq!(a.node_id(), b.node_id());
        assert_eq!(a.vendor_id(), b.vendor_id());
        assert_eq!(a.label(), b.label());
        assert_eq!(a.ipk(), b.ipk());
        assert_eq!(a.ipk_epoch_key(), b.ipk_epoch_key());
        assert_eq!(a.root_public_key(), b.root_public_key());
        assert_eq!(a.compressed_fabric_id(), b.compressed_fabric_id());
        assert_eq!(a.rcac(), chain.rcac());
        assert_eq!(b.rcac(), chain.rcac());
        assert_eq!(a.noc(), b.noc());
        assert_eq!(a.icac(), b.icac());
        assert_eq!(a.operational_key_bytes(), b.operational_key_bytes());

        // 復元した運用鍵で署名でき、NOC 公開鍵で検証が通る(CASE Sigma 署名の等価性)。
        let msg = b"sigma3 after reboot";
        let mut sig = [0u8; 64];
        Fabric::sign(b, msg, &mut sig).unwrap();
        let pk = crypto
            .p256_public_key_from_bytes(&chain.noc_kp.public_key().to_bytes())
            .unwrap();
        assert!(pk.verify(msg, &sig).unwrap());
    }

    // destination identifier(CASE Sigma1 の fabric 逆引き)も等価。
    let random = [0xAB; 32];
    let mut dest = [0u8; 32];
    table
        .get(NonZeroU8::new(1).unwrap())
        .unwrap()
        .compute_destination_id(&crypto, &random, NODE_ID, &mut dest)
        .unwrap();
    assert_eq!(
        restored.find_by_dest_id(&crypto, &random, &dest),
        Some(NonZeroU8::new(1).unwrap())
    );
}

#[test]
fn persist_load_from_empty_kvs_is_first_boot() {
    let crypto = backend();
    let mut kvs = MemKvs::new();
    let mut table: Table<5> = FabricTable::new();
    assert_eq!(table.load_from(&mut kvs, &crypto, 0).unwrap(), 0);
    assert!(table.is_empty());
}

#[test]
fn persist_load_rejects_nonempty_table() {
    let crypto = backend();
    let (table, _, _) = populated_table(&crypto);
    let mut kvs = MemKvs::new();
    table.save_to(&mut kvs).unwrap();

    let (mut nonempty, _, _) = populated_table(&crypto);
    assert_eq!(
        nonempty.load_from(&mut kvs, &crypto, 0),
        Err(Error::InvalidState)
    );
}

#[test]
fn persist_load_rejects_unknown_schema_version() {
    use crate::kvs::Kvs;

    let crypto = backend();
    let (table, _, _) = populated_table(&crypto);
    let mut kvs = MemKvs::new();
    table.save_to(&mut kvs).unwrap();

    // メタを version=2 で上書きする。
    let mut meta = [0u8; 16];
    let len = {
        let mut w = TlvWriter::new(&mut meta);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_u8(&cx(0), 2).unwrap();
        w.write_u32(&cx(1), 0).unwrap();
        w.end_container().unwrap();
        w.len()
    };
    kvs.set(b"fabm", &meta[..len]).unwrap();

    let mut restored: Table<5> = FabricTable::new();
    assert_eq!(restored.load_from(&mut kvs, &crypto, 0), Err(Error::Decode));
}

#[test]
fn persist_load_rejects_tampered_record() {
    let crypto = backend();
    let (table, _, _) = populated_table(&crypto);
    let mut kvs = MemKvs::new();
    table.save_to(&mut kvs).unwrap();
    // 運用秘密鍵(cx6)のバイトを破壊 → NOC 公開鍵との一致検査で必ず落ちる。
    kvs.corrupt(b"fab0", 60);

    let mut restored: Table<5> = FabricTable::new();
    assert!(restored.load_from(&mut kvs, &crypto, 0).is_err());
}

#[test]
fn persist_save_removes_deleted_slots() {
    let crypto = backend();
    let (mut table, _, _) = populated_table(&crypto);
    let mut kvs = MemKvs::new();
    table.save_to(&mut kvs).unwrap();

    // index 1 を削除して再保存 → 復元は 1 fabric(index 2)のみ。
    table.remove(NonZeroU8::new(1).unwrap()).unwrap();
    table.save_to(&mut kvs).unwrap();

    let mut restored: Table<5> = FabricTable::new();
    assert_eq!(restored.load_from(&mut kvs, &crypto, 0).unwrap(), 1);
    assert!(restored.get(NonZeroU8::new(2).unwrap()).is_some());
    assert!(restored.get(NonZeroU8::new(1).unwrap()).is_none());
}

// ---------------------------------------------------------------------------
// 実 chip-cert チェーン(埋め込み実バイト列)を add のチェーン検証段が受理すること
// 出典: research/rs-matter/rs-matter/src/cert.rs(chip-cert 生成の NOC1/ICAC1/RCA1)
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

/// NOC1 の not-before(0x2781_2280)< この時刻 < not-after(0x3a4d_2580)。
const REAL_NOW: u32 = 800_000_000;

#[test]
fn add_runs_real_chain_verification() {
    let crypto = backend();

    // 前提: 実 chip-cert チェーンは verify_chain を通る(実 Matter 互換)。
    let noc = MatterCert::parse(NOC1_SUCCESS).unwrap();
    let icac = MatterCert::parse(ICAC1_SUCCESS).unwrap();
    let rcac = MatterCert::parse(RCA1_SUCCESS).unwrap();
    verify_chain(&crypto, &noc, Some(&icac), &rcac, REAL_NOW).unwrap();

    // add はチェーン検証を通過した後、運用鍵不一致(NOC 秘密鍵は未知)で Crypto を返す。
    // すなわち add は実バイト列のチェーン検証を実行している。
    let mut table: Table<5> = FabricTable::new();
    let err = table
        .add(
            &crypto,
            RCA1_SUCCESS,
            Some(ICAC1_SUCCESS),
            NOC1_SUCCESS,
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            REAL_NOW,
            "",
        )
        .unwrap_err();
    assert_eq!(err, Error::Crypto);

    // 期限切れ時刻ではチェーン検証段で CertInvalid(実バイト列を検証していることの確証)。
    let err = table
        .add(
            &crypto,
            RCA1_SUCCESS,
            Some(ICAC1_SUCCESS),
            NOC1_SUCCESS,
            crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
            &EPOCH_KEY,
            0x8000,
            0x3a4d_2580 + 1,
            "",
        )
        .unwrap_err();
    assert_eq!(err, Error::CertInvalid);
}
