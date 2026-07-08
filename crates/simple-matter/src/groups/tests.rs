//! [`crate::groups`] のユニットテスト(`rustcrypto` backend が必要)。
//!
//! - 鍵導出は chip の既知テストベクタと照合する(`TestGroupOperationalCredentials.cpp`
//!   の epoch key → encryption key / hash(GKH)、仕様 §4.15.3 の IPK ベクタ)。
//! - マルチキャストアドレスは chip `PeerAddress::Multicast` の式との一致を固定する。
//! - GroupStore は CRUD / per-fabric 上限 / 復号候補解決 / 永続化往復 / fabric 連動を
//!   確認する。

use super::*;
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::Rng;

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

fn fx(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap()
}

/// 仕様 §4.3.2.2 の Compressed Fabric Identifier 例(chip テストベクタ共通)。
const CFID: [u8; COMPRESSED_FABRIC_ID_LEN] = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];

/// 仕様 §4.15.3 の IPK ベクタ: epoch → operational key。
#[test]
fn operational_key_matches_spec_ipk_vector() {
    let epoch = [
        0x23, 0x5b, 0xf7, 0xe6, 0x28, 0x23, 0xd3, 0x58, 0xdc, 0xa4, 0xba, 0x50, 0xb1, 0x53, 0x5f,
        0x4b,
    ];
    let expected = [
        0xa6, 0xf5, 0x30, 0x6b, 0xaf, 0x6d, 0x05, 0x0a, 0xf2, 0x3b, 0xa4, 0xbd, 0x6b, 0x9d, 0xd9,
        0x60,
    ];
    let op = derive_operational_group_key(&backend(), &epoch, &CFID).unwrap();
    assert_eq!(op, expected);
}

/// chip `TestGroupOperationalCredentials.cpp` の 3 ベクタ: epoch → (encryption key, GKH)。
#[test]
fn operational_key_and_gkh_match_chip_vectors() {
    // (epoch key, encryption key, hash)
    let vectors: [([u8; 16], [u8; 16], u16); 3] = [
        (
            [0u8; 16],
            [
                0xc5, 0xf2, 0x69, 0x01, 0x87, 0x11, 0x51, 0x50, 0xc3, 0x56, 0xad, 0x93, 0xb3, 0x85,
                0xbb, 0x0f,
            ],
            0x479e,
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
            0xa512,
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
            0xd800,
        ),
    ];
    let crypto = backend();
    for (epoch, enc, hash) in vectors {
        let op = derive_operational_group_key(&crypto, &epoch, &CFID).unwrap();
        assert_eq!(op, enc);
        assert_eq!(derive_group_session_id(&crypto, &op).unwrap(), hash);
    }
}

/// chip `PeerAddress::Multicast` の式(prefix/group32 分解)との一致。
#[test]
fn multicast_addr_matches_chip_formula() {
    for (fabric, gid) in [
        (0x0000_0000_0021_dfe0u64, 0x4141u16),
        (0x1122_3344_5566_7788, 0x0101),
        (u64::MAX, 0xffff),
        (1, 1),
    ] {
        let addr = group_multicast_addr(fabric, gid);
        let o = addr.octets();
        // chip: prefix(64bit) = 0xfd00... | (fabric >> 8)、group32 = ((fabric << 24) & 0xff000000) | gid
        let prefix: u64 = 0xfd00_0000_0000_0000 | (fabric >> 8);
        let group32: u32 = (((fabric as u32) << 24) & 0xff00_0000) | gid as u32;
        assert_eq!(&o[..4], &[0xff, 0x35, 0x00, 0x40]);
        assert_eq!(u64::from_be_bytes(o[4..12].try_into().unwrap()), prefix);
        assert_eq!(u32::from_be_bytes(o[12..16].try_into().unwrap()), group32);
    }
}

fn ep(key_byte: u8, t: u64) -> EpochKeyInput {
    EpochKeyInput {
        key: [key_byte; GROUP_KEY_LEN],
        start_time_us: t,
    }
}

#[test]
fn keyset_crud_and_limits() {
    let crypto = backend();
    let mut s = DefaultGroupStore::new();
    let g0 = s.generation();

    // keyset 0(IPK)は格納不可。
    assert_eq!(
        s.set_keyset(fx(1), 0, 0, &[ep(1, 1)], &crypto, &CFID),
        Err(Error::InvalidState)
    );
    // epoch 0 本 / 4 本は不正。
    assert_eq!(
        s.set_keyset(fx(1), 1, 0, &[], &crypto, &CFID),
        Err(Error::Decode)
    );
    assert_eq!(
        s.set_keyset(
            fx(1),
            1,
            0,
            &[ep(1, 1), ep(2, 2), ep(3, 3), ep(4, 4)],
            &crypto,
            &CFID
        ),
        Err(Error::Decode)
    );

    s.set_keyset(fx(1), 42, 0, &[ep(1, 1), ep(2, 2)], &crypto, &CFID)
        .unwrap();
    assert!(s.generation() != g0);
    let k = s.keyset(fx(1), 42).unwrap();
    assert_eq!(k.id(), 42);
    assert_eq!(k.epochs().len(), 2);
    // 導出済み鍵は epoch key と異なる。
    assert_ne!(k.epochs()[0].op_key(), &[1u8; 16]);

    // 上書き更新は本数を消費しない。
    s.set_keyset(fx(1), 42, 0, &[ep(9, 9)], &crypto, &CFID)
        .unwrap();
    assert_eq!(s.keyset(fx(1), 42).unwrap().epochs().len(), 1);
    assert_eq!(s.keyset_len(fx(1)), 1);

    // per-fabric 上限 3。
    s.set_keyset(fx(1), 43, 0, &[ep(2, 1)], &crypto, &CFID)
        .unwrap();
    s.set_keyset(fx(1), 44, 0, &[ep(3, 1)], &crypto, &CFID)
        .unwrap();
    assert_eq!(
        s.set_keyset(fx(1), 45, 0, &[ep(4, 1)], &crypto, &CFID),
        Err(Error::NoSpace)
    );
    // 別 fabric は独立。
    s.set_keyset(fx(2), 45, 0, &[ep(4, 1)], &crypto, &CFID)
        .unwrap();

    // ReadAllIndices 用の列挙。
    assert_eq!(s.keyset_id_at(fx(1), 0), Some(42));
    assert_eq!(s.keyset_id_at(fx(1), 1), Some(43));
    assert_eq!(s.keyset_id_at(fx(1), 2), Some(44));
    assert_eq!(s.keyset_id_at(fx(1), 3), None);

    // 削除で map も連動して消える。
    s.add_map(fx(1), 0x0101, 42).unwrap();
    s.add_map(fx(1), 0x0102, 43).unwrap();
    s.remove_keyset(fx(1), 42).unwrap();
    assert!(s.keyset(fx(1), 42).is_none());
    assert_eq!(s.map_len(fx(1)), 1);
    assert_eq!(s.remove_keyset(fx(1), 42), Err(Error::NotFound));
}

#[test]
fn map_replace_append_and_limits() {
    let crypto = backend();
    let mut s = DefaultGroupStore::new();
    s.set_keyset(fx(1), 42, 0, &[ep(1, 1)], &crypto, &CFID)
        .unwrap();

    s.set_map(fx(1), &[(0x0101, 42), (0x0102, 42)]).unwrap();
    assert_eq!(s.map_len(fx(1)), 2);
    // ReplaceAll は上書き。
    s.set_map(fx(1), &[(0x0103, 42)]).unwrap();
    assert_eq!(s.map_len(fx(1)), 1);
    assert_eq!(s.map_iter(fx(1)).next().unwrap().group_id(), 0x0103);

    // Append: 同一 group は上書き、上限 4。
    s.add_map(fx(1), 0x0103, 43).unwrap();
    assert_eq!(s.map_len(fx(1)), 1);
    assert_eq!(s.map_iter(fx(1)).next().unwrap().key_set_id(), 43);
    s.add_map(fx(1), 0x0104, 42).unwrap();
    s.add_map(fx(1), 0x0105, 42).unwrap();
    s.add_map(fx(1), 0x0106, 42).unwrap();
    assert_eq!(s.add_map(fx(1), 0x0107, 42), Err(Error::NoSpace));
    assert_eq!(
        s.set_map(fx(1), &[(1, 1), (2, 1), (3, 1), (4, 1), (5, 1)]),
        Err(Error::NoSpace)
    );

    // has_key_for_group: map + keyset が揃って true。
    assert!(s.has_key_for_group(fx(1), 0x0104));
    assert!(!s.has_key_for_group(fx(1), 0x0103), "keyset 43 は未登録");
    assert!(!s.has_key_for_group(fx(2), 0x0104), "fabric 不一致");
}

#[test]
fn membership_crud() {
    let mut s = DefaultGroupStore::new();
    assert!(s.member_endpoints(fx(1), 7).is_none());

    s.add_member(fx(1), 7, 1).unwrap();
    s.add_member(fx(1), 7, 2).unwrap();
    s.add_member(fx(1), 7, 2).unwrap(); // 冪等
    assert_eq!(s.member_endpoints(fx(1), 7).unwrap(), &[1, 2]);
    assert!(s.is_member(fx(1), 7, 1));
    assert!(!s.is_member(fx(1), 8, 1));

    // per-fabric group 行上限 4。
    s.add_member(fx(1), 8, 1).unwrap();
    s.add_member(fx(1), 9, 1).unwrap();
    s.add_member(fx(1), 10, 1).unwrap();
    assert_eq!(s.add_member(fx(1), 11, 1), Err(Error::NoSpace));

    // エンドポイント上限 4。
    s.add_member(fx(1), 7, 3).unwrap();
    s.add_member(fx(1), 7, 4).unwrap();
    assert_eq!(s.add_member(fx(1), 7, 5), Err(Error::NoSpace));

    // remove_member: 空になった行は消える。
    assert!(s.remove_member(fx(1), 8, 1));
    assert!(!s.remove_member(fx(1), 8, 1));
    assert!(s.member_endpoints(fx(1), 8).is_none());

    // remove_all_members: fabric の全行から外す。
    s.remove_all_members(fx(1), 1);
    assert_eq!(s.member_endpoints(fx(1), 7).unwrap(), &[2, 3, 4]);
    assert!(s.member_endpoints(fx(1), 9).is_none());
    assert!(s.member_endpoints(fx(1), 10).is_none());
}

#[test]
fn key_candidate_resolution() {
    let crypto = backend();
    let mut s = DefaultGroupStore::new();
    s.set_keyset(fx(1), 42, 0, &[ep(1, 1), ep(2, 2)], &crypto, &CFID)
        .unwrap();
    s.set_keyset(fx(2), 7, 0, &[ep(1, 1)], &crypto, &CFID)
        .unwrap();
    let gkh0 = s.keyset(fx(1), 42).unwrap().epochs()[0].gkh();
    let gkh1 = s.keyset(fx(1), 42).unwrap().epochs()[1].gkh();
    let op0 = *s.keyset(fx(1), 42).unwrap().epochs()[0].op_key();

    // map 未登録 group は候補なし。
    assert!(s.key_candidate(gkh0, 0x0101, 0).is_none());

    s.add_map(fx(1), 0x0101, 42).unwrap();
    s.add_map(fx(2), 0x0101, 7).unwrap();

    // fabric1 の epoch0(同一 epoch key + 同一 CFID のため fabric2 も同じ GKH を持つ)。
    let (f, k) = s.key_candidate(gkh0, 0x0101, 0).unwrap();
    assert_eq!(f, fx(1));
    assert_eq!(k, op0);
    // 2 候補目は fabric2 側(同一鍵素材なので gkh 一致)。
    let (f2, _) = s.key_candidate(gkh0, 0x0101, 1).unwrap();
    assert_eq!(f2, fx(2));
    assert!(s.key_candidate(gkh0, 0x0101, 2).is_none());

    // epoch1 は fabric1 のみ。
    let (f, _) = s.key_candidate(gkh1, 0x0101, 0).unwrap();
    assert_eq!(f, fx(1));
    assert!(s.key_candidate(gkh1, 0x0101, 1).is_none());

    // GroupKeyResolver 経由(RefCell)でも同じ。
    let cell = RefCell::new(s);
    let (f, k) = GroupKeyResolver::key_candidate(&cell, gkh0, 0x0101, 0).unwrap();
    assert_eq!(f, fx(1));
    assert_eq!(k, op0);
}

#[test]
fn fabric_cleanup() {
    let crypto = backend();
    let mut s = DefaultGroupStore::new();
    s.set_keyset(fx(1), 42, 0, &[ep(1, 1)], &crypto, &CFID)
        .unwrap();
    s.set_keyset(fx(2), 42, 0, &[ep(1, 1)], &crypto, &CFID)
        .unwrap();
    s.add_map(fx(1), 1, 42).unwrap();
    s.add_map(fx(2), 1, 42).unwrap();
    s.add_member(fx(1), 1, 1).unwrap();
    s.add_member(fx(2), 1, 1).unwrap();

    s.clear_fabric(fx(1));
    assert!(s.keyset(fx(1), 42).is_none());
    assert_eq!(s.map_len(fx(1)), 0);
    assert!(s.member_endpoints(fx(1), 1).is_none());
    assert!(s.keyset(fx(2), 42).is_some());

    s.retain_fabrics(|f| f.get() != 2);
    assert!(s.keyset(fx(2), 42).is_none());
    assert_eq!(s.map_len(fx(2)), 0);
    assert!(s.member_endpoints(fx(2), 1).is_none());
}

/// テスト用インメモリ KVS(単一キー `grpt` のみ扱う)。
struct MemKvs {
    used: bool,
    key: [u8; 8],
    klen: usize,
    val: [u8; MAX_GROUP_RECORD_LEN],
    vlen: usize,
}

impl MemKvs {
    fn new() -> Self {
        Self {
            used: false,
            key: [0; 8],
            klen: 0,
            val: [0; MAX_GROUP_RECORD_LEN],
            vlen: 0,
        }
    }
    fn matches(&self, key: &[u8]) -> bool {
        self.used && &self.key[..self.klen] == key
    }
}

impl Kvs for MemKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
        if !self.matches(key) {
            return Ok(None);
        }
        if buf.len() < self.vlen {
            return Err(Error::NoSpace);
        }
        buf[..self.vlen].copy_from_slice(&self.val[..self.vlen]);
        Ok(Some(self.vlen))
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        assert!(key.len() <= 8 && value.len() <= MAX_GROUP_RECORD_LEN);
        self.used = true;
        self.klen = key.len();
        self.key[..key.len()].copy_from_slice(key);
        self.vlen = value.len();
        self.val[..value.len()].copy_from_slice(value);
        Ok(())
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        if self.matches(key) {
            self.used = false;
        }
        Ok(())
    }
}

#[test]
fn persist_round_trip() {
    let crypto = backend();
    let mut s = DefaultGroupStore::new();
    s.set_keyset(fx(1), 42, 0, &[ep(1, 100), ep(2, 200)], &crypto, &CFID)
        .unwrap();
    s.set_keyset(fx(2), 7, 0, &[ep(3, 300)], &crypto, &CFID)
        .unwrap();
    s.add_map(fx(1), 0x0101, 42).unwrap();
    s.add_map(fx(2), 0x0202, 7).unwrap();
    s.add_member(fx(1), 0x0101, 1).unwrap();
    s.add_member(fx(1), 0x0101, 2).unwrap();

    let mut kvs = MemKvs::new();
    s.save_to(&mut kvs).unwrap();

    let mut restored = DefaultGroupStore::new();
    restored.load_from(&mut kvs).unwrap();

    // keyset(導出値込み)。
    let orig = s.keyset(fx(1), 42).unwrap();
    let rest = restored.keyset(fx(1), 42).unwrap();
    assert_eq!(orig.epochs().len(), rest.epochs().len());
    for (a, b) in orig.epochs().iter().zip(rest.epochs().iter()) {
        assert_eq!(a.op_key(), b.op_key());
        assert_eq!(a.gkh(), b.gkh());
        assert_eq!(a.start_time_us(), b.start_time_us());
    }
    // map / membership。
    assert_eq!(restored.map_len(fx(1)), 1);
    assert_eq!(restored.map_len(fx(2)), 1);
    assert_eq!(restored.member_endpoints(fx(1), 0x0101).unwrap(), &[1, 2]);
    // 復元後も key_candidate が引ける。
    let gkh = orig.epochs()[0].gkh();
    assert!(restored.key_candidate(gkh, 0x0101, 0).is_some());

    // 非空ストアへの load は InvalidState。
    assert_eq!(restored.load_from(&mut kvs), Err(Error::InvalidState));

    // レコード無しは初回起動として成功。
    let mut empty_kvs = MemKvs::new();
    let mut fresh = DefaultGroupStore::new();
    fresh.load_from(&mut empty_kvs).unwrap();
    assert_eq!(fresh.keyset_len(fx(1)), 0);
}

#[test]
fn group_node_id_helper() {
    assert_eq!(group_node_id(0x0101), 0xFFFF_FFFF_FFFF_0101);
    assert_eq!(group_node_id(0), 0xFFFF_FFFF_FFFF_0000);
}
