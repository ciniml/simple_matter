//! ACL データモデル / 権限評価 / 永続化のユニットテスト(`docs/design/acl.md` §8)。

use core::num::NonZeroU8;

use super::*;
use crate::dm::meta::{AccessContext, ClusterId, EndpointId, Privilege, SessionKind};
use crate::error::Error;
use crate::kvs::Kvs;

fn f(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap()
}

fn case_acc(fabric: u8, subject: u64) -> AccessContext {
    AccessContext::new(
        SessionKind::Case,
        NonZeroU8::new(fabric),
        subject,
        Privilege::View,
    )
}

fn pase_acc() -> AccessContext {
    AccessContext::new(SessionKind::Pase, None, 0, Privilege::View)
}

const EP1: EndpointId = EndpointId(1);
const ONOFF: ClusterId = ClusterId(0x0006);

// ---------------------------------------------------------------------------
// エントリ検証
// ---------------------------------------------------------------------------

#[test]
fn entry_validation_rules() {
    // PASE authMode のエントリは不可(implicit 専用)。
    let e = AclEntry::new(f(1), Privilege::View, AuthMode::Pase);
    assert!(!e.is_valid());

    // Group への Administer 付与は不可。
    let e = AclEntry::new(f(1), Privilege::Administer, AuthMode::Group);
    assert!(!e.is_valid());

    // CASE + Administer は可。
    let e = AclEntry::new(f(1), Privilege::Administer, AuthMode::Case);
    assert!(e.is_valid());

    // target: 全フィールド null は不可。
    assert!(!AclTarget::default().is_valid());
    // endpoint と device_type の同時指定は不可。
    let t = AclTarget {
        cluster: None,
        endpoint: Some(1),
        device_type: Some(0x0100),
    };
    assert!(!t.is_valid());
    let mut e = AclEntry::new(f(1), Privilege::View, AuthMode::Case);
    assert_eq!(e.add_target(t), Err(Error::Decode));
    // cluster のみは可。
    assert!(e
        .add_target(AclTarget {
            cluster: Some(6),
            endpoint: None,
            device_type: None,
        })
        .is_ok());
}

#[test]
fn subject_and_target_capacity() {
    let mut e = AclEntry::new(f(1), Privilege::View, AuthMode::Case);
    for i in 0..MAX_ACL_SUBJECTS {
        e.add_subject(i as u64 + 1).unwrap();
    }
    assert_eq!(e.add_subject(99), Err(Error::NoSpace));
    for i in 0..MAX_ACL_TARGETS {
        e.add_target(AclTarget {
            cluster: Some(i as u32 + 1),
            endpoint: None,
            device_type: None,
        })
        .unwrap();
    }
    assert_eq!(
        e.add_target(AclTarget {
            cluster: Some(99),
            endpoint: None,
            device_type: None,
        }),
        Err(Error::NoSpace)
    );
}

// ---------------------------------------------------------------------------
// テーブル容量 / fabric 分離
// ---------------------------------------------------------------------------

#[test]
fn per_fabric_capacity_enforced() {
    let mut t: AclTable<16> = AclTable::new();
    for _ in 0..ACL_ENTRIES_PER_FABRIC {
        t.add(AclEntry::new(f(1), Privilege::View, AuthMode::Case))
            .unwrap();
    }
    // fabric 1 は満杯、fabric 2 はまだ入る。
    assert_eq!(
        t.add(AclEntry::new(f(1), Privilege::View, AuthMode::Case)),
        Err(Error::NoSpace)
    );
    t.add(AclEntry::new(f(2), Privilege::View, AuthMode::Case))
        .unwrap();
    assert_eq!(t.fabric_len(f(1)), ACL_ENTRIES_PER_FABRIC);
    assert_eq!(t.fabric_len(f(2)), 1);
}

#[test]
fn table_capacity_enforced() {
    let mut t: AclTable<2> = AclTable::new();
    t.add(AclEntry::new(f(1), Privilege::View, AuthMode::Case))
        .unwrap();
    t.add(AclEntry::new(f(2), Privilege::View, AuthMode::Case))
        .unwrap();
    assert_eq!(
        t.add(AclEntry::new(f(3), Privilege::View, AuthMode::Case)),
        Err(Error::NoSpace)
    );
}

#[test]
fn clear_fabric_keeps_other_fabrics_and_order() {
    let mut t: AclTable<8> = AclTable::new();
    t.add(AclEntry::case_admin(f(1), 0x1111)).unwrap();
    t.add(AclEntry::case_admin(f(2), 0x2222)).unwrap();
    t.add(AclEntry::case_admin(f(1), 0x3333)).unwrap();
    t.add(AclEntry::case_admin(f(2), 0x4444)).unwrap();
    let gen = t.generation();
    assert_eq!(t.clear_fabric(f(1)), 2);
    assert!(t.generation() != gen);
    // fabric 2 の 2 件が挿入順のまま残る。
    assert_eq!(t.len(), 2);
    let mut it = t.iter();
    assert_eq!(it.next().unwrap().subjects(), &[0x2222]);
    assert_eq!(it.next().unwrap().subjects(), &[0x4444]);
}

// ---------------------------------------------------------------------------
// check(権限評価)
// ---------------------------------------------------------------------------

#[test]
fn pase_is_implicit_administer() {
    let t: AclTable<4> = AclTable::new();
    // エントリゼロでも PASE は全 target に Administer。
    assert!(t.check(&pase_acc(), EP1, ONOFF, Privilege::Administer));
}

#[test]
fn case_requires_matching_entry() {
    let mut t: AclTable<8> = AclTable::new();
    // エントリ無し → 拒否。
    assert!(!t.check(&case_acc(1, 0x0011_2233), EP1, ONOFF, Privilege::Operate));

    t.add(AclEntry::case_admin(f(1), 0x0011_2233)).unwrap();
    // subject 一致 → Administer まで許可。
    assert!(t.check(&case_acc(1, 0x0011_2233), EP1, ONOFF, Privilege::Administer));
    // subject 不一致 → 拒否。
    assert!(!t.check(&case_acc(1, 0xDEAD), EP1, ONOFF, Privilege::View));
    // 他 fabric の subject → 拒否(fabric 分離)。
    assert!(!t.check(&case_acc(2, 0x0011_2233), EP1, ONOFF, Privilege::View));
    // fabric 無し(PASE 未昇格の CASE はあり得ないが防御)→ 拒否。
    assert!(!t.check(&case_acc(0, 0x0011_2233), EP1, ONOFF, Privilege::View));
}

#[test]
fn privilege_hierarchy() {
    let mut t: AclTable<8> = AclTable::new();
    let mut e = AclEntry::new(f(1), Privilege::Operate, AuthMode::Case);
    e.add_subject(0xAA).unwrap();
    t.add(e).unwrap();
    let acc = case_acc(1, 0xAA);
    // Operate 付与 → View / Operate は可、Manage / Administer は不可。
    assert!(t.check(&acc, EP1, ONOFF, Privilege::View));
    assert!(t.check(&acc, EP1, ONOFF, Privilege::Operate));
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Manage));
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Administer));
}

#[test]
fn empty_subjects_matches_all_case_subjects() {
    let mut t: AclTable<8> = AclTable::new();
    t.add(AclEntry::new(f(1), Privilege::View, AuthMode::Case))
        .unwrap();
    assert!(t.check(&case_acc(1, 0x1), EP1, ONOFF, Privilege::View));
    assert!(t.check(&case_acc(1, 0x2), EP1, ONOFF, Privilege::View));
    assert!(!t.check(&case_acc(1, 0x1), EP1, ONOFF, Privilege::Operate));
}

#[test]
fn target_filtering() {
    let mut t: AclTable<8> = AclTable::new();
    let mut e = AclEntry::new(f(1), Privilege::Operate, AuthMode::Case);
    e.add_target(AclTarget {
        cluster: Some(ONOFF.0),
        endpoint: Some(1),
        device_type: None,
    })
    .unwrap();
    t.add(e).unwrap();
    let acc = case_acc(1, 0x1);
    // 一致 target のみ許可。
    assert!(t.check(&acc, EP1, ONOFF, Privilege::Operate));
    assert!(!t.check(&acc, EndpointId(0), ONOFF, Privilege::Operate));
    assert!(!t.check(&acc, EP1, ClusterId(0x001D), Privilege::Operate));

    // deviceType 指定 target はマッチしない(割り切り)。
    let mut e2 = AclEntry::new(f(1), Privilege::Manage, AuthMode::Case);
    e2.add_target(AclTarget {
        cluster: None,
        endpoint: None,
        device_type: Some(0x0100),
    })
    .unwrap();
    t.add(e2).unwrap();
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Manage));
}

#[test]
fn cat_subject_matching() {
    let mut t: AclTable<8> = AclTable::new();
    // CAT identifier 0xABCD、version 2 を要求するエントリ。
    let cat_subject = 0xFFFF_FFFD_0000_0000u64 | (0xABCDu64 << 16) | 2;
    let mut e = AclEntry::new(f(1), Privilege::Operate, AuthMode::Case);
    e.add_subject(cat_subject).unwrap();
    t.add(e).unwrap();

    // セッション CAT: identifier 一致 + version 3(>= 2)→ 許可。
    let acc = case_acc(1, 0x9999).with_cats(&[0xABCD_0003]);
    assert!(t.check(&acc, EP1, ONOFF, Privilege::Operate));
    // version 1(< 2)→ 拒否。
    let acc = case_acc(1, 0x9999).with_cats(&[0xABCD_0001]);
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Operate));
    // identifier 不一致 → 拒否。
    let acc = case_acc(1, 0x9999).with_cats(&[0x1234_0005]);
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Operate));
    // CAT 無しセッション → 拒否。
    let acc = case_acc(1, 0x9999);
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Operate));
}

#[test]
fn cat_version_zero_never_matches() {
    let mut t: AclTable<8> = AclTable::new();
    let cat_subject = 0xFFFF_FFFD_0000_0000u64 | (0xABCDu64 << 16); // version 0(不正)
    let mut e = AclEntry::new(f(1), Privilege::Operate, AuthMode::Case);
    e.add_subject(cat_subject).unwrap();
    t.add(e).unwrap();
    let acc = case_acc(1, 0x9999).with_cats(&[0xABCD_0001]);
    assert!(!t.check(&acc, EP1, ONOFF, Privilege::Operate));
}

// ---------------------------------------------------------------------------
// AclHandle(RefCell 共有)
// ---------------------------------------------------------------------------

#[test]
fn handle_add_case_admin_and_remove_fabric() {
    use core::cell::RefCell;
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let h: &dyn AclHandle = &cell;
    h.add_case_admin(f(1), 0x0011_2233).unwrap();
    assert!(h.check(
        &case_acc(1, 0x0011_2233),
        EP1,
        ONOFF,
        Privilege::Administer
    ));
    h.remove_fabric(f(1));
    assert!(!h.check(&case_acc(1, 0x0011_2233), EP1, ONOFF, Privilege::View));
    assert_eq!(cell.borrow().len(), 0);
}

// ---------------------------------------------------------------------------
// 永続化(save_to / load_from)
// ---------------------------------------------------------------------------

/// テスト用インメモリ KVS(単一スロット。ACL はキー 1 つだけ使う)。
struct MemKvs {
    used: bool,
    val: [u8; MAX_ACL_RECORD_LEN],
    vlen: usize,
}

impl MemKvs {
    fn new() -> Self {
        Self {
            used: false,
            val: [0; MAX_ACL_RECORD_LEN],
            vlen: 0,
        }
    }
}

impl Kvs for MemKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> crate::error::Result<Option<usize>> {
        assert_eq!(key, b"aclt");
        if !self.used {
            return Ok(None);
        }
        if buf.len() < self.vlen {
            return Err(Error::NoSpace);
        }
        buf[..self.vlen].copy_from_slice(&self.val[..self.vlen]);
        Ok(Some(self.vlen))
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> crate::error::Result<()> {
        assert_eq!(key, b"aclt");
        assert!(value.len() <= MAX_ACL_RECORD_LEN);
        self.val[..value.len()].copy_from_slice(value);
        self.vlen = value.len();
        self.used = true;
        Ok(())
    }

    fn remove(&mut self, key: &[u8]) -> crate::error::Result<()> {
        assert_eq!(key, b"aclt");
        self.used = false;
        Ok(())
    }
}

#[test]
fn persist_roundtrip() {
    let mut kvs = MemKvs::new();
    let mut t: AclTable<8> = AclTable::new();
    t.add(AclEntry::case_admin(f(1), 0x0011_2233)).unwrap();
    let mut e = AclEntry::new(f(2), Privilege::Operate, AuthMode::Case);
    e.add_subject(0xAA).unwrap();
    e.add_subject(0xBB).unwrap();
    e.add_target(AclTarget {
        cluster: Some(6),
        endpoint: Some(1),
        device_type: None,
    })
    .unwrap();
    t.add(e).unwrap();
    t.save_to(&mut kvs).unwrap();

    let mut t2: AclTable<8> = AclTable::new();
    assert_eq!(t2.load_from(&mut kvs).unwrap(), 2);
    assert_eq!(t2.len(), 2);
    let restored: [AclEntry; 2] = {
        let mut it = t2.iter();
        [*it.next().unwrap(), *it.next().unwrap()]
    };
    assert_eq!(restored[0], AclEntry::case_admin(f(1), 0x0011_2233));
    assert_eq!(restored[1].subjects(), &[0xAA, 0xBB]);
    assert_eq!(
        restored[1].targets(),
        &[AclTarget {
            cluster: Some(6),
            endpoint: Some(1),
            device_type: None,
        }]
    );

    // 非空テーブルへの復元は InvalidState。
    assert_eq!(t2.load_from(&mut kvs), Err(Error::InvalidState));
}

#[test]
fn load_from_missing_record_is_first_boot() {
    let mut kvs = MemKvs::new();
    let mut t: AclTable<8> = AclTable::new();
    assert_eq!(t.load_from(&mut kvs).unwrap(), 0);
    assert!(t.is_empty());
}

#[test]
fn retain_fabrics_drops_unknown() {
    let mut t: AclTable<8> = AclTable::new();
    t.add(AclEntry::case_admin(f(1), 0x1)).unwrap();
    t.add(AclEntry::case_admin(f(2), 0x2)).unwrap();
    t.add(AclEntry::case_admin(f(3), 0x3)).unwrap();
    t.retain_fabrics(|idx| idx.get() == 2);
    assert_eq!(t.len(), 1);
    assert_eq!(t.iter().next().unwrap().fabric_idx(), f(2));
}
