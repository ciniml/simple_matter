//! Access Control クラスタ(0x001F)のユニットテスト(read / write の ReplaceAll・Append、
//! fabric フィルタ、拒否 status)。

use core::cell::RefCell;
use core::num::NonZeroU8;

use super::*;
use crate::acl::{AclEntry, AclTable};
use crate::dm::meta::SessionKind;
use crate::tlv::{TlvTag, TlvWriter};

fn f(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap()
}

fn case_acc(fabric: u8) -> AccessContext {
    AccessContext::new(
        SessionKind::Case,
        NonZeroU8::new(fabric),
        0x0011_2233,
        Privilege::Administer,
    )
}

/// ワイヤ表現の ACL エントリ構造体を `w` に書く(タグは呼び出し側指定)。
fn write_wire_entry(
    w: &mut TlvWriter<'_>,
    tag: &TlvTag,
    privilege: u8,
    auth: u8,
    subjects: &[u64],
    fabric_index: Option<u8>,
) {
    w.start_struct(tag).unwrap();
    w.write_u8(&TlvTag::ContextSpecific(1), privilege).unwrap();
    w.write_u8(&TlvTag::ContextSpecific(2), auth).unwrap();
    if subjects.is_empty() {
        w.write_null(&TlvTag::ContextSpecific(3)).unwrap();
    } else {
        w.start_array(&TlvTag::ContextSpecific(3)).unwrap();
        for &s in subjects {
            w.write_u64(&TlvTag::Anonymous, s).unwrap();
        }
        w.end_container().unwrap();
    }
    w.write_null(&TlvTag::ContextSpecific(4)).unwrap();
    if let Some(fi) = fabric_index {
        w.write_u8(&TlvTag::ContextSpecific(254), fi).unwrap();
    }
    w.end_container().unwrap();
}

/// ReplaceAll 用の配列値(エントリ 1 つ)をエンコードする。
fn encode_replace_all(buf: &mut [u8], privilege: u8, subjects: &[u64]) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_array(&TlvTag::Anonymous).unwrap();
    write_wire_entry(&mut w, &TlvTag::Anonymous, privilege, 2, subjects, None);
    w.end_container().unwrap();
    w.len()
}

/// Append 用のエントリ値をエンコードする。
fn encode_append(
    buf: &mut [u8],
    privilege: u8,
    subjects: &[u64],
    fabric_index: Option<u8>,
) -> usize {
    let mut w = TlvWriter::new(buf);
    write_wire_entry(
        &mut w,
        &TlvTag::Anonymous,
        privilege,
        2,
        subjects,
        fabric_index,
    );
    w.len()
}

#[test]
fn write_replace_all_and_read_back() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let mut cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);

    let mut buf = [0u8; 128];
    let n = encode_replace_all(&mut buf, 5, &[0x0011_2233]);
    cl.write_attribute(AttributeId(0), AttrWrite::new(&buf[..n]), &acc)
        .unwrap();
    assert!(cl.take_dirty());
    {
        let t = cell.borrow();
        assert_eq!(t.len(), 1);
        let e = t.iter().next().unwrap();
        assert_eq!(e.fabric_idx(), f(1));
        assert_eq!(e.privilege(), Privilege::Administer);
        assert_eq!(e.subjects(), &[0x0011_2233]);
        assert!(e.targets().is_empty());
    }

    // read back(fabric フィルタ無し)。
    let mut out = [0u8; 256];
    let mut w = TlvWriter::new(&mut out);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        cl.read_attribute(AttributeId(0), &mut enc, &acc).unwrap();
    }
    let len = w.len();
    // 配列 → 構造体 → privilege(1)=5 を確認。
    let mut r = TlvReader::new(&out[..len]);
    assert!(matches!(
        r.read_next().unwrap().unwrap().value,
        TlvValue::ContainerStart(ContainerType::Array)
    ));
    assert!(matches!(
        r.read_next().unwrap().unwrap().value,
        TlvValue::ContainerStart(ContainerType::Structure)
    ));
    let e = r.read_next().unwrap().unwrap();
    assert_eq!(e.tag, crate::tlv::TlvTag::ContextSpecific(1));
    assert_eq!(e.value.as_unsigned().unwrap(), 5);
}

#[test]
fn write_append_adds_entry_and_forces_fabric() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let mut cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);

    // fabricIndex=9 を書いてもアクセス元 fabric(1)を強制する。
    let mut buf = [0u8; 128];
    let n = encode_append(&mut buf, 3, &[0xAA], Some(9));
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    cl.write_attribute(AttributeId(0), data, &acc).unwrap();
    let t = cell.borrow();
    assert_eq!(t.len(), 1);
    let e = t.iter().next().unwrap();
    assert_eq!(e.fabric_idx(), f(1));
    assert_eq!(e.privilege(), Privilege::Operate);
}

#[test]
fn replace_all_replaces_only_own_fabric() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    cell.borrow_mut()
        .add(AclEntry::case_admin(f(2), 0x9999))
        .unwrap();
    let mut cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);

    let mut buf = [0u8; 128];
    let n = encode_replace_all(&mut buf, 5, &[0x1111]);
    cl.write_attribute(AttributeId(0), AttrWrite::new(&buf[..n]), &acc)
        .unwrap();
    let t = cell.borrow();
    assert_eq!(t.len(), 2);
    assert_eq!(t.fabric_len(f(1)), 1);
    assert_eq!(t.fabric_len(f(2)), 1);
}

#[test]
fn fabric_filtered_read_hides_other_fabrics() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    cell.borrow_mut()
        .add(AclEntry::case_admin(f(1), 0x1111))
        .unwrap();
    cell.borrow_mut()
        .add(AclEntry::case_admin(f(2), 0x2222))
        .unwrap();
    let cl = AccessControlCluster::new(&cell);

    // fabricFiltered read → 自 fabric(1)の 1 件のみ。
    let acc = case_acc(1).with_fabric_filtered(true);
    let mut out = [0u8; 256];
    let mut w = TlvWriter::new(&mut out);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        cl.read_attribute(AttributeId(0), &mut enc, &acc).unwrap();
    }
    let len = w.len();
    let mut r = TlvReader::new(&out[..len]);
    let mut structs = 0;
    while let Some(e) = r.read_next().unwrap() {
        if matches!(e.value, TlvValue::ContainerStart(ContainerType::Structure)) {
            structs += 1;
        }
    }
    assert_eq!(structs, 1);
}

#[test]
fn write_without_fabric_is_unsupported_access() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let mut cl = AccessControlCluster::new(&cell);
    // fabric 未確定(PASE 未昇格相当)。
    let acc = AccessContext::new(SessionKind::Case, None, 0, Privilege::Administer);
    let mut buf = [0u8; 128];
    let n = encode_replace_all(&mut buf, 5, &[0x1]);
    let r = cl.write_attribute(AttributeId(0), AttrWrite::new(&buf[..n]), &acc);
    assert_eq!(r, Err(ImStatus::UnsupportedAccess));
}

#[test]
fn invalid_entry_is_constraint_error() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let mut cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);

    // privilege=2(ProxyView、未対応)→ ConstraintError。
    let mut buf = [0u8; 128];
    let n = encode_append(&mut buf, 2, &[0x1], None);
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    assert_eq!(
        cl.write_attribute(AttributeId(0), data, &acc),
        Err(ImStatus::ConstraintError)
    );

    // authMode=PASE(1)のエントリは受理しない(AclTable::add の検証)。
    let mut w = TlvWriter::new(&mut buf);
    write_wire_entry(&mut w, &TlvTag::Anonymous, 5, 1, &[0x1], None);
    let n = w.len();
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    assert_eq!(
        cl.write_attribute(AttributeId(0), data, &acc),
        Err(ImStatus::ConstraintError)
    );
}

#[test]
fn capacity_overflow_is_resource_exhausted() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let mut cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);
    let mut buf = [0u8; 128];
    for i in 0..crate::acl::ACL_ENTRIES_PER_FABRIC {
        let n = encode_append(&mut buf, 5, &[i as u64 + 1], None);
        let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
        cl.write_attribute(AttributeId(0), data, &acc).unwrap();
    }
    let n = encode_append(&mut buf, 5, &[0x99], None);
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    assert_eq!(
        cl.write_attribute(AttributeId(0), data, &acc),
        Err(ImStatus::ResourceExhausted)
    );
}

#[test]
fn scalar_attributes_report_spec_minimums() {
    let cell: RefCell<AclTable<8>> = RefCell::new(AclTable::new());
    let cl = AccessControlCluster::new(&cell);
    let acc = case_acc(1);
    for (attr, expect) in [(0x0002u32, 4u64), (0x0003, 3), (0x0004, 4)] {
        let mut out = [0u8; 16];
        let mut w = TlvWriter::new(&mut out);
        {
            let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            cl.read_attribute(AttributeId(attr), &mut enc, &acc)
                .unwrap();
        }
        let v = TlvReader::new(&out)
            .read_next()
            .unwrap()
            .unwrap()
            .value
            .as_unsigned()
            .unwrap();
        assert_eq!(v, expect, "attr {attr:#x}");
    }
}
