//! Groups クラスタ(0x0004)のユニットテスト。
//!
//! AddGroup のステータス規則(ConstraintError / UnsupportedAccess / Success)、
//! View / GetGroupMembership / Remove 系、AddGroupIfIdentifying のゲートを固定する。

use core::cell::RefCell;

use super::*;
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::Rng;
use crate::dm::meta::SessionKind;
use crate::groups::{DefaultGroupStore, EpochKeyInput};
use crate::tlv::TlvWriter;

struct DummyRng;
impl Rng for DummyRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
        dest.iter_mut().for_each(|b| *b = 7);
        Ok(())
    }
}

type Gc<'a> = GroupsCluster<'a, 6, 8, 8>;

fn f(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap()
}

fn acc(fabric: u8) -> AccessContext {
    AccessContext::new(
        SessionKind::Case,
        NonZeroU8::new(fabric),
        0x1234,
        Privilege::Manage,
    )
}

/// (fabric 1, gid) に keyset 42 を紐付けておく(AddGroup の前提)。
fn seed_key(groups: &RefCell<DefaultGroupStore>, gid: u16) {
    let crypto = RustCrypto::new(DummyRng);
    let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
    let mut s = groups.borrow_mut();
    if s.keyset(f(1), 42).is_none() {
        s.set_keyset(
            f(1),
            42,
            0,
            &[EpochKeyInput {
                key: [0xd0; 16],
                start_time_us: 1,
            }],
            &crypto,
            &cfid,
        )
        .unwrap();
    }
    s.add_map(f(1), gid, 42).unwrap();
}

/// `{0: gid, 1: name}` のコマンドフィールドをエンコードする。
fn encode_gid_fields(buf: &mut [u8], gid: u16, name: Option<&str>) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(0), gid).unwrap();
    if let Some(n) = name {
        w.write_utf8(&TlvTag::ContextSpecific(1), n).unwrap();
    }
    w.end_container().unwrap();
    w.len()
}

/// invoke を実行し、応答バイト列の長さも返す。
fn invoke(
    cl: &mut Gc<'_>,
    cmd: u32,
    fields: &[u8],
    out: &mut [u8],
    a: &AccessContext,
) -> (Result<(), ImStatus>, usize) {
    let mut fr = TlvReader::new(fields);
    let mut w = TlvWriter::new(out);
    let mut resp = CmdResponder::new(&mut w);
    let r = cl.invoke_command(CommandId(cmd), &mut fr, &mut resp, a);
    (r, w.len())
}

/// 応答から `{0: status, 1: gid}` を取り出す。
fn parse_status_gid(out: &[u8]) -> (u8, u16) {
    let mut r = TlvReader::new(out);
    let mut status = 0xFF;
    let mut gid = 0;
    while let Ok(Some(e)) = r.read_next() {
        match (e.tag, e.value) {
            (TlvTag::ContextSpecific(0), v) => status = v.as_unsigned().unwrap_or(0xFF) as u8,
            (TlvTag::ContextSpecific(1), v) => gid = v.as_unsigned().unwrap_or(0) as u16,
            _ => {}
        }
    }
    (status, gid)
}

#[test]
fn add_group_status_rules() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let mut cl = Gc::new_shared(&groups, 1);
    let a = acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 128];

    // gid 0 → ConstraintError(応答内 status)。
    let n = encode_gid_fields(&mut buf, 0, Some("x"));
    let (r, _) = invoke(&mut cl, 0x00, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::ConstraintError as u8);

    // 鍵未マップ → UnsupportedAccess。
    let n = encode_gid_fields(&mut buf, 0x0101, Some("x"));
    let (r, _) = invoke(&mut cl, 0x00, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::UnsupportedAccess as u8);

    // key-set-write + group-key-map 後は Success、メンバーシップに載る。
    seed_key(&groups, 0x0101);
    let (r, _) = invoke(&mut cl, 0x00, &buf[..n], &mut out, &a);
    r.unwrap();
    let (st, gid) = parse_status_gid(&out);
    assert_eq!(st, ImStatus::Success as u8);
    assert_eq!(gid, 0x0101);
    assert!(groups.borrow().is_member(f(1), 0x0101, 1));

    // fabric 未確定 → UnsupportedAccess(invoke 自体のエラー)。
    let no_fabric = AccessContext::new(SessionKind::Case, None, 0, Privilege::Manage);
    let (r, _) = invoke(&mut cl, 0x00, &buf[..n], &mut out, &no_fabric);
    assert_eq!(r, Err(ImStatus::UnsupportedAccess));
}

#[test]
fn view_and_membership_and_remove() {
    let groups = RefCell::new(DefaultGroupStore::new());
    seed_key(&groups, 0x0101);
    seed_key(&groups, 0x0102);
    let mut cl = Gc::new_shared(&groups, 1);
    let a = acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 128];

    // 2 group に加入。
    for gid in [0x0101u16, 0x0102] {
        let n = encode_gid_fields(&mut buf, gid, None);
        let (r, _) = invoke(&mut cl, 0x00, &buf[..n], &mut out, &a);
        r.unwrap();
        assert_eq!(parse_status_gid(&out).0, ImStatus::Success as u8);
    }

    // ViewGroup: 所属 → Success + 空 name、非所属 → NotFound。
    let n = encode_gid_fields(&mut buf, 0x0101, None);
    let (r, _) = invoke(&mut cl, 0x01, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::Success as u8);
    let n = encode_gid_fields(&mut buf, 0x0999, None);
    let (r, _) = invoke(&mut cl, 0x01, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::NotFound as u8);

    // GetGroupMembership(空リスト = 全所属)→ [0x0101, 0x0102]。
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.start_array(&TlvTag::ContextSpecific(0)).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.len()
    };
    let (r, len) = invoke(&mut cl, 0x02, &buf[..n], &mut out, &a);
    r.unwrap();
    let mut rr = TlvReader::new(&out[..len]);
    let mut gids = [0u16; 4];
    let mut ngids = 0;
    let mut saw_null_capacity = false;
    while let Ok(Some(e)) = rr.read_next() {
        match (e.tag, e.value) {
            (TlvTag::ContextSpecific(0), TlvValue::Null) => saw_null_capacity = true,
            (TlvTag::Anonymous, v) => {
                if let Ok(g) = v.as_unsigned() {
                    gids[ngids] = g as u16;
                    ngids += 1;
                }
            }
            _ => {}
        }
    }
    assert!(saw_null_capacity);
    assert_eq!(&gids[..ngids], &[0x0101, 0x0102]);

    // GetGroupMembership(交差)→ [0x0102]。
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.start_array(&TlvTag::ContextSpecific(0)).unwrap();
        w.write_u16(&TlvTag::Anonymous, 0x0102).unwrap();
        w.write_u16(&TlvTag::Anonymous, 0x0777).unwrap();
        w.end_container().unwrap();
        w.end_container().unwrap();
        w.len()
    };
    let (r, len) = invoke(&mut cl, 0x02, &buf[..n], &mut out, &a);
    r.unwrap();
    let mut rr = TlvReader::new(&out[..len]);
    let mut got = 0u16;
    let mut count = 0;
    while let Ok(Some(e)) = rr.read_next() {
        if let (TlvTag::Anonymous, Ok(v)) = (e.tag, e.value.as_unsigned()) {
            got = v as u16;
            count += 1;
        }
    }
    assert_eq!((got, count), (0x0102, 1));

    // RemoveGroup: 所属 → Success、再削除 → NotFound。
    let n = encode_gid_fields(&mut buf, 0x0101, None);
    let (r, _) = invoke(&mut cl, 0x03, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::Success as u8);
    let (r, _) = invoke(&mut cl, 0x03, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::NotFound as u8);

    // RemoveAllGroups → 全所属が消える(応答なしコマンド = Ok)。
    let (r, _) = invoke(&mut cl, 0x04, &[], &mut out, &a);
    r.unwrap();
    assert!(!groups.borrow().is_member(f(1), 0x0102, 1));
}

#[test]
fn add_group_if_identifying_gates_on_identify() {
    let groups = RefCell::new(DefaultGroupStore::new());
    seed_key(&groups, 0x0101);
    let mut cl = Gc::new_shared(&groups, 1);
    let a = acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 128];

    // 非識別中は無視(Success、加入しない)。
    let n = encode_gid_fields(&mut buf, 0x0101, None);
    let (r, _) = invoke(&mut cl, 0x05, &buf[..n], &mut out, &a);
    r.unwrap();
    assert!(!groups.borrow().is_member(f(1), 0x0101, 1));

    // 識別中は AddGroup 相当。
    cl.set_identifying(true);
    let (r, _) = invoke(&mut cl, 0x05, &buf[..n], &mut out, &a);
    r.unwrap();
    assert!(groups.borrow().is_member(f(1), 0x0101, 1));

    // 識別中でも鍵未マップは UnsupportedAccess。
    let n = encode_gid_fields(&mut buf, 0x0999, None);
    let (r, _) = invoke(&mut cl, 0x05, &buf[..n], &mut out, &a);
    assert_eq!(r, Err(ImStatus::UnsupportedAccess));
}

#[test]
fn endpoint_isolation() {
    // 別 endpoint のクラスタは別メンバーシップを持つ。
    let groups = RefCell::new(DefaultGroupStore::new());
    seed_key(&groups, 0x0101);
    let mut ep1 = Gc::new_shared(&groups, 1);
    let mut ep2 = Gc::new_shared(&groups, 2);
    let a = acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 128];

    let n = encode_gid_fields(&mut buf, 0x0101, None);
    let (r, _) = invoke(&mut ep1, 0x00, &buf[..n], &mut out, &a);
    r.unwrap();
    // ep2 は非所属。
    let (r, _) = invoke(&mut ep2, 0x01, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(parse_status_gid(&out).0, ImStatus::NotFound as u8);
    // ep2 も加入すると endpoints = [1, 2]。
    let (r, _) = invoke(&mut ep2, 0x00, &buf[..n], &mut out, &a);
    r.unwrap();
    assert_eq!(
        groups.borrow().member_endpoints(f(1), 0x0101).unwrap(),
        &[1, 2]
    );
}
