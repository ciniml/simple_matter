//! Group Key Management クラスタ(0x003F)のユニットテスト。
//!
//! KeySetWrite の検証規則(chip `group-key-mgmt-server.cpp` 一致)、GroupKeyMap の
//! ReplaceAll / Append と keyset 0 拒否、KeySetRead の EpochKey null 化、
//! KeySetRemove、fabric フィルタを固定する。KeySetWrite の成功系(実 fabric の
//! compressed fabric id が必要)は stack の groupcast E2E テストで担保する。

use core::cell::RefCell;

use super::*;
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::Rng;
use crate::dm::meta::SessionKind;
use crate::dm::ListOp;
use crate::groups::DefaultGroupStore;
use crate::tlv::TlvWriter;

struct DummyRng;
impl Rng for DummyRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
        dest.iter_mut().for_each(|b| *b = 7);
        Ok(())
    }
}

type Crb = RustCrypto<DummyRng>;
type Fabrics = FabricTable<Crb, 5>;
type Gkm<'a> = GroupKeyManagementCluster<'a, Crb, 5, 6, 8, 8>;

fn backend() -> Crb {
    RustCrypto::new(DummyRng)
}

fn f(n: u8) -> NonZeroU8 {
    NonZeroU8::new(n).unwrap()
}

fn admin_acc(fabric: u8) -> AccessContext {
    AccessContext::new(
        SessionKind::Case,
        NonZeroU8::new(fabric),
        0x1234,
        Privilege::Administer,
    )
}

/// KeySetWrite のコマンドフィールド `{0: GroupKeySetStruct}` をエンコードする。
///
/// `epochs[i] = (key, start_time)`。`None` は null として書く。
#[allow(clippy::type_complexity)]
fn encode_key_set_write(
    buf: &mut [u8],
    id: u16,
    policy: u8,
    epochs: &[(Option<&[u8]>, Option<u64>); 3],
) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.start_struct(&TlvTag::ContextSpecific(0)).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(0), id).unwrap();
    w.write_u8(&TlvTag::ContextSpecific(1), policy).unwrap();
    for (i, (key, st)) in epochs.iter().enumerate() {
        let key_tag = TlvTag::ContextSpecific(2 + 2 * i as u8);
        let st_tag = TlvTag::ContextSpecific(3 + 2 * i as u8);
        match key {
            Some(k) => w.write_bytes(&key_tag, k).unwrap(),
            None => w.write_null(&key_tag).unwrap(),
        }
        match st {
            Some(t) => w.write_u64(&st_tag, *t).unwrap(),
            None => w.write_null(&st_tag).unwrap(),
        }
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.len()
}

/// `{0: id}` 形式のコマンドフィールドをエンコードする(KeySetRead / KeySetRemove)。
fn encode_id_fields(buf: &mut [u8], id: u16) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(0), id).unwrap();
    w.end_container().unwrap();
    w.len()
}

/// invoke を実行して結果を返す(応答バイト列は `out` に残る)。
fn invoke(
    cl: &mut Gkm<'_>,
    cmd: u32,
    fields: &[u8],
    out: &mut [u8],
    acc: &AccessContext,
) -> Result<(), ImStatus> {
    let mut fr = TlvReader::new(fields);
    let mut w = TlvWriter::new(out);
    let mut resp = CmdResponder::new(&mut w);
    cl.invoke_command(CommandId(cmd), &mut fr, &mut resp, acc)
}

const KEY16: [u8; 16] = [0xd0; 16];

#[test]
fn key_set_write_validation_rules() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let fabrics: RefCell<Fabrics> = RefCell::new(FabricTable::new());
    let mut cl = Gkm::new_shared(&groups, &fabrics, backend());
    let acc = admin_acc(1);
    let mut buf = [0u8; 256];
    let mut out = [0u8; 256];

    // policy 未知(2)→ ConstraintError。
    let n = encode_key_set_write(
        &mut buf,
        42,
        2,
        &[(Some(&KEY16), Some(1)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::ConstraintError)
    );
    // CacheAndSync(1)→ InvalidCommand(MCSP 非対応)。
    let n = encode_key_set_write(
        &mut buf,
        42,
        1,
        &[(Some(&KEY16), Some(1)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // EpochKey0 null → InvalidCommand。
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[(None, Some(1)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // EpochStartTime0 = 0 → InvalidCommand。
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[(Some(&KEY16), Some(0)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // EpochKey 長 != 16 → ConstraintError。
    let short = [0u8; 8];
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[(Some(&short), Some(1)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::ConstraintError)
    );
    // EpochKey1 あり + StartTime1 <= StartTime0 → InvalidCommand。
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[
            (Some(&KEY16), Some(10)),
            (Some(&KEY16), Some(10)),
            (None, None),
        ],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // EpochKey2 あり + EpochKey1 null → InvalidCommand。
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[
            (Some(&KEY16), Some(10)),
            (None, None),
            (Some(&KEY16), Some(30)),
        ],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // fabric 未確定 → UnsupportedAccess。
    let no_fabric = AccessContext::new(SessionKind::Case, None, 0, Privilege::Administer);
    let n = encode_key_set_write(
        &mut buf,
        42,
        0,
        &[(Some(&KEY16), Some(1)), (None, None), (None, None)],
    );
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &no_fabric),
        Err(ImStatus::UnsupportedAccess)
    );
    // 検証を通っても fabric 実体が無ければ UnsupportedAccess(compressed fabric id 不在)。
    assert_eq!(
        invoke(&mut cl, 0x00, &buf[..n], &mut out, &acc),
        Err(ImStatus::UnsupportedAccess)
    );
}

/// GroupStore へ直接 keyset を入れるヘルパ(KeySetWrite 成功系の代替)。
fn seed_keyset(groups: &RefCell<DefaultGroupStore>, fabric: NonZeroU8, id: u16) {
    let crypto = backend();
    let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
    groups
        .borrow_mut()
        .set_keyset(
            fabric,
            id,
            0,
            &[
                EpochKeyInput {
                    key: KEY16,
                    start_time_us: 100,
                },
                EpochKeyInput {
                    key: [0xd1; 16],
                    start_time_us: 200,
                },
            ],
            &crypto,
            &cfid,
        )
        .unwrap();
}

#[test]
fn key_set_read_nulls_epoch_keys() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let fabrics: RefCell<Fabrics> = RefCell::new(FabricTable::new());
    seed_keyset(&groups, f(1), 42);
    let mut cl = Gkm::new_shared(&groups, &fabrics, backend());
    let acc = admin_acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 256];

    let n = encode_id_fields(&mut buf, 42);
    invoke(&mut cl, 0x01, &buf[..n], &mut out, &acc).unwrap();

    // 応答構造体: {0: {0: id, 1: policy, 2: null, 3: 100, 4: null, 5: 200, 6: null, 7: null}}
    let mut r = TlvReader::new(&out);
    let mut nulls = 0;
    let mut times = [0u64; 3];
    let mut ntimes = 0;
    while let Ok(Some(e)) = r.read_next() {
        match (e.tag, e.value) {
            (TlvTag::ContextSpecific(t @ (2 | 4 | 6)), TlvValue::Null) => {
                let _ = t;
                nulls += 1;
            }
            (TlvTag::ContextSpecific(3 | 5), v) => {
                if let Ok(t) = v.as_unsigned() {
                    times[ntimes] = t;
                    ntimes += 1;
                }
            }
            (TlvTag::ContextSpecific(7), TlvValue::Null) => nulls += 1,
            _ => {}
        }
    }
    assert_eq!(nulls, 4, "EpochKey0-2 と StartTime2 が null");
    assert_eq!(&times[..ntimes], &[100, 200]);

    // 未知 id → NotFound。
    let n = encode_id_fields(&mut buf, 99);
    assert_eq!(
        invoke(&mut cl, 0x01, &buf[..n], &mut out, &acc),
        Err(ImStatus::NotFound)
    );
    // 他 fabric からは見えない。
    let acc2 = admin_acc(2);
    let n = encode_id_fields(&mut buf, 42);
    assert_eq!(
        invoke(&mut cl, 0x01, &buf[..n], &mut out, &acc2),
        Err(ImStatus::NotFound)
    );
}

#[test]
fn key_set_remove_and_read_all_indices() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let fabrics: RefCell<Fabrics> = RefCell::new(FabricTable::new());
    seed_keyset(&groups, f(1), 42);
    seed_keyset(&groups, f(1), 43);
    let mut cl = Gkm::new_shared(&groups, &fabrics, backend());
    let acc = admin_acc(1);
    let mut buf = [0u8; 64];
    let mut out = [0u8; 256];

    // ReadAllIndices → [0, 42, 43]。
    invoke(&mut cl, 0x04, &[], &mut out, &acc).unwrap();
    let mut r = TlvReader::new(&out);
    let mut ids = [0u16; 8];
    let mut nids = 0;
    while let Ok(Some(e)) = r.read_next() {
        if let (TlvTag::Anonymous, Ok(v)) = (e.tag, e.value.as_unsigned()) {
            ids[nids] = v as u16;
            nids += 1;
        }
    }
    assert_eq!(&ids[..nids], &[0, 42, 43]);

    // KeySetRemove(0)= IPK 削除禁止。
    let n = encode_id_fields(&mut buf, 0);
    assert_eq!(
        invoke(&mut cl, 0x03, &buf[..n], &mut out, &acc),
        Err(ImStatus::InvalidCommand)
    );
    // KeySetRemove(42)成功、再削除は NotFound。
    let n = encode_id_fields(&mut buf, 42);
    invoke(&mut cl, 0x03, &buf[..n], &mut out, &acc).unwrap();
    assert_eq!(
        invoke(&mut cl, 0x03, &buf[..n], &mut out, &acc),
        Err(ImStatus::NotFound)
    );
    assert!(groups.borrow().keyset(f(1), 42).is_none());
}

/// GroupKeyMap 行(構造体)をエンコードする。
fn write_map_row(w: &mut TlvWriter<'_>, tag: &TlvTag, gid: u16, ksid: u16, fi: Option<u8>) {
    w.start_struct(tag).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(1), gid).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(2), ksid).unwrap();
    if let Some(fi) = fi {
        w.write_u8(&TlvTag::ContextSpecific(254), fi).unwrap();
    }
    w.end_container().unwrap();
}

#[test]
fn group_key_map_write_and_read() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let fabrics: RefCell<Fabrics> = RefCell::new(FabricTable::new());
    seed_keyset(&groups, f(1), 42);
    let mut cl = Gkm::new_shared(&groups, &fabrics, backend());
    let acc = admin_acc(1);

    // ReplaceAll: 2 行。
    let mut buf = [0u8; 256];
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        w.start_array(&TlvTag::Anonymous).unwrap();
        write_map_row(&mut w, &TlvTag::Anonymous, 0x0101, 42, None);
        // fabricIndex=9 を書いてもアクセス元 fabric を強制。
        write_map_row(&mut w, &TlvTag::Anonymous, 0x0102, 42, Some(9));
        w.end_container().unwrap();
        w.len()
    };
    cl.write_attribute(AttributeId(0), AttrWrite::new(&buf[..n]), &acc)
        .unwrap();
    assert!(cl.take_dirty());
    assert_eq!(groups.borrow().map_len(f(1)), 2);
    assert_eq!(groups.borrow().map_len(f(9)), 0);

    // Append: keyset 0 へのマップは ConstraintError。
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        write_map_row(&mut w, &TlvTag::Anonymous, 0x0103, 0, None);
        w.len()
    };
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    assert_eq!(
        cl.write_attribute(AttributeId(0), data, &acc),
        Err(ImStatus::ConstraintError)
    );

    // Append: 正常行。
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        write_map_row(&mut w, &TlvTag::Anonymous, 0x0103, 42, None);
        w.len()
    };
    let data = AttrWrite::new(&buf[..n]).with_op(ListOp::AppendItem);
    cl.write_attribute(AttributeId(0), data, &acc).unwrap();
    assert_eq!(groups.borrow().map_len(f(1)), 3);

    // fabricFiltered read: 他 fabric の行は見えない。
    groups.borrow_mut().add_map(f(2), 0x0201, 1).unwrap();
    let acc_f = admin_acc(1).with_fabric_filtered(true);
    let mut out = [0u8; 512];
    let mut w = TlvWriter::new(&mut out);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        cl.read_attribute(AttributeId(0), &mut enc, &acc_f).unwrap();
    }
    let len = w.len();
    let mut r = TlvReader::new(&out[..len]);
    let mut rows = 0;
    while let Ok(Some(e)) = r.read_next() {
        if matches!(e.value, TlvValue::ContainerStart(ContainerType::Structure)) {
            rows += 1;
        }
    }
    assert_eq!(rows, 3, "自 fabric の 3 行のみ");
}

#[test]
fn group_table_read_lists_membership() {
    let groups = RefCell::new(DefaultGroupStore::new());
    let fabrics: RefCell<Fabrics> = RefCell::new(FabricTable::new());
    groups.borrow_mut().add_member(f(1), 0x0101, 1).unwrap();
    groups.borrow_mut().add_member(f(1), 0x0101, 2).unwrap();
    let cl = Gkm::new_shared(&groups, &fabrics, backend());
    let acc = admin_acc(1);

    let mut out = [0u8; 256];
    let mut w = TlvWriter::new(&mut out);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        cl.read_attribute(AttributeId(1), &mut enc, &acc).unwrap();
    }
    let len = w.len();
    // groupId(1)= 0x0101 と endpoints [1, 2] が現れる。
    let mut r = TlvReader::new(&out[..len]);
    let mut saw_gid = false;
    let mut eps = 0;
    while let Ok(Some(e)) = r.read_next() {
        match (e.tag, e.value) {
            (TlvTag::ContextSpecific(1), v) => {
                if v.as_unsigned() == Ok(0x0101) {
                    saw_gid = true;
                }
            }
            (TlvTag::Anonymous, v) => {
                if matches!(v.as_unsigned(), Ok(1) | Ok(2)) {
                    eps += 1;
                }
            }
            _ => {}
        }
    }
    assert!(saw_gid);
    assert_eq!(eps, 2);
}
