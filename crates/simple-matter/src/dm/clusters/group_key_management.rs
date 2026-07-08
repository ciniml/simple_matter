//! Group Key Management クラスタ(0x003F、Matter Core Spec §11.2、
//! `docs/design/group-messaging.md` §2)。
//!
//! グループ鍵(KeySetWrite/Read/Remove/ReadAllIndices)と GroupKeyMap 属性
//! (group ↔ keyset の紐付け、rw)を提供する。鍵の実体は統合層が所有する共有
//! [`RefCell<GroupStore>`](crate::groups::GroupStore) で、transport の groupcast 復号と
//! Groups クラスタが同じストアを参照する([`super::AccessControlCluster`] の
//! テーブル共有と同じ流儀)。
//!
//! # IPK(GroupKeySetID 0)の扱い
//!
//! IPK は [`crate::fabric::FabricTable`] が所有する(keyset 0 は GroupStore に置かない)。
//! - KeySetWrite(id=0) = `FabricTable::rotate_ipk`(EpochKey0 のみ。epoch 1/2 は無視 =
//!   設計 §9 の割り切り)。
//! - KeySetRemove(id=0) = InvalidCommand(IPK 削除禁止)。
//! - KeySetRead は仕様どおり EpochKey0-2 を常に null で返す(chip 同様)。
//! - KeySetReadAllIndices は 0(IPK)を先頭に含める。
//!
//! # `cluster!` マクロを使わない理由
//!
//! const generic とライフタイムにジェネリックなため(AccessControl / OpCreds と同じ制約)、
//! [`ServerCluster`] は手書きし、メタデータは静的 `const` で単一ソース化する。

use core::cell::RefCell;
use core::num::NonZeroU8;

use crate::crypto::Crypto;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::{close_response, map_tlv, open_response};
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use crate::dm::{map_write_err, AttrWrite, ListOp, ServerCluster};
use crate::error::Error;
use crate::fabric::FabricTable;
use crate::groups::{
    EpochKeyInput, GroupStore, GROUP_KEY_LEN, MAX_EPOCHS_PER_KEYSET, MAX_GROUPS_PER_FABRIC,
    MAX_GROUP_KEYSETS_PER_FABRIC,
};
use crate::im::wire::ImStatus;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

/// GroupKeySecurityPolicy: TrustFirst(唯一サポートするポリシ)。
pub const POLICY_TRUST_FIRST: u8 = 0;

/// GroupKeySecurityPolicy: CacheAndSync(MCSP。非対応 = InvalidCommand)。
pub const POLICY_CACHE_AND_SYNC: u8 = 1;

/// Group Key Management クラスタの属性メタ。
static GKM_ATTRS: &[AttributeMeta] = &[
    // 0x0000 GroupKeyMap(fabric-scoped list、read View / write Manage)
    AttributeMeta::new(
        AttributeId(0x0000),
        Privilege::View,
        Quality::NONE,
        true,
        true,
        true,
    )
    .with_write_access(Privilege::Manage),
    // 0x0001 GroupTable(fabric-scoped list、RO)
    AttributeMeta::new(
        AttributeId(0x0001),
        Privilege::View,
        Quality::NONE,
        true,
        false,
        false,
    ),
    // 0x0002 MaxGroupsPerFabric
    AttributeMeta::new(
        AttributeId(0x0002),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
    // 0x0003 MaxGroupKeysPerFabric
    AttributeMeta::new(
        AttributeId(0x0003),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
];

/// Group Key Management クラスタのコマンドメタ(全て Administer)。
static GKM_CMDS: &[CommandMeta] = &[
    CommandMeta::new(CommandId(0x00), false, Privilege::Administer), // KeySetWrite
    CommandMeta::new(CommandId(0x01), true, Privilege::Administer),  // KeySetRead
    CommandMeta::new(CommandId(0x03), false, Privilege::Administer), // KeySetRemove
    CommandMeta::new(CommandId(0x04), true, Privilege::Administer),  // KeySetReadAllIndices
];

/// 生成レスポンス(KeySetReadResponse / KeySetReadAllIndicesResponse)。
static GKM_GENERATED: &[CommandId] = &[CommandId(0x02), CommandId(0x05)];

/// Group Key Management クラスタの静的メタデータ(revision 2 = Matter 1.3 値)。
static GKM_META: ClusterMeta =
    ClusterMeta::new(ClusterId(0x003F), 2, 0, GKM_ATTRS, GKM_CMDS, GKM_GENERATED);

/// Group Key Management クラスタ(0x003F)。
///
/// `C`/`N` は共有 [`FabricTable`] の型パラメータ(IPK ローテーションと
/// compressed fabric id の取得に使う)、`KS`/`GM`/`GT` は共有 [`GroupStore`] の容量。
pub struct GroupKeyManagementCluster<
    'a,
    C: Crypto,
    const N: usize,
    const KS: usize,
    const GM: usize,
    const GT: usize,
> {
    groups: &'a RefCell<GroupStore<KS, GM, GT>>,
    fabrics: &'a RefCell<FabricTable<C, N>>,
    crypto: C,
    dirty: Dirty,
}

/// KeySetWrite のフィールドを一時保持するデコード結果。
struct KeySetWriteReq {
    id: u16,
    policy: u8,
    /// (EpochKey, EpochStartTime)。key が `None` = フィールド欠落 or null。
    epochs: [(Option<[u8; GROUP_KEY_LEN]>, Option<u64>); MAX_EPOCHS_PER_KEYSET],
}

impl<'a, C: Crypto, const N: usize, const KS: usize, const GM: usize, const GT: usize>
    GroupKeyManagementCluster<'a, C, N, KS, GM, GT>
{
    /// 共有 GroupStore / FabricTable を参照するクラスタを作る。
    pub const fn new_shared(
        groups: &'a RefCell<GroupStore<KS, GM, GT>>,
        fabrics: &'a RefCell<FabricTable<C, N>>,
        crypto: C,
    ) -> Self {
        Self {
            groups,
            fabrics,
            crypto,
            dirty: Dirty::new(),
        }
    }

    /// fabric-scoped 操作の確定 fabric(PASE 未昇格は UnsupportedAccess)。
    fn require_fabric(acc: &AccessContext) -> Result<NonZeroU8, ImStatus> {
        acc.fabric_idx.ok_or(ImStatus::UnsupportedAccess)
    }

    /// GroupKeyMap 属性(0x0000)を読む。
    fn read_map(&self, e: &mut AttrEncoder<'_, '_>, acc: &AccessContext) -> Result<(), ImStatus> {
        let store = self.groups.borrow();
        e.write_array(|a| {
            for m in store.map_iter_all() {
                if acc.fabric_filtered && acc.fabric_idx != Some(m.fabric_idx()) {
                    continue;
                }
                a.push_struct(|s| {
                    s.field_u16(1, m.group_id())?;
                    s.field_u16(2, m.key_set_id())?;
                    s.field_u8(254, m.fabric_idx().get())
                })?;
            }
            Ok(())
        })
    }

    /// GroupTable 属性(0x0001)を読む(GroupInfoMapStruct。groupName は非対応 = 省略)。
    fn read_group_table(
        &self,
        e: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let store = self.groups.borrow();
        e.write_array(|a| {
            for g in store.groups_iter_all() {
                if acc.fabric_filtered && acc.fabric_idx != Some(g.fabric_idx()) {
                    continue;
                }
                a.push_struct(|s| {
                    s.field_u16(1, g.group_id())?;
                    s.field_array(2, |ea| {
                        for &ep in g.endpoints() {
                            ea.push_u16(ep)?;
                        }
                        Ok(())
                    })?;
                    s.field_u8(254, g.fabric_idx().get())
                })?;
            }
            Ok(())
        })
    }

    /// GroupKeyMap 属性(0x0000)を書く(ReplaceAll / AppendItem)。
    fn write_map(&mut self, data: AttrWrite<'_>, acc: &AccessContext) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        match data.op {
            ListOp::AppendItem => {
                let mut r = data.reader();
                let head = r.read_next().map_err(|_| ImStatus::InvalidDataType)?;
                match head.map(|e| e.value) {
                    Some(TlvValue::ContainerStart(ContainerType::Structure)) => {}
                    _ => return Err(ImStatus::InvalidDataType),
                }
                let (gid, ksid) = decode_map_row(&mut r)?;
                self.groups
                    .borrow_mut()
                    .add_map(fabric, gid, ksid)
                    .map_err(map_write_err)?;
            }
            ListOp::ReplaceAll => {
                let mut r = data.reader();
                let head = r.read_next().map_err(|_| ImStatus::InvalidDataType)?;
                match head.map(|e| e.value) {
                    Some(TlvValue::ContainerStart(ContainerType::Array)) => {}
                    _ => return Err(ImStatus::InvalidDataType),
                }
                // 先に全行を検証・収集してから置換する(途中失敗の半端な状態を避ける)。
                let mut staged = [(0u16, 0u16); MAX_GROUPS_PER_FABRIC];
                let mut count = 0usize;
                loop {
                    let el = r
                        .read_next()
                        .map_err(|_| ImStatus::InvalidDataType)?
                        .ok_or(ImStatus::InvalidDataType)?;
                    match el.value {
                        TlvValue::ContainerEnd => break,
                        TlvValue::ContainerStart(ContainerType::Structure) => {
                            if count >= MAX_GROUPS_PER_FABRIC {
                                return Err(ImStatus::ResourceExhausted);
                            }
                            staged[count] = decode_map_row(&mut r)?;
                            count += 1;
                        }
                        _ => return Err(ImStatus::InvalidDataType),
                    }
                }
                self.groups
                    .borrow_mut()
                    .set_map(fabric, &staged[..count])
                    .map_err(map_write_err)?;
            }
        }
        self.dirty.mark();
        Ok(())
    }

    /// KeySetWrite(0x00)。検証規則は chip `group-key-mgmt-server.cpp` と一致させる。
    fn cmd_key_set_write(
        &mut self,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let req = decode_key_set_write(fields)?;

        // policy: 未知 enum は ConstraintError、CacheAndSync は非対応(MCSP)= InvalidCommand。
        if req.policy > POLICY_CACHE_AND_SYNC {
            return Err(ImStatus::ConstraintError);
        }
        if req.policy == POLICY_CACHE_AND_SYNC {
            return Err(ImStatus::InvalidCommand);
        }
        // EpochKey0 必須 + EpochStartTime0 必須かつ非 0。
        let (Some(key0), Some(st0)) = (req.epochs[0].0, req.epochs[0].1) else {
            return Err(ImStatus::InvalidCommand);
        };
        if st0 == 0 {
            return Err(ImStatus::InvalidCommand);
        }
        // EpochKey1/2 の単調増加規則。
        let mut inputs = [EpochKeyInput {
            key: [0u8; GROUP_KEY_LEN],
            start_time_us: 0,
        }; MAX_EPOCHS_PER_KEYSET];
        inputs[0] = EpochKeyInput {
            key: key0,
            start_time_us: st0,
        };
        let mut ninputs = 1usize;
        if let Some(key1) = req.epochs[1].0 {
            let Some(st1) = req.epochs[1].1 else {
                return Err(ImStatus::InvalidCommand);
            };
            if st1 <= st0 {
                return Err(ImStatus::InvalidCommand);
            }
            inputs[1] = EpochKeyInput {
                key: key1,
                start_time_us: st1,
            };
            ninputs = 2;
            if let Some(key2) = req.epochs[2].0 {
                let Some(st2) = req.epochs[2].1 else {
                    return Err(ImStatus::InvalidCommand);
                };
                if st2 <= st1 {
                    return Err(ImStatus::InvalidCommand);
                }
                inputs[2] = EpochKeyInput {
                    key: key2,
                    start_time_us: st2,
                };
                ninputs = 3;
            }
        } else if req.epochs[2].0.is_some() {
            // EpochKey2 は EpochKey1 が非 null のときのみ有効。
            return Err(ImStatus::InvalidCommand);
        }

        if req.id == 0 {
            // IPK ローテーション(EpochKey0 のみ、設計 §9 の割り切り)。
            self.fabrics
                .borrow_mut()
                .rotate_ipk(&self.crypto, fabric, &key0)
                .map_err(|_| ImStatus::Failure)?;
        } else {
            let compressed = {
                let fabrics = self.fabrics.borrow();
                let entry = fabrics.get(fabric).ok_or(ImStatus::UnsupportedAccess)?;
                *entry.compressed_fabric_id_bytes()
            };
            self.groups
                .borrow_mut()
                .set_keyset(
                    fabric,
                    req.id,
                    req.policy,
                    &inputs[..ninputs],
                    &self.crypto,
                    &compressed,
                )
                .map_err(map_write_err)?;
        }
        self.dirty.mark();
        Ok(())
    }

    /// KeySetRead(0x01)→ KeySetReadResponse(0x02)。EpochKey は常に null。
    fn cmd_key_set_read(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let id = decode_keyset_id(fields)?;

        // (policy, [start_time; 3], epoch 数)
        let (policy, starts, nepochs) = if id == 0 {
            // IPK keyset: 単一 epoch、開始時刻 0(FabricTable が epoch 1 本のみ保持)。
            if self.fabrics.borrow().get(fabric).is_none() {
                return Err(ImStatus::UnsupportedAccess);
            }
            (POLICY_TRUST_FIRST, [0u64; MAX_EPOCHS_PER_KEYSET], 1usize)
        } else {
            let store = self.groups.borrow();
            let ks = store.keyset(fabric, id).ok_or(ImStatus::NotFound)?;
            let mut starts = [0u64; MAX_EPOCHS_PER_KEYSET];
            for (i, e) in ks.epochs().iter().enumerate() {
                starts[i] = e.start_time_us();
            }
            (ks.policy(), starts, ks.epochs().len())
        };

        let w = open_response(resp, 0x02)?;
        w.start_struct(&TlvTag::ContextSpecific(0))
            .map_err(map_tlv)?;
        w.write_u16(&TlvTag::ContextSpecific(0), id)
            .map_err(map_tlv)?;
        w.write_u8(&TlvTag::ContextSpecific(1), policy)
            .map_err(map_tlv)?;
        for (i, st) in starts.iter().enumerate() {
            let key_tag = TlvTag::ContextSpecific(2 + 2 * i as u8);
            let st_tag = TlvTag::ContextSpecific(3 + 2 * i as u8);
            // EpochKey は仕様どおり常に null(鍵素材は読み出せない)。
            w.write_null(&key_tag).map_err(map_tlv)?;
            if i < nepochs {
                w.write_u64(&st_tag, *st).map_err(map_tlv)?;
            } else {
                w.write_null(&st_tag).map_err(map_tlv)?;
            }
        }
        w.end_container().map_err(map_tlv)?;
        close_response(w)
    }

    /// KeySetRemove(0x03)。id 0(IPK)は削除禁止。
    fn cmd_key_set_remove(
        &mut self,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let id = decode_keyset_id(fields)?;
        if id == 0 {
            return Err(ImStatus::InvalidCommand);
        }
        match self.groups.borrow_mut().remove_keyset(fabric, id) {
            Ok(()) => {
                self.dirty.mark();
                Ok(())
            }
            Err(Error::NotFound) => Err(ImStatus::NotFound),
            Err(e) => Err(map_write_err(e)),
        }
    }

    /// KeySetReadAllIndices(0x04)→ Response(0x05)。0(IPK)を先頭に含める。
    fn cmd_key_set_read_all_indices(
        &mut self,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let w = open_response(resp, 0x05)?;
        w.start_array(&TlvTag::ContextSpecific(0))
            .map_err(map_tlv)?;
        w.write_u16(&TlvTag::Anonymous, 0).map_err(map_tlv)?;
        {
            let store = self.groups.borrow();
            let mut idx = 0usize;
            while let Some(id) = store.keyset_id_at(fabric, idx) {
                w.write_u16(&TlvTag::Anonymous, id).map_err(map_tlv)?;
                idx += 1;
            }
        }
        w.end_container().map_err(map_tlv)?;
        close_response(w)
    }
}

/// GroupKeyMapStruct の 1 行 `(groupId, groupKeySetID)` を読む(構造体開始を消費済み)。
///
/// 検証: groupId != 0、groupKeySetID != 0(IPK へのマップ禁止、chip 同様)。
fn decode_map_row(r: &mut TlvReader<'_>) -> Result<(u16, u16), ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut gid: Option<u16> = None;
    let mut ksid: Option<u16> = None;
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidDataType)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => {
                gid = Some(
                    u16::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                );
            }
            (TlvTag::ContextSpecific(2), v) => {
                ksid = Some(
                    u16::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                );
            }
            // fabricIndex(254)や未知フィールドは無視。
            _ => {}
        }
    }
    let gid = gid.ok_or(ImStatus::ConstraintError)?;
    let ksid = ksid.ok_or(ImStatus::ConstraintError)?;
    if gid == 0 || ksid == 0 {
        return Err(ImStatus::ConstraintError);
    }
    Ok((gid, ksid))
}

/// KeySetRead / KeySetRemove のフィールド `{0: GroupKeySetID}` を読む。
fn decode_keyset_id(fields: &mut TlvReader<'_>) -> Result<u16, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut r = fields.clone();
    match r.read_next().map_err(bad)?.map(|e| e.value) {
        Some(TlvValue::ContainerStart(ContainerType::Structure)) => {}
        _ => return Err(ImStatus::InvalidCommand),
    }
    let mut id: Option<u16> = None;
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidCommand)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => {
                id = Some(
                    u16::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                );
            }
            _ => {}
        }
    }
    id.ok_or(ImStatus::InvalidCommand)
}

/// KeySetWrite のフィールド `{0: GroupKeySetStruct}` を読む。
fn decode_key_set_write(fields: &mut TlvReader<'_>) -> Result<KeySetWriteReq, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut r = fields.clone();
    match r.read_next().map_err(bad)?.map(|e| e.value) {
        Some(TlvValue::ContainerStart(ContainerType::Structure)) => {}
        _ => return Err(ImStatus::InvalidCommand),
    }
    // フィールド 0 = GroupKeySetStruct。
    let mut req: Option<KeySetWriteReq> = None;
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidCommand)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), TlvValue::ContainerStart(ContainerType::Structure)) => {
                req = Some(decode_group_key_set(&mut r)?);
            }
            _ => {}
        }
    }
    req.ok_or(ImStatus::InvalidCommand)
}

/// GroupKeySetStruct 本体を読む(構造体開始を消費済み)。
fn decode_group_key_set(r: &mut TlvReader<'_>) -> Result<KeySetWriteReq, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut req = KeySetWriteReq {
        id: 0,
        policy: 0,
        epochs: [(None, None); MAX_EPOCHS_PER_KEYSET],
    };
    let mut have_id = false;
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidCommand)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => {
                req.id = u16::try_from(v.as_unsigned().map_err(bad)?)
                    .map_err(|_| ImStatus::ConstraintError)?;
                have_id = true;
            }
            (TlvTag::ContextSpecific(1), v) => {
                req.policy = u8::try_from(v.as_unsigned().map_err(bad)?)
                    .map_err(|_| ImStatus::ConstraintError)?;
            }
            // EpochKey0/1/2(タグ 2/4/6)。null は「なし」。長さ != 16 は ConstraintError。
            (TlvTag::ContextSpecific(t @ (2 | 4 | 6)), v) => {
                let slot = ((t - 2) / 2) as usize;
                match v {
                    TlvValue::Null => {}
                    TlvValue::ByteString(b) => {
                        if b.len() != GROUP_KEY_LEN {
                            return Err(ImStatus::ConstraintError);
                        }
                        let mut key = [0u8; GROUP_KEY_LEN];
                        key.copy_from_slice(b);
                        req.epochs[slot].0 = Some(key);
                    }
                    _ => return Err(ImStatus::InvalidDataType),
                }
            }
            // EpochStartTime0/1/2(タグ 3/5/7)。null は「なし」。
            (TlvTag::ContextSpecific(t @ (3 | 5 | 7)), v) => {
                let slot = ((t - 3) / 2) as usize;
                match v {
                    TlvValue::Null => {}
                    v => req.epochs[slot].1 = Some(v.as_unsigned().map_err(bad)?),
                }
            }
            _ => {}
        }
    }
    if !have_id {
        return Err(ImStatus::InvalidCommand);
    }
    Ok(req)
}

impl<C: Crypto, const N: usize, const KS: usize, const GM: usize, const GT: usize> ServerCluster
    for GroupKeyManagementCluster<'_, C, N, KS, GM, GT>
{
    fn meta(&self) -> &'static ClusterMeta {
        &GKM_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => self.read_map(enc, acc),
            0x0001 => self.read_group_table(enc, acc),
            0x0002 => enc.write_u16(MAX_GROUPS_PER_FABRIC as u16),
            0x0003 => enc.write_u16(MAX_GROUP_KEYSETS_PER_FABRIC as u16),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: AttrWrite<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => self.write_map(data, acc),
            _ => Err(ImStatus::UnsupportedWrite),
        }
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.cmd_key_set_write(fields, acc),
            0x01 => self.cmd_key_set_read(fields, resp, acc),
            0x03 => self.cmd_key_set_remove(fields, acc),
            0x04 => self.cmd_key_set_read_all_indices(resp, acc),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    fn take_dirty(&mut self) -> bool {
        self.dirty.take()
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests;
