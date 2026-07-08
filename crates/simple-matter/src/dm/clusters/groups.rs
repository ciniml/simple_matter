//! Groups クラスタ(0x0004、Matter Core Spec §9.9、`docs/design/group-messaging.md` §3)。
//!
//! group メンバーシップ(この endpoint がどの group に属するか)の CRUD を提供する。
//! 実体は統合層が所有する共有 [`RefCell<GroupStore>`](crate::groups::GroupStore) で、
//! GroupKeyManagement クラスタ(GroupTable 属性)と transport(groupcast 配送先の
//! endpoint 展開)が同じストアを参照する。インスタンスは endpoint ごとに作り、
//! 自 endpoint の id を保持する。
//!
//! # グループ名非対応(設計 §0-8)
//!
//! GN feature off(feature_map = 0)、NameSupport = 0x00。AddGroup の groupName は
//! 受理するが保存せず、ViewGroupResponse の groupName は空文字を返す(ヒープレス維持)。
//!
//! # AddGroupIfIdentifying
//!
//! 識別中(Identify クラスタの IdentifyTime > 0)のみ AddGroup として動作する。識別
//! 状態はアプリが [`GroupsCluster::set_identifying`] で仲介する(Identify の listener →
//! 本クラスタ、`take_on_off_request` と同じクラスタ↔アプリ契約)。

use core::cell::RefCell;
use core::num::NonZeroU8;

use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::{close_response, map_tlv, open_response};
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use crate::dm::{AttrWrite, ServerCluster};
use crate::error::Error;
use crate::groups::GroupStore;
use crate::im::wire::ImStatus;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

/// Groups クラスタの属性メタ。
static GROUPS_ATTRS: &[AttributeMeta] = &[
    // 0x0000 NameSupport(map8。GN off = 0x00)
    AttributeMeta::new(
        AttributeId(0x0000),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
];

/// Groups クラスタのコマンドメタ(Add/Remove 系 = Manage、View/GetMembership = Operate)。
static GROUPS_CMDS: &[CommandMeta] = &[
    CommandMeta::new(CommandId(0x00), true, Privilege::Manage), // AddGroup
    CommandMeta::new(CommandId(0x01), true, Privilege::Operate), // ViewGroup
    CommandMeta::new(CommandId(0x02), true, Privilege::Operate), // GetGroupMembership
    CommandMeta::new(CommandId(0x03), true, Privilege::Manage), // RemoveGroup
    CommandMeta::new(CommandId(0x04), false, Privilege::Manage), // RemoveAllGroups
    CommandMeta::new(CommandId(0x05), false, Privilege::Manage), // AddGroupIfIdentifying
];

/// 生成レスポンス(AddGroup/ViewGroup/GetGroupMembership/RemoveGroup の各 Response)。
static GROUPS_GENERATED: &[CommandId] = &[
    CommandId(0x00),
    CommandId(0x01),
    CommandId(0x02),
    CommandId(0x03),
];

/// Groups クラスタの静的メタデータ(revision 4、feature_map 0 = GN off)。
static GROUPS_META: ClusterMeta = ClusterMeta::new(
    ClusterId(0x0004),
    4,
    0,
    GROUPS_ATTRS,
    GROUPS_CMDS,
    GROUPS_GENERATED,
);

/// Groups クラスタ(0x0004)。endpoint ごとにインスタンスを作る。
pub struct GroupsCluster<'a, const KS: usize, const GM: usize, const GT: usize> {
    groups: &'a RefCell<GroupStore<KS, GM, GT>>,
    endpoint: u16,
    identifying: bool,
    dirty: Dirty,
}

impl<'a, const KS: usize, const GM: usize, const GT: usize> GroupsCluster<'a, KS, GM, GT> {
    /// 共有 GroupStore を参照するクラスタを作る(`endpoint` = 自 endpoint id)。
    pub const fn new_shared(groups: &'a RefCell<GroupStore<KS, GM, GT>>, endpoint: u16) -> Self {
        Self {
            groups,
            endpoint,
            identifying: false,
            dirty: Dirty::new(),
        }
    }

    /// 識別中フラグを設定する(AddGroupIfIdentifying のゲート。アプリが Identify の
    /// listener から配線する)。
    pub fn set_identifying(&mut self, identifying: bool) {
        self.identifying = identifying;
    }

    /// fabric-scoped 操作の確定 fabric(PASE 未昇格は UnsupportedAccess)。
    fn require_fabric(acc: &AccessContext) -> Result<NonZeroU8, ImStatus> {
        acc.fabric_idx.ok_or(ImStatus::UnsupportedAccess)
    }

    /// AddGroup の実処理。応答に書く status を返す。
    fn do_add_group(&mut self, fabric: NonZeroU8, gid: u16) -> ImStatus {
        if gid == 0 {
            return ImStatus::ConstraintError;
        }
        let mut store = self.groups.borrow_mut();
        // その group に紐づく鍵(GroupKeyMap + keyset)が無ければ UnsupportedAccess
        // (chip groups-server の KeyExists 検査)。
        if !store.has_key_for_group(fabric, gid) {
            return ImStatus::UnsupportedAccess;
        }
        match store.add_member(fabric, gid, self.endpoint) {
            Ok(()) => {
                self.dirty.mark();
                ImStatus::Success
            }
            Err(Error::NoSpace) => ImStatus::ResourceExhausted,
            Err(_) => ImStatus::Failure,
        }
    }

    /// AddGroup(0x00)→ AddGroupResponse(0x00)。
    fn cmd_add_group(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let gid = decode_group_id(fields)?;
        let status = self.do_add_group(fabric, gid);
        write_status_gid_response(resp, 0x00, status, gid)
    }

    /// ViewGroup(0x01)→ ViewGroupResponse(0x01)。groupName は常に空文字。
    fn cmd_view_group(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let gid = decode_group_id(fields)?;
        let status = if gid == 0 {
            ImStatus::ConstraintError
        } else if self.groups.borrow().is_member(fabric, gid, self.endpoint) {
            ImStatus::Success
        } else {
            ImStatus::NotFound
        };
        let w = open_response(resp, 0x01)?;
        w.write_u8(&TlvTag::ContextSpecific(0), status as u8)
            .map_err(map_tlv)?;
        w.write_u16(&TlvTag::ContextSpecific(1), gid)
            .map_err(map_tlv)?;
        w.write_utf8(&TlvTag::ContextSpecific(2), "")
            .map_err(map_tlv)?;
        close_response(w)
    }

    /// GetGroupMembership(0x02)→ Response(0x02)。
    ///
    /// 要求リストが空なら自 endpoint の全所属、非空なら交差を返す。capacity は
    /// null(容量不定)で返す。
    fn cmd_get_group_membership(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;

        // 要求 group リストを読む(空 = 全所属)。
        let bad = |_| ImStatus::InvalidDataType;
        let mut r = fields.clone();
        let mut requested = [0u16; 16];
        let mut nreq = 0usize;
        let mut req_present = false;
        if matches!(
            r.read_next().map_err(bad)?.map(|e| e.value),
            Some(TlvValue::ContainerStart(ContainerType::Structure))
        ) {
            while let Some(e) = r.read_next().map_err(bad)? {
                match (e.tag, e.value) {
                    (_, TlvValue::ContainerEnd) => break,
                    (
                        TlvTag::ContextSpecific(0),
                        TlvValue::ContainerStart(ContainerType::Array),
                    ) => loop {
                        let el = r
                            .read_next()
                            .map_err(bad)?
                            .ok_or(ImStatus::InvalidCommand)?;
                        match el.value {
                            TlvValue::ContainerEnd => break,
                            v => {
                                req_present = true;
                                if nreq < requested.len() {
                                    requested[nreq] = u16::try_from(v.as_unsigned().map_err(bad)?)
                                        .map_err(|_| ImStatus::ConstraintError)?;
                                    nreq += 1;
                                }
                            }
                        }
                    },
                    _ => {}
                }
            }
        }

        let w = open_response(resp, 0x02)?;
        // capacity(nullable)= null(容量は fabric 横断で不定)。
        w.write_null(&TlvTag::ContextSpecific(0)).map_err(map_tlv)?;
        w.start_array(&TlvTag::ContextSpecific(1))
            .map_err(map_tlv)?;
        {
            let store = self.groups.borrow();
            for g in store.groups_iter(fabric) {
                if !g.contains_endpoint(self.endpoint) {
                    continue;
                }
                let include = if req_present {
                    requested[..nreq].contains(&g.group_id())
                } else {
                    true
                };
                if include {
                    w.write_u16(&TlvTag::Anonymous, g.group_id())
                        .map_err(map_tlv)?;
                }
            }
        }
        w.end_container().map_err(map_tlv)?;
        close_response(w)
    }

    /// RemoveGroup(0x03)→ RemoveGroupResponse(0x03)。
    fn cmd_remove_group(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let gid = decode_group_id(fields)?;
        let status = if gid == 0 {
            ImStatus::ConstraintError
        } else if self
            .groups
            .borrow_mut()
            .remove_member(fabric, gid, self.endpoint)
        {
            self.dirty.mark();
            ImStatus::Success
        } else {
            ImStatus::NotFound
        };
        write_status_gid_response(resp, 0x03, status, gid)
    }

    /// RemoveAllGroups(0x04、応答なし = status Success のみ)。
    fn cmd_remove_all_groups(&mut self, acc: &AccessContext) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        self.groups
            .borrow_mut()
            .remove_all_members(fabric, self.endpoint);
        self.dirty.mark();
        Ok(())
    }

    /// AddGroupIfIdentifying(0x05、応答なし)。識別中のみ AddGroup 相当。
    fn cmd_add_group_if_identifying(
        &mut self,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let fabric = Self::require_fabric(acc)?;
        let gid = decode_group_id(fields)?;
        if !self.identifying {
            // 非識別中は無視(Success)。
            return Ok(());
        }
        match self.do_add_group(fabric, gid) {
            ImStatus::Success => Ok(()),
            st => Err(st),
        }
    }
}

/// コマンドフィールド `{0: groupID, 1: groupName?}` から groupID を読む
/// (groupName は保存しないため読み捨てる)。
fn decode_group_id(fields: &mut TlvReader<'_>) -> Result<u16, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut r = fields.clone();
    match r.read_next().map_err(bad)?.map(|e| e.value) {
        Some(TlvValue::ContainerStart(ContainerType::Structure)) => {}
        _ => return Err(ImStatus::InvalidCommand),
    }
    let mut gid: Option<u16> = None;
    while let Some(e) = r.read_next().map_err(bad)? {
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => {
                gid = Some(
                    u16::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                );
            }
            _ => {}
        }
    }
    gid.ok_or(ImStatus::InvalidCommand)
}

/// `{0: status, 1: groupID}` 形式の応答(AddGroupResponse / RemoveGroupResponse)を書く。
fn write_status_gid_response(
    resp: &mut CmdResponder<'_, '_>,
    response_id: u32,
    status: ImStatus,
    gid: u16,
) -> Result<(), ImStatus> {
    let w = open_response(resp, response_id)?;
    w.write_u8(&TlvTag::ContextSpecific(0), status as u8)
        .map_err(map_tlv)?;
    w.write_u16(&TlvTag::ContextSpecific(1), gid)
        .map_err(map_tlv)?;
    close_response(w)
}

impl<const KS: usize, const GM: usize, const GT: usize> ServerCluster
    for GroupsCluster<'_, KS, GM, GT>
{
    fn meta(&self) -> &'static ClusterMeta {
        &GROUPS_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            // NameSupport: GN off = 0x00。
            0x0000 => enc.write_u8(0x00),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        _attr: AttributeId,
        _data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        Err(ImStatus::UnsupportedWrite)
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.cmd_add_group(fields, resp, acc),
            0x01 => self.cmd_view_group(fields, resp, acc),
            0x02 => self.cmd_get_group_membership(fields, resp, acc),
            0x03 => self.cmd_remove_group(fields, resp, acc),
            0x04 => self.cmd_remove_all_groups(acc),
            0x05 => self.cmd_add_group_if_identifying(fields, acc),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    fn take_dirty(&mut self) -> bool {
        self.dirty.take()
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests;
