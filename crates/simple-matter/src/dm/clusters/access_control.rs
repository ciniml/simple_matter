//! Access Control クラスタ(0x001F、Matter Core Spec §9.10、`docs/design/acl.md` §4)。
//!
//! fabric-scoped な ACL エントリ list(属性 0x0000)の read / write を提供する。
//! エントリの実体は統合層が所有する共有 [`RefCell<AclTable<E>>`](crate::acl::AclTable)
//! で、IM エンジンの権限評価(`DataModel::acl`)と同じテーブルを参照する
//! ([`crate::dm::clusters::OpCredsCluster`] の fabric テーブル共有と同じ流儀)。
//!
//! # `cluster!` マクロを使わない理由
//!
//! const generic `E` とライフタイムにジェネリックなため(OpCreds と同じ制約)、
//! [`ServerCluster`] は手書きし、メタデータは静的 `const` で単一ソース化する。
//!
//! # write の list 操作
//!
//! chip 系コントローラは list 属性を「先頭 IB = 空配列(ReplaceAll)、以降 IB =
//! ListIndex null の per-item append」でチャンク書き込みする。本実装は
//! [`ListOp::ReplaceAll`](値 = 配列全体。自 fabric 行の置換)と
//! [`ListOp::AppendItem`](値 = エントリ 1 つ)の両方を受理する。
//! 書かれたエントリの fabricIndex フィールド(254)は無視し、アクセス元 fabric を強制する。

use core::cell::RefCell;

use crate::acl::{
    privilege_from_wire, privilege_to_wire, AclEntry, AclTable, AclTarget, AuthMode,
    ACL_ENTRIES_PER_FABRIC, MAX_ACL_SUBJECTS, MAX_ACL_TARGETS,
};
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, Privilege, Quality,
};
use crate::dm::{cluster::Dirty, map_write_err, AttrWrite, ListOp, ServerCluster};
use crate::im::wire::ImStatus;
use crate::tlv::{ContainerType, TlvReader, TlvValue};

/// Access Control クラスタの属性メタ。
static ACL_ATTRS: &[AttributeMeta] = &[
    // 0x0000 ACL(fabric-scoped list、read/write とも Administer)
    AttributeMeta::new(
        AttributeId(0x0000),
        Privilege::Administer,
        Quality::NONE,
        true,
        true,
        true,
    )
    .with_write_access(Privilege::Administer),
    // 0x0002 SubjectsPerAccessControlEntry
    AttributeMeta::new(
        AttributeId(0x0002),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
    // 0x0003 TargetsPerAccessControlEntry
    AttributeMeta::new(
        AttributeId(0x0003),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
    // 0x0004 AccessControlEntriesPerFabric
    AttributeMeta::new(
        AttributeId(0x0004),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
];

/// Access Control クラスタの静的メタデータ。
static ACL_META: ClusterMeta = ClusterMeta::new(ClusterId(0x001F), 1, 0, ACL_ATTRS, &[], &[]);

/// Access Control クラスタ(0x001F)。
///
/// `E` は共有 [`AclTable`] の容量。統合層が所有する `RefCell<AclTable<E>>` を参照する。
pub struct AccessControlCluster<'a, const E: usize> {
    acl: &'a RefCell<AclTable<E>>,
    dirty: Dirty,
}

impl<'a, const E: usize> AccessControlCluster<'a, E> {
    /// 共有 ACL テーブルを参照するクラスタを作る。
    pub const fn new(acl: &'a RefCell<AclTable<E>>) -> Self {
        Self {
            acl,
            dirty: Dirty::new(),
        }
    }

    /// 背後の ACL テーブルへの共有参照(検査・`DataModel::acl` の配線用)。
    pub const fn table(&self) -> &'a RefCell<AclTable<E>> {
        self.acl
    }

    /// ACL 属性(0x0000)を読む。
    fn read_acl(&self, e: &mut AttrEncoder<'_, '_>, acc: &AccessContext) -> Result<(), ImStatus> {
        let table = self.acl.borrow();
        e.write_array(|a| {
            for entry in table.iter() {
                // fabricFiltered read は自 fabric 行のみ。
                if acc.fabric_filtered && acc.fabric_idx != Some(entry.fabric_idx()) {
                    continue;
                }
                a.push_struct(|s| {
                    s.field_u8(1, privilege_to_wire(entry.privilege()))?;
                    s.field_u8(2, entry.auth_mode() as u8)?;
                    if entry.subjects().is_empty() {
                        s.field_null(3)?;
                    } else {
                        s.field_array(3, |sa| {
                            for &subj in entry.subjects() {
                                sa.push_u64(subj)?;
                            }
                            Ok(())
                        })?;
                    }
                    if entry.targets().is_empty() {
                        s.field_null(4)?;
                    } else {
                        s.field_array(4, |ta| {
                            for t in entry.targets() {
                                ta.push_struct(|ts| {
                                    match t.cluster {
                                        Some(c) => ts.field_u32(0, c)?,
                                        None => ts.field_null(0)?,
                                    }
                                    match t.endpoint {
                                        Some(ep) => ts.field_u16(1, ep)?,
                                        None => ts.field_null(1)?,
                                    }
                                    match t.device_type {
                                        Some(d) => ts.field_u32(2, d)?,
                                        None => ts.field_null(2)?,
                                    }
                                    Ok(())
                                })?;
                            }
                            Ok(())
                        })?;
                    }
                    s.field_u8(254, entry.fabric_idx().get())
                })?;
            }
            Ok(())
        })
    }

    /// ACL 属性(0x0000)を書く(ReplaceAll / AppendItem)。
    fn write_acl(&mut self, data: AttrWrite<'_>, acc: &AccessContext) -> Result<(), ImStatus> {
        // fabric-scoped write は確定 fabric が必須(PASE 未昇格は不可)。
        let Some(fabric) = acc.fabric_idx else {
            return Err(ImStatus::UnsupportedAccess);
        };

        match data.op {
            ListOp::AppendItem => {
                let mut r = data.reader();
                let head = r.read_next().map_err(|_| ImStatus::InvalidDataType)?;
                match head.map(|e| e.value) {
                    Some(TlvValue::ContainerStart(ContainerType::Structure)) => {}
                    _ => return Err(ImStatus::InvalidDataType),
                }
                let entry = decode_wire_entry(&mut r, fabric)?;
                self.acl.borrow_mut().add(entry).map_err(map_write_err)?;
            }
            ListOp::ReplaceAll => {
                let mut r = data.reader();
                let head = r.read_next().map_err(|_| ImStatus::InvalidDataType)?;
                match head.map(|e| e.value) {
                    Some(TlvValue::ContainerStart(ContainerType::Array)) => {}
                    _ => return Err(ImStatus::InvalidDataType),
                }
                // 全エントリを先に検証・収集してから置き換える(途中失敗で自 fabric の
                // エントリが半分消える事態を避ける)。
                let mut staged = [AclEntry::new(fabric, Privilege::View, AuthMode::Case);
                    ACL_ENTRIES_PER_FABRIC];
                let mut count = 0usize;
                loop {
                    let el = r
                        .read_next()
                        .map_err(|_| ImStatus::InvalidDataType)?
                        .ok_or(ImStatus::InvalidDataType)?;
                    match el.value {
                        TlvValue::ContainerEnd => break,
                        TlvValue::ContainerStart(ContainerType::Structure) => {
                            if count >= ACL_ENTRIES_PER_FABRIC {
                                return Err(ImStatus::ResourceExhausted);
                            }
                            staged[count] = decode_wire_entry(&mut r, fabric)?;
                            count += 1;
                        }
                        _ => return Err(ImStatus::InvalidDataType),
                    }
                }
                let mut table = self.acl.borrow_mut();
                table.clear_fabric(fabric);
                for entry in staged.iter().take(count) {
                    table.add(*entry).map_err(map_write_err)?;
                }
            }
        }
        self.dirty.mark();
        Ok(())
    }
}

/// ワイヤ表現(AccessControlEntryStruct)の 1 エントリを読む(構造体開始を消費済み)。
///
/// fabricIndex フィールド(254)は無視し、`fabric` を強制する。検証違反は
/// [`ImStatus::ConstraintError`]。
fn decode_wire_entry(
    r: &mut TlvReader<'_>,
    fabric: core::num::NonZeroU8,
) -> Result<AclEntry, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut privilege: Option<Privilege> = None;
    let mut auth: Option<AuthMode> = None;
    let mut subjects = [0u64; MAX_ACL_SUBJECTS];
    let mut nsubjects = 0usize;
    let mut targets = [AclTarget::default(); MAX_ACL_TARGETS];
    let mut ntargets = 0usize;
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidDataType)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (crate::tlv::TlvTag::ContextSpecific(1), v) => {
                let w = v.as_unsigned().map_err(bad)?;
                privilege =
                    privilege_from_wire(u8::try_from(w).map_err(|_| ImStatus::ConstraintError)?);
                if privilege.is_none() {
                    return Err(ImStatus::ConstraintError);
                }
            }
            (crate::tlv::TlvTag::ContextSpecific(2), v) => {
                let w = v.as_unsigned().map_err(bad)?;
                auth = AuthMode::from_u8(u8::try_from(w).map_err(|_| ImStatus::ConstraintError)?);
                if auth.is_none() {
                    return Err(ImStatus::ConstraintError);
                }
            }
            (crate::tlv::TlvTag::ContextSpecific(3), TlvValue::Null) => {}
            (
                crate::tlv::TlvTag::ContextSpecific(3),
                TlvValue::ContainerStart(ContainerType::Array),
            ) => loop {
                let el = r
                    .read_next()
                    .map_err(bad)?
                    .ok_or(ImStatus::InvalidDataType)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    v => {
                        if nsubjects >= MAX_ACL_SUBJECTS {
                            return Err(ImStatus::ConstraintError);
                        }
                        subjects[nsubjects] = v.as_unsigned().map_err(bad)?;
                        nsubjects += 1;
                    }
                }
            },
            (crate::tlv::TlvTag::ContextSpecific(4), TlvValue::Null) => {}
            (
                crate::tlv::TlvTag::ContextSpecific(4),
                TlvValue::ContainerStart(ContainerType::Array),
            ) => loop {
                let el = r
                    .read_next()
                    .map_err(bad)?
                    .ok_or(ImStatus::InvalidDataType)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    TlvValue::ContainerStart(ContainerType::Structure) => {
                        if ntargets >= MAX_ACL_TARGETS {
                            return Err(ImStatus::ConstraintError);
                        }
                        targets[ntargets] = decode_wire_target(r)?;
                        ntargets += 1;
                    }
                    _ => return Err(ImStatus::InvalidDataType),
                }
            },
            (_, v) => {
                // fabricIndex(254)や未知フィールドはスキップ。
                if matches!(v, TlvValue::ContainerStart(_)) {
                    skip_container(r)?;
                }
            }
        }
    }
    let mut entry = AclEntry::new(
        fabric,
        privilege.ok_or(ImStatus::ConstraintError)?,
        auth.ok_or(ImStatus::ConstraintError)?,
    );
    for &s in &subjects[..nsubjects] {
        entry.add_subject(s).map_err(map_write_err)?;
    }
    for t in &targets[..ntargets] {
        entry.add_target(*t).map_err(map_write_err)?;
    }
    Ok(entry)
}

/// ワイヤ表現の 1 target(AccessControlTargetStruct)を読む(構造体開始を消費済み)。
fn decode_wire_target(r: &mut TlvReader<'_>) -> Result<AclTarget, ImStatus> {
    let bad = |_| ImStatus::InvalidDataType;
    let mut t = AclTarget::default();
    loop {
        let e = r
            .read_next()
            .map_err(bad)?
            .ok_or(ImStatus::InvalidDataType)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (_, TlvValue::Null) => {}
            (crate::tlv::TlvTag::ContextSpecific(0), v) => {
                t.cluster = Some(
                    u32::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                )
            }
            (crate::tlv::TlvTag::ContextSpecific(1), v) => {
                t.endpoint = Some(
                    u16::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                )
            }
            (crate::tlv::TlvTag::ContextSpecific(2), v) => {
                t.device_type = Some(
                    u32::try_from(v.as_unsigned().map_err(bad)?)
                        .map_err(|_| ImStatus::ConstraintError)?,
                )
            }
            _ => {}
        }
    }
    if !t.is_valid() {
        return Err(ImStatus::ConstraintError);
    }
    Ok(t)
}

/// 現在のコンテナの残りを終端まで読み飛ばす(開始要素を消費済みの状態から)。
fn skip_container(r: &mut TlvReader<'_>) -> Result<(), ImStatus> {
    let mut depth = 1usize;
    loop {
        let e = r
            .read_next()
            .map_err(|_| ImStatus::InvalidDataType)?
            .ok_or(ImStatus::InvalidDataType)?;
        match e.value {
            TlvValue::ContainerStart(_) => depth += 1,
            TlvValue::ContainerEnd => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
}

impl<const E: usize> ServerCluster for AccessControlCluster<'_, E> {
    fn meta(&self) -> &'static ClusterMeta {
        &ACL_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => self.read_acl(enc, acc),
            0x0002 => enc.write_u16(MAX_ACL_SUBJECTS as u16),
            0x0003 => enc.write_u16(MAX_ACL_TARGETS as u16),
            0x0004 => enc.write_u16(ACL_ENTRIES_PER_FABRIC as u16),
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
            0x0000 => self.write_acl(data, acc),
            _ => Err(ImStatus::UnsupportedWrite),
        }
    }

    fn take_dirty(&mut self) -> bool {
        self.dirty.take()
    }
}

#[cfg(test)]
mod tests;
