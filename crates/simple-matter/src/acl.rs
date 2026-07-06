//! ACL(Access Control List)のデータモデルと権限評価(`docs/design/acl.md`)。
//!
//! Matter Core Spec §6.6(Access Control)/ §9.10(Access Control Cluster)の
//! fabric-scoped エントリテーブル [`AclTable`] と、IM エンジンが read/write/invoke の
//! 権限判定に使う object-safe trait [`AclHandle`] を提供する。
//!
//! # 設計判断
//!
//! - **固定容量・no-alloc**: エントリは const generic `E` の [`FixedVec`] に持ち、
//!   加えて仕様の per-fabric 上限 [`ACL_ENTRIES_PER_FABRIC`] を `add` で強制する。
//! - **共有は `RefCell`**: [`crate::fabric::FabricTable`] と同じ流儀で、統合層が所有する
//!   `RefCell<AclTable<E>>` を AccessControl クラスタと IM エンジン(`DataModel::acl`)が
//!   共有参照する。[`AclHandle`] は `RefCell<AclTable<E>>` に実装する(内部可変性)。
//! - **PASE = implicit Administer**: 仕様 §6.6.2.9(chip の implicit PASE entry)どおり、
//!   PASE セッションは ACL エントリなしで全 target に Administer を持つ。
//!   旧実装(`docs/design/interaction-model.md` §10 の「コミッショニングクラスタ限定」)
//!   より緩いが仕様準拠方向。
//! - **永続化**: [`AclTable::save_to`] / [`AclTable::load_from`](キー `b"aclt"`、単一
//!   versioned TLV レコード)。呼び出しタイミングは fabric と同じく統合層が
//!   [`AclTable::generation`] の変化で決める(sans-IO)。

use core::cell::RefCell;
use core::num::NonZeroU8;

use crate::dm::meta::{AccessContext, ClusterId, EndpointId, Privilege, SessionKind};
use crate::error::{Error, Result};
use crate::kvs::Kvs;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::fixed::FixedVec;

/// 1 エントリの subject 最大数(SubjectsPerAccessControlEntry、仕様最小値)。
pub const MAX_ACL_SUBJECTS: usize = 4;

/// 1 エントリの target 最大数(TargetsPerAccessControlEntry、仕様最小値)。
pub const MAX_ACL_TARGETS: usize = 3;

/// fabric あたりのエントリ上限(AccessControlEntriesPerFabric、仕様最小値)。
pub const ACL_ENTRIES_PER_FABRIC: usize = 4;

/// NodeId 上の CAT(CASE Authenticated Tag)領域の上位 32 ビット(§2.5.5.1)。
const CAT_PREFIX: u64 = 0xFFFF_FFFD;

/// 認証モード(AccessControlEntryAuthModeEnum、§9.10.4.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMode {
    /// PASE(implicit 専用。エントリとしては受理しない)。
    Pase = 1,
    /// CASE。
    Case = 2,
    /// Group(グループメッセージング。本実装では格納のみ)。
    Group = 3,
}

impl AuthMode {
    /// ワイヤ値から変換する。未知値は `None`。
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Pase),
            2 => Some(Self::Case),
            3 => Some(Self::Group),
            _ => None,
        }
    }
}

/// privilege のワイヤ値(AccessControlEntryPrivilegeEnum、§9.10.4.4)。
///
/// [`Privilege`] の宣言順(比較用)とワイヤ値は異なるため明示的に写像する。
/// ProxyView(2)は未対応(`None`)。
pub const fn privilege_from_wire(v: u8) -> Option<Privilege> {
    match v {
        1 => Some(Privilege::View),
        3 => Some(Privilege::Operate),
        4 => Some(Privilege::Manage),
        5 => Some(Privilege::Administer),
        _ => None,
    }
}

/// [`Privilege`] をワイヤ値へ写像する。
pub const fn privilege_to_wire(p: Privilege) -> u8 {
    match p {
        Privilege::View => 1,
        Privilege::Operate => 3,
        Privilege::Manage => 4,
        Privilege::Administer => 5,
    }
}

/// ACL エントリの 1 target(AccessControlTargetStruct、§9.10.4.5)。
///
/// 少なくとも 1 フィールドが `Some` で、`endpoint` と `device_type` は排他。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AclTarget {
    /// 対象クラスタ(`None` = 全クラスタ)。
    pub cluster: Option<u32>,
    /// 対象エンドポイント(`None` = 全エンドポイント)。
    pub endpoint: Option<u16>,
    /// 対象デバイスタイプ(受理・保存のみ。判定ではマッチしない、`docs/design/acl.md` §1)。
    pub device_type: Option<u32>,
}

impl AclTarget {
    /// 制約(§9.10.4.5)を満たすかを返す。
    pub const fn is_valid(&self) -> bool {
        let any = self.cluster.is_some() || self.endpoint.is_some() || self.device_type.is_some();
        let exclusive = !(self.endpoint.is_some() && self.device_type.is_some());
        any && exclusive
    }

    /// 具象 (endpoint, cluster) がこの target にマッチするかを返す。
    ///
    /// `device_type` 指定の target はマッチしない(未対応の割り切り)。
    fn matches(&self, ep: EndpointId, cl: ClusterId) -> bool {
        if self.device_type.is_some() {
            return false;
        }
        let cl_ok = match self.cluster {
            Some(c) => c == cl.0,
            None => true,
        };
        let ep_ok = match self.endpoint {
            Some(e) => e == ep.0,
            None => true,
        };
        cl_ok && ep_ok
    }
}

/// 1 つの ACL エントリ(AccessControlEntryStruct、fabric-scoped)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    fabric_idx: NonZeroU8,
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: [u64; MAX_ACL_SUBJECTS],
    nsubjects: u8,
    targets: [AclTarget; MAX_ACL_TARGETS],
    ntargets: u8,
}

impl AclEntry {
    /// subjects/targets 空(= 全 subject / 全 target)のエントリを作る。
    pub const fn new(fabric_idx: NonZeroU8, privilege: Privilege, auth_mode: AuthMode) -> Self {
        Self {
            fabric_idx,
            privilege,
            auth_mode,
            subjects: [0; MAX_ACL_SUBJECTS],
            nsubjects: 0,
            targets: [AclTarget {
                cluster: None,
                endpoint: None,
                device_type: None,
            }; MAX_ACL_TARGETS],
            ntargets: 0,
        }
    }

    /// AddNOC の bootstrap admin エントリ(Administer / CASE / subjects=[subject])を作る
    /// (§11.17.6.8)。
    pub fn case_admin(fabric_idx: NonZeroU8, subject: u64) -> Self {
        let mut e = Self::new(fabric_idx, Privilege::Administer, AuthMode::Case);
        // MAX_ACL_SUBJECTS >= 1 のため必ず成功する。
        let _ = e.add_subject(subject);
        e
    }

    /// 所属 fabric。
    pub const fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    /// 付与する権限。
    pub const fn privilege(&self) -> Privilege {
        self.privilege
    }

    /// 認証モード。
    pub const fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    /// subject 一覧(空 = 全 subject)。
    pub fn subjects(&self) -> &[u64] {
        &self.subjects[..self.nsubjects as usize]
    }

    /// target 一覧(空 = 全 target)。
    pub fn targets(&self) -> &[AclTarget] {
        &self.targets[..self.ntargets as usize]
    }

    /// subject を追加する。満杯は [`Error::NoSpace`]。
    pub fn add_subject(&mut self, subject: u64) -> Result<()> {
        if (self.nsubjects as usize) >= MAX_ACL_SUBJECTS {
            return Err(Error::NoSpace);
        }
        self.subjects[self.nsubjects as usize] = subject;
        self.nsubjects += 1;
        Ok(())
    }

    /// target を追加する。満杯は [`Error::NoSpace`]、制約違反は [`Error::Decode`]。
    pub fn add_target(&mut self, target: AclTarget) -> Result<()> {
        if !target.is_valid() {
            return Err(Error::Decode);
        }
        if (self.ntargets as usize) >= MAX_ACL_TARGETS {
            return Err(Error::NoSpace);
        }
        self.targets[self.ntargets as usize] = target;
        self.ntargets += 1;
        Ok(())
    }

    /// エントリ全体の制約(§9.10.5.3)を満たすかを返す。
    ///
    /// - `auth_mode == Pase` のエントリは不可(implicit 専用)。
    /// - Administer は CASE のみに付与できる(Group への付与禁止)。
    pub fn is_valid(&self) -> bool {
        if matches!(self.auth_mode, AuthMode::Pase) {
            return false;
        }
        if matches!(self.privilege, Privilege::Administer)
            && !matches!(self.auth_mode, AuthMode::Case)
        {
            return false;
        }
        self.targets().iter().all(AclTarget::is_valid)
    }

    /// アクセス元 `acc` の subject(NodeId / CAT)がこのエントリにマッチするかを返す。
    fn subject_matches(&self, acc: &AccessContext) -> bool {
        if self.nsubjects == 0 {
            return true;
        }
        for &s in self.subjects() {
            if s == acc.subject {
                return true;
            }
            // CAT subject: 上位 32bit が 0xFFFF_FFFD。下位 32bit = identifier(16) | version(16)。
            // セッション CAT の identifier 一致かつ version >= エントリの version で一致(§6.6.2.5)。
            if (s >> 32) == CAT_PREFIX {
                let want = (s & 0xFFFF_FFFF) as u32;
                let want_id = want >> 16;
                let want_ver = want & 0xFFFF;
                if want_ver == 0 {
                    // version 0 の CAT は不正(マッチしない)。
                    continue;
                }
                for &have in &acc.cats[..acc.cat_count as usize] {
                    if (have >> 16) == want_id && (have & 0xFFFF) >= want_ver {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// 具象 (endpoint, cluster) がこのエントリの target にマッチするかを返す。
    fn target_matches(&self, ep: EndpointId, cl: ClusterId) -> bool {
        if self.ntargets == 0 {
            return true;
        }
        self.targets().iter().any(|t| t.matches(ep, cl))
    }
}

/// `granted` が `required` を満たすかを返す(View < Operate < Manage < Administer)。
const fn privilege_grants(granted: Privilege, required: Privilege) -> bool {
    (granted as u8) >= (required as u8)
}

/// 固定容量 `E` の ACL テーブル。
pub struct AclTable<const E: usize> {
    entries: FixedVec<AclEntry, E>,
    generation: u32,
}

impl<const E: usize> Default for AclTable<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const E: usize> AclTable<E> {
    /// 空のテーブルを作る。
    pub const fn new() -> Self {
        Self {
            entries: FixedVec::new(),
            generation: 0,
        }
    }

    /// 現在のエントリ数(全 fabric 合計)。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// エントリが 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// テーブル容量(`E`)。
    pub const fn capacity(&self) -> usize {
        E
    }

    /// 変更世代番号(永続化フック。add / remove 系で増加する)。
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// 全エントリを走査する。
    pub fn iter(&self) -> impl Iterator<Item = &AclEntry> {
        self.entries.iter()
    }

    /// `fabric` のエントリのみ走査する。
    pub fn iter_fabric(&self, fabric: NonZeroU8) -> impl Iterator<Item = &AclEntry> {
        self.entries.iter().filter(move |e| e.fabric_idx == fabric)
    }

    /// `fabric` のエントリ数。
    pub fn fabric_len(&self, fabric: NonZeroU8) -> usize {
        self.iter_fabric(fabric).count()
    }

    /// エントリを追加する。
    ///
    /// 検証違反は [`Error::Decode`]、テーブル満杯・per-fabric 上限
    /// ([`ACL_ENTRIES_PER_FABRIC`])超過は [`Error::NoSpace`]。
    pub fn add(&mut self, entry: AclEntry) -> Result<()> {
        if !entry.is_valid() {
            return Err(Error::Decode);
        }
        if self.fabric_len(entry.fabric_idx) >= ACL_ENTRIES_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        self.entries.push(entry).map_err(|_| Error::NoSpace)?;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// `fabric` のエントリを全て削除し、削除数を返す(write ReplaceAll / fabric 削除連動)。
    pub fn clear_fabric(&mut self, fabric: NonZeroU8) -> usize {
        let mut removed = 0;
        loop {
            let Some(i) = self.entries.iter().position(|e| e.fabric_idx == fabric) else {
                break;
            };
            // 挿入順を保つため swap_remove ではなく前詰めで消す(read の順序保証)。
            self.remove_at(i);
            removed += 1;
        }
        if removed > 0 {
            self.generation = self.generation.wrapping_add(1);
        }
        removed
    }

    /// index 位置のエントリを順序を保って取り除く(左詰めして末尾を落とす)。
    fn remove_at(&mut self, index: usize) {
        let len = self.entries.len();
        if index >= len {
            return;
        }
        for i in index..len - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        let _ = self.entries.swap_remove(len - 1);
    }

    /// アクセス `acc` が (endpoint, cluster) に `required` 権限を持つかを判定する
    /// (`docs/design/acl.md` §3)。
    pub fn check(
        &self,
        acc: &AccessContext,
        ep: EndpointId,
        cl: ClusterId,
        required: Privilege,
    ) -> bool {
        match acc.kind {
            // PASE = implicit Administer(全 target、§6.6.2.9)。
            SessionKind::Pase => true,
            SessionKind::Case => {
                let Some(fabric) = acc.fabric_idx else {
                    return false;
                };
                self.iter_fabric(fabric).any(|e| {
                    matches!(e.auth_mode, AuthMode::Case)
                        && privilege_grants(e.privilege, required)
                        && e.subject_matches(acc)
                        && e.target_matches(ep, cl)
                })
            }
        }
    }
}

// ==========================================================================
// AclHandle(IM エンジン / OpCreds 連動の object-safe 境界)
// ==========================================================================

/// IM エンジンが `DataModel::acl` 越しに使う ACL 操作の object-safe 境界。
///
/// [`RefCell<AclTable<E>>`] に実装する(内部可変性で `&self` から書ける)。統合層は
/// fabric テーブルと同様に `RefCell` を所有し、AccessControl クラスタと `DataModel::acl`
/// の両方へ共有参照を渡す。
pub trait AclHandle {
    /// アクセス `acc` が (endpoint, cluster) に `required` 権限を持つか。
    fn check(
        &self,
        acc: &AccessContext,
        ep: EndpointId,
        cl: ClusterId,
        required: Privilege,
    ) -> bool;

    /// AddNOC 成功時の bootstrap admin エントリを追加する(§11.17.6.8)。
    fn add_case_admin(&self, fabric: NonZeroU8, subject: u64) -> Result<()>;

    /// fabric 削除に連動して当該 fabric のエントリを全て消す。
    fn remove_fabric(&self, fabric: NonZeroU8);
}

impl<const E: usize> AclHandle for RefCell<AclTable<E>> {
    fn check(
        &self,
        acc: &AccessContext,
        ep: EndpointId,
        cl: ClusterId,
        required: Privilege,
    ) -> bool {
        self.borrow().check(acc, ep, cl, required)
    }

    fn add_case_admin(&self, fabric: NonZeroU8, subject: u64) -> Result<()> {
        self.borrow_mut().add(AclEntry::case_admin(fabric, subject))
    }

    fn remove_fabric(&self, fabric: NonZeroU8) {
        self.borrow_mut().clear_fabric(fabric);
    }
}

// ==========================================================================
// KVS 永続化(fabric と同じ分業、docs/design/acl.md §6)
// ==========================================================================

/// 永続化フォーマットの schema version。
pub const ACL_SCHEMA_VERSION: u8 = 1;

/// ACL レコードのキー。
const ACL_KEY: &[u8] = b"aclt";

/// ACL レコードの TLV エンコード上限(バイト)。
///
/// 1 エントリ最大 ≈ subjects 4×(タグ+8B) + targets 3×struct ≈ 110B。上限 20 エントリ +
/// 外枠に余裕を持たせた値。
pub const MAX_ACL_RECORD_LEN: usize = 2400;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

impl<const E: usize> AclTable<E> {
    /// テーブル全体を `kvs` のキー `b"aclt"` へ保存する。
    ///
    /// 呼び出しタイミングは統合層の責務([`AclTable::generation`] の変化検知)。
    pub fn save_to<K: Kvs>(&self, kvs: &mut K) -> Result<()> {
        let mut buf = [0u8; MAX_ACL_RECORD_LEN];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), ACL_SCHEMA_VERSION)?;
            w.start_array(&cx(1))?;
            for e in self.entries.iter() {
                encode_entry(&mut w, e)?;
            }
            w.end_container()?;
            w.end_container()?;
            w.len()
        };
        kvs.set(ACL_KEY, &buf[..len])
    }

    /// `kvs` からテーブルを復元し、復元したエントリ数を返す。
    ///
    /// - 空テーブルにのみ呼べる(非空は [`Error::InvalidState`])。
    /// - レコードが無ければ初回起動として `Ok(0)`。
    /// - schema 不一致・レコード破損・エントリ検証違反は [`Error`] で中断する。
    pub fn load_from<K: Kvs>(&mut self, kvs: &mut K) -> Result<usize> {
        if !self.entries.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut buf = [0u8; MAX_ACL_RECORD_LEN];
        let len = match kvs.get(ACL_KEY, &mut buf)? {
            Some(l) => l,
            None => return Ok(0),
        };
        let mut r = TlvReader::new(&buf[..len]);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut version: Option<u8> = None;
        let mut restored = 0usize;
        loop {
            let e = r.read_next()?.ok_or(Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => {
                    version = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                    if version != Some(ACL_SCHEMA_VERSION) {
                        return Err(Error::Decode);
                    }
                }
                (TlvTag::ContextSpecific(1), TlvValue::ContainerStart(ContainerType::Array)) => {
                    loop {
                        let el = r.read_next()?.ok_or(Error::Decode)?;
                        match el.value {
                            TlvValue::ContainerEnd => break,
                            TlvValue::ContainerStart(ContainerType::Structure) => {
                                let entry = decode_entry(&mut r)?;
                                // add() は per-fabric 上限と検証を適用する。
                                self.add(entry)?;
                                restored += 1;
                            }
                            _ => return Err(Error::Decode),
                        }
                    }
                }
                _ => r.skip(&e)?,
            }
        }
        if version.is_none() {
            return Err(Error::Decode);
        }
        Ok(restored)
    }

    /// fabric テーブルに存在しない fabric のエントリを落とす(復元後の整合、
    /// `docs/design/acl.md` §6)。`exists(fabric)` が `false` のエントリを削除する。
    pub fn retain_fabrics(&mut self, mut exists: impl FnMut(NonZeroU8) -> bool) {
        let mut i = 0;
        let mut removed = false;
        while i < self.entries.len() {
            if exists(self.entries[i].fabric_idx) {
                i += 1;
            } else {
                self.remove_at(i);
                removed = true;
            }
        }
        if removed {
            self.generation = self.generation.wrapping_add(1);
        }
    }
}

/// 1 エントリを永続化レコードへ書く(`docs/design/acl.md` §6 のレイアウト)。
fn encode_entry(w: &mut TlvWriter<'_>, e: &AclEntry) -> Result<()> {
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_u8(&cx(1), e.fabric_idx.get())?;
    w.write_u8(&cx(2), privilege_to_wire(e.privilege))?;
    w.write_u8(&cx(3), e.auth_mode as u8)?;
    w.start_array(&cx(4))?;
    for &s in e.subjects() {
        w.write_u64(&TlvTag::Anonymous, s)?;
    }
    w.end_container()?;
    w.start_array(&cx(5))?;
    for t in e.targets() {
        w.start_struct(&TlvTag::Anonymous)?;
        if let Some(c) = t.cluster {
            w.write_u32(&cx(0), c)?;
        }
        if let Some(ep) = t.endpoint {
            w.write_u16(&cx(1), ep)?;
        }
        if let Some(d) = t.device_type {
            w.write_u32(&cx(2), d)?;
        }
        w.end_container()?;
    }
    w.end_container()?;
    w.end_container()
}

/// 永続化レコードの 1 エントリを読む(構造体開始を消費済みの状態から)。
fn decode_entry(r: &mut TlvReader<'_>) -> Result<AclEntry> {
    let mut fabric: Option<u8> = None;
    let mut privilege: Option<Privilege> = None;
    let mut auth: Option<AuthMode> = None;
    let mut subjects = [0u64; MAX_ACL_SUBJECTS];
    let mut nsubjects = 0usize;
    let mut targets = [AclTarget::default(); MAX_ACL_TARGETS];
    let mut ntargets = 0usize;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => {
                fabric = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(2), v) => {
                privilege =
                    privilege_from_wire(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                if privilege.is_none() {
                    return Err(Error::Decode);
                }
            }
            (TlvTag::ContextSpecific(3), v) => {
                auth = AuthMode::from_u8(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                if auth.is_none() {
                    return Err(Error::Decode);
                }
            }
            (TlvTag::ContextSpecific(4), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let el = r.read_next()?.ok_or(Error::Decode)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    v => {
                        if nsubjects >= MAX_ACL_SUBJECTS {
                            return Err(Error::Decode);
                        }
                        subjects[nsubjects] = v.as_unsigned()?;
                        nsubjects += 1;
                    }
                }
            },
            (TlvTag::ContextSpecific(5), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let el = r.read_next()?.ok_or(Error::Decode)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    TlvValue::ContainerStart(ContainerType::Structure) => {
                        if ntargets >= MAX_ACL_TARGETS {
                            return Err(Error::Decode);
                        }
                        targets[ntargets] = decode_target(r)?;
                        ntargets += 1;
                    }
                    _ => return Err(Error::Decode),
                }
            },
            _ => r.skip(&e)?,
        }
    }
    let fabric = NonZeroU8::new(fabric.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    let mut entry = AclEntry::new(
        fabric,
        privilege.ok_or(Error::Decode)?,
        auth.ok_or(Error::Decode)?,
    );
    for &s in &subjects[..nsubjects] {
        entry.add_subject(s)?;
    }
    for t in &targets[..ntargets] {
        entry.add_target(*t)?;
    }
    Ok(entry)
}

/// 永続化レコードの 1 target を読む(構造体開始を消費済みの状態から)。
fn decode_target(r: &mut TlvReader<'_>) -> Result<AclTarget> {
    let mut t = AclTarget::default();
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => {
                t.cluster = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(1), v) => {
                t.endpoint = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(2), v) => {
                t.device_type = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            _ => r.skip(&e)?,
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests;
