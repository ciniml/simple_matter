//! ICD Management クラスタ(0x0046、Matter 1.3 §9.16 / `docs/design/icd.md`)。
//!
//! **SIT(Short Idle Time)最小構成**(フェーズ I1a)。SIT ICD に必須の 3 属性
//! (IdleModeDuration / ActiveModeDuration / ActiveModeThreshold)だけを read-only で公開し、
//! FeatureMap=0(CIP / UAT / LITS いずれも無効)。RegisterClient / UnregisterClient /
//! StayActiveRequest と CheckInProtocol・RegisteredClients・ICDCounter は LIT フェーズ
//! (I1c)へ切り出す(受理コマンドを持たないので IM エンジンが UnsupportedCommand を返す)。
//!
//! 属性は全て FIXED(不変)。値は [`IcdConfig`](crate::icd::IcdConfig) をそのまま反映する。
//! active/idle の状態機械は [`IcdState`](crate::icd::IcdState) がコア側に持つ(本クラスタは
//! 広告メタデータの公開のみ、sans-IO)。

use crate::cluster;
use crate::dm::codec::AttrEncoder;
use crate::icd::IcdConfig;

/// ICD Management クラスタ(0x0046、SIT 最小)。
#[derive(Debug, Clone, Copy)]
pub struct IcdManagementCluster {
    cfg: IcdConfig,
}

impl IcdManagementCluster {
    /// SIT デフォルト([`IcdConfig::sit_default`])で作る。
    pub const fn new() -> Self {
        Self {
            cfg: IcdConfig::sit_default(),
        }
    }

    /// 明示的な [`IcdConfig`] で作る。
    pub const fn with_config(cfg: IcdConfig) -> Self {
        Self { cfg }
    }

    /// 公開している ICD パラメータを返す(アプリが SII/SAI 導出等に使う)。
    pub const fn config(&self) -> &IcdConfig {
        &self.cfg
    }
}

impl Default for IcdManagementCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    IcdManagementCluster {
        id: 0x0046,
        revision: 3,
        feature_map: 0,
        dirty: _,
        invoke: _,
        attributes: [
            0x0000 IdleModeDuration {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &IcdManagementCluster, e: &mut AttrEncoder<'_, '_>| e.write_u32(c.cfg.idle_mode_duration_s)),
                write: _
            },
            0x0001 ActiveModeDuration {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &IcdManagementCluster, e: &mut AttrEncoder<'_, '_>| e.write_u32(c.cfg.active_mode_duration_ms)),
                write: _
            },
            0x0002 ActiveModeThreshold {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &IcdManagementCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.cfg.active_mode_threshold_ms)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}

// ==========================================================================
// CIP / LITS 対応クラスタ(フェーズ I1c)
// ==========================================================================

use core::cell::RefCell;

use crate::dm::clusters::cmd::{close_response, map_tlv, open_response, Fields};
use crate::dm::codec::CmdResponder;
use crate::dm::map_write_err;
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use crate::dm::{AttrWrite, ServerCluster};
use crate::icd::{
    feature, IcdRegistration, IcdRegistrationTable, IcdState, OperatingMode, ICD_CLIENTS_PER_FABRIC,
};
use crate::im::wire::ImStatus;
use crate::tlv::{TlvReader, TlvTag};

/// CIP(CheckInProtocolSupport)対応クラスタの共通属性メタ(0x0000..=0x0005)。
static ICD_CIP_ATTRS: &[AttributeMeta] = &[
    AttributeMeta::new(AttributeId(0x0000), Privilege::View, Quality::FIXED, true, false, false),
    AttributeMeta::new(AttributeId(0x0001), Privilege::View, Quality::FIXED, true, false, false),
    AttributeMeta::new(AttributeId(0x0002), Privilege::View, Quality::FIXED, true, false, false),
    // RegisteredClients: fabric-scoped list、read のみ(管理はコマンド経由)。
    AttributeMeta::new(AttributeId(0x0003), Privilege::Administer, Quality::NONE, true, false, false),
    // ICDCounter。
    AttributeMeta::new(AttributeId(0x0004), Privilege::Administer, Quality::NONE, true, false, false),
    // ClientsSupportedPerFabric。
    AttributeMeta::new(AttributeId(0x0005), Privilege::View, Quality::FIXED, true, false, false),
];

/// LITS(LongIdleTimeSupport)対応クラスタの属性メタ(CIP + OperatingMode 0x0008)。
static ICD_LIT_ATTRS: &[AttributeMeta] = &[
    AttributeMeta::new(AttributeId(0x0000), Privilege::View, Quality::FIXED, true, false, false),
    AttributeMeta::new(AttributeId(0x0001), Privilege::View, Quality::FIXED, true, false, false),
    AttributeMeta::new(AttributeId(0x0002), Privilege::View, Quality::FIXED, true, false, false),
    AttributeMeta::new(AttributeId(0x0003), Privilege::Administer, Quality::NONE, true, false, false),
    AttributeMeta::new(AttributeId(0x0004), Privilege::Administer, Quality::NONE, true, false, false),
    AttributeMeta::new(AttributeId(0x0005), Privilege::View, Quality::FIXED, true, false, false),
    // OperatingMode(SIT=0/LIT=1)。
    AttributeMeta::new(AttributeId(0x0008), Privilege::View, Quality::FIXED, true, false, false),
];

/// 受理コマンド(RegisterClient / UnregisterClient / StayActiveRequest、いずれも Manage)。
static ICD_CMDS: &[CommandMeta] = &[
    CommandMeta::new(CommandId(0x00), true, Privilege::Manage),
    CommandMeta::new(CommandId(0x02), false, Privilege::Manage),
    CommandMeta::new(CommandId(0x03), true, Privilege::Manage),
];
/// 生成コマンド(RegisterClientResponse / StayActiveResponse)。
static ICD_GEN: &[CommandId] = &[CommandId(0x01), CommandId(0x04)];

/// CIP のみ(SIT ICD + check-in)の静的メタ。
static ICD_CIP_META: ClusterMeta =
    ClusterMeta::new(ClusterId(0x0046), 3, feature::CIP, ICD_CIP_ATTRS, ICD_CMDS, ICD_GEN);
/// CIP + LITS(LIT ICD)の静的メタ。
static ICD_LIT_META: ClusterMeta = ClusterMeta::new(
    ClusterId(0x0046),
    3,
    feature::CIP | feature::LITS,
    ICD_LIT_ATTRS,
    ICD_CMDS,
    ICD_GEN,
);

/// CIP / LITS 対応 ICD Management クラスタ(0x0046、フェーズ I1c)。
///
/// SIT 最小の [`IcdManagementCluster`] と異なり、登録クライアントテーブル
/// ([`IcdRegistrationTable`])を共有参照し、RegisterClient / UnregisterClient /
/// StayActiveRequest と RegisteredClients / ICDCounter を実装する。テーブルは統合層が
/// `RefCell` で所有し、RemoveFabric 連動削除のため IM エンジンも
/// [`IcdRegistryHandle`](crate::icd::IcdRegistryHandle) 越しに共有する(ACL の流儀)。
/// StayActiveRequest は共有 [`IcdState`] の active 窓を延長する。
pub struct IcdManagementCipCluster<'a, const N: usize> {
    cfg: IcdConfig,
    table: &'a RefCell<IcdRegistrationTable<N>>,
    icd_state: &'a RefCell<IcdState>,
    meta: &'static ClusterMeta,
    operating_mode: OperatingMode,
}

impl<'a, const N: usize> IcdManagementCipCluster<'a, N> {
    /// 共有テーブル / IcdState と設定からクラスタを作る。
    ///
    /// `lit == true` で LITS feature(OperatingMode=LIT)、`false` で CIP のみ(SIT)。
    pub fn new(
        cfg: IcdConfig,
        table: &'a RefCell<IcdRegistrationTable<N>>,
        icd_state: &'a RefCell<IcdState>,
        lit: bool,
    ) -> Self {
        Self {
            cfg,
            table,
            icd_state,
            meta: if lit { &ICD_LIT_META } else { &ICD_CIP_META },
            operating_mode: if lit {
                OperatingMode::Lit
            } else {
                OperatingMode::Sit
            },
        }
    }

    /// 背後の登録テーブル(`DataModel::icd_registry` の配線 / 検査用)。
    pub const fn table(&self) -> &'a RefCell<IcdRegistrationTable<N>> {
        self.table
    }

    /// RegisteredClients(0x0003)を fabric フィルタ付きで読む。
    fn read_registered(
        &self,
        e: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let table = self.table.borrow();
        e.write_array(|a| {
            for r in table.iter() {
                if acc.fabric_filtered && acc.fabric_idx != Some(r.fabric_idx()) {
                    continue;
                }
                a.push_struct(|s| {
                    // MonitoringRegistrationStruct: CheckInNodeID(1) / MonitoredSubject(2) /
                    // FabricIndex(254)。Key は読み出し不可(write-only)。
                    s.field_u64(1, r.check_in_node_id())?;
                    s.field_u64(2, r.monitored_subject())?;
                    s.field_u8(254, r.fabric_idx().get())
                })?;
            }
            Ok(())
        })
    }

    /// RegisterClient(0x00)→ RegisterClientResponse(0x01、ICDCounter)。
    fn register_client(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let Some(fabric) = acc.fabric_idx else {
            return Err(ImStatus::UnsupportedAccess);
        };
        let mut check_in: Option<u64> = None;
        let mut subject: Option<u64> = None;
        let mut key: Option<[u8; 16]> = None;
        let mut verification: Option<[u8; 16]> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => check_in = Some(v.as_unsigned().map_err(|_| ImStatus::InvalidDataType)?),
                1 => subject = Some(v.as_unsigned().map_err(|_| ImStatus::InvalidDataType)?),
                2 => key = Some(bytes16(&v)?),
                3 => verification = Some(bytes16(&v)?),
                _ => {}
            }
        }
        let check_in = check_in.ok_or(ImStatus::InvalidCommand)?;
        let subject = subject.ok_or(ImStatus::InvalidCommand)?;
        let key = key.ok_or(ImStatus::InvalidCommand)?;
        let is_admin = matches!(acc.privilege, Privilege::Administer);

        let counter = {
            let mut table = self.table.borrow_mut();
            // 既存エントリの更新は、非 admin なら verificationKey 一致が必須(§9.16.7.1)。
            if let Some(existing) = table.key_of(fabric, check_in) {
                if !is_admin {
                    let vk = verification.ok_or(ImStatus::Failure)?;
                    if vk != existing {
                        return Err(ImStatus::Failure);
                    }
                }
            }
            table
                .register(IcdRegistration::new(fabric, check_in, subject, key))
                .map_err(map_write_err)?;
            table.icd_counter()
        };

        let w = open_response(resp, 0x01)?;
        w.write_u32(&TlvTag::ContextSpecific(0), counter)
            .map_err(map_tlv)?;
        close_response(w)
    }

    /// UnregisterClient(0x02)。status のみ。
    fn unregister_client(
        &mut self,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let Some(fabric) = acc.fabric_idx else {
            return Err(ImStatus::UnsupportedAccess);
        };
        let mut check_in: Option<u64> = None;
        let mut verification: Option<[u8; 16]> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => check_in = Some(v.as_unsigned().map_err(|_| ImStatus::InvalidDataType)?),
                1 => verification = Some(bytes16(&v)?),
                _ => {}
            }
        }
        let check_in = check_in.ok_or(ImStatus::InvalidCommand)?;
        let is_admin = matches!(acc.privilege, Privilege::Administer);
        let mut table = self.table.borrow_mut();
        let Some(existing) = table.key_of(fabric, check_in) else {
            return Err(ImStatus::NotFound);
        };
        if !is_admin {
            let vk = verification.ok_or(ImStatus::Failure)?;
            if vk != existing {
                return Err(ImStatus::Failure);
            }
        }
        table.unregister(fabric, check_in).map_err(map_write_err)
    }

    /// StayActiveRequest(0x03)→ StayActiveResponse(0x04、promisedActiveDuration)。
    fn stay_active(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut requested: u32 = 0;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                requested = v.as_unsigned().unwrap_or(0) as u32;
            }
        }
        let promised = self.icd_state.borrow_mut().stay_active(acc.now_ms, requested);
        let w = open_response(resp, 0x04)?;
        w.write_u32(&TlvTag::ContextSpecific(0), promised)
            .map_err(map_tlv)?;
        close_response(w)
    }
}

/// フィールド値を 16 バイト固定長 octstr として取り出す(長さ違反は ConstraintError)。
fn bytes16(v: &crate::tlv::TlvValue<'_>) -> Result<[u8; 16], ImStatus> {
    let b = v.as_bytes().map_err(|_| ImStatus::InvalidDataType)?;
    if b.len() != 16 {
        return Err(ImStatus::ConstraintError);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(b);
    Ok(out)
}

impl<const N: usize> ServerCluster for IcdManagementCipCluster<'_, N> {
    fn meta(&self) -> &'static ClusterMeta {
        self.meta
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => enc.write_u32(self.cfg.idle_mode_duration_s),
            0x0001 => enc.write_u32(self.cfg.active_mode_duration_ms),
            0x0002 => enc.write_u16(self.cfg.active_mode_threshold_ms),
            0x0003 => self.read_registered(enc, acc),
            0x0004 => enc.write_u32(self.table.borrow().icd_counter()),
            0x0005 => enc.write_u16(ICD_CLIENTS_PER_FABRIC as u16),
            0x0008 if matches!(self.operating_mode, OperatingMode::Lit)
                || self.meta.feature_map & feature::LITS != 0 =>
            {
                enc.write_u8(self.operating_mode as u8)
            }
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
            0x00 => self.register_client(fields, resp, acc),
            0x02 => self.unregister_client(fields, acc),
            0x03 => self.stay_active(fields, resp, acc),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::AttrEncoder;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::im::wire::ImStatus;
    use crate::tlv::{TlvReader, TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::View)
            .with_env(0, [0u8; 16])
    }

    /// 属性を読み、書かれた TLV から u32/u16 の生値を取り出すヘルパ。
    fn read_u64(c: &IcdManagementCluster, id: u32) -> u64 {
        let mut buf = [0u8; 32];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(id), &mut e, &acc()).unwrap();
            w.written().len()
        };
        let mut r = TlvReader::new(&buf[..len]);
        r.read_next().unwrap().unwrap().value.as_unsigned().unwrap()
    }

    #[test]
    fn meta_is_sit_minimal() {
        let c = IcdManagementCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0046);
        assert_eq!(meta.revision, 3);
        assert_eq!(meta.feature_map, 0);
        // 必須 3 属性のみ、コマンド無し(SIT 最小)。
        assert_eq!(meta.attributes.len(), 3);
        assert!(meta.accepted_commands.is_empty());
        assert!(meta.generated_commands.is_empty());
    }

    #[test]
    fn reads_configured_values() {
        let cfg = IcdConfig {
            idle_mode_duration_s: 300,
            active_mode_duration_ms: 1500,
            active_mode_threshold_ms: 500,
        };
        let c = IcdManagementCluster::with_config(cfg);
        assert_eq!(read_u64(&c, 0x0000), 300);
        assert_eq!(read_u64(&c, 0x0001), 1500);
        assert_eq!(read_u64(&c, 0x0002), 500);
    }

    #[test]
    fn unknown_attribute_is_unsupported() {
        let c = IcdManagementCluster::new();
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        assert_eq!(
            c.read_attribute(AttributeId(0x0003), &mut e, &acc()),
            Err(ImStatus::UnsupportedAttribute)
        );
    }

    // ---- CIP / LITS クラスタ ----

    use crate::dm::codec::CmdResponder;
    use crate::icd::{IcdRegistrationTable, IcdState};
    use core::cell::RefCell;

    fn admin_acc(now_ms: u64) -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Administer)
            .with_env(now_ms, [0u8; 16])
    }

    /// RegisterClient のフィールド struct を組んで返す。
    fn register_fields(buf: &mut [u8], node: u64, subject: u64, key: [u8; 16]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_u64(&TlvTag::ContextSpecific(0), node).unwrap();
        w.write_u64(&TlvTag::ContextSpecific(1), subject).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(2), &key).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    #[test]
    fn cip_meta_and_feature() {
        let table = RefCell::new(IcdRegistrationTable::<4>::new());
        let state = RefCell::new(IcdState::new(IcdConfig::sit_default()));
        let sit = IcdManagementCipCluster::new(IcdConfig::sit_default(), &table, &state, false);
        assert_eq!(sit.meta().feature_map, crate::icd::feature::CIP);
        assert_eq!(sit.meta().accepted_commands.len(), 3);
        assert_eq!(sit.meta().generated_commands.len(), 2);
        let lit_cfg = IcdConfig {
            active_mode_threshold_ms: 5000,
            ..IcdConfig::sit_default()
        };
        let lit = IcdManagementCipCluster::new(lit_cfg, &table, &state, true);
        assert_eq!(
            lit.meta().feature_map,
            crate::icd::feature::CIP | crate::icd::feature::LITS
        );
        // OperatingMode 属性は LIT のみ。
        assert!(lit.meta().attribute(AttributeId(0x0008)).is_some());
        assert!(sit.meta().attribute(AttributeId(0x0008)).is_none());
    }

    #[test]
    fn register_returns_counter_and_lists_client() {
        let table = RefCell::new(IcdRegistrationTable::<4>::new());
        let state = RefCell::new(IcdState::new(IcdConfig::sit_default()));
        table.borrow_mut().bump_counter(); // ICDCounter = 1
        let mut c = IcdManagementCipCluster::new(IcdConfig::sit_default(), &table, &state, false);

        let mut fbuf = [0u8; 64];
        let flen = register_fields(&mut fbuf, 0xAABB, 0xCCDD, [7u8; 16]);
        let mut fr = TlvReader::new(&fbuf[..flen]);

        let mut rbuf = [0u8; 64];
        let counter = {
            let mut w = TlvWriter::new(&mut rbuf);
            let mut resp = CmdResponder::new(&mut w);
            c.invoke_command(CommandId(0x00), &mut fr, &mut resp, &admin_acc(0))
                .unwrap();
            assert_eq!(resp.response_command(), Some(CommandId(0x01)));
            // 応答 struct の field 0 = ICDCounter。
            let written = w.written().to_vec();
            let mut r = TlvReader::new(&written);
            r.enter_container().unwrap();
            r.read_next().unwrap().unwrap().value.as_unsigned().unwrap()
        };
        assert_eq!(counter, 1);
        assert_eq!(table.borrow().fabric_len(NonZeroU8::new(1).unwrap()), 1);

        // RegisteredClients 読み出しに 1 件現れる。
        let mut abuf = [0u8; 128];
        let mut w = TlvWriter::new(&mut abuf);
        let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        c.read_attribute(AttributeId(0x0003), &mut e, &admin_acc(0))
            .unwrap();
        assert!(w.written().len() > 2); // 空配列(2B)より大きい

        // ICDCounter 属性。
        assert_eq!(
            {
                let mut b = [0u8; 16];
                let mut w = TlvWriter::new(&mut b);
                let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
                c.read_attribute(AttributeId(0x0004), &mut e, &admin_acc(0))
                    .unwrap();
                let n = w.written().len();
                TlvReader::new(&b[..n])
                    .read_next()
                    .unwrap()
                    .unwrap()
                    .value
                    .as_unsigned()
                    .unwrap()
            },
            1
        );
    }

    #[test]
    fn unregister_removes_and_notfound() {
        let table = RefCell::new(IcdRegistrationTable::<4>::new());
        let state = RefCell::new(IcdState::new(IcdConfig::sit_default()));
        let mut c = IcdManagementCipCluster::new(IcdConfig::sit_default(), &table, &state, false);
        let mut fbuf = [0u8; 64];
        let flen = register_fields(&mut fbuf, 0x1234, 0x5678, [1u8; 16]);
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut rbuf = [0u8; 64];
        let mut w = TlvWriter::new(&mut rbuf);
        let mut resp = CmdResponder::new(&mut w);
        c.invoke_command(CommandId(0x00), &mut fr, &mut resp, &admin_acc(0))
            .unwrap();

        // UnregisterClient(check_in=0x1234)。
        let mut ubuf = [0u8; 32];
        let ulen = {
            let mut w = TlvWriter::new(&mut ubuf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u64(&TlvTag::ContextSpecific(0), 0x1234).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let mut ur = TlvReader::new(&ubuf[..ulen]);
        let mut rb = [0u8; 16];
        let mut w = TlvWriter::new(&mut rb);
        let mut resp = CmdResponder::new(&mut w);
        c.invoke_command(CommandId(0x02), &mut ur, &mut resp, &admin_acc(0))
            .unwrap();
        assert!(table.borrow().is_empty());

        // 2 回目は NotFound。
        let mut ur = TlvReader::new(&ubuf[..ulen]);
        let mut w = TlvWriter::new(&mut rb);
        let mut resp = CmdResponder::new(&mut w);
        assert_eq!(
            c.invoke_command(CommandId(0x02), &mut ur, &mut resp, &admin_acc(0)),
            Err(ImStatus::NotFound)
        );
    }

    #[test]
    fn stay_active_extends_state_and_responds() {
        let table = RefCell::new(IcdRegistrationTable::<4>::new());
        let state = RefCell::new(IcdState::new(IcdConfig::sit_default()));
        let mut c = IcdManagementCipCluster::new(IcdConfig::sit_default(), &table, &state, true);
        let mut fbuf = [0u8; 32];
        let flen = {
            let mut w = TlvWriter::new(&mut fbuf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u32(&TlvTag::ContextSpecific(0), 4000).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut rbuf = [0u8; 32];
        let promised = {
            let mut w = TlvWriter::new(&mut rbuf);
            let mut resp = CmdResponder::new(&mut w);
            c.invoke_command(CommandId(0x03), &mut fr, &mut resp, &admin_acc(1000))
                .unwrap();
            assert_eq!(resp.response_command(), Some(CommandId(0x04)));
            let written = w.written().to_vec();
            let mut r = TlvReader::new(&written);
            r.enter_container().unwrap();
            r.read_next().unwrap().unwrap().value.as_unsigned().unwrap()
        };
        assert_eq!(promised, 4000);
        // IcdState が now=1000 から 5000 まで active に延長された。
        assert!(state.borrow().is_active(4999));
        assert!(state.borrow().can_sleep(5000));
    }
}
