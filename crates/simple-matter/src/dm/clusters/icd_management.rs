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
}
