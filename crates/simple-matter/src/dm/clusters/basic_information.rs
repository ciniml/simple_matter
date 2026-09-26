//! Basic Information クラスタ(0x0028、`docs/design/interaction-model.md` §9.3)。
//!
//! 大半は焼き込み値([`BasicInfoConfig`]、`.rodata`)から返す読み取り専用属性。書き込み可能なのは
//! NodeLabel(0x0005)のみで、小さな固定バッファ(ヒープ非依存)に保持する。StartUp イベントは
//! イベント実装(初期スコープ外)のため省略。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::AccessContext;
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;

/// NodeLabel の最大長(Matter 仕様: char_string length 32)。
pub const NODE_LABEL_MAX: usize = 32;

/// DataModelRevision 属性(0x0000)の値(本実装が準拠する Data Model リビジョン)。
pub const DATA_MODEL_REVISION: u16 = 18;

/// Basic Information の焼き込み設定(`&'static` で渡す)。
#[derive(Debug, Clone, Copy)]
pub struct BasicInfoConfig {
    /// VendorName(0x0001)。
    pub vendor_name: &'static str,
    /// VendorID(0x0002)。
    pub vendor_id: u16,
    /// ProductName(0x0003)。
    pub product_name: &'static str,
    /// ProductID(0x0004)。
    pub product_id: u16,
    /// HardwareVersion(0x0007)。
    pub hardware_version: u16,
    /// HardwareVersionString(0x0008)。
    pub hardware_version_string: &'static str,
    /// SoftwareVersion(0x0009)。
    pub software_version: u32,
    /// SoftwareVersionString(0x000A)。
    pub software_version_string: &'static str,
    /// SerialNumber(0x000F)。
    pub serial_number: &'static str,
}

/// SpecificationVersion 属性(0x0015)の値。本実装が準拠する Matter 仕様(1.3.0)。
pub const SPECIFICATION_VERSION: u32 = 0x0103_0000;
/// MaxPathsPerInvoke 属性(0x0016)。本実装は 1 InvokeRequest あたり 1 コマンドパス。
pub const MAX_PATHS_PER_INVOKE: u16 = 1;
/// CapabilityMinima(0x0013)の CaseSessionsPerFabric / SubscriptionsPerFabric(仕様の最小値 3 を保証)。
pub const CAPABILITY_MINIMA: (u16, u16) = (3, 3);

/// Basic Information クラスタ(0x0028)。
#[derive(Debug)]
pub struct BasicInformationCluster {
    cfg: &'static BasicInfoConfig,
    /// Location(0x0006、ISO 3166-1 alpha-2、管理者が書き込み可)。既定 "XX"。
    location: [u8; 2],
    /// NodeLabel(0x0005、書き込み可)の UTF-8 バイト。
    node_label: [u8; NODE_LABEL_MAX],
    /// NodeLabel の有効バイト長。
    node_label_len: u8,
    dirty: Dirty,
}

impl BasicInformationCluster {
    /// 設定を与えてクラスタを作る(NodeLabel は空文字列で初期化)。
    pub const fn new(cfg: &'static BasicInfoConfig) -> Self {
        Self {
            cfg,
            location: *b"XX",
            node_label: [0u8; NODE_LABEL_MAX],
            node_label_len: 0,
            dirty: Dirty::new(),
        }
    }

    /// 現在の NodeLabel を返す。
    pub fn node_label(&self) -> &str {
        // 書き込み時に UTF-8 妥当性を保証しているため常に成功する。
        core::str::from_utf8(&self.node_label[..self.node_label_len as usize]).unwrap_or("")
    }

    /// NodeLabel(0x0005)を書き込む。
    /// 現在の Location(2 文字)を返す。
    pub fn location(&self) -> &str {
        core::str::from_utf8(&self.location).unwrap_or("XX")
    }

    /// Location(0x0006)を書き込む(2 文字固定、ConstraintError)。
    fn write_location(
        &mut self,
        data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let b = data.as_str()?.as_bytes();
        if b.len() != 2 {
            return Err(ImStatus::ConstraintError);
        }
        self.location.copy_from_slice(b);
        self.dirty.mark();
        Ok(())
    }

    /// CapabilityMinima(0x0013)を書く。
    fn read_capability_minima(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_struct(|s| {
            s.field_u16(0, CAPABILITY_MINIMA.0)?;
            s.field_u16(1, CAPABILITY_MINIMA.1)
        })
    }

    fn write_node_label(
        &mut self,
        data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let s = data.as_str()?;
        let bytes = s.as_bytes();
        if bytes.len() > NODE_LABEL_MAX {
            return Err(ImStatus::ConstraintError);
        }
        self.node_label[..bytes.len()].copy_from_slice(bytes);
        self.node_label_len = bytes.len() as u8;
        self.dirty.mark();
        Ok(())
    }
}

cluster! {
    BasicInformationCluster {
        id: 0x0028,
        revision: 3,
        feature_map: 0,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 DataModelRevision {
                access: View, quality: [FIXED], subscribe: false,
                read: (|_c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(DATA_MODEL_REVISION)),
                write: _
            },
            0x0001 VendorName {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.vendor_name)),
                write: _
            },
            0x0002 VendorID {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.cfg.vendor_id)),
                write: _
            },
            0x0003 ProductName {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.product_name)),
                write: _
            },
            0x0004 ProductID {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.cfg.product_id)),
                write: _
            },
            0x0005 NodeLabel {
                access: View, quality: [NONVOLATILE], subscribe: true,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.node_label())),
                write: (Manage, |c: &mut BasicInformationCluster, data, acc| c.write_node_label(data, acc))
            },
            0x0006 Location {
                access: View, quality: [NONVOLATILE], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.location())),
                write: (Administer, |c: &mut BasicInformationCluster, data, acc| c.write_location(data, acc))
            },
            0x0007 HardwareVersion {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.cfg.hardware_version)),
                write: _
            },
            0x0008 HardwareVersionString {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.hardware_version_string)),
                write: _
            },
            0x0009 SoftwareVersion {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u32(c.cfg.software_version)),
                write: _
            },
            0x000A SoftwareVersionString {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.software_version_string)),
                write: _
            },
            0x000F SerialNumber {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.serial_number)),
                write: _
            },
            // UniqueID(rev 3 では任意、rev 4 で必須)。デバイス固有値として SerialNumber を流用する。
            0x0012 UniqueID {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_str(c.cfg.serial_number)),
                write: _
            },
            0x0013 CapabilityMinima {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| c.read_capability_minima(e)),
                write: _
            },
            0x0015 SpecificationVersion {
                access: View, quality: [FIXED], subscribe: false,
                read: (|_c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u32(SPECIFICATION_VERSION)),
                write: _
            },
            0x0016 MaxPathsPerInvoke {
                access: View, quality: [FIXED], subscribe: false,
                read: (|_c: &BasicInformationCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(MAX_PATHS_PER_INVOKE)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}
