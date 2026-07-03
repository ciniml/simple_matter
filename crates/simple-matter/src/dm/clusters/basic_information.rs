//! Basic Information クラスタ(0x0028、`docs/design/interaction-model.md` §9.3)。
//!
//! 大半は焼き込み値([`BasicInfoConfig`]、`.rodata`)から返す読み取り専用属性。書き込み可能なのは
//! NodeLabel(0x0005)のみで、小さな固定バッファ(ヒープ非依存)に保持する。StartUp イベントは
//! イベント実装(初期スコープ外)のため省略。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::AccessContext;
use crate::im::wire::ImStatus;
use crate::tlv::TlvElement;

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

/// Basic Information クラスタ(0x0028)。
#[derive(Debug)]
pub struct BasicInformationCluster {
    cfg: &'static BasicInfoConfig,
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
    fn write_node_label(
        &mut self,
        data: TlvElement<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let s = data.value.as_str().map_err(|_| ImStatus::InvalidDataType)?;
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
                write: (|c: &mut BasicInformationCluster, data, acc| c.write_node_label(data, acc))
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
        ],
        accepted: [],
        generated: [],
    }
}
