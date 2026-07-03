//! Network Commissioning クラスタ(0x0031、Matter Core Spec §11.8)。
//!
//! Ethernet / on-network 前提の最小実装。FeatureMap は Ethernet(bit 2 = `0x04`)のみを
//! 立て、`MaxNetworks = 1`、`Networks` は接続済みの単一 Ethernet インターフェースを表す
//! 1 エントリを返す。Wi-Fi/Thread 系コマンド(ScanNetworks / AddOrUpdateWiFiNetwork 等)は
//! Ethernet feature では非対応のため、受理コマンドを持たない(IM エンジンが
//! [`ImStatus::UnsupportedCommand`](crate::im::wire::ImStatus) を返す)。

use crate::cluster;
use crate::dm::codec::AttrEncoder;
use crate::im::wire::ImStatus;

/// FeatureMap の Ethernet ビット(EN、bit 2)。
pub const FEATURE_ETHERNET: u32 = 0x04;

/// Network Commissioning クラスタ(0x0031、Ethernet 最小)。
#[derive(Debug)]
pub struct NetworkCommissioning {
    /// Ethernet インターフェースの NetworkID(通常は MAC またはインターフェース名バイト)。
    network_id: &'static [u8],
    /// InterfaceEnabled(0x0004)。
    interface_enabled: bool,
}

impl NetworkCommissioning {
    /// Ethernet インターフェースの NetworkID を与えてクラスタを作る。
    pub const fn new(network_id: &'static [u8]) -> Self {
        Self {
            network_id,
            interface_enabled: true,
        }
    }

    /// InterfaceEnabled(0x0004)を書き込む。
    fn write_interface_enabled(
        &mut self,
        data: crate::tlv::TlvElement<'_>,
        _acc: &crate::dm::meta::AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data
            .value
            .as_bool()
            .map_err(|_| ImStatus::InvalidDataType)?;
        Ok(())
    }

    /// Networks(0x0001): NetworkInfoStruct `{ 0: networkID, 1: connected }` の配列。
    fn read_networks(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            a.push_struct(|s| {
                s.field_bytes(0, self.network_id)?;
                s.field_bool(1, true)
            })
        })
    }
}

cluster! {
    NetworkCommissioning {
        id: 0x0031,
        revision: 1,
        feature_map: 0x04,
        dirty: _,
        invoke: _,
        attributes: [
            0x0000 MaxNetworks {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_u8(1)),
                write: _
            },
            0x0001 Networks {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| c.read_networks(e)),
                write: _
            },
            0x0004 InterfaceEnabled {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_bool(c.interface_enabled)),
                write: (|c: &mut NetworkCommissioning, data, acc| c.write_interface_enabled(data, acc))
            },
            0x0005 LastNetworkingStatus {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
            0x0006 LastNetworkID {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
            0x0007 LastConnectErrorValue {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}
