//! Descriptor クラスタ(0x001D、`docs/design/interaction-model.md` §9.2)。
//!
//! DeviceTypeList / ServerList / ClientList / PartsList を格納せず、[`device!`](マクロ)が
//! 合成メタから注入する `&'static` スライスから導出する。`device!` は同じ宣言で `DataModel` の
//! `clusters_on` も生成するため、ServerList はそれと一致する(単一ソース)。

use crate::cluster;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{ClusterId, DeviceType, EndpointId};
use crate::im::wire::ImStatus;

/// Descriptor クラスタ(0x001D)。
#[derive(Debug)]
pub struct DescriptorCluster {
    endpoint: EndpointId,
    device_types: &'static [DeviceType],
    server_list: &'static [ClusterId],
    client_list: &'static [ClusterId],
    parts: &'static [EndpointId],
}

impl DescriptorCluster {
    /// エンドポイントの合成メタを注入してクラスタを作る。
    ///
    /// `device_types`/`server_list`/`parts` は `device!` が生成する
    /// `device_types(ep)`/`server_list(ep)`/`parts(ep)` を渡す。`client_list` は通常空。
    pub const fn new(
        endpoint: EndpointId,
        device_types: &'static [DeviceType],
        server_list: &'static [ClusterId],
        client_list: &'static [ClusterId],
        parts: &'static [EndpointId],
    ) -> Self {
        Self {
            endpoint,
            device_types,
            server_list,
            client_list,
            parts,
        }
    }

    /// このクラスタが属するエンドポイント。
    pub const fn endpoint(&self) -> EndpointId {
        self.endpoint
    }

    /// DeviceTypeList(0x0000): `DeviceTypeStruct { 0: deviceType, 1: revision }` の配列。
    fn read_device_type_list(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for dt in self.device_types {
                a.push_struct(|s| {
                    s.field_u32(0, dt.id)?;
                    s.field_u16(1, dt.revision)
                })?;
            }
            Ok(())
        })
    }

    /// クラスタ ID の配列(ServerList / ClientList 共通)を書く。
    fn read_cluster_list(list: &[ClusterId], e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for c in list {
                a.push_u32(c.0)?;
            }
            Ok(())
        })
    }

    /// PartsList(0x0003): エンドポイント ID(u16)の配列。
    fn read_parts_list(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for ep in self.parts {
                a.push_u16(ep.0)?;
            }
            Ok(())
        })
    }
}

cluster! {
    DescriptorCluster {
        id: 0x001D,
        revision: 2,
        feature_map: 0,
        dirty: _,
        invoke: _,
        attributes: [
            0x0000 DeviceTypeList {
                access: View, quality: [], subscribe: false,
                read: (|c: &DescriptorCluster, e: &mut AttrEncoder<'_, '_>| c.read_device_type_list(e)),
                write: _
            },
            0x0001 ServerList {
                access: View, quality: [], subscribe: false,
                read: (|c: &DescriptorCluster, e: &mut AttrEncoder<'_, '_>| DescriptorCluster::read_cluster_list(c.server_list, e)),
                write: _
            },
            0x0002 ClientList {
                access: View, quality: [], subscribe: false,
                read: (|c: &DescriptorCluster, e: &mut AttrEncoder<'_, '_>| DescriptorCluster::read_cluster_list(c.client_list, e)),
                write: _
            },
            0x0003 PartsList {
                access: View, quality: [], subscribe: false,
                read: (|c: &DescriptorCluster, e: &mut AttrEncoder<'_, '_>| c.read_parts_list(e)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}
