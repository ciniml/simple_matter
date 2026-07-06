//! Network Commissioning クラスタ(0x0031)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0031, "network-commissioning") {
        attrs {
            0x0000 => "max-networks": U8;
            0x0001 => "networks": Raw;
            0x0002 => "scan-max-time-seconds": U8;
            0x0003 => "connect-max-time-seconds": U8;
            0x0004 => "interface-enabled": Bool rw;
            0x0005 => "last-networking-status": U8;
            0x0006 => "last-network-id": Bytes;
            0x0007 => "last-connect-error-value": I32;
        }
        cmds {
            0x00 => "scan-networks" {
                0 => "ssid": Bytes opt;
                1 => "breadcrumb": U64 opt;
            }
            0x02 => "add-or-update-wifi-network" {
                0 => "ssid": Bytes;
                1 => "credentials": Bytes;
                2 => "breadcrumb": U64 opt;
            }
            0x03 => "add-or-update-thread-network" {
                0 => "operational-dataset": Bytes;
                1 => "breadcrumb": U64 opt;
            }
            0x04 => "remove-network" {
                0 => "network-id": Bytes;
                1 => "breadcrumb": U64 opt;
            }
            0x06 => "connect-network" {
                0 => "network-id": Bytes;
                1 => "breadcrumb": U64 opt;
            }
            0x08 => "reorder-network" {
                0 => "network-id": Bytes;
                1 => "network-index": U8;
                2 => "breadcrumb": U64 opt;
            }
        }
    }
}
