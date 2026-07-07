//! General Diagnostics クラスタ(0x0033)の名前テーブル。
//!
//! `network-interfaces` と active-*-faults は struct list なので `Raw`。
//! `test-event-trigger` は製造テスト用(`enable-key` は 16 バイトの enable key)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0033, "general-diagnostics") {
        attrs {
            0x0000 => "network-interfaces": Raw;
            0x0001 => "reboot-count": U16;
            0x0002 => "up-time": U64;
            0x0003 => "total-operational-hours": U32;
            0x0004 => "boot-reason": U8;
            0x0005 => "active-hardware-faults": Raw;
            0x0006 => "active-radio-faults": Raw;
            0x0007 => "active-network-faults": Raw;
            0x0008 => "test-event-triggers-enabled": Bool;
        }
        cmds {
            0x00 => "test-event-trigger" {
                0 => "enable-key": Bytes;
                1 => "event-trigger": U64;
            }
            0x01 => "time-snapshot" {}
        }
    }
}
