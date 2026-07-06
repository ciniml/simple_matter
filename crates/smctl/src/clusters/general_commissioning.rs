//! General Commissioning クラスタ(0x0030)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0030, "general-commissioning") {
        attrs {
            0x0000 => "breadcrumb": U64 rw;
            0x0001 => "basic-commissioning-info": Raw;
            0x0002 => "regulatory-config": U8;
            0x0003 => "location-capability": U8;
            0x0004 => "supports-concurrent-connection": Bool;
        }
        cmds {
            0x00 => "arm-fail-safe" {
                0 => "expiry-length-seconds": U16;
                1 => "breadcrumb": U64;
            }
            0x02 => "set-regulatory-config" {
                0 => "new-regulatory-config": U8;
                1 => "country-code": Utf8;
                2 => "breadcrumb": U64;
            }
            0x04 => "commissioning-complete" {}
        }
    }
}
