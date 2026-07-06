//! Identify クラスタ(0x0003)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0003, "identify") {
        attrs {
            0x0000 => "identify-time": U16 rw;
            0x0001 => "identify-type": U8;
        }
        cmds {
            0x00 => "identify" { 0 => "identify-time": U16; }
            0x40 => "trigger-effect" {
                0 => "effect-identifier": U8;
                1 => "effect-variant": U8;
            }
        }
    }
}
