//! On/Off クラスタ(0x0006)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0006, "onoff") {
        attrs {
            0x0000 => "on-off": Bool;
        }
        cmds {
            0x00 => "off" {}
            0x01 => "on" {}
            0x02 => "toggle" {}
        }
    }
}
