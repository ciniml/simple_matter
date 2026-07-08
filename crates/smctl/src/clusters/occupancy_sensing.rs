//! Occupancy Sensing クラスタ(0x0406)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0406, "occupancy-sensing") {
        attrs {
            0x0000 => "occupancy": U8;
            0x0001 => "occupancy-sensor-type": U8;
            0x0002 => "occupancy-sensor-type-bitmap": U8;
        }
        cmds {}
    }
}
