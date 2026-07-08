//! Relative Humidity Measurement クラスタ(0x0405)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0405, "relative-humidity-measurement") {
        attrs {
            0x0000 => "measured-value": U16;
            0x0001 => "min-measured-value": U16;
            0x0002 => "max-measured-value": U16;
        }
        cmds {}
    }
}
