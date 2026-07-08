//! Pressure Measurement クラスタ(0x0403)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0403, "pressure-measurement") {
        attrs {
            0x0000 => "measured-value": I16;
            0x0001 => "min-measured-value": I16;
            0x0002 => "max-measured-value": I16;
        }
        cmds {}
    }
}
