//! Flow Measurement クラスタ(0x0404)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0404, "flow-measurement") {
        attrs {
            0x0000 => "measured-value": U16;
            0x0001 => "min-measured-value": U16;
            0x0002 => "max-measured-value": U16;
        }
        cmds {}
    }
}
