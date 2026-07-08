//! Fan Control クラスタ(0x0202)の名前テーブル。
//!
//! 例: `smctl fan-control write percent-setting 50 <node> <ep>`(PercentCurrent がランプ追従)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0202, "fan-control") {
        attrs {
            0x0000 => "fan-mode": U8 rw;
            0x0001 => "fan-mode-sequence": U8;
            0x0002 => "percent-setting": U8 rw;
            0x0003 => "percent-current": U8;
        }
        cmds {}
    }
}
