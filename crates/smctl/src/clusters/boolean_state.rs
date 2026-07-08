//! Boolean State クラスタ(0x0045)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0045, "boolean-state") {
        attrs {
            0x0000 => "state-value": Bool;
        }
        cmds {}
        events {
            // simple_matter の接点センサが状態変化で post する { 0: stateValue(bool) }。
            0x0000 => "state-change";
        }
    }
}
