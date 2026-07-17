//! ICD Management クラスタ(0x0046)の名前テーブル(SIT 最小 = 必須 3 属性)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0046, "icd-management") {
        attrs {
            0x0000 => "idle-mode-duration": U32;
            0x0001 => "active-mode-duration": U32;
            0x0002 => "active-mode-threshold": U16;
        }
        cmds {}
    }
}
