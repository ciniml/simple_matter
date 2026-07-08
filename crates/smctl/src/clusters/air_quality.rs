//! Air Quality クラスタ(0x005B)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x005B, "air-quality") {
        attrs {
            0x0000 => "air-quality": U8;
        }
        cmds {}
    }
}
