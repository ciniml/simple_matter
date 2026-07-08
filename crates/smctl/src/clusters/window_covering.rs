//! Window Covering クラスタ(0x0102)の名前テーブル。
//!
//! 例: `smctl window-covering go-to-lift-percentage 5000 <node> <ep>`(tick で線形移動)。
//! Target/Current の position は percent100ths(0=全開/10000=全閉)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0102, "window-covering") {
        attrs {
            0x0000 => "type": U8;
            0x0007 => "config-status": U8;
            0x0008 => "current-position-lift-percentage": U8;
            0x000A => "operational-status": U8;
            0x000B => "target-position-lift-percent100ths": U16;
            0x000D => "end-product-type": U8;
            0x000E => "current-position-lift-percent100ths": U16;
            0x0017 => "mode": U8 rw;
        }
        cmds {
            0x00 => "up-or-open" {}
            0x01 => "down-or-close" {}
            0x02 => "stop-motion" {}
            0x05 => "go-to-lift-percentage" {
                0 => "lift-percent100ths-value": U16;
            }
        }
    }
}
