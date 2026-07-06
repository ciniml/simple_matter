//! Descriptor クラスタ(0x001D)の名前テーブル。
//!
//! 属性はすべてリスト型なので `Raw`(表示は汎用ダンプ、`--json` では配列)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x001D, "descriptor") {
        attrs {
            0x0000 => "device-type-list": Raw;
            0x0001 => "server-list": Raw;
            0x0002 => "client-list": Raw;
            0x0003 => "parts-list": Raw;
        }
        cmds {
        }
    }
}
