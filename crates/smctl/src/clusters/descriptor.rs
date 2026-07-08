//! Descriptor クラスタ(0x001D)の名前テーブル。
//!
//! 属性はすべてリスト型なので `Raw`(表示は汎用ダンプ、`--json` では配列)。
//! `@<Semantic>` は `--names` の ID→名前デコード表示用の意味注釈(設計 doc §11):
//! server-list/client-list の要素は cluster ID、device-type-list の要素は
//! `{0: deviceType, 1: revision}` struct。parts-list は endpoint 番号のままで
//! 十分読めるので注釈しない。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x001D, "descriptor") {
        attrs {
            0x0000 => "device-type-list": Raw @DeviceTypeStructList;
            0x0001 => "server-list": Raw @ClusterIdList;
            0x0002 => "client-list": Raw @ClusterIdList;
            0x0003 => "parts-list": Raw;
        }
        cmds {
        }
    }
}
