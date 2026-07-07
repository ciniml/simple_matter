//! Access Control クラスタ(0x001F)の名前テーブル。
//!
//! `acl` / `extension` は fabric-scoped な struct list(型付きの手入力は非現実的)なので
//! `Raw` にする。読み取りは生 TLV ダンプ、書き込みは `any` の `tlv:<hex>` 経由。
//! コマンドは持たない(属性のみ)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x001F, "access-control") {
        attrs {
            0x0000 => "acl": Raw rw;
            0x0001 => "extension": Raw rw;
            0x0002 => "subjects-per-access-control-entry": U16;
            0x0003 => "targets-per-access-control-entry": U16;
            0x0004 => "access-control-entries-per-fabric": U16;
        }
        cmds {}
    }
}
