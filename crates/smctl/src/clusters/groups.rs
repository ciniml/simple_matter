//! Groups クラスタ(0x0004)の名前テーブル。
//!
//! `get-group-membership`(0x02)の `group-list`(GroupId の list)は省略する。
//! [`crate::clusters::FieldDef`] は単一の [`crate::clusters::ValueKind`] しか
//! 表現できず(list 用の variant が無い)、`Raw` を充ててもコマンド引数としては
//! `parse_literal` が Raw を `null` 以外拒否するため位置引数から実値を渡せない
//! (`crates/smctl/src/ops.rs` の `parse_literal`)。list を指定して呼びたい場合は
//! `smctl any invoke <node> <ep> 0x0004 0x02 tlv:<hex>` で生 TLV の command
//! fields(タグ 0 に GroupId の array)を渡すこと。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0004, "groups") {
        attrs {
            0x0000 => "name-support": U8;
        }
        cmds {
            0x00 => "add-group" {
                0 => "group-id": U16;
                1 => "group-name": Utf8;
            }
            0x01 => "view-group" {
                0 => "group-id": U16;
            }
            0x02 => "get-group-membership" {}
            0x03 => "remove-group" {
                0 => "group-id": U16;
            }
            0x04 => "remove-all-groups" {}
            0x05 => "add-group-if-identifying" {
                0 => "group-id": U16;
                1 => "group-name": Utf8;
            }
        }
    }
}
