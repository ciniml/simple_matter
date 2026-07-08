//! Group Key Management クラスタ(0x003F)の名前テーブル。
//!
//! `group-key-map` / `group-table` は fabric-scoped な struct list なので、
//! access_control.rs の `acl` 属性と同じ方針で `Raw` にする(表示は生 TLV
//! ダンプ、書き込みは `any` の `tlv:<hex>` 経由)。
//!
//! `key-set-write`(0x00)は収載しない。GroupKeySet 構造体
//! (group-key-set-id / group-key-security-policy / epoch-key0..2 /
//! epoch-start-time0..2 の 7 フィールドを持つ)を単一の command field として
//! 渡す必要があるが、[`crate::clusters::FieldDef`] はフラットな
//! `tag → ValueKind` しか表現できずネストした struct を組み立てられないため。
//! 呼び出す場合は
//! `smctl any invoke <node> <ep> 0x003F 0x00 tlv:<hex>` で
//! GroupKeySet 構造体を載せた生 TLV の command fields を渡すこと。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x003F, "groupkeymanagement") {
        attrs {
            0x0000 => "group-key-map": Raw rw;
            0x0001 => "group-table": Raw;
            0x0002 => "max-groups-per-fabric": U16;
            0x0003 => "max-group-keys-per-fabric": U16;
        }
        cmds {
            0x01 => "key-set-read" {
                0 => "group-key-set-id": U16;
            }
            0x03 => "key-set-remove" {
                0 => "group-key-set-id": U16;
            }
            0x04 => "key-set-read-all-indices" {}
        }
    }
}
