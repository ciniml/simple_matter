//! クラスタ名前テーブル(設計 doc §5)。
//!
//! 「名前 ⇔ ID ⇔ TLV 型」の静的対応表。新クラスタ対応は
//! 「`clusters/<name>.rs` を 1 個書く + [`CLUSTERS`] に 1 行」で完結する。
//! テーブルは便利層であり、未収載クラスタも将来の `any` サブコマンド(C2)で
//! ID 直指定できる(機能の欠落にしない)。

use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId};

pub mod administrator_commissioning;
pub mod basic_information;
pub mod descriptor;
pub mod general_commissioning;
pub mod identify;
pub mod level_control;
pub mod names;
pub mod network_commissioning;
pub mod on_off;
pub mod operational_credentials;

/// 値の型(表示とリテラルパースの両方に使う)。TLV のワイヤ型と 1:1。
///
/// 全型を最初から揃えておく(`cluster_def!` の拡張面)。初期収載クラスタが使わない
/// variant があるのは意図的なので dead_code は抑止する。
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Utf8,
    Bytes,
    /// 未知/複合(struct・array 等)。表示は生 TLV ダンプ、入力は `hex:` のみ受理。
    Raw,
}

impl ValueKind {
    /// ヘルプ表示用の型名。
    pub fn name(&self) -> &'static str {
        match self {
            ValueKind::Bool => "bool",
            ValueKind::U8 => "u8",
            ValueKind::U16 => "u16",
            ValueKind::U32 => "u32",
            ValueKind::U64 => "u64",
            ValueKind::I8 => "i8",
            ValueKind::I16 => "i16",
            ValueKind::I32 => "i32",
            ValueKind::I64 => "i64",
            ValueKind::F32 => "f32",
            ValueKind::F64 => "f64",
            ValueKind::Utf8 => "str",
            ValueKind::Bytes => "hex",
            ValueKind::Raw => "raw",
        }
    }
}

/// 属性の名前テーブルエントリ。
pub struct AttrDef {
    pub id: AttributeId,
    /// kebab-case の属性名。
    pub name: &'static str,
    pub kind: ValueKind,
    /// Write 可能属性か(`rw` 指定)。
    pub writable: bool,
}

/// コマンドフィールドの名前テーブルエントリ。
pub struct FieldDef {
    /// context タグ番号。
    pub tag: u8,
    pub name: &'static str,
    pub kind: ValueKind,
    /// 省略可能なフィールドか(`opt` 指定)。
    pub optional: bool,
}

/// コマンドの名前テーブルエントリ。
pub struct CmdDef {
    pub id: CommandId,
    pub name: &'static str,
    pub fields: &'static [FieldDef],
}

/// 1 クラスタ分の名前テーブル。
pub struct ClusterDef {
    pub id: ClusterId,
    /// kebab-case のクラスタ名。
    pub name: &'static str,
    pub attrs: &'static [AttrDef],
    pub cmds: &'static [CmdDef],
}

impl ClusterDef {
    /// 属性を名前で引く。
    pub fn attr_by_name(&self, name: &str) -> Option<&'static AttrDef> {
        self.attrs.iter().find(|a| a.name == name)
    }

    /// 属性を ID で引く(結果表示の名前引き)。
    pub fn attr_by_id(&self, id: AttributeId) -> Option<&'static AttrDef> {
        self.attrs.iter().find(|a| a.id == id)
    }

    /// コマンドを名前で引く。
    pub fn cmd_by_name(&self, name: &str) -> Option<&'static CmdDef> {
        self.cmds.iter().find(|c| c.name == name)
    }
}

/// クラスタレジストリ。新クラスタ対応はここに 1 行足すだけ(設計 doc §5.2)。ID 昇順。
pub static CLUSTERS: &[&ClusterDef] = &[
    &identify::DEF,                    // 0x0003
    &on_off::DEF,                      // 0x0006
    &level_control::DEF,               // 0x0008
    &descriptor::DEF,                  // 0x001D
    &basic_information::DEF,           // 0x0028
    &general_commissioning::DEF,       // 0x0030
    &network_commissioning::DEF,       // 0x0031
    &administrator_commissioning::DEF, // 0x003C
    &operational_credentials::DEF,     // 0x003E
];

/// クラスタを名前で引く。
pub fn by_name(name: &str) -> Option<&'static ClusterDef> {
    CLUSTERS.iter().copied().find(|c| c.name == name)
}

/// クラスタを ID で引く(結果表示の名前引き)。
pub fn by_id(id: ClusterId) -> Option<&'static ClusterDef> {
    CLUSTERS.iter().copied().find(|c| c.id == id)
}

/// 1 クラスタ 1 ブロックの宣言マクロ(設計 doc §5.3、(b) 案)。
///
/// ```ignore
/// cluster_def! {
///     pub DEF = cluster(0x0006, "onoff") {
///         attrs {
///             0x0000 => "on-off": Bool;          // 読み取り専用
///             0x4001 => "on-time": U16 rw;       // writable は末尾に `rw`
///         }
///         cmds {
///             0x02 => "toggle" {}
///             0x00 => "move-to-level" { 0 => "level": U8; 1 => "transition-time": U16 opt; }
///         }
///     }
/// }
/// ```
macro_rules! cluster_def {
    (
        pub $def:ident = cluster($cid:expr, $cname:literal) {
            attrs { $( $aid:expr => $aname:literal : $akind:ident $($aflag:ident)? ; )* }
            cmds { $( $mid:expr => $mname:literal { $( $ftag:expr => $fname:literal : $fkind:ident $($fflag:ident)? ; )* } )* }
        }
    ) => {
        pub static $def: crate::clusters::ClusterDef = crate::clusters::ClusterDef {
            id: simple_matter::dm::meta::ClusterId($cid),
            name: $cname,
            attrs: &[
                $(crate::clusters::AttrDef {
                    id: simple_matter::dm::meta::AttributeId($aid),
                    name: $aname,
                    kind: crate::clusters::ValueKind::$akind,
                    writable: cluster_def!(@wflag $($aflag)?),
                },)*
            ],
            cmds: &[
                $(crate::clusters::CmdDef {
                    id: simple_matter::dm::meta::CommandId($mid),
                    name: $mname,
                    fields: &[
                        $(crate::clusters::FieldDef {
                            tag: $ftag,
                            name: $fname,
                            kind: crate::clusters::ValueKind::$fkind,
                            optional: cluster_def!(@oflag $($fflag)?),
                        },)*
                    ],
                },)*
            ],
        };
    };
    (@wflag) => { false };
    (@wflag rw) => { true };
    (@oflag) => { false };
    (@oflag opt) => { true };
}

pub(crate) use cluster_def;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lookup_by_name_and_id() {
        let def = by_name("onoff").expect("onoff in registry");
        assert_eq!(def.id, ClusterId(0x0006));
        assert!(std::ptr::eq(by_id(ClusterId(0x0006)).unwrap(), def));
        assert!(by_name("no-such-cluster").is_none());
        assert!(by_id(ClusterId(0xFFFF)).is_none());
    }

    #[test]
    fn onoff_table_entries() {
        let def = by_name("onoff").unwrap();
        let attr = def.attr_by_name("on-off").expect("on-off attr");
        assert_eq!(attr.id, AttributeId(0x0000));
        assert_eq!(attr.kind, ValueKind::Bool);
        assert!(!attr.writable);
        assert!(std::ptr::eq(
            def.attr_by_id(AttributeId(0x0000)).unwrap(),
            attr
        ));
        for (name, id) in [("off", 0x00), ("on", 0x01), ("toggle", 0x02)] {
            let cmd = def.cmd_by_name(name).expect(name);
            assert_eq!(cmd.id, CommandId(id));
            assert!(cmd.fields.is_empty());
        }
        assert!(def.attr_by_name("bogus").is_none());
        assert!(def.cmd_by_name("bogus").is_none());
    }

    #[test]
    fn registry_names_and_ids_unique() {
        for (i, a) in CLUSTERS.iter().enumerate() {
            for b in &CLUSTERS[i + 1..] {
                assert_ne!(a.id, b.id, "duplicate cluster id {:#06x}", a.id.0);
                assert_ne!(a.name, b.name, "duplicate cluster name {}", a.name);
            }
            // 各クラスタ内の属性/コマンド名・ID も一意であること。
            for (j, x) in a.attrs.iter().enumerate() {
                for y in &a.attrs[j + 1..] {
                    assert_ne!(x.id, y.id, "{}: duplicate attr id", a.name);
                    assert_ne!(x.name, y.name, "{}: duplicate attr name", a.name);
                }
            }
            for (j, x) in a.cmds.iter().enumerate() {
                for y in &a.cmds[j + 1..] {
                    assert_ne!(x.id, y.id, "{}: duplicate cmd id", a.name);
                    assert_ne!(x.name, y.name, "{}: duplicate cmd name", a.name);
                }
            }
        }
    }
}
