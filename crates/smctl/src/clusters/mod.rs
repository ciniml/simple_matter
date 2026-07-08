//! クラスタ名前テーブル(設計 doc §5)。
//!
//! 「名前 ⇔ ID ⇔ TLV 型」の静的対応表。新クラスタ対応は
//! 「`clusters/<name>.rs` を 1 個書く + [`CLUSTERS`] に 1 行」で完結する。
//! テーブルは便利層であり、未収載クラスタも将来の `any` サブコマンド(C2)で
//! ID 直指定できる(機能の欠落にしない)。

use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EventId};

pub mod access_control;
pub mod administrator_commissioning;
pub mod basic_information;
pub mod boolean_state;
pub mod color_control;
pub mod descriptor;
pub mod device_types;
pub mod fan_control;
pub mod flow_measurement;
pub mod general_commissioning;
pub mod general_diagnostics;
pub mod group_key_management;
pub mod groups;
pub mod identify;
pub mod illuminance_measurement;
pub mod level_control;
pub mod names;
pub mod network_commissioning;
pub mod occupancy_sensing;
pub mod on_off;
pub mod operational_credentials;
pub mod pressure_measurement;
pub mod relative_humidity_measurement;
pub mod switch;
pub mod temperature_measurement;
pub mod thermostat;
pub mod window_covering;

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

/// 属性値の意味注釈(設計 doc §11)。
///
/// [`ValueKind`] はワイヤ型(TLV 型と 1:1)なので、「この Raw リストの要素は
/// cluster ID である」といった**意味**は載らない。`--names` の ID→名前デコード表示は
/// この注釈で駆動する(表示層に特定クラスタのハードコードを持ち込まない。
/// 単一ソース原則 = クラスタの知識は cluster_def! に集約)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Semantic {
    /// 注釈なし(従来表示)。
    #[default]
    None,
    /// 要素が cluster ID の list(Descriptor の ServerList/ClientList)。
    ClusterIdList,
    /// 要素が `{0: deviceType, 1: revision}` struct の list
    /// (Descriptor の DeviceTypeList)。
    DeviceTypeStructList,
}

/// 属性の名前テーブルエントリ。
pub struct AttrDef {
    pub id: AttributeId,
    /// kebab-case の属性名。
    pub name: &'static str,
    pub kind: ValueKind,
    /// 値の意味注釈(`@<Semantic>` 指定。既定 [`Semantic::None`])。
    ///
    /// マクロの区切りが `as` でなく `@` なのは、`as` が `ident` フラグメント
    /// (`rw` フラグ)にもマッチして macro_rules がローカル曖昧になるため。
    pub semantic: Semantic,
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

/// イベントの名前テーブルエントリ(設計 §12)。
pub struct EventDef {
    pub id: EventId,
    /// kebab-case のイベント名。
    pub name: &'static str,
}

/// 1 クラスタ分の名前テーブル。
pub struct ClusterDef {
    pub id: ClusterId,
    /// kebab-case のクラスタ名。
    pub name: &'static str,
    pub attrs: &'static [AttrDef],
    pub cmds: &'static [CmdDef],
    pub events: &'static [EventDef],
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

    /// イベントを名前で引く。
    pub fn event_by_name(&self, name: &str) -> Option<&'static EventDef> {
        self.events.iter().find(|e| e.name == name)
    }

    /// イベントを ID で引く(結果表示の名前引き)。
    pub fn event_by_id(&self, id: EventId) -> Option<&'static EventDef> {
        self.events.iter().find(|e| e.id == id)
    }
}

/// クラスタレジストリ。新クラスタ対応はここに 1 行足すだけ(設計 doc §5.2)。ID 昇順。
pub static CLUSTERS: &[&ClusterDef] = &[
    &identify::DEF,                      // 0x0003
    &groups::DEF,                        // 0x0004
    &on_off::DEF,                        // 0x0006
    &level_control::DEF,                 // 0x0008
    &descriptor::DEF,                    // 0x001D
    &access_control::DEF,                // 0x001F
    &basic_information::DEF,             // 0x0028
    &general_commissioning::DEF,         // 0x0030
    &network_commissioning::DEF,         // 0x0031
    &general_diagnostics::DEF,           // 0x0033
    &switch::DEF,                        // 0x003B
    &administrator_commissioning::DEF,   // 0x003C
    &operational_credentials::DEF,       // 0x003E
    &group_key_management::DEF,          // 0x003F
    &boolean_state::DEF,                 // 0x0045
    &window_covering::DEF,               // 0x0102
    &thermostat::DEF,                    // 0x0201
    &fan_control::DEF,                   // 0x0202
    &color_control::DEF,                 // 0x0300
    &illuminance_measurement::DEF,       // 0x0400
    &temperature_measurement::DEF,       // 0x0402
    &pressure_measurement::DEF,          // 0x0403
    &flow_measurement::DEF,              // 0x0404
    &relative_humidity_measurement::DEF, // 0x0405
    &occupancy_sensing::DEF,             // 0x0406
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
///             0x0001 => "server-list": Raw @ClusterIdList; // 意味注釈(--names 用)
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
            attrs { $( $aid:expr => $aname:literal : $akind:ident $(@ $asem:ident)? $($aflag:ident)? ; )* }
            cmds { $( $mid:expr => $mname:literal { $( $ftag:expr => $fname:literal : $fkind:ident $($fflag:ident)? ; )* } )* }
            $( events { $( $eid:expr => $ename:literal ; )* } )?
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
                    semantic: cluster_def!(@sem $($asem)?),
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
            events: &[
                $($(crate::clusters::EventDef {
                    id: simple_matter::dm::meta::EventId($eid),
                    name: $ename,
                },)*)?
            ],
        };
    };
    (@wflag) => { false };
    (@wflag rw) => { true };
    (@sem) => { crate::clusters::Semantic::None };
    (@sem $sem:ident) => { crate::clusters::Semantic::$sem };
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
    fn access_control_and_general_diagnostics_registered() {
        // Access Control(0x001F): 属性のみ、コマンド無し。
        let ac = by_name("access-control").expect("access-control in registry");
        assert_eq!(ac.id, ClusterId(0x001F));
        assert!(std::ptr::eq(by_id(ClusterId(0x001F)).unwrap(), ac));
        assert_eq!(ac.attr_by_name("acl").unwrap().id, AttributeId(0x0000));
        assert!(ac.attr_by_name("acl").unwrap().writable);
        assert_eq!(
            ac.attr_by_name("access-control-entries-per-fabric")
                .unwrap()
                .id,
            AttributeId(0x0004)
        );
        assert!(ac.cmds.is_empty());

        // General Diagnostics(0x0033): 属性 + test-event-trigger / time-snapshot。
        let gd = by_name("general-diagnostics").expect("general-diagnostics in registry");
        assert_eq!(gd.id, ClusterId(0x0033));
        assert!(std::ptr::eq(by_id(ClusterId(0x0033)).unwrap(), gd));
        assert_eq!(gd.attr_by_name("up-time").unwrap().kind, ValueKind::U64);
        assert_eq!(
            gd.attr_by_id(AttributeId(0x0004)).unwrap().name,
            "boot-reason"
        );
        let te = gd
            .cmd_by_name("test-event-trigger")
            .expect("test-event-trigger");
        assert_eq!(te.id, CommandId(0x00));
        assert_eq!(te.fields.len(), 2);
        assert_eq!(te.fields[0].name, "enable-key");
        assert_eq!(te.fields[0].kind, ValueKind::Bytes);
        let ts = gd.cmd_by_name("time-snapshot").expect("time-snapshot");
        assert_eq!(ts.id, CommandId(0x01));
        assert!(ts.fields.is_empty());
    }

    #[test]
    fn groups_and_group_key_management_registered() {
        // Groups(0x0004): get-group-membership は list フィールドを省略しているので
        // 引数無しコマンドとして収載されていることを確認する。
        let g = by_name("groups").expect("groups in registry");
        assert_eq!(g.id, ClusterId(0x0004));
        assert!(std::ptr::eq(by_id(ClusterId(0x0004)).unwrap(), g));
        assert_eq!(
            g.attr_by_name("name-support").unwrap().id,
            AttributeId(0x0000)
        );
        for (name, id, nfields) in [
            ("add-group", 0x00, 2),
            ("view-group", 0x01, 1),
            ("get-group-membership", 0x02, 0),
            ("remove-group", 0x03, 1),
            ("remove-all-groups", 0x04, 0),
            ("add-group-if-identifying", 0x05, 2),
        ] {
            let cmd = g.cmd_by_name(name).expect(name);
            assert_eq!(cmd.id, CommandId(id));
            assert_eq!(cmd.fields.len(), nfields, "{name}: field count");
        }

        // GroupKeyManagement(0x003F): key-set-write はネスト struct 引数のため
        // 未収載(コメント参照)。read/remove/read-all-indices のみ。
        let gkm = by_name("groupkeymanagement").expect("groupkeymanagement in registry");
        assert_eq!(gkm.id, ClusterId(0x003F));
        assert!(std::ptr::eq(by_id(ClusterId(0x003F)).unwrap(), gkm));
        let map = gkm.attr_by_name("group-key-map").unwrap();
        assert_eq!(map.kind, ValueKind::Raw);
        assert!(map.writable);
        let table = gkm.attr_by_name("group-table").unwrap();
        assert_eq!(table.kind, ValueKind::Raw);
        assert!(!table.writable);
        assert_eq!(
            gkm.attr_by_name("max-groups-per-fabric").unwrap().kind,
            ValueKind::U16
        );
        assert!(gkm.cmd_by_name("key-set-write").is_none());
        for (name, id) in [
            ("key-set-read", 0x01),
            ("key-set-remove", 0x03),
            ("key-set-read-all-indices", 0x04),
        ] {
            assert_eq!(gkm.cmd_by_name(name).expect(name).id, CommandId(id));
        }
    }

    #[test]
    fn descriptor_semantic_annotations() {
        // --names のデコード表示は cluster_def! の意味注釈で駆動する(設計 doc §11)。
        let d = by_name("descriptor").expect("descriptor in registry");
        let sem = |name: &str| d.attr_by_name(name).unwrap().semantic;
        assert_eq!(sem("device-type-list"), Semantic::DeviceTypeStructList);
        assert_eq!(sem("server-list"), Semantic::ClusterIdList);
        assert_eq!(sem("client-list"), Semantic::ClusterIdList);
        // parts-list(endpoint 番号)と他クラスタの属性は注釈なし。
        assert_eq!(sem("parts-list"), Semantic::None);
        let onoff = by_name("onoff").unwrap();
        assert_eq!(
            onoff.attr_by_name("on-off").unwrap().semantic,
            Semantic::None
        );
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
