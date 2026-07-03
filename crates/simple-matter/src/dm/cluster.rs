//! クラスタ宣言マクロ(`cluster!` / `device!`)と共通ヘルパ(`docs/design/interaction-model.md` §8/§9)。
//!
//! [`cluster!`] は属性/コマンドの宣言 1 箇所から、メタデータ `const`(`ClusterMeta`)と
//! `ServerCluster` の read/write/invoke ディスパッチ骨格を単一ソースで生成する。
//! [`device!`] は (endpoint, cluster) の合成から `DataModel` 実装とメタデータ列挙を生成する。
//! グローバル属性はクラスタに書かせず、[`read_global_attribute`] がメタから自動導出する。

use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{is_global_attribute, AttributeId, ClusterMeta, GLOBAL_ATTRIBUTE_IDS};
use crate::im::wire::ImStatus;

// ==========================================================================
// dirty フラグ
// ==========================================================================

/// 属性変更を Subscribe に伝えるためのクラスタ単位 dirty フラグ(設計 §6.2/§9)。
#[derive(Debug, Clone, Copy, Default)]
pub struct Dirty(bool);

impl Dirty {
    /// クリア状態の [`Dirty`] を作る。
    pub const fn new() -> Self {
        Self(false)
    }

    /// dirty を立てる。
    pub fn mark(&mut self) {
        self.0 = true;
    }

    /// 現在の dirty を返してクリアする。
    pub fn take(&mut self) -> bool {
        core::mem::take(&mut self.0)
    }

    /// dirty かどうかを返す(クリアしない)。
    pub const fn is_dirty(&self) -> bool {
        self.0
    }
}

// ==========================================================================
// グローバル属性の自動導出(エンジン相当。設計 §7.1)
// ==========================================================================

/// グローバル属性([`GLOBAL_ATTRIBUTE_IDS`])を `meta` から導出して `enc` に書く。
///
/// クラスタの `read_attribute` はグローバル属性を実装しない。IM エンジン(次ピース)は
/// read/展開でグローバル属性を検出したら本関数で応答する。`attr` がグローバル属性でなければ
/// [`ImStatus::UnsupportedAttribute`]。
pub fn read_global_attribute(
    meta: &ClusterMeta,
    attr: AttributeId,
    enc: &mut AttrEncoder<'_, '_>,
) -> Result<(), ImStatus> {
    match attr.0 {
        // ClusterRevision
        0xFFFD => enc.write_u16(meta.revision),
        // FeatureMap
        0xFFFC => enc.write_u32(meta.feature_map),
        // AttributeList = 固有属性 ID + グローバル属性 ID(昇順)
        0xFFFB => enc.write_array(|a| {
            for am in meta.attributes {
                a.push_u32(am.id.0)?;
            }
            for gid in GLOBAL_ATTRIBUTE_IDS {
                a.push_u32(gid.0)?;
            }
            Ok(())
        }),
        // AcceptedCommandList
        0xFFF9 => enc.write_array(|a| {
            for cm in meta.accepted_commands {
                a.push_u32(cm.id.0)?;
            }
            Ok(())
        }),
        // GeneratedCommandList
        0xFFF8 => enc.write_array(|a| {
            for gc in meta.generated_commands {
                a.push_u32(gc.0)?;
            }
            Ok(())
        }),
        _ => Err(ImStatus::UnsupportedAttribute),
    }
}

/// `attr` がグローバル属性かを返す(再エクスポート便宜)。
pub const fn is_global(attr: AttributeId) -> bool {
    is_global_attribute(attr)
}

// ==========================================================================
// cluster! / device! の内部ヘルパマクロ
// ==========================================================================

/// 書き込みディスパッチ: `_` は UnsupportedWrite、`(クロージャ)` は `(self, data, acc)` で起動。
#[macro_export]
#[doc(hidden)]
macro_rules! __cluster_write {
    (_, $s:expr, $data:expr, $acc:expr) => {
        Err($crate::im::wire::ImStatus::UnsupportedWrite)
    };
    (($f:expr), $s:expr, $data:expr, $acc:expr) => {
        ($f)($s, $data, $acc)
    };
}

/// invoke ディスパッチ: `_` は UnsupportedCommand、`(クロージャ)` は全引数付きで起動。
#[macro_export]
#[doc(hidden)]
macro_rules! __cluster_invoke {
    (_, $s:expr, $cmd:expr, $fields:expr, $resp:expr, $acc:expr) => {{
        let _ = ($cmd, $fields, $resp, $acc);
        Err($crate::im::wire::ImStatus::UnsupportedCommand)
    }};
    (($f:expr), $s:expr, $cmd:expr, $fields:expr, $resp:expr, $acc:expr) => {
        ($f)($s, $cmd, $fields, $resp, $acc)
    };
}

/// take_dirty ディスパッチ: `_` は常に false、フィールド名は `Dirty::take`。
#[macro_export]
#[doc(hidden)]
macro_rules! __cluster_dirty {
    (_, $s:expr) => {
        false
    };
    ($f:ident, $s:expr) => {
        $s.$f.take()
    };
}

/// 属性の書き込み可否メタ: `_` は false、`(クロージャ)` は true。
#[macro_export]
#[doc(hidden)]
macro_rules! __attr_writable {
    (_) => {
        false
    };
    ($g:tt) => {
        true
    };
}

// ==========================================================================
// cluster! マクロ(単一ソース: メタ + dispatch 骨格)
// ==========================================================================

/// 1 宣言からクラスタのメタ `const` と `ServerCluster` 実装骨格を生成する(設計 §8.2)。
///
/// 属性行 `$id $Name { access, quality, subscribe, read, write }` から、メタデータ配列の
/// 該当エントリと read/write の match アームを**同じ宣言**から生成する(整合ズレを防ぐ)。
/// `read`/`write`/`invoke` の本体は括弧で囲んだクロージャ式で与える(`read` は
/// `|self, enc|`、`write` は `|self, data, acc|`、`invoke` は `|self, cmd, fields, resp, acc|`)。
/// `write` に `_`、`invoke` に `_`、`dirty` に `_` を渡すと当該機能を持たないクラスタになる。
///
/// # 例
///
/// ```ignore
/// cluster! {
///     OnOffCluster {
///         id: 0x0006, revision: 6, feature_map: 0,
///         dirty: dirty,
///         invoke: (|c: &mut OnOffCluster, cmd, _f, _r, _a| c.invoke_cmd(cmd)),
///         attributes: [
///             0x0000 OnOff { access: View, quality: [NONVOLATILE, SCENE],
///                            subscribe: true, read: (|c: &OnOffCluster, e| e.write_bool(c.is_on())),
///                            write: _ },
///         ],
///         accepted: [ 0x0000 Off, 0x0001 On, 0x0002 Toggle ],
///         generated: [],
///     }
/// }
/// ```
#[macro_export]
macro_rules! cluster {
    (
        $ty:ty {
            id: $id:literal,
            revision: $rev:literal,
            feature_map: $fmap:literal,
            dirty: $dirty:tt,
            invoke: $invoke:tt,
            attributes: [
                $(
                    $aid:literal $aname:ident {
                        access: $aacc:ident,
                        quality: [ $( $q:ident ),* $(,)? ],
                        subscribe: $asub:literal,
                        read: ( $aread:expr ),
                        write: $awm:tt
                    }
                ),* $(,)?
            ],
            accepted: [ $( $cid:literal $cname:ident ),* $(,)? ],
            generated: [ $( $gid:literal ),* $(,)? ],
        }
    ) => {
        impl $crate::dm::ServerCluster for $ty {
            fn meta(&self) -> &'static $crate::dm::meta::ClusterMeta {
                static META: $crate::dm::meta::ClusterMeta =
                    $crate::dm::meta::ClusterMeta::new(
                        $crate::dm::meta::ClusterId($id),
                        $rev,
                        $fmap,
                        &[ $(
                            $crate::dm::meta::AttributeMeta::new(
                                $crate::dm::meta::AttributeId($aid),
                                $crate::dm::meta::Privilege::$aacc,
                                $crate::dm::meta::Quality::NONE
                                    $( .union($crate::dm::meta::Quality::$q) )*,
                                true,
                                $crate::__attr_writable!($awm),
                                $asub,
                            )
                        ),* ],
                        &[ $(
                            $crate::dm::meta::CommandMeta::new(
                                $crate::dm::meta::CommandId($cid),
                                false,
                                $crate::dm::meta::Privilege::Operate,
                            )
                        ),* ],
                        &[ $( $crate::dm::meta::CommandId($gid) ),* ],
                    );
                &META
            }

            fn read_attribute(
                &self,
                attr: $crate::dm::meta::AttributeId,
                enc: &mut $crate::dm::codec::AttrEncoder<'_, '_>,
            ) -> ::core::result::Result<(), $crate::im::wire::ImStatus> {
                let _ = &enc;
                match attr.0 {
                    $( $aid => ($aread)(self, enc), )*
                    _ => Err($crate::im::wire::ImStatus::UnsupportedAttribute),
                }
            }

            fn write_attribute(
                &mut self,
                attr: $crate::dm::meta::AttributeId,
                data: $crate::tlv::TlvElement<'_>,
                acc: &$crate::dm::meta::AccessContext,
            ) -> ::core::result::Result<(), $crate::im::wire::ImStatus> {
                let _ = (&data, acc);
                match attr.0 {
                    $( $aid => $crate::__cluster_write!($awm, self, data, acc), )*
                    _ => Err($crate::im::wire::ImStatus::UnsupportedWrite),
                }
            }

            fn invoke_command(
                &mut self,
                cmd: $crate::dm::meta::CommandId,
                fields: &mut $crate::tlv::TlvReader<'_>,
                resp: &mut $crate::dm::codec::CmdResponder<'_, '_>,
                acc: &$crate::dm::meta::AccessContext,
            ) -> ::core::result::Result<(), $crate::im::wire::ImStatus> {
                $crate::__cluster_invoke!($invoke, self, cmd, fields, resp, acc)
            }

            fn take_dirty(&mut self) -> bool {
                $crate::__cluster_dirty!($dirty, self)
            }
        }
    };
}

// ==========================================================================
// device! マクロ(合成: DataModel 実装 + メタデータ列挙)
// ==========================================================================

/// (endpoint, cluster) の合成から `DataModel` 実装とメタデータ列挙を生成する(設計 §8.3)。
///
/// `$ty` は各クラスタを**フィールドとして所有する**ユーザ定義 struct。マクロは
/// `impl DataModel for $ty` と、Descriptor 構築用の静的メタ取得関数
/// (`server_list`/`device_types`/`parts`)を生成する。クラスタ構築子は多様なため、
/// struct 定義とフィールド初期化はユーザが行う(設計 §8.3 の「フィールド所有」)。
///
/// # 例
///
/// ```ignore
/// device! {
///     MyLight {
///         endpoint 0 {
///             device_types: [ (0x0016, 1) ], parts: [ 1 ],
///             clusters: [ (0x0028, basic), (0x001D, desc0) ],
///         }
///         endpoint 1 {
///             device_types: [ (0x0100, 3) ], parts: [],
///             clusters: [ (0x0006, on_off), (0x001D, desc1) ],
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! device {
    (
        $ty:ty {
            $(
                endpoint $epid:literal {
                    device_types: [ $( ($dtid:literal, $dtrev:literal) ),* $(,)? ],
                    parts: [ $( $part:literal ),* $(,)? ],
                    clusters: [ $( ($clid:literal, $field:ident) ),* $(,)? ],
                }
            )*
        }
    ) => {
        impl $ty {
            /// エンドポイント `ep` のサーバクラスタ ID 一覧(Descriptor の ServerList)。
            pub fn server_list(ep: $crate::dm::meta::EndpointId) -> &'static [$crate::dm::meta::ClusterId] {
                match ep.0 {
                    $( $epid => {
                        const L: &[$crate::dm::meta::ClusterId] =
                            &[ $( $crate::dm::meta::ClusterId($clid) ),* ];
                        L
                    } )*
                    _ => &[],
                }
            }

            /// エンドポイント `ep` のデバイスタイプ一覧(Descriptor の DeviceTypeList)。
            pub fn device_types(ep: $crate::dm::meta::EndpointId) -> &'static [$crate::dm::meta::DeviceType] {
                match ep.0 {
                    $( $epid => {
                        const L: &[$crate::dm::meta::DeviceType] =
                            &[ $( $crate::dm::meta::DeviceType::new($dtid, $dtrev) ),* ];
                        L
                    } )*
                    _ => &[],
                }
            }

            /// エンドポイント `ep` の子エンドポイント一覧(Descriptor の PartsList)。
            pub fn parts(ep: $crate::dm::meta::EndpointId) -> &'static [$crate::dm::meta::EndpointId] {
                match ep.0 {
                    $( $epid => {
                        const L: &[$crate::dm::meta::EndpointId] =
                            &[ $( $crate::dm::meta::EndpointId($part) ),* ];
                        L
                    } )*
                    _ => &[],
                }
            }
        }

        impl $crate::dm::DataModel for $ty {
            fn endpoints(&self) -> &[$crate::dm::meta::EndpointMeta] {
                static EPS: &[$crate::dm::meta::EndpointMeta] = &[ $(
                    $crate::dm::meta::EndpointMeta::new(
                        $crate::dm::meta::EndpointId($epid),
                        &[ $( $crate::dm::meta::DeviceType::new($dtid, $dtrev) ),* ],
                        &[ $( $crate::dm::meta::ClusterId($clid) ),* ],
                    )
                ),* ];
                EPS
            }

            fn clusters_on(&self, ep: $crate::dm::meta::EndpointId) -> &[$crate::dm::meta::ClusterId] {
                <$ty>::server_list(ep)
            }

            fn cluster(
                &self,
                ep: $crate::dm::meta::EndpointId,
                cl: $crate::dm::meta::ClusterId,
            ) -> Option<&dyn $crate::dm::ServerCluster> {
                match (ep.0, cl.0) {
                    $( $( ($epid, $clid) => Some(&self.$field as &dyn $crate::dm::ServerCluster), )* )*
                    _ => None,
                }
            }

            fn cluster_mut(
                &mut self,
                ep: $crate::dm::meta::EndpointId,
                cl: $crate::dm::meta::ClusterId,
            ) -> Option<&mut dyn $crate::dm::ServerCluster> {
                match (ep.0, cl.0) {
                    $( $( ($epid, $clid) => Some(&mut self.$field as &mut dyn $crate::dm::ServerCluster), )* )*
                    _ => None,
                }
            }
        }
    };
}
