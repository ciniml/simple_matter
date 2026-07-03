//! データモデル層(dm、Matter Data Model / クラスタ)。
//!
//! `docs/design/interaction-model.md` の dm 節に対応する。クラスタのメタデータと
//! read/write/invoke ディスパッチを単一の [`ServerCluster`] 実装が提供し(combined、設計原則5/6)、
//! それらを (endpoint, cluster) で束ねる [`DataModel`] registry を [`device!`](マクロ)が生成する。
//! `im` エンジン(次ピース)は本層の [`DataModel`] trait だけに依存する。
//!
//! # 構成
//!
//! - [`meta`] — ID 新型・メタデータ型(`ClusterMeta`/`AttributeMeta`/`CommandMeta`)・
//!   グローバル属性 ID・アクセス制御型。ID 新型はここが正典で `im::wire` は再エクスポート。
//! - [`codec`] — `AttrEncoder`/`CmdResponder`(サイズ会計付き TLV 書き込みラッパ)。
//! - [`cluster`] — [`cluster!`]/[`device!`] マクロ、`Dirty`、グローバル属性の自動導出。
//! - [`expand`] — [`PathExpandCursor`] によるワイルドカード展開カーソル。
//! - [`clusters`] — 具象クラスタ実装(On/Off・Descriptor・Basic Information)。
//!
//! # object-safety
//!
//! [`ServerCluster`] はメソッドにジェネリック/GAT を持たず object-safe。`&dyn ServerCluster` で
//! 合成でき、`no_std`/no-alloc のまま型爆発を避ける(設計原則7、§8.3)。

pub mod cluster;
pub mod clusters;
pub mod codec;
pub mod expand;
pub mod meta;

pub use cluster::{read_global_attribute, Dirty};
pub use expand::PathExpandCursor;

use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, ClusterId, ClusterMeta, CommandId, EndpointId, EndpointMeta,
};
use crate::im::wire::ImStatus;
use crate::tlv::{TlvElement, TlvReader};

/// 1 クラスタの combined 実装(メタデータ列挙 + read/write/invoke dispatch、設計 §7.1)。
///
/// メソッドにジェネリック/GAT を持たないため object-safe で、`&dyn ServerCluster` として
/// 合成できる。グローバル属性はエンジンが [`read_global_attribute`] で自動導出するため、
/// [`ServerCluster::read_attribute`] は固有属性のみを扱う。
///
/// read/write/invoke は `Result<_, ImStatus>` を返し、クラスタが意味的ステータスを直接選べる。
pub trait ServerCluster {
    /// クラスタの静的メタデータ(グローバル属性を除く)。
    fn meta(&self) -> &'static ClusterMeta;

    /// 固有属性 `attr` の値を `enc` に書く。未知属性は [`ImStatus::UnsupportedAttribute`]。
    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
    ) -> Result<(), ImStatus>;

    /// 固有属性 `attr` に `data` を書き込む。既定は [`ImStatus::UnsupportedWrite`]。
    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: TlvElement<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let _ = (attr, data, acc);
        Err(ImStatus::UnsupportedWrite)
    }

    /// コマンド `cmd` を起動する。生成レスポンスは `resp` に書く。
    /// 既定は [`ImStatus::UnsupportedCommand`]。
    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let _ = (cmd, fields, resp, acc);
        Err(ImStatus::UnsupportedCommand)
    }

    /// 前回呼び出し以降にこのクラスタの属性が変更されたかを返してクリアする(Subscribe 用)。
    /// 既定は常に `false`(状態を持たないクラスタ)。
    fn take_dirty(&mut self) -> bool {
        false
    }
}

/// エンドポイント/クラスタの registry(設計 §7.1、chip `DataModel::Provider` 相当)。
///
/// IM エンジンはこの trait だけに依存する。[`device!`](マクロ)が実装を生成する。
pub trait DataModel {
    /// エンドポイント一覧(メタデータ列挙・ワイルドカード展開の起点)。
    fn endpoints(&self) -> &[EndpointMeta];

    /// `ep` に載るサーバクラスタ ID 一覧(Descriptor の ServerList / 展開に使う)。
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId];

    /// (ep, cl) → クラスタの共有ビュー(read / メタ / 列挙)。無ければ `None`。
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster>;

    /// (ep, cl) → クラスタの可変ビュー(write / invoke)。無ければ `None`。
    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster>;
}

#[cfg(test)]
mod tests;
