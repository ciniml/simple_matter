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

use crate::acl::AclHandle;
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, ClusterId, ClusterMeta, CommandId, EndpointId, EndpointMeta,
};
use crate::error::Error;
use crate::im::wire::ImStatus;
use crate::tlv::{TlvElement, TlvReader};

/// list 属性書き込みの操作種別(`docs/design/acl.md` §4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOp {
    /// 値全体で置き換える(パスに ListIndex 無し。スカラー属性は常にこれ)。
    ReplaceAll,
    /// 1 要素を追記する(パスの ListIndex = null。chip の chunked list write)。
    AppendItem,
}

/// 属性書き込みのデータビュー(値サブツリー全体の生 TLV + list 操作)。
///
/// 従来の `TlvElement`(先頭要素のみ)ではコンテナ(list 属性)の中身を辿れないため、
/// 生スライスを渡してクラスタが自分で [`TlvReader`] で iterate できるようにする。
#[derive(Debug, Clone, Copy)]
pub struct AttrWrite<'a> {
    /// 値要素の生 TLV(元のタグ込み・サブツリー全体)。
    pub raw: &'a [u8],
    /// list 操作種別。
    pub op: ListOp,
}

impl<'a> AttrWrite<'a> {
    /// 生 TLV から作る(操作は [`ListOp::ReplaceAll`])。
    pub const fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            op: ListOp::ReplaceAll,
        }
    }

    /// 操作種別を差し替えた複製を返す。
    pub const fn with_op(mut self, op: ListOp) -> Self {
        self.op = op;
        self
    }

    /// 値を読む [`TlvReader`](先頭が値要素)。
    pub fn reader(&self) -> TlvReader<'a> {
        TlvReader::new(self.raw)
    }

    /// 先頭の値要素を返す(スカラー属性用)。
    pub fn element(&self) -> Result<TlvElement<'a>, ImStatus> {
        self.reader()
            .read_next()
            .ok()
            .flatten()
            .ok_or(ImStatus::InvalidDataType)
    }

    /// 先頭要素を符号なし整数として読む(スカラー属性の便宜)。
    pub fn as_unsigned(&self) -> Result<u64, ImStatus> {
        self.element()?
            .value
            .as_unsigned()
            .map_err(|_| ImStatus::InvalidDataType)
    }

    /// 先頭要素を真偽値として読む。
    pub fn as_bool(&self) -> Result<bool, ImStatus> {
        self.element()?
            .value
            .as_bool()
            .map_err(|_| ImStatus::InvalidDataType)
    }

    /// 先頭要素を UTF-8 文字列として読む。
    pub fn as_str(&self) -> Result<&'a str, ImStatus> {
        self.element()?
            .value
            .as_str()
            .map_err(|_| ImStatus::InvalidDataType)
    }
}

/// [`crate::Error`] を書き込み系の [`ImStatus`] へ写像する(クラスタ実装の便宜)。
pub fn map_write_err(e: Error) -> ImStatus {
    match e {
        Error::NoSpace => ImStatus::ResourceExhausted,
        Error::Decode => ImStatus::ConstraintError,
        _ => ImStatus::Failure,
    }
}

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
    ///
    /// `acc` は fabric-scoped 属性(OpCreds の CurrentFabricIndex、ACL の fabric フィルタ等)
    /// のために渡す。多くのクラスタは無視してよい。
    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus>;

    /// 固有属性 `attr` に `data` を書き込む。既定は [`ImStatus::UnsupportedWrite`]。
    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: AttrWrite<'_>,
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

    /// 時間駆動のデバイス内部処理(fail-safe 期限切れ等)を進める。
    ///
    /// 統合層([`crate::stack`])が `poll`/`handle_rx` の度に呼ぶ。既定は何もしない
    /// (no-op)。fail-safe タイマ(General Commissioning)を持つデバイスは、この既定を
    /// 上書きして `GeneralCommissioning::on_tick` と `OpCredsCluster::on_failsafe_expired`
    /// を配線する。[`device!`](crate::device) マクロが生成する実装は既定のまま(汎用的に
    /// どのクラスタが fail-safe を持つか判定できないため、乖離。手書き `DataModel` 実装で
    /// 配線するか、将来の `device!` 拡張で対応)。返り値は次に処理すべき絶対時刻(あれば)。
    fn on_tick(&mut self, _now_ms: u64) -> Option<u64> {
        None
    }

    /// このデバイスの ACL(`docs/design/acl.md` §3)。
    ///
    /// `Some` を返すデバイスは IM エンジンが full ACL(per-entry 照合)で権限判定する。
    /// 既定の `None` は従来近似(PASE=コミッショニングクラスタのみ、CASE=Administer 相当)
    /// にフォールバックする(ACL クラスタを持たない最小デバイス/テスト用)。
    fn acl(&self) -> Option<&dyn AclHandle> {
        None
    }
}

#[cfg(test)]
mod tests;
