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

pub use cluster::{read_global_attribute, tick_clusters, Dirty};
pub use expand::PathExpandCursor;

use crate::acl::AclHandle;
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, ClusterId, ClusterMeta, CommandId, EndpointId, EndpointMeta,
};
use crate::error::Error;
use crate::im::wire::ImStatus;
use crate::tlv::{TlvElement, TlvReader, TlvValue};

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

    /// 先頭要素を符号付き整数として読む(i16 setpoint 等。設計 §15.2)。
    pub fn as_i64(&self) -> Result<i64, ImStatus> {
        self.element()?
            .value
            .as_signed()
            .map_err(|_| ImStatus::InvalidDataType)
    }

    /// 先頭要素が null かを返す(nullable 属性の write 判定。設計 §15.2)。
    pub fn is_null(&self) -> bool {
        matches!(self.element(), Ok(e) if matches!(e.value, TlvValue::Null))
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

    /// 時間駆動フック(設計 §15.1)。`now_ms` 時点でクラスタ内部状態を進め、次に呼んでほしい
    /// 絶対時刻(あれば)を返す。Level Control の TransitionTime 遷移のように、invoke 後も
    /// 時間とともに属性が変わるクラスタが実装する。既定は no-op(`None`)で object-safe を保つ。
    ///
    /// 駆動源は統合層([`crate::stack`])の `on_tick`(→ [`tick_clusters`](crate::dm::tick_clusters))。
    fn tick(&mut self, now_ms: u64) -> Option<u64> {
        let _ = now_ms;
        None
    }

    /// **遅延 InvokeResponse** の完了を問い合わせる(設計 `port-esp32-device.md` §E7.1)。
    ///
    /// 直前の [`invoke_command`](ServerCluster::invoke_command) が
    /// [`CmdResponder::set_deferred`](crate::dm::codec::CmdResponder::set_deferred) を立てた
    /// コマンド `command` について、IM エンジンが poll のたびに呼ぶ。まだ完了していなければ
    /// [`DeferredPoll::Pending`]、完了したら通常の invoke と同じく `resp` に生成レスポンス
    /// (`set_response`+フィールド)または status を書いて
    /// [`DeferredPoll::Ready`] を返す。`Ready` に添える `Result` は invoke_command と同じ意味
    /// (`Ok(())`=生成レスポンス/成功、`Err(status)`=CommandStatusIB)。
    ///
    /// 既定は `Ready(Err(Failure))`(応答を保留しない既存クラスタは呼ばれないため無影響)。
    fn poll_deferred(
        &mut self,
        command: CommandId,
        resp: &mut CmdResponder<'_, '_>,
    ) -> DeferredPoll {
        let _ = (command, resp);
        DeferredPoll::Ready(Err(ImStatus::Failure))
    }
}

/// [`ServerCluster::poll_deferred`] の結果(設計 `port-esp32-device.md` §E7.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredPoll {
    /// まだ完了していない。IM エンジンは締切まで再度 poll する。
    Pending,
    /// 応答準備完了。`resp` に書いた内容(生成レスポンス or status)で InvokeResponse を組む。
    /// `Ok(())` は生成レスポンス(または単純 Success)、`Err(status)` は CommandStatusIB。
    Ready(core::result::Result<(), ImStatus>),
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
    ///
    /// 既定実装は全 (endpoint, cluster) の [`ServerCluster::tick`] を走査する
    /// [`tick_clusters`] を呼ぶ(設計 §15.1)。これで `device!` 生成のデバイスと
    /// 「on_tick を上書きしない」デバイスは自動でクラスタ tick が回る。on_tick を上書きする
    /// 手書きデバイス(fail-safe/窓の手動配線がある例)は自分で `tick_clusters` も呼ぶ。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        tick_clusters(self, now_ms)
    }

    /// ArmFailSafe(0) 受信時の仕様準拠 fail-safe クリーンアップ(Core Spec §11.10)。
    ///
    /// IM エンジンが invoke の副作用として呼ぶ。実装は General Commissioning の fail-safe を
    /// 解除し、Operational Credentials の
    /// [`on_failsafe_expired`](crate::dm::clusters::OpCredsCluster::on_failsafe_expired) で
    /// pending を破棄しつつ未 CommissioningComplete の fabric を削除し、その index を返す
    /// (fail-safe を持つデバイスが上書き実装する)。返した index の ACL エントリとセッションは
    /// エンジン/統合層が掃除する。既定は `None`(fail-safe を持たないデバイス)。
    fn on_failsafe_cleanup(&mut self) -> Option<core::num::NonZeroU8> {
        None
    }

    /// CommissioningComplete 成功時のフック(Core Spec §11.10)。
    ///
    /// fail-safe 中に追加した fabric を確定し、以降の fail-safe クリーンアップで巻き戻さない
    /// ようにする(OpCreds の
    /// [`on_commissioning_complete`](crate::dm::clusters::OpCredsCluster::on_commissioning_complete)
    /// へ配線)。既定は no-op。
    fn on_commissioning_complete(&mut self) {}

    /// fail-safe タイマ経過([`on_tick`](DataModel::on_tick))で削除した fabric index を取り出す。
    ///
    /// タイマ経過は返り値でしか index を運べないため、アプリの `on_tick` がフィールドに退避し、
    /// 統合層([`crate::stack`])が本メソッドで回収して ACL / セッションを掃除する。既定は `None`。
    fn take_removed_fabric(&mut self) -> Option<core::num::NonZeroU8> {
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

    /// `(fabric, group_id)` に所属する endpoint を `idx` 順に返す
    /// (`docs/design/group-messaging.md` §5.2/§6)。
    ///
    /// groupcast invoke の配送先展開に使う。group 対応デバイスは共有
    /// [`GroupStore`](crate::groups::GroupStore) の `member_endpoints` へ委譲して
    /// 上書き実装する。既定の `None` は「group メンバーシップなし」(groupcast は
    /// どの endpoint にも配送されない)。
    fn group_endpoints(
        &self,
        fabric: core::num::NonZeroU8,
        group_id: u16,
        idx: usize,
    ) -> Option<EndpointId> {
        let _ = (fabric, group_id, idx);
        None
    }
}

#[cfg(test)]
mod tests;
