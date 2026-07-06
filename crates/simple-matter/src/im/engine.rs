//! Interaction Model エンジン(server 側トランザクション処理、`docs/design/interaction-model.md` §4–§11)。
//!
//! [`InteractionModel`] は Protocol ID 0x0001 の [`ProtocolHandler`] を実装し、`im::wire`
//! (メッセージ codec)と `dm::DataModel`(クラスタ registry)を配線する。設計の中核判断に従う:
//!
//! - **単一型パラメータ** `D: DataModel`(+ サイジング const generic `READS`/`SUBS`/`PATHS`)。
//!   クラスタを増やしても `im`/`exchange`/`transport` のシグネチャは不変(型消去境界 =
//!   `ProtocolHandler`、設計 §8.3)。
//! - **チャンク化 ReportData** と **Subscribe プライミング** を `ExchangeId` キーの
//!   [`ReadTxn`] slot で表現する(1 チャンク = 1 回の同期 `handle`、続きは client の
//!   `StatusResponse(SUCCESS)` 受信で駆動、設計 §5/§6)。展開位置は `Copy` な
//!   [`PathExpandCursor`] で保持する。
//! - **Subscribe の定期レポート**は受信駆動の `handle` から出せないため、IM 独自の駆動 API
//!   [`InteractionModel::next_deadline`] / [`InteractionModel::poll_subscriptions`] /
//!   [`InteractionModel::build_report`] を設け、統合層が `ExchangeManager` の送信 API と
//!   組み合わせる(設計 §6.3)。
//!
//! # 設計ドキュメントからの乖離(理由付き)
//!
//! - **単一ファイル集約**: 設計 §1 は `engine/{read,write,invoke,subscribe,timed}.rs` に分割するが、
//!   `im::wire` が単一ファイルに集約されているのと同じ理由(状態機械とタグ処理を 1 か所で
//!   見通す)で本エンジンも単一 [`engine`](自身)にまとめた。分割は将来可能。
//! - **チャンク境界の道具**: 設計 §5.4 は `AttrEncoder` にロールバックを持たせる想定だが、
//!   実装済み `dm::codec::AttrEncoder` はロールバックを持たない(意図的に IM へ委譲)。本エンジンは
//!   `im::wire::ReportChunkBuilder`([`TlvWriter::checkpoint`](crate::tlv::TlvWriter)ベース)で
//!   「試し書き→巻き戻し」を行う。
//! - **ACL**: `DataModel::acl` が `Some` のデバイスは full ACL(per-entry 照合、
//!   `docs/design/acl.md`)で判定する。`None` のデバイスは従来の最小近似(設計 §10:
//!   CASE = fabric メンバに Administer 相当、PASE = コミッショニング必須クラスタのみ許可)に
//!   フォールバックする。`DataModel::take_dirty` は実装済み trait に無いため、[`InteractionModel::poll_subscriptions`]
//!   が (endpoint, cluster) を走査して各クラスタの [`ServerCluster::take_dirty`](crate::dm::ServerCluster)
//!   を集約する(設計 §6.2 の意図を trait 変更なしで実現)。
//! - **DataVersion は単一共有カウンタ**: レポートの AttributeDataIB には DataVersion を必ず付与する
//!   (chip 系コントローラの ClusterStateCache が要求)。ただしクラスタ毎の管理はせず、エンジン全体で
//!   単一の単調カウンタを共有する(構造体フィールドの doc 参照)。リクエストの DataVersionFilter は
//!   非対応で、dirty クラスタに交差する購読はパス全体を再送する(設計 §6.2 の初期スコープ)。

use core::num::NonZeroU8;

use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    is_global_attribute, AccessContext, ClusterId, EndpointId, Privilege, SessionKind,
};
use crate::dm::{read_global_attribute, AttrWrite, DataModel, ListOp};
use crate::error::{Error, Result};
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, RxMessage};
use crate::im::wire::{
    encode_invoke_response, encode_write_response, transcribe, AttributeDataRef, AttributePath,
    CmdRespWriter, CommandDataRef, CommandPath, ConcreteAttrPath, ImOpCode, ImStatus,
    InvokeRequestRef, InvokeResponseHeader, ReadRequestRef, ReportChunkBuilder, StatusIB,
    StatusResponse, SubscribeRequestRef, SubscribeResponse, TimedRequest, WriteRequestRef,
    PROTO_ID_INTERACTION_MODEL,
};
use crate::tlv::{TlvReader, TlvWriter};
use crate::transport::session::fixed::FixedVec;
use crate::transport::session::{SessionId, SessionManager, SessionMode};

use crate::dm::expand::PathExpandCursor;

/// 放置されたチャンク中 Read トランザクションを掃除するまでの時間(ミリ秒)。
const READ_TXN_TIMEOUT_MS: u64 = 30_000;

/// dirty 掃引で 1 回に走査する (endpoint, cluster) の上限。
const MAX_SWEEP: usize = 64;

/// Invoke の生成レスポンスフィールドを一時構築するスクラッチバッファ長。
///
/// Operational Credentials の AttestationResponse(AttestationElements = CD(CMS、
/// chip 開発用は 541B)+ nonce + timestamp、に署名 64B が付く)が最大で、
/// これに収まる大きさとする(仕様の RESP_MAX = 900B が上限の目安)。
const INVOKE_SCRATCH: usize = 900;

/// PASE セッションからアクセス可能なコミッショニング必須クラスタか(設計 §10.1)。
///
/// **従来近似(`DataModel::acl` が `None`)専用**。full ACL では PASE は implicit
/// Administer(全クラスタ)になる(`docs/design/acl.md` §3)。
const fn is_commissioning_cluster(cl: ClusterId) -> bool {
    matches!(cl.0, 0x0028 | 0x0030 | 0x0031 | 0x003E)
}

/// アクセス `acc` が (ep, cl) へ `required` 権限を持つか(`docs/design/acl.md` §3)。
///
/// `DataModel::acl` が `Some` なら full ACL(per-entry 照合)、`None` なら従来近似
/// (PASE = コミッショニングクラスタのみ、CASE = セッション付与権限)で判定する。
fn allowed<D: DataModel + ?Sized>(
    dm: &D,
    acc: &AccessContext,
    ep: EndpointId,
    cl: ClusterId,
    required: Privilege,
) -> bool {
    match dm.acl() {
        Some(a) => a.check(acc, ep, cl, required),
        None => match acc.kind {
            SessionKind::Pase => is_commissioning_cluster(cl),
            SessionKind::Case => acc.has_privilege(required),
        },
    }
}

/// [`HandlerAction::Respond`] を IM 応答として組む。
fn respond(opcode: ImOpCode, reliable: bool, len: usize) -> HandlerAction {
    HandlerAction::Respond {
        opcode: opcode.to_u8(),
        proto_id: PROTO_ID_INTERACTION_MODEL,
        reliable,
        len,
    }
}

/// [`HandlerAction::Close`] を IM 応答(終端)として組む。
fn close(opcode: ImOpCode, reliable: bool, len: usize) -> HandlerAction {
    HandlerAction::Close {
        opcode: opcode.to_u8(),
        proto_id: PROTO_ID_INTERACTION_MODEL,
        reliable,
        len,
    }
}

/// StatusResponse を `tx` に書いて終端アクションを返す。
fn status_response(tx: &mut [u8], status: ImStatus) -> Result<HandlerAction> {
    let len = StatusResponse::new(status).encode(tx)?;
    Ok(close(ImOpCode::StatusResponse, true, len))
}

/// セッションからアクセス文脈を導く(設計 §10 / `docs/design/acl.md` §5)。
///
/// IM は暗号セッション必須のため、PlainText は [`Error::InvalidState`]。CASE は subject
/// NodeId と peer CAT をセッションから写す。`privilege` フィールドの Administer は
/// 従来近似(`DataModel::acl` == None)経路でのみ使われる。
fn access_from_session<const S: usize>(
    sessions: &SessionManager<S>,
    session: SessionId,
    now_ms: u64,
) -> Result<AccessContext> {
    let s = sessions.get(session).ok_or(Error::InvalidState)?;
    let challenge = s.att_challenge().copied().unwrap_or([0u8; 16]);
    let base = match s.mode() {
        SessionMode::PlainText => return Err(Error::InvalidState),
        // PASE は原則 fabric 未確定(None)だが、AddNOC で昇格済みなら確定 fabric を反映する。
        SessionMode::Pase { fabric_idx } => AccessContext::new(
            SessionKind::Pase,
            NonZeroU8::new(fabric_idx),
            0,
            Privilege::Administer,
        ),
        SessionMode::Case { fabric_idx } => AccessContext::new(
            SessionKind::Case,
            Some(fabric_idx),
            s.peer_node_id().unwrap_or(0),
            Privilege::Administer,
        )
        .with_cats(s.peer_cats()),
    };
    Ok(base.with_env(now_ms, challenge))
}

/// 具象パスの存在確認。存在すれば `None`、無ければ適切な IM Status(設計 §5.2)。
fn resolve_concrete_status<D: DataModel + ?Sized>(
    dm: &D,
    cp: ConcreteAttrPath,
) -> Option<ImStatus> {
    if !dm.endpoints().iter().any(|e| e.id == cp.endpoint) {
        return Some(ImStatus::UnsupportedEndpoint);
    }
    let Some(cluster) = dm.cluster(cp.endpoint, cp.cluster) else {
        return Some(ImStatus::UnsupportedCluster);
    };
    if is_global_attribute(cp.attribute) {
        return None;
    }
    if cluster.meta().attribute(cp.attribute).is_none() {
        return Some(ImStatus::UnsupportedAttribute);
    }
    None
}

// ==========================================================================
// トランザクション種別 / slot
// ==========================================================================

/// Read 継続 slot の種別。
#[derive(Debug, Clone, Copy)]
enum ReadKind {
    /// 通常の Read(最終チャンクは SuppressResponse=true で終端)。
    Read,
    /// Subscribe プライミング(最終チャンク後の StatusResponse で SubscribeResponse を送る)。
    Priming(u32),
    /// device 発の購読レポート継続(subscription_id を載せる)。
    Report(u32),
}

/// チャンク生成の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkOutcome {
    /// 全パス消化(MoreChunkedMessages 無し)。
    Done,
    /// バッファ満杯で打ち切り(MoreChunkedMessages=true、続きは次の handle)。
    More,
}

/// チャンク中 Read / プライミング / レポート継続の再開状態(設計 §5.3)。
struct ReadTxn<const P: usize> {
    /// 索引キー(このトランザクションを運ぶ exchange)。
    exchange: ExchangeId,
    /// アクセス文脈(継続チャンクでも同じ判定を使う)。
    acc: AccessContext,
    /// トランザクション種別。
    kind: ReadKind,
    /// リクエストのパス列(チャンクをまたいで保持)。
    paths: [AttributePath; P],
    /// `paths` の有効長。
    npaths: usize,
    /// ワイルドカード展開の再開カーソル(`Copy`)。
    cursor: PathExpandCursor,
    /// 具象パスの存在チェック(precheck)を済ませたか。
    prechecked: bool,
    /// プライミングのレポート送信を完了し SubscribeResponse 待ちか。
    priming_reports_done: bool,
    /// 開始時刻(タイムアウト掃除用)。
    started_ms: u64,
}

impl<const P: usize> ReadTxn<P> {
    fn new(exchange: ExchangeId, acc: AccessContext, kind: ReadKind, now_ms: u64) -> Self {
        Self {
            exchange,
            acc,
            kind,
            paths: [AttributePath::default(); P],
            npaths: 0,
            cursor: PathExpandCursor::new(),
            prechecked: false,
            priming_reports_done: false,
            started_ms: now_ms,
        }
    }
}

/// 購読の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubState {
    /// プライミング中(まだ Active でない)。
    Priming,
    /// 確立済み。定期/変化レポートの対象。
    Active,
}

/// 確立済み購読エントリ(設計 §6.2)。
struct Subscription<const P: usize> {
    /// 購読 ID。
    id: u32,
    /// 購読者(暗号セッション)。
    session: SessionId,
    /// プライミング時のアクセス文脈(定期レポートの ACL 再評価に使う、
    /// `docs/design/acl.md` §3)。
    acc: AccessContext,
    /// 購読パス列(固定上限)。
    paths: [AttributePath; P],
    /// `paths` の有効長。
    npaths: usize,
    /// 最小レポート間隔(秒)。
    min_interval_s: u16,
    /// 最大レポート間隔(秒)。
    max_interval_s: u16,
    /// 直近レポート時刻。
    last_report_ms: u64,
    /// 前回レポート以降に交差クラスタが変更されたか。
    dirty: bool,
    /// 状態。
    state: SubState,
}

impl<const P: usize> Subscription<P> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u32,
        session: SessionId,
        acc: AccessContext,
        min_interval_s: u16,
        max_interval_s: u16,
        now_ms: u64,
    ) -> Self {
        Self {
            id,
            session,
            acc,
            paths: [AttributePath::default(); P],
            npaths: 0,
            min_interval_s,
            max_interval_s,
            last_report_ms: now_ms,
            dirty: false,
            state: SubState::Priming,
        }
    }
}

/// いずれかの購読パスが (endpoint, cluster) を含むか。
fn sub_covers<const P: usize>(sub: &Subscription<P>, ep: EndpointId, cl: ClusterId) -> bool {
    for i in 0..sub.npaths {
        let p = &sub.paths[i];
        let ep_ok = match p.endpoint {
            Some(e) => e == ep,
            None => true,
        };
        let cl_ok = match p.cluster {
            Some(c) => c == cl,
            None => true,
        };
        if ep_ok && cl_ok {
            return true;
        }
    }
    false
}

/// TimedRequest による後続 Write/Invoke の期限(設計 §5.5)。
#[derive(Debug, Clone, Copy)]
struct TimedTxn {
    /// 対応する exchange。
    exchange: ExchangeId,
    /// 期限(絶対時刻ミリ秒)。
    deadline_ms: u64,
}

/// poll で「レポートすべき」と判定された購読(統合層へ返す、設計 §6.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubDue {
    /// 対象購読 ID。
    pub subscription: u32,
    /// 購読者セッション(統合層が `open_initiator` に使う)。
    pub session: SessionId,
}

// ==========================================================================
// チャンク生成(read_open / on_status / build_report の共通処理)
// ==========================================================================

/// `txn` の展開を進め、1 チャンク分の AttributeReportIB を `builder` に書く(設計 §5.4)。
///
/// 具象で存在しないパスは先頭で StatusIB を出し(precheck、1 回のみ)、以降はカーソルで
/// endpoint→cluster→attribute 昇順に展開する。1 属性が入らなければ巻き戻して打ち切り
/// ([`ChunkOutcome::More`])、全消化で [`ChunkOutcome::Done`]。
fn emit_chunk<D: DataModel + ?Sized, const P: usize>(
    dm: &D,
    txn: &mut ReadTxn<P>,
    builder: &mut ReportChunkBuilder<'_>,
    data_version: u32,
) -> Result<ChunkOutcome> {
    if !txn.prechecked {
        txn.prechecked = true;
        for i in 0..txn.npaths {
            let p = txn.paths[i];
            if let Some(cp) = p.to_concrete() {
                if let Some(st) = resolve_concrete_status(dm, cp) {
                    let _ = builder.try_push_status(&p, &StatusIB::simple(st))?;
                }
            }
        }
    }

    loop {
        let mut probe = txn.cursor;
        let Some((cpath, meta)) = probe.next(dm, &txn.paths[..txn.npaths]) else {
            return Ok(ChunkOutcome::Done);
        };
        let Some(cluster) = dm.cluster(cpath.endpoint, cpath.cluster) else {
            // 展開中に消えた等。スキップして前進。
            txn.cursor = probe;
            continue;
        };
        let wire = cpath.to_wire();

        // 属性 read の必要権限はメタの access(グローバル属性の合成メタは View)。
        let denied = !allowed(dm, &txn.acc, cpath.endpoint, cpath.cluster, meta.access);

        let fit = if denied || !meta.readable {
            let st = if denied {
                ImStatus::UnsupportedAccess
            } else {
                ImStatus::UnsupportedRead
            };
            let f = builder.try_push_status(&wire, &StatusIB::simple(st))?;
            if !f && !builder.is_empty() {
                return Ok(ChunkOutcome::More);
            }
            true
        } else {
            let mut read_err: Option<ImStatus> = None;
            let f = builder.try_push_data(Some(data_version), &wire, |w, tag| {
                let mut enc = AttrEncoder::new(w, *tag);
                let r = if is_global_attribute(cpath.attribute) {
                    read_global_attribute(cluster.meta(), cpath.attribute, &mut enc)
                } else {
                    cluster.read_attribute(cpath.attribute, &mut enc, &txn.acc)
                };
                match r {
                    Ok(()) => Ok(()),
                    Err(s) => {
                        read_err = Some(s);
                        Err(Error::NoSpace)
                    }
                }
            })?;
            if !f {
                if builder.is_empty() {
                    // 単一属性が空チャンクにも入らない(または read エラー)→ StatusIB を出して前進。
                    let st = read_err.unwrap_or(ImStatus::ResourceExhausted);
                    let _ = builder.try_push_status(&wire, &StatusIB::simple(st))?;
                    txn.cursor = probe;
                    continue;
                }
                return Ok(ChunkOutcome::More);
            }
            true
        };

        if fit {
            txn.cursor = probe;
        }
    }
}

// ==========================================================================
// InteractionModel(ProtocolHandler)
// ==========================================================================

/// Interaction Model エンジン(Protocol ID 0x0001、設計 §4)。
///
/// 型パラメータ `D` はデバイスの [`DataModel`] 実装(`device!` マクロが生成)。const generic は
/// サイジング(設計 §11):`READS` = 同時進行のチャンク中 Read + プライミング数、`SUBS` =
/// 確立済み購読数、`PATHS` = 1 リクエスト/購読あたりのパス数上限。
pub struct InteractionModel<D: DataModel, const READS: usize, const SUBS: usize, const PATHS: usize>
{
    dm: D,
    reads: FixedVec<ReadTxn<PATHS>, READS>,
    subs: FixedVec<Subscription<PATHS>, SUBS>,
    timed: FixedVec<TimedTxn, READS>,
    next_sub_id: u32,
    /// レポートの AttributeDataIB に付与する DataVersion。
    ///
    /// 仕様上サーバのレポートには DataVersion が必須で、chip 系コントローラの
    /// ClusterStateCache は DataVersion の無いデータをキャッシュに載せない。
    /// 本実装はクラスタ毎ではなく単一の単調カウンタを共有する(変更のたびに
    /// 全クラスタの version が進む)。仕様の要件「クラスタのデータ変更で version が
    /// 変わる」は満たし、無関係な変更でも version が進む分はコントローラ側の
    /// キャッシュ効率が下がるだけで正しさには影響しない。
    data_version: u32,
}

impl<D: DataModel, const READS: usize, const SUBS: usize, const PATHS: usize>
    InteractionModel<D, READS, SUBS, PATHS>
{
    /// データモデルを与えてエンジンを生成する。
    pub fn new(dm: D) -> Self {
        Self {
            dm,
            reads: FixedVec::new(),
            subs: FixedVec::new(),
            timed: FixedVec::new(),
            next_sub_id: 1,
            data_version: 1,
        }
    }

    /// データモデルへの共有参照(アプリからの属性読み取り等)。
    pub const fn data_model(&self) -> &D {
        &self.dm
    }

    /// データモデルへの可変参照(アプリからの状態変更。dirty はクラスタが立てる)。
    pub fn data_model_mut(&mut self) -> &mut D {
        &mut self.dm
    }

    /// 確立中/確立済みの購読数。
    pub fn subscription_count(&self) -> usize {
        self.subs.len()
    }

    /// 進行中のチャンク中 Read / プライミング数。
    pub fn active_read_count(&self) -> usize {
        self.reads.len()
    }

    /// 新しい購読 ID を採番する(0 は避ける)。
    fn alloc_sub_id(&mut self) -> u32 {
        let id = self.next_sub_id;
        self.next_sub_id = self.next_sub_id.wrapping_add(1);
        if self.next_sub_id == 0 {
            self.next_sub_id = 1;
        }
        id
    }

    // ----------------------------------------------------------------------
    // Read(§5)
    // ----------------------------------------------------------------------

    fn read_open(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        acc: &AccessContext,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let req = ReadRequestRef::new(rx.payload)?;
        let acc = acc.with_fabric_filtered(req.fabric_filtered().unwrap_or(false));
        let mut txn = ReadTxn::<PATHS>::new(rx.exchange, acc, ReadKind::Read, now_ms);
        for p in req.attr_paths()? {
            let p = p?;
            if txn.npaths >= PATHS {
                return status_response(tx, ImStatus::PathsExhausted);
            }
            txn.paths[txn.npaths] = p;
            txn.npaths += 1;
        }

        let outcome;
        let len;
        {
            let mut builder = ReportChunkBuilder::new(tx, None)?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            len = match outcome {
                ChunkOutcome::Done => builder.finish(false, true)?,
                ChunkOutcome::More => builder.finish(true, false)?,
            };
        }

        match outcome {
            ChunkOutcome::Done => Ok(close(ImOpCode::ReportData, true, len)),
            ChunkOutcome::More => {
                if self.reads.push(txn).is_err() {
                    return status_response(tx, ImStatus::ResourceExhausted);
                }
                Ok(respond(ImOpCode::ReportData, true, len))
            }
        }
    }

    // ----------------------------------------------------------------------
    // Subscribe(§6.1 プライミング)
    // ----------------------------------------------------------------------

    fn subscribe_open(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        acc: &AccessContext,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        if self.subs.is_full() || self.reads.is_full() {
            return status_response(tx, ImStatus::ResourceExhausted);
        }
        let req = SubscribeRequestRef::new(rx.payload)?;
        let acc = &acc.with_fabric_filtered(req.fabric_filtered().unwrap_or(false));
        let min = req.min_interval_floor_s()?;
        let max = req.max_interval_ceiling_s()?;
        // ネゴシエート: 上限を採用しつつ min 以上・最低 1 秒にクランプ。
        let max_neg = max.max(min).max(1);

        let id = self.alloc_sub_id();
        let mut sub = Subscription::<PATHS>::new(
            id,
            rx.exchange.session(),
            *acc,
            min,
            max_neg,
            now_ms,
        );
        let mut txn = ReadTxn::<PATHS>::new(rx.exchange, *acc, ReadKind::Priming(id), now_ms);
        for p in req.attr_paths()? {
            let p = p?;
            if sub.npaths >= PATHS {
                break;
            }
            sub.paths[sub.npaths] = p;
            sub.npaths += 1;
            txn.paths[txn.npaths] = p;
            txn.npaths += 1;
        }

        let outcome;
        let len;
        {
            let mut builder = ReportChunkBuilder::new(tx, None)?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            len = match outcome {
                ChunkOutcome::Done => {
                    txn.priming_reports_done = true;
                    builder.finish(false, false)?
                }
                ChunkOutcome::More => builder.finish(true, false)?,
            };
        }

        if self.subs.push(sub).is_err() {
            return status_response(tx, ImStatus::ResourceExhausted);
        }
        if self.reads.push(txn).is_err() {
            let ridx = self.subs.iter().position(|s| s.id == id);
            if let Some(i) = ridx {
                self.subs.swap_remove(i);
            }
            return status_response(tx, ImStatus::ResourceExhausted);
        }
        Ok(respond(ImOpCode::ReportData, true, len))
    }

    // ----------------------------------------------------------------------
    // StatusResponse(チャンク継続 / プライミング完了、§5.4/§6.1)
    // ----------------------------------------------------------------------

    fn on_status(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let sr = StatusResponse::decode(rx.payload)?;
        let Some(idx) = self.reads.iter().position(|t| t.exchange == rx.exchange) else {
            // 継続 slot が無い(完了済みトランザクションへの ACK 等)→ 無視。
            return Ok(HandlerAction::None);
        };
        if !sr.status.is_success() {
            self.reads.swap_remove(idx);
            return Ok(HandlerAction::None);
        }

        // プライミングのレポート送信が完了していれば SubscribeResponse を返す。
        let kind = self.reads[idx].kind;
        if let ReadKind::Priming(id) = kind {
            if self.reads[idx].priming_reports_done {
                let max_interval = self
                    .subs
                    .iter()
                    .find(|s| s.id == id)
                    .map(|s| s.max_interval_s)
                    .unwrap_or(0);
                let len = SubscribeResponse::new(id, max_interval).encode(tx)?;
                self.activate_subscription(id, now_ms);
                self.reads.swap_remove(idx);
                return Ok(close(ImOpCode::SubscribeResponse, true, len));
            }
        }

        // それ以外は次チャンクを送る。
        let outcome;
        let len;
        {
            let dv = self.data_version;
            let dm = &self.dm;
            let txn = &mut self.reads[idx];
            let sub_id = match txn.kind {
                ReadKind::Report(id) => Some(id),
                _ => None,
            };
            let mut builder = ReportChunkBuilder::new(tx, sub_id)?;
            outcome = emit_chunk(dm, txn, &mut builder, dv)?;
            len = match (outcome, txn.kind) {
                (ChunkOutcome::Done, ReadKind::Read) => builder.finish(false, true)?,
                (ChunkOutcome::Done, ReadKind::Priming(_)) => {
                    txn.priming_reports_done = true;
                    builder.finish(false, false)?
                }
                (ChunkOutcome::Done, ReadKind::Report(_)) => builder.finish(false, false)?,
                (ChunkOutcome::More, _) => builder.finish(true, false)?,
            };
        }

        match (outcome, kind) {
            (ChunkOutcome::Done, ReadKind::Read) => {
                self.reads.swap_remove(idx);
                Ok(close(ImOpCode::ReportData, true, len))
            }
            (ChunkOutcome::Done, ReadKind::Priming(_)) => {
                // 最終プライミングレポートを送った。次の StatusResponse で SubscribeResponse。
                Ok(respond(ImOpCode::ReportData, true, len))
            }
            (ChunkOutcome::Done, ReadKind::Report(id)) => {
                self.reads.swap_remove(idx);
                self.mark_reported(id, now_ms);
                Ok(close(ImOpCode::ReportData, true, len))
            }
            (ChunkOutcome::More, _) => Ok(respond(ImOpCode::ReportData, true, len)),
        }
    }

    // ----------------------------------------------------------------------
    // Write(§5.5/§9)
    // ----------------------------------------------------------------------

    fn write(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        acc: &AccessContext,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let req = WriteRequestRef::new(rx.payload)?;
        // 変更系トランザクションが来たら DataVersion を進める(過剰に進む分は無害)。
        self.data_version = self.data_version.wrapping_add(1);
        let suppress = req.suppress_response()?;
        let timed_flag = req.timed_request()?;
        if let Err(st) = self.check_timed(rx.exchange, timed_flag, now_ms) {
            return status_response(tx, st);
        }

        if suppress {
            let dm = &mut self.dm;
            for item in req.write_requests()? {
                let item = item?;
                let _ = write_one(dm, &item, acc);
            }
            return Ok(HandlerAction::None);
        }

        let dm = &mut self.dm;
        let len = encode_write_response(tx, |sw| {
            for item in req.write_requests()? {
                let item = item?;
                let status = write_one(dm, &item, acc);
                sw.push(&item.path, &StatusIB::simple(status))?;
            }
            Ok(())
        })?;
        Ok(close(ImOpCode::WriteResponse, true, len))
    }

    // ----------------------------------------------------------------------
    // Invoke(§5.5/§9)
    // ----------------------------------------------------------------------

    fn invoke<const SN: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        acc: &AccessContext,
        sessions: &mut SessionManager<SN>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let req = InvokeRequestRef::new(rx.payload)?;
        // コマンドは状態を変えうるため DataVersion を進める(過剰に進む分は無害)。
        self.data_version = self.data_version.wrapping_add(1);
        let suppress = req.suppress_response()?;
        let timed_flag = req.timed_request()?;
        if let Err(st) = self.check_timed(rx.exchange, timed_flag, now_ms) {
            return status_response(tx, st);
        }

        let session = rx.exchange.session();
        let header = InvokeResponseHeader {
            suppress_response: false,
            more_chunks: false,
        };
        let mut effects = InvokeEffects::default();

        if suppress {
            // 応答は送らないが副作用(および AddNOC の fabric 昇格)は適用する。
            // `tx` をスクラッチとして使い、生成結果は破棄する。
            let dm = &mut self.dm;
            let _ = encode_invoke_response(tx, header, |cw| {
                for item in req.invoke_requests()? {
                    let item = item?;
                    effects.merge(invoke_one(dm, &item, acc, cw)?);
                }
                Ok(())
            });
            self.apply_invoke_effects(effects, session, sessions);
            return Ok(HandlerAction::None);
        }

        let dm = &mut self.dm;
        let len = encode_invoke_response(tx, header, |cw| {
            for item in req.invoke_requests()? {
                let item = item?;
                effects.merge(invoke_one(dm, &item, acc, cw)?);
            }
            Ok(())
        })?;
        self.apply_invoke_effects(effects, session, sessions);
        Ok(close(ImOpCode::InvokeResponse, true, len))
    }

    /// invoke の副作用(fabric 昇格・bootstrap admin ACL・fabric 連動 ACL 削除)を適用する。
    fn apply_invoke_effects<const SN: usize>(
        &mut self,
        effects: InvokeEffects,
        session: SessionId,
        sessions: &mut SessionManager<SN>,
    ) {
        if let Some(p) = effects.promote {
            let _ = sessions.promote_pase_fabric(session, p);
        }
        if let Some(acl) = self.dm.acl() {
            if let Some((fabric, subject)) = effects.case_admin {
                // 満杯等は best-effort(コミッショニング自体は継続。エントリが無ければ
                // 当該 subject の CASE アクセスが拒否されるだけで安全側)。
                let _ = acl.add_case_admin(fabric, subject);
            }
            if let Some(fabric) = effects.removed_fabric {
                acl.remove_fabric(fabric);
            }
        }
    }

    // ----------------------------------------------------------------------
    // Timed(§5.5)
    // ----------------------------------------------------------------------

    fn timed_open(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let req = TimedRequest::decode(rx.payload)?;
        let deadline = now_ms.saturating_add(req.timeout_ms as u64);
        let existing = self.timed.iter().position(|t| t.exchange == rx.exchange);
        if let Some(i) = existing {
            self.timed.swap_remove(i);
        }
        if self
            .timed
            .push(TimedTxn {
                exchange: rx.exchange,
                deadline_ms: deadline,
            })
            .is_err()
        {
            return status_response(tx, ImStatus::Busy);
        }
        let len = StatusResponse::new(ImStatus::Success).encode(tx)?;
        Ok(respond(ImOpCode::StatusResponse, true, len))
    }

    /// 後続 Write/Invoke の Timed 整合を検証し、armed なら消費する(設計 §5.5)。
    fn check_timed(
        &mut self,
        exchange: ExchangeId,
        timed_flag: bool,
        now_ms: u64,
    ) -> core::result::Result<(), ImStatus> {
        let found = self.timed.iter().position(|t| t.exchange == exchange);
        if let Some(i) = found {
            let deadline = self.timed[i].deadline_ms;
            self.timed.swap_remove(i);
            if !timed_flag {
                return Err(ImStatus::TimedRequestMismatch);
            }
            if now_ms > deadline {
                return Err(ImStatus::Timeout);
            }
            Ok(())
        } else if timed_flag {
            Err(ImStatus::TimedRequestMismatch)
        } else {
            Ok(())
        }
    }

    // ----------------------------------------------------------------------
    // 購読レポート駆動 API(§6.3)
    // ----------------------------------------------------------------------

    /// 次に購読レポートを出すべき最も早い絶対時刻(統合層が `ExchangeManager::next_deadline`
    /// と min して 1 タイマにする)。Active 購読が無ければ `None`。
    pub fn next_deadline(&self, _now_ms: u64) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for s in self.subs.iter() {
            if s.state != SubState::Active {
                continue;
            }
            let max_due = s
                .last_report_ms
                .saturating_add((s.max_interval_s as u64) * 1000);
            let cand = if s.dirty {
                let min_due = s
                    .last_report_ms
                    .saturating_add((s.min_interval_s as u64) * 1000);
                min_due.min(max_due)
            } else {
                max_due
            };
            earliest = Some(match earliest {
                Some(e) => e.min(cand),
                None => cand,
            });
        }
        earliest
    }

    /// 期限到達 or dirty の Active 購読を 1 件返す(設計 §6.3)。
    ///
    /// 呼び出しごとに各クラスタの dirty を掃引して該当購読に伝播する。返した購読は統合層が
    /// [`InteractionModel::build_report`] でレポート生成する(そこで `last_report`/`dirty` を更新)。
    /// min_interval を尊重し、dirty でも `last_report + min` 未満なら due にしない。
    pub fn poll_subscriptions(&mut self, now_ms: u64) -> Option<SubDue> {
        self.sweep_dirty();
        for s in self.subs.iter() {
            if s.state != SubState::Active {
                continue;
            }
            let max_due = s
                .last_report_ms
                .saturating_add((s.max_interval_s as u64) * 1000);
            let min_ok = now_ms
                >= s.last_report_ms
                    .saturating_add((s.min_interval_s as u64) * 1000);
            if (s.dirty && min_ok) || now_ms >= max_due {
                return Some(SubDue {
                    subscription: s.id,
                    session: s.session,
                });
            }
        }
        None
    }

    /// 購読 `subscription` のレポート ReportData を `tx` に組み立て、長さを返す(設計 §6.3)。
    ///
    /// 統合層は `open_initiator` で開いた `exchange` を渡す。チャンク化が必要なら継続 slot を
    /// 確保し、続きは client の StatusResponse 受信(`handle`)で送る。全て収まれば `last_report`
    /// を更新し dirty をクリアする。購読が無ければ [`Error::NotFound`]。
    pub fn build_report(
        &mut self,
        subscription: u32,
        exchange: ExchangeId,
        tx: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        let Some(si) = self.subs.iter().position(|s| s.id == subscription) else {
            return Err(Error::NotFound);
        };
        // プライミング時のアクセス文脈で ACL を再評価する(時刻のみ更新)。
        let mut acc = self.subs[si].acc;
        acc.now_ms = now_ms;
        let mut txn = ReadTxn::<PATHS>::new(exchange, acc, ReadKind::Report(subscription), now_ms);
        {
            let sub = &self.subs[si];
            txn.npaths = sub.npaths;
            txn.paths[..sub.npaths].copy_from_slice(&sub.paths[..sub.npaths]);
        }

        let outcome;
        let len;
        {
            let mut builder = ReportChunkBuilder::new(tx, Some(subscription))?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            len = match outcome {
                ChunkOutcome::Done => builder.finish(false, false)?,
                ChunkOutcome::More => builder.finish(true, false)?,
            };
        }

        match outcome {
            ChunkOutcome::Done => {
                self.mark_reported(subscription, now_ms);
                Ok(len)
            }
            ChunkOutcome::More => {
                if self.reads.push(txn).is_err() {
                    // 継続 slot が無い場合は打ち切り(報告済み扱いにして stall を避ける)。
                    self.mark_reported(subscription, now_ms);
                }
                Ok(len)
            }
        }
    }

    /// device 発レポートが MRP で ack されなかった購読を破棄する(設計 §6.3、liveness)。
    pub fn on_report_failed(&mut self, subscription: u32) {
        let sidx = self.subs.iter().position(|s| s.id == subscription);
        if let Some(i) = sidx {
            self.subs.swap_remove(i);
        }
        loop {
            let Some(i) = self
                .reads
                .iter()
                .position(|t| matches!(t.kind, ReadKind::Report(id) if id == subscription))
            else {
                break;
            };
            self.reads.swap_remove(i);
        }
    }

    /// セッション切断時に、そのセッションに紐づく購読・継続・Timed を破棄する(設計 §6)。
    pub fn on_session_closed(&mut self, session: SessionId) {
        loop {
            let Some(i) = self.subs.iter().position(|s| s.session == session) else {
                break;
            };
            self.subs.swap_remove(i);
        }
        loop {
            let Some(i) = self
                .reads
                .iter()
                .position(|t| t.exchange.session() == session)
            else {
                break;
            };
            self.reads.swap_remove(i);
        }
        loop {
            let Some(i) = self
                .timed
                .iter()
                .position(|t| t.exchange.session() == session)
            else {
                break;
            };
            self.timed.swap_remove(i);
        }
    }

    /// 放置されたチャンク中 Read と期限切れ Timed を掃除する(統合層が定期的に呼ぶ)。
    pub fn on_tick(&mut self, now_ms: u64) {
        loop {
            let Some(i) = self.timed.iter().position(|t| now_ms > t.deadline_ms) else {
                break;
            };
            self.timed.swap_remove(i);
        }
        loop {
            let Some(i) = self
                .reads
                .iter()
                .position(|t| now_ms.saturating_sub(t.started_ms) > READ_TXN_TIMEOUT_MS)
            else {
                break;
            };
            self.reads.swap_remove(i);
        }
    }

    // ----------------------------------------------------------------------
    // 内部ヘルパ
    // ----------------------------------------------------------------------

    /// 各クラスタの dirty を掃引し、交差する購読に伝播する(設計 §6.2)。
    fn sweep_dirty(&mut self) {
        let mut pairs = [(EndpointId(0), ClusterId(0)); MAX_SWEEP];
        let mut n = 0;
        {
            for e in self.dm.endpoints() {
                for &cl in e.clusters {
                    if n < MAX_SWEEP {
                        pairs[n] = (e.id, cl);
                        n += 1;
                    }
                }
            }
        }
        for &(ep, cl) in pairs.iter().take(n) {
            let is_dirty = self
                .dm
                .cluster_mut(ep, cl)
                .map(|c| c.take_dirty())
                .unwrap_or(false);
            if is_dirty {
                // アプリ側の直接変更(IM 外)でも DataVersion を進める。
                self.data_version = self.data_version.wrapping_add(1);
                for i in 0..self.subs.len() {
                    if sub_covers(&self.subs[i], ep, cl) {
                        self.subs[i].dirty = true;
                    }
                }
            }
        }
    }

    /// プライミング完了で購読を Active 化する。
    fn activate_subscription(&mut self, id: u32, now_ms: u64) {
        let idx = self.subs.iter().position(|s| s.id == id);
        if let Some(i) = idx {
            let s = &mut self.subs[i];
            s.state = SubState::Active;
            s.last_report_ms = now_ms;
            s.dirty = false;
        }
    }

    /// レポート送出後に last_report を更新し dirty をクリアする。
    fn mark_reported(&mut self, id: u32, now_ms: u64) {
        let idx = self.subs.iter().position(|s| s.id == id);
        if let Some(i) = idx {
            let s = &mut self.subs[i];
            s.last_report_ms = now_ms;
            s.dirty = false;
        }
    }
}

/// 1 つの AttributeDataIB を書き込み、結果ステータスを返す(設計 §9 / `docs/design/acl.md` §4)。
///
/// パスの ListIndex が null(`list_append`)の場合は list 属性への 1 要素追記
/// ([`ListOp::AppendItem`])としてクラスタへ渡す。数値 ListIndex 指定の write は非対応
/// (`InvalidAction`)。
fn write_one<D: DataModel + ?Sized>(
    dm: &mut D,
    item: &AttributeDataRef<'_>,
    acc: &AccessContext,
) -> ImStatus {
    let p = item.path;
    let (Some(endpoint), Some(cluster_id), Some(attribute)) = (p.endpoint, p.cluster, p.attribute)
    else {
        return ImStatus::InvalidAction;
    };
    if p.list_index.is_some() {
        return ImStatus::InvalidAction;
    }
    if !dm.endpoints().iter().any(|e| e.id == endpoint) {
        return ImStatus::UnsupportedEndpoint;
    }
    // 必要権限は属性メタの write_access(未知属性は既定 Operate。クラスタが
    // UnsupportedWrite/UnsupportedAttribute を返す)。存在チェック → ACL の順(acl.md §3)。
    let required = match dm.cluster(endpoint, cluster_id) {
        Some(c) => c
            .meta()
            .attribute(attribute)
            .map(|m| m.write_access)
            .unwrap_or(Privilege::Operate),
        None => return ImStatus::UnsupportedCluster,
    };
    if !allowed(dm, acc, endpoint, cluster_id, required) {
        return ImStatus::UnsupportedAccess;
    }
    let Some(cluster) = dm.cluster_mut(endpoint, cluster_id) else {
        return ImStatus::UnsupportedCluster;
    };
    let op = if p.list_append {
        ListOp::AppendItem
    } else {
        ListOp::ReplaceAll
    };
    let data = AttrWrite::new(item.data).with_op(op);
    match cluster.write_attribute(attribute, data, acc) {
        Ok(()) => ImStatus::Success,
        Err(s) => s,
    }
}

/// invoke の副作用(クラスタからエンジンへの後処理要求、設計 §9.4 / `docs/design/acl.md` §3)。
#[derive(Debug, Clone, Copy, Default)]
struct InvokeEffects {
    /// PASE セッションの fabric 昇格(AddNOC)。
    promote: Option<NonZeroU8>,
    /// bootstrap admin ACL の生成(AddNOC の caseAdminSubject)。
    case_admin: Option<(NonZeroU8, u64)>,
    /// fabric 削除に連動する ACL エントリ削除(RemoveFabric)。
    removed_fabric: Option<NonZeroU8>,
}

impl InvokeEffects {
    /// `other` の要求をマージする(後勝ち)。
    fn merge(&mut self, other: InvokeEffects) {
        if other.promote.is_some() {
            self.promote = other.promote;
        }
        if other.case_admin.is_some() {
            self.case_admin = other.case_admin;
        }
        if other.removed_fabric.is_some() {
            self.removed_fabric = other.removed_fabric;
        }
    }
}

/// 1 つの CommandDataIB を起動し、応答(生成レスポンス or StatusIB)を `cw` に書く(設計 §9)。
///
/// クラスタが [`CmdResponder::set_response`](crate::dm::codec::CmdResponder::set_response) で
/// 生成レスポンスを宣言した場合、そのフィールド(スクラッチ上の匿名構造体)を InvokeResponseIB の
/// CommandDataIB へ転写する。宣言が無ければ結果ステータスを CommandStatusIB として書く。
/// 返り値はクラスタが要求した副作用([`InvokeEffects`])。
fn invoke_one<D: DataModel + ?Sized>(
    dm: &mut D,
    item: &CommandDataRef<'_>,
    acc: &AccessContext,
    cw: &mut CmdRespWriter<'_, '_>,
) -> Result<InvokeEffects> {
    let path = item.path;
    if !dm.endpoints().iter().any(|e| e.id == path.endpoint) {
        cw.push_status(
            &path,
            &StatusIB::simple(ImStatus::UnsupportedEndpoint),
            item.command_ref,
        )?;
        return Ok(InvokeEffects::default());
    }
    // 必要権限はコマンドメタの access(未知コマンドは既定 Operate。クラスタが
    // UnsupportedCommand を返す)。存在チェック → ACL の順(acl.md §3)。
    let required = match dm.cluster(path.endpoint, path.cluster) {
        Some(c) => c
            .meta()
            .accepted_commands
            .iter()
            .find(|m| m.id == path.command)
            .map(|m| m.access)
            .unwrap_or(Privilege::Operate),
        None => {
            cw.push_status(
                &path,
                &StatusIB::simple(ImStatus::UnsupportedCluster),
                item.command_ref,
            )?;
            return Ok(InvokeEffects::default());
        }
    };
    if !allowed(dm, acc, path.endpoint, path.cluster, required) {
        cw.push_status(
            &path,
            &StatusIB::simple(ImStatus::UnsupportedAccess),
            item.command_ref,
        )?;
        return Ok(InvokeEffects::default());
    }
    let Some(cluster) = dm.cluster_mut(path.endpoint, path.cluster) else {
        cw.push_status(
            &path,
            &StatusIB::simple(ImStatus::UnsupportedCluster),
            item.command_ref,
        )?;
        return Ok(InvokeEffects::default());
    };

    let mut fr = TlvReader::new(item.fields.unwrap_or(&[]));
    let mut scratch = [0u8; INVOKE_SCRATCH];
    // resp/sw の借用をブロックで閉じ、確定後にスクラッチを読めるようにする。
    let (result, response_cmd, effects, scratch_len) = {
        let mut sw = TlvWriter::new(&mut scratch);
        let (result, response_cmd, effects) = {
            let mut resp = CmdResponder::new(&mut sw);
            let result = cluster.invoke_command(path.command, &mut fr, &mut resp, acc);
            let effects = InvokeEffects {
                promote: resp.requested_promotion(),
                case_admin: resp.requested_case_admin_acl(),
                removed_fabric: resp.requested_fabric_removed(),
            };
            (result, resp.response_command(), effects)
        };
        let scratch_len = sw.len();
        (result, response_cmd, effects, scratch_len)
    };

    match result {
        Ok(()) => {
            if let Some(rid) = response_cmd {
                let rpath = CommandPath::new(path.endpoint, path.cluster, rid);
                cw.push_command(&rpath, item.command_ref, |w, tag| {
                    transcribe(&scratch[..scratch_len], w, tag)
                })?;
            } else {
                cw.push_status(
                    &path,
                    &StatusIB::simple(ImStatus::Success),
                    item.command_ref,
                )?;
            }
        }
        Err(s) => {
            cw.push_status(&path, &StatusIB::simple(s), item.command_ref)?;
        }
    }
    Ok(effects)
}

impl<D: DataModel, const READS: usize, const SUBS: usize, const PATHS: usize> ProtocolHandler
    for InteractionModel<D, READS, SUBS, PATHS>
{
    const PROTOCOL_ID: u16 = PROTO_ID_INTERACTION_MODEL;

    fn handle<const SN: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<SN>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let acc = match access_from_session(sessions, rx.exchange.session(), now_ms) {
            Ok(a) => a,
            // 未認証/PlainText 等はサイレントドロップ(panic しない)。
            Err(_) => return Ok(HandlerAction::None),
        };
        match ImOpCode::from_u8(rx.header.proto_opcode)? {
            ImOpCode::ReadRequest => self.read_open(rx, tx, &acc, now_ms),
            ImOpCode::SubscribeRequest => self.subscribe_open(rx, tx, &acc, now_ms),
            ImOpCode::WriteRequest => self.write(rx, tx, &acc, now_ms),
            ImOpCode::InvokeRequest => self.invoke(rx, tx, &acc, sessions, now_ms),
            ImOpCode::TimedRequest => self.timed_open(rx, tx, now_ms),
            ImOpCode::StatusResponse => self.on_status(rx, tx, now_ms),
            // ReportData/SubscribeResponse/WriteResponse/InvokeResponse は client→device では不正。
            _ => Ok(HandlerAction::None),
        }
    }
}

#[cfg(test)]
mod tests;
