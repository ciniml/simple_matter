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
    is_global_attribute, AccessContext, ClusterId, EndpointId, EventId, Privilege, SessionKind,
};
use crate::dm::{read_global_attribute, AttrWrite, DataModel, DeferredPoll, ListOp};
use crate::error::{Error, Result};
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, RxMessage};
use crate::im::events::EventLog;
use crate::im::wire::{
    encode_invoke_response, encode_write_response, transcribe, AttributeDataRef, AttributePath,
    CmdRespWriter, CommandDataRef, CommandPath, ConcreteAttrPath, EventPath, ImOpCode, ImStatus,
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

/// イベントログ(リングバッファ)の固定容量(設計 §12)。
const EVENT_LOG_CAP: usize = 8;

/// dirty 掃引で 1 回に走査する (endpoint, cluster) の上限。
const MAX_SWEEP: usize = 64;

/// 遅延 InvokeResponse の締切(設計 `port-esp32-device.md` §E7.2)。
///
/// ConnectMaxTimeSeconds(30)より短く、クライアント(ImClient/chip-tool)の txn
/// タイムアウト 30 秒より必ず先に返すため 20 秒とする。cluster がこの時間内に
/// `poll_deferred` で `Ready` を返さなければ Timeout ステータスで応答して終端する。
const DEFERRED_TIMEOUT_MS: u64 = 20_000;

/// 遅延 InvokeResponse 保留中の再 poll 間隔(設計 §E7.2)。
///
/// driver の状態変化(join 完了/失敗)はイベントではなく poll で観測するため、保留中は
/// `next_deadline` にこの間隔を合成して統合層に定期的な poll を促す(締切より手前で
/// 成功応答を返せるようにする)。
const DEFERRED_POLL_INTERVAL_MS: u64 = 100;

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
            // full ACL 無しデバイスの groupcast は Operate 近似で許可
            // (`docs/design/group-messaging.md` §4。CASE の近似と整合)。
            SessionKind::Group => (required as u8) <= (Privilege::Operate as u8),
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
    /// リクエストのイベントパス列(EventRequests、設計 §12)。
    event_paths: [EventPath; P],
    /// `event_paths` の有効長。
    n_event_paths: usize,
    /// EventFilters の eventMin(あれば `event_number >= eventMin` のみ返す)。
    event_min: Option<u64>,
    /// イベントレポート(EventReports)の出力を済ませたか(全属性チャンク完了後 1 回)。
    events_emitted: bool,
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
            event_paths: [EventPath::default(); P],
            n_event_paths: 0,
            event_min: None,
            events_emitted: false,
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
    /// 購読イベントパス列(EventRequests、固定上限、設計 §12)。
    event_paths: [EventPath; P],
    /// `event_paths` の有効長。
    n_event_paths: usize,
    /// リクエストの EventFilters eventMin(プライミングで既存イベントを絞る、設計 §12)。
    event_min: Option<u64>,
    /// 配信済みイベント floor: この番号未満のイベントは配信済み(> はプライミング/レポートで
    /// 未配信)。プライミング完了時に EventLog の次番号を記録し、レポートのたびに前進する。
    event_floor: u64,
    /// 最小レポート間隔(秒)。
    min_interval_s: u16,
    /// 最大レポート間隔(秒)。
    max_interval_s: u16,
    /// 直近レポート時刻。
    last_report_ms: u64,
    /// 前回レポート以降に交差クラスタが変更されたか。
    dirty: bool,
    /// 直近の device 発レポートを運んだ exchange(MRP 諦め時の購読破棄の逆引き用、
    /// 設計 §6.3。単一チャンクレポートは reads に継続 slot を持たないため購読側で覚える)。
    report_exchange: Option<ExchangeId>,
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
            event_paths: [EventPath::default(); P],
            n_event_paths: 0,
            event_min: None,
            event_floor: 0,
            min_interval_s,
            max_interval_s,
            last_report_ms: now_ms,
            dirty: false,
            report_exchange: None,
            state: SubState::Priming,
        }
    }
}

/// EventLog に、購読の event_paths に合致する未配信(番号 >= floor)イベントがあるか(設計 §12)。
fn sub_has_new_event<const P: usize>(sub: &Subscription<P>, log: &EventLog<EVENT_LOG_CAP>) -> bool {
    if sub.n_event_paths == 0 {
        return false;
    }
    log.iter().any(|rec| {
        rec.number >= sub.event_floor
            && sub.event_paths[..sub.n_event_paths]
                .iter()
                .any(|p| p.matches(rec.endpoint, rec.cluster, rec.event))
    })
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

/// 保留中の遅延 InvokeResponse スロット(設計 §E7.2)。
///
/// スロットは **エンジンに 1 本のみ**。2 本目の遅延要求は Busy(ImStatus)で即時拒否する。
#[derive(Debug, Clone, Copy)]
struct DeferredInvoke {
    /// 応答を返すべき元の responder exchange。
    exchange: ExchangeId,
    /// 具象コマンドパス(endpoint/cluster/command)。`poll_deferred` の再問い合わせに使う。
    path: CommandPath,
    /// バッチ Invoke 用の CommandRef(あれば。応答にエコーする)。
    command_ref: Option<u16>,
    /// 締切(絶対時刻ミリ秒)。超過したら cluster の完了を待たず Timeout で応答する。
    deadline_ms: u64,
}

// 設計 §E7.2 はスロットにアクセス文脈(fabric index 等)も保持するとしているが、
// `poll_deferred`(§E7.1 のシグネチャ)は `acc` を取らず、完了応答はアクセス判定を伴わない
//(元の invoke で ACL 通過済み)。不要な状態を持たないため本実装はスロットに `acc` を持たない。

/// `invoke_one` が「このコマンドは応答を保留した」ことをエンジンへ返す情報(設計 §E7.2)。
#[derive(Debug, Clone, Copy)]
struct DeferReq {
    /// 具象コマンドパス。
    path: CommandPath,
    /// CommandRef(あれば)。
    command_ref: Option<u16>,
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

/// `txn` のイベントリクエストに合致するイベントを `builder` に EventReportIB として書く(設計 §12)。
///
/// 全属性チャンクの消化後に 1 回だけ呼ぶ(`events_emitted` で単一化)。イベントパスが
/// 無ければ何もしない。合致判定はパス(ワイルドカード可)+ `event_min`(EventFilters)+
/// ACL(属性 read と同等の View で近似)。イベント数は少ない前提でチャンク化せず、収まる
/// 範囲で 1 レポートに載せる(入り切らないイベントはドロップ、割り切り)。
fn emit_events<D: DataModel + ?Sized, const P: usize>(
    dm: &D,
    log: &EventLog<EVENT_LOG_CAP>,
    txn: &mut ReadTxn<P>,
    builder: &mut ReportChunkBuilder<'_>,
) -> Result<()> {
    if txn.events_emitted || txn.n_event_paths == 0 {
        txn.events_emitted = true;
        return Ok(());
    }
    builder.begin_events()?;
    for rec in log.iter() {
        if let Some(min) = txn.event_min {
            if rec.number < min {
                continue;
            }
        }
        let matched = txn.event_paths[..txn.n_event_paths]
            .iter()
            .any(|p| p.matches(rec.endpoint, rec.cluster, rec.event));
        if !matched {
            continue;
        }
        // イベント read の権限は属性 read と同等(View)で近似(設計 §12、per-event 権限は割り切り)。
        if !allowed(dm, &txn.acc, rec.endpoint, rec.cluster, Privilege::View) {
            continue;
        }
        let path = EventPath::concrete(rec.endpoint, rec.cluster, rec.event);
        // 収まらなければドロップ(割り切り。イベント数は少ない前提)。
        let _ = builder.try_push_event(
            &path,
            rec.number,
            rec.priority,
            rec.system_timestamp_ms,
            rec.payload(),
        )?;
    }
    txn.events_emitted = true;
    Ok(())
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
    /// 保留中の遅延 InvokeResponse(設計 §E7.2)。同時に 1 本のみ。
    deferred: Option<DeferredInvoke>,
    /// イベントログ(リングバッファ、設計 §12)。StartUp 等をここに積む。
    events: EventLog<EVENT_LOG_CAP>,
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
            deferred: None,
            events: EventLog::new(),
        }
    }

    /// データモデルへの共有参照(アプリからの属性読み取り等)。
    pub const fn data_model(&self) -> &D {
        &self.dm
    }

    /// イベントログへの共有参照(診断・テスト用)。
    pub const fn events(&self) -> &EventLog<EVENT_LOG_CAP> {
        &self.events
    }

    /// イベントを 1 件積む(満杯なら最古を追い出す)。採番した EventNumber を返す。
    ///
    /// `write_data` は EventDataIB.Data の値要素を `tag`(anonymous)で書く。StartUp なら
    /// `{ 0: softwareVersion }` の struct(`docs/design/interaction-model.md` §12)。
    pub fn post_event(
        &mut self,
        endpoint: EndpointId,
        cluster: ClusterId,
        event: EventId,
        priority: u8,
        now_ms: u64,
        write_data: impl FnOnce(&mut TlvWriter<'_>, &crate::tlv::TlvTag) -> Result<()>,
    ) -> Result<u64> {
        self.events
            .post(endpoint, cluster, event, priority, now_ms, write_data)
    }

    /// データモデルへの可変参照(アプリからの状態変更。dirty はクラスタが立てる)。
    pub fn data_model_mut(&mut self) -> &mut D {
        &mut self.dm
    }

    /// groupcast InvokeRequest を配送する(`docs/design/group-messaging.md` §5.2)。
    ///
    /// groupcast は応答禁止のため、応答・ステータスを一切生成しない(失敗も黙って捨てる)。
    /// CommandPathIB は endpoint を持たないため
    /// [`DataModel::group_endpoints`] で所属 endpoint に展開し、各 (endpoint, cluster) に
    /// ACL([`SessionKind::Group`])を適用して invoke する。timed 必須コマンドは
    /// 黙って捨てる(chip `ProcessGroupCommandDataIB` 同様)。invoke の副作用
    /// (InvokeEffects)は group では発生しない前提で無視する(AddNOC 等の Administer
    /// コマンドは ACL 制約(Group に Administer 付与不可)で到達しない)。
    pub fn invoke_group(&mut self, payload: &[u8], group_id: u16, fabric: NonZeroU8, now_ms: u64) {
        let Ok(req) = InvokeRequestRef::new(payload) else {
            return;
        };
        let Ok(items) = req.group_invoke_requests() else {
            return;
        };
        // コマンドは状態を変えうるため DataVersion を進める(unicast invoke と同じ)。
        self.data_version = self.data_version.wrapping_add(1);
        let acc = AccessContext::new(
            SessionKind::Group,
            Some(fabric),
            crate::groups::group_node_id(group_id),
            Privilege::Operate,
        )
        .with_env(now_ms, [0u8; 16]);
        for item in items {
            let Ok(item) = item else {
                return;
            };
            let mut idx = 0usize;
            while let Some(ep) = self.dm.group_endpoints(fabric, group_id, idx) {
                idx += 1;
                let Some(c) = self.dm.cluster(ep, item.cluster) else {
                    continue;
                };
                let (required, needs_timed) = c
                    .meta()
                    .accepted_commands
                    .iter()
                    .find(|m| m.id == item.command)
                    .map(|m| (m.access, m.timed))
                    .unwrap_or((Privilege::Operate, false));
                if needs_timed {
                    // groupcast に timed interaction は存在しない → 黙って捨てる。
                    continue;
                }
                if !allowed(&self.dm, &acc, ep, item.cluster, required) {
                    continue;
                }
                let Some(cluster) = self.dm.cluster_mut(ep, item.cluster) else {
                    continue;
                };
                let mut fr = TlvReader::new(item.fields.unwrap_or(&[]));
                let mut scratch = [0u8; INVOKE_SCRATCH];
                let mut sw = TlvWriter::new(&mut scratch);
                let mut resp = CmdResponder::new(&mut sw);
                let _ = cluster.invoke_command(item.command, &mut fr, &mut resp, &acc);
            }
        }
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
        for p in req.event_paths()? {
            let p = p?;
            if txn.n_event_paths >= PATHS {
                return status_response(tx, ImStatus::PathsExhausted);
            }
            txn.event_paths[txn.n_event_paths] = p;
            txn.n_event_paths += 1;
        }
        txn.event_min = req.event_min()?;

        let outcome;
        let len;
        {
            let mut builder = ReportChunkBuilder::new(tx, None)?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            if outcome == ChunkOutcome::Done {
                emit_events(&self.dm, &self.events, &mut txn, &mut builder)?;
            }
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
        let mut sub =
            Subscription::<PATHS>::new(id, rx.exchange.session(), *acc, min, max_neg, now_ms);
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
        // EventRequests / EventFilters(設計 §12): 購読とプライミング txn の双方へ載せる。
        for p in req.event_paths()? {
            let p = p?;
            if sub.n_event_paths >= PATHS {
                break;
            }
            sub.event_paths[sub.n_event_paths] = p;
            sub.n_event_paths += 1;
            txn.event_paths[txn.n_event_paths] = p;
            txn.n_event_paths += 1;
        }
        sub.event_min = req.event_min()?;
        // プライミングでは EventFilters の eventMin を尊重して既存イベントを配信する。
        txn.event_min = sub.event_min;

        let outcome;
        let len;
        {
            // プライミングレポートにも SubscriptionId を含める(chip の ReadClient は
            // SubscriptionId 欠如の priming ReportData を Invalid argument で拒否する。実測)。
            let mut builder = ReportChunkBuilder::new(tx, Some(id))?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            len = match outcome {
                ChunkOutcome::Done => {
                    // プライミングで既存イベントを相乗り配信し、配信済み floor を記録する。
                    emit_events(&self.dm, &self.events, &mut txn, &mut builder)?;
                    sub.event_floor = self.events.next_number();
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
            // 継続 slot が無い = 完了済みトランザクション(単一チャンクの購読レポート等)への
            // 終端 StatusResponse。exchange を終端予約して回収させる(回帰修正: None のまま
            // 放置すると device 発の購読レポートごとに initiator exchange がリークし、
            // EXCHANGES 本のプールが枯渇して以降の受信が全て silent drop になる)。
            // 保留中の遅延 InvokeResponse の exchange だけは生存維持する(設計 §E7.2)。
            if self
                .deferred
                .as_ref()
                .is_some_and(|d| d.exchange == rx.exchange)
            {
                return Ok(HandlerAction::None);
            }
            // 配達確認: この exchange が購読レポートを運んでいたなら逆引きマップを消す
            // (以降の無関係な exchange 失敗で購読を誤破棄しないため)。
            let acked = self
                .subs
                .iter()
                .position(|s| s.report_exchange == Some(rx.exchange));
            if let Some(i) = acked {
                self.subs[i].report_exchange = None;
            }
            return Ok(HandlerAction::CloseSilent);
        };
        if !sr.status.is_success() {
            // クライアントがトランザクションを拒否(InvalidSubscription 等)。slot を破棄し、
            // exchange も終端予約する(リーク防止)。
            self.reads.swap_remove(idx);
            return Ok(HandlerAction::CloseSilent);
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
            let events = &self.events;
            let txn = &mut self.reads[idx];
            // 購読レポート/プライミング継続チャンクにも SubscriptionId を含める(chip 互換)。
            let sub_id = match txn.kind {
                ReadKind::Report(id) | ReadKind::Priming(id) => Some(id),
                ReadKind::Read => None,
            };
            let mut builder = ReportChunkBuilder::new(tx, sub_id)?;
            outcome = emit_chunk(dm, txn, &mut builder, dv)?;
            // 最終チャンクでイベントレポートを付ける(Read / Subscribe プライミング / 購読レポート、
            // 設計 §12)。txn.event_paths/event_min は各 open 経路で載せてある。
            if outcome == ChunkOutcome::Done {
                emit_events(dm, events, txn, &mut builder)?;
            }
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
            (ChunkOutcome::Done, ReadKind::Priming(id)) => {
                // 最終プライミングレポートを送った。既存イベントを配信し切ったので floor を記録。
                self.set_event_floor(id, self.events.next_number());
                // 次の StatusResponse で SubscribeResponse。
                Ok(respond(ImOpCode::ReportData, true, len))
            }
            (ChunkOutcome::Done, ReadKind::Report(id)) => {
                self.reads.swap_remove(idx);
                // 配信済みイベント floor を前進させてから last_report / dirty を更新する。
                self.set_event_floor(id, self.events.next_number());
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
        let was_timed = match self.check_timed(rx.exchange, timed_flag, now_ms) {
            Ok(b) => b,
            Err(st) => return status_response(tx, st),
        };

        if suppress {
            let dm = &mut self.dm;
            for item in req.write_requests()? {
                let item = item?;
                let _ = write_one(dm, &item, acc, was_timed);
            }
            return Ok(HandlerAction::None);
        }

        let dm = &mut self.dm;
        let len = encode_write_response(tx, |sw| {
            for item in req.write_requests()? {
                let item = item?;
                let status = write_one(dm, &item, acc, was_timed);
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
        let was_timed = match self.check_timed(rx.exchange, timed_flag, now_ms) {
            Ok(b) => b,
            Err(st) => return status_response(tx, st),
        };

        let session = rx.exchange.session();
        let header = InvokeResponseHeader {
            suppress_response: false,
            more_chunks: false,
        };
        let mut effects = InvokeEffects::default();

        if suppress {
            // 応答は送らないが副作用(および AddNOC の fabric 昇格)は適用する。
            // `tx` をスクラッチとして使い、生成結果は破棄する。応答が無いため遅延は行わない
            //(cluster が set_deferred しても無視。副作用のみ適用)。
            let dm = &mut self.dm;
            let mut defer = None;
            let _ = encode_invoke_response(tx, header, |cw| {
                for item in req.invoke_requests()? {
                    let item = item?;
                    effects.merge(invoke_one(dm, &item, acc, was_timed, cw, &mut defer)?);
                }
                Ok(())
            });
            self.apply_invoke_effects(effects, session, sessions);
            return Ok(HandlerAction::None);
        }

        // 遅延 InvokeResponse(設計 §E7.2): スロットは 1 本。既に保留中なら 2 本目は Busy。
        let already_deferred = self.deferred.is_some();
        let mut defer_req: Option<DeferReq> = None;
        let mut ncommands: usize = 0;
        let dm = &mut self.dm;
        let len = encode_invoke_response(tx, header, |cw| {
            for item in req.invoke_requests()? {
                let item = item?;
                ncommands += 1;
                let mut defer = None;
                effects.merge(invoke_one(dm, &item, acc, was_timed, cw, &mut defer)?);
                if let Some(dr) = defer {
                    defer_req = Some(dr);
                }
            }
            Ok(())
        })?;

        if let Some(dr) = defer_req {
            // 遅延はリクエストが単独コマンドのときのみ支持する(chip-tool は 1 コマンド送信)。
            // 複数コマンドで遅延しようとした場合や、既に別の遅延が保留中(Busy)の場合は
            // エラー status で即応答する(設計 §E7.2 の制約)。
            if ncommands == 1 && !already_deferred {
                self.deferred = Some(DeferredInvoke {
                    exchange: rx.exchange,
                    path: dr.path,
                    command_ref: dr.command_ref,
                    deadline_ms: now_ms.saturating_add(DEFERRED_TIMEOUT_MS),
                });
                self.apply_invoke_effects(effects, session, sessions);
                // exchange は生存維持(mark_closing しない)。受信 ACK は standalone ACK 機構が返す。
                return Ok(HandlerAction::None);
            }
            let st = if already_deferred {
                ImStatus::Busy
            } else {
                ImStatus::Failure
            };
            let len = encode_invoke_response(tx, header, |cw| {
                cw.push_status(&dr.path, &StatusIB::simple(st), dr.command_ref)
            })?;
            self.apply_invoke_effects(effects, session, sessions);
            return Ok(close(ImOpCode::InvokeResponse, true, len));
        }

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
        // RemoveFabric 連動: 当該 fabric の ICD 登録クライアントも消す(icd.md §I1c)。
        if let Some(fabric) = effects.removed_fabric {
            if let Some(reg) = self.dm.icd_registry() {
                reg.remove_fabric(fabric);
            }
        }
        // CommissioningComplete: fail-safe 中に追加した fabric を確定する(Core Spec §11.10)。
        if effects.commissioning_complete {
            self.dm.on_commissioning_complete();
        }
        // ArmFailSafe(0): 仕様準拠 fail-safe クリーンアップ(Core Spec §11.10)。GC の解除 +
        // OpCreds の pending 破棄 + 未 CommissioningComplete の fabric 削除を dm が行い、削除した
        // fabric index の ACL エントリと当該 fabric のセッションを掃除する。応答送出に使う現在の
        // セッション(ArmFailSafe を送ってきた PASE)は残す割り切り(直後に応答が必要なため。
        // このセッションはコミッショナが CloseSession するか失効で消える)。
        if effects.failsafe_cleanup {
            if let Some(fabric) = self.dm.on_failsafe_cleanup() {
                self.purge_fabric(fabric, Some(session), sessions);
            }
        }
    }

    /// 削除した `fabric` の ACL エントリと、その fabric に紐づくセッションを掃除する。
    ///
    /// `keep` に与えたセッション(応答送出中の現在セッション)は残す。それ以外の当該 fabric
    /// セッションは [`SessionManager::remove`] で閉じ、購読/継続/Timed を
    /// [`on_session_closed`](Self::on_session_closed) で掃除する。fail-safe クリーンアップ
    /// (invoke 経路、`keep = Some`)とタイマ経過経路(`stack`、`keep = None`)で共用する。
    pub fn purge_fabric<const SN: usize>(
        &mut self,
        fabric: NonZeroU8,
        keep: Option<SessionId>,
        sessions: &mut SessionManager<SN>,
    ) {
        if let Some(acl) = self.dm.acl() {
            acl.remove_fabric(fabric);
        }
        if let Some(reg) = self.dm.icd_registry() {
            reg.remove_fabric(fabric);
        }
        loop {
            let victim = sessions
                .iter()
                .find(|s| Some(s.id()) != keep && s.mode().fabric_idx() == fabric.get())
                .map(|s| s.id());
            let Some(id) = victim else { break };
            sessions.remove(id);
            self.on_session_closed(id);
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
    ///
    /// 成功時は「timed 経由だったか」を返す(timed 必須コマンドの強制に使う)。
    fn check_timed(
        &mut self,
        exchange: ExchangeId,
        timed_flag: bool,
        now_ms: u64,
    ) -> core::result::Result<bool, ImStatus> {
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
            Ok(true)
        } else if timed_flag {
            Err(ImStatus::TimedRequestMismatch)
        } else {
            Ok(false)
        }
    }

    // ----------------------------------------------------------------------
    // 購読レポート駆動 API(§6.3)
    // ----------------------------------------------------------------------

    /// 次に購読レポートを出すべき最も早い絶対時刻(統合層が `ExchangeManager::next_deadline`
    /// と min して 1 タイマにする)。Active 購読が無ければ `None`。
    pub fn next_deadline(&self, now_ms: u64) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        // 遅延 InvokeResponse 保留中は、driver の状態変化を締切より手前で拾うため定期 poll を促す
        //(設計 §E7.2)。締切は上限。
        if let Some(d) = &self.deferred {
            let cand = now_ms
                .saturating_add(DEFERRED_POLL_INTERVAL_MS)
                .min(d.deadline_ms);
            earliest = Some(cand);
        }
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
        self.sweep_events();
        for s in self.subs.iter() {
            if s.state != SubState::Active {
                continue;
            }
            // 前回レポートが未完了(ack 未着 = `report_exchange` 保持中)の購読は due にしない。
            // レポートトランザクションは購読ごとに同時 1 本(仕様どおり)で、これにより
            // (1) MRP 再送中の多重レポート送出、(2) 30 秒再レポートによる `report_exchange`
            // 上書きで MRP give-up 時の逆引き([`Self::on_report_exchange_failed`])が外れて
            // 死んだ購読者を破棄し損ねる問題、の両方を防ぐ(設計 §6.3 liveness)。
            if s.report_exchange.is_some() {
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
            // イベントパスと「未配信のみ」フィルタ(floor)を載せる(設計 §12)。
            txn.n_event_paths = sub.n_event_paths;
            txn.event_paths[..sub.n_event_paths]
                .copy_from_slice(&sub.event_paths[..sub.n_event_paths]);
            txn.event_min = Some(sub.event_floor);
        }

        let outcome;
        let len;
        {
            let mut builder = ReportChunkBuilder::new(tx, Some(subscription))?;
            outcome = emit_chunk(&self.dm, &mut txn, &mut builder, self.data_version)?;
            if outcome == ChunkOutcome::Done {
                emit_events(&self.dm, &self.events, &mut txn, &mut builder)?;
            }
            len = match outcome {
                ChunkOutcome::Done => builder.finish(false, false)?,
                ChunkOutcome::More => builder.finish(true, false)?,
            };
        }

        // このレポートを運ぶ exchange を記録する(MRP 諦め時の購読破棄の逆引き、設計 §6.3)。
        // 組み立て成功後にのみ記録する(エラー時に閉じた exchange を指したまま残すと、
        // in-flight ガードで購読が永久に due しなくなる)。送信失敗時は統合層が
        // [`Self::on_report_send_failed`] で解除する。
        self.subs[si].report_exchange = Some(exchange);

        match outcome {
            ChunkOutcome::Done => {
                // 配信済みイベント floor を前進させてから last_report / dirty を更新する。
                self.set_event_floor(subscription, self.events.next_number());
                self.mark_reported(subscription, now_ms);
                Ok(len)
            }
            ChunkOutcome::More => {
                if self.reads.push(txn).is_err() {
                    // 継続 slot が無い場合は打ち切り(報告済み扱いにして stall を避ける)。
                    self.set_event_floor(subscription, self.events.next_number());
                    self.mark_reported(subscription, now_ms);
                }
                Ok(len)
            }
        }
    }

    /// 組み立て済みレポートの**送出**に失敗した(が購読は維持する)ことを通知する。
    ///
    /// 統合層が一時的エラー(tx バッファ枯渇等)で ReportData を送れなかったときに呼ぶ。
    /// in-flight 記録(`report_exchange`)を解除し、次の poll で再レポートできるようにする
    /// (解除しないと in-flight ガードにより購読が永久に due しなくなる。設計 §6.3)。
    pub fn on_report_send_failed(&mut self, subscription: u32) {
        let idx = self.subs.iter().position(|s| s.id == subscription);
        if let Some(i) = idx {
            self.subs[i].report_exchange = None;
        }
    }

    // ----------------------------------------------------------------------
    // 遅延 InvokeResponse 駆動 API(設計 §E7.2)
    // ----------------------------------------------------------------------

    /// 保留中の遅延 InvokeResponse があれば、その応答先 [`ExchangeId`] を返す。
    ///
    /// 統合層([`crate::stack`])はこれで保留の有無を確認し、あれば
    /// [`build_deferred_invoke_response`](Self::build_deferred_invoke_response) を試みる。
    pub fn poll_deferred_invoke(&self, _now_ms: u64) -> Option<ExchangeId> {
        self.deferred.as_ref().map(|d| d.exchange)
    }

    /// 保留中の遅延応答を破棄する(送信成功後・exchange 消滅時に統合層が呼ぶ)。
    pub fn drop_deferred(&mut self) {
        self.deferred = None;
    }

    /// 保留中の遅延 InvokeResponse を `tx` に組み立てる(設計 §E7.2)。
    ///
    /// cluster の [`ServerCluster::poll_deferred`](crate::dm::ServerCluster::poll_deferred) を
    /// 問い合わせ、`Ready` なら応答を構築して長さを返す(**スロットはまだ消さない**。統合層が
    /// 送信成功後に [`drop_deferred`](Self::drop_deferred) で消す。送信失敗時は次 poll で再構築
    /// できるよう保持する)。`Pending` かつ締切内なら `Ok(None)`(まだ返さない)。締切超過時は
    /// cluster の完了を待たず Timeout ステータスで応答する。`exchange` が保留スロットと一致
    /// しなければ [`Error::NotFound`]。
    pub fn build_deferred_invoke_response(
        &mut self,
        exchange: ExchangeId,
        tx: &mut [u8],
        now_ms: u64,
    ) -> Result<Option<usize>> {
        let Some(slot) = self.deferred else {
            return Err(Error::NotFound);
        };
        if slot.exchange != exchange {
            return Err(Error::NotFound);
        }
        let path = slot.path;

        // cluster へ完了問い合わせ(応答フィールドはスクラッチに書かせ、確定後に転写)。
        //
        // スクラッチはスタックに置かず **`tx` の末尾を間借り**する。本関数は統合層の
        // `poll()` 経路(毎イテレーション呼ばれる)にインライン化され得るため、900B の
        // ローカル配列はターゲット(ESP32 等)のタスクスタック余裕を常時食い潰す
        // (実機で BLE ヒープ破壊として顕在化した)。deferred の応答は単一コマンドで
        // 小さく、`tx`(MAX_PACKET_SIZE)の先頭側だけで十分収まる。
        if tx.len() < INVOKE_SCRATCH + 128 {
            return Err(Error::NoSpace);
        }
        let (tx, scratch) = tx.split_at_mut(tx.len() - INVOKE_SCRATCH);
        let (ready, result, response_cmd, cluster_status, scratch_len) = {
            let mut sw = TlvWriter::new(scratch);
            let mut resp = CmdResponder::new(&mut sw);
            let poll = match self.dm.cluster_mut(path.endpoint, path.cluster) {
                Some(c) => c.poll_deferred(path.command, &mut resp),
                // cluster が消えた等は Failure 相当で確定させる(スロットを stall させない)。
                None => DeferredPoll::Ready(Err(ImStatus::Failure)),
            };
            match poll {
                DeferredPoll::Pending => {
                    if now_ms < slot.deadline_ms {
                        return Ok(None);
                    }
                    // 締切超過: cluster の完了を待たず Timeout status(設計 §E7.2 フォールバック)。
                    (false, Err(ImStatus::Timeout), None, None, 0)
                }
                DeferredPoll::Ready(result) => {
                    let response_cmd = resp.response_command();
                    let cluster_status = resp.cluster_status();
                    let scratch_len = sw.len();
                    (true, result, response_cmd, cluster_status, scratch_len)
                }
            }
        };
        let _ = ready;

        let header = InvokeResponseHeader {
            suppress_response: false,
            more_chunks: false,
        };
        let len = encode_invoke_response(tx, header, |cw| match result {
            Ok(()) => {
                if let Some(rid) = response_cmd {
                    let rpath = CommandPath::new(path.endpoint, path.cluster, rid);
                    cw.push_command(&rpath, slot.command_ref, |w, tag| {
                        transcribe(&scratch[..scratch_len], w, tag)
                    })
                } else {
                    cw.push_status(
                        &path,
                        &StatusIB::simple(ImStatus::Success),
                        slot.command_ref,
                    )
                }
            }
            Err(s) => cw.push_status(&path, &StatusIB::new(s, cluster_status), slot.command_ref),
        })?;
        Ok(Some(len))
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

    /// MRP が諦めた exchange を購読レポートへ逆引きし、該当購読を破棄する(設計 §6.3)。
    ///
    /// 統合層が `PollAction::Failed` のたびに呼ぶ。チャンク継続中は reads の
    /// [`ReadKind::Report`] slot、単一チャンクは購読の `report_exchange` で照合する。
    /// 該当が無ければ何もしない(購読レポート以外の exchange 失敗)。ack されない購読を
    /// 残すと、消えたピアへ max interval ごとにレポートを送り続けて exchange/tx バッファを
    /// 浪費する(実機回帰の 2 次要因)。
    pub fn on_report_exchange_failed(&mut self, exchange: ExchangeId) {
        let from_reads = self.reads.iter().find_map(|t| match t.kind {
            ReadKind::Report(id) if t.exchange == exchange => Some(id),
            _ => None,
        });
        let from_subs = self
            .subs
            .iter()
            .find(|s| s.report_exchange == Some(exchange))
            .map(|s| s.id);
        if let Some(id) = from_reads.or(from_subs) {
            self.on_report_failed(id);
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
        // 保留中の遅延応答の宛先セッションが閉じたら破棄する(送出先が無い、設計 §E7.2)。
        if let Some(d) = &self.deferred {
            if d.exchange.session() == session {
                self.deferred = None;
            }
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

    /// EventLog を掃引し、各 Active 購読の event_paths に合致する未配信イベント(番号 >= floor)
    /// があれば dirty を立てる(設計 §12、dirty 掃引への相乗り)。
    fn sweep_events(&mut self) {
        for i in 0..self.subs.len() {
            let s = &self.subs[i];
            if s.state != SubState::Active || s.dirty {
                continue;
            }
            if sub_has_new_event(s, &self.events) {
                self.subs[i].dirty = true;
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

    /// 購読 `id` の配信済みイベント floor を設定する(設計 §12)。
    fn set_event_floor(&mut self, id: u32, floor: u64) {
        let idx = self.subs.iter().position(|s| s.id == id);
        if let Some(i) = idx {
            self.subs[i].event_floor = floor;
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
    was_timed: bool,
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
    let (required, needs_timed) = match dm.cluster(endpoint, cluster_id) {
        Some(c) => c
            .meta()
            .attribute(attribute)
            .map(|m| (m.write_access, m.timed))
            .unwrap_or((Privilege::Operate, false)),
        None => return ImStatus::UnsupportedCluster,
    };
    // timed 必須属性の強制(設計 §5.5 / admin-commissioning.md §3)。
    if needs_timed && !was_timed {
        return ImStatus::NeedsTimedInteraction;
    }
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
    /// ArmFailSafe(0) の fail-safe クリーンアップ(Core Spec §11.10)。
    failsafe_cleanup: bool,
    /// CommissioningComplete の fabric 確定(Core Spec §11.10)。
    commissioning_complete: bool,
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
        self.failsafe_cleanup |= other.failsafe_cleanup;
        self.commissioning_complete |= other.commissioning_complete;
    }
}

/// 1 つの CommandDataIB を起動し、応答(生成レスポンス or StatusIB)を `cw` に書く(設計 §9)。
///
/// クラスタが [`CmdResponder::set_response`](crate::dm::codec::CmdResponder::set_response) で
/// 生成レスポンスを宣言した場合、そのフィールド(スクラッチ上の匿名構造体)を InvokeResponseIB の
/// CommandDataIB へ転写する。宣言が無ければ結果ステータスを CommandStatusIB として書く。
/// 返り値はクラスタが要求した副作用([`InvokeEffects`])。
///
/// クラスタが [`CmdResponder::set_deferred`](crate::dm::codec::CmdResponder::set_deferred) を
/// 立てた場合は `cw` に何も書かず、`defer_out` に [`DeferReq`] を返す(応答保留、設計 §E7.2)。
/// 呼び出し側([`invoke`](InteractionModel::invoke))が単独コマンドか等を判定してスロット化する。
fn invoke_one<D: DataModel + ?Sized>(
    dm: &mut D,
    item: &CommandDataRef<'_>,
    acc: &AccessContext,
    was_timed: bool,
    cw: &mut CmdRespWriter<'_, '_>,
    defer_out: &mut Option<DeferReq>,
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
    let (required, needs_timed) = match dm.cluster(path.endpoint, path.cluster) {
        Some(c) => c
            .meta()
            .accepted_commands
            .iter()
            .find(|m| m.id == path.command)
            .map(|m| (m.access, m.timed))
            .unwrap_or((Privilege::Operate, false)),
        None => {
            cw.push_status(
                &path,
                &StatusIB::simple(ImStatus::UnsupportedCluster),
                item.command_ref,
            )?;
            return Ok(InvokeEffects::default());
        }
    };
    // timed 必須コマンドの強制(設計 §5.5 / admin-commissioning.md §3)。
    if needs_timed && !was_timed {
        cw.push_status(
            &path,
            &StatusIB::simple(ImStatus::NeedsTimedInteraction),
            item.command_ref,
        )?;
        return Ok(InvokeEffects::default());
    }
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
    let (result, response_cmd, effects, cluster_status, deferred, scratch_len) = {
        let mut sw = TlvWriter::new(&mut scratch);
        let (result, response_cmd, effects, cluster_status, deferred) = {
            let mut resp = CmdResponder::new(&mut sw);
            let result = cluster.invoke_command(path.command, &mut fr, &mut resp, acc);
            let effects = InvokeEffects {
                promote: resp.requested_promotion(),
                case_admin: resp.requested_case_admin_acl(),
                removed_fabric: resp.requested_fabric_removed(),
                failsafe_cleanup: resp.requested_failsafe_cleanup(),
                commissioning_complete: resp.requested_commissioning_complete(),
            };
            (
                result,
                resp.response_command(),
                effects,
                resp.cluster_status(),
                resp.is_deferred(),
            )
        };
        let scratch_len = sw.len();
        (
            result,
            response_cmd,
            effects,
            cluster_status,
            deferred,
            scratch_len,
        )
    };

    // 応答保留(設計 §E7.2): cluster が set_deferred + Ok を返したら `cw` に何も書かず、
    // 呼び出し側へ保留を通知する。エラーを返したなら保留は無視して通常の status を書く。
    if deferred && result.is_ok() {
        *defer_out = Some(DeferReq {
            path,
            command_ref: item.command_ref,
        });
        return Ok(effects);
    }

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
            // クラスタ固有ステータス(§11.19.6 等)があれば StatusIB.cluster_status に写す。
            cw.push_status(&path, &StatusIB::new(s, cluster_status), item.command_ref)?;
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
            // 未認証/PlainText 等はサイレントドロップ(panic しない)。`Err` で返して
            // exchange 層に会話を終端予約させる(`Ok(None)` だと新規 responder 会話が
            // 残留して EXCHANGES を食い潰す)。
            Err(_) => return Err(Error::InvalidState),
        };
        match ImOpCode::from_u8(rx.header.proto_opcode)? {
            ImOpCode::ReadRequest => self.read_open(rx, tx, &acc, now_ms),
            ImOpCode::SubscribeRequest => self.subscribe_open(rx, tx, &acc, now_ms),
            ImOpCode::WriteRequest => self.write(rx, tx, &acc, now_ms),
            ImOpCode::InvokeRequest => self.invoke(rx, tx, &acc, sessions, now_ms),
            ImOpCode::TimedRequest => self.timed_open(rx, tx, now_ms),
            ImOpCode::StatusResponse => self.on_status(rx, tx, now_ms),
            // ReportData/SubscribeResponse/WriteResponse/InvokeResponse は client→device では不正。
            // `Err` で exchange 層に終端予約させる(上記と同じ理由)。
            _ => Err(Error::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests;
