//! Interaction Model クライアント(コントローラ側、`docs/design/controller.md` §4)。
//!
//! [`ImClient`] は Protocol ID 0x0001 の [`ProtocolHandler`] を実装し、**自分が開始した
//! exchange への応答**(ReportData / WriteResponse / InvokeResponse / StatusResponse /
//! SubscribeResponse)を消費する同期状態機械である。デバイス側 [`InteractionModel`] の
//! **鏡像**で、既存契約([`ProtocolHandler`] / [`HandlerAction`])への追加はゼロ(§4.2)。
//!
//! # 契約への適合(§4)
//!
//! - **開始**(受信駆動でない最初の送信)だけが契約の外にある。[`ImClient::start_read`] /
//!   [`ImClient::start_invoke`] / [`ImClient::start_write`] / [`ImClient::start_subscribe`] が
//!   `out` に IM リクエスト payload を書いて長さを返し、送信は統合層(`ControllerStack` /
//!   テスト)が `open_initiator` + `send_reliable` で行う([`ScInitiator`](crate::sc::initiator)
//!   の `start_*` と同型)。
//! - **応答消費**は [`ProtocolHandler::handle`] の一本道で届く。チャンク継続の合図
//!   (`MoreChunkedMessages=true`)には `StatusResponse(SUCCESS)` を [`HandlerAction::Respond`]
//!   で返し(「次を送れ」)、終端では結果を 1 深度イベント [`ImEvent`] に積む
//!   (`take_event` でポーリング取り出し、§4.4)。
//!
//! # 受信の混線が起きない理由(§3.1)
//!
//! 処理するのは常に「自分が `open_initiator` で開いた exchange への応答」であり、exchange 層の
//! role 対称照合が保証する。[`ImClient::handle`] は進行中トランザクションの exchange 以外を
//! silent drop する。**唯一の例外**はデバイス発の購読レポート(自分が responder の exchange に
//! 届く ReportData、§4.5)で、SubscriptionID を購読テーブルと照合して受理する。
//!
//! # Subscribe(§4.5)
//!
//! [`ImClient::start_subscribe`] でプライミング → [`ImEvent::SubscribeDone`] で確立
//! (購読テーブルへ登録、容量 [`MAX_CLIENT_SUBSCRIPTIONS`])。以降のデバイス発レポートは
//! チャンクごとに `StatusResponse(SUCCESS)` で ack し、レポート完了ごとに
//! [`ImEvent::SubscriptionReport`](本文は [`ImClient::sub_reports`]、`result` とは別の
//! 固定バッファに最新 1 件を保持)。maxInterval + [`SUBSCRIPTION_GRACE_MS`] を超えて
//! レポートが途絶したら [`ImClient::on_tick`] が購読を破棄し [`ImEvent::SubscriptionLost`]
//! を積む(keep-alive 途絶検出、期限は [`ImClient::next_sub_deadline`] で統合層へ供給)。
//!
//! # 結果の受け渡し(§4.4)
//!
//! Read の結果は固定バッファ `result`(既定 1280B = 1 チャンク相当)へ生 TLV
//! (`AttributeReportIB` の連結)としてコピーし、[`ImClient::read_reports`] で走査する。
//! バッファ溢れは打ち切り、[`ImEvent::Failed`]`(ResourceExhausted)` で終端する
//! (ストリーミング化は設計オープン論点 §9-3)。コマンド応答の意味的デコード
//! (NOCSRElements 等)は上位([`Commissioner`](crate::controller) 相当)が [`ImClient::result`]
//! の生 TLV から行う(`ImClient` はクラスタ知識を持たない)。

use crate::error::{Error, Result};
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, Role, RxMessage};
use crate::im::wire::{
    encode_invoke_request, encode_read_request, encode_subscribe_request,
    encode_subscribe_request_events, encode_write_request, AttributeDataRef, AttributePath,
    AttributeReportRef, AttributeStatusRef, CommandPath, EventPath, EventReportRef, ImOpCode,
    ImStatus, InvokeRequestHeader, InvokeResponseRef, InvokeResponseRefItem, ReportDataRef,
    StatusIB, StatusResponse, SubscribeResponse, TimedRequest, WriteRequestHeader,
    WriteResponseRef, PROTO_ID_INTERACTION_MODEL,
};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::fixed::FixedVec;
use crate::transport::session::{SessionId, SessionManager};

/// 放置されたトランザクションを掃除するまでの時間(ミリ秒)。デバイス側 Read slot と同値。
pub const CLIENT_TXN_TIMEOUT_MS: u64 = 30_000;

/// `result` バッファの既定サイズ(バイト)。1 チャンク(≈ 1 パケット)相当(§4.4)。
pub const DEFAULT_RESULT_LEN: usize = 1280;

/// 同時に保持できる確立済み購読数(容量 const、§4.5.2)。
///
/// const generic にしない判断: 型パラメータ追加は `ControllerStack` / example まで
/// シグネチャが波及する。CLI 用途(`smctl subscribe`)には固定 4 で足りる。
pub const MAX_CLIENT_SUBSCRIPTIONS: usize = 4;

/// maxInterval 超過をロスト(keep-alive 途絶)と判定するまでの猶予(ミリ秒、§4.5.3)。
///
/// デバイス側は `now >= last_report + max` でレポートを出すが、MRP 再送・処理遅延の
/// ゆらぎがあるため即断しない。chip の liveness timeout(maxInterval + MRP 往復余裕)相当。
///
/// 30 秒: MRP は最大 10 送信(累計 ~34 秒)まで再送するため、5 秒では「レポート 1 通の
/// 再送が数秒続いた」だけで誤 LOST → 再購読 → デバイス側に幽霊購読を量産していた
/// (設計 §16.6 P3、Tab5 実機 2026-08-26)。
pub const SUBSCRIPTION_GRACE_MS: u64 = 30_000;

// ==========================================================================
// イベント
// ==========================================================================

/// 完了/失敗イベント(1 深度、`take_event` でポーリング取り出し、§4.4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImEvent {
    /// Read が完了した。[`ImClient::read_reports`] / [`ImClient::result`] で結果を取り出す。
    ReadDone,
    /// Invoke が完了した。生成レスポンス TLV(あれば)は [`ImClient::result`] に格納される。
    InvokeDone {
        /// 応答の総合ステータス(CommandStatusIB の非成功が 1 つでもあればその値)。
        status: ImStatus,
    },
    /// Write が完了した。
    WriteDone {
        /// 応答の総合ステータス(AttributeStatusIB の非成功が 1 つでもあればその値)。
        status: ImStatus,
    },
    /// Subscribe のプライミングが完了し購読が確立した。
    SubscribeDone {
        /// 購読が乗るセッション(購読 ID はデバイスごとの採番で衝突するため、
        /// `(session, subscription_id)` で初めて一意、設計 §16.6 P7)。
        session: SessionId,
        /// デバイスが採番した購読 ID。
        subscription_id: u32,
        /// ネゴシエート済み最大レポート間隔(秒)。keep-alive 途絶検出の基準。
        max_interval_s: u16,
    },
    /// デバイス発の購読レポートを 1 件受理した(§4.5.4)。
    ///
    /// 本文(AttributeReportIB 連結の生 TLV)は [`ImClient::sub_report`] /
    /// [`ImClient::sub_reports`] で取り出す(次のレポート到着まで保持)。
    SubscriptionReport {
        /// 対象購読が乗るセッション(§16.6 P7)。
        session: SessionId,
        /// 対象購読 ID。
        subscription_id: u32,
    },
    /// 購読がロストした(maxInterval + 猶予を超えてレポートが途絶、§4.5.3)。
    SubscriptionLost {
        /// 対象購読が乗っていたセッション(§16.6 P7)。
        session: SessionId,
        /// 対象購読 ID(client 側の購読 slot は破棄済み)。
        subscription_id: u32,
    },
    /// トランザクションが失敗した(StatusResponse 受信・デコード不能・溢れ・タイムアウト)。
    Failed {
        /// 失敗のステータス。
        status: ImStatus,
    },
}

// ==========================================================================
// トランザクション slot
// ==========================================================================

/// 進行中トランザクションの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxnKind {
    /// Read(ReportData を消費、最終チャンクで [`ImEvent::ReadDone`])。
    Read,
    /// Write(WriteResponse を消費)。
    Write,
    /// Invoke(InvokeResponse を消費)。
    Invoke,
    /// Subscribe(プライミング ReportData を消費 → SubscribeResponse で確立)。
    Subscribe,
}

/// 進行中 1 本のトランザクション(§4.1、同時 1 本固定)。
#[derive(Debug, Clone, Copy)]
struct ClientTxn {
    /// `start_*` で開いた exchange(応答照合キー)。
    exchange: ExchangeId,
    /// 開始時刻(タイムアウト掃除用)。
    started_ms: u64,
    /// 種別。
    kind: TxnKind,
}

/// 確立済み購読(client 側、§4.5.2)。
#[derive(Debug, Clone, Copy)]
struct ClientSub {
    /// デバイスが採番した購読 ID。
    id: u32,
    /// 購読が乗るセッション。購読 ID はデバイスごとの採番なので別デバイス間で衝突する。
    /// `(session, id)` で初めて一意で、レポート照合もこの組で行う(設計 §16.6 P7)。
    session: SessionId,
    /// ネゴシエート済み最大レポート間隔(秒)。SubscribeResponse の値。
    max_interval_s: u16,
    /// 直近レポート(またはプライミング完了)時刻。keep-alive 途絶検出の基準。
    last_report_ms: u64,
}

impl ClientSub {
    /// この購読をロストと判定する絶対時刻(ミリ秒)。
    fn lost_deadline_ms(&self) -> u64 {
        self.last_report_ms
            .saturating_add((self.max_interval_s as u64) * 1000)
            .saturating_add(SUBSCRIPTION_GRACE_MS)
    }
}

/// チャンク継続中のデバイス発レポート(同時 1 本、§4.5.2)。
#[derive(Debug, Clone, Copy)]
struct ReportRx {
    /// デバイスが開いた exchange(継続照合キー)。
    exchange: ExchangeId,
    /// 対象購読 ID。
    subscription_id: u32,
}

// ==========================================================================
// ImClient
// ==========================================================================

/// Interaction Model(Protocol ID 0x0001)の **クライアント** ハンドラ(§4)。
///
/// 同時トランザクションは 1 本固定(`Option` 1 slot)で、2 本目の `start_*` は
/// [`Error::NoSpace`](Busy)。`RESULT` は Read/Invoke 応答を写す固定バッファ長
/// (既定 [`DEFAULT_RESULT_LEN`])。
pub struct ImClient<const RESULT: usize = DEFAULT_RESULT_LEN> {
    txn: Option<ClientTxn>,
    event: Option<ImEvent>,
    result: [u8; RESULT],
    result_len: usize,
    truncated: bool,
    /// 確立済み購読テーブル(§4.5.2)。
    subs: FixedVec<ClientSub, MAX_CLIENT_SUBSCRIPTIONS>,
    /// チャンク継続中のデバイス発レポート(同時 1 本)。
    report_rx: Option<ReportRx>,
    /// 直近の購読レポート本文(AttributeReportIB 連結)。txn の `result` と分離(§4.5.2)。
    sub_result: [u8; RESULT],
    /// `sub_result` の有効長。
    sub_result_len: usize,
    /// 直近の購読レポートのイベント本文(EventReportIB 連結、設計 §12)。属性本文と分離。
    sub_event_result: [u8; RESULT],
    /// `sub_event_result` の有効長。
    sub_event_result_len: usize,
    /// 直近レポートが溢れて打ち切られたか。
    sub_truncated: bool,
    /// 購読系イベントの 1 深度 slot(txn イベントと分離。取り出し前の上書きは最新優先)。
    sub_event: Option<ImEvent>,
    /// timed invoke/write の 2 相目(InvokeRequest/WriteRequest payload)の退避長。
    ///
    /// [`Self::start_invoke_timed`] / [`Self::start_write_timed`] が後続リクエストを `result` に
    /// 先エンコードして退避し、TimedRequest への `StatusResponse(SUCCESS)` 受信時に同 exchange の
    /// 応答として送出する(opcode は進行中トランザクション種別で決まる。
    /// `docs/design/admin-commissioning.md` §3)。
    pending_invoke_len: Option<usize>,
    /// 直近の InvokeResponse に載っていたクラスタ固有ステータス(§8.10 StatusIB)。
    ///
    /// [`ImEvent::InvokeDone`] の `status` は IM ステータスなので、AdministratorCommissioning の
    /// Busy(2)/ PAKEParameterError(3)のようなクラスタ固有コードはここに退避する
    /// (`docs/design/p4-thread-controller.md` §17.2)。次の InvokeResponse で上書きされる。
    last_cluster_status: Option<u8>,
}

impl<const RESULT: usize> Default for ImClient<RESULT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const RESULT: usize> ImClient<RESULT> {
    /// 空のクライアントハンドラを生成する。
    pub const fn new() -> Self {
        Self {
            txn: None,
            event: None,
            result: [0u8; RESULT],
            result_len: 0,
            truncated: false,
            subs: FixedVec::new(),
            report_rx: None,
            sub_result: [0u8; RESULT],
            sub_result_len: 0,
            sub_event_result: [0u8; RESULT],
            sub_event_result_len: 0,
            sub_truncated: false,
            sub_event: None,
            pending_invoke_len: None,
            last_cluster_status: None,
        }
    }

    /// 直近の InvokeResponse のクラスタ固有ステータス(無ければ `None`)。
    ///
    /// [`ImEvent::InvokeDone`] を受け取った直後に読む。
    pub const fn last_cluster_status(&self) -> Option<u8> {
        self.last_cluster_status
    }

    /// 進行中トランザクションがあれば `true`。
    pub const fn is_busy(&self) -> bool {
        self.txn.is_some()
    }

    /// 進行中トランザクションが使用中の exchange を返す(統合層の exchange 回収判定用)。
    pub fn active_exchange(&self) -> Option<ExchangeId> {
        self.txn.as_ref().map(|t| t.exchange)
    }

    /// 完了/失敗イベントを 1 件取り出す(§4.4)。
    ///
    /// トランザクション系イベントを優先し、無ければ購読系イベント
    /// ([`ImEvent::SubscriptionReport`] / [`ImEvent::SubscriptionLost`])を返す(§4.5.4)。
    pub fn take_event(&mut self) -> Option<ImEvent> {
        self.event.take().or_else(|| self.sub_event.take())
    }

    /// トランザクション系イベント(Read / Invoke / Write / Subscribe の完了・失敗)だけを取り出す。
    ///
    /// 購読系イベント(SubscriptionReport / SubscriptionLost)は残す。コミッショナのように自分の
    /// トランザクション完了だけを待つ利用者が、同じスタックで動いている他ノードの購読レポートを
    /// 「想定外のイベント」として誤って消費・失敗扱いしないため(実機: Tab5 で既存ノードの購読
    /// レポートが CommissioningComplete 待ちに割り込み Protocol エラーで失敗した)。
    pub fn take_txn_event(&mut self) -> Option<ImEvent> {
        self.event.take()
    }

    /// 直近イベントの結果 payload(生 TLV)を返す(§4.4)。
    ///
    /// Read では `AttributeReportIB` の連結(→ [`ImClient::read_reports`] で走査)、Invoke では
    /// `InvokeResponseIB` の連結。次の `start_*` までは保持される。
    pub fn result(&self) -> &[u8] {
        &self.result[..self.result_len]
    }

    /// 直近 Read 結果を [`AttributeReportRef`] 列として走査する(§4.4)。
    pub fn read_reports(&self) -> AttrReports<'_> {
        AttrReports {
            r: TlvReader::new(self.result()),
            done: false,
        }
    }

    /// 結果バッファが溢れて打ち切られたら `true`。
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// 直近の購読レポート本文(AttributeReportIB 連結の生 TLV、§4.5.4)。
    ///
    /// 次のレポート到着まで保持される([`ImEvent::SubscriptionReport`] を受けたら
    /// 速やかに取り出すこと)。
    pub fn sub_report(&self) -> &[u8] {
        &self.sub_result[..self.sub_result_len]
    }

    /// 直近の購読レポートを [`AttributeReportRef`] 列として走査する(§4.5.4)。
    pub fn sub_reports(&self) -> AttrReports<'_> {
        AttrReports {
            r: TlvReader::new(self.sub_report()),
            done: false,
        }
    }

    /// 直近の購読レポートのイベント本文(EventReportIB 連結の生 TLV、設計 §12)。
    pub fn sub_event_report(&self) -> &[u8] {
        &self.sub_event_result[..self.sub_event_result_len]
    }

    /// 直近の購読レポートを [`EventReportRef`] 列として走査する(設計 §12)。
    pub fn sub_event_reports(&self) -> EventReports<'_> {
        EventReports {
            r: TlvReader::new(self.sub_event_report()),
            done: false,
        }
    }

    /// 直近の購読レポートが溢れて打ち切られたら `true`。
    pub const fn is_sub_truncated(&self) -> bool {
        self.sub_truncated
    }

    /// 確立済み購読数。
    pub fn subscription_count(&self) -> usize {
        self.subs.len()
    }

    /// 購読テーブル容量(診断用)。
    pub const fn subscription_capacity(&self) -> usize {
        MAX_CLIENT_SUBSCRIPTIONS
    }

    /// 購読 `(session, id)` をローカルのテーブルから捨てる(設計 §16.6 P4/P7)。
    /// 戻り値 = 実際に消したか。
    ///
    /// デバイスへは何も送らない。以降その購読 ID のレポートには `InvalidSubscription` を
    /// 返すため、デバイス側は(§16.6 P2 の修正により)その購読を捨てて双方が整合する。
    /// [`ImEvent::SubscriptionLost`] は積まない(呼び出し元が意図して捨てているため)。
    pub fn remove_subscription(&mut self, session: SessionId, id: u32) -> bool {
        let Some(i) = self
            .subs
            .iter()
            .position(|s| s.id == id && s.session == session)
        else {
            return false;
        };
        self.subs.swap_remove(i);
        self.drop_report_rx_of(session, id);
        true
    }

    /// チャンク継続中のレポートが購読 `(session, id)` のものなら捨てる(§16.6 P7)。
    fn drop_report_rx_of(&mut self, session: SessionId, id: u32) {
        if matches!(&self.report_rx, Some(r)
            if r.subscription_id == id && r.exchange.session() == session)
        {
            self.report_rx = None;
        }
    }

    /// セッション `session` に乗る購読を全て捨てる(戻り値 = 捨てた本数、設計 §16.6 P4)。
    ///
    /// CASE を張り直す(= 旧セッションを捨てる)ときに呼ぶと、旧セッションに残った購読が
    /// keep-alive 途絶まで client 側テーブルを占有するのを防げる。
    pub fn remove_subscriptions_on_session(&mut self, session: SessionId) -> usize {
        let mut n = 0;
        loop {
            let Some(i) = self.subs.iter().position(|s| s.session == session) else {
                break;
            };
            let id = self.subs.swap_remove(i).id;
            self.drop_report_rx_of(session, id);
            n += 1;
        }
        n
    }

    /// チャンク継続中のデバイス発レポートが使用中の exchange(統合層の回収判定用、§4.5.4)。
    pub fn report_exchange(&self) -> Option<ExchangeId> {
        self.report_rx.as_ref().map(|r| r.exchange)
    }

    /// 全購読のロスト判定期限の最小(絶対時刻ミリ秒)。購読が無ければ `None`(§4.5.3)。
    ///
    /// 統合層(`ControllerStack::next_deadline`)が MRP 期限と min して 1 タイマにする。
    pub fn next_sub_deadline(&self) -> Option<u64> {
        self.subs.iter().map(|s| s.lost_deadline_ms()).min()
    }

    // ----------------------------------------------------------------------
    // 開始 API(§4.1。payload を out に書き、送信は統合層が行う)
    // ----------------------------------------------------------------------

    /// Read トランザクションを開始する。
    ///
    /// `paths`(ワイルドカード可)から ReadRequest を `out` に書き、その長さ
    /// (opcode = [`ImOpCode::ReadRequest`])を返す。進行中トランザクションがあれば
    /// [`Error::NoSpace`](Busy)。
    pub fn start_read(
        &mut self,
        exchange: ExchangeId,
        paths: &[AttributePath],
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        self.begin(exchange, TxnKind::Read, now_ms)?;
        let len = encode_read_request(out, false, |w| {
            for p in paths {
                w.push(p)?;
            }
            Ok(())
        });
        self.finish_start(len)
    }

    /// 単一コマンドの Invoke トランザクションを開始する。
    ///
    /// `fields` はコマンドフィールドを `tag`(context 1)で書くクロージャ(フィールドの無い
    /// コマンドでも空構造体等を書く)。InvokeRequest を `out` に書きその長さ
    /// (opcode = [`ImOpCode::InvokeRequest`])を返す。
    pub fn start_invoke<F>(
        &mut self,
        exchange: ExchangeId,
        path: CommandPath,
        fields: F,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize>
    where
        F: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        self.begin(exchange, TxnKind::Invoke, now_ms)?;
        let len = encode_invoke_request(out, InvokeRequestHeader::default(), |cw| {
            cw.push(&path, None, Some(fields))
        });
        self.finish_start(len)
    }

    /// timed invoke(TimedRequest → Invoke)トランザクションを開始する(設計 §5.5)。
    ///
    /// `out` には **TimedRequest**(opcode = [`ImOpCode::TimedRequest`])が書かれる。
    /// InvokeRequest(`timedRequest=true`)は内部バッファへ先エンコードして退避し、
    /// デバイスの `StatusResponse(SUCCESS)` 受信時に同 exchange の応答として自動送出する。
    /// 完了は通常の Invoke と同じく [`ImEvent::InvokeDone`]。
    pub fn start_invoke_timed<F>(
        &mut self,
        exchange: ExchangeId,
        timeout_ms: u16,
        path: CommandPath,
        fields: F,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize>
    where
        F: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        self.begin(exchange, TxnKind::Invoke, now_ms)?;
        // InvokeRequest を result バッファへ先エンコードして退避する(Invoke の結果書き込みは
        // InvokeResponse 受信時なので競合しない)。
        let header = InvokeRequestHeader {
            suppress_response: false,
            timed_request: true,
        };
        let invoke_len = match encode_invoke_request(&mut self.result, header, |cw| {
            cw.push(&path, None, Some(fields))
        }) {
            Ok(l) => l,
            Err(e) => {
                self.txn = None;
                return Err(e);
            }
        };
        self.pending_invoke_len = Some(invoke_len);
        let len = TimedRequest::new(timeout_ms).encode(out);
        match len {
            Ok(l) => Ok(l),
            Err(e) => {
                self.txn = None;
                self.pending_invoke_len = None;
                self.result_len = 0;
                Err(e)
            }
        }
    }

    /// 単一属性の Write トランザクションを開始する。
    ///
    /// `value` は属性値を `tag`(context 2)で書くクロージャ。WriteRequest を `out` に書き
    /// その長さ(opcode = [`ImOpCode::WriteRequest`])を返す。
    pub fn start_write<F>(
        &mut self,
        exchange: ExchangeId,
        path: &AttributePath,
        value: F,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize>
    where
        F: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        self.begin(exchange, TxnKind::Write, now_ms)?;
        let len = encode_write_request(out, WriteRequestHeader::default(), |aw| {
            aw.push(None, path, value)
        });
        self.finish_start(len)
    }

    /// timed write(TimedRequest → Write)トランザクションを開始する(設計 §5.5)。
    ///
    /// `out` には **TimedRequest**(opcode = [`ImOpCode::TimedRequest`])が書かれる。
    /// WriteRequest(`timedRequest=true`)は内部バッファへ先エンコードして退避し、
    /// デバイスの `StatusResponse(SUCCESS)` 受信時に同 exchange の応答として自動送出する。
    /// 完了は通常の Write と同じく [`ImEvent::WriteDone`]。
    pub fn start_write_timed<F>(
        &mut self,
        exchange: ExchangeId,
        timeout_ms: u16,
        path: &AttributePath,
        value: F,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize>
    where
        F: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        self.begin(exchange, TxnKind::Write, now_ms)?;
        // WriteRequest を result バッファへ先エンコードして退避する(Write の結果書き込みは
        // WriteResponse 受信時なので競合しない)。
        let header = WriteRequestHeader {
            suppress_response: false,
            timed_request: true,
        };
        let write_len =
            match encode_write_request(&mut self.result, header, |aw| aw.push(None, path, value)) {
                Ok(l) => l,
                Err(e) => {
                    self.txn = None;
                    return Err(e);
                }
            };
        self.pending_invoke_len = Some(write_len);
        let len = TimedRequest::new(timeout_ms).encode(out);
        match len {
            Ok(l) => Ok(l),
            Err(e) => {
                self.txn = None;
                self.pending_invoke_len = None;
                self.result_len = 0;
                Err(e)
            }
        }
    }

    /// Subscribe トランザクションを開始する。
    ///
    /// SubscribeRequest を `out` に書きその長さ(opcode = [`ImOpCode::SubscribeRequest`])を返す。
    /// プライミング ReportData の消化 → SubscribeResponse 受理までを駆動し、確立時に
    /// [`ImEvent::SubscribeDone`] を積んで購読テーブルへ登録する(容量
    /// [`MAX_CLIENT_SUBSCRIPTIONS`]、満杯なら SubscribeResponse 受理時に
    /// `Failed(ResourceExhausted)`)。
    ///
    /// 確立後の**定期/変化レポート**は device 発の新規 responder exchange として届き、
    /// [`ProtocolHandler::handle`] が受理して [`ImEvent::SubscriptionReport`] を積む(§4.5)。
    /// keep-alive 途絶(maxInterval + 猶予)は [`ImClient::on_tick`] が検出し
    /// [`ImEvent::SubscriptionLost`] を積む。
    pub fn start_subscribe(
        &mut self,
        exchange: ExchangeId,
        paths: &[AttributePath],
        min_interval_floor_s: u16,
        max_interval_ceiling_s: u16,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        self.begin(exchange, TxnKind::Subscribe, now_ms)?;
        let len = encode_subscribe_request(
            out,
            false,
            min_interval_floor_s,
            max_interval_ceiling_s,
            false,
            |w| {
                for p in paths {
                    w.push(p)?;
                }
                Ok(())
            },
        );
        self.finish_start(len)
    }

    /// イベントパス付き Subscribe を開始する(EventRequests + 任意の EventFilters eventMin、設計 §12)。
    ///
    /// 属性パス `attr_paths` とイベントパス `event_paths` を同一 SubscribeRequest に載せる
    /// (イベントのみの購読は `attr_paths` を空にする)。プライミングで既存イベントが配信され、
    /// 以降デバイス発レポートで新規イベントが届く([`Self::sub_event_reports`] で走査)。
    #[allow(clippy::too_many_arguments)]
    pub fn start_subscribe_events(
        &mut self,
        exchange: ExchangeId,
        attr_paths: &[AttributePath],
        event_paths: &[EventPath],
        event_min: Option<u64>,
        min_interval_floor_s: u16,
        max_interval_ceiling_s: u16,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        self.begin(exchange, TxnKind::Subscribe, now_ms)?;
        let len = encode_subscribe_request_events(
            out,
            false,
            min_interval_floor_s,
            max_interval_ceiling_s,
            false,
            |w| {
                for p in attr_paths {
                    w.push(p)?;
                }
                Ok(())
            },
            |w| {
                for p in event_paths {
                    w.push(p)?;
                }
                Ok(())
            },
            event_min,
        );
        self.finish_start(len)
    }

    /// 放置トランザクションと途絶した購読を掃除する(統合層が定期呼び出し、§4.1/§4.5.3)。
    ///
    /// トランザクションが期限切れなら破棄し [`ImEvent::Failed`]`(Timeout)` を積んで、その
    /// トランザクションの exchange を返す。**統合層は返った exchange を必ず close して
    /// 再送バッファを回収すること**(閉じないと、要求が standalone ACK で受領済み =
    /// 再送スロットが空で MRP の諦めも走らない exchange が永久に残り、プール枯渇で
    /// 以降の `start_*` が全て `NoSpace` になる — Tab5 実機 2026-08-25)。
    /// 加えて `last_report + maxInterval + 猶予` を超えた購読を破棄し
    /// [`ImEvent::SubscriptionLost`] を積む(戻り値には影響しない)。
    pub fn on_tick(&mut self, now_ms: u64) -> Option<ExchangeId> {
        let expired = match &self.txn {
            Some(t) if now_ms.saturating_sub(t.started_ms) > CLIENT_TXN_TIMEOUT_MS => {
                Some(t.exchange)
            }
            _ => None,
        };
        if expired.is_some() {
            self.txn = None;
            self.pending_invoke_len = None;
            self.event = Some(ImEvent::Failed {
                status: ImStatus::Timeout,
            });
        }
        // keep-alive 途絶の検出(§4.5.3)。
        loop {
            let Some(i) = self.subs.iter().position(|s| now_ms > s.lost_deadline_ms()) else {
                break;
            };
            let sub = self.subs.swap_remove(i);
            self.drop_report_rx_of(sub.session, sub.id);
            self.sub_event = Some(ImEvent::SubscriptionLost {
                session: sub.session,
                subscription_id: sub.id,
            });
        }
        expired
    }

    /// 進行中のトランザクションを外部都合で破棄する(統合層の待ちがタイムアウトした
    /// とき等)。イベントは積まない(呼び出し元が同期的に諦めているため)。破棄した
    /// トランザクションの exchange を返すので、統合層は close して再送バッファを回収する
    /// こと。進行中でなければ `None`。
    pub fn abort_txn(&mut self) -> Option<ExchangeId> {
        let ex = self.txn.take().map(|t| t.exchange);
        if ex.is_some() {
            self.pending_invoke_len = None;
            self.event = None;
        }
        ex
    }

    // ----------------------------------------------------------------------
    // 開始ヘルパ
    // ----------------------------------------------------------------------

    /// トランザクション slot を確保し、結果バッファをリセットする(Busy チェック込み)。
    fn begin(&mut self, exchange: ExchangeId, kind: TxnKind, now_ms: u64) -> Result<()> {
        if self.txn.is_some() {
            return Err(Error::NoSpace);
        }
        self.result_len = 0;
        self.truncated = false;
        self.event = None;
        self.pending_invoke_len = None;
        self.txn = Some(ClientTxn {
            exchange,
            started_ms: now_ms,
            kind,
        });
        Ok(())
    }

    /// エンコード結果を確定する。失敗時は slot を戻す(payload 未送出のため Busy を残さない)。
    fn finish_start(&mut self, encoded: Result<usize>) -> Result<usize> {
        match encoded {
            Ok(len) => Ok(len),
            Err(e) => {
                self.txn = None;
                Err(e)
            }
        }
    }

    // ----------------------------------------------------------------------
    // 受信処理(§4.2)
    // ----------------------------------------------------------------------

    /// ReportData を消費する(Read / Subscribe プライミング、§4.2)。
    fn on_report(&mut self, rx: &RxMessage<'_>, tx: &mut [u8]) -> Result<HandlerAction> {
        let rd = match ReportDataRef::new(rx.payload) {
            Ok(r) => r,
            Err(_) => return self.fail(ImStatus::InvalidAction),
        };
        let more = rd.more_chunks().unwrap_or(false);
        let suppress = rd.suppress_response().unwrap_or(false);

        if self.append_array_elements(rx.payload, 1).is_err() {
            return self.fail(ImStatus::InvalidAction);
        }
        if self.truncated {
            return self.fail(ImStatus::ResourceExhausted);
        }

        let is_sub = matches!(self.txn.as_ref().map(|t| t.kind), Some(TxnKind::Subscribe));

        // チャンク継続 or プライミング完了の合図: StatusResponse(SUCCESS) を返す。
        if more || is_sub {
            let len = StatusResponse::new(ImStatus::Success).encode(tx)?;
            return Ok(respond(ImOpCode::StatusResponse, len));
        }

        // 通常 Read の最終チャンク。
        self.event = Some(ImEvent::ReadDone);
        self.txn = None;
        if suppress {
            Ok(HandlerAction::None)
        } else {
            let len = StatusResponse::new(ImStatus::Success).encode(tx)?;
            Ok(close(ImOpCode::StatusResponse, len))
        }
    }

    /// InvokeResponse を消費する(§4.2)。
    fn on_invoke_resp(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        let ir = match InvokeResponseRef::new(rx.payload) {
            Ok(v) => v,
            Err(_) => return self.fail(ImStatus::InvalidAction),
        };
        // 生成レスポンス TLV を result へ写す(InvokeResponses = context 1)。
        let _ = self.append_array_elements(rx.payload, 1);

        let mut status = ImStatus::Success;
        self.last_cluster_status = None;
        match ir.invoke_responses() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok(InvokeResponseRefItem::Status(s)) => {
                            if !s.status.status.is_success() {
                                status = s.status.status;
                                self.last_cluster_status = s.status.cluster_status;
                            }
                        }
                        Ok(InvokeResponseRefItem::Command(_)) => {}
                        Err(_) => {
                            status = ImStatus::InvalidAction;
                            break;
                        }
                    }
                }
            }
            Err(_) => status = ImStatus::InvalidAction,
        }
        self.event = Some(ImEvent::InvokeDone { status });
        self.txn = None;
        Ok(HandlerAction::None)
    }

    /// WriteResponse を消費する(§4.2)。
    fn on_write_resp(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        let wr = match WriteResponseRef::new(rx.payload) {
            Ok(v) => v,
            Err(_) => return self.fail(ImStatus::InvalidAction),
        };
        let mut status = ImStatus::Success;
        match wr.write_responses() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok(s) => {
                            if !s.status.status.is_success() {
                                status = s.status.status;
                            }
                        }
                        Err(_) => {
                            status = ImStatus::InvalidAction;
                            break;
                        }
                    }
                }
            }
            Err(_) => status = ImStatus::InvalidAction,
        }
        self.event = Some(ImEvent::WriteDone { status });
        self.txn = None;
        Ok(HandlerAction::None)
    }

    /// SubscribeResponse を消費する(プライミング完了、§4.2)。
    ///
    /// 購読テーブルへ登録し(満杯なら `Failed(ResourceExhausted)`)、以降のデバイス発
    /// レポート([`Self::on_device_report`])と keep-alive 途絶検出の対象にする(§4.5)。
    fn on_subscribe_resp(&mut self, rx: &RxMessage<'_>, now_ms: u64) -> Result<HandlerAction> {
        match SubscribeResponse::decode(rx.payload) {
            Ok(sr) => {
                let sub = ClientSub {
                    id: sr.subscription_id,
                    session: rx.exchange.session(),
                    max_interval_s: sr.max_interval_s,
                    last_report_ms: now_ms,
                };
                if self.subs.push(sub).is_err() {
                    return self.fail(ImStatus::ResourceExhausted);
                }
                self.event = Some(ImEvent::SubscribeDone {
                    session: rx.exchange.session(),
                    subscription_id: sr.subscription_id,
                    max_interval_s: sr.max_interval_s,
                });
                self.txn = None;
                Ok(HandlerAction::None)
            }
            Err(_) => self.fail(ImStatus::InvalidAction),
        }
    }

    /// デバイス発の購読レポート(responder role の ReportData)を受理する(§4.5.1-2)。
    ///
    /// SubscriptionID を購読テーブルと照合し、未知 ID は `StatusResponse(InvalidSubscription)`
    /// で終端する(デバイス側の亡霊購読の掃除)。既知なら AttributeReports を `sub_result` へ
    /// 追記し、チャンク継続(`More=true`)は `Respond`、最終チャンクは `Close` +
    /// [`ImEvent::SubscriptionReport`]。いずれも `StatusResponse(SUCCESS)` を返す。
    fn on_device_report(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let Ok(rd) = ReportDataRef::new(rx.payload) else {
            // デコード不能な unsolicited は黙って落とす(応答しない)。
            return Ok(HandlerAction::None);
        };
        let more = rd.more_chunks().unwrap_or(false);
        let continuing = matches!(&self.report_rx, Some(r) if r.exchange == rx.exchange);
        // SubscriptionID はデバイス実装(engine::build_report / on_status)が全チャンクに
        // 付けるが、欠落時は継続中 exchange の記録で補う。
        let sub_id = match rd.subscription_id().unwrap_or(None) {
            Some(id) => Some(id),
            None if continuing => self.report_rx.as_ref().map(|r| r.subscription_id),
            None => None,
        };
        let Some(sub_id) = sub_id else {
            let len = StatusResponse::new(ImStatus::InvalidSubscription).encode(tx)?;
            return Ok(close(ImOpCode::StatusResponse, len));
        };
        // 購読 ID はデバイスごとの採番で別デバイス間で衝突するため、session と組で照合する
        // (§16.6 P7。ID だけで照合すると別ノードの幽霊レポートを受理してしまう)。
        let session = rx.exchange.session();
        let Some(si) = self
            .subs
            .iter()
            .position(|s| s.id == sub_id && s.session == session)
        else {
            if continuing {
                self.report_rx = None;
            }
            let len = StatusResponse::new(ImStatus::InvalidSubscription).encode(tx)?;
            return Ok(close(ImOpCode::StatusResponse, len));
        };

        if !continuing {
            // 新しいレポートの先頭チャンク: 直近レポートを破棄して上書き開始。
            self.sub_result_len = 0;
            self.sub_event_result_len = 0;
            self.sub_truncated = false;
        }
        if append_ctx_array_into(
            rx.payload,
            1,
            &mut self.sub_result,
            &mut self.sub_result_len,
        )
        .unwrap_or(true)
        {
            // 溢れ(または不正 TLV)は打ち切りマークだけ立て、レポート自体は ack する
            // (購読の生存を優先。本文は truncated として通知)。
            self.sub_truncated = true;
        }
        // EventReports(context 2)も別バッファへ写す(設計 §12)。
        if append_ctx_array_into(
            rx.payload,
            2,
            &mut self.sub_event_result,
            &mut self.sub_event_result_len,
        )
        .unwrap_or(true)
        {
            self.sub_truncated = true;
        }
        self.subs[si].last_report_ms = now_ms;

        let len = StatusResponse::new(ImStatus::Success).encode(tx)?;
        if more {
            self.report_rx = Some(ReportRx {
                exchange: rx.exchange,
                subscription_id: sub_id,
            });
            Ok(respond(ImOpCode::StatusResponse, len))
        } else {
            self.report_rx = None;
            self.sub_event = Some(ImEvent::SubscriptionReport {
                session,
                subscription_id: sub_id,
            });
            Ok(close(ImOpCode::StatusResponse, len))
        }
    }

    /// StatusResponse を受信した(エラー終端、§4.2)。
    fn on_status(&mut self, rx: &RxMessage<'_>, tx: &mut [u8]) -> Result<HandlerAction> {
        let status = StatusResponse::decode(rx.payload)
            .map(|s| s.status)
            .unwrap_or(ImStatus::InvalidAction);
        // timed invoke/write の 2 相目: TimedRequest への SUCCESS で退避済み
        // InvokeRequest/WriteRequest を送出する(opcode は進行中トランザクション種別で決まる)。
        if let Some(len) = self.pending_invoke_len.take() {
            if status.is_success() {
                if len > tx.len() {
                    return self.fail(ImStatus::ResourceExhausted);
                }
                tx[..len].copy_from_slice(&self.result[..len]);
                self.result_len = 0;
                let opcode = match self.txn.as_ref().map(|t| t.kind) {
                    Some(TxnKind::Write) => ImOpCode::WriteRequest,
                    _ => ImOpCode::InvokeRequest,
                };
                return Ok(respond(opcode, len));
            }
            return self.fail(status);
        }
        self.fail(status)
    }

    /// 進行中トランザクションを破棄し、`Failed` を積む。
    fn fail(&mut self, status: ImStatus) -> Result<HandlerAction> {
        self.txn = None;
        self.event = Some(ImEvent::Failed { status });
        Ok(HandlerAction::None)
    }

    /// メッセージ(anonymous 構造体)内の context 配列 `ctx` の各要素の生 TLV を `result` へ追記する。
    ///
    /// バッファに収まらない要素が出た時点で [`Self::truncated`] を立てて打ち切る。
    fn append_array_elements(&mut self, payload: &[u8], ctx: u8) -> Result<()> {
        if append_ctx_array_into(payload, ctx, &mut self.result, &mut self.result_len)? {
            self.truncated = true;
        }
        Ok(())
    }
}

/// メッセージ(anonymous 構造体)内の context 配列 `ctx` の各要素の生 TLV を `buf[..*len]` の
/// 後ろへ追記する。収まらない要素が出た時点で打ち切り `true`(truncated)を返す。
fn append_ctx_array_into(payload: &[u8], ctx: u8, buf: &mut [u8], len: &mut usize) -> Result<bool> {
    let Some(mut r) = locate_ctx_array(payload, ctx)? else {
        return Ok(false);
    };
    loop {
        let mut probe = r.clone();
        match probe.read_next()? {
            None => break,
            Some(e) if matches!(e.value, TlvValue::ContainerEnd) => break,
            Some(_) => {}
        }
        let raw = r.take_element_raw()?;
        let end = *len + raw.len();
        if end > buf.len() {
            return Ok(true);
        }
        buf[*len..end].copy_from_slice(raw);
        *len = end;
    }
    Ok(false)
}

/// [`HandlerAction::Respond`] を IM 応答として組む。
fn respond(opcode: ImOpCode, len: usize) -> HandlerAction {
    HandlerAction::Respond {
        opcode: opcode.to_u8(),
        proto_id: PROTO_ID_INTERACTION_MODEL,
        reliable: true,
        len,
    }
}

/// [`HandlerAction::Close`] を IM 応答(終端)として組む。
fn close(opcode: ImOpCode, len: usize) -> HandlerAction {
    HandlerAction::Close {
        opcode: opcode.to_u8(),
        proto_id: PROTO_ID_INTERACTION_MODEL,
        reliable: true,
        len,
    }
}

impl<const RESULT: usize> ProtocolHandler for ImClient<RESULT> {
    const PROTOCOL_ID: u16 = PROTO_ID_INTERACTION_MODEL;

    fn handle<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        _sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let op = match ImOpCode::from_u8(rx.header.proto_opcode) {
            Ok(op) => op,
            // 未知 opcode は silent drop(panic しない)。
            Err(_) => return Ok(HandlerAction::None),
        };
        // 自分の進行中 exchange への応答(§4.2)。
        if matches!(&self.txn, Some(t) if t.exchange == rx.exchange) {
            return match op {
                ImOpCode::ReportData => self.on_report(rx, tx),
                ImOpCode::InvokeResponse => self.on_invoke_resp(rx),
                ImOpCode::WriteResponse => self.on_write_resp(rx),
                ImOpCode::SubscribeResponse => self.on_subscribe_resp(rx, now_ms),
                ImOpCode::StatusResponse => self.on_status(rx, tx),
                // client 宛に Request 系は来ない(silent drop)。
                _ => Ok(HandlerAction::None),
            };
        }
        // デバイス発の購読レポート(自分が responder の exchange、§4.5)。
        // §3.1 の「unsolicited は受けない」方針の唯一の例外。
        if rx.role == Role::Responder && op == ImOpCode::ReportData {
            return self.on_device_report(rx, tx, now_ms);
        }
        Ok(HandlerAction::None)
    }
}

// ==========================================================================
// 結果走査(result 内の連結 AttributeReportIB)
// ==========================================================================

/// [`ImClient::result`] 内の連結 `AttributeReportIB` を走査するイテレータ(§4.4)。
#[derive(Debug, Clone)]
pub struct AttrReports<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl<'a> Iterator for AttrReports<'a> {
    type Item = Result<AttributeReportRef<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut probe = self.r.clone();
        match probe.read_next() {
            Ok(None) => {
                self.done = true;
                None
            }
            Ok(Some(e)) if matches!(e.value, TlvValue::ContainerEnd) => {
                self.done = true;
                None
            }
            Ok(Some(_)) => match decode_report(&mut self.r) {
                Ok(v) => Some(Ok(v)),
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// [`ImClient::sub_event_report`] 内の連結 `EventReportIB` を走査するイテレータ(設計 §12)。
#[derive(Debug, Clone)]
pub struct EventReports<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl<'a> Iterator for EventReports<'a> {
    type Item = Result<EventReportRef<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut probe = self.r.clone();
        match probe.read_next() {
            Ok(None) => {
                self.done = true;
                None
            }
            Ok(Some(e)) if matches!(e.value, TlvValue::ContainerEnd) => {
                self.done = true;
                None
            }
            Ok(Some(_)) => match EventReportRef::decode(&mut self.r) {
                Ok(v) => Some(Ok(v)),
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// anonymous 構造体内の context 配列 `ctx` の内側に位置するリーダを返す(無ければ `None`)。
fn locate_ctx_array(payload: &[u8], ctx: u8) -> Result<Option<TlvReader<'_>>> {
    let mut r = TlvReader::new(payload);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    loop {
        let e = match r.read_next()? {
            None => return Ok(None),
            Some(e) => e,
        };
        if matches!(e.value, TlvValue::ContainerEnd) {
            return Ok(None);
        }
        if e.tag == TlvTag::ContextSpecific(ctx) {
            // read_next が配列開始を消費し、リーダは配列内部に位置する。
            return match e.value {
                TlvValue::ContainerStart(ContainerType::Array) => Ok(Some(r)),
                _ => Ok(None),
            };
        }
        r.skip(&e)?;
    }
}

/// 連結 `AttributeReportIB` の 1 要素(struct)を [`AttributeReportRef`] へデコードする。
///
/// `im::wire` の非公開デコーダに触れず、公開 API([`AttributePath::decode`] /
/// [`StatusIB::decode`] / 公開フィールド)だけで再構成する(wire.rs 無改造の担保)。
fn decode_report<'a>(r: &mut TlvReader<'a>) -> Result<AttributeReportRef<'a>> {
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut out = None;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match e.value {
            TlvValue::ContainerEnd => break,
            TlvValue::ContainerStart(ContainerType::Structure) => match e.tag {
                TlvTag::ContextSpecific(0) => {
                    out = Some(AttributeReportRef::Status(decode_status(r)?))
                }
                TlvTag::ContextSpecific(1) => out = Some(AttributeReportRef::Data(decode_data(r)?)),
                _ => r.exit_container()?,
            },
            // 予期しないスカラ(revision 等)は read_next で消費済み。
            _ => {}
        }
    }
    out.ok_or(Error::Decode)
}

/// AttributeStatusIB(`{ path(0), status(1) }`)の本体を読む(構造体開始は消費済み)。
fn decode_status(r: &mut TlvReader<'_>) -> Result<AttributeStatusRef> {
    let mut path = None;
    let mut status = None;
    loop {
        let mut probe = r.clone();
        let e = match probe.read_next()? {
            None => return Err(Error::Decode),
            Some(e) => e,
        };
        if matches!(e.value, TlvValue::ContainerEnd) {
            r.read_next()?;
            break;
        }
        match e.tag {
            TlvTag::ContextSpecific(0) => path = Some(AttributePath::decode(r)?),
            TlvTag::ContextSpecific(1) => status = Some(StatusIB::decode(r)?),
            _ => {
                r.take_element_raw()?;
            }
        }
    }
    Ok(AttributeStatusRef {
        path: path.ok_or(Error::Decode)?,
        status: status.ok_or(Error::Decode)?,
    })
}

/// AttributeDataIB(`{ dataVer(0)?, path(1), data(2) }`)の本体を読む(構造体開始は消費済み)。
fn decode_data<'a>(r: &mut TlvReader<'a>) -> Result<AttributeDataRef<'a>> {
    let mut data_version = None;
    let mut path = None;
    let mut data = None;
    loop {
        let mut probe = r.clone();
        let e = match probe.read_next()? {
            None => return Err(Error::Decode),
            Some(e) => e,
        };
        if matches!(e.value, TlvValue::ContainerEnd) {
            r.read_next()?;
            break;
        }
        match e.tag {
            TlvTag::ContextSpecific(0) => {
                let v = r.read_next()?.ok_or(Error::Decode)?.value.as_unsigned()?;
                data_version = Some(u32::try_from(v).map_err(|_| Error::Decode)?);
            }
            TlvTag::ContextSpecific(1) => path = Some(AttributePath::decode(r)?),
            TlvTag::ContextSpecific(2) => data = Some(r.take_element_raw()?),
            _ => {
                r.take_element_raw()?;
            }
        }
    }
    Ok(AttributeDataRef {
        data_version,
        path: path.ok_or(Error::Decode)?,
        data: data.ok_or(Error::Decode)?,
    })
}

#[cfg(test)]
mod tests;
