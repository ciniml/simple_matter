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
//! silent drop する。
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
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, RxMessage};
use crate::im::wire::{
    encode_invoke_request, encode_read_request, encode_subscribe_request, encode_write_request,
    AttributeDataRef, AttributePath, AttributeReportRef, AttributeStatusRef, CommandPath, ImOpCode,
    ImStatus, InvokeRequestHeader, InvokeResponseRef, InvokeResponseRefItem, ReportDataRef,
    StatusIB, StatusResponse, SubscribeResponse, WriteRequestHeader, WriteResponseRef,
    PROTO_ID_INTERACTION_MODEL,
};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::SessionManager;

/// 放置されたトランザクションを掃除するまでの時間(ミリ秒)。デバイス側 Read slot と同値。
pub const CLIENT_TXN_TIMEOUT_MS: u64 = 30_000;

/// `result` バッファの既定サイズ(バイト)。1 チャンク(≈ 1 パケット)相当(§4.4)。
pub const DEFAULT_RESULT_LEN: usize = 1280;

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
        /// デバイスが採番した購読 ID。
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
        }
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
    pub fn take_event(&mut self) -> Option<ImEvent> {
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

    /// Subscribe トランザクションを開始する(プライミングまで)。
    ///
    /// SubscribeRequest を `out` に書きその長さ(opcode = [`ImOpCode::SubscribeRequest`])を返す。
    /// プライミング ReportData の消化 → SubscribeResponse 受理までを駆動し、確立時に
    /// [`ImEvent::SubscribeDone`] を積む。
    ///
    /// # スコープ(設計 §4.3 / オープン論点 §9-2)
    ///
    /// 確立後の**定期/変化レポート**は device 発の新規 responder exchange として届くため、その
    /// 受理経路は本ピースのスコープ外(初期スコープは Read/Write/Invoke + Subscribe プライミング)。
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

    /// 放置トランザクションを掃除する(統合層が定期呼び出し、§4.1)。
    ///
    /// 期限切れなら破棄し [`ImEvent::Failed`]`(Timeout)` を積んで `true` を返す。
    pub fn on_tick(&mut self, now_ms: u64) -> bool {
        let expired = match &self.txn {
            Some(t) => now_ms.saturating_sub(t.started_ms) > CLIENT_TXN_TIMEOUT_MS,
            None => false,
        };
        if expired {
            self.txn = None;
            self.event = Some(ImEvent::Failed {
                status: ImStatus::Timeout,
            });
        }
        expired
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
        match ir.invoke_responses() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok(InvokeResponseRefItem::Status(s)) => {
                            if !s.status.status.is_success() {
                                status = s.status.status;
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
    fn on_subscribe_resp(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        match SubscribeResponse::decode(rx.payload) {
            Ok(sr) => {
                self.event = Some(ImEvent::SubscribeDone {
                    subscription_id: sr.subscription_id,
                });
                self.txn = None;
                Ok(HandlerAction::None)
            }
            Err(_) => self.fail(ImStatus::InvalidAction),
        }
    }

    /// StatusResponse を受信した(エラー終端、§4.2)。
    fn on_status(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        let status = StatusResponse::decode(rx.payload)
            .map(|s| s.status)
            .unwrap_or(ImStatus::InvalidAction);
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
        let Some(mut r) = locate_ctx_array(payload, ctx)? else {
            return Ok(());
        };
        loop {
            let mut probe = r.clone();
            match probe.read_next()? {
                None => break,
                Some(e) if matches!(e.value, TlvValue::ContainerEnd) => break,
                Some(_) => {}
            }
            let raw = r.take_element_raw()?;
            let end = self.result_len + raw.len();
            if end > self.result.len() {
                self.truncated = true;
                break;
            }
            self.result[self.result_len..end].copy_from_slice(raw);
            self.result_len = end;
        }
        Ok(())
    }
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
        _now_ms: u64,
    ) -> Result<HandlerAction> {
        // 自分の進行中 exchange への応答のみを処理する(それ以外は silent drop)。
        match &self.txn {
            Some(t) if t.exchange == rx.exchange => {}
            _ => return Ok(HandlerAction::None),
        }
        let op = match ImOpCode::from_u8(rx.header.proto_opcode) {
            Ok(op) => op,
            // 未知 opcode は silent drop(panic しない)。
            Err(_) => return Ok(HandlerAction::None),
        };
        match op {
            ImOpCode::ReportData => self.on_report(rx, tx),
            ImOpCode::InvokeResponse => self.on_invoke_resp(rx),
            ImOpCode::WriteResponse => self.on_write_resp(rx),
            ImOpCode::SubscribeResponse => self.on_subscribe_resp(rx),
            ImOpCode::StatusResponse => self.on_status(rx),
            // client 宛に Request 系は来ない(silent drop)。
            _ => Ok(HandlerAction::None),
        }
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
