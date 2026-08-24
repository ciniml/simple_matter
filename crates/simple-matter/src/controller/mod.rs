//! コントローラ(commissioner)側の統合層。
//!
//! `docs/design/controller.md` ピース D(§7)。[`MatterStack`](crate::stack::MatterStack) と
//! **対**を成す sans-IO スタック [`ControllerStack`] を、同じ下位部品(`SessionManager` /
//! `ExchangeManager` / `BufferPool` / `SecureCodec`)を同じ形で所有する形で立てる。ハンドラ集合
//! だけが `ProtocolMux<`[`ScInitiator`]`, `[`ImClient`]`>` に差し替わる(exchange 層は無改造)。
//!
//! # 駆動契約(MatterStack と同一)
//!
//! - [`ControllerStack::handle_rx`] — 受信 datagram を処理し、応答があれば [`SendDirective`]。
//! - [`ControllerStack::poll`] — MRP 再送・standalone ACK を 1 件返す(購読レポートは無し)。
//! - [`ControllerStack::next_deadline`] — 次に poll すべき絶対時刻。
//!
//! MatterStack との唯一の構造差は、受信駆動の `ensure_unsecured_session` を**持たない**こと。
//! コントローラの unsecured セッションは [`start_pase`](ControllerStack::start_pase) /
//! [`start_case`](ControllerStack::start_case) が能動的に確保する(§7.2)。
//!
//! # 設計からの乖離(理由付き)
//!
//! - 設計 §7.1 のスケッチは `ScInitiator<'s, C>` と略記するが、実装済みの [`ScInitiator`] は
//!   `R: Rng`(乱数)と `F: FabricStore + NocResolver`(CASE creds)を型引数に持つ。よって
//!   [`ControllerStack`] も `R` / `F` を伝播させる(型パラメータ 2 つ増)。アプリは通常
//!   [`ControllerCreds`] を `F` に用いる。
//! - `start_case` は設計では `creds: &FabricTable` を引数に取るが、実装済み `ScInitiator` は
//!   creds を内部に保持するため、fabric インデックスのみを渡す。

pub mod ca;
pub mod commissioner;
pub mod nodes;

use core::num::NonZeroU8;

use crate::buf::BufferPool;
use crate::crypto::{Crypto, Rng};
use crate::error::{Error, Result};
use crate::exchange::{
    ExchangeId, ExchangeManager, HandlerAction, Outgoing, PollAction, ProtocolMux, SendTiming,
};
use crate::fabric::FabricEntry;
use crate::im::client::{AttrReports, EventReports, ImClient, ImEvent};
use crate::im::wire::{
    AttributePath, CommandPath, EventPath, ImOpCode, PROTO_ID_INTERACTION_MODEL,
};
use crate::sc::case::creds::{FabricStore, NocResolver, PeerIdentity};
use crate::sc::initiator::{ScEvent, ScInitiator};
use crate::sc::{OpCode, PROTO_ID_SECURE_CHANNEL};
use crate::stack::{SendDirective, MAX_PACKET_SIZE};
use crate::tlv::{TlvTag, TlvWriter};
use crate::transport::header::{PacketHeader, PayloadHeader};
use crate::transport::net::PeerAddr;
use crate::transport::session::{SessionId, SessionInit, SessionManager};
use crate::transport::util::WriteBuf;

use ca::Ca;

pub use ca::CONTROLLER_FABRIC_INDEX;

// ==========================================================================
// CASE 用の creds(コントローラの自 fabric ビュー)
// ==========================================================================

/// [`ScInitiator`] の型引数 `F` に渡す、コントローラ自身の fabric ビュー。
///
/// [`Ca`] 内の [`FabricTable<C, 1>`](crate::fabric::FabricTable) を共有借用して
/// [`FabricStore`](CASE の自 identity 素材)と [`NocResolver`](相手 NOC 検証)を提供する。
/// `Ca` を可変には触らないため、[`Commissioner`](commissioner::Commissioner) の
/// `&Ca` 共有借用と共存できる。
pub struct ControllerCreds<'a, C: Crypto> {
    ca: &'a Ca<C>,
    crypto: &'a C,
    now: u32,
}

impl<'a, C: Crypto> ControllerCreds<'a, C> {
    /// CA・crypto・検証時刻(Matter epoch 秒)からビューを作る。
    pub fn new(ca: &'a Ca<C>, crypto: &'a C, now: u32) -> Self {
        Self { ca, crypto, now }
    }
}

impl<C: Crypto> FabricStore for ControllerCreds<'_, C> {
    type Fabric<'x>
        = &'x FabricEntry<C>
    where
        Self: 'x;

    fn iter(&self) -> impl Iterator<Item = &FabricEntry<C>> {
        self.ca.creds().iter()
    }

    fn get(&self, idx: NonZeroU8) -> Option<&FabricEntry<C>> {
        self.ca.creds().get(idx)
    }
}

impl<C: Crypto> NocResolver for ControllerCreds<'_, C> {
    fn verify_peer_noc(
        &self,
        fabric_index: NonZeroU8,
        noc_tlv: &[u8],
        icac_tlv: Option<&[u8]>,
    ) -> Result<PeerIdentity> {
        self.ca
            .creds()
            .verify_peer_noc(self.crypto, fabric_index, noc_tlv, icac_tlv, self.now)
    }
}

// ==========================================================================
// ControllerStack
// ==========================================================================

/// コントローラのハンドラ mux(SC initiator + IM client)。
type Mux<'s, C, R, F, const RESULT: usize> =
    ProtocolMux<ScInitiator<'s, C, R, F>, ImClient<RESULT>>;

/// [`MatterStack`](crate::stack::MatterStack) と対の sans-IO コントローラスタック(§7)。
///
/// 型引数は `C`(暗号)/ `R`(乱数)/ `F`(CASE creds = 通常 [`ControllerCreds`])と、サイジングの
/// const generic。既定値は同時コミッショニング 1 台向け(§7.3)。
pub struct ControllerStack<
    's,
    C: Crypto,
    R: Rng,
    F,
    const SESSIONS: usize = 3,
    const EXCHANGES: usize = 2,
    const TX_BUFS: usize = 2,
    const RESULT: usize = 1280,
> {
    crypto: &'s C,
    sessions: SessionManager<SESSIONS>,
    mgr: ExchangeManager<Mux<'s, C, R, F, RESULT>, EXCHANGES>,
    tx_pool: BufferPool<TX_BUFS, MAX_PACKET_SIZE>,
    resp: [u8; MAX_PACKET_SIZE],
    /// 非セキュアメッセージの source Node ID に使うエフェメラル ID(非 0)。
    ephemeral_node_id: u64,
    /// 次に確保する unsecured(平文)セッションの送信カウンタ初期値。
    ///
    /// Matter Core Spec §4.5.1.1 の「Global Unencrypted Message Counter」は 1 ノードに 1 本で
    /// 単調増加する。本実装のカウンタはセッションごとだが、非セキュアメッセージの source Node
    /// ID は全 unsecured セッションで同一([`ephemeral_node_id`](Self::ephemeral_node_id))のため、
    /// 新しい unsecured セッションのカウンタが 1 に戻るとデバイス側のリプレイ窓に「重複」と判定
    /// される(BLE で PASE→AddNOC、その後別トランスポート = 運用 UDP で CASE を張る方向 B で
    /// 顕在化: CASE Sigma1 が M:1 で送られ、BLE PASE で観測済みの M:1 と衝突する)。そこで
    /// unsecured セッションの初期カウンタを跨いで単調に進め、セッション間で衝突しないよう十分な
    /// ストライドを空ける。初期値 1・ストライド 256(PASE の非セキュアメッセージは 3 通のみ、
    /// 再送は同一カウンタなので 256 の間隔で衝突しない)。
    next_unsecured_tx_ctr: u32,
}

/// unsecured セッションを新規確保するたびに [`ControllerStack::next_unsecured_tx_ctr`] を
/// 進めるストライド(§4.5.1.1 の単調性を跨セッションで担保する)。
const UNSECURED_CTR_STRIDE: u32 = 256;

impl<
        's,
        C: Crypto,
        R: Rng,
        F: FabricStore + NocResolver,
        const SESSIONS: usize,
        const EXCHANGES: usize,
        const TX_BUFS: usize,
        const RESULT: usize,
    > ControllerStack<'s, C, R, F, SESSIONS, EXCHANGES, TX_BUFS, RESULT>
{
    /// crypto 参照・構築済み [`ScInitiator`] / [`ImClient`] からスタックを組む。
    pub fn new(crypto: &'s C, mut sc: ScInitiator<'s, C, R, F>, im: ImClient<RESULT>) -> Self {
        // 非セキュアメッセージの source Node ID に使うエフェメラル ID(chip 系の
        // 受信検証が source/destination いずれかを必須とするため)。
        let ephemeral_node_id = sc.ephemeral_node_id();
        Self {
            crypto,
            sessions: SessionManager::new(),
            mgr: ExchangeManager::new(ProtocolMux::new(sc, im)),
            tx_pool: BufferPool::new(),
            resp: [0u8; MAX_PACKET_SIZE],
            ephemeral_node_id,
            // 既存の単一 unsecured セッション経路(PASE→CASE 同一ピア)では従来どおり M:1 から
            // 始まる。跨トランスポートで 2 本目を張ったときだけ 257,... と続く。
            next_unsecured_tx_ctr: 1,
        }
    }

    /// セッションテーブルへの共有参照。
    pub const fn sessions(&self) -> &SessionManager<SESSIONS> {
        &self.sessions
    }

    /// SC initiator の完了/失敗イベントを 1 件取り出す(§3.5)。
    pub fn sc_take_event(&mut self) -> Option<ScEvent> {
        self.mgr.handler_mut().sc.take_event()
    }

    /// ピアの CASE resumption 素材を取り出す(アプリ層の永続化用。
    /// [`ScInitiator::resumption_export`] への委譲)。
    pub fn resumption_export(
        &self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
    ) -> Option<(
        [u8; crate::sc::case::common::CASE_RESUMPTION_ID_LEN],
        [u8; crate::sc::case::common::SHARED_SECRET_LEN],
    )> {
        self.mgr
            .handler()
            .sc
            .resumption_export(fabric_idx, peer_node_id)
    }

    /// アプリ層が永続化していた CASE resumption 素材を取り込む
    /// ([`ScInitiator::resumption_import`] への委譲)。
    pub fn resumption_import(
        &mut self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        resumption_id: &[u8; crate::sc::case::common::CASE_RESUMPTION_ID_LEN],
        shared_secret: &[u8; crate::sc::case::common::SHARED_SECRET_LEN],
    ) {
        self.mgr.handler_mut().sc.resumption_import(
            fabric_idx,
            peer_node_id,
            resumption_id,
            shared_secret,
        );
    }

    /// IM client の完了/失敗イベントを 1 件取り出す(§4.4)。
    pub fn im_take_event(&mut self) -> Option<ImEvent> {
        self.mgr.handler_mut().im.take_event()
    }

    /// 直近 IM 応答の結果 payload(生 TLV)。
    pub fn im_result(&self) -> &[u8] {
        self.mgr.handler().im.result()
    }

    /// Rng から `dest` を満たす(コミッショナの attestation nonce 払い出し用)。
    pub fn fill_random(&mut self, dest: &mut [u8]) -> Result<()> {
        self.mgr.handler_mut().sc.fill_random(dest)
    }

    /// 直近 Read 結果を [`AttributeReportRef`](crate::im::wire::AttributeReportRef) 列で走査する。
    pub fn read_reports(&self) -> AttrReports<'_> {
        self.mgr.handler().im.read_reports()
    }

    /// 直近の購読レポート本文(AttributeReportIB 連結の生 TLV、§4.5.4)。
    pub fn im_sub_report(&self) -> &[u8] {
        self.mgr.handler().im.sub_report()
    }

    /// 直近の購読レポートを [`AttributeReportRef`](crate::im::wire::AttributeReportRef) 列で
    /// 走査する(§4.5.4)。
    pub fn sub_reports(&self) -> AttrReports<'_> {
        self.mgr.handler().im.sub_reports()
    }

    /// 直近の購読レポートのイベント本文(EventReportIB 連結の生 TLV、設計 §12)。
    pub fn im_sub_event_report(&self) -> &[u8] {
        self.mgr.handler().im.sub_event_report()
    }

    /// 直近の購読レポートを [`EventReportRef`](crate::im::wire::EventReportRef) 列で走査する
    /// (設計 §12)。
    pub fn sub_event_reports(&self) -> EventReports<'_> {
        self.mgr.handler().im.sub_event_reports()
    }

    /// 確立済み購読数(client 側テーブル)。
    pub fn subscription_count(&self) -> usize {
        self.mgr.handler().im.subscription_count()
    }

    /// 次に [`poll`](Self::poll) すべき最も早い絶対時刻(MRP 再送/ACK + 購読ロスト検出)。
    ///
    /// 購読確立後は keep-alive 途絶検出(§4.5.3)のため常に `Some` になる(呼び出し側の
    /// タイマがレポート途絶時にも [`poll`](Self::poll) を起こし、`drive_ticks` →
    /// [`ImClient::on_tick`] がロストを検出する)。
    pub fn next_deadline(&self, _now_ms: u64) -> Option<u64> {
        let a = self.mgr.next_deadline();
        let b = self.mgr.handler().im.next_sub_deadline();
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, None) => x,
            (None, y) => y,
        }
    }

    /// **MRP(再送 / standalone ACK)由来の期限だけ**を返す(購読 keep-alive を含まない)。
    ///
    /// [`next_deadline`](Self::next_deadline) は購読確立後に常に `Some` になるため、
    /// 「未達の ACK / 再送が無い(= 静穏化した)」ことだけを判定したい呼び出し側
    /// (C FFI シムの settle→drive 分離、`docs/design/c-ffi-shim.md` §11.1)が使う。
    pub fn transport_deadline(&self) -> Option<u64> {
        self.mgr.next_deadline()
    }

    /// 時間駆動の内部掃引(ハンドシェイク/トランザクションのタイムアウト掃除)。
    fn drive_ticks(&mut self, now_ms: u64) {
        // 期限切れハンドシェイクの exchange も閉じる(responder 側 stack.rs と同じ理由。
        // 閉じないと initiator exchange + 再送バッファがリークする)。
        while let Some(ex) = self
            .mgr
            .handler_mut()
            .sc
            .expire_timed_out(&mut self.sessions, now_ms)
        {
            if let Some(freed) = self.mgr.close(ex) {
                self.tx_pool.release(freed);
            }
        }
        self.mgr.handler_mut().im.on_tick(now_ms);
    }

    /// 受信 datagram を処理し、応答があれば [`SendDirective`] を返す(sans-IO、§7.2)。
    ///
    /// MatterStack と異なり `ensure_unsecured_session` を持たない(unsecured セッションは
    /// `start_*` が能動確保する)。未知セッション・不正入力は静かにドロップし `None`。
    pub fn handle_rx(
        &mut self,
        datagram: &mut [u8],
        peer: PeerAddr,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        self.drive_ticks(now_ms);

        let report = match self.mgr.recv(
            &mut self.sessions,
            self.crypto,
            peer,
            now_ms,
            datagram,
            &mut self.resp,
        ) {
            Ok(r) => r,
            Err(_) => return None,
        };

        if let Some(freed) = report.freed_tx {
            self.tx_pool.release(freed);
        }

        let dir = match report.action {
            HandlerAction::None => None,
            // 応答なしの終端。この後の共通スイープ(下)でも終端予約されるが、
            // ハンドラの明示宣言を尊重してここでも予約する。
            HandlerAction::CloseSilent => {
                if let Some(ex) = report.exchange {
                    self.mgr.mark_closing(ex);
                }
                None
            }
            HandlerAction::Respond {
                opcode,
                proto_id,
                reliable,
                len,
            } => {
                let ex = report.exchange?;
                self.stage_response(ex, proto_id, opcode, reliable, len, now_ms, tx_out)
            }
            HandlerAction::Close {
                opcode,
                proto_id,
                reliable,
                len,
            } => {
                let ex = report.exchange?;
                let d = self.stage_response(ex, proto_id, opcode, reliable, len, now_ms, tx_out);
                if let Some(ex) = report.exchange {
                    self.mgr.mark_closing(ex);
                }
                d
            }
        };

        // 完了/中断した(どちらのハンドラも使用していない)exchange を終端予約する。
        // MRP が静穏になり次第 poll が slot を回収する(プール枯渇防止)。
        if let Some(ex) = report.exchange {
            let sc_active = self.mgr.handler().sc.active_exchange();
            let im_active = self.mgr.handler().im.active_exchange();
            // チャンク継続中のデバイス発レポート exchange は閉じない(§4.5)。
            let im_report = self.mgr.handler().im.report_exchange();
            if Some(ex) != sc_active && Some(ex) != im_active && Some(ex) != im_report {
                self.mgr.mark_closing(ex);
            }
        }

        dir
    }

    /// 時間駆動の送出を 1 件返す(MRP 再送・standalone ACK)。`None` になるまで繰り返す。
    pub fn poll(&mut self, now_ms: u64, tx_out: &mut [u8]) -> Option<SendDirective> {
        self.drive_ticks(now_ms);

        loop {
            match self.mgr.poll(now_ms, now_ms as u8) {
                PollAction::Retransmit { buf, len, addr, .. } => {
                    let src = self.tx_pool.get(buf).ok()?;
                    if len > tx_out.len() || len > src.len() {
                        return None;
                    }
                    tx_out[..len].copy_from_slice(&src[..len]);
                    return Some(SendDirective { addr, len });
                }
                PollAction::SendAck { exchange, ack_ctr } => {
                    if let Some(d) = self.stage_standalone_ack(exchange, ack_ctr, now_ms, tx_out) {
                        return Some(d);
                    }
                }
                PollAction::Failed { freed_tx, .. } => {
                    self.tx_pool.release(freed_tx);
                }
                PollAction::Idle { .. } => break,
            }
        }
        None
    }

    // ----------------------------------------------------------------------
    // 開始系(open_initiator + send_reliable の配線、§7.2)
    // ----------------------------------------------------------------------

    /// 進行中のハンドシェイク(PASE/CASE)を外部都合で中断し、スロット・予約
    /// セッション・exchange を解放する。BLE リンク断で PASE を途中放棄するとき等に
    /// 統合層が呼ぶ。何も進行していなければ no-op。
    pub fn abort_handshake(&mut self) {
        if let Some(ex) = self
            .mgr
            .handler_mut()
            .sc
            .abort_handshake(&mut self.sessions)
        {
            if let Some(freed) = self.mgr.close(ex) {
                // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                self.tx_pool.release(freed);
            }
        }
    }

    /// peer への unsecured セッションを能動確保し PASE を開始する(§7.2)。
    pub fn start_pase(
        &mut self,
        peer: PeerAddr,
        passcode: u32,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        let unsec = self.unsecured_session(peer, now_ms)?;
        let ex = self.mgr.open_initiator(unsec)?;
        let reserved = match self.sessions.reserve(peer, now_ms) {
            Ok(r) => r,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        let ssid = self
            .sessions
            .get(reserved)
            .ok_or(Error::InvalidState)?
            .local_session_id();
        let len = match self.mgr.handler_mut().sc.start_pase(
            ex,
            reserved,
            ssid,
            passcode,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                self.sessions.remove(reserved);
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_SECURE_CHANNEL,
            OpCode::PbkdfParamRequest as u8,
            len,
            now_ms,
            tx_out,
        )
        .inspect_err(|_| {
            // 送信失敗時はハンドシェイク一式を巻き戻す(initiator 単一スロットの
            // 占有・予約セッション・exchange のリーク防止。放置すると次の
            // start_pase が NoSpace になり、HANDSHAKE_TIMEOUT 経過時に stale な
            // Failed イベントが積まれて後続の待ち手を誤らせる)。
            self.mgr.handler_mut().sc.cancel_handshake();
            self.sessions.remove(reserved);
            if let Some(freed) = self.mgr.close(ex) {
                // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                self.tx_pool.release(freed);
            }
        })
    }

    /// `fabric_idx` の fabric で peer と CASE を開始する(§7.2)。
    pub fn start_case(
        &mut self,
        peer: PeerAddr,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        let unsec = self.unsecured_session(peer, now_ms)?;
        let ex = self.mgr.open_initiator(unsec)?;
        let reserved = match self.sessions.reserve(peer, now_ms) {
            Ok(r) => r,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        let ssid = self
            .sessions
            .get(reserved)
            .ok_or(Error::InvalidState)?
            .local_session_id();
        let len = match self.mgr.handler_mut().sc.start_case(
            ex,
            reserved,
            ssid,
            fabric_idx,
            peer_node_id,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                self.sessions.remove(reserved);
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_SECURE_CHANNEL,
            OpCode::CaseSigma1 as u8,
            len,
            now_ms,
            tx_out,
        )
        .inspect_err(|_| {
            // start_pase と同じ巻き戻し(コメント参照)。
            self.mgr.handler_mut().sc.cancel_handshake();
            self.sessions.remove(reserved);
            if let Some(freed) = self.mgr.close(ex) {
                // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                self.tx_pool.release(freed);
            }
        })
    }

    /// 確立済み `session` 上で Invoke を開始する(§7.2)。
    pub fn start_invoke<W>(
        &mut self,
        session: SessionId,
        path: CommandPath,
        fields: W,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective>
    where
        W: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        let ex = self.mgr.open_initiator(session)?;
        let len =
            match self
                .mgr
                .handler_mut()
                .im
                .start_invoke(ex, path, fields, &mut self.resp, now_ms)
            {
                Ok(l) => l,
                Err(e) => {
                    if let Some(freed) = self.mgr.close(ex) {
                        // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                        // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                        self.tx_pool.release(freed);
                    }
                    return Err(e);
                }
            };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::InvokeRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上で timed invoke(TimedRequest → Invoke)を開始する
    /// (`docs/design/admin-commissioning.md` §3)。
    ///
    /// まず TimedRequest を送り、デバイスの `StatusResponse(SUCCESS)` 受信時
    /// ([`Self::handle_rx`] 内)に InvokeRequest(`timedRequest=true`)が同 exchange で
    /// 自動送出される。完了イベントは通常の Invoke と同じ。
    pub fn start_invoke_timed<W>(
        &mut self,
        session: SessionId,
        timeout_ms: u16,
        path: CommandPath,
        fields: W,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective>
    where
        W: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        let ex = self.mgr.open_initiator(session)?;
        let len = match self.mgr.handler_mut().im.start_invoke_timed(
            ex,
            timeout_ms,
            path,
            fields,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::TimedRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上で Read を開始する(§7.2)。
    pub fn start_read(
        &mut self,
        session: SessionId,
        paths: &[AttributePath],
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        let ex = self.mgr.open_initiator(session)?;
        let len = match self
            .mgr
            .handler_mut()
            .im
            .start_read(ex, paths, &mut self.resp, now_ms)
        {
            Ok(l) => l,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::ReadRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上で単一属性 Write を開始する(§7.2)。
    pub fn start_write<W>(
        &mut self,
        session: SessionId,
        path: &AttributePath,
        value: W,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective>
    where
        W: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        let ex = self.mgr.open_initiator(session)?;
        let len =
            match self
                .mgr
                .handler_mut()
                .im
                .start_write(ex, path, value, &mut self.resp, now_ms)
            {
                Ok(l) => l,
                Err(e) => {
                    if let Some(freed) = self.mgr.close(ex) {
                        // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                        // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                        self.tx_pool.release(freed);
                    }
                    return Err(e);
                }
            };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::WriteRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上で timed write(TimedRequest → Write)を開始する
    /// (`docs/design/admin-commissioning.md` §3)。
    ///
    /// まず TimedRequest を送り、デバイスの `StatusResponse(SUCCESS)` 受信時
    /// ([`Self::handle_rx`] 内)に WriteRequest(`timedRequest=true`)が同 exchange で
    /// 自動送出される。完了イベントは通常の Write と同じ。
    pub fn start_write_timed<W>(
        &mut self,
        session: SessionId,
        timeout_ms: u16,
        path: &AttributePath,
        value: W,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective>
    where
        W: FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    {
        let ex = self.mgr.open_initiator(session)?;
        let len = match self.mgr.handler_mut().im.start_write_timed(
            ex,
            timeout_ms,
            path,
            value,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::TimedRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上で Subscribe を開始する(§4.5)。
    ///
    /// プライミング完了で [`ImEvent::SubscribeDone`]、以降デバイス発レポートごとに
    /// [`ImEvent::SubscriptionReport`](本文は [`sub_reports`](Self::sub_reports))、
    /// keep-alive 途絶で [`ImEvent::SubscriptionLost`] が積まれる。
    pub fn start_subscribe(
        &mut self,
        session: SessionId,
        paths: &[AttributePath],
        min_interval_floor_s: u16,
        max_interval_ceiling_s: u16,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        let ex = self.mgr.open_initiator(session)?;
        let len = match self.mgr.handler_mut().im.start_subscribe(
            ex,
            paths,
            min_interval_floor_s,
            max_interval_ceiling_s,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::SubscribeRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    /// 確立済み `session` 上でイベント Subscribe を開始する(EventRequests + EventFilters、設計 §12)。
    ///
    /// `attr_paths` を空にすればイベントのみの購読。受信イベントは
    /// [`sub_event_reports`](Self::sub_event_reports) で走査する。
    #[allow(clippy::too_many_arguments)]
    pub fn start_subscribe_events(
        &mut self,
        session: SessionId,
        attr_paths: &[AttributePath],
        event_paths: &[EventPath],
        event_min: Option<u64>,
        min_interval_floor_s: u16,
        max_interval_ceiling_s: u16,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        let ex = self.mgr.open_initiator(session)?;
        let len = match self.mgr.handler_mut().im.start_subscribe_events(
            ex,
            attr_paths,
            event_paths,
            event_min,
            min_interval_floor_s,
            max_interval_ceiling_s,
            &mut self.resp,
            now_ms,
        ) {
            Ok(l) => l,
            Err(e) => {
                if let Some(freed) = self.mgr.close(ex) {
                    // close は再送バッファの返却を伴う(捨てると tx_pool が枯渇し、
                    // 数回の中断で start_pase/start_case が二度と通らなくなる。T5 実機)。
                    self.tx_pool.release(freed);
                }
                return Err(e);
            }
        };
        self.send_started(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::SubscribeRequest.to_u8(),
            len,
            now_ms,
            tx_out,
        )
    }

    // ----------------------------------------------------------------------
    // 内部ヘルパ
    // ----------------------------------------------------------------------

    /// peer への unsecured(平文)セッションを見つける、なければ確保する。
    fn unsecured_session(&mut self, peer: PeerAddr, now_ms: u64) -> Result<SessionId> {
        let existing = self
            .sessions
            .iter()
            .find(|s| {
                !s.is_encrypted()
                    && !s.is_reserved()
                    && s.peer_addr().canonical() == peer.canonical()
            })
            .map(|s| s.id());
        if let Some(id) = existing {
            return Ok(id);
        }
        // 跨セッションで単調な送信カウンタを与える(§4.5.1.1、フィールド doc 参照)。
        let tx_ctr_start = self.next_unsecured_tx_ctr;
        self.next_unsecured_tx_ctr = self
            .next_unsecured_tx_ctr
            .wrapping_add(UNSECURED_CTR_STRIDE);
        let mut init = SessionInit::plaintext(peer, 0, tx_ctr_start);
        // initiator 側は自身のエフェメラル Node ID を source として名乗る
        // (chip 系デバイスの非セキュアパケット検証を満たす)。
        init.local_node_id = self.ephemeral_node_id;
        self.sessions.insert(init, now_ms)
    }

    /// `self.resp` に書かれた開始 payload を信頼送信し `tx_out` に置く。
    fn send_started(
        &mut self,
        ex: ExchangeId,
        proto_id: u16,
        opcode: u8,
        len: usize,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Result<SendDirective> {
        if len > self.resp.len() {
            return Err(Error::NoSpace);
        }
        let msg = Outgoing {
            proto_id,
            opcode,
            payload: &self.resp[..len],
        };
        // BTP セッションでは信頼送信を格下げする(R フラグなし・再送スロット非登録)。
        // start_pase / start_case の第 1 メッセージも BLE 上では BTP に信頼性を委ねる
        // (`docs/design/ble-btp.md` §3.3)。
        let allows_mrp = self
            .sessions
            .get(ex.session())
            .map(|s| s.allows_mrp())
            .unwrap_or(true);
        if !allows_mrp {
            let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
            let (addr, start, end) = {
                let mut wb = WriteBuf::new(tx_out, headroom)?;
                let addr = self.mgr.send_unreliable(
                    &mut self.sessions,
                    self.crypto,
                    ex,
                    &msg,
                    &mut wb,
                    now_ms,
                )?;
                (addr, wb.start(), wb.end())
            };
            tx_out.copy_within(start..end, 0);
            return Ok(SendDirective {
                addr,
                len: end - start,
            });
        }
        let sent = self.mgr.send_reliable(
            &mut self.sessions,
            self.crypto,
            &mut self.tx_pool,
            ex,
            &msg,
            SendTiming {
                now_ms,
                jitter_rand: now_ms as u8,
            },
        )?;
        let src = self.tx_pool.get(sent.buf).map_err(|_| Error::NoSpace)?;
        if sent.len > tx_out.len() || sent.len > src.len() {
            return Err(Error::NoSpace);
        }
        tx_out[..sent.len].copy_from_slice(&src[..sent.len]);
        Ok(SendDirective {
            addr: sent.addr,
            len: sent.len,
        })
    }

    /// ハンドラが `self.resp` に書いた応答 payload をワイヤ化して `tx_out` に置く。
    #[allow(clippy::too_many_arguments)]
    fn stage_response(
        &mut self,
        ex: ExchangeId,
        proto_id: u16,
        opcode: u8,
        reliable: bool,
        len: usize,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        if len > self.resp.len() {
            return None;
        }
        // BTP セッションでは reliable → unreliable へ格下げ(R フラグなし・再送スロット
        // 非登録)。信頼性は下位の BTP が担う(`docs/design/ble-btp.md` §3.3)。
        let reliable = reliable
            && self
                .sessions
                .get(ex.session())
                .map(|s| s.allows_mrp())
                .unwrap_or(true);
        let msg = Outgoing {
            proto_id,
            opcode,
            payload: &self.resp[..len],
        };
        if reliable {
            let sent = self
                .mgr
                .send_reliable(
                    &mut self.sessions,
                    self.crypto,
                    &mut self.tx_pool,
                    ex,
                    &msg,
                    SendTiming {
                        now_ms,
                        jitter_rand: now_ms as u8,
                    },
                )
                .ok()?;
            let src = self.tx_pool.get(sent.buf).ok()?;
            if sent.len > tx_out.len() || sent.len > src.len() {
                return None;
            }
            tx_out[..sent.len].copy_from_slice(&src[..sent.len]);
            Some(SendDirective {
                addr: sent.addr,
                len: sent.len,
            })
        } else {
            let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
            let (addr, start, end) = {
                let mut wb = WriteBuf::new(tx_out, headroom).ok()?;
                let addr = self
                    .mgr
                    .send_unreliable(&mut self.sessions, self.crypto, ex, &msg, &mut wb, now_ms)
                    .ok()?;
                (addr, wb.start(), wb.end())
            };
            tx_out.copy_within(start..end, 0);
            Some(SendDirective {
                addr,
                len: end - start,
            })
        }
    }

    /// standalone ACK を組み立てて `tx_out` に置く。
    fn stage_standalone_ack(
        &mut self,
        ex: ExchangeId,
        ack_ctr: u32,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let (addr, start, end) = {
            let mut wb = WriteBuf::new(tx_out, headroom).ok()?;
            let addr = self
                .mgr
                .build_standalone_ack(
                    &mut self.sessions,
                    self.crypto,
                    ex,
                    ack_ctr,
                    &mut wb,
                    now_ms,
                )
                .ok()?;
            (addr, wb.start(), wb.end())
        };
        tx_out.copy_within(start..end, 0);
        Some(SendDirective {
            addr,
            len: end - start,
        })
    }
}

pub use commissioner::{
    AttestationError, AttestationPolicy, CommissionError, Commissioner, DriveOutcome, Phase,
    MAX_WIFI_CREDENTIALS_LEN, MAX_WIFI_SSID_LEN,
};

#[cfg(test)]
mod tests;
