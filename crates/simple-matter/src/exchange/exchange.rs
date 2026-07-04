//! 会話(Exchange)のプールと、受信一本道 / 送信 / タイマ poll を束ねる [`ExchangeManager`]。
//!
//! `docs/design/transport-exchange.md` §5 に基づく。Exchange は二ノード間の 1 会話
//! `(session, exchange_id, role)` を表し、MRP([`Mrp`](super::mrp::Mrp))を値として内包する。
//!
//! # session からの分離(§5.2)
//!
//! Exchange は session テーブルとは独立した flat な固定プールに格納し、session へは
//! [`SessionId`] で参照する(所有しない)。同時会話数の上限を全体で 1 つの const generic
//! (`EXCHANGES`)に集約できる。
//!
//! # ハンドル / 格納状態の分離(§5.3)
//!
//! - [`ExchangeState`] … プールに格納する状態(exch_id / session / role / MRP / MRP 設定)。
//! - [`ExchangeId`] … 不透明ハンドル(`{ session, exch_id }`)。rs-matter のような bit-packing は
//!   せず、素直な struct にする(counter マスク等への人工上限の波及を避ける)。
//!
//! 設計 §5.3 の `Exchange<'a>`(スタック参照を持ち `.await` をまたぐ async ハンドル)は
//! 採らない。確定した同期 sans-IO 方針に従い、操作はすべて [`ExchangeManager`] のメソッドに
//! `ExchangeId` を渡す形にする(乖離。async 統合は将来の統合層)。
//!
//! # 受信一本道(§10)
//!
//! [`ExchangeManager::recv`] が
//! `decode_rx(session) → exchange 照合/生成 → MRP(ACK 処理・重複再 ACK・standalone 武装)
//! → プロトコルディスパッチ` を 1 本にまとめる。送信は [`send_reliable`](ExchangeManager::send_reliable)
//! /[`send_unreliable`](ExchangeManager::send_unreliable)、再送・standalone ACK の駆動は
//! [`poll`](ExchangeManager::poll)(単一の poll 駆動点)。

use crate::buf::{BufferId, BufferPool};
use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, PayloadHeader, SecFlags};
use crate::transport::net::PeerAddr;
use crate::transport::secure::SecureCodec;
use crate::transport::session::fixed::FixedVec;
use crate::transport::session::{SessionId, SessionManager};
use crate::transport::util::WriteBuf;

use super::dispatch::{Dispatcher, HandlerAction, RxMessage};
use super::mrp::{Mrp, MrpConfig, RetransAction};

/// Secure Channel の Protocol ID。standalone ACK 等の生成に用いる。
pub const SECURE_CHANNEL_PROTOCOL_ID: u16 = 0x0000;

/// Secure Channel の MRP Standalone Acknowledgement メッセージ opcode。
pub const MRP_STANDALONE_ACK_OPCODE: u8 = 0x10;

/// exchange における自分側の役割。
///
/// responder のみ実装対象だが、型としては initiator も用意する(設計 §5.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 自分が会話を開始した側(送信メッセージに I フラグを立てる)。
    Initiator,
    /// ピアが会話を開始し、自分は応答する側。
    Responder,
}

/// 会話の不透明ハンドル。
///
/// `session` と `exch_id` の組で会話を一意に指す(§5.3。bit-packing しない)。役割は
/// 含めない(同一 `(session, exch_id)` に両役割の会話は同居しない前提)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeId {
    session: SessionId,
    exch_id: u16,
}

impl ExchangeId {
    /// セッションと Exchange ID からハンドルを構築する。
    pub const fn from_parts(session: SessionId, exch_id: u16) -> Self {
        Self { session, exch_id }
    }

    /// 所属セッションを返す。
    pub const fn session(self) -> SessionId {
        self.session
    }

    /// ワイヤ上の Exchange ID を返す。
    pub const fn exch_id(self) -> u16 {
        self.exch_id
    }
}

/// プールに格納する会話状態。
///
/// MRP([`Mrp`])を値として内包する。`config` はこの会話の再送タイミング(peer 広告 / 既定)。
#[derive(Debug)]
pub struct ExchangeState {
    exch_id: u16,
    session: SessionId,
    role: Role,
    mrp: Mrp,
    config: MrpConfig,
    /// トランザクション終端済み([`HandlerAction::Close`])の印。
    ///
    /// MRP が静穏(再送スロットなし・ACK 送信残なし)になり次第 [`ExchangeManager::poll`]
    /// が slot を回収する。即時 close しないのは、信頼送信した最終応答の再送責務が
    /// 残っている可能性があるため。
    closing: bool,
}

impl ExchangeState {
    /// 新しい会話状態を生成する。
    fn new(session: SessionId, exch_id: u16, role: Role) -> Self {
        Self {
            exch_id,
            session,
            role,
            mrp: Mrp::new(),
            config: MrpConfig::DEFAULT,
            closing: false,
        }
    }

    /// MRP に未了の責務(再送スロット・未送 ACK)が無いなら `true`。
    fn is_quiescent(&self) -> bool {
        self.mrp.retrans_buffer().is_none() && !self.mrp.is_ack_pending()
    }

    /// この会話のハンドルを返す。
    pub const fn id(&self) -> ExchangeId {
        ExchangeId::from_parts(self.session, self.exch_id)
    }

    /// 自分側の役割を返す。
    pub const fn role(&self) -> Role {
        self.role
    }

    /// MRP 状態への参照を返す。
    pub const fn mrp(&self) -> &Mrp {
        &self.mrp
    }
}

/// 送信するメッセージの内容(プロトコル・opcode・payload)。
///
/// 信頼(R フラグ)か否かは [`ExchangeManager::send_reliable`] /
/// [`send_unreliable`](ExchangeManager::send_unreliable) のどちらを呼ぶかで決まる。
pub struct Outgoing<'a> {
    /// Protocol ID(0x0000 = SC, 0x0001 = IM)。
    pub proto_id: u16,
    /// Protocol Opcode。
    pub opcode: u8,
    /// アプリケーション payload(平文。PayloadHeader は本層が前置する)。
    pub payload: &'a [u8],
}

/// 送信時の時間パラメータ。
#[derive(Debug, Clone, Copy)]
pub struct SendTiming {
    /// 単調増加する現在時刻(ミリ秒)。
    pub now_ms: u64,
    /// jitter 用の乱数 1 バイト(注入。テストは固定値で決定的)。
    pub jitter_rand: u8,
}

/// 信頼送信の結果。再送のため TX バッファを保持し続ける。
///
/// 呼び出し側は `pool.get(buf)[..len]` を `addr` へ送信する。バッファは ACK 受信
/// または諦め時に解放される(それまで本層が [`BufferId`] を保持)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReliableSent {
    /// 暗号化済みワイヤパケットを保持する TX バッファ。
    pub buf: BufferId,
    /// 送信長(バイト)。
    pub len: usize,
    /// 送信先。
    pub addr: PeerAddr,
}

/// [`ExchangeManager::recv`] の結果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecvReport {
    /// 照合/生成した会話(重複ドロップや未知会話への応答では `None`)。
    pub exchange: Option<ExchangeId>,
    /// piggyback ACK により解放された TX 再送バッファ(呼び出し側がプールへ返す)。
    pub freed_tx: Option<BufferId>,
    /// リプレイ窓で重複と判定され、ディスパッチしなかったなら `true`。
    pub duplicate: bool,
    /// ハンドラへディスパッチしたなら `true`。
    pub dispatched: bool,
    /// ハンドラが返したアクション(未ディスパッチなら [`HandlerAction::None`])。
    pub action: HandlerAction,
}

/// [`ExchangeManager::poll`] が返す、単一の期限到達アクション。
///
/// 呼び出し側は [`PollAction::Idle`] が返るまで繰り返し呼ぶ(1 回の呼び出しで最大 1 件を
/// 処理する)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollAction {
    /// 期限到達なし。次に poll すべき絶対時刻(あれば)。
    Idle {
        /// 次に処理すべき最も早い deadline(ミリ秒)。
        next_deadline: Option<u64>,
    },
    /// `buf` の先頭 `len` バイトを `addr` へ再送する。
    Retransmit {
        /// 対象の会話。
        exchange: ExchangeId,
        /// 再送パケットを保持する TX バッファ。
        buf: BufferId,
        /// 送信長(バイト)。
        len: usize,
        /// 送信先。
        addr: PeerAddr,
    },
    /// standalone ACK を送るべき会話。[`ExchangeManager::build_standalone_ack`] で生成する。
    SendAck {
        /// 対象の会話。
        exchange: ExchangeId,
        /// ACK 対象の受信メッセージカウンタ。
        ack_ctr: u32,
    },
    /// 再送上限到達で失敗した会話(プールから除去済み)。
    Failed {
        /// 失敗した会話のハンドル。
        exchange: ExchangeId,
        /// 解放すべき TX 再送バッファ。
        freed_tx: BufferId,
    },
}

/// 会話プール + プロトコルディスパッチ配線。
///
/// `H` はディスパッチャ(通常は [`ProtocolMux`](super::dispatch::ProtocolMux))で、
/// 単一の型パラメータに閉じる(設計 §9)。`EXCHANGES` は同時会話数の上限(§8)。
#[derive(Debug)]
pub struct ExchangeManager<H, const EXCHANGES: usize> {
    exchanges: FixedVec<ExchangeState, EXCHANGES>,
    next_exch_id: u16,
    handler: H,
}

impl<H, const EXCHANGES: usize> ExchangeManager<H, EXCHANGES> {
    /// ディスパッチャを与えて空の [`ExchangeManager`] を生成する。
    pub fn new(handler: H) -> Self {
        Self {
            exchanges: FixedVec::new(),
            next_exch_id: 1,
            handler,
        }
    }

    /// ディスパッチャ(ハンドラ mux)への参照を返す。
    pub const fn handler(&self) -> &H {
        &self.handler
    }

    /// ディスパッチャ(ハンドラ mux)への可変参照を返す。
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// 会話プールの最大容量を返す。
    pub const fn capacity(&self) -> usize {
        EXCHANGES
    }

    /// 現在の会話数を返す。
    pub fn len(&self) -> usize {
        self.exchanges.len()
    }

    /// 会話が 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.exchanges.is_empty()
    }

    /// プールが満杯なら `true`。
    pub fn is_full(&self) -> bool {
        self.exchanges.is_full()
    }

    /// 指定 `session` に紐づく生存会話数を返す(session 退避判定に用いる、§4.3/§5.2)。
    pub fn count_for_session(&self, session: SessionId) -> usize {
        self.exchanges
            .iter()
            .filter(|e| e.session == session)
            .count()
    }

    /// 指定 `session` に生存会話があれば `true`。
    pub fn has_live_exchanges(&self, session: SessionId) -> bool {
        self.exchanges.iter().any(|e| e.session == session)
    }

    /// 会話が存在すれば `true`。
    pub fn contains(&self, id: ExchangeId) -> bool {
        self.index_of_id(id).is_some()
    }

    /// 会話の役割を返す(存在しなければ `None`)。
    pub fn role(&self, id: ExchangeId) -> Option<Role> {
        self.index_of_id(id).map(|i| self.exchanges[i].role)
    }

    /// 未 ACK の再送が保留中なら `true`。
    pub fn is_retrans_pending(&self, id: ExchangeId) -> bool {
        self.index_of_id(id)
            .map(|i| self.exchanges[i].mrp.is_retrans_pending())
            .unwrap_or(false)
    }

    /// 会話の MRP 設定(再送タイミング)を差し替える。存在すれば `true`。
    pub fn set_config(&mut self, id: ExchangeId, config: MrpConfig) -> bool {
        match self.index_of_id(id) {
            Some(i) => {
                self.exchanges[i].config = config;
                true
            }
            None => false,
        }
    }

    /// すべての会話にまたがる、次に poll すべき最も早い deadline を返す。
    pub fn next_deadline(&self) -> Option<u64> {
        let mut next: Option<u64> = None;
        for e in self.exchanges.iter() {
            if let Some(d) = e.mrp.next_deadline() {
                next = Some(match next {
                    Some(n) => n.min(d),
                    None => d,
                });
            }
        }
        next
    }

    /// initiator 会話を新規に開く(Exchange ID を採番する)。
    ///
    /// 本デバイスは responder 専用だが、CASE 等で自発送信する場合の型は用意する。
    /// プール満杯は [`Error::NoSpace`]。
    pub fn open_initiator(&mut self, session: SessionId) -> Result<ExchangeId> {
        if self.exchanges.is_full() {
            return Err(Error::NoSpace);
        }
        let exch_id = self.alloc_exch_id(session);
        self.exchanges
            .push(ExchangeState::new(session, exch_id, Role::Initiator))
            .map_err(|_| Error::NoSpace)?;
        Ok(ExchangeId::from_parts(session, exch_id))
    }

    /// 会話を閉じてプールから除去する。
    ///
    /// 保持していた再送 TX バッファ(あれば)を返すので、呼び出し側がプールへ解放すること。
    /// 存在しない会話では `None`。
    pub fn close(&mut self, id: ExchangeId) -> Option<BufferId> {
        let i = self.index_of_id(id)?;
        let freed = self.exchanges[i].mrp.retrans_buffer();
        self.exchanges.swap_remove(i);
        freed
    }

    /// 会話を終端予約する([`HandlerAction::Close`] の宣言を受けた統合層が呼ぶ)。
    ///
    /// 即時 close はせず、MRP の再送・ACK 責務が済み次第 [`poll`](Self::poll) が
    /// slot を回収する。未知 ID は無視する。
    pub fn mark_closing(&mut self, id: ExchangeId) {
        if let Some(i) = self.index_of_id(id) {
            self.exchanges[i].closing = true;
        }
    }

    /// `(session, exch_id)` から格納 index を引く。
    fn index_of_id(&self, id: ExchangeId) -> Option<usize> {
        self.exchanges
            .iter()
            .position(|e| e.session == id.session && e.exch_id == id.exch_id)
    }

    /// 受信メッセージに一致する会話 index を引く(§5.5)。
    ///
    /// `session` と `exch_id` が一致し、かつ役割が受信の I フラグと整合すること
    /// (`rx_is_initiator == (role == Responder)`)。
    fn match_index(
        &self,
        session: SessionId,
        exch_id: u16,
        rx_is_initiator: bool,
    ) -> Option<usize> {
        self.exchanges.iter().position(|e| {
            e.session == session
                && e.exch_id == exch_id
                && rx_is_initiator == (e.role == Role::Responder)
        })
    }

    /// responder 会話を新規生成する(peer の exch_id を再利用、§5.5)。
    fn create_responder(&mut self, session: SessionId, exch_id: u16) -> Result<usize> {
        if self.exchanges.is_full() {
            return Err(Error::NoSpace);
        }
        self.exchanges
            .push(ExchangeState::new(session, exch_id, Role::Responder))
            .map_err(|_| Error::NoSpace)?;
        Ok(self.exchanges.len() - 1)
    }

    /// 使用中でない Exchange ID を採番する(0 と衝突を回避)。
    fn alloc_exch_id(&mut self, session: SessionId) -> u16 {
        loop {
            let id = self.next_exch_id;
            self.next_exch_id = self.next_exch_id.wrapping_add(1);
            if self.next_exch_id == 0 {
                self.next_exch_id = 1;
            }
            if !self
                .exchanges
                .iter()
                .any(|e| e.session == session && e.exch_id == id)
            {
                return id;
            }
        }
    }

    /// 再送・standalone ACK の期限到達を 1 件処理して返す(単一の poll 駆動点)。
    ///
    /// [`PollAction::Idle`] が返るまで繰り返し呼ぶことで、その時刻に処理すべき送出を
    /// すべて排出できる。`jitter_rand` は再送 deadline 再計算用の注入乱数。
    ///
    /// - 再送 deadline 到達 → [`PollAction::Retransmit`](状態は次回へ進む)。
    /// - 再送上限到達 → 会話を除去し [`PollAction::Failed`]。
    /// - standalone ACK 期限到達 → ACK 済みに印を付け [`PollAction::SendAck`]。
    pub fn poll(&mut self, now_ms: u64, jitter_rand: u8) -> PollAction {
        // 終端済み(closing)かつ MRP 静穏の会話を回収する(プール枯渇防止)。
        let mut i = 0;
        while i < self.exchanges.len() {
            if self.exchanges[i].closing && self.exchanges[i].is_quiescent() {
                self.exchanges.swap_remove(i);
            } else {
                i += 1;
            }
        }
        for i in 0..self.exchanges.len() {
            match self.exchanges[i].mrp.take_due_retrans(now_ms, jitter_rand) {
                RetransAction::Retransmit { buf, len, addr } => {
                    return PollAction::Retransmit {
                        exchange: self.exchanges[i].id(),
                        buf,
                        len,
                        addr,
                    };
                }
                RetransAction::GiveUp { buf } => {
                    let exchange = self.exchanges[i].id();
                    self.exchanges.swap_remove(i);
                    return PollAction::Failed {
                        exchange,
                        freed_tx: buf,
                    };
                }
                RetransAction::None => {}
            }
            if let Some(ack_ctr) = self.exchanges[i].mrp.peek_expired_ack(now_ms) {
                self.exchanges[i].mrp.mark_ack_sent();
                return PollAction::SendAck {
                    exchange: self.exchanges[i].id(),
                    ack_ctr,
                };
            }
        }
        PollAction::Idle {
            next_deadline: self.next_deadline(),
        }
    }

    /// 受信一本道(§10): decode → 会話照合/生成 → MRP → ディスパッチ。
    ///
    /// `datagram` は 1 datagram 全体(先頭が [`PacketHeader`])。復号は in-place で行い、
    /// 平文 payload の view をハンドラへ渡す。
    ///
    /// - リプレイ窓で重複と判定された信頼メッセージは、ディスパッチせず ACK を再武装する
    ///   (こちらの ACK ロストへの対処、§6)。[`RecvReport::duplicate`] が `true`。
    /// - piggyback ACK は再送スロットを解除し、その TX バッファを [`RecvReport::freed_tx`] で返す。
    /// - peer が initiator の未知会話は responder 会話を新規生成、それ以外の未知会話への
    ///   応答は無視(ディスパッチしない)。
    ///
    /// セッション不明は [`Error::NotFound`]、復号失敗は [`Error::Crypto`]、会話プール枯渇は
    /// [`Error::NoSpace`]。不正入力・枯渇でも `panic` しない。
    ///
    /// `tx` はハンドラが応答 payload を書くための出力バッファ。ハンドラが
    /// [`HandlerAction::Respond`] / [`HandlerAction::Close`] を返した場合、
    /// [`RecvReport::action`] にその宣言(opcode / len 等)が載る。呼び出し側は
    /// `tx[..len]` を [`send_reliable`](Self::send_reliable) /
    /// [`send_unreliable`](Self::send_unreliable) で送出する(送受信分離)。
    pub fn recv<C: Crypto, const SESSIONS: usize>(
        &mut self,
        sessions: &mut SessionManager<SESSIONS>,
        crypto: &C,
        peer: PeerAddr,
        now_ms: u64,
        datagram: &mut [u8],
        tx: &mut [u8],
    ) -> Result<RecvReport>
    where
        H: Dispatcher,
    {
        use crate::transport::util::ParseBuf;

        let mut pb = ParseBuf::new(datagram);
        let decoded = sessions.decode_rx_detailed(crypto, peer, now_ms, &mut pb)?;
        let phdr = decoded.header;
        let session = decoded.session;

        // リプレイ窓で弾かれた重複。信頼メッセージなら再 ACK を武装する。
        if decoded.duplicate {
            if phdr.is_reliable() {
                if let Some(i) = self.match_index(session, phdr.exch_id, phdr.is_initiator()) {
                    self.exchanges[i].mrp.rearm_ack(decoded.msg_ctr, now_ms);
                }
            }
            return Ok(RecvReport {
                duplicate: true,
                ..Default::default()
            });
        }

        // 会話照合 or 新規 responder 生成(§5.5)。
        let idx = match self.match_index(session, phdr.exch_id, phdr.is_initiator()) {
            Some(i) => i,
            None => {
                if phdr.is_initiator() {
                    self.create_responder(session, phdr.exch_id)?
                } else {
                    // 未知会話への応答 = 無視(role 不一致 / 消滅済み会話)。
                    return Ok(RecvReport::default());
                }
            }
        };

        let handle = self.exchanges[idx].id();
        let role = self.exchanges[idx].role;

        // MRP: piggyback ACK 処理 + standalone ACK 武装。
        let outcome = self.exchanges[idx].mrp.post_recv(
            phdr.ack(),
            phdr.is_reliable(),
            decoded.msg_ctr,
            now_ms,
        );

        let mut report = RecvReport {
            exchange: Some(handle),
            freed_tx: outcome.freed,
            duplicate: false,
            dispatched: false,
            action: HandlerAction::None,
        };

        // MRP レベルの重複(古いカウンタへの ACK など)はディスパッチしない。
        if outcome.duplicate {
            return Ok(report);
        }

        // プロトコルディスパッチ。未対応 Protocol ID は静かにドロップ(dispatched=false)。
        let rx = RxMessage {
            header: &phdr,
            payload: pb.as_slice(),
            exchange: handle,
            role,
        };
        if let Ok(action) = self
            .handler
            .dispatch(phdr.proto_id, &rx, tx, sessions, now_ms)
        {
            report.action = action;
            report.dispatched = true;
        }
        Ok(report)
    }

    /// 非信頼送信(R フラグなし)。`out` に暗号化済みパケットを組み立てる。
    ///
    /// 呼び出し側は headroom(`PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN`)を空けた
    /// [`WriteBuf`] を用意する。保留 ACK があれば piggyback する。送信先を返す。
    pub fn send_unreliable<C: Crypto, const SESSIONS: usize>(
        &mut self,
        sessions: &mut SessionManager<SESSIONS>,
        crypto: &C,
        exchange: ExchangeId,
        msg: &Outgoing<'_>,
        out: &mut WriteBuf<'_>,
        now_ms: u64,
    ) -> Result<PeerAddr> {
        let idx = self.index_of_id(exchange).ok_or(Error::NotFound)?;
        let role = self.exchanges[idx].role;
        let ack = self.exchanges[idx].mrp.take_ack_for_piggyback();
        let (_ctr, addr) = build_packet(
            sessions,
            crypto,
            exchange.session,
            role,
            exchange.exch_id,
            msg.proto_id,
            msg.opcode,
            false,
            ack,
            msg.payload,
            out,
            now_ms,
        )?;
        Ok(addr)
    }

    /// 信頼送信(R フラグ)。TX プールから確保したバッファへ組み立て、再送スロットに登録する。
    ///
    /// 暗号化済みパケットはバッファ先頭([0, len))へ詰めて保持し、ACK 受信または諦めまで
    /// 解放しない。既に再送保留中の会話への二重送信は [`Error::InvalidState`]、プール枯渇は
    /// [`Error::NoSpace`]。
    pub fn send_reliable<C: Crypto, const SESSIONS: usize, const BN: usize, const BS: usize>(
        &mut self,
        sessions: &mut SessionManager<SESSIONS>,
        crypto: &C,
        pool: &mut BufferPool<BN, BS>,
        exchange: ExchangeId,
        msg: &Outgoing<'_>,
        timing: SendTiming,
    ) -> Result<ReliableSent> {
        let idx = self.index_of_id(exchange).ok_or(Error::NotFound)?;
        if self.exchanges[idx].mrp.is_retrans_pending() {
            return Err(Error::InvalidState);
        }
        let role = self.exchanges[idx].role;
        let ack = self.exchanges[idx].mrp.take_ack_for_piggyback();
        let config = self.exchanges[idx].config;

        let buf_id = pool.acquire().ok_or(Error::NoSpace)?;
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let session = exchange.session;
        let exch_id = exchange.exch_id;

        // クロージャで組み立て、`?` の早期 return がバッファをリークしないよう捕捉する。
        let built: Result<(u32, PeerAddr, usize, usize)> = (|| {
            let slot = pool.get_mut(buf_id)?;
            let mut w = WriteBuf::new(&mut slot[..], headroom)?;
            let (ctr, addr) = build_packet(
                sessions,
                crypto,
                session,
                role,
                exch_id,
                msg.proto_id,
                msg.opcode,
                true,
                ack,
                msg.payload,
                &mut w,
                timing.now_ms,
            )?;
            Ok((ctr, addr, w.start(), w.end()))
        })();

        let (ctr, addr, start, end) = match built {
            Ok(v) => v,
            Err(e) => {
                pool.release(buf_id);
                return Err(e);
            }
        };

        let len = end - start;
        // 組み上がったパケットをスロット先頭へ詰め直す(再送は get(buf)[..len] で参照する)。
        if let Ok(slot) = pool.get_mut(buf_id) {
            slot.copy_within(start..end, 0);
        }

        if let Err(e) = self.exchanges[idx].mrp.on_reliable_sent(
            ctr,
            buf_id,
            len,
            addr,
            &config,
            timing.jitter_rand,
            timing.now_ms,
        ) {
            pool.release(buf_id);
            return Err(e);
        }

        Ok(ReliableSent {
            buf: buf_id,
            len,
            addr,
        })
    }

    /// standalone ACK(Secure Channel opcode 0x10)を `out` に組み立てる。
    ///
    /// [`poll`](Self::poll) が [`PollAction::SendAck`] を返したときに用いる。payload なし・
    /// R フラグなし・A フラグに `ack_ctr` を載せる。送信先を返す。
    pub fn build_standalone_ack<C: Crypto, const SESSIONS: usize>(
        &mut self,
        sessions: &mut SessionManager<SESSIONS>,
        crypto: &C,
        exchange: ExchangeId,
        ack_ctr: u32,
        out: &mut WriteBuf<'_>,
        now_ms: u64,
    ) -> Result<PeerAddr> {
        let idx = self.index_of_id(exchange).ok_or(Error::NotFound)?;
        let role = self.exchanges[idx].role;
        let (_ctr, addr) = build_packet(
            sessions,
            crypto,
            exchange.session,
            role,
            exchange.exch_id,
            SECURE_CHANNEL_PROTOCOL_ID,
            MRP_STANDALONE_ACK_OPCODE,
            false,
            Some(ack_ctr),
            &[],
            out,
            now_ms,
        )?;
        Ok(addr)
    }
}

/// 1 メッセージのワイヤパケットを `out` に組み立てる(暗号境界の送信側)。
///
/// セッションから宛先 Session ID・鍵・自ノード ID・送信カウンタを引き、PayloadHeader を
/// 前置して暗号化、PacketHeader を前置する。用いた送信カウンタと宛先を返す。
#[allow(clippy::too_many_arguments)] // ヘッダ構築に必要な素の値群。束ねると却って不透明になる。
fn build_packet<C: Crypto, const SESSIONS: usize>(
    sessions: &mut SessionManager<SESSIONS>,
    crypto: &C,
    session_id: SessionId,
    role: Role,
    exch_id: u16,
    proto_id: u16,
    opcode: u8,
    reliable: bool,
    ack_ctr: Option<u32>,
    payload: &[u8],
    out: &mut WriteBuf<'_>,
    now_ms: u64,
) -> Result<(u32, PeerAddr)> {
    let session = sessions
        .get_mut(session_id, now_ms)
        .ok_or(Error::NotFound)?;
    let ctr = session.next_tx_ctr();

    let mut exch_flags = ExchFlags::from_bits(0);
    if role == Role::Initiator {
        exch_flags.insert(ExchFlags::INITIATOR);
    }
    if reliable {
        exch_flags.insert(ExchFlags::RELIABLE);
    }

    let phdr = PayloadHeader {
        exch_flags,
        proto_opcode: opcode,
        exch_id,
        proto_id,
        vendor_id: None,
        ack_ctr,
    };
    // 非セキュアセッションでは、connectedhomeip 側の受信検証(source/destination
    // Node ID のいずれか必須)を満たすため、(a) responder は既知のピア Node ID
    // (イニシエータのエフェメラル ID)を宛先として echo し、(b) initiator
    // (コントローラ側: local_node_id にエフェメラル ID を設定済み)は自身の
    // Node ID を source として載せる(仕様 §4.6.2、chip-tool と同じ挙動)。
    let (src_node_id, dst) = if !session.is_encrypted() {
        let dst = match session.peer_node_id() {
            Some(id) => DstNodeId::Unicast(id),
            None => DstNodeId::None,
        };
        let src = match session.local_node_id() {
            0 => None,
            id => Some(id),
        };
        (src, dst)
    } else {
        (None, DstNodeId::None)
    };
    let pkt = PacketHeader {
        session_id: session.peer_session_id(),
        sec_flags: SecFlags::from_bits(0),
        ctr,
        src_node_id,
        dst,
    };

    let key = session.enc_key().copied();
    let local_node_id = session.local_node_id();
    let addr = session.peer_addr();

    out.append(payload)?;
    SecureCodec::encrypt(crypto, key.as_ref(), &pkt, &phdr, local_node_id, out)?;
    Ok((ctr, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::BufferPool;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::Rng;
    use crate::error::Result as CrateResult;
    use crate::transport::header::{ExchFlags, PacketHeader, PayloadHeader, SecFlags};
    use crate::transport::session::{SessionInit, SessionManager, SessionMode};
    use crate::transport::util::WriteBuf;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use core::num::NonZeroU8;

    struct ZeroRng;
    impl Rng for ZeroRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> CrateResult<()> {
            dest.fill(0);
            Ok(())
        }
    }
    fn crypto() -> RustCrypto<ZeroRng> {
        RustCrypto::new(ZeroRng)
    }

    fn addr(port: u16) -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        ))
    }

    fn sid(raw: u32) -> SessionId {
        SessionId::from_raw(raw)
    }

    /// 受信 proto_id を記録するモックディスパッチャ。
    #[derive(Default)]
    struct RecordingDispatcher {
        last_proto: Option<u16>,
        calls: u32,
    }
    impl Dispatcher for RecordingDispatcher {
        fn dispatch<const S: usize>(
            &mut self,
            proto_id: u16,
            _rx: &RxMessage<'_>,
            _tx: &mut [u8],
            _sessions: &mut SessionManager<S>,
            _now_ms: u64,
        ) -> Result<HandlerAction> {
            self.last_proto = Some(proto_id);
            self.calls += 1;
            Ok(HandlerAction::None)
        }
    }

    fn null_mgr<const N: usize>() -> ExchangeManager<RecordingDispatcher, N> {
        ExchangeManager::new(RecordingDispatcher::default())
    }

    /// テスト用受信メッセージの記述。
    struct Incoming {
        /// `Some((key, peer_node))` なら暗号化。`None` は平文。
        key: Option<([u8; 16], u64)>,
        wire_session_id: u16,
        ctr: u32,
        exch_id: u16,
        proto_id: u16,
        reliable: bool,
        ack_ctr: Option<u32>,
        initiator: bool,
    }

    /// 受信ワイヤメッセージを `out` に組み立て、長さを返す(1 datagram)。
    fn build_incoming<C: Crypto>(crypto: &C, m: &Incoming, out: &mut [u8]) -> usize {
        let mut flags = 0u8;
        if m.initiator {
            flags |= ExchFlags::INITIATOR;
        }
        if m.reliable {
            flags |= ExchFlags::RELIABLE;
        }
        let pkt = PacketHeader {
            session_id: m.wire_session_id,
            sec_flags: SecFlags::from_bits(0),
            ctr: m.ctr,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(flags),
            proto_opcode: 0x08,
            exch_id: m.exch_id,
            proto_id: m.proto_id,
            vendor_id: None,
            ack_ctr: m.ack_ctr,
        };
        let app: &[u8] = &[0x15, 0x18];
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 256];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(app).unwrap();
        let (k, node) = match m.key {
            Some((k, node)) => (Some(k), node),
            None => (None, 0),
        };
        SecureCodec::encrypt(crypto, k.as_ref(), &pkt, &phdr, node, &mut w).unwrap();
        let n = w.len();
        out[..n].copy_from_slice(w.as_slice());
        n
    }

    fn plaintext_session(mgr: &mut SessionManager<2>, peer: PeerAddr) -> SessionId {
        mgr.insert(SessionInit::plaintext(peer, 0, 0), 0).unwrap()
    }

    fn encrypted_session(mgr: &mut SessionManager<2>, peer: PeerAddr, key: [u8; 16]) -> SessionId {
        let init = SessionInit {
            peer_addr: peer,
            local_node_id: 0x1111_2222_3333_4444,
            peer_node_id: Some(0x5555_6666_7777_8888),
            peer_session_id: 0x00AA,
            tx_ctr_start: 100,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: NonZeroU8::new(1).unwrap(),
            },
            enc_key: key,
            dec_key: key,
            att_challenge: [0x33u8; 16],
        };
        mgr.insert(init, 0).unwrap()
    }

    // --- 会話照合 ---

    #[test]
    fn open_initiator_allocates_ids() {
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let s = sid(1);
        let a = mgr.open_initiator(s).unwrap();
        let b = mgr.open_initiator(s).unwrap();
        assert_ne!(a.exch_id(), b.exch_id());
        assert_eq!(mgr.len(), 2);
        assert_eq!(mgr.role(a), Some(Role::Initiator));
    }

    #[test]
    fn open_initiator_pool_exhaustion_is_no_space() {
        let mut mgr: ExchangeManager<RecordingDispatcher, 1> = null_mgr();
        let s = sid(1);
        mgr.open_initiator(s).unwrap();
        assert_eq!(mgr.open_initiator(s), Err(Error::NoSpace));
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn match_finds_responder_and_rejects_role_mismatch() {
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let s = sid(7);
        assert_eq!(mgr.create_responder(s, 5).unwrap(), 0);
        // peer が initiator(is_initiator=true)→ responder にマッチ。
        assert_eq!(mgr.match_index(s, 5, true), Some(0));
        // role 不一致: is_initiator=false はマッチしない。
        assert_eq!(mgr.match_index(s, 5, false), None);
        assert_eq!(mgr.match_index(sid(8), 5, true), None);
        assert_eq!(mgr.match_index(s, 6, true), None);
    }

    #[test]
    fn count_and_has_live_exchanges() {
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let s1 = sid(1);
        let s2 = sid(2);
        mgr.create_responder(s1, 1).unwrap();
        mgr.create_responder(s1, 2).unwrap();
        mgr.create_responder(s2, 1).unwrap();
        assert_eq!(mgr.count_for_session(s1), 2);
        assert_eq!(mgr.count_for_session(s2), 1);
        assert!(mgr.has_live_exchanges(s1));
        assert!(!mgr.has_live_exchanges(sid(9)));
    }

    #[test]
    fn responder_pool_exhaustion_is_no_space() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let mut mgr: ExchangeManager<RecordingDispatcher, 1> = null_mgr();

        let mut wire = [0u8; 256];
        let base = Incoming {
            key: None,
            wire_session_id: wire_sid,
            ctr: 1,
            exch_id: 0x10,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: None,
            initiator: true,
        };
        let n = build_incoming(&crypto(), &base, &mut wire);
        mgr.recv(
            &mut sessions,
            &crypto(),
            peer,
            10,
            &mut wire[..n],
            &mut [0u8; 512],
        )
        .unwrap();
        // 別 exch_id の新規 responder はプール満杯で NoSpace。
        let m2 = Incoming {
            ctr: 2,
            exch_id: 0x11,
            ..base
        };
        let n2 = build_incoming(&crypto(), &m2, &mut wire);
        assert_eq!(
            mgr.recv(
                &mut sessions,
                &crypto(),
                peer,
                11,
                &mut wire[..n2],
                &mut [0u8; 512]
            ),
            Err(Error::NoSpace)
        );
    }

    // --- 受信一本道の統合 ---

    #[test]
    fn recv_plaintext_creates_responder_and_dispatches() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        let mut wire = [0u8; 256];
        let m = Incoming {
            key: None,
            wire_session_id: wire_sid,
            ctr: 1,
            exch_id: 0x42,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: None,
            initiator: true,
        };
        let n = build_incoming(&crypto(), &m, &mut wire);
        let report = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                10,
                &mut wire[..n],
                &mut [0u8; 512],
            )
            .unwrap();
        assert!(report.dispatched);
        assert!(!report.duplicate);
        assert_eq!(mgr.handler().last_proto, Some(0x0001));
        let ex = report.exchange.unwrap();
        assert_eq!(ex.exch_id(), 0x42);
        assert_eq!(mgr.role(ex), Some(Role::Responder));

        // 同じ exch_id の続きは既存会話にマッチ。
        let m2 = Incoming { ctr: 2, ..m };
        let n2 = build_incoming(&crypto(), &m2, &mut wire);
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                11,
                &mut wire[..n2],
                &mut [0u8; 512],
            )
            .unwrap();
        assert_eq!(r2.exchange, Some(ex));
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.handler().calls, 2);
    }

    #[test]
    fn recv_encrypted_reliable_arms_standalone_ack() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let key = [0x11u8; 16];
        let sid_val = encrypted_session(&mut sessions, peer, key);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let peer_node = 0x5555_6666_7777_8888u64;
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        let mut wire = [0u8; 256];
        let m = Incoming {
            key: Some((key, peer_node)),
            wire_session_id: wire_sid,
            ctr: 5,
            exch_id: 0x70,
            proto_id: 0x0001,
            reliable: true,
            ack_ctr: None,
            initiator: true,
        };
        let n = build_incoming(&crypto(), &m, &mut wire);
        let report = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                1000,
                &mut wire[..n],
                &mut [0u8; 512],
            )
            .unwrap();
        assert!(report.dispatched);
        let ex = report.exchange.unwrap();

        assert_eq!(
            mgr.poll(1199, 0),
            PollAction::Idle {
                next_deadline: Some(1200)
            }
        );
        match mgr.poll(1200, 0) {
            PollAction::SendAck { exchange, ack_ctr } => {
                assert_eq!(exchange, ex);
                assert_eq!(ack_ctr, 5);
            }
            other => panic!("expected SendAck, got {other:?}"),
        }
        assert_eq!(
            mgr.poll(1200, 0),
            PollAction::Idle {
                next_deadline: None
            }
        );

        // standalone ACK を暗号往復で組み立てられる。
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 128];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        let dst = mgr
            .build_standalone_ack(&mut sessions, &crypto(), ex, 5, &mut w, 1200)
            .unwrap();
        assert_eq!(dst, peer);
        assert!(!w.as_slice().is_empty());
    }

    #[test]
    fn recv_duplicate_reliable_rearms_ack() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let key = [0x22u8; 16];
        let sid_val = encrypted_session(&mut sessions, peer, key);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let peer_node = 0x5555_6666_7777_8888u64;
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        let m = Incoming {
            key: Some((key, peer_node)),
            wire_session_id: wire_sid,
            ctr: 5,
            exch_id: 0x70,
            proto_id: 0x0001,
            reliable: true,
            ack_ctr: None,
            initiator: true,
        };
        let mut wire = [0u8; 256];
        let n = build_incoming(&crypto(), &m, &mut wire);
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                1000,
                &mut wire[..n],
                &mut [0u8; 512],
            )
            .unwrap();
        assert!(r1.dispatched);
        let ex = r1.exchange.unwrap();

        // 同一 ctr の再送(リプレイ)。ディスパッチせず重複扱い。
        let n2 = build_incoming(&crypto(), &m, &mut wire);
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                1500,
                &mut wire[..n2],
                &mut [0u8; 512],
            )
            .unwrap();
        assert!(r2.duplicate);
        assert!(!r2.dispatched);
        assert_eq!(mgr.handler().calls, 1, "重複はディスパッチしない");

        // 再 ACK が即時(now=1500)に武装される。
        match mgr.poll(1500, 0) {
            PollAction::SendAck { exchange, ack_ctr } => {
                assert_eq!(exchange, ex);
                assert_eq!(ack_ctr, 5);
            }
            other => panic!("expected immediate re-ACK, got {other:?}"),
        }
    }

    #[test]
    fn recv_response_to_unknown_exchange_is_dropped() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        // initiator=false(応答)だが対応会話が無い。
        let m = Incoming {
            key: None,
            wire_session_id: wire_sid,
            ctr: 1,
            exch_id: 0x42,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: None,
            initiator: false,
        };
        let mut wire = [0u8; 256];
        let n = build_incoming(&crypto(), &m, &mut wire);
        let report = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                10,
                &mut wire[..n],
                &mut [0u8; 512],
            )
            .unwrap();
        assert!(!report.dispatched);
        assert!(report.exchange.is_none());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn recv_unknown_session_is_not_found() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let _ = plaintext_session(&mut sessions, peer);
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        // 存在しない wire session id。
        let m = Incoming {
            key: None,
            wire_session_id: 0,
            ctr: 1,
            exch_id: 0x42,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: None,
            initiator: true,
        };
        let mut wire = [0u8; 256];
        let n = build_incoming(&crypto(), &m, &mut wire);
        // 別のアドレスからにしてセッション照合を外す。
        let other = addr(9999);
        assert_eq!(
            mgr.recv(
                &mut sessions,
                &crypto(),
                other,
                0,
                &mut wire[..n],
                &mut [0u8; 512]
            ),
            Err(Error::NotFound)
        );
    }

    // --- 送信 / MRP 結合 ---

    #[test]
    fn send_reliable_then_recv_ack_frees_buffer() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let key = [0x33u8; 16];
        let sid_val = encrypted_session(&mut sessions, peer, key);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let peer_node = 0x5555_6666_7777_8888u64;
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        // responder 会話(peer initiator の受信で生成)。
        let m0 = Incoming {
            key: Some((key, peer_node)),
            wire_session_id: wire_sid,
            ctr: 5,
            exch_id: 0x70,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: None,
            initiator: true,
        };
        let mut wire = [0u8; 256];
        let n0 = build_incoming(&crypto(), &m0, &mut wire);
        let ex = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                100,
                &mut wire[..n0],
                &mut [0u8; 512],
            )
            .unwrap()
            .exchange
            .unwrap();

        // 信頼応答を送る(tx_ctr_start=100 が使われる)。
        let mut pool: BufferPool<2, 1024> = BufferPool::new();
        let out = Outgoing {
            proto_id: 0x0001,
            opcode: 0x08,
            payload: &[0xAB, 0xCD],
        };
        let sent = mgr
            .send_reliable(
                &mut sessions,
                &crypto(),
                &mut pool,
                ex,
                &out,
                SendTiming {
                    now_ms: 200,
                    jitter_rand: 0,
                },
            )
            .unwrap();
        assert!(mgr.is_retrans_pending(ex));
        assert_eq!(pool.in_use(), 1);

        // ピアからの ACK piggyback(ack_ctr=100)を受信 → 再送解除 + 解放候補。
        let m_ack = Incoming {
            key: Some((key, peer_node)),
            wire_session_id: wire_sid,
            ctr: 6,
            exch_id: 0x70,
            proto_id: 0x0001,
            reliable: false,
            ack_ctr: Some(100),
            initiator: true,
        };
        let na = build_incoming(&crypto(), &m_ack, &mut wire);
        let report = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                300,
                &mut wire[..na],
                &mut [0u8; 512],
            )
            .unwrap();
        assert_eq!(report.freed_tx, Some(sent.buf));
        assert!(!mgr.is_retrans_pending(ex));
        pool.release(sent.buf);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn reliable_retransmit_until_failure() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let ex = mgr.open_initiator(sid_val).unwrap();

        let mut pool: BufferPool<1, 512> = BufferPool::new();
        let out = Outgoing {
            proto_id: 0x0000,
            opcode: 0x20,
            payload: &[0x15, 0x18],
        };
        let sent = mgr
            .send_reliable(
                &mut sessions,
                &crypto(),
                &mut pool,
                ex,
                &out,
                SendTiming {
                    now_ms: 0,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        let mut retransmits = 0u32;
        let mut now = 0u64;
        loop {
            now += 1_000_000;
            match mgr.poll(now, 0) {
                PollAction::Retransmit { exchange, buf, .. } => {
                    assert_eq!(exchange, ex);
                    assert_eq!(buf, sent.buf);
                    retransmits += 1;
                }
                PollAction::Failed { exchange, freed_tx } => {
                    assert_eq!(exchange, ex);
                    assert_eq!(freed_tx, sent.buf);
                    pool.release(freed_tx);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // 初回 1 + 再送 9 = 上限 10。poll で観測される再送は 9 回。
        assert_eq!(retransmits, 9);
        assert!(!mgr.contains(ex));
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn double_reliable_send_is_invalid_state() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let ex = mgr.open_initiator(sid_val).unwrap();

        let mut pool: BufferPool<2, 512> = BufferPool::new();
        let out = Outgoing {
            proto_id: 0x0000,
            opcode: 0x20,
            payload: &[0x00],
        };
        let timing = SendTiming {
            now_ms: 0,
            jitter_rand: 0,
        };
        mgr.send_reliable(&mut sessions, &crypto(), &mut pool, ex, &out, timing)
            .unwrap();
        assert_eq!(
            mgr.send_reliable(&mut sessions, &crypto(), &mut pool, ex, &out, timing),
            Err(Error::InvalidState)
        );
        // 2 本目は確保されずプールは 1 本のみ使用。
        assert_eq!(pool.in_use(), 1);
    }

    #[test]
    fn send_piggybacks_pending_ack() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let key = [0x44u8; 16];
        let sid_val = encrypted_session(&mut sessions, peer, key);
        let wire_sid = sessions.get(sid_val).unwrap().local_session_id();
        let peer_node = 0x5555_6666_7777_8888u64;
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();

        // 信頼メッセージ ctr=9 受信 → ACK 保留(200ms)。
        let m = Incoming {
            key: Some((key, peer_node)),
            wire_session_id: wire_sid,
            ctr: 9,
            exch_id: 0x70,
            proto_id: 0x0001,
            reliable: true,
            ack_ctr: None,
            initiator: true,
        };
        let mut wire = [0u8; 256];
        let n = build_incoming(&crypto(), &m, &mut wire);
        let ex = mgr
            .recv(
                &mut sessions,
                &crypto(),
                peer,
                1000,
                &mut wire[..n],
                &mut [0u8; 512],
            )
            .unwrap()
            .exchange
            .unwrap();

        // 非信頼応答を送る → ACK が piggyback され standalone は消える。
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 128];
        let mut wb = WriteBuf::new(&mut store, headroom).unwrap();
        let out = Outgoing {
            proto_id: 0x0001,
            opcode: 0x09,
            payload: &[0x01, 0x02],
        };
        mgr.send_unreliable(&mut sessions, &crypto(), ex, &out, &mut wb, 1100)
            .unwrap();

        assert_eq!(
            mgr.poll(2000, 0),
            PollAction::Idle {
                next_deadline: None
            }
        );
    }

    #[test]
    fn close_returns_held_retrans_buffer() {
        let mut sessions: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let sid_val = plaintext_session(&mut sessions, peer);
        let mut mgr: ExchangeManager<RecordingDispatcher, 4> = null_mgr();
        let ex = mgr.open_initiator(sid_val).unwrap();

        let mut pool: BufferPool<1, 512> = BufferPool::new();
        let out = Outgoing {
            proto_id: 0x0000,
            opcode: 0x20,
            payload: &[0x00],
        };
        let sent = mgr
            .send_reliable(
                &mut sessions,
                &crypto(),
                &mut pool,
                ex,
                &out,
                SendTiming {
                    now_ms: 0,
                    jitter_rand: 0,
                },
            )
            .unwrap();
        // 閉じると保持中の再送バッファが返り、呼び出し側が解放する。
        let freed = mgr.close(ex);
        assert_eq!(freed, Some(sent.buf));
        pool.release(sent.buf);
        assert_eq!(pool.in_use(), 0);
        assert!(!mgr.contains(ex));
    }
}
