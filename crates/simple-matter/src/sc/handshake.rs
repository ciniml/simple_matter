//! ハンドシェイク一時状態の固定容量プール。
//!
//! `docs/design/secure-channel.md` §5 に基づく。進行中の PASE ハンドシェイクを
//! `ExchangeId` をキーとして固定容量プール(既定 `H = 1`)に格納し、超過は呼び出し側で
//! Busy 応答に落とす。CASE は初期スコープ外のため、slot は PASE 状態を直接持つ
//! (設計の `HandshakeKind` enum は CASE 追加時に導入。乖離)。

use crate::crypto::spake2p::Spake2pVerifier;
use crate::error::{Error, Result};
use crate::exchange::ExchangeId;
use crate::transport::session::fixed::FixedVec;
use crate::transport::session::SessionId;

/// 往復をまたぐ PASE の進行状態(runtime enum。§5.2)。
pub enum PasePhase {
    /// PBKDFParamResponse 送信済み。PASEPake1 待ち。`context` は確定した 32 バイトの
    /// トランスクリプトコンテキストハッシュ。
    PbkdfSent {
        /// トランスクリプトコンテキストハッシュ。
        context: [u8; 32],
    },
    /// PASEPake2 送信済み。PASEPake3(cA)待ち。`verifier` は cA 検証・Ke 取得に用いる。
    Pake2Sent {
        /// SPAKE2+ verifier(Ke・cA・cB を保持)。
        verifier: Spake2pVerifier,
    },
}

/// 1 本のハンドシェイクの一時状態。
pub struct HandshakeSlot {
    /// 索引キー(ハンドシェイクを運ぶ unsecured exchange)。
    exchange: ExchangeId,
    /// `reserve()` で先取りした予約セッション(commit まで貫く)。
    reserved: SessionId,
    /// initiator が採番したワイヤ session id(commit 時に peer_session_id へ)。
    peer_session_id: u16,
    /// 開始時刻(タイムアウト判定)。
    started_ms: u64,
    /// 進行状態。
    phase: PasePhase,
}

impl HandshakeSlot {
    /// 索引キー(exchange)を返す。
    pub const fn exchange(&self) -> ExchangeId {
        self.exchange
    }

    /// 予約セッションの [`SessionId`] を返す。
    pub const fn reserved(&self) -> SessionId {
        self.reserved
    }

    /// initiator のワイヤ session id を返す。
    pub const fn peer_session_id(&self) -> u16 {
        self.peer_session_id
    }

    /// 進行状態への可変参照を返す。
    pub fn phase_mut(&mut self) -> &mut PasePhase {
        &mut self.phase
    }

    /// 進行状態を差し替える。
    pub fn set_phase(&mut self, phase: PasePhase) {
        self.phase = phase;
    }

    /// slot を消費し、`Pake2Sent` phase の SPAKE2+ verifier を取り出す。
    ///
    /// それ以外の phase(状態違反)では [`None`]。
    pub fn into_verifier(self) -> Option<Spake2pVerifier> {
        match self.phase {
            PasePhase::Pake2Sent { verifier } => Some(verifier),
            PasePhase::PbkdfSent { .. } => None,
        }
    }
}

/// 固定容量 `H` のハンドシェイクプール。
pub struct HandshakePool<const H: usize> {
    slots: FixedVec<HandshakeSlot, H>,
}

impl<const H: usize> Default for HandshakePool<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const H: usize> HandshakePool<H> {
    /// 空のプールを生成する。
    pub const fn new() -> Self {
        Self {
            slots: FixedVec::new(),
        }
    }

    /// 現在のハンドシェイク数を返す。
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// ハンドシェイクが 1 本も無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// プールが満杯なら `true`。
    pub fn is_full(&self) -> bool {
        self.slots.is_full()
    }

    /// 新規ハンドシェイクの slot を確保する。
    ///
    /// 満杯なら [`Error::NoSpace`](呼び出し側が Busy 応答に落とす)。
    pub fn open(
        &mut self,
        exchange: ExchangeId,
        reserved: SessionId,
        peer_session_id: u16,
        started_ms: u64,
        phase: PasePhase,
    ) -> Result<&mut HandshakeSlot> {
        let slot = HandshakeSlot {
            exchange,
            reserved,
            peer_session_id,
            started_ms,
            phase,
        };
        self.slots.push(slot).map_err(|_| Error::NoSpace)?;
        let i = self.slots.len() - 1;
        Ok(&mut self.slots[i])
    }

    /// `exchange` で slot を引く。
    pub fn get_mut(&mut self, exchange: ExchangeId) -> Option<&mut HandshakeSlot> {
        let i = self.index_of(exchange)?;
        Some(&mut self.slots[i])
    }

    /// `exchange` の slot を取り出して除去する(reserved の解放は呼び出し側)。
    pub fn close(&mut self, exchange: ExchangeId) -> Option<HandshakeSlot> {
        let i = self.index_of(exchange)?;
        Some(self.slots.swap_remove(i))
    }

    /// `now_ms - started_ms > timeout_ms` の slot を 1 つ取り出して除去する。
    ///
    /// [`None`] を返すまで繰り返し呼ぶことで、期限切れ slot をすべて回収できる。
    pub fn take_expired(&mut self, now_ms: u64, timeout_ms: u64) -> Option<HandshakeSlot> {
        let i = self
            .slots
            .iter()
            .position(|s| now_ms.saturating_sub(s.started_ms) > timeout_ms)?;
        Some(self.slots.swap_remove(i))
    }

    fn index_of(&self, exchange: ExchangeId) -> Option<usize> {
        self.slots.iter().position(|s| s.exchange == exchange)
    }
}
