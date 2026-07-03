//! ハンドシェイク一時状態の固定容量プール。
//!
//! `docs/design/secure-channel.md` §5 に基づく。進行中の PASE / CASE ハンドシェイクを
//! `ExchangeId` をキーとして固定容量プール(既定 `H = 1`)に格納し、超過は呼び出し側で
//! Busy 応答に落とす。
//!
//! # `HandshakeKind`(設計 §5.1 の導入)
//!
//! 前タスク(PASE のみ)では slot に PASE 状態を直接持たせ、設計の `HandshakeKind` enum を
//! 省略していた。本タスクで CASE を追加するにあたり、設計どおり
//! [`HandshakeKind`]`{ Pase | Case }` を導入する。PASE と CASE で中間状態のサイズが異なる
//! ため、enum の内側 struct として同型格納する(union は使わない、設計 §5.1)。
//!
//! # CASE 中間状態(トランスクリプトハッシュ)と `S: Sha256`
//!
//! CASE の中間状態 [`CaseCtx`] は、往復をまたいで **進行中のトランスクリプトハッシュ
//! (TT)**を保持する必要がある(Sigma1→Sigma3 の間、TT へ Sigma1+Sigma2 を畳んだ状態を
//! 保つ)。そのためインクリメンタルハッシャ型 `S: Sha256`(= `C::Sha256`)を slot に格納
//! する。よって [`HandshakePool`] / [`HandshakeSlot`] / [`HandshakeKind`] は `S` に
//! ジェネリックである。PASE のみで使う場合も `S` は具体化されるが、`FixedVec` の要素
//! サイズは max(PaseCtx, CaseCtx) で決まる(§5.1)。
//!
//! # スロットの一時バッファサイズ見積り(§9)
//!
//! 1 スロットの常駐サイズ(概算、証明書検証域を除く):
//!
//! - 索引・予約情報(`ExchangeId` / `SessionId` / `peer_session_id` / `started_ms`): ~40 B
//! - `HandshakeKind` enum(内側の大きい方が支配):
//!   - PASE: `PbkdfSent`(context 32 B)/ `Pake2Sent`([`Spake2pVerifier`]: Ke 16 + cA/cB 各
//!     32 = ~80 B)→ ~80 B
//!   - CASE([`CaseCtx`]): `shared_secret` 32 + `our_pub_key` 65 + `peer_pub_key` 65 +
//!     `fabric_index` 1 + トランスクリプトハッシャ `S`(RustCrypto の `sha2::Sha256` 内部
//!     state ~112 B)= **~275 B**
//! - よって slot 常駐は **~315 B**(CASE が支配)。`H = 1` なら sc 全体で 1 KB 未満に収まる。
//!
//! CASE の **証明書検証域(相手 NOC/ICAC の復号・DER 再構築・署名検証、最大 ~1 KB)**は
//! slot に常駐させず、Sigma3 処理の **呼び出しスタック上の一時バッファ**に置く(§7.2)。
//! これにより slot の肥大を避ける。

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::crypto::Sha256;
use crate::error::{Error, Result};
use crate::exchange::ExchangeId;
use crate::transport::session::fixed::FixedVec;
use crate::transport::session::SessionId;

pub use super::case::responder::CASE_EPH_PUBLIC_KEY_LEN;
use crate::crypto::spake2p::Spake2pVerifier;

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

/// 往復をまたぐ CASE の進行状態(Sigma2 送信済み → Sigma3 待ち)。
///
/// Sigma1 処理で確定した ECDH 共有秘密・両者のエフェメラル公開鍵・所属 fabric・
/// トランスクリプトハッシャ(Sigma1+Sigma2 を畳んだ状態)を保持する。`shared_secret` は
/// 中間秘密のため [`Zeroizing`] で drop 時にゼロ化する。
pub struct CaseCtx<S: Sha256> {
    /// 一致した fabric index。
    pub fabric_index: NonZeroU8,
    /// ECDH 共有秘密(X 座標 32 バイト)。中間秘密。
    pub shared_secret: Zeroizing<[u8; 32]>,
    /// responder(自分)のエフェメラル公開鍵(SEC1 非圧縮 65 バイト)。
    pub our_pub_key: [u8; CASE_EPH_PUBLIC_KEY_LEN],
    /// initiator(相手)のエフェメラル公開鍵(SEC1 非圧縮 65 バイト)。
    pub peer_pub_key: [u8; CASE_EPH_PUBLIC_KEY_LEN],
    /// 進行中のトランスクリプトハッシャ(Sigma1 + Sigma2 を畳んだ状態)。
    pub tt: S,
}

/// ハンドシェイク種別と、その往復進行状態(設計 §5.1)。
pub enum HandshakeKind<S: Sha256> {
    /// PASE ハンドシェイク。
    Pase(PasePhase),
    /// CASE ハンドシェイク。
    Case(CaseCtx<S>),
}

/// 1 本のハンドシェイクの一時状態。
pub struct HandshakeSlot<S: Sha256> {
    /// 索引キー(ハンドシェイクを運ぶ unsecured exchange)。
    exchange: ExchangeId,
    /// `reserve()` で先取りした予約セッション(commit まで貫く)。
    reserved: SessionId,
    /// initiator が採番したワイヤ session id(commit 時に peer_session_id へ)。
    peer_session_id: u16,
    /// 開始時刻(タイムアウト判定)。
    started_ms: u64,
    /// 進行状態(PASE / CASE)。
    kind: HandshakeKind<S>,
}

impl<S: Sha256> HandshakeSlot<S> {
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
    pub fn kind_mut(&mut self) -> &mut HandshakeKind<S> {
        &mut self.kind
    }

    /// PASE 進行状態への可変参照を返す(CASE slot では [`None`])。
    pub fn pase_phase_mut(&mut self) -> Option<&mut PasePhase> {
        match &mut self.kind {
            HandshakeKind::Pase(p) => Some(p),
            HandshakeKind::Case(_) => None,
        }
    }

    /// PASE 進行状態を差し替える(CASE slot では何もしない)。
    pub fn set_pase_phase(&mut self, phase: PasePhase) {
        if let HandshakeKind::Pase(p) = &mut self.kind {
            *p = phase;
        }
    }

    /// slot を消費し、`Pake2Sent` phase の SPAKE2+ verifier を取り出す。
    ///
    /// PASE の `Pake2Sent` 以外(状態違反 / CASE)では [`None`]。
    pub fn into_verifier(self) -> Option<Spake2pVerifier> {
        match self.kind {
            HandshakeKind::Pase(PasePhase::Pake2Sent { verifier }) => Some(verifier),
            _ => None,
        }
    }

    /// slot を消費し、CASE 中間状態 [`CaseCtx`] を取り出す(PASE slot では [`None`])。
    pub fn into_case(self) -> Option<CaseCtx<S>> {
        match self.kind {
            HandshakeKind::Case(ctx) => Some(ctx),
            HandshakeKind::Pase(_) => None,
        }
    }
}

/// 固定容量 `H` のハンドシェイクプール。要素はトランスクリプトハッシャ型 `S` に依存する。
pub struct HandshakePool<const H: usize, S: Sha256> {
    slots: FixedVec<HandshakeSlot<S>, H>,
}

impl<const H: usize, S: Sha256> Default for HandshakePool<H, S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const H: usize, S: Sha256> HandshakePool<H, S> {
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
        kind: HandshakeKind<S>,
    ) -> Result<&mut HandshakeSlot<S>> {
        let slot = HandshakeSlot {
            exchange,
            reserved,
            peer_session_id,
            started_ms,
            kind,
        };
        self.slots.push(slot).map_err(|_| Error::NoSpace)?;
        let i = self.slots.len() - 1;
        Ok(&mut self.slots[i])
    }

    /// `exchange` で slot を引く。
    pub fn get_mut(&mut self, exchange: ExchangeId) -> Option<&mut HandshakeSlot<S>> {
        let i = self.index_of(exchange)?;
        Some(&mut self.slots[i])
    }

    /// `exchange` の slot を取り出して除去する(reserved の解放は呼び出し側)。
    pub fn close(&mut self, exchange: ExchangeId) -> Option<HandshakeSlot<S>> {
        let i = self.index_of(exchange)?;
        Some(self.slots.swap_remove(i))
    }

    /// `now_ms - started_ms > timeout_ms` の slot を 1 つ取り出して除去する。
    ///
    /// [`None`] を返すまで繰り返し呼ぶことで、期限切れ slot をすべて回収できる。
    pub fn take_expired(&mut self, now_ms: u64, timeout_ms: u64) -> Option<HandshakeSlot<S>> {
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
