//! SC initiator(コントローラ側 PASE / CASE)の同期状態機械。
//!
//! `docs/design/controller.md` §3 に基づく。responder([`crate::sc::SecureChannel`])の
//! **鏡像**として、コントローラが自発的に開始する PASE / CASE ハンドシェイクを駆動する。
//!
//! - **PASE initiator**: PBKDFParamRequest 送信 → PBKDFParamResponse → PASEPake1 →
//!   PASEPake2 → PASEPake3 → 成功 StatusReport 受理(§3.4)。
//! - **CASE initiator**: Sigma1 送信 → Sigma2 検証 → Sigma3 → 成功 StatusReport 受理。
//!
//! # 契約への適合(§3.2)
//!
//! [`ProtocolHandler`] は受信駆動なので、**開始**(最初の送信)だけが契約の外にある。
//! 開始は [`ScInitiator::start_pase`] / [`ScInitiator::start_case`] が応答バッファに payload を
//! 書き、統合層(`ControllerStack`)が `open_initiator` + `send_reliable` で送る。以降の
//! 応答は [`ProtocolHandler::handle`] の一本道で届き、中間メッセージは [`HandlerAction::Respond`]
//! で返す。終端(StatusReport 受信)では送るものがないので [`HandlerAction::None`] を返し、
//! 結果を 1 深度イベント [`ScEvent`] に積む(`take_event` でポーリング取り出し)。
//!
//! # 受信の混線が起きない理由(§3.1)
//!
//! initiator が受け取るのは常に「自分が `open_initiator` で開いた exchange への応答」であり、
//! exchange 層の role 対称照合が保証する。`handle` は自分の進行中 exchange 以外を silent drop する。
//!
//! # 鍵の向き(responder の逆)
//!
//! initiator は **I2R = enc(送信)、R2I = dec(受信)**([`crate::sc::SecureChannel`] は逆)。

pub mod case;
pub mod pase;

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::crypto::spake2p::Spake2pProver;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng, Sha256};
use crate::error::{Error, Result};
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, RxMessage};
use crate::sc::case::common;
use crate::sc::case::creds::{Fabric, FabricStore, NocResolver};
use crate::sc::pase::{build_context, SESSION_KEYS_LEN, SPAKE2P_SESSION_KEYS_INFO};
use crate::sc::resumption::{ResumptionStore, RESUMPTION_CACHE_LEN};
use crate::sc::status::{GeneralCode, ScStatusCode, StatusReport, PROTO_ID_SECURE_CHANNEL};
use crate::sc::OpCode;
use crate::transport::session::{SessionId, SessionInit, SessionManager, SessionMode};

use case::{CaseInitiator, CasePhase};
use pase::{PaseInitiator, PasePhase};

/// ハンドシェイク確立のタイムアウト(ミリ秒)。responder と同値(60s)。
pub const HANDSHAKE_TIMEOUT_MS: u64 = 60_000;

/// AES-CCM 鍵長。
const KEY_LEN: usize = 16;

/// 完了したハンドシェイクの種別タグ([`ScEvent::Failed`] 用)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeKindTag {
    /// PASE(passcode)ハンドシェイク。
    Pase,
    /// CASE(operational)ハンドシェイク。
    Case,
}

/// ハンドシェイク失敗の理由(`docs/design/controller.md` §3.5)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScFailReason {
    /// 相手から失敗 StatusReport を受理した(値は `ScStatusCode` のワイヤ値。Busy を含む)。
    StatusReport(u16),
    /// タイムアウト(60s 超過)で破棄した。
    Timeout,
    /// 暗号演算・検証(ECDH / 署名 / AEAD / SPAKE2+ 確認値)に失敗した。
    Crypto,
    /// 受信メッセージのデコードに失敗した。
    Decode,
}

/// initiator ハンドシェイクの完了/失敗イベント(1 深度)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScEvent {
    /// PASE セッションが確立した。
    PaseEstablished {
        /// 確立したセッションのハンドル。
        session: SessionId,
    },
    /// CASE セッションが確立した。
    CaseEstablished {
        /// 確立したセッションのハンドル。
        session: SessionId,
        /// session resumption(Sigma2_Resume)経由で確立したなら `true`(§7.4)。
        resumed: bool,
    },
    /// ハンドシェイクが失敗した。
    Failed {
        /// 失敗したハンドシェイク種別。
        kind: HandshakeKindTag,
        /// 失敗理由。
        reason: ScFailReason,
    },
}

/// 進行中ハンドシェイクの種別ごとの往復状態。
///
/// 同時ハンドシェイクは 1 本固定(`Option` 1 slot)で、PASE(SPAKE2+ prover を内包し大きい)と
/// CASE でサイズが異なる。responder の [`HandshakePool`](crate::sc::handshake) と同様、単一 slot に
/// `max(Pase, Case)` サイズで格納するのが設計意図(§3.4)。`no_std`・定常パス no-alloc のため
/// box 化はできないので、variant サイズ差は許容する。
#[allow(clippy::large_enum_variant)]
enum InitiatorKind<C: Crypto> {
    Pase(PaseInitiator),
    Case(CaseInitiator<C>),
}

/// 進行中 1 本のハンドシェイク(§3.4)。
struct InitiatorHandshake<C: Crypto> {
    /// `start_*` で開いた exchange(応答照合キー)。
    exchange: ExchangeId,
    /// `reserve()` 済みの新セッション slot(commit まで貫く)。
    reserved: SessionId,
    /// 開始時刻(60s タイムアウト)。
    started_ms: u64,
    /// 種別ごとの往復状態。
    kind: InitiatorKind<C>,
}

/// Secure Channel(Protocol ID 0x0000)の **initiator** ハンドラ。
///
/// 同時コミッショニングは 1 台固定のため、進行中ハンドシェイクは単一 slot
/// (`Option`)で持つ(2 本目の `start_*` は [`Error::NoSpace`] = Busy)。`crypto` は参照、
/// `rng` は値で保持する(initiator_random / エフェメラル鍵 / SPAKE2+ の x スカラ生成)。
/// `creds` は CASE が触る fabric 面([`FabricStore`] + [`NocResolver`])。PASE だけで使う場合は
/// [`crate::sc::case::creds::NoFabrics`] を渡す。
pub struct ScInitiator<'c, C: Crypto, R: Rng, F> {
    crypto: &'c C,
    rng: R,
    creds: F,
    hs: Option<InitiatorHandshake<C>>,
    event: Option<ScEvent>,
    /// CASE session resumption レコード(メモリ内・固定容量。§7.4)。
    resumptions: ResumptionStore<RESUMPTION_CACHE_LEN>,
}

impl<'c, C: Crypto, R: Rng, F> ScInitiator<'c, C, R, F> {
    /// crypto・rng・creds を与えてハンドラを生成する。
    pub fn new(crypto: &'c C, rng: R, creds: F) -> Self {
        Self {
            crypto,
            rng,
            creds,
            hs: None,
            event: None,
            resumptions: ResumptionStore::new(),
        }
    }

    /// 保持している CASE resumption レコード数を返す(§7.4)。
    pub fn resumption_count(&self) -> usize {
        self.resumptions.len()
    }

    /// ピアの resumption 素材(現行 resumptionID + SharedSecret)を取り出す。
    ///
    /// アプリ層の永続化用(置き場とライフサイクル管理はアプリ層、コアは
    /// export/import のみ — `kvs::Kvs`/`FabricTable::save_to` と同じ分業)。
    /// レコードが無ければ `None`。
    pub fn resumption_export(
        &self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
    ) -> Option<(
        [u8; common::CASE_RESUMPTION_ID_LEN],
        [u8; common::SHARED_SECRET_LEN],
    )> {
        self.resumptions
            .find_by_peer(fabric_index, peer_node_id)
            .map(|r| (r.resumption_id, *r.shared_secret))
    }

    /// アプリ層が永続化していた resumption 素材を取り込む(`(fabric, peer)` で upsert)。
    ///
    /// 次回 `start_case` の Sigma1 に resumptionID + initiatorResumeMIC(ctx6/7)が
    /// 付き、responder が受理すれば Sigma2_Resume 経路で確立する(§7.4)。
    pub fn resumption_import(
        &mut self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
        resumption_id: &[u8; common::CASE_RESUMPTION_ID_LEN],
        shared_secret: &[u8; common::SHARED_SECRET_LEN],
    ) {
        self.resumptions
            .save(fabric_index, peer_node_id, resumption_id, shared_secret);
    }

    /// 進行中ハンドシェイクがあれば `true`。
    pub fn is_busy(&self) -> bool {
        self.hs.is_some()
    }

    /// 進行中ハンドシェイクが使用中の exchange を返す(統合層の exchange 回収判定用)。
    pub fn active_exchange(&self) -> Option<ExchangeId> {
        self.hs.as_ref().map(|h| h.exchange)
    }

    /// 完了/失敗イベントを 1 件取り出す(§3.5)。
    pub fn take_event(&mut self) -> Option<ScEvent> {
        self.event.take()
    }

    /// 期限切れ(60s 超過)ハンドシェイクを破棄し、予約セッションを解放する。
    ///
    /// 破棄した場合は `Failed { Timeout }` を積み `true` を返す。統合層が定期呼び出しする。
    pub fn on_tick<const S: usize>(
        &mut self,
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> bool {
        let expired = match &self.hs {
            Some(h) => now_ms.saturating_sub(h.started_ms) > HANDSHAKE_TIMEOUT_MS,
            None => false,
        };
        if expired {
            if let Some(h) = self.hs.take() {
                let kind = match h.kind {
                    InitiatorKind::Pase(_) => HandshakeKindTag::Pase,
                    InitiatorKind::Case(_) => HandshakeKindTag::Case,
                };
                sessions.remove(h.reserved);
                self.event = Some(ScEvent::Failed {
                    kind,
                    reason: ScFailReason::Timeout,
                });
            }
            true
        } else {
            false
        }
    }

    /// `dest` を Rng で満たす(コミッショナの attestation nonce 払い出し用)。
    pub fn fill_random(&mut self, dest: &mut [u8]) -> Result<()> {
        self.rng.fill_bytes(dest)
    }

    /// 新規セキュアセッションの送信メッセージカウンタ初期値(下位 28bit 乱数 + 1)。
    fn initial_tx_ctr(&mut self) -> u32 {
        let mut b = [0u8; 4];
        if self.rng.fill_bytes(&mut b).is_err() {
            return 1;
        }
        (u32::from_le_bytes(b) & 0x0FFF_FFFF) + 1
    }

    /// 非セキュアメッセージの source Node ID に使うエフェメラル ID を生成する(非 0)。
    ///
    /// chip 系実装は非セキュアパケットに source/destination Node ID のいずれかを
    /// 要求するため、initiator は自身のエフェメラル ID を source として載せる
    /// (chip-tool と同じ挙動)。乱数取得に失敗した場合は固定値にフォールバックする。
    pub fn ephemeral_node_id(&mut self) -> u64 {
        let mut b = [0u8; 8];
        if self.rng.fill_bytes(&mut b).is_err() {
            return 1;
        }
        match u64::from_le_bytes(b) {
            0 => 1,
            id => id,
        }
    }

    /// PASE ハンドシェイクを開始する(§3.4)。
    ///
    /// `exchange` は統合層が `open_initiator` で開いた unsecured exchange、`reserved` は
    /// `reserve()` 済みの新セッション、`initiator_ssid` はそのローカル session id(ワイヤ広告)。
    /// PBKDFParamRequest を `out` に書き、その長さ(opcode = [`OpCode::PbkdfParamRequest`])を返す。
    /// 進行中ハンドシェイクがあれば [`Error::NoSpace`](Busy)。
    pub fn start_pase(
        &mut self,
        exchange: ExchangeId,
        reserved: SessionId,
        initiator_ssid: u16,
        passcode: u32,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        if self.hs.is_some() {
            return Err(Error::NoSpace);
        }
        let mut initiator_random = [0u8; 32];
        self.rng
            .fill_bytes(&mut initiator_random)
            .map_err(|_| Error::Crypto)?;
        let len = pase::encode_pbkdf_param_req(out, &initiator_random, initiator_ssid, 0, false)?;
        if len > pase::PBKDF_REQ_MAX {
            return Err(Error::NoSpace);
        }
        let mut req = [0u8; pase::PBKDF_REQ_MAX];
        req[..len].copy_from_slice(&out[..len]);
        self.hs = Some(InitiatorHandshake {
            exchange,
            reserved,
            started_ms: now_ms,
            kind: InitiatorKind::Pase(PaseInitiator {
                phase: PasePhase::PbkdfReqSent,
                passcode,
                req,
                req_len: len,
                context: [0u8; 32],
                prover: None,
                confirm: None,
                peer_ssid: 0,
            }),
        });
        Ok(len)
    }

    /// 開始直後のハンドシェイクを**静かに**取り消す(`start_pase`/`start_case` の
    /// 第 1 メッセージ送信に失敗したときの巻き戻し用)。
    ///
    /// [`abort`](Self::abort) と違い `Failed` イベントは積まない(呼び出し元が同期
    /// エラーを受け取るため。イベントを積むと後続ハンドシェイクの待ち手が stale な
    /// Failed を拾って誤判定する — K4 実機で顕在化)。予約セッション・exchange の
    /// 解放は呼び出し元(controller 層)が行う。
    pub(crate) fn cancel_handshake(&mut self) {
        self.hs = None;
    }

    /// 進行中ハンドシェイクを破棄し、予約セッションを解放して `Failed` を積む。
    fn abort<const S: usize>(
        &mut self,
        sessions: &mut SessionManager<S>,
        kind: HandshakeKindTag,
        reason: ScFailReason,
    ) -> Result<HandlerAction> {
        if let Some(h) = self.hs.take() {
            sessions.remove(h.reserved);
        }
        self.event = Some(ScEvent::Failed { kind, reason });
        Ok(HandlerAction::None)
    }
}

impl<'c, C: Crypto, R: Rng, F: FabricStore> ScInitiator<'c, C, R, F> {
    /// CASE ハンドシェイクを開始する(§3.4)。
    ///
    /// `fabric_idx` は自 fabric([`FabricStore`] 内)、`peer_node_id` は相手(デバイス)の
    /// operational NodeId(destination-id に用いる)。Sigma1 を `out` に書き、その長さ
    /// (opcode = [`OpCode::CaseSigma1`])を返す。進行中ハンドシェイクがあれば
    /// [`Error::NoSpace`](Busy)、fabric 不明は [`Error::NotFound`]。
    #[allow(clippy::too_many_arguments)]
    pub fn start_case(
        &mut self,
        exchange: ExchangeId,
        reserved: SessionId,
        initiator_ssid: u16,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        out: &mut [u8],
        now_ms: u64,
    ) -> Result<usize> {
        if self.hs.is_some() {
            return Err(Error::NoSpace);
        }
        let (ipk, root_pub, fabric_id) = {
            let f = self.creds.get(fabric_idx).ok_or(Error::NotFound)?;
            (*f.ipk(), *f.root_public_key(), f.fabric_id())
        };
        let eph = self
            .crypto
            .p256_generate_keypair()
            .map_err(|_| Error::Crypto)?;
        let eph_pub = eph.public_key().to_bytes();
        let mut initiator_random = [0u8; common::CASE_RANDOM_LEN];
        self.rng
            .fill_bytes(&mut initiator_random)
            .map_err(|_| Error::Crypto)?;
        let mut dest_id = [0u8; common::CASE_DEST_ID_LEN];
        common::compute_destination_id(
            self.crypto,
            &ipk,
            &initiator_random,
            &root_pub,
            fabric_id,
            peer_node_id,
            &mut dest_id,
        )
        .map_err(|_| Error::Crypto)?;

        // resumption レコードがあれば Sigma1 に resumptionID + initiatorResumeMIC を付ける
        // (§7.4)。MIC 計算に失敗した場合はフル CASE として送る(安全側)。
        let mut shared_secret = Zeroizing::new([0u8; common::SHARED_SECRET_LEN]);
        let mut attempted_resumption_id = None;
        let mut mic = [0u8; common::RESUME_MIC_LEN];
        if let Some(record) = self.resumptions.find_by_peer(fabric_idx, peer_node_id) {
            if common::compute_resume_mic(
                self.crypto,
                &initiator_random,
                &record.resumption_id,
                &record.shared_secret,
                common::SIGMA1_RESUME_KEY_INFO,
                common::SIGMA1_RESUME_NONCE,
                &mut mic,
            )
            .is_ok()
            {
                attempted_resumption_id = Some(record.resumption_id);
                *shared_secret = *record.shared_secret;
            }
        }
        let resumption = attempted_resumption_id.as_ref().map(|rid| (rid, &mic));
        let len = case::encode_sigma1(
            out,
            &initiator_random,
            initiator_ssid,
            &dest_id,
            &eph_pub,
            resumption,
        )?;
        let mut tt = self.crypto.sha256();
        tt.update(&out[..len]);
        self.hs = Some(InitiatorHandshake {
            exchange,
            reserved,
            started_ms: now_ms,
            kind: InitiatorKind::Case(CaseInitiator {
                phase: CasePhase::Sigma1Sent,
                eph,
                tt,
                shared_secret,
                fabric_idx,
                peer_node_id,
                peer_ssid: 0,
                initiator_random,
                attempted_resumption_id,
                peer_resumption_id: None,
            }),
        });
        Ok(len)
    }
}

/// CASE Sigma2 処理の帰結(成功時は Sigma3 長、失敗時は理由)。
enum CaseOutcome {
    Ready(usize),
    Fail(ScFailReason),
}

impl<C: Crypto, R: Rng, F: FabricStore + NocResolver> ScInitiator<'_, C, R, F> {
    /// PBKDFParamResponse を受けて PASEPake1 を返す。
    fn pase_on_resp<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
    ) -> Result<HandlerAction> {
        // 短い借用で必要なスカラ/バイトを取り出す。
        let (passcode, req, req_len) = match &self.hs {
            Some(h) => match &h.kind {
                InitiatorKind::Pase(p) if p.phase == PasePhase::PbkdfReqSent => {
                    (p.passcode, p.req, p.req_len)
                }
                _ => return Err(Error::InvalidState),
            },
            None => return Ok(HandlerAction::None),
        };
        let resp = match pase::PbkdfParamResp::decode(rx.payload) {
            Ok(r) => r,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        let mut context = [0u8; 32];
        build_context(self.crypto, &req[..req_len], rx.payload, &mut context);
        let prover =
            match Spake2pProver::from_passcode(&mut self.rng, passcode, resp.salt, resp.iterations)
            {
                Ok(p) => p,
                Err(_) => {
                    return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Crypto)
                }
            };
        let len = match pase::encode_pake1(tx, prover.share()) {
            Ok(n) => n,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        if let Some(InitiatorKind::Pase(p)) = self.hs.as_mut().map(|h| &mut h.kind) {
            p.context = context;
            p.prover = Some(prover);
            p.peer_ssid = resp.responder_ssid;
            p.phase = PasePhase::Pake1Sent;
        }
        Ok(HandlerAction::Respond {
            opcode: OpCode::PasePake1 as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len,
        })
    }

    /// PASEPake2 を受けて確認・PASEPake3 を返す。
    fn pase_on_pake2<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
    ) -> Result<HandlerAction> {
        let (context, prover) = match &mut self.hs {
            Some(h) => match &mut h.kind {
                InitiatorKind::Pase(p) if p.phase == PasePhase::Pake1Sent => {
                    (p.context, p.prover.take())
                }
                _ => return Err(Error::InvalidState),
            },
            None => return Ok(HandlerAction::None),
        };
        let prover = match prover {
            Some(p) => p,
            None => return Err(Error::InvalidState),
        };
        let pake2 = match pase::Pake2::decode(rx.payload) {
            Ok(p) => p,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        let pb: &[u8; 65] = match pake2.pb.try_into() {
            Ok(p) => p,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        let cb: &[u8; 32] = match pake2.cb.try_into() {
            Ok(c) => c,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        let confirm = match prover.confirm(&context, pb) {
            Ok(c) => c,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Crypto),
        };
        if confirm.verify_b(cb).is_err() {
            // cB 不一致 = パスコード不一致等。
            return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Crypto);
        }
        let ca = *confirm.confirmation_a();
        let len = match pase::encode_pake3(tx, &ca) {
            Ok(n) => n,
            Err(_) => return self.abort(sessions, HandshakeKindTag::Pase, ScFailReason::Decode),
        };
        if let Some(InitiatorKind::Pase(p)) = self.hs.as_mut().map(|h| &mut h.kind) {
            p.confirm = Some(confirm);
            p.phase = PasePhase::Pake3Sent;
        }
        Ok(HandlerAction::Respond {
            opcode: OpCode::PasePake3 as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len,
        })
    }

    /// CASE Sigma2 を検証し、Sigma3 を返す。
    fn case_on_sigma2<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
    ) -> Result<HandlerAction> {
        let crypto = self.crypto;
        let outcome: CaseOutcome = 'blk: {
            let h = match &mut self.hs {
                Some(h) => h,
                None => return Ok(HandlerAction::None),
            };
            let c = match &mut h.kind {
                InitiatorKind::Case(c) => c,
                _ => return Err(Error::InvalidState),
            };
            if c.phase != CasePhase::Sigma1Sent {
                return Err(Error::InvalidState);
            }

            let s2 = match case::Sigma2::decode(rx.payload) {
                Ok(s) => s,
                Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
            };
            let peer_eph: &[u8; common::CASE_EPH_PUBLIC_KEY_LEN] = match s2.eph_pub.try_into() {
                Ok(p) => p,
                Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
            };
            let responder_random: &[u8; common::CASE_RANDOM_LEN] =
                match s2.responder_random.try_into() {
                    Ok(r) => r,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                };
            let peer_obj = match crypto.p256_public_key_from_bytes(peer_eph) {
                Ok(k) => k,
                Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
            };
            let mut shared = Zeroizing::new([0u8; common::SHARED_SECRET_LEN]);
            if c.eph.ecdh(&peer_obj, &mut shared).is_err() {
                break 'blk CaseOutcome::Fail(ScFailReason::Crypto);
            }
            let our_pub = c.eph.public_key().to_bytes();

            // fabric 素材(自 IPK)。
            let ipk = match self.creds.get(c.fabric_idx) {
                Some(f) => *f.ipk(),
                None => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
            };

            // S2K = HKDF(salt=IPK‖respRand‖respEph‖TThash(Σ1), ikm=shared, "Sigma2")。
            let mut tt_s1 = [0u8; common::TT_HASH_LEN];
            c.tt.clone().finish(&mut tt_s1);
            let mut s2k = Zeroizing::new([0u8; KEY_LEN]);
            if common::derive_sigma2_key(
                crypto,
                &ipk,
                responder_random,
                peer_eph,
                &tt_s1,
                &shared,
                &mut s2k,
            )
            .is_err()
            {
                break 'blk CaseOutcome::Fail(ScFailReason::Crypto);
            }

            // TBEData2 を復号し、相手 NOC/ICAC/署名を取り出す。
            let mut tbe2 = [0u8; common::CASE_SCRATCH_LEN];
            if s2.encrypted2.len() > tbe2.len() {
                break 'blk CaseOutcome::Fail(ScFailReason::Decode);
            }
            tbe2[..s2.encrypted2.len()].copy_from_slice(s2.encrypted2);
            let pt_len = match crypto.aes_ccm_decrypt(
                &s2k,
                common::SIGMA2_NONCE,
                &[],
                &mut tbe2[..s2.encrypted2.len()],
            ) {
                Ok(pt) => pt.len(),
                Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
            };

            // Sigma3 を組み立てて Outcome を得る(相手検証を通過してから)。
            let sigma3_len = {
                let (rnoc, ricac, rsig) = match common::decode_tbe_certs(&tbe2[..pt_len]) {
                    Ok(v) => v,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                };
                // 相手 NOC チェーン検証。
                let peer_id = match self.creds.verify_peer_noc(c.fabric_idx, rnoc, ricac) {
                    Ok(id) => id,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
                };
                // Sigma2 TBS 署名検証(sender = responderEph, receiver = initiatorEph)。
                let sig: &[u8; common::SIGNATURE_LEN] = match rsig.try_into() {
                    Ok(s) => s,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                };
                let mut tbs2 = [0u8; common::CASE_SCRATCH_LEN];
                let tbs2_len = match common::encode_tbs(&mut tbs2, rnoc, ricac, peer_eph, &our_pub)
                {
                    Ok(n) => n,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                };
                let pubk = match crypto.p256_public_key_from_bytes(peer_id.public_key()) {
                    Ok(k) => k,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
                };
                match pubk.verify(&tbs2[..tbs2_len], sig) {
                    Ok(true) => {}
                    _ => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
                }

                // 検証通過。相手採番の resumptionID(TBE2 ctx4。commit 時にレコード保存)を
                // 控え、Sigma2 を TT に畳む。
                c.peer_resumption_id = common::decode_tbe2_resumption_id(&tbe2[..pt_len]).ok();
                c.tt.update(rx.payload);
                let mut tt_s2 = [0u8; common::TT_HASH_LEN];
                c.tt.clone().finish(&mut tt_s2);

                // 自 fabric の NOC/ICAC で TBSData3 を署名し TBEData3 を暗号化。
                let fabric = match self.creds.get(c.fabric_idx) {
                    Some(f) => f,
                    None => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
                };
                let own_noc = fabric.noc();
                let own_icac = fabric.icac();
                let mut tbs3 = [0u8; common::CASE_SCRATCH_LEN];
                let tbs3_len =
                    match common::encode_tbs(&mut tbs3, own_noc, own_icac, &our_pub, peer_eph) {
                        Ok(n) => n,
                        Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                    };
                let mut sig3 = [0u8; common::SIGNATURE_LEN];
                if fabric.sign(&tbs3[..tbs3_len], &mut sig3).is_err() {
                    break 'blk CaseOutcome::Fail(ScFailReason::Crypto);
                }
                let mut s3k = Zeroizing::new([0u8; KEY_LEN]);
                if common::derive_ipk_tt_keyed(
                    crypto,
                    &ipk,
                    &tt_s2,
                    common::SIGMA3_KEY_INFO,
                    &shared,
                    &mut s3k[..],
                )
                .is_err()
                {
                    break 'blk CaseOutcome::Fail(ScFailReason::Crypto);
                }
                let mut enc3 = [0u8; common::CASE_SCRATCH_LEN];
                let enc3_len =
                    match case::encrypt_tbe3(crypto, &s3k, own_noc, own_icac, &sig3, &mut enc3) {
                        Ok(n) => n,
                        Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Crypto),
                    };
                match case::encode_sigma3(tx, &enc3[..enc3_len]) {
                    Ok(n) => n,
                    Err(_) => break 'blk CaseOutcome::Fail(ScFailReason::Decode),
                }
            };

            // Sigma3 生バイトを TT に畳み、slot を進める。
            c.tt.update(&tx[..sigma3_len]);
            *c.shared_secret = *shared;
            c.peer_ssid = s2.responder_ssid;
            c.phase = CasePhase::Sigma3Sent;
            CaseOutcome::Ready(sigma3_len)
        };

        match outcome {
            CaseOutcome::Ready(len) => Ok(HandlerAction::Respond {
                opcode: OpCode::CaseSigma3 as u8,
                proto_id: PROTO_ID_SECURE_CHANNEL,
                reliable: true,
                len,
            }),
            CaseOutcome::Fail(reason) => self.abort(sessions, HandshakeKindTag::Case, reason),
        }
    }

    /// CASE Sigma2_Resume を検証し、commit して成功 StatusReport を返す(§7.4)。
    ///
    /// commit を済ませてから成功 StatusReport を [`HandlerAction::Close`] で返す
    /// (responder は StatusReport 受信で commit する。chip と同順序)。
    fn case_on_sigma2_resume<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let crypto = self.crypto;

        // 検証フェーズ(hs は借用のまま)。
        let (new_rid, responder_ssid) = {
            let h = match &self.hs {
                Some(h) => h,
                None => return Ok(HandlerAction::None),
            };
            let c = match &h.kind {
                InitiatorKind::Case(c) => c,
                _ => return Err(Error::InvalidState),
            };
            if c.phase != CasePhase::Sigma1Sent {
                return Err(Error::InvalidState);
            }
            // resumption を要求していないのに Sigma2_Resume が届いた = プロトコル違反。
            if c.attempted_resumption_id.is_none() {
                return self.abort(sessions, HandshakeKindTag::Case, ScFailReason::Decode);
            }
            let s2r = match case::Sigma2Resume::decode(rx.payload) {
                Ok(s) => s,
                Err(_) => {
                    return self.abort(sessions, HandshakeKindTag::Case, ScFailReason::Decode)
                }
            };
            let new_rid: [u8; common::CASE_RESUMPTION_ID_LEN] = match s2r.resumption_id.try_into() {
                Ok(r) => r,
                Err(_) => {
                    return self.abort(sessions, HandshakeKindTag::Case, ScFailReason::Decode)
                }
            };
            // sigma2ResumeMIC 検証(S2RK。salt の resumptionID は新 ID)。
            if common::verify_resume_mic(
                crypto,
                &c.initiator_random,
                &new_rid,
                &c.shared_secret,
                common::SIGMA2_RESUME_KEY_INFO,
                common::SIGMA2_RESUME_NONCE,
                s2r.resume_mic,
            )
            .is_err()
            {
                return self.abort(sessions, HandshakeKindTag::Case, ScFailReason::Crypto);
            }
            (new_rid, s2r.responder_ssid)
        };

        // commit フェーズ(hs を消費)。
        let h = self.hs.take().ok_or(Error::InvalidState)?;
        let reserved = h.reserved;
        let c = match h.kind {
            InitiatorKind::Case(c) => c,
            _ => {
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };
        let old_rid = match c.attempted_resumption_id {
            Some(r) => r,
            None => {
                sessions.remove(reserved);
                return self.fail(HandshakeKindTag::Case, ScFailReason::Decode);
            }
        };
        let local_node_id = self.creds.get(c.fabric_idx).map(|f| f.node_id());
        let local_node_id = match local_node_id {
            Some(v) => v,
            None => {
                sessions.remove(reserved);
                return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
            }
        };
        // セッション鍵(salt = initiatorRandom ‖ 旧 resumptionID, "SessionResumptionKeys")。
        let mut keys = Zeroizing::new([0u8; common::CASE_SESSION_KEYS_LEN]);
        if common::derive_resumption_session_keys(
            crypto,
            &c.initiator_random,
            &old_rid,
            &c.shared_secret,
            &mut keys,
        )
        .is_err()
        {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
        }
        // initiator: enc = I2R, dec = R2I。
        let mut enc_key = [0u8; KEY_LEN];
        let mut dec_key = [0u8; KEY_LEN];
        let mut att = [0u8; KEY_LEN];
        enc_key.copy_from_slice(&keys[0..KEY_LEN]);
        dec_key.copy_from_slice(&keys[KEY_LEN..2 * KEY_LEN]);
        att.copy_from_slice(&keys[2 * KEY_LEN..3 * KEY_LEN]);

        let peer_addr = match sessions.get(reserved) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };
        let tx_ctr_start = self.initial_tx_ctr();
        let init = SessionInit {
            peer_addr,
            local_node_id,
            peer_node_id: Some(c.peer_node_id),
            peer_session_id: responder_ssid,
            tx_ctr_start,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: c.fabric_idx,
            },
            enc_key,
            dec_key,
            att_challenge: att,
        };
        if sessions.commit(reserved, init, now_ms).is_err() {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
        }
        // レコードを新 resumptionID でローテート保存(SharedSecret 不変)。
        self.resumptions
            .save(c.fabric_idx, c.peer_node_id, &new_rid, &c.shared_secret);
        self.event = Some(ScEvent::CaseEstablished {
            session: reserved,
            resumed: true,
        });

        // commit 後に成功 StatusReport を送って終端する(responder はこれで commit する)。
        let sr = StatusReport::new(ScStatusCode::SessionEstablishmentSuccess, &[]);
        let len = sr.encode(tx)?;
        Ok(HandlerAction::Close {
            opcode: OpCode::StatusReport as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len,
        })
    }

    /// 終端 StatusReport を受理する(成功なら commit、失敗なら破棄)。
    fn on_status<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let kind = match &self.hs {
            Some(h) => match &h.kind {
                InitiatorKind::Pase(_) => HandshakeKindTag::Pase,
                InitiatorKind::Case(_) => HandshakeKindTag::Case,
            },
            None => return Ok(HandlerAction::None),
        };
        let sr = match StatusReport::decode(rx.payload) {
            Ok(s) => s,
            Err(_) => return self.abort(sessions, kind, ScFailReason::Decode),
        };
        let success = sr.general_code == GeneralCode::Success
            && sr.proto_code == ScStatusCode::SessionEstablishmentSuccess as u16;
        if !success {
            return self.abort(sessions, kind, ScFailReason::StatusReport(sr.proto_code));
        }
        match kind {
            HandshakeKindTag::Pase => self.pase_commit(sessions, now_ms),
            HandshakeKindTag::Case => self.case_commit(sessions, now_ms),
        }
    }

    /// PASE 成功時のセッション鍵導出と commit。
    fn pase_commit<const S: usize>(
        &mut self,
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let h = self.hs.take().ok_or(Error::InvalidState)?;
        let reserved = h.reserved;
        let p = match h.kind {
            InitiatorKind::Pase(p) => p,
            _ => {
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };
        let confirm = match p.confirm {
            Some(c) => c,
            None => {
                sessions.remove(reserved);
                return self.fail(HandshakeKindTag::Pase, ScFailReason::Crypto);
            }
        };
        let mut keys = Zeroizing::new([0u8; SESSION_KEYS_LEN]);
        if self
            .crypto
            .hkdf_sha256(
                &[],
                confirm.shared_secret(),
                SPAKE2P_SESSION_KEYS_INFO,
                &mut keys[..],
            )
            .is_err()
        {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Pase, ScFailReason::Crypto);
        }
        // initiator: enc = I2R, dec = R2I。
        let mut enc_key = [0u8; KEY_LEN];
        let mut dec_key = [0u8; KEY_LEN];
        let mut att = [0u8; KEY_LEN];
        enc_key.copy_from_slice(&keys[0..KEY_LEN]);
        dec_key.copy_from_slice(&keys[KEY_LEN..2 * KEY_LEN]);
        att.copy_from_slice(&keys[2 * KEY_LEN..3 * KEY_LEN]);

        let peer_addr = match sessions.get(reserved) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };
        let tx_ctr_start = self.initial_tx_ctr();
        let init = SessionInit {
            peer_addr,
            local_node_id: 0,
            peer_node_id: None,
            peer_session_id: p.peer_ssid,
            tx_ctr_start,
            rx_ctr_start: 0,
            mode: SessionMode::Pase { fabric_idx: 0 },
            enc_key,
            dec_key,
            att_challenge: att,
        };
        if sessions.commit(reserved, init, now_ms).is_err() {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Pase, ScFailReason::Crypto);
        }
        self.event = Some(ScEvent::PaseEstablished { session: reserved });
        Ok(HandlerAction::None)
    }

    /// CASE 成功時のセッション鍵導出と commit。
    fn case_commit<const S: usize>(
        &mut self,
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let h = self.hs.take().ok_or(Error::InvalidState)?;
        let reserved = h.reserved;
        let c = match h.kind {
            InitiatorKind::Case(c) => c,
            _ => {
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };
        let fabric_material = self
            .creds
            .get(c.fabric_idx)
            .map(|f| (*f.ipk(), f.node_id()));
        let (ipk, local_node_id) = match fabric_material {
            Some(v) => v,
            None => {
                sessions.remove(reserved);
                return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
            }
        };
        // TT(Σ1‖Σ2‖Σ3)を確定。
        let mut tt_s3 = [0u8; common::TT_HASH_LEN];
        c.tt.finish(&mut tt_s3);
        let mut keys = Zeroizing::new([0u8; common::CASE_SESSION_KEYS_LEN]);
        if common::derive_ipk_tt_keyed(
            self.crypto,
            &ipk,
            &tt_s3,
            common::CASE_SESSION_KEYS_INFO,
            &c.shared_secret,
            &mut keys[..],
        )
        .is_err()
        {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
        }
        // initiator: enc = I2R, dec = R2I。
        let mut enc_key = [0u8; KEY_LEN];
        let mut dec_key = [0u8; KEY_LEN];
        let mut att = [0u8; KEY_LEN];
        enc_key.copy_from_slice(&keys[0..KEY_LEN]);
        dec_key.copy_from_slice(&keys[KEY_LEN..2 * KEY_LEN]);
        att.copy_from_slice(&keys[2 * KEY_LEN..3 * KEY_LEN]);

        let peer_addr = match sessions.get(reserved) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };
        let tx_ctr_start = self.initial_tx_ctr();
        let init = SessionInit {
            peer_addr,
            local_node_id,
            peer_node_id: Some(c.peer_node_id),
            peer_session_id: c.peer_ssid,
            tx_ctr_start,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: c.fabric_idx,
            },
            enc_key,
            dec_key,
            att_challenge: att,
        };
        if sessions.commit(reserved, init, now_ms).is_err() {
            sessions.remove(reserved);
            return self.fail(HandshakeKindTag::Case, ScFailReason::Crypto);
        }
        // フル CASE 成功: TBE2 から取り出した相手採番の resumptionID + ECDH SharedSecret を
        // resumption レコードとして保存する(§7.4)。
        if let Some(rid) = c.peer_resumption_id {
            self.resumptions
                .save(c.fabric_idx, c.peer_node_id, &rid, &c.shared_secret);
        }
        self.event = Some(ScEvent::CaseEstablished {
            session: reserved,
            resumed: false,
        });
        Ok(HandlerAction::None)
    }

    /// slot は既に取り出し済み(commit 経路)で、イベントだけ積む失敗ヘルパ。
    fn fail(&mut self, kind: HandshakeKindTag, reason: ScFailReason) -> Result<HandlerAction> {
        self.event = Some(ScEvent::Failed { kind, reason });
        Ok(HandlerAction::None)
    }
}

impl<C: Crypto, R: Rng, F: FabricStore + NocResolver> ProtocolHandler for ScInitiator<'_, C, R, F> {
    const PROTOCOL_ID: u16 = PROTO_ID_SECURE_CHANNEL;

    fn handle<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        // 自分の進行中 exchange への応答のみを処理する(それ以外は silent drop)。
        match &self.hs {
            Some(h) if h.exchange == rx.exchange => {}
            _ => return Ok(HandlerAction::None),
        }
        match OpCode::from_u8(rx.header.proto_opcode)? {
            OpCode::PbkdfParamResponse => self.pase_on_resp(rx, tx, sessions),
            OpCode::PasePake2 => self.pase_on_pake2(rx, tx, sessions),
            OpCode::CaseSigma2 => self.case_on_sigma2(rx, tx, sessions),
            OpCode::CaseSigma2Resume => self.case_on_sigma2_resume(rx, tx, sessions, now_ms),
            OpCode::StatusReport => self.on_status(rx, sessions, now_ms),
            // initiator にその他 opcode(Request 系)は届かない。
            _ => Err(Error::InvalidState),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
