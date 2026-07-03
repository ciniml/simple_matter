//! PASE / CASE responder(デバイス側)の同期状態機械。
//!
//! `docs/design/secure-channel.md` §6/§7 に基づく。
//!
//! - **PASE**: PBKDFParamRequest → PBKDFParamResponse → PASEPake1 → PASEPake2 →
//!   PASEPake3 → 成功 StatusReport の 3 往復。
//! - **CASE**: Sigma1 → Sigma2 → Sigma3 → 成功 StatusReport の 2 往復。
//!
//! いずれも `ExchangeId` をキーとする [`HandshakePool`] の slot で往復のまたぎを表現する
//! Mealy machine として実装する(設計「SecureChannel ハンドラに統合」)。CASE のプロトコル
//! プリミティブ(TLV codec・鍵導出・TBE/TBS)は [`super::case::responder`] に、fabric への
//! 依存は [`super::case::creds`] の 3 trait([`FabricStore`]/[`Fabric`]/[`NocResolver`])に
//! 隔離する(依存性逆転、§8)。

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::crypto::spake2p::{compute_verifier, Spake2pVerifier, Spake2pVerifierParams};
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng, Sha256};
use crate::error::{Error, Result};
use crate::exchange::{HandlerAction, ProtocolHandler, RxMessage};
use crate::transport::session::{SessionInit, SessionManager, SessionMode};

use super::case::creds::{Fabric, FabricStore, NocResolver};
use super::case::responder as case;
use super::handshake::{CaseCtx, HandshakeKind, HandshakePool, PasePhase};
use super::pase::{
    build_context, encode_pake2, encode_pbkdf_param_resp, Pake1, Pake3, PbkdfParamReq, KEY_LEN,
    SESSION_KEYS_LEN, SPAKE2P_ITERATION_COUNT, SPAKE2P_SESSION_KEYS_INFO,
};
use super::status::{ScStatusCode, StatusReport, PROTO_ID_SECURE_CHANNEL};
use super::OpCode;

/// PASE セッション確立のタイムアウト(ミリ秒)。60s(`PASE_SESSION_EST_TIMEOUT`)。
pub const PASE_SESSION_EST_TIMEOUT_MS: u64 = 60_000;

/// Busy 応答に載せる retry-delay(ミリ秒, u16 LE)。
pub const BUSY_RETRY_DELAY_MS: u16 = 500;

/// SPAKE2+ の salt の最小/最大長(バイト)。
const SALT_MIN_LEN: usize = 16;
const SALT_MAX_LEN: usize = 32;
/// SPAKE2+ の乱数(responder_random)長。
const RANDOM_LEN: usize = 32;
/// SPAKE2+ の点(pA/pB)長。
const POINT_LEN: usize = 65;
/// SPAKE2+ の確認値(cA/cB)長。
const CONFIRM_LEN: usize = 32;

/// PASE のデバイス設定(コミッショニング設定として注入される)。
///
/// パスコードは保持せず、SPAKE2+ 検証子 (w0, L) と salt / iteration count のみを持つ
/// (§6.3)。パスコードからの導出は [`PaseConfig::from_passcode`] が
/// [`compute_verifier`] を用いて行う。
pub struct PaseConfig {
    verifier: Spake2pVerifierParams,
    salt: [u8; SALT_MAX_LEN],
    salt_len: usize,
    iterations: u32,
}

impl PaseConfig {
    /// パスコード・salt・iteration count から設定を導出する。
    ///
    /// salt は 16..=32 バイトでなければ [`Error::Crypto`]。導出失敗も同様。
    pub fn from_passcode(passcode: u32, salt: &[u8], iterations: u32) -> Result<Self> {
        let verifier = compute_verifier(passcode, salt, iterations)?;
        Self::from_verifier(verifier, salt, iterations)
    }

    /// 既に導出済みの検証子 (w0, L) と salt / iteration count から設定を作る。
    ///
    /// salt は 16..=32 バイトでなければ [`Error::Crypto`]。
    pub fn from_verifier(
        verifier: Spake2pVerifierParams,
        salt: &[u8],
        iterations: u32,
    ) -> Result<Self> {
        if !(SALT_MIN_LEN..=SALT_MAX_LEN).contains(&salt.len()) || iterations == 0 {
            return Err(Error::Crypto);
        }
        let mut buf = [0u8; SALT_MAX_LEN];
        buf[..salt.len()].copy_from_slice(salt);
        Ok(Self {
            verifier,
            salt: buf,
            salt_len: salt.len(),
            iterations,
        })
    }

    /// パスコードと salt から既定反復回数([`SPAKE2P_ITERATION_COUNT`])で設定を作る。
    pub fn from_passcode_default(passcode: u32, salt: &[u8]) -> Result<Self> {
        Self::from_passcode(passcode, salt, SPAKE2P_ITERATION_COUNT)
    }

    fn salt(&self) -> &[u8] {
        &self.salt[..self.salt_len]
    }
}

/// Secure Channel(Protocol ID 0x0000)ハンドラ。PASE / CASE responder を内包する。
///
/// `H` は同時ハンドシェイク数の上限(既定 1)。crypto は参照で保持し、rng は
/// 値で保持する(responder_random / エフェメラル鍵 / SPAKE2+ の y スカラ生成に用いる)。
/// `F` は CASE が触る fabric 面([`FabricStore`] + [`NocResolver`])。PASE だけで使う場合は
/// [`super::case::creds::NoFabrics`] を渡す(CASE 経路は `NoSharedTrustRoots` で無効化)。
pub struct SecureChannel<'c, C: Crypto, R: Rng, F, const H: usize> {
    crypto: &'c C,
    rng: R,
    config: PaseConfig,
    fabrics: F,
    pool: HandshakePool<H, C::Sha256>,
}

impl<'c, C: Crypto, R: Rng, F, const H: usize> SecureChannel<'c, C, R, F, H> {
    /// crypto・rng・PASE 設定・fabric 面を与えてハンドラを生成する。
    pub fn new(crypto: &'c C, rng: R, config: PaseConfig, fabrics: F) -> Self {
        Self {
            crypto,
            rng,
            config,
            fabrics,
            pool: HandshakePool::new(),
        }
    }

    /// 進行中ハンドシェイク数を返す。
    pub fn handshake_count(&self) -> usize {
        self.pool.len()
    }

    /// 期限切れ(60s 超過)のハンドシェイク slot を回収し、予約セッションを解放する。
    ///
    /// 統合層が MRP の poll とは独立に定期呼び出しする(§6.4)。回収した slot 数を返す。
    pub fn on_tick<const S: usize>(
        &mut self,
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> usize {
        let mut n = 0;
        while let Some(slot) = self.pool.take_expired(now_ms, PASE_SESSION_EST_TIMEOUT_MS) {
            sessions.remove(slot.reserved());
            n += 1;
        }
        n
    }

    /// Busy StatusReport を `tx` に書き、終端アクションを返す(§6.4)。
    fn busy(&self, tx: &mut [u8]) -> Result<HandlerAction> {
        let delay = BUSY_RETRY_DELAY_MS.to_le_bytes();
        self.terminal(tx, ScStatusCode::Busy, &delay)
    }

    /// 指定コードの StatusReport を `tx` に書き、終端([`HandlerAction::Close`])を返す。
    fn terminal(
        &self,
        tx: &mut [u8],
        code: ScStatusCode,
        proto_data: &[u8],
    ) -> Result<HandlerAction> {
        let sr = StatusReport::new(code, proto_data);
        let len = sr.encode(tx)?;
        Ok(HandlerAction::Close {
            opcode: OpCode::StatusReport as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: code.reliable(),
            len,
        })
    }

    /// PBKDFParamRequest を受けて新規ハンドシェイクを開く(§6.1)。
    fn pase_open<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let req = PbkdfParamReq::decode(rx.payload)?;

        // passcode_id != 0 は未対応。
        if req.passcode_id != 0 {
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        // 同時ハンドシェイク上限超過 → Busy(容量判定に一本化、§6.4)。
        if self.pool.is_full() {
            return self.busy(tx);
        }

        // ハンドシェイクを運ぶ unsecured セッションの peer アドレス。
        let peer_addr = match sessions.get(rx.exchange.session()) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };

        // セッション slot を予約(容量先取り、§6.5)。枯渇なら Busy。
        let reserved = match sessions.reserve(peer_addr, now_ms) {
            Ok(id) => id,
            Err(_) => return self.busy(tx),
        };
        let responder_ssid = match sessions.get(reserved) {
            Some(s) => s.local_session_id(),
            None => {
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };

        // responder_random を生成。
        let mut responder_random = [0u8; RANDOM_LEN];
        if self.rng.fill_bytes(&mut responder_random).is_err() {
            sessions.remove(reserved);
            return Err(Error::Crypto);
        }

        // PBKDFParamResponse を tx に直列化する。
        let params = (!req.has_params).then_some((self.config.iterations, self.config.salt()));
        let resp_len = match encode_pbkdf_param_resp(
            tx,
            req.initiator_random,
            &responder_random,
            responder_ssid,
            params,
        ) {
            Ok(n) => n,
            Err(e) => {
                sessions.remove(reserved);
                return Err(e);
            }
        };

        // コンテキスト = SHA256(prefix || request || response)。
        let mut context = [0u8; 32];
        build_context(self.crypto, rx.payload, &tx[..resp_len], &mut context);

        // slot を確保(容量は上で確認済み)。
        if self
            .pool
            .open(
                rx.exchange,
                reserved,
                req.initiator_ssid,
                now_ms,
                HandshakeKind::Pase(PasePhase::PbkdfSent { context }),
            )
            .is_err()
        {
            sessions.remove(reserved);
            return self.busy(tx);
        }

        Ok(HandlerAction::Respond {
            opcode: OpCode::PbkdfParamResponse as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len: resp_len,
        })
    }

    /// PASEPake1(pA)を受けて PASEPake2(pB, cB)を返す(§6.1)。
    fn pase_pake1<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
    ) -> Result<HandlerAction> {
        let pake1 = Pake1::decode(rx.payload)?;
        let pa: &[u8; POINT_LEN] = pake1.pa.try_into().map_err(|_| Error::Decode)?;

        // slot と現在 phase を確認(PbkdfSent のみ受理)。context をコピーして取り出す。
        let context = {
            let slot = self.pool.get_mut(rx.exchange).ok_or(Error::InvalidState)?;
            match slot.pase_phase_mut() {
                Some(PasePhase::PbkdfSent { context }) => *context,
                _ => return Err(Error::InvalidState),
            }
        };

        // SPAKE2+ verifier 計算。不正な pA は InvalidParameter で終端し予約を解放。
        let (verifier, pb) =
            match Spake2pVerifier::respond(&mut self.rng, &context, &self.config.verifier, pa) {
                Ok(v) => v,
                Err(_) => {
                    if let Some(slot) = self.pool.close(rx.exchange) {
                        sessions.remove(slot.reserved());
                    }
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };

        let mut cb = [0u8; CONFIRM_LEN];
        cb.copy_from_slice(verifier.confirmation_b());
        let len = encode_pake2(tx, &pb, &cb)?;

        // phase を Pake2Sent へ。
        if let Some(slot) = self.pool.get_mut(rx.exchange) {
            slot.set_pase_phase(PasePhase::Pake2Sent { verifier });
        }

        Ok(HandlerAction::Respond {
            opcode: OpCode::PasePake2 as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len,
        })
    }

    /// PASEPake3(cA)を受けて検証し、成功なら鍵を commit する(§6.1/§6.5)。
    fn pase_pake3<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let pake3 = Pake3::decode(rx.payload)?;
        let ca: &[u8; CONFIRM_LEN] = pake3.ca.try_into().map_err(|_| Error::Decode)?;

        // slot を取り出して除去(終端 or 失敗のいずれでも slot は解放する)。
        let slot = self.pool.close(rx.exchange).ok_or(Error::InvalidState)?;
        let reserved = slot.reserved();
        let peer_session_id = slot.peer_session_id();
        let verifier = match slot.into_verifier() {
            Some(v) => v,
            None => {
                // Pake2Sent 以外での Pake3 = 状態違反。予約を解放して drop。
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };

        // cA 検証。失敗は InvalidParameter + reserve 解放。
        if verifier.verify(ca).is_err() {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        // Ke → HKDF("SessionKeys", 48) → I2R(dec)/R2I(enc)/AttestationChallenge。
        let mut keys = [0u8; SESSION_KEYS_LEN];
        if self
            .crypto
            .hkdf_sha256(
                &[],
                verifier.shared_secret(),
                SPAKE2P_SESSION_KEYS_INFO,
                &mut keys,
            )
            .is_err()
        {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }
        let mut dec_key = [0u8; KEY_LEN];
        let mut enc_key = [0u8; KEY_LEN];
        let mut att = [0u8; KEY_LEN];
        dec_key.copy_from_slice(&keys[0..KEY_LEN]);
        enc_key.copy_from_slice(&keys[KEY_LEN..2 * KEY_LEN]);
        att.copy_from_slice(&keys[2 * KEY_LEN..3 * KEY_LEN]);

        let peer_addr = match sessions.get(reserved) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };

        let init = SessionInit {
            peer_addr,
            local_node_id: 0,
            peer_node_id: None,
            peer_session_id,
            tx_ctr_start: 0,
            rx_ctr_start: 0,
            mode: SessionMode::Pase { fabric_idx: 0 },
            enc_key,
            dec_key,
            att_challenge: att,
        };

        // 成功 StatusReport を送る前に commit する(§3.3 の順序)。
        if sessions.commit(reserved, init, now_ms).is_err() {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        self.terminal(tx, ScStatusCode::SessionEstablishmentSuccess, &[])
    }
}

/// CASE responder(§7)。fabric 面への依存を [`FabricStore`] + [`NocResolver`] に隔離する。
impl<C: Crypto, R: Rng, F: FabricStore + NocResolver, const H: usize>
    SecureChannel<'_, C, R, F, H>
{
    /// destination identifier に一致する fabric index を全 fabric から総当りで探す(§7.3)。
    ///
    /// `destinationMessage = initiatorRandom ‖ rootPublicKey(65) ‖ fabricId(LE 8) ‖
    /// nodeId(LE 8)`、`destinationIdentifier = HMAC-SHA256(key = IPK, destinationMessage)`。
    /// [`FabricStore::iter`] と [`Fabric`] アクセサのみを用い、具象 `FabricTable` に依存しない
    /// (設計 §8 の trait 境界を保つ。乖離ではなく trait への正規化)。
    fn find_fabric_by_dest(
        &self,
        crypto: &C,
        initiator_random: &[u8],
        dest_id: &[u8],
    ) -> Option<NonZeroU8> {
        if dest_id.len() != case::CASE_DEST_ID_LEN || initiator_random.len() > case::CASE_RANDOM_LEN
        {
            return None;
        }
        const MSG_MAX: usize = case::CASE_RANDOM_LEN + case::CASE_EPH_PUBLIC_KEY_LEN + 8 + 8;
        for f in self.fabrics.iter() {
            let mut msg = [0u8; MSG_MAX];
            let mut off = 0;
            msg[off..off + initiator_random.len()].copy_from_slice(initiator_random);
            off += initiator_random.len();
            msg[off..off + case::CASE_EPH_PUBLIC_KEY_LEN].copy_from_slice(f.root_public_key());
            off += case::CASE_EPH_PUBLIC_KEY_LEN;
            msg[off..off + 8].copy_from_slice(&f.fabric_id().to_le_bytes());
            off += 8;
            msg[off..off + 8].copy_from_slice(&f.node_id().to_le_bytes());
            off += 8;
            let mut out = [0u8; case::CASE_DEST_ID_LEN];
            if crypto.hmac_sha256(f.ipk(), &msg[..off], &mut out).is_ok() && out[..] == *dest_id {
                return Some(f.fabric_index());
            }
        }
        None
    }

    /// CASE Sigma1 を受けて Sigma2 を返す(§7.1)。
    fn case_open<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let crypto = self.crypto;

        let sigma1 = match case::Sigma1::decode(rx.payload) {
            Ok(s) => s,
            Err(_) => return self.terminal(tx, ScStatusCode::InvalidParameter, &[]),
        };

        // resumptionID / initiatorResumeMIC は両方存在か両方欠落でなければ不正(Matter 仕様)。
        // 存在する場合も resumption は未対応でフルハンドシェイクへフォールバックする。
        if sigma1.has_resumption_id != sigma1.has_resume_mic {
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        let peer_pub: &[u8; case::CASE_EPH_PUBLIC_KEY_LEN] =
            match sigma1.initiator_eph_pub_key.try_into() {
                Ok(p) => p,
                Err(_) => return self.terminal(tx, ScStatusCode::InvalidParameter, &[]),
            };

        // 同時ハンドシェイク上限超過 → Busy。
        if self.pool.is_full() {
            return self.busy(tx);
        }

        // destination-id → fabric 特定。一致なしは NoSharedTrustRoots。
        let fabric_index = match self.find_fabric_by_dest(
            crypto,
            sigma1.initiator_random,
            sigma1.destination_id,
        ) {
            Some(i) => i,
            None => return self.terminal(tx, ScStatusCode::NoSharedTrustRoots, &[]),
        };

        let peer_addr = match sessions.get(rx.exchange.session()) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };

        // セッション slot を予約。
        let reserved = match sessions.reserve(peer_addr, now_ms) {
            Ok(id) => id,
            Err(_) => return self.busy(tx),
        };
        let responder_ssid = match sessions.get(reserved) {
            Some(s) => s.local_session_id(),
            None => {
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };

        // エフェメラル鍵ペア + ECDH。
        let keypair = match crypto.p256_generate_keypair() {
            Ok(k) => k,
            Err(_) => {
                sessions.remove(reserved);
                return Err(Error::Crypto);
            }
        };
        let our_pub = keypair.public_key().to_bytes();
        let peer_pub_obj = match crypto.p256_public_key_from_bytes(peer_pub) {
            Ok(k) => k,
            Err(_) => {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }
        };
        let mut shared = Zeroizing::new([0u8; case::SHARED_SECRET_LEN]);
        if keypair.ecdh(&peer_pub_obj, &mut shared).is_err() {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        // responder_random / resumption_id(resumption 未対応だが TBE2 に載せる 16B)。
        let mut responder_random = [0u8; case::CASE_RANDOM_LEN];
        let mut resumption_id = [0u8; case::CASE_RESUMPTION_ID_LEN];
        if self.rng.fill_bytes(&mut responder_random).is_err()
            || self.rng.fill_bytes(&mut resumption_id).is_err()
        {
            sessions.remove(reserved);
            return Err(Error::Crypto);
        }

        // トランスクリプト: TT ← Sigma1 生バイト。Sigma1 のみの TT ハッシュを控える(S2K 用)。
        let mut tt = crypto.sha256();
        tt.update(rx.payload);
        let mut tt_hash_s1 = [0u8; case::TT_HASH_LEN];
        tt.clone().finish(&mut tt_hash_s1);

        // Sigma2 の encrypted2(TBEData2)を fabric 素材で組み立てる(fabric 借用は限定)。
        let mut enc2 = [0u8; case::CASE_SCRATCH_LEN];
        let enc2_len: usize;
        {
            let fabric = match self.fabrics.get(fabric_index) {
                Some(f) => f,
                None => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::NoSharedTrustRoots, &[]);
                }
            };
            let ipk = *fabric.ipk();

            let mut s2k = Zeroizing::new([0u8; case::KEY_LEN]);
            if case::derive_sigma2_key(
                crypto,
                &ipk,
                &responder_random,
                &our_pub,
                &tt_hash_s1,
                &shared,
                &mut s2k,
            )
            .is_err()
            {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }

            // TBSData2 署名(responderNOC/ICAC/responderEph/initiatorEph)。
            let mut sig = [0u8; case::SIGNATURE_LEN];
            {
                let mut scratch = [0u8; case::CASE_SCRATCH_LEN];
                let tbs_len = match case::encode_tbs(
                    &mut scratch,
                    fabric.noc(),
                    fabric.icac(),
                    &our_pub,
                    peer_pub,
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        sessions.remove(reserved);
                        return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                    }
                };
                if fabric.sign(&scratch[..tbs_len], &mut sig).is_err() {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            }

            enc2_len = match case::encrypt_tbe2(
                crypto,
                &s2k,
                fabric.noc(),
                fabric.icac(),
                &sig,
                &resumption_id,
                &mut enc2,
            ) {
                Ok(n) => n,
                Err(_) => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };
        }

        // Sigma2 外枠を tx に直列化。
        let sigma2_len = match case::encode_sigma2(
            tx,
            &responder_random,
            responder_ssid,
            &our_pub,
            &enc2[..enc2_len],
        ) {
            Ok(n) => n,
            Err(_) => {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }
        };

        // Sigma2 生バイトを TT に畳む(§7.1)。
        tt.update(&tx[..sigma2_len]);

        // CASE 中間状態を slot に格納。
        let ctx = CaseCtx {
            fabric_index,
            shared_secret: shared,
            our_pub_key: our_pub,
            peer_pub_key: *peer_pub,
            tt,
        };
        if self
            .pool
            .open(
                rx.exchange,
                reserved,
                sigma1.initiator_sessid,
                now_ms,
                HandshakeKind::Case(ctx),
            )
            .is_err()
        {
            sessions.remove(reserved);
            return self.busy(tx);
        }

        Ok(HandlerAction::Respond {
            opcode: OpCode::CaseSigma2 as u8,
            proto_id: PROTO_ID_SECURE_CHANNEL,
            reliable: true,
            len: sigma2_len,
        })
    }

    /// CASE Sigma3 を受けて検証し、成功なら CASE セッションを commit する(§7.1)。
    fn case_step<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        let crypto = self.crypto;

        // slot を取り出す(成功・失敗いずれでも解放する)。
        let slot = match self.pool.close(rx.exchange) {
            Some(s) => s,
            None => return Err(Error::InvalidState),
        };
        let reserved = slot.reserved();
        let peer_session_id = slot.peer_session_id();
        let ctx = match slot.into_case() {
            Some(c) => c,
            None => {
                // CASE slot でない = 状態違反。
                sessions.remove(reserved);
                return Err(Error::InvalidState);
            }
        };

        let encrypted3 = match case::decode_sigma3(rx.payload) {
            Ok(e) => e,
            Err(_) => {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }
        };

        let (ipk, local_node_id) = match self.fabrics.get(ctx.fabric_index) {
            Some(f) => (*f.ipk(), f.node_id()),
            None => {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::NoSharedTrustRoots, &[]);
            }
        };

        // S3K = HKDF(IPK‖TThash(Σ1..Σ2), "Sigma3")。TT は消費せず clone して覗く。
        let mut tt = ctx.tt;
        let mut tt_hash_s2 = [0u8; case::TT_HASH_LEN];
        tt.clone().finish(&mut tt_hash_s2);
        let mut s3k = Zeroizing::new([0u8; case::KEY_LEN]);
        if case::derive_ipk_tt_keyed(
            crypto,
            &ipk,
            &tt_hash_s2,
            case::SIGMA3_KEY_INFO,
            &ctx.shared_secret,
            &mut s3k[..],
        )
        .is_err()
        {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        // TBEData3 をスタック上のスクラッチへ複製して in-place 復号(§7.2)。
        let mut scratch = [0u8; case::CASE_SCRATCH_LEN];
        if encrypted3.len() > scratch.len() {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }
        scratch[..encrypted3.len()].copy_from_slice(encrypted3);
        let pt_len = match case::decrypt_tbe3(crypto, &s3k, &mut scratch[..encrypted3.len()]) {
            Ok(pt) => pt.len(),
            Err(_) => {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }
        };

        let mut dec_key = [0u8; KEY_LEN];
        let mut enc_key = [0u8; KEY_LEN];
        let mut att = [0u8; KEY_LEN];
        let peer_node_id;
        {
            let (noc, icac, signature) = match case::decode_tbe_certs(&scratch[..pt_len]) {
                Ok(v) => v,
                Err(_) => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };

            // 相手 NOC チェーン検証(fabric 整合含む)。
            let identity = match self.fabrics.verify_peer_noc(ctx.fabric_index, noc, icac) {
                Ok(id) => id,
                Err(_) => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };

            // TBSData3 署名検証(sender = initiatorEph, receiver = responderEph)。
            let sig: &[u8; case::SIGNATURE_LEN] = match signature.try_into() {
                Ok(s) => s,
                Err(_) => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };
            let mut tbs = [0u8; case::CASE_SCRATCH_LEN];
            let tbs_len =
                match case::encode_tbs(&mut tbs, noc, icac, &ctx.peer_pub_key, &ctx.our_pub_key) {
                    Ok(n) => n,
                    Err(_) => {
                        sessions.remove(reserved);
                        return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                    }
                };
            let pub_key = match crypto.p256_public_key_from_bytes(identity.public_key()) {
                Ok(k) => k,
                Err(_) => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            };
            match pub_key.verify(&tbs[..tbs_len], sig) {
                Ok(true) => {}
                _ => {
                    sessions.remove(reserved);
                    return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
                }
            }
            peer_node_id = identity.node_id();

            // 全検証通過後に初めて Sigma3 を TT に畳み、SEKeys を導出する(§7.1)。
            tt.update(rx.payload);
            let mut tt_hash_s3 = [0u8; case::TT_HASH_LEN];
            tt.finish(&mut tt_hash_s3);
            let mut keys = Zeroizing::new([0u8; case::CASE_SESSION_KEYS_LEN]);
            if case::derive_ipk_tt_keyed(
                crypto,
                &ipk,
                &tt_hash_s3,
                case::CASE_SESSION_KEYS_INFO,
                &ctx.shared_secret,
                &mut keys[..],
            )
            .is_err()
            {
                sessions.remove(reserved);
                return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
            }
            // responder: I2R→dec, R2I→enc, att。
            dec_key.copy_from_slice(&keys[0..KEY_LEN]);
            enc_key.copy_from_slice(&keys[KEY_LEN..2 * KEY_LEN]);
            att.copy_from_slice(&keys[2 * KEY_LEN..3 * KEY_LEN]);
        }

        let peer_addr = match sessions.get(reserved) {
            Some(s) => s.peer_addr(),
            None => return Err(Error::InvalidState),
        };
        let init = SessionInit {
            peer_addr,
            local_node_id,
            peer_node_id: Some(peer_node_id),
            peer_session_id,
            tx_ctr_start: 0,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: ctx.fabric_index,
            },
            enc_key,
            dec_key,
            att_challenge: att,
        };

        // 成功 StatusReport を送る前に commit する(§3.3 の順序)。
        if sessions.commit(reserved, init, now_ms).is_err() {
            sessions.remove(reserved);
            return self.terminal(tx, ScStatusCode::InvalidParameter, &[]);
        }

        self.terminal(tx, ScStatusCode::SessionEstablishmentSuccess, &[])
    }
}

impl<C: Crypto, R: Rng, F: FabricStore + NocResolver, const H: usize> ProtocolHandler
    for SecureChannel<'_, C, R, F, H>
{
    const PROTOCOL_ID: u16 = PROTO_ID_SECURE_CHANNEL;

    fn handle<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        match OpCode::from_u8(rx.header.proto_opcode)? {
            OpCode::PbkdfParamRequest => self.pase_open(rx, tx, sessions, now_ms),
            OpCode::PasePake1 => self.pase_pake1(rx, tx, sessions),
            OpCode::PasePake3 => self.pase_pake3(rx, tx, sessions, now_ms),
            OpCode::CaseSigma1 => self.case_open(rx, tx, sessions, now_ms),
            OpCode::CaseSigma3 => self.case_step(rx, tx, sessions, now_ms),
            OpCode::StatusReport => {
                // 相手からの中断: slot を解放して黙って終える(reserve は on_tick で回収)。
                if let Some(slot) = self.pool.close(rx.exchange) {
                    sessions.remove(slot.reserved());
                }
                Ok(HandlerAction::None)
            }
            // group / その他は本ピースではスコープ外(silent drop)。
            _ => Err(Error::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::BufferPool;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::spake2p::Spake2pProver;
    use crate::error::Result as CrateResult;
    use crate::exchange::{ExchangeManager, Outgoing, ProtocolMux, SendTiming};
    use crate::sc::pase::{build_context, SPAKE2P_SESSION_KEYS_INFO};
    use crate::sc::status::{GeneralCode, ScStatusCode, StatusReport};
    use crate::tlv::{TlvReader, TlvTag, TlvWriter};
    use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, PayloadHeader, SecFlags};
    use crate::transport::net::PeerAddr;
    use crate::transport::secure::SecureCodec;
    use crate::transport::util::WriteBuf;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    const PASSCODE: u32 = 20202021;
    const ITERATIONS: u32 = 1000;
    const SALT: [u8; 16] = [
        0x53, 0x50, 0x41, 0x4b, 0x45, 0x32, 0x50, 0x20, 0x4b, 0x65, 0x79, 0x20, 0x53, 0x61, 0x6c,
        0x74,
    ];
    const EXCH_ID: u16 = 0x33;
    const NOW: u64 = 1000;

    /// 決定的な擬似乱数生成器(LCG)。暗号用途ではない。
    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> CrateResult<()> {
            for b in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    fn crypto() -> RustCrypto<SeqRng> {
        RustCrypto::new(SeqRng(0xC0FF_EE00_1234_5678))
    }

    fn peer() -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            5540,
        ))
    }

    /// IM プレースホルダハンドラ(常に None を返す)。
    struct ImPlaceholder;
    impl ProtocolHandler for ImPlaceholder {
        const PROTOCOL_ID: u16 = 0x0001;
        fn handle<const S: usize>(
            &mut self,
            _rx: &RxMessage<'_>,
            _tx: &mut [u8],
            _sessions: &mut SessionManager<S>,
            _now_ms: u64,
        ) -> Result<HandlerAction> {
            Ok(HandlerAction::None)
        }
    }

    use crate::sc::case::creds::NoFabrics;

    type Mux<'c> =
        ProtocolMux<SecureChannel<'c, RustCrypto<SeqRng>, SeqRng, NoFabrics, 1>, ImPlaceholder>;

    /// commissioner の平文ワイヤメッセージを組み立て、長さを返す。
    fn build_msg<C: Crypto>(
        crypto: &C,
        opcode: u8,
        payload: &[u8],
        ctr: u32,
        ack: Option<u32>,
        out: &mut [u8],
    ) -> usize {
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
            proto_opcode: opcode,
            exch_id: EXCH_ID,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: ack,
        };
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 512];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(payload).unwrap();
        SecureCodec::encrypt(crypto, None, &pkt, &phdr, 0, &mut w).unwrap();
        let n = w.len();
        out[..n].copy_from_slice(w.as_slice());
        n
    }

    fn build_pbkdf_req(initiator_random: &[u8; 32], ssid: u16, out: &mut [u8]) -> usize {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), initiator_random)
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(2), ssid).unwrap();
        w.write_u16(&TlvTag::ContextSpecific(3), 0).unwrap();
        w.write_bool(&TlvTag::ContextSpecific(4), false).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    /// 単一 context-1 バイト列(Pake1/Pake3)を作る。
    fn build_single(field: &[u8], out: &mut [u8]) -> usize {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), field).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    fn decode_pake2(payload: &[u8]) -> ([u8; 65], [u8; 32]) {
        let mut r = TlvReader::new(payload);
        r.enter_container().unwrap();
        let pb = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
        let cb = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
        (pb.try_into().unwrap(), cb.try_into().unwrap())
    }

    fn resp_ssid(payload: &[u8]) -> u16 {
        let mut r = TlvReader::new(payload);
        r.enter_container().unwrap();
        let _ = r.read_next().unwrap();
        let _ = r.read_next().unwrap();
        r.read_next().unwrap().unwrap().value.as_unsigned().unwrap() as u16
    }

    fn action_len(a: HandlerAction) -> (u8, usize, bool) {
        match a {
            HandlerAction::Respond {
                opcode,
                reliable,
                len,
                ..
            }
            | HandlerAction::Close {
                opcode,
                reliable,
                len,
                ..
            } => (opcode, len, reliable),
            HandlerAction::None => panic!("expected Respond/Close"),
        }
    }

    fn setup<'c>(
        crypto: &'c RustCrypto<SeqRng>,
    ) -> (
        ExchangeManager<Mux<'c>, 4>,
        SessionManager<4>,
        crate::transport::session::SessionId,
    ) {
        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let sc = SecureChannel::new(crypto, SeqRng(0xABCD_0001), config, NoFabrics);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mgr: ExchangeManager<Mux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        let unsecured = sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();
        (mgr, sessions, unsecured)
    }

    /// PASE フルハンドシェイク: 完了後に暗号セッションが commit され、導出鍵
    /// I2R/R2I が commissioner(prover)側と一致することを確認する。
    #[test]
    fn full_pase_handshake_derives_matching_keys() {
        let crypto = crypto();
        let (mut mgr, mut sessions, unsecured) = setup(&crypto);
        let mut pool: BufferPool<2, 512> = BufferPool::new();

        // --- 1) PBKDFParamRequest → PBKDFParamResponse ---
        let ir = [0x11u8; 32];
        let mut reqbuf = [0u8; 128];
        let rn = build_pbkdf_req(&ir, 0x1111, &mut reqbuf);
        let mut wire = [0u8; 512];
        let wn = build_msg(&crypto, 0x20, &reqbuf[..rn], 1, None, &mut wire);
        let mut tx = [0u8; 512];
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire[..wn],
                &mut tx,
            )
            .unwrap();
        assert!(r1.dispatched);
        let ex = r1.exchange.unwrap();
        let (op1, len1, rel1) = action_len(r1.action);
        assert_eq!(op1, OpCode::PbkdfParamResponse as u8);
        assert!(rel1);

        // context = SHA256(prefix || req || resp)。
        let mut resp_payload = [0u8; 512];
        resp_payload[..len1].copy_from_slice(&tx[..len1]);
        let mut context = [0u8; 32];
        build_context(&crypto, &reqbuf[..rn], &resp_payload[..len1], &mut context);
        let rssid = resp_ssid(&resp_payload[..len1]);

        // 応答を信頼送信(MRP)。使用 ctr を控える。
        let resp_ctr = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let sent1 = mgr
            .send_reliable(
                &mut sessions,
                &crypto,
                &mut pool,
                ex,
                &Outgoing {
                    proto_id: 0x0000,
                    opcode: op1,
                    payload: &resp_payload[..len1],
                },
                SendTiming {
                    now_ms: NOW,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        // --- 2) PASEPake1 → PASEPake2 ---
        let mut prover_rng = SeqRng(0x1122_3344);
        let prover =
            Spake2pProver::from_passcode(&mut prover_rng, PASSCODE, &SALT, ITERATIONS).unwrap();
        let pa = *prover.share();
        let mut p1 = [0u8; 128];
        let p1n = build_single(&pa, &mut p1);
        let mut wire2 = [0u8; 512];
        let w2n = build_msg(&crypto, 0x22, &p1[..p1n], 2, Some(resp_ctr), &mut wire2);
        let mut tx2 = [0u8; 512];
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire2[..w2n],
                &mut tx2,
            )
            .unwrap();
        // 応答の retrans バッファが piggyback ACK で解放される。
        assert_eq!(r2.freed_tx, Some(sent1.buf));
        pool.release(sent1.buf);
        let (op2, len2, _) = action_len(r2.action);
        assert_eq!(op2, OpCode::PasePake2 as u8);
        let (pb, cb) = decode_pake2(&tx2[..len2]);

        let resp_ctr2 = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let mut pake2_payload = [0u8; 512];
        pake2_payload[..len2].copy_from_slice(&tx2[..len2]);
        let sent2 = mgr
            .send_reliable(
                &mut sessions,
                &crypto,
                &mut pool,
                ex,
                &Outgoing {
                    proto_id: 0x0000,
                    opcode: op2,
                    payload: &pake2_payload[..len2],
                },
                SendTiming {
                    now_ms: NOW,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        // --- 3) PASEPake3 → 成功 StatusReport ---
        let confirm = prover.confirm(&context, &pb).unwrap();
        confirm.verify_b(&cb).unwrap(); // cB(responder)が prover 側で検証できる。
        let ca = *confirm.confirmation_a();
        let mut p3 = [0u8; 96];
        let p3n = build_single(&ca, &mut p3);
        let mut wire3 = [0u8; 512];
        let w3n = build_msg(&crypto, 0x24, &p3[..p3n], 3, Some(resp_ctr2), &mut wire3);
        let mut tx3 = [0u8; 512];
        let r3 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire3[..w3n],
                &mut tx3,
            )
            .unwrap();
        assert_eq!(r3.freed_tx, Some(sent2.buf));
        pool.release(sent2.buf);
        let (op3, len3, rel3) = action_len(r3.action);
        assert_eq!(op3, OpCode::StatusReport as u8);
        assert!(rel3);
        let sr = StatusReport::decode(&tx3[..len3]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Success);
        assert_eq!(
            sr.proto_code,
            ScStatusCode::SessionEstablishmentSuccess as u16
        );

        // --- 検証: 暗号セッションが commit され、鍵が両側で一致 ---
        let ke = confirm.shared_secret();
        let mut keys = [0u8; 48];
        crypto
            .hkdf_sha256(&[], ke, SPAKE2P_SESSION_KEYS_INFO, &mut keys)
            .unwrap();

        let committed = sessions
            .iter()
            .find(|s| s.local_session_id() == rssid)
            .expect("committed PASE session");
        assert!(matches!(
            committed.mode(),
            SessionMode::Pase { fabric_idx: 0 }
        ));
        assert_eq!(
            committed.state(),
            crate::transport::session::SlotState::Active
        );
        // responder: dec=I2R, enc=R2I。prover と一致すること。
        assert_eq!(&committed.dec_key().unwrap()[..], &keys[0..16]);
        assert_eq!(&committed.enc_key().unwrap()[..], &keys[16..32]);
        assert_eq!(&committed.att_challenge().unwrap()[..], &keys[32..48]);

        // ハンドシェイク slot は解放済み、TX プールもリークなし。
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
        assert_eq!(pool.in_use(), 0);
    }

    /// スロット満杯時の 2 本目ハンドシェイクは Busy で断られる。
    #[test]
    fn second_handshake_is_busy() {
        let crypto = crypto();
        let (mut mgr, mut sessions, _unsecured) = setup(&crypto);

        // 1 本目(exch=EXCH_ID)を開く。
        let ir = [0x22u8; 32];
        let mut reqbuf = [0u8; 128];
        let rn = build_pbkdf_req(&ir, 0x1111, &mut reqbuf);
        let mut wire = [0u8; 512];
        let wn = build_msg(&crypto, 0x20, &reqbuf[..rn], 1, None, &mut wire);
        let mut tx = [0u8; 512];
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire[..wn],
                &mut tx,
            )
            .unwrap();
        let (op1, _, _) = action_len(r1.action);
        assert_eq!(op1, OpCode::PbkdfParamResponse as u8);

        // 2 本目は別 exch。プール満杯(H=1)→ Busy。
        let mut wire2 = [0u8; 512];
        // 別 exch にするため PayloadHeader を手で組む(build_msg は EXCH_ID 固定なので別関数)。
        let w2n = build_msg_exch(&crypto, 0x20, &reqbuf[..rn], 2, 0x44, &mut wire2);
        let mut tx2 = [0u8; 512];
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire2[..w2n],
                &mut tx2,
            )
            .unwrap();
        let (op2, len2, rel2) = action_len(r2.action);
        assert_eq!(op2, OpCode::StatusReport as u8);
        assert!(!rel2, "Busy は R フラグを落とす");
        let sr = StatusReport::decode(&tx2[..len2]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Busy);
        assert_eq!(sr.proto_code, ScStatusCode::Busy as u16);
        assert_eq!(sr.proto_data, &BUSY_RETRY_DELAY_MS.to_le_bytes());
        // 2 本目は予約しない(session は unsecured + 1 本目の reserve = 2)。
        assert_eq!(sessions.len(), 2);
    }

    /// 別 exch_id 用のメッセージ組み立て。
    fn build_msg_exch<C: Crypto>(
        crypto: &C,
        opcode: u8,
        payload: &[u8],
        ctr: u32,
        exch_id: u16,
        out: &mut [u8],
    ) -> usize {
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
            proto_opcode: opcode,
            exch_id,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: None,
        };
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 512];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(payload).unwrap();
        SecureCodec::encrypt(crypto, None, &pkt, &phdr, 0, &mut w).unwrap();
        let n = w.len();
        out[..n].copy_from_slice(w.as_slice());
        n
    }

    /// Pake3 の cA 不一致で失敗 StatusReport(InvalidParameter)を返し予約を解放する。
    #[test]
    fn pake3_mismatch_fails_and_frees_reserve() {
        let crypto = crypto();
        let (mut mgr, mut sessions, unsecured) = setup(&crypto);
        let mut pool: BufferPool<2, 512> = BufferPool::new();

        let ir = [0x33u8; 32];
        let mut reqbuf = [0u8; 128];
        let rn = build_pbkdf_req(&ir, 0x1111, &mut reqbuf);
        let mut wire = [0u8; 512];
        let wn = build_msg(&crypto, 0x20, &reqbuf[..rn], 1, None, &mut wire);
        let mut tx = [0u8; 512];
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire[..wn],
                &mut tx,
            )
            .unwrap();
        let ex = r1.exchange.unwrap();
        let (op1, len1, _) = action_len(r1.action);
        let mut context = [0u8; 32];
        build_context(&crypto, &reqbuf[..rn], &tx[..len1], &mut context);
        let resp_ctr = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let mut resp_payload = [0u8; 512];
        resp_payload[..len1].copy_from_slice(&tx[..len1]);
        let sent1 = mgr
            .send_reliable(
                &mut sessions,
                &crypto,
                &mut pool,
                ex,
                &Outgoing {
                    proto_id: 0x0000,
                    opcode: op1,
                    payload: &resp_payload[..len1],
                },
                SendTiming {
                    now_ms: NOW,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        let mut prover_rng = SeqRng(0x5566_7788);
        let prover =
            Spake2pProver::from_passcode(&mut prover_rng, PASSCODE, &SALT, ITERATIONS).unwrap();
        let pa = *prover.share();
        let mut p1 = [0u8; 128];
        let p1n = build_single(&pa, &mut p1);
        let mut wire2 = [0u8; 512];
        let w2n = build_msg(&crypto, 0x22, &p1[..p1n], 2, Some(resp_ctr), &mut wire2);
        let mut tx2 = [0u8; 512];
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire2[..w2n],
                &mut tx2,
            )
            .unwrap();
        pool.release(sent1.buf);
        let (_, len2, _) = action_len(r2.action);
        let (pb, _cb) = decode_pake2(&tx2[..len2]);
        let confirm = prover.confirm(&context, &pb).unwrap();
        // cA を改竄する。
        let mut ca = *confirm.confirmation_a();
        ca[0] ^= 0x01;
        let mut p3 = [0u8; 96];
        let p3n = build_single(&ca, &mut p3);
        let resp_ctr2 = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let mut wire3 = [0u8; 512];
        let w3n = build_msg(&crypto, 0x24, &p3[..p3n], 3, Some(resp_ctr2), &mut wire3);
        let mut tx3 = [0u8; 512];
        let r3 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire3[..w3n],
                &mut tx3,
            )
            .unwrap();
        if let Some(b) = r3.freed_tx {
            pool.release(b);
        }
        let (op3, len3, rel3) = action_len(r3.action);
        assert_eq!(op3, OpCode::StatusReport as u8);
        assert!(rel3, "InvalidParameter は R フラグを立てる");
        let sr = StatusReport::decode(&tx3[..len3]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Failure);
        assert_eq!(sr.proto_code, ScStatusCode::InvalidParameter as u16);

        // 予約セッションは解放され、Pase セッションは存在しない。
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
        assert!(!sessions
            .iter()
            .any(|s| matches!(s.mode(), SessionMode::Pase { .. })));
        // 残るのは unsecured のみ。
        assert_eq!(sessions.len(), 1);
    }

    /// タイムアウトで進行中ハンドシェイクの slot と予約セッションが回収される。
    #[test]
    fn timeout_recovers_slot_and_reserve() {
        let crypto = crypto();
        let (mut mgr, mut sessions, _unsecured) = setup(&crypto);

        let ir = [0x44u8; 32];
        let mut reqbuf = [0u8; 128];
        let rn = build_pbkdf_req(&ir, 0x1111, &mut reqbuf);
        let mut wire = [0u8; 512];
        let wn = build_msg(&crypto, 0x20, &reqbuf[..rn], 1, None, &mut wire);
        let mut tx = [0u8; 512];
        let _ = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire[..wn],
                &mut tx,
            )
            .unwrap();
        assert_eq!(mgr.handler().sc.handshake_count(), 1);
        assert_eq!(sessions.len(), 2); // unsecured + reserved

        // 60s 未満では回収されない。
        let n0 = mgr
            .handler_mut()
            .sc
            .on_tick(&mut sessions, NOW + PASE_SESSION_EST_TIMEOUT_MS);
        assert_eq!(n0, 0);
        assert_eq!(mgr.handler().sc.handshake_count(), 1);

        // 60s 超過で回収され、予約セッションも消える。
        let n1 = mgr
            .handler_mut()
            .sc
            .on_tick(&mut sessions, NOW + PASE_SESSION_EST_TIMEOUT_MS + 1);
        assert_eq!(n1, 1);
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
        assert_eq!(sessions.len(), 1); // unsecured のみ
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod case_tests {
    //! CASE フルハンドシェイク結合テスト。
    //!
    //! テスト側で CASE initiator(commissioner)役の演算(Sigma1 生成 → Sigma2 処理 →
    //! Sigma3 生成)を実装し、responder(device)との Sigma1→2→3 を [`ExchangeManager`]
    //! 経由で駆動する。同一 fabric 配下に device / commissioner 双方の identity を
    //! 自己生成チェーンで用意し、両側で導出した SEKeys が一致すること・CASE セッションが
    //! [`SessionManager`] に commit されることを検証する。

    use super::*;

    use crate::buf::BufferPool;
    use crate::cert::{dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::{Crypto, P256Keypair, P256PublicKey};
    use crate::error::Result as CrateResult;
    use crate::exchange::{ExchangeManager, Outgoing, ProtocolMux, SendTiming};
    use crate::fabric::{FabricEntry, FabricTable};
    use crate::sc::case::creds::{FabricStore, NocResolver, PeerIdentity};
    use crate::sc::case::responder as case;
    use crate::sc::status::{GeneralCode, ScStatusCode, StatusReport};
    use crate::tlv::{TlvReader, TlvTag, TlvWriter};
    use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, PayloadHeader, SecFlags};
    use crate::transport::net::PeerAddr;
    use crate::transport::secure::SecureCodec;
    use crate::transport::session::{SessionInit, SessionMode, SlotState};
    use crate::transport::util::WriteBuf;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use core::num::NonZeroU8;

    const EXCH_ID: u16 = 0x55;
    const NOW: u64 = 2000;
    const NOW_SECS: u32 = 500;
    const NOT_BEFORE: u32 = 100;
    const NOT_AFTER: u32 = 100_000;
    const FABRIC_ID: u64 = 0x1122_3344_5566_7788;
    const DEVICE_NODE: u64 = 0x0000_0000_0001_0001;
    const COMM_NODE: u64 = 0x0000_0000_0002_0002;
    const IPK_EPOCH: [u8; 16] = [0x66u8; 16];

    /// 決定的な擬似乱数生成器(LCG)。暗号用途ではない。
    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> CrateResult<()> {
            for b in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    type Backend = RustCrypto<SeqRng>;

    fn crypto() -> Backend {
        RustCrypto::new(SeqRng(0xCA5E_0000_1111_2222))
    }

    fn peer() -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            5540,
        ))
    }

    /// テスト用 IM プレースホルダ(常に None)。
    struct ImPlaceholder;
    impl ProtocolHandler for ImPlaceholder {
        const PROTOCOL_ID: u16 = 0x0001;
        fn handle<const S: usize>(
            &mut self,
            _rx: &RxMessage<'_>,
            _tx: &mut [u8],
            _sessions: &mut SessionManager<S>,
            _now_ms: u64,
        ) -> Result<HandlerAction> {
            Ok(HandlerAction::None)
        }
    }

    /// FabricTable + crypto + 検証時刻を束ねた CASE 用 creds コンテキスト
    /// (`FabricStore` + `NocResolver` の両方を提供する。§8 の trait 面を単一型で満たす)。
    struct TestCreds<'a, const N: usize> {
        table: &'a FabricTable<Backend, N>,
        crypto: &'a Backend,
        now: u32,
    }

    impl<const N: usize> FabricStore for TestCreds<'_, N> {
        type Fabric<'x>
            = &'x FabricEntry<Backend>
        where
            Self: 'x;

        fn iter(&self) -> impl Iterator<Item = &FabricEntry<Backend>> {
            self.table.iter()
        }

        fn get(&self, idx: NonZeroU8) -> Option<&FabricEntry<Backend>> {
            self.table.get(idx)
        }
    }

    impl<const N: usize> NocResolver for TestCreds<'_, N> {
        fn verify_peer_noc(
            &self,
            fabric_index: NonZeroU8,
            noc_tlv: &[u8],
            icac_tlv: Option<&[u8]>,
        ) -> Result<PeerIdentity> {
            self.table
                .verify_peer_noc(self.crypto, fabric_index, noc_tlv, icac_tlv, self.now)
        }
    }

    type CaseMux<'a> =
        ProtocolMux<SecureChannel<'a, Backend, SeqRng, TestCreds<'a, 4>, 1>, ImPlaceholder>;

    // --- 自己生成証明書チェーン(cert/tests.rs の write_cert を移植) ---

    #[derive(Clone, Copy)]
    struct DnInt {
        tag: u8,
        val: u64,
    }

    fn cx(n: u8) -> TlvTag {
        TlvTag::ContextSpecific(n)
    }

    fn write_dn(w: &mut TlvWriter, ctx: u8, attrs: &[DnInt]) {
        w.start_list(&cx(ctx)).unwrap();
        for a in attrs {
            w.write_u64(&cx(a.tag), a.val).unwrap();
        }
        w.end_container().unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn write_cert(
        out: &mut [u8],
        serial: &[u8],
        issuer: &[DnInt],
        subject: &[DnInt],
        subject_pub: &[u8; 65],
        is_ca: bool,
        path_len: Option<u8>,
        key_usage_bits: u16,
        eku: &[u8],
        skid: &[u8; 20],
        akid: &[u8; 20],
        issuer_kp: &<Backend as Crypto>::Keypair,
    ) -> usize {
        let len = {
            let mut w = TlvWriter::new(out);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), serial).unwrap();
            w.write_u8(&cx(2), 1).unwrap();
            write_dn(&mut w, 3, issuer);
            w.write_u32(&cx(4), NOT_BEFORE).unwrap();
            w.write_u32(&cx(5), NOT_AFTER).unwrap();
            write_dn(&mut w, 6, subject);
            w.write_u8(&cx(7), 1).unwrap();
            w.write_u8(&cx(8), 1).unwrap();
            w.write_bytes(&cx(9), subject_pub).unwrap();
            w.start_list(&cx(10)).unwrap();
            w.start_struct(&cx(1)).unwrap();
            w.write_bool(&cx(1), is_ca).unwrap();
            if let Some(p) = path_len {
                w.write_u8(&cx(2), p).unwrap();
            }
            w.end_container().unwrap();
            w.write_u16(&cx(2), key_usage_bits).unwrap();
            if !eku.is_empty() {
                w.start_array(&cx(3)).unwrap();
                for e in eku {
                    w.write_u8(&TlvTag::Anonymous, *e).unwrap();
                }
                w.end_container().unwrap();
            }
            w.write_bytes(&cx(4), skid).unwrap();
            w.write_bytes(&cx(5), akid).unwrap();
            w.end_container().unwrap();
            w.write_bytes(&cx(11), &[0u8; 64]).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let mut tbs = [0u8; MAX_TBS_DER_LEN];
        let tbs_len = {
            let cert = MatterCert::parse(&out[..len]).unwrap();
            cert.to_be_signed(&mut tbs).unwrap()
        };
        let mut sig = [0u8; 64];
        issuer_kp.sign(&tbs[..tbs_len], &mut sig).unwrap();
        out[len - 65..len - 1].copy_from_slice(&sig);
        len
    }

    const RCAC_SKID: [u8; 20] = [0xA0; 20];
    const ICAC_SKID: [u8; 20] = [0xB0; 20];
    const NOC_SKID: [u8; 20] = [0xC0; 20];

    struct Identities {
        rcac: [u8; 400],
        rcac_len: usize,
        icac: [u8; 400],
        icac_len: usize,
        device_noc: [u8; 400],
        device_noc_len: usize,
        comm_noc: [u8; 400],
        comm_noc_len: usize,
        /// commissioner の運用鍵ペア(Sigma3 TBSData3 の署名に用いる)。
        comm_kp: <Backend as Crypto>::Keypair,
    }

    fn build_identities(crypto: &Backend) -> Identities {
        let rcac_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
        let icac_kp = crypto.p256_keypair_from_bytes(&[0x22; 32]).unwrap();
        let device_kp = crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap();
        let comm_kp = crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap();
        let rcac_pub = rcac_kp.public_key().to_bytes();
        let icac_pub = icac_kp.public_key().to_bytes();
        let device_pub = device_kp.public_key().to_bytes();
        let comm_pub = comm_kp.public_key().to_bytes();

        let rcac_dn = [
            DnInt {
                tag: dn_attr::MATTER_RCAC_ID,
                val: 0xAAAA,
            },
            DnInt {
                tag: dn_attr::MATTER_FABRIC_ID,
                val: FABRIC_ID,
            },
        ];
        let icac_dn = [
            DnInt {
                tag: dn_attr::MATTER_ICAC_ID,
                val: 0xBBBB,
            },
            DnInt {
                tag: dn_attr::MATTER_FABRIC_ID,
                val: FABRIC_ID,
            },
        ];
        let noc_dn = |node: u64| {
            [
                DnInt {
                    tag: dn_attr::MATTER_NODE_ID,
                    val: node,
                },
                DnInt {
                    tag: dn_attr::MATTER_FABRIC_ID,
                    val: FABRIC_ID,
                },
            ]
        };

        let mut ids = Identities {
            rcac: [0; 400],
            rcac_len: 0,
            icac: [0; 400],
            icac_len: 0,
            device_noc: [0; 400],
            device_noc_len: 0,
            comm_noc: [0; 400],
            comm_noc_len: 0,
            comm_kp,
        };

        ids.rcac_len = write_cert(
            &mut ids.rcac,
            &[0x00],
            &rcac_dn,
            &rcac_dn,
            &rcac_pub,
            true,
            None,
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            &[],
            &RCAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        ids.icac_len = write_cert(
            &mut ids.icac,
            &[0x01],
            &rcac_dn,
            &icac_dn,
            &icac_pub,
            true,
            Some(0),
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            &[],
            &ICAC_SKID,
            &RCAC_SKID,
            &rcac_kp,
        );
        ids.device_noc_len = write_cert(
            &mut ids.device_noc,
            &[0x02],
            &icac_dn,
            &noc_dn(DEVICE_NODE),
            &device_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &ICAC_SKID,
            &icac_kp,
        );
        ids.comm_noc_len = write_cert(
            &mut ids.comm_noc,
            &[0x03],
            &icac_dn,
            &noc_dn(COMM_NODE),
            &comm_pub,
            false,
            None,
            key_usage::DIGITAL_SIGNATURE,
            &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
            &NOC_SKID,
            &ICAC_SKID,
            &icac_kp,
        );
        ids
    }

    // --- ワイヤメッセージ組み立て(大 payload 対応) ---

    fn build_msg(
        crypto: &Backend,
        opcode: u8,
        payload: &[u8],
        ctr: u32,
        ack: Option<u32>,
    ) -> ([u8; 2048], usize) {
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
            proto_opcode: opcode,
            exch_id: EXCH_ID,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: ack,
        };
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 2048];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(payload).unwrap();
        SecureCodec::encrypt(crypto, None, &pkt, &phdr, 0, &mut w).unwrap();
        let n = w.len();
        let mut out = [0u8; 2048];
        out[..n].copy_from_slice(w.as_slice());
        (out, n)
    }

    fn action_len(a: HandlerAction) -> (u8, usize, bool) {
        match a {
            HandlerAction::Respond {
                opcode,
                reliable,
                len,
                ..
            }
            | HandlerAction::Close {
                opcode,
                reliable,
                len,
                ..
            } => (opcode, len, reliable),
            HandlerAction::None => panic!("expected Respond/Close"),
        }
    }

    /// Sigma2 の外枠を解析(責務: テスト initiator)。
    fn parse_sigma2(payload: &[u8]) -> ([u8; 32], u16, [u8; 65], usize, [u8; 1024]) {
        let mut r = TlvReader::new(payload);
        r.enter_container().unwrap();
        let rr = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
        let sid = r.read_next().unwrap().unwrap().value.as_unsigned().unwrap() as u16;
        let epk = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
        let enc = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
        let mut rr_a = [0u8; 32];
        rr_a.copy_from_slice(rr);
        let mut epk_a = [0u8; 65];
        epk_a.copy_from_slice(epk);
        let mut enc_a = [0u8; 1024];
        enc_a[..enc.len()].copy_from_slice(enc);
        (rr_a, sid, epk_a, enc.len(), enc_a)
    }

    /// 別 exch_id 用のワイヤメッセージ組み立て(同時ハンドシェイク超過テスト用)。
    fn build_msg_exch(
        crypto: &Backend,
        opcode: u8,
        payload: &[u8],
        ctr: u32,
        exch_id: u16,
    ) -> ([u8; 2048], usize) {
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
            proto_opcode: opcode,
            exch_id,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: None,
        };
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 2048];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(payload).unwrap();
        SecureCodec::encrypt(crypto, None, &pkt, &phdr, 0, &mut w).unwrap();
        let n = w.len();
        let mut out = [0u8; 2048];
        out[..n].copy_from_slice(w.as_slice());
        (out, n)
    }

    /// device の運用 IPK・root pub・node/fabric を用いて CASE フルハンドシェイクを駆動し、
    /// 両側 SEKeys 一致 + commit を検証する。
    #[test]
    fn full_case_handshake_derives_matching_keys_and_commits() {
        let crypto = crypto();
        let ids = build_identities(&crypto);

        // device の fabric をテーブルへ追加(NOC チェーンを検証して operational IPK を導出)。
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        let fabric_index = table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();

        // fabric 素材(initiator も同一 fabric なので同じ IPK / root pub を使う)。
        let (ipk, root_pub, device_node, fabric_id) = {
            let f = table.get(fabric_index).unwrap();
            (*f.ipk(), *f.root_public_key(), f.node_id(), f.fabric_id())
        };
        assert_eq!(device_node, DEVICE_NODE);
        assert_eq!(fabric_id, FABRIC_ID);

        // responder(SecureChannel + TestCreds)を構築。
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0xDEAD_0001), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        let unsecured = sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();
        let mut pool: BufferPool<2, 1600> = BufferPool::new();

        // --- initiator: Sigma1 を組み立てる ---
        let mut init_rng = SeqRng(0x1357_9BDF);
        let eph_i = crypto.p256_generate_keypair().unwrap();
        let eph_i_pub = eph_i.public_key().to_bytes();
        let mut initiator_random = [0u8; 32];
        init_rng.fill_bytes(&mut initiator_random).unwrap();
        // dest_id = HMAC(ipk, initiator_random || root_pub || fabric_id LE || device_node LE)。
        let mut dmsg = [0u8; 32 + 65 + 8 + 8];
        dmsg[..32].copy_from_slice(&initiator_random);
        dmsg[32..97].copy_from_slice(&root_pub);
        dmsg[97..105].copy_from_slice(&fabric_id.to_le_bytes());
        dmsg[105..113].copy_from_slice(&device_node.to_le_bytes());
        let mut dest_id = [0u8; 32];
        crypto.hmac_sha256(&ipk, &dmsg, &mut dest_id).unwrap();

        let mut s1_buf = [0u8; 256];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &initiator_random).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &dest_id).unwrap();
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let sigma1_bytes = {
            let mut b = [0u8; 256];
            b[..s1_len].copy_from_slice(&s1_buf[..s1_len]);
            (b, s1_len)
        };

        // --- Sigma1 → Sigma2 ---
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 1400];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        assert!(r1.dispatched);
        let ex = r1.exchange.unwrap();
        let (op1, len1, rel1) = action_len(r1.action);
        assert_eq!(op1, OpCode::CaseSigma2 as u8);
        assert!(rel1);

        let mut sigma2_bytes = [0u8; 1400];
        sigma2_bytes[..len1].copy_from_slice(&tx[..len1]);
        let (responder_random, responder_ssid, responder_eph_pub, enc2_len, enc2) =
            parse_sigma2(&sigma2_bytes[..len1]);

        // responder の Sigma2 を信頼送信(次の Sigma3 の piggyback ACK で解放される)。
        let resp_ctr = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let sent1 = mgr
            .send_reliable(
                &mut sessions,
                &crypto,
                &mut pool,
                ex,
                &Outgoing {
                    proto_id: 0x0000,
                    opcode: op1,
                    payload: &sigma2_bytes[..len1],
                },
                SendTiming {
                    now_ms: NOW,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        // --- initiator: Sigma2 を処理(ECDH + S2K + TBE2 復号) ---
        let responder_eph_obj = crypto
            .p256_public_key_from_bytes(&responder_eph_pub)
            .unwrap();
        let mut shared = [0u8; 32];
        eph_i.ecdh(&responder_eph_obj, &mut shared).unwrap();
        let mut tt_s1 = [0u8; 32];
        crypto.sha256_oneshot(&sigma1_bytes.0[..sigma1_bytes.1], &mut tt_s1);
        let mut s2k = [0u8; 16];
        case::derive_sigma2_key(
            &crypto,
            &ipk,
            &responder_random,
            &responder_eph_pub,
            &tt_s1,
            &shared,
            &mut s2k,
        )
        .unwrap();
        // TBE2 を復号し、responder NOC が載っていることを確認(S2K 一致の cross-check)。
        let mut tbe2 = [0u8; 1024];
        tbe2[..enc2_len].copy_from_slice(&enc2[..enc2_len]);
        let pt2 = crypto
            .aes_ccm_decrypt(&s2k, case::SIGMA2_NONCE, &[], &mut tbe2[..enc2_len])
            .unwrap();
        let (rnoc, _ricac, _rsig) = case::decode_tbe_certs(pt2).unwrap();
        assert!(!rnoc.is_empty());

        // --- initiator: Sigma3 を組み立てる ---
        // TT(Σ1+Σ2)。
        let mut hasher = crypto.sha256();
        hasher.update(&sigma1_bytes.0[..sigma1_bytes.1]);
        hasher.update(&sigma2_bytes[..len1]);
        let mut tt_s2 = [0u8; 32];
        hasher.clone().finish(&mut tt_s2);

        // TBSData3 = { initiator NOC, ICAC, initiatorEph(sender), responderEph(receiver) }。
        let mut tbs3 = [0u8; 1024];
        let tbs3_len = case::encode_tbs(
            &mut tbs3,
            &ids.comm_noc[..ids.comm_noc_len],
            Some(&ids.icac[..ids.icac_len]),
            &eph_i_pub,
            &responder_eph_pub,
        )
        .unwrap();
        let mut sig3 = [0u8; 64];
        ids.comm_kp.sign(&tbs3[..tbs3_len], &mut sig3).unwrap();

        // TBEData3 平文 = { NOC, ICAC, signature } を組み立て S3K で暗号化。
        let mut tbe3 = [0u8; 1024];
        let tbe3_pt_len = {
            let mut w = TlvWriter::new(&mut tbe3);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &ids.comm_noc[..ids.comm_noc_len])
                .unwrap();
            w.write_bytes(&cx(2), &ids.icac[..ids.icac_len]).unwrap();
            w.write_bytes(&cx(3), &sig3).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let mut s3k = [0u8; 16];
        case::derive_ipk_tt_keyed(
            &crypto,
            &ipk,
            &tt_s2,
            case::SIGMA3_KEY_INFO,
            &shared,
            &mut s3k,
        )
        .unwrap();
        let enc3 = crypto
            .aes_ccm_encrypt(&s3k, case::SIGMA3_NONCE, &[], &mut tbe3, tbe3_pt_len)
            .unwrap();
        let enc3_len = enc3.len();
        let mut sigma3_buf = [0u8; 1400];
        let s3_len = {
            let mut w = TlvWriter::new(&mut sigma3_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &tbe3[..enc3_len]).unwrap();
            w.end_container().unwrap();
            w.len()
        };

        // --- Sigma3 → 成功 StatusReport ---
        let (wire3, wn3) = build_msg(&crypto, 0x32, &sigma3_buf[..s3_len], 2, Some(resp_ctr));
        let mut tx3 = [0u8; 512];
        let mut wire3m = wire3;
        let r3 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire3m[..wn3],
                &mut tx3,
            )
            .unwrap();
        assert_eq!(r3.freed_tx, Some(sent1.buf));
        pool.release(sent1.buf);
        let (op3, len3, rel3) = action_len(r3.action);
        assert_eq!(op3, OpCode::StatusReport as u8);
        assert!(rel3);
        let sr = StatusReport::decode(&tx3[..len3]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Success);
        assert_eq!(
            sr.proto_code,
            ScStatusCode::SessionEstablishmentSuccess as u16
        );

        // --- 検証: 両側の SEKeys 一致 + CASE セッション commit ---
        // TT(Σ1+Σ2+Σ3) で SEKeys を導出。
        let mut hasher3 = crypto.sha256();
        hasher3.update(&sigma1_bytes.0[..sigma1_bytes.1]);
        hasher3.update(&sigma2_bytes[..len1]);
        hasher3.update(&sigma3_buf[..s3_len]);
        let mut tt_s3 = [0u8; 32];
        hasher3.finish(&mut tt_s3);
        let mut keys = [0u8; 48];
        case::derive_ipk_tt_keyed(
            &crypto,
            &ipk,
            &tt_s3,
            case::CASE_SESSION_KEYS_INFO,
            &shared,
            &mut keys,
        )
        .unwrap();

        let committed = sessions
            .iter()
            .find(|s| s.local_session_id() == responder_ssid)
            .expect("committed CASE session");
        assert_eq!(committed.state(), SlotState::Active);
        assert!(matches!(
            committed.mode(),
            SessionMode::Case { fabric_idx } if fabric_idx == fabric_index
        ));
        assert_eq!(committed.peer_node_id(), Some(COMM_NODE));
        assert_eq!(committed.local_node_id(), DEVICE_NODE);
        // responder: dec=I2R, enc=R2I, att。initiator が導出した鍵と一致する。
        assert_eq!(&committed.dec_key().unwrap()[..], &keys[0..16]);
        assert_eq!(&committed.enc_key().unwrap()[..], &keys[16..32]);
        assert_eq!(&committed.att_challenge().unwrap()[..], &keys[32..48]);

        assert_eq!(mgr.handler().sc.handshake_count(), 0);
    }

    /// destinationId が既知 fabric に一致しない Sigma1 は NoSharedTrustRoots で終端する。
    #[test]
    fn sigma1_unknown_dest_yields_no_shared_trust_roots() {
        let crypto = crypto();
        let ids = build_identities(&crypto);
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0xBEEF_0002), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();

        let eph_i = crypto.p256_generate_keypair().unwrap();
        let eph_i_pub = eph_i.public_key().to_bytes();
        let mut s1_buf = [0u8; 256];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &[0x01u8; 32]).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &[0xEEu8; 32]).unwrap(); // 一致しない dest_id
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 512];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        let (op, len, _) = action_len(r1.action);
        assert_eq!(op, OpCode::StatusReport as u8);
        let sr = StatusReport::decode(&tx[..len]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Failure);
        assert_eq!(sr.proto_code, ScStatusCode::NoSharedTrustRoots as u16);
        // slot は確保されず、予約セッションも作られない(unsecured のみ)。
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
        assert_eq!(sessions.len(), 1);
    }

    /// Sigma3 の TBSData3 署名が不正だと InvalidParameter で終端し予約を解放する。
    #[test]
    fn sigma3_bad_signature_fails_and_frees_reserve() {
        let crypto = crypto();
        let ids = build_identities(&crypto);
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        let fabric_index = table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();
        let (ipk, root_pub, device_node, fabric_id) = {
            let f = table.get(fabric_index).unwrap();
            (*f.ipk(), *f.root_public_key(), f.node_id(), f.fabric_id())
        };
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0xF00D_0003), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        let unsecured = sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();
        let mut pool: BufferPool<2, 1600> = BufferPool::new();

        let eph_i = crypto.p256_generate_keypair().unwrap();
        let eph_i_pub = eph_i.public_key().to_bytes();
        let mut initiator_random = [0u8; 32];
        SeqRng(0x2468_ACE0)
            .fill_bytes(&mut initiator_random)
            .unwrap();
        let mut dmsg = [0u8; 113];
        dmsg[..32].copy_from_slice(&initiator_random);
        dmsg[32..97].copy_from_slice(&root_pub);
        dmsg[97..105].copy_from_slice(&fabric_id.to_le_bytes());
        dmsg[105..113].copy_from_slice(&device_node.to_le_bytes());
        let mut dest_id = [0u8; 32];
        crypto.hmac_sha256(&ipk, &dmsg, &mut dest_id).unwrap();

        let mut s1_buf = [0u8; 256];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &initiator_random).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &dest_id).unwrap();
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 1400];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        let ex = r1.exchange.unwrap();
        let (op1, len1, _) = action_len(r1.action);
        assert_eq!(op1, OpCode::CaseSigma2 as u8);
        let mut sigma2_bytes = [0u8; 1400];
        sigma2_bytes[..len1].copy_from_slice(&tx[..len1]);
        let (responder_random, _rssid, responder_eph_pub, _enc2_len, _enc2) =
            parse_sigma2(&sigma2_bytes[..len1]);
        let _ = responder_random;
        let resp_ctr = sessions.get(unsecured).unwrap().peek_tx_ctr();
        let sent1 = mgr
            .send_reliable(
                &mut sessions,
                &crypto,
                &mut pool,
                ex,
                &Outgoing {
                    proto_id: 0x0000,
                    opcode: op1,
                    payload: &sigma2_bytes[..len1],
                },
                SendTiming {
                    now_ms: NOW,
                    jitter_rand: 0,
                },
            )
            .unwrap();

        let responder_eph_obj = crypto
            .p256_public_key_from_bytes(&responder_eph_pub)
            .unwrap();
        let mut shared = [0u8; 32];
        eph_i.ecdh(&responder_eph_obj, &mut shared).unwrap();
        let mut hasher = crypto.sha256();
        hasher.update(&s1_buf[..s1_len]);
        hasher.update(&sigma2_bytes[..len1]);
        let mut tt_s2 = [0u8; 32];
        hasher.clone().finish(&mut tt_s2);

        // 正しい署名を作ってから 1 バイト反転させて不正化する。
        let mut tbs3 = [0u8; 1024];
        let tbs3_len = case::encode_tbs(
            &mut tbs3,
            &ids.comm_noc[..ids.comm_noc_len],
            Some(&ids.icac[..ids.icac_len]),
            &eph_i_pub,
            &responder_eph_pub,
        )
        .unwrap();
        let mut sig3 = [0u8; 64];
        ids.comm_kp.sign(&tbs3[..tbs3_len], &mut sig3).unwrap();
        sig3[0] ^= 0x01; // 署名を破壊。

        let mut tbe3 = [0u8; 1024];
        let tbe3_pt_len = {
            let mut w = TlvWriter::new(&mut tbe3);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &ids.comm_noc[..ids.comm_noc_len])
                .unwrap();
            w.write_bytes(&cx(2), &ids.icac[..ids.icac_len]).unwrap();
            w.write_bytes(&cx(3), &sig3).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let mut s3k = [0u8; 16];
        case::derive_ipk_tt_keyed(
            &crypto,
            &ipk,
            &tt_s2,
            case::SIGMA3_KEY_INFO,
            &shared,
            &mut s3k,
        )
        .unwrap();
        let enc3 = crypto
            .aes_ccm_encrypt(&s3k, case::SIGMA3_NONCE, &[], &mut tbe3, tbe3_pt_len)
            .unwrap();
        let enc3_len = enc3.len();
        let mut sigma3_buf = [0u8; 1400];
        let s3_len = {
            let mut w = TlvWriter::new(&mut sigma3_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &tbe3[..enc3_len]).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (wire3, wn3) = build_msg(&crypto, 0x32, &sigma3_buf[..s3_len], 2, Some(resp_ctr));
        let mut tx3 = [0u8; 512];
        let mut wire3m = wire3;
        let r3 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire3m[..wn3],
                &mut tx3,
            )
            .unwrap();
        if let Some(b) = r3.freed_tx {
            pool.release(b);
        }
        let _ = sent1;
        let (op3, len3, _) = action_len(r3.action);
        assert_eq!(op3, OpCode::StatusReport as u8);
        let sr = StatusReport::decode(&tx3[..len3]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Failure);
        assert_eq!(sr.proto_code, ScStatusCode::InvalidParameter as u16);
        // 予約は解放され CASE セッションは commit されない(unsecured のみ)。
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
        assert!(!sessions
            .iter()
            .any(|s| matches!(s.mode(), SessionMode::Case { .. })));
        assert_eq!(sessions.len(), 1);
    }

    /// resumption フィールド付き Sigma1 は(未対応のため)フルハンドシェイクへフォールバック
    /// し、正常に Sigma2 を返す。
    #[test]
    fn sigma1_with_resumption_falls_back_to_full_handshake() {
        let crypto = crypto();
        let ids = build_identities(&crypto);
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        let fabric_index = table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();
        let (ipk, root_pub, device_node, fabric_id) = {
            let f = table.get(fabric_index).unwrap();
            (*f.ipk(), *f.root_public_key(), f.node_id(), f.fabric_id())
        };
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0x0BAD_0004), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();

        let eph_i = crypto.p256_generate_keypair().unwrap();
        let eph_i_pub = eph_i.public_key().to_bytes();
        let mut initiator_random = [0u8; 32];
        SeqRng(0x9999_1111)
            .fill_bytes(&mut initiator_random)
            .unwrap();
        let mut dmsg = [0u8; 113];
        dmsg[..32].copy_from_slice(&initiator_random);
        dmsg[32..97].copy_from_slice(&root_pub);
        dmsg[97..105].copy_from_slice(&fabric_id.to_le_bytes());
        dmsg[105..113].copy_from_slice(&device_node.to_le_bytes());
        let mut dest_id = [0u8; 32];
        crypto.hmac_sha256(&ipk, &dmsg, &mut dest_id).unwrap();

        let mut s1_buf = [0u8; 300];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &initiator_random).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &dest_id).unwrap();
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            // resumption フィールド(両方存在)。
            w.write_bytes(&cx(6), &[0xABu8; 16]).unwrap();
            w.write_bytes(&cx(7), &[0xCDu8; 16]).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 1400];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        let (op1, _len1, _) = action_len(r1.action);
        // resumption を無視してフル Sigma2 を返す(Busy でも StatusReport でもない)。
        assert_eq!(op1, OpCode::CaseSigma2 as u8);
        assert_eq!(mgr.handler().sc.handshake_count(), 1);
    }

    /// resumption フィールドが片方のみの Sigma1 は InvalidParameter で拒否する。
    #[test]
    fn sigma1_mismatched_resumption_is_invalid() {
        let crypto = crypto();
        let ids = build_identities(&crypto);
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0x5151_0005), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();

        let eph_i_pub = crypto
            .p256_generate_keypair()
            .unwrap()
            .public_key()
            .to_bytes();
        let mut s1_buf = [0u8; 300];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &[0x01u8; 32]).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &[0x02u8; 32]).unwrap();
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            w.write_bytes(&cx(6), &[0xABu8; 16]).unwrap(); // resumptionID のみ(MIC 欠落)
            w.end_container().unwrap();
            w.len()
        };
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 512];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        let (op, len, _) = action_len(r1.action);
        assert_eq!(op, OpCode::StatusReport as u8);
        let sr = StatusReport::decode(&tx[..len]).unwrap();
        assert_eq!(sr.proto_code, ScStatusCode::InvalidParameter as u16);
        assert_eq!(mgr.handler().sc.handshake_count(), 0);
    }

    /// 進行中の CASE ハンドシェイクがある間に別 exchange の Sigma1 が来ると Busy で断る
    /// (H=1 の共有 [`HandshakePool`] 容量判定。§6.4)。
    #[test]
    fn second_case_handshake_is_busy() {
        let crypto = crypto();
        let ids = build_identities(&crypto);
        let mut table: FabricTable<Backend, 4> = FabricTable::new();
        let fabric_index = table
            .add(
                &crypto,
                &ids.rcac[..ids.rcac_len],
                Some(&ids.icac[..ids.icac_len]),
                &ids.device_noc[..ids.device_noc_len],
                crypto.p256_keypair_from_bytes(&[0x33; 32]).unwrap(),
                &IPK_EPOCH,
                0xFFF1,
                NOW_SECS,
                "dev",
            )
            .unwrap();
        let (ipk, root_pub, device_node, fabric_id) = {
            let f = table.get(fabric_index).unwrap();
            (*f.ipk(), *f.root_public_key(), f.node_id(), f.fabric_id())
        };
        let creds = TestCreds {
            table: &table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let config = PaseConfig::from_passcode(20202021, &[0x53u8; 16], 1000).unwrap();
        let sc = SecureChannel::new(&crypto, SeqRng(0xAAAA_0006), config, creds);
        let mux = ProtocolMux::new(sc, ImPlaceholder);
        let mut mgr: ExchangeManager<CaseMux, 4> = ExchangeManager::new(mux);
        let mut sessions: SessionManager<4> = SessionManager::new();
        sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();

        // 1 本目: 有効な Sigma1 を送り slot を占有(Sigma2 を返す)。
        let eph_i_pub = crypto
            .p256_generate_keypair()
            .unwrap()
            .public_key()
            .to_bytes();
        let mut initiator_random = [0u8; 32];
        SeqRng(0x1010_2020)
            .fill_bytes(&mut initiator_random)
            .unwrap();
        let mut dmsg = [0u8; 113];
        dmsg[..32].copy_from_slice(&initiator_random);
        dmsg[32..97].copy_from_slice(&root_pub);
        dmsg[97..105].copy_from_slice(&fabric_id.to_le_bytes());
        dmsg[105..113].copy_from_slice(&device_node.to_le_bytes());
        let mut dest_id = [0u8; 32];
        crypto.hmac_sha256(&ipk, &dmsg, &mut dest_id).unwrap();
        let mut s1_buf = [0u8; 256];
        let s1_len = {
            let mut w = TlvWriter::new(&mut s1_buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &initiator_random).unwrap();
            w.write_u16(&cx(2), 0x7777).unwrap();
            w.write_bytes(&cx(3), &dest_id).unwrap();
            w.write_bytes(&cx(4), &eph_i_pub).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (wire1, wn1) = build_msg(&crypto, 0x30, &s1_buf[..s1_len], 1, None);
        let mut tx = [0u8; 1400];
        let mut wire1m = wire1;
        let r1 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire1m[..wn1],
                &mut tx,
            )
            .unwrap();
        let (op1, _, _) = action_len(r1.action);
        assert_eq!(op1, OpCode::CaseSigma2 as u8);
        assert_eq!(mgr.handler().sc.handshake_count(), 1);

        // 2 本目: 別 exch_id の Sigma1。プール満杯(H=1)→ Busy。
        let (wire2, wn2) = build_msg_exch(&crypto, 0x30, &s1_buf[..s1_len], 2, 0x66);
        let mut tx2 = [0u8; 512];
        let mut wire2m = wire2;
        let r2 = mgr
            .recv(
                &mut sessions,
                &crypto,
                peer(),
                NOW,
                &mut wire2m[..wn2],
                &mut tx2,
            )
            .unwrap();
        let (op2, len2, rel2) = action_len(r2.action);
        assert_eq!(op2, OpCode::StatusReport as u8);
        assert!(!rel2, "Busy は R フラグを落とす");
        let sr = StatusReport::decode(&tx2[..len2]).unwrap();
        assert_eq!(sr.general_code, GeneralCode::Busy);
        assert_eq!(sr.proto_code, ScStatusCode::Busy as u16);
        // 2 本目は予約しない(unsecured + 1 本目の reserve = 2)。
        assert_eq!(mgr.handler().sc.handshake_count(), 1);
        assert_eq!(sessions.len(), 2);
    }
}
