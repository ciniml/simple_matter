//! PASE responder(デバイス側)の同期状態機械。
//!
//! `docs/design/secure-channel.md` §6 に基づく。PBKDFParamRequest → PBKDFParamResponse →
//! PASEPake1 → PASEPake2 → PASEPake3 → 成功 StatusReport の 3 往復を、`ExchangeId` を
//! キーとする [`HandshakePool`] の slot で表現する Mealy machine として実装する。

use crate::crypto::spake2p::{compute_verifier, Spake2pVerifier, Spake2pVerifierParams};
use crate::crypto::{Crypto, Rng};
use crate::error::{Error, Result};
use crate::exchange::{HandlerAction, ProtocolHandler, RxMessage};
use crate::transport::session::{SessionInit, SessionManager, SessionMode};

use super::handshake::{HandshakePool, PasePhase};
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

/// Secure Channel(Protocol ID 0x0000)ハンドラ。PASE responder を内包する。
///
/// `H` は同時ハンドシェイク数の上限(既定 1)。crypto は参照で保持し、rng は
/// 値で保持する(responder_random / SPAKE2+ の y スカラ生成に用いる)。
pub struct SecureChannel<'c, C: Crypto, R: Rng, const H: usize> {
    crypto: &'c C,
    rng: R,
    config: PaseConfig,
    pool: HandshakePool<H>,
}

impl<'c, C: Crypto, R: Rng, const H: usize> SecureChannel<'c, C, R, H> {
    /// crypto・rng・PASE 設定を与えてハンドラを生成する。
    pub fn new(crypto: &'c C, rng: R, config: PaseConfig) -> Self {
        Self {
            crypto,
            rng,
            config,
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
                PasePhase::PbkdfSent { context },
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
            match slot.phase_mut() {
                PasePhase::PbkdfSent { context } => *context,
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
            slot.set_phase(PasePhase::Pake2Sent { verifier });
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

impl<C: Crypto, R: Rng, const H: usize> ProtocolHandler for SecureChannel<'_, C, R, H> {
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
            OpCode::StatusReport => {
                // 相手からの中断: slot を解放して黙って終える(reserve は on_tick で回収)。
                if let Some(slot) = self.pool.close(rx.exchange) {
                    sessions.remove(slot.reserved());
                }
                Ok(HandlerAction::None)
            }
            // CASE / group / その他は本ピースではスコープ外(silent drop)。
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

    type Mux<'c> = ProtocolMux<SecureChannel<'c, RustCrypto<SeqRng>, SeqRng, 1>, ImPlaceholder>;

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
        let sc = SecureChannel::new(crypto, SeqRng(0xABCD_0001), config);
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
