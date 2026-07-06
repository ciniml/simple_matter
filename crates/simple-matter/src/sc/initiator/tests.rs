//! [`ScInitiator`](super::ScInitiator)(コントローラ)を既存 [`SecureChannel`](crate::sc::SecureChannel)
//! (responder)とメモリ内で直結し、PASE / CASE 両ハンドシェイクを往復させる結合テスト。
//!
//! 2 つの [`ExchangeManager`] を相互の `recv` / `send_reliable` で駆動する軽量ポンプ
//! (`deliver`)で MRP・暗号境界も含めて 1 パケットずつ往復させ、両側で導出した
//! セッション鍵が鏡像(initiator enc == responder dec)で一致することを確認する。
//! 失敗系(不正パスコード → Pake2 検証失敗、Sigma2 署名不正、Busy StatusReport 受理)も含む。

use super::*;

use crate::buf::BufferPool;
use crate::cert::{dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use crate::error::Result as CrateResult;
use crate::exchange::{
    Dispatcher, ExchangeManager, HandlerAction, Outgoing, ProtocolHandler, ProtocolMux, RxMessage,
    SendTiming,
};
use crate::fabric::{FabricEntry, FabricTable};
use crate::sc::case::creds::{FabricStore, NoFabrics, NocResolver, PeerIdentity};
use crate::sc::status::{ScStatusCode, StatusReport};
use crate::sc::{OpCode, PaseConfig, SecureChannel};
use crate::tlv::{TlvTag, TlvWriter};
use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, PayloadHeader, SecFlags};
use crate::transport::net::PeerAddr;
use crate::transport::secure::SecureCodec;
use crate::transport::session::{SessionId, SessionInit, SessionManager, SessionMode};
use crate::transport::util::WriteBuf;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::NonZeroU8;

const NOW: u64 = 3000;
const NOW_SECS: u32 = 500;
const NOT_BEFORE: u32 = 100;
const NOT_AFTER: u32 = 100_000;
const FABRIC_ID: u64 = 0x1122_3344_5566_7788;
const DEVICE_NODE: u64 = 0x0000_0000_0001_0001;
const COMM_NODE: u64 = 0x0000_0000_0002_0002;
const IPK_EPOCH: [u8; 16] = [0x66u8; 16];
const PASSCODE: u32 = 20202021;
const ITERATIONS: u32 = 1000;
const SALT: [u8; 16] = [0x53u8; 16];

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
    RustCrypto::new(SeqRng(0x1417_0000_2222_3333))
}

fn peer() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        5540,
    ))
}

/// 「再起動後のデバイス」役の別アドレス(unsecured セッションのカウンタ窓を分離する)。
fn peer2() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)),
        5540,
    ))
}

/// IM プレースホルダ(常に None)。
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

/// FabricTable + crypto + 検証時刻を束ねた CASE 用 creds(`FabricStore` + `NocResolver`)。
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

// ---- 自己生成証明書チェーン(sc/responder.rs case_tests から移植) ----

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

struct Cert {
    buf: [u8; 400],
    len: usize,
}
impl Cert {
    fn slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

struct Identities {
    rcac: Cert,
    icac: Cert,
    device_noc: Cert,
    comm_noc: Cert,
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

    let mk = |serial: &[u8],
              issuer: &[DnInt],
              subject: &[DnInt],
              pubk: &[u8; 65],
              is_ca: bool,
              path: Option<u8>,
              ku: u16,
              eku: &[u8],
              skid: &[u8; 20],
              akid: &[u8; 20],
              kp: &<Backend as Crypto>::Keypair| {
        let mut c = Cert {
            buf: [0; 400],
            len: 0,
        };
        c.len = write_cert(
            &mut c.buf, serial, issuer, subject, pubk, is_ca, path, ku, eku, skid, akid, kp,
        );
        c
    };

    let rcac = mk(
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
    let icac = mk(
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
    let device_noc = mk(
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
    let comm_noc = mk(
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

    Identities {
        rcac,
        icac,
        device_noc,
        comm_noc,
    }
}

/// device 側 fabric テーブルを作る(`op_key` = 運用秘密鍵。正常系は NOC と一致する [0x33;32])。
fn device_table(crypto: &Backend, ids: &Identities, op_key: &[u8; 32]) -> FabricTable<Backend, 4> {
    let mut table = FabricTable::new();
    table
        .add(
            crypto,
            ids.rcac.slice(),
            Some(ids.icac.slice()),
            ids.device_noc.slice(),
            crypto.p256_keypair_from_bytes(op_key).unwrap(),
            &IPK_EPOCH,
            0xFFF1,
            NOW_SECS,
            "dev",
        )
        .unwrap();
    table
}

/// controller(commissioner)側 fabric テーブルを作る(自 NOC = comm、運用鍵 = [0x44;32])。
fn controller_table(crypto: &Backend, ids: &Identities) -> FabricTable<Backend, 4> {
    let mut table = FabricTable::new();
    table
        .add(
            crypto,
            ids.rcac.slice(),
            Some(ids.icac.slice()),
            ids.comm_noc.slice(),
            crypto.p256_keypair_from_bytes(&[0x44; 32]).unwrap(),
            &IPK_EPOCH,
            0xFFF1,
            NOW_SECS,
            "ctl",
        )
        .unwrap();
    table
}

/// 1 パケットを受け手のマネージャに配送し、応答(Respond/Close)があれば send_reliable で
/// 暗号化ワイヤを組み立てて返す。piggyback ACK で解放された TX バッファはプールへ返す。
fn deliver<H: Dispatcher>(
    mgr: &mut ExchangeManager<H, 4>,
    sessions: &mut SessionManager<4>,
    pool: &mut BufferPool<3, 1600>,
    crypto: &Backend,
    now: u64,
    peer_addr: PeerAddr,
    wire: &mut [u8],
) -> Option<([u8; 1600], usize)> {
    let mut tx = [0u8; 1600];
    let report = mgr
        .recv(sessions, crypto, peer_addr, now, wire, &mut tx)
        .unwrap();
    if let Some(b) = report.freed_tx {
        pool.release(b);
    }
    let (opcode, len) = match report.action {
        HandlerAction::Respond { opcode, len, .. } | HandlerAction::Close { opcode, len, .. } => {
            (opcode, len)
        }
        HandlerAction::None => return None,
        // 応答なしの終端(resumed 終端の StatusReport 受理)。実スタック同様に
        // 終端予約する(回収は poll)。
        HandlerAction::CloseSilent => {
            if let Some(ex) = report.exchange {
                mgr.mark_closing(ex);
            }
            return None;
        }
    };
    let ex = report.exchange.unwrap();
    let mut payload = [0u8; 1600];
    payload[..len].copy_from_slice(&tx[..len]);
    let sent = mgr
        .send_reliable(
            sessions,
            crypto,
            pool,
            ex,
            &Outgoing {
                proto_id: 0x0000,
                opcode,
                payload: &payload[..len],
            },
            SendTiming {
                now_ms: now,
                jitter_rand: 0,
            },
        )
        .unwrap();
    let mut out = [0u8; 1600];
    out[..sent.len].copy_from_slice(&pool.get(sent.buf).unwrap()[..sent.len]);
    Some((out, sent.len))
}

/// initiator が開始した最初のメッセージを送出し、往復ポンプで完走させる。
///
/// `first_opcode` は Sigma1 / PBKDFParamRequest の opcode、`payload` はその payload。
#[allow(clippy::too_many_arguments)]
fn pump_handshake<HI: Dispatcher, HR: Dispatcher>(
    crypto: &Backend,
    init_mgr: &mut ExchangeManager<HI, 4>,
    init_sessions: &mut SessionManager<4>,
    init_pool: &mut BufferPool<3, 1600>,
    resp_mgr: &mut ExchangeManager<HR, 4>,
    resp_sessions: &mut SessionManager<4>,
    resp_pool: &mut BufferPool<3, 1600>,
    ex: super::ExchangeId,
    first_opcode: u8,
    payload: &[u8],
    peer_addr: PeerAddr,
) {
    let sent = init_mgr
        .send_reliable(
            init_sessions,
            crypto,
            init_pool,
            ex,
            &Outgoing {
                proto_id: 0x0000,
                opcode: first_opcode,
                payload,
            },
            SendTiming {
                now_ms: NOW,
                jitter_rand: 0,
            },
        )
        .unwrap();
    let mut wire = [0u8; 1600];
    let mut wlen = sent.len;
    wire[..wlen].copy_from_slice(&init_pool.get(sent.buf).unwrap()[..wlen]);

    let mut to_responder = true;
    for _ in 0..8 {
        let resp = if to_responder {
            deliver(
                resp_mgr,
                resp_sessions,
                resp_pool,
                crypto,
                NOW,
                peer_addr,
                &mut wire[..wlen],
            )
        } else {
            deliver(
                init_mgr,
                init_sessions,
                init_pool,
                crypto,
                NOW,
                peer_addr,
                &mut wire[..wlen],
            )
        };
        match resp {
            Some((w, l)) => {
                wire = w;
                wlen = l;
                to_responder = !to_responder;
            }
            None => break,
        }
    }
}

/// 両スタックのセッションから鏡像鍵一致を確認する。
fn assert_mirror_keys(
    init_sessions: &SessionManager<4>,
    init_session: SessionId,
    resp_sessions: &SessionManager<4>,
    resp_ssid: u16,
) {
    let is = init_sessions.get(init_session).expect("initiator session");
    let rs = resp_sessions
        .iter()
        .find(|s| s.local_session_id() == resp_ssid)
        .expect("responder session");
    // initiator enc = I2R = responder dec; initiator dec = R2I = responder enc。
    assert_eq!(is.enc_key().unwrap(), rs.dec_key().unwrap());
    assert_eq!(is.dec_key().unwrap(), rs.enc_key().unwrap());
    assert_eq!(is.att_challenge().unwrap(), rs.att_challenge().unwrap());
}

/// responder → initiator 方向の平文 SC メッセージ(I フラグ clear)を組み立てる。
/// Busy StatusReport の注入に用いる。
fn build_response_msg(
    crypto: &Backend,
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
        // I フラグは立てない(応答方向)。
        exch_flags: ExchFlags::from_bits(0),
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

// =================== PASE ===================

#[test]
fn full_pase_handshake_initiator_vs_responder() {
    let crypto = crypto();

    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(&crypto, SeqRng(0xD00D_0001), config, NoFabrics);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_0002), NoFabrics);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    let ex = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved = init_sessions.reserve(peer(), NOW).unwrap();
    let init_ssid = init_sessions.get(reserved).unwrap().local_session_id();
    let mut payload = [0u8; 256];
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_pase(ex, reserved, init_ssid, PASSCODE, &mut payload, NOW)
        .unwrap();

    pump_handshake(
        &crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex,
        OpCode::PbkdfParamRequest as u8,
        &payload[..plen],
        peer(),
    );

    let session = match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::PaseEstablished { session }) => session,
        other => panic!("expected PaseEstablished, got {other:?}"),
    };
    assert!(!init_mgr.handler().sc.is_busy());
    let is = init_sessions.get(session).unwrap();
    assert!(matches!(is.mode(), SessionMode::Pase { fabric_idx: 0 }));
    assert_mirror_keys(&init_sessions, session, &resp_sessions, init_ssid);
}

#[test]
fn pase_wrong_passcode_fails_at_pake2_verify() {
    let crypto = crypto();
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(&crypto, SeqRng(0xD00D_0003), config, NoFabrics);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_0004), NoFabrics);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    let ex = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved = init_sessions.reserve(peer(), NOW).unwrap();
    let init_ssid = init_sessions.get(reserved).unwrap().local_session_id();
    let mut payload = [0u8; 256];
    // 誤ったパスコードで開始する。
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_pase(ex, reserved, init_ssid, PASSCODE + 1, &mut payload, NOW)
        .unwrap();

    pump_handshake(
        &crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex,
        OpCode::PbkdfParamRequest as u8,
        &payload[..plen],
        peer(),
    );

    // initiator は PASEPake2 の cB 検証で失敗し Failed を積む。
    match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::Failed {
            kind: HandshakeKindTag::Pase,
            reason: ScFailReason::Crypto,
        }) => {}
        other => panic!("expected Failed(Pase, Crypto), got {other:?}"),
    }
    assert!(!init_mgr.handler().sc.is_busy());
    assert!(!init_sessions
        .iter()
        .any(|s| matches!(s.mode(), SessionMode::Pase { .. })));
}

#[test]
fn pase_busy_status_report_is_accepted_as_failure() {
    let crypto = crypto();
    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_0005), NoFabrics);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    let ex = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved = init_sessions.reserve(peer(), NOW).unwrap();
    let init_ssid = init_sessions.get(reserved).unwrap().local_session_id();
    let mut payload = [0u8; 256];
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_pase(ex, reserved, init_ssid, PASSCODE, &mut payload, NOW)
        .unwrap();
    let _ = init_mgr
        .send_reliable(
            &mut init_sessions,
            &crypto,
            &mut init_pool,
            ex,
            &Outgoing {
                proto_id: 0x0000,
                opcode: OpCode::PbkdfParamRequest as u8,
                payload: &payload[..plen],
            },
            SendTiming {
                now_ms: NOW,
                jitter_rand: 0,
            },
        )
        .unwrap();

    // responder 役として Busy StatusReport を注入する。
    let delay = 500u16.to_le_bytes();
    let mut sr_payload = [0u8; 16];
    let sr_len = StatusReport::new(ScStatusCode::Busy, &delay)
        .encode(&mut sr_payload)
        .unwrap();
    let mut wire = [0u8; 512];
    let wlen = build_response_msg(
        &crypto,
        OpCode::StatusReport as u8,
        &sr_payload[..sr_len],
        1,
        ex.exch_id(),
        &mut wire,
    );
    let mut tx = [0u8; 1600];
    let report = init_mgr
        .recv(
            &mut init_sessions,
            &crypto,
            peer(),
            NOW,
            &mut wire[..wlen],
            &mut tx,
        )
        .unwrap();
    assert!(report.dispatched);
    assert_eq!(report.action, HandlerAction::None);

    match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::Failed {
            kind: HandshakeKindTag::Pase,
            reason: ScFailReason::StatusReport(code),
        }) => assert_eq!(code, ScStatusCode::Busy as u16),
        other => panic!("expected Failed(Pase, StatusReport(Busy)), got {other:?}"),
    }
    assert!(!init_mgr.handler().sc.is_busy());
}

// =================== CASE ===================

/// CASE ハンドシェイクを往復させ、initiator の完了イベントと両側セッションを返す。
fn run_case_handshake(
    crypto: &Backend,
    resp_table: &FabricTable<Backend, 4>,
    init_table: &FabricTable<Backend, 4>,
    init_fabric_idx: NonZeroU8,
) -> (ScEvent, SessionManager<4>, SessionManager<4>, u16) {
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let resp_creds = TestCreds {
        table: resp_table,
        crypto,
        now: NOW_SECS,
    };
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(crypto, SeqRng(0xD00D_1001), config, resp_creds);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    let init_creds = TestCreds {
        table: init_table,
        crypto,
        now: NOW_SECS,
    };
    let init = ScInitiator::new(crypto, SeqRng(0xBEEF_1002), init_creds);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    let ex = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved = init_sessions.reserve(peer(), NOW).unwrap();
    let init_ssid = init_sessions.get(reserved).unwrap().local_session_id();
    let mut payload = [0u8; 512];
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_case(
            ex,
            reserved,
            init_ssid,
            init_fabric_idx,
            DEVICE_NODE,
            &mut payload,
            NOW,
        )
        .unwrap();

    pump_handshake(
        crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex,
        OpCode::CaseSigma1 as u8,
        &payload[..plen],
        peer(),
    );

    let ev = init_mgr
        .handler_mut()
        .sc
        .take_event()
        .expect("initiator event");
    (ev, init_sessions, resp_sessions, init_ssid)
}

#[test]
fn full_case_handshake_initiator_vs_responder() {
    let crypto = crypto();
    let ids = build_identities(&crypto);
    let resp_table = device_table(&crypto, &ids, &[0x33; 32]);
    let init_table = controller_table(&crypto, &ids);
    let init_fabric = NonZeroU8::new(1).unwrap();

    let (ev, init_sessions, resp_sessions, init_ssid) =
        run_case_handshake(&crypto, &resp_table, &init_table, init_fabric);

    let session = match ev {
        ScEvent::CaseEstablished {
            session,
            resumed: false,
        } => session,
        other => panic!("expected CaseEstablished(full), got {other:?}"),
    };
    let is = init_sessions.get(session).unwrap();
    assert!(matches!(is.mode(), SessionMode::Case { .. }));
    assert_eq!(is.peer_node_id(), Some(DEVICE_NODE));
    assert_mirror_keys(&init_sessions, session, &resp_sessions, init_ssid);

    // responder 側にも CASE セッションが commit されている。
    assert!(
        resp_sessions
            .iter()
            .any(|s| s.local_session_id() == init_ssid
                && matches!(s.mode(), SessionMode::Case { .. }))
    );
}

/// CASE resumption(§7.4): 同一スタック上でフル CASE → 2 本目の CASE を張り、2 本目が
/// Sigma2_Resume 経路(`resumed: true`)で確立し、鏡像鍵が一致することを確認する。
#[test]
fn case_resumption_round_trip() {
    let crypto = crypto();
    let ids = build_identities(&crypto);
    let resp_table = device_table(&crypto, &ids, &[0x33; 32]);
    let init_table = controller_table(&crypto, &ids);
    let init_fabric = NonZeroU8::new(1).unwrap();

    // 両スタックを 1 度だけ構築し、2 回のハンドシェイクをまたいで resumption レコードを保つ。
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let resp_creds = TestCreds {
        table: &resp_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(&crypto, SeqRng(0xD00D_3001), config, resp_creds);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    let init_creds = TestCreds {
        table: &init_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_3002), init_creds);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    // --- 1 本目: フル CASE ---
    let ex1 = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved1 = init_sessions.reserve(peer(), NOW).unwrap();
    let ssid1 = init_sessions.get(reserved1).unwrap().local_session_id();
    let mut payload = [0u8; 512];
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_case(
            ex1,
            reserved1,
            ssid1,
            init_fabric,
            DEVICE_NODE,
            &mut payload,
            NOW,
        )
        .unwrap();
    pump_handshake(
        &crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex1,
        OpCode::CaseSigma1 as u8,
        &payload[..plen],
        peer(),
    );
    let s1 = match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::CaseEstablished {
            session,
            resumed: false,
        }) => session,
        other => panic!("expected full CaseEstablished, got {other:?}"),
    };
    // フル CASE 完了で両側に resumption レコードが 1 件ずつ保存される。
    assert_eq!(init_mgr.handler().sc.resumption_count(), 1);
    assert_eq!(resp_mgr.handler().sc.resumption_count(), 1);
    assert_mirror_keys(&init_sessions, s1, &resp_sessions, ssid1);

    // --- 2 本目: resumption(Sigma1 に ctx6/ctx7 が付き、Sigma2_Resume で確立)---
    let ex2 = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved2 = init_sessions.reserve(peer(), NOW).unwrap();
    let ssid2 = init_sessions.get(reserved2).unwrap().local_session_id();
    let plen2 = init_mgr
        .handler_mut()
        .sc
        .start_case(
            ex2,
            reserved2,
            ssid2,
            init_fabric,
            DEVICE_NODE,
            &mut payload,
            NOW,
        )
        .unwrap();
    pump_handshake(
        &crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex2,
        OpCode::CaseSigma1 as u8,
        &payload[..plen2],
        peer(),
    );
    let s2 = match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::CaseEstablished {
            session,
            resumed: true,
        }) => session,
        other => panic!("expected resumed CaseEstablished, got {other:?}"),
    };
    let is = init_sessions.get(s2).unwrap();
    assert!(matches!(is.mode(), SessionMode::Case { .. }));
    assert_eq!(is.peer_node_id(), Some(DEVICE_NODE));
    assert_mirror_keys(&init_sessions, s2, &resp_sessions, ssid2);
    // レコードはローテートされ、件数は 1 のまま(同一ピア upsert)。
    assert_eq!(init_mgr.handler().sc.resumption_count(), 1);
    assert_eq!(resp_mgr.handler().sc.resumption_count(), 1);
    // 責務の後始末: ハンドシェイク slot が両側とも解放されている。
    assert!(!init_mgr.handler().sc.is_busy());
    assert_eq!(resp_mgr.handler().sc.handshake_count(), 0);

    // 回帰(C4 実機で検出): resumed ハンドシェイクは responder が最後の受信者
    // (initiator の成功 StatusReport)なので、受理時に exchange を終端予約
    // (CloseSilent)しないと slot がプールに残り続け、EXCHANGES 回の resumption 後に
    // デバイスが新規ハンドシェイクへ応答不能になる。standalone ACK(200ms)を
    // 流し切った後に slot が回収されることを確認する。
    let before = resp_mgr.len();
    assert!(before >= 1);
    loop {
        if let crate::exchange::PollAction::Idle { .. } = resp_mgr.poll(NOW + 210, 0) {
            break;
        }
    }
    assert_eq!(
        resp_mgr.len(),
        before - 1,
        "resumed-handshake responder exchange must be reclaimed after CloseSilent"
    );
}

/// responder がレコードを失った場合(再起動相当 = 新しい SecureChannel)、initiator の
/// resumption 要求つき Sigma1 に対しフル Sigma2 が返り、フル CASE として確立する
/// (`resumed: false` フォールバック。§7.4)。
#[test]
fn case_resumption_unknown_id_falls_back_to_full() {
    let crypto = crypto();
    let ids = build_identities(&crypto);
    let resp_table = device_table(&crypto, &ids, &[0x33; 32]);
    let init_table = controller_table(&crypto, &ids);
    let init_fabric = NonZeroU8::new(1).unwrap();

    // initiator は 2 回のハンドシェイクをまたいで保持。
    let init_creds = TestCreds {
        table: &init_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_4002), init_creds);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    // --- 1 本目: 1 台目の responder とフル CASE(レコードを作る)---
    {
        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let resp_creds = TestCreds {
            table: &resp_table,
            crypto: &crypto,
            now: NOW_SECS,
        };
        let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
            SecureChannel::new(&crypto, SeqRng(0xD00D_4001), config, resp_creds);
        let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
            ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
        let mut resp_sessions: SessionManager<4> = SessionManager::new();
        resp_sessions
            .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
            .unwrap();
        let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

        let ex = init_mgr.open_initiator(init_unsec).unwrap();
        let reserved = init_sessions.reserve(peer(), NOW).unwrap();
        let ssid = init_sessions.get(reserved).unwrap().local_session_id();
        let mut payload = [0u8; 512];
        let plen = init_mgr
            .handler_mut()
            .sc
            .start_case(
                ex,
                reserved,
                ssid,
                init_fabric,
                DEVICE_NODE,
                &mut payload,
                NOW,
            )
            .unwrap();
        pump_handshake(
            &crypto,
            &mut init_mgr,
            &mut init_sessions,
            &mut init_pool,
            &mut resp_mgr,
            &mut resp_sessions,
            &mut resp_pool,
            ex,
            OpCode::CaseSigma1 as u8,
            &payload[..plen],
            peer(),
        );
        assert!(matches!(
            init_mgr.handler_mut().sc.take_event(),
            Some(ScEvent::CaseEstablished { resumed: false, .. })
        ));
        assert_eq!(init_mgr.handler().sc.resumption_count(), 1);
    }

    // --- 2 本目: レコードを持たない「再起動後の」responder に resumption を試みる ---
    // 再起動後は unsecured メッセージカウンタも初期化されるため、別アドレス(peer2)として
    // 現れる想定にし、initiator 側も新しい unsecured セッションで話す(カウンタ窓の分離)。
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let resp_creds = TestCreds {
        table: &resp_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(&crypto, SeqRng(0xD00D_4002), config, resp_creds);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer2(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    let init_unsec2 = init_sessions
        .insert(SessionInit::plaintext(peer2(), 0, 1), NOW)
        .unwrap();
    let ex2 = init_mgr.open_initiator(init_unsec2).unwrap();
    let reserved2 = init_sessions.reserve(peer2(), NOW).unwrap();
    let ssid2 = init_sessions.get(reserved2).unwrap().local_session_id();
    let mut payload = [0u8; 512];
    let plen2 = init_mgr
        .handler_mut()
        .sc
        .start_case(
            ex2,
            reserved2,
            ssid2,
            init_fabric,
            DEVICE_NODE,
            &mut payload,
            NOW,
        )
        .unwrap();
    // resumption レコードがあるので Sigma1 に ctx6/ctx7 が付いている。
    let s1 = crate::sc::case::responder::Sigma1::decode(&payload[..plen2]).unwrap();
    assert!(s1.has_resumption());

    pump_handshake(
        &crypto,
        &mut init_mgr,
        &mut init_sessions,
        &mut init_pool,
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        ex2,
        OpCode::CaseSigma1 as u8,
        &payload[..plen2],
        peer2(),
    );
    // 未知 resumptionID → フル CASE にフォールバックして確立(resumed: false)。
    let s2 = match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::CaseEstablished {
            session,
            resumed: false,
        }) => session,
        other => panic!("expected full-CASE fallback, got {other:?}"),
    };
    // 新 responder には CASE セッションが 1 本だけあるはず。鏡像鍵の一致を直接比較する
    // (両側のセッション ID 採番はもはや同期しないため、ID ではなくモードで引く)。
    let is = init_sessions.get(s2).expect("initiator session");
    let rs = resp_sessions
        .iter()
        .find(|s| matches!(s.mode(), SessionMode::Case { .. }))
        .expect("responder CASE session");
    assert_eq!(is.enc_key().unwrap(), rs.dec_key().unwrap());
    assert_eq!(is.dec_key().unwrap(), rs.enc_key().unwrap());
    assert_eq!(is.att_challenge().unwrap(), rs.att_challenge().unwrap());
    // 新 responder にもフル CASE の完了でレコードが作られる。
    assert_eq!(resp_mgr.handler().sc.resumption_count(), 1);
}

/// 改竄された Sigma2(TBEData2 の末尾 = AES-CCM タグを反転)を initiator が暗号的に拒否し、
/// `Failed(Case, Crypto)` を積むこと。unsecured パケットは外側 MIC を持たないため、ワイヤの
/// 末尾を反転しても transport は復号を通し、Sigma2 の TBEData2 復号(署名検証の前段)で弾かれる。
#[test]
fn case_corrupted_sigma2_is_rejected() {
    let crypto = crypto();
    let ids = build_identities(&crypto);
    let resp_table = device_table(&crypto, &ids, &[0x33; 32]);
    let init_table = controller_table(&crypto, &ids);
    let init_fabric = NonZeroU8::new(1).unwrap();

    // responder。
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let resp_creds = TestCreds {
        table: &resp_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let sc: SecureChannel<'_, Backend, SeqRng, _, 1> =
        SecureChannel::new(&crypto, SeqRng(0xD00D_2001), config, resp_creds);
    let mut resp_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(sc, ImPlaceholder));
    let mut resp_sessions: SessionManager<4> = SessionManager::new();
    resp_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut resp_pool: BufferPool<3, 1600> = BufferPool::new();

    // initiator。
    let init_creds = TestCreds {
        table: &init_table,
        crypto: &crypto,
        now: NOW_SECS,
    };
    let init = ScInitiator::new(&crypto, SeqRng(0xBEEF_2002), init_creds);
    let mut init_mgr: ExchangeManager<ProtocolMux<_, ImPlaceholder>, 4> =
        ExchangeManager::new(ProtocolMux::new(init, ImPlaceholder));
    let mut init_sessions: SessionManager<4> = SessionManager::new();
    let init_unsec = init_sessions
        .insert(SessionInit::plaintext(peer(), 0, 1), NOW)
        .unwrap();
    let mut init_pool: BufferPool<3, 1600> = BufferPool::new();

    let ex = init_mgr.open_initiator(init_unsec).unwrap();
    let reserved = init_sessions.reserve(peer(), NOW).unwrap();
    let init_ssid = init_sessions.get(reserved).unwrap().local_session_id();
    let mut payload = [0u8; 512];
    let plen = init_mgr
        .handler_mut()
        .sc
        .start_case(
            ex,
            reserved,
            init_ssid,
            init_fabric,
            DEVICE_NODE,
            &mut payload,
            NOW,
        )
        .unwrap();
    let sent = init_mgr
        .send_reliable(
            &mut init_sessions,
            &crypto,
            &mut init_pool,
            ex,
            &Outgoing {
                proto_id: 0x0000,
                opcode: OpCode::CaseSigma1 as u8,
                payload: &payload[..plen],
            },
            SendTiming {
                now_ms: NOW,
                jitter_rand: 0,
            },
        )
        .unwrap();
    let mut wire = [0u8; 1600];
    let wlen = sent.len;
    wire[..wlen].copy_from_slice(&init_pool.get(sent.buf).unwrap()[..wlen]);

    // responder が Sigma2 を生成 → 末尾バイトを反転して改竄する。
    let (mut s2wire, s2len) = deliver(
        &mut resp_mgr,
        &mut resp_sessions,
        &mut resp_pool,
        &crypto,
        NOW,
        peer(),
        &mut wire[..wlen],
    )
    .expect("responder produced Sigma2");
    // 末尾直前の TLV ContainerEnd(0x18)ではなく、その手前 = encrypted2 の AES-CCM タグ
    // 領域内を反転する(タグ不一致 → TBEData2 復号失敗 → Crypto)。
    s2wire[s2len - 8] ^= 0xFF;

    // initiator が改竄 Sigma2 を受理 → 暗号的に拒否し Failed を積む(応答は送らない)。
    let mut tx = [0u8; 1600];
    let report = init_mgr
        .recv(
            &mut init_sessions,
            &crypto,
            peer(),
            NOW,
            &mut s2wire[..s2len],
            &mut tx,
        )
        .unwrap();
    if let Some(b) = report.freed_tx {
        init_pool.release(b);
    }
    assert!(report.dispatched);
    assert_eq!(report.action, HandlerAction::None);

    match init_mgr.handler_mut().sc.take_event() {
        Some(ScEvent::Failed {
            kind: HandshakeKindTag::Case,
            reason: ScFailReason::Crypto,
        }) => {}
        other => panic!("expected Failed(Case, Crypto), got {other:?}"),
    }
    assert!(!init_sessions
        .iter()
        .any(|s| matches!(s.mode(), SessionMode::Case { .. })));
}
