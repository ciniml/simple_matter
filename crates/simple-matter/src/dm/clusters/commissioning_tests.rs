//! コミッショニングフローの統合テスト(`docs/design/interaction-model.md` §9)。
//!
//! IM エンジンの invoke 経路で
//! ArmFailSafe → CertificateChainRequest / AttestationRequest / CSRRequest →
//! AddTrustedRootCertificate → AddNOC → CommissioningComplete → RemoveFabric
//! を一連で駆動し、[`FabricTable`](crate::fabric::FabricTable) に fabric が
//! 増減することと、AddNOC で PASE セッションが確定 fabric へ昇格することを確認する。
//! NOC はテスト側(コミッショナ役)が CSR 応答の運用公開鍵から発行する。

use core::cell::RefCell;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::NonZeroU8;

use crate::acl::{AclHandle, AclTable};
use crate::cert::{self, dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioning, OpCredsCluster, TestDacProvider,
};
use crate::dm::meta::{DeviceType, EndpointId, EndpointMeta};
use crate::dm::{DataModel, ServerCluster};
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, Role, RxMessage};
use crate::im::engine::InteractionModel;
use crate::im::wire::{
    encode_invoke_request, CommandId, CommandPath, ImOpCode, InvokeRequestHeader,
    InvokeResponseRef, InvokeResponseRefItem,
};
use crate::im::wire::{AttributeId, ClusterId};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::header::{ExchFlags, PayloadHeader};
use crate::transport::net::PeerAddr;
use crate::transport::session::{SessionInit, SessionManager, SessionMode};

// ==========================================================================
// 決定的 crypto backend
// ==========================================================================

struct DummyRng;
impl Rng for DummyRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> crate::error::Result<()> {
        dest.iter_mut().for_each(|b| *b = 7);
        Ok(())
    }
}

type Crb = RustCrypto<DummyRng>;
type Dac = TestDacProvider<Crb>;
type Op = OpCredsCluster<Crb, Dac, 5>;

// ==========================================================================
// テスト用コミッショニングノード(EP0 のみ)
// ==========================================================================

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "TestVendor",
    vendor_id: 0xFFF1,
    product_name: "TestLight",
    product_id: 0x8000,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SN-0001",
};

/// テスト ACL 容量(5 fabric × per-fabric 上限相当に余裕)。
const NACL: usize = 8;

static COMM_EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static COMM_EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003E),
    ClusterId(0x0028),
    ClusterId(0x001D),
];
static COMM_EP0_PARTS: &[EndpointId] = &[];

/// EP0 のみのコミッショニングノード。fail-safe クリーンアップ検証のため ACL を持ち、
/// `device!` マクロではなく手書き [`DataModel`] で fail-safe フック(Core Spec §11.10)を配線する。
struct CommNode {
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    opcreds: Op,
    basic: BasicInformationCluster,
    desc: DescriptorCluster,
    acl: RefCell<AclTable<NACL>>,
    removed_fabric: Option<NonZeroU8>,
}

impl DataModel for CommNode {
    fn endpoints(&self) -> &[EndpointMeta] {
        static EPS: &[EndpointMeta] = &[EndpointMeta::new(
            EndpointId(0),
            COMM_EP0_DT,
            COMM_EP0_SERVERS,
        )];
        EPS
    }
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        match ep.0 {
            0 => COMM_EP0_SERVERS,
            _ => &[],
        }
    }
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x0030) => Some(&self.gc),
            (0, 0x0031) => Some(&self.net),
            (0, 0x003E) => Some(&self.opcreds),
            (0, 0x0028) => Some(&self.basic),
            (0, 0x001D) => Some(&self.desc),
            _ => None,
        }
    }
    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x0030) => Some(&mut self.gc),
            (0, 0x0031) => Some(&mut self.net),
            (0, 0x003E) => Some(&mut self.opcreds),
            (0, 0x0028) => Some(&mut self.basic),
            (0, 0x001D) => Some(&mut self.desc),
            _ => None,
        }
    }
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.gc.on_tick(now_ms) {
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        None
    }
    fn on_failsafe_cleanup(&mut self) -> Option<NonZeroU8> {
        self.gc.disarm();
        self.opcreds.on_failsafe_expired()
    }
    fn on_commissioning_complete(&mut self) {
        self.opcreds.on_commissioning_complete();
    }
    fn take_removed_fabric(&mut self) -> Option<NonZeroU8> {
        self.removed_fabric.take()
    }
    fn acl(&self) -> Option<&dyn AclHandle> {
        Some(&self.acl)
    }
}

impl CommNode {
    fn build() -> Self {
        let crypto = RustCrypto::new(DummyRng);
        let dac = TestDacProvider::new(&crypto).unwrap();
        CommNode {
            gc: GeneralCommissioning::default_config(),
            net: NetworkCommissioning::new(b"eth0"),
            opcreds: OpCredsCluster::new(RustCrypto::new(DummyRng), dac),
            basic: BasicInformationCluster::new(&CFG),
            desc: DescriptorCluster::new(
                EndpointId(0),
                COMM_EP0_DT,
                COMM_EP0_SERVERS,
                &[],
                COMM_EP0_PARTS,
            ),
            acl: RefCell::new(AclTable::new()),
            removed_fabric: None,
        }
    }
}

type Im = InteractionModel<CommNode, 2, 2, 8>;

// ==========================================================================
// ハーネス
// ==========================================================================

const EXCH_ID: u16 = 0x2222;
const CHALLENGE: [u8; 16] = [0x33u8; 16];

fn addr() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        5540,
    ))
}

/// PASE セッション(fabric 未確定)を 1 本張ったマネージャを返す。
fn setup() -> (Im, SessionManager<2>, ExchangeId) {
    let mut mgr: SessionManager<2> = SessionManager::new();
    let init = SessionInit {
        peer_addr: addr(),
        local_node_id: 1,
        peer_node_id: None,
        peer_session_id: 1,
        tx_ctr_start: 1,
        rx_ctr_start: 0,
        mode: SessionMode::Pase { fabric_idx: 0 },
        enc_key: [0u8; 16],
        dec_key: [0u8; 16],
        att_challenge: CHALLENGE,
    };
    let sid = mgr.insert(init, 0).unwrap();
    let ex = ExchangeId::from_parts(sid, EXCH_ID);
    (Im::new(CommNode::build()), mgr, ex)
}

fn phdr(opcode: u8) -> PayloadHeader {
    PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
        proto_opcode: opcode,
        exch_id: EXCH_ID,
        proto_id: 0x0001,
        vendor_id: None,
        ack_ctr: None,
    }
}

fn rxm<'a>(h: &'a PayloadHeader, payload: &'a [u8], ex: ExchangeId) -> RxMessage<'a> {
    RxMessage {
        header: h,
        payload,
        exchange: ex,
        role: Role::Responder,
    }
}

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// コマンドを invoke し、InvokeResponse バイト列を `out` に得て長さを返す。
#[allow(clippy::too_many_arguments)]
fn invoke<F>(
    im: &mut Im,
    mgr: &mut SessionManager<2>,
    ex: ExchangeId,
    cluster: u32,
    command: u32,
    now_ms: u64,
    fields: F,
    out: &mut [u8],
) -> usize
where
    F: FnOnce(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>,
{
    let mut req = [0u8; 640];
    let ilen = encode_invoke_request(&mut req, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &CommandPath::new(EndpointId(0), ClusterId(cluster), CommandId(command)),
            None,
            Some(fields),
        )
    })
    .unwrap();
    let ih = phdr(ImOpCode::InvokeRequest.to_u8());
    let a = im
        .handle(&rxm(&ih, &req[..ilen], ex), out, mgr, now_ms)
        .unwrap();
    match a {
        HandlerAction::Close { opcode, len, .. } | HandlerAction::Respond { opcode, len, .. } => {
            assert_eq!(opcode, ImOpCode::InvokeResponse.to_u8());
            len
        }
        HandlerAction::None | HandlerAction::CloseSilent => panic!("expected InvokeResponse"),
    }
}

/// InvokeResponse の単一 Command 応答から `(command_id, fields_raw)` を得る。
fn resp_command(msg: &[u8]) -> (u32, &[u8]) {
    let ir = InvokeResponseRef::new(msg).unwrap();
    let item = ir.invoke_responses().unwrap().next().unwrap().unwrap();
    match item {
        InvokeResponseRefItem::Command(c) => (c.path.command.0, c.fields.unwrap()),
        InvokeResponseRefItem::Status(s) => panic!("expected command, got {:?}", s.status.status),
    }
}

/// InvokeResponse の単一 Status 応答のステータス値を得る。
fn resp_status(msg: &[u8]) -> u8 {
    let ir = InvokeResponseRef::new(msg).unwrap();
    let item = ir.invoke_responses().unwrap().next().unwrap().unwrap();
    match item {
        InvokeResponseRefItem::Status(s) => s.status.status.to_u8(),
        InvokeResponseRefItem::Command(_) => panic!("expected status"),
    }
}

/// フィールド構造体(context タグ 1)から context タグ `tag` の octstr を得る。
fn field_bytes(fields: &[u8], tag: u8) -> Option<&[u8]> {
    struct_field(fields, tag, true).and_then(|v| match v {
        TlvValue::ByteString(b) => Some(b),
        _ => None,
    })
}

/// フィールド構造体から context タグ `tag` の符号なし整数を得る。
fn field_uint(fields: &[u8], tag: u8) -> Option<u64> {
    struct_field(fields, tag, true).and_then(|v| v.as_unsigned().ok())
}

/// 匿名/context 構造体の先頭を開き、指定 context タグの値を返す。
fn struct_field(bytes: &[u8], tag: u8, _outer: bool) -> Option<TlvValue<'_>> {
    let mut r = TlvReader::new(bytes);
    // 外枠の構造体開始。
    let head = r.read_next().ok()??;
    if !matches!(
        head.value,
        TlvValue::ContainerStart(ContainerType::Structure)
    ) {
        return None;
    }
    loop {
        let e = r.read_next().ok()??;
        match e.value {
            TlvValue::ContainerEnd => return None,
            v => {
                if e.tag == TlvTag::ContextSpecific(tag) {
                    return Some(v);
                }
            }
        }
    }
}

/// CSR DER から SEC1 非圧縮公開鍵(65 バイト)を抽出する(`03 42 00 04 ...` パターン)。
fn extract_pubkey(csr: &[u8]) -> [u8; 65] {
    for i in 0..csr.len().saturating_sub(4) {
        if csr[i] == 0x03 && csr[i + 1] == 0x42 && csr[i + 2] == 0x00 && csr[i + 3] == 0x04 {
            let mut pk = [0u8; 65];
            pk.copy_from_slice(&csr[i + 3..i + 3 + 65]);
            return pk;
        }
    }
    panic!("public key not found in CSR");
}

// ==========================================================================
// テスト用証明書ビルダ(cert/tests.rs の write_cert 相当。DER-TBS 方式で自己整合署名)
// ==========================================================================

const FABRIC_ID: u64 = 0xFAB1;
const NODE_ID: u64 = 0xAABB;
const RCAC_ID: u64 = 0xAAAA;
const RCAC_SKID: [u8; 20] = [0xA0; 20];
const NOC_SKID: [u8; 20] = [0xC0; 20];

fn write_dn(w: &mut TlvWriter, ctx: u8, attrs: &[(u8, u64)]) {
    w.start_list(&cx(ctx)).unwrap();
    for (tag, val) in attrs {
        w.write_u64(&cx(*tag), *val).unwrap();
    }
    w.end_container().unwrap();
}

#[allow(clippy::too_many_arguments)]
fn write_cert<K: P256Keypair>(
    out: &mut [u8],
    serial: &[u8],
    issuer: &[(u8, u64)],
    subject: &[(u8, u64)],
    subject_pub: &[u8; 65],
    is_ca: bool,
    ku: u16,
    eku: &[u8],
    skid: &[u8; 20],
    akid: &[u8; 20],
    issuer_kp: &K,
) -> usize {
    let len = {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), serial).unwrap();
        w.write_u8(&cx(2), 1).unwrap();
        write_dn(&mut w, 3, issuer);
        w.write_u32(&cx(4), 0).unwrap(); // not-before = 0(無期限下限)
        w.write_u32(&cx(5), 0).unwrap(); // not-after  = 0(無期限)
        write_dn(&mut w, 6, subject);
        w.write_u8(&cx(7), 1).unwrap();
        w.write_u8(&cx(8), 1).unwrap();
        w.write_bytes(&cx(9), subject_pub).unwrap();
        w.start_list(&cx(10)).unwrap();
        w.start_struct(&cx(1)).unwrap();
        w.write_bool(&cx(1), is_ca).unwrap();
        w.end_container().unwrap();
        w.write_u16(&cx(2), ku).unwrap();
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

// ==========================================================================
// フルフロー
// ==========================================================================

#[test]
fn full_commissioning_flow() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();
    let crypto = RustCrypto::new(DummyRng);
    let mut out = [0u8; 1024];

    // 1. ArmFailSafe(60s, breadcrumb=1)。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x0030,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), 60)?;
            w.write_u64(&cx(1), 1)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x01, "ArmFailSafeResponse");
    assert_eq!(field_uint(f, 0), Some(0), "errorCode OK");
    assert!(im.data_model().gc.fail_safe().is_armed());

    // 2. CertificateChainRequest(DAC)。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x02,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u8(&cx(0), 1)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x03, "CertificateChainResponse");
    assert!(field_bytes(f, 0).is_some(), "DAC certificate returned");

    // 3. AttestationRequest(nonce)。署名を DAC 公開鍵で検証する。
    let nonce = [0x11u8; 32];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &nonce)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x01, "AttestationResponse");
    let elems = field_bytes(f, 0).unwrap();
    let att_sig = field_bytes(f, 1).unwrap();
    {
        // sig は DAC 秘密鍵で (elements || attestationChallenge) を署名したもの。
        let dac = TestDacProvider::new(&crypto).unwrap();
        let mut msg = [0u8; 768];
        msg[..elems.len()].copy_from_slice(elems);
        msg[elems.len()..elems.len() + 16].copy_from_slice(&CHALLENGE);
        let key = crypto
            .p256_public_key_from_bytes(&dac.dac_public_key())
            .unwrap();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(att_sig);
        assert!(
            key.verify(&msg[..elems.len() + 16], &sig).unwrap(),
            "attestation signature verifies against DAC public key"
        );
    }

    // 4. CSRRequest → 運用公開鍵を CSR から抽出。
    let csr_nonce = [0x22u8; 32];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &csr_nonce)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x05, "CSRResponse");
    let nocsr = field_bytes(f, 0).unwrap();
    // NOCSRElements(struct){ 1: csr, 2: nonce }。
    let csr = field_bytes(nocsr, 1).unwrap();
    assert_eq!(field_bytes(nocsr, 2), Some(&csr_nonce[..]));
    let op_pub = extract_pubkey(csr);

    // 5. コミッショナ役: RCAC(自己署名)と NOC(op_pub, RCAC 発行)を作る。
    let root_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
    let root_pub = root_kp.public_key().to_bytes();
    let mut rcac = [0u8; 400];
    let rcac_len = write_cert(
        &mut rcac,
        &[0x01],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &root_pub,
        true,
        key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
        &[],
        &RCAC_SKID,
        &RCAC_SKID,
        &root_kp,
    );
    let mut noc = [0u8; 400];
    let noc_len = write_cert(
        &mut noc,
        &[0x02],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_NODE_ID, NODE_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &op_pub,
        false,
        key_usage::DIGITAL_SIGNATURE,
        &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
        &NOC_SKID,
        &RCAC_SKID,
        &root_kp,
    );

    // 6. AddTrustedRootCertificate。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x0B,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &rcac[..rcac_len])?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_status(&out[..len]), 0, "AddTrustedRoot success");

    // 7. AddNOC。
    let ipk = [0x44u8; 16];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x06,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &noc[..noc_len])?;
            w.write_bytes(&cx(2), &ipk)?;
            w.write_u64(&cx(3), 0x0000_0000_0000_0001)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x08, "NOCResponse");
    assert_eq!(field_uint(f, 0), Some(0), "statusCode OK");
    assert_eq!(field_uint(f, 1), Some(1), "fabricIndex 1");

    // FabricTable に fabric が増えた。
    assert_eq!(im.data_model().opcreds.fabrics().len(), 1);
    // PASE セッションが fabric 1 へ昇格した。
    assert_eq!(
        mgr.get(sid).unwrap().mode(),
        SessionMode::Pase { fabric_idx: 1 }
    );

    // 8. CommissioningComplete。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x0030,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x05, "CommissioningCompleteResponse");
    assert_eq!(field_uint(f, 0), Some(0), "errorCode OK");
    assert!(
        !im.data_model().gc.fail_safe().is_armed(),
        "fail-safe disarmed"
    );

    // 9. RemoveFabric(index 1)。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x0A,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u8(&cx(0), 1)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x08, "NOCResponse");
    assert_eq!(field_uint(f, 0), Some(0), "RemoveFabric OK");
    assert_eq!(im.data_model().opcreds.fabrics().len(), 0, "fabric removed");
}

// ==========================================================================
// 個別クラスタの単体確認
// ==========================================================================

#[test]
fn add_noc_without_trusted_root_fails() {
    let (mut im, mut mgr, ex) = setup();
    let mut out = [0u8; 512];
    // CSR を先に呼び pending 鍵を用意する。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &[0x22u8; 32])?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x05);
    // AddTrustedRoot を呼ばずに AddNOC → InvalidNOC(3)。
    let noc = [0u8; 4];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x06,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &noc)?;
            w.write_bytes(&cx(2), &[0x44u8; 16])?;
            w.write_u64(&cx(3), 1)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut out,
    );
    let (_, f) = resp_command(&out[..len]);
    assert_eq!(field_uint(f, 0), Some(3), "InvalidNOC (no trusted root)");
    assert_eq!(im.data_model().opcreds.fabrics().len(), 0);
}

/// AddNOC の ICAC フィールドの送出形態。
#[derive(Clone, Copy)]
enum IcacField {
    /// 空オクテット列 `cx(1)=[]` を含める(Apple Home が ICAC 不使用時に送る形)。
    Empty,
    /// ICAC フィールドを省略する。
    Omitted,
}

/// ArmFailSafe → CSR → AddTrustedRoot → AddNOC を実行し、AddNOC の statusCode を返す。
/// `icac` で ICAC フィールドの送出形態(空フィールド / 省略)を切り替える。NOC は RCAC 直下発行。
fn commission_and_add_noc(
    im: &mut Im,
    mgr: &mut SessionManager<2>,
    ex: ExchangeId,
    crypto: &RustCrypto<DummyRng>,
    icac: IcacField,
) -> u64 {
    let mut out = [0u8; 1024];
    // ArmFailSafe。
    let len = invoke(
        im,
        mgr,
        ex,
        0x0030,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), 60)?;
            w.write_u64(&cx(1), 1)?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x01, "ArmFailSafeResponse");

    // CSRRequest → 運用公開鍵。
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &[0x22u8; 32])?;
            w.end_container()
        },
        &mut out,
    );
    let (_, f) = resp_command(&out[..len]);
    let nocsr = field_bytes(f, 0).unwrap();
    let csr = field_bytes(nocsr, 1).unwrap();
    let op_pub = extract_pubkey(csr);

    // RCAC(自己署名)と NOC(op_pub, RCAC 直下発行)。
    let root_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
    let root_pub = root_kp.public_key().to_bytes();
    let mut rcac = [0u8; 400];
    let rcac_len = write_cert(
        &mut rcac,
        &[0x01],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &root_pub,
        true,
        key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
        &[],
        &RCAC_SKID,
        &RCAC_SKID,
        &root_kp,
    );
    let mut noc = [0u8; 400];
    let noc_len = write_cert(
        &mut noc,
        &[0x02],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_NODE_ID, NODE_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &op_pub,
        false,
        key_usage::DIGITAL_SIGNATURE,
        &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
        &NOC_SKID,
        &RCAC_SKID,
        &root_kp,
    );

    // AddTrustedRootCertificate。
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x0B,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &rcac[..rcac_len])?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_status(&out[..len]), 0, "AddTrustedRoot success");

    // AddNOC。ICAC フィールドは icac に従い空フィールド / 省略で送る。
    let ipk = [0x44u8; 16];
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x06,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &noc[..noc_len])?;
            if let IcacField::Empty = icac {
                // ICAC 不使用でも空オクテット列でフィールドを送るコミッショナ(Apple Home)を模す。
                w.write_bytes(&cx(1), &[])?;
            }
            w.write_bytes(&cx(2), &ipk)?;
            w.write_u64(&cx(3), 0x0000_0000_0000_0001)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut out,
    );
    let (rid, f) = resp_command(&out[..len]);
    assert_eq!(rid, 0x08, "NOCResponse");
    field_uint(f, 0).expect("statusCode present")
}

/// 実機回帰(Apple Home): AddNOC で ICAC 不使用時にコミッショナが ICACValue を空オクテット列で
/// 送ってくる。修正前は空スライスを証明書としてパースして InvalidNOC で失敗していた。
/// 空 ICAC フィールド版と、対照の ICAC 省略版の双方が statusCode OK(0)で fabric を 1 つ増やす。
#[test]
fn add_noc_with_empty_icac_field_succeeds() {
    // 空 ICAC フィールド `cx(1)=[]` を含める版。
    {
        let (mut im, mut mgr, ex) = setup();
        let crypto = RustCrypto::new(DummyRng);
        let status = commission_and_add_noc(&mut im, &mut mgr, ex, &crypto, IcacField::Empty);
        assert_eq!(status, 0, "AddNOC statusCode OK with empty ICAC field");
        assert_eq!(
            im.data_model().opcreds.fabrics().len(),
            1,
            "fabric added (empty ICAC field)"
        );
    }
    // 対照: ICAC フィールドを省略した版。
    {
        let (mut im, mut mgr, ex) = setup();
        let crypto = RustCrypto::new(DummyRng);
        let status = commission_and_add_noc(&mut im, &mut mgr, ex, &crypto, IcacField::Omitted);
        assert_eq!(status, 0, "AddNOC statusCode OK with ICAC omitted");
        assert_eq!(
            im.data_model().opcreds.fabrics().len(),
            1,
            "fabric added (ICAC omitted)"
        );
    }
}

#[test]
fn network_commissioning_reads_ethernet_networks() {
    let dev = CommNode::build();
    use crate::dm::codec::AttrEncoder;
    use crate::dm::meta::{Privilege, SessionKind};
    use crate::dm::DataModel;
    fn acc() -> crate::dm::meta::AccessContext {
        crate::dm::meta::AccessContext::new(SessionKind::Case, None, 0, Privilege::Administer)
    }
    let sc = dev.cluster(EndpointId(0), ClusterId(0x0031)).unwrap();
    assert_eq!(sc.meta().feature_map, 0x04, "Ethernet feature");
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        sc.read_attribute(AttributeId(0x0000), &mut enc, &acc())
            .unwrap(); // MaxNetworks
    }
    assert_eq!(
        TlvReader::new(&buf).read_next().unwrap().unwrap().value,
        TlvValue::UnsignedInteger(1)
    );
}

// ==========================================================================
// fail-safe 仕様準拠クリーンアップ(Core Spec §11.10)
// ==========================================================================

/// ArmFailSafe(arm_expiry_s) → CSR → AddTrustedRoot → AddNOC を実行し、fabric を 1 つ追加した
/// 状態にする(クリーンアップ検証の前準備。fail-safe は張られたまま = 未 CommissioningComplete)。
fn commission_to_addnoc(
    im: &mut Im,
    mgr: &mut SessionManager<2>,
    ex: ExchangeId,
    crypto: &RustCrypto<DummyRng>,
    arm_expiry_s: u16,
) {
    let mut out = [0u8; 1024];
    // ArmFailSafe。
    let len = invoke(
        im,
        mgr,
        ex,
        0x0030,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), arm_expiry_s)?;
            w.write_u64(&cx(1), 1)?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x01, "ArmFailSafeResponse");

    // CSRRequest → 運用公開鍵。
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &[0x22u8; 32])?;
            w.end_container()
        },
        &mut out,
    );
    let (_, f) = resp_command(&out[..len]);
    let nocsr = field_bytes(f, 0).unwrap();
    let csr = field_bytes(nocsr, 1).unwrap();
    let op_pub = extract_pubkey(csr);

    // RCAC(自己署名)と NOC(op_pub, RCAC 発行)。
    let root_kp = crypto.p256_keypair_from_bytes(&[0x11; 32]).unwrap();
    let root_pub = root_kp.public_key().to_bytes();
    let mut rcac = [0u8; 400];
    let rcac_len = write_cert(
        &mut rcac,
        &[0x01],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &root_pub,
        true,
        key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
        &[],
        &RCAC_SKID,
        &RCAC_SKID,
        &root_kp,
    );
    let mut noc = [0u8; 400];
    let noc_len = write_cert(
        &mut noc,
        &[0x02],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_NODE_ID, NODE_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &op_pub,
        false,
        key_usage::DIGITAL_SIGNATURE,
        &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
        &NOC_SKID,
        &RCAC_SKID,
        &root_kp,
    );

    // AddTrustedRootCertificate。
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x0B,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &rcac[..rcac_len])?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_status(&out[..len]), 0, "AddTrustedRoot success");

    // AddNOC(caseAdminSubject=1 → ACL bootstrap admin エントリが 1 つ入る)。
    let ipk = [0x44u8; 16];
    let len = invoke(
        im,
        mgr,
        ex,
        0x003E,
        0x06,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &noc[..noc_len])?;
            w.write_bytes(&cx(2), &ipk)?;
            w.write_u64(&cx(3), 0x0000_0000_0000_0001)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut out,
    );
    let (_, f) = resp_command(&out[..len]);
    assert_eq!(field_uint(f, 0), Some(0), "AddNOC OK");
    assert_eq!(im.data_model().opcreds.fabrics().len(), 1, "fabric added");
}

/// (a) AddNOC 後・CommissioningComplete 前に ArmFailSafe(0) → fabric / ACL / pending が巻き戻る。
#[test]
fn armfailsafe_zero_rolls_back_uncommitted_commissioning() {
    let (mut im, mut mgr, ex) = setup();
    let crypto = RustCrypto::new(DummyRng);
    commission_to_addnoc(&mut im, &mut mgr, ex, &crypto, 60);
    // AddNOC の caseAdminSubject で bootstrap admin ACL エントリが 1 つ入っている。
    assert_eq!(
        im.data_model().acl.borrow().len(),
        1,
        "case_admin ACL entry present after AddNOC"
    );

    // ArmFailSafe(expiry=0)。
    let mut out = [0u8; 512];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x0030,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), 0)?;
            w.write_u64(&cx(1), 0)?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x01, "ArmFailSafeResponse");

    assert_eq!(
        im.data_model().opcreds.fabrics().len(),
        0,
        "fabric rolled back"
    );
    assert_eq!(
        im.data_model().acl.borrow().len(),
        0,
        "ACL entries purged for removed fabric"
    );
    assert!(
        !im.data_model().gc.fail_safe().is_armed(),
        "fail-safe disarmed"
    );

    // pending も破棄されている: 直後の AddNOC(root/CSR なし)は InvalidNOC。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x003E,
        0x06,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &[0u8; 4])?;
            w.write_bytes(&cx(2), &[0x44u8; 16])?;
            w.write_u64(&cx(3), 1)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut out,
    );
    let (_, f) = resp_command(&out[..len]);
    assert_eq!(field_uint(f, 0), Some(3), "InvalidNOC (pending cleared)");
}

/// (b) AddNOC 後にタイマ期限経過 → 同様に巻き戻る(ACL・当該 fabric セッション close 込み)。
#[test]
fn failsafe_timer_expiry_rolls_back_uncommitted_commissioning() {
    let (mut im, mut mgr, ex) = setup();
    let crypto = RustCrypto::new(DummyRng);
    commission_to_addnoc(&mut im, &mut mgr, ex, &crypto, 60);
    assert_eq!(im.data_model().opcreds.fabrics().len(), 1);
    assert_eq!(im.data_model().acl.borrow().len(), 1);
    // AddNOC で PASE セッションは fabric 1 へ昇格済み。
    assert_eq!(
        mgr.get(ex.session()).unwrap().mode(),
        SessionMode::Pase { fabric_idx: 1 }
    );

    // fail-safe deadline = 60s。タイマ経過を模す(stack.drive_ticks 相当)。
    im.data_model_mut().on_tick(60_001);
    let idx = im
        .data_model_mut()
        .take_removed_fabric()
        .expect("fabric removed on failsafe timer expiry");
    im.purge_fabric(idx, None, &mut mgr);

    assert_eq!(
        im.data_model().opcreds.fabrics().len(),
        0,
        "fabric rolled back on timer"
    );
    assert_eq!(
        im.data_model().acl.borrow().len(),
        0,
        "ACL entries purged on timer"
    );
    assert!(
        mgr.get(ex.session()).is_none(),
        "promoted session closed on timer cleanup"
    );
}

/// (c) CommissioningComplete 完了後は fail-safe 経過/ArmFailSafe(0) でも fabric が残る。
#[test]
fn commissioning_complete_makes_fabric_survive_failsafe() {
    let (mut im, mut mgr, ex) = setup();
    let crypto = RustCrypto::new(DummyRng);
    commission_to_addnoc(&mut im, &mut mgr, ex, &crypto, 60);

    // CommissioningComplete で fabric 確定。
    let mut out = [0u8; 512];
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x0030,
        0x04,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x05, "CommissioningComplete");

    // 再 ArmFailSafe(60) → ArmFailSafe(0): 確定済みなので fabric は残る。
    for expiry in [60u16, 0u16] {
        let len = invoke(
            &mut im,
            &mut mgr,
            ex,
            0x0030,
            0x00,
            0,
            |w, t| {
                w.start_struct(t)?;
                w.write_u16(&cx(0), expiry)?;
                w.write_u64(&cx(1), 0)?;
                w.end_container()
            },
            &mut out,
        );
        assert_eq!(resp_command(&out[..len]).0, 0x01);
    }
    assert_eq!(
        im.data_model().opcreds.fabrics().len(),
        1,
        "fabric kept after CommissioningComplete + ArmFailSafe(0)"
    );

    // タイマ経過でも残る。
    let len = invoke(
        &mut im,
        &mut mgr,
        ex,
        0x0030,
        0x00,
        0,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), 60)?;
            w.write_u64(&cx(1), 0)?;
            w.end_container()
        },
        &mut out,
    );
    assert_eq!(resp_command(&out[..len]).0, 0x01);
    im.data_model_mut().on_tick(60_001);
    assert!(
        im.data_model_mut().take_removed_fabric().is_none(),
        "no fabric removed after CommissioningComplete"
    );
    assert_eq!(im.data_model().opcreds.fabrics().len(), 1);
}

#[test]
fn write_csr_roundtrips_public_key() {
    let crypto = RustCrypto::new(DummyRng);
    let kp = crypto.p256_generate_keypair().unwrap();
    let mut csr = [0u8; cert::MAX_CSR_DER_LEN];
    let n = cert::write_csr(&kp, &mut csr).unwrap();
    let pk = extract_pubkey(&csr[..n]);
    assert_eq!(
        pk,
        kp.public_key().to_bytes(),
        "CSR carries operational public key"
    );
}
