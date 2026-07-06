//! コミッショニングフローの統合テスト(`docs/design/interaction-model.md` §9)。
//!
//! IM エンジンの invoke 経路で
//! ArmFailSafe → CertificateChainRequest / AttestationRequest / CSRRequest →
//! AddTrustedRootCertificate → AddNOC → CommissioningComplete → RemoveFabric
//! を一連で駆動し、[`FabricTable`](crate::fabric::FabricTable) に fabric が
//! 増減することと、AddNOC で PASE セッションが確定 fabric へ昇格することを確認する。
//! NOC はテスト側(コミッショナ役)が CSR 応答の運用公開鍵から発行する。

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::cert::{self, dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioning, OpCredsCluster, TestDacProvider,
};
use crate::dm::meta::EndpointId;
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

struct CommNode {
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    opcreds: Op,
    basic: BasicInformationCluster,
    desc: DescriptorCluster,
}

crate::device! {
    CommNode {
        endpoint 0 {
            device_types: [ (0x0016, 1) ],
            parts: [],
            clusters: [
                (0x0030, gc), (0x0031, net), (0x003E, opcreds),
                (0x0028, basic), (0x001D, desc)
            ],
        }
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
                CommNode::device_types(EndpointId(0)),
                CommNode::server_list(EndpointId(0)),
                &[],
                CommNode::parts(EndpointId(0)),
            ),
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

#[test]
fn network_commissioning_reads_ethernet_networks() {
    let dev = CommNode::build();
    use crate::dm::codec::AttrEncoder;
    use crate::dm::DataModel;
    let sc = dev.cluster(EndpointId(0), ClusterId(0x0031)).unwrap();
    assert_eq!(sc.meta().feature_map, 0x04, "Ethernet feature");
    let mut buf = [0u8; 64];
    let mut w = TlvWriter::new(&mut buf);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        sc.read_attribute(AttributeId(0x0000), &mut enc).unwrap(); // MaxNetworks
    }
    assert_eq!(
        TlvReader::new(&buf).read_next().unwrap().unwrap().value,
        TlvValue::UnsignedInteger(1)
    );
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
