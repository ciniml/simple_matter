//! 統合層(`stack`)のエンドツーエンド縦通しテスト(On/Off ライト)。
//!
//! **実 UDP を使わずメモリ内で**、コミッショナ(client)役と [`MatterStack`] を
//! **メッセージバイト列レベル**(= [`SecureCodec`] の暗号化込み)で結合し、
//!
//! - (a) Unsecured セッションで PASE ハンドシェイク完走 → PASE セッション確立
//! - (b) PASE セッション上で IM が機能する(コミッショニングクラスタ Read)。OnOff の
//!   invoke は PASE では ACL(`is_commissioning_cluster`)で拒否されることを確認
//! - (c) フルコミッショニング(ArmFailSafe → … → AddNOC → CommissioningComplete)
//! - (d) CASE ハンドシェイク完走 → CASE セッション上で OnOff invoke(On)→ 属性変化を Read
//!
//! を検証する。これが「On/Off ライト縦通し」の証明である。
//!
//! # タスクからの乖離(理由付き)
//!
//! タスク (b) は「PASE セッション上で OnOff invoke」を求めるが、第5段階の IM ACL
//! (`is_commissioning_cluster`)は PASE セッションを **コミッショニング必須クラスタ**
//! (Basic Info / General・Network Commissioning / OpCreds)に限定する。既存挙動を
//! 変えない(217 テスト維持)ため、OnOff の invoke→変化→Read は **CASE(運用)セッション上**
//! で検証し(実 Matter の運用経路と一致)、PASE 上では (1) コミッショニングクラスタ Read が
//! 通ること、(2) OnOff invoke が `UnsupportedAccess` で拒否されること、を確認する。

use core::cell::RefCell;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::NonZeroU8;

use crate::cert::{dn_attr, ext_key_usage, key_usage, MatterCert, MAX_TBS_DER_LEN};
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::spake2p::Spake2pProver;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, Rng, Sha256};
use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioning, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use crate::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use crate::dm::{DataModel, ServerCluster};
use crate::fabric::FabricTable;
use crate::im::engine::InteractionModel;
use crate::im::wire::{
    encode_invoke_request, encode_read_request, AttributeId, AttributePath, AttributeReportRef,
    CommandId, CommandPath, ImOpCode, InvokeRequestHeader, InvokeResponseRef,
    InvokeResponseRefItem, ReportDataRef,
};
use crate::sc::case::responder as case;
use crate::sc::pase::{build_context, SPAKE2P_SESSION_KEYS_INFO};
use crate::sc::{PaseConfig, SecureChannel};
use crate::stack::{MatterStack, SharedFabricCreds};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, PayloadHeader, SecFlags};
use crate::transport::net::PeerAddr;
use crate::transport::secure::SecureCodec;
use crate::transport::session::SessionMode;
use crate::transport::util::{ParseBuf, WriteBuf};

type Result<T> = crate::error::Result<T>;

// ==========================================================================
// 決定的 crypto backend
// ==========================================================================

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
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

type Crb = RustCrypto<SeqRng>;
type Dac = TestDacProvider<Crb>;
type Op<'s> = OpCredsCluster<Crb, Dac, 5, &'s RefCell<FabricTable<Crb, 5>>>;
type TestStack<'s> = MatterStack<'s, Crb, SeqRng, Dev<'s>, 5, 4, 4, 8, 1, 2, 3, 8>;

const PASSCODE: u32 = 20202021;
const ITERATIONS: u32 = 1000;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const FABRIC_ID: u64 = 0xFAB1;
const DEVICE_NODE: u64 = 0xAABB;
const COMM_NODE: u64 = 0x1122;
const RCAC_ID: u64 = 0xAAAA;
const RCAC_SKID: [u8; 20] = [0xA0; 20];
const NOC_SKID: [u8; 20] = [0xC0; 20];
const COMM_SKID: [u8; 20] = [0xB0; 20];
const IPK: [u8; 16] = [0x44u8; 16];
const NOW: u64 = 1000;

// ==========================================================================
// テストデバイス(EP0: 必須クラスタ / EP1: On/Off + Descriptor)
// ==========================================================================

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "TestVendor",
    vendor_id: 0xFFF1,
    product_name: "OnOffLight",
    product_id: 0x8000,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SN-0001",
};

static EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x0028),
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003E),
    ClusterId(0x001D),
];
static EP1_SERVERS: &[ClusterId] = &[ClusterId(0x0006), ClusterId(0x001D)];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
static EP0_PARTS: &[EndpointId] = &[EndpointId(1)];
static EP1_PARTS: &[EndpointId] = &[];

/// On/Off ライトデバイス。OpCreds は外部所有の `RefCell<FabricTable>` を共有する(CASE と共用)。
struct Dev<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    opcreds: Op<'s>,
    desc0: DescriptorCluster,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
}

// device! マクロはライフタイム付きデバイスに使えないため DataModel を手書きする(乖離)。
impl DataModel for Dev<'_> {
    fn endpoints(&self) -> &[EndpointMeta] {
        static EPS: &[EndpointMeta] = &[
            EndpointMeta::new(EndpointId(0), EP0_DT, EP0_SERVERS),
            EndpointMeta::new(EndpointId(1), EP1_DT, EP1_SERVERS),
        ];
        EPS
    }

    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        match ep.0 {
            0 => EP0_SERVERS,
            1 => EP1_SERVERS,
            _ => &[],
        }
    }

    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x0028) => Some(&self.basic),
            (0, 0x0030) => Some(&self.gc),
            (0, 0x0031) => Some(&self.net),
            (0, 0x003E) => Some(&self.opcreds),
            (0, 0x001D) => Some(&self.desc0),
            (1, 0x0006) => Some(&self.onoff),
            (1, 0x001D) => Some(&self.desc1),
            _ => None,
        }
    }

    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x0028) => Some(&mut self.basic),
            (0, 0x0030) => Some(&mut self.gc),
            (0, 0x0031) => Some(&mut self.net),
            (0, 0x003E) => Some(&mut self.opcreds),
            (0, 0x001D) => Some(&mut self.desc0),
            (1, 0x0006) => Some(&mut self.onoff),
            (1, 0x001D) => Some(&mut self.desc1),
            _ => None,
        }
    }

    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.gc.on_tick(now_ms) {
            self.opcreds.on_failsafe_expired();
        }
        None
    }
}

fn build_device(fabrics: &RefCell<FabricTable<Crb, 5>>) -> Dev<'_> {
    let dac_crypto = RustCrypto::new(SeqRng(0xDAC0_0001));
    let dac = TestDacProvider::new(&dac_crypto).unwrap();
    Dev {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(SeqRng(0x00C0_0001)), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new(),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

// ==========================================================================
// ワイヤ(バイト列)ヘルパ:client 役の暗号往復
// ==========================================================================

fn peer() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        5540,
    ))
}

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// client → device の 1 メッセージをワイヤ化して `out` に書き、長さを返す。
#[allow(clippy::too_many_arguments)]
fn build_msg(
    crypto: &Crb,
    session_id: u16,
    key: Option<&[u8; 16]>,
    src_node: u64,
    proto_id: u16,
    opcode: u8,
    exch: u16,
    ctr: u32,
    ack: Option<u32>,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let pkt = PacketHeader {
        session_id,
        sec_flags: SecFlags::from_bits(0),
        ctr,
        src_node_id: None,
        dst: DstNodeId::None,
    };
    let phdr = PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
        proto_opcode: opcode,
        exch_id: exch,
        proto_id,
        vendor_id: None,
        ack_ctr: ack,
    };
    let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
    let mut store = [0u8; 1700];
    let mut w = WriteBuf::new(&mut store, headroom).unwrap();
    w.append(payload).unwrap();
    SecureCodec::encrypt(crypto, key, &pkt, &phdr, src_node, &mut w).unwrap();
    let n = w.len();
    out[..n].copy_from_slice(w.as_slice());
    n
}

/// device → client の応答ワイヤを復号し、(proto_opcode, payload を `out` にコピーした長さ, pkt ctr)。
fn decode_resp(
    crypto: &Crb,
    wire: &mut [u8],
    key: Option<&[u8; 16]>,
    src_node: u64,
    out: &mut [u8],
) -> (u8, usize, u32) {
    let mut pb = ParseBuf::new(wire);
    let pkt = PacketHeader::decode(&mut pb).unwrap();
    let phdr = SecureCodec::decrypt(crypto, key, &pkt, src_node, &mut pb).unwrap();
    let payload = pb.as_slice();
    out[..payload.len()].copy_from_slice(payload);
    (phdr.proto_opcode, payload.len(), pkt.ctr)
}

/// PASE 上でコマンドを invoke し、InvokeResponse を `out` に得て長さを返す。
#[allow(clippy::too_many_arguments)]
fn pase_invoke<F>(
    stack: &mut TestStack<'_>,
    crypto: &Crb,
    device_sid: u16,
    i2r: &[u8; 16],
    r2i: &[u8; 16],
    cluster: u32,
    command: u32,
    ctr: &mut u32,
    ack: &mut Option<u32>,
    fields: F,
    out: &mut [u8],
) -> usize
where
    F: FnOnce(&mut TlvWriter, &TlvTag) -> Result<()>,
{
    let mut fbuf = [0u8; 900];
    let ilen = encode_invoke_request(&mut fbuf, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &CommandPath::new(EndpointId(0), ClusterId(cluster), CommandId(command)),
            None,
            Some(fields),
        )
    })
    .unwrap();
    let mut wire = [0u8; 1700];
    let n = build_msg(
        crypto,
        device_sid,
        Some(i2r),
        0,
        0x0001,
        ImOpCode::InvokeRequest.to_u8(),
        0x0022,
        *ctr,
        *ack,
        &fbuf[..ilen],
        &mut wire,
    );
    *ctr += 1;
    let mut tx = [0u8; 1700];
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, rlen, dctr) = decode_resp(crypto, &mut tx[..dir.len], Some(r2i), 0, out);
    assert_eq!(op, ImOpCode::InvokeResponse.to_u8());
    *ack = Some(dctr);
    rlen
}

// ==========================================================================
// テスト用証明書ビルダ(commissioning_tests.rs と同方式)
// ==========================================================================

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
        w.write_u32(&cx(4), 0).unwrap();
        w.write_u32(&cx(5), 0).unwrap();
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

// --- InvokeResponse / TLV 取り出しヘルパ ---

fn resp_command_id(msg: &[u8]) -> u32 {
    let ir = InvokeResponseRef::new(msg).unwrap();
    match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
        InvokeResponseRefItem::Command(c) => c.path.command.0,
        InvokeResponseRefItem::Status(s) => panic!("expected command, got {:?}", s.status.status),
    }
}

fn resp_fields(msg: &[u8], out: &mut [u8]) -> usize {
    let ir = InvokeResponseRef::new(msg).unwrap();
    match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
        InvokeResponseRefItem::Command(c) => {
            let f = c.fields.unwrap();
            out[..f.len()].copy_from_slice(f);
            f.len()
        }
        InvokeResponseRefItem::Status(_) => panic!("expected command"),
    }
}

fn resp_status(msg: &[u8]) -> u8 {
    let ir = InvokeResponseRef::new(msg).unwrap();
    match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
        InvokeResponseRefItem::Status(s) => s.status.status.to_u8(),
        InvokeResponseRefItem::Command(_) => panic!("expected status"),
    }
}

fn field_uint(fields: &[u8], tag: u8) -> Option<u64> {
    struct_field(fields, tag).and_then(|v| v.as_unsigned().ok())
}

/// 構造体 `fields` の context タグ `tag` の octstr を `out` にコピーし長さを返す。
fn field_bytes(fields: &[u8], tag: u8, out: &mut [u8]) -> Option<usize> {
    match struct_field(fields, tag)? {
        TlvValue::ByteString(b) => {
            out[..b.len()].copy_from_slice(b);
            Some(b.len())
        }
        _ => None,
    }
}

fn struct_field(bytes: &[u8], tag: u8) -> Option<TlvValue<'_>> {
    let mut r = TlvReader::new(bytes);
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

fn single_ctx1(field: &[u8], out: &mut [u8]) -> usize {
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

/// Sigma2 を解析: (responder_random, responder_ssid, responder_eph_pub, enc2_buf, enc2_len)。
fn parse_sigma2(payload: &[u8]) -> ([u8; 32], u16, [u8; 65], [u8; 1024], usize) {
    let mut r = TlvReader::new(payload);
    r.enter_container().unwrap();
    let rr = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
    let ssid = r.read_next().unwrap().unwrap().value.as_unsigned().unwrap() as u16;
    let epk = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
    let enc = r.read_next().unwrap().unwrap().value.as_bytes().unwrap();
    let mut rr_a = [0u8; 32];
    rr_a.copy_from_slice(rr);
    let mut epk_a = [0u8; 65];
    epk_a.copy_from_slice(epk);
    let mut enc_a = [0u8; 1024];
    enc_a[..enc.len()].copy_from_slice(enc);
    (rr_a, ssid, epk_a, enc_a, enc.len())
}

// ==========================================================================
// フル縦通しテスト
// ==========================================================================

#[test]
fn onoff_light_end_to_end() {
    // 外部所有:crypto(SC/creds/stack が借用)と fabric テーブル(OpCreds/CASE が共有)。
    let crypto = RustCrypto::new(SeqRng(0xC0FF_EE00_1234_5678));
    let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0001), config, creds);
    let im = InteractionModel::new(build_device(&fabrics));
    let mut stack: TestStack = MatterStack::new(&crypto, sc, im);

    let mut tx = [0u8; 1700];
    let mut wire = [0u8; 1700];
    let mut pl = [0u8; 1024];
    let mut req = [0u8; 1024];

    let mut unsec_ctr = 1u32; // unsecured セッション上の client 送信カウンタ(PASE + CASE 共有)

    // ================= (a) PASE ハンドシェイク =================

    // 1) PBKDFParamRequest → PBKDFParamResponse
    let ir = [0x11u8; 32];
    let plen = {
        let mut w = TlvWriter::new(&mut pl);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), &ir).unwrap();
        w.write_u16(&cx(2), 0x1111).unwrap();
        w.write_u16(&cx(3), 0).unwrap();
        w.write_bool(&cx(4), false).unwrap();
        w.end_container().unwrap();
        w.len()
    };
    let n = build_msg(
        &crypto,
        0,
        None,
        0,
        0x0000,
        0x20,
        0x0011,
        unsec_ctr,
        None,
        &pl[..plen],
        &mut wire,
    );
    unsec_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, resp_len, dctr) = decode_resp(&crypto, &mut tx[..dir.len], None, 0, &mut req);
    assert_eq!(op, 0x21, "PBKDFParamResponse");

    let mut context = [0u8; 32];
    build_context(&crypto, &pl[..plen], &req[..resp_len], &mut context);
    let device_sid = resp_ssid(&req[..resp_len]);
    let mut pake_ack = Some(dctr);

    // 2) PASEPake1 → PASEPake2
    let mut prover_rng = SeqRng(0x1122_3344);
    let prover =
        Spake2pProver::from_passcode(&mut prover_rng, PASSCODE, &SALT, ITERATIONS).unwrap();
    let pa = *prover.share();
    let plen = single_ctx1(&pa, &mut pl);
    let n = build_msg(
        &crypto,
        0,
        None,
        0,
        0x0000,
        0x22,
        0x0011,
        unsec_ctr,
        pake_ack,
        &pl[..plen],
        &mut wire,
    );
    unsec_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, len2, dctr) = decode_resp(&crypto, &mut tx[..dir.len], None, 0, &mut req);
    assert_eq!(op, 0x23, "PASEPake2");
    let (pb, cb) = decode_pake2(&req[..len2]);
    pake_ack = Some(dctr);

    // 3) PASEPake3 → 成功 StatusReport
    let confirm = prover.confirm(&context, &pb).unwrap();
    confirm.verify_b(&cb).unwrap();
    let ca = *confirm.confirmation_a();
    let plen = single_ctx1(&ca, &mut pl);
    let n = build_msg(
        &crypto,
        0,
        None,
        0,
        0x0000,
        0x24,
        0x0011,
        unsec_ctr,
        pake_ack,
        &pl[..plen],
        &mut wire,
    );
    unsec_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, _l, _c) = decode_resp(&crypto, &mut tx[..dir.len], None, 0, &mut req);
    assert_eq!(op, 0x40, "StatusReport(success)");

    // PASE 鍵(client 視点: enc=I2R, dec=R2I)。
    let ke = confirm.shared_secret();
    let mut keys = [0u8; 48];
    crypto
        .hkdf_sha256(&[], ke, SPAKE2P_SESSION_KEYS_INFO, &mut keys)
        .unwrap();
    let pase_i2r: [u8; 16] = keys[0..16].try_into().unwrap();
    let pase_r2i: [u8; 16] = keys[16..32].try_into().unwrap();

    assert!(stack
        .sessions()
        .iter()
        .any(|s| s.local_session_id() == device_sid));

    // ================= (b) IM over PASE =================
    // Basic Information の VendorName(0x0001)を Read できる(コミッショニングクラスタ)。
    let mut pase_ctr = 1u32;
    let plen = encode_read_request(&mut pl, false, |p| {
        p.push(&AttributePath::concrete(
            EndpointId(0),
            ClusterId(0x0028),
            AttributeId(0x0001),
        ))
    })
    .unwrap();
    let n = build_msg(
        &crypto,
        device_sid,
        Some(&pase_i2r),
        0,
        0x0001,
        ImOpCode::ReadRequest.to_u8(),
        0x0022,
        pase_ctr,
        None,
        &pl[..plen],
        &mut wire,
    );
    pase_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, rlen, dctr) = decode_resp(&crypto, &mut tx[..dir.len], Some(&pase_r2i), 0, &mut req);
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    let rd = ReportDataRef::new(&req[..rlen]).unwrap();
    assert!(
        rd.attr_reports()
            .unwrap()
            .filter_map(|r| r.ok())
            .any(|r| matches!(r, AttributeReportRef::Data(d)
                if d.path.to_concrete().map(|c| c.attribute.0) == Some(0x0001))),
        "Basic Information Read over PASE returns data"
    );
    let mut imc_ack = Some(dctr);

    // OnOff invoke over PASE は ACL で拒否される(UnsupportedAccess = 0x7e)。
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x0006,
        0x01,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(
        resp_status(&req[..rl]),
        0x7e,
        "OnOff invoke denied over PASE"
    );

    // ================= (c) フルコミッショニング(PASE 上) =================

    // ArmFailSafe(60s)
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x0030,
        0x00,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.write_u16(&cx(0), 60)?;
            w.write_u64(&cx(1), 1)?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(resp_command_id(&req[..rl]), 0x01);
    let mut f = [0u8; 512];
    let fl = resp_fields(&req[..rl], &mut f);
    assert_eq!(field_uint(&f[..fl], 0), Some(0), "ArmFailSafe OK");
    assert!(stack.device().gc.fail_safe().is_armed());

    // CSRRequest → 運用公開鍵抽出
    let csr_nonce = [0x22u8; 32];
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x003E,
        0x04,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &csr_nonce)?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(resp_command_id(&req[..rl]), 0x05);
    let fl = resp_fields(&req[..rl], &mut f);
    let mut nocsr = [0u8; 512];
    let nocsr_len = field_bytes(&f[..fl], 0, &mut nocsr).unwrap();
    let mut csr = [0u8; 512];
    let csr_len = field_bytes(&nocsr[..nocsr_len], 1, &mut csr).unwrap();
    let op_pub = extract_pubkey(&csr[..csr_len]);

    // コミッショナ役: RCAC(自己署名)、device NOC(op_pub)、commissioner NOC(comm_kp)。
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
            (dn_attr::MATTER_NODE_ID, DEVICE_NODE),
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
    let comm_kp = crypto.p256_keypair_from_bytes(&[0x77; 32]).unwrap();
    let comm_pub = comm_kp.public_key().to_bytes();
    let mut comm_noc = [0u8; 400];
    let comm_noc_len = write_cert(
        &mut comm_noc,
        &[0x03],
        &[
            (dn_attr::MATTER_RCAC_ID, RCAC_ID),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &[
            (dn_attr::MATTER_NODE_ID, COMM_NODE),
            (dn_attr::MATTER_FABRIC_ID, FABRIC_ID),
        ],
        &comm_pub,
        false,
        key_usage::DIGITAL_SIGNATURE,
        &[ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH],
        &COMM_SKID,
        &RCAC_SKID,
        &root_kp,
    );

    // AddTrustedRootCertificate
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x003E,
        0x0B,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &rcac[..rcac_len])?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(resp_status(&req[..rl]), 0, "AddTrustedRoot OK");

    // AddNOC
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x003E,
        0x06,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.write_bytes(&cx(0), &noc[..noc_len])?;
            w.write_bytes(&cx(2), &IPK)?;
            w.write_u64(&cx(3), 1)?;
            w.write_u16(&cx(4), 0xFFF1)?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(resp_command_id(&req[..rl]), 0x08);
    let fl = resp_fields(&req[..rl], &mut f);
    assert_eq!(field_uint(&f[..fl], 0), Some(0), "AddNOC OK");
    assert_eq!(field_uint(&f[..fl], 1), Some(1), "fabricIndex 1");
    assert_eq!(stack.device().opcreds.fabrics().len(), 1);
    assert!(
        matches!(
            stack
                .sessions()
                .iter()
                .find(|s| s.local_session_id() == device_sid)
                .unwrap()
                .mode(),
            SessionMode::Pase { fabric_idx: 1 }
        ),
        "PASE session promoted to fabric 1"
    );

    // CommissioningComplete
    let rl = pase_invoke(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        0x0030,
        0x04,
        &mut pase_ctr,
        &mut imc_ack,
        |w, t| {
            w.start_struct(t)?;
            w.end_container()
        },
        &mut req,
    );
    assert_eq!(resp_command_id(&req[..rl]), 0x05);
    let fl = resp_fields(&req[..rl], &mut f);
    assert_eq!(field_uint(&f[..fl], 0), Some(0), "CommissioningComplete OK");
    assert!(!stack.device().gc.fail_safe().is_armed());

    // ================= (d) CASE + OnOff over CASE =================
    let (ipk, root_pub_f, dev_node, fabric_id) = {
        let g = fabrics.borrow();
        let fe = g.get(NonZeroU8::new(1).unwrap()).unwrap();
        (
            *fe.ipk(),
            *fe.root_public_key(),
            fe.node_id(),
            fe.fabric_id(),
        )
    };
    assert_eq!(dev_node, DEVICE_NODE);
    assert_eq!(fabric_id, FABRIC_ID);

    // Sigma1
    let eph_i = crypto.p256_generate_keypair().unwrap();
    let eph_i_pub = eph_i.public_key().to_bytes();
    let mut init_rng = SeqRng(0x1357_9BDF);
    let mut initiator_random = [0u8; 32];
    init_rng.fill_bytes(&mut initiator_random).unwrap();
    let mut dmsg = [0u8; 32 + 65 + 8 + 8];
    dmsg[..32].copy_from_slice(&initiator_random);
    dmsg[32..97].copy_from_slice(&root_pub_f);
    dmsg[97..105].copy_from_slice(&fabric_id.to_le_bytes());
    dmsg[105..113].copy_from_slice(&dev_node.to_le_bytes());
    let mut dest_id = [0u8; 32];
    crypto.hmac_sha256(&ipk, &dmsg, &mut dest_id).unwrap();

    let mut s1 = [0u8; 256];
    let s1_len = {
        let mut w = TlvWriter::new(&mut s1);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), &initiator_random).unwrap();
        w.write_u16(&cx(2), 0x7777).unwrap();
        w.write_bytes(&cx(3), &dest_id).unwrap();
        w.write_bytes(&cx(4), &eph_i_pub).unwrap();
        w.end_container().unwrap();
        w.len()
    };
    let n = build_msg(
        &crypto,
        0,
        None,
        0,
        0x0000,
        0x30,
        0x0033,
        unsec_ctr,
        None,
        &s1[..s1_len],
        &mut wire,
    );
    unsec_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, len1, dctr) = decode_resp(&crypto, &mut tx[..dir.len], None, 0, &mut req);
    assert_eq!(op, 0x31, "CASE Sigma2");
    let mut sigma2_bytes = [0u8; 1400];
    sigma2_bytes[..len1].copy_from_slice(&req[..len1]);
    let (responder_random, case_device_sid, responder_eph_pub, enc2, enc2_len) =
        parse_sigma2(&sigma2_bytes[..len1]);
    let case_ack = Some(dctr);

    // Sigma2 処理(ECDH + S2K + TBE2 復号で cross-check)。
    let responder_eph_obj = crypto
        .p256_public_key_from_bytes(&responder_eph_pub)
        .unwrap();
    let mut shared = [0u8; 32];
    eph_i.ecdh(&responder_eph_obj, &mut shared).unwrap();
    let mut tt_s1 = [0u8; 32];
    crypto.sha256_oneshot(&s1[..s1_len], &mut tt_s1);
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
    let mut tbe2 = [0u8; 1024];
    tbe2[..enc2_len].copy_from_slice(&enc2[..enc2_len]);
    let pt2 = crypto
        .aes_ccm_decrypt(&s2k, case::SIGMA2_NONCE, &[], &mut tbe2[..enc2_len])
        .unwrap();
    let (rnoc, _ricac, _rsig) = case::decode_tbe_certs(pt2).unwrap();
    assert!(!rnoc.is_empty(), "responder NOC present in Sigma2 TBE");

    // Sigma3
    let mut hasher = crypto.sha256();
    hasher.update(&s1[..s1_len]);
    hasher.update(&sigma2_bytes[..len1]);
    let mut tt_s2 = [0u8; 32];
    hasher.clone().finish(&mut tt_s2);
    let mut tbs3 = [0u8; 1024];
    let tbs3_len = case::encode_tbs(
        &mut tbs3,
        &comm_noc[..comm_noc_len],
        None,
        &eph_i_pub,
        &responder_eph_pub,
    )
    .unwrap();
    let mut sig3 = [0u8; 64];
    comm_kp.sign(&tbs3[..tbs3_len], &mut sig3).unwrap();
    let mut tbe3 = [0u8; 1024];
    let tbe3_pt_len = {
        let mut w = TlvWriter::new(&mut tbe3);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), &comm_noc[..comm_noc_len]).unwrap();
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
    let mut s3 = [0u8; 1400];
    let s3_len = {
        let mut w = TlvWriter::new(&mut s3);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&cx(1), &tbe3[..enc3_len]).unwrap();
        w.end_container().unwrap();
        w.len()
    };
    let n = build_msg(
        &crypto,
        0,
        None,
        0,
        0x0000,
        0x32,
        0x0033,
        unsec_ctr,
        case_ack,
        &s3[..s3_len],
        &mut wire,
    );
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, _l, _c) = decode_resp(&crypto, &mut tx[..dir.len], None, 0, &mut req);
    assert_eq!(op, 0x40, "CASE success StatusReport");

    // CASE 鍵(client 視点: enc=I2R, dec=R2I)。
    let mut hasher3 = crypto.sha256();
    hasher3.update(&s1[..s1_len]);
    hasher3.update(&sigma2_bytes[..len1]);
    hasher3.update(&s3[..s3_len]);
    let mut tt_s3 = [0u8; 32];
    hasher3.finish(&mut tt_s3);
    let mut ckeys = [0u8; 48];
    case::derive_ipk_tt_keyed(
        &crypto,
        &ipk,
        &tt_s3,
        case::CASE_SESSION_KEYS_INFO,
        &shared,
        &mut ckeys,
    )
    .unwrap();
    let case_i2r: [u8; 16] = ckeys[0..16].try_into().unwrap();
    let case_r2i: [u8; 16] = ckeys[16..32].try_into().unwrap();

    assert!(stack
        .sessions()
        .iter()
        .any(|s| s.local_session_id() == case_device_sid
            && matches!(s.mode(), SessionMode::Case { .. })));

    // OnOff invoke(On)over CASE(client src node = COMM_NODE, device src node = DEVICE_NODE)。
    let mut case_ctr = 1u32;
    let plen = encode_invoke_request(&mut pl, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
            None,
            Some(|w: &mut TlvWriter, t: &TlvTag| {
                w.start_struct(t)?;
                w.end_container()
            }),
        )
    })
    .unwrap();
    let n = build_msg(
        &crypto,
        case_device_sid,
        Some(&case_i2r),
        COMM_NODE,
        0x0001,
        ImOpCode::InvokeRequest.to_u8(),
        0x0044,
        case_ctr,
        None,
        &pl[..plen],
        &mut wire,
    );
    case_ctr += 1;
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, rlen, dctr) = decode_resp(
        &crypto,
        &mut tx[..dir.len],
        Some(&case_r2i),
        DEVICE_NODE,
        &mut req,
    );
    assert_eq!(op, ImOpCode::InvokeResponse.to_u8());
    assert_eq!(resp_status(&req[..rlen]), 0, "OnOff On OK over CASE");
    assert!(stack.device().onoff.is_on(), "OnOff attribute is now true");
    let case_ack2 = Some(dctr);

    // OnOff Read over CASE → true。
    let plen = encode_read_request(&mut pl, false, |p| {
        p.push(&AttributePath::concrete(
            EndpointId(1),
            ClusterId(0x0006),
            AttributeId(0x0000),
        ))
    })
    .unwrap();
    let n = build_msg(
        &crypto,
        case_device_sid,
        Some(&case_i2r),
        COMM_NODE,
        0x0001,
        ImOpCode::ReadRequest.to_u8(),
        0x0044,
        case_ctr,
        case_ack2,
        &pl[..plen],
        &mut wire,
    );
    let dir = stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .unwrap();
    let (op, rlen, _c) = decode_resp(
        &crypto,
        &mut tx[..dir.len],
        Some(&case_r2i),
        DEVICE_NODE,
        &mut req,
    );
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    let rd = ReportDataRef::new(&req[..rlen]).unwrap();
    let mut it = rd.attr_reports().unwrap();
    match it.next().unwrap().unwrap() {
        AttributeReportRef::Data(d) => {
            let mut v = d.value();
            assert_eq!(
                v.read_next().unwrap().unwrap().value,
                TlvValue::Boolean(true),
                "OnOff = true"
            );
        }
        AttributeReportRef::Status(_) => panic!("expected OnOff data report"),
    }
}
