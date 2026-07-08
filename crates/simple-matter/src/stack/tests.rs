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
type TestStack<'s, N = NetworkCommissioning> =
    MatterStack<'s, Crb, SeqRng, Dev<'s, N>, 5, 4, 4, 8, 1, 2, 3, 8>;

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
/// NetworkCommissioning クラスタは差し替え可能(既定 Ethernet、Wi-Fi コミッショニング
/// テストでは `NetworkCommissioningWifi`)。
struct Dev<'s, N: ServerCluster = NetworkCommissioning> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: N,
    opcreds: Op<'s>,
    desc0: DescriptorCluster,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    removed_fabric: Option<NonZeroU8>,
    /// group メンバーシップ(groupcast テスト用。`None` = group 非対応)。
    groups: Option<&'s RefCell<crate::groups::DefaultGroupStore>>,
}

// device! マクロはライフタイム付きデバイスに使えないため DataModel を手書きする(乖離)。
impl<N: ServerCluster> DataModel for Dev<'_, N> {
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

    fn group_endpoints(&self, fabric: NonZeroU8, group_id: u16, idx: usize) -> Option<EndpointId> {
        let store = self.groups?.borrow();
        let eps = store.member_endpoints(fabric, group_id)?;
        eps.get(idx).map(|&e| EndpointId(e))
    }
}

fn build_device(fabrics: &RefCell<FabricTable<Crb, 5>>) -> Dev<'_> {
    build_device_with(fabrics, NetworkCommissioning::new(b"eth0"))
}

/// CD を 1 バイト改竄した DAC provider を持つデバイス(CD CMS 検証の失敗系 E2E 用)。
fn build_device_tampered_cd(fabrics: &RefCell<FabricTable<Crb, 5>>) -> Dev<'_> {
    let dac_crypto = RustCrypto::new(SeqRng(0xDAC0_0001));
    let dac = TestDacProvider::new_with_tampered_cd(&dac_crypto).unwrap();
    Dev {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(SeqRng(0x00C0_0001)), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new(),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
        groups: None,
    }
}

/// NetworkCommissioning クラスタ差し替え版(Wi-Fi コミッショニングのテスト用)。
fn build_device_with<N: ServerCluster>(
    fabrics: &RefCell<FabricTable<Crb, 5>>,
    net: N,
) -> Dev<'_, N> {
    let dac_crypto = RustCrypto::new(SeqRng(0xDAC0_0001));
    let dac = TestDacProvider::new(&dac_crypto).unwrap();
    Dev {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net,
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(SeqRng(0x00C0_0001)), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new(),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
        groups: None,
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

/// PASE 上でコマンドを invoke し、InvokeResponse を `out` に得て長さを返す(EP0)。
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
    pase_invoke_ep(
        stack, crypto, device_sid, i2r, r2i, 0, cluster, command, ctr, ack, fields, out,
    )
}

/// PASE 上でコマンドを invoke し、InvokeResponse を `out` に得て長さを返す。
#[allow(clippy::too_many_arguments)]
fn pase_invoke_ep<F>(
    stack: &mut TestStack<'_>,
    crypto: &Crb,
    device_sid: u16,
    i2r: &[u8; 16],
    r2i: &[u8; 16],
    endpoint: u16,
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
            &CommandPath::new(EndpointId(endpoint), ClusterId(cluster), CommandId(command)),
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
    // ACL 無しデバイス(DataModel::acl == None)の従来近似ゲートの回帰テスト。
    // full ACL デバイスでは PASE は implicit Administer で許可される(acl.md §3)。
    let rl = pase_invoke_ep(
        &mut stack,
        &crypto,
        device_sid,
        &pase_i2r,
        &pase_r2i,
        1,
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

// ==========================================================================
// (ピース D)コントローラ縦通し: ControllerStack + Commissioner でフルコミッショニング
//
// `docs/design/controller.md` §9.1。上の `onoff_light_end_to_end` は client 役を手書き
// (build_msg/decode_resp/pase_invoke/write_cert/case:: 直叩き)で組むが、本テストは
// `ControllerStack` + `Commissioner` + `Ca` を用い、**手書きロジックなし**で
// PASE → ArmFailSafe → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete →
// CASE 上 OnOff invoke → Read 読み戻し を完走させる。デバイス側は同じ `build_device` を再利用。
// ==========================================================================

#[cfg(feature = "controller")]
mod controller_e2e {
    use super::*;

    use crate::controller::ca::Ca;
    use crate::controller::{
        AttestationError, AttestationPolicy, CommissionError, Commissioner, ControllerCreds,
        ControllerStack, Phase,
    };
    use crate::dm::clusters::operational_credentials::dev_creds::TEST_PAA_CERT_FFF1;
    use crate::im::client::ImClient;
    use crate::im::wire::ImStatus;
    use crate::im::ImEvent;
    use crate::sc::initiator::ScInitiator;

    /// コントローラスタック(SESSIONS=4 EXCHANGES=6 TX=3 RESULT=1280)。exchange は完了ごとに
    /// 回収されるが、往復の余裕を持たせる。
    type Ctrl<'s> = ControllerStack<'s, Crb, SeqRng, ControllerCreds<'s, Crb>, 4, 6, 3, 1280>;

    /// デバイスから見たコントローラのアドレス(ping-pong の from アドレス)。
    fn ctrl_addr() -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
            5540,
        ))
    }

    /// 1 パケットを宛先の handle_rx に渡し、応答が続く限り相互に ping-pong する。
    ///
    /// `to_device=true` は controller→device の向き。応答が `None`(終端)になったら戻る。
    fn ping_pong<N: ServerCluster>(
        ctrl: &mut Ctrl<'_>,
        dev: &mut TestStack<'_, N>,
        now: u64,
        first: &[u8],
        mut to_device: bool,
    ) {
        let mut buf = [0u8; 1700];
        let mut len = first.len();
        buf[..len].copy_from_slice(first);
        let mut txc = [0u8; 1700];
        let mut txd = [0u8; 1700];
        for _ in 0..32 {
            let dir = if to_device {
                dev.handle_rx(&mut buf[..len], ctrl_addr(), now, &mut txd)
            } else {
                ctrl.handle_rx(&mut buf[..len], peer(), now, &mut txc)
            };
            match dir {
                Some(d) => {
                    let src = if to_device { &txd } else { &txc };
                    buf[..d.len].copy_from_slice(&src[..d.len]);
                    len = d.len;
                    to_device = !to_device;
                }
                None => break,
            }
        }
    }

    /// 時間を進めながら両スタックを poll し、standalone ACK / 再送を流し切って静穏化する。
    fn flush<N: ServerCluster>(ctrl: &mut Ctrl<'_>, dev: &mut TestStack<'_, N>, base_now: u64) {
        let mut now = base_now;
        for _ in 0..16 {
            now += 400;
            let mut progressed = false;
            let mut tx = [0u8; 1700];
            while let Some(d) = ctrl.poll(now, &mut tx) {
                let mut b = [0u8; 1700];
                b[..d.len].copy_from_slice(&tx[..d.len]);
                ping_pong(ctrl, dev, now, &b[..d.len], true);
                progressed = true;
            }
            while let Some(d) = dev.poll(now, &mut tx) {
                let mut b = [0u8; 1700];
                b[..d.len].copy_from_slice(&tx[..d.len]);
                ping_pong(ctrl, dev, now, &b[..d.len], false);
                progressed = true;
            }
            let quiescent = ctrl.next_deadline(now).is_none() && dev.next_deadline(now).is_none();
            if !progressed && quiescent {
                break;
            }
        }
    }

    /// controller 発の 1 送信(`dir` のバイト列は `tx`)を device へ届け、応答を往復し、ACK を流す。
    fn deliver_and_settle<N: ServerCluster>(
        ctrl: &mut Ctrl<'_>,
        dev: &mut TestStack<'_, N>,
        now: u64,
        tx: &[u8],
        len: usize,
    ) {
        ping_pong(ctrl, dev, now, &tx[..len], true);
        flush(ctrl, dev, now);
    }

    #[test]
    fn controller_end_to_end() {
        let crypto = RustCrypto::new(SeqRng(0xC0FF_EE00_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        // --- デバイス(responder)側: 既存 onoff-light 構成を再利用 ---
        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0001), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        // --- コントローラ(initiator)側 ---
        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0001),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0001), ctrl_creds);
        let im_client = ImClient::new();
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, im_client);

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        // --- コミッショニングを Mealy 機械で駆動 ---
        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }

        let case_session = match final_phase {
            Phase::Done { session } => session,
            other => panic!("commissioning did not complete: {other:?}"),
        };

        // デバイス側に fabric が生えていること。
        assert_eq!(fabrics.borrow().len(), 1, "device fabric added");
        {
            let g = fabrics.borrow();
            let fe = g.get(NonZeroU8::new(1).unwrap()).unwrap();
            assert_eq!(fe.node_id(), DEVICE_NODE);
            assert_eq!(fe.fabric_id(), FABRIC_ID);
        }
        // fail-safe は CommissioningComplete で解除済み。
        assert!(!dev.device().gc.fail_safe().is_armed());

        // --- 運用 API: CASE 上で OnOff On を invoke ---
        assert!(!dev.device().onoff.is_on());
        let dir = ctrl
            .start_invoke(
                case_session,
                CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
                |w, t| {
                    w.start_struct(t)?;
                    w.end_container()
                },
                NOW,
                &mut tx,
            )
            .expect("start OnOff invoke");
        deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, dir.len);
        match ctrl.im_take_event() {
            Some(ImEvent::InvokeDone { status }) => {
                assert_eq!(status, ImStatus::Success, "OnOff On over CASE");
            }
            other => panic!("expected InvokeDone, got {other:?}"),
        }
        assert!(
            dev.device().onoff.is_on(),
            "device OnOff attribute is now true"
        );

        // --- 運用 API: CASE 上で OnOff を Read 読み戻し ---
        let dir = ctrl
            .start_read(
                case_session,
                &[AttributePath::concrete(
                    EndpointId(1),
                    ClusterId(0x0006),
                    AttributeId(0x0000),
                )],
                NOW,
                &mut tx,
            )
            .expect("start OnOff read");
        deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, dir.len);
        assert_eq!(ctrl.im_take_event(), Some(ImEvent::ReadDone));
        let mut found_true = false;
        for report in ctrl.read_reports() {
            if let Ok(AttributeReportRef::Data(d)) = report {
                if d.path.to_concrete().map(|c| c.attribute.0) == Some(0x0000) {
                    let mut v = d.value();
                    if matches!(
                        v.read_next().ok().flatten().map(|e| e.value),
                        Some(TlvValue::Boolean(true))
                    ) {
                        found_true = true;
                    }
                }
            }
        }
        assert!(found_true, "controller reads back OnOff = true over CASE");

        // --- Subscribe: 同一 CASE セッションで OnOff を購読(設計 §4.5)---
        let dir = ctrl
            .start_subscribe(
                case_session,
                &[AttributePath::concrete(
                    EndpointId(1),
                    ClusterId(0x0006),
                    AttributeId(0x0000),
                )],
                0,  // min interval floor
                60, // max interval ceiling
                NOW,
                &mut tx,
            )
            .expect("start subscribe");
        deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, dir.len);
        let sub_id = match ctrl.im_take_event() {
            Some(ImEvent::SubscribeDone {
                subscription_id,
                max_interval_s,
            }) => {
                assert_eq!(max_interval_s, 60, "negotiated max interval");
                subscription_id
            }
            other => panic!("expected SubscribeDone, got {other:?}"),
        };
        assert_eq!(ctrl.subscription_count(), 1, "client subscription table");
        assert_eq!(dev.im().subscription_count(), 1, "device subscription slot");
        // 購読確立後はロスト検出のため controller の deadline が常に立つ。
        assert!(ctrl.next_deadline(NOW).is_some());

        // --- 同一 CASE セッション上で自分で Toggle → デバイス発レポートが飛ぶ ---
        let t1 = NOW + 1000;
        let dir = ctrl
            .start_invoke(
                case_session,
                CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x02)), // Toggle
                |w, t| {
                    w.start_struct(t)?;
                    w.end_container()
                },
                t1,
                &mut tx,
            )
            .expect("start Toggle while subscribed");
        deliver_and_settle(&mut ctrl, &mut dev, t1, &tx, dir.len);
        assert!(!dev.device().onoff.is_on(), "toggled true → false");

        // deliver_and_settle 内の flush(dev.poll)で購読レポートが排出され、controller が
        // 受理済みのはず。イベントを収集して InvokeDone とレポートの両方を確認する。
        let mut invoke_done = false;
        let mut report_sub = None;
        while let Some(ev) = ctrl.im_take_event() {
            match ev {
                ImEvent::InvokeDone { status } => {
                    assert_eq!(status, ImStatus::Success);
                    invoke_done = true;
                }
                ImEvent::SubscriptionReport { subscription_id } => {
                    report_sub = Some(subscription_id);
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert!(invoke_done, "Toggle acknowledged");
        assert_eq!(
            report_sub,
            Some(sub_id),
            "device-initiated subscription report received"
        );
        let mut reported = None;
        for r in ctrl.sub_reports() {
            if let Ok(AttributeReportRef::Data(d)) = r {
                if d.path.to_concrete().map(|c| c.attribute.0) == Some(0x0000) {
                    let mut v = d.value();
                    if let Ok(Some(e)) = v.read_next() {
                        if let TlvValue::Boolean(b) = e.value {
                            reported = Some(b);
                        }
                    }
                }
            }
        }
        assert_eq!(
            reported,
            Some(false),
            "report carries the toggled OnOff value"
        );
    }

    /// イベント購読の回帰再現(実機 E2E: subscribe-event 確立後の同一セッション invoke が
    /// ドロップされた)。smctl の `onoff subscribe-event state-changed 0 30 1 1` →
    /// `onoff toggle 1 1` の流れを stack ループバックで再現する:
    /// (1) StartUp イベントを積んだデバイスへイベントのみ購読(min=0)を確立、
    /// (2) 同一 CASE セッションで Toggle が応答を返す(回帰点)、
    /// (3) OnOff イベント post → デバイス発レポートでイベントが届く。
    #[test]
    fn subscribe_events_then_invoke_end_to_end() {
        use crate::dm::meta::EventId;
        use crate::im::events::PRIORITY_INFO;
        use crate::im::wire::{EventPath, EventReportRef};

        let crypto = RustCrypto::new(SeqRng(0xE0E0_0001_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0EE0), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);
        // 実デバイス(examples/onoff-light)同様、起動直後に StartUp イベントを積む。
        let _ = dev.post_startup_event(CFG.software_version, 0);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0EE0),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0EE0), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();
        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        let case_session = match final_phase {
            Phase::Done { session } => session,
            other => panic!("commissioning did not complete: {other:?}"),
        };

        // --- (1) イベントのみ購読(smctl subscribe-event 相当、min=0 max=30)---
        let dir = ctrl
            .start_subscribe_events(
                case_session,
                &[],
                &[EventPath::concrete(
                    EndpointId(1),
                    ClusterId(0x0006),
                    EventId(0),
                )],
                None,
                0,
                30,
                NOW,
                &mut tx,
            )
            .expect("start subscribe-event");
        deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, dir.len);
        let sub_id = match ctrl.im_take_event() {
            Some(ImEvent::SubscribeDone {
                subscription_id, ..
            }) => subscription_id,
            other => panic!("expected SubscribeDone, got {other:?}"),
        };
        assert_eq!(dev.im().subscription_count(), 1, "device subscription slot");

        // --- (2) 同一 CASE セッションで Toggle(回帰点: 応答が返ること)---
        let t1 = NOW + 1000;
        let dir = ctrl
            .start_invoke(
                case_session,
                CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x02)),
                |w, t| {
                    w.start_struct(t)?;
                    w.end_container()
                },
                t1,
                &mut tx,
            )
            .expect("start Toggle after subscribe-event");
        deliver_and_settle(&mut ctrl, &mut dev, t1, &tx, dir.len);
        let mut invoke_done = false;
        while let Some(ev) = ctrl.im_take_event() {
            match ev {
                ImEvent::InvokeDone { status } => {
                    assert_eq!(status, ImStatus::Success);
                    invoke_done = true;
                }
                // 途中でレポートが混ざっても許容(この段階ではイベント未 post)。
                ImEvent::SubscriptionReport { .. } => {}
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert!(
            invoke_done,
            "Toggle must be answered while an event subscription is active"
        );
        assert!(dev.device().onoff.is_on(), "toggled false → true");

        // --- (3) OnOff イベント post(examples/onoff-light の 2b 相当)→ レポート配信 ---
        let t2 = t1 + 100;
        let _ = dev.post_event(
            EndpointId(1),
            ClusterId(0x0006),
            EventId(0),
            PRIORITY_INFO,
            t2,
            |w, tag| {
                w.start_struct(tag)?;
                w.write_bool(&TlvTag::ContextSpecific(0), true)?;
                w.end_container()
            },
        );
        flush(&mut ctrl, &mut dev, t2);
        let mut report_sub = None;
        while let Some(ev) = ctrl.im_take_event() {
            if let ImEvent::SubscriptionReport { subscription_id } = ev {
                report_sub = Some(subscription_id);
            }
        }
        assert_eq!(report_sub, Some(sub_id), "event report delivered");
        let mut got = None;
        for r in ctrl.sub_event_reports() {
            if let Ok(EventReportRef::Data(d)) = r {
                let mut v = d.value();
                let _ = v.read_next(); // struct 開始
                if let Ok(Some(e)) = v.read_next() {
                    if let TlvValue::Boolean(b) = e.value {
                        got = Some((d.number, b));
                    }
                }
            }
        }
        assert_eq!(
            got,
            Some((1, true)),
            "new OnOff event (number 1, newState=true) delivered"
        );

        // --- (4) toggle + イベント post + レポート配信を繰り返しても後続 invoke が通ること
        //     (実機回帰: 配信完了した device 発レポートの exchange が回収されず、数レポートで
        //      exchange プール(EXCHANGES=4)が枯渇 → 以降の受信が全て silent drop になった)---
        let mut now = t2;
        for cycle in 0..6u32 {
            now += 1000;
            let dir = ctrl
                .start_invoke(
                    case_session,
                    CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x02)),
                    |w, t| {
                        w.start_struct(t)?;
                        w.end_container()
                    },
                    now,
                    &mut tx,
                )
                .expect("start Toggle in soak cycle");
            deliver_and_settle(&mut ctrl, &mut dev, now, &tx, dir.len);
            let mut invoke_done = false;
            while let Some(ev) = ctrl.im_take_event() {
                match ev {
                    ImEvent::InvokeDone { status } => {
                        assert_eq!(status, ImStatus::Success);
                        invoke_done = true;
                    }
                    ImEvent::SubscriptionReport { .. } => {}
                    other => panic!("unexpected event {other:?}"),
                }
            }
            assert!(invoke_done, "Toggle answered in soak cycle {cycle}");

            // 実デバイス同様、状態変化イベントを post → レポート配信(flush 内)。
            now += 100;
            let on_now = dev.device().onoff.is_on();
            let _ = dev.post_event(
                EndpointId(1),
                ClusterId(0x0006),
                EventId(0),
                PRIORITY_INFO,
                now,
                |w, tag| {
                    w.start_struct(tag)?;
                    w.write_bool(&TlvTag::ContextSpecific(0), on_now)?;
                    w.end_container()
                },
            );
            flush(&mut ctrl, &mut dev, now);
            let mut report_seen = false;
            while let Some(ev) = ctrl.im_take_event() {
                if matches!(ev, ImEvent::SubscriptionReport { .. }) {
                    report_seen = true;
                }
            }
            assert!(report_seen, "event report delivered in soak cycle {cycle}");
            now += 4000; // flush が進めた時間(16*400ms)を跨いで単調に進める。
        }
    }

    /// 購読レポートが MRP で ack されない(購読者が消えた)場合に、購読が破棄され
    /// (`on_report_failed`、設計 §6.3)、exchange/tx バッファが解放されることを検証する。
    /// 実機回帰の 2 次要因(前回実行の残骸購読が 30 秒ごとに死んだピアへレポートを送り、
    /// スロットを浪費し続ける)の再発防止。
    #[test]
    fn subscription_dropped_when_report_unacked() {
        use crate::dm::meta::EventId;
        use crate::im::events::PRIORITY_INFO;
        use crate::im::wire::EventPath;

        let crypto = RustCrypto::new(SeqRng(0xDEAD_0001_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0DED), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0DED),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0DED), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();
        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        let case_session = match final_phase {
            Phase::Done { session } => session,
            other => panic!("commissioning did not complete: {other:?}"),
        };

        // イベント購読を確立する。
        let dir = ctrl
            .start_subscribe_events(
                case_session,
                &[],
                &[EventPath::concrete(
                    EndpointId(1),
                    ClusterId(0x0006),
                    EventId(0),
                )],
                None,
                0,
                30,
                NOW,
                &mut tx,
            )
            .expect("start subscribe-event");
        deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, dir.len);
        assert!(matches!(
            ctrl.im_take_event(),
            Some(ImEvent::SubscribeDone { .. })
        ));
        assert_eq!(dev.im().subscription_count(), 1);

        // 新イベントを post → レポートが staged される(が、購読者へは届けない = 死んだピア)。
        let _ = dev.post_event(
            EndpointId(1),
            ClusterId(0x0006),
            EventId(0),
            PRIORITY_INFO,
            NOW + 100,
            |w, tag| {
                w.start_struct(tag)?;
                w.write_bool(&TlvTag::ContextSpecific(0), true)?;
                w.end_container()
            },
        );
        let staged = dev.poll(NOW + 200, &mut tx);
        assert!(staged.is_some(), "report staged toward the (dead) peer");

        // 届けずに時間だけ進める → MRP 再送 → 諦め(Failed)→ 購読破棄。
        let mut now = NOW + 200;
        for _ in 0..64 {
            now += 2000;
            while dev.poll(now, &mut tx).is_some() {}
            if dev.im().subscription_count() == 0 {
                break;
            }
        }
        assert_eq!(
            dev.im().subscription_count(),
            0,
            "unacked report drops the subscription (design §6.3 liveness)"
        );
    }

    /// device attestation を **実検証**(`AttestationPolicy::Verify`)してフルコミッショニング
    /// する。デバイスは `TestDacProvider`(chip 開発 DAC チェーン)、PAA は埋め込みテスト定数。
    /// コミッショナが DAC/PAI 取得 → AttestationRequest → チェーン+署名+nonce 検証を通過し、
    /// CASE まで完走することを検証する(`docs/design/attestation.md` §5)。
    #[test]
    fn controller_end_to_end_attestation_verify() {
        let crypto = RustCrypto::new(SeqRng(0xA11E_5701_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0AAA), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0AAA),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0AAA), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let paa_store: [&[u8]; 1] = [&TEST_PAA_CERT_FFF1];
        let mut comm = Commissioner::new(
            &ca,
            &crypto,
            AttestationPolicy::Verify {
                paa_store: &paa_store,
            },
        );
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        let mut saw_attestation = false;
        for _ in 0..80 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if matches!(out.phase, Phase::Attestation) {
                saw_attestation = true;
            }
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        assert!(saw_attestation, "attestation phase was exercised");
        match final_phase {
            Phase::Done { .. } => {}
            other => panic!("attestation-verified commissioning did not complete: {other:?}"),
        }
        assert_eq!(
            fabrics.borrow().len(),
            1,
            "device fabric added after verify"
        );
    }

    /// PAA 信頼ストアに正しい PAA が無い場合、attestation 検証が
    /// `CommissionError::Attestation(PaaNotFound)` でコミッショニングを中断する(§5 失敗系)。
    #[test]
    fn controller_end_to_end_attestation_verify_fails_without_paa() {
        let crypto = RustCrypto::new(SeqRng(0xBAD0_5701_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0BBB), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0BBB),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0BBB), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        // 空の信頼ストア: DAC/PAI/AttestationRequest は完走するが PAA 照合で失敗する。
        let paa_store: [&[u8]; 0] = [];
        let mut comm = Commissioner::new(
            &ca,
            &crypto,
            AttestationPolicy::Verify {
                paa_store: &paa_store,
            },
        );
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..80 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        match final_phase {
            Phase::Failed {
                reason: CommissionError::Attestation(AttestationError::PaaNotFound),
                ..
            } => {}
            other => panic!("expected Attestation(PaaNotFound) failure, got {other:?}"),
        }
        assert_eq!(
            fabrics.borrow().len(),
            0,
            "no fabric added on attestation failure"
        );
    }

    /// CD(CMS)を 1 バイト改竄したデバイスは、DAC チェーン/attestation 署名は正しくても
    /// CD の CMS 署名検証([`AttestationError::CdSignature`])でコミッショニングが失敗する
    /// (attestation.md §7 の失敗系)。
    #[test]
    fn controller_end_to_end_attestation_rejects_tampered_cd() {
        let crypto = RustCrypto::new(SeqRng(0xBAD0_CD01_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0CDD), config, dev_creds);
        let im = InteractionModel::new(build_device_tampered_cd(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0CDD),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0CDD), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let paa_store: [&[u8]; 1] = [&TEST_PAA_CERT_FFF1];
        let mut comm = Commissioner::new(
            &ca,
            &crypto,
            AttestationPolicy::Verify {
                paa_store: &paa_store,
            },
        );
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..80 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        match final_phase {
            Phase::Failed {
                reason: CommissionError::Attestation(AttestationError::CdSignature),
                ..
            } => {}
            other => panic!("expected Attestation(CdSignature) failure, got {other:?}"),
        }
        assert_eq!(fabrics.borrow().len(), 0, "no fabric added on tampered CD");
    }

    /// Wi-Fi コミッショニング(`pairing ble-wifi` のコアフロー): `set_wifi_credentials`
    /// を設定した `Commissioner` が AddNOC 後に **同一 PASE セッション上で**
    /// AddOrUpdateWiFiNetwork → ConnectNetwork を送り、デバイス側
    /// `NetworkCommissioningWifi` のドライバに join が渡り、その後 CASE →
    /// CommissioningComplete まで完走することを検証する。
    #[test]
    fn controller_end_to_end_wifi_provisioning() {
        use crate::dm::clusters::NetworkCommissioningWifi;
        use crate::wifi::{WifiDriver, WifiStatus};

        let crypto = RustCrypto::new(SeqRng(0xC0FF_EE00_9876_5432));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        // --- デバイス側: NetworkCommissioning を Wi-Fi 版(NullWifiDriver シム)に差し替え ---
        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0002), config, dev_creds);
        let im =
            InteractionModel::new(build_device_with(&fabrics, NetworkCommissioningWifi::new()));
        let mut dev: TestStack<'_, NetworkCommissioningWifi> = MatterStack::new(&crypto, sc, im);

        // --- コントローラ側 ---
        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0003),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0004), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.set_wifi_credentials(b"iotap", b"hogeFugapiyo")
            .expect("set_wifi_credentials");
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        let (mut saw_add_wifi, mut saw_connect) = (false, false);
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            match out.phase {
                Phase::AddWifiNetwork => saw_add_wifi = true,
                Phase::ConnectNetwork => saw_connect = true,
                _ => {}
            }
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }
        assert!(
            matches!(final_phase, Phase::Done { .. }),
            "wifi commissioning did not complete: {final_phase:?}"
        );
        assert!(saw_add_wifi, "AddWifiNetwork phase was driven");
        assert!(saw_connect, "ConnectNetwork phase was driven");

        // デバイス側: Wi-Fi ドライバに join が渡っている(NullWifiDriver は即 Connected)。
        assert_eq!(
            dev.device().net.driver().status(),
            WifiStatus::Connected,
            "device wifi driver received ConnectNetwork"
        );
        // fabric も従来どおり生えている。
        assert_eq!(fabrics.borrow().len(), 1, "device fabric added");
    }

    /// 誤 credentials で join が失敗する場合、遅延 InvokeResponse として返る
    /// ConnectNetworkResponse(networkingStatus = OtherConnectionFailure)を Commissioner が
    /// 受けてコミッショニングを失敗終了することを検証する(doc §E7.3/§E7.4)。
    #[test]
    fn controller_wifi_provisioning_reports_connect_failure() {
        use crate::controller::CommissionError;
        use crate::dm::clusters::NetworkCommissioningWifi;
        use crate::wifi::{WifiDriver, WifiStatus};

        /// join が常に失敗するテスト用ドライバ(status() が Failed を返す)。
        #[derive(Default)]
        struct FailingDriver {
            calls: usize,
        }
        impl WifiDriver for FailingDriver {
            fn connect(&mut self, _ssid: &[u8], _creds: &[u8]) {
                self.calls += 1;
            }
            fn status(&self) -> WifiStatus {
                // auth 失敗 / AP 不在相当。reason は LastConnectErrorValue へ反映される。
                WifiStatus::Failed { reason: 15 }
            }
        }

        let crypto = RustCrypto::new(SeqRng(0xC0FF_EE00_DEAD_BEEF));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_00F2), config, dev_creds);
        let im = InteractionModel::new(build_device_with(
            &fabrics,
            NetworkCommissioningWifi::with_driver(FailingDriver::default()),
        ));
        let mut dev: TestStack<'_, NetworkCommissioningWifi<FailingDriver>> =
            MatterStack::new(&crypto, sc, im);

        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_00F3),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_00F4), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.set_wifi_credentials(b"iotap", b"wrongpassword")
            .expect("set_wifi_credentials");
        comm.commission(peer(), PASSCODE, DEVICE_NODE, NOW).unwrap();

        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        let mut saw_connect = false;
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, NOW, &mut tx);
            final_phase = out.phase;
            if let Phase::ConnectNetwork = out.phase {
                saw_connect = true;
            }
            if let Some(d) = out.send {
                deliver_and_settle(&mut ctrl, &mut dev, NOW, &tx, d.len);
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }

        assert!(saw_connect, "ConnectNetwork phase was driven");
        // ドライバに join が渡っている。
        // 初回 + リトライ 2 回(doc §E7.3 の過渡的失敗リトライ)で計 3 回 join を試みる。
        assert_eq!(
            dev.device().net.driver().calls,
            3,
            "connect started + retried"
        );
        // Commissioner は ConnectNetworkResponse(status=9)を受けて失敗終了する。
        match final_phase {
            Phase::Failed {
                stage,
                reason: CommissionError::Status(code),
            } => {
                assert_eq!(stage, 11, "failed at ConnectNetwork stage");
                // OtherConnectionFailure(9)。
                assert_eq!(code, 9, "networkingStatus = OtherConnectionFailure");
            }
            other => panic!("expected ConnectNetwork failure, got {other:?}"),
        }
        // 失敗したので fabric は生えるが運用ノードには到達しない(コミッショニング未完了)。
    }

    /// `set_wifi_credentials` の境界: SSID 32 / credentials 64 バイトまで受理、超過は拒否。
    #[test]
    fn set_wifi_credentials_validates_lengths() {
        use crate::controller::{MAX_WIFI_CREDENTIALS_LEN, MAX_WIFI_SSID_LEN};

        let crypto = RustCrypto::new(SeqRng(1));
        let ca = Ca::<Crb>::generate(&crypto, &mut SeqRng(2), FABRIC_ID, COMM_NODE, 0xFFF1, 0)
            .expect("Ca::generate");
        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        assert!(comm
            .set_wifi_credentials(
                &[0x41; MAX_WIFI_SSID_LEN],
                &[0x42; MAX_WIFI_CREDENTIALS_LEN]
            )
            .is_ok());
        assert!(comm
            .set_wifi_credentials(&[0x41; MAX_WIFI_SSID_LEN + 1], b"pw")
            .is_err());
        assert!(comm
            .set_wifi_credentials(b"ssid", &[0x42; MAX_WIFI_CREDENTIALS_LEN + 1])
            .is_err());
        assert!(comm.set_wifi_credentials(b"", b"pw").is_err());
    }

    /// 送信ファネルの MRP 格下げ(§3.3)を公開 API で観測する。BTP(BLE)ピアへの
    /// `start_pase` は第 1 メッセージを unreliable に格下げして再送スロットを登録しない
    /// (= MRP deadline が立たない)。同一呼び出しでも UDP ピアなら信頼送信で再送
    /// deadline が立つ。これで「格下げ + 再送非登録」を確認する。
    #[cfg(feature = "ble")]
    #[test]
    fn start_pase_downgrades_reliability_on_ble() {
        use crate::transport::net::BtpConnId;

        let crypto = RustCrypto::new(SeqRng(0xB1E0_0001_2222_3333));
        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0002),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");

        // UDP: 信頼送信 → MRP 再送 deadline が立つ。
        {
            let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
            let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0002), ctrl_creds);
            let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());
            let mut tx = [0u8; 1700];
            let dir = ctrl
                .start_pase(peer(), PASSCODE, NOW, &mut tx)
                .expect("start_pase udp");
            assert_eq!(dir.addr, peer());
            assert!(
                ctrl.next_deadline(NOW).is_some(),
                "UDP は信頼送信で再送 deadline が立つ"
            );
        }

        // BLE: unreliable へ格下げ → 再送スロット非登録 → MRP deadline なし。
        {
            let ble = PeerAddr::Ble(BtpConnId(7));
            let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
            let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0003), ctrl_creds);
            let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());
            let mut tx = [0u8; 1700];
            let dir = ctrl
                .start_pase(ble, PASSCODE, NOW, &mut tx)
                .expect("start_pase ble");
            assert_eq!(dir.addr, ble);
            assert!(
                ctrl.next_deadline(NOW).is_none(),
                "BTP は unreliable 格下げで再送 deadline が立たない"
            );
        }
    }

    // ======================================================================
    // BLE ループバック全経路 E2E(§9.1 段階1)
    //
    // `controller_end_to_end`(UDP 直結ポンプ)の BLE 版。デバイス側 MatterStack +
    // Btp<6>(Peripheral)⇔ コントローラ側 ControllerStack + Commissioner + Btp<6>
    // (Central)を、**フラグメントレベルのメモリ内ループバック**(相互の
    // `process_incoming` へ直接渡す)で接続し、PASE → ArmFailSafe → CSR →
    // AddTrustedRoot → AddNOC → CASE → CommissioningComplete → On/Off Toggle を
    // `PeerAddr::Ble` で通す。小さい ATT_MTU で複数フラグメント経路を必ず踏み、時間は
    // `now_ms` 注入で決定的。
    //
    // # なぜ trait 経由でなく BTP 直結ポンプか
    //
    // `GattPeripheral`/`GattCentral` は async trait で、テストで回すには executor が要る
    // (コアクレートは executor 非依存でテスト用 block_on も持たない)。設計 doc §9.1 が
    // 求める検証対象は **BTP + PASE + コミッショニング全経路のロジック**であり、これは
    // sans-IO の `Btp` を直結ポンプで駆動すれば無線・executor なしに決定的に証明できる。
    // trait 自体の実装可能性 + `&mut T` ブランケットは `btp/tests.rs` の
    // `gatt_traits_are_implementable_and_have_blanket_impls`(型レベル)で担保する。
    // ======================================================================

    #[cfg(feature = "ble")]
    use crate::btp::Btp;

    #[cfg(feature = "ble")]
    struct BleStats {
        /// 交渉済みフラグメント payload サイズ。
        frag_size: usize,
        /// 少なくとも 1 メッセージがフラグメント境界を跨いでセグメント化されたか。
        multi_fragment_seen: bool,
        /// R/A フラグをワイヤ検査した unsecured メッセージ数(検査が実際に走った証拠)。
        unsecured_checked: usize,
    }

    /// BTP が運ぶ 1 SDU(Matter datagram)を検査し、unsecured(session_id==0)なら
    /// 平文の PayloadHeader を読んで R(RELIABLE)/A(ACK)フラグが立っていないことを
    /// 確認する(§2.7)。暗号化メッセージはワイヤから exchange flags を読めないため、
    /// そちらは呼び出し側の「MRP deadline が立たない」アサートで担保する。
    #[cfg(feature = "ble")]
    fn assert_no_mrp_flags(sdu: &[u8], stats: &mut BleStats) {
        let mut copy = [0u8; 1600];
        copy[..sdu.len()].copy_from_slice(sdu);
        let mut pb = ParseBuf::new(&mut copy[..sdu.len()]);
        let pkt = PacketHeader::decode(&mut pb).expect("decode packet header");
        if pkt.session_id == 0 {
            let ph = PayloadHeader::decode(&mut pb).expect("decode payload header");
            assert!(
                !ph.exch_flags.contains(ExchFlags::RELIABLE),
                "R フラグが BTP 上の Matter メッセージに立っている"
            );
            assert!(
                !ph.exch_flags.contains(ExchFlags::ACK),
                "A フラグが BTP 上の Matter メッセージに立っている"
            );
            stats.unsecured_checked += 1;
        }
    }

    /// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため)。
    #[cfg(feature = "ble")]
    fn copy_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
        let sdu = btp.recv()?;
        let n = sdu.len();
        out[..n].copy_from_slice(sdu);
        Some(n)
    }

    /// スタックの応答 SDU を BTP 送信キューに載せる。フラグメント境界超過なら記録する。
    #[cfg(feature = "ble")]
    fn load_ble(btp: &mut Btp<6>, sdu: &[u8], now: u64, stats: &mut BleStats) {
        if sdu.len() > stats.frag_size {
            // 単一フラグメント payload 上限(< frag_size)を超える = 必ず複数フラグメント。
            stats.multi_fragment_seen = true;
        }
        btp.send(sdu, now).expect("btp.send");
    }

    /// BTP ループバックを回し切る:フラグメントを相互配送 → 再組立 SDU を対応スタックの
    /// `handle_rx` へ → 応答を再び BTP へ、を静穏化するまで反復する。各反復で両スタックを
    /// `poll` して **終端済み交換を回収**する(BTP では poll は送出を生まないが、交換プール
    /// 枯渇を防ぐために必須)。window ブロック解消のため停滞時のみ遅延 ACK 期限まで単調に
    /// 時刻を進める。各 `handle_rx` 後に **MRP deadline が立たないこと**(§3.3)を検証する。
    #[cfg(feature = "ble")]
    #[allow(clippy::too_many_arguments)]
    fn pump_ble(
        btp_c: &mut Btp<6>,
        btp_p: &mut Btp<6>,
        ctrl: &mut Ctrl<'_>,
        dev: &mut TestStack<'_>,
        dev_src: PeerAddr,
        ctrl_src: PeerAddr,
        mtu: Option<u16>,
        now: &mut u64,
        stats: &mut BleStats,
    ) {
        let mut frag = [0u8; 300];
        let mut sdu = [0u8; 1600];
        let mut txd = [0u8; 1700];
        let mut txc = [0u8; 1700];
        for _ in 0..8192 {
            let mut progressed = false;

            // controller → device フラグメント(1 本)。
            let n = btp_c.process_outgoing(&mut frag, mtu, *now).unwrap();
            if n > 0 {
                btp_p.process_incoming(&frag[..n], mtu, *now).unwrap();
                progressed = true;
            }
            // device → controller フラグメント(1 本)。
            let n = btp_p.process_outgoing(&mut frag, mtu, *now).unwrap();
            if n > 0 {
                btp_c.process_incoming(&frag[..n], mtu, *now).unwrap();
                progressed = true;
            }

            // device が 1 メッセージを再組立 → dev.handle_rx(応答を BTP へ)。
            // can_send() の間だけ引き取る(応答を同じ BTP に載せられる時のみ消費)。
            if btp_p.can_send() {
                if let Some(len) = copy_sdu(btp_p, &mut sdu) {
                    assert_no_mrp_flags(&sdu[..len], stats);
                    let dir = dev.handle_rx(&mut sdu[..len], dev_src, *now, &mut txd);
                    assert!(
                        dev.next_deadline(*now).is_none(),
                        "device に MRP deadline が立った(BTP では格下げされるはず)"
                    );
                    if let Some(d) = dir {
                        load_ble(btp_p, &txd[..d.len], *now, stats);
                    }
                    progressed = true;
                }
            }
            // controller が 1 メッセージを再組立 → ctrl.handle_rx(応答を BTP へ)。
            if btp_c.can_send() {
                if let Some(len) = copy_sdu(btp_c, &mut sdu) {
                    assert_no_mrp_flags(&sdu[..len], stats);
                    let dir = ctrl.handle_rx(&mut sdu[..len], ctrl_src, *now, &mut txc);
                    assert!(
                        ctrl.next_deadline(*now).is_none(),
                        "controller に MRP deadline が立った(BTP では格下げされるはず)"
                    );
                    if let Some(d) = dir {
                        load_ble(btp_c, &txc[..d.len], *now, stats);
                    }
                    progressed = true;
                }
            }

            // MRP poll: BTP セッションでは再送/standalone ACK は生じないが、`poll` は
            // **終端済み(closing)交換の回収**を兼ねる(プール枯渇防止)。UDP 版 flush が
            // poll を回すのと同じ理由で、BTP でも各スタックを poll して交換を解放する。
            // 万一 poll が送出を返しても BTP に載せる(防御)。
            if btp_p.can_send() {
                if let Some(d) = dev.poll(*now, &mut txd) {
                    load_ble(btp_p, &txd[..d.len], *now, stats);
                    progressed = true;
                }
            }
            if btp_c.can_send() {
                if let Some(d) = ctrl.poll(*now, &mut txc) {
                    load_ble(btp_c, &txc[..d.len], *now, stats);
                    progressed = true;
                }
            }

            if !progressed {
                // 停滞。送信ブロック(window 満杯で次フラグメントを出せない)を解くための
                // 遅延 ACK 期限まで **単調に** 時刻を進める。ブロックしていない(= 純粋に
                // idle/liveness deadline が残るだけ)なら静穏として終了する。時刻を idle まで
                // 膨らませないことで、両スタックの時間軸を単調・現実的に保つ(fail-safe や
                // セッションの時刻依存挙動を壊さない)。
                let blocked = !btp_c.can_send() || !btp_p.can_send();
                if !blocked {
                    break;
                }
                let dl = match (btp_c.next_deadline(), btp_p.next_deadline()) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, None) => a,
                    (None, b) => b,
                };
                match dl {
                    Some(t) if t > *now => *now = t,
                    _ => break,
                }
            }
        }
    }

    #[cfg(feature = "ble")]
    #[test]
    fn controller_end_to_end_over_ble() {
        use crate::btp::BtpRole;
        use crate::transport::net::BtpConnId;

        // 小さい ATT_MTU → fragment = clamp(64-3,6,244) = 61。大きめのコミッショニング
        // メッセージ(証明書・Sigma2 等)が必ず複数フラグメントに割れる。
        const MTU: Option<u16> = Some(64);
        // controller が見るデバイスアドレス(= commission 先、= ctrl.handle_rx の source)。
        let dev_addr = PeerAddr::Ble(BtpConnId(1));
        // device が見るコントローラアドレス(= dev.handle_rx の source)。
        let ctrl_src_addr = PeerAddr::Ble(BtpConnId(1));

        let crypto = RustCrypto::new(SeqRng(0xC0FF_EE00_1234_5678));
        let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());

        // --- デバイス(responder / BTP peripheral)---
        let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
        let dev_creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
        let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0001), config, dev_creds);
        let im = InteractionModel::new(build_device(&fabrics));
        let mut dev: TestStack = MatterStack::new(&crypto, sc, im);

        // --- コントローラ(initiator / BTP central)---
        let ca = Ca::<Crb>::generate(
            &crypto,
            &mut SeqRng(0xCA00_0001),
            FABRIC_ID,
            COMM_NODE,
            0xFFF1,
            0,
        )
        .expect("Ca::generate");
        let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
        let sc_init = ScInitiator::new(&crypto, SeqRng(0x1C00_0001), ctrl_creds);
        let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

        let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
        comm.commission(dev_addr, PASSCODE, DEVICE_NODE, NOW)
            .unwrap();

        // --- BTP handshake(central ⇔ peripheral)---
        let mut btp_c = Btp::<6>::new(BtpRole::Central);
        let mut btp_p = Btp::<6>::new(BtpRole::Peripheral);
        {
            let mut f = [0u8; 128];
            let n = btp_c.start_handshake(&mut f, MTU, NOW).unwrap();
            btp_p.process_incoming(&f[..n], MTU, NOW).unwrap();
            let n = btp_p.process_outgoing(&mut f, MTU, NOW).unwrap();
            btp_c.process_incoming(&f[..n], MTU, NOW).unwrap();
        }
        assert!(btp_c.is_established() && btp_p.is_established());
        let frag_size = btp_c.fragment_size();
        assert_eq!(
            frag_size, 61,
            "small MTU(64)で fragment=clamp(64-3,6,244)=61 に交渉"
        );

        let mut stats = BleStats {
            frag_size,
            multi_fragment_seen: false,
            unsecured_checked: 0,
        };

        // --- コミッショニングを Mealy 機械で駆動(送信は BTP ループバック経由)---
        // clock は両スタック共通の**単調増加**する仮想時刻。pump が window ブロック解消の
        // ため遅延 ACK 期限まで進めることはあるが、決して巻き戻さない。
        let mut clock = NOW;
        let mut tx = [0u8; 1700];
        let mut final_phase = comm.phase();
        for _ in 0..60 {
            let out = comm.drive(&mut ctrl, clock, &mut tx);
            final_phase = out.phase;
            if let Some(d) = out.send {
                assert!(
                    matches!(d.addr, PeerAddr::Ble(_)),
                    "commission 送信先は BLE アドレス"
                );
                assert!(
                    ctrl.next_deadline(clock).is_none(),
                    "controller 送信直後に MRP deadline なし(BTP 格下げ)"
                );
                load_ble(&mut btp_c, &tx[..d.len], clock, &mut stats);
                pump_ble(
                    &mut btp_c,
                    &mut btp_p,
                    &mut ctrl,
                    &mut dev,
                    ctrl_src_addr,
                    dev_addr,
                    MTU,
                    &mut clock,
                    &mut stats,
                );
            }
            match out.phase {
                Phase::Done { .. } | Phase::Failed { .. } => break,
                _ => {}
            }
        }

        let case_session = match final_phase {
            Phase::Done { session } => session,
            other => panic!("commissioning did not complete over BLE: {other:?}"),
        };

        // (a) コミッショニング完走: デバイス fabric が生え、fail-safe は解除済み。
        assert_eq!(fabrics.borrow().len(), 1, "device fabric added over BLE");
        {
            let g = fabrics.borrow();
            let fe = g.get(NonZeroU8::new(1).unwrap()).unwrap();
            assert_eq!(fe.node_id(), DEVICE_NODE);
            assert_eq!(fe.fabric_id(), FABRIC_ID);
        }
        assert!(!dev.device().gc.fail_safe().is_armed());

        // --- 運用 API: CASE 上で OnOff On を invoke(BTP 経由)---
        assert!(!dev.device().onoff.is_on());
        let dir = ctrl
            .start_invoke(
                case_session,
                CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
                |w, t| {
                    w.start_struct(t)?;
                    w.end_container()
                },
                clock,
                &mut tx,
            )
            .expect("start OnOff invoke");
        assert!(
            ctrl.next_deadline(clock).is_none(),
            "invoke 送信直後に MRP deadline なし(BTP 格下げ)"
        );
        load_ble(&mut btp_c, &tx[..dir.len], clock, &mut stats);
        pump_ble(
            &mut btp_c,
            &mut btp_p,
            &mut ctrl,
            &mut dev,
            ctrl_src_addr,
            dev_addr,
            MTU,
            &mut clock,
            &mut stats,
        );
        match ctrl.im_take_event() {
            Some(ImEvent::InvokeDone { status }) => {
                assert_eq!(status, ImStatus::Success, "OnOff On over CASE/BLE");
            }
            other => panic!("expected InvokeDone, got {other:?}"),
        }
        // (a) On/Off 属性反映。
        assert!(
            dev.device().onoff.is_on(),
            "device OnOff attribute now true"
        );

        // --- 運用 API: CASE 上で OnOff を Read 読み戻し(BTP 経由)---
        let dir = ctrl
            .start_read(
                case_session,
                &[AttributePath::concrete(
                    EndpointId(1),
                    ClusterId(0x0006),
                    AttributeId(0x0000),
                )],
                clock,
                &mut tx,
            )
            .expect("start OnOff read");
        load_ble(&mut btp_c, &tx[..dir.len], clock, &mut stats);
        pump_ble(
            &mut btp_c,
            &mut btp_p,
            &mut ctrl,
            &mut dev,
            ctrl_src_addr,
            dev_addr,
            MTU,
            &mut clock,
            &mut stats,
        );
        assert_eq!(ctrl.im_take_event(), Some(ImEvent::ReadDone));
        let mut found_true = false;
        for report in ctrl.read_reports() {
            if let Ok(AttributeReportRef::Data(d)) = report {
                if d.path.to_concrete().map(|c| c.attribute.0) == Some(0x0000) {
                    let mut v = d.value();
                    if matches!(
                        v.read_next().ok().flatten().map(|e| e.value),
                        Some(TlvValue::Boolean(true))
                    ) {
                        found_true = true;
                    }
                }
            }
        }
        assert!(
            found_true,
            "controller reads back OnOff = true over CASE/BLE"
        );

        // (b) BTP 上の Matter メッセージで R フラグが立たなかった(検査が実際に走った)。
        assert!(
            stats.unsecured_checked >= 3,
            "unsecured メッセージの R/A フラグ検査が走っていない(={}件)",
            stats.unsecured_checked
        );
        // (c) 両スタックとも MRP 再送 deadline なしで終端。
        assert!(ctrl.next_deadline(clock).is_none());
        assert!(dev.next_deadline(clock).is_none());
        // (d) 少なくとも 1 メッセージが複数フラグメントにセグメント化された。
        assert!(
            stats.multi_fragment_seen,
            "全メッセージが単一フラグメントに収まった(セグメント化経路を踏んでいない)"
        );
    }
}

// ==========================================================================
// groupcast(group messaging 受信)E2E(`docs/design/group-messaging.md` §8)
// ==========================================================================

/// groupcast E2E: 運用グループ鍵で暗号化した OnOff Toggle のマルチキャスト datagram を
/// バイト列で組み、`handle_rx` が (a) 応答なしで状態を反転させ、(b) 同一カウンタの
/// 再送(リプレイ)を捨て、(c) 鍵未設定 group を捨てることを固定する。
#[test]
fn groupcast_toggle_end_to_end() {
    use crate::groups::{DefaultGroupStore, EpochKeyInput};

    const GID: u16 = 0x0101;
    const SRC_NODE: u64 = 0x0000_0000_C0DE_CAFE;
    let fabric = NonZeroU8::new(1).unwrap();

    let crypto = Crb::new(SeqRng(0x6006_0001));
    let fabrics: RefCell<FabricTable<Crb, 5>> = RefCell::new(FabricTable::new());
    let groups: RefCell<DefaultGroupStore> = RefCell::new(DefaultGroupStore::new());

    // 鍵設定(KeySetWrite + GroupKeyMap + AddGroup 相当を直接ストアに投入)。
    let cfid = [0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30];
    groups
        .borrow_mut()
        .set_keyset(
            fabric,
            42,
            0,
            &[EpochKeyInput {
                key: *b"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf",
                start_time_us: 2_220_000,
            }],
            &crypto,
            &cfid,
        )
        .unwrap();
    groups.borrow_mut().add_map(fabric, GID, 42).unwrap();
    groups.borrow_mut().add_member(fabric, GID, 1).unwrap(); // EP1 が加入

    let (op_key, gkh) = {
        let s = groups.borrow();
        let e = &s.keyset(fabric, 42).unwrap().epochs()[0];
        (*e.op_key(), e.gkh())
    };

    let mut dev = build_device(&fabrics);
    dev.groups = Some(&groups);
    let config = PaseConfig::from_passcode(PASSCODE, &SALT, ITERATIONS).unwrap();
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, SeqRng(0x5C00_0002), config, creds);
    let im = InteractionModel::new(dev);
    let mut stack: TestStack<'_> = MatterStack::new(&crypto, sc, im);
    stack.set_group_keys(&groups);

    // groupcast datagram(OnOff Toggle)をバイト列で組むヘルパ。
    let build = |ctr: u32, gid: u16, session_id: u16, out: &mut [u8]| -> usize {
        // InvokeRequest: {0: suppress=true, 1: timed=false, 2: [ {0: path list {1: cluster, 2: cmd}} ]}
        let mut payload = [0u8; 128];
        let plen = {
            let mut w = TlvWriter::new(&mut payload);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bool(&cx(0), true).unwrap();
            w.write_bool(&cx(1), false).unwrap();
            w.start_array(&cx(2)).unwrap();
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.start_list(&cx(0)).unwrap();
            w.write_u32(&cx(1), 0x0006).unwrap(); // OnOff
            w.write_u32(&cx(2), 0x02).unwrap(); // Toggle
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let pkt = PacketHeader {
            session_id,
            sec_flags: SecFlags::from_bits(SecFlags::GROUP_SESSION),
            ctr,
            src_node_id: Some(SRC_NODE),
            dst: DstNodeId::Group(gid),
        };
        let phdr = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
            proto_opcode: ImOpCode::InvokeRequest as u8,
            exch_id: 0x4747,
            proto_id: 0x0001,
            vendor_id: None,
            ack_ctr: None,
        };
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut store = [0u8; 256];
        let mut w = WriteBuf::new(&mut store, headroom).unwrap();
        w.append(&payload[..plen]).unwrap();
        SecureCodec::encrypt(&crypto, Some(&op_key), &pkt, &phdr, SRC_NODE, &mut w).unwrap();
        out[..w.len()].copy_from_slice(w.as_slice());
        w.len()
    };

    let mut tx = [0u8; 1600];
    assert!(!stack.device().onoff.is_on());

    // (a) groupcast Toggle → 応答なしで On になる。
    let mut wire = [0u8; 256];
    let n = build(100, GID, gkh, &mut wire);
    assert!(stack
        .handle_rx(&mut wire[..n], peer(), NOW, &mut tx)
        .is_none());
    assert!(stack.device().onoff.is_on(), "groupcast Toggle が届く");

    // (b) 同一カウンタの再送 = リプレイ → 捨てる(状態不変)。
    let n = build(100, GID, gkh, &mut wire);
    assert!(stack
        .handle_rx(&mut wire[..n], peer(), NOW + 10, &mut tx)
        .is_none());
    assert!(stack.device().onoff.is_on(), "リプレイは配送されない");

    // (c) 新しいカウンタは受理 → Off へ戻る。
    let n = build(101, GID, gkh, &mut wire);
    stack.handle_rx(&mut wire[..n], peer(), NOW + 20, &mut tx);
    assert!(!stack.device().onoff.is_on());

    // (d) 鍵がマップされていない group 宛(鍵候補なし)→ 捨てる。
    let n = build(102, 0x0202, gkh, &mut wire);
    stack.handle_rx(&mut wire[..n], peer(), NOW + 30, &mut tx);
    assert!(!stack.device().onoff.is_on());

    // (e) ワイヤ session id(GKH)不一致 → 捨てる(MIC 検証まで到達しない)。
    let n = build(103, GID, gkh.wrapping_add(1), &mut wire);
    stack.handle_rx(&mut wire[..n], peer(), NOW + 40, &mut tx);
    assert!(!stack.device().onoff.is_on());

    // (f) P(privacy)フラグ付きは非対応 → 捨てる。
    let n = build(104, GID, gkh, &mut wire);
    wire[3] |= SecFlags::PRIVACY;
    stack.handle_rx(&mut wire[..n], peer(), NOW + 50, &mut tx);
    assert!(!stack.device().onoff.is_on());

    // (g) メンバーでない endpoint しか無い group(メンバーシップ除去後)→ 配送されない。
    groups.borrow_mut().remove_member(fabric, GID, 1);
    let n = build(105, GID, gkh, &mut wire);
    stack.handle_rx(&mut wire[..n], peer(), NOW + 60, &mut tx);
    assert!(!stack.device().onoff.is_on());
}
