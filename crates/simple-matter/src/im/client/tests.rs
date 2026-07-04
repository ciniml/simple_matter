//! [`ImClient`](super::ImClient)(コントローラ)を既存 [`InteractionModel`](crate::im::engine::InteractionModel)
//! (デバイス)とメモリ内で直結する結合テスト。
//!
//! 2 つの [`ExchangeManager`] を相互の `recv` / `send_reliable` で駆動する軽量ポンプ
//! (`deliver`)で MRP・暗号境界も含めて 1 パケットずつ往復させ、
//! (a) 単一属性 Read、(b) ワイルドカード Read + チャンク継続(小 tx バッファ強制)、
//! (c) Invoke(On/Off)、(d) Write(NodeLabel)、(e) 不正パス Status 集約、(f) タイムアウト
//! を検証する。
//!
//! セキュアセッションは [`SessionManager::reserve`] + [`SessionManager::commit`] で
//! **鏡像鍵の CASE セッション**を両側に直接注入して確立する(PASE/CASE ハンドシェイクは
//! ピース A で別途検証済みのため、IM 単体の検証にはハンドシェイクを走らせない)。

use super::*;

use crate::buf::BufferPool;
use crate::crypto::rustcrypto::RustCrypto;
use crate::crypto::Rng;
use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, OnOffCluster,
};
use crate::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use crate::dm::{DataModel, ServerCluster};
use crate::error::Result as CrateResult;
use crate::exchange::{
    Dispatcher, ExchangeManager, HandlerAction, Outgoing, ProtocolHandler, ProtocolMux, RxMessage,
    SendTiming,
};
use crate::im::engine::InteractionModel;
use crate::im::wire::{AttributeId, AttributePath, AttributeReportRef, CommandId, CommandPath};
use crate::tlv::{TlvTag, TlvWriter};
use crate::transport::net::PeerAddr;
use crate::transport::session::{SessionId, SessionInit, SessionManager, SessionMode};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::NonZeroU8;

const NOW: u64 = 5000;
const DEVICE_NODE: u64 = 0x0000_0000_0001_0001;
const COMM_NODE: u64 = 0x0000_0000_0002_0002;

/// 結果バッファは 4KB(ワイルドカード全属性の連結を溢れさせないため)。
type ImC = ImClient<4096>;
type Dev4 = InteractionModel<Dev, 2, 2, 8>;
type Backend = RustCrypto<SeqRng>;

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

fn crypto() -> Backend {
    RustCrypto::new(SeqRng(0x00AB_1234_5678_9ABC))
}

fn peer() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        5540,
    ))
}

/// SC プレースホルダ(常に None)。IM テストでは SC 経路は使わない。
struct ScPh;
impl ProtocolHandler for ScPh {
    const PROTOCOL_ID: u16 = 0x0000;
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

// ==========================================================================
// テストデバイス(EP0: BasicInformation + Descriptor / EP1: OnOff + Descriptor)
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

static EP0_SERVERS: &[ClusterId] = &[ClusterId(0x0028), ClusterId(0x001D)];
static EP1_SERVERS: &[ClusterId] = &[ClusterId(0x0006), ClusterId(0x001D)];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
static EP0_PARTS: &[EndpointId] = &[EndpointId(1)];
static EP1_PARTS: &[EndpointId] = &[];

struct Dev {
    basic: BasicInformationCluster,
    desc0: DescriptorCluster,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
}

impl DataModel for Dev {
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
            (0, 0x001D) => Some(&self.desc0),
            (1, 0x0006) => Some(&self.onoff),
            (1, 0x001D) => Some(&self.desc1),
            _ => None,
        }
    }

    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x0028) => Some(&mut self.basic),
            (0, 0x001D) => Some(&mut self.desc0),
            (1, 0x0006) => Some(&mut self.onoff),
            (1, 0x001D) => Some(&mut self.desc1),
            _ => None,
        }
    }
}

fn build_device() -> Dev {
    Dev {
        basic: BasicInformationCluster::new(&CFG),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new(),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

// ==========================================================================
// スタック生成 + セッション注入 + ポンプ
// ==========================================================================

type DevMgr = ExchangeManager<ProtocolMux<ScPh, Dev4>, 4>;
type CliMgr = ExchangeManager<ProtocolMux<ScPh, ImC>, 4>;

fn device() -> (DevMgr, SessionManager<4>, BufferPool<3, 1600>) {
    let im: Dev4 = InteractionModel::new(build_device());
    (
        ExchangeManager::new(ProtocolMux::new(ScPh, im)),
        SessionManager::new(),
        BufferPool::new(),
    )
}

fn client() -> (CliMgr, SessionManager<4>, BufferPool<3, 1600>) {
    (
        ExchangeManager::new(ProtocolMux::new(ScPh, ImC::new())),
        SessionManager::new(),
        BufferPool::new(),
    )
}

/// 両 [`SessionManager`] に鏡像鍵の CASE セッションを注入し、クライアント側のハンドルを返す。
fn establish_case_pair(
    cli_sessions: &mut SessionManager<4>,
    dev_sessions: &mut SessionManager<4>,
) -> SessionId {
    let k1 = [0xA1u8; 16];
    let k2 = [0xB2u8; 16];
    let att = [0xC3u8; 16];
    let fab = NonZeroU8::new(1).unwrap();

    let cli_res = cli_sessions.reserve(peer(), NOW).unwrap();
    let dev_res = dev_sessions.reserve(peer(), NOW).unwrap();
    let cli_sid = cli_sessions.get(cli_res).unwrap().local_session_id();
    let dev_sid = dev_sessions.get(dev_res).unwrap().local_session_id();

    // クライアント: enc = I2R(送信) / dec = R2I(受信)。
    cli_sessions
        .commit(
            cli_res,
            SessionInit {
                peer_addr: peer(),
                local_node_id: COMM_NODE,
                peer_node_id: Some(DEVICE_NODE),
                peer_session_id: dev_sid,
                tx_ctr_start: 100,
                rx_ctr_start: 0,
                mode: SessionMode::Case { fabric_idx: fab },
                enc_key: k1,
                dec_key: k2,
                att_challenge: att,
            },
            NOW,
        )
        .unwrap();
    // デバイス: 鍵は鏡像(enc = k2 / dec = k1)。
    dev_sessions
        .commit(
            dev_res,
            SessionInit {
                peer_addr: peer(),
                local_node_id: DEVICE_NODE,
                peer_node_id: Some(COMM_NODE),
                peer_session_id: cli_sid,
                tx_ctr_start: 200,
                rx_ctr_start: 0,
                mode: SessionMode::Case { fabric_idx: fab },
                enc_key: k2,
                dec_key: k1,
                att_challenge: att,
            },
            NOW,
        )
        .unwrap();
    cli_res
}

/// 1 パケットを受け手へ配送し、応答(Respond/Close)があれば暗号化ワイヤを組み立てて返す。
///
/// `handler_tx` はハンドラの応答出力バッファ。小さくするとデバイス側の ReportData が
/// チャンク化される(チャンク継続テスト)。
fn deliver<H: Dispatcher>(
    mgr: &mut ExchangeManager<H, 4>,
    sessions: &mut SessionManager<4>,
    pool: &mut BufferPool<3, 1600>,
    crypto: &Backend,
    handler_tx: &mut [u8],
    wire: &mut [u8],
) -> Option<([u8; 1600], usize)> {
    let report = mgr
        .recv(sessions, crypto, peer(), NOW, wire, handler_tx)
        .unwrap();
    if let Some(b) = report.freed_tx {
        pool.release(b);
    }
    let (opcode, proto_id, len) = match report.action {
        HandlerAction::Respond {
            opcode,
            proto_id,
            len,
            ..
        }
        | HandlerAction::Close {
            opcode,
            proto_id,
            len,
            ..
        } => (opcode, proto_id, len),
        HandlerAction::None => return None,
    };
    let ex = report.exchange.unwrap();
    let mut payload = [0u8; 1600];
    payload[..len].copy_from_slice(&handler_tx[..len]);
    let sent = mgr
        .send_reliable(
            sessions,
            crypto,
            pool,
            ex,
            &Outgoing {
                proto_id,
                opcode,
                payload: &payload[..len],
            },
            SendTiming {
                now_ms: NOW,
                jitter_rand: 0,
            },
        )
        .unwrap();
    let mut out = [0u8; 1600];
    out[..sent.len].copy_from_slice(&pool.get(sent.buf).unwrap()[..sent.len]);
    Some((out, sent.len))
}

/// クライアントが開始した最初の IM リクエストを送出し、往復ポンプで完走させる。
///
/// `dev_tx_cap` はデバイスハンドラ出力バッファ長(チャンク化の強制に使う)。
#[allow(clippy::too_many_arguments)]
fn run(
    crypto: &Backend,
    cli_mgr: &mut CliMgr,
    cli_sessions: &mut SessionManager<4>,
    cli_pool: &mut BufferPool<3, 1600>,
    dev_mgr: &mut DevMgr,
    dev_sessions: &mut SessionManager<4>,
    dev_pool: &mut BufferPool<3, 1600>,
    dev_tx_cap: usize,
    ex: ExchangeId,
    first_opcode: u8,
    payload: &[u8],
) {
    let sent = cli_mgr
        .send_reliable(
            cli_sessions,
            crypto,
            cli_pool,
            ex,
            &Outgoing {
                proto_id: PROTO_ID_INTERACTION_MODEL,
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
    wire[..wlen].copy_from_slice(&cli_pool.get(sent.buf).unwrap()[..wlen]);

    let mut dev_tx = [0u8; 1600];
    let mut cli_tx = [0u8; 1600];
    let mut to_device = true;
    for _ in 0..40 {
        let resp = if to_device {
            deliver(
                dev_mgr,
                dev_sessions,
                dev_pool,
                crypto,
                &mut dev_tx[..dev_tx_cap],
                &mut wire[..wlen],
            )
        } else {
            deliver(
                cli_mgr,
                cli_sessions,
                cli_pool,
                crypto,
                &mut cli_tx,
                &mut wire[..wlen],
            )
        };
        match resp {
            Some((w, l)) => {
                wire = w;
                wlen = l;
                to_device = !to_device;
            }
            None => break,
        }
    }
}

/// 空フィールド(フィールドの無いコマンド)を書くクロージャ。
fn empty_fields(w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()> {
    w.start_struct(tag)?;
    w.end_container()
}

// ==========================================================================
// (a) 単一属性 Read
// ==========================================================================

#[test]
fn single_attribute_read() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let mut out = [0u8; 256];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_read(ex, &paths, &mut out, NOW)
        .unwrap();
    assert!(cli_mgr.handler().im.is_busy());

    run(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        ex,
        ImOpCode::ReadRequest as u8,
        &out[..plen],
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::ReadDone)
    );
    assert!(!cli_mgr.handler().im.is_busy());

    let im = &cli_mgr.handler().im;
    let mut count = 0;
    let mut value = None;
    for r in im.read_reports() {
        match r.unwrap() {
            AttributeReportRef::Data(d) => {
                count += 1;
                let mut rd = d.value();
                let e = rd.read_next().unwrap().unwrap();
                value = Some(e.value.as_bool().unwrap());
            }
            AttributeReportRef::Status(s) => panic!("unexpected status {:?}", s.status.status),
        }
    }
    assert_eq!(count, 1, "one attribute report");
    assert_eq!(value, Some(false), "OnOff initial state = false");
}

// ==========================================================================
// (b) ワイルドカード Read + チャンク継続(小 tx バッファ強制)
// ==========================================================================

#[test]
fn wildcard_read_with_chunking() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    // 全ワイルドカード(endpoint/cluster/attribute すべて None)。
    let paths = [AttributePath::default()];
    let mut out = [0u8; 256];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_read(ex, &paths, &mut out, NOW)
        .unwrap();

    // デバイス出力バッファを小さく(160B)してチャンク化を強制する。
    run(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        160,
        ex,
        ImOpCode::ReadRequest as u8,
        &out[..plen],
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::ReadDone)
    );
    let im = &cli_mgr.handler().im;
    assert!(!im.is_truncated(), "result must not overflow");

    let mut data = 0;
    for r in im.read_reports() {
        match r.unwrap() {
            AttributeReportRef::Data(_) => data += 1,
            AttributeReportRef::Status(_) => {}
        }
    }
    // 全クラスタの属性(グローバル含む)が集約され、複数チャンクにまたがる。
    assert!(data > 8, "wildcard read collected many attributes: {data}");
}

// ==========================================================================
// (c) Invoke(On/Off)
// ==========================================================================

#[test]
fn invoke_onoff_on() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);
    assert!(!dev_mgr.handler().im.data_model().onoff.is_on());

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let path = CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x0001)); // On
    let mut out = [0u8; 128];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_invoke(ex, path, empty_fields, &mut out, NOW)
        .unwrap();

    run(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        ex,
        ImOpCode::InvokeRequest as u8,
        &out[..plen],
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::InvokeDone {
            status: ImStatus::Success
        })
    );
    assert!(
        dev_mgr.handler().im.data_model().onoff.is_on(),
        "device OnOff is now true"
    );
}

// ==========================================================================
// (d) Write(NodeLabel)
// ==========================================================================

#[test]
fn write_node_label() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let path = AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005));
    let mut out = [0u8; 128];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_write(
            ex,
            &path,
            |w, tag| w.write_utf8(tag, "kitchen"),
            &mut out,
            NOW,
        )
        .unwrap();

    run(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        ex,
        ImOpCode::WriteRequest as u8,
        &out[..plen],
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::WriteDone {
            status: ImStatus::Success
        })
    );
    assert_eq!(
        dev_mgr.handler().im.data_model().basic.node_label(),
        "kitchen"
    );
}

// ==========================================================================
// (e) 不正パスの Status 集約
// ==========================================================================

#[test]
fn read_invalid_path_yields_status() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    // 存在しないクラスタ 0x1234。
    let paths = [AttributePath::concrete(
        EndpointId(0),
        ClusterId(0x1234),
        AttributeId(0x0001),
    )];
    let mut out = [0u8; 128];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_read(ex, &paths, &mut out, NOW)
        .unwrap();

    run(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        ex,
        ImOpCode::ReadRequest as u8,
        &out[..plen],
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::ReadDone)
    );
    let im = &cli_mgr.handler().im;
    let mut statuses = 0;
    for r in im.read_reports() {
        match r.unwrap() {
            AttributeReportRef::Status(s) => {
                statuses += 1;
                assert_eq!(s.status.status, ImStatus::UnsupportedCluster);
            }
            AttributeReportRef::Data(_) => panic!("unexpected data report"),
        }
    }
    assert_eq!(statuses, 1, "one status report for the invalid path");
}

// ==========================================================================
// (f) タイムアウト
// ==========================================================================

#[test]
fn transaction_times_out() {
    let mut im = ImC::new();
    let ex = ExchangeId::from_parts(SessionId::from_raw(0), 1);
    let paths = [AttributePath::concrete(
        EndpointId(0),
        ClusterId(0x0028),
        AttributeId(0x0005),
    )];
    let mut out = [0u8; 128];
    im.start_read(ex, &paths, &mut out, 0).unwrap();
    assert!(im.is_busy());

    // 期限ちょうどでは掃除しない。
    assert!(!im.on_tick(CLIENT_TXN_TIMEOUT_MS));
    assert!(im.is_busy());
    // 期限超過で破棄し Failed(Timeout)。
    assert!(im.on_tick(CLIENT_TXN_TIMEOUT_MS + 1));
    assert_eq!(
        im.take_event(),
        Some(ImEvent::Failed {
            status: ImStatus::Timeout
        })
    );
    assert!(!im.is_busy());
}

// ==========================================================================
// 二重開始(Busy)
// ==========================================================================

#[test]
fn second_start_is_busy() {
    let mut im = ImC::new();
    let ex = ExchangeId::from_parts(SessionId::from_raw(0), 1);
    let paths = [AttributePath::concrete(
        EndpointId(0),
        ClusterId(0x0028),
        AttributeId(0x0005),
    )];
    let mut out = [0u8; 128];
    im.start_read(ex, &paths, &mut out, 0).unwrap();
    assert_eq!(
        im.start_read(ex, &paths, &mut out, 0),
        Err(crate::error::Error::NoSpace)
    );
}
