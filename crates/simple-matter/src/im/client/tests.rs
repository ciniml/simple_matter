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
use crate::im::wire::{
    AttributeId, AttributePath, AttributeReportRef, CommandId, CommandPath, EventId, EventPath,
    EventReportRef,
};
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
        HandlerAction::None | HandlerAction::CloseSilent => return None,
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
    wire[..sent.len].copy_from_slice(&cli_pool.get(sent.buf).unwrap()[..sent.len]);
    pump(
        crypto,
        cli_mgr,
        cli_sessions,
        cli_pool,
        dev_mgr,
        dev_sessions,
        dev_pool,
        dev_tx_cap,
        wire,
        sent.len,
        true,
    );
}

/// ワイヤ 1 通(`wire[..wlen]`)を `to_device` の向きに配送し、応答が続く限り往復させる。
#[allow(clippy::too_many_arguments)]
fn pump(
    crypto: &Backend,
    cli_mgr: &mut CliMgr,
    cli_sessions: &mut SessionManager<4>,
    cli_pool: &mut BufferPool<3, 1600>,
    dev_mgr: &mut DevMgr,
    dev_sessions: &mut SessionManager<4>,
    dev_pool: &mut BufferPool<3, 1600>,
    dev_tx_cap: usize,
    mut wire: [u8; 1600],
    mut wlen: usize,
    mut to_device: bool,
) {
    let mut dev_tx = [0u8; 1600];
    let mut cli_tx = [0u8; 1600];
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
    assert!(im.on_tick(CLIENT_TXN_TIMEOUT_MS).is_none());
    assert!(im.is_busy());
    // 期限超過で破棄し Failed(Timeout)。
    assert!(im.on_tick(CLIENT_TXN_TIMEOUT_MS + 1).is_some());
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

// ==========================================================================
// (g) Subscribe: プライミング → 確立 → デバイス発レポート受信(§4.5)
// ==========================================================================

/// デバイス側の due 購読を 1 件レポート送出する(`MatterStack::stage_subscription_report` 相当)。
///
/// 戻りは (ワイヤ, 長さ)。due が無ければ `None`。`report_cap` はレポート payload バッファ長
/// (小さくするとチャンク化を強制)。
fn stage_device_report(
    crypto: &Backend,
    dev_mgr: &mut DevMgr,
    dev_sessions: &mut SessionManager<4>,
    dev_pool: &mut BufferPool<3, 1600>,
    report_cap: usize,
    now: u64,
) -> Option<([u8; 1600], usize)> {
    let due = dev_mgr.handler_mut().im.poll_subscriptions(now)?;
    let ex = dev_mgr.open_initiator(due.session).unwrap();
    let mut payload = [0u8; 1600];
    let len = dev_mgr
        .handler_mut()
        .im
        .build_report(due.subscription, ex, &mut payload[..report_cap], now)
        .unwrap();
    let sent = dev_mgr
        .send_reliable(
            dev_sessions,
            crypto,
            dev_pool,
            ex,
            &Outgoing {
                proto_id: PROTO_ID_INTERACTION_MODEL,
                opcode: ImOpCode::ReportData as u8,
                payload: &payload[..len],
            },
            SendTiming {
                now_ms: now,
                jitter_rand: 0,
            },
        )
        .unwrap();
    let mut out = [0u8; 1600];
    out[..sent.len].copy_from_slice(&dev_pool.get(sent.buf).unwrap()[..sent.len]);
    Some((out, sent.len))
}

/// subscribe → priming → SubscribeDone まで駆動し、購読 ID と max_interval を返す。
#[allow(clippy::too_many_arguments)]
fn establish_subscription(
    crypto: &Backend,
    cli_mgr: &mut CliMgr,
    cli_sessions: &mut SessionManager<4>,
    cli_pool: &mut BufferPool<3, 1600>,
    dev_mgr: &mut DevMgr,
    dev_sessions: &mut SessionManager<4>,
    dev_pool: &mut BufferPool<3, 1600>,
    dev_tx_cap: usize,
    cli_s: SessionId,
    paths: &[AttributePath],
    min_s: u16,
    max_s: u16,
) -> (u32, u16) {
    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let mut out = [0u8; 256];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_subscribe(ex, paths, min_s, max_s, &mut out, NOW)
        .unwrap();
    run(
        crypto,
        cli_mgr,
        cli_sessions,
        cli_pool,
        dev_mgr,
        dev_sessions,
        dev_pool,
        dev_tx_cap,
        ex,
        ImOpCode::SubscribeRequest as u8,
        &out[..plen],
    );
    match cli_mgr.handler_mut().im.take_event() {
        Some(ImEvent::SubscribeDone {
            subscription_id,
            max_interval_s,
            ..
        }) => (subscription_id, max_interval_s),
        other => panic!("expected SubscribeDone, got {other:?}"),
    }
}

#[test]
fn subscribe_priming_and_device_report() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (sub_id, max_s) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        cli_s,
        &paths,
        0,
        60,
    );
    assert_eq!(max_s, 60, "negotiated max interval echoes ceiling");
    assert!(!cli_mgr.handler().im.is_busy(), "txn slot freed");
    assert_eq!(cli_mgr.handler().im.subscription_count(), 1);
    assert_eq!(dev_mgr.handler().im.subscription_count(), 1);

    // --- 属性変化 → デバイス発レポート ---
    dev_mgr.handler_mut().im.data_model_mut().onoff.set(true);
    let (wire, wlen) = stage_device_report(
        &crypto,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        NOW,
    )
    .expect("dirty subscription is due (min=0)");
    pump(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        wire,
        wlen,
        false,
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionReport {
            session: cli_s,
            subscription_id: sub_id
        })
    );
    let im = &cli_mgr.handler().im;
    assert!(im.report_exchange().is_none(), "report exchange finished");
    assert!(!im.is_sub_truncated());
    let mut value = None;
    for r in im.sub_reports() {
        if let AttributeReportRef::Data(d) = r.unwrap() {
            let mut rd = d.value();
            value = Some(rd.read_next().unwrap().unwrap().value.as_bool().unwrap());
        }
    }
    assert_eq!(value, Some(true), "report carries the changed OnOff value");

    // ack 済みなので dirty は消えている(即座に次の due は無い)。
    assert!(dev_mgr.handler_mut().im.poll_subscriptions(NOW).is_none());
}

// ==========================================================================
// (g') イベント購読: プライミング + デバイス発イベントレポート(設計 §12)
// ==========================================================================

#[test]
fn subscribe_events_priming_and_device_report() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    // デバイスに既存 StartUp イベントを 1 件積む(number 0)。
    dev_mgr
        .handler_mut()
        .im
        .post_event(
            EndpointId(0),
            ClusterId(0x0028),
            EventId(0),
            crate::im::events::PRIORITY_CRITICAL,
            NOW,
            |w, tag| {
                w.start_struct(tag)?;
                w.write_u32(&TlvTag::ContextSpecific(0), 0xABCD)?;
                w.end_container()
            },
        )
        .unwrap();

    // イベントのみの購読(属性パス 0 本、StartUp イベントパス)。
    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let event_paths = [EventPath::concrete(
        EndpointId(0),
        ClusterId(0x0028),
        EventId(0),
    )];
    let mut out = [0u8; 256];
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_subscribe_events(ex, &[], &event_paths, None, 0, 60, &mut out, NOW)
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
        ImOpCode::SubscribeRequest as u8,
        &out[..plen],
    );
    let sub_id = match cli_mgr.handler_mut().im.take_event() {
        Some(ImEvent::SubscribeDone {
            subscription_id, ..
        }) => subscription_id,
        other => panic!("expected SubscribeDone, got {other:?}"),
    };
    assert_eq!(dev_mgr.handler().im.subscription_count(), 1);

    // 新しいイベントを積む(number 1)。
    dev_mgr
        .handler_mut()
        .im
        .post_event(
            EndpointId(0),
            ClusterId(0x0028),
            EventId(0),
            crate::im::events::PRIORITY_CRITICAL,
            NOW,
            |w, tag| {
                w.start_struct(tag)?;
                w.write_u32(&TlvTag::ContextSpecific(0), 0x1234)?;
                w.end_container()
            },
        )
        .unwrap();

    let (wire, wlen) = stage_device_report(
        &crypto,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        NOW,
    )
    .expect("new event makes the subscription due (min=0)");
    pump(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        wire,
        wlen,
        false,
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionReport {
            session: cli_s,
            subscription_id: sub_id
        })
    );
    let im = &cli_mgr.handler().im;
    // 属性レポートは無く、イベントレポート(新規 number 1)が載る。
    assert_eq!(im.sub_reports().count(), 0, "no attribute reports");
    let mut n = 0;
    let mut last = (0u64, 0u64);
    for r in im.sub_event_reports() {
        if let EventReportRef::Data(d) = r.unwrap() {
            let mut v = d.value();
            let _struct = v.read_next().unwrap().unwrap();
            let sw = v.read_next().unwrap().unwrap().value.as_unsigned().unwrap();
            last = (d.number, sw);
            n += 1;
        }
    }
    assert_eq!(n, 1, "only the new event is delivered");
    assert_eq!(
        last,
        (1, 0x1234),
        "new event number 1, softwareVersion 0x1234"
    );
}

// ==========================================================================
// (h) チャンク化されたデバイス発レポート(小バッファ強制)
// ==========================================================================

#[test]
fn chunked_device_report() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    // 全ワイルドカード購読(レポートが複数チャンクにまたがる)。
    let paths = [AttributePath::default()];
    let (sub_id, _max) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        160,
        cli_s,
        &paths,
        0,
        60,
    );

    dev_mgr.handler_mut().im.data_model_mut().onoff.set(true);
    // レポートも 160B バッファでチャンク化を強制。継続チャンクは client の
    // StatusResponse(SUCCESS) 受信(pump 内)で device の on_status が送る。
    let (wire, wlen) = stage_device_report(
        &crypto,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        160,
        NOW,
    )
    .expect("due");
    pump(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        160,
        wire,
        wlen,
        false,
    );

    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionReport {
            session: cli_s,
            subscription_id: sub_id
        })
    );
    let im = &cli_mgr.handler().im;
    assert!(!im.is_sub_truncated());
    assert!(im.report_exchange().is_none());
    // 差分レポート(設計 §6.2): 変更した OnOff クラスタの属性(固有 + グローバル)だけが
    // 複数チャンクにまたがって届き、他クラスタは含まれない。
    let mut data = 0;
    for r in im.sub_reports() {
        if let AttributeReportRef::Data(d) = r.unwrap() {
            assert_eq!(d.path.cluster, Some(ClusterId(0x0006)));
            data += 1;
        }
    }
    assert!(
        data > 3,
        "chunked report aggregated the OnOff cluster attributes: {data}"
    );
}

// ==========================================================================
// (i) keep-alive 途絶 → SubscriptionLost
// ==========================================================================

#[test]
fn subscription_lost_on_max_interval_timeout() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (sub_id, max_s) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        cli_s,
        &paths,
        0,
        1,
    );
    assert_eq!(max_s, 1);

    let deadline = NOW + (max_s as u64) * 1000 + SUBSCRIPTION_GRACE_MS;
    // 期限ちょうどではロストしない。
    cli_mgr.handler_mut().im.on_tick(deadline);
    assert_eq!(cli_mgr.handler_mut().im.take_event(), None);
    assert_eq!(cli_mgr.handler().im.subscription_count(), 1);
    // 期限超過でロスト検出。
    cli_mgr.handler_mut().im.on_tick(deadline + 1);
    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionLost {
            session: cli_s,
            subscription_id: sub_id
        })
    );
    assert_eq!(cli_mgr.handler().im.subscription_count(), 0);
}

// ==========================================================================
// (j) keep-alive レポートで last_report が更新されロストしない
// ==========================================================================

#[test]
fn keep_alive_report_refreshes_liveness() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (sub_id, max_s) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        cli_s,
        &paths,
        0,
        1,
    );

    // 属性変化なしでも max interval 到達でデバイスが keep-alive(全パス再送)を出す。
    let t1 = NOW + (max_s as u64) * 1000;
    let (wire, wlen) = stage_device_report(
        &crypto,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        t1,
    )
    .expect("max interval reached → keep-alive report due");
    pump(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        wire,
        wlen,
        false,
    );
    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionReport {
            session: cli_s,
            subscription_id: sub_id
        })
    );

    // last_report が t1 に更新されている: 旧期限では生存、新期限で初めてロスト。
    // (pump は NOW 固定時刻で配送するが、client の last_report 更新は handle の now_ms =
    // 受信時刻 NOW を使うため、ここでは on_tick の閾値だけを確認する)
    let im = &mut cli_mgr.handler_mut().im;
    im.on_tick(NOW + (max_s as u64) * 1000 + SUBSCRIPTION_GRACE_MS);
    assert_eq!(im.take_event(), None, "still alive after keep-alive");
    assert_eq!(im.subscription_count(), 1);
}

// ==========================================================================
// (l) T8b §16.6 P4: remove_subscription 後のレポートは InvalidSubscription
// ==========================================================================

/// `remove_subscription` でローカルのテーブルから消した購読へレポートが届いたら
/// `InvalidSubscription` を返す(デバイス側は §16.6 P2 の修正でその購読を捨てるので、
/// シムが購読を張り直しても幽霊購読が残らない)。
#[test]
fn removed_subscription_report_is_rejected() {
    use crate::im::wire::{encode_report_data, ReportDataHeader};
    use crate::transport::header::{ExchFlags, PayloadHeader};

    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (sub_id, _max_s) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        cli_s,
        &paths,
        0,
        1,
    );
    assert_eq!(cli_mgr.handler().im.subscription_count(), 1);

    // ローカル破棄(シムの sm_ctrl_unsubscribe / 再購読が呼ぶ経路)。冪等。
    assert!(cli_mgr.handler_mut().im.remove_subscription(cli_s, sub_id));
    assert!(!cli_mgr.handler_mut().im.remove_subscription(cli_s, sub_id));
    assert_eq!(cli_mgr.handler().im.subscription_count(), 0);
    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        None,
        "明示破棄では SubscriptionLost を積まない"
    );

    // 旧購読のレポートが届く → InvalidSubscription で終端(デバイスがこれで購読を捨てる)。
    let mut payload = [0u8; 128];
    let plen = encode_report_data(
        &mut payload,
        ReportDataHeader {
            subscription_id: Some(sub_id),
            more_chunks: false,
            suppress_response: false,
        },
        |_| Ok(()),
    )
    .unwrap();
    let hdr = PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
        proto_opcode: ImOpCode::ReportData as u8,
        exch_id: 0x78,
        proto_id: PROTO_ID_INTERACTION_MODEL,
        vendor_id: None,
        ack_ctr: None,
    };
    let rx = RxMessage {
        header: &hdr,
        payload: &payload[..plen],
        exchange: ExchangeId::from_parts(cli_s, 0x78),
        role: crate::exchange::Role::Responder,
    };
    let mut tx = [0u8; 64];
    let action = cli_mgr
        .handler_mut()
        .im
        .handle(&rx, &mut tx, &mut cli_sessions, NOW)
        .unwrap();
    let HandlerAction::Close { opcode, len, .. } = action else {
        panic!("expected Close, got {action:?}");
    };
    assert_eq!(opcode, ImOpCode::StatusResponse as u8);
    assert_eq!(
        StatusResponse::decode(&tx[..len]).unwrap().status,
        ImStatus::InvalidSubscription
    );

    // セッション単位の破棄も同様(戻り値 = 本数)。
    assert_eq!(
        cli_mgr
            .handler_mut()
            .im
            .remove_subscriptions_on_session(cli_s),
        0,
        "既に空"
    );
}

// ==========================================================================
// (m) T8b §16.6 P3: 猶予 30 秒(max+29 s は生存 / max+31 s でロスト)
// ==========================================================================

/// MRP は最大 10 送信(累計 ~34 秒)まで再送するため、レポート 1 通の再送が数十秒続いても
/// 誤 LOST しない(旧値 5 秒では再購読 churn → デバイス側に幽霊購読を量産していた)。
#[test]
fn subscription_grace_tolerates_mrp_retransmission() {
    assert_eq!(SUBSCRIPTION_GRACE_MS, 30_000, "設計 §16.6 P3");

    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (sub_id, max_s) = establish_subscription(
        &crypto,
        &mut cli_mgr,
        &mut cli_sessions,
        &mut cli_pool,
        &mut dev_mgr,
        &mut dev_sessions,
        &mut dev_pool,
        1600,
        cli_s,
        &paths,
        0,
        1,
    );
    let max_ms = NOW + (max_s as u64) * 1000;

    // max + 29 秒(MRP 再送の途中)ではロストしない。
    cli_mgr.handler_mut().im.on_tick(max_ms + 29_000);
    assert_eq!(cli_mgr.handler_mut().im.take_event(), None);
    assert_eq!(cli_mgr.handler().im.subscription_count(), 1);
    // max + 31 秒(MRP が諦めた後)でロスト。
    cli_mgr.handler_mut().im.on_tick(max_ms + 31_000);
    assert_eq!(
        cli_mgr.handler_mut().im.take_event(),
        Some(ImEvent::SubscriptionLost {
            session: cli_s,
            subscription_id: sub_id
        })
    );
    assert_eq!(cli_mgr.handler().im.subscription_count(), 0);
}

// ==========================================================================
// (k) 未知の購読 ID → StatusResponse(InvalidSubscription) で終端
// ==========================================================================

#[test]
fn unknown_subscription_report_is_rejected() {
    use crate::im::wire::{encode_report_data, ReportDataHeader};
    use crate::transport::header::{ExchFlags, PayloadHeader};

    let mut im = ImC::new();
    let mut sessions: SessionManager<4> = SessionManager::new();

    let mut payload = [0u8; 128];
    let plen = encode_report_data(
        &mut payload,
        ReportDataHeader {
            subscription_id: Some(999),
            more_chunks: false,
            suppress_response: false,
        },
        |_| Ok(()),
    )
    .unwrap();

    let hdr = PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
        proto_opcode: ImOpCode::ReportData as u8,
        exch_id: 0x77,
        proto_id: PROTO_ID_INTERACTION_MODEL,
        vendor_id: None,
        ack_ctr: None,
    };
    let rx = RxMessage {
        header: &hdr,
        payload: &payload[..plen],
        exchange: ExchangeId::from_parts(SessionId::from_raw(3), 0x77),
        role: crate::exchange::Role::Responder,
    };
    let mut tx = [0u8; 64];
    let action = im.handle(&rx, &mut tx, &mut sessions, NOW).unwrap();
    let HandlerAction::Close { opcode, len, .. } = action else {
        panic!("expected Close, got {action:?}");
    };
    assert_eq!(opcode, ImOpCode::StatusResponse as u8);
    let sr = StatusResponse::decode(&tx[..len]).unwrap();
    assert_eq!(sr.status, ImStatus::InvalidSubscription);
    assert_eq!(im.take_event(), None, "no event for rejected report");
}

// ==========================================================================
// timed invoke(TimedRequest → StatusResponse → Invoke)
// ==========================================================================

#[test]
fn timed_invoke_onoff_on() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);
    assert!(!dev_mgr.handler().im.data_model().onoff.is_on());

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let path = CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x0001)); // On
    let mut out = [0u8; 128];
    // TimedRequest が out に書かれ、InvokeRequest(timed=true)は client 内部に退避される。
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_invoke_timed(ex, 10_000, path, empty_fields, &mut out, NOW)
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
        ImOpCode::TimedRequest as u8,
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
        "device OnOff turned on via timed invoke"
    );
}

// ==========================================================================
// timed write(TimedRequest → StatusResponse → Write)
// ==========================================================================

#[test]
fn timed_write_node_label() {
    let crypto = crypto();
    let (mut dev_mgr, mut dev_sessions, mut dev_pool) = device();
    let (mut cli_mgr, mut cli_sessions, mut cli_pool) = client();
    let cli_s = establish_case_pair(&mut cli_sessions, &mut dev_sessions);

    let ex = cli_mgr.open_initiator(cli_s).unwrap();
    let path = AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005));
    let mut out = [0u8; 128];
    // TimedRequest が out に書かれ、WriteRequest(timed=true)は client 内部に退避される。
    let plen = cli_mgr
        .handler_mut()
        .im
        .start_write_timed(
            ex,
            10_000,
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
        ImOpCode::TimedRequest as u8,
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
        "kitchen",
        "device NodeLabel written via timed write"
    );
}

// ==========================================================================
// (n) T8c §16.6 P7: 購読 ID は `(session, id)` で初めて一意
// ==========================================================================

/// 購読 `(session, id)` を `im` に確立する(プライミング省略、SubscribeResponse 直投入)。
fn establish_sub_on_session(
    im: &mut ImC,
    sessions: &mut SessionManager<4>,
    session: SessionId,
    exch_id: u16,
    sub_id: u32,
    max_interval_s: u16,
    now: u64,
) {
    use crate::transport::header::{ExchFlags, PayloadHeader};

    let ex = ExchangeId::from_parts(session, exch_id);
    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let mut out = [0u8; 256];
    im.start_subscribe(ex, &paths, 0, max_interval_s, &mut out, now)
        .unwrap();

    let mut payload = [0u8; 64];
    let plen = SubscribeResponse::new(sub_id, max_interval_s)
        .encode(&mut payload)
        .unwrap();
    let hdr = PayloadHeader {
        exch_flags: ExchFlags::from_bits(0),
        proto_opcode: ImOpCode::SubscribeResponse as u8,
        exch_id,
        proto_id: PROTO_ID_INTERACTION_MODEL,
        vendor_id: None,
        ack_ctr: None,
    };
    let rx = RxMessage {
        header: &hdr,
        payload: &payload[..plen],
        exchange: ex,
        role: crate::exchange::Role::Initiator,
    };
    let mut tx = [0u8; 64];
    im.handle(&rx, &mut tx, sessions, now).unwrap();
    assert_eq!(
        im.take_event(),
        Some(ImEvent::SubscribeDone {
            session,
            subscription_id: sub_id,
            max_interval_s,
        })
    );
}

/// デバイス発レポート(空 payload)を `session` 上の新規 responder exchange で投げ、
/// 返った `StatusResponse` のステータスを返す。
fn feed_device_report(
    im: &mut ImC,
    sessions: &mut SessionManager<4>,
    session: SessionId,
    exch_id: u16,
    sub_id: u32,
    now: u64,
) -> ImStatus {
    use crate::im::wire::{encode_report_data, ReportDataHeader};
    use crate::transport::header::{ExchFlags, PayloadHeader};

    let mut payload = [0u8; 128];
    let plen = encode_report_data(
        &mut payload,
        ReportDataHeader {
            subscription_id: Some(sub_id),
            more_chunks: false,
            suppress_response: false,
        },
        |_| Ok(()),
    )
    .unwrap();
    let hdr = PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
        proto_opcode: ImOpCode::ReportData as u8,
        exch_id,
        proto_id: PROTO_ID_INTERACTION_MODEL,
        vendor_id: None,
        ack_ctr: None,
    };
    let rx = RxMessage {
        header: &hdr,
        payload: &payload[..plen],
        exchange: ExchangeId::from_parts(session, exch_id),
        role: crate::exchange::Role::Responder,
    };
    let mut tx = [0u8; 64];
    let action = im.handle(&rx, &mut tx, sessions, now).unwrap();
    let HandlerAction::Close { opcode, len, .. } = action else {
        panic!("expected Close, got {action:?}");
    };
    assert_eq!(opcode, ImOpCode::StatusResponse as u8);
    StatusResponse::decode(&tx[..len]).unwrap().status
}

/// 購読 ID はデバイスごとの採番なので別デバイス(= 別セッション)間で衝突する。
/// ID だけで照合していた頃は、死んだノードの幽霊レポートが別ノードの購読として受理され、
/// (1) 幽霊購読が掃除されない (2) 偽の keep-alive で LOST 検出が効かない、が起きていた。
#[test]
fn same_subscription_id_on_two_sessions_is_not_confused() {
    const SUB: u32 = 2; // 実機(NanoC6 の幽霊 / AirQ の再購読)で衝突した ID。
    const MAX_S: u16 = 10;
    /// 確立時刻から数えたロスト期限(maxInterval + 猶予)。
    const LOST_AFTER_MS: u64 = (MAX_S as u64) * 1000 + SUBSCRIPTION_GRACE_MS;

    let mut im = ImC::new();
    let mut sessions: SessionManager<4> = SessionManager::new();
    let sa = SessionId::from_raw(1);
    let sb = SessionId::from_raw(2);

    establish_sub_on_session(&mut im, &mut sessions, sa, 0x11, SUB, MAX_S, NOW);
    establish_sub_on_session(&mut im, &mut sessions, sb, 0x22, SUB, MAX_S, NOW);
    assert_eq!(
        im.subscription_count(),
        2,
        "同じ ID でも別セッションなら別購読"
    );

    // セッション B のレポートは B の購読として受理される(A には混ざらない)。
    assert_eq!(
        feed_device_report(&mut im, &mut sessions, sb, 0x31, SUB, NOW + 5_000),
        ImStatus::Success
    );
    assert_eq!(
        im.take_event(),
        Some(ImEvent::SubscriptionReport {
            session: sb,
            subscription_id: SUB,
        })
    );

    // A の last_report は更新されていないので、A だけが自分の期限でロストする。
    im.on_tick(NOW + LOST_AFTER_MS + 1);
    assert_eq!(
        im.take_event(),
        Some(ImEvent::SubscriptionLost {
            session: sa,
            subscription_id: SUB,
        }),
        "B のレポートで A の keep-alive が偽装されてはならない"
    );
    assert_eq!(im.take_event(), None);
    assert_eq!(im.subscription_count(), 1, "B の購読は生き残る");

    // 死んだ A 側からの幽霊レポートは未知扱い(InvalidSubscription)で、B は refresh しない。
    assert_eq!(
        feed_device_report(&mut im, &mut sessions, sa, 0x32, SUB, NOW + 41_000),
        ImStatus::InvalidSubscription
    );
    assert_eq!(im.take_event(), None, "幽霊レポートで REPORT を積まない");
    im.on_tick(NOW + 5_000 + LOST_AFTER_MS + 1);
    assert_eq!(
        im.take_event(),
        Some(ImEvent::SubscriptionLost {
            session: sb,
            subscription_id: SUB,
        }),
        "幽霊レポートが B の last_report を更新していないこと"
    );
    assert_eq!(im.subscription_count(), 0);

    // 明示破棄も (session, id) 単位。
    establish_sub_on_session(&mut im, &mut sessions, sa, 0x13, SUB, MAX_S, NOW);
    establish_sub_on_session(&mut im, &mut sessions, sb, 0x24, SUB, MAX_S, NOW);
    assert!(
        !im.remove_subscription(SessionId::from_raw(9), SUB),
        "別セッション"
    );
    assert!(im.remove_subscription(sa, SUB));
    assert_eq!(im.subscription_count(), 1);
    assert_eq!(
        feed_device_report(&mut im, &mut sessions, sb, 0x33, SUB, NOW + 1_000),
        ImStatus::Success,
        "残った B の購読は引き続き受理する"
    );
}
