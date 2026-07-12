//! ESP32-S3 スタンドアロンコミッショナ(UDP-only ハブ)— K2。
//!
//! `docs/design/esp32-controller.md` §7 K2。smctl(PC ホスト)の駆動ループを
//! embassy へ写像し、S3 単独で WiFi 上の commissionable デバイス(PC の
//! `onoff-light` example / C6 e5 系)をフルコミッショニングして OnOff を操作する:
//!
//! 1. **WiFi join**(SSID/パスは定数 or `SM_WIFI_SSID`/`SM_WIFI_PASS` の
//!    ビルド時環境変数。K2 は簡易投入で可 — doc §8.3)→ DHCPv4。
//! 2. **mDNS ブラウズ**(`_matterc._udp`、discriminator 絞り込み)。エフェメラル
//!    ポートから **QU(unicast-response)クエリ**を第一候補とし、応答が無ければ
//!    5353 bind + マルチキャスト join の **QM フォールバック**(doc §4.2 / R5)。
//! 3. `Commissioner` フル(PASE → ArmFailSafe → CSR → AddTrustedRoot → AddNOC →
//!    CASE → CommissioningComplete)→ **OnOff Toggle → on-off Read**。
//! 4. **CA は初回起動時に生成して `EspKvs`(キー `b"cast"`)へ永続化**
//!    (smctl `ca-state.bin` v1 互換 = コアの `Ca::encode_state`/`decode_state`)。
//!    コミッショニング済みノードの記録(node_id / 最終アドレス / CASE resumption
//!    素材)もポートローカルレコード(キー `b"node"`)で永続化する。
//! 5. リブート後は CA / ノード記録を復元し、運用 mDNS 解決(`_matter._tcp`)→
//!    CASE(resumption 素材を import 済みなので可能なら Sigma2_Resume)→ Toggle。
//! 6. 定常は「30 秒ごとに Toggle」の常駐ハブ最小デモ(K4 の複数ノード管理は別段)。
//!
//! # RAM 配分(doc §6.3 / R3)
//!
//! デバイス bin と同じ **heap 112KiB / .stack ≈69KiB** を踏襲する。controller は
//! 署名回数が多い(CA generate 2 発 + issue_noc + CASE Sigma)ため、`[alive]` ログの
//! `heap_max`(esp-alloc internal-heap-stats)で最高水位を常時監視する。
//!
//! 実行: `cd ports/esp32s3 && cargo build --release --bin s3-controller`
//! 対向(PC): `SM_STATE_DIR=<dir> cargo run --release --example onoff-light`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select, select3, Either, Either3};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::StackResources;
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use simple_matter::controller::ca::{Ca, CA_STATE_MAX_LEN};
use simple_matter::controller::{
    AttestationPolicy, CommissionError, Commissioner, ControllerCreds, ControllerStack, Phase,
    CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::client::MdnsClient;
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_IPV6, MDNS_PORT};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::im::ImEvent;
use simple_matter::kvs::Kvs;
use simple_matter::sc::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::stack::SendDirective;
use simple_matter::tlv::TlvValue;
use simple_matter::transport::net::{
    PeerAddr, UdpMulticast, UdpReceive, UdpSend, MAX_RX_PACKET_SIZE,
};
use simple_matter::transport::session::SessionId;

use esp32s3_firmware::kvs::EspKvs;
use esp32s3_firmware::net::{peer_v4, peer_v6, v4_as_mapped, EspUdp};
use esp32s3_firmware::wifi::{wifi_task, EspWifiDriver};
use esp32s3_firmware::EspRng;
use simple_matter::wifi::WifiDriver;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須)。
esp_bootloader_esp_idf::esp_app_desc!();

// --- WiFi 資格情報(K2 は簡易投入: 定数 or ビルド時環境変数。doc §8.3)---
const WIFI_SSID: &str = match option_env!("SM_WIFI_SSID") {
    Some(s) => s,
    None => "iotap",
};
const WIFI_PASS: &str = match option_env!("SM_WIFI_PASS") {
    Some(s) => s,
    None => "hogeFugapiyo",
};

// --- 対向デバイス(PC onoff-light example と同値)---
const PASSCODE: u32 = 20202021;
const DISCRIMINATOR: u16 = 3840;

// --- コントローラ fabric / ノード識別子(smctl / examples と同値)---
const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
const DEVICE_NODE_ID: u64 = 0x0000_0000_AABB_CCDD;
const VENDOR_ID: u16 = 0xFFF1;

// --- OnOff クラスタ(EP1 / 0x0006)---
const ONOFF_EP: EndpointId = EndpointId(1);
const ONOFF_CLUSTER: ClusterId = ClusterId(0x0006);
const ONOFF_ATTR: AttributeId = AttributeId(0x0000);
const ONOFF_CMD_TOGGLE: CommandId = CommandId(0x02);

// --- KVS キー(pack_key の 7B 制限内)---
/// CA 鍵素材(smctl ca-state.bin v1 と同一バイト列。doc §5.2)。
const CA_STATE_KEY: &[u8] = b"cast";
/// コミッショニング済みノード記録(ポートローカル v1 フォーマット)。
const NODE_KEY: &[u8] = b"node";

// --- タイミング ---
/// mDNS 再クエリ間隔(smctl と同値)。
const MDNS_REQUERY_MS: u64 = 2_000;
/// QU 応答が無いとき QM フォールバック(5353 join)へ切り替えるまでの猶予(R5)。
const QM_FALLBACK_MS: u64 = 6_000;
/// コミッショニング全体のタイムアウト。
const COMMISSION_TIMEOUT_MS: u64 = 60_000;
/// 定常デモ: Toggle の周期。
const TOGGLE_PERIOD_MS: u64 = 30_000;

type Backend = RustCrypto<EspRng>;
/// コントローラスタック(ハブ既定サイジング: コミッショニング 1 + 運用 CASE 数本。
/// doc §6.1。RESULT=1280 は単一属性 Read には十分 — wildcard は使わない)。
type Ctrl<'s> = ControllerStack<'s, Backend, EspRng, ControllerCreds<'s, Backend>, 4, 6, 3, 1280>;

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

/// 単調時刻(ms)。スタックの `now_ms` 注入に使う(embassy-time の Instant 起点)。
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis()
}

/// MAC(48bit)から modified EUI-64 のリンクローカル IPv6(fe80::/64)を導出する
/// (s3-light と同じ。smoltcp に静的設定する)。
fn link_local_from_mac(mac: &[u8; 6]) -> core::net::Ipv6Addr {
    let mut eui = [0u8; 8];
    eui[0] = mac[0] ^ 0x02;
    eui[1] = mac[1];
    eui[2] = mac[2];
    eui[3] = 0xFF;
    eui[4] = 0xFE;
    eui[5] = mac[3];
    eui[6] = mac[4];
    eui[7] = mac[5];
    core::net::Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([eui[0], eui[1]]),
        u16::from_be_bytes([eui[2], eui[3]]),
        u16::from_be_bytes([eui[4], eui[5]]),
        u16::from_be_bytes([eui[6], eui[7]]),
    )
}

// ==========================================================================
// ノード記録(ポートローカル v1。node_id + 最終アドレス + CASE resumption 素材)
// ==========================================================================

/// ノード記録レコードのフォーマットバージョン。
const NODE_RECORD_VERSION: u8 = 1;
/// 固定長レイアウト:
/// [version(1)][node_id(8 LE)][ipv4(4)][port(2 LE)][has_resumption(1)]
/// [resumption_id(16)][shared_secret(32)] = 64 B。
const NODE_RECORD_LEN: usize = 1 + 8 + 4 + 2 + 1 + CASE_RESUMPTION_ID_LEN + SHARED_SECRET_LEN;

/// コミッショニング済みノードの記録(リブート後の再接続用)。
struct NodeRecord {
    node_id: u64,
    /// 最後に確認した運用アドレス(mDNS 解決が空振りしたときのフォールバック)。
    addr: SocketAddr,
    /// CASE resumption 素材(`ScInitiator::resumption_export`)。
    resumption: Option<([u8; CASE_RESUMPTION_ID_LEN], [u8; SHARED_SECRET_LEN])>,
}

fn encode_node_record(rec: &NodeRecord) -> Option<[u8; NODE_RECORD_LEN]> {
    let SocketAddr::V4(v4) = rec.addr else {
        // v6 運用アドレスは保存しない(次回は mDNS 解決に任せる)。呼び出し側で
        // None を「保存スキップ」として扱う。
        return None;
    };
    let mut out = [0u8; NODE_RECORD_LEN];
    out[0] = NODE_RECORD_VERSION;
    out[1..9].copy_from_slice(&rec.node_id.to_le_bytes());
    out[9..13].copy_from_slice(&v4.ip().octets());
    out[13..15].copy_from_slice(&v4.port().to_le_bytes());
    if let Some((rid, ss)) = &rec.resumption {
        out[15] = 1;
        out[16..16 + CASE_RESUMPTION_ID_LEN].copy_from_slice(rid);
        out[16 + CASE_RESUMPTION_ID_LEN..].copy_from_slice(ss);
    }
    Some(out)
}

fn decode_node_record(rec: &[u8]) -> Option<NodeRecord> {
    if rec.len() != NODE_RECORD_LEN || rec[0] != NODE_RECORD_VERSION {
        return None;
    }
    let node_id = u64::from_le_bytes(rec[1..9].try_into().ok()?);
    let ip = Ipv4Addr::new(rec[9], rec[10], rec[11], rec[12]);
    let port = u16::from_le_bytes(rec[13..15].try_into().ok()?);
    let resumption = if rec[15] == 1 {
        let rid: [u8; CASE_RESUMPTION_ID_LEN] =
            rec[16..16 + CASE_RESUMPTION_ID_LEN].try_into().ok()?;
        let ss: [u8; SHARED_SECRET_LEN] = rec[16 + CASE_RESUMPTION_ID_LEN..].try_into().ok()?;
        Some((rid, ss))
    } else {
        None
    };
    Some(NodeRecord {
        node_id,
        addr: SocketAddr::new(IpAddr::V4(ip), port),
        resumption,
    })
}

/// ノード記録(最新アドレス + resumption 素材)を KVS へ保存する。
fn save_node_record(kvs: &mut EspKvs, stack: &Ctrl<'_>, addr: SocketAddr) {
    let rec = NodeRecord {
        node_id: DEVICE_NODE_ID,
        addr,
        resumption: stack.resumption_export(CONTROLLER_FABRIC_INDEX, DEVICE_NODE_ID),
    };
    let Some(bytes) = encode_node_record(&rec) else {
        println!("[kvs] node record skipped (non-IPv4 operational address)");
        return;
    };
    match kvs.set(NODE_KEY, &bytes) {
        Ok(()) => println!(
            "[kvs] node record saved (node_id={:#x} addr={} resumption={})",
            rec.node_id,
            rec.addr,
            rec.resumption.is_some()
        ),
        Err(e) => println!("[kvs] node record save error: {:?}", e),
    }
}

/// CA 鍵素材を KVS へ保存する(v1 = smctl 互換。発行で next_serial が進むたびに呼ぶ)。
fn save_ca_state(kvs: &mut EspKvs, ca: &Ca<Backend>) {
    let mut rec = [0u8; CA_STATE_MAX_LEN];
    match ca.encode_state(&mut rec) {
        Ok(len) => match kvs.set(CA_STATE_KEY, &rec[..len]) {
            Ok(()) => println!(
                "[kvs] ca-state saved ({}B, next_serial={})",
                len,
                ca.next_serial()
            ),
            Err(e) => println!("[kvs] ca-state save error: {:?}", e),
        },
        Err(e) => println!("[kvs] ca-state encode error: {:?}", e),
    }
}

// ==========================================================================
// mDNS ディスカバリ(QU 第一候補 + QM フォールバック。doc §4.2)
// ==========================================================================

/// ブラウズ(commissionable)/ 運用解決(operational)のクエリ種別。
enum Query {
    Browse { discriminator: u16 },
    Operational { compressed: [u8; 8], node_id: u64 },
}

impl Query {
    fn build(&self, out: &mut [u8], qu: bool) -> simple_matter::error::Result<usize> {
        match self {
            Query::Browse { discriminator } => {
                MdnsClient::build_browse_discriminator(out, *discriminator, qu)
            }
            Query::Operational {
                compressed,
                node_id,
            } => MdnsClient::build_resolve_operational(out, compressed, *node_id, qu),
        }
    }

    /// 受信パケットを解析し、接続先(アドレス + ポート)を返す。IPv4 を優先し、
    /// 無ければ最初のアドレス(fe80 は単一インターフェースのため scope 不要)。
    fn parse(&self, pkt: &[u8]) -> Option<SocketAddr> {
        let (addrs, port) = match self {
            Query::Browse { discriminator } => {
                let node = MdnsClient::parse_commissionable(pkt)?;
                if node.discriminator != Some(*discriminator) {
                    return None;
                }
                (node.addrs, node.port)
            }
            Query::Operational {
                compressed,
                node_id,
            } => {
                let node = MdnsClient::parse_operational(pkt, compressed, *node_id)?;
                (node.addrs, node.port)
            }
        };
        let ip = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.iter().next())
            .copied()?;
        let port = if port != 0 { port } else { MATTER_PORT };
        Some(SocketAddr::new(ip, port))
    }
}

/// mDNS ディスカバリ 1 回(タイムアウトまで)。
///
/// エフェメラルポートの `qu_udp` から QU クエリを 2 秒間隔で送り、ユニキャスト応答を
/// 待つ。[`QM_FALLBACK_MS`] 経過しても応答が無い場合は `qm_udp`(5353 bind 済み)で
/// IGMP/MLD join し、QM クエリ + マルチキャスト応答/announce の受動受信を併用する。
/// 発見後は join を解除して(QM を有効化した場合のみ)無関係な mDNS 解析コストを畳む。
async fn discover(
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    query: &Query,
    timeout_ms: u64,
    start: Instant,
) -> Option<SocketAddr> {
    let t0 = now_ms(start);
    let mut joined = false;
    let mut next_query = t0;
    let mut rx_qu = [0u8; 1500];
    let mut rx_qm = [0u8; 1500];
    let mut q = [0u8; 128];

    let found = loop {
        let now = now_ms(start);
        if now - t0 >= timeout_ms {
            break None;
        }
        if !joined && now - t0 >= QM_FALLBACK_MS {
            joined = true;
            if let Err(e) = qm_udp.join(v4_as_mapped(MDNS_IPV4)).await {
                println!("[dis] v4 multicast join error: {:?}", e);
            }
            if let Err(e) = qm_udp.join(MDNS_IPV6).await {
                println!("[dis] v6 multicast join error: {:?}", e);
            }
            println!("[dis] no QU answer yet; QM fallback enabled (5353 + multicast join)");
        }
        if now >= next_query {
            next_query = now + MDNS_REQUERY_MS;
            // QU: エフェメラルポートからユニキャスト応答を要求する。
            if let Ok(len) = query.build(&mut q, true) {
                let _ = qu_udp
                    .send_to(&q[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
                    .await;
                let _ = qu_udp
                    .send_to(&q[..len], peer_v6(MDNS_IPV6, MDNS_PORT))
                    .await;
            }
            // QM(フォールバック時): 5353 発でマルチキャスト応答を要求する。
            if joined {
                if let Ok(len) = query.build(&mut q, false) {
                    let _ = qm_udp
                        .send_to(&q[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
                        .await;
                    let _ = qm_udp
                        .send_to(&q[..len], peer_v6(MDNS_IPV6, MDNS_PORT))
                        .await;
                }
            }
        }
        match select3(
            qu_udp.recv_from(&mut rx_qu),
            qm_udp.recv_from(&mut rx_qm),
            Timer::after_millis(100),
        )
        .await
        {
            Either3::First(Ok((n, _src))) => {
                if let Some(addr) = query.parse(&rx_qu[..n]) {
                    break Some(addr);
                }
            }
            Either3::Second(Ok((n, _src))) => {
                if let Some(addr) = query.parse(&rx_qm[..n]) {
                    break Some(addr);
                }
            }
            _ => {}
        }
    };

    if joined {
        let _ = qm_udp.leave(v4_as_mapped(MDNS_IPV4)).await;
        let _ = qm_udp.leave(MDNS_IPV6).await;
    }
    found
}

// ==========================================================================
// sans-IO 駆動ヘルパ(smctl runner/udp.rs の embassy 版。doc §4.3)
// ==========================================================================

/// [`SendDirective`] を UDP へ送出する(宛先が解決できないものは黙って捨てる)。
async fn send_dir(udp: &mut EspUdp<'_>, tx: &[u8], d: &SendDirective) {
    if let Err(e) = udp.send_to(&tx[..d.len], d.addr).await {
        println!("[udp] send error: {:?}", e);
    }
}

/// [`Commissioner::drive`] を進捗が止まるまで回し、送信を排出して現フェーズを返す
/// (smctl `pump_commissioner` と同形)。
async fn pump_commissioner(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    tx: &mut [u8],
) -> Phase {
    loop {
        let prev = comm.phase();
        let out = comm.drive(stack, now_ms(start), tx);
        if let Some(d) = out.send {
            send_dir(udp, tx, &d).await;
        }
        if out.send.is_none() && out.phase == prev {
            return out.phase;
        }
        if matches!(out.phase, Phase::Done { .. } | Phase::Failed { .. }) {
            return out.phase;
        }
    }
}

/// 応答を受け切り、MRP 再送・standalone ACK を含めて静穏化するまでネットワークを回す
/// (`next_deadline` が `None` になるまで。フェーズ間・トランザクション間で必ず呼ぶ)。
async fn settle(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Result<(), ()> {
    let until = now_ms(start) + timeout_ms;
    loop {
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
        let Some(deadline) = stack.next_deadline(now) else {
            return Ok(());
        };
        if now > until {
            return Err(());
        }
        let sleep = if deadline > now {
            (deadline - now).min(50)
        } else {
            // 期限到来済み: poll を回すために最小待ち。
            1
        };
        match select(udp.recv_from(rx), Timer::after_millis(sleep)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
    }
}

/// IM イベントを 1 件待つ(受信 + poll を回し続ける。タイムアウトで `None`)。
async fn wait_im_event(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Option<ImEvent> {
    let until = now_ms(start) + timeout_ms;
    loop {
        if let Some(ev) = stack.im_take_event() {
            return Some(ev);
        }
        if now_ms(start) > until {
            return None;
        }
        match select(udp.recv_from(rx), Timer::after_millis(50)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
    }
}

/// SC(CASE)イベントを 1 件待つ(タイムアウトで `None`)。
async fn wait_sc_event(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Option<ScEvent> {
    let until = now_ms(start) + timeout_ms;
    loop {
        if let Some(ev) = stack.sc_take_event() {
            return Some(ev);
        }
        if now_ms(start) > until {
            return None;
        }
        match select(udp.recv_from(rx), Timer::after_millis(50)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
    }
}

/// フェーズ遷移を人間可読に表示する(PC example と同形式)。
fn report_phase(phase: Phase) {
    let name = match phase {
        Phase::Idle => "Idle",
        Phase::Pase => "PASE handshake",
        Phase::ArmFailSafe => "ArmFailSafe",
        Phase::Attestation => "Attestation (skipped)",
        Phase::Csr => "CSRRequest",
        Phase::AddTrustedRoot => "AddTrustedRootCertificate",
        Phase::AddNoc => "AddNOC",
        Phase::AddWifiNetwork => "AddOrUpdateWiFiNetwork",
        Phase::ConnectNetwork => "ConnectNetwork",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    println!("[phase] {}", name);
}

/// フルコミッショニングを完走させて CASE セッションを返す。
async fn run_commissioning(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<SessionId, CommissionError> {
    let until = now_ms(start) + COMMISSION_TIMEOUT_MS;
    let mut last_phase = Phase::Idle;
    loop {
        if now_ms(start) > until {
            println!("[commission] timed out in phase {:?}", last_phase);
            return Err(CommissionError::Protocol);
        }
        let phase = pump_commissioner(comm, stack, udp, start, tx).await;
        if phase != last_phase {
            report_phase(phase);
            last_phase = phase;
        }
        match phase {
            Phase::Done { session } => return Ok(session),
            Phase::Failed { stage, reason } => {
                println!("[commission] FAILED at stage {}: {:?}", stage, reason);
                return Err(reason);
            }
            _ => {}
        }
        // 発行済みトランザクションの応答 + ACK を流し切ってから次フェーズへ
        // (デバイス側 IM responder は同時 1 トランザクションのため)。
        if settle(stack, udp, start, rx, tx, 20_000).await.is_err() {
            println!("[commission] settle timed out (device unresponsive)");
            return Err(CommissionError::Protocol);
        }
    }
}

/// 運用セッション上で OnOff Toggle → on-off Read を 1 巡実行し、読めた値を返す。
async fn toggle_and_read(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    session: SessionId,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<Option<bool>, ()> {
    let dir = stack
        .start_invoke(
            session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now_ms(start),
            tx,
        )
        .map_err(|e| println!("[onoff] start_invoke error: {:?}", e))?;
    send_dir(udp, tx, &dir).await;
    match wait_im_event(stack, udp, start, rx, tx, 10_000).await {
        Some(ImEvent::InvokeDone { status }) if status.is_success() => {}
        other => {
            println!("[onoff] Toggle failed: {:?}", other);
            return Err(());
        }
    }
    settle(stack, udp, start, rx, tx, 10_000).await?;

    let dir = stack
        .start_read(
            session,
            &[AttributePath::concrete(ONOFF_EP, ONOFF_CLUSTER, ONOFF_ATTR)],
            now_ms(start),
            tx,
        )
        .map_err(|e| println!("[onoff] start_read error: {:?}", e))?;
    send_dir(udp, tx, &dir).await;
    match wait_im_event(stack, udp, start, rx, tx, 10_000).await {
        Some(ImEvent::ReadDone) => {}
        other => {
            println!("[onoff] Read failed: {:?}", other);
            return Err(());
        }
    }
    settle(stack, udp, start, rx, tx, 10_000).await?;
    Ok(read_onoff_value(stack))
}

/// 直近 Read 応答から OnOff(EP1/0x0006/0x0000)の bool 値を取り出す。
fn read_onoff_value(stack: &Ctrl<'_>) -> Option<bool> {
    for report in stack.read_reports() {
        if let Ok(AttributeReportRef::Data(d)) = report {
            let is_onoff = d
                .path
                .to_concrete()
                .map(|c| c.attribute.0 == ONOFF_ATTR.0)
                .unwrap_or(false);
            if !is_onoff {
                continue;
            }
            let mut v = d.value();
            if let Ok(Some(e)) = v.read_next() {
                if let TlvValue::Boolean(b) = e.value {
                    return Some(b);
                }
            }
        }
    }
    None
}

/// CASE を張り、確立したセッションと resumed フラグを返す。
async fn establish_case(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    peer: SocketAddr,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Option<(SessionId, bool)> {
    let dir = match stack.start_case(
        PeerAddr::Udp(peer),
        CONTROLLER_FABRIC_INDEX,
        DEVICE_NODE_ID,
        now_ms(start),
        tx,
    ) {
        Ok(d) => d,
        Err(e) => {
            println!("[case] start_case error: {:?}", e);
            return None;
        }
    };
    send_dir(udp, tx, &dir).await;
    match wait_sc_event(stack, udp, start, rx, tx, 15_000).await {
        Some(ScEvent::CaseEstablished { session, resumed }) => {
            let _ = settle(stack, udp, start, rx, tx, 10_000).await;
            Some((session, resumed))
        }
        other => {
            println!("[case] failed: {:?}", other);
            None
        }
    }
}

// ==========================================================================
// 統合層(コントローラ本体のフロー)
// ==========================================================================

/// DHCP up を待って IPv4 を返す。
async fn wait_dhcp(net_stack: embassy_net::Stack<'_>) -> Ipv4Addr {
    loop {
        if let Some(cfg) = net_stack.config_v4() {
            println!("[net] DHCP up: ip={} gw={:?}", cfg.address, cfg.gateway);
            return cfg.address.address();
        }
        Timer::after_millis(100).await;
    }
}

/// コントローラのメインフロー(常駐)。
#[allow(clippy::too_many_arguments)]
async fn controller_task(
    stack: &mut Ctrl<'_>,
    comm: &mut Commissioner<'_, Backend>,
    ca: &Ca<Backend>,
    kvs: &mut EspKvs,
    net_stack: embassy_net::Stack<'_>,
    matter_udp: &mut EspUdp<'_>,
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    node_rec: Option<NodeRecord>,
) -> ! {
    let start = Instant::now();
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];

    // --- WiFi join(簡易投入: 定数資格情報)→ DHCP ---
    println!("[wifi] joining \"{}\"...", WIFI_SSID);
    EspWifiDriver.connect(WIFI_SSID.as_bytes(), WIFI_PASS.as_bytes());
    let _ip = wait_dhcp(net_stack).await;

    let mut session: Option<SessionId> = None;
    let mut peer: Option<SocketAddr> = None;

    // --- リブート後: ノード記録があれば運用解決 → CASE(resumption 素材 import 済み)---
    if let Some(rec) = &node_rec {
        println!(
            "[boot] node record found (node_id={:#x} last_addr={} resumption={}); reconnecting",
            rec.node_id,
            rec.addr,
            rec.resumption.is_some()
        );
        let compressed = ca.compressed_fabric_id_bytes();
        println!(
            "[dis] resolving _matter._tcp for {:016X}-{:016X}...",
            u64::from_be_bytes(compressed),
            rec.node_id
        );
        let query = Query::Operational {
            compressed,
            node_id: rec.node_id,
        };
        let addr = match discover(qu_udp, qm_udp, &query, 30_000, start).await {
            Some(a) => {
                println!("[dis] operational node resolved at {}", a);
                a
            }
            None => {
                println!(
                    "[dis] operational resolve timed out; falling back to last addr {}",
                    rec.addr
                );
                rec.addr
            }
        };
        if let Some((s, resumed)) =
            establish_case(stack, matter_udp, start, addr, &mut rx, &mut tx).await
        {
            println!(
                "[case] operational session re-established (session={:#x}, resumed={})",
                s.as_raw(),
                resumed
            );
            session = Some(s);
            peer = Some(addr);
            // resumption id は CASE のたびに回る。最新素材で記録を更新する。
            save_node_record(kvs, stack, addr);
        } else {
            println!("[case] reconnect failed; falling back to fresh commissioning");
        }
    }

    // --- 初回(またはリブート再接続失敗): ブラウズ → フルコミッショニング ---
    if session.is_none() {
        let addr = loop {
            println!(
                "[dis] browsing _matterc._udp (discriminator={}) via QU...",
                DISCRIMINATOR
            );
            let query = Query::Browse {
                discriminator: DISCRIMINATOR,
            };
            if let Some(a) = discover(qu_udp, qm_udp, &query, 30_000, start).await {
                println!("[dis] found commissionable node at {}", a);
                break a;
            }
            println!("[dis] no commissionable device found; retrying...");
        };

        comm.commission(PeerAddr::Udp(addr), PASSCODE, DEVICE_NODE_ID, now_ms(start))
            .expect("commission() rejected");
        println!(
            "[commission] starting to {} (device node_id={:#x})",
            addr, DEVICE_NODE_ID
        );
        match run_commissioning(comm, stack, matter_udp, start, &mut rx, &mut tx).await {
            Ok(s) => {
                println!(
                    "[commission] COMPLETE. operational CASE session = {:#x}",
                    s.as_raw()
                );
                session = Some(s);
                peer = Some(addr);
                // issue_noc で next_serial が進んだ CA 状態と、ノード記録
                // (アドレス + resumption 素材)を永続化する(doc §5.2)。
                save_ca_state(kvs, ca);
                save_node_record(kvs, stack, addr);
            }
            Err(_) => {
                println!("[commission] giving up; rebooting in 10s");
                Timer::after_millis(10_000).await;
                esp_hal::system::software_reset();
            }
        }
    }

    let mut session = session.expect("session established");
    let peer = peer.expect("peer known");

    // --- 定常デモ: 30 秒ごとに Toggle → Read(常駐ハブの最小形)---
    let mut consecutive_failures = 0u32;
    loop {
        match toggle_and_read(stack, matter_udp, start, session, &mut rx, &mut tx).await {
            Ok(v) => {
                consecutive_failures = 0;
                let heap = esp_alloc::HEAP.stats();
                println!(
                    "[onoff] Toggle OK (light={}) t={}s heap_max={}",
                    match v {
                        Some(true) => "ON",
                        Some(false) => "OFF",
                        None => "?",
                    },
                    now_ms(start) / 1000,
                    heap.max_usage
                );
            }
            Err(()) => {
                consecutive_failures += 1;
                println!(
                    "[onoff] Toggle failed ({} consecutive); re-establishing CASE",
                    consecutive_failures
                );
                if let Some((s, resumed)) =
                    establish_case(stack, matter_udp, start, peer, &mut rx, &mut tx).await
                {
                    println!(
                        "[case] session re-established (session={:#x}, resumed={})",
                        s.as_raw(),
                        resumed
                    );
                    session = s;
                    save_node_record(kvs, stack, peer);
                    consecutive_failures = 0;
                } else if consecutive_failures >= 5 {
                    println!("[onoff] device unreachable; rebooting");
                    esp_hal::system::software_reset();
                }
            }
        }

        // 次の Toggle まで受信 + poll を回しながら待つ。
        let until = now_ms(start) + TOGGLE_PERIOD_MS;
        loop {
            let now = now_ms(start);
            if now >= until {
                break;
            }
            while let Some(d) = stack.poll(now, &mut tx) {
                send_dir(matter_udp, &tx, &d).await;
            }
            let sleep = (until - now).min(50);
            if let Either::First(Ok((n, src))) =
                select(matter_udp.recv_from(&mut rx), Timer::after_millis(sleep)).await
            {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, &mut tx) {
                    send_dir(matter_udp, &tx, &d).await;
                }
            }
        }
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    // クロックを最大に設定して初期化(esp-radio は 80MHz 以上を要求)。
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-S3 controller (K2: s3-controller)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 + embassy-net 0.9");
    println!(" scope    : standalone commissioner (UDP-only hub)");
    println!("======================================================");

    // デバイス bin と同じ heap 112KiB / .stack ≈69KiB 配分(doc §6.3 / R3)。
    esp_alloc::heap_allocator!(size: 112 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG。TrngSource は main の生存期間中保持し続ける(drop すると擬似乱数に戻る)。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = esp_rng();

    // --- Wi-Fi station(esp-radio。ハブは BLE 不使用 = coex 負荷なし)---
    let (wifi_controller, wifi_interfaces) = esp_radio::wifi::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .expect("Wi-Fi controller init");
    let sta = wifi_interfaces.station;
    let mac = sta.mac_address();
    println!(
        "[wifi] STA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let mut seed_bytes = [0u8; 8];
    rng.fill_bytes(&mut seed_bytes).expect("TRNG fill");
    let seed = u64::from_le_bytes(seed_bytes);
    // ソケット枠: Matter UDP + mDNS QU + mDNS QM + DHCPv4 + 予備。
    let mut net_resources: StackResources<6> = StackResources::new();
    let ll_v6 = link_local_from_mac(&mac);
    println!("[net] IPv6 link-local: {}", ll_v6);
    let mut net_config = embassy_net::Config::dhcpv4(Default::default());
    net_config.ipv6 = embassy_net::ConfigV6::Static(embassy_net::StaticConfigV6 {
        address: embassy_net::Ipv6Cidr::new(ll_v6, 64),
        gateway: None,
        dns_servers: Default::default(),
    });
    let (net_stack, mut net_runner) = embassy_net::new(sta, net_config, &mut net_resources, seed);

    // Matter UDP(コミッショニング + 運用。コントローラはエフェメラルポート)。
    let mut m_rx_meta = [PacketMetadata::EMPTY; 8];
    let mut m_tx_meta = [PacketMetadata::EMPTY; 8];
    let mut m_rx_buf = [0u8; 4096];
    let mut m_tx_buf = [0u8; 4096];
    let mut matter_sock = UdpSocket::new(
        net_stack,
        &mut m_rx_meta,
        &mut m_rx_buf,
        &mut m_tx_meta,
        &mut m_tx_buf,
    );
    matter_sock.bind(0).expect("bind matter socket");
    let mut matter_udp = EspUdp::new(matter_sock, net_stack);

    // mDNS QU クエリソケット(エフェメラルポート。ユニキャスト応答を受ける)。
    let mut u_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut u_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut u_rx_buf = [0u8; 2048];
    let mut u_tx_buf = [0u8; 512];
    let mut qu_sock = UdpSocket::new(
        net_stack,
        &mut u_rx_meta,
        &mut u_rx_buf,
        &mut u_tx_meta,
        &mut u_tx_buf,
    );
    qu_sock.bind(0).expect("bind mDNS QU socket");
    let mut qu_udp = EspUdp::new(qu_sock, net_stack);

    // mDNS QM フォールバックソケット(5353。join は discover 内で必要時のみ)。
    let mut g_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut g_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut g_rx_buf = [0u8; 2048];
    let mut g_tx_buf = [0u8; 512];
    let mut qm_sock = UdpSocket::new(
        net_stack,
        &mut g_rx_meta,
        &mut g_rx_buf,
        &mut g_tx_meta,
        &mut g_tx_buf,
    );
    qm_sock.bind(MDNS_PORT).expect("bind 5353");
    let mut qm_udp = EspUdp::new(qm_sock, net_stack);

    // --- CA: flash KVS(キー b"cast")から復元、無ければ生成して保存 ---
    let crypto = RustCrypto::new(esp_rng());
    let mut kvs = EspKvs::new(peripherals.FLASH);
    let mut ca_rec = [0u8; CA_STATE_MAX_LEN];
    let ca: Ca<Backend> = match kvs.get(CA_STATE_KEY, &mut ca_rec) {
        Ok(Some(len)) => match Ca::decode_state(&crypto, &ca_rec[..len], 0) {
            Ok(ca) => {
                println!(
                    "[ca] restored from flash (fabric_id={:#018x} next_serial={})",
                    ca.fabric_id(),
                    ca.next_serial()
                );
                ca
            }
            Err(e) => {
                println!("[ca] stored record invalid ({:?}); generating new CA", e);
                Ca::generate(
                    &crypto,
                    &mut rng,
                    FABRIC_ID,
                    CONTROLLER_NODE_ID,
                    VENDOR_ID,
                    0,
                )
                .expect("CA generate")
            }
        },
        _ => {
            println!("[ca] no stored state; generating new CA (P-256 x2 + self-issue)...");
            Ca::generate(
                &crypto,
                &mut rng,
                FABRIC_ID,
                CONTROLLER_NODE_ID,
                VENDOR_ID,
                0,
            )
            .expect("CA generate")
        }
    };
    // 生成直後(または復元不能で再生成)は必ず保存しておく(クラッシュ耐性)。
    save_ca_state(&mut kvs, &ca);
    println!(
        "[ca] fabric_id={:#018x} controller_node_id={:#018x} compressed={:016X}",
        ca.fabric_id(),
        ca.controller_node_id(),
        u64::from_be_bytes(ca.compressed_fabric_id_bytes())
    );

    // --- ノード記録の復元(リブート後の再接続用)---
    let mut node_buf = [0u8; NODE_RECORD_LEN];
    let node_rec = match kvs.get(NODE_KEY, &mut node_buf) {
        Ok(Some(len)) => decode_node_record(&node_buf[..len]),
        _ => None,
    };

    // --- ControllerStack + Commissioner(now_epoch_s=0 運用。R7 は K1 で実証済み)---
    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, esp_rng(), ctrl_creds);
    let im_client = ImClient::new();
    let mut stack: Ctrl = ControllerStack::new(&crypto, sc_init, im_client);
    if let Some(rec) = &node_rec {
        if let Some((rid, ss)) = &rec.resumption {
            stack.resumption_import(CONTROLLER_FABRIC_INDEX, rec.node_id, rid, ss);
            println!("[case] resumption material imported from flash");
        }
    }
    let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
    println!(
        "[stack] ControllerStack ready ({} bytes, on main stack)",
        core::mem::size_of::<Ctrl<'static>>()
    );

    // wifi_task / embassy-net runner / コントローラ本体を単一 executor 上で並走させる。
    join3(
        wifi_task(wifi_controller),
        net_runner.run(),
        controller_task(
            &mut stack,
            &mut comm,
            &ca,
            &mut kvs,
            net_stack,
            &mut matter_udp,
            &mut qu_udp,
            &mut qm_udp,
            node_rec,
        ),
    )
    .await;
    unreachable!();
}
