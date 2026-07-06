//! std 上の実 UDP コミッショナサンプル(`controller` feature 必須)。
//!
//! `docs/design/controller.md` §検証計画。デバイス(responder)側 example `onoff-light` の
//! 鏡像として、[`ControllerStack`](simple_matter::controller::ControllerStack) と
//! [`Commissioner`](simple_matter::controller::Commissioner) を `std::net::UdpSocket` で駆動し、
//! **フルコミッショニング**(PASE → ArmFailSafe → CSR → AddTrustedRoot → AddNOC → CASE →
//! CommissioningComplete)を実機の UDP 越しに完走させる。完了後、確立した CASE(運用)
//! セッション上で OnOff **Toggle** を invoke し、on-off 属性を Read して表示する。
//!
//! sans-IO のコアはソケットに触れない。この example がバイト列と時刻の受け渡し
//! (受信 → `handle_rx`、期限 → `poll`、進行 → `Commissioner::drive`)を担う。
//!
//! # 使い方
//!
//! ```text
//! commissioner <passcode> [<ip> <port>]
//! ```
//!
//! - `ip` / `port` 省略時は **mDNS ブラウズ**(`_matterc._udp.local` の PTR クエリを
//!   224.0.0.251:5353 に送り、最初に発見した commissionable ノードを採用)。
//! - 明示時はそのアドレスへ直接 PASE を開始する(相互運用試験の主経路)。
//!
//! 実行例(別プロセスで `onoff-light` を起動しておく):
//! ```text
//! cargo run --release --example commissioner --features controller -- 20202021 127.0.0.1 5540
//! ```

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::controller::ca::Ca;
use simple_matter::controller::{
    AttestationPolicy, Commissioner, ControllerCreds, ControllerStack, Phase,
    CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::client::MdnsClient;
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_PORT};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::im::ImEvent;
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::stack::SendDirective;
use simple_matter::tlv::TlvValue;
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};
use simple_matter::transport::session::SessionId;

// --- コントローラ fabric / ノード識別子(この CA が新規に発行する)---
const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
/// コントローラ自身の運用 NodeId(AddNOC の CaseAdminSubject / CASE 自 identity)。
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
/// デバイスに割り当てる運用 NodeId。
const DEVICE_NODE_ID: u64 = 0x0000_0000_AABB_CCDD;
const VENDOR_ID: u16 = 0xFFF1;

// --- OnOff クラスタ(EP1 / 0x0006)---
const ONOFF_EP: EndpointId = EndpointId(1);
const ONOFF_CLUSTER: ClusterId = ClusterId(0x0006);
const ONOFF_ATTR: AttributeId = AttributeId(0x0000);
const ONOFF_CMD_TOGGLE: CommandId = CommandId(0x02);

/// 全体タイムアウト(コミッショニング + 運用往復)。
const OVERALL_TIMEOUT: Duration = Duration::from_secs(30);
/// mDNS ブラウズのタイムアウト。デバイスの再 announce 間隔(既定 30 秒)より長く取り、
/// クエリに応答できないデバイス(5353 共有で受信を取りこぼす場合)でも定期 announce を
/// 確実に拾えるようにする。
const MDNS_TIMEOUT: Duration = Duration::from_secs(35);
/// ブラウズ中にクエリを再送する間隔。
const MDNS_REQUERY_INTERVAL: Duration = Duration::from_secs(2);

type Backend = RustCrypto<DemoRng>;
type Ctrl<'s> = ControllerStack<'s, Backend, DemoRng, ControllerCreds<'s, Backend>, 4, 6, 3, 1280>;

/// デモ用の擬似乱数(SystemTime シードの LCG)。**暗号学的に安全ではない**。
///
/// 実機では OS/HW の CSPRNG を [`Rng`] に実装して差し替えること(onoff-light と同じ)。
struct DemoRng(u64);
impl DemoRng {
    fn from_time() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678)
            | 1;
        Self(seed)
    }
}
impl Rng for DemoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let passcode = match args.get(1).and_then(|s| s.parse::<u32>().ok()) {
        Some(p) => p,
        None => {
            eprintln!("usage: commissioner <passcode> [<ip> <port>]");
            return ExitCode::FAILURE;
        }
    };

    // 1) 対象デバイスのアドレスを決める(明示 or mDNS ブラウズ)。
    let peer_addr = match (args.get(2), args.get(3)) {
        (Some(ip), Some(port)) => match (ip.parse::<IpAddr>(), port.parse::<u16>()) {
            (Ok(ip), Ok(port)) => {
                println!("[target] using explicit address {ip}:{port}");
                SocketAddr::new(ip, port)
            }
            _ => {
                eprintln!("invalid <ip> or <port>: {ip} {port}");
                return ExitCode::FAILURE;
            }
        },
        _ => {
            println!("[discovery] browsing _matterc._udp.local via mDNS (no address given)...");
            match browse_commissionable() {
                Some(addr) => addr,
                None => {
                    eprintln!("[discovery] no commissionable device found within {MDNS_TIMEOUT:?}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };

    match run(passcode, peer_addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("[fatal] {msg}");
            ExitCode::FAILURE
        }
    }
}

/// コミッショニング → Toggle → Read を 1 本のソケットで駆動する。
fn run(passcode: u32, peer_addr: SocketAddr) -> Result<(), String> {
    // --- コントローラの資格情報(新規 CA)---
    let crypto = RustCrypto::new(DemoRng::from_time());
    let ca = Ca::<Backend>::generate(
        &crypto,
        &mut DemoRng::from_time(),
        FABRIC_ID,
        CONTROLLER_NODE_ID,
        VENDOR_ID,
        0,
    )
    .map_err(|e| format!("CA generate failed: {e:?}"))?;
    println!(
        "[ca] fabric_id={:#018x} controller_node_id={:#018x} (RCAC {} bytes)",
        ca.fabric_id(),
        ca.controller_node_id(),
        ca.rcac().len()
    );

    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, DemoRng::from_time(), ctrl_creds);
    let im_client = ImClient::new();
    let mut stack: Ctrl = ControllerStack::new(&crypto, sc_init, im_client);

    let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);

    // --- 駆動用ソケット(任意ポート)---
    // chip 系デバイスは IPv6 のみを広告することがあるため、デュアルスタック
    // (v6only=false)の IPv6 ソケットで開き、IPv4 宛は mapped アドレスで送る。
    let socket = open_dual_stack_udp().map_err(|e| format!("bind controller socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    println!(
        "[udp] controller socket bound on {}",
        socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );

    let peer = PeerAddr::Udp(peer_addr);
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    comm.commission(peer, passcode, DEVICE_NODE_ID, now_ms(&start))
        .map_err(|e| format!("commission() rejected: {e:?}"))?;
    println!("[commission] starting to {peer_addr} (device node_id={DEVICE_NODE_ID:#018x})");

    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut last_phase = Phase::Idle;

    let case_session: SessionId = loop {
        if start.elapsed() > OVERALL_TIMEOUT {
            return Err(format!("commissioning timed out in phase {last_phase:?}"));
        }

        // 進捗を進める(イベントを消費 → 次の start_* を発行)。
        let phase = pump_commissioner(&mut comm, &mut stack, &socket, now_ms(&start), &mut tx);
        if phase != last_phase {
            report_phase(phase);
            last_phase = phase;
        }
        match phase {
            Phase::Done { session } => break session,
            Phase::Failed { stage, reason } => {
                return Err(format!("commissioning failed at stage {stage}: {reason:?}"));
            }
            _ => {}
        }

        // 発行したトランザクションの応答を受け切り、standalone ACK も含めて完全に静穏化
        // させてから次フェーズへ進む。デバイスの IM responder は 1 トランザクション処理中に
        // 新規 exchange を受け付けない(前応答が未 ACK のうちに次を送ると落とされる)ため、
        // フェーズ間で ACK を流し切る必要がある(in-memory テストの `flush` 相当)。
        settle(&mut stack, &socket, &start, &mut rx, &mut tx)?;
    };

    println!(
        "[commission] COMPLETE. operational CASE session = {:#x}",
        case_session.as_raw()
    );

    // --- 運用: CASE 上で OnOff Toggle → 属性 Read ---
    let dir = stack
        .start_invoke(
            case_session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now_ms(&start),
            &mut tx,
        )
        .map_err(|e| format!("start OnOff Toggle: {e:?}"))?;
    send_dir(&socket, &tx, &dir);
    println!("[onoff] sent Toggle command over CASE");

    match drive_until_im_event(&mut stack, &socket, &start, &mut rx, &mut tx) {
        Some(ImEvent::InvokeDone { status }) if status.is_success() => {
            println!("[onoff] Toggle acknowledged (status = Success)");
        }
        Some(ev) => return Err(format!("Toggle failed: {ev:?}")),
        None => return Err("Toggle timed out".into()),
    }
    // Toggle 応答の ACK を流し切ってから Read(新規 exchange)を送る。
    settle(&mut stack, &socket, &start, &mut rx, &mut tx)?;

    let dir = stack
        .start_read(
            case_session,
            &[AttributePath::concrete(ONOFF_EP, ONOFF_CLUSTER, ONOFF_ATTR)],
            now_ms(&start),
            &mut tx,
        )
        .map_err(|e| format!("start OnOff Read: {e:?}"))?;
    send_dir(&socket, &tx, &dir);
    println!("[onoff] sent Read of OnOff attribute over CASE");

    match drive_until_im_event(&mut stack, &socket, &start, &mut rx, &mut tx) {
        Some(ImEvent::ReadDone) => {}
        Some(ev) => return Err(format!("Read failed: {ev:?}")),
        None => return Err("Read timed out".into()),
    }

    let value = read_onoff_value(&stack).ok_or("OnOff attribute not present in report")?;
    println!(
        "[onoff] OnOff attribute = {} ({})",
        value,
        if value { "ON" } else { "OFF" }
    );

    // --- CASE session resumption(secure-channel.md §7.4)---
    // 同一プロセス内で 2 本目の CASE を張る。ScInitiator が 1 本目のフル CASE で保存した
    // resumption レコードにより Sigma1 に resumptionID + initiatorResumeMIC が付き、
    // デバイスが Sigma2_Resume で応じれば証明書検証なしの 1 往復で確立する。
    settle(&mut stack, &socket, &start, &mut rx, &mut tx)?;
    let dir = stack
        .start_case(
            peer,
            CONTROLLER_FABRIC_INDEX,
            DEVICE_NODE_ID,
            now_ms(&start),
            &mut tx,
        )
        .map_err(|e| format!("start second CASE (resumption): {e:?}"))?;
    send_dir(&socket, &tx, &dir);
    println!("[resumption] second CASE started (Sigma1 carries resumptionID)");

    let resumed_session = match drive_until_sc_event(&mut stack, &socket, &start, &mut rx, &mut tx)
    {
        Some(ScEvent::CaseEstablished {
            session,
            resumed: true,
        }) => {
            println!(
                "[resumption] CASE session RESUMED via Sigma2_Resume (session = {:#x})",
                session.as_raw()
            );
            session
        }
        Some(ScEvent::CaseEstablished { resumed: false, .. }) => {
            return Err("second CASE fell back to full handshake (resumption not taken)".into());
        }
        Some(ev) => return Err(format!("second CASE failed: {ev:?}")),
        None => return Err("second CASE (resumption) timed out".into()),
    };
    settle(&mut stack, &socket, &start, &mut rx, &mut tx)?;

    // 再開したセッション上で実際に IM が通ることを Toggle で確認する。
    let dir = stack
        .start_invoke(
            resumed_session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now_ms(&start),
            &mut tx,
        )
        .map_err(|e| format!("start Toggle over resumed session: {e:?}"))?;
    send_dir(&socket, &tx, &dir);
    match drive_until_im_event(&mut stack, &socket, &start, &mut rx, &mut tx) {
        Some(ImEvent::InvokeDone { status }) if status.is_success() => {
            println!("[resumption] Toggle over RESUMED session acknowledged (status = Success)");
        }
        Some(ev) => return Err(format!("Toggle over resumed session failed: {ev:?}")),
        None => return Err("Toggle over resumed session timed out".into()),
    }
    settle(&mut stack, &socket, &start, &mut rx, &mut tx)?;

    println!("[done] commissioning + Toggle + Read + CASE resumption succeeded");
    Ok(())
}

/// SC(CASE/PASE)イベントを 1 件待つ(タイムアウトで `None`)。
fn drive_until_sc_event(
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Option<ScEvent> {
    loop {
        match socket.recv_from(rx) {
            Ok((n, src)) => {
                let now = start.elapsed().as_millis() as u64;
                if let Some(dir) = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, tx) {
                    send_dir(socket, tx, &dir);
                }
                if let Some(ev) = stack.sc_take_event() {
                    return Some(ev);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
        let now = start.elapsed().as_millis() as u64;
        while let Some(dir) = stack.poll(now, tx) {
            send_dir(socket, tx, &dir);
        }
        if let Some(ev) = stack.sc_take_event() {
            return Some(ev);
        }
        if start.elapsed() > OVERALL_TIMEOUT {
            return None;
        }
    }
}

/// [`Commissioner::drive`] を進捗が止まるまで回し、送信を排出して現フェーズを返す。
///
/// `drive` は「開始発行(send=Some, phase 不変)」と「イベント消費(send=None, phase 遷移)」を
/// 交互に行うので、`send=None && phase 不変`(= 次はイベント待ち)になったら返す。
fn pump_commissioner(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    now_ms: u64,
    tx: &mut [u8],
) -> Phase {
    loop {
        let prev = comm.phase();
        let out = comm.drive(stack, now_ms, tx);
        if let Some(dir) = out.send {
            send_dir(socket, tx, &dir);
        }
        if out.send.is_none() && out.phase == prev {
            return out.phase;
        }
        if matches!(out.phase, Phase::Done { .. } | Phase::Failed { .. }) {
            return out.phase;
        }
    }
}

/// IM トランザクション 1 本を回し切り、完了イベントを返す(タイムアウトで `None`)。
fn drive_until_im_event(
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Option<ImEvent> {
    loop {
        match socket.recv_from(rx) {
            Ok((n, src)) => {
                let now = start.elapsed().as_millis() as u64;
                if let Some(dir) = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, tx) {
                    send_dir(socket, tx, &dir);
                }
                if let Some(ev) = stack.im_take_event() {
                    return Some(ev);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
        let now = start.elapsed().as_millis() as u64;
        while let Some(dir) = stack.poll(now, tx) {
            send_dir(socket, tx, &dir);
        }
        if let Some(ev) = stack.im_take_event() {
            return Some(ev);
        }
        if start.elapsed() > OVERALL_TIMEOUT {
            return None;
        }
    }
}

/// 応答を受け切り、MRP 再送・standalone ACK を含めて完全に静穏化するまでネットワークを回す。
///
/// in-memory テストの `flush` に相当する。`next_deadline` が `None`(保留中の再送/ACK なし)に
/// なったら静穏とみなす。フェーズ間・トランザクション間で必ず呼び、前応答の ACK を確実に
/// デバイスへ届けてから次の新規 exchange を開始する。
fn settle(
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<(), String> {
    loop {
        match socket.recv_from(rx) {
            Ok((n, src)) => {
                let now = start.elapsed().as_millis() as u64;
                if let Some(dir) = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, tx) {
                    send_dir(socket, tx, &dir);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv: {e}")),
        }
        let now = start.elapsed().as_millis() as u64;
        while let Some(dir) = stack.poll(now, tx) {
            send_dir(socket, tx, &dir);
        }
        if stack
            .next_deadline(start.elapsed().as_millis() as u64)
            .is_none()
        {
            return Ok(());
        }
        if start.elapsed() > OVERALL_TIMEOUT {
            return Err("settle timed out (device unresponsive)".into());
        }
    }
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

/// デュアルスタック(v6only=false)の IPv6 UDP ソケットを任意ポートで開く。
fn open_dual_stack_udp() -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_only_v6(false)?;
    s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())?;
    Ok(s.into())
}

/// IPv4 宛アドレスを IPv4-mapped IPv6 に変換する(デュアルスタックソケット用)。
fn map_to_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        v6 => v6,
    }
}

/// [`SendDirective`] を宛先 UDP に送出する(宛先が解決できないものは黙って捨てる)。
fn send_dir(socket: &UdpSocket, tx: &[u8], dir: &SendDirective) {
    if let Some(addr) = dir.addr.socket_addr() {
        let _ = socket.send_to(&tx[..dir.len], map_to_v6(addr));
    }
}

/// フェーズ遷移を人間可読に表示する。
fn report_phase(phase: Phase) {
    let name = match phase {
        Phase::Idle => "Idle",
        Phase::Pase => "PASE handshake",
        Phase::ArmFailSafe => "ArmFailSafe",
        Phase::Attestation => "Attestation (skipped)",
        Phase::Csr => "CSRRequest",
        Phase::AddTrustedRoot => "AddTrustedRootCertificate",
        Phase::AddNoc => "AddNOC",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    println!("[phase] {name}");
}

// ==========================================================================
// mDNS ブラウズ(commissionable 発見)
// ==========================================================================

/// `_matterc._udp.local` を PTR ブラウズし、最初に発見した commissionable ノードの
/// (アドレス, ポート)を返す(discriminator 指定なし)。
fn browse_commissionable() -> Option<SocketAddr> {
    let trace = std::env::var_os("SM_MDNS_TRACE").is_some();
    let (socket, qu) = open_mdns_socket()?;

    let mut query = [0u8; 128];
    let qlen = MdnsClient::build_browse_commissionable(&mut query, qu).ok()?;
    let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
    if trace {
        eprintln!(
            "[mdns-trace] query sent ({qlen}B, qu={qu}) from {:?}",
            socket.local_addr()
        );
    }

    // クエリを周期的に再送する。デバイスが 5353 を他の mDNS レスポンダ(avahi 等)と
    // 共有していると受信クエリを取りこぼすことがあり、その場合は発見が「デバイスの定期
    // announce(既定 30 秒間隔)を拾う」ことに依存する。そこで window を announce 間隔より
    // 長く取り、クエリも再送して「デバイスが受信できる場合は即応答/できない場合は announce」
    // の両取りにする(docs/design/port-windows-commissioner.md §3)。
    let start = Instant::now();
    let mut last_query = Instant::now();
    let mut rx = [0u8; 1500];
    while start.elapsed() < MDNS_TIMEOUT {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
            last_query = Instant::now();
        }
        match socket.recv_from(&mut rx) {
            Ok((n, _src)) => {
                if trace {
                    eprintln!(
                        "[mdns-trace] rx {n}B from {_src} parse={}",
                        if MdnsClient::parse_commissionable(&rx[..n]).is_some() {
                            "commissionable"
                        } else {
                            "no-match"
                        }
                    );
                }
                if let Some(node) = MdnsClient::parse_commissionable(&rx[..n]) {
                    // discriminator 指定なし: アドレスを持つ最初の発見を採用する。
                    // 本 example のソケットは IPv4 なので IPv4 アドレスを優先する。
                    let picked = node
                        .addrs
                        .iter()
                        .find(|a| a.is_ipv4())
                        .or_else(|| node.addrs.iter().next())
                        .copied();
                    if let Some(ip) = picked {
                        let port = if node.port != 0 {
                            node.port
                        } else {
                            MATTER_PORT
                        };
                        let disc = node
                            .discriminator
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "?".into());
                        println!(
                            "[discovery] found commissionable node at {ip}:{port} (discriminator={disc})"
                        );
                        return Some(SocketAddr::new(ip, port));
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
    None
}

/// mDNS 用 UDP ソケットを開く。戻りの `bool` は「QU(unicast-response)モードか」。
///
/// - **Unix**: 224.0.0.251:5353 の共有 bind(SO_REUSEADDR/REUSEPORT で avahi と共存)。
///   マルチキャスト応答を受けるので QU 不要(`false`)。実績のある経路(変更なし)。
/// - **Windows**: 5353 は内蔵 mDNS(Dnscache)が掴んでおり、共有 bind してもマルチキャスト
///   応答の配送が環境依存で不安定なため、**エフェメラルポート + QU ビット**で応答を
///   自ポートへのユニキャストで受ける(RFC 6762 §5.4、
///   docs/design/port-windows-commissioner.md §3.2)。
fn open_mdns_socket() -> Option<(UdpSocket, bool)> {
    #[cfg(unix)]
    {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .ok()?;
        // SO_REUSEADDR のみ(SO_REUSEPORT はマルチキャストを listener 間でロードバランス
        // して取りこぼす。onoff-light の open_mdns_socket 参照)。
        socket.set_reuse_address(true).ok()?;
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
            .ok()?;
        let socket: UdpSocket = socket.into();
        socket
            .join_multicast_v4(&MDNS_IPV4, &Ipv4Addr::UNSPECIFIED)
            .ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok()?;
        Some((socket, false))
    }
    #[cfg(not(unix))]
    {
        // Windows は仮想アダプタ(WSL/Hyper-V/VPN)が多く、インターフェース未指定だと
        // マルチキャストの送信/join が LAN 以外の既定 IF に張り付くことがある
        // (クエリが LAN に出ない・announce も受からない)。デフォルトルートの
        // ローカル IPv4(connect トリック)で LAN 向き IF に明示的に固定する。
        let if_ip = default_route_local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .ok()?;
        // 送信 IF の固定(未指定だと既定 IF から送出され LAN に届かないことがある)。
        let _ = socket.set_multicast_if_v4(&if_ip);
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .ok()?;
        let socket: UdpSocket = socket.into();
        // マルチキャスト応答(QU を無視する responder 対策)も拾えるよう join はしておく。
        // join も同じ LAN 向き IF に固定する。
        let _ = socket.join_multicast_v4(&MDNS_IPV4, &if_ip);
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok()?;
        eprintln!("[discovery] mDNS QU mode: interface {if_ip}, ephemeral port");
        Some((socket, true))
    }
}

/// デフォルトルートのローカル IPv4 を推定する(外部宛 UDP の `local_addr` から。
/// 実際にはパケットを送らない)。マルチキャストの送信/join インターフェース固定用。
#[cfg(not(unix))]
fn default_route_local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
