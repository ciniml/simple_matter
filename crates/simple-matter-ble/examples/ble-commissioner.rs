//! BLE(BTP)版コミッショナ(`commissioner` feature、`docs/design/ble-btp.md` §6.2 / §8 / §9.2)。
//!
//! 既存の UDP 版 `simple-matter/examples/commissioner.rs` の BLE 版。btleplug バックエンド
//! [`BtleplugCentral`] で `scan(discriminator 照合)→ connect → C2 subscribe` した後、
//! [`Btp<6>`](Central)で handshake を能動開始し、pump ループで
//! [`ControllerStack`] + [`Commissioner`] を駆動して
//! PASE → ArmFailSafe → CSR → AddTrustedRoot → AddNOC → CASE → CommissioningComplete を
//! 実 BLE 上で完走させる。完了後、CASE 上で OnOff **Toggle** を invoke し、切断する。
//!
//! `Commissioner::drive` は無改造(トランスポート差は送信ファネルの MRP 格下げが吸収する、§3.3)。
//!
//! 実行(先に別ホスト/アダプタで `ble-onoff-light` を起動):
//! ```text
//! cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840
//! ```
//! 第 2 引数(discriminator)省略時は任意の commissionable デバイスに接続する。
//!
//! [`Btp<6>`]: simple_matter::btp::Btp
//! [`ControllerStack`]: simple_matter::controller::ControllerStack
//! [`Commissioner`]: simple_matter::controller::Commissioner

use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::btp::gatt::{GattCentral, ScanFilter};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::controller::ca::Ca;
use simple_matter::controller::{
    AttestationPolicy, Commissioner, ControllerCreds, ControllerStack, Phase,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::dm::meta::{ClusterId, CommandId, EndpointId};
use simple_matter::error::Result as MResult;
use simple_matter::im::wire::CommandPath;
use simple_matter::im::ImEvent;
use simple_matter::sc::initiator::ScInitiator;
use simple_matter::im::client::ImClient;
use simple_matter::transport::net::{BtpConnId, PeerAddr, MAX_RX_PACKET_SIZE};
use simple_matter::transport::session::SessionId;

use simple_matter_ble::btleplug_central::BtleplugCentral;

const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
const DEVICE_NODE_ID: u64 = 0x0000_0000_AABB_CCDD;
const VENDOR_ID: u16 = 0xFFF1;

const ONOFF_EP: EndpointId = EndpointId(1);
const ONOFF_CLUSTER: ClusterId = ClusterId(0x0006);
const ONOFF_CMD_TOGGLE: CommandId = CommandId(0x02);

/// 全体タイムアウト(BLE handshake + コミッショニング + 運用往復)。BLE は UDP より遅い。
const OVERALL_TIMEOUT: Duration = Duration::from_secs(90);

type Backend = RustCrypto<DemoRng>;
type Ctrl<'s> = ControllerStack<'s, Backend, DemoRng, ControllerCreds<'s, Backend>, 4, 6, 3, 1280>;

/// デモ用擬似乱数(UDP 版と同じ)。**暗号学的に安全ではない**。
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
    fn fill_bytes(&mut self, dest: &mut [u8]) -> MResult<()> {
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

/// `SM_BTP_TRACE=1` でフラグメントの先頭バイト(flags/ack/seq)をトレースする。
fn trace(dir: &str, frag: &[u8]) {
    if std::env::var_os("SM_BTP_TRACE").is_some() {
        let h: Vec<String> = frag.iter().take(5).map(|b| format!("{b:02x}")).collect();
        eprintln!("[btp {dir}] len={} {}", frag.len(), h.join(" "));
    }
}

/// BTP が吐く上りフラグメントを尽きるまで C1 write で送出する。
async fn flush_c1(
    gatt: &mut BtleplugCentral,
    btp: &mut Btp<6>,
    conn: BtpConnId,
    mtu: Option<u16>,
    now: u64,
) -> MResult<()> {
    let mut out = [0u8; 512];
    loop {
        let n = btp.process_outgoing(&mut out, mtu, now)?;
        if n == 0 {
            break;
        }
        trace("tx", &out[..n]);
        gatt.write_c1(conn, &out[..n]).await?;
    }
    Ok(())
}

/// 再組立済み Matter メッセージを `ctrl.handle_rx` へ配り、応答と `poll` の送出を BTP に載せる。
async fn service_ctrl(
    gatt: &mut BtleplugCentral,
    btp: &mut Btp<6>,
    ctrl: &mut Ctrl<'_>,
    peer: PeerAddr,
    conn: BtpConnId,
    mtu: Option<u16>,
    now: u64,
) -> MResult<()> {
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];
    while let Some(slen) = take_sdu(btp, &mut sdu) {
        if let Some(d) = ctrl.handle_rx(&mut sdu[..slen], peer, now, &mut txc) {
            btp.send(&txc[..d.len], now)?;
            flush_c1(gatt, btp, conn, mtu, now).await?;
        }
    }
    // 閉じた exchange の回収(§11-4)。BTP では再送/ACK は生じないが poll は必須。
    while let Some(d) = ctrl.poll(now, &mut txc) {
        btp.send(&txc[..d.len], now)?;
        flush_c1(gatt, btp, conn, mtu, now).await?;
    }
    Ok(())
}

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため)。
fn take_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let passcode = match args.get(1).and_then(|s| s.parse::<u32>().ok()) {
        Some(p) => p,
        None => {
            eprintln!("usage: ble-commissioner <passcode> [<discriminator>]");
            return ExitCode::FAILURE;
        }
    };
    let discriminator = args.get(2).and_then(|s| s.parse::<u16>().ok());

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[fatal] tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(passcode, discriminator)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("[fatal] {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn run(passcode: u32, discriminator: Option<u16>) -> Result<(), String> {
    // --- コントローラ資格情報(新規 CA)---
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
        "[ca] fabric_id={:#018x} controller_node_id={:#018x}",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, DemoRng::from_time(), ctrl_creds);
    let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());
    let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);

    // --- BLE スキャン & 接続 ---
    // SM_BLE_ADAPTER=hci1 等でアダプタを指定できる(2 アダプタ構成用)。未指定は最初の adapter。
    let adapter_name = std::env::var("SM_BLE_ADAPTER").ok();
    let mut gatt = BtleplugCentral::with_adapter(adapter_name.as_deref())
        .await
        .map_err(|e| format!("BtleplugCentral::with_adapter: {e:?} (BlueZ 稼働と権限を確認)"))?;
    println!("[ble] adapter: {}", gatt.adapter_info().await);
    println!(
        "[ble] scanning for 0xFFF6 commissionable (discriminator={})...",
        discriminator.map(|d| d.to_string()).unwrap_or_else(|| "any".into())
    );

    let target = gatt
        .scan(ScanFilter {
            discriminator,
            vendor_product: None,
        })
        .await
        .map_err(|e| format!("scan: {e:?}"))?;
    println!(
        "[ble] found device: discriminator={} vid={:#06x} pid={:#06x}",
        target.discriminator, target.vendor_id, target.product_id
    );

    let (conn, mtu) = gatt
        .connect(&target)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    println!("[ble] connected + subscribed C2 (conn={} att_mtu={mtu:?})", conn.0);

    let peer = PeerAddr::Ble(conn);
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- BTP handshake(central)---
    let mut btp = Btp::<6>::new(BtpRole::Central);
    let mut frag = [0u8; 512];
    {
        let now = now_ms(&start);
        let n = btp
            .start_handshake(&mut frag, mtu, now)
            .map_err(|e| format!("start_handshake: {e:?}"))?;
        gatt.write_c1(conn, &frag[..n])
            .await
            .map_err(|e| format!("write_c1(handshake): {e:?}"))?;
        while !btp.is_established() {
            if start.elapsed() > OVERALL_TIMEOUT {
                return Err("BTP handshake timed out".into());
            }
            let n = gatt
                .next_indication(conn, &mut frag)
                .await
                .map_err(|e| format!("next_indication(handshake): {e:?}"))?;
            trace("rx", &frag[..n]);
            btp.process_incoming(&frag[..n], mtu, now_ms(&start))
                .map_err(|e| format!("process_incoming(handshake): {e:?}"))?;
        }
    }
    println!(
        "[btp] established: fragment={} window={}",
        btp.fragment_size(),
        btp.window()
    );

    // --- コミッショニング開始 ---
    comm.commission(peer, passcode, DEVICE_NODE_ID, now_ms(&start))
        .map_err(|e| format!("commission() rejected: {e:?}"))?;
    println!("[commission] starting (device node_id={DEVICE_NODE_ID:#018x})");

    let mut last_phase = Phase::Idle;
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];

    let case_session: SessionId = 'outer: loop {
        if start.elapsed() > OVERALL_TIMEOUT {
            return Err(format!("commissioning timed out in phase {last_phase:?}"));
        }
        let now = now_ms(&start);

        // コミッショナを進められるだけ進める(要求を BTP で送る)。
        loop {
            let prev = comm.phase();
            let out = comm.drive(&mut ctrl, now, &mut txc);
            if out.phase != last_phase {
                report_phase(out.phase);
                last_phase = out.phase;
            }
            if let Some(d) = out.send {
                btp.send(&txc[..d.len], now)
                    .map_err(|e| format!("btp.send: {e:?}"))?;
                flush_c1(&mut gatt, &mut btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1: {e:?}"))?;
            }
            match out.phase {
                Phase::Done { session } => break 'outer session,
                Phase::Failed { stage, reason } => {
                    return Err(format!("commissioning failed at stage {stage}: {reason:?}"));
                }
                _ => {}
            }
            if out.send.is_none() && out.phase == prev {
                break;
            }
        }

        // 既に届いている応答を捌く。
        service_ctrl(&mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl: {e:?}"))?;

        // 次の下りフラグメントを待つ(BTP の遅延 ACK 期限まで)。
        let sleep = deadline_sleep(&btp, now);
        tokio::select! {
            r = gatt.next_indication(conn, &mut frag) => {
                let n = r.map_err(|e| format!("next_indication: {e:?}"))?;
                let now = now_ms(&start);
                trace("rx", &frag[..n]);
                btp.process_incoming(&frag[..n], mtu, now)
                    .map_err(|e| format!("process_incoming: {e:?}"))?;
                flush_c1(&mut gatt, &mut btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(ack): {e:?}"))?;
            }
            _ = tokio::time::sleep(sleep) => {
                let now = now_ms(&start);
                flush_c1(&mut gatt, &mut btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(timer): {e:?}"))?;
            }
        }
        let now = now_ms(&start);
        service_ctrl(&mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl(post): {e:?}"))?;
    };

    println!(
        "[commission] COMPLETE. operational CASE session = {:#x}",
        case_session.as_raw()
    );

    // --- 運用: CASE 上で OnOff Toggle を invoke ---
    let now = now_ms(&start);
    let dir = ctrl
        .start_invoke(
            case_session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now,
            &mut txc,
        )
        .map_err(|e| format!("start OnOff Toggle: {e:?}"))?;
    btp.send(&txc[..dir.len], now)
        .map_err(|e| format!("btp.send(toggle): {e:?}"))?;
    flush_c1(&mut gatt, &mut btp, conn, mtu, now)
        .await
        .map_err(|e| format!("flush_c1(toggle): {e:?}"))?;
    println!("[onoff] sent Toggle command over CASE/BLE");

    // Toggle 応答を待つ。
    let invoke_start = Instant::now();
    loop {
        if invoke_start.elapsed() > Duration::from_secs(30) {
            return Err("Toggle timed out".into());
        }
        let now = now_ms(&start);
        service_ctrl(&mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl(toggle): {e:?}"))?;
        if let Some(ev) = ctrl.im_take_event() {
            match ev {
                ImEvent::InvokeDone { status } if status.is_success() => {
                    println!("[onoff] Toggle acknowledged (status = Success)");
                    break;
                }
                other => return Err(format!("Toggle failed: {other:?}")),
            }
        }
        let sleep = deadline_sleep(&btp, now);
        tokio::select! {
            r = gatt.next_indication(conn, &mut frag) => {
                let n = r.map_err(|e| format!("next_indication(toggle): {e:?}"))?;
                let now = now_ms(&start);
                trace("rx", &frag[..n]);
                btp.process_incoming(&frag[..n], mtu, now)
                    .map_err(|e| format!("process_incoming(toggle): {e:?}"))?;
                flush_c1(&mut gatt, &mut btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(toggle-ack): {e:?}"))?;
            }
            _ = tokio::time::sleep(sleep) => {}
        }
    }

    // --- 切断 ---
    gatt.disconnect(conn)
        .await
        .map_err(|e| format!("disconnect: {e:?}"))?;
    println!("[done] commissioning + Toggle succeeded; disconnected");
    Ok(())
}

/// BTP の次 deadline(遅延 ACK 等)までの sleep 時間。無ければ緩いポーリング。
fn deadline_sleep(btp: &Btp<6>, now: u64) -> Duration {
    match btp.next_deadline() {
        Some(t) if t > now => Duration::from_millis(t - now),
        Some(_) => Duration::ZERO,
        None => Duration::from_millis(1000),
    }
}

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
