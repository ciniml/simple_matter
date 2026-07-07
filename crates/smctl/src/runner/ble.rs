//! BLE ランナー(feature `ble`、設計 doc §2.1 / §6 C2)。
//!
//! `simple-matter-ble/examples/ble-commissioner.rs` の btleplug central + BTP pump の移植。
//!
//! - `pairing ble`(`handoff = false`): scan → connect → BTP handshake → PASE〜CASE〜
//!   CommissioningComplete を **すべて BLE 上で**実行(自作デバイス向け)。完了後、
//!   運用 mDNS を best effort で解決してアドレス帳に記帳する(解決できなければ
//!   未解決 sentinel を記帳し、運用コマンド時に mDNS 再解決させる)。
//! - `pairing ble-handoff`(`handoff = true`): 方向 B。AddNOC 完了で CASE を保留
//!   ([`Commissioner::suspend_before_case`])し、BLE を閉じて運用 mDNS 解決 →
//!   CASE → CommissioningComplete を **UDP 上で**完走させる(chip-lighting-app は
//!   AddNOC 受理後に自ら BLE を閉じるため。ble-commissioner の `--udp-handoff` 相当)。
//! - `pairing ble-wifi`(`wifi = Some`): chip-tool `pairing ble-wifi` 相当。AddNOC 後、
//!   **同 BLE(PASE)セッション上で** AddOrUpdateWiFiNetwork → ConnectNetwork を送り
//!   (コアの [`Commissioner::set_wifi_credentials`] フェーズ)、以降は方向 B と同じく
//!   BLE を閉じて運用 mDNS 解決 → CASE → CommissioningComplete を UDP で完走する。
//!   デバイスは ConnectNetwork に即 Success を返してバックグラウンドで join するため、
//!   mDNS 解決は Wi-Fi association + DHCP を見込んだ長めのタイムアウトでリトライする。
//!
//! アダプタは `SM_BLE_ADAPTER=hciN` で指定できる。`SM_BTP_TRACE=1` で BTP フラグメントを
//! トレースする。tokio(current_thread)はこのモジュール内でのみ使う(設計 doc §2.4)。

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use simple_matter::btp::gatt::{GattCentral, ScanFilter};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::controller::ca::Ca;
use simple_matter::controller::{AttestationPolicy, Commissioner, Phase};
use simple_matter::error::Result as MResult;
use simple_matter::im::client::ImClient;
use simple_matter::sc::initiator::ScInitiator;
use simple_matter::transport::net::{BtpConnId, PeerAddr, MAX_RX_PACKET_SIZE};
use simple_matter::transport::session::SessionId;

use simple_matter_ble::btleplug_central::BtleplugCentral;

use crate::cli::Globals;
use crate::ops::report_phase;
use crate::runner::udp::{open_dual_stack_udp, pump_commissioner, settle};
use crate::runner::{mdns, Backend, Ctrl};
use crate::state::{ca as ca_state, nodes, StateDir};
use crate::OsRng;

/// BLE フェーズ(handshake + コミッショニング)の全体タイムアウト。BLE は UDP より遅い。
const BLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 運用 mDNS 解決のタイムアウト(handoff では必須解決)。クエリが届かない環境でも
/// デバイスの定期 announce(30 秒間隔)を 1 回は拾える長さを取る。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(35);
/// `ble-wifi` での運用 mDNS 解決タイムアウト。デバイスの Wi-Fi association(認証
/// リトライ込みで実測 ~25 秒かかることがある)+ DHCP + 運用 mDNS 開始を待ち、さらに
/// クエリが届かない環境でも定期 announce(30 秒間隔)を 1 回は拾えるだけの長さを取る。
const WIFI_RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);
/// フル BLE パスでの best-effort 運用解決のタイムアウト(失敗しても致命ではない)。
const RESOLVE_BEST_EFFORT: Duration = Duration::from_secs(10);
/// 運用 UDP フェーズ(CASE + CommissioningComplete)の全体タイムアウト。
const UDP_TIMEOUT: Duration = Duration::from_secs(30);

/// `pairing ble` / `pairing ble-handoff` / `pairing ble-wifi` のエントリポイント。
pub fn pair_ble(
    g: &Globals,
    node_id: u64,
    passcode: u32,
    discriminator: Option<u16>,
    handoff: bool,
    wifi: Option<(String, String)>,
) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let crypto = simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let ca = {
        let _lock = state.lock()?;
        ca_state::load_or_create(&state.ca_path(), &crypto)?
    };
    crate::log::logf!(
        crate::log::Level::Info,
        "ctl",
        "ca: fabric_id={:#018x} controller_node_id={:#018x}",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let recorded = rt.block_on(run_ble(
        &crypto,
        &ca,
        node_id,
        passcode,
        discriminator,
        handoff,
        wifi.as_ref().map(|(s, p)| (s.as_bytes(), p.as_bytes())),
    ))?;

    // 発行済み serial を CA 状態に反映し、アドレス帳へ記帳する。
    {
        let _lock = state.lock()?;
        ca_state::save(&state.ca_path(), &ca)?;
        nodes::upsert(
            &state.nodes_path(),
            nodes::NodeEntry {
                node_id,
                label: g.label.clone().unwrap_or_default(),
                last_addr: recorded,
            },
        )?;
    }
    if recorded.port() == 0 {
        crate::json::info!(
            "[pairing] node {node_id} recorded (operational address unresolved; \
             it will be re-resolved via mDNS on first use; state: {})",
            g.state_dir.display()
        );
    } else {
        crate::json::info!(
            "[pairing] node {node_id} recorded at {recorded} (state: {})",
            g.state_dir.display()
        );
    }
    Ok(())
}

/// BLE 上のコミッショニング本体。記帳すべき運用アドレス(未解決なら port=0 の sentinel)を返す。
#[allow(clippy::too_many_arguments)]
async fn run_ble(
    crypto: &Backend,
    ca: &Ca<Backend>,
    node_id: u64,
    passcode: u32,
    discriminator: Option<u16>,
    handoff: bool,
    wifi: Option<(&[u8], &[u8])>,
) -> Result<SocketAddr, String> {
    // ble-wifi はデバイスが Wi-Fi join 後に IP 到達可能になるため、CASE 以降は必ず
    // 運用 UDP で行う(handoff と同じ保留遷移)。
    let udp_case = handoff || wifi.is_some();
    let ctrl_creds = simple_matter::controller::ControllerCreds::new(ca, crypto, 0);
    let sc_init = ScInitiator::new(crypto, OsRng, ctrl_creds);
    let mut ctrl: Ctrl =
        simple_matter::controller::ControllerStack::new(crypto, sc_init, ImClient::new());

    // --- BLE スキャン & 接続(SM_BLE_ADAPTER=hciN でアダプタ指定)---
    let adapter_name = std::env::var("SM_BLE_ADAPTER").ok();
    let mut gatt = BtleplugCentral::with_adapter(adapter_name.as_deref())
        .await
        .map_err(|e| format!("BtleplugCentral::with_adapter: {e:?} (is BlueZ running?)"))?;
    crate::log::logf!(
        crate::log::Level::Info,
        "ble",
        "adapter: {}",
        gatt.adapter_info().await
    );
    crate::log::logf!(
        crate::log::Level::Info,
        "ble",
        "scanning for 0xFFF6 commissionable (discriminator={})...",
        discriminator
            .map(|d| d.to_string())
            .unwrap_or_else(|| "any".into())
    );
    let target = gatt
        .scan(ScanFilter {
            discriminator,
            vendor_product: None,
        })
        .await
        .map_err(|e| format!("scan: {e:?}"))?;
    crate::log::logf!(
        crate::log::Level::Info,
        "ble",
        "found device: discriminator={} vid={:#06x} pid={:#06x}",
        target.discriminator,
        target.vendor_id,
        target.product_id
    );
    let (conn, mtu) = gatt
        .connect(&target)
        .await
        .map_err(|e| format!("connect: {e:?}"))?;
    crate::log::logf!(
        crate::log::Level::Info,
        "ble",
        "connected (conn={} att_mtu={mtu:?})",
        conn.0
    );

    let peer = PeerAddr::Ble(conn);
    let start = Instant::now();

    // --- BTP handshake(central)。C1 write → C2 subscribe → 応答 indication の順序が必須。---
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
        gatt.subscribe_c2(conn)
            .await
            .map_err(|e| format!("subscribe_c2: {e:?}"))?;
        while !btp.is_established() {
            if start.elapsed() > BLE_TIMEOUT {
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
    crate::log::logf!(
        crate::log::Level::Info,
        "btp",
        "established: fragment={} window={}",
        btp.fragment_size(),
        btp.window()
    );

    // --- コミッショニング(BLE 上)---
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];
    let mut comm = Commissioner::new(ca, crypto, AttestationPolicy::Skip);
    if udp_case {
        comm.suspend_before_case();
    }
    if let Some((ssid, password)) = wifi {
        comm.set_wifi_credentials(ssid, password)
            .map_err(|e| format!("set_wifi_credentials: {e:?}"))?;
        crate::log::logf!(
            crate::log::Level::Info,
            "ctl",
            "wifi provisioning enabled (ssid={:?})",
            String::from_utf8_lossy(ssid)
        );
    }
    comm.commission(peer, passcode, node_id, now_ms(&start))
        .map_err(|e| format!("commission() rejected: {e:?}"))?;
    crate::log::logf!(
        crate::log::Level::Info,
        "ctl",
        "starting (device node_id={node_id:#018x})"
    );

    let outcome = drive_commission_ble(
        &mut comm, udp_case, &mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, &start, &mut frag,
        &mut txc,
    )
    .await?;

    match outcome {
        BleOutcome::Done(_session) => {
            // 従来パス: CASE も CommissioningComplete も BLE 上で完了済み。
            gatt.disconnect(conn)
                .await
                .map_err(|e| format!("disconnect: {e:?}"))?;
            crate::log::logf!(
                crate::log::Level::Info,
                "ctl",
                "commissioning succeeded (all over BLE); disconnected"
            );
            // 運用は UDP で行うので、運用 mDNS を best effort で解決して記帳する。
            match mdns::resolve_operational(ca, node_id, RESOLVE_BEST_EFFORT) {
                Ok(addr) => {
                    crate::log::logf!(
                        crate::log::Level::Info,
                        "dis",
                        "operational node resolved at {addr}"
                    );
                    Ok(addr)
                }
                Err(e) => {
                    crate::log::logf!(
                        crate::log::Level::Warn,
                        "dis",
                        "operational mDNS not resolved yet ({e})"
                    );
                    Ok(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
                }
            }
        }
        BleOutcome::PausedBeforeCase => {
            // 方向 B / ble-wifi: BLE を閉じ、運用 mDNS で解決、CASE→CommissioningComplete を
            // UDP で。ble-wifi ではデバイスの Wi-Fi join / DHCP / 運用 mDNS 開始を待つため
            // 解決タイムアウトを長めに取る(クエリは 2 秒間隔でリトライされる)。
            crate::log::logf!(
                crate::log::Level::Info,
                "ctl",
                "BLE commissioning phases complete; closing BLE, \
                 switching to operational UDP"
            );
            // chip は AddNOC 受理後に自ら BLE を閉じるので、失敗は無視する。
            let _ = gatt.disconnect(conn).await;

            let resolve_timeout = if wifi.is_some() {
                crate::log::logf!(
                    crate::log::Level::Info,
                    "ctl",
                    "waiting for device to join WiFi and start operational mDNS \
                     (up to {WIFI_RESOLVE_TIMEOUT:?})..."
                );
                WIFI_RESOLVE_TIMEOUT
            } else {
                RESOLVE_TIMEOUT
            };
            let device_addr = mdns::resolve_operational(ca, node_id, resolve_timeout)?;
            crate::log::logf!(
                crate::log::Level::Info,
                "ctl",
                "operational node resolved at {device_addr}"
            );

            let socket = open_dual_stack_udp().map_err(|e| format!("bind udp socket: {e}"))?;
            socket
                .set_read_timeout(Some(Duration::from_millis(50)))
                .map_err(|e| format!("set_read_timeout: {e}"))?;

            comm.set_peer(PeerAddr::Udp(device_addr));
            comm.resume();

            let session = drive_commission_udp(&mut comm, &mut ctrl, &socket, &start)?;
            crate::log::logf!(
                crate::log::Level::Info,
                "ctl",
                "direction-B complete: BLE commissioning -> BLE close -> mDNS -> \
                 CASE over UDP (session={:#x}) -> CommissioningComplete",
                session.as_raw()
            );
            Ok(device_addr)
        }
    }
}

/// [`drive_commission_ble`] の帰結。
enum BleOutcome {
    /// CASE まで BLE 上で完了した(従来パス)。運用 CASE セッションを返す。
    Done(SessionId),
    /// AddNOC まで完了し、CASE 開始直前で保留した(方向 B の運用 UDP 遷移待ち)。
    PausedBeforeCase,
}

fn now_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// BTP フラグメントの先頭バイト(flags/ack/seq)をトレースする。
/// `--log-level trace` または後方互換の `SM_BTP_TRACE=1` で有効(設計 doc §9.1)。
fn trace(dir: &str, frag: &[u8]) {
    if std::env::var_os("SM_BTP_TRACE").is_some() || crate::log::enabled(crate::log::Level::Trace) {
        let h: Vec<String> = frag.iter().take(5).map(|b| format!("{b:02x}")).collect();
        crate::log::force(
            crate::log::Level::Trace,
            "btp",
            format_args!("{dir} len={} {}", frag.len(), h.join(" ")),
        );
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
#[allow(clippy::too_many_arguments)]
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
        crate::wire::log_rx("ble", &sdu[..slen], "btp");
        if let Some(d) = ctrl.handle_rx(&mut sdu[..slen], peer, now, &mut txc) {
            crate::wire::log_tx("ble", &txc[..d.len], "btp");
            btp.send(&txc[..d.len], now)?;
            flush_c1(gatt, btp, conn, mtu, now).await?;
        }
    }
    // 閉じた exchange の回収(ble-btp.md §11-4)。BTP では再送/ACK は生じないが poll は必須。
    while let Some(d) = ctrl.poll(now, &mut txc) {
        crate::wire::log_tx("ble", &txc[..d.len], "btp");
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

/// BTP の次 deadline(遅延 ACK 等)までの sleep 時間。無ければ緩いポーリング。
fn deadline_sleep(btp: &Btp<6>, now: u64) -> Duration {
    match btp.next_deadline() {
        Some(t) if t > now => Duration::from_millis(t - now),
        Some(_) => Duration::ZERO,
        None => Duration::from_millis(1000),
    }
}

/// BLE 上でコミッショニングを駆動する。`udp_case` が真なら BLE 上の最終フェーズ完了
/// (AddNOC、ble-wifi では続く ConnectNetwork までで Phase::Case 到達)で保留して
/// [`BleOutcome::PausedBeforeCase`] を返す。偽なら CASE→Complete まで BLE で完走し
/// [`BleOutcome::Done`] を返す。
#[allow(clippy::too_many_arguments)]
async fn drive_commission_ble(
    comm: &mut Commissioner<'_, Backend>,
    udp_case: bool,
    gatt: &mut BtleplugCentral,
    btp: &mut Btp<6>,
    ctrl: &mut Ctrl<'_>,
    peer: PeerAddr,
    conn: BtpConnId,
    mtu: Option<u16>,
    start: &Instant,
    frag: &mut [u8; 512],
    txc: &mut [u8; MAX_RX_PACKET_SIZE],
) -> Result<BleOutcome, String> {
    let mut last_phase = Phase::Idle;
    loop {
        if start.elapsed() > BLE_TIMEOUT {
            return Err(format!("commissioning timed out in phase {last_phase:?}"));
        }
        let now = now_ms(start);

        // コミッショナを進められるだけ進める(要求を BTP で送る)。
        loop {
            let prev = comm.phase();
            let out = comm.drive(ctrl, now, txc);
            if out.phase != last_phase {
                report_phase(out.phase);
                last_phase = out.phase;
            }
            if let Some(d) = out.send {
                crate::wire::log_tx("ble", &txc[..d.len], "btp");
                btp.send(&txc[..d.len], now)
                    .map_err(|e| format!("btp.send: {e:?}"))?;
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1: {e:?}"))?;
            }
            match out.phase {
                Phase::Done { session } => {
                    crate::log::logf!(
                        crate::log::Level::Info,
                        "ctl",
                        "COMPLETE. operational CASE session = {:#x}",
                        session.as_raw()
                    );
                    return Ok(BleOutcome::Done(session));
                }
                Phase::Failed { stage, reason } => {
                    return Err(format!("commissioning failed at stage {stage}: {reason:?}"));
                }
                _ => {}
            }
            if out.send.is_none() && out.phase == prev {
                break;
            }
        }

        // 方向 B / ble-wifi: BLE 上の最終フェーズ完了で CASE が保留された(sigma1 未送出)。
        // ここで BLE を降りる。
        if udp_case && matches!(comm.phase(), Phase::Case) {
            crate::log::logf!(
                crate::log::Level::Info,
                "ctl",
                "BLE phases accepted; CASE suspended for operational UDP handoff"
            );
            return Ok(BleOutcome::PausedBeforeCase);
        }

        // 既に届いている応答を捌く。
        service_ctrl(gatt, btp, ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl: {e:?}"))?;

        // 次の下りフラグメントを待つ(BTP の遅延 ACK 期限まで)。
        let sleep = deadline_sleep(btp, now);
        tokio::select! {
            r = gatt.next_indication(conn, frag) => {
                let n = r.map_err(|e| format!("next_indication: {e:?}"))?;
                let now = now_ms(start);
                trace("rx", &frag[..n]);
                btp.process_incoming(&frag[..n], mtu, now)
                    .map_err(|e| format!("process_incoming: {e:?}"))?;
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(ack): {e:?}"))?;
            }
            _ = tokio::time::sleep(sleep) => {
                let now = now_ms(start);
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(timer): {e:?}"))?;
            }
        }
        let now = now_ms(start);
        service_ctrl(gatt, btp, ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl(post): {e:?}"))?;
    }
}

/// 運用 UDP 上で保留解除後のコミッショニング(CASE → CommissioningComplete)を駆動する。
fn drive_commission_udp(
    comm: &mut Commissioner<'_, Backend>,
    ctrl: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
) -> Result<SessionId, String> {
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut last_phase = comm.phase();
    let deadline = Instant::now() + UDP_TIMEOUT;

    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "UDP commissioning timed out in phase {last_phase:?}"
            ));
        }
        let phase = pump_commissioner(comm, ctrl, socket, now_ms(start), &mut tx);
        if phase != last_phase {
            report_phase(phase);
            last_phase = phase;
        }
        match phase {
            Phase::Done { session } => {
                crate::log::logf!(
                    crate::log::Level::Info,
                    "ctl",
                    "COMPLETE over UDP. operational CASE session = {:#x}",
                    session.as_raw()
                );
                // 最後の応答/ACK を流し切ってから返す。
                settle(ctrl, socket, start, &mut rx, &mut tx, deadline)?;
                return Ok(session);
            }
            Phase::Failed { stage, reason } => {
                return Err(format!(
                    "UDP commissioning failed at stage {stage}: {reason:?}"
                ));
            }
            _ => {}
        }
        // 発行したトランザクションの応答を受け切り、standalone ACK も含めて静穏化させる。
        settle(ctrl, socket, start, &mut rx, &mut tx, deadline)?;
    }
}
