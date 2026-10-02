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
//! # `--udp-handoff`: 方向 B(BLE→運用 UDP 遷移)
//!
//! 公式サンプル `chip-lighting-app` は AddNOC を受理すると自ら BLE を閉じるため、CASE 以降を
//! BLE 上で続けられない。`--udp-handoff` を付けると本 example は **AddNOC 完了で CASE を保留**
//! ([`Commissioner::suspend_before_case`])し、BLE を閉じてから運用 mDNS
//! (`<compressedFabricId>-<nodeId>._matter._tcp.local` を QU で解決)でデバイスを見つけ、
//! **CASE → CommissioningComplete → OnOff Toggle を UDP 上で**完走させる。保留解除後は
//! [`Commissioner::set_peer`] で運用アドレスへ差し替え [`Commissioner::resume`] するだけで、
//! フェーズ機械はそのまま UDP を走る。未指定時は従来どおり CASE も BLE 上で連続実行する。
//!
//! # E4: CA 永続化と `--operational` モード(`docs/design/port-esp32-device.md` §E4.6)
//!
//! - **CA 永続化**: 初回起動時に CA の鍵素材(root 秘密鍵・コントローラ運用秘密鍵・
//!   IPK epoch key・識別子・serial カウンタ)を `--ca-state <file>`(既定
//!   `./ca-state.bin`)へ TLV 保存し、以後の起動で再利用する。証明書は保存しない
//!   (署名が決定的なので同じ鍵から同一バイト列を再生成できる)。
//! - **`--operational`**: スキャン → BLE 接続 → BTP handshake → **PASE を飛ばして
//!   CASE のみ** → OnOff Toggle。デバイスの fabric 永続化(リブート後の CASE 再確立)の
//!   検証ゲートに使う。要・保存済み CA 状態(= 過去に通常モードでコミッショニング済み)。
//!
//! 実行(先に別ホスト/アダプタで `ble-onoff-light` / 実機 `e4-ble-light` を起動):
//! ```text
//! cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840
//! cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840 --operational
//! ```
//! 第 2 引数(discriminator)省略時は任意の commissionable デバイスに接続する。
//!
//! [`Btp<6>`]: simple_matter::btp::Btp
//! [`ControllerStack`]: simple_matter::controller::ControllerStack
//! [`Commissioner`]: simple_matter::controller::Commissioner

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::btp::gatt::{GattCentral, ScanFilter};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::controller::ca::Ca;
use simple_matter::controller::{
    AttestationPolicy, Commissioner, ControllerCreds, ControllerStack, Phase,
    CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::client::MdnsClient;
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_PORT};
use simple_matter::dm::meta::{ClusterId, CommandId, EndpointId};
use simple_matter::error::Result as MResult;
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::CommandPath;
use simple_matter::im::ImEvent;
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::stack::SendDirective;
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
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

/// CA 状態ファイルの既定パス。
const DEFAULT_CA_STATE: &str = "./ca-state.bin";

/// CA 状態レコードの schema version。
const CA_STATE_VERSION: u8 = 1;

type Backend = RustCrypto<DemoRng>;
// SS=6: 方向 B の BLE→UDP 遷移では BLE 側(unsecured + PASE)と UDP 側(unsecured + CASE)の
// セッションが一時的に共存しうるため、UDP 版(SS=4)より広く取る。
type Ctrl<'s> = ControllerStack<'s, Backend, DemoRng, ControllerCreds<'s, Backend>, 6, 6, 3, 1280>;

/// 運用 mDNS 解決のタイムアウト。
const MDNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(20);
/// 運用 mDNS のクエリ再送間隔。
const MDNS_REQUERY_INTERVAL: Duration = Duration::from_secs(2);
/// 運用 UDP フェーズ(CASE + CommissioningComplete + Toggle)の全体タイムアウト。
const UDP_TIMEOUT: Duration = Duration::from_secs(30);

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

// ==========================================================================
// CA 状態の永続化(E4、doc §E4.6)
// ==========================================================================

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// CA の鍵素材を TLV でファイルへ保存する。
fn save_ca_state(path: &Path, ca: &Ca<Backend>) -> Result<(), String> {
    let ctrl_key = ca
        .controller_key_bytes()
        .map_err(|e| format!("controller_key_bytes: {e:?}"))?;
    let mut buf = [0u8; 192];
    let len = {
        let mut w = TlvWriter::new(&mut buf);
        let write = |w: &mut TlvWriter| -> MResult<()> {
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), CA_STATE_VERSION)?;
            w.write_u64(&cx(1), ca.fabric_id())?;
            w.write_u64(&cx(2), ca.controller_node_id())?;
            w.write_u16(&cx(3), ca.vendor_id())?;
            w.write_bytes(&cx(4), ca.ipk_epoch_key())?;
            w.write_bytes(&cx(5), &ca.root_key_bytes())?;
            w.write_bytes(&cx(6), &ctrl_key)?;
            w.write_u32(&cx(7), ca.next_serial())?;
            w.end_container()
        };
        write(&mut w).map_err(|e| format!("encode CA state: {e:?}"))?;
        w.len()
    };
    std::fs::write(path, &buf[..len]).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

/// 保存済み CA 状態からの復元。ファイルが無ければ `Ok(None)`。
fn load_ca_state(path: &Path, crypto: &Backend) -> Result<Option<Ca<Backend>>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let decode = || -> MResult<Ca<Backend>> {
        let mut r = TlvReader::new(&bytes);
        if r.enter_container()? != ContainerType::Structure {
            return Err(simple_matter::Error::Decode);
        }
        let mut version = 0u8;
        let mut fabric_id = 0u64;
        let mut node_id = 0u64;
        let mut vendor_id = 0u16;
        let mut ipk = [0u8; 16];
        let mut root_key = [0u8; 32];
        let mut ctrl_key = [0u8; 32];
        let mut next_serial = 0u32;
        loop {
            let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
                (TlvTag::ContextSpecific(1), v) => fabric_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(2), v) => node_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(3), v) => vendor_id = v.as_unsigned()? as u16,
                (TlvTag::ContextSpecific(4), v) => {
                    ipk = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(5), v) => {
                    root_key = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(6), v) => {
                    ctrl_key = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(7), v) => next_serial = v.as_unsigned()? as u32,
                _ => r.skip(&e)?,
            }
        }
        if version != CA_STATE_VERSION {
            return Err(simple_matter::Error::Decode);
        }
        Ca::restore(
            crypto,
            &root_key,
            &ctrl_key,
            ipk,
            fabric_id,
            node_id,
            vendor_id,
            next_serial,
            0,
        )
    };
    decode()
        .map(Some)
        .map_err(|e| format!("restore CA from {}: {e:?}", path.display()))
}

/// CA を復元、無ければ新規生成して保存する。
fn load_or_create_ca(path: &Path, crypto: &Backend) -> Result<Ca<Backend>, String> {
    if let Some(ca) = load_ca_state(path, crypto)? {
        println!("[ca] restored from {}", path.display());
        return Ok(ca);
    }
    let ca = Ca::<Backend>::generate(
        crypto,
        &mut DemoRng::from_time(),
        FABRIC_ID,
        CONTROLLER_NODE_ID,
        VENDOR_ID,
        0,
    )
    .map_err(|e| format!("CA generate failed: {e:?}"))?;
    save_ca_state(path, &ca)?;
    println!("[ca] generated new CA; state saved to {}", path.display());
    Ok(ca)
}

// ==========================================================================
// 引数・main
// ==========================================================================

struct Opts {
    passcode: u32,
    discriminator: Option<u16>,
    operational: bool,
    udp_handoff: bool,
    ca_state: PathBuf,
}

fn usage() -> String {
    "usage: ble-commissioner <passcode> [<discriminator>] [--operational] [--udp-handoff] [--ca-state <file>]"
        .into()
}

fn parse_args() -> Result<Opts, String> {
    let mut positional: Vec<String> = Vec::new();
    let mut operational = false;
    let mut udp_handoff = false;
    let mut ca_state = PathBuf::from(DEFAULT_CA_STATE);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--operational" => operational = true,
            "--udp-handoff" => udp_handoff = true,
            "--ca-state" => {
                ca_state = PathBuf::from(it.next().ok_or_else(usage)?);
            }
            _ if arg.starts_with("--") => return Err(usage()),
            _ => positional.push(arg),
        }
    }
    let passcode = positional
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(usage)?;
    let discriminator = positional.get(1).and_then(|s| s.parse::<u16>().ok());
    Ok(Opts {
        passcode,
        discriminator,
        operational,
        udp_handoff,
        ca_state,
    })
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

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

    match rt.block_on(run(opts)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("[fatal] {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn run(opts: Opts) -> Result<(), String> {
    // --- コントローラ資格情報(CA の復元 or 新規生成 + 保存)---
    let crypto = RustCrypto::new(DemoRng::from_time());
    let ca = load_or_create_ca(&opts.ca_state, &crypto)?;
    println!(
        "[ca] fabric_id={:#018x} controller_node_id={:#018x}",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, DemoRng::from_time(), ctrl_creds);
    let mut ctrl: Ctrl = ControllerStack::new(&crypto, sc_init, ImClient::new());

    // --- BLE スキャン & 接続 ---
    // SM_BLE_ADAPTER=hci1 等でアダプタを指定できる(2 アダプタ構成用)。未指定は最初の adapter。
    let adapter_name = std::env::var("SM_BLE_ADAPTER").ok();
    let mut gatt = BtleplugCentral::with_adapter(adapter_name.as_deref())
        .await
        .map_err(|e| format!("BtleplugCentral::with_adapter: {e:?} (BlueZ 稼働と権限を確認)"))?;
    println!("[ble] adapter: {}", gatt.adapter_info().await);
    println!(
        "[ble] scanning for 0xFFF6 commissionable (discriminator={})...",
        opts.discriminator
            .map(|d| d.to_string())
            .unwrap_or_else(|| "any".into())
    );

    let target = gatt
        .scan(ScanFilter {
            short_discriminator: None,
            discriminator: opts.discriminator,
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
    println!("[ble] connected (conn={} att_mtu={mtu:?})", conn.0);

    let peer = PeerAddr::Ble(conn);
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- BTP handshake(central)---
    // BTP の確立順序: handshake request の C1 write → C2 subscribe → 応答 indication。
    // chip の peripheral は最初の C1 write で endpoint を作り subscribe を契機に応答を
    // 送るため、この順序でないと handshake がタイムアウトする(GattCentral の doc 参照)。
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

    let mut txc = [0u8; MAX_RX_PACKET_SIZE];

    // --- operational モード(保存済み CA で CASE のみ、BLE 上で Toggle)---
    if opts.operational {
        let session = establish_case_only(
            &mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, &start, &mut frag, &mut txc,
        )
        .await?;
        toggle_over_ble(
            &mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, &start, &mut frag, &mut txc, session,
        )
        .await?;
        gatt.disconnect(conn)
            .await
            .map_err(|e| format!("disconnect: {e:?}"))?;
        println!("[done] operational CASE + Toggle succeeded; disconnected");
        return Ok(());
    }

    // --- フルコミッショニング ---
    // `--udp-handoff` 指定時は AddNOC 完了で CASE を保留し、BLE を閉じて運用 mDNS→UDP に
    // 遷移する(方向 B: chip-lighting-app は AddNOC 受理後に BLE を閉じるため)。未指定時は
    // 従来どおり CASE も BLE 上で連続実行する(自作デバイス向け)。
    let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);
    if opts.udp_handoff {
        comm.suspend_before_case();
    }
    comm.commission(peer, opts.passcode, DEVICE_NODE_ID, now_ms(&start))
        .map_err(|e| format!("commission() rejected: {e:?}"))?;
    println!("[commission] starting (device node_id={DEVICE_NODE_ID:#018x})");

    let outcome = drive_commission_ble(
        &mut comm,
        opts.udp_handoff,
        &mut gatt,
        &mut btp,
        &mut ctrl,
        peer,
        conn,
        mtu,
        &start,
        &mut frag,
        &mut txc,
    )
    .await?;
    // 発行済み serial を CA 状態に反映する(--operational の前提を満たす)。
    save_ca_state(&opts.ca_state, &ca)?;

    match outcome {
        BleOutcome::Done(session) => {
            // 従来パス: CASE も BLE 上で完了済み。Toggle も BLE 上で。
            toggle_over_ble(
                &mut gatt, &mut btp, &mut ctrl, peer, conn, mtu, &start, &mut frag, &mut txc,
                session,
            )
            .await?;
            gatt.disconnect(conn)
                .await
                .map_err(|e| format!("disconnect: {e:?}"))?;
            println!("[done] commissioning + Toggle succeeded (all over BLE); disconnected");
        }
        BleOutcome::PausedBeforeCase => {
            // 方向 B: BLE を閉じ、運用 mDNS で解決、CASE→CommissioningComplete→Toggle を UDP で。
            println!("[handoff] AddNOC complete; closing BLE, switching to operational UDP");
            // chip は AddNOC 受理後に自ら BLE を閉じるので、失敗は無視する。
            let _ = gatt.disconnect(conn).await;

            let device_addr = resolve_operational(&ca, DEVICE_NODE_ID)?;
            println!("[handoff] operational node resolved at {device_addr}");

            let socket = open_dual_stack_udp().map_err(|e| format!("bind udp socket: {e}"))?;
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

            comm.set_peer(PeerAddr::Udp(device_addr));
            comm.resume();

            let session = drive_commission_udp(&mut comm, &mut ctrl, &socket, &start)?;
            toggle_over_udp(&mut ctrl, &socket, &start, session)?;
            println!(
                "[done] direction-B complete: BLE commissioning → BLE close → mDNS → CASE over UDP → CommissioningComplete → Toggle"
            );
        }
    }
    Ok(())
}

/// [`drive_commission_ble`] の帰結。
enum BleOutcome {
    /// CASE まで BLE 上で完了した(従来パス)。運用 CASE セッションを返す。
    Done(SessionId),
    /// AddNOC まで完了し、CASE 開始直前で保留した(方向 B の運用 UDP 遷移待ち)。
    PausedBeforeCase,
}

/// BLE 上でコミッショニングを駆動する。`handoff` が真なら AddNOC 完了(Phase::Case 到達)で
/// 保留して [`BleOutcome::PausedBeforeCase`] を返す。偽なら CASE→Complete まで BLE で完走し
/// [`BleOutcome::Done`] を返す。
#[allow(clippy::too_many_arguments)]
async fn drive_commission_ble(
    comm: &mut Commissioner<'_, Backend>,
    handoff: bool,
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
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let mut last_phase = Phase::Idle;
    loop {
        if start.elapsed() > OVERALL_TIMEOUT {
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
                btp.send(&txc[..d.len], now)
                    .map_err(|e| format!("btp.send: {e:?}"))?;
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1: {e:?}"))?;
            }
            match out.phase {
                Phase::Done { session } => {
                    println!(
                        "[commission] COMPLETE. operational CASE session = {:#x}",
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

        // 方向 B: AddNOC 完了で CASE が保留された(sigma1 未送出)。ここで BLE を降りる。
        if handoff && matches!(comm.phase(), Phase::Case) {
            println!("[commission] AddNOC accepted; CASE suspended for operational UDP handoff");
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

/// 確立済み CASE セッション上で OnOff Toggle を BLE 経由で送り、成功応答を待つ。
#[allow(clippy::too_many_arguments)]
async fn toggle_over_ble(
    gatt: &mut BtleplugCentral,
    btp: &mut Btp<6>,
    ctrl: &mut Ctrl<'_>,
    peer: PeerAddr,
    conn: BtpConnId,
    mtu: Option<u16>,
    start: &Instant,
    frag: &mut [u8; 512],
    txc: &mut [u8; MAX_RX_PACKET_SIZE],
    session: SessionId,
) -> Result<(), String> {
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let now = now_ms(start);
    let dir = ctrl
        .start_invoke(
            session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now,
            txc,
        )
        .map_err(|e| format!("start OnOff Toggle: {e:?}"))?;
    btp.send(&txc[..dir.len], now)
        .map_err(|e| format!("btp.send(toggle): {e:?}"))?;
    flush_c1(gatt, btp, conn, mtu, now)
        .await
        .map_err(|e| format!("flush_c1(toggle): {e:?}"))?;
    println!("[onoff] sent Toggle command over CASE/BLE");

    let invoke_start = Instant::now();
    loop {
        if invoke_start.elapsed() > Duration::from_secs(30) {
            return Err("Toggle timed out".into());
        }
        let now = now_ms(start);
        service_ctrl(gatt, btp, ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl(toggle): {e:?}"))?;
        if let Some(ev) = ctrl.im_take_event() {
            match ev {
                ImEvent::InvokeDone { status } if status.is_success() => {
                    println!("[onoff] Toggle acknowledged (status = Success)");
                    return Ok(());
                }
                other => return Err(format!("Toggle failed: {other:?}")),
            }
        }
        let sleep = deadline_sleep(btp, now);
        tokio::select! {
            r = gatt.next_indication(conn, frag) => {
                let n = r.map_err(|e| format!("next_indication(toggle): {e:?}"))?;
                let now = now_ms(start);
                trace("rx", &frag[..n]);
                btp.process_incoming(&frag[..n], mtu, now)
                    .map_err(|e| format!("process_incoming(toggle): {e:?}"))?;
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(toggle-ack): {e:?}"))?;
            }
            _ = tokio::time::sleep(sleep) => {}
        }
    }
}

// ==========================================================================
// 方向 B: 運用 UDP 遷移(mDNS 解決 → CASE → CommissioningComplete → Toggle)
// ==========================================================================

/// 運用 mDNS(`_matter._tcp.local`)でデバイスを解決し、UDP 上で CASE →
/// CommissioningComplete まで駆動して運用 CASE セッションを返す(方向 B)。
fn drive_commission_udp(
    comm: &mut Commissioner<'_, Backend>,
    ctrl: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
) -> Result<SessionId, String> {
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut last_phase = comm.phase();
    let udp_start = Instant::now();

    loop {
        if udp_start.elapsed() > UDP_TIMEOUT {
            return Err(format!(
                "UDP commissioning timed out in phase {last_phase:?}"
            ));
        }

        // 進捗を進める(イベント消費 → 次の start_* を発行)。
        loop {
            let prev = comm.phase();
            let out = comm.drive(ctrl, now_ms(start), &mut tx);
            if out.phase != last_phase {
                report_phase(out.phase);
                last_phase = out.phase;
            }
            if let Some(dir) = out.send {
                send_dir_udp(socket, &tx, &dir);
            }
            match out.phase {
                Phase::Done { session } => {
                    println!(
                        "[commission] COMPLETE over UDP. operational CASE session = {:#x}",
                        session.as_raw()
                    );
                    // 最後の応答/ACK を流し切ってから返す。
                    settle_udp(ctrl, socket, start)?;
                    return Ok(session);
                }
                Phase::Failed { stage, reason } => {
                    return Err(format!(
                        "UDP commissioning failed at stage {stage}: {reason:?}"
                    ));
                }
                _ => {}
            }
            if out.send.is_none() && out.phase == prev {
                break;
            }
        }

        // 発行したトランザクションの応答を受け切り、standalone ACK も含めて静穏化させる。
        settle_udp(ctrl, socket, start)?;
    }
}

/// 確立済み CASE セッション上で OnOff Toggle を UDP 経由で送り、成功応答を待つ。
fn toggle_over_udp(
    ctrl: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
    session: SessionId,
) -> Result<(), String> {
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];

    let dir = ctrl
        .start_invoke(
            session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now_ms(start),
            &mut tx,
        )
        .map_err(|e| format!("start OnOff Toggle: {e:?}"))?;
    send_dir_udp(socket, &tx, &dir);
    println!("[onoff] sent Toggle command over CASE/UDP");

    let toggle_start = Instant::now();
    loop {
        if toggle_start.elapsed() > UDP_TIMEOUT {
            return Err("Toggle timed out".into());
        }
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(start);
                if let Some(dir) = ctrl.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx) {
                    send_dir_udp(socket, &tx, &dir);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv(toggle): {e}")),
        }
        let now = now_ms(start);
        while let Some(dir) = ctrl.poll(now, &mut tx) {
            send_dir_udp(socket, &tx, &dir);
        }
        if let Some(ev) = ctrl.im_take_event() {
            match ev {
                ImEvent::InvokeDone { status } if status.is_success() => {
                    println!("[onoff] Toggle acknowledged (status = Success)");
                    return Ok(());
                }
                other => return Err(format!("Toggle failed: {other:?}")),
            }
        }
    }
}

/// 応答を受け切り、MRP 再送・standalone ACK を含めて完全に静穏化するまでソケットを回す。
fn settle_udp(ctrl: &mut Ctrl<'_>, socket: &UdpSocket, start: &Instant) -> Result<(), String> {
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let settle_start = Instant::now();
    loop {
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(start);
                if let Some(dir) = ctrl.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx) {
                    send_dir_udp(socket, &tx, &dir);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv(settle): {e}")),
        }
        let now = now_ms(start);
        while let Some(dir) = ctrl.poll(now, &mut tx) {
            send_dir_udp(socket, &tx, &dir);
        }
        if ctrl.next_deadline(now_ms(start)).is_none() {
            return Ok(());
        }
        if settle_start.elapsed() > UDP_TIMEOUT {
            return Err("settle timed out (device unresponsive)".into());
        }
    }
}

/// 運用 mDNS で `<compressedFabricId>-<nodeId>._matter._tcp.local` を解決し、
/// デバイスの (アドレス, ポート) を返す。
///
/// chip の Minimal mDNS は 5353 を掴む(この開発機では avahi とも競合)ため、
/// **QU(unicast-response)ビット + エフェメラルポート**で応答を自ポートへのユニキャストで
/// 受ける(W3 の Windows 対応と同じ手法。RFC 6762 §5.4)。マルチキャスト announce も
/// 拾えるよう group join も行う。
fn resolve_operational(ca: &Ca<Backend>, node_id: u64) -> Result<SocketAddr, String> {
    let trace = std::env::var_os("SM_MDNS_TRACE").is_some();
    let compressed = ca.compressed_fabric_id_bytes();

    let (socket, qu) = open_mdns_query_socket().ok_or("open mDNS query socket failed")?;
    let mut query = [0u8; 128];
    let qlen = MdnsClient::build_resolve_operational(&mut query, &compressed, node_id, qu)
        .map_err(|e| format!("build_resolve_operational: {e:?}"))?;
    println!(
        "[handoff] resolving _matter._tcp for {}-{node_id:016X} (qu={qu})...",
        hex16(u64::from_be_bytes(compressed))
    );

    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < MDNS_RESOLVE_TIMEOUT {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
            last_query = Instant::now();
            if trace {
                eprintln!("[mdns-trace] operational query sent ({qlen}B, qu={qu})");
            }
        }
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let parsed = MdnsClient::parse_operational(&rx[..n], &compressed, node_id);
                if trace {
                    eprintln!(
                        "[mdns-trace] rx {n}B from {src} parse={}",
                        if parsed.is_some() {
                            "operational"
                        } else {
                            "no-match"
                        }
                    );
                }
                if let Some(node) = parsed {
                    // IPv4 を優先(dual-stack ソケットで扱いやすい)、無ければ最初のアドレス。
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
                        return Ok(SocketAddr::new(ip, port));
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("mDNS recv: {e}")),
        }
    }
    Err(format!(
        "operational node not resolved within {MDNS_RESOLVE_TIMEOUT:?}"
    ))
}

/// mDNS 解決用ソケット(エフェメラルポート + QU)。戻りの `bool` は QU モード(常に true)。
fn open_mdns_query_socket() -> Option<(UdpSocket, bool)> {
    let if_ip = default_route_local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_reuse_address(true).ok()?;
    // 送信 IF を LAN 向きに固定(仮想 IF が多い環境でクエリが LAN に出ないのを防ぐ)。
    let _ = socket.set_multicast_if_v4(&if_ip);
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    // マルチキャスト announce も拾えるよう group join(best effort)。
    let _ = socket.join_multicast_v4(&MDNS_IPV4, &if_ip);
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    Some((socket, true))
}

/// デフォルトルートのローカル IPv4 を推定する(外部宛 UDP の `local_addr` から。
/// 実際にはパケットを送らない)。マルチキャストの送信/join IF 固定用。
fn default_route_local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// デュアルスタック(v6only=false)の IPv6 UDP ソケットを任意ポートで開く。
/// chip は IPv6 のみ広告することがあるため、IPv4 宛は mapped アドレスで送る。
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
fn send_dir_udp(socket: &UdpSocket, tx: &[u8], dir: &SendDirective) {
    if let Some(addr) = dir.addr.socket_addr() {
        let _ = socket.send_to(&tx[..dir.len], map_to_v6(addr));
    }
}

/// `v` を 16 桁大文字 hex で表す(ログ用)。
fn hex16(v: u64) -> String {
    format!("{v:016X}")
}

/// `--operational`: PASE を飛ばし、保存済み CA の fabric で CASE のみを確立する
/// (`docs/design/port-esp32-device.md` §E4.6。`Commissioner` は使わない最小フロー)。
#[allow(clippy::too_many_arguments)]
async fn establish_case_only(
    gatt: &mut BtleplugCentral,
    btp: &mut Btp<6>,
    ctrl: &mut Ctrl<'_>,
    peer: PeerAddr,
    conn: BtpConnId,
    mtu: Option<u16>,
    start: &Instant,
    frag: &mut [u8; 512],
    txc: &mut [u8; MAX_RX_PACKET_SIZE],
) -> Result<SessionId, String> {
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;
    let now = now_ms(start);
    println!("[case] starting operational CASE (device node_id={DEVICE_NODE_ID:#018x})");
    let dir = ctrl
        .start_case(peer, CONTROLLER_FABRIC_INDEX, DEVICE_NODE_ID, now, txc)
        .map_err(|e| format!("start_case: {e:?}"))?;
    btp.send(&txc[..dir.len], now)
        .map_err(|e| format!("btp.send(sigma1): {e:?}"))?;
    flush_c1(gatt, btp, conn, mtu, now)
        .await
        .map_err(|e| format!("flush_c1(sigma1): {e:?}"))?;

    loop {
        if start.elapsed() > OVERALL_TIMEOUT {
            return Err("operational CASE timed out".into());
        }
        let now = now_ms(start);
        service_ctrl(gatt, btp, ctrl, peer, conn, mtu, now)
            .await
            .map_err(|e| format!("service_ctrl(case): {e:?}"))?;
        if let Some(ev) = ctrl.sc_take_event() {
            match ev {
                ScEvent::CaseEstablished { session, .. } => {
                    println!(
                        "[case] ESTABLISHED. operational CASE session = {:#x}",
                        session.as_raw()
                    );
                    return Ok(session);
                }
                other => return Err(format!("operational CASE failed: {other:?}")),
            }
        }
        let sleep = deadline_sleep(btp, now);
        tokio::select! {
            r = gatt.next_indication(conn, frag) => {
                let n = r.map_err(|e| format!("next_indication(case): {e:?}"))?;
                let now = now_ms(start);
                trace("rx", &frag[..n]);
                btp.process_incoming(&frag[..n], mtu, now)
                    .map_err(|e| format!("process_incoming(case): {e:?}"))?;
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(case-ack): {e:?}"))?;
            }
            _ = tokio::time::sleep(sleep) => {
                let now = now_ms(start);
                flush_c1(gatt, btp, conn, mtu, now)
                    .await
                    .map_err(|e| format!("flush_c1(case-timer): {e:?}"))?;
            }
        }
    }
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
        Phase::AddWifiNetwork => "AddOrUpdateWiFiNetwork",
        Phase::ConnectNetwork => "ConnectNetwork",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    println!("[phase] {name}");
}
