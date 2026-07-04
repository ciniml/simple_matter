//! BLE(BTP)+ UDP + mDNS を **併走**させる On/Off ライト(`device` feature)。
//!
//! `docs/design/ble-btp.md` §9.4 の「BLE→UDP 運用遷移」を実機で通すための dual-transport
//! example。sans-IO の [`MatterStack`] を **1 つ共有**し、3 つの I/O を 1 つの
//! `tokio::select` ループで駆動する:
//!
//! - **BLE(BTP)**: BlueZ バックエンド [`BluerPeripheral`] + BTP 状態機械 [`Btp<6>`]。
//!   chip-tool の `pairing ble-wifi` はまず BLE で PASE→ArmFailSafe→CSR→AddNOC→
//!   AddOrUpdateWiFiNetwork→ConnectNetwork まで通す。
//! - **UDP(運用トランスポート)**: `0.0.0.0:5540` の `UdpSocket`。CommissioningComplete は
//!   運用 CASE(UDP)上で行われるため、BLE と並行して立てる必要がある。
//! - **mDNS**: commissionable + operational 広告([`MdnsResponder`])。chip-tool は
//!   ConnectNetwork 後、operational ノードを mDNS で発見し CASE over UDP を張る。
//!
//! NetworkCommissioning は **Wi-Fi シミュレーション**版 [`NetworkCommissioningWifi`] を使う。
//! 実際には Wi-Fi に join しない(この PC は既に IP 到達可能)。chip-tool の
//! AutoCommissioner が BLE 経由 commissionee に Wi-Fi/Thread を要求するポリシを満たすためだけの
//! シムであり、AddOrUpdateWiFiNetwork / ConnectNetwork に即 Success を返す。
//!
//! # pump ループの構造(設計 doc §6.2 / §11-4)
//!
//! - 毎イテレーション **両 deadline(`stack.next_deadline` / `btp.next_deadline`)を min で
//!   待つ**が、UDP / mDNS をこまめに拾うため待ち時間は 20ms で上限クリップする。
//! - `stack.poll` は**毎イテレーション必須**(閉じた exchange を回収してプール枯渇を防ぐ)。
//!   返る [`SendDirective`] の `addr` を見て BLE / UDP へ振り分ける([`route_send`])。
//! - `indicate` は C2 subscribe 済みまで保留(BlueZ が subscribe 前 indicate をエラーにする)。
//!
//! 実行(BlueZ 稼働・権限は README 参照):
//! ```text
//! SM_BLE_ADAPTER=hci1 cargo run --release -p simple-matter-ble --features device --example ble-onoff-light
//! ```
//!
//! [`MatterStack`]: simple_matter::stack::MatterStack
//! [`Btp<6>`]: simple_matter::btp::Btp
//! [`SendDirective`]: simple_matter::stack::SendDirective

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_PORT,
};
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioningWifi, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::error::Result as MResult;
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SendDirective, SharedFabricCreds};
use simple_matter::transport::net::{BtpConnId, PeerAddr, MAX_RX_PACKET_SIZE};

use simple_matter_ble::bluer_peripheral::BluerPeripheral;

const PASSCODE: u32 = 20202021;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const NF: usize = 5;
/// コミッショニング discriminator(12 ビット)。UDP 版 `onoff-light` と同じ既定値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子(hostname / commissionable インスタンス名の素)。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_6677;

type Backend = RustCrypto<DemoRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

/// デモ用擬似乱数(UDP 版と同じ)。**暗号学的に安全ではない**。実機では OS/HW CSPRNG に差し替える。
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

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "SimpleMatter",
    vendor_id: 0xFFF1,
    product_name: "OnOffLight",
    product_id: 0x8001,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-ONOFF-0001",
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

struct Light<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioningWifi,
    opcreds: OpCreds<'s>,
    desc0: DescriptorCluster,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
}

impl DataModel for Light<'_> {
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

fn build_light(fabrics: &RefCell<FabricTable<Backend, NF>>) -> Light<'_> {
    let dac_crypto = RustCrypto::new(DemoRng::from_time());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioningWifi::new(),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

/// `SM_BTP_TRACE=1` でフラグメントの先頭バイト(flags/ack/seq)をトレースする。
fn trace(dir: &str, frag: &[u8]) {
    if std::env::var_os("SM_BTP_TRACE").is_some() {
        let h: Vec<String> = frag.iter().take(5).map(|b| format!("{b:02x}")).collect();
        eprintln!("[btp {dir}] len={} {}", frag.len(), h.join(" "));
    }
}

/// BTP が吐く下りフラグメントを尽きるまで C2 indication で送出する。
async fn flush_out(
    gatt: &mut BluerPeripheral,
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
        gatt.indicate(conn, &out[..n]).await?;
    }
    Ok(())
}

/// スタックの送信指示を宛先トランスポートへ振り分ける(BLE = BTP indicate、UDP = socket)。
///
/// `bytes` は `stack.handle_rx` / `stack.poll` が書いた `tx_out[..len]`。BLE 宛は BTP に載せて
/// (subscribe 済みなら)排出、UDP 宛はそのまま 1 datagram で送る。
#[allow(clippy::too_many_arguments)]
async fn route_send(
    d: SendDirective,
    bytes: &[u8],
    gatt: &mut BluerPeripheral,
    btp: &mut Btp<6>,
    mtu: Option<u16>,
    subscribed: bool,
    udp: &UdpSocket,
    now: u64,
) -> MResult<()> {
    match d.addr {
        PeerAddr::Udp(addr) => {
            let _ = udp.send_to(bytes, addr);
            Ok(())
        }
        PeerAddr::Ble(c) => {
            btp.send(bytes, now)?;
            if subscribed {
                flush_out(gatt, btp, c, mtu, now).await?;
            }
            Ok(())
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), String> {
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

    let config = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_light(&fabrics));
    let mut stack: DefaultStack<Backend, DemoRng, Light> = MatterStack::new(&crypto, sc, im);

    // --- UDP(運用トランスポート)---
    let udp = UdpSocket::bind(("0.0.0.0", MATTER_PORT)).map_err(|e| format!("udp bind: {e}"))?;
    udp.set_nonblocking(true)
        .map_err(|e| format!("udp nonblocking: {e}"))?;

    // --- mDNS ディスカバリ(commissionable + operational)---
    let local_ipv4 = discover_local_ipv4();
    let mac = MDNS_INSTANCE_ID.to_be_bytes();
    let host = Host::from_mac(&mac[2..8], None, Some(local_ipv4));
    let mut mdns: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
    mdns.set_commissionable(Some(Commissionable {
        device_type: Some(0x0100),
        device_name: Some(CFG.product_name),
        ..Commissionable::new(
            MDNS_INSTANCE_ID,
            DISCRIMINATOR,
            CFG.vendor_id,
            CFG.product_id,
            CommissioningMode::Standard,
        )
    }));
    let mdns_socket = open_mdns_socket();

    // --- BLE バックエンド + BTP(peripheral)---
    // SM_BLE_ADAPTER=hci1 等でアダプタを指定できる(2 アダプタ構成用)。未指定は default。
    let adapter_name = std::env::var("SM_BLE_ADAPTER").ok();
    let mut gatt = BluerPeripheral::with_adapter(adapter_name.as_deref())
        .await
        .map_err(|e| format!("BluerPeripheral::with_adapter: {e:?}"))?;
    println!("[ble] using adapter {}", gatt.adapter_name());

    let adv = AdvData {
        discriminator: DISCRIMINATOR,
        vendor_id: CFG.vendor_id,
        product_id: CFG.product_id,
        additional_data: false,
        ext_announcement: false,
    };
    gatt.start_advertising(&adv)
        .await
        .map_err(|e| format!("start_advertising: {e:?}"))?;

    let mut btp = Btp::<6>::new(BtpRole::Peripheral);
    let mut conn: Option<BtpConnId> = None;
    let mut mtu: Option<u16> = None;
    // chip-tool は handshake req の C1 write を C2 subscribe より先に行う。
    // subscribe 前の indicate は BlueZ がエラーにするため、subscribe 済みになるまで
    // 送出(flush_out)を保留する。
    let mut subscribed = false;

    println!("simple-matter BLE+UDP On/Off light (dual-transport)");
    println!("  passcode: {PASSCODE}  discriminator: {DISCRIMINATOR}");
    println!("  BLE: 0xFFF6 service data advertising  |  UDP: 0.0.0.0:{MATTER_PORT}");
    match &mdns_socket {
        Some(_) => println!("  mDNS advertising on 224.0.0.251:5353 (A record: {local_ipv4})"),
        None => println!("  (mDNS socket unavailable; operational discovery may not work.)"),
    }
    println!("  commission with: chip-tool pairing ble-wifi 1 <ssid> <pass> {PASSCODE} {DISCRIMINATOR} --ble-controller 0 --bypass-attestation-verifier true");

    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_RX_PACKET_SIZE];
    let mut udp_rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    let mut last_generation = fabrics.borrow().generation();

    loop {
        let now = now_ms(&start);
        // 設計 doc §6.2: 両 deadline を min で待つ。ただし UDP/mDNS をこまめに拾うため
        // 待ち時間は 20ms で上限クリップする(sans-IO なので駆動間隔は任意)。
        let dl = match (stack.next_deadline(now), btp.next_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        };
        let sleep = match dl {
            Some(t) if t > now => Duration::from_millis((t - now).min(20)),
            Some(_) => Duration::ZERO,
            None => Duration::from_millis(20),
        };

        tokio::select! {
            ev = gatt.next_event(&mut buf) => {
                let ev = ev.map_err(|e| format!("next_event: {e:?}"))?;
                let now = now_ms(&start);
                match ev {
                    PeripheralEvent::Connected { conn: c, att_mtu } => {
                        println!("[ble] connected: conn={} att_mtu={att_mtu:?}", c.0);
                        conn = Some(c);
                        mtu = att_mtu;
                        subscribed = false;
                        btp.reset();
                    }
                    PeripheralEvent::C2Subscribed { conn: c } => {
                        conn = Some(c);
                        subscribed = true;
                        flush_out(&mut gatt, &mut btp, c, mtu, now)
                            .await
                            .map_err(|e| format!("flush(subscribe): {e:?}"))?;
                    }
                    PeripheralEvent::C1Write { conn: c, len } => {
                        conn = Some(c);
                        trace("rx", &buf[..len]);
                        btp.process_incoming(&buf[..len], mtu, now)
                            .map_err(|e| format!("process_incoming: {e:?}"))?;
                        if subscribed {
                            flush_out(&mut gatt, &mut btp, c, mtu, now)
                                .await
                                .map_err(|e| format!("flush(c1): {e:?}"))?;
                        }
                        // 再組立できた Matter メッセージを stack へ渡し、応答を BTP に載せる。
                        while let Some(slen) = take_sdu(&mut btp, &mut sdu) {
                            let dir =
                                stack.handle_rx(&mut sdu[..slen], PeerAddr::Ble(c), now, &mut txd);
                            if let Some(d) = dir {
                                route_send(d, &txd[..d.len], &mut gatt, &mut btp, mtu, subscribed, &udp, now)
                                    .await
                                    .map_err(|e| format!("route_send(rx): {e:?}"))?;
                            }
                        }
                    }
                    PeripheralEvent::Disconnected { conn: c } => {
                        println!("[ble] disconnected: conn={}", c.0);
                        conn = None;
                        subscribed = false;
                        btp.reset();
                    }
                }
            }
            _ = tokio::time::sleep(sleep) => {
                let now = now_ms(&start);
                if let (Some(c), true) = (conn, subscribed) {
                    // BTP 自身の遅延 ACK / idle 送出を排出。
                    flush_out(&mut gatt, &mut btp, c, mtu, now)
                        .await
                        .map_err(|e| format!("flush(timer): {e:?}"))?;
                }
            }
        }

        // --- UDP 受信(運用トランスポート): 溜まっているだけ排出する ---
        loop {
            match udp.recv_from(&mut udp_rx) {
                Ok((n, src)) => {
                    let now = now_ms(&start);
                    let dir = stack.handle_rx(&mut udp_rx[..n], PeerAddr::Udp(src), now, &mut txd);
                    if let Some(d) = dir {
                        route_send(
                            d,
                            &txd[..d.len],
                            &mut gatt,
                            &mut btp,
                            mtu,
                            subscribed,
                            &udp,
                            now,
                        )
                        .await
                        .map_err(|e| format!("route_send(udp): {e:?}"))?;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    break
                }
                Err(_) => break,
            }
        }

        // --- 時間駆動の送出 + 閉じた exchange の回収(§11-4、毎イテレーション必須)---
        let now = now_ms(&start);
        while let Some(d) = stack.poll(now, &mut txd) {
            route_send(
                d,
                &txd[..d.len],
                &mut gatt,
                &mut btp,
                mtu,
                subscribed,
                &udp,
                now,
            )
            .await
            .map_err(|e| format!("route_send(poll): {e:?}"))?;
        }

        // --- fabric が増減したら operational 広告に反映して再 announce ---
        let gen = fabrics.borrow().generation();
        if gen != last_generation {
            last_generation = gen;
            let ops: Vec<Operational> = fabrics
                .borrow()
                .iter()
                .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id()))
                .collect();
            mdns.set_operational(ops);
            mdns.notify_change(now_ms(&start));
        }

        // --- mDNS の受信応答と announce ---
        if let Some(msock) = &mdns_socket {
            match msock.recv_from(&mut mdns_rx) {
                Ok((n, _src)) => {
                    if let Some(len) = mdns.handle_query(&mdns_rx[..n], &mut mdns_tx) {
                        let _ = msock.send_to(&mdns_tx[..len], (MDNS_IPV4, MDNS_PORT));
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(_) => {}
            }
            if let Some(len) = mdns.poll_announce(now_ms(&start), &mut mdns_tx) {
                let _ = msock.send_to(&mdns_tx[..len], (MDNS_IPV4, MDNS_PORT));
            }
        }
    }
}

/// mDNS 用 UDP ソケットを開き、224.0.0.251 のマルチキャストグループに参加する。
///
/// ポート 5353 を他プロセス(avahi 等)が使用中でも SO_REUSEADDR/SO_REUSEPORT で共存する。
/// 開けなければ `None` を返し、operational 発見が効かない旨を警告して継続する。
fn open_mdns_socket() -> Option<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_reuse_address(true).ok()?;
    socket.set_reuse_port(true).ok()?;
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    socket
        .join_multicast_v4(&MDNS_IPV4, &Ipv4Addr::UNSPECIFIED)
        .ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}

/// ローカルの IPv4 アドレスを推定する(外部宛 UDP ソケットの `local_addr` から)。
fn discover_local_ipv4() -> Ipv4Addr {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|s| {
            s.connect((Ipv4Addr::new(8, 8, 8, 8), 53))?;
            s.local_addr()
        })
        .ok()
        .and_then(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため)。
fn take_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}
