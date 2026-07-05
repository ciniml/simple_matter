//! std 上の On/Off ライトサンプル(ロードマップ第6段階前半)。
//!
//! `std::net::UdpSocket` で [`MatterStack`](simple_matter::stack::MatterStack) を駆動する
//! **ブロッキングループ**の最小例。sans-IO のコアはソケットに触れず、この example が
//! バイト列と時刻の受け渡し(受信 → `handle_rx`、期限 → `poll`)を担う。
//!
//! # 構成
//!
//! - EP0: Basic Information / General Commissioning / Network Commissioning /
//!   Operational Credentials / Descriptor
//! - EP1: On/Off / Descriptor
//! - パスコード 20202021 + テスト DAC([`TestDacProvider`])。On/Off 変化を `println!`。
//!
//! mDNS ディスカバリ(commissionable / operational 広告)を
//! [`MdnsResponder`](simple_matter::discovery::MdnsResponder) で駆動する。sans-IO の
//! レスポンダはソケットに触れず、この example が 224.0.0.251:5353 の送受信を担う
//! (`join_multicast_v4`)。コミッショニングで fabric が増えたら operational 広告に
//! 反映する。mDNS ソケットを開けない環境(既存の avahi 等)では警告して継続する。
//!
//! 実行: `cargo run --example onoff-light`

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_PORT,
};
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioning, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

const PASSCODE: u32 = 20202021;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const NF: usize = 5;

/// コミッショニング discriminator(12 ビット)。chip-tool の既定テスト値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子(hostname / commissionable インスタンス名の素)。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_6677;

type Backend = RustCrypto<DemoRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

/// デモ用の擬似乱数(SystemTime シードの LCG)。**暗号学的に安全ではない**。
///
/// 実機では OS/HW の CSPRNG を [`Rng`] に実装して差し替えること。ここでは依存追加を避け、
/// example が動く最小の乱数源にとどめる。
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

// --- デバイス構成(device! マクロは共有 OpCreds のライフタイムを扱えないため手書き)---

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
    net: NetworkCommissioning,
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
        net: NetworkCommissioning::new(b"eth0"),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        // On/Off 変化を println で通知する。
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

fn main() -> std::io::Result<()> {
    // 外部所有:crypto(SC/creds/stack が借用)と fabric テーブル(OpCreds/CASE が共有)。
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

    let config = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_light(&fabrics));
    let mut stack: DefaultStack<Backend, DemoRng, Light> = MatterStack::new(&crypto, sc, im);

    let socket = UdpSocket::bind("0.0.0.0:5540")?;
    socket.set_nonblocking(true)?;
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- mDNS ディスカバリ ---
    let local_ipv4 = discover_local_ipv4();
    let mac = MDNS_INSTANCE_ID.to_be_bytes(); // 下位 6 バイトをホスト名(MAC 相当)に使う
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

    println!("simple-matter On/Off light listening on UDP/5540");
    println!("  passcode: {PASSCODE}  discriminator: {DISCRIMINATOR}");
    match &mdns_socket {
        Some(_) => println!("  mDNS advertising on 224.0.0.251:5353 (A record: {local_ipv4})"),
        None => println!("  (mDNS socket unavailable; point a commissioner at this UDP port.)"),
    }

    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    // 直近に広告済みの fabric 世代(変化検知に使う)。
    let mut last_generation = fabrics.borrow().generation();

    loop {
        // 1) Matter UDP の受信処理。
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(&start);
                let dir = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx);
                if std::env::var_os("MATTER_DEBUG").is_some() {
                    eprintln!(
                        "[rx] {n}B from {src} -> {}",
                        match &dir {
                            Some(d) => format!("respond {}B", d.len),
                            None => "no response".into(),
                        }
                    );
                }
                if let Some(dir) = dir {
                    if let Some(addr) = dir.addr.socket_addr() {
                        let _ = socket.send_to(&tx[..dir.len], addr);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        // 2) 時間駆動の送出(MRP 再送・standalone ACK・購読レポート)を排出する。
        let now = now_ms(&start);
        while let Some(dir) = stack.poll(now, &mut tx) {
            if let Some(addr) = dir.addr.socket_addr() {
                let _ = socket.send_to(&tx[..dir.len], addr);
            }
        }

        // 3) fabric が増減したら operational 広告に反映して再 announce。
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

        // 4) mDNS の受信応答と announce。
        if let Some(msock) = &mdns_socket {
            match msock.recv_from(&mut mdns_rx) {
                Ok((n, src)) => {
                    // QU(unicast-response)クエリには送信元へユニキャストで返す
                    // (5353 を共有できない querier 対策。RFC 6762 §5.4)。それ以外は
                    // 従来どおりマルチキャスト。
                    let qu = mdns.query_wants_unicast(&mdns_rx[..n]);
                    if let Some(len) = mdns.handle_query(&mdns_rx[..n], &mut mdns_tx) {
                        let dst = if qu {
                            src
                        } else {
                            (MDNS_IPV4, MDNS_PORT).into()
                        };
                        let _ = msock.send_to(&mdns_tx[..len], dst);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(_) => {}
            }
            if let Some(len) = mdns.poll_announce(now_ms(&start), &mut mdns_tx) {
                let _ = msock.send_to(&mdns_tx[..len], (MDNS_IPV4, MDNS_PORT));
            }
        }

        // ビジーループ回避のため短くスリープする(sans-IO なので駆動間隔は任意)。
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// mDNS 用 UDP ソケットを開き、224.0.0.251 のマルチキャストグループに参加する。
///
/// ポート 5353 を他プロセス(avahi 等)が使用中なら `None` を返し、example は mDNS
/// 無しで継続する。
fn open_mdns_socket() -> Option<UdpSocket> {
    // avahi 等の既存 mDNS レスポンダと共存するため SO_REUSEADDR/SO_REUSEPORT を
    // 立ててから 5353 に bind する(std の UdpSocket では bind 前に設定できないため
    // socket2 を使う)。マルチキャストグループ参加で 224.0.0.251 宛のクエリが
    // 両方のソケットに配送される。
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    // SO_REUSEADDR のみ。SO_REUSEPORT はマルチキャストを listener 間で **ロードバランス**
    // (=1 つに振り分けて他が取りこぼす)ため、avahi 等と共存すると受信クエリを奪われる。
    // REUSEADDR だけなら同一マルチキャストポートへの複数 bind が許され、全 listener が
    // 全マルチキャストを受信する(mDNS の定石)。
    socket.set_reuse_address(true).ok()?;
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
///
/// 実際にはパケットを送らない。取得できない場合はループバックを返す。
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
