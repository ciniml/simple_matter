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
//! mDNS(コミッショナブル/オペレーショナル広告)は本ピースのスコープ外(次ピース)。
//! 動作確認はテストクライアント(`stack::tests` のメモリ内縦通し)で行う。実機では
//! `UDP/5540` に手動でコミッショナを向ける、または mDNS ピースの追加後に自動発見する。
//!
//! 実行: `cargo run --example onoff-light`

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
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
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    println!("simple-matter On/Off light listening on UDP/5540");
    println!("  passcode: {PASSCODE}");
    println!("  (mDNS discovery is out of scope; point a commissioner at this UDP port.)");

    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];

    loop {
        // 次に処理すべき期限まで recv をブロックする(なければ 1 秒でタイムアウト)。
        let now = now_ms(&start);
        let timeout = match stack.next_deadline(now) {
            Some(d) => Duration::from_millis(d.saturating_sub(now).max(1)),
            None => Duration::from_secs(1),
        };
        socket.set_read_timeout(Some(timeout))?;

        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let peer = PeerAddr::Udp(src);
                let now = now_ms(&start);
                if let Some(dir) = stack.handle_rx(&mut rx[..n], peer, now, &mut tx) {
                    if let Some(addr) = dir.addr.socket_addr() {
                        let _ = socket.send_to(&tx[..dir.len], addr);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        // 時間駆動の送出(MRP 再送・standalone ACK・購読レポート)を排出する。
        let now = now_ms(&start);
        while let Some(dir) = stack.poll(now, &mut tx) {
            if let Some(addr) = dir.addr.socket_addr() {
                let _ = socket.send_to(&tx[..dir.len], addr);
            }
        }
    }
}
