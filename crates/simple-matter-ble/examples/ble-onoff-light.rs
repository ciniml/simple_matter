//! BLE(BTP)版 On/Off ライト(`device` feature、`docs/design/ble-btp.md` §6.2 / §9.2)。
//!
//! 既存の UDP 版 `simple-matter/examples/onoff-light.rs` の BLE 版。sans-IO の
//! [`MatterStack`] を、BTP 状態機械 [`Btp<6>`](Peripheral)と BlueZ バックエンド
//! [`BluerPeripheral`] に配線する。統合(pump)ループは設計 doc §6.2 の形:
//! **毎イテレーション両 deadline(`stack.next_deadline` / `btp.next_deadline`)を min で
//! 待ち、`stack.poll` を呼ぶ**(閉じた exchange を回収してプール枯渇を防ぐ、§11-4)。
//!
//! コミッショニング完了後も動き続け、On/Off の変化を stdout に表示する。
//!
//! # スコープ(設計 doc §9.4 からの逸脱)
//!
//! 本 example は **BLE のみ**。UDP スタック併走(BLE→UDP 運用遷移の可視化)は配線量が
//! 大きいため初期スコープ外とし、UDP 運用は既存 `onoff-light` に委ねる。BLE で
//! PASE→CASE→CommissioningComplete→On/Off までを実 BLE 上で通すことを目的とする。
//!
//! 実行(BlueZ 稼働・権限は README 参照):
//! ```text
//! cargo run -p simple-matter-ble --features device --example ble-onoff-light
//! ```
//!
//! [`MatterStack`]: simple_matter::stack::MatterStack
//! [`Btp<6>`]: simple_matter::btp::Btp

use std::cell::RefCell;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioning, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::error::Result as MResult;
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::transport::net::{BtpConnId, PeerAddr, MAX_RX_PACKET_SIZE};

use simple_matter_ble::bluer_peripheral::BluerPeripheral;

const PASSCODE: u32 = 20202021;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const NF: usize = 5;
/// コミッショニング discriminator(12 ビット)。UDP 版 `onoff-light` と同じ既定値。
const DISCRIMINATOR: u16 = 3840;

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), String> {
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

    let config = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_light(&fabrics));
    let mut stack: DefaultStack<Backend, DemoRng, Light> = MatterStack::new(&crypto, sc, im);

    // --- BLE バックエンド + BTP(peripheral)---
    // SM_BLE_ADAPTER=hci0 等でアダプタを指定できる(2 アダプタ構成用)。未指定は default。
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

    println!("simple-matter BLE On/Off light advertising (0xFFF6 service data)");
    println!("  passcode: {PASSCODE}  discriminator: {DISCRIMINATOR}");
    println!("  commission with: cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- {PASSCODE} {DISCRIMINATOR}");

    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_RX_PACKET_SIZE];

    loop {
        let now = now_ms(&start);
        // 設計 doc §6.2: 両 deadline を min で待つ。どちらも無ければ 1s の緩いポーリング。
        let dl = match (stack.next_deadline(now), btp.next_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        };
        let sleep = match dl {
            Some(t) if t > now => Duration::from_millis(t - now),
            Some(_) => Duration::ZERO,
            None => Duration::from_millis(1000),
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
                        btp.reset();
                    }
                    PeripheralEvent::C2Subscribed { conn: c } => {
                        conn = Some(c);
                        // handshake resp / 保留中フラグメントを排出。
                        flush_out(&mut gatt, &mut btp, c, mtu, now)
                            .await
                            .map_err(|e| format!("flush(subscribe): {e:?}"))?;
                    }
                    PeripheralEvent::C1Write { conn: c, len } => {
                        conn = Some(c);
                        trace("rx", &buf[..len]);
                        btp.process_incoming(&buf[..len], mtu, now)
                            .map_err(|e| format!("process_incoming: {e:?}"))?;
                        flush_out(&mut gatt, &mut btp, c, mtu, now)
                            .await
                            .map_err(|e| format!("flush(c1): {e:?}"))?;
                        // 再組立できた Matter メッセージを stack へ渡し、応答を BTP に載せる。
                        while let Some(slen) = take_sdu(&mut btp, &mut sdu) {
                            let dir =
                                stack.handle_rx(&mut sdu[..slen], PeerAddr::Ble(c), now, &mut txd);
                            if let Some(d) = dir {
                                btp.send(&txd[..d.len], now)
                                    .map_err(|e| format!("btp.send: {e:?}"))?;
                            }
                            flush_out(&mut gatt, &mut btp, c, mtu, now)
                                .await
                                .map_err(|e| format!("flush(rx): {e:?}"))?;
                        }
                    }
                    PeripheralEvent::Disconnected { conn: c } => {
                        println!("[ble] disconnected: conn={}", c.0);
                        conn = None;
                        btp.reset();
                    }
                }
            }
            _ = tokio::time::sleep(sleep) => {
                let now = now_ms(&start);
                if let Some(c) = conn {
                    // BTP 自身の遅延 ACK / idle 送出を排出。
                    flush_out(&mut gatt, &mut btp, c, mtu, now)
                        .await
                        .map_err(|e| format!("flush(timer): {e:?}"))?;
                }
            }
        }

        // 時間駆動の送出(購読レポート等)と、閉じた exchange の回収(§11-4)。
        // sleep 分岐だけでなく**毎イテレーション**回す。コミッショニング中は GATT
        // イベントが連続して sleep 分岐に落ちないため、ここで回収しないと
        // exchange プールが枯渇し AddNOC 以降が NoSpace で黙って落ちる(実 BLE で実証)。
        let now = now_ms(&start);
        while let Some(d) = stack.poll(now, &mut txd) {
            if let Some(c) = conn {
                btp.send(&txd[..d.len], now)
                    .map_err(|e| format!("btp.send(poll): {e:?}"))?;
                flush_out(&mut gatt, &mut btp, c, mtu, now)
                    .await
                    .map_err(|e| format!("flush(poll): {e:?}"))?;
            }
        }
    }
}

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため)。
fn take_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}
