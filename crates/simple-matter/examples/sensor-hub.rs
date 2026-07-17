//! std 上のマルチ EP センサハブサンプル(`docs/design/basic-clusters.md` §1.5)。
//!
//! [`thermostat`](../thermostat.rs) をベースに、EP1-7 に 7 種のセンサデバイスタイプを載せて
//! Identify + 各センサクラスタ + Descriptor を手書き [`DataModel`] で構成する(共有 OpCreds の
//! ライフタイムのため `device!` マクロは使えない)。擬似センサを `on_tick`(約 1 秒周期)で駆動する。
//!
//! # 構成(EP メタは各 EP のコメント参照。Device Library の必須/実装済み/省略を明記)
//!
//! - EP0: Root Node(0x0016)。既存 7 種(BasicInformation / GeneralCommissioning /
//!   NetworkCommissioning / OperationalCredentials / AccessControl / AdminCommissioning /
//!   Descriptor)。
//! - EP1: Temperature Sensor(0x0302)/ EP2: Humidity Sensor(0x0307)/
//!   EP3: Contact Sensor(0x0015)/ EP4: Occupancy Sensor(0x0107)/
//!   EP5: Light Sensor(0x0106)/ EP6: Pressure Sensor(0x0305)/ EP7: Flow Sensor(0x0306)。
//! - EP8: Fan(0x002B、Identify+FanControl+Descriptor。必須 Groups は省略)/
//!   EP9: Window Covering(0x0202、Identify+WindowCovering+Descriptor)。ファン/窓は
//!   コマンド駆動 + tick のためシム不要(設計 §2.4)。
//!
//! # 擬似センサ(設計 §1.5)
//!
//! - 温度 2150±100 / 湿度 5000±500 / 照度 30000±1000 / 気圧 1013±20 / 流量 100±50 を三角波で揺らす。
//! - 接点は 15 秒ごとにトグルし、StateChange イベントを pending に積む(main loop が
//!   [`take_state_change`](simple_matter::dm::clusters::BooleanStateCluster::take_state_change) で
//!   回収して `stack.post_event` する)。在室は 20 秒ごとにトグル。
//!
//! 実行: `cargo run --example sensor-hub`

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::acl::{AclHandle, AclTable};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_IPV6, MDNS_PORT,
};
use simple_matter::dm::clusters::{
    AccessControlCluster, AdminCommissioningCluster, BasicInfoConfig, BasicInformationCluster,
    BooleanStateCluster, CommissioningWindow, DescriptorCluster, FanControlCluster,
    FlowMeasurementCluster, GeneralCommissioning, IdentifyCluster, IlluminanceMeasurementCluster,
    NetworkCommissioning, OccupancySensingCluster, OpCredsCluster, PressureMeasurementCluster,
    RelativeHumidityMeasurementCluster, TemperatureMeasurementCluster, TestDacProvider,
    WindowCoveringCluster, WindowEvent,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta, EventId};
use simple_matter::dm::{tick_clusters, DataModel, ServerCluster};
use simple_matter::error::{Error, Result as SmResult};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::im::events::PRIORITY_INFO;
use simple_matter::kvs::Kvs;
use simple_matter::sc::SecureChannel;

#[path = "common/pase.rs"]
mod common_pase;
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::tlv::TlvTag;
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;

/// コミッショニング discriminator(12 ビット)。chip-tool の既定テスト値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子。他 example と別値にして同一ホスト併走時の衝突を避ける(設計 §1.5)。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_66CC;
/// mDNS 広告用のデバイスタイプ ID(先頭機能 EP = Temperature Sensor)。
const DEVICE_TYPE_SENSOR: u32 = 0x0302;

/// 擬似センサの駆動周期(ms)。設計 §1.5: 約 1 秒ごとに更新。
const SENSOR_PERIOD_MS: u64 = 1_000;

type Backend = RustCrypto<DemoRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

/// デモ用の擬似乱数(SystemTime シードの LCG)。**暗号学的に安全ではない**。
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

/// std のファイルベース [`Kvs`](環境変数 `SM_STATE_DIR` が指すディレクトリ)。
struct FileKvs {
    dir: PathBuf,
}

impl FileKvs {
    fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
    fn path(&self, key: &[u8]) -> PathBuf {
        let mut name = String::with_capacity(key.len() * 2 + 4);
        for b in key {
            name.push_str(&format!("{b:02x}"));
        }
        name.push_str(".bin");
        self.dir.join(name)
    }
}

impl Kvs for FileKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> SmResult<Option<usize>> {
        match std::fs::read(self.path(key)) {
            Ok(bytes) => {
                if buf.len() < bytes.len() {
                    return Err(Error::NoSpace);
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::InvalidState),
        }
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> SmResult<()> {
        std::fs::write(self.path(key), value).map_err(|_| Error::InvalidState)
    }
    fn remove(&mut self, key: &[u8]) -> SmResult<()> {
        match std::fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::InvalidState),
        }
    }
}

// --- デバイス構成(device! マクロは共有 OpCreds のライフタイムを扱えないため手書き)---

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "SimpleMatter",
    vendor_id: 0xFFF1,
    product_name: "SensorHub",
    product_id: 0x8004,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-SENSOR-0004",
};

// EP0 = Root Node(0x0016)。既存 7 種(必須すべて実装済み)。
static EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x001F),
    ClusterId(0x0028),
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003C),
    ClusterId(0x003E),
    ClusterId(0x001D),
];
// EP1 = Temperature Sensor(0x0302、rev 2)。
//   必須: Identify(実装済み)/ TemperatureMeasurement(実装済み)/ Descriptor(実装済み)。
//   省略: なし(Device Library の Temperature Sensor は Groups/Scenes を必須にしない)。
static EP1_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0402)];
// EP2 = Humidity Sensor(0x0307、rev 2)。必須: Identify / RelativeHumidity / Descriptor(実装済み)。
static EP2_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0405)];
// EP3 = Contact Sensor(0x0015、rev 1)。必須: Identify / BooleanState / Descriptor(実装済み)。
static EP3_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0045)];
// EP4 = Occupancy Sensor(0x0107、rev 3)。必須: Identify / OccupancySensing / Descriptor(実装済み)。
static EP4_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0406)];
// EP5 = Light Sensor(0x0106、rev 2)。必須: Identify / IlluminanceMeasurement / Descriptor(実装済み)。
static EP5_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0400)];
// EP6 = Pressure Sensor(0x0305、rev 2)。必須: Identify / PressureMeasurement / Descriptor(実装済み)。
static EP6_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0403)];
// EP7 = Flow Sensor(0x0306、rev 2)。必須: Identify / FlowMeasurement / Descriptor(実装済み)。
static EP7_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0404)];
// EP8 = Fan(0x002B、rev 2)。必須: Identify / Groups / FanControl / Descriptor。
//   実装済み: Identify(0x0003)/ FanControl(0x0202)/ Descriptor(0x001D)。
//   省略: Groups(0x0004)= Group messaging 自体がスコープ外(設計 §0-5)。
static EP8_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0202)];
// EP9 = Window Covering(0x0202、rev 2)。必須: Identify / WindowCovering / Descriptor(実装済み)。
static EP9_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0102)];

static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0302, 2)];
static EP2_DT: &[DeviceType] = &[DeviceType::new(0x0307, 2)];
static EP3_DT: &[DeviceType] = &[DeviceType::new(0x0015, 1)];
static EP4_DT: &[DeviceType] = &[DeviceType::new(0x0107, 3)];
static EP5_DT: &[DeviceType] = &[DeviceType::new(0x0106, 2)];
static EP6_DT: &[DeviceType] = &[DeviceType::new(0x0305, 2)];
static EP7_DT: &[DeviceType] = &[DeviceType::new(0x0306, 2)];
static EP8_DT: &[DeviceType] = &[DeviceType::new(0x002B, 2)];
static EP9_DT: &[DeviceType] = &[DeviceType::new(0x0202, 2)];

// Root(EP0)の子エンドポイントは EP1-9。機能 EP は子を持たない。
static EP0_PARTS: &[EndpointId] = &[
    EndpointId(1),
    EndpointId(2),
    EndpointId(3),
    EndpointId(4),
    EndpointId(5),
    EndpointId(6),
    EndpointId(7),
    EndpointId(8),
    EndpointId(9),
];
static NO_PARTS: &[EndpointId] = &[];

/// 三角波(base±amp、`step` 刻み)。周期は `4*amp/step` tick(設計 §1.5)。
fn triangle(ticks: u64, base: i32, amp: i32, step: i32) -> i32 {
    if amp <= 0 || step <= 0 {
        return base;
    }
    let period = (4 * amp / step) as u64;
    // 0..4*amp のこぎり位置。
    let p = ((ticks % period) as i32) * step;
    if p <= 2 * amp {
        base - amp + p
    } else {
        base + amp - (p - 2 * amp)
    }
}

struct SensorHub<'s> {
    acl: &'s RefCell<AclTable<NACL>>,
    access_control: AccessControlCluster<'s, NACL>,
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    admin: AdminCommissioningCluster<'s>,
    opcreds: OpCreds<'s>,
    desc0: DescriptorCluster,
    // EP1-7 の Identify(各 EP 独立の IdentifyTime を持つ)。
    identify1: IdentifyCluster,
    identify2: IdentifyCluster,
    identify3: IdentifyCluster,
    identify4: IdentifyCluster,
    identify5: IdentifyCluster,
    identify6: IdentifyCluster,
    identify7: IdentifyCluster,
    identify8: IdentifyCluster,
    identify9: IdentifyCluster,
    // 各センサクラスタ。
    temp: TemperatureMeasurementCluster,
    humidity: RelativeHumidityMeasurementCluster,
    contact: BooleanStateCluster,
    occupancy: OccupancySensingCluster,
    illuminance: IlluminanceMeasurementCluster,
    pressure: PressureMeasurementCluster,
    flow: FlowMeasurementCluster,
    // EP8 = Fan Control、EP9 = Window Covering(コマンド駆動 + tick)。
    fan: FanControlCluster,
    window_covering: WindowCoveringCluster,
    // 機能 EP の Descriptor。
    desc1: DescriptorCluster,
    desc2: DescriptorCluster,
    desc3: DescriptorCluster,
    desc4: DescriptorCluster,
    desc5: DescriptorCluster,
    desc6: DescriptorCluster,
    desc7: DescriptorCluster,
    desc8: DescriptorCluster,
    desc9: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    removed_fabric: Option<core::num::NonZeroU8>,
    /// 擬似センサの経過 tick(約 1 秒ごとに 1 増える)。
    sensor_ticks: u64,
    /// 擬似センサを最後に進めた時刻(ms)。
    last_sensor_ms: u64,
}

impl SensorHub<'_> {
    /// 擬似センサを 1 ステップ進める(設計 §1.5)。
    fn step_sensors(&mut self) {
        let t = self.sensor_ticks;
        self.temp
            .set_measured(Some(triangle(t, 2150, 100, 10) as i16));
        self.humidity
            .set_measured(Some(triangle(t, 5000, 500, 50) as u16));
        self.illuminance
            .set_measured(Some(triangle(t, 30000, 1000, 100) as u16));
        self.pressure
            .set_measured(Some(triangle(t, 1013, 20, 2) as i16));
        self.flow.set_measured(Some(triangle(t, 100, 50, 5) as u16));
        // 接点は 15 秒ごとにトグル(StateChange イベントは main loop が post する)。
        self.contact.set_state((t / 15) % 2 == 1);
        // 在室は 20 秒ごとにトグル。
        self.occupancy.set_occupied((t / 20) % 2 == 1);
        self.sensor_ticks = self.sensor_ticks.wrapping_add(1);
    }
}

impl DataModel for SensorHub<'_> {
    fn endpoints(&self) -> &[EndpointMeta] {
        static EPS: &[EndpointMeta] = &[
            EndpointMeta::new(EndpointId(0), EP0_DT, EP0_SERVERS),
            EndpointMeta::new(EndpointId(1), EP1_DT, EP1_SERVERS),
            EndpointMeta::new(EndpointId(2), EP2_DT, EP2_SERVERS),
            EndpointMeta::new(EndpointId(3), EP3_DT, EP3_SERVERS),
            EndpointMeta::new(EndpointId(4), EP4_DT, EP4_SERVERS),
            EndpointMeta::new(EndpointId(5), EP5_DT, EP5_SERVERS),
            EndpointMeta::new(EndpointId(6), EP6_DT, EP6_SERVERS),
            EndpointMeta::new(EndpointId(7), EP7_DT, EP7_SERVERS),
            EndpointMeta::new(EndpointId(8), EP8_DT, EP8_SERVERS),
            EndpointMeta::new(EndpointId(9), EP9_DT, EP9_SERVERS),
        ];
        EPS
    }
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        match ep.0 {
            0 => EP0_SERVERS,
            1 => EP1_SERVERS,
            2 => EP2_SERVERS,
            3 => EP3_SERVERS,
            4 => EP4_SERVERS,
            5 => EP5_SERVERS,
            6 => EP6_SERVERS,
            7 => EP7_SERVERS,
            8 => EP8_SERVERS,
            9 => EP9_SERVERS,
            _ => &[],
        }
    }
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x001F) => Some(&self.access_control),
            (0, 0x0028) => Some(&self.basic),
            (0, 0x0030) => Some(&self.gc),
            (0, 0x0031) => Some(&self.net),
            (0, 0x003C) => Some(&self.admin),
            (0, 0x003E) => Some(&self.opcreds),
            (0, 0x001D) => Some(&self.desc0),
            (1, 0x0003) => Some(&self.identify1),
            (1, 0x0402) => Some(&self.temp),
            (1, 0x001D) => Some(&self.desc1),
            (2, 0x0003) => Some(&self.identify2),
            (2, 0x0405) => Some(&self.humidity),
            (2, 0x001D) => Some(&self.desc2),
            (3, 0x0003) => Some(&self.identify3),
            (3, 0x0045) => Some(&self.contact),
            (3, 0x001D) => Some(&self.desc3),
            (4, 0x0003) => Some(&self.identify4),
            (4, 0x0406) => Some(&self.occupancy),
            (4, 0x001D) => Some(&self.desc4),
            (5, 0x0003) => Some(&self.identify5),
            (5, 0x0400) => Some(&self.illuminance),
            (5, 0x001D) => Some(&self.desc5),
            (6, 0x0003) => Some(&self.identify6),
            (6, 0x0403) => Some(&self.pressure),
            (6, 0x001D) => Some(&self.desc6),
            (7, 0x0003) => Some(&self.identify7),
            (7, 0x0404) => Some(&self.flow),
            (7, 0x001D) => Some(&self.desc7),
            (8, 0x0003) => Some(&self.identify8),
            (8, 0x0202) => Some(&self.fan),
            (8, 0x001D) => Some(&self.desc8),
            (9, 0x0003) => Some(&self.identify9),
            (9, 0x0102) => Some(&self.window_covering),
            (9, 0x001D) => Some(&self.desc9),
            _ => None,
        }
    }
    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x001F) => Some(&mut self.access_control),
            (0, 0x0028) => Some(&mut self.basic),
            (0, 0x0030) => Some(&mut self.gc),
            (0, 0x0031) => Some(&mut self.net),
            (0, 0x003C) => Some(&mut self.admin),
            (0, 0x003E) => Some(&mut self.opcreds),
            (0, 0x001D) => Some(&mut self.desc0),
            (1, 0x0003) => Some(&mut self.identify1),
            (1, 0x0402) => Some(&mut self.temp),
            (1, 0x001D) => Some(&mut self.desc1),
            (2, 0x0003) => Some(&mut self.identify2),
            (2, 0x0405) => Some(&mut self.humidity),
            (2, 0x001D) => Some(&mut self.desc2),
            (3, 0x0003) => Some(&mut self.identify3),
            (3, 0x0045) => Some(&mut self.contact),
            (3, 0x001D) => Some(&mut self.desc3),
            (4, 0x0003) => Some(&mut self.identify4),
            (4, 0x0406) => Some(&mut self.occupancy),
            (4, 0x001D) => Some(&mut self.desc4),
            (5, 0x0003) => Some(&mut self.identify5),
            (5, 0x0400) => Some(&mut self.illuminance),
            (5, 0x001D) => Some(&mut self.desc5),
            (6, 0x0003) => Some(&mut self.identify6),
            (6, 0x0403) => Some(&mut self.pressure),
            (6, 0x001D) => Some(&mut self.desc6),
            (7, 0x0003) => Some(&mut self.identify7),
            (7, 0x0404) => Some(&mut self.flow),
            (7, 0x001D) => Some(&mut self.desc7),
            (8, 0x0003) => Some(&mut self.identify8),
            (8, 0x0202) => Some(&mut self.fan),
            (8, 0x001D) => Some(&mut self.desc8),
            (9, 0x0003) => Some(&mut self.identify9),
            (9, 0x0102) => Some(&mut self.window_covering),
            (9, 0x001D) => Some(&mut self.desc9),
            _ => None,
        }
    }
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.gc.on_tick(now_ms) {
            // fail-safe 期限切れ: pending 破棄 + 未 CommissioningComplete の fabric 巻き戻し。
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        // コミッショニング窓のタイムアウト自動クローズ(admin-commissioning.md §2)。
        let _ = self.admin.on_tick(now_ms);
        // クラスタ tick(Identify の IdentifyTime 減衰)を回す(設計 §1.1/§15.1)。
        let next = tick_clusters(self, now_ms);
        // 擬似センサ: 約 1 秒周期で各センサ値を更新する(設計 §1.5)。
        if now_ms.saturating_sub(self.last_sensor_ms) >= SENSOR_PERIOD_MS {
            self.last_sensor_ms = now_ms;
            self.step_sensors();
        }
        next
    }
    fn on_failsafe_cleanup(&mut self) -> Option<core::num::NonZeroU8> {
        self.gc.disarm();
        self.opcreds.on_failsafe_expired()
    }
    fn on_commissioning_complete(&mut self) {
        self.opcreds.on_commissioning_complete();
    }
    fn take_removed_fabric(&mut self) -> Option<core::num::NonZeroU8> {
        self.removed_fabric.take()
    }
    fn acl(&self) -> Option<&dyn AclHandle> {
        Some(self.acl)
    }
}

fn build_sensor_hub<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    acl: &'s RefCell<AclTable<NACL>>,
    window: &'s RefCell<CommissioningWindow>,
) -> SensorHub<'s> {
    let dac_crypto = RustCrypto::new(DemoRng::from_time());
    let dac = if std::env::var_os("SM_TAMPER_CD").is_some() {
        eprintln!("[dac] SM_TAMPER_CD set: serving a tampered Certification Declaration");
        TestDacProvider::new_with_tampered_cd(&dac_crypto).expect("test DAC")
    } else {
        TestDacProvider::new(&dac_crypto).expect("test DAC")
    };
    SensorHub {
        acl,
        access_control: AccessControlCluster::new(acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        // 各 EP の Identify: 識別中/終了を println で通知する(EP 番号付き)。
        identify1: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP1 {}", ident_state(on))),
        identify2: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP2 {}", ident_state(on))),
        identify3: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP3 {}", ident_state(on))),
        identify4: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP4 {}", ident_state(on))),
        identify5: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP5 {}", ident_state(on))),
        identify6: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP6 {}", ident_state(on))),
        identify7: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP7 {}", ident_state(on))),
        identify8: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP8 {}", ident_state(on))),
        identify9: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP9 {}", ident_state(on))),
        temp: TemperatureMeasurementCluster::new(Some(-4000), Some(12500)),
        humidity: RelativeHumidityMeasurementCluster::new(Some(0), Some(10000)),
        contact: BooleanStateCluster::new(),
        occupancy: OccupancySensingCluster::new(),
        illuminance: IlluminanceMeasurementCluster::new(Some(1), Some(0xFFFE)),
        pressure: PressureMeasurementCluster::new(Some(0), Some(10000)),
        flow: FlowMeasurementCluster::new(Some(0), Some(0xFFFE)),
        fan: FanControlCluster::new()
            .with_listener(|pct| println!("[fan] EP8 PercentCurrent={pct}%")),
        window_covering: WindowCoveringCluster::new()
            .with_listener(|pos| println!("[window] EP9 CurrentLift={pos} (100ths)")),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], NO_PARTS),
        desc2: DescriptorCluster::new(EndpointId(2), EP2_DT, EP2_SERVERS, &[], NO_PARTS),
        desc3: DescriptorCluster::new(EndpointId(3), EP3_DT, EP3_SERVERS, &[], NO_PARTS),
        desc4: DescriptorCluster::new(EndpointId(4), EP4_DT, EP4_SERVERS, &[], NO_PARTS),
        desc5: DescriptorCluster::new(EndpointId(5), EP5_DT, EP5_SERVERS, &[], NO_PARTS),
        desc6: DescriptorCluster::new(EndpointId(6), EP6_DT, EP6_SERVERS, &[], NO_PARTS),
        desc7: DescriptorCluster::new(EndpointId(7), EP7_DT, EP7_SERVERS, &[], NO_PARTS),
        desc8: DescriptorCluster::new(EndpointId(8), EP8_DT, EP8_SERVERS, &[], NO_PARTS),
        desc9: DescriptorCluster::new(EndpointId(9), EP9_DT, EP9_SERVERS, &[], NO_PARTS),
        removed_fabric: None,
        sensor_ticks: 0,
        last_sensor_ms: 0,
    }
}

/// Identify リスナのメッセージ断片。
fn ident_state(on: bool) -> &'static str {
    if on {
        "identifying"
    } else {
        "stopped"
    }
}

fn main() -> std::io::Result<()> {
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());
    let acl: RefCell<AclTable<NACL>> = RefCell::new(AclTable::new());
    let window: RefCell<CommissioningWindow> = RefCell::new(CommissioningWindow::new());

    let config = common_pase::config();
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_sensor_hub(&fabrics, &acl, &window));
    let mut stack: DefaultStack<Backend, DemoRng, SensorHub> = MatterStack::new(&crypto, sc, im);

    let _ = stack.post_startup_event(CFG.software_version, 0);

    let mut kvs: Option<FileKvs> = match std::env::var_os("SM_STATE_DIR") {
        Some(dir) => match FileKvs::new(PathBuf::from(&dir)) {
            Ok(k) => {
                println!(
                    "[kvs] persistence enabled at {}",
                    PathBuf::from(&dir).display()
                );
                Some(k)
            }
            Err(e) => {
                println!("[kvs] cannot open SM_STATE_DIR ({e}); running in-memory");
                None
            }
        },
        None => None,
    };
    if let Some(kvs) = kvs.as_mut() {
        match fabrics.borrow_mut().load_from(kvs, &crypto, 0) {
            Ok(n) => println!("[kvs] restored {n} fabrics"),
            Err(e) => {
                println!("[kvs] fabric restore failed: {e:?}; starting with empty table");
                *fabrics.borrow_mut() = FabricTable::new();
            }
        }
        match acl.borrow_mut().load_from(kvs) {
            Ok(n) => println!("[kvs] restored {n} ACL entries"),
            Err(e) => println!("[kvs] ACL restore failed: {e:?}"),
        }
        match stack.load_resumptions_from(kvs) {
            Ok(n) => println!("[kvs] restored {n} resumptions"),
            Err(e) => println!("[kvs] resumption restore failed: {e:?}"),
        }
    }
    let restored_fabric_count = fabrics.borrow().len();
    if restored_fabric_count > 0 {
        stack.set_pase_enabled(false);
    }

    let socket = open_matter_udp()?;
    socket.set_nonblocking(true)?;
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- mDNS ディスカバリ ---
    let local_ipv4 = discover_local_ipv4();
    let local_ipv6 = discover_local_ipv6();
    let mac = MDNS_INSTANCE_ID.to_be_bytes();
    let host = Host::from_mac(&mac[2..8], local_ipv6.map(|(ip, _)| ip), Some(local_ipv4));
    let mut mdns: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
    let (sii_ms, sai_ms) = mdns_intervals();
    if sii_ms.is_some() || sai_ms.is_some() {
        println!("  mDNS TXT SII/SAI advertised: SII={sii_ms:?}ms SAI={sai_ms:?}ms");
    }
    // commissionable 広告(先頭機能 EP の device_type=0x0302 を広告する)。
    let commissionable = |discriminator: u16, mode: CommissioningMode| Commissionable {
        device_type: Some(DEVICE_TYPE_SENSOR),
        device_name: Some(CFG.product_name),
        sii: sii_ms,
        sai: sai_ms,
        ..Commissionable::new(
            MDNS_INSTANCE_ID,
            discriminator,
            CFG.vendor_id,
            CFG.product_id,
            mode,
        )
    };
    if restored_fabric_count == 0 {
        mdns.set_commissionable(Some(commissionable(
            DISCRIMINATOR,
            CommissioningMode::Standard,
        )));
    } else {
        let ops: Vec<Operational> = fabrics
            .borrow()
            .iter()
            .map(|f| Operational {
                sii: sii_ms,
                sai: sai_ms,
                ..Operational::new(f.compressed_fabric_id(), f.node_id())
            })
            .collect();
        mdns.set_operational(ops);
        println!("[kvs] advertising operational for {restored_fabric_count} restored fabric(s)");
    }
    let mdns_socket = open_mdns_socket();
    let mdns_socket_v6 = local_ipv6.and_then(|(_, scope)| open_mdns_socket_v6(scope));
    let mdns_v6_dst: Option<SocketAddr> = local_ipv6
        .map(|(_, scope)| SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6, MDNS_PORT, 0, scope)));

    println!("simple-matter SensorHub listening on UDP/5540 (dual-stack)");
    println!("  PASE: {}  discriminator: {DISCRIMINATOR}", common_pase::config_labeled().1);
    match &mdns_socket {
        Some(_) => println!("  mDNS advertising on 224.0.0.251:5353 (A record: {local_ipv4})"),
        None => println!("  (mDNS socket unavailable; point a commissioner at this UDP port.)"),
    }
    match (&mdns_socket_v6, local_ipv6) {
        (Some(_), Some((ip, scope))) => {
            println!("  mDNS advertising on [ff02::fb%{scope}]:5353 (AAAA record: {ip})")
        }
        _ => println!("  (no IPv6 link-local mDNS; IPv4-only discovery)"),
    }

    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    let mut last_generation = fabrics.borrow().generation();
    let mut last_resumption_gen = stack.resumption_generation();
    let mut boot_window_open = restored_fabric_count == 0;
    let mut last_fabric_count = fabrics.borrow().len();

    loop {
        // 1) Matter UDP の受信処理。
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(&start);
                let debug = std::env::var("MATTER_DEBUG").ok();
                if debug.as_deref() == Some("2") {
                    let hex: String = rx[..n].iter().map(|b| format!("{b:02x}")).collect();
                    eprintln!("[rx-hex] {n}B from {src}: {hex}");
                }
                let dir = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx);
                if debug.is_some() {
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

        // 2b) 接点センサ(EP3、Boolean State 0x0045)の StateChange を回収してイベント post。
        //     payload は struct { 0: stateValue(bool) }(設計 §1.5)。
        if let Some(state) = stack.device_mut().contact.take_state_change() {
            let _ = stack.post_event(
                EndpointId(3),
                ClusterId(0x0045),
                EventId(0),
                PRIORITY_INFO,
                now,
                |w, tag| {
                    w.start_struct(tag)?;
                    w.write_bool(&TlvTag::ContextSpecific(0), state)?;
                    w.end_container()
                },
            );
        }

        // 3) fabric が増減したら operational 広告に反映して再 announce。
        let gen = fabrics.borrow().generation();
        if gen != last_generation {
            last_generation = gen;
            if let Some(kvs) = kvs.as_mut() {
                match fabrics.borrow().save_to(kvs) {
                    Ok(()) => println!("[kvs] saved {} fabrics", fabrics.borrow().len()),
                    Err(e) => println!("[kvs] fabric save error: {e:?}"),
                }
                match acl.borrow().save_to(kvs) {
                    Ok(()) => println!("[kvs] saved ACL"),
                    Err(e) => println!("[kvs] ACL save error: {e:?}"),
                }
            }
            let ops: Vec<Operational> = fabrics
                .borrow()
                .iter()
                .map(|f| Operational {
                    sii: sii_ms,
                    sai: sai_ms,
                    ..Operational::new(f.compressed_fabric_id(), f.node_id())
                })
                .collect();
            mdns.set_operational(ops);
            mdns.notify_change(now_ms(&start));
            let fabric_count = fabrics.borrow().len();
            if fabric_count > last_fabric_count && window.borrow().is_open() {
                window.borrow_mut().close_window();
                println!("[window] commissioning succeeded; closing window");
            }
            last_fabric_count = fabric_count;
            if boot_window_open && fabric_count > 0 && !window.borrow().is_open() {
                boot_window_open = false;
                stack.set_pase_enabled(false);
                mdns.set_commissionable(None);
                mdns.notify_change(now_ms(&start));
                println!("[window] initial commissioning done; commissioning window closed");
            } else if !boot_window_open && fabric_count == 0 && !window.borrow().is_open() {
                boot_window_open = true;
                let cfg = common_pase::config();
                stack.set_pase_config(cfg);
                stack.set_pase_enabled(true);
                mdns.set_commissionable(Some(commissionable(
                    DISCRIMINATOR,
                    CommissioningMode::Standard,
                )));
                mdns.notify_change(now_ms(&start));
                println!("[window] all fabrics removed; reopening initial commissioning window");
            }
        }

        // 3.2) CASE resumption ストアの世代変化を検知して KVS へ保存する(§7.4)。
        let rgen = stack.resumption_generation();
        if rgen != last_resumption_gen {
            last_resumption_gen = rgen;
            if let Some(kvs) = kvs.as_mut() {
                match stack.save_resumptions_to(kvs) {
                    Ok(()) => println!("[kvs] saved resumptions"),
                    Err(e) => println!("[kvs] resumption save error: {e:?}"),
                }
            }
        }

        // 3.5) コミッショニング窓イベントを PASE 設定と mDNS 広告へ反映する。
        let window_event = window.borrow_mut().take_event();
        if let Some(ev) = window_event {
            let now = now_ms(&start);
            match ev {
                WindowEvent::OpenedEnhanced { discriminator } => {
                    if let Some(cfg) = window.borrow().pase_config() {
                        stack.set_pase_config(cfg);
                        stack.set_pase_enabled(true);
                        mdns.set_commissionable(Some(commissionable(
                            discriminator,
                            CommissioningMode::Enhanced,
                        )));
                        mdns.notify_change(now);
                        println!(
                            "[window] enhanced commissioning window open (CM=2, discriminator {discriminator})"
                        );
                    }
                }
                WindowEvent::OpenedBasic => {
                    let cfg = common_pase::config();
                    stack.set_pase_config(cfg);
                    stack.set_pase_enabled(true);
                    mdns.set_commissionable(Some(commissionable(
                        DISCRIMINATOR,
                        CommissioningMode::Standard,
                    )));
                    mdns.notify_change(now);
                    println!("[window] basic commissioning window open (CM=1)");
                }
                WindowEvent::Closed => {
                    stack.set_pase_enabled(false);
                    mdns.set_commissionable(None);
                    mdns.notify_change(now);
                    println!("[window] commissioning window closed");
                }
            }
            let admin_idx = window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }

        // 4) mDNS の受信応答と announce(v4 / v6 両ファミリ)。
        if let Some(msock) = &mdns_socket {
            serve_mdns_socket(
                &mut mdns,
                msock,
                (MDNS_IPV4, MDNS_PORT).into(),
                &mut mdns_rx,
                &mut mdns_tx,
            );
        }
        if let (Some(msock), Some(dst)) = (&mdns_socket_v6, mdns_v6_dst) {
            serve_mdns_socket(&mut mdns, msock, dst, &mut mdns_rx, &mut mdns_tx);
        }
        if let Some(len) = mdns.poll_announce(now_ms(&start), &mut mdns_tx) {
            if let Some(msock) = &mdns_socket {
                let _ = msock.send_to(&mdns_tx[..len], (MDNS_IPV4, MDNS_PORT));
            }
            if let (Some(msock), Some(dst)) = (&mdns_socket_v6, mdns_v6_dst) {
                let _ = msock.send_to(&mdns_tx[..len], dst);
            }
        }

        // ビジーループ回避のため短くスリープする(この 20ms 周期が擬似センサの分解能になる)。
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// mDNS 用 UDP ソケットを開き、224.0.0.251 のマルチキャストグループに参加する。
fn open_mdns_socket() -> Option<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
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

/// `SM_MDNS_SII_MS` / `SM_MDNS_SAI_MS` から mDNS TXT の SII/SAI(ミリ秒)を読む。
fn mdns_intervals() -> (Option<u32>, Option<u32>) {
    let read = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
    (read("SM_MDNS_SII_MS"), read("SM_MDNS_SAI_MS"))
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

/// Matter 運用 UDP(5540)をデュアルスタック(v6only=false)で bind する。
fn open_matter_udp() -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_only_v6(false)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MATTER_PORT)).into())?;
    Ok(s.into())
}

/// mDNS の受信クエリに応答する(1 ソケット分)。
fn serve_mdns_socket(
    mdns: &mut MdnsResponder<NF>,
    sock: &UdpSocket,
    mc_dst: SocketAddr,
    rx: &mut [u8],
    tx: &mut [u8],
) {
    match sock.recv_from(rx) {
        Ok((n, src)) => {
            let qu = mdns.query_wants_unicast(&rx[..n]);
            if let Some(len) = mdns.handle_query(&rx[..n], tx) {
                let dst = if qu { src } else { mc_dst };
                let _ = sock.send_to(&tx[..len], dst);
            }
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Err(_) => {}
    }
}

/// IPv6(ff02::fb)用 mDNS ソケットを開き、`scope`(if_index)で join する。
fn open_mdns_socket_v6(scope: u32) -> Option<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_only_v6(true).ok()?;
    socket.set_reuse_address(true).ok()?;
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    socket.join_multicast_v6(&MDNS_IPV6, scope).ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}

/// リンクローカル IPv6(fe80::/10)と scope_id(if_index)を推定する。
#[cfg(target_os = "linux")]
fn discover_local_ipv6() -> Option<(Ipv6Addr, u32)> {
    let want_if = default_route_ifname();
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    let mut fallback: Option<(Ipv6Addr, u32)> = None;
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let addr_hex = cols.next()?;
        let if_index_hex = cols.next()?;
        let _prefix = cols.next()?;
        let scope_hex = cols.next()?;
        let _flags = cols.next()?;
        let ifname = cols.next()?;
        if ifname == "lo" {
            continue;
        }
        if u32::from_str_radix(scope_hex, 16).ok()? != 0x20 {
            continue;
        }
        if addr_hex.len() != 32 {
            continue;
        }
        let mut octets = [0u8; 16];
        for (i, o) in octets.iter_mut().enumerate() {
            *o = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        let if_index = u32::from_str_radix(if_index_hex, 16).ok()?;
        let entry = (Ipv6Addr::from(octets), if_index);
        match &want_if {
            Some(name) if name == ifname => return Some(entry),
            _ => {
                if fallback.is_none() {
                    fallback = Some(entry);
                }
            }
        }
    }
    fallback
}

/// `/proc/net/route` から IPv4 既定経路(Destination=00000000)の iface 名を得る。
#[cfg(target_os = "linux")]
fn default_route_ifname() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let ifname = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(ifname.to_string());
        }
    }
    None
}

/// 非 Linux 向けフォールバック(IPv6 リンクローカル発見なし)。
#[cfg(not(target_os = "linux"))]
fn discover_local_ipv6() -> Option<(Ipv6Addr, u32)> {
    None
}
