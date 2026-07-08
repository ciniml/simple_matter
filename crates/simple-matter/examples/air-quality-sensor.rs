//! std 上の空気質センササンプル(`docs/design/airq-port.md` §4.4/§5、M5Stack AirQ 移植 A1)。
//!
//! [`sensor-hub`](sensor-hub.rs) の流儀で、AirQ 実機(SEN55 + SCD40)相当の 3 EP 構成を
//! 手書き [`DataModel`] で構成する(共有 OpCreds のライフタイムのため `device!` マクロは
//! 使えない)。擬似センサを `on_tick`(約 1 秒周期)で駆動する。
//!
//! # 構成(設計 §5。既存 esp-matter FW の 8 EP 構成を 3 EP に整理)
//!
//! - EP0: Root Node(0x0016)。既存 7 種。
//! - EP1: **Air Quality Sensor(0x002C)** = Identify + AirQuality(0x005B)+
//!   CO2(0x040D)+ PM2.5(0x042A)+ PM1(0x042C)+ PM10(0x042D)+ Descriptor。
//! - EP2: Temperature Sensor(0x0302)/ EP3: Humidity Sensor(0x0307)= SCD40 相当。
//!
//! # 擬似センサシム(設計 §4.4。SEN55/SCD40 相当の値域)
//!
//! - CO2: 400-1200 ppm(三角波、SCD40 相当)/ PM2.5: 0-50 µg/m³ ベース +
//!   240 秒周期の「汚染エピソード」スパイク(最大 +250 µg/m³。AirQualityEnum の
//!   Poor..ExtremelyPoor までの全レベル遷移を実証するため)。
//! - PM1/PM10 は PM2.5 からの比率導出(SEN55 の実測傾向に合わせた擬似値)。
//! - 温度 23.5±1.5 ℃ / 湿度 45±8 %(SCD40 相当)。
//!
//! # 既存 esp-matter FW のバグ是正(設計 §1.2)
//!
//! 1. **AirQuality 属性の常時更新**: 毎 tick、CO2/PM2.5 の worst-of で
//!    [`AirQualityEnum`] を算出して `set_air_quality` する(既存 FW は常に Unknown)。
//!    閾値はデバイスポリシー(本 example は屋内 IAQ / US EPA AQI 相当の帯域)。
//! 2. **VOC/NOx index を濃度クラスタに入れない**: TVOC(0x042E)/ NO2(0x0413)クラスタは
//!    コアに実装済みだが、Sensirion index(無次元)は濃度ではないため本 example には
//!    **搭載しない**(設計 §4.3)。
//!
//! 実行: `cargo run --example air-quality-sensor`

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
    AccessControlCluster, AdminCommissioningCluster, AirQualityCluster, AirQualityEnum,
    BasicInfoConfig, BasicInformationCluster, CarbonDioxideConcentrationCluster,
    CommissioningWindow, DescriptorCluster, GeneralCommissioning, IdentifyCluster,
    NetworkCommissioning, OpCredsCluster, Pm10ConcentrationCluster, Pm1ConcentrationCluster,
    Pm25ConcentrationCluster, RelativeHumidityMeasurementCluster, TemperatureMeasurementCluster,
    TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{tick_clusters, DataModel, ServerCluster};
use simple_matter::error::{Error, Result as SmResult};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::kvs::Kvs;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

const PASSCODE: u32 = 20202021;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;

/// コミッショニング discriminator(12 ビット)。chip-tool の既定テスト値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子。他 example と別値にして同一ホスト併走時の衝突を避ける。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_66FF;
/// mDNS 広告用のデバイスタイプ ID(先頭機能 EP = Air Quality Sensor)。
const DEVICE_TYPE_AIRQ: u32 = 0x002C;

/// 擬似センサの駆動周期(ms)。約 1 秒ごとに更新。
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
    product_name: "AirQualitySensor",
    product_id: 0x8007,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-AIRQ-0007",
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
// EP1 = Air Quality Sensor(0x002C、rev 1)。
//   必須: Identify / AirQuality / Descriptor(実装済み)。
//   任意: CO2 / PM2.5 / PM1 / PM10 Concentration(搭載)。
//   非搭載: TVOC(0x042E)/ NO2(0x0413)— Sensirion index は濃度ではない(設計 §4.3)。
static EP1_SERVERS: &[ClusterId] = &[
    ClusterId(0x0003),
    ClusterId(0x001D),
    ClusterId(0x005B),
    ClusterId(0x040D),
    ClusterId(0x042A),
    ClusterId(0x042C),
    ClusterId(0x042D),
];
// EP2 = Temperature Sensor(0x0302、rev 2)。必須: Identify / TemperatureMeasurement / Descriptor。
static EP2_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0402)];
// EP3 = Humidity Sensor(0x0307、rev 2)。必須: Identify / RelativeHumidity / Descriptor。
static EP3_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0405)];

static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x002C, 1)];
static EP2_DT: &[DeviceType] = &[DeviceType::new(0x0302, 2)];
static EP3_DT: &[DeviceType] = &[DeviceType::new(0x0307, 2)];

// Root(EP0)の子エンドポイントは EP1-3。機能 EP は子を持たない。
static EP0_PARTS: &[EndpointId] = &[EndpointId(1), EndpointId(2), EndpointId(3)];
static NO_PARTS: &[EndpointId] = &[];

/// 三角波(base±amp、`step` 刻み)。周期は `4*amp/step` tick(sensor-hub と同流儀)。
fn triangle(ticks: u64, base: i32, amp: i32, step: i32) -> i32 {
    if amp <= 0 || step <= 0 {
        return base;
    }
    let period = (4 * amp / step) as u64;
    let p = ((ticks % period) as i32) * step;
    if p <= 2 * amp {
        base - amp + p
    } else {
        base + amp - (p - 2 * amp)
    }
}

/// CO2 濃度(ppm)の擬似値: 400-1200 ppm を 80 秒周期でゆらぐ(SCD40 相当)。
fn co2_sim(t: u64) -> f32 {
    triangle(t, 800, 400, 20) as f32
}

/// PM2.5 濃度(µg/m³)の擬似値: 0-50 のベース三角波(SEN55 相当)+
/// 240 秒周期の後半 60 秒に最大 +250 µg/m³ の「汚染エピソード」スパイク
/// (調理・煙相当。AirQualityEnum の全レベル 1-6 遷移を E2E で観測するため)。
fn pm25_sim(t: u64) -> f32 {
    let base = triangle(t, 250, 250, 20) as f32 / 10.0;
    let phase = t % 240;
    let spike = if (180..240).contains(&phase) {
        let p = (phase - 180) as f32; // 0..60
        let s = if p < 30.0 { p } else { 60.0 - p }; // 0..30..0
        s / 30.0 * 250.0
    } else {
        0.0
    };
    base + spike
}

/// CO2(ppm)→ AirQualityEnum(屋内 IAQ 相当の帯域。デバイスポリシー、設計 §4.2)。
fn classify_co2(ppm: f32) -> AirQualityEnum {
    match ppm {
        v if v < 800.0 => AirQualityEnum::Good,
        v if v < 1000.0 => AirQualityEnum::Fair,
        v if v < 1400.0 => AirQualityEnum::Moderate,
        v if v < 2000.0 => AirQualityEnum::Poor,
        v if v < 3000.0 => AirQualityEnum::VeryPoor,
        _ => AirQualityEnum::ExtremelyPoor,
    }
}

/// PM2.5(µg/m³)→ AirQualityEnum(US EPA AQI 相当の帯域。デバイスポリシー)。
fn classify_pm25(ugm3: f32) -> AirQualityEnum {
    match ugm3 {
        v if v < 12.0 => AirQualityEnum::Good,
        v if v < 35.0 => AirQualityEnum::Fair,
        v if v < 55.0 => AirQualityEnum::Moderate,
        v if v < 150.0 => AirQualityEnum::Poor,
        v if v < 250.0 => AirQualityEnum::VeryPoor,
        _ => AirQualityEnum::ExtremelyPoor,
    }
}

struct AirQualityDevice<'s> {
    acl: &'s RefCell<AclTable<NACL>>,
    access_control: AccessControlCluster<'s, NACL>,
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    admin: AdminCommissioningCluster<'s>,
    opcreds: OpCreds<'s>,
    desc0: DescriptorCluster,
    // EP1-3 の Identify(各 EP 独立の IdentifyTime を持つ)。
    identify1: IdentifyCluster,
    identify2: IdentifyCluster,
    identify3: IdentifyCluster,
    // EP1 = Air Quality Sensor のクラスタ群。
    air_quality: AirQualityCluster,
    co2: CarbonDioxideConcentrationCluster,
    pm25: Pm25ConcentrationCluster,
    pm1: Pm1ConcentrationCluster,
    pm10: Pm10ConcentrationCluster,
    // EP2/EP3 = 温湿度(SCD40 相当)。
    temp: TemperatureMeasurementCluster,
    humidity: RelativeHumidityMeasurementCluster,
    // 機能 EP の Descriptor。
    desc1: DescriptorCluster,
    desc2: DescriptorCluster,
    desc3: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    removed_fabric: Option<core::num::NonZeroU8>,
    /// 擬似センサの経過 tick(約 1 秒ごとに 1 増える)。
    sensor_ticks: u64,
    /// 擬似センサを最後に進めた時刻(ms)。
    last_sensor_ms: u64,
}

impl AirQualityDevice<'_> {
    /// 擬似センサを 1 ステップ進め、AirQuality を CO2/PM2.5 の worst-of で常時更新する
    /// (既存 FW のバグ 1 の是正、設計 §1.2/§4.2)。
    fn step_sensors(&mut self) {
        let t = self.sensor_ticks;
        let co2 = co2_sim(t);
        let pm25 = pm25_sim(t);
        // SEN55 の実測傾向に合わせた比率導出(PM1 ≤ PM2.5 ≤ PM10)。
        let pm1 = pm25 * 0.7;
        let pm10 = pm25 * 1.6;
        self.co2.set_measured(Some(co2));
        self.pm25.set_measured(Some(pm25));
        self.pm1.set_measured(Some(pm1));
        self.pm10.set_measured(Some(pm10));
        self.temp
            .set_measured(Some(triangle(t, 2350, 150, 10) as i16));
        self.humidity
            .set_measured(Some(triangle(t, 4500, 800, 40) as u16));
        // 総合評価 = worst-of(CO2, PM2.5)。変化はログで観測できるようにする。
        let aq = classify_co2(co2).max(classify_pm25(pm25));
        let prev = self.air_quality.air_quality();
        self.air_quality.set_air_quality(aq);
        if prev != aq {
            println!("[airq] AirQuality {prev:?} -> {aq:?} (co2={co2:.0}ppm pm2.5={pm25:.1}ug/m3)");
        }
        self.sensor_ticks = self.sensor_ticks.wrapping_add(1);
    }
}

impl DataModel for AirQualityDevice<'_> {
    fn endpoints(&self) -> &[EndpointMeta] {
        static EPS: &[EndpointMeta] = &[
            EndpointMeta::new(EndpointId(0), EP0_DT, EP0_SERVERS),
            EndpointMeta::new(EndpointId(1), EP1_DT, EP1_SERVERS),
            EndpointMeta::new(EndpointId(2), EP2_DT, EP2_SERVERS),
            EndpointMeta::new(EndpointId(3), EP3_DT, EP3_SERVERS),
        ];
        EPS
    }
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        match ep.0 {
            0 => EP0_SERVERS,
            1 => EP1_SERVERS,
            2 => EP2_SERVERS,
            3 => EP3_SERVERS,
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
            (1, 0x001D) => Some(&self.desc1),
            (1, 0x005B) => Some(&self.air_quality),
            (1, 0x040D) => Some(&self.co2),
            (1, 0x042A) => Some(&self.pm25),
            (1, 0x042C) => Some(&self.pm1),
            (1, 0x042D) => Some(&self.pm10),
            (2, 0x0003) => Some(&self.identify2),
            (2, 0x0402) => Some(&self.temp),
            (2, 0x001D) => Some(&self.desc2),
            (3, 0x0003) => Some(&self.identify3),
            (3, 0x0405) => Some(&self.humidity),
            (3, 0x001D) => Some(&self.desc3),
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
            (1, 0x001D) => Some(&mut self.desc1),
            (1, 0x005B) => Some(&mut self.air_quality),
            (1, 0x040D) => Some(&mut self.co2),
            (1, 0x042A) => Some(&mut self.pm25),
            (1, 0x042C) => Some(&mut self.pm1),
            (1, 0x042D) => Some(&mut self.pm10),
            (2, 0x0003) => Some(&mut self.identify2),
            (2, 0x0402) => Some(&mut self.temp),
            (2, 0x001D) => Some(&mut self.desc2),
            (3, 0x0003) => Some(&mut self.identify3),
            (3, 0x0405) => Some(&mut self.humidity),
            (3, 0x001D) => Some(&mut self.desc3),
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
        // コミッショニング窓のタイムアウト自動クローズ。
        let _ = self.admin.on_tick(now_ms);
        // クラスタ tick(Identify の IdentifyTime 減衰)を回す。
        let next = tick_clusters(self, now_ms);
        // 擬似センサ: 約 1 秒周期で各センサ値と AirQuality を更新する。
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

fn build_device<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    acl: &'s RefCell<AclTable<NACL>>,
    window: &'s RefCell<CommissioningWindow>,
) -> AirQualityDevice<'s> {
    let dac_crypto = RustCrypto::new(DemoRng::from_time());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    AirQualityDevice {
        acl,
        access_control: AccessControlCluster::new(acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        identify1: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP1 {}", ident_state(on))),
        identify2: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP2 {}", ident_state(on))),
        identify3: IdentifyCluster::new()
            .with_listener(|on| println!("[identify] EP3 {}", ident_state(on))),
        air_quality: AirQualityCluster::new(),
        // Min/Max はセンサ定格相当(SCD40: 400-40000ppm、SEN55 PM: 0-1000µg/m³)。
        co2: CarbonDioxideConcentrationCluster::new(Some(400.0), Some(40000.0)),
        pm25: Pm25ConcentrationCluster::new(Some(0.0), Some(1000.0)),
        pm1: Pm1ConcentrationCluster::new(Some(0.0), Some(1000.0)),
        pm10: Pm10ConcentrationCluster::new(Some(0.0), Some(1000.0)),
        temp: TemperatureMeasurementCluster::new(Some(-1000), Some(6000)),
        humidity: RelativeHumidityMeasurementCluster::new(Some(0), Some(10000)),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], NO_PARTS),
        desc2: DescriptorCluster::new(EndpointId(2), EP2_DT, EP2_SERVERS, &[], NO_PARTS),
        desc3: DescriptorCluster::new(EndpointId(3), EP3_DT, EP3_SERVERS, &[], NO_PARTS),
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

    let config = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_device(&fabrics, &acl, &window));
    let mut stack: DefaultStack<Backend, DemoRng, AirQualityDevice> =
        MatterStack::new(&crypto, sc, im);

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
    let commissionable = |discriminator: u16, mode: CommissioningMode| Commissionable {
        device_type: Some(DEVICE_TYPE_AIRQ),
        device_name: Some(CFG.product_name),
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
            .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id()))
            .collect();
        mdns.set_operational(ops);
        println!("[kvs] advertising operational for {restored_fabric_count} restored fabric(s)");
    }
    let mdns_socket = open_mdns_socket();
    let mdns_socket_v6 = local_ipv6.and_then(|(_, scope)| open_mdns_socket_v6(scope));
    let mdns_v6_dst: Option<SocketAddr> = local_ipv6
        .map(|(_, scope)| SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6, MDNS_PORT, 0, scope)));

    println!("simple-matter AirQualitySensor listening on UDP/5540 (dual-stack)");
    println!("  passcode: {PASSCODE}  discriminator: {DISCRIMINATOR}");
    match &mdns_socket {
        Some(_) => println!("  mDNS advertising on 224.0.0.251:5353 (A record: {local_ipv4})"),
        None => println!("  (mDNS socket unavailable; point a commissioner at this UDP port.)"),
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
                if let Some(dir) = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx) {
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
                .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id()))
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
                let cfg = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
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

        // 3.2) CASE resumption ストアの世代変化を検知して KVS へ保存する。
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
                simple_matter::dm::clusters::WindowEvent::OpenedEnhanced { discriminator } => {
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
                simple_matter::dm::clusters::WindowEvent::OpenedBasic => {
                    let cfg =
                        PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
                    stack.set_pase_config(cfg);
                    stack.set_pase_enabled(true);
                    mdns.set_commissionable(Some(commissionable(
                        DISCRIMINATOR,
                        CommissioningMode::Standard,
                    )));
                    mdns.notify_change(now);
                    println!("[window] basic commissioning window open (CM=1)");
                }
                simple_matter::dm::clusters::WindowEvent::Closed => {
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

        // ビジーループ回避のため短くスリープする(20ms 周期)。
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
