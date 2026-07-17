//! M5Stack AirQ 本番ファームウェア — A5 段階 3: 実センサ(SEN55 + SCD40)の
//! Air Quality Sensor(BLE + Wi-Fi dual-transport)。
//!
//! `docs/design/airq-port.md` §5 / §7.1 A5。トランスポート・永続化・pump は
//! `s3-light.rs`(= C6 `e5-light.rs`)と同一で、データモデルを PC example
//! `examples/air-quality-sensor.rs` の 3 EP 構成に置き換え、擬似センサの代わりに
//! 実センサ([`sensor_task`])のスナップショットを反映する:
//!
//! | EP | デバイスタイプ | クラスタ | データ源 |
//! |---|---|---|---|
//! | 0 | Root Node 0x0016 | Basic/GC/NetComm(Wi-Fi)/OpCreds/Descriptor | — |
//! | 1 | Air Quality Sensor 0x002C | Identify + AirQuality + CO2 + PM1/2.5/10 | SCD40 + SEN55 |
//! | 2 | Temperature Sensor 0x0302 | Identify + TemperatureMeasurement | SEN55 |
//! | 3 | Humidity Sensor 0x0307 | Identify + RelativeHumidityMeasurement | SEN55 |
//!
//! - **AirQuality(0x005B)は CO2/PM2.5/VOC index/NOx index の worst-of で常時更新**
//!   (既存 esp-matter FW のバグ 1 是正。閾値 = 屋内 IAQ / US EPA AQI 相当 +
//!   Sensirion 公式アンカー。airq-port.md §4.2/§4.3b)。
//! - **VOC/NOx index は濃度クラスタに載せない**(無次元 index は濃度ではない。
//!   airq-port.md §4.3。AirQuality 算出材料 + ログにのみ使う)。
//! - 温湿度ソースは SEN55(A5 タスク指定。既存 FW は SCD4x 側を採用していた —
//!   airq-port.md §1.2。SCD40 側の値は参考としてログに出す)。温度には自己発熱
//!   補正 -3.0°C を適用(`sensors::SEN55_TEMP_OFFSET_C`、airq-port.md §7.4)。
//! - AirQ 固有のハード制御: **GPIO46 = HIGH(電源 HOLD)** を起動直後に固定、
//!   **GPIO10 = LOW(SEN55 電源 ON)+ 1 秒待ち**は [`sensor_task`] が行う。
//!
//! # pump ループの非自明な制約(C6 E3-E5 から継承。ble-btp.md §6.2 / §11-4)
//!
//! - **毎イテレーションで `stack.poll()` と BTP flush の両方を回す**(exchange 回収)。
//! - handshake 応答の indicate は **C2Subscribed 後まで保留**。
//! - flash 保存(fabric 変更時のみ)は同期・数十 ms 級で pump を止めるが低頻度なので許容。
//!
//! 実行: `cd ports/esp32s3 && cargo build --release --bin airq-sensor`(書き込みは README)
//! コミッショニング(実 SSID を渡す):
//! `chip-tool pairing ble-wifi 1 <ssid> <pass> 20202021 3840 --bypass-attestation-verifier true`
//!
//! [`sensor_task`]: esp32s3_firmware::sensors::sensor_task

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use core::cell::RefCell;

use embassy_executor::Spawner;
use embassy_futures::join::{join3, join5};
use embassy_futures::select::{select4, Either4};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::StackResources;
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull};
use esp_hal::i2c::master::{Config as I2cConfig, I2c};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_IPV6, MDNS_PORT,
};
use simple_matter::dm::clusters::{
    AdminCommissioningCluster, AirQualityCluster, AirQualityEnum, BasicInfoConfig,
    BasicInformationCluster, CarbonDioxideConcentrationCluster, CommissioningWindow,
    DescriptorCluster, GeneralCommissioning, IdentifyCluster, NetworkCommissioningWifi,
    OpCredsCluster, Pm10ConcentrationCluster, Pm1ConcentrationCluster, Pm25ConcentrationCluster,
    RelativeHumidityMeasurementCluster, TemperatureMeasurementCluster, TestDacProvider,
    WindowEvent,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{tick_clusters, DataModel, ServerCluster};
use simple_matter::error::Result as MResult;
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::SecureChannel;
use simple_matter::stack::{
    DefaultStack, MatterStack, SendDirective, SharedFabricCreds, MAX_PACKET_SIZE,
};
use simple_matter::transport::net::{
    BtpConnId, PeerAddr, UdpMulticast, UdpReceive, UdpSend, MAX_RX_PACKET_SIZE,
};
use simple_matter::wifi::WifiDriver;

use esp32s3_firmware::ble::{gatt_worker, BtpGattServer, GattChannels, TroubleGattPeripheral};
use esp32s3_firmware::display::{self, display_task};
use esp32s3_firmware::kvs::EspKvs;
use esp32s3_firmware::net::{peer_v4, peer_v6, v4_as_mapped, EspUdp};
use esp32s3_firmware::sensors::{self, sensor_task, SensorSnapshot};
use esp32s3_firmware::wifi::{take_pending_credentials, wifi_task, EspWifiDriver, WifiRequest};
use esp32s3_firmware::EspRng;
use simple_matter::kvs::Kvs;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須。
// 無いとブートローダがアプリを起動できず TG0 WDT リセットループになる)。
esp_bootloader_esp_idf::esp_app_desc!();

/// コミッショニングパスコード(PC example と同値)。
/// SPAKE2+ 検証子導出のソルト(PC example と同値)。
/// コミッショニング discriminator(12 ビット、PC example と同値)。
const DISCRIMINATOR: u16 = 3840;
/// fabric テーブル容量(`DefaultStack` の NF と一致させる)。
const NF: usize = 5;

/// BTP フラグメントの先頭バイトトレース。既定 off。
const BTP_TRACE: bool = false;

/// HCI コマンドの同時実行スロット数(C6 E2 と同値)。
const HCI_SLOTS: usize = 20;

type Backend = RustCrypto<EspRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;
/// 本 bin のスタック型(標準プロファイル。R = TRNG 注入の [`EspRng`])。
type AirqStack<'s> = DefaultStack<'s, Backend, EspRng, AirQualityDevice<'s>>;

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

// ==========================================================================
// DataModel(examples/air-quality-sensor.rs の 3 EP 構成。EP0 は C6 e5-light と
// 同じ 5 クラスタ + NetworkCommissioning は実 Wi-Fi ドライバ注入版)
// ==========================================================================

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "SimpleMatter",
    vendor_id: 0xFFF1,
    product_name: "AirQualitySensor",
    product_id: 0x8007,
    hardware_version: 1,
    hardware_version_string: "AirQ-StampS3",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-AIRQ-S3-1",
};

// EP0 = Root Node(0x0016)。管理系 5 クラスタ + AdminCommissioning(0x003C、OCW)。
static EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x0028),
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003C),
    ClusterId(0x003E),
    ClusterId(0x001D),
];
// EP1 = Air Quality Sensor(0x002C、rev 1)。
//   必須: Identify / AirQuality / Descriptor。任意: CO2 / PM2.5 / PM1 / PM10。
//   非搭載: TVOC(0x042E)/ NO2(0x0413)— Sensirion index は濃度ではない(§4.3)。
static EP1_SERVERS: &[ClusterId] = &[
    ClusterId(0x0003),
    ClusterId(0x001D),
    ClusterId(0x005B),
    ClusterId(0x040D),
    ClusterId(0x042A),
    ClusterId(0x042C),
    ClusterId(0x042D),
];
// EP2 = Temperature Sensor(0x0302、rev 2)。
static EP2_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0402)];
// EP3 = Humidity Sensor(0x0307、rev 2)。
static EP3_SERVERS: &[ClusterId] = &[ClusterId(0x0003), ClusterId(0x001D), ClusterId(0x0405)];

static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x002C, 1)];
static EP2_DT: &[DeviceType] = &[DeviceType::new(0x0302, 2)];
static EP3_DT: &[DeviceType] = &[DeviceType::new(0x0307, 2)];

static EP0_PARTS: &[EndpointId] = &[EndpointId(1), EndpointId(2), EndpointId(3)];
static NO_PARTS: &[EndpointId] = &[];

/// CO2(ppm)→ AirQualityEnum(屋内 IAQ 相当の帯域。PC example と同一ポリシー)。
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

/// PM2.5(µg/m³)→ AirQualityEnum(US EPA AQI 相当の帯域。PC example と同一ポリシー)。
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

/// Sensirion VOC index(1-500、100 = 過去 24h の平常)→ AirQualityEnum。
///
/// 帯域は Sensirion 公式のアンカーに基づく(根拠は airq-port.md §4.3b):
/// 100 = 平常(Info Note: VOC Index。アルゴリズムが 24h で 100 へ再基準化するため
/// 定常値。リップル ±5 があるので 100 を境界にすると平常時にフラップする —
/// AirQ 実機で 100↔101 の振動を実測)、>150 = 清浄機作動例(同 Info Note)を
/// 最初の劣化レベル境界に採用、200/400 = 公式ウェビナーの緑/黄/赤境界、
/// 300 のみ黄帯の補間。相対指標のため単一チャネルの寄与は VeryPoor を上限とする
/// (ExtremelyPoor は絶対量ベースの CO2/PM に予約)。
/// 有効範囲外(未較正マーカー 0x7FFF/10 = 3276.7、ウォームアップ中の 0)は Unknown
/// (worst-of 合成に影響しない)。
fn classify_voc(index: f32) -> AirQualityEnum {
    match index {
        v if !(1.0..=500.0).contains(&v) => AirQualityEnum::Unknown,
        v if v <= 150.0 => AirQualityEnum::Good,
        v if v <= 200.0 => AirQualityEnum::Fair,
        v if v <= 300.0 => AirQualityEnum::Moderate,
        v if v <= 400.0 => AirQualityEnum::Poor,
        _ => AirQualityEnum::VeryPoor,
    }
}

/// Sensirion NOx index(1-500、1 = クリーンが定常)→ AirQualityEnum。
///
/// 公式アンカーは「1 = クリーン」「>20 = 清浄機作動例」の 2 点のみで、
/// SEN55 の NOx index 個体差は ±50 point / ±50%(データシート Table 5)と大きい。
/// このため寄与は粗い 3 段階に落とし、上限 Poor に制限する(単一チャネルのノイズで
/// ExtremelyPoor まで振れないように。根拠は airq-port.md §4.3b)。
fn classify_nox(index: f32) -> AirQualityEnum {
    match index {
        v if !(1.0..=500.0).contains(&v) => AirQualityEnum::Unknown,
        v if v <= 20.0 => AirQualityEnum::Good,
        v if v <= 100.0 => AirQualityEnum::Moderate,
        _ => AirQualityEnum::Poor,
    }
}

/// AirQ デバイス(EP0 = ルート、EP1 = 空気質、EP2/3 = 温湿度)。
struct AirQualityDevice<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioningWifi<EspWifiDriver>,
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
    // EP2/EP3 = 温湿度(SEN55)。
    temp: TemperatureMeasurementCluster,
    humidity: RelativeHumidityMeasurementCluster,
    desc1: DescriptorCluster,
    desc2: DescriptorCluster,
    desc3: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    removed_fabric: Option<core::num::NonZeroU8>,
}

impl AirQualityDevice<'_> {
    /// センサスナップショットをクラスタへ反映し、AirQuality を worst-of で更新する。
    ///
    /// 未計測(`None`)の項目は触らない(null のまま = 起動直後の正しい表現)。
    /// AirQuality は「判定材料が 1 つでもあれば worst-of、無ければ Unknown」。
    fn apply_snapshot(&mut self, snap: &SensorSnapshot) {
        if let Some(v) = snap.co2_ppm {
            self.co2.set_measured(Some(v));
        }
        if let Some(v) = snap.pm25 {
            self.pm25.set_measured(Some(v));
        }
        if let Some(v) = snap.pm1 {
            self.pm1.set_measured(Some(v));
        }
        if let Some(v) = snap.pm10 {
            self.pm10.set_measured(Some(v));
        }
        // Matter の温度 = 0.01℃ の i16、湿度 = 0.01%RH の u16。
        if let Some(t) = snap.temp_c {
            self.temp.set_measured(Some((t * 100.0) as i16));
        }
        if let Some(h) = snap.rh {
            self.humidity.set_measured(Some((h * 100.0) as u16));
        }
        // 総合評価 = worst-of(CO2, PM2.5, VOC index, NOx index)。Unknown(=0)は
        // Ord の最小値なので「揃っていない/無効な材料は評価に影響しない」max 合成が
        // 成立する。VOC/NOx は濃度クラスタには載せず(§4.3)、ここでの合成にのみ使う。
        let aq = [
            snap.co2_ppm.map(classify_co2),
            snap.pm25.map(classify_pm25),
            snap.voc_index.map(classify_voc),
            snap.nox_index.map(classify_nox),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(AirQualityEnum::Unknown);
        let prev = self.air_quality.air_quality();
        self.air_quality.set_air_quality(aq);
        // e-ink 表示タスクへ総合評価を共有する(クラスタ本体は pump が所有するため)。
        display::set_air_quality_level(aq as u8);
        if prev != aq {
            println!(
                "[airq] AirQuality {:?} -> {:?} (co2={:?}ppm pm2.5={:?}ug/m3 voc={:?} nox={:?})",
                prev, aq, snap.co2_ppm, snap.pm25, snap.voc_index, snap.nox_index
            );
        }
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
        // fail-safe 期限切れで未 CommissioningComplete の fabric 追加を巻き戻す(§11.10)。
        if self.gc.on_tick(now_ms) {
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        // コミッショニング窓のタイムアウト自動クローズ(WindowEvent は pump が拾う)。
        let _ = self.admin.on_tick(now_ms);
        // クラスタ tick(Identify の IdentifyTime 減衰)を回す。
        tick_clusters(self, now_ms)
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
}

/// Identify リスナのメッセージ断片。
fn ident_state(on: bool) -> &'static str {
    if on {
        "identify START (log-only)"
    } else {
        "identify stop"
    }
}

fn build_device<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    window: &'s RefCell<CommissioningWindow>,
) -> AirQualityDevice<'s> {
    let dac_crypto = RustCrypto::new(esp_rng());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    AirQualityDevice {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioningWifi::with_driver(EspWifiDriver),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(esp_rng()), dac),
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
        // SEN55 定格: -10..+50℃ / 0..100%RH。
        temp: TemperatureMeasurementCluster::new(Some(-1000), Some(5000)),
        humidity: RelativeHumidityMeasurementCluster::new(Some(0), Some(10000)),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], NO_PARTS),
        desc2: DescriptorCluster::new(EndpointId(2), EP2_DT, EP2_SERVERS, &[], NO_PARTS),
        desc3: DescriptorCluster::new(EndpointId(3), EP3_DT, EP3_SERVERS, &[], NO_PARTS),
        removed_fabric: None,
    }
}

// ==========================================================================
// BTP ヘルパ(s3-light / C6 e5-light と同じパターン)
// ==========================================================================

/// BTP フラグメントの先頭 5 バイトトレース([`BTP_TRACE`] 時のみ)。
fn trace(dir: &str, frag: &[u8]) {
    if BTP_TRACE {
        let mut head = [0u8; 5];
        let n = frag.len().min(5);
        head[..n].copy_from_slice(&frag[..n]);
        println!(
            "[btp {}] len={} {:02x} {:02x} {:02x} {:02x} {:02x}",
            dir,
            frag.len(),
            head[0],
            head[1],
            head[2],
            head[3],
            head[4]
        );
    }
}

/// WiFi 資格情報レコードの KVS キー(ポートローカル)。
const WIFI_CREDS_KEY: &[u8] = b"wifc";
/// レコードのフォーマットバージョン。
const WIFI_CREDS_VERSION: u8 = 1;
/// 固定長レイアウト: [version(1)][ssid_len(1)][ssid(32)][pass_len(1)][pass(64)] = 99 B。
const WIFI_CREDS_RECORD_LEN: usize = 1 + 1 + 32 + 1 + 64;

/// join 要求を固定長レコードへエンコードする。
fn encode_wifi_creds(req: &WifiRequest) -> [u8; WIFI_CREDS_RECORD_LEN] {
    let mut rec = [0u8; WIFI_CREDS_RECORD_LEN];
    rec[0] = WIFI_CREDS_VERSION;
    let ssid = req.ssid();
    let pass = req.pass();
    rec[1] = ssid.len() as u8;
    rec[2..2 + ssid.len()].copy_from_slice(ssid);
    rec[34] = pass.len() as u8;
    rec[35..35 + pass.len()].copy_from_slice(pass);
    rec
}

/// 固定長レコードをデコードする。バージョン不一致・長さ不正は `None`。
fn decode_wifi_creds(rec: &[u8]) -> Option<WifiRequest> {
    if rec.len() != WIFI_CREDS_RECORD_LEN || rec[0] != WIFI_CREDS_VERSION {
        return None;
    }
    let ssid_len = rec[1] as usize;
    let pass_len = rec[34] as usize;
    if ssid_len > 32 || pass_len > 64 || ssid_len == 0 {
        return None;
    }
    Some(WifiRequest::new(
        &rec[2..2 + ssid_len],
        &rec[35..35 + pass_len],
    ))
}

/// 単調時刻(ms)。BTP / スタックの `now_ms` 注入に使う。
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis()
}

/// MAC(48bit)から modified EUI-64 のリンクローカル IPv6(fe80::/64)を導出する。
fn link_local_from_mac(mac: &[u8; 6]) -> core::net::Ipv6Addr {
    let mut eui = [0u8; 8];
    eui[0] = mac[0] ^ 0x02;
    eui[1] = mac[1];
    eui[2] = mac[2];
    eui[3] = 0xFF;
    eui[4] = 0xFE;
    eui[5] = mac[3];
    eui[6] = mac[4];
    eui[7] = mac[5];
    core::net::Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([eui[0], eui[1]]),
        u16::from_be_bytes([eui[2], eui[3]]),
        u16::from_be_bytes([eui[4], eui[5]]),
        u16::from_be_bytes([eui[6], eui[7]]),
    )
}

/// BTP が吐く下りフラグメントを尽きるまで C2 indication で送出する。
async fn flush_out(
    gatt: &mut TroubleGattPeripheral<'_>,
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

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため)。
fn take_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}

/// commissionable 広告(`_matterc._udp`)の材料を作る(instance id は MAC 由来)。
fn commissionable(mac: &[u8; 6], discriminator: u16, mode: CommissioningMode) -> Commissionable {
    let mut id = [0u8; 8];
    id[2..].copy_from_slice(mac);
    Commissionable {
        device_type: Some(0x002C),
        device_name: Some(CFG.product_name),
        ..Commissionable::new(
            u64::from_be_bytes(id),
            discriminator,
            CFG.vendor_id,
            CFG.product_id,
            mode,
        )
    }
}

/// スタックの送信指示を宛先トランスポートへ振り分ける。
#[allow(clippy::too_many_arguments)]
async fn route_send(
    gatt: &mut TroubleGattPeripheral<'_>,
    btp: &mut Btp<6>,
    udp: &mut EspUdp<'_>,
    d: SendDirective,
    bytes: &[u8],
    mtu: Option<u16>,
    subscribed: bool,
    now: u64,
) -> MResult<()> {
    match d.addr {
        PeerAddr::Ble(c) => {
            btp.send(bytes, now)?;
            if subscribed {
                flush_out(gatt, btp, c, mtu, now).await?;
            }
            Ok(())
        }
        PeerAddr::Udp(_) => udp.send_to(bytes, d.addr).await,
    }
}

// ==========================================================================
// 統合層(pump): BTP + UDP + mDNS + センサ反映 ⇔ MatterStack
// ==========================================================================

/// BTP / UDP / mDNS / センサと MatterStack を駆動する統合層。
///
/// s3-light の pump に対する差分は「センサスナップショットの世代変化を検知して
/// クラスタへ反映する」1 点のみ(ループ末尾)。
#[allow(clippy::too_many_arguments)]
async fn pump(
    gatt: &mut TroubleGattPeripheral<'_>,
    stack: &mut AirqStack<'_>,
    fabrics: &RefCell<FabricTable<Backend, NF>>,
    window: &RefCell<CommissioningWindow>,
    kvs: &mut EspKvs,
    net_stack: embassy_net::Stack<'_>,
    matter_udp: &mut EspUdp<'_>,
    mdns_udp: &mut EspUdp<'_>,
    mac: [u8; 6],
) -> ! {
    let mut btp = Btp::<6>::new(BtpRole::Peripheral);
    let mut conn: Option<BtpConnId> = None;
    let mut mtu: Option<u16> = None;
    // central は C1 write(handshake req)→ C2 subscribe の順で来る。subscribe 前の
    // indicate は捨てられるため、subscribe 済みになるまで送出を保留する。
    let mut subscribed = false;
    let mut established_logged = false;
    // fabric 永続化: 直近に保存(または復元)した時点の generation。
    let mut saved_gen = fabrics.borrow().generation();
    // CASE resumption 永続化: 復元後の世代を基準に取り、変化時に flash 保存する(§7.4)。
    let mut saved_resumption_gen = stack.resumption_generation();
    // 運用 mDNS レスポンダ(DHCP で IPv4 を取得してから構築する)。
    let mut mdns: Option<MdnsResponder<NF>> = None;
    // センサスナップショットの反映済み世代。
    let mut sensor_gen: u32 = 0;
    // 初回コミッショニング窓(fabric 0 個で起動 = 焼き込みパスコードの PASE が有効)。
    let mut boot_window_open = fabrics.borrow().is_empty();
    let mut last_fabric_count = fabrics.borrow().len();

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_PACKET_SIZE];
    let mut udp_rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    // 生存確認ログ。
    let mut next_heartbeat_ms: u64 = 0;

    loop {
        let now = now_ms(start);
        if now >= next_heartbeat_ms {
            let (_, snap) = sensors::snapshot();
            let heap = esp_alloc::HEAP.stats();
            println!(
                "[alive] t={}s conn={:?} sub={} wifi={:?} ip={:?} aq={:?} co2={:?} pm2.5={:?} heap_max={}",
                now / 1000,
                conn.map(|c| c.0),
                subscribed,
                stack.device().net.driver().status(),
                net_stack.config_v4().map(|c| c.address),
                stack.device().air_quality.air_quality(),
                snap.co2_ppm,
                snap.pm25,
                heap.max_usage,
            );
            next_heartbeat_ms = now + 10_000;
        }

        // 両 deadline(スタックの MRP/購読レポート・BTP の遅延 ACK/idle)を min で待つ。
        // 上限 50ms でクリップしてタイムアウト検知・mDNS announce も定期的に回す。
        let dl = match (stack.next_deadline(now), btp.next_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, None) => a,
            (None, b) => b,
        };
        let sleep_ms = match dl {
            Some(t) if t > now => (t - now).min(50),
            Some(_) => 0,
            None => 50,
        };

        match select4(
            gatt.next_event(&mut buf),
            matter_udp.recv_from(&mut udp_rx),
            mdns_udp.recv_from(&mut mdns_rx),
            Timer::after_millis(sleep_ms),
        )
        .await
        {
            // --- BLE(BTP)イベント ---
            Either4::First(Ok(ev)) => {
                let now = now_ms(start);
                match ev {
                    PeripheralEvent::Connected { conn: c, att_mtu } => {
                        println!("[ble] connected: conn={} att_mtu={:?}", c.0, att_mtu);
                        conn = Some(c);
                        mtu = att_mtu;
                        subscribed = false;
                        established_logged = false;
                        btp.reset();
                    }
                    PeripheralEvent::C2Subscribed { conn: c } => {
                        println!("[ble] C2 subscribed: conn={}", c.0);
                        conn = Some(c);
                        subscribed = true;
                        if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                            println!("[btp] flush(subscribe) error: {:?}", e);
                        }
                    }
                    PeripheralEvent::C1Write { conn: c, len } => {
                        conn = Some(c);
                        trace("rx", &buf[..len]);
                        if let Err(e) = btp.process_incoming(&buf[..len], mtu, now) {
                            println!("[btp] process_incoming error: {:?}", e);
                            btp.reset();
                            let _ = gatt.disconnect(c).await;
                            continue;
                        }
                        if subscribed {
                            if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                                println!("[btp] flush(c1) error: {:?}", e);
                            }
                        }
                        // 再組立できた Matter メッセージを stack へ渡し、応答を振り分ける。
                        while let Some(slen) = take_sdu(&mut btp, &mut sdu) {
                            let now = now_ms(start);
                            let dir =
                                stack.handle_rx(&mut sdu[..slen], PeerAddr::Ble(c), now, &mut txd);
                            if let Some(d) = dir {
                                if let Err(e) = route_send(
                                    gatt,
                                    &mut btp,
                                    matter_udp,
                                    d,
                                    &txd[..d.len],
                                    mtu,
                                    subscribed,
                                    now,
                                )
                                .await
                                {
                                    println!("[stack] send(rx) error: {:?}", e);
                                }
                            }
                        }
                    }
                    PeripheralEvent::Disconnected { conn: c } => {
                        println!("[ble] disconnected: conn={}", c.0);
                        conn = None;
                        subscribed = false;
                        established_logged = false;
                        btp.reset();
                    }
                }
            }
            Either4::First(Err(e)) => {
                println!("[ble] next_event error: {:?}", e);
            }
            // --- Matter UDP 受信(運用トランスポート。CASE over UDP はここを通る)---
            Either4::Second(Ok((n, src))) => {
                let now = now_ms(start);
                let dir = stack.handle_rx(&mut udp_rx[..n], src, now, &mut txd);
                if let Some(d) = dir {
                    if let Err(e) = route_send(
                        gatt,
                        &mut btp,
                        matter_udp,
                        d,
                        &txd[..d.len],
                        mtu,
                        subscribed,
                        now,
                    )
                    .await
                    {
                        println!("[stack] send(udp) error: {:?}", e);
                    }
                }
            }
            Either4::Second(Err(e)) => {
                println!("[udp] recv error: {:?}", e);
            }
            // --- mDNS 受信(運用ディスカバリ)---
            Either4::Third(Ok((n, src))) => {
                if let Some(r) = mdns.as_ref() {
                    // QU(unicast-response)クエリには送信元へユニキャストで返す
                    // (RFC 6762 §5.4)。QM は受信ファミリに合わせてマルチキャスト。
                    let qu = r.query_wants_unicast(&mdns_rx[..n]);
                    let src_is_v6 = src.socket_addr().map(|s| s.is_ipv6()).unwrap_or(false);
                    if let Some(len) = r.handle_query(&mdns_rx[..n], &mut mdns_tx) {
                        let dst = if qu {
                            src
                        } else if src_is_v6 {
                            peer_v6(MDNS_IPV6, MDNS_PORT)
                        } else {
                            peer_v4(MDNS_IPV4, MDNS_PORT)
                        };
                        let _ = mdns_udp.send_to(&mdns_tx[..len], dst).await;
                    }
                }
            }
            Either4::Third(Err(e)) => {
                println!("[mdns] recv error: {:?}", e);
            }
            Either4::Fourth(()) => {
                // 時間駆動: BTP 自身の遅延 ACK / idle 送出を排出する(毎周必須)。
                let now = now_ms(start);
                if let (Some(c), true) = (conn, subscribed) {
                    if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                        println!("[btp] flush(timer) error: {:?}", e);
                    }
                }
            }
        }

        // handshake 確立ログ。
        if !established_logged && btp.is_established() {
            established_logged = true;
            println!(
                "[btp] established (att_mtu={}, fragment={})",
                mtu.unwrap_or(0),
                btp.fragment_size()
            );
        }

        // --- 時間駆動の送出 + 閉じた exchange の回収(毎周必須)---
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, &mut txd) {
            if let Err(e) = route_send(
                gatt,
                &mut btp,
                matter_udp,
                d,
                &txd[..d.len],
                mtu,
                subscribed,
                now,
            )
            .await
            {
                println!("[stack] send(poll) error: {:?}", e);
            }
        }

        // ACK / idle タイムアウトで BTP セッションを畳んで再スタートに備える。
        let now = now_ms(start);
        if btp.is_timed_out(now) {
            println!("[btp] session timed out; disconnecting");
            btp.reset();
            established_logged = false;
            if let Some(c) = conn.take() {
                let _ = gatt.disconnect(c).await;
            }
        }

        // --- Wi-Fi join の結果(バックグラウンド)を NetworkCommissioning 属性へ反映 ---
        stack.device_mut().net.update_from_driver();

        // --- センサスナップショットの反映(世代変化時のみ)---
        let (gen, snap) = sensors::snapshot();
        if gen != sensor_gen {
            sensor_gen = gen;
            stack.device_mut().apply_snapshot(&snap);
        }

        // --- DHCP で IPv4 を取得したら運用 mDNS を開始する ---
        if mdns.is_none() {
            if let Some(cfg) = net_stack.config_v4() {
                let ip = cfg.address.address();
                println!("[net] DHCP up: ip={} gw={:?}", cfg.address, cfg.gateway);
                if let Err(e) = mdns_udp.join(v4_as_mapped(MDNS_IPV4)).await {
                    println!("[mdns] v4 multicast join error: {:?}", e);
                }
                if let Err(e) = mdns_udp.join(MDNS_IPV6).await {
                    println!("[mdns] v6 multicast join error: {:?}", e);
                }
                let host = simple_matter::discovery::Host::from_mac(
                    &mac,
                    Some(link_local_from_mac(&mac)),
                    Some(ip),
                );
                let mut r: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
                r.set_operational(
                    fabrics
                        .borrow()
                        .iter()
                        .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id())),
                );
                r.notify_change(now_ms(start));
                println!(
                    "[mdns] operational advertising on {}:{} + [{}%mld] (A={}, AAAA={})",
                    MDNS_IPV4,
                    MDNS_PORT,
                    MDNS_IPV6,
                    ip,
                    link_local_from_mac(&mac)
                );
                mdns = Some(r);
            }
        }

        // --- fabric 変更(generation)で flash 保存 + operational 広告更新 ---
        let gen = fabrics.borrow().generation();
        if gen != saved_gen {
            saved_gen = gen;
            {
                let table = fabrics.borrow();
                match table.save_to(kvs) {
                    Ok(()) => println!("[kvs] saved {} fabrics (generation={})", table.len(), gen),
                    Err(e) => println!("[kvs] save error: {:?}", e),
                }
            }
            if let Some(r) = mdns.as_mut() {
                r.set_operational(
                    fabrics
                        .borrow()
                        .iter()
                        .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id())),
                );
                r.notify_change(now_ms(start));
                println!(
                    "[mdns] operational records updated ({})",
                    r.operational_len()
                );
            }
            // 窓経由のコミッショニング成功(fabric 増加)で窓を閉じる(§11.19.5)。
            // Closed イベントが積まれ、次周の窓イベント処理で PASE/広告が畳まれる。
            let fabric_count = fabrics.borrow().len();
            if fabric_count > last_fabric_count && window.borrow().is_open() {
                window.borrow_mut().close_window();
                println!("[window] commissioning succeeded; closing window");
            }
            if boot_window_open && fabric_count > 0 && !window.borrow().is_open() {
                // 初回コミッショニング完了: 焼き込みパスコードの PASE を閉じる。
                // 以降の管理者追加は OCW(AdminCommissioning)経由のみ。
                boot_window_open = false;
                stack.set_pase_enabled(false);
                println!("[window] initial commissioning done; PASE disabled");
            } else if !boot_window_open && fabric_count == 0 && !window.borrow().is_open() {
                // 全 fabric 削除: 初期状態(焼き込みパスコード)へ戻す。
                boot_window_open = true;
                let cfg = simple_matter::dev_pase::dev_pase_config();
                stack.set_pase_config(cfg);
                stack.set_pase_enabled(true);
                println!("[window] all fabrics removed; reopening initial commissioning window");
            }
            last_fabric_count = fabric_count;
        }

        // --- コミッショニング窓イベントを PASE 設定と mDNS 広告へ反映する(設計 §4/§5)---
        // borrow を窓イベント取り出しとネスト利用で分ける(borrow がボディ全体で生存する罠)。
        let window_event = window.borrow_mut().take_event();
        if let Some(ev) = window_event {
            let now = now_ms(start);
            match ev {
                WindowEvent::OpenedEnhanced { discriminator } => {
                    if let Some(cfg) = window.borrow().pase_config() {
                        stack.set_pase_config(cfg);
                        stack.set_pase_enabled(true);
                        if let Some(r) = mdns.as_mut() {
                            r.set_commissionable(Some(commissionable(
                                &mac,
                                discriminator,
                                CommissioningMode::Enhanced,
                            )));
                            r.notify_change(now);
                        }
                        println!(
                            "[window] enhanced commissioning window open (CM=2, discriminator {})",
                            discriminator
                        );
                    }
                }
                WindowEvent::OpenedBasic => {
                    // 焼き込みパスコードへ戻す(PBKDF2 数百 ms、低頻度なので pump 停止は許容)。
                    let cfg = simple_matter::dev_pase::dev_pase_config();
                    stack.set_pase_config(cfg);
                    stack.set_pase_enabled(true);
                    if let Some(r) = mdns.as_mut() {
                        r.set_commissionable(Some(commissionable(
                            &mac,
                            DISCRIMINATOR,
                            CommissioningMode::Standard,
                        )));
                        r.notify_change(now);
                    }
                    println!("[window] basic commissioning window open (CM=1)");
                }
                WindowEvent::Closed => {
                    stack.set_pase_enabled(false);
                    if let Some(r) = mdns.as_mut() {
                        r.set_commissionable(None);
                        r.notify_change(now);
                    }
                    println!("[window] commissioning window closed");
                }
            }
            // AdminVendorId は fabric テーブルから解決して書き戻す(設計 §7)。
            let admin_idx = window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }

        // --- CASE resumption ストアの世代変化を検知して flash 保存(§7.4)---
        let rgen = stack.resumption_generation();
        if rgen != saved_resumption_gen {
            saved_resumption_gen = rgen;
            match stack.save_resumptions_to(kvs) {
                Ok(()) => println!("[kvs] saved {} resumptions", stack.resumption_count()),
                Err(e) => println!("[kvs] resumption save error: {:?}", e),
            }
        }

        // --- WiFi 資格情報の保存(ConnectNetwork で新しい join 要求が来たら)---
        if let Some(req) = take_pending_credentials() {
            let rec = encode_wifi_creds(&req);
            let mut existing = [0u8; WIFI_CREDS_RECORD_LEN];
            let same = matches!(
                kvs.get(WIFI_CREDS_KEY, &mut existing),
                Ok(Some(len)) if existing[..len] == rec[..]
            );
            if !same {
                match kvs.set(WIFI_CREDS_KEY, &rec) {
                    Ok(()) => println!("[kvs] saved wifi credentials"),
                    Err(e) => println!("[kvs] wifi credentials save error: {:?}", e),
                }
            }
        }

        // --- mDNS の定期 announce(未回答の gratuitous 広告。v4 + v6 両ファミリ)---
        if let Some(r) = mdns.as_mut() {
            if let Some(len) = r.poll_announce(now_ms(start), &mut mdns_tx) {
                let _ = mdns_udp
                    .send_to(&mdns_tx[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
                    .await;
                let _ = mdns_udp
                    .send_to(&mdns_tx[..len], peer_v6(MDNS_IPV6, MDNS_PORT))
                    .await;
            }
        }
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    // クロックを最大に設定して初期化(esp-radio は 80MHz 以上を要求)。
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: M5Stack AirQ (A5 stage-3: airq-sensor)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 (coex) + embassy-net 0.9");
    println!(" sensors  : SEN55 (sen5x-rs) + SCD40 (libscd) @ I2C SDA=11/SCL=12");
    println!("======================================================");

    // --- AirQ 固有の電源制御(airq-port.md §2)---
    // GPIO46 = HIGH で電源維持(バッテリー動作時の HOLD。USB 給電では無害)。
    let _hold = Output::new(peripherals.GPIO46, Level::High, OutputConfig::default());
    println!("[power] GPIO46 HOLD=HIGH");
    // GPIO10 = SEN55 電源(LOW で ON)。起動待ち 1 秒は sensor_task が担う。
    let sen55_power = Output::new(peripherals.GPIO10, Level::Low, OutputConfig::default());

    // Wi-Fi + BLE coex は esp-radio のヒープ要求が増える。C6 E5 は 144KiB だが、
    // S3 は DRAM リンカ領域が約 340KiB と狭く、.bss(ヒープ + embassy タスク POOL
    // 約 59KiB)の残りが main スタック(.stack)になる。144KiB では .stack が約
    // 37KiB しか残らず、コミッショニング中の P-256 署名(OpCreds invoke →
    // RcKeypair::sign)の同期呼び出し連鎖で stack guard 破壊 = 実機 PANIC を確認
    // (2026-07-12、AirQ 実機)。112KiB へ削減して .stack を約 70KiB 確保する
    // (ヒープ実測 max_usage は [alive] ログで監視)。
    esp_alloc::heap_allocator!(size: 112 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    // 「スケジューラ開始 → radio 初期化」の順序が必須(esp-radio ドキュメント)。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG。TrngSource は main の生存期間中保持し続ける(drop すると擬似乱数に戻る)。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = esp_rng();

    // BLE の static random address を TRNG から生成(上位 2 ビット = 0b11 が必須)。
    let mut addr = [0u8; 6];
    rng.fill_bytes(&mut addr).expect("TRNG fill");
    addr[5] |= 0xC0;
    println!(
        "[ble] static random address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    );

    // --- I2C バス(SDA=GPIO11 / SCL=GPIO12、100kHz = esp-hal 既定)---
    // SEN55(0x69)/ SCD40(0x62)/ RTC8563 が同居(airq-port.md §2 / R6。
    // 問題が出たら 50kHz へ落とす)。
    let i2c = I2c::new(peripherals.I2C0, I2cConfig::default())
        .expect("I2C init")
        .with_sda(peripherals.GPIO11)
        .with_scl(peripherals.GPIO12);
    println!("[i2c] SDA=GPIO11 SCL=GPIO12 100kHz (SEN55=0x69, SCD40=0x62)");

    // --- e-ink SPI(GDEW0154D67 = SSD1681 系。BUSY=1 RST=2 DC=3 CS=4 SCK=5 MOSI=6)---
    // 旧 FW は 40MHz だが SSD1681 定格に収まる 10MHz(mode 0)で駆動(display.rs)。
    let epd_spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default().with_frequency(Rate::from_mhz(10)),
    )
    .expect("SPI init")
    .with_sck(peripherals.GPIO5)
    .with_mosi(peripherals.GPIO6);
    let epd_cs = Output::new(peripherals.GPIO4, Level::High, OutputConfig::default());
    let epd_dc = Output::new(peripherals.GPIO3, Level::High, OutputConfig::default());
    let epd_rst = Output::new(peripherals.GPIO2, Level::High, OutputConfig::default());
    let epd_busy = Input::new(
        peripherals.GPIO1,
        InputConfig::default().with_pull(Pull::Up),
    );
    println!("[epd] SPI2 10MHz (BUSY=1 RST=2 DC=3 CS=4 SCK=5 MOSI=6)");

    // --- Wi-Fi station(esp-radio、BLE と coex)+ embassy-net(DHCPv4)---
    let (wifi_controller, wifi_interfaces) = esp_radio::wifi::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .expect("Wi-Fi controller init");
    let sta = wifi_interfaces.station;
    let mac = sta.mac_address();
    println!(
        "[wifi] STA MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    let mut seed_bytes = [0u8; 8];
    rng.fill_bytes(&mut seed_bytes).expect("TRNG fill");
    let seed = u64::from_le_bytes(seed_bytes);
    // ソケット枠: Matter UDP + mDNS + DHCPv4 + 予備。
    let mut net_resources: StackResources<6> = StackResources::new();
    // IPv4 は DHCPv4、IPv6 は MAC 由来の fe80 リンクローカルを静的設定する。
    let ll_v6 = link_local_from_mac(&mac);
    println!("[net] IPv6 link-local: {}", ll_v6);
    let mut net_config = embassy_net::Config::dhcpv4(Default::default());
    net_config.ipv6 = embassy_net::ConfigV6::Static(embassy_net::StaticConfigV6 {
        address: embassy_net::Ipv6Cidr::new(ll_v6, 64),
        gateway: None,
        dns_servers: Default::default(),
    });
    let (net_stack, mut net_runner) = embassy_net::new(sta, net_config, &mut net_resources, seed);

    // Matter UDP(5540)。CASE over UDP / IM の運用トラフィックが通る。
    let mut m_rx_meta = [PacketMetadata::EMPTY; 8];
    let mut m_tx_meta = [PacketMetadata::EMPTY; 8];
    let mut m_rx_buf = [0u8; 4096];
    let mut m_tx_buf = [0u8; 4096];
    let mut matter_sock = UdpSocket::new(
        net_stack,
        &mut m_rx_meta,
        &mut m_rx_buf,
        &mut m_tx_meta,
        &mut m_tx_buf,
    );
    matter_sock.bind(MATTER_PORT).expect("bind 5540");
    let mut matter_udp = EspUdp::new(matter_sock, net_stack);

    // mDNS(5353)。マルチキャスト join は DHCP up 後に行う(pump 内)。
    let mut d_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut d_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut d_rx_buf = [0u8; 2048];
    let mut d_tx_buf = [0u8; 2048];
    let mut mdns_sock = UdpSocket::new(
        net_stack,
        &mut d_rx_meta,
        &mut d_rx_buf,
        &mut d_tx_meta,
        &mut d_tx_buf,
    );
    mdns_sock.bind(MDNS_PORT).expect("bind 5353");
    let mut mdns_udp = EspUdp::new(mdns_sock, net_stack);

    // --- MatterStack 構築(乱数は全て TRNG)---
    let crypto = RustCrypto::new(esp_rng());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());
    // コミッショニング窓(AdminCommissioning 0x003C とpump が共有)。
    let window: RefCell<CommissioningWindow> = RefCell::new(CommissioningWindow::new());

    // flash KVS から fabric テーブルを復元する。
    let mut kvs = EspKvs::new(peripherals.FLASH);
    let restore = fabrics.borrow_mut().load_from(&mut kvs, &crypto, 0);
    match restore {
        Ok(n) => println!("[kvs] restored {} fabrics", n),
        Err(e) => {
            println!(
                "[kvs] restore failed: {:?}; starting with empty fabric table",
                e
            );
            *fabrics.borrow_mut() = FabricTable::new();
        }
    }

    // SPAKE2+ 検証子の導出(PBKDF2)は数百 ms かかるため進捗を出す。
    println!("[pase] loading embedded dev SPAKE2+ verifier (device holds no passcode)...");
    let pase = simple_matter::dev_pase::dev_pase_config();
    println!("[pase] verifier ready");

    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, esp_rng(), pase, creds);
    let im = InteractionModel::new(build_device(&fabrics, &window));
    let mut stack: AirqStack<'_> = MatterStack::new(&crypto, sc, im);
    // コミッショニング済みで起動した場合、焼き込みパスコードの PASE は閉じる
    // (管理者追加は OCW 経由のみ。PC example と同じ窓ゲート)。
    if !fabrics.borrow().is_empty() {
        stack.set_pase_enabled(false);
        println!("[pase] disabled at boot (already commissioned; use OCW to add admins)");
    }
    // 起動イベント(BasicInformation StartUp、CRITICAL、{ softwareVersion })を積む。
    let _ = stack.post_startup_event(CFG.software_version, 0);
    println!(
        "[stack] DefaultStack ready ({} bytes, on main stack)",
        core::mem::size_of::<AirqStack<'static>>()
    );

    // CASE resumption 素材を flash KVS から復元する(fabric 復元直後)。
    match stack.load_resumptions_from(&mut kvs) {
        Ok(n) => println!("[kvs] restored {} resumptions", n),
        Err(e) => println!("[kvs] resumption restore failed: {:?}", e),
    }

    // WiFi 資格情報を flash KVS から復元し、自動再 join を仕掛ける(リブート後 E2E 用)。
    {
        let mut rec = [0u8; WIFI_CREDS_RECORD_LEN];
        match kvs.get(WIFI_CREDS_KEY, &mut rec) {
            Ok(Some(len)) => match decode_wifi_creds(&rec[..len]) {
                Some(req) => {
                    println!("[kvs] restored wifi credentials; auto-joining");
                    EspWifiDriver.connect(req.ssid(), req.pass());
                }
                None => println!("[kvs] wifi credentials record invalid; ignoring"),
            },
            Ok(None) => {}
            Err(e) => println!("[kvs] wifi credentials read failed: {:?}", e),
        }
    }

    // --- BLE controller(esp-radio HCI)→ TrouBLE host ---
    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    let mut resources: HostResources<DefaultPacketPool, 1, 1> = HostResources::new();
    let ble_stack =
        trouble_host::new(controller, &mut resources).set_random_address(Address::random(addr));
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = ble_stack.build();

    // GATT サーバ(GAP + Matter BTP service)。
    let server =
        BtpGattServer::new_with_config(trouble_host::gap::GapConfig::default("simple-matter"))
            .expect("GATT server build");

    // GattPeripheral 実装(channel で worker と接続)。
    let channels = GattChannels::new();
    let mut gatt = TroubleGattPeripheral::new(&channels);

    let adv = AdvData {
        discriminator: DISCRIMINATOR,
        vendor_id: CFG.vendor_id,
        product_id: CFG.product_id,
        additional_data: false,
        ext_announcement: false,
    };
    gatt.start_advertising(&adv)
        .await
        .expect("start_advertising");

    println!(
        "[boot] dev verifier (passcode 20202021, not stored) discriminator={} vid={:#06x} pid={:#06x}",
        DISCRIMINATOR, CFG.vendor_id, CFG.product_id
    );
    println!(
        "[boot] commission with: chip-tool pairing ble-wifi 1 <ssid> <pass> {} {} --bypass-attestation-verifier true",
        20202021, DISCRIMINATOR
    );

    // TrouBLE host runner / GATT worker / Wi-Fi task / embassy-net runner / pump /
    // センサタスク / e-ink 表示タスクを単一 executor 上で並走させる。
    join3(
        join5(
            async {
                // runner は HCI イベントループ。落ちたら BLE 全体が止まるので panic で知らせる。
                let e = runner.run().await;
                panic!("[ble] host runner exited: {:?}", e);
            },
            gatt_worker(&mut peripheral, &server, &channels),
            wifi_task(wifi_controller),
            net_runner.run(),
            pump(
                &mut gatt,
                &mut stack,
                &fabrics,
                &window,
                &mut kvs,
                net_stack,
                &mut matter_udp,
                &mut mdns_udp,
                mac,
            ),
        ),
        sensor_task(i2c, sen55_power),
        display_task(epd_spi, epd_cs, epd_busy, epd_dc, epd_rst),
    )
    .await;
    unreachable!();
}
