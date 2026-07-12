//! AirQ 実機センサ(SEN55 + SCD40)の統合(A5 段階 3)。
//!
//! `docs/design/airq-port.md` §1.3 / §2 のハード知識を Rust 既製 crate で実装する:
//!
//! - **SEN55**(I2C 0x69、PM1/2.5/10 + 温湿度 + VOC/NOx index):
//!   [`sen5x-rs` 0.4](https://crates.io/crates/sen5x-rs)(embedded-hal 1.0)。
//!   電源は **GPIO10 = LOW で ON**(ロードスイッチ)、ON 後 **1 秒待ち**必須。
//!   計測周期 10 秒(既存 esp-matter FW と同じ)。
//! - **SCD40**(I2C 0x62、CO2 + 温湿度):
//!   [`libscd` 0.5](https://crates.io/crates/libscd)(features = sync/scd4x)。
//!   初期化は既存 FW のシーケンス踏襲: `stop_periodic_measurement` →
//!   `reinit` → `start_periodic_measurement`(SCD40 は wake_up 非対応 =
//!   SCD41 専用コマンドのため省略)。計測周期 30 秒(既存 FW と同じ。
//!   定格 5 秒だが電力/自己発熱への配慮)。
//! - I2C バス共有(SDA=GPIO11 / SCL=GPIO12、100kHz、RTC8563 同居):
//!   `embedded-hal-bus` の [`RefCellDevice`] で 1 本のバスを 2 ドライバへ分配
//!   (単一タスクが順番に触るため競合しない)。
//!
//! # crate 選定メモ(airq-port.md R2)
//!
//! - `sen5x-rs` 0.4.0: embedded-hal 1.0、no_std。スケーリング(PM ×10、湿度 ×100、
//!   温度 ×200、index ×10)は既存 FW の知識と一致することをソースで確認済み。
//!   **既知の癖: 温度を u16 として解釈する**(SEN55 データシートは i16)ため、
//!   氷点下で不正値になる。[`fix_sen55_temp`] で i16 に再解釈して補正する。
//! - `libscd` 0.5.1: embedded-hal(-async) 1.0、no_std、SCD40/41 両対応。
//!   コマンド毎の実行待ち(stop = 500ms 等)をドライバ内部で処理する。
//!   代替候補だった `scd4x` crate ではなくこちらを採用(sync/async 両対応で
//!   API が新しく、SCD40 で使えないコマンドが feature 分離されているため)。
//!
//! # 統合の形
//!
//! [`sensor_task`] が I2C バスと SEN55 電源 GPIO を所有する常駐タスク(pump と
//! 並走)で、計測値を [`SensorSnapshot`](世代カウンタ付き共有 static)へ置く。
//! pump 側は世代変化を見て Matter クラスタ(`set_measured`)へ反映する。
//! ドライバは blocking(数 ms 級の I2C 取引 + 初期化時のみ 500ms 級の内部待ち)
//! だが、常駐 executor を止める時間は定常状態で無視できる。

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_time::Timer;
use embedded_hal_bus::i2c::RefCellDevice;
use esp_hal::delay::Delay;
use esp_hal::gpio::Output;
use esp_hal::i2c::master::I2c;
use esp_hal::Blocking;
use esp_println::println;

use libscd::synchronous::scd4x::Scd4x;
use sen5x_rs::Sen5x;

/// SEN55 の計測周期(秒)。既存 FW と同じ(airq-port.md §1.3)。
const SEN55_PERIOD_S: u64 = 10;
/// SCD40 の計測周期(秒)。既存 FW と同じ(定格 5 秒だが自己発熱配慮で 30 秒)。
const SCD40_PERIOD_S: u64 = 30;
/// SEN55 電源 ON(GPIO10 = LOW)後の起動待ち(ms)。1 秒必須(§1.3)。
const SEN55_POWER_ON_WAIT_MS: u64 = 1000;
/// SEN55 温度の自己発熱補正オフセット(°C、読み値から減算)。
///
/// 根拠(airq-port.md §7.4): AirQ 同一筐体の ESPHome コミュニティ設定が
/// `temperature_compensation: offset: -3.0`(devices.esphome.io/devices/m5stack-airq)。
/// M5Stack 公式 FW(AirQUserDemo)は補正 0 で、公式サンプルデータでも SEN55 36°C 級の
/// 自己発熱を記録している。Sensirion 公式は「筐体ごとに実測して決める」立場
/// (SEN5x Temperature Acceleration and Compensation Instructions)。既存 esp-matter FW
/// の 9°C(Kconfig 既定)は **SCD4x 側** のオフセットで SEN55 には流用できない。
/// センサ内蔵の 0x60B2 補正(湿度も連動補正される)は sen5x-rs 0.4 が未対応のため
/// ソフト減算とする(湿度の連動補正は将来課題)。
pub const SEN55_TEMP_OFFSET_C: f32 = 3.0;
/// SEN55 reinit 後の待ち(ms)。データシートのリセット完了 100ms + 余裕。
const SEN55_REINIT_WAIT_MS: u64 = 200;

/// 最新の実測値スナップショット(未計測の項目は `None`)。
///
/// 値は物理量(f32)。Matter クラスタへの写像(温度 ×100 の i16 等)は pump 側で行う。
#[derive(Debug, Clone, Copy, Default)]
pub struct SensorSnapshot {
    /// CO2 濃度 ppm(SCD40)。
    pub co2_ppm: Option<f32>,
    /// PM1.0 µg/m³(SEN55)。
    pub pm1: Option<f32>,
    /// PM2.5 µg/m³(SEN55)。
    pub pm25: Option<f32>,
    /// PM10 µg/m³(SEN55)。
    pub pm10: Option<f32>,
    /// 温度 ℃(SEN55、[`SEN55_TEMP_OFFSET_C`] の自己発熱補正適用済み)。
    pub temp_c: Option<f32>,
    /// 相対湿度 %RH(SEN55)。
    pub rh: Option<f32>,
    /// Sensirion VOC index(1-500、無次元)。クラスタへは載せず
    /// AirQuality 算出やログの参考値(airq-port.md §4.3)。
    pub voc_index: Option<f32>,
    /// Sensirion NOx index(1-500、無次元)。同上。
    pub nox_index: Option<f32>,
    /// SCD40 側の温度 ℃(参考ログ用。クラスタへは SEN55 側を採用)。
    pub scd40_temp_c: Option<f32>,
    /// SCD40 側の湿度 %RH(参考ログ用)。
    pub scd40_rh: Option<f32>,
}

/// 共有スナップショット([`sensor_task`] が書き、pump が読む)。
static SNAPSHOT: Mutex<CriticalSectionRawMutex, RefCell<SensorSnapshot>> =
    Mutex::new(RefCell::new(SensorSnapshot {
        co2_ppm: None,
        pm1: None,
        pm25: None,
        pm10: None,
        temp_c: None,
        rh: None,
        voc_index: None,
        nox_index: None,
        scd40_temp_c: None,
        scd40_rh: None,
    }));
/// スナップショットの世代(更新毎に +1)。pump は変化を見て clusters へ反映する。
static GENERATION: AtomicU32 = AtomicU32::new(0);

/// 現在のスナップショットと世代を取得する(コピー。ロック区間は最小)。
pub fn snapshot() -> (u32, SensorSnapshot) {
    let snap = SNAPSHOT.lock(|cell| *cell.borrow());
    (GENERATION.load(Ordering::Acquire), snap)
}

/// スナップショットを更新して世代を進める。
fn publish(update: impl FnOnce(&mut SensorSnapshot)) {
    SNAPSHOT.lock(|cell| update(&mut cell.borrow_mut()));
    GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// sen5x-rs 0.4.0 の温度 u16 解釈(データシートは i16 ×200)を補正する。
///
/// crate は `u16::from_be_bytes(..) as f32 / 200.0` を返すため、氷点下は
/// 「65536/200 = 327.68 から下がる」大きな正値として現れる。raw に戻して
/// i16 として再解釈する(0℃ 以上は恒等変換)。
fn fix_sen55_temp(reported: f32) -> f32 {
    let raw = (reported * 200.0 + 0.5) as u32;
    (raw as u16 as i16) as f32 / 200.0
}

/// SEN55 + SCD40 を駆動する常駐タスク(pump と並走)。
///
/// - `i2c`: SDA=GPIO11 / SCL=GPIO12 の I2C バス(100kHz、blocking)。
/// - `sen55_power`: GPIO10(LOW = ON で構築済みの [`Output`])。本タスクが
///   起動待ち 1 秒を担う。
///
/// 初期化失敗はリトライ(5 秒間隔)。定常の読み取り失敗はログして次周期へ
/// (連続失敗でもタスクは死なない。値は最後に成功したものが残る)。
pub async fn sensor_task(i2c: I2c<'static, Blocking>, mut sen55_power: Output<'static>) -> ! {
    // SEN55 電源 ON(LOW)→ 1 秒の起動待ち(airq-port.md §1.3)。
    sen55_power.set_low();
    println!("[sensors] SEN55 power on (GPIO10=LOW); waiting 1s for boot");
    Timer::after_millis(SEN55_POWER_ON_WAIT_MS).await;

    // 1 本の I2C バスを RefCell 共有で 2 ドライバに分配する。
    let bus = RefCell::new(i2c);
    let mut sen55 = Sen5x::new(RefCellDevice::new(&bus), Delay::new());
    let mut scd40 = Scd4x::new(RefCellDevice::new(&bus), Delay::new());

    // --- SCD40 初期化(既存 FW のシーケンス踏襲。§1.3)---
    // 前回起動の周期計測が残っていても止まるよう stop → reinit → start。
    // 温度オフセットはセンサ EEPROM の既定値(4℃)を維持する(既存 FW は
    // Kconfig 値を書いていたが、本 FW は温湿度を SEN55 側から採るため
    // SCD40 の温度は参考ログのみ)。
    loop {
        let r = scd40
            .stop_periodic_measurement()
            .and_then(|()| scd40.reinit())
            .and_then(|()| scd40.serial_number())
            .and_then(|serial| {
                println!("[sensors] SCD40 serial={:012x}", serial);
                scd40.start_periodic_measurement()
            });
        match r {
            Ok(()) => {
                println!("[sensors] SCD40 periodic measurement started");
                break;
            }
            Err(e) => {
                println!("[sensors] SCD40 init failed: {:?}; retrying in 5s", e);
                Timer::after_secs(5).await;
            }
        }
    }

    // --- SEN55 初期化(reinit → start_measurement)---
    loop {
        let r = sen55.reinit();
        if let Err(e) = r {
            println!("[sensors] SEN55 reinit failed: {:?}; retrying in 5s", e);
            Timer::after_secs(5).await;
            continue;
        }
        Timer::after_millis(SEN55_REINIT_WAIT_MS).await;
        match sen55.serial_number().and_then(|serial| {
            println!("[sensors] SEN55 serial={:012x}", serial);
            sen55.start_measurement()
        }) {
            Ok(()) => {
                println!("[sensors] SEN55 measurement started (fan spin-up)");
                break;
            }
            Err(e) => {
                println!("[sensors] SEN55 start failed: {:?}; retrying in 5s", e);
                Timer::after_secs(5).await;
            }
        }
    }

    // --- 定常ループ: SEN55 は 10 秒周期、SCD40 は 30 秒周期で read ---
    // 1 秒 tick で経過秒を数える(embassy-time)。data_ready を確認してから読む。
    let mut t: u64 = 0;
    loop {
        Timer::after_secs(1).await;
        t += 1;

        if t.is_multiple_of(SEN55_PERIOD_S) {
            match sen55.data_ready_status() {
                Ok(true) => match sen55.measurement() {
                    Ok(d) => {
                        // 自己発熱補正: 生値(raw)から固定オフセットを減算する。
                        // 補正前後をログに並記する(補正値の妥当性検証のため)。
                        let raw_temp = fix_sen55_temp(d.temperature);
                        let temp = raw_temp - SEN55_TEMP_OFFSET_C;
                        publish(|s| {
                            s.pm1 = Some(d.pm1_0);
                            s.pm25 = Some(d.pm2_5);
                            s.pm10 = Some(d.pm10_0);
                            s.temp_c = Some(temp);
                            s.rh = Some(d.humidity);
                            s.voc_index = Some(d.voc_index);
                            s.nox_index = Some(d.nox_index);
                        });
                        println!(
                            "[sensors] SEN55 pm1={} pm2.5={} pm10={} T={}C (raw={}C offset=-{}C) RH={}% voc={} nox={}",
                            d.pm1_0,
                            d.pm2_5,
                            d.pm10_0,
                            temp,
                            raw_temp,
                            SEN55_TEMP_OFFSET_C,
                            d.humidity,
                            d.voc_index,
                            d.nox_index
                        );
                    }
                    Err(e) => println!("[sensors] SEN55 read failed: {:?}", e),
                },
                Ok(false) => println!("[sensors] SEN55 data not ready (t={}s)", t),
                Err(e) => println!("[sensors] SEN55 data_ready failed: {:?}", e),
            }
        }

        if t.is_multiple_of(SCD40_PERIOD_S) {
            match scd40.data_ready() {
                Ok(true) => match scd40.read_measurement() {
                    Ok(m) => {
                        publish(|s| {
                            s.co2_ppm = Some(m.co2 as f32);
                            s.scd40_temp_c = Some(m.temperature);
                            s.scd40_rh = Some(m.humidity);
                        });
                        println!(
                            "[sensors] SCD40 co2={}ppm T={}C RH={}%",
                            m.co2, m.temperature, m.humidity
                        );
                    }
                    Err(e) => println!("[sensors] SCD40 read failed: {:?}", e),
                },
                Ok(false) => println!("[sensors] SCD40 data not ready (t={}s)", t),
                Err(e) => println!("[sensors] SCD40 data_ready failed: {:?}", e),
            }
        }
    }
}
