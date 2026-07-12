//! K3 冒頭スモークゲート — TrouBLE central の scan 適合検証(リスク R1 消し込み)。
//!
//! `docs/design/esp32-controller.md` §7 K3。**BLE スキャンだけ**を行い、
//! `Runner::run_with_handler` の [`EventHandler::on_adv_reports`] で受けた広告から
//! 0xFFF6(Matter BLE Service)の service data を解析して discriminator / VID / PID を
//! ログに出す。ここで確認するのは:
//!
//! 1. trouble-host 0.6 の feature `central`,`scan` が esp-radio 0.18 の S3 で
//!    ビルド・動作すること(リポジトリ内に前例がない組み合わせ)。
//! 2. adv report が callback([`EventHandler`])経由で届き、
//!    `AdStructure::decode` → `ServiceData16 { uuid: 0xFFF6 }` →
//!    [`AdvData::parse_service_data`](コア)で discriminator が読めること。
//!
//! 対向: PC の `ble-onoff-light` example(bluer、discriminator=3840)を advertise
//! させる。WiFi は使わない(coex 下の挙動は K3 本体で見る。R2)。
//!
//! 実行: `cd ports/esp32s3 && cargo build --release --bin s3-scan-smoke`
//! 対向(PC): `SM_BLE_ADAPTER=hci1 cargo run --release -p simple-matter-ble \
//!            --features device --example ble-onoff-light`

#![no_std]
#![no_main]

use esp_backtrace as _;

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_time::Timer;

use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use simple_matter::btp::gatt::AdvData;
use simple_matter::crypto::Rng;

use esp32s3_firmware::EspRng;

esp_bootloader_esp_idf::esp_app_desc!();

/// HCI コマンドの同時実行スロット数(既存 bin と同値)。
const HCI_SLOTS: usize = 20;

/// 発見済み report の通算数(handler は `&self` のみなので atomic で数える)。
static REPORT_COUNT: AtomicU32 = AtomicU32::new(0);
static MATTER_COUNT: AtomicU32 = AtomicU32::new(0);

/// adv report を受けて 0xFFF6 service data を解析するハンドラ。
///
/// スモークなので発見のたびに直接ログへ出す(頻度は広告間隔なみ。うるさければ
/// dedupe するが、まずは「届いた生の事実」を見たい)。
struct SmokeHandler;

impl EventHandler for SmokeHandler {
    fn on_adv_reports(&self, mut reports: bt_hci::param::LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = reports.next() {
            REPORT_COUNT.fetch_add(1, Ordering::Relaxed);
            for ad in AdStructure::decode(report.data).flatten() {
                // ServiceData16 の uuid は LE バイト列(0xFFF6 → [0xF6, 0xFF])。
                let AdStructure::ServiceData16 {
                    uuid: [0xF6, 0xFF],
                    data,
                } = ad
                else {
                    continue;
                };
                let n = MATTER_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                let Ok(sd): Result<[u8; 8], _> = data.try_into() else {
                    println!("[scan] 0xFFF6 service data with odd length {}", data.len());
                    continue;
                };
                match AdvData::parse_service_data(&sd) {
                    Ok(adv) => println!(
                        "[scan] #{} matter commissionable: addr={:02x?} rssi={} \
                         discriminator={} vid={:#06x} pid={:#06x}",
                        n,
                        report.addr.raw(),
                        report.rssi,
                        adv.discriminator,
                        adv.vendor_id,
                        adv.product_id
                    ),
                    Err(e) => println!("[scan] 0xFFF6 service data parse error: {:?}", e),
                }
            }
        }
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-S3 controller (K3 gate: s3-scan-smoke)");
    println!(" scope    : TrouBLE central scan -> 0xFFF6 service data");
    println!("======================================================");

    esp_alloc::heap_allocator!(size: 112 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = EspRng(Trng::try_new().expect("TRNG"));

    // BLE の static random address(上位 2 ビット = 0b11 必須。既存 bin と同じ)。
    let mut addr = [0u8; 6];
    rng.fill_bytes(&mut addr).expect("TRNG fill");
    addr[5] |= 0xC0;

    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    let mut resources: HostResources<DefaultPacketPool, 1, 1> = HostResources::new();
    let ble_stack =
        trouble_host::new(controller, &mut resources).set_random_address(Address::random(addr));
    let Host {
        central,
        mut runner,
        ..
    } = ble_stack.build();

    let handler = SmokeHandler;
    join(
        async {
            let e = runner.run_with_handler(&handler).await;
            panic!("[ble] host runner exited: {:?}", e);
        },
        async {
            // Scanner は central を消費する(scan 停止 = ScanSession の drop)。
            // スモークでは常時スキャンのまま回す。
            let mut scanner = Scanner::new(central);
            let config = ScanConfig::default(); // active、interval=window=1s(常時)
            let _session = scanner.scan(&config).await.expect("scan start");
            println!("[scan] started (active, interval=window=1s)");
            loop {
                Timer::after_secs(5).await;
                println!(
                    "[alive] reports={} matter={}",
                    REPORT_COUNT.load(Ordering::Relaxed),
                    MATTER_COUNT.load(Ordering::Relaxed)
                );
            }
        },
    )
    .await;
    unreachable!();
}
