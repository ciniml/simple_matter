//! 生 HCI での BLE アドバタイズ・スモークテスト(E2 切り分け用、一時 bin)。
//!
//! trouble-host を外し、esp-radio の BLE controller に直接 HCI コマンド
//! (Reset → LE Set Adv Params → LE Set Adv Data → LE Set Adv Enable)を打って、
//! **コントローラ単体で電波が出るか**を確認する。
//!
//! - 電波が出る(PC の `bluetoothctl scan on` に `hcismoke` が見える)
//!   → コントローラ・ボードはシロ。問題は trouble-host 層。
//! - 出ない → esp-radio 0.18 の C6 controller / 初期化経路の問題。
//!
//! own address は PUBLIC(efuse MAC)を使い、random address 設定経路も外す。

#![no_std]
#![no_main]

use esp_backtrace as _;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_time::Timer;

use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::cmd::controller_baseband::Reset;
use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams};
use bt_hci::controller::{Controller, ControllerCmdSync, ExternalController};
use bt_hci::param::{AddrKind, AdvChannelMap, AdvFilterPolicy, AdvKind, BdAddr};
use esp_radio::ble::controller::BleConnector;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!("[hci-smoke] boot");

    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let controller: ExternalController<_, 4> = ExternalController::new(connector);

    // exec の完了は read() 側で処理されるため、読み取りポンプを併走させる。
    let read_pump = async {
        let mut rx = [0u8; 259];
        loop {
            match controller.read(&mut rx).await {
                Ok(_pkt) => println!("[hci-smoke] rx event"),
                Err(_) => println!("[hci-smoke] rx error"),
            }
        }
    };

    let sequence = async {
        Timer::after_millis(100).await;
        println!("[hci-smoke] HCI Reset...");
        controller.exec(&Reset::new()).await.expect("reset");
        println!("[hci-smoke] LE Set Adv Params...");
        controller
            .exec(&LeSetAdvParams::new(
                bt_hci::param::Duration::from_millis(160),
                bt_hci::param::Duration::from_millis(160),
                AdvKind::AdvInd,
                AddrKind::PUBLIC,
                AddrKind::PUBLIC,
                BdAddr::default(),
                AdvChannelMap::ALL,
                AdvFilterPolicy::default(),
            ))
            .await
            .expect("adv params");
        println!("[hci-smoke] LE Set Adv Data...");
        // AD: Flags(LE General Discoverable, BR/EDR 非対応) + Complete Local Name "hcismoke"
        let mut data = [0u8; 31];
        let ad: [u8; 13] = [
            0x02, 0x01, 0x06, 0x09, 0x09, b'h', b'c', b'i', b's', b'm', b'o', b'k', b'e',
        ];
        data[..ad.len()].copy_from_slice(&ad);
        controller
            .exec(&LeSetAdvData::new(ad.len() as u8, data))
            .await
            .expect("adv data");
        println!("[hci-smoke] LE Set Adv Enable...");
        controller
            .exec(&LeSetAdvEnable::new(true))
            .await
            .expect("adv enable");
        println!("[hci-smoke] advertising as 'hcismoke' (public address)");
        let mut tick = 0u32;
        loop {
            Timer::after_millis(1000).await;
            tick += 1;
            println!("[hci-smoke] alive {}", tick);
        }
    };

    join(read_pump, sequence).await;
    unreachable!();
}
