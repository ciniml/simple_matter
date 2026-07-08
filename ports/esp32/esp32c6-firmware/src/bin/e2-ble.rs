//! ESP32-C6 向け simple-matter ポート — フェーズ E2: BLE アドバタイズ + BTP handshake。
//!
//! `docs/design/port-esp32-device.md` §8「E2: BLE スモーク → GattPeripheral」の実装。
//! このファームウェアが実機で証明すること(検証ゲート):
//!
//! 1. esp-radio(BLE controller)+ TrouBLE(host)で 0xFFF6 service data の
//!    commissionable アドバタイズが出る。
//! 2. Matter GATT service(C1 write / C2 indicate)が立ち、コアの `GattPeripheral`
//!    trait 実装([`TroubleGattPeripheral`])経由でイベントが流れる。
//! 3. PC の `ble-commissioner` からの **BTP handshake が確立**する(fragment 交渉まで。
//!    PASE 以降は E3 スコープ)。確立時に `[btp] established (att_mtu=..., fragment=...)`
//!    を出力する。
//!
//! # pump ループの構造(ble-btp.md §6.2 の embassy 版)
//!
//! PC 版 `ble-onoff-light.rs` の select ループを embassy に写像した BTP 単体版。
//! MatterStack は載せない(E2 スコープ外)ため、確立後の C1 write(PASE 等)は
//! 再組立して受信ログを出すのみ。
//!
//! - **確立順序**: central は C1 write(handshake req)→ C2 subscribe の順で来る。
//!   handshake 応答の indicate は **C2Subscribed 後まで保留**する(subscribe 前の
//!   indication は捨てられ handshake がタイムアウトする。chip 実機で裏取り済みの制約)。
//! - **毎周 `Btp::next_deadline` を見て flush**: 遅延 ACK / idle 送出を取りこぼさない。
//! - 切断で BTP をリセットし、worker が自動再アドバタイズする。
//!
//! 実行: `cd ports/esp32 && cargo run --release --bin e2-ble`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select, Either};
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::Rng;
use simple_matter::error::Result as MResult;
use simple_matter::transport::net::{BtpConnId, MAX_RX_PACKET_SIZE};

use esp32c6_firmware::ble::{gatt_worker, BtpGattServer, GattChannels, TroubleGattPeripheral};
use esp32c6_firmware::EspRng;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須。
// 無いとブートローダがアプリを起動できず TG0 WDT リセットループになる)。
esp_bootloader_esp_idf::esp_app_desc!();

/// コミッショニング discriminator(12 ビット)。PC example `ble-onoff-light` と同値。
const DISCRIMINATOR: u16 = 3840;
/// Vendor ID(PC example と同値)。
const VENDOR_ID: u16 = 0xFFF1;
/// Product ID(PC example と同値)。
const PRODUCT_ID: u16 = 0x8001;

/// BTP フラグメントの先頭バイトトレース(PC 版 `SM_BTP_TRACE` の trace() と同形式)。
/// 実機切り分け用にコンパイル時 const で常時有効。
const BTP_TRACE: bool = true;

/// HCI コマンドの同時実行スロット数(ExternalController の const パラメータ)。
const HCI_SLOTS: usize = 20;

fn trace(dir: &str, frag: &[u8]) {
    if BTP_TRACE {
        let mut head = [0u8; 5];
        let n = frag.len().min(5);
        head[..n].copy_from_slice(&frag[..n]);
        match n {
            0 => println!("[btp {}] len={}", dir, frag.len()),
            1 => println!("[btp {}] len={} {:02x}", dir, frag.len(), head[0]),
            2 => println!(
                "[btp {}] len={} {:02x} {:02x}",
                dir,
                frag.len(),
                head[0],
                head[1]
            ),
            3 => println!(
                "[btp {}] len={} {:02x} {:02x} {:02x}",
                dir,
                frag.len(),
                head[0],
                head[1],
                head[2]
            ),
            4 => println!(
                "[btp {}] len={} {:02x} {:02x} {:02x} {:02x}",
                dir,
                frag.len(),
                head[0],
                head[1],
                head[2],
                head[3]
            ),
            _ => println!(
                "[btp {}] len={} {:02x} {:02x} {:02x} {:02x} {:02x}",
                dir,
                frag.len(),
                head[0],
                head[1],
                head[2],
                head[3],
                head[4]
            ),
        }
    }
}

/// 単調時刻(ms)。BTP コアの `now_ms` 注入に使う(embassy-time の Instant 起点)。
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis()
}

/// BTP が吐く下りフラグメントを尽きるまで C2 indication で送出する(PC 版 flush_out)。
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

/// BTP エンジンを駆動する統合層(pump)。PC 版 ble-onoff-light の BLE 経路のみ版。
async fn pump(gatt: &mut TroubleGattPeripheral<'_>) -> ! {
    let mut btp = Btp::<6>::new(BtpRole::Peripheral);
    let mut conn: Option<BtpConnId> = None;
    let mut mtu: Option<u16> = None;
    // central(chip-tool / PC ble-commissioner)は handshake req の C1 write を
    // C2 subscribe より先に行う。subscribe 前の indicate は捨てられるため、
    // subscribe 済みになるまで送出(flush_out)を保留する(ble-btp.md の確立順序)。
    let mut subscribed = false;
    let mut established_logged = false;

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    // 生存確認ログ。シリアルは任意のタイミングで接続される(過去分は残らない)ため、
    // いつ繋いでも状態がわかるよう定期出力する(実機切り分けで必須と判明)。
    let mut next_heartbeat_ms: u64 = 0;

    loop {
        let now = now_ms(start);
        if now >= next_heartbeat_ms {
            println!(
                "[alive] t={}s conn={:?} subscribed={}",
                now / 1000,
                conn.map(|c| c.0),
                subscribed
            );
            next_heartbeat_ms = now + 10_000;
        }

        // BTP の deadline(遅延 ACK / idle)まで待つ。上限 50ms でクリップして
        // タイムアウト検知(is_timed_out)も定期的に回す。
        let now = now_ms(start);
        let sleep_ms = match btp.next_deadline() {
            Some(t) if t > now => (t - now).min(50),
            Some(_) => 0,
            None => 50,
        };

        match select(gatt.next_event(&mut buf), Timer::after_millis(sleep_ms)).await {
            Either::First(Ok(ev)) => {
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
                        // 保留していた handshake 応答をここで排出する。
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
                        // 再組立できた Matter メッセージは E2 では受信ログのみ
                        // (MatterStack への接続は E3 スコープ)。
                        while let Some(n) = take_sdu(&mut btp, &mut sdu) {
                            println!("[btp] rx sdu: len={} (matter message; ignored in E2)", n);
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
            Either::First(Err(e)) => {
                println!("[ble] next_event error: {:?}", e);
            }
            Either::Second(()) => {
                // 時間駆動: BTP 自身の遅延 ACK / idle 送出を排出する(毎周必須)。
                let now = now_ms(start);
                if let (Some(c), true) = (conn, subscribed) {
                    if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                        println!("[btp] flush(timer) error: {:?}", e);
                    }
                }
            }
        }

        // handshake 応答の送出で確立が完了したらログを出す(E2 の検証ゲート)。
        if !established_logged && btp.is_established() {
            established_logged = true;
            println!(
                "[btp] established (att_mtu={}, fragment={})",
                mtu.unwrap_or(0),
                btp.fragment_size()
            );
        }

        // ACK / idle タイムアウトでセッションを畳んで再スタートに備える。
        let now = now_ms(start);
        if btp.is_timed_out(now) {
            println!("[btp] session timed out; disconnecting");
            btp.reset();
            established_logged = false;
            if let Some(c) = conn.take() {
                let _ = gatt.disconnect(c).await;
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
    println!(" simple-matter :: ESP32-C6 port (phase E2: BLE/BTP)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 + trouble-host 0.6");
    println!(" scope    : 0xFFF6 adv + C1/C2 GATT + BTP handshake");
    println!("======================================================");

    // esp-radio の BLE controller タスク・内部バッファはヒープを要求する。
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    // 「スケジューラ開始 → radio 初期化」の順序が必須(esp-radio ドキュメント)。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG(E1 と同じ)。TrngSource は main の生存期間中保持し続ける。
    // BLE(RF)有効時は真性乱数(設計 doc §5)。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TrngSource must be active before Trng::try_new()");
    let mut rng = EspRng(trng);

    // BLE の static random address を TRNG から生成(上位 2 ビット = 0b11 が必須)。
    let mut addr = [0u8; 6];
    rng.fill_bytes(&mut addr).expect("TRNG fill");
    addr[5] |= 0xC0;
    println!(
        "[ble] static random address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    );

    // --- BLE controller(esp-radio HCI)→ TrouBLE host ---
    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    // 同時 1 接続・L2CAP 追加チャネルなし(ATT は組み込み)・広告セット 1。
    let mut resources: HostResources<DefaultPacketPool, 1, 1> = HostResources::new();
    let stack =
        trouble_host::new(controller, &mut resources).set_random_address(Address::random(addr));
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    // GATT サーバ(GAP + Matter BTP service)。
    let server =
        BtpGattServer::new_with_config(trouble_host::gap::GapConfig::default("simple-matter"))
            .expect("GATT server build");

    // GattPeripheral 実装(channel で worker と接続)。
    let channels = GattChannels::new();
    let mut gatt = TroubleGattPeripheral::new(&channels);

    let adv = AdvData {
        discriminator: DISCRIMINATOR,
        vendor_id: VENDOR_ID,
        product_id: PRODUCT_ID,
        additional_data: false,
        ext_announcement: false,
    };
    gatt.start_advertising(&adv)
        .await
        .expect("start_advertising");

    println!(
        "[boot] discriminator={} vid={:#06x} pid={:#06x}",
        DISCRIMINATOR, VENDOR_ID, PRODUCT_ID
    );
    println!("[boot] commission with: cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 {}", DISCRIMINATOR);

    // TrouBLE host runner / GATT worker / BTP pump を単一 executor 上で並走させる。
    join3(
        async {
            // runner は HCI イベントループ。落ちたら BLE 全体が止まるので panic で知らせる。
            let e = runner.run().await;
            panic!("[ble] host runner exited: {:?}", e);
        },
        gatt_worker(&mut peripheral, &server, &channels),
        pump(&mut gatt),
    )
    .await;
    unreachable!();
}
