//! ESP32-C6 向け simple-matter ポート — フェーズ E4: fabric 永続化付き BLE ライト。
//!
//! `docs/design/port-esp32-device.md` §8「E4: KVS + fabric 永続化」/ §E4 の実装。
//! E3(`e3-ble-light.rs`)に flash KVS([`EspKvs`])を接続する:
//!
//! - **起動時**: `nvs` 領域から fabric テーブルを復元する(`[kvs] restored N fabrics`)。
//! - **実行中**: `FabricTable::generation()` の変化(AddNOC / fail-safe 巻き戻し等)を
//!   pump ループで検知して保存する(`[kvs] saved N fabrics`。PC 版 onoff-light の
//!   operational 広告更新と同じ generation 監視パターン)。
//!
//! これで「run1: コミッショニング → リセット → run2: PASE を飛ばして CASE のみ
//! (`ble-commissioner --operational`)→ Toggle」が通る = リブート後も運用 CASE を
//! 再確立できる(E4 ゲート)。E4 では運用広告(mDNS)は載せず、リブート後も
//! commissionable の BLE 広告を出し続ける(検証の簡略化、doc §E4.6)。
//!
//! # pump ループの非自明な制約(E3 から継承。ble-btp.md §6.2 / §11-4)
//!
//! - **毎イテレーションで `stack.poll()` と BTP flush の両方を回す**。閉じた exchange の
//!   回収は `ExchangeManager::poll` の quiescent sweep でのみ行われ、BLE では MRP が
//!   無効なため poll を怠ると exchange プールが数往復で `NoSpace` 枯渇する。
//! - **確立順序**: central は C1 write(handshake req)→ C2 subscribe の順で来る。
//!   handshake 応答の indicate は **C2Subscribed 後まで保留**する(E2 と同じ)。
//! - flash 書き込み(保存)は同期・数十 ms 級で pump を止める。保存契機は fabric
//!   変更時(コミッショニングの数回)のみなので許容する(doc §E4.5 の注意点)。
//!
//! 実行: `cd ports/esp32 && cargo run --release --bin e4-ble-light`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use core::cell::RefCell;

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select, Either};
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::*;

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioningWifi, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::error::Result as MResult;
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::SecureChannel;
use simple_matter::stack::{
    DefaultStack, MatterStack, SendDirective, SharedFabricCreds, MAX_PACKET_SIZE,
};
use simple_matter::transport::net::{BtpConnId, PeerAddr, MAX_RX_PACKET_SIZE};

use esp32c6_firmware::ble::{gatt_worker, BtpGattServer, GattChannels, TroubleGattPeripheral};
use esp32c6_firmware::kvs::EspKvs;
use esp32c6_firmware::EspRng;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須。
// 無いとブートローダがアプリを起動できず TG0 WDT リセットループになる)。
esp_bootloader_esp_idf::esp_app_desc!();

/// コミッショニングパスコード(PC example と同値)。
/// SPAKE2+ 検証子導出のソルト(PC example と同値)。
/// コミッショニング discriminator(12 ビット、PC example と同値)。
const DISCRIMINATOR: u16 = 3840;
/// fabric テーブル容量(`DefaultStack` の NF と一致させる)。
const NF: usize = 5;

/// BTP フラグメントの先頭バイトトレース(E2 と同形式)。コミッショニングは
/// フラグメント数が多く(AddNOC の証明書チェーンで数十)、UART ログが BTP の
/// ACK タイミングを圧迫し得るため既定は off。切り分け時のみ true にする。
const BTP_TRACE: bool = false;

/// HCI コマンドの同時実行スロット数(E2 と同値)。
const HCI_SLOTS: usize = 20;

type Backend = RustCrypto<EspRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;
/// 本 bin のスタック型(標準プロファイル。R = TRNG 注入の [`EspRng`])。
type LightStack<'s> = DefaultStack<'s, Backend, EspRng, Light<'s>>;

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
///
/// コアは Rng を値で複数箇所(crypto backend / SecureChannel / OpCreds / DAC)に
/// 要求するため、`Trng::try_new` で必要数だけハンドルを増やす(実体は同一 HW)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

// ==========================================================================
// DataModel(PC 版 ble-onoff-light.rs と同一構成)
// ==========================================================================

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

/// On/Off ライトのデバイス(endpoint 0 = ルート、endpoint 1 = ライト)。
///
/// NetworkCommissioning は Wi-Fi **シミュレーション**版 [`NetworkCommissioningWifi`]。
/// 実際には Wi-Fi に join しない(実 join は E5 スコープ)が、chip-tool
/// `pairing ble-wifi` / PC commissioner の ConnectNetwork 互換のために載せる
/// (AddOrUpdateWiFiNetwork / ConnectNetwork に即 Success を返すシム)。
struct Light<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioningWifi,
    opcreds: OpCreds<'s>,
    desc0: DescriptorCluster,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    removed_fabric: Option<core::num::NonZeroU8>,
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
        // fail-safe 期限切れで未 CommissioningComplete の fabric 追加を巻き戻す(Core Spec §11.10)。
        if self.gc.on_tick(now_ms) {
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        None
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

fn build_light(fabrics: &RefCell<FabricTable<Backend, NF>>) -> Light<'_> {
    let dac_crypto = RustCrypto::new(esp_rng());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioningWifi::new(),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(esp_rng()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        // listener は fn ポインタ(キャプチャ不可)のためログのみ。実 LED(GPIO7)は
        // pump ループが OnOff 属性([`OnOffCluster::is_on`])を観測して追従させる。
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
    }
}

// ==========================================================================
// BTP ヘルパ(E2 と同じパターン)
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

/// 単調時刻(ms)。BTP / スタックの `now_ms` 注入に使う(embassy-time の Instant 起点)。
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

/// スタックの送信指示を BLE(BTP)へ載せる(PC 版 route_send の BLE 専用版)。
///
/// `bytes` は `stack.handle_rx` / `stack.poll` が書いた `txd[..d.len]`。BTP に SDU として
/// 積み、C2 subscribe 済みなら即フラグメント排出する(未 subscribe なら C2Subscribed
/// 時の flush まで BTP 内に留まる)。UDP 宛は E3 では発生しない(UDP トランスポートを
/// 載せていない = UDP セッションが存在しない)ため、防御的にログしてドロップする。
async fn send_ble(
    gatt: &mut TroubleGattPeripheral<'_>,
    btp: &mut Btp<6>,
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
        PeerAddr::Udp(_) => {
            println!("[stack] dropping UDP-bound directive (no UDP transport in E3)");
            Ok(())
        }
    }
}

// ==========================================================================
// 統合層(pump): BTP ⇔ MatterStack
// ==========================================================================

/// BTP と MatterStack を駆動する統合層(PC 版 ble-onoff-light の BLE 経路の embassy 版)。
///
/// E4 拡張: `fabrics` の generation を監視し、変化したら `kvs` へ保存する
/// (`docs/design/port-esp32-device.md` §E4.4 の「呼び出しタイミングは統合層の責務」)。
async fn pump(
    gatt: &mut TroubleGattPeripheral<'_>,
    stack: &mut LightStack<'_>,
    led: &mut Output<'_>,
    fabrics: &RefCell<FabricTable<Backend, NF>>,
    kvs: &mut EspKvs,
) -> ! {
    let mut btp = Btp::<6>::new(BtpRole::Peripheral);
    let mut conn: Option<BtpConnId> = None;
    let mut mtu: Option<u16> = None;
    // central(PC ble-commissioner / chip-tool)は handshake req の C1 write を
    // C2 subscribe より先に行う。subscribe 前の indicate は捨てられるため、
    // subscribe 済みになるまで送出(flush_out)を保留する(ble-btp.md の確立順序)。
    let mut subscribed = false;
    let mut established_logged = false;
    // GPIO7 の青 LED(M5Stack NanoC6、active-high)の現在値。OnOff 属性に追従させる。
    let mut led_on = false;
    // fabric 永続化: 直近に保存(または復元)した時点の generation。
    let mut saved_gen = fabrics.borrow().generation();
    // CASE resumption 永続化: 復元後の世代を基準に取り、変化時に flash 保存する(§7.4)。
    let mut saved_resumption_gen = stack.resumption_generation();

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_PACKET_SIZE];
    // 生存確認ログ(E2 と同じ)。シリアルは任意のタイミングで接続されるため定期出力する。
    let mut next_heartbeat_ms: u64 = 0;

    loop {
        let now = now_ms(start);
        if now >= next_heartbeat_ms {
            println!(
                "[alive] t={}s conn={:?} subscribed={} light={}",
                now / 1000,
                conn.map(|c| c.0),
                subscribed,
                if led_on { "ON" } else { "OFF" }
            );
            next_heartbeat_ms = now + 10_000;
        }

        // 両 deadline(スタックの MRP/購読レポート・BTP の遅延 ACK/idle)を min で待つ。
        // 上限 50ms でクリップしてタイムアウト検知(is_timed_out)も定期的に回す。
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
                        // BTP レベルの ACK / handshake 応答を先に排出する。
                        if subscribed {
                            if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                                println!("[btp] flush(c1) error: {:?}", e);
                            }
                        }
                        // 再組立できた Matter メッセージを stack へ渡し、応答を BTP に載せる
                        // (ここが E2 からの拡張点)。
                        while let Some(slen) = take_sdu(&mut btp, &mut sdu) {
                            let now = now_ms(start);
                            let dir =
                                stack.handle_rx(&mut sdu[..slen], PeerAddr::Ble(c), now, &mut txd);
                            if let Some(d) = dir {
                                if let Err(e) =
                                    send_ble(gatt, &mut btp, d, &txd[..d.len], mtu, subscribed, now)
                                        .await
                                {
                                    println!("[stack] send(rx) error: {:?}", e);
                                }
                            }
                        }
                    }
                    PeripheralEvent::Disconnected { conn: c } => {
                        // BTP セッションだけ畳む。スタック側のセキュアセッションは
                        // PC 版と同じく明示的には閉じない(再接続は新しい BtpConnId で
                        // 新規 PASE/CASE を張るため、古いセッションは寿命管理に任せる)。
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

        // handshake 確立ログ(E2 の検証ゲートと同形式。E3 でも切り分けに有用)。
        if !established_logged && btp.is_established() {
            established_logged = true;
            println!(
                "[btp] established (att_mtu={}, fragment={})",
                mtu.unwrap_or(0),
                btp.fragment_size()
            );
        }

        // --- 時間駆動の送出 + 閉じた exchange の回収(ble-btp.md §11-4、毎周必須)---
        // BLE では MRP が無効なため、poll を怠ると exchange プールが数往復で NoSpace
        // 枯渇し AddNOC が黙って失敗する(PC 実機で踏んだバグ)。
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, &mut txd) {
            if let Err(e) = send_ble(gatt, &mut btp, d, &txd[..d.len], mtu, subscribed, now).await {
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

        // --- OnOff 属性を実 LED(GPIO7)へ反映する ---
        let on = stack.device().onoff.is_on();
        if on != led_on {
            led_on = on;
            led.set_level(if on { Level::High } else { Level::Low });
        }

        // --- E4: fabric 変更(generation)を検知して flash へ保存する ---
        let gen = fabrics.borrow().generation();
        if gen != saved_gen {
            saved_gen = gen;
            let table = fabrics.borrow();
            match table.save_to(kvs) {
                Ok(()) => println!("[kvs] saved {} fabrics (generation={})", table.len(), gen),
                Err(e) => println!("[kvs] save error: {:?}", e),
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
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    // クロックを最大に設定して初期化(esp-radio は 80MHz 以上を要求)。
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-C6 port (phase E4: persisted)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 + trouble-host 0.6");
    println!(" scope    : E3 + fabric persistence (flash KVS @ nvs)");
    println!("======================================================");

    // esp-radio の BLE controller タスク・内部バッファはヒープを要求する(E2 と同値)。
    // MatterStack 自体はヒープレス(main のスタック上に置く)。
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    // 「スケジューラ開始 → radio 初期化」の順序が必須(esp-radio ドキュメント)。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG。TrngSource は main の生存期間中保持し続ける(drop すると擬似乱数に戻る)。
    // BLE(RF)有効時は真性乱数(設計 doc §5)。
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

    // M5Stack NanoC6 の青 LED(GPIO7、active-high)。OnOff 属性を実表示する。
    let mut led = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());

    // --- MatterStack 構築(PC 版 ble-onoff-light.rs の写像。乱数は全て TRNG)---
    let crypto = RustCrypto::new(esp_rng());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

    // --- E4: flash KVS から fabric テーブルを復元する(doc §E4.4 / §E4.5)---
    // 壁時計を持たないため now=0。検証時刻は保存済み LKGT が下支えする。
    let mut kvs = EspKvs::new(peripherals.FLASH);
    let restore = fabrics.borrow_mut().load_from(&mut kvs, &crypto, 0);
    match restore {
        Ok(n) => println!("[kvs] restored {} fabrics", n),
        Err(e) => {
            // 部分復元の可能性があるためテーブルを空に作り直す(初回起動相当で続行)。
            println!(
                "[kvs] restore failed: {:?}; starting with empty fabric table",
                e
            );
            *fabrics.borrow_mut() = FabricTable::new();
        }
    }

    // SPAKE2+ 検証子の導出(PBKDF2)は C6 では数百 ms かかるため進捗を出す。
    println!("[pase] loading embedded dev SPAKE2+ verifier (device holds no passcode)...");
    let pase = simple_matter::dev_pase::dev_pase_config();
    println!("[pase] verifier ready");

    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, esp_rng(), pase, creds);
    let im = InteractionModel::new(build_light(&fabrics));
    let mut stack: LightStack<'_> = MatterStack::new(&crypto, sc, im);
    // 起動イベント(BasicInformation StartUp、CRITICAL、{ softwareVersion })を積む。
    let _ = stack.post_startup_event(CFG.software_version, 0);
    println!(
        "[stack] DefaultStack ready ({} bytes, on main stack)",
        core::mem::size_of::<LightStack<'static>>()
    );

    // CASE resumption 素材を flash KVS から復元する(fabric 復元直後。secure-channel.md §7.4)。
    match stack.load_resumptions_from(&mut kvs) {
        Ok(n) => println!("[kvs] restored {} resumptions", n),
        Err(e) => println!("[kvs] resumption restore failed: {:?}", e),
    }

    // --- BLE controller(esp-radio HCI)→ TrouBLE host(E2 と同じ)---
    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);

    // 同時 1 接続・L2CAP 追加チャネルなし(ATT は組み込み)・広告セット 1。
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
    println!("[boot] commission with: cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- {} {}", 20202021, DISCRIMINATOR);
    println!(
        "[boot] after reboot   : ... -- {} {} --operational (CASE only)",
        20202021, DISCRIMINATOR
    );

    // TrouBLE host runner / GATT worker / 統合層 pump を単一 executor 上で並走させる。
    join3(
        async {
            // runner は HCI イベントループ。落ちたら BLE 全体が止まるので panic で知らせる。
            let e = runner.run().await;
            panic!("[ble] host runner exited: {:?}", e);
        },
        gatt_worker(&mut peripheral, &server, &channels),
        pump(&mut gatt, &mut stack, &mut led, &fabrics, &mut kvs),
    )
    .await;
    unreachable!();
}
