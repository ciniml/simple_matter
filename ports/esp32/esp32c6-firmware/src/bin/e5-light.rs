//! ESP32-C6 向け simple-matter ポート — フェーズ E5: Wi-Fi 実 join + UDP/mDNS。
//!
//! `docs/design/port-esp32-device.md` §8「E5」/ §E5 の実装。E4(`e4-ble-light.rs`、
//! BLE コミッショニング + fabric 永続化)に **実 Wi-Fi + UDP dual-transport** を足す:
//!
//! - **Wi-Fi 実 join**: ConnectNetwork で受けた実 SSID/パスフレーズで esp-radio の
//!   station join([`wifi_task`]、BLE と coex)。ConnectNetworkResponse は即 Success
//!   (バックグラウンド join、doc §E5.2)。
//! - **UDP(運用トランスポート)**: embassy-net(DHCPv4)+ コアの
//!   `UdpSend`/`UdpReceive`/`UdpMulticast` trait 実装 [`EspUdp`](実利用第 1 号)。
//!   Matter UDP は 5540。
//! - **mDNS(運用ディスカバリ)**: DHCP で IPv4 取得後に 5353 + 224.0.0.251 join で
//!   sans-IO の [`MdnsResponder`] を駆動(IPv4 のみ)。fabric `generation()` 変化で
//!   operational レコードを更新して再 announce(PC 版 ble-onoff-light と同じパターン)。
//!
//! これで chip-tool の `pairing ble-wifi` が最後まで通る:
//! BLE で PASE→CSR→AddNOC→AddOrUpdateWiFiNetwork→ConnectNetwork → Wi-Fi join →
//! DHCP → 運用 mDNS 発見 → **CASE over UDP** → CommissioningComplete → OnOff。
//!
//! # pump ループの非自明な制約(E3/E4 から継承。ble-btp.md §6.2 / §11-4)
//!
//! - **毎イテレーションで `stack.poll()` と BTP flush の両方を回す**(exchange 回収)。
//! - handshake 応答の indicate は **C2Subscribed 後まで保留**。
//! - flash 保存(fabric 変更時のみ)は同期・数十 ms 級で pump を止めるが低頻度なので許容。
//!
//! 実行: `cd ports/esp32 && cargo run --release --bin e5-light`
//! コミッショニング(実 SSID を渡す):
//! `chip-tool pairing ble-wifi 1 <ssid> <pass> 20202021 3840 --bypass-attestation-verifier true`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use core::cell::RefCell;

use embassy_executor::Spawner;
use embassy_futures::join::join5;
use embassy_futures::select::{select4, Either4};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::StackResources;
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
use simple_matter::discovery::{MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4, MDNS_PORT};
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    NetworkCommissioningWifi, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::error::Result as MResult;
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{
    DefaultStack, MatterStack, SendDirective, SharedFabricCreds, MAX_PACKET_SIZE,
};
use simple_matter::transport::net::{
    BtpConnId, PeerAddr, UdpMulticast, UdpReceive, UdpSend, MAX_RX_PACKET_SIZE,
};
use simple_matter::wifi::WifiDriver;

use esp32c6_firmware::ble::{gatt_worker, BtpGattServer, GattChannels, TroubleGattPeripheral};
use esp32c6_firmware::kvs::EspKvs;
use esp32c6_firmware::net::{peer_v4, v4_as_mapped, EspUdp};
use esp32c6_firmware::wifi::{wifi_task, EspWifiDriver};
use esp32c6_firmware::EspRng;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須。
// 無いとブートローダがアプリを起動できず TG0 WDT リセットループになる)。
esp_bootloader_esp_idf::esp_app_desc!();

/// コミッショニングパスコード(PC example と同値)。
const PASSCODE: u32 = 20202021;
/// SPAKE2+ 検証子導出のソルト(PC example と同値)。
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
/// コミッショニング discriminator(12 ビット、PC example と同値)。
const DISCRIMINATOR: u16 = 3840;
/// fabric テーブル容量(`DefaultStack` の NF と一致させる)。
const NF: usize = 5;

/// BTP フラグメントの先頭バイトトレース(E2 と同形式)。既定 off(E4 と同じ)。
const BTP_TRACE: bool = false;

/// HCI コマンドの同時実行スロット数(E2 と同値)。
const HCI_SLOTS: usize = 20;

type Backend = RustCrypto<EspRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;
/// 本 bin のスタック型(標準プロファイル。R = TRNG 注入の [`EspRng`])。
type LightStack<'s> = DefaultStack<'s, Backend, EspRng, Light<'s>>;

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

// ==========================================================================
// DataModel(E4 と同一構成。NetworkCommissioning のみ実ドライバ注入)
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
/// NetworkCommissioning は [`EspWifiDriver`] 注入版 [`NetworkCommissioningWifi`]。
/// ConnectNetwork で esp-radio の実 join([`wifi_task`])が始まる(E5 の中心差分)。
struct Light<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioningWifi<EspWifiDriver>,
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
        // fail-safe 期限切れで未 commit の fabric 追加を巻き戻す(PC 版と同じ)。
        if self.gc.on_tick(now_ms) {
            self.opcreds.on_failsafe_expired();
        }
        None
    }
}

fn build_light(fabrics: &RefCell<FabricTable<Backend, NF>>) -> Light<'_> {
    let dac_crypto = RustCrypto::new(esp_rng());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioningWifi::with_driver(EspWifiDriver),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(esp_rng()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

// ==========================================================================
// BTP ヘルパ(E4 と同じパターン)
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

/// スタックの送信指示を宛先トランスポートへ振り分ける(PC 版 route_send の embassy 版)。
///
/// BLE 宛は BTP に SDU として積み(C2 subscribe 済みなら即排出)、UDP 宛は
/// [`EspUdp`] で 1 datagram 送信する(CASE over UDP / MRP 再送は stack.poll 経由)。
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
// 統合層(pump): BTP + UDP + mDNS ⇔ MatterStack
// ==========================================================================

/// BTP / UDP / mDNS と MatterStack を駆動する統合層(PC 版 ble-onoff-light の embassy 版)。
///
/// E5 拡張(E4 の pump に対して):
/// - Matter UDP(5540)の受信を select に加え、UDP 宛の送信指示を実際に送る。
/// - DHCP で IPv4 を取得したら mDNS(5353 + 224.0.0.251 join)の運用広告を開始する。
/// - fabric `generation()` 変化で flash 保存(E4)+ operational レコード更新(E5)。
/// - `NetworkCommissioningWifi::update_from_driver` で join 結果を属性へ反映する。
#[allow(clippy::too_many_arguments)]
async fn pump(
    gatt: &mut TroubleGattPeripheral<'_>,
    stack: &mut LightStack<'_>,
    led: &mut Output<'_>,
    fabrics: &RefCell<FabricTable<Backend, NF>>,
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
    // indicate は捨てられるため、subscribe 済みになるまで送出を保留する(E2〜E4 と同じ)。
    let mut subscribed = false;
    let mut established_logged = false;
    // GPIO7 の青 LED(M5Stack NanoC6、active-high)の現在値。OnOff 属性に追従させる。
    let mut led_on = false;
    // fabric 永続化: 直近に保存(または復元)した時点の generation。
    let mut saved_gen = fabrics.borrow().generation();
    // 運用 mDNS レスポンダ(DHCP で IPv4 を取得してから構築する)。
    let mut mdns: Option<MdnsResponder<NF>> = None;

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_PACKET_SIZE];
    let mut udp_rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    // 生存確認ログ(E2〜E4 と同じ)。
    let mut next_heartbeat_ms: u64 = 0;

    loop {
        let now = now_ms(start);
        if now >= next_heartbeat_ms {
            println!(
                "[alive] t={}s conn={:?} subscribed={} wifi={:?} ip={:?} light={}",
                now / 1000,
                conn.map(|c| c.0),
                subscribed,
                stack.device().net.driver().status(),
                net_stack.config_v4().map(|c| c.address),
                if led_on { "ON" } else { "OFF" }
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
            // --- BLE(BTP)イベント(E4 と同じ)---
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
                                    gatt, &mut btp, matter_udp, d, &txd[..d.len], mtu, subscribed,
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
                        gatt, &mut btp, matter_udp, d, &txd[..d.len], mtu, subscribed, now,
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
                    // (5353 を共有できない querier 対策。RFC 6762 §5.4、PC 版と同じ)。
                    let qu = r.query_wants_unicast(&mdns_rx[..n]);
                    if let Some(len) = r.handle_query(&mdns_rx[..n], &mut mdns_tx) {
                        let dst = if qu {
                            src
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

        // handshake 確立ログ(E2 の検証ゲートと同形式)。
        if !established_logged && btp.is_established() {
            established_logged = true;
            println!(
                "[btp] established (att_mtu={}, fragment={})",
                mtu.unwrap_or(0),
                btp.fragment_size()
            );
        }

        // --- 時間駆動の送出 + 閉じた exchange の回収(ble-btp.md §11-4、毎周必須)---
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, &mut txd) {
            if let Err(e) = route_send(
                gatt, &mut btp, matter_udp, d, &txd[..d.len], mtu, subscribed, now,
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

        // --- OnOff 属性を実 LED(GPIO7)へ反映する ---
        let on = stack.device().onoff.is_on();
        if on != led_on {
            led_on = on;
            led.set_level(if on { Level::High } else { Level::Low });
        }

        // --- DHCP で IPv4 を取得したら運用 mDNS を開始する(doc §E5.5)---
        if mdns.is_none() {
            if let Some(cfg) = net_stack.config_v4() {
                let ip = cfg.address.address();
                println!("[net] DHCP up: ip={} gw={:?}", cfg.address, cfg.gateway);
                // 224.0.0.251 の IGMP join(コア trait は IPv6 のみのため mapped 規約)。
                if let Err(e) = mdns_udp.join(v4_as_mapped(MDNS_IPV4)).await {
                    println!("[mdns] multicast join error: {:?}", e);
                }
                let host = simple_matter::discovery::Host::from_mac(&mac, None, Some(ip));
                let mut r: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
                r.set_operational(
                    fabrics
                        .borrow()
                        .iter()
                        .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id())),
                );
                r.notify_change(now_ms(start));
                println!(
                    "[mdns] operational advertising on {}:{} (A record: {})",
                    MDNS_IPV4, MDNS_PORT, ip
                );
                mdns = Some(r);
            }
        }

        // --- fabric 変更(generation)で flash 保存(E4)+ operational 広告更新(E5)---
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
                println!("[mdns] operational records updated ({})", r.operational_len());
            }
        }

        // --- mDNS の定期 announce(未回答の gratuitous 広告)---
        if let Some(r) = mdns.as_mut() {
            if let Some(len) = r.poll_announce(now_ms(start), &mut mdns_tx) {
                let _ = mdns_udp
                    .send_to(&mdns_tx[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
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
    println!(" simple-matter :: ESP32-C6 port (phase E5: wifi+udp)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 (coex) + embassy-net 0.9");
    println!(" scope    : E4 + real Wi-Fi join + UDP/mDNS dual-transport");
    println!("======================================================");

    // Wi-Fi + BLE coex は esp-radio のヒープ要求が増える(E4 の 72KiB から増量)。
    // MatterStack 自体はヒープレス(main のスタック上に置く)。
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

    // M5Stack NanoC6 の青 LED(GPIO7、active-high)。OnOff 属性を実表示する。
    let mut led = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());

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
    let (net_stack, mut net_runner) = embassy_net::new(
        sta,
        embassy_net::Config::dhcpv4(Default::default()),
        &mut net_resources,
        seed,
    );

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

    // --- MatterStack 構築(E4 と同じ。乱数は全て TRNG)---
    let crypto = RustCrypto::new(esp_rng());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());

    // flash KVS から fabric テーブルを復元する(E4、doc §E4.4 / §E4.5)。
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

    // SPAKE2+ 検証子の導出(PBKDF2)は C6 では数百 ms かかるため進捗を出す。
    println!("[pase] deriving SPAKE2+ verifier from passcode (PBKDF2)...");
    let pase = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    println!("[pase] verifier ready");

    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, esp_rng(), pase, creds);
    let im = InteractionModel::new(build_light(&fabrics));
    let mut stack: LightStack<'_> = MatterStack::new(&crypto, sc, im);
    println!(
        "[stack] DefaultStack ready ({} bytes, on main stack)",
        core::mem::size_of::<LightStack<'static>>()
    );

    // --- BLE controller(esp-radio HCI)→ TrouBLE host(E2〜E4 と同じ)---
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
    let server = BtpGattServer::new_with_config(trouble_host::gap::GapConfig::default(
        "simple-matter",
    ))
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
        "[boot] passcode={} discriminator={} vid={:#06x} pid={:#06x}",
        PASSCODE, DISCRIMINATOR, CFG.vendor_id, CFG.product_id
    );
    println!(
        "[boot] commission with: chip-tool pairing ble-wifi 1 <ssid> <pass> {} {} --bypass-attestation-verifier true",
        PASSCODE, DISCRIMINATOR
    );

    // TrouBLE host runner / GATT worker / Wi-Fi task / embassy-net runner / pump を
    // 単一 executor 上で並走させる。
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
            &mut led,
            &fabrics,
            &mut kvs,
            net_stack,
            &mut matter_udp,
            &mut mdns_udp,
            mac,
        ),
    )
    .await;
    unreachable!();
}
