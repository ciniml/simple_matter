//! ESP32-C6 向け Matter over Thread ライト — フェーズ T2。
//!
//! `docs/design/thread-port.md` §T2。E4(`e4-ble-light`、BLE コミッショニング +
//! fabric 永続化)をベースに Wi-Fi を openthread(Thread)へ置き換える:
//!
//! - **コミッショニング**: BLE/BTP(既存 `TroubleGattPeripheral`)→ PASE → AddNOC →
//!   AddOrUpdateThreadNetwork(dataset TLV)→ ConnectNetwork(Thread attach 開始、
//!   遅延応答)→ attach 完了(role=Child/Router/Leader)で ConnectNetworkResponse。
//! - **運用トランスポート**: openthread ネイティブ UDP(5540、[`OtUdp`])。CASE over Thread。
//! - **運用広告**: SRP client(`_matter._tcp`)。OTBR の advertising proxy が LAN 側
//!   mDNS へ変換するのでコントローラ側は無改造。
//! - **永続化**: fabric / ACL / CASE resumption / dataset TLV を flash KVS([`EspKvs`])。
//!   OT の Settings は RAM(`SimpleRamSettings`)+ dataset 自前永続化(doc §5.3 の T2
//!   割り切り)。KVS 裏打ち Settings は attach 時の flash 書き込みバーストが 15.4 radio を
//!   停止させるため T3 送り(リスク R6 実測。`ot_settings.rs` に実装は残置)。
//!
//! R2(BLE + 802.15.4 の実行時同時動作)は本 bin の実機コミッショニングで検証する
//! (ConnectNetwork の遅延応答は BLE 接続維持中の 15.4 attach を要求する)。
//!
//! 実行: `cd ports/esp32 && cargo run -p esp32c6-thread --release --bin t2-light`
//! コミッショニング:
//! `chip-tool pairing ble-thread 1 hex:<dataset-tlv> 20202021 3840 --ble-controller 0`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;
// OpenThread の C コードが参照する str*/mem* 系 libc シンボルのポリフィル。
use tinyrlibc as _;

use core::cell::RefCell;
use core::fmt::Write as _;
use core::net::{Ipv6Addr, SocketAddrV6};

use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_futures::select::{select3, Either3};
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Rng, Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use esp_radio::ieee802154::Ieee802154;
use trouble_host::prelude::*;

use openthread::esp::EspRadio;
use openthread::{
    OpenThread, OtResources, OtSrpResources, OtUdpResources, SrpConf, SrpService, SrpState,
    UdpSocket,
};

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng as _;
use simple_matter::dm::clusters::{
    AdminCommissioningCluster, BasicInfoConfig, BasicInformationCluster, CommissioningWindow,
    DescriptorCluster, GeneralCommissioning, NetworkCommissioningThread, OnOffCluster,
    OpCredsCluster, TestDacProvider, WindowEvent,
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
use simple_matter::transport::net::{
    BtpConnId, PeerAddr, UdpReceive, UdpSend, MAX_RX_PACKET_SIZE,
};

use esp32c6_thread::ble::{gatt_worker, BtpGattServer, GattChannels, TroubleGattPeripheral};
use esp32c6_thread::kvs::EspKvs;
use esp32c6_thread::ot_settings::{self, KvsSettings, SettingsStore};
use esp32c6_thread::ot_thread::OtThreadDriver;
use esp32c6_thread::ot_udp::OtUdp;
use esp32c6_thread::EspRng;
use simple_matter::kvs::Kvs;

use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

/// コミッショニングパスコード(PC example と同値)。
/// SPAKE2+ 検証子導出のソルト(PC example と同値)。
/// コミッショニング discriminator(12 ビット、PC example と同値)。
const DISCRIMINATOR: u16 = 3840;
/// fabric テーブル容量(`DefaultStack` の NF と一致させる)。
const NF: usize = 5;
/// HCI コマンドの同時実行スロット数(E2 と同値)。
const HCI_SLOTS: usize = 20;
/// Matter 運用 UDP ポート。
const MATTER_PORT: u16 = 5540;

/// OT ネイティブ UDP のバッファ構成(1 ソケット 1280B = IPv6 MTU)。
const UDP_SOCKETS_BUF: usize = 1280;
const UDP_MAX_SOCKETS: usize = 2;

/// 永続化した dataset TLV の KVS キー(ポートローカル)。
const DATASET_KEY: &[u8] = b"otds";

type Backend = RustCrypto<EspRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;
/// 本 bin のスタック型(標準プロファイル。R = TRNG 注入の [`EspRng`])。
type LightStack<'s> = DefaultStack<'s, Backend, EspRng, Light<'s>>;

/// `StaticCell` 経由で 'static な可変参照を作る(openthread のリソースは 'static 要求)。
macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: StaticCell<$t> = StaticCell::new();
        CELL.init($val)
    }};
}

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

// ==========================================================================
// DataModel(e4-ble-light と同一構成。NetworkCommissioning のみ Thread ドライバ注入)
// ==========================================================================

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "SimpleMatter",
    vendor_id: 0xFFF1,
    product_name: "ThreadLight",
    product_id: 0x8003,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-THREAD-0001",
};

static EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x0028),
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003C),
    ClusterId(0x003E),
    ClusterId(0x001D),
];
static EP1_SERVERS: &[ClusterId] = &[ClusterId(0x0006), ClusterId(0x001D)];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
static EP0_PARTS: &[EndpointId] = &[EndpointId(1)];
static EP1_PARTS: &[EndpointId] = &[];

/// On/Off ライトのデバイス(endpoint 0 = ルート、endpoint 1 = ライト)。
struct Light<'s> {
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioningThread<OtThreadDriver<'static>>,
    admin: AdminCommissioningCluster<'s>,
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
            (0, 0x003C) => Some(&self.admin),
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
            (0, 0x003C) => Some(&mut self.admin),
            (0, 0x003E) => Some(&mut self.opcreds),
            (0, 0x001D) => Some(&mut self.desc0),
            (1, 0x0006) => Some(&mut self.onoff),
            (1, 0x001D) => Some(&mut self.desc1),
            _ => None,
        }
    }
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.gc.on_tick(now_ms) {
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        // コミッショニング窓のタイムアウト自動クローズ(WindowEvent は pump が拾う)。
        let _ = self.admin.on_tick(now_ms);
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

fn build_light<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    window: &'s RefCell<CommissioningWindow>,
    thread_driver: OtThreadDriver<'static>,
) -> Light<'s> {
    let dac_crypto = RustCrypto::new(esp_rng());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioningThread::with_driver(thread_driver),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(esp_rng()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
    }
}

// ==========================================================================
// BTP ヘルパ(e4-ble-light と同じ)
// ==========================================================================

fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis()
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
        gatt.indicate(conn, &out[..n]).await?;
    }
    Ok(())
}

/// 再組立済み 1 SDU を `out` にコピーして長さを返す。
fn take_sdu(btp: &mut Btp<6>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}

/// スタックの送信指示を宛先トランスポートへ振り分ける(BLE=BTP / UDP=OtUdp)。
#[allow(clippy::too_many_arguments)]
async fn route_send(
    gatt: &mut TroubleGattPeripheral<'_>,
    btp: &mut Btp<6>,
    udp: &mut OtUdp<'_>,
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

/// SRP client で `_matter._tcp` の運用サービスを登録する(attach 完了 + fabric 存在時に 1 回)。
///
/// ホスト名 `SM<mac-hex>`、インスタンス名 `<compressedFabricId16>-<nodeId16>`(既存 mDNS
/// operational と同一命名)。OTBR の advertising proxy が LAN 側 mDNS へ変換する。
fn register_srp(
    ot: &OpenThread<'_>,
    compressed_fabric_id: u64,
    node_id: u64,
    mac: &[u8; 6],
) -> Result<(), openthread::OtError> {
    let mut host = heapless::String::<20>::new();
    let _ = host.push_str("SM");
    for b in mac {
        let _ = write!(host, "{:02X}", b);
    }
    ot.srp_set_conf(&SrpConf {
        host_name: &host,
        ..SrpConf::new()
    })?;

    let mut instance = heapless::String::<40>::new();
    let _ = write!(instance, "{:016X}-{:016X}", compressed_fabric_id, node_id);
    // TXT: SII/SAI/T = MRP パラメータ(§T3。Thread は Wi-Fi よりレイテンシ大)。
    //
    // SII (Session Idle Interval) / SAI (Session Active Interval) は、コントローラが
    // **この**ノードへ送る MRP メッセージの再送間隔をこの値まで待つよう指示する(ms)。
    // Thread はメッシュのマルチホップ + 6LoWPAN 断片化 + 本ポートの 8ms TX ペーシング +
    // TX イベント喪失リカバリ(500ms)で往復レイテンシが Wi-Fi より大きく、フレーム損失も
    // 大きい(T2 実測: ping loss 30-50%)。Wi-Fi 版の SAI=300ms だとコントローラが応答到達
    // 前に再送し、輻輳と重複処理を招く。Thread 向けに **SAI を 300→1000ms、SII を 5000→
    // 10000ms** に拡大し、1 メッシュ往復ぶんの余裕を持たせる(実測で調整可能な運用パラメータ)。
    let txt: [(&str, &[u8]); 3] = [("SII", b"10000"), ("SAI", b"1000"), ("T", b"0")];
    let service = SrpService {
        name: "_matter._tcp",
        instance_name: &instance,
        subtype_labels: core::iter::empty::<&str>(),
        txt_entries: txt.iter().copied(),
        port: MATTER_PORT,
        priority: 0,
        weight: 0,
        lease_secs: 0,
        key_lease_secs: 0,
    };
    ot.srp_add_service(&service)?;
    // SRP サーバ(OTBR)を netdata から自動発見して登録を開始する。
    ot.srp_autostart()?;
    println!(
        "[srp] registration submitted host={} instance={} port={}",
        host.as_str(),
        instance.as_str(),
        MATTER_PORT
    );
    Ok(())
}

/// fabric の増減(AddNOC / RemoveFabric)に合わせて SRP 運用登録を作り直す(§T3 項目 2)。
///
/// SRP のインスタンス名は `<compressedFabricId>-<nodeId>` で **fabric に紐づく**ため、
/// AddNOC(新 fabric)/ RemoveFabric で node/fabric が変わると古い登録が陳腐化する。
/// 変更時は既存サービスを全削除してから現行の先頭 fabric で登録し直す。fabric が
/// 全て消えた(工場出荷相当)場合は SRP を全削除する(ホスト登録も撤去)。
///
/// 戻り値: 登録が有効(サービスあり)なら `true`、全削除したら `false`。
fn resync_srp<const NF: usize>(
    ot: &OpenThread<'_>,
    fabrics: &RefCell<FabricTable<Backend, NF>>,
    mac: &[u8; 6],
) -> bool {
    // 既存の SRP サービスを全撤去(サーバへ削除を通知)。
    if let Err(e) = ot.srp_remove_all(false) {
        println!("[srp] resync: remove_all error: {e:?}");
    }
    let fab = fabrics
        .borrow()
        .iter()
        .next()
        .map(|f| (f.compressed_fabric_id(), f.node_id()));
    match fab {
        Some((cfid, nid)) => {
            match register_srp(ot, cfid, nid, mac) {
                Ok(()) => println!("[srp] resync: re-registered for fabric node={nid:016X}"),
                Err(e) => println!("[srp] resync: re-register error: {e:?}"),
            }
            true
        }
        None => {
            // fabric 皆無 → SRP client を止め、広告を撤去する。
            let _ = ot.srp_stop();
            println!("[srp] resync: all fabrics removed; SRP torn down");
            false
        }
    }
}

/// netdata の on-mesh(SLAAC フラグ付き)prefix から OMR アドレスを合成して追加する。
///
/// プリビルトの OpenThread ライブラリは SLAAC 無効ビルド(`otIp6SetSlaacEnabled` が
/// 未リンク)のため、OMR アドレスが自動生成されない。link-local + mesh-local のみだと
/// SRP の auto host address が mesh-local に落ち、**OTBR の advertising proxy が AAAA を
/// LAN 側 mDNS に出さない**(T2 実測 — 発見不能の根本原因)。attach 後に netdata から
/// SLAAC prefix を拾い、`prefix(64bit) + EUI64 由来 IID` のアドレスを手動追加する。
///
/// 追加に成功したら `true`(呼び出し側は 1 回で止める)。
fn maybe_add_omr_address(ot: &OpenThread<'_>, eui64: &[u8; 8]) -> bool {
    let mut prefix: Option<(Ipv6Addr, u8)> = None;
    let _ = ot.netdata_get_on_mesh_prefixes(|p| {
        if let Some(cfg) = p {
            // SLAAC 用の on-mesh prefix(OMR)。mesh-local は netdata に載らない。
            if cfg.slaac && cfg.prefix.1 == 64 && prefix.is_none() {
                prefix = Some(cfg.prefix);
            }
        }
        Ok(())
    });
    let Some((pfx, plen)) = prefix else {
        return false;
    };
    // IID: EUI-64 の u/l ビット反転(modified EUI-64)。
    let mut iid = *eui64;
    iid[0] ^= 0x02;
    let p = pfx.octets();
    let addr = Ipv6Addr::from([
        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], iid[0], iid[1], iid[2], iid[3], iid[4],
        iid[5], iid[6], iid[7],
    ]);
    match ot.add_unicast_address(addr, plen) {
        Ok(()) => {
            println!("[ot] OMR address added: {addr}/{plen}");
            true
        }
        Err(e) => {
            println!("[ot] add OMR address failed: {e:?}");
            false
        }
    }
}

/// SRP のホストと全サービスがサーバ確認済み(Registered)かを返す。
///
/// OTBR の SRP server が登録を受理した時点で advertising proxy が LAN 側 mDNS へ
/// 変換する = コントローラの operational discovery が解決可能になる。
fn srp_all_registered(ot: &OpenThread<'_>) -> bool {
    let host_ok = ot
        .srp_conf(|_conf, state, _empty| Ok(state == SrpState::Registered))
        .unwrap_or(false);
    if !host_ok {
        return false;
    }
    let mut services = 0usize;
    let mut registered = 0usize;
    let _ = ot.srp_services(|svc| {
        if let Some((_svc, state, _slot)) = svc {
            services += 1;
            if state == SrpState::Registered {
                registered += 1;
            }
        }
    });
    services > 0 && services == registered
}

/// SRP のホスト/サービス状態と client 稼働状況の要約ログ(状態変化の切り分け用)。
fn srp_status_log(ot: &OpenThread<'_>) {
    let host = ot
        .srp_conf(|_c, state, _| Ok(state))
        .map(|s| s as SrpState);
    let running = ot.srp_running().unwrap_or(false);
    let mut svc_state: Option<SrpState> = None;
    let _ = ot.srp_services(|svc| {
        if let Some((_s, state, _slot)) = svc {
            svc_state = Some(state);
        }
    });
    println!(
        "[srp] state host={:?} service={:?} client_running={} server={:?}",
        host.ok(),
        svc_state,
        running,
        ot.srp_server_addr().ok().flatten(),
    );
}

/// BLE commissionable 広告データ(0xFFF6 service data)を生成する。
///
/// Thread 版の OCW(AdminCommissioning)では commissionable 発見に mDNS
/// (`_matterc._udp`)を使えない(SRP は運用広告のみ。未参加時は SRP に出せず、
/// 参加後も advertising proxy が流すのは運用系 = `_matter._tcp`)。そこで **窓オープン中
/// のみ BLE 広告を時分割で一時再開**し、新コントローラは BLE(BTP)経由 PASE、または
/// デバイスが既に Thread 上にあることを利用した **Thread UDP 直接 PASE** のいずれかで
/// 入る(どちらも `set_pase_enabled(true)` で開いた PASE を共有する)。詳細は
/// `docs/design/thread-port.md` §T3 item 8(OCW の Thread 流)。
fn adv_data(discriminator: u16) -> AdvData {
    AdvData {
        discriminator,
        vendor_id: CFG.vendor_id,
        product_id: CFG.product_id,
        additional_data: false,
        ext_announcement: false,
    }
}

// ==========================================================================
// 統合層(pump): BTP + OT UDP ⇔ MatterStack、SRP 登録、dataset 永続化
// ==========================================================================

#[allow(clippy::too_many_arguments)]
async fn pump(
    gatt: &mut TroubleGattPeripheral<'_>,
    channels: &GattChannels,
    stack: &mut LightStack<'_>,
    led: &mut Output<'_>,
    fabrics: &RefCell<FabricTable<Backend, NF>>,
    window: &RefCell<CommissioningWindow>,
    kvs: &RefCell<EspKvs>,
    settings_store: &'static RefCell<SettingsStore>,
    matter_udp: &mut OtUdp<'_>,
    ot: OpenThread<'static>,
    mac: [u8; 6],
) -> ! {
    let mut btp = Btp::<6>::new(BtpRole::Peripheral);
    let mut conn: Option<BtpConnId> = None;
    let mut mtu: Option<u16> = None;
    let mut subscribed = false;
    let mut established_logged = false;
    let mut led_on = false;
    let mut saved_gen = fabrics.borrow().generation();
    let mut saved_resumption_gen = stack.resumption_generation();
    // 初回コミッショニング窓(fabric 0 個で起動 = 焼き込みパスコードの PASE が有効)。
    // fabric 保有で起動した場合は false(PASE は main で無効化済み。OCW でのみ受付)。
    let mut boot_window_open = fabrics.borrow().is_empty();
    let mut last_fabric_count = fabrics.borrow().len();
    // SRP 登録は fabric が存在した時点で 1 回だけ発行する(attach 前でも SRP client が
    // netdata 監視で自動開始する。fabric 変更時の再登録はリブートで吸収 = T2 割り切り)。
    let mut srp_submitted = false;
    // 遅延 ConnectNetworkResponse の SRP ゲート: サーバ確認(Registered)を観測したら
    // driver の operational_ready を立てる。attach から FALLBACK ms 経っても確認できない
    // 場合は安全側で立てる(IM エンジンの deferred 締切 20s に収める)。
    let mut operational_ready = false;
    // attach(role connected)を最初に観測した時刻(ms)。フォールバックの起点。
    let mut attached_since_ms: Option<u64> = None;
    // IM エンジンの deferred 締切は 20 秒で、attach 自体に ~10 秒かかることがあるため
    // 短くする(SRP サーバ確認が間に合わない場合はコントローラ側の解決リトライに委ねる)。
    const OPERATIONAL_READY_FALLBACK_MS: u64 = 5_000;
    // SRP 登録が滞った際の再キック(stop→autostart)の最終発行時刻。
    let mut last_srp_kick_ms: u64 = 0;
    // SRP 運用登録が有効な fabric 世代(item 2: fabric 増減で SRP を作り直す起点)。
    let mut srp_fabric_gen = fabrics.borrow().generation();
    // --- OT settings の idle 時 flush(item 1 / R6)---
    // 直近に 15.4 radio が通信した時刻(UDP 送受で更新)。flash flush を静穏窓に限る。
    let mut last_radio_activity_ms: u64 = 0;
    // 直近に settings を flash へ書いた時刻(flush 頻度の絞り込み)。
    let mut last_settings_flush_ms: u64 = 0;
    // flash write(キャッシュ停止)を許してよい静穏時間(直近 UDP からの経過)。
    const SETTINGS_QUIET_MS: u64 = 4_000;
    // settings flush の最小間隔。重要データ(dataset / network key / SRP ECDSA 鍵)は
    // attach 直後に一度書けば十分で、以降の軽微な更新(parent info / lease カウンタ)を
    // 頻繁に flash へ書くと flash 摩耗とキャッシュ停止の機会が増える。60s に広げて
    // ソーク中の書き込み回数を抑える(dirty が続いても 60s に 1 回まで)。
    const SETTINGS_FLUSH_INTERVAL_MS: u64 = 60_000;
    // attach 直後の settings 書き込みバースト(dataset/NetworkInfo/SRP 鍵)を RAM で吸収し、
    // attach が落ち着くまで flush を遅らせる猶予(attach からの経過)。
    const SETTINGS_ATTACH_SETTLE_MS: u64 = 10_000;
    // OMR アドレスを手動追加済みか(netdata 受信後 1 回だけ。maybe_add_omr_address)。
    let mut omr_added = false;
    // EUI-64(OMR アドレスの IID 生成用。main と同じ FF:FE 挿入)。
    let eui64: [u8; 8] = [
        mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ];

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txd = [0u8; MAX_PACKET_SIZE];
    let mut udp_rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut next_heartbeat_ms: u64 = 0;

    loop {
        let now = now_ms(start);
        if now >= next_heartbeat_ms {
            let st = ot.net_status();
            println!(
                "[alive] t={}s conn={:?} subscribed={} role={:?} light={}",
                now / 1000,
                conn.map(|c| c.0),
                subscribed,
                st.role,
                if led_on { "ON" } else { "OFF" }
            );
            next_heartbeat_ms = now + 10_000;
        }

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

        match select3(
            gatt.next_event(&mut buf),
            matter_udp.recv_from(&mut udp_rx),
            Timer::after_millis(sleep_ms),
        )
        .await
        {
            // --- BLE(BTP)イベント ---
            Either3::First(Ok(ev)) => {
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
                        // R2 時分割: コミッショニング済み(fabric 保有)なら BLE 広告を止め、
                        // 2.4GHz 無線を 802.15.4(CASE over Thread / SRP)に明け渡す。
                        // esp-radio に BLE/15.4 コエグジスタンスが無く、常時広告は 15.4 RX を
                        // 恒常的に劣化させる(thread-port.md R2 実測)。
                        if !fabrics.borrow().is_empty() {
                            channels.set_adv_enabled(false);
                            println!("[ble] advertising disabled (commissioned; radio to 15.4)");
                        }
                    }
                }
            }
            Either3::First(Err(e)) => {
                println!("[ble] next_event error: {:?}", e);
            }
            // --- Matter UDP 受信(CASE over Thread はここを通る)---
            Either3::Second(Ok((n, src))) => {
                let now = now_ms(start);
                // 15.4 radio が今 active(settings flush をこの直後は避ける)。
                last_radio_activity_ms = now;
                // 先頭 8 バイト(message flags / session id / security flags / counter)を
                // 添えて受信を記録する(silent drop の切り分け用)。
                let mut head = [0u8; 8];
                let hl = n.min(8);
                head[..hl].copy_from_slice(&udp_rx[..hl]);
                println!(
                    "[udp] rx {}B from {:?} head={:02x?}",
                    n, src, &head[..hl]
                );
                let dir = stack.handle_rx(&mut udp_rx[..n], src, now, &mut txd);
                if dir.is_none() {
                    println!("[udp] rx dropped (no directive)");
                }
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
            Either3::Second(Err(e)) => {
                println!("[udp] recv error: {:?}", e);
            }
            Either3::Third(()) => {
                let now = now_ms(start);
                if let (Some(c), true) = (conn, subscribed) {
                    if let Err(e) = flush_out(gatt, &mut btp, c, mtu, now).await {
                        println!("[btp] flush(timer) error: {:?}", e);
                    }
                }
            }
        }

        if !established_logged && btp.is_established() {
            established_logged = true;
            println!(
                "[btp] established (att_mtu={}, fragment={})",
                mtu.unwrap_or(0),
                btp.fragment_size()
            );
        }

        // --- 時間駆動の送出 + 閉じた exchange の回収(毎周必須)+ 遅延 ConnectNetwork 解決 ---
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, &mut txd) {
            // 周期的な UDP 送出(subscribe レポート / MRP ack / 再送)= radio active。
            if matches!(d.addr, PeerAddr::Udp(_)) {
                last_radio_activity_ms = now;
            }
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

        let now = now_ms(start);
        if btp.is_timed_out(now) {
            println!("[btp] session timed out; disconnecting");
            btp.reset();
            established_logged = false;
            if let Some(c) = conn.take() {
                let _ = gatt.disconnect(c).await;
            }
        }

        // --- Thread attach の結果を NetworkCommissioning 属性へ反映 ---
        stack.device_mut().net.update_from_driver();

        // --- OnOff 属性を実 LED(GPIO7)へ反映する ---
        let on = stack.device().onoff.is_on();
        if on != led_on {
            led_on = on;
            led.set_level(if on { Level::High } else { Level::Low });
        }

        // --- 新しい dataset(AddOrUpdateThreadNetwork)を flash へ永続化 ---
        if let Some(ds) = stack.device_mut().net.driver_mut().take_pending_dataset() {
            match kvs.borrow_mut().set(DATASET_KEY, &ds) {
                Ok(()) => println!("[kvs] saved thread dataset ({} bytes)", ds.len()),
                Err(e) => println!("[kvs] dataset save error: {:?}", e),
            }
        }

        // --- fabric が存在したら SRP 運用広告を提出する(1 回。attach 前でも可:
        //     srp_autostart が netdata から SRP サーバを発見した時点で登録が走る)---
        if !srp_submitted {
            let fab = fabrics
                .borrow()
                .iter()
                .next()
                .map(|f| (f.compressed_fabric_id(), f.node_id()));
            if let Some((cfid, nid)) = fab {
                match register_srp(&ot, cfid, nid, &mac) {
                    Ok(()) => {
                        srp_submitted = true;
                        // 以降の fabric 世代変化(item 2 の resync)の起点を確定する。
                        srp_fabric_gen = fabrics.borrow().generation();
                    }
                    Err(e) => println!("[srp] register error: {:?}", e),
                }
            }
        }

        // --- SRP ゲート: 運用準備完了を driver へ報告する(thread-port.md §T2)---
        //
        // 遅延 ConnectNetworkResponse は driver の status()=Attached で送出されるが、
        // SRP 登録が OTBR advertising proxy(LAN mDNS)へ伝搬する前に返すと chip-tool の
        // operational discovery(~30s)が SRP 伝搬に先行してタイムアウトする(T2 実測)。
        // そこで「SRP service が Registered(サーバ確認済み)」まで Attached を保留する。
        // フォールバック: attach から 12 秒(attach 検知の遅れ込みで IM の deferred 締切
        // 20 秒に収まる)経っても Registered にならなければ成功として進める — Thread
        // 自体は接続済みであり、SRP の遅延・失敗で ConnectNetwork ごと落とすのは過剰
        // (chip-tool 側の発見リトライに賭ける)。
        let attached = ot.net_status().role.is_connected();
        if attached && attached_since_ms.is_none() {
            attached_since_ms = Some(now_ms(start));
        }
        // --- OMR アドレスの手動追加(attach 後、netdata の SLAAC prefix が届いたら 1 回)---
        if attached && !omr_added {
            omr_added = maybe_add_omr_address(&ot, &eui64);
        }

        // SRP client の登録リトライは失敗バックオフで数分単位に伸び得る(T2 実測:
        // attach 直後の初回登録がジッタ/失敗すると server へ届くまで数分沈黙)。attach 済み
        // かつ未登録のまま 20 秒経過するごとに autostart を再発行して登録サイクルを
        // 即時再開させる(サーバ再選択 + 登録試行)。
        if srp_submitted && attached && !srp_all_registered(&ot) {
            let now = now_ms(start);
            if now.saturating_sub(last_srp_kick_ms) >= 30_000 {
                last_srp_kick_ms = now;
                srp_status_log(&ot);
                let _ = ot.srp_stop();
                match ot.srp_autostart() {
                    Ok(()) => println!("[srp] re-kicked client (stop -> autostart)"),
                    Err(e) => println!("[srp] re-kick error: {:?}", e),
                }
            }
        }

        if !operational_ready && attached {
            let registered = srp_submitted && srp_all_registered(&ot);
            let deadline_passed = attached_since_ms
                .map(|t| now_ms(start).saturating_sub(t) >= OPERATIONAL_READY_FALLBACK_MS)
                .unwrap_or(false);
            if registered || deadline_passed {
                operational_ready = true;
                stack
                    .device_mut()
                    .net
                    .driver_mut()
                    .set_operational_ready(true);
                println!(
                    "[srp] operational ready ({})",
                    if registered {
                        "server-confirmed"
                    } else {
                        "fallback: deadline after attach"
                    }
                );
            }
        }

        // --- fabric 変更(generation)で flash 保存 ---
        let gen = fabrics.borrow().generation();
        if gen != saved_gen {
            saved_gen = gen;
            let table = fabrics.borrow();
            match table.save_to(&mut *kvs.borrow_mut()) {
                Ok(()) => println!("[kvs] saved {} fabrics (generation={})", table.len(), gen),
                Err(e) => println!("[kvs] save error: {:?}", e),
            }
        }

        // --- fabric 増減で SRP 運用登録を作り直す(item 2)---
        //
        // 初回登録は下の `!srp_submitted` ブロックが担う。ここは **登録済みの後に**
        // fabric 世代が変わった(AddNOC で追加 fabric / RemoveFabric / 全削除)場合に
        // 反応する。全削除なら SRP を撤去し、次の fabric 追加で初回登録経路に戻す。
        if srp_submitted && gen != srp_fabric_gen {
            srp_fabric_gen = gen;
            let still_registered = resync_srp(&ot, fabrics, &mac);
            if !still_registered {
                srp_submitted = false;
                operational_ready = false;
            }
        }

        // --- CASE resumption ストアの世代変化を検知して flash 保存 ---
        let rgen = stack.resumption_generation();
        if rgen != saved_resumption_gen {
            saved_resumption_gen = rgen;
            match stack.save_resumptions_to(&mut *kvs.borrow_mut()) {
                Ok(()) => println!("[kvs] saved {} resumptions", stack.resumption_count()),
                Err(e) => println!("[kvs] resumption save error: {:?}", e),
            }
        }

        // --- コミッショニング窓ゲート(fabric 数ベース。§admin-commissioning §4/§5)---
        //
        // 焼き込みパスコードの PASE は「fabric 0 個」の間だけ有効(初回コミッショニング)。
        // 窓経由でコミッショニングが成功(fabric 増加)したら窓を閉じ、以降の管理者追加は
        // OCW(AdminCommissioning)経由のみとする。Thread では commissionable 発見に mDNS を
        // 使えないため、窓オープン中のみ BLE 広告を再開 + PASE を開き、新コントローラは BLE
        // または Thread UDP 直接 PASE で入る(adv_data のドキュメント参照)。
        let fabric_count = fabrics.borrow().len();
        if fabric_count > last_fabric_count && window.borrow().is_open() {
            // 窓経由のコミッショニング成功 → 窓を閉じる(§11.19.5)。Closed イベントが積まれ、
            // 次周の WindowEvent 処理で PASE/BLE 広告が畳まれる。
            window.borrow_mut().close_window();
            println!("[window] commissioning succeeded; closing window");
        }
        if boot_window_open && fabric_count > 0 && !window.borrow().is_open() {
            // 初回コミッショニング完了: 焼き込みパスコードの PASE を閉じる。
            boot_window_open = false;
            stack.set_pase_enabled(false);
            println!("[window] initial commissioning done; PASE disabled");
        } else if !boot_window_open && fabric_count == 0 && !window.borrow().is_open() {
            // 全 fabric 削除(工場出荷相当): 初期状態(焼き込みパスコード)へ戻す。
            boot_window_open = true;
            let cfg = simple_matter::dev_pase::dev_pase_config();
            stack.set_pase_config(cfg);
            stack.set_pase_enabled(true);
            channels.set_adv_enabled(true);
            let _ = gatt.start_advertising(&adv_data(DISCRIMINATOR)).await;
            println!("[window] all fabrics removed; reopening initial commissioning window");
        }
        last_fabric_count = fabric_count;

        // --- コミッショニング窓イベントを PASE 設定と BLE 広告へ反映する(§admin-commissioning §4)---
        // borrow を窓イベント取り出しと後続利用で分ける(borrow がボディ全体で生存する罠)。
        let window_event = window.borrow_mut().take_event();
        if let Some(ev) = window_event {
            match ev {
                WindowEvent::OpenedEnhanced { discriminator } => {
                    // borrow を await 手前で落とすため所有値へ取り出す(clippy: await_holding_refcell_ref)。
                    let pase = window.borrow().pase_config();
                    if let Some(cfg) = pase {
                        stack.set_pase_config(cfg);
                        stack.set_pase_enabled(true);
                        // Thread 時分割: 窓オープン中のみ BLE 広告(CM=2、新 discriminator)を
                        // 再開する。Thread UDP 直接 PASE も set_pase_enabled(true) で同時に開く。
                        channels.set_adv_enabled(true);
                        let _ = gatt.start_advertising(&adv_data(discriminator)).await;
                        println!(
                            "[window] enhanced window open (CM=2, discriminator {}); PASE enabled, BLE re-advertising",
                            discriminator
                        );
                    }
                }
                WindowEvent::OpenedBasic => {
                    // 焼き込み(dev)verifier で BC 窓を開く(§FeatureMap bit0)。
                    let cfg = simple_matter::dev_pase::dev_pase_config();
                    stack.set_pase_config(cfg);
                    stack.set_pase_enabled(true);
                    channels.set_adv_enabled(true);
                    let _ = gatt.start_advertising(&adv_data(DISCRIMINATOR)).await;
                    println!("[window] basic window open (CM=1); PASE enabled, BLE re-advertising");
                }
                WindowEvent::Closed => {
                    stack.set_pase_enabled(false);
                    // BLE 広告を止めて 2.4GHz を 15.4 に明け渡す(接続中なら切断後に効く)。
                    channels.set_adv_enabled(false);
                    println!("[window] commissioning window closed; PASE disabled, BLE advertising off");
                }
            }
            // AdminVendorId は fabric テーブルから解決して書き戻す(admin-commissioning §7)。
            let admin_idx = window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }

        // --- OT settings の idle 時 flush(item 1 / R6)---
        //
        // OT の settings 書き込みは RAM 権威([`SettingsStore`])で即応し flash に触れない。
        // ここで **radio が静穏な窓** = ①直近 UDP から SETTINGS_QUIET_MS 経過 ②attach 済みで
        // 落ち着き済み ③前回 flush から SETTINGS_FLUSH_INTERVAL_MS 経過 ―― が揃った時だけ
        // flash へ 1 アイテムで書き出す。attach 時の書き込みバーストを RAM で吸収して 15.4
        // radio を止めない(R6 根治)。dataset / NetworkInfo / SRP ECDSA 鍵が永続化される。
        let now = now_ms(start);
        let quiet = now.saturating_sub(last_radio_activity_ms) >= SETTINGS_QUIET_MS;
        let settled = attached_since_ms
            .map(|t| now.saturating_sub(t) >= SETTINGS_ATTACH_SETTLE_MS)
            .unwrap_or(false);
        let throttle_ok = now.saturating_sub(last_settings_flush_ms) >= SETTINGS_FLUSH_INTERVAL_MS
            || last_settings_flush_ms == 0;
        if settings_store.borrow().is_dirty()
            && quiet
            && settled
            && throttle_ok
            && ot_settings::flush(settings_store, kvs)
        {
            last_settings_flush_ms = now;
            println!(
                "[kvs] flushed OT settings ({} bytes) at idle t={}s",
                settings_store.borrow().raw().len(),
                now / 1000
            );
        }
    }
}

/// OT スタック本体を駆動する(radio 送受と内部タイマ処理。戻らない)。
#[embassy_executor::task]
async fn run_ot(ot: OpenThread<'static>, radio: EspRadio<'static>) -> ! {
    ot.run(radio).await
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // openthread クレート(vendored)の log 出力(R9/TX 診断の warn/info)を有効化する。
    // レベルはビルド時の `ESP_LOG` 環境変数(未指定は info)。
    esp_println::logger::init_logger_from_env();

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-C6 port (phase T2: Matter/Thread)");
    println!(" hal   : esp-hal 1.1.1 + esp-radio 0.18 (802.15.4+ble)");
    println!(" stack : openthread 0.2.0 + trouble-host 0.6 + simple-matter");
    println!("======================================================");

    // 802.15.4 + BLE + OT 内部 + simple-matter のヒープ(esp-radio 用)。
    esp_alloc::heap_allocator!(size: 128 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG。TrngSource は main の生存期間中保持し続ける(drop すると擬似乱数に戻る)。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = esp_rng();

    // BLE の static random address を TRNG から生成(上位 2 ビット = 0b11)。
    let mut addr = [0u8; 6];
    rng.fill_bytes(&mut addr).expect("TRNG fill");
    addr[5] |= 0xC0;
    println!(
        "[ble] static random address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]
    );

    // M5Stack NanoC6 の青 LED(GPIO7、active-high)。OnOff を実表示する。
    let mut led = Output::new(peripherals.GPIO7, Level::Low, OutputConfig::default());

    // EUI-64(efuse factory MAC から FF:FE 挿入で導出)。
    let mac6 = esp_hal::efuse::base_mac_address();
    let mac6 = mac6.as_bytes();
    let mac: [u8; 6] = [mac6[0], mac6[1], mac6[2], mac6[3], mac6[4], mac6[5]];
    let ieee_eui64 = [
        mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ];

    // --- flash KVS(fabric / resumption / dataset / OT settings で共有)---
    //
    // OT の Settings 実装(KvsSettings)と pump の永続化が同じ flash 領域を使うため、
    // RefCell で包んで 'static に置く(すべて同一 executor 上の同期借用)。
    let kvs: &'static RefCell<EspKvs> = mk_static!(
        RefCell<EspKvs>,
        RefCell::new(EspKvs::new(peripherals.FLASH))
    );

    // --- openthread 初期化(UDP + SRP 対応。リソースは全て 'static)---
    let ot_rng = mk_static!(Rng, Rng::new());
    let ot_resources = mk_static!(OtResources, OtResources::new());
    let ot_udp_resources = mk_static!(
        OtUdpResources<UDP_MAX_SOCKETS, UDP_SOCKETS_BUF>,
        OtUdpResources::new()
    );
    // MAX_SERVICES=2, BUF=512(SRP: host + _matter._tcp)。
    let ot_srp_resources = mk_static!(OtSrpResources<2, 512>, OtSrpResources::new());
    // OT Settings = **RAM 権威 + idle 時 flush**(item 1 / リスク R6 解決。ot_settings.rs)。
    // OT の settings 書き込み(attach 時にバースト)はすべて RAM で即応し flash に触れない。
    // pump が radio 静穏窓でまとめて 1 アイテムを flash へ書く。これで attach 時の書き込み
    // バーストが 15.4 radio を止めず(T2 の R6 顕在化を根治)、dataset / NetworkInfo /
    // **SRP ECDSA 鍵** が永続化される → リブート後に SRP 鍵が保たれ、SRP サーバに残る旧登録
    // (key-lease 既定 ~7.8 日)と鍵衝突せず同一ホストで再登録できる。
    let settings_store = mk_static!(RefCell<SettingsStore>, RefCell::new(SettingsStore::new()));
    match ot_settings::restore(settings_store, kvs) {
        Ok(0) => println!("[kvs] no persisted OT settings (fresh)"),
        Ok(n) => println!("[kvs] restored OT settings ({} bytes)", n),
        Err(()) => println!("[kvs] OT settings restore failed; starting empty"),
    }
    let ot_settings = mk_static!(KvsSettings, KvsSettings::new(settings_store));

    let ot = OpenThread::new_with_udp_srp(
        ieee_eui64,
        ot_rng,
        ot_settings,
        ot_resources,
        ot_udp_resources,
        ot_srp_resources,
    )
    .expect("OpenThread init failed");

    // OT スタック駆動タスク(radio との橋渡し)。
    spawner.spawn(
        run_ot(
            ot.clone(),
            EspRadio::new(Ieee802154::new(peripherals.IEEE802154)),
        )
        .unwrap(),
    );

    // MTD だが rx-on-when-idle(Matter コマンド / SRP 応答の受信に必須)。
    if let Err(e) = ot.set_link_mode(true, false, true) {
        println!("[ot] set_link_mode error: {:?}", e);
    }
    // OMR アドレスは pump が netdata の on-mesh prefix から手動生成する
    // (プリビルト OT は SLAAC 無効ビルドのため。maybe_add_omr_address 参照)。

    // Thread ドライバ(cluster に注入)。OpenThread ハンドルのクローンを保持。
    let thread_driver = OtThreadDriver::new(ot.clone());

    // --- MatterStack 構築 ---
    let crypto = RustCrypto::new(esp_rng());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());
    // コミッショニング窓(AdminCommissioning 0x003C と pump が共有)。
    let window: RefCell<CommissioningWindow> = RefCell::new(CommissioningWindow::new());

    // flash KVS から fabric テーブルを復元する。
    let restore = fabrics
        .borrow_mut()
        .load_from(&mut *kvs.borrow_mut(), &crypto, 0);
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

    // 永続化した dataset があれば OT を起動して自動 re-attach する(リブート後)。
    // dataset 本体は OT 自身が KvsSettings(ActiveDataset)から復元済みなので、
    // ここでは own レコードの有無を「コミッショニング済みか」の判定に使い
    // enable のみ行う(再注入は不整合時の保険)。
    {
        let mut ds = [0u8; 254];
        let read = kvs.borrow_mut().get(DATASET_KEY, &mut ds);
        match read {
            Ok(Some(len)) => {
                println!("[kvs] restored thread dataset ({} bytes); re-attaching", len);
                if let Err(e) = ot.set_active_dataset_tlv(&ds[..len]) {
                    println!("[ot] set_active_dataset_tlv error: {:?}", e);
                }
                let _ = ot.enable_ipv6(true);
                if let Err(e) = ot.enable_thread(true) {
                    println!("[ot] enable_thread error: {:?}", e);
                }
            }
            Ok(None) => println!("[kvs] no persisted thread dataset (fresh)"),
            Err(e) => println!("[kvs] dataset read failed: {:?}", e),
        }
    }

    println!("[pase] loading embedded dev SPAKE2+ verifier (device holds no passcode)...");
    let pase = simple_matter::dev_pase::dev_pase_config();
    println!("[pase] verifier ready");

    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, esp_rng(), pase, creds);
    let im = InteractionModel::new(build_light(&fabrics, &window, thread_driver));
    let mut stack: LightStack<'_> = MatterStack::new(&crypto, sc, im);
    // コミッショニング済みで起動した場合、焼き込みパスコードの PASE は閉じる
    // (管理者追加は OCW 経由のみ。§admin-commissioning の窓ゲート)。BLE 広告も
    // 既に抑止済み(下の start_advertising 分岐)なので、Thread UDP 直接 PASE も含めて
    // 未認可のコミッショニングを封じる。
    if !fabrics.borrow().is_empty() {
        stack.set_pase_enabled(false);
        println!("[pase] disabled at boot (already commissioned; use OCW to add admins)");
    }
    let _ = stack.post_startup_event(CFG.software_version, 0);
    println!(
        "[stack] DefaultStack ready ({} bytes, on main stack)",
        core::mem::size_of::<LightStack<'static>>()
    );

    match stack.load_resumptions_from(&mut *kvs.borrow_mut()) {
        Ok(n) => println!("[kvs] restored {} resumptions", n),
        Err(e) => println!("[kvs] resumption restore failed: {:?}", e),
    }

    // Matter UDP(5540)ソケットを OT ネイティブ UDP で bind する。
    let socket = UdpSocket::bind(
        ot.clone(),
        &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MATTER_PORT, 0, 0),
    )
    .expect("UDP bind 5540");
    let mut matter_udp = OtUdp::new(socket);
    println!("[udp] Matter UDP bound on [::]:{}", MATTER_PORT);

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

    let server =
        BtpGattServer::new_with_config(trouble_host::gap::GapConfig::default("simple-matter"))
            .expect("GATT server build");

    let channels = GattChannels::new();
    let mut gatt = TroubleGattPeripheral::new(&channels);

    let adv = AdvData {
        discriminator: DISCRIMINATOR,
        vendor_id: CFG.vendor_id,
        product_id: CFG.product_id,
        additional_data: false,
        ext_announcement: false,
    };
    // R2 時分割: コミッショニング済みで起動した場合は BLE 広告を出さない
    // (再コミッショニングはNVS消去で。15.4 の RX 品質を確保する)。
    if fabrics.borrow().is_empty() {
        gatt.start_advertising(&adv)
            .await
            .expect("start_advertising");
    } else {
        channels.set_adv_enabled(false);
        println!("[ble] advertising suppressed (already commissioned; radio to 15.4)");
    }

    println!(
        "[boot] dev verifier (passcode 20202021, not stored) discriminator={} vid={:#06x} pid={:#06x}",
        DISCRIMINATOR, CFG.vendor_id, CFG.product_id
    );
    println!("[boot] commission with: chip-tool pairing ble-thread 1 hex:<dataset-tlv> {} {} --ble-controller 0", 20202021, DISCRIMINATOR);

    // TrouBLE host runner / GATT worker / 統合層 pump を単一 executor 上で並走させる
    // (OT スタックは spawner で別タスク)。
    join3(
        async {
            let e = runner.run().await;
            panic!("[ble] host runner exited: {:?}", e);
        },
        gatt_worker(&mut peripheral, &server, &channels),
        pump(
            &mut gatt,
            &channels,
            &mut stack,
            &mut led,
            &fabrics,
            &window,
            kvs,
            settings_store,
            &mut matter_udp,
            ot.clone(),
            mac,
        ),
    )
    .await;
    unreachable!();
}
