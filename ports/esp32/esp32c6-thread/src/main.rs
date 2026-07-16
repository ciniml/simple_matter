//! ESP32-C6 向け Thread join スモーク — フェーズ T1。
//!
//! `docs/design/thread-port.md` §T1 の検証ファームウェア。証明すること:
//!
//! 1. openthread 0.2.0(esp-rs 公式バインディング)+ esp-radio 0.18 の
//!    IEEE 802.15.4 ドライバが、既存 C6 ポートのワークスペース
//!    (esp-hal 1.1.1 / esp-rtos 0.3 / stable rustc)でビルド・リンクできる。
//! 2. コンパイル時定数の Operational Dataset(TLV hex)で Thread ネットワークに
//!    join し、状態遷移(detached → child/router)と mesh-local アドレスが
//!    ログで確認できる。
//! 3. OTBR(ホスト側 Border Router、`scripts/otbr/` 参照)から ping / UDP echo
//!    が通る(ICMPv6 echo は OT スタック自身が応答する。UDP echo はポート
//!    [`ECHO_PORT`] で本ファームウェアが応答する)。
//!
//! esp32c6-firmware とは別パッケージ(esp-radio が ieee802154 と wifi の同時
//! 有効化を拒否するため。`Cargo.toml` のコメント参照)。
//!
//! dataset の払い出しと実機手順は `scripts/otbr/README.md` を参照。書き込み:
//!
//! ```sh
//! cd ports/esp32
//! THREAD_DATASET=<ot-ctl "dataset active -x" の hex> \
//!     cargo run -p esp32c6-thread --release --bin thread-smoke
//! ```
//!
//! THREAD_DATASET 未指定時は esp-rs/openthread の example と同じダミー dataset で
//! 起動する(join 先が無くても状態機械とログは動く = ビルド/起動スモーク)。

#![no_std]
#![no_main]

use core::net::{Ipv6Addr, SocketAddrV6};

use embassy_executor::Spawner;

use esp_backtrace as _;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_radio::ieee802154::Ieee802154;

use log::info;

use openthread::esp::EspRadio;
use openthread::{
    BytesFmt, OpenThread, OtResources, OtUdpResources, SimpleRamSettings, UdpSocket,
};

use static_cell::StaticCell;

// OpenThread の C コードが参照する str*/mem* 系 libc シンボルのポリフィル
// (リンクのために必要。docs/design/thread-port.md §3.2)。
use tinyrlibc as _;

esp_bootloader_esp_idf::esp_app_desc!();

/// UDP echo を待ち受けるポート。OTBR 側から
/// `ot-ctl udp send <mesh-local> 11095 hello` で応答を確認する。
const ECHO_PORT: u16 = 11095;

/// OT ネイティブ UDP ソケットのバッファ構成。1 ソケット 1280B(IPv6 MTU)。
const UDP_SOCKETS_BUF: usize = 1280;
const UDP_MAX_SOCKETS: usize = 2;

/// Thread Operational Dataset(TLV 形式の hex 文字列)。
///
/// T1 ではコンパイル時定数で注入する(`THREAD_DATASET=... cargo build`)。
/// T2 以降は NetworkCommissioning(AddOrUpdateThreadNetwork)経由で受け取り
/// KVS に永続化する(doc §4)。未指定時のデフォルトは esp-rs/openthread の
/// example と同じダミー値(実網には join しない)。
const THREAD_DATASET: &str = if let Some(dataset) = option_env!("THREAD_DATASET") {
    dataset
} else {
    "000300001901020fd80208b566147d38e384200e080000639c5d67a3bd0510c490f58d4be0d5eaeb0f09b395d1ae17030d4e4553542d50414e2d304644380708fd7d4f8232cb00000410a7e08419ae47c177fb91bcfcec789aa50c0402a0f77835060004001fffe0"
};

/// `StaticCell` 経由で 'static な可変参照を作る(openthread のリソースは
/// すべて 'static を要求する。esp-rs/openthread example の mk_static! と同じ)。
macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: StaticCell<$t> = StaticCell::new();
        CELL.init($val)
    }};
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    // esp-rtos(esp-alloc feature)+ esp-radio の内部バッファ用ヒープ。
    // 802.15.4 のみなので Wi-Fi/BLE 併用の e5-light(144KiB)より小さくてよい。
    esp_alloc::heap_allocator!(size: 96 * 1024);

    esp_println::logger::init_logger_from_env();

    info!("==============================================");
    info!(" simple-matter :: ESP32-C6 thread-smoke (T1)");
    info!(" openthread 0.2.0 + esp-radio 0.18 (802.15.4)");
    info!("==============================================");

    let peripherals = esp_hal::init(esp_hal::Config::default());

    // esp-radio が要求する preemptive スケジューラを起動(e5-light と同じ手順)。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // RNG(openthread の OtRngCore = rand_core 0.9)。
    // T1 スモークでは疑似乱数で十分(本番ポートでは TrngSource を有効化した
    // Trng を使う。src/main.rs の EspRng 参照)。
    let rng = mk_static!(Rng, Rng::new());

    // EUI-64。efuse の factory MAC(EUI-48)から EUI-64 を導出する
    // (FF:FE 挿入方式)。extended address / SLAAC の元になる。
    let mac = esp_hal::efuse::base_mac_address();
    let mac = mac.as_bytes();
    let ieee_eui64 = [
        mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ];
    info!(
        "eui64: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        ieee_eui64[0],
        ieee_eui64[1],
        ieee_eui64[2],
        ieee_eui64[3],
        ieee_eui64[4],
        ieee_eui64[5],
        ieee_eui64[6],
        ieee_eui64[7]
    );

    // openthread のリソース(すべて呼び出し側が 'static で用意する。ヒープレス)。
    let ot_resources = mk_static!(OtResources, OtResources::new());
    let ot_udp_resources = mk_static!(
        OtUdpResources<UDP_MAX_SOCKETS, UDP_SOCKETS_BUF>,
        OtUdpResources::new()
    );
    // T1 は RAM settings(揮発)。T2 以降で KVS 裏打ちの Settings 実装に差し替え、
    // dataset / SRP キーを flash に永続化する(doc §5.3)。
    let ot_settings_buf = mk_static!([u8; 1024], [0; 1024]);
    let ot_settings = mk_static!(SimpleRamSettings, SimpleRamSettings::new(ot_settings_buf));

    let ot = OpenThread::new_with_udp(ieee_eui64, rng, ot_settings, ot_resources, ot_udp_resources)
        .expect("OpenThread init failed");

    // OT スタック本体の駆動タスク(radio との橋渡し)。
    // embassy-executor 0.10 では task fn が Result<SpawnToken> を返す。
    spawner.spawn(
        run_ot(
            ot.clone(),
            EspRadio::new(Ieee802154::new(peripherals.IEEE802154)),
        )
        .unwrap(),
    );

    // 状態遷移(role)と IPv6 アドレス(mesh-local 含む)の監視ログタスク。
    spawner.spawn(run_ot_state_log(ot.clone()).unwrap());

    // R9 切り分け用 heartbeat(5 秒周期)。これが止まる = executor/タイマ層ごと停止、
    // 続く = OT 層のみ停止、を区別する(thread-port.md R9)。
    spawner.spawn(run_heartbeat(ot.clone()).unwrap());

    info!("dataset (TLV hex): {THREAD_DATASET}");

    ot.set_active_dataset_tlv_hexstr(THREAD_DATASET)
        .expect("invalid dataset TLV");
    ot.enable_ipv6(true).expect("enable_ipv6 failed");
    ot.enable_thread(true).expect("enable_thread failed");

    info!("thread enabled; joining...");

    // UDP echo。OTBR から `ot-ctl udp send <addr> 11095 hello` で確認する。
    let socket = UdpSocket::bind(
        ot.clone(),
        &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, ECHO_PORT, 0, 0),
    )
    .expect("UDP bind failed");

    info!("UDP echo listening on port {ECHO_PORT}");

    let buf = mk_static!([u8; UDP_SOCKETS_BUF], [0; UDP_SOCKETS_BUF]);

    // R9 切り分け: TX 生死の直接確認。SM_TX_PROBE=<OTBR の ML-EID> を与えると
    // 10 秒周期で UDP を送る(OTBR 側は `ot-ctl udp bind :: 12345` で観測)。
    if let Some(target) = option_env!("SM_TX_PROBE") {
        if let Ok(addr) = target.parse::<Ipv6Addr>() {
            spawner.spawn(run_tx_probe(ot.clone(), addr).unwrap());
        }
    }

    loop {
        match socket.recv(buf).await {
            Ok((len, local, remote)) => {
                info!("[echo] {} from {remote} on {local}", BytesFmt(&buf[..len]));
                if let Err(e) = socket.send(&buf[..len], Some(&local), &remote).await {
                    info!("[echo] send failed: {e:?}");
                }
            }
            Err(e) => info!("[echo] recv failed: {e:?}"),
        }
    }
}

/// OT スタック本体を駆動する(radio 送受と内部タイマ処理。戻らない)。
#[embassy_executor::task]
async fn run_ot(ot: OpenThread<'static>, radio: EspRadio<'static>) -> ! {
    ot.run(radio).await
}

/// R9 切り分け用 TX プローブ。attach 後の TX 経路が生きているかを直接確認する。
#[embassy_executor::task]
async fn run_tx_probe(ot: OpenThread<'static>, target: Ipv6Addr) -> ! {
    // 2 本目のソケット(UDP_MAX_SOCKETS=2 の範囲内、共有 OtUdpResources を使う)。
    let sock = UdpSocket::bind(
        ot,
        &SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 12346, 0, 0),
    )
    .expect("probe bind failed");
    let mut n = 0u32;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(10)).await;
        n += 1;
        let r = sock
            .send(b"probe", None, &SocketAddrV6::new(target, 12345, 0, 0))
            .await;
        info!("[txprobe] #{n} -> {target}: {r:?}");
    }
}

/// R9 切り分け用 heartbeat。executor と embassy-time が生きている限り出続ける。
#[embassy_executor::task]
async fn run_heartbeat(ot: OpenThread<'static>) -> ! {
    let mut n = 0u32;
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(5)).await;
        n += 1;
        info!("[hb] {}s role={:?}", n * 5, ot.net_status().role);
    }
}

/// 状態変化を監視し、role 遷移(detached → child/router)と IPv6 アドレスを
/// ログに出す。mesh-local アドレス(fd..、dataset の mesh-local prefix 配下)が
/// 出れば join 成功 — OTBR 側から `ping <そのアドレス>` で疎通確認する。
#[embassy_executor::task]
async fn run_ot_state_log(ot: OpenThread<'static>) -> ! {
    let mut last_role = None;
    let mut last_addrs = heapless::Vec::<(Ipv6Addr, u8), 6>::new();

    loop {
        let role = ot.net_status().role;
        if last_role != Some(role) {
            info!("[state] role: {:?} -> {:?}", last_role, role);
            last_role = Some(role);
        }

        let mut addrs = heapless::Vec::<(Ipv6Addr, u8), 6>::new();
        ot.ipv6_addrs(|addr| {
            if let Some(addr) = addr {
                let _ = addrs.push(addr);
            }
            Ok(())
        })
        .expect("ipv6_addrs failed");

        if addrs != last_addrs {
            for (addr, prefix_len) in &addrs {
                info!("[state] ipv6: {addr}/{prefix_len}");
            }
            last_addrs = addrs;
        }

        ot.wait_changed().await;
    }
}
