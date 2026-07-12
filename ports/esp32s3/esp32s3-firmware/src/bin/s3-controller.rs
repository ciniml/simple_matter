//! ESP32-S3 スタンドアロンコミッショナ(常駐ハブ)— K2(UDP)+ K3(BLE central)+
//! K4(複数ノード常駐)。
//!
//! `docs/design/esp32-controller.md` §7。smctl(PC ホスト)の駆動ループを embassy へ
//! 写像し、S3 単独で [`NODE_PLAN`] の各デバイスをフルコミッショニングして常駐管理する:
//!
//! 1. **WiFi join**(SSID/パスは定数 or `SM_WIFI_SSID`/`SM_WIFI_PASS` の
//!    ビルド時環境変数)→ DHCPv4。
//! 2. ノードごとの計画([`NODE_PLAN`])に従いコミッショニング:
//!    - **UDP**: mDNS ブラウズ(`_matterc._udp` discriminator subtype、QU 第一候補 +
//!      QM フォールバック — doc §4.2 / R5)→ `Commissioner` フル(PASE → … →
//!      AddNOC → CASE → CommissioningComplete)。
//!    - **BLE**: TrouBLE central([`TroubleGattCentral`])で scan(0xFFF6 service
//!      data、discriminator 照合)→ accept-list connect → BTP handshake → PASE〜
//!      AddNOC を BLE 上で実行 → **AddOrUpdateWiFiNetwork / ConnectNetwork**
//!      (smctl `pairing ble-wifi` と同じ `set_wifi_credentials` +
//!      `suspend_before_case`)→ BLE close → 運用 mDNS 解決 → **CASE over UDP** →
//!      CommissioningComplete。
//! 3. 定常は **30 秒ごとに全ノードをラウンドロビンで OnOff Toggle → Read**。失敗した
//!    ノードは mDNS 再解決 → CASE 再確立(resumption)で回復し、全ノードが連続失敗
//!    したときのみリブートする。
//! 4. 永続化(すべて `EspKvs`):
//!    - CA 鍵素材: キー `b"cast"`(smctl `ca-state.bin` v1 互換 =
//!      `Ca::encode_state`/`decode_state`)。
//!    - ノード帳: キー `b"nods"`(**smctl `nodes.tlv` v1 互換** = コアの
//!      `controller::nodes` codec。K2 のポートローカル 64B レコードを置き換え)。
//!    - CASE resumption 素材: ノードごとにキー `b"rsm<i>"`(ポートローカル 49B。
//!      smctl は `resume/<node>.tlv` に相当)。
//! 5. リブート後は CA / ノード帳 / resumption を復元し、各ノードを運用 mDNS 解決
//!    (`_matter._tcp`)→ CASE(可能なら Sigma2_Resume)で自動再接続する
//!    (BLE でコミッショニングしたデバイスも運用は常に UDP = dual-transport 前提)。
//!
//! # RAM 配分(doc §6.3 / R3)
//!
//! デバイス bin と同じ **heap 112KiB / .stack ≈69KiB** を踏襲する。controller は
//! 署名回数が多い(CA generate 2 発 + issue_noc + CASE Sigma)ため、`[alive]` ログの
//! `heap_max`(esp-alloc internal-heap-stats)で最高水位を常時監視する。
//!
//! 実行: `cd ports/esp32s3 && cargo build --release --bin s3-controller`
//! 対向(PC、両ノードを同一ホストで同時起動できる):
//! - node1: `SM_DISCRIMINATOR=3841 SM_MATTER_PORT=5541 SM_STATE_DIR=<dir1> \
//!   cargo run --release --example onoff-light`
//! - node2: `SM_BLE_ADAPTER=hci1 SM_STATE_DIR=<dir2> cargo run --release \
//!   -p simple-matter-ble --features device --example ble-onoff-light`

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレース(リンクのために必要)。
use esp_backtrace as _;

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use embassy_executor::Spawner;
use embassy_futures::join::join5;
use embassy_futures::select::{select, select3, Either, Either3};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::StackResources;
use embassy_time::{Instant, Timer};

use esp_hal::clock::CpuClock;
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;

use bt_hci::controller::ExternalController;
use esp_radio::ble::controller::BleConnector;
use trouble_host::prelude::{Address, DefaultPacketPool, Host, HostResources};

use simple_matter::btp::gatt::{GattCentral, ScanFilter};
use simple_matter::btp::{Btp, BtpRole};
use simple_matter::controller::ca::{Ca, CA_STATE_MAX_LEN};
use simple_matter::controller::nodes as nodes_codec;
use simple_matter::controller::{
    AttestationPolicy, CommissionError, Commissioner, ControllerCreds, ControllerStack, Phase,
    CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::client::MdnsClient;
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_IPV6, MDNS_PORT};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::im::ImEvent;
use simple_matter::kvs::Kvs;
use simple_matter::sc::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::stack::SendDirective;
use simple_matter::tlv::TlvValue;
use simple_matter::transport::net::{
    BtpConnId, PeerAddr, UdpMulticast, UdpReceive, UdpSend, MAX_RX_PACKET_SIZE,
};
use simple_matter::transport::session::SessionId;

use esp32s3_firmware::central::{
    central_worker, CentralChannels, MatterAdvHandler, TroubleGattCentral,
};
use esp32s3_firmware::kvs::EspKvs;
use esp32s3_firmware::net::{peer_v4, peer_v6, v4_as_mapped, EspUdp};
use esp32s3_firmware::wifi::{wifi_task, EspWifiDriver};
use esp32s3_firmware::EspRng;
use simple_matter::wifi::WifiDriver;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタ(全 bin に必須)。
esp_bootloader_esp_idf::esp_app_desc!();

// --- WiFi 資格情報(K2 は簡易投入: 定数 or ビルド時環境変数。doc §8.3)---
const WIFI_SSID: &str = match option_env!("SM_WIFI_SSID") {
    Some(s) => s,
    None => "iotap",
};
const WIFI_PASS: &str = match option_env!("SM_WIFI_PASS") {
    Some(s) => s,
    None => "hogeFugapiyo",
};

// --- 対向デバイス(PC onoff-light / ble-onoff-light example と同値)---
const PASSCODE: u32 = 20202021;

// --- コントローラ fabric / ノード識別子(smctl / examples と同値)---
const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
const VENDOR_ID: u16 = 0xFFF1;

// --- ノード計画(K4: 常駐ハブが管理するデバイスの静的テーブル)---

/// コミッショニングに使うトランスポート。
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    /// mDNS ブラウズ → 全フェーズ UDP(K2)。
    Udp,
    /// BLE scan → BTP → PASE〜ConnectNetwork → 運用 UDP へハンドオフ(K3)。
    Ble,
}

/// 管理対象ノード 1 台の計画(discriminator / passcode は永続化しない —
/// nodes.tlv v1 の方針。再コミッショニングに必要な値はここに持つ)。
struct NodePlan {
    node_id: u64,
    transport: Transport,
    discriminator: u16,
    passcode: u32,
    label: &'static str,
}

/// 常駐ハブの管理ノード。node1 = PC `onoff-light`(UDP、`SM_DISCRIMINATOR=3841
/// SM_MATTER_PORT=5541` で起動)、node2 = PC `ble-onoff-light`(BLE、既定 3840)。
static NODE_PLAN: &[NodePlan] = &[
    NodePlan {
        node_id: 0x0000_0000_AABB_CCDD,
        transport: Transport::Udp,
        discriminator: 3841,
        passcode: PASSCODE,
        label: "onoff-light",
    },
    NodePlan {
        node_id: 0x0000_0000_AABB_CCEE,
        transport: Transport::Ble,
        discriminator: 3840,
        passcode: PASSCODE,
        label: "ble-onoff-light",
    },
];

/// [`NODE_PLAN`] の上限(ノード帳バッファ・resumption キーのサイジング)。
const MAX_NODES: usize = 4;

// --- OnOff クラスタ(EP1 / 0x0006)---
const ONOFF_EP: EndpointId = EndpointId(1);
const ONOFF_CLUSTER: ClusterId = ClusterId(0x0006);
const ONOFF_ATTR: AttributeId = AttributeId(0x0000);
const ONOFF_CMD_TOGGLE: CommandId = CommandId(0x02);

// --- KVS キー(pack_key の 7B 制限内)---
/// CA 鍵素材(smctl ca-state.bin v1 と同一バイト列。doc §5.2)。
const CA_STATE_KEY: &[u8] = b"cast";
/// ノード帳(smctl `nodes.tlv` v1 と同一バイト列 = コア `controller::nodes` codec)。
const NODES_KEY: &[u8] = b"nods";

/// ノードごとの CASE resumption 素材のキー(`b"rsm0"`..)。index は [`NODE_PLAN`] 順。
fn resumption_key(index: usize) -> [u8; 4] {
    let mut k = *b"rsm0";
    k[3] = b'0' + (index as u8);
    k
}

// --- タイミング ---
/// mDNS 再クエリ間隔(smctl と同値)。
const MDNS_REQUERY_MS: u64 = 2_000;
/// QU 応答が無いとき QM フォールバック(5353 join)へ切り替えるまでの猶予(R5)。
const QM_FALLBACK_MS: u64 = 6_000;
/// コミッショニング全体のタイムアウト。
const COMMISSION_TIMEOUT_MS: u64 = 60_000;
/// BLE 上のコミッショニングフェーズ(handshake + PASE〜ConnectNetwork)のタイムアウト
/// (BLE は UDP より遅い。smctl と同値)。
const BLE_COMMISSION_TIMEOUT_MS: u64 = 90_000;
/// BTP handshake(C1 write → C2 subscribe → 応答 indication)のタイムアウト。
const BTP_HANDSHAKE_TIMEOUT_MS: u64 = 15_000;
/// ble-wifi 後の運用 mDNS 解決タイムアウト(デバイスの WiFi join + DHCP を見込む。
/// 対向がシム(ble-onoff-light)なら即応答するが、実デバイスへの余裕を持たせる)。
const BLE_RESOLVE_TIMEOUT_MS: u64 = 60_000;
/// 定常デモ: Toggle の周期(この周期でラウンドロビンに 1 ノードずつ回す)。
const TOGGLE_PERIOD_MS: u64 = 30_000;
/// 全ノードがこの回数連続で失敗したらリブートする。
const FAILURES_BEFORE_REBOOT: u32 = 5;

/// HCI コマンドの同時実行スロット数(既存 bin と同値)。
const HCI_SLOTS: usize = 20;

type Backend = RustCrypto<EspRng>;
/// コントローラスタック(K4 サイジング: 運用 CASE ×ノード数 + コミッショニング時の
/// PASE/unsecured + 再確立の揺らぎ。SS=4 では 2 ノード目のコミッショニング中に
/// 1 ノード目の運用セッションが LRU 退避される(実測)ため 6 へ。EX も連続
/// コミッショニング直後の未回収 exchange を見込んで 8 へ。RESULT=1280 は単一属性
/// Read には十分 — wildcard は使わない)。
type Ctrl<'s> = ControllerStack<'s, Backend, EspRng, ControllerCreds<'s, Backend>, 6, 8, 3, 1280>;

/// TRNG ハンドルを 1 つ生成する([`TrngSource`] が有効な間だけ成功する)。
fn esp_rng() -> EspRng {
    EspRng(Trng::try_new().expect("TrngSource must be active before Trng::try_new()"))
}

/// 単調時刻(ms)。スタックの `now_ms` 注入に使う(embassy-time の Instant 起点)。
fn now_ms(start: Instant) -> u64 {
    start.elapsed().as_millis()
}

/// MAC(48bit)から modified EUI-64 のリンクローカル IPv6(fe80::/64)を導出する
/// (s3-light と同じ。smoltcp に静的設定する)。
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

// ==========================================================================
// ノード帳(smctl nodes.tlv v1 互換 = コア codec)+ resumption 素材の永続化
// ==========================================================================

/// ノードごとの実行時状態([`NODE_PLAN`] と同順)。
struct NodeRt {
    /// 最後に確認した運用アドレス(mDNS 解決が空振りしたときのフォールバック)。
    addr: Option<SocketAddr>,
    /// 確立済みの運用 CASE セッション。
    session: Option<SessionId>,
    /// 連続 Toggle 失敗回数(成功でリセット。全ノード同時に閾値超えでリブート)。
    failures: u32,
}

impl NodeRt {
    const fn new() -> Self {
        Self {
            addr: None,
            session: None,
            failures: 0,
        }
    }
}

/// ノード帳(`b"nods"`)を読み、[`NODE_PLAN`] の node_id 一致エントリのアドレスを
/// 返す(帳面にあるが計画に無いノードは無視 = 帳面が真、計画がフィルタ)。
fn load_node_ledger(kvs: &mut EspKvs) -> [Option<SocketAddr>; MAX_NODES] {
    let mut addrs = [None; MAX_NODES];
    let mut buf = [0u8; nodes_codec::nodes_max_len(MAX_NODES)];
    match kvs.get(NODES_KEY, &mut buf) {
        Ok(Some(len)) => {
            let res = nodes_codec::decode_nodes(&buf[..len], |rec| {
                if let Some(i) = NODE_PLAN.iter().position(|p| p.node_id == rec.node_id) {
                    addrs[i] = Some(rec.last_addr);
                }
            });
            match res {
                Ok(n) => println!("[kvs] node ledger restored ({} entries)", n),
                Err(e) => println!("[kvs] node ledger decode error: {:?}", e),
            }
        }
        Ok(None) => {}
        Err(e) => println!("[kvs] node ledger read error: {:?}", e),
    }
    addrs
}

/// ノード帳(アドレスが判明している全ノード)を `b"nods"` へ保存する
/// (smctl `nodes.tlv` v1 と同一バイト列。全量書き換え)。
fn save_node_ledger(kvs: &mut EspKvs, rt: &[NodeRt]) {
    // NodeRecord は Copy なのでダミー埋めの固定長配列に先頭詰めする。
    let dummy =
        nodes_codec::NodeRecord::new(0, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), "")
            .unwrap();
    let mut flat = [dummy; MAX_NODES];
    let mut n = 0;
    for (plan, node) in NODE_PLAN.iter().zip(rt) {
        if let Some(addr) = node.addr {
            match nodes_codec::NodeRecord::new(plan.node_id, addr, plan.label) {
                Ok(rec) => {
                    flat[n] = rec;
                    n += 1;
                }
                Err(e) => println!("[kvs] node record build error: {:?}", e),
            }
        }
    }
    let mut buf = [0u8; nodes_codec::nodes_max_len(MAX_NODES)];
    match nodes_codec::encode_nodes(&mut buf, &flat[..n]) {
        Ok(len) => match kvs.set(NODES_KEY, &buf[..len]) {
            Ok(()) => println!("[kvs] node ledger saved ({} nodes, {}B)", n, len),
            Err(e) => println!("[kvs] node ledger save error: {:?}", e),
        },
        Err(e) => println!("[kvs] node ledger encode error: {:?}", e),
    }
}

/// resumption 素材レコード(ポートローカル): [version(1)][rid(16)][ss(32)] = 49B。
const RESUMPTION_RECORD_VERSION: u8 = 1;
const RESUMPTION_RECORD_LEN: usize = 1 + CASE_RESUMPTION_ID_LEN + SHARED_SECRET_LEN;

/// ノード `index` の CASE resumption 素材を KVS(`b"rsm<i>"`)へ保存する
/// (CASE 確立のたびに rid が回るので、確立ごとに呼ぶ)。
fn save_resumption(kvs: &mut EspKvs, stack: &Ctrl<'_>, index: usize, node_id: u64) {
    let key = resumption_key(index);
    match stack.resumption_export(CONTROLLER_FABRIC_INDEX, node_id) {
        Some((rid, ss)) => {
            let mut rec = [0u8; RESUMPTION_RECORD_LEN];
            rec[0] = RESUMPTION_RECORD_VERSION;
            rec[1..1 + CASE_RESUMPTION_ID_LEN].copy_from_slice(&rid);
            rec[1 + CASE_RESUMPTION_ID_LEN..].copy_from_slice(&ss);
            if let Err(e) = kvs.set(&key, &rec) {
                println!("[kvs] resumption save error (node{}): {:?}", index, e);
            }
        }
        None => {
            // セッションが張れていない(素材なし)。古い素材は消しておく。
            let _ = kvs.remove(&key);
        }
    }
}

/// ノード `index` の resumption 素材を KVS から stack へ import する。
fn restore_resumption(kvs: &mut EspKvs, stack: &mut Ctrl<'_>, index: usize, node_id: u64) {
    let key = resumption_key(index);
    let mut rec = [0u8; RESUMPTION_RECORD_LEN];
    match kvs.get(&key, &mut rec) {
        Ok(Some(len)) if len == RESUMPTION_RECORD_LEN && rec[0] == RESUMPTION_RECORD_VERSION => {
            let rid: [u8; CASE_RESUMPTION_ID_LEN] =
                rec[1..1 + CASE_RESUMPTION_ID_LEN].try_into().unwrap();
            let ss: [u8; SHARED_SECRET_LEN] = rec[1 + CASE_RESUMPTION_ID_LEN..].try_into().unwrap();
            stack.resumption_import(CONTROLLER_FABRIC_INDEX, node_id, &rid, &ss);
            println!(
                "[case] resumption material imported (node_id={:#x})",
                node_id
            );
        }
        Ok(Some(_)) => println!("[kvs] resumption record invalid (node{}); ignoring", index),
        Ok(None) => {}
        Err(e) => println!("[kvs] resumption read error (node{}): {:?}", index, e),
    }
}

/// CA 鍵素材を KVS へ保存する(v1 = smctl 互換。発行で next_serial が進むたびに呼ぶ)。
fn save_ca_state(kvs: &mut EspKvs, ca: &Ca<Backend>) {
    let mut rec = [0u8; CA_STATE_MAX_LEN];
    match ca.encode_state(&mut rec) {
        Ok(len) => match kvs.set(CA_STATE_KEY, &rec[..len]) {
            Ok(()) => println!(
                "[kvs] ca-state saved ({}B, next_serial={})",
                len,
                ca.next_serial()
            ),
            Err(e) => println!("[kvs] ca-state save error: {:?}", e),
        },
        Err(e) => println!("[kvs] ca-state encode error: {:?}", e),
    }
}

// ==========================================================================
// mDNS ディスカバリ(QU 第一候補 + QM フォールバック。doc §4.2)
// ==========================================================================

/// ブラウズ(commissionable)/ 運用解決(operational)のクエリ種別。
enum Query {
    Browse { discriminator: u16 },
    Operational { compressed: [u8; 8], node_id: u64 },
}

impl Query {
    fn build(&self, out: &mut [u8], qu: bool) -> simple_matter::error::Result<usize> {
        match self {
            Query::Browse { discriminator } => {
                MdnsClient::build_browse_discriminator(out, *discriminator, qu)
            }
            Query::Operational {
                compressed,
                node_id,
            } => MdnsClient::build_resolve_operational(out, compressed, *node_id, qu),
        }
    }

    /// 受信パケットを解析し、接続先(アドレス + ポート)を返す。IPv4 を優先し、
    /// 無ければ最初のアドレス(fe80 は単一インターフェースのため scope 不要)。
    fn parse(&self, pkt: &[u8]) -> Option<SocketAddr> {
        let (addrs, port) = match self {
            Query::Browse { discriminator } => {
                let node = MdnsClient::parse_commissionable(pkt)?;
                if node.discriminator != Some(*discriminator) {
                    return None;
                }
                (node.addrs, node.port)
            }
            Query::Operational {
                compressed,
                node_id,
            } => {
                let node = MdnsClient::parse_operational(pkt, compressed, *node_id)?;
                (node.addrs, node.port)
            }
        };
        let ip = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs.iter().next())
            .copied()?;
        let port = if port != 0 { port } else { MATTER_PORT };
        Some(SocketAddr::new(ip, port))
    }
}

/// mDNS ディスカバリ 1 回(タイムアウトまで)。
///
/// エフェメラルポートの `qu_udp` から QU クエリを 2 秒間隔で送り、ユニキャスト応答を
/// 待つ。[`QM_FALLBACK_MS`] 経過しても応答が無い場合は `qm_udp`(5353 bind 済み)で
/// IGMP/MLD join し、QM クエリ + マルチキャスト応答/announce の受動受信を併用する。
/// 発見後は join を解除して(QM を有効化した場合のみ)無関係な mDNS 解析コストを畳む。
async fn discover(
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    query: &Query,
    timeout_ms: u64,
    start: Instant,
) -> Option<SocketAddr> {
    let t0 = now_ms(start);
    let mut joined = false;
    let mut next_query = t0;
    let mut rx_qu = [0u8; 1500];
    let mut rx_qm = [0u8; 1500];
    let mut q = [0u8; 128];

    let found = loop {
        let now = now_ms(start);
        if now - t0 >= timeout_ms {
            break None;
        }
        if !joined && now - t0 >= QM_FALLBACK_MS {
            joined = true;
            if let Err(e) = qm_udp.join(v4_as_mapped(MDNS_IPV4)).await {
                println!("[dis] v4 multicast join error: {:?}", e);
            }
            if let Err(e) = qm_udp.join(MDNS_IPV6).await {
                println!("[dis] v6 multicast join error: {:?}", e);
            }
            println!("[dis] no QU answer yet; QM fallback enabled (5353 + multicast join)");
        }
        if now >= next_query {
            next_query = now + MDNS_REQUERY_MS;
            // QU: エフェメラルポートからユニキャスト応答を要求する。
            if let Ok(len) = query.build(&mut q, true) {
                let _ = qu_udp
                    .send_to(&q[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
                    .await;
                let _ = qu_udp
                    .send_to(&q[..len], peer_v6(MDNS_IPV6, MDNS_PORT))
                    .await;
            }
            // QM(フォールバック時): 5353 発でマルチキャスト応答を要求する。
            if joined {
                if let Ok(len) = query.build(&mut q, false) {
                    let _ = qm_udp
                        .send_to(&q[..len], peer_v4(MDNS_IPV4, MDNS_PORT))
                        .await;
                    let _ = qm_udp
                        .send_to(&q[..len], peer_v6(MDNS_IPV6, MDNS_PORT))
                        .await;
                }
            }
        }
        match select3(
            qu_udp.recv_from(&mut rx_qu),
            qm_udp.recv_from(&mut rx_qm),
            Timer::after_millis(100),
        )
        .await
        {
            Either3::First(Ok((n, _src))) => {
                if let Some(addr) = query.parse(&rx_qu[..n]) {
                    break Some(addr);
                }
            }
            Either3::Second(Ok((n, _src))) => {
                if let Some(addr) = query.parse(&rx_qm[..n]) {
                    break Some(addr);
                }
            }
            _ => {}
        }
    };

    if joined {
        let _ = qm_udp.leave(v4_as_mapped(MDNS_IPV4)).await;
        let _ = qm_udp.leave(MDNS_IPV6).await;
    }
    found
}

// ==========================================================================
// sans-IO 駆動ヘルパ(smctl runner/udp.rs の embassy 版。doc §4.3)
// ==========================================================================

/// [`SendDirective`] を UDP へ送出する(宛先が解決できないものは黙って捨てる)。
async fn send_dir(udp: &mut EspUdp<'_>, tx: &[u8], d: &SendDirective) {
    if let Err(e) = udp.send_to(&tx[..d.len], d.addr).await {
        println!("[udp] send error: {:?}", e);
    }
}

/// [`Commissioner::drive`] を進捗が止まるまで回し、送信を排出して現フェーズを返す
/// (smctl `pump_commissioner` と同形)。
async fn pump_commissioner(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    tx: &mut [u8],
) -> Phase {
    loop {
        let prev = comm.phase();
        let out = comm.drive(stack, now_ms(start), tx);
        if let Some(d) = out.send {
            send_dir(udp, tx, &d).await;
        }
        if out.send.is_none() && out.phase == prev {
            return out.phase;
        }
        if matches!(out.phase, Phase::Done { .. } | Phase::Failed { .. }) {
            return out.phase;
        }
    }
}

/// 応答を受け切り、MRP 再送・standalone ACK を含めて静穏化するまでネットワークを回す
/// (`next_deadline` が `None` になるまで。フェーズ間・トランザクション間で必ず呼ぶ)。
async fn settle(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Result<(), ()> {
    let until = now_ms(start) + timeout_ms;
    loop {
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
        let Some(deadline) = stack.next_deadline(now) else {
            return Ok(());
        };
        if now > until {
            return Err(());
        }
        let sleep = if deadline > now {
            (deadline - now).min(50)
        } else {
            // 期限到来済み: poll を回すために最小待ち。
            1
        };
        match select(udp.recv_from(rx), Timer::after_millis(sleep)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
    }
}

/// IM イベントを 1 件待つ(受信 + poll を回し続ける。タイムアウトで `None`)。
async fn wait_im_event(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Option<ImEvent> {
    let until = now_ms(start) + timeout_ms;
    loop {
        if let Some(ev) = stack.im_take_event() {
            return Some(ev);
        }
        if now_ms(start) > until {
            return None;
        }
        match select(udp.recv_from(rx), Timer::after_millis(50)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
    }
}

/// SC(CASE)イベントを 1 件待つ(タイムアウトで `None`)。
async fn wait_sc_event(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    timeout_ms: u64,
) -> Option<ScEvent> {
    let until = now_ms(start) + timeout_ms;
    loop {
        if let Some(ev) = stack.sc_take_event() {
            return Some(ev);
        }
        if now_ms(start) > until {
            return None;
        }
        match select(udp.recv_from(rx), Timer::after_millis(50)).await {
            Either::First(Ok((n, src))) => {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, tx) {
                    send_dir(udp, tx, &d).await;
                }
            }
            Either::First(Err(e)) => println!("[udp] recv error: {:?}", e),
            Either::Second(()) => {}
        }
        let now = now_ms(start);
        while let Some(d) = stack.poll(now, tx) {
            send_dir(udp, tx, &d).await;
        }
    }
}

/// フェーズ遷移を人間可読に表示する(PC example と同形式)。
fn report_phase(phase: Phase) {
    let name = match phase {
        Phase::Idle => "Idle",
        Phase::Pase => "PASE handshake",
        Phase::ArmFailSafe => "ArmFailSafe",
        Phase::Attestation => "Attestation (skipped)",
        Phase::Csr => "CSRRequest",
        Phase::AddTrustedRoot => "AddTrustedRootCertificate",
        Phase::AddNoc => "AddNOC",
        Phase::AddWifiNetwork => "AddOrUpdateWiFiNetwork",
        Phase::ConnectNetwork => "ConnectNetwork",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    println!("[phase] {}", name);
}

/// フルコミッショニングを完走させて CASE セッションを返す。
async fn run_commissioning(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<SessionId, CommissionError> {
    let until = now_ms(start) + COMMISSION_TIMEOUT_MS;
    let mut last_phase = Phase::Idle;
    loop {
        if now_ms(start) > until {
            println!("[commission] timed out in phase {:?}", last_phase);
            return Err(CommissionError::Protocol);
        }
        let phase = pump_commissioner(comm, stack, udp, start, tx).await;
        if phase != last_phase {
            report_phase(phase);
            last_phase = phase;
        }
        match phase {
            Phase::Done { session } => return Ok(session),
            Phase::Failed { stage, reason } => {
                println!("[commission] FAILED at stage {}: {:?}", stage, reason);
                return Err(reason);
            }
            _ => {}
        }
        // 発行済みトランザクションの応答 + ACK を流し切ってから次フェーズへ
        // (デバイス側 IM responder は同時 1 トランザクションのため)。
        if settle(stack, udp, start, rx, tx, 20_000).await.is_err() {
            println!("[commission] settle timed out (device unresponsive)");
            return Err(CommissionError::Protocol);
        }
    }
}

/// 運用セッション上で OnOff Toggle → on-off Read を 1 巡実行し、読めた値を返す。
async fn toggle_and_read(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    session: SessionId,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<Option<bool>, ()> {
    let dir = stack
        .start_invoke(
            session,
            CommandPath::new(ONOFF_EP, ONOFF_CLUSTER, ONOFF_CMD_TOGGLE),
            |w, t| {
                w.start_struct(t)?;
                w.end_container()
            },
            now_ms(start),
            tx,
        )
        .map_err(|e| println!("[onoff] start_invoke error: {:?}", e))?;
    send_dir(udp, tx, &dir).await;
    match wait_im_event(stack, udp, start, rx, tx, 10_000).await {
        Some(ImEvent::InvokeDone { status }) if status.is_success() => {}
        other => {
            println!("[onoff] Toggle failed: {:?}", other);
            return Err(());
        }
    }
    settle(stack, udp, start, rx, tx, 10_000).await?;

    let dir = stack
        .start_read(
            session,
            &[AttributePath::concrete(ONOFF_EP, ONOFF_CLUSTER, ONOFF_ATTR)],
            now_ms(start),
            tx,
        )
        .map_err(|e| println!("[onoff] start_read error: {:?}", e))?;
    send_dir(udp, tx, &dir).await;
    match wait_im_event(stack, udp, start, rx, tx, 10_000).await {
        Some(ImEvent::ReadDone) => {}
        other => {
            println!("[onoff] Read failed: {:?}", other);
            return Err(());
        }
    }
    settle(stack, udp, start, rx, tx, 10_000).await?;
    Ok(read_onoff_value(stack))
}

/// 直近 Read 応答から OnOff(EP1/0x0006/0x0000)の bool 値を取り出す。
fn read_onoff_value(stack: &Ctrl<'_>) -> Option<bool> {
    for report in stack.read_reports() {
        if let Ok(AttributeReportRef::Data(d)) = report {
            let is_onoff = d
                .path
                .to_concrete()
                .map(|c| c.attribute.0 == ONOFF_ATTR.0)
                .unwrap_or(false);
            if !is_onoff {
                continue;
            }
            let mut v = d.value();
            if let Ok(Some(e)) = v.read_next() {
                if let TlvValue::Boolean(b) = e.value {
                    return Some(b);
                }
            }
        }
    }
    None
}

/// CASE を張り、確立したセッションと resumed フラグを返す。
#[allow(clippy::too_many_arguments)]
async fn establish_case(
    stack: &mut Ctrl<'_>,
    udp: &mut EspUdp<'_>,
    start: Instant,
    peer: SocketAddr,
    node_id: u64,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Option<(SessionId, bool)> {
    let dir = match stack.start_case(
        PeerAddr::Udp(peer),
        CONTROLLER_FABRIC_INDEX,
        node_id,
        now_ms(start),
        tx,
    ) {
        Ok(d) => d,
        Err(e) => {
            println!("[case] start_case error: {:?}", e);
            return None;
        }
    };
    send_dir(udp, tx, &dir).await;
    match wait_sc_event(stack, udp, start, rx, tx, 15_000).await {
        Some(ScEvent::CaseEstablished { session, resumed }) => {
            let _ = settle(stack, udp, start, rx, tx, 10_000).await;
            Some((session, resumed))
        }
        other => {
            println!("[case] failed: {:?}", other);
            None
        }
    }
}

// ==========================================================================
// BLE コミッショニング(K3。smctl runner/ble.rs の embassy 版)
// ==========================================================================

/// BTP が吐く上りフラグメントを尽きるまで C1 write で送出する(smctl `flush_c1`)。
async fn flush_c1(
    gatt: &mut TroubleGattCentral<'_>,
    btp: &mut Btp<6>,
    conn: BtpConnId,
    mtu: Option<u16>,
    now: u64,
) -> simple_matter::error::Result<()> {
    let mut out = [0u8; 512];
    loop {
        let n = btp.process_outgoing(&mut out, mtu, now)?;
        if n == 0 {
            break;
        }
        gatt.write_c1(conn, &out[..n]).await?;
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

/// 再組立済み Matter メッセージを `stack.handle_rx` へ配り、応答と `poll` の送出を
/// BTP に載せる(smctl `service_ctrl`)。
async fn service_ctrl_ble(
    gatt: &mut TroubleGattCentral<'_>,
    btp: &mut Btp<6>,
    stack: &mut Ctrl<'_>,
    conn: BtpConnId,
    mtu: Option<u16>,
    now: u64,
) -> simple_matter::error::Result<()> {
    let peer = PeerAddr::Ble(conn);
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];
    while let Some(slen) = take_sdu(btp, &mut sdu) {
        if let Some(d) = stack.handle_rx(&mut sdu[..slen], peer, now, &mut txc) {
            btp.send(&txc[..d.len], now)?;
            flush_c1(gatt, btp, conn, mtu, now).await?;
        }
    }
    // 閉じた exchange の回収(ble-btp.md §11-4)。BTP では MRP 再送は生じないが poll は必須。
    while let Some(d) = stack.poll(now, &mut txc) {
        btp.send(&txc[..d.len], now)?;
        flush_c1(gatt, btp, conn, mtu, now).await?;
    }
    Ok(())
}

/// BLE 上のコミッショニングフェーズを CASE 保留(`suspend_before_case`)まで駆動する
/// (smctl `drive_commission_ble` の embassy 版。常に ble-wifi = 運用 UDP 遷移前提)。
async fn drive_commission_ble(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    gatt: &mut TroubleGattCentral<'_>,
    btp: &mut Btp<6>,
    conn: BtpConnId,
    mtu: Option<u16>,
    start: Instant,
) -> Result<(), CommissionError> {
    let until = now_ms(start) + BLE_COMMISSION_TIMEOUT_MS;
    let mut last_phase = Phase::Idle;
    let mut frag = [0u8; 512];
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];
    loop {
        if now_ms(start) > until {
            println!("[commission] BLE timed out in phase {:?}", last_phase);
            return Err(CommissionError::Protocol);
        }

        // コミッショナを進められるだけ進める(要求を BTP で送る)。
        loop {
            let now = now_ms(start);
            let prev = comm.phase();
            let out = comm.drive(stack, now, &mut txc);
            if out.phase != last_phase {
                report_phase(out.phase);
                last_phase = out.phase;
            }
            if let Some(d) = out.send {
                if btp.send(&txc[..d.len], now).is_err()
                    || flush_c1(gatt, btp, conn, mtu, now).await.is_err()
                {
                    println!("[btp] send failed (link down?)");
                    return Err(CommissionError::Protocol);
                }
            }
            match out.phase {
                Phase::Failed { stage, reason } => {
                    println!("[commission] FAILED at BLE stage {}: {:?}", stage, reason);
                    return Err(reason);
                }
                // suspend_before_case 前提なので Done には到達しない(防御)。
                Phase::Done { .. } => return Ok(()),
                _ => {}
            }
            if out.send.is_none() && out.phase == prev {
                break;
            }
        }

        // BLE 上の最終フェーズ完了 = CASE 保留(sigma1 未送出)。ここで BLE を降りる。
        if matches!(comm.phase(), Phase::Case) {
            return Ok(());
        }

        // 既に届いている応答を捌く。
        let now = now_ms(start);
        if service_ctrl_ble(gatt, btp, stack, conn, mtu, now)
            .await
            .is_err()
        {
            return Err(CommissionError::Protocol);
        }

        // 次の下りフラグメントを待つ(BTP の遅延 ACK 期限まで)。
        let now = now_ms(start);
        let sleep = match btp.next_deadline() {
            Some(t) if t > now => (t - now).min(1_000),
            Some(_) => 0,
            None => 1_000,
        };
        match select(
            gatt.next_indication(conn, &mut frag),
            Timer::after_millis(sleep),
        )
        .await
        {
            Either::First(Ok(n)) => {
                let now = now_ms(start);
                if btp.process_incoming(&frag[..n], mtu, now).is_err() {
                    println!("[btp] process_incoming error");
                    return Err(CommissionError::Protocol);
                }
                if flush_c1(gatt, btp, conn, mtu, now).await.is_err() {
                    return Err(CommissionError::Protocol);
                }
            }
            Either::First(Err(e)) => {
                println!("[ble] indication error (link down?): {:?}", e);
                return Err(CommissionError::Protocol);
            }
            Either::Second(()) => {
                let now = now_ms(start);
                if flush_c1(gatt, btp, conn, mtu, now).await.is_err() {
                    return Err(CommissionError::Protocol);
                }
            }
        }
        let now = now_ms(start);
        if service_ctrl_ble(gatt, btp, stack, conn, mtu, now)
            .await
            .is_err()
        {
            return Err(CommissionError::Protocol);
        }
    }
}

/// BLE コミッショニングの BLE 区間: scan → connect → BTP handshake → PASE〜
/// ConnectNetwork(CASE 保留)→ BLE close。成功で `comm` は `Phase::Case` 保留状態。
async fn commission_over_ble(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    gatt: &mut TroubleGattCentral<'_>,
    start: Instant,
    plan: &NodePlan,
) -> Result<(), ()> {
    // --- scan(0xFFF6 service data、discriminator 照合。2 セッションまで)---
    let mut attempts = 0;
    let target = loop {
        println!(
            "[ble] scanning for 0xFFF6 commissionable (discriminator={})...",
            plan.discriminator
        );
        match gatt
            .scan(ScanFilter {
                discriminator: Some(plan.discriminator),
                vendor_product: None,
            })
            .await
        {
            Ok(t) => break t,
            Err(e) => {
                attempts += 1;
                println!("[ble] scan failed ({:?}); attempt {}/2", e, attempts);
                if attempts >= 2 {
                    return Err(());
                }
            }
        }
    };
    println!(
        "[ble] found device: discriminator={} vid={:#06x} pid={:#06x}",
        target.discriminator, target.vendor_id, target.product_id
    );

    // --- connect(accept-list 経由)+ MTU 交換 + C1/C2 discovery ---
    let (conn, mtu) = match gatt.connect(&target).await {
        Ok(r) => r,
        Err(e) => {
            println!("[ble] connect failed: {:?}", e);
            return Err(());
        }
    };
    println!("[ble] connected (conn={} att_mtu={:?})", conn.0, mtu);

    // --- BTP handshake(C1 write → C2 subscribe → 応答 indication の順序が必須)---
    let mut btp = Btp::<6>::new(BtpRole::Central);
    let mut frag = [0u8; 512];
    let now = now_ms(start);
    let hs = async {
        let n = btp
            .start_handshake(&mut frag, mtu, now)
            .map_err(|e| println!("[btp] start_handshake: {:?}", e))?;
        gatt.write_c1(conn, &frag[..n])
            .await
            .map_err(|e| println!("[btp] write_c1(handshake): {:?}", e))?;
        gatt.subscribe_c2(conn)
            .await
            .map_err(|e| println!("[btp] subscribe_c2: {:?}", e))?;
        while !btp.is_established() {
            let n = gatt
                .next_indication(conn, &mut frag)
                .await
                .map_err(|e| println!("[btp] next_indication(handshake): {:?}", e))?;
            btp.process_incoming(&frag[..n], mtu, now_ms(start))
                .map_err(|e| println!("[btp] process_incoming(handshake): {:?}", e))?;
        }
        Ok::<(), ()>(())
    };
    match select(hs, Timer::after_millis(BTP_HANDSHAKE_TIMEOUT_MS)).await {
        Either::First(Ok(())) => {}
        Either::First(Err(())) | Either::Second(()) => {
            println!("[btp] handshake failed / timed out");
            let _ = gatt.disconnect(conn).await;
            return Err(());
        }
    }
    println!(
        "[btp] established: fragment={} window={}",
        btp.fragment_size(),
        btp.window()
    );

    // --- コミッショニング(BLE 上、ble-wifi 型: AddNOC 後に WiFi 投入 → CASE 保留)---
    comm.suspend_before_case();
    if comm
        .set_wifi_credentials(WIFI_SSID.as_bytes(), WIFI_PASS.as_bytes())
        .is_err()
    {
        println!("[commission] set_wifi_credentials rejected");
        let _ = gatt.disconnect(conn).await;
        return Err(());
    }
    if comm
        .commission(
            PeerAddr::Ble(conn),
            plan.passcode,
            plan.node_id,
            now_ms(start),
        )
        .is_err()
    {
        println!("[commission] commission() rejected");
        let _ = gatt.disconnect(conn).await;
        return Err(());
    }
    println!(
        "[commission] starting over BLE (device node_id={:#x}, wifi ssid=\"{}\")",
        plan.node_id, WIFI_SSID
    );
    let result = drive_commission_ble(comm, stack, gatt, &mut btp, conn, mtu, start).await;
    // chip 系デバイスは AddNOC 受理後に自ら BLE を閉じることがある。失敗は無視する。
    let _ = gatt.disconnect(conn).await;
    match result {
        Ok(()) => {
            println!("[commission] BLE phases accepted; switching to operational UDP");
            Ok(())
        }
        Err(_) => Err(()),
    }
}

// ==========================================================================
// 統合層(コントローラ本体のフロー)
// ==========================================================================

/// DHCP up を待って IPv4 を返す。
async fn wait_dhcp(net_stack: embassy_net::Stack<'_>) -> Ipv4Addr {
    loop {
        if let Some(cfg) = net_stack.config_v4() {
            println!("[net] DHCP up: ip={} gw={:?}", cfg.address, cfg.gateway);
            return cfg.address.address();
        }
        Timer::after_millis(100).await;
    }
}

/// ノード 1 台のトランスポート別フルコミッショニング。成功で運用 CASE セッションと
/// 運用アドレスを返す(`Commissioner` はノードごとに使い捨て — `commission()` は
/// Idle からしか開始できないため)。
#[allow(clippy::too_many_arguments)]
async fn commission_node(
    plan: &NodePlan,
    stack: &mut Ctrl<'_>,
    ca: &Ca<Backend>,
    crypto: &Backend,
    gatt: &mut TroubleGattCentral<'_>,
    matter_udp: &mut EspUdp<'_>,
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    start: Instant,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<(SessionId, SocketAddr), ()> {
    let mut comm = Commissioner::new(ca, crypto, AttestationPolicy::Skip);
    match plan.transport {
        Transport::Udp => {
            // --- K2 パス: ブラウズ(discriminator subtype)→ 全フェーズ UDP ---
            println!(
                "[dis] browsing _matterc._udp (discriminator={}) via QU...",
                plan.discriminator
            );
            let query = Query::Browse {
                discriminator: plan.discriminator,
            };
            let Some(addr) = discover(qu_udp, qm_udp, &query, 30_000, start).await else {
                println!(
                    "[dis] no commissionable device found (disc={})",
                    plan.discriminator
                );
                return Err(());
            };
            println!("[dis] found commissionable node at {}", addr);
            comm.commission(
                PeerAddr::Udp(addr),
                plan.passcode,
                plan.node_id,
                now_ms(start),
            )
            .map_err(|e| println!("[commission] commission() rejected: {:?}", e))?;
            println!(
                "[commission] starting to {} (device node_id={:#x})",
                addr, plan.node_id
            );
            let session = run_commissioning(&mut comm, stack, matter_udp, start, rx, tx)
                .await
                .map_err(|_| ())?;
            // Done 直後の残 ACK/exchange を流し切る(次ノードのコミッショニングや
            // 直後の Invoke が exchange プール枯渇(NoSpace)にならないように)。
            let _ = settle(stack, matter_udp, start, rx, tx, 10_000).await;
            println!(
                "[commission] COMPLETE. operational CASE session = {:#x}",
                session.as_raw()
            );
            Ok((session, addr))
        }
        Transport::Ble => {
            // --- K3 パス: BLE 区間 → BLE close → 運用解決 → CASE over UDP ---
            commission_over_ble(&mut comm, stack, gatt, start, plan).await?;
            let compressed = ca.compressed_fabric_id_bytes();
            println!(
                "[dis] resolving _matter._tcp for {:016X}-{:016X} (up to {}s)...",
                u64::from_be_bytes(compressed),
                plan.node_id,
                BLE_RESOLVE_TIMEOUT_MS / 1000
            );
            let query = Query::Operational {
                compressed,
                node_id: plan.node_id,
            };
            let Some(addr) = discover(qu_udp, qm_udp, &query, BLE_RESOLVE_TIMEOUT_MS, start).await
            else {
                println!("[dis] operational resolve timed out after BLE phases");
                return Err(());
            };
            println!("[dis] operational node resolved at {}", addr);
            comm.set_peer(PeerAddr::Udp(addr));
            comm.resume();
            let session = run_commissioning(&mut comm, stack, matter_udp, start, rx, tx)
                .await
                .map_err(|_| ())?;
            let _ = settle(stack, matter_udp, start, rx, tx, 10_000).await;
            println!(
                "[commission] COMPLETE (BLE -> mDNS -> CASE over UDP). session = {:#x}",
                session.as_raw()
            );
            Ok((session, addr))
        }
    }
}

/// コミッショニング済みノードへ再接続する: 運用 mDNS 解決(空振りは記録アドレスへ
/// フォールバック)→ CASE(resumption 素材があれば Sigma2_Resume)。
#[allow(clippy::too_many_arguments)]
async fn reconnect_node(
    plan: &NodePlan,
    last_addr: Option<SocketAddr>,
    stack: &mut Ctrl<'_>,
    ca: &Ca<Backend>,
    matter_udp: &mut EspUdp<'_>,
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    start: Instant,
    resolve_timeout_ms: u64,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Option<(SessionId, SocketAddr, bool)> {
    let compressed = ca.compressed_fabric_id_bytes();
    println!(
        "[dis] resolving _matter._tcp for {:016X}-{:016X}...",
        u64::from_be_bytes(compressed),
        plan.node_id
    );
    let query = Query::Operational {
        compressed,
        node_id: plan.node_id,
    };
    let addr = match discover(qu_udp, qm_udp, &query, resolve_timeout_ms, start).await {
        Some(a) => {
            println!("[dis] operational node resolved at {}", a);
            a
        }
        None => {
            let Some(a) = last_addr else {
                println!("[dis] operational resolve timed out (no cached addr)");
                return None;
            };
            println!(
                "[dis] operational resolve timed out; falling back to last addr {}",
                a
            );
            a
        }
    };
    let (session, resumed) =
        establish_case(stack, matter_udp, start, addr, plan.node_id, rx, tx).await?;
    Some((session, addr, resumed))
}

/// コントローラのメインフロー(常駐)。
#[allow(clippy::too_many_arguments)]
async fn controller_task(
    stack: &mut Ctrl<'_>,
    ca: &Ca<Backend>,
    crypto: &Backend,
    kvs: &mut EspKvs,
    net_stack: embassy_net::Stack<'_>,
    matter_udp: &mut EspUdp<'_>,
    qu_udp: &mut EspUdp<'_>,
    qm_udp: &mut EspUdp<'_>,
    gatt: &mut TroubleGattCentral<'_>,
    known_addrs: [Option<SocketAddr>; MAX_NODES],
) -> ! {
    let start = Instant::now();
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];

    // --- WiFi join(簡易投入: 定数資格情報)→ DHCP ---
    println!("[wifi] joining \"{}\"...", WIFI_SSID);
    EspWifiDriver.connect(WIFI_SSID.as_bytes(), WIFI_PASS.as_bytes());
    let _ip = wait_dhcp(net_stack).await;

    let mut rt: [NodeRt; MAX_NODES] = core::array::from_fn(|_| NodeRt::new());
    for (node, addr) in rt.iter_mut().zip(known_addrs) {
        node.addr = addr;
    }

    // --- 各ノードへ接続(帳面に記録があれば再接続、なければコミッショニング)---
    for (i, plan) in NODE_PLAN.iter().enumerate() {
        // リブート後の再接続(resumption 素材は main で import 済み)。
        if rt[i].addr.is_some() {
            println!(
                "[boot] node{} ({}, node_id={:#x}) found in ledger; reconnecting",
                i, plan.label, plan.node_id
            );
            if let Some((session, addr, resumed)) = reconnect_node(
                plan, rt[i].addr, stack, ca, matter_udp, qu_udp, qm_udp, start, 30_000, &mut rx,
                &mut tx,
            )
            .await
            {
                println!(
                    "[case] node{} session re-established (session={:#x}, resumed={})",
                    i,
                    session.as_raw(),
                    resumed
                );
                rt[i].session = Some(session);
                rt[i].addr = Some(addr);
                save_node_ledger(kvs, &rt);
                save_resumption(kvs, stack, i, plan.node_id);
                continue;
            }
            println!(
                "[case] node{} reconnect failed; falling back to fresh commissioning",
                i
            );
        }
        // フレッシュコミッショニング(2 回まで。失敗したノードは残して先へ進む —
        // 定常ループの全滅判定 or 次リブートで再試行される)。
        let mut ok = false;
        for attempt in 1..=2 {
            println!(
                "[commission] node{} ({}, {:?}) attempt {}/2",
                i,
                plan.label,
                match plan.transport {
                    Transport::Udp => "udp",
                    Transport::Ble => "ble",
                },
                attempt
            );
            if let Ok((session, addr)) = commission_node(
                plan, stack, ca, crypto, gatt, matter_udp, qu_udp, qm_udp, start, &mut rx, &mut tx,
            )
            .await
            {
                rt[i].session = Some(session);
                rt[i].addr = Some(addr);
                // issue_noc で next_serial が進んだ CA 状態と、ノード帳 + resumption
                // 素材を永続化する(doc §5.2)。
                save_ca_state(kvs, ca);
                save_node_ledger(kvs, &rt);
                save_resumption(kvs, stack, i, plan.node_id);
                ok = true;
                break;
            }
        }
        if !ok {
            println!(
                "[commission] node{} ({}) FAILED; continuing without it",
                i, plan.label
            );
            rt[i].failures = FAILURES_BEFORE_REBOOT;
        }
    }
    if rt.iter().take(NODE_PLAN.len()).all(|n| n.session.is_none()) {
        println!("[boot] no node reachable; rebooting in 10s");
        Timer::after_millis(10_000).await;
        esp_hal::system::software_reset();
    }

    // --- 定常: 30 秒ごとに全ノードをラウンドロビンで Toggle → Read ---
    let mut turn = 0usize;
    loop {
        let i = turn % NODE_PLAN.len();
        turn += 1;
        let plan = &NODE_PLAN[i];

        // セッションが無ければ再接続を試みる(mDNS 再解決 + resumption CASE)。
        if rt[i].session.is_none() && rt[i].addr.is_some() {
            if let Some((session, addr, resumed)) = reconnect_node(
                plan, rt[i].addr, stack, ca, matter_udp, qu_udp, qm_udp, start, 10_000, &mut rx,
                &mut tx,
            )
            .await
            {
                println!(
                    "[case] node{} session re-established (session={:#x}, resumed={})",
                    i,
                    session.as_raw(),
                    resumed
                );
                rt[i].session = Some(session);
                rt[i].addr = Some(addr);
                save_node_ledger(kvs, &rt);
                save_resumption(kvs, stack, i, plan.node_id);
            }
        }

        match rt[i].session {
            Some(session) => {
                match toggle_and_read(stack, matter_udp, start, session, &mut rx, &mut tx).await {
                    Ok(v) => {
                        rt[i].failures = 0;
                        let heap = esp_alloc::HEAP.stats();
                        println!(
                            "[onoff] node{} ({}) Toggle OK (light={}) t={}s heap_max={}",
                            i,
                            plan.label,
                            match v {
                                Some(true) => "ON",
                                Some(false) => "OFF",
                                None => "?",
                            },
                            now_ms(start) / 1000,
                            heap.max_usage
                        );
                    }
                    Err(()) => {
                        rt[i].failures += 1;
                        rt[i].session = None;
                        println!(
                            "[onoff] node{} Toggle failed ({} consecutive); will re-establish",
                            i, rt[i].failures
                        );
                    }
                }
            }
            None => {
                rt[i].failures += 1;
                println!(
                    "[onoff] node{} unreachable ({} consecutive)",
                    i, rt[i].failures
                );
            }
        }

        // 全ノードが閾値を超えて連続失敗 → ネットワーク側の問題とみなしてリブート。
        if rt
            .iter()
            .take(NODE_PLAN.len())
            .all(|n| n.failures >= FAILURES_BEFORE_REBOOT)
        {
            println!("[onoff] all nodes unreachable; rebooting");
            esp_hal::system::software_reset();
        }

        // 次の Toggle まで受信 + poll を回しながら待つ。
        let until = now_ms(start) + TOGGLE_PERIOD_MS;
        loop {
            let now = now_ms(start);
            if now >= until {
                break;
            }
            while let Some(d) = stack.poll(now, &mut tx) {
                send_dir(matter_udp, &tx, &d).await;
            }
            let sleep = (until - now).min(50);
            if let Either::First(Ok((n, src))) =
                select(matter_udp.recv_from(&mut rx), Timer::after_millis(sleep)).await
            {
                let now = now_ms(start);
                if let Some(d) = stack.handle_rx(&mut rx[..n], src, now, &mut tx) {
                    send_dir(matter_udp, &tx, &d).await;
                }
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
    println!(" simple-matter :: ESP32-S3 controller (K4: s3-controller)");
    println!(" hal      : esp-hal 1.1.1 + esp-radio 0.18 (coex) + embassy-net 0.9");
    println!(
        " scope    : resident hub ({} nodes, UDP + BLE commissioning)",
        NODE_PLAN.len()
    );
    println!("======================================================");

    // デバイス bin と同じ heap 112KiB / .stack ≈69KiB 配分(doc §6.3 / R3)。
    esp_alloc::heap_allocator!(size: 112 * 1024);

    // esp-radio は preemptive スケジューラ(esp-rtos)を要求する。
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // TRNG。TrngSource は main の生存期間中保持し続ける(drop すると擬似乱数に戻る)。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = esp_rng();

    // --- Wi-Fi station(esp-radio。K3 から BLE central と coex — R2)---
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
    // ソケット枠: Matter UDP + mDNS QU + mDNS QM + DHCPv4 + 予備。
    let mut net_resources: StackResources<6> = StackResources::new();
    let ll_v6 = link_local_from_mac(&mac);
    println!("[net] IPv6 link-local: {}", ll_v6);
    let mut net_config = embassy_net::Config::dhcpv4(Default::default());
    net_config.ipv6 = embassy_net::ConfigV6::Static(embassy_net::StaticConfigV6 {
        address: embassy_net::Ipv6Cidr::new(ll_v6, 64),
        gateway: None,
        dns_servers: Default::default(),
    });
    let (net_stack, mut net_runner) = embassy_net::new(sta, net_config, &mut net_resources, seed);

    // Matter UDP(コミッショニング + 運用。コントローラはエフェメラルポート)。
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
    matter_sock.bind(0).expect("bind matter socket");
    let mut matter_udp = EspUdp::new(matter_sock, net_stack);

    // mDNS QU クエリソケット(エフェメラルポート。ユニキャスト応答を受ける)。
    let mut u_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut u_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut u_rx_buf = [0u8; 2048];
    let mut u_tx_buf = [0u8; 512];
    let mut qu_sock = UdpSocket::new(
        net_stack,
        &mut u_rx_meta,
        &mut u_rx_buf,
        &mut u_tx_meta,
        &mut u_tx_buf,
    );
    qu_sock.bind(0).expect("bind mDNS QU socket");
    let mut qu_udp = EspUdp::new(qu_sock, net_stack);

    // mDNS QM フォールバックソケット(5353。join は discover 内で必要時のみ)。
    let mut g_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut g_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut g_rx_buf = [0u8; 2048];
    let mut g_tx_buf = [0u8; 512];
    let mut qm_sock = UdpSocket::new(
        net_stack,
        &mut g_rx_meta,
        &mut g_rx_buf,
        &mut g_tx_meta,
        &mut g_tx_buf,
    );
    qm_sock.bind(MDNS_PORT).expect("bind 5353");
    let mut qm_udp = EspUdp::new(qm_sock, net_stack);

    // --- BLE controller(esp-radio HCI)→ TrouBLE host(K3: central ロール)---
    let mut ble_addr = [0u8; 6];
    rng.fill_bytes(&mut ble_addr).expect("TRNG fill");
    ble_addr[5] |= 0xC0; // static random address(上位 2 ビット = 0b11 必須)
    let connector = BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())
        .expect("BLE controller init");
    let ble_controller: ExternalController<_, HCI_SLOTS> = ExternalController::new(connector);
    let mut ble_resources: HostResources<DefaultPacketPool, 1, 1> = HostResources::new();
    let ble_stack = trouble_host::new(ble_controller, &mut ble_resources)
        .set_random_address(Address::random(ble_addr));
    let Host {
        central,
        mut runner,
        ..
    } = ble_stack.build();

    // GattCentral 実装(channel で central_worker と接続)+ adv report ハンドラ。
    let channels = CentralChannels::new();
    let adv_handler = MatterAdvHandler::new(&channels);
    let mut gatt = TroubleGattCentral::new(&channels);

    // --- CA: flash KVS(キー b"cast")から復元、無ければ生成して保存 ---
    let crypto = RustCrypto::new(esp_rng());
    let mut kvs = EspKvs::new(peripherals.FLASH);
    let mut ca_rec = [0u8; CA_STATE_MAX_LEN];
    let ca: Ca<Backend> = match kvs.get(CA_STATE_KEY, &mut ca_rec) {
        Ok(Some(len)) => match Ca::decode_state(&crypto, &ca_rec[..len], 0) {
            Ok(ca) => {
                println!(
                    "[ca] restored from flash (fabric_id={:#018x} next_serial={})",
                    ca.fabric_id(),
                    ca.next_serial()
                );
                ca
            }
            Err(e) => {
                println!("[ca] stored record invalid ({:?}); generating new CA", e);
                Ca::generate(
                    &crypto,
                    &mut rng,
                    FABRIC_ID,
                    CONTROLLER_NODE_ID,
                    VENDOR_ID,
                    0,
                )
                .expect("CA generate")
            }
        },
        _ => {
            println!("[ca] no stored state; generating new CA (P-256 x2 + self-issue)...");
            Ca::generate(
                &crypto,
                &mut rng,
                FABRIC_ID,
                CONTROLLER_NODE_ID,
                VENDOR_ID,
                0,
            )
            .expect("CA generate")
        }
    };
    // 生成直後(または復元不能で再生成)は必ず保存しておく(クラッシュ耐性)。
    save_ca_state(&mut kvs, &ca);
    println!(
        "[ca] fabric_id={:#018x} controller_node_id={:#018x} compressed={:016X}",
        ca.fabric_id(),
        ca.controller_node_id(),
        u64::from_be_bytes(ca.compressed_fabric_id_bytes())
    );

    // --- ノード帳(smctl nodes.tlv v1 互換)の復元(リブート後の再接続用)---
    let known_addrs = load_node_ledger(&mut kvs);

    // --- ControllerStack(now_epoch_s=0 運用。R7 は K1 で実証済み)---
    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, esp_rng(), ctrl_creds);
    let im_client = ImClient::new();
    let mut stack: Ctrl = ControllerStack::new(&crypto, sc_init, im_client);
    // resumption 素材(ノードごとの b"rsm<i>")を import する。
    for (i, plan) in NODE_PLAN.iter().enumerate() {
        restore_resumption(&mut kvs, &mut stack, i, plan.node_id);
    }
    println!(
        "[stack] ControllerStack ready ({} bytes, on main stack)",
        core::mem::size_of::<Ctrl<'static>>()
    );

    // wifi_task / embassy-net runner / TrouBLE host runner / central worker /
    // コントローラ本体を単一 executor 上で並走させる。
    join5(
        wifi_task(wifi_controller),
        net_runner.run(),
        async {
            // runner は HCI イベントループ。落ちたら BLE 全体が止まるので panic で知らせる。
            let e = runner.run_with_handler(&adv_handler).await;
            panic!("[ble] host runner exited: {:?}", e);
        },
        central_worker(&ble_stack, central, &channels),
        controller_task(
            &mut stack,
            &ca,
            &crypto,
            &mut kvs,
            net_stack,
            &mut matter_udp,
            &mut qu_udp,
            &mut qm_udp,
            &mut gatt,
            known_addrs,
        ),
    )
    .await;
    unreachable!();
}
