//! std 上の On/Off ライトサンプル(ロードマップ第6段階前半)。
//!
//! `std::net::UdpSocket` で [`MatterStack`](simple_matter::stack::MatterStack) を駆動する
//! **ブロッキングループ**の最小例。sans-IO のコアはソケットに触れず、この example が
//! バイト列と時刻の受け渡し(受信 → `handle_rx`、期限 → `poll`)を担う。
//!
//! # 構成
//!
//! - EP0: Basic Information / General Commissioning / Network Commissioning /
//!   Operational Credentials / Descriptor
//! - EP1: On/Off / Descriptor
//! - パスコード 20202021 + テスト DAC([`TestDacProvider`])。On/Off 変化を `println!`。
//!
//! mDNS ディスカバリ(commissionable / operational 広告)を
//! [`MdnsResponder`](simple_matter::discovery::MdnsResponder) で駆動する。sans-IO の
//! レスポンダはソケットに触れず、この example が 224.0.0.251:5353 の送受信を担う
//! (`join_multicast_v4`)。コミッショニングで fabric が増えたら operational 広告に
//! 反映する。mDNS ソケットを開けない環境(既存の avahi 等)では警告して継続する。
//!
//! 実行: `cargo run --example onoff-light`

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use simple_matter::acl::{AclHandle, AclTable};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_IPV6, MDNS_PORT,
};
use simple_matter::dm::clusters::{
    AccessControlCluster, AdminCommissioningCluster, BasicInfoConfig, BasicInformationCluster,
    CommissioningWindow, DescriptorCluster, GeneralCommissioning, NetworkCommissioning,
    OnOffCluster, OpCredsCluster, TestDacProvider, WindowEvent,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

const PASSCODE: u32 = 20202021;
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;

/// コミッショニング discriminator(12 ビット)。chip-tool の既定テスト値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子(hostname / commissionable インスタンス名の素)。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_6677;

type Backend = RustCrypto<DemoRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

/// デモ用の擬似乱数(SystemTime シードの LCG)。**暗号学的に安全ではない**。
///
/// 実機では OS/HW の CSPRNG を [`Rng`] に実装して差し替えること。ここでは依存追加を避け、
/// example が動く最小の乱数源にとどめる。
struct DemoRng(u64);
impl DemoRng {
    fn from_time() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678)
            | 1;
        Self(seed)
    }
}
impl Rng for DemoRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
        for b in dest.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

// --- デバイス構成(device! マクロは共有 OpCreds のライフタイムを扱えないため手書き)---

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
    ClusterId(0x001F),
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

struct Light<'s> {
    acl: &'s RefCell<AclTable<NACL>>,
    access_control: AccessControlCluster<'s, NACL>,
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    admin: AdminCommissioningCluster<'s>,
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
            (0, 0x001F) => Some(&self.access_control),
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
            (0, 0x001F) => Some(&mut self.access_control),
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
            self.opcreds.on_failsafe_expired();
        }
        // コミッショニング窓のタイムアウト自動クローズ(admin-commissioning.md §2)。
        let _ = self.admin.on_tick(now_ms);
        None
    }
    fn acl(&self) -> Option<&dyn AclHandle> {
        // full ACL(per-entry 照合)を有効化する(docs/design/acl.md §3)。
        Some(self.acl)
    }
}

fn build_light<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    acl: &'s RefCell<AclTable<NACL>>,
    window: &'s RefCell<CommissioningWindow>,
) -> Light<'s> {
    let dac_crypto = RustCrypto::new(DemoRng::from_time());
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        acl,
        access_control: AccessControlCluster::new(acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        // On/Off 変化を println で通知する。
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
    }
}

fn main() -> std::io::Result<()> {
    // 外部所有:crypto(SC/creds/stack が借用)と fabric テーブル(OpCreds/CASE が共有)。
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());
    // ACL テーブル(AccessControl クラスタと IM エンジンの権限評価が共有)。
    let acl: RefCell<AclTable<NACL>> = RefCell::new(AclTable::new());
    // コミッショニング窓(AdminCommissioning クラスタと app ループが共有)。
    let window: RefCell<CommissioningWindow> = RefCell::new(CommissioningWindow::new());

    let config = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_light(&fabrics, &acl, &window));
    let mut stack: DefaultStack<Backend, DemoRng, Light> = MatterStack::new(&crypto, sc, im);

    // Matter 運用 UDP はデュアルスタック(v6only=false)で bind する。AAAA で解決した
    // コントローラが IPv6(fe80 リンクローカル含む)で CASE を張れるようにするため
    // (docs/design/mdns-ipv6.md §1)。v4 ピアは ::ffff: mapped で届き、セッション照合は
    // コアの canonical_socket_addr が吸収する。
    let socket = open_matter_udp()?;
    socket.set_nonblocking(true)?;
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- mDNS ディスカバリ ---
    let local_ipv4 = discover_local_ipv4();
    // リンクローカル v6 とその scope_id(if_index)。取得できれば AAAA を広告し、
    // ff02::fb 側の mDNS ソケットもその scope で join する。
    let local_ipv6 = discover_local_ipv6();
    let mac = MDNS_INSTANCE_ID.to_be_bytes(); // 下位 6 バイトをホスト名(MAC 相当)に使う
    let host = Host::from_mac(&mac[2..8], local_ipv6.map(|(ip, _)| ip), Some(local_ipv4));
    let mut mdns: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
    // VPN 運用ガイド(matter-over-vpn.md V2): SM_MDNS_SII_MS / SM_MDNS_SAI_MS を
    // TXT の SII/SAI として広告する。DERP リレー経由等で RTT が伸びる環境では
    // SAI を大きめ(≥500ms 目安)に広告すると MRP の偽再送を抑えられる。
    let (sii_ms, sai_ms) = mdns_intervals();
    if sii_ms.is_some() || sai_ms.is_some() {
        println!("  mDNS TXT SII/SAI advertised: SII={sii_ms:?}ms SAI={sai_ms:?}ms");
    }
    // commissionable 広告の組み立て(起動時 CM=1 / ECM 窓オープン時 CM=2 で再利用)。
    let commissionable = |discriminator: u16, mode: CommissioningMode| Commissionable {
        device_type: Some(0x0100),
        device_name: Some(CFG.product_name),
        sii: sii_ms,
        sai: sai_ms,
        ..Commissionable::new(
            MDNS_INSTANCE_ID,
            discriminator,
            CFG.vendor_id,
            CFG.product_id,
            mode,
        )
    };
    mdns.set_commissionable(Some(commissionable(
        DISCRIMINATOR,
        CommissioningMode::Standard,
    )));
    let mdns_socket = open_mdns_socket();
    // IPv6(ff02::fb)側の mDNS ソケット(リンクローカルが取れたときのみ)。
    let mdns_socket_v6 = local_ipv6.and_then(|(_, scope)| open_mdns_socket_v6(scope));
    // v6 マルチキャスト応答/announce の宛先([ff02::fb%scope]:5353)。
    let mdns_v6_dst: Option<SocketAddr> = local_ipv6
        .map(|(_, scope)| SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6, MDNS_PORT, 0, scope)));

    println!("simple-matter On/Off light listening on UDP/5540 (dual-stack)");
    println!("  passcode: {PASSCODE}  discriminator: {DISCRIMINATOR}");
    match &mdns_socket {
        Some(_) => println!("  mDNS advertising on 224.0.0.251:5353 (A record: {local_ipv4})"),
        None => println!("  (mDNS socket unavailable; point a commissioner at this UDP port.)"),
    }
    match (&mdns_socket_v6, local_ipv6) {
        (Some(_), Some((ip, scope))) => {
            println!("  mDNS advertising on [ff02::fb%{scope}]:5353 (AAAA record: {ip})")
        }
        _ => println!("  (no IPv6 link-local mDNS; IPv4-only discovery)"),
    }

    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut mdns_rx = [0u8; 1500];
    let mut mdns_tx = [0u8; 1500];
    // 直近に広告済みの fabric 世代(変化検知に使う)。
    let mut last_generation = fabrics.borrow().generation();
    // 起動時コミッショニング窓(未コミッショニング時の announcement 窓)が開いているか。
    let mut boot_window_open = true;
    // 直近の fabric 数(窓経由コミッショニング完了の検知に使う)。
    let mut last_fabric_count = fabrics.borrow().len();

    loop {
        // 1) Matter UDP の受信処理。
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(&start);
                // MATTER_DEBUG=2: 受信 datagram の hex ダンプ(プロトコル調査用)。
                let debug = std::env::var("MATTER_DEBUG").ok();
                if debug.as_deref() == Some("2") {
                    let hex: String = rx[..n].iter().map(|b| format!("{b:02x}")).collect();
                    eprintln!("[rx-hex] {n}B from {src}: {hex}");
                }
                let dir = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, &mut tx);
                if debug.is_some() {
                    eprintln!(
                        "[rx] {n}B from {src} -> {}",
                        match &dir {
                            Some(d) => format!("respond {}B", d.len),
                            None => "no response".into(),
                        }
                    );
                }
                if let Some(dir) = dir {
                    if let Some(addr) = dir.addr.socket_addr() {
                        let _ = socket.send_to(&tx[..dir.len], addr);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }

        // 2) 時間駆動の送出(MRP 再送・standalone ACK・購読レポート)を排出する。
        let now = now_ms(&start);
        while let Some(dir) = stack.poll(now, &mut tx) {
            if let Some(addr) = dir.addr.socket_addr() {
                let _ = socket.send_to(&tx[..dir.len], addr);
            }
        }

        // 3) fabric が増減したら operational 広告に反映して再 announce。
        //    初回コミッショニング(fabric 0 → 1+)で起動時窓を閉じ、全 fabric 削除で再び開く
        //    (docs/design/admin-commissioning.md §5)。
        let gen = fabrics.borrow().generation();
        if gen != last_generation {
            last_generation = gen;
            let ops: Vec<Operational> = fabrics
                .borrow()
                .iter()
                .map(|f| Operational {
                    sii: sii_ms,
                    sai: sai_ms,
                    ..Operational::new(f.compressed_fabric_id(), f.node_id())
                })
                .collect();
            mdns.set_operational(ops);
            mdns.notify_change(now_ms(&start));
            let fabric_count = fabrics.borrow().len();
            // 窓経由のコミッショニング完了(fabric 追加)で窓を閉じる(§11.19.5)。
            // Closed イベントは次の 3.5) が PASE 無効化と広告停止に反映する。
            if fabric_count > last_fabric_count && window.borrow().is_open() {
                window.borrow_mut().close_window();
                println!("[window] commissioning succeeded; closing window");
            }
            last_fabric_count = fabric_count;
            if boot_window_open && fabric_count > 0 && !window.borrow().is_open() {
                boot_window_open = false;
                stack.set_pase_enabled(false);
                mdns.set_commissionable(None);
                mdns.notify_change(now_ms(&start));
                println!("[window] initial commissioning done; commissioning window closed");
            } else if !boot_window_open && fabric_count == 0 && !window.borrow().is_open() {
                boot_window_open = true;
                let cfg = PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
                stack.set_pase_config(cfg);
                stack.set_pase_enabled(true);
                mdns.set_commissionable(Some(commissionable(
                    DISCRIMINATOR,
                    CommissioningMode::Standard,
                )));
                mdns.notify_change(now_ms(&start));
                println!("[window] all fabrics removed; reopening initial commissioning window");
            }
        }

        // 3.5) コミッショニング窓イベント(OpenCommissioningWindow / Revoke / タイムアウト)を
        //      PASE 設定と mDNS 広告へ反映する(admin-commissioning.md §4/§5)。
        // 注意: `if let` の scrutinee の borrow_mut はボディ全体で生存するため、先に取り出す。
        let window_event = window.borrow_mut().take_event();
        if let Some(ev) = window_event {
            let now = now_ms(&start);
            match ev {
                WindowEvent::OpenedEnhanced { discriminator } => {
                    if let Some(cfg) = window.borrow().pase_config() {
                        stack.set_pase_config(cfg);
                        stack.set_pase_enabled(true);
                        mdns.set_commissionable(Some(commissionable(
                            discriminator,
                            CommissioningMode::Enhanced,
                        )));
                        mdns.notify_change(now);
                        println!(
                            "[window] enhanced commissioning window open (CM=2, discriminator {discriminator})"
                        );
                    }
                }
                WindowEvent::OpenedBasic => {
                    let cfg =
                        PaseConfig::from_passcode_default(PASSCODE, &SALT).expect("PASE config");
                    stack.set_pase_config(cfg);
                    stack.set_pase_enabled(true);
                    mdns.set_commissionable(Some(commissionable(
                        DISCRIMINATOR,
                        CommissioningMode::Standard,
                    )));
                    mdns.notify_change(now);
                    println!("[window] basic commissioning window open (CM=1)");
                }
                WindowEvent::Closed => {
                    stack.set_pase_enabled(false);
                    mdns.set_commissionable(None);
                    mdns.notify_change(now);
                    println!("[window] commissioning window closed");
                }
            }
            // AdminVendorId を fabric テーブルから解決して書き戻す(admin-commissioning.md §7)。
            let admin_idx = window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }

        // 4) mDNS の受信応答と announce(v4 / v6 両ファミリ)。
        //    受信は届いたソケット側で個別に応答し、定期 announce は 1 回の
        //    poll_announce を両ソケットへ送る(poll_announce はスケジュールを進める
        //    ため socket ごとに呼ばない)。
        if let Some(msock) = &mdns_socket {
            serve_mdns_socket(
                &mut mdns,
                msock,
                (MDNS_IPV4, MDNS_PORT).into(),
                &mut mdns_rx,
                &mut mdns_tx,
            );
        }
        if let (Some(msock), Some(dst)) = (&mdns_socket_v6, mdns_v6_dst) {
            serve_mdns_socket(&mut mdns, msock, dst, &mut mdns_rx, &mut mdns_tx);
        }
        if let Some(len) = mdns.poll_announce(now_ms(&start), &mut mdns_tx) {
            if let Some(msock) = &mdns_socket {
                let _ = msock.send_to(&mdns_tx[..len], (MDNS_IPV4, MDNS_PORT));
            }
            if let (Some(msock), Some(dst)) = (&mdns_socket_v6, mdns_v6_dst) {
                let _ = msock.send_to(&mdns_tx[..len], dst);
            }
        }

        // ビジーループ回避のため短くスリープする(sans-IO なので駆動間隔は任意)。
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// mDNS 用 UDP ソケットを開き、224.0.0.251 のマルチキャストグループに参加する。
///
/// ポート 5353 を他プロセス(avahi 等)が使用中なら `None` を返し、example は mDNS
/// 無しで継続する。
fn open_mdns_socket() -> Option<UdpSocket> {
    // avahi 等の既存 mDNS レスポンダと共存するため SO_REUSEADDR/SO_REUSEPORT を
    // 立ててから 5353 に bind する(std の UdpSocket では bind 前に設定できないため
    // socket2 を使う)。マルチキャストグループ参加で 224.0.0.251 宛のクエリが
    // 両方のソケットに配送される。
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    // SO_REUSEADDR のみ。SO_REUSEPORT はマルチキャストを listener 間で **ロードバランス**
    // (=1 つに振り分けて他が取りこぼす)ため、avahi 等と共存すると受信クエリを奪われる。
    // REUSEADDR だけなら同一マルチキャストポートへの複数 bind が許され、全 listener が
    // 全マルチキャストを受信する(mDNS の定石)。
    socket.set_reuse_address(true).ok()?;
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    socket
        .join_multicast_v4(&MDNS_IPV4, &Ipv4Addr::UNSPECIFIED)
        .ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}

/// `SM_MDNS_SII_MS` / `SM_MDNS_SAI_MS` から mDNS TXT の SII/SAI(ミリ秒)を読む。
///
/// VPN 運用(matter-over-vpn.md V2)で MRP を緩めるための広告値。未設定・不正値は
/// `None`(既定の広告挙動 = TXT に SII/SAI を載せない)。
fn mdns_intervals() -> (Option<u32>, Option<u32>) {
    let read = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
    (read("SM_MDNS_SII_MS"), read("SM_MDNS_SAI_MS"))
}

/// ローカルの IPv4 アドレスを推定する(外部宛 UDP ソケットの `local_addr` から)。
///
/// 実際にはパケットを送らない。取得できない場合はループバックを返す。
fn discover_local_ipv4() -> Ipv4Addr {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|s| {
            s.connect((Ipv4Addr::new(8, 8, 8, 8), 53))?;
            s.local_addr()
        })
        .ok()
        .and_then(|addr| match addr {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
        .unwrap_or(Ipv4Addr::LOCALHOST)
}

/// Matter 運用 UDP(5540)をデュアルスタック(v6only=false)で bind する。
fn open_matter_udp() -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_only_v6(false)?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MATTER_PORT)).into())?;
    Ok(s.into())
}

/// mDNS の受信クエリに応答する(1 ソケット分)。QU はソース宛ユニキャスト、
/// QM は `mc_dst`(v4=224.0.0.251 / v6=[ff02::fb%scope])宛マルチキャスト。
fn serve_mdns_socket(
    mdns: &mut MdnsResponder<NF>,
    sock: &UdpSocket,
    mc_dst: SocketAddr,
    rx: &mut [u8],
    tx: &mut [u8],
) {
    match sock.recv_from(rx) {
        Ok((n, src)) => {
            let qu = mdns.query_wants_unicast(&rx[..n]);
            if let Some(len) = mdns.handle_query(&rx[..n], tx) {
                let dst = if qu { src } else { mc_dst };
                let _ = sock.send_to(&tx[..len], dst);
            }
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
        Err(_) => {}
    }
}

/// IPv6(ff02::fb)用 mDNS ソケットを開き、`scope`(if_index)で join する。
///
/// `set_only_v6(true)` で v4 側(別ソケット)と役割を分ける。5353 共有のため
/// `SO_REUSEADDR`(+ unix は `SO_REUSEPORT`)を立ててから bind する。
fn open_mdns_socket_v6(scope: u32) -> Option<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_only_v6(true).ok()?;
    socket.set_reuse_address(true).ok()?;
    #[cfg(unix)]
    let _ = socket.set_reuse_port(true);
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    socket.join_multicast_v6(&MDNS_IPV6, scope).ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}

/// リンクローカル IPv6(fe80::/10)と scope_id(if_index)を推定する。
///
/// Linux は `/proc/net/route` から **既定経路の iface** を特定し、その iface の
/// fe80 行を `/proc/net/if_inet6` から採る(W3 の教訓: 仮想 IF(tailscale/docker 等)
/// が先に並ぶ環境で「最初の fe80」は LAN に届かないアドレスを広告してしまう)。
/// 既定経路が無い場合のみ最初の非 lo fe80 にフォールバック。columns:
/// addr(32hex) if_index(hex) prefixlen(hex) scope(hex) flags(hex) ifname。
/// 非 unix はディスカバリ非対応で `None`(device example は Linux 前提)。
#[cfg(target_os = "linux")]
fn discover_local_ipv6() -> Option<(Ipv6Addr, u32)> {
    let want_if = default_route_ifname();
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    let mut fallback: Option<(Ipv6Addr, u32)> = None;
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let addr_hex = cols.next()?;
        let if_index_hex = cols.next()?;
        let _prefix = cols.next()?;
        let scope_hex = cols.next()?;
        let _flags = cols.next()?;
        let ifname = cols.next()?;
        if ifname == "lo" {
            continue;
        }
        // scope 0x20 = link-local(RFC 4291)。
        if u32::from_str_radix(scope_hex, 16).ok()? != 0x20 {
            continue;
        }
        if addr_hex.len() != 32 {
            continue;
        }
        let mut octets = [0u8; 16];
        for (i, o) in octets.iter_mut().enumerate() {
            *o = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        let if_index = u32::from_str_radix(if_index_hex, 16).ok()?;
        let entry = (Ipv6Addr::from(octets), if_index);
        match &want_if {
            Some(name) if name == ifname => return Some(entry),
            _ => {
                if fallback.is_none() {
                    fallback = Some(entry);
                }
            }
        }
    }
    fallback
}

/// `/proc/net/route` から IPv4 既定経路(Destination=00000000)の iface 名を得る。
#[cfg(target_os = "linux")]
fn default_route_ifname() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let ifname = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(ifname.to_string());
        }
    }
    None
}

/// 非 Linux 向けフォールバック(IPv6 リンクローカル発見なし)。
#[cfg(not(target_os = "linux"))]
fn discover_local_ipv6() -> Option<(Ipv6Addr, u32)> {
    None
}
