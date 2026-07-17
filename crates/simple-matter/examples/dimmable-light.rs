//! std 上の Dimmable Light サンプル(ロードマップ第5段階 §15 の型実証)。
//!
//! [`onoff-light`](../onoff-light.rs) をベースに、EP1 を **Dimmable Light**
//! (DeviceType 0x0101)にして On/Off(0x0006)+ Level Control(0x0008)+ Descriptor を
//! 載せる。Level Control の TransitionTime 遷移は
//! [`ServerCluster::tick`](simple_matter::dm::ServerCluster::tick) を
//! [`tick_clusters`](simple_matter::dm::tick_clusters) 経由で駆動する(設計 §15.1)。
//! OnOff ⇔ Level の連動はアプリ(この example)が
//! [`take_on_off_request`](simple_matter::dm::clusters::LevelControlCluster::take_on_off_request)/
//! [`notify_on_off`](simple_matter::dm::clusters::LevelControlCluster::notify_on_off) で仲介する
//! (設計 §15.3)。
//!
//! # 構成
//!
//! - EP0: Basic Information / General Commissioning / Network Commissioning /
//!   Operational Credentials / AccessControl / AdminCommissioning / Descriptor
//! - EP1: On/Off / Level Control / Descriptor
//! - パスコード 20202021 + テスト DAC([`TestDacProvider`])。On/Off / CurrentLevel 変化を `println!`。
//!
//! mDNS ディスカバリは [`MdnsResponder`](simple_matter::discovery::MdnsResponder) で駆動する。
//! mDNS インスタンス ID は onoff-light と別値にして、同一ホストで併走しても衝突しないようにする。
//!
//! 実行: `cargo run --example dimmable-light`

use std::cell::RefCell;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::path::PathBuf;
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
    CommissioningWindow, DescriptorCluster, GeneralCommissioning, IdentifyCluster,
    LevelControlCluster, NetworkCommissioning, OnOffCluster, OpCredsCluster, TestDacProvider,
    WindowEvent,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta, EventId};
use simple_matter::dm::{tick_clusters, DataModel, ServerCluster};
use simple_matter::error::{Error, Result as SmResult};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::im::events::PRIORITY_INFO;
use simple_matter::kvs::Kvs;
use simple_matter::sc::SecureChannel;

#[path = "common/pase.rs"]
mod common_pase;
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::tlv::TlvTag;
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};

const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;

/// コミッショニング discriminator(12 ビット)。chip-tool の既定テスト値。
const DISCRIMINATOR: u16 = 3840;
/// mDNS インスタンス識別子。onoff-light(0x0011_2233_4455_6677)と別値にして
/// 同一ホスト併走時の衝突を避ける(設計 §15.4 の割り切り)。
const MDNS_INSTANCE_ID: u64 = 0x0011_2233_4455_66AA;
/// Dimmable Light デバイスタイプ ID(mDNS 広告と Descriptor で使う)。
const DEVICE_TYPE_DIMMABLE: u32 = 0x0101;

type Backend = RustCrypto<DemoRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds<'s> = OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

/// デモ用の擬似乱数(SystemTime シードの LCG)。**暗号学的に安全ではない**。
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

/// std のファイルベース [`Kvs`](環境変数 `SM_STATE_DIR` が指すディレクトリ)。
struct FileKvs {
    dir: PathBuf,
}

impl FileKvs {
    fn new(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
    fn path(&self, key: &[u8]) -> PathBuf {
        let mut name = String::with_capacity(key.len() * 2 + 4);
        for b in key {
            name.push_str(&format!("{b:02x}"));
        }
        name.push_str(".bin");
        self.dir.join(name)
    }
}

impl Kvs for FileKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> SmResult<Option<usize>> {
        match std::fs::read(self.path(key)) {
            Ok(bytes) => {
                if buf.len() < bytes.len() {
                    return Err(Error::NoSpace);
                }
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(bytes.len()))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::InvalidState),
        }
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> SmResult<()> {
        std::fs::write(self.path(key), value).map_err(|_| Error::InvalidState)
    }
    fn remove(&mut self, key: &[u8]) -> SmResult<()> {
        match std::fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Error::InvalidState),
        }
    }
}

// --- デバイス構成(device! マクロは共有 OpCreds のライフタイムを扱えないため手書き)---

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "SimpleMatter",
    vendor_id: 0xFFF1,
    product_name: "DimmableLight",
    product_id: 0x8002,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SM-DIM-0001",
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
// EP1 = Dimmable Light: On/Off(0x0006)+ Level Control(0x0008)+ Descriptor(0x001D)。
static EP1_SERVERS: &[ClusterId] = &[
    ClusterId(0x0003),
    ClusterId(0x0006),
    ClusterId(0x0008),
    ClusterId(0x001D),
];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(DEVICE_TYPE_DIMMABLE, 3)];
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
    identify: IdentifyCluster,
    onoff: OnOffCluster,
    level: LevelControlCluster,
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
            (0, 0x001F) => Some(&self.access_control),
            (0, 0x0028) => Some(&self.basic),
            (0, 0x0030) => Some(&self.gc),
            (0, 0x0031) => Some(&self.net),
            (0, 0x003C) => Some(&self.admin),
            (0, 0x003E) => Some(&self.opcreds),
            (0, 0x001D) => Some(&self.desc0),
            (1, 0x0003) => Some(&self.identify),
            (1, 0x0006) => Some(&self.onoff),
            (1, 0x0008) => Some(&self.level),
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
            (1, 0x0003) => Some(&mut self.identify),
            (1, 0x0006) => Some(&mut self.onoff),
            (1, 0x0008) => Some(&mut self.level),
            (1, 0x001D) => Some(&mut self.desc1),
            _ => None,
        }
    }
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.gc.on_tick(now_ms) {
            // fail-safe 期限切れ: pending 破棄 + 未 CommissioningComplete の fabric 巻き戻し。
            if let Some(idx) = self.opcreds.on_failsafe_expired() {
                self.removed_fabric = Some(idx);
            }
        }
        // コミッショニング窓のタイムアウト自動クローズ(admin-commissioning.md §2)。
        let _ = self.admin.on_tick(now_ms);
        // クラスタ tick(Level Control の遷移エンジン)を回す(設計 §15.1)。
        // on_tick を手書きで上書きしているため、tick_clusters は明示的に呼ぶ。
        let next = tick_clusters(self, now_ms);
        // OnOff ⇔ Level の連動 sync(設計 §15.3 のコード断片どおり)。
        if let Some(on) = self.level.take_on_off_request() {
            self.onoff.set(on);
        }
        let on = self.onoff.is_on();
        if on != self.level.coupled_on() {
            self.level.notify_on_off(on);
        }
        next
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
    fn acl(&self) -> Option<&dyn AclHandle> {
        Some(self.acl)
    }
}

fn build_light<'s>(
    fabrics: &'s RefCell<FabricTable<Backend, NF>>,
    acl: &'s RefCell<AclTable<NACL>>,
    window: &'s RefCell<CommissioningWindow>,
) -> Light<'s> {
    let dac_crypto = RustCrypto::new(DemoRng::from_time());
    let dac = if std::env::var_os("SM_TAMPER_CD").is_some() {
        eprintln!("[dac] SM_TAMPER_CD set: serving a tampered Certification Declaration");
        TestDacProvider::new_with_tampered_cd(&dac_crypto).expect("test DAC")
    } else {
        TestDacProvider::new(&dac_crypto).expect("test DAC")
    };
    Light {
        acl,
        access_control: AccessControlCluster::new(acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        admin: AdminCommissioningCluster::new(window),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::from_time()), dac),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        // 識別中/終了を println で通知する。
        identify: IdentifyCluster::new().with_listener(|on| {
            println!("[identify] {}", if on { "identifying" } else { "stopped" });
        }),
        // On/Off 変化を println で通知する。
        onoff: OnOffCluster::new().with_listener(|on| {
            println!("[onoff] light is now {}", if on { "ON" } else { "OFF" });
        }),
        // CurrentLevel 変化を println で通知する(設計 §15.3)。
        level: LevelControlCluster::new().with_listener(|lvl| match lvl {
            Some(v) => println!("[level] CurrentLevel={v}"),
            None => println!("[level] CurrentLevel=null"),
        }),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
    }
}

fn main() -> std::io::Result<()> {
    let crypto = RustCrypto::new(DemoRng::from_time());
    let fabrics: RefCell<FabricTable<Backend, NF>> = RefCell::new(FabricTable::new());
    let acl: RefCell<AclTable<NACL>> = RefCell::new(AclTable::new());
    let window: RefCell<CommissioningWindow> = RefCell::new(CommissioningWindow::new());

    let config = common_pase::config();
    let creds = SharedFabricCreds::new(&fabrics, &crypto, 0);
    let sc = SecureChannel::new(&crypto, DemoRng::from_time(), config, creds);
    let im = InteractionModel::new(build_light(&fabrics, &acl, &window));
    let mut stack: DefaultStack<Backend, DemoRng, Light> = MatterStack::new(&crypto, sc, im);

    let _ = stack.post_startup_event(CFG.software_version, 0);

    let mut kvs: Option<FileKvs> = match std::env::var_os("SM_STATE_DIR") {
        Some(dir) => match FileKvs::new(PathBuf::from(&dir)) {
            Ok(k) => {
                println!(
                    "[kvs] persistence enabled at {}",
                    PathBuf::from(&dir).display()
                );
                Some(k)
            }
            Err(e) => {
                println!("[kvs] cannot open SM_STATE_DIR ({e}); running in-memory");
                None
            }
        },
        None => None,
    };
    if let Some(kvs) = kvs.as_mut() {
        match fabrics.borrow_mut().load_from(kvs, &crypto, 0) {
            Ok(n) => println!("[kvs] restored {n} fabrics"),
            Err(e) => {
                println!("[kvs] fabric restore failed: {e:?}; starting with empty table");
                *fabrics.borrow_mut() = FabricTable::new();
            }
        }
        match acl.borrow_mut().load_from(kvs) {
            Ok(n) => println!("[kvs] restored {n} ACL entries"),
            Err(e) => println!("[kvs] ACL restore failed: {e:?}"),
        }
        match stack.load_resumptions_from(kvs) {
            Ok(n) => println!("[kvs] restored {n} resumptions"),
            Err(e) => println!("[kvs] resumption restore failed: {e:?}"),
        }
    }
    let restored_fabric_count = fabrics.borrow().len();
    if restored_fabric_count > 0 {
        stack.set_pase_enabled(false);
    }

    let socket = open_matter_udp()?;
    socket.set_nonblocking(true)?;
    let start = Instant::now();
    let now_ms = |start: &Instant| start.elapsed().as_millis() as u64;

    // --- mDNS ディスカバリ ---
    let local_ipv4 = discover_local_ipv4();
    let local_ipv6 = discover_local_ipv6();
    let mac = MDNS_INSTANCE_ID.to_be_bytes();
    let host = Host::from_mac(&mac[2..8], local_ipv6.map(|(ip, _)| ip), Some(local_ipv4));
    let mut mdns: MdnsResponder<NF> = MdnsResponder::new(host, MATTER_PORT);
    let (sii_ms, sai_ms) = mdns_intervals();
    if sii_ms.is_some() || sai_ms.is_some() {
        println!("  mDNS TXT SII/SAI advertised: SII={sii_ms:?}ms SAI={sai_ms:?}ms");
    }
    // commissionable 広告(Dimmable Light は device_type=0x0101 を広告する)。
    let commissionable = |discriminator: u16, mode: CommissioningMode| Commissionable {
        device_type: Some(DEVICE_TYPE_DIMMABLE),
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
    if restored_fabric_count == 0 {
        mdns.set_commissionable(Some(commissionable(
            DISCRIMINATOR,
            CommissioningMode::Standard,
        )));
    } else {
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
        println!("[kvs] advertising operational for {restored_fabric_count} restored fabric(s)");
    }
    let mdns_socket = open_mdns_socket();
    let mdns_socket_v6 = local_ipv6.and_then(|(_, scope)| open_mdns_socket_v6(scope));
    let mdns_v6_dst: Option<SocketAddr> = local_ipv6
        .map(|(_, scope)| SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6, MDNS_PORT, 0, scope)));

    println!("simple-matter Dimmable light listening on UDP/5540 (dual-stack)");
    println!("  PASE: {}  discriminator: {DISCRIMINATOR}", common_pase::config_labeled().1);
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
    let mut last_generation = fabrics.borrow().generation();
    let mut last_resumption_gen = stack.resumption_generation();
    let mut last_on = stack.device().onoff.is_on();
    let mut boot_window_open = restored_fabric_count == 0;
    let mut last_fabric_count = fabrics.borrow().len();

    loop {
        // 1) Matter UDP の受信処理。
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let now = now_ms(&start);
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

        // 2b) OnOff 状態変化を OnOff クラスタ(0x0006)のイベント(id 0x00)として post する。
        let on_now = stack.device().onoff.is_on();
        if on_now != last_on {
            last_on = on_now;
            let _ = stack.post_event(
                EndpointId(1),
                ClusterId(0x0006),
                EventId(0),
                PRIORITY_INFO,
                now,
                |w, tag| {
                    w.start_struct(tag)?;
                    w.write_bool(&TlvTag::ContextSpecific(0), on_now)?;
                    w.end_container()
                },
            );
        }

        // 3) fabric が増減したら operational 広告に反映して再 announce。
        let gen = fabrics.borrow().generation();
        if gen != last_generation {
            last_generation = gen;
            if let Some(kvs) = kvs.as_mut() {
                match fabrics.borrow().save_to(kvs) {
                    Ok(()) => println!("[kvs] saved {} fabrics", fabrics.borrow().len()),
                    Err(e) => println!("[kvs] fabric save error: {e:?}"),
                }
                match acl.borrow().save_to(kvs) {
                    Ok(()) => println!("[kvs] saved ACL"),
                    Err(e) => println!("[kvs] ACL save error: {e:?}"),
                }
            }
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
                let cfg = common_pase::config();
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

        // 3.2) CASE resumption ストアの世代変化を検知して KVS へ保存する(§7.4)。
        let rgen = stack.resumption_generation();
        if rgen != last_resumption_gen {
            last_resumption_gen = rgen;
            if let Some(kvs) = kvs.as_mut() {
                match stack.save_resumptions_to(kvs) {
                    Ok(()) => println!("[kvs] saved resumptions"),
                    Err(e) => println!("[kvs] resumption save error: {e:?}"),
                }
            }
        }

        // 3.5) コミッショニング窓イベントを PASE 設定と mDNS 広告へ反映する。
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
                    let cfg = common_pase::config();
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
            let admin_idx = window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }

        // 4) mDNS の受信応答と announce(v4 / v6 両ファミリ)。
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

        // ビジーループ回避のため短くスリープする(この 20ms 周期が遷移の分解能になる)。
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// mDNS 用 UDP ソケットを開き、224.0.0.251 のマルチキャストグループに参加する。
fn open_mdns_socket() -> Option<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
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
fn mdns_intervals() -> (Option<u32>, Option<u32>) {
    let read = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u32>().ok());
    (read("SM_MDNS_SII_MS"), read("SM_MDNS_SAI_MS"))
}

/// ローカルの IPv4 アドレスを推定する(外部宛 UDP ソケットの `local_addr` から)。
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

/// mDNS の受信クエリに応答する(1 ソケット分)。
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
