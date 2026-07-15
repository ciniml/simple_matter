//! C ABI シム(staticlib):`simple-matter` のデバイススタックを C/C++17 から駆動する。
//!
//! 設計は `docs/design/c-ffi-shim.md`。方式は **sans-IO コアをそのまま C に写す**:
//! TX はコールバックではなく out-buffer 戻り値方式、I/O(ソケット・時刻・永続化)の
//! 所有は呼び出し側。コールバックが残るのは KVS(get/set/delete)と RNG のみ。
//!
//! - 単一インスタンス・単線アクセス(スタックは crate 内 `static` に確保)。全 API は
//!   同一タスクから呼ぶ契約(コアは `&mut` 単線)。
//! - `sm_udp_rx` / `sm_poll` は [`MatterStack::handle_rx`] / [`MatterStack::poll`] を、
//!   `sm_mdns_rx` / `sm_mdns_poll` は [`MdnsResponder`] を写す。
//! - fabric 増減での operational/commissionable 広告切替・KVS 永続化・OCW・イベント運搬は
//!   PC example(`examples/onoff-light.rs`)の pump 相当をシム内 [`Shim::housekeep`] に内蔵。
//!
//! ビルド:
//! - ベアメタル: `--features panic-abort`(`#[panic_handler]` を提供、no_std)。
//! - ホスト(ctest / `cargo test`): `--features std`(std のパニックハンドラを使う)。

// no_std はベアメタル deliverable(`--features panic-abort`)でのみ有効化する。
// ホスト(ctest / `cargo test` / feature 無しの workspace ビルド)は std を使い、
// std のパニックハンドラ・eh_personality にリンクする(docs/design/c-ffi-shim.md §2)。
#![cfg_attr(all(feature = "panic-abort", not(feature = "std"), not(test)), no_std)]
#![allow(non_camel_case_types)]
// FFI 境界(caller 提供ポインタの deref)は非 unsafe fn 内の unsafe ブロックで扱う。
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::cell::RefCell;
use core::ffi::{c_char, c_void};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use core::num::NonZeroU8;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use simple_matter::acl::{AclHandle, AclTable};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT, MDNS_IPV4,
    MDNS_IPV6, MDNS_PORT,
};
use simple_matter::dm::clusters::{
    AccessControlCluster, AdminCommissioningCluster, BasicInfoConfig, BasicInformationCluster,
    CommissioningWindow, DescriptorCluster, GeneralCommissioning, GroupKeyManagementCluster,
    GroupsCluster, IdentifyCluster, NetworkCommissioning, OnOffCluster, OpCredsCluster,
    TestDacProvider, WindowEvent,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta, EventId};
use simple_matter::dm::{tick_clusters, DataModel, ServerCluster};
use simple_matter::fabric::FabricTable;
use simple_matter::groups::DefaultGroupStore;
use simple_matter::im::engine::InteractionModel;
use simple_matter::im::events::PRIORITY_INFO;
use simple_matter::kvs::Kvs;
use simple_matter::sc::{PaseConfig, SecureChannel};
use simple_matter::stack::{DefaultStack, MatterStack, SharedFabricCreds};
use simple_matter::tlv::TlvTag;
use simple_matter::transport::net::PeerAddr;

// ==========================================================================
// サイジング(DefaultStack 相当、NF=5 固定)
// ==========================================================================

/// fabric テーブル容量(`DefaultStack` と同じ 5)。
const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;
/// SPAKE2+ ソルト(PC example と同じ開発用固定値)。
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
/// 期限なしのセンチネル([`sm_next_deadline`] が返す。C 側 `SM_NO_DEADLINE`)。
pub const SM_NO_DEADLINE: u64 = u64::MAX;
/// 内部エイリアス。
const NO_DEADLINE: u64 = SM_NO_DEADLINE;

type Backend = RustCrypto<CRng>;
type Dac = TestDacProvider<Backend>;
type OpCreds = OpCredsCluster<Backend, Dac, NF, &'static RefCell<FabricTable<Backend, NF>>>;
type Stack = DefaultStack<'static, Backend, CRng, Light>;

/// BasicInformation の固定設定(プリセットデバイス。VID/PID はテスト DAC = 0xFFF1/0x8001)。
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

// ==========================================================================
// C ABI 型(cbindgen が simple_matter.h を生成する)
// ==========================================================================

/// KVS get コールバック: 値を `buf` へ書き実長を返す(無ければ負値)。
pub type SmKvsGet =
    Option<unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char, buf: *mut u8, cap: usize) -> i32>;
/// KVS set コールバック。
pub type SmKvsSet = Option<
    unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char, val: *const u8, len: usize) -> i32,
>;
/// KVS delete コールバック(冪等)。
pub type SmKvsDelete = Option<unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char) -> i32>;
/// RNG コールバック(esp_fill_random 等)。
pub type SmRngFill = Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize)>;

/// 初期化設定(`docs/design/c-ffi-shim.md` §1)。
#[repr(C)]
pub struct sm_config_t {
    /// discriminator(12 ビット)。
    pub discriminator: u16,
    /// PASE パスコード(開発用)。
    pub passcode: u32,
    /// Vendor ID(commissionable 広告に反映)。
    pub vendor_id: u16,
    /// Product ID(commissionable 広告に反映)。
    pub product_id: u16,
    /// mDNS インスタンス名の素材(NULL 可、現状 device_name TXT は固定値)。
    pub device_name: *const c_char,
    /// hostname / instance id 用の MAC。
    pub mac: [u8; 6],
    /// KVS get コールバック(NULL 可 = 永続化なし)。
    pub kvs_get: SmKvsGet,
    /// KVS set コールバック。
    pub kvs_set: SmKvsSet,
    /// KVS delete コールバック。
    pub kvs_delete: SmKvsDelete,
    /// KVS コールバックの ctx。
    pub kvs_ctx: *mut c_void,
    /// RNG コールバック(必須)。
    pub rng_fill: SmRngFill,
    /// RNG コールバックの ctx。
    pub rng_ctx: *mut c_void,
}

/// v4/v6 両対応の datagram 宛先/送信元。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_addr_t {
    /// IP アドレス(v4 は先頭 4 バイト)。
    pub ip: [u8; 16],
    /// v6 なら true。
    pub is_v6: bool,
    /// ポート。
    pub port: u16,
    /// v6 link-local 用 scope_id(それ以外 0)。
    pub scope_id: u32,
}

/// アプリイベント種別(`docs/design/c-ffi-shim.md` §1)。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum sm_event_kind_t {
    SM_EV_NONE = 0,
    SM_EV_ONOFF_CHANGED = 1,
    SM_EV_COMMISSIONED = 2,
    SM_EV_FABRIC_REMOVED = 3,
    SM_EV_WINDOW_CHANGED = 4,
}

/// アプリイベント(立った順にリングから取り出す)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_event_t {
    pub kind: sm_event_kind_t,
    /// 補助値(ONOFF: 0/1、COMMISSIONED/FABRIC_REMOVED: fabric 数、WINDOW: 0=閉/1=開)。
    pub arg: u8,
}

// ==========================================================================
// コールバックアダプタ(C → Rust trait)
// ==========================================================================

/// C の rng_fill を [`Rng`] にアダプトする(fn ptr + ctx。単線契約下でのみ使用)。
#[derive(Clone, Copy)]
struct CRng {
    fill: unsafe extern "C" fn(*mut c_void, *mut u8, usize),
    ctx: *mut c_void,
}

impl Rng for CRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
        // SAFETY: 呼び出し側が有効な rng_fill/ctx を与える契約(sm_config_t)。
        unsafe { (self.fill)(self.ctx, dest.as_mut_ptr(), dest.len()) };
        Ok(())
    }
}

/// C の kvs_{get,set,delete} を [`Kvs`] にアダプトする。
#[derive(Clone, Copy)]
struct CKvs {
    get: unsafe extern "C" fn(*mut c_void, *const c_char, *mut u8, usize) -> i32,
    set: unsafe extern "C" fn(*mut c_void, *const c_char, *const u8, usize) -> i32,
    del: unsafe extern "C" fn(*mut c_void, *const c_char) -> i32,
    ctx: *mut c_void,
}

/// KVS キーを NUL 終端 C 文字列へ整える一時バッファ(コアのキーは短い ASCII)。
fn cstr_key(key: &[u8], out: &mut [u8; 64]) -> *const c_char {
    let n = key.len().min(out.len() - 1);
    out[..n].copy_from_slice(&key[..n]);
    out[n] = 0;
    out.as_ptr() as *const c_char
}

impl Kvs for CKvs {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> simple_matter::error::Result<Option<usize>> {
        let mut kb = [0u8; 64];
        let k = cstr_key(key, &mut kb);
        // SAFETY: caller 契約(sm_config_t の kvs コールバック)。
        let n = unsafe { (self.get)(self.ctx, k, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Ok(None);
        }
        let n = n as usize;
        if n > buf.len() {
            return Err(simple_matter::error::Error::NoSpace);
        }
        Ok(Some(n))
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> simple_matter::error::Result<()> {
        let mut kb = [0u8; 64];
        let k = cstr_key(key, &mut kb);
        // SAFETY: 同上。
        let r = unsafe { (self.set)(self.ctx, k, value.as_ptr(), value.len()) };
        if r < 0 {
            Err(simple_matter::error::Error::InvalidState)
        } else {
            Ok(())
        }
    }
    fn remove(&mut self, key: &[u8]) -> simple_matter::error::Result<()> {
        let mut kb = [0u8; 64];
        let k = cstr_key(key, &mut kb);
        // SAFETY: 同上。
        let r = unsafe { (self.del)(self.ctx, k) };
        if r < 0 {
            Err(simple_matter::error::Error::InvalidState)
        } else {
            Ok(())
        }
    }
}

// ==========================================================================
// イベントリング(容量 8、あふれは古い方を落とす)
// ==========================================================================

const EV_CAP: usize = 8;

struct EventRing {
    buf: [sm_event_t; EV_CAP],
    head: usize,
    len: usize,
}

impl EventRing {
    const fn new() -> Self {
        Self {
            buf: [sm_event_t {
                kind: sm_event_kind_t::SM_EV_NONE,
                arg: 0,
            }; EV_CAP],
            head: 0,
            len: 0,
        }
    }
    fn push(&mut self, kind: sm_event_kind_t, arg: u8) {
        let tail = (self.head + self.len) % EV_CAP;
        self.buf[tail] = sm_event_t { kind, arg };
        if self.len == EV_CAP {
            self.head = (self.head + 1) % EV_CAP; // 満杯: 最古を落とす
        } else {
            self.len += 1;
        }
    }
    fn pop(&mut self) -> Option<sm_event_t> {
        if self.len == 0 {
            return None;
        }
        let e = self.buf[self.head];
        self.head = (self.head + 1) % EV_CAP;
        self.len -= 1;
        Some(e)
    }
}

// ==========================================================================
// デバイス構成(examples/onoff-light.rs の Light を no_std・listener 無しで写す)
// ==========================================================================

static EP0_SERVERS: &[ClusterId] = &[
    ClusterId(0x001F),
    ClusterId(0x0028),
    ClusterId(0x0030),
    ClusterId(0x0031),
    ClusterId(0x003C),
    ClusterId(0x003E),
    ClusterId(0x003F),
    ClusterId(0x001D),
];
static EP1_SERVERS: &[ClusterId] = &[
    ClusterId(0x0003),
    ClusterId(0x0004),
    ClusterId(0x0006),
    ClusterId(0x001D),
];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
static EP0_PARTS: &[EndpointId] = &[EndpointId(1)];
static EP1_PARTS: &[EndpointId] = &[];

struct Light {
    acl: &'static RefCell<AclTable<NACL>>,
    access_control: AccessControlCluster<'static, NACL>,
    basic: BasicInformationCluster,
    gc: GeneralCommissioning,
    net: NetworkCommissioning,
    admin: AdminCommissioningCluster<'static>,
    opcreds: OpCreds,
    gkm: GroupKeyManagementCluster<'static, Backend, NF, 6, 8, 8>,
    desc0: DescriptorCluster,
    identify: IdentifyCluster,
    groups_cl: GroupsCluster<'static, 6, 8, 8>,
    onoff: OnOffCluster,
    desc1: DescriptorCluster,
    groups: &'static RefCell<DefaultGroupStore>,
    removed_fabric: Option<NonZeroU8>,
}

impl DataModel for Light {
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
            (0, 0x003F) => Some(&self.gkm),
            (0, 0x001D) => Some(&self.desc0),
            (1, 0x0003) => Some(&self.identify),
            (1, 0x0004) => Some(&self.groups_cl),
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
            (0, 0x003F) => Some(&mut self.gkm),
            (0, 0x001D) => Some(&mut self.desc0),
            (1, 0x0003) => Some(&mut self.identify),
            (1, 0x0004) => Some(&mut self.groups_cl),
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
        let _ = self.admin.on_tick(now_ms);
        let next = tick_clusters(self, now_ms);
        let identifying = self.identify.is_identifying();
        self.groups_cl.set_identifying(identifying);
        next
    }
    fn group_endpoints(&self, fabric: NonZeroU8, group_id: u16, idx: usize) -> Option<EndpointId> {
        let store = self.groups.borrow();
        let eps = store.member_endpoints(fabric, group_id)?;
        eps.get(idx).map(|&e| EndpointId(e))
    }
    fn on_failsafe_cleanup(&mut self) -> Option<NonZeroU8> {
        self.gc.disarm();
        self.opcreds.on_failsafe_expired()
    }
    fn on_commissioning_complete(&mut self) {
        self.opcreds.on_commissioning_complete();
    }
    fn take_removed_fabric(&mut self) -> Option<NonZeroU8> {
        self.removed_fabric.take()
    }
    fn acl(&self) -> Option<&dyn AclHandle> {
        Some(self.acl)
    }
}

/// 外部所有(スタックが `&'static` で借用する)テーブル群。
struct Owned {
    crypto: Backend,
    fabrics: RefCell<FabricTable<Backend, NF>>,
    acl: RefCell<AclTable<NACL>>,
    window: RefCell<CommissioningWindow>,
    groups: RefCell<DefaultGroupStore>,
}

fn build_light(o: &'static Owned, rng: CRng) -> Light {
    let dac_crypto = RustCrypto::new(rng);
    let dac = TestDacProvider::new(&dac_crypto).expect("test DAC");
    Light {
        acl: &o.acl,
        access_control: AccessControlCluster::new(&o.acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        admin: AdminCommissioningCluster::new(&o.window),
        opcreds: OpCredsCluster::new_shared(&o.fabrics, RustCrypto::new(rng), dac),
        gkm: GroupKeyManagementCluster::new_shared(&o.groups, &o.fabrics, RustCrypto::new(rng)),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        identify: IdentifyCluster::new(),
        onoff: OnOffCluster::new(),
        groups_cl: GroupsCluster::new_shared(&o.groups, 1),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
        groups: &o.groups,
    }
}

// ==========================================================================
// シム状態(単一 static インスタンス)
// ==========================================================================

struct Shim {
    owned: Owned,
    stack: Stack,
    mdns: MdnsResponder<NF>,
    kvs: Option<CKvs>,
    mac: [u8; 6],
    instance_id: u64,
    vendor_id: u16,
    product_id: u16,
    discriminator: u16,
    passcode: u32,
    ipv4: Option<[u8; 4]>,
    ipv6_ll: Option<[u8; 16]>,
    last_fabric_gen: u32,
    last_group_gen: u32,
    last_resumption_gen: u32,
    last_fabric_count: usize,
    last_on: bool,
    boot_window_open: bool,
    events: EventRing,
}

/// `MaybeUninit<Shim>` を包む Sync セル(単一インスタンス・単線アクセス契約)。
struct ShimCell(core::cell::UnsafeCell<core::mem::MaybeUninit<Shim>>);
// SAFETY: 単一タスクからのみアクセスする契約(sm_* 全 API)。
unsafe impl Sync for ShimCell {}

static SHIM: ShimCell = ShimCell(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static INITED: AtomicBool = AtomicBool::new(false);

/// 初期化済みシムへの排他参照(単線契約)。
///
/// # SAFETY
/// `INITED` が true(= sm_init 済み)かつ単一タスクからのみ呼ぶこと。
unsafe fn shim() -> &'static mut Shim {
    (*SHIM.0.get()).assume_init_mut()
}

impl Shim {
    fn commissionable_ad(&self, discriminator: u16, mode: CommissioningMode) -> Commissionable {
        Commissionable {
            device_type: Some(0x0100),
            device_name: Some(CFG.product_name),
            sii: None,
            sai: None,
            ..Commissionable::new(
                self.instance_id,
                discriminator,
                self.vendor_id,
                self.product_id,
                mode,
            )
        }
    }

    /// 現在の fabric テーブルから operational 広告を再構成する(no-alloc、イテレータ直渡し)。
    fn refresh_operational(&mut self) {
        let fb = self.owned.fabrics.borrow();
        self.mdns.set_operational(
            fb.iter()
                .map(|f| Operational::new(f.compressed_fabric_id(), f.node_id())),
        );
    }

    /// Host(A/AAAA)を現在のアドレスで作り直し、広告状態を再適用する。
    fn rebuild_mdns(&mut self, now: u64) {
        let host = Host::from_mac(
            &self.mac,
            self.ipv6_ll.map(Ipv6Addr::from),
            self.ipv4.map(Ipv4Addr::from),
        );
        self.mdns = MdnsResponder::new(host, MATTER_PORT);
        let count = self.owned.fabrics.borrow().len();
        if count == 0 && self.boot_window_open {
            let ad = self.commissionable_ad(self.discriminator, CommissioningMode::Standard);
            self.mdns.set_commissionable(Some(ad));
        } else {
            self.refresh_operational();
        }
        self.mdns.notify_change(now);
    }

    /// KVS からの復元 + 広告初期化(sm_init 末尾)。
    fn restore_and_advertise(&mut self, now: u64) {
        if let Some(mut kvs) = self.kvs {
            let _ = self
                .owned
                .fabrics
                .borrow_mut()
                .load_from(&mut kvs, &self.owned.crypto, 0);
            let _ = self.owned.acl.borrow_mut().load_from(&mut kvs);
            let _ = self.owned.groups.borrow_mut().load_from(&mut kvs);
            let _ = self.stack.load_resumptions_from(&mut kvs);
        }
        let count = self.owned.fabrics.borrow().len();
        if count > 0 {
            self.stack.set_pase_enabled(false);
        }
        self.boot_window_open = count == 0;
        self.last_fabric_count = count;
        self.last_fabric_gen = self.owned.fabrics.borrow().generation();
        self.last_group_gen = self.owned.groups.borrow().generation();
        self.last_resumption_gen = self.stack.resumption_generation();
        self.last_on = self.stack.device().onoff.is_on();
        self.rebuild_mdns(now);
    }

    /// PC example の pump 相当: 世代変化での永続化・広告切替、窓イベント、OnOff イベント。
    fn housekeep(&mut self, now: u64) {
        // OnOff 状態変化 → イベント post + リング push。
        let on_now = self.stack.device().onoff.is_on();
        if on_now != self.last_on {
            self.last_on = on_now;
            let _ = self.stack.post_event(
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
            self.events
                .push(sm_event_kind_t::SM_EV_ONOFF_CHANGED, on_now as u8);
        }

        // fabric 世代変化 → 永続化 + operational/commissionable 広告切替。
        let gen = self.owned.fabrics.borrow().generation();
        if gen != self.last_fabric_gen {
            self.last_fabric_gen = gen;
            if let Some(mut kvs) = self.kvs {
                let _ = self.owned.fabrics.borrow().save_to(&mut kvs);
                let _ = self.owned.acl.borrow().save_to(&mut kvs);
            }
            self.refresh_operational();
            self.mdns.notify_change(now);
            let count = self.owned.fabrics.borrow().len();
            if count > self.last_fabric_count {
                self.events
                    .push(sm_event_kind_t::SM_EV_COMMISSIONED, count as u8);
                if self.owned.window.borrow().is_open() {
                    self.owned.window.borrow_mut().close_window();
                }
            } else if count < self.last_fabric_count {
                self.events
                    .push(sm_event_kind_t::SM_EV_FABRIC_REMOVED, count as u8);
            }
            if self.boot_window_open && count > 0 && !self.owned.window.borrow().is_open() {
                self.boot_window_open = false;
                self.stack.set_pase_enabled(false);
                self.mdns.set_commissionable(None);
                self.mdns.notify_change(now);
            } else if !self.boot_window_open && count == 0 && !self.owned.window.borrow().is_open() {
                self.boot_window_open = true;
                if let Ok(cfg) = PaseConfig::from_passcode_default(self.passcode, &SALT) {
                    self.stack.set_pase_config(cfg);
                    self.stack.set_pase_enabled(true);
                }
                let ad = self.commissionable_ad(self.discriminator, CommissioningMode::Standard);
                self.mdns.set_commissionable(Some(ad));
                self.mdns.notify_change(now);
            }
            self.last_fabric_count = count;
        }

        // group 世代変化 → 永続化。
        let ggen = self.owned.groups.borrow().generation();
        if ggen != self.last_group_gen {
            self.last_group_gen = ggen;
            if let Some(mut kvs) = self.kvs {
                let _ = self.owned.groups.borrow().save_to(&mut kvs);
            }
        }

        // CASE resumption 世代変化 → 永続化。
        let rgen = self.stack.resumption_generation();
        if rgen != self.last_resumption_gen {
            self.last_resumption_gen = rgen;
            if let Some(mut kvs) = self.kvs {
                let _ = self.stack.save_resumptions_to(&mut kvs);
            }
        }

        // コミッショニング窓イベント(OCW / Revoke / タイムアウト)を PASE + 広告へ反映。
        let wev = self.owned.window.borrow_mut().take_event();
        if let Some(wev) = wev {
            match wev {
                WindowEvent::OpenedEnhanced { discriminator } => {
                    if let Some(cfg) = self.owned.window.borrow().pase_config() {
                        self.stack.set_pase_config(cfg);
                        self.stack.set_pase_enabled(true);
                        let ad =
                            self.commissionable_ad(discriminator, CommissioningMode::Enhanced);
                        self.mdns.set_commissionable(Some(ad));
                        self.mdns.notify_change(now);
                        self.events.push(sm_event_kind_t::SM_EV_WINDOW_CHANGED, 1);
                    }
                }
                WindowEvent::OpenedBasic => {
                    if let Ok(cfg) = PaseConfig::from_passcode_default(self.passcode, &SALT) {
                        self.stack.set_pase_config(cfg);
                        self.stack.set_pase_enabled(true);
                    }
                    let ad =
                        self.commissionable_ad(self.discriminator, CommissioningMode::Standard);
                    self.mdns.set_commissionable(Some(ad));
                    self.mdns.notify_change(now);
                    self.events.push(sm_event_kind_t::SM_EV_WINDOW_CHANGED, 1);
                }
                WindowEvent::Closed => {
                    self.stack.set_pase_enabled(false);
                    self.mdns.set_commissionable(None);
                    self.mdns.notify_change(now);
                    self.events.push(sm_event_kind_t::SM_EV_WINDOW_CHANGED, 0);
                }
            }
            let admin_idx = self.owned.window.borrow().admin_fabric_index();
            if let Some(idx) = admin_idx {
                let vid = self.owned.fabrics.borrow().get(idx).map(|f| f.vendor_id());
                if let Some(vid) = vid {
                    self.owned.window.borrow_mut().set_admin_vendor_id(vid);
                }
            }
        }
    }
}

// ==========================================================================
// アドレス変換
// ==========================================================================

fn addr_to_peer(a: &sm_addr_t) -> PeerAddr {
    if a.is_v6 {
        let ip = Ipv6Addr::from(a.ip);
        PeerAddr::Udp(SocketAddr::V6(SocketAddrV6::new(ip, a.port, 0, a.scope_id)))
    } else {
        let ip = Ipv4Addr::new(a.ip[0], a.ip[1], a.ip[2], a.ip[3]);
        PeerAddr::Udp(SocketAddr::V4(SocketAddrV4::new(ip, a.port)))
    }
}

fn peer_to_addr(p: PeerAddr) -> sm_addr_t {
    let mut out = sm_addr_t {
        ip: [0u8; 16],
        is_v6: false,
        port: 0,
        scope_id: 0,
    };
    match p.socket_addr() {
        Some(SocketAddr::V4(v4)) => {
            out.ip[..4].copy_from_slice(&v4.ip().octets());
            out.port = v4.port();
        }
        Some(SocketAddr::V6(v6)) => {
            out.is_v6 = true;
            out.ip.copy_from_slice(&v6.ip().octets());
            out.port = v6.port();
            out.scope_id = v6.scope_id();
        }
        None => {}
    }
    out
}

/// QM(マルチキャスト)応答/announce の宛先を送信元ファミリから決める。
fn multicast_dst(is_v6: bool, scope_id: u32) -> sm_addr_t {
    if is_v6 {
        peer_to_addr(PeerAddr::Udp(SocketAddr::V6(SocketAddrV6::new(
            MDNS_IPV6, MDNS_PORT, 0, scope_id,
        ))))
    } else {
        peer_to_addr(PeerAddr::Udp(SocketAddr::V4(SocketAddrV4::new(
            MDNS_IPV4, MDNS_PORT,
        ))))
    }
}

// ==========================================================================
// C API
// ==========================================================================

/// スタックを初期化する(KVS から fabric/ACL/resumption 復元込み)。0=OK、負値=失敗。
#[no_mangle]
pub extern "C" fn sm_init(cfg: *const sm_config_t, now_ms: u64) -> i32 {
    if cfg.is_null() {
        return -1;
    }
    if INITED.load(Ordering::SeqCst) {
        return -2; // 単一インスタンス: 二重初期化を拒否。
    }
    // SAFETY: cfg は有効な sm_config_t を指す契約。
    let cfg = unsafe { &*cfg };
    let Some(rng_fill) = cfg.rng_fill else {
        return -3;
    };
    let rng = CRng {
        fill: rng_fill,
        ctx: cfg.rng_ctx,
    };
    let kvs = match (cfg.kvs_get, cfg.kvs_set, cfg.kvs_delete) {
        (Some(get), Some(set), Some(del)) => Some(CKvs {
            get,
            set,
            del,
            ctx: cfg.kvs_ctx,
        }),
        _ => None,
    };

    let mut instance_id_bytes = [0u8; 8];
    instance_id_bytes[2..8].copy_from_slice(&cfg.mac);
    let instance_id = u64::from_be_bytes(instance_id_bytes);

    let owned = Owned {
        crypto: RustCrypto::new(rng),
        fabrics: RefCell::new(FabricTable::new()),
        acl: RefCell::new(AclTable::new()),
        window: RefCell::new(CommissioningWindow::new()),
        groups: RefCell::new(DefaultGroupStore::new()),
    };

    // SAFETY: 単一インスタンスを in-place 構築する。SHIM は static(不動)なので
    // owned フィールドへの &'static 参照は健全(自己参照はプログラム全生存期間有効)。
    unsafe {
        let sp = SHIM.0.get() as *mut Shim;
        addr_of_mut!((*sp).owned).write(owned);
        let o: &'static Owned = &*addr_of!((*sp).owned);

        let config = match PaseConfig::from_passcode_default(cfg.passcode, &SALT) {
            Ok(c) => c,
            Err(_) => return -4,
        };
        let creds = SharedFabricCreds::new(&o.fabrics, &o.crypto, 0);
        let sc = SecureChannel::new(&o.crypto, rng, config, creds);
        let im = InteractionModel::new(build_light(o, rng));
        let mut stack: Stack = MatterStack::new(&o.crypto, sc, im);
        stack.set_group_keys(&o.groups);
        let _ = stack.post_startup_event(CFG.software_version, 0);

        addr_of_mut!((*sp).stack).write(stack);
        // Host は sm_set_addrs 前は A/AAAA 無し(--at ユニキャストで解決可)。
        let host = Host::from_mac(&cfg.mac, None, None);
        addr_of_mut!((*sp).mdns).write(MdnsResponder::new(host, MATTER_PORT));
        addr_of_mut!((*sp).kvs).write(kvs);
        addr_of_mut!((*sp).mac).write(cfg.mac);
        addr_of_mut!((*sp).instance_id).write(instance_id);
        addr_of_mut!((*sp).vendor_id).write(cfg.vendor_id);
        addr_of_mut!((*sp).product_id).write(cfg.product_id);
        addr_of_mut!((*sp).discriminator).write(cfg.discriminator & 0x0FFF);
        addr_of_mut!((*sp).passcode).write(cfg.passcode);
        addr_of_mut!((*sp).ipv4).write(None);
        addr_of_mut!((*sp).ipv6_ll).write(None);
        addr_of_mut!((*sp).last_fabric_gen).write(0);
        addr_of_mut!((*sp).last_group_gen).write(0);
        addr_of_mut!((*sp).last_resumption_gen).write(0);
        addr_of_mut!((*sp).last_fabric_count).write(0);
        addr_of_mut!((*sp).last_on).write(false);
        addr_of_mut!((*sp).boot_window_open).write(true);
        addr_of_mut!((*sp).events).write(EventRing::new());

        INITED.store(true, Ordering::SeqCst);
        (*sp).restore_and_advertise(now_ms);
    }
    0
}

/// Matter UDP(:5540)受信。戻り値 = tx_out に書いた応答長(0 = 応答なし)。
#[no_mangle]
pub extern "C" fn sm_udp_rx(
    datagram: *mut u8,
    len: usize,
    src: *const sm_addr_t,
    now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !INITED.load(Ordering::SeqCst) || datagram.is_null() || src.is_null() || tx_out.is_null() {
        return 0;
    }
    // SAFETY: caller が有効なバッファ/アドレスを与える契約。
    let s = unsafe { shim() };
    let dg = unsafe { core::slice::from_raw_parts_mut(datagram, len) };
    let peer = addr_to_peer(unsafe { &*src });
    let tx = unsafe { core::slice::from_raw_parts_mut(tx_out, tx_cap) };

    let dir = s.stack.handle_rx(dg, peer, now_ms, tx);
    s.housekeep(now_ms);
    match dir {
        Some(d) => {
            if !tx_dst.is_null() {
                unsafe { *tx_dst = peer_to_addr(d.addr) };
            }
            d.len
        }
        None => 0,
    }
}

/// 期限処理(MRP 再送・ACK・購読レポート)。0 になるまで繰り返し呼んで送信する。
#[no_mangle]
pub extern "C" fn sm_poll(
    now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !INITED.load(Ordering::SeqCst) || tx_out.is_null() {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.housekeep(now_ms);
    let tx = unsafe { core::slice::from_raw_parts_mut(tx_out, tx_cap) };
    match s.stack.poll(now_ms, tx) {
        Some(d) => {
            if !tx_dst.is_null() {
                unsafe { *tx_dst = peer_to_addr(d.addr) };
            }
            d.len
        }
        None => 0,
    }
}

/// 次に sm_poll を呼ぶべき時刻(ms)。SM_NO_DEADLINE(=UINT64_MAX)= 期限なし。
#[no_mangle]
pub extern "C" fn sm_next_deadline(now_ms: u64) -> u64 {
    if !INITED.load(Ordering::SeqCst) {
        return NO_DEADLINE;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    let stack_dl = s.stack.next_deadline(now_ms).unwrap_or(NO_DEADLINE);
    let mdns_dl = s.mdns.next_announce_deadline();
    stack_dl.min(mdns_dl)
}

/// DHCP 後のアドレス反映(A/AAAA 更新)。NULL は「未設定」。
#[no_mangle]
pub extern "C" fn sm_set_addrs(ipv4: *const u8, ipv6_ll: *const u8) {
    if !INITED.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: 単線契約。ipv4/ipv6_ll は NULL か有効な 4/16 バイト。
    let s = unsafe { shim() };
    s.ipv4 = if ipv4.is_null() {
        None
    } else {
        let mut b = [0u8; 4];
        unsafe { core::ptr::copy_nonoverlapping(ipv4, b.as_mut_ptr(), 4) };
        Some(b)
    };
    s.ipv6_ll = if ipv6_ll.is_null() {
        None
    } else {
        let mut b = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(ipv6_ll, b.as_mut_ptr(), 16) };
        if b == [0u8; 16] {
            None
        } else {
            Some(b)
        }
    };
    s.rebuild_mdns(0);
}

/// mDNS(:5353)受信応答。戻り値 = tx_out に書いた応答長、tx_dst に宛先(QU=ユニキャスト)。
#[no_mangle]
pub extern "C" fn sm_mdns_rx(
    pkt: *const u8,
    len: usize,
    src: *const sm_addr_t,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !INITED.load(Ordering::SeqCst) || pkt.is_null() || src.is_null() || tx_out.is_null() {
        return 0;
    }
    // SAFETY: 単線契約 + caller のバッファ。
    let s = unsafe { shim() };
    let p = unsafe { core::slice::from_raw_parts(pkt, len) };
    let src = unsafe { &*src };
    let tx = unsafe { core::slice::from_raw_parts_mut(tx_out, tx_cap) };
    let Some(n) = s.mdns.handle_query(p, tx) else {
        return 0;
    };
    if !tx_dst.is_null() {
        let dst = if s.mdns.query_wants_unicast(p) {
            *src
        } else {
            multicast_dst(src.is_v6, src.scope_id)
        };
        unsafe { *tx_dst = dst };
    }
    n
}

/// mDNS の定期 announce。戻り値 = tx_out に書いた長さ、tx_dst にマルチキャスト宛先。
#[no_mangle]
pub extern "C" fn sm_mdns_poll(
    now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !INITED.load(Ordering::SeqCst) || tx_out.is_null() {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.housekeep(now_ms);
    let tx = unsafe { core::slice::from_raw_parts_mut(tx_out, tx_cap) };
    let Some(n) = s.mdns.poll_announce(now_ms, tx) else {
        return 0;
    };
    if !tx_dst.is_null() {
        // v4 アドレスを持てば v4 マルチキャスト、無ければ v6(F1 ホストは v4)。
        let dst = multicast_dst(s.ipv4.is_none() && s.ipv6_ll.is_some(), 0);
        unsafe { *tx_dst = dst };
    }
    n
}

/// アプリイベントを立った順に 1 件取り出す(LED 反映等)。
#[no_mangle]
pub extern "C" fn sm_take_event(out: *mut sm_event_t) -> bool {
    if !INITED.load(Ordering::SeqCst) || out.is_null() {
        return false;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    match s.events.pop() {
        Some(e) => {
            unsafe { *out = e };
            true
        }
        None => false,
    }
}

/// ローカル操作の OnOff 書き戻し(物理スイッチ等)。
#[no_mangle]
pub extern "C" fn sm_onoff_set(on: bool, now_ms: u64) {
    if !INITED.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.stack.device_mut().onoff.set(on);
    s.housekeep(now_ms);
}

/// 現在の OnOff 状態。
#[no_mangle]
pub extern "C" fn sm_onoff_get() -> bool {
    if !INITED.load(Ordering::SeqCst) {
        return false;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.stack.device().onoff.is_on()
}

/// コミッション済み fabric 数。
#[no_mangle]
pub extern "C" fn sm_fabric_count() -> u8 {
    if !INITED.load(Ordering::SeqCst) {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.owned.fabrics.borrow().len() as u8
}

// ==========================================================================
// #[panic_handler](ベアメタルビルドのみ)
// ==========================================================================

#[cfg(all(feature = "panic-abort", not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests;
