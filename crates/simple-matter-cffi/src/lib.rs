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
    BorrowedDacProvider, CommissioningWindow, DacProvider, DacSigner, DescriptorCluster,
    GeneralCommissioning, GroupKeyManagementCluster, GroupsCluster, IdentifyCluster, OnOffCluster,
    OpCredsCluster, TestDacProvider, WindowEvent,
};
use simple_matter::crypto::{Crypto, P256Keypair, P256_SIGNATURE_LEN};
// NetworkCommissioning クラスタは sm_config.network で実行時に選ぶ(§10.1、ShimNetComm):
// - SM_NET_ETHERNET: 従来の Ethernet 版(F2 の固定 SSID を C++ が自力 join)。常時利用可。
// - SM_NET_WIFI: WiFi 版(take 方式ドライバ注入)で `pairing ble-wifi`(ble 必須)。
// - SM_NET_THREAD: Thread 版(take 方式ドライバ注入)で `pairing ble-thread`(ble 必須)。
use simple_matter::dm::clusters::NetworkCommissioning;
#[cfg(feature = "ble")]
use simple_matter::dm::clusters::{NetworkCommissioningThread, NetworkCommissioningWifi};
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

mod custom;
use custom::{sm_cluster_def_t, CustomCluster, PendingRegistry};

// ---- BLE(BTP)+ WiFi プロビジョン(F3、docs/design/c-ffi-shim.md §9)----
#[cfg(feature = "ble")]
use simple_matter::btp::gatt::{AdvData, ADV_TOTAL_LEN};
#[cfg(feature = "ble")]
use simple_matter::btp::{Btp, BtpRole};
#[cfg(feature = "ble")]
use simple_matter::transport::net::{BtpConnId, MAX_RX_PACKET_SIZE};
#[cfg(feature = "ble")]
mod wifi_driver;
#[cfg(feature = "ble")]
use wifi_driver::ShimWifiDriver;
// ---- Thread プロビジョン(F6、docs/design/c-ffi-shim.md §10)----
#[cfg(feature = "ble")]
mod thread_driver;
#[cfg(feature = "ble")]
use thread_driver::ShimThreadDriver;

/// NetworkCommissioning クラスタの実型。sm_config.network で実行時に選ぶ(§10.1)。
///
/// WiFi / Thread コミッショニングは BLE(BTP)経由なので、ble 無効ビルドは Ethernet のみ。
/// Descriptor 合成・IM ディスパッチ側は本 enum を単一 [`ServerCluster`] として扱う。
enum ShimNetComm {
    /// Ethernet(固定 SSID を C++ が自力 join、または on-network PASE)。常時利用可。
    Ethernet(NetworkCommissioning),
    /// WiFi(take 方式 [`ShimWifiDriver`]、`pairing ble-wifi`)。
    #[cfg(feature = "ble")]
    Wifi(NetworkCommissioningWifi<ShimWifiDriver>),
    /// Thread(take 方式 [`ShimThreadDriver`]、`pairing ble-thread`)。
    #[cfg(feature = "ble")]
    Thread(NetworkCommissioningThread<ShimThreadDriver>),
}

impl ShimNetComm {
    /// WiFi ドライバへの可変参照(WiFi 構成でなければ `None`)。
    #[cfg(feature = "ble")]
    fn wifi_driver_mut(&mut self) -> Option<&mut ShimWifiDriver> {
        match self {
            ShimNetComm::Wifi(n) => Some(n.driver_mut()),
            _ => None,
        }
    }

    /// Thread ドライバへの可変参照(Thread 構成でなければ `None`)。
    #[cfg(feature = "ble")]
    fn thread_driver_mut(&mut self) -> Option<&mut ShimThreadDriver> {
        match self {
            ShimNetComm::Thread(n) => Some(n.driver_mut()),
            _ => None,
        }
    }

    /// ドライバ状態(join / attach 結果)を属性へ反映する(統合層が定期的に呼ぶ)。
    #[cfg(feature = "ble")]
    fn update_from_driver(&mut self) {
        match self {
            ShimNetComm::Wifi(n) => n.update_from_driver(),
            ShimNetComm::Thread(n) => n.update_from_driver(),
            ShimNetComm::Ethernet(_) => {}
        }
    }

    /// C++ に渡していない WiFi join 要求があるか。
    #[cfg(feature = "ble")]
    fn has_pending_wifi(&self) -> bool {
        matches!(self, ShimNetComm::Wifi(n) if n.driver().has_pending())
    }

    /// C++ に渡していない Thread attach 要求があるか。
    #[cfg(feature = "ble")]
    fn has_pending_thread(&self) -> bool {
        matches!(self, ShimNetComm::Thread(n) if n.driver().has_pending())
    }
}

impl ServerCluster for ShimNetComm {
    fn meta(&self) -> &'static simple_matter::dm::meta::ClusterMeta {
        match self {
            ShimNetComm::Ethernet(n) => n.meta(),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.meta(),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.meta(),
        }
    }
    fn read_attribute(
        &self,
        attr: simple_matter::dm::meta::AttributeId,
        enc: &mut simple_matter::dm::codec::AttrEncoder<'_, '_>,
        acc: &simple_matter::dm::meta::AccessContext,
    ) -> Result<(), simple_matter::im::wire::ImStatus> {
        match self {
            ShimNetComm::Ethernet(n) => n.read_attribute(attr, enc, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.read_attribute(attr, enc, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.read_attribute(attr, enc, acc),
        }
    }
    fn write_attribute(
        &mut self,
        attr: simple_matter::dm::meta::AttributeId,
        data: simple_matter::dm::AttrWrite<'_>,
        acc: &simple_matter::dm::meta::AccessContext,
    ) -> Result<(), simple_matter::im::wire::ImStatus> {
        match self {
            ShimNetComm::Ethernet(n) => n.write_attribute(attr, data, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.write_attribute(attr, data, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.write_attribute(attr, data, acc),
        }
    }
    fn invoke_command(
        &mut self,
        cmd: simple_matter::dm::meta::CommandId,
        fields: &mut simple_matter::tlv::TlvReader<'_>,
        resp: &mut simple_matter::dm::codec::CmdResponder<'_, '_>,
        acc: &simple_matter::dm::meta::AccessContext,
    ) -> Result<(), simple_matter::im::wire::ImStatus> {
        match self {
            ShimNetComm::Ethernet(n) => n.invoke_command(cmd, fields, resp, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.invoke_command(cmd, fields, resp, acc),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.invoke_command(cmd, fields, resp, acc),
        }
    }
    fn take_dirty(&mut self) -> bool {
        match self {
            ShimNetComm::Ethernet(n) => n.take_dirty(),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.take_dirty(),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.take_dirty(),
        }
    }
    fn tick(&mut self, now_ms: u64) -> Option<u64> {
        match self {
            ShimNetComm::Ethernet(n) => n.tick(now_ms),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.tick(now_ms),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.tick(now_ms),
        }
    }
    fn poll_deferred(
        &mut self,
        command: simple_matter::dm::meta::CommandId,
        resp: &mut simple_matter::dm::codec::CmdResponder<'_, '_>,
    ) -> simple_matter::dm::DeferredPoll {
        match self {
            ShimNetComm::Ethernet(n) => n.poll_deferred(command, resp),
            #[cfg(feature = "ble")]
            ShimNetComm::Wifi(n) => n.poll_deferred(command, resp),
            #[cfg(feature = "ble")]
            ShimNetComm::Thread(n) => n.poll_deferred(command, resp),
        }
    }
}

/// BTP window(コアの参照実装 `ble-onoff-light.rs` と同じ 6)。
#[cfg(feature = "ble")]
const BTP_WINDOW: usize = 6;

// ==========================================================================
// サイジング(DefaultStack 相当、NF=5 固定)
// ==========================================================================

/// fabric テーブル容量(`DefaultStack` と同じ 5)。
const NF: usize = 5;
/// ACL テーブル容量(fabric 5 × per-fabric 上限 4)。
const NACL: usize = 20;
/// マージ後の総エンドポイント数上限(プリセット EP0/EP1 + カスタム)。
const MAX_EP_TOTAL: usize = 2 + custom::MAX_CUSTOM_ENDPOINTS;
/// 1 エンドポイントあたりのサーバクラスタ ID 上限(合成 Descriptor 用)。
const MAX_SERVERS: usize = 16;
/// SPAKE2+ ソルト(PC example と同じ開発用固定値。passcode フォールバック時のみ使用)。
const SALT: [u8; 16] = *b"SPAKE2P Key Salt";
/// SPAKE2+ verifier の `w0 ‖ L` 長(97 バイト)。
const VERIFIER_W0L_LEN: usize = 97;

/// デバイスが保持する PASE 資格情報(**SPAKE2+ verifier のみ**、passcode は保持しない)。
///
/// `sm_config_t` の verifier フィールド指定時はそれを、未指定時は後方互換のため
/// `passcode`(開発専用)から導出した verifier を保持する。いずれの場合もデバイス側は
/// verifier だけを持ち、コミッショニング窓の再オープンごとに [`PaseConfig`] を再構築する。
struct DevPase {
    salt: heapless::Vec<u8, 32>,
    w0_l: [u8; VERIFIER_W0L_LEN],
    iterations: u32,
}

impl DevPase {
    /// 保持中の verifier から [`PaseConfig`] を構築する。
    fn build(&self) -> Option<PaseConfig> {
        let params = simple_matter::dev_pase::verifier_params_from_w0l(&self.w0_l)?;
        PaseConfig::from_verifier(params, &self.salt, self.iterations).ok()
    }

    /// `sm_config_t` から PASE 資格情報を組み立てる。
    ///
    /// verifier(`verifier_w0_l` 非 NULL かつ `verifier_iterations != 0`)が与えられれば
    /// それを使う(**推奨。デバイスは passcode を保持しない**)。無ければ後方互換として
    /// `passcode` から verifier を導出する(開発専用)。
    ///
    /// # Safety
    /// `cfg` の verifier ポインタは、非 NULL のとき有効かつ規定長でなければならない。
    unsafe fn from_config(cfg: &sm_config_t) -> Option<Self> {
        if !cfg.verifier_w0_l.is_null() && cfg.verifier_iterations != 0 {
            let mut w0_l = [0u8; VERIFIER_W0L_LEN];
            w0_l.copy_from_slice(core::slice::from_raw_parts(cfg.verifier_w0_l, VERIFIER_W0L_LEN));
            let salt: heapless::Vec<u8, 32> =
                if !cfg.verifier_salt.is_null() && (16..=32).contains(&cfg.verifier_salt_len) {
                    heapless::Vec::from_slice(core::slice::from_raw_parts(
                        cfg.verifier_salt,
                        cfg.verifier_salt_len,
                    ))
                    .ok()?
                } else {
                    heapless::Vec::from_slice(&SALT).ok()?
                };
            let out = Self {
                salt,
                w0_l,
                iterations: cfg.verifier_iterations,
            };
            // verifier / salt / iterations の妥当性をここで確認する。
            out.build()?;
            return Some(out);
        }
        // 後方互換フォールバック: passcode(開発専用)から verifier を導出する。
        let v = simple_matter::crypto::spake2p::compute_verifier(
            cfg.passcode,
            &SALT,
            simple_matter::sc::pase::SPAKE2P_ITERATION_COUNT,
        )
        .ok()?;
        let mut w0_l = [0u8; VERIFIER_W0L_LEN];
        w0_l[..32].copy_from_slice(&v.w0);
        w0_l[32..].copy_from_slice(&v.l);
        Some(Self {
            salt: heapless::Vec::from_slice(&SALT).ok()?,
            w0_l,
            iterations: simple_matter::sc::pase::SPAKE2P_ITERATION_COUNT,
        })
    }
}
/// 期限なしのセンチネル([`sm_next_deadline`] が返す。C 側 `SM_NO_DEADLINE`)。
pub const SM_NO_DEADLINE: u64 = u64::MAX;
/// 内部エイリアス。
const NO_DEADLINE: u64 = SM_NO_DEADLINE;

type Backend = RustCrypto<CRng>;
type Dac = ShimDac;
type OpCreds = OpCredsCluster<Backend, Dac, NF, &'static RefCell<FabricTable<Backend, NF>>>;

/// DAC 秘密鍵署名コールバック(セキュアエレメント委譲用)。
///
/// `msg`(`msg_len` バイト)に ECDSA-SHA256 署名し、生 `r||s`(64 バイト)を `out` に書く。
/// 0 = 成功、負値 = 失敗。`sm_config_t::dac_privkey` の代わりに使う。
pub type SmDacSign = Option<
    unsafe extern "C" fn(ctx: *mut c_void, msg: *const u8, msg_len: usize, out: *mut u8) -> i32,
>;

/// [`BorrowedDacProvider`] の署名バックエンド(生鍵 or C コールバック)。
enum ShimSigner {
    /// `dac_privkey`(32B)から復元した鍵ペアで署名する。
    Keypair(<Backend as Crypto>::Keypair),
    /// C コールバック(セキュアエレメント)に署名を委譲する。
    Callback { cb: SmDacSign, ctx: *mut c_void },
}

impl DacSigner for ShimSigner {
    fn sign_with_dac(
        &self,
        msg: &[u8],
        out: &mut [u8; P256_SIGNATURE_LEN],
    ) -> simple_matter::error::Result<()> {
        match self {
            ShimSigner::Keypair(kp) => kp.sign(msg, out),
            ShimSigner::Callback { cb, ctx } => {
                let f = cb.ok_or(simple_matter::error::Error::Crypto)?;
                // SAFETY: 呼び出し側が有効な署名コールバックを与える契約(sm_config_t)。
                let rc = unsafe { f(*ctx, msg.as_ptr(), msg.len(), out.as_mut_ptr()) };
                if rc == 0 {
                    Ok(())
                } else {
                    Err(simple_matter::error::Error::Crypto)
                }
            }
        }
    }
}

/// DAC provider: dev テスト DAC(後方互換)か、C 供給の [`BorrowedDacProvider`]。
///
/// `Light` の型を単一に保つための enum ディスパッチ。Borrowed の借用スライスは
/// `Owned::dac_store`(単一 static)を指す `&'static`。
///
/// `Test` 変種は CD(539B)を内包するため大きいが、DAC provider は単一 static スタックに
/// 1 個だけ常駐する(no_std で alloc も無い)ので Box 化せず値保持する。
#[allow(clippy::large_enum_variant)]
enum ShimDac {
    /// chip 開発用テスト DAC(`sm_config_t` に DAC 未指定時。後方互換)。
    Test(TestDacProvider<Backend>),
    /// C 供給の DAC/PAI/CD + 鍵(生鍵 or 署名コールバック)。
    Borrowed(BorrowedDacProvider<'static, ShimSigner>),
}

impl DacProvider for ShimDac {
    fn dac_der(&self) -> &[u8] {
        match self {
            Self::Test(d) => d.dac_der(),
            Self::Borrowed(d) => d.dac_der(),
        }
    }
    fn pai_der(&self) -> &[u8] {
        match self {
            Self::Test(d) => d.pai_der(),
            Self::Borrowed(d) => d.pai_der(),
        }
    }
    fn certification_declaration(&self) -> &[u8] {
        match self {
            Self::Test(d) => d.certification_declaration(),
            Self::Borrowed(d) => d.certification_declaration(),
        }
    }
    fn sign_with_dac(
        &self,
        msg: &[u8],
        out: &mut [u8; P256_SIGNATURE_LEN],
    ) -> simple_matter::error::Result<()> {
        match self {
            Self::Test(d) => d.sign_with_dac(msg, out),
            Self::Borrowed(d) => d.sign_with_dac(msg, out),
        }
    }
}

/// C 供給の DAC/PAI/CD DER を保持するストア(`Owned` が所有 → `&'static` で借用)。
const DAC_BLOB_CAP: usize = 1024;
#[derive(Default)]
struct DacStore {
    dac: heapless::Vec<u8, DAC_BLOB_CAP>,
    pai: heapless::Vec<u8, DAC_BLOB_CAP>,
    cd: heapless::Vec<u8, DAC_BLOB_CAP>,
}

impl DacStore {
    /// C 供給の DAC/PAI(+ 任意で CD)をコピーする。
    ///
    /// `dac_der` と `pai_der` が両方非 NULL のとき C 供給 DAC を使う。`cd_der` が NULL の
    /// ときは埋め込み dev CD([`dev_creds::DEV_CD_FOR_ALL_EXAMPLES`])で補う(factory NVS
    /// に CD が含まれない一般的な構成に対応。VID=0xFFF1/PID=0x8001 向け)。DAC/PAI が
    /// 揃わなければ dev DAC 扱い(空ストア)。
    ///
    /// # Safety
    /// `cfg` の各 DER ポインタは非 NULL のとき対応 `*_len` バイト有効であること。
    unsafe fn from_config(cfg: &sm_config_t) -> Result<Self, ()> {
        use simple_matter::dm::clusters::operational_credentials::dev_creds::DEV_CD_FOR_ALL_EXAMPLES;
        let mut s = Self::default();
        // DAC/PAI が揃っていなければ dev DAC 扱い(空ストア)。
        if cfg.dac_der.is_null() || cfg.pai_der.is_null() {
            return Ok(s);
        }
        let copy = |dst: &mut heapless::Vec<u8, DAC_BLOB_CAP>,
                    ptr: *const u8,
                    len: usize|
         -> Result<(), ()> {
            if len == 0 || len > DAC_BLOB_CAP {
                return Err(());
            }
            let src = core::slice::from_raw_parts(ptr, len);
            dst.extend_from_slice(src).map_err(|_| ())
        };
        copy(&mut s.dac, cfg.dac_der, cfg.dac_der_len)?;
        copy(&mut s.pai, cfg.pai_der, cfg.pai_der_len)?;
        if cfg.cd_der.is_null() {
            // factory に CD が無い → 埋め込み dev CD で補う。
            s.cd.extend_from_slice(&DEV_CD_FOR_ALL_EXAMPLES).map_err(|_| ())?;
        } else {
            copy(&mut s.cd, cfg.cd_der, cfg.cd_der_len)?;
        }
        Ok(s)
    }

    /// DAC/PAI が揃っているか(= C 供給 DAC を使うか)。
    fn is_supplied(&self) -> bool {
        !self.dac.is_empty() && !self.pai.is_empty()
    }
}

/// `sm_config_t` から [`ShimDac`] を組み立てる。
///
/// DER 3 本 + (生鍵 or 署名コールバック)が揃えば [`BorrowedDacProvider`]、
/// 揃わなければ dev テスト DAC(後方互換)。鍵復元失敗時は `None`。
fn build_shim_dac(o: &'static Owned, cfg: &sm_config_t, rng: CRng) -> Option<ShimDac> {
    let crypto = RustCrypto::new(rng);
    if o.dac_store.is_supplied() {
        // 署名バックエンド: dac_privkey(32B)優先、無ければ dac_sign コールバック。
        let signer = if !cfg.dac_privkey.is_null() {
            // SAFETY: dac_privkey は非 NULL のとき 32 バイト有効という契約。
            let raw = unsafe { core::slice::from_raw_parts(cfg.dac_privkey, 32) };
            let mut key = [0u8; 32];
            key.copy_from_slice(raw);
            ShimSigner::Keypair(crypto.p256_keypair_from_bytes(&key).ok()?)
        } else if cfg.dac_sign.is_some() {
            ShimSigner::Callback {
                cb: cfg.dac_sign,
                ctx: cfg.dac_sign_ctx,
            }
        } else {
            // DER はあるが鍵が無い → 誤設定。dev DAC にフォールバックせず失敗させる。
            return None;
        };
        let provider =
            BorrowedDacProvider::new(&o.dac_store.dac, &o.dac_store.pai, &o.dac_store.cd, signer);
        Some(ShimDac::Borrowed(provider))
    } else {
        Some(ShimDac::Test(TestDacProvider::new(&crypto).ok()?))
    }
}
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

/// プリセット NetworkCommissioning の種別(`docs/design/c-ffi-shim.md` §10.1)。
///
/// C 側が `sm_config_t` を 0 クリアすると `SM_NET_ETHERNET`(従来動作)になる(後方互換)。
/// WiFi / Thread は BLE コミッショニング前提のため、ble 無効ビルドでは種別によらず
/// Ethernet として動作する。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum sm_network_t {
    /// Ethernet(FeatureMap EN)。既定・後方互換。
    SM_NET_ETHERNET = 0,
    /// WiFi(FeatureMap WI)。`pairing ble-wifi`。ble 必須。
    SM_NET_WIFI = 1,
    /// Thread(FeatureMap TH)。`pairing ble-thread`。ble 必須。
    SM_NET_THREAD = 2,
}

/// 初期化設定(`docs/design/c-ffi-shim.md` §1)。
#[repr(C)]
pub struct sm_config_t {
    /// discriminator(12 ビット)。
    pub discriminator: u16,
    /// [非推奨・開発専用] PASE パスコード。**デバイスは passcode を保持してはならない**
    /// (Matter セキュリティ要件)。後方互換のため残すが、製品では `verifier_w0_l` /
    /// `verifier_salt` / `verifier_iterations` で SPAKE2+ verifier を直接渡すこと。
    /// verifier(`verifier_w0_l` 非 NULL かつ `verifier_iterations != 0`)が指定された場合、
    /// 本フィールドは無視される。
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
    /// プリセット NetworkCommissioning の種別(0 = SM_NET_ETHERNET = 従来動作。§10.1)。
    pub network: sm_network_t,
    /// SPAKE2+ verifier の iteration count。0 = 未指定(`passcode` からの導出にフォールバック)。
    /// verifier を使う場合は `verifier_w0_l` と併せて非 0 を設定する。
    pub verifier_iterations: u32,
    /// SPAKE2+ verifier の salt(16..=32 バイト)。NULL の場合は既定 dev salt を使う。
    pub verifier_salt: *const u8,
    /// `verifier_salt` の長さ(バイト)。
    pub verifier_salt_len: usize,
    /// SPAKE2+ verifier 本体 `w0 ‖ L`(97 バイト)。NULL のとき、または
    /// `verifier_iterations == 0` のときは `passcode` から導出する(開発専用フォールバック)。
    /// **推奨: 製品はここに verifier を渡し、passcode をデバイスに置かない**
    /// (`smctl pase-verifier <passcode>` で生成)。
    pub verifier_w0_l: *const u8,

    // --- 工場出荷 DAC 供給(未指定時は dev テスト DAC = 後方互換。§FD1)---
    /// DAC 証明書(X.509 DER)。`pai_der` / `cd_der` と、`dac_privkey` または
    /// `dac_sign` のいずれかが揃ったときに [`BorrowedDacProvider`] を使う。
    /// いずれかが欠ければ従来の dev テスト DAC(`TestDacProvider`)にフォールバック。
    pub dac_der: *const u8,
    /// `dac_der` の長さ(バイト、≤ 1024)。
    pub dac_der_len: usize,
    /// PAI 証明書(X.509 DER)。
    pub pai_der: *const u8,
    /// `pai_der` の長さ(バイト、≤ 1024)。
    pub pai_der_len: usize,
    /// Certification Declaration(CMS DER)。
    pub cd_der: *const u8,
    /// `cd_der` の長さ(バイト、≤ 1024)。
    pub cd_der_len: usize,
    /// DAC 生秘密鍵(P-256 スカラ 32 バイト、ビッグエンディアン)。NULL なら `dac_sign` を使う。
    pub dac_privkey: *const u8,
    /// DAC 署名コールバック(セキュアエレメント委譲)。`dac_privkey` が NULL のとき使う。
    pub dac_sign: SmDacSign,
    /// `dac_sign` の ctx。
    pub dac_sign_ctx: *mut c_void,
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
    /// BLE commissionable 広告の内容が変わった(`sm_ble_adv_data` を再取得して反映。§9.1)。
    SM_EV_BLE_ADV_CHANGED = 5,
    /// ConnectNetwork 受理で WiFi join 要求が立った(`sm_take_wifi_request` で取り出す。§9.1)。
    SM_EV_WIFI_CONNECT_REQUEST = 6,
    /// ConnectNetwork 受理で Thread attach 要求が立った(`sm_take_thread_dataset` で
    /// dataset TLV を取り出す。§10.1)。
    SM_EV_THREAD_ATTACH_REQUEST = 7,
}

/// BLE(BTP)イベント種別(`sm_ble_event` の引数、`docs/design/c-ffi-shim.md` §9.1)。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum sm_ble_event_kind_t {
    /// GATT 接続確立。`arg` = ATT MTU(不明なら 0 = 23 扱い)。
    SM_BLE_CONNECTED = 0,
    /// GATT 切断。
    SM_BLE_DISCONNECTED = 1,
    /// C1(0xFFF6 write)受信。`data`/`len` = 書き込まれた 1 BTP フラグメント。
    SM_BLE_C1_WRITE = 2,
    /// C2(indicate)CCCD subscribe 完了。以降 `sm_ble_poll` のフラグメントを送出可。
    SM_BLE_C2_SUBSCRIBED = 3,
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
    net: ShimNetComm,
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
    // ---- カスタムクラスタ(F4b、docs/design/c-ffi-shim.md §8)----
    /// C 登録のカスタムクラスタ(read/write/invoke を C vtable へ委譲)。
    custom_clusters: heapless::Vec<CustomCluster, { custom::MAX_CUSTOM_CLUSTERS }>,
    /// カスタムエンドポイント用に自動合成した Descriptor(0x001D)。
    custom_descs: heapless::Vec<DescriptorCluster, { custom::MAX_CUSTOM_ENDPOINTS }>,
    /// `custom_descs` と並行するエンドポイント ID。
    custom_ep_ids: heapless::Vec<u16, { custom::MAX_CUSTOM_ENDPOINTS }>,
    /// マージ後の全エンドポイントメタ([`DataModel::endpoints`] が返す)。
    endpoint_metas: heapless::Vec<EndpointMeta, MAX_EP_TOTAL>,
    /// 各エンドポイントのサーバクラスタ ID(`endpoint_metas` が `&'static` で借用する裏付け)。
    ep_servers: heapless::Vec<heapless::Vec<ClusterId, MAX_SERVERS>, MAX_EP_TOTAL>,
    /// 各エンドポイントのデバイスタイプ(同上)。
    ep_dts: heapless::Vec<heapless::Vec<DeviceType, 2>, MAX_EP_TOTAL>,
    /// EP0 の PartsList(EP1 + カスタムエンドポイント)。
    ep0_parts: heapless::Vec<EndpointId, MAX_EP_TOTAL>,
}

/// `heapless::Vec` の内容を指す `&'static` スライスを作る。
///
/// # Safety
/// `v` がシム static 内に固定(sm_init 後は移動・変更しない)であること。
unsafe fn static_slice<T, const N: usize>(v: &heapless::Vec<T, N>) -> &'static [T] {
    core::slice::from_raw_parts(v.as_ptr(), v.len())
}

impl DataModel for Light {
    fn endpoints(&self) -> &[EndpointMeta] {
        &self.endpoint_metas
    }
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        for m in &self.endpoint_metas {
            if m.id == ep {
                return m.clusters;
            }
        }
        &[]
    }
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x001F) => return Some(&self.access_control),
            (0, 0x0028) => return Some(&self.basic),
            (0, 0x0030) => return Some(&self.gc),
            (0, 0x0031) => return Some(&self.net),
            (0, 0x003C) => return Some(&self.admin),
            (0, 0x003E) => return Some(&self.opcreds),
            (0, 0x003F) => return Some(&self.gkm),
            (0, 0x001D) => return Some(&self.desc0),
            (1, 0x0003) => return Some(&self.identify),
            (1, 0x0004) => return Some(&self.groups_cl),
            (1, 0x0006) => return Some(&self.onoff),
            (1, 0x001D) => return Some(&self.desc1),
            _ => {}
        }
        // カスタムエンドポイントの合成 Descriptor。
        if cl.0 == 0x001D {
            if let Some(i) = self.custom_ep_ids.iter().position(|&cep| cep == ep.0) {
                return Some(&self.custom_descs[i]);
            }
        }
        // カスタムクラスタ。
        self.custom_clusters
            .iter()
            .find(|c| c.endpoint == ep.0 && c.cluster_id() == cl.0)
            .map(|c| c as &dyn ServerCluster)
    }
    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x001F) => return Some(&mut self.access_control),
            (0, 0x0028) => return Some(&mut self.basic),
            (0, 0x0030) => return Some(&mut self.gc),
            (0, 0x0031) => return Some(&mut self.net),
            (0, 0x003C) => return Some(&mut self.admin),
            (0, 0x003E) => return Some(&mut self.opcreds),
            (0, 0x003F) => return Some(&mut self.gkm),
            (0, 0x001D) => return Some(&mut self.desc0),
            (1, 0x0003) => return Some(&mut self.identify),
            (1, 0x0004) => return Some(&mut self.groups_cl),
            (1, 0x0006) => return Some(&mut self.onoff),
            (1, 0x001D) => return Some(&mut self.desc1),
            _ => {}
        }
        if cl.0 == 0x001D {
            if let Some(i) = self.custom_ep_ids.iter().position(|&cep| cep == ep.0) {
                return Some(&mut self.custom_descs[i]);
            }
        }
        self.custom_clusters
            .iter_mut()
            .find(|c| c.endpoint == ep.0 && c.cluster_id() == cl.0)
            .map(|c| c as &mut dyn ServerCluster)
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

impl Light {
    /// ステージング済みのカスタム登録を取り込み、マージ後のメタ(endpoints/server list/
    /// Descriptor)を合成する(F4b、`docs/design/c-ffi-shim.md` §8.2)。
    ///
    /// `self` は既にシム static 内の最終位置に居ること(自己参照 `&'static` スライスの前提)。
    /// カスタム登録が無くてもプリセット EP0/EP1 のメタを構築する(常に sm_init で 1 度呼ぶ)。
    fn install_custom(&mut self, pending: PendingRegistry) {
        self.custom_clusters = pending.clusters;

        // 1) エンドポイント集合(0/1 + カスタムクラスタの EP + 登録 EP)を昇順で確定。
        let mut ep_ids: heapless::Vec<u16, MAX_EP_TOTAL> = heapless::Vec::new();
        let _ = ep_ids.push(0);
        let _ = ep_ids.push(1);
        for c in &self.custom_clusters {
            if c.endpoint > 1 && !ep_ids.contains(&c.endpoint) {
                let _ = ep_ids.push(c.endpoint);
            }
        }
        for er in &pending.endpoints {
            if er.endpoint > 1 && !ep_ids.contains(&er.endpoint) {
                let _ = ep_ids.push(er.endpoint);
            }
        }
        ep_ids.sort_unstable();

        // 2) 各 EP のサーバリスト・デバイスタイプを裏付け Vec に構築。
        self.ep_servers.clear();
        self.ep_dts.clear();
        for &ep in ep_ids.iter() {
            let mut servers: heapless::Vec<ClusterId, MAX_SERVERS> = heapless::Vec::new();
            let mut dts: heapless::Vec<DeviceType, 2> = heapless::Vec::new();
            match ep {
                0 => {
                    for c in EP0_SERVERS {
                        let _ = servers.push(*c);
                    }
                    for d in EP0_DT {
                        let _ = dts.push(*d);
                    }
                }
                1 => {
                    for c in EP1_SERVERS {
                        let _ = servers.push(*c);
                    }
                    for d in EP1_DT {
                        let _ = dts.push(*d);
                    }
                }
                _ => {
                    // 新規エンドポイント: 登録デバイスタイプ + 合成 Descriptor(0x001D)。
                    if let Some(er) = pending.endpoints.iter().find(|e| e.endpoint == ep) {
                        let _ = dts.push(DeviceType::new(er.device_type, er.dt_revision));
                    }
                    let _ = servers.push(ClusterId(0x001D));
                }
            }
            for c in &self.custom_clusters {
                if c.endpoint == ep && !servers.iter().any(|s| s.0 == c.cluster_id()) {
                    let _ = servers.push(ClusterId(c.cluster_id()));
                }
            }
            let _ = self.ep_servers.push(servers);
            let _ = self.ep_dts.push(dts);
        }

        // 3) EP0 の PartsList = EP0 以外の全 EP。
        self.ep0_parts.clear();
        for &ep in ep_ids.iter() {
            if ep != 0 {
                let _ = self.ep0_parts.push(EndpointId(ep));
            }
        }

        // 4) カスタムクラスタの meta 自己参照を最終確定(以降 attr/cmd Vec は不変)。
        for c in self.custom_clusters.iter_mut() {
            // SAFETY: self はシム static 内の最終位置。attr_metas/cmd_metas は以降変更しない。
            unsafe { c.finalize() };
        }

        // 5) EndpointMeta と Descriptor を裏付け Vec の &'static スライスで合成。
        self.endpoint_metas.clear();
        self.custom_descs.clear();
        self.custom_ep_ids.clear();
        for (i, &ep) in ep_ids.iter().enumerate() {
            // SAFETY: ep_servers/ep_dts/ep0_parts はこれ以降変更しない(static スライス化)。
            let servers: &'static [ClusterId] = unsafe { static_slice(&self.ep_servers[i]) };
            let dts: &'static [DeviceType] = unsafe { static_slice(&self.ep_dts[i]) };
            let _ = self
                .endpoint_metas
                .push(EndpointMeta::new(EndpointId(ep), dts, servers));
            match ep {
                0 => {
                    let parts: &'static [EndpointId] = unsafe { static_slice(&self.ep0_parts) };
                    self.desc0 = DescriptorCluster::new(EndpointId(0), dts, servers, &[], parts);
                }
                1 => {
                    self.desc1 = DescriptorCluster::new(EndpointId(1), dts, servers, &[], &[]);
                }
                _ => {
                    let d = DescriptorCluster::new(EndpointId(ep), dts, servers, &[], &[]);
                    let _ = self.custom_descs.push(d);
                    let _ = self.custom_ep_ids.push(ep);
                }
            }
        }
    }

    /// C からの dirty 通知(`sm_attr_mark_dirty`)を該当カスタムクラスタへ橋渡しする。
    fn mark_custom_dirty(&mut self, ep: u16, cluster_id: u32, _attr_id: u32) {
        for c in self.custom_clusters.iter_mut() {
            if c.endpoint == ep && c.cluster_id() == cluster_id {
                c.mark_dirty();
                return;
            }
        }
    }
}

/// 外部所有(スタックが `&'static` で借用する)テーブル群。
struct Owned {
    crypto: Backend,
    fabrics: RefCell<FabricTable<Backend, NF>>,
    acl: RefCell<AclTable<NACL>>,
    window: RefCell<CommissioningWindow>,
    groups: RefCell<DefaultGroupStore>,
    /// C 供給の DAC/PAI/CD DER(`ShimDac::Borrowed` が `&'static` で借用)。
    dac_store: DacStore,
}

/// NetworkCommissioning クラスタを sm_config.network から作り分ける(§10.1)。
///
/// ble 無効ビルドは Ethernet 固定(WiFi/Thread は BLE コミッショニング前提のため)。
#[cfg(feature = "ble")]
fn new_netcomm(network: sm_network_t) -> ShimNetComm {
    match network {
        sm_network_t::SM_NET_WIFI => {
            ShimNetComm::Wifi(NetworkCommissioningWifi::with_driver(ShimWifiDriver::new()))
        }
        sm_network_t::SM_NET_THREAD => ShimNetComm::Thread(
            NetworkCommissioningThread::with_driver(ShimThreadDriver::new()),
        ),
        sm_network_t::SM_NET_ETHERNET => ShimNetComm::Ethernet(NetworkCommissioning::new(b"eth0")),
    }
}
#[cfg(not(feature = "ble"))]
fn new_netcomm(_network: sm_network_t) -> ShimNetComm {
    ShimNetComm::Ethernet(NetworkCommissioning::new(b"eth0"))
}

fn build_light(o: &'static Owned, rng: CRng, network: sm_network_t, dac: ShimDac) -> Light {
    Light {
        acl: &o.acl,
        access_control: AccessControlCluster::new(&o.acl),
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: new_netcomm(network),
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
        custom_clusters: heapless::Vec::new(),
        custom_descs: heapless::Vec::new(),
        custom_ep_ids: heapless::Vec::new(),
        endpoint_metas: heapless::Vec::new(),
        ep_servers: heapless::Vec::new(),
        ep_dts: heapless::Vec::new(),
        ep0_parts: heapless::Vec::new(),
    }
}

// ==========================================================================
// シム状態(単一 static インスタンス)
// ==========================================================================

struct Shim {
    owned: Owned,
    stack: Stack,
    mdns: MdnsResponder<NF>,
    /// C++ 側が一度でも `sm_mdns_rx`/`sm_mdns_poll` を呼んだか。呼ばれない構成
    /// (Thread = SRP 運用、mDNS ソケット無し)では mDNS announce 期限を
    /// `sm_next_deadline` に併合しない(過去期限が残り続けて pump が
    /// 0 タイムアウトでスピンする — NanoC6 実機 F6 で task_wdt 発火を実測)。
    mdns_used: bool,
    kvs: Option<CKvs>,
    mac: [u8; 6],
    instance_id: u64,
    vendor_id: u16,
    product_id: u16,
    discriminator: u16,
    /// デバイスが保持する PASE 資格情報(SPAKE2+ verifier のみ。passcode は保持しない)。
    /// コミッショニング窓の再オープン時に PaseConfig を再構築するために保持する。
    dev_pase: DevPase,
    ipv4: Option<[u8; 4]>,
    ipv6_ll: Option<[u8; 16]>,
    last_fabric_gen: u32,
    last_group_gen: u32,
    last_resumption_gen: u32,
    last_fabric_count: usize,
    last_on: bool,
    boot_window_open: bool,
    /// 現在 commissionable(BLE 広告すべき)なら Some(discriminator)、無ければ None。
    /// mDNS の set_commissionable と同じ場所で更新し、BLE 広告(§9.1)の生成元にする。
    commissionable_disc: Option<u16>,
    events: EventRing,
    // ---- BLE(BTP)給餌(F3、docs/design/c-ffi-shim.md §9)----
    /// BTP 状態機械(peripheral)。同時 1 接続。
    #[cfg(feature = "ble")]
    btp: Btp<BTP_WINDOW>,
    /// 現在の BLE 接続ハンドル(Matter は同時 1 本)。
    #[cfg(feature = "ble")]
    ble_conn: Option<BtpConnId>,
    /// 交渉済み ATT MTU(不明なら None)。
    #[cfg(feature = "ble")]
    ble_mtu: Option<u16>,
    /// C2 subscribe 済み(以降 indicate 可)。
    #[cfg(feature = "ble")]
    ble_subscribed: bool,
    /// 直近に生成した BLE 広告バイト列(内容変化検出用。None=広告停止)。
    #[cfg(feature = "ble")]
    ble_adv: Option<[u8; ADV_TOTAL_LEN]>,
    /// WiFi join 要求の SM_EV_WIFI_CONNECT_REQUEST を既に立てたか(多重発火抑止)。
    #[cfg(feature = "ble")]
    wifi_req_signaled: bool,
    /// Thread attach 要求の SM_EV_THREAD_ATTACH_REQUEST を既に立てたか(多重発火抑止)。
    #[cfg(feature = "ble")]
    thread_req_signaled: bool,
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
            self.commissionable_disc = Some(self.discriminator);
        } else {
            self.refresh_operational();
            self.commissionable_disc = None;
        }
        self.mdns.notify_change(now);
        self.sync_ble_adv(now);
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
                self.commissionable_disc = None;
                self.mdns.notify_change(now);
            } else if !self.boot_window_open && count == 0 && !self.owned.window.borrow().is_open() {
                self.boot_window_open = true;
                if let Some(cfg) = self.dev_pase.build() {
                    self.stack.set_pase_config(cfg);
                    self.stack.set_pase_enabled(true);
                }
                let ad = self.commissionable_ad(self.discriminator, CommissioningMode::Standard);
                self.mdns.set_commissionable(Some(ad));
                self.commissionable_disc = Some(self.discriminator);
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
                        self.commissionable_disc = Some(discriminator);
                        self.mdns.notify_change(now);
                        self.events.push(sm_event_kind_t::SM_EV_WINDOW_CHANGED, 1);
                    }
                }
                WindowEvent::OpenedBasic => {
                    if let Some(cfg) = self.dev_pase.build() {
                        self.stack.set_pase_config(cfg);
                        self.stack.set_pase_enabled(true);
                    }
                    let ad =
                        self.commissionable_ad(self.discriminator, CommissioningMode::Standard);
                    self.mdns.set_commissionable(Some(ad));
                    self.commissionable_disc = Some(self.discriminator);
                    self.mdns.notify_change(now);
                    self.events.push(sm_event_kind_t::SM_EV_WINDOW_CHANGED, 1);
                }
                WindowEvent::Closed => {
                    self.stack.set_pase_enabled(false);
                    self.mdns.set_commissionable(None);
                    self.commissionable_disc = None;
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

        // BLE(F3): WiFi ドライバ状態の属性反映・join 要求イベント・広告差分同期。
        self.housekeep_ble(now);
    }

    /// BLE 給餌に伴う定常処理(§9・§10)。ble 無効ビルドでは no-op。
    #[cfg(feature = "ble")]
    fn housekeep_ble(&mut self, now: u64) {
        // WiFi/Thread driver の join/attach 結果を NetworkCommissioning 属性へ反映
        // (遅延 ConnectNetworkResponse の裏付け)。
        self.stack.device_mut().net.update_from_driver();
        // 未取り出しの WiFi join 要求があれば 1 回だけ SM_EV_WIFI_CONNECT_REQUEST を立てる。
        let wifi_pending = self.stack.device().net.has_pending_wifi();
        if wifi_pending && !self.wifi_req_signaled {
            self.wifi_req_signaled = true;
            self.events
                .push(sm_event_kind_t::SM_EV_WIFI_CONNECT_REQUEST, 0);
        } else if !wifi_pending {
            self.wifi_req_signaled = false;
        }
        // 未取り出しの Thread attach 要求があれば 1 回だけ SM_EV_THREAD_ATTACH_REQUEST を立てる。
        let thread_pending = self.stack.device().net.has_pending_thread();
        if thread_pending && !self.thread_req_signaled {
            self.thread_req_signaled = true;
            self.events
                .push(sm_event_kind_t::SM_EV_THREAD_ATTACH_REQUEST, 0);
        } else if !thread_pending {
            self.thread_req_signaled = false;
        }
        // BLE 広告の差分同期(commissionable_disc は上で更新済み)。
        self.sync_ble_adv(now);
    }

    #[cfg(not(feature = "ble"))]
    #[inline]
    fn housekeep_ble(&mut self, _now: u64) {}

    /// `commissionable_disc` から BLE 広告バイト列を生成し、変化時に
    /// `SM_EV_BLE_ADV_CHANGED` を立てる(§9.1・§9.2)。ble 無効ビルドでは no-op。
    #[cfg(feature = "ble")]
    fn sync_ble_adv(&mut self, _now: u64) {
        let desired: Option<[u8; ADV_TOTAL_LEN]> = self.commissionable_disc.map(|disc| {
            let adv = AdvData {
                discriminator: disc,
                vendor_id: self.vendor_id,
                product_id: self.product_id,
                additional_data: false,
                ext_announcement: false,
            };
            let mut buf = [0u8; ADV_TOTAL_LEN];
            // encode_adv は ADV_TOTAL_LEN 固定長で失敗しない。
            let _ = adv.encode_adv(&mut buf);
            buf
        });
        if desired != self.ble_adv {
            self.ble_adv = desired;
            self.events.push(sm_event_kind_t::SM_EV_BLE_ADV_CHANGED, 0);
        }
    }

    #[cfg(not(feature = "ble"))]
    #[inline]
    fn sync_ble_adv(&mut self, _now: u64) {}
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

    // C 供給の DAC/PAI/CD DER を Owned にコピーする(未指定なら空 = dev DAC)。
    // SAFETY: cfg の DER ポインタは非 NULL のとき len バイト有効という契約。
    let dac_store = match unsafe { DacStore::from_config(cfg) } {
        Ok(s) => s,
        Err(()) => return -5, // DER が容量超過 / 長さ不整合。
    };

    let owned = Owned {
        crypto: RustCrypto::new(rng),
        fabrics: RefCell::new(FabricTable::new()),
        acl: RefCell::new(AclTable::new()),
        window: RefCell::new(CommissioningWindow::new()),
        groups: RefCell::new(DefaultGroupStore::new()),
        dac_store,
    };

    // SAFETY: 単一インスタンスを in-place 構築する。SHIM は static(不動)なので
    // owned フィールドへの &'static 参照は健全(自己参照はプログラム全生存期間有効)。
    unsafe {
        let sp = SHIM.0.get() as *mut Shim;
        addr_of_mut!((*sp).owned).write(owned);
        let o: &'static Owned = &*addr_of!((*sp).owned);

        // デバイス側 PASE 資格情報(SPAKE2+ verifier のみ。passcode は保持しない)。
        let dev_pase = match DevPase::from_config(cfg) {
            Some(d) => d,
            None => return -4,
        };
        let config = match dev_pase.build() {
            Some(c) => c,
            None => return -4,
        };
        let creds = SharedFabricCreds::new(&o.fabrics, &o.crypto, 0);
        let sc = SecureChannel::new(&o.crypto, rng, config, creds);
        // DAC provider: C 供給の DER/鍵があれば BorrowedDacProvider、無ければ dev DAC。
        let dac = match build_shim_dac(o, cfg, rng) {
            Some(d) => d,
            None => return -6, // 鍵復元失敗。
        };
        let im = InteractionModel::new(build_light(o, rng, cfg.network, dac));
        let mut stack: Stack = MatterStack::new(&o.crypto, sc, im);
        stack.set_group_keys(&o.groups);
        let _ = stack.post_startup_event(CFG.software_version, 0);

        addr_of_mut!((*sp).stack).write(stack);
        // Host は sm_set_addrs 前は A/AAAA 無し(--at ユニキャストで解決可)。
        let host = Host::from_mac(&cfg.mac, None, None);
        addr_of_mut!((*sp).mdns).write(MdnsResponder::new(host, MATTER_PORT));
        addr_of_mut!((*sp).mdns_used).write(false);
        addr_of_mut!((*sp).kvs).write(kvs);
        addr_of_mut!((*sp).mac).write(cfg.mac);
        addr_of_mut!((*sp).instance_id).write(instance_id);
        addr_of_mut!((*sp).vendor_id).write(cfg.vendor_id);
        addr_of_mut!((*sp).product_id).write(cfg.product_id);
        addr_of_mut!((*sp).discriminator).write(cfg.discriminator & 0x0FFF);
        addr_of_mut!((*sp).dev_pase).write(dev_pase);
        addr_of_mut!((*sp).ipv4).write(None);
        addr_of_mut!((*sp).ipv6_ll).write(None);
        addr_of_mut!((*sp).last_fabric_gen).write(0);
        addr_of_mut!((*sp).last_group_gen).write(0);
        addr_of_mut!((*sp).last_resumption_gen).write(0);
        addr_of_mut!((*sp).last_fabric_count).write(0);
        addr_of_mut!((*sp).last_on).write(false);
        addr_of_mut!((*sp).boot_window_open).write(true);
        addr_of_mut!((*sp).commissionable_disc).write(None);
        addr_of_mut!((*sp).events).write(EventRing::new());
        #[cfg(feature = "ble")]
        {
            addr_of_mut!((*sp).btp).write(Btp::new(BtpRole::Peripheral));
            addr_of_mut!((*sp).ble_conn).write(None);
            addr_of_mut!((*sp).ble_mtu).write(None);
            addr_of_mut!((*sp).ble_subscribed).write(false);
            addr_of_mut!((*sp).ble_adv).write(None);
            addr_of_mut!((*sp).wifi_req_signaled).write(false);
            addr_of_mut!((*sp).thread_req_signaled).write(false);
        }

        // カスタム登録(sm_init 前にステージング)を最終位置の Light へ取り込む(F4b、§8)。
        let pending = custom::take_pending();
        (*sp).stack.device_mut().install_custom(pending);

        INITED.store(true, Ordering::SeqCst);
        (*sp).restore_and_advertise(now_ms);
        // 初期広告の SM_EV_BLE_ADV_CHANGED は抑止(C++ は sm_init 後に sm_ble_adv_data で
        // 広告をブートストラップする)。以降の変化のみイベント化する。§9.1。
        (*sp).events = EventRing::new();
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
    // BLE 宛の SendDirective は BTP に載せ(送出は sm_ble_poll が担う)、UDP 宛のみ返す。
    // BLE 宛を返してしまうと C++ が UDP として送ってしまうため、ここで振り分ける(§9.2)。
    loop {
        match s.stack.poll(now_ms, tx) {
            Some(d) => match route_directive(s, &d, tx) {
                Some(len) => {
                    if !tx_dst.is_null() {
                        unsafe { *tx_dst = peer_to_addr(d.addr) };
                    }
                    return len;
                }
                None => continue, // BLE 宛は BTP に載せた。次の directive を引く。
            },
            None => return 0,
        }
    }
}

/// SendDirective の宛先で振り分ける。UDP なら `Some(len)`(そのまま返す)、BLE なら
/// BTP に載せて `None`(sm_ble_poll が排出する)。ble 無効時は常に UDP 扱い。
#[cfg(feature = "ble")]
fn route_directive(s: &mut Shim, d: &simple_matter::stack::SendDirective, tx: &[u8]) -> Option<usize> {
    match d.addr {
        PeerAddr::Ble(_) => {
            let _ = s.btp.send(&tx[..d.len], 0);
            None
        }
        PeerAddr::Udp(_) => Some(d.len),
    }
}
#[cfg(not(feature = "ble"))]
#[inline]
fn route_directive(_s: &mut Shim, d: &simple_matter::stack::SendDirective, _tx: &[u8]) -> Option<usize> {
    Some(d.len)
}

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切るため。§9)。
#[cfg(feature = "ble")]
fn take_sdu(btp: &mut Btp<BTP_WINDOW>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
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
    // mDNS announce 期限は C++ 側が mDNS を実際に駆動している場合のみ併合する
    // (Thread 構成 = SRP 運用では sm_mdns_* が呼ばれず、期限が過去に固定されて
    // pump の select が 0 タイムアウトでスピンする。Shim::mdns_used 参照)。
    let mdns_dl = if s.mdns_used {
        s.mdns.next_announce_deadline()
    } else {
        NO_DEADLINE
    };
    let dl = stack_dl.min(mdns_dl);
    // BTP の ACK / keep-alive / liveness 期限も併合する(§9.2)。
    #[cfg(feature = "ble")]
    let dl = match s.btp.next_deadline() {
        Some(btp_dl) => dl.min(btp_dl),
        None => dl,
    };
    dl
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
    s.mdns_used = true;
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
    s.mdns_used = true;
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
// カスタムクラスタ C vtable(F4b、docs/design/c-ffi-shim.md §8)
// ==========================================================================

/// カスタムクラスタを登録する(sm_init より前。0=OK、負値=失敗)。
///
/// `def`/`attrs`/`cmds` の内容はここでコピーするため、呼び出し後は解放してよい
/// (コールバックポインタ・ctx は保持されるので有効に保つこと)。sm_init 済みは `-2`。
#[no_mangle]
pub extern "C" fn sm_cluster_register(def: *const sm_cluster_def_t) -> i32 {
    if INITED.load(Ordering::SeqCst) {
        return -2; // sm_init 後の登録は SM_ERR。
    }
    if def.is_null() {
        return -1;
    }
    // SAFETY: caller が有効な sm_cluster_def_t を与える契約。
    let def = unsafe { &*def };
    // SAFETY: attrs/cmds は n_attrs/n_cmds 要素を指す契約(from_def 内で検証)。
    let cluster = match unsafe { CustomCluster::from_def(def) } {
        Ok(c) => c,
        Err(()) => return -3, // 容量超過 or 不正なポインタ。
    };
    // SAFETY: 単線契約・sm_init 前のステージング。
    let p = unsafe { custom::pending() };
    if p.clusters.push(cluster).is_err() {
        return -4; // カスタムクラスタ数上限。
    }
    0
}

/// 新規エンドポイント(2..)にデバイスタイプを付与して登録する(sm_init より前)。
///
/// プリセット EP0/EP1(0/1)は登録不可(`-5`)。sm_init 済みは `-2`。
#[no_mangle]
pub extern "C" fn sm_endpoint_register(endpoint: u16, device_type: u32, dt_revision: u8) -> i32 {
    if INITED.load(Ordering::SeqCst) {
        return -2;
    }
    if endpoint <= 1 {
        return -5; // プリセットエンドポイントは予約。
    }
    // SAFETY: 単線契約・sm_init 前。
    let p = unsafe { custom::pending() };
    if p.endpoints
        .push(custom::EndpointReg {
            endpoint,
            device_type,
            dt_revision: dt_revision as u16,
        })
        .is_err()
    {
        return -4; // エンドポイント数上限。
    }
    0
}

/// C 側の値変化を購読レポートへ橋渡しする(該当カスタムクラスタを dirty にする)。
#[no_mangle]
pub extern "C" fn sm_attr_mark_dirty(endpoint: u16, cluster_id: u32, attr_id: u32) {
    if !INITED.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    s.stack
        .device_mut()
        .mark_custom_dirty(endpoint, cluster_id, attr_id);
}

// ==========================================================================
// BLE(BTP)給餌 + WiFi プロビジョン(F3、docs/design/c-ffi-shim.md §9)
//
// ヘッダは常時宣言し、ble 無効ビルドでは SM_ERR(-1)/ 0 を返す(後方互換。§9.2)。
// ==========================================================================

/// BLE(BTP)イベントをシムへ給餌する(§9.1)。0=OK、負値=エラー。
///
/// - `SM_BLE_CONNECTED`(`arg`=ATT MTU、0=不明): 2 本目の接続は `-2`(C++ は切断すべき)。
/// - `SM_BLE_C1_WRITE`(`data`/`len`=1 上りフラグメント): BTP に投入し、再組立できた
///   Matter メッセージを処理して応答を BTP に積む(送出は `sm_ble_poll`)。
/// - `SM_BLE_C2_SUBSCRIBED` / `SM_BLE_DISCONNECTED`: セッション状態を更新。
///
/// ble 無効ビルドは常に `-1`。
#[no_mangle]
pub extern "C" fn sm_ble_event(
    kind: sm_ble_event_kind_t,
    arg: u16,
    data: *const u8,
    len: usize,
    now_ms: u64,
) -> i32 {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (kind, arg, data, len, now_ms);
        -1
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) {
            return -1;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        match kind {
            sm_ble_event_kind_t::SM_BLE_CONNECTED => {
                if s.ble_conn.is_some() {
                    return -2; // 同時 1 接続(§9.2)。C++ は 2 本目を切断する。
                }
                s.ble_conn = Some(BtpConnId(0));
                s.ble_mtu = if arg == 0 { None } else { Some(arg) };
                s.ble_subscribed = false;
                s.btp.reset();
                0
            }
            sm_ble_event_kind_t::SM_BLE_DISCONNECTED => {
                s.ble_conn = None;
                s.ble_subscribed = false;
                s.btp.reset();
                0
            }
            sm_ble_event_kind_t::SM_BLE_C2_SUBSCRIBED => {
                s.ble_subscribed = true;
                0
            }
            sm_ble_event_kind_t::SM_BLE_C1_WRITE => {
                if data.is_null() {
                    return -1;
                }
                let Some(conn) = s.ble_conn else {
                    return -1;
                };
                // SAFETY: caller が有効な data/len を与える契約。
                let frag = unsafe { core::slice::from_raw_parts(data, len) };
                if s.btp.process_incoming(frag, s.ble_mtu, now_ms).is_err() {
                    return -3;
                }
                // 再組立できた Matter メッセージを stack へ渡し、応答を BTP に積む。
                let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
                let mut txd = [0u8; MAX_RX_PACKET_SIZE];
                // take_sdu は s.btp の借用を都度切る(次行で s.stack を可変借用するため)。
                while let Some(slen) = take_sdu(&mut s.btp, &mut sdu) {
                    let dir =
                        s.stack
                            .handle_rx(&mut sdu[..slen], PeerAddr::Ble(conn), now_ms, &mut txd);
                    if let Some(d) = dir {
                        // BLE rx への応答は BLE 宛。BTP に載せる(UDP 宛はここでは起きない)。
                        if matches!(d.addr, PeerAddr::Ble(_)) {
                            let _ = s.btp.send(&txd[..d.len], now_ms);
                        }
                    }
                }
                s.housekeep(now_ms);
                0
            }
        }
    }
}

/// C2 indication で送るべき次の BTP フラグメントを取り出す(§9.1)。0 = なし。
///
/// subscribe 完了前・未接続は 0(handshake 応答も subscribe 後に排出する)。BTP の
/// 再送・keep-alive ACK もここから産まれる(`sm_next_deadline` が BTP 期限を併合する)。
/// ble 無効ビルドは常に 0。
#[no_mangle]
pub extern "C" fn sm_ble_poll(now_ms: u64, frag_out: *mut u8, cap: usize) -> usize {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (now_ms, frag_out, cap);
        0
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) || frag_out.is_null() {
            return 0;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        if s.ble_conn.is_none() || !s.ble_subscribed {
            return 0;
        }
        let out = unsafe { core::slice::from_raw_parts_mut(frag_out, cap) };
        s.btp.process_outgoing(out, s.ble_mtu, now_ms).unwrap_or(0)
    }
}

/// commissionable 広告(Flags AD + Service Data 0xFFF6、計 15 バイト)を `out` に書く(§9.1)。
///
/// 戻り値 = 書いた長さ。0 = 広告を停止すべき状態(fabric あり・窓閉)。内容が変わると
/// `SM_EV_BLE_ADV_CHANGED` が立つので、C++ はそれを受けて本 API を再取得し NimBLE に反映する。
/// ble 無効ビルドは常に 0。
#[no_mangle]
pub extern "C" fn sm_ble_adv_data(out: *mut u8, cap: usize) -> usize {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (out, cap);
        0
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) || out.is_null() {
            return 0;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        match s.ble_adv {
            Some(adv) if cap >= adv.len() => {
                let dst = unsafe { core::slice::from_raw_parts_mut(out, adv.len()) };
                dst.copy_from_slice(&adv);
                adv.len()
            }
            _ => 0,
        }
    }
}

/// ConnectNetwork で受理した WiFi join 要求(SSID/資格情報)を取り出す(§9.1)。
///
/// 戻り値 = SSID バイト長(0 = 保留要求なし)。`pass_len` に資格情報長を返す。
/// `SM_EV_WIFI_CONNECT_REQUEST` を受けて呼ぶ。取り出したら C++ が esp_wifi で join し、
/// 結果を [`sm_wifi_status`] で報告する。ble 無効ビルドは常に 0。
#[no_mangle]
pub extern "C" fn sm_take_wifi_request(
    ssid_out: *mut u8,
    ssid_cap: usize,
    pass_out: *mut u8,
    pass_cap: usize,
    pass_len: *mut usize,
) -> usize {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (ssid_out, ssid_cap, pass_out, pass_cap, pass_len);
        0
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) || ssid_out.is_null() || pass_out.is_null() {
            return 0;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        let Some(driver) = s.stack.device_mut().net.wifi_driver_mut() else {
            return 0; // WiFi 構成でない(Ethernet/Thread)。
        };
        let Some((ssid, creds)) = driver.take_request() else {
            return 0;
        };
        let sn = ssid.len().min(ssid_cap);
        // SAFETY: caller が ssid_cap バイトの ssid_out を与える契約。
        unsafe { core::ptr::copy_nonoverlapping(ssid.as_ptr(), ssid_out, sn) };
        let pn = creds.len().min(pass_cap);
        // SAFETY: 同上(pass_out / pass_cap)。
        unsafe { core::ptr::copy_nonoverlapping(creds.as_ptr(), pass_out, pn) };
        if !pass_len.is_null() {
            unsafe { *pass_len = pn };
        }
        sn
    }
}

/// WiFi join 結果を報告する(§9.1)。遅延 ConnectNetworkResponse がこれで確定する。
///
/// `connected`=true で Connected、false で Failed。次の `sm_poll`/`sm_ble_poll` サイクルで
/// コアが遅延 ConnectNetworkResponse を BTP に積む。ble 無効ビルドは no-op。
#[no_mangle]
pub extern "C" fn sm_wifi_status(connected: bool, now_ms: u64) {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (connected, now_ms);
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) {
            return;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        if let Some(driver) = s.stack.device_mut().net.wifi_driver_mut() {
            driver.set_status(connected);
        }
        s.housekeep(now_ms);
    }
}

// ==========================================================================
// Thread プロビジョン(F6、docs/design/c-ffi-shim.md §10)
//
// WiFi の take 方式(§9)の鏡像。ヘッダは常時宣言し、ble 無効ビルド / Thread 以外の
// 構成では 0 / no-op を返す(後方互換)。
// ==========================================================================

/// ConnectNetwork で受理した Thread attach 要求の dataset TLV を取り出す(§10.1)。
///
/// 戻り値 = dataset TLV バイト長(0 = 保留要求なし / Thread 構成でない / ble 無効)。
/// `SM_EV_THREAD_ATTACH_REQUEST` を受けて呼ぶ。取り出したら C++ が esp_openthread へ
/// `otDatasetSetActiveTlvs` で投入し Thread start → attach を開始し、結果を
/// [`sm_thread_status`] で報告する。
#[no_mangle]
pub extern "C" fn sm_take_thread_dataset(tlv_out: *mut u8, cap: usize) -> usize {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (tlv_out, cap);
        0
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) || tlv_out.is_null() {
            return 0;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        let Some(driver) = s.stack.device_mut().net.thread_driver_mut() else {
            return 0; // Thread 構成でない(Ethernet/WiFi)。
        };
        let Some(ds) = driver.take_dataset() else {
            return 0;
        };
        let n = ds.len().min(cap);
        // SAFETY: caller が cap バイトの tlv_out を与える契約。
        unsafe { core::ptr::copy_nonoverlapping(ds.as_ptr(), tlv_out, n) };
        n
    }
}

/// Thread attach 結果を報告する(§10.1)。遅延 ConnectNetworkResponse がこれで確定する。
///
/// `attached`=true で Attached、false で Failed。次の `sm_poll`/`sm_ble_poll` サイクルで
/// コアが遅延 ConnectNetworkResponse を BTP に積む。Thread 構成でない / ble 無効は no-op。
#[no_mangle]
pub extern "C" fn sm_thread_status(attached: bool, now_ms: u64) {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (attached, now_ms);
    }
    #[cfg(feature = "ble")]
    {
        if !INITED.load(Ordering::SeqCst) {
            return;
        }
        // SAFETY: 単線契約。
        let s = unsafe { shim() };
        if let Some(driver) = s.stack.device_mut().net.thread_driver_mut() {
            driver.set_status(attached);
        }
        s.housekeep(now_ms);
    }
}

/// `u64` を大文字 16 進 16 桁で `out`(長さ 16)へ書く。
fn write_hex16_upper(out: &mut [u8], v: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, b) in out.iter_mut().enumerate().take(16) {
        let nib = (v >> (4 * (15 - i))) & 0xF;
        *b = HEX[nib as usize];
    }
}

/// SRP の運用インスタンス名素材 `<compressedFabricId>-<nodeId>`(各 16 進大文字 16 桁)を
/// `buf` へ NUL 終端で書く(`docs/design/c-ffi-shim.md` §10.1)。
///
/// 戻り値 = NUL を除く名前長(33)。fabric 未確定 / `cap` 不足(< 34)は 0。fabric 複数時は
/// 最初の 1 つを使う(制約: マルチ fabric では代表 1 つのみ。§10.1)。
#[no_mangle]
pub extern "C" fn sm_operational_instance_name(buf: *mut u8, cap: usize) -> usize {
    if !INITED.load(Ordering::SeqCst) || buf.is_null() {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { shim() };
    let fb = s.owned.fabrics.borrow();
    let Some(f) = fb.iter().next() else {
        return 0; // fabric 未確定(コミッショニング前)。
    };
    // "<16 hex>-<16 hex>" = 33 バイト + NUL = 34。
    let mut name = [0u8; 33];
    write_hex16_upper(&mut name[0..16], f.compressed_fabric_id());
    name[16] = b'-';
    write_hex16_upper(&mut name[17..33], f.node_id());
    if cap < name.len() + 1 {
        return 0; // NUL 終端の余地がない。
    }
    // SAFETY: cap >= 34 を確認済み。NUL 終端して C 文字列にする。
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), buf, name.len());
        *buf.add(name.len()) = 0;
    }
    name.len()
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
