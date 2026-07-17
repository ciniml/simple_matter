//! bloat-check 共有コア(`no_std`):On/Off ライトのデバイス構成と、コンポーネント別の
//! `core::mem::size_of` 計測ロジック。
//!
//! ここは `no_std` のライブラリで、std の `ram-report` バイナリと `no_std`/`no_main` の
//! `flash-probe` バイナリの双方から使う。デバイス定義は `crates/simple-matter/examples/onoff-light.rs`
//! の `Light` を、プロファイル(fabric 数 `NF`)に対して汎用化して持つ。
//!
//! 計測方式(rs-matter の `bloat-check` に倣う):
//! - RAM: 実 MCU では `.bss` に載る構造体群を `size_of` で足し上げる(型サイズ計測)。
//! - flash: MCU 向けにスタック一式をリンクする最小 `no_std` バイナリを作り、セクション
//!   (.text/.rodata/.data/.bss)を `size` で読む(`flash-probe` 側)。

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::cell::RefCell;
use core::mem::size_of;

use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::Rng;
use simple_matter::discovery::MdnsResponder;
use simple_matter::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, GeneralCommissioning,
    IcdManagementCluster, NetworkCommissioning, OnOffCluster, OpCredsCluster, TestDacProvider,
};
use simple_matter::dm::meta::{ClusterId, DeviceType, EndpointId, EndpointMeta};
use simple_matter::dm::{DataModel, ServerCluster};
use simple_matter::exchange::{ExchangeManager, ProtocolMux};
use simple_matter::fabric::FabricTable;
use simple_matter::im::engine::InteractionModel;
use simple_matter::sc::SecureChannel;
use simple_matter::stack::{MatterStack, SharedFabricCreds};

/// スタックが 1 パケットで扱う TX バッファ長(`simple_matter::stack::MAX_PACKET_SIZE`)。
pub use simple_matter::stack::MAX_PACKET_SIZE;

// --- 暗号バックエンドと乱数 ---------------------------------------------------

/// デモ用の擬似乱数(LCG)。**暗号学的に安全ではない**。計測ではスタックが
/// リンク・構築できればよいので、依存を増やさない最小の乱数源にとどめる。
#[derive(Clone, Copy)]
pub struct DemoRng(u64);

impl DemoRng {
    /// 固定シードで生成する(計測用途、再現性重視)。
    pub const fn new(seed: u64) -> Self {
        Self(seed | 1)
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

/// 暗号バックエンド(RustCrypto)。
pub type Backend = RustCrypto<DemoRng>;
/// テスト DAC プロバイダ。
pub type Dac = TestDacProvider<Backend>;
/// 共有 fabric テーブル参照つき OpCreds クラスタ。
pub type OpCreds<'s, const NF: usize> =
    OpCredsCluster<Backend, Dac, NF, &'s RefCell<FabricTable<Backend, NF>>>;

// --- デバイス構成(On/Off ライト。examples/onoff-light.rs の Light を NF で汎用化)----

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
    ClusterId(0x0046),
    ClusterId(0x001D),
];
static EP1_SERVERS: &[ClusterId] = &[ClusterId(0x0006), ClusterId(0x001D)];
static EP0_DT: &[DeviceType] = &[DeviceType::new(0x0016, 1)];
static EP1_DT: &[DeviceType] = &[DeviceType::new(0x0100, 3)];
static EP0_PARTS: &[EndpointId] = &[EndpointId(1)];
static EP1_PARTS: &[EndpointId] = &[];

/// On/Off ライトのデータモデル(fabric 数 `NF` で汎用化)。
pub struct Light<'s, const NF: usize> {
    /// Basic Information クラスタ。
    pub basic: BasicInformationCluster,
    /// General Commissioning クラスタ。
    pub gc: GeneralCommissioning,
    /// Network Commissioning クラスタ。
    pub net: NetworkCommissioning,
    /// Operational Credentials クラスタ(共有 fabric テーブル参照)。
    pub opcreds: OpCreds<'s, NF>,
    /// ICD Management クラスタ(SIT 最小)。
    pub icd: IcdManagementCluster,
    /// EP0 の Descriptor クラスタ。
    pub desc0: DescriptorCluster,
    /// EP1 の On/Off クラスタ。
    pub onoff: OnOffCluster,
    /// EP1 の Descriptor クラスタ。
    pub desc1: DescriptorCluster,
    /// fail-safe タイマ経過で削除した fabric index の退避先(stack が take する)。
    pub removed_fabric: Option<core::num::NonZeroU8>,
}

impl<const NF: usize> DataModel for Light<'_, NF> {
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
            (0, 0x0046) => Some(&self.icd),
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
            (0, 0x0046) => Some(&mut self.icd),
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

/// 共有 fabric テーブルを参照する On/Off ライトを構築する(`flash-probe` 用)。
pub fn build_light<const NF: usize>(fabrics: &RefCell<FabricTable<Backend, NF>>) -> Light<'_, NF> {
    let dac_crypto = RustCrypto::new(DemoRng::new(1));
    let dac = match TestDacProvider::new(&dac_crypto) {
        Ok(d) => d,
        // 計測用途:テスト DAC の構築失敗は起こらない前提だが、no_std で Debug を要求
        // しないよう match で潰す(失敗時は panic)。
        Err(_) => panic!("test DAC construction failed"),
    };
    Light {
        basic: BasicInformationCluster::new(&CFG),
        gc: GeneralCommissioning::default_config(),
        net: NetworkCommissioning::new(b"eth0"),
        opcreds: OpCredsCluster::new_shared(fabrics, RustCrypto::new(DemoRng::new(2)), dac),
        icd: IcdManagementCluster::new(),
        desc0: DescriptorCluster::new(EndpointId(0), EP0_DT, EP0_SERVERS, &[], EP0_PARTS),
        onoff: OnOffCluster::new(),
        desc1: DescriptorCluster::new(EndpointId(1), EP1_DT, EP1_SERVERS, &[], EP1_PARTS),
        removed_fabric: None,
    }
}

/// PASE コンフィグ(コミッショニング窓)を構築する(`flash-probe` 用)。
///
/// デバイスは passcode を保持せず verifier のみを持つ(Matter セキュリティ要件)。
/// footprint 計測も実機同様に dev verifier 定数([`simple_matter::dev_pase`])から作る。
pub fn pase_config() -> simple_matter::sc::PaseConfig {
    simple_matter::dev_pase::dev_pase_config()
}

// --- コンポーネント別 RAM(size_of)計測 -------------------------------------

/// 1 コンポーネントの計測結果(名前とバイト数、集計上の扱い)。
#[derive(Clone, Copy)]
pub struct Row {
    /// コンポーネント名。
    pub name: &'static str,
    /// `size_of` のバイト数。
    pub bytes: usize,
    /// 集計区分(表示用)。
    pub kind: Kind,
}

/// 行の集計区分。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `MatterStack` を構成するフィールド(合計すると `MatterStack` になる)。
    StackField,
    /// `MatterStack` 合計(検算用)。
    StackTotal,
    /// `ExchangeManager` 内に含まれる内訳(二重計上しないよう情報表示のみ)。
    Nested,
    /// スタック外で別途所有する状態(デバイス RAM 合計に加算する)。
    External,
}

const N_ROWS: usize = 19;

/// 指定プロファイル(const generic のサイジング)についてコンポーネント別 `size_of` を集める。
///
/// 返す配列は「`MatterStack` フィールド → `MatterStack` 合計 → 内訳(nested) →
/// スタック外(external)」の順。`ram-report` バイナリが表形式で出力する。
pub fn component_sizes<
    const NF: usize,
    const SESSIONS: usize,
    const EXCHANGES: usize,
    const TX_BUFS: usize,
    const HANDSHAKES: usize,
    const READS: usize,
    const SUBS: usize,
    const PATHS: usize,
>() -> [Row; N_ROWS] {
    use simple_matter::transport::session::SessionManager;

    // スタック内部の合成型(stack.rs の private エイリアス Sc/Mux を pub 型だけで再構成)。
    type Sc<'s, const NF: usize, const H: usize> =
        SecureChannel<'s, Backend, DemoRng, SharedFabricCreds<'s, Backend, NF>, H>;
    type Mux<
        's,
        const NF: usize,
        const H: usize,
        const READS: usize,
        const SUBS: usize,
        const PATHS: usize,
    > = ProtocolMux<Sc<'s, NF, H>, InteractionModel<Light<'s, NF>, READS, SUBS, PATHS>>;

    let sc = size_of::<Sc<'static, NF, HANDSHAKES>>();
    let im = size_of::<InteractionModel<Light<'static, NF>, READS, SUBS, PATHS>>();
    let mgr =
        size_of::<ExchangeManager<Mux<'static, NF, HANDSHAKES, READS, SUBS, PATHS>, EXCHANGES>>();
    let sessions = size_of::<SessionManager<SESSIONS>>();
    let buf = size_of::<simple_matter::buf::BufferPool<TX_BUFS, MAX_PACKET_SIZE>>();
    let resp = MAX_PACKET_SIZE; // resp: [u8; MAX_PACKET_SIZE]
    let crypto_ref = size_of::<&Backend>();
    let stack_total = size_of::<
        MatterStack<
            'static,
            Backend,
            DemoRng,
            Light<'static, NF>,
            NF,
            SESSIONS,
            EXCHANGES,
            TX_BUFS,
            HANDSHAKES,
            READS,
            SUBS,
            PATHS,
        >,
    >();

    [
        Row {
            name: "crypto &ref",
            bytes: crypto_ref,
            kind: Kind::StackField,
        },
        Row {
            name: "SessionManager",
            bytes: sessions,
            kind: Kind::StackField,
        },
        Row {
            name: "ExchangeManager(mgr)",
            bytes: mgr,
            kind: Kind::StackField,
        },
        Row {
            name: "BufferPool(TX)",
            bytes: buf,
            kind: Kind::StackField,
        },
        Row {
            name: "resp buffer",
            bytes: resp,
            kind: Kind::StackField,
        },
        Row {
            name: "= MatterStack total",
            bytes: stack_total,
            kind: Kind::StackTotal,
        },
        // ExchangeManager(mgr) の内訳(二重計上しない情報表示)。
        Row {
            name: "  SecureChannel(handshake pool)",
            bytes: sc,
            kind: Kind::Nested,
        },
        Row {
            name: "  InteractionModel",
            bytes: im,
            kind: Kind::Nested,
        },
        Row {
            name: "    BasicInformation",
            bytes: size_of::<BasicInformationCluster>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    GeneralCommissioning",
            bytes: size_of::<GeneralCommissioning>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    NetworkCommissioning",
            bytes: size_of::<NetworkCommissioning>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    OpCreds",
            bytes: size_of::<OpCreds<'static, NF>>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    IcdManagement",
            bytes: size_of::<IcdManagementCluster>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    Descriptor",
            bytes: size_of::<DescriptorCluster>(),
            kind: Kind::Nested,
        },
        Row {
            name: "    OnOff",
            bytes: size_of::<OnOffCluster>(),
            kind: Kind::Nested,
        },
        // スタック外で別途所有する状態(デバイス RAM 合計に加算)。
        Row {
            name: "FabricTable(external)",
            bytes: size_of::<FabricTable<Backend, NF>>(),
            kind: Kind::External,
        },
        Row {
            name: "RustCrypto backend(external)",
            bytes: size_of::<Backend>(),
            kind: Kind::External,
        },
        Row {
            name: "MdnsResponder(external)",
            bytes: size_of::<MdnsResponder<NF>>(),
            kind: Kind::External,
        },
        Row {
            name: "rx/tx scratch(external)",
            bytes: MAX_RX_PACKET_SIZE_2,
            kind: Kind::External,
        },
    ]
}

/// example の rx/tx 作業バッファ 2 本ぶん(MAX_RX_PACKET_SIZE × 2)。デバイス RAM の実態に
/// 含める。値は `transport::net::MAX_RX_PACKET_SIZE` に一致。
const MAX_RX_PACKET_SIZE_2: usize = simple_matter::transport::net::MAX_RX_PACKET_SIZE * 2;

/// `DefaultStack`(NF=5/S=4/E=4/TX=3/H=1/R=2/SUB=3/P=8)の計測。
pub fn default_stack() -> [Row; N_ROWS] {
    component_sizes::<5, 4, 4, 3, 1, 2, 3, 8>()
}

/// `MinimalStack`(NF=2/S=3/E=3/TX=2/H=1/R=1/SUB=2/P=4)の計測。
pub fn minimal_stack() -> [Row; N_ROWS] {
    component_sizes::<2, 3, 3, 2, 1, 1, 2, 4>()
}
