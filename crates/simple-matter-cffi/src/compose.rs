//! composition モード(Phase A、`docs/design/generic-firmware.md` §9.1)。
//!
//! `sm_config_t.composition`(Matter TLV blob)からエンドポイント/クラスタ構成を
//! **起動時に合成**する。コア(`crates/simple-matter`)は無改造で、実装済みクラスタを
//! 固定容量の static プールに持ち、blob の指示どおりに割り当てるだけ(スーパーセット方式、
//! §2)。
//!
//! # composition TLV スキーマ(§9.1)
//!
//! ```text
//! anonymous list|array of endpoint structs:
//!   {
//!     0: endpoint-id     u16   (1..=8。0 = システム EP は予約)
//!     1: device-type     u32
//!     2: device-type-rev u8
//!     3: cluster list    [u32, ...]        (array|list。合成可能クラスタ ID)
//!     4: options         [ {0: cluster u32, 1: attr u32, 2: value any-scalar}, ... ]
//!                        (optional。起動時に適用する初期値)
//!   }
//! ```
//!
//! Descriptor(0x001D)は各 EP に自動付与され、DeviceTypeList / ServerList / PartsList は
//! 合成結果から `crate::Light::install` が自動整合させる(blob に書かない)。
//!
//! # 制約
//!
//! - 合成可能クラスタは下の `POOL` 定数の型のみ(標準に無いものは F4b CustomCluster へ)。
//! - プール上限はコンパイル時定数。超過は `sm_init` が `-8` を返す。
//! - `sm_attr_set_value` の書き込み先はコアが setter を公開しているクラスタのみ
//!   (LevelControl/ColorControl の現在値のようにコマンド駆動の属性は read-only)。

use core::cell::RefCell;

use heapless::Vec;
use simple_matter::dm::clusters::{
    BooleanStateCluster, ColorControlCluster, DoorLockCluster, FanControlCluster,
    FlowMeasurementCluster, GroupsCluster, IdentifyCluster, IlluminanceMeasurementCluster,
    LevelControlCluster, OccupancySensingCluster, OnOffCluster, PressureMeasurementCluster,
    RelativeHumidityMeasurementCluster, SwitchCluster, TemperatureMeasurementCluster,
    ThermostatCluster,
};
use simple_matter::dm::ServerCluster;
use simple_matter::groups::DefaultGroupStore;
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

use crate::custom::{sm_attr_type_t, sm_attr_value_t};

// ==========================================================================
// 容量上限(§9.1 の初期プール)
// ==========================================================================

/// 合成できるエンドポイント数の上限(EP0 を除く。§9.1「最大 EP 8」)。
pub const MAX_COMPOSED_EPS: usize = 8;
/// 1 エンドポイントあたりの合成クラスタ数上限。
pub const MAX_CLUSTERS_PER_EP: usize = 12;
/// 合成クラスタ slot の総数上限(プール総容量と同オーダ)。
pub const MAX_SLOTS: usize = 40;
/// composition TLV の options(初期値)エントリ総数上限。
pub const MAX_OPTIONS: usize = 16;
/// 1 クラスタあたりの変化監視属性数(`on_cluster_change`)。
const MAX_WATCH: usize = 3;

const N_ONOFF: usize = 8;
const N_LEVEL: usize = 4;
const N_COLOR: usize = 2;
const N_BOOL: usize = 4;
const N_OCC: usize = 2;
const N_TEMP: usize = 4;
const N_HUM: usize = 4;
const N_ILLUM: usize = 4;
const N_PRESS: usize = 4;
const N_FLOW: usize = 4;
const N_SWITCH: usize = 4;
const N_FAN: usize = 2;
const N_LOCK: usize = 1;
const N_THERMO: usize = 1;
const N_IDENTIFY: usize = 8;
const N_GROUPS: usize = 8;

// 合成可能クラスタ ID。
/// Identify(0x0003)。
pub const CL_IDENTIFY: u32 = 0x0003;
/// Groups(0x0004)。
pub const CL_GROUPS: u32 = 0x0004;
/// On/Off(0x0006)。
pub const CL_ONOFF: u32 = 0x0006;
/// Level Control(0x0008)。
pub const CL_LEVEL: u32 = 0x0008;
/// Switch(0x003B)。
pub const CL_SWITCH: u32 = 0x003B;
/// Boolean State(0x0045)。
pub const CL_BOOL: u32 = 0x0045;
/// Door Lock(0x0101)。
pub const CL_LOCK: u32 = 0x0101;
/// Thermostat(0x0201)。
pub const CL_THERMO: u32 = 0x0201;
/// Fan Control(0x0202)。
pub const CL_FAN: u32 = 0x0202;
/// Color Control(0x0300)。
pub const CL_COLOR: u32 = 0x0300;
/// Illuminance Measurement(0x0400)。
pub const CL_ILLUM: u32 = 0x0400;
/// Temperature Measurement(0x0402)。
pub const CL_TEMP: u32 = 0x0402;
/// Pressure Measurement(0x0403)。
pub const CL_PRESS: u32 = 0x0403;
/// Flow Measurement(0x0404)。
pub const CL_FLOW: u32 = 0x0404;
/// Relative Humidity Measurement(0x0405)。
pub const CL_HUM: u32 = 0x0405;
/// Occupancy Sensing(0x0406)。
pub const CL_OCC: u32 = 0x0406;
/// Descriptor(0x001D、自動付与)。
pub const CL_DESCRIPTOR: u32 = 0x001D;

/// 値アクセス(`sm_attr_get_value` / `sm_attr_set_value`)の結果コード:
/// 対象のエンドポイント/クラスタが無い。
pub const RC_NO_CLUSTER: i32 = -2;
/// 対象属性が汎用値アクセス非対応(read-only 属性への set を含む)。
pub const RC_NO_ATTR: i32 = -3;
/// 値の型が属性に合わない。
pub const RC_TYPE: i32 = -4;

// ==========================================================================
// composition TLV のパース
// ==========================================================================

/// composition blob のパース結果(1 エンドポイント分)。
pub struct EpSpec {
    /// エンドポイント ID(1..=8)。
    pub ep: u16,
    /// デバイスタイプ ID。
    pub device_type: u32,
    /// デバイスタイプリビジョン。
    pub dt_rev: u16,
    /// サーバクラスタ ID(宣言順)。
    pub clusters: Vec<u32, MAX_CLUSTERS_PER_EP>,
}

/// composition blob の options エントリ(起動時に適用する初期値)。
pub struct OptSpec {
    /// 対象エンドポイント。
    pub ep: u16,
    /// 対象クラスタ。
    pub cluster: u32,
    /// 対象属性。
    pub attr: u32,
    /// 初期値。
    pub value: sm_attr_value_t,
}

/// composition blob 全体のパース結果。
pub struct CompositionSpec {
    /// エンドポイント宣言。
    pub eps: Vec<EpSpec, MAX_COMPOSED_EPS>,
    /// 初期値宣言。
    pub opts: Vec<OptSpec, MAX_OPTIONS>,
}

/// パース失敗の理由。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// TLV として不正、またはスキーマ違反。
    Decode,
    /// 容量上限超過(EP 数 / クラスタ数 / options 数)。
    Capacity,
}

/// composition TLV blob をパースする(§9.1 のスキーマ)。
pub fn parse(blob: &[u8]) -> Result<CompositionSpec, ParseError> {
    let mut r = TlvReader::new(blob);
    let mut out = CompositionSpec {
        eps: Vec::new(),
        opts: Vec::new(),
    };
    // 先頭は anonymous list / array(struct 直書きの単一 EP も受け付ける)。
    let first = r.read_next().map_err(|_| ParseError::Decode)?;
    let Some(first) = first else {
        return Ok(out); // 空 blob = 構成なし。
    };
    match first.value {
        TlvValue::ContainerStart(ContainerType::List | ContainerType::Array) => {}
        TlvValue::ContainerStart(ContainerType::Structure) => {
            parse_ep(&mut r, &mut out)?;
            return Ok(out);
        }
        _ => return Err(ParseError::Decode),
    }
    while let Some(e) = r.read_next().map_err(|_| ParseError::Decode)? {
        match e.value {
            TlvValue::ContainerEnd => break,
            TlvValue::ContainerStart(ContainerType::Structure) => parse_ep(&mut r, &mut out)?,
            TlvValue::ContainerStart(_) => r.exit_container().map_err(|_| ParseError::Decode)?,
            _ => {}
        }
    }
    Ok(out)
}

/// エンドポイント struct(開始トークン消費済み)を 1 つ読む。
fn parse_ep(r: &mut TlvReader<'_>, out: &mut CompositionSpec) -> Result<(), ParseError> {
    let mut spec = EpSpec {
        ep: 0,
        device_type: 0,
        dt_rev: 1,
        clusters: Vec::new(),
    };
    let mut opts: Vec<OptSpec, MAX_OPTIONS> = Vec::new();
    loop {
        let Some(e) = r.read_next().map_err(|_| ParseError::Decode)? else {
            return Err(ParseError::Decode); // 閉じ忘れ。
        };
        if matches!(e.value, TlvValue::ContainerEnd) {
            break;
        }
        let tag = match e.tag {
            TlvTag::ContextSpecific(t) => t,
            _ => {
                r.skip(&e).map_err(|_| ParseError::Decode)?;
                continue;
            }
        };
        match (tag, &e.value) {
            (0, v) => spec.ep = v.as_unsigned().map_err(|_| ParseError::Decode)? as u16,
            (1, v) => spec.device_type = v.as_unsigned().map_err(|_| ParseError::Decode)? as u32,
            (2, v) => spec.dt_rev = v.as_unsigned().map_err(|_| ParseError::Decode)? as u16,
            (3, TlvValue::ContainerStart(_)) => {
                // クラスタ ID 配列。
                loop {
                    let Some(c) = r.read_next().map_err(|_| ParseError::Decode)? else {
                        return Err(ParseError::Decode);
                    };
                    match c.value {
                        TlvValue::ContainerEnd => break,
                        TlvValue::ContainerStart(_) => {
                            r.exit_container().map_err(|_| ParseError::Decode)?
                        }
                        ref v => {
                            let id = v.as_unsigned().map_err(|_| ParseError::Decode)? as u32;
                            if id != CL_DESCRIPTOR && !spec.clusters.contains(&id) {
                                spec.clusters.push(id).map_err(|_| ParseError::Capacity)?;
                            }
                        }
                    }
                }
            }
            (4, TlvValue::ContainerStart(_)) => {
                // options 配列(cluster/attr/value の struct 列)。
                loop {
                    let Some(c) = r.read_next().map_err(|_| ParseError::Decode)? else {
                        return Err(ParseError::Decode);
                    };
                    match c.value {
                        TlvValue::ContainerEnd => break,
                        TlvValue::ContainerStart(ContainerType::Structure) => {
                            let o = parse_option(r)?;
                            opts.push(o).map_err(|_| ParseError::Capacity)?;
                        }
                        TlvValue::ContainerStart(_) => {
                            r.exit_container().map_err(|_| ParseError::Decode)?
                        }
                        _ => {}
                    }
                }
            }
            (_, TlvValue::ContainerStart(_)) => {
                r.exit_container().map_err(|_| ParseError::Decode)?
            }
            _ => {}
        }
    }
    if spec.ep == 0 {
        return Err(ParseError::Decode); // EP0 はシステム予約(§9.1)。
    }
    for mut o in opts {
        o.ep = spec.ep;
        out.opts.push(o).map_err(|_| ParseError::Capacity)?;
    }
    out.eps.push(spec).map_err(|_| ParseError::Capacity)?;
    Ok(())
}

/// options struct(開始トークン消費済み)を 1 つ読む。
fn parse_option(r: &mut TlvReader<'_>) -> Result<OptSpec, ParseError> {
    let mut o = OptSpec {
        ep: 0,
        cluster: 0,
        attr: 0,
        value: sm_attr_value_t::zero(),
    };
    loop {
        let Some(e) = r.read_next().map_err(|_| ParseError::Decode)? else {
            return Err(ParseError::Decode);
        };
        if matches!(e.value, TlvValue::ContainerEnd) {
            break;
        }
        match e.tag {
            TlvTag::ContextSpecific(0) => {
                o.cluster = e.value.as_unsigned().map_err(|_| ParseError::Decode)? as u32
            }
            TlvTag::ContextSpecific(1) => {
                o.attr = e.value.as_unsigned().map_err(|_| ParseError::Decode)? as u32
            }
            TlvTag::ContextSpecific(2) => match e.value {
                TlvValue::Boolean(b) => o.value = v_bool(b),
                TlvValue::UnsignedInteger(u) => o.value = v_u(sm_attr_type_t::SM_T_U64, u),
                TlvValue::SignedInteger(i) => o.value = v_i(sm_attr_type_t::SM_T_I64, i),
                TlvValue::Null => o.value.is_null = true,
                _ => r.skip(&e).map_err(|_| ParseError::Decode)?,
            },
            _ => r.skip(&e).map_err(|_| ParseError::Decode)?,
        }
    }
    Ok(o)
}

// ==========================================================================
// 値ヘルパ(sm_attr_value_t)
// ==========================================================================

/// bool 値を作る。
pub fn v_bool(b: bool) -> sm_attr_value_t {
    let mut v = sm_attr_value_t::zero();
    v.r#type = sm_attr_type_t::SM_T_BOOL;
    v.v.b = b;
    v
}

/// 符号なし値を作る。
pub fn v_u(t: sm_attr_type_t, u: u64) -> sm_attr_value_t {
    let mut v = sm_attr_value_t::zero();
    v.r#type = t;
    v.v.u = u;
    v
}

/// 符号付き値を作る。
pub fn v_i(t: sm_attr_type_t, i: i64) -> sm_attr_value_t {
    let mut v = sm_attr_value_t::zero();
    v.r#type = t;
    v.v.i = i;
    v
}

/// null 値を作る(型タグのみ有効)。
fn v_null(t: sm_attr_type_t) -> sm_attr_value_t {
    let mut v = sm_attr_value_t::zero();
    v.r#type = t;
    v.is_null = true;
    v
}

/// 値をスカラ u64 として読む(bool/符号なし)。型が合わなければ `None`。
fn as_u64(v: &sm_attr_value_t) -> Option<u64> {
    // SAFETY: union は `type` タグに従って読む(C 側の契約)。
    unsafe {
        match v.r#type {
            sm_attr_type_t::SM_T_BOOL => Some(v.v.b as u64),
            sm_attr_type_t::SM_T_U8
            | sm_attr_type_t::SM_T_U16
            | sm_attr_type_t::SM_T_U32
            | sm_attr_type_t::SM_T_U64 => Some(v.v.u),
            sm_attr_type_t::SM_T_I8
            | sm_attr_type_t::SM_T_I16
            | sm_attr_type_t::SM_T_I32
            | sm_attr_type_t::SM_T_I64 => {
                if v.v.i >= 0 {
                    Some(v.v.i as u64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// 値をスカラ i64 として読む(符号付き/符号なし/bool)。
fn as_i64(v: &sm_attr_value_t) -> Option<i64> {
    // SAFETY: 同上。
    unsafe {
        match v.r#type {
            sm_attr_type_t::SM_T_BOOL => Some(v.v.b as i64),
            sm_attr_type_t::SM_T_U8
            | sm_attr_type_t::SM_T_U16
            | sm_attr_type_t::SM_T_U32
            | sm_attr_type_t::SM_T_U64 => {
                if v.v.u <= i64::MAX as u64 {
                    Some(v.v.u as i64)
                } else {
                    None
                }
            }
            sm_attr_type_t::SM_T_I8
            | sm_attr_type_t::SM_T_I16
            | sm_attr_type_t::SM_T_I32
            | sm_attr_type_t::SM_T_I64 => Some(v.v.i),
            _ => None,
        }
    }
}

/// 値を bool として読む(0/非 0)。
fn as_bool(v: &sm_attr_value_t) -> Option<bool> {
    // SAFETY: 同上。
    unsafe {
        match v.r#type {
            sm_attr_type_t::SM_T_BOOL => Some(v.v.b),
            _ => as_u64(v).map(|u| u != 0),
        }
    }
}

/// 変化監視のスナップショット(スカラ 1 個分)。
#[derive(Clone, Copy, Default)]
struct Snap {
    valid: bool,
    is_null: bool,
    bits: u64,
}

impl Snap {
    /// 値からスナップショットを作る(スカラ以外は `valid=false`)。
    fn from_value(v: &sm_attr_value_t) -> Self {
        if v.is_null {
            return Self {
                valid: true,
                is_null: true,
                bits: 0,
            };
        }
        let bits = as_u64(v).or_else(|| as_i64(v).map(|i| i as u64));
        match bits {
            Some(b) => Self {
                valid: true,
                is_null: false,
                bits: b,
            },
            None => Self::default(),
        }
    }
    /// 同じ値か(未取得同士は「同じ」とみなす)。
    fn same(&self, o: &Snap) -> bool {
        self.valid == o.valid && self.is_null == o.is_null && self.bits == o.bits
    }
}

/// クラスタごとの変化監視属性(`on_cluster_change` の発火対象)。
fn watch_attrs(cluster: u32) -> &'static [u32] {
    match cluster {
        CL_ONOFF | CL_LEVEL | CL_BOOL | CL_OCC | CL_TEMP | CL_HUM | CL_ILLUM | CL_PRESS
        | CL_FLOW | CL_LOCK | CL_IDENTIFY => &[0x0000],
        CL_SWITCH => &[0x0001],
        CL_FAN => &[0x0000, 0x0002],
        CL_THERMO => &[0x0000, 0x001C],
        CL_COLOR => &[0x0000, 0x0001, 0x0007],
        _ => &[],
    }
}

// ==========================================================================
// 合成プール
// ==========================================================================

/// 合成クラスタ 1 個の割当(エンドポイント・クラスタ ID・プール内 index)。
struct Slot {
    ep: u16,
    cluster: u32,
    idx: u8,
    snap: [Snap; MAX_WATCH],
}

/// 合成済みエンドポイント(Descriptor 合成の素材)。
pub struct EpEntry {
    /// エンドポイント ID。
    pub ep: u16,
    /// デバイスタイプ ID。
    pub device_type: u32,
    /// デバイスタイプリビジョン。
    pub dt_rev: u16,
    /// サーバクラスタ ID(Descriptor 0x001D を含まない)。
    pub clusters: Vec<u32, MAX_CLUSTERS_PER_EP>,
}

/// 実装済みクラスタの static プール + 割当表(§9.1)。
///
/// `Light` が値で保持する(シム static 内。sm_init 後は移動しない)。
#[derive(Default)]
pub struct Composed {
    onoff: Vec<OnOffCluster, N_ONOFF>,
    level: Vec<LevelControlCluster, N_LEVEL>,
    color: Vec<ColorControlCluster, N_COLOR>,
    boolean: Vec<BooleanStateCluster, N_BOOL>,
    occ: Vec<OccupancySensingCluster, N_OCC>,
    temp: Vec<TemperatureMeasurementCluster, N_TEMP>,
    hum: Vec<RelativeHumidityMeasurementCluster, N_HUM>,
    illum: Vec<IlluminanceMeasurementCluster, N_ILLUM>,
    press: Vec<PressureMeasurementCluster, N_PRESS>,
    flow: Vec<FlowMeasurementCluster, N_FLOW>,
    switches: Vec<SwitchCluster, N_SWITCH>,
    fan: Vec<FanControlCluster, N_FAN>,
    lock: Vec<DoorLockCluster, N_LOCK>,
    thermo: Vec<ThermostatCluster, N_THERMO>,
    identify: Vec<IdentifyCluster, N_IDENTIFY>,
    groups: Vec<GroupsCluster<'static, 6, 8, 8>, N_GROUPS>,
    slots: Vec<Slot, MAX_SLOTS>,
    /// 合成済みエンドポイント(宣言順)。
    eps: Vec<EpEntry, MAX_COMPOSED_EPS>,
}

impl Composed {
    /// 空(composition 未使用 = 従来の固定ライト構成)。
    pub fn new() -> Self {
        Self::default()
    }

    /// 合成済みエンドポイント一覧。
    pub fn endpoints(&self) -> &[EpEntry] {
        &self.eps
    }

    /// 合成モードか(1 つ以上のエンドポイントを合成した)。
    pub fn is_active(&self) -> bool {
        !self.eps.is_empty()
    }

    /// パース済み構成をプールへ割り当てる(sm_init から 1 度だけ)。
    ///
    /// `groups` はグループストア(`Owned::groups`)。エラーは容量超過 or 未対応クラスタ。
    pub fn install(
        &mut self,
        spec: &CompositionSpec,
        groups: &'static RefCell<DefaultGroupStore>,
    ) -> Result<(), ParseError> {
        for e in spec.eps.iter() {
            if e.ep == 0 || e.ep as usize > MAX_COMPOSED_EPS {
                return Err(ParseError::Decode);
            }
            if self.eps.iter().any(|x| x.ep == e.ep) {
                return Err(ParseError::Decode); // EP 重複。
            }
            let mut entry = EpEntry {
                ep: e.ep,
                device_type: e.device_type,
                dt_rev: e.dt_rev,
                clusters: Vec::new(),
            };
            for &cl in e.clusters.iter() {
                let idx = self.alloc(cl, e.ep, groups)?;
                self.slots
                    .push(Slot {
                        ep: e.ep,
                        cluster: cl,
                        idx,
                        snap: [Snap::default(); MAX_WATCH],
                    })
                    .map_err(|_| ParseError::Capacity)?;
                entry.clusters.push(cl).map_err(|_| ParseError::Capacity)?;
            }
            self.eps.push(entry).map_err(|_| ParseError::Capacity)?;
        }
        // options(初期値)を適用する。未対応属性は無視(構成の可搬性を優先)。
        for o in spec.opts.iter() {
            let _ = self.set_value(o.ep, o.cluster, o.attr, &o.value);
        }
        self.sync_snapshots();
        Ok(())
    }

    /// クラスタ 1 個をプールへ確保して index を返す。
    fn alloc(
        &mut self,
        cluster: u32,
        ep: u16,
        groups: &'static RefCell<DefaultGroupStore>,
    ) -> Result<u8, ParseError> {
        /// `heapless::Vec` へ push して index を返す。
        macro_rules! push {
            ($v:expr, $val:expr) => {{
                let i = $v.len();
                $v.push($val).map_err(|_| ParseError::Capacity)?;
                i as u8
            }};
        }
        let idx = match cluster {
            CL_IDENTIFY => push!(self.identify, IdentifyCluster::new()),
            CL_GROUPS => push!(self.groups, GroupsCluster::new_shared(groups, ep)),
            CL_ONOFF => push!(self.onoff, OnOffCluster::new()),
            CL_LEVEL => push!(self.level, LevelControlCluster::new()),
            CL_COLOR => push!(self.color, ColorControlCluster::new()),
            CL_BOOL => push!(self.boolean, BooleanStateCluster::new()),
            CL_OCC => push!(self.occ, OccupancySensingCluster::new()),
            CL_TEMP => push!(
                self.temp,
                TemperatureMeasurementCluster::new(Some(-4000), Some(12000))
            ),
            CL_HUM => push!(
                self.hum,
                RelativeHumidityMeasurementCluster::new(Some(0), Some(10000))
            ),
            CL_ILLUM => push!(
                self.illum,
                IlluminanceMeasurementCluster::new(Some(1), Some(0xFFFE))
            ),
            CL_PRESS => push!(
                self.press,
                PressureMeasurementCluster::new(Some(0), Some(10000))
            ),
            CL_FLOW => push!(self.flow, FlowMeasurementCluster::new(Some(0), Some(10000))),
            CL_SWITCH => push!(self.switches, SwitchCluster::new()),
            CL_FAN => push!(self.fan, FanControlCluster::new()),
            CL_LOCK => push!(self.lock, DoorLockCluster::new()),
            CL_THERMO => push!(self.thermo, ThermostatCluster::new()),
            _ => return Err(ParseError::Decode), // 未対応クラスタ(CustomCluster で追加する)。
        };
        Ok(idx)
    }

    /// slot 検索(エンドポイント + クラスタ ID)。
    fn slot(&self, ep: u16, cluster: u32) -> Option<&Slot> {
        self.slots
            .iter()
            .find(|s| s.ep == ep && s.cluster == cluster)
    }

    /// 指定 EP/クラスタの共有参照(IM ディスパッチ)。
    pub fn cluster(&self, ep: u16, cluster: u32) -> Option<&dyn ServerCluster> {
        let s = self.slot(ep, cluster)?;
        let i = s.idx as usize;
        Some(match cluster {
            CL_IDENTIFY => self.identify.get(i)? as &dyn ServerCluster,
            CL_GROUPS => self.groups.get(i)?,
            CL_ONOFF => self.onoff.get(i)?,
            CL_LEVEL => self.level.get(i)?,
            CL_COLOR => self.color.get(i)?,
            CL_BOOL => self.boolean.get(i)?,
            CL_OCC => self.occ.get(i)?,
            CL_TEMP => self.temp.get(i)?,
            CL_HUM => self.hum.get(i)?,
            CL_ILLUM => self.illum.get(i)?,
            CL_PRESS => self.press.get(i)?,
            CL_FLOW => self.flow.get(i)?,
            CL_SWITCH => self.switches.get(i)?,
            CL_FAN => self.fan.get(i)?,
            CL_LOCK => self.lock.get(i)?,
            CL_THERMO => self.thermo.get(i)?,
            _ => return None,
        })
    }

    /// 指定 EP/クラスタの可変参照(IM ディスパッチ)。
    pub fn cluster_mut(&mut self, ep: u16, cluster: u32) -> Option<&mut dyn ServerCluster> {
        let i = self.slot(ep, cluster)?.idx as usize;
        Some(match cluster {
            CL_IDENTIFY => self.identify.get_mut(i)? as &mut dyn ServerCluster,
            CL_GROUPS => self.groups.get_mut(i)?,
            CL_ONOFF => self.onoff.get_mut(i)?,
            CL_LEVEL => self.level.get_mut(i)?,
            CL_COLOR => self.color.get_mut(i)?,
            CL_BOOL => self.boolean.get_mut(i)?,
            CL_OCC => self.occ.get_mut(i)?,
            CL_TEMP => self.temp.get_mut(i)?,
            CL_HUM => self.hum.get_mut(i)?,
            CL_ILLUM => self.illum.get_mut(i)?,
            CL_PRESS => self.press.get_mut(i)?,
            CL_FLOW => self.flow.get_mut(i)?,
            CL_SWITCH => self.switches.get_mut(i)?,
            CL_FAN => self.fan.get_mut(i)?,
            CL_LOCK => self.lock.get_mut(i)?,
            CL_THERMO => self.thermo.get_mut(i)?,
            _ => return None,
        })
    }

    // ----------------------------------------------------------------------
    // 汎用値アクセス(§9.1)
    // ----------------------------------------------------------------------

    /// 属性値を読む(`sm_attr_get_value`)。
    pub fn get_value(&self, ep: u16, cluster: u32, attr: u32) -> Result<sm_attr_value_t, i32> {
        let i = match self.slot(ep, cluster) {
            Some(s) => s.idx as usize,
            None => return Err(RC_NO_CLUSTER),
        };
        /// nullable スカラを値へ写す。
        macro_rules! nullable {
            ($opt:expr, $ty:expr, $conv:expr) => {
                match $opt {
                    Some(x) => Ok($conv($ty, x as _)),
                    None => Ok(v_null($ty)),
                }
            };
        }
        match (cluster, attr) {
            (CL_ONOFF, 0x0000) => Ok(v_bool(self.onoff[i].is_on())),
            (CL_LEVEL, 0x0000) => {
                nullable!(self.level[i].current_level(), sm_attr_type_t::SM_T_U8, v_u)
            }
            (CL_COLOR, 0x0000) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.color[i].current_hue() as u64,
            )),
            (CL_COLOR, 0x0001) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.color[i].current_saturation() as u64,
            )),
            (CL_COLOR, 0x0007) => Ok(v_u(
                sm_attr_type_t::SM_T_U16,
                self.color[i].color_temperature() as u64,
            )),
            (CL_COLOR, 0x0008) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.color[i].color_mode() as u64,
            )),
            (CL_BOOL, 0x0000) => Ok(v_bool(self.boolean[i].state())),
            (CL_OCC, 0x0000) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.occ[i].is_occupied() as u64,
            )),
            (CL_TEMP, 0x0000) => {
                nullable!(self.temp[i].measured(), sm_attr_type_t::SM_T_I16, v_i)
            }
            (CL_HUM, 0x0000) => nullable!(self.hum[i].measured(), sm_attr_type_t::SM_T_U16, v_u),
            (CL_ILLUM, 0x0000) => {
                nullable!(self.illum[i].measured(), sm_attr_type_t::SM_T_U16, v_u)
            }
            (CL_PRESS, 0x0000) => {
                nullable!(self.press[i].measured(), sm_attr_type_t::SM_T_I16, v_i)
            }
            (CL_FLOW, 0x0000) => nullable!(self.flow[i].measured(), sm_attr_type_t::SM_T_U16, v_u),
            (CL_SWITCH, 0x0001) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.switches[i].current_position() as u64,
            )),
            (CL_FAN, 0x0000) => Ok(v_u(sm_attr_type_t::SM_T_U8, self.fan[i].fan_mode() as u64)),
            (CL_FAN, 0x0002) => {
                nullable!(self.fan[i].percent_setting(), sm_attr_type_t::SM_T_U8, v_u)
            }
            (CL_FAN, 0x0003) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.fan[i].percent_current() as u64,
            )),
            (CL_LOCK, 0x0000) => nullable!(self.lock[i].lock_state(), sm_attr_type_t::SM_T_U8, v_u),
            (CL_THERMO, 0x0000) => nullable!(
                self.thermo[i].local_temperature(),
                sm_attr_type_t::SM_T_I16,
                v_i
            ),
            (CL_THERMO, 0x0011) => Ok(v_i(
                sm_attr_type_t::SM_T_I16,
                self.thermo[i].occupied_cooling_setpoint() as i64,
            )),
            (CL_THERMO, 0x0012) => Ok(v_i(
                sm_attr_type_t::SM_T_I16,
                self.thermo[i].occupied_heating_setpoint() as i64,
            )),
            (CL_THERMO, 0x001C) => Ok(v_u(
                sm_attr_type_t::SM_T_U8,
                self.thermo[i].system_mode() as u64,
            )),
            (CL_IDENTIFY, 0x0000) => Ok(v_u(
                sm_attr_type_t::SM_T_U16,
                self.identify[i].identify_time() as u64,
            )),
            _ => Err(RC_NO_ATTR),
        }
    }

    /// 属性値を書く(`sm_attr_set_value`。センサ値 push・ローカル操作の書き戻し)。
    ///
    /// コアが setter を公開していない属性(コマンド駆動の CurrentLevel 等)は
    /// [`RC_NO_ATTR`]。書き込み後はスナップショットを更新するので
    /// `on_cluster_change` は発火しない(アプリ発の変化とループしないため)。
    pub fn set_value(
        &mut self,
        ep: u16,
        cluster: u32,
        attr: u32,
        v: &sm_attr_value_t,
    ) -> Result<(), i32> {
        let i = match self.slot(ep, cluster) {
            Some(s) => s.idx as usize,
            None => return Err(RC_NO_CLUSTER),
        };
        /// nullable 整数の書き込み値を取り出す。
        macro_rules! nv {
            ($conv:expr, $t:ty) => {
                if v.is_null {
                    None
                } else {
                    Some(<$t>::try_from($conv(v).ok_or(RC_TYPE)?).map_err(|_| RC_TYPE)?)
                }
            };
        }
        match (cluster, attr) {
            (CL_ONOFF, 0x0000) => self.onoff[i].set(as_bool(v).ok_or(RC_TYPE)?),
            (CL_BOOL, 0x0000) => self.boolean[i].set_state(as_bool(v).ok_or(RC_TYPE)?),
            (CL_OCC, 0x0000) => self.occ[i].set_occupied(as_bool(v).ok_or(RC_TYPE)?),
            (CL_TEMP, 0x0000) => self.temp[i].set_measured(nv!(as_i64, i16)),
            (CL_HUM, 0x0000) => self.hum[i].set_measured(nv!(as_u64, u16)),
            (CL_ILLUM, 0x0000) => self.illum[i].set_measured(nv!(as_u64, u16)),
            (CL_PRESS, 0x0000) => self.press[i].set_measured(nv!(as_i64, i16)),
            (CL_FLOW, 0x0000) => self.flow[i].set_measured(nv!(as_u64, u16)),
            (CL_THERMO, 0x0000) => self.thermo[i].set_local_temperature(nv!(as_i64, i16)),
            (CL_SWITCH, 0x0001) => {
                let p = u8::try_from(as_u64(v).ok_or(RC_TYPE)?).map_err(|_| RC_TYPE)?;
                if p == 0 {
                    self.switches[i].release();
                } else {
                    self.switches[i].press(p);
                }
            }
            _ => return Err(RC_NO_ATTR),
        }
        self.refresh_snapshot(ep, cluster);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // 変化監視・クラスタ間連動
    // ----------------------------------------------------------------------

    /// 全 slot の監視スナップショットを現在値で更新する(初期化直後)。
    fn sync_snapshots(&mut self) {
        for k in 0..self.slots.len() {
            let (ep, cluster) = (self.slots[k].ep, self.slots[k].cluster);
            let attrs = watch_attrs(cluster);
            for (w, &a) in attrs.iter().enumerate().take(MAX_WATCH) {
                let snap = match self.get_value(ep, cluster, a) {
                    Ok(v) => Snap::from_value(&v),
                    Err(_) => Snap::default(),
                };
                self.slots[k].snap[w] = snap;
            }
        }
    }

    /// 1 クラスタ分のスナップショットを更新する(`set_value` 後)。
    fn refresh_snapshot(&mut self, ep: u16, cluster: u32) {
        let Some(k) = self
            .slots
            .iter()
            .position(|s| s.ep == ep && s.cluster == cluster)
        else {
            return;
        };
        for (w, &a) in watch_attrs(cluster).iter().enumerate().take(MAX_WATCH) {
            let snap = match self.get_value(ep, cluster, a) {
                Ok(v) => Snap::from_value(&v),
                Err(_) => Snap::default(),
            };
            self.slots[k].snap[w] = snap;
        }
    }

    /// IM write / コマンドで変化した属性を検出して `f` へ通知する(`on_cluster_change`)。
    pub fn poll_changes<F: FnMut(u16, u32, u32, &sm_attr_value_t)>(&mut self, mut f: F) {
        for k in 0..self.slots.len() {
            let (ep, cluster) = (self.slots[k].ep, self.slots[k].cluster);
            for (w, &a) in watch_attrs(cluster).iter().enumerate().take(MAX_WATCH) {
                let Ok(v) = self.get_value(ep, cluster, a) else {
                    continue;
                };
                let snap = Snap::from_value(&v);
                if !snap.same(&self.slots[k].snap[w]) {
                    self.slots[k].snap[w] = snap;
                    f(ep, cluster, a, &v);
                }
            }
        }
    }

    /// LevelControl / ColorControl の OnOff 連動を反映する(コアの規約: アプリが橋渡し)。
    pub fn couple_on_off(&mut self) {
        for k in 0..self.slots.len() {
            if self.slots[k].cluster != CL_ONOFF {
                continue;
            }
            let ep = self.slots[k].ep;
            let oi = self.slots[k].idx as usize;
            // Level → OnOff(WithOnOff 変種の要求)。
            if let Some(li) = self.index_of(ep, CL_LEVEL) {
                if let Some(req) = self.level[li].take_on_off_request() {
                    self.onoff[oi].set(req);
                }
            }
            let on = self.onoff[oi].is_on();
            // OnOff → Level / Color(現在状態の通知)。
            if let Some(li) = self.index_of(ep, CL_LEVEL) {
                if self.level[li].coupled_on() != on {
                    self.level[li].notify_on_off(on);
                }
            }
            if let Some(ci) = self.index_of(ep, CL_COLOR) {
                if self.color[ci].coupled_on() != on {
                    self.color[ci].notify_on_off(on);
                }
            }
        }
    }

    /// Identify 中フラグを同一 EP の Groups クラスタへ伝える(コアの規約)。
    pub fn sync_identify(&mut self) {
        for k in 0..self.slots.len() {
            if self.slots[k].cluster != CL_IDENTIFY {
                continue;
            }
            let ep = self.slots[k].ep;
            let identifying = self.identify[self.slots[k].idx as usize].is_identifying();
            if let Some(gi) = self.index_of(ep, CL_GROUPS) {
                self.groups[gi].set_identifying(identifying);
            }
        }
    }

    /// 指定 EP/クラスタのプール index。
    fn index_of(&self, ep: u16, cluster: u32) -> Option<usize> {
        self.slot(ep, cluster).map(|s| s.idx as usize)
    }

    /// 最小 EP の OnOff クラスタ(`sm_onoff_get` / `sm_onoff_set` の対象)。
    pub fn primary_onoff(&self) -> Option<(u16, usize)> {
        let mut best: Option<(u16, usize)> = None;
        for s in self.slots.iter() {
            if s.cluster == CL_ONOFF && best.map(|(e, _)| s.ep < e).unwrap_or(true) {
                best = Some((s.ep, s.idx as usize));
            }
        }
        best
    }

    /// OnOff の現在値(合成済みの代表 OnOff)。
    pub fn onoff_get(&self) -> Option<bool> {
        self.primary_onoff().map(|(_, i)| self.onoff[i].is_on())
    }

    /// OnOff を書き戻す(ローカル操作)。
    pub fn onoff_set(&mut self, on: bool) -> Option<u16> {
        let (ep, i) = self.primary_onoff()?;
        self.onoff[i].set(on);
        self.refresh_snapshot(ep, CL_ONOFF);
        Some(ep)
    }
}
