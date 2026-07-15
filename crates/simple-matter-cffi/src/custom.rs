//! カスタムクラスタ C vtable(F4b、`docs/design/c-ffi-shim.md` §8)。
//!
//! C++ アプリが自前のエンドポイント/クラスタを追加できるようにする。値の所有は C++ 側で、
//! read/write/invoke を C 関数ポインタへ委譲する汎用クラスタ [`CustomCluster`]
//! ([`ServerCluster`] の手書き実装)を提供する。TLV は「型付きスカラの get/set」だけを
//! シムが担い、C++ 側に TLV エンコーダを書かせない(§8.2)。
//!
//! - メタ(attr/cmd 表)は heapless 固定容量で保持(§8.2 の容量上限)。
//! - GlobalAttributes(ClusterRevision/FeatureMap/AttributeList/AcceptedCommandList)は
//!   IM エンジンが [`ClusterMeta`] から自動導出する。
//! - 権限は既定(read=View、write/invoke=Operate)。`SM_ATTR_TIMED`/`SM_CMD_TIMED` で timed 必須。

use core::cell::UnsafeCell;
use core::ffi::c_void;

use heapless::Vec;
use simple_matter::dm::codec::{AttrEncoder, CmdResponder};
use simple_matter::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use simple_matter::dm::{AttrWrite, ServerCluster};
use simple_matter::im::wire::ImStatus;
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

// ==========================================================================
// 容量上限(§8.2)
// ==========================================================================

/// 追加できるカスタムクラスタの最大数。
pub const MAX_CUSTOM_CLUSTERS: usize = 8;
/// 追加できる新規エンドポイントの最大数。
pub const MAX_CUSTOM_ENDPOINTS: usize = 4;
/// 1 クラスタあたりの属性上限。
pub const MAX_ATTRS: usize = 16;
/// 1 クラスタあたりのコマンド上限。
pub const MAX_CMDS: usize = 8;
/// invoke の引数(context tag)上限。
pub const MAX_ARGS: usize = 8;
/// 文字列/オクテット列の上限バイト数(`sm_attr_value_t` 内固定バッファ)。
pub const STR_CAP: usize = 64;

// ==========================================================================
// C ABI 型(cbindgen が simple_matter.h を生成する。§8.1)
// ==========================================================================

/// 属性/引数のスカラ型タグ(§8.1)。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum sm_attr_type_t {
    SM_T_BOOL = 0,
    SM_T_U8,
    SM_T_U16,
    SM_T_U32,
    SM_T_U64,
    SM_T_I8,
    SM_T_I16,
    SM_T_I32,
    SM_T_I64,
    SM_T_F32,
    SM_T_STRING,
    SM_T_OCTETS,
}

/// 短いバイト列/文字列(64B 上限。§8.2)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_attr_bytes {
    /// バイト内容(STRING は UTF-8、末尾 NUL 不要)。
    pub buf: [u8; STR_CAP],
    /// 有効バイト数。
    pub len: u8,
}

/// スカラ + 短いバイト列の tagged union の値部(§8.1)。
#[repr(C)]
#[derive(Clone, Copy)]
pub union sm_attr_value_data {
    /// 真偽値。
    pub b: bool,
    /// 符号なし整数。
    pub u: u64,
    /// 符号付き整数。
    pub i: i64,
    /// 単精度浮動小数点数。
    pub f: f32,
    /// 文字列/オクテット列。
    pub bytes: sm_attr_bytes,
}

/// スカラ + 短いバイト列の tagged union(§8.1)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_attr_value_t {
    /// 値の型。
    pub r#type: sm_attr_type_t,
    /// NULLABLE 属性のみ有効(true = null)。
    pub is_null: bool,
    /// 値本体(`type` で解釈)。
    pub v: sm_attr_value_data,
}

/// 属性定義(§8.1)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_attr_def_t {
    /// 属性 ID。
    pub attr_id: u32,
    /// スカラ型。
    pub r#type: sm_attr_type_t,
    /// `SM_ATTR_*` フラグ。
    pub flags: u32,
}

/// コマンド定義(§8.1)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_cmd_def_t {
    /// コマンド ID。
    pub cmd_id: u32,
    /// `SM_CMD_*` フラグ。
    pub flags: u32,
}

/// read コールバック(値を `out` へ。戻り値 = IM ステータス、0=Success)。
pub type SmClusterRead =
    Option<unsafe extern "C" fn(ctx: *mut c_void, attr_id: u32, out: *mut sm_attr_value_t) -> u8>;
/// write コールバック(戻り値 = IM ステータス)。
pub type SmClusterWrite = Option<
    unsafe extern "C" fn(ctx: *mut c_void, attr_id: u32, val: *const sm_attr_value_t) -> u8,
>;
/// invoke コールバック(引数はスカラ列に平坦化。戻り値 = IM ステータス)。
pub type SmClusterInvoke = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        cmd_id: u32,
        args: *const sm_attr_value_t,
        n_args: usize,
        now_ms: u64,
    ) -> u8,
>;

/// カスタムクラスタ定義(§8.1)。`attrs`/`cmds` は登録時にシムがコピーする。
#[repr(C)]
pub struct sm_cluster_def_t {
    /// 追加先エンドポイント(新規 EP は 2..、プリセット EP1 への追加も可)。
    pub endpoint: u16,
    /// クラスタ ID(vendor 領域 or 標準 ID)。
    pub cluster_id: u32,
    /// クラスタリビジョン。
    pub revision: u16,
    /// FeatureMap。
    pub feature_map: u32,
    /// 属性定義配列。
    pub attrs: *const sm_attr_def_t,
    /// 属性定義数。
    pub n_attrs: usize,
    /// コマンド定義配列。
    pub cmds: *const sm_cmd_def_t,
    /// コマンド定義数。
    pub n_cmds: usize,
    /// read ハンドラ。
    pub read: SmClusterRead,
    /// write ハンドラ。
    pub write: SmClusterWrite,
    /// invoke ハンドラ。
    pub invoke: SmClusterInvoke,
    /// コールバック ctx。
    pub ctx: *mut c_void,
}

// フラグ(cbindgen が #define を生成する。§8.1)。
/// 書き込み可能(未指定は read-only)。
pub const SM_ATTR_WRITABLE: u32 = 1 << 0;
/// NULLABLE(null 許容)。
pub const SM_ATTR_NULLABLE: u32 = 1 << 1;
/// timed write 必須。
pub const SM_ATTR_TIMED: u32 = 1 << 2;
/// timed invoke 必須。
pub const SM_CMD_TIMED: u32 = 1 << 0;

// ==========================================================================
// 値のエンコード/デコード
// ==========================================================================

impl sm_attr_value_t {
    /// ゼロ値(型 U64・非 null)。
    pub const fn zero() -> Self {
        Self {
            r#type: sm_attr_type_t::SM_T_U64,
            is_null: false,
            v: sm_attr_value_data { u: 0 },
        }
    }
}

/// C コールバックのステータス(u8)を [`Result`] に写す(0=Success)。
fn status_from_c(code: u8) -> Result<(), ImStatus> {
    if code == 0 {
        Ok(())
    } else {
        Err(ImStatus::from_u8(code).unwrap_or(ImStatus::Failure))
    }
}

/// TLV 値(invoke 引数)を [`sm_attr_value_t`] に平坦化する(§8.2)。
fn tlv_to_value(v: TlvValue<'_>) -> sm_attr_value_t {
    let mut out = sm_attr_value_t::zero();
    match v {
        TlvValue::Boolean(b) => {
            out.r#type = sm_attr_type_t::SM_T_BOOL;
            out.v.b = b;
        }
        TlvValue::UnsignedInteger(u) => {
            out.r#type = sm_attr_type_t::SM_T_U64;
            out.v.u = u;
        }
        TlvValue::SignedInteger(i) => {
            out.r#type = sm_attr_type_t::SM_T_I64;
            out.v.i = i;
        }
        TlvValue::Float(f) => {
            out.r#type = sm_attr_type_t::SM_T_F32;
            out.v.f = f;
        }
        TlvValue::Double(d) => {
            out.r#type = sm_attr_type_t::SM_T_F32;
            out.v.f = d as f32;
        }
        TlvValue::Utf8String(s) => {
            out.r#type = sm_attr_type_t::SM_T_STRING;
            copy_bytes(&mut out, s.as_bytes());
        }
        TlvValue::ByteString(b) => {
            out.r#type = sm_attr_type_t::SM_T_OCTETS;
            copy_bytes(&mut out, b);
        }
        TlvValue::Null => {
            out.is_null = true;
        }
        _ => {
            out.is_null = true;
        }
    }
    out
}

/// バイト列を値バッファへコピー(64B で切り詰め)。
fn copy_bytes(out: &mut sm_attr_value_t, src: &[u8]) {
    let n = src.len().min(STR_CAP);
    let mut bytes = sm_attr_bytes {
        buf: [0u8; STR_CAP],
        len: n as u8,
    };
    bytes.buf[..n].copy_from_slice(&src[..n]);
    out.v.bytes = bytes;
}

// ==========================================================================
// CustomCluster(ServerCluster の手書き実装)
// ==========================================================================

/// C vtable へ委譲する汎用クラスタ。
pub struct CustomCluster {
    /// 追加先エンドポイント。
    pub endpoint: u16,
    cluster_id: u32,
    revision: u16,
    feature_map: u32,
    attr_metas: Vec<AttributeMeta, MAX_ATTRS>,
    attr_types: Vec<sm_attr_type_t, MAX_ATTRS>,
    cmd_metas: Vec<CommandMeta, MAX_CMDS>,
    /// [`ServerCluster::meta`] が返すメタ。[`CustomCluster::finalize`] で自己参照を確定する。
    meta: ClusterMeta,
    read: SmClusterRead,
    write: SmClusterWrite,
    invoke: SmClusterInvoke,
    ctx: *mut c_void,
    dirty: bool,
}

impl CustomCluster {
    /// C 定義から構築する(容量超過は `Err`)。`attrs`/`cmds` の内容はここでコピーする。
    ///
    /// # Safety
    /// `def` は有効な [`sm_cluster_def_t`]。`attrs`/`cmds` は `n_attrs`/`n_cmds` 要素を指すこと。
    pub unsafe fn from_def(def: &sm_cluster_def_t) -> Result<Self, ()> {
        if def.n_attrs > MAX_ATTRS || def.n_cmds > MAX_CMDS {
            return Err(());
        }
        let mut attr_metas: Vec<AttributeMeta, MAX_ATTRS> = Vec::new();
        let mut attr_types: Vec<sm_attr_type_t, MAX_ATTRS> = Vec::new();
        if def.n_attrs > 0 {
            if def.attrs.is_null() {
                return Err(());
            }
            let attrs = core::slice::from_raw_parts(def.attrs, def.n_attrs);
            for a in attrs {
                let mut q = Quality::NONE;
                if a.flags & SM_ATTR_NULLABLE != 0 {
                    q = q.union(Quality::NULLABLE);
                }
                let writable = a.flags & SM_ATTR_WRITABLE != 0;
                let timed = a.flags & SM_ATTR_TIMED != 0;
                // read=View、write=Operate、全属性 subscribe 可(§8.2)。
                let m = AttributeMeta::new(AttributeId(a.attr_id), Privilege::View, q, true, writable, true)
                    .with_write_access(Privilege::Operate)
                    .with_timed(timed);
                attr_metas.push(m).map_err(|_| ())?;
                attr_types.push(a.r#type).map_err(|_| ())?;
            }
        }
        let mut cmd_metas: Vec<CommandMeta, MAX_CMDS> = Vec::new();
        if def.n_cmds > 0 {
            if def.cmds.is_null() {
                return Err(());
            }
            let cmds = core::slice::from_raw_parts(def.cmds, def.n_cmds);
            for c in cmds {
                let timed = c.flags & SM_CMD_TIMED != 0;
                let m = CommandMeta::new(CommandId(c.cmd_id), false, Privilege::Operate)
                    .with_timed(timed);
                cmd_metas.push(m).map_err(|_| ())?;
            }
        }
        Ok(Self {
            endpoint: def.endpoint,
            cluster_id: def.cluster_id,
            revision: def.revision,
            feature_map: def.feature_map,
            attr_metas,
            attr_types,
            cmd_metas,
            meta: ClusterMeta::new(ClusterId(def.cluster_id), def.revision, def.feature_map, &[], &[], &[]),
            read: def.read,
            write: def.write,
            invoke: def.invoke,
            ctx: def.ctx,
            dirty: false,
        })
    }

    /// クラスタ ID。
    pub const fn cluster_id(&self) -> u32 {
        self.cluster_id
    }

    /// dirty フラグを立てる([`crate::sm_attr_mark_dirty`] 経由)。
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// [`ServerCluster::meta`] の自己参照(attributes/accepted_commands)を最終確定する。
    ///
    /// # Safety
    /// `self` が二度と移動しない最終格納位置(シム static 内)に居ること。以降 `attr_metas`
    /// / `cmd_metas` を変更しないこと(スライスが無効化される)。
    pub unsafe fn finalize(&mut self) {
        let attrs: &'static [AttributeMeta] =
            core::slice::from_raw_parts(self.attr_metas.as_ptr(), self.attr_metas.len());
        let cmds: &'static [CommandMeta] =
            core::slice::from_raw_parts(self.cmd_metas.as_ptr(), self.cmd_metas.len());
        self.meta = ClusterMeta::new(
            ClusterId(self.cluster_id),
            self.revision,
            self.feature_map,
            attrs,
            cmds,
            &[],
        );
    }

    fn attr_index(&self, attr: AttributeId) -> Option<usize> {
        self.attr_metas.iter().position(|m| m.id == attr)
    }

    /// read コールバックの返り値を TLV へエンコードする。
    fn encode_value(&self, v: &sm_attr_value_t, enc: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        if v.is_null {
            return enc.write_null();
        }
        // SAFETY: union フィールドは `type` タグに従って読む(C 側の契約)。
        unsafe {
            match v.r#type {
                sm_attr_type_t::SM_T_BOOL => enc.write_bool(v.v.b),
                sm_attr_type_t::SM_T_U8 => enc.write_u8(v.v.u as u8),
                sm_attr_type_t::SM_T_U16 => enc.write_u16(v.v.u as u16),
                sm_attr_type_t::SM_T_U32 => enc.write_u32(v.v.u as u32),
                sm_attr_type_t::SM_T_U64 => enc.write_u64(v.v.u),
                sm_attr_type_t::SM_T_I8 => enc.write_i8(v.v.i as i8),
                sm_attr_type_t::SM_T_I16 => enc.write_i16(v.v.i as i16),
                sm_attr_type_t::SM_T_I32 => enc.write_i32(v.v.i as i32),
                sm_attr_type_t::SM_T_I64 => enc.write_i64(v.v.i),
                sm_attr_type_t::SM_T_F32 => enc.write_f32(v.v.f),
                sm_attr_type_t::SM_T_STRING => {
                    let n = (v.v.bytes.len as usize).min(STR_CAP);
                    let s = core::str::from_utf8(&v.v.bytes.buf[..n]).map_err(|_| ImStatus::Failure)?;
                    enc.write_str(s)
                }
                sm_attr_type_t::SM_T_OCTETS => {
                    let n = (v.v.bytes.len as usize).min(STR_CAP);
                    enc.write_bytes(&v.v.bytes.buf[..n])
                }
            }
        }
    }
}

/// 受信 TLV を宣言型 `ty` に従い [`sm_attr_value_t`] へデコードする(型不一致は `ConstraintError`)。
fn decode_write(
    ty: sm_attr_type_t,
    nullable: bool,
    data: AttrWrite<'_>,
) -> Result<sm_attr_value_t, ImStatus> {
    let el = data.element()?;
    if matches!(el.value, TlvValue::Null) {
        if nullable {
            let mut out = sm_attr_value_t::zero();
            out.r#type = ty;
            out.is_null = true;
            return Ok(out);
        }
        return Err(ImStatus::ConstraintError);
    }
    let mut out = sm_attr_value_t::zero();
    out.r#type = ty;
    let cerr = ImStatus::ConstraintError;
    match ty {
        sm_attr_type_t::SM_T_BOOL => out.v.b = el.value.as_bool().map_err(|_| cerr)?,
        sm_attr_type_t::SM_T_U8 => {
            let u = el.value.as_unsigned().map_err(|_| cerr)?;
            if u > u8::MAX as u64 {
                return Err(cerr);
            }
            out.v.u = u;
        }
        sm_attr_type_t::SM_T_U16 => {
            let u = el.value.as_unsigned().map_err(|_| cerr)?;
            if u > u16::MAX as u64 {
                return Err(cerr);
            }
            out.v.u = u;
        }
        sm_attr_type_t::SM_T_U32 => {
            let u = el.value.as_unsigned().map_err(|_| cerr)?;
            if u > u32::MAX as u64 {
                return Err(cerr);
            }
            out.v.u = u;
        }
        sm_attr_type_t::SM_T_U64 => out.v.u = el.value.as_unsigned().map_err(|_| cerr)?,
        sm_attr_type_t::SM_T_I8 => {
            let i = el.value.as_signed().map_err(|_| cerr)?;
            if !(i8::MIN as i64..=i8::MAX as i64).contains(&i) {
                return Err(cerr);
            }
            out.v.i = i;
        }
        sm_attr_type_t::SM_T_I16 => {
            let i = el.value.as_signed().map_err(|_| cerr)?;
            if !(i16::MIN as i64..=i16::MAX as i64).contains(&i) {
                return Err(cerr);
            }
            out.v.i = i;
        }
        sm_attr_type_t::SM_T_I32 => {
            let i = el.value.as_signed().map_err(|_| cerr)?;
            if !(i32::MIN as i64..=i32::MAX as i64).contains(&i) {
                return Err(cerr);
            }
            out.v.i = i;
        }
        sm_attr_type_t::SM_T_I64 => out.v.i = el.value.as_signed().map_err(|_| cerr)?,
        sm_attr_type_t::SM_T_F32 => {
            out.v.f = match el.value {
                TlvValue::Float(f) => f,
                TlvValue::Double(d) => d as f32,
                _ => return Err(cerr),
            }
        }
        sm_attr_type_t::SM_T_STRING => {
            let s = el.value.as_str().map_err(|_| cerr)?;
            if s.len() > STR_CAP {
                return Err(cerr);
            }
            copy_bytes(&mut out, s.as_bytes());
        }
        sm_attr_type_t::SM_T_OCTETS => {
            let b = el.value.as_bytes().map_err(|_| cerr)?;
            if b.len() > STR_CAP {
                return Err(cerr);
            }
            copy_bytes(&mut out, b);
        }
    }
    Ok(out)
}

/// invoke 引数を context tag 0..N-1 の宣言順で平坦デコードする(§8.2)。戻り値 = 引数数。
fn decode_args(fields: &mut TlvReader<'_>, out: &mut [sm_attr_value_t; MAX_ARGS]) -> usize {
    let mut r = fields.clone();
    let opened = matches!(
        r.read_next(),
        Ok(Some(e)) if matches!(e.value, TlvValue::ContainerStart(ContainerType::Structure))
    );
    if !opened {
        return 0;
    }
    let mut count = 0usize;
    while let Ok(Some(e)) = r.read_next() {
        match e.value {
            TlvValue::ContainerEnd => break,
            v => {
                if let TlvTag::ContextSpecific(t) = e.tag {
                    let idx = t as usize;
                    if idx < MAX_ARGS {
                        out[idx] = tlv_to_value(v);
                        if idx + 1 > count {
                            count = idx + 1;
                        }
                    }
                }
            }
        }
    }
    count
}

impl ServerCluster for CustomCluster {
    fn meta(&self) -> &'static ClusterMeta {
        // SAFETY: self はシム static 内に固定(sm_init 後は移動しない)。finalize 済みの
        // meta スライスは attr_metas/cmd_metas を指し、プログラム全生存期間有効。
        unsafe { &*(&self.meta as *const ClusterMeta) }
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        if self.attr_index(attr).is_none() {
            return Err(ImStatus::UnsupportedAttribute);
        }
        let Some(cb) = self.read else {
            return Err(ImStatus::UnsupportedRead);
        };
        let mut out = sm_attr_value_t::zero();
        // SAFETY: 単線契約下で C の read ハンドラを呼ぶ。
        let code = unsafe { cb(self.ctx, attr.0, &mut out) };
        status_from_c(code)?;
        self.encode_value(&out, enc)
    }

    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let Some(idx) = self.attr_index(attr) else {
            return Err(ImStatus::UnsupportedAttribute);
        };
        let m = self.attr_metas[idx];
        if !m.writable {
            return Err(ImStatus::UnsupportedWrite);
        }
        let ty = self.attr_types[idx];
        let nullable = m.quality.contains(Quality::NULLABLE);
        let val = decode_write(ty, nullable, data)?;
        let Some(cb) = self.write else {
            return Err(ImStatus::UnsupportedWrite);
        };
        // SAFETY: 単線契約下で C の write ハンドラを呼ぶ。
        let code = unsafe { cb(self.ctx, attr.0, &val) };
        status_from_c(code)?;
        // IM 経由の書き込みも購読へ反映(値が変わったとみなす)。
        self.dirty = true;
        Ok(())
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        _resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        if !self.cmd_metas.iter().any(|c| c.id == cmd) {
            return Err(ImStatus::UnsupportedCommand);
        }
        let Some(cb) = self.invoke else {
            return Err(ImStatus::UnsupportedCommand);
        };
        let mut args = [sm_attr_value_t::zero(); MAX_ARGS];
        let n = decode_args(fields, &mut args);
        // SAFETY: 単線契約下で C の invoke ハンドラを呼ぶ。args は n 要素有効。
        let code = unsafe { cb(self.ctx, cmd.0, args.as_ptr(), n, acc.now_ms) };
        status_from_c(code)
    }

    fn take_dirty(&mut self) -> bool {
        core::mem::take(&mut self.dirty)
    }
}

// ==========================================================================
// 登録ステージング(sm_init より前に積む。§8.1)
// ==========================================================================

/// 新規エンドポイント登録(device type 付与)。
pub struct EndpointReg {
    /// エンドポイント ID(2..)。
    pub endpoint: u16,
    /// デバイスタイプ ID。
    pub device_type: u32,
    /// デバイスタイプリビジョン。
    pub dt_revision: u16,
}

/// sm_init 前に積む登録内容。
pub struct PendingRegistry {
    /// 登録されたカスタムクラスタ。
    pub clusters: Vec<CustomCluster, MAX_CUSTOM_CLUSTERS>,
    /// 登録された新規エンドポイント。
    pub endpoints: Vec<EndpointReg, MAX_CUSTOM_ENDPOINTS>,
}

impl PendingRegistry {
    /// 空のレジストリ。
    pub const fn new() -> Self {
        Self {
            clusters: Vec::new(),
            endpoints: Vec::new(),
        }
    }
}

/// `PendingRegistry` を包む Sync セル(単一タスク契約)。
struct PendingCell(UnsafeCell<PendingRegistry>);
// SAFETY: 単一タスクからのみアクセスする契約。
unsafe impl Sync for PendingCell {}

static PENDING: PendingCell = PendingCell(UnsafeCell::new(PendingRegistry::new()));

/// ステージングレジストリへの排他参照。
///
/// # Safety
/// 単一タスクからのみ呼ぶこと。
pub unsafe fn pending() -> &'static mut PendingRegistry {
    &mut *PENDING.0.get()
}

/// ステージング内容を取り出して空に戻す(sm_init が Light へ移す)。
pub fn take_pending() -> PendingRegistry {
    // SAFETY: 単線契約。sm_init から 1 度だけ呼ぶ。
    unsafe { core::mem::replace(&mut *PENDING.0.get(), PendingRegistry::new()) }
}
