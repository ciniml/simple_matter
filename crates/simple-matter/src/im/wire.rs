//! Interaction Model ワイヤ層 codec(`docs/design/interaction-model.md` §2)。
//!
//! IM メッセージ・IB(Information Block)・パス・Status の TLV エンコード/デコードを
//! 提供する。すべて借用ビュー(所有しない・ヒープ確保しない)で、`no_std` かつ暗号非依存。
//! 不正入力に対して `panic` せず [`Error::Decode`] を返す。
//!
//! # ワイヤ形式の出典
//!
//! タグ番号・メッセージ構造は Matter Core Specification §10(Interaction Model)および
//! Appendix A(TLV)に基づく。実装にあたって以下の参照実装でタグ番号を確認した:
//! - `research/rs-matter/rs-matter/src/im/encoding/*.rs`(`ReadReqTag`/`ReportDataRespTag`/
//!   `SubscribeReqTag`/`WriteReqTag`/`InvReqTag`/`AttrPathTag`/`CmdDataTag` 等の各 `*Tag` enum)
//! - `research/connectedhomeip/src/app/MessageDef/*.h`(`AttributeDataIB` 等の `Tag` 定数)
//!
//! # 値ペイロードの扱い
//!
//! 属性値/コマンドフィールドは「TLV 要素をそのまま転写できる」形で扱う(設計 §2.2)。
//! デコード側は値要素の生スライス(元のタグ込み)を返し([`AttributeDataRef::data`] 等)、
//! エンコード側はクロージャで値を書かせる([`AttrReportWriter::push_data`] 等)。生スライスを
//! 別タグへ移し替える転写は [`transcribe`] が行う。

use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

// ==========================================================================
// 定数
// ==========================================================================

/// Interaction Model の Protocol ID。
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x0001;

/// 送信する全 IM メッセージに載せる `InteractionModelRevision`(Matter Core Spec R1.3 §8.10)。
///
/// 受信側は本フィールドの有無・値を無視する(前方互換。rs-matter は 13 を用いるなど
/// 実装/仕様版により値が異なるが、いずれもワイヤ上妥当)。
pub const INTERACTION_MODEL_REVISION: u8 = 11;

/// `InteractionModelRevision` を載せるコンテキストタグ(グローバル要素タグ 0xFF)。
const IM_REVISION_TAG: u8 = 0xFF;

// ==========================================================================
// OpCode
// ==========================================================================

/// IM メッセージの Protocol Opcode(Matter Core Spec §10.6、chip `interaction_model/Constants.h`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImOpCode {
    /// StatusResponse(双方向。チャンク継続の ACK にも使う)。
    StatusResponse = 0x01,
    /// ReadRequest(Read 入口)。
    ReadRequest = 0x02,
    /// SubscribeRequest(Subscribe 入口)。
    SubscribeRequest = 0x03,
    /// SubscribeResponse(device→client、プライミング完了後)。
    SubscribeResponse = 0x04,
    /// ReportData(device→client、Read 応答 / 購読レポート)。
    ReportData = 0x05,
    /// WriteRequest(Write 入口)。
    WriteRequest = 0x06,
    /// WriteResponse。
    WriteResponse = 0x07,
    /// InvokeRequest(Invoke 入口)。
    InvokeRequest = 0x08,
    /// InvokeResponse。
    InvokeResponse = 0x09,
    /// TimedRequest(Timed 入口)。
    TimedRequest = 0x0a,
}

impl ImOpCode {
    /// Protocol opcode バイトから変換する。未知の値は [`Error::Decode`]。
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x01 => Self::StatusResponse,
            0x02 => Self::ReadRequest,
            0x03 => Self::SubscribeRequest,
            0x04 => Self::SubscribeResponse,
            0x05 => Self::ReportData,
            0x06 => Self::WriteRequest,
            0x07 => Self::WriteResponse,
            0x08 => Self::InvokeRequest,
            0x09 => Self::InvokeResponse,
            0x0a => Self::TimedRequest,
            _ => return Err(Error::Decode),
        })
    }

    /// opcode バイトを返す。
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// responder が新規 exchange の初回として受理する入口 opcode かを返す。
    ///
    /// Read / Subscribe / Write / Invoke / Timed が `true`。
    pub const fn is_transaction_start(self) -> bool {
        matches!(
            self,
            Self::ReadRequest
                | Self::SubscribeRequest
                | Self::WriteRequest
                | Self::InvokeRequest
                | Self::TimedRequest
        )
    }
}

// ==========================================================================
// ID 新型(暫定。設計上は dm::meta。dm 実装時に移設予定)
// ==========================================================================

/// エンドポイント ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EndpointId(pub u16);

/// クラスタ ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClusterId(pub u32);

/// 属性 ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AttributeId(pub u32);

/// コマンド ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CommandId(pub u32);

/// イベント ID(型のみ。codec は初期スコープ外)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EventId(pub u32);

// ==========================================================================
// IM Status コード(Matter Core Spec §10.7 / cluster Status Codes)
// ==========================================================================

/// IM Status コード。
///
/// 値は Matter Core Spec §10.7 の `Status Code Table`(rs-matter `IMStatusCode`、
/// chip `Protocols::InteractionModel::Status` と一致)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)] // 各バリアントは仕様のステータス名そのもの(自明)。
pub enum ImStatus {
    Success = 0x00,
    Failure = 0x01,
    InvalidSubscription = 0x7d,
    UnsupportedAccess = 0x7e,
    UnsupportedEndpoint = 0x7f,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    UnsupportedRead = 0x8f,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9c,
    UnsupportedCluster = 0xc3,
    NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6,
    UnsupportedEvent = 0xc7,
    PathsExhausted = 0xc8,
    TimedRequestMismatch = 0xc9,
    FailsafeRequired = 0xca,
    InvalidInState = 0xcb,
    NoCommandResponse = 0xcc,
}

impl ImStatus {
    /// ステータスバイトから変換する。未知の値は [`Error::Decode`]。
    pub const fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x00 => Self::Success,
            0x01 => Self::Failure,
            0x7d => Self::InvalidSubscription,
            0x7e => Self::UnsupportedAccess,
            0x7f => Self::UnsupportedEndpoint,
            0x80 => Self::InvalidAction,
            0x81 => Self::UnsupportedCommand,
            0x85 => Self::InvalidCommand,
            0x86 => Self::UnsupportedAttribute,
            0x87 => Self::ConstraintError,
            0x88 => Self::UnsupportedWrite,
            0x89 => Self::ResourceExhausted,
            0x8b => Self::NotFound,
            0x8c => Self::UnreportableAttribute,
            0x8d => Self::InvalidDataType,
            0x8f => Self::UnsupportedRead,
            0x92 => Self::DataVersionMismatch,
            0x94 => Self::Timeout,
            0x9c => Self::Busy,
            0xc3 => Self::UnsupportedCluster,
            0xc5 => Self::NoUpstreamSubscription,
            0xc6 => Self::NeedsTimedInteraction,
            0xc7 => Self::UnsupportedEvent,
            0xc8 => Self::PathsExhausted,
            0xc9 => Self::TimedRequestMismatch,
            0xca => Self::FailsafeRequired,
            0xcb => Self::InvalidInState,
            0xcc => Self::NoCommandResponse,
            _ => return Err(Error::Decode),
        })
    }

    /// ステータスバイトを返す。
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    /// 成功(`Success`)かを返す。
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

// ==========================================================================
// StatusIB(Matter Core Spec: StatusIB)
// ==========================================================================

/// StatusIB(`{ status: ImStatus(0), cluster_status: Option<u8>(1) }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusIB {
    /// IM ステータスコード。
    pub status: ImStatus,
    /// クラスタ固有ステータス(enum8)。無ければ `None`。
    pub cluster_status: Option<u8>,
}

impl StatusIB {
    /// 新しい [`StatusIB`] を作る。
    pub const fn new(status: ImStatus, cluster_status: Option<u8>) -> Self {
        Self {
            status,
            cluster_status,
        }
    }

    /// クラスタステータス無しの [`StatusIB`] を作る。
    pub const fn simple(status: ImStatus) -> Self {
        Self::new(status, None)
    }

    /// StatusIB を `tag` 付きの構造体として書く。
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()> {
        w.start_struct(tag)?;
        w.write_u8(&TlvTag::ContextSpecific(0), self.status.to_u8())?;
        if let Some(cs) = self.cluster_status {
            w.write_u8(&TlvTag::ContextSpecific(1), cs)?;
        }
        w.end_container()
    }

    /// StatusIB 構造体を読む(構造体開始はまだ読んでいない状態から)。
    pub fn decode(r: &mut TlvReader<'_>) -> Result<Self> {
        expect_container(r, ContainerType::Structure)?;
        Self::decode_body(r)
    }

    /// StatusIB 構造体の本体を読む(構造体開始を消費済みの状態から)。
    fn decode_body(r: &mut TlvReader<'_>) -> Result<Self> {
        let mut status = None;
        let mut cluster_status = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => status = Some(ImStatus::from_u8(read_u8(r)?)?),
                1 => cluster_status = Some(read_u8(r)?),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            status: status.ok_or(Error::Decode)?,
            cluster_status,
        })
    }
}

// ==========================================================================
// パス
// ==========================================================================

/// AttributePathIB(ワイヤ上の生表現、ワイルドカード可)。
///
/// TLV では `list` として context タグ付きで並ぶ(`AttrPathTag`: TagCompression=0,
/// Node=1, Endpoint=2, Cluster=3, Attribute=4, ListIndex=5)。省略フィールドは
/// ワイルドカード。Node は device 側では扱わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttributePath {
    /// エンドポイント。`None` はワイルドカード。
    pub endpoint: Option<EndpointId>,
    /// クラスタ。`None` はワイルドカード。
    pub cluster: Option<ClusterId>,
    /// 属性。`None` はワイルドカード。
    pub attribute: Option<AttributeId>,
    /// list 要素インデックス(Write の list 編集用)。初期は保持のみ。
    pub list_index: Option<u16>,
    /// EnableTagCompression。受理はするが device 側では無視する。
    pub enable_tag_compression: bool,
}

impl AttributePath {
    /// エンドポイント/クラスタ/属性を指定した具象パスを作る。
    pub const fn concrete(
        endpoint: EndpointId,
        cluster: ClusterId,
        attribute: AttributeId,
    ) -> Self {
        Self {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attribute: Some(attribute),
            list_index: None,
            enable_tag_compression: false,
        }
    }

    /// [`ConcreteAttrPath`] から生成する。
    pub const fn from_concrete(p: ConcreteAttrPath) -> Self {
        Self::concrete(p.endpoint, p.cluster, p.attribute)
    }

    /// ワイルドカード/`list_index` を含まない完全解決済みなら [`ConcreteAttrPath`] を返す。
    pub const fn to_concrete(&self) -> Option<ConcreteAttrPath> {
        match (self.endpoint, self.cluster, self.attribute) {
            (Some(e), Some(c), Some(a)) if self.list_index.is_none() => {
                Some(ConcreteAttrPath::new(e, c, a))
            }
            _ => None,
        }
    }

    /// いずれかのフィールドがワイルドカードなら `true`。
    pub const fn is_wildcard(&self) -> bool {
        self.endpoint.is_none() || self.cluster.is_none() || self.attribute.is_none()
    }

    /// 具象パス `p` がこのパス(ワイルドカード可)にマッチするかを返す。
    pub fn matches(&self, p: ConcreteAttrPath) -> bool {
        fn m<T: PartialEq>(o: Option<T>, v: T) -> bool {
            match o {
                Some(x) => x == v,
                None => true,
            }
        }
        m(self.endpoint, p.endpoint) && m(self.cluster, p.cluster) && m(self.attribute, p.attribute)
    }

    /// AttributePathIB を `tag` 付きの list として書く。
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()> {
        w.start_list(tag)?;
        if self.enable_tag_compression {
            w.write_bool(&TlvTag::ContextSpecific(0), true)?;
        }
        if let Some(e) = self.endpoint {
            w.write_u16(&TlvTag::ContextSpecific(2), e.0)?;
        }
        if let Some(c) = self.cluster {
            w.write_u32(&TlvTag::ContextSpecific(3), c.0)?;
        }
        if let Some(a) = self.attribute {
            w.write_u32(&TlvTag::ContextSpecific(4), a.0)?;
        }
        if let Some(i) = self.list_index {
            w.write_u16(&TlvTag::ContextSpecific(5), i)?;
        }
        w.end_container()
    }

    /// AttributePathIB(list)を読む(list 開始はまだ読んでいない状態から)。
    pub fn decode(r: &mut TlvReader<'_>) -> Result<Self> {
        expect_container(r, ContainerType::List)?;
        Self::decode_body(r)
    }

    /// AttributePathIB(list)の本体を読む(list 開始を消費済みの状態から)。
    fn decode_body(r: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = Self::default();
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => path.enable_tag_compression = read_bool(r)?,
                1 => skip_field(r)?, // Node: device 側では扱わない
                2 => path.endpoint = Some(EndpointId(read_u16(r)?)),
                3 => path.cluster = Some(ClusterId(read_u32(r)?)),
                4 => path.attribute = Some(AttributeId(read_u32(r)?)),
                5 => path.list_index = Some(read_u16(r)?),
                _ => skip_field(r)?,
            }
        }
        Ok(path)
    }
}

/// CommandPathIB(具象パス。Invoke ではワイルドカード不可)。
///
/// TLV では `list`(`CmdPathTag`: Endpoint=0, Cluster=1, Command=2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPath {
    /// エンドポイント。
    pub endpoint: EndpointId,
    /// クラスタ。
    pub cluster: ClusterId,
    /// コマンド。
    pub command: CommandId,
}

impl CommandPath {
    /// 新しい [`CommandPath`] を作る。
    pub const fn new(endpoint: EndpointId, cluster: ClusterId, command: CommandId) -> Self {
        Self {
            endpoint,
            cluster,
            command,
        }
    }

    /// CommandPathIB を `tag` 付きの list として書く。
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()> {
        w.start_list(tag)?;
        w.write_u16(&TlvTag::ContextSpecific(0), self.endpoint.0)?;
        w.write_u32(&TlvTag::ContextSpecific(1), self.cluster.0)?;
        w.write_u32(&TlvTag::ContextSpecific(2), self.command.0)?;
        w.end_container()
    }

    /// CommandPathIB(list)を読む。全フィールド必須(ワイルドカードは [`Error::Decode`])。
    pub fn decode(r: &mut TlvReader<'_>) -> Result<Self> {
        expect_container(r, ContainerType::List)?;
        Self::decode_body(r)
    }

    fn decode_body(r: &mut TlvReader<'_>) -> Result<Self> {
        let mut endpoint = None;
        let mut cluster = None;
        let mut command = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => endpoint = Some(EndpointId(read_u16(r)?)),
                1 => cluster = Some(ClusterId(read_u32(r)?)),
                2 => command = Some(CommandId(read_u32(r)?)),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            endpoint: endpoint.ok_or(Error::Decode)?,
            cluster: cluster.ok_or(Error::Decode)?,
            command: command.ok_or(Error::Decode)?,
        })
    }
}

/// EventPathIB(型のみ。codec は初期スコープ外、設計 §2.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventPath {
    /// エンドポイント。`None` はワイルドカード。
    pub endpoint: Option<EndpointId>,
    /// クラスタ。`None` はワイルドカード。
    pub cluster: Option<ClusterId>,
    /// イベント。`None` はワイルドカード。
    pub event: Option<EventId>,
    /// 緊急フラグ(Subscribe のイベント用)。
    pub is_urgent: Option<bool>,
}

/// 完全解決済みの属性パス(エンジン内部で扱う具象表現)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcreteAttrPath {
    /// エンドポイント。
    pub endpoint: EndpointId,
    /// クラスタ。
    pub cluster: ClusterId,
    /// 属性。
    pub attribute: AttributeId,
}

impl ConcreteAttrPath {
    /// 新しい [`ConcreteAttrPath`] を作る。
    pub const fn new(endpoint: EndpointId, cluster: ClusterId, attribute: AttributeId) -> Self {
        Self {
            endpoint,
            cluster,
            attribute,
        }
    }

    /// ワイヤ表現の [`AttributePath`] へ変換する。
    pub const fn to_wire(self) -> AttributePath {
        AttributePath::from_concrete(self)
    }
}

// ==========================================================================
// StatusResponse(OpCode 0x01)
// ==========================================================================

/// StatusResponse メッセージ(`{ status: ImStatus(0), imRevision(0xFF) }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusResponse {
    /// ステータスコード。
    pub status: ImStatus,
}

impl StatusResponse {
    /// 新しい [`StatusResponse`] を作る。
    pub const fn new(status: ImStatus) -> Self {
        Self { status }
    }

    /// メッセージを `tx` に書き、書き込みバイト数を返す。
    pub fn encode(&self, tx: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(tx);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u8(&TlvTag::ContextSpecific(0), self.status.to_u8())?;
        end_msg(&mut w)
    }

    /// メッセージバイト列をデコードする。
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let status = ImStatus::from_u8(field_u8(msg, 0)?.ok_or(Error::Decode)?)?;
        Ok(Self { status })
    }
}

// ==========================================================================
// TimedRequest(OpCode 0x0a)
// ==========================================================================

/// TimedRequest メッセージ(`{ timeout_ms: u16(0), imRevision(0xFF) }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedRequest {
    /// タイムアウト(ミリ秒)。後続の Write/Invoke の期限。
    pub timeout_ms: u16,
}

impl TimedRequest {
    /// 新しい [`TimedRequest`] を作る。
    pub const fn new(timeout_ms: u16) -> Self {
        Self { timeout_ms }
    }

    /// メッセージを `tx` に書き、書き込みバイト数を返す。
    pub fn encode(&self, tx: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(tx);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u16(&TlvTag::ContextSpecific(0), self.timeout_ms)?;
        end_msg(&mut w)
    }

    /// メッセージバイト列をデコードする。
    pub fn decode(msg: &[u8]) -> Result<Self> {
        let timeout_ms = field_u16(msg, 0)?.ok_or(Error::Decode)?;
        Ok(Self { timeout_ms })
    }
}

// ==========================================================================
// SubscribeResponse(OpCode 0x04)
// ==========================================================================

/// SubscribeResponse メッセージ(`{ subscription_id: u32(0), max_interval_s: u16(1), imRevision }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeResponse {
    /// 購読 ID。
    pub subscription_id: u32,
    /// ネゴシエート済み最大インターバル(秒)。
    pub max_interval_s: u16,
}

impl SubscribeResponse {
    /// 新しい [`SubscribeResponse`] を作る。
    pub const fn new(subscription_id: u32, max_interval_s: u16) -> Self {
        Self {
            subscription_id,
            max_interval_s,
        }
    }

    /// メッセージを `tx` に書き、書き込みバイト数を返す。
    pub fn encode(&self, tx: &mut [u8]) -> Result<usize> {
        let mut w = TlvWriter::new(tx);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u32(&TlvTag::ContextSpecific(0), self.subscription_id)?;
        w.write_u16(&TlvTag::ContextSpecific(1), self.max_interval_s)?;
        end_msg(&mut w)
    }

    /// メッセージバイト列をデコードする。
    pub fn decode(msg: &[u8]) -> Result<Self> {
        Ok(Self {
            subscription_id: field_u32(msg, 0)?.ok_or(Error::Decode)?,
            max_interval_s: field_u16(msg, 1)?.ok_or(Error::Decode)?,
        })
    }
}

// ==========================================================================
// ReadRequest(OpCode 0x02)
// ==========================================================================

/// ReadRequest の借用デコードビュー。
///
/// `ReadReqTag`: AttrRequests=0, EventRequests=1, EventFilters=2, FabricFiltered=3,
/// DataVersionFilters=4。属性パスは遅延イテレータで取り出す。
#[derive(Debug, Clone, Copy)]
pub struct ReadRequestRef<'a> {
    msg: &'a [u8],
}

impl<'a> ReadRequestRef<'a> {
    /// メッセージバイト列をラップする(構造体であることのみ検証)。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        // トップレベルが anonymous 構造体であることを確認。
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 属性パス列(`AttributePathIBs`)のイテレータを返す。
    pub fn attr_paths(&self) -> Result<AttrPathIter<'a>> {
        array_iter(self.msg, 0)
    }

    /// fabric-filtered フラグ(既定 `false`)。
    pub fn fabric_filtered(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 3)?.unwrap_or(false))
    }
}

/// ReadRequest をエンコードする(属性パスのみ。EventPath/DataVersionFilter は初期未対応)。
///
/// `paths` クロージャで [`AttrPathListWriter`] にパスを積む。
pub fn encode_read_request(
    tx: &mut [u8],
    fabric_filtered: bool,
    paths: impl FnOnce(&mut AttrPathListWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.start_array(&TlvTag::ContextSpecific(0))?;
    paths(&mut AttrPathListWriter { w: &mut w })?;
    w.end_container()?;
    w.write_bool(&TlvTag::ContextSpecific(3), fabric_filtered)?;
    end_msg(&mut w)
}

// ==========================================================================
// SubscribeRequest(OpCode 0x03)
// ==========================================================================

/// SubscribeRequest の借用デコードビュー。
///
/// `SubscribeReqTag`: KeepSubs=0, MinIntFloor=1, MaxIntCeil=2, AttrRequests=3,
/// EventRequests=4, EventFilters=5, FabricFiltered=7, DataVersionFilters=8(タグ 6 は予約)。
#[derive(Debug, Clone, Copy)]
pub struct SubscribeRequestRef<'a> {
    msg: &'a [u8],
}

impl<'a> SubscribeRequestRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 既存購読を維持するか(`KeepSubscriptions`、既定 `false`)。
    pub fn keep_existing(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 0)?.unwrap_or(false))
    }

    /// 最小インターバル下限(秒)。
    pub fn min_interval_floor_s(&self) -> Result<u16> {
        field_u16(self.msg, 1)?.ok_or(Error::Decode)
    }

    /// 最大インターバル上限(秒)。
    pub fn max_interval_ceiling_s(&self) -> Result<u16> {
        field_u16(self.msg, 2)?.ok_or(Error::Decode)
    }

    /// 属性パス列のイテレータを返す。
    pub fn attr_paths(&self) -> Result<AttrPathIter<'a>> {
        array_iter(self.msg, 3)
    }

    /// fabric-filtered フラグ(既定 `false`)。
    pub fn fabric_filtered(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 7)?.unwrap_or(false))
    }
}

/// SubscribeRequest をエンコードする(属性パスのみ)。
pub fn encode_subscribe_request(
    tx: &mut [u8],
    keep_existing: bool,
    min_interval_floor_s: u16,
    max_interval_ceiling_s: u16,
    fabric_filtered: bool,
    paths: impl FnOnce(&mut AttrPathListWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bool(&TlvTag::ContextSpecific(0), keep_existing)?;
    w.write_u16(&TlvTag::ContextSpecific(1), min_interval_floor_s)?;
    w.write_u16(&TlvTag::ContextSpecific(2), max_interval_ceiling_s)?;
    w.start_array(&TlvTag::ContextSpecific(3))?;
    paths(&mut AttrPathListWriter { w: &mut w })?;
    w.end_container()?;
    w.write_bool(&TlvTag::ContextSpecific(7), fabric_filtered)?;
    end_msg(&mut w)
}

// ==========================================================================
// ReportData(OpCode 0x05)
// ==========================================================================

/// ReportData のヘッダ(繰り返しでない共通フィールド)。
///
/// `ReportDataRespTag`: SubscriptionId=0, AttributeReports=1, EventReports=2,
/// MoreChunkedMessages=3, SuppressResponse=4。
#[derive(Debug, Clone, Copy, Default)]
pub struct ReportDataHeader {
    /// 購読 ID(購読レポート時のみ `Some`)。
    pub subscription_id: Option<u32>,
    /// まだチャンクが続くか(`MoreChunkedMessages`)。
    pub more_chunks: bool,
    /// 応答抑制(`SuppressResponse`)。
    pub suppress_response: bool,
}

/// ReportData をエンコードする。
///
/// `reports` クロージャで [`AttrReportWriter`] に `AttributeReportIB` を積む。ヘッダの
/// `subscription_id` は AttributeReports 配列の前に、`more_chunks`/`suppress_response` は
/// 配列の後に書く(仕様のタグ順)。
pub fn encode_report_data(
    tx: &mut [u8],
    header: ReportDataHeader,
    reports: impl FnOnce(&mut AttrReportWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    if let Some(id) = header.subscription_id {
        w.write_u32(&TlvTag::ContextSpecific(0), id)?;
    }
    w.start_array(&TlvTag::ContextSpecific(1))?;
    reports(&mut AttrReportWriter { w: &mut w })?;
    w.end_container()?;
    if header.more_chunks {
        w.write_bool(&TlvTag::ContextSpecific(3), true)?;
    }
    if header.suppress_response {
        w.write_bool(&TlvTag::ContextSpecific(4), true)?;
    }
    end_msg(&mut w)
}

/// ReportData の借用デコードビュー。
#[derive(Debug, Clone, Copy)]
pub struct ReportDataRef<'a> {
    msg: &'a [u8],
}

impl<'a> ReportDataRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 購読 ID(あれば)。
    pub fn subscription_id(&self) -> Result<Option<u32>> {
        field_u32(self.msg, 0)
    }

    /// `MoreChunkedMessages`(既定 `false`)。
    pub fn more_chunks(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 3)?.unwrap_or(false))
    }

    /// `SuppressResponse`(既定 `false`)。
    pub fn suppress_response(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 4)?.unwrap_or(false))
    }

    /// `AttributeReportIB` 列のイテレータを返す。
    pub fn attr_reports(&self) -> Result<AttrReportIter<'a>> {
        match field_reader(self.msg, 1)? {
            None => Ok(AttrReportIter::empty()),
            Some(mut r) => {
                if r.enter_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                Ok(AttrReportIter { r, done: false })
            }
        }
    }
}

// ==========================================================================
// WriteRequest / WriteResponse(OpCode 0x06 / 0x07)
// ==========================================================================

/// WriteRequest のヘッダ。
///
/// `WriteReqTag`: SuppressResponse=0, TimedRequest=1, WriteRequests=2, MoreChunked=3。
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteRequestHeader {
    /// 応答抑制。
    pub suppress_response: bool,
    /// 直前の TimedRequest と対応する Write か。
    pub timed_request: bool,
}

/// WriteRequest をエンコードする。`writes` クロージャで [`AttrDataWriter`] にデータを積む。
pub fn encode_write_request(
    tx: &mut [u8],
    header: WriteRequestHeader,
    writes: impl FnOnce(&mut AttrDataWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bool(&TlvTag::ContextSpecific(0), header.suppress_response)?;
    w.write_bool(&TlvTag::ContextSpecific(1), header.timed_request)?;
    w.start_array(&TlvTag::ContextSpecific(2))?;
    writes(&mut AttrDataWriter { w: &mut w })?;
    w.end_container()?;
    end_msg(&mut w)
}

/// WriteRequest の借用デコードビュー。
#[derive(Debug, Clone, Copy)]
pub struct WriteRequestRef<'a> {
    msg: &'a [u8],
}

impl<'a> WriteRequestRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 応答抑制(既定 `false`)。
    pub fn suppress_response(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 0)?.unwrap_or(false))
    }

    /// TimedRequest フラグ(既定 `false`)。
    pub fn timed_request(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 1)?.unwrap_or(false))
    }

    /// `AttributeDataIB` 列のイテレータを返す。
    pub fn write_requests(&self) -> Result<AttrDataIter<'a>> {
        match field_reader(self.msg, 2)? {
            None => Ok(AttrDataIter::empty()),
            Some(mut r) => {
                if r.enter_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                Ok(AttrDataIter { r, done: false })
            }
        }
    }
}

/// WriteResponse をエンコードする(`WriteResponses=0` の配列 = `AttributeStatusIB` 列)。
pub fn encode_write_response(
    tx: &mut [u8],
    statuses: impl FnOnce(&mut AttrStatusWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.start_array(&TlvTag::ContextSpecific(0))?;
    statuses(&mut AttrStatusWriter { w: &mut w })?;
    w.end_container()?;
    end_msg(&mut w)
}

/// WriteResponse の借用デコードビュー。
#[derive(Debug, Clone, Copy)]
pub struct WriteResponseRef<'a> {
    msg: &'a [u8],
}

impl<'a> WriteResponseRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// `AttributeStatusIB` 列のイテレータを返す。
    pub fn write_responses(&self) -> Result<AttrStatusIter<'a>> {
        match field_reader(self.msg, 0)? {
            None => Ok(AttrStatusIter::empty()),
            Some(mut r) => {
                if r.enter_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                Ok(AttrStatusIter { r, done: false })
            }
        }
    }
}

// ==========================================================================
// InvokeRequest / InvokeResponse(OpCode 0x08 / 0x09)
// ==========================================================================

/// InvokeRequest のヘッダ。
///
/// `InvReqTag`: SuppressResponse=0, TimedRequest=1, InvokeRequests=2。
#[derive(Debug, Clone, Copy, Default)]
pub struct InvokeRequestHeader {
    /// 応答抑制。
    pub suppress_response: bool,
    /// 直前の TimedRequest と対応する Invoke か。
    pub timed_request: bool,
}

/// InvokeRequest をエンコードする。`commands` クロージャで [`CmdDataWriter`] にデータを積む。
pub fn encode_invoke_request(
    tx: &mut [u8],
    header: InvokeRequestHeader,
    commands: impl FnOnce(&mut CmdDataWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bool(&TlvTag::ContextSpecific(0), header.suppress_response)?;
    w.write_bool(&TlvTag::ContextSpecific(1), header.timed_request)?;
    w.start_array(&TlvTag::ContextSpecific(2))?;
    commands(&mut CmdDataWriter { w: &mut w })?;
    w.end_container()?;
    end_msg(&mut w)
}

/// InvokeRequest の借用デコードビュー。
#[derive(Debug, Clone, Copy)]
pub struct InvokeRequestRef<'a> {
    msg: &'a [u8],
}

impl<'a> InvokeRequestRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 応答抑制(既定 `false`)。
    pub fn suppress_response(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 0)?.unwrap_or(false))
    }

    /// TimedRequest フラグ(既定 `false`)。
    pub fn timed_request(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 1)?.unwrap_or(false))
    }

    /// `CommandDataIB` 列のイテレータを返す。
    pub fn invoke_requests(&self) -> Result<CmdDataIter<'a>> {
        match field_reader(self.msg, 2)? {
            None => Ok(CmdDataIter::empty()),
            Some(mut r) => {
                if r.enter_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                Ok(CmdDataIter { r, done: false })
            }
        }
    }
}

/// InvokeResponse のヘッダ。
///
/// InvokeResponseMessage: SuppressResponse=0, InvokeResponses=1, MoreChunkedMessages=2。
#[derive(Debug, Clone, Copy, Default)]
pub struct InvokeResponseHeader {
    /// 応答抑制(リクエストのエコー)。
    pub suppress_response: bool,
    /// まだチャンクが続くか。
    pub more_chunks: bool,
}

/// InvokeResponse をエンコードする。`responses` クロージャで [`CmdRespWriter`] に積む。
pub fn encode_invoke_response(
    tx: &mut [u8],
    header: InvokeResponseHeader,
    responses: impl FnOnce(&mut CmdRespWriter<'_, '_>) -> Result<()>,
) -> Result<usize> {
    let mut w = TlvWriter::new(tx);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bool(&TlvTag::ContextSpecific(0), header.suppress_response)?;
    w.start_array(&TlvTag::ContextSpecific(1))?;
    responses(&mut CmdRespWriter { w: &mut w })?;
    w.end_container()?;
    if header.more_chunks {
        w.write_bool(&TlvTag::ContextSpecific(2), true)?;
    }
    end_msg(&mut w)
}

/// InvokeResponse の借用デコードビュー。
#[derive(Debug, Clone, Copy)]
pub struct InvokeResponseRef<'a> {
    msg: &'a [u8],
}

impl<'a> InvokeResponseRef<'a> {
    /// メッセージバイト列をラップする。
    pub fn new(msg: &'a [u8]) -> Result<Self> {
        let _ = open_struct(msg)?;
        Ok(Self { msg })
    }

    /// 応答抑制(既定 `false`)。
    pub fn suppress_response(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 0)?.unwrap_or(false))
    }

    /// `MoreChunkedMessages`(既定 `false`)。
    pub fn more_chunks(&self) -> Result<bool> {
        Ok(field_bool(self.msg, 2)?.unwrap_or(false))
    }

    /// `InvokeResponseIB` 列のイテレータを返す。
    pub fn invoke_responses(&self) -> Result<InvokeRespIter<'a>> {
        match field_reader(self.msg, 1)? {
            None => Ok(InvokeRespIter::empty()),
            Some(mut r) => {
                if r.enter_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                Ok(InvokeRespIter { r, done: false })
            }
        }
    }
}

// ==========================================================================
// IB デコードビュー
// ==========================================================================

/// AttributeDataIB の借用デコードビュー(`{ dataVer(0)?, path(1), data(2) }`)。
#[derive(Debug, Clone, Copy)]
pub struct AttributeDataRef<'a> {
    /// クラスタ DataVersion(あれば)。
    pub data_version: Option<u32>,
    /// 属性パス。
    pub path: AttributePath,
    /// 値要素の生 TLV バイト列(元の context タグ 2 を含む)。[`transcribe`] で転写できる。
    pub data: &'a [u8],
}

impl<'a> AttributeDataRef<'a> {
    /// 値を読むための [`TlvReader`] を返す(先頭要素のタグは context 2)。
    pub fn value(&self) -> TlvReader<'a> {
        TlvReader::new(self.data)
    }

    /// AttributeDataIB 構造体の本体を読む(構造体開始を消費済みの状態から)。
    fn decode_body(r: &mut TlvReader<'a>) -> Result<Self> {
        let mut data_version = None;
        let mut path = None;
        let mut data = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => data_version = Some(read_u32(r)?),
                1 => path = Some(AttributePath::decode(r)?),
                2 => data = Some(r.take_element_raw()?),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            data_version,
            path: path.ok_or(Error::Decode)?,
            data: data.ok_or(Error::Decode)?,
        })
    }
}

/// AttributeStatusIB の借用デコードビュー(`{ path(0), status(1) }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeStatusRef {
    /// 属性パス。
    pub path: AttributePath,
    /// StatusIB。
    pub status: StatusIB,
}

impl AttributeStatusRef {
    fn decode_body(r: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut status = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => path = Some(AttributePath::decode(r)?),
                1 => status = Some(StatusIB::decode(r)?),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::Decode)?,
            status: status.ok_or(Error::Decode)?,
        })
    }
}

/// AttributeReportIB の借用デコードビュー(`{ attributeStatus(0) | attributeData(1) }`)。
#[derive(Debug, Clone, Copy)]
pub enum AttributeReportRef<'a> {
    /// 値レポート(`AttributeDataIB`)。
    Data(AttributeDataRef<'a>),
    /// ステータス(`AttributeStatusIB`)。
    Status(AttributeStatusRef),
}

impl<'a> AttributeReportRef<'a> {
    fn decode_body(r: &mut TlvReader<'a>) -> Result<Self> {
        let mut out = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => {
                    expect_container(r, ContainerType::Structure)?;
                    out = Some(Self::Status(AttributeStatusRef::decode_body(r)?));
                }
                1 => {
                    expect_container(r, ContainerType::Structure)?;
                    out = Some(Self::Data(AttributeDataRef::decode_body(r)?));
                }
                _ => skip_field(r)?,
            }
        }
        out.ok_or(Error::Decode)
    }
}

/// CommandDataIB の借用デコードビュー(`{ path(0), fields(1)?, commandRef(2)? }`)。
#[derive(Debug, Clone, Copy)]
pub struct CommandDataRef<'a> {
    /// コマンドパス。
    pub path: CommandPath,
    /// コマンドフィールドの生 TLV バイト列(あれば。元の context タグ 1 を含む)。
    pub fields: Option<&'a [u8]>,
    /// バッチ Invoke 用の CommandRef(あれば)。
    pub command_ref: Option<u16>,
}

impl<'a> CommandDataRef<'a> {
    fn decode_body(r: &mut TlvReader<'a>) -> Result<Self> {
        let mut path = None;
        let mut fields = None;
        let mut command_ref = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => path = Some(CommandPath::decode(r)?),
                1 => fields = Some(r.take_element_raw()?),
                2 => command_ref = Some(read_u16(r)?),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::Decode)?,
            fields,
            command_ref,
        })
    }
}

/// CommandStatusIB の借用デコードビュー(`{ path(0), status(1), commandRef(2)? }`)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandStatusRef {
    /// コマンドパス。
    pub path: CommandPath,
    /// StatusIB。
    pub status: StatusIB,
    /// CommandRef(あれば)。
    pub command_ref: Option<u16>,
}

impl CommandStatusRef {
    fn decode_body(r: &mut TlvReader<'_>) -> Result<Self> {
        let mut path = None;
        let mut status = None;
        let mut command_ref = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => path = Some(CommandPath::decode(r)?),
                1 => status = Some(StatusIB::decode(r)?),
                2 => command_ref = Some(read_u16(r)?),
                _ => skip_field(r)?,
            }
        }
        Ok(Self {
            path: path.ok_or(Error::Decode)?,
            status: status.ok_or(Error::Decode)?,
            command_ref,
        })
    }
}

/// InvokeResponseIB の借用デコードビュー(`{ command(0) | status(1) }`)。
#[derive(Debug, Clone, Copy)]
pub enum InvokeResponseRefItem<'a> {
    /// コマンド応答(`CommandDataIB`)。
    Command(CommandDataRef<'a>),
    /// ステータス(`CommandStatusIB`)。
    Status(CommandStatusRef),
}

impl<'a> InvokeResponseRefItem<'a> {
    fn decode_body(r: &mut TlvReader<'a>) -> Result<Self> {
        let mut out = None;
        while let Some(tag) = next_ctx(r)? {
            match tag {
                0 => {
                    expect_container(r, ContainerType::Structure)?;
                    out = Some(Self::Command(CommandDataRef::decode_body(r)?));
                }
                1 => {
                    expect_container(r, ContainerType::Structure)?;
                    out = Some(Self::Status(CommandStatusRef::decode_body(r)?));
                }
                _ => skip_field(r)?,
            }
        }
        out.ok_or(Error::Decode)
    }
}

// ==========================================================================
// リストライタ(エンコード側、クロージャに渡す)
// ==========================================================================

/// `AttributePathIBs` 配列にパスを積むライタ。
#[derive(Debug)]
pub struct AttrPathListWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl AttrPathListWriter<'_, '_> {
    /// 1 つの [`AttributePath`] を配列要素として書く。
    pub fn push(&mut self, path: &AttributePath) -> Result<()> {
        path.encode(self.w, &TlvTag::Anonymous)
    }
}

/// `AttributeReportIBs` 配列に `AttributeReportIB` を積むライタ。
#[derive(Debug)]
pub struct AttrReportWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl AttrReportWriter<'_, '_> {
    /// 値レポート(`AttributeDataIB`)を書く。`value` は値要素を `tag`(context 2)で書く。
    pub fn push_data(
        &mut self,
        data_version: Option<u32>,
        path: &AttributePath,
        value: impl FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    ) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        self.w.start_struct(&TlvTag::ContextSpecific(1))?; // AttributeDataIB
        if let Some(dv) = data_version {
            self.w.write_u32(&TlvTag::ContextSpecific(0), dv)?;
        }
        path.encode(self.w, &TlvTag::ContextSpecific(1))?;
        value(self.w, &TlvTag::ContextSpecific(2))?;
        self.w.end_container()?;
        self.w.end_container()
    }

    /// ステータス(`AttributeStatusIB`)を書く。
    pub fn push_status(&mut self, path: &AttributePath, status: &StatusIB) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        self.w.start_struct(&TlvTag::ContextSpecific(0))?; // AttributeStatusIB
        path.encode(self.w, &TlvTag::ContextSpecific(0))?;
        status.encode(self.w, &TlvTag::ContextSpecific(1))?;
        self.w.end_container()?;
        self.w.end_container()
    }

    /// これまでに 1 件以上書き込んだかを返す(チャンク境界判定の補助)。
    pub fn is_empty(&self) -> bool {
        self.w.is_empty()
    }
}

/// `AttributeDataIBs` 配列(WriteRequest)にデータを積むライタ。
#[derive(Debug)]
pub struct AttrDataWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl AttrDataWriter<'_, '_> {
    /// 1 つの `AttributeDataIB` を書く。`value` は値要素を `tag`(context 2)で書く。
    pub fn push(
        &mut self,
        data_version: Option<u32>,
        path: &AttributePath,
        value: impl FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    ) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        if let Some(dv) = data_version {
            self.w.write_u32(&TlvTag::ContextSpecific(0), dv)?;
        }
        path.encode(self.w, &TlvTag::ContextSpecific(1))?;
        value(self.w, &TlvTag::ContextSpecific(2))?;
        self.w.end_container()
    }
}

/// `AttributeStatusIBs` 配列(WriteResponse)にステータスを積むライタ。
#[derive(Debug)]
pub struct AttrStatusWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl AttrStatusWriter<'_, '_> {
    /// 1 つの `AttributeStatusIB` を書く。
    pub fn push(&mut self, path: &AttributePath, status: &StatusIB) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        path.encode(self.w, &TlvTag::ContextSpecific(0))?;
        status.encode(self.w, &TlvTag::ContextSpecific(1))?;
        self.w.end_container()
    }
}

/// `CommandDataIBs` 配列(InvokeRequest)にコマンドを積むライタ。
#[derive(Debug)]
pub struct CmdDataWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl CmdDataWriter<'_, '_> {
    /// 1 つの `CommandDataIB` を書く。`fields` はコマンドフィールドを `tag`(context 1)で書く。
    /// フィールドが無いコマンドは `fields` を `None` にする。
    pub fn push(
        &mut self,
        path: &CommandPath,
        command_ref: Option<u16>,
        fields: Option<impl FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>>,
    ) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        path.encode(self.w, &TlvTag::ContextSpecific(0))?;
        if let Some(f) = fields {
            f(self.w, &TlvTag::ContextSpecific(1))?;
        }
        if let Some(cr) = command_ref {
            self.w.write_u16(&TlvTag::ContextSpecific(2), cr)?;
        }
        self.w.end_container()
    }
}

/// `InvokeResponseIBs` 配列に `InvokeResponseIB` を積むライタ。
#[derive(Debug)]
pub struct CmdRespWriter<'w, 'b> {
    w: &'w mut TlvWriter<'b>,
}

impl CmdRespWriter<'_, '_> {
    /// コマンド応答(`CommandDataIB`)を書く。`fields` は応答フィールドを `tag`(context 1)で書く。
    pub fn push_command(
        &mut self,
        path: &CommandPath,
        command_ref: Option<u16>,
        fields: impl FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    ) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        self.w.start_struct(&TlvTag::ContextSpecific(0))?; // command = CommandDataIB
        path.encode(self.w, &TlvTag::ContextSpecific(0))?;
        fields(self.w, &TlvTag::ContextSpecific(1))?;
        if let Some(cr) = command_ref {
            self.w.write_u16(&TlvTag::ContextSpecific(2), cr)?;
        }
        self.w.end_container()?;
        self.w.end_container()
    }

    /// ステータス(`CommandStatusIB`)を書く。
    pub fn push_status(
        &mut self,
        path: &CommandPath,
        status: &StatusIB,
        command_ref: Option<u16>,
    ) -> Result<()> {
        self.w.start_struct(&TlvTag::Anonymous)?;
        self.w.start_struct(&TlvTag::ContextSpecific(1))?; // status = CommandStatusIB
        path.encode(self.w, &TlvTag::ContextSpecific(0))?;
        status.encode(self.w, &TlvTag::ContextSpecific(1))?;
        if let Some(cr) = command_ref {
            self.w.write_u16(&TlvTag::ContextSpecific(2), cr)?;
        }
        self.w.end_container()?;
        self.w.end_container()
    }
}

// ==========================================================================
// デコードイテレータ
// ==========================================================================

/// [`AttributePath`] の配列イテレータ。
#[derive(Debug, Clone)]
pub struct AttrPathIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl AttrPathIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl Iterator for AttrPathIter<'_> {
    type Item = Result<AttributePath>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_list_element(&mut self.r, &mut self.done, AttributePath::decode_body)
    }
}

/// [`AttributeReportRef`] の配列イテレータ。
#[derive(Debug, Clone)]
pub struct AttrReportIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl AttrReportIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl<'a> Iterator for AttrReportIter<'a> {
    type Item = Result<AttributeReportRef<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_struct_element(&mut self.r, &mut self.done, AttributeReportRef::decode_body)
    }
}

/// [`AttributeDataRef`] の配列イテレータ(WriteRequest 用)。
#[derive(Debug, Clone)]
pub struct AttrDataIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl AttrDataIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl<'a> Iterator for AttrDataIter<'a> {
    type Item = Result<AttributeDataRef<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_struct_element(&mut self.r, &mut self.done, AttributeDataRef::decode_body)
    }
}

/// [`AttributeStatusRef`] の配列イテレータ(WriteResponse 用)。
#[derive(Debug, Clone)]
pub struct AttrStatusIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl AttrStatusIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl Iterator for AttrStatusIter<'_> {
    type Item = Result<AttributeStatusRef>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_struct_element(&mut self.r, &mut self.done, AttributeStatusRef::decode_body)
    }
}

/// [`CommandDataRef`] の配列イテレータ(InvokeRequest 用)。
#[derive(Debug, Clone)]
pub struct CmdDataIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl CmdDataIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl<'a> Iterator for CmdDataIter<'a> {
    type Item = Result<CommandDataRef<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_struct_element(&mut self.r, &mut self.done, CommandDataRef::decode_body)
    }
}

/// [`InvokeResponseRefItem`] の配列イテレータ(InvokeResponse 用)。
#[derive(Debug, Clone)]
pub struct InvokeRespIter<'a> {
    r: TlvReader<'a>,
    done: bool,
}

impl InvokeRespIter<'_> {
    fn empty() -> Self {
        Self {
            r: TlvReader::new(&[]),
            done: true,
        }
    }
}

impl<'a> Iterator for InvokeRespIter<'a> {
    type Item = Result<InvokeResponseRefItem<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        iter_struct_element(
            &mut self.r,
            &mut self.done,
            InvokeResponseRefItem::decode_body,
        )
    }
}

// ==========================================================================
// 値の転写(生スライス → 別タグへ移し替え)
// ==========================================================================

/// 生 TLV 要素 `src`(先頭 1 要素)を、`tag` を付け替えて `w` に転写する。
///
/// [`AttributeDataRef::data`] 等の生スライスを、別の context タグの下へ書き直す用途に使う。
/// 整数は最小幅で正規化して再エンコードされる(Matter TLV では幅は意味を持たないため妥当)。
/// 入れ子コンテナは子要素を元のタグのまま再帰的にコピーする。
pub fn transcribe(src: &[u8], w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()> {
    let mut r = TlvReader::new(src);
    let first = r.read_next()?.ok_or(Error::Decode)?;
    let is_container = matches!(first.value, TlvValue::ContainerStart(_));
    write_token(w, tag, &first.value)?;
    if !is_container {
        return Ok(());
    }
    let mut depth = 1usize;
    while depth > 0 {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match e.value {
            TlvValue::ContainerStart(_) => {
                depth += 1;
                write_token(w, &e.tag, &e.value)?;
            }
            TlvValue::ContainerEnd => {
                depth -= 1;
                w.end_container()?;
            }
            _ => write_token(w, &e.tag, &e.value)?,
        }
    }
    Ok(())
}

/// 1 つの TLV トークンを `tag` 付きで `w` に書く(コンテナ終端はタグを無視)。
fn write_token(w: &mut TlvWriter<'_>, tag: &TlvTag, value: &TlvValue<'_>) -> Result<()> {
    match *value {
        TlvValue::SignedInteger(v) => w.write_i64(tag, v),
        TlvValue::UnsignedInteger(v) => w.write_u64(tag, v),
        TlvValue::Boolean(v) => w.write_bool(tag, v),
        TlvValue::Float(v) => w.write_f32(tag, v),
        TlvValue::Double(v) => w.write_f64(tag, v),
        TlvValue::Utf8String(v) => w.write_utf8(tag, v),
        TlvValue::ByteString(v) => w.write_bytes(tag, v),
        TlvValue::Null => w.write_null(tag),
        TlvValue::ContainerStart(t) => w.start_container(tag, t),
        TlvValue::ContainerEnd => w.end_container(),
    }
}

// ==========================================================================
// 内部ヘルパ
// ==========================================================================

/// メッセージ(anonymous 構造体)を開き、構造体内部に位置するリーダを返す。
fn open_struct(msg: &[u8]) -> Result<TlvReader<'_>> {
    let mut r = TlvReader::new(msg);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    Ok(r)
}

/// 構造体内の context タグ `tag` を持つフィールドの直前に位置するリーダのクローンを返す。
/// 見つからなければ `None`。
fn field_reader(msg: &[u8], tag: u8) -> Result<Option<TlvReader<'_>>> {
    let mut r = open_struct(msg)?;
    loop {
        let before = r.clone();
        match r.read_next()? {
            None => return Ok(None),
            Some(e) if matches!(e.value, TlvValue::ContainerEnd) => return Ok(None),
            Some(e) => {
                if e.tag == TlvTag::ContextSpecific(tag) {
                    return Ok(Some(before));
                }
                r.skip(&e)?;
            }
        }
    }
}

/// スカラーフィールドを 1 要素だけ読む共通処理。
fn field_scalar(msg: &[u8], tag: u8) -> Result<Option<TlvValue<'_>>> {
    match field_reader(msg, tag)? {
        None => Ok(None),
        Some(mut r) => Ok(Some(r.read_next()?.ok_or(Error::Decode)?.value)),
    }
}

fn field_u8(msg: &[u8], tag: u8) -> Result<Option<u8>> {
    match field_scalar(msg, tag)? {
        None => Ok(None),
        Some(v) => Ok(Some(
            u8::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)?,
        )),
    }
}

fn field_u16(msg: &[u8], tag: u8) -> Result<Option<u16>> {
    match field_scalar(msg, tag)? {
        None => Ok(None),
        Some(v) => Ok(Some(
            u16::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)?,
        )),
    }
}

fn field_u32(msg: &[u8], tag: u8) -> Result<Option<u32>> {
    match field_scalar(msg, tag)? {
        None => Ok(None),
        Some(v) => Ok(Some(
            u32::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)?,
        )),
    }
}

fn field_bool(msg: &[u8], tag: u8) -> Result<Option<bool>> {
    match field_scalar(msg, tag)? {
        None => Ok(None),
        Some(v) => Ok(Some(v.as_bool()?)),
    }
}

/// 構造体内の配列フィールド `tag` の [`AttrPathIter`] を返す。無ければ空。
fn array_iter(msg: &[u8], tag: u8) -> Result<AttrPathIter<'_>> {
    match field_reader(msg, tag)? {
        None => Ok(AttrPathIter::empty()),
        Some(mut r) => {
            if r.enter_container()? != ContainerType::Array {
                return Err(Error::Decode);
            }
            Ok(AttrPathIter { r, done: false })
        }
    }
}

/// 構造体/list の次の context タグ番号を「消費せずに」返す。
///
/// 構造体/コンテナ終端(`ContainerEnd`)に達したら終端を消費して `None` を返す。
/// context 以外のタグは [`Error::Decode`]。返り値が `Some` のとき `r` は当該要素の
/// 制御バイト直前に留まる(呼び出し側が値を読む)。
fn next_ctx(r: &mut TlvReader<'_>) -> Result<Option<u8>> {
    let mut probe = r.clone();
    match probe.read_next()? {
        // コンテナ本体の走査中に EOF は閉じ忘れ(切り詰め)= 不正。
        None => Err(Error::Decode),
        Some(e) => match e.value {
            TlvValue::ContainerEnd => {
                *r = probe;
                Ok(None)
            }
            _ => match e.tag {
                TlvTag::ContextSpecific(t) => Ok(Some(t)),
                _ => Err(Error::Decode),
            },
        },
    }
}

/// `next_ctx` で得たフィールドを 1 つ読み飛ばす(スカラー/コンテナどちらも)。
fn skip_field(r: &mut TlvReader<'_>) -> Result<()> {
    r.take_element_raw().map(|_| ())
}

/// `next_ctx` 後のスカラー u8 を読む。
fn read_u8(r: &mut TlvReader<'_>) -> Result<u8> {
    let v = r.read_next()?.ok_or(Error::Decode)?.value.as_unsigned()?;
    u8::try_from(v).map_err(|_| Error::Decode)
}

fn read_u16(r: &mut TlvReader<'_>) -> Result<u16> {
    let v = r.read_next()?.ok_or(Error::Decode)?.value.as_unsigned()?;
    u16::try_from(v).map_err(|_| Error::Decode)
}

fn read_u32(r: &mut TlvReader<'_>) -> Result<u32> {
    let v = r.read_next()?.ok_or(Error::Decode)?.value.as_unsigned()?;
    u32::try_from(v).map_err(|_| Error::Decode)
}

fn read_bool(r: &mut TlvReader<'_>) -> Result<bool> {
    r.read_next()?.ok_or(Error::Decode)?.value.as_bool()
}

/// 次の要素が期待するコンテナ開始であることを確認して消費する。
fn expect_container(r: &mut TlvReader<'_>, want: ContainerType) -> Result<()> {
    if r.enter_container()? == want {
        Ok(())
    } else {
        Err(Error::Decode)
    }
}

/// list 要素(`AttributePath` のような list)の配列イテレータ 1 ステップ。
fn iter_list_element<'a, T>(
    r: &mut TlvReader<'a>,
    done: &mut bool,
    decode_body: impl FnOnce(&mut TlvReader<'a>) -> Result<T>,
) -> Option<Result<T>> {
    if *done {
        return None;
    }
    let e = match r.read_next() {
        Ok(Some(e)) => e,
        Ok(None) => {
            *done = true;
            return None;
        }
        Err(err) => {
            *done = true;
            return Some(Err(err));
        }
    };
    match e.value {
        TlvValue::ContainerEnd => {
            *done = true;
            None
        }
        TlvValue::ContainerStart(ContainerType::List) => match decode_body(r) {
            Ok(v) => Some(Ok(v)),
            Err(err) => {
                *done = true;
                Some(Err(err))
            }
        },
        _ => {
            *done = true;
            Some(Err(Error::Decode))
        }
    }
}

/// 構造体要素(IB のような struct)の配列イテレータ 1 ステップ。
fn iter_struct_element<'a, T>(
    r: &mut TlvReader<'a>,
    done: &mut bool,
    decode_body: impl FnOnce(&mut TlvReader<'a>) -> Result<T>,
) -> Option<Result<T>> {
    if *done {
        return None;
    }
    let e = match r.read_next() {
        Ok(Some(e)) => e,
        Ok(None) => {
            *done = true;
            return None;
        }
        Err(err) => {
            *done = true;
            return Some(Err(err));
        }
    };
    match e.value {
        TlvValue::ContainerEnd => {
            *done = true;
            None
        }
        TlvValue::ContainerStart(ContainerType::Structure) => match decode_body(r) {
            Ok(v) => Some(Ok(v)),
            Err(err) => {
                *done = true;
                Some(Err(err))
            }
        },
        _ => {
            *done = true;
            Some(Err(Error::Decode))
        }
    }
}

/// メッセージ末尾に `InteractionModelRevision`(context 0xFF)を書き、構造体を閉じて長さを返す。
fn end_msg(w: &mut TlvWriter<'_>) -> Result<usize> {
    w.write_u8(
        &TlvTag::ContextSpecific(IM_REVISION_TAG),
        INTERACTION_MODEL_REVISION,
    )?;
    w.end_container()?;
    Ok(w.len())
}

#[cfg(test)]
mod tests;
