# im 層(Interaction Model エンジン)+ dm 層(データモデル/クラスタ)設計 — ロードマップ第5段階

対象: `docs/ARCHITECTURE.md` の「レイヤ構成」における `im` 層と `dm` 層。Matter デバイス
(responder)専用・`no_std`・定常パス no-alloc・executor 非依存を前提とする。

- 上位境界: `im` は Protocol ID **0x0001(Interaction Model)** の [`ProtocolHandler`] を
  実装し、`exchange` 層([`ExchangeManager`])から復号済み平文メッセージを 1 通ずつ受け取る。
  応答は `tx: &mut [u8]` に書き [`HandlerAction`] で宣言する(既存契約、後述 §3)。
- 下位境界: `im` エンジンは `dm` の [`DataModel`] trait だけに依存する(connectedhomeip の
  `DataModel::Provider` に相当)。具象クラスタは `dm::clusters` が [`ServerCluster`] として実装する。
- 第4段階との接続: Operational Credentials クラスタが `fabric` 層(実装済み [`FabricTable`])の
  `add`/`remove`/`update_label` を呼ぶ。接続点を §9.4 に明示する。

本書はシグネチャスケッチを含むが、コンパイル可能性より設計判断の明確化を優先する。
参照実装は `research/rs-matter/rs-matter/src/{im.rs, dm/}`(以下 rs-matter)、
`research/connectedhomeip/src/app/`(以下 chip)、matter.js の `packages/{model,types,protocol}`。
既存の下位層設計は `docs/design/{transport-exchange,secure-channel}.md`、実装済みコードは
`crates/simple-matter/src/{exchange,sc,tlv,fabric}.rs` を参照する。

---

## 0. サマリ(主要な設計判断)

1. **プロトコル語彙(im/wire)とエンジン(im/engine)を分離する**(chip の
   `protocols/interaction_model`(定数のみ)と `src/app`(エンジン)の「正しい継ぎ目」を踏襲)。
   `im/wire` は IM メッセージ・IB・パス・Status の TLV codec だけを持ち、`DataModel` を知らない。
   エンジンは `im/wire` と `dm::DataModel` を配線する(§2, §4)。
2. **エンジンは既存の同期 sans-IO 契約([`ProtocolHandler`])にそのまま乗る**。sc 層が
   ハンドシェイクの往復を `ExchangeId` キーの `HandshakePool` slot で表現したのと同型に、IM の
   **複数チャンクにわたる ReportData** と **Subscribe のプライミング**を `ExchangeId` キーの
   `ReadTxnPool` slot で表現する(1 チャンク = 1 回の同期 `handle`、続きは StatusResponse 受信で駆動)。
   これが本層の最重要判断で、全体の形を規定する(§5)。
3. **Subscribe の定期レポートは ProtocolHandler では表現できない**(device 発の送信は受信駆動の
   `handle` から出せない)ため、sc の `on_tick` と同じく IM 独自の駆動 API
   (`next_deadline()` / `poll_subscriptions()`)を設け、統合層が `ExchangeManager::poll`(MRP)と
   同じ select ループで回す。device 発の ReportData は `ExchangeManager::open_initiator` +
   `send_reliable` で送る(§6)。
4. **メタデータと dispatch を単一ソース化するのは「[`ServerCluster`] trait の 1 実装」**
   (設計原則5)。1 クラスタの read/write/invoke(dispatch)と attributes/commands 列挙(メタデータ)を
   同じ impl が提供し、グローバル属性(AttributeList / FeatureMap / ClusterRevision /
   Accepted/GeneratedCommandList)は const メタデータから**エンジンが自動導出**する。
   合成は `macro_rules!` の `device!`(手書き trait 実装の規約を減らすヘルパ)で 1 宣言から
   dispatch 表とメタデータの両方を生成する。**proc-macro は初期スコープでは導入しない**(§7, §8)。
5. **クラスタ合成は `&dyn ServerCluster` の registry**(chip `ServerClusterInterface` /
   `SingleEndpointServerClusterRegistry` 方式)。rs-matter の `ChainedHandler` タプルチェイン
   (型爆発の主因、設計原則7)を採らず、`(endpoint, cluster) → &dyn ServerCluster` の match で
   dispatch する。エンジンは単一型パラメータ `D: DataModel` しか見ず、クラスタを 1 個足しても
   `D` の**中身**が変わるだけで `im`/`exchange`/`transport` のシグネチャは不変(型消去境界=
   `ProtocolHandler`。§8)。**dyn 化はメソッドを object-safe に保つ**ことで no_std / no-alloc の
   まま成立する(GAT を使わない)。
6. **combined 実装(logic/translation 分離なし)**。属性ストレージはクラスタ構造体が所有し、
   dirty フラグ(Subscribe 用)も構造体が持つ。chip 公式 `writing_clusters.md` の「combined 推奨・
   modular 非推奨(virtual 翻訳層の flash/RAM コスト)」に従う(§9)。
7. **ACL は初期スコープを明示的に絞る**。full ACL クラスタ(per-subject エントリ照合)は後回しにし、
   最低限「CASE session = fabric メンバ」+「PASE session = commissioning window 中のみ
   コミッショニング必須クラスタへ Administer」+「属性/コマンドの access level による粗いゲート」
   だけを入れる(§10)。
8. **サイジングは IM 固有 const generic を少数**(同時 Read チャンク数 `READS`、Subscribe 数 `SUBS`、
   1 リクエスト/購読あたりパス数 `PATHS`)にまとめ、プロファイルエイリアスで隠す(§11)。

---

## 1. モジュール構成と依存関係

`crates/simple-matter/src/{im,dm}/` 配下(実装は別ピース。本書は設計のみ)。

```
im/
  mod.rs         InteractionModel<D>(ProtocolHandler 実装, 0x0001), 駆動 API(next_deadline/poll)
  wire/
    mod.rs       ImOpCode(0x01..0x0a), IM メッセージ TLV codec(Read/Report/Subscribe/Write/
                 Invoke/Timed/StatusResponse), SubscribeResponse
    path.rs      AttributePath / CommandPath / EventPath(ワイルドカード), Concrete*Path
    ib.rs        AttributeDataIB / AttributeReportIB / CommandDataIB / InvokeResponseIB / StatusIB /
                 DataVersionFilterIB
    status.rs    ImStatus(IM Status Code 0x00 Success .. 0xC0.. ), ClusterStatus
  engine/
    read.rs      ReadTxnPool, PathExpandCursor(ワイルドカード展開 + チャンク再開状態)
    write.rs     Write トランザクション(atomic list write, TimedRequest 連携)
    invoke.rs    Invoke ディスパッチ
    subscribe.rs SubscriptionPool, レポートスケジューリング(min/max interval, dirty)
    timed.rs     TimedTxn(TimedRequest → 続く Write/Invoke の deadline)
  access.rs      AccessContext, Privilege, 最小 ACL 判定(§10)
dm/
  mod.rs         DataModel trait, ServerCluster trait
  meta.rs        EndpointId/ClusterId/AttributeId/CommandId, AttributeMeta, Access, Quality,
                 EndpointMeta, グローバル属性 ID 定数
  codec.rs       AttrEncoder / AttrDecoder / CmdResponder(サイズ会計付き TLV 書き込みラッパ)
  cluster.rs     cluster! / device! マクロ(macro_rules), グローバル属性の自動導出
  clusters/
    basic_information.rs      (0x0028) ← §9.3
    descriptor.rs            (0x001D) ← §9.2
    on_off.rs               (0x0006) ← §9.1
    identify.rs             (0x0003)
    general_commissioning.rs (0x0030)
    network_commissioning.rs (0x0031)
    operational_credentials.rs (0x003E) ← fabric.rs 接続, §9.4
    general_diagnostics.rs   (0x0033)
```

### 依存方向(下→上の一方向)

```
error, tlv                                   … 既存(全層横断)
   ▲
fabric (FabricTable, FabricEntry)            … 第4段階成果物。opcreds クラスタのみが利用
   ▲
dm::meta ── dm::codec ── dm::cluster(マクロ)  … TLV に依存、DataModel を知らない
   ▲
dm::clusters (ServerCluster を実装)           … meta/codec/tlv、opcreds のみ fabric に依存
   ▲
dm::mod (DataModel trait)                     … clusters を (ep,cl) で束ねる registry
   ▲
im::wire (IM メッセージ codec)                 … DataModel を知らない(語彙のみ)
   ▲
im::engine (Read/Write/Invoke/Subscribe/Timed) … wire + DataModel を配線
   ▲
im::mod (InteractionModel<D> = ProtocolMux の Im スロット)
```

- `im` は `sc` を知らない。`ProtocolMux<Sc, Im>`(実装済み `exchange/dispatch.rs`)の `Im` スロットに
  `InteractionModel<D>` が入る。BDX 追加時も `im` は不変。
- **`im::wire` は `dm` を知らない**(chip の `protocols/interaction_model` = 定数のみ、を踏襲)。
  パスの**ワイルドカード展開**は `dm` のメタデータを要するので `im::engine` の責務で、`im::wire` は
  ワイヤ上の `AttributePath`(ワイルドカード可の生表現)を提供するにとどめる。
- **`dm::clusters` は `im` を知らない**(matter.js の「protocol 層はクラスタの意味を知らない」= 依存性
  逆転を踏襲)。クラスタは `ServerCluster` を実装するだけで、IM エンジンとはコールバックで接続する。

**rs-matter との差**: rs-matter は `im.rs`(2016 行)に read/write/subscribe/invoke を同居させ、`dm` は
`Handler`/`AsyncHandler` を `ChainedHandler` で合成する。本設計は (a) wire とエンジンを分離、(b) 合成を
`&dyn` registry にして型爆発を断つ、(c) 同期 sans-IO のためチャンク/プライミングを slot に外出しする、の
3 点で構造が異なる(いずれも設計原則 5/6/7 と実装済みの同期契約から要請される)。

---

## 2. IM ワイヤ層(im/wire)

Protocol ID = `0x0001`。opcode は chip `interaction_model/Constants.h` / rs-matter と同一(仕様値)。

```rust
// im/wire/mod.rs
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImOpCode {
    StatusResponse        = 0x01,  // 双方向(チャンク継続の合図にもなる)
    ReadRequest           = 0x02,  // ← Read 入口
    SubscribeRequest      = 0x03,  // ← Subscribe 入口
    SubscribeResponse     = 0x04,  // device→client(プライミング完了後)
    ReportData            = 0x05,  // device→client(Read 応答 / 購読レポート)
    WriteRequest          = 0x06,  // ← Write 入口
    WriteResponse         = 0x07,
    InvokeRequest         = 0x08,  // ← Invoke 入口
    InvokeResponse        = 0x09,
    TimedRequest          = 0x0a,  // ← Timed 入口
}
impl ImOpCode {
    pub fn from_u8(v: u8) -> Result<Self>;
    /// responder が新規 exchange の初回として受理する入口 opcode か。
    pub fn is_transaction_start(&self) -> bool; // Read/Subscribe/Write/Invoke/Timed
}
```

### 2.1 パス型(ワイルドカード対応)

`AttributePath` は endpoint / cluster / attribute のいずれも省略(ワイルドカード)可。エンジンが
`dm` メタデータで**具象パスに展開**する(§5.2)。`im/wire` は生の(ワイルドカード可の)表現のみを持つ。

```rust
// im/wire/path.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributePath {
    pub endpoint: Option<EndpointId>,   // None = ワイルドカード
    pub cluster:  Option<ClusterId>,
    pub attribute: Option<AttributeId>,
    pub list_index: Option<u16>,        // list 要素編集(Write)。初期は未対応で Decode
    pub enable_tag_compression: bool,   // 受理はするが device 側では無視
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandPath {                // Invoke。ワイルドカード invoke は device 側で不可
    pub endpoint: EndpointId,
    pub cluster:  ClusterId,
    pub command:  CommandId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventPath { /* endpoint/cluster/event ワイルドカード可。初期スコープでは空実装 */ }

/// 展開後の具象パス(エンジン内部で扱う)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcreteAttrPath { pub endpoint: EndpointId, pub cluster: ClusterId, pub attribute: AttributeId }

impl AttributePath {
    /// AttributePathIB(TLV list, ctx tag 0..4)をパースする。省略フィールドはワイルドカード。
    pub fn decode(r: &mut TlvReader<'_>) -> Result<Self>;
    /// AttributePathIB を書く(Report の中で使う)。
    pub fn encode(&self, w: &mut TlvWriter<'_>, tag: &TlvTag) -> Result<()>;
    pub fn matches(&self, p: ConcreteAttrPath) -> bool;  // 展開時のフィルタ
}
```

### 2.2 IM メッセージと IB

各メッセージは既存 `tlv.rs`(`TlvReader`/`TlvWriter`)で組み立てる。**すべて借用スライスで受け、所有しない**。

```rust
// im/wire/mod.rs
pub struct ReadRequest<'a> {
    pub attr_paths: PathList<'a>,              // AttributePathIBs(借用イテレータ or 固定容量にコピー)
    pub event_paths: PathList<'a>,             // 初期は無視
    pub data_version_filters: DvfList<'a>,     // 初期は無視(常にフル送信)
    pub fabric_filtered: bool,
}
pub struct SubscribeRequest<'a> {
    pub keep_existing: bool,
    pub min_interval_floor_s: u16,
    pub max_interval_ceiling_s: u16,
    pub attr_paths: PathList<'a>,
    pub event_paths: PathList<'a>,
    pub fabric_filtered: bool,
}
pub struct SubscribeResponse { pub subscription_id: u32, pub max_interval_s: u16 }
pub struct WriteRequest<'a> {
    pub suppress_response: bool,
    pub timed_request: bool,                   // 直前の TimedRequest と対応必須
    pub write_requests: AttrDataList<'a>,      // AttributeDataIB(path + TLV data)
}
pub struct InvokeRequest<'a> {
    pub suppress_response: bool,
    pub timed_request: bool,
    pub invoke_requests: CmdDataList<'a>,      // CommandDataIB(path + TLV fields)
}
pub struct TimedRequest { pub timeout_ms: u16 }
pub struct StatusResponse { pub status: ImStatus }   // 非 IB。チャンク継続の ACK にも使う

// im/wire/ib.rs
pub struct AttributeReportIB<'a> {                    // ReportData の要素
    pub path: ConcreteAttrPath,
    pub data_version: u32,
    pub value: AttrValue<'a>,                          // TLV element(借用) or StatusIB
}
pub struct StatusIB { pub status: ImStatus, pub cluster_status: Option<u8> }
```

### 2.3 IM Status(status.rs)

```rust
// im/wire/status.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ImStatus {
    Success = 0x00, Failure = 0x01,
    InvalidSubscription = 0x7d, UnsupportedAccess = 0x7e, UnsupportedEndpoint = 0x7f,
    InvalidAction = 0x80, UnsupportedCommand = 0x81, InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86, ConstraintError = 0x87, UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89, NotFound = 0x8b, UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d, UnsupportedRead = 0x8f, DataVersionMismatch = 0x92,
    Timeout = 0x94, Busy = 0x9c, UnsupportedCluster = 0xc3, NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6, /* … 仕様値 */
}
```

`Error`(実装済み enum)と `ImStatus` の対応は `im/engine` が持つ(例: `Error::NotFound` →
`UnsupportedAttribute`/`UnsupportedCluster`、`Error::Decode` → `InvalidAction`)。`ServerCluster` の
read/write/invoke は**`Result<_, ImStatus>`** を返す(クラスタが意味的ステータスを直接選べるようにする)。

---

## 3. exchange 層との接続(既存契約への適合)

`im` は既存 `exchange/dispatch.rs` の [`ProtocolHandler`] を実装する。契約は sc と共通:

```rust
// 実装済み(exchange/dispatch.rs)。再掲。
pub trait ProtocolHandler {
    const PROTOCOL_ID: u16;
    fn handle<const S: usize>(
        &mut self, rx: &RxMessage<'_>, tx: &mut [u8],
        sessions: &mut SessionManager<S>, now_ms: u64,
    ) -> Result<HandlerAction>;
}
// HandlerAction = None | Respond { opcode, proto_id, reliable, len } | Close { .. }
```

- **`tx` は 1 メッセージ分の出力バッファ**(exchange 層が headroom 確保済み。実 TX 上限
  `MAX_TX_PACKET_SIZE = 1232` 相当)。IM の応答(ReportData/InvokeResponse/…)はこの 1 バッファに収まる
  分だけ書き、収まらなければ**チャンク化**して `MoreChunkedMessages` を立てる(§5)。
- 応答は `Respond { opcode: ReportData, proto_id: 0x0001, reliable: true, len }` を返す。**IM トラフィックは
  常に暗号必須 + 信頼(R フラグ)**(chip `ApplicationExchangeDispatch`)。SuppressResponse な最終メッセージや
  会話終端は `Close` を返す。
- `SessionManager` は**ACL 判定のための session 情報取得**に使う(fabric_idx / mode / peer_node_id、
  実装済み `Session` アクセサ)。IM は session を書き換えない(sc と異なり reserve/commit しない)。
  ただし **Operational Credentials の AddNOC** は例外で、PASE session の `SessionMode::Pase{fabric_idx:0}`
  を確定 fabric へ昇格する必要がある(§9.4)。

**なぜ既存契約に無改造で乗るか**: sc 層が「1 メッセージ=1 同期 handle + 状態は `ExchangeId` キーの slot」で
複数往復を実現したのと**完全に同型**の問題(IM のチャンク/プライミングも複数往復)であり、同じ道具立て
(slot pool + `HandlerAction::Respond/Close`)で解ける。`HandlerAction` の拡張も不要。**唯一の追加要求**は
Subscribe の device 発レポート(§6)で、これは `ProtocolHandler` の外(IM 独自駆動 API)に置く。

---

## 4. エンジン本体の骨格

```rust
// im/mod.rs
pub struct InteractionModel<D: DataModel, const READS: usize, const SUBS: usize, const PATHS: usize> {
    dm: D,
    reads: ReadTxnPool<READS, PATHS>,     // チャンク中 Read / プライミング Subscribe の再開状態
    subs:  SubscriptionPool<SUBS, PATHS>, // 確立済み購読
    timed: TimedTxnTable,                 // TimedRequest → 後続 Write/Invoke の deadline(小)
    next_sub_id: u32,
}

impl<D: DataModel, const R: usize, const S: usize, const P: usize> ProtocolHandler
    for InteractionModel<D, R, S, P>
{
    const PROTOCOL_ID: u16 = PROTO_ID_INTERACTION_MODEL;
    fn handle<const SN: usize>(
        &mut self, rx: &RxMessage<'_>, tx: &mut [u8],
        sessions: &mut SessionManager<SN>, now_ms: u64,
    ) -> Result<HandlerAction> {
        let acc = AccessContext::from_session(sessions, rx.exchange.session())?; // §10
        match ImOpCode::from_u8(rx.header.proto_opcode)? {
            ImOpCode::ReadRequest      => self.read_open(rx, tx, &acc, now_ms),      // §5
            ImOpCode::SubscribeRequest => self.subscribe_open(rx, tx, &acc, now_ms), // §6
            ImOpCode::WriteRequest     => self.write(rx, tx, &acc, sessions, now_ms),// §9.4 は AddNOC
            ImOpCode::InvokeRequest    => self.invoke(rx, tx, &acc, sessions, now_ms),
            ImOpCode::TimedRequest     => self.timed_open(rx, tx, now_ms),           // §5.5
            ImOpCode::StatusResponse   => self.on_status(rx, tx, now_ms),            // チャンク継続
            _ => Err(Error::InvalidState),  // ReportData/SubscribeResponse は client→device では不正
        }
    }
}
```

`AccessContext::from_session` は session の mode(PASE/CASE)と fabric_idx を読むだけ(実装済みアクセサ)。

---

## 5. Read/Report のチャンク化と状態管理(本層の核)

### 5.1 なぜチャンクが必要か

Read/Subscribe のプライミング応答(ReportData)は 1 TX パケット(~1232B)に収まらないことがある
(ワイルドカード Read は全属性を返す)。Matter はこれを **`MoreChunkedMessages = true`** の ReportData を
連続送信して解決する。仕様上のフロー(device 視点):

```
client → ReadRequest
device → ReportData(chunk 1, MoreChunkedMessages=true)      [信頼]
client → StatusResponse(SUCCESS)                            ← 「次を送れ」の合図
device → ReportData(chunk 2, MoreChunkedMessages=true)
client → StatusResponse(SUCCESS)
device → ReportData(chunk N, MoreChunkedMessages 無し)       ← 最終
client → StatusResponse(SUCCESS)                            (SuppressResponse 無しなら)
```

各矢印が**別々の `handle` 呼び出し**になる。sc のハンドシェイクと同じく、往復のまたぎを
`ExchangeId` キーの slot に保存する。

### 5.2 ワイルドカード展開 = 再開可能なカーソル

チャンクをまたいで展開位置を保持するため、`AttributePathExpandIterator`(chip)相当を
**インデックスだけの Copy な再開カーソル**として実装する(借用イテレータは slot に格納できない)。

```rust
// im/engine/read.rs
#[derive(Debug, Clone, Copy, Default)]
pub struct PathExpandCursor {
    path_idx: u16,   // リクエストの何番目の AttributePath を処理中か
    ep_idx:   u16,   // DataModel::endpoints() の走査位置
    cl_idx:   u16,   // その endpoint の clusters_on() の走査位置
    at_idx:   u16,   // その cluster の attributes() の走査位置(グローバル属性含む)
}
impl PathExpandCursor {
    /// 次の「(具象パス, そのメタ)」を返す。リクエストパス列 `paths` と `dm` を突き合わせ、
    /// ワイルドカードを dm メタデータで展開する。返り値が None なら全パス消化。
    fn next<D: DataModel>(&mut self, dm: &D, paths: &[AttributePath])
        -> Option<(ConcreteAttrPath, &'static AttributeMeta)>;
}
```

- 展開順序は **endpoint → cluster → attribute の昇順**(chip と同じ、決定的)。カーソルは 8 バイト
  (u16×4)で slot が軽い。
- ワイルドカードでない具象パスは「その 1 点だけ」を返す(存在確認 + access チェック → 無ければ StatusIB)。
- **access チェックはここで**行い、不可の属性は AttributeReportIB の代わりに **StatusIB(UnsupportedAccess)**
  を書く(fabric-filtered や access level のフィルタ、§10)。

### 5.3 Read トランザクション slot

```rust
// im/engine/read.rs
pub struct ReadTxn<const P: usize> {
    exchange: ExchangeId,                 // 索引キー(sc の HandshakeSlot と同型)
    paths: FixedVec<AttributePath, P>,    // リクエストのパス列(チャンクをまたいで保持)
    cursor: PathExpandCursor,             // 再開位置(§5.2)
    started_ms: u64,                      // タイムアウト(SUBSCRIPTION_MAX_..等)
    subscription: Option<u32>,            // Some = Subscribe のプライミング中(§6)
    suppress_response: bool,
    fabric_filtered: bool,
    fabric_idx: Option<NonZeroU8>,        // access 判定に使う
}
pub struct ReadTxnPool<const R: usize, const P: usize> {
    slots: FixedVec<ReadTxn<P>, R>,       // 実装済み transport::session::fixed::FixedVec を流用
}
```

### 5.4 チャンク生成(1 回の handle 内)

`read_open`(ReadRequest 受信)と `on_status`(StatusResponse 受信でチャンク継続)は、共通の
`emit_report_chunk` を呼ぶ:

```rust
fn emit_report_chunk<D: DataModel>(
    dm: &D, txn: &mut ReadTxn<P>, tx: &mut [u8], acc: &AccessContext,
) -> Result<ChunkOutcome> {
    let mut w = ReportWriter::new(tx);            // ReportData 外枠 + AttributeReportIBs 配列を開く
    loop {
        // 展開を 1 属性進め、AttributeReportIB を「試し書き」する。
        let Some((path, meta)) = txn.cursor.peek(dm, &txn.paths) else {
            w.finish(/*more=*/ false)?;           // 全消化 → MoreChunkedMessages 無し
            return Ok(ChunkOutcome::Done { len: w.len() });
        };
        match w.try_encode_attribute(dm, path, meta, acc) {  // AttrEncoder 経由(§7.2)
            Ok(()) => { txn.cursor.advance(); }              // 収まった → 次へ
            Err(Full) if w.has_any() => {                    // 1 個も入らなかったのではなく満杯
                w.finish(/*more=*/ true)?;                   // MoreChunkedMessages=true
                return Ok(ChunkOutcome::More { len: w.len() });
            }
            Err(Full) => {                                   // 単一属性が 1 パケットに入らない
                w.encode_status(path, ImStatus::ResourceExhausted)?; // 大属性は list chunking(将来)
                txn.cursor.advance();
            }
        }
    }
}
```

- **`read_open`**: リクエストをパースし paths を slot(未確定)に積む。`emit_report_chunk` を呼び、
  - `Done` → slot を確保せず `Respond { ReportData, reliable, len }`(単発で完結)。
  - `More` → slot を `ReadTxnPool` に確保(満杯なら **StatusResponse(Busy)** / `ResourceExhausted`)、
    `Respond { ReportData, reliable, len }`。
- **`on_status`**(StatusResponse(SUCCESS) 受信): `ExchangeId` で slot を引き、`emit_report_chunk` を続行。
  - `More` → slot 保持、`Respond`。
  - `Done` → slot 解放。Subscribe プライミング中(`subscription = Some`)なら**続けて SubscribeResponse**
    を送る必要があるため、`on_status` は `Respond { SubscribeResponse }` を返し、購読を Active 化する(§6)。
    通常 Read なら `Close`(SuppressResponse 準拠)。
- StatusResponse が SUCCESS 以外(client が中断)なら slot 解放 + `HandlerAction::None`。

**チャンク境界の要点**(chip/rs-matter 共通): `MoreChunkedMessages` を立てた場合、次の
StatusResponse(SUCCESS) を**必ず待って**から次チャンクを送る(勝手に連投しない)。これが「1 チャンク=
1 handle」に自然に写像される。`ReportData` 内では最低 1 個の AttributeReportIB を必ず入れる
(0 個 chunk 禁止)。

### 5.5 Write / Invoke / Timed(単発が基本)

- **Write**: WriteRequest → 各 AttributeDataIB を `dm.write_attribute` に流し、WriteResponse に per-path
  StatusIB を積む。原則 1 メッセージに収まる(書き込みパスは少数)。list 属性の atomic write は初期未対応。
  `suppress_response` 準拠。
- **Invoke**: InvokeRequest → 各 CommandDataIB を `dm.invoke_command`。応答(コマンドの生成レスポンス or
  StatusIB)を InvokeResponse に積む。**ワイルドカード invoke は禁止**(具象 CommandPath のみ)。
  大きな生成コマンド(将来)以外は単発。
- **Timed**(`timed.rs`): TimedRequest(timeout_ms)受信 → `TimedTxn { exchange, deadline_ms }` を小テーブルに
  記録し、StatusResponse(SUCCESS) を返す。続く Write/Invoke(`timed_request=true`)受信時に
  `deadline_ms` 超過なら **`Timeout`**、`timed_request` フラグ不整合なら **`NeedsTimedInteraction`** /
  `TimedRequestMismatch` を返す。TimedTxn は消化 or `on_tick` の deadline 掃除で解放。

---

## 6. Subscribe(プライミング + 定期レポート)

Subscribe は 2 相: **(A) プライミング**(§5 の Read チャンクと同一機構、受信 exchange 上)と
**(B) 定期/変化レポート**(device 発、別 exchange)。(B) が既存 sans-IO 契約の外に出る唯一の要素。

### 6.1 プライミング(受信駆動、§5 の再利用)

```
client → SubscribeRequest
device → ReportData(priming chunk 1, More=true)     ← ReadTxn{ subscription: Some(id) } で駆動
client → StatusResponse(SUCCESS)
   …(§5 のチャンク機構そのまま)…
device → ReportData(final priming chunk, More 無し)
client → StatusResponse(SUCCESS)
device → SubscribeResponse(subscription_id, max_interval)   ← ここで購読を Active 化
```

`subscribe_open` は (a) min/max interval のネゴシエート(floor/ceiling を仕様範囲にクランプ)、
(b) `SubscriptionPool` に slot を予約(満杯なら `ResourceExhausted`)、(c) `ReadTxn` を
`subscription = Some(id)` で開始し §5 のチャンク送信を始める。プライミング最終チャンクの ACK
(`on_status` の `Done` 分岐)で `SubscribeResponse` を返し、`Subscription.state = Active`、
`last_report_ms = now`、`next_deadline = now + max_interval` を設定する。

### 6.2 Subscription slot と dirty 追跡

```rust
// im/engine/subscribe.rs
pub struct Subscription<const P: usize> {
    id: u32,
    session: SessionId,               // 購読者(暗号セッション)
    fabric_idx: NonZeroU8,
    paths: FixedVec<AttributePath, P>,
    min_interval_s: u16, max_interval_s: u16,
    last_report_ms: u64,
    report: Option<ReportProgress>,   // in-flight の device 発レポート(チャンクカーソル)
    state: SubState,                  // Priming | Active | Reporting
}
pub struct SubscriptionPool<const S: usize, const P: usize> { slots: FixedVec<Subscription<P>, S> }
```

**dirty 追跡**: クラスタが属性変更時に自分の dirty フラグを立てる(§9)。エンジンは「変更のあった
`(endpoint, cluster)`」を粗く知りたいだけなので、初期スコープは **クラスタ単位 dirty フラグ**にする。
`DataModel::take_dirty()` が「前回レポート以降に dirty になった cluster を列挙」し、購読の `paths` と
交差すれば当該購読を「報告要」とする。**属性単位の DataVersion フィルタ**(変更属性だけ送る)は
enhancement(§12)。初期は「関係クラスタが dirty または max interval 到達 → 購読パス全体を再送」で
仕様準拠(過剰報告は許容)。

### 6.3 定期/変化レポート(device 発、IM 駆動 API)

`ProtocolHandler::handle` は受信駆動なので device 発送信を出せない。sc の `on_tick` と同型に、
**IM 独自の駆動 API** を設け、統合層が回す:

```rust
impl<D: DataModel, const R: usize, const S: usize, const P: usize> InteractionModel<D, R, S, P> {
    /// 次に購読レポートを出すべき最も早い絶対時刻。exchange 層の next_deadline と min して select。
    pub fn next_deadline(&self, now_ms: u64) -> Option<u64>;

    /// 期限到達 or dirty の購読を 1 件返す。統合層はこれを受けて device 発 exchange を開き送る。
    /// (min_interval を尊重: dirty でも last_report + min 未満なら待つ)
    pub fn poll_subscriptions(&mut self, now_ms: u64) -> Option<SubDue>;
}
pub struct SubDue { pub subscription: u32, pub session: SessionId }
```

統合層(第6段階)のループ:

```
loop select {
    rx      = net.recv()               → mgr.recv(...)  (受信一本道, 実装済み)
    _       = timer(mgr.next_deadline()) → mgr.poll(...)  (MRP 再送/ACK, 実装済み)
    _       = timer(im.next_deadline())  → {                // 購読レポート(本設計の追加)
        if let Some(due) = im.poll_subscriptions(now) {
            let ex = mgr.open_initiator(due.session)?;      // device 発 exchange(実装済み API)
            let action = im.build_report(due.subscription, tx, now)?; // ReportData chunk を書く
            mgr.send_reliable(sessions, crypto, pool, ex, &Outgoing{ proto_id:0x0001,
                opcode: ReportData, payload:&tx[..len] }, timing)?;
        }
    }
    _       = timer(sc_timeout)          → sc.on_tick(...)  (ハンドシェイク掃除, 実装済み)
}
```

- device 発レポートの**続きチャンク**は、client の StatusResponse(SUCCESS) が上の
  `mgr.recv → im.handle(StatusResponse)` 経路で戻ってくるので、`on_status` が `Subscription.report`
  カーソルを進めて次チャンクを `Respond` する(受信駆動に戻る)。つまり device 発は「最初のチャンクだけ」で、
  以降は §5 の受信駆動に合流する。
- **購読の生存**: device 発 ReportData が MRP で ack されない(再送上限)場合、`mgr.poll` が
  `PollAction::Failed { exchange }` を返す。統合層は exchange→subscription を引いて
  `im.on_report_failed(sub_id)` を呼び購読を破棄する(chip の subscription liveness)。
- **min interval / max interval**: `poll_subscriptions` は `now >= last_report + min` を満たす dirty 購読、
  または `now >= last_report + max` の購読を due とする。報告後 `last_report = now`、dirty クリア。

### 6.4 なぜこの分割か(判断根拠)

- 受信駆動の `handle` に device 発送信を無理に押し込む(例: handle が「送るべき自発メッセージ」も返す)と、
  MRP バッファ所有・exchange 採番・信頼送信を IM が抱えることになり、**sans-IO の送受信分離**
  (exchange 層が送信を持つ)を壊す。`poll_subscriptions` + 統合層の `open_initiator`/`send_reliable` なら、
  既存の送信 API(実装済み)をそのまま使え、IM は「何を報告すべきか」だけを決める純粋な状態機械に保てる。
- `next_deadline` を返す形は `ExchangeManager::next_deadline`(実装済み)と統一され、統合層の select が
  素直(全 deadline を min して 1 タイマ)。

---

## 7. データモデル抽象(dm)

### 7.1 DataModel / ServerCluster trait

```rust
// dm/mod.rs
/// エンドポイント/クラスタの registry。IM エンジンはこの trait だけに依存する(chip DataModel::Provider)。
pub trait DataModel {
    /// エンドポイント一覧(メタデータ列挙・ワイルドカード展開の起点)。
    fn endpoints(&self) -> &[EndpointMeta];
    /// endpoint に載るクラスタ ID 一覧(Descriptor の ServerList / 展開に使う)。
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId];
    /// (ep, cl) → クラスタの読み取りビュー(read / メタデータ / invoke の共有参照)。
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster>;
    /// (ep, cl) → 可変ビュー(write / invoke の状態変更)。
    fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster>;
    /// 前回レポート以降に dirty になったクラスタを列挙し dirty をクリア(Subscribe 用, §6.2)。
    fn take_dirty(&mut self, out: &mut impl FnMut(EndpointId, ClusterId));
}

/// 1 クラスタの combined 実装。**メタデータ列挙と dispatch を同じ impl が提供**(設計原則5)。
/// object-safe(メソッドにジェネリック/GAT なし)なので `&dyn ServerCluster` で束ねられる。
pub trait ServerCluster {
    // --- メタデータ(const, ワイルドカード展開 + グローバル属性導出の元) ---
    fn cluster_id(&self) -> ClusterId;
    fn attributes(&self) -> &'static [AttributeMeta];           // グローバル属性は含めない(自動導出)
    fn accepted_commands(&self) -> &'static [CommandId];
    fn generated_commands(&self) -> &'static [CommandId];
    fn feature_map(&self) -> u32 { 0 }
    fn cluster_revision(&self) -> u16;

    // --- dispatch ---
    fn read_attribute(&self, attr: AttributeId, enc: &mut AttrEncoder<'_>)
        -> Result<(), ImStatus>;
    fn write_attribute(&mut self, attr: AttributeId, data: TlvElement<'_>, acc: &AccessContext)
        -> Result<(), ImStatus> { Err(ImStatus::UnsupportedWrite) }
    fn invoke_command(&mut self, cmd: CommandId, fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_>, acc: &AccessContext) -> Result<(), ImStatus>
        { Err(ImStatus::UnsupportedCommand) }
}
```

- **グローバル属性はエンジンが intercept して自動導出**(単一ソース化の核): read で
  `attr ∈ {0xFFFB AttributeList, 0xFFF8 GeneratedCommandList, 0xFFF9 AcceptedCommandList,
  0xFFFC FeatureMap, 0xFFFD ClusterRevision}` を検出したら、`ServerCluster::read_attribute` を呼ばず
  `attributes()`/`accepted_commands()`/… から**エンジンが直接生成**する。ワイルドカード展開の `attributes()`
   列挙にもエンジンがグローバル属性 ID を後付けする。クラスタは手書きしない(整合ズレが起きない)。
- **object-safe を保つ制約**: `read_attribute` は `&mut AttrEncoder`(具象型)に書く。`TlvWriter` の GAT や
  ジェネリックを避けることで `&dyn` 化が成立する。これが「dyn で型爆発を断つ」ための必要条件(§8)。

### 7.2 codec(サイズ会計付きラッパ)

```rust
// dm/codec.rs
/// 属性値を ReportData 内の 1 AttributeReportIB として書く。バッファ満杯を Err(Full) で返す
/// (チャンク境界判定の要, §5.4)。TlvWriter を包み、「入り切らなければロールバック」する。
pub struct AttrEncoder<'a> { w: &'a mut TlvWriter<'a>, /* rollback marker */ }
impl AttrEncoder<'_> {
    pub fn write_bool(&mut self, v: bool) -> Result<(), Full>;
    pub fn write_u8/u16/u32/u64(&mut self, v: _) -> Result<(), Full>;
    pub fn write_str(&mut self, s: &str) -> Result<(), Full>;
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), Full>;
    pub fn begin_list(&mut self) -> Result<ListGuard<'_>, Full>;   // list 属性(Descriptor 等)
    // …単純型のみ。複雑 struct はクラスタが TlvWriter 相当を直接呼ぶ低レベル API も用意。
}
/// Invoke の生成レスポンスを InvokeResponse に書く。
pub struct CmdResponder<'a> { /* command_id + fields writer */ }
```

`AttrEncoder` は **「試し書き → 満杯ならロールバック」**(marker で `TlvWriter` の書き込み位置を巻き戻す)を
提供し、`emit_report_chunk`(§5.4)がチャンク境界を「属性単位」で切れるようにする。これが chip の
`AttributeValueEncoder` + `TLVWriter` チェックポイントに相当する。

### 7.3 メタデータ型(const 評価でどこまで作れるか)

```rust
// dm/meta.rs
#[derive(Clone, Copy)] pub struct EndpointId(pub u16);
#[derive(Clone, Copy)] pub struct ClusterId(pub u32);
#[derive(Clone, Copy)] pub struct AttributeId(pub u32);
#[derive(Clone, Copy)] pub struct CommandId(pub u32);

#[derive(Clone, Copy)]
pub struct AttributeMeta {
    pub id: AttributeId,
    pub access: Access,     // read/write privilege(§10)
    pub quality: Quality,   // Nullable / Nonvolatile / Scene / Fixed 等の bitflags
}
#[derive(Clone, Copy)]
pub struct EndpointMeta { pub id: EndpointId, pub device_types: &'static [DeviceType] }
```

- **属性/コマンドのメタは全て `&'static [AttributeMeta]` の const 配列**。`const fn` コンストラクタで
  クラスタ実装ファイル内に定義でき、`.rodata` に置ける(RAM を食わない)。これは const 評価で完全に作れる。
- **endpoint 合成**(どの endpoint にどのクラスタが載るか)は device 構造体が所有する。`clusters_on` が
  返す `&'static [ClusterId]` も const にできる。Descriptor の ServerList はこれを読むだけ(§9.2)。
- **conformance/constraint はコンパイル時に確定**(設計原則6・matter.js 示唆): 「feature 有効時のみ存在する
  属性」は、そのクラスタの `attributes()` が返す const 配列を feature で切り替える(`cfg!` or const 選択)。
  実行時 conformance パーサ(matter.js の文字列 DSL)は持たない。

---

## 8. クラスタ宣言 → メタデータ + dispatch の単一ソース導出(具体案)

### 8.1 判断: `macro_rules!` ヘルパ + 手書き trait 実装(proc-macro なし)

設計原則5(単一ソース)への回答。選択肢と評価:

| 案 | 評価 |
|---|---|
| **手書き trait 実装のみ** | 素直だが、`attributes()` の const 配列と read の match を手で二重に書くと**整合ズレ**が起きうる(rs-matter の Node/Handler 二重管理と同じ病)。 |
| **`macro_rules!` の `cluster!`** | 属性/コマンドの宣言 1 つから (a) `AttributeMeta` const 配列、(b) `attributes()`/`accepted_commands()`、(c) グローバル属性導出、(d) read/invoke の match 骨格を生成。**proc-macro 不要**・ビルド依存ゼロ・型付き。 |
| **proc-macro クレート** | IDL/属性から強く型付き struct を生成でき表現力は高いが、クレート追加・ビルド時間・複雑性。**8 クラスタ規模では費用対効果が薄い**(rs-matter は 283 クラスタ生成のために持つ)。 |

**判断: `macro_rules!` の `cluster!` + `device!`**。単一ソースの利益(メタと dispatch のズレ防止)を、
proc-macro のコストなしで得る。`FromTLV`/`ToTLV` derive(proc-macro)はコマンド/struct payload の
デコードに有用だが、**初期スコープでは手書き `TlvReader` 呼び出し**で足り、必要になった段階で
別途導入を検討する(オープン論点 §12)。

### 8.2 `cluster!` マクロ(1 宣言 → メタ + dispatch 骨格)

```rust
// 使用例(dm/clusters/on_off.rs)。宣言は 1 箇所。
cluster! {
    OnOffCluster(id = 0x0006, revision = 6) {
        // attribute: (id, 名前, access, quality) → メタ + read アーム名を生成
        attr 0x0000 OnOff: read(access = View, quality = NONVOLATILE | SCENE);
        // command: (id, 名前) → accepted_commands + invoke アーム名を生成
        cmd  0x0000 Off;
        cmd  0x0001 On;
        cmd  0x0002 Toggle;
    }
    // read/invoke の本体は手書き(下記 impl ブロックを macro が要求)。
}
```

マクロが生成するもの:
- `const ON_OFF_ATTRS: &[AttributeMeta] = &[ AttributeMeta::new(0x0000, Access::View, Q::NONVOLATILE|Q::SCENE) ];`
- `const ON_OFF_ACCEPTED: &[CommandId] = &[CommandId(0), CommandId(1), CommandId(2)];`
- `impl ServerCluster for OnOffCluster { fn attributes() { ON_OFF_ATTRS } fn accepted_commands() {..}
   fn cluster_id() {..} fn cluster_revision() {6} /* read/invoke は下の手書きへ委譲 */ }`
- read/invoke の **match 骨格**(`0x0000 => self.read_on_off(enc)` 等)。本体メソッドは手書き。

これで「属性/コマンド一覧」の真実源は宣言 1 箇所になり、`attributes()` と read の match が**同じ宣言から
生成**される(整合はマクロが保証)。グローバル属性はエンジンが `attributes()` から導出(§7.1)。

### 8.3 `device!` マクロ(クラスタ合成 → DataModel 実装)

```rust
// 使用例(アプリ側)。endpoint とクラスタの対応を 1 宣言。
device! {
    MyLight {
        endpoint 0 [BasicInformation, GeneralCommissioning, NetworkCommissioning,
                    OperationalCredentials, GeneralDiagnostics, Descriptor] {
            device_type ROOT_NODE (0x0016, rev 1)
        }
        endpoint 1 [Identify, OnOff, Descriptor] {
            device_type ON_OFF_LIGHT (0x0100, rev 3)
        }
    }
}
// → struct MyLight { basic: BasicInformationCluster, on_off: OnOffCluster, descriptor_ep1: DescriptorCluster, … }
//   impl DataModel for MyLight {
//       fn cluster(&self, ep, cl) -> Option<&dyn ServerCluster> {
//           match (ep.0, cl.0) {
//               (0, 0x0028) => Some(&self.basic),
//               (1, 0x0006) => Some(&self.on_off), … _ => None } }
//       fn clusters_on(&self, ep) -> &[ClusterId] { match ep.0 { 0 => EP0_CLUSTERS, 1 => EP1_CLUSTERS, … } }
//       fn endpoints() -> &[EndpointMeta] { ENDPOINTS }  // device_type 込み
//   }
```

- `device!` が **dispatch 表(`cluster`/`cluster_mut` の match)とメタデータ(`clusters_on`/`endpoints`)を
  同じ宣言から生成**する。クラスタを 1 個足すのは宣言に 1 行足すだけで、両者が自動で揃う。
- 生成される `MyLight` は具象クラスタ struct を**フィールドとして所有**(属性ストレージの所有=§9)。
  `&dyn ServerCluster` は match で作るだけ(alloc なし・vtable 参照のみ)。
- **型爆発の遮断**: `InteractionModel<MyLight, …>` の型パラメータは `MyLight` の**単一名**。クラスタ数が
  増えても `MyLight` の中身(フィールド)が変わるだけで、`im`/`exchange`/`transport` のシグネチャは不変。
  rs-matter の `(Node, Handler)` タプルが最上位まで伸びる問題が起きない(型消去境界=`ProtocolHandler`)。

---

## 9. クラスタ実装の形(combined)

共通形: クラスタ struct が**属性ストレージ + dirty フラグ**を所有し、`ServerCluster` を combined 実装する。
dirty は「変更を Subscribe に伝える」ためのクラスタ単位フラグ(§6.2)。

```rust
// dirty ヘルパ(dm/cluster.rs)。属性を書き換える setter が set_dirty を呼ぶ規約。
pub struct Dirty(bool);
impl Dirty { pub fn mark(&mut self) { self.0 = true; } pub fn take(&mut self) -> bool { core::mem::take(&mut self.0) } }
```

### 9.1 On/Off(0x0006)— 具体例

```rust
// dm/clusters/on_off.rs
pub struct OnOffCluster {
    on_off: bool,     // attr 0x0000
    dirty: Dirty,
}
impl OnOffCluster {
    pub const fn new() -> Self { Self { on_off: false, dirty: Dirty(false) } }
    fn read_on_off(&self, enc: &mut AttrEncoder<'_>) -> Result<(), ImStatus> {
        enc.write_bool(self.on_off).map_err(|_| ImStatus::ResourceExhausted)
    }
    fn set(&mut self, v: bool) { if self.on_off != v { self.on_off = v; self.dirty.mark(); } }
}
// cluster! が ServerCluster を生成。invoke 本体だけ手書き:
impl OnOffCluster {
    fn invoke(&mut self, cmd: CommandId, _f: &mut TlvReader<'_>, _r: &mut CmdResponder<'_>,
              _acc: &AccessContext) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => { self.set(false); Ok(()) }   // Off
            0x01 => { self.set(true);  Ok(()) }   // On
            0x02 => { self.set(!self.on_off); Ok(()) } // Toggle
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}
```

- Off/On/Toggle は payload なし・生成レスポンスなし(status のみ)。`set` が dirty を立て、Subscribe が
  次の poll でレポートする。属性 `OnOff` の quality は `NONVOLATILE | SCENE`(永続化は platform 統合で KVS へ。
  初期は RAM のみ)。FeatureMap=0(Lighting feature は後日)。

### 9.2 Descriptor(0x001D)— 具体例(合成から導出)

Descriptor の属性(DeviceTypeList / ServerList / ClientList / PartsList)は**格納せず DataModel 合成から
導出**する。よって Descriptor は自分の endpoint のメタへの参照を持つ。

```rust
// dm/clusters/descriptor.rs
pub struct DescriptorCluster {
    endpoint: EndpointId,
    server_list: &'static [ClusterId],   // device! が clusters_on(ep) を渡す
    device_types: &'static [DeviceType], // device! が endpoint の device_type を渡す
    parts: &'static [EndpointId],        // ep0 のみ子 endpoint 一覧、他は空
}
impl ServerCluster for DescriptorCluster {
    fn cluster_id(&self) -> ClusterId { ClusterId(0x001D) }
    fn attributes(&self) -> &'static [AttributeMeta] { DESCRIPTOR_ATTRS } // 0x0000..0x0003
    fn cluster_revision(&self) -> u16 { 2 }
    fn read_attribute(&self, attr: AttributeId, enc: &mut AttrEncoder<'_>) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => { let mut l = enc.begin_list()?;             // DeviceTypeList
                        for dt in self.device_types { l.write_device_type(dt)?; } Ok(()) }
            0x0001 => { let mut l = enc.begin_list()?;             // ServerList
                        for c in self.server_list { l.write_u32(c.0)?; } Ok(()) }
            0x0002 => { enc.begin_list()?; Ok(()) }                // ClientList(空)
            0x0003 => { let mut l = enc.begin_list()?;             // PartsList
                        for e in self.parts { l.write_u16(e.0)?; } Ok(()) }
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }
}
```

- Descriptor が「DataModel 構造を読む唯一のクラスタ」。`device!` マクロが `server_list = clusters_on(ep)` /
  `device_types` / `parts` を各 endpoint の Descriptor に注入する(§8.3)。ServerList はグローバル属性
  自動導出とは別(こちらは仕様上 Descriptor の通常属性)。

### 9.3 Basic Information(0x0028)— 具体例(endpoint 0 のみ)

```rust
// dm/clusters/basic_information.rs
pub struct BasicInfoConfig {           // 焼き込み値(const, &'static で渡す)
    pub vendor_name: &'static str, pub vendor_id: u16,
    pub product_name: &'static str, pub product_id: u16,
    pub hardware_version: u16, pub software_version: u32,
    pub serial_number: &'static str, /* … */
}
pub struct BasicInformationCluster {
    cfg: &'static BasicInfoConfig,
    node_label: heapless::String<32>,  // 書き込み可(NodeLabel 0x0005)
    location: [u8; 2],                  // 書き込み可(Location 0x0006, ISO 3166-1)
    dirty: Dirty,
}
impl ServerCluster for BasicInformationCluster {
    fn cluster_id(&self) -> ClusterId { ClusterId(0x0028) }
    fn attributes(&self) -> &'static [AttributeMeta] { BASIC_INFO_ATTRS }
    fn cluster_revision(&self) -> u16 { 3 }
    fn read_attribute(&self, attr: AttributeId, enc: &mut AttrEncoder<'_>) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => enc.write_u16(3).map_err(|_| ImStatus::ResourceExhausted), // DataModelRevision
            0x0001 => enc.write_str(self.cfg.vendor_name).map_err(e),
            0x0002 => enc.write_u16(self.cfg.vendor_id).map_err(e),
            0x0003 => enc.write_str(self.cfg.product_name).map_err(e),
            0x0004 => enc.write_u16(self.cfg.product_id).map_err(e),
            0x0005 => enc.write_str(&self.node_label).map_err(e),  // NodeLabel
            0x0006 => enc.write_str(core::str::from_utf8(&self.location).unwrap_or("XX")).map_err(e),
            0x0007 => enc.write_u16(self.cfg.hardware_version).map_err(e),
            0x0009 => enc.write_u32(self.cfg.software_version).map_err(e),
            0x000f => enc.write_str(self.cfg.serial_number).map_err(e),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }
    fn write_attribute(&mut self, attr: AttributeId, data: TlvElement<'_>, acc: &AccessContext)
        -> Result<(), ImStatus> {
        match attr.0 {
            0x0005 => { let s = data.as_str().map_err(|_| ImStatus::InvalidDataType)?;
                        self.node_label = s.try_into().map_err(|_| ImStatus::ConstraintError)?;
                        self.dirty.mark(); Ok(()) }
            0x0006 => { /* Location: 2 byte 制約チェック */ self.dirty.mark(); Ok(()) }
            _ => Err(ImStatus::UnsupportedWrite),
        }
    }
}
```

- 大半は const config(`.rodata`)、書き込み可は NodeLabel/Location のみ(小さな RAM)。StartUp イベントは
  イベント実装(初期スコープ外)なので省略。

### 9.4 Operational Credentials(0x003E)— fabric.rs 接続点

OpCreds は詳細設計対象外だが、`fabric` 層(実装済み)との接続点を明示する。クラスタは
**`&mut FabricTable<C, N>` と DAC provider と failsafe context** を持ち、AddNOC 等のコマンドで
`FabricTable` を叩く。

```rust
// dm/clusters/operational_credentials.rs
pub struct OpCredsCluster<'f, C: Crypto, const NF: usize> {
    fabrics: &'f mut FabricTable<C, NF>,     // 実装済み fabric.rs
    dac: &'f dyn DeviceAttestation,          // DAC/PAI/CD 提供(fabric 層 or 別 trait)
    pending: Option<PendingNoc<C>>,          // CSRRequest で作った keypair の一時保持(failsafe 中)
}
impl<C: Crypto, const NF: usize> OpCredsCluster<'_, C, NF> {
    fn invoke(&mut self, cmd: CommandId, f: &mut TlvReader<'_>, resp: &mut CmdResponder<'_>,
              acc: &AccessContext, sessions: &mut SessionManager<_>) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 /*AttestationRequest*/ => { /* dac.sign(attestation_nonce) → AttestationResponse */ }
            0x02 /*CertificateChainRequest*/ => { /* dac.dac()/pai() を返す */ }
            0x04 /*CSRRequest*/ => {
                let kp = self.crypto.p256_generate_keypair()?;    // NOCSR 用鍵ペア
                self.pending = Some(PendingNoc { keypair: kp, .. });
                /* NOCSRElements を dac.sign で署名して CSRResponse */ }
            0x06 /*AddNOC*/ => {
                let p = self.pending.take().ok_or(ImStatus::Failure)?;
                // ★ fabric.rs 接続点 ★
                let fabric_idx = self.fabrics.add(
                    self.crypto, root_ca, icac, noc, p.keypair,
                    &ipk_epoch_key, admin_vendor_id, now_epoch_s, /*label*/ "",
                ).map_err(|e| map_fabric_err(e))?;                // Error::NoSpace → TableFull 等
                // PASE session(fabric_idx:0)を確定 fabric へ昇格。
                sessions.promote_pase_fabric(acc.session, fabric_idx);  // 追加が要る小 API
                /* NOCResponse{ statusCode: Ok, fabricIndex } */ }
            0x0a /*UpdateFabricLabel*/ => { self.fabrics.update_label(acc.fabric_idx?, label)?; }
            0x0b /*RemoveFabric*/ => { self.fabrics.remove(NonZeroU8::new(idx)?)?; }
            _ => return Err(ImStatus::UnsupportedCommand),
        }
    }
    // 属性: NOCs/Fabrics は fabric-scoped list、SupportedFabrics=NF、CommissionedFabrics=fabrics.len()、
    //       CurrentFabricIndex=acc.fabric_idx。read_attribute が fabrics.iter() を走査して組む。
}
```

- **接続点**: AddNOC → `FabricTable::add(...)`(実装済み、シグネチャ §fabric.rs:365)。証明書チェーン検証・
  compressed fabric id・operational IPK 導出はすべて `add` 内で完結(第4段階成果物)。OpCreds は
  「TLV パース + `add` 呼び出し + NOCResponse 組み立て」だけを担う薄い層。
- **fabric-scoped 属性**: `read_attribute` が `NOCs`/`Fabrics` を **fabric-filtered**(`acc.fabric_idx` の
  行だけ、または fabric_filtered=false なら全行を fabric_index 付きで)返す。§10 の fabric-scoped 判定と連動。
- **CurrentFabricIndex** は `acc`(session の fabric)から。AddNOC で PASE→CASE 移行するため、
  `promote_pase_fabric`(session.rs への小追加)で `SessionMode::Pase{fabric_idx:0}` を確定値にする。
  これは sc の commit と対称の 1 点変更(オープン論点 §12)。
- **failsafe**: AddNOC 前に ArmFailsafe(General Commissioning)が必要。CSRRequest の pending keypair は
  failsafe 中のみ保持し、failsafe expire でロールバック(General Commissioning と OpCreds が failsafe
  context を共有)。初期スコープでは failsafe を簡略実装(タイマ + rollback フック)。

---

## 10. ACL(アクセス制御)の初期スコープ

> **更新(2026-07-07)**: full ACL(Access Control クラスタ 0x001F + per-entry 照合)を
> `docs/design/acl.md` として実装済み。本節の最小近似は `DataModel::acl() == None` の
> デバイス(ACL クラスタを持たない最小構成/テスト)のフォールバックとして残る。

**明示的に絞る**。full ACL クラスタ(Access Control 0x001F の per-subject/per-target エントリ照合)は
後回しにし、最低限だけを入れる。

```rust
// im/access.rs
#[derive(Clone, Copy)] pub struct AccessContext {
    pub session: SessionId,
    pub kind: SessionKind,               // Pase | Case
    pub fabric_idx: Option<NonZeroU8>,   // Case なら Some。Pase(commissioning)は None
    pub subject: u64,                    // CASE の peer NodeId(将来 CAT 対応)
}
#[derive(Clone, Copy, PartialEq)] pub enum Privilege { View, Operate, Manage, Administer }
```

初期ポリシー(chip の default ACL を粗く近似):

1. **PASE session(commissioning window 中)** = コミッショニングに必要なクラスタ(General
   Commissioning / Network Commissioning / Operational Credentials / Basic Information の一部)へ
   **Administer 相当**を与える。それ以外のクラスタへの PASE アクセスは `UnsupportedAccess`。
2. **CASE session** = fabric メンバ。属性/コマンドの **access level(`AttributeMeta.access`)による粗いゲート**
   のみ行う。初期は「fabric メンバなら Operate まで、Manage/Administer は初回コミッショナ相当に付与」で近似し、
   **per-entry ACL 照合は行わない**(= 同一 fabric の任意 CASE subject を同権限として扱う)。
3. **fabric-scoped 属性/コマンド**(OpCreds の NOCs/Fabrics 等)は `fabric_idx` で行フィルタ(§9.4)。
   fabric_filtered read は自 fabric 行のみ、write/invoke は自 fabric のみ対象。
4. **書き込み/Invoke の privilege 不足**は `UnsupportedAccess`、**Timed 必須の write/invoke に Timed 無し**は
   `NeedsTimedInteraction`。

**割り切りの明示**: この近似は「同一 fabric 内の権限分離(Access Control クラスタ)」を実装しないため、
複数コントローラの権限差を区別できない。単一管理者・単一デバイスの縦通しには十分だが、認証テスト
(TC-ACL-*)を通すには full ACL クラスタが必要(§12 のオープン論点)。access level のメタデータ(`Access`)は
day 1 から持たせ、後日 full ACL を被せても API を変えない。

---

## 11. サイジング

IM 固有の const generic は 3 つ:

```rust
pub struct InteractionModel<D, const READS: usize, const SUBS: usize, const PATHS: usize>;
```

| パラメータ | 意味 | 既定 |
|---|---|---|
| `READS` | 同時進行のチャンク中 Read + プライミング中 Subscribe(`ReadTxnPool` slot 数) | 1〜2 |
| `SUBS` | 確立済み購読数(`SubscriptionPool` slot 数) | 2〜3 |
| `PATHS` | 1 リクエスト/購読あたりのパス数上限 | 4〜8 |

slot サイズ概算(`PATHS=4`):

| 要素 | 概算 |
|---|---|
| `ReadTxn`(paths 4 × ~16B + cursor 8B + bookkeeping) | ~90 B / slot |
| `Subscription`(paths 4 × ~16B + interval/timing + report cursor) | ~110 B / slot |
| `TimedTxn` | ~20 B / slot |

`READS=2, SUBS=3, PATHS=4` で IM の状態は **~600 B**(パケットバッファは exchange 層と共有、別枠)。

### 11.1 全体 const generic への集約とプロファイル

`docs/design/transport-exchange.md` §8 の `MatterStack<N, C, SESSIONS, EXCHANGES, RX_BUFS, TX_BUFS>` に
IM の 3 つを足す:

```rust
pub struct MatterStack<
    N, C, const SESSIONS: usize, const EXCHANGES: usize, const RX_BUFS: usize, const TX_BUFS: usize,
    const READS: usize, const SUBS: usize, const PATHS: usize,
> { /* … */ }

// プロファイルエイリアスで数値を隠す(transport-exchange §8.1 と同方針)。
pub type MinimalStack<N, C> = MatterStack<N, C, 3, 3, 1, 1, 1, 2, 4>;
pub type DefaultStack<N, C> = MatterStack<N, C, 4, 4, 2, 2, 2, 3, 8>;
```

- **`generic_const_exprs` 未安定**のため関連 const 束ね trait は不可(transport-exchange §8.2 と同じ制約)。
  素の const generic + プロファイルエイリアスで表面的な 1 名前化を達成。
- クラスタ側のストレージは `device!` が生成する device 構造体のフィールドで固定(サイジング不要。属性は
  const メタ + 小さな可変フィールドのみ)。fabric 数 `NF` は fabric 層の既存パラメータを流用。

---

## 12. イベント(最小実装)

Matter のイベント(Core Spec §8.4 / §10.6.9 EventDataIB)を最小構成で実装する。範囲は
「デバイスがイベントをリングに積み、ReadRequest の EventPaths に対して EventReportIB を返す」まで。
Subscribe のイベント配信は範囲外(下記)。

### 12.1 イベントログ(リングバッファ)

`im/events.rs` の `EventLog<const N: usize = 8>`(IM エンジンが所有、容量 `EVENT_LOG_CAP = 8`)。
1 エントリ(`EventRecord`)は endpoint / cluster / event / `event_number`(u64 グローバル単調増加)/
priority(u8: DEBUG=0 / INFO=1 / CRITICAL=2)/ SystemTimestamp(起動起点の単調 ms)/ payload
(EventDataIB.Data の値要素の生 TLV、固定 `EVENT_PAYLOAD_MAX = 32` バイト)を持つ。満杯時は
最古を追い出す(リング)。`InteractionModel::post_event(...)` / `events()` でアクセスし、`MatterStack`
は `post_event` と `post_startup_event(software_version, now_ms)` を passthrough する。

### 12.2 ワイヤ形式(chip 互換、E2E の生命線)

タグ番号は chip `src/app/MessageDef/*.h` に一致させた:

- **EventReportIB**: `EventStatus`=0, `EventData`=1(本実装は EventData のみ生成)。
- **EventDataIB**: `Path`=0, `EventNumber`=1, `Priority`=2, `EpochTimestamp`=3, `SystemTimestamp`=4,
  `DeltaEpochTimestamp`=5, `DeltaSystemTimestamp`=6, `Data`=7。**壁時計を持たないため
  SystemTimestamp(4)を使う**(EpochTimestamp は書かない。chip-tool は SystemTimestamp を受理)。
- **EventPathIB**(list): `Node`=0, `Endpoint`=1, `Cluster`=2, `Event`=3, `IsUrgent`=4。
- **EventFilterIB**(struct): `Node`=0, `EventMin`=1。
- **ReadRequest**: `EventRequests`=1(EventPathIB のリスト), `EventFilters`=2。
- **ReportData**: `EventReports`=2(AttributeReports=1 の後に書く)。

StartUp イベント(BasicInformation 0x0028 / event 0x00 / CRITICAL)の Data は
`{ softwareVersion: u32 (field 0) }`。デバイス起動直後に `post_startup_event` で 1 回積む
(examples/onoff-light と ports/esp32 の e3/e4/e5 bin。`BasicInfoConfig::software_version` を渡す)。

### 12.3 Read の EventPaths 対応

`ReadRequest` の `EventRequests`(EventPathIB リスト)を解釈し、合致イベントを EventReportIB として
同一 ReportData に載せる(AttributeReports の後に EventReports 配列)。ワイルドカード(endpoint /
cluster / event 省略)対応。`EventFilters` の `eventMin` があれば `event_number >= eventMin` のみ返す
(先頭フィルタの eventMin のみ解釈)。属性チャンク化(§5.4)の最終チャンク完了後に 1 回だけ
イベントを出力する(`ReadTxn::events_emitted` で単一化)。

### 12.4 割り切り(意図的な制約)

- **永続化なし**: `event_number` は起動でリセットされる(仕様上は永続カウンタだが、chip-tool の
  単発 read には実害なし)。
- **priority 別バッファなし**: 単一リング。満杯時は priority に関わらず最古を追い出す。
- **イベントのチャンク化なし**: イベント数が少ない前提で 1 ReportData に収まる範囲で載せる。入り
  切らないイベントはドロップ(§5.4 の属性 chunking 機構はイベントに適用しない)。
- **per-event ACL 近似**: イベント read の権限は属性 read と同等(View、`(endpoint, cluster)`)で近似
  する(仕様の per-event 権限は割り切り)。
- **Subscribe のイベント配信は未対応**: 購読へのイベント通知(IsUrgent / 定期配信)は範囲外。
  `EventLog` と Read 経路のみで、`poll_subscriptions` はイベントを見ない。将来課題(§12.5)。

### 12.5 将来課題

Subscribe のイベント対応(購読パスの EventRequests、dirty 相当の「新規イベント」通知、IsUrgent に
よる即時レポート)。属性の dirty 追跡(§6.2)と同様に、購読ごとに「最後に配信した event_number」を
保持して差分配信する形が素直。永続 event_number(リブート跨ぎの単調性)も同時に検討する。

---

## 13. オープンな論点

1. **Subscribe device 発レポートの統合層契約**(§6.3)。`poll_subscriptions` + `open_initiator` +
   `send_reliable` の配線を統合層(第6段階)がどう回すか。`ExchangeManager::next_deadline` と
   `im.next_deadline` を min する単一タイマで足りるか、購読数が増えたときの走査コスト(O(SUBS))は許容か。
2. **DataVersion フィルタ**(§6.2)。初期は「関係クラスタ dirty → 購読パス全再送」で過剰報告。属性単位の
   DataVersion カウンタ + 購読側 last-reported version で「変更属性だけ送る」への拡張余地。RAM(購読ごとに
   version 表)と正確性のトレードオフ。
3. **full ACL クラスタ**(§10)。Access Control 0x001F の per-entry 照合をいつ入れるか。認証テスト
   (TC-ACL-*)通過には必須。`AccessContext` に subject/CAT を既に持たせてあるので後付け可能な形か要確認。
4. **`FromTLV`/`ToTLV` derive(proc-macro)の要否**(§8.1)。コマンド payload / struct 属性(Descriptor の
   DeviceTypeStruct 等)のデコードが増えたら proc-macro が boilerplate を減らす。8 クラスタでは手書きで足りる
   見込みだが、General/Network Commissioning のコマンド引数が多いので早期に再評価。
5. **session.rs への `promote_pase_fabric` 追加**(§9.4)。PASE→CASE の fabric 確定を session API に足す
   1 点変更。sc の reserve/commit と対称。IM が SessionManager を可変で触る唯一の箇所で、責務境界
   (IM は本来 session を書き換えない)をどう整理するか。
6. **failsafe / ArmFailsafe の実装深度**(§9.4)。AddNOC 前提の failsafe timer + rollback(pending keypair /
   pending fabric)を General Commissioning と OpCreds でどう共有するか。初期は簡略実装だが、
   MaxCumulativeFailsafe / BreadcrumbValue の扱いを明確化する必要。
7. **単一属性が 1 パケットに入らない場合の list chunking**(§5.4)。初期は `ResourceExhausted` で逃げるが、
   大 list 属性(将来の ACL エントリ list 等)は AttributeReportIB を list 要素単位でチャンクする必要
   (chip の list chunking)。`AttrEncoder` の粒度をどこまで細かくするか。
8. **`ReadTxn` / Subscription のタイムアウト掃除**(§5.3/§6)。sc の `on_tick` と同じく、放置された
   チャンク中 Read や無応答購読を掃除する `on_tick(now_ms)` を IM が持つ。exchange の `poll` /
   sc の `on_tick` と 3 者の deadline をどう 1 ループに束ねるか(統合層の設計、第6段階)。
9. **`dm::codec` の複雑型対応**(§7.2)。単純型は `AttrEncoder` で足りるが、struct/list of struct を
   object-safe な `&mut dyn` 越しにどこまで扱うか。GAT を避けつつ nested writer をどう提供するか。

---

## 14. 参照実装との対応表

| 論点 | rs-matter | chip | 本設計 |
|---|---|---|---|
| wire とエンジンの分離 | `im.rs` に同居 | `protocols/im`(定数)+ `app`(エンジン) | **分離**(chip 寄り, §1) |
| ハンドラ契約 | `async fn`(往復を await) | delegate + 状態 | **同期 sans-IO + ExchangeId slot**(実装済み契約, §3) |
| チャンク ReportData | async スタックが保持 | `ReadHandler` 状態機械 | **ReadTxn slot + PathExpandCursor**(§5) |
| ワイルドカード展開 | `im/expand.rs`(alloc) | `AttributePathExpandIterator` | **インデックス Cursor**(no-alloc, §5.2) |
| Subscribe レポート | async タスク | `reporting/Engine` + `ReportScheduler` | **poll_subscriptions + 統合層 open_initiator**(§6) |
| メタ+dispatch 単一ソース | Node(const)+ChainedHandler(二重) | ServerClusterInterface(combined) | **ServerCluster 1 実装 + cluster!/device! マクロ**(§7,§8) |
| クラスタ合成 | `ChainedHandler` タプル | `&ServerClusterInterface` registry | **`&dyn ServerCluster` registry**(型爆発回避, §8.3) |
| コード生成 | 416KB IDL 全生成 | ZAP + matter-idl | **手書き + macro_rules(proc-macro なし)**(§8.1) |
| グローバル属性 | 生成 | AttributeListBuilder | **エンジンが const メタから自動導出**(§7.1) |
| クラスタ実装 | logic/translation 二層あり | combined 推奨 | **combined**(§9) |
| ACL | `acl.rs` full | Access Control + AccessControl.cpp | **最小近似(CASE=fabric, PASE=commissioning)**(§10) |
| fabric 接続 | `state.fabrics` 直参照 | FabricTable | **OpCreds → 実装済み `FabricTable::add`**(§9.4) |
| サイジング | ~100 feature | CHIPConfig 定数 | **const generic 3 + プロファイル**(§11) |

**借りるもの**: wire とエンジンの分離、`DataModel::Provider` 抽象、`AttributePathExpandIterator`、combined
クラスタ、ServerClusterInterface registry、グローバル属性の builder 導出、IM Status/opcode 語彙。
**変える点**: (a) 往復駆動を async から同期 slot 機構へ(実装済み契約準拠、最大の差)、(b) 合成を
ChainedHandler から `&dyn` registry へ(型爆発回避)、(c) コード生成を macro_rules に絞り proc-macro を
初期は持たない、(d) Subscribe device 発を IM 駆動 API + 統合層送信に分離(sans-IO 送受信分離の保持)、
(e) ACL を初期スコープで明示的に近似する。
