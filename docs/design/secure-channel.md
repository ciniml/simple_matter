# sc 層(Secure Channel)設計 — PASE / CASE responder(ロードマップ第3段階)

対象: `docs/ARCHITECTURE.md` の「レイヤ構成」における `sc` 層。Matter デバイス
(responder)専用・`no_std`・定常パス no-alloc・executor 非依存を前提とする。

- 上位境界: `sc` は Protocol ID **0x0000(Secure Channel)** の [`ProtocolHandler`] を
  実装し、`exchange` 層(`ExchangeManager`)から復号済み平文メッセージを受け取る。
- 下位境界: セッション確立の成果物(鍵・mode)を `transport` の `SessionManager` に
  `reserve → commit` の 2 相で書き込む。暗号プリミティブは `crypto` の `Crypto` trait
  越しにのみ触る(暗号境界は既に `transport::secure` に 1 点化済み。sc は鍵導出のみ)。
- 第4段階境界: fabric / 証明書(NOC/ICAC/RCAC・IPK・DAC)への依存は **最小の trait**
  で切り、CASE がその trait だけに依存する形にする(§8)。

本書はシグネチャスケッチを含むが、コンパイル可能性より設計判断の明確化を優先する。
参照実装は `research/rs-matter/rs-matter/src/sc/`(以下 rs-matter)、
`research/connectedhomeip/src/protocols/secure_channel/`(以下 chip)、matter.js
の `packages/protocol`。既存の下位層設計は `docs/design/transport-exchange.md`(以下
transport-exchange)を参照する。

---

## 0. サマリ(主要な設計判断)

1. **同期 sans-IO の state-machine ハンドラ**。既存の [`ProtocolHandler`](
   `exchange/dispatch.rs`)は rs-matter の「async fn が複数往復を await で表現する」
   方式ではなく、**1 メッセージ = 1 回の同期 `handle` 呼び出し**に確定している(§4)。
   したがって sc のハンドシェイクは、往復のまたぎを **明示的な runtime 状態 enum**
   (`PasePhase`/`CasePhase`)として `ExchangeId` ごとに保持する state machine で表現する。
   これが rs-matter との最大の構造差であり、本層のすべての形を規定する。
2. **typestate は「1 メッセージ処理内の crypto パイプライン」に限定**。ARCHITECTURE の
   「typestate はハンドシェイクに限定」は踏襲するが、**往復をまたぐ**進行は runtime enum に
   する(SessionMode を enum にしたのと同じ理由 = 固定容量 slot に同型で格納するため)。
   typestate は Spake2+ / Sigma のサブステップ順序(点計算 → 鍵導出 → 検証)を型で誤順序
   防止する内側にのみ使う(§5.2, §6.2)。
3. **ハンドシェイク一時状態は固定容量プール**(既定 `HANDSHAKES=1`)。大バッファ
   (トランスクリプトハッシュ状態・Spake2+ 中間値・CASE の相手 NOC 一時展開)は
   `HandshakeSlot` に押し込み、同時ハンドシェイク数を const generic で 1〜2 に絞る。
   2 本目以降は **Busy StatusReport** で即断る(§5, §7)。chip/rs-matter は「ハンドラ本数」で
   暗黙に絞るが、本層は数を明示する。
4. **StatusReport がプロトコルの終端語彙**。成功も失敗も、PASE Pake3 後 / CASE の各拒否は
   単一の StatusReport メッセージで通知する(成功 = `SessionEstablishmentSuccess`、
   Busy/CloseSession/SessionNotFound は R フラグを落とす)。sc はこの 1 種のフレームで
   終端を表現し、上位に enum の結果を返す(§3)。
5. **fabric/credentials への依存は 3 つの読み取り専用 trait に集約**(`FabricStore` /
   `Fabric` / `NocResolver`)。CASE responder はこの trait だけに依存し、第4段階の
   `FabricTable` 実装差し替えで CASE 本体を変えない。第3段階では PASE を先に縦通しし、
   CASE はこの trait 境界のスタブ(単一 fabric のモック)で単体テストする(§8)。
6. **応答生成は `HandlerAction` の拡張で表現**。現状 placeholder の `HandlerAction::None`
   に `Respond { opcode, reliable, len }`(+ 出力バッファ)variant を足し、ハンドラが
   「この opcode でこの payload を(信頼)送れ」と宣言、実送信は既存の `ExchangeManager`
   送信 API が行う(sans-IO の送受信分離を保つ)。これは exchange 層への **最小の追加**で、
   本書はその契約を定義する(実装は別ピース、§4.3)。

---

## 1. モジュール構成と依存関係

`crates/simple-matter/src/sc/` 配下(実装は別ピース。本書は設計のみ)。

```
sc/
  mod.rs         SecureChannel(ProtocolHandler 実装), OpCode, StatusReport,
                 SessionParameters, ScResult。opcode → handler ディスパッチ。
  status.rs      StatusReport の parse/encode, GeneralCode, ScStatusCode, 運用ヘルパ。
  handshake.rs   HandshakeSlot / HandshakePool(固定容量), PasePhase / CasePhase の格納。
  pase/
    mod.rs       PBKDFParamReq/Resp, Pake1/2/3 の TLV 型と info 定数。
    responder.rs PASE responder state machine(PBKDFParamRequest→Pake1→Pake3)。
  case/
    mod.rs       Sigma1/2/3 の TLV 型, 鍵導出 info 定数, destination-id 計算。
    responder.rs CASE responder state machine(Sigma1→Sigma3)。
    creds.rs     第4段階への trait 境界(FabricStore/Fabric/NocResolver)+ テスト用モック。
  spake2p.rs     Spake2+ の高レベル手順(crypto の Spake2p プリミティブを束ねる。
                 crypto 側 API が確定したら thin にする。§6.3)。
```

### 依存方向(下→上の一方向)

```
error, tlv, crypto                              … 既存
   ▲
transport::session (SessionManager, reserve/commit, SessionMode)
transport::header  (PayloadHeader)
   ▲
exchange::dispatch (ProtocolHandler, RxMessage, HandlerAction)   … sc が実装する境界
exchange::exchange (ExchangeManager 送信 API, ExchangeId)
   ▲
sc::status ── sc::spake2p ── sc::case::creds(trait 境界)
   ▲
sc::pase / sc::case(state machine)
   ▲
sc::mod (SecureChannel = ProtocolMux の Sc スロット)
```

- `sc` は `im` を知らない。`ProtocolMux<Sc, Im>`(既存 `exchange/dispatch.rs`)の `Sc`
  スロットに `SecureChannel` が入る。BDX 追加時も sc は不変。
- `case::creds` の trait は `sc` 内に**定義**し、第4段階の `fabric` モジュールが**実装**する
  (依存性逆転。matter.js の「プロトコル本体はプラットフォーム trait のみに依存」に一致)。

**rs-matter との差**: rs-matter は `sc.rs` に `SecureChannel<'a,C>` を置き、`handle` が
`async fn` で `exchange.recv_fetch().await` を挟みながら PBKDF→Pake1→Pake3 を**一直線に**
書く(`pase/responder.rs` の `handle_inner`)。本設計は同期モデルのため、この一直線を
**イベント駆動の state machine に分解**する(§4)。ファイル分割の方針(mod/pase/case/status)
は rs-matter を踏襲する。

---

## 2. Secure Channel メッセージ種別(OpCode)

Protocol ID = `0x0000`。opcode は rs-matter / chip と同一(仕様値)。

```rust
// sc/mod.rs
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    MsgCounterSyncReq  = 0x00,   // group 用。初期スコープ外
    MsgCounterSyncResp = 0x01,   //   〃
    MrpStandaloneAck   = 0x10,   // exchange 層が既に生成(MRP_STANDALONE_ACK_OPCODE)
    PbkdfParamRequest  = 0x20,   // ← PASE responder 入口
    PbkdfParamResponse = 0x21,
    PasePake1          = 0x22,
    PasePake2          = 0x23,
    PasePake3          = 0x24,
    CaseSigma1         = 0x30,   // ← CASE responder 入口
    CaseSigma2         = 0x31,
    CaseSigma3         = 0x32,
    CaseSigma2Resume   = 0x33,   // resumption(§7.4)
    StatusReport       = 0x40,
}

impl OpCode {
    /// 受信 opcode を判別。未知は Error::Decode。
    pub fn from_u8(v: u8) -> Result<Self>;
    /// TLV ペイロードを持つか(StatusReport / StandaloneAck / MsgCounterSync は非 TLV)。
    pub fn is_tlv(&self) -> bool;
    /// このメッセージは信頼送信(R フラグ)か。StandaloneAck のみ false。
    pub fn reliable(&self) -> bool;
}
```

- **responder が受理する入口 opcode は 2 つだけ**: `PbkdfParamRequest`(PASE)と
  `CaseSigma1`(CASE)。この 2 つは「新規ハンドシェイクの開始」で、`ExchangeManager` が
  作った新 responder exchange の最初のメッセージとして届く。
- それ以外の受信 opcode(Pake1/Pake3/Sigma3 等)は「**進行中ハンドシェイクの続き**」で、
  `ExchangeId` から既存 `HandshakeSlot` を引いて処理する(§4.2)。対応 slot が無い続き
  opcode は状態違反 → `InvalidState`(silent drop または CloseSession)。
- `MrpStandaloneAck` は sc へは来ない(exchange 層が MRP として消費済み。transport-exchange
  §5.4/§6)。`MsgCounterSyncReq/Resp` は group session 用で初期スコープ外。

---

## 3. StatusReport(終端語彙)

Matter 仕様 "Appendix D: Status Report Messages"。**非 TLV** の固定バイト列。

### 3.1 バイトレイアウト(全て little-endian)

```
| GeneralCode : u16 | ProtocolId : u32 | ProtocolCode : u16 | ProtocolData : [u8] |
```

`StatusReport` メッセージの payload は上記そのもの(PayloadHeader の後、TLV ではない)。

```rust
// sc/status.rs
pub struct StatusReport<'a> {
    pub general_code: GeneralCode, // u16
    pub proto_id: u32,             // SC 終端では PROTO_ID_SECURE_CHANNEL(=0)
    pub proto_code: u16,           // ScStatusCode
    pub proto_data: &'a [u8],      // Busy では 500ms の retry-delay(u16 LE)等
}
impl<'a> StatusReport<'a> {
    pub fn decode(buf: &'a [u8]) -> Result<Self>;      // le_u16, le_u32, le_u16, rest
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<()>;
}
```

### 3.2 コード値(仕様固定)

```rust
#[repr(u16)]
pub enum GeneralCode {   // Appendix D 汎用コード(抜粋)
    Success = 0, Failure = 1, BadPrecondition = 2, OutOfRange = 3,
    BadRequest = 4, Unsupported = 5, Unexpected = 6, ResourceExhausted = 7,
    Busy = 8, Timeout = 9, /* … */ NotFound = 13,
}

#[repr(u16)]
pub enum ScStatusCode {  // Secure Channel protocol code(chip Constants.h / rs-matter 一致)
    SessionEstablishmentSuccess = 0x0000,
    NoSharedTrustRoots          = 0x0001,
    InvalidParameter            = 0x0002,
    CloseSession                = 0x0003,
    Busy                        = 0x0004,
    SessionNotFound             = 0x0005,
}
```

### 3.3 運用(成功通知・エラー通知)

`ScStatusCode` → `GeneralCode` のマップと R フラグ(rs-matter `SCStatusCodes` を踏襲):

| ScStatusCode | GeneralCode | R フラグ | proto_data | 用途 |
|---|---|---|---|---|
| SessionEstablishmentSuccess | Success | あり | 空 | PASE Pake3 / CASE Sigma3 検証成功。**確立完了通知** |
| CloseSession | Success | **なし** | 空 | 明示的セッション終了 |
| Busy | Busy | **なし** | `retry_delay_ms: u16 LE`(既定 500) | 同時ハンドシェイク上限超過(§5) |
| SessionNotFound | Failure | **なし** | 空 | 進行中セッション不明(状態違反) |
| InvalidParameter | Failure | あり | 空 | パラメータ不正(passcode_id≠0, 曲線点不正 等) |
| NoSharedTrustRoots | Failure | あり | 空 | CASE: destination-id が既知 fabric に一致せず |

- **成功も StatusReport**。sc は「成功時に att_challenge を含む鍵をセッションへ commit
  した上で `SessionEstablishmentSuccess` を送る」。CloseSession/Busy/SessionNotFound を
  R なしで送るのは、これらが「もう会話を続けない」通知で ACK 往復が不要なため。
- **鍵確立 → 送信の順序が重要**(rs-matter `handle_pasepake3` のコメント)。成功
  StatusReport を送る**前に** `commit()` で新セッションを Active にする。commit 前に応答を
  送ると、相手が新セッションで送る最初のメッセージを Reserved のまま取りこぼす。

---

## 4. exchange 層との接続 — 同期ハンドラで複数往復を表現する

**本層で最も重要な設計判断**。既存 `exchange/dispatch.rs` の

```rust
pub trait ProtocolHandler {
    const PROTOCOL_ID: u16;
    fn handle(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction>;  // 同期・1 メッセージ
}
```

は sans-IO 同期モデルであり、rs-matter のように 1 つの `async fn` で往復を await できない。
PASE は 3 往復(PBKDF/Pake1/Pake3 受信 → PBKDFResp/Pake2/Status 送信)、CASE は 2 往復ある。

### 4.1 分解: state machine + `ExchangeId` キー

各往復を**別々の `handle` 呼び出し**として受け、進行を `ExchangeId` ごとの `HandshakeSlot`
に保存する。`SecureChannel::handle` は毎回:

1. `rx.header.proto_opcode` を `OpCode` に。
2. 入口 opcode(`PbkdfParamRequest`/`CaseSigma1`)なら **新規 slot を確保**して初期状態へ。
   確保できない(上限超過)なら `Busy` を返して終わり。
3. 続き opcode なら `rx.exchange`(= `ExchangeId`)で既存 slot を引き、**現在の phase と
   受信 opcode の整合を確認**して 1 ステップ進める。不整合は `SessionNotFound`/`InvalidState`。
4. ステップの結果として**送るべき応答**を `HandlerAction` で宣言して返す。
5. 終端(成功 Status / エラー Status を送った)なら slot を解放。

```rust
// sc/mod.rs
pub struct SecureChannel<'c, C: Crypto, F: FabricStore, const H: usize> {
    crypto: &'c C,
    fabrics: F,                    // CASE 用(§8)。PASE のみなら NullFabrics 可
    commissioning: CommissioningState, // comm window / PASE verifier / failure count(§6.4)
    handshakes: HandshakePool<H>,  // 進行中ハンドシェイクの固定プール(§5)
}

impl<C: Crypto, F: FabricStore, const H: usize> ProtocolHandler
    for SecureChannel<'_, C, F, H>
{
    const PROTOCOL_ID: u16 = PROTO_ID_SECURE_CHANNEL;
    fn handle(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        match OpCode::from_u8(rx.header.proto_opcode)? {
            OpCode::PbkdfParamRequest => self.pase_open(rx),   // 新規 PASE
            OpCode::CaseSigma1        => self.case_open(rx),    // 新規 CASE
            OpCode::PasePake1 | OpCode::PasePake3 => self.pase_step(rx),
            OpCode::CaseSigma3        => self.case_step(rx),
            OpCode::StatusReport      => self.on_peer_status(rx), // 相手からの中断
            other => { /* log */ Err(Error::InvalidState) }
        }
    }
}
```

### 4.2 `HandshakeSlot` の索引と生存

- slot は `ExchangeId`(`{ SessionId, exch_id }`)をキーに引く。入口 opcode は
  `ExchangeManager` が作った**新 responder exchange**の初回メッセージなので、その
  `ExchangeId` を slot に記録する。以降の続きは同一 exchange で届くため一致で引ける。
- PASE は**非暗号(unsecured)セッション上**で PBKDF/Pake1/Pake3 が流れる。Pake3 成功時に
  初めて暗号セッションを別 `SessionId` で commit する(§6.5)。よって slot キーは
  「ハンドシェイクを運ぶ unsecured exchange の `ExchangeId`」で一貫する。
- slot は「予約した `SessionId`」も保持する(reserve → commit を貫くため、§6.5)。
- 中断・タイムアウト・完了で slot を解放。タイムアウトは exchange 層の `poll`(MRP)とは
  別に、sc が `on_tick(now_ms)` で 60s(`PASE_SESSION_EST_TIMEOUT`)超過 slot を掃除する
  (§6.4)。

### 4.3 応答生成: `HandlerAction` の拡張(exchange 層への最小追加契約)

現状 `HandlerAction::None` のみ。sc の各ステップは応答メッセージを 1 通(または終端 Status)
返す必要がある。**提案する拡張**(実装は exchange ピースが行う。本書は契約を定義):

```rust
// exchange/dispatch.rs(将来拡張)
pub enum HandlerAction {
    None,
    /// ハンドラが応答 payload を書いた。exchange 層がヘッダ付与・暗号化・(信頼)送信する。
    Respond { opcode: u8, proto_id: u16, reliable: bool, len: usize },
    /// このハンドシェイクを終端し exchange を閉じてよい(終端 Status 送出後)。
    Close   { opcode: u8, proto_id: u16, reliable: bool, len: usize },
}
```

- ハンドラには**出力バッファへの可変参照**を渡す必要がある。よって `handle` シグネチャは
  `fn handle(&mut self, rx: &RxMessage<'_>, tx: &mut WriteBuf<'_>) -> Result<HandlerAction>`
  へ拡張する(headroom は exchange 層が確保済み)。ハンドラは `tx` に payload を書き、
  `Respond { len }` を返す。**送信は exchange 層**が `build_packet`(既存)経由で行うため、
  sans-IO の送受信分離と暗号境界 1 点を保つ。
- rs-matter の `exchange.send_with(|_, wb| ...)` クロージャは、同じ「ハンドラが wb に書き
  exchange が送る」構造。本設計は async を排し、それを戻り値(`HandlerAction::Respond`)へ
  写像しただけである。
- **これは exchange 層の 1 箇所の拡張**で、transport-exchange の受信一本道(`recv` が
  `dispatch` の戻り値 `action` を `RecvReport.action` に載せる、既存)にそのまま乗る。
  `recv` 側は `action` が `Respond`/`Close` のとき、渡した tx バッファを送信キューへ回す。

**判断根拠**: 同期 sans-IO を崩さずに複数往復を実現する唯一の素直な形は「状態を外に持ち、
入力ごとに 1 出力を返す Mealy machine」。async にすると executor 依存と `.await` またぎの
借用問題(transport-exchange §5.3 が避けた)が sc に戻ってくる。状態を `HandshakeSlot` に
外出しすることで、ハンドラ自身は再入可能・借用フリーに保てる。

---

## 5. ハンドシェイク一時状態の管理(HandshakePool)

### 5.1 どこに置くか

ハンドシェイク中の大きな一時状態:

| 状態 | 概算サイズ | 使途 |
|---|---|---|
| トランスクリプトハッシュ(SHA-256 incremental) | ~112 B(`Crypto::Sha256` の内部 state) | PASE context hash / CASE TT |
| Spake2+ 中間(w0/w1, X/Y/Z/V 点, K_e) | ~300–400 B | PASE Pake1→Pake2→Pake3 |
| responder random / initiator random | 32 B ×2 | PBKDFParamResponse / Sigma |
| 導出鍵(dec/enc/att = 16×3) | 48 B | commit 直前まで保持 |
| CASE: 相手 NOC/ICAC の一時展開・署名検証域 | 最大 ~1 KB(`MAX_CERT_TLV_LEN*2`) | Sigma3 復号後の証明書検証 |
| 予約した SessionId / peer session id / mode | 数 B | reserve→commit を貫く |

これらを **1 つの `HandshakeSlot` 構造体**に格納し、`HandshakePool<H>` で `H` 本だけ静的確保。

```rust
// sc/handshake.rs
pub struct HandshakeSlot {
    exchange: ExchangeId,        // 索引キー(§4.2)
    reserved: SessionId,         // reserve() で先取りした slot(§6.5)
    started_ms: u64,             // タイムアウト判定
    peer_session_id: u16,
    kind: HandshakeKind,         // Pase(PaseCtx) | Case(CaseCtx)
}
pub enum HandshakeKind { Pase(PaseCtx), Case(CaseCtx) }

pub struct HandshakePool<const H: usize> {
    slots: FixedVec<HandshakeSlot, H>,   // 既存 transport::session::fixed::FixedVec を流用
}
impl<const H: usize> HandshakePool<H> {
    pub fn open(&mut self, ex: ExchangeId, reserved: SessionId, now: u64, kind: HandshakeKind)
        -> Result<&mut HandshakeSlot>; // 満杯なら Err(NoSpace) → 呼び出しが Busy を返す
    pub fn get(&mut self, ex: ExchangeId) -> Option<&mut HandshakeSlot>;
    pub fn close(&mut self, ex: ExchangeId) -> Option<HandshakeSlot>; // reserved 解放は呼び出し
    pub fn evict_expired(&mut self, now: u64, timeout_ms: u64) -> impl Iterator<Item=HandshakeSlot>;
}
```

`PaseCtx` / `CaseCtx` は `union` ではなく enum の内側 struct。両者の最大サイズが slot を
支配するので、CASE の証明書検証域は**slot に常駐させず**、Sigma3 処理の**呼び出しスタック**に
置くか、パケットバッファ(受信 RX を in-place で使う)に載せて slot からは外す(§7.2)。

### 5.2 typestate と runtime enum の使い分け(ARCHITECTURE の「typestate 限定」の解釈)

- **往復をまたぐ進行** = runtime enum(`PasePhase`/`CasePhase`)。理由は SessionMode を
  enum にした transport-exchange §4.1 と同一: 固定容量 slot に同型格納し、`ExchangeId` で
  引いて任意順の入力を弾く必要があるから。typestate 型は slot に同型格納できない。
- **1 メッセージ処理内の crypto サブステップ順序** = typestate。Spake2+ の
  「w0/w1 セット → pB/cB 計算 → K_e 検証」や CASE の「ECDH → S2K 導出 → TBE 復号 →
  署名検証」は 1 回の `handle` 内で線形に進むので、中間オブジェクトを `self` 消費する
  typestate(`Spake2pVerifier → Spake2pConfirm`)で誤順序をコンパイル時に防ぐ。
- これで ARCHITECTURE の意図(「順序保証に typestate」)を守りつつ、sans-IO の event-driven
  外殻と両立させる。**変える点の理由**を明記: rs-matter は async の線形フローで往復も
  typestate 的に扱えるが、本設計は同期分解のため往復進行だけ runtime enum に落とす。

---

## 6. PASE responder

### 6.1 状態遷移(テキスト図)

```
                [unsecured session 上の responder exchange]
 (start)
   │  rx PBKDFParamRequest(0x20)
   ▼
 ┌─────────────┐  tx PBKDFParamResponse(0x21, 信頼)   slot 確保・reserve(SessionId)
 │  Idle       │──────────────────────────────────────►┐
 └─────────────┘   ・context hash に req/resp を投入       │
                    ・comm window 無 → silent drop         ▼
                    ・2 本目のハンドシェイク → Busy      ┌──────────────┐
                                                        │ PbkdfSent    │
                    rx PASEPake1(0x22) ─────────────────┤              │
                    ・pA 受領, Spake2+ verifier セット     └──────────────┘
                    ・pB, cB 計算                              │
                    tx PASEPake2(0x23, 信頼) ◄────────────────┘
                                                              │
                                                              ▼
                                                        ┌──────────────┐
                    rx PASEPake3(0x24) ─────────────────┤ Pake2Sent    │
                    ・cA 検証                             └──────────────┘
                       ├─ OK:  K_e → HKDF("SessionKeys") → dec/enc/att   │
                       │       commit(reserved, keys, Pase{fab_idx:0})    │
                       │       tx StatusReport(Success, 信頼) ───────────►(done, slot 解放)
                       └─ NG:  失敗カウント++, tx StatusReport(InvalidParameter) ─►(done)
```

- **1 メッセージ ↔ 1 ハンドラステップの 1:1**(ARCHITECTURE 原則): PBKDFParamRequest→
  `pase_open`、Pake1/Pake3→`pase_step`。Pake2 は Pake1 ステップの応答、成功 Status は
  Pake3 ステップの応答として同一呼び出しで返す。
- **rs-matter との対応**: `handle_inner` の一直線(`handle_pbkdfparamrequest` →
  `recv_fetch` → `handle_pasepake1` → `recv_fetch` → `handle_pasepake3`)を、`recv_fetch`
  の位置で切って 3 つの `handle` 呼び出しに分解したもの。中間の `PbkdfSent`/`Pake2Sent`
  が rs-matter の `await` 点に対応する。

### 6.2 メッセージ型(TLV)

```rust
// sc/pase/mod.rs
struct PbkdfParamReq<'a> {  // ctx 1..
    initiator_random: &'a [u8],  // 32
    initiator_ssid: u16,         // 相手のワイヤ session id
    passcode_id: u16,            // 0 のみ対応(≠0 は InvalidParameter)
    has_params: bool,
    session_parameters: Option<SessionParameters>, // MRP SII/SAI/SAT(peer 広告)
}
struct PbkdfParamResp<'a> {
    initiator_random: &'a [u8], responder_random: &'a [u8], responder_ssid: u16,
    params: Option<PbkdfParamRespParams<'a>>,      // has_params=false のとき同送
    session_parameters: Option<SessionParameters>,
}
struct PbkdfParamRespParams<'a> { iterations: u32, salt: &'a [u8] }  // salt 16..=32
struct Pake1<'a> { pa: &'a [u8] }   // ctx 1: SEC1 65B
struct Pake2<'a> { pb: &'a [u8], cb: &'a [u8] }  // 65B, 32B
struct Pake3<'a> { ca: &'a [u8] }   // 32B
```

`SessionParameters`(SII/SAI/SAT ほか)は sc 共通型として `sc/mod.rs` に置き、CASE Sigma1/2 と
共用する。受領した peer の MRP パラメータは、(a) 現在ハンドシェイクを運ぶ unsecured
セッションと (b) reserve した PASE セッションの両方の `MrpConfig` に反映する(Pake2 再送が
peer の SAI を尊重するため。rs-matter と同旨)。

### 6.3 Spake2+ プリミティブとの接続(crypto 層への追加予定)

crypto は現状 SHA/HMAC/HKDF/AES-CCM/P-256 を持つが **Spake2+ は未実装**(`crypto.rs` の
scope 注記)。別ピースが crypto に追加する。sc からの要求 API(責務分界):

```rust
// crypto 側に追加を要する Spake2+ プリミティブ(responder が使う分)
//  ・verifier(w0, L)から pB(EC 点)と cB(HMAC)を計算
//  ・pA を受けて Z, V を計算し K_e(16B)を導出、cA を検証
// sc 側(spake2p.rs)はこれを phase 順に呼ぶ薄いラッパにする。
pub const SPAKE2P_SESSION_KEYS_INFO: &[u8] = b"SessionKeys"; // HKDF info(11B)
pub const SPAKE2P_KE_LEN: usize = 16;
pub const SPAKE2P_VERIFIER_SALT_LEN: usize = 32;    // 16..=32
pub const SPAKE2P_RANDOM_LEN: usize = 32;
```

- **verifier の入力**: PASE は passcode を持たず、**Spake2+ verifier**(w0, L)+ salt +
  iterations を持つ(コミッショニング設定で焼く)。responder は passcode 検証をせず、
  verifier だけで pB/cB を作る。これが `CommissioningState`(§6.4)に置かれる。
- **鍵導出**: Pake3 検証成功で得た `K_e`(16B)から
  `HKDF(salt=[], ikm=K_e, info="SessionKeys", L=48)` で 48B を導出し、先頭から
  **I2R(dec)16 / R2I(enc)16 / AttestationChallenge 16** に分割(rs-matter
  `Spake2pSessionKeys` の split と同一。responder 視点で dec=I2R, enc=R2I)。
- **context hash**: 固定プレフィックス `"CHIP PAKE V1 Commissioning"` に続けて
  PBKDFParamRequest と PBKDFParamResponse の**生バイト列**を SHA-256 に逐次投入して
  context を作り、Spake2+ の transcript(TT)に混ぜる(rs-matter `SPAKE2P_CONTEXT_PREFIX`、
  chip `kSpake2pContext` と一致)。response の生バイトは TLV 直列化後にしか分からないので、
  **応答を送信する `handle` 呼び出し内で** context を確定する(rs-matter が `send_with`
  クロージャ内で `finish_context` するのと同じタイミング)。sc は `Crypto::Sha256`
  incremental をそのまま使う(トランスクリプト用途は crypto.rs のドキュメントに明記済み)。
  PBKDF2 反復回数は既定 `2000`(`SPAKE2P_ITERATION_COUNT`)。

#### 6.3.1 デバイスは verifier のみ保持する(passcode を持たない)

Matter のセキュリティ要件上、**デバイス側(responder)は passcode を保持してはならない**。
デバイスが持つのは SPAKE2+ 検証子 `(w0, L)` と `salt` / `iteration count` だけで、passcode は
QR コード / 製品ラベル(= コミッショナ側)にのみ存在する。

- 製品コードは [`PaseConfig::from_verifier`] で verifier を読み込む(工場プロビジョニングで
  機器ごとに書き込む)。verifier は `smctl pase-verifier <passcode> [--salt <hex>]
  [--iterations N]` で生成でき、出力の `w0‖L`(97 バイト)/ `salt` / `iterations` を
  デバイスへ渡す。
- `PaseConfig::from_passcode` / `from_passcode_default` は**開発・テスト・コントローラ
  (prover)側専用**。コントローラは passcode から w0/w1 を導出するため `compute_verifier`
  を使うのが正しい。デバイスコードでは使わない。
- サンプル・移植先ファーム・C FFI シムは passcode をコードに置かず、事前計算した
  **dev verifier 定数**([`dev_pase`] モジュール。passcode `20202021` 相当)を使う。
  PC example は環境変数 `SM_PASE_VERIFIER=<iterations>:<salt_hex>:<w0l_hex>` で上書きできる。
  C FFI は `sm_config_t.verifier_w0_l` / `verifier_salt` / `verifier_iterations` で渡す
  (旧 `passcode` フィールドは後方互換の開発専用フォールバック)。

PASE 成立は、コントローラの passcode 由来 w0/w1 とデバイスの埋め込み verifier w0/L が一致する
ことによる。デバイスが passcode を一切知らなくても PASE は成立する。

[`PaseConfig::from_verifier`]: crate::sc::PaseConfig::from_verifier
[`dev_pase`]: crate::dev_pase

### 6.4 コミッショニング状態・タイムアウト・同時試行(Busy)

```rust
// sc/mod.rs(または commissioning.rs)
pub struct CommissioningState {
    window: Option<CommWindow>,   // 開いている間だけ PASE を受理
    verifier: Spake2pVerifier,    // w0, L(焼き込み or OpenCommissioningWindow で設定)
    salt: heapless salt, iterations: u32,
    failures: u8,                 // MAX_PAKE_FAILURES = 20 で window 失効
}
```

- **comm window が閉じているとき**: PBKDFParamRequest を **silent drop**(応答しない)。
  rs-matter の判断(TC-CADMIN-1.5 準拠)を踏襲。InvalidParameter を返すと相手が誤判定する。
  失敗カウントにも加算しない(パスコード誤りではないため)。
- **失敗カウント**: Pake3 検証失敗 / 途中エラーを 1 回として数え、20 回で window を revoke
  (`MAX_PAKE_FAILURES=20`, 仕様)。成功・プロトコル拒否(Busy 等)は数えない。
- **セッション確立タイムアウト**: `PASE_SESSION_EST_TIMEOUT = 60s`。slot の `started_ms`
  から超過で `evict_expired` が掃除。sc の `on_tick(now_ms)` を統合層が定期呼び出しする
  (MRP の `ExchangeManager::poll` とは独立)。
- **同時試行の制限(Busy)**: PASE は本質的に**同時 1 本**(comm window に紐づく 1 試行)。
  進行中 PASE がある間に別 exchange の PBKDFParamRequest / 別の PBKDF が来たら
  **`Busy`(retry_delay を proto_data に u16 LE、R フラグなし)** を返す(rs-matter
  `update_session_timeout` の「Another PAKE session in progress → Busy」+ `BusySecureChannel`
  の 500ms を統合)。`HandshakePool` の容量超過(`open` が `NoSpace`)も同じ Busy 経路に
  落とす。retry_delay は PASE で既定 500ms。CASE の Busy は chip では
  `ComputeSigma2ResponseTimeout`(MRP 往復 + 処理見積り)または 5000ms フォールバックを
  使うが、本設計は当面 500ms 固定でよい(オープン論点 §10-2 と連動)。
- rs-matter は「実 responder が忙しいとき用に別途 `BusySecureChannel` ハンドラ」を持つが、
  本設計は **`HandshakePool` 容量 = Busy 判定**に一本化する(ハンドラ多重化を避ける、
  ARCHITECTURE の抽象多重化回避)。

### 6.5 SessionManager の reserve → commit への接続

- `pase_open`(PBKDFParamRequest 受信)で **`SessionManager::reserve(peer_addr, now)`** を
  呼び、`SessionId` とワイヤ session id(= responder_ssid として PBKDFParamResponse に載せる)
  を先取りする。reserve は `SlotState::Reserved` で退避不可(transport-exchange §4.3、
  実装済み `session.rs`)。これで「ハンドシェイク中に他要求でセッションテーブルが埋まる」
  競合を防ぐ。
- `pase_step`(Pake3 成功)で導出鍵・mode を `SessionInit` に詰め、**`commit(reserved, init, now)`**
  で予約 slot を Active へ昇格。`SessionInit.mode = SessionMode::Pase { fabric_idx: 0 }`
  (fabric 未確定。AddNOC で後日 1 度だけ昇格)。ワイヤ session id は reserve 時のものを保持
  (既に相手へ広告済み、実装済み `commit` の不変条件)。
- **順序**: `commit` を成功 StatusReport 送信の**前**に行う(§3.3)。
- 失敗時は slot を `remove(reserved)` で解放(未 commit の Reserved を掃除)。

---

## 7. CASE responder

CASE は運用証明書ベース。fabric/credentials(第4段階)への依存が本質だが、**その依存を
trait 3 つに閉じる**(§8)ことで、第3段階では PASE を先に縦通し CASE を trait スタブで組む。

### 7.1 状態遷移(テキスト図。resumption は §7.4)

```
 (start)  rx CASE_Sigma1(0x30)  [unsecured session 上]
   │  ・destinationId を全 fabric の { IPK, rootPubKey, fabricId, nodeId } で総当り照合
   │     → 一致 fabric_idx を得る(無ければ NoSharedTrustRoots で終端)
   │  ・resumptionID/resumeMIC 有 → resumption 照合(§7.4)。不成立はフルへフォールバック
   │  ・ephemeral keypair 生成, responder_random, TT に Sigma1 生バイト投入
   ▼
 ┌───────────┐  tx CASE_Sigma2(0x31, 信頼)  reserve(SessionId)
 │  Idle     │──────────────────────────────────────────────►┐
 └───────────┘   ・ECDH(eph, peerEph) → S2K = HKDF(IPK||rand||ephPub||TThash,"Sigma2") │
                  ・TBEData2 = { responderNOC(+ICAC), signature, resumptionID }         ▼
                  ・AES-CCM 暗号(nonce "NCASE_Sigma2N")                          ┌───────────┐
                                                                                │ Sigma2Sent│
        rx CASE_Sigma3(0x32) ───────────────────────────────────────────────────┤           │
        ・S3K = HKDF(IPK||TThash(Σ1..Σ2),"Sigma3"), TBEData3 復号("NCASE_Sigma3N") └───────────┘
        ・相手 NOC/ICAC を fabric の RCAC で鎖検証, NodeId/FabricId 一致確認             │
        ・TBSData3 署名(相手 NOC 公開鍵)検証                                             │
           ├─ OK:  sessionKeys = HKDF(IPK||TThash(Σ1..Σ3),"SessionKeys",48)              │
           │       → I2R/R2I/att に分割, commit(reserved, keys, Case{fab_idx})           │
           │       tx StatusReport(Success, 信頼) ─────────────────────────────────────►(done)
           └─ NG:  tx StatusReport(InvalidParameter) ──────────────────────────────────►(done)
```

- **メッセージ↔ハンドラ 1:1**: Sigma1→`case_open`(応答 Sigma2)、Sigma3→`case_step`
  (応答 成功/失敗 Status)。Sigma2 は Sigma1 ステップの応答。
- 鍵導出 info 定数(rs-matter `casep.rs` / chip `CASESession.cpp` と一致):
  S2K info=`"Sigma2"`、S3K info=`"Sigma3"`、最終 session keys info=`"SessionKeys"`(11B)。
  TBE nonce は `"NCASE_Sigma2N"` / `"NCASE_Sigma3N"`(各 13B)。
  - **S2K salt = IPK(16) ‖ responderRandom(32) ‖ responderEphPubKey(65) ‖ TThash(32) = 145B**、
    IKM = ECDH 共有秘密、出力 16B。
  - **S3K salt = IPK(16) ‖ TThash(32) = 48B**。最終 session keys も salt = IPK ‖ TThash(48B)、
    出力 48B(I2R/R2I/att 各 16B。responder は I2R→dec, R2I→enc)。
  - resumption id 長 16B、CASE random 32B。
- **TT へのフォールド順序**(rs-matter/chip 共通の要点): Sigma2 の生バイトは TLV 直列化
  **後**に、Sigma3 の生バイトは**証明書鎖検証・署名検証を通過した後**に TT へ投入する。
  不正な Sigma3 でトランスクリプトを汚染しない(検証失敗時に TT を進めない)ため。

### 7.2 一時状態(CASE は大きい)

- Sigma3 の **相手 NOC(+ICAC)は最大 ~1 KB**(`MAX_CERT_TLV_LEN*2`)。これを
  `HandshakeSlot` に常駐させると slot が肥大するので、**受信 RX パケットバッファ上で
  in-place に**復号・検証する(復号後 TBEData3 は RX バッファ内。証明書検証はそこを参照)。
  slot には「ECDH 共有秘密・TThash 途中状態・responder eph 秘密鍵・reserved SessionId」の
  小さな値だけ残す。rs-matter は `CASE_LARGE_BUF_SIZE ≈ 1024` の一時バッファを `MaybeUninit`
  で確保(`sc.rs` の "TODO LARGE BUFFER")。本設計はそれを**共有 RX バッファに寄せて**
  slot 常駐サイズを圧縮する(オープン論点 §10-3)。
- CASE 署名検証(P-256 verify)・ECDH は既存 `Crypto` の `P256PublicKey::verify` /
  `P256Keypair::ecdh` で足りる(crypto.rs に実装済み)。CASE は **crypto に新規追加を
  要さない**(Spake2+ を要する PASE と対照的)。

### 7.3 destination ID

Sigma1 の `destinationId` = `HMAC-SHA256(key=IPK, msg=initiatorRandom || rootPubKey ||
fabricId || nodeId)`。responder は自分が属する**全 fabric**についてこれを計算し、一致する
fabric を選ぶ(rs-matter `casep.rs` の `find_fabric`/destination 照合)。一致なしは
`NoSharedTrustRoots` で終端。`Crypto::hmac_sha256` で計算できる。

### 7.4 CASE resumption(Sigma1 + resumption → Sigma2_Resume)

Matter 仕様 §4.14.4。フル CASE で確立した `SharedSecret` と `resumptionID` を両側が控え、
再接続時に証明書鎖検証・署名・ECDH を省いた 1 往復 + StatusReport でセッションを再確立する。
参照実装 connectedhomeip `CASESession.cpp` と一致させる(定数・salt 構成とも)。

#### 状態保持(SessionResumption record)

`sc/resumption.rs` の固定容量ストア(メモリ内。KVS 永続化は下記「#### KVS 永続化」):

```rust
pub struct ResumptionRecord {
    fabric_index: NonZeroU8,          // 所属 fabric(削除された fabric のレコードは照合失敗)
    peer_node_id: u64,                // 相手の operational NodeId(fabric スコープ)
    resumption_id: [u8; 16],          // 現行 resumptionID(セッション確立ごとにローテート)
    shared_secret: Zeroizing<[u8;32]>,// フル CASE の ECDH SharedSecret(resumption でも不変)
}
pub struct ResumptionStore<const N: usize = 4> { /* FixedVec + 挿入順 seq */ }
```

- **キー**: `(fabric_index, peer_node_id)` で upsert(同一ピアは常に 1 レコード)。
  responder の入口照合は `resumption_id` の線形探索(N=4 なので総当りで十分)。
- **容量と追い出し**: 既定 `N = 4` レコード(1 レコード ≈ 60 B、常駐 ~256 B)。満杯時は
  **挿入順が最も古いレコードを追い出す**(FIFO。u32 単調 seq で判定)。デバイスは通常
  相手コントローラが 1〜2 なので N=4 で運用上十分、追い出されても影響はフル CASE への
  フォールバックのみ(機能劣化なし)。
- 置き場所: responder は `SecureChannel` のフィールド、initiator は `ScInitiator` の
  フィールド(公開 API 変更なし。コンストラクタで空を生成)。

#### 鍵導出とワイヤ(仕様固定・chip `CASESession.cpp` と一致)

- `S1RK = HKDF-SHA256(salt = initiatorRandom(32) ‖ resumptionID(16), ikm = SharedSecret,
  info = "Sigma1_Resume", L=16)`。`initiatorResumeMIC` = AES-CCM(S1RK, nonce
  `"NCASE_SigmaS1"`, 空平文, 空 AAD) の 16B タグ。Sigma1 の ctx6 = resumptionID / ctx7 = MIC。
- `S2RK`: 同型で salt の resumptionID は **responder が新規採番した resumptionID**、
  info = `"Sigma2_Resume"`、nonce `"NCASE_SigmaS2"`。
- **Sigma2_Resume(0x33)** = `{ ctx1: resumptionID(新・16B), ctx2: sigma2ResumeMIC(16B),
  ctx3: responderSessionID(u16) }`(MRP params ctx4 は省略 = フル Sigma2 と同じ割り切り)。
- セッション鍵 `I2R‖R2I‖Att = HKDF(salt = initiatorRandom ‖ resumptionID(**旧** = Sigma1 の
  ctx6), ikm = SharedSecret, info = "SessionResumptionKeys", L=48)`。IPK も TT ハッシュも
  使わない(resumption 経路にトランスクリプトは無い)。

#### responder 側フロー(`case_open` 内で分岐)

```
rx Sigma1(ctx6/ctx7 あり)
  ├─ store を resumptionID で照合 + fabric 生存確認 + S1RK で MIC 検証
  │    ├─ 成立: reserve → 新 resumptionID 採番 → Sigma2_Resume 送信
  │    │        slot = HandshakeKind::CaseResume { 導出済みセッション鍵, fabric_idx,
  │    │               peer_node_id, 新 resumptionID, shared_secret }
  │    │   rx StatusReport(Success) → commit(Case{fabric_idx}) + store を新 ID でローテート保存
  │    │   rx StatusReport(失敗) / timeout → reserved 解放(slot 破棄)
  │    └─ 不成立(未知 ID・MIC 不一致・fabric 消滅): **フル CASE へフォールバック**
  │        (destinationId 照合から通常経路。エラー終端にしない = 仕様の指示)
  └─ ctx6/ctx7 の片方のみ → InvalidParameter(従来どおり)
```

- destinationId は resumption 成立時には照合しない(chip と同じ。fabric はレコードが示す)。
- フル CASE 成功時(Sigma3 検証通過 → commit 直後)に、Sigma2 の TBE2 へ載せた
  resumptionID + ECDH SharedSecret を store へ保存する(`CaseCtx` に resumptionID を追加)。
- responder は Sigma2_Resume 送信後 **initiator の成功 StatusReport を待って** commit する
  (chip の `kSentSigma2Resume → kFinishedViaResume` と同順序。先 commit しない)。

#### initiator 側フロー(`start_case` / `case_on_sigma2_resume`)

- `start_case` は store を `(fabric_idx, peer_node_id)` で引き、レコードがあれば Sigma1 に
  ctx6/ctx7 を付けて送る(`CaseInitiator` に initiatorRandom・旧 resumptionID・SharedSecret
  を控える)。レコードが無ければ従来どおりのフル Sigma1。
- 応答が **Sigma2_Resume**: S2RK で MIC 検証(salt は受信した新 resumptionID)→
  "SessionResumptionKeys" でセッション鍵導出 → **commit してから** 成功 StatusReport を
  `HandlerAction::Close` で返す → store を新 resumptionID でローテート保存 →
  `ScEvent::CaseEstablished { resumed: true }`。MIC 不一致は Failed(Crypto) で破棄。
- 応答が **フル Sigma2**(responder が resumption を蹴った): 従来経路がそのまま走る
  (TT には resumption フィールド込みの Sigma1 生バイトが投入済みなので整合)。
- フル CASE 成功時は TBE2 から取り出した resumptionID(ctx4)+ SharedSecret を保存する。

#### KVS 永続化(デバイス側 responder / initiator 共通の export-import)

resumption ストアを [`Kvs`] へ versioned TLV で書き出し、リブート後に復元する。目的は
「再起動後も resumption を効かせてフル CASE(証明書鎖検証・署名・ECDH)を省く」こと。
分業は fabric 永続化(`fabric/persist.rs`)・ACL 永続化と同じ流儀:

> **管理(いつ・どこに保存)はアプリ層、コアは export/import(`save_to` / `load_from`)のみ。**

- **API**(`ResumptionStore` に追加。`SecureChannel` / `MatterStack` へ passthrough):
  - `save_to<K: Kvs>(&self, kvs)` / `load_from<K: Kvs>(&mut self, kvs) -> Result<usize>`
    (復元件数を返す。**空ストアにのみ**呼べる = fabric persist と同一契約)。
  - `generation() -> u32`(内容変化のたびに単調増加)。アプリ層はこの値の変化を検知して
    `save_to` を呼ぶ(`FabricTable::generation` と同じ用途)。`load_from` は復元 1 件ごとに
    内部 `save` を通すため generation を進める。**アプリ層は復元後の `generation()` を保存
    トリガの基準値に取る**(復元直後の不要な再保存を避ける)。
- **キー**: 単一キー `b"rsmp"`。レコードが 0 件のときはキーを削除する(削除済みレコードが
  リブート後に復活しないように。fabric persist の空スロット削除と同じ発想)。
- **TLV スキーマ**(schema version 1。不一致は `Error::Decode`):

  ```text
  struct {
    cx0: version(u8) = 1,
    cx1: array of struct {
      cx1: fabric_index(u8),
      cx2: peer_node_id(u64),
      cx3: resumption_id(bytes16),
      cx4: shared_secret(bytes32),
    }
  }
  ```

  エンコードは固定長スタック配列(`RESUMPTION_STORE_BUF_LEN` = 外側 +
  `RESUMPTION_CACHE_LEN` × `MAX_RESUMPTION_RECORD_LEN`)。`shared_secret` を平文で載せるため
  エンコード/デコードの中間バッファは `Zeroizing` でスコープ抜けにゼロ化する。
- **配線**: `SecureChannel`(responder)→ `resumption_generation` /
  `save_resumptions_to` / `load_resumptions_from`。`MatterStack` に同名 passthrough。
  統合層(PC の `examples/onoff-light.rs` は `SM_STATE_DIR` 設定時のみ、ports/esp32 の
  `EspKvs`)は fabric 復元直後に `load_resumptions_from`、メインループで
  `resumption_generation()` 変化時に `save_resumptions_to` を呼ぶ。

**セキュリティ注記**: `shared_secret` を flash に平文で置くと、物理アクセスで CASE
セッションを再確立できる素材になる。ただし同じ flash に NOC 運用秘密鍵・IPK も置いており
(fabric 永続化、port-esp32-device.md §E4)、脅威モデル上の追加露出は限定的。プラット
フォームの flash 暗号化(ESP32 Flash Encryption 等)での保護を推奨する。永続化しなくても
再起動でフル CASE へフォールバックするだけで機能劣化はない(安全側)。

#### 仕様との差分/割り切り

- 永続化は KVS export-import(上記)。未接続なら再起動でフル CASE に戻るだけで安全側。
- Sigma2_Resume の MRP `session_parameters`(ctx4)は送らない(optional。フル Sigma2 と同じ)。
- CAT(CASE Authenticated Tags)はレコードに保存しない(本実装は ACL の CAT 未対応のため。
  chip は保存する)。

---

## 8. 第4段階(fabric/credentials)へ切り出す trait 境界

CASE が必要とする fabric/証明書側の前提を、**読み取り専用の最小 trait 3 つ**に集約する。
これらを `sc/case/creds.rs` に**定義**し、第4段階の `fabric` モジュールが**実装**する
(依存性逆転)。第3段階は同ファイルの**モック実装**で CASE を単体テストする。

```rust
// sc/case/creds.rs
/// fabric テーブルの読み取りビュー(CASE が触る最小面)。
pub trait FabricStore {
    type Fabric<'a>: Fabric where Self: 'a;
    /// 全 fabric を走査(destination-id 総当りに使う)。
    fn iter(&self) -> impl Iterator<Item = Self::Fabric<'_>>;
    /// fabric_idx で引く(1-origin, NonZeroU8)。
    fn get(&self, idx: core::num::NonZeroU8) -> Option<Self::Fabric<'_>>;
}

/// 1 fabric が CASE に提供する素材。
pub trait Fabric {
    fn fabric_idx(&self) -> core::num::NonZeroU8;
    fn fabric_id(&self) -> u64;
    fn node_id(&self) -> u64;                 // 自ノードの operational NodeId
    fn ipk(&self) -> &[u8; 16];               // Operational IPK(destination-id / 鍵導出の salt)
    fn root_public_key(&self) -> &[u8; 65];   // RCAC 公開鍵(destination-id 照合)
    /// 自 NOC/ICAC の TLV(Sigma2 の TBEData2 に載せる)。
    fn noc(&self) -> &[u8];
    fn icac(&self) -> Option<&[u8]>;
    /// TBSData 署名に使う operational 秘密鍵で署名する(鍵は外に出さない)。
    fn sign(&self, msg: &[u8], out: &mut [u8; 64]) -> Result<()>;
}

/// 相手 NOC/ICAC を fabric の信頼根で検証し、NodeId/FabricId/CAT を取り出す。
/// 証明書チェーン検証(ヒープレス DER/TLV)は第4段階の実装に委ねる。
pub trait NocResolver {
    fn verify_peer_noc(
        &self, fabric_idx: core::num::NonZeroU8,
        noc_tlv: &[u8], icac_tlv: Option<&[u8]>,
    ) -> Result<PeerIdentity>;   // { node_id, fabric_id, public_key:[u8;65], cat_ids }
}
```

- **切り出しの理由**: 証明書検証(x509/DER・チェーン・CAT)は ARCHITECTURE 原則2の要
  (alloc 依存を避けるヒープレスパース)で、規模が大きく第4段階の主題。CASE の state
  machine と鍵導出は**証明書の中身に依存しない**(バイト列と検証結果しか要らない)ので、
  trait 越しに切れる。
- **PASE は fabric に依存しない**。`SecureChannel` の型パラメータ `F: FabricStore` は
  PASE のみ縦通しの段階では `NullFabrics`(空 iterator)を渡せばよく、CASE 経路は
  `NoSharedTrustRoots` を返して無効化できる。これで第3段階は PASE を先に完成できる。
- **`SessionMode::Case { fabric_idx: NonZeroU8 }`**(実装済み)に commit する際、
  `Fabric::fabric_idx()` をそのまま使う。CASE セッションは `find_for_node(fabric, node)`
  (実装済み)で後日引ける。

---

## 9. サイジング

sc 固有の const generic は **同時ハンドシェイク数 `H`** の 1 つ(既定 1)。

```rust
pub type SecureChannel1<C, F> = SecureChannel<'_, C, F, 1>;  // 通常(PASE/CASE 同時 1)
// 極小や検証機で 2 本許すなら H=2。
```

サイジング見積り(1 スロットあたり、概算):

| 要素 | PASE slot | CASE slot |
|---|---|---|
| 索引・予約情報(ExchangeId/SessionId/session_id/started_ms) | ~40 B | ~40 B |
| トランスクリプト SHA-256 state | ~112 B | ~112 B |
| Spake2+ 中間(点・スカラ・K_e) | ~350 B | — |
| CASE ephemeral 秘密鍵 + ECDH 共有 + responder_random | — | ~100 B |
| 導出鍵一時(48B) | 48 B | 48 B |
| **slot 合計(証明書域を除く)** | **~550 B** | **~300 B** |

- CASE の証明書検証域(~1 KB)は slot に含めず RX パケットバッファ(既存 1583B RX)に
  in-place で載せる(§7.2)ため、slot 常駐は数百 B に収まる。`H=1` なら sc 全体で **1 KB 未満**。
- `HandshakeKind` enum のサイズは max(PaseCtx, CaseCtx) = PaseCtx が支配(~550B)。
  `H=1` を既定にするのは、responder が同時に 2 つのコミッショニング/CASE を進める需要が
  乏しく、2 本目は Busy で足りるため(§6.4)。
- **同時 PASE は仕様上 1**(comm window に紐づく)。CASE は複数コントローラからの並行接続が
  あり得るが、responder は逐次処理 + Busy で十分(chip の CASEServer も 1 ハンドシェイクずつ
  受ける構造)。`H=2` は「PASE 進行中に CASE が来る」等の稀ケース用の余地。

---

## 10. オープンな論点

1. **`HandlerAction` / `handle` シグネチャ拡張の最終形**(§4.3)。`tx: &mut WriteBuf` を
   引数に足すか、`RxMessage` に出力バッファを同梱するか。exchange ピースとの契約確定が必要。
   `Respond`/`Close` に加え「複数フラグメント(CASE の大 Sigma2)」を要するかも要検討。
2. **sc タイムアウトの駆動**(§4.2/§6.4)。`on_tick(now_ms)` を統合層が MRP `poll` と同じ
   ループで回すか、別 deadline を返させるか。exchange の `next_deadline()` と統合する形が理想。
3. **CASE 証明書域を RX バッファに寄せる**(§7.2)方式が、受信一本道(RX リースの寿命)と
   両立するか。Sigma3 復号→検証の間 RX バッファを保持する必要があり、その間 他 exchange の
   RX が止まる(transport-exchange §7.2 の「1 枚保持で停止」と同じ緊張)。RX プールを
   2 枚にするか、証明書域だけ別小プールにするか。
4. **Spake2+ プリミティブの crypto 側 API 形**(§6.3)。verifier(w0,L)を responder が
   どう受け取るか(型・所有権)、typestate 境界(verifier → confirm)を crypto と sc の
   どちらに置くか。crypto ピースと要調整。
5. ~~**resumption(Sigma2Resume)の後付け余地**(§7.1)~~ → **解決(§7.4 で実装)**。
   復元情報は `Session` ではなく専用の `ResumptionStore`(`sc/resumption.rs`、メモリ内
   固定容量)に持たせた。KVS 永続化のみ将来課題として残る。
6. **PASE の commit タイミングと unsecured exchange の後始末**。Pake3 後、成功 Status を
   運ぶ unsecured exchange と、新 PASE セッションの整理(unsecured session/exchange をいつ
   閉じるか)。相手が即新セッションを使い始める競合(§3.3)への実挙動確認。
7. **failure counter / comm window の永続化**(§6.4)。20 失敗での revoke や window
   タイムアウトを再起動間で保つか(KVS 依存)。第5/6段階の platform 統合と連動。
8. **`SessionParameters`(MRP)の反映範囲**(§6.2)。unsecured/reserved 双方への反映を
   sc がやるか、exchange の `set_config` に委ねるか(既存 API との配線)。

---

## 11. 参照実装との対応表

| 論点 | rs-matter | chip | 本設計 |
|---|---|---|---|
| ハンドシェイク駆動 | `async fn` 一直線 + `recv_fetch().await` | delegate + 状態 enum(`OnMessageReceived`) | **同期 state machine + `ExchangeId` キーの slot**(§4)。sans-IO に合わせ chip 寄り |
| 進行状態の表現 | async スタック(暗黙) | メンバ状態 enum | runtime enum `PasePhase`/`CasePhase`(§5.2) |
| typestate | 主に crypto 内 | なし | crypto サブステップ順序に限定(§5.2) |
| 一時状態格納 | `MaybeUninit` 大バッファ(sc.rs) | ヒープ or 固定オブジェクト/ハンドシェイク | 固定 `HandshakePool<H>` + 証明書域は RX へ退避(§5,§7.2) |
| 同時数の制御 | ハンドラ本数 + 別 `BusySecureChannel` | CASEServer 逐次 | `H`(既定 1)+ 容量超過 = Busy 一本化(§6.4) |
| StatusReport | `SCStatusCodes`/`GeneralCode` | `StatusReport` + Constants | 同値・同運用を踏襲(§3) |
| 鍵導出 info | "SessionKeys"/"Sigma2"/"Sigma3" | 同 | 同(仕様固定, §6.3/§7.1) |
| fabric 依存 | `state.fabrics`/`Fabric` 直参照 | `FabricTable*` | **trait 3 つに隔離**(§8)。第4段階を後付けに |
| セッション確立 | `ReservedSession` reserve/complete | PairingSession | 実装済み `reserve`/`commit`(§6.5) |

**借りるもの**: opcode/StatusReport の語彙と運用、鍵導出 info 定数、reserve→commit の 2 相、
ファイル分割(mod/pase/case/status)、comm window / 20-failure / 60s タイムアウトの規律、
Busy 500ms。**変える点**: 往復駆動を async から同期 state machine へ(sans-IO 準拠、最大の差)、
Busy を専用ハンドラでなく容量判定に統合、fabric 依存を trait に隔離、CASE 証明書域を
slot 常駐から外す。
