# controller 層設計 — commissioner / initiator(`controller` Cargo feature)

対象: `docs/ARCHITECTURE.md` で「将来スコープ」とされていたコントローラ
(commissioner / initiator)側。本書はそれを **`controller` Cargo feature** として
追加するための設計である。前提は既存設計と同一(`no_std`・定常パス no-alloc・
同期 sans-IO・executor 非依存)で、加えて本件固有の絶対条件が 1 つある:

> **デバイス(responder)専用ビルドの flash / RAM フットプリントに影響を与えないこと。**

- 上位境界: コントローラは [`ControllerStack`](§7)として、既存 [`MatterStack`] と
  対になる sans-IO API(`handle_rx` / `poll` / `next_deadline` / `SendDirective`)を提供する。
- 下位境界: `transport` / `exchange` / `crypto` / `tlv` / `cert` / `fabric` の既存実装を
  **無改造で共用**する。initiator に必要な下位機構(`open_initiator` / `send_reliable` /
  role 照合つき受信ディスパッチ / IM wire 双方向 codec)は**すべて実装済み**である(§2)。

本書の中心的な認識: **コントローラ側の演算はすでにテストとして全経路が実証済み**である。
`crates/simple-matter/src/stack/tests.rs` の `onoff_light_end_to_end` は、PASE initiator
(`Spake2pProver`)・CA(RCAC/NOC 自己発行 = `write_cert`)・CASE initiator
(`sc::case::responder` の公開ヘルパ群)・NOC 発行までを含む**完全なメモリ内 commissioner**
として動いている。本設計はこのテストコードを製品 API へ「昇格」させる作業の設計であり、
新規発明はほとんど含まない。

参照実装: `research/connectedhomeip/src/controller/`(`DeviceCommissioner` の
commissioning stage 遷移)、`research/rs-matter/`、`research/matter.js` の controller。
chip-tool の実挙動は本プロジェクトのデバイス側相互運用試験で既に実証済み。

---

## 0. サマリ(主要な設計判断)

1. **initiator は responder ハンドラに統合せず、controller 専用ハンドラを別に立てる**。
   `ProtocolMux<ScInitiator, ImClient>` を `ControllerStack` 用に別インスタンス化する
   (`ProtocolMux` はジェネリックなので流用)。既存 `SecureChannel` / `InteractionModel`
   には 1 行も触れない。これがフットプリント不変の最も確実な担保であり、受信照合の
   実装済みの role 対称性(`rx_is_initiator == (role == Responder)`)により
   「自分が開始した exchange への応答」だけが initiator ハンドラへ届くため、
   responder との opcode 競合も原理的に起きない(§3.1)。
2. **`ProtocolHandler` / `HandlerAction` 契約は無改造で initiator にも使う**。
   initiator の各トランザクションも「1 受信 = 1 同期 `handle`、応答は
   `Respond`/`Close`、状態は slot に外出し」という Mealy machine にそのまま写像できる
   (例: ReportData チャンク受信 → StatusResponse を `Respond` で返す)。**唯一の追加軸は
   「トランザクションの開始」**(受信駆動でない最初の送信)で、これは既存の
   `open_initiator` + `send_reliable` を `ControllerStack` の `start_*` API が呼ぶ
   (`MatterStack::stage_subscription_report` が既にこのパターンのシード)(§3.2)。
3. **結果はコールバックでなくポーリング(`take_event`)で取り出す**。initiator ハンドラは
   完了/失敗/受信データを内部の 1 深度イベントに積み、上位(`Commissioner` /アプリ)が
   `handle_rx`/`poll` の後に取り出す。sans-IO の入出力分離を保ち、`Commissioner` の
   Mealy machine が「イベントを入力として遷移する」形と自然に揃う(§4.4, §6.2)。
4. **codec の欠けている方向だけを埋め、共有ヘルパを中立モジュールへ移す**。
   IM wire は完全双方向で追加ゼロ。PASE/CASE は responder 方向の codec のみ存在するため
   鏡像(`encode_pbkdf_param_req` / `PbkdfParamResp::decode` / `encode_sigma1` /
   `decode_sigma2` 等)を controller 側に追加する。`sc/case/responder.rs` に居る両方向
   共用ヘルパ(`derive_sigma2_key` / `encode_tbs` / `decode_tbe_certs` / 各種定数)は
   `sc/case/common.rs` へ移動する(cfg なし・両ビルド共通。移動のみで挙動不変)(§3.3)。
5. **CA 機能は `cert/tests.rs` の `write_cert` の正式化**。`MatterCertSpec` を受ける
   `write_matter_cert`(TLV 形式 Matter 証明書の発行)を feature gate 下で `cert` に置き、
   `controller::Ca` が RCAC 自己署名・NOC 発行・fabric id / IPK / CA 鍵の管理を担う。
   コントローラ自身の運用資格情報は**実装済み `FabricTable<C, 1>` を流用**する
   (チェーン検証・CompressedFabricId・operational IPK 導出が既に内蔵)(§6.3)。
6. **feature gate は「モジュール宣言 + 数行」に限定し、フットプリント不変は bloat-check で
   機械検証**する。`controller` feature は依存クレート追加ゼロの additive feature。
   CI に「`--features controller` でビルドした flash-probe のセクションサイズが
   feature なしと一致する」ことの検証を組み込む(§2.3)。
7. **同時コミッショニング 1 台で固定**。initiator ハンドシェイク slot・IM クライアント
   トランザクション slot とも単一(`Option<T>`)。`HandshakePool` は responder 文脈
   (Busy 判定・入口 opcode)に結合しているため流用せず、controller 専用の小さな slot を
   持つ(§3.4)。

---

## 1. モジュール構成と依存関係

`crates/simple-matter/src/` 配下(実装は別ピース。本書は設計のみ)。`(+)` = 新規、
`(±)` = 既存ファイルへの最小変更。

```
sc/
  case/
    common.rs   (+) responder.rs から移動する両方向共用ヘルパ(cfg なし)     … §3.3
    responder.rs(±) 共用ヘルパを common へ移し pub use で互換維持
  initiator/    (+) #[cfg(feature = "controller")]
    mod.rs          ScInitiator(ProtocolHandler 0x0000)、ScEvent、start_pase/start_case
    pase.rs         PASE initiator 状態機械 + 鏡像 codec(encode req/pake1/pake3, decode resp/pake2)
    case.rs         CASE initiator 状態機械 + 鏡像 codec(encode sigma1/sigma3, decode sigma2)
im/
  client.rs     (+) #[cfg(feature = "controller")]
                    ImClient(ProtocolHandler 0x0001)、ClientTxn、ImEvent、
                    start_read/start_write/start_invoke(/start_subscribe)
discovery/
  dns.rs        (±) クエリビルダ(QR=0 + Question)と A/AAAA アクセサを cfg 下で追加
  client.rs     (+) #[cfg(feature = "controller")] MdnsClient(browse/resolve、sans-IO)
cert.rs         (±) #[cfg(feature = "controller")] mod issue(write_matter_cert, parse_csr)
controller/     (+) #[cfg(feature = "controller")]
  mod.rs            ControllerStack(MatterStack と対の sans-IO スタック)
  ca.rs             Ca(RCAC 自己署名・NOC 発行・IPK/fabric id 管理)
  commissioner.rs   Commissioner(コミッショニングフローの Mealy machine)
lib.rs          (±) #[cfg(feature = "controller")] pub mod controller; ほか mod 宣言数行
```

### 依存方向(下→上の一方向)

```
error, tlv, crypto(Spake2pProver 実装済み), cert(±), fabric      … 既存
   ▲
transport(SessionManager/SecureCodec), exchange(open_initiator/send_reliable, 実装済み)
   ▲
sc::case::common(移動)── sc::pase の共有定数(build_context 等)
   ▲
sc::initiator ── im::client ── discovery::client     … 3 つは相互に独立
   ▲
controller::ca(cert::issue + fabric に依存)
   ▲
controller::mod(ControllerStack = ProtocolMux<ScInitiator, ImClient> を所有)
   ▲
controller::commissioner(ControllerStack を駆動する Mealy machine)
```

- `sc::initiator` は `sc::SecureChannel`(responder)を知らない。共有するのは
  `sc::status`(StatusReport)・`sc::pase` のメッセージ型/定数・`sc::case::common` のみ。
- `im::client` は `im::wire` のみに依存し、`im::engine` / `dm` を知らない
  (コントローラはデバイスのデータモデルを持たない)。
- `discovery::client` は `discovery::dns` のみに依存。`MdnsResponder` を知らない。

---

## 2. 実装済み資産の棚卸し(何が既にあるか)

本設計の分量を規定するため、initiator 化に必要な資産の有無を先に確定する。

| 領域 | 状態 | 根拠(実装箇所) |
|---|---|---|
| initiator exchange の開設・送信 | **完備** | `ExchangeManager::open_initiator(session) -> Result<ExchangeId>`、`send_reliable`/`send_unreliable` は `Role` を `ExchangeState` から読み I フラグを正しく設定 |
| initiator 宛て応答の受信照合 | **完備** | `recv` の role 対称照合(`rx_is_initiator == (role == Responder)`)。応答は既存 exchange にマッチし `RxMessage { role: Initiator }` でハンドラへ届く |
| 「開始→応答待ち」の駆動パターン | **完備** | `MatterStack::stage_subscription_report`(open_initiator → encode → send_reliable)がシード |
| PASE initiator 暗号 | **完備** | `crypto::spake2p::Spake2pProver::{from_passcode, share, confirm}` + `Spake2pProverConfirm::{confirmation_a, verify_b, shared_secret}` |
| PASE メッセージ codec | **responder 方向のみ** | `sc/pase.rs`: `PbkdfParamReq::decode` / `encode_pbkdf_param_resp` / `Pake1::decode` / `encode_pake2` / `Pake3::decode`。鏡像 5 本が不足 |
| CASE 暗号・codec | **大半あり(配置が responder 下)** | `sc/case/responder.rs` の pub ヘルパ: `derive_sigma2_key` / `derive_ipk_tt_keyed` / `encode_tbs` / `decode_tbe_certs` / `encrypt_tbe2` / `decrypt_tbe3` / `encode_sigma2` / `decode_sigma3` + info/nonce 定数。不足は `encode_sigma1` / `decode_sigma2`(外枠)/ `encode_sigma3`(外枠)/ TBE3 暗号化ラッパ |
| IM メッセージ codec | **完全双方向** | `im/wire`: `encode_read_request` / `encode_invoke_request` / `ReportDataRef` / `InvokeResponseRef` 等、全メッセージ encode/decode 両方向あり。**追加ゼロ** |
| 証明書発行(CA) | **テストに実在** | `cert/tests.rs` / `stack/tests.rs` の `write_cert`(TLV 組み立て → `MatterCert::parse` → `to_be_signed` → ECDSA 署名の埋め戻し)。CSR 生成は `cert::write_csr` が製品 API として実在 |
| CSR の解析 | **なし** | commissioner はデバイスの CSRResponse(NOCSRElements)から公開鍵を取り署名検証する必要がある。`parse_csr` が不足 |
| mDNS レスポンス解析 | **あり** | `discovery/dns.rs`: `Response`/`Record`/`Name`(SRV/TXT・圧縮ポインタ対応) |
| mDNS クエリ生成 | **なし** | `MsgWriter` は QR=1(Response)固定・Question セクション writer なし。A/AAAA の型付きアクセサもなし |
| メモリ内 commissioner 全体 | **テストに実在** | `stack/tests.rs onoff_light_end_to_end`: `build_msg`/`decode_resp`(ワイヤ組立/解読)、`pase_invoke`、Spake2pProver での PASE、write_cert での RCAC/NOC 発行、case ヘルパでの CASE initiator |

**結論**: 新規に書くのは (a) 鏡像 codec 十数本、(b) initiator 側の 2 つの状態機械、
(c) IM クライアント状態機械、(d) DNS クエリビルダ + 集約、(e) CA とフローの正式化、のみ。
暗号・検証・ワイヤ形式はすべて実証済みコードの移動と薄いラッパで賄う。

### 2.3 feature gating 戦略とフットプリント不変の検証

**feature 定義**(`crates/simple-matter/Cargo.toml`):

```toml
[features]
controller = []   # 依存クレート追加なし。additive(有効化で既存 API は不変)
```

**cfg 分岐の置き場所の規律**: `#[cfg(feature = "controller")]` は次の 3 種類にのみ許す。

1. **モジュール宣言と re-export**(`lib.rs` / `sc.rs` / `im.rs` / `discovery.rs` /
   `cert.rs` の `pub mod xxx;` 行)。
2. **新規ファイル全体**(`sc/initiator/*`, `im/client.rs`, `discovery/client.rs`,
   `controller/*`, `cert.rs` 内の `mod issue`)。
3. **dns.rs のクエリビルダ 3 関数**(§5.2。既存関数の中に分岐は入れない)。

既存の**関数の内部**に cfg 分岐を入れることは禁止する(responder パスのコードが
feature で形を変えないこと = レビューと計測の単純化)。唯一の「既存コード変更」は
`sc/case/responder.rs` → `sc/case/common.rs` のヘルパ移動で、これは cfg 無しの
純粋なリファクタ(responder も同じ関数を使い続ける。`pub use` で旧パス互換を維持し、
`stack/tests.rs` の `use crate::sc::case::responder as case` も壊さない)。

**フットプリント不変が成立する理由**: (a) feature は default off なのでデバイス専用
ビルドではモジュール自体がコンパイルされない。(b) feature を on にしても、Rust の
ジェネリック単相化と `--gc-sections`(リンカ)により、`ControllerStack` を参照しない
バイナリには controller のコードが載らない。(a) だけで十分だが、(b) を機械検証する。

**bloat-check への組み込み**(CI 追加ジョブ):

```yaml
# .github/workflows/ci.yml への追加(概略)
- name: Bloat-check controller-feature footprint invariance
  run: |
    cargo build -p bloat-check --bin flash-probe --release --target thumbv7em-none-eabihf
    size -A target/.../flash-probe > /tmp/size-base.txt
    cargo build -p bloat-check --bin flash-probe --release --target thumbv7em-none-eabihf \
      --features simple-matter/controller
    size -A target/.../flash-probe > /tmp/size-ctl.txt
    diff /tmp/size-base.txt /tmp/size-ctl.txt   # .text/.rodata/.data/.bss 完全一致を要求
```

- flash-probe(デバイススタックのみをリンクする計測バイナリ)を controller feature
  有効/無効の 2 回ビルドし、**全セクションサイズの一致**を assert する。1 バイトでも
  差が出たら「デバイスパスに controller コードが波及した」ことの検知になる。
- 加えて `ram-report` に **ControllerStack のプロファイル行**を追加する
  (`#[cfg(feature = "controller")]`)。controller 有効時のみ `size_of::<ControllerStack>` を
  出力し、コントローラ自身のサイジング(§7.3)を継続計測する。

---

## 3. SC initiator(PASE / CASE)

### 3.1 responder ハンドラに統合するか、専用ハンドラにするか — **専用ハンドラ**

| 案 | 評価 |
|---|---|
| 既存 `SecureChannel` に initiator 経路を追加(opcode で分岐) | 1 ハンドラで済むが、responder ビルドに initiator コードが**物理的に同居**する。cfg で切ると関数内部分岐が増殖(§2.3 の規律違反)。`HandshakePool` の slot 型も両対応で肥大 |
| **controller 専用 `ScInitiator`(別 `ProtocolMux` インスタンス)** | デバイスコードに 1 行も触れない。footprint 不変が構造的に自明。受信の混線は exchange 層の role 照合が防ぐ |

**判断: 専用ハンドラ**。決め手は受信ディスパッチの実装済みの性質:

- initiator が受け取るメッセージは常に「自分が `open_initiator` で開始した exchange への
  応答」であり、`recv` は `exch_id` 一致 + role 対称(`rx_is_initiator == (role ==
  Responder)`)で**既存 exchange に照合してから**ハンドラを呼ぶ。つまり `ScInitiator` に
  未知 exchange の PBKDFParamRequest が届くことはなく、responder の入口 opcode 処理は不要。
- 逆に、コントローラ専用ノードは新規 responder exchange を受ける必要がない
  (`ControllerStack` は unsolicited な入口 opcode を silent drop する。将来「両役ノード」を
  作る場合の統合は §9-6)。
- `ProtocolMux<Sc, Im>` はジェネリック(実装済み)なので、`ProtocolMux<ScInitiator,
  ImClient>` の別インスタンス化に exchange 層の変更は一切要らない。これは
  transport-exchange §5.4 が意図した「プロトコル集合の差し替え」の最初の実利用でもある。

### 3.2 トランザクションの開始と応答消費(既存契約への適合)

`ProtocolHandler::handle`(実装済み契約: `fn handle<const S: usize>(&mut self,
rx: &RxMessage<'_>, tx: &mut [u8], sessions: &mut SessionManager<S>, now_ms: u64)
-> Result<HandlerAction>`)は受信駆動なので、**開始**(最初の送信)だけが契約の外に出る。
sc responder 設計(secure-channel §4)の双対:

- **開始** = `ScInitiator::start_pase(...)` / `start_case(...)` が応答バッファに
  payload を書き、`ControllerStack` が `open_initiator` + `send_reliable` で送る
  (`Outgoing { proto_id: 0x0000, opcode, payload }`、実装済み API)。
- **応答消費** = 以降の PBKDFParamResponse / Pake2 / Sigma2 / StatusReport は
  `handle_rx` の受信一本道でそのまま `ScInitiator::handle` に届き、
  次のメッセージ(Pake1/Pake3/Sigma3)を `HandlerAction::Respond` で返す。
  **`HandlerAction` の拡張は不要**(initiator の途中メッセージも「受信への応答として
  1 通送る」形に完全に一致する)。
- 終端(成功/失敗 StatusReport の**受信**)では送るものがないので `HandlerAction::None`
  を返し、結果を `ScEvent` に積む(§3.5)。

### 3.3 codec の昇格(鏡像方向の追加と共有ヘルパの中立化)

**PASE**(`sc/initiator/pase.rs` に追加。既存 `sc/pase.rs` の型・`build_context`・
`SPAKE2P_SESSION_KEYS_INFO` を再利用):

```rust
pub fn encode_pbkdf_param_req(out: &mut [u8], initiator_random: &[u8; 32],
    initiator_ssid: u16, passcode_id: u16, has_params: bool) -> Result<usize>;
pub struct PbkdfParamResp<'a> { /* initiator/responder random, responder_ssid,
    params: Option<{iterations, salt}> */ }
impl<'a> PbkdfParamResp<'a> { pub fn decode(payload: &'a [u8]) -> Result<Self>; }
pub fn encode_pake1(out: &mut [u8], pa: &[u8; 65]) -> Result<usize>;
pub struct Pake2<'a> { pub pb: &'a [u8], pub cb: &'a [u8] }
impl<'a> Pake2<'a> { pub fn decode(payload: &'a [u8]) -> Result<Self>; }
pub fn encode_pake3(out: &mut [u8], ca: &[u8; 32]) -> Result<usize>;
```

**CASE**: まず `sc/case/responder.rs` の**両方向共用**ヘルパを `sc/case/common.rs` へ
移動する(cfg なし。responder が使い続けるため、移動はデバイスビルドに中立):

- 定数群(`SIGMA2_KEY_INFO` / `SIGMA3_KEY_INFO` / `CASE_SESSION_KEYS_INFO` /
  `SIGMA2_NONCE` / `SIGMA3_NONCE` / 各 LEN)
- `derive_sigma2_key` / `derive_ipk_tt_keyed`(S2K/S3K/SessionKeys 導出)
- `encode_tbs` / `decode_tbe_certs` / `encrypt_tbe2` / `decrypt_tbe3`
- destination-id 計算(responder 内にある照合ロジックから計算関数を切り出す)

`responder.rs` には responder 固有の状態機械と `encode_sigma2` / `decode_sigma3` が残り、
旧パスは `pub use common::*` で互換維持する。initiator 側(`sc/initiator/case.rs`)が
追加するのは外枠 codec の鏡像のみ:

```rust
pub fn encode_sigma1(out: &mut [u8], initiator_random: &[u8; 32],
    initiator_ssid: u16, destination_id: &[u8; 32], eph_pub: &[u8; 65]) -> Result<usize>;
pub struct Sigma2<'a> { pub responder_random: &'a [u8], pub responder_ssid: u16,
    pub eph_pub: &'a [u8], pub encrypted2: &'a [u8] }
impl<'a> Sigma2<'a> { pub fn decode(payload: &'a [u8]) -> Result<Self>; }
pub fn encode_sigma3(out: &mut [u8], encrypted3: &[u8]) -> Result<usize>;
pub fn encrypt_tbe3<C: Crypto>(/* encrypt_tbe2 の鏡像(TBEData3 の AES-CCM) */) -> Result<usize>;
```

`stack/tests.rs` はこれらの正式版へ書き換わる(手書き TLV 組み立ての除去、§8)。

### 3.4 状態機械とハンドシェイク状態の置き場所

`HandshakePool` は流用しない。理由: (a) slot 型が responder 文脈(`PaseCtx` の
verifier 側 Spake2+ 中間・Busy 判定・入口 opcode 起動)に結合、(b) コントローラは
同時コミッショニング 1 台で固定なのでプールが不要、(c) デバイスビルドの型を触らない。
代わりに `ScInitiator` が単一 slot を持つ:

```rust
// sc/initiator/mod.rs
pub struct ScInitiator<'c, C: Crypto> {
    crypto: &'c C,
    hs: Option<InitiatorHandshake>,   // 同時 1 本(2 本目の start_* は Err(Busy))
    event: Option<ScEvent>,           // 完了/失敗の 1 深度イベント(§3.5)
}

struct InitiatorHandshake {
    exchange: ExchangeId,             // start_* で開いた exchange(応答照合キー)
    reserved: SessionId,              // reserve() 済みの新セッション slot
    started_ms: u64,                  // 60s タイムアウト(sc responder と同値)
    kind: InitiatorKind,
}
enum InitiatorKind { Pase(PaseInitiator), Case(CaseInitiator) }

// sc/initiator/pase.rs
enum PasePhase { PbkdfReqSent, Pake1Sent, Pake3Sent }
struct PaseInitiator {
    phase: PasePhase,
    passcode: u32,                    // PBKDFParamResp の salt/iterations 受領後に prover 構築
    context: Sha256Ctx,               // "CHIP PAKE V1 Commissioning" + req/resp 生バイト
    prover: Option<Spake2pProver>,    // Pake1 送信時に from_passcode で構築
    confirm: Option<Spake2pProverConfirm>, // Pake2 受信で confirm、Pake3 送信後 verify 済み
    peer_ssid: u16,
}

// sc/initiator/case.rs
enum CasePhase { Sigma1Sent, Sigma3Sent }
struct CaseInitiator {
    phase: CasePhase,
    eph: C::Keypair,                  // ephemeral(ECDH 用)
    tt: Sha256Ctx,                    // トランスクリプト(Sigma1 生バイトから逐次投入)
    shared_secret: [u8; 32],          // Sigma2 受信時の ECDH 結果
    fabric_idx: NonZeroU8,            // ControllerCreds(FabricTable)内の自 fabric
    peer_ssid: u16,
}
```

**状態遷移(PASE initiator)** — responder(secure-channel §6.1)の鏡像:

```
 start_pase(peer, passcode)
   │ tx PBKDFParamRequest(0x20)  [unsecured session, open_initiator, 信頼]
   │ reserve(SessionId)、initiator_ssid をワイヤ session id として広告
   ▼
 PbkdfReqSent ── rx PBKDFParamResponse(0x21) ──► context 確定(req/resp 生バイト)、
   │            salt/iterations 受領 → Spake2pProver::from_passcode、
   │            tx Pake1(0x22) = HandlerAction::Respond
   ▼
 Pake1Sent ──── rx Pake2(0x23) ──► prover.confirm(context_hash, pB)、cB を verify_b、
   │            tx Pake3(0x24, cA) = Respond
   ▼
 Pake3Sent ──── rx StatusReport ──► Success: Ke → HKDF("SessionKeys") → keys、
                commit(reserved, keys, SessionMode::Pase{fabric_idx:0})、
                event = PaseEstablished { session } / 失敗: event = Failed、reserve 解放
                (送るものなし = HandlerAction::None)
```

**状態遷移(CASE initiator)**:

```
 start_case(peer_session_or_addr, fabric_idx, peer_node_id)
   │ destination_id = HMAC(IPK, rand ‖ rootPub ‖ fabricId ‖ nodeId)(common.rs の計算関数)
   │ tx Sigma1(0x30)、reserve(SessionId)、TT ← Sigma1 生バイト
   ▼
 Sigma1Sent ─── rx Sigma2(0x31) ──► ECDH(eph, peerEph)、S2K = derive_sigma2_key、
   │            decrypt_tbe3 の鏡像で TBEData2 復号 → decode_tbe_certs、
   │            相手 NOC を自 RCAC で鎖検証 + TBS 署名検証(fabric::verify_chain 流用)、
   │            TT ← Sigma2 生バイト、TBS3 = encode_tbs、自 NOC で署名、
   │            S3K = derive_ipk_tt_keyed(Sigma3)、encrypt_tbe3、
   │            tx Sigma3(0x32) = Respond、TT ← Sigma3 生バイト
   ▼
 Sigma3Sent ─── rx StatusReport ──► Success: SessionKeys = derive_ipk_tt_keyed(SessionKeys)、
                commit(reserved, keys, SessionMode::Case{fabric_idx})、
                event = CaseEstablished { session } / 失敗: event = Failed
```

- **鍵の向きは responder と逆**: initiator は **I2R = enc(送信)、R2I = dec(受信)**。
  `SessionInit` に詰める際の唯一の注意点(responder 実装は I2R=dec)。
- reserve → commit の 2 相・「commit してから終端」の規律は responder(secure-channel
  §6.5)と同一の実装済み `SessionManager` API を使う。initiator では commit は
  「成功 StatusReport **受信**時」になる(responder は送信前)。
- **unsecured セッションの開設**: デバイス側は受信駆動で `ensure_unsecured_session` するが、
  initiator は送信起点なので `ControllerStack::start_pase` が
  `SessionInit::plaintext(peer, ..)` を**能動的に** insert する(§7.2)。
- タイムアウト: `on_tick(now_ms)` で 60s(`PASE_SESSION_EST_TIMEOUT` と同値)超過の
  slot を破棄し `Failed` イベントを積む。`ControllerStack::drive_ticks` から呼ぶ。

### 3.5 結果の受け渡し(ScEvent)

```rust
pub enum ScEvent {
    PaseEstablished { session: SessionId },
    CaseEstablished { session: SessionId, resumed: bool },  // resumed: §3.6 の resumption 経由か
    Failed { kind: HandshakeKindTag, reason: ScFailReason },  // StatusReport 値 or Timeout
}
impl<C: Crypto> ScInitiator<'_, C> {
    pub fn take_event(&mut self) -> Option<ScEvent>;
}
```

`handle` の戻り値は `HandlerAction`(送信指示)専用に保ち、**完了通知は別チャネル
(1 深度イベント + ポーリング)**にする。コールバック(クロージャ登録)を採らないのは、
no_std でのクロージャ所有・ライフタイムの複雑化を避け、`Commissioner`(§6)が
「イベント入力 → 次のコマンド出力」の Mealy machine として素直に書けるため。

### 3.6 CASE resumption(initiator 側)

`secure-channel.md` §7.4 の initiator 鏡像。設計の詳細(レコード構造・鍵導出・容量/追い出し)
は同節を正とし、ここでは initiator 固有の配線だけ記す:

- `ScInitiator` は `ResumptionStore<4>`(メモリ内・FIFO 追い出し)を内包する。公開 API は
  不変: `start_case` が store を `(fabric_idx, peer_node_id)` で引き、レコードがあれば
  Sigma1 に resumptionID(ctx6)+ S1RK ベースの initiatorResumeMIC(ctx7)を自動で付ける。
- 応答分岐: `CaseSigma2Resume`(0x33)なら MIC 検証 → "SessionResumptionKeys" で鍵導出 →
  commit → 成功 StatusReport を `HandlerAction::Close` で返し
  `ScEvent::CaseEstablished { resumed: true }`。フル `CaseSigma2` なら従来経路
  (responder がレコードを失っていた場合の自動フォールバック)。
- フル CASE 成功時は Sigma2 の TBE2 から resumptionID(ctx4)を取り出して保存、
  resumption 成功時は受信した新 resumptionID でローテート保存。
- 永続化は今回スコープ外(プロセス内のみ)。§10-7 の operational 再接続で KVS 接続時に
  レコードの export/import を足す。

---

## 4. IM クライアント

### 4.1 全体構造

```rust
// im/client.rs
pub struct ImClient<const RESULT: usize = 1280> {
    txn: Option<ClientTxn>,           // 同時 1 トランザクション
    event: Option<ImEvent>,
    result: [u8; RESULT],             // 応答 payload の写し(§4.4)
    result_len: usize,
}

enum ClientTxn {
    Read    { exchange: ExchangeId, started_ms: u64 },   // Subscribe プライミングも同型
    Write   { exchange: ExchangeId, started_ms: u64 },
    Invoke  { exchange: ExchangeId, started_ms: u64 },
    Subscribe { exchange: ExchangeId, started_ms: u64, sub_id: Option<u32> },
}

impl<const RESULT: usize> ProtocolHandler for ImClient<RESULT> {
    const PROTOCOL_ID: u16 = PROTO_ID_INTERACTION_MODEL;
    fn handle<const S: usize>(&mut self, rx: &RxMessage<'_>, tx: &mut [u8],
        sessions: &mut SessionManager<S>, now_ms: u64) -> Result<HandlerAction>
    {
        match ImOpCode::from_u8(rx.header.proto_opcode)? {
            ImOpCode::ReportData      => self.on_report(rx, tx),        // §4.2
            ImOpCode::SubscribeResponse => self.on_subscribe_resp(rx),
            ImOpCode::WriteResponse   => self.on_write_resp(rx),
            ImOpCode::InvokeResponse  => self.on_invoke_resp(rx),
            ImOpCode::StatusResponse  => self.on_status(rx),            // エラー終端
            _ => Err(Error::InvalidState),   // client 宛に Request 系は来ない
        }
    }
}
```

送信 payload の組み立ては**既存 `im::wire` の encode 系をそのまま使う**
(`encode_read_request` / `encode_invoke_request` / `encode_write_request`。§2 の通り
双方向 codec 完備)。開始 API:

```rust
impl<const RESULT: usize> ImClient<RESULT> {
    /// 各 start_* は out に payload を書き長さを返す(送信は ControllerStack、§7.2)。
    pub fn start_read(&mut self, ex: ExchangeId, paths: &[AttributePath],
        out: &mut [u8], now_ms: u64) -> Result<usize>;
    pub fn start_invoke<F>(&mut self, ex: ExchangeId, path: CommandPath,
        fields: F, out: &mut [u8], now_ms: u64) -> Result<usize>
        where F: FnOnce(&mut TlvWriter, &TlvTag) -> Result<()>;   // pase_invoke と同形
    pub fn start_write(...) -> Result<usize>;
    pub fn take_event(&mut self) -> Option<ImEvent>;
    pub fn on_tick(&mut self, now_ms: u64);   // 放置トランザクションの掃除
}
```

### 4.2 受信状態機械(デバイス側の正確な鏡像)

- **ReportData 受信**(Read / Subscribe プライミング):
  `ReportDataRef`(実装済み)で解析し、payload を `result` に**追記コピー**(§4.4)。
  - `MoreChunkedMessages = true` → `StatusResponse(Success)` を書いて
    **`HandlerAction::Respond`**(「次を送れ」の合図。デバイス側 §5.1 の client 矢印
    そのもの)。トランザクション継続。
  - 最終チャンク(More なし)→ `suppress_response` でなければ `StatusResponse(Success)`
    を **`Close`** で返し、`ImEvent::ReadDone` を積む。Subscribe プライミング中なら
    続く SubscribeResponse を待つ(トランザクション維持、Respond で Status を返す)。
- **InvokeResponse / WriteResponse 受信**: `InvokeResponseRef` 等で解析し
  `ImEvent::InvokeDone` / `WriteDone`(status / 生成レスポンスの写し)を積む。
  送るものはない(standalone ACK は MRP = exchange 層が処理)→ `HandlerAction::None`。
- **StatusResponse 受信**(エラー終端): `ImEvent::Failed { status }`、`None`。

1 メッセージ = 1 `handle`・状態は slot・応答は `Respond`/`Close` — デバイス側
(interaction-model §5)と完全に同型で、**既存契約への追加はゼロ**。

### 4.3 Subscribe クライアントのスコープ

コミッショニングに Subscribe は不要なため**初期スコープでは Read/Write/Invoke のみ**を
実装し、Subscribe は型(`ClientTxn::Subscribe`)と経路だけ確保する。理由と将来の注意:

- 確立後の定期レポートは**デバイス発の新規 exchange**(デバイスが `open_initiator`)で
  届くため、コントローラ側では「新規 responder exchange の ReportData」になる。
  これは §3.1 の「unsolicited は受けない」方針の唯一の例外であり、実装時は
  `ImClient::handle` に「sub_id 照合つきの unsolicited ReportData 受理」分岐を足す
  (`RxMessage.role == Responder` で判別可能。オープン論点 §9-2)。

### 4.4 結果の返し方 — **固定バッファへのコピー + ポーリング取り出し**

| 案 | 評価 |
|---|---|
| コールバック(visitor)を start 時に登録 | コピー不要だが、no_std でのクロージャ所有(トレイトオブジェクト or 型パラメータ増殖)と、`handle` の借用(`rx` は受信バッファ借用で `handle` を出ると無効)の緊張。API が複雑化 |
| **`result` 固定バッファへコピーし `take_event` + `result()` で取り出し** | コピー 1 回(≤ 1 チャンク × チャンク数)を払う代わりに、所有権が自明・イベント駆動の Commissioner と揃う |

**判断: コピー + ポーリング**。コミッショニングで読むデータは小さく
(CSRResponse の NOCSRElements ~600B、AttestationResponse 同程度、コマンド応答は数十 B)、
`RESULT = 1280`(1 チャンク分)の既定で足りる。チャンクをまたぐ大 Read(ワイルドカード
全属性)はコントローラの初期ユースケースにないため、`result` 溢れは
`ImEvent::Failed(ResourceExhausted)` で打ち切る(ストリーミング化はオープン論点 §9-3)。

```rust
pub enum ImEvent {
    ReadDone,                              // result() に AttributeReportIB 列(連結生 TLV)
    InvokeDone { status: ImStatus },       // result() に生成レスポンス TLV(あれば)
    WriteDone { status: ImStatus },
    SubscribeDone { sub_id: u32 },
    Failed { status: ImStatus },
}
impl<const RESULT: usize> ImClient<RESULT> {
    pub fn result(&self) -> &[u8];         // 直近イベントの payload 写し
}
```

コマンド応答(NOCSRElements / NOCResponse 等)の**意味的デコード**は `Commissioner`
(§6)側のヘルパが行う(`ImClient` は IM の枠組みまで、クラスタ知識は持たない —
デバイス側で `im::wire` が `dm` を知らないのと同じ規律)。

---

## 5. discovery クライアント

### 5.1 スコープと形

sans-IO を厳格に守る: `MdnsClient` は**クエリのバイト列生成**と**レスポンスの解析・集約**
のみを行い、ソケット・マルチキャスト join・リトライ・タイムアウトは呼び出し側
(アプリ / 統合層)の責務とする(`MdnsResponder` と同じ分界)。キャッシュも持たない
(1 パケット内で解決できる情報だけを返し、不足分は呼び出し側が再クエリ)。

```rust
// discovery/client.rs
pub struct MdnsClient;   // 状態レス(関数群の名前空間。将来 tid 管理が要れば struct 化)

impl MdnsClient {
    /// _matterc._udp.local の PTR クエリ(commissionable browse)。戻りは out 内の長さ。
    pub fn build_browse_commissionable(out: &mut [u8]) -> Result<usize>;
    /// long discriminator サブタイプ(_L<d>._sub._matterc._udp)での絞り込みクエリ。
    pub fn build_browse_discriminator(out: &mut [u8], discriminator: u16) -> Result<usize>;
    /// operational 解決: <compressed-fabric-id>-<node-id>._matter._tcp.local の SRV/AAAA。
    pub fn build_resolve_operational(out: &mut [u8],
        compressed_fabric_id: &[u8; 8], node_id: u64) -> Result<usize>;

    /// 受信パケットから commissionable ノードを抽出する(PTR→SRV→TXT→A/AAAA を
    /// 同一パケット内で辿る。additional records 同梱が通例のため 1 パケットで完結する)。
    pub fn parse_commissionable(pkt: &[u8]) -> Option<DiscoveredCommissionable>;
    /// operational 解決レスポンスから (アドレス, ポート) を抽出する。
    pub fn parse_operational(pkt: &[u8], compressed_fabric_id: &[u8; 8], node_id: u64)
        -> Option<DiscoveredNode>;
}

pub struct DiscoveredCommissionable {
    pub instance: heapless::String<64>,   // インスタンス名(再クエリ用)
    pub port: u16,
    pub addrs: FixedVec<IpAddr, 2>,       // A/AAAA(同一パケット内で見つかった分)
    pub discriminator: Option<u16>,       // TXT "D="
    pub vendor_product: Option<(u16, u16)>, // TXT "VP="
    pub commissioning_mode: Option<u8>,   // TXT "CM="
}
pub struct DiscoveredNode { pub addrs: FixedVec<IpAddr, 2>, pub port: u16 }
```

### 5.2 dns.rs への追加(最小の cfg 付き拡張)

既存 `dns.rs` は `Response`/`Record`/`Name` の解析(SRV/TXT・圧縮ポインタ)を持つが、
(a) `MsgWriter` が QR=1(Response)固定で Question セクションを書けない、
(b) A/AAAA の型付きアクセサ(`Record::srv()`/`txt_contains()` 相当)がない。
`#[cfg(feature = "controller")]` で次を足す(§2.3 の規律 3。既存関数は不変):

```rust
impl<'a> MsgWriter<'a> {
    /// QR=0(Query)ヘッダで開始する(既存 new は QR=1 のまま不変)。
    pub fn new_query(buf: &'a mut [u8]) -> Result<Self>;
    /// Question セクションに 1 問を書く(QU ビット指定可)。
    pub fn question(&mut self, name: &[&[u8]], rtype: u16, unicast_response: bool) -> Result<()>;
}
impl<'a> Record<'a> {
    pub fn a(&self) -> Option<Ipv4Addr>;      // TYPE=1
    pub fn aaaa(&self) -> Option<Ipv6Addr>;   // TYPE=28
    /// TXT を "K=V" ペアとして走査(既存 txt_contains の一般化)。
    pub fn txt_entries(&self) -> TxtEntries<'a>;
}
```

`Response::parse` / `Records` / 圧縮ポインタ処理はそのまま使う(mDNS レスポンスの解析は
QR ビット以外 Query と同形式であり、`Response::parse` が受理する)。

---

## 6. コミッショナ本体と CA

### 6.1 コミッショニングフロー(Mealy 状態機械)

chip の `DeviceCommissioner` の commissioning stage 列を、単一コントローラ・IP 直結・
attestation スキップ可、の前提で最小化する。**状態機械の入力は §3.5 / §4.4 のイベント、
出力は次のトランザクション開始**(= `ControllerStack` の `start_*` 呼び出し)。

```
 Idle
  │ commission(peer, passcode, node_id)
  ▼
 Pase          ─ ScEvent::PaseEstablished ──────────────► ArmFailSafe
 ArmFailSafe   ─ Invoke GC::ArmFailSafe(expiry=120s) → InvokeDone(Success)
  │                                        (任意: ReadCommissioningInfo — 初期は省略可)
  ▼
 [Attestation] ─ policy=Skip なら素通し(§6.4)。Verify なら
  │              CertificateChainRequest(DAC/PAI) → AttestationRequest → 検証
  ▼
 Csr           ─ Invoke OC::CSRRequest(nonce) → InvokeDone → NOCSRElements 解析
  │              → parse_csr で公開鍵抽出 + CSR 署名検証(§6.3)
  ▼
 AddTrustedRoot─ Invoke OC::AddTrustedRootCertificate(RCAC)
  ▼
 AddNoc        ─ Ca::issue_noc(csr_pub, node_id) → Invoke OC::AddNOC(noc, ipk,
  │              case_admin_subject = 自 node id, admin_vendor_id) → NOCResponse(Ok)
  ▼
 Case          ─ start_case(同一 peer への新 unsecured セッション) …
  │              ScEvent::CaseEstablished(operational セッション確立)
  ▼
 Complete      ─ Invoke GC::CommissioningComplete(CASE 上) → InvokeDone(Success)
  ▼
 Done { session }         (以降アプリはこの CASE セッションで On/Off 等を invoke)

 任意の状態: ScEvent::Failed / ImEvent::Failed / タイムアウト ─► Failed { stage, reason }
             (fail-safe はデバイス側 expiry による自動巻き戻しに任せる。§9-8)
```

```rust
// controller/commissioner.rs
pub struct Commissioner<'a, C: Crypto> {
    ca: &'a mut Ca<C>,                 // §6.3
    phase: Phase,
    peer: PeerAddr,
    passcode: u32,
    target_node_id: u64,
    policy: AttestationPolicy,         // §6.4
    started_ms: u64,                   // フェーズ別タイムアウト
}
pub enum Phase { Idle, Pase, ArmFailSafe, Attestation(AttStep), Csr, AddTrustedRoot,
                 AddNoc, Case, Complete, Done { session: SessionId },
                 Failed { stage: u8, reason: CommissionError } }

impl<'a, C: Crypto> Commissioner<'a, C> {
    pub fn new(ca: &'a mut Ca<C>, policy: AttestationPolicy) -> Self;
    /// コミッショニングを開始する(Idle 以外では Err(Busy))。
    pub fn commission(&mut self, peer: PeerAddr, passcode: u32, node_id: u64,
        now_ms: u64) -> Result<()>;
    /// イベントを消費して 1 遷移進める。stack の start_* を呼ぶのはここだけ。
    /// handle_rx / poll のたびに呼ぶ(進展がなければ何もしない)。
    pub fn drive<S: ControllerStackApi>(&mut self, stack: &mut S, now_ms: u64)
        -> Phase;   // 現フェーズを返す(Done / Failed で終端)
}
```

- `drive` は `stack.sc_take_event()` / `stack.im_take_event()` を読み、フェーズ表に従って
  次の `start_*` を発行する純粋な Mealy machine。**送受信も暗号も持たない**ため、
  フェーズ遷移は入出力列だけで単体テストできる(モック stack)。
- 各 Invoke の payload 組み立て / 応答デコード(ArmFailSafe 引数、NOCSRElements、
  NOCResponse 等)は `commissioner.rs` 内の小さなヘルパ関数群
  (`stack/tests.rs` の該当コードの移設)。

### 6.2 コールバック vs ポーリング(統合層との駆動契約)

アプリ(統合層)のループはデバイス側と同じ単一 select に載る:

```
loop select {
    rx = net.recv()                  → stack.handle_rx(...) → 送信; commissioner.drive(...)
    _  = timer(stack.next_deadline)  → stack.poll(...) → 送信;      commissioner.drive(...)
    _  = mdns.recv()                 → MdnsClient::parse_*(...)     (discovery 期間のみ)
}
```

`drive` の戻り値(`Phase`)がアプリへの進捗通知を兼ねる。プッシュ型コールバックを
提供しないのは §3.5 と同じ判断(sans-IO の同期契約を汚さない)。

### 6.3 CA 機能(RCAC 自己署名・NOC 発行・鍵と IPK の管理)

**cert 側の正式化**(`cert.rs` 内 `#[cfg(feature = "controller")] mod issue`):

```rust
/// Matter TLV 証明書の発行仕様。cert/tests.rs write_cert の引数列の構造化。
pub struct MatterCertSpec<'a> {
    pub serial: &'a [u8],
    pub issuer: &'a [DnAttr],          // DnAttr = { tag: u8, val: u64 }(rcac-id 等)
    pub subject: &'a [DnAttr],         // NOC は node-id(17) + fabric-id(21)
    pub not_before: u32, pub not_after: u32,   // Matter epoch 秒
    pub subject_pub: &'a [u8; 65],
    pub is_ca: bool,                   // RCAC/ICAC = true(+path_len)、NOC = false
    pub key_usage: u16,                // CA: keyCertSign|CRLSign / NOC: digitalSignature
    pub eku: &'a [u8],                 // NOC: [serverAuth, clientAuth]
    pub skid: &'a [u8; 20], pub akid: &'a [u8; 20],   // SHA-1(pubkey) 由来
}
/// 仕様どおり TLV を組み、DER TBS を再構成して issuer_kp で ECDSA 署名し埋め戻す
/// (tests の write_cert と同一手順の製品化)。戻りは証明書 TLV 長。
pub fn write_matter_cert<C: Crypto>(out: &mut [u8], spec: &MatterCertSpec<'_>,
    issuer_kp: &C::Keypair) -> Result<usize>;

/// PKCS#10 CSR(DER)から公開鍵を取り出し、self-signature を検証する
/// (write_csr の逆方向。デバイスの CSRResponse 処理に使う)。
pub fn parse_csr<C: Crypto>(crypto: &C, csr: &[u8]) -> Result<[u8; 65]>;
```

**Ca 本体**(`controller/ca.rs`):

```rust
pub struct Ca<C: Crypto> {
    root_kp: C::Keypair,               // CA 秘密鍵(初期は RAM のみ。永続化は §9-9)
    rcac: CertBuf,                     // 自己署名 RCAC(TLV)
    rcac_id: u64,
    fabric_id: u64,
    ipk_epoch_key: [u8; 16],           // AddNOC で配る epoch key(乱数生成)
    next_serial: u32,
    creds: FabricTable<C, 1>,          // コントローラ自身の運用資格情報(下記)
}

impl<C: Crypto> Ca<C> {
    /// 新規 CA を生成: 鍵ペア + 自己署名 RCAC + IPK epoch key + 自 NOC の発行と
    /// FabricTable::add(検証込み)まで行う。controller_node_id は自ノードの運用 ID。
    pub fn generate<R: Rng>(crypto: &C, rng: &mut R, fabric_id: u64,
        controller_node_id: u64, vendor_id: u16, now_epoch_s: u32) -> Result<Self>;
    /// デバイス CSR の公開鍵に対して NOC を発行する(out に TLV、戻りは長さ)。
    pub fn issue_noc(&mut self, crypto: &C, subject_pub: &[u8; 65], node_id: u64,
        out: &mut [u8]) -> Result<usize>;
    pub fn rcac(&self) -> &[u8];
    pub fn ipk_epoch_key(&self) -> &[u8; 16];
    pub fn creds(&self) -> &FabricTable<C, 1>;   // CASE initiator の素材(§3.4)
}
```

**コントローラ自身の資格情報に `FabricTable<C, 1>` を流用する判断**: CASE initiator が
必要とする素材(自 NOC・operational 鍵・root 公開鍵・operational IPK・
CompressedFabricId・destination-id 用の fabric/node id)は、responder の
`FabricStore`/`Fabric` trait が提供する面と同一である。`FabricTable::add` は
チェーン検証・IPK 導出込みで実装・検証済みであり、専用 struct を新設するより
「自分が発行した証明書が自分の検証器を通る」ことの常時確認にもなる。

### 6.4 attestation の扱い(初期はスキップ可能な設計)

```rust
pub enum AttestationPolicy {
    /// DAC/PAI/CD を取得も検証もしない(自作デバイス・開発フロー用の既定)。
    Skip,
    /// CertificateChainRequest + AttestationRequest を実行し、与えられた PAA 集合で検証。
    Verify(/* &'a PaaStore — 形はオープン論点 §9-4 */),
}
```

フェーズ列に `Attestation` を**常設**し、`Skip` では即遷移する(後日 `Verify` を
実装してもフェーズ表が変わらない)。chip 系デバイスは attestation コマンドに応答する
だけでコミッショナ側検証は必須でないため、`Skip` でも相互運用は成立する
(chip-tool 相当の緩和は `--bypass-attestation-verifier` に相当)。

---

## 7. ControllerStack(統合)

### 7.1 MatterStack の拡張か、対になる別スタックか — **別スタック**

`MatterStack` に initiator 面を足す案は、(a) 型パラメータ増(D: DataModel が不要なのに
残る)、(b) デバイスビルドへの cfg 波及、(c) `ensure_unsecured_session` 等の受信駆動
前提との混線、で不利。**`ControllerStack` を独立に立て、同じ下位部品
(`SessionManager` / `ExchangeManager` / `BufferPool` / `SecureCodec`)を同じ形で所有する**。
コードの重複は「配線」のみで、部品はすべて共用される。

```rust
// controller/mod.rs
pub struct ControllerStack<'s, C: Crypto, R: Rng,
    const SESSIONS: usize = 3,     // unsecured + PASE + CASE(コミッショニング中の最大)
    const EXCHANGES: usize = 2,    // SC ハンドシェイク + IM トランザクション
    const TX_BUFS: usize = 2,
    const RESULT: usize = 1280,
> {
    crypto: &'s C,
    sessions: SessionManager<SESSIONS>,
    mgr: ExchangeManager<ProtocolMux<ScInitiator<'s, C>, ImClient<RESULT>>, EXCHANGES>,
    tx_pool: BufferPool<TX_BUFS, MAX_PACKET_SIZE>,
    resp: [u8; MAX_PACKET_SIZE],
}
```

### 7.2 API(MatterStack と対の sans-IO 契約 + 開始系)

```rust
impl<...> ControllerStack<...> {
    pub fn new(crypto: &'s C, sc: ScInitiator<'s, C>, im: ImClient<RESULT>) -> Self;

    // --- MatterStack と同一の受信/時間駆動契約 ---
    pub fn handle_rx(&mut self, datagram: &mut [u8], peer: PeerAddr, now_ms: u64,
        tx_out: &mut [u8]) -> Option<SendDirective>;
    pub fn poll(&mut self, now_ms: u64, tx_out: &mut [u8]) -> Option<SendDirective>;
    pub fn next_deadline(&self, now_ms: u64) -> Option<u64>;

    // --- 開始系(open_initiator + send_reliable の配線。stage_subscription_report と同型)---
    /// peer への unsecured セッションを能動的に確保し PASE を開始する。
    pub fn start_pase(&mut self, peer: PeerAddr, passcode: u32, now_ms: u64,
        tx_out: &mut [u8]) -> Result<SendDirective>;
    /// creds(Ca 内 FabricTable)の fabric で peer と CASE を開始する。
    pub fn start_case(&mut self, peer: PeerAddr, creds: &FabricTable<C, 1>,
        peer_node_id: u64, now_ms: u64, tx_out: &mut [u8]) -> Result<SendDirective>;
    /// 確立済み session 上で IM トランザクションを開始する。
    pub fn start_invoke<F>(&mut self, session: SessionId, path: CommandPath, fields: F,
        now_ms: u64, tx_out: &mut [u8]) -> Result<SendDirective> where F: FnOnce(..);
    pub fn start_read(...) -> Result<SendDirective>;
    pub fn start_write(...) -> Result<SendDirective>;

    // --- イベント取り出し(§3.5 / §4.4)---
    pub fn sc_take_event(&mut self) -> Option<ScEvent>;
    pub fn im_take_event(&mut self) -> Option<ImEvent>;
    pub fn im_result(&self) -> &[u8];
}
```

- `start_*` の内部は共通ヘルパ 1 本:「ハンドラの `start_*` で `resp` に payload を
  書かせ → `open_initiator(session)` → `send_reliable(sessions, crypto, pool, ex,
  &Outgoing{..}, timing)` → 暗号化済みワイヤを `tx_out` へ」。
  `MatterStack::stage_response` / `stage_subscription_report` と同じ実装パターンで、
  暗号境界(`SecureCodec`)・MRP 再送は既存実装のまま。
- `handle_rx` は MatterStack のそれから `ensure_unsecured_session`(受信駆動の平文
  セッション確保)を**外した**形。コントローラの unsecured セッションは `start_pase` /
  `start_case` が能動的に insert する。未知セッション・unsolicited 入口 opcode は
  silent drop。

### 7.3 サイジング(同時コミッショニング 1 台)

| 要素 | 概算 |
|---|---|
| `SessionManager<3>` | Session ~200B × 3 ≈ 600 B |
| `ExchangeManager<_, 2>` | ExchangeState(MRP 込み)~100B × 2 + mux |
| `ScInitiator`(slot 1) | PaseInitiator が支配: prover(スカラ 3 + 点 65)+ context ≈ 400 B |
| `ImClient<1280>` | result バッファ 1280 B + txn/event ~64 B |
| `BufferPool<2, 1600>` | 3.2 KB(MRP 再送保持用。デバイス側と同値) |
| `resp` 作業バッファ | 1.6 KB |
| `Ca` | 鍵 32B + RCAC CertBuf(~600B)+ `FabricTable<C,1>`(~1.5KB: NOC/RCAC 格納) |
| **合計(ControllerStack + Ca)** | **≈ 9–10 KB RAM**(flash はデバイス側と共通部品 + 差分数 KB 見込み) |

const generic は 4 つ(SESSIONS/EXCHANGES/TX_BUFS/RESULT)に既定値を与え、
アプリは `ControllerStack<C, R>` とだけ書ける(プロファイルエイリアス不要の規模)。
`ram-report` に controller プロファイル行を追加して継続計測する(§2.3)。

---

## 8. 実装分割(4 ピース)と依存順序

| ピース | 範囲 | 依存 |
|---|---|---|
| **A: sc initiator** | `controller` feature 追加(Cargo.toml/lib.rs)、`sc/case/common.rs` への移動リファクタ、PASE/CASE 鏡像 codec、`ScInitiator` 状態機械、CI の footprint 不変ジョブ(§2.3)。**単体テスト**: 既存 `SecureChannel`(responder)と直結し PASE/CASE をメモリ内往復(sc/responder.rs tests の prover 駆動コードを置換・吸収) | なし(既存実装のみ) |
| **B: IM クライアント** | `im/client.rs`(`ImClient` + イベント)、チャンク受信 + StatusResponse 返し。**単体テスト**: 既存 `InteractionModel`(responder)+ 最小 DataModel と直結し Read(チャンク)/Invoke/Write 往復 | なし(A と並列可) |
| **C: discovery client** | `dns.rs` のクエリビルダ/アクセサ(cfg 付き)、`discovery/client.rs`(browse/resolve/parse)。**単体テスト**: `MdnsResponder` の `handle_query` 出力を `parse_commissionable` に食わせる自己整合 + chip 実キャプチャの固定バイト列 | なし(A/B と並列可。D の実機試験までに合流) |
| **D: コミッショナ統合 + CA** | `cert::issue`(`write_matter_cert`/`parse_csr`)、`controller/ca.rs`、`controller/commissioner.rs`、`ControllerStack`、bloat-check ram-report 行、セルフテスト(§9.1)と examples/commissioner.rs | **A・B 必須**。C は実機相互運用時に使用(セルフテストでは不要) |

推奨順序: **A → B → D**(A/B は並列開発可)。C は独立しており、D のセルフテスト完了後・
実機相互運用試験の前までに合わせればよい。各ピースの完了条件に「footprint 不変 CI が
green」を含める。

---

## 9. 検証計画

### 9.1 セルフテスト(メモリ内コミッショニング)

`crates/simple-matter/src/controller/tests.rs`(または stack/tests.rs 併設)に
`controller_end_to_end` を追加する:

1. デバイス側: 既存 `onoff_light_end_to_end` と同じ `MatterStack` + On/Off ライト構成。
2. コントローラ側: `Ca::generate` → `ControllerStack` + `Commissioner`。
3. **メモリ内ポンプ**: 2 つのスタックの `SendDirective` を相互の `handle_rx` に渡す
   ループ(`poll` / `next_deadline` も時刻を進めながら駆動。MRP 再送・ACK 経路も踏む)。
4. 検証項目: PASE 確立 → ArmFailSafe → CSR → AddTrustedRoot → AddNOC(デバイス側
   `FabricTable` に fabric が生えること)→ CASE 確立 → CommissioningComplete →
   CASE 上で On/Off `Toggle` invoke → デバイスの属性が変わること → Read で読み戻し。
5. **既存 `onoff_light_end_to_end` の手書き commissioner 部分(build_msg/decode_resp/
   pase_invoke/write_cert/case:: 直叩き)を本テストで段階的に置換**する。テストコードの
   削減量が「昇格」の完了指標になる。異常系(パスコード不一致 → Pake2 で失敗、
   CSR 署名不正、CASE destination-id 不一致)も同じポンプで足す。

### 9.2 chip 系サンプルデバイスとの実相互運用(想定手順)

デバイス側 ↔ chip-tool の相互運用は実証済みなので、今回は**コントローラ側 ↔ chip デバイス**:

1. 相手: `connectedhomeip` の `chip-all-clusters-app` または `chip-lighting-app`
   (Linux 上、`--discriminator 3840 --passcode 20202021` 等の既知値で起動)。
2. ホスト用サンプル `crates/simple-matter/examples/commissioner.rs`(std UDP +
   socket2 の mDNS ソケット。`onoff-light.rs` example と同じ流儀)を用意し、
   (a) `MdnsClient::build_browse_commissionable` を 5353/multicast へ送出、
   (b) `parse_commissionable` で discriminator 照合しアドレス/ポート決定、
   (c) `Commissioner::commission(peer, 20202021, node_id)` を駆動、
   (d) Done 後に On/Off Toggle を invoke し、chip 側ログ(`CHIP:ZCL` の On/Off 遷移)で確認。
3. 比較検証: 同一デバイスを chip-tool でコミッショニングした際のパケットキャプチャ
   (Wireshark の Matter dissector)と本コントローラのシーケンスを突き合わせる。
   特に PBKDFParamRequest の session parameters、Sigma1 の destination-id、
   AddNOC の IPK/CaseAdminSubject。
4. 失敗パスの相互運用: 誤パスコードで PASE が `InvalidParameter` で終わること、
   fail-safe expiry(ArmFailSafe 後に放置)でデバイスが巻き戻ること。
5. 逆方向(セルフのデバイス ↔ chip-tool)は既存の実証を回帰として維持
   (コントローラ追加がデバイス側を壊していないことの確認は §2.3 の CI が担う)。

---

## 10. オープンな論点

1. **`sc/case/responder.rs` → `common.rs` リファクタの正確な切断線**。destination-id
   照合(responder は全 fabric 総当り、initiator は 1 fabric で計算)をどう共有するか。
   旧パス `pub use` 互換をいつまで残すか(`stack/tests.rs` 置換完了時に整理)。
2. **Subscribe クライアント**(§4.3)。デバイス発レポートが controller 側では
   unsolicited な responder exchange として届く経路の設計(sub_id 照合・liveness)。
   初期スコープ外だが `ClientTxn::Subscribe` の型だけ確保する、の妥当性。
3. **大きな Read 結果**(§4.4)。`result` 固定バッファ溢れの打ち切りで足りるか。
   チャンクごとにアプリへ渡すストリーミング API(`ImEvent::ReadChunk`)の要否。
4. **attestation `Verify` の形**(§6.4)。PAA trust store の持ち方(const 埋め込み /
   KVS)、CD(Certification Declaration)の CMS 検証をどこまで no-alloc でやるか。
5. **CA 鍵・fabric 情報の永続化**。`Ca` を再起動間で維持しないと再コミッショニングに
   なる。platform KVS trait(第6段階)との接続。IPK epoch key のローテーション。
6. **両役ノード(device + controller 同居)**。将来 bridge/admin を作る場合、
   `MatterStack` と `ControllerStack` が 1 つの UDP ソケット/SessionManager を共有する
   必要が出る。現設計は別スタック(ポート分離)で割り切っており、統合には
   ProtocolMux の 4 スロット化(ScResp/ScInit/ImServer/ImClient)が要る。
7. **operational 再接続**。コミッショニング後にコントローラを再起動した場合の
   CASE 再確立(operational discovery → start_case)。session resumption(Sigma2Resume)
   自体は §3.6 / secure-channel §7.4 で実装済み(プロセス内)。再起動をまたぐには
   resumption レコードと CA 状態の永続化(KVS)が要る。
8. **失敗時の後始末**。`Failed` 終端でコントローラ側は slot/セッションを破棄するのみで、
   デバイス側の巻き戻しは fail-safe expiry 任せにしている。明示的な
   CloseSession StatusReport 送出や ArmFailSafe(0) での即時解除を送るべきか。
9. **`start_*` と MRP 再送中の競合**。前トランザクションの最終送信が ACK 未達のまま
   次の `start_*` を呼んだ場合の挙動(TX バッファ枯渇 → Err(NoSpace) で呼び出し側リトライ、
   で足りるか)。`Commissioner::drive` がイベント駆動なので通常は起きないが、規約の明文化。
10. **mDNS クエリの追加問い合わせ**。additional records に A/AAAA を同梱しない
    レスポンダ(稀)への追撃クエリ(SRV → ターゲット名の AAAA)をクライアントの
    状態として持つか、呼び出し側に任せるか(現設計は後者)。

---

## 11. 参照実装との対応表

| 論点 | chip(src/controller) | rs-matter | 本設計 |
|---|---|---|---|
| commissioning stage 遷移 | `DeviceCommissioner` + `CommissioningStage` enum(自動遷移) | (controller は限定的) | `Commissioner::Phase` の Mealy machine(§6.1)。stage 列は chip の必須部分集合 |
| PASE/CASE initiator | `PASESession`/`CASESession`(両役同居) | 同居(initiator/responder 同居が課題と分析済み) | **initiator を別ハンドラ・別 feature に分離**(§3.1)。デバイスに同居させない |
| IM クライアント | `ReadClient`/`CommandSender`(状態機械) | `im` 同居 | `ImClient` slot 機構(デバイス側 ReadTxn と同型の鏡像、§4) |
| CA / NOC 発行 | `ExampleOperationalCredentialsIssuer` | (テスト内) | `Ca` + `write_matter_cert`(実証済み write_cert の正式化、§6.3) |
| attestation | `DeviceAttestationVerifier`(必須・bypass 可) | — | `AttestationPolicy::Skip / Verify`(フェーズ常設・初期 Skip、§6.4) |
| discovery クライアント | `Resolver`/DNS-SD(プラットフォーム委譲) | mDNS 混在 | sans-IO の `MdnsClient`(クエリ生成 + 解析のみ、リトライは呼び出し側、§5) |
| スタック統合 | 単一 `DeviceControllerSystemState`(巨大) | 単一 stack | **`ControllerStack` を `MatterStack` と対で分離**、下位部品は完全共用(§7) |

**借りるもの**: chip の commissioning stage 語彙と順序、AddNOC の引数構成
(IPK/CaseAdminSubject/AdminVendorId)、attestation bypass の運用。
**変える点**: initiator/responder の物理分離(feature + 別ハンドラ)、async でなく
同期 sans-IO の Mealy machine への写像、CA を FabricTable 流用で最小化、
discovery を完全 sans-IO 化。いずれも本プロジェクトの既存規律
(footprint・受信一本道・型爆発回避)からの必然的帰結である。
