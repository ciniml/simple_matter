# connectedhomeip (Matter 公式 SDK) 構造調査レポート

- 調査対象: `/home/kenta/repos/simple_matter/research/connectedhomeip`（sparse checkout、`src/` と `docs/` のみ）
- SDK バージョン: `SPECIFICATION_VERSION` = 1.2.0、コミット `4164983`（2026-07-02）
- 目的: (a) 参照実装としてのレイヤ構造の把握、(b) 肥大化の構造的要因の特定
- 前提: 我々は Rust / no_std で「小フットプリント Matter デバイス側実装」を新規に作る

本レポート中のパスはすべて `src/` 起点（絶対パスは `/home/kenta/repos/simple_matter/research/connectedhomeip/` を前置）。

---

## 0. サマリ（結論先出し）

connectedhomeip の `src/` は約 4,000 C/C++ ファイル。トップレベルのサイズ内訳は次の通りで、上位 3 つ（`controller` 33M、`darwin` 28M、`app` 26M）だけで全体の過半を占める。

| dir | size | 役割 |
|---|---|---|
| controller | 33M | クライアント（コントローラ）側実装 + Python/各言語バインディング |
| darwin | 28M | Apple 向け Objective-C ラッパ + 生成コード |
| app | 26M | サーバ側（デバイス側）Interaction Model エンジン + 120 個のクラスタ実装 |
| platform | 13M | OS/SoC 抽象（約 24 バックエンド） |
| lib | 4.2M | core（TLV/CHIP_ERROR）+ support（組込ユーティリティ）+ dnssd |
| credentials | 3.1M | 証明書 / 認証 / FabricTable / GroupData |
| crypto | 1.4M | 暗号プリミティブ抽象（PAL）+ 複数バックエンド |
| protocols | 1.3M | Secure Channel / IM 定数 / BDX / Echo / UDC |
| transport | 872K | Session / 暗号化 / raw transport |
| messaging | 544K | Exchange + MRP |
| system | 520K | PacketBuffer / event loop / timer |
| inet | 736K | UDP/TCP エンドポイント抽象 |

**レイヤ構造は非常に綺麗**（下記 §2 の一方向依存）。問題は各層の「幅」（機能網羅・抽象の多重化・コード生成量）であって、レイヤ分割そのものは新実装でもほぼ踏襲すべき（§7）。

---

## 1. src/ 主要ディレクトリの責務とレイヤ構造

下から積み上げる。依存は基本的に下向き（上位が下位に依存）で、循環は避けられている。

### 1.1 基盤層（全層が依存）

- **`src/system`（39 ファイル）** — スタックの土台。
  - `System::PacketBuffer` / `System::PacketBufferHandle`（`SystemPacketBuffer.h/.cpp`、34KB）= 全レイヤを move で貫通するメッセージコンテナ。
  - `System::Layer`（`SystemLayer.h`）= イベントループ / タイマサービス。`StartTimer` / `ScheduleWork`。MRP 再送も応答タイムアウトもここでスケジュールされる。実装は `SystemLayerImplSelect`（POSIX select/epoll、26KB）、`...FreeRTOS`、`...Zephyr`、`...Dispatch`（Darwin）。
  - `System::Clock`（`SystemClock.h`）、`SystemConfig.h`（34KB のコンパイル時設定）。
- **`src/lib/core`（56 ファイル、1020K）** — 型と直列化の中核。
  - `CHIPError.h`（`CHIP_ERROR` 型）、`CHIPConfig.h`（**2,108 行**の巨大コンパイル時設定）。
  - 基本 ID 型: `NodeId.h` / `GroupId.h` / `ScopedNodeId.h` / `PeerId.h` / `CASEAuthTag.h` / `DataModelTypes.h`。
  - **TLV 実装**（Matter 全ペイロードと証明書の on-wire 符号化）: `TLVReader` / `TLVWriter` / `TLVUpdater`（in-place 編集）/ `TLVTags` / `TLVTypes` / `TLVCircularBuffer` / `TLVBackingStore`。
- **`src/lib/support`（117 ファイル、1.7M）** — 組込向けユーティリティ帯。
  - Span: `Span.h`（ByteSpan/MutableByteSpan/FixedSpan）、`BufferReader/Writer`、`ScopedMemoryBuffer`、`FixedBufferAllocator`。
  - フラグ: `BitFlags.h` / `BitMask.h` / `PopCount.h`。
  - プール/確保: `Pool.h`（`ObjectPool`）、`CHIPMem`、`PrivateHeap`。
  - コンテナ/関数: `IntrusiveList.h`、`Variant.h`、`Defer.h`、`LambdaBridge.h`、`StateMachine.h`。
  - 安全性マクロ: `CodeUtils.h`（`ReturnErrorOnFailure` / `VerifyOrReturn` 群）、`SafeInt.h`。
  - 符号化: `Base64` / `BytesToHex` / `StringBuilder` / `utf8`。
  - コミッショニング補助: `SetupDiscriminator.h`、`ThreadOperationalDataset`、`verhoeff/`（setup code チェックサム）。
- **`src/inet`（52 ファイル）** — IP エンドポイント抽象。socket / LwIP / OpenThread / Network.framework を統一 UDP/TCP API に。
  - `UDPEndPoint`（`Bind` / `Listen` / `SendMsg`）、`TCPEndPoint`。実装は `UDPEndPointImplSockets/LwIP/OpenThread`。
  - `EndPointBasis<T>`（参照カウント + プール確保）、`IPAddress`、`IPPacketInfo`、`InterfaceId`。
  - 注: inet は Matter のセッション・セキュリティを一切知らない。バイト + アドレス情報を運ぶだけ。

### 1.2 通信層

- **`src/transport`（root 37 ファイル + `raw/` 22 + `retransmit/`）** — セッション・暗号化・raw transport。詳細 §2。
- **`src/messaging`（25 ファイル）** — Exchange（会話単位）と MRP（信頼性）。詳細 §2。
- **`src/protocols`（1.3M）** — Matter アプリケーションプロトコル群。
  - `Protocols.h/.cpp` — プロトコル ID レジストリ。`Protocols::Id` = `(VendorId<<16)|protocolId`。標準プロトコル: SecureChannel=0x0000, InteractionModel=0x0001, BDX=0x0002, UDC=0x0003, Echo=0x0004。
  - `secure_channel/`（31 ファイル、~8,146 LOC）— PASE/CASE。最大。
  - `interaction_model/`（5 ファイル）— **定数とステータスコードのみ**（`MsgType`、`Status`）。エンジン本体は `src/app`。
  - `bdx/`（23 ファイル、~4,027 LOC）— OTA 等のバルク転送。
  - `echo/`（3 ファイル、診断）、`user_directed_commissioning/`（5 ファイル）。

### 1.3 アプリケーション層（サーバ = デバイス側）

- **`src/app`（26M、120 クラスタ）** — Interaction Model エンジン + データモデル + クラスタ実装。詳細 §3・§4。
- **`src/credentials`（3.1M）** — セキュリティ永続状態。
  - `CHIPCert`（Matter TLV 証明書）、`CHIPCertToX509` / `CHIPCertFromX509`。
  - デバイス側 Attestation: `DeviceAttestationCredsProvider`（DAC/PAI/CD 提供）、`CertificationDeclaration`。
  - コミッショナ側検証: `attestation_verifier/`（`DefaultDeviceAttestationVerifier`、`FileAttestationTrustStore` = PAA ルート）。
  - `FabricTable`（`FabricInfo` / `FabricTable`）= 参加済み fabric の集中管理。`OperationalCertificateStore`（NOC/ICAC/root のステージングコミット）。`GroupDataProvider`（マルチキャスト用グループ鍵）。
- **`src/crypto`（1.4M）** — 暗号プリミティブ抽象。詳細 §5.2。
- **`src/lib/dnssd`（948K）** — commissionable（`_matterc._udp`）と operational（`_matter._tcp`）の mDNS。**独自の `minimal_mdns/` スタック同梱**（OS の mDNS に依存しない）。Advertiser（サーバ側）/ Resolver（クライアント側）/ `Discovery_ImplPlatform`（プラットフォーム DNS-SD 委譲）。

### 1.4 プラットフォーム層

- **`src/platform`（13M、28 サブディレクトリ）** — OS/SoC 抽象。詳細 §5.1。

### 1.5 依存方向まとめ

```
app / credentials
      │（DataModel::Provider / FabricTable / attestation）
      ▼
protocols（secure_channel, interaction_model 定数, bdx …）
      │
      ▼
messaging（ExchangeManager, MRP）
      │
      ▼
transport（SessionManager, SecureSession, 暗号化）
      │
      ▼
inet（UDP/TCP EndPoint）
      │
      ▼
system（PacketBuffer, Layer/timer） ← lib/core, lib/support は全層が横断利用
      │
platform（PlatformManager, ConnectivityManager …）← system/inet の実装を供給
crypto ← transport/credentials/secure_channel が CHIPCryptoPAL 経由で利用
```

---

## 2. トランスポート→メッセージ→エクスチェンジ→セキュアチャネル のコード対応

### 2.1 受信パケットのデータフロー（暗号文 → 平文 → アプリ）

```
ネットワーク（socket / LwIP / OpenThread）
 → src/inet          UDPEndPoint::Listen コールバック（OnMessageReceivedFunct）
 → src/transport/raw Transport::UDP → Transport::Base → RawTransportDelegate::HandleMessageReceived
 → src/transport     TransportMgrBase → TransportMgrDelegate::OnMessageReceived
 → src/transport     SessionManager::OnMessageReceived   ← PacketHeader 解析 + セッション選択 + 復号
 → src/transport     SessionMessageDelegate::OnMessageReceived
 → src/messaging     ExchangeManager::OnMessageReceived  ← Exchange 照合/生成 + MRP ack
 → src/messaging     ExchangeContext::HandleMessage → ExchangeDelegate::OnMessageReceived（アプリ）
```

境界インタフェース（新実装でも踏襲すべき「継ぎ目」）:

| 境界 | インタフェース（ファイル） | 生産者 → 消費者 |
|---|---|---|
| inet→raw | `OnMessageReceivedFunct`（`inet/UDPEndPoint.h`） | UDPEndPoint → Transport::UDP |
| raw→mgr | `Transport::RawTransportDelegate`（`transport/raw/Base.h`） | Transport::Base → TransportMgrBase |
| mgr→session | `TransportMgrDelegate::OnMessageReceived`（`transport/TransportMgr.h`） | TransportMgrBase → SessionManager |
| session→messaging | `SessionMessageDelegate::OnMessageReceived`（`transport/SessionMessageDelegate.h`） | SessionManager → ExchangeManager |
| messaging→アプリ | `ExchangeDelegate::OnMessageReceived`（`messaging/ExchangeDelegate.h`） | ExchangeContext → プロトコルハンドラ |

**暗号化/復号は SessionManager 一箇所**（`transport/SecureMessageCodec.{h,cpp}` の `Encrypt`/`Decrypt`、鍵は `transport/CryptoContext`）。この線より下（inet, raw）は常に暗号文 + `PacketHeader`、上（messaging, app）は常に平文 + `PayloadHeader`。ヘッダ構造は `transport/raw/MessageHeader.h`: `PacketHeader`（非暗号 = session id / counter / node id）、`PayloadHeader`（暗号内 = protocol id / message type / exchange id / ack）、`MessageAuthenticationCode`。

### 2.2 セッションモデル

`Transport::Session`（`transport/Session.h`）を基底に `enum SessionType { kUnauthenticated, kSecure, kGroupIncoming, kGroupOutgoing }`。

- `UnauthenticatedSession`（`UnauthenticatedSessionTable.h`）— PASE/CASE ハンドシェイク第 1 メッセージ用（暗号なし）。
- **`SecureSession`（`SecureSession.h`）— PASE も CASE も同一クラス**、`enum Type { kPASE, kCASE }` で区別。`GetCryptoContext()` が `SecureMessageCodec` の鍵を返す。プール = `SecureSessionTable`（LRU eviction）。
- `IncomingGroupSession` / `OutgoingGroupSession` — マルチキャスト。
- リプレイ保護: `PeerMessageCounter`（スライディングウィンドウ）、`GroupPeerMessageCounter`。

`SessionManager::OnMessageReceived` はセッション種別で 3 分岐: `UnauthenticatedMessageDispatch`（復号なし）/ `SecureUnicastMessageDispatch`（`SecureMessageCodec::Decrypt` → counter チェック）/ `SecureGroupMessageDispatch`（`PrivacyDecrypt` + group 鍵試行）。

### 2.3 Exchange 層と MRP

- `ExchangeManager`（`messaging/ExchangeMgr.h`、`SessionMessageDelegate` を実装）= SessionManager から呼ばれる `mCB`。既存 `ExchangeContext` に照合、または未応答メッセージなら登録済ハンドラを探して新規 Exchange を生成。
  - プロトコルディスパッチ = `RegisterUnsolicitedMessageHandlerForProtocol/Type`。スロットは `UMHandlerPool[CHIP_CONFIG_MAX_UNSOLICITED_MESSAGE_HANDLERS]`。
- `ExchangeContext`（`messaging/ExchangeContext.h`）= 二ノード間の 1 会話。**`ReliableMessageContext` を継承**するので全 Exchange が MRP 状態を持つ。`SendMessage(Protocols::Id, msgType, buf, SendFlags)` / `HandleMessage(...)`。
- `ExchangeMessageDispatch` の派生でプロトコルごとの送受信ポリシー（暗号必須か等）: `ApplicationExchangeDispatch`（IM トラフィック、暗号必須）、`EphemeralExchangeDispatch`（standalone-ack）。secure channel 用の非暗号ディスパッチは `protocols/secure_channel/SessionEstablishmentExchangeDispatch` にある。
- **MRP（Message Reliability Protocol）は `src/messaging` に集約**:
  - `ReliableMessageMgr`（再送テーブル `ObjectPool<RetransTableEntry, CHIP_CONFIG_RMP_RETRANS_TABLE_SIZE>`、指数バックオフ、`System::Layer` でタイマ駆動）。再送は送信時に確保した `EncryptedPacketBufferHandle` を再利用。
  - `ReliableMessageContext`（Exchange 毎の ack 状態、piggyback ack、`SendStandaloneAckMessage`）。
  - `ReliableMessageProtocolConfig`（idle/active リトライ間隔 = SII/SAI/SAT としてアドバタイズ）。

### 2.4 セキュアチャネル（PASE / CASE）

メッセージ種別は 1 つの enum `Protocols::SecureChannel::MsgType`（`protocols/secure_channel/Constants.h`）:
- PASE: `PBKDFParamRequest 0x20` / `Response 0x21` / `PASE_Pake1 0x22` / `Pake2 0x23` / `Pake3 0x24`
- CASE: `CASE_Sigma1 0x30` / `Sigma2 0x31` / `Sigma3 0x32` / `Sigma2Resume 0x33`
- `StatusReport 0x40`、`ICD_CheckIn 0x50`、`StandaloneAck 0x10`

共通基底 `PairingSession`（`SessionDelegate` を継承、`DeriveSecureSession()` 等の virtual）を PASE/CASE 双方が継承。

- **PASE**: `PASESession`（`.h` 10KB / `.cpp` 41KB）。`UnsolicitedMessageHandler + ExchangeDelegate + PairingSession`。暗号エンジンは member `Spake2p_P256_SHA256_HKDF_HMAC`（PSA 版あり）。`WaitForPairing(...)`（アクセサリ側）/ `Pair(...)`（コミッショナ側）。ハンドシェイクメソッドが 5 メッセージに 1:1 対応。
- **CASE**: `CASESession`（`.h` 28.8KB / **`.cpp` 122.8KB = レイヤ最大**）。`... + FabricTable::Delegate`。Sigma プロトコルを豊富な struct（`ParsedSigma1/2/3`）+ 数値 `State` + `enum class Step`（`Variant<Step, CHIP_ERROR>`）でモデル化。運用証明書（NOC/ICAC/RCAC）、`P256ECDSASignature`、`CASEDestinationId`、セッション resumption を使う。
- `CASEServer`（常時応答側、`CASESession mPairingSession` を保有、`CASE_Sigma1` を受けて `InitCASEHandshake`）。
- 注: **CASE のクライアント側ドライバ**（`CASEClient` / `CASESessionManager`）は `src/app` にある（protocols ではない）。

### 2.5 Interaction Model（protocols と app の分離）

`protocols/interaction_model` は薄い（5 ファイル）= **wire 定数のみ**:
- `Constants.h`: `MsgType { StatusResponse 0x01, ReadRequest 0x02, SubscribeRequest 0x03, SubscribeResponse 0x04, ReportData 0x05, WriteRequest 0x06, WriteResponse 0x07, InvokeCommandRequest 0x08, InvokeCommandResponse 0x09, TimedRequest 0x0a }`。
- `StatusCode.{h,cpp}`（`Status` enum）。

**エンジン本体は `src/app`**（§3）。この「プロトコル語彙（protocols/） vs エンジン実装（app/）」の分離は正しい設計。

---

## 3. Interaction Model エンジン（src/app トップレベル）

`src/app` 直下に IM の状態機械が巨大なフラットクラス群として並ぶ。Read/Subscribe/Write/Invoke/Timed の各インタラクションが対象。

- **中枢**: `InteractionModelEngine`（`.h` 36KB / **`.cpp` 97KB = ここ最大**）。シングルトン。`UnsolicitedMessageHandler` として `Protocols::InteractionModel::Id` を登録し全 IM メッセージをディスパッチ。ハンドラプールとサブスクリプションを保有。
- **サーバ側（デバイス）**: `ReadHandler`、`WriteHandler`、`CommandHandler`（IF）+ `CommandHandlerImpl`（`.cpp` 45KB）、`TimedHandler`、`CommandResponseSender`。クラスタが実装するフック = `CommandHandlerInterface`、`AttributeAccessInterface`（+ 各 `...Registry`）。
- **クライアント側（コントローラ）**: `ReadClient`（`.cpp` 57KB）、`WriteClient`、`CommandSender`（`.cpp` 28KB）、`ClusterStateCache`（31KB）。
- **パス処理**: `AttributePathExpandIterator`（ワイルドカードのデータモデル展開 = Read/Subscribe fan-out の核）、`AttributeValueEncoder/Decoder`、`ConcreteAttributePath` / `ConcreteCommandPath` 等。
- **イベント**: `EventManagement`（`.cpp` 38KB、循環イベントログ）、`EventLogging`。
- **レポートエンジン**: `src/app/reporting/Engine`（`EventReporter + DataModel::AttributeChangeListener`）。サブスクリプション用のレポート生成。`ReportScheduler` / `SynchronizedReportSchedulerImpl`（min/max interval）。
- **IM メッセージの TLV スキーマ**: `src/app/MessageDef`（**95 ファイル**）= `ReadRequestMessage` / `ReportDataMessage` / `AttributeDataIB` / `CommandDataIB` / `EventReportIB` / `StatusIB` 等のビルダ/パーサ。§2.5 の MsgType が実際に符号化される場所。
- **サーバ基盤**: `src/app/server`（`CommissioningWindowManager`、`AclStorage`、`DefaultTermsAndConditionsProvider` 等）。

---

## 4. データモデル / クラスタ実装方式（肥大化の中心）

ここが SDK 肥大化の最大要因かつ、最も設計判断が必要な部分。**現在「Ember（旧）」から「code-driven（新）」への移行途上**で、両方式の機構が同居している。

### 4.1 Ember 互換レイヤ（旧、Zigbee 由来）

`src/app/util`（360K、22 ヘッダ）が Ember ランタイム。ZAP が生成する**フラットなバイトテーブル**に属性を格納し、**生成された switch 文**でコマンドをディスパッチする。

- `af-types.h`（`EmberAfCluster` / `EmberAfAttributeMetadata` / `EmberAfEndpointType`。※この checkout に `af.h` は無い）。
- `attribute-storage.{h,cpp}`（ZAP 生成の `endpoint_config.h` から構築する RAM/flash 属性ストア）。
- `attribute-table.{h,cpp}`（パス指定の read/write）、`ember-io-storage.{h,cpp}`（TLV ↔ Ember 生バイト配置のマーシャル）、`IMClusterCommandHandler.h`。
- ZAP プラグイン方法: ZAP が cluster XML + アプリ毎 `.zap` から `zap-generated/endpoint_config.h`（具体的な endpoint/cluster/attribute メタデータテーブル）と `IMClusterCommandHandler` ディスパッチを生成。`attribute-storage.cpp` が init 時にそれを読んでメモリモデルを作り、コマンドは生成 switch 経由で `<name>-server.cpp` のコールバックへ。

### 4.2 抽象インタフェース `DataModel::Provider`（新契約）

IM エンジンは Ember を直接叩かず、`src/app/data-model-provider`（184K）の抽象を叩く。

- `Provider.h/.cpp`（`DataModel::Provider` 抽象基底: `ReadAttribute` / `WriteAttribute` / `InvokeCommand` + メタデータ列挙）。
- `ProviderMetadataTree` / `MetadataTypes.h` / `ClusterMetadataProvider.h`（endpoint/cluster/attribute/command 列挙）。
- `ActionReturnStatus` / `OperationTypes.h` / `AttributeChangeListener.h` / `EventsGenerator`。

この抽象化で `InteractionModelEngine` が `DataModel::Provider` にのみ依存するようになり、新旧両方式が共存可能に（= ツリーが重複機構を抱える大きな理由）。

### 4.3 Provider の具象実装（`src/data-model-providers`、476K）

- **`codegen/`** — `CodegenDataModelProvider`（`.cpp` 551 行 + `_Read` 147 + `_Write` 195）。**旧 Ember ストアを新 Provider インタフェースの裏にラップ**するブリッジ。ZAP 生成メタデータ + `attribute-storage` を `DataModel::Provider` に適合。`EmberAttributeDataBuffer`、`ClusterIntegration`。既存 Ember クラスタが新エンジン下でそのまま動く仕組み。
- **`codedriven/`** — `CodeDrivenDataModelProvider`。ZAP メタデータ不要、クラスタがオブジェクトとして自己登録する完全新方式。`codedriven/endpoint/`（`EndpointInterface`、`SpanEndpoint` = プログラム的に endpoint 組み立て）。

### 4.4 新クラスタ基底 `src/app/server-cluster`（296K）= 移行のゴール

- `ServerClusterInterface`（`.h`）/ `DefaultServerCluster.{h,cpp}` — クラスタはこれを実装。`ReadAttribute` / `WriteAttribute` / `InvokeCommand` + `Attributes()` / `AcceptedCommands()`。
- 登録: `ServerClusterInterfaceRegistry` / `SingleEndpointServerClusterRegistry`。
- `ServerClusterContext.h`（`interactionContext->dataModelChangeListener->MarkDirty(path)` でサブスクリプション通知）、`OptionalAttributeSet.h`、`AttributeListBuilder`。
- 永続化: `src/app/persistence/AttributePersistence`（スカラ属性の load/store）。

`docs/guides/writing_clusters.md`・`migrating_ember_cluster_to_code_driven.md` が明示する設計指針（新実装に直接効く）:
- **combined 実装を推奨**、logic/translation を分離する modular（`ClusterLogic` + `ClusterImplementation`）は**フラッシュ/RAM オーバヘッドが大きく非推奨**。virtual の翻訳層を減らせと明言。
- feature map + `BitFlags` で optional 要素を制御。**フラッシュ/RAM 最適化には C++ テンプレートで feature/attribute をコンパイル時選択**せよ、と公式が推奨。
- builder 風 `Config`（`LevelControlCluster` が参照実装）で feature とその必須属性の整合を型で強制。
- no-op write は通知もデリゲートコールバックも起こすな（`NotifyAttributeChangedIfSuccess` + `kWriteSuccessNoOp`）。
- getter は値返し（ポインタ/参照返しは lifetime リスク）。

### 4.5 クラスタ実装の規模

- `src/app/clusters` = **120 ディレクトリ、11M（src/app の約 42%）**。
  - 110 が旧 `*-server/` 命名（`door-lock-server` 308K・`.cpp` 4,491 行、`thermostat-server` 192K、`color-control-server` 180K 等）。
  - 10 が新スタイル（`basic-information` / `level-control` / `descriptor` / `network-commissioning` / `ota-provider` / `ota-requestor` / `bindings` 等）。
  - 旧クラスタ 1 個の典型構成 = `BUILD.gn` + `app_config_dependent_sources.gni/.cmake` + `<name>-server.cpp` + `<name>-server.h` + `<name>-delegate.h` + コールバック `.cpp`。
- cluster XML: `src/app/zap-templates/zcl/data-model/chip/*.xml` = **155 ファイル、1.7M**。ZAP と codegen.py の入力（真実源）。

### 4.6 コード生成の 2 系統（ZAP と matter-idl）

`docs/zap_and_codegen/code_generation.md` より:
- 入力は `.zap`（大きな JSON、Zigbee 後方互換の汎用データ含む、SQLite 由来で非決定性の歴史）と、その人間可読等価物 `.matter`（IDL 風、Matter 特化）。
- 2 経路が実験的に併存: (1) `zap-cli`（npm 大量依存、遅い）、(2) `scripts/codegen.py` + `scripts/py_matter_idl`（依存少・高速・クラスタ単位で複数ファイル出力可・型付き・決定的）。将来は単一化したいが未達。
- 生成物: サーバ側処理（どのコールバックを立てるか、属性ストレージ用の RAM 予約）、TLV 直列化（struct/list/command）、controller/tools/tests/java/python 用の client 側。
- **`zzz_generated/`（この sparse checkout では空、ビルド時生成）** = `app-common/zap-generated/cluster/*` に `Clusters.h` / `Ids.h` / `Attributes.h` をクラスタ毎に大量生成、通常数 MB。`src/app` 配下 **78 個の BUILD.gn が zzz_generated を参照**。
- さらに Darwin 向けに**完全に別系統の Objective-C 生成コード**（`src/darwin/Framework/CHIP/zap-generated/`: `MTRBaseClusters.h` 32,339 行、`CHIPAttributeTLVValueDecoder.cpp` 62,453 行 等）。

---

## 5. プラットフォーム抽象 / 暗号抽象

### 5.1 `src/platform`（13M）+ `src/include/platform`

「マネージャ・シングルトン + delegate + Generic テンプレート」設計。

- 抽象 API は `src/include/platform`（27 エントリ）: `PlatformManager`（イベントループ/タスク/`LockChipStack`/`PostEvent`）、`ConnectivityManager`、`ConfigurationManager`、`KeyValueStoreManager`、`ThreadStackManager`、`DiagnosticDataProvider`、`CommissionableDataProvider`、`DeviceInstanceInfoProvider` 等。各 IF が `Impl()` アクセサ + グローバルシングルトンを宣言。
- **`CHIPDeviceConfig.h` = 1,747 行**のコンパイル時設定（VID/PID デフォルト、バッファサイズ、タイムアウト、feature フラグ）。
- Generic テンプレート: `src/include/platform/internal`（36 エントリ、CRTP）。`.h`（宣言）+ `.ipp`（テンプレート定義）。OS 特化 `GenericPlatformManagerImpl_POSIX/_FreeRTOS/_CMSISOS/_Zephyr`。feature スライス `GenericConnectivityManagerImpl_BLE/_NoBLE/_WiFi/_NoWiFi/_Thread/_NoThread/_TCP/_UDP` を組み合わせて対応トランスポートを合成。
- **28 サブディレクトリ ≈ 24 の実 OS/SoC バックエンド**（nxp 1.4M, silabs 1.1M, Linux 932K, ti 900K, Infineon 808K, ESP32 768K, Darwin 580K, Zephyr, nrfconnect, Ameba, ASR, Beken, bouffalolab, cc32xx, mt793x, NuttX, qpg, realtek, stm32, telink, Tizen, webos, android + `fake`）+ 4 共通（`FreeRTOS`, `OpenThread`, `logging`, `tests`）。各バックエンドは統一命名の `PlatformManagerImpl` / `ConnectivityManagerImpl` / `ConfigurationManagerImpl` / `KeyValueStoreManagerImpl`。

### 5.2 `src/crypto`（1.4M）

単一抽象ヘッダ + ビルド時選択の複数バックエンド。

- 抽象: **`CHIPCryptoPAL.h` = 2,176 行**。`P256PublicKey` / `P256Keypair`（ECDSA/ECDH）、`AES_CCM_encrypt/decrypt`、`Hash_SHA256`（+ streaming）、`HKDF_sha`、`DRBG_get_bytes`、PBKDF2、HMAC、SPAKE2+（`Spake2p` 抽象 + `Spake2p_P256_SHA256_HKDF_HMAC` + `Spake2pVerifier`）。
- バックエンド: OpenSSL（`CHIPCryptoPALOpenSSL`、BoringSSL も API 互換で兼用）、mbedTLS（`CHIPCryptoPALmbedTLS` + `...Cert`）、**PSA**（`CHIPCryptoPALPSA` + `PSASpake2p` + `PSAOperationalKeystore` + `PSASessionKeystore`）、Trusty（TEE）、NXP ELE（secure element）。`crypto.gni` で選択。
- 鍵ストア抽象: `OperationalKeystore`（fabric 運用鍵）、`SessionKeystore` / `RawKeySessionKeystore`（対称セッション鍵ハンドル）。

---

## 6. フットプリントが大きくなる構造的要因

docs 上に単独の footprint 資料は無い（`docs/product_considerations` は lwip_ipv6 のみ）が、`writing_clusters.md`・`migrating_ember_cluster_to_code_driven.md` がフラッシュ/RAM 最適化を随所で論じており、SDK 自身が肥大化を課題認識していることが読み取れる。構造的要因を大きい順に:

1. **クラスタ実装の物量（最大要因）** — `src/app/clusters` に 120 ディレクトリ・11M。各クラスタが独立した server `.cpp`・delegate・build ファイル群を持つ。仕様の全クラスタ網羅を目指すため線形に膨張。加えて cluster XML 155 個 × ZAP テンプレートが `zzz_generated`（通常数 MB）を生成。

2. **データモデル機構の多重化（移行途上の同居）** — 旧 Ember（`app/util`）+ 抽象 `data-model-provider` + 具象 2 種（`codegen`=Ember ラップ / `codedriven`）+ 新基底 `server-cluster`。同じ「属性を読み書きする」ために 3〜4 層の機構が併存。`CodegenDataModelProvider` は互換性のためだけに存在する橋。

3. **コード生成の量と二重化** — ZAP と matter-idl の 2 系統併存（公式も統一未達と明記）。生成物は server 処理・TLV 直列化・client/tools/tests/java/python を網羅。さらに Darwin 向け Objective-C 生成が完全別系統（1 ファイルで 6 万行超）。この checkout に見えない `zzz_generated` がビルド時に大量展開される。

4. **client（コントローラ）と server（デバイス）を同一ツリーに同居** — `src/controller` 33M、`app` に `ReadClient`（57KB）/ `CommandSender` / `ClusterStateCache` 等のクライアント側状態機械がサーバ側と並存。デバイス専用実装には本来不要な半分。IM エンジンだけで `InteractionModelEngine.cpp` 97KB。

5. **全プラットフォーム・全バックエンドの同梱と重い抽象** — `src/platform` 13M に約 24 の OS/SoC バックエンド。CRTP Generic テンプレート（`.h`+`.ipp`、feature スライス多数）、マネージャ・シングルトン + delegate の多層 virtual。crypto も 5 バックエンド、dnssd は独自 `minimal_mdns` 同梱。`CHIPConfig.h` 2,108 行 / `CHIPDeviceConfig.h` 1,747 行 / `CHIPCryptoPAL.h` 2,176 行という巨大な設定・抽象ヘッダ。

補足要因: (a) BDX/Echo/UDC/ICD/group/session-resumption 等の完全実装、(b) modular クラスタパターンの virtual 翻訳層（公式が非推奨と認める）、(c) `#ifdef` によるビルド時分岐の多用（同 doc が非推奨と明記）。

---

## 7. 新実装への示唆（肥大化回避策 + 踏襲すべき構造）

### 7.1 踏襲すべき正しいレイヤ分割・概念（Matter 仕様 ↔ コード対応）

以下は仕様に根ざした「正しい継ぎ目」で、小型実装でも維持すべき。Rust ではこれらを trait 境界 + module 境界にマップするとよい。

- **暗号境界を 1 点に**: 平文（Exchange 以上）と暗号文（transport 以下）を `SecureMessageCodec` 相当の 1 モジュールで分ける。`PacketHeader`（非暗号）/ `PayloadHeader`（暗号内）の分離もそのまま。
- **セッション抽象**: `Unauthenticated` / `Secure(PASE|CASE)` / `Group` の 4 種を 1 つの enum で。PASE と CASE を同一 `SecureSession` 型 + `Type` 判別にする設計は簡潔で有効。
- **Exchange = 会話単位** + **MRP を Exchange に内包**（`ReliableMessageContext` を `ExchangeContext` の基底にする発想）。MRP config（SII/SAI/SAT）と指数バックオフを 1 モジュールに。
- **プロトコル語彙とエンジンの分離**: `protocols/interaction_model`（MsgType・Status 定数のみ）と `app`（エンジン）を分けた設計は正しい。Rust でも「wire 定数 crate」と「IM エンジン crate」を分離。
- **セキュアチャネルのメッセージ ↔ ハンドラ 1:1**: PASE の 5 メッセージ、CASE の Sigma1/2/3(+Resume) をハンドシェイクメソッドに素直に対応させる。状態は `Optional<MsgType> mNextExpectedMsg` / `enum State` で明示。
- **データモデルの `Provider` 抽象**: IM エンジンを `DataModel::Provider`（`ReadAttribute`/`WriteAttribute`/`InvokeCommand` + メタデータ列挙）にのみ依存させる。これは新実装でも中核 trait にすべき（ただし具象は 1 つで良い、下記）。
- **クラスタ = 自己記述オブジェクト（code-driven）**: `ServerClusterInterface` / `DefaultServerCluster` の思想（各クラスタが自分のメタデータと storage を所有）を採用。Rust の trait + 構造体に自然にマップ。
- **命名・概念語彙をそのまま借用**: Endpoint / Cluster / Attribute / Command / Event / ConcretePath / feature map / FabricTable / NOC・ICAC・RCAC / DAC・PAI・CD・PAA / AttributePathExpandIterator（ワイルドカード展開）/ commissionable vs operational discovery。仕様準拠の証跡になる。
- **基盤の型**: `Span`（Rust なら `&[u8]`/`&mut [u8]` で自然）、`BitFlags`、`ObjectPool`（no_std では固定長プール = heapless）、TLV codec、`CHIP_ERROR` 相当の統一エラー（Rust では `Result` + enum）。TLV は自前実装必須（証明書・IM ペイロード両方で使う）。

### 7.2 肥大化要因の回避策

1. **デバイス（server）側に限定** — controller / client 側の状態機械（`ReadClient` / `CommandSender` / `ClusterStateCache`）を作らない。IM は Read/Subscribe/Write/Invoke/Timed の**ハンドラ側のみ**。これだけで `src/app` の半分を落とせる。

2. **データモデルは code-driven 一本化** — Ember 互換レイヤ・ZAP メタデータテーブル・`CodegenDataModelProvider` ブリッジは作らない。`DataModel::Provider` 抽象 + 具象 1 つ（code-driven）のみ。移行途上の重複機構をそもそも持ち込まない。

3. **コード生成を最小化 or ビルド時 Rust マクロ/build.rs に** — 巨大 `zzz_generated` 相当を避け、クラスタ定義は Rust の型（derive マクロ / 手書き）で。ZAP・`.zap` の Zigbee 由来汎用データや SQLite 非決定性を排除。必要なら matter-idl（`.matter`）を入力にした軽量 codegen のみ採用。

4. **クラスタは必要な最小セットだけ** — 120 個ではなく対象デバイスタイプの必須クラスタ（例: On/Off, Level Control, Basic Information, Descriptor, Identify, Network Commissioning, General Commissioning, Operational Credentials 等）に限定。**combined 実装**（logic/translation 分離なし、virtual 翻訳層なし）を採用。feature の有無は Rust の型パラメータ / feature フラグでコンパイル時選択。

5. **抽象は薄く、バックエンドは 1 つ** — platform 抽象は必要なマネージャ（event loop, KVS, connectivity）だけを最小 trait で。CRTP 多層 Generic 相当は不要。crypto も 1 バックエンド（例: PSA / RustCrypto / mbedTLS）に固定。dnssd は既存の `no_std` mDNS crate を活用し `minimal_mdns` 相当の自前実装は避ける。巨大設定ヘッダ（2,000 行級）に相当するものは、Cargo feature + `const` で最小限に。

6. **オプショナル機能を初期スコープから外す** — BDX/OTA、group messaging、session resumption、ICD、UDC は初期実装から分離し、feature gate 化。まず「BLE/IP コミッショニング + PASE/CASE + IM(Read/Write/Invoke/Subscribe) + 数クラスタ」の最小縦通しを通す。

### 7.3 推奨する最小レイヤ構成（Rust / no_std）

```
system   : パケットバッファ(heapless), タイマ/イベントループ抽象, Clock
codec/tlv: TLV Reader/Writer, Span, BitFlags, 統一エラー
inet     : UDP エンドポイント抽象（smoltcp / OS socket / OpenThread）
transport: SessionManager, SecureSession(PASE|CASE|Group), SecureMessageCodec, counter
messaging: ExchangeManager, ExchangeContext(+MRP), Dispatch
protocols: secure_channel(PASE/CASE), im 定数
crypto   : CryptoProvider trait（Spake2p, P256, HKDF, AES-CCM, SHA256）+ 1 backend
credentials: FabricTable, OperationalCredentials, DeviceAttestation(DAC/PAI/CD)
app      : InteractionModel エンジン（server ハンドラのみ）, DataModel::Provider trait
clusters : 対象デバイスタイプの必須クラスタのみ（自己記述オブジェクト）
platform : PlatformManager/KVS/Connectivity 最小 trait + 単一バックエンド
discovery: commissionable/operational mDNS（既存 crate 活用）
```

connectedhomeip の**レイヤ境界と概念語彙は「正しい参照」**として全面的に借用し、**各層の幅（機能網羅・抽象多重化・コード生成・両サイド同居）を削る**のが小型化の本質、というのが本調査の結論。
