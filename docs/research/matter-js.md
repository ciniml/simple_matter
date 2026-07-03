# matter.js コード構造調査レポート

調査対象: `/home/kenta/repos/simple_matter/research/matter.js`（TypeScript による Matter プロトコルスタック実装、project-chip/matter.js）

目的: 小フットプリント・no_std 前提の Rust 製 Matter コントローラ/デバイス実装を新規設計するにあたり、matter.js のレイヤ分割・責務分割・インターフェース設計を参考にする。API の逐語的な模倣ではなく、アーキテクチャ上の考え方の抽出に主眼を置く。

---

## 1. パッケージ構成

`packages/` はモノレポ（npm workspaces）構成で、依存方向はほぼ一直線の DAG になっている。各 `package.json` の `dependencies` から確認した実際の依存関係は次の通り。

```
@matter/general        (依存なし。crypto/@noble/curves のみ)
   ↑
@matter/model           depends: general
   ↑
@matter/types            depends: general, model
   ↑
@matter/protocol          depends: general, model, types
   ↑
@matter/node                depends: general, model, types, protocol
   ↑
@matter/nodejs / @matter/nodejs-ble / @matter/nodejs-shell / @matter/nodejs-ws
                              depends: general, node, protocol, types (Node.js固有実装)
   ↑
@matter/main / @project-chip/matter.js   (統合・再エクスポート層)
   ↑
@matter/cli-tool, packages/create        (アプリケーション/ツール)
```

- **general**: プラットフォーム非依存の基盤層。ネットワーク・ストレージ・暗号・時刻・ログ・Observable・Environment DI コンテナなど、Matter 固有仕様を知らない「OS 抽象化 + ユーティリティ」層。依存先はゼロ（暗号ライブラリ `@noble/curves` のみ外部依存）。
- **model**: Matter 仕様（クラスタ・デバイスタイプ・データ型・命名空間など）をデータとして表現する「宣言的スキーマ」層。general にのみ依存し、プロトコル実装やネットワークを一切知らない。
- **types**: model を使って実際に TypeScript の型・ランタイム値（TLV型、ClusterType、コマンド/属性のスキーマ）を組み立てる層。matter.js 独自のワイヤフォーマット（TLV）や共通データ型 (`NodeId`, `FabricIndex` 等) もここ。
- **protocol**: メッセージ層・セッション層・セキュアチャネル(PASE/CASE)・インタラクションモデル(Read/Write/Invoke/Subscribe)・mDNS/BLE アドバタイズ・コミッショニング(Commissioner側)・Fabric管理など、Matter の「プロトコルスタック本体」。ネットワークの実バインディングは general の Transport/Network インターフェース越しに使うのみで、Node.js 固有実装には依存しない。
- **node**: エンドポイント／ビヘイビア（Behavior）／デバイスタイプ実装など「サーバーサイドのアプリケーションモデル」を提供する上位層。属性の状態管理、バリデーション、永続化(StorageContext経由)を含む。ここが実質的な「アクセサリ側フレームワーク」。
- **nodejs / nodejs-ble / nodejs-shell / nodejs-ws**: Node.js ランタイム固有のプラットフォーム実装（UDPソケット、ファイルストレージ、Node crypto、BLE(noble/bleno)、WebSocket）。`general`/`node`/`protocol` が定義するインターフェースの「差し替え可能な実装」を提供するだけで、プロトコルロジックは持たない。
- **main / matter.js**: 上位すべてを束ねて公開 API として再エクスポートするファサードパッケージ（`matter.js` は旧パッケージ名を保った後方互換レイヤ）。
- **testing**: テスト用のモック実装（MockCrypto, MockNetwork, MockStorageService等）を各層に提供するテスト専用パッケージ。
- **cli-tool / create / react-native / mqtt**: 応用ツール・別ランタイム向けバインディング。

依存方向は一方向で循環は見当たらない。**「general(OS抽象) → model(仕様データ) → types(型・TLV) → protocol(プロトコル本体) → node(アプリケーションフレームワーク) → nodejs*(プラットフォーム実装)」という層構造**であり、下位層は上位層のクラスを一切 import しない。特に protocol パッケージは Node.js 固有 API を直接使わず、general が提供する `Network`/`Transport`/`Crypto`/`StorageService` などのインターフェース越しにのみ動作する点が重要（後述 4章）。

---

## 2. プロトコルスタックのレイヤリング

`packages/protocol/src` の主要ディレクトリと責務:

| ディレクトリ | 責務 |
|---|---|
| `codec/` | `MessageCodec.ts`（Matterメッセージヘッダ/ペイロードのバイナリエンコード/デコード）、`BtpCodec.ts`（BLE Transport Protocol）、`MessagePrivacy.ts` |
| `transport/` | UDP/TCP など下位トランスポートの束ね（`TransportSet`は general 側にある） |
| `protocol/` | `MessageExchange.ts`, `ExchangeManager.ts`, `ExchangeProvider.ts`, `MessageChannel.ts`, `MRP.ts`（Message Reliability Protocol）, `ProtocolHandler.ts`, `DeviceCommissioner.ts`, `DeviceAdvertiser.ts` |
| `session/` | `Session.ts`, `SecureSession.ts`, `UnsecuredSession.ts`, `GroupSession.ts`, `NodeSession.ts`, `SessionManager.ts`, `session/pase/*`, `session/case/*` |
| `securechannel/` | `SecureChannelProtocol.ts`, `SecureChannelMessenger.ts` (PASE/CASE のセッション確立を仲介する ProtocolHandler 実装) |
| `interaction/` | `InteractionMessenger.ts`, `Subscription.ts`, `AttributeDataEncoder/Decoder.ts`, `EventDataDecoder.ts`, `FabricAccessControl.ts` |
| `peer/` | コントローラ側の「相手ノード」管理（`Peer.ts`, `PeerSet.ts`, `PeerAddress.ts`, `ControllerCommissioner.ts`, `ControllerCommissioningFlow.ts`, `CommissioningConnection*.ts`） |
| `fabric/`, `certificate/` | Fabric（信頼ドメイン）と証明書(NOC/RCAC)管理 |
| `mdns/` | `MdnsServer.ts`, `CommissionableMdnsScanner.ts` によるサービスディスカバリ |
| `advertisement/` | コミッショニング用アドバタイズ（`CommissioningMode.ts` 等） |
| `ble/`, `bdx/`, `ota/`, `groups/`, `dcl/` | BLE転送、Bulk Data Exchange、OTA、Group通信、DCL連携 |

### レイヤ間の呼び出し関係

1. **トランスポート層**: general の `Transport` インターフェース（`packages/general/src/net/Transport.ts`）を実装したもの（UDP/BLE/WebSocket）を `TransportSet` として `ExchangeManager` に注入する。
2. **メッセージ/エクスチェンジ層**: `ExchangeManager`（`protocol/src/protocol/ExchangeManager.ts`）がトランスポートから受信した生バイト列を `MessageCodec` でデコードし、`SessionManager` からセッションを解決した上で `MessageExchange`（`protocol/src/protocol/MessageExchange.ts`）を生成・管理する。MRP（再送・確認応答）のロジックは `MessageExchange` と `MRP.ts` に閉じている。
3. **プロトコルディスパッチ**: `ExchangeManager` は protocol ID ごとに `ProtocolHandler` インターフェース実装（`protocol/src/protocol/ProtocolHandler.ts`）を登録し、新規 exchange の最初のメッセージの protocol ID でディスパッチする:

   ```ts
   export interface ProtocolHandler {
       readonly id: number;
       readonly requiresSecureSession: boolean | undefined;
       onNewExchange(exchange: MessageExchange, message: Message): Promise<void>;
       close(): Promise<void>;
   }
   ```
   セキュアチャネル(PASE/CASE)もインタラクションモデルも、この同じインターフェースを実装した別々の `ProtocolHandler`（`SecureChannelProtocol`, インタラクションモデルの handler）として登録される。この設計により、**新しいプロトコル（BDX等）を追加してもExchangeManagerを変更しなくてよい**プラガブルな構造になっている。
4. **セッション/セキュアチャネル層**: `Session`（抽象基底）→ `SecureSession`（抽象、fabric・peerAddress・アクセス制御 subject を持つ）→ `NodeSession`（CASE確立後のノード間セッション）/ `UnsecuredSession`（PASE確立前の平文セッション）/ `GroupSession`（マルチキャスト）という継承構造。`SecureSession.ts`:
   ```ts
   export abstract class SecureSession extends Session {
       readonly isSecure = true;
       abstract fabric: Fabric | undefined;
       abstract peerAddress: PeerAddress;
       abstract subjectFor(message?: Message): Subject;
   }
   ```
   PASE/CASEの鍵確立プロトコル自体は `session/pase/{PaseClient,PaseServer,PaseMessenger,PaseMessages}.ts`、`session/case/{CaseClient,CaseServer,CaseMessenger,CaseMessages}.ts` に分離されており、確立後に `SessionManager` へ `NodeSession` を登録する。
5. **インタラクションモデル層**: `interaction/InteractionMessenger.ts` が Read/Write/Invoke/Subscribe の各インタラクションのメッセージ整形・分割（chunking）を担当し、`interaction/Subscription.ts` がサブスクリプションのライフサイクル（`subscriptionId`, `handlePeerCancel`, `close`）を、`AttributeDataEncoder/Decoder.ts` が属性値とTLVの相互変換を担う。ここは `SecureSession` を要求する `ProtocolHandler` として `ExchangeManager` に登録される。
6. **データモデル層**（endpoint/cluster/attribute）は protocol パッケージには存在せず、**上位の `node` パッケージ**が担当する。protocol 層はクラスタの「意味」（値の妥当性やビジネスロジック）を知らず、TLVでエンコードされた生データと ClusterId/AttributeId のみを扱う。node 層の `Behavior`/`ClusterBehavior`（後述）が実際の属性値保持・検証・永続化を行い、protocol 層とはコールバック（Read/Write/Invoke handler）を介して接続される。

依存方向は「transport → exchange → session/securechannel → interaction」の一方向で、循環は無い。`interaction` は `session` を使うが `session` は `interaction` を知らない。`node` 層は `protocol` に依存するが逆はない。この「下位が上位のインターフェースを知らず、上位が下位のインターフェースを実装/注入する」という一貫した方向性は、Rust実装でもトレイト境界の設計指針として直接応用できる。

---

## 3. クラスタ/デバイスタイプ定義のモデル化手法

matter.js の最大の特徴は、**Matter仕様のクラスタ定義を「コード生成された宣言的データ構造」として単一のソースオブトゥルースに集約し、そこから型・ランタイムAPI・バリデーションロジックを段階的に導出する**アーキテクチャである（`packages/model/README.md` に明記）。

### 3.1 3層のモデル表現

1. **`elements/`** (`packages/model/src/elements/*.ts`): `ClusterElement`, `AttributeElement`, `CommandElement`, `FieldElement`, `DatatypeElement`, `DeviceTypeElement` 等。Matter仕様が定義する「要素」をそのままTypeScript型として表現するプレーンなデータ型。全ての要素定義は `BaseElement` のサブタイプ。
2. **`models/`** (`packages/model/src/models/*.ts`): `ClusterModel`, `AttributeModel`, `CommandModel`, `DeviceTypeModel` 等、`elements` のデータをラップして走査・解決・バリデーションのメソッドを提供する「操作可能な」クラス。全て `Model` 基底クラスのサブタイプ。
3. **`standard/elements/*.element.ts`**: Matter仕様全体をカバーする**自動生成されたデータファイル群**（各クラスタ・デバイスタイプごとに1ファイル、合計数百ファイル）。ファイル冒頭に `/*** THIS FILE IS GENERATED, DO NOT EDIT ***/` と明記されている。例（`on-off.element.ts`）:

   ```ts
   export const OnOff = Cluster(
       { name: "OnOff", id: 0x6, classification: "application" },
       Attribute({ name: "ClusterRevision", id: 0xfffd, type: "ClusterRevision", default: 6 }),
       Attribute(
           { name: "FeatureMap", id: 0xfffc, type: "FeatureMap" },
           Field({ name: "LT", conformance: "[!OFFONLY]", constraint: "0", title: "Lighting" }),
           ...
       ),
       Attribute({ name: "OnOff", id: 0x0, type: "bool", access: "R V", conformance: "M", quality: "N S" }),
       Command({ name: "Off", id: 0x0, access: "O", conformance: "M", direction: "request", response: "status" }),
       ...
   );
   ```
   `conformance`（feature依存の必須/任意）、`constraint`（値域）、`quality`（Nullable/Scene対応等）、`access`（ACL要件）は、Matter仕様が定めるミニ言語の**文字列としてそのままデータに埋め込まれ**、`packages/model/src/aspects/`（`Quality.ts` 等）や `packages/node/src/behavior/state/validation/`（`conformance-compiler.ts`, `constraint.ts`）でパース・評価される。つまり「仕様の複雑な条件式」もコード分岐ではなくデータ+パーサとして表現している。

### 3.2 生成パイプライン

Matter仕様のMarkdown/XML相当資料 → `support/codegen/src/generate-spec.ts` により中間データモデル `support/models/src/v1.4.1/spec.ts` を生成 → それを元に `packages/model/src/standard/elements/*.element.ts`（283クラスタ以上、`generate-model` スクリプト）を生成、という2段階パイプライン。`support/codegen/README.md` および `packages/model/README.md` に手順が明記されている。

### 3.3 typesパッケージでの「操作的表現」への変換

`packages/types/src/clusters/*.js` (+対応する `.d.ts`) も自動生成物で、モデルから `ClusterType()` ファクトリ関数を呼んで実行時オブジェクトを作る:

```ts
// packages/types/src/clusters/on-off.js（生成物）
import { ClusterType } from "../cluster/ClusterType.js";
import { OnOff as OnOffModel } from "@matter/model";
export const OnOff = ClusterType(OnOffModel);
```
型定義(`.d.ts`)は別途生成され、TypeScriptの型システムでは表現しきれない「モデルから導出される正確な型」を静的に提供する。つまり **「1つの宣言的モデル → (a) 実行時に検証/解釈可能なデータ、(b) 型安全なコンパイル時API」の両方を生成** するという二重導出構造になっている。README にある通り「Cluster APIはモデルから部分的に生成される」("partially generated from this model")。

### 3.4 デバイスタイプ

`DeviceTypeElement`/`DeviceTypeModel` も同様に `standard/elements/*.element.ts` にクラスタの必須/任意requirement一覧として宣言的に定義され、`node/src/devices/` でエンドポイントのビヘイビア集合として具体化される。

---

## 4. 環境抽象

`packages/general/src/environment/` に **`Environment` という軽量DIコンテナ**が実装されており、これがプラットフォーム差し替えの核。

- `Environment.ts`: サービスのレジストリ。`env.get(ServiceClass)` / `env.set(instance)` でサービスを登録・取得する。
- `Environmental.ts`: サービスとして登録可能なクラスが実装すべき規約。特にファクトリパターンの `Symbol` ベースの `create` メソッドが特徴的:

  ```ts
  export interface Factory<T extends object = object> {
      new (...args: any[]): T;
      [create]: (environment: Environment) => T;
  }
  ```
  各コンポーネント（`ExchangeManager`, `DeviceCommissioner`, `SessionManager` 等）は `static [Environmental.create](env: Environment) { ... }` を実装し、必要な依存サービスを `env.get(...)` で解決してコンストラクタに渡す。これはコンストラクタインジェクションと Service Locator のハイブリッドで、テスト時は `MockCrypto`/`MockNetwork`/`MockStorageService`（`packages/testing`）を同じインターフェースで環境に登録するだけで差し替えられる。

- **Network抽象**: `packages/general/src/net/Network.ts`（TCP接続エラー分類等）、`Transport.ts`（`Transport` インターフェース: `onData`, `openChannel`, `supports` 等）、`udp/UdpSocket.ts`, `tcp/TcpConnection.ts` がプラットフォーム非依存インターフェースを定義し、`packages/nodejs/src/net/{NodeJsNetwork,NodeJsUdpSocket,NodeJsTcpConnection}.ts` がNode.js（`dgram`/`net`モジュール）向けの実装を提供する。BLEも同様に `packages/nodejs-ble/src/{NobleBleClient,BlenoBleServer,NobleBleChannel}.ts` が `noble`/`bleno` ライブラリをラップして protocol層のBLEインターフェースに適合させる。
- **Storage抽象**: `packages/general/src/storage/StorageManager.ts`, `StorageService.ts`, `BaseStorageDriver.ts` がキー・バリューストア＋WAL(Write-Ahead Log)の抽象を定義し、`packages/nodejs/src/storage/fs/*`（ファイルベース）や `storage/sqlite/*`（SQLite）が実装を差し替える。
- **Crypto抽象**: `packages/general/src/crypto/Crypto.ts` が抽象基底、`StandardCrypto.ts`/`WebCrypto.ts` が汎用実装、`packages/nodejs/src/crypto/NodeJsCrypto.ts` がNode.js版（内部でnoble/curvesとNode `crypto`モジュールを併用）。
- **プラットフォーム登録**: `packages/nodejs/src/environment/register.ts` のような「レジストレーションファイル」を import するだけで、そのランタイム向けの実装一式がデフォルト環境に登録される設計:
  ```ts
  // packages/nodejs/src/environment/register.ts
  Environment.default = NodeJsEnvironment();
  ```
  これにより、上位の `node`/`protocol` パッケージのコードは一切変更せず、`import "@matter/nodejs"` の有無だけでランタイムのバックエンドを切り替えられる。**「インターフェースは下位(general)が定義し、実装は最上位(nodejs, nodejs-ble)が提供し、中間層(protocol, node)は常にインターフェースにのみ依存する」**という典型的な依存性逆転(DIP)の適用例。

---

## 5. コミッショニング（ペアリング）フロー

- **PASE**: `packages/protocol/src/session/pase/{PaseServer.ts, PaseClient.ts, PaseMessenger.ts, PaseMessages.ts}`。`PaseServer`（アクセサリ側）と `PaseClient`（コントローラ側）が SPAKE2+（`general/src/crypto/Spake2p.ts`）による鍵合意を実装。
- **CASE**: 同様に `session/case/{CaseServer.ts, CaseClient.ts, CaseMessenger.ts, CaseMessages.ts}`。証明書ベースの相互認証は `protocol/src/certificate/` と `protocol/src/fabric/Fabric.ts` に依存。
- **セキュアチャネルの仲介**: `securechannel/SecureChannelProtocol.ts` が `ProtocolHandler` として登録され、新規exchangeのメッセージタイプ(PASE/CASE)を見て内部でPase/CaseサーバーやClientに処理を委譲する。
- **デバイス側（アクセサリ）のコミッショニング状態機械**: `protocol/src/protocol/DeviceCommissioner.ts` の `DeviceCommissioner` クラスが、コミッショニングウィンドウの開閉状態(`CommissioningWindowStatus`)、`FailsafeContext`（一定時間内にコミット/ロールバックしないと自動失敗する安全装置）、PASEエラー回数制限（`tooManyPaseErrors`）などのステートマシンを実装。コンストラクタでは `FabricManager`, `SessionManager`, `DeviceAdvertiser`, `SecureChannelProtocol` を依存として受け取る（Environmentから解決）。
- **コントローラ側のコミッショニング**: `protocol/src/peer/ControllerCommissioner.ts` と `ControllerCommissioningFlow.ts` が、PASE確立 → ArmFailsafe → 証明書チェーン交換(CSR/NOC発行) → CASE確立 → ネットワーク設定 → コミッショニング完了、という一連のステップを順序立てて実行するフローを実装。`CommissioningConnectionPool.ts`/`CommissioningConnection.ts` が複数デバイス同時コミッショニングの接続管理を担う。
- **Discovery（mDNS）**: `protocol/src/mdns/CommissionableMdnsScanner.ts`（コントローラ側、コミッショナブルデバイスの探索）、`MdnsServer.ts`（アクセサリ側、自身のアドバタイズ）。実際のマルチキャストDNS送受信は `general/src/net/dns-sd/{MdnsSocket.ts, ServiceDiscovery.ts}` に切り出されており、mdns パッケージはその上にMatter固有のTXTレコード（ディスクリミネータ、VendorID等）の意味付けを載せるだけ。
- **Advertisement**: `protocol/src/protocol/DeviceAdvertiser.ts` がmDNS(IP)とBLEアドバタイズを統括する上位インターフェース。

全体として「PASE/CASEという暗号プロトコル」「コミッショニングの手順制御（ステートマシン）」「Discovery」が明確に別ファイル・別クラスに分離されており、それぞれが単体でテスト可能な設計になっている。

---

## 6. 状態管理とイベント/リアクティブの仕組み

- **Observable**: `packages/general/src/util/Observable.ts` が独自のObserver/Observableパターンを実装。DOM EventTargetやRxJSではなく自前実装で、`AsyncIterable`と`PromiseLike`を兼ねる（`for await`でも`await observable`でも使える）点が特徴的。同期/非同期どちらのオブザーバーも許容し、戻り値がPromiseなら`emit`側もawaitする、という柔軟な設計:
  ```ts
  export interface Observable<T extends any[] = any[], R = void> extends AsyncIterable<T>, PromiseLike<T> {
      emit(...args: T): R | undefined;
      on(observer: Observer<T, R>): void;
      use(observer: Observer<T, R>): Disposable;   // Disposableで自動解除
      isObserved: boolean;
      isAsync: boolean;
  }
  ```
- **属性の変更検知と永続化**: `packages/node/src/behavior/state/managed/Datasource.ts` の `DatasourceImpl` が属性値の「バージョン番号(`version: number`)」を保持し、値が変わるたびにインクリメントする。フィールド単位で `"fieldName$Changing"`（コミット前）／`"fieldName$Changed"`（コミット後）というObservableイベントを動的に生成・発火する仕組みを持つ（`changedEventFor(key)`）。これはMatterの属性バージョン管理（DataVersion）とSubscriptionの差分配信の内部実装基盤になっている。
- **トランザクション**: `packages/general/src/transaction/`（`Transaction`）を介して属性の変更をバッチ化し、複数属性の同時変更を1コミットとして扱う。`Behavior`クラス（`node/src/behavior/Behavior.ts`）は状態を`Transaction`経由で読み書きする。
- **Subscription（購読）**: `protocol/src/interaction/Subscription.ts` はネットワーク越しの購読契約（`subscriptionId`, キャンセル処理, close）を表す軽量インターフェースであり、実際の変更検知(Datasource)とは疎結合。ReportエンジンがDatasourceの変更イベントを監視し、対象Subscriptionに対してDataReportメッセージを送るという、"内部状態変更(Observable)" と "ネットワーク購読(Subscription)" の2段構成になっている。
- **バリデーション**: `node/src/behavior/state/validation/{conformance.ts, conformance-compiler.ts, constraint.ts}` が、3章で述べたモデルの`conformance`/`constraint`文字列をパースして実行時バリデータ関数へコンパイルする。属性書き込み時にこれらが呼ばれ、仕様違反の値を拒否する。

---

## 7. 新実装（Rust/no_std/小フットプリント）への示唆に向けた考察

matter.js はNode.js/ブラウザ双方で動く前提のため、GC・動的型・Promiseベースの非同期・巨大な依存ツリー（283以上のクラスタ生成ファイル、数百KB〜MB級のコード）を許容している。no_std/小フットプリントのRust実装では、そのままは持ち込めない部分と、思想として持ち込める部分がはっきり分かれる。

## 新実装への示唆

### 参考にすべき構造上の工夫

1. **レイヤの単方向依存とインターフェースによる分離**（`general → model → types → protocol → node → platform実装`）。特に「プロトコルスタック本体(protocol相当)はプラットフォーム実装を一切知らず、下位が定義したtrait/インターフェースにのみ依存する」という依存性逆転は、no_std環境でも`embedded-hal`スタイルのtraitとして直接踏襲できる。`Network`/`Transport`/`Crypto`/`Storage`をtraitとして`general`相当のクレートに定義し、実装クレート（Linux/Embassy/RTOS等）を分離するのは高フットプリントJS版と同じ理由（テスト容易性・移植性）でRustでも有効。
2. **`ProtocolHandler`のようなプラガブルディスパッチ**（protocol IDごとにハンドラを登録し、ExchangeManagerはハンドラの中身を知らない）は、Rustでも`&dyn ProtocolHandler`もしくは列挙型+match（no_stdでvtable回避したい場合）で再現でき、BDX/OTA等の任意プロトコルの追加/削除を疎結合に保てる。
3. **Session種別の型による区別**（`Session`基底 → `SecureSession`(abstract) → `NodeSession`/`GroupSession`/`UnsecuredSession`）は、Rustではenumまたはtraitオブジェクトより「型状態(typestate)パターン」で置き換えるとメモリレイアウトが静的に決まり、no_stdでも都合が良い。「セキュアでないセッションでは特定APIを呼べない」という制約を`SecureSession::assert`のような実行時チェックではなく型で保証できる点はRustの強み。
4. **宣言的クラスタモデル + コード生成の二段構成**（`model`のデータ定義 → `types`の実行時+コンパイル時API生成）という発想自体は非常に有用。Rustでは`build.rs`やproc-macroでMatterのクラスタXML/独自DSLから`struct`/`enum`と`const`テーブルを生成し、conformance/constraint相当のロジックは実行時パーサではなく**コンパイル時に確定させて分岐コード or ルックアップテーブルに落とす**ことで、matter.js以上にフットプリントを削減できる余地がある（JS版は仕様の複雑性ゆえ文字列DSL+ランタイムパーサに頼らざるを得なかったが、Rustではビルド時展開が可能）。
5. **Environment/DIパターンの精神（差し替え可能な最小サービス集合）**は保つ価値がある。ただしJS版の`Environment`はSymbolキー+実行時解決の動的レジストリであり、これはno_stdでは不向き。Rustでは同じ目的を「ジェネリクス+trait境界で結ばれたコンテキスト構造体を最上位でモノモーフィズ化する」形（例: `MatterStack<N: Network, C: Crypto, S: Storage>`）で静的に実現でき、ゼロコスト抽象化の恩恵を受けられる。
6. **状態変更のObservable/バージョン管理とSubscriptionの分離**（内部の値変更通知 vs ネットワーク購読契約を別レイヤーにする）という設計思想は踏襲する価値がある。ただし実装はheapless/no-allocのリングバッファやビットフラグでの「dirty属性リスト」管理に置き換えるべきで、JS版のようなSymbol動的プロパティ・Map<string, Observable>方式は使えない。
7. **MRP（メッセージ再送）・Exchange・Session・SecureChannel・Interactionの明確なファイル/型分割**自体はプロトコルの正しさを保証する上で重要な構造であり、Rust版でもモジュール境界としてそのまま踏襲できる（`mrp.rs`, `exchange.rs`, `session.rs`, `securechannel/{pase,case}.rs`, `interaction.rs`のような分割）。

### JS特有で参考にならない/避けるべき部分

- **動的型・Symbolベースのプロパティ拡張**（`Behavior`の`STATE`/`INTERNAL`/`EVENTS` Symbol、`Datasource`の`"fieldName$Changed"`という文字列キー動的生成）は、GCと動的ディスパッチ前提の設計で、no_stdでは再現不可能かつ不要（Rustでは構造体フィールド+コンパイル時マクロで代替）。
- **Promiseベースの協調的非同期・`AsyncIterable`兼用のObservable**は、no_std環境ではasync executorの選択（Embassy等）に強く依存し、そのまま移植できない。matter.jsの「同期/非同期どちらも許容する`Observer`」という柔軟性はRustの型システムでは表現しづらく、複雑性の元になるため簡素化すべき。
- **数百ファイルにおよぶクラスタ全種の事前生成**（`packages/model/src/standard/elements/*.element.ts`が283+、`types/src/clusters/*`も同数）は、tree-shakingとJITに頼れるJS/Node.jsだから許容されるアプローチ。小フットプリントRustでは「必要なクラスタだけをfeature flagやbuild.rsで選択的に生成する」ことが必須で、全クラスタを常時リンクする設計は避けるべき。
- **WAL付きストレージドライバやSQLite統合**（`general/src/storage/wal/*`, `nodejs/src/storage/sqlite/*`）は、フラッシュメモリ制約下の組込み向けにはオーバースペックであり、シンプルなKVストア+チェックサム程度に簡略化すべき。
- **巨大な依存ツリーと再エクスポートファサード（`main`/`matter.js`パッケージ）**は、パッケージ管理・後方互換性維持を目的としたJS/npmエコシステム特有の事情であり、Rustクレート設計では不要な複雑性になりうる。
- **実行時DSLパーサ（conformance/constraint文字列の実行時コンパイル）**は仕様の表現力は高いが、no_stdでの文字列パース処理はコード/RAM双方にコストがかかる。前述の通りビルド時展開に置き換えるのが望ましい。

---

以上、matter.jsは「JSらしい動的さ」と「厳密なレイヤ分割・依存性逆転による移植性」を両立させた設計であり、後者の設計思想（プロトコル本体とプラットフォーム実装の分離、宣言的モデルからの多段生成、プラガブルなProtocolHandler、型による状態遷移の表現）はRust/no_std実装においても十分に価値のある指針となる。一方、動的型・Symbol・Promise・全クラスタ常時生成といった実装手法はGC/JITありきの妥協であり、そのまま持ち込むべきではない。
