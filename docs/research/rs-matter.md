# rs-matter 構造調査レポート

対象: `project-chip/rs-matter`（ワークスペース version 0.2.0, rust-version 1.87）
clone 先: `/home/kenta/repos/simple_matter/research/rs-matter`
調査コミット: `6304fdd Depend on the just-released to crates.io mbedtls-rs-sys`
目的: no_std 前提・小フットプリントの Matter デバイス側実装を Rust でゼロから作るにあたり、rs-matter の構造的課題と参考点を抽出する。

---

## 0. サマリ

rs-matter は「no_std + 静的確保 + async」を志向した、connectedhomeip より遥かに軽量な純 Rust 実装で、設計思想は我々の目標と非常に近い。特に以下は積極的に参考にすべき:

- 全状態を単一の巨大構造体に集約し `pinned-init` で `.bss` に in-place 初期化する方式
- サイジングを Cargo feature（`max-sessions-16` 等）で `const` に落とし込み、`heapless` ベースの固定容量コンテナで表現する方式
- クラスタ・ハンドラを型レベルのタプルチェイン（`ChainedHandler`）で静的ディスパッチする方式
- crypto をトレイト境界と const generics で完全に抽象化し、バックエンド（rustcrypto / mbedtls / openssl）を差し替え可能にしている点

一方、構造的な課題も明確:

- 「no_std」ではあるが「no-alloc」ではない。crypto/cert 経路（x509-cert, ccm）が `alloc` を要求し、完全ヒープレス化ができない。
- 122k 行・巨大ファイル（`transport.rs` 2600行、`im.rs` 2000行、`color_control.rs` 4000行）で、コアと全クラスタが一体。フィーチャによる粗いカット。
- IDL コード生成（`build.rs` で 416KB の `.matter` を毎ビルドパースし全クラスタを生成）への依存。
- 型パラメータが app 全体に伝播し、`embassy-executor` タスク境界で「型名が書けない」問題が発生（`handler_chain_type!` マクロや bloat-check の長大な型エイリアスがその証拠）。
- コントローラ（デバイス）専用ではなく双方向（レスポンダ中心 + コミッショナ）を1クレートに同居。

以下、調査項目ごとに詳述する。

---

## 1. クレート構成とモジュール構成

ワークスペース `Cargo.toml`（メンバー）:

```
members = ["rs-matter", "rs-matter-macros", "rs-matter-codegen", "examples"]
exclude = ["bloat-check", "xtask"]
```

| クレート | 役割 |
|---|---|
| `rs-matter` | 本体。プロトコル全実装。約 122,000 行。 |
| `rs-matter-macros` | proc-macro。実体は `#[derive(FromTLV)]` / `#[derive(ToTLV)]` の2つのみ（`rs-matter-macros/src/lib.rs`）。 |
| `rs-matter-codegen` | Matter IDL(`.matter`) パーサ + コード生成ライブラリ。`nom` ベースのパーサと `quote`/`prettyplease` による生成器。 |
| `examples` | 実行例（`onoff_light`, `bridge`, `speaker`, `webrtc_camera` 等 18 バイナリ）。 |
| `bloat-check` | フットプリント計測専用の別ワークスペース（後述）。nrf52840 / rp2040 / esp32c6 向けクロスビルド設定を持つ。 |
| `xtask` | ビルド補助スクリプト。 |

### rs-matter 本体のモジュール（`rs-matter/src/lib.rs` の `pub mod`）

```
acl / attest / bdx / cert / crypto / dm / error / fabric / failsafe /
group_keys / im / onboard / pairing / persist / respond / sc / tlv /
transport / utils
```

レイヤ対応:

- `tlv` — Matter TLV エンコード/デコード（`tlv/read.rs` 2049行, `tlv/traits/`）。
- `transport` — トランスポート層 + Exchange 層 + MRP + セッション + ネットワーク（UDP/BTP/mDNS/wifi）。`transport.rs` 2610行 + `transport/` サブモジュール。
- `sc` — Secure Channel。`sc/pase/`（SPAKE2+）と `sc/case/`（CASE）。
- `im` — Interaction Model エンジン（read/write/subscribe/invoke, `im.rs` 2016行 + `im/`）。
- `dm` — Data Model。`dm/types/`（トレイト群）と `dm/clusters/`（クラスタ実装）。
- `cert` / `crypto` / `fabric` / `acl` / `failsafe` — 証明書・暗号・ファブリック・アクセス制御・フェイルセーフ。

中核オブジェクトは `Matter<'a>`（`lib.rs:132`）:

```rust
pub struct Matter<'a> {
    state: Mutex<RefCell<MatterState>>,   // fabrics, sessions, pase, failsafe, basic_info, rtc
    transport: Transport,
    dev_det: &'a BasicInfoConfig<'a>,
    dev_comm: BasicCommData,
    dev_att: &'a dyn DeviceAttestation,
    port: u16,
    kv_buf: Mutex<RefCell<[u8; crate::persist::KV_BUF_SIZE]>>,
}
```

`MatterState`（`lib.rs:630`）が永続状態（`fabrics`, `sessions`, `pase`, `failsafe`, `basic_info_settings`, `rtc`）を集約。`&'a dyn DeviceAttestation` のように依存はライフタイム借用 + トレイトオブジェクトで注入される。

---

## 2. no_std 対応の実態

### 基本

`lib.rs:26`:

```rust
#![cfg_attr(not(feature = "std"), no_std)]
```

`std` feature がなければ `no_std`。デフォルトフィーチャは `default = ["os", "rustcrypto", "log"]` であり、**デフォルトビルドは std/OS 前提**。組み込みでは `default-features = false` にして使う（bloat-check がまさにそれ）。

### フィーチャ階層（`rs-matter/Cargo.toml`）

```
os     = ["std", "backtrace", "async-io", "critical-section/std",
          "embassy-sync/std", "embassy-time/std", "dep:if-addrs"]
std    = ["alloc", "rand"]
alloc  = ["defmt?/alloc"]
rustcrypto = ["alloc", "digest", "cipher", "ccm", ... "x509-cert", ...]
mbedtls    = ["alloc", "dep:mbedtls-rs-sys"]
openssl    = ["alloc", "dep:openssl", ...]
```

階層は `os ⊃ std ⊃ alloc`。組み込みは `os`/`std` を外して `alloc` 単独、あるいは `alloc` すら外す方向。

### 重要な構造的制約: no_std ≠ no-alloc

- **3つの crypto バックエンドすべてが `alloc` を要求する**（`rustcrypto`, `mbedtls`, `openssl` いずれも feature list 先頭に `"alloc"`）。理由は cert 経路: `x509-cert = { ... }`（Cargo.toml のコメントに `# TODO: requires alloc`）、および `ccm = { features = ["alloc"] }`。
- したがって現実的に動作させるには `alloc` が必要。bloat-check の組み込みターゲットは実際にヒープを確保している（`bloat-check/src/bin/bloat-check.rs`）:

```rust
// `rs-matter` uses the `x509` crate which (still) needs a few kilos of heap space
const HEAP_SIZE: usize = 4096;
static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = ...;
unsafe { HEAP.init(...) }  // embedded_alloc::LlffHeap
```

- `alloc::` を直接使うファイルは限定的だが確実に存在する: `crypto/backend/rustcrypto.rs`, `crypto/backend/openssl.rs`, `cert` 経路、`tlv/traits/{octets,str,vec}.rs`, `transport/network/tcp.rs`, `im/expand.rs`, `dm/networks/{unix,generic}.rs`, `error.rs`。

### std が残る箇所

`feature = "std"` / `feature = "os"` でガードされる主なファイル: `dm/networks.rs`, `persist.rs`（`DirKvBlobStore`）, `transport/network/{udp,tcp,btp}.rs`, `transport/network/btp/gatt.rs`, `utils/sync/blocking.rs`, `attest/trust_store.rs`。これらは OS ソケット・ファイルシステム・BlueZ(zbus) 等プラットフォーム実装であり、コア protocol は no_std を保つ設計。分離自体は比較的きれい。

**示唆:** コアプロトコルの no_std 化は達成されているが、暗号・証明書のために `alloc` が事実上必須。完全 no-alloc を狙うなら、cert パースと ECC/AEAD を alloc なしの実装（またはスタック上固定バッファ実装）で置き換える必要がある。ここが rs-matter を丸ごと流用できない最大の技術的ネック。

---

## 3. メモリ管理戦略

全体として「静的確保 + const generics + heapless」が基本方針で、ヒープはあくまで crypto/cert のための必要悪。

### 3.1 pinned-init による in-place 初期化

`utils/init.rs` が `pinned-init` クレート（0.0.8）を再エクスポート。全主要型が `fn new() -> Self`(const) と `fn init() -> impl Init<Self>` を持つ。`Matter::init`（`lib.rs:193`）や `MatterState::init`（`lib.rs:662`）が典型:

```rust
init!(Self {
    fabrics <- Fabrics::init(),
    sessions <- Sessions::init(),
    ...
})
```

目的は bloat-check のコメントが明快に説明している: 巨大な `MatterStack` を **`.rodata` を経由せず `.bss` に直接ゼロ初期化** し、フラッシュ消費と初期化時のスタック消費を避けること。`static_cell::StaticCell::uninit()` + `init_with` で `static` 領域へ emplacement する。

### 3.2 サイジング = Cargo feature → const

容量パラメータはすべてビルド時 feature で `const` に落とす。`fabric.rs:817` 付近:

```rust
cfg_if! {
    if #[cfg(feature = "max-fabrics-32")] { pub const MAX_FABRICS: usize = 32; }
    else if #[cfg(feature = "max-fabrics-16")] { pub const MAX_FABRICS: usize = 16; }
    ...
}
```

同様のパターンが `max-sessions-*`, `max-exchanges-per-session-*`, `max-acls-per-fabric-*`, `max-subjects-per-acl-*`, `max-groups-per-fabric-*`, `kv-blob-store-*`（KVスクラッチバッファのバイト数）等、`Cargo.toml` に **十数カテゴリ・約100個** 定義されている。消費側は `acl.rs`, `fabric.rs`, `transport/session.rs`。

### 3.3 heapless 固定容量コンテナ

- 独自の `utils/storage/Vec<T, N>`（`storage/vec.rs` 1706行, const generic 容量）を多用。`heapless` 0.9 も依存。
- `utils/storage/pooled.rs` の `PooledBuffers<T, const N, M>`（`DEFAULT_BUFFER_POOL_SIZE = 10`）がバッファプール。`Signal<[bool; N]>` で空き管理し、`async fn get()` で空き待ち（タイムアウト付き）。RX/TX 用の巨大パケットバッファはここから貸し出す。

### 3.4 パケットバッファサイズ（構造的な地雷）

`transport/network.rs`:

```rust
pub const MAX_RX_PACKET_SIZE: usize = 1583;
pub const MAX_TX_PACKET_SIZE: usize = 1280 - 40 - 8;   // IPv6+UDP ヘッダ控除
pub const MAX_RX_LARGE_PACKET_SIZE: usize = 1024 * 1024;   // large-buffers (TCP) 時
```

`large-buffers` feature（TCP サポート）を有効化すると **バッファが 1MB に膨れる**。`MatterBuffers = PooledBuffers<Buffer, N>`, `Buffer = Vec<u8, MAX_EXCHANGE_RX_BUF_SIZE>`（`transport/exchange.rs:74`）。デフォルト（UDP のみ）では 1583 バイト × プール数。組み込みでは `large-buffers` は当然使わない。

**示唆:** 3.1〜3.3 の方針（`.bss` 集約 + feature サイジング + heapless）はほぼそのまま真似る価値がある。ただし feature 数が 100 近くあるのは過剰で、ビルドマトリクスと組合せ爆発の温床。我々は const generics のジェネリックパラメータ or 少数のプロファイルにまとめるべき。

---

## 4. レイヤ分離と結合度

### レイヤ構成

```
[Data Model / Clusters] (dm)
        │  Handler / AsyncHandler トレイト
[Interaction Model]     (im)  read/write/subscribe/invoke, subscriptions
        │
[Secure Channel]        (sc)  PASE(sc/pase, SPAKE2+), CASE(sc/case)
        │
[Exchange / MRP]        (transport/{exchange,mrp,dedup})
        │
[Session]               (transport/session)
        │
[Transport / Network]   (transport/network/{udp,tcp,btp,mdns,wifi})
```

### 分離のされ方

- **dm ↔ im**: `dm` はデータモデルの「構造とハンドラ」、`im` は「それを駆動するエンジン」と明確にコメントで宣言（`dm.rs` docstring）。IM は単一の `AsyncHandler` を受け取り、それをアプリが `ChainedHandler` で合成する（後述）。
- **sc (PASE/CASE)**: `sc/pase/{initiator,responder,spake2p}.rs`, `sc/case/{initiator,responder,casep}.rs`。イニシエータ/レスポンダが対で存在 = コミッショナ側とデバイス側の両方を実装。デバイス専用なら responder のみで足りる。
- **transport**: `transport.rs` に `Transport` / `TransportRunner` が集約され、session/exchange/MRP/dedup/mDNS が同居。`transport.rs` が 2610 行と巨大で、ここがコアの結合の中心。
- **crypto**: `Crypto` トレイト（`crypto.rs:38`）が全暗号プリミティブを抽象化し、`transport`/`sc`/`cert` はジェネリック `C: Crypto` 越しに使う。結合は疎。

### 結合度の評価

- レイヤ境界はトレイト（`Handler`, `Crypto`, `NetworkSend`/`NetworkReceive`/`NetworkMulticast`, `KvBlobStore`）で切られており、概念的には良好。
- ただし **型パラメータの伝播が激しい**。`InteractionModel` / `DefaultResponder` は `<'a, Crypto, Buffers, (Node, Handler), Kv, Networks, NetCtl>` の 7 パラメータを持つ（bloat-check の `AppInteractionModel` / `AppResponder` エイリアス参照）。1つのクラスタを足すと `Handler` 型が変わり、app 全体の型が変わる。
- `Matter` 本体は `state: Mutex<RefCell<MatterState>>` に fabrics/sessions/pase/failsafe を全部握っており、`with_state(|state| ...)` クロージャ経由で全レイヤがアクセスする。データ結合は中央集権的。

**示唆:** トレイト境界での分離思想は良い。ただし「ジェネリック型が最上位まで伝播して型名が爆発する」問題は避けたい。デバイス専用なら、responder 側だけに絞り、ハンドラ合成をトレイトオブジェクト or 少数の固定形にして型伝播を抑える設計を検討すべき。

---

## 5. 非同期モデル

- **async/await ネイティブ**。`Matter::run`（`lib.rs:503`）が `async fn`。ハンドラも `AsyncHandler`（`read`/`write`/`invoke`/`run` が `impl Future`）。
- **executor 非依存**を標榜。同期プリミティブは `embassy-sync`（`Signal`, `Mutex`, `blocking_mutex`）、時間は `embassy-time`、選択は `embassy-futures`（`select`, `select3`, `select4`, `Coalesce`）を使うが、**executor は選ばない**。
  - `examples/onoff_light.rs` は `futures_lite::future::block_on(select4(...).coalesce())` で単一スレッド実行。
  - bloat-check は `embassy-executor` の `#[task]` で個別タスクをスポーンし、future を `.bss` に配置。
- **embassy との関係**: 同期/時間/futures ユーティリティに embassy を採用（`embassy-sync 0.8`, `embassy-time 0.5`, `embassy-futures 0.1`）。executor は差し替え可能で、embassy-executor は選択肢の一つ。`sync-mutex` feature で work-stealing executor 対応も用意。
- **並行モデル**: 「N 本のレスポンダタスク × M エクスチェンジ」を `responder.run::<4, 4>()` のように const generic で指定（`onoff_light.rs`）。同時処理数もコンパイル時固定。
- **`*_awaits` 最適化**: `AsyncHandler::read_awaits/write_awaits/invoke_awaits`（`handler.rs`）で「このハンドラは await しない」と申告でき、IM が中間バッファを省いてメモリ削減する仕組み。async でありながらメモリを気にした設計。

**示唆:** executor 非依存 + embassy-sync/time/futures 採用という選択は組み込み Rust の事実上の標準で、そのまま踏襲して良い。`*_awaits` のような「await しないパスを型で申告してバッファを省く」工夫は参考になる。

---

## 6. コード生成・マクロ依存度

### proc-macro（`rs-matter-macros`）

実体は **`FromTLV` / `ToTLV` の derive 2つだけ**（`rs-matter-macros/src/lib.rs`）。`get_crate_name()` で `rs-matter` or `crate` を解決。依存度は限定的で健全。

### IDL コード生成（`rs-matter-codegen` + `build.rs`）— ここが重い

- `rs-matter/build.rs` がビルドごとに `rs_matter_codegen::generate("crate", &out_dir)` を呼ぶ。
- 入力は `rs-matter-codegen/src/idl/parser/controller-clusters-V1.5.1.0.matter`（**416 KB** の Matter IDL）。`nom` ベースのパーサ（`codegen/src/idl/parser/`）でパースし、`quote` + `prettyplease` で **全クラスタの Rust コードを毎ビルド生成**（`OUT_DIR/clusters_generated.rs` + `clusters_generated/*.rs`）。
- 生成物はクラスタごとの「強く型付けされたハンドラトレイト」`ClusterXHandler` / `ClusterXAsyncHandler`（`codegen/src/idl/handler.rs`）。属性・コマンド・enum・bitmap・struct がすべて IDL 由来の型として生える。
- クラスタ実装（例: `basic_info.rs`）は `pub use crate::dm::clusters::decl::basic_information::*;` で生成物を取り込み、その上に手書きロジックを載せる二層構造。

### 手書きマクロ

app 側の宣言用に `root_endpoint!`（`dm/endpoints.rs:61`）, `devices!`（`dm/devices.rs:138`）, `clusters!`（`dm/types/cluster.rs:610`）, `handler_chain_type!`（`dm/types/handler.rs:1320`）。最後のものは「ハンドラチェインの型名を書けない」問題への対症療法。

### クラスタ定義の記述方法（実例）

`examples/onoff_light.rs` の `data_model()`:

```rust
endpoints::EthSysHandlerBuilder::new()
    .netif_diag(&SysNetifs)
    .build(rand)
    .chain(EpClMatcher::new(Some(1), Some(desc::DescHandler::CLUSTER.id)),
           Async(desc::DescHandler::new(...).adapt()))
    .chain(EpClMatcher::new(Some(1), Some(groups::GroupsHandler::CLUSTER.id)),
           Async(groups::GroupsHandler::new(...).adapt()))
    .chain(EpClMatcher::new(Some(1), Some(TestOnOffDeviceLogic::CLUSTER.id)),
           on_off::HandlerAsyncAdaptor(on_off))
```

`(Matcher, Handler)` タプルを `.chain()` で積み上げ、`Handler for (M,H)` / `ChainedHandler<M,H,T>`（`handler.rs:1203-`）が静的ディスパッチで解決。メタデータ側は `Node { endpoints: &[...] }` を `const` で別途宣言し、実行時ハンドラと二重管理になっている（メタデータとハンドラの整合はプログラマ責任）。

**示唆:**
- FromTLV/ToTLV derive は良い。維持すべきパターン。
- 416KB IDL を毎ビルドパースするコード生成はビルド時間・複雑性の大きな負債。かつ **全クラスタを生成**するため、使わないクラスタの型定義もコンパイル対象に入りやすい。デバイス実装なら「使うクラスタだけを手書き or 最小生成」する方が軽い。
- `Node` メタデータと `ChainedHandler` の二重管理（宣言とハンドラのズレを型で守れない）は設計上の弱点。1箇所からメタデータとハンドラを導出できる方が良い。

---

## 7. フットプリント（bloat-check）

`bloat-check/` は計測専用の独立ワークスペース。nrf52840(thumbv7em) / rp2040(thumbv6m) / esp32c6(riscv32imac) のクロスビルド設定と `memory-*.x` を持ち、`opt-level="z"` + `lto="fat"` + `codegen-units=1`。

計測方針（`bloat-check/src/bin/bloat-check.rs` の docstring）:

- **RAM**: future 自体を含む全メモリを `.bss` に置いて `bloaty` が実サイズを検出できるようにする。BTP + wireless + 内蔵 mDNS + フェイク persister を有効化して現実的な構成で計測。
- 計測に含めない: UDP/IP スタック、Wi-Fi/Thread スタック、BLE GATT スタック（プラットフォーム依存のため）。
- 各コンポーネントのサイズを実行時に `size_of_val` でログ出力する（`Matter`, `Buffers`, `Subscriptions`, `Events`, `Networks`, `BTP`, 各 future など）。

構造的に読み取れるフットプリント上の論点:

- 全状態を1つの `MatterStack` 構造体に集約 → `.bss` サイズ = 各サブシステムの静的容量の総和。容量は feature で決まるため、**feature を絞るほど直接 RAM が減る**明快なモデル。
- RX/TX バッファ（1583B × プール）と BTP セッション、サブスクリプションテーブル、イベントキューが RAM の主要消費。
- crypto/cert が要求する 4KB のヒープ（前述）。
- README は「1MB flash / 256KB RAM の bare-metal MCU から embedded Linux までスケール」と主張。つまり **256KB RAM クラスが下限**であり、それより小さい MCU は想定外。

**示唆:** 「全状態を単一構造体 + `.bss` + `size_of_val` で可視化」という計測手法は非常に良い。新実装でも同型の bloat-check を最初から用意すべき。ただし 256KB RAM 下限は crypto/cert のヒープと 1.5KB×プールのバッファに起因しており、より小さいフットプリントを狙うなら crypto とバッファ戦略の再設計が必要。

---

## 8. 構造上の課題の抽出

### 避けるべき / 負債と考えられる設計

1. **no_std だが alloc 必須**。crypto(rustcrypto/mbedtls/openssl) と x509-cert・ccm が `alloc` を強制し、真のヒープレスにならない。組み込みで 4KB ヒープを確保している。
2. **巨大 IDL のビルド時コード生成**（416KB `.matter` を毎ビルドパースし全クラスタ生成）。ビルド時間・複雑性・不要クラスタの巻き込み。
3. **モノリシックな巨大ファイルとコア/クラスタ一体**（`transport.rs` 2610, `im.rs` 2016, `color_control.rs` 4094, `unit_testing.rs` 3050 行）。全部入りで、フィーチャによる粗いカットに依存。
4. **型パラメータの上位伝播 / 型名爆発**。`InteractionModel`/`DefaultResponder` の 7 型パラメータ、`handler_chain_type!` マクロ、bloat-check の長大な型エイリアスが必要になっている（embassy-executor がジェネリックを扱えないため）。
5. **メタデータ（`Node`）とハンドラチェインの二重管理**。整合はプログラマ責任で、型では守られない。
6. **約100個のサイジング feature** による組合せ爆発（`max-*-*` が十数カテゴリ）。
7. **コントローラ/デバイス両対応**（PASE/CASE の initiator と responder 両方、コミッショナ例あり）で、デバイス専用にはオーバースペック。

### 参考にすべき設計

1. **`pinned-init` による `.bss` in-place 初期化**（`.rodata` を経由しない静的確保）。組み込みで初期化スタック・フラッシュを節約する要。
2. **feature/const による容量サイジング + heapless 固定容量コンテナ**（`Vec<T,N>`, `PooledBuffers<T,N>`）。RAM 使用量がビルド時に決定でき可視化しやすい。
3. **`Crypto` トレイト + const generics による暗号バックエンド抽象化**（鍵長・ハッシュ長・署名長を const generic で表現）。バックエンド差し替え可能。
4. **`ChainedHandler` によるクラスタハンドラの型レベル静的ディスパッチ**（`(Matcher, Handler)` タプルの合成、vtable なし）。
5. **executor 非依存 + embassy-sync/time/futures 採用**。単純な `block_on` から embassy `#[task]` まで同一コードで動く。
6. **`*_awaits` による「await しないパスの申告 → 中間バッファ省略」**というメモリ最適化の型設計。
7. **`FromTLV`/`ToTLV` derive** による TLV シリアライズの宣言的記述。
8. **bloat-check サブプロジェクト**による継続的フットプリント計測（`size_of_val` によるコンポーネント別可視化 + マルチMCUクロスビルド）。
9. **プラットフォーム依存（UDP/BTP/mDNS/FS）を `std`/`os` feature 背後のトレイト実装として分離**し、コアプロトコルを no_std に保っている点。

---

## 9. 新実装への示唆

我々の目標（小フットプリント・no_std 前提のデバイス側実装）に照らした具体的な指針:

1. **デバイス(responder)専用に絞る。** PASE/CASE の initiator、コミッショナ、BDX の一部、多数の app クラスタは初期スコープから外す。`sc/pase/responder` と `sc/case/responder` に相当する片側だけで足りる。rs-matter が両対応で膨らんでいる分をそぎ落とす。

2. **crypto/cert の alloc 依存を最初から断つ設計にする。** rs-matter を丸ごと流用できない最大要因。ECC(P-256)/AES-CCM/HKDF/SHA-256 をスタック固定バッファで完結する実装（あるいは alloc なしで使える crate 選定）にし、証明書パースも固定バッファ・ストリーミングパースにする。ここを解けば 4KB ヒープが不要になり 256KB 未満を狙える。

3. **静的確保の枠組みは rs-matter を踏襲する。** 単一の巨大 state 構造体 + `pinned-init` で `.bss` 初期化 + heapless 固定容量。ただしサイジングは feature 100 個ではなく、少数の const generic パラメータ（or 2〜3個のプロファイル）に集約する。

4. **コード生成は最小化する。** 416KB IDL 全パースはやめ、実装するクラスタのみを手書き（TLV 型は `FromTLV`/`ToTLV` derive で軽量に）。生成が必要でも「使うクラスタのみ」を対象にする。

5. **型パラメータ伝播を抑える。** ハンドラ合成は rs-matter の `ChainedHandler` を参考にしつつ、最上位まで巨大タプル型が漏れないよう、境界でトレイトオブジェクト化 or 型消去する層を1枚挟む。`handler_chain_type!` のような型名回避マクロが不要な形を目指す。

6. **メタデータとハンドラを単一ソースから導出する。** rs-matter の `Node`(const) と `ChainedHandler` の二重管理を避け、1つの宣言からメタデータと dispatch を生成する（macro or const 評価）。

7. **executor 非依存 + embassy-sync/time/futures を採用する。** ここは rs-matter と同じで良い。`*_awaits` 相当のバッファ省略最適化も取り入れる。

8. **bloat-check を day 1 から用意する。** `size_of_val` によるコンポーネント別 RAM 計測 + 実 MCU(nrf/esp) クロスビルドを CI に入れ、フィーチャ追加による肥大を早期検知する。

### 主要参照ファイル

- 中核オブジェクト: `rs-matter/src/lib.rs`（`Matter`, `MatterState`, `init!`）
- メモリ/初期化: `rs-matter/src/utils/init.rs`, `rs-matter/src/utils/storage/{vec,pooled}.rs`
- サイジング feature: `rs-matter/Cargo.toml`, `rs-matter/src/fabric.rs`（`MAX_FABRICS`）, `rs-matter/src/transport/session.rs`
- ハンドラ/dispatch: `rs-matter/src/dm/types/handler.rs`（`Handler`, `AsyncHandler`, `ChainedHandler`）
- crypto 抽象: `rs-matter/src/crypto.rs`, `rs-matter/src/crypto/backend/{rustcrypto,mbedtls,openssl,dummy}.rs`
- トランスポート: `rs-matter/src/transport.rs`, `rs-matter/src/transport/{exchange,session,mrp}.rs`, `rs-matter/src/transport/network.rs`（バッファサイズ）
- Secure Channel: `rs-matter/src/sc/{pase,case}/`
- コード生成: `rs-matter/build.rs`, `rs-matter-codegen/src/lib.rs`, `rs-matter-codegen/src/idl/handler.rs`, `rs-matter-codegen/src/idl/parser/controller-clusters-V1.5.1.0.matter`
- クラスタ実例: `rs-matter/src/dm/clusters/basic_info.rs`, `rs-matter/src/dm/clusters/app/on_off.rs`
- app 配線実例: `examples/src/bin/onoff_light.rs`
- フットプリント: `bloat-check/src/bin/bloat-check.rs`, `bloat-check/Cargo.toml`
