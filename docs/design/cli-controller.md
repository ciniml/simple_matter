# CLI コントローラツール(`smctl`)設計 — chip-tool 相当の操作 CLI

対象: 実装済みのコントローラ資産(`controller` feature の `ControllerStack` /
`Commissioner` / `ImClient` / `Ca` / `MdnsClient`、BLE は `simple-matter-ble` の
`BtleplugCentral`)を束ね、**コミッショニングと標準クラスタの Read/Write/Invoke を
コマンドラインから行う独立バイナリ `smctl`** を追加するための設計。

前提と制約:

- **コア(`crates/simple-matter*`)は無改造**。本件は「examples に散っている駆動コードの
  製品化」であり、コアへの新規要求はない(§8 のギャップは将来コア側で解消する)。
- 現時点で実装済みの通信機能のみをスコープとする。未実装機能(Subscribe レポート受信、
  attestation 検証、ACL 等)に依存するコマンドは将来節(§7)へ分離する。
- 本書執筆時点で別作業として **CASE resumption が `src/sc/` に実装中**。本設計はその
  成果物を「ノード状態ストアに保存すべき項目」として先取りで設計に織り込む(§4.3)が、
  C1〜C2 は resumption なしで成立する。

実装済み資産の根拠(調査結果):

| 資産 | 場所 | CLI での用途 |
|---|---|---|
| sans-IO コントローラスタック | `src/controller/mod.rs`(`ControllerStack`: `start_pase/start_case/start_read/start_write/start_invoke` + `handle_rx/poll/next_deadline`) | 全コマンドの通信基盤 |
| コミッショニング状態機械 | `src/controller/commissioner.rs`(`Commissioner`: PASE→ArmFailSafe→CSR→AddTrustedRoot→AddNOC→CASE→Complete、`suspend_before_case`/`set_peer`/`resume` で BLE→UDP handoff) | `pairing` サブコマンド |
| CA(RCAC/NOC 発行 + 復元) | `src/controller/ca.rs`(`Ca::generate`/`Ca::restore` + persistence accessor) | fabric 資格情報の永続化 |
| IM クライアント | `src/im/client.rs`(`ImClient`: Read/Write/Invoke/Subscribe プライミング、結果は生 TLV + `read_reports()` 走査) | `read`/`write`/汎用 invoke |
| mDNS クライアント | `src/discovery/client.rs`(`MdnsClient::build_browse_commissionable`/`build_browse_discriminator`/`build_resolve_operational` + `parse_*`、`CommissionableSet`) | `discover`、運用アドレス解決 |
| UDP 駆動ループ | `examples/commissioner.rs`(`pump_commissioner`/`settle`/`drive_until_im_event`、dual-stack socket、Windows QU mDNS + マルチキャスト IF 固定) | `smctl` の UDP ランナーへ昇格 |
| BLE 駆動ループ + CA 永続化 | `simple-matter-ble/examples/ble-commissioner.rs`(btleplug central、BTP pump、`--udp-handoff`、`ca-state.bin` v1、`--operational`) | `smctl` の BLE ランナー + 状態ストアへ昇格 |
| ID/メタ型 | `src/dm/meta.rs`(`EndpointId`/`ClusterId`/`AttributeId`/`CommandId`、`ClusterMeta` ほか) | ID 新型は再利用(§5.4) |

---

## 1. ゴールと非ゴール

### 1.1 ゴール

1. **コミッショニング**: UDP(mDNS 発見 or アドレス直指定)と BLE(btleplug スキャン)
   の両経路、および方向 B(BLE で AddNOC まで → 運用 UDP へ handoff)。
2. **運用操作**: コミッション済みノードに対する CASE 確立 + 標準クラスタの
   Read / Write / Invoke。名前ベース(`onoff toggle`)と ID ベース(`any invoke`)の両方。
3. **状態の永続化**: CA(fabric)・ノードアドレス帳を跨起動で保持し、
   「一度ペアリングすれば以後は `smctl onoff toggle <node>` だけで動く」体験にする。
4. **クラスタ追加の容易性**: 新クラスタの名前対応 = **小さな 1 ファイル追加 + 登録 1 行**
   (§5)。名前テーブルが無いクラスタも ID 直指定で常に操作可能(機能の欠落にしない)。
5. Linux / Windows の両対応(W0-W4 で得た Windows mDNS / クロスビルド資産を吸収)。

### 1.2 非ゴール(現時点)

- Subscribe の**レポート受信**(プライミングまでは可能だが、確立後のデバイス発
  レポート受理経路がコア未実装。§7.1)。
- attestation 検証(コアは `AttestationPolicy::Skip` のみ)。PAA ストア等は将来。
- 複数 fabric / 複数コントローラ identity(`Ca` は `FabricTable<C,1>` 固定)。
- グループ通信、Timed Invoke/Write、イベント Read、Thread コミッショニング
  (WiFi credentials 投入も現状デバイス側が WiFi シムのため network-commissioning
  コマンド送出のみサポートし、実 join の面倒は見ない)。
- chip-tool の**完全互換**(YAML テスト実行、interactive モード等)。

### 1.3 CLI 文法 — chip-tool 風の独自文法(推奨)

**推奨: chip-tool の語順(`<cluster> <command|read|write> ... <node-id> <endpoint>`)を
踏襲した独自文法**とする。完全互換は目指さない。

根拠:

- chip-tool の語順は Matter 界隈の共通言語で、既存の手順書・スクリプトの読み替えが容易。
  一方で完全互換(全クラスタ・全オプション・キャメルケース属性名)はコード生成器
  (zap)前提の物量であり、本プロジェクトの「小さく正しく」方針に合わない。
- 独自化する点: 名前は **kebab-case 統一**(`basic-information`、`vendor-id`)、
  未知クラスタへの escape hatch として `any` サブコマンド(ID 直指定)を第一級で持つ。
  chip-tool の `any` サブコマンドと同じ発想で、名前テーブルは「便利層」に徹する。

```text
# コミッショニング
smctl pairing onnetwork  <node-id> <passcode>                 # mDNS ブラウズ → UDP フル
smctl pairing onnetwork-long <node-id> <passcode> <discriminator>
smctl pairing address    <node-id> <passcode> <ip> [port]     # アドレス直指定
smctl pairing ble        <node-id> <passcode> [discriminator] # BLE 上で CASE まで連続
smctl pairing ble-handoff <node-id> <passcode> [discriminator] # 方向 B(AddNOC→運用UDP)
smctl pairing list                                            # アドレス帳の一覧

# 発見のみ
smctl discover commissionable [--discriminator N]
smctl discover operational <node-id>

# 名前ベースのクラスタ操作(クラスタテーブル収載分)
smctl onoff toggle <node-id> <endpoint>
smctl onoff on     <node-id> <endpoint>
smctl onoff read on-off <node-id> <endpoint>
smctl basic-information read vendor-id <node-id> <endpoint>
smctl descriptor read server-list <node-id> <endpoint>

# ID ベース(全クラスタで常に可能。テーブル未収載でも動く)
smctl any read   <node-id> <endpoint> <cluster-id> <attribute-id>
smctl any write  <node-id> <endpoint> <cluster-id> <attribute-id> <type>:<value>
smctl any invoke <node-id> <endpoint> <cluster-id> <command-id> [<tag>=<type>:<value>...]

# 共通オプション
--state-dir <dir>     # 状態ディレクトリ(既定 ~/.smctl、§4)
--json                # 結果を JSON 1 行で出力(§7.4 で拡充)
--timeout <sec>
SM_MDNS_TRACE=1 / SM_BTP_TRACE=1 / SM_BLE_ADAPTER=hciN   # 既存トレース環境変数を継承
```

値リテラルは `<type>:<value>` 形式(`bool:true`、`u16:1234`、`str:hello`、
`hex:0a0b`、`null`)。名前テーブル収載属性では型はテーブルから引くので `<value>` のみで
よい(§5.2)。

---

## 2. crate 構成

### 2.1 新規 bin crate `crates/smctl`

```text
crates/smctl/
├── Cargo.toml            # [[bin]] smctl。features: ble(既定 on)
└── src/
    ├── main.rs           # 引数パース(自前、§2.3)→ サブコマンド dispatch
    ├── cli.rs            # 文法定義・ヘルプ・値リテラルパーサ
    ├── runner/
    │   ├── mod.rs        # Runner trait: コマンド列を sans-IO スタックに流す共通駆動
    │   ├── udp.rs        # examples/commissioner.rs の pump/settle/socket 群を移植
    │   ├── ble.rs        # ble-commissioner.rs の BTP pump(btleplug)を移植(feature "ble")
    │   └── mdns.rs       # browse/resolve(QU モード・IF 固定・再クエリ込み)
    ├── state/
    │   ├── mod.rs        # StateDir(パス解決・排他)
    │   ├── ca.rs         # ca-state.bin の読み書き(既存 v1 フォーマット互換、§4.1)
    │   └── nodes.rs      # ノードアドレス帳 + resumption 置き場(§4.2/§4.3)
    ├── ops.rs            # 高レベル操作: commission / connect(CASE) / read / write / invoke
    └── clusters/         # クラスタ名前テーブル(§5)
        ├── mod.rs        # レジストリ(全クラスタ 1 行ずつ)
        ├── on_off.rs
        ├── basic_information.rs
        └── ...
```

- 依存: `simple-matter`(features `controller`)、`socket2`。feature `ble` で
  `simple-matter-ble`(features `commissioner`)+ `btleplug` 経由の central。
  **`bluer` は使わない**(デバイス側 peripheral 専用・Linux 限定のため、コントローラには
  不要。`simple-matter-ble` の `commissioner` feature は btleplug のみを引く構成が既に
  ある)。これにより `smctl` は feature 既定のまま **Linux/Windows/macOS(btleplug の
  範囲)でビルド可能**。
- Windows: 実装は `runner/udp.rs`/`runner/mdns.rs` に W3 の成果(QU クエリ +
  エフェメラルポート、`IP_MULTICAST_IF`/join の LAN 向き IF 固定、`SM_MDNS_TRACE`)を
  そのまま `#[cfg]` で移植する。ビルドは既存 recipe(cargo-xwin +
  `x86_64-pc-windows-msvc`)が `smctl` にもそのまま効く。CI の `windows-commissioner`
  ジョブに `-p smctl` を足す(W0 資産の流用)。

### 2.2 examples との関係

- `examples/commissioner.rs` / `ble-commissioner.rs` は**当面残す**(設計 doc の検証
  ゲート・HANDOFF 手順が参照しているため)。smctl が C2 まで到達し実機ゲートを通過した
  時点で、examples を「smctl の薄いラッパ or 削除」に整理する(別コミット)。
- コピーではなく移植: pump/settle/mdns/CA 永続化のロジックは smctl 側を正とし、
  examples は据え置き(コード変更しない)。重複期間は許容する。

### 2.3 引数パースは自前(clap 不採用)

リポジトリは依存最小方針(コアは依存ゼロ、examples も socket2 程度)。CLI 文法は
「サブコマンド + 位置引数 + 少数のフラグ」で clap の物量に見合わないため、
`ble-commissioner.rs` と同様の手書きパーサを `cli.rs` に置く。ヘルプ文字列は
クラスタレジストリ(§5)から自動生成する(`smctl onoff --help` で属性/コマンド一覧)。

### 2.4 非同期ランタイム

btleplug が tokio を要求するため、feature `ble` 有効時のみ tokio(current_thread)を
持つ(ble-commissioner と同じ)。UDP 経路は同期 `std::net` のまま(examples 実証済み)。
`Runner` trait は同期 API(`fn run(&mut self, plan: &mut dyn Plan) -> Result<..>`)とし、
BLE ランナー内部でのみ block_on する。

### 2.5 乱数

examples の `DemoRng`(LCG)は**持ち込まない**。`smctl` は製品バイナリなので
`getrandom` ベースの `Rng` 実装(`OsRng` 相当、10 行)を `main.rs` 脇に置く。

---

## 3. コマンド実行のフロー

全コマンドは次の 3 段に正規化される(`ops.rs`):

1. **resolve** — 対象ノードのトランスポートアドレスを決める。
   - `pairing onnetwork`: `MdnsClient::build_browse_commissionable`(+ discriminator
     フィルタ)→ 最初の一致。
   - 運用コマンド: アドレス帳のキャッシュアドレスへまず CASE を試み、失敗したら
     `build_resolve_operational(compressedFabricId, node_id)` で再解決 → 帳を更新。
2. **connect** — `pairing` は `Commissioner::commission` を `drive` で回す。運用
   コマンドは `ControllerStack::start_case`(→ 将来は resumption、§4.3)。
3. **execute** — `start_read` / `start_write` / `start_invoke` を 1 本ずつ発行し、
   `settle` で静穏化(デバイス側 IM responder は同時 1 トランザクションのため、
   examples と同じく**トランザクション間で必ず ACK を流し切る**)。

1 プロセス 1 コマンドの実行モデル(chip-tool と同じ)。CASE を張り直すコストは
resumption 実装後に解消される(§4.3)。プロセス間の状態ディレクトリ排他は
lock ファイル(`state.lock`、`std::fs` の create_new)で行う。

---

## 4. 状態管理(`--state-dir`、既定 `~/.smctl/`)

```text
~/.smctl/
├── state.lock
├── ca-state.bin        # CA 鍵素材(既存フォーマット v1 をそのまま採用)
├── nodes.tlv           # ノードアドレス帳(新規、TLV versioned)
└── resume/<node-id>.tlv  # CASE resumption 素材(コア API 確定後、§4.3)
```

### 4.1 CA 永続化 — `ca-state.bin` v1 互換

`ble-commissioner.rs` の `save_ca_state`/`load_ca_state`(version=1 の TLV: root 秘密鍵・
コントローラ運用秘密鍵・IPK epoch key・fabric_id・controller_node_id・vendor_id・
next_serial)を**フォーマット変更なしで**`state/ca.rs` へ移植する。既存の
`ca-state.bin` を `--state-dir` へコピーすれば、example でコミッショニングした
デバイスを smctl からそのまま操作できる(互換性ゲート、§6 C2)。
復元は `Ca::restore`(証明書は決定的署名により鍵から再生成)。

### 4.2 ノードアドレス帳 `nodes.tlv`

コミッショニング成功時に 1 エントリ追記。versioned TLV(コアの `FabricTable::save_to`
と同じ流儀。手書きエンコーダで依存追加なし):

- `node_id: u64` — smctl が採番(帳内の最大 + 1。`pairing` の引数で明示指定も可)。
- `label: utf8`(任意、`--label`)。
- `last_addr: ip/port + 種別(udp)` — 最後に疎通したアドレス(キャッシュ。TTL 概念は
  持たず、CASE 失敗時に mDNS 再解決で上書き)。
- `discriminator / passcode は保存しない`(再コミッショニングに必要な秘密を残さない)。

運用解決は `Ca::compressed_fabric_id_bytes()` + node_id から
`<compressedFabricId>-<nodeId>._matter._tcp.local` を引く(実装済み経路)。

### 4.3 CASE resumption(実装中機能との接続)

`src/sc/` に実装中の resumption が確定したら、initiator 側が保存すべき素材
(想定: resumption ID + shared secret / SessionResumptionStorage 相当、ピア node_id
キー)を `resume/<node-id>.tlv` に置く。設計上の取り決め:

- **置き場とライフサイクル管理は smctl(アプリ層)**。コアは既存方針どおり
  in-memory + 素材の export/import API のみ(E4 の `kvs::Kvs`/`FabricTable::save_to`
  と同じ分業)。
- ファイルは 1 ノード 1 ファイル(部分更新・削除が単純)。versioned TLV。
- resumption 失敗時はフル CASE へフォールバックし、素材を上書きする。
- コア API が未確定の間(C1〜C2)は本ディレクトリを作らない。**nodes.tlv の
  スキーマに resumption を混ぜない**ことで、実装中機能の形が変わっても帳の互換性が
  壊れないようにする。

---

## 5. クラスタ拡張機構(最重要)

### 5.1 課題と候補比較

CLI に必要なのは「名前 ⇔ ID ⇔ TLV 型」の対応表:
クラスタ名 → ClusterId、属性名 → AttributeId + 値型(表示/パース用)、
コマンド名 → CommandId + フィールド列(タグ番号 + 型 + 名前)。

| 案 | 概要 | 利点 | 欠点 |
|---|---|---|---|
| (a) 静的テーブル + trait | `&'static ClusterDef` の const 配列を手書き | 型安全・`.rodata`・依存ゼロ・grep 可能 | ボイラープレートがやや多い |
| (b) 宣言マクロで 1 クラスタ 1 ブロック | (a) を `cluster_def!` マクロで生成 | (a) の利点 + 記述量最小・追加手順が定型化 | マクロの学習コスト(小)。エラーメッセージがやや不親切 |
| (c) 外部データ(JSON/TOML)駆動 | 実行時 or build.rs でデータファイルを読む | コード変更なしで追加・zap XML からの変換も可能 | 実行時パーサ + スキーマ検証が必要(依存 or 手書き大)。型対応の静的検査が消える。配布物が増える |

**推奨: (b)(実体は (a) のマクロ糖衣)**。根拠:

- リポジトリ全体が「静的 const テーブル + 依存ゼロ」路線(`dm::meta` の
  `ClusterMeta` と同型の発想)であり、(c) は方針からの逸脱が大きい。
- CLI の名前テーブルは頻繁に増えるが**形が完全に定型**なので、宣言マクロで
  「新クラスタ = 1 ファイル + レジストリ 1 行」に圧縮できる。(c) の柔軟性が
  効くのは実行時拡張が要る場合だが、ID 直指定の `any` が escape hatch として
  常にあるため、実行時拡張の需要は薄い。
- 将来 zap XML からの自動生成をやる場合も、生成先を「このマクロ呼び出し」に
  すればよく、(b) は (c) への発展を妨げない。

### 5.2 データモデル(`clusters/mod.rs`)

```rust
/// 値の型(表示とリテラルパースの両方に使う)。TlvWriter/TlvValue と 1:1。
#[derive(Clone, Copy)]
pub enum ValueKind {
    Bool,
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Utf8, Bytes,
    /// 未知/複合(struct・array 等)。表示は生 TLV ダンプ、入力は `hex:` のみ受理。
    Raw,
}

pub struct AttrDef {
    pub id: AttributeId,
    pub name: &'static str,   // kebab-case
    pub kind: ValueKind,
    pub writable: bool,
}

pub struct FieldDef {
    pub tag: u8,              // context タグ
    pub name: &'static str,
    pub kind: ValueKind,
    pub optional: bool,
}

pub struct CmdDef {
    pub id: CommandId,
    pub name: &'static str,
    pub fields: &'static [FieldDef],
}

pub struct ClusterDef {
    pub id: ClusterId,
    pub name: &'static str,
    pub attrs: &'static [AttrDef],
    pub cmds: &'static [CmdDef],
}

/// レジストリ。新クラスタ対応はここに 1 行足すだけ。
pub static CLUSTERS: &[&ClusterDef] = &[
    &on_off::DEF,
    &basic_information::DEF,
    &descriptor::DEF,
    // ...
];

pub fn by_name(name: &str) -> Option<&'static ClusterDef> { /* 線形探索 */ }
pub fn by_id(id: ClusterId) -> Option<&'static ClusterDef> { /* 結果表示の名前引きにも使う */ }
```

`ValueKind` が果たす役割:

- **入力**: `parse_literal(kind, "true") -> ParsedValue` → `TlvWriter::write_bool` 等へ
  ディスパッチ(`ImClient::start_write`/`start_invoke` のクロージャ内)。
- **出力**: Read 結果(`AttributeReportRef::Data.value()` の `TlvValue`)の表示。
  テーブルに無い属性・`Raw` は TLV を汎用ダンプ(タグ + 型 + 値の再帰表示)する。
  つまり**表示は名前テーブルが無くても常に成立**し、テーブルは可読性を足すだけ。

### 5.3 1 クラスタ 1 ファイル(マクロ糖衣)

`clusters/on_off.rs` の全文イメージ:

```rust
use super::prelude::*;

cluster_def! {
    pub DEF = cluster(0x0006, "onoff") {
        attrs {
            0x0000 => "on-off": Bool;
            // writable 属性は `mut` を付ける(例: level-control の on-level)
            // 0x0011 => mut "on-level": U8;
        }
        cmds {
            0x00 => "off" {}
            0x01 => "on" {}
            0x02 => "toggle" {}
            // フィールド付きコマンドの例(level-control move-to-level):
            // 0x00 => "move-to-level" { 0 => "level": U8; 1 => "transition-time": U16 opt; }
        }
    }
}
```

`cluster_def!` は `macro_rules!` で上記を `ClusterDef`/`AttrDef`/`CmdDef` の const に
展開するだけ(proc-macro 不要)。**新クラスタ対応の手順は「このファイルを 1 個書く +
`clusters/mod.rs` のレジストリに 1 行」で完結**し、通信コードには一切触れない。
ヘルプ・補完・結果表示・値パースはすべてレジストリから導出される。

初期収載(C3): `onoff`, `basic-information`, `descriptor`, `general-commissioning`,
`operational-credentials`, `network-commissioning`, `level-control`(デバイス側未実装でも
コントローラからの操作対象としては有効)。

### 5.4 コアの `dm::meta` との共有可否

**共有しない(ID 新型のみ再利用)**。理由:

- `dm::meta::ClusterMeta` は**デバイス(responder)側の関心事**(access 権限・quality・
  subscribable)のみを持ち、CLI に必要な**名前と値型を持たない**。名前文字列を
  `dm::meta` に足すとデバイス専用ビルドの `.rodata` を膨らませ、「デバイスビルドの
  フットプリント不変」というコア側の絶対条件(controller.md)に抵触する。
- ID の突き合わせだけが共有点であり、それは `EndpointId`/`ClusterId`/`AttributeId`/
  `CommandId` 新型の import で足りる。
- 将来 zap XML からの codegen を導入する場合、生成器の出力先を
  「コアの `ClusterMeta`(メタ)」と「smctl の `cluster_def!`(名前+型)」の 2 面に
  すれば単一ソース化できる。今それをやる必要はない。

---

## 6. 段階的実装計画

| フェーズ | 内容 | ゲート(実機) | 工数感 |
|---|---|---|---|
| **C1** 骨格 + UDP pairing + onoff | crate 新設、自前 CLI パーサ、`runner/udp.rs`+`runner/mdns.rs` 移植、`state/ca.rs`(v1 互換)+ `nodes.tlv`、`pairing onnetwork/address`、`onoff on/off/toggle`、`onoff read on-off`(名前テーブルは onoff 1 個をハードコードでよい) | `smctl pairing onnetwork 1 20202021` → `smctl onoff toggle 1 1` が `onoff-light` 相手に別プロセス・別起動で通る(= アドレス帳と CA 永続化の実証)。既存 example と同一挙動 | 1.5〜2 日 |
| **C2** 汎用 read/write/invoke + BLE | `any read/write/invoke` + 値リテラル + TLV 汎用ダンプ、`runner/ble.rs`(btleplug)、`pairing ble` / `pairing ble-handoff`(方向 B)、`discover` | (1) example の `ca-state.bin` を持ち込み `--operational` 相当の運用操作が通る(互換ゲート)。(2) `pairing ble-handoff` が chip-lighting-app 相手に完走(W4/方向 B の smctl 再現)。(3) Windows exe(cargo-xwin)で C1 ゲート再現 | 2〜3 日 |
| **C3** クラスタテーブル機構 | `cluster_def!` マクロ + レジストリ + 初期 6〜7 クラスタ、名前ベース `read`/`write`/invoke、レジストリ駆動ヘルプ、`--json` 出力(1 行 JSON、手書きエンコーダ) | 新クラスタ(例: level-control)を「1 ファイル + 1 行」で追加する PR がテーブル以外に差分ゼロであること(構造ゲート)。`basic-information read vendor-id` 実機 | 1.5〜2 日 |
| **C4** resumption + 仕上げ | `resume/<node>.tlv`(コア API 確定後)、CASE 失敗時の mDNS 再解決フォールバック、examples の整理方針決定、CI(`-p smctl` を Linux/Windows ジョブへ)、README | 2 回目以降の `onoff toggle` が resumption で高速化(コア側ゲートと共同)。CI green | 1〜1.5 日 |

各フェーズとも: 設計 doc 先行 → 実装 → 親セッションの実機検証ゲート → コミット
(既存の作業パターンに従う)。C1/C2 は既存 examples からの移植が主で新規ロジックが
薄いため、リスクは低い。

---

## 7. リスクと将来拡張

### 7.1 Subscribe

`ImClient::start_subscribe` はプライミング〜`SubscribeDone` まで動くが、確立後の
レポートは**デバイス発の新規 exchange** で届き、その受理経路がコア未実装
(controller.md §9-2)。よって `smctl subscribe` は当面提供しない
(中途半端に「プライミングだけ」を出すと誤解を招く)。コア側にレポート受理
(`ImClient` の responder 面 or 専用ハンドラ)が入った時点で
`smctl onoff subscribe on-off <node> <ep> <min> <max>`(受信を表示し続ける常駐モード)
を追加する。CLI 文法は先取りでこの形を予約しておく。

### 7.2 その他の既知リスク

- **ACL 最小 / attestation スキップ**: smctl は開発・自作デバイス用ツールであることを
  ヘルプと README に明記する。商用デバイス相手では attestation スキップにより
  コミッショニングを拒否される可能性は低い(デバイス側が検証するのはコントローラ側の
  実装)が、CD 検証なしで信頼を確立している事実は変わらない。
- **Read 結果バッファ 1280B 固定**(`ImClient<RESULT>`): ワイルドカード Read
  (`any read <node> <ep> <cluster> 0xFFFFFFFF` 等)で `ResourceExhausted` になりうる。
  smctl は `RESULT` を大きめ(例 8192)にインスタンス化して緩和し、溢れ時は
  「truncated」を明示表示する。根本対応(ストリーミング消費)はコア側の
  オープン論点(controller.md §9-3)。
- **同時 1 トランザクション**(`ImClient` slot 1 本): CLI の逐次実行モデルでは制約に
  ならないが、将来のバッチ実行(`smctl script`)では直列化が必要。
- **mDNS が IPv4 経路のみ**(examples 実証範囲): IPv6 only 環境のデバイス発見は不可。
  通信自体は dual-stack ソケットで IPv6 対応済みなので、ブラウズの AAAA/IPv6
  マルチキャスト対応が将来課題。
- **プロセスモデル**: 1 コマンド 1 プロセスは CASE 再確立コストを毎回払う。
  resumption(C4)で大幅緩和されるが、さらに詰めるならデーモン化(将来)。

### 7.3 複数 fabric / identity

`Ca` が `FabricTable<C,1>` である間は fabric 1 本固定。将来 `--fabric <name>` で
状態ディレクトリ内に複数 `ca-state` を持つ(ファイル分離だけで済む)拡張余地を
`state/` のパス設計に残す(`ca-state.bin` → 将来 `fabrics/<name>/ca-state.bin`)。

### 7.4 スクリプタビリティ(JSON 出力)

`--json` で 1 コマンド 1 行の JSON を stdout に出す(ログ類は stderr へ分離)。
例: `{"status":"ok","node":1,"path":{"endpoint":1,"cluster":6,"attribute":0},"value":true}`。
値のシリアライズは `ValueKind`/`TlvValue` からの手書きエンコーダ(依存追加なし)。
将来: `smctl script <file>`(コマンド列の一括実行)、exit code 規約の文書化。

---

## 8. 現状機能とのギャップ一覧(CLI 視点)

| # | ギャップ | 影響するコマンド | 扱い |
|---|---|---|---|
| G1 | Subscribe レポート受信(コア未実装) | `subscribe` | 非提供(§7.1)。文法のみ予約 |
| G2 | attestation 検証(Skip のみ) | `pairing` | Skip 前提を明記。将来 `--paa-store` |
| G3 | CASE resumption(実装中) | 全運用コマンドの起動コスト | C4 で統合(§4.3) |
| G4 | Read 結果 1280B 固定・非ストリーミング | ワイルドカード `read` | RESULT 拡大 + truncated 表示で緩和 |
| G5 | Timed Invoke / Timed Write 未実装 | door-lock 等の timed 必須コマンド | 将来(コア側) |
| G6 | イベント Read / EventPath 未実装 | `read-event` | 将来(コア側) |
| G7 | 複数 fabric(`FabricTable<C,1>`) | `--fabric` | パス設計のみ先取り(§7.3) |
| G8 | mDNS ブラウズが IPv4 のみ | `discover`、IPv6 only 機器 | 将来(コア + runner) |
| G9 | ノード削除(RemoveFabric)の高レベル化 | `pairing unpair` | `any invoke`(0x3E/0x0A)で代替可。C3 で opcreds テーブル収載により名前でも可能 |
| G10 | WiFi credentials の実投入(デバイス側シム) | `pairing ble-wifi` 相当 | network-commissioning コマンド送出は可能。実 join はデバイス側 E5 以降 |

いずれも smctl の骨格(§2〜§5)には影響せず、解消され次第コマンドを足すだけの
位置に置いてある。
