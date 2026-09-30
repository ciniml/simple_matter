# Web コントローラ(`smweb`)設計 — PC(Linux/Windows)で動く Matter コントローラ + ダッシュボード

対象: Tab5 コントローラアプリ(`ports/esp-idf/examples/tab5_ctrl_app`、設計
`p4-thread-controller.md` §9〜§17)と同等の「コミッショニング + 状態表示 + 操作」を、
**PC 上のクロスプラットフォーム(Windows / Linux)バイナリ**として提供する。構成は
「Matter コントローラ機能を持つ Web サーバ」で、画面は同梱 HTML/JS(ブラウザ)、
ブラウザからは HTTP(JSON)/ WebSocket API でデバイス状態を取得・操作する。

前提と制約:

- **コア(`crates/simple-matter*`)は無改造**を原則とする(§8 のギャップは別タスク)。
- **`smctl` の駆動コード(UDP/mDNS/BLE ランナー、状態ストア、クラスタ表)を再利用**する。
  そのため `smctl` をライブラリ + バイナリの 2 層に分け、`smweb` はライブラリ側に依存する
  (§3)。CLI の挙動・出力は変えない。
- 表示は「対応クラスタを持つ任意のデバイスを汎用に表示」できる作りとし(§5)、初期の
  実機検証対象は **AirQ(空気質センサ、WiFi)と NanoC6(OnOff 照明、Thread)**。
- fabric/ノード状態は `smctl` と同じ `~/.smctl/`(`--state-dir`)を共有する。ただし
  `smctl` と `smweb` の**同時実行は非サポート**(同一 controller node ID で別プロセスが
  CASE を張ると相手側セッションが揺れる。§4.4)。

実装済み資産(調査結果、2026-10-01):

| 資産 | 場所 | `smweb` での用途 |
|---|---|---|
| sans-IO コントローラ | `crates/simple-matter/src/controller/mod.rs`(`ControllerStack`: `start_pase/start_case/start_read/start_write/start_invoke/start_subscribe/start_open_commissioning_window/…`、`handle_rx/poll/next_deadline`、`im_take_event/sub_reports`) | 通信基盤(そのまま) |
| コミッショナ状態機械 | `src/controller/commissioner.rs`(`Commissioner`、`suspend_before_case`/`resume`、WiFi/Thread 資格情報投入) | pairing |
| smctl 駆動ループ | `crates/smctl/src/ops.rs`(`Exec`: 50ms read-timeout の `step_io`、`wait_txn_event`、`quiesce`、CASE キャッシュ `(node_id, SessionId)`) | コントローラスレッドの本体 |
| UDP / mDNS / BLE ランナー | `crates/smctl/src/runner/{udp,mdns,ble}.rs`(dual-stack UDP、自前 mDNS(unix: v4/v6 join、Windows: v4 QU)、btleplug central) | そのまま |
| 状態ストア | `crates/smctl/src/state/`(`ca-state.bin` / `nodes.tlv` / `resume/*.tlv` / `state.lock`) | fabric・ノード表の永続化 |
| クラスタ表 | `crates/smctl/src/clusters/`(`cluster_def!`: 名前↔ID↔`ValueKind`、約 34 クラスタ) | JSON 化・表示名・単位 |
| TLV 整形 | `crates/smctl/src/tlvfmt.rs` | 未知属性の生表示 |
| Tab5 の UI 設計 | `p4-thread-controller.md` §12(ノード種別自動判定)、§14(Dashboard)、§16(購読)、§17(窓オープン) | 画面仕様の踏襲 |

---

## 1. ゴールと非ゴール

### 1.1 ゴール

1. **単一バイナリ `smweb`**(Linux x86_64 / Windows x86_64、CI でビルド・Release 添付)。
   起動するとローカルで HTTP サーバ(既定 `127.0.0.1:8080`)を立て、ブラウザで開くと
   ダッシュボードが出る。
2. **コミッショニング**: on-network(QR/manual code または discriminator+passcode)、
   BLE→WiFi、BLE→Thread(dataset 指定)。進捗を WebSocket で逐次表示。
3. **汎用デバイス表示**: ノードごとに Descriptor(PartsList / ServerList / DeviceTypeList)
   を読み、エンドポイント×クラスタの木を作る。クラスタ表にある属性は名前・型・単位付きで
   表示、無いものは生 TLV(hex + 整形)で表示。値は Subscribe で自動更新。
4. **操作**: OnOff(On/Off/Toggle)、LevelControl、任意コマンド(ID + TLV hex)、属性書き込み。
5. **共有**: コミッショニングウィンドウを開き、manual code / QR ペイロードを表示(Tab5 T9 相当)。
6. **AirQ + NanoC6 の実機検証**: AirQ の 5 センサ値(AirQuality / CO2 / PM2.5 / 温度 / 湿度)
   のカード表示と NanoC6 の OnOff トグル。

### 1.2 非ゴール(今回)

- 認証・TLS(ローカル利用前提。`--bind` で外部公開する場合は利用者責任。§7.4 に将来案)。
- マルチ fabric / 複数コントローラ ID、ACL 編集 UI、OTA、グループ。
- Thread 経路の提供: PC は Thread に直接出られない。NanoC6 へは **OTBR(Thread Border
  Router)経由の IPv6 到達性**が必要(§8.1)。`smweb` 自体は UDP/IPv6 で話すだけ。
- Tab5 アプリの置き換え(Tab5 は継続。UI 仕様の参照元)。

---

## 2. 全体構成

```
 ブラウザ ── HTTP(JSON) / WebSocket ──┐
                                      ▼
 ┌──────────────── smweb(1 プロセス)────────────────────┐
 │  HTTP/WS サーバ(tokio + axum)                           │
 │    static: 同梱 HTML/JS/CSS(include_str!)                │
 │    REST : /api/…  → CtrlHandle(mpsc)へ Command を投げ、  │
 │           oneshot で Reply を待つ                        │
 │    WS   : /ws     ← broadcast<Event> を JSON で流す      │
 │                                                          │
 │  コントローラスレッド(std::thread、1 本、同期)           │
 │    smctl::Exec 相当のループ: UDP recv(50ms) → handle_rx  │
 │      → poll → 送信 → 購読レポート回収 → Command 1 件処理 │
 │    ControllerStack(sans-IO)を専有                        │
 │    状態ストア(~/.smctl)を読み書き                        │
 │  BLE ランナー(feature ble、btleplug、pairing 中のみ)     │
 └──────────────────────────────────────────────────────────┘
```

- **スレッド分離の理由**: `ControllerStack` は sans-IO・単一所有者で、`ImClient` の
  トランザクションは同時 1 本(`Error::NoSpace` = Busy)。HTTP 側の並行性は
  「コマンドキュー(mpsc)で直列化」し、コントローラスレッドは 1 本に固定する
  (Tab5 の「pump が sm_ctrl を専有、UI は操作キュー + スナップショット」と同じ形)。
- **同期/非同期の境界**: コントローラスレッドは `smctl` と同じ同期 `std::net`。
  HTTP は tokio。橋渡しは `std::sync::mpsc`(Command)+ `tokio::sync::oneshot`(Reply)
  + `tokio::sync::broadcast`(Event)。tokio 側は `spawn_blocking` を使わず、
  送信だけして待つ。
- **状態のスナップショット**: ブラウザが初期表示に使う「全ノードの最新値」は
  コントローラスレッドが `Arc<RwLock<Snapshot>>` に書き、REST はそれを読むだけ
  (コントローラを待たない)。

---

## 3. クレート構成と `smctl` のライブラリ化

```
crates/smctl/        既存。src/lib.rs を追加し、以下を pub にする(挙動不変):
  runner::{udp, mdns, ble}   ソケット/BLE ランナー
  state::{ca, nodes, resume, lock}   状態ストア
  clusters                    クラスタ表(名前・ID・ValueKind・単位)
  tlvfmt                      TLV 整形
  ops::Exec(+ 必要な pub fn)  駆動ループ(§4.1 の拡張)
  main.rs は lib を使う薄いバイナリに(CLI パーサ cli.rs は残す)
crates/smweb/        新規バイナリ。
  Cargo.toml: smctl(lib, features 継承)、tokio(rt-multi-thread, macros, sync)、
              axum 0.7(ws)、serde/serde_json、tracing(任意)
  src/main.rs       引数(--bind, --state-dir, --paa-trust-store-path, --bypass-attestation, --log)
  src/ctrl.rs       コントローラスレッド(Command/Reply/Event、ループ)
  src/api.rs        REST ハンドラ(JSON 型は serde)
  src/ws.rs         WebSocket(broadcast → JSON)
  src/model.rs      Node/Endpoint/Cluster/Attribute の表示モデルとスナップショット
  src/static/       index.html, app.js, app.css(include_str! で同梱)
```

- `smctl` の JSON 出力(手書き `json.rs`)は CLI 互換のため残す。`smweb` の API 型は
  serde で別に定義する(§6)。
- feature: `smweb --features ble` で BLE pairing を有効化(`smctl` と同じ。btleplug は
  Windows WinRT / Linux BlueZ)。CI と Release は `ble` 有効でビルドする。

---

## 4. コントローラスレッド

### 4.1 ループ

`smctl::ops::Exec` の `step_io` / `wait_*` / `quiesce` を再利用し、1 反復を次にする:

1. UDP recv(50ms timeout)→ `handle_rx` → 送信。
2. `poll(now)` → 送信。`next_deadline` は 50ms 粒度で十分。
3. `im_take_event` を空になるまで回収:
   - `SubscriptionReport` → `sub_reports()` を走査し、`(node, ep, cluster, attr)` ごとに
     値を JSON 化(§5.3)→ Snapshot 更新 + `Event::Attr` を broadcast。
   - `SubscriptionLost` → Snapshot に `stale=true`、`Event::SubLost`、再購読を Command
     キューの末尾に自己投入(Tab5 T8 の「LOST で即再購読」)。
   - `ReadDone/WriteDone/InvokeDone` → 実行中 Command の Reply。
4. Command キューから **1 件**取り出して開始(実行中があれば取り出さない)。
   長時間 Command(pairing ≈ 15〜20 s)は `Event::Progress` を段階ごとに流す。
5. mDNS 受信(運用アドレス解決の応答)を `runner::mdns` 経由で処理。

### 4.2 Command / Reply / Event

```
Command::Pair{ method: OnNetwork{code|disc+passcode}, BleWifi{code, ssid, pass},
               BleThread{code, dataset_hex}, Address{ip, port, passcode}, node_id: Option<u64> }
Command::Unpair{node_id}
Command::Discover{Commissionable|Operational(node_id)}
Command::Describe{node_id}            // Descriptor 木の取得(§5.1)
Command::Read{node_id, ep, cluster, attr}
Command::Write{node_id, ep, cluster, attr, value: Json}
Command::Invoke{node_id, ep, cluster, cmd, args: Json | tlv_hex, timed_ms: Option<u16>}
Command::Subscribe{node_id, paths: Vec<Path>, min_s, max_s}
Command::Unsubscribe{node_id, sub_id | all}
Command::OpenWindow{node_id, timeout_s, discriminator: Option<u16>}  // 既定: 乱数 passcode + 既定 disc
Command::Revoke{node_id}
Reply = Result<Json, ApiError{code, message, im_status: Option<u8>}>
Event::Attr{node_id, ep, cluster, attr, value: Json, raw_hex, data_version, ts}
Event::SubLost{node_id, sub_id} / Event::SubReady{node_id, sub_id}
Event::NodeState{node_id, state: Online|Stale|Offline, addr}
Event::Progress{op_id, phase: String, detail}   // pairing/描画用
Event::Log{level, msg}
```

### 4.3 ノードのライフサイクル

- 起動時に `nodes.tlv` を読み、各ノードを `Offline` で Snapshot に載せる。
- 「接続」= 運用 mDNS 解決(`discover operational` 相当)→ CASE(resumption 優先)→
  `Describe` → 種別ごとの既定購読(§5.2)。起動時に全ノードへ順に実行し、
  失敗したノードは 60 s 後に再試行(バックオフ最大 10 分)。
- Tab5 の P6/P7(死んだセッションの無効化、購読 ID の `(session, id)` 照合)は
  コアで解決済みなので、`smweb` は `SubscriptionLost` と op タイムアウトで
  `Offline` に落として再接続するだけにする。

### 4.4 状態ストアの共有

- `~/.smctl/` を共有。`state.lock` は読み書き区間だけ保持(`smctl` と同じ)。
- 起動時に `smctl` プロセスが動いていても検出はしない。README に「同時実行不可」と明記。
- `nodes.tlv` に **表示ラベルと最終アドレス**は既にある。`smweb` 用の追加情報
  (種別キャッシュ、ユーザーが選んだ購読パス)は別ファイル `smweb.json`(serde)に置き、
  `nodes.tlv` のフォーマットは触らない。

---

## 5. 汎用デバイスモデルと表示

### 5.1 Describe(構造の取得)

1. `Descriptor(0x001D)` を EP0 で読む: `PartsList(0x0003)` → 全 EP、各 EP の
   `DeviceTypeList(0x0000)` と `ServerList(0x0001)`。
2. `BasicInformation(0x0028)`: VendorName / ProductName / NodeLabel / SerialNumber /
   SoftwareVersionString。
3. 各 EP × ServerList のクラスタについて、クラスタ表(§5.3)に載っていれば
   `AttributeList(0xFFFB)` を読んで属性一覧を確定する(表にない属性 ID も列挙する)。
   表に無いクラスタは ID のみ表示(展開時に AttributeList を読む)。
4. 結果を `NodeModel{ endpoints: [ {ep, device_types, clusters: [ {id, name?, attrs: [...]}]}]}`
   として Snapshot に保存し、`smweb.json` にキャッシュ(再起動時の初期表示用。値は
   含めない)。

### 5.2 既定購読(ダッシュボード用)

Tab5 T4/T8 の種別判定を踏襲する:

| 種別判定 | 条件 | 既定購読パス |
|---|---|---|
| SENSOR | どこかの EP に AirQuality(0x005B) | AirQuality.AirQuality、CO2(0x040D).MeasuredValue、PM2.5(0x042A).MeasuredValue、Temperature(0x0402).MeasuredValue、RelativeHumidity(0x0405).MeasuredValue(存在する EP を Describe から決める) |
| LIGHT | OnOff(0x0006)あり | OnOff.OnOff、(あれば)LevelControl.CurrentLevel、ColorControl 主要属性 |
| その他 | 上記以外 | 購読なし。ユーザーが属性を選んで「ウォッチ」(§5.4) |

購読は **ノード 1 本**(複数パス、min 0 / max 60 s)にまとめる(デバイス側 SUBS=3 の制約。
AirQ は Apple/Alexa/Google + smweb で上限に当たり得るため、1 本厳守)。

### 5.3 値の JSON 化

- クラスタ表の `ValueKind`(Bool/U8..U64/I8..I64/F32/Utf8/Enum/Raw)に従って JSON 値へ。
  単位・スケール(温度 ×0.01 ℃、湿度 ×0.01 %)はクラスタ表に **表示ヒント**として
  追加する(`unit`, `scale`)。列挙(AirQuality の 0..6)は表示名表を持つ。
- 表に無い属性は `{ "raw": "<hex>", "pretty": "<tlvfmt 出力>" }`。
- 属性ごとに `data_version` と受信時刻を保持し、UI は "updated N s ago" を出す(Tab5 T6)。

### 5.4 画面(単一ページ)

1. **Dashboard**(既定): ノードごとのカード。SENSOR は 5 タイル(しきい値で色分け、
   Tab5 T6 と同じ閾値)、LIGHT は状態 + Toggle ボタン。オフライン/stale はグレー。
2. **Devices**: ノード一覧(NodeId、ラベル、種別、アドレス、状態)。行を開くと
   Describe の木(EP → クラスタ → 属性)を表示し、属性の「読む」「書く」「ウォッチ」、
   クラスタのコマンド実行(表にあるものは名前と引数フォーム、無いものは TLV hex)。
   「Share」でウィンドウを開き manual code / QR(payload 文字列 + QR 画像は JS で生成)を表示。
3. **Pair**: on-network(QR/manual code 貼り付け or disc+passcode)、BLE-WiFi(SSID/pass)、
   BLE-Thread(dataset hex)、アドレス直指定。進捗ログを WS で表示。
4. **Log**: `Event::Log` のテール。

JS は依存なしの素の ES2020(ビルド工程を持たない)。QR 生成のみ小さな同梱ライブラリ
(MIT、単一ファイル)を許容する。

---

## 6. HTTP / WebSocket API

すべて JSON。エラーは `{ "error": { "code": "busy|timeout|im_status|not_found|bad_request", "message": "...", "im_status": 0x.. } }`。

| メソッド | パス | 内容 |
|---|---|---|
| GET | `/` , `/app.js`, `/app.css` | 同梱 UI |
| GET | `/api/info` | バージョン、state-dir、fabric ID、controller node ID、feature(ble) |
| GET | `/api/nodes` | ノード一覧(Snapshot: id, label, kind, addr, state, last_seen) |
| GET | `/api/nodes/{id}` | Describe 結果 + 最新値(Snapshot) |
| POST | `/api/nodes/{id}/connect` | 解決 + CASE + Describe + 既定購読(手動再接続) |
| DELETE | `/api/nodes/{id}` | unpair(RemoveFabric)+ nodes.tlv から削除 |
| PATCH | `/api/nodes/{id}` | `{label}` の更新 |
| GET | `/api/nodes/{id}/attr/{ep}/{cluster}/{attr}` | 都度 Read(`?raw=1` で生 TLV も) |
| PUT | 同上 | Write `{ "value": <json> }` または `{ "tlv": "<hex>" }` |
| POST | `/api/nodes/{id}/invoke/{ep}/{cluster}/{cmd}` | `{ "args": {...} \| "tlv": "<hex>", "timed_ms": n }` |
| POST | `/api/nodes/{id}/watch` | `{ "paths": [ {ep,cluster,attr} ] }` を既定購読に追加(`smweb.json` に保存) |
| DELETE | `/api/nodes/{id}/watch` | 同上を解除 |
| POST | `/api/nodes/{id}/window` | `{ "timeout_s": 900 }` → `{ "manual_code", "qr_payload", "discriminator", "passcode", "expires_at" }` |
| DELETE | `/api/nodes/{id}/window` | Revoke |
| POST | `/api/pairing` | `{ "method": "onnetwork\|ble-wifi\|ble-thread\|address", "code"?, "discriminator"?, "passcode"?, "ssid"?, "password"?, "dataset"?, "ip"?, "port"?, "node_id"?, "label"? }` → `{ "op_id" }`(進捗は WS) |
| GET | `/api/discover/commissionable` | 5 秒スキャン結果 |
| GET | `/api/clusters` | クラスタ表(名前・属性・コマンド・ValueKind・単位)を UI に渡す |
| WS | `/ws` | 接続直後に `{"type":"snapshot", ...}` を 1 回送り、以後 `Event` を JSON で流す |

- `POST /api/pairing` はキュー投入で即返し、完了は `Event::Progress{phase:"done"|"failed"}`。
  他の Read/Write/Invoke は同期(コントローラの Reply を最大 `--timeout`、既定 20 s 待つ)。
- 同時実行制御: HTTP 側は Command をキューに積むだけ。キューが `N`(既定 32)を超えたら
  `busy`。

---

## 7. 実装分割と検証

### 7.1 ピース

- **W1: `smctl` ライブラリ化 + `smweb` 骨格**  
  `crates/smctl/src/lib.rs`(pub 化のみ、CLI の挙動・出力不変)、`crates/smweb` に
  コントローラスレッド + `/api/info` `/api/nodes` `/api/nodes/{id}/attr` `/invoke` +
  静的ページ(ノード一覧と生 Read)。検証: `smctl` の既存テストが全通過、`smweb` で
  AirQ の BasicInformation を読める。
- **W2: 購読 + WebSocket + Dashboard**  
  Describe、種別判定、既定購読、`Event::Attr`、Dashboard カード(SENSOR 5 タイル、LIGHT
  Toggle)。検証: AirQ の値が 10 秒周期で更新、NanoC6 のトグルが反映(§8.1 の経路が要る)。
- **W3: Pairing + Share**  
  on-network / BLE-WiFi / BLE-Thread / address、進捗表示、ウィンドウ開閉 + QR。検証:
  AirQ を NVS 消去からブラウザだけでコミッショニング、Share から Tab5 で 2 fabric 目。
- **W4: Windows + CI/Release**  
  Windows 実機(BLE = WinRT、mDNS = v4 QU)で W1〜W3 を確認。`ci.yml`/`release.yml` に
  `smweb`(ble)を追加し、Release バンドルへ同梱。README(`docs/README-demos.md`)に使い方。

### 7.2 検証ゲート(各ピース)

`cargo fmt --check` / `cargo test --workspace` / `cargo clippy -p smctl -p smweb --all-targets
--all-features -D warnings` / Windows は CI の `cargo build -p smweb --features ble`。
コアは無改造なので no_std ゲートは既存のまま。

### 7.3 テスト方針

- `smweb` の API 型と値 JSON 化はユニットテスト(クラスタ表 → JSON、Raw フォールバック)。
- コントローラスレッドは `smctl` と同様に実機 E2E で検証(AirQ、NanoC6)。E2E 手順は
  JOURNAL に記録し、`docs/README-demos.md` に再現手順を載せる。
- ブラウザ UI はスクリーンショットでの目視確認(Tab5 T5c と同様に人手)。

### 7.4 将来

- 認証(トークン)+ TLS、`--bind 0.0.0.0` 時の警告。
- イベント購読(Subscribe events)と履歴グラフ(時系列は `smweb.json` ではなく SQLite 等)。
- Tab5 と同じ「カメラ QR」の代わりに、ブラウザのカメラ(`getUserMedia` + jsQR)で QR 読取。

---

## 8. オープンな論点・ギャップ

### 8.1 NanoC6(Thread)への到達経路 — **要決定**

PC には Thread インタフェースが無く、Tab5 は OpenThread リーダ + SRP サーバではあるが
**WiFi↔Thread の IPv6 ルーティングは提供していない**(`p4-thread-controller.md`、JOURNAL
「PC から Thread への経路が無い」)。選択肢:

- (a) **OTBR を用意する**(ESP Thread BR、または Raspberry Pi + RCP)。PC は OTBR が広告する
  Thread メッシュの ULA へ経路を得て、mDNS は OTBR の SRP→mDNS 代理広告で解決する。
  `smweb` 側の変更は不要(運用アドレスが ULA になるだけ)。
- (b) NanoC6 を WiFi 構成(`onoff_light_cpp` の WiFi ビルド、または AirQ と同じ経路)で
  検証対象にする。初期検証を早く回せるが、Thread の実証にはならない。
- (c) Tab5 に BR 機能(OTBR 相当)を足す。工数大、別タスク。

推奨: **初期は (b)** で `smweb` の機能を固め、並行して (a) の環境を用意して Thread を確認。

### 8.2 `ImClient` の同時トランザクション 1 本

Describe(複数 Read)や複数ノードの初期接続はキュー直列化で遅くなる(ノードあたり数百 ms
× 属性数)。W2 で体感が悪ければ、`ImClient` の同時トランザクション数をコアで増やす
(`controller.md` §4 の将来項目)。本設計はまず直列で成立させる。

### 8.3 Windows の mDNS(IPv4 QU のみ)

運用アドレスが IPv6 link-local の場合、Windows では v4 の A レコード経由で到達する
(`port-windows-commissioner.md` §3.3)。IPv6 のみで広告するデバイスには届かない。
AirQ は IPv4 も持つため初期検証は通る見込み。

### 8.4 `docs/README-demos.md` の attestation 記述の食い違い

README は「未指定ならスキップ」と書くが、コードの既定は `VerifyNoPaa`。W4 の README 更新で
直す(`smweb` も同じ既定・同じフラグにする)。
