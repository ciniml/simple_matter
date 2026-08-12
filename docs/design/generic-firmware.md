# 汎用 Matter ファームウェア構想(設定駆動 + スクリプト)

Status: 実装中。**決定(2026-08-12、ユーザ確定): 実行系 = WASM(WAMR)、
スコープ = G1-G4 + Web Configurator**。実装仕様は §9、進捗は §10。
Depends: docs/design/c-ffi-shim.md(§8 F4b CustomCluster、§10 Thread)、docs/design/factory-data.md

## 1. ゴール

1 つのビルド済みファームウェアで、以下を**再ビルド無しに**変えられるようにする:

- **G-A: クラスター構成**(エンドポイント数、デバイスタイプ、搭載クラスタ)
- **G-B: クラスタ⇔ハードウェアのマッピング**(OnOff→GPIO、LevelControl→PWM、
  温度計測→I2C センサ、等)
- **G-C: ちょっとしたロジック**(スクリプト)の実行と、その **OTA 更新**

先行事例は Tasmota(ESP32 汎用 FW: GPIO テンプレート + Berry スクリプト)と
ESPHome(YAML→再ビルド型なので G-A/B の反面教師)。本構想は「Tasmota の Matter 版を
simple-matter の小フットプリントで」に相当する。

## 2. 前提: simple-matter の静的アーキテクチャとの折り合い

コアのデータモデルは静的(heapless、コンパイル時容量、`&dyn ServerCluster` 合成)。
「完全動的なクラスタロード」はコア設計と衝突するが、**その必要はない**:

- **スーパーセット方式**: 実装済みサーバクラスタ 32 種(On/Off、Level、Color、
  Thermostat、Door Lock、センサ計測系…)を全部コンパイルインし、**起動時に設定から
  合成**する。C FFI シムは既にエンドポイント合成を実行時に行っている
  (`ep_servers` heapless 構築、上限 `MAX_EP_TOTAL`/`MAX_SERVERS` のみコンパイル時)。
- **CustomCluster(F4b)**: attr/cmd メタを実行時に与えられる汎用クラスタ vtable が
  シムに既在。read/write/invoke は関数ポインタ委譲なので、**「スクリプトで実装された
  クラスタ」を再ビルド無しで追加**する受け皿になる(標準に無いクラスタも可)。

つまり不足しているのは「設定スキーマ」「HAL バインディング層」「スクリプト実行系」の
3 つで、**コア(crates/simple-matter)は原則無改造**で成立する見込み。
アプリは ESP-IDF C++(C FFI シム)経路を主とする(Thread 品質最良・
スクリプト処理系の生態系が揃う。§6)。

## 3. 全体構成

```
┌────────────────────────────── 汎用 FW(ESP-IDF C++17)──────────────────────────────┐
│  設定 blob(NVS/factory)          スクリプト(NVS/専用パーティション)                │
│      │                                  │                                            │
│      ▼                                  ▼                                            │
│  ① 合成器(boot 時)              ③ スクリプト VM(フック実行)                     │
│      │  endpoints/クラスタ選択          │ on_command/on_attr_write/on_timer/...       │
│      ▼                                  ▼                                            │
│  simple-matter C FFI シム ◄──── ② HAL バインディング層(GPIO/PWM/I2C/ADC/UART 表)  │
│  (sm_init + CustomCluster)              │                                            │
└──────────────────────────────────────────┼────────────────────────────────────────────┘
                                           ▼ 実ハードウェア
```

## 4. G-A: 設定駆動のクラスタ構成

- **設定 blob**(CBOR or 素朴な TLV。JSON はパーサ・断片化コスト非優先):
  ```
  device:   { vid, pid, discriminator, verifier, network: wifi|thread|eth }
  endpoints: [
    { id: 1, device_type: 0x0101(dimmable-light),
      clusters: [ {id: OnOff, bind: b1}, {id: LevelControl, bind: b2} ] },
    { id: 2, device_type: 0x0302(temp-sensor),
      clusters: [ {id: TempMeasurement, bind: b3} ] },
  ]
  bindings: [ b1: {drv: gpio, pin: 5, invert: false},
              b2: {drv: ledc, ch: 0, pin: 6, freq: 1000},
              b3: {drv: i2c_sht30, sda: 8, scl: 9, poll_ms: 5000} ]
  ```
- 格納: 工場設定は factory パーティション(既存 factory-data 経路に相乗り)、
  運用変更は NVS。**変更は再起動で反映**(Matter 的にもエンドポイント構成変更は
  再起動が自然。descriptor/PartsList は boot 時合成で自動整合)。
- 設定の投入経路: ① シリアル/コンソール(初期)、② 専用 CustomCluster
  (vendor cluster "DeviceConfig")経由で chunked write(運用)。
- 制約(明記): クラスタ**実装**の追加は再ビルド(スーパーセットに無いものは
  CustomCluster+スクリプト実装で逃がす)。容量上限(最大 EP 数・クラスタ数/EP)は
  コンパイル時定数 — 汎用 FW では余裕を持たせる(例: EP 8 × クラスタ 12)。

## 5. G-B: HAL バインディング層

- 小さなドライバ表: `drv` 名 → 初期化/読み/書きの関数群(C++)。初期セット:
  - `gpio`(OnOff、BooleanState/占有センサ入力)
  - `ledc`(LevelControl。ガンマ/フェードは ESP-IDF LEDC のフェード機能)
  - `rmt_ws2812` / `ledc_rgb`(ColorControl)
  - `i2c_*` センサ(温湿度/照度/CO2 等。poll_ms 周期で属性へ push)
  - `adc`、`uart_raw`(スクリプトから使う生口)
  - `script`(バインディング先がドライバでなくスクリプトフック = 変則ハードは
    スクリプトで吸収)
- 既存クラスタ実装は「値の保持と IM 応答」をコアが、「副作用」をアプリ callback が
  持つ構造(cffi の on_off change callback 等)なので、バインディング層は
  **callback の集線と dispatch** に徹する。コア改造不要。

## 6. G-C: スクリプト実行系の比較と推奨

要件: C6 クラス(flash 4MB / RAM 512KB、アプリ既に約 1.1〜1.5MB)に収まり、
フック駆動の短いロジック(単位: ms〜数十 ms)、OTA で差し替え可能、
Matter タスク(単線ポンプ)をブロックしない。

| | **Lua 5.4** | **Berry** | **MicroPython** | **WASM(WAMR/wasm3)** |
|---|---|---|---|---|
| flash 追加(目安) | 〜150-250KB | **〜40-80KB** | 〜600KB-1MB+ | 〜85-150KB(VM のみ) |
| RAM(VM+小スクリプト) | 数十 KB | **〜10-20KB** | 100KB 級 | 線形メモリ固定(例 64KB)+VM |
| 記述言語 | Lua | Berry(Lua 風) | Python | Rust/C/TinyGo/AssemblyScript |
| 隔離/サンドボックス | ○(専用 lua_State、危険 lib 非搭載で閉じる) | ○(同左) | △(組込 API 露出管理が大変) | **◎(能力ベース import、メモリ隔離)** |
| OTA 配布物 | .lua テキスト(or luac) | .be テキスト | .py/.mpy | .wasm(**署名検証と相性最良**) |
| 実行速度 | 速い(組込最速級) | 十分 | 遅め+GC 停止 | interp で Lua 並、AOT で数倍 |
| ESP-IDF 統合 | ◎(素の C、実績多数) | ◎(Tasmota 実績) | △(embed port は重め) | ○(WAMR は Espressif 公式 component あり) |
| 利用者体験 | ○(周知) | ○(Lua 風+組込向け設計) | **◎(最人気)** | △(コンパイル必須、"ちょっとした"に重い) |

**推奨: 第一候補 = Lua 5.4**。理由: (a) 組込みの実績・資料・人材が最も厚く、
"ちょっとしたスクリプト" の編集→転送→即反映(テキストのまま)という体験が最短、
(b) フットプリントが本プロジェクトの思想と整合、(c) C API が単純で HAL/Matter API の
公開が薄く書ける、(d) 協調的な実行(フック 1 回=短時間で返る規約 + 命令数
フック `lua_sethook` で暴走スクリプトを強制中断)が容易。
さらに削りたければ **Berry**(Tasmota が同一ユースケースで実証済み)が有力な代替。

**WASM(WAMR)を選ぶ条件**: サードパーティ配布スクリプトを走らせる等、
**強い隔離と署名付き配布**が要件になる場合。その際は Espressif 公式の WAMR
component を使い、ホスト関数を能力ベースで渡す。MicroPython は「エンドユーザに
Python を書かせる」ことが製品価値になる場合のみ(S3/P4 の flash 潤沢構成限定)。

補足(WASM の開発体験): 「コンパイル必須」の摩擦は**ブラウザ内コンパイル**で
緩和できる。AssemblyScript はコンパイラ(asc)自体が TypeScript 製でブラウザ内で
完結する(公式 playground 方式)ため、静的 Web ページ 1 枚
(エディタ+API 型定義+asc)で「ブラウザで書く→その場で .wasm→ScriptStore 転送」が
サーバ無しで成立する。C/C++(clang の WASM 化)は重く、Rust/TinyGo は実質
サーバサイドコンパイルが要る。よって WASM 採用時のスクリプト言語は
AssemblyScript を第一候補とする。

**オフライン開発なら Rust も第一級**: ブラウザ内コンパイル不可なだけで、ローカルでは
`wasm32-unknown-unknown` ターゲット + ホスト API の extern 宣言クレート
(`sm-script-api`、フックは `#[no_mangle] extern "C"` export)で普通の cargo
プロジェクトとして書ける。`#![no_std]` + panic-abort + opt-z + wasm-opt で数 KB 級。
デバイス側 VM は言語非依存なので、**ブラウザ AssemblyScript(カジュアル)と
オフライン Rust(本格・テスト付き)が同一 ABI で共存**する。API クレートの型は
コアの ClusterId 等から生成でき、simple-matter 本体との相性も良い。

注: 純 Rust(esp-hal)経路に載せる場合は C ランタイム持ち込みが苦しいため
`wasmi`(Rust 製 WASM interp)がほぼ一択になる。汎用 FW は ESP-IDF 経路を主とし、
Rust 経路は対象外とする(必要になった時点で wasmi で再検討)。

### 6.1 フックポイントと公開 API(最小)

- フック: `on_boot()` / `on_command(ep, cluster, cmd, args)` /
  `on_attr_write(ep, cluster, attr, val)` / `on_timer(id)` / `on_sensor(bind, val)`
- API: `matter.get/set(ep, cluster, attr)`(属性の読み書き=イベント/subscribe 反映は
  コアが面倒を見る)、`hw.gpio/pwm/i2c/adc/uart`、`timer.every/after`、`log()`、
  `kvs.get/set`(スクリプト用の名前空間)
- 実行モデル: Matter ポンプと**同一タスクでフックを同期実行**(単線契約を維持)、
  1 フックあたり命令数上限(sethook)+壁時計上限で打ち切り。長い処理は
  timer 分割をスクリプト側の規約とする。

### 6.2 スクリプト OTA

- **短期(Matter OTA 未実装の現状)**: vendor CustomCluster "ScriptStore" を定義し、
  chunked write(begin/data/commit、CRC32 + サイズ検証)→ NVS(小)or 専用
  パーティション(大)へ格納 → commit で VM 再ロード。旧版は 1 世代残して
  ロード失敗時ロールバック。smctl の `any invoke`/batch でそのまま運用できる。
- **長期**: Matter OTA(+BDX)実装後(Matter 1.3 残項目)、FW イメージ更新と
  スクリプト束更新を別 OTA イメージ種別として扱うか、FW に既定スクリプトを
  同梱し ScriptStore を上書き層とする 2 層構成にする。
- 署名: 短期は Matter セッション(CASE+ACL Administer)を投入経路の認可として
  信頼。配布物署名(公開鍵を factory data に置く)は WASM 採用時 or 配布
  エコシステムを作る段階で導入。

## 6.3 Web Configurator(ブラウザ配布・プロビジョニングツール)

構成選択 → 書き込み → 個体プロビジョニングまでを**静的ページ 1 枚(サーバ無し)**で行う:

1. **構成選択 UI** → 設定 blob(CBOR)生成。FW はチップ別ビルド済みイメージ
   (静的アセット)なのでコンパイル不要(ESPHome との差別化点)。
2. **書き込み**: esptool-js(Web Serial、Espressif 公式)で app + 設定 + スクリプト +
   factory の各パーティションを一括 flash。Chrome/Edge 系限定。
3. **個体情報生成**(全てクライアントサイド): discriminator/salt/passcode 乱数 →
   SPAKE2+ verifier(PBKDF2 = WebCrypto、P-256 = noble-curves)→
   **mfg_tool 互換 NVS バイナリ**にエンコード(nvs_partition_gen の JS 移植)。
   simple-matter の factory-data パーサがそのまま読むため FW 側無改造。
   デバイスへは verifier のみ(規格準拠)。JS 実装の正しさは smctl `pase-verifier`
   出力とのベクタ照合で担保する。
4. **QR + MPC 表示**: onboarding payload TLV → Base38(`MT:`)、Manual Pairing Code
   (11/21 桁 + Verhoeff チェックディジット)。ラベル印刷まで同ページで。
5. **スクリプト**: WASM 採用時は AssemblyScript エディタ+ブラウザ内コンパイル(§6 補足)を
   同居させ、.wasm をスクリプトパーティションに含めて一括書き込み。Lua 採用時は
   テキストをそのまま同梱(さらに単純)。
6. DAC はテスト PAI 鍵同梱の開発用(テスト鍵は公開物 = 開発専用と明記。R-G5)。

前提はG1(設定 blob)のみ。初回書き込みはパーティション直書きなので
G4(ScriptStore OTA)にも依存しない。

## 7. 段階計画(実装フェーズ案)

| フェーズ | 内容 | ゲート |
|---|---|---|
| **G1** | 設定 blob スキーマ+boot 時合成(スーパーセット FW、ESP-IDF C++) | 設定差し替えのみで onoff-light ⇔ dimmable+温度計 2EP に変身、chip-tool/smctl で descriptor 整合 |
| **G2** | HAL バインディング層(gpio/ledc/i2c 初期セット) | 実機: 設定変更だけで GPIO ピン付け替え・PWM 化 |
| **G3** | Lua VM 統合+フック+公開 API(script バインディング) | ループバック+実機: スクリプトで変則ハード(例: モーメンタリスイッチのトグル化)を実装 |
| **G4** | ScriptStore CustomCluster(chunked 転送、ロールバック) | smctl batch でスクリプト OTA → 再ロード → 動作変化を実機確認 |
| **G5** | Matter OTA(+BDX)との統合(コア側の残項目に着手する場合) | chip-tool OTA provider 相互 |

## 8. リスク・未決

- **R-G1**: 設定でクラスタ構成を変えると Matter 的には「別デバイス」になり得る
  (device type / DeviceTypeList 変更)。コミッショニング済み fabric との整合は
  「構成変更=factory reset を推奨、少なくとも descriptor 変更の告知(BasicInformation
  ConfigurationVersion 相当)」の運用規約を決める必要がある。
- **R-G2**: CustomCluster の現行上限(クラスタ 8 / EP 4 / attr 16)はスクリプト実装
  クラスタの受け皿としては要拡張(コンパイル時定数の引き上げで済む)。
- **R-G3**: Lua の GC 停止は数 KB ヒープでは µs〜ms オーダで実害は薄い見込みだが、
  フック内で大量アロケーションするスクリプトへの防御(メモリ上限付き custom
  allocator)は G3 で必須。
- **R-G4**: NVS の書換耐性。スクリプト頻繁更新は専用パーティション+ウェアレベリング
  (esp_partition 直 or littlefs)へ。
- **R-G5**: 汎用 FW は attestation と相性が悪い(VID/PID が設定次第)。開発・自家用
  前提とし、製品化時はクラスタ構成ごとに CD/DAC を焼き分ける前提を明記する。

## 9. 実装仕様(フェーズ A〜E)

### 9.1 Phase A: シム composition モード(G1 の実体)

現行デバイスシムは「OnOff ライト固定 + CustomCluster 追加」なので、コア実装済み
クラスタの**任意合成**をシムに追加する。コア(crates/simple-matter)は無改造。

- **FFI**: `sm_config_t` に `composition`/`composition_len`(NULL = 従来の固定
  ライト構成 → 既存 example 完全互換)。composition は **Matter TLV**
  (コアの tlv モジュールを流用。JSON/CBOR は使わない):
  ```
  anonymous list of endpoint structs:
    { 0: endpoint-id u16, 1: device-type u32, 2: device-type-rev u8,
      3: cluster list [u32...], 4: options(cluster ごとの初期値, optional) }
  ```
- **合成可能クラスタの初期プール**(static、コンパイル時上限): OnOff×8、
  LevelControl×4、ColorControl×2、BooleanState×4、OccupancySensing×2、
  Temperature/RelativeHumidity/Illuminance/Pressure/FlowMeasurement×各 4、
  Switch×4、FanControl×2、DoorLock×1、Thermostat×1。EP0(システムクラスタ)は
  固定のまま。最大 EP 8。CustomCluster(F4b)は併用可(WASM 実装クラスタ用)。
- **汎用値アクセス FFI**(HAL バインディングとスクリプトの共通口):
  - `sm_attr_set_value(ep, cluster, attr, const sm_attr_value_t*)`(センサ値 push 等)
  - `sm_attr_get_value(ep, cluster, attr, sm_attr_value_t*)`
  - `sm_config_t.on_cluster_change(user, ep, cluster, attr, const sm_attr_value_t*)`
    (IM write / コマンドで状態が変わったら発火。既存の個別 callback は互換維持)
  - 値表現は custom.rs の `sm_attr_value_t`(型付きスカラ)を流用。
- ゲート: ホストテスト(composed 構成の commissioning+read/write/subscribe E2E)、
  ctest(composed light を controller とペア)、ヘッダ再生成冪等、riscv32imac ビルド。

### 9.2 Phase B: `generic_matter_cpp` example(G1+G2)

- NVS namespace `smgen`: `comp`(composition TLV)/ `bind`(binding TLV)。
  無ければ既定(EP1 OnOff light + gpio)。変更は再起動反映。
- binding TLV: `[{ 0: ep, 1: cluster, 2: drv-id u8, 3: params(drv 固有) }]`。
  初期ドライバ: `gpio_out`(OnOff→pin/invert)、`gpio_in`(BooleanState/Switch、
  ポーリング+デバウンス)、`ledc`(LevelControl→ch/pin/freq、ガンマ)、
  `i2c_sht30`(Temp/Humidity poll_ms)、`script`(Phase C のフックへ委譲)。
- esp_console: `cfg-comp <hex>` / `cfg-bind <hex>` / `cfg-show` / `restart`
  (Configurator 完成前のテスト経路)。
- ベース: onoff_light_cpp(WiFi/BLE/128KB スタック/KVS 配線を踏襲)。
- パーティション: app 2.5MB / nvs / factory(NVS 形式)/ `smscript`(raw 256KB)。
- ゲート: docker esp32c6 ビルド green + 既存 2 example 回帰。実機はユーザ。

### 9.3 Phase C: WASM(WAMR)統合(G3)

- WAMR は ESP Registry の公式 component を第一候補(不可なら interp-only を vendor)。
  interp モード、線形メモリ既定 64KB、`smscript` パーティションの active slot から
  ロード。暴走対策: FreeRTOS タイマから `wasm_runtime_terminate`(壁時計上限
  既定 50ms/フック)+ esp_task_wdt。フックは Matter ポンプと同一タスクで同期実行。
- **フック ABI(export、いずれも optional)**: `on_boot()`、`on_timer(id: i32)`、
  `on_attr_write(ep: i32, cluster: i32, attr: i32) -> i32`(0=承認)、
  `on_command(ep: i32, cluster: i32, cmd: i32) -> i32`、`on_sensor(bind: i32)`。
  値の受け渡しはホスト関数経由(引数に生ポインタを渡さない)。
- **ホスト import(module "sm")**: `attr_get(ep,cluster,attr, out_ptr,cap)->len` /
  `attr_set(ep,cluster,attr, ptr,len)->rc`(値は sm_attr_value_t の 16B 固定
  バイナリ表現)、`gpio_write(pin,v)` / `gpio_read(pin)->v` / `pwm_set(ch,duty)`、
  `timer_after(ms,id)` / `timer_every(ms,id)` / `timer_cancel(id)`、
  `log(ptr,len)`、`kvs_get/set(key_ptr,key_len, ...)`(名前空間 `smscr`)。
- **SDK**: `crates/sm-script-api`(`#![no_std]`、wasm32-unknown-unknown、extern 宣言
  + safe wrapper + サンプル)と `web/sdk/sm.d.ts` + AssemblyScript サンプル。
- ゲート: Linux ホストで WAMR を cmake ビルドし、モック sm import でフック
  ラウンドトリップ(Rust 製サンプル .wasm)+ C6 ビルド green。

### 9.4 Phase D: ScriptStore クラスタ(G4)

- vendor cluster `0xFFF1FC01`(CustomCluster/F4b で C++ 側実装 = シム無改造)。
  - commands: `Begin(size u32, crc32 u32)` / `Data(offset u32, bytes octstr≤512)` /
    `Commit()` / `Abort()`、attributes: `State u8`, `ActiveSlot u8`, `Version u32`。
  - 格納: `smscript` パーティション 2 スロット(ヘッダ magic "SMWS" + ver + len +
    crc32)。Commit = CRC 検証 → active 切替 → VM 再ロード。ロード失敗は旧スロットへ
    ロールバック。認可は CASE + ACL(Administer)。
- smctl `any invoke` / batch での転送手順を README に記載(チャンク分割スクリプト付き)。
- ゲート: ループバック(ctest or ホスト)で Begin→Data→Commit→リロード、C6 ビルド。

### 9.5 Phase E: Web Configurator

- `web/configurator/`: ビルドステップ無しの静的サイト(ES modules)。依存は vendor
  同梱(esptool-js、noble-curves、qrcode、assemblyscript web 版。CDN 参照しない)。
- 機能: ①構成/バインディング UI → TLV(§9.1/9.2 と同一スキーマ)、②個体情報生成
  (SPAKE2+ verifier = WebCrypto PBKDF2 + noble P-256。**mfg_tool 互換 NVS
  バイナリ**を生成)、③QR(`MT:` Base38)+ MPC(Verhoeff)表示・印刷、
  ④AssemblyScript エディタ→ .wasm → smscript イメージ(slot A)、
  ⑤esptool-js で app+nvs(smgen)+factory+smscript を一括 flash(FW イメージは
  Release asset 取得 or ローカルファイル指定)。
- 検証ゲート(自動化可能分): Node で単体テスト — verifier が `smctl pase-verifier`
  出力と一致、生成 NVS を Rust factory パーサ(fixtures 経由の cargo test)が読める、
  MPC/QR が仕様テストベクタと一致。ブラウザ実操作はユーザ確認。

## 10. 実装進捗

### Phase A(完了、2026-08-12): シム composition モード + 汎用値アクセス FFI

§9.1 の実装。**コア(`crates/simple-matter`)はアクセサ 1 個の追加のみ**(理由は下記「罠 3」)。
既存 API/ABI は後方互換(`composition=NULL` で従来の固定 OnOff ライト構成)。

#### 変更ファイル

- `crates/simple-matter-cffi/src/compose.rs`(新規、約 900 行): composition TLV パーサ +
  実装済みクラスタの static プール `Composed` + 汎用値アクセス(get/set)+ 変化監視
  (`poll_changes`)+ LevelControl/ColorControl ⇔ OnOff 連動 + Identify→Groups 伝播。
- `src/lib.rs`: `sm_config_t` に `composition` / `composition_len` / `on_cluster_change` /
  `cluster_change_ctx` を**末尾追加**(memset 済み構造体は従来動作)。`Light` に
  `composed: Composed` を持たせ、`cluster()`/`cluster_mut()`/`on_tick()`/`install_custom()`
  を合成モード対応に分岐。新 FFI `sm_attr_set_value` / `sm_attr_get_value`。`sm_onoff_get/set`
  は合成時「最小 EP の OnOff」を対象にする。`custom` は非公開のまま C ABI 型だけ crate
  ルートへ再輸出、`compose` / `controller` は `pub mod`(統合テストから叩くため)。
- `src/custom.rs`: `CustomCluster::call_read` / `call_write`(`sm_attr_*_value` が
  F4b カスタムクラスタへもフォールバックする)+ `write_value`(値 → 生 TLV。controller gated)。
- `src/controller.rs`: テスト用に必要だった 3 API を追加(いずれも additive)。
  `sm_ctrl_invoke_args`(引数付き invoke = MoveToLevel)/ `sm_ctrl_write_scalar`(IM write)/
  `sm_ctrl_subscribe`(単一属性 subscribe)+ イベント `SM_CTRL_EV_WRITE_DONE`(12)/
  `WRITE_FAILED`(13)/ `SUBSCRIBE_DONE`(14)/ `SUBSCRIBE_FAILED`(15)/ `REPORT`(16)。
  `op_args`(引数 4 個まで)と `sub_path` を `CtrlShim` に追加。
- `crates/simple-matter/src/controller/mod.rs`: **コア唯一の変更** =
  `ControllerStack::transport_deadline()`(`mgr.next_deadline()` を返すだけの 3 行アクセサ)。
- テスト: `src/tests.rs`(composition 単体 9 本)、`tests/composed_e2e.rs`(新規統合テスト =
  デバイス+コントローラ同一プロセス UDP ループバック E2E)、
  `ctest/composed_loopback.cpp`(新規 C レベル E2E)、`ctest/Makefile` に
  `composed_loopback` と `make check`(ble_loopback wifi/thread + composed を一括実行)。
- `cbindgen.toml`: `compose` の Rust 内部定数/型を除外(`CL_*` 等を C の名前空間に
  漏らさない)。`include/simple_matter.h` 再生成。

#### composition TLV スキーマ(最終形)

```
anonymous list|array of endpoint structs:      ← struct 直書き(単一 EP)も受理
  {
    0: endpoint-id     u16   必須。1..=8(0 = システム EP は予約 → Decode エラー)
    1: device-type     u32   DeviceTypeList に載る
    2: device-type-rev u8    既定 1
    3: cluster list    [u32, ...]   array|list。合成可能クラスタ ID(重複と 0x001D は無視)
    4: options         [ {0: cluster u32, 1: attr u32, 2: value(scalar|null)}, ... ]  optional
  }
```

- Descriptor(0x001D)は各 EP に**自動付与**、DeviceTypeList / ServerList / EP0 PartsList は
  合成結果から自動整合(blob には書かない)。
- options は起動時に `sm_attr_set_value` と同じ経路で適用する(未対応属性は黙って無視)。
- 合成可能クラスタ(初期プール、括弧内 = 個数上限): Identify(8)/ Groups(8)/ OnOff(8)/
  LevelControl(4)/ ColorControl(2)/ BooleanState(4)/ OccupancySensing(2)/
  Temperature・RelativeHumidity・Illuminance・Pressure・Flow(各 4)/ Switch(4)/
  FanControl(2)/ DoorLock(1)/ Thermostat(1)。最大 EP 8・EP あたり 12 クラスタ・
  slot 総数 40・options 16。上限超過は `sm_init` が `-8`、TLV 不正/未対応クラスタは `-7`。
- 汎用値アクセス: get は上記 16 クラスタの主要属性、set は**コアが setter を公開している
  もの**のみ(OnOff / BooleanState / Occupancy / 5 計測 / Thermostat LocalTemperature /
  Switch CurrentPosition)。LevelControl CurrentLevel 等のコマンド駆動属性は get のみで、
  set は `-3` を返す(Phase B で必要なら core に setter を足す判断)。
- `on_cluster_change` は IM write / コマンド由来の変化でのみ発火する。`sm_attr_set_value`
  由来(= アプリ発)では発火しない(HAL バインディングの無限ループ防止。スナップショットを
  書き込み時に同期する実装)。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| `cargo test --workspace` | **649 pass / 0 fail**(既存 639 + 新規 10: composition 単体 8 + Descriptor 合成 1 + E2E 1) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0(`--no-default-features` / `+controller` / `+ble` / `+ble,controller` の各構成も 0) |
| `cargo fmt --all --check` | クリーン |
| `scripts/gen-cffi-header.sh --check` | 冪等(再生成差分ゼロ) |
| ctest `make check` | **ALL GREEN ×3**: `ble_loopback wifi` / `ble_loopback thread`(F7b 回帰)/ **`composed_loopback`**(下記) |
| ctest 従来経路の回帰 | `onoff_light`(composition=NULL)↔ `controller`: PAIR OK → TOGGLE OK → READ value=1 |
| riscv32imac `--features panic-abort` | build green。`sm_attr_set_value` / `sm_attr_get_value` / `sm_ctrl_invoke_args` / `sm_ctrl_write_scalar` / `sm_ctrl_subscribe` が `T`。`--no-default-features --features panic-abort` も green(`sm_ctrl_*` は出力されない) |

`composed_loopback`(C レベル E2E、composition blob 89 バイトを素の TLV で C から組み立て):
pairing(UDP PASE→CASE→CommissioningComplete)→ **OnOff Toggle**(`sm_ctrl_invoke`)→
**LevelControl MoveToLevel(level=200)**(`sm_ctrl_invoke_args`)→ CurrentLevel read=200 +
`sm_attr_get_value`=200 + `on_cluster_change` 発火 → **EP2 温度 read**
(`sm_attr_set_value` で push した 18.75℃ が IM read で返る)。

Rust ホスト E2E(`tests/composed_e2e.rs`、3.6 秒): 上記に加えて
**IM write**(LevelControl OnOffTransitionTime=20 → WRITE_DONE → read で確認)と
**subscribe**(EP2 温度 min=0/max=5 → `sm_attr_set_value` push → `SM_CTRL_EV_REPORT` で
新値 12.34℃ を受信 = 購読反映)、`on_cluster_change` がアプリ発 set では鳴らないことを検証。

#### `.a` サイズ増分(riscv32imac-unknown-none-elf、release、`--features panic-abort`)

| | before(HEAD) | after | 差分 |
|---|---|---|---|
| `.text` | 936,391 B | 954,897 B | **+18,506 B** |
| `.bss` | 39,873 B | 45,129 B | **+5,256 B**(合成クラスタ static プール + EP テーブル拡張) |
| アーカイブ全体 | 15,073,474 B | 15,483,456 B | +409,982 B(大半は rlib メタデータ) |

コントローラの供給メモリ `sm_ctrl_context_size()`: 28,800 B → **29,144 B**(+344 B =
`op_args` 4 個 + `sub_path`)。

#### 発見した罠

1. **デバイスシムは単一 static インスタンス** → `sm_init` はプロセス 1 回。既存
   `src/tests.rs`(composition=NULL 経路)と合成 E2E は同居できないため、E2E は
   **独立した統合テストバイナリ**(`tests/composed_e2e.rs` = 別プロセス = 別 static)に置いた。
   Descriptor 合成の検証は `Light` を `Box::leak` でヒープに固定して行う(不動なら
   `install` の `&'static` 自己参照の前提を満たす)。
2. **`Composed::cluster_mut` の借用**: slot 検索(`&self`)の戻り値を保持したまま
   プールを可変借用できない。index を先に取り出して借用を切る 2 段構えが要る
   (`let i = self.slot(..)?.idx;` の形)。
3. **購読を張ると `ControllerStack::next_deadline` が永久に `Some`**(keep-alive 途絶検出の
   期限が常駐する)。F7a の settle→drive 分離は「`next_deadline == None` で完全静穏化」を
   pump の発火条件にしていたため、**subscribe 後に pump へ到達しなくなり SUBSCRIBE_DONE も
   レポートも永久に上がらない**(実測: 25 秒タイムアウト)。対処としてコアに
   `transport_deadline()`(MRP 由来の期限だけ)を足し、シムの静穏化判定をそちらへ切り替えた
   = **コア変更はこれだけ**。
   なお「イベント取り込みだけ静穏化ゲートの前でやる」案は **不可**: 完了イベントが早く
   上がるとアプリが standalone ACK 送出前に次の exchange を始めてしまい、デバイス IM
   responder(同時 1 トランザクション)が無応答になる(F7a と同じ罠を再現した)。
4. **`pub mod` 化で clippy が増える**: モジュールを公開すると `result_unit_err` /
   `new_without_default` が公開 API に対して発火する。`custom` は非公開のまま C ABI 型だけ
   crate ルートへ `pub use` する形に落ち着けた。cbindgen も同様で、`compose` を公開すると
   `CL_ONOFF` / `MAX_SLOTS` / `RC_TYPE` のような**汎用名の `#define` が C ヘッダに漏れる**
   → `cbindgen.toml` の `export.exclude` に列挙して抑止。
5. **LevelControl ⇔ OnOff 連動はアプリの責務**(コアは `take_on_off_request` /
   `notify_on_off` を出すだけ)。合成モードでは同一 EP の組を `couple_on_off()` で橋渡しし、
   `housekeep`(コマンド直後)と `on_tick`(遷移完了時)の両方で呼ぶ必要がある。
6. **`sm_config_t` の拡張は末尾追加限定**。既存 example/ctest は `memset` + 個別代入なので
   NULL 埋め = 従来動作になる(位置指定初期化をしている利用者がいれば壊れる)。

### Phase B(完了、2026-08-12): `generic_matter_cpp` example(G1 設定駆動 + G2 HAL バインディング)

§9.2 の実装。**コア(`crates/simple-matter`)とシム(`crates/simple-matter-cffi/src`)は
無改造**(Phase A の `sm_config_t.composition` / `on_cluster_change` / `sm_attr_set_value` /
`sm_attr_get_value` だけで成立した)。既存 example 3 つも無変更。

#### 変更ファイル

- `ports/esp-idf/examples/generic_matter_cpp/`(新規):
  - `main/main.cpp` — onoff_light_cpp をベースに 3 点だけ差し替え: ①起動時に NVS
    namespace `smgen` の `comp` / `bind` を読み `sm_config_t.composition` へ渡す
    (無ければ既定 blob)、②`on_cluster_change` を HAL へ配線、③pump ループで
    `bindings_poll`。カスタムクラスタ(EP2)と LED 直叩きは削除。
  - `main/bind_tlv.hpp`(新規)— binding TLV スキーマ + パーサ。**ESP-IDF 非依存の
    ヘッダオンリー**にして、ホスト検算プログラムとファームで同一コードを使う。
  - `main/bindings.{hpp,cpp}`(新規)— ドライバ表 gpio_out / gpio_in / ledc /
    i2c_sht30 / script と dispatch・ポーリング。
  - `main/cfg_store.{hpp,cpp}`(新規)— NVS `smgen` の読み書き + esp_console REPL
    (USB-Serial-JTAG)`cfg-comp` / `cfg-bind` / `cfg-show` / `cfg-clear` / `restart`。
  - `main/{ble,ot_thread}.{hpp,cpp}` / `app_cmd.hpp` — onoff_light_cpp からのコピー(無改変)。
  - `main/Kconfig.projbuild` / `CMakeLists.txt` / `partitions.csv` /
    `sdkconfig.defaults{,.esp32c6,.thread}` / `README.md`。
- `scripts/smgen-tlv.py`(新規)— composition / binding TLV のエンコーダ + デコーダ
  + `examples`(README 掲載 hex の生成元)+ `selftest`(ラウンドトリップ)。
- `crates/simple-matter-cffi/ctest/compose_check.cpp`(新規)+ `Makefile` の
  `compose_check` / `check-generic` ターゲット — README の hex 例を**実際に `sm_init` へ
  食わせて**合成結果を検証するホストハーネス(下記ゲート)。シム本体は無改造。

#### binding TLV スキーマ(最終形)

```
anonymous list|array of binding structs:      ← struct 直書き(単一 binding)も受理
  {
    0: endpoint u16   必須(1..)
    1: cluster  u32   必須(ドライバを結び付けるクラスタ ID)
    2: drv-id   u8    必須(1=gpio_out 2=gpio_in 3=ledc 4=i2c_sht30 5=script)
    3: params   struct(ドライバ固有。context tag → スカラ)。省略可
  }
```

| drv | id | params(context tag) | 対象クラスタ | 動作 |
|---|---|---|---|---|
| `gpio_out` | 1 | 0=pin u8、1=invert bool | OnOff(0x0006) | 変化 → GPIO 出力 |
| `gpio_in` | 2 | 0=pin、1=invert、2=poll_ms u16(既定 50)、3=pull u8(0/1=up 既定/2) | BooleanState(0x0045)/ Switch(0x003B) | ポーリング + 2 連続一致デバウンス → `sm_attr_set_value` |
| `ledc` | 3 | 0=ch、1=pin、2=freq u32(既定 1000)、3=invert bool | LevelControl(0x0008) | CurrentLevel(0..254)→ duty(10bit)。同一 EP の OnOff が off なら duty 0 |
| `i2c_sht30` | 4 | 0=sda、1=scl、2=poll_ms u16(既定 5000)、3=port u8 | Temperature(0x0402) | 0x2C06 単発測定 + CRC8 検証 → 0x0402 と同一 EP の 0x0405 へ push |
| `script` | 5 | (予約) | 任意 | Phase C の WASM フックへ委譲(現状 no-op) |

パーサは params を「context tag → u64」の疎な表として持つだけなので、**ドライバ追加で
パーサを触る必要はない**(ドライバ側が `param(tag, default)` で読む)。上限は
バインディング 16 / params tag 0..7。tag 割り当ては `scripts/smgen-tlv.py` の `PARAMS` と 1 対 1。

#### 既定構成(NVS に `comp` / `bind` が無いとき)

- composition = EP1 / device type `0x0100`(On/Off Light)rev 2 / Identify + Groups + OnOff。
  **`main.cpp` に 35 バイトの生 TLV を直書き**(TLV エンコーダをファームに持ち込まないため)。
  この 35 バイトは `scripts/smgen-tlv.py examples` の例 ① と同一バイト列。
- binding = EP1 OnOff → `gpio_out`(pin = `CONFIG_SM_DEFAULT_GPIO`、既定 7 / S3 は 48、invert=false)。

パーティション(`partitions.csv`、4MB): `nvs` 24KB / `factory`(app)2.5MB /
`nvs_factory` 24KB(mfg-tool 互換 factory データ)/ **`smscript` 256KB(data, subtype 0x40。
Phase D 用に予約、Phase B では未使用)**。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| docker `espressif/idf:release-v5.4` esp32c6(WiFi+BLE、経路 (b) cargo) | **build green**。app **1,594,688 B**(`0x185140`、partition 39% free) |
| 同 esp32c6 Thread 構成(`sdkconfig.defaults.thread`) | **build green**。app **1,622,096 B**(`0x18c050`、38% free)= Thread 経路も維持 |
| ELF シンボル | `sm_init` / `sm_udp_rx` / `sm_poll` / `sm_attr_set_value` / `sm_attr_get_value` / `sm_onoff_set` / `sm_ble_*` が `T`。`smgen::parse_bindings` ほか example 側シンボルも健在 |
| README hex 例の検算(ctest `make check-generic`) | **COMPOSE CHECK OK ×2**。例 ①(comp 35B / bind 25B)→ EP1{Identify,Groups,OnOff}、例 ②(comp 68B / bind 60B)→ EP1{Identify,Groups,OnOff,LevelControl} + EP2{Temperature,RelativeHumidity}。`--expect` と**過不足なく一致** |
| `scripts/smgen-tlv.py selftest` | PASS(encode→decode ラウンドトリップ) |
| ctest `make check` | **ALL GREEN ×3 + COMPOSE CHECK OK ×2**(`ble_loopback wifi` / `ble_loopback thread` / `composed_loopback` の回帰込み) |
| `cargo test --workspace` | **649 pass / 0 fail**(Phase A と同数 = 回帰なし) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` / `cargo fmt --all --check` | 0 / クリーン(ワークスペースへの Rust 追加は無し) |
| onoff_light_cpp esp32c6 回帰 | **build green**(app `0x176c50`)。既存 example 3 つは無変更 |

実機検証はユーザの機材で行う(未実施)。

#### 発見した罠

1. **ESP-IDF docker を `-u $(id -u)` で回すと ccache が `Permission denied` で全 C
   コンパイルが FAILED になる**(ccache のキャッシュディレクトリがコンテナ内 root 所有)。
   `-e CCACHE_DISABLE=1` を足すと通る。root で回して後片付けする従来手順の代わりに、
   **非 root + CCACHE_DISABLE** なら `build/` が user 所有で生成されるので後片付けが楽。
2. **`esp_console_new_repl_usb_serial_jtag` は `CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG`
   (または SECONDARY)でしかコンパイルされない**。C6 の IDF 既定は UART なので
   `sdkconfig.defaults` に明示が要る。REPL の `max_cmdline_length` も既定(256)では
   composition hex(例 ② は 136 文字、EP 8 構成なら数百文字)が切れるので 2048 にした。
3. **コンソールタスクから `sm_*` を呼ばない**設計にすれば単線契約を壊さずに済む
   (`cfg-*` は NVS のみ、反映は `restart`)。設定変更 = 再起動という §4 の割り切りが
   そのままタスク分離の根拠になる。
4. **binding パーサをファーム専用にすると hex 例を検証できない**。`bind_tlv.hpp` を
   ESP-IDF 非依存のヘッダオンリーにして ctest から `-I` で取り込む形にしたことで、
   README の hex を**ファームと同一コード**で検算できるようになった(`compose_check`)。
5. **`sm_attr_get_value` の戻り値で「クラスタの有無」を判定できる**(-2 = クラスタ無し、
   -3 = クラスタはあるが属性が非公開)。Groups のように値アクセス非対応のクラスタでも
   -3 が返るので、合成結果の走査(`compose_check` の EP×クラスタ探索)に使える。
6. **LevelControl の CurrentLevel は `sm_attr_set_value` では書けない**(Phase A の
   既知制約)。よって `ledc` ドライバは「`on_cluster_change` で通知された値」ではなく
   **毎回 `sm_attr_get_value` で CurrentLevel と OnOff を読み直して duty を決める**方式に
   した(OnOff 変化・Level 変化のどちらの通知でも同じ計算に合流する)。
7. **`gpio_in` / `i2c_sht30` の push は `sm_attr_set_value` 経由なので `on_cluster_change` が
   鳴らない**(§9.1 の設計どおり)= HAL の無限ループが構造的に起きない。逆に
   ローカル操作(`CmdKind::LocalToggle` → `sm_onoff_set`)も通知が来ないため、
   出力への反映はアプリ側で明示的に呼ぶ必要がある(`bindings_apply_initial` を再利用)。

### Phase C(完了、2026-08-12): WASM(WAMR)スクリプト統合(G3)

§9.3 の実装。**コア(`crates/simple-matter`)と C FFI シム(`crates/simple-matter-cffi/src`)は
無改造**(Phase A の `sm_attr_get_value` / `sm_attr_set_value` / `on_cluster_change` だけで
成立した)。既存 example 3 つ(onoff_light_cpp / controller_hub_cpp / thread_ctrl_hub_cpp)も無変更。

#### WAMR の入手形態と版

**ESP Component Registry の公式 component をそのまま使う(vendor しない)**:

- `espressif/wasm-micro-runtime` **2.4.0~1**(upstream WAMR 2.4.0、
  `repository_info.commit_sha = 8f806e0f2c02a768d2c35044f2964f769612d9bc`)。
  targets に `esp32c6` / `esp32p4` / `esp32s3` などを含む。
- 宣言は `ports/esp-idf/examples/generic_matter_cpp/main/idf_component.yml`
  (`espressif/wasm-micro-runtime: "~2.4.0"`)。CMake の `REQUIRES` は
  **`espressif__wasm-micro-runtime`**(managed component の完全名)。
- 機能選択は `sdkconfig.defaults` の `CONFIG_WAMR_*`:
  **classic interpreter のみ**(`WAMR_INTERP_CLASSIC`)、AOT / LIBC_WASI / LIBC_BUILTIN /
  APP_FRAMEWORK / MULTI_MODULE / SHARED_MEMORY / REF_TYPES は無効、
  **LIB_PTHREAD は有効**(理由は罠 1)。
- ホスト検証ハーネスは `tools/wasm-harness/fetch-wamr.sh` が**同じ zip**を取得して
  Linux 用に cmake ビルドする(`.wamr/` は gitignore)。リポジトリのサイズ増は 0 バイト。

#### 追加ファイル

- `ports/esp-idf/examples/generic_matter_cpp/main/`:
  - `script_abi.hpp`(新規)— **16B 値表現**・フック名・import 名・エラーコード。
    ESP-IDF 非依存(ファーム/ハーネス共用)。
  - `script_img.hpp`(新規)— `smscript` の `SMWS` ヘッダ + CRC-32 + スロット計算。
    **Phase D(ScriptStore)と共用**する小さなヘッダオンリーモジュール。
  - `script_vm.{hpp,cpp}`(新規、約 460 行)— WAMR ラッパ。**ESP-IDF 非依存**
    (`wasm_export.h` + libc のみ)。ホスト機能は `ScriptHostOps` の関数ポインタで注入。
    ホスト import 11 本の実装(線形メモリ範囲検証込み)、フック呼び出し、
    スクリプトタイマ 8 本、統計。
  - `script_host.{hpp,cpp}`(新規)— ESP 実体。パーティションからの active slot ロード、
    `sm_attr_*` ⇔ 16B 変換、gpio/ledc、NVS `smscr`、esp_timer 暴走監視。
  - `main.cpp` / `bindings.cpp` — 呼び出し 4 箇所の追加のみ(`script_init` /
    `script_poll` / `script_notify_attr_write` / `script_notify_sensor`)。
  - `Kconfig.projbuild` — `SM_SCRIPT_ENABLE`(既定 y)/ `SM_SCRIPT_POOL_KB`(96)/
    `SM_SCRIPT_POOL_STATIC`(既定 n)/ `SM_SCRIPT_MAX_KB`(24)/ `SM_SCRIPT_STACK_KB`(8)/
    `SM_SCRIPT_BUDGET_MS`(50)。
- `crates/sm-script-api/`(新規、ワークスペースメンバ)— `#![no_std]` の Rust SDK。
  wasm32 では実 import、それ以外では「未対応」スタブ(= `cargo test --workspace` が壊れない)。
  `examples-wasm/momentary-toggle/` は**独立ワークスペース**(ルートの `exclude`)。
- `tools/wasm-harness/`(新規)— Linux ホストハーネス(`run.sh` / `fetch-wamr.sh` /
  `CMakeLists.txt` / `harness.cpp`)。`make -C crates/simple-matter-cffi/ctest check-wasm`。
- `scripts/smscript-img.py`(新規)— `.wasm` → `SMWS` イメージの pack / show / selftest。
- `web/sdk/sm.d.ts` + `web/sdk/momentary-toggle.ts`(新規)— AssemblyScript 用の宣言と
  サンプル(**コンパイルはしない**。Phase E で使う)。

#### フック ABI(最終形)

| export | 発火元 | 戻り値 |
|---|---|---|
| `on_boot()` | `script_init()`(sm_init + bindings 初期化の直後) | — |
| `on_timer(id: i32)` | pump ループの `script_poll`(`timer_after` / `timer_every`) | — |
| `on_attr_write(ep,cluster,attr) -> i32` | `on_cluster_change`(HAL dispatch の後) | 0 = 承認。**非 0 は観測のみ** |
| `on_command(ep,cluster,cmd) -> i32` | **未接続**(シムにコマンドフックが無い。Phase D で繋ぐ) | 0 = 承認 |
| `on_sensor(bind: i32)` | `gpio_in` の確定変化 / `i2c_sht30` の push / `script` binding の周期(`poll_ms`) | — |

未 export のフックは no-op(`on_attr_write` / `on_command` は 0 扱い)。全フックは
Matter ポンプと同一タスクで同期実行(単線契約)。フック内からフックは呼ばない(再入抑止)。

**拒否が「観測のみ」な理由**: `on_cluster_change` は**既に適用された**変化の通知で、
現行シムに IM write を却下する口(write ハンドラの戻り値)が無い。ファームは非 0 を
警告ログに出すだけで書き込みを取り消さない。スクリプト側で拒否したいときは
`attr_set` で元の値へ書き戻す(README に明記)。

#### ホスト import(module `"sm"`、最終形)

`attr_get(ep,cluster,attr,out_ptr,cap)->len` / `attr_set(ep,cluster,attr,ptr,len)->rc` /
`gpio_write(pin,v)` / `gpio_read(pin)` / `pwm_set(ch,duty)` /
`timer_after(ms,id)` / `timer_every(ms,id)` / `timer_cancel(id)` / `log(ptr,len)` /
`kvs_get(key,key_len,out,cap)` / `kvs_set(key,key_len,val,len)`。
引数は全て i32(ポインタも i32 オフセット)。**ポインタは必ず
`wasm_runtime_validate_app_addr` で範囲検証してから native ポインタへ変換する**。
エラーは負値(-1 ARG / -2 NOTFOUND / -3 UNSUPPORTED / -4 TYPE / -5 NOSPACE / -6 HW)。
KVS は NVS namespace `smscr`(キーは 15 バイトまで)。タイマは同時 8 本、
ホスト側(`script_vm.cpp`)で管理し pump の `script_poll(now_ms)` で満了させる。

#### 値の 16B 固定バイナリ表現

| offset | size | 内容 |
|---|---|---|
| 0 | 1 | `type`(`sm_attr_type_t` と同一: 0=BOOL 1=U8 2=U16 3=U32 4=U64 5=I8 6=I16 7=I32 8=I64 9=F32 10=STRING 11=OCTETS) |
| 1 | 1 | `flags`(bit0 = is_null) |
| 2 | 2 | `len`(STRING/OCTETS の**後続**バイト数、u16 LE。スカラは 0) |
| 4 | 4 | 予約(0) |
| 8 | 8 | `val`(u64 LE。BOOL=0/1、U\*=ゼロ拡張、I\*=符号拡張、F32=下位 32bit にビットパターン) |

**スカラはちょうど 16B**、STRING/OCTETS は `16+len` B(本体が 16B の直後に続く)。
定義は `main/script_abi.hpp` / `crates/sm-script-api`(`Value::encode_into`)/
`web/sdk/sm.d.ts` の 3 箇所に同じものを書き、ハーネスが両実装のラウンドトリップを検証する。

#### スクリプトイメージ(`smscript` パーティション、Phase D と共通)

128KB × 2 スロット(slot A = +0x00000、slot B = +0x20000)。各スロット先頭 16B:
`"SMWS"` + `ver u16` + `flags u16` + `len u32` + `crc32 u32`(CRC-32/IEEE)。
active slot = ヘッダ妥当 + CRC 一致のうち **ver 最大**(同値なら A)。両方無効 =
スクリプト無し(従来動作)。ツールは `scripts/smscript-img.py`
(`pack` は `esptool.py write_flash 0x296000 slotA.bin` にそのまま渡せる)。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| docker `espressif/idf:release-v5.4` esp32c6(WiFi+BLE+WAMR) | **build green**。app **0x1a1ca0 = 1,711,264 B**(partition 35% free) |
| 同(`CONFIG_SM_SCRIPT_ENABLE=n`) | **build green**。app 0x185340 = 1,595,200 B(= Phase B + 512 B) |
| ホストハーネス `make check-wasm` | **WASM HARNESS OK**(下記) |
| `cargo test --workspace` | **655 pass / 0 fail**(Phase B の 649 + sm-script-api 6) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0(サンプル wasm クレートも `--target wasm32-unknown-unknown` で 0) |
| `cargo fmt --all --check` | クリーン(サンプル wasm クレートも) |
| ctest `make check` | **ALL GREEN ×3 + COMPOSE CHECK OK ×2**(Phase A/B の回帰) |
| `scripts/smgen-tlv.py selftest` / `smscript-img.py selftest` | PASS / PASS |
| onoff_light_cpp esp32c6 回帰 | **build green**(app 0x176c50 = Phase B と同一) |

ホストハーネス(`tools/wasm-harness`、ファームと同一の `script_vm.cpp` + Linux 用 WAMR):
`momentary_toggle.wasm`(**1,452 B**)をロード →
`on_boot`(log + `kvs_get`)→ `on_sensor`(押下エッジ → `attr_get` BooleanState →
`attr_set` OnOff トグル → `kvs_set` で押下回数)→ `timer_after` → `script_vm_poll` →
`on_timer` で長押し強制 OFF → `timer_cancel` が効く(離すと発火しない)→
`on_attr_write` が 0 → 未 export の `on_command` が no-op → **暴走スクリプト
(手組みの `loop br 0`)が 50ms で terminate されて復帰**(traps=1 / timeouts=1)。

#### app サイズ増分(esp32c6、WiFi+BLE 構成)

| | Phase B(HEAD) | Phase C(script 無効) | Phase C(既定 = script 有効) |
|---|---|---|---|
| app `.bin` | 1,594,688 B | 1,595,200 B(**+512**) | **1,711,264 B(+116,576 = +113.8KB)** |
| DIRAM `.bss` | — | 77,664 B | 77,776 B(**+112 B**。プールはヒープ) |
| うち WAMR 単体(`idf.py size-components`) | — | — | 91,902 B(flash `.text` 90,122 / rodata 1,304 / DIRAM 476) |

WAMR 実体は約 90KB(§6 の見積り「85-150KB」の下限側)。残り約 26KB は
`script_vm.cpp` / `script_host.cpp` と、WAMR が引き込む pthread / thread-manager。
**RAM は既定でヒープから 96KB(スクリプトがある時だけ)**: 静的確保(96KB を .bss)に
すると DIRAM 残が 219KB → 96KB まで落ちて WiFi+BLE+Matter のヒープを圧迫するため、
既定を「イメージが見つかったら 1 度だけ `heap_caps_aligned_alloc`」にした
(`CONFIG_SM_SCRIPT_POOL_STATIC=y` で §9.3 どおりの静的確保にできる)。

#### 発見した罠

1. **`wasm_runtime_terminate` は THREAD_MGR 無しでは無限ループを止められない**。
   classic interpreter の `CHECK_SUSPEND_FLAGS()`(loop/br の back-edge)は
   `WASM_ENABLE_THREAD_MGR != 0` でしかコンパイルされず、terminate は例外を立てるだけなので
   `loop br 0` は永久に回り続ける。**`CONFIG_WAMR_ENABLE_LIB_PTHREAD=y`(→ thread-manager)**
   にすると `wasm_set_exception` が `wasm_cluster_set_exception` → `set_thread_cancel_flags`
   経由で suspend flag を立て、フックから抜けられる。ホストハーネスで
   「50ms で復帰」を実測して確認した(この検証が無ければ実機で気づけない類の罠)。
2. **WAMR のローダはバイトコードバッファを保持し、書き換える**(labels-as-values の
   opcode 置換)。`esp_partition_mmap` の読み取り専用領域を直接渡せないので、
   プール上へ `wasm_runtime_malloc` して複製してから `wasm_runtime_load` する。
   読み出し用の一時バッファはロード後に解放する。
3. **静的 96KB プールは C6 では高すぎる**。DIRAM 452KB のうち `.bss` が 200KB になり、
   ヒープ残が 96KB まで落ちる(WiFi+BLE+Matter には不足)。既定を遅延ヒープ確保に変えて
   `.bss` +112 B に収めた。**WAMR に malloc を渡さない**方針は維持(プール外へは伸びない =
   スクリプトがシステムヒープを食い潰せない)。
4. **非 root docker では `~/.cache/Espressif` のマウントが要る**。Phase C から
   component manager が WAMR を取りに行くため、キャッシュディレクトリを作れないと
   `ERROR: Failed to create cache directory` で configure が落ちる
   (Phase B の `CCACHE_DISABLE=1` と同じ系統の罠)。REQUIRES に書く名前も
   短縮名ではなく **`espressif__wasm-micro-runtime`**。
5. **`no_std` + `#[panic_handler]` + `cdylib` のサンプルはワークスペースに入れられない**
   (`cargo test --workspace` / `clippy --all-targets` がホスト向けにビルドしようとして壊れる)。
   ルートの `exclude` + サンプル側の空 `[workspace]` で**独立ワークスペース**にした。
   SDK 本体(`sm-script-api`)は「wasm32 では実 import、それ以外ではスタブ」にして
   ワークスペースメンバのまま置き、16B レイアウトの単体テストをホストで回している。
6. **フック内からホスト関数を呼ぶ間も監視タイマは動いている**。`attr_set` などの副作用は
   打ち切り時点まで残る(トランザクションではない)。長い処理は `timer_after` で分割する、
   というスクリプト側の規約を README に明記した。
7. **`on_sensor` の引数は binding index**(EP/cluster ではない)。バインディング表の
   並び順に依存するので、スクリプトは index を信用せず `attr_get` で状態を読み直す設計に
   した方が壊れにくい(サンプルはそうしている)。

### Phase D(完了、2026-08-12): ScriptStore クラスタ(G4 = スクリプト OTA)

§9.4 の実装。**コア(`crates/simple-matter`)と C FFI シム(`crates/simple-matter-cffi/src`)は
無改造**(F4b の `sm_cluster_register` + Phase A の `sm_attr_mark_dirty` だけで成立した)。
既存 example 3 つ(onoff_light_cpp / controller_hub_cpp / thread_ctrl_hub_cpp)も無変更。

#### 追加・変更ファイル

- `ports/esp-idf/examples/generic_matter_cpp/main/`:
  - `script_store.hpp`(新規、約 420 行)— **ESP-IDF 非依存のヘッダオンリー**。
    受信ステートマシン(`ScriptStore`)+ 格納バックエンド vtable(`ScriptStoreBackend`)+
    CustomCluster への登録(`script_store_register`)。イメージ形式は Phase C の
    `script_img.hpp` をそのまま使う(**無改造**)。ホストのループバックテストと共用。
  - `script_store.cpp`(新規)— ESP 実体。`smscript` パーティション(esp_partition)を
    backend にし、`reload` を `script_reload()` へ、`mark_dirty` を `sm_attr_mark_dirty` へ、
    `on_command` を `script_notify_command()` へ配線する。起動時にローダと同一規則
    (ヘッダ妥当 + CRC 一致のうち ver 最大)で active slot を求める。
  - `script_host.{hpp,cpp}` — `script_reload()`(VM 停止 → active slot から再ロード)と
    `script_notify_command()`(`on_command` フック)を追加。
  - `main.cpp` — 3 行(`script_store_init()` を **sm_init より前**、pump ループの
    `script_store_poll()`、起動ログの `script_store_log_status()`)。
  - `Kconfig.projbuild` — `SM_SCRIPTSTORE_ENABLE`(既定 y、`SM_SCRIPT_ENABLE` 依存)/
    `SM_SCRIPTSTORE_EP`(既定 1)。
  - `README.md` — 「スクリプト OTA — ScriptStore クラスタ」節(コマンド/属性表、
    smctl 手順、64B チャンク上限・順次のみ・権限の注意)。
- `crates/simple-matter-cffi/ctest/scriptstore_loopback.cpp`(新規、約 560 行)+ Makefile —
  ファームと**同一の `script_store.hpp`** にメモリ backend(フラッシュ意味論を模倣:
  4KB 消去 / 消去済み領域にしか書けない)を注入したループバック。
- `scripts/smscript-img.py` — `batch` サブコマンド(`.wasm` → `smctl batch` テキスト)と
  `parse_batch`(往復検証)。`selftest` に batch ラウンドトリップを追加。

#### クラスタ仕様(実装確定)

vendor cluster **`0xFFF1FC01`**、既定 **EP1**(合成 EP へ相乗り。Descriptor の
ServerList はシムが自動マージ)。

| commands | 引数 |
|---|---|
| `Begin`(0x00) | `0`=size u32、`1`=crc32 u32 |
| `Data`(0x01) | `0`=offset u32(**順次のみ**)、`1`=bytes octstr(**≤64B**) |
| `Commit`(0x02) / `Abort`(0x03) | なし |

| attributes | 型 | 内容 |
|---|---|---|
| `State`(0x0000) | u8 | 0=idle / 1=receiving / 2=committing / 3=error |
| `ActiveSlot`(0x0001) | u8 | 0=A / 1=B / 255=無し |
| `Version`(0x0002) | u32 | active イメージの `SMWS` ver |
| `ChunkMax`(0x0003) | u16 | 64(§9.4 への追加。下記「罠 1」を発見可能にする) |

#### 状態遷移

```
        Begin                     Commit                    poll: reload ok
 idle --------> receiving -----------------> committing --------------------> idle
  ^  \             |  \  Data(順不同/超過)        |  \ poll: reload 失敗
  |   \ Abort      |   +--> ConstraintError       |   +--> ヘッダ消去 → 旧スロット再ロード
  |    +-----------+                              |                          |
  |                | Commit(サイズ不足/CRC 不一致)|                          v
  +--- Abort/Begin -+------------------------> error <-------------------------+
```

- `Begin` は idle / receiving / error のどれからでも受ける(やり直し)。
- `committing` 中の Begin / Data / Commit / Abort は **Busy(0x9c)**。
- 受信先は**非 active スロット**。`Begin` で `16 + size` を 4KB 単位に切り上げて消去、
  `Data` は 512B ステージング経由で 4B アラインして書く。
- **`SMWS` ヘッダは Commit の最後**に書く(それまでスロットは magic 無し = 無効)。
  途中で電源が落ちても旧スロットが active のまま = 半焼けで文鎮化しない。
- Commit = **書き戻し読みによる CRC 検証** → ヘッダ書き込み(ver = 現行 +1)→
  `committing`。**再ロードは invoke ハンドラの中ではなく pump ループの
  `script_store_poll()`**(単線契約・再入回避)。成功 = idle、失敗 = 新スロットの
  ヘッダを消して旧スロットを再ロードし error(ロールバック)。
- active 切替の「マーカー」は置いていない。**ヘッダの ver が切替そのもの**
  (active = 妥当 + CRC 一致のうち ver 最大 = Phase C のローダ規則)なので、
  NVS `smgen` 側に状態を持たずに済んだ。

#### 権限(§9.4 との差分)

**invoke = Operate、read = View**(F4b の CustomCluster 既定)。設計 §9.4 は
「CASE + ACL(Administer)」を想定していたが、**シムに per-command の privilege 指定の
口が無い**(`SM_CMD_TIMED` のみ)ため、シム無改造では Administer 要求にできない。
CASE セッション外からは投入できないので「fabric の外から書ける」わけではないが、
Operate 権限しか持たない相手にもスクリプト投入を許すことになる。README に明記し、
運用では ACL で Operate を与える相手を絞る。Administer 化はシム側に
`SM_CMD_ADMINISTER` フラグを足す将来作業(F4b の拡張)。

#### `on_command` フックの配線(§9.3 の宿題)

**カスタムクラスタの invoke だけ**が C++ 側(`sm_cluster_def_t.invoke`)を通るので、
ScriptStore の invoke から `script_notify_command(ep, cluster, cmd)` を呼べる。
**合成クラスタ(OnOff 等)のコマンドは依然として未接続**: シムの通知口は
`on_cluster_change`(= 適用済みの属性変化)だけで、コマンド到達そのものを通す
コールバックが無い。コア/シム無改造の制約内ではここが上限で、全クラスタで
`on_command` を鳴らすには `sm_config_t` にコマンドフックを足す必要がある(将来)。
戻り値は**観測のみ**(壊れたスクリプトが ScriptStore を塞いで文鎮化するのを防ぐ)。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| ctest `make check` | **ALL GREEN ×4 + COMPOSE CHECK OK ×2**(`ble_loopback wifi/thread`・`composed_loopback` の回帰 + 新規 `scriptstore_loopback`) |
| docker `espressif/idf:release-v5.4` esp32c6(WiFi+BLE+WAMR) | **build green**。app **0x1a32a0 = 1,716,384 B**(partition 35% free) |
| `cargo test --workspace` | **655 pass / 0 fail**(Phase C と同数 = 回帰なし) |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 |
| `cargo fmt --all --check` | クリーン(Rust の追加は無し) |
| `scripts/smscript-img.py selftest` | **PASS**(pack/unpack + batch 往復 6 サイズ + 欠落チャンク検出) |

`scriptstore_loopback` の内容(1 プロセス、UDP メモリループバック):
pairing → 属性 read(State=idle / ActiveSlot=none / Version=0 / ChunkMax=64)→
**転送 #1**(700B / 11 チャンク → slot A ver 1、フラッシュ内容とヘッダ CRC が一致、
再ロード済みイメージが原本と bit 一致)→ **転送 #2**(1301B / 21 チャンク → slot B ver 2、
**slot A は無傷**)→ 順不同 `Data` と サイズ不足 `Commit` が `ConstraintError` →
`Abort` で idle → **CRC 不一致**の Commit が `ConstraintError` で active を変えない →
**ロード失敗 → ロールバック**(slot A のヘッダが消え、slot B ver 2 が active のまま)→
やり直し転送が ver 3 で成功 → `on_command` 通知 62 回。

#### app サイズ増分(esp32c6、WiFi+BLE+WAMR 構成)

| | Phase C | Phase D |
|---|---|---|
| app `.bin` | 1,711,264 B(0x1a1ca0) | **1,716,384 B(0x1a32a0、+5,120 = +5.0KB)** |
| DIRAM `.bss` | 77,776 B | 77,776 B(**±0**。ScriptStore の状態はステートマシン 1 個 ≒ 0.6KB で `.data`/`.bss` 内訳の丸めに埋もれる) |

受信バッファはステージング 512B + ステート ≒ 600B(静的 1 個)。イメージ全体を
RAM に置かない(チャンクごとにフラッシュへ書く)ので、128KB のスクリプトでも
RAM は増えない。

#### 発見した罠

1. **`Data` の実効チャンク上限は 64B(設計の 512B は不可)**。シムの
   `sm_attr_value_t` は octet string を **64B 固定バッファ**(`custom.rs` の `STR_CAP`)で
   運ぶため、65B 以上の octstr 引数は `ConstraintError` でデコード段階に落ちる。
   シム無改造の制約なので**仕様側を 64B に合わせ**、`ChunkMax` 属性で機械可読にした
   (1.5KB のスクリプトで 23 チャンク ≒ 数百 ms、`smctl batch` の単一 CASE 共有前提)。
   512B にしたければシムの `STR_CAP` 拡大か「長大引数用の別 API」が要る。
2. **CustomCluster の invoke 引数は型が潰れる**。TLV → `sm_attr_value_t` の平坦化は
   符号なし整数を一律 `SM_T_U64` にする(宣言型による復元はしない)ので、
   ハンドラ側は U8/U16/U32/U64 を全部受けて範囲検査する必要がある。
3. **再ロードを invoke ハンドラの中でやってはいけない**。Commit の応答を返す前に
   VM を落とすと、フック実行中の再入・IM 応答の遅延(WAMR のロードは数十 ms)が
   起きる。`committing` 状態を挟んで pump ループで実行する設計にした
   (ホストテストも `poll()` を pump 相当の位置から呼んで同じ経路を通す)。
4. **ヘッダを先に書くと半焼けイメージが active になる**。`SMWS` を最後に書けば
   「本体だけ書かれたスロット = magic 無し = 無効」となり、電源断に対して
   追加のジャーナルもマーカーも要らない。ロールバックも**ヘッダ 1 個の消去**で済む。
5. **`esp_partition_write` は 4B アラインで呼ぶ**。64B チャンクをそのまま書くと
   最終チャンクで長さが 4 の倍数にならない。512B ステージングに貯めて 4B 境界で
   吐き、端数は Commit 時に 0xFF パディングして書く(len はヘッダが持つので
   パディングは無害)。ホストのメモリ backend でも**アラインと二重書きを検査**して、
   実機でしか出ない類のバグをループバックで拾えるようにした。
6. **カスタムクラスタの登録は `sm_init` より前**(ステージング方式)。一方で
   active slot はパーティション走査が要るので、`script_store_init()` の中で
   ローダと同一規則の CRC 検証込み走査を先に回している(128KB の CRC で数 ms)。
7. **`sm_endpoint_register` は EP0/EP1 に使えない**(`-5`)が、**カスタムクラスタは
   合成 EP へ足せる**。ScriptStore を EP1 に載せると新規 EP を消費せず、
   Descriptor の ServerList もシムが合成してくれる(F4b の install_custom)。
