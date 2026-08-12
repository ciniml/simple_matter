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
