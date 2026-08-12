# 汎用 Matter ファームウェア構想(設定駆動 + スクリプト)

Status: 検討(G0)。実装フェーズ未着手。
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
