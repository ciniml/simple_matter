# M5Stack AirQ の Matter ファームウェア再実装 — 調査と移植設計

対象: M5Stack AirQ(Air Quality Kit)向けの Matter ファームウェアを、既存の
esp-matter/ESP-IDF 実装(`/home/kenta/repos/m5stack_matter_examples`)から
simple-matter ベース(Rust / no_std)へ再実装する検討。本書は調査・設計
(+フェーズ進捗の記録)。

**進捗**: フェーズ A1(クラスタ実装 + PC シム E2E)**完了(2026-07-09)**。
フェーズ A5(ESP32-S3 ポート)は **ツールチェーン + 全ビルド整備まで完了
(2026-07-09。ports/esp32s3、実機未検証 = AirQ 未接続)**。記録は §7.1、
実機残作業は §7.3。なお A2-A4(C6 ブリッジ = NanoC6 + 外付けセンサ)は
機材未手配のため未着手のまま A5 のビルド整備を先行した(センサドライバ統合の
初検証も AirQ 実機で行うことになる点に注意)。

前提となる現状(2026-07-08 時点):

- コア(`simple-matter`)はクラスタ約 20 種を実装済み。計測系 5 クラスタ
  (温度/気圧/流量/湿度/照度)は `measurement_cluster!` マクロで量産
  (`dm/clusters/measurement.rs`、basic-clusters.md §1.3)。
- ports/esp32 は **ESP32-C6(RISC-V、upstream stable Rust)** 前提で E0-E6 完了:
  esp-hal 1.1.1 + esp-radio 0.18(BLE+Wi-Fi coex)+ TrouBLE 0.6 + embassy-net。
  BLE コミッショニング・fabric 永続化・Wi-Fi 実 join・UDP/mDNS・chip-tool
  `pairing ble-wifi` まで実機(M5Stack NanoC6)で検証済み(port-esp32-device.md §8)。
- AirQ の SoC は **ESP32-S3(Xtensa)** であり、現 ports の「upstream Rust で完結」
  という前提と衝突する(本書 §3 が主要論点)。

---

## 0. サマリ(推奨路線と設計判断)

1. **クラスタ実装(A1)はハード選定と独立に先行できる**。必要な新規クラスタは
   Air Quality(0x005B)+ Concentration Measurement 族(CO2/PM1/PM2.5/PM10/TVOC/NO2 の
   6 種)で、後者は既存 `measurement_cluster!` と同型の
   **`concentration_cluster!` マクロで量産可能**(§4)。PC シム example
   (`air-quality-sensor.rs`)+ chip-tool/smctl E2E で先にゲートを閉じる。
2. **ツールチェーン判断: AirQ 実機(S3/Xtensa)は最終フェーズへ後送し、
   「AirQ ハード据え置き・C6 ベースの同等構成(NanoC6 + Grove 接続センサ)」を
   先に作る**(§3)。Xtensa は 2026 年時点でも espup(rustc フォーク)が必要で、
   E1-E5 で蓄積した C6 資産(TrouBLE/esp-radio/embassy 構成、実機で潰した罠)を
   そのまま使える C6 経路のほうがリスクが一桁小さい。S3 対応は独立フェーズ(A5)
   として espup スパイクから入る。
3. **センサドライバは既製の embedded-hal crate で足りる**:
   [`sen5x-rs`](https://crates.io/crates/sen5x-rs)(SEN55、embedded-hal 1.0 /
   async 対応)と [`scd4x`](https://crates.io/crates/scd4x) または
   [`libscd`](https://crates.io/crates/libscd)(SCD40、embedded-hal(-async))。
   esp-hal の I2C は embedded-hal(-async) trait を実装するため接着コードは薄い(§2)。
4. **既存 FW から流用するのは「コード」ではなく「知識」**: ピンマップ・センサ初期化
   シーケンス(SCD4x の wake/stop/reinit/温度オフセット、SEN55 の GPIO10
   電源制御 + 起動待ち)・スケーリング(SEN55 は ×10/×100/×200 の固定小数)・
   計測周期(SCD4x 30s / SEN55 10s)・エンドポイント⇔クラスタ対応。C++ コード
   自体は esp-matter API 密結合で移植対象にならない(§1)。
5. **VOC/NOx の意味論を既存 FW から是正する**: 既存 FW は Sensirion の
   **無次元 index(0-500)** を TVOC/NO2 の Concentration(濃度)クラスタに
   そのまま入れており、単位が仕様と不整合。再実装では VOC/NOx index は
   **Air Quality(0x005B)の AirQualityEnum 算出材料**として使い、TVOC/NO2
   クラスタは初期スコープから外す(載せるなら MeasurementUnit との整合を
   取れないことを明記した上でオプション扱い。§4.3)。
6. **ディスプレイ(e-ink)と電源管理(バッテリー/スリープ/ICD)は初期スコープ外**
   (§6)。AirQ は常時給電(USB、HOLD=GPIO46 HIGH 維持)+ 表示なしで Matter
   ノードとして完結する。ICD はコア未実装(project-status の残課題)であり、
   本移植と直交する別トラックとする。

---

## 1. 既存ファームウェアの分析(m5stack_matter_examples)

### 1.1 構成

| 項目 | 内容 |
|---|---|
| SDK | **esp-matter(Espressif)+ ESP-IDF**、C++。connectedhomeip を内包 |
| ビルド | Docker(esp-matter 公式イメージ + NanoC6 パッチ)、`idf.py set-target esp32s3` |
| 対象チップ | **ESP32-S3**(AirQ = M5StampS3)。sdkconfig.defaults に c3/c6/h2 用も併存(Thread 系デバイス転用の名残) |
| トランスポート | Wi-Fi + BLE コミッショニング(`CONFIG_BT_ENABLED=y`)。Thread は sleepy_device(NanoC6)側のみ |
| 主ソース | `matter/air_quality/main/app_main.cpp`(約 1,170 行、単一ファイル)+ `main/drivers/epd.{h,cpp}` |
| センサドライバ | `components/scd4x-idf`(Sensirion 公式 C ドライバの IDF 移植。scd4x + sen5x + sensirion_i2c HAL) |
| 表示 | M5GFX/LGFX(`Panel_GDEW0154D67`、200×200 e-ink)を SPI 直結 |
| DAC/PAI | テスト用 factory データ(`matter/common/mfg_manifest/`、VID 0xFFF1 系)。DeviceInstanceInfoProvider をカスタム実装 |

### 1.2 Matter データモデル(既存 FW)

エンドポイント構成(esp_matter の endpoint API で生成):

| EP | esp-matter デバイスタイプ | クラスタ | データ源 |
|---|---|---|---|
| 1 | temperature_sensor | TemperatureMeasurement 0x0402 | SCD4x(m°C → ×100) |
| 2 | humidity_sensor | RelativeHumidityMeasurement 0x0405 | SCD4x(mRH → ×100) |
| 3 | air_quality_sensor | + PM1 Concentration 0x042C | SEN55(×10 固定小数 → float µg/m³) |
| 4 | air_quality_sensor | + PM2.5 Concentration 0x042A | SEN55 |
| 5 | air_quality_sensor | + PM10 Concentration 0x042D | SEN55 |
| 6 | air_quality_sensor | + CO2 Concentration 0x040D | SCD4x(ppm → float) |
| 7 | air_quality_sensor | + TVOC Concentration 0x042E | SEN55 **VOC index(無次元)** |
| 8 | air_quality_sensor | + NO2 Concentration 0x0413 | SEN55 **NOx index(無次元)** |

実装上の特徴と問題点(再実装で改善する点):

- **計測値 1 種ごとに air_quality_sensor エンドポイントを 1 個生成**しており、
  Air Quality Sensor(0x002C)が 6 個並ぶ。Matter 的には **1 つの 0x002C EP に
  Concentration クラスタ群を同居**させるのが自然(§5)。esp-matter の
  `air_quality_sensor::create` が必須の AirQuality クラスタを足すが、
  **AirQuality 属性(総合評価 enum)は誰も更新していない**(常に Unknown)。
- **VOC/NOx は Sensirion index(0-500、無次元)を濃度クラスタの MeasuredValue に
  そのまま代入**(コメントでも「index を TVOC/NO2 クラスタで報告」と明記)。
  MeasurementUnit と不整合(§0-5)。
- 属性更新は `ScheduleLambda` で Matter スレッドへ移送(FreeRTOS タスク間)。
  simple-matter は sans-IO 単一ポンプなのでこの複雑さ自体が消える。
- SEN54/SEN55 の温湿度(ambient_temperature/humidity)は読むだけで Matter へは
  未反映(SCD4x 側を採用)。再実装でも SCD4x 系を温湿度ソースとする。

### 1.3 ハードウェア制御の知識(流用対象)

- **I2C**: SDA=GPIO11、SCL=GPIO12、100kHz(ESPHome 設定では 50kHz。バス上に
  SEN55 0x69 / SCD40 0x62 / RTC8563 が同居するため低速安定側に倒すのが無難)。
- **SEN55 電源**: GPIO10 を **LOW で ON**(ロードスイッチ、SEN55 はファン内蔵で
  電流大)。ON 後 **1 秒の起動待ち**が必要。リセット(`device_reset`)後にも 1 秒待ち。
- **SCD4x 初期化**: `wake_up → stop_periodic_measurement → reinit →
  set_temperature_offset(既定オフセットを Kconfig 化)→ start_periodic_measurement`。
  data_ready ポーリング後に read。周期 30 秒(SCD40 の定格 5 秒だが電力/自己発熱を配慮)。
- **SEN55 計測**: `start_measurement` 後、10 秒周期で data_ready → read。
  戻り値のスケーリング: PM 系 ×10、湿度 ×100、温度 ×200、VOC/NOx index ×10。
- **EPD**: 1.54 インチ 200×200(パネル GDEW0154D67 / 現行資料では GDEY0154D67)、
  SPI: MOSI=6, SCLK=5, DC=3, CS=4, RST=2, BUSY=1、40MHz。
- 計測タスクは値をミューテックス付き共有構造体に置き、表示タスク(30 秒周期)が読む。

---

## 2. M5Stack AirQ ハードウェアマップ

出典: [m5-docs Air Quality](https://docs.m5stack.com/en/core/Air_Quality)、
[ESPHome M5Stack AirQ](https://devices.esphome.io/devices/m5stack-airq/)、
[製品ページ](https://shop.m5stack.com/products/air-quality-kit-w-m5stamps3-sen55-scd40)
(v1.0 は EOL、現行は [v1.1 = M5StampS3A 搭載](https://shop.m5stack.com/products/air-quality-kit-v1-1-with-m5stamps3a-sen55-scd40))。

| 要素 | 型番 / ピン | 必要ドライバ(Rust) | 状況 |
|---|---|---|---|
| SoC | **ESP32-S3FN8**(StampS3、Xtensa LX7 ×2、flash 8MB、PSRAM なし) | esp-hal(feature `esp32s3`) | esp-hal は S3 対応済みだが **Xtensa ツールチェーン必須**(§3) |
| PM/VOC/NOx/温湿度 | **SEN55**(I2C 0x69) | [`sen5x-rs`](https://crates.io/crates/sen5x-rs) — no_std、embedded-hal 1.0、`async` feature で embedded-hal-async 対応 | ○ 既製 crate |
| CO2(+温湿度) | **SCD40**(I2C 0x62) | [`scd4x`](https://crates.io/crates/scd4x)(embedded-hal(-async)、ESP32-C3+Embassy example あり)or [`libscd`](https://crates.io/crates/libscd) | ○ 既製 crate |
| RTC | **RTC8563**(BM8563、PCF8563 互換、同一 I2C バス) | `pcf8563` 系 crate あり(スリープ復帰用。初期スコープ外) | △ 初期不使用 |
| e-ink | **GDEY0154D67** 1.54" 200×200(SSD1681 系)SPI: BUSY=1, RST=2, DC=3, CS=4, SCK=5, MOSI=6 | `ssd1681` / `epd-waveshare`(1.54" v2 200×200)候補。要実機確認 | △ 初期スコープ外 |
| I2C バス | SDA=11、SCL=12(50-100kHz) | esp-hal I2C(embedded-hal(-async) 実装) | ○ |
| SEN55 電源 | GPIO10(**LOW で ON**、ON 後 1 秒待ち) | esp-hal GPIO | ○ |
| ボタン | A=GPIO0、B=GPIO8、HOLD=GPIO46、PWR=GPIO42 | esp-hal GPIO | ○ |
| 電源保持 | **GPIO46 HIGH で電源維持**(バッテリー動作時) | 起動直後に HIGH 固定(初期スコープの唯一の電源処理) | ○ |
| ブザー | GPIO9(パッシブ) | esp-hal LEDC/PWM(任意) | △ 任意 |
| バッテリー | 600mAh @3.7V + RTC による timer wake | ICD/スリープ設計が必要 → 初期スコープ外(§6) | △ |
| Grove | SDA=13、SCL=15(HY2.0-4P) | — | C6 ブリッジ構成(§3.3)で利用可能な参考 |

注: AirQ v1.1(M5StampS3A)はモジュール改版のみでピン/センサ構成は同一とされるが、
A5(実機フェーズ)着手時に手元個体のリビジョンを確認すること。

**SHT4x について**: タスク仮説にあった SHT4x は AirQ には**非搭載**。温湿度は
SEN55/SCD40 の内蔵値を使う(既存 FW は SCD4x 側を採用)。なお Rust には
`sht4x` crate(embedded-hal 対応)が存在するため、別ハードで必要になっても問題ない。

---

## 3. ツールチェーン論点(最重要): S3/Xtensa vs C6/RISC-V

### 3.1 現状認識

- AirQ の ESP32-S3 は **Xtensa LX7**。ベアメタル target
  `xtensa-esp32s3-none-elf` は **upstream rustc に存在せず**、
  [espup](https://github.com/esp-rs/espup) で Espressif の
  **rustc フォーク(esp channel)** を導入する必要がある(2026 年時点でも同様。
  espup の stable 指定は RISC-V にのみ適用され、Xtensa はフォーク必須)。
  LLVM 側の Xtensa バックエンド upstream 化は進行しているが、rustc target の
  upstream 化は未完了 — A2 着手時に最新状況を再確認すること。
- simple-matter の ports/esp32 は「**upstream stable Rust で完結**」を C6 選定の
  主理由にしており(ports/esp32/README.md)、S3 対応はこの前提を破る。
- esp-hal 自体は 1.x で S3 を含む全チップ統一 API を提供済み。esp-radio の
  Wi-Fi/BLE coex も S3 対応(port-esp32-device.md §1 の表に記載済み)。
  つまり**コードはほぼ C6 版のままで、問題はツールチェーンだけ**。

### 3.2 選択肢の比較

| 案 | 内容 | 利点 | 欠点/リスク |
|---|---|---|---|
| (a) espup で S3 直行 | ports/esp32 に `esp32s3-firmware` を追加、rust-toolchain を esp channel に | AirQ 実機に最短 | rustc フォーク運用(CI・再現性・stable からの遅延)。E1-E5 の実機検証を S3 で全部やり直し。coex/ヒープ挙動も再計測 |
| (b) **C6 ブリッジ先行(推奨)** | NanoC6 + Grove/外付けで SEN55・SCD40 を接続し、**AirQ 相当の C6 構成**を先に完成 | E1-E6 資産(BLE/Wi-Fi/KVS/mDNS、実機で潰した罠)を無変更で流用。stable Rust 維持。センサドライバ統合とクラスタ実装を S3 リスクから分離 | AirQ の筐体/表示/電源は未達(センサ配線は手組み)。最終的に S3 は別途必要 |
| (c) ESP-IDF std 路線 | esp-idf-hal/svc(std)で S3 | ツールチェーンは espup 同様必要だが IDF の実績あり | port-esp32-device.md §1 で不採用済みの路線(フットプリント目標と非整合)。二重投資 |

**判断**: (b) → (a) の 2 段構え。クラスタ(A1)とセンサドライバ統合(A3)は
(b) の C6 上で完成させ、S3 対応(A5)は「動くものを Xtensa に載せ替える」だけの
純ツールチェーン課題に縮退させる。(a) を先にやると「初めてのセンサ統合 × 初めての
Xtensa × 初めての S3 radio」が同時に来る。

### 3.3 C6 ブリッジ構成の具体化

- ハード: M5Stack NanoC6(E1-E6 実績機)+ SEN55(M5 の SEN55 ユニット or
  素子直結。**5V 供給必須**、Grove の 5V ラインで供給)+ SCD40(Grove ユニット)。
  I2C 1 本に 0x69/0x62 を同居(AirQ と同トポロジ)。SEN55 の電源制御 GPIO は
  省略可(常時 ON でよい。AirQ 実機では GPIO10 制御を実装)。
- ソフト: `ports/esp32/esp32c6-firmware/src/bin/airq-c6.rs`(仮)= e5-light の
  dual-transport 構成 + センサタスク + Air Quality クラスタ群。
- S3 移行時(A5): `ports/esp32/esp32s3-firmware/`(または `ports/esp32s3/` として
  workspace 分離 — rust-toolchain.toml がターゲット毎に異なるため **workspace 分離が
  必須**。C6 側の stable 前提を汚染しない)。

---

## 4. Matter クラスタマップ(ギャップ分析)

仕様ソース: `research/connectedhomeip/src/app/zap-templates/zcl/data-model/chip/`
(air-quality-cluster.xml / concentration-measurement-cluster.xml / matter-devices.xml)。
Matter 1.3 で全クラスタ確定済み。

### 4.1 実装済み(流用)

| クラスタ | ID | 状況 |
|---|---|---|
| TemperatureMeasurement | 0x0402 | ✅ `measurement_cluster!` 生成済み(i16、0.01℃) |
| RelativeHumidityMeasurement | 0x0405 | ✅ 同上(u16、0.01%) |
| Identify | 0x0003 | ✅(全センサ EP の必須クラスタ) |
| Descriptor / 管理系(EP0 の 7 種) | — | ✅(sensor-hub example で実証済み) |

### 4.2 新規実装が必要なクラスタ

| クラスタ | ID | rev | 種別 | データ源 | 優先度 |
|---|---|---|---|---|---|
| **Air Quality** | 0x005B | 1 | 単独(enum 属性 1 個) | 各計測値から算出 | **必須**(0x002C の必須クラスタ) |
| CO2 Concentration | 0x040D | 3 | Concentration 族 | SCD40(ppm) | 高 |
| PM2.5 Concentration | 0x042A | 3 | Concentration 族 | SEN55(µg/m³) | 高 |
| PM10 Concentration | 0x042D | 3 | Concentration 族 | SEN55 | 高 |
| PM1 Concentration | 0x042C | 3 | Concentration 族 | SEN55 | 中 |
| TVOC Concentration | 0x042E | 3 | Concentration 族 | SEN55 VOC index(**単位問題** §4.3) | 低(初期外) |
| NO2 Concentration | 0x0413 | 3 | Concentration 族 | SEN55 NOx index(同上) | 低(初期外) |

参考: 族の他メンバー(CO 0x040C、Ozone 0x0415、Formaldehyde 0x042B、Radon 0x042F)は
センサが無いため対象外だが、マクロ化により 1 行で追加可能な形にしておく。

**Concentration Measurement 族の共通形**(concentration-measurement-cluster.xml):

- FeatureMap: **MEA(bit0、数値計測)のみ立てる**(最低 MEA か LEV のどちらかが必要)。
  PEA/AVG(ピーク/平均)、LEV(レベル表示)は任意 → 非実装。
- 属性(MEA 構成): MeasuredValue(0x0000、**single/f32**、nullable、subscribe)、
  MinMeasuredValue(0x0001)/ MaxMeasuredValue(0x0002)(nullable f32、固定)、
  MeasurementUnit(0x0008、enum8: 0=PPM, 1=PPB, …, 4=UGM3)、
  MeasurementMedium(0x0009、enum8、常に必須: 0=Air)、Uncertainty(0x0007)は任意 → 非実装。
- コマンド・イベントなし。

**実装方式**: `measurement_cluster!` の同型拡張として
`concentration_cluster!`(`dm/clusters/concentration.rs`)を新設し、
**型名 / cluster id / MeasurementUnit 既定値**を引数に 6+ クラスタを 1 宣言ずつで
量産する。既存マクロとの差分は:

1. 値型が f32(TLV `single`)。TLV writer には `write_f32` が既にあるが、
   **`AttrEncoder::write_nullable_f32` の追加が必要**(codec.rs への小改修)。
2. MeasurementUnit / MeasurementMedium の固定値属性 2 個が増える
   (コンストラクタ引数 or マクロ引数で単位指定)。
3. FeatureMap = MEA(1)(既存は 0)。

→ 既存マクロの構造がそのまま使えるため、**族 6 種で「マクロ 1 本 + 宣言 6 行 +
単体テスト」の工数 S〜M**。`cluster!` マクロの流儀(dirty/subscribe/nullable)は
実証済みパターンの踏襲で済む。

**Air Quality(0x005B)**: 属性 1 個(AirQuality、enum8 0-6、subscribe)+
FeatureMap = FAIR|MOD|VPOOR|XPOOR(0x0F、全レベル対応)。手書きで工数 S。
AirQualityEnum の算出(CO2/PM2.5 等 → Good..ExtremelyPoor)は**クラスタではなく
アプリ層(example / ファーム)の責務**とする(閾値はデバイスポリシー。コアは
`set_air_quality(enum)` を受けるだけ)。既存 FW が放置していた「総合評価の未更新」を
ここで是正する。

### 4.3 VOC/NOx index の扱い(既存 FW からの意味論変更)

Sensirion VOC/NOx index は較正済み濃度ではなく相対指標(1-500、無次元)。
Matter の TVOC/NO2 Concentration クラスタに ppm/ppb として入れるのは不正確
(既存 FW の挙動)。方針:

- **初期スコープ: TVOC/NO2 クラスタは載せない**。VOC index は AirQualityEnum 算出の
  入力として活用(例: Sensirion 推奨の index 帯 → Good/Fair/Moderate…)。
- 将来オプション: エコシステム互換(Home Assistant 等が TVOC 表示を期待)を優先する
  場合のみ、既存 FW と同じ「index 値を MeasuredValue に入れる」割り切りを feature 的に
  提供(その場合も MeasurementUnit=PPB 等の詐称はせず、doc に明記)。

**A1 での判断(2026-07-09)**: TVOC(0x042E)/ NO2(0x0413)の**クラスタ型は
コアに実装済み**(`concentration_cluster!` の 2 宣言。将来較正済み濃度センサを
使うデバイスのため)。ただし `air-quality-sensor` example / AirQ ファームには
**搭載しない**(上記方針どおり。既存 FW のバグ 2 の是正)。dead-code 除去により
未使用クラスタのフットプリント影響はゼロ(flash-probe 実測 102259B、増分なし)。

### 4.4 smctl / example

- smctl: `air-quality` + concentration 族 6 種の `cluster_def!` 追加(read/subscribe 確認用)。
- PC example: `examples/air-quality-sensor.rs` — sensor-hub の流儀で
  EP1 = Air Quality Sensor 0x002C(§5 のクラスタ構成)、擬似センサ(三角波 +
  AirQuality enum の周期遷移)。既存 sensor-hub に EP 追加する案もあるが、
  AirQ 移植のリファレンスとして**単独 example** の方が ports へ写しやすい。

## 5. デバイスタイプ: Air Quality Sensor(0x002C、rev 1)

matter-devices.xml より:

| クラスタ | 必須/任意 |
|---|---|
| Descriptor | 必須 |
| Identify(IdentifyTime/IdentifyType + Identify コマンド) | 必須 |
| **Air Quality 0x005B** | **必須** |
| TemperatureMeasurement / RelativeHumidityMeasurement | 任意 |
| Concentration 族(CO/CO2/NO2/Ozone/HCHO/PM1/PM2.5/PM10/Radon/TVOC) | 任意 |

**エンドポイント設計(既存 FW の 8 EP 構成を 3 EP に整理)**:

| EP | デバイスタイプ | クラスタ |
|---|---|---|
| 0 | Root Node 0x0016 | 既存 7 種 |
| 1 | **Air Quality Sensor 0x002C** | Identify + AirQuality + CO2 + PM1 + PM2.5 + PM10 + Descriptor |
| 2 | Temperature Sensor 0x0302 | Identify + TemperatureMeasurement + Descriptor |
| 3 | Humidity Sensor 0x0307 | Identify + RelativeHumidityMeasurement + Descriptor |

温湿度を 0x002C の EP1 に同居させることも仕様上は可能(任意クラスタ)だが、
コントローラ UI(Apple Home 等)はデバイスタイプ単位でタイルを出すため、
sensor-hub と同じ「1 計測ドメイン = 1 EP」の分離構成を採る。

## 6. ディスプレイ / 電源管理の切り分け

| 項目 | 初期スコープ | 将来 |
|---|---|---|
| e-ink 表示 | **外す**。Matter ノードとしては不要。デバッグはシリアルログ | `ssd1681`/`epd-waveshare` 系 crate で計測値表示(D2 フェーズ)。embedded-graphics ベースなので no_std 整合は良い |
| 電源保持 | GPIO46 HIGH 固定(起動直後)+ USB 給電前提 | — |
| バッテリー運用 / スリープ | **外す**。SEN55 はファン駆動で連続計測前提のため、スリープ設計は計測戦略ごと変える必要がある(間欠計測 + RTC wake) | Matter **ICD**(SIT/LIT)はコア未実装(project-status 残課題)。ICD 実装後に「RTC8563 timer wake + 間欠計測 + LIT」を別トラックで設計 |
| ボタン/ブザー | 外す(factory reset は既存の手段で) | ボタン A 長押し = factory reset、ブザー = Identify 応答など |

初期スコープの AirQ ファームは「常時給電の Wi-Fi Matter センサノード」。
これは既存 FW と同じ運用形態(既存 FW もバッテリー/スリープ未対応)。

## 7. フェーズ計画・工数感・リスク

### 7.1 フェーズ

| フェーズ | 範囲 | 検証ゲート | 工数感 |
|---|---|---|---|
| **A1: クラスタ実装(PC シム E2E)** | `concentration_cluster!` マクロ + 6 クラスタ、AirQuality 0x005B、`AttrEncoder::write_nullable_f32`、`examples/air-quality-sensor.rs`、smctl cluster_def 追加 | chip-tool: pairing → 0x002C の device-type-list / airquality read / co2・pm25 subscribe。smctl read --names | **✅ 完了(2026-07-09)** |
| **A2: ハード選定 / ツールチェーン確認** | C6 ブリッジ機材(NanoC6 + SEN55 5V 供給 + SCD40)手配・配線。espup/S3 の最新状況・esp-hal S3 の coex 実績を再調査(§3.1 の再確認) | I2C スキャンで 0x69/0x62 応答(素の esp-hal bin) | **S** |
| **A3: センサドライバ統合(C6)** | `sen5x-rs`/`scd4x`(async)を embassy タスクに統合、SCD4x 初期化シーケンス移植(§1.3)、AirQualityEnum 算出ロジック、`airq-c6` bin(e5-light ベース) | シリアルで実測値ログ(既存 FW と同一個体センサの値比較)| **M** |
| **A4: C6 実機 E2E** | chip-tool `pairing ble-wifi` → 全属性 read / subscribe(30s/10s 周期更新の配信)、リブート後 CASE 再確立(E4 資産) | chip-tool + smctl のフル E2E、フットプリント実測を README に記録 | **S〜M** |
| **A5: ESP32-S3(AirQ 実機)ポート** | espup 導入、`ports/esp32s3` workspace(rust-toolchain 分離)、E1 相当スモーク(boot/TRNG)→ E2-E5 相当の再検証(S3 radio/coex)→ airq bin 移植 + GPIO10 電源制御 + GPIO46 HOLD | AirQ 実機で chip-tool フル E2E | **ビルド整備まで完了(2026-07-09)**。実機ゲートは §7.3(AirQ 未接続のため保留) |
| **A6(任意): 表示・UX** | e-ink 表示(計測値 + コミッショニング QR)、ボタン/ブザー | 目視 | M |
| (別トラック) | ICD/バッテリー運用 | — | コアの ICD 実装後 |

A1 と A2 は並行可能。総工数感: **A1-A4 で L 相当**(C6 ベース完成まで)、
A5 が追加で L。

**A1 完了記録(2026-07-09)**:

- コア: `dm/clusters/air_quality.rs`(0x005B、rev 1、FeatureMap=0x0F、`AirQualityEnum`
  は `Ord` 導出で worst-of 合成可)+ `dm/clusters/concentration.rs`
  (`concentration_cluster!` マクロ → CO2/PM1/PM2.5/PM10/TVOC/NO2 の 6 宣言。
  FeatureMap=MEA、MeasuredValue f32 nullable + Min/Max + MeasurementUnit/Medium)。
  codec に `AttrEncoder::write_f32` / `write_nullable_f32` を追加。
- **revision は本書の表どおり 3(Matter 1.3)を採用**。research の ZAP XML は
  1.6 世代で rev 5 に上がっているが、実装済み属性集合は 1.3 と同一(chip-tool
  v1.5.1 との相互運用に影響なし)。
- example: `examples/air-quality-sensor.rs`(§5 の 3 EP 構成)。擬似センサは
  CO2 400-1200ppm 三角波 + PM2.5 0-50µg/m³ 三角波 + 240 秒周期の汚染エピソード
  スパイク(最大 +250µg/m³、全レベル遷移の実証用)。**AirQuality は毎 tick
  CO2/PM2.5 の worst-of で算出・更新**(バグ 1 是正。閾値は屋内 IAQ / US EPA AQI
  相当のデバイスポリシー)。TVOC/NO2 は非搭載(バグ 2 是正、§4.3)。
- smctl: `air-quality` + concentration 族 6 種の cluster_def!(f32 の
  parse/表示経路は既存実装で完備)。device_types.rs の 0x002C は登録済みだった。
- E2E 実測(PC、chip-tool v1.5.1 snap + smctl): pairing already-discovered
  (--paa-trust-store-path、attestation 実検証)→ `airquality read air-quality`
  (3→2 変動)/ CO2 read = 1100.0(f32、unit=PPM)/ PM2.5 read = 30.0(f32、
  unit=UGM3)/ descriptor device-type-list = 44(Air Quality Sensor)。
  OCW manual code 経由で smctl を 2 fabric 目としてコミッショニングし、
  `--names` で device-type-list = `0x002c(AirQualitySensor)`、
  `air-quality subscribe` で **1-6 全レベルの変化レポートをライブ受信**
  (6→5→4→3→2→1→2→3、70 秒間)。
- ゲート: テスト 518(コア +7)+ 58(smctl +1)、clippy 0、no_std 3 ターゲット
  green、ports/esp32 ビルド green、flash-probe 102259B(増分ゼロ)。

**A5 進捗記録(2026-07-09。ツールチェーン + 全ビルド整備まで。実機未検証 = AirQ 未接続)**:

- **ツールチェーン(段階 1)**: espup 0.16.0 / esp channel(rustc 1.95.0-nightly
  フォーク、`xtensa-esp32s3-none-elf` built-in)を確認。esp toolchain は xtensa の
  プリビルド std を含まず **`build-std = ["core", "alloc"]` が必須**(rust-src 同梱)。
  リンカは target spec 既定の **xtensa-esp32s3-elf-gcc**(esp toolchain 同梱、
  `. ~/export-esp.sh` で PATH)+ `-nostartfiles` + `-Wl,-Tlinkall.x`。
  C6(RISC-V)で必須だった `-C force-frame-pointers` は **Xtensa では不要**
  (esp-backtrace は register window を辿る)。stable への非干渉はコア 518 +
  smctl 58 テスト green / C6 workspace ビルド green で確認。
- **`ports/esp32s3` は独立 workspace**(§3.3 の判断どおり)。rust-toolchain.toml
  (esp channel)がルート(stable)/ ports/esp32(stable + riscv)と両立しない
  ため分離必須。lock はコミット(C6 と同方針)。
- **S3 版スタック(段階 2)**: ポート層(ble/kvs/net/wifi)は C6 実装のロジック
  そのままで chip feature 差し替えのみ(esp-hal 1.x の統一 API が機能)。
  `esp_rtos::start(timg0.timer0, sw_int.software_interrupt0)` のシグネチャも S3 で
  同一。差分は AirQ に LED が無いことによる LEDC PWM 削除だけ。
  esp-radio 0.18 の esp32s3 + ble + wifi + coex はビルド green(実機 coex 挙動は
  未検証 = R1 残)。
- **センサ統合(段階 3)**: `sensors.rs` + `airq-sensor` bin。crate 選定は
  **SEN55 = sen5x-rs 0.4.0**(embedded-hal 1.0。スケーリングが §1.3 の知識と一致
  することをソース確認。**温度を u16 解釈する癖**があり氷点下で不正 →
  `fix_sen55_temp` で i16 再解釈補正)、**SCD40 = libscd 0.5.1**(sync + scd4x
  feature。コマンド実行待ちを内包。SCD41 専用コマンドが feature 分離されており
  wake_up 誤用を型で防げるため `scd4x` crate より優先)。バス共有は
  embedded-hal-bus の RefCellDevice(単一センサタスクが順に触る)。
  初期化は §1.3 踏襲(SCD40: stop→reinit→start、SEN55: GPIO10=LOW→1s→reinit→start)。
  周期は既存 FW と同じ SEN55 10s / SCD40 30s。温湿度クラスタのソースは
  **SEN55 側**(A5 タスク指定。既存 FW の SCD4x 採用 = §1.2 とは異なる。SCD40 の
  温湿度は参考ログ)。データモデルは §5 の 3 EP(A1 example と同一)+ EP0 は
  C6 e5-light と同じ管理系 5 クラスタ。AirQuality は CO2/PM2.5 worst-of
  (材料が無い項は Unknown=Ord 最小として max 合成)。VOC/NOx はログのみ(§4.3)。
- フットプリント(espflash save-image): スモーク 104,928 B / s3-light 911,600 B /
  airq-sensor 952,544 B(8MB flash に対し 12% 未満)。
- ゲート: 3 bin ビルド green + clippy 0(esp channel)、コア 518 + smctl 58 green、
  C6 riscv ビルド green(回帰なし)。**実機ゲート(§7.3)は AirQ 接続後**。

### 7.2 リスク表

| # | リスク | 影響 | 確認方法 / 回避策 |
|---|---|---|---|
| R1 | **Xtensa ツールチェーン**(espup フォーク運用、CI 再現性、esp-hal S3 + esp-radio coex の未検証差分) | A5 全体 | (b) 先行で分離済み。A5 冒頭に E1 相当スモークのゲートを置き、詰まったら「C6 ブリッジ構成を成果物とし S3 は保留」で撤退可能 |
| R2 | `sen5x-rs`/`scd4x` crate の品質(スケーリング・data_ready 挙動・async 対応の成熟度) | A3 | 既存 FW と同一センサでの値比較をゲート化。不足時は Sensirion C ドライバのシーケンス(§1.3)を参照に薄い自前ドライバ(I2C コマンドは単純) |
| R3 | SEN55 の電源(5V/ファン、ピーク電流)を C6 ブリッジで安定供給できるか | A2/A3 | Grove 5V ライン + 実測。不安定なら外部 5V 供給 |
| R4 | f32 属性(single)の subscribe/report 経路が未実証(既存クラスタは整数のみ) | A1 | 単体テスト + chip-tool subscribe で dirty→report を確認(TLV writer は f32 対応済み) |
| R5 | VOC/NOx を落とすことによるエコシステム期待とのズレ(HA 等が TVOC を表示しない) | 機能性 | §4.3 の将来オプション(明示的割り切りで復活可能な設計) |
| R6 | I2C バス共有(SEN55/SCD40/RTC、50-100kHz)でのタイミング・クロックストレッチ | A3 | 既存 FW 実績(100kHz)に合わせ、問題時 50kHz へ。esp-hal I2C のタイムアウト設定を確認 |
| R7 | C6 の RAM/flash 予算(e5-light + センサタスク + クラスタ増分) | A3/A4 | E6 の実測ベースに bloat-check で差分監視。クラスタ 7 種追加は数 KB 級の見込み(measurement 系実績より) |
| R8 | AirQ v1.1(StampS3A)でのピン/挙動差分 | A5 | 着手時に実機リビジョン確認(§2 注記) |

### 7.3 AirQ 接続後の実機チェックリスト(A5 残作業)

前提: AirQ を USB 接続し、`espflash board-info` で **esp32s3 / 8MB flash** を確認
(他の ESP デバイス同居時はポート取り違えに注意。board-info もリセットを伴う)。
手元個体のリビジョン(v1.0 = StampS3 / v1.1 = StampS3A)も記録すること(R8)。

1. **段階 1 スモーク**: `esp32s3-firmware` を書き込み → バナー + TRNG サンプル +
   P-256(SEC1 tag 0x04)+ heartbeat をシリアルで確認(stty+cat。
   `espflash monitor --no-reset` 禁止)。
   ※ 2026-07-09 に手違いで別個体の S3(rev v0.2, 8MB)へ書き込んだ際は
   全チェック green(Xtensa バイナリが実シリコンで動く証明にはなっている)。
2. **段階 2(s3-light)**: BLE 広告 → chip-tool
   `pairing ble-wifi 1 <ssid> <pass> 20202021 3840`(--paa-trust-store-path または
   --bypass-attestation-verifier)でフルコミッショニング → `onoff toggle` →
   リブート後 CASE 再確立。S3 coex の安定性(R1)・ヒープ(144KiB で足りるか)を
   ログで確認。
3. **I2C スキャン相当**: `airq-sensor` 起動ログで SEN55/SCD40 の serial number が
   出ること(= 0x69/0x62 応答)。NACK が続く場合は 50kHz へ落とす(R6)。
4. **段階 3(airq-sensor)E2E**:
   - シリアルで実測値ログ(CO2 400-2000ppm / PM2.5 数-数十 µg/m³ / 温湿度が
     現実的な室内値)。既存 esp-matter FW と同一個体での値比較(R2)。
   - chip-tool: pairing ble-wifi → `airquality read air-quality 1 1` /
     `carbondioxideconcentrationmeasurement read measured-value 1 1` /
     `pm25concentrationmeasurement read measured-value 1 1` /
     `temperaturemeasurement read measured-value 1 2` /
     `relativehumiditymeasurement read measured-value 1 3`。
   - smctl: OCW 経由 2 fabric 目 + `--names` read + `air-quality subscribe` で
     時間変動(換気・呼気で CO2 を動かす)のレポート受信。
   - リブート → fabric/資格情報復元 → 自動 Wi-Fi join → CASE 再確立 → read。
5. 結果を本書 §7.1 の A5 行・ports/esp32s3/README.md・memory へ反映する。

## 8. 参考(調査ソース)

- 既存 FW: `/home/kenta/repos/m5stack_matter_examples/matter/air_quality/`
  (app_main.cpp、drivers/epd.h、sdkconfig、Makefile)、`components/scd4x-idf/`。
- simple-matter: `docs/design/port-esp32-device.md`(E0-E7)、
  `docs/design/basic-clusters.md`(measurement_cluster! / sensor-hub)、
  `crates/simple-matter/src/dm/clusters/measurement.rs`、`ports/esp32/README.md`。
- Matter 仕様(ZAP XML): `research/connectedhomeip/src/app/zap-templates/zcl/data-model/chip/`
  — air-quality-cluster.xml、concentration-measurement-cluster.xml、matter-devices.xml。
- ハードウェア: [m5-docs AirQ](https://docs.m5stack.com/en/core/Air_Quality)、
  [ESPHome M5Stack AirQ](https://devices.esphome.io/devices/m5stack-airq/)、
  [M5Stack shop(v1.0 EOL)](https://shop.m5stack.com/products/air-quality-kit-w-m5stamps3-sen55-scd40)
  / [v1.1](https://shop.m5stack.com/products/air-quality-kit-v1-1-with-m5stamps3a-sen55-scd40)、
  [CNX Software v1.1 記事](https://www.cnx-software.com/2025/09/14/m5stack-air-quality-kit-v1-1-features-sensirion-sen55-environmental-sensor-and-scd40-co2-sensor/)。
- Rust crate: [sen5x-rs](https://crates.io/crates/sen5x-rs)、
  [scd4x](https://crates.io/crates/scd4x)、[libscd](https://crates.io/crates/libscd)、
  [espup](https://github.com/esp-rs/espup)(Xtensa ツールチェーン)。
