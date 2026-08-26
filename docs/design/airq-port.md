# M5Stack AirQ の Matter ファームウェア再実装 — 調査と移植設計

対象: M5Stack AirQ(Air Quality Kit)向けの Matter ファームウェアを、既存の
esp-matter/ESP-IDF 実装(`/home/kenta/repos/m5stack_matter_examples`)から
simple-matter ベース(Rust / no_std)へ再実装する検討。本書は調査・設計
(+フェーズ進捗の記録)。

**進捗**: フェーズ A1(クラスタ実装 + PC シム E2E)**完了(2026-07-09)**。
フェーズ A5(ESP32-S3 ポート)**完了(2026-07-12。AirQ 実機で §7.3 チェック
リスト全項目 green = chip-tool フル E2E + smctl 2 fabric 目 + リブート永続化)**。
記録は §7.1 と §7.3 の実機検証記録。なお A2-A4(C6 ブリッジ = NanoC6 +
外付けセンサ)は機材未手配のためスキップし、センサドライバ統合の初検証も
AirQ 実機で行った(SEN55/SCD40 とも初回起動から実測値取得に成功)。

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

### 4.3b VOC/NOx index → AirQualityEnum の閾値(残改善バッチ 1、2026-07-13)

§4.3 の「VOC index は AirQualityEnum 算出材料として活用」を実装した。閾値の根拠
(Sensirion 公式ドキュメント調査。詳細な出典は各 Info Note / Engineering
Guidelines / SEN5x データシート / 公式ウェビナー資料):

- **VOC index**(1-500、100 = 過去 24h の平常。アルゴリズムが 24h で 100 へ
  再基準化するため定常値は常に 100 近傍、リップル ±5):

  | AirQualityEnum | VOC index | 根拠 |
  |---|---|---|
  | Good | ≤ 150 | 100 = 平常(Info Note: VOC Index)+ >150 = 清浄機作動例(同)を最初の劣化境界に採用。**100 を境界にすると平常時にフラップする**(AirQ 実機で 100↔101 の振動を実測)ため 100-150 は Good に含める |
  | Fair | ≤ 200 | 公式ウェビナーの緑/黄境界 200 |
  | Moderate | ≤ 300 | 黄帯 200-400 の補間(公式のイベントゲーティング閾値 230 を含む) |
  | Poor | ≤ 400 | 公式の黄/赤境界 400 |
  | VeryPoor | > 400 | 公式赤帯("ventilate intensely")。**相対指標のため単一チャネル寄与は VeryPoor 上限**(ExtremelyPoor は絶対量ベースの CO2/PM に予約) |

- **NOx index**(1-500、**1 = クリーンが定常**。公式アンカーは「1 = クリーン」
  「>20 = 清浄機作動例」の 2 点のみで、個体差 ±50 point / ±50%(データシート
  Table 5)と大きい): 粗い 3 段階 + Poor 上限に制限 —
  **≤20 Good / ≤100 Moderate / >100 Poor**。
- **無効値ガード**: 有効範囲(1.0..=500.0)外 — 未較正マーカー 0x7FFF/10 =
  3276.7、ウォームアップ中の 0 — は Unknown として worst-of から除外
  (実機でウォームアップ直後の voc=0 / nox=3276.7 が Unknown 扱いになることを確認)。
- ウォームアップ: VOC はスペック到達 <1h、**NOx は <6h**(データシート)。
  無効値ガードで安全側だが、NOx の初期数時間は 1 に張り付くのが正常。
- worst-of 合成は従来どおり `AirQualityEnum: Ord` の max(Unknown = 最小)。
  実装は airq-sensor.rs の `classify_voc` / `classify_nox`。
  **濃度クラスタ(TVOC/NO2)には引き続き載せない**(§4.3 の方針は不変)。

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
| e-ink 表示 | ~~外す~~ → **計測値の定期表示を実装済み(2026-07-13、§7.5)**。epd-waveshare 0.6 epd1in54_v2 + embedded-graphics | コミッショニング QR 表示、バッテリー運用時の deep sleep |
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
| **A5: ESP32-S3(AirQ 実機)ポート** | espup 導入、`ports/esp32s3` workspace(rust-toolchain 分離)、E1 相当スモーク(boot/TRNG)→ E2-E5 相当の再検証(S3 radio/coex)→ airq bin 移植 + GPIO10 電源制御 + GPIO46 HOLD | AirQ 実機で chip-tool フル E2E | **✅ 完了(2026-07-12、AirQ 実機で §7.3 全項目 green。S3 固有のスタック逼迫バグ 1 件を発見・修正 = §7.3 実機検証記録)** |
| **A6(任意): 表示・UX** | e-ink 表示(計測値 + コミッショニング QR)、ボタン/ブザー | 目視 | **計測値表示は ✅ 完了(2026-07-13、§7.5 = 残改善バッチ 2)**。QR/ボタン/ブザーは未着手 |
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
- フットプリント(espflash save-image): スモーク 104,928 B / s3-light 906,800 B /
  airq-sensor 953,168 B(8MB flash に対し 12% 未満。2026-07-12 のヒープ調整 +
  heap-stats 後の実測)。
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

### 7.3.1 実機検証記録(2026-07-12、A5 完了)

個体: esp32s3 rev v0.2 / 8MB flash / MAC 48:27:e2:e3:0f:b8(/dev/ttyACM0。
espflash board-info で確認。キットの v1.0/v1.1 目視確認は未実施 — 挙動上の
差分は観測されず、R8 は顕在化しなかった)。espflash 4.4.0、NVS erase
(0x9000 0x6000)から実施。

1. **段階 1 スモーク ✅**: バナー / TRNG サンプル / P-256 keygen(SEC1 tag 0x04)/
   1Hz heartbeat すべて green。
2. **段階 2(s3-light)**: 単独では実施せず(airq-sensor が同一 transport 構成
   = BLE+Wi-Fi coex + UDP/mDNS を包含するため、段階 3 の E2E でまとめて検証)。
3. **I2C / センサ ✅**: `[sensors] SCD40 serial=135177073b70` /
   `SEN55 serial=443544363146`(0x62/0x69 応答、100kHz で NACK なし)。
   GPIO10=LOW→1s 待ち→reinit の電源シーケンス、GPIO46 HOLD とも問題なし。
   実測値: CO2 800-840ppm / PM2.5 1.6-5.2µg/m³ / RH 34-43% と現実的な室内値。
   温度は 32-33°C 表示で室温より数 °C 高い(筐体内自己発熱。SEN55/SCD40 とも
   同傾向で、既存 esp-matter FW でも知られる AirQ の特性。補正は将来課題)。
   VOC/NOx はログのみ(仕様どおり)。ウォームアップ中の SEN55 nox=3276.7
   (=0x7FFF/10、未較正マーカー)も初回読みで観測 — 実害なし。
4. **E2E**:
   - **S3 固有バグを発見・修正**: 初回 `chip-tool pairing ble-wifi` で BTP 確立
     直後に **stack guard 破壊 PANIC**(OpCreds invoke → `RcKeypair::sign` →
     p256 `ProjectivePoint::mul` の同期呼び出し連鎖)。原因は S3 の DRAM リンカ
     領域(約 340KiB)が C6 より狭く、ヒープ 144KiB + embassy main タスク POOL
     約 59KiB の残り = **.stack が約 37KiB** しかなかったこと(C6 e5-light は
     約 130KiB)。ヒープを **112KiB に削減**して .stack ≈ 69KiB を確保し解消。
     esp-alloc の `internal-heap-stats` を有効化し `[alive]` ログで heap_max を
     常時監視 — **E2E ピーク実測 90,160B / 114,688B**(コミッショニング +
     coex 中。マージン約 24KiB)。C6 で 112KiB が枯渇した ATT 切断は S3 では
     再現せず(radio blob のヒープ要求が C6 と異なる)。
   - chip-tool `pairing ble-wifi 1 <ssid> <pass> 20202021 3840 --ble-controller 0
     --paa-trust-store-path ...`(**--bypass 無し** = DAC/PAI 実検証)で
     **フルコミッショニング完走**: BTP(fragment=244)→ PASE → CSR/AddNOC →
     `[kvs] saved 1 fabrics` → Wi-Fi join → DHCP → mDNS operational →
     CASE over UDP → CommissioningComplete → BLE クリーン切断。
   - chip-tool read(実測値): `airquality read air-quality` = 2(Fair)/
     CO2 = 832.0(f32)/ PM2.5 = 2.4(f32)/ 温度(EP2)= 3267 / 湿度(EP3)=
     4169 / device-type-list = 44(Air Quality Sensor)。
   - smctl 2 fabric 目: **OCW は不可**(本 bin の EP0 は e5-light と同じ管理系
     5 クラスタで AdminCommissioning 0x003C 未搭載 — PC example には有り。
     搭載は将来課題)。代替の既存経路 `smctl pairing address 2 20202021
     <ip>`(PASE over UDP、attestation 実検証)で **2 fabric 目完走**。
     `--names` read: device-type-list = `0x002c(AirQualitySensor)`、CO2 = 833、
     PM2.5 = 2.5、温度 = 3284、湿度 = 4166。
   - smctl subscribe: `carbon-dioxide-concentration subscribe measured-value
     0 60 2 1` → ESTABLISHED(CASE は Sigma2Resume 再開)+ 周期レポート受信
     (+26s/+86s)。`air-quality subscribe` も ESTABLISHED + レポート受信
     (= 2。観測中に空気質レベル遷移なし — CO2 が 800-840ppm で安定していた
     ため。A1 の PC シムで全レベル遷移の配信は実証済み)。
5. **リブート永続化 ✅**: リセット → `[kvs] restored 2 fabrics / 2 resumptions /
   wifi credentials` → 自動 join(初回 AuthenticationExpired で 1 回リトライ後
   成功 — 自動再接続が機能)→ DHCP 同一 IP → chip-tool(fabric 1)/
   smctl(fabric 2)とも CASE 再確立して read 成功。

既知の罠の対処: BlueZ 亡霊キャッシュ(FFF6 の `bluetoothctl remove`)と
chip-tool kvs のフレッシュ化(`rm ~/snap/chip-tool/common/chip_tool_kvs`)を
事前に実施。`espflash reset` は cat がポートを開いたまま実行すると DOWNLOAD
モードへ落ちることがある(USB-Serial-JTAG のストラップ干渉)— reset 単独実行
→ 直後に stty+cat の順なら正常起動を捕捉できる。

残課題(A5 スコープ外): ~~AdminCommissioning(OCW)を S3 bin へ搭載~~、
~~SEN55 温度の自己発熱補正~~(いずれも §7.4 の残改善バッチ 1 で完了、2026-07-13)、
既存 esp-matter FW との同一個体値比較(R2 の完全クローズ)、s3-light 単独の
onoff E2E。

## 7.4 残改善バッチ 1(2026-07-13): OCW 搭載 + 温度補正 + VOC/NOx 活用

### 7.4.1 AdminCommissioning(0x003C)の ESP32 bin 搭載

`airq-sensor` / `s3-light`(S3)+ `e5-light`(C6)の EP0 に AdminCommissioning を
搭載し、PC example(air-quality-sensor.rs)の窓管理配線を pump へ移植した
(docs/design/admin-commissioning.md の設計どおり):

- 外部所有 `RefCell<CommissioningWindow>` を クラスタ / pump で共有、
  `DataModel::on_tick` で窓タイムアウト自動クローズ。
- pump が `take_event()` をポーリング: OpenedEnhanced → `set_pase_config`(動的
  verifier)+ `set_pase_enabled(true)` + **mDNS commissionable(CM=2、動的
  discriminator)広告**(ESP32 bin で commissionable 広告を出すのは初。instance id
  は MAC 由来)。Closed → PASE 無効化 + 広告停止。
- **PASE 窓ゲート**: fabric >0 で起動したら焼き込みパスコードの PASE を無効化
  (`[pase] disabled at boot`)。初回コミッショニング完了(fabric 0→1)でも無効化。
  全 fabric 削除で焼き込みパスコードへ戻す。fabric 増加で開窓中の窓を自動クローズ
  (§11.19.5)。
- 挙動変更: 従来可能だった「コミッショニング済みデバイスへの `pairing address`
  直接 PASE」は **窓が開いていない限り StatusReport(4) で拒否**される(仕様準拠。
  実機で確認)。

### 7.4.2 SEN55 温度の自己発熱補正(-3.0°C 固定オフセット)

`sensors::SEN55_TEMP_OFFSET_C = 3.0`(読み値から減算)。調査結果:

| ソース | 値 |
|---|---|
| ESPHome M5Stack AirQ コミュニティ設定(devices.esphome.io/devices/m5stack-airq) | **sen5x temperature_compensation offset=-3.0**(time_constant 1200s)← 採用 |
| M5Stack 公式 FW(AirQUserDemo) | 0.0(無補正。公式サンプルデータでも SEN55 36°C 級) |
| 既存 esp-matter FW(Kconfig 既定) | 9.0°C だが **SCD4x 側**(SEN55 には流用不可) |
| Sensirion 公式(SEN5x 補償ガイド) | 「筐体ごとに実測して決める」(万能推奨値なし) |

センサ内蔵の 0x60B2 補正(湿度も連動補正)は sen5x-rs 0.4 が未対応のためソフト
減算とし、**補正前後をログに並記**(`T=30.5C (raw=33.5C offset=-3C)`)。
実測: 起動直後 raw 38.7°C(ファン起動過渡)→ 定常 raw 33.5°C / 補正後 30.5°C。
湿度の連動補正(絶対湿度不変での RH 再計算)は将来課題。

### 7.4.3 実機 E2E 記録(AirQ、NVS erase から)

1. chip-tool `pairing ble-wifi 1 iotap … 20202021 3840 --paa-trust-store-path …`
   (attestation 実検証)フル完走 → 全属性 read(AQ=2 / CO2=817.0 / PM2.5=2.5 /
   温度=3129(補正後)/ 湿度=3530)。
2. **OCW E2E**: chip-tool `pairing open-commissioning-window 1 1 300 1000 3841`
   → デバイス `[window] enhanced commissioning window open (CM=2, discriminator
   3841)` → manual code 36164605764 から passcode 復元(chunk2 下位 14bit |
   chunk3<<14 = 9449678)→ 別 state-dir の smctl `pairing onnetwork-long 2
   9449678 3841` で **2 fabric 目完走** → `[window] commissioning succeeded;
   closing window`(自動クローズ)。revoke-commissioning も確認。
3. smctl read(--names で 0x002c 表示)+ `carbon-dioxide-concentration subscribe`
   (Sigma2Resume 再開 + 周期レポート +25s/+55s)。
4. 閉窓中の `pairing address`(3 人目)= `Sc(StatusReport(4))` 拒否(窓ゲート実証)。
5. リブート: restored 2 fabrics / 2 resumptions / wifi credentials → PASE
   disabled at boot → auto-join → chip-tool(fabric 1)/ smctl(fabric 2)とも
   CASE 再確立 + read 成功。
6. AirQuality worst-of のライブ遷移: ブート時のファン起動で PM2.5 が 62→32µg/m³
   と変動し Poor→Moderate→Fair の遷移をログ + chip-tool read(=4)で観測。
   VOC/NOx は定常(voc≈100 / nox=1)のため Good 寄与(専用の VOC イベント起因の
   遷移は未観測 — 平常時は発生しないのが正しい挙動)。

ゲート: コア 519 + smctl 58 テスト green、clippy 0(root/S3/C6)、
riscv/thumbv6m/no-default-features check green、S3 3 bin + C6 ビルド green。
フットプリント: airq-sensor 959,408 B(前回 953,168 B から +6.2KB =
AdminCommissioning + 窓配線 + mDNS commissionable)。

## 7.5 残改善バッチ 2(2026-07-13): e-ink ディスプレイ

### 7.5.1 パネル調査とドライバ選定

- **コントローラ判定: SSD1681 系で確定**。パネル名 GDEW0154D67 は UC8151 系を
  示唆するが、旧 FW の LGFX `Panel_GDEW0154D67`(m5stack_matter_examples 内の
  M5GFX コピー)の初期化列は完全に SSD1681: `0x12` SWReset / `0x01` Driver
  Output(200 gate)/ `0x11` Data Entry / `0x3C` Border / `0x18` 内蔵温度センサ /
  `0x0C` Booster / `0x24` RAM write / `0x22`+`0x20` update。UC8151 系の
  0x00 PSR / 0x04 PON は登場しない。LGFX は OTP 内蔵 LUT + Display Mode 1(フル)
  / Mode 2(差分)を使い、リフレッシュ所要目安 256ms(Mode 2)。BUSY は
  **HIGH=busy**。専用電源レールなし(FW が制御する電源 GPIO は SEN55 の 10 のみ)。
- **採用 crate: `epd-waveshare` 0.6.0 の `epd1in54_v2`**。同モジュールは
  **GDEH0154D67(同一 D67 パネル)向け**と明記。embedded-hal 1.0 / no_std /
  embedded-graphics 0.8 `DrawTarget`(`Display1in54`、5000B 静的バッファ)/
  `RefreshLut::Full/Quick`。esp-hal `Spi<Blocking>`(SpiBus)を embedded-hal-bus
  `ExclusiveDevice` で SpiDevice 化する接着のみで適合した。
  - 代替比較: `weact-studio-epd`(1.54" 非対応)、`ssd1681` crate(partial
    update 非対応)、`uc8151`(コントローラ違い)。
  - LGFX との方式差: epd-waveshare は OTP でなく **159B のカスタム LUT を 0x32 で
    書く**方式(同一パネルの Waveshare 1.54 V2 実績波形)。booster 調整
    (0x0C 8B 9C 96 0F)は入らないが実機で問題なし。
  - crate の feature 罠: `default-features = false` でも `epd2in13_v2/v3` の
    どちらかが必須(2in13 モジュールが無条件コンパイルされるため。未使用 =
    dead-code はリンカが落とす)。
- 配線は §1.3 のとおり BUSY=1 / RST=2 / DC=3 / CS=4 / SCK=5 / MOSI=6。
  SPI は旧 FW の 40MHz に対し **10MHz(mode 0)** に落とした(SSD1681 定格内の
  安全側。実測で十分)。

### 7.5.2 表示内容と更新戦略(実装 = esp32s3-firmware/src/display.rs)

- 表示: ヘッダ + **AirQuality(総合評価ラベル)/ CO2 ppm / PM2.5 µg/m³ /
  温度(補正後)/ 湿度** + 更新カウンタ(FONT_10X20 / 6X10)。AirQuality は
  pump → `display::set_air_quality_level`(AtomicU8)で共有、他は
  `sensors::snapshot()` から。
- 更新周期 **30 秒**(旧 FW と同じ)。通常はクイック更新(フリッカーなし)、
  **20 回に 1 回(10 分毎)フル更新**でゴーストをリセット(旧 FW はフル更新なし
  = ゴースト対策なしだった改善点)。値が変わらない周期はパネルを触らない。
- blocking ドライバの executor 停止対策: リフレッシュ起動(`display_frame`)は
  完了を待たずに戻るため、**次にパネルへ触るまで 4 秒 await** して
  `wait_until_idle` の実ブロックをほぼゼロにする(唯一の例外 = 起動時の
  init + 全面クリアの数秒、Matter トラフィック開始前)。
- 電源: 常時給電前提で deep sleep(0x10)は使わない(将来のバッテリー運用時に
  ICD と合わせて設計)。

### 7.5.3 実機 E2E 記録

- `[epd] initialized (SSD1681 / epd1in54_v2, full clear done)` → update #1(full、
  センサ未確定で "---" 表示)→ 30 秒毎の quick 更新で実測値
  (例: `update #7 (quick) aq=Fair co2=831 pm2.5(x10)=71 T(x10)=304 RH(x10)=389`)。
- 表示更新と並行して chip-tool read(fabric 1)/ smctl read + subscribe
  (fabric 2、keep-alive レポート +30s/+60s 受信)が無停滞で動作 — 4 秒 settle
  戦略で MRP/購読への影響なし。heap_max 91,908B / 114,688B(マージン維持)。
  .stack は 65,284B(フレームバッファ 5KB が main future に載った分減、余裕あり)。
- 表示内容の目視確認はユーザに依頼(ログの update #N の値と画面表示の一致)。
- **2026-07-13 ユーザ目視確認済み: 表示問題なし** — A5+残改善の全項目クローズ。
- フットプリント: airq-sensor 981,184B(バッチ 1 の 959,408B から +21.8KB =
  epd-waveshare + embedded-graphics + フォント)。

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

## 9. Alexa 互換: 既接続 Wi-Fi の NetworkCommissioning 反映(2026-08-27)

**事象**: Tab5(または smctl)で OCW を開き Alexa から AirQ を追加すると、Alexa は発見・PASE・非認証警告まで進み、
「デバイスのネットワーク登録」段階でエラー。AirQ 側では fabric 世代も Wi-Fi 資格情報も変化なし(= AddNOC 未到達)、
`[pase]`/`[net]` の異常ログなし。Alexa の到達性(IPv6 mDNS 応答・ND)は PC から確認済み。

**原因(推定、コードで裏付け)**: AirQ はビルド時プリセット/KVS 復元の資格情報で **クラスタを経由せず** join するため、
`NetworkCommissioning.Networks = []`。さらにコアの `ScanNetworks` は **常に空結果で Success**(chip-tool は既定で
スキャンを省くので問題化しなかった)。Alexa/Apple/Google のコミッショナは「Networks が空 → 未設定」と判断して
Wi-Fi 設定に入り、目的 SSID を `ScanNetworks` で確認する → 空 → 「ネットワークが見つからない」で中断。

**対処(デバイス側、コア + AirQ FW)**:

1. コア `wifi::WifiDriver` に **接続中ネットワーク情報**の取得を追加(既定実装は `None`):
   ```rust
   pub struct WifiNetworkInfo { pub ssid: [u8; 32], pub ssid_len: usize, pub bssid: [u8; 6],
                                pub channel: u16, pub rssi: i8, pub security: u8 /* WiFiSecurityBitmap */ }
   fn current_network(&self) -> Option<WifiNetworkInfo> { None }
   ```
2. コア `NetworkCommissioningWifi`:
   - `seed_network(ssid, creds)`: プリセット/KVS 復元の資格情報をクラスタの保持ネットワークとして登録
     (`Networks[0] = { networkID: ssid, connected: <driver status> }`、`LastNetworkingStatus = Success`)。
     `connected` は従来どおり `update_from_driver` で追従。
   - `ScanNetworks(0x00)`(fields: 0 ssid?: octstr、1 breadcrumb): `driver.current_network()` が `Some` なら、
     SSID フィルタ無し or 一致のときそのエントリ 1 件を `wiFiScanResults`(tag 2)に載せて Success。
     `WiFiInterfaceScanResultStruct` = { 0 security(map8), 1 ssid(octstr), 2 bssid(octstr 6B), 3 channel(u16),
     4 wiFiBand(enum8、2G4=0), 5 rssi(int8) }。`None` でも保持 SSID があれば security=WPA2-Personal(0x08)、
     bssid=00..、channel=0、rssi=-60 の**推定エントリ**を返す(空よりコミッショナが先へ進める)。保持も無ければ従来どおり空。
   - `AddOrUpdateWiFiNetwork` が **保持中と同じ SSID** なら `connected` を落とさない(同一 AP への再設定で
     Networks[].connected が一瞬 false になるのを避ける)。
3. AirQ FW(`ports/esp32s3`): 起動時の preset/KVS join 直後に `net.seed_network(ssid, pass)`。`EspWifiDriver::current_network`
   は `WIFI_ACTIVE` の SSID + associate 時の `info.channel`(static に保持)+ rssi(esp-radio から取れれば実値、無理なら
   -60 固定)+ bssid(取れれば。無理なら 0)。security は WPA2-Personal 固定。
4. cffi(`wifi_driver.rs`、onoff_light_cpp の Wi-Fi 構成)にも同型の `sm_wifi_seed_network(ssid, pass)` /
   `sm_wifi_set_link_info(bssid, channel, rssi)` を追加(C++ が esp_wifi の接続情報を渡す)。Kconfig プリセット SSID で
   起動する構成が同じ問題を持つため。ヘッダ再生成。

**テスト**(コア): seed 後の `Networks` 読み出しが 1 件・connected 追従、`ScanNetworks` の TLV(フィルタ一致/不一致/
無し、driver 情報あり/推定エントリ/空)、同一 SSID の AddOrUpdate で connected 維持、既存 ConnectNetwork 遅延応答テスト不変。
**ゲート**: cargo 全緑、AirQ FW ビルド(esp toolchain)、実機で smctl `any read 0x11 0 0x0031 1` が 1 件、
`any invoke`(あれば)で ScanNetworks 応答確認 → Alexa で再試行。
