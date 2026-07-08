# 基本クラスタ・デバイスタイプ(Matter 1.3)設計 — Identify/センサ族/Switch/Fan/Window Covering/Color Control

対象: `crates/simple-matter/src/dm/clusters/`(コア)、`crates/simple-matter/examples/`、
`crates/smctl/src/clusters/`。参照実装の型は `docs/design/interaction-model.md` §8/§9/§15
(`cluster!` マクロ、tick フック、nullable、enum 検証、クラスタ↔アプリ仲介)。

仕様ソース: `research/connectedhomeip/src/app/zap-templates/zcl/data-model/chip/*.xml`
(ID/属性/コマンド/イベントの正典。ただし checkout は 1.4 系なので、revision と feature は
**Matter 1.3 時点の値**を採用する。ズレは本 doc に明記)。

## 0. サマリ(主要な設計判断)

1. **計測系クラスタはマクロで単一ソース化**: Temperature/Pressure(i16)、
   RelativeHumidity/Illuminance/Flow(u16)は「MeasuredValue(nullable)+ Min/Max 固定」の
   同型パターン。内部マクロ `measurement_cluster!`(`dm/clusters/measurement.rs`)で
   struct + API + `cluster!` 呼び出しを 1 宣言から生成し、5 クラスタの重複を排除する。
   Tolerance(任意)は非実装。
2. **イベントは「クラスタが積み、アプリが stack.post_event へ運ぶ」**: コアの EventLog は
   `InteractionModel` が所有し、クラスタから直接触れない。Boolean State / Switch は
   クラスタ内の小さな pending キュー(固定長)に発生イベントを積み、アプリループが
   `take_*` API で回収して `stack.post_event` する。既存の
   `take_on_off_request` / `WindowEvent` と同じ「クラスタ↔アプリ仲介」契約。
3. **feature_map は型レベル定数**(`cluster!` の static META)。インスタンスごとに
   feature を変えられないため、Switch は momentary(MS|MSR)と latching(LS)を
   **別型**で提供する(共通ロジックは共有 struct)。META の動的化はスコープ外。
4. **Identify は Device Library でほぼ全タイプ必須** → 全 example の機能 EP に載せる
   (onoff-light / dimmable-light / thermostat の既存 example にも追加)。
   ESP32 e5-light への追加は見送り(実機フラッシュ再検証が必要になるため。将来課題)。
5. **スコープ外(将来リスト)**: Groups / Scenes / GroupKeyManagement / Binding /
   Door Lock / OTA / ICD。クラスタ内の任意機能では TriggerEffect(Identify)、
   Tolerance(計測系)、Switch の AS/MSM/MSL feature、Fan の SPD/RCK/WND/AUTO、
   Window Covering の Tilt/ABS、Color Control の XY/EnhancedHue/ColorLoop。
   デバイスタイプ必須の Groups/Scenes は「省略(Group messaging 自体がスコープ外)」と
   example の EP コメントに明記する。

## 1. バッチ 1 — Identify + センサ族

### 1.1 Identify(0x0003、revision 4、feature_map 0)

- 属性: IdentifyTime(0x0000、u16、rw、秒)、IdentifyType(0x0001、enum8、固定値。
  コンストラクタで指定、既定 2=VisibleIndicator)。
- コマンド: Identify(0x00、{0: identifyTime u16})。TriggerEffect(0x40)は任意 → 非実装。
- **tick 減衰**: IdentifyTime > 0 の間、1 秒刻みで自減。dirty は「識別開始/終了」の
  遷移時のみ立てる(毎秒の減衰では立てない。Level Control の RemainingTime と同じ方針)。
- アプリ通知: `with_listener(fn(bool))`(識別中→true / 終了→false)。example は println。
- IdentifyTime への write も識別開始として扱う(仕様どおり)。

### 1.2 Boolean State(0x0045、revision 1、feature_map 0)

- 属性: StateValue(0x0000、bool、View、subscribe)。
- イベント: StateChange(0x00、INFO、`{0: stateValue bool}`)。
- API: `set_state(bool)`(変化時のみ dirty + StateChange を pending に積む)、
  `state()`、`take_state_change() -> Option<bool>`(アプリが post_event へ運ぶ)。

### 1.3 計測系 5 クラスタ(measurement_cluster! で生成)

共通形: MeasuredValue(0x0000、nullable、View、subscribe)/ MinMeasuredValue(0x0001、
nullable)/ MaxMeasuredValue(0x0002、nullable)。コンストラクタ `new(min, max)`、
API `set_measured(Option<T>)`(変化時のみ dirty)+ `measured()`。

| クラスタ | ID | rev | 型 | 単位 |
|---|---|---|---|---|
| TemperatureMeasurement | 0x0402 | 4 | i16 | 0.01℃ |
| PressureMeasurement | 0x0403 | 3 | i16 | 0.1kPa |
| FlowMeasurement | 0x0404 | 3 | u16 | 0.1m³/h |
| RelativeHumidityMeasurement | 0x0405 | 3 | u16 | 0.01% |
| IlluminanceMeasurement | 0x0400 | 3 | u16 | log10(lux)×10⁴(0=不明→null 扱い) |

マクロ引数: 型名 / cluster id / revision / 値型(i16 or u16)/ エンコーダ関数
(`write_nullable_i16` / `write_nullable_u16`)。ScaledValue 系(Pressure)、
LightSensorType(Illuminance)は任意 → 非実装。

### 1.4 Occupancy Sensing(0x0406、revision 3、feature_map 0)

- 属性: Occupancy(0x0000、map8 bit0、subscribe)、OccupancySensorType(0x0001、enum8)、
  OccupancySensorTypeBitmap(0x0002、map8)。コンストラクタで sensor type(既定 PIR=0 /
  bitmap bit0)。HoldTime / PIR 遅延系は任意(1.3)→ 非実装。
- API: `set_occupied(bool)`(変化時のみ dirty)。1.3 の rev 3 にはイベント無し。

### 1.5 example: sensor-hub(マルチ EP 実証)

`examples/sensor-hub.rs`。thermostat.rs をベースに手書き DataModel(共有 OpCreds の
ライフタイムのため device! 不可)。**EP メタコメントに Device Library の
必須/実装済み/省略(理由)を明記**。

| EP | デバイスタイプ | rev | クラスタ |
|---|---|---|---|
| 0 | Root Node 0x0016 | 1 | 既存 7 種 |
| 1 | Temperature Sensor 0x0302 | 2 | Identify + TemperatureMeasurement + Descriptor |
| 2 | Humidity Sensor 0x0307 | 2 | Identify + RelativeHumidity + Descriptor |
| 3 | Contact Sensor 0x0015 | 1 | Identify + BooleanState + Descriptor |
| 4 | Occupancy Sensor 0x0107 | 3 | Identify + OccupancySensing + Descriptor |
| 5 | Light Sensor 0x0106 | 2 | Identify + Illuminance + Descriptor |
| 6 | Pressure Sensor 0x0305 | 2 | Identify + Pressure + Descriptor |
| 7 | Flow Sensor 0x0306 | 2 | Identify + Flow + Descriptor |

デバイスタイプ revision は Matter 1.3 Device Library 時点の値(ZAP XML は 1.4 系で
+1 されているものがある。相互運用に影響しないため 1.3 値を採用)。

擬似センサ(on_tick、1 秒周期): 温度/湿度/照度/気圧/流量は基準値±三角波でゆらす。
接点は 15 秒ごとにトグル(StateChange イベント → main loop が take して post_event)、
在室は 20 秒ごとにトグル。mDNS instance id は既存 example と別値、product id 0x8004。

### 1.6 smctl

cluster_def! 追加(ID 昇順で CLUSTERS へ): boolean-state(events { 0x00 state-change })、
illuminance-measurement / temperature-measurement / pressure-measurement /
flow-measurement / relative-humidity-measurement / occupancy-sensing。
identify は収載済み。

### 1.7 E2E(chip-tool + smctl)

pairing → descriptor read device-type-list(EP1-7)→ 各計測値 read →
identify identify(IdentifyTime 減衰を read で確認)→ smctl read --names →
smctl boolean-state subscribe-event(15 秒トグルの StateChange 受信)。

## 2. バッチ 2 — Switch + Fan Control + Window Covering

### 2.1 Switch(0x003B、revision 1)

- 共通属性: NumberOfPositions(0x0000、u8、既定 2)、CurrentPosition(0x0001、u8、subscribe)。
- **SwitchCluster(momentary)**: feature_map = MS|MSR = 0x06。
  API `press(new_position)` / `release()` → CurrentPosition 更新 + InitialPress(0x01、
  `{0: newPosition}`)/ ShortRelease(0x03、`{0: previousPosition}`)を pending に積む。
- **LatchingSwitchCluster**: feature_map = LS = 0x01。API `set_position(u8)` →
  SwitchLatched(0x00、`{0: newPosition}`)。
- pending イベントは固定長リング(4)。`take_event() -> Option<SwitchEvent>`
  (SwitchEvent = { id, position })をアプリが post_event へ運ぶ。
  MultiPress / LongPress(MSM/MSL)はスコープ外。

### 2.2 Fan Control(0x0202、revision 4、feature_map 0)

- 属性: FanMode(0x0000、enum8、rw、{0=Off,1=Low,2=Med,3=High} のみ受理。4=On/5=Auto/
  6=Smart は ConstraintError ※feature 無しのため)、FanModeSequence(0x0001、enum8、
  固定 2=Off/Low/Med/High)、PercentSetting(0x0002、nullable u8 0-100、rw)、
  PercentCurrent(0x0003、u8、subscribe)。
- 連動: FanMode write → PercentSetting へ写像(Off=0/Low=33/Med=66/High=100)。
  PercentSetting write → FanMode を再導出。PercentCurrent は **tick で 10%/秒の
  ランプ追従**(Level Control の遷移パターン簡略版。dirty は開始/完了と 1% 変化ごと)。
  PercentSetting=null 書き込みは Auto 相当だが AUTO feature 無し → 無効果(Success)。
- SpeedSetting 系(SPD)/Rock/Wind は任意 → 非実装。

### 2.3 Window Covering(0x0102、revision 5、feature_map = LF|PA_LF = 0x05)

- 属性: Type(0x0000、enum8 = 0 Rollershade)、ConfigStatus(0x0007、map8 =
  Operational|LiftPositionAware = 0x09)、OperationalStatus(0x000A、map8、subscribe。
  global bits0-1 + lift bits2-3、動作中 = Opening 01 / Closing 10)、
  EndProductType(0x000D、enum8 = 0)、Mode(0x0017、map8、rw、保持のみ)、
  TargetPositionLiftPercent100ths(0x000B、nullable u16 0-10000、subscribe)、
  CurrentPositionLiftPercent100ths(0x000E、nullable u16、subscribe)。
  ※ percent100ths は 0=全開(up)/10000=全閉(down)。
- コマンド: UpOrOpen(0x00)→ target 0、DownOrClose(0x01)→ target 10000、
  StopMotion(0x02)→ 現在位置で停止、GoToLiftPercentage(0x05、
  `{0: liftPercent100thsValue u16}`、>10000 は ConstraintError)。
- tick 移動シム: 1000(=10%)/秒で Current→Target へ線形移動。到達で
  OperationalStatus=0。Tilt / ABS はスコープ外。
- CurrentPositionLiftPercentage(0x0008、0-100)も PA_LF の互換必須属性 → 100ths/100 を返す。

### 2.4 example 構成

- `examples/switch-demo.rs`: EP1 = Generic Switch 0x000F(rev 1、momentary、
  10 秒周期で press→1 秒後 release のシム)、EP2 = Generic Switch(latching、
  15 秒周期でトグル)。必須クラスタ: Identify(載せる)+ Switch + Descriptor。
- Fan / Window Covering は **sensor-hub に EP8/EP9 として追加**(新 example を増やすより
  マルチ EP 実証を深める。EP8 = Fan 0x002B rev 2: Identify+FanControl+Descriptor
  ※必須の Groups は省略、EP9 = Window Covering 0x0202 rev 2: Identify+WindowCovering
  +Descriptor)。
- smctl: switch(events 収載)/ fan-control / window-covering の cluster_def! 追加。

### 2.5 E2E

chip-tool fancontrol write percent-setting → percent-current のランプ追従 read、
windowcovering go-to-lift-percentage → tick 移動 → operational-status/現在位置 read、
switch のイベント subscribe(chip-tool interactive or smctl subscribe-event)で
InitialPress/ShortRelease 受信。

## 3. バッチ 3 — Color Control(0x0300、revision 6)

- feature_map = HS|CT = 0x11。XY / EnhancedHue / ColorLoop はスコープ外(doc 化)。
- 属性: CurrentHue(0x0000、u8、subscribe)、CurrentSaturation(0x0001、u8、subscribe)、
  RemainingTime(0x0002、u16)、ColorTemperatureMireds(0x0007、u16、subscribe)、
  ColorMode(0x0008、enum8 {0=HS, 2=CT})、Options(0x000F、map8、rw)、
  NumberOfPrimaries(0x0010、nullable u8 = null)、EnhancedColorMode(0x4001、enum8 =
  ColorMode+同値 {0,2})、ColorCapabilities(0x400A、map16 = 0x0011)、
  ColorTempPhysicalMinMireds(0x400B、u16 = 153)、ColorTempPhysicalMaxMireds
  (0x400C、u16 = 500)、CoupleColorTempToLevelMinMireds(0x400D = 153)、
  StartUpColorTemperatureMireds(0x4010、nullable u16、rw、保持のみ)。
- コマンド: MoveToHue(0x00、{hue, direction, transitionTime, mask, override}。
  direction 0=最短/1=最長/2=up/3=down)、MoveToSaturation(0x03)、
  MoveToHueAndSaturation(0x06)、MoveToColorTemperature(0x0A、物理 Min/Max へクランプ)。
  Move/Step 系(0x01/0x02/0x04/0x05/0x08/0x09/0x4B/0x4C)は任意 → 非実装。
- 遷移: Level Control の Transition パターンを流用(tick、線形補間、hue は wrap を
  考慮した最短/指定方向経路)。HS 系コマンドで ColorMode=0、CT で ColorMode=2 に遷移し
  dirty。Options bit0(ExecuteIfOff)ゲートは Level Control と同じ契約
  (`notify_on_off`/`coupled_on` でアプリ仲介)。
- example: `examples/color-light.rs`(dimmable-light ベース、EP1 = Extended Color Light
  0x010D rev 2: Identify+OnOff+LevelControl+ColorControl+Descriptor、Groups/Scenes は
  省略コメント)。**ESP32 は PC example のみ**: NanoC6 の LED は単色で CT/HS を表現できず、
  輝度換算は Level Control と区別がつかないため見送り(e5-light は Dimmable のまま)。
- smctl: color-control の cluster_def! 追加。
- E2E: chip-tool `colorcontrol move-to-hue-and-saturation` / `move-to-color-temperature`
  (transitionTime 付きで RemainingTime/遷移を確認)、smctl 同等 + subscribe。

## 4. 検証ゲート(各バッチ共通)

1. `cargo fmt --check`
2. `cargo test --all-features`(コア)+ `cargo test -p smctl --all-features`
3. `cargo clippy --all-targets --all-features -- -D warnings`
4. `cargo check -p simple-matter --all-features --target thumbv6m-none-eabi` /
   `--target riscv32imc-unknown-none-elf` / `--no-default-features`
5. ports/esp32 ビルド(`cargo build --release` in `ports/esp32/esp32c6-firmware`)
6. bloat-check(ram-report + flash-probe thumbv7em)でフットプリント記録
7. 実機 E2E: chip-tool(snap v1.5.1)+ smctl で該当バッチの §E2E 項目

## 5. 割り切り一覧(実装後に追記)

### バッチ 2(実装済み)

- LatchingSwitch の `set_position` は**変化時のみ** SwitchLatched を発火(同一位置への
  再設定でスプリアスイベントを出さない)。momentary の press/release は動作イベントの
  ため常に発火。
- Switch の pending イベントリング(4)は満杯時に最古を上書き(press+release=2 件で
  容量に十分収まる)。
- Fan の PercentCurrent ランプは 1%/100ms tick(=10%/秒)。

### バッチ 1(実装済み)

- 計測系の Min/MaxMeasuredValue はいずれも nullable のため、コンストラクタは
  `new(min: Option<T>, max: Option<T>)`(null 公開も可能な形)。
- onoff-light の `on_tick` は従来 `None` 固定で `tick_clusters` を呼んでいなかった →
  Identify 減衰が回るよう `tick_clusters` 呼び出しを追加(dimmable/thermostat は既に対応済み)。
- センサ系デバイスタイプ(0x0302/0x0307/0x0015/0x0107/0x0106/0x0305/0x0306)は
  Groups/Scenes を必須にしないため、sensor-hub EP1-7 に省略クラスタは無し
  (必須 = Identify + 計測系 + Descriptor をすべて実装)。
