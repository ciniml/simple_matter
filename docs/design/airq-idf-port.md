# AirQ IDF ポート(esp-idf + simple_matter cffi)

Status: 設計(2026-08-29)。

## 背景・動機

Rust ネイティブ版 AirQ(`ports/esp32s3/esp32s3-firmware/src/bin/airq-sensor.rs`、esp-radio + embassy-net/smoltcp)は、
**マルチキャスト RX がアソシエーション後 ~20 秒で停止**する(実測: 起動直後だけ受信でき、AP の IGMP/MLD スヌーピング収束で
刈り取られる)。ユニキャストは無事。結果、Apple/Alexa/Google のコミッショニング最終段(運用ディスカバリ mDNS / IPv6 近隣
解決)が届かず CommissioningComplete に至らずロールバックする。

原因は **TCP/IP スタック層**(embassy-net/smoltcp が IGMP/MLD メンバーシップを実効維持できない)であり、無線/RF 部
(esp-radio)は電波認証上 IDF とほぼ同一なので無関係。connectedhomeip(esp-idf + lwIP)ベースの実製品は正しく動く。

→ **esp-idf(lwIP + esp_wifi + mDNS)にネットワークを任せ、Matter は simple_matter を C FFI で駆動する**版を作る。
既存の `ports/esp-idf/examples/onoff_light_cpp`(WiFi 構成)/ `generic_matter_cpp`(センサ合成 + `sm_attr_set_value`)と
同一アーキテクチャ。プロトコル修正(PID 0x8001、空 ICAC 受理)もそのまま活きる。

## アーキテクチャ

`ports/esp-idf/examples/airq_sensor_cpp`(新規、onoff_light_cpp を土台に):

- **ネットワーク**: esp_wifi(STA)+ lwIP + esp-idf mDNS ソケット。コミッショニングで投入された WiFi 資格情報でのみ join
  (**ビルド時プリセット自動接続はしない** = Rust 版で実施済みの通常 Matter 挙動)。NVS へ保存、再起動で再 join。
- **BLE**: onoff_light_cpp と同じ `sm_ble_*`(ble-wifi コミッショニング)。Kconfig `SM_NETWORK_WIFI`。
- **Matter コア**: simple_matter cffi(`sm_init`/`sm_udp_rx`/`sm_mdns_rx`/`sm_poll`/`sm_ble_*`/`sm_attr_set_value`)。
- **デバイス構成(compose blob)**: `sm_config_t.compose`(Matter TLV)で 3 EP を宣言。
  - EP1 = Air Quality Sensor(device type **0x002C**): Identify(0x0003) + AirQuality(**0x005B**) + CO2(**0x040D**)
    + PM2.5(**0x042A**) + PM1(**0x042C**) + PM10(**0x042D**)。
  - EP2 = Temperature Sensor(**0x0302**): Identify + TemperatureMeasurement(**0x0402**)。
  - EP3 = Humidity Sensor(**0x0307**): Identify + RelativeHumidityMeasurement(**0x0405**)。
- **センサ**: SEN55(I2C 0x69)+ SCD40(I2C 0x62)を esp-idf I2C で読み、`sm_attr_set_value(ep, cluster, 0x0000, v)` で注入
  + `sm_attr_mark_dirty` で購読へ。AirQuality enum は CO2/PM2.5/VOC/NOx の worst-of でアプリ層算出(Rust 版 §4.3 と同じ規則)。
- **Factory/DAC**: VID 0xFFF1 / **PID 0x8001**(DAC=FFF1/8001 と一致。今回のアテステーション修正)。埋め込み dev DAC/CD。

## 作業分割

### W1: cffi compose に AirQuality/CO2/PM クラスタを追加(crates/simple-matter-cffi)

現状 `compose.rs` は Temperature(0x0402)/Humidity(0x0405)等は組み込むが、**AirQuality/CO2/PM concentration が未配線**
(コアには `AirQualityCluster` / `CarbonDioxideConcentrationCluster` / `Pm1/Pm25/Pm10ConcentrationCluster` が実装済み)。

- `compose.rs`: `CL_AIR_QUALITY=0x005B` / `CL_CO2=0x040D` / `CL_PM25=0x042A` / `CL_PM1=0x042C` / `CL_PM10=0x042D` を追加。
  `Light`(合成構造体)に各クラスタの `FixedVec` フィールドと `push!` アーム、ServerList/属性リスト(concentration は
  MeasuredValue 0x0000 等)を追加。attr set 経路(`sm_attr_set_value` → `poll_changes`/set 反映)に AirQuality(enum8、u64)と
  concentration(f32、0x0000 MeasuredValue)を配線。
- `sm_attr_set_value` が AirQuality を `set_air_quality`(enum)、concentration を `set_measured`(f32)へ届くこと。
- 容量定数(`MAX_SERVERS`/各 `N_*`)を EP1 の 6 クラスタ構成が収まるよう調整。
- テスト: compose blob(EP1: AirQuality+CO2+PM×3、EP2: Temp、EP3: Hum)→ `sm_init` 成功、`sm_attr_set_value` で各値が
  read で返る、Descriptor の ServerList/DeviceTypeList が正しい、購読 dirty が発火。ヘッダ再生成(`gen-cffi-header.sh`)。

### W2: esp-idf アプリ(ports/esp-idf/examples/airq_sensor_cpp)

- onoff_light_cpp を土台に main.cpp/CMakeLists/Kconfig/partitions/sdkconfig を用意(WiFi 構成、BLE 有効)。
- compose blob を C 側で構築(TLV を手組み、or ヘルパ)。3 EP を宣言。
- SEN55 + SCD40 の I2C ドライバ(Sensirion の esp-idf コンポーネント `sensirion/sen5x` `sensirion/scd4x` を
  idf_component.yml で取得。無ければ最小コマンド列を移植。Rust の sen5x-rs / libscd がプロトコル参照)。
- ポンプループ: 既存 onoff の `select→sm_udp_rx/sm_mdns_rx→sm_poll` に、周期センサ読み→`sm_attr_set_value`+`mark_dirty` を追加。
- **WiFi は自動接続しない**(投入資格情報のみ)。KVS 保存・再 join。
- ゲート: docker `espressif/idf:release-v5.4` で esp32s3 ビルド green。実機で Apple/Alexa/Google コミッショニング完走
  (WiFi join → 運用 CASE → CommissioningComplete)、センサ値が各エコシステムに表示。

## 既存資産の残置

Rust ネイティブ版(esp32s3-firmware)は削除しない(smoltcp 側の切り分け・比較用)。IDF 版が動けば「Rust TCP/IP スタックの
マルチキャスト維持問題」が確定する。
