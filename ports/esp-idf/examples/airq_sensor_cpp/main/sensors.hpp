// AirQ 実機センサ(SEN55 + SCD40)の最小 I2C ドライバ(ESP-IDF v5.4 の
// i2c_master API を直接使用。managed component 非依存)。
//
// docs/design/airq-port.md §1.3 / §2 のハード知識を移植する:
//   - SEN55(I2C 0x69): PM1/2.5/10 + 温湿度 + VOC/NOx index。GPIO で電源制御。
//   - SCD40(I2C 0x62): CO2 + 温湿度(温湿度は参考ログ用。クラスタは SEN55 側)。
//   - I2C: SDA=GPIO11 / SCL=GPIO12、100kHz。CRC-8(poly 0x31, init 0xFF)。
//
// 値注入(sm_attr_set_value)は main.cpp が担う。本モジュールは物理量スナップショット
// (f32)と AirQualityEnum の算出(worst-of)だけを提供する。全 API は matter_task
// (単線)から呼ぶ前提でロックを持たない。
#pragma once

#include <cstddef>
#include <cstdint>

// 最新の実測値スナップショット(未計測は has_* = false)。値は物理量(f32)。
struct SensorSnapshot {
  bool has_co2 = false;
  float co2_ppm = 0.0f; // SCD40
  bool has_pm1 = false, has_pm25 = false, has_pm10 = false;
  float pm1 = 0.0f, pm25 = 0.0f, pm10 = 0.0f; // SEN55 [µg/m³]
  bool has_temp = false, has_rh = false;
  float temp_c = 0.0f, rh = 0.0f; // SEN55(温度は自己発熱補正済み)
  bool has_voc = false, has_nox = false;
  float voc_index = 0.0f, nox_index = 0.0f; // SEN55 index(無次元。クラスタ非搭載)
};

// I2C バス + SEN55/SCD40 を初期化する(電源 GPIO の制御・起動待ち・初期化シーケンス)。
// 失敗しても false を返すだけでタスクは継続する(値は None のまま)。
// sda/scl/sen55_power/hold は GPIO 番号(hold < 0 で HOLD 制御なし)。
bool sensors_init(int sda_gpio, int scl_gpio, int sen55_power_gpio, int hold_gpio);

// 周期読み取りを進める(now_ms 駆動: SEN55 10s / SCD40 30s)。スナップショットが
// 更新されたら true。main.cpp は true のとき sm_attr_set_value で反映する。
bool sensors_poll(uint64_t now_ms);

// 現在のスナップショットを取得する。
const SensorSnapshot &sensors_snapshot();

// worst-of(CO2 / PM2.5 / VOC index / NOx index)で AirQualityEnum(0..6)を算出する。
// 判定材料が 1 つも無ければ 0(Unknown)。docs/design/airq-port.md §4.3 / §4.3b。
uint8_t sensors_air_quality(const SensorSnapshot &s);
