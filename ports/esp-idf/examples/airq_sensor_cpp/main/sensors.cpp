// SEN55 + SCD40 の最小 I2C ドライバ実装(sensors.hpp 参照)。
//
// プロトコル出典: Sensirion SEN5x / SCD4x データシート。コマンドは 16bit ビッグ
// エンディアン、データは 2 バイトワード + CRC-8(poly 0x31, init 0xFF)。Rust 版
// (ports/esp32s3 の sen5x-rs / libscd 利用箇所)と同じスケーリングを用いる:
//   SEN55 read measured values(0x03C4): 8 ワード
//     PM1.0/PM2.5/PM4.0/PM10(u16 /10 µg/m³), RH(i16 /100 %), T(i16 /200 ℃),
//     VOC index(i16 /10), NOx index(i16 /10)
//   SCD40 read measurement(0xEC05): CO2(u16 ppm), T(u16 → -45+175*x/65536),
//     RH(u16 → 100*x/65536)

#include "sensors.hpp"

#include <cstring>

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_timer.h"

#include "driver/gpio.h"

static const char *TAG = "airq_sensors";

// ---- I2C アドレス / コマンド ------------------------------------------------

static constexpr uint8_t kSen55Addr = 0x69;
static constexpr uint8_t kScd40Addr = 0x62;

// SEN55
static constexpr uint16_t kSen55Reset = 0xD304;         // device reset(>100ms)
static constexpr uint16_t kSen55StartMeas = 0x0021;     // start measurement(>50ms)
static constexpr uint16_t kSen55DataReady = 0x0202;     // read data-ready flag
static constexpr uint16_t kSen55ReadValues = 0x03C4;    // read measured values(24B)
// SCD40
static constexpr uint16_t kScd40StopPeriodic = 0x3F86;  // stop periodic(500ms)
static constexpr uint16_t kScd40Reinit = 0x3646;        // reinit(20ms)
static constexpr uint16_t kScd40StartPeriodic = 0x21B1; // start periodic
static constexpr uint16_t kScd40DataReady = 0xE4B8;     // get data-ready status
static constexpr uint16_t kScd40ReadMeas = 0xEC05;      // read measurement(9B)

// 計測周期(秒)。Rust 版と同じ(SEN55 10s / SCD40 30s)。
static constexpr uint64_t kSen55PeriodMs = 10000;
static constexpr uint64_t kScd40PeriodMs = 30000;
// SEN55 温度の自己発熱補正オフセット(℃、読み値から減算)。airq-port.md §7.4。
static constexpr float kSen55TempOffsetC = 3.0f;

// ---- 状態 ------------------------------------------------------------------

static i2c_master_bus_handle_t s_bus = nullptr;
static i2c_master_dev_handle_t s_sen55 = nullptr;
static i2c_master_dev_handle_t s_scd40 = nullptr;
static bool s_ready = false;
static SensorSnapshot s_snap;          // センサタスク専用の作業スナップショット
static SensorSnapshot s_pub;           // 公開スナップショット(ロック保護)
static SemaphoreHandle_t s_lock = nullptr;
static volatile bool s_dirty = false;
static uint64_t s_last_sen55 = 0;
static uint64_t s_last_scd40 = 0;

// ---- CRC-8(Sensirion: poly 0x31, init 0xFF) ------------------------------

static uint8_t crc8(const uint8_t *d, size_t n) {
  uint8_t crc = 0xFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++) {
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
    }
  }
  return crc;
}

// ---- I2C 取引 --------------------------------------------------------------

// 16bit コマンドを送る(引数なし)。
static bool send_cmd(i2c_master_dev_handle_t dev, uint16_t cmd) {
  uint8_t b[2] = {(uint8_t)(cmd >> 8), (uint8_t)(cmd & 0xFF)};
  return i2c_master_transmit(dev, b, sizeof(b), 100) == ESP_OK;
}

// コマンド送信 → 遅延 → n ワード(各 2B + CRC)受信。CRC 検証して words[] へ。
static bool read_words(i2c_master_dev_handle_t dev, uint16_t cmd, uint16_t *words, size_t n,
                       uint32_t delay_ms) {
  if (!send_cmd(dev, cmd)) {
    return false;
  }
  if (delay_ms) {
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
  }
  uint8_t buf[3 * 12];
  size_t rd = n * 3;
  if (rd > sizeof(buf)) {
    return false;
  }
  if (i2c_master_receive(dev, buf, rd, 200) != ESP_OK) {
    return false;
  }
  for (size_t i = 0; i < n; i++) {
    const uint8_t *w = &buf[i * 3];
    if (crc8(w, 2) != w[2]) {
      ESP_LOGW(TAG, "CRC mismatch (cmd=0x%04x word=%u)", cmd, (unsigned)i);
      return false;
    }
    words[i] = (uint16_t)((w[0] << 8) | w[1]);
  }
  return true;
}

// ---- 初期化 ----------------------------------------------------------------

static bool add_dev(uint8_t addr, i2c_master_dev_handle_t *out) {
  i2c_device_config_t dc = {};
  dc.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dc.device_address = addr;
  dc.scl_speed_hz = 100000;
  return i2c_master_bus_add_device(s_bus, &dc, out) == ESP_OK;
}

bool sensors_init(int sda_gpio, int scl_gpio, int sen55_power_gpio, int hold_gpio) {
  if (!s_lock) {
    s_lock = xSemaphoreCreateMutex();
  }
  // AirQ 固有の電源制御(airq-port.md §2)。
  if (hold_gpio >= 0) {
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << hold_gpio;
    io.mode = GPIO_MODE_OUTPUT;
    gpio_config(&io);
    gpio_set_level((gpio_num_t)hold_gpio, 1); // HOLD=HIGH で電源維持
    ESP_LOGI(TAG, "power HOLD gpio=%d HIGH", hold_gpio);
  }
  if (sen55_power_gpio >= 0) {
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << sen55_power_gpio;
    io.mode = GPIO_MODE_OUTPUT;
    gpio_config(&io);
    gpio_set_level((gpio_num_t)sen55_power_gpio, 0); // LOW = SEN55 電源 ON
    ESP_LOGI(TAG, "SEN55 power gpio=%d LOW (on); waiting 1s", sen55_power_gpio);
    vTaskDelay(pdMS_TO_TICKS(1000));                 // 起動待ち 1 秒(§1.3)
  }

  i2c_master_bus_config_t bc = {};
  bc.clk_source = I2C_CLK_SRC_DEFAULT;
  bc.i2c_port = I2C_NUM_0;
  bc.sda_io_num = (gpio_num_t)sda_gpio;
  bc.scl_io_num = (gpio_num_t)scl_gpio;
  bc.glitch_ignore_cnt = 7;
  bc.flags.enable_internal_pullup = true;
  if (i2c_new_master_bus(&bc, &s_bus) != ESP_OK) {
    ESP_LOGE(TAG, "i2c_new_master_bus failed");
    return false;
  }
  if (!add_dev(kSen55Addr, &s_sen55) || !add_dev(kScd40Addr, &s_scd40)) {
    ESP_LOGE(TAG, "i2c add device failed");
    return false;
  }
  ESP_LOGI(TAG, "I2C SDA=%d SCL=%d 100kHz (SEN55=0x69, SCD40=0x62)", sda_gpio, scl_gpio);

  // --- SCD40 初期化(stop → reinit → start_periodic。Rust 版シーケンス踏襲)---
  send_cmd(s_scd40, kScd40StopPeriodic);
  vTaskDelay(pdMS_TO_TICKS(500));
  send_cmd(s_scd40, kScd40Reinit);
  vTaskDelay(pdMS_TO_TICKS(30));
  if (send_cmd(s_scd40, kScd40StartPeriodic)) {
    ESP_LOGI(TAG, "SCD40 periodic measurement started");
  } else {
    ESP_LOGW(TAG, "SCD40 start failed (continuing; will read when ready)");
  }

  // --- SEN55 初期化(reset → start_measurement)---
  send_cmd(s_sen55, kSen55Reset);
  vTaskDelay(pdMS_TO_TICKS(100));
  if (send_cmd(s_sen55, kSen55StartMeas)) {
    vTaskDelay(pdMS_TO_TICKS(50));
    ESP_LOGI(TAG, "SEN55 measurement started (fan spin-up)");
  } else {
    ESP_LOGW(TAG, "SEN55 start failed (continuing)");
  }

  s_ready = true;
  return true;
}

// ---- 周期読み取り ----------------------------------------------------------

static bool sen55_read(uint64_t now_ms) {
  uint16_t dr[1];
  if (!read_words(s_sen55, kSen55DataReady, dr, 1, 20) || (dr[0] & 0x0001) == 0) {
    return false; // 未準備 / 読み取り失敗
  }
  uint16_t w[8];
  if (!read_words(s_sen55, kSen55ReadValues, w, 8, 20)) {
    return false;
  }
  s_snap.pm1 = (float)w[0] / 10.0f;
  s_snap.pm25 = (float)w[1] / 10.0f;
  // w[2] = PM4.0(未使用)
  s_snap.pm10 = (float)w[3] / 10.0f;
  s_snap.rh = (float)(int16_t)w[4] / 100.0f;
  float raw_temp = (float)(int16_t)w[5] / 200.0f;
  s_snap.temp_c = raw_temp - kSen55TempOffsetC; // 自己発熱補正
  s_snap.voc_index = (float)(int16_t)w[6] / 10.0f;
  s_snap.nox_index = (float)(int16_t)w[7] / 10.0f;
  s_snap.has_pm1 = s_snap.has_pm25 = s_snap.has_pm10 = true;
  s_snap.has_temp = s_snap.has_rh = true;
  s_snap.has_voc = s_snap.has_nox = true;
  ESP_LOGI(TAG, "SEN55 pm1=%.1f pm2.5=%.1f pm10=%.1f T=%.2fC(raw=%.2f) RH=%.1f%% voc=%.0f nox=%.0f",
           s_snap.pm1, s_snap.pm25, s_snap.pm10, s_snap.temp_c, raw_temp, s_snap.rh,
           s_snap.voc_index, s_snap.nox_index);
  return true;
}

static bool scd40_read(uint64_t now_ms) {
  uint16_t dr[1];
  if (!read_words(s_scd40, kScd40DataReady, dr, 1, 2) || (dr[0] & 0x07FF) == 0) {
    return false;
  }
  uint16_t w[3];
  if (!read_words(s_scd40, kScd40ReadMeas, w, 3, 2)) {
    return false;
  }
  s_snap.co2_ppm = (float)w[0];
  s_snap.has_co2 = true;
  float t = -45.0f + 175.0f * (float)w[1] / 65536.0f;
  float rh = 100.0f * (float)w[2] / 65536.0f;
  ESP_LOGI(TAG, "SCD40 co2=%.0fppm T=%.2fC RH=%.1f%% (ref)", s_snap.co2_ppm, t, rh);
  return true;
}

bool sensors_poll(uint64_t now_ms) {
  if (!s_ready) {
    return false;
  }
  bool changed = false;
  if (now_ms - s_last_sen55 >= kSen55PeriodMs) {
    s_last_sen55 = now_ms;
    if (sen55_read(now_ms)) {
      changed = true;
    }
  }
  if (now_ms - s_last_scd40 >= kScd40PeriodMs) {
    s_last_scd40 = now_ms;
    if (scd40_read(now_ms)) {
      changed = true;
    }
  }
  if (changed && s_lock) {
    // 作業スナップショット s_snap を公開スナップショット s_pub へ短時間ロックでコピー。
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
      s_pub = s_snap;
      s_dirty = true;
      xSemaphoreGive(s_lock);
    }
  }
  return changed;
}

void sensors_snapshot(SensorSnapshot &out) {
  if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE) {
    out = s_pub;
    xSemaphoreGive(s_lock);
  } else {
    out = s_pub; // ロック取得失敗(まれ)。値はほぼ原子的なので許容。
  }
}

bool sensors_take_dirty() {
  if (!s_lock) {
    return false;
  }
  bool d = false;
  if (xSemaphoreTake(s_lock, 0) == pdTRUE) {
    d = s_dirty;
    s_dirty = false;
    xSemaphoreGive(s_lock);
  }
  return d;
}

// センサ読取タスク: I2C ブロッキング読取をここに隔離し、pump(matter_task)を塞がない。
static void sensors_task_fn(void *) {
  for (;;) {
    uint64_t now = (uint64_t)(esp_timer_get_time() / 1000);
    sensors_poll(now);
    vTaskDelay(pdMS_TO_TICKS(500));
  }
}

void sensors_start_task() {
  // stack 4096 words(16KB): I2C 読取は浅い。優先度 4(matter_task=5 より低)。
  xTaskCreate(&sensors_task_fn, "sensors", 4096, nullptr, 4, nullptr);
}

// ---- AirQualityEnum 算出(worst-of)----------------------------------------
//
// enum: 0=Unknown 1=Good 2=Fair 3=Moderate 4=Poor 5=VeryPoor 6=ExtremelyPoor。
// 閾値は airq-sensor.rs の classify_* と同一(§4.3 / §4.3b)。

static uint8_t classify_co2(float ppm) {
  if (ppm < 800.0f) return 1;
  if (ppm < 1000.0f) return 2;
  if (ppm < 1400.0f) return 3;
  if (ppm < 2000.0f) return 4;
  if (ppm < 3000.0f) return 5;
  return 6;
}
static uint8_t classify_pm25(float u) {
  if (u < 12.0f) return 1;
  if (u < 35.0f) return 2;
  if (u < 55.0f) return 3;
  if (u < 150.0f) return 4;
  if (u < 250.0f) return 5;
  return 6;
}
static uint8_t classify_voc(float v) {
  if (v < 1.0f || v > 500.0f) return 0; // 無効値ガード
  if (v <= 150.0f) return 1;
  if (v <= 200.0f) return 2;
  if (v <= 300.0f) return 3;
  if (v <= 400.0f) return 4;
  return 5; // 単一チャネル寄与は VeryPoor 上限
}
static uint8_t classify_nox(float v) {
  if (v < 1.0f || v > 500.0f) return 0;
  if (v <= 20.0f) return 1;
  if (v <= 100.0f) return 3;
  return 4; // 上限 Poor
}

uint8_t sensors_air_quality(const SensorSnapshot &s) {
  uint8_t worst = 0; // Unknown
  auto take = [&](uint8_t c) {
    if (c > worst) worst = c;
  };
  if (s.has_co2) take(classify_co2(s.co2_ppm));
  if (s.has_pm25) take(classify_pm25(s.pm25));
  if (s.has_voc) take(classify_voc(s.voc_index));
  if (s.has_nox) take(classify_nox(s.nox_index));
  return worst;
}
