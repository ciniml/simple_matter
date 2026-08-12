// HAL バインディング層の実装(§9.2)。bindings.hpp のコメントを参照。

#include "bindings.hpp"

#include <cstring>

#include "esp_err.h"
#include "esp_log.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/ledc.h"

namespace smgen {
namespace {

const char *TAG = "smgen_hal";

BindingTable g_table;

// LEDC の共通設定(全チャネルで共有。timer は ch % 4)。
constexpr ledc_mode_t kLedcMode = LEDC_LOW_SPEED_MODE;
constexpr ledc_timer_bit_t kLedcBits = LEDC_TIMER_10_BIT;
constexpr uint32_t kLedcMaxDuty = (1u << 10) - 1u;

// I2C バス(ポートごとに 1 本だけ張る)。
i2c_master_bus_handle_t g_i2c_bus[2] = {nullptr, nullptr};

// ---- sm_attr_value_t ヘルパ -------------------------------------------------

sm_attr_value_t v_bool(bool b) {
  sm_attr_value_t v{};
  v.type = SM_T_BOOL;
  v.v.b = b;
  return v;
}
sm_attr_value_t v_u8(uint8_t x) {
  sm_attr_value_t v{};
  v.type = SM_T_U8;
  v.v.u = x;
  return v;
}
sm_attr_value_t v_u16(uint16_t x) {
  sm_attr_value_t v{};
  v.type = SM_T_U16;
  v.v.u = x;
  return v;
}
sm_attr_value_t v_i16(int16_t x) {
  sm_attr_value_t v{};
  v.type = SM_T_I16;
  v.v.i = x;
  return v;
}

// 合成クラスタから現在値を読む(失敗は def)。
bool read_onoff(uint16_t ep, bool def) {
  sm_attr_value_t v{};
  if (sm_attr_get_value(ep, kClOnOff, 0x0000, &v) != 0) {
    return def;
  }
  return v.v.b;
}
uint8_t read_level(uint16_t ep, uint8_t def) {
  sm_attr_value_t v{};
  if (sm_attr_get_value(ep, kClLevel, 0x0000, &v) != 0) {
    return def;
  }
  return v.is_null ? def : (uint8_t)v.v.u;
}

// ---- gpio_out ---------------------------------------------------------------

void gpio_out_init(Binding &b) {
  const gpio_num_t pin = (gpio_num_t)b.param(0, 0);
  gpio_config_t io{};
  io.pin_bit_mask = 1ULL << (int)pin;
  io.mode = GPIO_MODE_OUTPUT;
  gpio_config(&io);
  gpio_set_level(pin, b.param(1, 0) ? 1 : 0); // off の物理レベル
}

void gpio_out_write(const Binding &b, bool on) {
  const gpio_num_t pin = (gpio_num_t)b.param(0, 0);
  const bool invert = b.param(1, 0) != 0;
  gpio_set_level(pin, (on != invert) ? 1 : 0);
}

// ---- ledc -------------------------------------------------------------------

void ledc_init(Binding &b) {
  const uint8_t ch = (uint8_t)b.param(0, 0);
  const gpio_num_t pin = (gpio_num_t)b.param(1, 0);
  const uint32_t freq = (uint32_t)b.param(2, 1000);
  const ledc_timer_t timer = (ledc_timer_t)(ch % 4);

  ledc_timer_config_t tc{};
  tc.speed_mode = kLedcMode;
  tc.duty_resolution = kLedcBits;
  tc.timer_num = timer;
  tc.freq_hz = freq;
  tc.clk_cfg = LEDC_AUTO_CLK;
  esp_err_t err = ledc_timer_config(&tc);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "ledc timer%u freq=%u failed: %s", (unsigned)timer, (unsigned)freq,
             esp_err_to_name(err));
    return;
  }
  ledc_channel_config_t cc{};
  cc.gpio_num = (int)pin;
  cc.speed_mode = kLedcMode;
  cc.channel = (ledc_channel_t)ch;
  cc.timer_sel = timer;
  cc.duty = b.param(3, 0) ? kLedcMaxDuty : 0; // invert 時の off = full
  cc.hpoint = 0;
  err = ledc_channel_config(&cc);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "ledc channel%u pin=%d failed: %s", (unsigned)ch, (int)pin, esp_err_to_name(err));
  }
}

// CurrentLevel(0..254)+ 同一 EP の OnOff から duty を決めて反映する。
void ledc_apply(const Binding &b) {
  const uint8_t ch = (uint8_t)b.param(0, 0);
  const bool invert = b.param(3, 0) != 0;
  // OnOff が同居していれば off = duty 0(§9.2)。無ければ常時 on 扱い。
  const bool on = read_onoff(b.ep, true);
  const uint8_t level = read_level(b.ep, 0);
  uint32_t duty = on ? ((uint32_t)level * kLedcMaxDuty) / 254u : 0u;
  if (duty > kLedcMaxDuty) {
    duty = kLedcMaxDuty;
  }
  if (invert) {
    duty = kLedcMaxDuty - duty;
  }
  ledc_set_duty(kLedcMode, (ledc_channel_t)ch, duty);
  ledc_update_duty(kLedcMode, (ledc_channel_t)ch);
}

// ---- gpio_in ----------------------------------------------------------------

void gpio_in_init(Binding &b) {
  const gpio_num_t pin = (gpio_num_t)b.param(0, 0);
  const uint64_t pull = b.param(3, 1); // 既定 = pull-up
  gpio_config_t io{};
  io.pin_bit_mask = 1ULL << (int)pin;
  io.mode = GPIO_MODE_INPUT;
  io.pull_up_en = (pull == 1) ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE;
  io.pull_down_en = (pull == 2) ? GPIO_PULLDOWN_ENABLE : GPIO_PULLDOWN_DISABLE;
  gpio_config(&io);
  const bool invert = b.param(1, 0) != 0;
  const bool logical = (gpio_get_level(pin) != 0) != invert;
  b.state = logical ? 1 : 0;  // 確定値
  b.state2 = b.state;         // 直近サンプル(2 連続一致でデバウンス確定)
  b.next_ms = 0;
}

// 確定した論理値をクラスタへ push する。
void gpio_in_commit(const Binding &b, bool logical) {
  if (b.cluster == kClBoolean) {
    sm_attr_value_t v = v_bool(logical);
    sm_attr_set_value(b.ep, kClBoolean, 0x0000, &v);
  } else if (b.cluster == kClSwitch) {
    sm_attr_value_t v = v_u8(logical ? 1 : 0);
    sm_attr_set_value(b.ep, kClSwitch, 0x0001, &v);
  }
}

void gpio_in_poll(Binding &b, uint64_t now_ms) {
  const uint32_t period = (uint32_t)b.param(2, 50);
  if (now_ms < b.next_ms) {
    return;
  }
  b.next_ms = now_ms + (period ? period : 50);
  const gpio_num_t pin = (gpio_num_t)b.param(0, 0);
  const bool invert = b.param(1, 0) != 0;
  const int sample = ((gpio_get_level(pin) != 0) != invert) ? 1 : 0;
  if (sample != b.state2) {
    b.state2 = sample; // 1 回目: 候補として覚えるだけ(デバウンス)。
    return;
  }
  if (sample != b.state) {
    b.state = sample; // 2 連続一致 → 確定。
    gpio_in_commit(b, sample != 0);
    ESP_LOGI(TAG, "gpio_in pin=%d -> ep=%u cluster=0x%04x value=%d", (int)pin, b.ep,
             (unsigned)b.cluster, sample);
  }
}

// ---- i2c_sht30 --------------------------------------------------------------

constexpr uint8_t kSht30Addr = 0x44;

uint8_t sht_crc8(const uint8_t *d, size_t n) {
  uint8_t crc = 0xFF;
  for (size_t i = 0; i < n; i++) {
    crc ^= d[i];
    for (int b = 0; b < 8; b++) {
      crc = (crc & 0x80) ? (uint8_t)((crc << 1) ^ 0x31) : (uint8_t)(crc << 1);
    }
  }
  return crc;
}

void sht30_init(Binding &b) {
  const uint8_t port = (uint8_t)b.param(3, 0);
  if (port >= 2) {
    ESP_LOGE(TAG, "i2c_sht30: bad port %u", (unsigned)port);
    return;
  }
  if (g_i2c_bus[port] == nullptr) {
    i2c_master_bus_config_t bc{};
    bc.i2c_port = (i2c_port_num_t)port;
    bc.sda_io_num = (gpio_num_t)b.param(0, 8);
    bc.scl_io_num = (gpio_num_t)b.param(1, 9);
    bc.clk_source = I2C_CLK_SRC_DEFAULT;
    bc.glitch_ignore_cnt = 7;
    bc.flags.enable_internal_pullup = true;
    esp_err_t err = i2c_new_master_bus(&bc, &g_i2c_bus[port]);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "i2c bus%u init failed: %s", (unsigned)port, esp_err_to_name(err));
      g_i2c_bus[port] = nullptr;
      return;
    }
  }
  i2c_device_config_t dc{};
  dc.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dc.device_address = kSht30Addr;
  dc.scl_speed_hz = 100000;
  i2c_master_dev_handle_t dev = nullptr;
  esp_err_t err = i2c_master_bus_add_device(g_i2c_bus[port], &dc, &dev);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "i2c_sht30 add_device failed: %s", esp_err_to_name(err));
    return;
  }
  b.handle = dev;
  b.next_ms = 0;
}

void sht30_poll(Binding &b, uint64_t now_ms) {
  if (b.handle == nullptr) {
    return;
  }
  const uint32_t period = (uint32_t)b.param(2, 5000);
  if (now_ms < b.next_ms) {
    return;
  }
  b.next_ms = now_ms + (period ? period : 5000);
  // 単発測定・高再現性・clock stretching 有効(0x2C06)。デバイスが SCL を伸ばすので
  // transmit_receive 1 回で読み切れる(pump タスクを ~15ms 占有する)。
  const uint8_t cmd[2] = {0x2C, 0x06};
  uint8_t rx[6] = {};
  esp_err_t err = i2c_master_transmit_receive((i2c_master_dev_handle_t)b.handle, cmd, sizeof(cmd),
                                              rx, sizeof(rx), 100);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "sht30 read failed: %s", esp_err_to_name(err));
    return;
  }
  if (sht_crc8(rx, 2) != rx[2] || sht_crc8(rx + 3, 2) != rx[5]) {
    ESP_LOGW(TAG, "sht30 CRC mismatch");
    return;
  }
  const uint32_t raw_t = ((uint32_t)rx[0] << 8) | rx[1];
  const uint32_t raw_h = ((uint32_t)rx[3] << 8) | rx[4];
  // Matter: Temperature = 0.01℃(i16)、RelativeHumidity = 0.01%(u16)。
  const int32_t centi_c = (int32_t)((17500 * (int64_t)raw_t) / 65535 - 4500);
  const int32_t centi_rh = (int32_t)((10000 * (int64_t)raw_h) / 65535);
  sm_attr_value_t tv = v_i16((int16_t)centi_c);
  sm_attr_set_value(b.ep, kClTemperature, 0x0000, &tv);
  sm_attr_value_t hv = v_u16((uint16_t)centi_rh);
  // 同一 EP に RelativeHumidity が合成されていなければ -2 が返るだけ(無害)。
  sm_attr_set_value(b.ep, kClHumidity, 0x0000, &hv);
  ESP_LOGI(TAG, "sht30 ep=%u %d.%02d C / %d.%02d %%RH", b.ep, (int)(centi_c / 100),
           (int)(centi_c < 0 ? -centi_c : centi_c) % 100, (int)(centi_rh / 100),
           (int)(centi_rh % 100));
}

} // namespace

// ---- 公開 API ---------------------------------------------------------------

void bindings_init(const BindingTable &table) {
  g_table = table;
  for (size_t i = 0; i < g_table.n; i++) {
    Binding &b = g_table.items[i];
    switch (b.drv) {
    case DRV_GPIO_OUT:
      gpio_out_init(b);
      break;
    case DRV_GPIO_IN:
      gpio_in_init(b);
      break;
    case DRV_LEDC:
      ledc_init(b);
      break;
    case DRV_I2C_SHT30:
      sht30_init(b);
      break;
    case DRV_SCRIPT:
      // Phase C(WASM フック)で接続する。現状は no-op プレースホルダ。
      ESP_LOGI(TAG, "binding ep=%u cluster=0x%04x drv=script (no-op until Phase C)", b.ep,
               (unsigned)b.cluster);
      break;
    default:
      ESP_LOGW(TAG, "binding ep=%u cluster=0x%04x: unknown drv %u", b.ep, (unsigned)b.cluster,
               (unsigned)b.drv);
      break;
    }
  }
}

void bindings_apply_initial() {
  for (size_t i = 0; i < g_table.n; i++) {
    Binding &b = g_table.items[i];
    if (b.drv == DRV_GPIO_OUT && b.cluster == kClOnOff) {
      gpio_out_write(b, read_onoff(b.ep, false));
    } else if (b.drv == DRV_LEDC) {
      ledc_apply(b);
    }
  }
}

void bindings_on_change(uint16_t ep, uint32_t cluster, uint32_t attr,
                        const sm_attr_value_t *value) {
  for (size_t i = 0; i < g_table.n; i++) {
    Binding &b = g_table.items[i];
    if (b.ep != ep) {
      continue;
    }
    switch (b.drv) {
    case DRV_GPIO_OUT:
      // OnOff(または任意の bool 属性)を GPIO レベルへ。
      if (b.cluster == cluster && attr == 0x0000 && value != nullptr &&
          value->type == SM_T_BOOL) {
        gpio_out_write(b, value->v.b);
      }
      break;
    case DRV_LEDC:
      // LevelControl の CurrentLevel、および同一 EP の OnOff 変化で duty を再計算する。
      if ((cluster == kClLevel || cluster == kClOnOff) && attr == 0x0000) {
        ledc_apply(b);
      }
      break;
    case DRV_SCRIPT:
      // Phase C: on_attr_write フックへ委譲する。現状はログのみ。
      ESP_LOGD(TAG, "script binding: ep=%u cluster=0x%04x attr=0x%04x", ep, (unsigned)cluster,
               (unsigned)attr);
      break;
    default:
      break;
    }
  }
}

void bindings_poll(uint64_t now_ms) {
  for (size_t i = 0; i < g_table.n; i++) {
    Binding &b = g_table.items[i];
    if (b.drv == DRV_GPIO_IN) {
      gpio_in_poll(b, now_ms);
    } else if (b.drv == DRV_I2C_SHT30) {
      sht30_poll(b, now_ms);
    }
  }
}

void bindings_log() {
  ESP_LOGI(TAG, "bindings: %u entries", (unsigned)g_table.n);
  for (size_t i = 0; i < g_table.n; i++) {
    const Binding &b = g_table.items[i];
    ESP_LOGI(TAG, "  [%u] ep=%u cluster=0x%04x drv=%s p0=%llu p1=%llu p2=%llu p3=%llu",
             (unsigned)i, b.ep, (unsigned)b.cluster, drv_name(b.drv),
             (unsigned long long)b.param(0, 0), (unsigned long long)b.param(1, 0),
             (unsigned long long)b.param(2, 0), (unsigned long long)b.param(3, 0));
  }
}

} // namespace smgen
