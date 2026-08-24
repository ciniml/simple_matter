// display_gfx.cpp — M5Unified/M5GFX + 自前 LVGL ポート(T1b)。
//
// 経緯: Espressif BSP(espressif/m5stack_tab5 1.2.0 + esp_lvgl_port 2.9)は
// 実機 Tab5(board version 2 / ST7123 タッチ)で初期化ログが全て正常・
// バックライト点灯にもかかわらず画面が真っ黒だった。M5GFX は同一個体で
// 表示実績があるためこちらへ移行した(docs/design/p4-thread-controller.md §9.5)。
//
// M5GFX は「パネル + タッチ + 電源」までを見る。LVGL のポート(tick / タスク /
// display / indev)は薄いので自前で持つ。

#include "display_gfx.hpp"

#include "M5Unified.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace {

constexpr const char *TAG = "tab5_disp";

// 描画バッファは画面の 1/10 を 2 枚(PARTIAL レンダリング)。
// 1280x720 の 1/10 = 1280x72 = 92160px = 184320B。2 枚で約 360KB を PSRAM から取る。
// 内蔵 RAM は pump の静的スタック 128KB と OT/lwIP/mbedTLS が使うので触らない。
constexpr int kDrawBufDiv = 10;

SemaphoreHandle_t g_lvgl_mutex = nullptr;
StaticSemaphore_t g_lvgl_mutex_buf;
lv_display_t *g_disp = nullptr;
bool g_hw_ready = false;

// LVGL の時間源。esp_timer(64bit us)を ms に落とすだけで、
// 別途 1ms の周期タイマを回すより取りこぼしに強い。
uint32_t lvgl_tick_cb(void) { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

// LVGL(RGB565)→ M5GFX。DSI パネルの内部フレームバッファへ書き込む。
void lvgl_flush_cb(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map) {
  const int32_t w = area->x2 - area->x1 + 1;
  const int32_t h = area->y2 - area->y1 + 1;
  auto &d = M5.Display;
  d.startWrite();
  d.setAddrWindow(area->x1, area->y1, w, h);
  // 型付き writePixels は M5GFX 側で色形式変換を任せられる(swap 引数の
  // 取り違えでバイト順が壊れるのを避ける)。
  d.writePixels(reinterpret_cast<const lgfx::rgb565_t *>(px_map), static_cast<int32_t>(w) * h);
  d.endWrite();
  lv_display_flush_ready(disp);
}

// 合成ポインタ(T5b)。read_cb 内だけで進む状態機械なので、LVGL タスク以外は
// 「起動(active を立てる)」と「完了待ち(active を読む)」しかしない。
struct SynthPointer {
  int32_t x1, y1, x2, y2;
  int64_t t0_us, t1_us;
  uint32_t press_reads; // 最低 1 回は PRESSED を LVGL に見せてから離す
  bool released_sent;
  volatile bool active;
};
SynthPointer g_synth = {};

// タッチ。M5GFX の getTouch() は setRotation() を反映した「画面座標」を返すので、
// BSP 経路で必要だった回転シム(SM_UI_TOUCH_MIRROR_X/Y 含む)は不要になった。
int g_touch_log_left = 5;
void lvgl_touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
  (void)indev;
  // 合成注入中は実タッチを完全に無視する(排他)。
  if (g_synth.active) {
    const int64_t now = esp_timer_get_time();
    if (now < g_synth.t1_us || g_synth.press_reads == 0) {
      const int64_t span = g_synth.t1_us - g_synth.t0_us;
      const int64_t el = now - g_synth.t0_us;
      int32_t k = (span > 0) ? static_cast<int32_t>((el * 1000) / span) : 1000;
      if (k < 0) {
        k = 0;
      }
      if (k > 1000) {
        k = 1000;
      }
      data->point.x = g_synth.x1 + (g_synth.x2 - g_synth.x1) * k / 1000;
      data->point.y = g_synth.y1 + (g_synth.y2 - g_synth.y1) * k / 1000;
      data->state = LV_INDEV_STATE_PRESSED;
      ++g_synth.press_reads;
      return;
    }
    if (!g_synth.released_sent) {
      data->point.x = g_synth.x2;
      data->point.y = g_synth.y2;
      data->state = LV_INDEV_STATE_RELEASED;
      g_synth.released_sent = true;
      return;
    }
    // 「離す」まで LVGL に届いた。次の読みから実タッチへ戻す。
    g_synth.active = false;
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }
  int32_t x = 0;
  int32_t y = 0;
  if (M5.Display.getTouch(&x, &y)) {
    data->point.x = x;
    data->point.y = y;
    data->state = LV_INDEV_STATE_PRESSED;
    if (g_touch_log_left > 0) {
      --g_touch_log_left;
      ESP_LOGI(TAG, "touch: (%d,%d)", static_cast<int>(x), static_cast<int>(y));
    }
  } else {
    data->state = LV_INDEV_STATE_RELEASED;
  }
}

void lvgl_task(void *) {
  ESP_LOGI(TAG, "lvgl task started");
  for (;;) {
    uint32_t delay_ms = 50;
    if (sm_display_lock(0)) {
      delay_ms = lv_timer_handler();
      sm_display_unlock();
    }
    if (delay_ms == LV_NO_TIMER_READY || delay_ms > 50) {
      delay_ms = 50;
    }
    if (delay_ms < 2) {
      delay_ms = 2;
    }
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
  }
}

} // namespace

bool sm_display_hw_init(void) {
  auto cfg = M5.config();
  // PORT.A(Grove)の 5V。Power_Class::begin() が Tab5 の IO エキスパンダ #0
  // (PI4IOE5V6408 @0x43)を初期化した直後に setExtOutput(cfg.output_power) で
  // EXT5V_EN(P2)を入れ直す。手動のエキスパンダ叩き(旧 enable_ext_5v)は不要。
  cfg.output_power = true;
  cfg.clear_display = true;
  // 使わない周辺は初期化しない(I2S/IMU/RTC の分だけ起動が軽くなる)。
  cfg.internal_spk = false;
  cfg.internal_mic = false;
  cfg.internal_imu = false;
  cfg.internal_rtc = false;
  M5.begin(cfg);

  // パネルは MIPI-DSI 720x1280(縦)。rotation 1 = 1280x720 横。
  M5.Display.setRotation(1);
  M5.Display.setBrightness(255);
  M5.Display.fillScreen(TFT_BLACK);

  ESP_LOGI(TAG, "M5.begin: board=%d display=%dx%d touch=%s", static_cast<int>(M5.getBoard()),
           static_cast<int>(M5.Display.width()), static_cast<int>(M5.Display.height()),
           M5.Display.touch() != nullptr ? "yes" : "no");
  g_hw_ready = (M5.Display.width() > 0 && M5.Display.height() > 0);
  if (!g_hw_ready) {
    ESP_LOGE(TAG, "M5.Display has no panel (autodetect failed)");
  }
  return g_hw_ready;
}

lv_display_t *sm_display_lvgl_start(void) {
  if (!g_hw_ready) {
    ESP_LOGE(TAG, "sm_display_lvgl_start before a successful sm_display_hw_init()");
    return nullptr;
  }
  if (g_disp != nullptr) {
    return g_disp;
  }

  g_lvgl_mutex = xSemaphoreCreateRecursiveMutexStatic(&g_lvgl_mutex_buf);
  if (g_lvgl_mutex == nullptr) {
    ESP_LOGE(TAG, "lvgl mutex alloc failed");
    return nullptr;
  }

  lv_init();
  lv_tick_set_cb(lvgl_tick_cb);

  const int32_t hor = M5.Display.width();
  const int32_t ver = M5.Display.height();
  g_disp = lv_display_create(hor, ver);
  if (g_disp == nullptr) {
    ESP_LOGE(TAG, "lv_display_create failed");
    return nullptr;
  }
  lv_display_set_color_format(g_disp, LV_COLOR_FORMAT_RGB565);
  lv_display_set_flush_cb(g_disp, lvgl_flush_cb);

  const size_t buf_px = static_cast<size_t>(hor) * ((ver + kDrawBufDiv - 1) / kDrawBufDiv);
  const size_t buf_bytes = buf_px * sizeof(uint16_t);
  void *buf1 = heap_caps_malloc(buf_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  void *buf2 = heap_caps_malloc(buf_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (buf1 == nullptr || buf2 == nullptr) {
    ESP_LOGE(TAG, "draw buffer alloc failed (%u B x2)", static_cast<unsigned>(buf_bytes));
    heap_caps_free(buf1);
    heap_caps_free(buf2);
    return nullptr;
  }
  lv_display_set_buffers(g_disp, buf1, buf2, buf_bytes, LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_default(g_disp);
  ESP_LOGI(TAG, "lvgl display %dx%d, draw buf %u B x2 (PSRAM)", static_cast<int>(hor),
           static_cast<int>(ver), static_cast<unsigned>(buf_bytes));

  lv_indev_t *indev = lv_indev_create();
  if (indev != nullptr) {
    lv_indev_set_type(indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(indev, lvgl_touch_read_cb);
    lv_indev_set_display(indev, g_disp);
  } else {
    ESP_LOGW(TAG, "lv_indev_create failed; touch is disabled");
  }

  // LVGL タスク。sm_ctrl_* は絶対に呼ばない(単線契約は pump タスク)。
  if (xTaskCreate(lvgl_task, "lvgl", 10240, nullptr, 4, nullptr) != pdPASS) {
    ESP_LOGE(TAG, "lvgl task create failed");
    return nullptr;
  }
  return g_disp;
}

bool sm_display_lock(uint32_t timeout_ms) {
  if (g_lvgl_mutex == nullptr) {
    return false;
  }
  const TickType_t ticks = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
  return xSemaphoreTakeRecursive(g_lvgl_mutex, ticks) == pdTRUE;
}

void sm_display_unlock(void) {
  if (g_lvgl_mutex != nullptr) {
    xSemaphoreGiveRecursive(g_lvgl_mutex);
  }
}

bool sm_display_inject_pointer(int32_t x1, int32_t y1, int32_t x2, int32_t y2, uint32_t ms) {
  if (g_disp == nullptr) {
    return false;
  }
  if (g_synth.active) {
    return false; // 前の注入がまだ終わっていない
  }
  const int32_t w = lv_display_get_horizontal_resolution(g_disp);
  const int32_t h = lv_display_get_vertical_resolution(g_disp);
  auto clamp = [](int32_t v, int32_t lo, int32_t hi) { return v < lo ? lo : (v > hi ? hi : v); };
  g_synth.x1 = clamp(x1, 0, w - 1);
  g_synth.y1 = clamp(y1, 0, h - 1);
  g_synth.x2 = clamp(x2, 0, w - 1);
  g_synth.y2 = clamp(y2, 0, h - 1);
  if (ms == 0) {
    ms = 1;
  }
  g_synth.t0_us = esp_timer_get_time();
  g_synth.t1_us = g_synth.t0_us + static_cast<int64_t>(ms) * 1000;
  g_synth.press_reads = 0;
  g_synth.released_sent = false;
  // フィールドの書き込みが active=true より前に見えるようにする。
  __sync_synchronize();
  g_synth.active = true;
  return true;
}

bool sm_display_inject_busy(void) { return g_synth.active; }
