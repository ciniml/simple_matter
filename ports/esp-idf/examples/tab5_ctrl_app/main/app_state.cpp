// app_state.hpp の実体(キュー + mutex + スナップショット)。

#include "app_state.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

namespace {

constexpr const char *TAG = "app_state";

// UI の操作キュー。UI は 1 タップ = 1 op なので浅くてよい。
constexpr UBaseType_t OP_QUEUE_LEN = 8;

QueueHandle_t g_op_queue = nullptr;
SemaphoreHandle_t g_snap_mutex = nullptr;
sm_ui_snapshot_t g_snap;

// 静的確保(起動直後に heap を掘らない。P4 の起動シーケンスは繊細)。
StaticQueue_t g_op_queue_buf;
uint8_t g_op_queue_storage[OP_QUEUE_LEN * sizeof(sm_ui_op_t)];
StaticSemaphore_t g_mutex_buf;

} // namespace

void sm_app_state_init() {
  memset(&g_snap, 0, sizeof(g_snap));
  for (size_t i = 0; i < SM_UI_MAX_NODES; ++i) {
    g_snap.nodes[i].onoff = -1;
  }
  snprintf(g_snap.status, sizeof(g_snap.status), "booting ...");
  g_op_queue = xQueueCreateStatic(OP_QUEUE_LEN, sizeof(sm_ui_op_t), g_op_queue_storage,
                                  &g_op_queue_buf);
  g_snap_mutex = xSemaphoreCreateMutexStatic(&g_mutex_buf);
  assert(g_op_queue != nullptr && g_snap_mutex != nullptr);
}

bool sm_app_post_op(const sm_ui_op_t *op) {
  if (g_op_queue == nullptr || op == nullptr) {
    return false;
  }
  if (xQueueSend(g_op_queue, op, 0) != pdTRUE) {
    ESP_LOGW(TAG, "op queue full; dropping kind=%u", (unsigned)op->kind);
    return false;
  }
  return true;
}

bool sm_app_take_op(sm_ui_op_t *out, uint32_t wait_ms) {
  if (g_op_queue == nullptr || out == nullptr) {
    return false;
  }
  return xQueueReceive(g_op_queue, out, pdMS_TO_TICKS(wait_ms)) == pdTRUE;
}

void sm_app_snapshot_get(sm_ui_snapshot_t *out) {
  if (out == nullptr) {
    return;
  }
  if (g_snap_mutex == nullptr) {
    memset(out, 0, sizeof(*out));
    return;
  }
  xSemaphoreTake(g_snap_mutex, portMAX_DELAY);
  memcpy(out, &g_snap, sizeof(*out));
  xSemaphoreGive(g_snap_mutex);
}

sm_ui_snapshot_t *sm_app_lock() {
  xSemaphoreTake(g_snap_mutex, portMAX_DELAY);
  return &g_snap;
}

void sm_app_unlock() {
  ++g_snap.seq;
  xSemaphoreGive(g_snap_mutex);
}

void sm_app_set_status(const char *fmt, ...) {
  char buf[sizeof(g_snap.status)];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  ESP_LOGI(TAG, "%s", buf);
  sm_ui_snapshot_t *s = sm_app_lock();
  memcpy(s->status, buf, sizeof(buf));
  sm_app_unlock();
}
