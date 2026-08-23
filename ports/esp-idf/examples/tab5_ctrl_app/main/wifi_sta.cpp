// WiFi STA(ESP32-C6 over SDIO / esp_hosted + esp_wifi_remote)。
// docs/design/p4-thread-controller.md §10(T2)。
//
// 参照実装: `~/repos/tab5_claude_client` の `main/wifi_setup.cpp`(同一個体の
// Tab5 で WiFi 実証済み)。あちらは IDF 6.0 + ブロッキング接続だったが、ここは
// IDF 5.4.4 + イベント駆動・ノンブロッキング(GUI を待たせない)に組み直してある。

#include "wifi_sta.hpp"

#include <cstdio>
#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "M5Unified.h"

namespace {

constexpr const char *TAG = "tab5_wifi";

// Tab5 の IO エキスパンダ #2(PI4IOE5V6408 @0x44)の bit0 = WLAN_PWR_EN。
// M5Unified 0.2.20 の `Power_Class::begin()`(`utility/Power_Class.cpp` の
// `board_M5Tab5` 分岐)は @0x44 へ OUT_SET = 0b10000001 / IO_DIR = 0b10110001 を
// 書くので、**bit0 は M5.begin() の時点で既に High** になっている。
// ただしそれは「M5.begin() が成功していれば」の話なので、ここでは読み戻して
// 確認し、0 だったときだけ明示的に立てる(§9.4 の @0x43 P2 と同じ流儀)。
constexpr uint8_t kPi4ioe2Addr = 0x44;
constexpr uint8_t kRegOutSet = 0x05;
constexpr uint32_t kI2cFreq = 400000;

// 立て直したときの C6 ブート待ち(参照 repo の 1500ms と同値)。
constexpr uint32_t kC6BootMs = 1500;

SemaphoreHandle_t g_lock = nullptr;
sm_wifi_status_t g_status = {};
esp_netif_t *g_netif = nullptr;
bool g_started = false;

void lock() {
  if (g_lock != nullptr) {
    xSemaphoreTake(g_lock, portMAX_DELAY);
  }
}
void unlock() {
  if (g_lock != nullptr) {
    xSemaphoreGive(g_lock);
  }
}

void set_state(uint8_t s) {
  lock();
  g_status.state = s;
  unlock();
}

// C6 の電源(WLAN_PWR_EN)を確認し、落ちていたら入れる。
// 戻り値 = 「ここで入れ直したので C6 のブートを待つ必要がある」。
bool ensure_c6_power() {
  auto &bus = M5.In_I2C;
  uint8_t cur = 0;
  if (!bus.readRegister(kPi4ioe2Addr, kRegOutSet, &cur, 1, kI2cFreq)) {
    ESP_LOGW(TAG, "PI4IOE2 @0x%02x read failed; assuming M5.begin() powered the C6", kPi4ioe2Addr);
    return false;
  }
  if ((cur & 0x01) != 0) {
    ESP_LOGI(TAG, "C6 power: already on (OUT_SET=0x%02x, set by M5Unified Power_Class)", cur);
    return false;
  }
  ESP_LOGW(TAG, "C6 power: WLAN_PWR_EN was low (OUT_SET=0x%02x); driving it high", cur);
  bus.writeRegister8(kPi4ioe2Addr, kRegOutSet, (uint8_t)(cur | 0x01), kI2cFreq);
  uint8_t back = 0;
  bus.readRegister(kPi4ioe2Addr, kRegOutSet, &back, 1, kI2cFreq);
  if ((back & 0x01) == 0) {
    ESP_LOGE(TAG, "PI4IOE2 bit0 readback mismatch (0x%02x) -- I2C did not reach 0x44", back);
  }
  return true;
}

void on_event(void *, esp_event_base_t base, int32_t id, void *data) {
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
    return;
  }
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
    // リンクローカルを明示的に生やす(Matter の on-network PASE は LL 宛でも通る)。
    if (g_netif != nullptr) {
      esp_netif_create_ip6_linklocal(g_netif);
    }
    return;
  }
  if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
    // ここは既定イベントループのタスク。**絶対にブロックしない**
    // (OT / IP のイベントも同じループに乗っている)。再接続は監視ループに任せる。
    lock();
    g_status.state = SM_WIFI_CONNECTING;
    g_status.ll_addr[0] = 0;
    g_status.ip4[0] = 0;
    g_status.retries++;
    uint32_t n = g_status.retries;
    unlock();
    ESP_LOGW(TAG, "disconnected (attempt %u); will retry", (unsigned)n);
    return;
  }
  if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
    auto *ev = (ip_event_got_ip_t *)data;
    lock();
    g_status.state = SM_WIFI_CONNECTED;
    snprintf(g_status.ip4, sizeof(g_status.ip4), IPSTR, IP2STR(&ev->ip_info.ip));
    unlock();
    ESP_LOGI(TAG, "got IPv4 " IPSTR, IP2STR(&ev->ip_info.ip));
    if (g_netif != nullptr) {
      esp_netif_create_ip6_linklocal(g_netif);
    }
    return;
  }
  if (base == IP_EVENT && id == IP_EVENT_GOT_IP6) {
    auto *ev = (ip_event_got_ip6_t *)data;
    if (ev->esp_netif != g_netif) {
      return; // OT netif の GOT_IP6 は無視する
    }
    lock();
    g_status.state = SM_WIFI_CONNECTED;
    snprintf(g_status.ll_addr, sizeof(g_status.ll_addr), IPV6STR, IPV62STR(ev->ip6_info.ip));
    g_status.netif_index = (uint32_t)esp_netif_get_netif_impl_index(g_netif);
    unlock();
    ESP_LOGI(TAG, "got IPv6 " IPV6STR " (netif index %d)", IPV62STR(ev->ip6_info.ip),
             esp_netif_get_netif_impl_index(g_netif));
    return;
  }
}

// 実際の bringup。C6 の電源投入待ちが要る場合があるので専用タスクで回す
// (app_main / LVGL を待たせない)。
void wifi_task(void *) {
  if (ensure_c6_power()) {
    vTaskDelay(pdMS_TO_TICKS(kC6BootMs));
  }

  // esp_netif / event loop は app_main で作成済み。
  g_netif = esp_netif_create_default_wifi_sta();
  if (g_netif == nullptr) {
    ESP_LOGE(TAG, "esp_netif_create_default_wifi_sta() failed");
    set_state(SM_WIFI_FAILED);
    vTaskDelete(nullptr);
    return;
  }

  esp_err_t err = esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &on_event,
                                                      nullptr, nullptr);
  if (err == ESP_OK) {
    err = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, &on_event, nullptr,
                                              nullptr);
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "event handler register failed: %s", esp_err_to_name(err));
    set_state(SM_WIFI_FAILED);
    vTaskDelete(nullptr);
    return;
  }

  // esp_wifi_init 以降は esp_wifi_remote が SDIO 越しに C6 へ転送する。
  // ここで失敗する典型は「C6 の slave FW が esp_hosted 2.x でない」
  // 「SDIO のピン/クロック設定が違う」(CMD5 タイムアウト)。
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  err = esp_wifi_init(&cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_wifi_init failed: %s (C6 slave firmware / SDIO link?)",
             esp_err_to_name(err));
    set_state(SM_WIFI_FAILED);
    vTaskDelete(nullptr);
    return;
  }

  wifi_config_t wcfg = {};
  snprintf((char *)wcfg.sta.ssid, sizeof(wcfg.sta.ssid), "%s", CONFIG_SM_WIFI_SSID);
  snprintf((char *)wcfg.sta.password, sizeof(wcfg.sta.password), "%s", CONFIG_SM_WIFI_PASSWORD);
  // 空パスワードなら open AP も許す。
  wcfg.sta.threshold.authmode = wcfg.sta.password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;

  if ((err = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK ||
      (err = esp_wifi_set_config(WIFI_IF_STA, &wcfg)) != ESP_OK ||
      (err = esp_wifi_start()) != ESP_OK) {
    ESP_LOGE(TAG, "wifi start failed: %s", esp_err_to_name(err));
    set_state(SM_WIFI_FAILED);
    vTaskDelete(nullptr);
    return;
  }

  ESP_LOGI(TAG, "wifi started; connecting to \"%s\"", CONFIG_SM_WIFI_SSID);

  // --- 監視ループ: 切断されたままなら 5 秒毎に再接続を試す ---
  // (esp_wifi_connect() をイベントハンドラから呼ぶとイベントループを塞ぐので、
  //  リトライはこのタスクの仕事にしてある。)
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(5000));
    lock();
    uint8_t st = g_status.state;
    unlock();
    if (st == SM_WIFI_CONNECTING) {
      esp_wifi_connect();
    }
  }
}

} // namespace

void sm_wifi_start() {
  if (g_started) {
    return;
  }
  g_started = true;
  if (g_lock == nullptr) {
    g_lock = xSemaphoreCreateMutex();
  }
  memset(&g_status, 0, sizeof(g_status));

  if (CONFIG_SM_WIFI_SSID[0] == '\0') {
    g_status.state = SM_WIFI_OFF;
    ESP_LOGI(TAG, "SM_WIFI_SSID is empty -- WiFi disabled (Thread only)");
    return;
  }
  snprintf(g_status.ssid, sizeof(g_status.ssid), "%s", CONFIG_SM_WIFI_SSID);
  g_status.state = SM_WIFI_CONNECTING;

  // スタックは esp_hosted の初期化(SDIO + RPC)込みで 6KB。
  if (xTaskCreate(&wifi_task, "wifi_up", 6144, nullptr, 4, nullptr) != pdPASS) {
    ESP_LOGE(TAG, "failed to create the wifi bringup task");
    g_status.state = SM_WIFI_FAILED;
  }
}

uint32_t sm_wifi_netif_index() {
  lock();
  uint32_t idx = g_status.netif_index;
  unlock();
  if (idx == 0 && g_netif != nullptr) {
    int i = esp_netif_get_netif_impl_index(g_netif);
    idx = i > 0 ? (uint32_t)i : 0;
  }
  return idx;
}

void sm_wifi_get_status(sm_wifi_status_t *out) {
  if (out == nullptr) {
    return;
  }
  lock();
  *out = g_status;
  unlock();
}
