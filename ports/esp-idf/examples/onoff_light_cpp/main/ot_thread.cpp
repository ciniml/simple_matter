// esp_openthread 配線の実体(docs/design/c-ffi-shim.md §10)。
// CONFIG_SM_NETWORK_THREAD のときのみコンパイルされる(それ以外は空)。

#include "ot_thread.hpp"

#include "sdkconfig.h"

#if CONFIG_SM_NETWORK_THREAD

#include <cstring>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_openthread.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_vfs_eventfd.h"

#include "freertos/task.h"

#include "openthread/dataset.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/srp_client.h"
#include "openthread/thread.h"

static const char *TAG = "ot_thread";

static QueueHandle_t g_ot_queue = nullptr;
static esp_netif_t *g_ot_netif = nullptr;

// SRP に渡すバッファは OT がポインタ保持するため static に持つ。
static char g_srp_host[24];       // "SM" + 12 hex + NUL
static char g_srp_instance[40];   // "<fab16>-<node16>" + NUL
static otSrpClientService g_srp_service;
static otDnsTxtEntry g_srp_txt[3];
static bool g_srp_registered = false;

// ---- role 変化コールバック(OT タスクコンテキスト、lock 保持中)------------------

static void ot_state_changed(otChangedFlags flags, void *ctx) {
  (void)ctx;
  if ((flags & OT_CHANGED_THREAD_ROLE) == 0) {
    return;
  }
  otInstance *inst = esp_openthread_get_instance();
  otDeviceRole role = otThreadGetDeviceRole(inst);
  bool attached = (role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
                   role == OT_DEVICE_ROLE_LEADER);
  ESP_LOGI(TAG, "OT role changed: %d (attached=%d)", (int)role, (int)attached);
  if (g_ot_queue) {
    Cmd c{};
    c.kind = CmdKind::ThreadRole;
    c.thread_attached = attached;
    xQueueSend(g_ot_queue, &c, 0);
  }
}

// ---- OT mainloop タスク ----------------------------------------------------

static void ot_task(void *ctx) {
  (void)ctx;
  esp_openthread_platform_config_t config = {};
  config.radio_config.radio_mode = RADIO_MODE_NATIVE; // C6 内蔵 802.15.4
  config.host_config.host_connection_mode = HOST_CONNECTION_MODE_NONE;
  config.port_config.storage_partition_name = "nvs";
  config.port_config.netif_queue_size = 10;
  config.port_config.task_queue_size = 10;

  ESP_ERROR_CHECK(esp_openthread_init(&config));

  // OT netif(lwIP 統合): UDP ソケットは WiFi と同じ lwIP 経由になる。
  esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
  g_ot_netif = esp_netif_new(&netif_cfg);
  assert(g_ot_netif != nullptr);
  ESP_ERROR_CHECK(esp_netif_attach(g_ot_netif, esp_openthread_netif_glue_init(&config)));

  otInstance *inst = esp_openthread_get_instance();
  otSetStateChangedCallback(inst, ot_state_changed, nullptr);

  ESP_LOGI(TAG, "openthread mainloop starting");
  esp_openthread_launch_mainloop(); // ブロック(内部イベントループ)

  // 到達しないが後始末。
  esp_openthread_netif_glue_deinit();
  esp_netif_destroy(g_ot_netif);
  esp_openthread_deinit();
  vTaskDelete(nullptr);
}

void sm_ot_init(QueueHandle_t q) {
  g_ot_queue = q;
  // OT は eventfd を使う(radio / netif / task queue の 3 本)。
  esp_vfs_eventfd_config_t eventfd_config = {};
  eventfd_config.max_fds = 3;
  ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));
  // OT スタックは専用タスクで回す(スタックは 8KB 級で足りる)。
  xTaskCreate(ot_task, "ot_main", 10 * 1024, nullptr, 5, nullptr);
}

bool sm_ot_apply_dataset(const uint8_t *tlv, size_t len) {
  if (len == 0 || len > sizeof(((otOperationalDatasetTlvs *)nullptr)->mTlvs)) {
    ESP_LOGE(TAG, "invalid dataset len=%u", (unsigned)len);
    return false;
  }
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otOperationalDatasetTlvs ds;
  memset(&ds, 0, sizeof(ds));
  memcpy(ds.mTlvs, tlv, len);
  ds.mLength = (uint8_t)len;
  otError e = otDatasetSetActiveTlvs(inst, &ds);
  if (e == OT_ERROR_NONE) {
    e = otIp6SetEnabled(inst, true);
  }
  if (e == OT_ERROR_NONE) {
    e = otThreadSetEnabled(inst, true);
  }
  esp_openthread_lock_release();
  ESP_LOGI(TAG, "apply dataset (len=%u) -> otError %d", (unsigned)len, (int)e);
  return e == OT_ERROR_NONE;
}

void sm_ot_srp_register(const char *instance_name) {
  if (g_srp_registered) {
    return; // 単一 fabric・単一登録(§10.1)。
  }
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();

  // host 名 = SM<MAC 12hex>。SRP host address は auto(OT の unicast アドレス)。
  uint8_t mac[8] = {0};
  esp_read_mac(mac, ESP_MAC_IEEE802154);
  snprintf(g_srp_host, sizeof(g_srp_host), "SM%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
  otSrpClientSetHostName(inst, g_srp_host);
  otSrpClientEnableAutoHostAddress(inst);

  // service: _matter._tcp、port 5540、TXT SII/SAI/T(thread-port.md T3 実測値)。
  strncpy(g_srp_instance, instance_name, sizeof(g_srp_instance) - 1);
  g_srp_instance[sizeof(g_srp_instance) - 1] = 0;

  g_srp_txt[0].mKey = "SII";
  g_srp_txt[0].mValue = (const uint8_t *)"10000";
  g_srp_txt[0].mValueLength = 5;
  g_srp_txt[1].mKey = "SAI";
  g_srp_txt[1].mValue = (const uint8_t *)"1000";
  g_srp_txt[1].mValueLength = 4;
  g_srp_txt[2].mKey = "T";
  g_srp_txt[2].mValue = (const uint8_t *)"0";
  g_srp_txt[2].mValueLength = 1;

  memset(&g_srp_service, 0, sizeof(g_srp_service));
  g_srp_service.mName = "_matter._tcp";
  g_srp_service.mInstanceName = g_srp_instance;
  g_srp_service.mPort = 5540;
  g_srp_service.mTxtEntries = g_srp_txt;
  g_srp_service.mNumTxtEntries = 3;

  otError e = otSrpClientAddService(inst, &g_srp_service);
  if (e == OT_ERROR_NONE || e == OT_ERROR_ALREADY) {
    otSrpClientEnableAutoStartMode(inst, nullptr, nullptr); // OTBR を netdata から自動発見
    g_srp_registered = true;
    ESP_LOGI(TAG, "SRP registered: host=%s instance=%s", g_srp_host, g_srp_instance);
  } else {
    ESP_LOGE(TAG, "otSrpClientAddService failed: %d", (int)e);
  }
  esp_openthread_lock_release();
}

bool sm_ot_is_attached() {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otDeviceRole role = otThreadGetDeviceRole(inst);
  esp_openthread_lock_release();
  return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
         role == OT_DEVICE_ROLE_LEADER;
}

#endif // CONFIG_SM_NETWORK_THREAD
