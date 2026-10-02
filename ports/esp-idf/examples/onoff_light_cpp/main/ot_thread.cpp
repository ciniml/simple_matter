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

// SRP に渡すバッファは OT がポインタ保持するため static に持つ(定常ヒープレス)。
// サービス枠は fabric ごとに 1 つ(マルチ admin、p4-thread-controller.md §18.4 D1)。
enum class SrpSlot : uint8_t {
  Free,     // 未使用
  Active,   // otSrpClientAddService 済み(登録待ち or 登録済み)
  Removing, // otSrpClientRemoveService 済み(サーバ応答待ち。完了まで再利用不可)
};
struct SrpSvc {
  SrpSlot state;
  char instance[40]; // "<fab16>-<node16>" + NUL
  otSrpClientService svc;
};
static char g_srp_host[24]; // "SM" + 12 hex + NUL
static SrpSvc g_srp_slots[SM_OT_SRP_MAX_SERVICES];
static otDnsTxtEntry g_srp_txt[3]; // 全サービス共通(内容は不変)
static bool g_srp_started = false; // host 名 / autostart / callback を設定済みか

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

// SRP client コールバック(OT タスクコンテキスト、lock 保持中)。削除完了したサービスの枠を
// 解放し、枠待ちの追加があり得るので matter_task へ再同期を依頼する。
static void srp_client_cb(otError err, const otSrpClientHostInfo *host,
                          const otSrpClientService *services,
                          const otSrpClientService *removed, void *ctx) {
  (void)host;
  (void)services;
  (void)ctx;
  if (err != OT_ERROR_NONE) {
    ESP_LOGW(TAG, "SRP client update error: %d", (int)err);
  }
  bool freed = false;
  for (const otSrpClientService *r = removed; r != nullptr; r = r->mNext) {
    for (auto &slot : g_srp_slots) {
      if (&slot.svc == r && slot.state != SrpSlot::Free) {
        ESP_LOGI(TAG, "SRP service removed (server ack): instance=%s", slot.instance);
        slot.state = SrpSlot::Free;
        freed = true;
      }
    }
  }
  if (freed && g_ot_queue) {
    Cmd c{};
    c.kind = CmdKind::SrpResync;
    xQueueSend(g_ot_queue, &c, 0);
  }
}

// host 名 / host address / TXT / callback / autostart の初回設定(lock 保持中に呼ぶ)。
static void srp_start_locked(otInstance *inst) {
  if (g_srp_started) {
    return;
  }
  // host 名 = SM<MAC 12hex>。SRP host address は auto(OT の unicast アドレス)。
  uint8_t mac[8] = {0};
  esp_read_mac(mac, ESP_MAC_IEEE802154);
  snprintf(g_srp_host, sizeof(g_srp_host), "SM%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
  otSrpClientSetHostName(inst, g_srp_host);
  otSrpClientEnableAutoHostAddress(inst);

  // TXT SII/SAI/T(thread-port.md T3 実測値)。
  g_srp_txt[0].mKey = "SII";
  g_srp_txt[0].mValue = (const uint8_t *)"10000";
  g_srp_txt[0].mValueLength = 5;
  g_srp_txt[1].mKey = "SAI";
  g_srp_txt[1].mValue = (const uint8_t *)"1000";
  g_srp_txt[1].mValueLength = 4;
  g_srp_txt[2].mKey = "T";
  g_srp_txt[2].mValue = (const uint8_t *)"0";
  g_srp_txt[2].mValueLength = 1;

  otSrpClientSetCallback(inst, srp_client_cb, nullptr);
  otSrpClientEnableAutoStartMode(inst, nullptr, nullptr); // OTBR を netdata から自動発見
  g_srp_started = true;
  ESP_LOGI(TAG, "SRP client started: host=%s", g_srp_host);
}

void sm_ot_srp_sync(const char *const *names, size_t n) {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();

  // (1) 現 fabric 集合に無い Active 枠を削除する。
  for (auto &slot : g_srp_slots) {
    if (slot.state != SrpSlot::Active) {
      continue;
    }
    bool wanted = false;
    for (size_t i = 0; i < n; i++) {
      if (strcmp(slot.instance, names[i]) == 0) {
        wanted = true;
        break;
      }
    }
    if (wanted) {
      continue;
    }
    // サーバへ一度も送っていない(TO_ADD)/ client 停止中はサーバ応答が来ないので即時クリア。
    // それ以外はサーバから消す(完了は srp_client_cb で枠を解放)。
    bool local_only =
        slot.svc.mState == OT_SRP_CLIENT_ITEM_STATE_TO_ADD || !otSrpClientIsRunning(inst);
    otError e = local_only ? otSrpClientClearService(inst, &slot.svc)
                           : otSrpClientRemoveService(inst, &slot.svc);
    if (e != OT_ERROR_NONE) {
      // NOT_FOUND 等: OT 側に既に無い → 枠を解放して整合させる。
      ESP_LOGW(TAG, "SRP remove failed (%d), dropping slot: instance=%s", (int)e, slot.instance);
      slot.state = SrpSlot::Free;
    } else if (local_only) {
      ESP_LOGI(TAG, "SRP service cleared (not yet registered): instance=%s", slot.instance);
      slot.state = SrpSlot::Free;
    } else {
      ESP_LOGI(TAG, "SRP service remove requested: instance=%s", slot.instance);
      slot.state = SrpSlot::Removing;
    }
  }

  // (2) 未登録の名前を追加する。
  for (size_t i = 0; i < n; i++) {
    bool present = false;
    bool removing = false;
    for (auto &slot : g_srp_slots) {
      if (slot.state != SrpSlot::Free && strcmp(slot.instance, names[i]) == 0) {
        present = present || slot.state == SrpSlot::Active;
        removing = removing || slot.state == SrpSlot::Removing;
      }
    }
    if (present) {
      continue;
    }
    if (removing) {
      // 同名を削除中(同じ fabric/node の再追加)。完了後の SrpResync で追加する。
      ESP_LOGI(TAG, "SRP add deferred (same instance being removed): instance=%s", names[i]);
      continue;
    }
    SrpSvc *free_slot = nullptr;
    for (auto &slot : g_srp_slots) {
      if (slot.state == SrpSlot::Free) {
        free_slot = &slot;
        break;
      }
    }
    if (free_slot == nullptr) {
      // 全枠が Active/Removing。削除完了後の SrpResync で再試行される。
      ESP_LOGW(TAG, "SRP add deferred (no free slot): instance=%s", names[i]);
      continue;
    }
    srp_start_locked(inst);

    // service: _matter._tcp、port 5540。
    strncpy(free_slot->instance, names[i], sizeof(free_slot->instance) - 1);
    free_slot->instance[sizeof(free_slot->instance) - 1] = 0;
    memset(&free_slot->svc, 0, sizeof(free_slot->svc));
    free_slot->svc.mName = "_matter._tcp";
    free_slot->svc.mInstanceName = free_slot->instance;
    free_slot->svc.mPort = 5540;
    free_slot->svc.mTxtEntries = g_srp_txt;
    free_slot->svc.mNumTxtEntries = 3;

    otError e = otSrpClientAddService(inst, &free_slot->svc);
    if (e == OT_ERROR_NONE) {
      free_slot->state = SrpSlot::Active;
      ESP_LOGI(TAG, "SRP service added: host=%s instance=%s", g_srp_host, free_slot->instance);
    } else {
      ESP_LOGE(TAG, "otSrpClientAddService failed: %d instance=%s", (int)e, names[i]);
    }
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
