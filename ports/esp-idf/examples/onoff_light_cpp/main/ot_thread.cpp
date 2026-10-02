// esp_openthread 配線の実体(docs/design/c-ffi-shim.md §10)。
// CONFIG_SM_NETWORK_THREAD のときのみコンパイルされる(それ以外は空)。

#include "ot_thread.hpp"

#include "sdkconfig.h"

#if CONFIG_SM_NETWORK_THREAD

#include <cstdint>
#include <cstdio>
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
#include "esp_timer.h"
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
// サービス枠は fabric ごとに 1 つ(マルチ admin、p4-thread-controller.md §18.4 D1)+ commissionable
// (`_matterc._udp`、窓オープン中のみ、§18.4 D2)が 1 つ。
enum class SrpSlot : uint8_t {
  Free,     // 未使用
  Active,   // otSrpClientAdd/Service 済み(登録待ち or 登録済み)
  Removing, // otSrpClientRemoveService 済み(サーバ応答待ち。完了まで再利用不可)
  Blocked,  // サーバが名前重複(Duplicated)で拒否 → OT から外して retry_at_us まで保留
};
struct SrpSvc {
  SrpSlot state;
  bool registered_once; // サーバに一度でも受理されたか(重複拒否の犯人候補から外す)
  uint32_t backoff_s;   // Blocked の再試行間隔(犯人と特定できたら倍々)
  int64_t retry_at_us;  // Blocked: 再登録を試す時刻(esp_timer_get_time 基準)
  char instance[40];    // "<fab16>-<node16>"(運用)/ "<id16>"(commissionable)+ NUL
  otSrpClientService svc;
};
static char g_srp_host[24]; // "SM" + 12 hex + NUL
static SrpSvc g_srp_slots[SM_OT_SRP_MAX_SERVICES];
static otDnsTxtEntry g_srp_txt[3]; // 運用サービス共通(内容は不変)
static bool g_srp_started = false; // host 名 / autostart / callback を設定済みか
// サーバが更新を Duplicated で拒否した(コールバックで立て、次の同期で処理する)。
static volatile bool g_srp_dup_pending = false;
static esp_timer_handle_t g_srp_retry_timer = nullptr;

// commissionable(`_matterc._udp`)枠とその文字列バッファ(登録中は OT が参照するので不変に保つ)。
static SrpSvc g_srp_comm;
static sm_commissionable_t g_comm_cur; // g_srp_comm に載せている内容
static char g_comm_sub[5][16];         // _L<d> / _S<d> / _V<vid> / _T<dt> / _CM
static const char *g_comm_sub_ptrs[6];
static char g_comm_txt_val[4][16];     // D / CM / VP / DT
static otDnsTxtEntry g_comm_txt[6];
// 重複拒否で犯人を特定できたときの再試行間隔(初回 / 上限)。名前は SRP サーバの key-lease
// (既定約 7.9 日)の間予約され続けるので、上限は長めに取る。
static constexpr uint32_t kSrpBlockFirstS = 600;
static constexpr uint32_t kSrpBlockMaxS = 6 * 3600;
// 犯人が特定できない(未受理のサービスが複数)ときは、短い間隔で 1 つずつ戻して切り分ける。
static constexpr uint32_t kSrpBlockProbeS = 5;

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

static void srp_client_cb(otError err, const otSrpClientHostInfo *host,
                          const otSrpClientService *services,
                          const otSrpClientService *removed, void *ctx);

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

static void post_srp_resync() {
  if (g_ot_queue) {
    Cmd c{};
    c.kind = CmdKind::SrpResync;
    xQueueSend(g_ot_queue, &c, 0);
  }
}

static void srp_retry_timer_cb(void *) { post_srp_resync(); }

// 全サービス枠(運用 + commissionable)を走査する。
template <typename F> static void for_each_slot(F f) {
  for (auto &slot : g_srp_slots) {
    f(slot);
  }
  f(g_srp_comm);
}

// SRP client コールバック(OT タスクコンテキスト、lock 保持中)。削除完了したサービスの枠を
// 解放し、枠待ちの追加があり得るので matter_task へ再同期を依頼する。
static void srp_client_cb(otError err, const otSrpClientHostInfo *host,
                          const otSrpClientService *services,
                          const otSrpClientService *removed, void *ctx) {
  (void)host;
  (void)services;
  (void)ctx;
  bool resync = false;
  if (err == OT_ERROR_NONE) {
    bool any_blocked = false;
    for_each_slot([&](SrpSvc &slot) {
      if (slot.state == SrpSlot::Active && slot.svc.mState == OT_SRP_CLIENT_ITEM_STATE_REGISTERED &&
          !slot.registered_once) {
        slot.registered_once = true;
        slot.backoff_s = 0;
      }
      any_blocked = any_blocked || slot.state == SrpSlot::Blocked;
    });
    // 保留中の名前は 1 つずつ戻す(切り分け中)ので、成功のたびに次を試させる。
    resync = any_blocked;
  } else {
    ESP_LOGW(TAG, "SRP client update error: %d", (int)err);
    if (err == OT_ERROR_DUPLICATED) {
      // 更新は全サービス一括で、1 つでも名前が重複すると全体が拒否される(既存登録の更新も
      // 止まり、lease 切れで全広告が消える)。ここでは OT の内部を触らず、matter_task 側の
      // 同期で未受理のサービスだけを外す。
      g_srp_dup_pending = true;
      resync = true;
    }
  }
  for (const otSrpClientService *r = removed; r != nullptr; r = r->mNext) {
    for_each_slot([&](SrpSvc &slot) {
      if (&slot.svc == r && slot.state != SrpSlot::Free) {
        ESP_LOGI(TAG, "SRP service removed (server ack): instance=%s", slot.instance);
        slot.state = SrpSlot::Free;
        resync = true;
      }
    });
  }
  if (resync) {
    post_srp_resync();
  }
}

// 重複拒否の後始末(lock 保持中)。サーバに一度も受理されていないサービス(= 重複の犯人候補)を
// OT から外す(ClearService は残りのサービスで即座に更新を送り直させる)。候補が 1 つなら犯人と
// 確定して長めに保留、複数なら短い保留で 1 つずつ戻して切り分ける。
static void srp_handle_duplicated(otInstance *inst, int64_t now) {
  int candidates = 0;
  for_each_slot([&](SrpSvc &slot) {
    if ((slot.state == SrpSlot::Active || slot.state == SrpSlot::Removing) && !slot.registered_once) {
      candidates++;
    }
  });
  if (candidates == 0) {
    ESP_LOGW(TAG, "SRP update rejected as duplicate, but every service was accepted before "
                  "(host name %s conflict?)",
             g_srp_host);
    return;
  }
  for_each_slot([&](SrpSvc &slot) {
    if ((slot.state != SrpSlot::Active && slot.state != SrpSlot::Removing) || slot.registered_once) {
      return;
    }
    otSrpClientClearService(inst, &slot.svc);
    if (slot.state == SrpSlot::Removing) {
      // 削除したかった名前(一度も受理されていない)。サーバ側に残っていないので捨ててよい。
      ESP_LOGW(TAG, "SRP: dropped unregistered service being removed: instance=%s", slot.instance);
      slot.state = SrpSlot::Free;
      return;
    }
    uint32_t wait_s;
    if (candidates == 1) {
      slot.backoff_s = slot.backoff_s == 0 ? kSrpBlockFirstS : slot.backoff_s * 2;
      if (slot.backoff_s > kSrpBlockMaxS) {
        slot.backoff_s = kSrpBlockMaxS;
      }
      wait_s = slot.backoff_s;
    } else {
      wait_s = kSrpBlockProbeS;
    }
    slot.state = SrpSlot::Blocked;
    slot.retry_at_us = now + (int64_t)wait_s * 1000000;
    ESP_LOGW(TAG, "SRP: name rejected as duplicate (%s): instance=%s %s, retry in %u s",
             candidates == 1 ? "identified" : "one of several new names", slot.instance,
             slot.svc.mName, (unsigned)wait_s);
  });
}

// サーバから消す(未送信 / client 停止中は即時クリア)。lock 保持中。
static void srp_remove_slot(otInstance *inst, SrpSvc &slot) {
  if (slot.state == SrpSlot::Blocked) {
    slot.state = SrpSlot::Free; // OT には載っていない。
    ESP_LOGI(TAG, "SRP blocked service dropped: instance=%s", slot.instance);
    return;
  }
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

// 保留中(Blocked)の名前を戻してよいか: 期限切れで、かつ未受理のサービスが他に飛んでいない
// (重複の切り分けは 1 つずつ)。lock 保持中。
static bool srp_may_retry(const SrpSvc &slot, int64_t now) {
  if (slot.state != SrpSlot::Blocked || now < slot.retry_at_us) {
    return false;
  }
  bool in_flight = false;
  for_each_slot([&](SrpSvc &o) {
    in_flight = in_flight || (&o != &slot && o.state == SrpSlot::Active && !o.registered_once);
  });
  return !in_flight;
}

// サービスを OT に載せる(枠の文字列・TXT は呼び出し側で設定済み)。lock 保持中。
static void srp_add_slot(otInstance *inst, SrpSvc &slot, bool fresh) {
  srp_start_locked(inst);
  otError e = otSrpClientAddService(inst, &slot.svc);
  if (e == OT_ERROR_NONE) {
    slot.state = SrpSlot::Active;
    slot.registered_once = false;
    if (fresh) {
      slot.backoff_s = 0;
    }
    ESP_LOGI(TAG, "SRP service added: host=%s instance=%s %s", g_srp_host, slot.instance,
             slot.svc.mName);
  } else {
    ESP_LOGE(TAG, "otSrpClientAddService failed: %d instance=%s", (int)e, slot.instance);
    slot.state = SrpSlot::Free;
  }
}

static void fill_operational_svc(SrpSvc &slot, const char *name) {
  strncpy(slot.instance, name, sizeof(slot.instance) - 1);
  slot.instance[sizeof(slot.instance) - 1] = 0;
  memset(&slot.svc, 0, sizeof(slot.svc));
  slot.svc.mName = "_matter._tcp";
  slot.svc.mInstanceName = slot.instance;
  slot.svc.mPort = 5540;
  slot.svc.mTxtEntries = g_srp_txt;
  slot.svc.mNumTxtEntries = 3;
}

static bool same_comm(const sm_commissionable_t &a, const sm_commissionable_t &b) {
  return a.instance_id == b.instance_id && a.discriminator == b.discriminator &&
         a.vendor_id == b.vendor_id && a.product_id == b.product_id && a.mode == b.mode &&
         a.device_type == b.device_type;
}

static void set_txt(otDnsTxtEntry &t, const char *key, const char *val) {
  t.mKey = key;
  t.mValue = (const uint8_t *)val;
  t.mValueLength = (uint16_t)strlen(val);
}

// commissionable 枠に `c` の内容を組む(Matter Core §4.3.1: サブタイプ _L/_S/_V/_T/_CM、
// TXT D/CM/VP/DT)。
static void fill_commissionable_svc(const sm_commissionable_t &c) {
  g_comm_cur = c;
  SrpSvc &slot = g_srp_comm;
  snprintf(slot.instance, sizeof(slot.instance), "%016llX", (unsigned long long)c.instance_id);
  size_t ns = 0;
  snprintf(g_comm_sub[ns++], sizeof(g_comm_sub[0]), "_L%u", (unsigned)c.discriminator);
  snprintf(g_comm_sub[ns++], sizeof(g_comm_sub[0]), "_S%u", (unsigned)(c.discriminator >> 8));
  snprintf(g_comm_sub[ns++], sizeof(g_comm_sub[0]), "_V%u", (unsigned)c.vendor_id);
  if (c.device_type != 0) {
    snprintf(g_comm_sub[ns++], sizeof(g_comm_sub[0]), "_T%u", (unsigned)c.device_type);
  }
  snprintf(g_comm_sub[ns++], sizeof(g_comm_sub[0]), "_CM");
  for (size_t i = 0; i < ns; i++) {
    g_comm_sub_ptrs[i] = g_comm_sub[i];
  }
  g_comm_sub_ptrs[ns] = nullptr;

  size_t nt = 0;
  snprintf(g_comm_txt_val[0], sizeof(g_comm_txt_val[0]), "%u", (unsigned)c.discriminator);
  set_txt(g_comm_txt[nt++], "D", g_comm_txt_val[0]);
  snprintf(g_comm_txt_val[1], sizeof(g_comm_txt_val[1]), "%u", (unsigned)c.mode);
  set_txt(g_comm_txt[nt++], "CM", g_comm_txt_val[1]);
  snprintf(g_comm_txt_val[2], sizeof(g_comm_txt_val[2]), "%u+%u", (unsigned)c.vendor_id,
           (unsigned)c.product_id);
  set_txt(g_comm_txt[nt++], "VP", g_comm_txt_val[2]);
  if (c.device_type != 0) {
    snprintf(g_comm_txt_val[3], sizeof(g_comm_txt_val[3]), "%u", (unsigned)c.device_type);
    set_txt(g_comm_txt[nt++], "DT", g_comm_txt_val[3]);
  }
  g_comm_txt[nt++] = g_srp_txt[0]; // SII
  g_comm_txt[nt++] = g_srp_txt[1]; // SAI

  memset(&slot.svc, 0, sizeof(slot.svc));
  slot.svc.mName = "_matterc._udp";
  slot.svc.mInstanceName = slot.instance;
  slot.svc.mSubTypeLabels = g_comm_sub_ptrs;
  slot.svc.mPort = 5540;
  slot.svc.mTxtEntries = g_comm_txt;
  slot.svc.mNumTxtEntries = (uint8_t)nt;
}

// commissionable 枠を `want`(窓が閉じていれば nullptr)に合わせる。lock 保持中。
static void sync_commissionable(otInstance *inst, const sm_commissionable_t *want, int64_t now) {
  SrpSvc &slot = g_srp_comm;
  switch (slot.state) {
  case SrpSlot::Removing:
    return; // 削除完了(SrpResync)を待ってから追加し直す。
  case SrpSlot::Active:
    if (want != nullptr && same_comm(*want, g_comm_cur)) {
      return;
    }
    srp_remove_slot(inst, slot); // 窓が閉じた / 内容が変わった(ECM は窓ごとに discriminator が変わる)
    if (slot.state != SrpSlot::Free || want == nullptr) {
      return;
    }
    break;
  case SrpSlot::Blocked:
    if (want == nullptr) {
      srp_remove_slot(inst, slot);
      return;
    }
    if (same_comm(*want, g_comm_cur)) {
      if (srp_may_retry(slot, now)) {
        srp_add_slot(inst, slot, false);
      }
      return;
    }
    slot.state = SrpSlot::Free; // 内容が変わった → 新しい名前で即試す。
    break;
  case SrpSlot::Free:
    break;
  }
  if (want == nullptr) {
    return;
  }
  fill_commissionable_svc(*want);
  srp_add_slot(inst, slot, true);
}

// 最も早い Blocked の再試行時刻にタイマを掛ける(lock 保持中)。
static void arm_srp_retry_timer(int64_t now) {
  int64_t earliest = INT64_MAX;
  for_each_slot([&](SrpSvc &slot) {
    if (slot.state == SrpSlot::Blocked && slot.retry_at_us < earliest) {
      earliest = slot.retry_at_us;
    }
  });
  if (earliest == INT64_MAX) {
    return;
  }
  if (g_srp_retry_timer == nullptr) {
    esp_timer_create_args_t args = {};
    args.callback = srp_retry_timer_cb;
    args.name = "srp_retry";
    if (esp_timer_create(&args, &g_srp_retry_timer) != ESP_OK) {
      return;
    }
  }
  esp_timer_stop(g_srp_retry_timer);
  int64_t wait = earliest - now;
  esp_timer_start_once(g_srp_retry_timer, (uint64_t)(wait > 1000 ? wait : 1000));
}

void sm_ot_srp_sync(const char *const *names, size_t n, const sm_commissionable_t *comm) {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  int64_t now = esp_timer_get_time();

  // (0) 直前の更新が名前重複で拒否されていたら、未受理のサービスを外して残りを通す。
  if (g_srp_dup_pending) {
    g_srp_dup_pending = false;
    srp_handle_duplicated(inst, now);
  }

  // (1) 現 fabric 集合に無い枠を削除する。
  for (auto &slot : g_srp_slots) {
    if (slot.state != SrpSlot::Active && slot.state != SrpSlot::Blocked) {
      continue;
    }
    bool wanted = false;
    for (size_t i = 0; i < n; i++) {
      if (strcmp(slot.instance, names[i]) == 0) {
        wanted = true;
        break;
      }
    }
    if (!wanted) {
      srp_remove_slot(inst, slot);
    }
  }

  // (2) 未登録の名前を追加する(保留中は期限が来たものだけ戻す)。
  for (size_t i = 0; i < n; i++) {
    SrpSvc *mine = nullptr;
    bool removing = false;
    for (auto &slot : g_srp_slots) {
      if (slot.state != SrpSlot::Free && strcmp(slot.instance, names[i]) == 0) {
        if (slot.state == SrpSlot::Removing) {
          removing = true;
        } else {
          mine = &slot;
        }
      }
    }
    if (mine != nullptr) {
      if (srp_may_retry(*mine, now)) {
        srp_add_slot(inst, *mine, false);
      }
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
      // 全枠が使用中。削除完了後の SrpResync で再試行される。
      ESP_LOGW(TAG, "SRP add deferred (no free slot): instance=%s", names[i]);
      continue;
    }
    fill_operational_svc(*free_slot, names[i]);
    srp_add_slot(inst, *free_slot, true);
  }

  // (3) commissionable(窓オープン中のみ、§18.4 D2)。
  sync_commissionable(inst, comm, now);

  arm_srp_retry_timer(now);
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
