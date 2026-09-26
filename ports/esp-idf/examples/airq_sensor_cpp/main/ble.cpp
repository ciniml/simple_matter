// NimBLE 配線の実装(docs/design/c-ffi-shim.md §9.3)。
// CONFIG_SM_ENABLE_BLE のときのみ NimBLE を組み込む。無効ビルド(例: ESP32-S3)では
// 空実装で、main.cpp 側も #if で呼び出さないためリンクされない。

#include "ble.hpp"

#include "sdkconfig.h"

#if CONFIG_SM_ENABLE_BLE

#include <cstring>

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char *TAG = "sm_ble";

// ---- GATT UUID(コア crates/simple-matter/src/btp/gatt.rs と一致) ----------
//
// Service = 0xFFF6(16bit)。C1(write)= 18EE2EF5-263D-4559-959F-4F9C429F9D11、
// C2(indicate)= ...9D12。NimBLE の BLE_UUID128_INIT はリトルエンディアン(LSB 先頭)
// でバイトを取るため、上記 big-endian 表記を反転して並べる。
static const ble_uuid16_t s_svc_uuid = BLE_UUID16_INIT(0xFFF6);
static const ble_uuid128_t s_c1_uuid = BLE_UUID128_INIT(
    0x11, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95, 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);
static const ble_uuid128_t s_c2_uuid = BLE_UUID128_INIT(
    0x12, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95, 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);

// ---- 状態(NimBLE host タスク / matter_task から触る。単純な atomic 相当で足りる) --
static QueueHandle_t s_queue = nullptr;
static uint8_t s_own_addr_type = 0;
static uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
static uint16_t s_c2_val_handle = 0;
static bool s_synced = false;
static bool s_connected_sent = false; // 当該接続で SM_BLE_CONNECTED を送ったか
static SemaphoreHandle_t s_ind_sem = nullptr;
static uint8_t s_adv[31];
static uint8_t s_adv_len = 0;

static void start_advertising();

// ---- GATT アクセスコールバック(C1 write を Cmd に載せる) -------------------

static int gatt_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg) {
  (void)attr_handle;
  (void)arg;
  if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
    // C1 write の前に SM_BLE_CONNECTED を確実に先行させる(MTU 交換を挟まない central 対策)。
    if (!s_connected_sent) {
      Cmd cc{};
      cc.kind = CmdKind::BleConnected;
      cc.mtu = 0; // 不明 = BTP は central 提示 MTU から算出
      if (s_queue) {
        xQueueSend(s_queue, &cc, 0);
      }
      s_connected_sent = true;
    }
    Cmd c{};
    c.kind = CmdKind::BleC1Write;
    uint16_t om_len = OS_MBUF_PKTLEN(ctxt->om);
    uint16_t copied = om_len > sizeof(c.frag) ? (uint16_t)sizeof(c.frag) : om_len;
    ble_hs_mbuf_to_flat(ctxt->om, c.frag, copied, &copied);
    c.frag_len = copied;
    if (s_queue) {
      if (xQueueSend(s_queue, &c, 0) != pdTRUE) ESP_LOGW(TAG, "C1 queue FULL, dropped");
    }
    (void)conn_handle;
    return 0;
  }
  return BLE_ATT_ERR_UNLIKELY;
}

// ---- GATT サービス定義(0xFFF6: C1 write / C2 indicate) ---------------------

static const struct ble_gatt_chr_def s_chrs[] = {
    {
        .uuid = &s_c1_uuid.u,
        .access_cb = gatt_access_cb,
        .arg = nullptr,
        .descriptors = nullptr,
        .flags = BLE_GATT_CHR_F_WRITE, // Matter C1 は Write(応答あり)。WRITE_NO_RSP を出すと iPhone が
                                          // 応答なし書き込みを連投し、NimBLE の mbuf 枯渇で BTP セグメントが落ちる
                                          // (Apple の CSR 後沈黙→切断、2026-08-30)。
        .min_key_size = 0,
        .val_handle = nullptr,
    },
    {
        .uuid = &s_c2_uuid.u,
        .access_cb = gatt_access_cb,
        .arg = nullptr,
        .descriptors = nullptr,
        .flags = BLE_GATT_CHR_F_INDICATE,
        .min_key_size = 0,
        .val_handle = &s_c2_val_handle,
    },
    {0},
};

static const struct ble_gatt_svc_def s_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_svc_uuid.u,
        .includes = nullptr,
        .characteristics = s_chrs,
    },
    {0},
};

// ---- GAP イベント -----------------------------------------------------------

static int gap_event_cb(struct ble_gap_event *event, void *arg) {
  (void)arg;
  switch (event->type) {
  case BLE_GAP_EVENT_CONNECT: {
    // NimBLE(peripheral)は LE Read Remote Features の結果を status に載せて CONNECT を通知する。
    // BT 4.0 の central(slave-initiated feature exchange 非対応)では status=0x21a
    // (Unsupported Remote Feature)になるがリンク自体は確立している。status ではなく
    // 接続の実在で判定しないと、conn_handle 未登録 → C2 indication 全滅 → BTP handshake 不成立になる。
    struct ble_gap_conn_desc desc;
    bool alive = event->connect.conn_handle != BLE_HS_CONN_HANDLE_NONE &&
                 ble_gap_conn_find(event->connect.conn_handle, &desc) == 0;
    if (alive) {
      s_conn_handle = event->connect.conn_handle;
      s_connected_sent = false;
      if (event->connect.status != 0) {
        ESP_LOGW(TAG, "connected conn=%d (feature read status=0x%x, ignored)", s_conn_handle,
                 event->connect.status);
      } else {
        ESP_LOGI(TAG, "connected conn=%d", s_conn_handle);
      }
    } else {
      // 接続失敗: 広告を再開する。
      ESP_LOGW(TAG, "connect failed status=0x%x, re-advertising", event->connect.status);
      start_advertising();
    }
    return 0;
  }

  case BLE_GAP_EVENT_DISCONNECT: {
    ESP_LOGI(TAG, "disconnected reason=%d", event->disconnect.reason);
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_connected_sent = false;
    Cmd c{};
    c.kind = CmdKind::BleDisconnected;
    if (s_queue) {
      xQueueSend(s_queue, &c, 0);
    }
    // まだ commissionable(広告データ有り)なら再開。
    start_advertising();
    return 0;
  }

  case BLE_GAP_EVENT_MTU:
    ESP_LOGI(TAG, "mtu=%d", event->mtu.value);
    if (!s_connected_sent) {
      Cmd c{};
      c.kind = CmdKind::BleConnected;
      c.mtu = event->mtu.value;
      if (s_queue) {
        xQueueSend(s_queue, &c, 0);
      }
      s_connected_sent = true;
    }
    return 0;

  case BLE_GAP_EVENT_SUBSCRIBE:
    if (event->subscribe.attr_handle == s_c2_val_handle && event->subscribe.cur_indicate) {
      Cmd c{};
      c.kind = CmdKind::BleC2Subscribed;
      if (s_queue) {
        xQueueSend(s_queue, &c, 0);
      }
    }
    return 0;

  case BLE_GAP_EVENT_NOTIFY_TX:
    // indication の確認(EDONE)で 1 フラグメントの送出完了 → 次を直列送出可能にする。
    if (event->notify_tx.attr_handle == s_c2_val_handle &&
        event->notify_tx.status == BLE_HS_EDONE) {
      if (s_ind_sem) {
        xSemaphoreGive(s_ind_sem);
      }
    }
    return 0;

  default:
    return 0;
  }
}

// ---- 広告 -------------------------------------------------------------------

static void start_advertising() {
  if (!s_synced || s_adv_len == 0 || s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
    return; // 未同期 / 広告停止中 / 接続中は広告しない。
  }
  ble_gap_adv_stop();
  int rc = ble_gap_adv_set_data(s_adv, s_adv_len);
  if (rc != 0) {
    ESP_LOGW(TAG, "adv_set_data rc=%d", rc);
    return;
  }
  struct ble_gap_adv_params advp;
  memset(&advp, 0, sizeof(advp));
  advp.conn_mode = BLE_GAP_CONN_MODE_UND;
  advp.disc_mode = BLE_GAP_DISC_MODE_GEN;
  rc = ble_gap_adv_start(s_own_addr_type, nullptr, BLE_HS_FOREVER, &advp, gap_event_cb, nullptr);
  if (rc != 0) {
    ESP_LOGW(TAG, "adv_start rc=%d", rc);
  }
}

// ---- host 同期 / タスク -----------------------------------------------------

static void on_sync() {
  ble_hs_id_infer_auto(0, &s_own_addr_type);
  s_synced = true;
  ESP_LOGI(TAG, "host synced (addr_type=%d)", s_own_addr_type);
  start_advertising();
}

static void on_reset(int reason) { ESP_LOGW(TAG, "host reset reason=%d", reason); }

static void host_task(void *param) {
  (void)param;
  nimble_port_run();
  nimble_port_freertos_deinit();
}

// ---- 公開 API ---------------------------------------------------------------

void sm_ble_init(QueueHandle_t q) {
  s_queue = q;
  s_ind_sem = xSemaphoreCreateBinary();

  esp_err_t err = nimble_port_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "nimble_port_init failed: %d", err);
    return;
  }

  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;

  ble_svc_gap_init();
  ble_svc_gatt_init();

  int rc = ble_gatts_count_cfg(s_svcs);
  if (rc != 0) {
    ESP_LOGE(TAG, "gatts_count_cfg rc=%d", rc);
    return;
  }
  rc = ble_gatts_add_svcs(s_svcs);
  if (rc != 0) {
    ESP_LOGE(TAG, "gatts_add_svcs rc=%d", rc);
    return;
  }
  ble_svc_gap_device_name_set("SM-OnOff");
  ble_att_set_preferred_mtu(247);

  nimble_port_freertos_init(host_task);
  ESP_LOGI(TAG, "NimBLE started");
}

void sm_ble_stop() {
  // コミッショニング完了後に BLE/BT を完全停止して無線を WiFi に明け渡す。
  // WiFi/BT SW coex が有効なままだと、再送のないマルチキャスト(mDNS)が coex
  // ギャップで両方向とも落ちる。BT コントローラを止めることでこれを解消する。
  if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
    ble_gap_terminate(s_conn_handle, 0x13);
  }
  ble_gap_adv_stop();
  int rc = nimble_port_stop();
  ESP_LOGI(TAG, "NimBLE stopping rc=%d", rc);
  if (rc == 0) {
    nimble_port_deinit();
    ESP_LOGI(TAG, "NimBLE + BT controller deinitialized (radio freed for WiFi)");
  }
}

void sm_ble_set_adv(const uint8_t *adv, size_t len) {
  if (len > sizeof(s_adv)) {
    len = sizeof(s_adv);
  }
  if (len > 0) {
    memcpy(s_adv, adv, len);
  }
  s_adv_len = (uint8_t)len;
  if (len == 0) {
    ble_gap_adv_stop();
    return;
  }
  start_advertising();
}

bool sm_ble_indicate(const uint8_t *frag, size_t len) {
  uint16_t conn = s_conn_handle;
  if (conn == BLE_HS_CONN_HANDLE_NONE) {
    return false;
  }
  struct os_mbuf *om = ble_hs_mbuf_from_flat(frag, (uint16_t)len);
  if (!om) {
    return false;
  }
  // 前回の残り(万一の取りこぼし)を掃除してから送る。
  if (s_ind_sem) {
    xSemaphoreTake(s_ind_sem, 0);
  }
  int rc = ble_gatts_indicate_custom(conn, s_c2_val_handle, om);
  if (rc != 0) {
    // 失敗時は NimBLE が om を解放済み。
    ESP_LOGW(TAG, "indicate_custom rc=%d (len=%u)", rc, (unsigned)len);
    return false;
  }
  // 確認(EDONE)まで待つ。リンク断で来なければタイムアウト。
  if (!s_ind_sem || xSemaphoreTake(s_ind_sem, pdMS_TO_TICKS(2000)) != pdTRUE) {
    ESP_LOGW(TAG, "indicate EDONE timeout (len=%u)", (unsigned)len);
    return false;
  }
  return true;
}

#else // !CONFIG_SM_ENABLE_BLE

// BLE 無効ビルド(S3 等)。main.cpp は #if で呼ばないため、これらは参照されない。

#endif // CONFIG_SM_ENABLE_BLE
