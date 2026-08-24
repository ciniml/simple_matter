// NimBLE central 配線(T3、docs/design/p4-thread-controller.md §11.1)。
// controller_hub_cpp/main/ble_central.cpp(F7b、S3 実機検証済み)の移植 +
// P4 host-only(esp_hosted VHCI)の起動シーケンス。

#include "ble_central.hpp"

#if defined(CONFIG_BT_ENABLED)

#include "esp_log.h"
#include "freertos/task.h"

#include "esp_hosted.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "simple_matter.h" // sm_ctrl_match_adv
#include "wifi_sta.hpp"    // sm_wifi_get_status(esp_hosted 初期化の順序合わせ)

#include <cstring>

namespace {

constexpr const char *TAG = "ble_cent";

// Matter GATT: Service 0xFFF6、C1(write)= ...9D11、C2(indicate)= ...9D12。
// BLE_UUID128_INIT はリトルエンディアン(LSB 先頭)。
const ble_uuid16_t s_svc_uuid = BLE_UUID16_INIT(0xFFF6);
const ble_uuid128_t s_c1_uuid = BLE_UUID128_INIT(0x11, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95,
                                                 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);
const ble_uuid128_t s_c2_uuid = BLE_UUID128_INIT(0x12, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95,
                                                 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);

QueueHandle_t s_queue = nullptr;
volatile uint8_t s_state = SM_BLE_HOST_OFF;
uint8_t s_own_addr_type = 0;
uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
uint16_t s_c1_val_handle = 0;
uint16_t s_c2_val_handle = 0;
uint16_t s_svc_start = 0, s_svc_end = 0;
uint16_t s_want_disc = 0;    // 照合対象 discriminator(0 = スキャンしない)
int32_t s_scan_ms = 0;       // スキャン継続時間(ble_gap_disc の duration)
uint16_t s_att_mtu = 0;
bool s_scanning = false;

void push(BleCentralEvent kind, uint16_t mtu, const uint8_t *frag, uint16_t len) {
  if (s_queue == nullptr) {
    return;
  }
  BleCentralMsg m{};
  m.kind = kind;
  m.mtu = mtu;
  if (frag != nullptr && len != 0) {
    if (len > sizeof(m.frag)) {
      len = sizeof(m.frag);
    }
    memcpy(m.frag, frag, len);
    m.frag_len = len;
  }
  xQueueSend(s_queue, &m, 0);
}

int gap_event(struct ble_gap_event *event, void *arg);

void start_scan() {
  if (s_want_disc == 0) {
    return;
  }
  struct ble_gap_disc_params dp = {};
  dp.passive = 0;
  dp.itvl = 0;
  dp.window = 0;
  dp.filter_policy = 0;
  dp.limited = 0;
  int rc = ble_gap_disc(s_own_addr_type, s_scan_ms, &dp, gap_event, nullptr);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
    s_scanning = false;
  } else {
    s_scanning = true;
    ESP_LOGI(TAG, "scanning for 0xFFF6 commissionable (discriminator=%u)", s_want_disc);
  }
}

// 広告フィールドから 0xFFF6 service data payload(8B)を取り出して照合する。
bool adv_matches(const uint8_t *data, uint8_t len) {
  struct ble_hs_adv_fields fields;
  if (ble_hs_adv_parse_fields(&fields, data, len) != 0) {
    return false;
  }
  if (fields.svc_data_uuid16 == nullptr || fields.svc_data_uuid16_len < 3) {
    return false;
  }
  // svc_data_uuid16 = [uuid_lo, uuid_hi, payload...]。UUID 0xFFF6。
  const uint8_t *p = fields.svc_data_uuid16;
  if (!(p[0] == 0xF6 && p[1] == 0xFF)) {
    return false;
  }
  const uint8_t *payload = p + 2;
  uint8_t plen = (uint8_t)(fields.svc_data_uuid16_len - 2);
  if (plen < 8) {
    return false;
  }
  return sm_ctrl_match_adv(payload, 8, s_want_disc);
}

// ---- GATT 発見チェーン: svc(0xFFF6)→ C1/C2 → C2 CCCD subscribe ----

int on_cccd_write(uint16_t conn, const struct ble_gatt_error *err, struct ble_gatt_attr *attr,
                  void *arg) {
  (void)conn;
  (void)attr;
  (void)arg;
  if (err->status == 0) {
    ESP_LOGI(TAG, "C2 subscribed");
    push(BleCentralEvent::Subscribed, 0, nullptr, 0);
  } else {
    ESP_LOGE(TAG, "CCCD write failed status=%d", err->status);
  }
  return 0;
}

int on_dsc_disc(uint16_t conn, const struct ble_gatt_error *err, uint16_t chr_val,
                const struct ble_gatt_dsc *dsc, void *arg) {
  (void)chr_val;
  (void)arg;
  if (err->status == 0 && dsc != nullptr) {
    // CCCD = 0x2902。indication 有効化(0x0002)を書く。
    if (ble_uuid_u16(&dsc->uuid.u) == 0x2902) {
      static const uint8_t val[2] = {0x02, 0x00};
      ble_gattc_write_flat(conn, dsc->handle, val, sizeof(val), on_cccd_write, nullptr);
    }
  }
  return 0;
}

int on_c2_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_chr *chr,
               void *arg) {
  (void)arg;
  if (err->status == 0 && chr != nullptr) {
    s_c2_val_handle = chr->val_handle;
  } else if (err->status == BLE_HS_EDONE) {
    if (s_c2_val_handle != 0) {
      ble_gattc_disc_all_dscs(conn, s_c2_val_handle, s_svc_end, on_dsc_disc, nullptr);
    } else {
      ESP_LOGE(TAG, "C2 characteristic not found");
    }
  }
  return 0;
}

int on_c1_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_chr *chr,
               void *arg) {
  (void)arg;
  if (err->status == 0 && chr != nullptr) {
    s_c1_val_handle = chr->val_handle;
  } else if (err->status == BLE_HS_EDONE) {
    ble_gattc_disc_chrs_by_uuid(conn, s_svc_start, s_svc_end, &s_c2_uuid.u, on_c2_disc, nullptr);
  }
  return 0;
}

int on_svc_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_svc *svc,
                void *arg) {
  (void)arg;
  if (err->status == 0 && svc != nullptr) {
    s_svc_start = svc->start_handle;
    s_svc_end = svc->end_handle;
  } else if (err->status == BLE_HS_EDONE) {
    if (s_svc_start != 0) {
      ble_gattc_disc_chrs_by_uuid(conn, s_svc_start, s_svc_end, &s_c1_uuid.u, on_c1_disc, nullptr);
    } else {
      ESP_LOGE(TAG, "0xFFF6 service not found");
    }
  }
  return 0;
}

int gap_event(struct ble_gap_event *event, void *arg) {
  (void)arg;
  switch (event->type) {
  case BLE_GAP_EVENT_DISC: {
    if (adv_matches(event->disc.data, event->disc.length_data)) {
      ESP_LOGI(TAG, "matched device; connecting");
      ble_gap_disc_cancel();
      s_scanning = false;
      ble_gap_connect(s_own_addr_type, &event->disc.addr, 30000, nullptr, gap_event, nullptr);
    }
    return 0;
  }
  case BLE_GAP_EVENT_DISC_COMPLETE: {
    // duration 満了。まだ接続していなければ pump に「見つからなかった」と伝える。
    s_scanning = false;
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) {
      ESP_LOGW(TAG, "scan finished without a matching advertisement");
      push(BleCentralEvent::ScanTimeout, 0, nullptr, 0);
    }
    return 0;
  }
  case BLE_GAP_EVENT_CONNECT: {
    if (event->connect.status == 0) {
      s_conn_handle = event->connect.conn_handle;
      ESP_LOGI(TAG, "connected; exchanging MTU");
      ble_gattc_exchange_mtu(s_conn_handle, nullptr, nullptr);
    } else {
      ESP_LOGE(TAG, "connect failed status=%d; rescan", event->connect.status);
      start_scan();
    }
    return 0;
  }
  case BLE_GAP_EVENT_MTU: {
    s_att_mtu = event->mtu.value;
    ESP_LOGI(TAG, "MTU=%u; discovering GATT", s_att_mtu);
    // ピアの BT MAC を Connected に載せる(NimBLE の addr.val は LSB first →
    // 印字順に反転して詰める)。ctrl_pump の EUI-64 フォールバック用。
    {
      BleCentralMsg m{};
      m.kind = BleCentralEvent::Connected;
      m.mtu = s_att_mtu;
      struct ble_gap_conn_desc desc;
      if (ble_gap_conn_find(s_conn_handle, &desc) == 0 &&
          desc.peer_id_addr.type == BLE_ADDR_PUBLIC) {
        for (int i = 0; i < 6; ++i) {
          m.peer_mac[i] = desc.peer_id_addr.val[5 - i];
        }
        m.peer_mac_valid = 1;
        ESP_LOGI(TAG, "peer BT MAC %02x:%02x:%02x:%02x:%02x:%02x", m.peer_mac[0], m.peer_mac[1],
                 m.peer_mac[2], m.peer_mac[3], m.peer_mac[4], m.peer_mac[5]);
      }
      if (s_queue != nullptr) {
        xQueueSend(s_queue, &m, 0);
      }
    }
    ble_gattc_disc_svc_by_uuid(s_conn_handle, &s_svc_uuid.u, on_svc_disc, nullptr);
    return 0;
  }
  case BLE_GAP_EVENT_DISCONNECT: {
    ESP_LOGI(TAG, "disconnected reason=%d", event->disconnect.reason);
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    s_c1_val_handle = 0;
    s_c2_val_handle = 0;
    push(BleCentralEvent::Disconnected, 0, nullptr, 0);
    return 0;
  }
  case BLE_GAP_EVENT_NOTIFY_RX: {
    // C2 indication(is_indication=1)。BTP フラグメントを pump タスクへ。
    uint16_t om_len = OS_MBUF_PKTLEN(event->notify_rx.om);
    uint8_t buf[256];
    uint16_t copied = om_len > sizeof(buf) ? (uint16_t)sizeof(buf) : om_len;
    ble_hs_mbuf_to_flat(event->notify_rx.om, buf, copied, &copied);
    push(BleCentralEvent::Indication, 0, buf, copied);
    return 0;
  }
  default:
    return 0;
  }
}

void on_sync() {
  ble_hs_util_ensure_addr(0);
  ble_hs_id_infer_auto(0, &s_own_addr_type);
  s_state = SM_BLE_HOST_READY;
  ESP_LOGI(TAG, "nimble host synced (own addr type %u)", s_own_addr_type);
  if (s_want_disc != 0) {
    start_scan();
  }
}

void on_reset(int reason) { ESP_LOGW(TAG, "nimble reset reason=%d", reason); }

void host_task(void *) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

// esp_hosted(SDIO/RPC)+ C6 の BT controller + NimBLE ホストを起こす。
//
// **順序の要点**: esp_hosted_init() は WiFi(esp_wifi_init → esp_wifi_remote →
// esp_hosted_init)と同じ関数を呼ぶが、二重呼びガード(esp_hosted_init_done)は
// 排他されていない。よって WiFi が有効なときは wifi_up タスクが esp_wifi_init を
// 終えて落ち着くのを待ってから呼ぶ(状態が CONNECTING でなくなる = 接続成功か失敗の確定)。
void ble_up_task(void *) {
  sm_wifi_status_t w = {};
  sm_wifi_get_status(&w);
  if (w.state != SM_WIFI_OFF) {
    // WiFi 有効: esp_wifi_init が済んでいることを状態遷移で待つ(最大 30 秒)。
    for (int i = 0; i < 300; ++i) {
      sm_wifi_get_status(&w);
      if (w.state == SM_WIFI_CONNECTED || w.state == SM_WIFI_FAILED) {
        break;
      }
      vTaskDelay(pdMS_TO_TICKS(100));
    }
    ESP_LOGI(TAG, "wifi settled (state=%u); bringing up hosted BT", (unsigned)w.state);
  } else {
    ESP_LOGI(TAG, "wifi disabled; this task owns esp_hosted_init()");
  }

  // esp_hosted_init() は初期化済みなら即 ESP_OK(WiFi 経路が既に呼んでいる)。
  if (esp_hosted_init() != ESP_OK) {
    ESP_LOGE(TAG, "esp_hosted_init() failed (SDIO link / C6 firmware?)");
    s_state = SM_BLE_HOST_FAILED;
    vTaskDelete(nullptr);
    return;
  }
  if (esp_hosted_connect_to_slave() != ESP_OK) {
    ESP_LOGE(TAG, "esp_hosted_connect_to_slave() failed");
    s_state = SM_BLE_HOST_FAILED;
    vTaskDelete(nullptr);
    return;
  }
  // FeatureControl RPC で C6 側 BT controller を起動する。**失敗しても致命にしない**:
  // 同梱例(host_nimble_bleprph_host_only_vhci)も警告どまりで nimble_port_init へ進む。
  // slave FW によっては BT が起動時から生きていて RPC 側だけ応答しない(実機 2.12.7 で
  // Req_FeatureControl タイムアウトを観測)。真の判定は HCI reset(nimble sync)の成否。
  esp_err_t bt_rc = esp_hosted_bt_controller_init();
  if (bt_rc != ESP_OK) {
    ESP_LOGW(TAG, "bt_controller_init rc=%d; retrying once", (int)bt_rc);
    vTaskDelay(pdMS_TO_TICKS(1000));
    bt_rc = esp_hosted_bt_controller_init();
  }
  esp_err_t bt_en = esp_hosted_bt_controller_enable();
  if (bt_rc != ESP_OK || bt_en != ESP_OK) {
    ESP_LOGW(TAG, "C6 BT controller init/enable rc=%d/%d -- continuing; nimble sync will tell "
                  "whether the slave firmware has BT",
             (int)bt_rc, (int)bt_en);
  }
  if (nimble_port_init() != ESP_OK) {
    ESP_LOGE(TAG, "nimble_port_init() failed");
    s_state = SM_BLE_HOST_FAILED;
    vTaskDelete(nullptr);
    return;
  }
  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;
  // central-only: GAP/GATT サービス(peripheral 用)は登録しない。
  nimble_port_freertos_init(host_task);
  ESP_LOGI(TAG, "nimble host started (host-only over esp_hosted VHCI)");
  vTaskDelete(nullptr);
}

} // namespace

void sm_ble_central_boot() {
  if (s_state != SM_BLE_HOST_OFF) {
    return;
  }
  s_state = SM_BLE_HOST_STARTING;
  s_queue = xQueueCreate(12, sizeof(BleCentralMsg));
  if (s_queue == nullptr) {
    ESP_LOGE(TAG, "failed to create the BLE event queue");
    s_state = SM_BLE_HOST_FAILED;
    return;
  }
  // スタックは esp_hosted の RPC(protobuf-c)+ nimble_port_init 込みで 5KB。
  if (xTaskCreate(&ble_up_task, "ble_up", 5120, nullptr, 4, nullptr) != pdPASS) {
    ESP_LOGE(TAG, "failed to create the BLE bringup task");
    s_state = SM_BLE_HOST_FAILED;
  }
}

uint8_t sm_ble_central_state() { return s_state; }

QueueHandle_t sm_ble_central_queue() { return s_queue; }

bool sm_ble_central_start(uint16_t discriminator, uint32_t scan_ms) {
  if (s_state != SM_BLE_HOST_READY) {
    return false;
  }
  s_c1_val_handle = 0;
  s_c2_val_handle = 0;
  s_svc_start = s_svc_end = 0;
  s_att_mtu = 0;
  s_want_disc = discriminator;
  s_scan_ms = (int32_t)scan_ms;
  start_scan();
  return s_scanning;
}

void sm_ble_central_stop() {
  s_want_disc = 0;
  if (s_scanning) {
    ble_gap_disc_cancel();
    s_scanning = false;
  }
  s_c1_val_handle = 0;
  s_c2_val_handle = 0;
  s_svc_start = s_svc_end = 0;
}

bool sm_ble_central_write_c1(const uint8_t *frag, size_t len) {
  if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || s_c1_val_handle == 0) {
    return false;
  }
  return ble_gattc_write_no_rsp_flat(s_conn_handle, s_c1_val_handle, frag, (uint16_t)len) == 0;
}

void sm_ble_central_disconnect() {
  if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
    ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
  }
}

#else // !CONFIG_BT_ENABLED

void sm_ble_central_boot() {}
uint8_t sm_ble_central_state() { return SM_BLE_HOST_OFF; }
QueueHandle_t sm_ble_central_queue() { return nullptr; }
bool sm_ble_central_start(uint16_t, uint32_t) { return false; }
void sm_ble_central_stop() {}
bool sm_ble_central_write_c1(const uint8_t *, size_t) { return false; }
void sm_ble_central_disconnect() {}

#endif
