// NimBLE central 配線(F7b、docs/design/c-ffi-shim.md §11.4)。onoff_light_cpp の
// ble.cpp(peripheral)の鏡像。CONFIG_SM_HUB_BLE_PAIR のときのみビルドされる。

#include "ble_central.hpp"

#if defined(CONFIG_SM_HUB_BLE_PAIR) && defined(CONFIG_BT_ENABLED)

#include "esp_log.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"

#include "simple_matter.h" // sm_ctrl_match_adv

#include <cstring>

namespace {

constexpr const char *TAG = "ble_cent";

// Matter GATT: Service 0xFFF6、C1(write)= ...9D11、C2(indicate)= ...9D12。
// BLE_UUID128_INIT はリトルエンディアン(LSB 先頭)。
const ble_uuid16_t s_svc_uuid = BLE_UUID16_INIT(0xFFF6);
const ble_uuid128_t s_c1_uuid = BLE_UUID128_INIT(
    0x11, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95, 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);
const ble_uuid128_t s_c2_uuid = BLE_UUID128_INIT(
    0x12, 0x9d, 0x9f, 0x42, 0x9c, 0x4f, 0x9f, 0x95, 0x59, 0x45, 0x3d, 0x26, 0xf5, 0x2e, 0xee, 0x18);

QueueHandle_t s_queue = nullptr;
uint8_t s_own_addr_type = 0;
uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
uint16_t s_c1_val_handle = 0;
uint16_t s_c2_val_handle = 0;
uint16_t s_svc_start = 0, s_svc_end = 0;
uint16_t s_want_disc = 0; // 照合対象 discriminator
uint16_t s_att_mtu = 0;
bool s_synced = false;

void push(BleCentralEvent kind, uint16_t mtu, const uint8_t *frag, uint16_t len) {
  if (!s_queue) return;
  BleCentralMsg m{};
  m.kind = kind;
  m.mtu = mtu;
  if (frag && len) {
    if (len > sizeof(m.frag)) len = sizeof(m.frag);
    memcpy(m.frag, frag, len);
    m.frag_len = len;
  }
  xQueueSend(s_queue, &m, 0);
}

int gap_event(struct ble_gap_event *event, void *arg);

void start_scan() {
  struct ble_gap_disc_params dp = {};
  dp.passive = 0;
  dp.itvl = 0;
  dp.window = 0;
  dp.filter_policy = 0;
  dp.limited = 0;
  int rc = ble_gap_disc(s_own_addr_type, BLE_HS_FOREVER, &dp, gap_event, nullptr);
  if (rc != 0) {
    ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
  } else {
    ESP_LOGI(TAG, "scanning for 0xFFF6 commissionable (discriminator=%u)", s_want_disc);
  }
}

// 広告フィールドから 0xFFF6 service data payload(8B)を取り出して照合する。
bool adv_matches(const uint8_t *data, uint8_t len) {
  struct ble_hs_adv_fields fields;
  if (ble_hs_adv_parse_fields(&fields, data, len) != 0) return false;
  if (fields.svc_data_uuid16 == nullptr || fields.svc_data_uuid16_len < 3) return false;
  // svc_data_uuid16 = [uuid_lo, uuid_hi, payload...]。UUID 0xFFF6。
  const uint8_t *p = fields.svc_data_uuid16;
  if (!(p[0] == 0xF6 && p[1] == 0xFF)) return false;
  const uint8_t *payload = p + 2;
  uint8_t plen = fields.svc_data_uuid16_len - 2;
  if (plen < 8) return false;
  return sm_ctrl_match_adv(payload, 8, s_want_disc);
}

// ---- GATT 発見チェーン: svc(0xFFF6)→ C1/C2 → C2 CCCD subscribe ----

int on_cccd_write(uint16_t conn, const struct ble_gatt_error *err, struct ble_gatt_attr *attr, void *arg) {
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

int on_c2_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_chr *chr, void *arg) {
  (void)arg;
  if (err->status == 0 && chr != nullptr) {
    s_c2_val_handle = chr->val_handle;
  } else if (err->status == BLE_HS_EDONE) {
    if (s_c2_val_handle != 0) {
      // C2 の CCCD を探して subscribe する。
      ble_gattc_disc_all_dscs(conn, s_c2_val_handle, s_svc_end, on_dsc_disc, nullptr);
    } else {
      ESP_LOGE(TAG, "C2 characteristic not found");
    }
  }
  return 0;
}

int on_c1_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_chr *chr, void *arg) {
  (void)arg;
  if (err->status == 0 && chr != nullptr) {
    s_c1_val_handle = chr->val_handle;
  } else if (err->status == BLE_HS_EDONE) {
    // C2 を発見する。
    ble_gattc_disc_chrs_by_uuid(conn, s_svc_start, s_svc_end, &s_c2_uuid.u, on_c2_disc, nullptr);
  }
  return 0;
}

int on_svc_disc(uint16_t conn, const struct ble_gatt_error *err, const struct ble_gatt_svc *svc, void *arg) {
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
      ble_gap_connect(s_own_addr_type, &event->disc.addr, 30000, nullptr, gap_event, nullptr);
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
    push(BleCentralEvent::Connected, s_att_mtu, nullptr, 0);
    ble_gattc_disc_svc_by_uuid(s_conn_handle, &s_svc_uuid.u, on_svc_disc, nullptr);
    return 0;
  }
  case BLE_GAP_EVENT_DISCONNECT: {
    ESP_LOGI(TAG, "disconnected reason=%d", event->disconnect.reason);
    s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
    push(BleCentralEvent::Disconnected, 0, nullptr, 0);
    return 0;
  }
  case BLE_GAP_EVENT_NOTIFY_RX: {
    // C2 indication(is_indication=1)。BTP フラグメントを matter タスクへ。
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
  s_synced = true;
  if (s_want_disc != 0) start_scan();
}

void on_reset(int reason) { ESP_LOGW(TAG, "nimble reset reason=%d", reason); }

void host_task(void *) {
  nimble_port_run();
  nimble_port_freertos_deinit();
}

} // namespace

void sm_ble_central_init(QueueHandle_t q) {
  s_queue = q;
  ESP_ERROR_CHECK(nimble_port_init());
  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.reset_cb = on_reset;
  // central-only: GAP サービス(peripheral 用)は登録不要。
  nimble_port_freertos_init(host_task);
}

void sm_ble_central_start(uint16_t discriminator) {
  s_want_disc = discriminator;
  if (s_synced) start_scan();
}

bool sm_ble_central_write_c1(const uint8_t *frag, size_t len) {
  if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || s_c1_val_handle == 0) return false;
  return ble_gattc_write_no_rsp_flat(s_conn_handle, s_c1_val_handle, frag, len) == 0;
}

void sm_ble_central_disconnect() {
  if (s_conn_handle != BLE_HS_CONN_HANDLE_NONE) {
    ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
  }
}

#else // !CONFIG_SM_HUB_BLE_PAIR

void sm_ble_central_init(QueueHandle_t) {}
void sm_ble_central_start(uint16_t) {}
bool sm_ble_central_write_c1(const uint8_t *, size_t) { return false; }
void sm_ble_central_disconnect() {}

#endif
