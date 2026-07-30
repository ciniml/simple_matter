// OT ホスト配線の実体(ESP32-P4 + ESP32-H2 RCP over UART)。
// docs/design/p4-thread-controller.md §3 F8c。
//
// onoff_light_cpp/main/ot_thread.cpp(F6、C6 の native radio + SRP クライアント)を
// 土台に、P4 = radio 無しのホスト MCU 向けへ改めたもの。差分:
//   - radio_mode = RADIO_MODE_UART_RCP(H2 の ot_rcp と spinel over UART)
//   - SRP は「クライアント」ではなく「サーバ」(このハブがネットワーク主宰)
//   - dataset を復元/生成して自分が leader になる

#include "ot_hub.hpp"

#include "sdkconfig.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_types.h"
#include "esp_openthread.h"
#include "esp_openthread_lock.h"
#include "esp_openthread_netif_glue.h"
#include "esp_openthread_types.h"
#include "esp_vfs_eventfd.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "openthread/dataset.h"
#include "openthread/dataset_ftd.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/srp_server.h"
#include "openthread/thread.h"

#if CONFIG_SM_THREAD_BR
// F8e(ベストエフォート): backbone netif を用意して border routing を有効化する。
#include "esp_openthread_border_router.h"
#endif

namespace {

constexpr const char *TAG = "ot_hub";

esp_netif_t *g_ot_netif = nullptr;
volatile bool g_ot_ready = false;

// OT スタックタスク(esp_openthread_launch_mainloop でブロックする)。
void ot_task(void *) {
  esp_openthread_platform_config_t config = {};
  // --- radio: H2 の ot_rcp と spinel over UART(P4 は 802.15.4 radio 非搭載)---
  config.radio_config.radio_mode = RADIO_MODE_UART_RCP;
  config.radio_config.radio_uart_config.port = (uart_port_t)CONFIG_SM_OT_UART_PORT;
  config.radio_config.radio_uart_config.uart_config.baud_rate = CONFIG_SM_OT_UART_BAUD;
  config.radio_config.radio_uart_config.uart_config.data_bits = UART_DATA_8_BITS;
  config.radio_config.radio_uart_config.uart_config.parity = UART_PARITY_DISABLE;
  config.radio_config.radio_uart_config.uart_config.stop_bits = UART_STOP_BITS_1;
  config.radio_config.radio_uart_config.uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
  config.radio_config.radio_uart_config.uart_config.rx_flow_ctrl_thresh = 0;
  config.radio_config.radio_uart_config.uart_config.source_clk = UART_SCLK_DEFAULT;
  config.radio_config.radio_uart_config.rx_pin = (gpio_num_t)CONFIG_SM_OT_UART_RX_PIN;
  config.radio_config.radio_uart_config.tx_pin = (gpio_num_t)CONFIG_SM_OT_UART_TX_PIN;
  // --- host: CLI/NCP は使わない(このアプリ自身がホスト)---
  config.host_config.host_connection_mode = HOST_CONNECTION_MODE_NONE;
  // --- port: dataset/SRP の設定保存は "nvs" パーティション ---
  config.port_config.storage_partition_name = "nvs";
  config.port_config.netif_queue_size = 10;
  config.port_config.task_queue_size = 10;

  ESP_ERROR_CHECK(esp_openthread_init(&config));

  // OT netif(lwIP 統合): Matter の UDP ソケットはこの netif 越しに Thread へ出る。
  esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_OPENTHREAD();
  g_ot_netif = esp_netif_new(&netif_cfg);
  assert(g_ot_netif != nullptr);
  ESP_ERROR_CHECK(esp_netif_attach(g_ot_netif, esp_openthread_netif_glue_init(&config)));

#if CONFIG_SM_THREAD_BR
  // backbone netif(WiFi/Ethernet)は app 側で先に上げておく契約(F8e)。
  // P4 は radio 非搭載のため WiFi backbone は esp_wifi_remote / esp-hosted 経由
  // (例: M5Stack Tab5 = P4 + C6)。Ethernet でも可。
  esp_netif_t *backbone = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (backbone == nullptr) {
    backbone = esp_netif_get_handle_from_ifkey("ETH_DEF");
  }
  if (backbone == nullptr) {
    ESP_LOGE(TAG, "SM_THREAD_BR=y but no backbone netif (WIFI_STA_DEF/ETH_DEF) is up; "
                  "skipping border router init");
  } else {
    esp_openthread_set_backbone_netif(backbone);
    esp_openthread_lock_acquire(portMAX_DELAY);
    esp_openthread_border_router_init();
    esp_openthread_lock_release();
    ESP_LOGI(TAG, "border router enabled on backbone netif");
  }
#endif

  g_ot_ready = true;
  ESP_LOGI(TAG, "openthread mainloop starting (RCP over UART%d, %d baud, rx=%d tx=%d)",
           CONFIG_SM_OT_UART_PORT, CONFIG_SM_OT_UART_BAUD, CONFIG_SM_OT_UART_RX_PIN,
           CONFIG_SM_OT_UART_TX_PIN);
  esp_openthread_launch_mainloop(); // ブロック

  esp_openthread_netif_glue_deinit();
  esp_netif_destroy(g_ot_netif);
  esp_openthread_deinit();
  vTaskDelete(nullptr);
}

// hex 文字列 → バイト列。戻り値 = 書いたバイト数(0 = 空/不正)。
size_t hex_to_bytes(const char *hex, uint8_t *out, size_t cap) {
  size_t n = strlen(hex);
  if (n == 0 || (n % 2) != 0 || (n / 2) > cap) {
    return 0;
  }
  for (size_t i = 0; i < n / 2; ++i) {
    unsigned v = 0;
    if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
      return 0;
    }
    out[i] = (uint8_t)v;
  }
  return n / 2;
}

// active dataset の TLV を hex でログに出す(デバイス側にプリセットするため)。
void log_dataset_tlvs(const otOperationalDatasetTlvs &ds) {
  char buf[2 * OT_OPERATIONAL_DATASET_MAX_LENGTH + 1];
  size_t len = ds.mLength <= OT_OPERATIONAL_DATASET_MAX_LENGTH ? ds.mLength : 0;
  for (size_t i = 0; i < len; ++i) {
    snprintf(buf + 2 * i, 3, "%02x", ds.mTlvs[i]);
  }
  buf[2 * len] = 0;
  ESP_LOGI(TAG, "ACTIVE DATASET TLV (%u bytes):", (unsigned)len);
  ESP_LOGI(TAG, "  %s", buf);
}

// node_id を 16 桁大文字 hex にする(Matter の operational instance 名の後半)。
void node_hex(uint64_t node_id, char out[17]) {
  static const char *HEX = "0123456789ABCDEF";
  for (int i = 0; i < 16; ++i) {
    out[i] = HEX[(node_id >> (4 * (15 - i))) & 0xF];
  }
  out[16] = 0;
}

// 大文字小文字を無視した部分一致。
bool contains_ci(const char *hay, const char *needle) {
  size_t hn = strlen(hay), nn = strlen(needle);
  if (nn == 0 || nn > hn) {
    return false;
  }
  for (size_t i = 0; i + nn <= hn; ++i) {
    size_t j = 0;
    for (; j < nn; ++j) {
      char a = hay[i + j], b = needle[j];
      if (a >= 'a' && a <= 'z') {
        a = (char)(a - 'a' + 'A');
      }
      if (b >= 'a' && b <= 'z') {
        b = (char)(b - 'a' + 'A');
      }
      if (a != b) {
        break;
      }
    }
    if (j == nn) {
      return true;
    }
  }
  return false;
}

} // namespace

void sm_ot_hub_init() {
  // OT は eventfd を使う(radio / netif / task queue の 3 本)。
  esp_vfs_eventfd_config_t eventfd_config = {};
  eventfd_config.max_fds = 3;
  ESP_ERROR_CHECK(esp_vfs_eventfd_register(&eventfd_config));
  xTaskCreate(ot_task, "ot_main", 10 * 1024, nullptr, 5, nullptr);
}

bool sm_ot_hub_wait_ready(uint32_t timeout_ms) {
  uint32_t waited = 0;
  while (!g_ot_ready && waited < timeout_ms) {
    vTaskDelay(pdMS_TO_TICKS(100));
    waited += 100;
  }
  return g_ot_ready;
}

bool sm_ot_hub_form_network() {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otOperationalDatasetTlvs ds;
  memset(&ds, 0, sizeof(ds));
  otError err = otDatasetGetActiveTlvs(inst, &ds);
  if (err == OT_ERROR_NONE && ds.mLength > 0) {
    ESP_LOGI(TAG, "restored active dataset from NVS");
  } else {
    uint8_t tlv[OT_OPERATIONAL_DATASET_MAX_LENGTH];
    size_t n = hex_to_bytes(CONFIG_SM_THREAD_DATASET_TLV_HEX, tlv, sizeof(tlv));
    if (n > 0) {
      // (2) Kconfig の TLV hex を適用する(既存 Thread ネットワークに合わせる場合)。
      memset(&ds, 0, sizeof(ds));
      memcpy(ds.mTlvs, tlv, n);
      ds.mLength = (uint8_t)n;
      err = otDatasetSetActiveTlvs(inst, &ds);
      ESP_LOGI(TAG, "applied dataset from Kconfig (%u bytes) -> otError %d", (unsigned)n, (int)err);
    } else {
      // (3) 新規ネットワークを生成する(このハブが主宰 = leader になる)。
      otOperationalDataset fresh;
      memset(&fresh, 0, sizeof(fresh));
      err = otDatasetCreateNewNetwork(inst, &fresh);
      if (err == OT_ERROR_NONE) {
        err = otDatasetSetActive(inst, &fresh);
      }
      if (err == OT_ERROR_NONE) {
        err = otDatasetGetActiveTlvs(inst, &ds);
      }
      ESP_LOGI(TAG, "created new Thread network -> otError %d", (int)err);
    }
  }
  if (err != OT_ERROR_NONE) {
    esp_openthread_lock_release();
    ESP_LOGE(TAG, "dataset setup failed: %d", (int)err);
    return false;
  }
  log_dataset_tlvs(ds);

  err = otIp6SetEnabled(inst, true);
  if (err == OT_ERROR_NONE) {
    err = otThreadSetEnabled(inst, true);
  }
  if (err == OT_ERROR_NONE) {
    // SRP サーバ: デバイスの `_matter._tcp` 登録を受ける(このハブが DNS-SD の出所)。
    otSrpServerSetEnabled(inst, true);
  }
  esp_openthread_lock_release();
  ESP_LOGI(TAG, "thread start -> otError %d (SRP server enabled)", (int)err);
  return err == OT_ERROR_NONE;
}

bool sm_ot_hub_is_attached() {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otDeviceRole role = otThreadGetDeviceRole(esp_openthread_get_instance());
  esp_openthread_lock_release();
  return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
         role == OT_DEVICE_ROLE_LEADER;
}

bool sm_ot_hub_wait_leader(uint32_t timeout_ms) {
  uint32_t waited = 0;
  for (;;) {
    esp_openthread_lock_acquire(portMAX_DELAY);
    otDeviceRole role = otThreadGetDeviceRole(esp_openthread_get_instance());
    esp_openthread_lock_release();
    if (role == OT_DEVICE_ROLE_LEADER || role == OT_DEVICE_ROLE_ROUTER) {
      ESP_LOGI(TAG, "thread role = %d", (int)role);
      return true;
    }
    if (waited >= timeout_ms) {
      ESP_LOGW(TAG, "still not leader/router (role=%d)", (int)role);
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(500));
    waited += 500;
  }
}

uint32_t sm_ot_hub_netif_index() {
  return g_ot_netif ? (uint32_t)esp_netif_get_netif_impl_index(g_ot_netif) : 0;
}

bool sm_ot_hub_srp_lookup(uint64_t node_id, uint8_t out_ip[16]) {
  char want[17];
  node_hex(node_id, want);
  bool found = false;
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  const otSrpServerHost *host = nullptr;
  while ((host = otSrpServerGetNextHost(inst, host)) != nullptr && !found) {
    const otSrpServerService *svc = nullptr;
    while ((svc = otSrpServerHostGetNextService(host, svc)) != nullptr) {
      const char *inst_name = otSrpServerServiceGetInstanceName(svc);
      if (inst_name == nullptr || !contains_ci(inst_name, want)) {
        continue;
      }
      uint8_t num = 0;
      const otIp6Address *addrs = otSrpServerHostGetAddresses(host, &num);
      if (addrs == nullptr || num == 0) {
        continue;
      }
      // リンクローカル(fe80::/10)以外を優先する(SRP 登録は通常 ML-EID/OMR)。
      int pick = -1;
      for (uint8_t i = 0; i < num; ++i) {
        bool ll = addrs[i].mFields.m8[0] == 0xfe && (addrs[i].mFields.m8[1] & 0xc0) == 0x80;
        if (!ll) {
          pick = i;
          break;
        }
      }
      if (pick < 0) {
        pick = 0;
      }
      memcpy(out_ip, addrs[pick].mFields.m8, 16);
      found = true;
      break;
    }
  }
  esp_openthread_lock_release();
  return found;
}

void sm_ot_hub_dump_srp() {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  const otSrpServerHost *host = nullptr;
  while ((host = otSrpServerGetNextHost(inst, host)) != nullptr) {
    ESP_LOGI(TAG, "SRP host: %s", otSrpServerHostGetFullName(host));
    const otSrpServerService *svc = nullptr;
    while ((svc = otSrpServerHostGetNextService(host, svc)) != nullptr) {
      ESP_LOGI(TAG, "  service: %s", otSrpServerServiceGetInstanceName(svc));
    }
  }
  esp_openthread_lock_release();
}
