// OT ホスト配線の実体(ESP32-P4 + ESP32-H2 RCP over UART)。
// docs/design/p4-thread-controller.md §3 F8c。
//
// thread_ctrl_hub_cpp/main/ot_hub.cpp(F8c、実機 P9 で確定)のコピー + GUI 用の
// ステータス取得。元との差分は sm_ot_hub_get_status / sm_ot_hub_dataset_hex の追加と
// F8e(border router)足場の削除のみで、OT の配線自体は 1 行も変えていない:
//   - radio_mode = RADIO_MODE_UART_RCP(H2 の ot_rcp と spinel over UART)
//   - SRP は「クライアント」ではなく「サーバ」(このハブがネットワーク主宰)
//   - dataset を復元/生成して自分が leader になる
// §18(T11 / P1)で「FORM(上記)/ JOIN(外部ネットワークへ参加、SRP サーバ無し)」の
// モード切替を足した(sm_ot_hub_start_network)。

#include "ot_hub.hpp"

#include "sdkconfig.h"

#include <cstdarg>
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
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "nvs.h"

#include "openthread/dataset.h"
#include "openthread/dataset_ftd.h"
#include "openthread/dns_client.h"
#include "openthread/instance.h"
#include "openthread/ip6.h"
#include "openthread/link.h"
#include "openthread/netdata.h"
#include "openthread/srp_server.h"
#include "openthread/thread.h"
#include "openthread/thread_ftd.h"

namespace {

constexpr const char *TAG = "ot_hub";

esp_netif_t *g_ot_netif = nullptr;
volatile bool g_ot_ready = false;
volatile bool g_started = false; // Thread を起動したか(JOIN で dataset 無しなら false のまま)

// --- モード切替の永続化(§18.3-1)。UI 用 namespace "smui" に同居させる ---
constexpr const char *MODE_NS = "smui";
constexpr const char *KEY_MODE = "otmode";       // u8: sm_ot_mode_t
constexpr const char *KEY_JOIN_DS = "otjoin_ds"; // blob: JOIN で適用する dataset TLV
constexpr const char *KEY_FORM_DS = "otform_ds"; // blob: JOIN 中に退避した自前 dataset TLV

int g_mode = -1; // 未決定。起動後は固定(切替は NVS に書いて再起動)

size_t nvs_get_ds(const char *key, uint8_t *out, size_t cap) {
  nvs_handle_t h;
  if (nvs_open(MODE_NS, NVS_READONLY, &h) != ESP_OK) {
    return 0;
  }
  size_t len = cap;
  esp_err_t err = nvs_get_blob(h, key, out, &len);
  nvs_close(h);
  return err == ESP_OK ? len : 0;
}

bool nvs_set_ds(const char *key, const uint8_t *val, size_t len) {
  nvs_handle_t h;
  if (nvs_open(MODE_NS, NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t err = nvs_set_blob(h, key, val, len);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK;
}

void nvs_erase_ds(const char *key) {
  nvs_handle_t h;
  if (nvs_open(MODE_NS, NVS_READWRITE, &h) != ESP_OK) {
    return;
  }
  if (nvs_erase_key(h, key) == ESP_OK) {
    nvs_commit(h);
  }
  nvs_close(h);
}

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
    for (int k = 0; k < 2; ++k) {
      char c = hex[2 * i + k];
      unsigned d;
      if (c >= '0' && c <= '9') {
        d = (unsigned)(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        d = (unsigned)(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        d = (unsigned)(c - 'A' + 10);
      } else {
        return 0;
      }
      v = (v << 4) | d;
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

sm_ot_mode_t sm_ot_hub_mode() {
  if (g_mode < 0) {
#if CONFIG_SM_THREAD_MODE_JOIN
    uint8_t m = SM_OT_MODE_JOIN;
#else
    uint8_t m = SM_OT_MODE_FORM;
#endif
    nvs_handle_t h;
    if (nvs_open(MODE_NS, NVS_READONLY, &h) == ESP_OK) {
      uint8_t v = 0;
      if (nvs_get_u8(h, KEY_MODE, &v) == ESP_OK && v <= SM_OT_MODE_JOIN) {
        m = v;
      }
      nvs_close(h);
    }
    g_mode = m;
  }
  return (sm_ot_mode_t)g_mode;
}

const char *sm_ot_hub_mode_name(sm_ot_mode_t m) { return m == SM_OT_MODE_JOIN ? "JOIN" : "FORM"; }

bool sm_ot_hub_mode_save(sm_ot_mode_t mode, const char *dataset_hex) {
  if (dataset_hex != nullptr && dataset_hex[0] != 0) {
    uint8_t tlv[OT_OPERATIONAL_DATASET_MAX_LENGTH];
    size_t n = hex_to_bytes(dataset_hex, tlv, sizeof(tlv));
    if (n == 0 || !nvs_set_ds(KEY_JOIN_DS, tlv, n)) {
      return false;
    }
  }
  nvs_handle_t h;
  if (nvs_open(MODE_NS, NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t err = nvs_set_u8(h, KEY_MODE, (uint8_t)mode);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK;
}

const char *sm_ot_hub_join_dataset_source() {
  uint8_t tlv[OT_OPERATIONAL_DATASET_MAX_LENGTH];
  if (nvs_get_ds(KEY_JOIN_DS, tlv, sizeof(tlv)) > 0) {
    return "nvs";
  }
  return CONFIG_SM_THREAD_DATASET_TLV_HEX[0] != 0 ? "kconfig" : "none";
}

namespace {

// FORM: 従来動作(+ JOIN から戻ったときの自前 dataset の復元)。OT ロック保持中に呼ぶ。
otError prepare_dataset_form(otInstance *inst, otOperationalDatasetTlvs &ds) {
  memset(&ds, 0, sizeof(ds));
  otError err = otDatasetGetActiveTlvs(inst, &ds);
  // (0) JOIN 中に退避した自前 dataset があれば復元する(§18.6 ゲート C)。
  {
    uint8_t bak[OT_OPERATIONAL_DATASET_MAX_LENGTH];
    size_t bn = nvs_get_ds(KEY_FORM_DS, bak, sizeof(bak));
    if (bn > 0) {
      if (err != OT_ERROR_NONE || ds.mLength != bn || memcmp(ds.mTlvs, bak, bn) != 0) {
        memset(&ds, 0, sizeof(ds));
        memcpy(ds.mTlvs, bak, bn);
        ds.mLength = (uint8_t)bn;
        err = otDatasetSetActiveTlvs(inst, &ds);
        ESP_LOGI(TAG, "FORM: restored own dataset from backup (%u bytes) -> otError %d",
                 (unsigned)bn, (int)err);
      }
      if (err == OT_ERROR_NONE) {
        nvs_erase_ds(KEY_FORM_DS);
      }
      return err;
    }
  }
  if (err == OT_ERROR_NONE && ds.mLength > 0) {
    ESP_LOGI(TAG, "restored active dataset from NVS");
    return OT_ERROR_NONE;
  }
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
  return err;
}

// JOIN: 与えられた dataset を active にする(NVS の active より優先)。OT ロック保持中に呼ぶ。
// dataset が無ければ OT_ERROR_NOT_FOUND(呼び出し側は Thread を起動しない)。
otError prepare_dataset_join(otInstance *inst, otOperationalDatasetTlvs &ds) {
  uint8_t tlv[OT_OPERATIONAL_DATASET_MAX_LENGTH];
  const char *src = "nvs";
  size_t n = nvs_get_ds(KEY_JOIN_DS, tlv, sizeof(tlv));
  if (n == 0) {
    src = "kconfig";
    n = hex_to_bytes(CONFIG_SM_THREAD_DATASET_TLV_HEX, tlv, sizeof(tlv));
  }
  if (n == 0) {
    return OT_ERROR_NOT_FOUND;
  }
  otOperationalDatasetTlvs cur;
  memset(&cur, 0, sizeof(cur));
  otError err = otDatasetGetActiveTlvs(inst, &cur);
  const bool have_cur = (err == OT_ERROR_NONE && cur.mLength > 0);
  memset(&ds, 0, sizeof(ds));
  memcpy(ds.mTlvs, tlv, n);
  ds.mLength = (uint8_t)n;
  if (have_cur && cur.mLength == n && memcmp(cur.mTlvs, tlv, n) == 0) {
    ESP_LOGI(TAG, "JOIN: active dataset already matches the join dataset (%s)", src);
    return OT_ERROR_NONE;
  }
  if (have_cur) {
    // 自前 dataset の退避は **未退避のときだけ**(JOIN dataset を差し替えた 2 回目以降に、
    // 前回の JOIN dataset で自前のものを潰さない)。
    uint8_t bak[OT_OPERATIONAL_DATASET_MAX_LENGTH];
    if (nvs_get_ds(KEY_FORM_DS, bak, sizeof(bak)) == 0) {
      if (!nvs_set_ds(KEY_FORM_DS, cur.mTlvs, cur.mLength)) {
        ESP_LOGE(TAG, "JOIN: failed to back up the own dataset; not overwriting it");
        return OT_ERROR_FAILED;
      }
      ESP_LOGI(TAG, "JOIN: backed up the own dataset (%u bytes) to NVS", (unsigned)cur.mLength);
    }
  }
  err = otDatasetSetActiveTlvs(inst, &ds);
  ESP_LOGI(TAG, "JOIN: applied join dataset from %s (%u bytes) -> otError %d", src, (unsigned)n,
           (int)err);
  return err;
}

} // namespace

bool sm_ot_hub_start_network() {
  const sm_ot_mode_t mode = sm_ot_hub_mode();
  ESP_LOGI(TAG, "thread mode = %s", sm_ot_hub_mode_name(mode));
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otOperationalDatasetTlvs ds;
  otError err = (mode == SM_OT_MODE_JOIN) ? prepare_dataset_join(inst, ds)
                                          : prepare_dataset_form(inst, ds);
  if (err != OT_ERROR_NONE) {
    esp_openthread_lock_release();
    if (mode == SM_OT_MODE_JOIN && err == OT_ERROR_NOT_FOUND) {
      ESP_LOGE(TAG, "JOIN: no dataset (use `otmode join <hex>` or CONFIG_SM_THREAD_DATASET_TLV_HEX);"
                    " Thread is NOT started");
    } else {
      ESP_LOGE(TAG, "dataset setup failed: %d", (int)err);
    }
    return false;
  }
  if (mode == SM_OT_MODE_FORM) {
    // 自前ネットワークの dataset はデバイス側プリセット用にログへ出す(従来動作)。
    // JOIN の dataset は他人のネットワークの鍵なのでログに出さない。
    log_dataset_tlvs(ds);
  }

  // JOIN(§18.7 / P2): **router 不適格(FED = rx-on の FTD 子)で参加**する。適格のままだと、
  // 起動直後に親が見つからない間(実機で ~15 秒)に Tab5 が自分のパーティションの leader に
  // なり、~75 秒後に OTBR 側へ併合されるまで別網に居た(その間 SRP/DNS も OTBR ノードも見えない)。
  // 不適格なら親が見つかるまで detached のまま attach を繰り返すだけで、パーティションは作らない。
  // attach 後も適格へは戻さない(OTBR が落ちたときに Tab5 が網を引き継ぐと SRP/DNS の無い
  // パーティションになる。Tab5 は経路の中継役を担う必要が無い)。FORM は従来どおり適格(leader)。
  // この設定は OT の settings に保存されないので毎回明示する。
  err = otThreadSetRouterEligible(inst, mode == SM_OT_MODE_FORM);
  if (err != OT_ERROR_NONE) {
    ESP_LOGW(TAG, "otThreadSetRouterEligible(%d) -> otError %d", (int)(mode == SM_OT_MODE_FORM),
             (int)err);
  }
  err = otIp6SetEnabled(inst, true);
  if (err == OT_ERROR_NONE) {
    err = otThreadSetEnabled(inst, true);
  }
  if (err == OT_ERROR_NONE && mode == SM_OT_MODE_FORM) {
    // SRP サーバ: デバイスの `_matter._tcp` 登録を受ける(このハブが DNS-SD の出所)。
    // JOIN では有効化しない(netdata に 2 つ目の SRP サーバを publish すると登録先が割れる)。
    otSrpServerSetEnabled(inst, true);
  }
  esp_openthread_lock_release();
  g_started = (err == OT_ERROR_NONE);
  ESP_LOGI(TAG, "thread start -> otError %d (%s, SRP server %s)", (int)err,
           sm_ot_hub_mode_name(mode), mode == SM_OT_MODE_FORM ? "enabled" : "not started");
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

bool sm_ot_hub_wait_attached(uint32_t timeout_ms) {
  uint32_t waited = 0;
  for (;;) {
    esp_openthread_lock_acquire(portMAX_DELAY);
    otDeviceRole role = otThreadGetDeviceRole(esp_openthread_get_instance());
    esp_openthread_lock_release();
    if (role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
        role == OT_DEVICE_ROLE_LEADER) {
      ESP_LOGI(TAG, "thread attached, role = %d", (int)role);
      return true;
    }
    if (waited >= timeout_ms) {
      ESP_LOGW(TAG, "still not attached (role=%d)", (int)role);
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(500));
    waited += 500;
  }
}

size_t sm_ot_hub_addrs(char *out, size_t cap) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  out[0] = 0;
  if (!g_ot_ready) {
    return 0;
  }
  size_t n = 0, used = 0;
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  for (const otNetifAddress *a = inst ? otIp6GetUnicastAddresses(inst) : nullptr; a != nullptr;
       a = a->mNext) {
    char buf[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&a->mAddress, buf, sizeof(buf));
    int w = snprintf(out + used, cap - used, "%s\n", buf);
    if (w < 0 || (size_t)w >= cap - used) {
      out[used] = 0;
      break;
    }
    used += (size_t)w;
    ++n;
  }
  esp_openthread_lock_release();
  return n;
}

uint32_t sm_ot_hub_netif_index() {
  return g_ot_netif ? (uint32_t)esp_netif_get_netif_impl_index(g_ot_netif) : 0;
}

// --- JOIN: OT DNS client による解決(§18.3-2 / P2)---
namespace {

constexpr uint32_t THREAD_ENTERPRISE = 44970;   // netdata の Thread サービス(IANA 44970)
constexpr uint8_t SVC_DNS_SRP_ANYCAST = 0x5c;   // service data = [0x5c, seq]
constexpr uint8_t SVC_DNS_SRP_UNICAST = 0x5d;   // service data = [0x5d(, addr16, port2(, ver))]
constexpr uint16_t DNS_PORT = 53;                // OT の DNS-SD サーバ(SRP サーバと同居)の固定ポート

__attribute__((format(printf, 3, 4))) void put_msg(char *msg, size_t cap, const char *fmt, ...) {
  if (msg == nullptr || cap == 0) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, cap, fmt, ap);
  va_end(ap);
}

bool is_link_local(const otIp6Address &a) {
  return a.mFields.m8[0] == 0xfe && (a.mFields.m8[1] & 0xc0) == 0x80;
}

// ML プレフィクス + 0000:00ff:fe00:<rloc/aloc16>(RLOC / ALOC)。OT ロック保持中に呼ぶ。
void compose_locator(otInstance *inst, uint16_t loc16, otIp6Address &out) {
  memset(&out, 0, sizeof(out));
  const otMeshLocalPrefix *ml = otThreadGetMeshLocalPrefix(inst);
  if (ml != nullptr) {
    memcpy(out.mFields.m8, ml->m8, 8);
  }
  out.mFields.m8[11] = 0xff;
  out.mFields.m8[12] = 0xfe;
  out.mFields.m8[14] = (uint8_t)(loc16 >> 8);
  out.mFields.m8[15] = (uint8_t)loc16;
}

// netdata から DNS/SRP サーバを選ぶ。OT ロック保持中に呼ぶ。
// OT の DNS client のサーバ自動設定(DEFAULT_SERVER_ADDRESS_AUTO_SET)は SRP client 前提で
// 本アプリでは使えないので、同じ規則を自前で辿る:
//   1. unicast(0x5d)— アドレスが service data 側([0x5d][addr16][port2])
//   2. unicast(0x5d)— アドレスが server data 側([addr16][port2])/ port だけなら server の RLOC
//   3. anycast(0x5c)— ALOC = ML プレフィクス::ff:fe00:fc10+serviceId
// ポートは netdata の値(= **SRP** サーバのポート)ではなく DNS の 53 を使う(OT の DNS-SD
// サーバは SRP サーバと同じホストの :53 で答える。OT 自身の自動設定もアドレスだけを流用する)。
bool find_dns_server(otInstance *inst, otIp6Address &out, char *desc, size_t cap) {
  bool have_srv = false, have_srvr = false, have_any = false;
  otIp6Address a_srv = {}, a_srvr = {}, a_any = {};
  uint16_t rloc_srv = 0, rloc_srvr = 0, rloc_any = 0;
  otNetworkDataIterator it = OT_NETWORK_DATA_ITERATOR_INIT;
  otServiceConfig cfg;
  while (otNetDataGetNextService(inst, &it, &cfg) == OT_ERROR_NONE) {
    if (cfg.mEnterpriseNumber != THREAD_ENTERPRISE || cfg.mServiceDataLength < 1) {
      continue;
    }
    const uint8_t num = cfg.mServiceData[0];
    if (num == SVC_DNS_SRP_UNICAST) {
      if (cfg.mServiceDataLength >= 1 + 18) {
        if (!have_srv) {
          memcpy(a_srv.mFields.m8, &cfg.mServiceData[1], 16);
          rloc_srv = cfg.mServerConfig.mRloc16;
          have_srv = true;
        }
      } else if (cfg.mServerConfig.mServerDataLength >= 18) {
        if (!have_srvr) {
          memcpy(a_srvr.mFields.m8, cfg.mServerConfig.mServerData, 16);
          rloc_srvr = cfg.mServerConfig.mRloc16;
          have_srvr = true;
        }
      } else if (cfg.mServerConfig.mServerDataLength == 2) {
        if (!have_srvr) {
          compose_locator(inst, cfg.mServerConfig.mRloc16, a_srvr);
          rloc_srvr = cfg.mServerConfig.mRloc16;
          have_srvr = true;
        }
      }
    } else if (num == SVC_DNS_SRP_ANYCAST && !have_any) {
      compose_locator(inst, (uint16_t)(0xfc10 + cfg.mServiceId), a_any);
      rloc_any = cfg.mServerConfig.mRloc16;
      have_any = true;
    }
  }
  const char *kind = nullptr;
  uint16_t rloc = 0;
  if (have_srv) {
    out = a_srv, kind = "unicast/service-data", rloc = rloc_srv;
  } else if (have_srvr) {
    out = a_srvr, kind = "unicast/server-data", rloc = rloc_srvr;
  } else if (have_any) {
    out = a_any, kind = "anycast", rloc = rloc_any;
  } else {
    if (desc != nullptr && cap > 0) {
      snprintf(desc, cap, "no DNS/SRP service in netdata");
    }
    return false;
  }
  if (desc != nullptr && cap > 0) {
    char abuf[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6AddressToString(&out, abuf, sizeof(abuf));
    snprintf(desc, cap, "[%s]:%u (%s, server rloc 0x%04x)", abuf, (unsigned)DNS_PORT, kind,
             (unsigned)rloc);
  }
  return true;
}

void dump_netdata_services() {
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otNetworkDataIterator it = OT_NETWORK_DATA_ITERATOR_INIT;
  otServiceConfig cfg;
  int n = 0;
  while (otNetDataGetNextService(inst, &it, &cfg) == OT_ERROR_NONE) {
    char sd[2 * OT_SERVICE_DATA_MAX_SIZE + 1] = {0};
    char vd[2 * OT_SERVER_DATA_MAX_SIZE + 1] = {0};
    for (uint8_t i = 0; i < cfg.mServiceDataLength && i < OT_SERVICE_DATA_MAX_SIZE; ++i) {
      snprintf(sd + 2 * i, 3, "%02x", cfg.mServiceData[i]);
    }
    for (uint8_t i = 0; i < cfg.mServerConfig.mServerDataLength && i < OT_SERVER_DATA_MAX_SIZE;
         ++i) {
      snprintf(vd + 2 * i, 3, "%02x", cfg.mServerConfig.mServerData[i]);
    }
    ESP_LOGI(TAG, "netdata service: %lu %s %s %s rloc 0x%04x id %u",
             (unsigned long)cfg.mEnterpriseNumber, sd, vd[0] ? vd : "-",
             cfg.mServerConfig.mStable ? "s" : "-", (unsigned)cfg.mServerConfig.mRloc16,
             (unsigned)cfg.mServiceId);
    ++n;
  }
  char desc[96];
  otIp6Address srv;
  bool ok = find_dns_server(inst, srv, desc, sizeof(desc));
  esp_openthread_lock_release();
  ESP_LOGI(TAG, "netdata services: %d; DNS server %s%s", n, ok ? "" : "not found: ", desc);
}

// DNS client の同期ラップ。コールバックは OT タスク(OT ロック保持)で走る。
// 待ちがタイムアウトした後に遅れて来たコールバックは世代番号で捨てる。
struct DnsWait {
  SemaphoreHandle_t sem = nullptr;
  uint32_t gen = 0; // 読み書きは全て OT ロック下
  otError err = OT_ERROR_NONE;
  bool have_ip = false;
  uint8_t ip[16] = {0};
  uint16_t port = 0;
  char host[96] = {0};
};
DnsWait g_dns;

void dns_service_cb(otError err, const otDnsServiceResponse *resp, void *ctx) {
  if ((uint32_t)(uintptr_t)ctx != g_dns.gen) {
    return; // 古い問い合わせ
  }
  g_dns.err = err;
  g_dns.have_ip = false;
  if (err == OT_ERROR_NONE) {
    otDnsServiceInfo info;
    memset(&info, 0, sizeof(info));
    info.mHostNameBuffer = g_dns.host;
    info.mHostNameBufferSize = sizeof(g_dns.host);
    otError e = otDnsServiceResponseGetServiceInfo(resp, &info);
    if (e == OT_ERROR_NONE) {
      g_dns.port = info.mPort;
      // AAAA を全部見て、リンクローカル以外の最初のものを採る(SRP 登録は通常 OMR / ML-EID)。
      otIp6Address a;
      bool picked_ll = false;
      for (uint16_t i = 0; i < 8; ++i) {
        if (otDnsServiceResponseGetHostAddress(resp, g_dns.host, i, &a, nullptr) != OT_ERROR_NONE) {
          break;
        }
        char abuf[OT_IP6_ADDRESS_STRING_SIZE];
        otIp6AddressToString(&a, abuf, sizeof(abuf));
        ESP_LOGI(TAG, "DNS: %s AAAA[%u] %s", g_dns.host, (unsigned)i, abuf);
        if (!g_dns.have_ip || (picked_ll && !is_link_local(a))) {
          memcpy(g_dns.ip, a.mFields.m8, 16);
          picked_ll = is_link_local(a);
          g_dns.have_ip = true;
        }
      }
      if (!g_dns.have_ip && !otIp6IsAddressUnspecified(&info.mHostAddress)) {
        memcpy(g_dns.ip, info.mHostAddress.mFields.m8, 16);
        g_dns.have_ip = true;
      }
      if (!g_dns.have_ip) {
        g_dns.err = OT_ERROR_NOT_FOUND; // SRV はあるが AAAA が無い
      }
    } else {
      g_dns.err = e;
    }
  }
  xSemaphoreGive(g_dns.sem);
}

} // namespace

bool sm_ot_hub_dns_server(char *desc, size_t cap) {
  if (!g_ot_ready) {
    if (desc != nullptr && cap > 0) {
      snprintf(desc, cap, "OT not ready");
    }
    return false;
  }
  esp_openthread_lock_acquire(portMAX_DELAY);
  otIp6Address srv;
  bool ok = find_dns_server(esp_openthread_get_instance(), srv, desc, cap);
  esp_openthread_lock_release();
  return ok;
}

bool sm_ot_hub_dns_resolve(const char *instance_label, uint8_t out_ip[16], uint16_t *out_port,
                           uint32_t timeout_ms, char *msg, size_t msgcap) {
  if (instance_label == nullptr || instance_label[0] == 0) {
    put_msg(msg, msgcap, "no instance label");
    return false;
  }
  if (!g_ot_ready || !sm_ot_hub_is_attached()) {
    put_msg(msg, msgcap, "Thread not attached");
    return false;
  }
  if (g_dns.sem == nullptr) {
    g_dns.sem = xSemaphoreCreateBinary();
    if (g_dns.sem == nullptr) {
      put_msg(msg, msgcap, "no memory");
      return false;
    }
  }
  if (timeout_ms < 2000) {
    timeout_ms = 2000;
  }
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  char sdesc[96] = {0};
  otDnsQueryConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  if (!find_dns_server(inst, cfg.mServerSockAddr.mAddress, sdesc, sizeof(sdesc))) {
    esp_openthread_lock_release();
    put_msg(msg, msgcap, "%s", sdesc);
    return false;
  }
  cfg.mServerSockAddr.mPort = DNS_PORT;
  // 1 回あたりの応答待ち × 試行回数がこちらの待ち時間に収まるようにする(コールバックが
  // 必ず先に来る = 世代の取りこぼしを避ける)。
  cfg.mMaxTxAttempts = 2;
  cfg.mResponseTimeout = timeout_ms / 2 > 500 ? timeout_ms / 2 - 250 : 500;
  cfg.mRecursionFlag = OT_DNS_FLAG_NO_RECURSION;
  cfg.mNat64Mode = OT_DNS_NAT64_DISALLOW;
  cfg.mServiceMode = OT_DNS_SERVICE_MODE_SRV;
  cfg.mTransportProto = OT_DNS_TRANSPORT_UDP;
  const uint32_t gen = ++g_dns.gen;
  xSemaphoreTake(g_dns.sem, 0); // 前回の取り残しを捨てる
  g_dns.err = OT_ERROR_RESPONSE_TIMEOUT;
  g_dns.have_ip = false;
  g_dns.host[0] = 0;
  otError err = otDnsClientResolveServiceAndHostAddress(
      inst, instance_label, "_matter._tcp.default.service.arpa.", dns_service_cb,
      (void *)(uintptr_t)gen, &cfg);
  esp_openthread_lock_release();
  ESP_LOGI(TAG, "DNS: resolve %s._matter._tcp.default.service.arpa via %s -> otError %d",
           instance_label, sdesc, (int)err);
  if (err != OT_ERROR_NONE) {
    put_msg(msg, msgcap, "query not sent (otError %d %s)", (int)err, otThreadErrorToString(err));
    return false;
  }
  bool got = xSemaphoreTake(g_dns.sem, pdMS_TO_TICKS(timeout_ms + 1000)) == pdTRUE;
  esp_openthread_lock_acquire(portMAX_DELAY);
  if (!got) {
    ++g_dns.gen; // 以後のコールバックは捨てる
  }
  const otError rerr = got ? g_dns.err : OT_ERROR_RESPONSE_TIMEOUT;
  const bool ok = got && rerr == OT_ERROR_NONE && g_dns.have_ip;
  if (ok) {
    memcpy(out_ip, g_dns.ip, 16);
    if (out_port != nullptr) {
      *out_port = g_dns.port;
    }
    char abuf[OT_IP6_ADDRESS_STRING_SIZE];
    otIp6Address a;
    memcpy(a.mFields.m8, g_dns.ip, 16);
    otIp6AddressToString(&a, abuf, sizeof(abuf));
    put_msg(msg, msgcap, "[%s]:%u host %s (server %s)", abuf, (unsigned)g_dns.port, g_dns.host, sdesc);
  } else {
    put_msg(msg, msgcap, "otError %d %s (server %s)", (int)rerr, otThreadErrorToString(rerr), sdesc);
  }
  esp_openthread_lock_release();
  return ok;
}

bool sm_ot_hub_resolve(uint64_t node_id, const char *instance_label, uint8_t out_ip[16],
                       uint32_t timeout_ms, char *msg, size_t msgcap) {
  if (sm_ot_hub_mode() == SM_OT_MODE_FORM) {
    bool ok = sm_ot_hub_srp_lookup(node_id, out_ip);
    if (msg != nullptr && msgcap > 0) {
      snprintf(msg, msgcap, ok ? "SRP table hit" : "not in the SRP table");
    }
    return ok;
  }
  return sm_ot_hub_dns_resolve(instance_label, out_ip, nullptr, timeout_ms, msg, msgcap);
}

bool sm_ot_hub_srp_lookup(uint64_t node_id, uint8_t out_ip[16]) {
  if (sm_ot_hub_mode() == SM_OT_MODE_JOIN) {
    return false; // 自分の SRP サーバ帳は無い(§18.2。JOIN は sm_ot_hub_resolve → DNS client)
  }
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
  if (sm_ot_hub_mode() == SM_OT_MODE_JOIN) {
    dump_netdata_services(); // 自分の SRP サーバ帳は無い。代わりに netdata のサービス一覧
    return;
  }
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

// --- GUI 用のステータス取得(T1)---

void sm_ot_hub_get_status(sm_ot_status_t *out) {
  if (out == nullptr) {
    return;
  }
  memset(out, 0, sizeof(*out));
  out->mode = (uint8_t)sm_ot_hub_mode();
  out->started = g_started;
  if (!g_ot_ready) {
    return;
  }
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  if (inst != nullptr) {
    out->role = (int)otThreadGetDeviceRole(inst);
    out->rloc16 = otThreadGetRloc16(inst);
    out->channel = (uint8_t)otLinkGetChannel(inst);
    out->panid = (uint16_t)otLinkGetPanId(inst);
    const char *name = otThreadGetNetworkName(inst);
    if (name != nullptr) {
      strncpy(out->netname, name, sizeof(out->netname) - 1);
    }
    out->srp_enabled = otSrpServerGetState(inst) != OT_SRP_SERVER_STATE_DISABLED;
    const otSrpServerHost *host = nullptr;
    while ((host = otSrpServerGetNextHost(inst, host)) != nullptr) {
      ++out->srp_hosts;
    }
  }
  esp_openthread_lock_release();
}

size_t sm_ot_hub_dataset_hex(char *out, size_t cap) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  out[0] = 0;
  if (!g_ot_ready) {
    return 0;
  }
  otOperationalDatasetTlvs ds;
  memset(&ds, 0, sizeof(ds));
  esp_openthread_lock_acquire(portMAX_DELAY);
  otInstance *inst = esp_openthread_get_instance();
  otError err = inst ? otDatasetGetActiveTlvs(inst, &ds) : OT_ERROR_FAILED;
  esp_openthread_lock_release();
  if (err != OT_ERROR_NONE || ds.mLength == 0) {
    return 0;
  }
  size_t len = ds.mLength;
  if (2 * len + 1 > cap) {
    return 0;
  }
  static const char *HEX = "0123456789abcdef";
  for (size_t i = 0; i < len; ++i) {
    out[2 * i] = HEX[ds.mTlvs[i] >> 4];
    out[2 * i + 1] = HEX[ds.mTlvs[i] & 0xF];
  }
  out[2 * len] = 0;
  return 2 * len;
}
