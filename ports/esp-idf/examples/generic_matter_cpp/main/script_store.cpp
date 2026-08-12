// ScriptStore クラスタ(§9.4 / G4)の ESP-IDF 側の受け皿。script_store.hpp を参照。
//
// backend = `smscript` パーティション(esp_partition)+ script_host の VM 再ロード。
// 受信ステートマシン本体は script_store.hpp(ESP-IDF 非依存)にあり、ホストの
// ループバックテスト(ctest/scriptstore_loopback.cpp)と同一コードを使う。

#include "script_store.hpp"

#include "sdkconfig.h"

#include "esp_log.h"

#if CONFIG_SM_SCRIPTSTORE_ENABLE

#include "script_host.hpp"
#include "script_img.hpp"

#include "esp_partition.h"

namespace smgen {
namespace {

const char *TAG = "smgen_store";

const esp_partition_t *g_part = nullptr;
uint16_t g_ep = 1;

// 4KB 消去単位へ切り上げる。
size_t round_up_erase(size_t len) {
  const size_t sec = 4096;
  return ((len + sec - 1) / sec) * sec;
}

bool be_erase(void *, size_t slot, size_t len) {
  if (g_part == nullptr || slot >= kScriptSlots) {
    return false;
  }
  const size_t off = script_slot_offset(slot);
  size_t n = round_up_erase(len);
  if (n > kScriptSlotSize) {
    n = kScriptSlotSize;
  }
  if (off + n > g_part->size) {
    return false;
  }
  const esp_err_t err = esp_partition_erase_range(g_part, off, n);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "erase slot %u (%u B) failed: %d", (unsigned)slot, (unsigned)n, (int)err);
    return false;
  }
  return true;
}

bool be_write(void *, size_t slot, size_t off, const uint8_t *data, size_t len) {
  if (g_part == nullptr || slot >= kScriptSlots || off + len > kScriptSlotSize) {
    return false;
  }
  return esp_partition_write(g_part, script_slot_offset(slot) + off, data, len) == ESP_OK;
}

bool be_read(void *, size_t slot, size_t off, uint8_t *out, size_t len) {
  if (g_part == nullptr || slot >= kScriptSlots || off + len > kScriptSlotSize) {
    return false;
  }
  return esp_partition_read(g_part, script_slot_offset(slot) + off, out, len) == ESP_OK;
}

bool be_reload(void *) { return script_reload(); }

void be_mark_dirty(void *, uint32_t attr_id) { sm_attr_mark_dirty(g_ep, kClScriptStore, attr_id); }

void be_on_command(void *, uint32_t cluster, uint32_t cmd) {
  // §9.3 で未接続だった on_command フック。**カスタムクラスタの invoke だけ**が
  // C++ 側を通るので、ここからスクリプトへ通知できる(合成クラスタのコマンドは
  // シムに口が無い。§10 Phase D)。戻り値は見ない(文鎮化防止)。
  script_notify_command(g_ep, cluster, cmd);
}

void be_log(void *, const char *msg) { ESP_LOGI(TAG, "%s", msg); }

// 起動時の active slot を loader と同一規則(ヘッダ妥当 + CRC 一致のうち ver 最大、
// 同値なら A)で求める。VM のロード可否とは独立に「格納の世代」を決める。
int scan_active(uint16_t &ver) {
  int best = -1;
  uint16_t best_ver = 0;
  for (size_t s = 0; s < kScriptSlots; s++) {
    const size_t off = script_slot_offset(s);
    uint8_t hdr[kScriptHdrSize];
    if (off + kScriptHdrSize > g_part->size) {
      continue;
    }
    if (esp_partition_read(g_part, off, hdr, sizeof(hdr)) != ESP_OK) {
      continue;
    }
    ScriptHeader h;
    if (!script_hdr_parse(hdr, sizeof(hdr), h)) {
      continue;
    }
    if (off + kScriptHdrSize + h.len > g_part->size) {
      continue;
    }
    uint8_t buf[128];
    uint32_t crc = 0;
    size_t done = 0;
    bool ok = true;
    while (done < h.len) {
      const size_t n = (h.len - done < sizeof(buf)) ? (size_t)(h.len - done) : sizeof(buf);
      if (esp_partition_read(g_part, off + kScriptHdrSize + done, buf, n) != ESP_OK) {
        ok = false;
        break;
      }
      crc = script_crc32(buf, n, crc);
      done += n;
    }
    if (!ok || crc != h.crc32) {
      continue;
    }
    if (best < 0 || h.ver > best_ver) {
      best = (int)s;
      best_ver = h.ver;
    }
  }
  ver = best_ver;
  return best;
}

} // namespace

bool script_store_init(uint16_t endpoint) {
  g_ep = endpoint;
  g_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40,
                                    CONFIG_SM_SCRIPT_PARTITION);
  if (g_part == nullptr) {
    ESP_LOGW(TAG, "no '%s' partition; ScriptStore not registered", CONFIG_SM_SCRIPT_PARTITION);
    return false;
  }
  uint16_t ver = 0;
  const int slot = scan_active(ver);

  ScriptStoreBackend be;
  be.user = nullptr;
  be.erase = be_erase;
  be.write = be_write;
  be.read = be_read;
  be.reload = be_reload;
  be.mark_dirty = be_mark_dirty;
  be.on_command = be_on_command;
  be.log = be_log;
  script_store().configure(be, slot, ver);

  const int rc = script_store_register(endpoint, script_store());
  if (rc != 0) {
    ESP_LOGE(TAG, "sm_cluster_register(ScriptStore) failed: rc=%d", rc);
    return false;
  }
  ESP_LOGI(TAG, "ScriptStore registered: EP%u cluster=0x%08x slot=%d ver=%u chunk<=%u B", endpoint,
           (unsigned)kClScriptStore, slot, (unsigned)ver, (unsigned)kSsChunkMax);
  return true;
}

void script_store_poll() {
  if (g_part != nullptr) {
    script_store().poll();
  }
}

void script_store_log_status() {
  if (g_part == nullptr) {
    ESP_LOGI(TAG, "ScriptStore: disabled (no partition)");
    return;
  }
  const ScriptStore &s = script_store();
  ESP_LOGI(TAG, "ScriptStore: state=%u active_slot=%u ver=%u recv=%u/%u", (unsigned)s.state(),
           (unsigned)s.active_slot(), (unsigned)s.version(), (unsigned)s.received(),
           (unsigned)s.expected());
}

} // namespace smgen

#else // !CONFIG_SM_SCRIPTSTORE_ENABLE

namespace smgen {

bool script_store_init(uint16_t) { return false; }
void script_store_poll() {}
void script_store_log_status() { ESP_LOGI("smgen_store", "ScriptStore: disabled at build time"); }

} // namespace smgen

#endif
