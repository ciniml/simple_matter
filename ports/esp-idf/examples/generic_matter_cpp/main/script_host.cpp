// スクリプト VM の ESP-IDF 側の受け皿(§9.3)。script_host.hpp のコメントを参照。

#include "script_host.hpp"

#include "sdkconfig.h"

#include "esp_log.h"

#if CONFIG_SM_SCRIPT_ENABLE

#include <cstring>

#include "script_img.hpp"
#include "script_vm.hpp"

#include "simple_matter.h"

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_heap_caps.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"

namespace smgen {
namespace {

const char *TAG = "smgen_script";

// スクリプト用 KVS の NVS namespace(§9.3)。
constexpr const char *kScriptNvs = "smscr";

// WAMR のヒーププール(線形メモリ 64KB + モジュール + 実行スタック)。
// CONFIG_SM_SCRIPT_POOL_STATIC=y なら .bss に常時確保、n(既定)ならスクリプトが
// 見つかったときだけ内部 RAM から確保する(§10 Phase C の罠 3)。
constexpr size_t kPoolSize = (size_t)CONFIG_SM_SCRIPT_POOL_KB * 1024;
#if CONFIG_SM_SCRIPT_POOL_STATIC
alignas(8) uint8_t g_pool_storage[kPoolSize];
uint8_t *g_pool = g_pool_storage;
#else
uint8_t *g_pool = nullptr;
#endif

// 直近にロードしたイメージのメタ情報。
uint16_t g_ver = 0;
uint32_t g_len = 0;
int g_slot = -1;

esp_timer_handle_t g_wdt = nullptr;

// ---- 暴走監視(esp_timer ワンショット)---------------------------------------
//
// esp_timer のコールバックは esp_timer タスク(pump とは別タスク)で走る。そこから
// wasm_runtime_terminate 相当を呼ぶと、実行中のフックに trap が上がって復帰する。

void wdt_cb(void *) {
  ESP_LOGE(TAG, "hook exceeded %d ms budget; terminating", CONFIG_SM_SCRIPT_BUDGET_MS);
  script_vm_terminate();
}

void wdt_arm(void *, uint32_t ms) {
  if (g_wdt == nullptr) {
    esp_timer_create_args_t args{};
    args.callback = &wdt_cb;
    args.name = "smscr_wdt";
    args.dispatch_method = ESP_TIMER_TASK;
    if (esp_timer_create(&args, &g_wdt) != ESP_OK) {
      g_wdt = nullptr;
      return;
    }
  }
  esp_timer_stop(g_wdt); // 冪等(未起動なら ESP_ERR_INVALID_STATE)
  esp_timer_start_once(g_wdt, (uint64_t)ms * 1000ull);
}

void wdt_disarm(void *) {
  if (g_wdt != nullptr) {
    esp_timer_stop(g_wdt);
  }
}

// ---- 16B 値レコード ⇔ sm_attr_value_t ----------------------------------------

// sm_attr_value_t → 16B(+ STRING/OCTETS 本体)。書いた全長を返す(cap 不足は -5)。
int32_t encode_value(const sm_attr_value_t &v, uint8_t *out, uint32_t cap) {
  ScriptValue sv;
  sv.type = (uint8_t)v.type;
  sv.is_null = v.is_null;
  switch (v.type) {
  case SM_T_BOOL:
    sv.bits = v.v.b ? 1u : 0u;
    break;
  case SM_T_U8:
  case SM_T_U16:
  case SM_T_U32:
  case SM_T_U64:
    sv.bits = v.v.u;
    break;
  case SM_T_I8:
  case SM_T_I16:
  case SM_T_I32:
  case SM_T_I64:
    sv.bits = (uint64_t)v.v.i;
    break;
  case SM_T_F32: {
    uint32_t bits = 0;
    memcpy(&bits, &v.v.f, sizeof(bits));
    sv.bits = bits;
    break;
  }
  case SM_T_STRING:
  case SM_T_OCTETS:
    sv.len = v.v.bytes.len;
    break;
  default:
    return SCRIPT_ERR_TYPE;
  }
  const uint32_t total = (uint32_t)kScriptValueSize + sv.len;
  if (cap < total) {
    return SCRIPT_ERR_NOSPACE;
  }
  script_value_encode(out, sv);
  if (sv.len > 0) {
    memcpy(out + kScriptValueSize, v.v.bytes.buf, sv.len);
  }
  return (int32_t)total;
}

// 16B(+本体)→ sm_attr_value_t。
bool decode_value(const uint8_t *in, uint32_t len, sm_attr_value_t &out) {
  ScriptValue sv;
  if (!script_value_decode(in, len, sv)) {
    return false;
  }
  memset(&out, 0, sizeof(out));
  out.is_null = sv.is_null;
  switch (sv.type) {
  case SV_BOOL:
    out.type = SM_T_BOOL;
    out.v.b = (sv.bits & 1) != 0;
    break;
  case SV_U8:
  case SV_U16:
  case SV_U32:
  case SV_U64:
    out.type = (sm_attr_type_t)sv.type;
    out.v.u = sv.bits;
    break;
  case SV_I8:
  case SV_I16:
  case SV_I32:
  case SV_I64:
    out.type = (sm_attr_type_t)sv.type;
    out.v.i = (int64_t)sv.bits;
    break;
  case SV_F32: {
    out.type = SM_T_F32;
    uint32_t bits = (uint32_t)sv.bits;
    memcpy(&out.v.f, &bits, sizeof(bits));
    break;
  }
  case SV_STRING:
  case SV_OCTETS: {
    if (sv.len > STR_CAP || len < kScriptValueSize + sv.len) {
      return false;
    }
    out.type = (sm_attr_type_t)sv.type;
    out.v.bytes.len = (uint8_t)sv.len;
    memcpy(out.v.bytes.buf, in + kScriptValueSize, sv.len);
    break;
  }
  default:
    return false;
  }
  return true;
}

// ---- module "sm" の実体 ------------------------------------------------------

int32_t host_attr_get(void *, int32_t ep, int32_t cluster, int32_t attr, uint8_t *out,
                      uint32_t cap) {
  sm_attr_value_t v{};
  const int32_t rc = sm_attr_get_value((uint16_t)ep, (uint32_t)cluster, (uint32_t)attr, &v);
  if (rc != 0) {
    // シムの戻り値(-2 = クラスタ無し、-3 = 属性非対応)をそのまま伝える。
    return rc;
  }
  return encode_value(v, out, cap);
}

int32_t host_attr_set(void *, int32_t ep, int32_t cluster, int32_t attr, const uint8_t *val,
                      uint32_t len) {
  sm_attr_value_t v{};
  if (!decode_value(val, len, v)) {
    return SCRIPT_ERR_TYPE;
  }
  return sm_attr_set_value((uint16_t)ep, (uint32_t)cluster, (uint32_t)attr, &v);
}

int32_t host_gpio_write(void *, int32_t pin, int32_t value) {
  if (pin < 0 || pin >= GPIO_NUM_MAX) {
    return SCRIPT_ERR_ARG;
  }
  gpio_config_t io{};
  io.pin_bit_mask = 1ULL << pin;
  io.mode = GPIO_MODE_OUTPUT;
  if (gpio_config(&io) != ESP_OK) {
    return SCRIPT_ERR_HW;
  }
  return gpio_set_level((gpio_num_t)pin, value ? 1 : 0) == ESP_OK ? SCRIPT_OK : SCRIPT_ERR_HW;
}

int32_t host_gpio_read(void *, int32_t pin) {
  if (pin < 0 || pin >= GPIO_NUM_MAX) {
    return SCRIPT_ERR_ARG;
  }
  return gpio_get_level((gpio_num_t)pin) != 0 ? 1 : 0;
}

int32_t host_pwm_set(void *, int32_t ch, int32_t duty) {
  // ledc バインディング(drv=3)が設定済みのチャネルに対してだけ意味を持つ
  // (タイマ・ピンの割り当ては binding TLV の責務。§9.2)。
  if (ch < 0 || ch >= LEDC_CHANNEL_MAX || duty < 0) {
    return SCRIPT_ERR_ARG;
  }
  const uint32_t max_duty = (1u << 10) - 1u; // bindings.cpp と同じ 10bit 分解能
  uint32_t d = (uint32_t)duty;
  if (d > max_duty) {
    d = max_duty;
  }
  if (ledc_set_duty(LEDC_LOW_SPEED_MODE, (ledc_channel_t)ch, d) != ESP_OK) {
    return SCRIPT_ERR_HW;
  }
  return ledc_update_duty(LEDC_LOW_SPEED_MODE, (ledc_channel_t)ch) == ESP_OK ? SCRIPT_OK
                                                                             : SCRIPT_ERR_HW;
}

void host_log(void *, const char *msg, uint32_t len) {
  ESP_LOGI(TAG, "script: %.*s", (int)len, msg);
}

// NVS キーは 15 文字まで。スクリプト側の任意バイト列を NUL 終端文字列にする。
bool make_key(const char *key, uint32_t key_len, char *out, size_t cap) {
  if (key_len == 0 || key_len >= cap) {
    return false;
  }
  for (uint32_t i = 0; i < key_len; i++) {
    if (key[i] == '\0') {
      return false;
    }
    out[i] = key[i];
  }
  out[key_len] = '\0';
  return true;
}

int32_t host_kvs_get(void *, const char *key, uint32_t key_len, uint8_t *out, uint32_t cap) {
  char k[16];
  if (!make_key(key, key_len, k, sizeof(k))) {
    return SCRIPT_ERR_ARG;
  }
  nvs_handle_t h;
  if (nvs_open(kScriptNvs, NVS_READONLY, &h) != ESP_OK) {
    return SCRIPT_ERR_NOTFOUND;
  }
  size_t len = 0;
  if (nvs_get_blob(h, k, nullptr, &len) != ESP_OK) {
    nvs_close(h);
    return SCRIPT_ERR_NOTFOUND;
  }
  if (len > cap) {
    nvs_close(h);
    return (int32_t)len; // 実長を返す(呼び出し側が NoSpace を検出)
  }
  size_t rd = cap;
  const esp_err_t err = nvs_get_blob(h, k, out, &rd);
  nvs_close(h);
  return err == ESP_OK ? (int32_t)rd : SCRIPT_ERR_NOTFOUND;
}

int32_t host_kvs_set(void *, const char *key, uint32_t key_len, const uint8_t *val, uint32_t len) {
  char k[16];
  if (!make_key(key, key_len, k, sizeof(k))) {
    return SCRIPT_ERR_ARG;
  }
  nvs_handle_t h;
  if (nvs_open(kScriptNvs, NVS_READWRITE, &h) != ESP_OK) {
    return SCRIPT_ERR_HW;
  }
  esp_err_t err = nvs_set_blob(h, k, val, len);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK ? SCRIPT_OK : SCRIPT_ERR_HW;
}

// ---- パーティションからのロード ----------------------------------------------

// スロット s のヘッダを読み、CRC まで検証して本体を buf に置く。成功で true。
bool read_slot(const esp_partition_t *part, size_t s, uint8_t *buf, size_t cap, ScriptHeader &h) {
  const size_t off = script_slot_offset(s);
  if (off + kScriptHdrSize > part->size) {
    return false;
  }
  uint8_t hdr[kScriptHdrSize];
  if (esp_partition_read(part, off, hdr, sizeof(hdr)) != ESP_OK) {
    return false;
  }
  if (!script_hdr_parse(hdr, sizeof(hdr), h)) {
    return false; // 未書き込み(0xFF 埋め)を含む
  }
  if (h.len > cap || off + kScriptHdrSize + h.len > part->size) {
    ESP_LOGW(TAG, "slot %u: script too large (%u B > %u B buffer)", (unsigned)s, (unsigned)h.len,
             (unsigned)cap);
    return false;
  }
  if (esp_partition_read(part, off + kScriptHdrSize, buf, h.len) != ESP_OK) {
    return false;
  }
  const uint32_t crc = script_crc32(buf, h.len);
  if (crc != h.crc32) {
    ESP_LOGW(TAG, "slot %u: CRC mismatch (%08x != %08x)", (unsigned)s, (unsigned)crc,
             (unsigned)h.crc32);
    return false;
  }
  return true;
}

// active slot(妥当なスロットのうち ver 最大。同値なら A)を選び、本体を buf に読む。
// 無ければ -1。
int load_active(const esp_partition_t *part, uint8_t *buf, size_t cap, uint16_t &ver,
                uint32_t &len) {
  int best = -1;
  ScriptHeader best_hdr;
  // まずヘッダだけ見て active を決める(本体の読み出しは 1 回で済ませる)。
  for (size_t s = 0; s < kScriptSlots; s++) {
    ScriptHeader h;
    if (!read_slot(part, s, buf, cap, h)) {
      continue;
    }
    if (best < 0 || h.ver > best_hdr.ver) {
      best = (int)s;
      best_hdr = h;
    }
  }
  if (best < 0) {
    return -1;
  }
  ScriptHeader h;
  if (!read_slot(part, (size_t)best, buf, cap, h)) {
    return -1; // 直前に検証済みなので通常起きない
  }
  ver = h.ver;
  len = h.len;
  return best;
}

ScriptHostOps make_ops() {
  ScriptHostOps ops;
  ops.user = nullptr;
  ops.attr_get = host_attr_get;
  ops.attr_set = host_attr_set;
  ops.gpio_write = host_gpio_write;
  ops.gpio_read = host_gpio_read;
  ops.pwm_set = host_pwm_set;
  ops.log = host_log;
  ops.kvs_get = host_kvs_get;
  ops.kvs_set = host_kvs_set;
  ops.watchdog_arm = wdt_arm;
  ops.watchdog_disarm = wdt_disarm;
  return ops;
}

} // namespace

bool script_init() {
  const esp_partition_t *part = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x40, CONFIG_SM_SCRIPT_PARTITION);
  if (part == nullptr) {
    ESP_LOGI(TAG, "no '%s' partition; scripting disabled", CONFIG_SM_SCRIPT_PARTITION);
    return false;
  }

  // 読み出しバッファはロードの間だけ確保する(バイトコードは script_vm_start が
  // プールへ複製するので、起動後は不要)。
  const size_t img_cap = (size_t)CONFIG_SM_SCRIPT_MAX_KB * 1024;
  uint8_t *img = (uint8_t *)heap_caps_malloc(img_cap, MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
  if (img == nullptr) {
    ESP_LOGE(TAG, "cannot allocate %u B script read buffer", (unsigned)img_cap);
    return false;
  }
  uint16_t ver = 0;
  uint32_t len = 0;
  const int slot = load_active(part, img, img_cap, ver, len);
  if (slot < 0) {
    ESP_LOGI(TAG, "no valid script image in '%s' (device runs without script)", part->label);
    heap_caps_free(img);
    return false;
  }

#if !CONFIG_SM_SCRIPT_POOL_STATIC
  // ここで初めてプールを確保する(スクリプトを積んでいないデバイスは 0 バイト)。
  if (g_pool == nullptr) {
    g_pool = (uint8_t *)heap_caps_aligned_alloc(8, kPoolSize, MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
  }
  if (g_pool == nullptr) {
    ESP_LOGE(TAG, "cannot allocate %u KB WAMR pool (free heap %u B); running without script",
             (unsigned)(kPoolSize / 1024), (unsigned)esp_get_free_heap_size());
    heap_caps_free(img);
    return false;
  }
#endif

  ScriptVmConfig cfg;
  cfg.heap_pool = g_pool;
  cfg.heap_pool_size = (uint32_t)kPoolSize;
  cfg.stack_size = CONFIG_SM_SCRIPT_STACK_KB * 1024;
  cfg.app_heap_size = 0;
  cfg.hook_budget_ms = CONFIG_SM_SCRIPT_BUDGET_MS;
  cfg.max_timers = kScriptMaxTimers;

  char err[128] = {0};
  const ScriptHostOps ops = make_ops();
  const bool ok = script_vm_start(img, len, cfg, ops, err, sizeof(err));
  heap_caps_free(img); // バイトコードはプール上に複製済み
  if (!ok) {
    ESP_LOGE(TAG, "script load failed (slot %d, ver %u, %u B): %s", slot, (unsigned)ver,
             (unsigned)len, err);
#if !CONFIG_SM_SCRIPT_POOL_STATIC
    heap_caps_free(g_pool);
    g_pool = nullptr;
#endif
    return false;
  }
  g_slot = slot;
  g_ver = ver;
  g_len = len;
  ESP_LOGI(TAG, "script loaded: slot %d ver %u (%u B), pool %u KB, budget %d ms, free heap %u B",
           slot, (unsigned)ver, (unsigned)len, (unsigned)(kPoolSize / 1024),
           CONFIG_SM_SCRIPT_BUDGET_MS, (unsigned)esp_get_free_heap_size());
  script_on_boot();
  return true;
}

void script_poll(uint64_t now_ms) {
  if (script_vm_active()) {
    script_vm_poll(now_ms);
  }
}

void script_notify_attr_write(uint16_t ep, uint32_t cluster, uint32_t attr) {
  if (!script_vm_active()) {
    return;
  }
  const int32_t rc = script_on_attr_write((int32_t)ep, (int32_t)cluster, (int32_t)attr);
  if (rc != 0) {
    // 現行シムに「IM write を拒否する」口が無いため観測のみ(§9.3 / README)。
    ESP_LOGW(TAG, "on_attr_write returned %d (observed only; write already applied)", (int)rc);
  }
}

void script_notify_sensor(int32_t bind_index) {
  if (script_vm_active()) {
    script_on_sensor(bind_index);
  }
}

void script_log_status() {
  if (!script_vm_active()) {
    ESP_LOGI(TAG, "script: none");
    return;
  }
  const ScriptVmStats &s = script_vm_stats();
  ESP_LOGI(TAG, "script: slot %d ver %u (%u B) calls=%u traps=%u timeouts=%u last_err=%s", g_slot,
           (unsigned)g_ver, (unsigned)g_len, (unsigned)s.calls, (unsigned)s.traps,
           (unsigned)s.timeouts, script_vm_last_error());
}

} // namespace smgen

#else // !CONFIG_SM_SCRIPT_ENABLE

namespace smgen {

bool script_init() { return false; }
void script_poll(uint64_t) {}
void script_notify_attr_write(uint16_t, uint32_t, uint32_t) {}
void script_notify_sensor(int32_t) {}
void script_log_status() { ESP_LOGI("smgen_script", "script: disabled at build time"); }

} // namespace smgen

#endif
