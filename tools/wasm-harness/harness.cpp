// WASM スクリプトフックの Linux ホスト検証ハーネス(§9.3 のゲート)。
//
//   ./sm_wasm_harness <momentary_toggle.wasm>
//
// ファームと同一の `script_vm.cpp` を使い、`sm` ホスト import をメモリ上のモックで
// 差し替えて、以下を検証する:
//
//   1. on_boot            → log と KVS 読み出しが走る
//   2. on_sensor(押下)   → attr_get(BooleanState) → attr_set(OnOff) のトグル + KVS 更新
//   3. timer_after/on_timer → 長押し 1 秒で強制 OFF
//   4. timer_cancel       → 離すと長押しが発火しない
//   5. on_attr_write      → 戻り値 0(承認)
//   6. 暴走スクリプト     → 壁時計上限で wasm_runtime_terminate が効き、その後も
//                           ランタイムが使える(trap を数える)
//
// 失敗は最初の 1 件で非 0 終了する。

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "script_abi.hpp"
#include "script_img.hpp"
#include "script_vm.hpp"

using namespace smgen;

namespace {

int g_failures = 0;

#define CHECK(cond, ...)                                                                           \
  do {                                                                                             \
    if (!(cond)) {                                                                                 \
      printf("FAIL %s:%d: ", __FILE__, __LINE__);                                                  \
      printf(__VA_ARGS__);                                                                         \
      printf("\n");                                                                                \
      g_failures++;                                                                                \
    }                                                                                              \
  } while (0)

// ---- モックホスト -----------------------------------------------------------

struct AttrKey {
  int32_t ep, cluster, attr;
  bool operator<(const AttrKey &o) const {
    if (ep != o.ep) return ep < o.ep;
    if (cluster != o.cluster) return cluster < o.cluster;
    return attr < o.attr;
  }
};

struct Mock {
  std::map<AttrKey, std::vector<uint8_t>> attrs; // 16B(+本体)レコード
  std::map<std::string, std::vector<uint8_t>> kvs;
  std::map<int32_t, int32_t> gpio;
  std::map<int32_t, int32_t> pwm;
  std::vector<std::string> logs;
  int attr_sets = 0;

  void set_scalar(int32_t ep, int32_t cluster, int32_t attr, uint8_t type, uint64_t bits) {
    ScriptValue sv;
    sv.type = type;
    sv.bits = bits;
    std::vector<uint8_t> rec(kScriptValueSize);
    script_value_encode(rec.data(), sv);
    attrs[AttrKey{ep, cluster, attr}] = rec;
  }

  bool get_bool(int32_t ep, int32_t cluster, int32_t attr) const {
    auto it = attrs.find(AttrKey{ep, cluster, attr});
    if (it == attrs.end()) return false;
    ScriptValue sv;
    script_value_decode(it->second.data(), it->second.size(), sv);
    return (sv.bits & 1) != 0;
  }

  bool logged(const char *needle) const {
    for (const auto &l : logs) {
      if (l.find(needle) != std::string::npos) return true;
    }
    return false;
  }
};

Mock g_mock;

int32_t m_attr_get(void *, int32_t ep, int32_t cluster, int32_t attr, uint8_t *out, uint32_t cap) {
  auto it = g_mock.attrs.find(AttrKey{ep, cluster, attr});
  if (it == g_mock.attrs.end()) {
    return SCRIPT_ERR_NOTFOUND;
  }
  if (cap < it->second.size()) {
    return SCRIPT_ERR_NOSPACE;
  }
  memcpy(out, it->second.data(), it->second.size());
  return (int32_t)it->second.size();
}

int32_t m_attr_set(void *, int32_t ep, int32_t cluster, int32_t attr, const uint8_t *val,
                   uint32_t len) {
  ScriptValue sv;
  if (!script_value_decode(val, len, sv)) {
    return SCRIPT_ERR_TYPE;
  }
  g_mock.attrs[AttrKey{ep, cluster, attr}] = std::vector<uint8_t>(val, val + len);
  g_mock.attr_sets++;
  return SCRIPT_OK;
}

int32_t m_gpio_write(void *, int32_t pin, int32_t v) {
  g_mock.gpio[pin] = v ? 1 : 0;
  return SCRIPT_OK;
}
int32_t m_gpio_read(void *, int32_t pin) {
  auto it = g_mock.gpio.find(pin);
  return it == g_mock.gpio.end() ? 0 : it->second;
}
int32_t m_pwm_set(void *, int32_t ch, int32_t duty) {
  g_mock.pwm[ch] = duty;
  return SCRIPT_OK;
}
void m_log(void *, const char *msg, uint32_t len) {
  std::string s(msg, msg + len);
  printf("  [script] %s\n", s.c_str());
  g_mock.logs.push_back(s);
}
int32_t m_kvs_get(void *, const char *key, uint32_t key_len, uint8_t *out, uint32_t cap) {
  auto it = g_mock.kvs.find(std::string(key, key + key_len));
  if (it == g_mock.kvs.end()) {
    return SCRIPT_ERR_NOTFOUND;
  }
  if (it->second.size() > cap) {
    return (int32_t)it->second.size();
  }
  memcpy(out, it->second.data(), it->second.size());
  return (int32_t)it->second.size();
}
int32_t m_kvs_set(void *, const char *key, uint32_t key_len, const uint8_t *val, uint32_t len) {
  g_mock.kvs[std::string(key, key + key_len)] = std::vector<uint8_t>(val, val + len);
  return SCRIPT_OK;
}

// 壁時計監視(デバイスの esp_timer ワンショットに相当)。arm 時の世代番号を持つ
// スレッドを立て、期限までに disarm されなければ terminate する。
std::atomic<uint64_t> g_wdt_gen{0};

void m_wdt_arm(void *, uint32_t ms) {
  const uint64_t gen = g_wdt_gen.fetch_add(1) + 1;
  std::thread([gen, ms]() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
      if (g_wdt_gen.load() != gen) {
        return; // disarm / 別のフックで張り替えられた
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (g_wdt_gen.load() == gen) {
      printf("  [wdt] budget exceeded -> terminate\n");
      script_vm_terminate();
    }
  }).detach();
}

void m_wdt_disarm(void *) { g_wdt_gen.fetch_add(1); }

ScriptHostOps mock_ops() {
  ScriptHostOps ops;
  ops.attr_get = m_attr_get;
  ops.attr_set = m_attr_set;
  ops.gpio_write = m_gpio_write;
  ops.gpio_read = m_gpio_read;
  ops.pwm_set = m_pwm_set;
  ops.log = m_log;
  ops.kvs_get = m_kvs_get;
  ops.kvs_set = m_kvs_set;
  ops.watchdog_arm = m_wdt_arm;
  ops.watchdog_disarm = m_wdt_disarm;
  return ops;
}

// 128KB の静的プール(デバイスの CONFIG_SM_SCRIPT_POOL_KB 相当)。
alignas(8) uint8_t g_pool[128 * 1024];

std::vector<uint8_t> read_file(const char *path) {
  std::vector<uint8_t> out;
  FILE *f = fopen(path, "rb");
  if (f == nullptr) {
    return out;
  }
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    out.insert(out.end(), buf, buf + n);
  }
  fclose(f);
  return out;
}

// 無限ループする最小 WASM モジュール(手組み。`on_boot` が `loop br 0 end`)。
// wat 相当: (module (func (export "on_boot") (loop (br 0))))
const uint8_t kSpinWasm[] = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,             // magic + version
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,                         // type: () -> ()
    0x03, 0x02, 0x01, 0x00,                                     // func: 1 個(type 0)
    0x07, 0x0b, 0x01, 0x07, 'o', 'n', '_', 'b', 'o', 'o', 't',  // export "on_boot"
    0x00, 0x00,                                                 //   kind=func idx=0
    0x0a, 0x09, 0x01, 0x07, 0x00,                               // code: 1 本、本体 7B、local 0
    0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b,                         //   loop(void) br 0 end end
};

ScriptVmConfig vm_config(uint32_t budget_ms) {
  ScriptVmConfig cfg;
  cfg.heap_pool = g_pool;
  cfg.heap_pool_size = sizeof(g_pool);
  cfg.stack_size = 8 * 1024;
  cfg.app_heap_size = 0;
  cfg.hook_budget_ms = budget_ms;
  cfg.max_timers = kScriptMaxTimers;
  return cfg;
}

// ---- テスト 1: momentary-toggle のラウンドトリップ ---------------------------

void test_momentary_toggle(const std::vector<uint8_t> &wasm) {
  printf("== momentary-toggle round trip\n");
  g_mock = Mock{};
  // 初期状態: EP1 OnOff=false、BooleanState=false。
  g_mock.set_scalar(1, 0x0006, 0x0000, SV_BOOL, 0);
  g_mock.set_scalar(1, 0x0045, 0x0000, SV_BOOL, 0);

  char err[128] = {0};
  const bool started = script_vm_start(wasm.data(), wasm.size(), vm_config(200), mock_ops(), err,
                                       sizeof(err));
  CHECK(started, "script_vm_start failed: %s", err);
  if (!started) {
    return;
  }
  CHECK(script_vm_active(), "vm should be active");

  // 1. on_boot
  script_vm_poll(0);
  script_on_boot();
  CHECK(g_mock.logged("momentary-toggle ready"), "on_boot did not log");

  // 2. 押下エッジ → OnOff トグル(false -> true)
  g_mock.set_scalar(1, 0x0045, 0x0000, SV_BOOL, 1);
  script_vm_poll(100);
  script_on_sensor(0);
  CHECK(g_mock.get_bool(1, 0x0006, 0x0000), "press should turn OnOff on");
  CHECK(g_mock.logged("press: off -> on"), "press log missing");
  CHECK(g_mock.kvs.count("cnt") == 1, "press count should be persisted");
  CHECK(g_mock.kvs["cnt"].size() == 4 && g_mock.kvs["cnt"][0] == 1, "press count should be 1");

  // 3. 押しっぱなし 1 秒 → on_timer(1) で強制 OFF
  script_vm_poll(1000);  // まだ期限前(押下は t=100)
  CHECK(g_mock.get_bool(1, 0x0006, 0x0000), "OnOff should still be on before 1s");
  script_vm_poll(1101); // 100 + 1000
  CHECK(!g_mock.get_bool(1, 0x0006, 0x0000), "long press should force OnOff off");
  CHECK(g_mock.logged("long press: forced off"), "long press log missing");

  // 4. 離す → 次の押下でトグル、長押しタイマは取り消される
  g_mock.set_scalar(1, 0x0045, 0x0000, SV_BOOL, 0);
  script_on_sensor(0);
  g_mock.set_scalar(1, 0x0045, 0x0000, SV_BOOL, 1);
  script_vm_poll(2000);
  script_on_sensor(0);
  CHECK(g_mock.get_bool(1, 0x0006, 0x0000), "second press should turn OnOff on");
  CHECK(g_mock.kvs["cnt"][0] == 2, "press count should be 2");
  g_mock.set_scalar(1, 0x0045, 0x0000, SV_BOOL, 0);
  script_on_sensor(0); // 離した = timer_cancel
  const bool on_before = g_mock.get_bool(1, 0x0006, 0x0000);
  script_vm_poll(4000); // 長押し期限を大きく超えて進める
  CHECK(g_mock.get_bool(1, 0x0006, 0x0000) == on_before,
        "cancelled long-press timer must not fire");

  // 5. on_attr_write は 0(承認)を返す
  const int32_t rc = script_on_attr_write(1, 0x0006, 0x0000);
  CHECK(rc == 0, "on_attr_write should return 0, got %d", (int)rc);
  CHECK(g_mock.logged("on_off changed by controller"), "attr_write log missing");

  // 6. 未実装フック(on_command)は no-op で 0
  CHECK(script_on_command(1, 0x0006, 2) == 0, "missing hook must be a no-op");

  const ScriptVmStats &st = script_vm_stats();
  printf("  stats: calls=%u traps=%u timeouts=%u\n", st.calls, st.traps, st.timeouts);
  CHECK(st.traps == 0, "no trap expected, got %u", st.traps);
  CHECK(st.timeouts == 0, "no timeout expected, got %u", st.timeouts);
  script_vm_stop();
  CHECK(!script_vm_active(), "vm should be stopped");
}

// ---- テスト 2: 暴走スクリプトの打ち切り ---------------------------------------

void test_runaway_is_terminated() {
  printf("== runaway hook is terminated by the wall-clock budget\n");
  g_mock = Mock{};
  char err[128] = {0};
  const bool started =
      script_vm_start(kSpinWasm, sizeof(kSpinWasm), vm_config(50), mock_ops(), err, sizeof(err));
  CHECK(started, "spin module failed to load: %s", err);
  if (!started) {
    return;
  }
  const auto t0 = std::chrono::steady_clock::now();
  script_on_boot(); // 無限ループ。50ms 後に terminate されて返るはず。
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
          .count();
  printf("  hook returned after %" PRId64 " ms\n", (int64_t)ms);
  CHECK(ms < 3000, "runaway hook did not return in time (%" PRId64 " ms)", (int64_t)ms);
  const ScriptVmStats &st = script_vm_stats();
  CHECK(st.traps == 1, "expected 1 trap, got %u", st.traps);
  CHECK(st.timeouts == 1, "expected 1 timeout, got %u", st.timeouts);
  printf("  last error: %s\n", script_vm_last_error());
  script_vm_stop();
}

// ---- テスト 3: 値の 16B レイアウトとイメージヘッダ -----------------------------

void test_value_layout_and_header() {
  printf("== 16B value layout / SMWS header\n");
  ScriptValue sv;
  sv.type = SV_I16;
  sv.bits = (uint64_t)(int64_t)-4500;
  uint8_t rec[kScriptValueSize];
  script_value_encode(rec, sv);
  CHECK(rec[0] == SV_I16 && rec[1] == 0 && rec[2] == 0 && rec[3] == 0, "header bytes");
  ScriptValue back;
  CHECK(script_value_decode(rec, sizeof(rec), back), "decode");
  CHECK((int64_t)back.bits == -4500, "sign extension lost");

  uint8_t hdr[kScriptHdrSize];
  ScriptHeader h;
  h.ver = 7;
  h.len = 4;
  const uint8_t body[4] = {1, 2, 3, 4};
  h.crc32 = script_crc32(body, sizeof(body));
  script_hdr_write(hdr, h);
  ScriptHeader parsed;
  CHECK(script_hdr_parse(hdr, sizeof(hdr), parsed), "header parse");
  CHECK(parsed.ver == 7 && parsed.len == 4 && parsed.crc32 == h.crc32, "header roundtrip");
  // CRC-32/IEEE の既知ベクタ("123456789" = 0xCBF43926)。
  CHECK(script_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u, "crc32 test vector");
  hdr[0] = 'X';
  CHECK(!script_hdr_parse(hdr, sizeof(hdr), parsed), "bad magic must be rejected");
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2) {
    printf("usage: %s <momentary_toggle.wasm>\n", argv[0]);
    return 2;
  }
  const std::vector<uint8_t> wasm = read_file(argv[1]);
  if (wasm.empty()) {
    printf("FAIL cannot read %s\n", argv[1]);
    return 2;
  }
  printf("script: %s (%zu B)\n", argv[1], wasm.size());

  test_value_layout_and_header();
  test_momentary_toggle(wasm);
  test_runaway_is_terminated();

  if (g_failures == 0) {
    printf("WASM HARNESS OK\n");
    return 0;
  }
  printf("WASM HARNESS FAILED (%d checks)\n", g_failures);
  return 1;
}
