// ScriptStore(Phase D / G4、docs/design/generic-firmware.md §9.4)のホストループバック。
//
// 同一プロセスでデバイス側シム(composition = EP1 OnOff ライト + **ScriptStore vendor
// クラスタ 0xFFF1FC01**)と既存コントローラ(sm_ctrl_*、F7a)を初期化し、UDP datagram を
// メモリ渡しでループバックして C レベルで検証する:
//
//   pairing → 属性 read(State/ActiveSlot/Version/ChunkMax)
//     → Begin → Data ×N → Commit → 再ロード → スロット内容と CRC の一致
//     → 2 回目の転送が反対スロットへ行く(A ↔ B)
//     → 順不同 Data / サイズ不足 Commit / CRC 不一致が弾かれる
//     → ロード失敗時に旧スロットへロールバックする
//     → on_command 通知(§9.3 で未接続だったフックの配線)が鳴る
//
// **受信ステートマシンはファームと同一コード**(generic_matter_cpp/main/script_store.hpp)。
// esp_partition の代わりにメモリ backend を注入する(§9.4 のゲート)。
//
// 使い方:
//   ./scriptstore_loopback --dev-dir <dir> --ctrl-dir <dir> [-v]

#include "simple_matter.h"

#include "script_img.hpp"
#include "script_store.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace {

bool g_verbose = false;
std::string g_dev_dir, g_ctrl_dir;

const uint32_t CL_IDENTIFY = 0x0003;
const uint32_t CL_GROUPS = 0x0004;
const uint32_t CL_ONOFF = 0x0006;
const uint16_t EP_STORE = 1;

sm_addr_t make_addr(const char *ip, uint16_t port) {
  sm_addr_t a;
  memset(&a, 0, sizeof(a));
  a.port = port;
  a.is_v6 = false;
  inet_pton(AF_INET, ip, a.ip);
  return a;
}

uint64_t now_ms() {
  static struct timespec start = [] {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t;
  }();
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  uint64_t n = (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
  uint64_t s = (uint64_t)start.tv_sec * 1000000000ull + (uint64_t)start.tv_nsec;
  return (n - s) / 1000000ull;
}

// ---- ファイルベース KVS ------------------------------------------------------

std::string key_path(const std::string &dir, const char *key) {
  std::string p = dir + "/";
  for (const unsigned char *k = (const unsigned char *)key; *k; ++k) {
    char b[3];
    snprintf(b, sizeof(b), "%02x", *k);
    p += b;
  }
  return p + ".bin";
}

int32_t kvs_get_dir(const std::string &dir, const char *key, uint8_t *buf, size_t cap) {
  FILE *f = fopen(key_path(dir, key).c_str(), "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0) { fclose(f); return -1; }
  if ((size_t)sz <= cap) { size_t g = fread(buf, 1, (size_t)sz, f); (void)g; }
  fclose(f);
  return (int32_t)sz;
}
int32_t kvs_set_dir(const std::string &dir, const char *key, const uint8_t *val, size_t len) {
  FILE *f = fopen(key_path(dir, key).c_str(), "wb");
  if (!f) return -1;
  size_t w = (len == 0) ? 0 : fwrite(val, 1, len, f);
  fclose(f);
  return (w == len) ? 0 : -1;
}
int32_t kvs_del_dir(const std::string &dir, const char *key) {
  if (unlink(key_path(dir, key).c_str()) != 0 && errno != ENOENT) return -1;
  return 0;
}

extern "C" int32_t dev_kvs_get(void *, const char *k, uint8_t *b, size_t c) { return kvs_get_dir(g_dev_dir, k, b, c); }
extern "C" int32_t dev_kvs_set(void *, const char *k, const uint8_t *v, size_t l) { return kvs_set_dir(g_dev_dir, k, v, l); }
extern "C" int32_t dev_kvs_del(void *, const char *k) { return kvs_del_dir(g_dev_dir, k); }
extern "C" int32_t ctrl_kvs_get(void *, const char *k, uint8_t *b, size_t c) { return kvs_get_dir(g_ctrl_dir, k, b, c); }
extern "C" int32_t ctrl_kvs_set(void *, const char *k, const uint8_t *v, size_t l) { return kvs_set_dir(g_ctrl_dir, k, v, l); }
extern "C" int32_t ctrl_kvs_del(void *, const char *k) { return kvs_del_dir(g_ctrl_dir, k); }

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = getrandom(buf + off, len - off, 0);
    if (n <= 0) { for (; off < len; ++off) buf[off] = (uint8_t)(rand() & 0xFF); return; }
    off += (size_t)n;
  }
}

extern "C" void on_cluster_change(void *, uint16_t, uint32_t, uint32_t, const sm_attr_value_t *) {}

// ---- メモリ backend(esp_partition の代役)------------------------------------
//
// フラッシュの意味論を真似る: 消去は 4KB 単位で 0xFF、書き込みは「消去済みの領域にしか
// 書けない」(二重書きをテストが検出できるようにする)。

uint8_t g_flash[smgen::kScriptSlots][smgen::kScriptSlotSize];
// 「ロード済みイメージ」= 再ロードのたびに active slot から複製する。
std::vector<uint8_t> g_loaded;
int g_loaded_slot = -1;
uint16_t g_loaded_ver = 0;
unsigned g_reloads = 0;
bool g_fail_reload = false;   // ロード失敗を模擬する(ロールバック検証)
unsigned g_on_command = 0;    // on_command 通知の回数

bool be_erase(void *, size_t slot, size_t len) {
  if (slot >= smgen::kScriptSlots) return false;
  size_t n = ((len + 4095) / 4096) * 4096;
  if (n > smgen::kScriptSlotSize) n = smgen::kScriptSlotSize;
  memset(g_flash[slot], 0xFF, n);
  return true;
}

bool be_write(void *, size_t slot, size_t off, const uint8_t *data, size_t len) {
  if (slot >= smgen::kScriptSlots || off + len > smgen::kScriptSlotSize) return false;
  if ((off % 4) != 0 || (len % 4) != 0) {
    fprintf(stderr, "backend: unaligned write off=%zu len=%zu\n", off, len);
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    if (g_flash[slot][off + i] != 0xFF) {
      fprintf(stderr, "backend: write over un-erased byte at %zu\n", off + i);
      return false;
    }
  }
  memcpy(g_flash[slot] + off, data, len);
  return true;
}

bool be_read(void *, size_t slot, size_t off, uint8_t *out, size_t len) {
  if (slot >= smgen::kScriptSlots || off + len > smgen::kScriptSlotSize) return false;
  memcpy(out, g_flash[slot] + off, len);
  return true;
}

// active slot(妥当ヘッダ + CRC 一致のうち ver 最大)を選んで「ロード」する。
// ファームの script_host::script_reload() と同じ規則。
bool be_reload(void *) {
  g_reloads++;
  int best = -1;
  smgen::ScriptHeader best_h;
  for (size_t s = 0; s < smgen::kScriptSlots; s++) {
    smgen::ScriptHeader h;
    if (!smgen::script_hdr_parse(g_flash[s], smgen::kScriptHdrSize, h)) continue;
    if (smgen::kScriptHdrSize + h.len > smgen::kScriptSlotSize) continue;
    if (smgen::script_crc32(g_flash[s] + smgen::kScriptHdrSize, h.len) != h.crc32) continue;
    if (best < 0 || h.ver > best_h.ver) { best = (int)s; best_h = h; }
  }
  if (best < 0) {
    g_loaded.clear();
    g_loaded_slot = -1;
    g_loaded_ver = 0;
    return false;
  }
  if (g_fail_reload) {
    // 「ロードはできたが VM が受け付けなかった」= script_vm_start 失敗の模擬。
    return false;
  }
  g_loaded.assign(g_flash[best] + smgen::kScriptHdrSize,
                  g_flash[best] + smgen::kScriptHdrSize + best_h.len);
  g_loaded_slot = best;
  g_loaded_ver = best_h.ver;
  return true;
}

void be_mark_dirty(void *, uint32_t attr) { sm_attr_mark_dirty(EP_STORE, smgen::kClScriptStore, attr); }
void be_on_command(void *, uint32_t, uint32_t) { g_on_command++; }
void be_log(void *, const char *msg) {
  if (g_verbose) printf("  [store] %s\n", msg);
}

// ---- composition TLV blob(EP1 = OnOff ライト)---------------------------------

std::vector<uint8_t> build_composition() {
  std::vector<uint8_t> b;
  auto u8_ = [&](uint8_t t, uint8_t v) { b.push_back(0x24); b.push_back(t); b.push_back(v); };
  auto u16_ = [&](uint8_t t, uint16_t v) {
    b.push_back(0x25); b.push_back(t);
    b.push_back((uint8_t)(v & 0xFF)); b.push_back((uint8_t)(v >> 8));
  };
  auto u32_ = [&](uint8_t t, uint32_t v) {
    b.push_back(0x26); b.push_back(t);
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
  };
  auto u32a = [&](uint32_t v) {
    b.push_back(0x06);
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
  };
  b.push_back(0x17);            // list(anon)
  b.push_back(0x15);            // struct(anon)
  u16_(0, 1);                   // endpoint 1
  u32_(1, 0x0100);              // device type = OnOff light
  u8_(2, 3);
  b.push_back(0x36); b.push_back(3); // array(ctx 3) = clusters
  u32a(CL_IDENTIFY);
  u32a(CL_GROUPS);
  u32a(CL_ONOFF);
  b.push_back(0x18);
  b.push_back(0x18);
  b.push_back(0x18);
  return b;
}

// ---- 運用 UDP(in-memory passthrough)------------------------------------------

sm_addr_t DEV_ADDR, CTRL_ADDR;

struct Datagram { std::vector<uint8_t> buf; bool to_device; };

void ctrl_emit(std::vector<Datagram> &q, uint64_t now) {
  uint8_t tx[2048];
  sm_addr_t dst;
  size_t n;
  while ((n = sm_ctrl_poll(now, tx, sizeof(tx), &dst)) > 0)
    q.push_back({std::vector<uint8_t>(tx, tx + n), true});
}
void dev_emit(std::vector<Datagram> &q, uint64_t now) {
  uint8_t tx[2048];
  sm_addr_t dst;
  size_t n;
  while ((n = sm_poll(now, tx, sizeof(tx), &dst)) > 0)
    q.push_back({std::vector<uint8_t>(tx, tx + n), false});
}

void drain_queue(std::vector<Datagram> &q, uint64_t now) {
  int guard = 0;
  while (!q.empty() && guard++ < 4000) {
    Datagram d = q.front();
    q.erase(q.begin());
    uint8_t tx[2048];
    sm_addr_t dst;
    if (d.to_device) {
      size_t rn = sm_udp_rx(d.buf.data(), d.buf.size(), &CTRL_ADDR, now, tx, sizeof(tx), &dst);
      if (rn > 0) q.push_back({std::vector<uint8_t>(tx, tx + rn), false});
      dev_emit(q, now);
      // pump ループ相当: Commit で保留した再ロードをフックの外で実行する。
      smgen::script_store().poll();
    } else {
      size_t rn = sm_ctrl_udp_rx(d.buf.data(), d.buf.size(), &DEV_ADDR, now, tx, sizeof(tx), &dst);
      if (rn > 0) q.push_back({std::vector<uint8_t>(tx, tx + rn), true});
      ctrl_emit(q, now);
    }
  }
}

bool drive_until(sm_ctrl_event_kind_t want, sm_ctrl_event_kind_t wantfail, sm_ctrl_event_t *out) {
  uint64_t end = now_ms() + 20000;
  std::vector<Datagram> q;
  while (now_ms() < end) {
    uint64_t now = now_ms();
    ctrl_emit(q, now);
    dev_emit(q, now);
    drain_queue(q, now);
    smgen::script_store().poll();
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (g_verbose)
        printf("  [ctrl] kind=%d node=%#llx phase=%u status=0x%02x\n", (int)ev.kind,
               (unsigned long long)ev.node_id, ev.phase, ev.status);
      if (ev.kind == want) { if (out) *out = ev; return true; }
      if (ev.kind == wantfail) { if (out) *out = ev; return true; }
    }
    uint64_t ndc = sm_ctrl_next_deadline(now_ms());
    uint64_t ndd = sm_next_deadline(now_ms());
    uint64_t nd = (ndc < ndd) ? ndc : ndd;
    uint64_t cur = now_ms();
    if (nd == SM_NO_DEADLINE) {
      usleep(2000);
    } else if (nd > cur) {
      uint64_t w = nd - cur;
      if (w > 50) w = 50;
      usleep((useconds_t)(w * 1000));
    }
  }
  return false;
}

uint64_t g_node = 0x0000000AABBCCDDull;

// invoke を 1 本投げて IM ステータスを返す(-1 = 駆動失敗)。
int invoke_status(uint32_t cmd, const sm_attr_value_t *args, size_t n) {
  if (sm_ctrl_invoke_args(g_node, EP_STORE, smgen::kClScriptStore, cmd, args, n, now_ms()) != 0) {
    return -1;
  }
  sm_ctrl_event_t ev;
  memset(&ev, 0, sizeof(ev));
  if (!drive_until(SM_CTRL_EV_INVOKE_DONE, SM_CTRL_EV_INVOKE_FAILED, &ev)) return -1;
  return (int)ev.status;
}

int ss_begin(uint32_t size, uint32_t crc) {
  sm_attr_value_t a[2];
  memset(a, 0, sizeof(a));
  a[0].type = SM_T_U32;
  a[0].v.u = size;
  a[1].type = SM_T_U32;
  a[1].v.u = crc;
  return invoke_status(smgen::kSsCmdBegin, a, 2);
}

int ss_data(uint32_t off, const uint8_t *p, uint8_t len) {
  sm_attr_value_t a[2];
  memset(a, 0, sizeof(a));
  a[0].type = SM_T_U32;
  a[0].v.u = off;
  a[1].type = SM_T_OCTETS;
  a[1].v.bytes.len = len;
  memcpy(a[1].v.bytes.buf, p, len);
  return invoke_status(smgen::kSsCmdData, a, 2);
}

int ss_commit() { return invoke_status(smgen::kSsCmdCommit, nullptr, 0); }
int ss_abort() { return invoke_status(smgen::kSsCmdAbort, nullptr, 0); }

bool read_scalar(uint32_t attr, uint64_t *value) {
  if (sm_ctrl_read_scalar(g_node, EP_STORE, smgen::kClScriptStore, attr, now_ms()) != 0) return false;
  sm_ctrl_event_t ev;
  memset(&ev, 0, sizeof(ev));
  if (!drive_until(SM_CTRL_EV_READ_DONE, SM_CTRL_EV_READ_FAILED, &ev)) return false;
  if (ev.kind != SM_CTRL_EV_READ_DONE) return false;
  *value = ev.value_u64;
  return true;
}

// イメージ全体を Begin → Data ×N → Commit で送る。戻り値 = Commit のステータス。
// `bad_crc` = 宣言 CRC をわざと壊す。
int transfer(const std::vector<uint8_t> &body, bool bad_crc, uint32_t *chunks_out) {
  uint32_t crc = smgen::script_crc32(body.data(), body.size());
  if (bad_crc) crc ^= 0xA5A5A5A5u;
  int st = ss_begin((uint32_t)body.size(), crc);
  if (st != 0) {
    fprintf(stderr, "Begin status 0x%02x\n", st);
    return st;
  }
  uint32_t chunks = 0;
  for (size_t off = 0; off < body.size(); off += smgen::kSsChunkMax) {
    const size_t n = std::min((size_t)smgen::kSsChunkMax, body.size() - off);
    st = ss_data((uint32_t)off, body.data() + off, (uint8_t)n);
    if (st != 0) {
      fprintf(stderr, "Data(off=%zu) status 0x%02x\n", off, st);
      return st;
    }
    chunks++;
  }
  if (chunks_out) *chunks_out = chunks;
  return ss_commit();
}

// 疑似 .wasm ペイロード(内容は問わない。CRC と一致することだけを見る)。
std::vector<uint8_t> make_body(size_t len, uint8_t seed) {
  std::vector<uint8_t> b;
  b.reserve(len);
  const uint8_t magic[8] = {0x00, 'a', 's', 'm', 0x01, 0x00, 0x00, 0x00};
  for (size_t i = 0; i < len; i++) {
    b.push_back(i < sizeof(magic) ? magic[i] : (uint8_t)(i * 31u + seed));
  }
  return b;
}

bool slot_matches(int slot, const std::vector<uint8_t> &body, uint16_t ver) {
  smgen::ScriptHeader h;
  if (!smgen::script_hdr_parse(g_flash[slot], smgen::kScriptHdrSize, h)) {
    fprintf(stderr, "slot %d: header invalid\n", slot);
    return false;
  }
  if (h.ver != ver || h.len != body.size()) {
    fprintf(stderr, "slot %d: ver/len mismatch (ver=%u len=%u)\n", slot, h.ver, h.len);
    return false;
  }
  if (h.crc32 != smgen::script_crc32(body.data(), body.size())) {
    fprintf(stderr, "slot %d: header CRC mismatch\n", slot);
    return false;
  }
  if (memcmp(g_flash[slot] + smgen::kScriptHdrSize, body.data(), body.size()) != 0) {
    fprintf(stderr, "slot %d: body mismatch\n", slot);
    return false;
  }
  return true;
}

int run() {
  memset(g_flash, 0xFF, sizeof(g_flash));

  static const uint8_t kDevSalt[16] = {'S', 'P', 'A', 'K', 'E', '2', 'P', ' ', 'K', 'e', 'y', ' ', 'S', 'a', 'l', 't'};
  static const uint8_t kDevVerifierW0L[97] = {
      0x7d, 0x04, 0x77, 0x6b, 0xb4, 0x69, 0xc4, 0x94, 0x92, 0x28, 0x30, 0x14,
      0x4f, 0x3f, 0xa2, 0xf1, 0x9c, 0xfd, 0x82, 0xc0, 0x4d, 0x10, 0x8d, 0x8b,
      0xa6, 0x35, 0x3f, 0xdd, 0x92, 0xc0, 0x1f, 0x93, 0x04, 0x51, 0x1b, 0x6c,
      0x47, 0x65, 0xba, 0xb1, 0x47, 0x94, 0x9d, 0xd9, 0x42, 0xc4, 0x3b, 0x3d,
      0x8d, 0xc6, 0x32, 0x30, 0x89, 0xca, 0x31, 0x89, 0xd9, 0xe4, 0xa5, 0x63,
      0x6e, 0x16, 0xd8, 0x2f, 0x1a, 0xef, 0x72, 0x8b, 0x0d, 0x90, 0x2c, 0x1a,
      0x9b, 0x0f, 0x7e, 0x96, 0x52, 0xab, 0x7f, 0x65, 0x78, 0x61, 0xb6, 0xbb,
      0xac, 0xd6, 0xbf, 0xdf, 0x04, 0xf8, 0x07, 0x09, 0x24, 0x8b, 0x83, 0xde, 0xc7,
  };

  DEV_ADDR = make_addr("127.0.0.1", 5540);
  CTRL_ADDR = make_addr("127.0.0.1", 55000);

  // --- ScriptStore の登録(sm_init より前)---
  smgen::ScriptStoreBackend be;
  be.user = nullptr;
  be.erase = be_erase;
  be.write = be_write;
  be.read = be_read;
  be.reload = be_reload;
  be.mark_dirty = be_mark_dirty;
  be.on_command = be_on_command;
  be.log = be_log;
  smgen::script_store().configure(be, -1, 0); // スクリプト未搭載で起動
  const int reg = smgen::script_store_register(EP_STORE, smgen::script_store());
  if (reg != 0) {
    fprintf(stderr, "script_store_register rc=%d\n", reg);
    return 1;
  }

  std::vector<uint8_t> comp = build_composition();
  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.verifier_iterations = 2000;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.verifier_w0_l = kDevVerifierW0L;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "ScriptStoreDev";
  const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x78};
  memcpy(cfg.mac, mac, 6);
  cfg.kvs_get = dev_kvs_get;
  cfg.kvs_set = dev_kvs_set;
  cfg.kvs_delete = dev_kvs_del;
  cfg.rng_fill = rng_fill;
  cfg.network = SM_NET_ETHERNET;
  cfg.composition = comp.data();
  cfg.composition_len = comp.size();
  cfg.on_cluster_change = on_cluster_change;

  if (sm_init(&cfg, now_ms()) != 0) {
    fprintf(stderr, "sm_init failed\n");
    return 1;
  }
  uint8_t v4[4] = {127, 0, 0, 1};
  sm_set_addrs(v4, nullptr);
  printf("device ready: EP1 OnOff light + ScriptStore 0x%08x (chunk<=%u B)\n",
         (unsigned)smgen::kClScriptStore, (unsigned)smgen::kSsChunkMax);

  // --- コントローラ ---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = aligned_alloc(align, rounded);
  if (!mem) { fprintf(stderr, "aligned_alloc failed\n"); return 1; }
  sm_ctrl_config_t ccfg;
  memset(&ccfg, 0, sizeof(ccfg));
  ccfg.fabric_id = 0xFAB0000000000001ull;
  ccfg.controller_node_id = 0x0000000011223344ull;
  ccfg.vendor_id = 0xFFF1;
  ccfg.kvs_get = ctrl_kvs_get;
  ccfg.kvs_set = ctrl_kvs_set;
  ccfg.kvs_delete = ctrl_kvs_del;
  ccfg.rng_fill = rng_fill;
  if (sm_ctrl_init((uint8_t *)mem, rounded, &ccfg, now_ms()) != 0) {
    fprintf(stderr, "sm_ctrl_init failed\n");
    return 1;
  }

  if (sm_ctrl_pair_start(g_node, 20202021, &DEV_ADDR, now_ms()) != 0) {
    fprintf(stderr, "sm_ctrl_pair_start failed\n");
    return 1;
  }
  {
    sm_ctrl_event_t ev;
    memset(&ev, 0, sizeof(ev));
    if (!drive_until(SM_CTRL_EV_PAIR_COMPLETE, SM_CTRL_EV_PAIR_FAILED, &ev) ||
        ev.kind != SM_CTRL_EV_PAIR_COMPLETE) {
      fprintf(stderr, "pairing did not complete\n");
      return 1;
    }
  }
  printf("PAIR COMPLETE: fabrics=%u\n", sm_fabric_count());
  fflush(stdout);

  // --- 初期状態の read(IM 経由で ScriptStore の属性が見える)---
  uint64_t state = 0, slot = 0, ver = 0, chunk = 0;
  if (!read_scalar(smgen::kSsAttrState, &state) ||
      !read_scalar(smgen::kSsAttrActiveSlot, &slot) ||
      !read_scalar(smgen::kSsAttrVersion, &ver) ||
      !read_scalar(smgen::kSsAttrChunkMax, &chunk)) {
    fprintf(stderr, "attribute read failed\n");
    return 1;
  }
  if (state != smgen::SS_IDLE || slot != smgen::kSsNoSlot || ver != 0 ||
      chunk != smgen::kSsChunkMax) {
    fprintf(stderr, "initial attrs mismatch: state=%llu slot=%llu ver=%llu chunk=%llu\n",
            (unsigned long long)state, (unsigned long long)slot, (unsigned long long)ver,
            (unsigned long long)chunk);
    return 1;
  }
  printf("ATTRS OK: State=idle ActiveSlot=none Version=0 ChunkMax=%llu\n",
         (unsigned long long)chunk);

  // --- 転送 1 回目(slot A、ver 1)---
  std::vector<uint8_t> body1 = make_body(700, 0x11);
  uint32_t chunks = 0;
  int st = transfer(body1, false, &chunks);
  if (st != 0) { fprintf(stderr, "commit #1 status 0x%02x\n", st); return 1; }
  // Commit 後の VM 再ロードは pump 側(script_store().poll())で起きる。
  smgen::script_store().poll();
  if (smgen::script_store().state() != smgen::SS_IDLE) {
    fprintf(stderr, "state after commit #1 = %u\n", smgen::script_store().state());
    return 1;
  }
  if (!slot_matches(0, body1, 1)) return 1;
  if (g_loaded_slot != 0 || g_loaded != body1 || g_loaded_ver != 1) {
    fprintf(stderr, "reload #1 mismatch (slot=%d ver=%u %zu B)\n", g_loaded_slot, g_loaded_ver,
            g_loaded.size());
    return 1;
  }
  if (!read_scalar(smgen::kSsAttrActiveSlot, &slot) || !read_scalar(smgen::kSsAttrVersion, &ver) ||
      !read_scalar(smgen::kSsAttrState, &state)) {
    fprintf(stderr, "attribute read failed (after commit #1)\n");
    return 1;
  }
  if (slot != 0 || ver != 1 || state != smgen::SS_IDLE) {
    fprintf(stderr, "attrs after commit #1: slot=%llu ver=%llu state=%llu\n",
            (unsigned long long)slot, (unsigned long long)ver, (unsigned long long)state);
    return 1;
  }
  printf("TRANSFER #1 OK: %zu B in %u chunks -> slot A ver 1 (CRC verified, reloaded)\n",
         body1.size(), chunks);
  fflush(stdout);

  // --- 転送 2 回目(反対スロット B、ver 2。旧スロットは無傷)---
  std::vector<uint8_t> body2 = make_body(1301, 0x77);
  st = transfer(body2, false, &chunks);
  if (st != 0) { fprintf(stderr, "commit #2 status 0x%02x\n", st); return 1; }
  smgen::script_store().poll();
  if (!slot_matches(1, body2, 2)) return 1;
  if (!slot_matches(0, body1, 1)) { fprintf(stderr, "slot A was clobbered\n"); return 1; }
  if (g_loaded_slot != 1 || g_loaded != body2 || g_loaded_ver != 2) {
    fprintf(stderr, "reload #2 mismatch\n");
    return 1;
  }
  printf("TRANSFER #2 OK: %zu B in %u chunks -> slot B ver 2 (slot A intact)\n", body2.size(),
         chunks);
  fflush(stdout);

  // --- 順不同 Data は弾く / Abort で idle へ戻る ---
  std::vector<uint8_t> body3 = make_body(200, 0x33);
  if (ss_begin((uint32_t)body3.size(), smgen::script_crc32(body3.data(), body3.size())) != 0) {
    fprintf(stderr, "Begin #3 failed\n");
    return 1;
  }
  if (ss_data(64, body3.data(), 64) != 0x87) {
    fprintf(stderr, "out-of-order Data was not rejected\n");
    return 1;
  }
  if (ss_data(0, body3.data(), 64) != 0) { fprintf(stderr, "sequential Data failed\n"); return 1; }
  if (ss_commit() != 0x87) { fprintf(stderr, "short Commit was not rejected\n"); return 1; }
  if (ss_abort() != 0) { fprintf(stderr, "Abort failed\n"); return 1; }
  if (smgen::script_store().state() != smgen::SS_IDLE) {
    fprintf(stderr, "state after Abort = %u\n", smgen::script_store().state());
    return 1;
  }
  if (!slot_matches(1, body2, 2)) { fprintf(stderr, "active slot damaged by aborted xfer\n"); return 1; }
  printf("REJECT OK: out-of-order Data + short Commit -> ConstraintError, Abort -> idle\n");

  // --- CRC 不一致は Commit で弾く(active は変わらない)---
  std::vector<uint8_t> body4 = make_body(300, 0x44);
  st = transfer(body4, true, nullptr);
  if (st != 0x87) { fprintf(stderr, "bad-CRC commit status 0x%02x (expected 0x87)\n", st); return 1; }
  if (smgen::script_store().state() != smgen::SS_ERROR) {
    fprintf(stderr, "state after bad CRC = %u\n", smgen::script_store().state());
    return 1;
  }
  if (smgen::script_store().active_slot() != 1 || smgen::script_store().version() != 2) {
    fprintf(stderr, "active changed after bad CRC\n");
    return 1;
  }
  if (!slot_matches(1, body2, 2)) return 1;
  printf("BAD CRC OK: Commit -> ConstraintError, State=error, active slot B ver 2 unchanged\n");

  // --- ロード失敗 → 旧スロットへロールバック ---
  const unsigned reloads_before = g_reloads;
  g_fail_reload = true;
  std::vector<uint8_t> body5 = make_body(512, 0x55);
  st = transfer(body5, false, nullptr);
  if (st != 0) { fprintf(stderr, "commit #5 status 0x%02x\n", st); return 1; }
  smgen::script_store().poll();
  g_fail_reload = false;
  if (smgen::script_store().state() != smgen::SS_ERROR) {
    fprintf(stderr, "state after failed reload = %u\n", smgen::script_store().state());
    return 1;
  }
  if (smgen::script_store().active_slot() != 1 || smgen::script_store().version() != 2) {
    fprintf(stderr, "rollback did not restore slot B ver 2 (slot=%u ver=%u)\n",
            smgen::script_store().active_slot(), smgen::script_store().version());
    return 1;
  }
  {
    smgen::ScriptHeader h;
    if (smgen::script_hdr_parse(g_flash[0], smgen::kScriptHdrSize, h)) {
      fprintf(stderr, "rolled back slot A still has a valid header\n");
      return 1;
    }
  }
  if (g_reloads <= reloads_before) { fprintf(stderr, "reload was not attempted\n"); return 1; }
  if (!slot_matches(1, body2, 2)) return 1;
  // ロールバック後も転送はやり直せる(ERROR → Begin)。
  st = transfer(make_body(128, 0x66), false, nullptr);
  if (st != 0) { fprintf(stderr, "retry after rollback status 0x%02x\n", st); return 1; }
  smgen::script_store().poll();
  if (smgen::script_store().state() != smgen::SS_IDLE ||
      smgen::script_store().active_slot() != 0 || smgen::script_store().version() != 3) {
    fprintf(stderr, "retry after rollback did not activate slot A ver 3\n");
    return 1;
  }
  printf("ROLLBACK OK: load failure -> slot A invalidated, slot B ver 2 active; retry -> ver 3\n");

  // --- on_command 通知(§9.3 で未接続だったフックの配線)---
  if (g_on_command == 0) { fprintf(stderr, "on_command was never notified\n"); return 1; }
  printf("ON_COMMAND OK: %u invokes forwarded to the script hook\n", g_on_command);

  printf("== scriptstore_loopback: ALL GREEN ==\n");
  sm_ctrl_deinit();
  free(mem);
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--dev-dir" && i + 1 < argc) g_dev_dir = argv[++i];
    else if (a == "--ctrl-dir" && i + 1 < argc) g_ctrl_dir = argv[++i];
    else if (a == "-v" || a == "--verbose") g_verbose = true;
    else {
      fprintf(stderr, "usage: %s --dev-dir <dir> --ctrl-dir <dir> [-v]\n", argv[0]);
      return 2;
    }
  }
  if (g_dev_dir.empty() || g_ctrl_dir.empty()) {
    fprintf(stderr, "usage: %s --dev-dir <dir> --ctrl-dir <dir> [-v]\n", argv[0]);
    return 2;
  }
  mkdir(g_dev_dir.c_str(), 0700);
  mkdir(g_ctrl_dir.c_str(), 0700);
  return run();
}
