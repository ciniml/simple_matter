// ホスト composition ループバックハーネス(Phase A、docs/design/generic-firmware.md §9.1)。
//
// 同一プロセスでデバイス側シム(sm_init に composition blob を渡して EP1=dimmable light /
// EP2=温湿度センサに合成)と既存コントローラ(sm_ctrl_*、F7a)を初期化し、UDP datagram を
// メモリ渡しでループバックして C レベルで検証する:
//
//   pairing(UDP PASE → CASE → CommissioningComplete)
//     → OnOff Toggle(sm_ctrl_invoke)
//     → LevelControl MoveToLevel(sm_ctrl_invoke_args、引数 level/transitionTime)
//     → EP2 温度 read(sm_attr_set_value で push した値が IM read で返る)
//     → on_cluster_change が IM コマンド由来の変化で発火する
//
// composition blob は C 側で素の Matter TLV を組み立てる(Web Configurator / NVS から
// 渡ってくる blob と同じバイト列。エンコーダを持ち込まなくても書けることの実証)。
//
// 使い方:
//   ./composed_loopback --dev-dir <dir> --ctrl-dir <dir> [-v]

#include "simple_matter.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

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

// 合成クラスタ ID(Matter 標準)。
const uint32_t CL_IDENTIFY = 0x0003;
const uint32_t CL_GROUPS = 0x0004;
const uint32_t CL_ONOFF = 0x0006;
const uint32_t CL_LEVEL = 0x0008;
const uint32_t CL_TEMP = 0x0402;
const uint32_t CL_HUM = 0x0405;

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

// ---- ファイルベース KVS(デバイス/コントローラで別ディレクトリ) ----

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

// ---- on_cluster_change(§9.1): 変化を記録する ----

struct Change {
  uint16_t ep;
  uint32_t cluster;
  uint32_t attr;
  uint64_t bits;
};
std::vector<Change> g_changes;

extern "C" void on_cluster_change(void *, uint16_t ep, uint32_t cluster, uint32_t attr,
                                  const sm_attr_value_t *v) {
  g_changes.push_back({ep, cluster, attr, v->v.u});
  if (g_verbose)
    printf("  [dev] on_cluster_change ep=%u cluster=%#x attr=%#x value=%llu\n", ep, cluster, attr,
           (unsigned long long)v->v.u);
}

bool saw_change(uint16_t ep, uint32_t cluster, uint32_t attr, uint64_t *out) {
  for (auto it = g_changes.rbegin(); it != g_changes.rend(); ++it) {
    if (it->ep == ep && it->cluster == cluster && it->attr == attr) {
      if (out) *out = it->bits;
      return true;
    }
  }
  return false;
}

// ---- composition TLV blob(§9.1 のスキーマ)を素の Matter TLV で組み立てる ----
//
// 制御バイト: 上位 3bit = タグ制御(0=anonymous, 1=context)、下位 5bit = 要素型
// (0x01=i16, 0x04=u8, 0x05=u16, 0x06=u32, 0x15=struct, 0x16=array, 0x17=list, 0x18=end)。

struct Tlv {
  std::vector<uint8_t> b;
  void u8_(uint8_t t, uint8_t v) { b.push_back(0x24); b.push_back(t); b.push_back(v); }
  void u16_(uint8_t t, uint16_t v) {
    b.push_back(0x25); b.push_back(t);
    b.push_back((uint8_t)(v & 0xFF)); b.push_back((uint8_t)(v >> 8));
  }
  void u32_(uint8_t t, uint32_t v) {
    b.push_back(0x26); b.push_back(t);
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
  }
  void i16_(uint8_t t, int16_t v) {
    uint16_t u = (uint16_t)v;
    b.push_back(0x21); b.push_back(t);
    b.push_back((uint8_t)(u & 0xFF)); b.push_back((uint8_t)(u >> 8));
  }
  void u32_anon(uint32_t v) {
    b.push_back(0x06);
    for (int i = 0; i < 4; ++i) b.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
  }
  void list_anon() { b.push_back(0x17); }
  void struct_anon() { b.push_back(0x15); }
  void array_ctx(uint8_t t) { b.push_back(0x36); b.push_back(t); }
  void end() { b.push_back(0x18); }
};

std::vector<uint8_t> build_composition() {
  Tlv t;
  t.list_anon();
  // EP1 = dimmable light(0x0101 rev3): Identify + Groups + OnOff + LevelControl。
  t.struct_anon();
  t.u16_(0, 1);
  t.u32_(1, 0x0101);
  t.u8_(2, 3);
  t.array_ctx(3);
  t.u32_anon(CL_IDENTIFY);
  t.u32_anon(CL_GROUPS);
  t.u32_anon(CL_ONOFF);
  t.u32_anon(CL_LEVEL);
  t.end();
  t.end();
  // EP2 = 温湿度センサ(0x0302 rev2): Temperature + RelativeHumidity(初期温度 23.50℃)。
  t.struct_anon();
  t.u16_(0, 2);
  t.u32_(1, 0x0302);
  t.u8_(2, 2);
  t.array_ctx(3);
  t.u32_anon(CL_TEMP);
  t.u32_anon(CL_HUM);
  t.end();
  t.array_ctx(4);
  t.struct_anon();
  t.u32_(0, CL_TEMP);
  t.u32_(1, 0x0000);
  t.i16_(2, 2350);
  t.end();
  t.end();
  t.end();
  t.end();
  return t.b;
}

// ---- 運用 UDP(in-memory passthrough。ble_loopback.cpp と同じ流儀)----

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
    } else {
      size_t rn = sm_ctrl_udp_rx(d.buf.data(), d.buf.size(), &DEV_ADDR, now, tx, sizeof(tx), &dst);
      if (rn > 0) q.push_back({std::vector<uint8_t>(tx, tx + rn), true});
      ctrl_emit(q, now);
    }
  }
}

const char *ctrl_ev_name(sm_ctrl_event_kind_t k) {
  switch (k) {
  case SM_CTRL_EV_PAIR_PHASE: return "PAIR_PHASE";
  case SM_CTRL_EV_PAIR_COMPLETE: return "PAIR_COMPLETE";
  case SM_CTRL_EV_PAIR_FAILED: return "PAIR_FAILED";
  case SM_CTRL_EV_CASE_ESTABLISHED: return "CASE_ESTABLISHED";
  case SM_CTRL_EV_INVOKE_DONE: return "INVOKE_DONE";
  case SM_CTRL_EV_INVOKE_FAILED: return "INVOKE_FAILED";
  case SM_CTRL_EV_READ_DONE: return "READ_DONE";
  case SM_CTRL_EV_READ_FAILED: return "READ_FAILED";
  case SM_CTRL_EV_WRITE_DONE: return "WRITE_DONE";
  case SM_CTRL_EV_WRITE_FAILED: return "WRITE_FAILED";
  default: return "OTHER";
  }
}

// 仮想時刻(= 実時計)を進めつつ終端イベントまで駆動する。
bool drive_until(sm_ctrl_event_kind_t want, sm_ctrl_event_kind_t wantfail, sm_ctrl_event_t *out) {
  uint64_t end = now_ms() + 20000;
  std::vector<Datagram> q;
  while (now_ms() < end) {
    uint64_t now = now_ms();
    ctrl_emit(q, now);
    dev_emit(q, now);
    drain_queue(q, now);
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (g_verbose || ev.kind == SM_CTRL_EV_PAIR_PHASE)
        printf("  [ctrl] %s node=%#llx phase=%u status=%u\n", ctrl_ev_name(ev.kind),
               (unsigned long long)ev.node_id, ev.phase, ev.status);
      if (ev.kind == want) { if (out) *out = ev; return true; }
      if (ev.kind == wantfail) return false;
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

bool read_scalar(uint64_t node, uint16_t ep, uint32_t cluster, uint32_t attr, uint64_t *value) {
  if (sm_ctrl_read_scalar(node, ep, cluster, attr, now_ms()) != 0) return false;
  sm_ctrl_event_t ev;
  memset(&ev, 0, sizeof(ev));
  if (!drive_until(SM_CTRL_EV_READ_DONE, SM_CTRL_EV_READ_FAILED, &ev)) return false;
  *value = ev.value_u64;
  return true;
}

int run() {
  uint64_t node_id = 0x0000000AABBCCDDull;
  DEV_ADDR = make_addr("127.0.0.1", 5540);
  CTRL_ADDR = make_addr("127.0.0.1", 55000);

  // --- デバイス側シム(composition モード)---
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
  std::vector<uint8_t> comp = build_composition();
  printf("composition blob: %zu bytes\n", comp.size());

  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.verifier_iterations = 2000;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.verifier_w0_l = kDevVerifierW0L;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "ComposedLight";
  const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x77};
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
    fprintf(stderr, "sm_init(composition) failed\n");
    return 1;
  }
  uint8_t v4[4] = {127, 0, 0, 1};
  sm_set_addrs(v4, nullptr);

  // 合成結果を汎用値アクセスで確認する。
  sm_attr_value_t v;
  memset(&v, 0, sizeof(v));
  if (sm_attr_get_value(2, CL_TEMP, 0x0000, &v) != 0 || v.v.i != 2350) {
    fprintf(stderr, "EP2 temperature initial value mismatch\n");
    return 1;
  }
  if (sm_attr_get_value(3, CL_ONOFF, 0x0000, &v) != -2) {
    fprintf(stderr, "unexpected cluster on EP3\n");
    return 1;
  }
  printf("device ready: composed EP1(dimmable light) + EP2(temp/humidity), onoff=%d temp=%d\n",
         sm_onoff_get(), 2350);

  // --- コントローラ(供給メモリ経路)---
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
  printf("ctrl ready: context=%zuB nodes=%zu\n", need, sm_ctrl_node_count());
  fflush(stdout);

  // --- コミッショニング(UDP)---
  if (sm_ctrl_pair_start(node_id, 20202021, &DEV_ADDR, now_ms()) != 0) {
    fprintf(stderr, "sm_ctrl_pair_start failed\n");
    return 1;
  }
  if (!drive_until(SM_CTRL_EV_PAIR_COMPLETE, SM_CTRL_EV_PAIR_FAILED, nullptr)) {
    fprintf(stderr, "pairing did not complete\n");
    return 1;
  }
  printf("PAIR COMPLETE: device fabrics=%u\n", sm_fabric_count());
  fflush(stdout);

  // --- OnOff Toggle(合成した EP1 OnOff)---
  g_changes.clear();
  bool before = sm_onoff_get();
  if (sm_ctrl_invoke(node_id, 1, CL_ONOFF, 0x02, now_ms()) != 0) {
    fprintf(stderr, "toggle invoke rc\n");
    return 1;
  }
  if (!drive_until(SM_CTRL_EV_INVOKE_DONE, SM_CTRL_EV_INVOKE_FAILED, nullptr)) {
    fprintf(stderr, "toggle did not complete\n");
    return 1;
  }
  if (sm_onoff_get() == before) { fprintf(stderr, "onoff did not change\n"); return 1; }
  uint64_t onoff_read = 0;
  if (!read_scalar(node_id, 1, CL_ONOFF, 0x0000, &onoff_read) || onoff_read != 1) {
    fprintf(stderr, "onoff read mismatch (%llu)\n", (unsigned long long)onoff_read);
    return 1;
  }
  uint64_t changed = 0;
  if (!saw_change(1, CL_ONOFF, 0x0000, &changed) || changed != 1) {
    fprintf(stderr, "on_cluster_change(OnOff) not fired\n");
    return 1;
  }
  printf("TOGGLE OK: device onoff %d -> %d (read=1, on_cluster_change fired)\n", before,
         sm_onoff_get());

  // --- LevelControl MoveToLevel(引数付き invoke)---
  g_changes.clear();
  sm_attr_value_t args[2];
  memset(args, 0, sizeof(args));
  args[0].type = SM_T_U8;
  args[0].v.u = 200; // level
  args[1].type = SM_T_U16;
  args[1].v.u = 0; // transitionTime(即時)
  if (sm_ctrl_invoke_args(node_id, 1, CL_LEVEL, 0x0000, args, 2, now_ms()) != 0) {
    fprintf(stderr, "MoveToLevel invoke rc\n");
    return 1;
  }
  if (!drive_until(SM_CTRL_EV_INVOKE_DONE, SM_CTRL_EV_INVOKE_FAILED, nullptr)) {
    fprintf(stderr, "MoveToLevel did not complete\n");
    return 1;
  }
  uint64_t level = 0;
  if (!read_scalar(node_id, 1, CL_LEVEL, 0x0000, &level) || level != 200) {
    fprintf(stderr, "CurrentLevel mismatch (%llu)\n", (unsigned long long)level);
    return 1;
  }
  memset(&v, 0, sizeof(v));
  if (sm_attr_get_value(1, CL_LEVEL, 0x0000, &v) != 0 || v.v.u != 200) {
    fprintf(stderr, "sm_attr_get_value(CurrentLevel) mismatch\n");
    return 1;
  }
  if (!saw_change(1, CL_LEVEL, 0x0000, &changed) || changed != 200) {
    fprintf(stderr, "on_cluster_change(CurrentLevel) not fired\n");
    return 1;
  }
  printf("MOVETOLEVEL OK: CurrentLevel=200 (read + sm_attr_get_value + on_cluster_change)\n");

  // --- EP2 温度 read(HAL 相当の sm_attr_set_value push が IM から見える)---
  memset(&v, 0, sizeof(v));
  v.type = SM_T_I16;
  v.v.i = 1875; // 18.75℃
  if (sm_attr_set_value(2, CL_TEMP, 0x0000, &v) != 0) {
    fprintf(stderr, "sm_attr_set_value(temp) failed\n");
    return 1;
  }
  uint64_t temp = 0;
  if (!read_scalar(node_id, 2, CL_TEMP, 0x0000, &temp) || (int16_t)temp != 1875) {
    fprintf(stderr, "temperature read mismatch (%lld)\n", (long long)(int16_t)temp);
    return 1;
  }
  printf("TEMP READ OK: MeasuredValue=%d (0.01degC)\n", (int)(int16_t)temp);

  printf("== composed_loopback: ALL GREEN ==\n");
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
