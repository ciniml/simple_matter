// ホスト BLE ループバックハーネス(F7b、docs/design/c-ffi-shim.md §11.4)。
//
// 同一プロセス内でデバイス側シム(sm_init + sm_ble_*)とコントローラ(sm_ctrl_*)を両方
// 初期化し、無線・ネットワークなしで `pairing ble-wifi` / `ble-thread` の全経路を検証する。
//
//  - **BLE(BTP)= メモリ渡し**: コントローラの sm_ctrl_ble_poll 出力を
//    デバイス sm_ble_event(C1_WRITE) へ、デバイス sm_ble_poll 出力を
//    コントローラ sm_ctrl_ble_event(C2_INDICATION) へ直結する。CONNECTED / C2_SUBSCRIBED
//    は両側に mtu=247 で注入する。
//  - **運用 UDP / mDNS = プロセス内ループバック**(合成アドレスで in-memory passthrough)。
//    BLE フェーズ完了(SM_CTRL_EV_BLE_DONE)→ BLE 切断 → デバイス mDNS レスポンダで
//    operational 解決 → コントローラが運用 UDP へ handoff(set_peer + resume)→
//    CASE → CommissioningComplete → toggle。
//
// デバイス側シムとコントローラは同一プロセス内の別 static(F7a で確認済みの同居性)。
//
// 使い方:
//   ./ble_loopback <wifi|thread> --dev-dir <dir> --ctrl-dir <dir> [-v]

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

// 合成アドレス(in-memory passthrough の一貫した PeerAddr)。DEV_ADDR は operational
// mDNS が広告する 127.0.0.1:5540 に一致させる(handoff 後のコントローラ宛先)。
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

// ---- Thread テスト用 dataset TLV(先頭に Ext PAN ID。thread.rs REAL_DATASET) ----
const uint8_t kThreadDataset[] = {
    0x02, 0x08, 0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43,
    0x03, 0x0f, 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '-', '2', '7', '0', '2',
};

// ---- デバイス側 BLE サービス(ネットワーク投入 take + 遅延応答を BTP へ) ----
void device_ble_service(uint64_t now) {
  sm_event_t ev;
  while (sm_take_event(&ev)) {
    if (ev.kind == SM_EV_WIFI_CONNECT_REQUEST) {
      uint8_t ssid[64], pass[128];
      size_t pl = 0;
      size_t sl = sm_take_wifi_request(ssid, sizeof(ssid), pass, sizeof(pass), &pl);
      if (g_verbose) printf("  [dev] wifi request: ssid=%.*s (%zuB creds) -> connected\n", (int)sl, ssid, pl);
      sm_wifi_status(true, now);
    } else if (ev.kind == SM_EV_THREAD_ATTACH_REQUEST) {
      uint8_t ds[256];
      size_t n = sm_take_thread_dataset(ds, sizeof(ds));
      if (g_verbose) printf("  [dev] thread attach request: dataset %zuB -> attached\n", n);
      sm_thread_status(true, now);
    }
  }
  // 遅延 ConnectNetworkResponse など BLE 宛の送信を BTP へ積む(UDP 宛は BLE 中は生じない)。
  uint8_t tx[2048];
  sm_addr_t dst;
  while (sm_poll(now, tx, sizeof(tx), &dst) > 0) { /* BLE 宛は内部で BTP へ */ }
}

// BLE(BTP)を 1 往復シャトルする。戻り値 = 動いたフラグメント数。
int shuttle_ble(uint64_t now) {
  uint8_t frag[512];
  int moved = 0;
  // controller -> device(C1 write)
  size_t n;
  while ((n = sm_ctrl_ble_poll(now, frag, sizeof(frag))) > 0) {
    sm_ble_event(SM_BLE_C1_WRITE, 0, frag, n, now);
    moved++;
  }
  device_ble_service(now);
  // device -> controller(C2 indication)
  while ((n = sm_ble_poll(now, frag, sizeof(frag))) > 0) {
    sm_ctrl_ble_event(SM_BLE_C1_WRITE, 0, frag, n, now);
    moved++;
  }
  return moved;
}

const char *ctrl_ev_name(sm_ctrl_event_kind_t k) {
  switch (k) {
  case SM_CTRL_EV_PAIR_PHASE: return "PAIR_PHASE";
  case SM_CTRL_EV_PAIR_COMPLETE: return "PAIR_COMPLETE";
  case SM_CTRL_EV_PAIR_FAILED: return "PAIR_FAILED";
  case SM_CTRL_EV_CASE_ESTABLISHED: return "CASE_ESTABLISHED";
  case SM_CTRL_EV_CASE_FAILED: return "CASE_FAILED";
  case SM_CTRL_EV_INVOKE_DONE: return "INVOKE_DONE";
  case SM_CTRL_EV_INVOKE_FAILED: return "INVOKE_FAILED";
  case SM_CTRL_EV_READ_DONE: return "READ_DONE";
  case SM_CTRL_EV_READ_FAILED: return "READ_FAILED";
  case SM_CTRL_EV_RESOLVE_DONE: return "RESOLVE_DONE";
  case SM_CTRL_EV_BLE_DONE: return "BLE_DONE";
  default: return "NONE";
  }
}

// controller のイベントを排出し、指定 kind が来たら *hit=true。
void pump_ctrl_events(bool always_log, sm_ctrl_event_kind_t want, bool *hit,
                      sm_ctrl_event_t *out, sm_ctrl_event_kind_t want2, bool *hit2) {
  sm_ctrl_event_t ev;
  while (sm_ctrl_take_event(&ev)) {
    if (always_log || g_verbose || ev.kind == SM_CTRL_EV_PAIR_PHASE)
      printf("  [ctrl] %s node=%#llx phase=%u status=%u resumed=%d\n", ctrl_ev_name(ev.kind),
             (unsigned long long)ev.node_id, ev.phase, ev.status, ev.resumed ? 1 : 0);
    fflush(stdout);
    if (ev.kind == want) { *hit = true; if (out) *out = ev; }
    if (hit2 && ev.kind == want2) *hit2 = true;
  }
}

// ---- 運用 UDP フェーズ(in-memory passthrough) ----
sm_addr_t DEV_ADDR;  // 127.0.0.1:5540(operational 広告と一致)
sm_addr_t CTRL_ADDR; // 127.0.0.1:55000(controller の合成ソース)

struct Datagram { std::vector<uint8_t> buf; bool to_device; };

// controller が積んだ送信をキューへ。
void ctrl_emit(std::vector<Datagram> &q, uint64_t now) {
  uint8_t tx[2048];
  sm_addr_t dst;
  size_t n;
  while ((n = sm_ctrl_poll(now, tx, sizeof(tx), &dst)) > 0)
    q.push_back({std::vector<uint8_t>(tx, tx + n), true});
}
// device が積んだ送信をキューへ。
void dev_emit(std::vector<Datagram> &q, uint64_t now) {
  uint8_t tx[2048];
  sm_addr_t dst;
  size_t n;
  while ((n = sm_poll(now, tx, sizeof(tx), &dst)) > 0)
    q.push_back({std::vector<uint8_t>(tx, tx + n), false});
}

// キュー内の datagram を相互に配って空にする(応答は同じキューに連鎖する)。
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

// 運用 UDP を仮想時刻を進めつつ終端イベントまで駆動する(F7a の settle→drive を再現:
// standalone ACK / MRP 再送の期限を実時計で待って、静穏化後に次の exchange を発行させる)。
bool drive_udp_until(sm_ctrl_event_kind_t want, sm_ctrl_event_kind_t wantfail, sm_ctrl_event_t *out) {
  uint64_t end = now_ms() + 20000;
  std::vector<Datagram> q;
  while (now_ms() < end) {
    uint64_t now = now_ms();
    // 1. コントローラ/デバイスの時間駆動送信(pump / due ACK / 再送)を排出して配る。
    ctrl_emit(q, now);
    dev_emit(q, now);
    drain_queue(q, now);
    // 2. イベント確認。
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (g_verbose || ev.kind == SM_CTRL_EV_PAIR_PHASE || ev.kind == SM_CTRL_EV_CASE_ESTABLISHED)
        printf("  [ctrl] %s node=%#llx phase=%u status=%u resumed=%d\n", ctrl_ev_name(ev.kind),
               (unsigned long long)ev.node_id, ev.phase, ev.status, ev.resumed ? 1 : 0);
      if (ev.kind == want) { if (out) *out = ev; return true; }
      if (ev.kind == wantfail) return false;
    }
    // 3. 次の期限まで実時計で待つ(仮想時刻 = 実 now_ms を進める)。
    uint64_t ndc = sm_ctrl_next_deadline(now_ms());
    uint64_t ndd = sm_next_deadline(now_ms());
    uint64_t nd = (ndc < ndd) ? ndc : ndd;
    uint64_t cur = now_ms();
    if (nd == SM_NO_DEADLINE) {
      usleep(2000); // 完全アイドル(通常は起きない: Pairing 中は即時期限)。
    } else if (nd > cur) {
      uint64_t w = nd - cur;
      if (w > 150) w = 150;
      usleep((useconds_t)(w * 1000));
    }
  }
  return false;
}

int run(const std::string &mode) {
  bool thread = (mode == "thread");
  uint64_t node_id = 0x0000000AABBCCDDull;

  DEV_ADDR = make_addr("127.0.0.1", 5540);
  CTRL_ADDR = make_addr("127.0.0.1", 55000);

  // --- デバイス側シム(sm_*)---
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
  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.passcode = 0;
  cfg.verifier_iterations = 2000;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.verifier_w0_l = kDevVerifierW0L;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "OnOffLight";
  const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  memcpy(cfg.mac, mac, 6);
  cfg.kvs_get = dev_kvs_get;
  cfg.kvs_set = dev_kvs_set;
  cfg.kvs_delete = dev_kvs_del;
  cfg.rng_fill = rng_fill;
  cfg.network = thread ? SM_NET_THREAD : SM_NET_WIFI;

  if (sm_init(&cfg, now_ms()) != 0) {
    fprintf(stderr, "sm_init failed\n");
    return 1;
  }
  // DHCP 相当のアドレス反映(operational mDNS が 127.0.0.1 を広告する)。
  uint8_t v4[4] = {127, 0, 0, 1};
  sm_set_addrs(v4, nullptr);
  printf("device ready: network=%s discriminator=3840 onoff=%d\n", thread ? "thread" : "wifi", sm_onoff_get());

  // --- コントローラ(sm_ctrl_*、供給メモリ経路)---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = aligned_alloc(align, rounded);
  if (!mem) { fprintf(stderr, "aligned_alloc failed\n"); return 1; }
  printf("ctrl context: size=%zu align=%zu\n", need, align);
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
  printf("ctrl ready: nodes=%zu\n", sm_ctrl_node_count());
  fflush(stdout);

  // --- match_adv: デバイスの広告 service data を照合(scan の代用)---
  uint8_t adv[64];
  size_t advn = sm_ble_adv_data(adv, sizeof(adv));
  // 完全な広告(15B)から service data payload(末尾 8B)を取り出して照合する。
  if (advn >= 15) {
    if (!sm_ctrl_match_adv(adv + 7, 8, 3840)) {
      fprintf(stderr, "match_adv failed to match discriminator 3840\n");
      return 1;
    }
    printf("match_adv: discriminator 3840 matched (adv %zuB)\n", advn);
  }

  // --- BLE コミッショニング開始 ---
  int rc;
  if (thread) {
    rc = sm_ctrl_ble_pair_start(node_id, 20202021, 1, kThreadDataset, sizeof(kThreadDataset), nullptr, 0, now_ms());
  } else {
    const uint8_t ssid[] = "iotap";
    const uint8_t pass[] = "hogeFugapiyo";
    rc = sm_ctrl_ble_pair_start(node_id, 20202021, 0, ssid, sizeof(ssid) - 1, pass, sizeof(pass) - 1, now_ms());
  }
  if (rc != 0) { fprintf(stderr, "sm_ctrl_ble_pair_start rc=%d\n", rc); return 1; }
  printf("ble pair start: node=%#llx mode=%s\n", (unsigned long long)node_id, mode.c_str());

  // --- CONNECTED / C2_SUBSCRIBED を両側へ注入(mtu=247)---
  uint16_t mtu = 247;
  sm_ctrl_ble_event(SM_BLE_CONNECTED, mtu, nullptr, 0, now_ms());
  sm_ble_event(SM_BLE_CONNECTED, mtu, nullptr, 0, now_ms());
  sm_ctrl_ble_event(SM_BLE_C2_SUBSCRIBED, 0, nullptr, 0, now_ms());
  sm_ble_event(SM_BLE_C2_SUBSCRIBED, 0, nullptr, 0, now_ms());

  // --- BLE フェーズ: BLE_DONE / PAIR_FAILED まで駆動 ---
  bool ble_done = false, failed = false;
  sm_ctrl_event_t last;
  memset(&last, 0, sizeof(last));
  for (int i = 0; i < 400 && !ble_done && !failed; ++i) {
    shuttle_ble(now_ms());
    bool d = false, f = false;
    pump_ctrl_events(false, SM_CTRL_EV_BLE_DONE, &d, &last, SM_CTRL_EV_PAIR_FAILED, &f);
    if (d) ble_done = true;
    if (f) failed = true;
  }
  if (failed) { fprintf(stderr, "BLE commissioning FAILED\n"); return 1; }
  if (!ble_done) { fprintf(stderr, "BLE phase did not reach BLE_DONE\n"); return 1; }
  printf("BLE phase complete: SM_CTRL_EV_BLE_DONE (AddNOC + %s + ConnectNetwork over BTP)\n",
         thread ? "AddThreadNetwork" : "AddWiFiNetwork");
  fflush(stdout);

  // --- BLE 切断 ---
  sm_ctrl_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());
  sm_ble_event(SM_BLE_DISCONNECTED, 0, nullptr, 0, now_ms());

  // デバイスの operational mDNS を最新化(fabric 追加後の広告切替を反映)。
  {
    uint8_t tx[2048];
    sm_addr_t dst;
    while (sm_poll(now_ms(), tx, sizeof(tx), &dst) > 0) {}
  }

  // --- operational 解決(デバイス mDNS レスポンダで in-memory 解決 → handoff)---
  {
    uint8_t q[512], resp[2048];
    sm_addr_t qdst;
    size_t qn = sm_ctrl_resolve_start(node_id, nullptr, now_ms(), q, sizeof(q), &qdst);
    if (qn == 0) { fprintf(stderr, "sm_ctrl_resolve_start failed\n"); return 1; }
    sm_addr_t ctrl_mdns = make_addr("127.0.0.1", 5353);
    sm_addr_t rdst;
    size_t rn = sm_mdns_rx(q, qn, &ctrl_mdns, resp, sizeof(resp), &rdst);
    if (rn == 0) { fprintf(stderr, "device mDNS did not answer operational query\n"); return 1; }
    if (sm_ctrl_mdns_rx(resp, rn, &DEV_ADDR, now_ms()) != 0) {
      fprintf(stderr, "sm_ctrl_mdns_rx did not resolve\n");
      return 1;
    }
    bool resolved = false, hs = false;
    pump_ctrl_events(true, SM_CTRL_EV_RESOLVE_DONE, &resolved, nullptr, SM_CTRL_EV_NONE, &hs);
    sm_addr_t na;
    if (sm_ctrl_node_addr(node_id, &na)) {
      char ip[64] = {0};
      inet_ntop(AF_INET, na.ip, ip, sizeof(ip));
      printf("operational resolved: %s:%u -> handoff to UDP CASE\n", ip, na.port);
    }
  }

  // --- 運用 UDP: CASE → CommissioningComplete → PAIR_COMPLETE ---
  if (!drive_udp_until(SM_CTRL_EV_PAIR_COMPLETE, SM_CTRL_EV_PAIR_FAILED, nullptr)) {
    fprintf(stderr, "UDP handoff/CASE did not complete\n");
    return 1;
  }
  printf("PAIR COMPLETE (CASE over UDP + CommissioningComplete). device fabrics=%u\n", sm_fabric_count());
  fflush(stdout);

  // --- toggle over UDP ---
  bool onoff_before = sm_onoff_get();
  if (sm_ctrl_invoke(node_id, 1, 0x0006, 0x02, now_ms()) != 0) { fprintf(stderr, "sm_ctrl_invoke rc\n"); return 1; }
  if (!drive_udp_until(SM_CTRL_EV_INVOKE_DONE, SM_CTRL_EV_INVOKE_FAILED, nullptr)) {
    fprintf(stderr, "toggle did not complete\n");
    return 1;
  }
  bool onoff_after = sm_onoff_get();
  printf("TOGGLE OK: device onoff %d -> %d\n", onoff_before, onoff_after);
  if (onoff_after == onoff_before) { fprintf(stderr, "onoff did not change\n"); return 1; }

  // --- read over UDP(検算)---
  if (sm_ctrl_read_scalar(node_id, 1, 0x0006, 0x0000, now_ms()) != 0) { fprintf(stderr, "read rc\n"); return 1; }
  sm_ctrl_event_t rev;
  memset(&rev, 0, sizeof(rev));
  if (!drive_udp_until(SM_CTRL_EV_READ_DONE, SM_CTRL_EV_READ_FAILED, &rev)) {
    fprintf(stderr, "read did not complete\n");
    return 1;
  }
  printf("READ OK: onoff=%llu (device=%d)\n", (unsigned long long)rev.value_u64, sm_onoff_get());
  if ((rev.value_u64 != 0) != (bool)sm_onoff_get()) { fprintf(stderr, "read value mismatch\n"); return 1; }

  printf("== ble_loopback %s: ALL GREEN ==\n", mode.c_str());
  sm_ctrl_deinit();
  free(mem);
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  std::string mode;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--dev-dir" && i + 1 < argc) g_dev_dir = argv[++i];
    else if (a == "--ctrl-dir" && i + 1 < argc) g_ctrl_dir = argv[++i];
    else if (a == "-v" || a == "--verbose") g_verbose = true;
    else if (a == "wifi" || a == "thread") mode = a;
    else { fprintf(stderr, "usage: %s <wifi|thread> --dev-dir <dir> --ctrl-dir <dir> [-v]\n", argv[0]); return 2; }
  }
  if (mode.empty() || g_dev_dir.empty() || g_ctrl_dir.empty()) {
    fprintf(stderr, "usage: %s <wifi|thread> --dev-dir <dir> --ctrl-dir <dir> [-v]\n", argv[0]);
    return 2;
  }
  mkdir(g_dev_dir.c_str(), 0700);
  mkdir(g_ctrl_dir.c_str(), 0700);
  return run(mode);
}
