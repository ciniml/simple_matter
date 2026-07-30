// ホスト C++17 テストコントローラ(POSIX ソケット)。
//
// C FFI シム(libsimple_matter_cffi.a)の sm_ctrl_* API を C++ から駆動する。
// docs/design/c-ffi-shim.md §11(F7a)の POSIX 版 = ESP-IDF controller_hub_cpp の対向。
//
//  - **供給メモリ経路の実証**: sm_ctrl_context_size() で必要サイズを取り、malloc
//    (aligned_alloc)したバッファを sm_ctrl_init に渡す(PSRAM 配置と同じ経路)。
//  - Matter UDP をエフェメラルポート(dual-stack IPv6 v6only=0)で bind。
//  - KVS は --state-dir 配下のファイル(キーを hex 化した <hex>.bin)。ca-state(cast)/
//    ノード帳(nods)/CASE resumption(rsm*)を永続化 → プロセス再起動で復元。
//  - RNG は getrandom(2)。
//
// コマンド(1 行 1 コマンドを標準入力から読む。EOF で終了):
//   pair    <node_hex> <passcode> <ip> <port>   フルコミッショニング(UDP 直接 PASE)
//   toggle  <node_hex>                            OnOff Toggle(EP1/0x0006/cmd 0x02)
//   read    <node_hex> [ep cluster attr]          スカラ read(既定 = OnOff 状態)
//   resolve <node_hex> <ip>                        operational 解決(QU 直指定 = --at)
//
// 使い方:
//   printf 'pair 0xAABBCCDD 20202021 127.0.0.1 5540\ntoggle 0xAABBCCDD\n'
//     | ./controller --state-dir <dir> [-v]

#include "simple_matter.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>

namespace {

bool g_verbose = false;
std::string g_state_dir;
uint16_t kMdnsPort = 5353;

uint64_t now_ms() {
  static struct timespec start = [] {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t;
  }();
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  uint64_t now_ns = (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
  uint64_t start_ns = (uint64_t)start.tv_sec * 1000000000ull + (uint64_t)start.tv_nsec;
  return (now_ns - start_ns) / 1000000ull;
}

// ---- ファイルベース KVS(cast / nods / rsm* を hex 化ファイル名で保存) ----

std::string key_path(const char *key) {
  std::string p = g_state_dir + "/";
  for (const unsigned char *k = (const unsigned char *)key; *k; ++k) {
    char b[3];
    snprintf(b, sizeof(b), "%02x", *k);
    p += b;
  }
  p += ".bin";
  return p;
}

extern "C" int32_t kvs_get(void *, const char *key, uint8_t *buf, size_t cap) {
  FILE *f = fopen(key_path(key).c_str(), "rb");
  if (!f) {
    return -1;
  }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0) {
    fclose(f);
    return -1;
  }
  if ((size_t)sz <= cap) {
    size_t got = fread(buf, 1, (size_t)sz, f);
    (void)got;
  }
  fclose(f);
  return (int32_t)sz;
}

extern "C" int32_t kvs_set(void *, const char *key, const uint8_t *val, size_t len) {
  FILE *f = fopen(key_path(key).c_str(), "wb");
  if (!f) {
    return -1;
  }
  size_t wrote = (len == 0) ? 0 : fwrite(val, 1, len, f);
  fclose(f);
  return (wrote == len) ? 0 : -1;
}

extern "C" int32_t kvs_delete(void *, const char *key) {
  if (unlink(key_path(key).c_str()) != 0 && errno != ENOENT) {
    return -1;
  }
  return 0;
}

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = getrandom(buf + off, len - off, 0);
    if (n <= 0) {
      for (; off < len; ++off) {
        buf[off] = (uint8_t)(rand() & 0xFF);
      }
      return;
    }
    off += (size_t)n;
  }
}

// ---- sockaddr <-> sm_addr_t ----

void smaddr_to_sockaddr(const sm_addr_t &a, sockaddr_storage &ss, socklen_t &len) {
  memset(&ss, 0, sizeof(ss));
  if (a.is_v6) {
    auto *s6 = (sockaddr_in6 *)&ss;
    s6->sin6_family = AF_INET6;
    s6->sin6_port = htons(a.port);
    memcpy(&s6->sin6_addr, a.ip, 16);
    s6->sin6_scope_id = a.scope_id;
    len = sizeof(sockaddr_in6);
  } else {
    auto *s4 = (sockaddr_in *)&ss;
    s4->sin_family = AF_INET;
    s4->sin_port = htons(a.port);
    memcpy(&s4->sin_addr, a.ip, 4);
    len = sizeof(sockaddr_in);
  }
}

sm_addr_t sockaddr_to_smaddr(const sockaddr_storage &ss) {
  sm_addr_t a;
  memset(&a, 0, sizeof(a));
  if (ss.ss_family == AF_INET6) {
    auto *s6 = (const sockaddr_in6 *)&ss;
    a.is_v6 = true;
    memcpy(a.ip, &s6->sin6_addr, 16);
    a.port = ntohs(s6->sin6_port);
    a.scope_id = s6->sin6_scope_id;
  } else {
    auto *s4 = (const sockaddr_in *)&ss;
    a.is_v6 = false;
    memcpy(a.ip, &s4->sin_addr, 4);
    a.port = ntohs(s4->sin_port);
  }
  return a;
}

// v4/v6 いずれの IP 文字列も sm_addr_t へ。
bool parse_ip(const std::string &ip, uint16_t port, sm_addr_t &out) {
  memset(&out, 0, sizeof(out));
  out.port = port;
  if (ip.find(':') != std::string::npos) {
    if (inet_pton(AF_INET6, ip.c_str(), out.ip) != 1) {
      return false;
    }
    out.is_v6 = true;
  } else {
    if (inet_pton(AF_INET, ip.c_str(), out.ip) != 1) {
      return false;
    }
    out.is_v6 = false;
  }
  return true;
}

int open_udp() {
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket(udp)");
    return -1;
  }
  int off = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)); // dual-stack
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_addr = in6addr_any;
  a.sin6_port = 0; // エフェメラルポート(コントローラ)
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    perror("bind(ephemeral)");
    close(fd);
    return -1;
  }
  return fd;
}

int g_udp = -1;

void send_sm(int fd, const uint8_t *buf, size_t len, const sm_addr_t &dst) {
  sockaddr_storage ss;
  socklen_t sl;
  smaddr_to_sockaddr(dst, ss, sl);
  // IPv4 宛は dual-stack ソケットのため v4-mapped v6 へ。
  if (!dst.is_v6) {
    sockaddr_in6 m{};
    m.sin6_family = AF_INET6;
    m.sin6_port = htons(dst.port);
    m.sin6_addr.s6_addr[10] = 0xff;
    m.sin6_addr.s6_addr[11] = 0xff;
    memcpy(&m.sin6_addr.s6_addr[12], dst.ip, 4);
    sendto(fd, buf, len, 0, (sockaddr *)&m, sizeof(m));
    return;
  }
  sendto(fd, buf, len, 0, (sockaddr *)&ss, sl);
}

// TX キューを空になるまで排出する(sm_ctrl_poll を 0 が返るまで)。
void drain_tx(int fd) {
  uint8_t tx[2048];
  sm_addr_t dst;
  for (;;) {
    size_t n = sm_ctrl_poll(now_ms(), tx, sizeof(tx), &dst);
    if (n == 0) {
      break;
    }
    send_sm(fd, tx, n, dst);
  }
}

const char *ev_name(sm_ctrl_event_kind_t k) {
  switch (k) {
  case SM_CTRL_EV_PAIR_PHASE:
    return "PAIR_PHASE";
  case SM_CTRL_EV_PAIR_COMPLETE:
    return "PAIR_COMPLETE";
  case SM_CTRL_EV_PAIR_FAILED:
    return "PAIR_FAILED";
  case SM_CTRL_EV_CASE_ESTABLISHED:
    return "CASE_ESTABLISHED";
  case SM_CTRL_EV_CASE_FAILED:
    return "CASE_FAILED";
  case SM_CTRL_EV_INVOKE_DONE:
    return "INVOKE_DONE";
  case SM_CTRL_EV_INVOKE_FAILED:
    return "INVOKE_FAILED";
  case SM_CTRL_EV_READ_DONE:
    return "READ_DONE";
  case SM_CTRL_EV_READ_FAILED:
    return "READ_FAILED";
  case SM_CTRL_EV_RESOLVE_DONE:
    return "RESOLVE_DONE";
  default:
    return "NONE";
  }
}

// 単一コマンドを終端イベントまで駆動する。out_ev に終端イベントを返す。成功=true。
bool run_until(int fd, uint64_t timeout_ms, sm_ctrl_event_t &out_ev,
               bool (*is_terminal)(const sm_ctrl_event_t &)) {
  uint64_t until = now_ms() + timeout_ms;
  uint8_t rx[2048];
  drain_tx(fd); // 発行済みの最初のメッセージを送る。
  for (;;) {
    // 途中のイベント(PAIR_PHASE / CASE_ESTABLISHED)を吐き出し、終端で返す。
    sm_ctrl_event_t ev;
    while (sm_ctrl_take_event(&ev)) {
      if (g_verbose || ev.kind == SM_CTRL_EV_PAIR_PHASE) {
        printf("  [event] %s node=%#llx phase=%u status=%u resumed=%d\n", ev_name(ev.kind),
               (unsigned long long)ev.node_id, ev.phase, ev.status, ev.resumed ? 1 : 0);
        fflush(stdout);
      }
      if (is_terminal(ev)) {
        out_ev = ev;
        // 終端後、残 ACK/exchange を流し切る(次コマンドの exchange 枯渇回避)。
        for (int i = 0; i < 50; ++i) {
          drain_tx(fd);
          if (sm_ctrl_next_deadline(now_ms()) == SM_NO_DEADLINE) {
            break;
          }
          fd_set r;
          FD_ZERO(&r);
          FD_SET(fd, &r);
          struct timeval tv = {0, 20000};
          if (select(fd + 1, &r, nullptr, nullptr, &tv) > 0 && FD_ISSET(fd, &r)) {
            sockaddr_storage src;
            socklen_t sl = sizeof(src);
            ssize_t n = recvfrom(fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
            if (n > 0) {
              sm_addr_t sa = sockaddr_to_smaddr(src);
              uint8_t tx[2048];
              sm_addr_t dst;
              size_t tn = sm_ctrl_udp_rx(rx, (size_t)n, &sa, now_ms(), tx, sizeof(tx), &dst);
              if (tn > 0) {
                send_sm(fd, tx, tn, dst);
              }
              drain_tx(fd);
            }
          }
        }
        return true;
      }
    }

    if (now_ms() > until) {
      fprintf(stderr, "  [timeout] no terminal event within %llums\n",
              (unsigned long long)timeout_ms);
      return false;
    }

    uint64_t now = now_ms();
    uint64_t dl = sm_ctrl_next_deadline(now);
    uint64_t wait = 100;
    if (dl != SM_NO_DEADLINE) {
      wait = (dl > now) ? (dl - now) : 0;
    }
    if (wait > 200) {
      wait = 200;
    }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = wait / 1000;
    tv.tv_usec = (wait % 1000) * 1000;
    int r = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (r > 0 && FD_ISSET(fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      ssize_t n = recvfrom(fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        uint8_t tx[2048];
        sm_addr_t dst;
        size_t tn = sm_ctrl_udp_rx(rx, (size_t)n, &sa, now_ms(), tx, sizeof(tx), &dst);
        if (tn > 0) {
          send_sm(fd, tx, tn, dst);
        }
      }
    }
    drain_tx(fd);
  }
}

bool term_pair(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_PAIR_COMPLETE || e.kind == SM_CTRL_EV_PAIR_FAILED;
}
bool term_invoke(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_INVOKE_DONE || e.kind == SM_CTRL_EV_INVOKE_FAILED;
}
bool term_read(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_READ_DONE || e.kind == SM_CTRL_EV_READ_FAILED;
}
bool term_resolve(const sm_ctrl_event_t &e) {
  return e.kind == SM_CTRL_EV_RESOLVE_DONE;
}

uint64_t parse_u64(const std::string &s) { return strtoull(s.c_str(), nullptr, 0); }

// 1 コマンドを実行する。成功で 0、失敗で非 0。
int exec_command(const std::string &line) {
  std::istringstream iss(line);
  std::string cmd;
  iss >> cmd;
  if (cmd.empty() || cmd[0] == '#') {
    return 0;
  }
  if (cmd == "pair") {
    std::string node, pass, ip, port;
    iss >> node >> pass >> ip >> port;
    if (port.empty()) {
      fprintf(stderr, "usage: pair <node_hex> <passcode> <ip> <port>\n");
      return 2;
    }
    sm_addr_t addr;
    if (!parse_ip(ip, (uint16_t)parse_u64(port), addr)) {
      fprintf(stderr, "bad ip %s\n", ip.c_str());
      return 2;
    }
    uint64_t node_id = parse_u64(node);
    printf("pair node=%#llx passcode=%s -> %s:%s\n", (unsigned long long)node_id, pass.c_str(),
           ip.c_str(), port.c_str());
    fflush(stdout);
    int rc = sm_ctrl_pair_start(node_id, (uint32_t)parse_u64(pass), &addr, now_ms());
    if (rc != 0) {
      fprintf(stderr, "sm_ctrl_pair_start rc=%d\n", rc);
      return 1;
    }
    sm_ctrl_event_t ev;
    if (!run_until(g_udp, 60000, ev, term_pair)) {
      return 1;
    }
    if (ev.kind == SM_CTRL_EV_PAIR_COMPLETE) {
      printf("PAIR OK node=%#llx\n", (unsigned long long)ev.node_id);
      fflush(stdout);
      return 0;
    }
    printf("PAIR FAILED node=%#llx phase=%u reason=%u\n", (unsigned long long)ev.node_id, ev.phase,
           ev.status);
    return 1;
  }
  if (cmd == "toggle") {
    std::string node;
    iss >> node;
    uint64_t node_id = parse_u64(node);
    int rc = sm_ctrl_invoke(node_id, 1, 0x0006, 0x02, now_ms());
    if (rc != 0) {
      fprintf(stderr, "sm_ctrl_invoke rc=%d\n", rc);
      return 1;
    }
    sm_ctrl_event_t ev;
    if (!run_until(g_udp, 30000, ev, term_invoke)) {
      return 1;
    }
    if (ev.kind == SM_CTRL_EV_INVOKE_DONE) {
      printf("TOGGLE OK node=%#llx status=%u\n", (unsigned long long)ev.node_id, ev.status);
      fflush(stdout);
      return 0;
    }
    printf("TOGGLE FAILED node=%#llx status=%u\n", (unsigned long long)ev.node_id, ev.status);
    return 1;
  }
  if (cmd == "read") {
    std::string node, ep, cl, at;
    iss >> node >> ep >> cl >> at;
    uint64_t node_id = parse_u64(node);
    uint16_t endpoint = ep.empty() ? 1 : (uint16_t)parse_u64(ep);
    uint32_t cluster = cl.empty() ? 0x0006 : (uint32_t)parse_u64(cl);
    uint32_t attr = at.empty() ? 0x0000 : (uint32_t)parse_u64(at);
    int rc = sm_ctrl_read_scalar(node_id, endpoint, cluster, attr, now_ms());
    if (rc != 0) {
      fprintf(stderr, "sm_ctrl_read_scalar rc=%d\n", rc);
      return 1;
    }
    sm_ctrl_event_t ev;
    if (!run_until(g_udp, 30000, ev, term_read)) {
      return 1;
    }
    if (ev.kind == SM_CTRL_EV_READ_DONE) {
      printf("READ OK node=%#llx value=%llu null=%d\n", (unsigned long long)ev.node_id,
             (unsigned long long)ev.value_u64, ev.value_is_null ? 1 : 0);
      fflush(stdout);
      return 0;
    }
    printf("READ FAILED node=%#llx\n", (unsigned long long)ev.node_id);
    return 1;
  }
  if (cmd == "resolve") {
    std::string node, ip;
    iss >> node >> ip;
    uint64_t node_id = parse_u64(node);
    sm_addr_t at;
    bool have_at = !ip.empty() && parse_ip(ip, kMdnsPort, at);
    uint8_t q[512];
    sm_addr_t dst;
    size_t n = sm_ctrl_resolve_start(node_id, have_at ? &at : nullptr, now_ms(), q, sizeof(q), &dst);
    if (n == 0) {
      fprintf(stderr, "sm_ctrl_resolve_start failed\n");
      return 1;
    }
    // mDNS はエフェメラル UDP から送る(QU ユニキャスト応答が同ソケットへ返る)。
    send_sm(g_udp, q, n, dst);
    // 応答を待つ(mDNS 応答は Matter UDP と別ソケットが本来だが、QU はエフェメラル
    // ポート宛なので同一 g_udp で受ける)。
    uint64_t until = now_ms() + 5000;
    uint8_t rx[2048];
    for (;;) {
      sm_ctrl_event_t ev;
      if (sm_ctrl_take_event(&ev) && term_resolve(ev)) {
        sm_addr_t a;
        if (sm_ctrl_node_addr(node_id, &a)) {
          char ipbuf[64] = {0};
          inet_ntop(a.is_v6 ? AF_INET6 : AF_INET, a.ip, ipbuf, sizeof(ipbuf));
          printf("RESOLVE OK node=%#llx addr=%s:%u\n", (unsigned long long)node_id, ipbuf, a.port);
        }
        fflush(stdout);
        return 0;
      }
      if (now_ms() > until) {
        fprintf(stderr, "RESOLVE timeout\n");
        return 1;
      }
      fd_set r;
      FD_ZERO(&r);
      FD_SET(g_udp, &r);
      struct timeval tv = {0, 200000};
      if (select(g_udp + 1, &r, nullptr, nullptr, &tv) > 0) {
        sockaddr_storage src;
        socklen_t sl = sizeof(src);
        ssize_t rn = recvfrom(g_udp, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
        if (rn > 0) {
          sm_addr_t sa = sockaddr_to_smaddr(src);
          sm_ctrl_mdns_rx(rx, (size_t)rn, &sa, now_ms());
        }
      }
    }
  }
  if (cmd == "setaddr") {
    // F8b: mDNS 以外(Thread/SRP 列挙)で得たアドレスをノード帳へ直接設定する。
    //   setaddr <node_hex> <ip> [port]   port 省略 = 0 = シム側で 5540 に補完。
    std::string node, ip, port;
    iss >> node >> ip >> port;
    if (ip.empty()) {
      fprintf(stderr, "usage: setaddr <node_hex> <ip> [port]\n");
      return 2;
    }
    uint64_t node_id = parse_u64(node);
    sm_addr_t addr;
    if (!parse_ip(ip, port.empty() ? 0 : (uint16_t)parse_u64(port), addr)) {
      fprintf(stderr, "bad ip %s\n", ip.c_str());
      return 2;
    }
    int rc = sm_ctrl_set_node_addr(node_id, &addr);
    if (rc != 0) {
      fprintf(stderr, "sm_ctrl_set_node_addr rc=%d\n", rc);
      return 1;
    }
    // RESOLVE_DONE が立ち、ノード帳が更新されていること。
    sm_ctrl_event_t ev;
    bool resolved = false;
    while (sm_ctrl_take_event(&ev)) {
      if (term_resolve(ev) && ev.node_id == node_id) {
        resolved = true;
      }
    }
    sm_addr_t a;
    if (!resolved || !sm_ctrl_node_addr(node_id, &a)) {
      fprintf(stderr, "SETADDR: no RESOLVE_DONE / node missing\n");
      return 1;
    }
    char ipbuf[64] = {0};
    inet_ntop(a.is_v6 ? AF_INET6 : AF_INET, a.ip, ipbuf, sizeof(ipbuf));
    printf("SETADDR OK node=%#llx addr=%s:%u\n", (unsigned long long)node_id, ipbuf, a.port);
    fflush(stdout);
    return 0;
  }
  fprintf(stderr, "unknown command: %s\n", cmd.c_str());
  return 2;
}

} // namespace

int main(int argc, char **argv) {
  uint64_t fabric_id = 0xFAB0000000000001ull;
  uint64_t controller_node_id = 0x0000000011223344ull;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--state-dir" && i + 1 < argc) {
      g_state_dir = argv[++i];
    } else if (arg == "-v" || arg == "--verbose") {
      g_verbose = true;
    } else {
      fprintf(stderr, "usage: %s --state-dir <dir> [-v]\n", argv[0]);
      return 2;
    }
  }
  if (g_state_dir.empty()) {
    fprintf(stderr, "error: --state-dir is required\n");
    return 2;
  }
  mkdir(g_state_dir.c_str(), 0700);

  // --- 供給メモリ経路: context_size / align で必要量を取り malloc して渡す ---
  size_t need = sm_ctrl_context_size();
  size_t align = sm_ctrl_context_align();
  size_t rounded = ((need + align - 1) / align) * align;
  void *mem = aligned_alloc(align, rounded);
  if (!mem) {
    fprintf(stderr, "aligned_alloc(%zu, %zu) failed\n", align, rounded);
    return 1;
  }
  printf("ctrl context: size=%zu align=%zu (supplied via aligned_alloc)\n", need, align);

  sm_ctrl_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.fabric_id = fabric_id;
  cfg.controller_node_id = controller_node_id;
  cfg.vendor_id = 0xFFF1;
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.rng_fill = rng_fill;

  int rc = sm_ctrl_init((uint8_t *)mem, rounded, &cfg, now_ms());
  if (rc != 0) {
    fprintf(stderr, "sm_ctrl_init rc=%d\n", rc);
    free(mem);
    return 1;
  }
  printf("ctrl ready: nodes=%zu state=%s\n", sm_ctrl_node_count(), g_state_dir.c_str());
  fflush(stdout);

  g_udp = open_udp();
  if (g_udp < 0) {
    sm_ctrl_deinit();
    free(mem);
    return 1;
  }

  // 標準入力から 1 行 1 コマンドを読み、終端まで駆動する。
  int status = 0;
  std::string line;
  char buf[512];
  while (fgets(buf, sizeof(buf), stdin)) {
    line = buf;
    // 改行除去。
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
      line.pop_back();
    }
    if (line.empty()) {
      continue;
    }
    int r = exec_command(line);
    if (r != 0) {
      status = r;
      break;
    }
  }

  close(g_udp);
  sm_ctrl_deinit();
  free(mem);
  return status;
}
