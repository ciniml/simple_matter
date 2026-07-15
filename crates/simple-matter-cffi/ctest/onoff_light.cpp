// ホスト C++17 テストデバイス(POSIX ソケット)。
//
// C FFI シム(libsimple_matter_cffi.a)を C++ から駆動する onoff-light 相当。
// docs/design/c-ffi-shim.md §3 の ESP-IDF ポンプループの POSIX 版。
//
//  - Matter UDP :5540 を dual-stack(IPv6 v6only=0)で bind。
//  - mDNS :5353 を --at-ip(既定 127.0.0.1)に **特定 IP bind** する。既存の
//    mDNS レスポンダ(avahi 等)が 0.0.0.0:5353 に居ても、特定 IP への
//    ユニキャスト QU クエリ(smctl --at)は特定 bind の当ソケットへ配送される。
//    v4 マルチキャスト join も試みる(失敗しても継続)。
//  - KVS は --state-dir 配下のファイル(キーを hex 化した <hex>.bin)。
//  - RNG は getrandom(2)。
//
// 使い方:
//   ./onoff_light --state-dir <dir> [--at-ip 127.0.0.1] [-v]

#include "sm_wrapper.hpp"

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
#include <ctime>
#include <string>

namespace {

constexpr uint16_t kMatterPort = 5540;
constexpr uint16_t kMdnsPort = 5353;

bool g_verbose = false;
std::string g_state_dir;

uint64_t now_ms() {
  static struct timespec start = [] {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t;
  }();
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  // 総ナノ秒で引く(tv_nsec 同士を先に引くと符号なし桁溢れで巨大値になる)。
  uint64_t now_ns = (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
  uint64_t start_ns = (uint64_t)start.tv_sec * 1000000000ull + (uint64_t)start.tv_nsec;
  return (now_ns - start_ns) / 1000000ull;
}

// ---- ファイルベース KVS コールバック(SM_STATE_DIR 相当) ----

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
  std::string path = key_path(key);
  FILE *f = fopen(path.c_str(), "rb");
  if (!f) {
    return -1; // 無し
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
  return (int32_t)sz; // cap 不足でも実長を返す(呼び出し側が NoSpace を検出)
}

extern "C" int32_t kvs_set(void *, const char *key, const uint8_t *val, size_t len) {
  std::string path = key_path(key);
  FILE *f = fopen(path.c_str(), "wb");
  if (!f) {
    return -1;
  }
  size_t wrote = (len == 0) ? 0 : fwrite(val, 1, len, f);
  fclose(f);
  return (wrote == len) ? 0 : -1;
}

extern "C" int32_t kvs_delete(void *, const char *key) {
  std::string path = key_path(key);
  if (unlink(path.c_str()) != 0 && errno != ENOENT) {
    return -1;
  }
  return 0;
}

// ---- RNG コールバック ----

extern "C" void rng_fill(void *, uint8_t *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = getrandom(buf + off, len - off, 0);
    if (n <= 0) {
      // フォールバック(決定的ではないが起動を止めない)。
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

int open_matter_udp() {
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket(matter)");
    return -1;
  }
  int off = 0;
  setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off)); // dual-stack
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in6 a{};
  a.sin6_family = AF_INET6;
  a.sin6_addr = in6addr_any;
  a.sin6_port = htons(kMatterPort);
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    perror("bind(:5540)");
    close(fd);
    return -1;
  }
  return fd;
}

int open_mdns_socket(const char *at_ip) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket(mdns)");
    return -1;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(kMdnsPort);
  // 特定 IP に bind(既存レスポンダより優先してユニキャスト QU を受ける)。
  if (inet_pton(AF_INET, at_ip, &a.sin_addr) != 1) {
    fprintf(stderr, "invalid --at-ip %s\n", at_ip);
    close(fd);
    return -1;
  }
  if (bind(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    perror("bind(:5353)");
    close(fd);
    return -1;
  }
  // マルチキャスト join も試みる(失敗は無視、QU 経路には不要)。
  ip_mreq mreq{};
  inet_pton(AF_INET, "224.0.0.251", &mreq.imr_multiaddr);
  inet_pton(AF_INET, at_ip, &mreq.imr_interface);
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
    if (g_verbose) {
      perror("IP_ADD_MEMBERSHIP (ignored)");
    }
  }
  return fd;
}

const char *event_name(sm_event_kind_t k) {
  switch (k) {
  case SM_EV_ONOFF_CHANGED:
    return "ONOFF_CHANGED";
  case SM_EV_COMMISSIONED:
    return "COMMISSIONED";
  case SM_EV_FABRIC_REMOVED:
    return "FABRIC_REMOVED";
  case SM_EV_WINDOW_CHANGED:
    return "WINDOW_CHANGED";
  default:
    return "NONE";
  }
}

} // namespace

int main(int argc, char **argv) {
  std::string at_ip = "127.0.0.1";
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--state-dir" && i + 1 < argc) {
      g_state_dir = argv[++i];
    } else if (arg == "--at-ip" && i + 1 < argc) {
      at_ip = argv[++i];
    } else if (arg == "-v" || arg == "--verbose") {
      g_verbose = true;
    } else {
      fprintf(stderr, "usage: %s --state-dir <dir> [--at-ip <ip>] [-v]\n", argv[0]);
      return 2;
    }
  }
  if (g_state_dir.empty()) {
    fprintf(stderr, "error: --state-dir is required\n");
    return 2;
  }
  mkdir(g_state_dir.c_str(), 0700);

  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.passcode = 20202021;
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "OnOffLight";
  const uint8_t mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  memcpy(cfg.mac, mac, 6);
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.kvs_ctx = nullptr;
  cfg.rng_fill = rng_fill;
  cfg.rng_ctx = nullptr;

  SmStack stack(cfg, now_ms());
  if (!stack.ok()) {
    fprintf(stderr, "sm_init failed: rc=%d\n", stack.rc());
    return 1;
  }
  stack.on_event([](const sm_event_t &ev) {
    printf("EVENT %s arg=%u\n", event_name(ev.kind), (unsigned)ev.arg);
    fflush(stdout);
  });

  int udp_fd = open_matter_udp();
  int mdns_fd = open_mdns_socket(at_ip.c_str());
  if (udp_fd < 0 || mdns_fd < 0) {
    return 1;
  }

  // A レコード = --at-ip。
  uint8_t v4[4];
  inet_pton(AF_INET, at_ip.c_str(), v4);
  stack.set_addrs(v4, nullptr);

  printf("onoff_light ready: Matter UDP :%u (dual-stack), mDNS %s:%u, state=%s\n", kMatterPort,
         at_ip.c_str(), kMdnsPort, g_state_dir.c_str());
  printf("  passcode=20202021 discriminator=3840 fabrics=%u onoff=%d\n", stack.fabric_count(),
         stack.onoff_get());
  fflush(stdout);

  // 送出クロージャ(TX 宛先ソケットを固定して sockaddr へ変換)。
  auto make_sender = [](int fd) {
    return [fd](const uint8_t *buf, size_t len, const sm_addr_t &dst) {
      sockaddr_storage ss;
      socklen_t sl;
      smaddr_to_sockaddr(dst, ss, sl);
      sendto(fd, buf, len, 0, (sockaddr *)&ss, sl);
    };
  };
  SmStack::Sender udp_send = make_sender(udp_fd);
  SmStack::Sender mdns_send = make_sender(mdns_fd);

  uint8_t rx[2048];
  for (;;) {
    uint64_t now = now_ms();
    uint64_t dl = stack.next_deadline(now);
    struct timeval tv;
    if (dl == SM_NO_DEADLINE) {
      tv.tv_sec = 1;
      tv.tv_usec = 0;
    } else {
      uint64_t wait = (dl > now) ? (dl - now) : 0;
      if (wait > 1000) {
        wait = 1000; // mDNS announce 等のため上限 1s
      }
      tv.tv_sec = wait / 1000;
      tv.tv_usec = (wait % 1000) * 1000;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(udp_fd, &rfds);
    FD_SET(mdns_fd, &rfds);
    int maxfd = (udp_fd > mdns_fd ? udp_fd : mdns_fd) + 1;
    int r = select(maxfd, &rfds, nullptr, nullptr, &tv);
    now = now_ms();

    if (r > 0 && FD_ISSET(udp_fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      ssize_t n = recvfrom(udp_fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        if (g_verbose) {
          printf("[udp] %zd bytes\n", n);
          fflush(stdout);
        }
        stack.udp_rx(rx, (size_t)n, sa, now, udp_send);
      }
    }
    if (r > 0 && FD_ISSET(mdns_fd, &rfds)) {
      sockaddr_storage src;
      socklen_t sl = sizeof(src);
      ssize_t n = recvfrom(mdns_fd, rx, sizeof(rx), 0, (sockaddr *)&src, &sl);
      if (n > 0) {
        sm_addr_t sa = sockaddr_to_smaddr(src);
        stack.mdns_rx(rx, (size_t)n, sa, mdns_send);
      }
    }

    // 時間駆動の送出・イベント・mDNS announce。
    stack.pump(now, udp_send);
    stack.mdns_poll(now, mdns_send);
  }
  return 0;
}
