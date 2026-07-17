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

// ---- F4b: カスタムクラスタ(EP2、vendor 領域クラスタ ID)----
//
// docs/design/c-ffi-shim.md §8。値の所有は C++ 側(ここ)で、read/write/invoke を
// C vtable としてシムへ渡す。sm_init より前に登録する。

constexpr uint16_t kCustomEndpoint = 2;
constexpr uint32_t kCustomCluster = 0xFFF1FC01u; // vendor 0xFFF1 の MS クラスタ(0xFC01)
constexpr uint32_t kCustomDeviceType = 0xFFF10055u;

// 属性 ID。
constexpr uint32_t kAttrWritableU16 = 0x0000; // U16 rw
constexpr uint32_t kAttrFlagBool = 0x0001;    // BOOL ro
constexpr uint32_t kAttrLabelStr = 0x0002;    // STRING ro
constexpr uint32_t kAttrSignedI16 = 0x0003;   // nullable i16 ro
constexpr uint32_t kAttrCounterU16 = 0x0004;  // U16 ro(周期更新 → mark_dirty)
constexpr uint32_t kCmdSetState = 0x0000;     // 引数 (u8, u16)

struct CustomState {
  uint16_t writable = 100;
  bool flag = false;
  int16_t signedv = -42;
  bool signed_null = false;
  uint16_t counter = 0;
};
CustomState g_custom;

extern "C" uint8_t custom_read(void *, uint32_t attr_id, sm_attr_value_t *out) {
  switch (attr_id) {
  case kAttrWritableU16:
    out->type = SM_T_U16;
    out->v.u = g_custom.writable;
    return 0;
  case kAttrFlagBool:
    out->type = SM_T_BOOL;
    out->v.b = g_custom.flag;
    return 0;
  case kAttrLabelStr: {
    out->type = SM_T_STRING;
    const char *s = "custom-label";
    size_t n = strlen(s);
    memcpy(out->v.bytes.buf, s, n);
    out->v.bytes.len = (uint8_t)n;
    return 0;
  }
  case kAttrSignedI16:
    out->type = SM_T_I16;
    if (g_custom.signed_null) {
      out->is_null = true;
    } else {
      out->v.i = g_custom.signedv;
    }
    return 0;
  case kAttrCounterU16:
    out->type = SM_T_U16;
    out->v.u = g_custom.counter;
    return 0;
  default:
    return 0x86; // UnsupportedAttribute
  }
}

extern "C" uint8_t custom_write(void *, uint32_t attr_id, const sm_attr_value_t *val) {
  if (attr_id == kAttrWritableU16) {
    g_custom.writable = (uint16_t)val->v.u;
    printf("CUSTOM write attr 0x%04x = %u\n", attr_id, g_custom.writable);
    fflush(stdout);
    return 0;
  }
  return 0x88; // UnsupportedWrite
}

extern "C" uint8_t custom_invoke(void *, uint32_t cmd_id, const sm_attr_value_t *args,
                                 size_t n_args, uint64_t now_ms) {
  if (cmd_id == kCmdSetState && n_args == 2) {
    uint8_t a = (uint8_t)args[0].v.u;
    uint16_t b = (uint16_t)args[1].v.u;
    g_custom.flag = (a != 0);
    g_custom.writable = b;
    printf("CUSTOM invoke cmd 0x%04x a=%u b=%u now=%llu\n", cmd_id, a, b,
           (unsigned long long)now_ms);
    fflush(stdout);
    return 0;
  }
  return 0x85; // InvalidCommand
}

void register_custom() {
  static const sm_attr_def_t attrs[] = {
      {kAttrWritableU16, SM_T_U16, SM_ATTR_WRITABLE},
      {kAttrFlagBool, SM_T_BOOL, 0},
      {kAttrLabelStr, SM_T_STRING, 0},
      {kAttrSignedI16, SM_T_I16, SM_ATTR_NULLABLE},
      {kAttrCounterU16, SM_T_U16, 0},
  };
  static const sm_cmd_def_t cmds[] = {
      {kCmdSetState, 0},
  };
  sm_cluster_def_t def;
  memset(&def, 0, sizeof(def));
  def.endpoint = kCustomEndpoint;
  def.cluster_id = kCustomCluster;
  def.revision = 1;
  def.feature_map = 0;
  def.attrs = attrs;
  def.n_attrs = sizeof(attrs) / sizeof(attrs[0]);
  def.cmds = cmds;
  def.n_cmds = sizeof(cmds) / sizeof(cmds[0]);
  def.read = custom_read;
  def.write = custom_write;
  def.invoke = custom_invoke;
  def.ctx = nullptr;
  int r1 = sm_endpoint_register(kCustomEndpoint, kCustomDeviceType, 1);
  int r2 = sm_cluster_register(&def);
  printf("custom register: endpoint rc=%d cluster rc=%d (EP%u cluster=0x%08x)\n", r1, r2,
         kCustomEndpoint, kCustomCluster);
  fflush(stdout);
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

  // 開発用 dev SPAKE2+ verifier(passcode 20202021 相当)。デバイスは passcode を保持せず
  // verifier だけを受け取る(Matter セキュリティ要件)。工場では passcode ごとに
  //   smctl pase-verifier 20202021 --salt 5350414b453250204b65792053616c74 --iterations 2000
  // で生成した w0‖L を書き込む。
  static const uint8_t kDevSalt[16] = {'S', 'P', 'A', 'K', 'E', '2', 'P', ' ',
                                       'K', 'e', 'y', ' ', 'S', 'a', 'l', 't'};
  static const uint8_t kDevVerifierW0L[97] = {
      0x7d, 0x04, 0x77, 0x6b, 0xb4, 0x69, 0xc4, 0x94, 0x92, 0x28, 0x30, 0x14,
      0x4f, 0x3f, 0xa2, 0xf1, 0x9c, 0xfd, 0x82, 0xc0, 0x4d, 0x10, 0x8d, 0x8b,
      0xa6, 0x35, 0x3f, 0xdd, 0x92, 0xc0, 0x1f, 0x93, 0x04, 0x51, 0x1b, 0x6c,
      0x47, 0x65, 0xba, 0xb1, 0x47, 0x94, 0x9d, 0xd9, 0x42, 0xc4, 0x3b, 0x3d,
      0x8d, 0xc6, 0x32, 0x30, 0x89, 0xca, 0x31, 0x89, 0xd9, 0xe4, 0xa5, 0x63,
      0x6e, 0x16, 0xd8, 0x2f, 0x1a, 0xef, 0x72, 0x8b, 0x0d, 0x90, 0x2c, 0x1a,
      0x9b, 0x0f, 0x7e, 0x96, 0x52, 0xab, 0x7f, 0x65, 0x78, 0x61, 0xb6, 0xbb,
      0xac, 0xd6, 0xbf, 0xdf, 0x04, 0xf8, 0x07, 0x09, 0x24, 0x8b, 0x83, 0xde,
      0xc7,
  };

  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  // passcode はデバイスに置かない(verifier 指定時は無視される)。
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
  cfg.kvs_get = kvs_get;
  cfg.kvs_set = kvs_set;
  cfg.kvs_delete = kvs_delete;
  cfg.kvs_ctx = nullptr;
  cfg.rng_fill = rng_fill;
  cfg.rng_ctx = nullptr;

  // カスタムクラスタは sm_init より前に登録する(F4b、§8)。
  register_custom();

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
  printf("  dev verifier (passcode 20202021, not stored) discriminator=3840 fabrics=%u onoff=%d\n",
         stack.fabric_count(),
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

    // カスタム属性の周期更新(Counter を 2 秒ごとに +1 → mark_dirty で購読へ)。
    static uint64_t last_counter_ms = 0;
    if (now - last_counter_ms >= 2000) {
      last_counter_ms = now;
      g_custom.counter++;
      sm_attr_mark_dirty(kCustomEndpoint, kCustomCluster, kAttrCounterU16);
    }

    // 時間駆動の送出・イベント・mDNS announce。
    stack.pump(now, udp_send);
    stack.mdns_poll(now, mdns_send);
  }
  return 0;
}
