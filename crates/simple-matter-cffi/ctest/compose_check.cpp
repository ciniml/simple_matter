// composition / binding blob のホスト検算(Phase B、docs/design/generic-firmware.md §9.2)。
//
// generic_matter_cpp の README に載せる hex 例が「本当にその構成になる」ことを、
// 実機や無線なしで確かめるための小さなハーネス:
//
//   1. `--bind <hex>` を **ファームと同一の実装**(ports/esp-idf/examples/generic_matter_cpp/
//      main/bind_tlv.hpp。ESP-IDF 非依存のヘッダオンリー)でパースして表示する。
//   2. `--comp <hex>` を `sm_config_t.composition` に渡して `sm_init` し(rc=0 なら
//      composition TLV は妥当)、合成された (endpoint, cluster) を `sm_attr_get_value`
//      で走査して列挙する。
//   3. `--expect ep:cluster,...` を与えると、走査結果と**完全一致**するか検証する
//      (過不足どちらも FAIL)。
//
// 使い方:
//   ./compose_check --comp <hex> [--bind <hex>] [--expect 1:0006,1:0008] [-v]

#include "bind_tlv.hpp"
#include "simple_matter.h"

#include <sys/random.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

bool g_verbose = false;

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

int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hex_decode(const char *s, std::vector<uint8_t> &out) {
  out.clear();
  int hi = -1;
  for (const char *p = s; *p; ++p) {
    if (*p == ' ' || *p == '_' || *p == ':') continue;
    int v = hex_val(*p);
    if (v < 0) return false;
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back((uint8_t)((hi << 4) | v));
      hi = -1;
    }
  }
  return hi < 0;
}

// 走査対象(合成可能クラスタ ID と、その存在確認に使う属性)。§9.1 の初期プール。
struct Probe {
  uint32_t cluster;
  uint32_t attr;
  const char *name;
};
const Probe kProbes[] = {
    {0x0003, 0x0000, "Identify"},     {0x0004, 0x0000, "Groups"},
    {0x0006, 0x0000, "OnOff"},        {0x0008, 0x0000, "LevelControl"},
    {0x003B, 0x0001, "Switch"},       {0x0045, 0x0000, "BooleanState"},
    {0x0101, 0x0000, "DoorLock"},     {0x0201, 0x0000, "Thermostat"},
    {0x0202, 0x0000, "FanControl"},   {0x0300, 0x0000, "ColorControl"},
    {0x0400, 0x0000, "Illuminance"},  {0x0402, 0x0000, "Temperature"},
    {0x0403, 0x0000, "Pressure"},     {0x0404, 0x0000, "Flow"},
    {0x0405, 0x0000, "Humidity"},     {0x0406, 0x0000, "Occupancy"},
};

// 「ep:cluster」を 1 個の 64 ビットキーにする。
uint64_t key_of(uint16_t ep, uint32_t cluster) { return ((uint64_t)ep << 32) | cluster; }

} // namespace

int main(int argc, char **argv) {
  const char *comp_hex = nullptr;
  const char *bind_hex = nullptr;
  const char *expect = nullptr;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--comp") && i + 1 < argc) {
      comp_hex = argv[++i];
    } else if (!strcmp(argv[i], "--bind") && i + 1 < argc) {
      bind_hex = argv[++i];
    } else if (!strcmp(argv[i], "--expect") && i + 1 < argc) {
      expect = argv[++i];
    } else if (!strcmp(argv[i], "-v")) {
      g_verbose = true;
    } else {
      fprintf(stderr, "usage: %s --comp <hex> [--bind <hex>] [--expect ep:cluster,...] [-v]\n",
              argv[0]);
      return 2;
    }
  }
  if (!comp_hex) {
    fprintf(stderr, "error: --comp is required\n");
    return 2;
  }

  // ---- 1. binding TLV(ファームと同一のパーサ) ----
  if (bind_hex) {
    std::vector<uint8_t> blob;
    if (!hex_decode(bind_hex, blob)) {
      fprintf(stderr, "FAIL: --bind is not valid hex\n");
      return 1;
    }
    smgen::BindingTable t;
    int rc = smgen::parse_bindings(blob.data(), blob.size(), t);
    if (rc != smgen::BIND_OK) {
      fprintf(stderr, "FAIL: binding TLV rejected (rc=%d, %u bytes)\n", rc, (unsigned)blob.size());
      return 1;
    }
    printf("binding blob: %u bytes, %u entries\n", (unsigned)blob.size(), (unsigned)t.n);
    for (size_t i = 0; i < t.n; i++) {
      const smgen::Binding &b = t.items[i];
      printf("  [%u] ep=%u cluster=0x%04x drv=%s params=", (unsigned)i, b.ep, (unsigned)b.cluster,
             smgen::drv_name(b.drv));
      for (size_t k = 0; k < smgen::kMaxParams; k++) {
        if (b.has[k]) printf("%u:%llu ", (unsigned)k, (unsigned long long)b.p[k]);
      }
      printf("\n");
    }
  }

  // ---- 2. composition TLV -> sm_init ----
  std::vector<uint8_t> comp;
  if (!hex_decode(comp_hex, comp)) {
    fprintf(stderr, "FAIL: --comp is not valid hex\n");
    return 1;
  }
  static const uint8_t kDevSalt[16] = {'S', 'P', 'A', 'K', 'E', '2', 'P', ' ',
                                       'K', 'e', 'y', ' ', 'S', 'a', 'l', 't'};
  sm_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.discriminator = 3840;
  cfg.passcode = 20202021;
  cfg.verifier_salt = kDevSalt;
  cfg.verifier_salt_len = sizeof(kDevSalt);
  cfg.vendor_id = 0xFFF1;
  cfg.product_id = 0x8001;
  cfg.device_name = "GenericMatter";
  for (int i = 0; i < 6; i++) cfg.mac[i] = (uint8_t)(0x10 + i);
  cfg.rng_fill = rng_fill; // KVS は NULL(永続化なし)。
  cfg.network = SM_NET_WIFI;
  cfg.composition = comp.data();
  cfg.composition_len = comp.size();

  int32_t rc = sm_init(&cfg, 0);
  if (rc != 0) {
    fprintf(stderr, "FAIL: sm_init rc=%d (composition %u bytes; -7=TLV invalid, -8=capacity)\n",
            rc, (unsigned)comp.size());
    return 1;
  }
  printf("composition blob: %u bytes, sm_init ok\n", (unsigned)comp.size());

  // 合成された (endpoint, cluster) を走査する(-2 = クラスタ無し)。
  std::vector<uint64_t> found;
  for (uint16_t ep = 1; ep <= 8; ep++) {
    bool any = false;
    for (const Probe &p : kProbes) {
      sm_attr_value_t v;
      memset(&v, 0, sizeof(v));
      int32_t r = sm_attr_get_value(ep, p.cluster, p.attr, &v);
      if (r == -2) {
        continue; // このクラスタは合成されていない。
      }
      if (!any) {
        printf("  EP%u:\n", ep);
        any = true;
      }
      found.push_back(key_of(ep, p.cluster));
      if (r == 0) {
        printf("    0x%04x %-13s value=%llu%s\n", (unsigned)p.cluster, p.name,
               (unsigned long long)v.v.u, v.is_null ? " (null)" : "");
      } else {
        printf("    0x%04x %-13s (present; attr 0x%04x not exposed, rc=%d)\n", (unsigned)p.cluster,
               p.name, (unsigned)p.attr, r);
      }
    }
  }

  // ---- 3. --expect との照合 ----
  if (expect) {
    std::vector<uint64_t> want;
    std::string s(expect);
    size_t pos = 0;
    while (pos < s.size()) {
      size_t comma = s.find(',', pos);
      std::string item = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
      pos = (comma == std::string::npos) ? s.size() : comma + 1;
      size_t colon = item.find(':');
      if (colon == std::string::npos) {
        fprintf(stderr, "FAIL: bad --expect item '%s'\n", item.c_str());
        return 1;
      }
      uint16_t ep = (uint16_t)strtoul(item.substr(0, colon).c_str(), nullptr, 0);
      uint32_t cl = (uint32_t)strtoul(item.substr(colon + 1).c_str(), nullptr, 16);
      want.push_back(key_of(ep, cl));
    }
    bool ok = true;
    for (uint64_t k : want) {
      bool hit = false;
      for (uint64_t f : found) hit = hit || (f == k);
      if (!hit) {
        fprintf(stderr, "FAIL: expected EP%u cluster 0x%04x is missing\n", (unsigned)(k >> 32),
                (unsigned)(k & 0xFFFFFFFF));
        ok = false;
      }
    }
    for (uint64_t f : found) {
      bool hit = false;
      for (uint64_t k : want) hit = hit || (f == k);
      if (!hit) {
        fprintf(stderr, "FAIL: unexpected EP%u cluster 0x%04x was composed\n", (unsigned)(f >> 32),
                (unsigned)(f & 0xFFFFFFFF));
        ok = false;
      }
    }
    if (!ok) {
      return 1;
    }
    printf("expect: %u (endpoint, cluster) pairs matched exactly\n", (unsigned)want.size());
  }

  printf("COMPOSE CHECK OK\n");
  return 0;
}
