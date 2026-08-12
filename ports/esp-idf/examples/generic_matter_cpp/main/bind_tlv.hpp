// binding TLV(HAL バインディング表)のスキーマとパーサ。
// docs/design/generic-firmware.md §9.2。
//
// **ESP-IDF 非依存のヘッダオンリー実装**にしてある(ホスト側の検証プログラム
// crates/simple-matter-cffi/ctest/compose_check.cpp が同じコードで hex を検算するため)。
//
// スキーマ(素の Matter TLV。context tag のみ):
//
//   anonymous list|array of binding structs:     ← struct 直書き(単一 binding)も受理
//     {
//       0: endpoint u16   必須(1..)
//       1: cluster  u32   必須(ドライバを結び付けるクラスタ ID)
//       2: drv-id   u8    必須(1=gpio_out 2=gpio_in 3=ledc 4=i2c_sht30 5=script)
//       3: params   struct  ドライバ固有(context tag → スカラ)。省略可
//     }
//
// params の context tag はドライバごと(scripts/smgen-tlv.py の PARAMS と同一):
//
//   gpio_out (1): 0=pin u8, 1=invert bool
//   gpio_in  (2): 0=pin u8, 1=invert bool, 2=poll_ms u16, 3=pull u8(0=none 1=up 2=down)
//   ledc     (3): 0=ch u8, 1=pin u8, 2=freq u32, 3=invert bool
//   i2c_sht30(4): 0=sda u8, 1=scl u8, 2=poll_ms u16, 3=port u8
//   script   (5): 予約(Phase C でスクリプトフックへ委譲)
//
// パーサは params を「context tag → u64」の疎な表として保持するだけなので、
// ドライバ追加時にパーサを触る必要はない(ドライバ側が param() で読む)。
#pragma once

#include <cstddef>
#include <cstdint>

namespace smgen {

// ドライバ ID(binding TLV の tag 2)。
enum DrvId : uint8_t {
  DRV_NONE = 0,
  DRV_GPIO_OUT = 1,
  DRV_GPIO_IN = 2,
  DRV_LEDC = 3,
  DRV_I2C_SHT30 = 4,
  DRV_SCRIPT = 5,
};

// バインディング 1 件あたりの params 上限(context tag 0..7)。
static constexpr size_t kMaxParams = 8;
// バインディング表の上限。
static constexpr size_t kMaxBindings = 16;

struct Binding {
  uint16_t ep = 0;
  uint32_t cluster = 0;
  uint8_t drv = DRV_NONE;
  uint64_t p[kMaxParams] = {};
  bool has[kMaxParams] = {};
  // ドライバの実行時状態(パーサは触らない)。
  int32_t state = 0;
  int32_t state2 = 0;
  uint64_t next_ms = 0;
  void *handle = nullptr;

  // params[tag] を取り出す(未指定なら def)。
  uint64_t param(size_t tag, uint64_t def) const {
    return (tag < kMaxParams && has[tag]) ? p[tag] : def;
  }
};

struct BindingTable {
  Binding items[kMaxBindings];
  size_t n = 0;

  // (ep, cluster) に結び付いた最初のバインディングを返す(無ければ nullptr)。
  Binding *find(uint16_t ep, uint32_t cluster) {
    for (size_t i = 0; i < n; i++) {
      if (items[i].ep == ep && items[i].cluster == cluster) {
        return &items[i];
      }
    }
    return nullptr;
  }
};

// パース結果。
enum BindParseRc : int {
  BIND_OK = 0,
  BIND_ERR_TLV = -1,      // TLV として不正
  BIND_ERR_SCHEMA = -2,   // スキーマ違反(ep=0 / drv 不明 など)
  BIND_ERR_CAPACITY = -3, // kMaxBindings 超過
};

namespace detail {

// 最小 Matter TLV リーダ。
struct Reader {
  const uint8_t *d;
  size_t len;
  size_t i = 0;

  bool eof() const { return i >= len; }
  bool take(size_t n, const uint8_t **out) {
    if (i + n > len) {
      return false;
    }
    *out = d + i;
    i += n;
    return true;
  }
};

// エレメント種別。
enum Kind { K_INT, K_UINT, K_BOOL, K_NULL, K_START, K_END, K_OTHER };

struct Elem {
  int tag = -1; // context tag(anonymous / それ以外は -1)
  Kind kind = K_OTHER;
  uint64_t u = 0;
  int64_t i = 0;
  uint8_t ctype = 0; // K_START のときコンテナ型(0x15/0x16/0x17)
};

// 1 エレメント読む。失敗(不正/末尾)は false。
inline bool read_elem(Reader &r, Elem &e) {
  const uint8_t *p;
  if (!r.take(1, &p)) {
    return false;
  }
  const uint8_t c = *p;
  const uint8_t tagctrl = (uint8_t)(c >> 5);
  const uint8_t etype = (uint8_t)(c & 0x1F);
  e = Elem{};
  if (tagctrl == 0) {
    e.tag = -1;
  } else if (tagctrl == 1) {
    if (!r.take(1, &p)) {
      return false;
    }
    e.tag = (int)*p;
  } else {
    // common / implicit / fully-qualified タグは使わない(読み飛ばす)。
    static const size_t kTagBytes[8] = {0, 1, 2, 4, 2, 4, 6, 8};
    if (!r.take(kTagBytes[tagctrl], &p)) {
      return false;
    }
    e.tag = -1;
  }
  auto le = [](const uint8_t *b, size_t n) -> uint64_t {
    uint64_t v = 0;
    for (size_t k = 0; k < n; k++) {
      v |= (uint64_t)b[k] << (8 * k);
    }
    return v;
  };
  switch (etype) {
  case 0x00:
  case 0x01:
  case 0x02:
  case 0x03: { // int8/16/32/64
    const size_t n = (size_t)1u << etype;
    if (!r.take(n, &p)) {
      return false;
    }
    uint64_t v = le(p, n);
    const uint64_t sign = 1ull << (8 * n - 1);
    e.kind = K_INT;
    e.i = (int64_t)((v ^ sign) - sign);
    e.u = v;
    return true;
  }
  case 0x04:
  case 0x05:
  case 0x06:
  case 0x07: { // uint8/16/32/64
    const size_t n = (size_t)1u << (etype - 0x04);
    if (!r.take(n, &p)) {
      return false;
    }
    e.kind = K_UINT;
    e.u = le(p, n);
    e.i = (int64_t)e.u;
    return true;
  }
  case 0x08:
  case 0x09:
    e.kind = K_BOOL;
    e.u = (etype == 0x09) ? 1 : 0;
    return true;
  case 0x0A: // float
    e.kind = K_OTHER;
    return r.take(4, &p);
  case 0x0B: // double
    e.kind = K_OTHER;
    return r.take(8, &p);
  case 0x0C:
  case 0x0D:
  case 0x0E:
  case 0x0F:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13: { // utf8 / octet string(長さ 1/2/4/8 バイト)
    const size_t lw = (size_t)1u << (etype & 0x03);
    if (!r.take(lw, &p)) {
      return false;
    }
    const uint64_t n = le(p, lw);
    if (!r.take((size_t)n, &p)) {
      return false;
    }
    e.kind = K_OTHER;
    return true;
  }
  case 0x14:
    e.kind = K_NULL;
    return true;
  case 0x15:
  case 0x16:
  case 0x17:
    e.kind = K_START;
    e.ctype = etype;
    return true;
  case 0x18:
    e.kind = K_END;
    return true;
  default:
    return false;
  }
}

// コンテナ(開始トークン消費済み)を末尾まで読み飛ばす。
inline bool skip_container(Reader &r) {
  int depth = 1;
  Elem e;
  while (depth > 0) {
    if (!read_elem(r, e)) {
      return false;
    }
    if (e.kind == K_START) {
      depth++;
    } else if (e.kind == K_END) {
      depth--;
    }
  }
  return true;
}

// binding struct(開始トークン消費済み)を 1 件読む。
inline int read_binding(Reader &r, Binding &b) {
  Elem e;
  bool have_ep = false, have_cl = false, have_drv = false;
  for (;;) {
    if (!read_elem(r, e)) {
      return BIND_ERR_TLV;
    }
    if (e.kind == K_END) {
      break;
    }
    if (e.tag == 0 && (e.kind == K_UINT || e.kind == K_INT)) {
      b.ep = (uint16_t)e.u;
      have_ep = true;
    } else if (e.tag == 1 && (e.kind == K_UINT || e.kind == K_INT)) {
      b.cluster = (uint32_t)e.u;
      have_cl = true;
    } else if (e.tag == 2 && (e.kind == K_UINT || e.kind == K_INT)) {
      b.drv = (uint8_t)e.u;
      have_drv = true;
    } else if (e.tag == 3 && e.kind == K_START) {
      // params struct: context tag → スカラ。
      for (;;) {
        Elem q;
        if (!read_elem(r, q)) {
          return BIND_ERR_TLV;
        }
        if (q.kind == K_END) {
          break;
        }
        if (q.kind == K_START) {
          if (!skip_container(r)) {
            return BIND_ERR_TLV;
          }
          continue;
        }
        if (q.tag >= 0 && (size_t)q.tag < kMaxParams &&
            (q.kind == K_UINT || q.kind == K_INT || q.kind == K_BOOL)) {
          b.p[q.tag] = q.u;
          b.has[q.tag] = true;
        }
      }
    } else if (e.kind == K_START) {
      if (!skip_container(r)) {
        return BIND_ERR_TLV;
      }
    }
  }
  if (!have_ep || !have_cl || !have_drv || b.ep == 0) {
    return BIND_ERR_SCHEMA;
  }
  if (b.drv == DRV_NONE || b.drv > DRV_SCRIPT) {
    return BIND_ERR_SCHEMA;
  }
  return BIND_OK;
}

} // namespace detail

// binding TLV blob をパースする。0 = OK、負値 = `BindParseRc`。
inline int parse_bindings(const uint8_t *blob, size_t len, BindingTable &out) {
  out.n = 0;
  if (blob == nullptr || len == 0) {
    return BIND_OK; // 空 = バインディング無し。
  }
  detail::Reader r{blob, len, 0};
  detail::Elem e;
  if (!detail::read_elem(r, e) || e.kind != detail::K_START) {
    return BIND_ERR_TLV;
  }
  if (e.ctype == 0x15) { // struct 直書き = 単一 binding。
    int rc = detail::read_binding(r, out.items[0]);
    if (rc != BIND_OK) {
      return rc;
    }
    out.n = 1;
    return BIND_OK;
  }
  for (;;) {
    if (!detail::read_elem(r, e)) {
      return BIND_ERR_TLV;
    }
    if (e.kind == detail::K_END) {
      break;
    }
    if (e.kind != detail::K_START) {
      continue; // 素の値は無視。
    }
    if (e.ctype != 0x15) {
      if (!detail::skip_container(r)) {
        return BIND_ERR_TLV;
      }
      continue;
    }
    if (out.n >= kMaxBindings) {
      return BIND_ERR_CAPACITY;
    }
    int rc = detail::read_binding(r, out.items[out.n]);
    if (rc != BIND_OK) {
      return rc;
    }
    out.n++;
  }
  return BIND_OK;
}

// ドライバ名(ログ表示用)。
inline const char *drv_name(uint8_t drv) {
  switch (drv) {
  case DRV_GPIO_OUT:
    return "gpio_out";
  case DRV_GPIO_IN:
    return "gpio_in";
  case DRV_LEDC:
    return "ledc";
  case DRV_I2C_SHT30:
    return "i2c_sht30";
  case DRV_SCRIPT:
    return "script";
  default:
    return "?";
  }
}

} // namespace smgen
