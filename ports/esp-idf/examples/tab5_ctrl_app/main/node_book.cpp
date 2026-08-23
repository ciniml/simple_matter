// node_book.hpp の実体 — Matter TLV の最小リーダで "nods" v1 を舐める。

#include "node_book.hpp"

#include <cstring>

#include "esp_log.h"
#include "nvs.h"

namespace {

constexpr const char *TAG = "node_book";
constexpr const char *SM_NVS_NAMESPACE = "smctl";
constexpr const char *NODES_KEY = "nods";

// "nods" の最大長: nodes_max_len(MAX_NODES=8) = 8 + 8*112 = 904。余裕を見て 1024。
constexpr size_t NODES_BLOB_CAP = 1024;

// Matter TLV の element type(control byte 下位 5 ビット)。
constexpr uint8_t TLV_STRUCT = 0x15;
constexpr uint8_t TLV_ARRAY = 0x16;
constexpr uint8_t TLV_LIST = 0x17;
constexpr uint8_t TLV_END = 0x18;

// TLV 要素を 1 つ読む。`tag` は context タグ番号(anonymous / その他は -1)。
// 値バイト列(utf8 / bytes)は `bytes`/`blen` に、整数は `uval` に返す。
bool tlv_next(const uint8_t **pp, const uint8_t *end, int *tag, uint8_t *type, uint64_t *uval,
              const uint8_t **bytes, size_t *blen) {
  const uint8_t *p = *pp;
  if (p >= end) {
    return false;
  }
  const uint8_t ctrl = *p++;
  const uint8_t tag_ctrl = (uint8_t)(ctrl >> 5);
  const uint8_t t = (uint8_t)(ctrl & 0x1f);
  *tag = -1;
  *type = t;
  *uval = 0;
  *bytes = nullptr;
  *blen = 0;

  // タグ長: 0=anonymous, 1=context(1B), 2/3=common(2/4B), 4/5=implicit(2/4B),
  // 6=fully qualified(6B), 7=fully qualified(8B)。
  static const uint8_t TAG_LEN[8] = {0, 1, 2, 4, 2, 4, 6, 8};
  const size_t tag_len = TAG_LEN[tag_ctrl];
  if ((size_t)(end - p) < tag_len) {
    return false;
  }
  if (tag_ctrl == 1) {
    *tag = (int)p[0];
  }
  p += tag_len;

  if (t <= 0x07) { // 符号付き/符号なし整数 1/2/4/8 バイト
    const size_t vlen = (size_t)1u << (t & 0x03);
    if ((size_t)(end - p) < vlen) {
      return false;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < vlen; ++i) {
      v |= (uint64_t)p[i] << (8 * i);
    }
    *uval = v;
    p += vlen;
  } else if (t == 0x08 || t == 0x09) { // bool false / true
    *uval = (t == 0x09) ? 1 : 0;
  } else if (t == 0x0a) { // float
    p += 4;
  } else if (t == 0x0b) { // double
    p += 8;
  } else if (t >= 0x0c && t <= 0x13) { // utf8 / byte string(長さ 1/2/4/8 バイト)
    const size_t llen = (size_t)1u << (t & 0x03);
    if ((size_t)(end - p) < llen) {
      return false;
    }
    size_t len = 0;
    for (size_t i = 0; i < llen; ++i) {
      len |= (size_t)p[i] << (8 * i);
    }
    p += llen;
    if ((size_t)(end - p) < len) {
      return false;
    }
    *bytes = p;
    *blen = len;
    p += len;
  }
  // 0x14 null / 0x15,0x16,0x17 コンテナ開始 / 0x18 終端 は値バイトなし。
  if (p > end) {
    return false;
  }
  *pp = p;
  return true;
}

} // namespace

size_t sm_node_ids_from_nvs(uint64_t *out, size_t cap) {
  if (out == nullptr || cap == 0) {
    return 0;
  }
  nvs_handle_t h;
  if (nvs_open(SM_NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
    ESP_LOGI(TAG, "no '%s' namespace yet (fresh device)", SM_NVS_NAMESPACE);
    return 0;
  }
  static uint8_t blob[NODES_BLOB_CAP];
  size_t len = sizeof(blob);
  const esp_err_t err = nvs_get_blob(h, NODES_KEY, blob, &len);
  nvs_close(h);
  if (err != ESP_OK) {
    ESP_LOGI(TAG, "no '%s' key (%s)", NODES_KEY, esp_err_to_name(err));
    return 0;
  }

  // 深さ 3(外側 struct → array → entry struct)の context tag 0 が NodeId。
  const uint8_t *p = blob;
  const uint8_t *end = blob + len;
  int depth = 0;
  uint64_t cur = 0;
  bool have = false;
  size_t n = 0;
  for (;;) {
    int tag = -1;
    uint8_t type = 0;
    uint64_t uval = 0;
    const uint8_t *bytes = nullptr;
    size_t blen = 0;
    if (!tlv_next(&p, end, &tag, &type, &uval, &bytes, &blen)) {
      break;
    }
    if (type == TLV_STRUCT || type == TLV_ARRAY || type == TLV_LIST) {
      ++depth;
      if (depth == 3) {
        cur = 0;
        have = false;
      }
      continue;
    }
    if (type == TLV_END) {
      if (depth == 3 && have && n < cap) {
        out[n++] = cur;
      }
      --depth;
      if (depth <= 0) {
        break;
      }
      continue;
    }
    if (depth == 3 && tag == 0 && type <= 0x07) {
      cur = uval;
      have = true;
    }
  }
  ESP_LOGI(TAG, "node book: %u node id(s) from NVS blob (%u bytes)", (unsigned)n, (unsigned)len);
  return n;
}
