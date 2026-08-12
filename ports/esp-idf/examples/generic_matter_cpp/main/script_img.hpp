// スクリプトイメージ(`smscript` パーティション)のヘッダ形式。
// docs/design/generic-firmware.md §9.3(ロード)/ §9.4(ScriptStore = Phase D)共通。
//
// **ESP-IDF 非依存のヘッダオンリー**(ファーム・ホストハーネス・ツールで共用)。
//
// パーティション(256KB)は 2 スロット構成:
//
//   slot A: offset 0x00000 .. 0x1FFFF (128KB)
//   slot B: offset 0x20000 .. 0x3FFFF (128KB)
//
// 各スロットの先頭 16 バイトがヘッダ:
//
//   offset size 内容
//   0      4    magic  "SMWS"
//   4      2    ver    u16 LE(スクリプトの世代。大きい方が新しい)
//   6      2    flags  u16 LE(予約、0)
//   8      4    len    u32 LE(ヘッダに続く本体バイト数)
//   12     4    crc32  u32 LE(本体 len バイトの CRC-32/IEEE)
//
// active slot = 「ヘッダが妥当(magic 一致・len が上限以内・CRC 一致)なスロットのうち
// ver が最大のもの」。同値なら A。両方無効なら「スクリプト無し」= 従来どおり動く。
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace smgen {

static constexpr size_t kScriptHdrSize = 16;
static constexpr size_t kScriptSlotSize = 0x20000; // 128KB
static constexpr size_t kScriptSlots = 2;
// 本体の上限(スロットサイズ - ヘッダ)。
static constexpr size_t kScriptMaxLen = kScriptSlotSize - kScriptHdrSize;

struct ScriptHeader {
  uint16_t ver = 0;
  uint16_t flags = 0;
  uint32_t len = 0;
  uint32_t crc32 = 0;
};

// CRC-32/IEEE(zlib 互換。反射多項式 0xEDB88320、初期値 0xFFFFFFFF、最終 XOR)。
// テーブルを持たないビット単位実装(数十 KB のスクリプトで十分速い)。
inline uint32_t script_crc32(const uint8_t *data, size_t len, uint32_t seed = 0) {
  uint32_t crc = ~seed;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int b = 0; b < 8; b++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
    }
  }
  return ~crc;
}

// ヘッダ(16B)をパースする。magic 不一致 / len 超過は false。
inline bool script_hdr_parse(const uint8_t *buf, size_t len, ScriptHeader &out) {
  if (buf == nullptr || len < kScriptHdrSize) {
    return false;
  }
  if (memcmp(buf, "SMWS", 4) != 0) {
    return false;
  }
  out.ver = (uint16_t)((uint16_t)buf[4] | ((uint16_t)buf[5] << 8));
  out.flags = (uint16_t)((uint16_t)buf[6] | ((uint16_t)buf[7] << 8));
  out.len = (uint32_t)buf[8] | ((uint32_t)buf[9] << 8) | ((uint32_t)buf[10] << 16) |
            ((uint32_t)buf[11] << 24);
  out.crc32 = (uint32_t)buf[12] | ((uint32_t)buf[13] << 8) | ((uint32_t)buf[14] << 16) |
              ((uint32_t)buf[15] << 24);
  return out.len > 0 && out.len <= kScriptMaxLen;
}

// ヘッダ(16B)を書く。
inline void script_hdr_write(uint8_t *buf, const ScriptHeader &h) {
  memcpy(buf, "SMWS", 4);
  buf[4] = (uint8_t)(h.ver & 0xFF);
  buf[5] = (uint8_t)(h.ver >> 8);
  buf[6] = (uint8_t)(h.flags & 0xFF);
  buf[7] = (uint8_t)(h.flags >> 8);
  buf[8] = (uint8_t)(h.len & 0xFF);
  buf[9] = (uint8_t)((h.len >> 8) & 0xFF);
  buf[10] = (uint8_t)((h.len >> 16) & 0xFF);
  buf[11] = (uint8_t)((h.len >> 24) & 0xFF);
  buf[12] = (uint8_t)(h.crc32 & 0xFF);
  buf[13] = (uint8_t)((h.crc32 >> 8) & 0xFF);
  buf[14] = (uint8_t)((h.crc32 >> 16) & 0xFF);
  buf[15] = (uint8_t)((h.crc32 >> 24) & 0xFF);
}

// スロット s の先頭オフセット。
inline size_t script_slot_offset(size_t slot) { return slot * kScriptSlotSize; }

} // namespace smgen
