// `smscript` パーティションイメージ("SMWS" ヘッダ + .wasm 本体)。
//
// 正実装は `scripts/smscript-img.py` /
// `ports/esp-idf/examples/generic_matter_cpp/main/script_img.hpp`:
//
//   offset 0  4B  magic "SMWS"
//          4  2B  ver   u16 LE
//          6  2B  flags u16 LE(予約)
//          8  4B  len   u32 LE
//         12  4B  crc32 u32 LE(本体 len バイト、初期値 0)

import { crc32, concatBytes } from "./util.js";

export const MAGIC = new Uint8Array([0x53, 0x4d, 0x57, 0x53]); // "SMWS"
export const HDR_SIZE = 16;
/** 1 スロットのサイズ(128 KiB)。`smscript` パーティションは 2 スロット = 256 KiB。 */
export const SLOT_SIZE = 0x20000;
export const MAX_LEN = SLOT_SIZE - HDR_SIZE;

/** .wasm 本体 → SMWS イメージ。 */
export function packScript(body, ver = 1, flags = 0) {
  if (body.length === 0 || body.length > MAX_LEN) {
    throw new Error(`script body must be 1..${MAX_LEN} bytes (got ${body.length})`);
  }
  const hdr = new Uint8Array(HDR_SIZE);
  hdr.set(MAGIC, 0);
  const dv = new DataView(hdr.buffer);
  dv.setUint16(4, ver, true);
  dv.setUint16(6, flags, true);
  dv.setUint32(8, body.length, true);
  dv.setUint32(12, crc32(body, 0), true);
  return concatBytes(hdr, body);
}

/** SMWS イメージの検査(不正なら例外)。 */
export function unpackScript(img) {
  if (img.length < HDR_SIZE || !MAGIC.every((b, i) => img[i] === b)) {
    throw new Error("bad magic (not an smscript image)");
  }
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const ver = dv.getUint16(4, true);
  const flags = dv.getUint16(6, true);
  const len = dv.getUint32(8, true);
  const crc = dv.getUint32(12, true);
  if (len === 0 || len > MAX_LEN) {
    throw new Error(`bad length ${len}`);
  }
  const body = img.subarray(HDR_SIZE, HDR_SIZE + len);
  if (body.length !== len) {
    throw new Error(`truncated body (${body.length} < ${len})`);
  }
  const actual = crc32(body, 0);
  if (actual !== crc) {
    throw new Error(`CRC mismatch (header ${crc.toString(16)}, actual ${actual.toString(16)})`);
  }
  return { ver, flags, len, crc, body };
}

/** WASM マジック(`\0asm`)かどうか。 */
export function looksLikeWasm(bytes) {
  return (
    bytes.length >= 4 && bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d
  );
}
