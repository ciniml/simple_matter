// 汎用ユーティリティ(hex / base64 / CRC32 / バイト連結)。
//
// ブラウザと Node の双方で動くよう、Web API(btoa/atob、Buffer)に依存しない
// 素の実装にしてある(`node --test web/configurator/test/` から同じコードを検証する)。

/** バイト列 → 小文字 hex 文字列。 */
export function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) {
    s += b.toString(16).padStart(2, "0");
  }
  return s;
}

/** hex 文字列 → Uint8Array(空白 / `:` / `_` は無視)。 */
export function hexToBytes(hex) {
  const clean = hex.replace(/[\s:_]/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error(`invalid hex string (${clean.length} chars)`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** バイト列 → base64(パディング付き)。 */
export function bytesToBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64_ALPHABET[b0 >> 2];
    out += B64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] : "=";
    out += i + 2 < bytes.length ? B64_ALPHABET[b2 & 0x3f] : "=";
  }
  return out;
}

/** base64 → Uint8Array。 */
export function base64ToBytes(s) {
  const clean = s.replace(/[\s=]/g, "");
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const ch of clean) {
    const v = B64_ALPHABET.indexOf(ch);
    if (v < 0) {
      throw new Error(`invalid base64 character ${JSON.stringify(ch)}`);
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

// ---- CRC32(IEEE 802.3、reflected)-----------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[i] = c >>> 0;
  }
  return t;
})();

/**
 * CRC32(zlib / Python `binascii.crc32(data, prev)` と同一のセマンティクス)。
 *
 * ESP-IDF の `esp_rom_crc32_le(crc, buf, len)` はこれと**同じ値**を返す
 * (`crc32(buf, crc)`)。NVS のエントリ CRC は初期値 `0xFFFFFFFF`、
 * SMWS イメージの CRC(`scripts/smscript-img.py`)は初期値 `0`。
 */
export function crc32(bytes, prev = 0) {
  let c = (~prev) >>> 0;
  for (const b of bytes) {
    c = (CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8)) >>> 0;
  }
  return (~c) >>> 0;
}

/** Uint8Array 群を連結する。 */
export function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** UTF-8 エンコード(TextEncoder は Node/ブラウザ双方にある)。 */
export function utf8(s) {
  return new TextEncoder().encode(s);
}
