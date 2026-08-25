// SPAKE2+ verifier(w0 ‖ L)の生成。
//
// 正実装は `crates/simple-matter/src/crypto/spake2p.rs::compute_verifier`
// (= `cargo run -p smctl -- pase-verifier`)。手順(Matter 仕様 §3.10):
//
//   1. PBKDF2-HMAC-SHA256(password = passcode の u32 リトルエンディアン 4 バイト,
//      salt, iterations, dkLen = 80) → w0s ‖ w1s(各 40 バイト)
//   2. w0 = int(w0s, big-endian) mod n、w1 = int(w1s, big-endian) mod n
//   3. L = w1 * G(SEC1 非圧縮 65 バイト)
//   4. デバイスへ渡すのは `w0(32) ‖ L(65)` = 97 バイトと salt / iterations だけ
//      (passcode はデバイスに置かない)。
//
// PBKDF2 は WebCrypto、P-256 のスカラ倍は vendor の @noble/curves。

import { p256 } from "../vendor/noble/noble-p256.js";

/** SPAKE2+ の PBKDF2 中間値 w0s / w1s 各々の長さ(CRYPTO_W_SIZE_BYTES)。 */
export const W_LEN = 40;
/** w0 の長さ(P-256 スカラ)。 */
export const SCALAR_LEN = 32;
/** L の長さ(SEC1 非圧縮点)。 */
export const POINT_LEN = 65;

/** WebCrypto の SubtleCrypto を取り出す(ブラウザ / Node 双方)。 */
function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error("WebCrypto (crypto.subtle) is unavailable; use HTTPS or http://localhost");
  }
  return c.subtle;
}

/** ビッグエンディアンのバイト列 → BigInt。 */
function beToBigInt(bytes) {
  let x = 0n;
  for (const b of bytes) {
    x = (x << 8n) | BigInt(b);
  }
  return x;
}

/** BigInt → 固定長ビッグエンディアンのバイト列。 */
function bigIntToBe(x, len) {
  const out = new Uint8Array(len);
  let v = x;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) {
    throw new Error("value does not fit the requested length");
  }
  return out;
}

/** PBKDF2-HMAC-SHA256(WebCrypto)。 */
export async function pbkdf2Sha256(password, salt, iterations, dkLenBytes) {
  const key = await subtle().importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    dkLenBytes * 8
  );
  return new Uint8Array(bits);
}

/**
 * SPAKE2+ verifier を計算する。
 *
 * @param {number} passcode 8 桁 setup passcode(1..99999998、無効値は除く)
 * @param {Uint8Array} salt 16..32 バイト
 * @param {number} iterations PBKDF2 反復回数(1000..100000)
 * @returns `{ w0, l, w0l }`(w0 = 32B、l = 65B、w0l = 97B)
 */
export async function computeVerifier(passcode, salt, iterations) {
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("iterations must be a positive integer");
  }
  if (salt.length < 16 || salt.length > 32) {
    throw new Error(`salt must be 16..32 bytes (got ${salt.length})`);
  }
  // password = passcode の u32 リトルエンディアン。
  const pw = new Uint8Array(4);
  new DataView(pw.buffer).setUint32(0, passcode >>> 0, true);

  const ws = await pbkdf2Sha256(pw, salt, iterations, W_LEN * 2);
  const n = p256.Point.CURVE().n;
  const w0 = beToBigInt(ws.subarray(0, W_LEN)) % n;
  const w1 = beToBigInt(ws.subarray(W_LEN)) % n;

  const w0Bytes = bigIntToBe(w0, SCALAR_LEN);
  const l = p256.Point.BASE.multiply(w1).toBytes(false);
  if (l.length !== POINT_LEN) {
    throw new Error(`unexpected point encoding length ${l.length}`);
  }

  const w0l = new Uint8Array(SCALAR_LEN + POINT_LEN);
  w0l.set(w0Bytes, 0);
  w0l.set(l, SCALAR_LEN);
  return { w0: w0Bytes, l: new Uint8Array(l), w0l };
}
