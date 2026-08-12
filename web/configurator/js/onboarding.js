// Onboarding payload: setup passcode / discriminator の生成、Manual Pairing Code
// (11 桁 + Verhoeff)、QR コード payload(88 ビットのビットフィールド → Base38 → `MT:`)。
//
// 仕様: Matter Core §5.1.3(QR)/ §5.1.4(manual code)。
// 正実装の突き合わせ先: `crates/smctl/src/ops.rs::manual_pairing_code`
// (テストベクタ: discriminator 3840 / passcode 20202021 → `34970112332`)。

/** setup passcode として使えない値(仕様 §5.1.7.1)。 */
export const INVALID_PASSCODES = [
  0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999,
  12345678, 87654321,
];

/** setup passcode が有効か(1..=99999998 かつ禁止値でない)。 */
export function passcodeIsValid(p) {
  return Number.isInteger(p) && p >= 1 && p <= 99999998 && !INVALID_PASSCODES.includes(p);
}

/** 暗号論的乱数バイト列。 */
export function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

/** 有効な setup passcode を乱数生成する(無効値は引き直す)。 */
export function randomPasscode() {
  for (let i = 0; i < 64; i++) {
    const b = randomBytes(4);
    const v = new DataView(b.buffer).getUint32(0, true);
    const p = (v % 99999998) + 1;
    if (passcodeIsValid(p)) {
      return p;
    }
  }
  throw new Error("failed to draw a valid passcode");
}

/** 12 ビットの discriminator を乱数生成する。 */
export function randomDiscriminator() {
  const b = randomBytes(2);
  return ((b[0] | (b[1] << 8)) & 0x0fff) >>> 0;
}

// ---- Verhoeff(manual pairing code のチェックディジット)-----------------------

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/** Verhoeff チェックディジット(数字文字列に対して 1 桁)。 */
export function verhoeffCheckDigit(digits) {
  let c = 0;
  const rev = digits.split("").reverse();
  for (let i = 0; i < rev.length; i++) {
    const d = rev[i].charCodeAt(0) - 48;
    if (d < 0 || d > 9) {
      throw new Error(`not a digit: ${JSON.stringify(rev[i])}`);
    }
    c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][d]];
  }
  return VERHOEFF_INV[c];
}

/**
 * 11 桁 Manual Pairing Code(§5.1.4.1、VID/PID なし・カスタムフローなし)。
 *
 * - digit 1: `(VID_PID_present(0) << 2) | (discriminator >> 10)`
 * - digits 2-6: `((discriminator & 0x300) << 6) | (passcode & 0x3FFF)`
 * - digits 7-10: `passcode >> 14`
 * - digit 11: Verhoeff チェックディジット
 */
export function manualPairingCode(discriminator, passcode) {
  const d1 = (discriminator >> 10) & 0x03;
  const d2to6 = (((discriminator & 0x300) << 6) | (passcode & 0x3fff)) >>> 0;
  const d7to10 = passcode >>> 14;
  const body = `${d1}${String(d2to6).padStart(5, "0")}${String(d7to10).padStart(4, "0")}`;
  return `${body}${verhoeffCheckDigit(body)}`;
}

/** 見やすい区切り(`3497-011-2332`)。 */
export function formatManualPairingCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4, 7)}-${code.slice(7)}`;
}

// ---- QR payload -------------------------------------------------------------

/** Discovery Capabilities Bitmask(§5.1.3.1)。 */
export const DISCOVERY = {
  SOFT_AP: 1 << 0,
  BLE: 1 << 1,
  ON_NETWORK: 1 << 2,
  WIFI_PAF: 1 << 3,
};

/** Commissioning Flow(§5.1.3.1)。 */
export const COMMISSIONING_FLOW = {
  STANDARD: 0,
  USER_ACTION: 1,
  CUSTOM: 2,
};

/** LSB ファーストのビットライタ(Matter QR payload のパック順)。 */
class BitWriter {
  constructor() {
    this.bytes = [];
    this.bitPos = 0;
  }

  write(value, bits) {
    let v = BigInt(value);
    for (let i = 0; i < bits; i++) {
      const byteIdx = this.bitPos >> 3;
      const bitIdx = this.bitPos & 7;
      if (byteIdx >= this.bytes.length) {
        this.bytes.push(0);
      }
      if ((v >> BigInt(i)) & 1n) {
        this.bytes[byteIdx] |= 1 << bitIdx;
      }
      this.bitPos++;
    }
  }

  toBytes() {
    return Uint8Array.from(this.bytes);
  }
}

/**
 * onboarding payload の 88 ビット固定部(11 バイト)を組み立てる(§5.1.3.1)。
 *
 * ビット割り当て(LSB から順に詰める):
 * version 3 / VID 16 / PID 16 / commissioning flow 2 / discovery 8 /
 * discriminator 12 / passcode 27 / padding 4。
 */
export function onboardingPayloadBytes({
  version = 0,
  vendorId,
  productId,
  commissioningFlow = COMMISSIONING_FLOW.STANDARD,
  discovery = DISCOVERY.ON_NETWORK,
  discriminator,
  passcode,
}) {
  const w = new BitWriter();
  w.write(version, 3);
  w.write(vendorId, 16);
  w.write(productId, 16);
  w.write(commissioningFlow, 2);
  w.write(discovery, 8);
  w.write(discriminator & 0x0fff, 12);
  w.write(passcode & 0x7ffffff, 27);
  w.write(0, 4); // padding
  const out = w.toBytes();
  if (out.length !== 11) {
    throw new Error(`payload must be 11 bytes, got ${out.length}`);
  }
  return out;
}

/** Base38 の文字集合(§5.1.3.2)。 */
export const BASE38_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

/**
 * Base38 エンコード(§5.1.3.2)。
 *
 * 3 バイトずつ(リトルエンディアンの 24 ビット値)を 5 文字へ、余り 2 バイトは 4 文字、
 * 1 バイトは 2 文字へ変換する。
 */
export function base38Encode(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const remaining = bytes.length - i;
    let value = 0;
    let chars;
    if (remaining >= 3) {
      value = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16);
      chars = 5;
    } else if (remaining === 2) {
      value = bytes[i] | (bytes[i + 1] << 8);
      chars = 4;
    } else {
      value = bytes[i];
      chars = 2;
    }
    value = value >>> 0;
    for (let k = 0; k < chars; k++) {
      out += BASE38_CHARS[value % 38];
      value = Math.floor(value / 38);
    }
  }
  return out;
}

/** Base38 デコード(検算用)。 */
export function base38Decode(text) {
  const out = [];
  for (let i = 0; i < text.length; i += 5) {
    const chunk = text.slice(i, i + 5);
    let value = 0;
    for (let k = chunk.length - 1; k >= 0; k--) {
      const d = BASE38_CHARS.indexOf(chunk[k]);
      if (d < 0) {
        throw new Error(`invalid base38 character ${JSON.stringify(chunk[k])}`);
      }
      value = value * 38 + d;
    }
    const nBytes = chunk.length === 5 ? 3 : chunk.length === 4 ? 2 : chunk.length === 2 ? 1 : null;
    if (nBytes === null) {
      throw new Error(`invalid base38 chunk length ${chunk.length}`);
    }
    for (let k = 0; k < nBytes; k++) {
      out.push((value >>> (k * 8)) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

/** `MT:` 付きの QR コード文字列を組み立てる。 */
export function qrPayload(params) {
  return `MT:${base38Encode(onboardingPayloadBytes(params))}`;
}
