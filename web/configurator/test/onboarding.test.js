// Onboarding payload の検証: QR(`MT:` Base38)と Manual Pairing Code が
// 公知テストベクタと一致すること。
//
// 基準ベクタ: chip-tool / esp-matter の既定デバイス
//   VID=0xFFF1 PID=0x8001 discriminator=3840 passcode=20202021 標準フロー
//   discovery = ON_NETWORK(0x04)
//   → QR `MT:-24J0AFN00KA0648G00` / MPC `34970112332`

import test from "node:test";
import assert from "node:assert/strict";

import {
  qrPayload,
  onboardingPayloadBytes,
  base38Encode,
  base38Decode,
  manualPairingCode,
  formatManualPairingCode,
  verhoeffCheckDigit,
  passcodeIsValid,
  randomPasscode,
  randomDiscriminator,
  DISCOVERY,
  COMMISSIONING_FLOW,
} from "../js/onboarding.js";
import { bytesToHex } from "../js/util.js";

const DEFAULT = {
  vendorId: 0xfff1,
  productId: 0x8001,
  discriminator: 3840,
  passcode: 20202021,
  commissioningFlow: COMMISSIONING_FLOW.STANDARD,
};

test("QR payload が公知ベクタ MT:-24J0AFN00KA0648G00 と一致する", () => {
  assert.equal(qrPayload({ ...DEFAULT, discovery: DISCOVERY.ON_NETWORK }), "MT:-24J0AFN00KA0648G00");
});

test("QR payload の固定部は 11 バイト、Base38 で 19 文字になる", () => {
  const bytes = onboardingPayloadBytes({ ...DEFAULT, discovery: DISCOVERY.ON_NETWORK });
  assert.equal(bytes.length, 11);
  assert.equal(base38Encode(bytes).length, 19);
  // ビット割り当ての実バイト列(version=0 / VID / PID / flow / discovery / disc / passcode / pad)。
  assert.equal(bytesToHex(bytes), "88ff0f008400e04b846802");
});

test("discovery capability を変えると payload も変わる(BLE / SoftAP)", () => {
  assert.equal(qrPayload({ ...DEFAULT, discovery: DISCOVERY.BLE }), "MT:-24J042C00KA0648G00");
  assert.equal(qrPayload({ ...DEFAULT, discovery: DISCOVERY.SOFT_AP }), "MT:-24J0KE600KA0648G00");
  assert.equal(
    qrPayload({ ...DEFAULT, discovery: DISCOVERY.BLE | DISCOVERY.ON_NETWORK }),
    qrPayload({ ...DEFAULT, discovery: 0x06 })
  );
});

test("Base38 はラウンドトリップする(3 / 2 / 1 バイト余りの各ケース)", () => {
  for (const len of [1, 2, 3, 4, 5, 6, 11, 17]) {
    const src = Uint8Array.from({ length: len }, (_, i) => (i * 37 + 11) & 0xff);
    const enc = base38Encode(src);
    assert.deepEqual(base38Decode(enc), src, `len=${len}`);
  }
});

test("Manual Pairing Code が公知ベクタ 34970112332 と一致する", () => {
  assert.equal(manualPairingCode(3840, 20202021), "34970112332");
  assert.equal(formatManualPairingCode("34970112332"), "3497-011-2332");
});

test("Verhoeff チェックディジット(既知ベクタ)", () => {
  // 3497011233 の検査数字は 2(上の MPC の末尾)。
  assert.equal(verhoeffCheckDigit("3497011233"), 2);
  // Verhoeff の代表例。
  assert.equal(verhoeffCheckDigit("236"), 3);
  assert.equal(verhoeffCheckDigit("12345"), 1);
});

test("Manual Pairing Code は 11 桁で、末尾は本体から再計算できる", () => {
  for (const [disc, pass] of [
    [0, 1],
    [4095, 99999998],
    [1234, 56781234],
    [3840, 20202021],
  ]) {
    const code = manualPairingCode(disc, pass);
    assert.equal(code.length, 11, `disc=${disc} pass=${pass}`);
    assert.equal(Number(code[10]), verhoeffCheckDigit(code.slice(0, 10)));
  }
});

test("passcode の有効範囲と禁止値", () => {
  assert.equal(passcodeIsValid(0), false);
  assert.equal(passcodeIsValid(99999999), false);
  assert.equal(passcodeIsValid(12345678), false);
  assert.equal(passcodeIsValid(87654321), false);
  assert.equal(passcodeIsValid(11111111), false);
  assert.equal(passcodeIsValid(1), true);
  assert.equal(passcodeIsValid(99999998), true);
  assert.equal(passcodeIsValid(20202021), true);
});

test("乱数生成は常に有効な passcode / 12bit discriminator を返す", () => {
  for (let i = 0; i < 200; i++) {
    assert.equal(passcodeIsValid(randomPasscode()), true);
    const d = randomDiscriminator();
    assert.ok(d >= 0 && d <= 0x0fff);
  }
});
