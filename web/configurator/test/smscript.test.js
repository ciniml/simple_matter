// SMWS(smscript パーティション)イメージの検証。
// 正実装は `scripts/smscript-img.py`(pack / show)。

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { packScript, unpackScript, looksLikeWasm, HDR_SIZE, MAX_LEN } from "../js/smscript.js";
import { crc32, bytesToHex } from "../js/util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const SMSCRIPT = path.join(REPO, "scripts/smscript-img.py");

/** テスト用の最小 .wasm 相当(スクリプト本体としての中身は問わない)。 */
function sampleBody(n = 64) {
  const body = new Uint8Array(8 + n);
  body.set([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00], 0);
  for (let i = 0; i < n; i++) {
    body[8 + i] = i & 0xff;
  }
  return body;
}

test("crc32 が既知ベクタと一致する(binascii.crc32 と同一)", () => {
  assert.equal(crc32(new TextEncoder().encode("123456789"), 0), 0xcbf43926);
});

test("pack → unpack がラウンドトリップする", () => {
  const body = sampleBody();
  const img = packScript(body, 7);
  assert.equal(img.length, HDR_SIZE + body.length);
  assert.equal(bytesToHex(img.subarray(0, 4)), "534d5753"); // "SMWS"
  const out = unpackScript(img);
  assert.equal(out.ver, 7);
  assert.equal(out.flags, 0);
  assert.equal(out.len, body.length);
  assert.equal(out.crc, crc32(body, 0));
  assert.deepEqual(out.body, body);
});

test("本体を壊すと CRC 不一致で弾かれる", () => {
  const img = packScript(sampleBody());
  img[HDR_SIZE] ^= 0xff;
  assert.throws(() => unpackScript(img), /CRC mismatch/);
});

test("マジックが違うイメージは弾かれる", () => {
  const img = packScript(sampleBody());
  img[0] = 0x00;
  assert.throws(() => unpackScript(img), /bad magic/);
});

test("空 / 巨大な本体は弾かれる", () => {
  assert.throws(() => packScript(new Uint8Array(0)), /1\.\./);
  assert.throws(() => packScript(new Uint8Array(MAX_LEN + 1)), /1\.\./);
});

test("looksLikeWasm が WASM マジックを判定する", () => {
  assert.equal(looksLikeWasm(sampleBody()), true);
  assert.equal(looksLikeWasm(new Uint8Array([1, 2, 3, 4])), false);
});

test("scripts/smscript-img.py show が JS 生成イメージを受理する(python3 が無ければ skip)", (t) => {
  const body = sampleBody(200);
  const img = packScript(body, 3);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smws-"));
  const file = path.join(dir, "slotA.bin");
  fs.writeFileSync(file, img);
  let out;
  try {
    out = execFileSync("python3", [SMSCRIPT, "show", file], { encoding: "utf8" });
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true });
    t.skip(`python3 / smscript-img.py を実行できない: ${e.message}`);
    return;
  }
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(out, /slot A: ver=3 flags=0 len=208 crc32=[0-9a-f]{8} OK/);
});

test("scripts/smscript-img.py pack と同一バイト列になる(python3 が無ければ skip)", (t) => {
  const body = sampleBody(333);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smws-"));
  const wasm = path.join(dir, "x.wasm");
  const out = path.join(dir, "x.img");
  fs.writeFileSync(wasm, body);
  try {
    execFileSync("python3", [SMSCRIPT, "pack", wasm, "-o", out, "--ver", "5"], { stdio: "ignore" });
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true });
    t.skip(`python3 / smscript-img.py を実行できない: ${e.message}`);
    return;
  }
  const want = new Uint8Array(fs.readFileSync(out));
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(bytesToHex(packScript(body, 5)), bytesToHex(want));
});
