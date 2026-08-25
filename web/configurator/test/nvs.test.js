// NVS パーティションジェネレータの検証。
//
// 最強の検算: `esp-matter-mfg-tool 1.0.24` が実際に生成した
// `crates/simple-matter/tests/fixtures/factory-fff1-8001.bin` を、同じ入力値から
// **バイト単位で完全再現**できること(ページヘッダ CRC・エントリ CRC・本体 CRC・
// エントリ状態ビットマップ・span まで含めて一致)。
//
// 生成物を Rust の factory パーサが読めることは
// `crates/simple-matter/src/factory/tests.rs::generated_by_web_configurator` が
// 別途 fixture 経由で検証する(`cargo test -p simple-matter --features factory-data`)。

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { NvsBuilder, NvsReader, buildFactoryNvs, buildSmgenNvs, FACTORY_NS, SMGEN_NS } from "../js/nvs.js";
import { encodeComposition, encodeBindings } from "../js/tlv.js";
import { PRESETS } from "../js/catalog.js";
import { computeVerifier } from "../js/spake2p.js";
import { base64ToBytes, bytesToHex, hexToBytes } from "../js/util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const FIXTURE = path.join(REPO, "crates/simple-matter/tests/fixtures/factory-fff1-8001.bin");

function fixture() {
  return new Uint8Array(fs.readFileSync(FIXTURE));
}

test("mfg_tool 実生成の factory パーティションをバイト単位で再現できる", () => {
  const want = fixture();
  const r = new NvsReader(want);
  const got = buildFactoryNvs({
    vendorId: r.getU32(FACTORY_NS, "vendor-id"),
    productId: r.getU32(FACTORY_NS, "product-id"),
    discriminator: r.getU32(FACTORY_NS, "discriminator"),
    iterations: r.getU32(FACTORY_NS, "iteration-count"),
    salt: base64ToBytes(r.getStr(FACTORY_NS, "salt")),
    verifier: base64ToBytes(r.getStr(FACTORY_NS, "verifier")),
    vendorName: r.getStr(FACTORY_NS, "vendor-name"),
    productName: r.getStr(FACTORY_NS, "product-name"),
    hardwareVersion: r.getU32(FACTORY_NS, "hardware-ver"),
    hardwareVersionStr: r.getStr(FACTORY_NS, "hw-ver-str"),
    serialNumber: r.getStr(FACTORY_NS, "serial-num"),
    dac: {
      dac: r.getBlob(FACTORY_NS, "dac-cert"),
      pai: r.getBlob(FACTORY_NS, "pai-cert"),
      key: r.getBlob(FACTORY_NS, "dac-key"),
      pub: r.getBlob(FACTORY_NS, "dac-pub-key"),
    },
    size: want.length,
  });
  assert.equal(got.length, want.length);
  const diff = got.findIndex((b, i) => b !== want[i]);
  assert.equal(
    diff,
    -1,
    diff < 0
      ? ""
      : `first difference at 0x${diff.toString(16)}: got ${bytesToHex(got.slice(diff, diff + 16))} ` +
        `want ${bytesToHex(want.slice(diff, diff + 16))}`
  );
});

test("fixture の値を自前リーダで読み戻せる(factory/tests.rs と同じ期待値)", () => {
  const r = new NvsReader(fixture());
  assert.equal(r.getU32(FACTORY_NS, "discriminator"), 3840);
  assert.equal(r.getU32(FACTORY_NS, "iteration-count"), 10000);
  assert.equal(r.getU32(FACTORY_NS, "vendor-id"), 0xfff1);
  assert.equal(r.getU32(FACTORY_NS, "product-id"), 0x8001);
  const salt = base64ToBytes(r.getStr(FACTORY_NS, "salt"));
  assert.equal(salt.length, 32);
  assert.equal(
    bytesToHex(salt),
    "bb67b05aa530234611b4e444716d386b20987873a64a5adf7f446b23c6fede80"
  );
  const verifier = base64ToBytes(r.getStr(FACTORY_NS, "verifier"));
  assert.equal(verifier.length, 97);
  assert.equal(verifier[32], 0x04, "L は SEC1 非圧縮点");
  assert.equal(r.getBlob(FACTORY_NS, "dac-cert").length, 518);
  assert.equal(r.getBlob(FACTORY_NS, "pai-cert").length, 466);
  assert.equal(r.getBlob(FACTORY_NS, "dac-key").length, 32);
});

test("fixture の verifier は passcode 20202021 からの導出値と一致する", async () => {
  const r = new NvsReader(fixture());
  const derived = await computeVerifier(
    20202021,
    base64ToBytes(r.getStr(FACTORY_NS, "salt")),
    r.getU32(FACTORY_NS, "iteration-count")
  );
  assert.equal(bytesToHex(derived.w0l), bytesToHex(base64ToBytes(r.getStr(FACTORY_NS, "verifier"))));
});

test("新規生成した factory NVS を読み戻すと入力値が復元できる", async () => {
  const salt = hexToBytes("55a3cb8b1ed2b5b1c0fda2b9d9a3d0e2f1c4b7a68d5e3f201122334455667788");
  const v = await computeVerifier(43708557, salt, 10000);
  const img = buildFactoryNvs({
    vendorId: 0xfff1,
    productId: 0x8001,
    discriminator: 0x0abc,
    iterations: 10000,
    salt,
    verifier: v.w0l,
    vendorName: "SimpleMatter",
    productName: "GenericDevice",
    hardwareVersion: 1,
    hardwareVersionStr: "HW1",
    serialNumber: "SM-GEN-0042",
  });
  assert.equal(img.length, 0x6000);
  const r = new NvsReader(img);
  assert.equal(r.getU32(FACTORY_NS, "discriminator"), 0x0abc);
  assert.equal(r.getU32(FACTORY_NS, "iteration-count"), 10000);
  assert.equal(r.getU32(FACTORY_NS, "vendor-id"), 0xfff1);
  assert.equal(r.getStr(FACTORY_NS, "serial-num"), "SM-GEN-0042");
  assert.equal(bytesToHex(base64ToBytes(r.getStr(FACTORY_NS, "salt"))), bytesToHex(salt));
  assert.equal(bytesToHex(base64ToBytes(r.getStr(FACTORY_NS, "verifier"))), bytesToHex(v.w0l));
  // DAC 無しなら blob は存在しない。
  assert.equal(r.getBlob(FACTORY_NS, "dac-cert"), null);
});

test("smgen パーティション(comp / bind blob)を生成して読み戻せる", () => {
  const preset = PRESETS[1];
  const comp = encodeComposition(preset.comp);
  const bind = encodeBindings(preset.bind);
  const img = buildSmgenNvs({ comp, bind });
  const r = new NvsReader(img);
  assert.equal(bytesToHex(r.getBlob(SMGEN_NS, "comp")), bytesToHex(comp));
  assert.equal(bytesToHex(r.getBlob(SMGEN_NS, "bind")), bytesToHex(bind));
});

test("キー長 / パーティションサイズ / ページ溢れを検査する", () => {
  assert.throws(() => new NvsBuilder(0x1000), /multiple of 4096/);
  assert.throws(() => new NvsBuilder(0x6001), /multiple of 4096/);
  const b = new NvsBuilder(0x6000);
  assert.throws(() => b.setU32("ns", "0123456789abcdef", 1), /1\.\.15 bytes/);
  const big = new NvsBuilder(0x6000);
  assert.throws(() => big.setBlob("ns", "huge", new Uint8Array(5000)), /too large/);
});

test("verifier が 97 バイトでなければ弾く", () => {
  assert.throws(
    () =>
      buildFactoryNvs({
        vendorId: 1,
        productId: 1,
        discriminator: 1,
        iterations: 1000,
        salt: new Uint8Array(16),
        verifier: new Uint8Array(96),
      }),
    /97 bytes/
  );
});
