// Web Configurator が生成する factory NVS の **Rust 側検証用フィクスチャ**を作る。
//
//   node web/configurator/tools/gen-test-fixture.js
//     → crates/simple-matter/tests/fixtures/factory-webconfig.bin(24 KiB)
//
// 検証は `crates/simple-matter/src/factory/tests.rs` の `web_configurator_*` テスト群
// (`cargo test -p simple-matter --features factory-data,rustcrypto`)。
// 入力は**すべて固定値**なので出力はバイト単位で決定的。

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildFactoryNvs } from "../js/nvs.js";
import { computeVerifier } from "../js/spake2p.js";
import { DEV_DAC } from "../js/dev-dac.js";
import { hexToBytes } from "../js/util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(HERE, "../../../crates/simple-matter/tests/fixtures/factory-webconfig.bin");

/** フィクスチャの個体情報(Rust テストの期待値と一致させること)。 */
export const FIXTURE = {
  vendorId: 0xfff1,
  productId: 0x8001,
  discriminator: 0x0abc, // 2748
  passcode: 43708557,
  iterations: 10000,
  saltHex: "55a3cb8b1ed2b5b1c0fda2b9d9a3d0e2f1c4b7a68d5e3f201122334455667788",
  vendorName: "SimpleMatter",
  productName: "GenericDevice",
  hardwareVersion: 1,
  hardwareVersionStr: "HW1",
  serialNumber: "SM-WEBCFG-0001",
};

const salt = hexToBytes(FIXTURE.saltHex);
const v = await computeVerifier(FIXTURE.passcode, salt, FIXTURE.iterations);
const img = buildFactoryNvs({
  vendorId: FIXTURE.vendorId,
  productId: FIXTURE.productId,
  discriminator: FIXTURE.discriminator,
  iterations: FIXTURE.iterations,
  salt,
  verifier: v.w0l,
  vendorName: FIXTURE.vendorName,
  productName: FIXTURE.productName,
  hardwareVersion: FIXTURE.hardwareVersion,
  hardwareVersionStr: FIXTURE.hardwareVersionStr,
  serialNumber: FIXTURE.serialNumber,
  dac: DEV_DAC,
});

fs.writeFileSync(OUT, img);
console.log(`${OUT}: ${img.length} B (discriminator=${FIXTURE.discriminator}, passcode=${FIXTURE.passcode})`);
