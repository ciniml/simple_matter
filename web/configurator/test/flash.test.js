// 書き込みオフセットが `generic_matter_cpp/partitions.csv` と一致していること
// (Web Serial の実操作はブラウザ限定なのでユーザ確認事項。ここは表の整合だけを見る)。

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { OFFSETS, SIZES, validateFlashPlan, bootloaderOffset } from "../js/flash.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const CSV = path.join(REPO, "ports/esp-idf/examples/generic_matter_cpp/partitions.csv");

/** partitions.csv → `{name: {offset, size}}`。 */
function parsePartitions() {
  const out = {};
  for (const line of fs.readFileSync(CSV, "utf8").split("\n")) {
    const s = line.trim();
    if (!s || s.startsWith("#")) {
      continue;
    }
    const cols = s.split(",").map((c) => c.trim());
    if (cols.length < 5 || !cols[3]) {
      continue;
    }
    out[cols[0]] = { offset: Number(cols[3]), size: Number(cols[4]) };
  }
  return out;
}

test("オフセット / サイズが partitions.csv と一致する", () => {
  const p = parsePartitions();
  assert.equal(OFFSETS.nvs, p.nvs.offset);
  assert.equal(SIZES.nvs, p.nvs.size);
  assert.equal(OFFSETS.app, p.factory.offset);
  assert.equal(SIZES.app, p.factory.size);
  assert.equal(OFFSETS.nvsFactory, p.nvs_factory.offset);
  assert.equal(SIZES.nvsFactory, p.nvs_factory.size);
  assert.equal(OFFSETS.smscript, p.smscript.offset);
  assert.equal(SIZES.smscript, p.smscript.size);
  assert.equal(OFFSETS.smscriptSlotB, p.smscript.offset + 0x20000);
  assert.equal(OFFSETS.partitionTable, 0x8000);
});

test("bootloader オフセットはチップごとの ESP-IDF 既定と一致する", () => {
  assert.equal(bootloaderOffset("ESP32-C6"), 0x0);
  assert.equal(bootloaderOffset("ESP32-H2"), 0x0);
  assert.equal(bootloaderOffset("ESP32-S3"), 0x0);
  assert.equal(bootloaderOffset("ESP32"), 0x1000);
  assert.equal(bootloaderOffset("ESP32-S2"), 0x1000);
  assert.equal(bootloaderOffset("ESP32-P4"), 0x2000);
});

test("パーティション溢れと領域の重なりを検出する", () => {
  assert.deepEqual(
    validateFlashPlan([
      { name: "nvs", address: OFFSETS.nvs, data: new Uint8Array(SIZES.nvs) },
      { name: "app", address: OFFSETS.app, data: new Uint8Array(1024) },
    ]),
    []
  );
  const tooBig = validateFlashPlan([
    { name: "factory NVS", address: OFFSETS.nvsFactory, data: new Uint8Array(SIZES.nvsFactory + 1) },
  ]);
  assert.equal(tooBig.length, 1);
  assert.match(tooBig[0], /nvs_factory/);

  const overlap = validateFlashPlan([
    { name: "app", address: OFFSETS.app, data: new Uint8Array(0x300000) },
    { name: "factory NVS", address: OFFSETS.nvsFactory, data: new Uint8Array(16) },
  ]);
  assert.ok(overlap.some((e) => /重なって/.test(e)));
});
