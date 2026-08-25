// TLV エンコーダの検証: JS 実装が `scripts/smgen-tlv.py` と**同一の hex** を出すこと。
//
//   node --test web/configurator/test/

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { encodeComposition, encodeBindings } from "../js/tlv.js";
import { PRESETS } from "../js/catalog.js";
import { bytesToHex } from "../js/util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const SMGEN = path.join(REPO, "scripts/smgen-tlv.py");

/**
 * `scripts/smgen-tlv.py examples` の出力(正実装)。
 * 更新時は `python3 scripts/smgen-tlv.py examples` を再実行して貼り直す。
 */
const EXPECTED = {
  "onoff-light": {
    comp: "1715250001002601000100002402023603060300000006040000000606000000181818",
    bind: "17152500010026010600000024020135032400072801181818",
  },
  "dimmer-sensor": {
    comp:
      "1715250001002601010100002402033603060300000006040000000606000000060800000018181525000200" +
      "260102030000240202360306020400000605040000181818",
    bind:
      "17152500010026010800000024020335032400002401062602e8030000181815250002002601020400002402" +
      "04350324000824010925028813181818",
  },
};

test("プリセット ① / ② の comp / bind hex が smgen-tlv.py の examples と一致する", () => {
  for (const preset of PRESETS) {
    const want = EXPECTED[preset.key];
    assert.ok(want, `no expected hex for preset ${preset.key}`);
    assert.equal(bytesToHex(encodeComposition(preset.comp)), want.comp, `${preset.key}: comp`);
    assert.equal(bytesToHex(encodeBindings(preset.bind)), want.bind, `${preset.key}: bind`);
  }
});

test("smgen-tlv.py を実際に呼んで出力が一致する(python3 が無ければ skip)", (t) => {
  let out;
  try {
    out = execFileSync("python3", [SMGEN, "examples"], { encoding: "utf8" });
  } catch (e) {
    t.skip(`python3 / smgen-tlv.py を実行できない: ${e.message}`);
    return;
  }
  const comps = [...out.matchAll(/^cfg-comp (\S+)$/gm)].map((m) => m[1]);
  const binds = [...out.matchAll(/^cfg-bind (\S+)$/gm)].map((m) => m[1]);
  assert.equal(comps.length, PRESETS.length, "examples の個数がプリセット数と一致する");
  PRESETS.forEach((preset, i) => {
    assert.equal(bytesToHex(encodeComposition(preset.comp)), comps[i], `${preset.key}: comp`);
    assert.equal(bytesToHex(encodeBindings(preset.bind)), binds[i], `${preset.key}: bind`);
  });
});

test("smgen-tlv.py の decode-comp / decode-bind で往復できる", (t) => {
  const preset = PRESETS[1];
  const compHex = bytesToHex(encodeComposition(preset.comp));
  const bindHex = bytesToHex(encodeBindings(preset.bind));
  let comp;
  let bind;
  try {
    comp = JSON.parse(execFileSync("python3", [SMGEN, "decode-comp", compHex], { encoding: "utf8" }));
    bind = JSON.parse(execFileSync("python3", [SMGEN, "decode-bind", bindHex], { encoding: "utf8" }));
  } catch (e) {
    t.skip(`python3 / smgen-tlv.py を実行できない: ${e.message}`);
    return;
  }
  assert.deepEqual(
    comp.map((e) => [e.ep, e.device_type, e.rev, e.clusters]),
    preset.comp.map((e) => [e.ep, e.device_type, e.rev, e.clusters])
  );
  assert.deepEqual(
    bind.map((b) => [b.ep, b.cluster, b.drv]),
    preset.bind.map((b) => [b.ep, b.cluster, b.drv])
  );
  assert.equal(bind[0].params.ch, 0);
  assert.equal(bind[0].params.pin, 6);
  assert.equal(bind[0].params.freq, 1000);
  assert.equal(bind[1].params.poll_ms, 5000);
});

test("未知の param 名はエラーになる", () => {
  assert.throws(
    () => encodeBindings([{ ep: 1, cluster: 0x0006, drv: "gpio_out", params: { channel: 1 } }]),
    /has no param/
  );
});

test("options 付き composition が smgen-tlv.py と一致する(温度 2350 = 23.50℃ の初期値)", () => {
  const spec = [
    {
      ep: 2,
      device_type: 0x0302,
      rev: 2,
      clusters: [0x0402],
      options: [{ cluster: 0x0402, attr: 0, type: "i16", value: 2350 }],
    },
  ];
  // `python3 scripts/smgen-tlv.py comp <spec.json>` の出力。
  assert.equal(
    bytesToHex(encodeComposition(spec)),
    "171525000200260102030000240202360306020400001836041526000204000026010000000021022e0918181818"
  );
});
