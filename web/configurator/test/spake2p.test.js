// SPAKE2+ verifier の検証: JS 実装が `smctl pase-verifier`(= コアの
// `crypto::spake2p::compute_verifier`)と一致すること。
//
// ベクタは以下で生成した(再生成手順を README にも記載):
//   cargo run -q -p smctl -- pase-verifier <passcode> --salt <hex> --iterations <n>

import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { computeVerifier } from "../js/spake2p.js";
import { bytesToHex, hexToBytes } from "../js/util.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");

/** `smctl pase-verifier` 出力(`w0_l` 行 = w0(32B) ‖ L(65B) の hex)。 */
const VECTORS = [
  {
    // Matter 仕様 §3.10 の公知ベクタ(salt = "SPAKE2P Key Salt")。
    passcode: 20202021,
    salt: "5350414b453250204b65792053616c74",
    iterations: 1000,
    w0l:
      "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb35" +
      "0457f8ab79ee253ab6a8e46bb09e543ae422736de501e3db37d441fe344920d095" +
      "48e4c18240630c4ff4913c53513839b7c07fcc0627a1b8573a149fcd1fa466cf",
  },
  {
    passcode: 123456,
    salt: "04a1d2c611f0bd367867797bfe823600",
    iterations: 2000,
    w0l:
      "a4f0660683915b82e0a753758d48840f33bde297321b4712632f8dd343fc165f" +
      "041bcbd5b3b504640d2bd252633487816e386f65b7917eff925146b4f780a2afe5" +
      "e3ae8fbed8a593b2a4b845e4016b73c0a80df490b3fe33daddae8456ae970d71",
  },
  {
    // salt 32 バイト / iteration-count 10000(mfg_tool の既定と同じ強度)。
    passcode: 20202021,
    salt: "55a3cb8b1ed2b5b1c0fda2b9d9a3d0e2f1c4b7a68d5e3f201122334455667788",
    iterations: 10000,
    w0l:
      "37f9f8798c814bfeb0e66330b8919a646e1cf85612d3821a6b13fa14ecc0bb15" +
      "046fc5f5b7e9d481bab9992df47da78b8e6df3e6b29d6782397b73e3f2ef7eafd8" +
      "706ac94bffbd56ad8f101582cd0053ca52463f5abe378afd20748b0fda0b84c3",
  },
  {
    passcode: 88888887,
    salt: "000102030405060708090a0b0c0d0e0f",
    iterations: 15000,
    w0l:
      "c52f48ec34df630326d33be06ee6d940aafcf29f03a241dea13e9a51f19f2162" +
      "049d389564d51aa13fb96298e5e360f85dac5f1cd8c726cdb132c24b63527c2e1f" +
      "af96064381b302e211fcf7750f31e2e49d6233f5f90214fafaf92f2211fefe14",
  },
];

test("JS の computeVerifier が smctl pase-verifier のベクタと一致する", async () => {
  for (const v of VECTORS) {
    const out = await computeVerifier(v.passcode, hexToBytes(v.salt), v.iterations);
    assert.equal(out.w0l.length, 97);
    assert.equal(out.w0.length, 32);
    assert.equal(out.l.length, 65);
    assert.equal(out.l[0], 0x04, "L は SEC1 非圧縮点");
    assert.equal(
      bytesToHex(out.w0l),
      v.w0l,
      `passcode=${v.passcode} salt=${v.salt} iters=${v.iterations}`
    );
  }
});

test("smctl pase-verifier を実際に呼んで一致する(cargo が無ければ skip)", async (t) => {
  const v = { passcode: 34567890, salt: "aabbccddeeff00112233445566778899", iterations: 3000 };
  let out;
  try {
    out = execFileSync(
      "cargo",
      [
        "run",
        "-q",
        "-p",
        "smctl",
        "--",
        "pase-verifier",
        String(v.passcode),
        "--salt",
        v.salt,
        "--iterations",
        String(v.iterations),
      ],
      { encoding: "utf8", cwd: REPO, stdio: ["ignore", "pipe", "ignore"] }
    );
  } catch (e) {
    t.skip(`cargo run -p smctl を実行できない: ${e.message}`);
    return;
  }
  const m = out.match(/^w0_l:\s+(\S+)$/m);
  assert.ok(m, `pase-verifier の出力を解釈できない:\n${out}`);
  const js = await computeVerifier(v.passcode, hexToBytes(v.salt), v.iterations);
  assert.equal(bytesToHex(js.w0l), m[1]);
});

test("不正な salt 長 / iterations は弾く", async () => {
  await assert.rejects(() => computeVerifier(20202021, hexToBytes("0011"), 1000), /16\.\.32/);
  await assert.rejects(
    () => computeVerifier(20202021, hexToBytes("5350414b453250204b65792053616c74"), 0),
    /positive integer/
  );
});
