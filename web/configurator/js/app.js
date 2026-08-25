// Web Configurator の UI 配線。ロジックは各モジュールに置き、ここは DOM とイベントだけ。

import qrcode from "../vendor/qrcode-generator/qrcode.mjs";

import {
  CLUSTERS,
  CLUSTER_BY_ID,
  DEVICE_TYPES,
  DEVICE_TYPE_BY_ID,
  DRIVER_FORMS,
  DRIVER_FORM_BY_NAME,
  PRESETS,
  validateComposition,
} from "./catalog.js";
import { encodeComposition, encodeBindings } from "./tlv.js";
import { buildFactoryNvs, buildSmgenNvs } from "./nvs.js";
import { computeVerifier } from "./spake2p.js";
import { DEV_DAC, DEV_DAC_PID, DEV_DAC_VID } from "./dev-dac.js";
import { packScript, looksLikeWasm } from "./smscript.js";
import {
  manualPairingCode,
  formatManualPairingCode,
  qrPayload,
  randomBytes,
  randomDiscriminator,
  randomPasscode,
  passcodeIsValid,
} from "./onboarding.js";
import { bytesToHex, hexToBytes } from "./util.js";
import {
  OFFSETS,
  bootloaderOffset,
  connect as serialConnect,
  fetchBinary,
  validateFlashPlan,
  webSerialAvailable,
  writeAll,
} from "./flash.js";

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") {
      node.className = v;
    } else if (k.startsWith("on")) {
      node.addEventListener(k.slice(2), v);
    } else if (v !== null && v !== undefined && v !== false) {
      node.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) {
      continue;
    }
    node.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
};
const hex4 = (n) => `0x${n.toString(16).toUpperCase().padStart(4, "0")}`;

// ---- 状態 -------------------------------------------------------------------

const state = {
  endpoints: [],
  bindings: [],
  verifier: null, // { w0l, salt, iterations, passcode, discriminator }
  factoryNvs: null,
  smgenNvs: null,
  scriptImage: null,
  scriptSlot: "a",
  firmware: { bootloader: null, partitionTable: null, app: null },
  chipName: "",
  loader: null,
};

function log(msg) {
  const pre = $("log");
  pre.textContent += `${msg}\n`;
  pre.scrollTop = pre.scrollHeight;
}

// ---- ① 構成 -----------------------------------------------------------------

function applyPreset(key) {
  const preset = PRESETS.find((p) => p.key === key) ?? PRESETS[0];
  state.endpoints = preset.comp.map((e) => ({
    id: e.ep,
    deviceType: e.device_type,
    rev: e.rev,
    clusters: new Set(e.clusters),
  }));
  state.bindings = preset.bind.map((b) => ({
    ep: b.ep,
    cluster: b.cluster,
    drv: b.drv,
    params: { ...b.params },
  }));
  renderComposition();
}

function compositionSpec() {
  return state.endpoints.map((e) => ({
    ep: e.id,
    device_type: e.deviceType,
    rev: e.rev,
    clusters: [...e.clusters].sort((a, b) => a - b),
  }));
}

function bindingSpec() {
  return state.bindings.map((b) => ({
    ep: b.ep,
    cluster: b.cluster,
    drv: b.drv,
    params: { ...b.params },
  }));
}

function renderEndpoint(ep, index) {
  const dtSelect = el(
    "select",
    {
      onchange: (ev) => {
        const dt = DEVICE_TYPE_BY_ID.get(Number(ev.target.value));
        ep.deviceType = dt.id;
        ep.rev = dt.rev;
        ep.clusters = new Set(dt.clusters);
        renderComposition();
      },
    },
    DEVICE_TYPES.map((d) =>
      el("option", { value: d.id, selected: d.id === ep.deviceType }, `${d.name} (${hex4(d.id)})`)
    )
  );

  const clusterList = el(
    "div",
    { class: "cluster-list" },
    CLUSTERS.map((c) =>
      el(
        "label",
        { title: `最大 ${c.max} 個 / ${c.group}` },
        el("input", {
          type: "checkbox",
          checked: ep.clusters.has(c.id),
          onchange: (ev) => {
            if (ev.target.checked) {
              ep.clusters.add(c.id);
            } else {
              ep.clusters.delete(c.id);
            }
            renderComposition();
          },
        }),
        `${c.name} (${hex4(c.id)})`
      )
    )
  );

  return el(
    "div",
    { class: "card" },
    el(
      "header",
      {},
      el(
        "label",
        {},
        "EP ID",
        el("input", {
          type: "number",
          min: 1,
          max: 8,
          value: ep.id,
          onchange: (ev) => {
            ep.id = Number(ev.target.value);
            renderComposition();
          },
        })
      ),
      el("label", {}, "デバイスタイプ", dtSelect),
      el(
        "label",
        {},
        "rev",
        el("input", {
          type: "number",
          min: 1,
          max: 255,
          value: ep.rev,
          onchange: (ev) => {
            ep.rev = Number(ev.target.value);
            renderComposition();
          },
        })
      ),
      el(
        "button",
        {
          class: "secondary",
          onclick: () => {
            state.endpoints.splice(index, 1);
            renderComposition();
          },
        },
        "削除"
      )
    ),
    clusterList
  );
}

function renderBinding(b, index) {
  const form = DRIVER_FORM_BY_NAME.get(b.drv);
  const clusterOptions = [...state.endpoints.flatMap((e) => [...e.clusters])];
  const uniqueClusters = [...new Set(clusterOptions)].sort((a, b2) => a - b2);

  const paramInputs = form.params.map((p) => {
    const current = b.params[p.name] ?? p.default;
    if (p.type === "bool") {
      return el(
        "label",
        {},
        p.label,
        el("input", {
          type: "checkbox",
          checked: Boolean(current),
          onchange: (ev) => {
            b.params[p.name] = ev.target.checked;
            renderComposition();
          },
        })
      );
    }
    if (p.type === "enum") {
      return el(
        "label",
        {},
        p.label,
        el(
          "select",
          {
            onchange: (ev) => {
              b.params[p.name] = Number(ev.target.value);
              renderComposition();
            },
          },
          p.options.map((o) =>
            el("option", { value: o.value, selected: Number(current) === o.value }, o.label)
          )
        )
      );
    }
    return el(
      "label",
      {},
      p.label,
      el("input", {
        type: "number",
        min: p.min,
        max: p.max,
        value: current,
        onchange: (ev) => {
          b.params[p.name] = Number(ev.target.value);
          renderComposition();
        },
      })
    );
  });

  return el(
    "div",
    { class: "card" },
    el(
      "header",
      {},
      el(
        "label",
        {},
        "EP",
        el("input", {
          type: "number",
          min: 1,
          max: 8,
          value: b.ep,
          onchange: (ev) => {
            b.ep = Number(ev.target.value);
            renderComposition();
          },
        })
      ),
      el(
        "label",
        {},
        "クラスタ",
        el(
          "select",
          {
            onchange: (ev) => {
              b.cluster = Number(ev.target.value);
              renderComposition();
            },
          },
          uniqueClusters.map((id) =>
            el(
              "option",
              { value: id, selected: id === b.cluster },
              `${CLUSTER_BY_ID.get(id)?.name ?? "?"} (${hex4(id)})`
            )
          )
        )
      ),
      el(
        "label",
        {},
        "ドライバ",
        el(
          "select",
          {
            onchange: (ev) => {
              b.drv = ev.target.value;
              const f = DRIVER_FORM_BY_NAME.get(b.drv);
              b.params = Object.fromEntries(f.params.map((p) => [p.name, p.default]));
              renderComposition();
            },
          },
          DRIVER_FORMS.map((d) =>
            el("option", { value: d.name, selected: d.name === b.drv }, `${d.name} — ${d.label}`)
          )
        )
      ),
      el(
        "button",
        {
          class: "secondary",
          onclick: () => {
            state.bindings.splice(index, 1);
            renderComposition();
          },
        },
        "削除"
      )
    ),
    el("div", { class: "grid" }, paramInputs)
  );
}

function renderComposition() {
  const epRoot = $("endpoints");
  epRoot.replaceChildren(...state.endpoints.map(renderEndpoint));
  const bindRoot = $("bindings");
  bindRoot.replaceChildren(...state.bindings.map(renderBinding));

  const spec = compositionSpec();
  const errors = validateComposition(spec);
  for (const b of state.bindings) {
    const ep = state.endpoints.find((e) => e.id === b.ep);
    if (!ep) {
      errors.push(`バインディング: EP${b.ep} が構成にありません。`);
    } else if (!ep.clusters.has(b.cluster)) {
      errors.push(
        `バインディング: EP${b.ep} に ${CLUSTER_BY_ID.get(b.cluster)?.name ?? hex4(b.cluster)} がありません。`
      );
    }
  }
  if (state.bindings.length > 16) {
    errors.push("バインディングは最大 16 個です(§9.2)。");
  }
  $("comp-errors").textContent = errors.join("\n");

  try {
    const comp = encodeComposition(spec);
    const bind = encodeBindings(bindingSpec());
    $("comp-hex").textContent = `${bytesToHex(comp)}  (${comp.length} B)`;
    $("bind-hex").textContent = `${bytesToHex(bind)}  (${bind.length} B)`;
    state.smgenNvs = errors.length === 0 ? buildSmgenNvs({ comp, bind }) : null;
  } catch (e) {
    $("comp-hex").textContent = `エラー: ${e.message}`;
    $("bind-hex").textContent = "";
    state.smgenNvs = null;
  }
  renderPlan();
}

// ---- ② 個体情報 --------------------------------------------------------------

function regenerateIdentity() {
  $("discriminator").value = String(randomDiscriminator());
  $("passcode").value = String(randomPasscode());
  $("salt").value = bytesToHex(randomBytes(32));
  renderOnboarding();
}

function deviceInputs() {
  const parseNum = (v) => (/^0[xX]/.test(v.trim()) ? parseInt(v, 16) : parseInt(v, 10));
  return {
    vendorId: parseNum($("vid").value),
    productId: parseNum($("pid").value),
    vendorName: $("vendor-name").value.trim(),
    productName: $("product-name").value.trim(),
    hardwareVersion: Number($("hw-ver").value),
    hardwareVersionStr: $("hw-ver-str").value.trim(),
    serialNumber: $("serial").value.trim(),
    iterations: Number($("iterations").value),
    discriminator: Number($("discriminator").value) & 0x0fff,
    passcode: Number($("passcode").value),
    discovery: Number($("discovery").value),
    dacSource: $("dac-source").value,
  };
}

async function readFileBytes(input) {
  const f = input.files?.[0];
  if (!f) {
    return null;
  }
  return new Uint8Array(await f.arrayBuffer());
}

async function buildDevice() {
  const errors = [];
  const d = deviceInputs();
  $("device-errors").textContent = "";
  if (!passcodeIsValid(d.passcode)) {
    errors.push(`setup passcode ${d.passcode} は無効です(1..99999998、ゾロ目 / 12345678 は禁止)。`);
  }
  if (d.iterations < 1000 || d.iterations > 100000) {
    errors.push("PBKDF2 iterations は 1000..100000 の範囲にしてください。");
  }
  let salt;
  try {
    salt = hexToBytes($("salt").value);
  } catch (e) {
    errors.push(`salt: ${e.message}`);
  }
  if (salt && (salt.length < 16 || salt.length > 32)) {
    errors.push(`salt は 16..32 バイトです(現在 ${salt.length})。`);
  }

  let dac = null;
  if (d.dacSource === "dev") {
    dac = DEV_DAC;
    if (d.vendorId !== DEV_DAC_VID || d.productId !== DEV_DAC_PID) {
      errors.push(
        `同梱テスト DAC は VID=${hex4(DEV_DAC_VID)} / PID=${hex4(DEV_DAC_PID)} 固定です` +
          "(他の VID/PID にすると attestation が通りません)。"
      );
    }
  } else if (d.dacSource === "upload") {
    const [dacDer, paiDer, key] = await Promise.all([
      readFileBytes($("dac-der")),
      readFileBytes($("pai-der")),
      readFileBytes($("dac-key")),
    ]);
    if (!dacDer || !paiDer || !key) {
      errors.push("DAC / PAI / 秘密鍵の 3 ファイルすべてを指定してください。");
    } else if (key.length !== 32) {
      errors.push(`dac_key.bin は生の P-256 秘密鍵 32 バイトです(現在 ${key.length})。`);
    } else {
      dac = { dac: dacDer, pai: paiDer, key };
    }
  }

  if (errors.length > 0) {
    $("device-errors").textContent = errors.join("\n");
    return;
  }

  const v = await computeVerifier(d.passcode, salt, d.iterations);
  state.verifier = { ...v, salt, iterations: d.iterations, ...d };
  $("verifier-hex").textContent = `${bytesToHex(v.w0l)}  (97 B)`;
  state.factoryNvs = buildFactoryNvs({
    vendorId: d.vendorId,
    productId: d.productId,
    discriminator: d.discriminator,
    iterations: d.iterations,
    salt,
    verifier: v.w0l,
    vendorName: d.vendorName || undefined,
    productName: d.productName || undefined,
    hardwareVersion: Number.isFinite(d.hardwareVersion) ? d.hardwareVersion : undefined,
    hardwareVersionStr: d.hardwareVersionStr || undefined,
    serialNumber: d.serialNumber || undefined,
    dac,
  });
  if (!dac) {
    $("device-errors").textContent =
      "注意: DAC を入れていないため、generic_matter_cpp の factory ローダは factory データ全体を" +
      "捨てて dev 資格情報(discriminator 3840 / passcode 20202021)にフォールバックします。";
  }
  log(`factory NVS を生成: ${state.factoryNvs.length} B(discriminator=${d.discriminator})`);
  renderOnboarding();
  renderPlan();
}

// ---- ③ QR / MPC --------------------------------------------------------------

function renderOnboarding() {
  const d = deviceInputs();
  if (!passcodeIsValid(d.passcode) || !Number.isFinite(d.discriminator)) {
    $("qr").replaceChildren();
    $("qr-text").textContent = "(passcode / discriminator が未確定)";
    $("manual-code").textContent = "";
    return;
  }
  const payload = qrPayload({
    vendorId: d.vendorId,
    productId: d.productId,
    discriminator: d.discriminator,
    passcode: d.passcode,
    discovery: d.discovery,
  });
  $("qr-text").textContent = payload;
  $("manual-code").textContent = formatManualPairingCode(
    manualPairingCode(d.discriminator, d.passcode)
  );
  $("show-disc").textContent = `${d.discriminator} (0x${d.discriminator.toString(16)})`;
  $("show-pass").textContent = String(d.passcode);

  const qr = qrcode(0, "M");
  qr.addData(payload);
  qr.make();
  $("qr").innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}

// ---- ④ スクリプト ------------------------------------------------------------

async function onWasmSelected() {
  const bytes = await readFileBytes($("wasm-file"));
  if (!bytes) {
    state.scriptImage = null;
    $("script-status").textContent = "";
    renderPlan();
    return;
  }
  if (!looksLikeWasm(bytes)) {
    $("script-status").textContent = "警告: WASM マジック(\\0asm)で始まっていません。";
  }
  try {
    state.scriptImage = packScript(bytes, Number($("wasm-ver").value) || 1);
    state.scriptSlot = $("wasm-slot").value;
    $("script-status").textContent =
      `SMWS イメージ: 本体 ${bytes.length} B / 合計 ${state.scriptImage.length} B ` +
      `(slot ${state.scriptSlot.toUpperCase()})`;
  } catch (e) {
    state.scriptImage = null;
    $("script-status").textContent = `エラー: ${e.message}`;
  }
  renderPlan();
}

// ---- ⑤ 書き込み --------------------------------------------------------------

function flashPlan() {
  const files = [];
  const bl = state.firmware.bootloader;
  if (bl) {
    files.push({ name: "bootloader", address: bootloaderOffset(state.chipName), data: bl });
  }
  if (state.firmware.partitionTable) {
    files.push({
      name: "partition-table",
      address: OFFSETS.partitionTable,
      data: state.firmware.partitionTable,
    });
  }
  if (state.firmware.app) {
    files.push({ name: "app", address: OFFSETS.app, data: state.firmware.app });
  }
  if ($("write-nvs").checked && state.smgenNvs) {
    files.push({ name: "設定 NVS (smgen)", address: OFFSETS.nvs, data: state.smgenNvs });
  }
  if ($("write-factory").checked && state.factoryNvs) {
    files.push({ name: "factory NVS", address: OFFSETS.nvsFactory, data: state.factoryNvs });
  }
  if (state.scriptImage) {
    files.push({
      name: "smscript",
      address: state.scriptSlot === "b" ? OFFSETS.smscriptSlotB : OFFSETS.smscript,
      data: state.scriptImage,
    });
  }
  return files.sort((a, b) => a.address - b.address);
}

function renderPlan() {
  const files = flashPlan();
  const tbody = $("plan").querySelector("tbody");
  tbody.replaceChildren(
    ...files.map((f) =>
      el(
        "tr",
        {},
        el("td", {}, `0x${f.address.toString(16).padStart(6, "0")}`),
        el("td", {}, f.name),
        el("td", {}, `${f.data.length.toLocaleString()} B`)
      )
    )
  );
  const errors = validateFlashPlan(files);
  $("flash").disabled = !state.loader || files.length === 0 || errors.length > 0;
  if (errors.length > 0) {
    log(errors.join("\n"));
  }
}

function download(name, bytes) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = el("a", { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---- 初期化 -----------------------------------------------------------------

function wire() {
  $("preset").replaceChildren(
    ...PRESETS.map((p) => el("option", { value: p.key }, p.label))
  );
  $("preset-apply").addEventListener("click", () => applyPreset($("preset").value));
  $("ep-add").addEventListener("click", () => {
    const used = new Set(state.endpoints.map((e) => e.id));
    let id = 1;
    while (used.has(id) && id < 8) {
      id++;
    }
    const dt = DEVICE_TYPES[0];
    state.endpoints.push({ id, deviceType: dt.id, rev: dt.rev, clusters: new Set(dt.clusters) });
    renderComposition();
  });
  $("bind-add").addEventListener("click", () => {
    const ep = state.endpoints[0];
    const form = DRIVER_FORMS[0];
    state.bindings.push({
      ep: ep?.id ?? 1,
      cluster: ep ? [...ep.clusters][0] : 0x0006,
      drv: form.name,
      params: Object.fromEntries(form.params.map((p) => [p.name, p.default])),
    });
    renderComposition();
  });

  $("regen").addEventListener("click", regenerateIdentity);
  $("build-device").addEventListener("click", () => {
    buildDevice().catch((e) => {
      $("device-errors").textContent = String(e.message ?? e);
    });
  });
  $("dac-source").addEventListener("change", () => {
    $("dac-upload").classList.toggle("hidden", $("dac-source").value !== "upload");
  });
  for (const id of ["discriminator", "passcode", "vid", "pid", "discovery"]) {
    $(id).addEventListener("input", renderOnboarding);
  }
  $("print").addEventListener("click", () => window.print());

  $("wasm-file").addEventListener("change", onWasmSelected);
  $("wasm-ver").addEventListener("change", onWasmSelected);
  $("wasm-slot").addEventListener("change", onWasmSelected);
  $("as-download").addEventListener("click", () => {
    download("script.ts", new TextEncoder().encode($("as-source").value));
  });

  const fwInputs = [
    ["fw-bootloader", "bootloader"],
    ["fw-parttable", "partitionTable"],
    ["fw-app", "app"],
  ];
  for (const [id, key] of fwInputs) {
    $(id).addEventListener("change", async () => {
      state.firmware[key] = await readFileBytes($(id));
      renderPlan();
    });
  }
  $("fw-fetch").addEventListener("click", async () => {
    const url = $("fw-url").value.trim();
    if (!url) {
      return;
    }
    try {
      log(`取得中: ${url}`);
      state.firmware.app = await fetchBinary(url);
      log(`取得しました(${state.firmware.app.length} B)。`);
      renderPlan();
    } catch (e) {
      log(`取得に失敗: ${e.message}(CORS の可能性。ダウンロードしてローカル指定に切り替えてください)`);
    }
  });
  for (const id of ["write-nvs", "write-factory"]) {
    $(id).addEventListener("change", renderPlan);
  }

  $("connect").addEventListener("click", async () => {
    try {
      const { ESPLoader, Transport } = await import("../vendor/esptool-js/esptool-js.bundle.js");
      const terminal = {
        clean: () => {},
        writeLine: (d) => log(d),
        write: (d) => log(d.replace(/\r?\n$/, "")),
      };
      const res = await serialConnect(
        { ESPLoader, Transport },
        { baudrate: Number($("baud").value), terminal }
      );
      state.loader = res.loader;
      state.chipName = res.chipName;
      log(`接続しました: ${res.chipDescription}`);
      log(`bootloader オフセット = 0x${bootloaderOffset(res.chipName).toString(16)}`);
      renderPlan();
    } catch (e) {
      log(`接続に失敗: ${e.message ?? e}`);
    }
  });

  $("flash").addEventListener("click", async () => {
    const files = flashPlan();
    $("progress").classList.remove("hidden");
    try {
      await writeAll(state.loader, files, {
        eraseAll: $("erase-all").checked,
        reportProgress: (i, written, total) => {
          $("progress").value = Math.round((written / total) * 100);
          if (written === total) {
            log(`書き込み完了: ${files[i].name}`);
          }
        },
      });
      log("すべて書き込みました。デバイスをリセットしてください。");
    } catch (e) {
      log(`書き込みに失敗: ${e.message ?? e}`);
    } finally {
      $("progress").classList.add("hidden");
    }
  });

  $("download-all").addEventListener("click", () => {
    if (state.smgenNvs) {
      download("nvs-smgen.bin", state.smgenNvs);
    }
    if (state.factoryNvs) {
      download("factory-nvs.bin", state.factoryNvs);
    }
    if (state.scriptImage) {
      download(`smscript-slot${state.scriptSlot.toUpperCase()}.bin`, state.scriptImage);
    }
  });

  if (!webSerialAvailable()) {
    const w = $("env-warning");
    w.classList.remove("hidden");
    w.textContent =
      "このブラウザには Web Serial API がありません。構成 / 個体情報 / QR の生成とダウンロードは" +
      "できますが、書き込みには Chrome / Edge 系(かつ HTTPS または http://localhost)が必要です。";
  }

  $("as-source").value = `// AssemblyScript のひな形(型宣言は web/sdk/sm.d.ts)。
// ローカルでのコンパイル例:
//   npx asc script.ts --outFile script.wasm --optimize --runtime stub \\
//     --use abort= --exportRuntime false

@external("sm", "attr_get")
declare function attr_get(ep: i32, cluster: i32, attr: i32, out: usize, cap: i32): i32;
@external("sm", "attr_set")
declare function attr_set(ep: i32, cluster: i32, attr: i32, val: usize, len: i32): i32;
@external("sm", "log")
declare function sm_log(ptr: usize, len: i32): void;

export function on_boot(): void {
  // 起動時に 1 回呼ばれる。
}

export function on_sensor(bind: i32): void {
  // 入力 binding の更新 / script binding の周期発火。
}
`;

  applyPreset(PRESETS[0].key);
  regenerateIdentity();
}

wire();
