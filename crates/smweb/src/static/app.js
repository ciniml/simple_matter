// smweb UI (W2): Dashboard / Devices / Log, live from the WebSocket.
// Plain ES2020, no build step, no external dependencies.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const hex = (n, w = 4) => "0x" + Number(n).toString(16).toUpperCase().padStart(w, "0");

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** node_id -> node (snapshot entry: model, values[], watch[], sub_paths[], ...) */
const nodes = new Map();
/** node_id -> Map("ep/cluster/attr" -> value entry) */
const values = new Map();
let clusters = [];
const clusterById = new Map();
let info = null;
let activeTab = "dashboard";
/** node_ids whose Devices panel is expanded */
const expanded = new Set();

const vkey = (ep, cluster, attr) => `${ep}/${cluster}/${attr}`;

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(e.dataset, v);
    else if (k in e && typeof v !== "string") e[k] = v;
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    return { ok: false, status: 0, data: { error: { code: "network", message: String(e) } } };
  }
  let data;
  try {
    data = await res.json();
  } catch (_) {
    data = { error: { code: "bad_response", message: `HTTP ${res.status}` } };
  }
  return { ok: res.ok, status: res.status, data };
}

const errText = (r) => (r.data && r.data.error ? `${r.data.error.code}: ${r.data.error.message}` : `HTTP ${r.status}`);

// ---------------------------------------------------------------------------
// Value formatting (hints from /api/clusters: unit / scale / enum)
// ---------------------------------------------------------------------------

function attrDef(cluster, attr) {
  const c = clusterById.get(cluster);
  return c ? c.attributes.find((a) => a.id === attr) : undefined;
}

function numStr(v, digits) {
  if (typeof v !== "number") return String(v);
  if (digits !== undefined) return v.toFixed(digits);
  if (Number.isInteger(v)) return String(v);
  return String(Math.round(v * 1000) / 1000);
}

/** Human-readable value with hint (enum name, scale + unit). */
function fmtValue(cluster, attr, v) {
  if (v === undefined) return "—";
  if (v === null) return "null";
  if (typeof v === "object") {
    if (v.status) return `status ${v.status}`;
    if ("decoded" in v) {
      const d = JSON.stringify(v.decoded);
      return d.length > 160 ? d.slice(0, 160) + "…" : d;
    }
    return JSON.stringify(v);
  }
  const h = attrDef(cluster, attr) || {};
  if (h.enum && typeof v === "number") return `${h.enum[v] !== undefined ? h.enum[v] : "?"} (${v})`;
  if (typeof v === "number" && h.scale) {
    return `${numStr(v * h.scale, 2)}${h.unit ? " " + h.unit : ""}`;
  }
  if (typeof v === "number") return `${numStr(v)}${h.unit ? " " + h.unit : ""}`;
  if (typeof v === "string") return JSON.stringify(v);
  return String(v);
}

function fmtAgo(tsMs) {
  if (!tsMs) return "-";
  const s = Math.max(0, Math.round((Date.now() - tsMs) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** <span class="ago" data-ts=...> refreshed every second. */
const agoSpan = (tsMs, prefix = "") => el("span", { class: "ago", dataset: { ts: String(tsMs || 0), prefix }, text: prefix + fmtAgo(tsMs) });

function refreshAgo() {
  for (const e of document.querySelectorAll(".ago[data-ts]")) {
    e.textContent = (e.dataset.prefix || "") + fmtAgo(Number(e.dataset.ts));
  }
}

function nodeTitle(n) {
  const b = n.model && n.model.basic ? n.model.basic : {};
  return n.label || b.node_label || b.product_name || `Node ${n.node_id}`;
}

const nodeValue = (n, ep, cluster, attr) => {
  const m = values.get(n.node_id);
  return m ? m.get(vkey(ep, cluster, attr)) : undefined;
};

/** First endpoint that has `cluster` (model, else subscribed paths). */
function epOf(n, cluster) {
  if (n.model) {
    for (const e of n.model.endpoints) if (e.clusters.some((c) => c.id === cluster)) return e.ep;
  }
  const p = (n.sub_paths || []).find((p) => p.cluster === cluster);
  return p ? p.ep : undefined;
}

function hasCluster(n, cluster) {
  return epOf(n, cluster) !== undefined;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

const AQ_CLASS = ["none", "good", "fair", "moderate", "poor", "verypoor", "extremelypoor"];
const AQ_NAME = ["Unknown", "Good", "Fair", "Moderate", "Poor", "VeryPoor", "ExtremelyPoor"];

/** Sensor tile definitions (Tab5 T6 layout). */
const SENSOR_TILES = [
  {
    cluster: 0x005b, label: "Air Quality",
    render: (v) => ({ text: AQ_NAME[v] || `? (${v})`, unit: "", cls: AQ_CLASS[v] || "none", isText: true }),
  },
  {
    cluster: 0x040d, label: "CO2",
    render: (v) => ({ text: numStr(v, 0), unit: "ppm", cls: v >= 2000 ? "bad" : v >= 1000 ? "warn" : "good" }),
  },
  {
    cluster: 0x042a, label: "PM2.5",
    render: (v) => ({ text: numStr(v, 1), unit: "µg/m³", cls: v >= 75 ? "bad" : v >= 35 ? "warn" : "good" }),
  },
  {
    cluster: 0x0402, label: "Temperature",
    render: (v) => ({ text: numStr(v * 0.01, 1), unit: "°C", cls: "neutral" }),
  },
  {
    cluster: 0x0405, label: "Humidity",
    render: (v) => ({ text: numStr(v * 0.01, 1), unit: "%", cls: "neutral" }),
  },
];

function cardHead(n) {
  const head = el("div", { class: "card-head" },
    el("span", { class: "title", text: nodeTitle(n) }),
    el("span", { class: "muted mono small", text: `${n.node_id} (${hex(n.node_id)})` }),
    el("span", { class: `badge ${n.state}`, text: n.state }),
  );
  const last = n.last_report;
  head.appendChild(last ? agoSpan(last, "updated ") : el("span", { class: "ago", text: n.state === "online" ? "waiting for data" : "" }));
  return head;
}

function sensorCard(n) {
  const card = el("div", { class: "card" + (n.state === "online" ? "" : " inactive") }, cardHead(n));
  const tiles = el("div", { class: "tiles" });
  for (const t of SENSOR_TILES) {
    const ep = epOf(n, t.cluster);
    if (ep === undefined) continue;
    const e = nodeValue(n, ep, t.cluster, 0);
    let r = { text: "—", unit: "", cls: "none" };
    if (e && typeof e.value === "number") r = t.render(e.value);
    else if (e && e.value === null) r = { text: "null", unit: "", cls: "none" };
    tiles.appendChild(el("div", { class: `tile ${r.cls}`, title: e ? `ep${ep} dataVersion ${e.data_version}` : `ep${ep}` },
      el("div", { class: "t-label", text: t.label }),
      el("div", { class: "t-value" + (r.isText ? " text" : ""), text: r.text }),
      el("div", { class: "t-unit", text: r.unit || " " }),
    ));
  }
  card.appendChild(tiles);
  if ((n.watch || []).length) card.appendChild(watchKv(n));
  if (n.error && n.state !== "online") card.appendChild(el("div", { class: "muted small", text: n.error }));
  return card;
}

async function lightCmd(n, ep, cmd, btnRow) {
  for (const b of btnRow.querySelectorAll("button")) b.disabled = true;
  const r = await api("POST", `/api/nodes/${n.node_id}/invoke/${ep}/onoff/${cmd}`, {});
  for (const b of btnRow.querySelectorAll("button")) b.disabled = false;
  if (!r.ok) appendLog(`${new Date().toLocaleTimeString()} [ui] ${cmd} node ${n.node_id}: ${errText(r)}`);
}

function lightCard(n) {
  const card = el("div", { class: "card light-card" + (n.state === "online" ? "" : " inactive") }, cardHead(n));
  const eps = n.model
    ? n.model.endpoints.filter((e) => e.clusters.some((c) => c.id === 0x0006)).map((e) => e.ep)
    : (n.sub_paths || []).filter((p) => p.cluster === 0x0006).map((p) => p.ep);
  for (const ep of eps) {
    const on = nodeValue(n, ep, 0x0006, 0);
    const lvl = nodeValue(n, ep, 0x0008, 0);
    const state = on === undefined ? "—" : on.value === true ? "ON" : on.value === false ? "OFF" : String(on.value);
    const row = el("div", { class: "btn-row" },
      el("button", { type: "button", text: "On", onclick: () => lightCmd(n, ep, "on", row) }),
      el("button", { type: "button", text: "Off", class: "secondary", onclick: () => lightCmd(n, ep, "off", row) }),
      el("button", { type: "button", text: "Toggle", onclick: () => lightCmd(n, ep, "toggle", row) }),
    );
    card.append(
      eps.length > 1 ? el("div", { class: "muted small", text: `endpoint ${ep}` }) : "",
      el("div", { class: "light-state " + (state === "ON" ? "on" : "off") },
        state,
        lvl && typeof lvl.value === "number" ? el("span", { class: "muted small", text: `  level ${lvl.value}` }) : ""),
      row,
    );
  }
  if (eps.length === 0) card.appendChild(el("div", { class: "muted", text: "(not described yet — connect from Devices)" }));
  if ((n.watch || []).length) card.appendChild(watchKv(n));
  return card;
}

/** Watched attributes as a key/value list. */
function watchKv(n) {
  const kv = el("div", { class: "kv watch-kv" });
  for (const p of n.watch || []) {
    const c = clusterById.get(p.cluster);
    const a = attrDef(p.cluster, p.attr);
    const e = nodeValue(n, p.ep, p.cluster, p.attr);
    kv.append(
      el("span", { class: "muted", text: `ep${p.ep} ${c ? c.name : hex(p.cluster)}.${a ? a.name : hex(p.attr)}` }),
      el("span", { class: "mono", text: e ? fmtValue(p.cluster, p.attr, e.value) : "—" }),
    );
  }
  return kv;
}

function otherCard(n) {
  const card = el("div", { class: "card" + (n.state === "online" ? "" : " inactive") }, cardHead(n));
  if ((n.watch || []).length === 0) {
    card.appendChild(el("div", { class: "muted small", text: "No watched attributes. Use Watch in the Devices tab." }));
  } else card.appendChild(watchKv(n));
  return card;
}

function renderDashboard() {
  const sensors = $("#dash-sensors");
  const lights = $("#dash-lights");
  const others = $("#dash-others");
  sensors.textContent = "";
  lights.textContent = "";
  others.textContent = "";
  const list = [...nodes.values()].sort((a, b) => a.node_id - b.node_id);
  $("#dash-empty").hidden = list.length !== 0;
  for (const n of list) {
    if (n.kind === "sensor") sensors.appendChild(sensorCard(n));
    else if (n.kind === "light") lights.appendChild(lightCard(n));
    else others.appendChild(otherCard(n));
  }
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

function nodeRow(n) {
  const b = n.model && n.model.basic ? n.model.basic : {};
  const row = el("div", { class: "node-row", onclick: (ev) => {
    if (ev.target.closest("button")) return;
    if (expanded.has(n.node_id)) expanded.delete(n.node_id);
    else expanded.add(n.node_id);
    renderNodePanel(n.node_id);
  } },
    el("span", { class: "caret", text: expanded.has(n.node_id) ? "▾" : "▸" }),
    el("span", { class: "mono", text: `${n.node_id} (${hex(n.node_id)})` }),
    el("span", { text: nodeTitle(n) }),
    b.vendor_name ? el("span", { class: "muted small", text: b.vendor_name }) : "",
    el("span", { class: "badge kind", text: n.kind }),
    el("span", { class: "mono small muted grow", text: n.addr || "(unresolved)" }),
    n.sub_id !== null && n.sub_id !== undefined ? el("span", { class: "badge sub", title: "subscription id", text: `sub ${n.sub_id}` }) : "",
    el("span", { class: `badge ${n.state}`, title: n.error || "", text: n.state }),
  );
  const connect = el("button", { type: "button", class: "small", text: "Connect", onclick: async () => {
    connect.disabled = true;
    connect.textContent = "Connecting...";
    const r = await api("POST", `/api/nodes/${n.node_id}/connect`);
    showNodeResult(n.node_id, `connect`, r);
    connect.disabled = false;
    connect.textContent = "Connect";
  } });
  const describe = el("button", { type: "button", class: "small secondary", text: "Describe", onclick: async () => {
    describe.disabled = true;
    const r = await api("POST", `/api/nodes/${n.node_id}/describe`);
    showNodeResult(n.node_id, `describe`, r);
    describe.disabled = false;
  } });
  row.append(connect, describe);
  return row;
}

function showNodeResult(nodeId, title, r) {
  if (!expanded.has(nodeId)) {
    expanded.add(nodeId);
    renderNodePanel(nodeId);
  }
  const pre = document.getElementById(`result-${nodeId}`);
  if (!pre) return;
  pre.hidden = false;
  pre.classList.toggle("error", !r.ok);
  pre.textContent = `${title} -> HTTP ${r.status}\n` + JSON.stringify(r.data, null, 2);
}

function isWatched(n, p) {
  return (n.watch || []).some((w) => w.ep === p.ep && w.cluster === p.cluster && w.attr === p.attr);
}

function isSubscribed(n, p) {
  return (n.sub_paths || []).some((w) => w.ep === p.ep && w.cluster === p.cluster && w.attr === p.attr);
}

function valueCell(n, ep, cluster, attr) {
  const td = el("td", { class: "val", id: `val-${n.node_id}-${ep}-${cluster}-${attr}` });
  fillValueCell(td, n, ep, cluster, attr);
  return td;
}

function fillValueCell(td, n, ep, cluster, attr) {
  td.textContent = "";
  const e = nodeValue(n, ep, cluster, attr);
  if (!e) {
    td.appendChild(el("span", { class: "muted", text: "—" }));
    return;
  }
  const text = fmtValue(cluster, attr, e.value);
  const span = el("span", { text });
  if (e.raw_hex) span.title = `raw ${e.raw_hex}` + (e.value && e.value.pretty ? `\n${e.value.pretty}` : "") + (e.data_version !== null ? `\ndataVersion ${e.data_version}` : "");
  td.append(span, agoSpan(e.ts));
}

function attrTable(n, ep, c) {
  const table = el("table", { class: "attrs" },
    el("thead", {}, el("tr", {}, el("th", { text: "Attr" }), el("th", { text: "Name" }), el("th", { text: "Type" }), el("th", { text: "Value" }), el("th", { text: "" }))));
  const tbody = el("tbody");
  const attrs = c.attrs && c.attrs.length ? c.attrs : [];
  if (attrs.length === 0) {
    tbody.appendChild(el("tr", {}, el("td", { colspan: "5", class: "muted", text: "attribute list unknown (cluster not in the table) — use the raw Read form" })));
  }
  for (const a of attrs) {
    const p = { ep, cluster: c.id, attr: a.id };
    const watched = isWatched(n, p);
    const subscribed = isSubscribed(n, p);
    const readBtn = el("button", { type: "button", class: "small", text: "Read", onclick: async () => {
      readBtn.disabled = true;
      const r = await api("GET", `/api/nodes/${n.node_id}/attr/${ep}/${c.id}/${a.id}?raw=1`);
      readBtn.disabled = false;
      if (!r.ok) showNodeResult(n.node_id, `read ep${ep} ${hex(c.id)}/${hex(a.id)}`, r);
    } });
    const watchBtn = el("button", {
      type: "button",
      class: "small" + (watched ? "" : " secondary"),
      text: watched ? "Unwatch" : subscribed ? "Subscribed" : "Watch",
      disabled: subscribed && !watched,
      title: subscribed && !watched ? "part of the default subscription" : "",
      onclick: async () => {
        watchBtn.disabled = true;
        const r = await api(watched ? "DELETE" : "POST", `/api/nodes/${n.node_id}/watch`, { paths: [p] });
        if (!r.ok) showNodeResult(n.node_id, "watch", r);
        else {
          n.watch = r.data.watch;
          n.sub_paths = r.data.sub_paths || n.sub_paths;
          renderNodePanel(n.node_id);
          renderDashboard();
        }
      },
    });
    tbody.appendChild(el("tr", {},
      el("td", { class: "mono", text: hex(a.id) }),
      el("td", { text: a.name || "" }),
      el("td", { class: "muted", text: a.kind || "" }),
      valueCell(n, ep, c.id, a.id),
      el("td", {}, el("div", { class: "btn-row" }, readBtn, watchBtn)),
    ));
  }
  table.appendChild(tbody);
  return table;
}

function cmdForms(n, ep, c) {
  const box = el("div", { class: "cmds" });
  const def = clusterById.get(c.id);
  const invoke = async (cmd, body, btn) => {
    btn.disabled = true;
    const r = await api("POST", `/api/nodes/${n.node_id}/invoke/${ep}/${c.id}/${cmd}`, body);
    btn.disabled = false;
    showNodeResult(n.node_id, `invoke ep${ep} ${def ? def.name : hex(c.id)}.${cmd}`, r);
  };
  if (def && def.commands.length) {
    for (const m of def.commands) {
      const inputs = m.fields.map((f) => el("input", { placeholder: `${f.name}: ${f.kind}${f.optional ? " (opt)" : ""}`, title: `tag ${f.tag}`, dataset: { name: f.name } }));
      const btn = el("button", { type: "button", class: "small", text: "Invoke" });
      btn.onclick = () => {
        const args = {};
        for (const i of inputs) if (i.value.trim() !== "") args[i.dataset.name] = i.value.trim();
        invoke(m.name, { args }, btn);
      };
      box.appendChild(el("div", { class: "cmd" }, el("span", { class: "cmd-name", text: `${hex(m.id, 2)} ${m.name}` }), ...inputs, btn));
    }
  } else {
    const id = el("input", { placeholder: "command id (0x..)" });
    const tlv = el("input", { class: "wide", placeholder: "fields TLV hex (e.g. 1518)" });
    const btn = el("button", { type: "button", class: "small", text: "Invoke" });
    btn.onclick = () => {
      if (!id.value.trim()) return;
      invoke(encodeURIComponent(id.value.trim()), tlv.value.trim() ? { tlv: tlv.value.trim() } : {}, btn);
    };
    box.appendChild(el("div", { class: "cmd" }, el("span", { class: "cmd-name", text: "raw command" }), id, tlv, btn));
  }
  return box;
}

/** Open <details> state survives re-render (key = node/ep[/cluster]). */
const openDetails = new Set();

function detailsEl(cls, key, summary, fill) {
  const d = el("details", { class: cls }, el("summary", {}, ...summary));
  let filled = false;
  const doFill = () => {
    if (!filled) {
      filled = true;
      fill(d);
    }
  };
  if (openDetails.has(key)) {
    d.open = true;
    doFill();
  }
  d.addEventListener("toggle", () => {
    if (d.open) {
      openDetails.add(key);
      doFill();
    } else openDetails.delete(key);
  });
  return d;
}

function nodeBody(n) {
  const body = el("div", { class: "node-body" });
  const b = n.model && n.model.basic ? n.model.basic : {};
  const kv = el("div", { class: "kv" });
  const addKv = (k, v) => v && kv.append(el("span", { class: "muted", text: k }), el("span", { text: v }));
  addKv("Vendor", b.vendor_name);
  addKv("Product", b.product_name);
  addKv("Node label", b.node_label);
  addKv("Serial", b.serial_number);
  addKv("Software", b.software_version);
  addKv("Last seen", n.last_seen ? new Date(n.last_seen * 1000).toLocaleString() : "");
  addKv("Subscribed", (n.sub_paths || []).length ? `${n.sub_paths.length} path(s)${n.sub_id != null ? `, sub ${n.sub_id}` : " (not established)"}` : "");
  addKv("Next retry", n.next_retry ? new Date(n.next_retry * 1000).toLocaleTimeString() : "");
  body.appendChild(kv);
  if (n.error) body.appendChild(el("div", { class: "err small", text: n.error }));
  if (!n.model) {
    body.appendChild(el("p", { class: "muted", text: "Not described yet. Connect to read the endpoint / cluster tree." }));
  } else {
    for (const e of n.model.endpoints) {
      const dts = (e.device_type_names || e.device_types.map((d) => hex(d))).join(", ");
      body.appendChild(detailsEl("ep", `${n.node_id}/${e.ep}`,
        [`Endpoint ${e.ep}`, el("span", { class: "muted small", text: `  ${dts}  (${e.clusters.length} clusters)` })],
        (d) => {
          for (const c of e.clusters) {
            const label = c.name || c.spec_name || "(unknown)";
            d.appendChild(detailsEl("cl", `${n.node_id}/${e.ep}/${c.id}`,
              [el("span", { class: "mono", text: hex(c.id) }), ` ${label}`, c.spec_name && c.name ? el("span", { class: "muted small", text: `  ${c.spec_name}` }) : ""],
              (cd) => {
                cd.appendChild(attrTable(n, e.ep, c));
                cd.appendChild(cmdForms(n, e.ep, c));
              }));
          }
        }));
    }
  }
  body.appendChild(el("pre", { class: "node-result", id: `result-${n.node_id}`, hidden: true }));
  return body;
}

function renderNodePanel(nodeId) {
  const n = nodes.get(nodeId);
  let panel = document.getElementById(`node-${nodeId}`);
  if (!n) {
    if (panel) panel.remove();
    return;
  }
  const fresh = el("div", { class: "node-panel", id: `node-${nodeId}` }, nodeRow(n));
  if (expanded.has(nodeId)) {
    // Keep the last result visible across re-renders.
    const old = panel && panel.querySelector(`#result-${nodeId}`);
    const body = nodeBody(n);
    if (old && !old.hidden) body.replaceChild(old, body.querySelector(`#result-${nodeId}`));
    fresh.appendChild(body);
  }
  if (panel) panel.replaceWith(fresh);
  else $("#node-list").appendChild(fresh);
}

/** Update only the header row (state / sub badges) without collapsing the tree. */
function renderNodeRow(nodeId) {
  const n = nodes.get(nodeId);
  const panel = document.getElementById(`node-${nodeId}`);
  if (!n || !panel) return renderNodePanel(nodeId);
  panel.replaceChild(nodeRow(n), panel.firstChild);
}

function renderDevices() {
  const list = $("#node-list");
  list.textContent = "";
  const all = [...nodes.values()].sort((a, b) => a.node_id - b.node_id);
  if (all.length === 0) list.appendChild(el("p", { class: "muted", text: "No paired nodes (commission with smctl first)." }));
  for (const n of all) renderNodePanel(n.node_id);
  for (const sel of document.querySelectorAll(".node-select")) {
    const prev = sel.value;
    sel.textContent = "";
    for (const n of all) sel.appendChild(el("option", { value: String(n.node_id), text: `${n.node_id} - ${nodeTitle(n)}` }));
    if (prev) sel.value = prev;
  }
}

// ---------------------------------------------------------------------------
// Raw forms (W1)
// ---------------------------------------------------------------------------

function showResult(title, r) {
  const e = $("#result");
  e.classList.remove("muted");
  e.classList.toggle("error", !r.ok);
  e.textContent = `${title} -> HTTP ${r.status}\n` + JSON.stringify(r.data, null, 2);
}

function findCluster(v) {
  const s = v.trim().toLowerCase();
  return clusters.find((c) => c.name === s || String(c.id) === s || hex(c.id).toLowerCase() === s || "0x" + c.id.toString(16) === s);
}

function fillList(id, items) {
  const dl = document.getElementById(id);
  dl.textContent = "";
  for (const it of items) dl.appendChild(el("option", { value: it.name, label: `${hex(it.id)}${it.kind ? " " + it.kind : ""}` }));
}

const updateAttrList = () => { const c = findCluster($("#read-form").cluster.value); fillList("attr-list", c ? c.attributes : []); };
const updateCmdList = () => { const c = findCluster($("#invoke-form").cluster.value); fillList("cmd-list", c ? c.commands : []); };
const seg = (s) => encodeURIComponent(s.trim());

$("#read-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const path = `/api/nodes/${seg(f.node.value)}/attr/${seg(f.ep.value)}/${seg(f.cluster.value)}/${seg(f.attr.value)}` + (f.raw.checked ? "?raw=1" : "");
  const btn = f.querySelector("button");
  btn.disabled = true;
  try {
    showResult(`GET ${path}`, await api("GET", path));
  } finally {
    btn.disabled = false;
  }
});

$("#invoke-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const body = {};
  if (f.args.value.trim()) {
    try {
      body.args = JSON.parse(f.args.value);
    } catch (e) {
      showResult("invoke", { ok: false, status: 0, data: { error: { code: "bad_request", message: `args: ${e}` } } });
      return;
    }
  }
  if (f.tlv.value.trim()) body.tlv = f.tlv.value.trim();
  if (f.timed.value.trim()) body.timed_ms = Number(f.timed.value.trim());
  const path = `/api/nodes/${seg(f.node.value)}/invoke/${seg(f.ep.value)}/${seg(f.cluster.value)}/${seg(f.cmd.value)}`;
  const btn = f.querySelector("button");
  btn.disabled = true;
  try {
    showResult(`POST ${path}`, await api("POST", path, body));
  } finally {
    btn.disabled = false;
  }
});
$("#read-form").cluster.addEventListener("change", updateAttrList);
$("#invoke-form").cluster.addEventListener("change", updateCmdList);

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

const logLines = [];
const LOG_MAX = 1000;

function logVisible(line) {
  const f = $("#log-filter").value.trim().toLowerCase();
  return !f || line.toLowerCase().includes(f);
}

function appendLog(line, isAttr = false) {
  logLines.push({ line, isAttr });
  if (logLines.length > LOG_MAX) logLines.splice(0, logLines.length - LOG_MAX);
  if (isAttr && !$("#log-attr").checked) return;
  if (!logVisible(line)) return;
  const e = $("#log");
  const atBottom = e.scrollTop + e.clientHeight >= e.scrollHeight - 4;
  e.appendChild(document.createTextNode(line + "\n"));
  while (e.childNodes.length > LOG_MAX) e.removeChild(e.firstChild);
  if (atBottom) e.scrollTop = e.scrollHeight;
}

function rerenderLog() {
  const e = $("#log");
  const withAttr = $("#log-attr").checked;
  e.textContent = logLines.filter((l) => (withAttr || !l.isAttr) && logVisible(l.line)).map((l) => l.line).join("\n") + "\n";
  e.scrollTop = e.scrollHeight;
}
$("#log-filter").addEventListener("input", rerenderLog);
$("#log-attr").addEventListener("change", rerenderLog);
$("#log-clear").addEventListener("click", () => { logLines.length = 0; rerenderLog(); });

// ---------------------------------------------------------------------------
// Snapshot / events
// ---------------------------------------------------------------------------

function renderInfo() {
  if (!info) return;
  const parts = [`v${info.version}`, `state: ${info.state_dir}`];
  if (info.fabric_id) parts.push(`fabric ${info.fabric_id}`);
  if (info.controller_node_id) parts.push(`controller ${info.controller_node_id}`);
  if (info.features && info.features.length) parts.push(`features: ${info.features.join(",")}`);
  if (info.error) parts.push(`ERROR: ${info.error}`);
  $("#info").textContent = parts.join(" | ");
  $("#info").title = parts.join("\n");
}

function setNode(n) {
  nodes.set(n.node_id, n);
  const m = new Map();
  for (const v of n.values || []) m.set(vkey(v.ep, v.cluster, v.attr), v);
  values.set(n.node_id, m);
}

let dashTimer = null;
/** Coalesce dashboard re-renders (reports arrive in bursts). */
function scheduleDashboard() {
  if (dashTimer) return;
  dashTimer = setTimeout(() => {
    dashTimer = null;
    renderDashboard();
  }, 100);
}

function onEvent(ev) {
  const t = new Date().toLocaleTimeString();
  switch (ev.type) {
    case "snapshot":
      info = ev.info;
      renderInfo();
      nodes.clear();
      values.clear();
      for (const n of ev.nodes) setNode(n);
      renderDashboard();
      renderDevices();
      break;
    case "node_state": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.state = ev.state;
      if (ev.addr) n.addr = ev.addr;
      n.error = ev.error || null;
      n.next_retry = ev.next_retry || null;
      if (ev.state === "online") n.last_seen = Math.floor(Date.now() / 1000);
      scheduleDashboard();
      renderNodeRow(ev.node_id);
      appendLog(`${t} [node] ${ev.node_id}: ${ev.state}${ev.error ? " (" + ev.error + ")" : ""}`);
      break;
    }
    case "model": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.model = ev.model;
      n.kind = ev.kind;
      scheduleDashboard();
      renderDevices();
      break;
    }
    case "attr": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      let m = values.get(ev.node_id);
      if (!m) values.set(ev.node_id, (m = new Map()));
      m.set(vkey(ev.ep, ev.cluster, ev.attr), ev);
      n.last_report = ev.ts;
      const td = document.getElementById(`val-${ev.node_id}-${ev.ep}-${ev.cluster}-${ev.attr}`);
      if (td) fillValueCell(td, n, ev.ep, ev.cluster, ev.attr);
      scheduleDashboard();
      const c = clusterById.get(ev.cluster);
      const a = attrDef(ev.cluster, ev.attr);
      appendLog(`${t} [attr] ${ev.node_id} ep${ev.ep} ${c ? c.name : hex(ev.cluster)}.${a ? a.name : hex(ev.attr)} = ${fmtValue(ev.cluster, ev.attr, ev.value)}`, true);
      break;
    }
    case "sub_ready": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.sub_id = ev.sub_id;
      n.sub_paths = ev.paths;
      renderNodeRow(ev.node_id);
      appendLog(`${t} [sub] ${ev.node_id}: subscription ${ev.sub_id} ready (${ev.paths.length} paths, max ${ev.max_interval_s}s)`);
      break;
    }
    case "sub_lost": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.sub_id = null;
      n.state = "stale";
      scheduleDashboard();
      renderNodeRow(ev.node_id);
      appendLog(`${t} [sub] ${ev.node_id}: subscription ${ev.sub_id} LOST`);
      break;
    }
    case "watch": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.watch = ev.watch;
      scheduleDashboard();
      break;
    }
    case "log":
      appendLog(`${new Date(ev.ts).toLocaleTimeString()} [${ev.tag}] ${ev.level !== "info" ? ev.level + ": " : ""}${ev.msg}`);
      break;
    case "lagged":
      appendLog(`${t} (missed ${ev.missed} events; resyncing)`);
      break;
    default:
      break;
  }
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws`);
  const badge = $("#ws");
  ws.onopen = () => {
    badge.textContent = "ws: connected";
    badge.className = "badge online";
  };
  ws.onclose = () => {
    badge.textContent = "ws: disconnected";
    badge.className = "badge offline";
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (m) => {
    let ev;
    try {
      ev = JSON.parse(m.data);
    } catch (_) {
      return;
    }
    if (ev.type === "lagged") {
      // Missed events: reconnect to get a fresh snapshot.
      onEvent(ev);
      ws.close();
      return;
    }
    onEvent(ev);
  };
}

// ---------------------------------------------------------------------------
// Tabs / boot
// ---------------------------------------------------------------------------

function showTab(name) {
  activeTab = name;
  for (const b of document.querySelectorAll("button.tab")) b.classList.toggle("active", b.dataset.tab === name);
  for (const p of document.querySelectorAll(".tab-panel")) p.hidden = p.id !== `tab-${name}`;
  try {
    localStorage.setItem("smweb.tab", name);
  } catch (_) { /* storage unavailable */ }
  if (name === "log") $("#log").scrollTop = $("#log").scrollHeight;
}
for (const b of document.querySelectorAll("button.tab")) b.addEventListener("click", () => showTab(b.dataset.tab));

(async () => {
  let saved = null;
  try {
    saved = localStorage.getItem("smweb.tab");
  } catch (_) { /* storage unavailable */ }
  showTab(["dashboard", "devices", "log"].includes(saved) ? saved : "dashboard");
  const r = await api("GET", "/api/clusters");
  if (r.ok) {
    clusters = r.data;
    for (const c of clusters) clusterById.set(c.id, c);
    fillList("cluster-list", clusters);
    updateAttrList();
    updateCmdList();
  }
  connectWs();
  setInterval(refreshAgo, 1000);
})();
