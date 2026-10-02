// smweb UI (W5): Dashboard / Devices / Pair / Log, live from the WebSocket.
// Plain ES2020, no build step. The only dependency is the vendored MIT QR generator
// (/qrcode.js, global `qrcode`) used by the Share panel. History charts are drawn by
// /chart.js (global `SmChart`, pure SVG builder).
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

/**
 * Threshold bands per cluster (MeasuredValue / AirQuality, raw units): [from, to, class].
 * Shared by the tile colors and the chart backgrounds (Tab5 T6 thresholds).
 */
const BANDS = {
  0x040d: [[-Infinity, 1000, "good"], [1000, 2000, "warn"], [2000, Infinity, "bad"]],
  0x042a: [[-Infinity, 35, "good"], [35, 75, "warn"], [75, Infinity, "bad"]],
  0x005b: AQ_CLASS.map((cls, i) => [i - 0.5, i + 0.5, cls]),
};

function bandClass(cluster, v) {
  const b = (BANDS[cluster] || []).find(([from, to]) => v >= from && v < to);
  return b ? b[2] : "neutral";
}

/** Sensor tile definitions (Tab5 T6 layout). */
const SENSOR_TILES = [
  {
    cluster: 0x005b, label: "Air Quality",
    render: (v) => ({ text: AQ_NAME[v] || `? (${v})`, unit: "", cls: AQ_CLASS[v] || "none", isText: true }),
  },
  {
    cluster: 0x040d, label: "CO2",
    render: (v) => ({ text: numStr(v, 0), unit: "ppm", cls: bandClass(0x040d, v) }),
  },
  {
    cluster: 0x042a, label: "PM2.5",
    render: (v) => ({ text: numStr(v, 1), unit: "µg/m³", cls: bandClass(0x042a, v) }),
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

const TRANSPORT_LABEL = { wifi: "WiFi", thread: "Thread", ethernet: "Ethernet" };

/** Transport list of a node (described model first, then the /api/nodes summary). */
function nodeTransports(n) {
  const m = n.model || {};
  const list = (m.transports && m.transports.length ? m.transports : n.transports) || [];
  if (list.length) return list;
  const one = m.transport || n.transport;
  return one ? [one] : [];
}

/** "IPv6" / "IPv4" from the operational address, or "" when unresolved. */
function addrFamily(addr) {
  if (!addr) return "";
  return addr.startsWith("[") || (addr.match(/:/g) || []).length > 1 ? "IPv6" : "IPv4";
}

/** Transport badges (WiFi / Thread / Ethernet); empty when unknown. */
function transportBadges(n) {
  return nodeTransports(n).map((t) => el("span", {
    class: `badge transport ${t}`,
    title: "NetworkCommissioning FeatureMap",
    text: TRANSPORT_LABEL[t] || t,
  }));
}

function cardHead(n) {
  const head = el("div", { class: "card-head" },
    el("span", { class: "title", text: nodeTitle(n) }),
    ...transportBadges(n),
    addrFamily(n.addr) ? el("span", { class: "muted small", title: n.addr, text: addrFamily(n.addr) }) : "",
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
    const graphing = charts.has(chartKey("dash", n.node_id, ep, t.cluster, 0));
    tiles.appendChild(el("div", {
      class: `tile ${r.cls}` + (graphing ? " graphing" : ""),
      title: (e ? `ep${ep} dataVersion ${e.data_version}` : `ep${ep}`) + "\nclick: show / hide history graph",
      role: "button", tabindex: "0",
      onclick: () => { toggleChart("dash", n.node_id, ep, t.cluster, 0, t.label); renderDashboard(); },
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggleChart("dash", n.node_id, ep, t.cluster, 0, t.label); renderDashboard(); } },
    },
      el("div", { class: "t-label", text: t.label }),
      el("div", { class: "t-value" + (r.isText ? " text" : ""), text: r.text }),
      el("div", { class: "t-unit", text: r.unit || " " }),
    ));
  }
  card.appendChild(tiles);
  if ((n.watch || []).length) card.appendChild(watchKv(n));
  if (n.error && n.state !== "online") card.appendChild(el("div", { class: "muted small", text: n.error }));
  card.appendChild(chartsBox(n));
  return card;
}

/**
 * Contact sensor (BooleanState 0x0045): StateValue true = contact = closed (ContactSensor
 * device type). Battery from PowerSource.BatPercentRemaining (0.5 % units) when subscribed.
 */
function contactCard(n) {
  const card = el("div", { class: "card" + (n.state === "online" ? "" : " inactive") }, cardHead(n));
  const tiles = el("div", { class: "tiles" });
  const tile = (ep, cluster, attr, label, r) => {
    const e = nodeValue(n, ep, cluster, attr);
    const graphing = charts.has(chartKey("dash", n.node_id, ep, cluster, attr));
    const toggle = () => { toggleChart("dash", n.node_id, ep, cluster, attr, label); renderDashboard(); };
    return el("div", {
      class: `tile ${r.cls}` + (graphing ? " graphing" : ""),
      title: (e ? `ep${ep} dataVersion ${e.data_version}` : `ep${ep}`) + "\nclick: show / hide history graph",
      role: "button", tabindex: "0",
      onclick: toggle,
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(); } },
    },
      el("div", { class: "t-label", text: label }),
      el("div", { class: "t-value" + (r.isText ? " text" : ""), text: r.text }),
      el("div", { class: "t-unit", text: r.unit || " " }),
    );
  };
  const paths = n.sub_paths || [];
  const stateEps = n.model
    ? n.model.endpoints.filter((e) => e.clusters.some((c) => c.id === 0x0045)).map((e) => e.ep)
    : paths.filter((p) => p.cluster === 0x0045).map((p) => p.ep);
  for (const ep of stateEps) {
    const e = nodeValue(n, ep, 0x0045, 0);
    let r = { text: "—", unit: "", cls: "none", isText: true };
    if (e && e.value === true) r = { text: "Closed", unit: "contact", cls: "good", isText: true };
    else if (e && e.value === false) r = { text: "Open", unit: "no contact", cls: "warn", isText: true };
    const label = stateEps.length > 1 ? `Contact (ep${ep})` : "Contact";
    tiles.appendChild(tile(ep, 0x0045, 0, label, r));
  }
  for (const p of paths.filter((p) => p.cluster === 0x002f && p.attr === 0x000c)) {
    const e = nodeValue(n, p.ep, 0x002f, 0x000c);
    let r = { text: "—", unit: "%", cls: "none" };
    if (e && typeof e.value === "number") {
      const pct = e.value * 0.5;
      r = { text: numStr(pct, 0), unit: "%", cls: pct <= 10 ? "bad" : pct <= 25 ? "warn" : "neutral" };
    }
    tiles.appendChild(tile(p.ep, 0x002f, 0x000c, "Battery", r));
  }
  if (stateEps.length === 0) card.appendChild(el("div", { class: "muted", text: "(not described yet — connect from Devices)" }));
  card.appendChild(tiles);
  if ((n.watch || []).length) card.appendChild(watchKv(n));
  if (n.error && n.state !== "online") card.appendChild(el("div", { class: "muted small", text: n.error }));
  card.appendChild(chartsBox(n));
  return card;
}

/** The dashboard card's open graphs (persistent elements, moved into the fresh card). */
function chartsBox(n) {
  const box = el("div", { class: "card-charts" });
  for (const ch of chartsFor("dash", n.node_id)) box.appendChild(ch.el);
  return box;
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
  card.appendChild(chartsBox(n));
  return card;
}

/** Watched attributes as a key/value list. */
function watchKv(n) {
  const kv = el("div", { class: "kv watch-kv" });
  for (const p of n.watch || []) {
    const c = clusterById.get(p.cluster);
    const a = attrDef(p.cluster, p.attr);
    const e = nodeValue(n, p.ep, p.cluster, p.attr);
    const name = `ep${p.ep} ${c ? c.name : hex(p.cluster)}.${a ? a.name : hex(p.attr)}`;
    const graphable = isNumericAttr(p.cluster, p.attr);
    const graphing = charts.has(chartKey("dash", n.node_id, p.ep, p.cluster, p.attr));
    kv.append(
      graphable
        ? el("a", { href: "#", class: "graph-link" + (graphing ? " active" : ""), title: "show / hide history graph", text: name,
          onclick: (ev) => { ev.preventDefault(); toggleChart("dash", n.node_id, p.ep, p.cluster, p.attr, name); renderDashboard(); } })
        : el("span", { class: "muted", text: name }),
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
  card.appendChild(chartsBox(n));
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
    else if (n.kind === "contact") sensors.appendChild(contactCard(n));
    else if (n.kind === "light") lights.appendChild(lightCard(n));
    else others.appendChild(otherCard(n));
  }
  for (const ch of charts.values()) if (ch.where === "dash") fitChart(ch);
}

// ---------------------------------------------------------------------------
// History charts (W5): /api/nodes/{id}/history + live `attr` events
// ---------------------------------------------------------------------------

const C = window.SmChart;
const RANGES = [["1h", 3600e3], ["6h", 6 * 3600e3], ["24h", 86400e3], ["all", 0]];
/** Client-side buffer bound per chart (the server keeps --history-points). */
const CHART_MAX_POINTS = 100000;
/** Open charts: key ("dash|dev:node/ep/cluster/attr") -> chart. Insertion order = display order. */
const charts = new Map();
const chartKey = (where, nodeId, ep, cluster, attr) => `${where}:${nodeId}/${ep}/${cluster}/${attr}`;
let chartSeq = 0;

function isNumericAttr(cluster, attr, kind) {
  const k = kind || (attrDef(cluster, attr) || {}).kind;
  return C.NUMERIC_KINDS.has(k);
}

function seriesName(cluster, attr) {
  const c = clusterById.get(cluster);
  const a = attrDef(cluster, attr);
  return `${c ? c.name : hex(cluster)}.${a ? a.name : hex(attr)}`;
}

function chartMeta(ch) {
  const h = attrDef(ch.cluster, ch.attr) || {};
  const m = ch.meta || {};
  return { kind: m.kind || h.kind, unit: m.unit || h.unit, scale: m.scale || h.scale, enum: m.enum || h.enum };
}

function toggleChart(where, nodeId, ep, cluster, attr, title) {
  const key = chartKey(where, nodeId, ep, cluster, attr);
  if (charts.has(key)) {
    closeChart(key);
    return false;
  }
  openChart(where, nodeId, ep, cluster, attr, title);
  return true;
}

function openChart(where, nodeId, ep, cluster, attr, title) {
  const key = chartKey(where, nodeId, ep, cluster, attr);
  let saved = null;
  try {
    saved = localStorage.getItem("smweb.chartRange");
  } catch (_) { /* storage unavailable */ }
  const ch = {
    key, where, nodeId, ep, cluster, attr,
    title: title || `ep${ep} ${seriesName(cluster, attr)}`,
    range: RANGES.some((r) => r[0] === saved) ? saved : "6h",
    points: [], pending: [], loaded: false, error: null, meta: null, geom: null,
    clipId: `clip${++chartSeq}`,
  };
  ch.el = el("div", { class: "chart", dataset: { key } });
  ch.head = el("div", { class: "chart-head" });
  ch.body = el("div", { class: "chart-body" });
  ch.tip = el("div", { class: "chart-tip", hidden: true });
  ch.statsRow = el("div", { class: "chart-stats small" });
  ch.el.append(ch.head, ch.statsRow, ch.body);
  ch.body.addEventListener("mousemove", (ev) => chartHover(ch, ev));
  ch.body.addEventListener("mouseleave", () => chartHover(ch, null));
  charts.set(key, ch);
  renderChartHead(ch);
  loadChart(ch);
  return ch;
}

function closeChart(key) {
  const ch = charts.get(key);
  if (!ch) return;
  charts.delete(key);
  const row = ch.el.closest("tr.graph-row");
  if (row) row.remove();
  ch.el.remove();
  if (ch.where === "dash") scheduleDashboard();
  else {
    const btn = document.getElementById(`gbtn-${ch.nodeId}-${ch.ep}-${ch.cluster}-${ch.attr}`);
    if (btn) btn.textContent = "Graph";
  }
}

function closeNodeCharts(nodeId) {
  for (const ch of [...charts.values()]) if (ch.nodeId === nodeId) closeChart(ch.key);
}

async function loadChart(ch) {
  ch.loaded = false;
  ch.pending = [];
  renderChart(ch);
  const q = `ep=${ch.ep}&cluster=${ch.cluster}&attr=${ch.attr}&limit=${CHART_MAX_POINTS}`;
  const r = await api("GET", `/api/nodes/${ch.nodeId}/history?${q}`);
  if (!charts.has(ch.key)) return;
  if (!r.ok) {
    ch.error = errText(r);
    ch.loaded = true;
    renderChart(ch);
    return;
  }
  ch.error = null;
  ch.meta = { kind: r.data.kind, unit: r.data.unit, scale: r.data.scale, enum: r.data.enum };
  ch.points = r.data.points || [];
  ch.loaded = true;
  for (const [t, v] of ch.pending) addChartPoint(ch, t, v);
  ch.pending = [];
  renderChartHead(ch);
  renderChart(ch);
}

function addChartPoint(ch, t, v) {
  if (!ch.loaded) {
    ch.pending.push([t, v]);
    return;
  }
  const last = ch.points[ch.points.length - 1];
  if (last && (t < last[0] || (t === last[0] && v === last[1]))) return;
  ch.points.push([t, v]);
  if (ch.points.length > CHART_MAX_POINTS) ch.points.splice(0, ch.points.length - CHART_MAX_POINTS);
}

/** WS `attr` -> every open chart of that series. */
function chartsOnAttr(ev) {
  const v = C.numericOf(ev.value);
  if (v === null) return;
  for (const ch of charts.values()) {
    if (ch.nodeId === ev.node_id && ch.ep === ev.ep && ch.cluster === ev.cluster && ch.attr === ev.attr) {
      addChartPoint(ch, ev.ts, v);
      scheduleChart(ch);
    }
  }
}

const chartsDirty = new Set();
let chartTimer = null;
function scheduleChart(ch) {
  chartsDirty.add(ch);
  if (chartTimer) return;
  chartTimer = setTimeout(() => {
    chartTimer = null;
    for (const c of chartsDirty) if (charts.has(c.key)) renderChart(c);
    chartsDirty.clear();
  }, 200);
}

function chartWindow(ch) {
  const now = Date.now();
  const span = RANGES.find((r) => r[0] === ch.range)[1];
  if (span) return [now - span, now];
  const first = ch.points.length ? ch.points[0][0] : now - 3600e3;
  return [Math.min(first, now - 60e3), now];
}

function renderChartHead(ch) {
  ch.head.textContent = "";
  const seg = el("div", { class: "seg" });
  for (const [name] of RANGES) {
    seg.appendChild(el("button", {
      type: "button", class: "small" + (ch.range === name ? " active" : ""), text: name,
      onclick: () => {
        ch.range = name;
        try {
          localStorage.setItem("smweb.chartRange", name);
        } catch (_) { /* storage unavailable */ }
        renderChartHead(ch);
        renderChart(ch);
      },
    }));
  }
  ch.stats = ch.statsRow;
  ch.head.append(
    el("span", { class: "chart-title", text: ch.title }),
    seg,
    el("button", { type: "button", class: "small secondary chart-close", title: "close graph", text: "×", onclick: () => closeChart(ch.key) }),
  );
}

function renderChart(ch) {
  const meta = chartMeta(ch);
  const [t0, t1] = chartWindow(ch);
  if (ch.stats) {
    const s = C.stats(ch.points, t0, t1);
    if (!ch.loaded) ch.stats.textContent = "loading…";
    else if (ch.error) ch.stats.textContent = ch.error;
    else if (!s.latest) ch.stats.textContent = "no history yet";
    else {
      ch.stats.textContent = "";
      const item = (k, v) => el("span", {}, el("span", { class: "muted", text: k + " " }), el("b", { text: v }));
      ch.stats.append(item("latest", C.fmtValue(s.latest[1], meta)));
      if (s.count) ch.stats.append(item("min", C.fmtValue(s.min, meta)), item("max", C.fmtValue(s.max, meta)));
      ch.stats.append(el("span", { class: "muted", text: `${s.count} pt` }));
    }
  }
  const width = ch.body.clientWidth || (ch.el.parentElement && ch.el.parentElement.clientWidth) || 640;
  const n = nodes.get(ch.nodeId);
  const bands = ch.attr === 0 ? chartBands(ch.cluster) : null;
  const r = C.chartSvg(ch.points, {
    width, height: 190, t0, t1, meta, bands, clipId: ch.clipId,
    live: !!n && n.state === "online", label: ch.title,
  });
  ch.geom = r.geom;
  ch.body.innerHTML = r.svg;
  ch.body.appendChild(ch.tip);
  ch.tip.hidden = true;
}

/** Threshold bands for the chart background, in display units (same table as the tiles). */
function chartBands(cluster) {
  const b = BANDS[cluster];
  if (!b) return null;
  const s = (attrDef(cluster, 0) || {}).scale || 1;
  return b.map(([from, to, cls]) => [from * s, to * s, cls]);
}

function chartHover(ch, ev) {
  const svg = ch.body.querySelector("svg");
  const old = svg && svg.querySelector(".hover");
  if (old) old.remove();
  if (!ev || !svg || !ch.geom) {
    ch.tip.hidden = true;
    return;
  }
  const rect = svg.getBoundingClientRect();
  const px = ev.clientX - rect.left;
  const g = ch.geom;
  if (px < g.L || px > g.L + g.pw) {
    ch.tip.hidden = true;
    return;
  }
  const p = C.nearest(g, px);
  if (!p) {
    ch.tip.hidden = true;
    return;
  }
  const NS = "http://www.w3.org/2000/svg";
  const grp = document.createElementNS(NS, "g");
  grp.setAttribute("class", "hover");
  const line = document.createElementNS(NS, "line");
  line.setAttribute("x1", p[2]); line.setAttribute("x2", p[2]);
  line.setAttribute("y1", g.T); line.setAttribute("y2", g.T + g.ph);
  const dot = document.createElementNS(NS, "circle");
  dot.setAttribute("cx", p[2]); dot.setAttribute("cy", p[3]); dot.setAttribute("r", 4);
  grp.append(line, dot);
  svg.appendChild(grp);
  ch.tip.textContent = "";
  ch.tip.append(
    el("b", { text: C.fmtValue(p[1], chartMeta(ch)) }),
    el("span", { class: "muted", text: " " + new Date(p[0]).toLocaleString() }),
  );
  ch.tip.hidden = false;
  const tw = ch.tip.offsetWidth;
  let x = p[2] + 12;
  if (x + tw > rect.width) x = p[2] - tw - 12;
  ch.tip.style.left = `${Math.max(0, x)}px`;
  ch.tip.style.top = `${Math.max(0, p[3] - 34)}px`;
}

/** Charts of a node for one place (dashboard card / devices row), in opening order. */
const chartsFor = (where, nodeId) => [...charts.values()].filter((c) => c.where === where && c.nodeId === nodeId);

/** After (re)attaching a chart element: re-fit when the width it was drawn at is off. */
function fitChart(ch) {
  const w = ch.body.clientWidth;
  if (w && ch.geom && Math.abs(w - ch.geom.W) > 2) renderChart(ch);
}

// Slide the time window / re-fit widths.
setInterval(() => { for (const ch of charts.values()) renderChart(ch); }, 15000);
let resizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { for (const ch of charts.values()) renderChart(ch); }, 150);
});

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
    ...transportBadges(n),
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
  const rename = el("button", { type: "button", class: "small secondary", text: "Rename", onclick: () => openRename(n.node_id) });
  const share = el("button", { type: "button", class: "small secondary", text: "Share", title: "open a commissioning window for another controller", onclick: () => openShare(n.node_id) });
  const unpairBtn = el("button", { type: "button", class: "small danger", text: "Unpair", onclick: () => openUnpair(n.node_id) });
  row.append(connect, describe, rename, share, unpairBtn);
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
    const gkey = chartKey("dev", n.node_id, ep, c.id, a.id);
    const graphRow = (ch) => el("tr", { class: "graph-row" }, el("td", { colspan: "5" }, ch.el));
    let graphBtn = null;
    if (isNumericAttr(c.id, a.id, a.kind)) {
      graphBtn = el("button", {
        type: "button", class: "small secondary", id: `gbtn-${n.node_id}-${ep}-${c.id}-${a.id}`,
        text: charts.has(gkey) ? "Hide graph" : "Graph", title: "history graph (numeric attribute)",
        onclick: () => {
          if (charts.has(gkey)) {
            closeChart(gkey);
            return;
          }
          const ch = openChart("dev", n.node_id, ep, c.id, a.id, `ep${ep} ${c.name || hex(c.id)}.${a.name || hex(a.id)}`);
          tr.after(graphRow(ch));
          graphBtn.textContent = "Hide graph";
          fitChart(ch);
        },
      });
    }
    const tr = el("tr", {},
      el("td", { class: "mono", text: hex(a.id) }),
      el("td", { text: a.name || "" }),
      el("td", { class: "muted", text: a.kind || "" }),
      valueCell(n, ep, c.id, a.id),
      el("td", {}, el("div", { class: "btn-row" }, readBtn, watchBtn, graphBtn)),
    );
    tbody.appendChild(tr);
    if (charts.has(gkey)) {
      const ch = charts.get(gkey);
      tbody.appendChild(graphRow(ch));
      setTimeout(() => fitChart(ch), 0);
    }
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
  if (all.length === 0) list.appendChild(el("p", { class: "muted", text: "No paired nodes (commission one from the Pair tab)." }));
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
// Modal (in-page; no window.confirm)
// ---------------------------------------------------------------------------

let modalClose = null;

function openModal(title, body, onClose) {
  if (modalClose) modalClose();
  $("#modal-title").textContent = title;
  const b = $("#modal-body");
  b.textContent = "";
  b.appendChild(body);
  $("#modal").hidden = false;
  modalClose = () => {
    modalClose = null;
    $("#modal").hidden = true;
    $("#modal-body").textContent = "";
    if (onClose) onClose();
  };
  const first = b.querySelector("input, select, button");
  if (first) first.focus();
}

function closeModal() {
  if (modalClose) modalClose();
}

$("#modal-x").addEventListener("click", closeModal);
$("#modal").addEventListener("click", (ev) => { if (ev.target.id === "modal") closeModal(); });
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && modalClose) closeModal(); });

// ---------------------------------------------------------------------------
// Devices: rename / unpair
// ---------------------------------------------------------------------------

function openRename(nodeId) {
  const n = nodes.get(nodeId);
  if (!n) return;
  const input = el("input", { value: n.label || "", maxlength: "64", placeholder: "label (empty to clear)" });
  const msg = el("div", { class: "err small" });
  const save = el("button", { type: "submit", text: "Save" });
  const form = el("form", { class: "plain", onsubmit: async (ev) => {
    ev.preventDefault();
    save.disabled = true;
    const r = await api("PATCH", `/api/nodes/${nodeId}`, { label: input.value });
    save.disabled = false;
    if (!r.ok) {
      msg.textContent = errText(r);
      return;
    }
    const m = nodes.get(nodeId);
    if (m) m.label = r.data.label;
    renderDevices();
    scheduleDashboard();
    closeModal();
  } },
    el("label", {}, `Label for node ${nodeId} (${hex(nodeId)})`, input),
    msg,
    el("div", { class: "modal-actions" }, el("button", { type: "button", class: "secondary", text: "Cancel", onclick: closeModal }), save),
  );
  openModal("Rename node", form);
}

function openUnpair(nodeId) {
  const n = nodes.get(nodeId);
  if (!n) return;
  const msg = el("div", { class: "err small" });
  const status = el("div", { class: "muted small" });
  const cancel = el("button", { type: "button", class: "secondary", text: "Cancel", onclick: closeModal });
  const go = el("button", { type: "button", class: "danger", text: "Unpair" });
  const force = el("button", { type: "button", class: "danger", text: "Remove locally only", hidden: true });
  const run = async (forced) => {
    go.disabled = true;
    force.disabled = true;
    cancel.disabled = true;
    msg.textContent = "";
    status.textContent = forced ? "Removing local state..." : "Sending RemoveFabric to the device...";
    const r = await api("DELETE", `/api/nodes/${nodeId}` + (forced ? "?force=1" : ""));
    go.disabled = false;
    force.disabled = false;
    cancel.disabled = false;
    status.textContent = "";
    if (!r.ok) {
      msg.textContent = errText(r);
      force.hidden = false;
      return;
    }
    removeNodeLocal(nodeId);
    closeModal();
  };
  go.onclick = () => run(false);
  force.onclick = () => run(true);
  openModal("Unpair node", el("div", {},
    el("p", { class: "modal-body-text" },
      "Remove ", el("b", { text: nodeTitle(n) }), ` (node ${nodeId}, ${hex(nodeId)}) from this fabric? `,
      "This sends RemoveFabric to the device and deletes it from the address book (nodes.tlv) and smweb.json."),
    el("p", { class: "muted small", text: "If the device is unreachable, the request fails; you can then remove it locally only (the device keeps its fabric entry)." }),
    status, msg,
    el("div", { class: "modal-actions" }, cancel, force, go),
  ));
}

function removeNodeLocal(nodeId) {
  nodes.delete(nodeId);
  values.delete(nodeId);
  expanded.delete(nodeId);
  renderDashboard();
  renderDevices();
}

// ---------------------------------------------------------------------------
// Share: commissioning window + manual code + QR
// ---------------------------------------------------------------------------

/** Active share panel: { nodeId, timer, window } */
let share = null;

function fmtManual(code) {
  const c = String(code || "");
  return c.length === 11 ? `${c.slice(0, 4)}-${c.slice(4, 7)}-${c.slice(7)}` : c;
}

function qrSvg(text) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  if (typeof qrcode !== "function") {
    svg.setAttribute("viewBox", "0 0 10 10");
    return svg;
  }
  const q = qrcode(0, "M");
  // Matter QR payloads use the base38 alphabet (0-9 A-Z - .) plus "MT:", all in the
  // QR alphanumeric set.
  q.addData(text, /^[0-9A-Z $%*+\-./:]*$/.test(text) ? "Alphanumeric" : "Byte");
  q.make();
  const n = q.getModuleCount();
  const m = 4; // quiet zone
  svg.setAttribute("viewBox", `0 0 ${n + 2 * m} ${n + 2 * m}`);
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `QR code: ${text}`);
  const bg = document.createElementNS(NS, "rect");
  bg.setAttribute("width", String(n + 2 * m));
  bg.setAttribute("height", String(n + 2 * m));
  bg.setAttribute("fill", "#fff");
  svg.appendChild(bg);
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c)) d += `M${c + m} ${r + m}h1v1h-1z`;
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", "#000");
  svg.appendChild(path);
  return svg;
}

function openShare(nodeId) {
  const n = nodes.get(nodeId);
  if (!n) return;
  const body = el("div", { class: "share" });
  share = { nodeId, timer: null, body };
  openModal(`Share ${nodeTitle(n)} (node ${nodeId})`, body, () => {
    if (share && share.timer) clearInterval(share.timer);
    share = null;
  });
  renderShareIdle("Checking the current window state...");
  refreshShareStatus();
}

async function refreshShareStatus() {
  if (!share) return;
  const id = share.nodeId;
  const r = await api("GET", `/api/nodes/${id}/window`);
  if (!share || share.nodeId !== id) return;
  if (!r.ok) {
    renderShareIdle(`Could not read the window state: ${errText(r)}`, true);
    return;
  }
  if (r.data.open && r.data.window) renderShareOpen(r.data.window);
  else if (r.data.open) renderShareForeign(r.data);
  else renderShareIdle("No commissioning window is open.");
}

function renderShareIdle(note, isErr = false) {
  if (!share) return;
  if (share.timer) clearInterval(share.timer);
  share.timer = null;
  const b = share.body;
  b.textContent = "";
  const sel = el("select", {},
    ...[[180, "3 minutes"], [300, "5 minutes"], [600, "10 minutes"], [900, "15 minutes"]].map(([v, t]) => el("option", { value: String(v), text: t, selected: v === 300 })));
  const msg = el("div", { class: "err small" });
  const open = el("button", { type: "button", text: "Open window" });
  open.onclick = async () => {
    open.disabled = true;
    msg.textContent = "";
    const id = share.nodeId;
    const r = await api("POST", `/api/nodes/${id}/window`, { timeout_s: Number(sel.value) });
    open.disabled = false;
    if (!share || share.nodeId !== id) return;
    if (!r.ok) {
      msg.textContent = errText(r);
      return;
    }
    renderShareOpen(r.data);
  };
  b.append(
    el("p", { class: isErr ? "err small" : "muted small", text: note }),
    el("p", { class: "modal-body-text", text: "Open an enhanced commissioning window (random passcode) so a second controller (phone app, Tab5, chip-tool, another smweb) can add this device to its fabric." }),
    el("label", { class: "inline" }, "Window timeout", sel),
    msg,
    el("div", { class: "modal-actions" }, el("button", { type: "button", class: "secondary", text: "Close", onclick: closeModal }), open),
  );
}

function renderShareForeign(st) {
  if (!share) return;
  const b = share.body;
  b.textContent = "";
  const msg = el("div", { class: "err small" });
  const revoke = el("button", { type: "button", class: "danger", text: "Revoke" });
  revoke.onclick = () => doRevoke(revoke, msg);
  b.append(
    el("p", { class: "modal-body-text", text: `A commissioning window is open (${st.window_status_name}, opened by fabric index ${st.admin_fabric_index ?? "?"}), but its code was not issued by this smweb.` }),
    msg,
    el("div", { class: "modal-actions" }, el("button", { type: "button", class: "secondary", text: "Refresh", onclick: refreshShareStatus }), revoke),
  );
}

async function doRevoke(btn, msg) {
  if (!share) return;
  const id = share.nodeId;
  btn.disabled = true;
  const r = await api("DELETE", `/api/nodes/${id}/window`);
  btn.disabled = false;
  if (!share || share.nodeId !== id) return;
  if (!r.ok) {
    msg.textContent = errText(r);
    return;
  }
  renderShareIdle("Window revoked.");
}

function renderShareOpen(w) {
  if (!share) return;
  if (share.timer) clearInterval(share.timer);
  const b = share.body;
  b.textContent = "";
  const countdown = el("div", { class: "share-countdown" });
  const tick = () => {
    const left = Math.max(0, Math.round(w.expires_at - Date.now() / 1000));
    if (left > 0) {
      countdown.textContent = `Window open: ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} remaining`;
      countdown.classList.remove("expired");
    } else {
      countdown.textContent = "Window expired.";
      countdown.classList.add("expired");
      clearInterval(share.timer);
      share.timer = null;
    }
  };
  const msg = el("div", { class: "err small" });
  const revoke = el("button", { type: "button", class: "danger", text: "Revoke" });
  revoke.onclick = () => doRevoke(revoke, msg);
  const pass = w.passcode_str || String(w.passcode).padStart(8, "0");
  b.append(
    el("div", { class: "muted small", text: "Manual pairing code" }),
    el("div", { class: "share-code", text: fmtManual(w.manual_code) }),
    w.qr_payload ? el("div", { class: "share-qr" }, qrSvg(w.qr_payload)) : "",
    w.qr_payload ? el("div", { class: "share-payload mono small", text: w.qr_payload }) : "",
    countdown,
    el("div", { class: "kv", style: "margin-top:10px" },
      el("span", { class: "muted", text: "Discriminator" }), el("span", { class: "mono", text: String(w.discriminator) }),
      el("span", { class: "muted", text: "Passcode" }), el("span", { class: "mono", text: pass }),
      el("span", { class: "muted", text: "VID / PID" }), el("span", { class: "mono", text: `${hex(w.vendor_id)} / ${hex(w.product_id)}` }),
      el("span", { class: "muted", text: "Expires" }), el("span", { text: new Date(w.expires_at * 1000).toLocaleTimeString() }),
    ),
    msg,
    el("div", { class: "modal-actions" },
      el("button", { type: "button", class: "secondary", text: "Refresh state", onclick: refreshShareStatus }),
      el("button", { type: "button", class: "secondary", text: "Close", onclick: closeModal }),
      revoke),
  );
  tick();
  share.timer = setInterval(tick, 1000);
}

// ---------------------------------------------------------------------------
// Pair: setup-code preview (client-side decode; the server re-validates)
// ---------------------------------------------------------------------------

const B38 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

function passcodeValid(p) {
  const bad = [0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999, 12345678, 87654321];
  return Number.isInteger(p) && p >= 1 && p <= 99999998 && !bad.includes(p);
}

function decodeQr(t) {
  const body = t.slice(3).split("*")[0].toUpperCase();
  const bytes = [];
  for (let i = 0; i < body.length;) {
    const rem = body.length - i;
    const [chars, nb] = rem >= 5 ? [5, 3] : rem === 4 ? [4, 2] : rem === 2 ? [2, 1] : [0, 0];
    if (!chars) throw new Error("invalid QR payload length");
    let v = 0;
    for (let k = chars - 1; k >= 0; k--) {
      const d = B38.indexOf(body[i + k]);
      if (d < 0) throw new Error(`invalid character ${JSON.stringify(body[i + k])}`);
      v = v * 38 + d;
    }
    if (v >= 2 ** (8 * nb)) throw new Error("invalid base38 chunk");
    for (let k = 0; k < nb; k++) bytes.push(Math.floor(v / 2 ** (8 * k)) % 256);
    i += chars;
  }
  if (bytes.length < 11) throw new Error("QR payload too short");
  const bits = (off, w) => {
    let v = 0;
    for (let i = 0; i < w; i++) if ((bytes[(off + i) >> 3] >> ((off + i) & 7)) & 1) v += 2 ** i;
    return v;
  };
  if (bits(0, 3) !== 0) throw new Error("unsupported QR version");
  const r = { source: "QR", vid: bits(3, 16), pid: bits(19, 16), caps: bits(37, 8), disc: bits(45, 12), passcode: bits(57, 27) };
  if (!passcodeValid(r.passcode)) throw new Error("invalid passcode in QR payload");
  return r;
}

function verhoeffOk(ds) {
  const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  let c = 0;
  [...ds].reverse().forEach((d, i) => { c = D[c][P[i % 8][d]]; });
  return c === 0;
}

function decodeManual(t) {
  if (/[^0-9\s-]/.test(t)) throw new Error("expected MT:... or an 11/21-digit manual code");
  const ds = t.replace(/[\s-]/g, "").split("").map(Number);
  if (ds.length !== 11 && ds.length !== 21) throw new Error(`manual code must have 11 or 21 digits (got ${ds.length})`);
  if (!verhoeffOk(ds)) throw new Error("check digit mismatch (typo?)");
  const num = (a, b) => Number(ds.slice(a, b).join(""));
  const d1 = ds[0];
  if (d1 > 7) throw new Error("invalid leading digit");
  const c2 = num(1, 6);
  const c3 = num(6, 10);
  const short = ((d1 & 3) << 2) | ((c2 >> 14) & 3);
  const passcode = c3 * 16384 + (c2 & 0x3fff);
  if (!passcodeValid(passcode)) throw new Error("invalid passcode in manual code");
  const r = { source: "manual code", short, passcode };
  if ((d1 >> 2) & 1) {
    r.vid = num(10, 15);
    r.pid = num(15, 20);
  }
  return r;
}

function decodeSetupCode(s) {
  const t = s.trim();
  if (!t) return null;
  return /^mt:/i.test(t) ? decodeQr(t) : decodeManual(t);
}

function updateCodePreview() {
  const f = $("#pair-form");
  const p = $("#code-preview");
  p.classList.remove("ok", "bad");
  const v = f.code.value;
  f.discriminator.disabled = f.passcode.disabled = !!v.trim();
  if (!v.trim()) {
    p.textContent = "Paste a QR payload / manual code, or give discriminator + passcode below.";
    return;
  }
  try {
    const r = decodeSetupCode(v);
    const parts = [`${r.source}:`];
    parts.push(r.disc !== undefined ? `discriminator ${r.disc}` : `short discriminator ${r.short} (discriminators ${r.short * 256}..${r.short * 256 + 255})`);
    parts.push(`passcode ${String(r.passcode).padStart(8, "0")}`);
    if (r.vid !== undefined) parts.push(`VID/PID ${hex(r.vid)}/${hex(r.pid)}`);
    if (r.caps !== undefined) {
      const caps = [];
      if (r.caps & 1) caps.push("SoftAP");
      if (r.caps & 2) caps.push("BLE");
      if (r.caps & 4) caps.push("on-network");
      parts.push(`discovery: ${caps.join("+") || "none"}`);
    }
    p.textContent = parts.join("  ");
    p.classList.add("ok");
  } catch (e) {
    p.textContent = `Invalid code: ${e.message}`;
    p.classList.add("bad");
  }
}

function pairMethod() {
  const f = $("#pair-form");
  const m = f.querySelector('input[name="method"]:checked');
  return m ? m.value : "onnetwork";
}

function updatePairMethod() {
  const m = pairMethod();
  for (const e of document.querySelectorAll("#pair-form [data-show]")) e.hidden = !e.dataset.show.split(" ").includes(m);
}

function updateBleAvailability() {
  const ble = !!(info && info.features && info.features.includes("ble"));
  for (const l of document.querySelectorAll("#pair-form .ble-only")) {
    const input = l.querySelector("input");
    input.disabled = !ble;
    l.classList.toggle("disabled", !ble);
    l.title = ble ? "" : "BLE not compiled in (build smweb with --features ble)";
    if (!ble && input.checked) {
      $('#pair-form input[value="onnetwork"]').checked = true;
      updatePairMethod();
    }
  }
  $("#ble-note").hidden = ble;
}

$("#pair-form").code.addEventListener("input", updateCodePreview);
for (const r of document.querySelectorAll('#pair-form input[name="method"]')) r.addEventListener("change", updatePairMethod);

$("#pair-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const m = pairMethod();
  const body = { method: m };
  const opt = (k, v) => { if (v !== undefined && String(v).trim() !== "") body[k] = String(v).trim(); };
  if (f.code.value.trim()) body.code = f.code.value.trim();
  else {
    opt("discriminator", f.discriminator.value);
    opt("passcode", f.passcode.value);
  }
  if (m === "address") {
    opt("ip", f.ip.value);
    opt("port", f.port.value);
  }
  if (m === "ble-wifi") {
    body.ssid = f.ssid.value;
    body.password = f.password.value;
  }
  if (m === "ble-thread") opt("dataset", f.dataset.value);
  opt("node_id", f.node_id.value);
  opt("label", f.label.value);
  const err = $("#pair-error");
  err.hidden = true;
  const btn = $("#pair-start");
  btn.disabled = true;
  const r = await api("POST", "/api/pairing", body);
  btn.disabled = false;
  if (!r.ok) {
    err.textContent = errText(r);
    err.hidden = false;
    return;
  }
  opBlock(r.data.op_id, `${m}${r.data.node_id ? ` -> node ${r.data.node_id}` : ""}${body.label ? ` "${body.label}"` : ""}`);
});

$("#discover-btn").addEventListener("click", async () => {
  const btn = $("#discover-btn");
  const out = $("#discover-result");
  btn.disabled = true;
  out.textContent = "Scanning _matterc._udp (5 s)...";
  const r = await api("GET", "/api/discover/commissionable?timeout=5");
  btn.disabled = false;
  out.textContent = "";
  if (!r.ok) {
    out.appendChild(el("span", { class: "err", text: errText(r) }));
    return;
  }
  if (!r.data.nodes.length) {
    out.appendChild(el("span", { class: "muted", text: "No commissionable device found (is a window open / the device in pairing mode?)." }));
    return;
  }
  for (const c of r.data.nodes) {
    const use = el("button", { type: "button", class: "small", text: "Use", onclick: () => {
      const f = $("#pair-form");
      f.code.value = "";
      updateCodePreview();
      if (c.discriminator !== null && c.discriminator !== undefined) f.discriminator.value = String(c.discriminator);
      if (pairMethod() === "address" && c.addrs.length) {
        const a = c.addrs[0];
        const i = a.lastIndexOf(":");
        f.ip.value = a.slice(0, i).replace(/^\[|\]$/g, "");
        f.port.value = a.slice(i + 1);
      }
      f.passcode.focus();
    } });
    out.appendChild(el("div", { class: "disc-item" },
      el("span", { class: "mono", text: `D=${c.discriminator ?? "?"}` }),
      c.vendor_id !== null && c.vendor_id !== undefined ? el("span", { class: "mono small", text: `${hex(c.vendor_id)}/${hex(c.product_id)}` }) : "",
      el("span", { class: "small", text: `CM=${c.commissioning_mode ?? "?"}` }),
      el("span", { class: "mono small muted", text: c.addrs.join(", ") }),
      el("span", { class: "muted small", text: c.instance }),
      use));
  }
});

// ---------------------------------------------------------------------------
// Pair: live progress (WS `progress` events keyed by op_id)
// ---------------------------------------------------------------------------

/** op_id -> { box, lines, badge, done } */
const ops = new Map();
const LOG_TAGS_IN_OPS = new Set(["ctl", "dis", "ble", "btp"]);

function opBlock(opId, title) {
  let o = ops.get(opId);
  if (o) {
    if (title) o.title.textContent = `#${opId} ${title}`;
    return o;
  }
  const holder = $("#pair-ops");
  if (!ops.size) holder.textContent = "";
  const badge = el("span", { class: "badge running", text: "running" });
  const titleEl = el("span", { class: "mono", text: `#${opId} ${title || "pairing"}` });
  const lines = el("div", { class: "op-lines" });
  const box = el("div", { class: "op" }, el("div", { class: "op-head" }, titleEl, badge), lines);
  holder.prepend(box);
  o = { box, lines, badge, title: titleEl, done: false };
  ops.set(opId, o);
  return o;
}

function opLine(o, cls, time, phase, detail) {
  const atBottom = o.lines.scrollTop + o.lines.clientHeight >= o.lines.scrollHeight - 4;
  o.lines.appendChild(el("div", { class: `op-line ${cls}` }, el("span", { class: "muted", text: time }), el("span", { text: phase }), el("span", { text: detail })));
  if (atBottom) o.lines.scrollTop = o.lines.scrollHeight;
}

function onProgress(ev) {
  const o = opBlock(ev.op_id);
  const t = new Date(ev.ts || Date.now()).toLocaleTimeString();
  opLine(o, ev.phase, t, ev.phase, ev.detail);
  if (ev.phase === "done") {
    o.done = true;
    o.badge.className = "badge ok";
    o.badge.textContent = ev.result && ev.result.warning ? "commissioned (offline)" : "done";
    if (ev.node_id) {
      o.box.querySelector(".op-head").appendChild(el("button", { type: "button", class: "small secondary", text: "Show on Dashboard", onclick: () => showTab("dashboard") }));
    }
  } else if (ev.phase === "failed") {
    o.done = true;
    o.badge.className = "badge failed";
    o.badge.textContent = "failed";
  }
  appendLog(`${t} [pair] #${ev.op_id} ${ev.phase}: ${ev.detail}`);
}

/** Forward commissioning-related log lines to the running op (single active op only). */
function logToOps(ev) {
  if (!LOG_TAGS_IN_OPS.has(ev.tag)) return;
  const active = [...ops.values()].filter((o) => !o.done);
  if (active.length !== 1) return;
  opLine(active[0], "log", new Date(ev.ts).toLocaleTimeString(), `[${ev.tag}]`, ev.msg);
}

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
  updateBleAvailability();
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
      for (const ch of [...charts.values()]) {
        if (nodes.has(ch.nodeId)) loadChart(ch); // refill what was missed while disconnected
        else closeChart(ch.key);
      }
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
      chartsOnAttr(ev);
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
    case "progress":
      onProgress(ev);
      break;
    case "node_added": {
      setNode(ev.node);
      renderDashboard();
      renderDevices();
      appendLog(`${t} [node] ${ev.node.node_id}: added (${ev.node.label || "no label"})`);
      break;
    }
    case "node_removed":
      closeNodeCharts(ev.node_id);
      if (nodes.has(ev.node_id)) removeNodeLocal(ev.node_id);
      if (share && share.nodeId === ev.node_id) closeModal();
      appendLog(`${t} [node] ${ev.node_id}: removed`);
      break;
    case "node_label": {
      const n = nodes.get(ev.node_id);
      if (!n) break;
      n.label = ev.label;
      renderDevices();
      scheduleDashboard();
      break;
    }
    case "window":
      if (share && share.nodeId === ev.node_id) {
        if (ev.open && ev.window) renderShareOpen(ev.window);
        else if (!ev.open) renderShareIdle("No commissioning window is open.");
      }
      appendLog(`${t} [share] ${ev.node_id}: window ${ev.open ? "opened" : "closed"}`);
      break;
    case "log":
      logToOps(ev);
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
for (const a of document.querySelectorAll("a[data-goto]")) a.addEventListener("click", (ev) => { ev.preventDefault(); showTab(a.dataset.goto); });

(async () => {
  let saved = null;
  try {
    saved = localStorage.getItem("smweb.tab");
  } catch (_) { /* storage unavailable */ }
  showTab(["dashboard", "devices", "pair", "log"].includes(saved) ? saved : "dashboard");
  updatePairMethod();
  updateCodePreview();
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
