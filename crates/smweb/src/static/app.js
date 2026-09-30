// smweb W1 UI: node list + connect, raw attribute read, command invoke, live log.
// Plain ES2020, no build step, no external dependencies.
"use strict";

const $ = (sel) => document.querySelector(sel);
const hex = (n) => "0x" + BigInt(n).toString(16).padStart(4, "0");
const nodes = new Map(); // node_id -> snapshot entry
let clusters = [];

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data;
  try {
    data = await res.json();
  } catch (_) {
    data = { error: { code: "bad_response", message: `HTTP ${res.status}` } };
  }
  return { ok: res.ok, status: res.status, data };
}

function showResult(title, r) {
  const el = $("#result");
  el.classList.remove("muted");
  el.classList.toggle("error", !r.ok);
  el.textContent = `${title} -> HTTP ${r.status}\n` + JSON.stringify(r.data, null, 2);
}

function fmtAgo(ts) {
  if (!ts) return "-";
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function renderNodes() {
  const tbody = $("#nodes tbody");
  tbody.textContent = "";
  if (nodes.size === 0) {
    const tr = tbody.insertRow();
    const td = tr.insertCell();
    td.colSpan = 6;
    td.className = "muted";
    td.textContent = "no paired nodes (commission with smctl first)";
  }
  for (const n of [...nodes.values()].sort((a, b) => a.node_id - b.node_id)) {
    const tr = tbody.insertRow();
    const id = tr.insertCell();
    id.className = "mono";
    id.textContent = `${n.node_id} (${hex(n.node_id)})`;
    tr.insertCell().textContent = n.label || "";
    const addr = tr.insertCell();
    addr.className = "mono";
    addr.textContent = n.addr || "(unresolved)";
    const st = tr.insertCell();
    const badge = document.createElement("span");
    badge.className = `badge ${n.state}`;
    badge.textContent = n.state;
    st.appendChild(badge);
    tr.insertCell().textContent = fmtAgo(n.last_seen);
    const act = tr.insertCell();
    const btn = document.createElement("button");
    btn.textContent = "Connect";
    btn.onclick = async () => {
      btn.disabled = true;
      btn.textContent = "Connecting...";
      const r = await api("POST", `/api/nodes/${n.node_id}/connect`);
      showResult(`connect ${n.node_id}`, r);
      btn.disabled = false;
      btn.textContent = "Connect";
      await loadNodes();
    };
    act.appendChild(btn);
  }
  for (const sel of document.querySelectorAll(".node-select")) {
    const prev = sel.value;
    sel.textContent = "";
    for (const n of nodes.values()) {
      const o = document.createElement("option");
      o.value = String(n.node_id);
      o.textContent = `${n.node_id}${n.label ? " - " + n.label : ""}`;
      sel.appendChild(o);
    }
    if (prev) sel.value = prev;
  }
}

async function loadNodes() {
  const r = await api("GET", "/api/nodes");
  if (!r.ok) return;
  nodes.clear();
  for (const n of r.data) nodes.set(n.node_id, n);
  renderNodes();
}

function renderInfo(info) {
  const parts = [`v${info.version}`, `state: ${info.state_dir}`];
  if (info.fabric_id) parts.push(`fabric ${info.fabric_id}`);
  if (info.controller_node_id) parts.push(`controller ${info.controller_node_id}`);
  if (info.features && info.features.length) parts.push(`features: ${info.features.join(",")}`);
  if (info.error) parts.push(`ERROR: ${info.error}`);
  $("#info").textContent = parts.join(" | ");
}

function findCluster(v) {
  const s = v.trim();
  return clusters.find((c) => c.name === s || String(c.id) === s || hex(c.id) === s.toLowerCase());
}

function fillList(id, items) {
  const dl = document.getElementById(id);
  dl.textContent = "";
  for (const it of items) {
    const o = document.createElement("option");
    o.value = it.name;
    o.label = `${hex(it.id)}${it.kind ? " " + it.kind : ""}`;
    dl.appendChild(o);
  }
}

function updateAttrList() {
  const c = findCluster($("#read-form").cluster.value);
  fillList("attr-list", c ? c.attributes : []);
}

function updateCmdList() {
  const c = findCluster($("#invoke-form").cluster.value);
  fillList("cmd-list", c ? c.commands : []);
}

async function loadClusters() {
  const r = await api("GET", "/api/clusters");
  if (!r.ok) return;
  clusters = r.data;
  fillList("cluster-list", clusters);
  updateAttrList();
  updateCmdList();
}

const seg = (s) => encodeURIComponent(s.trim());

$("#read-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const path =
    `/api/nodes/${seg(f.node.value)}/attr/${seg(f.ep.value)}/${seg(f.cluster.value)}/${seg(f.attr.value)}` +
    (f.raw.checked ? "?raw=1" : "");
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

function appendLog(line) {
  const el = $("#log");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  el.textContent += line + "\n";
  const lines = el.textContent.split("\n");
  if (lines.length > 500) el.textContent = lines.slice(-500).join("\n");
  if (atBottom) el.scrollTop = el.scrollHeight;
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
    switch (ev.type) {
      case "snapshot":
        renderInfo(ev.info);
        nodes.clear();
        for (const n of ev.nodes) nodes.set(n.node_id, n);
        renderNodes();
        break;
      case "node_state": {
        const n = nodes.get(ev.node_id);
        if (n) {
          n.state = ev.state;
          if (ev.addr) n.addr = ev.addr;
          if (ev.state === "online") n.last_seen = Math.floor(Date.now() / 1000);
          renderNodes();
        }
        break;
      }
      case "log": {
        const t = new Date(ev.ts).toLocaleTimeString();
        appendLog(`${t} [${ev.tag}] ${ev.level !== "info" ? ev.level + ": " : ""}${ev.msg}`);
        break;
      }
      case "lagged":
        appendLog(`(missed ${ev.missed} events)`);
        break;
      default:
        break;
    }
  };
}

(async () => {
  const info = await api("GET", "/api/info");
  if (info.ok) renderInfo(info.data);
  await Promise.all([loadNodes(), loadClusters()]);
  connectWs();
  setInterval(renderNodes, 10000); // refresh "last seen"
})();
