// smweb history chart (W5): dependency-free SVG line chart.
// Pure functions only (no DOM access) so the geometry can be exercised from node:
//   const C = require("./chart.js"); C.chartSvg(points, opts)
// In the browser this defines the global `SmChart`.
"use strict";

(function (root) {
  /** Attribute kinds that are kept in the history (server: history.rs is_numeric_kind). */
  const NUMERIC_KINDS = new Set(["bool", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64"]);

  /** JSON attribute value -> number for the chart (bool -> 0/1), else null. */
  function numericOf(v) {
    if (typeof v === "boolean") return v ? 1 : 0;
    if (typeof v === "number" && Number.isFinite(v)) return v;
    return null;
  }

  /** 1/2/5 x 10^n step so that `span` has about `target` intervals. */
  function niceStep(span, target) {
    if (!(span > 0)) return 1;
    const raw = span / Math.max(1, target);
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const f = raw / mag;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * mag;
  }

  /** Tick values inside [min, max]. */
  function niceTicks(min, max, target = 4, integer = false) {
    let step = niceStep(max - min, target);
    if (integer) step = Math.max(1, Math.round(step));
    const out = [];
    const first = Math.ceil(min / step - 1e-9) * step;
    for (let v = first; v <= max + step * 1e-9 && out.length < 50; v += step) {
      out.push(Math.abs(v) < step * 1e-9 ? 0 : Number(v.toPrecision(12)));
    }
    return out;
  }

  const MIN = 60e3;
  const HOUR = 3600e3;
  const DAY = 86400e3;
  const TIME_STEPS = [MIN, 2 * MIN, 5 * MIN, 10 * MIN, 15 * MIN, 30 * MIN, HOUR, 2 * HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY, 14 * DAY, 30 * DAY];

  /** Time ticks (ms) in [t0, t1], aligned to local wall-clock steps. */
  function timeTicks(t0, t1, target = 6, tzOffsetMin = new Date(t0).getTimezoneOffset()) {
    const span = t1 - t0;
    if (!(span > 0)) return { step: MIN, ticks: [] };
    const step = TIME_STEPS.find((s) => span / s <= target) || TIME_STEPS[TIME_STEPS.length - 1];
    const off = -tzOffsetMin * MIN; // local = utc + off
    const out = [];
    let t = Math.ceil((t0 + off) / step) * step - off;
    for (; t <= t1 && out.length < 50; t += step) out.push(t);
    return { step, ticks: out };
  }

  function pad2(n) {
    return String(n).padStart(2, "0");
  }

  /** Axis label for a time tick (date when the step is >= 1 day or at local midnight). */
  function fmtTime(t, step) {
    const d = new Date(t);
    const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    const md = `${d.getMonth() + 1}/${d.getDate()}`;
    if (step >= DAY) return md;
    if (d.getHours() === 0 && d.getMinutes() === 0) return md;
    return hm;
  }

  function fmtNum(v, digits) {
    if (!Number.isFinite(v)) return String(v);
    if (digits !== undefined) return v.toFixed(digits);
    if (Number.isInteger(v)) return String(v);
    const a = Math.abs(v);
    return v.toFixed(a >= 100 ? 0 : a >= 10 ? 1 : 2);
  }

  /** Display string for a raw (unscaled) value with the series meta. */
  function fmtValue(raw, meta) {
    if (meta.kind === "bool") return raw ? "on" : "off";
    if (meta.enum) {
      const n = meta.enum[Math.round(raw)];
      return n !== undefined ? n : String(raw);
    }
    const v = raw * (meta.scale || 1);
    return fmtNum(v, meta.scale ? 2 : undefined) + (meta.unit ? " " + meta.unit : "");
  }

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  }

  /** Points of `pts` ([[ts, raw], ...], ts ascending) with ts in [t0, t1], plus the last point before t0. */
  function visible(pts, t0, t1) {
    let lo = 0;
    let hi = pts.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (pts[mid][0] < t0) lo = mid + 1;
      else hi = mid;
    }
    const start = Math.max(0, lo - 1);
    const out = [];
    for (let i = start; i < pts.length && pts[i][0] <= t1; i++) out.push(pts[i]);
    return { points: out, before: lo > 0 };
  }

  /** min / max / latest of the in-range raw values (`before` point excluded). */
  function stats(pts, t0, t1) {
    let min = Infinity;
    let max = -Infinity;
    let n = 0;
    for (const [t, v] of pts) {
      if (t < t0 || t > t1) continue;
      if (v < min) min = v;
      if (v > max) max = v;
      n++;
    }
    const latest = pts.length ? pts[pts.length - 1] : null;
    return n ? { min, max, count: n, latest } : { min: null, max: null, count: 0, latest };
  }

  /**
   * Build the chart.
   * points: [[ts_ms, raw], ...] ascending. opts:
   *   width, height, t0, t1 (ms), meta {kind, unit, scale, enum}, bands [[from, to, cls], ...]
   *   (in scaled units), live (extend the last value to t1 with a dashed segment).
   * Returns { svg, geom } where geom maps ts/value <-> px for the hover layer.
   */
  function chartSvg(points, opts) {
    const W = Math.max(160, Math.round(opts.width || 600));
    const H = Math.max(100, Math.round(opts.height || 180));
    const meta = opts.meta || {};
    const scale = meta.scale || 1;
    const discrete = meta.kind === "bool" || !!meta.enum;
    const R = 12;
    const T = 10;
    const B = 22;
    const ph = H - T - B;
    const t1 = opts.t1;
    const t0 = Math.min(opts.t0, t1 - 1);
    const vis = visible(points, t0, t1).points;
    const vals = vis.map((p) => p[1] * scale);

    // Y domain from the visible data (bands are clipped, they do not stretch the axis).
    let y0;
    let y1;
    if (meta.kind === "bool") {
      y0 = -0.15;
      y1 = 1.15;
    } else if (vals.length === 0) {
      y0 = 0;
      y1 = 1;
    } else {
      y0 = Math.min(...vals);
      y1 = Math.max(...vals);
      if (discrete) {
        y0 -= 0.5;
        y1 += 0.5;
      } else {
        const span = y1 - y0 || Math.max(Math.abs(y1) * 0.05, 1);
        y0 -= span * 0.08;
        y1 += span * 0.08;
      }
    }
    // Y ticks + labels first: the left margin fits the longest label (enum names).
    let yt;
    if (meta.kind === "bool") yt = [0, 1];
    else if (discrete && y1 - y0 <= 10) yt = niceTicks(y0, y1, Math.ceil(y1 - y0), true); // every level
    else yt = niceTicks(y0, y1, 4, discrete);
    const ylabels = yt.map((v) => (discrete ? fmtValue(v, meta) : fmtNum(v)));
    const L = Math.round(Math.min(120, Math.max(40, 12 + 6.6 * Math.max(0, ...ylabels.map((s) => s.length)))));
    const pw = W - L - R;
    const xOf = (t) => L + ((t - t0) / (t1 - t0)) * pw;
    const yOf = (v) => T + (1 - (v - y0) / (y1 - y0)) * ph;
    const clampY = (y) => Math.max(T, Math.min(T + ph, y));
    const f1 = (n) => n.toFixed(1);
    const parts = [];
    parts.push(`<svg xmlns="http://www.w3.org/2000/svg" class="chart-svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(opts.label || "history")}">`);
    parts.push(`<defs><clipPath id="${opts.clipId || "plot"}"><rect x="${L}" y="${T}" width="${pw}" height="${ph}"/></clipPath></defs>`);

    // Threshold bands (light background).
    for (const [from, to, cls] of opts.bands || []) {
      const ya = clampY(yOf(Math.min(to, y1)));
      const yb = clampY(yOf(Math.max(from, y0)));
      if (yb - ya <= 0.5) continue;
      parts.push(`<rect class="band ${esc(cls)}" x="${L}" y="${f1(ya)}" width="${pw}" height="${f1(yb - ya)}"/>`);
    }

    // Y grid + labels.
    for (let i = 0; i < yt.length; i++) {
      const y = yOf(yt[i]);
      if (y < T - 0.5 || y > T + ph + 0.5) continue;
      parts.push(`<line class="grid" x1="${L}" x2="${L + pw}" y1="${f1(y)}" y2="${f1(y)}"/>`);
      const label = ylabels[i];
      parts.push(`<text class="ylab" x="${L - 6}" y="${f1(y + 3.5)}" text-anchor="end">${esc(label)}</text>`);
    }

    // X ticks.
    const tt = timeTicks(t0, t1, Math.max(2, Math.floor(pw / 90)), opts.tzOffsetMin);
    for (const t of tt.ticks || []) {
      const x = xOf(t);
      parts.push(`<line class="tick" x1="${f1(x)}" x2="${f1(x)}" y1="${T + ph}" y2="${T + ph + 4}"/>`);
      parts.push(`<text class="xlab" x="${f1(x)}" y="${T + ph + 16}" text-anchor="middle">${esc(fmtTime(t, tt.step))}</text>`);
    }
    parts.push(`<line class="axis" x1="${L}" x2="${L + pw}" y1="${T + ph}" y2="${T + ph}"/>`);

    // Series.
    const geomPts = [];
    if (vis.length === 0) {
      parts.push(`<text class="empty" x="${L + pw / 2}" y="${T + ph / 2}" text-anchor="middle">no data in this range</text>`);
    } else {
      let d = "";
      let prevY = null;
      for (let i = 0; i < vis.length; i++) {
        const x = xOf(Math.max(vis[i][0], t0));
        const y = yOf(vals[i]);
        if (i === 0) d += `M${f1(x)} ${f1(y)}`;
        else if (discrete) d += `H${f1(x)}V${f1(y)}`;
        else d += `L${f1(x)} ${f1(y)}`;
        prevY = y;
        if (vis[i][0] >= t0) geomPts.push([vis[i][0], vis[i][1], x, y]);
      }
      parts.push(`<g clip-path="url(#${opts.clipId || "plot"})">`);
      parts.push(`<path class="line" d="${d}"/>`);
      const last = vis[vis.length - 1];
      if (opts.live && last[0] < t1) {
        parts.push(`<path class="line hold" d="M${f1(xOf(Math.max(last[0], t0)))} ${f1(prevY)}H${f1(L + pw)}"/>`);
      }
      if (geomPts.length <= 1 || geomPts.length * 12 < pw) {
        // Sparse data: show the samples themselves.
        for (const [, , x, y] of geomPts) parts.push(`<circle class="pt" cx="${f1(x)}" cy="${f1(y)}" r="2.5"/>`);
      }
      parts.push(`</g>`);
    }
    parts.push(`</svg>`);
    return {
      svg: parts.join(""),
      geom: { L, R, T, B, W, H, pw, ph, t0, t1, y0, y1, points: geomPts },
    };
  }

  /** Nearest sample to pixel x (geom from chartSvg), or null. */
  function nearest(geom, px) {
    const p = geom.points;
    if (!p.length) return null;
    let best = p[0];
    for (const q of p) if (Math.abs(q[2] - px) < Math.abs(best[2] - px)) best = q;
    return best;
  }

  const api = { NUMERIC_KINDS, numericOf, niceStep, niceTicks, timeTicks, fmtTime, fmtValue, visible, stats, chartSvg, nearest };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SmChart = api;
})(typeof window !== "undefined" ? window : globalThis);
