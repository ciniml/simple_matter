// Matter TLV ライタ + composition / binding blob エンコーダ。
//
// 正実装は `scripts/smgen-tlv.py`(docs/design/generic-firmware.md §9.1 / §9.2)。
// 本モジュールは同一バイト列を出す JS 移植で、`test/tlv.test.js` が
// smgen-tlv.py の examples 出力と hex 一致を検証する。

import { bytesToHex } from "./util.js";

// ---- TLV エレメント型(下位 5 ビット)---------------------------------------

export const T_I8 = 0x00;
export const T_I16 = 0x01;
export const T_I32 = 0x02;
export const T_I64 = 0x03;
export const T_U8 = 0x04;
export const T_U16 = 0x05;
export const T_U32 = 0x06;
export const T_U64 = 0x07;
export const T_BOOL_F = 0x08;
export const T_BOOL_T = 0x09;
export const T_NULL = 0x14;
export const T_STRUCT = 0x15;
export const T_ARRAY = 0x16;
export const T_LIST = 0x17;
export const T_END = 0x18;

const TAG_ANON = 0x00;
const TAG_CTX = 0x20;

const UINT_TYPE = { 1: T_U8, 2: T_U16, 4: T_U32, 8: T_U64 };
const INT_TYPE = { 1: T_I8, 2: T_I16, 4: T_I32, 8: T_I64 };

/** 必要最小限の Matter TLV ライタ(anonymous / 1 バイト context タグのみ)。 */
export class TlvWriter {
  constructor() {
    this.bytes = [];
  }

  _hdr(etype, tag) {
    if (tag === null || tag === undefined) {
      this.bytes.push(TAG_ANON | etype);
    } else {
      this.bytes.push(TAG_CTX | etype);
      this.bytes.push(tag & 0xff);
    }
  }

  _le(value, width) {
    let v = BigInt(value);
    if (v < 0n) {
      v += 1n << BigInt(width * 8);
    }
    for (let i = 0; i < width; i++) {
      this.bytes.push(Number((v >> BigInt(i * 8)) & 0xffn));
    }
  }

  /** 符号なし整数(width 未指定なら値に収まる最小幅)。 */
  uint(value, tag = null, width = null) {
    const v = BigInt(value);
    if (width === null) {
      width = v < 0x100n ? 1 : v < 0x10000n ? 2 : v < 0x100000000n ? 4 : 8;
    }
    this._hdr(UINT_TYPE[width], tag);
    this._le(v, width);
    return this;
  }

  /** 符号付き整数。 */
  int(value, tag = null, width = 2) {
    this._hdr(INT_TYPE[width], tag);
    this._le(value, width);
    return this;
  }

  bool(value, tag = null) {
    this._hdr(value ? T_BOOL_T : T_BOOL_F, tag);
    return this;
  }

  null_(tag = null) {
    this._hdr(T_NULL, tag);
    return this;
  }

  start(ctype, tag = null) {
    this._hdr(ctype, tag);
    return this;
  }

  end() {
    this.bytes.push(T_END);
    return this;
  }

  toBytes() {
    return Uint8Array.from(this.bytes);
  }

  toHex() {
    return bytesToHex(this.toBytes());
  }
}

/** `"0x0100"` / `256` のどちらでも整数にする(smgen-tlv.py の `_num`)。 */
export function num(x) {
  if (typeof x === "number") {
    return x;
  }
  if (typeof x === "bigint") {
    return Number(x);
  }
  const s = String(x).trim();
  const v = /^0[xX]/.test(s) ? parseInt(s, 16) : parseInt(s, 10);
  if (Number.isNaN(v)) {
    throw new Error(`not a number: ${JSON.stringify(x)}`);
  }
  return v;
}

const SCALAR_WIDTH = { i8: 1, i16: 2, i32: 4, i64: 8, u8: 1, u16: 2, u32: 4, u64: 8 };

function writeScalar(w, type, value, tag) {
  if (value === null || value === undefined) {
    w.null_(tag);
  } else if (type === "bool") {
    w.bool(Boolean(value), tag);
  } else if (type in SCALAR_WIDTH) {
    const width = SCALAR_WIDTH[type];
    if (type[0] === "i") {
      w.int(num(value), tag, width);
    } else {
      w.uint(num(value), tag, width);
    }
  } else {
    throw new Error(`unknown scalar type ${JSON.stringify(type)}`);
  }
}

// ---- composition(§9.1)------------------------------------------------------

/**
 * composition TLV を組み立てる。
 *
 * `spec` は `[{ ep, device_type, rev?, clusters: [...], options?: [{cluster, attr, type?, value}] }]`
 * (`scripts/smgen-tlv.py` の spec.json と同形式)。
 */
export function encodeComposition(spec) {
  const w = new TlvWriter();
  w.start(T_LIST);
  for (const ep of spec) {
    w.start(T_STRUCT);
    w.uint(num(ep.ep), 0, 2); // 0: endpoint-id u16
    w.uint(num(ep.device_type), 1, 4); // 1: device-type u32
    w.uint(num(ep.rev ?? 1), 2, 1); // 2: device-type-rev u8
    w.start(T_ARRAY, 3); // 3: cluster list
    for (const cl of ep.clusters) {
      w.uint(num(cl), null, 4);
    }
    w.end();
    const opts = ep.options || [];
    if (opts.length > 0) {
      w.start(T_ARRAY, 4); // 4: options
      for (const o of opts) {
        w.start(T_STRUCT);
        w.uint(num(o.cluster), 0, 4);
        w.uint(num(o.attr), 1, 4);
        writeScalar(w, o.type ?? "u16", o.value, 2);
        w.end();
      }
      w.end();
    }
    w.end();
  }
  w.end();
  return w.toBytes();
}

// ---- binding(§9.2)---------------------------------------------------------

/** ドライバ ID(binding TLV の context tag 2)。`scripts/smgen-tlv.py` の DRIVERS と同一。 */
export const DRIVERS = {
  gpio_out: 1,
  gpio_in: 2,
  ledc: 3,
  i2c_sht30: 4,
  script: 5,
};

export const DRIVER_NAMES = Object.fromEntries(
  Object.entries(DRIVERS).map(([k, v]) => [v, k])
);

/**
 * ドライバ固有 params の context tag 割り当て(`main/bind_tlv.hpp` と同一)。
 * `name -> { tag, width, kind }`(kind: `"u"` = 符号なし / `"b"` = bool)。
 */
export const PARAMS = {
  1: {
    // gpio_out
    pin: { tag: 0, width: 1, kind: "u" },
    invert: { tag: 1, width: 0, kind: "b" },
  },
  2: {
    // gpio_in
    pin: { tag: 0, width: 1, kind: "u" },
    invert: { tag: 1, width: 0, kind: "b" },
    poll_ms: { tag: 2, width: 2, kind: "u" },
    pull: { tag: 3, width: 1, kind: "u" }, // 0=none 1=up(既定) 2=down
  },
  3: {
    // ledc
    ch: { tag: 0, width: 1, kind: "u" },
    pin: { tag: 1, width: 1, kind: "u" },
    freq: { tag: 2, width: 4, kind: "u" },
    invert: { tag: 3, width: 0, kind: "b" },
  },
  4: {
    // i2c_sht30
    sda: { tag: 0, width: 1, kind: "u" },
    scl: { tag: 1, width: 1, kind: "u" },
    poll_ms: { tag: 2, width: 2, kind: "u" },
    port: { tag: 3, width: 1, kind: "u" },
  },
  5: {
    // script(Phase C の WASM フックへ委譲)
    poll_ms: { tag: 0, width: 4, kind: "u" },
  },
};

/**
 * binding TLV を組み立てる。
 *
 * `spec` は `[{ ep, cluster, drv, params: {...} }]`。`drv` はドライバ名か ID。
 * params の**列挙順**がそのままバイト列の順になる(smgen-tlv.py の dict 順と同じ)。
 */
export function encodeBindings(spec) {
  const w = new TlvWriter();
  w.start(T_LIST);
  for (const b of spec) {
    const drvId = typeof b.drv === "string" ? DRIVERS[b.drv] : num(b.drv);
    if (!drvId) {
      throw new Error(`unknown driver ${JSON.stringify(b.drv)}`);
    }
    w.start(T_STRUCT);
    w.uint(num(b.ep), 0, 2); // 0: endpoint u16
    w.uint(num(b.cluster), 1, 4); // 1: cluster u32
    w.uint(drvId, 2, 1); // 2: drv-id u8
    w.start(T_STRUCT, 3); // 3: params
    const known = PARAMS[drvId];
    for (const [name, value] of Object.entries(b.params || {})) {
      const p = known[name];
      if (!p) {
        throw new Error(`driver ${DRIVER_NAMES[drvId]} has no param ${JSON.stringify(name)}`);
      }
      if (p.kind === "b") {
        w.bool(Boolean(value), p.tag);
      } else {
        w.uint(num(value), p.tag, p.width);
      }
    }
    w.end();
    w.end();
  }
  w.end();
  return w.toBytes();
}
