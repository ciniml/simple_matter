#!/usr/bin/env python3
"""generic_matter_cpp の設定 blob(Matter TLV)ジェネレータ/デコーダ。

`docs/design/generic-firmware.md` §9.1(composition)/ §9.2(binding)のスキーマを
そのまま素の Matter TLV にエンコードし、hex 文字列として出す。出力は
generic_matter_cpp のコンソール `cfg-comp <hex>` / `cfg-bind <hex>` にそのまま貼れる。

使い方:
    scripts/smgen-tlv.py comp   <spec.json>     # composition TLV hex
    scripts/smgen-tlv.py bind   <spec.json>     # binding TLV hex
    scripts/smgen-tlv.py decode-comp <hex>      # 逆変換(検算)
    scripts/smgen-tlv.py decode-bind <hex>
    scripts/smgen-tlv.py examples               # README 掲載の例を出力
    scripts/smgen-tlv.py selftest               # encode→decode ラウンドトリップ

spec.json(composition):
    [ { "ep": 1, "device_type": "0x0100", "rev": 2,
        "clusters": ["0x0003", "0x0004", "0x0006"],
        "options": [ {"cluster": "0x0402", "attr": 0, "type": "i16", "value": 2350} ] } ]

spec.json(binding):
    [ { "ep": 1, "cluster": "0x0006", "drv": "gpio_out",
        "params": {"pin": 7, "invert": false} } ]
"""

import json
import sys

# ---- Matter TLV エレメント型(下位 5 ビット) --------------------------------

T_I8, T_I16, T_I32, T_I64 = 0x00, 0x01, 0x02, 0x03
T_U8, T_U16, T_U32, T_U64 = 0x04, 0x05, 0x06, 0x07
T_BOOL_F, T_BOOL_T = 0x08, 0x09
T_NULL = 0x14
T_STRUCT, T_ARRAY, T_LIST, T_END = 0x15, 0x16, 0x17, 0x18

TAG_ANON = 0x00  # タグ制御 0
TAG_CTX = 0x20  # タグ制御 1(1 バイトの context tag が続く)


class TlvWriter:
    """必要最小限の Matter TLV ライタ(anonymous / context タグのみ)。"""

    def __init__(self):
        self.b = bytearray()

    def _hdr(self, etype, tag):
        if tag is None:
            self.b.append(TAG_ANON | etype)
        else:
            self.b.append(TAG_CTX | etype)
            self.b.append(tag & 0xFF)

    def uint(self, value, tag=None, width=None):
        """符号なし整数(width 未指定なら値に合う最小幅)。"""
        if width is None:
            width = 1 if value < 0x100 else 2 if value < 0x10000 else 4 if value < 0x100000000 else 8
        etype = {1: T_U8, 2: T_U16, 4: T_U32, 8: T_U64}[width]
        self._hdr(etype, tag)
        self.b += int(value).to_bytes(width, "little")

    def int_(self, value, tag=None, width=2):
        etype = {1: T_I8, 2: T_I16, 4: T_I32, 8: T_I64}[width]
        self._hdr(etype, tag)
        self.b += int(value).to_bytes(width, "little", signed=True)

    def bool_(self, value, tag=None):
        self._hdr(T_BOOL_T if value else T_BOOL_F, tag)

    def null(self, tag=None):
        self._hdr(T_NULL, tag)

    def start(self, ctype, tag=None):
        self._hdr(ctype, tag)

    def end(self):
        self.b.append(T_END)

    def hex(self):
        return self.b.hex()


class TlvReader:
    """必要最小限の Matter TLV リーダ(検算用)。"""

    def __init__(self, data):
        self.d = data
        self.i = 0

    def eof(self):
        return self.i >= len(self.d)

    def next(self):
        """(tag, kind, value) を返す。kind は 'int'/'bool'/'null'/'start'/'end'/'skip'。"""
        c = self.d[self.i]
        self.i += 1
        tagctrl, etype = c >> 5, c & 0x1F
        if tagctrl == 0:
            tag = None
        elif tagctrl == 1:
            tag = self.d[self.i]
            self.i += 1
        else:
            nbytes = {2: 2, 3: 4, 4: 2, 5: 4, 6: 6, 7: 8}[tagctrl]
            tag = int.from_bytes(self.d[self.i : self.i + nbytes], "little")
            self.i += nbytes
        if etype in (T_U8, T_U16, T_U32, T_U64, T_I8, T_I16, T_I32, T_I64):
            width = {T_U8: 1, T_U16: 2, T_U32: 4, T_U64: 8, T_I8: 1, T_I16: 2, T_I32: 4, T_I64: 8}[etype]
            signed = etype in (T_I8, T_I16, T_I32, T_I64)
            v = int.from_bytes(self.d[self.i : self.i + width], "little", signed=signed)
            self.i += width
            return (tag, "int", v)
        if etype in (T_BOOL_F, T_BOOL_T):
            return (tag, "bool", etype == T_BOOL_T)
        if etype == T_NULL:
            return (tag, "null", None)
        if etype in (T_STRUCT, T_ARRAY, T_LIST):
            return (tag, "start", etype)
        if etype == T_END:
            return (tag, "end", None)
        raise ValueError("unsupported TLV element type 0x%02x at %d" % (etype, self.i - 1))


# ---- composition(§9.1) -----------------------------------------------------


def _num(x):
    return int(x, 0) if isinstance(x, str) else int(x)


def encode_composition(spec):
    w = TlvWriter()
    w.start(T_LIST)  # anonymous list of endpoint structs
    for ep in spec:
        w.start(T_STRUCT)
        w.uint(_num(ep["ep"]), tag=0, width=2)  # 0: endpoint-id u16
        w.uint(_num(ep["device_type"]), tag=1, width=4)  # 1: device-type u32
        w.uint(_num(ep.get("rev", 1)), tag=2, width=1)  # 2: device-type-rev u8
        w.start(T_ARRAY, tag=3)  # 3: cluster list
        for cl in ep["clusters"]:
            w.uint(_num(cl), width=4)
        w.end()
        opts = ep.get("options") or []
        if opts:
            w.start(T_ARRAY, tag=4)  # 4: options
            for o in opts:
                w.start(T_STRUCT)
                w.uint(_num(o["cluster"]), tag=0, width=4)
                w.uint(_num(o["attr"]), tag=1, width=4)
                _write_scalar(w, o.get("type", "u16"), o["value"], tag=2)
                w.end()
            w.end()
        w.end()
    w.end()
    return w.hex()


def _write_scalar(w, ty, value, tag):
    if value is None:
        w.null(tag=tag)
    elif ty == "bool":
        w.bool_(bool(value), tag=tag)
    elif ty in ("i8", "i16", "i32", "i64"):
        w.int_(_num(value), tag=tag, width={"i8": 1, "i16": 2, "i32": 4, "i64": 8}[ty])
    elif ty in ("u8", "u16", "u32", "u64"):
        w.uint(_num(value), tag=tag, width={"u8": 1, "u16": 2, "u32": 4, "u64": 8}[ty])
    else:
        raise ValueError("unknown scalar type %r" % ty)


def decode_composition(blob):
    r = TlvReader(blob)
    tag, kind, val = r.next()
    out = []
    if kind != "start":
        raise ValueError("composition must start with a container")
    if val == T_STRUCT:
        out.append(_decode_ep(r))
        return out
    while not r.eof():
        tag, kind, val = r.next()
        if kind == "end":
            break
        if kind == "start" and val == T_STRUCT:
            out.append(_decode_ep(r))
    return out


def _decode_ep(r):
    ep = {"ep": 0, "device_type": 0, "rev": 1, "clusters": [], "options": []}
    while True:
        tag, kind, val = r.next()
        if kind == "end":
            break
        if tag == 0:
            ep["ep"] = val
        elif tag == 1:
            ep["device_type"] = val
        elif tag == 2:
            ep["rev"] = val
        elif tag == 3 and kind == "start":
            while True:
                _t, k, v = r.next()
                if k == "end":
                    break
                ep["clusters"].append(v)
        elif tag == 4 and kind == "start":
            while True:
                _t, k, v = r.next()
                if k == "end":
                    break
                if k == "start":
                    o = {}
                    while True:
                        t2, k2, v2 = r.next()
                        if k2 == "end":
                            break
                        o[{0: "cluster", 1: "attr", 2: "value"}.get(t2, t2)] = v2
                    ep["options"].append(o)
    return ep


# ---- binding(§9.2) ---------------------------------------------------------

# ドライバ ID(binding TLV の context tag 2)。
DRIVERS = {
    "gpio_out": 1,
    "gpio_in": 2,
    "ledc": 3,
    "i2c_sht30": 4,
    "script": 5,
}
DRIVER_NAMES = {v: k for k, v in DRIVERS.items()}

# ドライバ固有 params の context tag 割り当て(main/bind_tlv.hpp と同一)。
#   name -> (tag, width, kind)   kind: "u" | "b"(bool)
PARAMS = {
    1: {  # gpio_out
        "pin": (0, 1, "u"),
        "invert": (1, 0, "b"),
    },
    2: {  # gpio_in
        "pin": (0, 1, "u"),
        "invert": (1, 0, "b"),
        "poll_ms": (2, 2, "u"),
        "pull": (3, 1, "u"),  # 0=none 1=up(既定) 2=down
    },
    3: {  # ledc
        "ch": (0, 1, "u"),
        "pin": (1, 1, "u"),
        "freq": (2, 4, "u"),
        "invert": (3, 0, "b"),
    },
    4: {  # i2c_sht30
        "sda": (0, 1, "u"),
        "scl": (1, 1, "u"),
        "poll_ms": (2, 2, "u"),
        "port": (3, 1, "u"),
    },
    5: {  # script(Phase C。WASM フックへ委譲)
        "poll_ms": (0, 4, "u"),  # 0 = 周期発火しない(属性変化時のみ)
    },
}
PARAM_BY_TAG = {drv: {t: (n, w, k) for n, (t, w, k) in ps.items()} for drv, ps in PARAMS.items()}


def encode_bindings(spec):
    w = TlvWriter()
    w.start(T_LIST)  # anonymous list of binding structs
    for b in spec:
        drv = b["drv"]
        drv_id = DRIVERS[drv] if isinstance(drv, str) else _num(drv)
        w.start(T_STRUCT)
        w.uint(_num(b["ep"]), tag=0, width=2)  # 0: endpoint u16
        w.uint(_num(b["cluster"]), tag=1, width=4)  # 1: cluster u32
        w.uint(drv_id, tag=2, width=1)  # 2: drv-id u8
        params = b.get("params") or {}
        w.start(T_STRUCT, tag=3)  # 3: params(drv 固有)
        known = PARAMS[drv_id]
        for name, value in params.items():
            if name not in known:
                raise ValueError("driver %s has no param %r" % (drv, name))
            tag, width, kind = known[name]
            if kind == "b":
                w.bool_(bool(value), tag=tag)
            else:
                w.uint(_num(value), tag=tag, width=width)
        w.end()
        w.end()
    w.end()
    return w.hex()


def decode_bindings(blob):
    r = TlvReader(blob)
    _t, kind, val = r.next()
    if kind != "start":
        raise ValueError("binding must start with a container")
    out = []
    if val == T_STRUCT:
        return [_decode_binding(r)]
    while not r.eof():
        _t, kind, val = r.next()
        if kind == "end":
            break
        if kind == "start" and val == T_STRUCT:
            out.append(_decode_binding(r))
    return out


def _decode_binding(r):
    b = {"ep": 0, "cluster": 0, "drv": None, "params": {}}
    raw = {}
    while True:
        tag, kind, val = r.next()
        if kind == "end":
            break
        if tag == 0:
            b["ep"] = val
        elif tag == 1:
            b["cluster"] = val
        elif tag == 2:
            b["drv"] = DRIVER_NAMES.get(val, val)
        elif tag == 3 and kind == "start":
            while True:
                t2, k2, v2 = r.next()
                if k2 == "end":
                    break
                raw[t2] = v2
    drv_id = DRIVERS.get(b["drv"], 0)
    for t, v in raw.items():
        name, _w, _k = PARAM_BY_TAG.get(drv_id, {}).get(t, ("tag%d" % t, 0, "u"))
        b["params"][name] = v
    return b


# ---- README 掲載の例 ---------------------------------------------------------

EXAMPLE_COMP_DEFAULT = [
    {
        "ep": 1,
        "device_type": "0x0100",  # On/Off Light
        "rev": 2,
        "clusters": ["0x0003", "0x0004", "0x0006"],  # Identify / Groups / OnOff
    }
]
EXAMPLE_BIND_DEFAULT = [
    {"ep": 1, "cluster": "0x0006", "drv": "gpio_out", "params": {"pin": 7, "invert": False}}
]

EXAMPLE_COMP_DIMMER_SENSOR = [
    {
        "ep": 1,
        "device_type": "0x0101",  # Dimmable Light
        "rev": 3,
        "clusters": ["0x0003", "0x0004", "0x0006", "0x0008"],
    },
    {
        "ep": 2,
        "device_type": "0x0302",  # Temperature Sensor
        "rev": 2,
        "clusters": ["0x0402", "0x0405"],
    },
]
EXAMPLE_BIND_DIMMER_SENSOR = [
    {"ep": 1, "cluster": "0x0008", "drv": "ledc", "params": {"ch": 0, "pin": 6, "freq": 1000}},
    {
        "ep": 2,
        "cluster": "0x0402",
        "drv": "i2c_sht30",
        "params": {"sda": 8, "scl": 9, "poll_ms": 5000},
    },
]

EXAMPLES = [
    ("① 既定 = OnOff light(EP1: Identify/Groups/OnOff、GPIO7)", EXAMPLE_COMP_DEFAULT, EXAMPLE_BIND_DEFAULT),
    (
        "② dimmable light + 温湿度計 2EP(EP1: +LevelControl→LEDC、EP2: SHT30)",
        EXAMPLE_COMP_DIMMER_SENSOR,
        EXAMPLE_BIND_DIMMER_SENSOR,
    ),
]


def cmd_examples():
    for title, comp, bind in EXAMPLES:
        print("## %s" % title)
        print("cfg-comp %s" % encode_composition(comp))
        print("cfg-bind %s" % encode_bindings(bind))
        print()


def cmd_selftest():
    ok = True
    for title, comp, bind in EXAMPLES:
        ch = encode_composition(comp)
        bh = encode_bindings(bind)
        dc = decode_composition(bytes.fromhex(ch))
        db = decode_bindings(bytes.fromhex(bh))
        for want, got in zip(comp, dc):
            if _num(want["ep"]) != got["ep"] or _num(want["device_type"]) != got["device_type"]:
                ok = False
                print("MISMATCH ep/dt in %s: %r != %r" % (title, want, got))
            if [_num(c) for c in want["clusters"]] != got["clusters"]:
                ok = False
                print("MISMATCH clusters in %s: %r != %r" % (title, want, got))
        for want, got in zip(bind, db):
            if _num(want["ep"]) != got["ep"] or _num(want["cluster"]) != got["cluster"]:
                ok = False
                print("MISMATCH ep/cluster in %s: %r != %r" % (title, want, got))
            if want["drv"] != got["drv"]:
                ok = False
                print("MISMATCH drv in %s: %r != %r" % (title, want, got))
            for k, v in (want.get("params") or {}).items():
                gv = got["params"].get(k)
                if int(v) != int(gv):
                    ok = False
                    print("MISMATCH param %s in %s: %r != %r" % (k, title, v, gv))
        print("roundtrip ok: %s" % title)
        print("  comp(%d B) %s" % (len(ch) // 2, ch))
        print("  bind(%d B) %s" % (len(bh) // 2, bh))
    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "comp":
        print(encode_composition(json.load(open(argv[2]))))
    elif cmd == "bind":
        print(encode_bindings(json.load(open(argv[2]))))
    elif cmd == "decode-comp":
        print(json.dumps(decode_composition(bytes.fromhex(argv[2])), indent=2))
    elif cmd == "decode-bind":
        print(json.dumps(decode_bindings(bytes.fromhex(argv[2])), indent=2))
    elif cmd == "examples":
        cmd_examples()
    elif cmd == "selftest":
        return cmd_selftest()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
