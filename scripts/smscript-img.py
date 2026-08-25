#!/usr/bin/env python3
"""smscript パーティションイメージ(.wasm → "SMWS" ヘッダ付き)の生成・検査ツール。

docs/design/generic-firmware.md §9.3(ロード)/ §9.4(ScriptStore = Phase D)。
ヘッダ形式は ports/esp-idf/examples/generic_matter_cpp/main/script_img.hpp と同一:

    offset 0  4B  magic "SMWS"
           4  2B  ver   u16 LE
           6  2B  flags u16 LE(予約)
           8  4B  len   u32 LE
          12  4B  crc32 u32 LE(本体 len バイト)

使い方:

    # slot A のイメージ(ヘッダ + 本体)を作る
    ./smscript-img.py pack momentary_toggle.wasm -o slotA.bin --ver 1

    # esptool で書き込む(partitions.csv の smscript は 0x296000 / 256KB)
    esptool.py write_flash 0x296000 slotA.bin

    # 既存イメージの検査
    ./smscript-img.py show slotA.bin

    # ScriptStore(§9.4)への転送バッチを作る(smctl any invoke 群)
    ./smscript-img.py batch momentary_toggle.wasm --node 1 --ep 1 > store.batch
    smctl batch store.batch

    # 自己検証(pack → show / batch のラウンドトリップ)
    ./smscript-img.py selftest
"""

import argparse
import binascii
import struct
import sys
import tempfile

MAGIC = b"SMWS"
HDR_SIZE = 16
SLOT_SIZE = 0x20000  # 128KB
MAX_LEN = SLOT_SIZE - HDR_SIZE


def pack(body: bytes, ver: int = 1, flags: int = 0) -> bytes:
    if len(body) == 0 or len(body) > MAX_LEN:
        raise ValueError(f"body must be 1..{MAX_LEN} bytes (got {len(body)})")
    crc = binascii.crc32(body) & 0xFFFFFFFF
    return MAGIC + struct.pack("<HHII", ver, flags, len(body), crc) + body


def unpack(img: bytes):
    """(ver, flags, len, crc32, body) を返す。不正なら ValueError。"""
    if len(img) < HDR_SIZE or img[:4] != MAGIC:
        raise ValueError("bad magic (not an smscript image)")
    ver, flags, ln, crc = struct.unpack("<HHII", img[4:HDR_SIZE])
    if ln == 0 or ln > MAX_LEN:
        raise ValueError(f"bad length {ln}")
    body = img[HDR_SIZE:HDR_SIZE + ln]
    if len(body) != ln:
        raise ValueError(f"truncated body ({len(body)} < {ln})")
    actual = binascii.crc32(body) & 0xFFFFFFFF
    if actual != crc:
        raise ValueError(f"CRC mismatch (header {crc:08x}, actual {actual:08x})")
    return ver, flags, ln, crc, body


def cmd_pack(args) -> int:
    with open(args.wasm, "rb") as f:
        body = f.read()
    if body[:4] != b"\x00asm":
        print(f"warning: {args.wasm} does not start with the WASM magic", file=sys.stderr)
    img = pack(body, args.ver, args.flags)
    out = args.output or (args.wasm + ".img")
    with open(out, "wb") as f:
        f.write(img)
    print(f"{out}: ver={args.ver} len={len(body)} crc32={struct.unpack('<I', img[12:16])[0]:08x} "
          f"total={len(img)} B")
    if args.slot == "b":
        print(f"flash offset = smscript_offset + 0x{SLOT_SIZE:05x} (slot B)")
    return 0


def cmd_show(args) -> int:
    with open(args.image, "rb") as f:
        img = f.read()
    for slot in range(2):
        off = slot * SLOT_SIZE
        chunk = img[off:off + SLOT_SIZE]
        if len(chunk) < HDR_SIZE:
            break
        try:
            ver, flags, ln, crc, _ = unpack(chunk)
        except ValueError as e:
            print(f"slot {'AB'[slot]}: invalid ({e})")
            continue
        print(f"slot {'AB'[slot]}: ver={ver} flags={flags} len={ln} crc32={crc:08x} OK")
    return 0


# ---- ScriptStore(§9.4)転送バッチ --------------------------------------------

SCRIPTSTORE_CLUSTER = 0xFFF1FC01
CMD_BEGIN, CMD_DATA, CMD_COMMIT, CMD_ABORT = 0x00, 0x01, 0x02, 0x03
# 1 チャンクの上限。シムの sm_attr_value_t は octstr を 64B 固定バッファで運ぶ
# (STR_CAP)ため、§9.4 の「≤512」ではなく 64 が実効上限
# (ports/esp-idf/examples/generic_matter_cpp/main/script_store.hpp の kSsChunkMax)。
CHUNK_MAX = 64


def make_batch(body: bytes, node: int = 1, ep: int = 1, chunk: int = CHUNK_MAX,
               comment: str = "") -> str:
    """.wasm 本体 → smctl batch(Begin/Data.../Commit)テキスト。"""
    if not 1 <= chunk <= CHUNK_MAX:
        raise ValueError(f"chunk must be 1..{CHUNK_MAX} (shim octstr cap)")
    if len(body) == 0 or len(body) > MAX_LEN:
        raise ValueError(f"body must be 1..{MAX_LEN} bytes (got {len(body)})")
    crc = binascii.crc32(body) & 0xFFFFFFFF
    cl = f"0x{SCRIPTSTORE_CLUSTER:08X}"
    out = []
    if comment:
        out.append(f"# {comment}")
    out.append(f"# ScriptStore transfer: {len(body)} B, crc32={crc:08x}, "
               f"{(len(body) + chunk - 1) // chunk} chunks of <= {chunk} B")
    out.append(f"any invoke {node} {ep} {cl} 0x{CMD_BEGIN:02X} "
               f"0=u32:{len(body)} 1=u32:{crc}")
    for off in range(0, len(body), chunk):
        part = body[off:off + chunk]
        out.append(f"any invoke {node} {ep} {cl} 0x{CMD_DATA:02X} "
                   f"0=u32:{off} 1=hex:{part.hex()}")
    out.append(f"any invoke {node} {ep} {cl} 0x{CMD_COMMIT:02X}")
    out.append(f"any read {node} {ep} {cl} 2  # Version")
    return "\n".join(out) + "\n"


def parse_batch(text: str):
    """make_batch の出力を読み戻して (size, crc32, body) を返す(往復検証用)。"""
    size = crc = None
    body = bytearray()
    saw_commit = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tok = line.split()
        if tok[:1] != ["any"]:
            raise ValueError(f"unexpected line: {raw!r}")
        if tok[1] == "read":
            continue
        if tok[1] != "invoke":
            raise ValueError(f"unexpected command: {raw!r}")
        cluster = int(tok[4], 0)
        if cluster != SCRIPTSTORE_CLUSTER:
            raise ValueError(f"unexpected cluster in {raw!r}")
        cmd = int(tok[5], 0)
        fields = dict(t.split("=", 1) for t in tok[6:])
        if cmd == CMD_BEGIN:
            size = int(fields["0"].split(":", 1)[1])
            crc = int(fields["1"].split(":", 1)[1])
            body = bytearray()
        elif cmd == CMD_DATA:
            off = int(fields["0"].split(":", 1)[1])
            chunk = bytes.fromhex(fields["1"].split(":", 1)[1])
            if off != len(body):
                raise ValueError(f"out-of-order chunk at {off} (have {len(body)})")
            if len(chunk) > CHUNK_MAX:
                raise ValueError(f"chunk too large: {len(chunk)} B")
            body += chunk
        elif cmd == CMD_COMMIT:
            saw_commit = True
        else:
            raise ValueError(f"unexpected command id {cmd}")
    if size is None or not saw_commit:
        raise ValueError("batch lacks Begin or Commit")
    if len(body) != size:
        raise ValueError(f"declared size {size} != transferred {len(body)}")
    actual = binascii.crc32(bytes(body)) & 0xFFFFFFFF
    if actual != crc:
        raise ValueError(f"CRC mismatch (declared {crc:08x}, actual {actual:08x})")
    return size, crc, bytes(body)


def cmd_batch(args) -> int:
    with open(args.wasm, "rb") as f:
        body = f.read()
    if body[:4] != b"\x00asm":
        print(f"warning: {args.wasm} does not start with the WASM magic", file=sys.stderr)
    text = make_batch(body, args.node, args.ep, args.chunk, comment=f"from {args.wasm}")
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"{args.output}: {len(text.splitlines())} lines", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_selftest(_args) -> int:
    body = b"\x00asm\x01\x00\x00\x00" + bytes(range(64))
    img = pack(body, ver=7)
    ver, flags, ln, crc, out = unpack(img)
    assert (ver, flags, ln, out) == (7, 0, len(body), body), "roundtrip mismatch"
    assert binascii.crc32(b"123456789") & 0xFFFFFFFF == 0xCBF43926, "crc32 vector"
    # 壊れたイメージは弾く。
    broken = bytearray(img)
    broken[HDR_SIZE] ^= 0xFF
    try:
        unpack(bytes(broken))
        print("FAIL: corrupted image accepted")
        return 1
    except ValueError:
        pass
    with tempfile.NamedTemporaryFile(suffix=".img") as f:
        f.write(img)
        f.flush()

    # ScriptStore バッチ(§9.4)の往復: make_batch → parse_batch で本体が一致すること。
    for length in (1, 63, 64, 65, 700, 4096):
        payload = bytes((i * 31 + 7) & 0xFF for i in range(length))
        text = make_batch(payload, node=1, ep=1)
        size, crc, out = parse_batch(text)
        assert out == payload, f"batch roundtrip mismatch at {length} B"
        assert size == length and crc == binascii.crc32(payload) & 0xFFFFFFFF, "batch header"
        # 全 Data 行が 64B 上限に収まっていること(シムの octstr 上限)。
        for line in text.splitlines():
            if "0x01 " in line and "1=hex:" in line:
                hexpart = line.split("1=hex:", 1)[1].strip()
                assert len(hexpart) // 2 <= CHUNK_MAX, "chunk exceeds shim octstr cap"
    # 壊れたバッチ(チャンク欠落)は弾く。
    text = make_batch(bytes(200), node=1, ep=1)
    lines = [ln for ln in text.splitlines() if "0=u32:64 " not in ln]
    try:
        parse_batch("\n".join(lines))
        print("FAIL: batch with a missing chunk accepted")
        return 1
    except ValueError:
        pass

    print("PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack", help="wasm → smscript イメージ")
    p.add_argument("wasm")
    p.add_argument("-o", "--output")
    p.add_argument("--ver", type=int, default=1, help="世代(大きい方が active。既定 1)")
    p.add_argument("--flags", type=int, default=0)
    p.add_argument("--slot", choices=["a", "b"], default="a")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("show", help="イメージ(またはパーティションダンプ)の検査")
    p.add_argument("image")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("batch", help="wasm → ScriptStore 転送バッチ(smctl batch 用)")
    p.add_argument("wasm")
    p.add_argument("-o", "--output", help="出力ファイル(既定 = 標準出力)")
    p.add_argument("--node", type=int, default=1, help="ノード ID(既定 1)")
    p.add_argument("--ep", type=int, default=1, help="ScriptStore のエンドポイント(既定 1)")
    p.add_argument("--chunk", type=int, default=CHUNK_MAX,
                   help=f"1 Data あたりのバイト数(1..{CHUNK_MAX}、既定 {CHUNK_MAX})")
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("selftest", help="pack/unpack + batch のラウンドトリップ")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
