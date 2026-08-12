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

    # 自己検証(pack → show のラウンドトリップ)
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

    p = sub.add_parser("selftest", help="pack/unpack ラウンドトリップ")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
