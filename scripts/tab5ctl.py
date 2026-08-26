#!/usr/bin/env python3
"""tab5ctl.py — Tab5 コントローラ(tab5_ctrl_app)のデバッグコンソール用クライアント。

docs/design/p4-thread-controller.md §13(T5)。Tab5 の USB-Serial-JTAG に載っている
esp_console REPL(main/console_dbg.cpp)へコマンドを投げ、応答を終端マーカ
(`OK` / `ERR` / `END` + `OK`)で切って返す。

要点(実機で確定した流儀):
  - **送信は CRLF**。LF だけでは linenoise が行を確定しない(§13.4)。
  - 応答にはアプリのログ行(`I (12345) tag: ...`)が混ざる。既定では捨てる
    (`--keep-logs` で残す)。
  - コマンドのエコーバックも来るので、送ったコマンド行は読み飛ばす。

使い方:
    scripts/tab5ctl.py status
    scripts/tab5ctl.py nodes
    scripts/tab5ctl.py ui-dump
    scripts/tab5ctl.py tap 640 360
    scripts/tab5ctl.py swipe 900 400 300 400 400
    scripts/tab5ctl.py screenshot -o shot.png
    scripts/tab5ctl.py screenshot --div 2 -o shot_half.png
    scripts/tab5ctl.py openwindow aabbccdd 300
    scripts/tab5ctl.py window
    scripts/tab5ctl.py revoke aabbccdd
    scripts/tab5ctl.py send "pair 192.168.1.23 11 wifi"

依存: pyserial(必須)、Pillow(screenshot の PNG 出力にのみ必要)。
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
import time

try:
    import serial  # type: ignore
except ImportError:  # pragma: no cover
    sys.exit("pyserial が要ります: pip install pyserial")

DEFAULT_PORT = "/dev/ttyACM3"
DEFAULT_BAUD = 115200

# ESP-IDF のログ行(`I (12345) tag: msg` / 色エスケープ付き)。
# OpenThread のログは `I(12345) OPENTHREAD:` とスペース無しで来る(実機で確認)。
LOG_RE = re.compile(r"^(?:\x1b\[[0-9;]*m)?[VDIWE] ?\(\d+\)")
# base64 本文(`B:` 接頭辞 + 最大 76 桁)。行内のどこにあっても拾う。
B64_LINE_RE = re.compile(r"B([0-9a-f]{4}):([A-Za-z0-9+/=]{1,76})")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
PROMPT_RE = re.compile(r"^tab5>\s*")


class Tab5:
    def __init__(self, port: str, baud: int, timeout: float = 1.0, keep_logs: bool = False):
        self.ser = serial.Serial(port, baud, timeout=timeout)
        self.keep_logs = keep_logs

    def close(self) -> None:
        self.ser.close()

    def _readline(self, deadline: float) -> str | None:
        """1 行読む。deadline を過ぎたら None。"""
        while time.monotonic() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            line = ANSI_RE.sub("", line)
            # プロンプトはコマンドと同じ行に来ることがある(`tab5> status`)。
            line = PROMPT_RE.sub("", line)
            return line
        return None

    def run(self, command: str, timeout: float = 20.0):
        """コマンドを 1 発投げ、終端(OK/ERR)までの行を返す。

        戻り値: (status, lines)。status は "OK" / "ERR" / "TIMEOUT"。
        lines は終端行を含まない本文(ログ行はフィルタ済み)。
        """
        self.ser.reset_input_buffer()
        self.ser.write((command + "\r\n").encode())
        self.ser.flush()
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        while True:
            line = self._readline(deadline)
            if line is None:
                return "TIMEOUT", lines
            if LOG_RE.match(line):
                if self.keep_logs:
                    lines.append(line)
                continue
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == command.strip():  # エコーバック
                continue
            if stripped == "OK" or stripped.startswith("OK "):
                return "OK", lines
            if stripped == "ERR" or stripped.startswith("ERR"):
                lines.append(stripped)
                return "ERR", lines
            lines.append(stripped)

    def screenshot(self, div: int = 1, timeout: float = 180.0):
        """`screenshot [div]` を投げてフレームを受け取る。

        戻り値: (w, h, raw_rgb565_bytes)。
        フレーミング: `SCREENSHOT <w> <h> RGB565 <b64len>` → base64 本文 → `END` → `OK`。
        """
        cmd = f"screenshot {div}"
        self.ser.reset_input_buffer()
        self.ser.write((cmd + "\r\n").encode())
        self.ser.flush()
        deadline = time.monotonic() + timeout

        w = h = 0
        b64len = 0
        # ヘッダ待ち
        while True:
            line = self._readline(deadline)
            if line is None:
                raise TimeoutError("SCREENSHOT ヘッダが来ませんでした")
            stripped = line.strip()
            if LOG_RE.match(stripped):
                continue
            if stripped.startswith("ERR"):
                raise RuntimeError(stripped)
            if stripped.startswith("SCREENSHOT "):
                parts = stripped.split()
                w, h, b64len = int(parts[1]), int(parts[2]), int(parts[4])
                break

        chunks: list[str] = []
        got = 0
        while True:
            line = self._readline(deadline)
            if line is None:
                raise TimeoutError(f"転送が途中で止まりました({got}/{b64len} 桁)")
            stripped = line.strip()
            if stripped == "END":
                break
            if stripped.startswith("ERR"):
                raise RuntimeError(stripped)
            # 転送中に混ざるログ行(OpenThread の `I(...)` 等)は **行の途中に癒着する**
            # ことがある(実機で `...MeshForwarder-: screenshot 2` を観測)。本文行は
            # `B:` 接頭辞付きなので、行内から正規表現で抽出する(癒着しても拾える)。
            for m in B64_LINE_RE.finditer(stripped):
                idx = int(m.group(1), 16)
                # 連番は 16bit で折り返す(フル解像度は 3.2 万行)。
                while idx < (len(chunks) & 0xFFFF) and idx + 0x10000 > len(chunks) - 0x8000:
                    idx += 0x10000
                if idx < len(chunks):
                    continue  # 重複(再送等)は無視
                while len(chunks) < idx:
                    chunks.append(None)  # 欠落
                chunks.append(m.group(2))
                got += len(m.group(2))

        missing = [i for i, c in enumerate(chunks) if c is None]
        if missing:
            raise RuntimeError(
                f"base64 行の欠落 {len(missing)} 本(先頭: {missing[:8]} / 全 {len(chunks)} 行)"
            )
        data = base64.b64decode("".join(chunks))
        expect = w * h * 2
        if len(data) < expect:
            raise RuntimeError(f"フレームが短い: {len(data)} < {expect}")
        return w, h, data[:expect]


def rgb565_to_png(w: int, h: int, data: bytes, path: str) -> None:
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        sys.exit("PNG 出力には Pillow が要ります: pip install Pillow")
    # LVGL の RGB565 はリトルエンディアンの uint16。
    img = Image.frombytes("RGB", (w, h), _rgb565_to_rgb888(w, h, data))
    img.save(path)


def _rgb565_to_rgb888(w: int, h: int, data: bytes) -> bytes:
    out = bytearray(w * h * 3)
    for i in range(w * h):
        v = data[2 * i] | (data[2 * i + 1] << 8)
        r = (v >> 11) & 0x1F
        g = (v >> 5) & 0x3F
        b = v & 0x1F
        out[3 * i] = (r << 3) | (r >> 2)
        out[3 * i + 1] = (g << 2) | (g >> 4)
        out[3 * i + 2] = (b << 3) | (b >> 2)
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Tab5 デバッグコンソールクライアント")
    ap.add_argument("-p", "--port", default=DEFAULT_PORT, help=f"シリアルポート(既定 {DEFAULT_PORT})")
    ap.add_argument("-b", "--baud", type=int, default=DEFAULT_BAUD)
    ap.add_argument("-t", "--timeout", type=float, default=20.0, help="コマンド応答のタイムアウト秒")
    ap.add_argument("--keep-logs", action="store_true", help="ログ行(I (...))も出力する")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("screenshot", help="画面を PNG で取る")
    p.add_argument("--div", type=int, default=1, choices=(1, 2), help="2 で 1/2 間引き(640x360)")
    p.add_argument("-o", "--out", default="tab5.png")

    p = sub.add_parser("tap", help="合成タップ")
    p.add_argument("x", type=int)
    p.add_argument("y", type=int)

    p = sub.add_parser("swipe", help="合成スワイプ")
    p.add_argument("x1", type=int)
    p.add_argument("y1", type=int)
    p.add_argument("x2", type=int)
    p.add_argument("y2", type=int)
    p.add_argument("ms", type=int, nargs="?", default=300)

    # T9(§17.4): コミッショニングウィンドウ。
    p = sub.add_parser("openwindow", help="コミッショニングウィンドウを開く")
    p.add_argument("node", help="NodeId(hex)")
    p.add_argument("timeout_s", type=int, nargs="?", default=300, help="180..900(既定 300)")
    p.add_argument("disc", type=int, nargs="?", default=None, help="discriminator(既定: 乱数)")

    p = sub.add_parser("revoke", help="コミッショニングウィンドウを閉じる")
    p.add_argument("node", help="NodeId(hex)")

    sub.add_parser("window", help="直近の窓(manual code / QR / 残り秒)")

    sub.add_parser("ui-dump", help="ウィジェットツリーをダンプ")
    sub.add_parser("nodes", help="ノード一覧")
    sub.add_parser("status", help="コントローラ状態")

    p = sub.add_parser("send", help="任意のコンソールコマンドをそのまま投げる")
    p.add_argument("line", help='例: "pair 192.168.1.23 11 wifi"')

    args = ap.parse_args()
    dev = Tab5(args.port, args.baud, keep_logs=args.keep_logs)
    try:
        if args.cmd == "screenshot":
            t0 = time.monotonic()
            w, h, data = dev.screenshot(args.div, timeout=max(args.timeout, 180.0))
            rgb565_to_png(w, h, data, args.out)
            print(f"saved {args.out} ({w}x{h}, {time.monotonic() - t0:.1f}s)")
            return 0

        if args.cmd == "tap":
            line = f"tap {args.x} {args.y}"
        elif args.cmd == "swipe":
            line = f"swipe {args.x1} {args.y1} {args.x2} {args.y2} {args.ms}"
        elif args.cmd == "send":
            line = args.line
        elif args.cmd == "openwindow":
            line = f"openwindow {args.node} {args.timeout_s}"
            if args.disc is not None:
                line += f" {args.disc}"
        elif args.cmd == "revoke":
            line = f"revoke {args.node}"
        else:
            line = args.cmd  # ui-dump / nodes / status / window

        status, lines = dev.run(line, timeout=args.timeout)
        for out_line in lines:
            print(out_line)
        print(status)
        return 0 if status == "OK" else 1
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main())
