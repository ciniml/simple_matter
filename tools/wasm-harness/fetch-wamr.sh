#!/usr/bin/env bash
# WAMR のソースを ESP Component Registry から取得する(ファームが使うのと同一版)。
# リポジトリには WAMR を vendor しない(docs/design/generic-firmware.md §9.3)。
#
#   ./fetch-wamr.sh            # .wamr/wamr/ へ展開(取得済みなら何もしない)
#
# 版を変える場合は WAMR_VERSION / WAMR_URL を環境変数で上書きする。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAMR_VERSION="${WAMR_VERSION:-2.4.0~1}"
WAMR_FILE="${WAMR_FILE:-espressif__wasm-micro-runtime-v2.4.0_1.zip}"
WAMR_URL="${WAMR_URL:-https://components-file.espressif.com/components/espressif/wasm-micro-runtime/${WAMR_VERSION}/${WAMR_FILE}}"
DEST="$HERE/.wamr"

if [ -f "$DEST/wamr/build-scripts/runtime_lib.cmake" ]; then
  echo "WAMR already present: $DEST/wamr (version $WAMR_VERSION)"
  exit 0
fi

mkdir -p "$DEST"
echo "downloading WAMR $WAMR_VERSION ..."
curl -sSLf "$WAMR_URL" -o "$DEST/wamr.zip"
rm -rf "$DEST/wamr"
mkdir -p "$DEST/wamr"
unzip -q "$DEST/wamr.zip" -d "$DEST/wamr"
echo "$WAMR_VERSION" > "$DEST/VERSION"
echo "WAMR $WAMR_VERSION extracted to $DEST/wamr"
