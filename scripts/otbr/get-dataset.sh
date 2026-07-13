#!/usr/bin/env bash
# 稼働中 OTBR の active Operational Dataset(TLV hex)を 1 行で出力する。
# 使用例: THREAD_DATASET=$(./get-dataset.sh) cargo run -p esp32c6-thread --release
set -euo pipefail
NAME="${OTBR_NAME:-otbr}"
docker exec "${NAME}" ot-ctl dataset active -x | head -1 | tr -d '\r'
