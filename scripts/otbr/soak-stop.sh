#!/usr/bin/env bash
#
# soak.sh が起動したバックグラウンドプロセス群を停止する。
# 使い方: soak-stop.sh <logdir>   (soak.sh が出力した soak-logs/<stamp> ディレクトリ)
#
set -uo pipefail
LOGDIR="${1:-}"
if [ -z "${LOGDIR}" ] || [ ! -f "${LOGDIR}/pids" ]; then
    echo "usage: $0 <logdir with pids file>" >&2
    exit 1
fi
while read -r name pid; do
    if kill "${pid}" 2>/dev/null; then
        echo "stopped ${name} (pid ${pid})"
    else
        echo "already gone: ${name} (pid ${pid})"
    fi
done < "${LOGDIR}/pids"
