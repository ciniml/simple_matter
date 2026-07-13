#!/usr/bin/env bash
# OTBR コンテナを停止する(--rm 起動なので停止 = 破棄。dataset は otbr-data
# ボリュームに残る。完全リセットは: docker volume rm otbr-data)。
set -euo pipefail
NAME="${OTBR_NAME:-otbr}"
docker stop "${NAME}"
