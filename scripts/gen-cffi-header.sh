#!/usr/bin/env bash
# C FFI シムの C ヘッダ(simple_matter.h)を cbindgen で再生成する。
#
# 使い方:
#   scripts/gen-cffi-header.sh          再生成してリポジトリのヘッダを上書き
#   scripts/gen-cffi-header.sh --check  再生成が既存と一致するか検査(CI 用、差分で非0終了)
#
# 生成物はリポジトリにコミットする方式(消費者は cbindgen 無しでビルドできる)。
set -euo pipefail

# cbindgen の固定バージョン(環境差での出力揺れを避ける)。
CBINDGEN_VERSION="0.23.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="${REPO_ROOT}/crates/simple-matter-cffi"
CONFIG="${CRATE_DIR}/cbindgen.toml"
OUT="${CRATE_DIR}/include/simple_matter.h"

# cbindgen が無ければ固定バージョンを導入する。
if ! command -v cbindgen >/dev/null 2>&1; then
  echo "cbindgen not found; installing ${CBINDGEN_VERSION}..." >&2
  cargo install cbindgen --version "${CBINDGEN_VERSION}"
fi

mkdir -p "${CRATE_DIR}/include"

gen() {
  cbindgen --config "${CONFIG}" --crate simple-matter-cffi --output "$1" "${CRATE_DIR}"
}

if [[ "${1:-}" == "--check" ]]; then
  TMP="$(mktemp)"
  trap 'rm -f "${TMP}"' EXIT
  gen "${TMP}"
  if ! diff -u "${OUT}" "${TMP}"; then
    echo "ERROR: simple_matter.h is out of date; run scripts/gen-cffi-header.sh" >&2
    exit 1
  fi
  echo "simple_matter.h is up to date." >&2
else
  gen "${OUT}"
  echo "wrote ${OUT}" >&2
fi
