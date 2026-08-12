#!/usr/bin/env bash
# Phase C(§9.3)のホストゲート一式:
#
#   1. WAMR ソース取得(初回のみ。ネットワークが要る)
#   2. サンプルスクリプト momentary-toggle を wasm32-unknown-unknown でビルド
#   3. ハーネス(ファームと同一の script_vm.cpp + Linux 用 WAMR)を cmake ビルド
#   4. 実行(フックのラウンドトリップ + 暴走スクリプトの打ち切り)
#
#   ./run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
EXAMPLE="$REPO/crates/sm-script-api/examples-wasm/momentary-toggle"
WASM="$EXAMPLE/target/wasm32-unknown-unknown/release/momentary_toggle.wasm"

"$HERE/fetch-wamr.sh"

echo "== building momentary-toggle (wasm32-unknown-unknown)"
(cd "$EXAMPLE" && cargo build --release --target wasm32-unknown-unknown)
ls -l "$WASM"

echo "== building harness"
cmake -S "$HERE" -B "$HERE/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$HERE/build" -j"$(nproc)" >/dev/null

echo "== running harness"
"$HERE/build/sm_wasm_harness" "$WASM"
