#!/usr/bin/env bash
#
# OTBR 上に Thread ネットワークを form し、Operational Dataset(TLV hex)を出力する。
# 既に active dataset がある場合(otbr-data ボリュームに保存済み)はそれを使う。
# 強制再作成は FORCE=1 ./form-network.sh。
#
# 出力される hex は次で使う:
#   - thread-smoke: THREAD_DATASET=<hex> cargo run -p esp32c6-thread --release
#   - chip-tool   : chip-tool pairing ble-thread <node-id> hex:<hex> <PIN> <discriminator>

set -euo pipefail

NAME="${OTBR_NAME:-otbr}"

otctl() {
    docker exec "${NAME}" ot-ctl "$@"
}

state="$(otctl state | head -1 | tr -d '\r')"
echo "current state: ${state}" >&2

need_new=0
if [ "${FORCE:-0}" = "1" ]; then
    need_new=1
elif ! otctl dataset active -x >/dev/null 2>&1; then
    # active dataset が無い(NotFound)→ 新規 form。
    need_new=1
fi

if [ "${need_new}" = "1" ]; then
    echo "forming new network..." >&2
    otctl dataset init new >/dev/null
    otctl dataset commit active >/dev/null
fi

otctl ifconfig up >/dev/null || true
otctl thread start >/dev/null || true

# leader になるまで待つ(単独 BR なら数秒)。
for _ in $(seq 1 30); do
    state="$(otctl state | head -1 | tr -d '\r')"
    if [ "${state}" = "leader" ] || [ "${state}" = "router" ]; then
        break
    fi
    sleep 1
done
echo "state: ${state}" >&2

echo "--- active dataset (TLV hex) ---" >&2
otctl dataset active -x | head -1 | tr -d '\r'
