#!/usr/bin/env bash
#
# OTBR 検証環境のプリフライトチェック(RCP ボード未接続でも実行可)。
# docker / イメージ / otbr-agent 起動可否 / chip-tool / シリアルデバイスを確認する。

set -uo pipefail

ok=0
ng=0
pass() { echo "  [OK] $1"; ok=$((ok + 1)); }
fail() { echo "  [NG] $1"; ng=$((ng + 1)); }

echo "== OTBR 環境チェック =="

if command -v docker >/dev/null && docker ps >/dev/null 2>&1; then
    pass "docker: $(docker --version)"
else
    fail "docker が使えません(インストール / グループ権限を確認)"
fi

IMAGE="${OTBR_IMAGE:-openthread/otbr:latest}"
if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    pass "イメージ取得済み: ${IMAGE}"
else
    fail "イメージ未取得: docker pull ${IMAGE}"
fi

# otbr-agent がコンテナ内で実行できること(radio 不要の --version で確認)。
ver="$(docker run --rm --entrypoint otbr-agent "${IMAGE}" --version 2>/dev/null | head -1)"
if [ -n "${ver}" ]; then
    pass "otbr-agent 実行確認: ${ver}"
else
    fail "otbr-agent を起動できません"
fi

if command -v chip-tool >/dev/null; then
    pass "chip-tool: $(command -v chip-tool)"
else
    fail "chip-tool が見つかりません(pairing ble-thread に必要)"
fi

RADIO_DEV="${OTBR_RADIO_DEV:-/dev/ttyACM0}"
if [ -e "${RADIO_DEV}" ]; then
    pass "RCP デバイス: ${RADIO_DEV}"
else
    echo "  [--] RCP デバイス ${RADIO_DEV} 未接続(実機フェーズで接続)"
fi

if [ -e /dev/net/tun ]; then
    pass "/dev/net/tun(wpan0 作成に必要)"
else
    fail "/dev/net/tun がありません"
fi

echo
echo "OK=${ok} NG=${ng}"
exit "$((ng > 0 ? 1 : 0))"
