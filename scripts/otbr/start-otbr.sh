#!/usr/bin/env bash
#
# OTBR(OpenThread Border Router)を docker で起動する。
#
# 前提: RCP ファームウェア(ot_rcp)を書き込んだ 802.15.4 ボードが
#       $OTBR_RADIO_DEV(既定 /dev/ttyACM0)に接続されていること。
#       RCP の入手/ビルドは ./build-ot-rcp.sh、全体手順は ./README.md 参照。
#
# 環境変数:
#   OTBR_RADIO_DEV    RCP のシリアルデバイス(既定: /dev/ttyACM0)
#   OTBR_BAUD         RCP の UART ボーレート(既定: 460800。esp-idf ot_rcp の既定)
#   OTBR_BACKBONE_IF  LAN 側 IF(mDNS/advertising proxy を流す側。
#                     既定: デフォルトルートの IF を自動検出)
#   OTBR_NAME         コンテナ名(既定: otbr)
#   OTBR_IMAGE        イメージ(既定: openthread/otbr:latest)
#   OTBR_HTTP_PORT    otbr-web の待受ポート(既定: 8080。host network なので
#                     127.0.0.1:<port> に直接バインドされる)

set -euo pipefail

RADIO_DEV="${OTBR_RADIO_DEV:-/dev/ttyACM0}"
BAUD="${OTBR_BAUD:-460800}"
NAME="${OTBR_NAME:-otbr}"
IMAGE="${OTBR_IMAGE:-openthread/otbr:latest}"
HTTP_PORT="${OTBR_HTTP_PORT:-8080}"
BACKBONE_IF="${OTBR_BACKBONE_IF:-$(ip route show default | awk '{print $5; exit}')}"
# OTBR コンテナ内 firewall(ingress ip6tables フィルタ)を有効化するか。
# 既定 0: ホストカーネルに ip6table_filter が無い環境("Table does not exist"で
# エントリポイントが die する)でも起動できるようにする。T1 の join スモークでは
# ingress フィルタは不要。LAN 側 border routing の ingress 制御が要るなら
# ホストで `sudo modprobe ip6table_filter` 後に OTBR_FIREWALL=1 を指定する。
FIREWALL="${OTBR_FIREWALL:-0}"

if [ ! -e "${RADIO_DEV}" ]; then
    echo "error: radio device ${RADIO_DEV} not found." >&2
    echo "       RCP ボードを接続し OTBR_RADIO_DEV を設定してください。" >&2
    exit 1
fi
if [ -z "${BACKBONE_IF}" ]; then
    echo "error: backbone interface を検出できません。OTBR_BACKBONE_IF を設定してください。" >&2
    exit 1
fi

echo "radio    : spinel+hdlc+uart://${RADIO_DEV}?uart-baudrate=${BAUD}"
echo "backbone : ${BACKBONE_IF}"
echo "web GUI  : http://127.0.0.1:${HTTP_PORT}"

# Border Routing に必要な sysctl(IPv6 有効化 + v4/v6 フォワーディング)は
# ホスト側で設定する。docker 28.x は --network host のコンテナで net.* sysctl の
# 指定を拒否する("sysctl ... not allowed in host network namespace")ため、
# ここでホストの値を確認し、不足していれば警告する(root で
# `sudo sysctl -w <key>=<val>` を実行)。host network なのでホストの値が
# そのままコンテナに効く。
check_sysctl() {
    local key="$1" want="$2" have
    have="$(sysctl -n "${key}" 2>/dev/null || echo "?")"
    if [ "${have}" != "${want}" ]; then
        echo "warn: ${key}=${have} (期待 ${want})。Border Routing に必要。" >&2
        echo "      root で: sudo sysctl -w ${key}=${want}" >&2
    fi
}
check_sysctl net.ipv6.conf.all.disable_ipv6 0
check_sysctl net.ipv4.conf.all.forwarding 1
check_sysctl net.ipv6.conf.all.forwarding 1

# --network host: chip-tool(ホスト側)が wpan0 経由で Thread 網へ到達し、
#   advertising proxy の mDNS が LAN にそのまま流れるようにする(Matter 前提)。
# --privileged + /dev/net/tun: wpan0(TUN)作成に必要。
# otbr-data ボリューム: Thread 網の状態(active dataset 等)を再起動間で保持。
exec docker run -d --rm --name "${NAME}" \
    --privileged --network host \
    --device /dev/net/tun \
    -v "${RADIO_DEV}:${RADIO_DEV}" \
    -v otbr-data:/var/lib/thread \
    -e HTTP_PORT="${HTTP_PORT}" \
    -e FIREWALL="${FIREWALL}" \
    -e NAT64="${OTBR_NAT64:-0}" \
    "${IMAGE}" \
    --radio-url "spinel+hdlc+uart://${RADIO_DEV}?uart-baudrate=${BAUD}" \
    --backbone-interface "${BACKBONE_IF}"
