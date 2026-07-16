#!/usr/bin/env bash
#
# ESP32-C6 用 ot_rcp ファームウェア(RCP = Radio Co-Processor、OTBR の 802.15.4
# ラジオ側)を esp-idf の docker イメージでビルドする。ローカルに ESP-IDF を
# インストールする必要はない(docker のみ)。
#
# 出力: scripts/otbr/dist/ot_rcp/
#   - ot_rcp.bin / bootloader.bin / partition-table.bin と flash 手順(下記)
#
# 書き込み(実機フェーズ。ボード接続後に実行):
#   espflash write-bin 0x0 dist/ot_rcp/merged_ot_rcp.bin --port /dev/ttyACM0
#   ないし esptool.py --chip esp32c6 write_flash 0x0 dist/ot_rcp/merged_ot_rcp.bin
#
# 注意: RCP とホスト(OTBR)間の接続は UART(既定 460800 baud)。ボードの USB が
#   USB-Serial-JTAG 直結(例: M5 NanoC6)の場合、既定設定の ot_rcp(UART0 想定)が
#   その USB ポート越しに動くかは要実機確認(docs/design/thread-port.md リスク表)。

set -euo pipefail

IDF_IMAGE="${IDF_IMAGE:-espressif/idf:release-v5.4}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
WORK_DIR="${DIST_DIR}/work"

# RCP の spinel トランスポートを USB-Serial-JTAG にするか(既定 1 = する)。
# 既定の ot_rcp は spinel をハードウェア UART(GPIO)に出すため、UART ブリッジの
# 無い M5 NanoC6 等では USB ポート越しに spinel が通らない(T1 実測で確定。
# docs/design/thread-port.md リスク R3 / §T1)。この構成では
# CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y にして spinel を USB CDC へ出す。
# UART ブリッジ付きボード(DevKitC 等)を UART で使う場合は RCP_OVER_USB=0。
RCP_OVER_USB="${RCP_OVER_USB:-1}"

mkdir -p "${WORK_DIR}"

# esp-idf 同梱の examples/openthread/ot_rcp をコンテナ内でコピーしてビルドする。
# merge-bin で bootloader + partition table + app を 1 ファイルに結合する
# (0x0 に一発書きできる)。
docker run --rm \
    -v "${WORK_DIR}:/work" \
    -w /work \
    -e HOME=/tmp \
    -e FIX_UID="$(id -u)" \
    -e FIX_GID="$(id -g)" \
    -e RCP_OVER_USB="${RCP_OVER_USB}" \
    "${IDF_IMAGE}" \
    bash -ec '
        # コンテナは root で走るため、終了時に成果物をホストユーザへ chown する
        # (これが無いとホスト側で rm -rf dist できなくなる)。
        trap "chown -R ${FIX_UID}:${FIX_GID} /work" EXIT
        rm -rf /work/ot_rcp
        cp -r "${IDF_PATH}/examples/openthread/ot_rcp" /work/
        cd /work/ot_rcp
        if [ "${RCP_OVER_USB}" = "1" ]; then
            # spinel を USB-Serial-JTAG に出す(NanoC6 等 UART ブリッジ無しボード向け)。
            {
                echo ""
                echo "CONFIG_OPENTHREAD_RCP_UART=n"
                echo "CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y"
            } >> sdkconfig.defaults
        fi
        idf.py set-target esp32c6
        idf.py build
        grep -E "OPENTHREAD_RCP_(UART|USB_SERIAL_JTAG)" sdkconfig || true
        idf.py merge-bin -o merged_ot_rcp.bin
    '

mkdir -p "${DIST_DIR}/ot_rcp"
# app バイナリ名は IDF バージョンで異なりうる(esp_ot_rcp.bin)ため glob で拾う。
cp "${WORK_DIR}/ot_rcp/build/"*ot_rcp*.bin \
   "${WORK_DIR}/ot_rcp/build/bootloader/bootloader.bin" \
   "${WORK_DIR}/ot_rcp/build/partition_table/partition-table.bin" \
   "${DIST_DIR}/ot_rcp/"

echo
echo "ビルド完了: ${DIST_DIR}/ot_rcp/"
echo "書き込み(実機フェーズ):"
echo "  espflash write-bin 0x0 ${DIST_DIR}/ot_rcp/merged_ot_rcp.bin --port <PORT>"
