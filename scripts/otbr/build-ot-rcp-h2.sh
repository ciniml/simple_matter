#!/usr/bin/env bash
#
# ESP32-H2 用 ot_rcp ファームウェア(RCP = Radio Co-Processor)を esp-idf の docker
# イメージでビルドする。build-ot-rcp.sh(C6 / USB-Serial-JTAG 版)の姉妹版で、
# こちらは **spinel をハードウェア UART(GPIO)に出す**。ホスト MCU(ESP32-P4)と
# UART で結線して使うため(docs/design/p4-thread-controller.md §3 F8d)。
#
# 出力: scripts/otbr/dist/ot_rcp_h2/
#   - merged_ot_rcp.bin(bootloader + partition table + app を 0x0 に一発書き)
#   - esp_ot_rcp.bin / bootloader.bin / partition-table.bin(個別)
#
# 書き込み(実機フェーズ。ボード接続後にユーザが実行する):
#   espflash write-bin 0x0 dist/ot_rcp_h2/merged_ot_rcp.bin --port <PORT>
#   ないし esptool.py --chip esp32h2 write_flash 0x0 dist/ot_rcp_h2/merged_ot_rcp.bin
#
# 結線(P4 ↔ H2。TX/RX はクロス + GND 共通):
#   H2 spinel TX → P4 RX(CONFIG_SM_OT_UART_RX_PIN、既定 GPIO4)
#   H2 spinel RX → P4 TX(CONFIG_SM_OT_UART_TX_PIN、既定 GPIO5)
#   ※ H2 側は既定で UART0(= コンソールと同じピン)に spinel を出す(ot_rcp の
#      UART_PIN_NO_CHANGE)。ボードに合わせて RCP_UART_TX_PIN / RCP_UART_RX_PIN で
#      明示指定できる(ot_rcp の CONFIG_OPENTHREAD_UART_PIN_MANUAL 経由)。
#      P4 側の CONFIG_SM_OT_UART_* と baud を必ず一致させること。
#
# env で上書きできる設定:
#   IDF_IMAGE        使用する docker イメージ(既定 espressif/idf:release-v5.4)
#   RCP_BAUD         spinel の baud(既定 460800。P4 側 CONFIG_SM_OT_UART_BAUD と一致必須)
#   RCP_UART_TX_PIN  H2 側 spinel TX ピン(未指定 = ot_rcp 既定 = コンソール UART0 のピン)
#   RCP_UART_RX_PIN  H2 側 spinel RX ピン(未指定 = 同上)
# ※ baud は ot_rcp example の main/esp_ot_config.h にハードコードされている(Kconfig
#    ではない)ため、RCP_BAUD を変えるときは本スクリプトがヘッダを sed で書き換える。

set -euo pipefail

IDF_IMAGE="${IDF_IMAGE:-espressif/idf:release-v5.4}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
WORK_DIR="${DIST_DIR}/work_h2"

RCP_BAUD="${RCP_BAUD:-460800}"
RCP_UART_TX_PIN="${RCP_UART_TX_PIN:-}"
RCP_UART_RX_PIN="${RCP_UART_RX_PIN:-}"

mkdir -p "${WORK_DIR}"

# esp-idf 同梱の examples/openthread/ot_rcp をコンテナ内でコピーしてビルドする。
docker run --rm \
    -v "${WORK_DIR}:/work" \
    -w /work \
    -e HOME=/tmp \
    -e FIX_UID="$(id -u)" \
    -e FIX_GID="$(id -g)" \
    -e RCP_BAUD="${RCP_BAUD}" \
    -e RCP_UART_TX_PIN="${RCP_UART_TX_PIN}" \
    -e RCP_UART_RX_PIN="${RCP_UART_RX_PIN}" \
    "${IDF_IMAGE}" \
    bash -ec '
        # コンテナは root で走るため、終了時に成果物をホストユーザへ chown する。
        trap "chown -R ${FIX_UID}:${FIX_GID} /work" EXIT
        rm -rf /work/ot_rcp
        cp -r "${IDF_PATH}/examples/openthread/ot_rcp" /work/
        cd /work/ot_rcp
        {
            echo ""
            echo "# --- build-ot-rcp-h2.sh: spinel over hardware UART (to the ESP32-P4 host) ---"
            echo "CONFIG_OPENTHREAD_RCP_UART=y"
            echo "CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=n"
            if [ -n "${RCP_UART_TX_PIN}" ] || [ -n "${RCP_UART_RX_PIN}" ]; then
                # ot_rcp example の Kconfig(OPENTHREAD_UART_PIN_MANUAL)。未指定なら
                # UART_PIN_NO_CHANGE = ボード既定(= コンソール UART0)のピンになる。
                echo "CONFIG_OPENTHREAD_UART_PIN_MANUAL=y"
                [ -n "${RCP_UART_RX_PIN}" ] && echo "CONFIG_OPENTHREAD_UART_RX_PIN=${RCP_UART_RX_PIN}"
                [ -n "${RCP_UART_TX_PIN}" ] && echo "CONFIG_OPENTHREAD_UART_TX_PIN=${RCP_UART_TX_PIN}"
            fi
        } >> sdkconfig.defaults
        # baud は example の esp_ot_config.h にハードコードされている(Kconfig 化されて
        # いない)ため、既定 460800 以外を要求されたらヘッダを書き換える。
        if [ "${RCP_BAUD}" != "460800" ]; then
            sed -i "s/\.baud_rate =  *460800/.baud_rate = ${RCP_BAUD}/" main/esp_ot_config.h
        fi
        grep -n "baud_rate" main/esp_ot_config.h
        idf.py set-target esp32h2
        idf.py build
        echo "--- sdkconfig (spinel transport / uart) ---"
        grep -E "OPENTHREAD_RCP_(UART|USB_SERIAL_JTAG)|OPENTHREAD_UART_(PIN_MANUAL|TX_PIN|RX_PIN)" sdkconfig || true
        idf.py merge-bin -o merged_ot_rcp.bin
    '

mkdir -p "${DIST_DIR}/ot_rcp_h2"
# app バイナリ名は IDF バージョンで異なりうる(esp_ot_rcp.bin)ため glob で拾う。
cp "${WORK_DIR}/ot_rcp/build/"*ot_rcp*.bin \
   "${WORK_DIR}/ot_rcp/build/bootloader/bootloader.bin" \
   "${WORK_DIR}/ot_rcp/build/partition_table/partition-table.bin" \
   "${DIST_DIR}/ot_rcp_h2/"
# merge-bin の出力はプロジェクト直下(build/ ではない)に出ることがあるため両方見る。
if [ -f "${WORK_DIR}/ot_rcp/merged_ot_rcp.bin" ]; then
    cp "${WORK_DIR}/ot_rcp/merged_ot_rcp.bin" "${DIST_DIR}/ot_rcp_h2/"
fi
if [ ! -f "${DIST_DIR}/ot_rcp_h2/merged_ot_rcp.bin" ]; then
    echo "ERROR: merged_ot_rcp.bin was not produced" >&2
    exit 1
fi

echo
echo "ビルド完了: ${DIST_DIR}/ot_rcp_h2/"
ls -l "${DIST_DIR}/ot_rcp_h2/"
echo "書き込み(実機フェーズ):"
echo "  espflash write-bin 0x0 ${DIST_DIR}/ot_rcp_h2/merged_ot_rcp.bin --port <PORT>"
