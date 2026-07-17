#!/usr/bin/env bash
#
# Matter over Thread 長時間ソーク試験(docs/design/thread-port.md §T3 検証ゲート
# 「24h 連続運用: subscribe 維持 + SRP lease 更新」)。
#
# 何を観測するか:
#   1. subscribe over Thread の維持 — smctl で OnOff を購読し続け、周期レポートが
#      Thread(UDP)経由で届き続けるか(切断/再確立をログで追える)。
#   2. SRP lease の更新 — OTBR の SRP server が持つ DUT ホスト登録の remaining lease が
#      lease 満了前に更新(再登録で戻る)され続けるか。揮発鍵だと再登録衝突で消える。
#   3. DUT の生存 — シリアルの [alive] ハートビートと role を記録。
#
# 判定はこのスクリプトではせず、ログファイルを親/ユーザが後で確認する(24h)。
# 起動したまま残す運用(nohup 相当。停止は soak-stop で PID を kill)。
#
# 環境変数 / 引数:
#   SOAK_NODE      対象 node-id(既定: 1)
#   SOAK_AT        運用解決を QU ユニキャストする DUT の operational IPv6(任意。
#                  未指定なら smctl 既定の mDNS 解決に任せる)
#   SOAK_DUT_DEV   DUT シリアル(既定: /dev/ttyACM1)
#   SOAK_INTERVAL  周期観測(read + SRP lease)の間隔秒(既定: 600 = 10 分)
#   SOAK_SUB_MIN   subscribe の min-interval 秒(既定: 30)
#   SOAK_SUB_MAX   subscribe の max-interval 秒(既定: 120)
#   OTBR_NAME      OTBR コンテナ名(既定: otbr)
#   SMCTL         smctl バイナリ(既定: リポジトリの target/release/smctl)
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

NODE="${SOAK_NODE:-1}"
AT="${SOAK_AT:-}"
DUT_DEV="${SOAK_DUT_DEV:-/dev/ttyACM1}"
INTERVAL="${SOAK_INTERVAL:-600}"
SUB_MIN="${SOAK_SUB_MIN:-30}"
SUB_MAX="${SOAK_SUB_MAX:-120}"
OTBR_NAME="${OTBR_NAME:-otbr}"
SMCTL="${SMCTL:-${REPO}/target/release/smctl}"

if [ ! -x "${SMCTL}" ]; then
    echo "error: smctl が見つかりません(${SMCTL})。cargo build -p smctl --release してください。" >&2
    exit 1
fi

AT_ARGS=()
if [ -n "${AT}" ]; then
    AT_ARGS=(--at "${AT}")
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
LOGDIR="${HERE}/soak-logs/${STAMP}"
mkdir -p "${LOGDIR}"

SUB_LOG="${LOGDIR}/subscribe.log"
MON_LOG="${LOGDIR}/observe.log"
DUT_LOG="${LOGDIR}/dut-serial.log"
PIDFILE="${LOGDIR}/pids"
: > "${PIDFILE}"

echo "soak: logs -> ${LOGDIR}"
echo "soak: node=${NODE} at=${AT:-<mdns>} interval=${INTERVAL}s subscribe=${SUB_MIN}/${SUB_MAX}s"

log() { echo "[$(date -Is)] $*"; }

# --- 1. DUT シリアル取り込み(stty+cat のみ。espflash monitor 不使用)---
if [ -e "${DUT_DEV}" ]; then
    stty -F "${DUT_DEV}" 115200 raw -echo 2>/dev/null || true
    ( cat "${DUT_DEV}" 2>/dev/null | while IFS= read -r line; do
          printf '[%s] %s\n' "$(date -Is)" "${line}"
      done ) >> "${DUT_LOG}" 2>&1 &
    echo "dut-serial $!" >> "${PIDFILE}"
    log "DUT serial capture started (${DUT_DEV})" | tee -a "${MON_LOG}"
else
    log "warn: DUT device ${DUT_DEV} not present; serial capture skipped" | tee -a "${MON_LOG}"
fi

# --- 2. subscribe over Thread(OnOff を購読し続ける)---
# smctl subscribe は届いたレポートを stdout に出し続ける。切断すると終了するため、
# ループで再起動して「再確立できるか」も観測する(各セッションを区切りログ付きで)。
( while true; do
      echo "[$(date -Is)] === subscribe session start ===" >> "${SUB_LOG}"
      "${SMCTL}" --timeout 120 "${AT_ARGS[@]}" onoff subscribe "${SUB_MIN}" "${SUB_MAX}" "${NODE}" 1 \
          >> "${SUB_LOG}" 2>&1
      echo "[$(date -Is)] === subscribe session ended (rc=$?); retry in 30s ===" >> "${SUB_LOG}"
      sleep 30
  done ) &
echo "subscribe $!" >> "${PIDFILE}"
log "subscribe loop started" | tee -a "${MON_LOG}"

# --- 3. 周期観測(SRP lease + operational read)---
( while true; do
      {
          echo "----- [$(date -Is)] observe -----"
          # SRP server 側の DUT ホスト登録(remaining lease が縮む→更新で戻る、を観測)。
          echo "# srp server host:"
          docker exec "${OTBR_NAME}" ot-ctl srp server host 2>&1 | \
              grep -E "service.arpa|lease|remaining|addresses|deleted" || echo "  (srp query failed)"
          # 運用 read(CASE over Thread が生きているか)。失敗しても継続。
          echo "# onoff read:"
          "${SMCTL}" --timeout 60 "${AT_ARGS[@]}" onoff read on-off "${NODE}" 1 2>&1 | tail -3 || true
      } >> "${MON_LOG}" 2>&1
      sleep "${INTERVAL}"
  done ) &
echo "observe $!" >> "${PIDFILE}"
log "periodic observer started (every ${INTERVAL}s)" | tee -a "${MON_LOG}"

log "soak running. stop with: bash ${HERE}/soak-stop.sh ${LOGDIR}" | tee -a "${MON_LOG}"
echo "${LOGDIR}"
