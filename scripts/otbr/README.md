# OTBR(OpenThread Border Router)検証環境

Thread ポート(`docs/design/thread-port.md`)の検証環境。ホスト PC 上の
OTBR docker + RCP ボード(ESP32-C6 に ot_rcp ファームウェア)で Thread
ネットワークを form し、DUT(`ports/esp32/esp32c6-thread` の thread-smoke、
以降の Matter over Thread ファームウェア)を join させる。

```
[ホスト PC]
  chip-tool ──┐
  OTBR docker ┴─ wpan0(TUN)      LAN 側 IF(backbone、mDNS/advertising proxy)
      │ spinel+hdlc+uart(/dev/ttyACM*、460800)
[RCP ボード: ESP32-C6 + ot_rcp FW]
      │ 802.15.4
[DUT: ESP32-C6 + thread-smoke / Matter over Thread FW]
```

## スクリプト

| スクリプト | 役割 |
|---|---|
| `check-env.sh` | プリフライト(docker/イメージ/chip-tool/デバイス。RCP 未接続でも可) |
| `build-ot-rcp.sh` | ot_rcp FW を esp-idf docker でビルド(ローカル IDF 不要)→ `dist/ot_rcp/` |
| `start-otbr.sh` | OTBR コンテナ起動(要 RCP 接続。`OTBR_RADIO_DEV` 既定 /dev/ttyACM0) |
| `form-network.sh` | Thread 網 form + dataset TLV hex 出力(冪等。`FORCE=1` で再作成) |
| `get-dataset.sh` | 稼働中 OTBR の dataset TLV hex を 1 行出力 |
| `stop-otbr.sh` | コンテナ停止(dataset は `otbr-data` ボリュームに保持) |

## 手順(T1: join スモーク)

```sh
# 0. プリフライト(いつでも可)
./check-env.sh

# 1. RCP ファームウェアをビルド(いつでも可。数分)
./build-ot-rcp.sh

# 2.(実機)RCP ボードを接続し ot_rcp を書き込む
espflash write-bin 0x0 dist/ot_rcp/merged_ot_rcp.bin --port /dev/ttyACM0

# 3. OTBR 起動 + Thread 網 form
OTBR_RADIO_DEV=/dev/ttyACM0 ./start-otbr.sh
docker logs -f otbr          # "Start Thread Border Agent" 等が出るまで
DATASET=$(./form-network.sh)
echo "$DATASET"

# 4.(実機)DUT に thread-smoke を書き込む(dataset はコンパイル時定数)
cd ../../ports/esp32
THREAD_DATASET=$DATASET cargo run -p esp32c6-thread --release --bin thread-smoke
#   ログ: role: Detached -> Child、ipv6: fdxx:...(mesh-local)が join 成功の合図

# 5. 疎通確認(OTBR 側から)
docker exec otbr ot-ctl ping <DUT の mesh-local アドレス>
docker exec otbr ot-ctl udp open
docker exec otbr ot-ctl udp send <DUT の mesh-local アドレス> 11095 hello
#   → thread-smoke が echo を返す([echo] ログ + udp receive 表示)
```

## chip-tool でのコミッショニング(T2 以降)

```sh
DATASET=$(./get-dataset.sh)
chip-tool pairing ble-thread <node-id> hex:${DATASET} 20202021 3840
```

chip-tool は BLE(BTP)で PASE を確立し、`AddOrUpdateThreadNetwork(dataset)` →
`ConnectNetwork` で dataset をデバイスへ渡す。運用系の解決は OTBR の
advertising proxy(SRP → LAN の mDNS)経由。

## トラブルシュート

- **otbr-agent が radio を開けない**: baudrate(既定 460800。`OTBR_BAUD`)と
  デバイス名を確認。`docker logs otbr` に spinel のエラーが出る。
- **ボードの USB が USB-Serial-JTAG 直結の場合**(M5 NanoC6 等、外付け
  UART ブリッジ無し): 既定の ot_rcp は UART0 想定。USB-Serial-JTAG 経由の
  spinel は要実機確認(`docs/design/thread-port.md` リスク表 R3)。ダメな場合は
  外付け USB-UART アダプタを RCP の UART0 ピンに接続する。
- **web GUI**: http://127.0.0.1:8080(`OTBR_HTTP_PORT` で変更)。
- **完全リセット**: `./stop-otbr.sh && docker volume rm otbr-data`。
- **REST API**: :8081(otbr-agent の rest listener。host network)。
