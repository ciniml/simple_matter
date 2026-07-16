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

- **USB-Serial-JTAG 直結ボード(M5 NanoC6 等、UART ブリッジ無し)を RCP に使う**:
  既定の `ot_rcp` は spinel を**ハードウェア UART(GPIO)**に出すため、USB ポート
  (/dev/ttyACM*)には spinel が流れず OTBR は `spinel_driver.cpp: Init() Failure`
  になる(T1 実測で確定。`docs/design/thread-port.md` R3)。**対策: `build-ot-rcp.sh`
  を `RCP_OVER_USB=1`(既定)でビルドする** → `CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y`
  で spinel が USB CDC に出て、そのまま `OTBR_RADIO_DEV=/dev/ttyACM<n>` で接続できる。
  UART ブリッジ付きボード(DevKitC 等)を UART 配線で使う場合は `RCP_OVER_USB=0`。
  疎通確認: `docker exec otbr ot-ctl rcp version`(RCP 版が返れば spinel リンク OK)。
- **`docker run` が sysctl で失敗**(`net.ipv4.conf.all.forwarding not allowed in
  host network namespace`): docker 28.x は `--network host` で `net.*` sysctl 指定を
  拒否する。`start-otbr.sh` は指定をやめ、**ホスト側の値を確認**する方式にした。
  不足していれば `sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0`,
  `... net.ipv4.conf.all.forwarding=1`, `... net.ipv6.conf.all.forwarding=1` を実行。
- **otbr のエントリポイントが firewall init で die**(`ip6tables ... Table 'filter'
  does not exist`): ホストカーネルに `ip6table_filter` が無い。`start-otbr.sh` は
  `OTBR_FIREWALL`(既定 0)で otbr 内 firewall を無効化して回避する(T1 join では不要)。
  ingress フィルタが要るなら `sudo modprobe ip6table_filter` 後に `OTBR_FIREWALL=1`。
- **otbr-agent が radio を開けない**: baudrate(既定 460800。`OTBR_BAUD`)と
  デバイス名を確認。`docker logs otbr` に spinel のエラーが出る。
- **DUT のシリアルモニタ**: `espflash monitor --no-reset` は使わない(flasher stub を
  保持し無線が止まる)。`stty -F /dev/ttyACM<n> 115200 raw -echo` + `timeout N cat` で
  読む。`espflash reset` の前後は `fuser -k /dev/ttyACM<n>` でポートを解放する。
- **web GUI**: http://127.0.0.1:8080(`OTBR_HTTP_PORT` で変更)。
- **完全リセット**: `./stop-otbr.sh && docker volume rm otbr-data`。
- **REST API**: :8081(otbr-agent の rest listener。host network)。
