# simple_matter

小フットプリントの Matter プロトコル実装(Rust)。コアは `#![no_std]`・**sans-IO**
(プロトコル処理はソケット/無線 I/O を持たず、バイト列の入出力だけを扱う)で、
**定常状態のデータパス(メッセージ送受信・セッション・IM 処理)はヒープ確保しない**。
alloc は optional feature とし、コアのプロトコル処理は alloc 無しで成立する。
設計思想と原則は [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) を参照。

connectedhomeip の肥大への対処として出発し、rs-matter の公称下限
(1 MB flash / 256 KB RAM)を大きく下回ることを実測で確認しながら、
デバイス側スタックとコントローラ側(コミッショナ+CLI)の両方を実装している。

## 実績・特徴

- **コア 519 テスト**(暗号化込みバイト列レベルの PASE→フルコミッショニング→CASE→操作
  の縦通し E2E を含む)、clippy warning 0、CI で no_std / クロスビルド / フットプリントを常時検証
- **サーバクラスタ 32 種**(Basic Information / OpCreds / ACL / Group Key Management 等の
  ユーティリティ系から、On/Off / Level Control / Color Control / Thermostat / Door Lock /
  Switch / Fan / Window Covering / センサ計測 5 種 / Air Quality+濃度計測 6 種まで)、
  **デバイスタイプ 17 種**の example / ファームウェア構成
- **chip-tool 実機相互運用**: pairing(onnetwork / ble-wifi)〜属性 read/write・subscribe・
  イベント・timed interaction まで。**attestation は実検証**(PAA trust store による DAC
  チェーン検証+CD の CMS 署名検証+VID/PID クロスチェック。`--bypass` 不要)
- **コミッショニング経路**: UDP(mDNS commissionable)、**BLE(BTP)**、
  BLE→WiFi プロビジョニング(`pairing ble-wifi`)。Open Commissioning Window(ECM)
  によるマルチ fabric も実機 E2E 済み
- **CASE resumption**(Sigma2Resume、KVS 永続化込み)、**Subscribe(属性+イベント)**、
  **full ACL**(per-entry 権限 enforcement、CAT 照合)、**groupcast 受信**
  (グループ鍵導出+マルチキャスト経路)
- **fabric / ACL / resumption / WiFi 資格情報の KVS 永続化**(リブート後の CASE 再確立を実機確認)
- **コントローラ側も同一コア**: PASE/CASE initiator、IM クライアント、mDNS ブラウズ/解決、
  コミッショナ+CA(`controller` feature、デバイス専用ビルドへのサイズ影響は CI で閾値検証)
- mDNS は IPv4/IPv6(fe80)両対応、QU ユニキャスト応答・VPN(WireGuard)越え実測済み

## フットプリント(実測)

| 対象 | flash | RAM |
|---|---:|---:|
| コア一式(thumbv7em、opt-level=z + LTO、`crates/bloat-check` 実測) | **約 102 KB**(.text 95,284 + .rodata 6,780 B) | **DefaultStack 23,982 B(約 23.4 KiB)** / MinimalStack 16,006 B |
| ESP32-C6 `e5-light`(BLE+WiFi+UDP/mDNS/IPv6 フル構成) | 約 1,124 KB | 常駐 約 285 KB / SRAM 512 KB(ヒープ 112 KiB 含む) |
| ESP32-S3 `airq-sensor`(SEN55/SCD40+e-ink+OCW) | 981,184 B(8 MB flash の 12% 弱) | ヒープ実測ピーク 約 90 KB / 112 KiB |

コア一式は rs-matter 公称下限(1 MB flash / 256 KB RAM)の**約 1/10**。
計測方法と再現手順は [crates/bloat-check](crates/bloat-check/)(CI 組み込み済み)。

## 構成

- [crates/simple-matter](crates/simple-matter/) — コアクレート(`#![no_std]`、sans-IO)。
  デバイス側スタック+`controller` / `ble` は optional feature。examples/ に PC で動く
  デバイス例 9 種(onoff-light / dimmable-light / thermostat / sensor-hub / switch-demo /
  color-light / door-lock / air-quality-sensor / commissioner)
- [crates/simple-matter-ble](crates/simple-matter-ble/) — PC 実 BLE バックエンド
  (device=bluer / commissioner=btleplug)。BLE コミッショニングの PC 側実行環境
- [crates/smctl](crates/smctl/) — **chip-tool 代替の CLI コントローラ**(pairing 各種 /
  read / write / subscribe / invoke / batch / OCW / unpair、`~/.smctl/` に CA と
  アドレス帳を永続化)。設計は [docs/design/cli-controller.md](docs/design/cli-controller.md)
- [crates/bloat-check](crates/bloat-check/) — フットプリント計測(RAM size_of レポート+
  MCU クロスビルド flash probe)
- [ports/esp32](ports/esp32/) — ESP32-C6 ポート(M5Stack NanoC6。別 workspace)
- [ports/esp32s3](ports/esp32s3/) — ESP32-S3 ポート(M5Stack AirQ。Xtensa、さらに別 workspace)

### ドキュメント

- [設計方針](docs/ARCHITECTURE.md) — レイヤ構成・設計原則・ロードマップ
- [docs/design/](docs/design/) — 機能別設計 doc(
  [transport/exchange](docs/design/transport-exchange.md)・
  [Secure Channel](docs/design/secure-channel.md)・
  [Interaction Model](docs/design/interaction-model.md)・
  [BLE/BTP](docs/design/ble-btp.md)・
  [ACL](docs/design/acl.md)・
  [attestation](docs/design/attestation.md)・
  [コントローラ](docs/design/controller.md)・
  [group messaging](docs/design/group-messaging.md)・
  [ESP32 ポート](docs/design/port-esp32-device.md)・
  [AirQ ポート](docs/design/airq-port.md) ほか)
- 既存実装の構造調査: [rs-matter](docs/research/rs-matter.md) /
  [matter.js](docs/research/matter-js.md) /
  [connectedhomeip](docs/research/connectedhomeip.md)

## クイックスタート(PC)

On/Off ライトのデバイス例を起動し、`smctl` でコミッショニングして操作する:

```sh
# ターミナル 1: デバイス(SM_STATE_DIR を与えると fabric 等を永続化)
cargo run --release --example onoff-light

# ターミナル 2: コミッショニング(mDNS ブラウズ → PASE → AddNOC → CASE)+操作
cargo run -p smctl --release -- pairing onnetwork 1 20202021
cargo run -p smctl --release -- onoff toggle 1
cargo run -p smctl --release -- onoff subscribe on-off 1
```

chip-tool からも同様にコミッショニングできる(attestation 実検証込み):

```sh
chip-tool pairing already-discovered 1 20202021 127.0.0.1 5540 \
    --paa-trust-store-path <テスト PAA ディレクトリ>
chip-tool onoff toggle 1 1
```

ESP32 実機への書き込み・BLE/WiFi コミッショニング手順は各ポートの README を参照:
[ports/esp32/README.md](ports/esp32/README.md)(NanoC6)/
[ports/esp32s3/README.md](ports/esp32s3/README.md)(AirQ)。

## 実機実績

- **M5Stack NanoC6**(ESP32-C6): `e5-light` で chip-tool `pairing ble-wifi` フルパス
  (BLE コミッショニング→WiFi join→運用 mDNS→CASE over UDP)、青 LED の
  On/Off+PWM 調光(Dimmable Light)、リブート永続化
- **M5Stack AirQ**(ESP32-S3): `airq-sensor` で SEN55/SCD40 実測値の
  Air Quality+濃度計測クラスタ配信、e-ink 表示、OCW によるマルチ fabric
- **Windows**: `smctl.exe` / BLE コミッショナを cargo-xwin で Linux からクロスビルドし、
  Windows 実機から BLE/mDNS/UDP コミッショニングを完走

## ライセンス

[Boost Software License 1.0](LICENSE_1_0.txt)(BSL-1.0)
