# 調査・検討サマリ(2026-07-14 時点)

実装済み機能の全体像と、調査済み・実装待ちの検討事項を 1 枚に集約する。
詳細は各設計 doc へ。再開手順は `HANDOFF.md`、進捗詳細は自動メモリ(project-status)。

## 1. 実装完了(実機検証済み)

| 領域 | 内容 | doc |
|---|---|---|
| コア | no_std sans-IO Matter スタック。PASE/CASE/resumption/MRP/IM(Read/Write/Invoke/Subscribe/Timed/イベント)/full ACL/OCW/groupcast 受信/fail-safe 巻き戻し/attestation(DAC+CD CMS)。テスト 525+ | ARCHITECTURE.md、secure-channel.md、interaction-model.md、acl.md、group-messaging.md、attestation.md |
| クラスタ | サーバ 32 種(Matter 1.3 基本域)+ デバイスタイプ 17 種。`cluster!`/`measurement_cluster!`/`concentration_cluster!` の単一ソースマクロ | basic-clusters.md |
| コントローラ | Commissioner/CASE initiator/ImClient/MdnsClient(コアも no_std)。smctl = chip-tool 代替 CLI(pairing 4 方式、any、--names、resumption、詳細ログ、Windows exe) | controller.md、cli-controller.md |
| ポート | Windows(W0-W4)、ESP32-C6 デバイス(E0-E6)、ESP32-S3 デバイス=AirQ(A1-A5)、ESP32-S3 コントローラ/常駐ハブ(K1-K4) | port-windows-commissioner.md、port-esp32-device.md、airq-port.md、esp32-controller.md |
| AirQ | SEN55/SCD40 + e-ink + OCW + 温度補正 + VOC/NOx 活用。旧 esp-matter FW のバグ 2 件是正。FW 980KB | airq-port.md |
| VPN | WireGuard 実測(V1 = smctl `--at` QU ユニキャスト直送)。tailscale/DERP は未実測 | matter-over-vpn.md |

フットプリント(実測): コア flash 約 102KB / RAM 約 23.4KB(thumbv7em、rs-matter 比 ~1/10)。
AirQ デバイス FW 980KB(8MB の 12%)、S3 コントローラ FW 879KB(コントローラ正味 ≈83KB)。

## 2. 調査済み・実装待ち

### 2.1 Thread 対応(T1 準備完了、**機材待ち**)— thread-port.md

- openthread 0.2(esp-rs)= C 製 OpenThread + Rust バインディング。**プリビルト .a で
  stable rustc のみでビルド green 確認済み**。SRP client(TXT 対応)ネイティブあり。
- 確定制約: esp-radio 0.18 は 802.15.4×WiFi 同時不可(ble+15.4 は可 = ble-thread 成立)。
  Thread 系は `ports/esp32/esp32c6-thread` に分離済み。
- 準備済み: `thread-smoke` bin(ビルド green)、OTBR docker スクリプト+ot_rcp FW ビルド済み
  (`scripts/otbr/`)。
- **待ち**: C6 ボード 2 枚(RCP 用+DUT 用)。リスク R3 = NanoC6 の USB-Serial-JTAG で
  spinel が通るか未確認(不可なら外付け UART or DevKitC)。
- 計画: T1(join スモーク)→ T2(ThreadDriver trait + NetworkCommissioning Thread +
  SRP → chip-tool ble-thread)→ T3(運用 E2E)→ I1(ICD、下記)。

### 2.2 ICD(省電力)— thread-port.md §I1

- Thread 実装後に着手する判断済み(ICD の価値が Thread 電池デバイスに依存、
  リスクの前倒しは Thread 側)。ICD Management cluster + check-in プロトコル +
  LIT/SIT + ESP32 deep sleep 統合。AirQ のバッテリー対応と合流。

### 2.3 nRF52/nRF54・NXP RW612 — port-nrf-rw612.md

- **nRF52840 = ベアメタル Rust 路線が本命**(embassy-nrf + TrouBLE/nrf-sdc +
  openthread embassy-nrf feature。継ぎ目 trait 対応表で ESP32 資産の写像のみ)。
- **nRF54L15 = BLE まで**(Rust に 802.15.4 ドライバ不存在)。
- **RW612 = Zephyr 統合が唯一解**(Rust HAL 不存在、WiFi/BLE ブロブは Zephyr のみ)。
  方式は zephyr-lang-rust でなく **staticlib + C FFI シム約 10 本**(sans-IO の利点。
  API 素案 doc §4)。シムは nRF の Zephyr 環境にも使い回し可。
- 検証済み: コアは thumbv8m.main(M33)で all-features check green(コード変更ゼロ)。
- 最初の一手: **N1 = nRF52840 DK の BLE スモーク**(controller を nrf-sdc に差し替えるだけで
  ESP32 E2 と同一ゲート)。**機材待ち**(nRF52840 DK)。
- 参考実装: rs-matter-embassy(git)が nRF52840 で Matter over Thread 動作
  (BLE+15.4 共存方式のリファレンス)。

### 2.4 その他の将来課題(記録済み)

- OTA、ScenesManagement(スキップ判断済み・再開入口記録あり)、groupcast 送信側、
  CD 署名者の動的検証(CSA 002-005)、ACL の残り(redact/deviceType target/Extension)、
  AirQ の QR 表示・ボタン・湿度連動温度補正、tailscale/DERP 実測。
- **上流貢献候補**(実機で発見・裏取り済み): trouble-host 0.6 の切断 try_send 取りこぼし、
  同 `GattClient::subscribe` の初回 indication 喪失(vendor パッチ済み)、
  sen5x-rs の温度 u16/i16 バグ。

## 3. 機材待ちリスト

| 機材 | 用途 | 解除されるタスク |
|---|---|---|
| ESP32-C6 ボード ×2(RCP 用+DUT 用) | Thread 検証(OTBR + デバイス) | T1〜T3、その後 I1(ICD) |
| nRF52840 DK | Nordic ポート | N1〜N3 |
| (任意)SEN55/SCD40 Grove | NanoC6 での AirQ 相当ブリッジ構成 | airq-port.md A3(C6 ブリッジ) |
| (任意)FRDM-RW612 | Zephyr シム検証 | Z1〜Z2 |

## 4. ハードウェア注意(運用メモ)

- AirQ(現在 /dev/ttyACM0)には K4 版 s3-controller が焼き込み済み。センサ FW へ戻すのは
  ビルド済み `airq-sensor` の espflash 一発。
- /dev/ttyACM1 はユーザの別デバイス(**アクセス禁止**)。ポートは接続の度にユーザに確認する。
- 過去に誤認で ACM1 の旧 S3 devkit へスモークを書き込んだ経緯あり(元 FW 消去済み、
  ユーザへ報告済み)。
