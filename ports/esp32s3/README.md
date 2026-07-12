# simple-matter ESP32-S3 port(M5Stack AirQ)

`simple-matter`(no_std コア)を **M5Stack AirQ(ESP32-S3FN8 / M5StampS3、
Xtensa LX7)** で動かすためのポート層。設計と経緯は
`docs/design/airq-port.md`(フェーズ A5)。

本ディレクトリは **ルート workspace とも `ports/esp32`(C6)とも独立した別
workspace**。S3 は espup の esp channel(rustc フォーク)を要求し、
`rust-toolchain.toml` が stable 前提の両者と衝突するため、workspace 分離が
必須(airq-port.md §3.3)。

> **状態(2026-07-13)**: **A5 完了 + 残改善バッチ 1 完了 — AirQ 実機
> (esp32s3 rev v0.2 / 8MB / MAC 48:27:e2:e3:0f:b8)で §7.3 チェックリスト
> 全項目 green**。SEN55/SCD40 実測値取得、chip-tool `pairing ble-wifi` フル E2E
> (--paa-trust-store-path、attestation 実検証)、smctl 2 fabric 目 +
> subscribe、リブート永続化まで確認。実機で発見した S3 固有バグ
> (main スタック逼迫 → ヒープ 112KiB 化)と検証記録は airq-port.md §7.3.1 を参照。
> **残改善バッチ 1(airq-port.md §7.4)**: EP0 に AdminCommissioning(0x003C)
> 搭載(OCW → mDNS CM=2 → smctl manual code 経由 2 fabric 目を実機 E2E 済み。
> 以降、閉窓中の直接 PASE は仕様どおり拒否される)、SEN55 温度の自己発熱補正
> -3.0°C(補正前後をログ並記)、VOC/NOx index の AirQuality worst-of 活用
> (閾値根拠は §4.3b。濃度クラスタには載せない方針は不変)。

## ツールチェーン(C6 との最大の違い)

ベアメタル target `xtensa-esp32s3-none-elf` は **upstream rustc に存在しない**
(2026-07 時点。LLVM の Xtensa backend upstream 化は進行中だが rustc target は
未完)。[espup](https://github.com/esp-rs/espup) で Espressif の rustc フォーク
(カスタムツールチェーン名 `esp`)を導入する:

```sh
cargo install espup --locked
espup install        # ~/.rustup/toolchains/esp と ~/export-esp.sh を生成
```

本ポートで確認した構成(2026-07-09):

- espup 0.16.0 / esp toolchain = **rustc 1.95.0-nightly ベースのフォーク**
  (`xtensa-esp32s3-none-elf` を built-in target として持つ)
- 同梱 GNU ツールチェーン: xtensa-esp-elf gcc 15.2.0(**リンカ**。target spec の
  既定リンカが `xtensa-esp32s3-elf-gcc` のため必須)
- esp toolchain は xtensa の **プリビルド std を含まない** →
  `.cargo/config.toml` の `build-std = ["core", "alloc"]`(rust-src 同梱)で
  core/alloc をソースからビルドする

**ビルド前に gcc へ PATH を通すこと**(espup が生成する env script):

```sh
. ~/export-esp.sh
```

`rust-toolchain.toml` の `channel = "esp"` により、このディレクトリ配下では
自動的に esp toolchain が使われる。**ルート workspace / ports/esp32(C6)の
stable ビルドには干渉しない**(コア 518 テスト green を確認済み)。

C6(RISC-V)との設定差分:

| 項目 | C6(ports/esp32) | S3(本ポート) |
|---|---|---|
| toolchain | stable + `riscv32imac-unknown-none-elf` | `esp`(espup フォーク) |
| std | プリビルド | `build-std = ["core", "alloc"]` |
| リンカ | rust-lld(target 既定) | xtensa-esp32s3-elf-gcc(`-nostartfiles` + `-Wl,-Tlinkall.x`) |
| `-C force-frame-pointers` | 必須(esp-backtrace) | 不要(Xtensa は register window を辿る) |

## 構成

```
ports/esp32s3/
├── Cargo.toml              # 別 workspace(members = ["esp32s3-firmware"])
├── rust-toolchain.toml     # channel = "esp"(espup)
├── .cargo/config.toml      # xtensa-esp32s3-none-elf 既定・build-std・gcc リンカ引数
└── esp32s3-firmware/       # lib + 複数 bin
    └── src/
        ├── main.rs         # default bin(段階 1 スモーク: バナー + TRNG + P-256 + heartbeat)
        ├── lib.rs          # 共有部(EspRng。C6 ポートから移植)
        ├── ble.rs          # GattPeripheral の TrouBLE 実装(C6 と同一ロジック)
        ├── kvs.rs          # Kvs trait の esp-storage + sequential-storage 実装
        ├── net.rs          # UDP trait 群の embassy-net 実装
        ├── wifi.rs         # WifiDriver trait の esp-radio 実装
        ├── sensors.rs      # SEN55(sen5x-rs)+ SCD40(libscd)統合タスク
        ├── display.rs      # e-ink(GDEW0154D67=SSD1681、epd-waveshare)表示タスク
        └── bin/
            ├── s3-light.rs      # 段階 2: C6 e5-light の S3 版(dual-transport、LED なし)
            ├── airq-sensor.rs   # 段階 3: AirQ 本番 FW(3 EP 空気質センサ + 実センサ)
            ├── s3-controller.rs # K2-K4: スタンドアロン常駐ハブ(UDP + BLE central、
            │                    #     複数ノード。docs/design/esp32-controller.md)
            └── s3-scan-smoke.rs # K3 冒頭ゲート: TrouBLE central の scan スモーク
```

## ビルド

```sh
. ~/export-esp.sh           # xtensa gcc(リンカ)へ PATH を通す
cd ports/esp32s3
cargo build --release --bins
```

フラッシュイメージ実測(2026-07-13、残改善バッチ 1+2 = OCW + e-ink 搭載後):

| bin | app image |
|---|---|
| esp32s3-firmware(スモーク) | 104,928 B |
| s3-light | 912,016 B(OCW 搭載後。e-ink なし) |
| airq-sensor | 981,184 B(OCW + e-ink 表示) |
| s3-controller | 690,656 B(コントローラ。BLE/センサ/e-ink なし) |

**RAM 配分の注意(S3 固有、実機で顕在化)**: S3 の DRAM リンカ領域は約 340KiB
(C6 より狭い)で、main スタック(`.stack`)は「.data/.bss の残り」になる。
ヒープ 144KiB(C6 E5 と同値)では .stack が約 37KiB しか残らず、
**コミッショニング中の P-256 署名(OpCreds invoke → sign)の同期呼び出し連鎖で
stack guard 破壊 PANIC** を実機で確認(2026-07-12)。両 Matter bin とも
**ヒープ 112KiB**(.stack ≈ 69-75KiB)に調整済み。esp-alloc の
`internal-heap-stats` を有効化しており、`[alive]` ログの `heap_max` で最高水位を
常時監視できる(E2E ピーク実測 90,160B / 114,688B — マージン約 24KiB)。

ELF は `target/xtensa-esp32s3-none-elf/release/` に生成される。

## s3-controller(K2〜K4: スタンドアロン常駐ハブ)

`docs/design/esp32-controller.md` K2〜K4 のハブ。S3 単独で bin 内の静的
`NODE_PLAN`(既定 2 ノード)を管理する: 未コミッショニングのノードを
トランスポート別にフルコミッショニング → 全ノードへ CASE → **30 秒ごとに
ラウンドロビンで OnOff Toggle → Read**。失敗ノードは mDNS 再解決 + CASE
再確立(resumption)で回復する。

- **node1(UDP、K2 パス)**: mDNS ブラウズ(discriminator subtype、QU 第一候補 +
  QM フォールバック)→ 全フェーズ UDP。対向(PC、ポート/識別子は同居用に変更):
  `SM_DISCRIMINATOR=3841 SM_MATTER_PORT=5541 SM_STATE_DIR=<dir1> \
  cargo run --release --example onoff-light`
- **node2(BLE、K3 パス)**: TrouBLE central で scan → BTP handshake →
  PASE〜AddNOC → AddOrUpdateWiFiNetwork/ConnectNetwork(smctl `pairing ble-wifi`
  相当)→ BLE close → 運用 mDNS 解決 → CASE over UDP → CommissioningComplete。
  対向(PC): `SM_BLE_ADAPTER=hci1 SM_STATE_DIR=<dir2> cargo run --release \
  -p simple-matter-ble --features device --example ble-onoff-light`

- WiFi 資格情報はコンパイル時定数(既定 iotap)。ビルド時に
  `SM_WIFI_SSID=... SM_WIFI_PASS=... cargo build ...` で差し替え可(`option_env!`)。
- 永続化(flash KVS): CA = キー `b"cast"`(smctl `ca-state.bin` v1 互換)、
  ノード帳 = キー `b"nods"`(**smctl `nodes.tlv` v1 互換** = コアの
  `controller::nodes` codec)、CASE resumption 素材 = ノードごとの `b"rsm<i>"`。
  リブート後は全ノードを復元 → 運用 mDNS 解決 → CASE(Sigma2_Resume)→
  Toggle 再開。
- **vendored trouble-host**: `vendor/trouble-host`(0.6.0 + `GattClient::subscribe`
  の 1 関数パッチ、workspace `[patch.crates-io]`)。upstream 0.6 は CCCD write
  応答後に subscriber を作るため、subscribe 直後の最初の indication(BTP handshake
  response)を 100% 取りこぼす(詳細は esp32-controller.md §7.2)。

## 実機への書き込み・観測(AirQ 接続後)

**前提**: espflash **4.x**(3.x は不可 — C6 で実証した罠。
`esp_app_desc!` 欠如を検出せず TG0 WDT リセットループを作る)。
AirQ のポートは接続後に `espflash board-info` で確認(esp32s3 / 8MB flash)。
**AirQ 以外のデバイスが同居している場合はポートの取り違えに注意**
(espflash board-info もリセットを伴う)。

```sh
espflash flash --port <PORT> target/xtensa-esp32s3-none-elf/release/airq-sensor
# 観測は stty + cat(espflash monitor --no-reset はチップが止まるため禁止):
stty -F <PORT> 115200 raw -echo
cat <PORT>
```

ブートログを頭から捕りたいときは `espflash reset -p <PORT>` → 直後に stty+cat。
**cat がポートを開いたまま reset すると DOWNLOAD モードに落ちることがある**
(USB-Serial-JTAG のストラップ干渉。AirQ 実機で確認)— reset は単独で実行する。

実機検証の残作業チェックリストは `docs/design/airq-port.md` §7.3。

## AirQ ハードウェア要点(airq-port.md §2)

- I2C: SDA=GPIO11 / SCL=GPIO12、100kHz。バス上に SEN55(0x69)+ SCD40(0x62)
  + RTC8563 が同居。
- SEN55 電源: **GPIO10 = LOW で ON**(ロードスイッチ)。ON 後 **1 秒待ち**必須。
- 電源保持: **GPIO46 = HIGH 固定**(バッテリー動作時の電源維持。起動直後に設定)。
- e-ink: GDEW0154D67(**SSD1681 系**、200x200)。SPI 10MHz mode0、
  BUSY=1(HIGH=busy)/ RST=2 / DC=3 / CS=4 / SCK=5 / MOSI=6。
  ドライバは epd-waveshare 0.6 `epd1in54_v2`(選定根拠と更新戦略 =
  airq-port.md §7.5)。30 秒毎クイック更新 + 10 分毎フル更新。
- ボタン / ブザー / RTC / バッテリー運用はスコープ外(§6)。
