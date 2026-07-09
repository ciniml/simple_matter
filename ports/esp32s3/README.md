# simple-matter ESP32-S3 port(M5Stack AirQ)

`simple-matter`(no_std コア)を **M5Stack AirQ(ESP32-S3FN8 / M5StampS3、
Xtensa LX7)** で動かすためのポート層。設計と経緯は
`docs/design/airq-port.md`(フェーズ A5)。

本ディレクトリは **ルート workspace とも `ports/esp32`(C6)とも独立した別
workspace**。S3 は espup の esp channel(rustc フォーク)を要求し、
`rust-toolchain.toml` が stable 前提の両者と衝突するため、workspace 分離が
必須(airq-port.md §3.3)。

> **状態(2026-07-09)**: A5 段階 1-3(ツールチェーン + 全 bin)ビルド green・
> clippy 0。**AirQ 実機は未検証(未接続)**。実機ゲートは
> 「AirQ 接続後のチェックリスト」(airq-port.md §7.3)を参照。

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
        └── bin/
            ├── s3-light.rs     # 段階 2: C6 e5-light の S3 版(dual-transport、LED なし)
            └── airq-sensor.rs  # 段階 3: AirQ 本番 FW(3 EP 空気質センサ + 実センサ)
```

## ビルド

```sh
. ~/export-esp.sh           # xtensa gcc(リンカ)へ PATH を通す
cd ports/esp32s3
cargo build --release --bins
```

フラッシュイメージ実測(espflash save-image、2026-07-09):

| bin | app image |
|---|---|
| esp32s3-firmware(スモーク) | 104,928 B |
| s3-light | 911,600 B |
| airq-sensor | 952,544 B |

ELF は `target/xtensa-esp32s3-none-elf/release/` に生成される。

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

実機検証の残作業チェックリストは `docs/design/airq-port.md` §7.3。

## AirQ ハードウェア要点(airq-port.md §2)

- I2C: SDA=GPIO11 / SCL=GPIO12、100kHz。バス上に SEN55(0x69)+ SCD40(0x62)
  + RTC8563 が同居。
- SEN55 電源: **GPIO10 = LOW で ON**(ロードスイッチ)。ON 後 **1 秒待ち**必須。
- 電源保持: **GPIO46 = HIGH 固定**(バッテリー動作時の電源維持。起動直後に設定)。
- e-ink / ボタン / ブザー / RTC / バッテリー運用は初期スコープ外(§6)。
