# simple-matter ESP32 port

`simple-matter`(no_std コア)を ESP32 シリーズ実機で動かすためのポート層。
本ディレクトリは **ルート workspace とは独立した別 workspace** で、esp 系依存
(esp-hal / esp-println / esp-backtrace)の lock をコアから分離する
(`docs/design/port-esp32-device.md` §7 / リスク R4)。

現状は **フェーズ E1(ports 骨格 + 起動ログ + TRNG→Rng)** のみ。
BLE コミッショニング・Wi-Fi join・UDP/mDNS は後続フェーズ(E2 以降)。

## ターゲット: ESP32-C6 を選んだ経緯

設計 doc(`docs/design/port-esp32-device.md`)は最小ターゲットを ESP32-**C3** と
していたが、本ポートは **ユーザ指定で ESP32-C6** を採用する。

- C6 は RISC-V(**RV32IMAC**)。ターゲット `riscv32imac-unknown-none-elf` は
  **upstream の stable Rust** で完結し、Xtensa(無印/S3)の `espup` 依存を避けられる
  (C3 と同じ利点。設計 doc §0-2, §1)。
- C6 は SRAM 512KB / Wi-Fi6 + BLE5 で、C3(400KB / Wi-Fi4)より余裕がある。
- コア(`simple-matter`)側は一切変更せず、`default-features = false` +
  `rustcrypto,ble` で組み込む。

## 構成

```
ports/esp32/
├── Cargo.toml              # 別 workspace(members = ["esp32c6-firmware"])
├── rust-toolchain.toml     # stable + riscv32imac ターゲット
├── .cargo/config.toml      # ターゲット既定・linkall.x・force-frame-pointers・espflash runner
└── esp32c6-firmware/       # bin crate(E1 骨格ファームウェア)
    └── src/main.rs
```

## 前提

- Rust stable(`rust-toolchain.toml` が `riscv32imac-unknown-none-elf` を自動追加)。
- 書き込み/モニタには [`espflash`](https://github.com/esp-rs/espflash) **v4 以降**が必要:

  ```sh
  cargo install espflash --locked
  ```

  **espflash 3.x は不可**(2026-07-05 実機で確認した罠): アプリディスクリプタを検証せず
  書き込むため一見成功するが、ブートローダがアプリを起動できず **TG0 WDT リセット
  ループ**(`rst:0x7 (TG0_WDT_HPSYS)` の繰り返し・アプリログ一切なし)になる。
  espflash 4.x は欠如を書き込み時に検出して明確なエラーを出す。なお 3.3.0 は C6 への
  stub 接続自体もタイムアウトすることがある(`--no-stub` では接続可)。

- ESP32-C6 ボード(USB シリアル/JTAG 経由)。

## ビルド

```sh
cd ports/esp32
cargo build --release
```

`.cargo/config.toml` で `target = "riscv32imac-unknown-none-elf"` が既定のため
`--target` 指定は不要。ELF は
`target/riscv32imac-unknown-none-elf/release/esp32c6-firmware` に生成される。

## 実機への書き込み・モニタ(次の手順)

`runner = "espflash flash --monitor"` を設定済みなので、C6 を USB 接続して:

```sh
cd ports/esp32
cargo run --release
```

これで flash 書き込み後にシリアルモニタが開く。ボーレート指定やポート明示が
必要なら:

```sh
espflash flash --monitor \
  --baud 115200 \
  --port /dev/ttyACM0 \
  target/riscv32imac-unknown-none-elf/release/esp32c6-firmware
```

### 期待されるシリアル出力(実機)

```
======================================================
 simple-matter :: ESP32-C6 port (phase E1 skeleton)
 target   : riscv32imac-unknown-none-elf (stable Rust)
 hal      : esp-hal 1.1.1
 scope    : boot log + TRNG -> crypto::Rng + P-256 keygen
======================================================
[trng] SAR ADC entropy source enabled; TRNG ready
[trng] sample bytes: .. .. .. .. ...
[crypto] RustCrypto backend built with EspRng (esp-hal TRNG)
[crypto] P-256 keypair generated. public key (SEC1) [65B]:
[crypto]   04 .. .. .. .. .. .. .. ...
[crypto]   SEC1 tag (expect 0x04): 0x04
[boot] E1 checks done. entering 1 Hz heartbeat loop.
[heartbeat] tick 0
[heartbeat] tick 1
...
```

## E1 の位置づけ(`docs/design/port-esp32-device.md` §8)

| フェーズ | 範囲 | 本ポートの状態 |
|---|---|---|
| E1 | ports 骨格 + 起動ログ + TRNG→`crypto::Rng` + P-256 鍵生成 | ✅ **実機確認済み**(2026-07-05、M5Stack NanoC6) |
| E2 | BLE スモーク → `GattPeripheral`(TrouBLE) | 未 |
| E3〜 | コミッショニング / KVS / Wi-Fi join / UDP・mDNS | 未 |

実機確認(2026-07-05、M5Stack NanoC6 / ESP32-C6 rev v0.1、USB シリアル/JTAG =
`/dev/ttyACM0`): 期待ログの全項目(バナー → `[trng]` サンプル → P-256 公開鍵
SEC1 tag 0x04 → 1 Hz heartbeat 継続)を確認。WDT リセットなしで安定動作。

E1 が実機で証明するのは「esp-hal で C6 が起動しログが出る」「esp-hal の **真性乱数
(TRNG)** をコアの `crypto::Rng` trait に橋渡しできる」「その RNG でコアの
RustCrypto バックエンドが **P-256 鍵ペアを生成できる**」の 3 点(コアの暗号 +
プラットフォーム TRNG が実チップ上で動く最小証明)。LED ピンはボード依存のため、
点滅の代わりに 1 秒ごとのカウンタログで生存を示す。

### TRNG について

esp-hal の `Trng` は `TrngSource`(SAR ADC のエントロピー源)が有効な間だけ
真性乱数を供給する。本 FW は `TrngSource` を main の生存期間中保持し、`Trng` を
`EspRng` アダプタでコアに注入する。ADC を占有するため、後続フェーズで ADC を
別用途に使う場合は方式を見直す(設計 doc §5: 「Wi-Fi/BLE 有効時に真性乱数である旨」
も併せて、E2 以降で esp-radio 有効時のエントロピー源を再評価する)。

## サイズ実測(E1, `cargo build --release`, opt-level="s" + LTO)

`size -A` による ELF セクションサイズ(ホスト `size`、単位バイト):

| セクション | サイズ | 備考 |
|---|---:|---|
| `.text` | 40,654 | 実コード |
| `.rodata` | 11,472 | 定数・文字列 |
| `.data` | 732 | 初期化済みデータ(RAM 常駐) |
| `.bss` | 536 | 未初期化データ(RAM) |

- `size`(BSD 形式)の `text` 合計 557,034 には、メモリレイアウト上のパディング
  `.text_gap`(54,064)が含まれるため、実コード量は上表の `.text` 40,654 で読む。
- これは **BLE/Wi-Fi(esp-radio)を含まない E1 骨格**の値。フットプリントの本計測は
  設計 doc の E6(bloat-check 拡張)で BLE/Wi-Fi 込みの実測を行う。

## 使用した esp-hal のバージョンと API 上の注意点

- **esp-hal 1.1.1**(1.0 系で API が大きく変わっており、以下は 1.x の実 API に準拠):
  - 初期化: `esp_hal::init(Config::default().with_cpu_clock(CpuClock::max()))` が
    `Peripherals` を返す。エントリは `#[esp_hal::main]`(旧 `#[entry]` ではない)。
  - TRNG: `esp_hal::rng::Rng::new()` は **擬似乱数**。真性乱数には
    `esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1)` で ADC
    エントロピー源を有効化してから `Trng::try_new()` を呼ぶ。`TrngSource` を
    drop すると擬似乱数に戻るため、生存させ続ける必要がある(`unstable` feature)。
    読み出しは `Trng::read(&mut [u8])`。
  - `unstable` feature が必要(`TrngSource` / `Trng` / `Delay` 等)。`Cargo.toml` で
    `esp-hal = { features = ["esp32c6", "unstable"] }`。
- **esp-println 0.17.0**: `esp_println::println!` マクロで直接シリアル出力
  (logger 初期化不要)。feature は `esp32c6`。
- **esp-backtrace 0.19.0**: feature は `esp32c6, println, panic-handler`
  (`exception-handler` feature は **存在しない** ので付けるとビルド失敗する)。
  `use esp_backtrace as _;` でリンクする。
- **esp-bootloader-esp-idf 0.5.0**(**必須**): `esp_bootloader_esp_idf::esp_app_desc!()`
  をアプリに 1 回置いて ESP-IDF アプリディスクリプタを埋め込む。無いとブートローダが
  アプリを起動できず TG0 WDT リセットループになる(前掲「前提」の espflash 3.x の罠と
  同根。espflash 4.x なら書き込み時にエラーで検出される)。feature は `esp32c6`。
- **リンク**: `.cargo/config.toml` の rustflags に `-C link-arg=-Tlinkall.x`
  (esp-hal の build.rs が `linkall.x`→`memory.x`/`esp32c6.x`/`hal-defaults.x` を
  `OUT_DIR` に配置)と、RISC-V で **必須の** `-C force-frame-pointers`
  (esp-backtrace README)を指定する。
