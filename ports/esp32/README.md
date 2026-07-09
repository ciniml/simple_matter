# simple-matter ESP32 port

`simple-matter`(no_std コア)を ESP32 シリーズ実機で動かすためのポート層。
本ディレクトリは **ルート workspace とは独立した別 workspace** で、esp 系依存
(esp-hal / esp-println / esp-backtrace)の lock をコアから分離する
(`docs/design/port-esp32-device.md` §7 / リスク R4)。

> **ESP32-S3(Xtensa)は `ports/esp32s3/`**(さらに別 workspace)。S3 は espup の
> esp channel(rustc フォーク)を要求し stable 前提の本 workspace と両立しない
> ため分離している(docs/design/airq-port.md §3.3。M5Stack AirQ 向け)。

現状は **E1(骨格 + TRNG)/ E2(BLE + BTP handshake)/ E3(MatterStack 統合 =
BLE フルコミッショニング)/ E4(fabric 永続化 = リブート後の CASE 再確立)** まで
実機確認済み。Wi-Fi join・UDP/mDNS は後続フェーズ(E5 以降)。

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
└── esp32c6-firmware/       # lib + 複数 bin
    └── src/
        ├── main.rs         # default bin(E1 骨格ファームウェア)
        ├── lib.rs          # 共有部(EspRng)
        ├── ble.rs          # GattPeripheral の TrouBLE 実装 + GATT worker(E2)
        ├── kvs.rs          # Kvs trait の esp-storage + sequential-storage 実装(E4)
        └── bin/
            ├── e2-ble.rs       # E2: BLE adv + BTP handshake(スタック無し)
            ├── e3-ble-light.rs # E3: MatterStack 統合 On/Off ライト(BLE フルコミッショニング)
            ├── e4-ble-light.rs # E4: e3 + fabric 永続化(リブート後 CASE 再確立)
            └── hci-smoke.rs    # 生 HCI 広告スモーク(RF 切り分け用)
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
| E2 | BLE スモーク → `GattPeripheral`(TrouBLE) | ✅ **実機確認済み**(2026-07-05、PC ble-commissioner と BTP handshake 確立) |
| E3 | BLE コミッショニング(MatterStack 統合、`e3-ble-light`) | ✅ **実機確認済み**(2026-07-06、PC ble-commissioner からフルコミッショニング+Toggle、青 LED 追従) |
| E4 | KVS + fabric 永続化(`e4-ble-light`) | ✅ **実機確認済み**(2026-07-06、リブート後に `--operational` で CASE 再確立+Toggle) |
| E5〜 | Wi-Fi join / UDP・mDNS | 未 |

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

## E2: BLE(`e2-ble` bin)

コアの `GattPeripheral` trait(ble-btp.md §5.1)を TrouBLE で実装し、
0xFFF6 commissionable アドバタイズ + C1/C2 GATT サービス + BTP handshake を通す。
MatterStack は載せない(handshake = fragment 交渉までが E2 の検証ゲート。
PASE 以降は E3)。

```sh
cd ports/esp32
cargo run --release --bin e2-ble        # flash + monitor
```

PC 側(BlueZ / btleplug が使える Linux):

```sh
cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840
```

期待ログ(デバイス側): `[ble] advertising` → `[ble] central connected` →
`[btp rx] len=9 65 6c ...`(handshake req)→ `[ble] C2 subscribed` →
`[btp tx] len=6 65 6c 04 ...`(handshake resp)→
**`[btp] established (att_mtu=..., fragment=...)`**。
PC 側は handshake 確立後 PASE に進んで失敗するが、それは E2 スコープ外
(デバイスは PASE メッセージを `[btp] rx sdu` としてログするのみ)。

**実機確認済み(2026-07-05、NanoC6 ↔ PC btleplug/hci1)**: 上記の全シーケンスを実測。
handshake 確立(device: `att_mtu=247, fragment=20` / PC: `fragment=20 window=6`)、
PASE 第 1 メッセージ(67B SDU)の 4 フラグメント再組立と ACK 返送、セッション
タイムアウトでのクリーン切断→自動再広告まで確認。

### 既知の問題と修正(E2 実機で発見)

- **切断通知の取りこぼし → 再広告されず発見不能になるバグ(修正済み)**:
  trouble-host 0.6 の `connection_manager::disconnected()` は切断イベントを
  `try_send` で通知するため、接続イベントキューが埋まった瞬間の切断は**黙って
  落ちる**。この場合 GATT worker が `Disconnected` を永遠に待ち、再広告されない
  (デバイスは生きているのに BLE スキャンから消える。スマホのスキャナアプリで
  接続→切断した後などに実機で再現)。対策として worker は 1 秒周期で
  `Connection::is_connected()` をポーリングし、イベントが落ちても確実に
  切断を回収して再広告に戻る(`ble.rs` の run_connection / send_indication)。
- **接続中は広告が止まる(仕様)**: 単一接続設計のため、スキャナアプリ等が
  接続を保持している間は他のホストから発見できない。切断すれば自動で再広告する。
- e2-ble は `[alive] t=..s conn=.. subscribed=..` を 10 秒ごとに出す(シリアルを
  後から繋いでも生存・状態確認できる)。

### 実機デバッグの罠(E2 で確認)

- **`espflash monitor --no-reset` はチップを flasher stub に入れて保持する**
  (アプリが止まり、BLE 広告も消える)。「広告が出ない」ように見えたら、まず
  モニタ方法を疑う。副作用のない観測は `stty -F /dev/ttyACM0 115200 raw -echo`
  → `cat /dev/ttyACM0`(制御線に触らない)。リセットから確実にログを取るには
  `espflash flash`(書き込み後に hard-reset でアプリ起動)直後に cat を繋ぐ。
- **`src/bin/hci-smoke.rs`**: trouble-host を外した生 HCI の広告スモーク
  (Reset→Set Adv Params/Data/Enable、`hcismoke` 名で広告 + 毎秒 heartbeat)。
  「コントローラ/ボード起因か、host 層起因か」の切り分けに使う。
- **PC 側 btleplug が発見できない問題(修正済み)**: 旧実装はスキャン時に BlueZ の
  サービス UUID フィルタ(`SetDiscoveryFilter`)へ 0xFFF6 を渡していたが、Matter の
  commissionable 広告は **service data のみ**(Service UUID リスト AD なし)のため、
  BlueZ のバージョン・キャッシュ状態によっては報告されない(Android の無フィルタ
  スキャンでは見えるのに btleplug で見えない、という実機症状)。無フィルタで
  スキャンしてコード側で照合する方式に変更。`SM_BLE_TRACE=1` で発見デバイスと
  照合判断をトレースできる。アダプタは `SM_BLE_ADAPTER=hci1` 等で明示指定。

### 使用バージョンと API 上の注意点(E2 で判明)

- **esp-radio 0.18.0**(旧 esp-wifi。features: `esp32c6, ble, unstable`):
  - `BleConnector::new(peripherals.BT, esp_radio::ble::Config::default())` が
    BLE controller(HCI)。`esp_radio::init()` の明示呼び出しは不要
    (`BleConnector::new` 内部の `RadioRefGuard` が行う)。
  - **preemptive スケジューラ必須**: `esp_rtos::start(timg0.timer0,
    sw_int.software_interrupt0)` を **radio 初期化より先に** 呼ぶ(呼ばないと
    `BleConnector::new` が panic)。
  - **ヒープ必須**(controller タスク・内部バッファ): `esp_alloc::heap_allocator!`
    で確保する。本 FW は 72KB で動作余裕を見ている(E6 で実測・調整)。
- **esp-rtos 0.3.0**(features: `esp32c6, embassy, esp-radio, esp-alloc`):
  `embassy` feature が embassy-time driver と `#[esp_rtos::main]`
  (thread-mode executor で async main を回すマクロ)を提供する。
  embassy-executor は **arch-\* feature を付けずに** 依存に入れる(esp-rtos README)。
- **trouble-host は 0.6.0 に固定**(0.7 は使えない):
  esp-radio 0.18 の `BleConnector` は **bt-hci 0.8** の `Transport` を実装するが、
  trouble-host 0.7 は **bt-hci 0.9** を要求し、trait がクレートバージョン違いで
  別物になるため `ExternalController` に渡せない。bt-hci ^0.8 の最終版が 0.6.0。
  - GATT server は `#[gatt_server]` / `#[gatt_service]` マクロで宣言
    (`heapless 0.9` / `static_cell` / `embassy-sync 0.7` を **こちらの依存にも**
    追加する必要がある — マクロ生成コードがこれらをクレート名で参照する)。
  - **negotiated ATT_MTU** は `Connection::att_mtu()`。接続直後は未交渉なので、
    bluer 版と同じく「最初の C1 write / subscribe 観測時」に `Connected` イベントへ
    載せる。
  - **CCCD(subscribe)検知**: CCCD への write も通常の `GattEvent::Write` として
    アプリに届く(`handle == c2.cccd_handle`、値の bit1=0x02 が indication)。
    `event.accept()` を呼ぶと attribute server が CCCD 状態を記録する
    (accept を忘れると `Characteristic::indicate` が黙って no-op になる)。
  - **indication は confirmation を待たない**(`Characteristic::indicate` は PDU を
    キューするだけ)。ATT は同時 1 indication 制約があるため、本実装の GATT worker が
    ATT Handle Value Confirmation(`AttClient::Confirmation`)の受信まで次の
    indicate 要求を受けない。
  - default packet pool は MTU 251 / 8 packets(`HostResources<DefaultPacketPool, 1, 1>`
    で同時 1 接続)。BTP fragment 上限 244 に対して十分。
- **サイズ実測(e2-ble, release)**: `.text` 357KB / `.rodata` 41KB /
  `.data+.bss` 約 97KB(esp-radio BLE controller + TrouBLE + BTP 込み)。

## E3: BLE コミッショニング(`e3-ble-light` bin)

`e2-ble` の pump に `MatterStack`(DefaultStack、NF=5)を統合した On/Off ライト。
PC 版 `ble-onoff-light.rs` の BLE 経路を no_std/embassy に写像したもので、
WiFi シム(`NetworkCommissioningWifi`)込み。UDP/mDNS は E5、fabric 永続化は E4。

```sh
cd ports/esp32
cargo run --release --bin e3-ble-light      # flash + monitor
```

PC 側:

```sh
cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840
```

**実機確認済み(2026-07-06、NanoC6 ↔ PC btleplug/hci1)**: PASE→CSR→AddNOC→CASE→
CommissioningComplete→**OnOff Toggle 反映**までフル完走(E3 ゲートの AddNOC を超えて
フルパス)。連続 2 回のコミッショニング(切断→再広告→2 fabric 目)も成功。
M5Stack NanoC6 の **青 LED(GPIO7)が OnOff 属性に追従**する。

実装メモ:

- **毎イテレーションで `stack.poll()` と BTP flush の両方を回す**(exchange 回収。
  回さないと AddNOC が NoSpace で黙って死ぬ — PC 実機で踏んだ教訓の移植。
  ble-btp.md §11-4)。
- 乱数は crypto/SC/OpCreds/DAC の全箇所 TRNG 直結(PC 版の DemoRng::from_time は
  std 依存のため排除)。SPAKE2+ verifier(PBKDF2)は起動時に前計算。
- BTP フラグメントトレースは既定 off(`BTP_TRACE`)。AddNOC の数十フラグメントで
  UART ログが ACK タイミングを圧迫し得るため。
- サイズ実測: flash = .text 491KB + .rodata 52KB、RAM 静的 ≈ 149KB / 512KB
  (heap 72KB 含む)。`MatterStack` 本体は約 11.3KB(main スタック上)。

## E4: fabric 永続化(`e4-ble-light` bin)

`e3-ble-light` + KVS 永続化。コアの `kvs::Kvs` trait を esp-storage +
sequential-storage で実装(`src/kvs.rs`、パーティションの nvs 領域 0x9000..0xF000
を自前フォーマットで使用 — IDF NVS 非互換)。fabric は AddNOC 直後
(generation 変化検知)に TLV で保存され、リブート時に復元される。
設計は `docs/design/port-esp32-device.md` の「E4 設計」節。

```sh
cd ports/esp32
cargo run --release --bin e4-ble-light
# run1(コミッショニング。PC 側に ca-state.bin が保存される):
cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840
#   → デバイス: [kvs] saved 1 fabrics (generation=1)
# デバイスをリセット → [kvs] restored 1 fabrics
# run2(PASE なしで運用 CASE 再確立):
cargo run -p simple-matter-ble --features commissioner --example ble-commissioner -- 20202021 3840 --operational
#   → [case] ESTABLISHED → Toggle acknowledged
```

**実機確認済み(2026-07-06、NanoC6)**: 上記フロー完走。BLE 稼働中の flash 書き込み
(AddNOC 直後)も問題なし。

### BlueZ の stale キャッシュ(PC 側の既知の罠)

デバイスのランダムアドレスは**起動毎に変わる**が、BlueZ は過去ブートの広告
(FFF6 service data 込み)をキャッシュし続けるため、スキャンが古いアドレスに
マッチして **connect がタイムアウト/abort する**ことがある。症状が出たら:

```sh
for d in $(bluetoothctl devices | awk '{print $2}'); do
  bluetoothctl info "$d" | grep -qi fff6 && bluetoothctl remove "$d"
done
```

## E5: Wi-Fi 実 join + UDP/mDNS(`e5-light` bin)

`e4-ble-light` + **実 Wi-Fi + UDP dual-transport**。chip-tool の
`pairing ble-wifi`(実 SSID)が最後まで通る構成。設計は
`docs/design/port-esp32-device.md` の「E5 設計」節。

- **Wi-Fi**: コアの `wifi::WifiDriver` trait(E5 で追加)を esp-radio で実装
  (`src/wifi.rs`)。ConnectNetwork の invoke ハンドラ(同期)は要求を
  `Signal` に置くだけで、join(`connect_async`)は常駐 `wifi_task` が実行する。
  BLE とは esp-radio の `coex` feature で同時動作。切断時は自動再接続。
- **UDP**: コアの `UdpSend`/`UdpReceive`/`UdpMulticast` trait を embassy-net 0.9 の
  `UdpSocket` で実装(`src/net.rs`、**trait 実利用第 1 号**)。DHCPv4 +
  IPv6 リンクローカル(fe80、MAC 由来の modified EUI-64 を `StaticConfigV6` で静的設定)。
  Matter UDP は 5540(v4/v6 両受け)。
- **mDNS**: DHCP で IPv4 取得後に 5353 + 224.0.0.251(IGMP join)**および ff02::fb
  (MLD join)**で、コアの sans-IO `MdnsResponder` を駆動。A に DHCP v4、AAAA に fe80 を
  載せる(`docs/design/mdns-ipv6.md` §4)。operational レコードのみ広告
  (commissionable は BLE 広告が担う)。QU クエリにはユニキャスト応答、QM は受信
  ファミリ側のマルチキャストへ返す。
- ConnectNetworkResponse は**即 Success + バックグラウンド join**
  (シムで chip-tool 相互運用実証済みのフロー。遅延応答は将来課題、doc §E5.2)。
- ヒープは 144KiB(E4 の 72KiB → E5 の 112KiB から再増量)。IPv6(proto-ipv6)追加後、
  BLE+Wi-Fi coex 中の大型応答(attestation/CSR)で ATT エラー切断が再発し、ヒープ圧が
  原因だった(112KiB では枯渇)。144KiB で安定(.stack は 162K→130K に減るが十分)。

```sh
cd ports/esp32
cargo run --release --bin e5-light
# chip-tool でコミッショニング(実 SSID/パスワードを渡す):
chip-tool pairing ble-wifi 1 <SSID> <PASS> 20202021 3840 --bypass-attestation-verifier true
# 期待ログ列:
#   [ble] connected → [btp] established → PASE/CSR/AddNOC(BLE)
#   → [wifi] connecting to "<SSID>" → [wifi] associated → [net] DHCP up: ip=...
#   → [mdns] operational advertising → CASE over UDP → CommissioningComplete
# 操作:
chip-tool onoff toggle 1 1   # → [onoff] light is now ON / GPIO7 の青 LED 追従
```

## E6: フェーズ別サイズ実測(`size -A`、release、opt-level="s" + LTO)

全 bin の ELF セクションサイズ(単位バイト、ホスト `size -A`。
`.text_gap` はメモリレイアウト上のパディングのため除外):

| bin(フェーズ) | .text | .rodata(+wifi) | .rwtext(+wifi) | .data(+wifi) | .bss | flash 概算† | RAM 常駐‡ |
|---|---:|---:|---:|---:|---:|---:|---:|
| `esp32c6-firmware`(E1 骨格) | 40,654 | 11,472 | 2,076 | 732 | 536 | 55K | 3.3K |
| `e2-ble`(E2 BLE スモーク) | 369,814 | 45,784 | 30,288 | 7,068 | 90,900 | 453K | 128K |
| `e3-ble-light`(E3 コミッショニング) | 502,174 | 56,568 | 29,832 | 7,812 | 110,908 | 596K | 149K |
| `e4-ble-light`(E4 + 永続化) | 525,060 | 58,456 | 30,200 | 7,892 | 112,448 | 622K | 151K |
| `e5-light`(E5 + Wi-Fi/UDP/mDNS/IPv6) | 901,924 | 127,720 | 80,772 | 13,652 | 190,176 | 1,124K | 285K |

† flash 概算 = .text + .rodata(+wifi) + .rwtext(+wifi) + .data(+wifi)(ロードイメージ)。
‡ RAM 常駐 = .rwtext(+wifi) + .data(+wifi) + .bss(スタック除く)。
E2〜E4 の .bss はヒープ 72KiB を、E5 は 112KiB を含む(esp-alloc の
`heap_allocator!` は .bss に確保)。E5 の RAM 常駐 285KiB は C6 の SRAM 512KiB に
収まる(残り ~227KiB がタスクスタック等)。E5 の増分(flash +474K / RAM +134K)は
ほぼ esp-radio の Wi-Fi ドライバ + smoltcp/embassy-net によるもの。
bloat-check crate の C6 対応拡張はスコープ外(doc §8 E6 行のとおり記録のみ)。

IPv6(運用 mDNS を ff02::fb でも提供、`docs/design/mdns-ipv6.md` §4)の追加コストは
smoltcp `proto-ipv6` + MLD 分で **flash +~50K(.text +45K / .rodata +5K)/ RAM(.bss)
+~2K**(v6 なし版の e5-light 比、`size -A`)。リンクローカル fe80 は MAC 由来の
modified EUI-64 を `StaticConfigV6` で静的設定(SLAAC 不要)。
