# 作業ハンドオフ(2026-07-05 時点)

別セッションで作業を再開するための状態記録。全体の設計方針は `docs/ARCHITECTURE.md`、
個別設計は `docs/design/*.md`、進捗の要約は自動メモリ(`MEMORY.md` → `project-status.md`)
にもある。本ファイルは「BLE コミッショニング + 2 プラットフォーム移植(Windows / ESP32-C6)」
の作業を再開するための即時参照。

## 1. 現在地(1 行サマリ)

BLE コミッショニングは chip-tool 相互運用まで達成済み。移植は **Windows: W0-W3 完了
(W3 は mDNS ディスカバリ込みで実機フル完走、2026-07-05)**、
**ESP32-C6: E1〜E4 実機確認済み(E4 = fabric 永続化、リブート後に `--operational` で
CASE 再確立+Toggle、2026-07-06)。次は E5(実 WiFi join + UDP/mDNS)**。

## 2. リポジトリ状態

- ブランチ `master`、ワーキングツリー **クリーン**(全コミット済み)。
- 直近コミット(新しい順):
  - `b58793a` W3: mDNS マルチキャスト受信と QU ユニキャスト応答の修正
  - `4b88f94` W3: UDP commissioner の Windows 対応(QU クエリモード)
  - `a8d8298` W2 記録: Windows commissioner の BLE フルコミッショニング
  - `7dd9db1` W1 記録: Windows 実機で R1/R2 解消
  - `25d2aaa` ports/esp32: ESP32-C6 の E1 骨格 FW
  - `6cb87b8` W1 手順とクロスビルド recipe
  - `7139451` ports W0/E0: CI クロスチェック
  - `7d32a6c` 移植調査 doc 2 本
  - `8eef4aa` chip-tool BLE フルコミッショニング(WiFi シム + dual-transport)
- テスト: `cargo test -p simple-matter --features ble,controller` → **310 passed**。
- 実行中プロセス: `onoff-light`(UDP デバイス)が **192.168.2.14:5540** で待ち受け中
  (別セッションでは終了している可能性が高い。W3 再テストには再起動が必要。§5 参照)。

## 3. 主要な設計ドキュメント

| doc | 内容 |
|---|---|
| `docs/design/ble-btp.md` | BTP 設計。GATT 抽象 trait(`GattPeripheral`/`GattCentral`)、MRP 無効化、確立順序 |
| `docs/design/controller.md` | コントローラ(commissioner/initiator)設計 |
| `docs/design/port-windows-commissioner.md` | Windows 移植。§3.0 に W3 の mDNS 知見、末尾にフェーズ表(W0-W4) |
| `docs/design/port-esp32-device.md` | ESP32 移植。推奨 no_std 路線、フェーズ表(E0-E6) |

## 4. 達成済み(検証レベル付き)

### BLE コミッショニング(コア)
- BTP エンジン(`src/btp/`、sans-IO・no_std・ヒープレス)、`GattPeripheral`/`GattCentral` trait。
- chip-tool `pairing ble-wifi` フルパス実機成功(`8eef4aa`)。`NetworkCommissioningWifi`
  (WiFi シム)+ `ble-onoff-light`(BLE+UDP+mDNS dual-transport)。
- BTP ワイヤ互換の実機修正 4 件(`8a83fe1`): seq 規約(handshake 応答=暗黙 seq0)、
  handshake req mtu=0=不明、確立順序(C1 write→subscribe)、寛容 ACK。

### Windows commissioner 移植
- **W0** ✅: CI に `windows-commissioner` ジョブ、bluer を Linux target 依存化。
- **W1** ✅ 実機: `ble-commissioner.exe`(cargo-xwin クロスビルド)で scan/service data
  取得(R1)・subscribe 前 write(R2)とも問題なし。
- **W2** ✅ 実機: Windows `ble-commissioner.exe` → Linux `ble-onoff-light` へ BLE フル
  コミッショニング + Toggle 完走(fragment=20、115 フラグメント)。
- **W3** ✅ 実機フル完走(mDNS ディスカバリ込み、2026-07-05):
  - Windows(192.168.2.11)`commissioner.exe 20202021`(**IP 指定なし**)で
    **mDNS ブラウズ→発見→UDP フルコミッショニング→Toggle→Read 完走**。
  - 当初 mDNS が 35 秒タイムアウトした**真因はマルチキャスト送信/join の IF 未指定**
    (コード欠陥)。FW 仮説は棄却(FW 無変更で成功)。詳細と実機ログは
    `port-windows-commissioner.md` §3.2c。
  - 実装内容(以下は完了):
  - UDP commissioner の Windows 対応(QU クエリ + エフェメラルポート)。
  - **マルチキャスト IF の明示固定**(connect トリックで LAN 向き IF を選び
    `IP_MULTICAST_IF` + join に指定。Windows パスのみ)。
  - **`SM_MDNS_TRACE=1`** で browse 中の送出クエリ・受信パケットを stderr にトレース。
  - responder の QU ユニキャスト応答(`MdnsResponder::query_wants_unicast`、
    `Question.unicast`、単体テスト `detects_qu_unicast_requests`)。QU 応答パスは
    avahi 不在のクリーン環境(docker + lo 閉域)でソケット E2E 実証済み。
  - 全 mDNS listener を `SO_REUSEPORT`→`SO_REUSEADDR` に(REUSEPORT はマルチキャストを
    listener 間でロードバランスして奪う)。
  - commissioner の browse を **35 秒 window + 2 秒ごと再クエリ**に(旧 5 秒)。
  - Linux UDP フルパスは改修後も回帰なし(発見→コミッショニング→Toggle→Read 実測)。

### ESP32-C6 移植
- **E0** ✅: コアの `riscv32imc-unknown-none-elf` クロスビルド(CI 済み、コード変更ゼロ)。
- **E1** ✅ 実機確認(2026-07-05、M5Stack NanoC6 / `/dev/ttyACM0`): 期待ログ全項目
  (バナー → `[trng]` → P-256 公開鍵 SEC1 tag 0x04 → 1 Hz heartbeat 継続)を確認。
  実機で発見・修正した罠 2 つ(詳細 `ports/esp32/README.md`):
  - **`esp_bootloader_esp_idf::esp_app_desc!()` が必須**(esp-bootloader-esp-idf 0.5.0 を
    追加)。無いとブートローダがアプリを起動できず **TG0 WDT リセットループ**
    (`rst:0x7`、アプリログなし)。
  - **espflash 4.x 必須**(4.4.0 に更新済み)。3.3.0 はディスクリプタ欠如を検出せず
    書き込む + C6 への stub 接続がタイムアウトする(`--no-stub` は可)。
  - 非 TTY 環境では `espflash flash --monitor` が「Failed to initialize input reader」で
    落ちる → `script -qec "espflash flash --monitor ..." /dev/null` で pty を与える。
- **E2** ✅ 実機確認(2026-07-05、NanoC6 ↔ PC ble-commissioner/btleplug hci1):
  TrouBLE 0.6(esp-radio 0.18 = bt-hci 0.8 に合わせ、0.7 は不可)で `GattPeripheral`
  実装(`ports/esp32/esp32c6-firmware/src/ble.rs`、worker⇔channel 構造)。
  **BTP handshake 確立**(fragment=20)、PASE 第 1 SDU(67B)の 4 フラグメント
  再組立 + ACK、タイムアウト切断→自動再広告まで実測。
  - 実機切り分けの罠(README に詳述): **`espflash monitor --no-reset` はチップを
    flasher stub に保持し広告が止まる**(「電波が出ない」誤診の元)。観測は
    `stty` + `cat`。生 HCI スモーク bin `hci-smoke` で controller/host 層を切り分け可能。
  - PC 側 btleplug は `SM_BLE_ADAPTER=hci1` を明示。
  - E2 実機化後に発見・修正したバグ 2 件(2026-07-06):
    1. **切断通知の取りこぼしで再広告停止**(デバイス側): trouble-host 0.6 は切断を
       `try_send` で通知するためキューが埋まった瞬間の切断が落ちる → worker が 1 秒
       周期の `is_connected()` ポーリングで確実に回収するよう修正(`2c376e9`)。
    2. **btleplug スキャンの BlueZ UUID フィルタ**(PC 側): Matter 広告は service
       data のみで Service UUID リスト AD を含まず、`SetDiscoveryFilter` に掛からない
       ことがある(Android では見えるのに PC で見えない症状の正体)→ 無フィルタ +
       コード側照合に変更、`SM_BLE_TRACE=1` トレース追加。
- **E3** ✅ 実機確認(2026-07-06、NanoC6 ↔ PC ble-commissioner):
  `e3-ble-light` bin(MatterStack DefaultStack NF=5 + WiFi シム + On/Off ライト、
  PC 版 ble-onoff-light の BLE 経路を no_std/embassy に写像)で
  **BLE フルコミッショニング完走**(PASE→CSR→AddNOC→CASE→CommissioningComplete→
  Toggle 反映、連続 2 fabric も成功)。NanoC6 青 LED(GPIO7)が OnOff に追従。
  乱数は全箇所 TRNG 直結、毎周 stack.poll() + BTP flush(NoSpace 教訓の移植)。
  RAM 静的 ≈149KB / 512KB。fabric 永続化なし(E4)・実 WiFi なし(E5)。
- **E4** ✅ 実機確認(2026-07-06、NanoC6): fabric 永続化。コアに `kvs::Kvs` trait +
  `FabricTable::save_to/load_from`(TLV versioned、設計は port-esp32-device.md
  「E4 設計」節)、運用鍵は `P256Keypair::to_bytes`(既存)で往復、CA 証明書は
  決定的署名により鍵から再生成。ESP32 は esp-storage + sequential-storage
  (nvs 領域、IDF 非互換)。PC 側 ble-commissioner に CA 永続化(`ca-state.bin`)+
  `--operational` モード(PASE なしで CASE→Toggle)。
  **ゲート実測**: run1 コミッショニング→`[kvs] saved 1 fabrics`→リセット→
  `[kvs] restored 1 fabrics`→run2 `--operational` で CASE 再確立+Toggle 成功。
  単体テスト +7(計 317)。BLE 稼働中の flash 書き込みも問題なし。
  PC 側の罠: **BlueZ が過去ブートの FFF6 広告をキャッシュ**し stale アドレスへの
  connect が失敗する → FFF6 デバイスを `bluetoothctl remove`(README 参照)。

## 5. クロスビルド / 実機テストの実務メモ

- **Windows exe クロスビルド**(Linux から、mingw 不要):
  ```sh
  XWIN_ACCEPT_LICENSE=1 cargo xwin build --release --target x86_64-pc-windows-msvc \
      -p simple-matter-ble --features commissioner --example ble-commissioner   # BLE 版
  XWIN_ACCEPT_LICENSE=1 cargo xwin build --release --target x86_64-pc-windows-msvc \
      -p simple-matter --features controller --example commissioner             # UDP 版
  # → target/x86_64-pc-windows-msvc/release/examples/{ble-commissioner,commissioner}.exe
  ```
  (windows-gnu / gnullvm は import ライブラリ不足でリンク不可。MSVC + cargo-xwin が正解)
- **BLE アダプタ**(2 ドングル構成): hci0=`00:1B:DC:06:0E:8C`(chip-tool/central 用)、
  hci1=`E8:48:B8:C8:40:00`(デバイス/peripheral 用)。`SM_BLE_ADAPTER=hci1` でデバイス側指定。
- **BTP トレース**: 両 example とも `SM_BTP_TRACE=1` でフラグメント先頭バイトを stderr へ。
- **BlueZ 亡霊キャッシュ**: `bluetoothctl remove <MAC>`。chip-tool フレッシュ化:
  `rm -f ~/snap/chip-tool/common/chip_tool_kvs`。
- **UDP デバイス起動**(W3 待ち受け):
  ```sh
  MATTER_DEBUG=0 ./target/release/examples/onoff-light   # 192.168.2.14:5540, disc=3840, pass=20202021
  ```
- **avahi 常駐の影響(重要)**: この開発機は avahi が 5353 を掴んでおり、`SO_REUSEPORT` で
  デバイスの mDNS 受信を奪う。REUSEADDR 化後も、グループに REUSEPORT ソケット(avahi)が
  いると配送が安定しない。**QU の socket レベル E2E は avahi の無い環境でしか検証不可**
  (コアロジックは単体テスト済み)。avahi は共有サービスのため停止不可。

## 6. W3 mDNS ディスカバリ問題の顛末(2026-07-05 解決)

**真因はマルチキャスト送信/join の IF 未指定**(Windows パスのコード欠陥)。仮想アダプタが
既定 IF に張り付くとクエリが LAN に出ず、announce も受からない。UDP ユニキャストは通るため
「直指定は完走・ブラウズだけタイムアウト」という症状になった。

調査の経緯(詳細と実機ログは `port-windows-commissioner.md` §3.2b/§3.2c):
1. avahi 不在のクリーン環境(docker + マルチキャスト lo 閉域)で **QU ユニキャスト応答の
   ソケット E2E を実証** → デバイス側はシロと確定。
2. コード精査で IF 未指定を発見 → connect トリックで LAN 向き IF に `IP_MULTICAST_IF` +
   join を固定、`SM_MDNS_TRACE=1` トレースを追加。
3. Windows 実機で **FW 無変更のまま** `commissioner.exe 20202021` が mDNS 発見→フル完走
   → IF 仮説で確定、当初の FW 仮説は棄却。QU 応答ユニキャスト(実 IP:5353→エフェメラル)
   は Windows FW を素通しだった。

教訓: マルチキャストは bind だけでなく **送信 IF と join IF の明示指定が必須**(特に
仮想アダプタの多い Windows)。`SM_MDNS_TRACE` は今後の mDNS 切り分けにも使える。

## 7. 残タスク(優先度順の目安)

1. **E5 以降**: 実 WiFi join + UDP/mDNS(embassy-net、WifiDriver trait)→
   bloat-check(E6)(`port-esp32-device.md` のフェーズ表)。E3 の chip-tool
   `pairing ble-wifi` 相互試験も未実施(PC 版と同一 DataModel なので通る想定)。
   E4 で追加: コア `kvs::Kvs` trait + `FabricTable::save_to/load_from`(TLV)、
   PC 側 ble-commissioner の CA 永続化(`ca-state.bin`)+ `--operational` モード。
   PC 側の罠: BlueZ は過去ブートの FFF6 広告をキャッシュし stale アドレスへの
   connect が失敗する → `bluetoothctl remove`(ports/esp32/README.md 参照)。
2. **W4**: chip デバイス相手のフルパス(commissioner 側の BLE→UDP 運用遷移の実装が前提)。
3. **方向 B 完結**: 我々の commissioner → chip-lighting-app の AddNOC 後、BLE を閉じて
   運用 mDNS→CASE over UDP→CommissioningComplete(現状 AddNOC まで実証済み)。

## 8. 既知の割り切り(コード内 doc コメントにも記載)

- BTP: 純粋 standalone ACK の応酬を省略(長アイドルで chip 側 ACK タイムアウトの可能性)。
- 統合層は BTP 経由でも両スタックの `poll()` 必須(exchange 回収、ble-btp.md §11-4)。
- fabric-scoped 属性の非フィルタ、CurrentFabricIndex=0、DataVersion 全クラスタ共有等。
- fabric 永続化は未実装(in-memory + `generation()` フックのみ。ESP32 E4 で KVS trait と実装予定)。
