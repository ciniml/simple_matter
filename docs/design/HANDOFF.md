# 作業ハンドオフ(2026-07-05 時点)

別セッションで作業を再開するための状態記録。全体の設計方針は `docs/ARCHITECTURE.md`、
個別設計は `docs/design/*.md`、進捗の要約は自動メモリ(`MEMORY.md` → `project-status.md`)
にもある。本ファイルは「BLE コミッショニング + 2 プラットフォーム移植(Windows / ESP32-C6)」
の作業を再開するための即時参照。

## 1. 現在地(1 行サマリ)

BLE コミッショニングは chip-tool 相互運用まで達成済み。移植は **Windows: W0-W3 完了
(W3 は mDNS ディスカバリ込みで実機フル完走、2026-07-05)**、
**ESP32-C6: E1(骨格 FW)ビルド完了・実機未確認**。

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
- **E1** 🔶 ビルドのみ(実機未確認): `ports/esp32/`(別 workspace、Cargo.lock 分離)に
  ESP32-C6 FW。esp-hal 1.1.1、TRNG→`crypto::Rng` アダプタ、P-256 鍵生成、heartbeat。
  `.text` 40.7KB。**実機で `cargo run --release` して期待ログ確認が E1 の残作業**。

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

1. **W4**: chip デバイス相手のフルパス(commissioner 側の BLE→UDP 運用遷移の実装が前提)。
2. **E1 実機確認**: ESP32-C6 ボードで `cd ports/esp32 && cargo run --release`。
   期待ログ: バナー → `[trng]` → `[crypto] P-256 keypair generated ... SEC1 tag 0x04` → heartbeat。
3. **E2 以降**: TrouBLE で `GattPeripheral` 実装 → BLE コミッショニング → KVS/fabric 永続化
   → 実 WiFi join(`port-esp32-device.md` のフェーズ表)。
4. **方向 B 完結**: 我々の commissioner → chip-lighting-app の AddNOC 後、BLE を閉じて
   運用 mDNS→CASE over UDP→CommissioningComplete(現状 AddNOC まで実証済み)。

## 8. 既知の割り切り(コード内 doc コメントにも記載)

- BTP: 純粋 standalone ACK の応酬を省略(長アイドルで chip 側 ACK タイムアウトの可能性)。
- 統合層は BTP 経由でも両スタックの `poll()` 必須(exchange 回収、ble-btp.md §11-4)。
- fabric-scoped 属性の非フィルタ、CurrentFabricIndex=0、DataVersion 全クラスタ共有等。
- fabric 永続化は未実装(in-memory + `generation()` フックのみ。ESP32 E4 で KVS trait と実装予定)。
