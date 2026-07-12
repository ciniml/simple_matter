# ESP32-S3 コントローラ(コミッショナ)ポート設計 — `controller` を組込みで動かす

対象: 実装済みのコントローラ資産(`controller` feature の `ControllerStack` /
`Commissioner` / `Ca` / `ImClient` / `MdnsClient`、`btp` の `GattCentral` trait)を
**ESP32-S3 上で動かし、スタンドアロンのコミッショナ(ハブ)にする**ための設計。
`docs/design/cli-controller.md`(smctl = PC ホスト駆動)と
`docs/design/airq-port.md` / `port-esp32-device.md`(S3/C6 = デバイス側ポート)の
合流点にあたる。

前提は既存設計と同一: コア(`crates/simple-matter*`)は sans-IO・no_std・
定常パス no-alloc。本件は smctl でやったのと同じ「駆動コードの追加」を
組込み(embassy)側でやる話であり、**コアへの新規要求はほぼゼロ**である
(§2 の監査結果)。唯一の例外は ca-state codec の置き場所(§5.3、コード移動のみ)。

---

## 0. サマリ(調査結果と主要な設計判断)

1. **no_std 監査は green(追加作業なし)**。本設計時に
   `cargo check --target riscv32imac-unknown-none-elf --no-default-features
   --features rustcrypto,ble,controller -p simple-matter` を実測し成功。
   controller パス(`controller/`・`sc/initiator/`・`im/client.rs`・
   `discovery/client.rs`)に `alloc::` / `std::` / `HashMap` / `Instant` / `Vec` は
   **一切ない**(自前 `FixedVec` + const generic 固定バッファのみ)。CI は既に
   `--all-features`(= controller + ble 込み)の riscv32imc クロスチェックを
   回している(`.github/workflows/ci.yml` 36 行目)ので、退行も検出済み(§2)。
2. **欠けているのは「ホスト形状」の 3 点だけ**で、いずれも smctl / device ポートに
   雛形がある: (a) `GattCentral` の TrouBLE 実装(device 側 `ble.rs` の
   worker+channel パターンの central 版)、(b) embassy-net 上の mDNS
   クライアント駆動(`EspUdp` はマルチキャスト join 込みで実装済み)、
   (c) ca-state の `EspKvs` 永続化(smctl の v1 フォーマットを流用)(§3-§5)。
3. **TrouBLE 0.6 は central ロールを完全サポート**: `Central::connect` +
   `Scanner` + `GattClient`(discovery by UUID / write / subscribe indication /
   `NotificationListener`)で `GattCentral` の全メソッドが実装できる。
   feature `central` + `scan` の追加が必要(現行ポートは
   `peripheral,gatt,derive,default-packet-pool` のみ)。esp-radio の
   `BleConnector` は純粋な HCI トランスポートでロール制限なし(§3)。
4. **RAM は既存配分(heap 112KiB / .stack ≈69KiB)で収まる見込み**。
   ControllerStack 一式の静的サイズは実測 ~20KiB(host x86-64、§6.1)。
   ハブ専用ビルドはデバイス側 `MatterStack` を持たないため、device ポートより
   むしろ軽い。リスクは容量でなく **P-256 連続署名のスタック深度**
   (S3 デバイス側で実証済みの逼迫、§6.3)。
5. **フェーズは K1-K4**: K1 = 監査固定+ホストシム(済み部分が大半)、
   K2 = S3 で UDP-only コミッショニング(mDNS ブラウズ→PASE→…→CASE→Toggle)、
   K3 = BLE central(`GattCentral` on TrouBLE)→ ble-wifi 相当、
   K4 = 常駐ハブ化(複数ノード + resumption)(§7)。

---

## 1. ユースケースとターゲットハード

### 1.1 ユースケース

- **(a) スタンドアロンハブ(初期ターゲット)**: ヘッドレスの S3 が smctl 相当の
  自動コミッショニング(`pairing onnetwork` / `ble-wifi`)と定常操作
  (CASE + Read/Invoke)を単独で行う。PC 不要の「自宅ハブ」。
  パスコード等の投入は当面シリアル/コンパイル時定数で足りる
  (smctl の `batch.rs` に相当する筋書きの固定実行)。
- **(b) 画面付きコントローラ(将来)**: M5Stack CoreS3 等、タッチ UI で
  デバイス一覧・操作。K4 以降の応用でありコア設計には影響しない
  (表示は airq-sensor の e-ink 表示と同様アプリ層の話)。

### 1.2 ハード

- 初期ターゲットは**手元の素の ESP32-S3 devkit(MAC b4:3a:45:bc:a8:00 の個体、
  AirQ ではない方)**。AirQ(M5Stack、ESP32-S3FN8)で確立した
  `ports/esp32s3` の基盤(espup esp channel、esp-hal 1.1.1 + esp-radio 0.18 +
  TrouBLE 0.6 + embassy-net、分離 workspace)をそのまま使い、
  **同 workspace に bin を 1 本追加**する(`s3-controller.rs`)。
  devkit は AirQ 固有の周辺(GPIO10 電源制御・e-ink・センサ)を持たないため、
  `lib.rs` の共有部(net/kvs/wifi/ble/EspRng)だけで成立する。
- デバイス側の対向は既存資産: C6(NanoC6)`e2-ble`/`e5` 系 bin、
  S3 `s3-light`、AirQ `airq-sensor`、PC の `onoff-light` example。

---

## 2. `controller` feature の no_std 適合監査

### 2.1 クロスビルド検証(実測)

```
cargo check --target riscv32imac-unknown-none-elf \
  --no-default-features --features rustcrypto,ble,controller -p simple-matter
   → Finished(エラーなし、2026-07-13 実測 @ 6f52ac0)
```

CI(`.github/workflows/ci.yml`)は既に以下を常時検証している:

- 36 行目: `cargo check -p simple-matter --all-features --target
  riscv32imc-unknown-none-elf` — **controller + ble 込みの no_std ビルド**。
- 47-59 行目: bloat-check により「`--features controller` がデバイス専用ビルドの
  flash に影響しない」ことの機械検証(閾値 128B)。

つまり「controller feature が no_std でビルド可能」は**新規の発見ではなく
CI で維持されている不変条件**であり、K1 での追加作業は Xtensa(esp channel)
での確認と bloat-check への controller プローブ追加(§6.2)のみ。

### 2.2 モジュール別監査(alloc / std 依存)

grep(`alloc::` / `std::` / `Vec<` / `HashMap` / `Instant`、tests 除外)の結果:

| モジュール | 依存 | 状態バッファ |
|---|---|---|
| `controller/mod.rs`(`ControllerStack`) | なし | `resp: [u8; 1600]`、`BufferPool<TX,1600>`、const generic |
| `controller/commissioner.rs`(`Commissioner`) | なし | `scratch/dac_der/pai_der/att_elements` 全固定長 |
| `controller/ca.rs`(`Ca`) | なし | `rcac: [u8; MAX_CERT_TLV_LEN]`、`FabricTable<C,1>`、serial は `Cell<u32>` |
| `sc/initiator/`(PASE/CASE initiator) | なし | slot 単一(`Option<T>`) |
| `im/client.rs`(`ImClient`) | なし | `result: [u8; RESULT]`、`FixedVec<ClientSub, MAX>` |
| `discovery/client.rs`(`MdnsClient`) | なし | **ステートレス**(builder/parser のみ、`FixedVec<IpAddr,6>`) |

時刻は全 API が `now_ms: u64` / `now_epoch_s: u32` を**引数で受ける**
(sans-IO)ため `std::time` 依存はない。乱数は `crate::crypto::Rng` trait
経由で、S3 には `EspRng`(TRNG、`ports/esp32s3/esp32s3-firmware/src/main.rs`)が
実装済み。**結論: コア側の no_std 化作業は残っていない。**

### 2.3 sans-IO 駆動 API(S3 側が書くもの)

`ControllerStack` の駆動契約は `MatterStack` と対称
(`controller/mod.rs`): `handle_rx(datagram, peer, now_ms, tx_out)` /
`poll(now_ms, tx_out)` / `next_deadline(now_ms)` が
`Option<SendDirective>` を返す。`Commissioner::drive(stack, now_ms, tx_out)`
がフェーズ(PASE→ArmFailSafe→Attestation→Csr→AddTrustedRoot→AddNoc→
[AddWifiNetwork→ConnectNetwork]→Case→Complete→Done)を進める。
smctl の `runner/udp.rs::pump_commissioner`/`settle` が PC 版駆動ループの
参照実装であり、S3 版は同じ形を embassy の `select`(UDP 受信 or
`next_deadline` タイマ)で書き直すだけ。`PeerAddr` は `Udp`/`Ble` 両対応で、
BTP セッションでは MRP が自動で無効化される(`allows_mrp`)ため
**トランスポート差はループの外側(ソケット vs BTP pump)に閉じる**。

---

## 3. BLE central — `GattCentral` on TrouBLE 0.6

### 3.1 適合性の結論

**実装可能(ギャップは feature 追加と実装コードのみ)**。根拠となる API 対応:

| `GattCentral`(`src/btp/gatt.rs:232`) | TrouBLE 0.6 API | 備考 |
|---|---|---|
| `scan(filter) -> ScanResult` | `Scanner::scan(&ScanConfig)` + `Runner::run_with_handler(&EventHandler)`。report は `EventHandler::on_adv_reports`(callback)で受け、`AdStructure::decode(report.data)` → `ServiceData16 { uuid: [0xF6,0xFF], data }` から discriminator/VID/PID を解析 | scan は **`scan` feature 必須**(→ `central` を連動有効化)。`ScanSession` は drop で停止する RAII ハンドル |
| `connect(target) -> (BtpConnId, Option<u16>)` | report の `(AddrKind, BdAddr)` を `ScanConfig::filter_accept_list` に入れて `Central::connect(&ConnectConfig)`(**accept list 空だとエラー**)→ `GattClient::new(stack, &conn)`(この時点で ATT MTU 交換)→ `services_by_uuid(0xFFF6)` → `characteristic_by_uuid`(C1 `…9D11` / C2 `…9D12`) | ATT MTU は `Connection::att_mtu()` |
| `write_c1(conn, frag)` | `GattClient::write_characteristic(&c1, frag)`(ATT Write Request) | |
| `subscribe_c2(conn)` | `GattClient::subscribe(&c2, indication=true)` → `NotificationListener` | CCCD 0x02。trait 契約どおり「最初の C1 write の後」に呼べる |
| `next_indication(conn, buf)` | `NotificationListener::next()` → データ取得 → `confirm_indication()` | 受信バッファは `Notification<512>` 固定 — BTP フラグメント(≤244B)には十分。**確認応答は自動でない**ので必ず confirm する |
| `disconnect(conn)` | `Connection` の切断(drop / disconnect) | |

- **esp-radio 側の制約なし**: `BleConnector`(esp-radio 0.18)は HCI バイト
  トランスポートに徹していてロール概念を持たず、`bt_hci::ExternalController` は
  `LeSetScanParams`/`LeCreateConn` 等のコマンド trait をジェネリックに実装する。
  S3 の BLE コントローラファームは full LE controller なので central は型レベル・
  HW レベルとも成立する。
- **Cargo 変更**: `ports/esp32s3` の trouble-host features に `central`, `scan` を
  追加(現行は `peripheral, gatt, derive, default-packet-pool`)。ハブ専用 bin なら
  `peripheral` を落とすことも可能だが、feature はワークスペースで合成されるため
  当面は追加のみとする。

### 3.2 実装スケッチ — device 側 `ble.rs` の鏡像

device 側 `TroubleGattPeripheral`(`ports/esp32s3/esp32s3-firmware/src/ble.rs`)と
同じ **worker + channel** 分割にする。TrouBLE の `GattClient` は `Stack` と
`Connection` を借用し、かつ `GattClient::task()`(RX ポンプ)を並走させる必要が
あるため、寿命の絡む一式を worker タスクに閉じ、`GattCentral` impl 本体は
channel 越しの façade にする:

```text
TroubleGattCentral(GattCentral impl、channel façade)
   │  cmd: Scan/Connect/WriteC1/SubscribeC2/Disconnect     ind: 受信 C2 フラグメント
   ▼
central_worker タスク(所有: Central, Scanner, Connection, GattClient)
   ├─ runner.run_with_handler(&AdvHandler)   … scan report → Signal
   ├─ gatt_client.task()                     … ATT RX ポンプ(subscribe 後)
   └─ cmd ループ: scan → accept-list → connect → discovery → write/subscribe
```

BTP central ハンドシェイク(`Btp::<6>` は共有・無改造)は smctl の
`runner/ble.rs::run_ble` と同一手順: scan → connect → **C1 に handshake
request を write → subscribe_c2 → 最初の indication(handshake response)**
→ 以降 `Commissioner` を `PeerAddr::Ble` で駆動。

### 3.3 制約・注意点(調査で確定したもの)

1. **scan と connect は直列**(scan 停止 → accept-list 設定 → connect)。
   TrouBLE 内部で別 CommandState だが accept-list を両者が書き換えるため、
   同時実行は意図されていない。`GattCentral::scan` → `connect` の trait 契約は
   もともと直列なので問題ない。
2. **`GattClient::new` は MTU 交換応答を待ってブロック**する。無応答デバイスで
   ハングしないよう embassy-time の timeout でラップする(リスク R4)。
3. central ロールと peripheral ロールは `Host { central, peripheral, runner }` で
   同時取得可能(将来「ハブ 兼 ブリッジデバイス」をやる場合の布石)。
   本設計では central 専用で使う。
4. indication の `confirm_indication()` 忘れはデバイス側の次 indication を
   止める(peripheral 実装が ATT 確認待ちで直列化しているのはこのため)。
   `next_indication` 内で受領後即 confirm する。

---

## 4. UDP / mDNS — embassy-net での controller 駆動

### 4.1 既存資産の流用

`EspUdp`(`ports/esp32s3/esp32s3-firmware/src/net.rs`)はコアの
`UdpSend`/`UdpReceive`/`UdpMulticast` を実装済みで、**IGMP(mapped-v4)+
MLD(`ff02::fb`)の join まで持っている**。device 用に書かれたが送受信の向きに
非対称はなく、controller がそのまま使える。sans-IO `MdnsClient`
(`discovery/client.rs`)はステートレスな builder/parser なので流用に条件なし。

### 4.2 ブラウズ(_matterc._udp)と運用解決(_matter._tcp)

smctl `runner/mdns.rs` の手順を embassy-net に写像する:

| 操作 | クエリ | 送信先 | 受信 |
|---|---|---|---|
| commissionable ブラウズ | `build_browse_commissionable` / `build_browse_discriminator(d)` | `224.0.0.251:5353` と `[ff02::fb]:5353` | `parse_commissionable` → `CommissionableSet<N>::ingest_filtered` |
| 運用解決 | `build_resolve_operational(compressed_fabric_id, node_id)` | 同上(または既知アドレスへ QU 直叩き) | `parse_operational` |

**受信モードは QU(unicast-response)を第一候補**とする:

- エフェメラルポートの UDP ソケットから QU ビット付き(builder の
  `unicast_response: true`)で送り、**ユニキャスト応答を自ソケットで受ける**。
  5353 の常時 listen も multicast join も不要になり、無関係な mDNS
  トラフィックの解析コスト(= 受信バッファと CPU)を持たずに済む。
  Windows W3 パス・matter-over-vpn V1(QU 直叩き)で実証済みの方式であり、
  自デバイス(`query_wants_unicast` 対応)・chip 系デバイスとも動作確認済み。
- QU に応答しない実装に当たった場合のフォールバックとして QM
  (5353 bind + join、`EspUdp::join` 実装済み)を残す。リスク R5。
- 再クエリ間隔は smctl と同じ 2 秒、タイムアウトはブラウズ 6-10 秒 /
  運用解決 60 秒(ble-wifi 後の join 待ちを含む)。

embassy-net の `StackResources<6>` はソケット数に効く。controller bin は
UDP(Matter 5540 相当の操作用)+ mDNS 用の 2 ソケット構成で足りるが、
余裕を見て device ポートと同じ 6 のままとする。

### 4.3 K2(UDP-only)の駆動ループ

```text
loop {
    select(
        udp.receive(buf)                     → stack.handle_rx(...) → 送信,
        Timer::at(next_deadline)             → stack.poll(...)      → 送信,
    );
    comm.drive(stack, now_ms, tx)            → Phase 進行 / 送信;
    if let Done { session } = phase { break; }
}
```

`now_ms` は `embassy_time::Instant::now().as_millis()`。これは smctl
`pump_commissioner` の embassy 版であり、新規性はない。

---

## 5. CA・証明書発行のオンデバイス実行と永続化

### 5.1 演算の no_std / ヒープ要件 — 問題なし

`Ca`(`controller/ca.rs`)は全フィールド固定長
(root 鍵ペア・`rcac: [u8; MAX_CERT_TLV_LEN]`・IPK 16B・`FabricTable<C,1>`)。
`Ca::generate`(P-256 鍵 2 対生成 + RCAC/NOC 自己発行 + FabricTable 登録)も
`issue_noc`(デバイス NOC の TLV 構築 + ECDSA 署名)もヒープを使わない。
乱数は `EspRng`(TRNG、`TrngSource` 常駐)をそのまま渡す。

### 5.2 永続化 — smctl v1 フォーマットを `EspKvs` へ

`Ca` の persistence accessor(`root_key_bytes` / `controller_key_bytes` /
`ipk_epoch_key` / `fabric_id` / `controller_node_id` / `vendor_id` /
`next_serial`)と `Ca::restore` により、**保存するのは鍵素材 8 フィールド
(~100B、エンコード後 ≤192B)だけ**で証明書は保存不要
(RFC 6979 決定的署名なので restore が同一バイト列を再生成する)。

- smctl の `state/ca.rs`(v1 TLV、cx0..cx7)と同じレコードを **`EspKvs` の
  1 キー(例 `b"cast"`、pack_key の 7B 制限内)** に置く。`EspKvs` の
  値バッファは fabric レコード基準(`MAX_FABRIC_RECORD_LEN + 64`)で
  192B を大きく上回るため追加変更なし。フォーマットを smctl と揃えておくと、
  PC で作った fabric を S3 ハブへ移す(またはその逆)ことが将来単純コピーで
  できる。
- **コード配置の提案(唯一のコア変更、K2 で実施)**: `state/ca.rs` の
  encode/decode は純 TLV で I/O を含まないため、
  `simple_matter::controller::ca` 配下(feature 内)へ移して smctl と S3 で
  共有する。移動のみで挙動不変、bloat-check の不変条件にも影響しない
  (controller feature 内)。
- `next_serial` は NOC 発行のたびに進むため、**発行のたびに save**(頻度は
  コミッショニング時のみなので flash 摩耗は無視できる)。

### 5.3 時刻(epoch)の扱い

`Ca::generate/restore` と `verify_peer_noc` は `now_epoch_s: u32` を取るが、
証明書は not-before/after = 0(無期限)で発行される(`ca.rs` の設計)。
RTC のない S3 では **now_epoch_s = 0 固定**で開始し、ホストシム(K1)で
0 運用に問題がないことを先に確認する(リスク R7)。将来 SNTP を載せる場合も
API は引数渡しなので差し替えるだけ。

---

## 6. リソース見積り

### 6.1 静的サイズ(host x86-64 で `size_of` 実測、本設計時)

| 型 | サイズ | 備考 |
|---|---|---|
| `ControllerStack<…, 3,2,2,1280>`(既定) | 10,344 B | resp 1600B + TxPool 2×1600B が主 |
| `ControllerStack<…, 4,6,3,1280>`(example 相当) | 12,544 B | |
| `Commissioner` | 2,912 B | DAC/PAI/attestation 固定バッファ |
| `Ca` | 1,952 B | RCAC + FabricTable<C,1> |
| `ScInitiator` | 712 B | |
| `ImClient<1280>` | 4,080 B(Stack に内包) | RESULT=8192(smctl 相当)なら +6.9KiB |
| `MdnsClient` | 0 B | ステートレス |
| `Btp<6>` | 2,936 B | K3 で追加 |

合計 **~20KiB(BTP 込み)**。32bit ターゲットではポインタ幅の分さらに小さい。
ハブのサイジングは `4,6,3,1280`(コミッショニング 1 + 運用 CASE 数本)から
始め、wildcard read が要るときだけ RESULT を 2048 程度へ広げる(リスク R6)。

### 6.2 flash

S3 は 8MB flash で容量制約は実質ない。計測面の整備として、K1 で
bloat-check に **controller プローブ**(`ControllerStack` + `Commissioner` +
`MdnsClient` の経路を `black_box` 参照する `controller-probe` bin)を追加し、
controller ビルドの .text/.rodata を CI で記録する(既存 flash-probe は
device 経路のみ参照するため controller コードは gc される)。
共有基盤(P-256/AES/SHA/TLV/transport)は device と同一なので、増分は
initiator 状態機械 + codec + CA 分(実装 ~5.7k LoC)に留まる見込み。

### 6.3 RAM 配分と coex(AirQ A5 の知見の適用)

- **S3 の DRAM リンカ領域 ≈340KiB。heap 112KiB / .stack ≈69-75KiB の配分を
  そのまま踏襲**する(AirQ 実測: coex E2E ピーク heap 90,160B、
  144KiB heap では .stack 37KiB になり P-256 署名チェーンでスタック
  ガード衝突 — airq-port.md §7.3.1)。esp-alloc `internal-heap-stats` の
  `[alive]` 監視も踏襲。
- controller の静的 ~20KiB は .bss/.data 側。ハブ専用 bin はデバイス側
  `MatterStack`(DefaultStack)を持たないため、device bin より RAM 収支は
  良い方向。
- **スタック深度が本命のリスク**: controller は device より署名回数が多い
  (CA generate で 2 発行 + コミッショニングごとに issue_noc + CASE Sigma)。
  device 側で顕在化した「同期 P-256 チェーンによる main .stack 逼迫」が
  同型で起きうるため、K2 で stack watermark を計測し、必要なら
  コミッショニング処理を専用スタックのタスクへ切り出す(リスク R3)。
- **coex**: esp-radio 0.18 の S3 coex(BLE+WiFi)は device 側で実証済み。
  controller 固有の差分は「advertise でなく **scan**」で、スキャン窓は
  coex 中の WiFi と帯域を取り合う。`ScanConfig::interval/window`
  (既定 1s/1s = 常時スキャン)をコミッショニング時のみ有効化し、
  取りこぼしはリトライで吸収する(リスク R2)。

---

## 7. フェーズ計画

方針は airq-port と同じ「各フェーズ冒頭に安いゲートを置き、詰まったら撤退線へ」。

| フェーズ | 内容 | 完了条件(ゲート) | 工数感 |
|---|---|---|---|
| **K1: 監査固定 + ホストシム** | (a) no_std 監査の成果を CI に固定: bloat-check へ controller プローブ追加(§6.2)。(b) ホストシム: `examples/commissioner.rs` / smctl の駆動ループを「S3 と同形状」(同期 pump・`now_ms` 引数・QU mDNS・now_epoch_s=0)に整理した host bin で、実デバイス(C6 / AirQ / PC onoff-light)を UDP コミッショニング | ホストシムで PASE→…→CASE→Toggle が通り、now_epoch_s=0 でも `verify_peer_noc` が通ることを確認(R7 消し込み) | **S**(1-2 日) |
| **K2: S3 UDP-only コミッショニング** | `ports/esp32s3` に `s3-controller` bin 追加(devkit b4:3a:45:bc:a8:00)。`EspUdp` + mDNS ブラウズ(QU、QM フォールバック)→ `Commissioner` フル(onnetwork)→ Toggle。ca-state を `EspKvs`(`b"cast"`)へ、codec は `state/ca.rs` からコアの controller feature 内へ移動(§5.2)。stack watermark 計測(R3) | S3 devkit 単独で、WiFi 上のデバイス(C6 e5 系 or AirQ)をコミッショニングし OnOff Toggle。**リブート後に `Ca::restore` → 運用解決 → CASE 再確立**まで | **M**(3-5 日) |
| **K3: BLE central → ble-wifi 相当** | trouble-host features に `central`,`scan` 追加。冒頭ゲート: スキャンスモーク(`on_adv_reports` で 0xFFF6 service data と discriminator が読めること = R1 消し込み)。`TroubleGattCentral`(worker+channel、§3.2)→ BTP central handshake → BLE 上 PASE→AddNOC、`set_wifi_credentials` + `suspend_before_case`/`set_peer`/`resume` による **ble-wifi**(AddWifiNetwork→ConnectNetwork→BLE close→運用解決→CASE over UDP) | S3 devkit から BLE デバイス(C6 `e2-ble` / S3 `s3-light`)を ble-wifi コミッショニングし、運用 UDP で Toggle | **M-L**(4-7 日) |
| **K4: 常駐ハブ化** | ノード帳(smctl `nodes` 相当: node_id / last_addr / resumption 素材)を `EspKvs` 化。CASE resumption(コア実装済み、`export/import` API)で跨リブート再接続。複数ノードの定常管理(定期 Read or Subscribe)。(オプション)CoreS3 表示 UI | 2 ノード以上を管理し、ハブ再起動後に resumption で CASE 再確立 → 操作継続 | **L**(5 日+) |

### リスク表

| # | リスク | 影響フェーズ | 緩和 |
|---|---|---|---|
| R1 | trouble `scan`/`central` を esp-radio S3 で使った実績がリポジトリ内にない(`run_with_handler` 経由の adv report、accept-list 前提の connect) | K3 | K3 冒頭に独立したスキャンスモークをゲートとして置く。詰まった場合の撤退線 = UDP-only ハブ(K2 成果)は成立済み |
| R2 | WiFi coex 中の central スキャン取りこぼし・接続確立遅延 | K3 | scan window/interval 調整、コミッショニング時のみスキャン、リトライ。device 側 coex 実測(association 数秒)と同様の余裕をタイムアウトに持たせる |
| R3 | P-256 連続署名のスタック深度(S3 device 側で実証済みの .stack 逼迫が controller ではさらに深い) | K2 | heap 112KiB 配分を踏襲し stack watermark を計測。超過時はコミッショニング処理を専用スタックタスクへ |
| R4 | `GattClient::new` の ATT MTU 交換が無応答ペアでハング | K3 | embassy-time timeout でラップし scan からやり直し |
| R5 | QU 応答を返さない mDNS 実装 | K2 | QM フォールバック(5353 bind + join は `EspUdp` 実装済み) |
| R6 | wildcard read の RESULT バッファ(smctl は 8192)と RAM のトレードオフ | K2/K4 | ハブは 1280-2048 で開始。大量読みは属性を絞るか分割読みに倒す |
| R7 | RTC なし(now_epoch_s=0)での証明書検証 | K1 | 証明書は not-before/after=0 発行(実装済み)。K1 ホストシムで 0 運用を先に実証 |

---

## 8. オープン論点

1. **ハブ 兼 デバイス(ブリッジ)**: TrouBLE は `Host` から central と
   peripheral を同時に取れるため、「Matter デバイスとしてコミッショニング
   されつつ、自分も下位デバイスをコミッショニングするハブ」は構造上可能。
   RAM(MatterStack + ControllerStack 同居)と coex 負荷の見極めが必要で、
   K4 より後の検討とする。
2. **attestation Verify のオンデバイス化**: 現状 `AttestationPolicy::Skip` で
   開始する。PAA ストア(DER 数枚)を flash 定数として持てば
   `Verify { paa_store }` は no_std で成立するはずで、K4 以降の追加候補。
3. **パスコード投入 UI**: ヘッドレスハブの実運用ではシリアル/固定値以外の
   投入経路(ボタン + 既知 QR、または (b) の画面つき UI)が要る。
   コア設計に影響しないためユースケース (b) と併せて検討。
4. **smctl との fabric 共有**: ca-state フォーマットを揃える(§5.2)ことで
   「PC でコミッショニングした fabric を S3 ハブが引き継ぐ」運用が可能になる。
   ノード帳(`nodes.tlv`)側の互換もそのとき決める。
