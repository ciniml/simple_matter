# コミッショニー(デバイス)の ESP32 シリーズ対応 — 調査と移植設計

対象: デバイス(responder)側スタックを ESP32 シリーズ(まず ESP32-C3/C6、次いで無印
ESP32/S3)で動かし、**BLE コミッショニング → 実 Wi-Fi join → UDP 運用**を実機で通す。
本書は調査・設計のみでコード変更を含まない。

前提となる現状(2026-07-05 時点):

- コア(`simple-matter`)は no_std・sans-IO・定常パス no-alloc・executor 非依存。
  thumbv7em 実測で flash 約 85KB / デバイス RAM 約 20.3KiB(DefaultStack)。
- BTP 状態機械(`src/btp/`)はヒープレス sans-IO で、**移植の継ぎ目は
  `GattPeripheral` trait 1 枚**(ble-btp.md §5)。PC 実装(bluer)と chip-tool
  相互運用で trait 契約は実証済み(確立順序・subscribe 前 indicate 保留・毎周 poll 等)。
- ただしコアの外に **未整備の継ぎ目が 3 つ**あり、ESP32 移植はこれらを表面化させる:
  1. `UdpSend`/`UdpReceive`/`UdpMulticast` trait は**定義のみで実装ゼロ**
     (examples は `std::net::UdpSocket` 直書き)。
  2. **KVS / Clock の trait が存在しない**(RNG のみ `crypto::Rng` として trait 化済み)。
     fabric 永続化は in-memory + `generation()` フックのみ。
  3. mDNS は自前 sans-IO 実装だが**実運用は IPv4(224.0.0.251)のみ**
     (`ff02::fb` は定数のみ)。
- NetworkCommissioning は Ethernet 版と Wi-Fi シム版のみ(実 join なし)。

---

## 0. サマリ(推奨路線と設計判断)

1. **推奨は (a) no_std ベアメタル路線: esp-hal + esp-radio(旧 esp-wifi)+ TrouBLE +
   embassy-net**。本プロジェクトの方針(no_std コア・heapless・embassy 系 executor
   非依存 async・bloat-check)と唯一整合する。std/ESP-IDF 路線 (b) は「動かすだけ」なら
   速いが、フットプリント計測の意味が薄れ、コアの規律(alloc 制御)も検証できない。
   (b) は (a) が特定チップで詰まった場合の**バックアップ**に位置付ける。
2. **最小ターゲットは ESP32-C3**(RISC-V RV32IMC、SRAM 400KB、Wi-Fi4 + BLE5)。
   ツールチェーンが upstream Rust(`riscv32imc-unknown-none-elf`)で完結し、
   Xtensa(無印/S3)の espup 依存を避けられる。次点 C6(SRAM 512KB、Wi-Fi6)。
3. **GattPeripheral は TrouBLE(embassy 系 BLE Host)で実装**する。esp-radio が BLE
   controller(HCI)を提供し、TrouBLE がその上で GATT server / advertising を提供する。
   イベントは embassy-sync channel で `next_event` に運ぶ(PC 版 bluer 実装の
   mpsc 設計をそのまま写像できる)。
4. **UDP/mDNS は embassy-net(smoltcp)で `UdpSend`/`UdpReceive`/`UdpMulticast` を
   初めて実装**する(コア trait の実利用第 1 号)。mDNS は自前 responder が sans-IO
   なので、マルチキャスト join(IPv4 IGMP / IPv6 MLD は smoltcp が対応)だけが新規。
5. **Wi-Fi 実 join**: `NetworkCommissioningWifi`(現シム版)を一般化し、
   「AddOrUpdateWiFiNetwork で credentials を保持 → ConnectNetwork で
   プラットフォームフック(trait)を叩き、association+DHCP 完了で
   ConnectNetworkResponse(Success)→ 運用 mDNS 開始」という **WifiDriver trait** を
   コアに切る。PC シム版はこの trait の「即 Success」実装として統合し直せる。
6. **KVS trait をコアに追加**(fabric 永続化の第 5/6 段階作業を本移植で消化)。
   ESP32 実装は esp-storage(flash)+ sequential-storage(wear-leveling KV、no_std)。
   Clock は現状どおり値渡し(`now_ms`)で足り、trait 追加は不要(embassy-time から
   注入)。RNG は esp-hal の HW TRNG(Wi-Fi/BLE 有効時に真性乱数)を `Rng` に接続。
7. **リソース見積り**: 本スタック(~85KB/20KiB)+ esp-radio Wi-Fi+BLE coex
   (flash ~200-300KB / RAM ~100KB 級のヒープ・バッファ)+ embassy-net バッファで、
   **C3 の 400KB SRAM / 4MB flash に対して十分収まる見込み**(rs-matter が同構成で
   C3 動作実績あり)。正確な数値は P1 の bloat-check 拡張で実測する。

---

## 1. 路線比較: (a) esp-hal no_std vs (b) esp-idf std

| 観点 | (a) esp-hal + esp-radio + embassy | (b) esp-idf-hal/svc + esp32-nimble |
|---|---|---|
| 言語環境 | no_std(バイナリ全体を Rust が掌握) | std(ESP-IDF = FreeRTOS + lwIP に FFI) |
| 本プロジェクト方針との整合 | ◎(heapless・embassy・bloat-check がそのまま) | △(alloc/スレッド前提、フットプリントは IDF 込み) |
| BLE peripheral | TrouBLE(GATT server/adv、embassy 統合) | esp32-nimble(NimBLE バインディング、成熟) |
| Wi-Fi + BLE 同時(coex) | esp-radio の coex feature(C3/S3/C6 対応) | ESP-IDF の coex(最も実績あり) |
| UDP/mDNS | embassy-net(smoltcp)。マルチキャスト join 対応 | std::net(lwIP)。PC example がほぼそのまま動く |
| KVS | esp-storage + sequential-storage | NVS(esp-idf-svc) |
| ツールチェーン | C3/C6: upstream stable Rust。無印/S3: espup(Xtensa) | espup + ESP-IDF SDK 一式 |
| リスク | TrouBLE/esp-radio の成熟度(§6 R1) | フットプリント目標との乖離、IDF バージョン地獄 |

**判断**: ARCHITECTURE.md の存在意義(rs-matter 比 1/12 のフットプリント)を実機で
示すには (a) 一択。(b) は「コアが std でも動く」ことの確認以上の価値がなく、
本命にしない。ただし TrouBLE の GATT server 実装が C1/C2 の要件(write with response、
indicate、CCCD 検知、ATT_MTU 取得)を満たすかは P2 の最初のゲートで確認し、
不足があれば bleps(esp-radio 同梱の簡易 BLE スタック)direct か (b) へ切り替える。

## 2. GattPeripheral の TrouBLE マップ

PC 版(bluer)実装の構造をそのまま写像する。bluer 調査で確立したパターン:
「コールバック/別タスク発の生イベント → channel → `next_event` が翻訳して先読みキュー」。

| trait メソッド | TrouBLE 側 | 備考 |
|---|---|---|
| `start_advertising(AdvData)` | advertising パラメータ + AD 構造(service data 0xFFF6) | `AdvData::service_data()` はコア共有(バイト列生成済み) |
| `next_event` | GATT server イベントループ(embassy task)→ `embassy_sync::channel` | `Connected`(+ATT_MTU)/`C1Write`/`C2Subscribed`(CCCD 書き込み検知)/`Disconnected` |
| `indicate(conn, frag)` | C2 の indicate(confirmation 待ち) | TrouBLE は indication の完了 future を返す |
| `disconnect(conn)` | 接続 handle の切断 | |

- **ATT_MTU**: TrouBLE は接続の negotiated MTU を公開する(bluer では write 要求から
  取っていた)。handshake の fragment 交渉(mtu=0 は不明扱い、実装済み)がそのまま効く。
- **イベントバッファ**: `next_event(&mut buf)` の契約(呼び出し側バッファ、
  実装はヒープ確保しない)は embassy-sync の固定容量 channel + コピーで満たせる。
  C1 フラグメントは最大 244B なので channel 要素は固定長配列で持つ。
- **接続数 1** の現行スコープ(ble-btp.md §11-2)は TrouBLE の single-connection
  構成と一致し、`BtpConnId` 採番も PC 版と同じ(1 起点 wrap)。

## 3. UDP / mDNS(embassy-net)

- `UdpSend`/`UdpReceive` を embassy-net の `UdpSocket` で実装(**trait の実装第 1 号**。
  PC examples が trait を経由していない現状は、ESP32 統合タスクが同じポンプを書く際の
  参照にならない点に注意 — ble-onoff-light の select ループを embassy の
  `select` + `Timer::at` で書き直す)。
- `UdpMulticast::join` は smoltcp の IGMP(v4)/MLD(v6)join に接続。
  mDNS responder(sans-IO)は 5353 の受信バイト列を `handle_query` に渡すだけ。
- **IPv6 対応を本移植で有効化する**(現 PC 実装は IPv4 のみ)。Matter の運用
  ディスカバリは link-local IPv6 が本流で、Thread 系エコシステムや一部コントローラは
  IPv4 mDNS に応答しない。smoltcp は IPv6/MLD 対応済みなので、responder の
  AAAA レコード生成(実装済み)に ff02::fb join を足すだけ。chip-tool 相手の
  受け入れ試験は IPv4(実績)と IPv6 の両方で行う。

## 4. Wi-Fi 実 join(NetworkCommissioning の一般化)

現状: Ethernet 版(実 join 不要)と Wi-Fi シム版(即 Success)のみ。ESP32 では
ConnectNetwork で実際に esp-radio の Wi-Fi を叩く必要がある。

- コアに **`WifiDriver` trait(最小 2 メソッド)** を切る:
  `fn connect(&mut self, ssid: &[u8], creds: &[u8])`(開始のみ、非同期完了)+
  `fn status(&self) -> WifiStatus`(Idle/Connecting/Connected{…}/Failed{reason})。
  `NetworkCommissioningWifi` はこれを注入され、ConnectNetwork 受信で `connect` を呼ぶ。
- **応答タイミングの設計判断**: chip-tool は ConnectNetworkResponse を BLE 上で待つ。
  仕様は「接続完了後に応答」だが、BLE と Wi-Fi の coex 中は association に数秒かかる。
  chip 実装同様、`ConnectMaxTimeSeconds`(属性、実装済み)以内に完了を返す。
  IM ハンドラは同期 Mealy machine なので、「ConnectNetwork 受信 → `connect()` 開始 →
  応答は遅延送出(`HandlerAction` の遅延型 or poll 経由の後追い InvokeResponse)」が
  必要になる。**ここがコア側の唯一の新規メカニズム**(現行 IM エンジンは 1 受信 1 応答)。
  代替として「即 Success を返し、実接続は継続処理」も chip-tool 相手には通る
  (シム版で実証済みのフロー)が、失敗を報告できないため trait 化と併せて遅延応答を検討する。
- PC の Wi-Fi シム版は `WifiDriver` の「即 Connected」実装として統合し直し、
  クラスタ実装を単一に戻す(現在の型二重化を解消)。
- join 完了後: DHCP/SLAAC 取得(embassy-net)→ 運用 mDNS 広告開始(fabric
  generation 検知の既存パターン)→ BLE は CommissioningComplete 後に広告停止・切断。

## 5. KVS / Clock / RNG(プラットフォーム統合)

| 項目 | 現状 | ESP32 設計 |
|---|---|---|
| RNG | `crypto::Rng` trait 化済み(鍵生成のみ消費) | esp-hal の HW TRNG を `Rng` 実装に。Wi-Fi/BLE 有効時に真性乱数である旨を doc 化 |
| Clock(単調) | trait なし・`now_ms: u64` 値渡し | embassy-time `Instant` から注入(ポンプが渡す)。**trait 追加不要** |
| Clock(壁時計) | 証明書検証の `now_secs: u32` 値渡し | Last Known Good Time(fabric に実装済み)を既定に。NTP はスコープ外 |
| KVS | **trait なし**(fabric は in-memory + `generation()` フック) | コアに `Kvs` trait(get/set/remove、キーは短い &str、値は &[u8])を追加し、fabric の TLV シリアライズ(`FabricEntry` は素材保持済み)と接続。ESP32 実装は esp-storage + sequential-storage |

KVS trait とfabric シリアライズは ARCHITECTURE.md ロードマップ第 5/6 段階の積み残しで、
ESP32 で「再起動後も fabric が残る」ために必須。**本移植の中で最大のコア側新規実装**。

## 6. リスク一覧(未確認事項)

| # | リスク | 影響 | 確認方法 / 回避策 |
|---|---|---|---|
| R1 | TrouBLE + esp-radio の GATT server 成熟度(indicate 確認、CCCD 検知、MTU 公開)(未確認・要実機) | GattPeripheral 実装可否 | P2 冒頭でスモーク(advertise + write + indicate のみの最小 FW)。不足時は bleps 直 or (b) 路線 |
| R2 | Wi-Fi + BLE coex 中の安定性・RAM(コミッショニング中は両方アクティブ) | 実機でのみ判明 | C3 で実測。予算超過なら C6/S3 へ、または「ConnectNetwork 後に BLE 停止→Wi-Fi 起動」の順次方式(chip の一部デバイスと同挙動)へ緩和 |
| R3 | IM の遅延 InvokeResponse(ConnectNetwork の完了後応答)がエンジン契約に無い | コア変更(中規模) | 初期は即 Success(シム実証済み)で回し、遅延応答は別コミットで設計 |
| R4 | esp-hal / esp-radio / TrouBLE / embassy のバージョン整合(エコシステムが速い) | ビルド維持コスト | 専用 crate(workspace 外の `ports/esp32` も検討)で lock を固定し、コアと分離 |
| R5 | Xtensa(無印 ESP32)のツールチェーン | C3/C6 に無関係 | 初期スコープを RISC-V(C3/C6)に限定 |

## 7. crate / ビルド構成

- 新 crate `crates/simple-matter-esp32`(または workspace 分離の `ports/esp32/` —
  esp 系依存はビルドターゲット・feature 解決がホスト側と衝突しやすいため、
  **別 workspace を推奨**。R4 の lock 分離も兼ねる)。
- 中身: `GattPeripheral`(TrouBLE)、`UdpSend/Receive/Multicast`(embassy-net)、
  `Kvs`(esp-storage)、`Rng`(TRNG)、`WifiDriver`(esp-radio)、
  examples/`esp32c3-onoff-light`(ble-onoff-light の embassy 版ポンプ)。
- CI: `cargo check --target riscv32imc-unknown-none-elf`(コアのみは既に no_std なので
  即可能 — **これはコアの回帰ゲートとして先行導入する価値あり**)。ports 側は
  esp-radio が要 nightly なら nightly ジョブを分離。bloat-check に C3 ターゲットの
  セクションサイズ計測を追加。

## 8. 実装フェーズ分割

| フェーズ | 範囲 | 検証ゲート | 工数感 |
|---|---|---|---|
| **E0: コアのクロスビルド CI** ✅(2026-07-05) | `riscv32imc-unknown-none-elf` で simple-matter(ble, controller なし/あり)を check | CI green(コード変更ゼロのはず) | S |
| **E1: ports 骨格 + Lチカ** ✅(2026-07-05 実機確認、M5Stack NanoC6) | ports/esp32 workspace、esp-hal(1.1.1)で C6 起動・ログ・TRNG→`Rng`・P-256 鍵生成(ユーザ指定で C3→C6)。実機で発見した罠: **esp-bootloader-esp-idf の `esp_app_desc!()` 必須**(無いと TG0 WDT リセットループ)+ **espflash は 4.x 必須**(3.x は欠如を検出せず書き込む)。詳細 `ports/esp32/README.md` | 実機でログ出力・乱数取得 ✅(バナー→TRNG→SEC1 tag 0x04→heartbeat) | S |
| **E2: BLE スモーク → GattPeripheral** ✅(2026-07-05 実機確認) | TrouBLE(0.6、esp-radio 0.18 の bt-hci 0.8 に合わせる)で 0xFFF6 広告 + C1/C2。`GattPeripheral` 実装は `ports/esp32/esp32c6-firmware/src/ble.rs`(worker⇔channel 構造で bluer 版を写像)。R1 は解消: CCCD 検知(`GattEvent::Write` + `accept()` 必須)・`Connection::att_mtu()`・indication は worker が Confirmation 待ちで直列化。切り分け用の生 HCI スモーク bin(`hci-smoke`)と espflash monitor の罠は `ports/esp32/README.md` | PC の `ble-commissioner` から BTP handshake 確立 ✅(fragment=20、PASE SDU 再組立・ACK・クリーン切断まで実測) | M |
| **E3: BLE コミッショニング** ✅(2026-07-06 実機確認) | embassy 版ポンプ(毎周 poll・subscribe 前保留の教訓を移植)+ MatterStack(`e3-ble-light`、DefaultStack NF=5、WiFi シム込み、NanoC6 青 LED 追従)。乱数は全箇所 TRNG 直結、SPAKE2+ verifier は起動時前計算 | PC commissioner から **フルコミッショニング完走** ✅(PASE→CSR→AddNOC→CASE→CommissioningComplete→Toggle。ゲートの AddNOC 超え。連続 2 fabric も成功)。chip-tool 相互試験は未実施 | M |
| **E4: KVS + fabric 永続化** ✅(2026-07-06 実機確認) | コアに `kvs::Kvs` trait + `FabricTable::save_to/load_from`(TLV versioned、詳細は本書「E4 設計」節)、ESP32 は esp-storage + sequential-storage(nvs 領域、IDF 非互換)。PC 側 ble-commissioner に CA 永続化(`ca-state.bin`)+ `--operational` モード追加。単体テスト +7(317 passed) | **再起動後の運用 CASE 再確立 ✅**(コミッショニング→`[kvs] saved 1 fabrics`→リセット→`[kvs] restored 1 fabrics`→`--operational` で CASE+Toggle 成功) | M〜L(コア側含む) |
| **E5: Wi-Fi 実 join + UDP/mDNS** 実装済み(2026-07-06、実機検証は未) | WifiDriver trait(コア追加)、embassy-net で UDP trait 実装(実利用第 1 号)、mDNS(**IPv4 のみ**に縮小、IPv6 は将来)。詳細は本書「E5 設計」節 | chip-tool `pairing ble-wifi`(実 SSID)フルパス + toggle(実機検証待ち) | L |
| **E6: bloat-check / チューニング** サイズ記録済み(2026-07-06) | C6 全 bin の `size -A` 実測を `ports/esp32/README.md` に記録(bloat-check 拡張はスコープ外) | flash/RAM 実測値を README に記録 ✅ | S |

**総工数感: L**(E4/E5 がコア側の未整備領域を含むため。BLE 経路だけなら E0-E3 で M)。

## E4 設計: KVS と fabric 永続化

E4 の目的は「デバイスをリブートしても運用 CASE を再確立できる」こと。そのために
(1) コアに最小の KVS 抽象を切り、(2) `FabricTable` を TLV で保存/復元できるようにし、
(3) ESP32-C6 の flash(`nvs` パーティション領域)に実装を接続する。以下は確定した設計判断。

### E4.1 `Kvs` trait(コア `src/kvs.rs`)

- **置き場所はコア**(`crates/simple-matter/src/kvs.rs`、feature ゲートなし・依存ゼロ)。
  `crypto::Rng` と同じ「最小 trait + プラットフォーム注入」の流儀(ARCHITECTURE 原則 9)。
  trait 定義だけなら no_std・alloc 非依存・フットプリントゼロで常時コンパイルできる。
- **同期(blocking)API**。flash 書き込みは低頻度パス(fabric 変更時のみ)であり、
  コアを executor 非依存に保つ現行方針(Clock も値渡し)と揃える。ESP32 側の
  非同期 flash API は実装側で `block_on` 相当により吸収する(下層は元々 blocking)。
- シグネチャ(キーは短いバイト列、値は borrowed slice。ヒープ確保なし):
  - `fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>>`
    — 無ければ `Ok(None)`、あれば `buf` 先頭に値をコピーし長さを返す。`buf` 不足は `NoSpace`。
  - `fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>` — 上書き。
  - `fn remove(&mut self, key: &[u8]) -> Result<()>` — **キー不在でも `Ok`**
    (呼び出し側が空スロットを無条件に消せるように冪等とする)。
  `&mut self` なのは flash ドライバが本質的に排他だから(共有したい層が外側で包む)。

### E4.2 fabric 永続化フォーマット(versioned TLV)

既存の `src/tlv.rs`(Matter TLV)でエンコードする。専用フォーマットを増やさず、
既にコアにあるコーデックを再利用するのが理由(パーサの二重化を避ける)。

- **キーはスロット毎**: `b"fab0"`..`b"fab{N-1}"`(スロット位置 = テーブル内順序。
  N ≤ 10 前提、`DefaultStack` は NF=5)。メタは `b"fabm"`。
- **メタレコード**(`fabm`): struct { cx0: schema version (u8, 現行 1), cx1:
  last_known_good_epoch (u32) }。version 不一致は復元拒否(`Error::Decode`)—
  将来のマイグレーションはここで分岐する。
- **fabric レコード**(`fabN`): struct {
  cx1: fabric_index (u8), cx2: fabric_id (u64), cx3: node_id (u64),
  cx4: vendor_id (u16), cx5: ipk_epoch_key (bytes 16), cx6: 運用秘密鍵 (bytes 32),
  cx7: RCAC TLV 原本 (bytes), cx8: ICAC TLV 原本 (bytes, 無ければ省略),
  cx9: NOC TLV 原本 (bytes), cx10: label (utf8), cx11: compressed_fabric_id (bytes 8) }。
- **保存するのは「素材」であり導出値は復元時に再計算する**: root_public_key /
  operational IPK は RCAC / epoch key から再導出(HKDF は安価)。cx11 の
  compressed_fabric_id は照合用に保存し、再導出値と不一致なら破損として拒否する。
- レコード上限は `MAX_FABRIC_RECORD_LEN`(証明書 3 通 ≤ 400B ×3 + 鍵 + タグ類)。

### E4.3 秘密鍵の取り出し(公開 API の増分)

- `P256Keypair::to_bytes()`(秘密スカラ 32B の export)と
  `Crypto::p256_keypair_from_bytes()`(import)は**既に trait に存在**するため
  trait 変更は不要。
- `FabricEntry::operational_key_bytes()` を追加(`to_bytes` の薄い転送)。
  **persistence 専用**と doc に明記し、これ以外の用途で秘密鍵を触らせない。
- controller 側 `Ca` にも同趣旨の persistence 用 API を追加する(E4.6)。

### E4.4 `FabricTable` の save/load

- `save_to(&self, kvs)` — メタ + 全スロットを書き、**空きスロットのキーは remove**
  (削除された fabric がゾンビ復活しないように)。
- `load_from(&mut self, kvs, crypto, now) -> Result<usize>` — 空テーブル前提
  (非空は `InvalidState`)。復元数を返す。メタ不在は「初回起動」として `Ok(0)`。
- **復元時もチェーン検証・NOC 公開鍵と運用鍵の一致検査を add と同水準で行う**
  (flash 破損・改竄をロード段で検出する)。検証時刻は `max(now, 保存済み LKGT,
  チェーンの notBefore)`(壁時計を持たないデバイスの LKGT 復元、add と同じ扱い)。
  fabric_index は保存値を採用(採番し直さない — コントローラが覚えている index と
  一致させる必要はないが、remove 後の非連続 index を保存どおり保つ)。
- **呼び出しタイミングは統合層の責務**: `FabricTable::generation()` の変化を検知して
  `save_to` を呼ぶ(PC 版 onoff-light の operational 広告更新と同じパターン)。
  コアはいつ保存するかを知らない(sans-IO 維持)。

### E4.5 ESP32 実装(`ports/esp32/esp32c6-firmware/src/kvs.rs`)

- **esp-storage(`FlashStorage`)+ sequential-storage(map)** で `Kvs` を実装する。
  sequential-storage は no_std の wear-leveling 付き KV(ページ巡回 + 追記型)。
  **IDF の NVS フォーマットとは非互換の自前フォーマット**であることを明記する
  (領域だけを間借りする。IDF ツールで読み書きしない前提)。
- 使用領域はパーティションテーブルの `nvs`(offset 0x9000, len 0x6000 = 4KiB × 6
  ページ)。espflash 既定テーブルの nvs と同じ位置で、アプリ領域と衝突しない。
- sequential-storage の API は async(embedded-storage-async)なので、blocking の
  `FlashStorage` を async trait に持ち上げる薄いアダプタを書き、`Kvs` 実装内で
  `embassy_futures::block_on` で駆動する(下層が blocking なので即完了する)。
- キーは 4 バイト固定(`fab0` 等)を u64 にパックして sequential-storage の
  `Key` 制約を満たす。コアには esp 依存を一切入れない。
- 既知のリスク(実機で要観測): flash 書き込み中はキャッシュが止まるため、BLE
  (esp-radio)稼働中の erase/write でタイミング違反が出る可能性。E4 の保存契機は
  コミッショニング直後(数回)のみなので影響は限定的、問題が出たら BLE idle 時に
  遅延保存する。

### E4.6 検証プロトコル(E4 ゲート)と PC 側の追加

デバイス単体では「リブート後に CASE が張れる」ことを外から証明できないため、
PC 側 `ble-commissioner` に 2 つの機能を足してゲートを閉じる:

1. **CA 永続化**: 初回に CA の素材(root 秘密鍵・コントローラ運用秘密鍵・IPK epoch
   key・fabric_id/node_id/vendor_id・serial カウンタ)をファイル保存し、以後再利用する。
   パスは `--ca-state <file>`(既定 `./ca-state.bin`)。証明書(RCAC/NOC)は保存しない
   — 署名が決定的(RFC 6979)なので同じ鍵から**同一バイト列を再生成できる**し、
   CASE の検証は鍵素材にしか依存しない。コアに `Ca::restore(...)` と persistence 用
   accessor(`root_key_bytes` / `operational_key_bytes` / `next_serial`)を追加する。
2. **`--operational` モード**: スキャン → BLE 接続 → BTP handshake → **PASE を飛ばして
   CASE のみ**(`ControllerStack::start_case`、経路は既存 API で足りる)→ OnOff Toggle。
   `Commissioner` は使わない(example 層で `sc_take_event()` の `CaseEstablished` を
   待つ最小フロー)。

デバイス側はリブート後も **commissionable 広告を出し続ける**(E3 と同じ広告)。
運用広告 = mDNS は E5 スコープであり、E4 では「BLE で繋いで CASE だけ張る」ことで
永続化の正しさを検証する(テストの簡略化。Matter 本来の運用経路ではない点に注意)。

**E4 ゲート**: run1(通常コミッショニング)→ デバイスリセット → run2
`--operational`: CASE 確立 + Toggle 成功。デバイスログは起動時
`[kvs] restored N fabrics`、保存時 `[kvs] saved N fabrics` を出す(bin は
`e4-ble-light`。既存 bin は変更しない)。

## E5 設計: Wi-Fi 実 join + UDP/mDNS

E5 の目的は「chip-tool `pairing ble-wifi` が実 SSID で最後まで通る」こと:
BLE コミッショニング → ConnectNetwork で **実 Wi-Fi join**(esp-radio、BLE と coex)→
DHCP → **運用 mDNS 広告**(IPv4)→ chip-tool が mDNS で発見 → **CASE over UDP** →
CommissioningComplete → OnOff Toggle。以下は確定した設計判断。

### E5.1 `WifiDriver` trait(コア `src/wifi.rs`)

§4 の設計を具体化する。`kvs::Kvs` / `crypto::Rng` と同じ「最小 trait +
プラットフォーム注入」の流儀(依存ゼロ・no_std・feature ゲートなし)。

- `fn connect(&mut self, ssid: &[u8], creds: &[u8])` — join の**開始のみ**
  (非同期完了)。同期・非ブロッキングであること(IM の invoke ハンドラ =
  同期 Mealy machine の中から呼ばれる)。実装はリクエストを記録して即返る。
- `fn status(&self) -> WifiStatus` — `Idle` / `Connecting` / `Connected` /
  `Failed { reason: i32 }`。統合層(pump)や cluster の遅延反映
  (`update_from_driver`)がポーリングで読む。

エラーは `connect` からは返さない(開始要求の記録に失敗する要素がない)。失敗は
すべて `status()` の `Failed` に集約する。

### E5.2 ConnectNetworkResponse は「即 Success + バックグラウンド join」

chip-tool は ConnectNetworkResponse を BLE 上で待つ。仕様は「接続完了後に応答」
だが、現行 IM エンジンは 1 受信 1 応答の同期 Mealy machine で、遅延 InvokeResponse
のメカニズムを持たない(§6 R3)。**E5 では Wi-Fi シムで chip-tool 相互運用を実証済みの
「即 Success を返し、実 join はバックグラウンドで進める」方式を採用する。**

- ConnectNetwork 受信 → `WifiDriver::connect()` を開始 → その場で
  ConnectNetworkResponse(Success) を返す。
- chip-tool はその後 mDNS で運用ノードを探すため、join+DHCP が
  ディスカバリのリトライ窓(数十秒)内に完了すれば全体は成立する。
- **限界**: join 失敗(パスワード誤り等)を ConnectNetworkResponse で報告できない。
  失敗は `LastNetworkingStatus` / `LastConnectErrorValue` 属性
  (`update_from_driver` で反映)からしか観測できず、chip-tool はディスカバリ
  タイムアウトで失敗する。**将来課題**: `HandlerAction` の遅延応答型を IM エンジンに
  追加し、`ConnectMaxTimeSeconds` 以内の完了後応答へ移行する(コア IM の中規模改修。
  E5 スコープ外)。

### E5.3 `NetworkCommissioningWifi` の一般化(型二重化の解消)

既存の Wi-Fi シム版クラスタを `NetworkCommissioningWifi<W: WifiDriver = NullWifiDriver>`
に一般化し、driver 注入型へ変更する:

- `AddOrUpdateWiFiNetwork` で SSID(tag 0)に加え **credentials(tag 1)も保存**する
  (最大 64 バイト。WPA2/WPA3 パスフレーズの上限)。
- `ConnectNetwork` で `driver.connect(ssid, creds)` を呼び、即 Success を返す(E5.2)。
- **PC シムは `NullWifiDriver`(コア提供の「即 Connected」実装)として統合**し、
  既定型パラメータにより既存コード(`NetworkCommissioningWifi::new()`)は無変更で
  動く。型二重化は解消(シム専用型は存在しない)。
- `update_from_driver()`: driver の `status()` を属性
  (Networks[].connected / LastNetworkingStatus / LastConnectErrorValue)へ反映する。
  呼び出しタイミングは統合層(pump)の責務(sans-IO 維持、E4.4 と同じパターン)。
- `cluster!` マクロは非ジェネリック型専用のため、`ServerCluster` は OpCredsCluster と
  同様に手書き実装へ移す(メタは static 1 個、挙動は従来と同一)。

### E5.4 ESP32 実装(Wi-Fi / coex)

- **esp-radio 0.18 の Wi-Fi**(`esp_radio::wifi::new(WIFI, ControllerConfig)` →
  `WifiController` + `Interfaces`)。`coex` feature で BLE と同時動作
  (コミッショニング中は BLE + Wi-Fi 両アクティブ)。
- `WifiController::connect_async()` は async なので、IM ハンドラから直接呼べない。
  **`EspWifiDriver`(コア trait 実装)は要求を `embassy_sync::Signal` に置くだけ**の
  ハンドルとし、専用の `wifi_task`(pump と並走)が Signal を待って
  `set_config(Station)` → `connect_async()` を実行、結果を atomic な状態
  (`WifiStatus` 相当)へ書き戻す。切断イベント時は自動再接続する。
- esp-radio 0.18 の `StationConfig` はパスワードに `alloc::String` を要求する
  (ヒープは esp-radio 用に既に存在するため許容。コアは無関係)。

### E5.5 UDP / mDNS(embassy-net、コア trait の実利用第 1 号)

- **embassy-net**(esp-radio の `Interface` が `embassy-net-driver` 0.2 の `Driver` を
  実装)+ DHCPv4。ports 側 `src/net.rs` に `EspUdp`(`embassy_net::udp::UdpSocket`
  ラッパ)を置き、コアの `UdpSend` / `UdpReceive` / `UdpMulticast` を実装する。
- **IPv4 のみ**(§3 の IPv6 有効化は将来スコープへ後送。chip-tool は IPv4 mDNS で
  相互運用実績あり — PC 版 dual-transport / W3 Windows commissioner で実証済み)。
- `UdpMulticast::join(Ipv6Addr)` の IPv4 グループは **IPv4-mapped IPv6**
  (`::ffff:224.0.0.251`)の規約で受け、実装側で unmap して smoltcp の IGMP join に
  渡す(コア trait のシグネチャ不変更。`canonical_socket_addr` と同じ mapped 規約)。
- ソケットは 2 本: Matter UDP(5540)と mDNS(5353 + 224.0.0.251 join)。
  mDNS responder(sans-IO、コア実装済み)は受信バイト列を `handle_query` に渡し、
  QU クエリはユニキャスト返信(PC 版と同じ)。
- **運用 mDNS の開始タイミング**: DHCP で IPv4 取得後に `MdnsResponder` を構築
  (`Host::from_mac(STA MAC, None, Some(ip))`)。fabric `generation()` 変化で
  operational レコードを更新して再 announce(PC 版と同じパターン)。
  commissionable 広告は BLE(GATT)側が担うため、mDNS は operational のみ広告する。

### E5.6 bin 構成とリソース

- 新 bin `ports/esp32/esp32c6-firmware/src/bin/e5-light.rs` = e4-ble-light
  (BLE + fabric 永続化)+ Wi-Fi/UDP/mDNS dual-transport。移植元は PC 版
  `crates/simple-matter-ble/examples/ble-onoff-light.rs` の select ループ構造。
- ヒープ: Wi-Fi + BLE coex で esp-radio の要求が増える。E4 の 72KiB から増量し、
  SRAM 512KiB(C6)内に収める(実測は E6 の表)。

## 9. 参考(調査ソース)

- 本リポジトリ実測: bluer 版 `GattPeripheral` の実装パターン(channel 化・MTU 取得・
  切断監視)、chip-tool 相互運用で確立した BTP/確立順序/ポンプの教訓(ble-btp.md、
  simple-matter-ble/README.md)。
- rs-matter(research/rs-matter): ESP32-C3 での動作実績(no_std + esp-wifi 構成)、
  BTP/GATT の esp 側配線の先行例。
- esp-rs エコシステム(esp-hal / esp-radio / TrouBLE / embassy-net)の対応状況は
  本書執筆時点の知識ベースであり、**バージョン・API の最新確認は E1 着手時に行うこと**
  (エコシステムの変化が速い。特に esp-wifi → esp-radio の改名・再編後の API)。
