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
| **E0: コアのクロスビルド CI** | `riscv32imc-unknown-none-elf` で simple-matter(ble, controller なし/あり)を check | CI green(コード変更ゼロのはず) | S |
| **E1: ports 骨格 + Lチカ** | ports/esp32 workspace、esp-hal + embassy で C3 起動・ログ・TRNG→`Rng` | 実機でログ出力・乱数取得 | S |
| **E2: BLE スモーク → GattPeripheral** | TrouBLE で 0xFFF6 広告 + C1/C2、R1 確認。`GattPeripheral` 実装 | PC の `ble-commissioner` から BTP handshake 確立(fragment 交渉まで) | M |
| **E3: BLE コミッショニング** | embassy 版ポンプ(毎周 poll・subscribe 前保留の教訓を移植)+ MatterStack | PC commissioner から PASE→AddNOC(chip-tool code-paseonly も) | M |
| **E4: KVS + fabric 永続化** | コアに Kvs trait + fabric TLV 保存/復元、esp-storage 実装 | 再起動後に運用 CASE が再確立できる | M〜L(コア側含む) |
| **E5: Wi-Fi 実 join + UDP/mDNS** | WifiDriver trait、embassy-net で UDP trait 実装、mDNS(IPv4+IPv6) | chip-tool `pairing ble-wifi`(実 SSID)フルパス + toggle | L |
| **E6: bloat-check / チューニング** | C3 実測、バッファ・window の const generic 調整 | flash/RAM 実測値を README/ARCHITECTURE に記録 | S |

**総工数感: L**(E4/E5 がコア側の未整備領域を含むため。BLE 経路だけなら E0-E3 で M)。

## 9. 参考(調査ソース)

- 本リポジトリ実測: bluer 版 `GattPeripheral` の実装パターン(channel 化・MTU 取得・
  切断監視)、chip-tool 相互運用で確立した BTP/確立順序/ポンプの教訓(ble-btp.md、
  simple-matter-ble/README.md)。
- rs-matter(research/rs-matter): ESP32-C3 での動作実績(no_std + esp-wifi 構成)、
  BTP/GATT の esp 側配線の先行例。
- esp-rs エコシステム(esp-hal / esp-radio / TrouBLE / embassy-net)の対応状況は
  本書執筆時点の知識ベースであり、**バージョン・API の最新確認は E1 着手時に行うこと**
  (エコシステムの変化が速い。特に esp-wifi → esp-radio の改名・再編後の API)。
