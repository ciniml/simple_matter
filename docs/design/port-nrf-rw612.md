# nRF52 / nRF54(Nordic)・NXP RW612 への移植可能性 — 調査と設計

対象: デバイス(responder)側スタックを Nordic nRF52840 / nRF54L15 および
NXP RW612 で動かすための移植路線の比較と設計。本書は調査・設計のみで
コード変更を含まない(実施した検証は §5 の thumbv8m クロスチェックのみ)。

前提となる現状(2026-07-14 時点):

- コア(`simple-matter`)は no_std・sans-IO・定常パス no-alloc・executor 非依存。
  継ぎ目はすべて trait 注入: `GattPeripheral`/`GattCentral`(BTP)、
  `UdpSend`/`UdpReceive`/`UdpMulticast`、`Kvs`、`WifiDriver`、`Rng`/`Crypto`。
  Clock は `now_ms` 値渡し(trait なし)。`ThreadDriver` は thread-port.md §4 で
  設計済み(T2 で追加予定)。
- 既存ポートは 2 系統: PC(std、bluer/tokio)と **ESP32-C6 ベアメタル**
  (esp-hal + embassy + TrouBLE + esp-radio。BLE コミッショニング〜Wi-Fi 運用まで
  実機完走済み)。Thread は openthread クレート(esp-rs)でビルド green まで到達
  (thread-port.md)。
- CI 済みクロスターゲット: thumbv6m-none-eabi / riscv32imc / thumbv7em-none-eabihf。
- ユーザ文脈: **nRF 系・RW612 とも Zephyr RTOS 前提の環境で使われている**
  (= Zephyr 統合路線には実運用環境との整合という独立した価値がある)。

対象チップの諸元:

| チップ | CPU | Rust ターゲット | flash / RAM | radio |
|---|---|---|---|---|
| nRF52840 | Cortex-M4F 64MHz | thumbv7em-none-eabihf(**CI 済み**) | 1MB / 256KB | BLE 5 + 802.15.4(Thread デバイスの定番) |
| nRF54L15 | Cortex-M33 128MHz | thumbv8m.main-none-eabi(hf) | 1.5MB RRAM / 256KB | BLE 5.4 + 802.15.4 |
| RW612 | Cortex-M33 260MHz | thumbv8m.main-none-eabihf | 外部 QSPI flash / 1.2MB SRAM | **tri-radio**: Wi-Fi 6 + BLE 5.3 + 802.15.4 |

---

## 0. サマリ(路線比較の結論とチップ別推奨)

1. **nRF52840 は (a) ベアメタル Rust 路線が本命**。部品が全て揃っている:
   embassy-nrf(成熟、0.11.0)+ TrouBLE 0.7(controller に **nrf-sdc** =
   SoftDevice Controller の Rust ラッパを公式サポート)+ **openthread クレートの
   `embassy-nrf` radio feature(nRF52840 で example 実行実績、thumbv7em の
   プリビルト .a 同梱)** + nvmc flash(`Kvs`)。ESP32 ポートの資産
   (TrouBLE ベースの `GattPeripheral`、sequential-storage ベースの `Kvs`、
   embassy ポンプ、OtUdp/SRP 設計)が**ほぼそのまま写像できる**。
   BLE(SDC/MPSL)と 15.4 の共存も道がある: Nordic のオープンソース 802.15.4
   Radio Driver の Rust バインディング **nrf-802154**(git のみ)が「SDC と同時動作
   可能」を明記し、rs-matter-embassy が実際に BLE+Thread 同時コミッショニング
   (coex)と時分割(IRQ mux)の両モードを実装済み(いずれも git・実験的 = §7 R1)。
2. **RW612 は (b) Zephyr 統合路線が唯一の現実解**。RW612 の Rust HAL/PAC は
   存在せず(2026-07 時点、確認済み)、Wi-Fi/BLE はプロプライエタリ blob
   ファームウェア + オープンソースのホストドライバ(Zephyr upstream / MCUX SDK)
   でしか駆動できない。Zephyr は frdm_rw612 / rd_rw612_bga を upstream サポートし、
   NXP 自身が Matter(C++ SDK)の Zephyr ポートを同チップで動かしている =
   プラットフォーム能力は実証済み。
3. **Zephyr 統合の方式は「staticlib + C FFI シム」を本線にする**。コアは sans-IO
   なので「バイト in/out + コールバック」の薄い C API で足りる(§4)。
   zephyr-lang-rust(Zephyr 公式 Rust サポート、4.1 で導入)は 2026-06 現在も
   0.1.0・binding 最小限(**net/BLE binding なし**)で、使うとしてもビルド統合
   (`rust_cargo_application()`)と embassy executor 統合のみ。net/BLE が無い事実は
   sans-IO 設計には痛くない(どうせ C 側から給餌する)。
4. **nRF54L15 は (a) だと「BLE は可・Thread は現状ブロック」**: embassy-nrf 0.11 が
   nrf54l15-app-s/ns を(RRAMC flash 込みで)サポートし、nrf-sdc(git main、
   0.4 未リリース)+ TrouBLE examples/nrf54 で BLE は成立する。しかし
   **embassy-nrf の `radio` モジュール(BLE PHY/802.15.4)は nRF54L 系で未実装
   (`#[cfg(not(feature = "_nrf54l"))] // TODO`)**、nrf-802154 も 54L 非対応のため、
   **Rust には nRF54L15 の 15.4 ドライバが存在しない** = Matter over Thread の
   運用トランスポートが組めない。nRF54L15 は (a) では 15.4 ドライバ整備待ち、
   実運用は (b) Zephyr シムの展開先(Z3)とするのが現実的。
5. **検証ビルド(§5)**: `thumbv8m.main-none-eabi` / `thumbv8m.main-none-eabihf`
   の `cargo check -p simple-matter --all-features` は **green**(コード変更ゼロ、
   2026-07-14、rustc 1.96.0)。M33(nRF54/RW612)へのコア適合はターゲット追加だけで
   確認できた。CI 追加候補(§5.2)。
6. **最初のターゲットは nRF52840 DK での BLE スモーク(路線 a)を推奨**(§6 N1)。
   ESP32 資産の流用率が最も高く、TrouBLE の controller を esp-radio → nrf-sdc に
   差し替えるだけで `GattPeripheral` 契約の検証に入れる。その後 Thread デバイス化
   (N3)。Zephyr シム(Z 系)は RW612 で立ち上げ、実証後に nRF へ展開すれば
   「Zephyr 前提の実運用環境」への出口も塞がない(デュアルトラック)。

---

## 1. 統合路線の比較

### 1.1 (a) ベアメタル Rust 路線(Zephyr 不使用)

nRF 側の部品成熟度(2026-07 時点の調査結果):

| 部品 | 状態 | 本ポートでの役割 |
|---|---|---|
| embassy-nrf **0.11.0**(2026-06-16) | 成熟(nRF52 系)。**nrf54l15-app-s/ns 対応済み**(GPIO/GRTC/RNG に加え **RRAMC flash が embedded-storage 実装**)。802.15.4 radio ドライバは nrf52811/52820/52833/**52840**/5340-net のみ(**nRF54L は TODO ゲートで未実装**) | HAL、`Rng`、flash(`Kvs` 下層)、embassy-time、15.4 radio(nRF52840) |
| TrouBLE(trouble-host)**0.7.0**(2026-06-16) | BLE Host。controller 対応: **nrf-sdc(examples/nrf52・nrf54 同梱)**、ESP32、Pico W、STM32WB55/WBA6、NimBLE、HCI UART。peripheral+central、GATT server(write/notify/**indicate** — indicate はコード確認済みかつ本リポジトリの ESP32 E2 で TrouBLE 0.6 実機実証済み)。BT 資格試験用 tester app あり(qualification 志向) | `GattPeripheral`(ESP32 版 `ble.rs` の worker⇔channel 構造をそのまま流用)。rs-matter-embassy も同構成で Matter BTP を実装済み(先行例) |
| nrf-sdc(crates.io **0.3.0** = nRF52 系+nrf5340-net のみ / **git main 0.4 未リリース** = nrf54l05/10/15-app-s/ns・nrf54lm20 追加)+ nrf-mpsl 0.3.0 | Nordic **SoftDevice Controller**(クローズドバイナリ)の Rust async ラッパ。role feature: peripheral / central / multirole。**旧 SoftDevice(S140)と違いアプリとリンクする通常のライブラリ**で、割り込み予約・flash 配置の呪縛がない(ただし nrf-mpsl #103: MBR 併設で FLASH≠0x0 配置だと init クラッシュ — DFU レイアウト時は注意) | TrouBLE の controller(HCI 相当を in-memory で提供) |
| **nrf-802154**(sysgrok/nrf-802154、**git のみ**。crates.io は 0.0.0 予約) | Nordic の**オープンソース** 802.15.4 Radio Driver の Rust バインディング。README が「**SDC と同時動作可能**(MPSL 経由)」を明記。対応は nRF52 系 + nRF5340-net(**nRF54L 未対応**) | BLE+Thread **同時**動作時の 15.4 radio(embassy-nrf radio 直叩きの代替) |
| openthread クレート **0.2.0**(esp-rs、2026-06-25) | radio 実装として EspRadio と **`embassy-nrf` feature = `NrfRadio`(embassy_nrf::radio::ieee802154、nRF52840 で example 実行実績)** を同梱。ほかに `rcp`(Spinel ホスト。nRF52840 ot-rcp ドングルで UART 検証済み)。プリビルト .a: riscv32imac / **thumbv7em-none-eabi** / thumbv6m(**thumbv8m なし**)。UDP / SRP client / dataset API / Settings trait(thread-port.md §2 の調査どおり) | Thread スタック + `UdpSend`/`UdpReceive` + SRP 運用広告 + `ThreadDriver` |
| rs-matter-embassy(sysgrok、git のみ) | nRF52840 で Matter over Thread を trouble + nrf-sdc + openthread で動かす**先行実装**。BLE/15.4 の共存は 2 モード実装: `light_thread`(IRQ mux による時分割)と `light_thread_coex`(**nrf-802154 + MPSL による真の同時動作**、2026-07 の最新・実験的) | 採用はしない(コアが異なる)が、共存方式・部品組合せの動作リファレンス |
| sequential-storage + embedded-storage | ESP32 E4 で実証済み | `Kvs`(nRF52840 は NVMC、nRF54L15 は RRAMC の上) |

- **nRF52840 は「Thread デバイスの定番石」でありこの路線の主戦場**。BLE(SDC)+
  15.4(openthread)+ flash + TRNG が全部 Rust クレートで揃う唯一の非 Espressif
  チップ。rs-matter も同系統(nrf-sdc + openthread)への移植が進行中で、
  エコシステムの方向性とも一致する。
- **ライセンス注意**: SDC/MPSL は Nordic のクローズドソースバイナリ
  (`LicenseRef-Nordic-5-Clause`、Nordic シリコン上での実行に限定・逆解析禁止)。
  esp-radio の blob と同格の扱いで、本プロジェクトの方針(コアは純 Rust、radio は
  ベンダ提供物を許容)の範囲内。なお 802.15.4 Radio Driver 側は Nordic が
  **オープンソース**で公開している(nrf-802154 はそのバインディング)。
- **Nordic の公式姿勢**: Rust の公式サポートは無し(DevZone 回答で明言)。
  nrf-rs / embassy / nrf-sdc はコミュニティ駆動であり、上記スタックは
  「ベンダ公式サポート無しのエコシステム」前提で選定する(esp-rs が Espressif
  公式であるのとの違い。§7 R2)。
- **RW612 にはこの路線が存在しない**: RW612/RW61x の PAC/HAL は crates.io /
  GitHub に見当たらず(確認済み)、最も近縁でも embassy-imxrt(RT685、ODP/
  Microsoft、2026-05 に 0.1.0)まで。Wi-Fi/BLE ホストドライバ(NXP/wifi_nxp の
  IMU 転送プロトコル)は C ソースから逆読みするしかなく、独立仕様書なし。
  **短期の Rust 直駆動は非現実的**。

### 1.2 (b) Zephyr 統合路線

Rust コアを Zephyr アプリに載せる 2 方式:

| 方式 | 内容 | 評価 |
|---|---|---|
| **staticlib + C FFI シム**(推奨) | コアを `thumbv8m.main-none-eabihf` 等の staticlib にビルドし、CMake(手書き or Corrosion)で Zephyr アプリにリンク。継ぎ目は「バイト in/out + コールバック」の C API(§4) | パターンとして 2021 年から実証済み(Zephyr 公式 blog の cbindgen 記事ほか)。既知の罠: `--allow-multiple-definition`(compiler-builtins の mem* と libc の衝突)、float ABI 整合(hard-float Zephyr ⇔ eabihf) |
| zephyr-lang-rust(Zephyr 公式) | Zephyr 4.1(2025-03)で導入された optional module。`CONFIG_RUST` + `rust_cargo_application()`。thread/sync/timer/logging/allocator の binding と **embassy executor 統合(`zephyr::embassy`、k_timer 裏打ちの time-driver)** を提供 | 2026-06 現在 **0.1.0・リリースなし・binding 最小限**(公式 doc も "rather minimalistic")。**net(zsock)/BLE(bt_*)の binding なし** → Matter ポートにはどのみち自前 FFI が要る。ビルド統合と executor だけ借りる選択肢 |

Zephyr 側プラットフォーム資産(trait 実装の材料)は揃っている:

- **BLE host**: `bt_gatt_service_register()` + `CONFIG_BT_GATT_DYNAMIC_DB` で
  動的サービス登録。chip(C++ Matter SDK)の Zephyr ポートが BTP をこの API で
  実装しており実運用実績あり。
- **OpenThread**: Zephyr 4.2 で独立モジュール化、4.3 で強化。成熟。
- **永続化**: NVS(安定)/ ZMS(4.0 で導入、RRAM 等の新 NVM 向け)+ settings。
- **BSD ソケット**: IPv6 マルチキャスト join(`IPV6_ADD_MEMBERSHIP`)対応。
  4.1 で `IPV6_MULTICAST_IF` 追加。
- **RW612**: frdm_rw612 / rd_rw612_bga が upstream。Wi-Fi は `nxp_wifi` ドライバ +
  `west blobs fetch hal_nxp`(`rw61x_sb_wifi_a2.bin`)、BLE は on-chip controller +
  `rw61x_sb_ble_a2.bin`(いずれも monolithic リンク可)。**NXP 自身の Matter
  Zephyr ポート(NXP/matter、nxp-zsdk ベース)が Matter over Wi-Fi を同板で
  動かしている**。802.15.4/Thread は upstream ではまだ流動的(NXP の
  Matter-over-Thread 実績は FreeRTOS SDK 側。§7 R5)。

### 1.3 判断

| 観点 | (a) ベアメタル Rust | (b) Zephyr + staticlib シム |
|---|---|---|
| 本プロジェクト方針との整合 | ◎(heapless・bloat-check・バイナリ全体を Rust が掌握) | △(フットプリントは Zephyr 込み。ただしコアの規律自体は sans-IO なので汚染されない) |
| nRF52840 | ◎ 部品全部あり + ESP32 資産流用 | ○ 可能(Zephyr の nRF サポートは最成熟)だが旨味は環境整合のみ |
| nRF54L15 | △ BLE のみ(SDC は git、**15.4 ドライバ不存在で Thread 不可**) | ◎ NCS/Zephyr の主力チップ(Thread も C 側は完備) |
| RW612 | ✗ HAL なし・Wi-Fi blob 駆動不能 | ◎ **唯一の現実解**(NXP の Matter 実績あり) |
| ユーザの実運用環境(Zephyr 前提) | ✗ 別 RTOS 構成になる | ◎ そのまま載る |
| 工数 | nRF52840 は ESP32 の再演で S〜M/フェーズ | シム新規設計(C API + ポンプ)が初回 M、以後チップ横断で再利用 |

**結論**: 択一ではなく**併走**。(a) は nRF52840 で最短・最小工数(ESP32 の再演)で
「sans-IO コアの 3 プラットフォーム目」を実証する価値があり、(b) は RW612 の
唯一解かつユーザ環境(Zephyr)への出口。**(b) のシムは一度書けば nRF にも
そのまま使える**(Zephyr の BT host/OpenThread/NVS は nRF で最も成熟)ため、
RW612 で立ち上げた Zephyr シムを nRF54L15/nRF52840 の Zephyr 環境へ展開する形が
全体最適(§6)。

## 2. 継ぎ目 trait 対応表(sans-IO 設計の効果測定)

ESP32 移植で実証した「コア無改造・trait 実装の差し替えのみ」の対応表を
4 プラットフォームへ拡張する。**この表が本 doc の再利用価値の中心**。

| コア trait / 継ぎ目 | PC(std) | ESP32-C6(実績) | nRF52840(a) | nRF54L15(a) | Zephyr(b: RW612/nRF) |
|---|---|---|---|---|---|
| `GattPeripheral` | bluer(BlueZ) | TrouBLE + esp-radio(`ble.rs`、worker⇔channel) | **TrouBLE + nrf-sdc(peripheral)** — `ble.rs` をほぼ流用 | 同左(nrf-sdc git の nrf54l15-app-s feature) | C シム: `bt_gatt_service_register`(DYNAMIC_DB)+ indicate/CCCD コールバック → イベントキュー |
| `UdpSend` / `UdpReceive` | std::net | embassy-net(Wi-Fi)/ OtUdp(Thread) | **openthread `UdpSocket`**(OtUdp — thread-port.md §3.4 の写しそのまま) | **不可**(15.4 ドライバ不存在 = 運用トランスポートなし) | C シム: `zsock_sendto`/`zsock_recvfrom`(専用 RX スレッド → キュー) |
| `UdpMulticast` | socket2 | smoltcp IGMP/MLD | 不要(Thread 運用は SRP。thread-port.md §3.4) | — | `zsock_setsockopt(IPV6_ADD_MEMBERSHIP)` |
| `Kvs` | ファイル | esp-storage + sequential-storage | **embassy-nrf NVMC** + sequential-storage | **embassy-nrf RRAMC**(embedded-storage 実装済み)+ sequential-storage | C シム: NVS or ZMS(settings)get/set |
| `WifiDriver` | NullWifiDriver | esp-radio(EspWifiDriver) | —(Wi-Fi なし) | — | C シム: `net_mgmt`(NET_REQUEST_WIFI_CONNECT)+ 状態コールバック |
| `ThreadDriver` | NullThreadDriver(T2) | openthread(OtThreadDriver、T2) | openthread(radio = embassy-nrf `NrfRadio` or nrf-802154)— OtThreadDriver 流用 | **不可**(同上) | C シム: Zephyr OpenThread(`otThreadSetEnabled` 等の otApi) |
| `Rng` | OsRng | esp-hal TRNG | embassy-nrf `Rng`(HW) | 同左 | C シム: `sys_csrand_get`(CSPRNG) |
| Clock(`now_ms` 値渡し) | Instant | embassy-time | embassy-time | embassy-time | `k_uptime_get()` |
| `Crypto` | RustCrypto(共通) | 同左 | 同左 | 同左 | 同左(コア内蔵。Zephyr の mbedTLS とは独立) |
| 実行形態 | tokio | esp-rtos thread-mode executor | **embassy-executor**(ポンプ構造は e3〜e5 bin の写し) | 同左 | 専用 Zephyr thread 上の同期ポンプ(§4.2)or zephyr-lang-rust の embassy executor |

読み取れること:

- (a) 路線の nRF52840 は**新規設計がゼロ**(全行が既存実装の流用 or 既製クレート)。
  差分は「TrouBLE の controller 初期化」と「openthread の radio 初期化」だけ。
  nRF54L15 列は BLE までで途切れる(15.4 ドライバ不存在。§7 R3)。
- (b) 路線は全行が「C シム経由」になるが、trait の契約(呼び出し側バッファ・
  イベントキュー・開始のみ+status ポーリング)は bluer/TrouBLE 実装で確立した
  パターンがそのまま C API の形を規定する(§4.1)。
- コア(`Crypto`/`Rng` を除く全プロトコル処理)はどの列でも**無改造**。
  thumbv8m 検証(§5)がこれをビルドレベルで裏付けた。

## 3. チップ別推奨マトリクスと工数感

| チップ | 推奨路線 | BLE | 15.4/Thread | Wi-Fi | flash(Kvs) | 工数感(BLE コミッショニングまで/Thread 運用まで) |
|---|---|---|---|---|---|---|
| **nRF52840** | **(a) 本命** | TrouBLE + nrf-sdc(実績ある組合せ、ESP32 版 ble.rs 流用) | openthread `embassy-nrf`(プリビルトあり、example 実績)。BLE 共存は時分割 or nrf-802154(§7 R1) | — | NVMC + sequential-storage | **S〜M / M**(ESP32 E0〜E4 + T 系の再演。リスクは coex = §7 R1) |
| **nRF54L15** | (a) は BLE まで/実運用は **(b) 展開先(Z3)** | TrouBLE + nrf-sdc(**git main のみ**、nrf54l15-app-s) | **(a) 不可**: Rust の 15.4 ドライバ不存在(embassy-nrf radio は nRF54L 未実装、nrf-802154 も 54L 非対応)。(b) なら Zephyr OpenThread で可 | — | RRAMC + sequential-storage(a)/ ZMS(b) | (a) BLE スモークのみ S〜M。フル機能は 15.4 ドライバ待ち or (b) で M(シム再利用時 S〜M) |
| **RW612** | **(b) 唯一解** | Zephyr BT host + BLE blob | upstream は流動的(§7 R5)。当面 **Matter over Wi-Fi** | `nxp_wifi` + Wi-Fi blob(monolithic) | NVS/ZMS(settings) | M〜L / —(シム初回設計込み。Wi-Fi 版は NXP の Matter 実績があり道は舗装済み) |
| (参考)nRF52840/54L15 on Zephyr | (b) 展開先 | Zephyr BT host(最成熟) | Zephyr OpenThread(成熟) | — | NVS/ZMS | RW612 でシム実証後なら S〜M(シム再利用) |

- フットプリント見込み(nRF52840、1MB flash / 256KB RAM): コア ~85KB(thumbv7em
  実測)+ SDC(peripheral 構成、数十 KB)+ openthread + MbedTLS(ESP32 実測で
  OT 一式 ~330KiB)+ HAL/executor。**flash は 600KB 級に収まる見込みで 1MB 内、
  RAM はコア ~20KiB + SDC/MPSL ~10-20KiB + OT バッファで 256KB に余裕**。
  正確な値は N1/N3 で `size -A` 実測を README に記録する(ESP32 E6 と同じ流儀)。

## 4. Zephyr 統合(staticlib + C FFI シム)の設計

### 4.1 C API の形(sans-IO の写像)

コアの trait は「バイト in/out + イベント」に還元できるので、シムは薄い:

```c
/* rust 側(staticlib)が export。ハンドルは static 確保(pinned-init)。 */
void  sm_init(const sm_config_t *cfg, uint64_t now_ms);
/* 受信給餌: UDP datagram / BLE C1 write / BLE 接続イベント */
void  sm_udp_rx(const uint8_t *buf, size_t len, const sm_addr_t *src, uint64_t now_ms);
void  sm_ble_event(const sm_ble_event_t *ev, uint64_t now_ms);  /* connected/c1_write/c2_subscribed/disconnected */
/* ポンプ: 期限処理 + 送出要求の回収。次に呼ぶべき時刻を返す(MRP/購読の deadline)*/
uint64_t sm_poll(uint64_t now_ms);
/* C 側が実装するコールバック(送出・状態変化)*/
void  sm_out_udp_tx(const uint8_t *buf, size_t len, const sm_addr_t *dst);
void  sm_out_ble_indicate(uint8_t conn, const uint8_t *frag, size_t len);
void  sm_out_wifi_connect(const uint8_t *ssid, size_t ssid_len, const uint8_t *creds, size_t creds_len);
void  sm_out_kvs_set(const uint8_t *key, size_t klen, const uint8_t *val, size_t vlen);
/* … Kvs get / mDNS join / Thread dataset 等、trait 1 メソッド ≒ C 関数 1 本 */
```

- **設計原則: trait 契約をそのまま C に写す**。呼び出し側バッファ・イベント駆動・
  「開始のみ + status ポーリング」(WifiDriver/ThreadDriver)の各契約は
  C API でも同一に保つ。コアの async trait は、シム内部では
  「即時完了 future」(コールバック送出をキューに積むだけ)として実装するため
  executor は不要 — PC/ESP32 のポンプループを C の `sm_poll` 周期呼び出しに
  置き換えた形になる。
- スレッドモデル: Zephyr 側は BT RX/ソケット RX が別スレッドで届くため、
  シム入口で 1 本のメッセージキュー(`k_msgq`)に直列化し、専用スレッドが
  `sm_udp_rx`/`sm_ble_event`/`sm_poll` を呼ぶ(コアは `&mut` 単線アクセス)。
  ESP32 の「worker⇔channel」構造の Zephyr 版。
- 代替: zephyr-lang-rust の `zephyr::embassy` executor 上に既存の embassy ポンプを
  そのまま載せる方式も可能(Rust 側完結度が上がる)。ただし module 自体が 0.1.0 で
  流動的なため、**初版は依存しない**(ビルド統合も手書き CMake + cargo とし、
  安定後に乗り換え検討)。

### 4.2 ビルド統合

- `ports/zephyr/`(新 workspace): `sm-shim` crate(cdylib ではなく **staticlib**、
  `crate-type = ["staticlib"]`)+ cbindgen でヘッダ生成。ターゲットは
  RW612 = `thumbv8m.main-none-eabihf`(Zephyr 側 FPU 設定と ABI を必ず一致させる)。
- Zephyr アプリ側(C): CMake `add_library(sm STATIC IMPORTED)` +
  `target_link_libraries`。既知の罠(調査で確認済み):
  `--allow-multiple-definition`(compiler-builtins の mem* と picolibc の衝突)、
  Kconfig で FPU/ABI を Rust ターゲットに揃える。
- blob: `west blobs fetch hal_nxp` で Wi-Fi/BLE blob を取得し
  `CONFIG_NXP_MONOLITHIC_*` でアプリに同梱(書き込み 1 回で済む構成)。

## 5. 検証ビルド(thumbv8m.main = Cortex-M33)

### 5.1 実施結果(2026-07-14、rustc 1.96.0 stable)

```sh
rustup target add thumbv8m.main-none-eabi thumbv8m.main-none-eabihf  # 追加のみ
cargo check -p simple-matter --all-features --target thumbv8m.main-none-eabi    # ✅ green
cargo check -p simple-matter --all-features --target thumbv8m.main-none-eabihf  # ✅ green
cargo check -p simple-matter --no-default-features --target thumbv8m.main-none-eabi  # ✅ green
```

- **コード変更ゼロで green**。再ビルドされた依存は p256/ecdsa/primeorder のみ
  (ターゲット固有コードがコアに無いことの傍証)。nRF54L15 / RW612 の
  CPU(M33)に対するコア適合はこれで確認済み。

### 5.2 CI 追加候補

既存の no_std クロスチェック行(thumbv6m / riscv32imc)に 1 行追加する:

```yaml
      - name: Check no_std (Cortex-M33 / nRF54+RW612 gate)
        run: cargo check -p simple-matter --all-features --target thumbv8m.main-none-eabi
```

(toolchain の `targets:` に `thumbv8m.main-none-eabi` を追記。)N1 着手時に
ESP32 E0 と同じ「移植の前提ゲート」としてコミットする。

## 6. フェーズ計画

ESP32(E 系)/ Thread(T 系)と同じ「スモーク → コミッショニング → 運用」の
段階割り。N 系 = nRF ベアメタル、Z 系 = Zephyr シム。

| フェーズ | 範囲 | 検証ゲート | 工数感 |
|---|---|---|---|
| **N0: コアの M33 ゲート CI** | §5.2 の 1 行(+ M4F は CI 済み) | CI green(コード変更ゼロ) | S |
| **N1: nRF52840 DK BLE スモーク**(**最初のターゲット**) | `ports/nrf`(新 workspace、lock 分離 — ESP32 R4 と同じ理由)。embassy-nrf + nrf-sdc(peripheral)+ TrouBLE 0.7 で 0xFFF6 広告 + C1/C2。`GattPeripheral` 実装は ESP32 `ble.rs` の移植(controller 初期化のみ差し替え) | PC `ble-commissioner` から BTP handshake 確立(ESP32 E2 ゲートと同一) | S〜M |
| **N2: BLE コミッショニング + KVS** | MatterStack 統合(e3/e4 bin の写し)。`Kvs` = NVMC + sequential-storage、`Rng` = embassy-nrf Rng、SPAKE2+ verifier 前計算 | フルコミッショニング完走 + リブート後 CASE 再確立(E3+E4 ゲート) | M |
| **N3: Thread 運用(Matter over Thread)** | openthread 0.2(`embassy-nrf` feature)+ OtUdp + OtThreadDriver + SRP + KvsSettings(すべて thread-port.md T2 の設計を流用)。**最初に BLE(SDC)+15.4 の共存方式を確定**(§7 R1: 第一候補 = 時分割(コミッショニング後に SDC → 15.4 切替)、第二候補 = nrf-802154(git)による同時動作) | `chip-tool pairing ble-thread` 完走 + toggle(CASE over Thread)+ リブート re-attach(T2 ゲートと同一) | M〜L(R1 次第) |
| **N4: nRF54L15 展開(条件付き)** | N1〜N2 相当(BLE コミッショニング + KVS(RRAMC)まで)を nrf54l15-app-s で。**着手条件: nrf-sdc 0.4 の crates.io リリース**。Thread は Rust の 15.4 ドライバ(embassy-nrf radio の nRF54L 対応 or nrf-802154 の 54L 対応)が出るまで凍結し、フル機能は Z3(Zephyr シム)で先行 | N2 と同ゲート(運用トランスポートは保留) | M |
| **Z1: Zephyr シム PoC(RW612)** | frdm_rw612 + upstream Zephyr。staticlib リンク + `sm_poll` ポンプ + UDP シムのみ(BLE なし)で **IP コミッショニング**(PC 版 onoff-light 相当)を通す | chip-tool `pairing onnetwork`(Wi-Fi 接続は shell で事前確立)+ toggle | M(シム初回設計込み) |
| **Z2: RW612 フル(BLE + Wi-Fi)** | BT host シム(`GattPeripheral` 相当のイベント写像)+ `WifiDriver` シム(net_mgmt)+ NVS/ZMS `Kvs` シム | `pairing ble-wifi` 完走(NXP Matter Zephyr ポートと同等の到達点) | M〜L |
| **Z3(任意): Zephyr シムの nRF 展開** | 同一シムを nrf52840dk / nrf54l15dk でビルド(ユーザの Zephyr 前提環境への出口) | N2 相当ゲートが Zephyr 構成で通る | S〜M(シム再利用) |

- **推奨順序: N0 → N1 → N2 → N3(nRF52840 を Thread デバイスとして完成)**、
  Z1/Z2 は RW612 実機の入手/優先度に応じて並走。N4 は N3 の後。
- 依存関係: Z 系は N 系に依存しない(シムは PC 版ポンプ構造から直接導ける)。
  N3 は T2(ESP32 Thread、`ThreadDriver`/`NetworkCommissioningThread` のコア追加)
  の完了が前提。

## 7. リスク一覧

| # | リスク | 影響 | 確認方法 / 回避策 |
|---|---|---|---|
| R1 | **BLE(SDC/MPSL)と 15.4 の同時動作**: embassy-nrf の 15.4 radio 直叩きは SDC と RADIO 所有権が衝突する。同時動作の既知解は nrf-802154(MPSL 配下、「SDC と同時動作可能」を README 明記)だが **git のみ・2026-07 に動き出したばかりの実験段階**(rs-matter-embassy の `light_thread_coex` が唯一の動作例) | 高(N3 の `pairing ble-thread`) | N3 冒頭で共存方式を単体検証。**第一候補 = 時分割**: コミッショニング中は BLE のみ → dataset 受領・ConnectNetwork 後に SDC を停めて 15.4 起動(ESP32 T 系 R2 と同じ緩和。chip-tool は CASE を Thread 側で張るので BTP 維持は必須でない。rs-matter-embassy `light_thread` の IRQ mux が先行例)。**第二候補 = nrf-802154 で真の同時動作**(成熟待ち、rev 固定で試行) |
| R2 | nrf-sdc/nrf-mpsl が若い(crates.io 0.3.0、0.4 未リリース)。API 流動・ドキュメント薄・**ベンダ公式サポート無し**(Nordic は Rust 公式サポートを明確に否定)。既知バグ: nrf-mpsl #103(MBR 併設・FLASH≠0x0 配置で init クラッシュ → DFU/ブートローダ構成に影響) | 中 | TrouBLE examples(nrf52840dk)+ rs-matter-embassy が動作リファレンス。バージョン固定 + ports workspace の lock 分離。DFU レイアウトは当面スコープ外と明記 |
| R3 | **nRF54L15 の 15.4 ドライバが Rust に不存在**(embassy-nrf radio は `_nrf54l` で TODO ゲート、nrf-802154 も 54L 非対応)= (a) 路線では Thread 不可。BLE 側も nrf-sdc の nRF54L feature は git のみ。加えて openthread の thumbv8m プリビルト無し → 対応が来てもソースビルド(CMake+Clang)が「stable rustc のみ」の前提を破る | 中(N4) | N4 は BLE スコープに限定 + 着手条件(nrf-sdc 0.4 リリース)を設定。フル機能は Z3(Zephyr シム)で先行。upstream(embassy-nrf radio の 54L 対応)をウォッチ |
| R4 | zephyr-lang-rust の成熟度(0.1.0、net/BLE binding なし、Zephyr main 追従) | 低(依存しない設計にした) | §4 のとおり初版は手書き CMake + cargo。executor 統合のみ将来検討 |
| R5 | **RW612 の 802.15.4/Thread が upstream Zephyr で流動的**(NXP の Matter over Thread 実績は FreeRTOS SDK 側) | 中(RW612 での Thread) | Z1/Z2 は Wi-Fi スコープに限定(NXP 実績と同じ到達点)。Thread は upstream の成熟を待つ(RW612 は tri-radio だが当面 Wi-Fi デバイスとして扱う) |
| R6 | RW612 の Wi-Fi/BLE blob(プロプライエタリ)への依存 | 低(構造的に不可避) | Zephyr 公式の `west blobs` 配布 + monolithic リンクで管理。ライセンスは NXP LA_OPT(製品化時に確認) |
| R7 | Matter over Thread の運用広告(SRP)・MTU 等の仕様適合 | 低(**解決済みの再利用**) | openthread クレートの SRP client + `MAX_TX_PACKET_SIZE=1232`(IPv6 MTU 1280 適合)は thread-port.md / matter-over-vpn.md で検証済みの設計をそのまま使う |
| R8 | Zephyr シムのスレッド境界(BT RX/ソケット RX とポンプの直列化)でのイベント欠落・優先度逆転 | 中(Z1 で表面化) | §4.1 の単一 k_msgq 直列化を最初から採用(ESP32 worker⇔channel の教訓)。キュー深さは BTP フラグメント最大レートで見積る |

## 8. 参考(調査ソース、2026-07-14 取得)

- 本リポジトリ: `docs/design/port-esp32-device.md`(移植の型・E 系ゲート)、
  `docs/design/thread-port.md` §2(openthread クレート調査 — nRF radio・プリビルト
  ターゲット・SRP/Settings API)、`ports/esp32/`(TrouBLE 版 GattPeripheral・
  sequential-storage 版 Kvs の実装)。
- TrouBLE: github.com/embassy-rs/trouble(0.7.0、controller 一覧に nRF SDC、
  examples/nrf52 + examples/nrf54(後者は embassy/nrf-sdc の git rev 固定)、
  indicate 実装は host/src/attribute_server.rs で確認)。crates.io trouble-host
  0.7.0(2026-06-16)。
- nrf-sdc: github.com/alexmoon/nrf-sdc(git main = 0.4 未リリースで
  nrf54l05/10/15-app-s/ns・nrf54lm20 追加。crates.io 0.3.0(2025-08-28)は
  nRF52 系 + nrf5340-net のみ)。SDC/MPSL blob のライセンスは
  sdk-nrfxlib の LicenseRef-Nordic-5-Clause。既知 issue: nrf-mpsl #103。
- nrf-802154: github.com/sysgrok/nrf-802154(git のみ、最終 push 2026-07-08。
  「SDC と同時動作可能」を README 明記。nRF52 系 + nrf5340-net)。
- rs-matter-embassy: github.com/sysgrok/rs-matter-embassy
  (nRF52840 の `light_thread`(時分割 IRQ mux)/ `light_thread_coex`
  (nrf-802154 + MPSL)example — 共存方式の先行実装)。
- embassy-nrf: crates.io 0.11.0(2026-06-16)、docs.embassy.dev(nrf54l15-app-s の
  `rramc`(embedded-storage 実装)ほか)。src/radio/mod.rs の cfg で 15.4 対応
  チップ(52811/52820/52833/52840/5340-net)と nRF54L の TODO ゲートを確認。
- openthread: crates.io 0.2.0(2026-06-25)、esp-rs/openthread README
  (`embassy-nrf` feature = `NrfRadio`(nRF52840 example 実績)、`rcp` は
  nRF52840 ot-rcp ドングルで UART 検証済み、プリビルト
  riscv32imac/thumbv7em/thumbv6m)。
- Nordic 公式姿勢: DevZone「How much does Nordic actually support Rust
  developers?」(公式サポート無しの明言)、zephyr-lang-rust issue #126
  (nRF54 は zephyr-lang-rust でも未動作)。
- Zephyr Rust: docs.zephyrproject.org「Rust Language Support」(4.1 で導入)、
  zephyrproject-rtos/zephyr-lang-rust(0.1.0、`zephyr::embassy` executor、
  net/BLE binding なし)、Zephyr 公式 blog「Embedding Rust Into Zephyr Firmware
  Using C-bindgen」(staticlib パターンと linker の罠)。
- RW612: docs.zephyrproject.org の frdm_rw612 / rd_rw612_bga ボード doc
  (`rw61x_sb_wifi_a2.bin`/`rw61x_sb_ble_a2.bin`、monolithic ビルド)、
  project-chip「Matter NXP Zephyr Application」ガイド、NXP/matter(v1.4.0-pvw1、
  nxp-zsdk で frdmrw612 Wi-Fi ビルド)、NXP/wifi_nxp(ホストドライバ C ソース)。
  Rust HAL/PAC は不存在を確認(最近縁は ODP embassy-imxrt = RT685、2026-05)。
- MPSL 共存(R1 の背景): Nordic MPSL timeslot API doc、NCS の
  `CONFIG_MPSL`(15.4 ドライバとの共存は timeslot 経由)。
