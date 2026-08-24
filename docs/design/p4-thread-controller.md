# F8: ESP32-P4 + ESP32-H2 — TBR 兼 Thread Matter コントローラ

Status: 設計 → 実装(実機は後日ユーザ検証。本フェーズのゲートはビルド green まで)
Depends: docs/design/c-ffi-shim.md(§10 F6 デバイス Thread、§11 F7a/F7b コントローラ)

## 1. 目的

ESP-IDF C++17 アプリとして、ESP32-P4(ホスト MCU、radio なし)+ ESP32-H2
(802.15.4 RCP、UART 接続)の構成で動く **Thread ネットワーク主宰(leader)兼
SRP サーバ兼 Matter コントローラ** を作る。simple-matter 側の材料(コントローラ
C FFI = F7a/F7b)は完成済みで、本フェーズは ESP-IDF 側の統合が主となる。

TBR(border routing、backbone = WiFi/Ethernet)は Kconfig でオプション化し、
既定ビルド(backbone なし)は「自己完結 Thread ハブ」として成立させる。
コントローラ自身が OT ホストとして Thread メッシュ上に居るため、Thread デバイス
との Matter 通信(PASE/CASE/IM over UDP)に border routing は不要。

## 2. ハードウェア前提

- ESP32-P4: OT ホスト + simple-matter コントローラ。PSRAM 搭載なら供給メモリを
  PSRAM に置く(F7a と同じ heap_caps 優先順)。非搭載でも internal fallback。
- ESP32-H2: `ot_rcp`(spinel over **UART**、既定 460800)。P4 と UART で結線。
  ピン割当はボード依存のため P4 側は Kconfig、H2 側はビルドスクリプトの env で
  指定可能にする(既定は IDF ot_rcp の既定 = UART0 ピン。要スクリプト内コメント)。
- BLE なし。よって **コミッショニングは on-network PASE over Thread UDP**
  (デバイスに dataset をプリセットして Thread 参加させておく。§6)。

## 3. 構成要素と変更点

### F8a: ESP-IDF コンポーネントの esp32p4 対応

`ports/esp-idf/components/simple_matter/CMakeLists.txt`:

- `IDF_TARGET=esp32p4` → Rust ターゲット `riscv32imafc-unknown-none-elf`
  (stable rustc、rustup 導入済み。ilp32f ABI = P4 の GCC hard-float と一致する
  こと。ビルド後 ELF リンクが ABI mismatch で落ちないことがゲート)。
- 経路 (a) SM_PREBUILT_A / (b) cargo 両対応(C6/C3 と同格)。
- README.md の対応表更新。

### F8b: シム API 追加 — `sm_ctrl_set_node_addr`

Thread では運用アドレス解決が mDNS ではなく SRP(P4 自身が SRP サーバ)になる。
C++ 側が `otSrpServerGetNextHost()` 列挙で得たデバイスアドレスをノード帳へ
反映できるよう、`crates/simple-matter-cffi/src/controller.rs` に追加:

```c
// 既知ノードの運用アドレスを直接設定する(Thread/SRP 等、mDNS 以外の解決経路用)。
// 戻り値: 0=OK、-1=未初期化/NULL、-2=ノード帳に node_id なし。
int32_t sm_ctrl_set_node_addr(uint64_t node_id, const sm_addr_t *addr);
```

実装は `sm_ctrl_mdns_rx` の解決成功時と同じノード帳更新経路を呼ぶだけ
(コア変更なし。シム内で完結すること)。cbindgen ヘッダ再生成
(`scripts/gen-cffi-header.sh`、`--check` 冪等)+ ctest ホストテスト 1 本追加。

なお pairing 時に使ったアドレスはノード帳に残るため、アドレスが安定な
Thread(ML-EID)では F8b なしでも定常運用は成立する。F8b は再解決
(デバイス再起動で OMR が変わる等)のための補助。

### F8c: example `ports/esp-idf/examples/thread_ctrl_hub_cpp`(新規)

`controller_hub_cpp`(F7a/F7b)の骨格 + `onoff_light_cpp/main/ot_thread.cpp`
(F6)の OT 配線を土台に P4 向けに新設。既存 2 example は変更しない。

- **OT init**: F6 との差分は
  `config.radio_config.radio_mode = RADIO_MODE_UART`(+ UART port/pins/baud を
  Kconfig から)、`HOST_CONNECTION_MODE_NONE`、storage は NVS。
- **ネットワーク主宰**: NVS に active dataset があれば復元、なければ
  - `CONFIG_SM_THREAD_DATASET_TLV_HEX` 非空: その TLV を `otDatasetSetActiveTlvs`
  - 空: `otDatasetCreateNewNetwork` で生成
  して ifup + thread start → leader 化。**active dataset TLV を hex で必ずログ
  出力する**(デバイス側プリセット用。§6)。
- **SRP サーバ + DNS-SD**: `otSrpServerSetEnabled(inst, true)`。デバイスの
  `_matter._tcp` SRP 登録を受ける。
- **コントローラ**: F7a と同一の供給メモリ経路(PSRAM 優先)+ NVS "smctl"
  KVS 配線 + UDP ポンプ(`main.cpp` の `run_until`/`drain_tx` をほぼ流用。
  IPv6 リンクローカルは scope_id が要るため `sockaddr_to_smaddr`/`send_sm` の
  v6 経路が正しく通ること)。タスクスタックは **128KB**(実機確定値)。
- **pairing**: 未コミッショニング時、`CONFIG_SM_TARGET_IPV6`(デバイスの
  ML-EID/OMR、ユーザがデバイスログから転記)へ `sm_ctrl_pair_start`
  (on-network PASE。F7a の IPv4 固定と鏡像)。
- **定常**: 30 秒毎 OnOff Toggle。invoke 失敗が続いたら SRP サーバ列挙
  (`otSrpServerGetNextHost` → instance 名にノード ID 下位 16hex を含む host の
  アドレス)→ `sm_ctrl_set_node_addr` → リトライ、を 1 回試す(F8b の実戦配線)。
  OT API 呼び出しは必ず `esp_openthread_lock_acquire/release` で囲む。
- **Kconfig**: UART(port/RX/TX/baud)、dataset TLV hex、target
  node id / passcode / IPv6、SM_THREAD_BR(§F8e、default n)。
- **sdkconfig.defaults**: esp32p4、`CONFIG_ESP_MAIN_TASK_STACK_SIZE=131072`
  (または専用タスク 128KB)、`CONFIG_OPENTHREAD_ENABLED=y`、RCP UART 系、
  `CONFIG_SPIRAM` 系(P4 は `CONFIG_SPIRAM_IGNORE_NOTFOUND=y` 相当の非搭載時
  fallback を維持)、eventfd(`esp_vfs_eventfd` は vfs コンポーネント)。

### F8d: `scripts/otbr/build-ot-rcp-h2.sh`

`build-ot-rcp.sh`(C6/USB)の姉妹版。H2 向け `ot_rcp` を
`espressif/idf:release-v5.4` docker でビルドし `dist/ot_rcp_h2/` に merged bin を
出す。spinel は **UART(GPIO)**(P4 と結線するため。USB CDC ではない)。
baud / UART ピンを env で上書き可能に。flash 手順コメント付き。

### F8e: TBR(backbone)オプション — ベストエフォート

`CONFIG_SM_THREAD_BR=y` のとき `CONFIG_OPENTHREAD_BORDER_ROUTER=y` +
backbone netif(P4 は radio なしのため esp_wifi_remote / esp-hosted 経由 WiFi、
ボード例: M5Stack Tab5 = P4+C6)を配線し、`esp_openthread_border_router_init`
を呼ぶ。これで LAN 側 chip-tool からも Thread デバイスが見える(advertising
proxy)。**docker ビルドで managed component(esp_wifi_remote/esp_hosted)の
統合が過大な障害になる場合は、Kconfig 足場 + README 記録までで打ち切り、
実機フェーズ送りとする**(既定ビルドのゲートには含めない)。

## 4. ゲート(親が再実行して確認)

1. ホスト: `cargo test --workspace`(既存 639 + F8b 追加分)green、
   `scripts/gen-cffi-header.sh --check` 冪等。
2. `cargo build -p simple-matter-cffi --release --target riscv32imafc-unknown-none-elf --features panic-abort` green。
3. docker `espressif/idf:release-v5.4`: `thread_ctrl_hub_cpp` を
   `idf.py set-target esp32p4 && idf.py build` green(既定 = backbone なし。
   経路 (b) cargo。コンテナは rustup をホスト同一パスでマウント)。
   終了時にコンテナ内で build/・sdkconfig を rm(root 残骸なし)。
4. 回帰: `onoff_light_cpp` esp32c6 build green(コンポーネント CMake 変更の回帰)。
5. `build-ot-rcp-h2.sh` 完走、`dist/ot_rcp_h2/merged_ot_rcp.bin` 生成。

## 5. 実機手順(後日、ユーザ機材接続後)

1. H2 に `dist/ot_rcp_h2/merged_ot_rcp.bin` を flash(ポートはその都度確認)。
2. H2↔P4 を UART 結線(TX/RX クロス + GND。ピンは Kconfig/env の設定と一致させる)。
3. P4 に thread_ctrl_hub_cpp を flash → ログの dataset TLV hex を控える。
4. デバイス側(onoff_light_cpp Thread 構成 or t2-light)に同 dataset をプリセット
   して起動 → attach 後のログから ML-EID/OMR を控える。
5. P4 の `CONFIG_SM_TARGET_IPV6` に転記して再ビルド/flash → PASE → PAIR COMPLETE
   → 30 秒毎 toggle を確認。

## 6. リスク

- **R-P4-1**: esp_openthread の RADIO_MODE_UART が esp32p4 で未サポート/未検証の
  可能性(v5.4)。ビルドで判明する。落ちる場合は IDF バージョン変更
  (release-v5.5)を検討して記録する。
- **R-P4-2**: riscv32imafc の ilp32f ABI と IDF P4 ツールチェーンの整合。最終
  ELF リンクまで通ることで確認(imac/ilp32 の .a は soft/hard float mismatch で
  リンク不可のはず — だからこそ imafc を使う)。
- **R-P4-3**: on-network PASE はデバイスが commissionable window open であること
  が前提。onoff_light_cpp/t2-light は未コミッショニング起動時に window open で
  実装済み(F1〜)。既コミッショニング状態のデバイスでは pairing 不可(仕様通り)。
- **R-P4-4**: UART RCP の spinel 断片取りこぼし(C6 vendored OT の R9 系)は
  ESP-IDF ホスト側では未観測(F6 実績)。P4+UART では新規条件のため実機で確認。

## 7. 実装記録(F8a〜F8e、2026-07-31)

ビルドゲート(§4 の 1〜5)は全て green。実機検証はユーザの機材接続後。

### 変更 / 追加ファイル

- **F8b(シム)**: `crates/simple-matter-cffi/src/controller.rs`
  (`sm_ctrl_set_node_addr` + テスト追記)、`crates/simple-matter-cffi/include/simple_matter.h`
  (cbindgen 再生成)、`crates/simple-matter-cffi/ctest/controller.cpp`(`setaddr` コマンド)。
  コア(`crates/simple-matter`)への変更ゼロ。
- **F8a(コンポーネント)**: `ports/esp-idf/components/simple_matter/CMakeLists.txt`
  (esp32p4 = `riscv32imafc-unknown-none-elf`、+ soft-float .o 除去ステップ)、
  同 `README.md`、新規 `strip_softfloat_objs.cmake`。
- **F8c(example、新規)**: `ports/esp-idf/examples/thread_ctrl_hub_cpp/`
  = `CMakeLists.txt` / `partitions.csv`(app 2.75MB)/ `sdkconfig.defaults` /
  `sdkconfig.defaults.br`(F8e)/ `README.md` /
  `main/{CMakeLists.txt,Kconfig.projbuild,main.cpp,ot_hub.cpp,ot_hub.hpp,esp_ot_custom_config.h}`。
- **F8d**: `scripts/otbr/build-ot-rcp-h2.sh`(新規)。
- 既存 example 2 つ(`onoff_light_cpp` / `controller_hub_cpp`)は無変更。

### ゲート実測

1. **ホスト**: `cargo test --workspace` = **639 pass / 0 fail**(F8b 分は既存
   `ctrl_lifecycle_roundtrip` に集約 = 本数不変)。clippy 0。
   `scripts/gen-cffi-header.sh --check` = `simple_matter.h is up to date`(冪等)。
   ctest E2E: `pair → setaddr → toggle → read` = `PAIR OK` / `SETADDR OK
   node=0xaabbccdd addr=127.0.0.1:5540` / `TOGGLE OK` / `READ OK value=1`。
2. `cargo build -p simple-matter-cffi --release --target riscv32imafc-unknown-none-elf
   --features panic-abort` green(`libsimple_matter_cffi.a` 14.1MB)。
3. **docker `espressif/idf:release-v5.4`(v5.4.4-813)、経路 (b) cargo**:
   `thread_ctrl_hub_cpp` `idf.py set-target esp32p4 && idf.py build` = **Project build
   complete**、app **1,017,472 B**(`0xf8680`、partition 65% free)。ELF に
   `sm_ctrl_init` / `sm_ctrl_pair_start` / `sm_ctrl_invoke` / **`sm_ctrl_set_node_addr`**
   ほか 12 シンボルが `T`。**R-P4-1 は不発**(v5.4 のまま `RADIO_MODE_UART_RCP` +
   esp32p4 でビルド green。v5.5 への切替は不要だった)。
   コンテナ内で `build/`・`sdkconfig`・`managed_components`・`dependencies.lock` を rm
   (root 残骸なし)。
4. **回帰**: `onoff_light_cpp` esp32c6(WiFi 構成、経路 (b))build green、app
   **1,512,672 B**(42% free)、`sm_init` / `sm_poll` / `sm_udp_rx` が `T`。
5. `scripts/otbr/build-ot-rcp-h2.sh` 完走 → `scripts/otbr/dist/ot_rcp_h2/`
   = `merged_ot_rcp.bin` **270,112 B** + `esp_ot_rcp.bin` / `bootloader.bin` /
   `partition-table.bin`(esp32h2、spinel over UART)。

### F8e の到達点

**Kconfig + コード足場 + 構成ファイルまで(既定ビルドには非搭載)**。
`CONFIG_SM_THREAD_BR` と `sdkconfig.defaults.br`(BORDER_ROUTER / mbedTLS DTLS-ECJPAKE /
lwIP forwarding + hooks)を用意し、`ot_hub.cpp` は `WIFI_STA_DEF` / `ETH_DEF` の netif を
探して `esp_openthread_set_backbone_netif` + `esp_openthread_border_router_init` を
呼ぶところまで実装済み。BR 構成のビルドは**最終リンクまで到達**したが、
`libopenthread_br.a`(IDF 同梱プリビルト)が要求する mDNS API
(`mdns_service_add_for_host` / `mdns_query_async_new` / `mdns_hostname_get` …)が
`espressif/mdns` **1.2.5 / 1.11.3 のどちらでも未解決**で止まっている(リンク順か
API/Kconfig の齟齬。要調査)。加えて P4 の backbone WiFi には `esp_wifi_remote` +
esp-hosted が要るため、**実機フェーズ送り**とする(prompt の打ち切り条件どおり)。

### 発見した罠(次に触る人へ)

1. **`RADIO_MODE_UART` は存在しない** — 正しくは `RADIO_MODE_UART_RCP`
   (`esp_openthread_types.h`)。Kconfig 側は `CONFIG_OPENTHREAD_RADIO_SPINEL_UART=y`。
   UART 設定は `radio_config.radio_uart_config`(port / uart_config / rx_pin / tx_pin)。
2. **`CONFIG_LWIP_IPV6_NUM_ADDRESSES=12` が必須** — openthread の lwIP netif が
   `#error CONFIG_LWIP_IPV6_NUM_ADDRESSES should be set to 12` で configure ではなく
   コンパイルで落ちる(8 では不可)。
3. **SRP サーバは BORDER_ROUTER でゲートされている**(v5.4)。`otSrpServerSetEnabled` を
   使うだけなら `CONFIG_OPENTHREAD_HEADER_CUSTOM` の custom header で
   `OPENTHREAD_CONFIG_SRP_SERVER_ENABLE 1` + `OPENTHREAD_CONFIG_ECDSA_ENABLE 1`
   (後者が無いと `srp_server.hpp` が `#error`)を定義するのが軽い。
   `CONFIG_OPENTHREAD_BORDER_ROUTER=y` にすると border agent の meshcop mDNS まで
   引き込まれ、`espressif/mdns` 無しではリンクできない(BORDER_AGENT_ENABLE=n にしても
   `esp_openthread_border_router.c` が `otBorderAgent*` を参照するため回避不能)。
4. **R-P4-2 は「imafc を使えば済む」ではなかった(重要)** — rustup の
   `riscv32imafc` 向け `compiler_builtins` rlib には cc ビルド済みの C ルーチン
   (`popcountsi2.o` / `bswapsi2.o` / `muldc3.o` … 36 個)が **soft-float ABI(ilp32)**
   のまま同梱されている。Rust 生成の .o は ilp32f なので普段は通るが、これらが
   1 つでも参照された瞬間に riscv ld が
   `can't link soft-float modules with single-float modules` で最終リンクを拒否する
   (**参照が無ければ黙って通るため構成依存で発症する**。既定ビルドでは出ず、BR 構成で
   初めて露見した)。対策としてコンポーネントで **soft-float の .o を .a から除去**する
   ステップを入れた(`strip_softfloat_objs.cmake`。同名ルーチンは IDF が常にリンクする
   libgcc(ilp32f)が提供する)。恒久対策は nightly の `-Zbuild-std` でビルトインを
   自前ビルドすること。
5. **`c"..."` リテラルは cbindgen が読めない** — テストコード内であっても
   `scripts/gen-cffi-header.sh` が `Error("expected `,`")` で落ちる。clippy の
   `manual_c_str_literals` に従って書き換えると壊れるので `#[allow]` で抑える。
6. `esp_ptr_external_ram()` は `esp_memory_utils.h`(`esp_heap_caps.h` からは来ない)。
7. `idf.py` の `-DSDKCONFIG_DEFAULTS` を使わない既定経路では、`sdkconfig` が既に
   存在すると `sdkconfig.defaults` の変更が反映されない。設定を足したら
   `rm sdkconfig` してから再 configure する。

## 8. 実機 E2E 記録(P9、2026-08-23、コミット 6946b9d)

Tab5(ESP32-P4)+ Unit Gateway H2 で F8 の全経路を実機確認:

- **配線**: Unit Gateway H2 の Grove は H2 の UART0(TX0/RX0)直結(回路図
  U195_Sch_v0.3 で確認)= ot_rcp 既定ピンのまま。Tab5 Port A は RX=GPIO54 /
  TX=GPIO53(53/54 逆は spinel 無応答)。baud 460800。
- **フロー**: H2 に build-ot-rcp-h2.sh の merged bin(ユニット自身の USB-C から
  書込)→ Tab5 で spinel 同期 → Thread leader 化 + SRP サーバ → NanoC6
  (onoff_light_cpp Thread 構成。dataset は smctl `pairing ble-thread` で投入し、
  PC から CASE 不達 → fail-safe 失効ロールバックで「Thread に居る commissionable」
  状態にする)→ `CONFIG_SM_TARGET_IPV6`(デバイス ML-EID)へ on-network PASE →
  **フルコミッショニング 7 秒 → CASE resumption → 30 秒毎 toggle OK**。
- **実機発見バグ**(詳細はコミット 6946b9d): ① コアのピア照合が ULA の scope_id
  食い違いで PASE 応答を黙って落とす(canonical_socket_addr を scope 非依存化)、
  ② P4 は起動直後の main タスク 128KB 生成が assert(hub タスクを静的スタック化)、
  ③ デバイスの Thread 自動 attach が fabric>0 ゲートで commissionable 状態に
  ならない(dataset があれば attach に変更)、④ ピン極性。
- 残: TBR(F8e backbone)、NanoH2 のデバイス対応(esp32h2 ターゲット追加)、
  smctl→Thread デバイスの直接操作(PC からは mesh への経路が無く BR 実装後)。

## 9. T1: LVGL コントローラアプリ(Tab5)

Status: ビルドゲート green(2026-08-24。§9.3 実装記録)。実機は親の flash 待ち。
基本通信(F8/P9)完動を受けて、Tab5 の 5 インチ
タッチ画面で操作する GUI コントローラを作る。

> **注意**: §9.1〜§9.4 の「BSP(`espressif/m5stack_tab5` + `esp_lvgl_port`)」記述は
> **T1b(§9.5)で M5Unified/M5GFX + 自前 LVGL ポートに置き換わった**(実機で画面が
> 黒のままだったため)。表示層まわりは §9.5 を正とする。OT / pump / UI の記述は有効。

### 9.1 構成

- **新 example `ports/esp-idf/examples/tab5_ctrl_app/`**(Tab5 専用)。
  thread_ctrl_hub_cpp(F8 参照実装)は無改変で残し、その OT/コントローラ配線を
  土台に GUI を足す。表示は公式 BSP `espressif/m5stack_tab5`(idf_component.yml)
  + esp_lvgl_port。フレームバッファ等は PSRAM。
- **タスク構成(単線契約の維持)**: sm_ctrl_* は従来どおり pump タスク(静的
  スタック 128KB)専有。UI(LVGL タスク)とは
  - UI → pump: 操作キュー `UiOp`(Toggle{node} / ReadOnOff{node} /
    Pair{node, passcode, ipv6} / RefreshAddr{node} = SRP 列挙→set_node_addr)
  - pump → UI: mutex 保護のスナップショット構造体(ノード一覧・on/off 状態・
    Thread 状態・直近イベント文字列)+ 更新フラグ。LVGL 側はタイマで反映
  で結ぶ。pump は run_until 相当を 1 op ずつ実行(settle 済みで次 op)。
- **画面(v1)**:
  1. ステータスバー: Thread role/RLOC16/channel/PAN、ノード数、free heap
  2. デバイス一覧: ノード帳の各ノード(node id / アドレス / on-off 状態バッジ /
     Toggle ボタン / 再解決ボタン)。10 秒周期で on-off を順次 read して反映
  3. Pair ダイアログ: IPv6 入力(オンスクリーンキーボード)+ node id(自動採番、
     編集可)+ passcode(既定 20202021)→ 進捗表示 → 結果
  4. ネットワーク情報パネル: dataset TLV hex 表示(+ LVGL の QR ウィジェットが
     使えるなら dataset の QR。デバイス側プリセットの転記を楽にする)
- Kconfig: 既定ピン(Port A RX=54/TX=53)・baud は F8 と同値。SM_TARGET_* の
  固定ターゲット自動ペアリングは持たない(UI から行う)。

### 9.2 ゲート

1. docker esp32p4 ビルド green(BSP は managed component。idf:release-v5.4 で
   依存が解決しない場合は BSP バージョンを固定するか本 example のみ新しい
   イメージを使い、選択を README/doc に記録)
2. 実機: 起動ログで LVGL/表示初期化 + leader 化 + pump 稼働。既存ノード
   (NanoC6 = 0xaabbccdd)が一覧に出て Toggle が通ること(ログで確認、
   画面・タッチの見た目はユーザ確認)
3. 回帰: thread_ctrl_hub_cpp / generic_matter_cpp のビルド green 維持

### 9.3 実装記録(T1、2026-08-24)

ビルドゲート(§9.2 の 1 と 3)は green。実機(§9.2 の 2)は親の flash 待ち。

#### IDF / BSP の版数

- **`espressif/idf:release-v5.4`(v5.4.4)のまま解決した**。v5.5 への切替は不要。
- managed component: **`espressif/m5stack_tab5` 1.2.0~1**(`main/idf_component.yml` で
  `~1.2.0` 指定)→ 芋づるで **`lvgl/lvgl` 9.5.0** / `espressif/esp_lvgl_port` 2.9.0 /
  `esp_lcd_ili9881c` / `esp_lcd_touch_gt911` / `esp_lcd_touch_st7123` /
  `esp_video` 2.0.1(カメラ。使わないがリンクされる)/ `esp_codec_dev` / `usb` 等 23 個。
- 表示は `bsp_display_start()`(BSP 既定の描画バッファ方針)+ `bsp_display_rotate()`。
  パネルは MIPI-DSI **720x1280(縦)**、`LV_DISPLAY_ROTATION_90` で **1280x720 横**にする。

#### 追加ファイル(`ports/esp-idf/examples/tab5_ctrl_app/`、全て新規)

`CMakeLists.txt` / `partitions.csv` / `sdkconfig.defaults` / `README.md` /
`main/{CMakeLists.txt, idf_component.yml, Kconfig.projbuild, esp_ot_custom_config.h,
main.cpp, ui.{hpp,cpp}, ctrl_pump.{hpp,cpp}, app_state.{hpp,cpp}, node_book.{hpp,cpp},
ot_hub.{hpp,cpp}}`。

- `ot_hub.*` は `thread_ctrl_hub_cpp` からのコピー(OT 配線は 1 行も変えていない)+
  GUI 用の `sm_ot_hub_get_status()` / `sm_ot_hub_dataset_hex()` 追加、F8e(BR)足場の削除。
- `ctrl_pump.cpp` は hub の `main.cpp` の KVS / UDP / `run_until` をそのまま流用し、
  固定シナリオの代わりに UI 操作キューのループを載せたもの。静的スタック 128KB の
  `xTaskCreateStatic`(P4 の起動時 assert 回避。P9 の発見)も同形。
- **既存 example(`thread_ctrl_hub_cpp` / `generic_matter_cpp` / `onoff_light_cpp`)と
  コア/シム(`crates/`)への変更はゼロ**。
- `partitions.csv` は hub と **nvs(0x9000/0x6000)・phy_init のオフセットが同一**で、
  app のみ 4MB(Tab5 = 16MB flash)。hub を焼いた Tab5 に上書きしてもノード帳
  (NVS `smctl`)と OT dataset が残る。

#### UI 構成(最終形)

- ステータスバー(96px): role / network name / channel / PAN / RLOC16 / SRP 状態 +
  登録ホスト数 / ノード数、内蔵 heap(最小値付き)と PSRAM、直近イベント 1 行。
- `Devices` タブ: ノード 1 件 = 96px の行(NodeId / 運用アドレス / On-Off バッジ /
  直近結果 / `Toggle` / `Read` / `⟳ Addr`)。ボタン高さ 64px。10 秒周期で 1 ノードずつ
  read してバッジを更新。`+ Pair new device` でモーダル。
- Pair ダイアログ: IPv6 / NodeId(hex、既存と衝突しない値を自動採番)/ passcode を
  `lv_keyboard` で入力 → PAIR_PHASE をフェーズ名で表示 → 結果。
- `Network` タブ: Thread 詳細 + active dataset TLV hex + `lv_qrcode`(280px)。
- タスク分離: UI→pump は `sm_ui_op_t` の FreeRTOS キュー、pump→UI は mutex 保護
  スナップショット + LVGL 500ms タイマ。**`ui.cpp` は `sm_ctrl_*` / `ot*` を 1 つも呼ばない**。

#### ゲート実測

1. docker `espressif/idf:release-v5.4`、経路 (b) cargo、`rm -f sdkconfig` →
   `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults" set-target esp32p4` → `build` =
   **Project build complete**、app **1,627,200 B**(`0x18d440`、4MB パーティションの 61% free)。
   ELF に `sm_ctrl_init` / `sm_ctrl_pair_start` / `sm_ctrl_invoke` / `sm_ctrl_read_scalar` /
   `sm_ctrl_set_node_addr` ほか **`T sm_ctrl_*` 14 本**、`T lv_*` 785 本
   (`lv_qrcode_create` / `lv_keyboard_create` / `lv_tabview_create` / `bsp_display_start` 確認)。
2. 回帰: `thread_ctrl_hub_cpp` esp32p4 build green(app **1,022,560 B**、65% free)。
   `generic_matter_cpp` / `onoff_light_cpp` は共有ファイル無変更のため影響なし。
3. 回帰: `cargo test --workspace` = **656 pass / 0 fail**、`cargo fmt --check` 差分なし、
   `cargo clippy --workspace --all-targets` 警告 0(Rust は無変更)。

#### 発見した罠(次に触る人へ)

1. **LVGL 9.5 も esp_lvgl_port 2.9 もタッチ座標を画面回転に追従させない**(最重要)。
   `lv_indev.c` に rotation 処理は存在せず、`esp_lvgl_port_touch.c` はタッチ IC の
   生座標をそのまま `lv_indev_data_t` に入れる。パネルが 720x1280 なので
   `lv_display_set_rotation(90)` すると**タッチだけ 90 度ずれる**。対策として
   `lv_indev_get_read_cb()` で BSP が入れた read_cb を取り出し、回転変換を挟んで
   `lv_indev_set_read_cb()` で差し替えている(`main.cpp: rotated_touch_read`。公開 API のみ)。
   実機で反転していたときのために `SM_UI_TOUCH_MIRROR_X/Y` と、先頭 5 点の
   `touch: panel(x,y) -> screen(x,y)` ログを用意した。
2. **シムには NodeId の列挙 API が無い**。`sm_ctrl_node_count`(件数)と
   `sm_ctrl_node_addr(node_id)`(引き当て)だけでは GUI の一覧が作れない。
   コア/シム無改造の制約下では、シムが書いた NVS `smctl`/`nods`
   (= smctl `nodes.tlv` v1。`crates/simple-matter/src/controller/nodes.rs` の doc が仕様)を
   C++ 側で Matter TLV パースして NodeId を取り出すのが唯一の道
   (`main/node_book.cpp`、読み取り専用 60 行)。**将来 `sm_ctrl_node_id_at(index)` を
   シムに足すのが素直**(そのときこのファイルは捨てられる)。
3. **BSP の LVGL 描画バッファは内蔵 RAM の DMA 領域**。既定 50 行で
   720x50x2B のダブルバッファ + SW 回転用 1 枚 ≒ 216KB。pump の静的スタック 128KB と
   同居させるため `CONFIG_BSP_LCD_DRAW_BUF_HEIGHT=40` に絞った。
4. **`CONFIG_BSP_DISPLAY_LVGL_AVOID_TEAR=y` は SW 回転を無効化する**
   (`bsp_display.c` が `sw_rotate = false` を強制)。既定 n のままにすること。
5. `idf.py set-target` は引数形式が `set-target <target>`(`-DIDF_TARGET=` 併用でも
   ターゲット引数は必須)。スクリプト化するときに嵌る。
6. BSP は使わないカメラ(`esp_video`)/音声(`esp_codec_dev`)/USB ホストまで引くが、
   初期化しなければリンクされるだけで害はない(app 1.6MB のうち相応分は占める)。

### 9.4 実機ブリングアップ追記(親検証、2026-08-24)

エージェント実装後の実機で 2 つの罠を追加発見・修正:

1. **PORT.A(Grove)5V は IO エキスパンダ #0(PI4IOE5V6408 @0x43)の P2**。
   Espressif BSP はエキスパンダ初期化でチップをリセットするだけで P2 を立て直さない
   ため、BSP を一度でも初期化すると **Grove 5V が落ちて H2 が無電源ブートループ**
   (残留電流の ROM ログ 115200bps が spinel 460800 に Parse ゴミとして流れ込み、
   既知良品の hub ビルドまで巻き添えで起動不能に見える)。電源状態は P4 リセットを
   跨いで保持される。対策: app_main 冒頭で明示的に P2 を出力 High(M5Tab5-UserDemo
   の bsp_set_ext_5v_en と同じビット。同デモの「PI4IOE1」= addr low に注意)。
2. **OT(spinel 同期)→ 表示の順で初期化**。MIPI-DSI + LVGL の初期描画中に spinel
   UART を開くと RX 取りこぼしで初期リセットが失敗し assert ループ。role>=detached を
   待ってから bsp_display_start する。

実機確認済み: 5V 投入 → spinel 同期(2.1s)→ display 1280x720 → UI 構築 →
ノード帳から NanoC6 が一覧表示(1 shown)→ controller ready → 10 秒周期の
OnOff read が CASE で疎通(MeshForwarder に暗号化 UDP)。タッチ操作・画面の
見た目はユーザ確認待ち。

### 9.5 T1b: 表示層を Espressif BSP から M5Unified/M5GFX へ差し替え(2026-08-24)

#### 動機(実機で確定した事実)

`espressif/m5stack_tab5` 1.2.0(+ `esp_lvgl_port` 2.9 / `esp_lcd_ili9881c`)経路は、
実機 Tab5(board version 2 = **ST7123 タッチ**搭載個体)で

- 初期化ログは全て正常(MIPI-DSI / io expander / touch / lvgl port とも ESP_OK)
- バックライトは点灯する(白っぽく光る)
- **しかし画面は真っ黒**。`SM_UI_ROTATION=0`(SW 回転なし)でも黒

という状態から抜けられなかった。BSP のパネル init シーケンス / DPI タイミングが
この個体のパネルに合っていない疑いが濃厚。ユーザ所有の別プロジェクト
(`tab5_claude_client`)は **同一個体で M5Unified/M5GFX により表示実績あり**のため、
ユーザ判断で M5GFX へ移行した。

#### M5GFX の入手形態と版

**ESP Registry 版でそのまま解決した**(参考リポジトリの vendor コピーは不要だった)。

| component | 版 | 備考 |
|---|---|---|
| `m5stack/m5unified` | **0.2.20** | `main/idf_component.yml` で `^0.2.20` |
| `m5stack/m5gfx` | **0.2.27** | m5unified が `>=0.2.27` で引く |
| `lvgl/lvgl` | **9.5.0** | BSP 経由をやめたので直接指定(`^9.2.0`) |
| idf | **5.4.4** | `espressif/idf:release-v5.4` のまま |

参考リポジトリ(`~/repos/tab5_claude_client`)の `components/M5GFX` / `M5Unified` は
ciniml フォークの `idf6-tab5-patches` ブランチ(M5GFX 0.2.20 / M5Unified 0.2.14 ベース)で、
パッチ内容は (a) IDF6 で分割された driver コンポーネントの `REQUIRES` 追加、
(b) IDF6 で消えた `i2s_port_t` の typedef シム、(c) IDF 6.0.1+ で消えた
`use_dma2d` フラグのガード — **いずれも IDF6 専用の話**で、IDF 5.4 の registry 版
(より新しい 0.2.27 / 0.2.20)には不要。今回は 1 行も vendor していない。

ELF 確認: `lgfx::v1::Panel_ST7123` / `Touch_ST7123` / `Touch_GT911` /
`m5::PI4IOE5V6408_Class` / `m5::Power_Class::setExtOutput` がリンクされている
(= Tab5 のパネル・タッチ・電源系は M5GFX/M5Unified 側が持っている)。

#### LVGL ポートの構成(`main/display_gfx.{hpp,cpp}`、新規)

`esp_lvgl_port` は使わず、必要最小限を自前で持つ(約 190 行):

- **tick**: `lv_tick_set_cb(esp_timer_get_time()/1000)`。1ms 周期タイマは立てない
  (取りこぼしに強く、タイマ 1 本節約できる)。
- **display**: `lv_display_create(1280, 720)` + `LV_COLOR_FORMAT_RGB565` +
  `lv_display_set_buffers(buf1, buf2, ..., LV_DISPLAY_RENDER_MODE_PARTIAL)`。
  バッファは **画面の 1/10(1280x72x2B = 184,320B)を 2 枚、PSRAM
  (`MALLOC_CAP_SPIRAM`)**。DSI は M5GFX 内部のフレームバッファへ書き込む形なので
  描画バッファ側に DMA 可能性の要求は無い。内蔵 RAM は pump の静的スタック 128KB と
  OT/lwIP/mbedTLS に残す(BSP 経路では内蔵 RAM から 216KB 取られていた)。
- **flush_cb**: `M5.Display.startWrite() / setAddrWindow(x,y,w,h) /
  writePixels((const lgfx::rgb565_t*)px_map, w*h) / endWrite()` →
  `lv_display_flush_ready()`。**型付き `writePixels`** を使うのがポイントで、
  `swap` 引数を取り違えて RGB565 のバイト順が壊れる事故を避けられる。
- **indev**: `LV_INDEV_TYPE_POINTER` + `M5.Display.getTouch(&x,&y)`。
  **M5GFX は `setRotation()` を反映した画面座標を返す**ので、T1 で必要だった
  回転シムは丸ごと不要(§9.3 の罠 1 が消滅)。
- **タスク**: `"lvgl"`(stack 10KB、prio 4)が再帰 mutex を取って `lv_timer_handler()`。
- **ロック API**: `sm_display_lock(timeout_ms)` / `sm_display_unlock()`
  (`bsp_display_lock` / `bsp_display_unlock` の置き換え。0 = 無限待ち)。

#### 起動順序(ここが最重要。§9.4 の 2 つの罠と両立させる)

```
nvs / netif / event loop
  → sm_display_hw_init()   = M5.begin()  … PORT.A 5V ON + MIPI-DSI パネル + タッチ
  → vTaskDelay(500ms)                    … H2(ot_rcp)のブート待ち
  → sm_ctrl_pump_start() + role>=detached 待ち … spinel 同期
  → sm_display_lvgl_start()              … LVGL 初期化 + 描画開始
  → sm_ui_create()
```

**なぜ `M5.begin()` だけ前倒しなのか**: `Power_Class::begin()` は Tab5 の
IO エキスパンダ #0(PI4IOE5V6408 @0x43)へ `OUT_SET=0b01110000` を書く。この値の
bit2 = **EXT5V_EN が 0**、つまり **`M5.begin()` は PORT.A の 5V を一瞬切る**
(直後の `Power.setExtOutput(cfg.output_power)` で戻る)。5V は H2(RCP)の電源
そのものなので、spinel 同期後に `M5.begin()` を呼ぶと H2 が再起動して spinel が死ぬ。
一方 §9.4 の「表示の初期描画中に spinel を開くと RX 取りこぼしで assert ループ」は
**LVGL の描画**が原因なので、パネル init(前)と LVGL(後)に分割すれば両立する。

#### 削除したもの

- managed component: `espressif/m5stack_tab5`(+ 芋づるの `esp_lvgl_port` /
  `esp_lcd_ili9881c` / `esp_lcd_touch_*` / `esp_video` / `esp_codec_dev` / `usb` 等 23 個)。
- `main.cpp` の `enable_ext_5v()`(手動 IO エキスパンダ操作)。**M5Unified が
  `Power.begin()` + `setExtOutput(cfg.output_power=true)` で同一ビット(@0x43 P2)を
  保証する**ので削除した(判断根拠: `utility/Power_Class.cpp` の
  `board_M5Tab5` 分岐が `ioe.setPullMode(2,en)` / `ioe.digitalWrite(2,en)` を叩く)。
- `main.cpp` の `rotated_touch_read()` / `install_touch_rotation()`(タッチ回転シム)。
- Kconfig: `SM_UI_ROTATION` / `SM_UI_TOUCH_MIRROR_X` / `SM_UI_TOUCH_MIRROR_Y`
  (回転は `display_gfx.cpp` の `setRotation(1)` 固定。上下逆なら 3)。
  これに伴い `sdkconfig.local` は**空**にした。
- sdkconfig: `CONFIG_BSP_LCD_DRAW_BUF_HEIGHT` / `CONFIG_BSP_LCD_DRAW_BUF_DOUBLE` /
  `CONFIG_CAM_CTRL_SPI_ENABLE` / `CONFIG_CODEC_I2C_BACKWARD_COMPATIBLE`(BSP 由来)。
  LVGL の `CONFIG_LV_*` は BSP ではなく lvgl 自身の Kconfig なのでそのまま残し、
  `CONFIG_LV_DEF_REFR_PERIOD=16` を明示。

`ui.cpp` / `app_state.*` / `ctrl_pump.*` / `node_book.*` / `ot_hub.*` は**無変更**
(`ui.cpp` は元々 `bsp_*` を 1 つも呼んでいなかった)。

#### ゲート実測(T1b)

1. docker `espressif/idf:release-v5.4`、`rm -f sdkconfig` →
   `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.local" set-target esp32p4` →
   `build` = **Project build complete**、app **0x1949b0 = 1,657,776 B**
   (4MB パーティションの 60% free。BSP 版 1,627,200 B から +30KB)。
   text 1,643,932 / data 13,209 / bss 1,477,829。
   ELF: `T lv_*` **750 本**(`lv_display_create` / `lv_indev_create` /
   `lv_tick_set_cb` / `lv_qrcode_create` / `lv_keyboard_create` 確認)、
   `T sm_ctrl_*` **14 本**、`sm_display_hw_init` / `sm_display_lvgl_start` /
   `sm_display_lock`、M5GFX 系(`Panel_ST7123` / `Touch_ST7123` / `Touch_GT911` /
   `PI4IOE5V6408_Class` / `Power_Class::setExtOutput`)。**`bsp_*` シンボルは 0**。
2. 回帰: `cargo fmt --check` 差分なし、`cargo test --workspace` **656 pass / 0 fail**、
   `cargo clippy --workspace --all-targets` 警告 0(Rust は無変更)。
   他 example / `crates/` は 1 行も触っていない。
3. 実機(表示が出るか)は親の flash 待ち。

#### 実機で見るべき起動ログ

```
tab5_disp: M5.begin: board=<N> display=1280x720 touch=yes   ← autodetect 結果
tab5_ctrl: openthread up (role=1); starting lvgl
tab5_disp: lvgl display 1280x720, draw buf 184320 B x2 (PSRAM)
tab5_disp: lvgl task started
tab5_ctrl: display up: 1280x720
tab5_disp: touch: (x,y)                                     ← 先頭 5 点だけ
tab5_ctrl: app_main done; ui + pump are running
```

`board=` が Tab5 として検出されているか(`m5gfx::board_t::board_M5Tab5`)、
`display=1280x720`(720x1280 なら `setRotation` が効いていない)、
`touch=yes` の 3 点が最初の判断材料。

#### それでも表示されない場合の切り分け候補

1. `board=` が 0(`board_unknown`)/ `display=0x0` → autodetect 失敗。
   `cfg.fallback_board` は P4 では既に `board_M5Tab5` なので、その場合は
   パネル種別ではなく I2C(内部 GPIO31/32)側を疑う。
2. `M5.begin()` は通るのに黒 → `M5.Display.fillScreen(TFT_RED)` を
   `sm_display_hw_init()` の末尾に入れて **LVGL 抜きで**赤くなるか見る。
   赤くなれば LVGL ポート(flush / バッファ)側、黒のままなら M5GFX 側。
3. 色が壊れる(赤青反転・ノイズ)→ `flush_cb` の
   `writePixels((const lgfx::rgb565_t*)...)` を
   `writePixels((const uint16_t*)px_map, w*h, true/false)` に替えて swap を試す。
4. タッチが効かない / ずれる → `touch:` ログの座標を見る。回転が効いていなければ
   `setRotation(1)` を 3 に、上下逆なら同じく 3。
5. H2 が再起動する / spinel が Parse ゴミを吐く → `M5.begin()` と pump の順序
   (上記「起動順序」)が崩れていないか。最終手段として `M5.begin()` の前に
   raw I2C で @0x43 の P2 を立てる旧 `enable_ext_5v()` 相当を復活させる
   (0x03 bit2=1 / 0x07 bit2=0 / 0x05 bit2=1)。
6. LVGL の描画が重い / tear → 描画バッファを 1/6 程度に増やす
   (`kDrawBufDiv`)、または `LV_DISPLAY_RENDER_MODE_FULL` + PSRAM 全画面 2 枚を試す。

### 9.6 T1 実機確認完了(2026-08-24)

M5GFX 版(T1b)でユーザ確認済み: 画面表示(1280x720 横)、タッチ操作、
Devices タブの Toggle で NanoC6 の LED 反転まで動作。autodetect は
`board=22 display=1280x720 touch=yes`。Espressif BSP(board v2 = ST7123)の
黒画面は M5GFX への差し替えで解消(バックライトは点くが描画されない症状。
BSP の v2 パネル対応の問題と推定 — upstream 報告候補)。

## 10. T2: WiFi コミッショニング(AirQ 等の WiFi デバイスを Tab5 から)

Status: 設計(2026-08-24)。T1(§9)完動を受けて、Tab5 コントローラから
**WiFi LAN 上の Matter デバイス**(例: AirQ = onoff_light_cpp、現在は smctl の
fabric)を on-network PASE でコミッショニングできるようにする。

### 10.1 方式

- Tab5 の P4 は radio 非搭載。WiFi は**基板上の ESP32-C6 を SDIO 経由で使う**
  (`espressif/esp_hosted` + `espressif/esp_wifi_remote`。標準 `esp_wifi_*` API が
  C6 に透過転送される)。BLE コミッショニングはスコープ外(v1 は on-network のみ。
  デバイス側は WiFi 参加済み or factory data で WiFi 資格情報プリセットが前提)。
- lwIP に WiFi STA netif が生えれば、pump の UDP ソケットは **wildcard bind 済み**
  なので送受信はそのまま両 netif で通る。必要なのは
  (a) WiFi bringup、(b) リンクローカル宛 `sin6_scope_id` の netif 選択、
  (c) UI(Pair ダイアログの transport 選択 + WiFi 状態表示)の 3 点。

### 10.2 前提(このユニット固有。最重要)

- **C6 の slave FW は esp_hosted 2.12.7 系に焼き替え済み**(同一個体で
  `~/repos/tab5_claude_client` が実証。工場出荷 V1.4.1 = hosted 1.4.x とは
  プロトコル非互換)。よって **host も esp_hosted 2.x 系で合わせる**(`^2.12.7`)。
  参照は IDF 6.0 だったが本 repo は **IDF 5.4.4 のまま**。2.x host が 5.4 で
  解決・ビルドできるかが最初の検証点(できない場合は版を下げるか、判断を持ち帰る)。
- SDIO 設定は参照 repo の `sdkconfig.defaults.esp32p4` を正とする:
  4-bit / CLK=GPIO12 / CMD=13 / D0..D3=11,10,9,8 / **reset=GPIO15 ACTIVE_HIGH** /
  clock 20MHz / RX streaming mode。
- **C6 の電源は IO エキスパンダ #2(PI4IOE5V6408 @0x44)bit0 を High**にして入れる
  (参照 repo `main/wifi_setup.cpp`)。M5Unified の `Power_Class` が保証するかは
  未確認 → 保証が確認できなければ raw I2C で明示的に立てる(§9.4 の @0x43 P2 と同じ流儀)。
- WiFi 資格情報は Kconfig(`SM_WIFI_SSID` / `SM_WIFI_PASSWORD`。SSID 空 = WiFi 無効)。

### 10.3 実装項目

1. `main/idf_component.yml`: `espressif/esp_hosted` + `espressif/esp_wifi_remote` 追加。
2. `sdkconfig.defaults`: 上記 SDIO / hosted 設定(esp32p4 のみの example なので直書きで可)。
3. **新規 `main/wifi_sta.{hpp,cpp}`**: hosted 初期化 + STA 接続(creds は Kconfig)、
   IPv6 リンクローカル生成(`esp_netif_create_ip6_linklocal`)、
   `sm_wifi_netif_index()` / `sm_wifi_status()`(SSID / 接続状態 / LL アドレス)を公開。
   接続はイベント駆動・ノンブロッキング(UI を待たせない。再接続リトライつき)。
4. **起動順序**: `M5.begin()` → H2 待ち → spinel 同期(role>=detached)→
   **WiFi bringup 開始**(完了は待たない)→ LVGL → UI。
   SDIO は UART54/53 と無関係だが、§9.4 の 2 罠(5V 断 / spinel RX 取りこぼし)を
   避けるため spinel 同期後に置く。
5. `ctrl_pump.cpp`:
   - `sm_ui_op_t` に `via`(0=Thread / 1=WiFi)を追加。`do_pair` は LL 宛のとき
     `addr.scope_id` を選択された netif index にする(グローバル/ULA 宛は 0 のままで可)。
   - `send_sm` の fallback: `dst.scope_id==0` かつ宛先が `fe80::/10` のときの既定は
     従来どおり OT netif。ノード帳由来のアドレスは scope_id を保持している前提だが、
     リブート後に netif index が変わり得る点はエージェントが nodes.tlv 仕様
     (`crates/simple-matter/src/controller/nodes.rs`)を確認して対処を記録する。
   - `REFRESH_ADDR` は SRP 列挙(Thread のみ)。WiFi ノードが SRP に居ない場合は
     "not in SRP" を note に出すだけで良い(mDNS operational resolve は T2b、今回はやらない)。
6. `ui.cpp`: Pair ダイアログに transport 選択(Thread / WiFi の 2 択、既定 Thread)。
   ステータスバーに WiFi 状態(SSID or off / LL アドレス有無)を 1 項目追加。
   `app_state.hpp` のスナップショットに WiFi 状態フィールドを追加。
7. コア(`crates/`)・シム・他 example は**変更ゼロ**を維持する。

### 10.4 ゲート

1. docker `espressif/idf:release-v5.4` esp32p4 ビルド green(managed component の
   解決を含む。hosted 2.x が 5.4 で解決しない場合はその事実と選択肢を記録して停止)。
2. 回帰: `thread_ctrl_hub_cpp` esp32p4 ビルド green。Rust 無変更なら cargo 系は省略可。
3. 実機(親/ユーザ): AirQ を factory reset(または open-window)→ Tab5 の WiFi が
   LAN に接続 → Pair ダイアログ(via=WiFi、AirQ の LL or LAN IPv6 + passcode)→
   PAIR COMPLETE → Toggle で AirQ の LED 反転 → 再起動後 resumption。

### 10.5 実装記録(T2、2026-08-24)

ビルドゲート(§10.4 の 1 と 2)は green。実機(§10.4 の 3)は親/ユーザ待ち。

#### 版数確定(IDF 5.4.4 のままで解決した)

`espressif/idf:release-v5.4`(v5.4.4)を上げる必要は無かった。`dependencies.lock`:

| component | 確定版 | manifest 指定 | 備考 |
|---|---|---|---|
| `espressif/esp_hosted` | **2.12.12** | `^2.12.7` | idf 要件は `>=5.3`。2.12 系のまま |
| `espressif/esp_wifi_remote` | **1.6.4** | `^1.5.1` | 同じく `>=5.3`。IDF 版別ディレクトリ `idf_v5.4/` を持つ |
| `espressif/esp_serial_slave_link` | 1.1.2 | (芋づる) | SDIO slave link |
| `espressif/eppp_link` / `wifi_remote_over_eppp` | 1.1.6 / 0.3.3 | (芋づる) | 使わないがリンク対象 |
| idf | 5.4.4 | `>=5.4` | 変更なし |

`esp_hosted` 3.x は `idf >= 5.5` なので自動的に除外される(`^2.12.7` 指定でも
到達しない)。**C6 の slave FW が 2.12.7 系に焼かれている前提**(§10.2)と整合する。

#### 追加 / 変更ファイル(`ports/esp-idf/examples/tab5_ctrl_app/` のみ)

- **新規** `main/wifi_sta.{hpp,cpp}`(約 240 行)。公開 API は `sm_wifi_start()` /
  `sm_wifi_netif_index()` / `sm_wifi_get_status()` の 3 本。
- `main/idf_component.yml`: `espressif/esp_hosted ^2.12.7` + `espressif/esp_wifi_remote ^1.5.1`。
- `main/CMakeLists.txt`: `wifi_sta.cpp` 追加 + REQUIRES に **`esp_wifi`**。
- `sdkconfig.defaults`: hosted/SDIO 一式(参照 repo `~/repos/tab5_claude_client`
  `sdkconfig.defaults.esp32p4` からの転記であることをコメントに明記)。
- `main/Kconfig.projbuild`: `SM_WIFI_SSID` / `SM_WIFI_PASSWORD`(string、既定空)。
- `main/app_state.hpp`: `sm_ui_op_t.via`(`sm_ui_via_t`: 0=Thread / 1=WiFi)+
  スナップショットに `wifi_state` / `wifi_ssid` / `wifi_ll` / `wifi_ip4` / `wifi_netif`。
- `main/ctrl_pump.cpp`: `refresh_wifi_status()`(2 秒周期でスナップショットへ写す)+
  `do_pair` の scope_id 選択。
- `main/main.cpp`: spinel 同期の**後**・LVGL の**前**に `sm_wifi_start()`(完了は待たない)。
- `main/ui.cpp`: Pair ダイアログの `via` ドロップダウン(Thread/WiFi、既定 Thread。
  Passcode と同じ行に相乗りさせてカード高を維持)+ ステータスバー右下の WiFi 1 項目。
- `README.md`: 設定節に WiFi の 1 項目。
- **`crates/` / シム / 他 example は 1 行も触っていない**。

#### 起動順序(§9.4 / §9.5 の不変条件を維持)

```
M5.begin()  → 500ms → pump(spinel 同期、role>=detached 待ち)
            → sm_wifi_start()      … ここ。ノンブロッキング
            → LVGL → UI
```

`sm_wifi_start()` は「SSID が空なら即 return」「そうでなければ `wifi_up` タスク
(6KB)を起こして戻る」だけ。C6 の電源確認 → `esp_wifi_init` → `esp_wifi_start` は
そのタスクの中で走り、接続完了はイベント(`IP_EVENT_STA_GOT_IP` / `GOT_IP6`)で拾う。
**app_main も LVGL も待たない**。

#### C6 の電源(@0x44 bit0 = WLAN_PWR_EN)— M5Unified が既に立てている

`managed_components/m5stack__m5unified/src/utility/Power_Class.cpp` の
`board_M5Tab5` 分岐は、IO エキスパンダ #2(PI4IOE5V6408 @0x44)へ
`OUT_SET = 0b10000001` / `IO_DIR = 0b10110001` を書く。**bit0 = WLAN_PWR_EN が 1**
なので、`M5.begin()` の時点で C6 の電源は入っている(@0x43 の EXT5V_EN = PORT.A 5V と
同じ流儀)。よって raw I2C での再設定は不要と判断したが、`M5.begin()` が失敗した
個体でも黙って死なないよう、`ensure_c6_power()` で **読み戻して 0 のときだけ**
明示的に立てる(立て直した場合のみ 1500ms の C6 ブート待ちを入れる)。
`M5.In_I2C` を使うので M5Unified のバス設定と食い違わない。

なお参照 repo は「off → 300ms → on → 1500ms」の強制電源サイクルをしていたが、
本 repo では (a) `M5.begin()` から spinel 同期(実測 2.1s)分の余裕があること、
(b) esp_hosted が GPIO15(C6 の CHIP_EN)を reset パルスで叩くこと、から
既定では行わない。**実機で CMD5 / op_cond がタイムアウトするなら、ここに参照 repo と
同じ強制電源サイクルを足すのが最初の手**(ただし LVGL のタッチも `M5.In_I2C` を
使うので、LVGL 開始前に済ませること)。

#### `via` と scope_id の扱い(§10.3 の 5)

`do_pair` は入力アドレスが **`fe80::/10` のときだけ** `scope_id` を設定する
(`via` = Thread なら `sm_ot_hub_netif_index()`、WiFi なら `sm_wifi_netif_index()`)。
ULA / グローバル宛(Thread の OMR、WiFi の GUA/ULA)は **`scope_id = 0` のまま**で
lwIP の経路選択に任せる。選んだ netif がまだ上がっていなければ pairing を始めずに
`pair_state = 3` + ステータス行でその旨を出す。`send_sm` の fallback
(`scope_id==0` の LL 宛 → OT netif)は**現状維持**。

#### nodes.tlv は scope_id を保存しない(リブート後の netif index ずれ)

`crates/simple-matter/src/controller/nodes.rs` の v1 フォーマットは 1 エントリあたり
`node_id` / `label` / **IP バイト列(4 or 16)** / `port` だけで、
`decode_entry` は `SocketAddr::new(ip, port)` を組む = **`scope_id` は 0 に落ちる**
(`encode_nodes` も `ip.octets()` しか書かない)。つまり:

- **リンクローカル(`fe80::`)でコミッショニングしたノードは、リブート後に
  `scope_id = 0` で復元される** → `send_sm` の fallback で **OT netif** 宛になる。
  Thread ノードなら正しいが、**WiFi ノードだと宛先が壊れる**。
- ULA / グローバル宛(Thread OMR、WiFi の GUA/ULA)は scope が要らないので**実害なし**。

対処は「WiFi デバイスは LL ではなく LAN の GUA/ULA でコミッショニングする」を
運用の既定にすること(Pair ダイアログの説明文にもその旨を書いた)。恒久対処は
(a) nodes.tlv v2 で scope_id を持つ、(b) C++ 側で「WiFi 由来の NodeId」を別 KVS に
覚えて起動時に `sm_ctrl_set_node_addr` で scope 付きに直す、(c) mDNS operational
resolve(T2b)で毎回引き直す、のいずれか。**今回は (c) の前段として "not in SRP" を
note に出すところまで**(`REFRESH_ADDR` は SRP 列挙のまま = Thread 専用)。

#### ゲート実測

1. docker `espressif/idf:release-v5.4`、経路 (b) cargo、`rm -f sdkconfig` →
   `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.local" set-target esp32p4` →
   `build` = **Project build complete**、app **0x1d5870 = 1,923,184 B**
   (4MB パーティションの 54% free。T1b の 1,657,776 B から **+265,408 B** = hosted /
   wifi_remote / protobuf-c RPC の分)。text 1,908,664 / data 14,397 / bss 1,609,803。
   ELF: `sm_wifi_start()` / `sm_wifi_netif_index()` / `sm_wifi_get_status()`、
   `T esp_hosted_*` 12 本(`esp_hosted_init` / `esp_hosted_get_default_sdio_config` ほか)、
   `sdmmc_card_init`、`rpc__*` 1125 本、`T sm_ctrl_*` 14 本、`T lv_*` 751 本。
2. 追加確認(**下記の罠 1 のため必須**): `CONFIG_SM_WIFI_SSID="testssid"` を足した
   別ビルドで green、app **約 1,937,700 B**(+14.5KB)。ELF に `(anonymous namespace)::wifi_task`、
   `esp_netif_create_default_wifi_sta` / `esp_netif_create_ip6_linklocal`、
   `W esp_wifi_init` / `W esp_wifi_connect`(esp_hosted の
   `host/api/src/esp_wifi_weak.c`)→ `T esp_wifi_remote_init` / `_connect` /
   `_set_mode` / `_set_config` / `_start` に解決。`CONFIG_ESP_WIFI_REMOTE_LIBRARY_HOSTED=1`。
3. 回帰: `thread_ctrl_hub_cpp` esp32p4 build green(app **1,022,048 B**)。
   Rust は無変更なので cargo 系は省略(§10.4 の 2 の但し書き)。

#### 発見した罠(次に触る人へ)

1. **既定(SSID 空)ビルドでは WiFi のコードが丸ごと GC される**。`CONFIG_SM_WIFI_SSID`
   は文字列マクロなので `CONFIG_SM_WIFI_SSID[0] == '\0'` は**コンパイル時定数**、
   `sm_wifi_start()` の早期 return 以降(`wifi_task` / `esp_wifi_init` 呼び出し)が
   `-ffunction-sections` + `--gc-sections` で消える。**既定ビルドの ELF に
   `esp_wifi_init` が居ないのは正常**で、リンク可能性を確かめたければ SSID を入れた
   ビルドを別に回す必要がある(上のゲート 2)。flash 節約としては望ましい挙動だが、
   hosted / wifi_remote 自体は SSID の有無に関わらずリンクされる(+265,408 B)。
2. **`main` の REQUIRES に `esp_wifi` が要る**。`esp_wifi_remote` は自分の
   `include/` に `esp_wifi.h` を持っておらず、**IDF 内蔵 `esp_wifi` コンポーネントの
   include ディレクトリに `idf_v5.4/include/injected/` を前置する**形で差し込む
   (`esp_wifi_remote/CMakeLists.txt` の `set_target_properties(... INTERFACE_INCLUDE_DIRECTORIES)`)。
   managed component を manifest に足しただけでは `esp_wifi.h: No such file or directory`。
3. **`esp_wifi_*` は esp_hosted の weak シンボル経由**。`nm` で `W esp_wifi_init`
   (8 バイト)しか見えないのが正しい姿で、中身は `esp_wifi_remote_init` への
   テールコール。`T esp_wifi_init` を探しても見つからないので驚かないこと。
4. **`esp_wifi_connect()` を `WIFI_EVENT_STA_DISCONNECTED` ハンドラから呼ばない**。
   既定イベントループのタスクには OT / IP のイベントも乗っているので、リトライの
   バックオフを `vTaskDelay` で入れるとそこが詰まる。本実装ではハンドラは状態を
   書くだけにして、再接続は `wifi_up` タスクの 5 秒周期監視ループに任せている。
5. `IP_EVENT_GOT_IP6` は **OT netif でも飛ぶ**。`ev->esp_netif != g_netif` で
   弾かないと Thread の LL アドレスを WiFi のものとして表示してしまう。

### 10.6 T2 実機 E2E 完了(2026-08-24)

実機で §10.4 ゲート 3 を完走した。手順と結果:

- AirQ(S3 onoff_light_cpp)を NVS 消去(`espflash erase-region 0x9000 0x6000`)で
  factory reset → 再起動で WiFi join、`fabrics=0` = PASE 受付、GUA 取得を確認。
- Tab5 起動: C6 電源は M5Unified 設定済みを読み戻しで確認 → SDIO/esp_hosted 初期化 OK →
  iotap 接続(切断リトライ 2 回は coex の常態)→ IPv4 + LL + **GUA** 取得。
- Pair ダイアログ(via=WiFi、AirQ の GUA)→ **PASE phase 1→9 約 7 秒 → PAIR COMPLETE**
  → Toggle 連続 OK(status=0)→ read OnOff 一致 → AirQ 側ログでも OnOff イベント確認。
- 同一 fabric の NanoC6(Thread)Toggle も並行して成功 = **Thread + WiFi の
  2 トランスポート同時運用**を 1 台の Tab5 で実証。

#### 実機で発見・修正したバグ(T1 から潜在)

**Pair ダイアログのオンスクリーンキーボードが画面外に飛ぶ**: LVGL 9 の
`lv_keyboard` はコンストラクタで `lv_obj_align(obj, LV_ALIGN_BOTTOM_MID, 0, 0)` を
設定するため、その後の `lv_obj_set_pos(kb, 0, 424)` は「下端中央アンカーからの
オフセット」と解釈され、kb が画面下端より 424px 下=完全に画面外になる
(LVGL の set_pos は align プロパティを上書きしない)。`lv_obj_align(BOTTOM_MID)`
への置き換えで解決。T1 実機確認ではダイアログを開いていなかったため今回まで潜伏。

#### 実機での観測メモ

- **GUA(SLAAC)取得は RA タイミング依存**: 初回ブートでは 4 分待っても GUA が
  出ず(LL のみ)、リブート後は 12 秒で取得した。恒常的な esp_hosted の
  マルチキャスト RX 問題ではない(LL への NDP/ping は常に通る)。GUA が無い間は
  fe80 + via=WiFi で運用できる。§10.5 の「CMD5 / スタック 6KB / spinel 干渉」の
  懸念 3 点はすべて杞憂だった(問題なし)。
- 実測フロー: SDIO 初期化 ≈2 秒、WiFi 接続 ≈5-15 秒(リトライ込み)、
  PASE→AddNOC→CASE 完了 ≈7 秒。

## 11. T3: BLE コミッショニング(Tab5 から ble-wifi / ble-thread)

Status: 設計(2026-08-24)。T2(WiFi、§10)完了を受けて、BLE 広告中の Matter デバイスを
Tab5 から直接コミッショニングできるようにする(コミッショニング窓が UDP で開いていない
工場出荷状態のデバイスを、IP アドレス入力なしで取り込む)。

### 11.1 方式

- **BLE radio は基板上 C6(esp_hosted)**: P4 に BT controller は無いので、
  NimBLE を **host-only** で動かし HCI を esp_hosted VHCI 経由で C6 に流す。
  esp_hosted 2.12.12 に P4 向けの同梱例 `examples/host_nimble_bleprph_host_only_vhci`
  があり、これの sdkconfig(`CONFIG_BT_ENABLED` + NimBLE host-only +
  `ESP_HOSTED_NIMBLE_HCI_VHCI`)を正とする。**IDF 5.4.4 で解決・ビルドできるかが
  最初の検証点**(esp_hosted の Kconfig 依存: `BT_NIMBLE_ENABLED &&
  !BT_CONTROLLER_ENABLED && !BT_NIMBLE_TRANSPORT_UART`)。
- **C6 slave FW**: 焼き替え済み 2.12.7 slave は `sdkconfig.defaults.esp32c6` の
  `CONFIG_BT_ENABLED=y` 既定のままビルドされている見込み(参照 repo の build.sh は
  BT を無効化していない)= BT controller 入り。真偽は実機の HCI 同期で確定する
  (失敗したら slave 再ビルド・再書込が必要という事実を記録して停止)。
- **BTP central 給餌はシム F7b API をそのまま使う**(c-ffi-shim.md §11.4:
  `sm_ctrl_match_adv` / `sm_ctrl_ble_pair_start`(kind 0=wifi / 1=thread)/
  `sm_ctrl_ble_event` / `sm_ctrl_ble_poll`、完了イベント `SM_CTRL_EV_BLE_DONE`)。
  staticlib は default features(ble,controller)で **既に有効**(Rust 変更ゼロ)。
- **NimBLE central は controller_hub_cpp の移植**(`main/ble_central.{hpp,cpp}`、
  F7b 実機検証済み): scan → `sm_ctrl_match_adv` で discriminator 照合 → connect →
  MTU 交換 → GATT 0xFFF6 C1/C2 発見 → C2 subscribe → C1 write / C2 indication 給餌。
  **C1 write は C2 subscribe 完了までゲート**(F7b 実機バグの学び)。
  NimBLE コールバック → FreeRTOS queue → pump の直列化も同形(単線契約維持)。
- **資格情報は Tab5 が既に持っているものを自動使用**(ダイアログ入力は増やさない):
  - ble-wifi: Kconfig `SM_WIFI_SSID` / `SM_WIFI_PASSWORD`(= Tab5 自身と同じ AP へ)
  - ble-thread: ot_hub の active dataset TLV(`sm_ot_hub_dataset_hex` を bytes 化。
    Tab5 は Thread leader なので dataset の持ち主そのもの)
- **handoff(BLE_DONE 後)**: C++ が BLE 切断 → 運用アドレス解決 → シムが自動で
  CASE over UDP + CommissioningComplete(F7b の流儀)。解決手段は kind で分岐:
  - thread: SRP 列挙(既存 REFRESH_ADDR と同じ)→ `sm_ctrl_set_node_addr`
  - wifi: **mDNS resolve を pump に追加**(`sm_ctrl_resolve_start` の出力を
    5353/ff02::fb(WiFi netif join)ソケットで送り、応答を `sm_ctrl_mdns_rx` へ。
    = T2b の前倒し。これで WiFi ノードのリブート後再解決も手に入る)
- **UI**: Pair ダイアログの via を 4 択に(On-network Thread / On-network WiFi /
  BLE→WiFi / BLE→Thread)。BLE 選択時は IPv6 欄の代わりに discriminator 欄
  (既定 3840)を使う(欄の付け替えは表示切替で可。passcode / NodeId は共通)。
  進捗はスキャン→接続→BTP→PASE フェーズ→handoff→完了をステータス行で見せる。

### 11.2 E2E ターゲット(実機)

- **ble-wifi(主)**: NanoC6 の generic_matter_cpp(P6 で ble-wifi 実績)を
  factory reset して BLE 広告状態にする。
- ble-thread: 対応デバイス(BLE+Thread 併載ビルド)が現用機材に無ければ実装のみ
  (ループバックゲートは F7b で検証済み)。準備できたら後日実機。

### 11.3 ゲート

1. docker esp32p4 ビルド green(NimBLE host-only + VHCI が IDF 5.4 で成立するか。
   不可なら事実と選択肢(IDF 5.5 の影響範囲等)を記録して停止)
2. 回帰: thread_ctrl_hub_cpp / controller_hub_cpp(S3 BLE)/ tab5_ctrl_app の
  (BLE 無し構成があるなら)ビルド green
3. 実機: scan → discriminator 照合 → BTP handshake → PASE → BLE_DONE →
   handoff(mDNS/SRP)→ PAIR COMPLETE → Toggle

### 11.4 実装記録(T3、2026-08-24)

ビルドゲート(§11.3 の 1 と 2)は green。実機(同 3)は親/ユーザ待ち。

#### 版数 / Kconfig の確定内容(IDF 5.4.4 のままで成立した)

**NimBLE host-only + esp_hosted VHCI は `espressif/idf:release-v5.4`(5.4.4)で素直に通る**。
決め手は IDF 5.4 の `components/bt/Kconfig` で **`BT_ENABLED` が `SOC_BT_SUPPORTED` に
依存していない**こと(依存するのは `BT_CONTROLLER_ENABLED` の方)。よって radio を持たない
P4 でも「ホストだけ有効・controller 無効」が選べる。managed component の版は T2 から不変
(`esp_hosted` 2.12.12 / `esp_wifi_remote` 1.6.4)で、**`dependencies.lock` は 1 行も動いていない**
(BLE は既に入っているコンポーネントの Kconfig を立てるだけ)。

`sdkconfig.defaults` への追記(前半 8 行は esp_hosted 同梱例
`examples/host_nimble_bleprph_host_only_vhci/sdkconfig.defaults` からの転記 = 由来を明記):

| Kconfig | 値 | 理由 |
|---|---|---|
| `CONFIG_BT_ENABLED` | y | BT スタックを引く(P4 でも可) |
| `CONFIG_BT_CONTROLLER_DISABLED` | y | **host-only**。controller は C6 側 |
| `CONFIG_BT_BLUEDROID_ENABLED` | n | ホストは NimBLE |
| `CONFIG_BT_NIMBLE_ENABLED` | y | |
| `CONFIG_BT_NIMBLE_TRANSPORT_UART` | n | VHCI を使うので UART HCI は切る |
| `CONFIG_ESP_HOSTED_ENABLE_BT_NIMBLE` | y | esp_hosted の BT 経路 |
| `CONFIG_ESP_HOSTED_NIMBLE_HCI_VHCI` | y | HCI を SDIO(hosted)へ |
| `CONFIG_ESP_WIFI_REMOTE_LIBRARY_HOSTED` | y | 同梱例に合わせる(T2 でも実質同値) |
| `CONFIG_BT_NIMBLE_ROLE_CENTRAL/OBSERVER` | y | scan + connect + GATT client |
| `CONFIG_BT_NIMBLE_ROLE_PERIPHERAL/BROADCASTER` | n | コミッショナは advertise しない |
| `CONFIG_BT_NIMBLE_MAX_CONNECTIONS` | 1 | BTP は 1 本。内蔵 RAM の節約 |
| `CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE` | 5120 | 同上(既定 4096〜) |

esp_hosted の Kconfig ガードは `BT_ENABLED && BT_NIMBLE_ENABLED && !BT_CONTROLLER_ENABLED &&
!BT_NIMBLE_TRANSPORT_UART`。4 条件のどれかを外すと `ESP_HOSTED_ENABLE_BT_NIMBLE` が
**メニューごと消える**(設定しても sdkconfig に現れない)ので、確認は生成後の
`grep ESP_HOSTED_ENABLE_BT_NIMBLE sdkconfig` で行うこと。

#### 追加 / 変更ファイル(`ports/esp-idf/examples/tab5_ctrl_app/` のみ)

- **新規** `main/ble_central.{hpp,cpp}`(約 380 行)。controller_hub_cpp(F7b、S3 実機検証済み)の
  移植 + P4 host-only の起動シーケンス。公開 API は
  `sm_ble_central_boot()` / `_state()` / `_queue()` / `_start(disc, scan_ms)` / `_stop()` /
  `_write_c1()` / `_disconnect()`。NimBLE のコールバックは **queue に積むだけ**で
  `sm_ctrl_*` を 1 つも呼ばない(単線契約)。
- `main/ctrl_pump.cpp`: 新 op `SM_UI_OP_PAIR_BLE` の処理(`do_pair_ble` / `drive_ble_phase`)、
  mDNS 解決(`open_mdns` / `resolve_via_mdns`)、SRP アドレスを mDNS 応答に仕立てる
  `feed_addr_as_mdns`(下記の罠 2)、`REFRESH_ADDR` の mDNS フォールバック、
  スナップショットへの `ble_host` 反映。
- `main/app_state.hpp`: `SM_UI_OP_PAIR_BLE` / `sm_ui_via_t` を 4 値へ拡張 /
  `sm_ui_op_t.discriminator` / `sm_ui_ble_stage_t` / スナップショットの `ble_host` `ble_stage`。
- `main/ui.cpp`: via ドロップダウンを 4 択(`On-network Thread` / `On-network WiFi` /
  `BLE - WiFi` / `BLE - Thread`。**並びは `sm_ui_via_t` と同一**)、`LV_EVENT_VALUE_CHANGED` で
  1 番目の欄を `IPv6` ⇄ `Discriminator`(既定 3840)に付け替え(退避つき)+ 説明文の差し替え、
  ステータスバーに `BLE off/starting/ready/failed`、ダイアログに BLE stage 表示。
- `main/main.cpp`: `sm_wifi_start()` の**直後**に `sm_ble_central_boot()`(非ブロッキング)。
- `main/CMakeLists.txt`: `ble_central.cpp` + REQUIRES に `bt` / `espressif__esp_hosted`
  (条件付き REQUIRES は不可なので常時)。
- `main/Kconfig.projbuild`: `SM_UI_DEFAULT_DISCRIMINATOR`(3840)。
- `sdkconfig.defaults` / `README.md`。
- **`crates/` / シム / 他 example は 1 行も触っていない**。`dependencies.lock` も無変更。

#### 起動順序(§9.4 / §9.5 / §10.5 の不変条件を維持)

```
M5.begin() → 500ms → pump(spinel 同期、role>=detached 待ち)
           → sm_wifi_start()        … ノンブロッキング
           → sm_ble_central_boot()  … ここ。同じくノンブロッキング
           → LVGL → UI
```

`sm_ble_central_boot()` は queue を作って `ble_up` タスク(5KB)を起こすだけ。そのタスクは

1. WiFi が有効なら状態が `CONNECTING` を抜ける(= `esp_wifi_init` が済んだ)のを最大 30 秒待つ
2. `esp_hosted_init()`(済んでいれば即 OK)→ `esp_hosted_connect_to_slave()`
3. `esp_hosted_bt_controller_init()` / `_enable()`(**C6 側 controller の起動 RPC**)
4. `nimble_port_init()` + `nimble_port_freertos_init(host_task)`

を順に行い、`ble_hs` の sync コールバックで `READY` になる。

#### BLE コミッショニングのフロー(pump タスク内、`do_pair_ble`)

```
資格情報(WiFi = Kconfig / Thread = sm_ot_hub_dataset_hex → bytes)
  → sm_ctrl_ble_pair_start(node_id, passcode, kind, cred…)
  → sm_ble_central_start(discriminator, 60s)      … scan(sm_ctrl_match_adv で照合)
  → drive_ble_phase(120s): queue → sm_ctrl_ble_event / sm_ctrl_ble_poll → C1 write
       ※ C1 write は **C2 subscribe 完了までゲート**(F7b 実機バグ)
  → SM_CTRL_EV_BLE_DONE → BLE 切断
  → handoff: thread = SRP 列挙(最大 ~120 秒リトライ)/ wifi = mDNS 解決(60 秒)
  → run_until(120s) で CASE over UDP + CommissioningComplete → PAIR COMPLETE
```

#### ゲート実測

1. docker `espressif/idf:release-v5.4`、経路 (b) cargo、`rm -f sdkconfig` →
   `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.local" set-target esp32p4` → `build` =
   **Project build complete**、app **0x1fe030 = 2,088,496 B**(4MB パーティションの 50% free。
   T2 の 1,923,184 B から **+165,312 B** = NimBLE ホスト + hosted VHCI + BLE central)。
   text 2,074,422 / data 14,461 / bss 1,741,707。
   ELF: `T ble_hs_*` **88 本**(`ble_hs_init` / `ble_gap_disc` / `ble_gattc_write_no_rsp_flat` /
   `nimble_port_init` / `nimble_port_run`)、`T ble_transport_ll_init` /
   `ble_transport_to_ll_acl_impl`(= VHCI 経路が繋がっている)、
   `T sm_ctrl_ble_pair_start` / `sm_ctrl_ble_event` / `sm_ctrl_ble_poll` / `sm_ctrl_match_adv`、
   `T sm_ble_central_*` 7 本、`T esp_hosted_bt_controller_init` / `_enable` /
   `esp_hosted_init` / `esp_hosted_connect_to_slave`、`T sm_ctrl_*` 21 本、`T lv_*` 751 本。
2. 回帰: `thread_ctrl_hub_cpp` esp32p4 build **green**。`controller_hub_cpp` は S3 prebuilt が
   必要なためビルドせず、**共有ファイル(`crates/` / シム / 他 example)の無変更**で代替
   (`git status` で本 example 以外の差分ゼロを確認)。Rust 無変更のため cargo 系は省略。

#### 発見した罠(次に触る人へ)

1. **`esp_hosted_init()` の二重呼びは排他されていない**。WiFi(`esp_wifi_init` →
   `esp_wifi_remote` → `esp_hosted_init`)と BLE(VHCI)は**同じ SDIO トランスポートを共有**
   するが、`esp_hosted_init_done` は素の `static uint8_t` で、同時に走らせると SDIO/RPC の
   二重初期化になる。本実装は `ble_up` タスクが **WiFi の状態が `CONNECTING` を抜けるまで
   待ってから** `esp_hosted_init()` を呼ぶことで直列化している(WiFi 無効時は BLE 側が
   トランスポートの持ち主になるので、**SSID 未設定でも BLE は動く**)。
2. **`sm_ctrl_set_node_addr` は BLE→UDP handoff を再開しない**(最重要)。シムで
   `Activity::BleHandoff` → `set_peer` + `resume` → `Activity::Pairing` を行うのは
   **`sm_ctrl_mdns_rx` が解決に成功したときだけ**(`controller.rs` の `sm_ctrl_mdns_rx`)。
   `set_node_addr` はノード帳のアドレスを書き替えて `RESOLVE_DONE` を積むだけなので、
   §11.1 が想定した「thread: SRP → `sm_ctrl_set_node_addr`」だけでは **BLE_DONE の後で
   永久に止まる**。シム無改造の制約下での回避策として、SRP で引いたアドレスを
   **最小の mDNS 応答に仕立てて `sm_ctrl_mdns_rx` へ渡している**(`feed_addr_as_mdns`):
   `sm_ctrl_resolve_start` が作るクエリの QNAME(= `<compressed-fabric>-<node-id>._matter._tcp.local`。
   compressed fabric は C++ から見えないのでここから借りる)を owner にした SRV 1 本 +
   その target(`smsrp.local`)の AAAA 1 本、DNS 圧縮ポインタなし。
   **恒久対処はシム側で `sm_ctrl_set_node_addr` にも handoff 再開を持たせること**
   (そうすればこの合成パケットは捨てられる)。
3. **`ESP_HOSTED_ENABLE_BT_NIMBLE` は 4 条件が揃わないとメニューごと消える**(上表)。
   `sdkconfig.defaults` に書いても無言で無視されるので、生成後の `sdkconfig` を grep して
   確認すること。`BT_CONTROLLER_DISABLED` は choice のメンバなので `BT_CONTROLLER_ENABLED` を
   明示的に n にする必要はない(P4 では `SOC_BT_SUPPORTED` 不成立で選べない)。
4. **C6 の BT controller は RPC で明示的に起動する**。esp_hosted 同梱例と同じく
   `esp_hosted_bt_controller_init()` + `_enable()` を `nimble_port_init()` の**前**に呼ぶ
   (`ble_transport_ll_init` は `transport_drv_reconfigure()` しかしない)。
   ここが失敗するときは **C6 の slave FW が `CONFIG_BT_ENABLED=n` でビルドされている**疑い。
5. mDNS 解決用ソケットは **5353 に bind**(QM 応答をマルチキャストで返す実装のため)し、
   `ff02::fb` を **WiFi netif の index で join** する。クエリはシムが返す IPv4
   マルチキャスト(224.0.0.251、v4-mapped で送出)と `ff02::fb%wifi` の両方へ投げる。
6. NimBLE は既定の `BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL` で内蔵 RAM を取る。pump の静的
   スタック 128KB + LVGL(描画バッファは PSRAM)と同居させるため、接続数 1 / host タスク 5KB /
   central+observer のみに絞ってある。bss は T2 の 1,609,803 → 1,741,707(+約 129KB)。

#### 実機で見るべき点

```
tab5_wifi: got IPv4 ... / got IPv6 ...             ← 先に WiFi(esp_hosted)が上がる
ble_cent: wifi settled (state=2); bringing up hosted BT
ble_cent: nimble host started (host-only over esp_hosted VHCI)
ble_cent: nimble host synced (own addr type 0)     ← ここまで来れば BLE ready
ble_cent: scanning for 0xFFF6 commissionable (discriminator=3840)
ble_cent: matched device; connecting → MTU=... → C2 subscribed
pump:  BLE phase 1..9 → BLE_DONE → handoff → PAIR COMPLETE
```

判断材料は (a) `nimble host synced` が出るか(出なければ C6 の BT controller / slave FW)、
(b) `matched device` が出るか(出なければ discriminator or 広告)、(c) `C2 subscribed` の後で
BTP が進むか、(d) handoff で運用アドレスが引けるか(WiFi = mDNS、Thread = SRP)。
ble-thread は §11.2 のとおり対応デバイスが手元に無ければ実機は後日。

### 11.5 T3 実機 E2E 完了(2026-08-24)

BLE→WiFi の実機フルパスを完走した(ターゲット = NanoC6 generic_matter_cpp、
factory reset 状態、discriminator 3840): scan 0.05 秒で照合 → connect → MTU 247 →
GATT → C2 subscribe → BTP+PASE(phase 1-6)→ AddWiFi(10)→ ConnectNetwork(11、
遅延応答 8 秒)→ BLE_DONE → **mDNS 解決 0.3 秒**(453B 応答)→ CASE(phase 8-9)→
**PAIR COMPLETE 全体 ≈17 秒** → Toggle OK。ble-thread は実装済み・実機は対象デバイス
の準備待ち(§11.2)。

#### 実機で発見した問題と対処(時系列。重要度順ではない)

1. **C6 slave 2.12.7 は FeatureControl RPC(BT init/enable)に無応答**(タイムアウト)。
   ただし BT controller は slave 起動時から生きていて HCI は通る。同梱例に合わせ
   **警告して続行**に変更(真の判定は nimble sync)。slave を 2.12.12+ に焼き替えれば
   解消する可能性はあるが未確認。
2. **死んだノードへの周期 read が livelock を起こす**: CASE 確立試行が MRP 諦めまで
   ~20 秒シムを塞ぎ、10 秒周期 poll と重なってシムがほぼ常時 busy →
   `sm_ctrl_ble_pair_start` が rc=-2 で弾かれ続ける。対処 = read 失敗ノードに
   **2 分バックオフ** + pair 開始の **30 秒 busy リトライ**(pump を回しながら)。
3. **`sm_ctrl_set_node_addr` は BLE handoff を再開しない**(シム制約。再開するのは
   `sm_ctrl_mdns_rx` の解決成功だけ)。Thread kind の SRP 引き当ては **mDNS 応答に
   合成して給餌**(`feed_addr_as_mdns`。QNAME は `sm_ctrl_resolve_start` の出力から
   借用)。恒久策 = シムに set_node_addr でも resume する改修(将来)。
4. **handoff 失敗でシムが BleHandoff のまま永久 busy**(abort API なし)。対処 =
   ダミー解決(::1)を給餌して CASE を即失敗させ状態機械を畳む(unwedge)。
5. **最重要: esp_hosted + WiFi power save(既定 MIN_MODEM)で IPv4 マルチキャスト
   RX が全滅する**。症状は「IPv6 NDP(solicited-node)は通るのに 224.0.0.251 が
   1 パケットも届かない」「RA が来ず GUA 取得がブート毎に不安定」。
   **`esp_wifi_set_ps(WIFI_PS_NONE)` で完治**(mDNS announce/応答の受信も RA も安定。
   デバイス例が全て ps=none だったのはこれ)。PC 上の 5353 リスナー
   (マルチキャスト join + パケットダンプ)が切り分けの決め手だった。
6. **デバイスの operational announce は ConnectNetwork 成功直後(BLE_DONE より前)に
   3 発だけ流れる**。取り逃すと以後はクエリ頼みになるため、mDNS ソケット
   (AF_INET、:5353 bind + IGMP join、IF=WiFi IPv4 明示)を **BLE 開始前に開き**、
   BLE フェーズ中の応答パケット(QR=1、150B 以上)をキャッシュして BLE_DONE 後に
   リプレイする。加えてクエリループ(source port 5353、20 秒)と、
   **EUI-64 導出フォールバック**(BLE ピアの BT MAC−2 = WiFi MAC → 自分の GUA
   prefix or fe80 + EUI-64 を合成して直接給餌。ESP32 ファミリ限定の割り切り)の
   三段構え。今回の成功パスはクエリ応答(0.3 秒)で、キャッシュ・導出は保険として残す。
7. **前回セッションの BLE イベント残骸(Disconnected 等)が新セッションを即死させる**
   → pair 開始前にキューをドレイン。
8. デバイス側の改善課題(generic FW、このリポジトリの別タスク):
   (a) fail-safe 巻き戻し後も WiFi 資格情報が残り、次回 ConnectNetwork が
   「切断 → coex 中の再 join」になって失敗しやすい(e5-light の「同一資格情報なら
   no-op」未移植)。(b) mDNS responder がクエリに答えない状況が PS/join 状態に
   依存して発生し得る(announce 頼みの潜在穴。generic-firmware.md の注記どおり)。

#### 送信側の scope 補完の変更

`send_sm` の「scope 未指定の fe80 宛」fallback を OT netif 固定から
**WiFi netif 優先(up なら)**に変更。Thread ノードの実用アドレスは fd::(ML/OMR)
なので実害なし、WiFi ノードの fe80(nodes.tlv は scope を持たない)が正しく届く。
