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
