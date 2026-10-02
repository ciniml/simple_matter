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

## 12. T4: マルチデバイス UI(AirQ 空気質 + NanoC6 照明を 1 画面で)

Status: 設計(2026-08-24)。T3 完了を受けて、Tab5 コントローラの UI を
「照明の on/off」専用から**ノード種別対応**に拡張する。目標構成:
AirQ(airq-sensor = Rust S3 FW、SEN55/SCD40 実センサ)の空気質値の表示 +
NanoC6(onoff_light_cpp Thread 構成)の on/off 操作を同一画面で扱う。

### 12.1 前提と実機配置(T4 完了時の姿)

| 機材 | FW | 役割 |
|---|---|---|
| Tab5 + H2 | tab5_ctrl_app | Thread leader + WiFi + BLE コントローラ |
| NanoC6 | onoff_light_cpp(thread) | Thread 照明(要焼き戻し。現 generic FW) |
| AirQ(S3) | airq-sensor(Rust) | WiFi 空気質センサ(要焼き替え。現 onoff_light_cpp) |

コミッショニングは T2/T3 の既存経路(NanoC6 = on-network Thread、AirQ =
on-network WiFi か BLE→WiFi)。フリート焼き替えは実機フェーズで親が行う。

### 12.2 シム拡張(唯一の crates/ 変更): f32 スカラ read

`scalar_from_reports`(crates/simple-matter-cffi/src/controller.rs)の TlvValue
マッチに **Float32 を追加**し、`f32::to_bits()` のビットパターンを `value_u64` に
載せる(C ヘッダ・ABI 変更なし。C++ 側は `memcpy` で f32 に戻す)。現状 f32 属性
(CO2 / PM2.5 の MeasuredValue)は `_ => (0,false)` に落ちて読めない。
subscribe レポート経路(同関数)も同時に直る。回帰 = cargo test 全緑。
**値の型判別**のため、イベントに型情報は足さない(ABI 維持)— C++ 側が
「このパスは f32」と知っている前提で読み替える(smctl の cluster_def! と同じ割り切り)。

### 12.3 UI / pump の拡張(tab5_ctrl_app)

1. **ノード種別の検出**: ペア完了時と起動時の一覧再構築時に、EP1 の
   AirQuality(0x005B attr 0x0000)を read してみる → 成功 = センサ、
   失敗(UNSUPPORTED_CLUSTER 等)= 照明(OnOff 前提)。結果は NVS
   (namespace "smui"、key = node id hex)にキャッシュしてリブート後も再判別しない
   (誤判別時は ⟳ で再検出できる導線があるとよい)。
2. **周期ポーリングの種別分岐**(既存の 10 秒周期 + 2 分バックオフを維持):
   - 照明: OnOff read(現行どおり)
   - センサ: AirQuality(EP1 0x005B/0, u8)→ CO2(EP1 0x040D/0, f32)→
     PM2.5(EP1 0x042A/0, f32)→ 温度(EP2 0x0402/0, i16 ×0.01℃)→
     湿度(EP3 0x0405/0, u16 ×0.01%)を 1 周期 1 属性ずつ順繰り
     (CASE 済みなら 1 read ≈ 0.3 秒なので 5 属性 50 秒で一巡。まとめ読みは
     シムが単発 read のみなので v1 はしない)
3. **ノード行の表示**(sm_ui_node_t 拡張):
   - 照明行: 現行どおり(On/Off バッジ + Toggle/Read/⟳)
   - センサ行: バッジの代わりに **AirQuality の 6 段階を色付きラベル**
     (Good=緑〜VeryPoor/ExtremelyPoor=赤)、2 行目に
     `CO2 812ppm  PM2.5 3.2µg/m³  26.5℃  41%` のようなサマリ。Toggle ボタンは
     出さない(Read = 全属性の再読込に流用)
4. スナップショット: sm_ui_node_t に `kind`(0=不明/1=照明/2=センサ)と
   センサ値 5 種(f32×2 / i32×3、null 可)を追加。UI ↔ pump の単線契約は不変。

### 12.4 ゲート

1. cargo test / clippy / fmt 全緑(シム f32)+ tab5_ctrl_app esp32p4 docker build green
2. 回帰: thread_ctrl_hub_cpp ビルド green、他 example 変更ゼロ
3. 実機(親 + ユーザ): AirQ(airq-sensor)と NanoC6(thread 照明)を Tab5 の
   fabric にコミッショニング → 一覧にセンサ行(実測値)と照明行(Toggle 動作)が並ぶ

### 12.5 実装記録(T4、2026-08-24)

**結論**: §12.2(シム f32)+ §12.3(tab5_ctrl_app のノード種別対応)を実装。
crates/ の変更は設計どおり **1 箇所(+ 単体テスト 1 本)** のみ、他 example の
変更ゼロ。ビルドゲートは全緑(実機 E2E は次フェーズ)。

#### 変更 / 追加ファイル

| ファイル | 変更 |
|---|---|
| `crates/simple-matter-cffi/src/controller.rs` | `scalar_from_reports` の TLV → `value_u64` 変換を `scalar_from_tlv()` に切り出し、`Float(f32)` / `Double(f64)` を追加。テスト `scalar_from_tlv_covers_floats` を追加 |
| `.../tab5_ctrl_app/main/app_state.hpp` | `sm_ui_node_kind_t` / `sm_ui_sensor_slot_t` を追加、`sm_ui_node_t` に `kind` + センサ値 5 種(`has_*` フラグ付き)を追加 |
| `.../tab5_ctrl_app/main/ctrl_pump.cpp` | 種別検出(NVS "smui" キャッシュ)、センサ属性の順繰り poll、`f32_from_value()`、Read / ⟳ の種別分岐 |
| `.../tab5_ctrl_app/main/ui.cpp` | センサ行(AirQuality 色付きバッジ + 2 行目サマリ、Toggle 非表示) |

#### シムの差分(§12.2)

```rust
fn scalar_from_tlv(v: &TlvValue<'_>) -> (u64, bool) {
    match *v {
        TlvValue::Boolean(b) => (b as u64, false),
        TlvValue::UnsignedInteger(u) => (u, false),
        TlvValue::SignedInteger(i) => (i as u64, false),
        TlvValue::Float(f) => (f.to_bits() as u64, false),      // ← 追加
        TlvValue::Double(d) => ((d as f32).to_bits() as u64, false), // ← 追加
        TlvValue::Null => (0, true),
        _ => (0, false),
    }
}
```

C ヘッダ / ABI は不変。read と subscribe が同じ関数を通るので両経路が同時に直る。
Double は **f32 に丸めてから**載せる(C++ 側の読み替えを「下位 32bit を memcpy」の
1 通りに保つため)。C++ 側は `f32_from_value()`(ctrl_pump.cpp)で復元する。

#### tab5_ctrl_app の設計メモ

- **種別検出は 2 段**: EP1 AirQuality(0x005B/0)read 成功 = センサ、駄目なら
  EP1 OnOff(0x0006/0)read を試して成功 = 照明。**両方落ちたら UNKNOWN のまま
  キャッシュしない**。「AirQuality が読めない = 照明」と即断すると、単にノードが
  不達なだけのときに誤って照明として NVS に焼き付いてしまう(実装中に気付いた罠)。
- **キャッシュ**: NVS namespace `"smui"`、key = NodeId の hex。**NVS のキー長上限は
  15 文字**なので `%016llx` は入らない。下位 60bit を `%015llx` で焼く。値は
  `nvs_set_u8`(sm_ui_node_kind_t)。
- **判定タイミング**: (a) ペア完了直後(`after_pair_complete`)、(b) キャッシュに
  無いノードの初回 poll(その 1 周期を検出に使う)、(c) ⟳ Addr ボタン
  (キャッシュを消して再検出 = 誤判別からの復帰導線)。
- **周期 poll**: 10 秒周期 / 2 分バックオフ / 1 周期 1 操作の既存契約は不変。
  センサは `SENSOR_ATTRS[]`(AQ → CO2 → PM2.5 → 温度 → 湿度)を
  **NodeId で引くカーソル表**(`g_cursor`)で 1 属性ずつ回す。行の並び替えで
  カーソルが他ノードへ移らないよう、行 index ではなく NodeId で持つこと。
- **Read ボタン**: 照明 = 従来どおり OnOff 1 発。センサ = カーソルを先頭に戻して
  5 属性を連続読み(1 本落ちたら打ち切る。死んだノードで CASE を 5 回試さない)。

#### UI(§12.3 の 3)

- ノード行の高さは **96px 据え置き**。左カラム(480px)を
  `NodeId / アドレス / 計測値サマリ` の 3 段にし、サマリ行は照明行では
  `LV_OBJ_FLAG_HIDDEN`(LVGL 9 の flex は hidden 要素を配置から外す)。
- バッジ(150×56)は照明が `ON` / `OFF` / `?`、センサが AirQuality 6 段階の
  色付きラベル(Good 緑 → ExtPoor 赤、0/未取得はグレー "?")。
- 2 行目サマリ = `CO2 812ppm   PM2.5 3.2ug/m3   26.5C   41%`。未取得は "-"。
- Toggle ボタンはセンサ行では hidden。Read / ⟳ Addr は両種別に出す。
- **`lv_label_set_text_fmt` に `%f` は渡さない**(`lv_snprintf` は既定で float
  非対応)。float は C ライブラリの `snprintf` か整数演算で桁を作ってから `%s`
  で流す。ここでは整数演算にしてある(`-Wformat-truncation` 対策で値域も clamp)。
- 行幅の内訳: 480(左カラム)+ 150(バッジ)+ 120(note)+ 160(Toggle)
  + 120(Read)+ 150(⟳ Addr)+ 隙間 12×5 = 1240 < 1280。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| `cargo fmt --all --check` | green |
| `cargo test --workspace` | green(`controller::tests::scalar_from_tlv_covers_floats` を含め全通過) |
| `cargo clippy --workspace --all-targets` | green(警告ゼロ) |
| tab5_ctrl_app esp32p4 docker build | green(`tab5_ctrl_app.bin` = 0x1ffc00 バイト、app partition の 50% 空き) |
| thread_ctrl_hub_cpp esp32p4 build(回帰) | green(0xf98a0 バイト) |
| 他 example の変更 | ゼロ(`git status` = crates 1 + tab5_ctrl_app 3 ファイルのみ) |

#### 実機で見るべき点(次フェーズ)

1. AirQ の EP 配置が前提どおりか(EP1 = AirQuality/CO2/PM2.5、EP2 = 温度、
   EP3 = 湿度)。ずれていたら `SENSOR_ATTRS[]` の ep だけ直せばよい。
2. CO2 / PM2.5 が **f32 として妥当な値**に見えるか(壊れていれば TLV が
   f32 でない = デバイス側が u16 等で報告している可能性。その場合は
   `scalar_from_tlv` ではなく C++ 側の読み替えを直す)。
3. 種別検出が 1 回で決まり、リブート後に再検出が走らないこと(NVS "smui")。
4. センサ 1 ノード + 照明 1 ノードで、照明の Toggle 応答が
   センサの順繰り poll に阻害されないこと(1 周期 1 操作 + busy 契約)。

## 13. T5: デバッグ自動化(GUI リモート制御 / GUI 非依存の機能呼び出し / スクショ)

Status: 設計(2026-08-24)。T3/T4 の実機デバッグで「タッチ操作が人間必須」なことが
反復速度のボトルネックだったため、シリアルコンソールから Tab5 を完全リモート制御
できるようにする。エージェントによる自動 E2E(コマンド投入 → ログ/画面で検証)が狙い。

### 13.1 構成(3 層。いずれも USB-Serial-JTAG の esp_console に載せる)

Tab5 の CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y は設定済みで、ログと同じ ttyACM を
esp_console REPL と共用する(generic FW の smgen コンソールと同じ流儀)。

**T5a: 機能の直接呼び出し(GUI 非依存)** — UI↔pump の単線契約(sm_ui_op_t キュー +
スナップショット)がそのまま注入点になる。コンソールコマンドは **UI と同じ
`sm_app_post_op()` を呼ぶだけ**(pump 側は呼び出し元を区別しない = 実機で GUI と
同一経路の検証になる)。
- `nodes` = ノード帳 + 種別 + センサ値/on-off(スナップショットのテキストダンプ)
- `status` = Thread/WiFi/BLE/pairing 状態(ステータスバー相当)
- `toggle <node>` / `read <node>` / `addr <node>`
- `pair <ipv6> <node> <passcode> [thread|wifi]`(on-network)
- `pair-ble <disc> <node> <passcode> [wifi|thread]`(BLE)
- 出力は 1 行 1 レコードの安定書式(スクリプトから grep できること)

**T5b: GUI のリモート操作** — LVGL の入力はタッチ indev 経由なので、
`display_gfx.cpp` の indev read_cb をラップして**合成タップを注入**する
(T1 の回転シムと同じ手口。公開 API のみ)。
- `tap <x> <y>` = 押下 80ms → 離す(1 発でボタン/キーボードが押せる)
- `swipe <x1> <y1> <x2> <y2>`(タブ切替等。v1 では任意)
- `ui-dump` = ウィジェットツリーを走査してクラス名 / 座標 / hidden / ラベル文字列を
  印字(タップ座標の特定と表示検証の両方に使う。LVGL タスクで
  `sm_display_lock()` を取って走査)

**T5c: スクリーンショット(フレームバッファ転送)** — `lv_snapshot_take`
(RGB565、PSRAM に 1280×720×2 ≒ 1.8MB)で現在の画面を取り、コンソールへ
base64 で流す。フレーミングは
`SCREENSHOT <w> <h> RGB565 <base64len>` → base64 本文(76 桁/行)→ `END`。
- USB-Serial-JTAG の実効スループットで 1.8MB×4/3 ≒ 5〜15 秒。`screenshot 2` で
  1/2 間引き(640×360、約 1/4 時間)も用意する
- PC 側デコーダ `scripts/tab5shot.py`(pyserial: コマンド送信 → フレーム受信 →
  PNG 保存)。tap/ui-dump/nodes も同スクリプトのサブコマンドにすると
  エージェントの 1 コマンド操作になる
- 撮影中は `sm_display_lock()` で描画を止める(転送はロック外で行う =
  スナップショットバッファからの送出なので UI は数秒固まらない)

### 13.2 契約上の注意

- コンソールタスクから `sm_ctrl_*` / `lv_*` を直接呼ばない。pump へは op キュー、
  LVGL へは「合成タップの注入」(indev read_cb が LVGL タスクで拾う)と
  「lock を取ってのツリー走査 / snapshot」だけ。単線契約は不変。
- ログと REPL が混ざるのは許容(プロンプト汚れ対策として、コマンド応答は
  `OK`/`ERR` 終端の安定書式にし、スクリプト側は終端マーカで切る)。

### 13.3 ゲート

1. tab5_ctrl_app esp32p4 build green + 回帰(hub)green
2. 実機: シリアルから `nodes`/`toggle`/`pair-ble` が GUI と同一挙動、
   `tap` で Pair ダイアログが開く、`ui-dump` にラベルが出る、
   `screenshot` の PNG が PC で復元できる(目視一致)
3. 以降の実機 E2E はこの経路で**エージェントが自走**できること(タッチ手番の排除)

### 12.6 / 13.4 実機追記(T4 実戦投入 + T5a 稼働、2026-08-25 未明)

**動いたもの(実機実証)**:
- **T5a デバッグコンソール稼働**(`main/console_dbg.cpp`): USB-Serial-JTAG の REPL に
  `nodes` / `status` / `toggle` / `read` / `pair` / `pairble` / `udptest`。
  入力は **CRLF 必須**(LF のみでは linenoise が確定しない)。以降の実機 E2E は
  タッチ操作なしでエージェントが自走できるようになった(この節の検証は全て自走)。
- **AirQ(airq-sensor、discriminator 2340 に変更 + WiFi 資格情報のビルド時プリセット
  `SM_WIFI_SSID/SM_WIFI_PASS` を追加)を on-network PASE で 4.7 秒コミッショニング**
  (`pair fe80::... 11 wifi`)→ **T4 の種別検出が kind=2(センサ)を自動判定し
  AirQuality=Good を CASE read で取得**。f32 パイプライン込みの T4 経路が実機で成立。
- `udptest` による決定的切り分け: **esp_hosted 経由の Tab5 は非既定グループの
  IPv4 マルチキャスト受信が不可能**(join は成功を返すのに 1 パケットも来ない。
  ユニキャスト :5353 受信は正常)。ff02::1(RA)等の既定グループのみ通る。
  → mDNS 解決はマルチキャスト受信に依存してはならない。resolve は
  v4/v6 マルチキャスト送信 + **/24 ユニキャスト掃引**(デバイスはユニキャスト
  クエリに応答することを PC probe で実証)の 3 本立てに変更済み。

**残る不具合(次セッションの先頭課題)**:
1. **シム: BLE 試行の 2 回目以降で BTP が壊れる**(3 バイトの C1 write を 5 秒毎に
   繰り返す。1 回目は常に正常)。`sm_ctrl_ble_pair_start` の再入で BTP/handshake
   状態が完全リセットされていない疑い。回避 = 試行毎に Tab5 再起動。
2. **airq-sensor(Rust S3)の WiFi RX が数分で沈黙する**(コミッショニング直後は
   CASE/read 成立 → 数分後に NDP/ping ごと不応答。センサ/e-ink は生存)。
   esp-radio + BLE coex の RX 停止系。Tab5 再起動後の CASE resumption が
   「unreachable」になる直接原因。
3. NanoC6(onoff_light_cpp thread、discriminator 2560 に変更)の ble-thread E2E は
   1 の回避(再起動後 1 発目)で再試行するところで中断。
4. 細事: unwedge のダミー解決がノード帳に幽霊ノード(::1)を残す/その
   「0 shown / 1 in book」ログが 2 秒毎に出る。掃引のバースト(254 パケット)は
   10ms/32 発で均しているが要観察。
5. **ビルドの罠(重要)**: simple_matter コンポーネントの cargo 呼び出しは
   staticlib(.a)が存在すると ninja にスキップされ **Rust の変更が反映されない**。
   Rust を触ったら `target/<triple>/release/libsimple_matter_cffi.a` を消してから
   ビルドする(恒久対処 = CMakeLists に Rust ソースの DEPENDS を張る、将来)。

### 12.7 / 13.5 実機完了記録(①〜③ + T4 目標構成の成立、2026-08-25)

前節 §12.6/13.4 の残課題①〜③を順に解消し、**T4 の目標構成(AirQ 空気質センサ +
NanoC6 Thread 照明を 1 台の Tab5 で)を実機で成立**させた。検証は全てコンソール
(T5a)からの自走。

1. **① シム: BLE 2 回目以降の沈黙 — 真因 = initiator の handshake スロット(1 本)が
   中断後も残り `start_pase` が NoSpace**(commissioner は「後で再試行」扱いで無送信、
   60s の HANDSHAKE_TIMEOUT まで沈黙。BTP keep-alive の 3 バイト書き込みだけが残る)。
   `ScInitiator::abort_handshake` + `ControllerStack::abort_handshake` を追加し、
   BLE 切断時の abort で予約セッション・exchange ごと畳む。ホストのユニットテストに
   「2 セッション連続」を追加して再現・修正を固定(657 pass)。
2. **② AirQ「不達」— 真因は WiFi 沈黙ではなく IPv6 近隣解決**: airq-sensor(esp-radio)
   は NS(solicited-node マルチキャスト)を受信できず、近隣キャッシュが冷えると
   fe80 宛が届かなくなる(PC からのユニキャスト mDNS には常に応答 = 生きている)。
   対処 = **WiFi デバイスの運用アドレスは IPv4**: mDNS 解決成功時に応答元 v4 を
   `sm_ctrl_set_node_addr` で固定、`pair`/`setaddr` は v4 リテラルを受理。
   v4 では ARP(ブロードキャスト)で解決できるため再起動後も安定。
3. **③ NanoC6 ble-thread E2E 完走**(onoff_light_cpp thread、discriminator 2560):
   scan → BTP+PASE → dataset 投入 → Thread attach → SRP 登録 → CASE、**約 13 秒で
   PAIR COMPLETE** → Toggle OK。
4. **pump の残骸イベント誤認**(実機で発覚): run_until がタイムアウトで諦めた後に
   シム内で完了した READ_DONE がキューに残り、次の read がそれを自分の結果と誤認
   (裏で本物の read が進行 → 続く開始が -10)。`start_op_clean` = 開始前ドレイン +
   busy 5 秒リトライを全 op に適用。pair 開始の busy 待ちは 90 秒(不達ノードの
   CASE が HANDSHAKE_TIMEOUT まで粘るため)。
5. **console_repl のスタック不足**: 数 KB のスナップショットをスタックに置いた上で
   float printf → stack protection fault でリブート。static 化 + REPL スタック 16KB。
6. 実測: AirQ 5 属性 read(AQ/CO2 f32/PM2.5 f32/温度/湿度)が **1 秒で全成功**
   (例: CO2 772ppm、PM2.5 1.9µg/m³、28.3℃、45.8%)。起動直後の初回 poll は
   Thread 再アタッチ待ちで落ちるため 30 秒後に変更、成功した操作はバックオフを解除。
7. **`sm_ctrl_abort_op`(シム API 追加)**: pump の `run_until` がタイムアウトで諦めたら
   シム側の進行中 op(CASE 確立待ち / 応答待ち / pairing)も畳んで Idle に戻す。
   これが無いと、Thread 再アタッチ中の NanoC6 宛 CASE が内部で 60 秒粘り、その間の
   AirQ read や UI 操作が全部 busy(-10)になる(実機で観測 → 追加後は abort 直後に
   AirQ の 5 属性 read が成功)。C ヘッダに宣言追加(ABI 追加のみ)。
8. **コアの exchange リーク 2 件(実機で発覚、②の最終真因)**:
   (a) 期限切れハンドシェイクで予約セッションは解放するが **exchange を閉じていなかった**
   (responder / initiator 両方)。コントローラ再起動を挟んだ半端な CASE の exchange が
   デバイスのプール(4 本)に残り、数回で枯渇 → 新規 Sigma1 を黙って捨てる
   (NanoC6 が「デバイス再起動まで応答しない」症状。Tab5 の連続再起動で再現)。
   `ScResponder::expire_one` / `ScInitiator::expire_timed_out` を追加し、両 stack の
   drive_ticks で exchange を close + 再送バッファ回収。
   (b) `ExchangeManager::close` の返す再送バッファ id を捨てていた(`let _ =`)→ 中断
   数回で tx_pool 枯渇 → `start_case` が -4 で二度と通らない。全 close 箇所で release。
   検証: 3 台の FW を更新後、**Tab5 を 60 秒間隔で 3 回連続再起動 → NanoC6 Toggle OK ×2、
   AirQ 5 属性 read OK**(デバイス側の再起動なし)。

### 13.6 実装記録(T5b/T5c、2026-08-25)

T5a(コンソール REPL)の上に **GUI リモート操作(T5b)** と
**スクリーンショット(T5c)** を載せた。これでエージェントは「操作 → 画面で検証」まで
シリアル 1 本で自走できる(タッチ手番と目視手番の両方が消える)。

#### 変更 / 追加ファイル

| ファイル | 中身 |
|---|---|
| `main/display_gfx.{hpp,cpp}` | 合成ポインタ注入。`sm_display_inject_pointer(x1,y1,x2,y2,ms)` / `sm_display_inject_busy()`。実体は indev の `read_cb` 内の状態機械(押下 → 線形補間で移動 → 離す)。注入中は実タッチを完全に無視(排他) |
| `main/console_dbg.cpp` | `tap` / `swipe` / `ui-dump` / `screenshot` を追加 |
| `sdkconfig.defaults` | `CONFIG_LV_USE_SNAPSHOT=y` |
| `scripts/tab5ctl.py`(新規) | PC 側クライアント(pyserial + Pillow) |
| `ports/esp-idf/examples/tab5_ctrl_app/README.md` | 「デバッグコンソール(T5)」節を追加 |

#### コマンド仕様(1 行 1 レコード + `OK`/`ERR` 終端は T5a と同じ)

- `tap <x> <y>` — 押下 80ms → 離す。コンソールタスクは注入完了 + 150ms を待ってから
  `TAP <x> <y>` / `OK` を返すので、直後の `ui-dump` / `screenshot` は
  タップ後の画面を映す。
- `swipe <x1> <y1> <x2> <y2> [ms]` — 既定 300ms(上限 5000ms)。
- `ui-dump` — `UI <depth> <class> x=.. y=.. w=.. h=.. hidden=0/1 text="..."` を
  深さ 8 / 子 64 件まで。`x,y,w,h` は**画面絶対座標**(`lv_obj_get_coords`)なので
  そのまま `tap` の座標計算に使える。`text` は label / textarea / dropdown から取り、
  ボタン内ラベルは子として別行に出る。
- `screenshot [1|2]` — `SCREENSHOT <w> <h> RGB565 <base64桁数>` → base64 76 桁/行 →
  `END` → `OK`。`2` は 640x360 への単純間引き。

#### 設計判断(なぜこうしたか)

1. **クラス名は `lv_obj_check_type()` で当てる**。`obj->class_p->name` は
   `lv_obj_class_private.h` の中で、公開ヘッダから触れない。既知クラス
   (label/button/textarea/dropdown/keyboard/buttonmatrix/tabview/qrcode/image)を
   派生 → 基底の順に判定し、外れたら `obj`。private ヘッダを引かないので LVGL の
   マイナー更新で壊れない。
2. **snapshot バッファは自前で PSRAM から取る**。`lv_snapshot_take()` は
   `lv_draw_buf_create()` → LVGL の malloc(この構成では `CONFIG_LV_USE_CLIB_MALLOC=y`
   = 内蔵 RAM)へ行き、1.8MB は**内蔵 RAM に載らない**。よって
   `heap_caps_malloc(MALLOC_CAP_SPIRAM)` + 64B アラインした領域を
   `lv_draw_buf_init()` で包み、`lv_snapshot_take_to_draw_buf()` に渡す
   (`lv_draw_buf_reshape` が `LV_STRIDE_AUTO` で stride を決め、
   `size > data_size` なら弾いてくれるので安全)。
3. **撮影は lock 内 / 転送は lock 外**。`sm_display_lock(10000)` を取って
   snapshot を撮り、unlock してから base64 を吐く。数十秒の転送中も UI は生きている。
4. **base64 は自前**(64 文字テーブル + 57 バイト → 76 桁の 1 行)。mbedtls を
   main の `REQUIRES` に足さずに済む。

#### 踏んだ罠

1. **`lv_snapshot_*` は既定 `n`**(`CONFIG_LV_USE_SNAPSHOT`)。有効化を忘れると
   ヘッダは通るのに実体が無くリンクエラーになる。`sdkconfig` が既にあると
   `sdkconfig.defaults` の変更が反映されないので、**`rm -f sdkconfig` してから
   set-target し直す**(F8 の罠 7 と同じ)。
2. **合成タップは「PRESSED を最低 1 回 LVGL に見せてから離す」必要がある**。
   indev の読み取り周期(~16-33ms)より短い押下だと read_cb が 1 度も
   PRESSED を返さずクリックが生成されない。`press_reads` カウンタで
   「1 回も押していないなら期限を過ぎていても押す」ようにしてある。
3. **`ui-dump` は再帰**。REPL スタックは 16KB なので 1 段あたりの自動変数を
   小さく保ち、文字列バッファは `static`(§13.5 の罠 5 と同じ理由。コンソールは単一タスク)。
4. **PC 側は送信 CRLF**(§13.4)。加えてコマンドのエコーバックとプロンプト
   `tab5>` が同じ行に来ることがあるので、`tab5ctl.py` は正規表現で剥がしてから
   終端マーカ判定をする。ログ行(`I (12345) tag:`)は既定で捨てる。

#### ゲート実測

1. `tab5_ctrl_app` esp32p4 docker ビルド **green**
   (`SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.local"`、
   `rm -f sdkconfig` → set-target → build。bin 0x20cd60 = 2.05MB、パーティション 49% 空き)。
   Rust には触っていないので staticlib の消去は不要。
2. `python3 -m py_compile scripts/tab5ctl.py` **OK**。
3. 実機(親): 書き込み → `ui-dump` にラベルが出ること、`tap` で
   `+ Pair new device` ダイアログが開くこと、`screenshot --div 2` の PNG が
   画面と目視一致すること。

#### 13.6 補足: 実機確認(親、2026-08-25)

- `ui-dump` → `tap`(「Pair new device」ラベル中心 182,204)→ ダイアログのラベルが
  `ui-dump` に出る → `tap` Close で閉じる、まで自走で成立(T5b OK)。
  ラベルの LVGL シンボル(`+` 等の私用領域文字)はダンプで落ちるので、文字列照合は
  部分一致で行う。
- `screenshot`: 1/2 間引き(640×360)**≈5 秒**、フル(1280×720)**≈20 秒**で PNG 復元、
  目視一致(T5c OK)。実機で発覚した罠 2 つ: (1) OpenThread のログは `I(12345)`
  (スペース無し)形式で PC 側フィルタをすり抜ける、(2) ログ行が base64 行の**途中に
  癒着する**ことがある(行単位の原子性は無い)→ 本文行に `B:` 接頭辞を付け、PC は行内から
  `B:([base64]{1,76})` を抽出する方式に変更(欠落ゼロを確認)。
- 以降の実機デバッグは `scripts/tab5ctl.py` で「操作 → ui-dump/screenshot で検証」を
  エージェントが自走できる(§13.3 ゲート 3 達成)。
- **転送の取りこぼし(追記)**: `B:` 接頭辞だけでは **267 行 ≈ 22KB の連続欠落**が残った。
  真因は printf/puts(VFS 経由)が USB-Serial-JTAG の TX バッファ満杯時に**捨てる**こと。
  base64 行は `usb_serial_jtag_write_bytes`(空き待ちでブロック)で直接書く方式にし、
  行に連番(`B<hex4>:`)を付けて PC 側が欠落を検出できるようにした。
  結果: 1/2 間引き **3.4 秒**、フル **12.7 秒**、6/6 回欠落ゼロ。

## 14. T6: センサダッシュボード(Tab5 UI)

Status: 設計(2026-08-25)。T4 の Devices タブは「操作用の一覧」で、センサ値は 1 行の
サマリに詰めている。展示・常時表示に耐える**ダッシュボード画面**を足す。

### 14.1 画面構成(1280×720 横)

```
┌──────────────────────────────────────────────────────────────────┐
│ ステータスバー(既存 96px)                                         │
├─ Dashboard ─┬─ Devices ─┬─ Network ───────────────────────────────┤ ← タブ 64px
│ ┌ AirQ 0x…11 ──────────────────────── updated 8s ago ─────────┐   │
│ │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────┐ │   │
│ │  │ Air      │ │ CO2      │ │ PM2.5    │ │ Temp     │ │ RH │ │   │  タイル高 ≈ 260px
│ │  │ Quality  │ │  701     │ │  1.9     │ │  28.8    │ │ 44 │ │   │  数値は 48px フォント
│ │  │  GOOD    │ │  ppm     │ │  µg/m³   │ │  °C      │ │ %  │ │   │  単位は 20px
│ │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └────┘ │   │
│ └──────────────────────────────────────────────────────────────┘   │
│ ┌ Lights ───────────────────────────────────────────────────────┐   │
│ │  [ 0x…22   ON  ] [Toggle]     (照明ノードは横並びの小タイル)      │   │  ≈ 120px
│ └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

- **Dashboard タブを先頭・既定表示**にする(Devices / Network は現状維持)。
- センサノード 1 台 = 1 カード。カード見出しに NodeId 短縮(下位 4 桁)と
  「updated N s ago」(スナップショットに `last_update_ms` を追加)。
  5 タイル: AirQuality(6 段階の色 + 名称、既存 AQ_STYLE 流用)/ CO2(ppm)/ PM2.5
  (µg/m³)/ 温度(℃、×0.01 → 小数 1 桁)/ 湿度(%)。**値はタイル色で状態を示す**
  (CO2: <800 緑 / <1000 黄 / <1500 橙 / それ以上 赤。PM2.5: <12 / <35 / <55 / 以上。
  温湿度は中立色)。未取得は "—" + グレー。
- 照明ノードは下段に小タイル(NodeId 短縮 + ON/OFF バッジ + Toggle ボタン。
  操作は既存の SM_UI_OP_TOGGLE を post するだけ)。
- センサノード 2 台以上ならカードを縦に積む(3 台目以降はスクロール)。0 台なら
  「No sensor yet — pair one from the Devices tab」。
- フォント: 数値用に `CONFIG_LV_FONT_MONTSERRAT_48=y`(+32 があれば見出しに)。
  LVGL の `%f` は使わない(既存どおり整数演算で桁を作る)。

### 14.2 データ供給(pump 側)

- センサノードの周期 poll を「1 周期 1 属性」から **「1 周期で 5 属性まとめ読み」**
  (`do_read_sensor_all`)に変更(CASE 済みなら 5 属性 ≈ 1 秒。ダッシュボードの
  鮮度 = 10 秒周期)。照明ノードは従来どおり OnOff 1 本。
- `sm_ui_node_t` に `last_update_ms`(センサ値の最終成功時刻)を追加。UI は
  `esp_timer` 相当の現在時刻(pump が snapshot に `now_ms` を入れる)との差を表示。
- 単線契約は不変(UI は snapshot を読むだけ、操作は op を post するだけ)。

### 14.3 ゲート

1. esp32p4 docker ビルド green(Rust 無変更)。
2. 実機(自走): `tab5ctl.py screenshot` でダッシュボードの目視、`ui-dump` に
   5 タイルの値が入る、Toggle タイルで NanoC6 が反転、10 秒周期で updated が進む。

### 14.4 実装記録(T6、2026-08-25)

**結論**: §14.1(Dashboard タブ)+ §14.2(まとめ読み + 鮮度)を実装。変更は
`tab5_ctrl_app/` のみ(Rust / crates は無変更、他 example の変更ゼロ)。
esp32p4 docker ビルド green。

#### 変更ファイル

| ファイル | 変更 |
|---|---|
| `main/app_state.hpp` | `sm_ui_node_t` に `last_update_ms`(センサ値の最終成功時刻)、`sm_ui_snapshot_t` に `now_ms`(pump の現在時刻)を追加 |
| `main/ctrl_pump.cpp` | 周期 poll のセンサ分岐を `do_read_sensor_slot`(順繰り 1 属性)→ **`do_read_sensor_all`(5 属性まとめ読み)**に変更。順繰りカーソル(`SensorCursor` / `g_cursor` / `cursor_for`)を削除。`mark_node_updated()` を追加して read 成立ごとに時刻を打つ。`now_ms` をスナップショットへ(500ms 刻み + `refresh_thread_status`) |
| `main/ui.cpp` | Dashboard タブ(先頭・既定表示)。センサカード + 5 タイル + 照明の小タイル。しきい値色 `co2_color()` / `pm25_color()` |
| `main/console_dbg.cpp` | `nodes` に `SENSORAGE <node> <秒>` 行を追加(自走検証用。`-1` = 未取得) |
| `sdkconfig.defaults` | `CONFIG_LV_FONT_MONTSERRAT_32=y` / `CONFIG_LV_FONT_MONTSERRAT_48=y` |
| `README.md` | 「画面」節に Dashboard タブを追記 |

#### レイアウト実測(1280×720)

- タブ本体の可視領域 = 720 − 96(ステータスバー)− 64(タブバー)− 12×2(pad)= **536px**。
- センサカード = `LV_PCT(100)` × **272px**(見出し 34 + 隙間 8 + タイル 210 + pad 10×2)。
- 幅の内訳: 1280 − 24(タブ pad)= 1256 → カード pad 10×2 → 1236。
  タイル **236×5 + 隙間 12×4 = 1228 ≤ 1236**。
- 照明パネル = 154px(見出し 34 + 隙間 8 + タイル 92 + pad 20)。小タイルは
  **400×92**(NodeId 120 + バッジ 80 + Toggle 140 + 隙間 12×2 + pad 20 = 384 ≤ 400)を
  `LV_FLEX_FLOW_ROW_WRAP` で 3 枚/行(400×3 + 12×2 = 1224 ≤ 1236)。
- センサ 1 台 + 照明 = 272 + 12 + 154 = **438 ≤ 536**(スクロール無し)。2 台で 722 >
  536 になるのでタブ本体に `lv_obj_set_scroll_dir(LV_DIR_VER)` を張ってある。
- ビルド成果物: `tab5_ctrl_app.bin` = **0x230af0(2.30MB)**、app partition 45% 空き
  (T5c 時点の 0x20cd60 から +約 150KB = Montserrat 32/48 のビットマップ分)。

#### 踏んだ罠

1. **`for (lv_obj_t *t : {a,b,c})`(初期化子リストの範囲 for)は
   `#include <initializer_list>` が要る**。IDF の C++ 構成では自動では入らず
   `deducing from brace-enclosed initializer list requires ...` でコンパイルエラー。
   素の配列 `lv_obj_t *tabs[] = {...}` に直した。
2. **フォント追加は `sdkconfig` の再生成が必須**(§13.6 の罠 1 と同じ)。
   `rm -f sdkconfig` → `set-target esp32p4` → `build` の順でないと
   `lv_font_montserrat_48` がリンクエラーになる。
3. **µ / ³ / ° / — は Montserrat の内蔵レンジに無い**(LVGL 内蔵フォントは
   ASCII + 一部シンボルのみ)。設計図の `µg/m³` `℃` `—` はそのまま出すと
   豆腐になるので、表示は `ug/m3` / `C` / `-`(既存 Devices 行と同じ流儀)。
4. **`lv_obj_move_to_index(panel, -1)`** で照明パネルを常に最後に置く。カードは
   `dash` の子として後から append されるため、これが無いと照明がカードの上に来る。
5. **ダッシュボードのボタンの `user_data` は Devices 行の `row_ids` と別配列**
   (`g_ui.light_ids`)にした。両者はスナップショットの並びが同じでも
   作り直しの契機が違うので、共有すると片方の再構築で index がずれる。
6. **鮮度の基準時刻は pump が入れる**(`snapshot.now_ms`)。UI 側で `lv_tick_get()`
   を使うと pump の `esp_timer` と原点が揃わない。pump のループが 20 秒の CASE で
   止まっている間は `now_ms` も止まる = 「updated N s ago」が凍る仕様(そのほうが
   「pump が詰まっている」ことが画面に出るので都合がよい)。

#### 契約の維持

- UI は `sm_app_snapshot_get()` を読み、`SM_UI_OP_TOGGLE` を post するだけ
  (Dashboard の Toggle も Devices タブと同じ既存 op)。`sm_ctrl_*` は一切呼ばない。
- pump の 10 秒周期・2 分バックオフ・`start_op_clean`・照明の OnOff poll は不変。
  センサだけが「1 周期 1 属性」→「1 周期 5 属性」に変わった(1 本落ちたら打ち切るので、
  死んだノードでの CASE 再試行回数は従来どおり 1 周期 1 回)。
- 500ms の `tick_cb` が `refresh_dashboard()` → `refresh_devices()` の順に回る。

#### ゲート実測

| ゲート | 結果 |
|---|---|
| tab5_ctrl_app esp32p4 docker build(`rm -f sdkconfig` → set-target → build) | **green**(0x230af0 バイト、45% 空き) |
| Rust / crates の変更 | ゼロ |
| 他 example の変更 | ゼロ |

#### 実機で見るべき点

1. `tab5ctl.py screenshot --div 2` で Dashboard が既定表示、5 タイルが読めること。
2. `tab5ctl.py ui-dump` に数値がラベルとして出ること(タイルは
   `label` 3 行 = 名称 / 値 / 単位。canvas は使っていない)。
3. 10 秒周期で `updated N s ago` が 0 付近へ戻ること(`nodes` の `SENSORAGE` 行でも可)。
4. 下段 `Lights` の `Toggle` タイルをタップ(`tap x y`)して NanoC6 が反転すること。
5. まとめ読みでセンサ 1 周期が ≈1 秒に収まり、照明の Toggle 応答が阻害されないこと。

## 15. T7: NanoC6 本体ボタンでの on/off トグル(デバイス側)

Status: 設計(2026-08-25)。onoff_light_cpp には `CmdKind::LocalToggle`(ローカル操作 →
`stack.onoff_set(!get)` + LED 反映)のハンドラだけがあり、**送り手が居ない**。

- M5 NanoC6 の本体ボタン = **GPIO9(BOOT、active-low、内部プルアップ)**。
  Kconfig `SM_BUTTON_GPIO`(既定 9、-1 で無効。S3 等は既定 -1)を追加。
- 実装: GPIO 入力 + プルアップ、**ボタンタスク(小)で 20ms ポーリング + デバウンス
  (3 回連続 Low で押下確定、離すまで再発火しない)** → `Cmd{LocalToggle}` を
  `g_cmd_queue` へ post(ISR は使わない。BOOT ピンはストラップなので起動時の
  状態を読まないよう 1 秒待ってから監視開始)。
- 期待動作: 押すたびに LED が反転し、OnOff 属性が変わる(`sm_onoff_set` 経由なので
  購読者への変化レポート / Tab5 の次回 read に反映)。Tab5 側は既存の 10 秒 poll で
  バッジが追従する(即時性が欲しければ Subscribe だが v1 では poll)。
- ゲート: esp32c6 thread 構成の docker ビルド green(他構成も壊さない)。実機は
  親が焼いて、ユーザがボタンを押す → NanoC6 ログ `EVENT kind=1`(ONOFF_CHANGED)と
  Tab5 の `nodes` で onoff が反転することを確認。

### 15.1 実装記録(T7、2026-08-25)

変更ファイル(いずれも `ports/esp-idf/examples/onoff_light_cpp/`):

- `main/Kconfig.projbuild`: `SM_BUTTON_GPIO`(int、既定 9 / `IDF_TARGET_ESP32S3` は
  既定 -1、-1 で無効)を `SM_LED_GPIO` の直後に追加。
- `main/main.cpp`:
  - `#define SM_BUTTON_GPIO CONFIG_SM_BUTTON_GPIO`(未定義構成向けに `-1`
    フォールバック)を `SM_LED_GPIO` の隣に追加。
  - LED セクション直後に `button_task`(`#if SM_BUTTON_GPIO >= 0`)を追加。
    `gpio_config` で INPUT + `GPIO_PULLUP_ENABLE` + `GPIO_INTR_DISABLE` →
    `vTaskDelay(1000ms)`(BOOT ストラップ期間を回避)→ 20ms 周期ポーリング。
    3 回連続 Low で押下確定 → `Cmd c{}; c.kind = CmdKind::LocalToggle;`
    `xQueueSend(g_cmd_queue, &c, 0)`。3 回連続 High を見るまで `pressed` を
    落とさないので押しっぱなしでは再発火しない。ISR 不使用。
  - `app_main` 末尾で `xTaskCreate(&button_task, "button", 3 * 1024, nullptr, 2, nullptr)`
    (`#if SM_BUTTON_GPIO >= 0` のときのみ)。matter タスク(優先度 5)より低い。

既存の `CmdKind::LocalToggle` ハンドラ(`stack.onoff_set(!stack.onoff_get(), now)` +
`led_set`)をそのまま使うので、LED 反映・変化レポート経路は無改造。ネットワーク
(Thread / WiFi / BLE)側のコードには一切触れていない。

ゲート: esp32c6 + thread 構成の docker ビルド **green**
(`sdkconfig.defaults;sdkconfig.defaults.esp32c6;sdkconfig.defaults.thread;sdkconfig.local`、
bin 0x183360 バイト / app パーティション 39% free)。生成 sdkconfig に
`CONFIG_SM_BUTTON_GPIO=9` を確認。

実機確認手順(NanoC6): 焼いて起動 → ログに
`button task started (gpio=9, active-low)` が出るのを待つ(起動 +1 秒)→ 本体
ボタンを押す → `button pressed -> local toggle` と `EVENT kind=1`(ONOFF_CHANGED)、
LED 反転。Tab5 側は既存の 10 秒 poll でバッジが追従する。

## 16. T8: 属性 Subscribe による Tab5 表示の即時更新(NanoC6 OnOff → 将来 AirQ センサ)

Status: 設計(2026-08-26)。T7 §15 で「v1 では poll」と見送った Subscribe 化。
NanoC6 の本体ボタン/他コントローラからの操作が Tab5 のバッジに **1 秒以内**で反映される
ことが目標。**AirQ のセンサ 5 属性も同じ仕組みで購読する**ことを前提に、shim の購読を
「ノード複数 × パス複数」に一般化する。

### 16.1 現状と制約

- Tab5(`ctrl_pump.cpp` 定常ループ)は 10 秒周期でノードを **交互に 1 台** read(2 台なら
  鮮度 ≤20 秒)。IM Subscribe は未使用。
- shim [`sm_ctrl_subscribe`](../../crates/simple-matter-cffi/include/simple_matter.h) は
  **単一パス・購読 1 本**(`CtrlShim::sub_path: Option<(ep,cluster,attr)>`)。
  `SM_CTRL_EV_REPORT` は `node_id` を `nodes.first()` で埋める暫定実装(複数ノード不可)。
- コア `ImClient` は `MAX_CLIENT_SUBSCRIPTIONS = 4` 本の購読テーブルを持ち、
  `start_subscribe(ex, paths: &[AttributePath], ..)` で **1 購読に複数パス**を載せられる。
  レポートは `SubscriptionReport { subscription_id }` + `sub_reports()`(AttributeReportIB 列)、
  keep-alive 途絶(`last_report + max_interval + 猶予`)で `SubscriptionLost`。
- shim は単一トランザクション直列(`Activity`)。購読レポートは **Idle 中は
  `drain_subscription_reports`、op 進行中は `drive_awaitop` が `im_take_event` で取る**ので、
  op 中に届いた購読イベントを落とさない経路が要る。

### 16.2 shim の変更(`crates/simple-matter-cffi`)

**購読テーブル**(`sub_path` を置換):

```rust
const SUB_MAX_PATHS: usize = 8;                           // AirQ 5 属性 + 余裕
struct SubEntry { id: u32, node_id: u64, paths: heapless::Vec<(u16, u32, u32), SUB_MAX_PATHS> }
subs: heapless::Vec<SubEntry, MAX_CLIENT_SUBSCRIPTIONS>   // コアと同容量(4)
pending_sub_paths: heapless::Vec<(u16,u32,u32), SUB_MAX_PATHS>  // 進行中 Subscribe の引数(op_args と同格)
```

**C API**(既存 `sm_ctrl_subscribe` は 1 パスの薄いラッパとして残す):

```c
typedef struct { uint16_t endpoint; uint32_t cluster; uint32_t attribute; } sm_attr_path_t;
// 複数パスを 1 購読で張る。同一ノードの既存購読があれば **先に捨てる**(二重購読しない)。
// 戻り値: 0 / -1 未初期化 / -3 未知ノード / -4 CASE 失敗 / -10 busy / -11 パス数超過 /
//         -12 購読テーブル満杯。
int32_t sm_ctrl_subscribe_paths(uint64_t node_id, const sm_attr_path_t *paths, size_t n,
                                uint16_t min_interval_s, uint16_t max_interval_s, uint64_t now_ms);
// ノードの購読をローカルで破棄する(デバイスへは何も送らない。keep-alive 途絶で自然消滅)。
// 戻り値 = 破棄した本数。
int32_t sm_ctrl_unsubscribe(uint64_t node_id);
// ノードの購読が生きていれば true(UI の「subscribed」表示・poll 抑止の判定用)。
bool sm_ctrl_is_subscribed(uint64_t node_id);
```

**イベント**(`sm_ctrl_event_t` 末尾にフィールド追加 = ABI 変更。ヘッダと Rust `repr(C)` の
両方を更新し、Tab5/他 example を再ビルド):

```c
  // REPORT / SUBSCRIPTION_LOST の対象パス(REPORT のみ有効)。
  uint16_t endpoint; uint32_t cluster; uint32_t attribute;
```

- `SM_CTRL_EV_SUBSCRIBE_DONE`: `node_id`、`value_u64` = 購読 ID。**その前に**プライミング
  レポートに含まれる各属性を `SM_CTRL_EV_REPORT` として 1 属性 1 イベントで積む
  (初期値が READ と同じ経路で表示に入る)。
- `SM_CTRL_EV_REPORT`: `node_id` + `endpoint/cluster/attribute` + `value_u64/value_is_null`。
  デバイス発レポート 1 通に複数属性があれば **属性ごとに 1 イベント**。購読テーブルに
  無い属性(パス外)は捨てる。`phase` = 購読 ID 下位 8bit(従来通り、診断用)。
- `SM_CTRL_EV_SUBSCRIPTION_LOST = 17`(新設): `node_id`、`value_u64` = 購読 ID。
  テーブルから除去済み。C++ 側はここから poll フォールバック/再購読に入る。
- `EV_CAP` を 16 → 32(センサ 1 レポート = 5 イベント。ring 溢れで落とさない)。

**取り回し**:

- `SubscriptionReport` / `SubscriptionLost` の処理を `handle_sub_event(s, ev)` に一本化し、
  `drain_subscription_reports`(Idle)と `drive_awaitop` / `drive_connecting` 等の
  **全 `im_take_event` 経路**から呼ぶ(op 中に届いた購読イベントを `_ => {}` で捨てない)。
- 購読 ID → node_id はテーブルで引く(`nodes.first()` 撤廃)。
- `start_operation` が古いセッションを捨てて CASE を張り直すとき、そのノードの購読は
  旧セッションに残ったまま keep-alive 途絶で `SubscriptionLost` になる(コア任せ)。
  即時に整合させたければ `sm_ctrl_unsubscribe` を C++ が呼ぶ。
- `sm_ctrl_abort_op` で Subscribe 進行中を中断したら `pending_sub_paths` を捨てる。
- サイズ: `sm_ctrl_context_size` が増える(PSRAM 供給なので許容。値をログで確認)。

**テスト**(`controller.rs` の既存 loopback テスト流儀): (a) 2 パス購読 → priming で
REPORT×2 + DONE、デバイス側 `mark_dirty` 1 属性 → REPORT×1 に正しい path/node_id、
(b) 2 ノード分の購読を同時保持し、レポートが正しい node_id に振り分く、(c) keep-alive 途絶 →
SUBSCRIPTION_LOST + テーブル除去、(d) 購読中に別 op(read)を発行し、その最中に届いた
レポートが落ちない、(e) 既存 `sm_ctrl_subscribe` 回帰。

### 16.3 Tab5 の変更(`ports/esp-idf/examples/tab5_ctrl_app`)

- ノードごとに購読状態を持つ: `g_sub[slot] = {NONE, ACTIVE}` + `g_sub_retry_until[slot]`。
- **購読の張り方**(既存 10 秒 poll tick の中で行う。CASE 込みで数秒かかるので run_until 直列):
  - 種別 LIGHT: `sm_ctrl_subscribe_paths(node, {EP1/0x0006/0}, min=0, max=60)`。
  - 種別 SENSOR: `SENSOR_ATTRS` 5 本を 1 購読(min=1, max=60)。
  - `SUBSCRIBE_DONE` → ACTIVE、note "subscribed"。`SUBSCRIBE_FAILED` / rc<0 → 従来の
    2 分バックオフへ(`g_backoff_until`)。この間の表示更新は従来 read で賄う。
- **poll の役割変更**: ACTIVE のノードは周期 read しない(keep-alive はコア)。NONE の
  ノードだけ従来通り交互 read(+購読再試行)。
- **非同期イベントの受け皿** `consume_async_event(const sm_ctrl_event_t&)`: `REPORT` →
  path で `set_node_onoff` / `set_node_sensor`(f32 の 2 本は既存 `f32_from_value`)、
  `SUBSCRIPTION_LOST` → NONE + note "subscription lost"。定常ループの `pump_once` 直後に
  `while (sm_ctrl_take_event(&ev)) consume_async_event(ev);` を追加。**`run_until` と
  各 `do_*` の「stale イベント捨て」ループも REPORT/LOST を捨てずにここへ流す**
  (op 中のレポートを落とさない)。
- `run_until` の終端判定は kind ベースなので REPORT が混ざっても壊れないが、非終端
  イベントは `consume_async_event` に通す。
- `do_refresh_addr`(⟳)は `sm_ctrl_unsubscribe(node)` してから種別再検出(旧購読の残骸を
  切る)。`do_toggle` 後の追加 read は不要になる(レポートで返る)が、現状維持で可。
- UI: `sm_ui_node_t` に `uint8_t subscribed` を足し、行に小さな "●sub" 表示(任意)。
  鮮度表示(`updated N s ago`)は REPORT でも更新する。

### 16.4 デバイス側の確認事項

- NanoC6(onoff_light_cpp): `MatterStack` の SUBS 容量 ≥ 1、`sm_onoff_set` → dirty →
  レポート送出は T7 で成立済み。Tab5 が再起動を繰り返すと旧購読がデバイス側に残る
  (`SUBS` 枯渇で SubscribeResponse が失敗しうる)ので、デバイスの購読 max_interval 超過
  回収が働くことを `pools:` ログで確認する。
- AirQ(Rust ポート): センサ更新時に該当属性を dirty にしているか(していなければ
  レポートは max_interval ごと=60 秒になる)。未対応なら **本タスクでは「購読は張るが
  鮮度は max_interval」**として動かし、AirQ 側の dirty 化は別タスクにする。

### 16.5 ゲート

1. `cargo test -p simple-matter-cffi`(新テスト 5 本含む)+ workspace 全緑、`cargo clippy` 警告なし。
2. docker ビルド: tab5_ctrl_app(P4)、onoff_light_cpp(C6)が green。ヘッダ変更で
   他 example(thread_ctrl_hub_cpp 等)が壊れないこと。
3. 実機: NanoC6 ボタン押下 → Tab5 バッジ反転が **1 秒以内**。Tab5 の `nodes` に
   "subscribed"。NanoC6 `pools:` で ex/hs が安定、購読数が 1 で頭打ち(Tab5 再起動 3 回)。
   AirQ は購読確立と 60 秒以内の値更新を確認(dirty 対応済みなら即時)。

### 16.6 T8b: 購読の堅牢化(NanoC6 の購読が長時間後に切れて見える件、2026-08-26)

**症状**: 長時間稼働後、NanoC6 ボタン操作が Tab5 に 10 秒以上反映されない。Tab5 からの Toggle は効き、
その後は購読レポートも再び届く。観測(8.5h 稼働中の 3 分間)では keep-alive レポートは 60 秒ちょうどで
到達しており常時再現ではない = 間欠。デバイス側ログは未取得(シリアルが別プロセス占有)。

**コードから特定した、購読が「凍る/幽霊化する」経路**(いずれも根本原因候補。全部塞ぐ):

| # | 経路 | 影響 |
|---|---|---|
| P1 | デバイス: 単一チャンクレポート送出後 `report_exchange` を **StatusResponse 受信でしか解除しない**。MRP ACK だけ届いて StatusResponse が来ない(相手側で exchange 消滅後の重複、パケットロスの組合せ)と **購読が永久に due しない**(dirty も max_interval も止まる)+ initiator exchange が 1 本永久リーク(EXCHANGES=4) | 押しても届かない・keep-alive も止まる → Tab5 は 65 秒後 LOST → 再購読。凍った購読は SUBS(3)を食い続ける |
| P2 | デバイス: 単一チャンクレポートへの **StatusResponse が失敗ステータス(InvalidSubscription 等)でも購読を破棄しない**(`on_status` の reads 不在分岐はステータス不問で `report_exchange` 解除のみ) | Tab5 が LOST/再購読した後の旧購読が幽霊化し、60 秒ごとに無駄レポート + SUBS 枯渇 → 4 本目以降の Subscribe が失敗 |
| P3 | クライアント: `SUBSCRIPTION_GRACE_MS = 5 s`。MRP は最大 10 送信(累計 ~34 秒)まで再送するため、レポート 1 通の再送が数秒続くだけで **誤 LOST** → 再購読 → P2 の幽霊を量産 | 再購読の churn |
| P4 | shim: `sm_ctrl_unsubscribe` / 同一ノード再購読時の旧エントリ破棄が **shim のテーブルだけ**で、コア `ImClient::subs` には残る → 旧購読のレポートに Success を返し続け、デバイスの旧購読が生き残る(P2 と合わせて幽霊化)。コア側テーブル(4)も詰まる | ⟳ や再購読のたびにリーク |
| P5 | Tab5: LOST 後の再購読が次の 10 秒 tick 任せ | 復旧が最大 10 秒遅れる |

**対処**:

- **コア engine(デバイス側)**
  - `Subscription` に `report_sent_ms: u64` を追加。`build_report` 成功時に記録。
  - `InteractionModel::expire_stale_reports(now_ms) -> Option<ExchangeId>`(新設): `report_exchange` が
    `REPORT_INFLIGHT_TIMEOUT_MS = 40_000`(MRP give-up 上限 ~34 s + 余裕)を超えて残っている購読を
    **1 件ずつ破棄**(`on_report_failed` 相当)し、その exchange を返す。統合層 `MatterStack::drive_ticks`
    が `while let Some(ex)` で回して `mgr.close(ex)` + `tx_pool.release` する(P1)。
  - `on_status`: reads 不在分岐でも `!sr.status.is_success()` なら該当購読を `on_report_failed`(P2)。
  - `next_deadline` に in-flight 期限も含める(凍った購読を寝たまま放置しない)。
- **コア client(コントローラ側)**
  - `SUBSCRIPTION_GRACE_MS` を 5 s → **30 s**(P3)。
  - `ImClient::remove_subscription(id) -> bool` / `remove_subscriptions_on_session(session)` を追加。
    `ControllerStack` に `im_remove_subscription` を経由(P4)。
- **shim**: `sm_ctrl_unsubscribe` と `sm_ctrl_subscribe_paths` の旧エントリ破棄で、コア client 側も
  `remove_subscription`(P4)。以降、旧購読のレポートには `InvalidSubscription` が返り、デバイスは P2 の
  修正で購読を捨てる = 双方が自然に整合する。
- **診断**: `sm_pool_stats_t` 末尾に `subs / subs_cap / reads / reads_cap`(u16×4)を追加(デバイス側
  `MatterStack::pool_usage` に `subscriptions` を追加)。onoff_light_cpp の `pools:` ログに `sub=%u/%u`。
  コントローラ側にも `sm_ctrl_pool_stats`(既存があれば `subs` 追加)。
- **Tab5**: `SUBSCRIPTION_LOST` を受けたら **その場で再購読キューに積み、次ループで即再購読**(tick を
  待たない。失敗時は従来の 2 分退避)(P5)。`nodes` 出力にコアの購読数も出す。

**テスト**(コア): (1) 単一チャンクレポート送出後 StatusResponse を届けず 40 s 経過 → 購読破棄 + exchange
回収(pool_usage で exchange 0)。(2) InvalidSubscription の StatusResponse → 購読破棄。(3) client:
`remove_subscription` 後に届いたレポートへ InvalidSubscription を返す。(4) client: レポートが max+29 s
遅れても LOST にならず、max+31 s で LOST。既存テストの期待値(5 s 前提)は更新。

**ゲート**: cargo 全緑 → docker C6(onoff_light_cpp)/ P4(Tab5)→ 実機で NanoC6 `pools:` の `sub=` が
1 で安定(Tab5 の ⟳ / 再起動を数回挟んでも増えない)、ボタン→Tab5 反映を長時間(数時間)観測。

**追記(P6、2026-08-26 実機で確定)**: shim は op の IM タイムアウト / `sm_ctrl_abort_op` / `SubscriptionLost` の
いずれでも **ノードの live セッションを無効化していなかった**。デバイスが再起動すると、shim は死んだ CASE
セッションで暗号化パケットを送り続け(デバイスは未知セッションとして黙殺)、Tab5 を再起動するまで全 op が
タイムアウトし続ける(今朝の「AirQ unreachable」の正体)。修正: 3 経路で `invalidate_session(node)`(次の op は
CASE(resumption 可)を張り直す)。回帰テスト `tests/session_invalidation.rs`(仮想時計ハーネス、3 シナリオ)。
実機: AirQ リセット → Tab5 が LOST → 2 分後の再試行で Tab5 無再起動のまま再購読成功(購読 ID=1 = 幽霊なし)。

**追記(P7: 購読 ID の衝突、2026-08-26 夜、8 時間ログで確定)**: 購読 ID はデバイスごとの採番なので、別デバイス間で
同じ値になる(NanoC6 の幽霊購読 ID=2 と AirQ の再購読 ID=2)。ところが `ImClient::on_device_report` /
`ClientSub` 照合、shim の `sub_index_by_id` は **ID だけ**で照合しており、NanoC6 の幽霊レポートが AirQ の購読として
受理(Success 応答 + AirQ の `last_report_ms` 更新)されていた。結果: (1) デバイスの幽霊購読が P2 で破棄されず
残り続ける(`sub=2/3` が 5 時間)、(2) 死んだノードの keep-alive が別ノードのレポートで偽装され LOST 検出が
効かない、(3) パスが重なれば値の誤配。
修正: `ClientSub` の `session` を照合に使う(`(session, id)` で一意。`RxMessage` の exchange から session を取る)。
`ImEvent::SubscriptionReport / SubscriptionLost / SubscribeDone` に `session: SessionId` を載せ、shim の `SubEntry`
にも `session` を持たせて `(session, id)` で引く。`remove_subscription(session, id)` に変更。
回帰テスト: 2 セッション上で同じ購読 ID を確立し、片方のレポートがもう片方に混ざらない(未知扱いで
InvalidSubscription)こと、shim でも node_id が正しく振り分くこと。

**追記(Tab5 pump の停止、要計測)**: 8 時間ログで 15:25:28→15:28:39 の **191 秒間 pump が無反応**(AirQ の 10 秒
レポートが途絶、UI op なし)。これが両ノード LOST(→ 再購読、幽霊化)の直接の引き金で、ユーザー症状
(ボタンが 10 秒以上反映されない → Toggle で戻る)に一致。原因未特定(候補: `sm_ot_hub_get_status` の OT ロック、
`esp_wifi_remote`(SDIO)呼び出し、`sm_app_lock` を UI 側が長時間保持)。対処: 定常ループの各ステップ
(take_op / pump_once / refresh_thread_status / refresh_wifi_status / rebuild_node_list / poll tick / resub)の所要時間を
計測し、**1 秒超で `pump: slow step=<name> ms=<n>` を WARN ログ**。次の停止で犯人を特定する。

## 17. T9: Tab5 からコミッショニングウィンドウを開く(マルチコントローラ化)

Status: 設計(2026-08-26)。目的: Tab5 が管理するデバイス(NanoC6 / AirQ 等)に、**別のコントローラ**
(chip-tool / smctl / スマホアプリ)を追加コミッションできるようにする。Matter の標準手順 =
AdministratorCommissioning(EP0 / 0x003C)の **OpenCommissioningWindow(ECM、timed invoke)** を既存 fabric の
管理者(Tab5)が発行し、生成した passcode / discriminator を **manual pairing code(11 桁)と QR(`MT:` payload)**
で 2 人目に渡す。

### 17.1 既存部品

- コア: デバイス側 AdministratorCommissioning クラスタ(ECW/BC/Revoke、`dm/clusters/administrator_commissioning.rs`)、
  `crypto::spake2p::compute_verifier(passcode, salt, iterations)`、`ControllerStack::start_invoke_timed`。
- smctl: `admincommissioning open-window`(`ops.rs::admin_open_window`)= verifier 生成 → timed invoke →
  `manual_pairing_code`(`ops.rs:1760`、chip-tool 一致テスト付き)。**QR payload は未実装**。
- shim: `sm_ctrl_invoke_args`(引数 4 個まで、`sm_attr_bytes.len` は u8 なので 97 B verifier は載る)だが
  **timed invoke が無い**。
- Tab5: LVGL `lv_qrcode`(`CONFIG_LV_USE_QRCODE=y`、Network タブで使用中)、pair ダイアログの作法、
  console_dbg(`toggle`/`read`…)、`tab5ctl.py`。
- デバイス: AirQ は chip-tool で OCW→2 fabric 目を実証済み(airq-port.md §7.4.3)。NanoC6(cffi デバイス)は
  fabric 容量 `NF` と AdministratorCommissioning の組み込みを **要確認**(§17.5)。

### 17.2 コア(`crates/simple-matter`、no_std)

新モジュール `discovery::onboarding`(smctl から移設・拡張):
```rust
pub fn manual_pairing_code(discriminator: u16, passcode: u32) -> [u8; 11];   // 11 桁 ASCII(chip-tool 一致)
pub fn passcode_is_valid(p: u32) -> bool;                                    // 仕様の禁止値
pub fn random_passcode<R: Rng>(rng: &mut R) -> Result<u32>;
/// QR payload(仕様 §5.1.3、"MT:" + base38)。VID/PID/discriminator(12bit)/passcode/
/// discovery caps(bit0 SoftAP, bit1 BLE, bit2 on-network)/ commissioning flow=0。
pub fn qr_payload(p: &OnboardingPayload, out: &mut [u8]) -> Result<usize>;   // "MT:" 含めて ≤ 32 B
pub struct OnboardingPayload { pub vendor_id: u16, pub product_id: u16, pub discriminator: u16,
                               pub passcode: u32, pub discovery_caps: u8 }
```
テストベクタ: chip-tool `payload generate-qrcode` 既知値(例: VID 0xFFF1 PID 0x8000 disc 3840 passcode 20202021
→ `MT:Y.K9042C00KA0648G00`)+ manual code の既存ベクタ移設。

`ControllerStack` に OCW 専用ヘルパ(smctl / shim 共用):
```rust
pub struct OpenWindowParams { pub timeout_s: u16, pub discriminator: u16, pub passcode: u32,
                              pub salt: [u8; 16], pub iterations: u32 /* 1000 */ }
pub fn start_open_commissioning_window(&mut self, session, p: &OpenWindowParams, now_ms, tx) -> Result<SendDirective>;
pub fn start_revoke_commissioning(&mut self, session, now_ms, tx) -> Result<SendDirective>;
```
中身 = `compute_verifier` → InvokeRequest(EP0/0x003C/0x00、fields 0..4)を `start_invoke_timed` で。Revoke は
0x02 を timed invoke。完了は従来の `ImEvent::InvokeDone { status }`(クラスタ固有ステータス Busy=2 /
PAKEParameterError=3 / WindowNotOpen=4 は `status` に載る)。smctl の `admin_open_window` はこれらを呼ぶ形に置換
(出力は不変、QR 文字列を追加表示)。

### 17.3 shim(`crates/simple-matter-cffi`)

```c
typedef struct {
  uint64_t node_id; uint16_t timeout_s; uint16_t discriminator; uint32_t passcode;
  uint16_t vendor_id; uint16_t product_id;      // QR 用(取得できなければ 0)
  char manual_code[12];                          // 11 桁 + NUL
  char qr_payload[32];                           // "MT:..." + NUL
  uint64_t opened_at_ms;                         // 0 = 未オープン
} sm_ctrl_window_t;

// ECM 窓を開く。passcode=0 なら乱数生成、discriminator=0xFFFF なら乱数(12bit)。timeout 180..900。
// 内部で (1) EP0 BasicInformation VendorID(0x0002)/ProductID(0x0004) を read(失敗しても続行、QR は VID/PID=0)、
// (2) OpenCommissioningWindow を timed invoke。完了は SM_CTRL_EV_WINDOW_OPENED(value_u64=passcode、
// endpoint=discriminator、attribute=timeout_s)/ SM_CTRL_EV_WINDOW_FAILED(status=クラスタステータス or IM ステータス、
// phase=失敗段階 1=VID read 2=PID read 3=invoke)。戻り値は他の op と同じ(-10 busy 等)。
int32_t sm_ctrl_open_commissioning_window(uint64_t node_id, uint16_t timeout_s, uint16_t discriminator,
                                          uint32_t passcode, uint64_t now_ms);
// 直近に開いた窓の情報(manual code / QR 文字列込み)。未オープンなら false。
bool sm_ctrl_last_window(sm_ctrl_window_t *out);
// RevokeCommissioning(timed invoke)。完了は INVOKE_DONE / INVOKE_FAILED(node_id で識別)。
int32_t sm_ctrl_revoke_commissioning(uint64_t node_id, uint64_t now_ms);
```
- 実装: `PendingOp::OpenWindow { step, params }` の 3 段階(read VID → read PID → timed invoke)を `drive_awaitop`
  で直列に進める(既存の単一トランザクション直列の枠内。各段階で `issue_op` を再発行)。RNG は shim の `CRng`。
- `SM_CTRL_EV_WINDOW_OPENED = 18` / `SM_CTRL_EV_WINDOW_FAILED = 19`。
- WindowStatus の確認は既存 `sm_ctrl_read_scalar(node, 0, 0x003C, 0x0000)` で(0=閉 1=ECM 2=BC)。

### 17.4 Tab5(`tab5_ctrl_app`)

- Devices タブ各行に **「Share」ボタン**(幅 110。名前列 480→370 で捻出。合計 ≤1280 を維持)。
- `SM_UI_OP_OPEN_WINDOW`(timeout 既定 300 s、discriminator 乱数、passcode 乱数)/ `SM_UI_OP_REVOKE_WINDOW` を追加。
  pump: `sm_ctrl_open_commissioning_window` → `run_until(term_window)`(30 s)→ 成功なら `sm_ctrl_last_window` を
  スナップショット `window` 欄(`sm_ui_window_t`: node_id / passcode / discriminator / manual_code / qr / expires_ms /
  status)へ、失敗は note "open window failed (status N)"。
- **Share ダイアログ**(pair ダイアログと同作法): 見出し「Share <node> with another controller」、manual pairing
  code(montserrat 48、`XXXX-XXX-XXXX` 区切り)、passcode / discriminator(小)、QR(`lv_qrcode`、220px)、残り時間
  「closes in N s」(snapshot の now_ms から計算)、ボタン **Revoke**(→ `SM_UI_OP_REVOKE_WINDOW`)と **Close**。
  ダイアログ表示中は pump が 10 秒ごとに WindowStatus を read(既存 poll tick 内、対象ノードのみ)し、閉じたら
  `status=closed` にして「window closed」表示。Revoke 完了/期限切れで自動的に closed。
- 行の note に "window open (N s)" を出す。`nodes` 出力に `window=` を追加。
- console: `openwindow <node_hex> [timeout_s] [disc]` / `revoke <node_hex>` / `window`(直近の窓を表示)を追加
  (tab5ctl で自走検証できるように)。

### 17.5 デバイス側の確認・調整

- cffi デバイス(onoff_light_cpp / NanoC6): `NF`(fabric 容量)≥ 2、AdministratorCommissioning が EP0 に組み込まれ、
  ECW open → PASE(動的 verifier)→ AddNOC で 2 fabric 目が入ること。不足なら NF を 2 以上に(KVS 容量も確認)。
- AirQ(Rust)は chip-tool で実証済み。

### 17.6 テスト・ゲート

- コア: onboarding のベクタテスト(manual code 既存 + QR 新規)、`start_open_commissioning_window` の
  InvokeRequest エンコード(fields 0..4、timed)テスト。
- **ctrl↔dev ループバック E2E**(`stack/tests.rs`): コントローラ A がコミッション → A が OCW(生成 passcode)→
  デバイス WindowStatus=1 → **コントローラ B(2 つ目の `ControllerStack`)が PASE(その passcode)→ AddNOC で
  2 fabric 目** → B から OnOff read 成功、A からも引き続き操作可 → A が Revoke → WindowStatus=0。
- shim: `composed_e2e` に open window → `sm_ctrl_last_window` の manual/QR が妥当 → WindowStatus read=1 → revoke → 0。
- 実機: Tab5 の Share → 表示された manual code で **PC の smctl(別 state-dir)`pairing code`/onnetwork-long** で
  NanoC6・AirQ に 2 fabric 目 → smctl から toggle/read、Tab5 からも引き続き購読・操作できる。tab5ctl で
  `openwindow` → `window` → screenshot(QR 表示)。

## 18. T11: 外部 OTBR の Thread ネットワークへの参加(マルチ admin)

Status: 設計(2026-10-02、コード未変更)。目的: Tab5 が **自前で Thread ネットワークを主宰する**(現状)代わりに、
**既存の OTBR(ESP-IDF ot_br / NanoC6、WiFi "matter-test"、ch 11 / PAN 0xf592、OMR `fd5a:3d14:1acf:1::/64`)の
ネットワークへ 1 ノードとして参加**し、PC(smweb/smctl、node 34)が既にコミッション済みの NanoC6 OnOff light
(`[fd5a:3d14:1acf:1:e635:75ac:d22f:a3e0]:5540`)を **2 人目の admin(Tab5 自身の fabric / CA)** として操作する。
(T10 は「カメラ QR」= docs/design/tab5-camera-qr.md。)

### 18.1 ゴール / 非ゴール

- ゴール: (1) 「主宰(leader + SRP サーバ)」と「参加(dataset 供給、SRP サーバ無し)」の切替、(2) 参加モードでの
  Thread ノードのアドレス解決、(3) Tab5 から 2 fabric 目を入れる手順の確立、(4) PC(smweb)側の登録と AirQ 等
  WiFi デバイスの現行動作を壊さない。
- 非ゴール: Tab5 自身の border router 化(F8e)、OTBR 側 FW の変更、`_matterc._udp` の DNS-SD 発見による
  「アドレス入力なし」ペアリング(18.5 の D2 として任意)、主宰モード時代のノード帳の自動移行。

### 18.2 調査結果

**(1) Tab5 側(`ports/esp-idf/examples/tab5_ctrl_app/main`)**

- ネットワーク形成は `sm_ot_hub_form_network`(ot_hub.cpp:171-221)。優先順は **NVS の active dataset**
  (:176-178)→ Kconfig `SM_THREAD_DATASET_TLV_HEX`(:181-188)→ 新規生成(:190-200)。つまり **既に NVS に
  自前 dataset がある実機では Kconfig を設定しても無視される**。SRP サーバは無条件で有効化(:216)。参加モードで
  これを残すと Tab5 が netdata に 2 つ目の SRP サーバを publish し、デバイスの登録先が割れる。
- 起動は pump タスクから(ctrl_pump.cpp:2201-2223)。`sm_ot_hub_wait_leader`(ot_hub.cpp:231-248)は
  leader/router だけを成功扱いにするので、child で参加した場合 30 秒待って警告になる(動作は継続)。
- SRP 逆引き `sm_ot_hub_srp_lookup`(ot_hub.cpp:254-292)は **自分の SRP サーバ帳**を node_id の 16 hex 部分一致で
  走査する。呼び出しは ctrl_pump.cpp の 2 箇所だけ: `do_refresh_addr`(:1347、失敗時は WiFi mDNS へ
  フォールバック :1351-1364)と ble-thread の handoff 待ち(:2089-2106)。app_state / node_book / console_dbg は
  ot_hub を直接呼ばない(console の `refresh` は op 経由、console_dbg.cpp:163,675)。
  `sm_ot_hub_get_status` は SRP サーバの状態/ホスト数を読む(ot_hub.cpp:329-333、表示用)。
- UDP ソケットは **netif 非束縛の AF_INET6 1 本**(dual-stack、ctrl_pump.cpp:330-347)。宛先 netif は lwIP の経路
  選択に任せ、scope_id を付けるのは fe80 宛だけ(:355-365、fe80 は WiFi 優先)。ULA/GUA は scope 0
  (:1408-1410)。lwIP `ip6_route` は「宛先 /64 が netif の(static な)アドレスと一致」→ RA 由来の経路 →
  既定 netif の順(IDF 5.4 `lwip/src/core/ipv6/ip6.c`)。主宰モードで ML-EID 宛が OT netif に出ているのは前者。
- ペアリング: `pair`(`do_pair`、:1388-1456)は **与えたアドレスへ直接 PASE**(発見なし、via は fe80 の scope
  選択にしか使わない)。`pairble`(`do_pair_ble`、:1937-2194)は BLE → 資格情報投入で、thread 種別では
  **Tab5 の active dataset をそのまま渡し**(:1959-1961)、handoff は SRP サーバ帳待ち(:2089)。WiFi 種別は
  mDNS(マルチキャスト + /24 ユニキャスト掃引、:1662-1750)。
- sdkconfig: `CONFIG_OPENTHREAD_DNS_CLIENT=y`、`SRP_CLIENT` 無効、`BORDER_ROUTER` 無効(sdkconfig:2385-2389)。
  SRP サーバは custom header で有効化(esp_ot_custom_config.h)。`CONFIG_LWIP_IPV6_ND6_ROUTE_INFO_OPTION_SUPPORT`
  は **未設定**(sdkconfig:2075)、`LWIP_HOOK_IP6_ROUTE_NONE`(:2121)。WiFi は sdkconfig.local の `SM_WIFI_SSID`。

**(2) デバイス側(`onoff_light_cpp` + `crates/simple-matter-cffi`)— マルチ admin の要**

- ECW を開くと shim は PASE を有効化し、mDNS の commissionable 広告と `commissionable_disc` を更新して
  `SM_EV_WINDOW_CHANGED` を立てる(lib.rs:1593-1603)。続く `sync_ble_adv` が広告バイト列の差分で
  `SM_EV_BLE_ADV_CHANGED` を立て(lib.rs:1674-1691)、main.cpp:807-812 が `sm_ble_set_adv` で **BLE 広告を再開**
  する(ble.cpp:260-273、`CONFIG_SM_ENABLE_BLE` 時)。discriminator は ECM で指定された値になる。
- 一方 Thread ビルドは **mDNS ソケットを開かない**(main.cpp:886-890)ので shim の commissionable 広告はどこにも
  出ない。`SM_EV_WINDOW_CHANGED` は main.cpp で **未処理**(:800-846 の switch に無い)で、SRP に `_matterc._udp`
  を登録するコードも無い。結論: **コミッション済み Thread デバイスの窓は「BLE 広告」か「アドレス既知の UDP 直接
  PASE(:5540)」でしか到達できない。DNS-SD では発見できない。**
- 運用広告: `SM_EV_COMMISSIONED`(fabric 増加ごとに発火、lib.rs:1539-1541)→ `maybe_register_srp`
  (main.cpp:712-722、838-841)→ `sm_ot_srp_register`。しかし ot_thread.cpp:129-131 が `g_srp_registered` で
  **2 回目以降を即 return**(「単一 fabric・単一登録」)、サービス枠も 1 個(:38-39)、shim の
  `sm_operational_instance_name` も **先頭 fabric しか返さない**(lib.rs:2790-2802)。結論: **2 つ目の AddNOC は
  通る(NF=5、lib.rs:268)が、2 fabric 目の `_matter._tcp` インスタンスは SRP に登録されない。** Tab5 の fabric 名
  では OTBR の DNS-SD にも advertising proxy(mDNS)にも現れない。`SM_EV_FABRIC_REMOVED` 時の登録解除も無い。
- 影響: Tab5 はペアリング時のアドレスをノード帳に持つので **当面は動く**(OMR prefix が変わるまで)。再解決
  (`refresh`)は不可。Apple/Google 等の標準コントローラを 2 人目にする場合は運用発見が必須なので致命的。

**(3) 外部ネットワークでの解決手段**

| 案 | 可否 | 根拠 / 条件 |
|---|---|---|
| (a) OT DNS client で OTBR の DNS-SD サーバへ `otDnsClientResolveService` | **可(推奨)** | `OPENTHREAD_DNS_CLIENT=y` 済み、`DNS_CLIENT_SERVICE_DISCOVERY_ENABLE` は OT 既定 1。OTBR 側は BORDER_ROUTER で `DNSSD_SERVER_ENABLE=1`(IDF ftd-config.h:556-562)。ただしサーバアドレス自動設定は SRP client 前提(`DEFAULT_SERVER_ADDRESS_AUTO_SET` = SRP_CLIENT 有効時のみ)なので、**netdata の SRP/DNS サービス(service number 0x5d)から OTBR アドレスを自分で引いて** `otDnsQueryConfig` に入れる。Thread 内ユニキャストだけで完結 |
| (b) WiFi 側 mDNS(OTBR advertising proxy) | 条件付き | 既存 `resolve_via_mdns` が使えるが、esp_hosted はマルチキャスト受信不可(JOURNAL:162-164)で /24 掃引頼み。OTBR の mDNS がユニキャスト QU に応答するか未確認。フォールバックとして現状のまま残す(追加実装なし) |
| (c) WiFi → OTBR 経由でルーティング(Thread 無線を使わない) | 可(予備) | OTBR は OMR を RA の RIO で広告する。lwIP は RIO 対応コードを持つ(nd6.c `ND6_OPTION_TYPE_ROUTE_INFO`、`LWIP_ND6_SUPPORT_RIO`)が Tab5 は Kconfig 無効。`CONFIG_LWIP_IPV6_ND6_ROUTE_INFO_OPTION_SUPPORT=y` で有効化可。RA は ff02::1(既定グループ)なので受信見込みあり。H2 RCP 不調時の迂回路・切り分け用 |

(a)(b) とも **デバイスが Tab5 fabric のインスタンスを SRP 登録していること**が前提(18.2 (2))。

### 18.3 推奨アーキテクチャ

1. **モード切替**: Kconfig `SM_THREAD_MODE`(choice: `FORM` = 既定・現状 / `JOIN`)+ NVS 上書き(namespace
   "smui"、key "otmode" と "otjoin_ds"。console `otmode form|join [dataset_hex]` で書いて再起動)。優先は NVS →
   Kconfig。JOIN では:
   - dataset は「NVS "otjoin_ds" → Kconfig `SM_THREAD_DATASET_TLV_HEX`」。OT の active dataset と **異なれば
     `otDatasetSetActiveTlvs` で上書き**(ot_hub.cpp:176-178 の「NVS 優先」を JOIN では逆転)。上書き前に自前
     dataset を NVS "otform_ds" へ退避し、FORM に戻すとき復元する。JOIN で dataset が空なら Thread を起動せず
     status に明示(勝手に新規ネットワークを作らない)。
   - `otSrpServerSetEnabled` を **呼ばない**。待ちは `wait_leader` ではなく attach(child 以上)で成立。
   - dataset hex(network key を含む)は docs / コミットに書かない。sdkconfig.local(git 管理外)か console で投入。
2. **ノード解決(JOIN)**: 順に ①OT DNS client(案 a)→ ②既存 WiFi mDNS(案 b、現行コードのまま)→
   ③ノード帳の保存アドレスを維持。`sm_ot_hub_resolve(node_id, instance_label, out_ip, timeout_ms)` を新設し、FORM は
   従来の SRP サーバ帳、JOIN は `otDnsClientResolveService("<cfid>-<node>", "_matter._tcp.default.service.arpa.")`
   を同期ラップ(コールバック → セマフォ)。instance ラベルは `feed_addr_as_mdns` と同じく `sm_ctrl_resolve_start` の
   QNAME 先頭ラベルから借りる(ctrl_pump.cpp:1752-1760。shim 変更不要)。
3. **経路**: Tab5 は OT netif に OMR アドレス(OT の SLAAC、`IP6_SLAAC_ENABLE=1`)を持つので、OMR 宛は scope 0 の
   まま OT netif に出る想定。WiFi デバイス(AirQ = IPv4 運用)は無変更。保険として案 (c) の RIO を有効化しておく。
4. **2 人目 admin の手順(Tab5 が後から入る。デバイス変更なしで成立する最短経路)**:
   1. PC(smweb の Share、または `smctl admincommissioning open-window`)で node 34 に ECW を開き、
      **passcode(数値)** を控える(Tab5 の `pair` は passcode を取る。manual code の復号は Tab5 に無い)。
   2. Tab5: `pair fd5a:3d14:1acf:1:e635:75ac:d22f:a3e0 <tab5_node_hex> thread <passcode>` — アドレス直指定の
      on-network PASE → AddTrustedRoot/AddNOC(2 fabric 目)→ 同アドレスで CASE → CommissioningComplete。
      ネットワーク資格情報は触らない(デバイスは OTBR 網に居るまま)。UI の Pair ダイアログ(via=Thread)でも同じ。
   3. Tab5: `nodes` / `toggle` / 購読で確認。PC 側 node 34 が引き続き操作できることを確認。
   - BLE 経路(`pairble <ECM disc> <node> thread <passcode>`)も原理上可能(BLE 広告は再開する)。ただし
     Tab5 が dataset を再投入するため「同一 dataset の AddOrUpdate/ConnectNetwork を attach 済みデバイスが正しく
     捌くか」が未検証で、handoff が SRP サーバ帳待ち(:2089)なので P2 の修正後に限る。**第一経路にはしない。**
   - 逆向き(Tab5 が Share → PC が入る)は T9 のまま動く(PC は OTBR 経由でアドレス到達可能)。

### 18.4 デバイス側の必須/任意変更(`onoff_light_cpp`、cffi)

- **D1(必須・堅牢化)マルチ fabric SRP 登録**: shim に
  `size_t sm_operational_instance_name_at(uint8_t index, uint8_t *buf, size_t cap)`(fabric 反復の index 番目、
  無ければ 0。既存 API は index 0 の薄いラッパに)を追加。ot_thread.cpp は `g_srp_registered` を廃し、
  **NF(5) 個の静的サービス枠**(instance 文字列 + `otSrpClientService`)を持つ `sm_ot_srp_sync(names[], n)` に置換:
  未登録の名前は `otSrpClientAddService`、消えた名前は `otSrpClientRemoveService`。main.cpp は
  `SM_EV_COMMISSIONED` / `SM_EV_FABRIC_REMOVED` / ThreadRole(attach) で全 fabric 名を集めて sync を呼ぶ。
  OT が保持するポインタは静的領域のまま(定常ヒープレス方針に合致)。`CONFIG_OPENTHREAD_SRP_CLIENT_MAX_SERVICES`
  (既定 5)が NF 以上であることを確認。
- **D2(任意)`_matterc._udp` の SRP 登録**: `SM_EV_WINDOW_CHANGED` で開閉に合わせ commissionable サービス
  (サブタイプ `_L<disc>` / `_S<disc>` / `_CM`、TXT D/CM/VP)を登録/削除。shim から TXT 素材を出す API が要るため
  別ユニット。スマホ系コントローラの on-network 追加に必要、Tab5 の T10 ゴールには不要。

### 18.5 実装ピース(各 1 エージェント)

- **P1 ot_hub モード切替**: Kconfig choice、NVS キー、`sm_ot_hub_start_network()`(form/join 分岐、dataset 上書き・
  退避、SRP サーバ条件化)、`sm_ot_hub_wait_attached`、`sm_ot_status_t` に `mode` 追加と Network タブ/ステータスバー
  表示("JOIN child ch11 f592")、console `otmode`。sdkconfig.local に `SM_WIFI_SSID="matter-test"` と dataset。
  set-target 再ビルド時は `SDKCONFIG_DEFAULTS` に sdkconfig.local を含める(既知の罠)。
- **P2 解決の抽象化**: `sm_ot_hub_resolve`(FORM = SRP 帳 / JOIN = DNS client、netdata から DNS サーバ発見)、
  ctrl_pump.cpp:1347 と :2090 を差し替え、JOIN 時の `do_refresh_addr` は DNS → mDNS → 「保存アドレス維持」の順。
  `sm_ot_hub_dump_srp` は JOIN で netdata のサービス一覧ダンプに。
- **P3 経路の保険**: `CONFIG_LWIP_IPV6_ND6_ROUTE_INFO_OPTION_SUPPORT=y`、console `route <ipv6>`(`ip6_route` が選ぶ
  netif と OT/WiFi の保有アドレスを表示)で切り分け可能にする。
- **P4 デバイス D1**: shim API + テスト(2 fabric で index 0/1 が別名、範囲外 0)、ot_thread.cpp / main.cpp の sync 化。
  Rust 変更後は `target/<triple>/release/libsimple_matter_cffi.a` を消してから docker ビルド。
- **P5(任意)D2**。P1 → 実機ゲート A → P2/P3 → P4 → ゲート B の順。P1 だけで 18.3-4 の手順は実行できる。

### 18.6 実機検証(OTBR + NanoC6 light node 34 + Tab5 `/dev/ttyACM4`)

- **ゲート A(P1)**: Tab5 を JOIN で起動 → `status` が role=child/router、ch 11、PAN f592、SRP サーバ無効。
  OTBR 側 `netdata show` で SRP サーバが 1 つのまま。Tab5 に OMR(`fd5a:3d14:1acf:1::/64`)アドレスが付く。
  WiFi "matter-test" 接続、AirQ の既存操作が回帰しない。PC で ECW → Tab5 `pair <addr> <node> thread <passcode>` が
  PAIR COMPLETE → Tab5 から toggle/購読、smweb からも toggle 可(双方向で 10 往復)。デバイス `fabrics=2`。
- **ゲート B(P2+P4)**: デバイス更新後、OTBR `srp server service` に 2 インスタンス(PC fabric / Tab5 fabric)。
  Tab5 `refresh <node>` が "DNS -> fd5a:…" で解決。Tab5 再起動後も操作可。Tab5 から RemoveFabric(または
  unpair)→ SRP から Tab5 側インスタンスだけ消え、PC 側は残る。
- **ゲート C(回帰)**: `otmode form` で主宰モードへ戻り、退避 dataset で従来ネットワークが復元される。
- chip-tool を使う場合は attestation 検証 ON(`--bypass-attestation-verifier` は使わない)。

### 18.7 リスク / 未決事項

- **lwIP の経路選択**: OT netif の OMR アドレスが static 扱いでないと /64 一致が効かず、既定 netif(WiFi)へ流れる
  可能性。P3 の RIO がその場合の受け皿だが、送信元アドレス選択が WiFi 側になり経路が非対称になる。ゲート A で
  `route` と OTBR のパケット観測で確定させる。駄目なら `LWIP_HOOK_IP6_ROUTE_CUSTOM` で prefix → OT netif を明示。
- **FTD として参加**: Tab5 が router/leader に昇格し得る(OTBR 停止時に Tab5 がパーティションを引き継ぐと SRP/DNS
  が消える)。必要なら JOIN では `otThreadSetRouterEligible(false)` で child 固定にするか要判断。
- **OMR prefix の変化**(OTBR 再構成)でノード帳アドレスが陳腐化 → D1 + P2 が入るまでは手動 `setaddr`。
- OTBR の DNS-SD サーバが Thread 側 :53 で SRP 登録を返すこと、netdata のサービス形式(unicast 0x5d / anycast 0x5c)
  は実機で要確認。anycast だけの場合は ALOC を組むか Kconfig で DNS サーバを与える。
- PASE 中のデバイス負荷(Thread + SRP 更新 + CASE 既存 2 セッション)と exchange プール。2 fabric 同時購読の実測要。
- 主宰モード時代の Thread ノード(旧 0xaabbccdd 等)は JOIN では到達不能のまま一覧に残る。削除 UI で対処。
- T10 の番号衝突(カメラ QR)。
