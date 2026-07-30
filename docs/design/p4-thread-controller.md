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
