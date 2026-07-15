# C FFI シム設計(ESP-IDF C++17 からの呼び出し)

対象: 既存の ESP-IDF(C++17)アプリケーションから simple-matter のデバイススタックを
呼び出せるようにする。方式は **staticlib + `extern "C"` C ABI シム + cbindgen ヘッダ +
薄い C++17 RAII ラッパ**。

`port-nrf-rw612.md` §4(Zephyr 向け C FFI シム)と同じ路線の具体化であり、
**シム crate 本体はプラットフォーム非依存**に作る(ESP-IDF が初版の消費者、
Zephyr/nRF は同じ .a とヘッダを使い回す)。

関連 doc: `port-nrf-rw612.md` §4(API 素案の原型)、`port-esp32-device.md`(C6 ベアメタル
ポート = 本シムを使わない Rust 完結路線)、`ARCHITECTURE.md`(sans-IO 契約)。

## 0. サマリ(設計判断)

- **cxx は使わない。** 接続面が「バイト列 in/out + 整数 + 少数のコールバック」に還元
  できるため(コアが sans-IO)、`extern "C"` が最短。cxx は codegen/ランタイム/ビルド統合の
  コストに見合う双方向の型往来が無い。
- **TX はコールバックではなく out-buffer 戻り値方式。** コアの
  `handle_rx(&mut [u8], PeerAddr, now_ms, &mut tx) -> Option<SendDirective>` /
  `poll(now_ms, &mut tx) -> Option<SendDirective>` の形をそのまま C に写す
  (RW612 素案 §4.1 の `sm_out_udp_tx` コールバック案から変更。FFI 境界の再入が無くなり、
  C++ 側の送信タイミング制御も素直になる)。コールバックが残るのは KVS(get/set/delete)のみ。
- **I/O・時刻・永続化の所有は C++ 側。** ソケット(5540 + 5353 v4/v6)、NimBLE、NVS、
  `esp_timer` は既存アプリの資産をそのまま使う。シムは純粋計算(OS 呼び出しゼロ)なので
  **ベアメタルターゲット(`riscv32imac-unknown-none-elf` 等)の .a を ESP-IDF の
  gcc にそのままリンクできる**。esp-idf-sys(std ターゲット)は不要。
- **単一インスタンス・単線アクセス。** スタックは shim 内 static に確保(ハンドル不要、
  v1 は 1 インスタンス)。全 API は**同一タスクから呼ぶ**契約(コアは `&mut` 単線)。
  ESP-IDF 側は FreeRTOS queue で RX/タイマを 1 タスクに直列化する(ESP32 ポートの
  worker⇔channel、RW612 案の k_msgq と同型)。
- **v1 スコープ = UDP トランスポート + mDNS + プリセットデバイス(OnOff ライト)。**
  コミッショニングは UDP 直接 PASE(`pairing onnetwork` / `address`)。BLE(NimBLE 給餌)と
  カスタムクラスタ(C vtable)は API 予約のみして後続フェーズ(§6)。

## 1. C API(v1)

ヘッダは cbindgen で自動生成(`simple_matter.h`)。全関数は同一タスクから呼ぶこと。

```c
/* ---- 初期化 ---- */
typedef struct {
  uint16_t discriminator;      /* 例 3840 */
  uint32_t passcode;           /* 例 20202021(開発用。verifier 供給は将来 API) */
  uint16_t vendor_id, product_id;
  const char *device_name;     /* mDNS インスタンス名の素材(NULL 可) */
  uint8_t  mac[6];             /* hostname / instance id 用 */
  /* KVS コールバック(NVS 等へ委譲)。get は実長を返す(無ければ負値) */
  int32_t (*kvs_get)(void *ctx, const char *key, uint8_t *buf, size_t cap);
  int32_t (*kvs_set)(void *ctx, const char *key, const uint8_t *val, size_t len);
  int32_t (*kvs_delete)(void *ctx, const char *key);
  void    *kvs_ctx;
  void   (*rng_fill)(void *ctx, uint8_t *buf, size_t len); /* esp_fill_random 等 */
  void    *rng_ctx;
} sm_config_t;

int  sm_init(const sm_config_t *cfg, uint64_t now_ms);   /* 0=OK。KVS から fabric 復元込み */

/* ---- アドレス(v4/v6 両対応の datagram 宛先/送信元) ---- */
typedef struct {
  uint8_t  ip[16];             /* v4 は先頭 4 バイト */
  bool     is_v6;
  uint16_t port;
  uint32_t scope_id;           /* v6 link-local 用(それ以外 0) */
} sm_addr_t;

/* ---- Matter UDP(:5540)。戻り値 = tx_out に書いた応答長(0 = 応答なし) ---- */
size_t sm_udp_rx(uint8_t *datagram, size_t len, const sm_addr_t *src,
                 uint64_t now_ms, uint8_t *tx_out, size_t tx_cap, sm_addr_t *tx_dst);

/* 期限処理(MRP 再送・ACK・購読レポート)。0 になるまで繰り返し呼んで送信する */
size_t sm_poll(uint64_t now_ms, uint8_t *tx_out, size_t tx_cap, sm_addr_t *tx_dst);

/* 次に sm_poll を呼ぶべき時刻(ms)。SM_NO_DEADLINE(=UINT64_MAX)= 期限なし */
uint64_t sm_next_deadline(uint64_t now_ms);

/* ---- mDNS(:5353)。ソケット・マルチキャスト join は C++ 側所有 ---- */
void   sm_set_addrs(const uint8_t ipv4[4], const uint8_t ipv6_ll[16]);  /* DHCP 後に反映 */
size_t sm_mdns_rx(const uint8_t *pkt, size_t len, const sm_addr_t *src,
                  uint8_t *tx_out, size_t tx_cap, sm_addr_t *tx_dst);
size_t sm_mdns_poll(uint64_t now_ms, uint8_t *tx_out, size_t tx_cap, sm_addr_t *tx_dst);

/* ---- アプリ(v1 = OnOff ライトプリセット) ---- */
typedef enum { SM_EV_NONE, SM_EV_ONOFF_CHANGED, SM_EV_COMMISSIONED,
               SM_EV_FABRIC_REMOVED, SM_EV_WINDOW_CHANGED } sm_event_kind_t;
typedef struct { sm_event_kind_t kind; uint8_t arg; } sm_event_t;
bool sm_take_event(sm_event_t *out);           /* 立った順に取り出し(LED 反映等) */
void sm_onoff_set(bool on, uint64_t now_ms);   /* ローカル操作の書き戻し */
bool sm_onoff_get(void);
uint8_t sm_fabric_count(void);
```

設計メモ:

- `sm_udp_rx` の `datagram` は `mut`(コアが in-place 復号)。`tx_out` は
  `MAX_PACKET_SIZE`(1280)以上を要求(不足は 0 返し + エラーカウンタ)。
- `sm_poll` は「1 回 1 送出」。0 が返るまで回す(コアの
  `while let Some(dir) = stack.poll(...)` の写し)。
- mDNS は `MdnsResponder` をシム内に抱き、パケット給餌 + `poll_announce` を
  `sm_mdns_rx`/`sm_mdns_poll` に写像。QU 応答のユニキャスト宛先は `tx_dst` で返す
  (`tx_dst->port == 5353 && マルチキャスト` なら multicast 送信、の判定は C++ 側不要 —
  シムが宛先アドレスまで確定させる)。fabric 増減時の operational 広告切替は
  シム内部で自動(PC example の pump 相当を内蔵)。
- KVS キーはコアの既存キー(`fabt`/`aclt`/`rsmp`/`grpt` 等)を NUL 終端文字列で渡す。
- イベントは固定長リング(8)。あふれは古い方を落とす(LED 状態は最終値で追従可)。

C++17 ラッパ(ヘッダオンリー、`sm_wrapper.hpp`)は `SmStack` クラス 1 枚:
コンストラクタで `sm_init`、`pump()` が poll ループ + イベント dispatch(std::function)、
デストラクタは無し(static インスタンス)。cbindgen ヘッダは `extern "C"` ガード付きで
C からも使える。

## 2. crate 構成とビルド

- `crates/simple-matter-cffi`(ルート workspace、`crate-type = ["staticlib", "rlib"]`、
  no_std)。依存は simple-matter(default-features 無し)+ heapless のみ。
  - スタック実体は `static`(`StaticCell` 相当の MaybeUninit + init フラグ)。
    `DefaultStack` 相当の型パラメータを 1 つ固定(NF=5、ハブ用途ではないので十分)。
  - `#[panic_handler]` は feature `panic-abort`(default off)で提供
    (ベアメタルビルド時のみ有効化。ホストテストビルドは std 側のを使う)。
  - cbindgen.toml 同梱、ヘッダ生成は `scripts/gen-cffi-header.sh`(CI で差分チェック)。
- ターゲット別ビルド:
  - ESP32-C6/C3: `cargo build -p simple-matter-cffi --release
    --target riscv32imac-unknown-none-elf --features panic-abort`(stable rustc)
  - ESP32-S3: 同コマンドを esp チャネルで `--target xtensa-esp32s3-none-elf -Zbuild-std=core`
    (ports/esp32s3 と同じ espup 環境。リンクは ESP-IDF の xtensa gcc で問題なし)
  - ホストテスト: `--target x86_64-unknown-linux-gnu`(panic-abort off)
- ESP-IDF 統合は **コンポーネント 1 個**(`ports/esp-idf/components/simple_matter/`):
  `CMakeLists.txt` が `cargo build` を custom command で叩き
  `add_prebuilt_library` でリンク。ヘッダ + `sm_wrapper.hpp` を `INCLUDE_DIRS` で公開。
  Rust ツールチェーン不在の環境向けに、ビルド済み .a のパス指定
  (`SM_PREBUILT_A`)でも通るようにする。

## 3. ESP-IDF 側の参照実装(example)

`ports/esp-idf/examples/onoff_light_cpp/` — C++17、既存アプリへの組み込み手順の見本:

1. WiFi 接続(既存の `esp_wifi` コード)→ IP 取得で `sm_set_addrs`。
2. UDP ソケット 2 本(5540 dual-stack、5353 + IGMP/MLD join)。
3. 単一タスクのポンプループ: `select`/queue 待ち →
   `sm_udp_rx`/`sm_mdns_rx` → `while (sm_poll(...))` → `sm_take_event` で LED(GPIO)反映。
   待ち時間は `sm_next_deadline` と mDNS announce の近い方。
4. NVS を `kvs_*` コールバックに配線(namespace `smatter`)。
5. 時刻は `esp_timer_get_time()/1000` を毎回引数で渡す。

## 4. フェーズ計画とゲート

| フェーズ | 内容 | ゲート |
|---|---|---|
| **F1** | シム crate + cbindgen ヘッダ + **ホスト C++17 テストデバイス**(POSIX ソケットで onoff-light 相当を C++ から駆動) | ホストで smctl `pairing onnetwork` → toggle → read → リブート(プロセス再起動)後 resumption E2E。コアテスト回帰なし、clippy 0、riscv32imac ビルド green、ヘッダ生成差分ゼロ |
| **F2** | ESP-IDF コンポーネント + onoff_light_cpp example(C6 向け) | esp-idf docker(ot_rcp ビルドで使用済みの環境)で `idf.py build` green。**実機 flash はユーザの機材・ポート確認後** |
| **F3**(後続) | BLE 給餌 API(`sm_ble_event`、NimBLE 接続)= `pairing ble-wifi` 対応 | C6 実機 |
| **F4**(後続) | カスタムクラスタ C vtable(read/write/invoke ハンドラ登録)、S3/Xtensa .a、Zephyr 消費(RW612 doc §4 と合流) | — |

F1 のホスト E2E が本設計の核心ゲート: **C++ から見た API の妥当性をハードウェア無しで
フル検証できる**(smctl も同一リポジトリ内)。

## 5. 制約・割り切り(v1)

- 単一インスタンス・単線アクセス(マルチタスクから呼ぶと未定義。ESP-IDF 側で直列化)。
- デバイス構成はプリセット(EP0 標準 + EP1 OnOff ライト)。attestation はテスト DAC。
- BLE コミッショニング不可(UDP 直接 PASE のみ。実用上は WiFi 接続済みデバイスの
  ヘッドレスコミッショニングに相当し、e5-light で常用している経路)。
- OCW(AdminCommissioning)は搭載するが、PASE verifier の外部供給 API は将来。
- `sm_addr_t` の scope_id は C++ 側の netif index をそのまま往復(シムは解釈しない)。

## 6. 将来の拡張点(API 予約)

- `sm_ble_event(const sm_ble_event_t*, ...)` + C1/C2 給餌(F3)。BTP はコア実装済みなので
  シムの追加面は薄い。
- `sm_cluster_register(const sm_cluster_vtable_t*)`(F4): read/write/invoke を
  C 関数ポインタへ委譲する汎用クラスタ。TLV は「型付きスカラの get/set ヘルパ」を
  シムが提供し、C++ 側に TLV エンコーダを書かせない。
- Thread 版は ThreadDriver trait 確定(thread-port.md T2)後に同型の給餌 API を追加。

## 7. 完了記録

### F1(完了、コミット d574ff9)

シム crate(`crates/simple-matter-cffi` = staticlib + rlib)+ cbindgen ヘッダ
`include/simple_matter.h` + C++17 RAII ラッパ `include/sm_wrapper.hpp` + ホスト
C++17 テストデバイス(`ctest/onoff_light.cpp`)。ホスト E2E(smctl `pairing
onnetwork` → toggle → read → プロセス再起動後 resumption)green、riscv32imac
`--features panic-abort` ビルド green、ヘッダ生成差分ゼロ。

### F2(完了)

ESP-IDF コンポーネント + onoff_light_cpp example(ESP32-C6 向け)。

追加物:
- `ports/esp-idf/components/simple_matter/`:
  - `CMakeLists.txt` — 2 経路のリンク。(a) `SM_PREBUILT_A` でビルド済み .a を
    受ける(Rust ツールチェーン不要)、(b) 未指定なら custom command で
    `cargo build -p simple-matter-cffi --release --target <triple>
    --features panic-abort` を叩く。`add_prebuilt_library` + `INCLUDE_DIRS` で
    ヘッダ 2 枚を公開。IDF_TARGET → Rust ターゲット対応付け(esp32c6/c3 =
    `riscv32imac-unknown-none-elf`、非対応は `FATAL_ERROR`。S3/Xtensa は F4)。
  - `sm_component_stub.c` — COMPONENT_LIB を STATIC library 化する空 TU
    (経路 (b) の cargo 実行順序を `add_dependencies` で強制するため)。
  - `README.md` — 組み込み手順(components 追加・`SM_PREBUILT_A` の渡し方・
    経路 (b) の前提)。
- `ports/esp-idf/examples/onoff_light_cpp/`(C++17、C6): §3 の 5 項目
  (esp_wifi 接続 → `sm_set_addrs`、UDP 5540 dual-stack + 5353 v4/v6 join、
  単一タスクのポンプループ、NVS を `kvs_*` へ配線 namespace `smatter`、
  `esp_timer` 時刻、LED GPIO7=NanoC6)。RNG は `esp_fill_random`。
  `partitions.csv`(app 1.875MB、既定 1MB では収まらないため)、`sdkconfig.defaults`
  (C6、IPv6 有効)、`Kconfig.projbuild`(WiFi SSID/PASS・LED GPIO)。
- `ports/esp-idf/.gitignore`(build/・sdkconfig・managed_components 除外)。

ゲート(実測、`espressif/idf:release-v5.4` docker):
- ホスト .a ビルド green(`libsimple_matter_cffi.a` 12.9MB)。
- `idf.py set-target esp32c6 && idf.py build` を `SM_PREBUILT_A` 経路で完走。
  `Project build complete`、app バイナリ 1,107,616 B(partition 44% free)。
- 最終 ELF に sm_init/sm_udp_rx/sm_poll ほか全 11 シンボルが `T` で存在(nm 確認)。
  C++17(`sm_wrapper.hpp` include)コンパイル通過。
- コア(`crates/simple-matter`)・シム(`crates/simple-matter-cffi`)への変更ゼロ。

実機 flash はユーザの機材・ポート確認後(F2 のゲートはビルドまで)。
