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
  uint32_t passcode;           /* [非推奨・開発専用] verifier_* 指定時は無視。§1.1 */
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
  sm_network_t network;        /* プリセット NetworkCommissioning 種別(§10.1) */
  /* ---- PASE 資格情報(SPAKE2+ verifier)。§1.1 ---- */
  uint32_t verifier_iterations;   /* 0 = 未指定(passcode 由来にフォールバック) */
  const uint8_t *verifier_salt;   /* 16..=32 バイト。NULL = 既定 dev salt */
  size_t   verifier_salt_len;
  const uint8_t *verifier_w0_l;   /* w0‖L(97 バイト)。NULL = passcode 由来 */
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

### 1.1 PASE 資格情報(verifier 供給)

Matter のセキュリティ要件上、**デバイスは passcode を保持してはならない**。デバイスが持つのは
SPAKE2+ 検証子 `(w0, L)` + `salt` + `iteration count` だけで、passcode は QR / ラベル
(= コミッショナ側)にのみ存在する。

- 推奨: `sm_config_t.verifier_w0_l`(97 バイトの `w0‖L`)/ `verifier_salt`(16..=32 バイト、
  NULL なら既定 dev salt)/ `verifier_iterations`(非 0)を設定する。工場では passcode ごとに
  `smctl pase-verifier <passcode> [--salt <hex>] [--iterations N]` で生成した値を書き込む。
- 後方互換: `verifier_w0_l == NULL` または `verifier_iterations == 0` のときは、旧
  `passcode` フィールドから verifier を導出する(**開発専用フォールバック**)。verifier を
  与えた場合 `passcode` は無視される。
- `ctest/onoff_light.cpp` と `examples/onoff_light_cpp/main/main.cpp` は事前計算した
  dev verifier 定数(passcode `20202021` 相当)を渡す。デバイスコードに passcode リテラルは
  置かない(表示・ログも「dev verifier (passcode 20202021, not stored)」と明示)。

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
| **F4a** | S3/Xtensa 向け .a(esp チャネル + build-std)+ コンポーネントの esp32s3 対応 | esp32s3 の `idf.py build` green(docker、SM_PREBUILT_A 経路) |
| **F4b** | カスタムクラスタ C vtable(§8。read/write/invoke ハンドラ登録 + dirty 通知) | ホスト ctest E2E(カスタムクラスタを smctl の any read/write/invoke + subscribe で検証) |
| **F5**(後続) | Zephyr 消費(RW612 doc §4 と合流) | 機材(FRDM-RW612)待ち |
| **F6** | Thread 対応(§10。take-API + プリセット切替、Thread スタック/SRP は C++ 側 = esp_openthread) | C6 実機で pairing ble-thread → CASE over Thread → toggle + リブート永続化 |

F1 のホスト E2E が本設計の核心ゲート: **C++ から見た API の妥当性をハードウェア無しで
フル検証できる**(smctl も同一リポジトリ内)。

## 5. 制約・割り切り(v1)

- 単一インスタンス・単線アクセス(マルチタスクから呼ぶと未定義。ESP-IDF 側で直列化)。
- デバイス構成はプリセット(EP0 標準 + EP1 OnOff ライト)。attestation はテスト DAC。
- BLE コミッショニング不可(UDP 直接 PASE のみ。実用上は WiFi 接続済みデバイスの
  ヘッドレスコミッショニングに相当し、e5-light で常用している経路)。
- OCW(AdminCommissioning)は搭載。PASE verifier の外部供給は `sm_config_t.verifier_*`
  で対応済み(§1.1)。
- `sm_addr_t` の scope_id は C++ 側の netif index をそのまま往復(シムは解釈しない)。

## 6. 将来の拡張点(API 予約)

- `sm_ble_event(const sm_ble_event_t*, ...)` + C1/C2 給餌(F3)。BTP はコア実装済みなので
  シムの追加面は薄い。
- `sm_cluster_register(const sm_cluster_def_t*)`(F4b、§8): read/write/invoke を
  C 関数ポインタへ委譲する汎用クラスタ。TLV は「型付きスカラの get/set ヘルパ」を
  シムが提供し、C++ 側に TLV エンコーダを書かせない。

## 8. カスタムクラスタ C vtable(F4b 設計)

目的: C++ アプリが自前のエンドポイント/クラスタを追加できるようにする
(v1 プリセットの EP1 OnOff の隣に、既存 C++ 資産のドメインロジックを載せる)。

### 8.1 C API

```c
typedef enum { SM_T_BOOL, SM_T_U8, SM_T_U16, SM_T_U32, SM_T_U64,
               SM_T_I8, SM_T_I16, SM_T_I32, SM_T_I64, SM_T_F32,
               SM_T_STRING, SM_T_OCTETS } sm_attr_type_t;

typedef struct {            /* スカラ + 短いバイト列の tagged union */
  sm_attr_type_t type;
  bool is_null;             /* NULLABLE 属性のみ有効 */
  union { bool b; uint64_t u; int64_t i; float f;
          struct { uint8_t buf[64]; uint8_t len; } bytes; } v;
} sm_attr_value_t;

#define SM_ATTR_WRITABLE  (1u << 0)
#define SM_ATTR_NULLABLE  (1u << 1)
#define SM_ATTR_TIMED     (1u << 2)   /* timed write 必須 */
#define SM_CMD_TIMED      (1u << 0)

typedef struct { uint32_t attr_id; sm_attr_type_t type; uint32_t flags; } sm_attr_def_t;
typedef struct { uint32_t cmd_id; uint32_t flags; } sm_cmd_def_t;

typedef struct {
  uint16_t endpoint;        /* 新規 EP(2..)またはプリセット EP1 への追加 */
  uint32_t cluster_id;      /* vendor 領域 or 標準 ID */
  uint16_t revision;
  uint32_t feature_map;
  const sm_attr_def_t *attrs;  size_t n_attrs;
  const sm_cmd_def_t  *cmds;   size_t n_cmds;
  /* 戻り値は IM ステータス(0=Success、0x87=ConstraintError 等の下位バイト) */
  uint8_t (*read)  (void *ctx, uint32_t attr_id, sm_attr_value_t *out);
  uint8_t (*write) (void *ctx, uint32_t attr_id, const sm_attr_value_t *val);
  uint8_t (*invoke)(void *ctx, uint32_t cmd_id,
                    const sm_attr_value_t *args, size_t n_args, uint64_t now_ms);
  void *ctx;
} sm_cluster_def_t;

/* sm_init より前に呼ぶ(以降は SM_ERR)。def/attrs/cmds は呼び出し側が静的に保持 */
int  sm_cluster_register(const sm_cluster_def_t *def);
int  sm_endpoint_register(uint16_t endpoint, uint32_t device_type, uint8_t dt_revision);
/* 値変化を購読レポートへ(C++ 側の値が変わったら呼ぶ) */
void sm_attr_mark_dirty(uint16_t endpoint, uint32_t cluster_id, uint32_t attr_id);
```

### 8.2 設計判断

- **値の所有は C++ 側**。read は毎回コールバック(単線アクセスなので安全)。シムは
  キャッシュしない。dirty 追跡だけ `sm_attr_mark_dirty` で IM へ橋渡し
  (subscribe レポートの契機)。
- **invoke の引数はスカラ列に平坦化**(TLV context tag 0..N-1 を宣言順で
  `sm_attr_value_t` にデコードして渡す)。応答はステータスのみ(v1)。
  応答ペイロード・構造体引数・イベント post は将来(§6 に残す)。
- **Rust 側は `CustomCluster`(ServerCluster trait の手書き実装)1 型**: 実行時メタ
  (attr/cmd 表)を heapless 固定容量で保持し、read/write/invoke を vtable へ委譲。
  `cluster!` マクロは使わない(静的メタ前提のため)。GlobalAttributes
  (ClusterRevision/FeatureMap/AttributeList/AcceptedCommandList)はシムが合成。
- **容量固定**: 追加エンドポイント最大 4、カスタムクラスタ最大 8、クラスタあたり
  属性 16・コマンド 8(超過は SM_ERR)。Descriptor(PartsList/ServerList/DeviceTypeList)
  はプリセット分と合成して自動生成。
- 権限は既定(read=View、write/invoke=Operate、SM_ATTR_TIMED/SM_CMD_TIMED で
  timed 必須)。Administer 指定は将来フラグ。
- 文字列/オクテット列は 64B 上限(`sm_attr_value_t` 内固定バッファ。長大データは
  スコープ外と明記)。
- Thread 版は ThreadDriver trait 確定(thread-port.md T2)後に同型の給餌 API を追加。

### 8.3 実装で確定した差分(F4b)

設計 §8.1/§8.2 に対し、実装で以下を確定した(§8 本文は上記のまま、差分をここに集約):

- **union は cbindgen が名前付き型 `sm_attr_value_data` として出力**する(匿名インライン
  union にはならない)。C からの値アクセスは設計どおり `val.v.u` / `val.v.b` /
  `val.v.i` / `val.v.f` / `val.v.bytes`。`bytes` は名前付き型 `sm_attr_bytes`
  (`{ uint8_t buf[64]; uint8_t len; }`)。`sm_attr_value_t.type` は Rust の
  `r#type` から `type` として出力される(設計どおり)。
- **登録の戻り値**(`sm_cluster_register`/`sm_endpoint_register`): `0`=OK、`-1`=NULL、
  `-2`=sm_init 済み(SM_ERR)、`-3`=不正 or 属性/コマンド上限超過、`-4`=クラスタ/EP 数上限、
  `-5`=プリセット EP(0/1)への `sm_endpoint_register`(予約)。
- **カスタム属性は既定で subscribe 可**(`subscribable=true`)。IM 経由の write 成功でも
  自動 dirty にする(C からの `sm_attr_mark_dirty` と併せて購読へ反映)。
- **Descriptor 合成**: sm_init 時に「プリセット EP0/EP1 + カスタム EP」をマージし、各 EP の
  ServerList・DeviceTypeList・EP0 の PartsList を再構成する(新規 EP には 0x001D を自動付与)。
- 権限は設計どおり read=View / write・invoke=Operate。`SM_ATTR_TIMED`/`SM_CMD_TIMED` の
  timed 強制は既存 IM エンジン(メタの `timed` フラグ)がそのまま担う。
- smctl に **`any subscribe <node> <ep> <cluster-id> <attr-id> <min> <max>`** を追加
  (テーブル未収載のカスタムクラスタを ID 直指定で購読する escape hatch。テスト用ツール)。

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

### F4a(完了)

S3/Xtensa 向け staticlib + コンポーネントの esp32s3 対応。

- **xtensa staticlib ビルド**: ルート workspace から
  `cargo +esp build -p simple-matter-cffi --release --target xtensa-esp32s3-none-elf
  -Zbuild-std=core --features panic-abort` で完走(espup 環境。ラッパ不要 — ルートに
  rust-toolchain.toml が無く default stable のため `+esp` 上書きが効く。`-Zbuild-std=core`
  と `--target` はコマンドラインで渡す)。`libsimple_matter_cffi.a` 8.4MB。
- **コンポーネント**: `CMakeLists.txt` の IDF_TARGET 対応表に
  `esp32s3 = xtensa-esp32s3-none-elf` を追加。S3 は esp channel + build-std が要るため
  経路 (b)(cargo 自動ビルド)は不可 → **経路 (a) `SM_PREBUILT_A` のみサポート**
  (S3 で (b) を選ぶと明示的 `FATAL_ERROR`)。README にビルド手順を追記。
- **example**: LED GPIO を Kconfig 化済み(既定 C6=GPIO7、`IDF_TARGET_ESP32S3` は GPIO48)。
  `sdkconfig.defaults` から `CONFIG_IDF_TARGET` を外しターゲット非依存化(set-target で選ぶ)。
  onoff_light_cpp にオンデバイスのカスタムクラスタ登録(EP2)も追加(F4b をハードウェア
  経路でも実演し、新シンボルを ELF に残す)。

ゲート(実測、`espressif/idf:release-v5.4` docker、`SM_PREBUILT_A` 経路):
- **esp32s3 `idf.py build` green**: `Project build complete`、app バイナリ 1,018,432 B
  (partition 48% free)。ELF に sm_init/sm_udp_rx/sm_poll + 新規
  sm_cluster_register/sm_endpoint_register/sm_attr_mark_dirty が `T` で存在(nm 確認)。
- **esp32c6 `idf.py build` 回帰なし**(riscv .a、同 docker)。
- docker 終了時にコンテナ内で `build/`・`sdkconfig` を rm(root 所有残骸なし)。

### F4b(完了)

カスタムクラスタ C vtable(§8)。

追加物:
- `crates/simple-matter-cffi/src/custom.rs`: C ABI 型(`sm_attr_type_t`/`sm_attr_value_t`/
  `sm_attr_def_t`/`sm_cmd_def_t`/`sm_cluster_def_t`)+ `CustomCluster`(`ServerCluster` の
  手書き実装、heapless 固定容量 §8.2)+ 登録ステージング `PendingRegistry`。
- `src/lib.rs`: `sm_cluster_register`/`sm_endpoint_register`/`sm_attr_mark_dirty` の 3 関数、
  `Light` にカスタムクラスタ/合成 Descriptor/マージ EndpointMeta を保持し
  `install_custom` で sm_init 時に合成。`heapless` 依存を追加。
- ヘッダ再生成(冪等)。`ctest/onoff_light.cpp` を拡張(EP2 にカスタムクラスタ登録:
  U16 rw / BOOL ro / STRING ro / nullable i16 ro / U16 ro(周期 mark_dirty)、コマンド
  引数 2 個)。smctl に `any subscribe`(ID 直指定)を追加。

ゲート(実測):
- Rust 単体テスト 7 本追加(read/write/invoke ディスパッチ、全型 read、nullable、
  型不一致 ConstraintError、幅超過、meta 合成 + timed フラグ、from_def 容量拒否)。
  `cargo test --workspace` = 595 pass(588 + 新規 7、回帰なし)。clippy 0。
- **ホスト E2E green**(ctest ↔ smctl、`--state-dir` 分離、127.0.0.1):
  - pairing onnetwork → COMPLETE。
  - any read(EP2): u16=100 / bool=false / str="custom-label" / i16=-42(全型一致)。
  - any write u16=4242 → C コールバック到達 → read 反映。
  - any invoke cmd 0x0000(u8:1, u16:1234)→ invoke ハンドラ実行 → writable=1234 / flag=true。
  - any subscribe(0x0004)→ 周期更新レポート 4→5→6→7(mark_dirty 経由)。
  - descriptor: EP0 PartsList=[1,2]、EP2 ServerList=[0x001D, 0xFFF1FC01]、
    EP2 DeviceTypeList=[{0:0xFFF10055, 1:1}]。

コア(`crates/simple-matter`)への変更ゼロ(`ServerCluster` の pub 契約のみで実装。
ClusterMeta の `&'static` は CustomCluster がシム static 内で自己参照を確定して満たす)。

### F3(完了、NanoC6 実機 E2E green 2026-07-16)

BLE(BTP)給餌 API + NimBLE 配線。`pairing ble-wifi`(BLE コミッショニング → WiFi
プロビジョン → 運用 UDP)を NanoC6 実機で通した。

追加/変更物:
- `crates/simple-matter-cffi`:
  - `Cargo.toml`: feature `ble`(default on)= `simple-matter/ble` を引き込む。
  - `src/lib.rs`: §9.1 の 5 API(`sm_ble_event`/`sm_ble_poll`/`sm_ble_adv_data`/
    `sm_take_wifi_request`/`sm_wifi_status`)+ `sm_ble_event_kind_t` + イベント
    `SM_EV_BLE_ADV_CHANGED`/`SM_EV_WIFI_CONNECT_REQUEST`。Shim に `Btp<6>` + BLE 接続状態
    (conn/mtu/subscribed/adv)を ble-gated 保持。`sm_poll` は BLE 宛 SendDirective を
    BTP に載せ替え(UDP 宛のみ返す)、`sm_next_deadline` に BTP deadline を併合。
    NetworkCommissioning を ble 有無で `NetworkCommissioningWifi<ShimWifiDriver>` /
    `NetworkCommissioning`(Ethernet)に切替。
  - `src/wifi_driver.rs`: take 方式 `ShimWifiDriver`(§9.2)。`connect` で SSID/creds を
    退避 + `Connecting`、`sm_take_wifi_request` で降ろし、`sm_wifi_status` で
    `Connected`/`Failed` を反映 → コアの `poll_deferred` が遅延 ConnectNetworkResponse を確定。
  - `src/tests.rs`: BTP handshake フラグメントラウンドトリップ(central→C1 write→subscribe→
    `sm_ble_poll` で handshake resp→central 確立)、adv data 生成、wifi request take を
    `ffi_lifecycle_roundtrip` に追加。ble 無効時 SM_ERR は `ble_disabled_returns_sm_err`
    (`--no-default-features` で走る新規テスト)。
  - ヘッダ再生成(冪等)。
- `ports/esp-idf/examples/onoff_light_cpp`(NimBLE、C6):
  - `main/ble.cpp` + `ble.hpp`: NimBLE(GATT 0xFFF6 / C1 write / C2 indicate / 広告)。
    コールバックは `app_cmd.hpp` の Cmd queue で matter タスクへ直列化。indicate は
    確認(EDONE)まで待って次フラグメントを直列送出。MTU 交換で `SM_BLE_CONNECTED`
    (C1 write が先着したら mtu=0 で先行送出)。
  - `main/main.cpp`: BLE 有効時は起動時 WiFi join を止め、`SM_EV_WIFI_CONNECT_REQUEST`
    → `sm_take_wifi_request` → esp_wifi join → got_ip/失敗で `sm_wifi_status`。
    `SM_EV_BLE_ADV_CHANGED` → `sm_ble_adv_data` を NimBLE に反映。WiFi 資格情報は NVS
    (namespace `smwifi`)に保存し、起動時 fabric>0 なら復元 auto-join(再起動 resumption 用)。
    `esp_wifi_set_ps(WIFI_PS_NONE)`(省電力オフ。mDNS/CASE の UDP 取りこぼし対策)。
  - `main/Kconfig.projbuild`: `CONFIG_SM_ENABLE_BLE`(C6 既定 y / それ以外 n)。
  - `sdkconfig.defaults.esp32c6`: NimBLE(peripheral)+ WiFi/BLE coex 有効(S3 は読まれず
    BLE 無効ビルド)。`main/CMakeLists.txt`: `bt` を常時要求(条件付き REQUIRES は
    sdkconfig 展開前に評価されるため不可。S3 は BT 無効でスタブ)。matter タスクスタック
    128KB は §7 の知見どおり維持。
- `crates/smctl/src/runner/ble.rs`(テストツール): `pairing ble-wifi` の運用 mDNS 解決に
  `--at`(ユニキャスト QU)を配線(既存 `resolve_operational_at` を使用)。マルチキャストを
  落とす AP / IGMP snooping 環境で運用ノードが解決できない実機症状の回避。

ゲート(実測):
- `cargo test --workspace` = 595 pass(BLE ラウンドトリップ等を `ffi_lifecycle_roundtrip`
  に集約。単一 static 契約のため)。`--no-default-features` で +1(ble 無効 SM_ERR)。clippy 0。
- riscv32imac staticlib: `--features panic-abort,ble` green + `--features panic-abort`
  (ble 無効・後方互換)green。ヘッダ冪等。5 新規シンボルが最終 ELF に `T` で存在。
- `idf.py build`: esp32c6(BLE 有効)green(app 1,504,320B、partition 24% free)。
  esp32s3(`CONFIG_SM_ENABLE_BLE=n`、BT 無効)green(app 1,019,344B、48% free)= 回帰なし。
- **実機 E2E(NanoC6、/dev/ttyACM1、MAC 40:4c:ca:5b:2f:e0)green**: フレッシュ NVS →
  `smctl --at 192.168.2.129 pairing ble-wifi 1 20202021 iotap hogeFugapiyo 3840`:
  PASE→ArmFailSafe→…→AddNOC→AddOrUpdateWiFiNetwork→ConnectNetwork(`sm_take_wifi_request`
  経由で esp_wifi join、got_ip で `sm_wifi_status(true)` → 遅延 ConnectNetworkResponse)→
  BLE close → 運用ノード unicast 解決(192.168.2.129:5540)→ CASE(Sigma1/2/3) over UDP →
  **CommissioningComplete** → onoff toggle(Success)。運用中の read は Sigma2Resume で確立。
  **リブート → `fabrics=1` 復元 + 保存 WiFi で auto-join → Sigma2Resume で toggle** 確認。
- RAM 実測(BLE+WiFi coex + 128KB スタック): `sm_init` 直後 free heap ≈ 92.7–93.2KB
  (NimBLE 起動後・WiFi 接続前)。逼迫なし。
- コア(`crates/simple-matter`)への変更ゼロ。

## 9. BLE 給餌 API(F3 設計)

目的: C++ 側が所有する BLE スタック(ESP-IDF なら NimBLE)から BTP バイト列を
給餌し、`pairing ble-wifi`(BLE コミッショニング → WiFi プロビジョン → 運用 UDP)を
成立させる。コアの BTP はポンプ型(`Btp::process_incoming` / `recv` / `send` /
`process_outgoing`)なので、UDP と同じ out-buffer 流儀で写像する。

### 9.1 C API

```c
/* ---- BLE(BTP)。GATT サービス 0xFFF6 / C1 write / C2 indicate は C++ 側所有 ---- */
typedef enum { SM_BLE_CONNECTED,      /* arg = ATT MTU(不明なら 0 = 23 扱い) */
               SM_BLE_DISCONNECTED,
               SM_BLE_C1_WRITE,       /* data/len = 書き込まれた 1 フラグメント */
               SM_BLE_C2_SUBSCRIBED   /* CCCD subscribe 完了 */ } sm_ble_event_kind_t;
int    sm_ble_event(sm_ble_event_kind_t kind, uint16_t arg,
                    const uint8_t *data, size_t len, uint64_t now_ms);
/* C2 indication で送るべき次フラグメント(0 = なし)。indication 完了(ACK)を
   待たず次を取り出してよい(C++ 側は NimBLE の indicate 完了イベントで直列化) */
size_t sm_ble_poll(uint64_t now_ms, uint8_t *frag_out, size_t cap);
/* commissionable 広告の service data(0xFFF6)。0 = 広告停止すべき状態。
   内容が変わったら SM_EV_BLE_ADV_CHANGED イベントが立つ */
size_t sm_ble_adv_data(uint8_t *out, size_t cap);

/* ---- WiFi プロビジョン(NetworkCommissioning → C++ の esp_wifi へ) ---- */
/* ConnectNetwork 受理で SM_EV_WIFI_CONNECT_REQUEST が立つ → C++ が取り出して join */
size_t sm_take_wifi_request(uint8_t *ssid_out, size_t ssid_cap,
                            uint8_t *pass_out, size_t pass_cap, size_t *pass_len);
/* join 結果の報告(遅延 ConnectNetworkResponse がこれで確定する) */
void   sm_wifi_status(bool connected, uint64_t now_ms);
```

### 9.2 設計判断

- **BLE 接続は同時 1 本**(BTP エンジン 1 個。Matter デバイスの通例。2 本目の
  CONNECTED は拒否 = C++ 側で接続を切る)。conn id は API に出さない。
- **fragment サイズ = CONNECTED で渡された ATT MTU から BTP が交渉**(mtu=0 は
  「不明」= 23 既定。E4 実機で fragment=244 実証済みの経路)。
- `sm_ble_poll` は BTP の再送・keep-alive ACK(2.5s、chip ack-timer 互換)も
  産むため、`sm_next_deadline` は BTP の deadline も併合する。
- **WiFi driver は callback でなく take 方式**(pump 単線契約の維持)。コアの
  NetworkCommissioningWifi(即 Success + バックグラウンド join + 遅延
  ConnectNetworkResponse)に `sm_take_wifi_request` / `sm_wifi_status` で橋渡し。
  v1 プリセット(F2 example)の「固定 SSID を C++ が自力 join」も引き続き可
  (BLE 無効ビルド/未使用なら従来どおり)。
- 広告ペイロードはシムが生成(discriminator/VID/PID 入り Matter service data)。
  開始/停止の判断もシム(fabric 有無・窓状態)で、C++ は SM_EV_BLE_ADV_CHANGED を
  受けて `sm_ble_adv_data` を反映するだけ。
- シムの `ble` は Cargo feature(default on。ヘッダは常時宣言、無効ビルドは
  SM_ERR 返し)。

### 9.3 example(NimBLE)

onoff_light_cpp に NimBLE 配線を追加(Kconfig で BLE on/off):
GATT サービス 0xFFF6(C1 write / C2 indicate)、広告 = `sm_ble_adv_data`、
indicate 完了イベントで次フラグメント送出、MTU 交換後に SM_BLE_CONNECTED。
WiFi は起動時 join をやめ(BLE 有効時)、`sm_take_wifi_request` 駆動に切替。

ゲート: NanoC6 実機で PC から smctl `pairing ble-wifi`(BLE コミッショニング →
WiFi provision → BLE close → 運用 mDNS → CASE over UDP)+ chip-tool 相互試験。

### 9.4 実装で確定した差分(F3)

設計 §9.1/§9.2/§9.3 に対し、実装で以下を確定した(§9 本文はそのまま、差分をここに集約):

- **`sm_ble_adv_data` は完全な広告ペイロード(15 バイト)を返す**。§9.1 の「service data
  (0xFFF6)」は、C++ がそのまま `ble_gap_adv_set_data` に渡せるよう **Flags AD + Service
  Data AD(`AdvData::encode_adv`、`ADV_TOTAL_LEN=15`)** を返す実装にした(8 バイトの
  service data 単体ではない)。`cap` 不足は 0 返し。
- **`sm_ble_event` の戻り値**: `0`=OK、`-1`=未初期化/NULL/ble 無効、`-2`=2 本目の接続拒否
  (C++ は当該接続を切る)、`-3`=BTP `process_incoming` 失敗。
- **`sm_ble_poll` は subscribe 完了前は 0**(handshake resp も含め、C2 subscribe 後に排出)。
- **`sm_take_wifi_request` は SSID バイト長を返す**(0=保留なし)、`pass_len` に資格情報長。
- **初期広告イベントは抑止**: `sm_init` 末尾で立つ最初の `SM_EV_BLE_ADV_CHANGED` は
  イベントリングから除去する(C++ は init 後に `sm_ble_adv_data` で広告をブートストラップ
  するため。以降の変化のみイベント化)。
- **ATT MTU が未知でも成立**: MTU 交換前の C1 write 先着時は `SM_BLE_CONNECTED(mtu=0)` を
  先行送出し、BTP handshake は central 提示 MTU からフラグメントを算出する(実機 chip/smctl は
  MTU 交換後に BTP handshake するため通常は交渉済み MTU が入る)。
- **example の追加(§9.3 外だが実運用に必須)**: (a) WiFi 資格情報の NVS 永続化 + 起動時
  auto-join(再起動 resumption)、(b) `esp_wifi_set_ps(WIFI_PS_NONE)`(coex 省電力で mDNS/CASE
  の UDP を取りこぼす対策)。
- **`Kconfig SM_ENABLE_BLE` は C6 のみ既定 y**(S3 は既定 n = 従来の UDP 直接 PASE)。BT/NimBLE
  の sdkconfig は `sdkconfig.defaults.esp32c6` に置き S3 では読まれない。`bt` は常時 REQUIRES
  (条件付き REQUIRES 不可)。

### 実機検証(NanoC6、2026-07-16)

onoff_light_cpp を M5Stack NanoC6(esp32c6、4MB)で実機 E2E green:
WiFi join(iotap)→ smctl `pairing onnetwork --at <ip>` COMPLETE(約 4 秒)→
onoff toggle → カスタムクラスタ any read / invoke(u8,u16 → 反映確認)→
リブートで NVS から fabrics=1 復元 → Sigma2Resume で toggle。
資格情報は `sdkconfig.local`(gitignore)を `SDKCONFIG_DEFAULTS` に連結して注入、
flash は `espflash write-bin`(0x0/0x8000/0x10000)。

**実機で確定した必須知見: pump タスクのスタックは 128KB 級が必要。**
8KB(当初値)は起動直後に Stack protection fault で即リセットループ、80KB でも
不足(SP が下限を 11.5KB 突き抜け)。原因は `sm_init` の「スタック上で構築 →
static へ move」の一時コピー多段(LTO/opt-z でも解消しない)+コミッショニング中の
P-256 署名チェーン(ベアメタル実測 ~70KB)。将来の削減案: シム内の完全 in-place
構築(§2 の MaybeUninit 直書きを構築式の内側まで徹底)。

### F6(完了、Thread 対応 — §10 設計の実装)

`pairing ble-thread`(BLE コミッショニング → Thread プロビジョン → CASE over Thread)を
シムの take 方式で写像し、esp_openthread(15.4 radio + lwIP 統合 netif + SRP client)を
C++ 側の責務として onoff_light_cpp に統合した。

追加/変更物:
- `crates/simple-matter-cffi`:
  - `src/thread_driver.rs`: take 方式 `ShimThreadDriver`(§10.2、`ShimWifiDriver` の鏡像)。
    `set_dataset` で dataset TLV を退避 + Ext PAN ID を返す、`connect` で `pending` を立て
    `Attaching` に、`sm_take_thread_dataset` で dataset を降ろし、`sm_thread_status` で
    `Attached`/`Failed` を反映 → コアの `poll_deferred` が遅延 ConnectNetworkResponse を確定。
  - `src/lib.rs`: NetworkCommissioning を **実行時 enum `ShimNetComm`**(Ethernet / Wifi /
    Thread の 3 バリアント、`ServerCluster` を委譲)に置換し、`sm_config_t.network`
    (`sm_network_t` = SM_NET_ETHERNET/WIFI/THREAD)で選ぶ。新規 3 API:
    `sm_take_thread_dataset`/`sm_thread_status`/`sm_operational_instance_name`
    (SRP インスタンス名 `<compressedFabricId 16hex 大文字>-<nodeId 16hex 大文字>` を
    fabric 先頭 1 つから NUL 終端で生成)。イベント `SM_EV_THREAD_ATTACH_REQUEST`。
    `housekeep_ble` を WiFi/Thread 両対応に一般化。**後方互換**: `network` は
    `sm_config_t` 末尾に追加、0 = SM_NET_ETHERNET = 従来動作。WiFi/Thread は BLE 前提の
    ため ble 無効ビルドは種別によらず Ethernet(shim フォールバック)。
  - ヘッダ再生成(冪等)。Rust 単体テスト +3(dataset take ラウンドトリップ、不正
    dataset 拒否、network 種別毎の enum バリアント/FeatureMap/ドライバ有無)。`ble_checks`
    と `ffi_lifecycle_roundtrip` は `network = SM_NET_WIFI` に更新(wifi_driver_mut 経由)。
- `ports/esp-idf/examples/onoff_light_cpp`:
  - `main/ot_thread.{hpp,cpp}`: esp_openthread 初期化(RADIO_MODE_NATIVE)+ OT netif
    (`ESP_NETIF_DEFAULT_OPENTHREAD`、lwIP 統合)+ mainloop タスク + eventfd 登録 +
    role 変化コールバック(→ `CmdKind::ThreadRole`)。`sm_ot_apply_dataset`
    (`otDatasetSetActiveTlvs` + `otIp6SetEnabled` + `otThreadSetEnabled`)、`sm_ot_srp_register`
    (host `SM<MAC>` / instance `sm_operational_instance_name` / `_matter._tcp` port 5540 /
    TXT `SII=10000,SAI=1000,T=0`(thread-port.md T3 実測)+ `otSrpClientEnableAutoStartMode`)。
  - `main/main.cpp`: Kconfig `SM_NETWORK_TYPE`(wifi/thread 択一、既定 wifi)で分岐。
    thread 時は WiFi 初期化を止め `sm_ot_init` を起動、`cfg.network = SM_NET_THREAD`、
    `SM_EV_THREAD_ATTACH_REQUEST` → `sm_take_thread_dataset` → `sm_ot_apply_dataset` +
    dataset を NVS(namespace `smthr`)へ永続化、`ThreadRole` cmd → `sm_thread_status` +
    SRP 登録、`SM_EV_COMMISSIONED` → SRP 登録、起動時 fabric>0 なら保存 dataset で
    auto-attach。mDNS ソケット(5353)は thread 構成では開かない(SRP 運用)。UDP :5540 は
    OT netif が lwIP 統合のため WiFi と同一コード。
  - `main/Kconfig.projbuild`: `SM_NETWORK_TYPE` choice(thread は C6 依存、選択で
    `SM_ENABLE_BLE` 既定 y)。`main/CMakeLists.txt`: `openthread`・`vfs`(eventfd)を常時
    REQUIRES(条件付き REQUIRES 不可のため。ble.cpp の `bt` と同方針)。
  - `sdkconfig.defaults.thread`(OPENTHREAD_ENABLED/FTD/SRP_CLIENT + IEEE802154 +
    coex + `CONFIG_SM_NETWORK_THREAD=y`)、`sdkconfig.defaults` に `FLASHSIZE_4MB`、
    `partitions.csv` を app 2.5MB(`0x280000`)へ拡張(openthread 分。WiFi 構成でも同一)。

ゲート(実測):
- **ホスト**: `cargo test --workspace` green(562+13+59+…、新規 3 本込み、回帰なし)。
  `--no-default-features` も green。clippy 0(default / no-default 両方)。
  riscv32imac staticlib green(`--features panic-abort`(ble 込み)/ `--features
  panic-abort --no-default-features`(ble 無効・後方互換)両方、新規 3 シンボルが `T`)。
  ヘッダ冪等。**ホスト ctest 回帰 green**: memset 既定 = `network=0=Ethernet` で
  `pairing onnetwork` → COMPLETE → onoff toggle(Success)→ read=true → Sigma2Resume
  (WiFi/Ethernet 経路が壊れていないことを確認)。
- **idf.py build(docker `espressif/idf:release-v5.4`、`SM_PREBUILT_A` 経路)**:
  - **esp32c6 Thread 構成 green**: `Project build complete`、app 1,558,624 B
    (`0x17c460`、partition 41% free)。sdkconfig に OPENTHREAD_ENABLED/FTD/SRP_CLIENT/
    IEEE802154/NimBLE/coex/FLASHSIZE_4MB が反映。ELF に `esp_openthread_init` /
    `otDatasetSetActiveTlvs` / `otThreadSetEnabled` / `otSrpClientAddService` +
    `sm_take_thread_dataset` / `sm_thread_status` / `sm_operational_instance_name` が `T`。
  - **esp32c6 WiFi 構成の回帰 green**: app 1,507,200 B(`0x16ff80`、43% free)。
    `openthread`/`vfs` の常時 REQUIRES + main.cpp の #if 分岐が WiFi ビルドを壊さない。
  - **esp32s3 の回帰 green**(F4a、xtensa prebuilt): app 1,027,184 B(61% free)。
    S3 は 15.4 非搭載だが `openthread` の常時 REQUIRES は `CONFIG_OPENTHREAD_ENABLED=n` で
    スタブ化され configure/リンク成立。
- 合成に注意した点(prompt 指示): thread は
  `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.esp32c6;sdkconfig.defaults.thread"`、
  wifi は末尾を `sdkconfig.local` にして明示合成(`-DSDKCONFIG_DEFAULTS` を渡すと IDF の
  target 自動連結が無効化されるため esp32c6 を明示)。`vfs` コンポーネント(eventfd の
  提供元。IDF v5.4 で `esp_vfs_eventfd` という独立コンポーネントは無い)を REQUIRES。
- コア(`crates/simple-matter`)への変更ゼロ(`NetworkCommissioningThread`/`ThreadDriver` は
  T2 で実装済み。シムは `ShimNetComm` enum + take 方式アダプタで写すのみ)。

**実機 E2E(核心ゲート)は未実施(残)**: DUT フラッシュ + 稼働中ソーク停止/再開 +
OTBR SRP 掃除を伴う live 操作のため、本実装エージェントでは着手せず親の確認に委ねる。
ファーム(bootloader/partition-table/app の 3 点)はビルド済みで即 flash 可能。手順は
§10.2 + prompt のゲート 3(soak-stop → NVS 消去 → 3 点 flash → `ot-ctl srp server
disable/enable` → get-dataset → `smctl --features ble pairing ble-thread` → attach →
SRP → CASE over Thread → toggle → リブート auto-attach → soak 再開)。

## 10. Thread 対応(F6 設計)

目的: ESP-IDF C++17 アプリを Thread デバイスにする(`pairing ble-thread`)。
コアの `ThreadDriver`/`NetworkCommissioningThread`(thread-port.md T2)を
シムの take 方式で写像する。**Thread スタック・SRP は C++ 側の責務**
(ESP-IDF 公式 `esp_openthread` + lwIP 統合 netif。ベアメタル Rust 路線と違い
ESP-IDF には BLE/15.4 の本物の coex があるため、R9 系の radio 問題や
運用中 BLE 時分割の制約が出ない見込み — 実機で確認するのも F6 の成果)。

### 10.1 C API 追加

```c
/* sm_config_t に追加 */
typedef enum { SM_NET_ETHERNET, SM_NET_WIFI, SM_NET_THREAD } sm_network_t;
/* sm_config_t.network = プリセットの NetworkCommissioning 種別 */

/* ConnectNetwork(Thread)受理で SM_EV_THREAD_ATTACH_REQUEST が立つ →
   C++ が dataset TLV を取り出して esp_openthread へ投入・attach 開始 */
size_t sm_take_thread_dataset(uint8_t *tlv_out, size_t cap);
/* attach 結果の報告(遅延 ConnectNetworkResponse が確定) */
void   sm_thread_status(bool attached, uint64_t now_ms);
```

- WiFi の `sm_take_wifi_request`/`sm_wifi_status` の鏡像。dataset の NVS 永続化と
  起動時 auto-attach は C++ 側(WiFi 資格情報と同じ流儀)。
- 運用広告: `sm_mdns_*` は Thread では使わない。C++ が ESP-IDF の SRP client API で
  `_matter._tcp` を登録する(TXT の SII/SAI 推奨値は thread-port.md T3 実測 =
  SII=10000/SAI=1000。インスタンス名 `<compressedFabricId hex>-<nodeId hex>` の
  素材はシムが返す: `sm_operational_instance_name(buf, cap)`)。
- UDP は既存 `sm_udp_rx`/`sm_poll` のまま(OT netif は lwIP に統合されるので
  C++ のソケットコードは WiFi と同一。dual-stack の v6 経路が本線になるだけ)。

### 10.2 example / ゲート

- onoff_light_cpp に Kconfig で `SM_NETWORK_TYPE`(wifi/thread 択一)。thread 選択時:
  esp_openthread 初期化 + OT netif + NimBLE(ble-thread)+ SRP client 登録 +
  dataset NVS 永続化。app パーティションは openthread 分の増加に注意
  (BLE 版 1.5MB + OT → 1.875MB 上限を超えるなら partitions.csv を拡張)。
- ゲート: idf.py build green(wifi 構成の回帰込み)→ NanoC6 実機で
  smctl/chip-tool `pairing ble-thread` → 運用発見(SRP → OTBR proxy)→
  CASE over Thread → toggle → リブート永続化。既存 OTBR 環境を流用。

### F6 実機検証(NanoC6 + OTBR、2026-07-17)

thread 構成の onoff_light_cpp を NanoC6 実機で E2E green:
smctl `pairing ble-thread`(BLE/BTP → PASE → AddNOC → dataset take →
`otDatasetSetActiveTlvs` → attach(detached→child ~2 秒)→ 遅延
ConnectNetworkResponse → BLE close → SRP 登録(ESP-IDF SRP client)→
運用解決 → CASE over Thread → **COMPLETE 約 26 秒**)→ toggle。
リブートで fabric+dataset 復元 → auto-attach(~1 秒、**Router に昇格**)→
Sigma2Resume 64〜121ms → toggle。

**実機で発見・修正したバグ(シム)**: mDNS を駆動しない構成(Thread = SRP
運用)では `sm_next_deadline` が mDNS announce の過去期限を返し続け、pump の
select が 0 タイムアウトでスピン → task_wdt 発火 → abort ループ。
`Shim::mdns_used`(sm_mdns_rx/poll が一度でも呼ばれたか)で announce 期限の
併合をゲートして解決(mDNS 不使用の全構成に効く自己構成方式)。

**所見**: ESP-IDF の BLE/15.4 coex は本物で、ベアメタル esp-radio 路線の
R9 系症状(RX 沈黙・TX イベント喪失)は観測されず。attach・CASE とも
リトライ不要で安定。C++ 連携経路は Thread の実用品質が既に高い。

## 11. コントローラ C FFI 化(F7 設計)

目的: C++/ESP-IDF アプリからコントローラ(Commissioner/ImClient/MdnsClient)を
駆動する。ターゲットは ESP32-S3(将来 P4+H2 構成へ展開)。コアのコントローラは
no_std 実装済み(K1、正味 ~83KB)で、K2-K4 の s3-controller が Rust 側の参照実装。

### 11.1 設計方針

- デバイス側と同じ **out-buffer ポンプ型**の `sm_ctrl_*` API 群(別インスタンス、
  デバイス側と同居可だが v1 はコントローラ単独動作をゲートとする)。
- **メモリは呼び出し側供給**: `sm_ctrl_init(mem, mem_len, cfg)` — C++ が
  `heap_caps_malloc(MALLOC_CAP_SPIRAM)` 等で確保した領域に in-place 構築
  (PSRAM 配置対応。必要サイズは `sm_ctrl_context_size()` で取得)。
- CA/ノード帳の永続化は KVS コールバック(デバイス側と同じ contract。
  ca-state v1 / nodes.tlv 互換 = smctl/s3-controller と持ち運び可)。
- コミッショニング(F7a は UDP のみ): `sm_ctrl_pair_start(node_id, passcode,
  addr)` → pump(`sm_ctrl_udp_rx`/`sm_ctrl_poll`/`sm_ctrl_next_deadline`)→
  `sm_ctrl_take_event`(フェーズ進行/完了/失敗)。
- 運用操作: `sm_ctrl_invoke`/`sm_ctrl_read`/`sm_ctrl_write`(cluster/attr/cmd
  ID 直指定 + スカラ値、応答は take イベント + 値バッファ)+ subscribe 最小。
- 発見: MdnsClient のブラウズ/解決をポンプ写像(`sm_ctrl_mdns_*`。QU 直指定
  `--at` 相当のモードも)。
- F7b(後続): BLE central 給餌 API(BTP central を C++ の NimBLE central から
  駆動 = pairing ble-wifi/ble-thread)。

### 11.2 ゲート

- F7a: ホスト C++ テストコントローラ(POSIX)で既存デバイス example 相手に
  pairing address → CommissioningComplete → toggle → read → リブート
  (プロセス再起動)で CA/ノード帳復元 + resumption。S3/Xtensa .a +
  ESP-IDF S3 ビルド green(実機は S3 ボード接続確認後)。

### 11.3 F7a 完了記録

コントローラ(Commissioner / ControllerStack / MdnsClient)を C++/ESP-IDF から駆動する
`sm_ctrl_*` API 群を実装した(UDP 経路)。デバイス側スタックとは独立したインスタンスで、
**呼び出し側供給メモリに in-place 構築**する(PSRAM 配置の核心)。

追加/変更物:
- `crates/simple-matter-cffi`:
  - `src/controller.rs`(新規): C ABI 型(`sm_ctrl_config_t` / `sm_ctrl_event_t` /
    `sm_ctrl_event_kind_t`)+ 供給メモリに構築する `CtrlShim`(`ControllerStack` +
    `Commissioner` + ノード帳 + イベント/TX リング。owned への `&'static` 自己参照は
    `sm_init` と同じ addr_of 構築で満たす)+ 15 個の `sm_ctrl_*` 関数。
    - 供給メモリ: `sm_ctrl_context_size()` / `sm_ctrl_context_align()`(ビルド定数)+
      `sm_ctrl_init(mem, mem_len, cfg, now)`(サイズ/アラインを検証して in-place 構築)。
    - ポンプ: `sm_ctrl_udp_rx` / `sm_ctrl_poll` / `sm_ctrl_next_deadline`(デバイス側と
      同じ out-buffer 契約)。**settle→drive 分離**を守る: `sm_ctrl_udp_rx` は受信処理と
      ACK 送出のみ(コミッショナ駆動はしない)、`sm_ctrl_poll` は「未達 ACK/再送を先に
      流し切り(`next_deadline==None` で完全静穏化)→ 次のトランザクションを発行」の順で
      1 歩進める。これを守らないと、受信応答の遅延 standalone ACK より先に次の exchange を
      開始してしまい、デバイス IM responder(同時 1 トランザクション)が busy で無応答 →
      **AddTrustedRoot で Timeout** になる(実装中に実測・修正)。
    - コミッショニング: `sm_ctrl_pair_start`(UDP 直接 PASE、attestation Skip)→
      `sm_ctrl_take_event`(PAIR_PHASE / PAIR_COMPLETE / PAIR_FAILED。phase = フェーズ
      コード、status = 失敗理由コード)。
    - 運用: `sm_ctrl_invoke`(引数なしコマンド = OnOff Toggle)/ `sm_ctrl_read_scalar`
      (スカラ属性、値は READ_DONE イベントの `value_u64` + `value_is_null`)。**live
      セッションが無ければ内部で CASE を自動確立**(resumption 素材があれば Sigma2Resume)
      してから発行する(Connecting → AwaitOp の内部状態機械)。
    - 発見: `sm_ctrl_resolve_start`(MdnsClient の operational 解決、QU ユニキャスト直指定
      `--at` 相当を最優先)+ `sm_ctrl_mdns_rx`(解決結果を RESOLVE_DONE)+
      `sm_ctrl_node_addr` getter。
    - 永続化: KVS コールバックで CA 状態(`b"cast"` = ca-state v1)/ ノード帳
      (`b"nods"` = nodes.tlv v1、smctl / s3-controller 互換)/ CASE resumption 素材
      (`b"rsm<node16hex>"`、ポートローカル 49B)。init 末尾で復元。
  - `Cargo.toml`: feature `controller`(default on)= `simple-matter/controller` を引き込む。
    無効ビルド(`--no-default-features`)では `sm_ctrl_*` シンボルは出力されない
    (デバイス専用構成のフットプリント不変)。
  - `lib.rs`: `CRng` / `CKvs` / `cstr_key` / アドレス変換を `pub(crate)` 化して共有。
  - ヘッダ再生成(冪等)。Rust 単体テスト +1(`ctrl_lifecycle_roundtrip`: context_size/
    align・供給メモリ init/deinit・二重 init 拒否・pair_start の PASE 発行 + PAIR_PHASE
    イベント + TX 排出・deinit→再 init での CA/ノード帳復元)。
- `crates/simple-matter-cffi/ctest/controller.cpp`(新規)+ Makefile / .gitignore:
  ホスト C++17 テストコントローラ。`aligned_alloc` で供給メモリを確保して `sm_ctrl_init`
  に渡す(= 供給メモリ経路の実証)。標準入力から `pair` / `toggle` / `read` / `resolve`
  コマンドを 1 行ずつ実行する。
- `ports/esp-idf/examples/controller_hub_cpp`(新規、esp32s3): ビルド検証用の最小 main。
  WiFi 接続 → PSRAM に `heap_caps_aligned_alloc(MALLOC_CAP_SPIRAM)`(無ければ internal)で
  供給メモリを確保 → `sm_ctrl_init` → 固定ノード 1 台を pairing → 30 秒毎 Toggle。KVS は
  NVS(namespace `smctl`。resumption キーは NVS 15 文字制限のため短縮)。`sdkconfig.defaults`
  (partition 2MB / IPv6 / main task 16KB スタック)+ `sdkconfig.defaults.esp32s3`(SPIRAM 有効)。

ゲート(実測):
- `cargo test --workspace` = 639 pass(564 core + 14 cffi(新規 1 含む)+ 60 smctl 他、
  0 failed、回帰なし)。clippy 0(default / `--no-default-features` 両方、workspace 全体)。
  ヘッダ冪等。
- riscv32imac `--features panic-abort` .a green(`sm_ctrl_*` 15 シンボルが `T`)+
  `--no-default-features --features panic-abort` .a green(`sm_ctrl_*` 0 = フットプリント不変)。
  **xtensa** `cargo +esp build … -Zbuild-std=core --features panic-abort` .a green
  (`sm_ctrl_*` 15 シンボル)。
- **ホスト E2E(核心)green**: `controller.cpp`(供給メモリ malloc)↔ デバイス側シム
  `ctest/onoff_light`(シム同士の相互)、127.0.0.1、状態ディレクトリ分離。
  - `pair 0xAABBCCDD 20202021 127.0.0.1 5540` → PASE→ArmFailSafe→(Attestation skip)→
    CSR→AddTrustedRoot→AddNOC→CASE→CommissioningComplete = **PAIR OK**。
  - `toggle` → INVOKE_DONE(デバイス EVENT COMMISSIONED + ONOFF_CHANGED)、`read` → value=1
    (点灯状態一致)。
  - **コントローラプロセス再起動** → `nodes=1` 復元(nodes.tlv v1)→ `toggle` が
    `CASE_ESTABLISHED resumed=1`(**Sigma2Resume**)で確立 → INVOKE_DONE、`read` value=1。
  - `供給メモリ経路`: `sm_ctrl_context_size()` = 25,816 B(ホスト x86_64、align 8)を
    `aligned_alloc` で確保して `sm_ctrl_init` に渡す経路で全 E2E を実施。
- **ESP-IDF docker(`espressif/idf:release-v5.4`、`SM_PREBUILT_A` 経路)**:
  - **controller_hub_cpp esp32s3 build green**: `Project build complete`、app 947,968 B
    (`0xe7500`、partition 55% free)。ELF に `sm_ctrl_init` / `sm_ctrl_pair_start` /
    `sm_ctrl_invoke` ほか 11 シンボルが `T`(main.cpp 参照分。未参照は GC)。
  - **onoff_light_cpp esp32c6(WiFi/BLE)回帰 build green**(riscv prebuilt、`sm_init` /
    `sm_udp_rx` / `sm_poll` 健在)。
  - docker 終了時にコンテナ内で `build/`・`sdkconfig` を rm(root 所有残骸なし)。
- **デバイス側シム回帰 green**: smctl `pairing address 0x1234 20202021 127.0.0.1 5540` →
  CommissioningComplete(既存 F1 経路が壊れていないことを確認)。

コア(`crates/simple-matter`)への変更ゼロ(K1 の controller / ca / nodes codec と
`ControllerStack` / `Commissioner` / `MdnsClient` の pub 契約のみで実装。供給メモリの
自己参照 `&'static` は `CtrlShim` がシム内で確定して満たす)。

**実機(S3 ボード)E2E は未実施(残)**: 実機接続状況が未確認のため親の確認に委ねる。
ファーム(controller_hub_cpp)はビルド済みで即 flash 可能。**F7b(BLE central 給餌)は後続**。

差分メモ(§11.1 に対し実装で確定):
- `sm_ctrl_config_t` は KVS/RNG コールバック + `fabric_id` / `controller_node_id` /
  `vendor_id`(CA 生成素材。KVS に ca-state があればそちら優先)。verifier は不要
  (コントローラは passcode を `sm_ctrl_pair_start` 引数で受ける)。
- 運用操作は「単一トランザクション直列」: 進行中は新規要求を `-10`(busy)で拒否する。
  `sm_ctrl_resolve_start` は同期的にクエリバイト列を返す方式(TX キューを介さない。
  デバイス側 `sm_mdns_poll` と同型)。QM マルチキャストは `at=NULL` で対応。

### F7a 実機検証(AirQ = ESP32-S3、2026-07-18)

controller_hub_cpp を AirQ(S3FN8、PSRAM 非搭載)実機で E2E green:
WiFi join → 供給メモリ確保(SPIRAM 不在 → 内部 RAM フォールバック、
context 25,560B)→ ホスト PC のシムデバイスへ **PAIR COMPLETE(~6 秒)** →
30 秒毎 toggle OK → リブートで CA/ノード帳復元(nodes=1)→ 再 pair なしで
toggle 成立(resumption)。

実機で直した 2 点(いずれも既知知見の適用漏れ):
1. `CONFIG_SPIRAM_IGNORE_NOTFOUND=y` — PSRAM 必須設定のままだと非搭載
   ボードで boot loop("Failed to init external RAM!" abort)。
2. **メインタスクスタック 128KB**(`CONFIG_ESP_MAIN_TASK_STACK_SIZE=131072`)—
   16KB では sm_ctrl の in-place 構築 + P-256 署名チェーンでスタック破壊し、
   LoadProhibited / IntegerDivideByZero のリセットループ(F2 の 128KB 知見と
   同根。コントローラ側にも同様に必要)。
PSRAM 実搭載ボードでの SPIRAM 配置確認は P4 等の機材があるときに。
