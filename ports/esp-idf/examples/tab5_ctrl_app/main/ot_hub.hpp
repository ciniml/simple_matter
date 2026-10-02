// OT ホスト(M5Stack Tab5 = ESP32-P4 + Unit Gateway H2 の RCP over UART)の配線。
// docs/design/p4-thread-controller.md §3 F8c / §9 T1。
//
// thread_ctrl_hub_cpp/main/ot_hub.{hpp,cpp}(実機 P9 で確定した配線)のコピーに、
// GUI 用のステータス取得(sm_ot_hub_get_status / sm_ot_hub_dataset_hex)を足したもの。
// F8e(border router)の足場は本アプリには持ち込んでいない。
//
// 責務: esp_openthread の初期化(RADIO_MODE_UART_RCP)、Thread ネットワークの
// 生成/復元と leader 化、SRP サーバの有効化、SRP サーバ帳からのデバイス
// アドレス逆引き(F8b `sm_ctrl_set_node_addr` の実戦配線)。
//
// 注意: ここの関数は全て内部で esp_openthread_lock_acquire/release を取る。
// LVGL タスクから呼んでも安全だが、実際の呼び出しは pump タスクに集約している
//(sm_ctrl_* の単線契約と足並みを揃えるため)。

#pragma once

#include <cstddef>
#include <cstdint>

// OT スタックを起動する(専用タスク + eventfd 登録)。戻ると OT インスタンスは
// まだ準備中の可能性がある(sm_ot_hub_wait_ready を使う)。
void sm_ot_hub_init();

// OT インスタンスが使えるようになるまで待つ。timeout_ms で諦める。
bool sm_ot_hub_wait_ready(uint32_t timeout_ms);

// --- Thread の動作モード(§18 T11 / P1)---
//   FORM: 自前のネットワークを主宰する(dataset 復元/生成、leader、SRP サーバ)= 従来動作。
//   JOIN: 外部(OTBR 等)のネットワークへ 1 ノードとして参加する。与えられた dataset を
//         active に適用し、SRP サーバは **起動しない**(登録先が割れるため)。
// 決定順は NVS("smui"/"otmode")→ Kconfig(SM_THREAD_MODE)。
enum sm_ot_mode_t : uint8_t {
  SM_OT_MODE_FORM = 0,
  SM_OT_MODE_JOIN = 1,
};

// 現在のモード(起動時に一度決めてキャッシュする。NVS だけを読むので OT 起動前でも呼べる)。
sm_ot_mode_t sm_ot_hub_mode();
const char *sm_ot_hub_mode_name(sm_ot_mode_t m);

// モードを NVS に保存する(反映は再起動後)。`dataset_hex` が非 null・非空なら JOIN 用の
// dataset(TLV hex)として NVS("smui"/"otjoin_ds")へ保存する。hex が不正なら false。
// dataset は network key を含むので **ログには出さない**。
bool sm_ot_hub_mode_save(sm_ot_mode_t mode, const char *dataset_hex);

// JOIN 用 dataset の出所("nvs" / "kconfig" / "none")。
const char *sm_ot_hub_join_dataset_source();

// OT netif が持つユニキャスト IPv6 アドレスを 1 行 1 個で `out` へ書く(診断用)。戻り値 = 個数。
size_t sm_ot_hub_addrs(char *out, size_t cap);

// Thread ネットワークを用意して起動する(モードで分岐):
//  FORM:
//   0. JOIN 時に退避した自前 dataset(NVS "smui"/"otform_ds")があれば復元して退避を消す
//   1. NVS に active dataset があればそれを使う(OT の settings は "nvs" パーティション)
//   2. なければ CONFIG_SM_THREAD_DATASET_TLV_HEX(非空)を適用
//   3. それも空なら otDatasetCreateNewNetwork で新規生成
//   → Thread 起動 + SRP サーバ有効化
//  JOIN:
//   1. dataset = NVS "otjoin_ds" → CONFIG_SM_THREAD_DATASET_TLV_HEX。どちらも空なら
//      Thread を起動せず false(勝手に新規ネットワークを作らない)
//   2. OT の active dataset と異なれば、自前 dataset を "otform_ds" へ退避(未退避のときだけ)
//      してから otDatasetSetActiveTlvs で上書き
//   → Thread 起動(SRP サーバは触らない)
bool sm_ot_hub_start_network();

// attach 済み(child/router/leader)か。
bool sm_ot_hub_is_attached();

// leader になるまで待つ(戻り値 = leader になれたか)。FORM 用。
bool sm_ot_hub_wait_leader(uint32_t timeout_ms);

// attach(child / router / leader)まで待つ。JOIN 用。
bool sm_ot_hub_wait_attached(uint32_t timeout_ms);

// OT netif の実装インデックス(IPv6 リンクローカル宛の sin6_scope_id に使う)。
uint32_t sm_ot_hub_netif_index();

// SRP サーバに登録されているホストから、インスタンス名に `node_id` の 16 hex を
// 含むサービスを探し、そのホストの IPv6 アドレスを out_ip[16] へ書く。
// Thread では mDNS ではなく SRP がデバイスの運用アドレスの出所になる(F8b)。
// JOIN モードでは自分の SRP サーバ帳が無いので常に false(呼び出し側は保存アドレス /
// WiFi mDNS へフォールバックする。OT DNS client による解決は P2)。
bool sm_ot_hub_srp_lookup(uint64_t node_id, uint8_t out_ip[16]);

// SRP サーバの登録内容をログに出す(デバッグ補助)。
void sm_ot_hub_dump_srp();

// --- GUI 用のステータス取得(T1)---

// Thread の現況(ステータスバー表示用)。
struct sm_ot_status_t {
  uint8_t mode;     // sm_ot_mode_t(FORM / JOIN)
  bool started;     // Thread を起動したか(JOIN で dataset 無しなら false)
  int role;         // otDeviceRole(0=disabled 1=detached 2=child 3=router 4=leader)
  uint16_t rloc16;  // RLOC16(attach 前は不定)
  uint8_t channel;  // 802.15.4 チャネル
  uint16_t panid;   // PAN ID
  bool srp_enabled; // SRP サーバが動いているか
  uint32_t srp_hosts;   // SRP に登録されているホスト数
  char netname[17]; // ネットワーク名(NUL 終端)
};

// 現況を読む(OT ロックは内部で取る)。
void sm_ot_hub_get_status(sm_ot_status_t *out);

// active dataset の TLV を hex(小文字、NUL 終端)で `out` へ書く。
// 戻り値 = 書いた文字数(0 = dataset 未設定 / バッファ不足)。cap は 2*254+1 あれば十分。
size_t sm_ot_hub_dataset_hex(char *out, size_t cap);
