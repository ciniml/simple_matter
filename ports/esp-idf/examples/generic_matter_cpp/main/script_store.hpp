// ScriptStore vendor クラスタ(0xFFF1FC01)= スクリプト OTA(§9.4 / G4)。
//
// **ESP-IDF 非依存のヘッダオンリー**(ファーム・ホストループバックテストで共用)。
// 格納先(フラッシュ / メモリ / ファイル)と VM 再ロードは `ScriptStoreBackend` の
// 関数ポインタで注入する:
//
//   - ファーム   : script_store.cpp(esp_partition + script_host の再ロード)
//   - ホスト検証 : crates/simple-matter-cffi/ctest/scriptstore_loopback.cpp(メモリ backend)
//
// イメージ形式・スロット規則は script_img.hpp(Phase C と共通)。ヘッダは**本体を
// 全部書き終えてから最後に**書くので、途中で電源が落ちたスロットは「magic 無し =
// 無効」となり、旧スロットがそのまま active であり続ける。
//
//   commands: Begin(0x00: size u32, crc32 u32) / Data(0x01: offset u32, bytes octstr)
//             Commit(0x02) / Abort(0x03)
//   attributes: State(0x0000 u8) / ActiveSlot(0x0001 u8) / Version(0x0002 u32)
//               ChunkMax(0x0003 u16、シムの octstr 上限 = 64B を通知する拡張)
//
// 状態遷移(State):
//
//   IDLE(0) --Begin--> RECEIVING(1) --Commit--> COMMITTING(2) --poll(reload ok)--> IDLE
//        ^                  |                        |
//        |                  +--Abort----------------+--poll(reload 失敗 = ロールバック)
//        +--Abort/Begin-- ERROR(3) <--CRC 不一致 / 書き込み失敗---------------------+
//
// Begin は RECEIVING / ERROR からも受け付ける(やり直し)。COMMITTING 中の
// Begin/Data/Commit は Busy(0x9c)。
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "script_img.hpp"
#include "simple_matter.h"

namespace smgen {

// ---- クラスタ / コマンド / 属性 ID -------------------------------------------

static constexpr uint32_t kClScriptStore = 0xFFF1FC01u;

static constexpr uint32_t kSsCmdBegin = 0x00;
static constexpr uint32_t kSsCmdData = 0x01;
static constexpr uint32_t kSsCmdCommit = 0x02;
static constexpr uint32_t kSsCmdAbort = 0x03;

static constexpr uint32_t kSsAttrState = 0x0000;
static constexpr uint32_t kSsAttrActiveSlot = 0x0001;
static constexpr uint32_t kSsAttrVersion = 0x0002;
static constexpr uint32_t kSsAttrChunkMax = 0x0003;

// State の値。
enum ScriptStoreState : uint8_t {
  SS_IDLE = 0,
  SS_RECEIVING = 1,
  SS_COMMITTING = 2,
  SS_ERROR = 3,
};

// ActiveSlot の「スクリプト無し」表現。
static constexpr uint8_t kSsNoSlot = 0xFF;

// Data 1 発で運べる最大バイト数。**シムの `sm_attr_value_t` は octstr を 64B 固定
// バッファで運ぶ**(`STR_CAP`)ため、§9.4 の「≤512」ではなく 64 が実効上限になる
// (シム無改造の制約。README / §10 Phase D の罠)。
static constexpr uint32_t kSsChunkMax = 64;

// フラッシュへ吐き出す単位(4B アライン要求を吸収し、書き込み回数を減らす)。
static constexpr size_t kSsStagingSize = 512;

// IM ステータス(下位バイト。crates/simple-matter/src/im/wire.rs)。
static constexpr uint8_t kImSuccess = 0x00;
static constexpr uint8_t kImFailure = 0x01;
static constexpr uint8_t kImInvalidCommand = 0x85;
static constexpr uint8_t kImUnsupportedWrite = 0x88;
static constexpr uint8_t kImConstraintError = 0x87;
static constexpr uint8_t kImResourceExhausted = 0x89;
static constexpr uint8_t kImBusy = 0x9C;

// ---- 格納バックエンド --------------------------------------------------------

struct ScriptStoreBackend {
  void *user = nullptr;
  // スロット先頭から少なくとも len バイトを消去する(実装側で 4KB 単位へ切り上げる)。
  bool (*erase)(void *user, size_t slot, size_t len) = nullptr;
  // スロット内オフセット off へ書く(off / len は 4B アラインで渡す)。
  bool (*write)(void *user, size_t slot, size_t off, const uint8_t *data, size_t len) = nullptr;
  // スロット内オフセット off から読む(commit の CRC 検証で使う)。
  bool (*read)(void *user, size_t slot, size_t off, uint8_t *out, size_t len) = nullptr;
  // VM を「現在の active slot」から読み直す。false = ロード失敗(→ ロールバック)。
  // nullptr = 再ロードしない(= 再起動で反映。commit は成功扱い)。
  bool (*reload)(void *user) = nullptr;
  // 属性変化を購読へ反映する(sm_attr_mark_dirty の注入。nullptr 可)。
  void (*mark_dirty)(void *user, uint32_t attr_id) = nullptr;
  // invoke を受けたことをスクリプトへ通知する(on_command フック。nullptr 可)。
  // **戻り値は見ない**: 壊れたスクリプトが ScriptStore を塞いで文鎮化するのを防ぐ。
  void (*on_command)(void *user, uint32_t cluster, uint32_t cmd) = nullptr;
  // ログ(nullptr 可)。
  void (*log)(void *user, const char *msg) = nullptr;
};

// ---- 受信ステートマシン -------------------------------------------------------

class ScriptStore {
public:
  // 起動時に 1 度。`active_slot` < 0 = スクリプト未搭載。
  void configure(const ScriptStoreBackend &be, int active_slot, uint16_t active_ver) {
    be_ = be;
    active_ = active_slot;
    ver_ = active_ver;
    state_ = SS_IDLE;
    reset_transfer();
  }

  uint8_t state() const { return state_; }
  uint8_t active_slot() const { return active_ < 0 ? kSsNoSlot : (uint8_t)active_; }
  uint32_t version() const { return ver_; }
  uint32_t received() const { return received_; }
  uint32_t expected() const { return size_; }
  int target_slot() const { return target_; }
  bool commit_pending() const { return commit_pending_; }

  // ---- コマンド(戻り値 = IM ステータス)----

  uint8_t cmd_begin(uint32_t size, uint32_t crc32) {
    if (state_ == SS_COMMITTING) {
      return kImBusy;
    }
    if (size == 0 || size > kScriptMaxLen) {
      return kImConstraintError;
    }
    if (be_.erase == nullptr || be_.write == nullptr || be_.read == nullptr) {
      return kImFailure;
    }
    // 書き込み先 = 非 active スロット(未搭載なら A)。
    target_ = (active_ == 0) ? 1 : 0;
    reset_transfer();
    if (!be_.erase(be_.user, (size_t)target_, kScriptHdrSize + size)) {
      set_state(SS_ERROR);
      log("begin: erase failed");
      return kImFailure;
    }
    size_ = size;
    crc_ = crc32;
    set_state(SS_RECEIVING);
    return kImSuccess;
  }

  uint8_t cmd_data(uint32_t offset, const uint8_t *bytes, uint32_t len) {
    if (state_ == SS_COMMITTING) {
      return kImBusy;
    }
    if (state_ != SS_RECEIVING) {
      return kImInvalidCommand;
    }
    if (bytes == nullptr || len == 0 || len > kSsChunkMax) {
      return kImConstraintError;
    }
    // **順次のみ**(offset は受信済みバイト数と一致すること。再送 = 同一 offset も不可)。
    if (offset != received_) {
      log("data: out-of-order offset");
      return kImConstraintError;
    }
    if (received_ + len > size_) {
      return kImResourceExhausted;
    }
    memcpy(staging_ + staged_, bytes, len);
    staged_ += len;
    received_ += len;
    if (staged_ >= kSsStagingSize && !flush(false)) {
      set_state(SS_ERROR);
      return kImFailure;
    }
    return kImSuccess;
  }

  uint8_t cmd_commit() {
    if (state_ == SS_COMMITTING) {
      return kImBusy;
    }
    if (state_ != SS_RECEIVING) {
      return kImInvalidCommand;
    }
    if (received_ != size_) {
      log("commit: size mismatch");
      set_state(SS_ERROR);
      return kImConstraintError;
    }
    if (!flush(true)) {
      set_state(SS_ERROR);
      return kImFailure;
    }
    // 書き込んだ本体を読み返して CRC を検証する(転送とフラッシュの両方を確かめる)。
    if (!verify_crc()) {
      log("commit: CRC mismatch");
      set_state(SS_ERROR);
      return kImConstraintError;
    }
    // ヘッダを最後に書く = ここで初めて「妥当なスロット」になる。ver は現行 +1
    // (active slot 判定は ver 最大。script_img.hpp)。
    ScriptHeader h;
    h.ver = next_ver();
    h.flags = 0;
    h.len = size_;
    h.crc32 = crc_;
    uint8_t hdr[kScriptHdrSize];
    script_hdr_write(hdr, h);
    if (!be_.write(be_.user, (size_t)target_, 0, hdr, sizeof(hdr))) {
      set_state(SS_ERROR);
      log("commit: header write failed");
      return kImFailure;
    }
    new_ver_ = h.ver;
    commit_pending_ = true;
    set_state(SS_COMMITTING);
    return kImSuccess;
  }

  uint8_t cmd_abort() {
    if (state_ == SS_COMMITTING) {
      return kImBusy; // 再ロード中は中断できない(poll で決着する)。
    }
    reset_transfer();
    set_state(SS_IDLE);
    return kImSuccess;
  }

  // pump ループから毎周回。Commit で保留した VM 再ロードを**フックの外**で実行する
  // (invoke ハンドラの中で VM を落とすと単線契約と再入の扱いが難しくなるため)。
  void poll() {
    if (!commit_pending_) {
      return;
    }
    commit_pending_ = false;
    const int prev_slot = active_;
    const uint16_t prev_ver = ver_;
    active_ = target_;
    ver_ = new_ver_;
    if (be_.reload == nullptr || be_.reload(be_.user)) {
      log("commit: activated");
      reset_transfer();
      set_state(SS_IDLE);
      return;
    }
    // ロード失敗 → 新スロットのヘッダを潰して旧スロットへ戻す(script_img の
    // active 判定は「妥当なヘッダのうち ver 最大」なので、ヘッダ消去で無効化できる)。
    log("commit: load failed; rolling back");
    if (be_.erase != nullptr) {
      (void)be_.erase(be_.user, (size_t)target_, kScriptHdrSize);
    }
    active_ = prev_slot;
    ver_ = prev_ver;
    if (be_.reload != nullptr) {
      (void)be_.reload(be_.user); // 旧スロットで復帰(スクリプト無しもあり得る)
    }
    reset_transfer();
    set_state(SS_ERROR);
  }

  // ---- クラスタ vtable の実体 ----

  uint8_t read_attr(uint32_t attr_id, sm_attr_value_t *out) const {
    memset(out, 0, sizeof(*out));
    switch (attr_id) {
    case kSsAttrState:
      out->type = SM_T_U8;
      out->v.u = state_;
      return kImSuccess;
    case kSsAttrActiveSlot:
      out->type = SM_T_U8;
      out->v.u = active_slot();
      return kImSuccess;
    case kSsAttrVersion:
      out->type = SM_T_U32;
      out->v.u = ver_;
      return kImSuccess;
    case kSsAttrChunkMax:
      out->type = SM_T_U16;
      out->v.u = kSsChunkMax;
      return kImSuccess;
    default:
      return kImFailure;
    }
  }

  uint8_t invoke(uint32_t cmd_id, const sm_attr_value_t *args, size_t n_args) {
    if (be_.on_command != nullptr) {
      be_.on_command(be_.user, kClScriptStore, cmd_id);
    }
    const uint8_t before = state_;
    const uint8_t st = dispatch(cmd_id, args, n_args);
    if (state_ != before && be_.mark_dirty != nullptr) {
      be_.mark_dirty(be_.user, kSsAttrState);
    }
    return st;
  }

private:
  uint8_t dispatch(uint32_t cmd_id, const sm_attr_value_t *args, size_t n_args) {
    switch (cmd_id) {
    case kSsCmdBegin: {
      uint32_t size = 0, crc = 0;
      if (n_args < 2 || !arg_u32(args[0], size) || !arg_u32(args[1], crc)) {
        return kImInvalidCommand;
      }
      return cmd_begin(size, crc);
    }
    case kSsCmdData: {
      uint32_t off = 0;
      if (n_args < 2 || !arg_u32(args[0], off) || args[1].type != SM_T_OCTETS) {
        return kImInvalidCommand;
      }
      return cmd_data(off, args[1].v.bytes.buf, args[1].v.bytes.len);
    }
    case kSsCmdCommit:
      return cmd_commit();
    case kSsCmdAbort:
      return cmd_abort();
    default:
      return kImInvalidCommand;
    }
  }

  // invoke 引数は TLV から平坦化されるので符号なし整数は SM_T_U64 で来る
  // (デバイス内テストから U8/U16/U32 で渡すこともあるので全部受ける)。
  static bool arg_u32(const sm_attr_value_t &a, uint32_t &out) {
    switch (a.type) {
    case SM_T_U8:
    case SM_T_U16:
    case SM_T_U32:
    case SM_T_U64:
      if (a.v.u > 0xFFFFFFFFull) {
        return false;
      }
      out = (uint32_t)a.v.u;
      return true;
    default:
      return false;
    }
  }

  void reset_transfer() {
    size_ = 0;
    crc_ = 0;
    received_ = 0;
    staged_ = 0;
    flushed_ = 0;
    commit_pending_ = false;
  }

  void set_state(uint8_t s) { state_ = s; }

  void log(const char *msg) {
    if (be_.log != nullptr) {
      be_.log(be_.user, msg);
    }
  }

  // staging を書き出す。final=true なら端数を 0xFF で 4B アラインまで詰める。
  bool flush(bool final_chunk) {
    if (staged_ == 0) {
      return true;
    }
    size_t n = staged_;
    if (final_chunk) {
      while ((n % 4) != 0) {
        staging_[n++] = 0xFF;
      }
    } else {
      n -= (n % 4); // 端数は次回へ持ち越す
      if (n == 0) {
        return true;
      }
    }
    if (!be_.write(be_.user, (size_t)target_, kScriptHdrSize + flushed_, staging_, n)) {
      log("flush: write failed");
      return false;
    }
    const size_t left = staged_ - (final_chunk ? staged_ : n);
    if (left > 0) {
      memmove(staging_, staging_ + n, left);
    }
    flushed_ += n;
    staged_ = left;
    return true;
  }

  bool verify_crc() const {
    uint8_t buf[128];
    uint32_t crc = 0;
    size_t off = 0;
    while (off < size_) {
      const size_t n = (size_ - off < sizeof(buf)) ? (size_t)(size_ - off) : sizeof(buf);
      if (!be_.read(be_.user, (size_t)target_, kScriptHdrSize + off, buf, n)) {
        return false;
      }
      crc = script_crc32(buf, n, crc);
      off += n;
    }
    return crc == crc_;
  }

  uint16_t next_ver() const {
    // ver は u16(script_img)。飽和したら 1 へ巻き戻す(旧スロットは必ず無効化済み)。
    return (ver_ >= 0xFFFEu) ? (uint16_t)1 : (uint16_t)(ver_ + 1);
  }

  ScriptStoreBackend be_{};
  uint8_t state_ = SS_IDLE;
  int active_ = -1;    // 現在の active slot(-1 = 無し)
  uint16_t ver_ = 0;   // active イメージの ver
  int target_ = 0;     // 受信中スロット
  uint16_t new_ver_ = 0;
  uint32_t size_ = 0;     // Begin で宣言された本体サイズ
  uint32_t crc_ = 0;      // Begin で宣言された CRC32
  uint32_t received_ = 0; // Data で受けたバイト数
  size_t staged_ = 0;     // staging 内の未書き出しバイト数
  size_t flushed_ = 0;    // 書き出し済みバイト数
  bool commit_pending_ = false;
  // 吐き出し判定はチャンクを積んだ**後**なので、1 チャンク分と 4B パディング分の
  // 余裕を持たせる。
  uint8_t staging_[kSsStagingSize + kSsChunkMax + 4] = {};
};

// プロセス唯一の ScriptStore(クラスタ vtable の ctx)。
inline ScriptStore &script_store() {
  static ScriptStore s;
  return s;
}

// ---- CustomCluster(F4b)への登録 ---------------------------------------------

extern "C" inline uint8_t script_store_read_cb(void *ctx, uint32_t attr_id,
                                               sm_attr_value_t *out) {
  return ((const ScriptStore *)ctx)->read_attr(attr_id, out);
}

extern "C" inline uint8_t script_store_write_cb(void *, uint32_t, const sm_attr_value_t *) {
  return kImUnsupportedWrite; // 全属性 read-only(変更はコマンド経由)
}

extern "C" inline uint8_t script_store_invoke_cb(void *ctx, uint32_t cmd_id,
                                                 const sm_attr_value_t *args, size_t n_args,
                                                 uint64_t) {
  return ((ScriptStore *)ctx)->invoke(cmd_id, args, n_args);
}

// `sm_init` より前に呼ぶ。戻り値は `sm_cluster_register` の rc(0 = OK)。
// 認可は F4b の既定(read=View / invoke=Operate)。Administer 指定の口はシムに無い。
inline int script_store_register(uint16_t endpoint, ScriptStore &store) {
  static const sm_attr_def_t attrs[] = {
      {kSsAttrState, SM_T_U8, 0},
      {kSsAttrActiveSlot, SM_T_U8, 0},
      {kSsAttrVersion, SM_T_U32, 0},
      {kSsAttrChunkMax, SM_T_U16, 0},
  };
  static const sm_cmd_def_t cmds[] = {
      {kSsCmdBegin, 0},
      {kSsCmdData, 0},
      {kSsCmdCommit, 0},
      {kSsCmdAbort, 0},
  };
  sm_cluster_def_t def;
  memset(&def, 0, sizeof(def));
  def.endpoint = endpoint;
  def.cluster_id = kClScriptStore;
  def.revision = 1;
  def.feature_map = 0;
  def.attrs = attrs;
  def.n_attrs = sizeof(attrs) / sizeof(attrs[0]);
  def.cmds = cmds;
  def.n_cmds = sizeof(cmds) / sizeof(cmds[0]);
  def.read = script_store_read_cb;
  def.write = script_store_write_cb;
  def.invoke = script_store_invoke_cb;
  def.ctx = &store;
  return (int)sm_cluster_register(&def);
}

// ---- ESP-IDF 側の受け皿(script_store.cpp。ホストテストでは未使用)-------------

// smscript パーティションを backend にして ScriptStore を登録する(sm_init より前)。
bool script_store_init(uint16_t endpoint);
// pump ループから毎周回(保留中の再ロードを実行する)。
void script_store_poll();
// 状態をログに出す。
void script_store_log_status();

} // namespace smgen
