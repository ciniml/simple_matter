// 設定 blob(composition / binding)の NVS 格納とコンソール(§9.2)。
//
// NVS namespace `smgen`:
//   key "comp" = composition TLV(§9.1)
//   key "bind" = binding TLV(§9.2 / bind_tlv.hpp)
//
// 変更は再起動で反映する(エンドポイント構成の変更は Matter 的にも再起動が自然)。
#pragma once

#include <cstddef>
#include <cstdint>

namespace smgen {

// 設定 blob の上限(NVS blob。EP 8 × クラスタ 12 でも十分な余裕)。
static constexpr size_t kMaxBlob = 1024;

// NVS namespace(コンソール・ローダで共有)。
static constexpr const char *kNvsNamespace = "smgen";

// blob を読む。戻り値 = 読めたバイト数(0 = 未設定 / 失敗)。
size_t cfg_load(const char *key, uint8_t *buf, size_t cap);

// blob を書く(commit まで)。成功で true。
bool cfg_save(const char *key, const uint8_t *val, size_t len);

// blob を消す(存在しなくても成功)。
bool cfg_erase(const char *key);

// esp_console REPL(USB-Serial-JTAG)を起動し、cfg-* コマンドを登録する。
// コンソールタスクは sm_* を一切呼ばない(NVS と esp_restart のみ)。
void console_start();

} // namespace smgen
