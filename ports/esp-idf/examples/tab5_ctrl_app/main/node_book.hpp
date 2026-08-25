// ノード帳(NVS namespace "smctl" のキー "nods")から NodeId を列挙する。
//
// なぜ要るか: C FFI シムには `sm_ctrl_node_count()`(件数)と
// `sm_ctrl_node_addr(node_id, ...)`(引き当て)はあるが、**NodeId を列挙する入口が
// ない**。GUI は「起動時にノード帳の中身を一覧にする」ため NodeId そのものが要る。
// コア/シム(crates/)は無改造という制約があるので、シムが書いた永続化バイト列を
// C++ 側で読み直す(フォーマットは smctl `nodes.tlv` v1 = 安定仕様。
// crates/simple-matter/src/controller/nodes.rs の doc コメント):
//
//   struct(anonymous) { 0: u8 version(=1)
//                       1: array of struct { 0: u64 node_id, 1: utf8 label,
//                                            2: bytes ip, 3: u16 port } }
//
// 読み取り専用。書き込みは常にシム(sm_ctrl_*)が行う。

#pragma once

#include <cstddef>
#include <cstdint>

// NVS の "smctl"/"nods" を読んで NodeId を `out` へ書く。戻り値 = 書いた件数。
// NVS 未初期化 / キー無し / パース失敗はすべて 0(エラーではなく「居ない」扱い)。
size_t sm_node_ids_from_nvs(uint64_t *out, size_t cap);
