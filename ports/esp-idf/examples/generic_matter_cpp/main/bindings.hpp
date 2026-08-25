// HAL バインディング層(G2、docs/design/generic-firmware.md §9.2)。
//
// binding TLV(bind_tlv.hpp)で宣言された「クラスタ ⇔ ドライバ」の表を保持し、
//
//   - `sm_config_t.on_cluster_change`(IM write / コマンド由来の属性変化)→ 出力ドライバ
//     (gpio_out / ledc)へ dispatch
//   - 周期ポーリング(gpio_in / i2c_sht30)→ `sm_attr_set_value` で属性へ push
//
// の 2 方向を担う。すべて matter pump タスク(単線)から呼ぶこと。
#pragma once

#include "bind_tlv.hpp"

#include "simple_matter.h"

namespace smgen {

// バインディング表を受け取り、各ドライバのハードウェアを初期化する。
// `table` は内部にコピーされる(以降の poll/dispatch は内部表を使う)。
void bindings_init(const BindingTable &table);

// 合成済みクラスタの現在値をハードウェアへ初期反映する(sm_init 直後に 1 回)。
void bindings_apply_initial();

// `on_cluster_change` からの dispatch(OnOff → gpio_out/ledc、LevelControl → ledc duty)。
void bindings_on_change(uint16_t ep, uint32_t cluster, uint32_t attr, const sm_attr_value_t *value);

// 入力系ドライバの周期処理(gpio_in のポーリング + デバウンス、i2c_sht30 の計測)。
void bindings_poll(uint64_t now_ms);

// 表の内容をログに出す(cfg-show / 起動時)。
void bindings_log();

// Matter クラスタ ID(このレイヤで意味を持つもの)。
static constexpr uint32_t kClOnOff = 0x0006;
static constexpr uint32_t kClLevel = 0x0008;
static constexpr uint32_t kClSwitch = 0x003B;
static constexpr uint32_t kClBoolean = 0x0045;
static constexpr uint32_t kClTemperature = 0x0402;
static constexpr uint32_t kClHumidity = 0x0405;

} // namespace smgen
