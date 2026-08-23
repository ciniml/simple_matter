# tab5_ctrl_app — M5Stack Tab5 の LVGL Matter コントローラ

M5Stack **Tab5**(ESP32-P4 + 5 インチ 1280x720 タッチ)と **Unit Gateway H2**
(`ot_rcp`、spinel over UART)で動く **Thread ネットワーク主宰(leader)兼 SRP サーバ兼
Matter コントローラ**の GUI 版。設計は `docs/design/p4-thread-controller.md` §9(T1)、
土台の CUI 版は `thread_ctrl_hub_cpp`(同 §3 F8c / §8 P9 で実機動作確定)。

BLE は使わない。コミッショニングは **on-network PASE over Thread UDP**
(デバイスを同じ active dataset で Thread に参加させてから、その IPv6 へ PASE)。

## 画面(v1)

```
┌──────────────────────────────────────────────────────────────────────┐
│ Thread Leader  net=... ch=15 pan=0x.... rloc=0x....  SRP:on(1) nodes:1 │ ← ステータスバー
│ toggle 00000000aabbccdd OK (status=0)          heap 210kB / psram ...  │
├── Devices ── Network ─────────────────────────────────────────────────┤
│ [+ Pair new device] [⟳ Redraw list]                                   │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ Node 0x00000000aabbccdd     [ON]  toggle OK  [Toggle][Read][⟳Addr]│ │
│ │ [fd..:...]:5540                                                    │ │
│ └───────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

- **ステータスバー**: Thread role / network name / channel / PAN ID / RLOC16 /
  SRP サーバ状態と登録ホスト数 / ノード数、内蔵 heap(最小値付き)と PSRAM、
  そして直近イベントの 1 行。
- **Devices タブ**: ノード帳の各ノードを 1 行(NodeId / 運用アドレス / On-Off バッジ /
  直近結果)。ボタンは `Toggle`(OnOff.Toggle)、`Read`(OnOff.OnOff 読み)、
  `⟳ Addr`(SRP サーバ帳から運用アドレスを引き直して `sm_ctrl_set_node_addr`)。
  加えて 10 秒周期で 1 ノードずつ read してバッジを更新する。
- **Pair ダイアログ**: `+ Pair new device` → IPv6 / NodeId(hex、自動採番・編集可)/
  passcode をオンスクリーンキーボードで入力 → `Start pairing` → フェーズ表示
  (PASE → ArmFailSafe → … → Done)→ 結果。
- **Network タブ**: Thread の詳細と **active dataset TLV hex**、その **QR**
  (`lv_qrcode`)。デバイス側へ dataset をプリセットするときの転記用。

## タスク構成(単線契約)

| タスク | 役割 |
|---|---|
| `app_main` | NVS / netif / event loop → BSP(表示・タッチ・LVGL)→ UI 構築 → pump 起動 |
| `ctrl_pump`(静的スタック **128KB**)| `sm_ctrl_*` を専有。UI の操作キューを 1 件ずつ実行 |
| `ot_main` | `esp_openthread` のメインループ |
| esp_lvgl_port の LVGL タスク | `lv_*` のみ。`sm_ctrl_*` / `ot*` は**呼ばない** |

UI → pump は FreeRTOS キューの `sm_ui_op_t`(Toggle / ReadOnOff / Pair / RefreshAddr)、
pump → UI は mutex 保護のスナップショット + LVGL の 500ms タイマ反映
(`main/app_state.hpp`)。タップは「キューに積むだけ」なので、pump が 20 秒の CASE を
待っていても画面は固まらない(ただし操作の実行はその分待たされる)。

## 構成ファイル

| ファイル | 中身 |
|---|---|
| `main/main.cpp` | 起動シーケンス、画面回転、**タッチ座標の回転補正**(下記の罠) |
| `main/ui.cpp` | LVGL の画面全部(sm_ctrl_* を一切呼ばない) |
| `main/ctrl_pump.cpp` | pump タスク(KVS / UDP / `run_until` は hub から流用) |
| `main/app_state.{hpp,cpp}` | 操作キュー + スナップショット(UI ↔ pump の唯一の連絡路) |
| `main/node_book.{hpp,cpp}` | NVS `smctl`/`nods` を TLV パースして NodeId を列挙 |
| `main/ot_hub.{hpp,cpp}` | hub のコピー + GUI 用ステータス取得(OT 配線は無改変) |
| `main/idf_component.yml` | `espressif/m5stack_tab5 ~1.2.0`(BSP。lvgl 9.5 / esp_lvgl_port を引く) |

## ビルド

```sh
# RCP(H2)側のファーム(Unit Gateway H2 に書く)
scripts/otbr/build-ot-rcp-h2.sh          # → scripts/otbr/dist/ot_rcp_h2/merged_ot_rcp.bin

# ホスト(Tab5 / P4)側
cd ports/esp-idf/examples/tab5_ctrl_app
rm -f sdkconfig
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" set-target esp32p4
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" build
```

docker(**`espressif/idf:release-v5.4` のままで BSP 1.2.0 / LVGL 9.5 が解決する**。
5.5 への切替は不要だった):

```sh
REPO=$(git rev-parse --show-toplevel)
docker run --rm -u $(id -u):$(id -g) \
  -v $REPO:$REPO -v $HOME/.cargo:$HOME/.cargo -v $HOME/.rustup:$HOME/.rustup \
  -v $HOME/.cache/Espressif:$HOME/.cache/Espressif \
  -e HOME=$HOME -e CCACHE_DISABLE=1 \
  -w $REPO/ports/esp-idf/examples/tab5_ctrl_app espressif/idf:release-v5.4 \
  bash -ec 'export PATH=$HOME/.cargo/bin:$PATH; rm -f sdkconfig;
            idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" set-target esp32p4 &&
            idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults" build'
```

Rust staticlib は経路 (b)(コンポーネントが `cargo build --target
riscv32imafc-unknown-none-elf` を実行)。経路 (a) は `-DSM_PREBUILT_A=...` を
`set-target` / `build` の両方に渡す。

## 書き込み

パーティションは `thread_ctrl_hub_cpp` と **nvs / phy_init のオフセット・サイズが同一**
なので、hub を書いた Tab5 に本アプリを上書きしてもコントローラのノード帳
(NVS `smctl`)と OT の active dataset はそのまま残る(= 既にコミッショニング済みの
デバイスが起動直後から一覧に出る)。**`erase-flash` はしないこと。**

```sh
idf.py -p /dev/ttyACM0 flash monitor
```

## 設定(`idf.py menuconfig` → "tab5_ctrl_app configuration")

- **RCP UART**: `SM_OT_UART_PORT`(1)/ `SM_OT_UART_RX_PIN`(**54**)/
  `SM_OT_UART_TX_PIN`(**53**)/ `SM_OT_UART_BAUD`(460800)。
  既定値は Tab5 の Port A(Grove)で実機確定済み(§8 P9)。53/54 が逆だと spinel 無応答。
- **Thread**: `SM_THREAD_DATASET_TLV_HEX`(空 = 新規ネットワーク生成。NVS 優先)。
- **Matter**: `SM_TARGET_PORT`(5540)、`SM_UI_DEFAULT_NODE_ID` / `SM_UI_DEFAULT_PASSCODE`
  (Pair ダイアログの初期値)、`SM_UI_FALLBACK_NODE_ID`。
- **表示/タッチ**: `SM_UI_ROTATION`(既定 90 = 1280x720 横)、
  `SM_UI_TOUCH_MIRROR_X` / `SM_UI_TOUCH_MIRROR_Y`。

## 実機手順

1. Unit Gateway H2 に `merged_ot_rcp.bin` を書き込み、Tab5 の **Port A** に挿す。
2. Tab5 に本アプリを flash → 画面が出て、ログに `ot_hub: thread role = 4`(Leader)。
3. Network タブの dataset TLV hex(または QR)をデバイス側にプリセットして起動。
4. デバイスのログの ML-EID / OMR を `+ Pair new device` の IPv6 欄へ入力 → `Start pairing`。
5. 一覧に出た行の `Toggle` でデバイスが点滅すれば完走。

## 踏んだ罠(次に触る人へ)

1. **LVGL 9.5 も esp_lvgl_port 2.9 もタッチ座標を画面回転に追従させない。**
   `lv_indev.c` に rotation 処理は無く、`esp_lvgl_port_touch.c` はタッチ IC の生座標を
   そのまま渡す。パネルは 720x1280(縦)なので、`lv_display_set_rotation(90)` すると
   タッチだけ 90 度ずれる。本アプリは `lv_indev_get_read_cb()` で元の read_cb を取り出し、
   回転変換を挟む形で包んでいる(`main.cpp` の `rotated_touch_read`)。
   実機で左右/上下が反転していたら `SM_UI_TOUCH_MIRROR_X/Y` を y にする。判断材料は
   起動直後のログ `touch: panel(x,y) -> screen(x,y) [screen 1280x720]`(先頭 5 点だけ出る)。
2. **シムに NodeId の列挙 API が無い**(`sm_ctrl_node_count` は件数、
   `sm_ctrl_node_addr` は引き当てのみ)。GUI の一覧を作るには NodeId そのものが要るので、
   シムが書いた NVS `smctl`/`nods`(smctl `nodes.tlv` v1 = 安定仕様)を C++ 側で
   TLV パースして読み直している(`main/node_book.cpp`。読み取り専用、コア/シムは無改造)。
3. **BSP の LVGL 描画バッファは内蔵 RAM の DMA 領域**。既定の 50 行だと
   720x50x2B のダブルバッファ + SW 回転用の 1 枚で約 216KB。pump の静的スタック 128KB と
   同居するので `CONFIG_BSP_LCD_DRAW_BUF_HEIGHT=40` に絞っている。
4. **`CONFIG_BSP_DISPLAY_LVGL_AVOID_TEAR=y` にすると SW 回転が無効化される**
   (`bsp_display.c`)。tear 対策を入れるなら回転をやめるか別手段が要る。
5. hub 由来の罠(`RADIO_MODE_UART_RCP`、`CONFIG_LWIP_IPV6_NUM_ADDRESSES=12`、
   SRP サーバの custom header、soft-float `.o` 除去、`rm sdkconfig` してから再 configure)は
   そのまま有効。`thread_ctrl_hub_cpp/README.md` と `docs/design/p4-thread-controller.md` §7 を参照。
