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
| `app_main` | NVS / netif / event loop → `M5.begin()`(PORT.A 5V + パネル + タッチ)→ pump 起動 → spinel 同期待ち → LVGL 起動 → UI 構築 |
| `ctrl_pump`(静的スタック **128KB**)| `sm_ctrl_*` を専有。UI の操作キューを 1 件ずつ実行 |
| `ot_main` | `esp_openthread` のメインループ |
| `lvgl`(`main/display_gfx.cpp` が起動)| `lv_*` のみ。`sm_ctrl_*` / `ot*` は**呼ばない** |

UI → pump は FreeRTOS キューの `sm_ui_op_t`(Toggle / ReadOnOff / Pair / RefreshAddr)、
pump → UI は mutex 保護のスナップショット + LVGL の 500ms タイマ反映
(`main/app_state.hpp`)。タップは「キューに積むだけ」なので、pump が 20 秒の CASE を
待っていても画面は固まらない(ただし操作の実行はその分待たされる)。

## 構成ファイル

| ファイル | 中身 |
|---|---|
| `main/main.cpp` | 起動シーケンス(5V → spinel 同期 → LVGL の順序が命) |
| `main/display_gfx.{hpp,cpp}` | M5Unified/M5GFX の初期化 + 自前 LVGL ポート(flush / touch / tick / タスク / ロック) |
| `main/ui.cpp` | LVGL の画面全部(sm_ctrl_* を一切呼ばない) |
| `main/ctrl_pump.cpp` | pump タスク(KVS / UDP / `run_until` は hub から流用) |
| `main/app_state.{hpp,cpp}` | 操作キュー + スナップショット(UI ↔ pump の唯一の連絡路) |
| `main/node_book.{hpp,cpp}` | NVS `smctl`/`nods` を TLV パースして NodeId を列挙 |
| `main/ot_hub.{hpp,cpp}` | hub のコピー + GUI 用ステータス取得(OT 配線は無改変) |
| `main/idf_component.yml` | `m5stack/m5unified ^0.2.20`(→ `m5stack/m5gfx 0.2.27`)+ `lvgl/lvgl ^9.2.0` |

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

docker(**`espressif/idf:release-v5.4` のまま。ESP Registry の
`m5stack/m5unified 0.2.20` / `m5stack/m5gfx 0.2.27` / `lvgl/lvgl 9.5.0` が解決する**):

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
- **表示/タッチ**: Kconfig は無い。回転は `main/display_gfx.cpp` の
  `M5.Display.setRotation(1)`(= 1280x720 横。上下逆なら 3)。M5GFX の `getTouch()` は
  回転を反映した画面座標を返すので、旧 `SM_UI_ROTATION` / `SM_UI_TOUCH_MIRROR_X/Y` は廃止した。

## 実機手順

1. Unit Gateway H2 に `merged_ot_rcp.bin` を書き込み、Tab5 の **Port A** に挿す。
2. Tab5 に本アプリを flash → 画面が出て、ログに `ot_hub: thread role = 4`(Leader)。
3. Network タブの dataset TLV hex(または QR)をデバイス側にプリセットして起動。
4. デバイスのログの ML-EID / OMR を `+ Pair new device` の IPv6 欄へ入力 → `Start pairing`。
5. 一覧に出た行の `Toggle` でデバイスが点滅すれば完走。

## 踏んだ罠(次に触る人へ)

1. **Espressif BSP(`espressif/m5stack_tab5` 1.2.0 + `esp_lvgl_port`)は実機で画面が
   出なかった**(T1b の発端)。初期化ログは全て正常・バックライトも点くのに真っ黒
   (board version 2 = ST7123 タッチ搭載個体。パネル init / DPI タイミングが疑い)。
   **M5Unified/M5GFX へ差し替えて解決した**。BSP 経路で必要だったタッチ座標の回転シム
   (`rotated_touch_read`)は M5GFX が回転済み座標を返すので不要になり、削除した。
2. **シムに NodeId の列挙 API が無い**(`sm_ctrl_node_count` は件数、
   `sm_ctrl_node_addr` は引き当てのみ)。GUI の一覧を作るには NodeId そのものが要るので、
   シムが書いた NVS `smctl`/`nods`(smctl `nodes.tlv` v1 = 安定仕様)を C++ 側で
   TLV パースして読み直している(`main/node_book.cpp`。読み取り専用、コア/シムは無改造)。
3. **`M5.begin()` は PORT.A の 5V を一瞬切る**。`Power_Class::begin()` が Tab5 の
   IO エキスパンダ #0(PI4IOE5V6408 @0x43)へ `OUT_SET=0b01110000` を書く時点で
   EXT5V_EN(P2)が 0 になり、直後の `setExtOutput(cfg.output_power)` で戻る。
   5V は **H2(RCP)の電源そのもの**なので、`M5.begin()` は必ず pump(spinel)より
   前に置くこと。逆順にすると H2 が再起動して spinel が落ちる。
4. **表示の初期化は 2 段に分けてある**。`sm_display_hw_init()`(= `M5.begin()`。5V と
   パネル)は最初期、`sm_display_lvgl_start()`(LVGL + 描画)は **spinel 同期後**。
   T1 で踏んだ「LVGL の初期描画中に spinel UART を開くと RX 取りこぼしで OT の
   初期リセットが assert ループ」を避けるための分割(§9.4 / §9.5)。
   LVGL の描画バッファは PSRAM に 1280x72x2B を 2 枚(約 360KB)。内蔵 RAM は
   pump の静的スタック 128KB と OT/lwIP/mbedTLS に残す。
5. hub 由来の罠(`RADIO_MODE_UART_RCP`、`CONFIG_LWIP_IPV6_NUM_ADDRESSES=12`、
   SRP サーバの custom header、soft-float `.o` 除去、`rm sdkconfig` してから再 configure)は
   そのまま有効。`thread_ctrl_hub_cpp/README.md` と `docs/design/p4-thread-controller.md` §7 を参照。
