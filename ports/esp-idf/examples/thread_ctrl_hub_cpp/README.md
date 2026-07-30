# thread_ctrl_hub_cpp — ESP32-P4 + ESP32-H2 の Thread ハブ兼 Matter コントローラ

ESP32-P4(ホスト MCU、802.15.4 radio 非搭載)+ ESP32-H2(`ot_rcp`、spinel over UART)で
動く **Thread ネットワーク主宰(leader)兼 SRP サーバ兼 Matter コントローラ**。
設計は `docs/design/p4-thread-controller.md`(F8)、コントローラ C FFI は
`docs/design/c-ffi-shim.md` §11(F7a/F7b)。

BLE は使わない。コミッショニングは **on-network PASE over Thread UDP**
(デバイスを同じ active dataset で Thread に参加させてから、その IPv6 アドレスへ PASE)。

## 構成

| 要素 | 実体 |
|---|---|
| OT スタック | `main/ot_hub.cpp`(`RADIO_MODE_UART_RCP` + `HOST_CONNECTION_MODE_NONE`) |
| Thread 主宰 | NVS の active dataset を復元 → 無ければ Kconfig TLV → 無ければ新規生成 |
| DNS-SD | OT の **SRP サーバ**(`otSrpServerSetEnabled`)。デバイスの `_matter._tcp` 登録を受ける |
| コントローラ | `sm_ctrl_*`(供給メモリは PSRAM 優先)。KVS は NVS namespace `smctl` |
| 運用アドレス解決 | SRP サーバ帳の列挙 → `sm_ctrl_set_node_addr`(F8b) |

## ビルド

```sh
# RCP(H2)側のファーム
scripts/otbr/build-ot-rcp-h2.sh          # → scripts/otbr/dist/ot_rcp_h2/merged_ot_rcp.bin

# ホスト(P4)側
cd ports/esp-idf/examples/thread_ctrl_hub_cpp
idf.py set-target esp32p4
idf.py build
```

Rust staticlib は経路 (b)(コンポーネントが `cargo build --target
riscv32imafc-unknown-none-elf` を実行)か、経路 (a)(`-DSM_PREBUILT_A=...` を
`set-target`/`build` 両方に渡す)。**P4 は hard-float(ilp32f)なので
`riscv32imafc-unknown-none-elf` が必須**(`riscv32imac` の .a はリンクできない)。

docker(Rust をコンテナに入れない場合はホストと同一パスで rustup をマウントする):

```sh
docker run --rm -v $REPO:$REPO -v $HOME/.cargo:$HOME/.cargo -v $HOME/.rustup:$HOME/.rustup \
  -e HOME=$HOME -w $REPO/ports/esp-idf/examples/thread_ctrl_hub_cpp espressif/idf:release-v5.4 \
  bash -ec 'export PATH=$HOME/.cargo/bin:$PATH; idf.py set-target esp32p4 && idf.py build'
```

## 設定(`idf.py menuconfig` → "thread_ctrl_hub_cpp configuration")

- **RCP UART**: `SM_OT_UART_PORT`(既定 1)/ `SM_OT_UART_RX_PIN`(4)/ `SM_OT_UART_TX_PIN`(5)/
  `SM_OT_UART_BAUD`(460800)。H2 側(`build-ot-rcp-h2.sh` の env)と必ず一致させる。
- **Thread**: `SM_THREAD_DATASET_TLV_HEX`(空 = 新規ネットワーク生成)。
- **対象デバイス**: `SM_TARGET_NODE_ID` / `SM_TARGET_PASSCODE` / `SM_TARGET_IPV6` /
  `SM_TARGET_PORT`。
- **TBR**: `SM_THREAD_BR`(既定 n。下記)。

秘密(WiFi 資格情報など)は Kconfig の default に書かず、`sdkconfig.local` で注入する
(`sdkconfig.local` は gitignore 済み)。

## 実機手順(概略)

1. H2 に `merged_ot_rcp.bin` を書き込み、P4 と UART 結線(TX/RX クロス + GND)。
2. P4 に本アプリを書き込む → 起動ログの `ACTIVE DATASET TLV (...)` の hex を控える。
3. デバイス(`onoff_light_cpp` の Thread 構成 / `ports/esp32/esp32c6-thread` の t2-light)に
   同じ dataset をプリセットして起動 → attach 後のログから ML-EID / OMR を控える。
4. `SM_TARGET_IPV6` に転記して再ビルド・書き込み → PASE → `PAIR COMPLETE` →
   30 秒毎の toggle を確認。

## TBR(border routing)= `SM_THREAD_BR`(未完・実機フェーズ送り)

既定ビルド(`SM_THREAD_BR=n`)は **backbone なしの自己完結 Thread ハブ**。コントローラ
自身が Thread メッシュ上に居るため、Matter 通信(PASE/CASE/IM over UDP)に border
routing は不要。

`sdkconfig.defaults.br` を明示合成すると border router 構成になる:

```sh
idf.py -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.br" set-target esp32p4 build
```

ただし ESP-IDF v5.4 では以下が追加で必要で、**本フェーズでは未完**(F8e):

- `main/idf_component.yml` に `espressif/mdns` を足す(border agent の meshcop mDNS)。
  1.2.5 / 1.11.3 いずれでも `libopenthread_br.a` が要求する
  `mdns_service_add_for_host` 等が最終リンクで未解決になる(要調査)。
- backbone netif の実体。P4 は radio 非搭載なので WiFi backbone には
  `espressif/esp_wifi_remote` + esp-hosted(例: M5Stack Tab5 = P4+C6)、
  ないし Ethernet が要る。`ot_hub.cpp` は `WIFI_STA_DEF` / `ETH_DEF` の netif を
  探して backbone に設定する足場まで実装済み。

## メモ(この構成で踏んだ罠)

- OT の radio モードは `RADIO_MODE_UART_RCP`(`RADIO_MODE_UART` という名前ではない)。
  Kconfig は `CONFIG_OPENTHREAD_RADIO_SPINEL_UART=y`。
- `CONFIG_LWIP_IPV6_NUM_ADDRESSES=12` 必須(openthread の lwIP netif が `#error` で要求)。
- v5.4 では `OPENTHREAD_CONFIG_SRP_SERVER_ENABLE` が `CONFIG_OPENTHREAD_BORDER_ROUTER`
  の内側でしか 1 にならない。BR 一式を避けるため `main/esp_ot_custom_config.h`
  (`CONFIG_OPENTHREAD_HEADER_CUSTOM`)で SRP サーバ + ECDSA だけを有効化している。
- P4 は ilp32f。rustup の `compiler_builtins` に同梱される cc ビルド済み C ルーチンは
  soft-float のままなので、参照されるとリンクが落ちる。コンポーネント側で該当 .o を
  除去している(`components/simple_matter/strip_softfloat_objs.cmake`)。
