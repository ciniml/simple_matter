# sm-script-api — 汎用 Matter ファームウェア用 WASM スクリプト SDK(Rust)

`docs/design/generic-firmware.md` §9.3(Phase C)。`generic_matter_cpp` に載る WAMR VM の
**ホスト import(module `"sm"`)の宣言 + safe wrapper + フック宣言マクロ**。

- ターゲット: `wasm32-unknown-unknown`(`#![no_std]`)
- ホスト(x86_64)でも lib としてビルドできる。import は「未対応(`rc::UNSUPPORTED`)」を
  返すスタブになるので、値のエンコード/デコードはホストの `cargo test` で検証できる
  (= `cargo test --workspace` が壊れない)。

## フック ABI(export、いずれも optional)

| export | 発火元 | 戻り値 |
|---|---|---|
| `on_boot()` | VM ロード直後に 1 回 | — |
| `on_timer(id: i32)` | `timer_after` / `timer_every` の満了 | — |
| `on_attr_write(ep, cluster, attr) -> i32` | IM write / コマンド由来の属性変化(`on_cluster_change`) | 0 = 承認 |
| `on_command(ep, cluster, cmd) -> i32` | コマンド受信(**発火元は Phase D**) | 0 = 承認 |
| `on_sensor(bind: i32)` | `gpio_in` / `i2c_sht30` の更新、`script` binding の周期発火 | — |

**`on_attr_write` の非 0(拒否)は現状「観測のみ」**: 現行の C FFI シムには IM write を
アプリ側から拒否する口(write ハンドラの戻り値)が無く、`on_cluster_change` は
「**もう適用された**変化」の通知だからである。ファームは戻り値を警告ログに出すだけで、
書き込みは取り消さない。拒否を本当に効かせたい場合はスクリプト側で「元の値へ書き戻す」
(`attr_set`)のが現状の唯一の手段。

## 値の 16B 表現(`sm_attr_value_t` のワイヤ形式)

| offset | size | 内容 |
|---|---|---|
| 0 | 1 | `type`(`ValType`: 0=Bool 1=U8 2=U16 3=U32 4=U64 5=I8 6=I16 7=I32 8=I64 9=F32 10=String 11=Octets) |
| 1 | 1 | `flags`(bit0 = is_null) |
| 2 | 2 | `len`(String/Octets の**後続**バイト数、u16 LE。スカラは 0) |
| 4 | 4 | 予約(0) |
| 8 | 8 | `val`(u64 LE。Bool=0/1、U\*=ゼロ拡張、I\*=符号拡張、F32=下位 32bit にビットパターン) |

**スカラはちょうど 16 バイト**、String/Octets は `16 + len` バイト。
`attr_get(ep,cluster,attr,out,cap)` は書いた**全長**を返すので、文字列を読むときは
`cap >= 16 + len` を渡すこと(`attr_get_into`)。同じ定義が
`ports/esp-idf/examples/generic_matter_cpp/main/script_abi.hpp` と `web/sdk/sm.d.ts` にある。

## ホスト import 一覧(module `"sm"`)

| import | 意味 |
|---|---|
| `attr_get(ep,cluster,attr,out_ptr,cap) -> i32` | 属性を読む。>=0 = 書いた全長 |
| `attr_set(ep,cluster,attr,ptr,len) -> i32` | 属性を書く(0 = OK) |
| `gpio_write(pin,v) -> i32` / `gpio_read(pin) -> i32` | GPIO(出力は毎回 `gpio_config` する) |
| `pwm_set(ch,duty) -> i32` | LEDC(10bit。チャネルは binding TLV で設定済みのこと) |
| `timer_after(ms,id)` / `timer_every(ms,id)` / `timer_cancel(id)` | スクリプトタイマ(同時 8 本) |
| `log(ptr,len)` | ログ出力 |
| `kvs_get(key,key_len,out,cap)` / `kvs_set(key,key_len,val,len)` | NVS namespace `smscr`(キーは 15 バイトまで) |

エラーは負値(`rc::ARG` = -1 / `NOTFOUND` = -2 / `UNSUPPORTED` = -3 / `TYPE` = -4 /
`NOSPACE` = -5 / `HW` = -6)。ポインタ引数は VM 側で線形メモリ範囲を検証してから
native ポインタへ変換する(範囲外は `ARG`)。

## サンプルとビルド

`examples-wasm/momentary-toggle/`(モーメンタリスイッチ → OnOff トグル + 長押しで強制 OFF)。
**ワークスペースからは除外**してある(`no_std` + `#[panic_handler]` + `cdylib` はホストの
`cargo test` / `clippy --all-targets` と同居できないため)。

```sh
rustup target add wasm32-unknown-unknown
cd examples-wasm/momentary-toggle
cargo build --release --target wasm32-unknown-unknown
# -> target/wasm32-unknown-unknown/release/momentary_toggle.wasm(約 1.4KB)
```

`Cargo.toml` の profile(推奨値):

```toml
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

デバイスへの書き込み(`smscript` パーティション slot A):

```sh
scripts/smscript-img.py pack momentary_toggle.wasm -o slotA.bin --ver 1
esptool.py write_flash 0x296000 slotA.bin     # partitions.csv の smscript オフセット
```

ホスト検証は `tools/wasm-harness/run.sh`(= `make -C crates/simple-matter-cffi/ctest check-wasm`)。
