# simple_matter — ESP-IDF コンポーネント

`crates/simple-matter-cffi`(C FFI シム、staticlib)を ESP-IDF の C++17
アプリケーションからリンクするためのコンポーネント。cbindgen 生成ヘッダ
`simple_matter.h` と C++17 RAII ラッパ `sm_wrapper.hpp` を `INCLUDE_DIRS` で公開し、
Rust staticlib `libsimple_matter_cffi.a` を `add_prebuilt_library` で最終 ELF に
リンクする。設計は `docs/design/c-ffi-shim.md`(§2 後半・§3・§4 F2)。

## 対応ターゲット

| IDF_TARGET | Rust target | 状態 |
|---|---|---|
| esp32c6 / esp32c3 | `riscv32imac-unknown-none-elf` | F2(経路 (a)/(b) 両対応) |
| esp32s3 | `xtensa-esp32s3-none-elf` | F4a(経路 (a) = `SM_PREBUILT_A` のみ) |

非対応の `IDF_TARGET` を選ぶと configure 時に `FATAL_ERROR` になる。

**S3/Xtensa の注意**: `xtensa-esp32s3-none-elf` は upstream rustc に無く、esp channel
(espup)+ `-Zbuild-std=core` が要る。コンポーネントの経路 (b)(cargo 自動ビルド)は
素朴な `cargo build` を叩くだけなので S3 では通らない。S3 は**必ず経路 (a)
(`SM_PREBUILT_A`)**を使うこと(経路 (b) を選ぶと明示的に `FATAL_ERROR`)。.a は
以下でビルドする:

```sh
. ~/export-esp.sh
cargo +esp build -p simple-matter-cffi --release \
    --target xtensa-esp32s3-none-elf -Zbuild-std=core --features panic-abort
# → target/xtensa-esp32s3-none-elf/release/libsimple_matter_cffi.a

A=/abs/.../target/xtensa-esp32s3-none-elf/release/libsimple_matter_cffi.a
idf.py -DSM_PREBUILT_A=$A set-target esp32s3   # set-target にも -DSM_PREBUILT_A が必要
idf.py -DSM_PREBUILT_A=$A build
```

## 既存プロジェクトへの組み込み

1. トップ `CMakeLists.txt` でこの `components/` ディレクトリを追加する:

   ```cmake
   set(EXTRA_COMPONENT_DIRS "/path/to/simple_matter/ports/esp-idf/components")
   include($ENV{IDF_PATH}/tools/cmake/project.cmake)
   project(my_app)
   ```

   (このリポジトリの `examples/onoff_light_cpp` は相対パスで参照している。)

2. アプリの `main/CMakeLists.txt` で `REQUIRES simple_matter` を宣言する:

   ```cmake
   idf_component_register(SRCS "main.cpp"
       INCLUDE_DIRS "."
       REQUIRES simple_matter nvs_flash esp_wifi esp_netif esp_event lwip driver esp_timer)
   ```

3. C++ から `#include "sm_wrapper.hpp"`(または C から `#include "simple_matter.h"`)。

## リンク経路: (a) ビルド済み .a と (b) cargo

コンポーネントは 2 経路をサポートする。

### (a) SM_PREBUILT_A — Rust ツールチェーン不要(推奨・CI 既定)

ホスト側で一度 .a をビルドしておき、そのパスを `idf.py` に渡す:

```sh
# ホスト(rustup + target 有り)で:
cargo build -p simple-matter-cffi --release \
    --target riscv32imac-unknown-none-elf --features panic-abort
# → target/riscv32imac-unknown-none-elf/release/libsimple_matter_cffi.a

# ESP-IDF ビルド(Rust 不在のコンテナでも可):
A=/abs/path/target/riscv32imac-unknown-none-elf/release/libsimple_matter_cffi.a
idf.py -DSM_PREBUILT_A=$A set-target esp32c6
idf.py -DSM_PREBUILT_A=$A build
```

`SM_PREBUILT_A` は存在しないと `FATAL_ERROR`。ターゲットに合った .a を渡すこと
(C6/C3 = `riscv32imac-unknown-none-elf`)。

注意: **`set-target` も CMake configure を走らせる**ため、`-DSM_PREBUILT_A` は
`set-target` 時にも必要(付けないと cargo 不在環境では configure が
`FATAL_ERROR` になる)。

### (b) cargo 自動ビルド — ビルド環境に Rust がある場合

`SM_PREBUILT_A` を渡さなければ、コンポーネントが custom command で
`cargo build -p simple-matter-cffi --release --target <triple> --features panic-abort`
を repo ルートで実行し、生成された `.a` をリンクする。

前提:
- `cargo` が PATH にあること(無ければ `FATAL_ERROR`)。
- 対象トリプルの target が導入済みであること
  (`rustup target add riscv32imac-unknown-none-elf`)。
- panic ハンドラは `panic-abort` feature が提供する(ベアメタルビルド)。

ESP-IDF の docker イメージには Rust が入っていないため、コンテナ内で (b) を
使うにはツールチェーンをマウントする必要がある。このとき**ホストと同一パスに
マウントすること**(例: `-v $HOME/.cargo:$HOME/.cargo -v $HOME/.rustup:$HOME/.rustup`
+ `PATH` に `$HOME/.cargo/bin` を追加)。`/root/.cargo` など別パスへのマウントは
rustup プロキシ(`cargo` → `$HOME/.cargo/bin/rustup` の絶対 symlink)が壊れて
`command not found` になる。ツールチェーン不在の環境では (a) を使う。

## メモ

- staticlib はプラットフォーム非依存(sans-IO、OS 呼び出しゼロ)。ソケット・NVS・
  時刻・RNG は C++ アプリ側が所有し、`sm_config_t` のコールバックと `sm_*` 引数で
  シムへ渡す(`examples/onoff_light_cpp` 参照)。
