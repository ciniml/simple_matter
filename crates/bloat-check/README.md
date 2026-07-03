# bloat-check

`simple-matter` のフットプリント計測(`docs/ARCHITECTURE.md` 設計原則 10「bloat-check を
day 1 から」)。On/Off ライトのデバイス一式(EP0: Basic Information / General Commissioning /
Network Commissioning / Operational Credentials / Descriptor、EP1: On/Off / Descriptor)を
題材に、`DefaultStack` / `MinimalStack` の 2 プロファイルを測る。

依存はコアクレート `simple-matter` 1 本のみ(外部依存ゼロ)。HAL やランタイム crate
(`cortex-m-rt` 等)は持ち込まない。デバイス構成は
`crates/simple-matter/examples/onoff-light.rs` の `Light` を fabric 数 `NF` で汎用化して
共有する(`src/lib.rs`)。

## 計測方式

rs-matter の `bloat-check`(`research/rs-matter/bloat-check/`)に倣う。

- **RAM**(`ram-report`, ホスト実行, std): 実 MCU で `.bss` に載る状態構造体群を
  `core::mem::size_of` でコンポーネント別に足し上げる。ホストの型レイアウトは MCU と
  同じなので RAM の下限見積りとして妥当。`MatterStack` のフィールド和が
  `size_of::<MatterStack>()` に一致することを検算表示する。
- **flash**(`flash-probe`, MCU クロスビルド, `no_std`/`no_main`): スタック一式を
  リンクする最小バイナリを `--release`(`opt-level="z"` + LTO)でビルドし、`size` で
  セクション(`.text` / `.rodata` / `.data` / `.bss`)を読む。エントリ(`_start`)と
  `#[panic_handler]` は自前で用意し、リンカ設定は `build.rs` + `link.x` で与える
  (ベンダ HAL 非依存)。ネットワーク/時刻はダミー注入で、スタックとデータパス
  (`handle_rx` / `poll` / mDNS `handle_query`)を `core::hint::black_box` で参照保持し、
  リンカ GC(`--gc-sections`)で消えないようにする。

`flash-probe` はスタックをコールスタック上に構築するため `.bss`/`.data` は 0 になる。
flash フットプリントは `.text` + `.rodata`(= コード + 定数)で読む。RAM は上記の
`size_of` レポートで別途評価する。

## 実行

RAM 計測(ホスト):

```sh
cargo run -p bloat-check --bin ram-report --release
```

flash 計測(Cortex-M4F 例。インストール済みの他ターゲットでも可):

```sh
rustup target add thumbv7em-none-eabihf
cargo build -p bloat-check --bin flash-probe --release --target thumbv7em-none-eabihf
size -A target/thumbv7em-none-eabihf/release/flash-probe   # arm-none-eabi-size / llvm-size でも可
```

## 参考値

rs-matter 公称下限 = **1 MB flash / 256 KB (262144 B) RAM**。本計測はこれを下回ることを
確認するためのもの。数値は CI(`.github/workflows/ci.yml`)でも毎回出力する。
