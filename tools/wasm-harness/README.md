# tools/wasm-harness — WASM スクリプトフックのホスト検証ハーネス(Phase C ゲート)

`docs/design/generic-firmware.md` §9.3 のゲート。**ファームと同一の
`ports/esp-idf/examples/generic_matter_cpp/main/script_vm.cpp`** を Linux 用にビルドした
WAMR へリンクし、`sm` ホスト import をメモリ上のモックに差し替えてフックを回す。

```sh
./run.sh                                  # 取得 → wasm ビルド → ハーネスビルド → 実行
# または
make -C ../../crates/simple-matter-cffi/ctest check-wasm
```

`run.sh` がやること:

1. `fetch-wamr.sh` — WAMR 2.4.0(ESP Component Registry の `espressif/wasm-micro-runtime`
   と**同一の zip**)を `.wamr/` へ展開する。**初回のみネットワークが要る**。
   WAMR はリポジトリに vendor しない(`.gitignore` 済み)。
2. `momentary-toggle` を `wasm32-unknown-unknown` でビルド
   (`rustup target add wasm32-unknown-unknown` が前提)。
3. `cmake` でハーネスをビルド(WAMR は classic interp + thread-manager のみ。
   ファームの `CONFIG_WAMR_*` と同じ機能セット)。
4. 実行 — 検証内容:
   - 16B 値レコードと `SMWS` イメージヘッダ(CRC-32 テストベクタ込み)
   - `on_boot` → ログ + KVS 読み出し
   - `on_sensor`(押下)→ `attr_get`(BooleanState)→ `attr_set`(OnOff)のトグル + KVS 更新
   - `timer_after` → `on_timer` で長押し強制 OFF、`timer_cancel` で発火しないこと
   - `on_attr_write` が 0(承認)を返すこと、未 export フックが no-op であること
   - **暴走スクリプト**(手組みの `loop br 0` モジュール)が壁時計上限で
     `wasm_runtime_terminate` により打ち切られ、その後もランタイムが使えること

成功すると `WASM HARNESS OK` を出して 0 で終了する。
