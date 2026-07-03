//! flash 計測バイナリ(`flash-probe`)のリンカ設定を注入する build script。
//!
//! ベアメタル(`target_os = "none"`)向けビルドのときだけ、最小リンカスクリプト
//! `link.x` を検索パスに置き、`-Tlink.x` と `--gc-sections` を渡す。ホストビルド
//! (`ram-report`)には一切影響しない。

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "none" {
        // ホスト(std)ビルドではリンカ設定を触らない。
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let script = include_bytes!("link.x");
    fs::write(out.join("link.x"), script).unwrap();

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=build.rs");

    // GC で未使用セクションを削り、実際に使われるコードだけを .text/.rodata に残す。
    println!("cargo:rustc-link-arg-bins=--gc-sections");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    // ベクタテーブル等が無いので未定義エントリ警告を無視できるよう nmagic は付けない。
}
