//! `smctl` — chip-tool 風の CLI コントローラ(`docs/design/cli-controller.md`)。
//!
//! 本体はライブラリ(`lib.rs`)。このバイナリは引数を [`smctl::cli::run`] に渡すだけ。

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match smctl::cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("smctl: {msg}");
            ExitCode::FAILURE
        }
    }
}
