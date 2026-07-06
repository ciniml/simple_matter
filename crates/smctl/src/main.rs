//! `smctl` — chip-tool 風の CLI コントローラ(`docs/design/cli-controller.md`)。
//!
//! - C1: UDP pairing(mDNS ブラウズ / アドレス直指定)+ 名前ベースのクラスタ操作
//!   (on-off / basic-information)+ Subscribe(レポート常駐表示)。
//! - C2: `any read/write/invoke`(ID 直指定 + 型付きリテラル + hex TLV)、`discover`、
//!   BLE pairing(feature `ble`: `pairing ble` / `pairing ble-handoff`)、
//!   バッチ実行(`smctl batch <file|->`、単一プロセスで CASE セッションと購読を共有)。
//!
//! 開発・自作デバイス用ツールであり、attestation は検証しない(`AttestationPolicy::Skip`)。

use std::process::ExitCode;

mod batch;
mod cli;
mod clusters;
mod ops;
mod runner;
mod state;

/// OS の CSPRNG による [`Rng`](simple_matter::crypto::Rng) 実装(設計 doc §2.5)。
///
/// examples の `DemoRng`(LCG)は持ち込まない。`getrandom` は Linux/Windows/macOS で
/// OS のエントロピー源(`getrandom(2)` / `BCryptGenRandom` 等)を叩く。
pub struct OsRng;

impl simple_matter::crypto::Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
        getrandom::fill(dest).map_err(|_| simple_matter::Error::Crypto)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("smctl: {msg}");
            ExitCode::FAILURE
        }
    }
}
