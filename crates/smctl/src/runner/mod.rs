//! sans-IO スタックの駆動層(設計 doc §2.1 `runner/`)。
//!
//! - [`udp`]: examples/commissioner.rs の pump/settle/socket 群の移植。
//! - [`mdns`]: commissionable ブラウズ / operational 解決(QU モード・IF 固定・再クエリ込み)。
//!
//! BLE ランナー(btleplug)は C2 で追加する。

use simple_matter::controller::{ControllerCreds, ControllerStack};
use simple_matter::crypto::rustcrypto::RustCrypto;

use crate::OsRng;

pub mod mdns;
pub mod udp;

/// 暗号バックエンド(OS CSPRNG)。
pub type Backend = RustCrypto<OsRng>;

/// smctl のコントローラスタック型。
///
/// - SS=4 / EX=6 / TX=3: examples/commissioner.rs と同じ。
/// - RESULT=8192: Read 結果バッファ。examples の 1280B ではワイルドカード Read で
///   溢れやすいため大きめに取る(設計 doc §7.2 G4 の緩和)。
pub type Ctrl<'s> =
    ControllerStack<'s, Backend, OsRng, ControllerCreds<'s, Backend>, 4, 6, 3, 8192>;
