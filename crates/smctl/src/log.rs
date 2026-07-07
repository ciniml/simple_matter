//! ログ機構(設計 doc §9)。レベル分け + レイヤタグ + 起動からの ms タイムスタンプ。
//!
//! - レベル: `error < warn < info < debug < trace`(既定 info)。
//!   `--log-level` / `-v`(debug)/ `-vv`(trace)/ 環境変数 `SMCTL_LOG` で指定。
//! - 出力は**常に stderr**(stdout は結果と `--json` の JSON Lines 専用)。
//! - 書式: `[<起動からの ms(右詰め 6 桁)>][<tag>] メッセージ`。warn/error は
//!   `warn:` / `error:` を前置する。ANSI 色は使わない(Windows コンソール互換の
//!   無色フォールバックに一本化)。
//! - 後方互換: `SM_MDNS_TRACE=1` / `SM_BTP_TRACE=1` は該当レイヤのみ trace 相当を
//!   強制する([`force`] 経由)。`-vv` はライブラリ側トレース(`SM_BLE_TRACE`)も
//!   env 経由で有効化する([`init`])。

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

/// ログレベル。数値が大きいほど冗長。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    /// レベル名(`--log-level` の値)をパースする。
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "error" => Ok(Level::Error),
            "warn" => Ok(Level::Warn),
            "info" => Ok(Level::Info),
            "debug" => Ok(Level::Debug),
            "trace" => Ok(Level::Trace),
            _ => Err(format!(
                "invalid log level {s:?} (expected error|warn|info|debug|trace)"
            )),
        }
    }
}

/// 現在の有効レベル(既定 info)。
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
/// タイムスタンプ基準時刻(プロセス起動 = 初回参照時)。
static START: OnceLock<Instant> = OnceLock::new();

/// CLI 指定(`--log-level`/`-v`/`-vv`)と環境変数 `SMCTL_LOG` から有効レベルを決める。
/// CLI 指定が優先。どちらも無ければ info。
pub fn resolve(cli: Option<Level>) -> Level {
    if let Some(l) = cli {
        return l;
    }
    match std::env::var("SMCTL_LOG") {
        Ok(v) => Level::parse(v.trim()).unwrap_or(Level::Info),
        Err(_) => Level::Info,
    }
}

/// レベルを設定し、タイムスタンプ基準を初期化する。
///
/// trace ではライブラリ側トレース(`simple-matter-ble` の `SM_BLE_TRACE`)も env 経由で
/// 有効化する(smctl から見えない層の後方互換トレースを巻き込む)。
pub fn init(level: Level) {
    let _ = START.get_or_init(Instant::now);
    LEVEL.store(level as u8, Ordering::Relaxed);
    if level >= Level::Trace {
        // edition 2021: set_var は safe。BLE central(ライブラリ内)の発見トレース用。
        std::env::set_var("SM_BLE_TRACE", "1");
    }
}

/// 指定レベルが現在の有効レベルで出力されるか。
pub fn enabled(l: Level) -> bool {
    (l as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// 起動からの経過ミリ秒。
pub fn ms() -> u128 {
    START.get_or_init(Instant::now).elapsed().as_millis()
}

/// 1 行書き出す(レベル判定済みの内部用。[`force`] からも使う)。
pub fn write(l: Level, tag: &str, args: std::fmt::Arguments<'_>) {
    let sev = match l {
        Level::Error => "error: ",
        Level::Warn => "warn: ",
        _ => "",
    };
    eprintln!("[{:>6}][{tag}] {sev}{args}", ms());
}

/// グローバルレベルに関わらず出力する(`SM_MDNS_TRACE` 等の per-layer 強制用)。
pub fn force(l: Level, tag: &str, args: std::fmt::Arguments<'_>) {
    write(l, tag, args);
}

/// レイヤタグ付きログ。`logf!(Level::Debug, "im", "...")`。
macro_rules! logf {
    ($lvl:expr, $tag:expr, $($arg:tt)*) => {
        if crate::log::enabled($lvl) {
            crate::log::write($lvl, $tag, format_args!($($arg)*));
        }
    };
}
pub(crate) use logf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parse_and_order() {
        assert_eq!(Level::parse("error").unwrap(), Level::Error);
        assert_eq!(Level::parse("warn").unwrap(), Level::Warn);
        assert_eq!(Level::parse("info").unwrap(), Level::Info);
        assert_eq!(Level::parse("debug").unwrap(), Level::Debug);
        assert_eq!(Level::parse("trace").unwrap(), Level::Trace);
        assert!(Level::parse("verbose").is_err());
        assert!(Level::Error < Level::Warn);
        assert!(Level::Debug < Level::Trace);
    }

    #[test]
    fn resolve_prefers_cli() {
        // 環境変数に依存しない分岐のみ検証(env はテスト間で共有されるため触らない)。
        assert_eq!(resolve(Some(Level::Trace)), Level::Trace);
        assert_eq!(resolve(Some(Level::Error)), Level::Error);
    }

    #[test]
    fn enabled_respects_level() {
        init(Level::Debug);
        assert!(enabled(Level::Error));
        assert!(enabled(Level::Info));
        assert!(enabled(Level::Debug));
        assert!(!enabled(Level::Trace));
        init(Level::Info); // 他テストへの影響を減らすため既定へ戻す
    }
}
