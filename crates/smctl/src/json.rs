//! `--json` 出力(設計 doc §6 C3)。手書きエンコーダで依存追加なし。
//!
//! - **1 行 1 オブジェクト**(JSON Lines)。`read`/`write`/`invoke`/`subscribe`/
//!   `discover` の結果と購読レポート(レポート毎に 1 行)を stdout へ出す。
//! - JSON モードでは stdout を JSON 行専用に保つため、人間向けの情報行
//!   ([`info!`])は stderr へ逃がす。これにより通常・subscribe 常駐・バッチの
//!   どのモードでも `smctl --json ... | jq` がそのまま通る。
//! - モードはプロセス全体のフラグ(バッチは行をまたいで 1 プロセスなので、
//!   行ごとの `Globals` から [`set_mode`] で同期する)。

use std::sync::atomic::{AtomicBool, Ordering};

static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// JSON 出力モードを設定する(CLI/バッチ行の `--json` から)。
pub fn set_mode(on: bool) {
    JSON_MODE.store(on, Ordering::Relaxed);
}

/// JSON 出力モードかを返す。
pub fn enabled() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// 人間向け情報行: 通常は stdout、`--json` では stderr(stdout は JSON 行専用)。
macro_rules! info {
    ($($arg:tt)*) => {
        if crate::json::enabled() {
            eprintln!($($arg)*);
        } else {
            println!($($arg)*);
        }
    };
}
pub(crate) use info;

/// JSON 文字列リテラルの中身をエスケープする(引用符は付けない)。
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// 1 行 JSON オブジェクトのビルダ。先頭キーは常に `"event"`。
///
/// ```ignore
/// Obj::new("write").num("node", 1).str("status", "Success").emit();
/// // => {"event":"write","node":1,"status":"Success"}
/// ```
pub struct Obj {
    buf: String,
}

impl Obj {
    /// `{"event":"<event>"` から始める。
    pub fn new(event: &str) -> Self {
        Self {
            buf: format!("{{\"event\":\"{}\"", escape(event)),
        }
    }

    fn key(&mut self, k: &str) {
        self.buf.push_str(",\"");
        self.buf.push_str(&escape(k));
        self.buf.push_str("\":");
    }

    /// 文字列値。
    pub fn str(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        self.buf.push('"');
        self.buf.push_str(&escape(v));
        self.buf.push('"');
        self
    }

    /// 数値(呼び出し側が有効な JSON 数値表現であることを保証する)。
    pub fn num(mut self, k: &str, v: impl std::fmt::Display) -> Self {
        self.key(k);
        self.buf.push_str(&v.to_string());
        self
    }

    /// エンコード済み JSON 値(オブジェクト・配列・`null` 等)をそのまま埋める。
    pub fn raw(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        self.buf.push_str(v);
        self
    }

    /// `}` で閉じて stdout へ 1 行で出力する。
    pub fn emit(mut self) {
        self.buf.push('}');
        println!("{}", self.buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_specials() {
        assert_eq!(escape("a\"b\\c\nd\te\u{1}"), "a\\\"b\\\\c\\nd\\te\\u0001");
    }

    #[test]
    fn obj_builds_one_line() {
        // emit は stdout に書くので、ここでは内部バッファの形だけ検証する。
        let o = Obj::new("read")
            .num("node", 1u64)
            .str("status", "Success")
            .raw("value", "true");
        assert_eq!(
            o.buf,
            "{\"event\":\"read\",\"node\":1,\"status\":\"Success\",\"value\":true"
        );
    }
}
