//! ログ機構(設計 doc §9)。レベル分け + レイヤタグ + 起動からの ms タイムスタンプ。
//!
//! - レベル: `error < warn < info < debug < trace`(既定 info)。
//!   `--log-level` / `-v`(debug)/ `-vv`(trace)/ 環境変数 `SMCTL_LOG` で指定。
//! - 出力は**常に stderr**(stdout は結果と `--json` の JSON Lines 専用)。
//! - 書式: `[<起動からの ms(右詰め 6 桁)>][<tag>] メッセージ`。warn/error は
//!   `warn:` / `error:` を前置する。
//! - 色付け(§9.5): stderr が TTY のとき ANSI 色を自動で有効化する
//!   (`--color <auto|always|never>`、既定 auto)。auto では `NO_COLOR` で無効化、
//!   `SMCTL_FORCE_COLOR=1` で非 TTY でも強制。Windows 10+ では有効化時に
//!   kernel32 直叩き(依存 crate なし)で VT 処理(ENABLE_VIRTUAL_TERMINAL_PROCESSING)
//!   を立てる。
//! - ログファイル(§9.5): `--log-file <path>` で stderr と並行してファイルへ追記する。
//!   ファイルは**常に無色・全レベル(trace 相当)**で記録し、画面はレベル/色設定
//!   どおり。open/write 失敗は warn して継続する(ログ機構がツールを止めない)。
//! - 後方互換: `SM_MDNS_TRACE=1` / `SM_BTP_TRACE=1` は該当レイヤのみ trace 相当を
//!   強制する([`trace_forced`] 経由)。`-vv` はライブラリ側トレース(`SM_BLE_TRACE`)も
//!   env 経由で有効化する([`init`])。

use std::fs::File;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
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

/// 色モード(`--color` の値、既定 auto)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// stderr が TTY なら色付き(`NO_COLOR` で無効化、`SMCTL_FORCE_COLOR` で強制)。
    Auto,
    Always,
    Never,
}

impl ColorMode {
    /// `--color` の値をパースする。
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "auto" => Ok(ColorMode::Auto),
            "always" => Ok(ColorMode::Always),
            "never" => Ok(ColorMode::Never),
            _ => Err(format!(
                "invalid color mode {s:?} (expected auto|always|never)"
            )),
        }
    }
}

/// 現在の有効レベル(既定 info)。
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
/// タイムスタンプ基準時刻(プロセス起動 = 初回参照時)。
static START: OnceLock<Instant> = OnceLock::new();
/// ANSI 色の有効フラグ([`init_color`] で決定)。
static COLOR: AtomicBool = AtomicBool::new(false);
/// 並行出力先のログファイル(`--log-file`。プロセスで 1 回だけ開く)。
static FILE: OnceLock<Mutex<File>> = OnceLock::new();
/// ファイル書き込みエラーの warn を 1 回に抑えるフラグ。
static FILE_ERR: AtomicBool = AtomicBool::new(false);
/// 埋め込み側(`smweb`)のログ転送フック。未設定なら何もしない(CLI の挙動は不変)。
static HOOK: OnceLock<LogHook> = OnceLock::new();

/// ログ転送フックの型: `(レベル, レイヤタグ, 本文)`。
pub type LogHook = Box<dyn Fn(Level, &str, &str) + Send + Sync>;

/// stderr へ出す行を併せて受け取るフックを設定する(プロセスで 1 回。2 回目以降は `false`)。
///
/// `smweb` が `Event::Log` として WebSocket へ流すために使う。フックは stderr の
/// レベル判定を通った行に対してだけ呼ばれる。
pub fn set_hook(hook: LogHook) -> bool {
    HOOK.set(hook).is_ok()
}

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

/// 指定レベルが現在の有効レベルで **stderr へ**出力されるか。
pub fn enabled(l: Level) -> bool {
    (l as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// 指定レベルの行を**どこかへ**出力するか(stderr のレベル判定 or ログファイル)。
/// ログ行の組み立てをスキップする早期 return のゲートにはこちらを使う
/// (ファイルは常に trace 全量を記録するため)。
pub fn wants(l: Level) -> bool {
    enabled(l) || file_enabled()
}

/// 起動からの経過ミリ秒。
pub fn ms() -> u128 {
    START.get_or_init(Instant::now).elapsed().as_millis()
}

// ==========================================================================
// 色付け(設計 doc §9.5)
// ==========================================================================

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";

/// レイヤタグの色(chip-tool のカテゴリ色風にタグを識別しやすくする)。
fn tag_color(tag: &str) -> &'static str {
    match tag {
        "sc" => "\x1b[35m",          // magenta: Secure Channel
        "im" => "\x1b[32m",          // green:   Interaction Model
        "tlv" => "\x1b[34m",         // blue:    ペイロード構造
        "ex" => "\x1b[36m",          // cyan:    exchange/MRP
        "udp" => "\x1b[94m",         // bright blue
        "ble" | "btp" => "\x1b[95m", // bright magenta
        "dis" => "\x1b[96m",         // bright cyan
        "ctl" => "\x1b[1m",          // bold:    コントローラ進行
        _ => "",
    }
}

/// レベルの色(メッセージ本文に掛ける)。error=赤、warn=黄、他は無色。
fn level_color(l: Level) -> &'static str {
    match l {
        Level::Error => "\x1b[31m",
        Level::Warn => "\x1b[33m",
        _ => "",
    }
}

/// 色の有効/無効を**純粋に**判定する(テスト対象。I/O や env はしない)。
///
/// - always/never は無条件。
/// - auto: `NO_COLOR`(非空)が最優先で無効、次に `SMCTL_FORCE_COLOR` で強制有効、
///   でなければ stderr の TTY 判定に従う。
pub fn color_decision(mode: ColorMode, is_tty: bool, force_env: bool, no_color_env: bool) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => !no_color_env && (force_env || is_tty),
    }
}

/// 色モードを解決して有効化する。有効化時、Windows ではコンソールの VT 処理を立てる
/// (失敗したら auto では無色へフォールバック。always は指示どおり色を出す)。
pub fn init_color(mode: ColorMode) {
    use std::io::IsTerminal;
    let is_tty = std::io::stderr().is_terminal();
    let force_env = env_flag("SMCTL_FORCE_COLOR");
    let no_color = env_flag("NO_COLOR");
    let mut on = color_decision(mode, is_tty, force_env, no_color);
    if on && !enable_vt() && mode != ColorMode::Always {
        on = false;
    }
    COLOR.store(on, Ordering::Relaxed);
}

/// 環境変数が「セットされていて空でない」か(`NO_COLOR` 慣例)。
fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// Windows 10+ のコンソールで ANSI エスケープ処理を有効化する。
///
/// 依存 crate を増やさず kernel32 を直接 FFI する(windows-sys 追加より小さい。
/// 判断根拠は設計 doc §9.5)。非 Windows では常に成功。
#[cfg(windows)]
fn enable_vt() -> bool {
    use std::ffi::c_void;
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4; // (DWORD)-12
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
        fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut c_void, dwMode: u32) -> i32;
    }
    unsafe {
        let h = GetStdHandle(STD_ERROR_HANDLE);
        if h.is_null() || h as isize == -1 {
            return false;
        }
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_vt() -> bool {
    true
}

// ==========================================================================
// ログファイル(設計 doc §9.5 `--log-file`)
// ==========================================================================

/// ログファイルを追記モードで開く(プロセスで 1 回)。失敗は warn して継続する。
pub fn init_file(path: &Path) {
    match File::options().create(true).append(true).open(path) {
        Ok(f) => {
            if FILE.set(Mutex::new(f)).is_err() {
                logf!(
                    Level::Warn,
                    "ctl",
                    "--log-file already set; keeping the first file"
                );
            }
        }
        Err(e) => {
            logf!(
                Level::Warn,
                "ctl",
                "cannot open log file {}: {e}; continuing without file logging",
                path.display()
            );
        }
    }
}

/// ログファイル出力が有効か。
pub fn file_enabled() -> bool {
    FILE.get().is_some()
}

/// ファイルへ 1 行追記する(常に無色・レベル無条件)。失敗は 1 回だけ warn。
fn file_line(line: &str) {
    let Some(m) = FILE.get() else { return };
    let mut f = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if writeln!(f, "{line}").is_err() && !FILE_ERR.swap(true, Ordering::Relaxed) {
        // ファイルには書けないので stderr のみ(emit 経由だと再帰する)。
        eprintln!(
            "[{:>6}][ctl] warn: log file write failed; file logging degraded",
            ms()
        );
    }
}

// ==========================================================================
// 出力
// ==========================================================================

/// 1 行書き出す共通処理。`to_stderr` が真なら画面へ(色設定どおり)、ファイルが
/// 有効なら常に無色でファイルへも書く。
fn emit(l: Level, tag: &str, args: std::fmt::Arguments<'_>, to_stderr: bool) {
    let sev = match l {
        Level::Error => "error: ",
        Level::Warn => "warn: ",
        _ => "",
    };
    let t = ms();
    let msg = args.to_string();
    if to_stderr {
        if COLOR.load(Ordering::Relaxed) {
            let tc = tag_color(tag);
            let lc = level_color(l);
            let (tc_end, lc_end) = (
                if tc.is_empty() { "" } else { RESET },
                if lc.is_empty() { "" } else { RESET },
            );
            eprintln!("[{DIM}{t:>6}{RESET}][{tc}{tag}{tc_end}] {lc}{sev}{msg}{lc_end}");
        } else {
            eprintln!("[{t:>6}][{tag}] {sev}{msg}");
        }
        if let Some(hook) = HOOK.get() {
            hook(l, tag, &msg);
        }
    }
    if file_enabled() {
        file_line(&format!("[{t:>6}][{tag}] {sev}{msg}"));
    }
}

/// 1 行書き出す(stderr へのレベル判定は済んでいる前提。マクロ [`logf!`] から使う)。
pub fn write(l: Level, tag: &str, args: std::fmt::Arguments<'_>) {
    emit(l, tag, args, true);
}

/// per-layer 強制トレース(`SM_MDNS_TRACE` / `SM_BTP_TRACE`)用: stderr へは
/// 「env で強制された or グローバルレベルが trace」のときだけ、ファイルへは常に出す。
pub fn trace_forced(env_forced: bool, tag: &str, args: std::fmt::Arguments<'_>) {
    emit(Level::Trace, tag, args, env_forced || enabled(Level::Trace));
}

/// レイヤタグ付きログ。`logf!(Level::Debug, "im", "...")`。
///
/// stderr はレベル判定どおり、ログファイルが有効ならレベルに関わらずファイルへ記録する。
macro_rules! logf {
    ($lvl:expr, $tag:expr, $($arg:tt)*) => {
        if crate::log::enabled($lvl) {
            crate::log::write($lvl, $tag, format_args!($($arg)*));
        } else if crate::log::file_enabled() {
            crate::log::file_only($lvl, $tag, format_args!($($arg)*));
        }
    };
}
pub(crate) use logf;

/// ファイルのみへ書く([`logf!`] の stderr レベル外分岐用)。
pub fn file_only(l: Level, tag: &str, args: std::fmt::Arguments<'_>) {
    emit(l, tag, args, false);
}

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

    #[test]
    fn color_mode_parse() {
        assert_eq!(ColorMode::parse("auto").unwrap(), ColorMode::Auto);
        assert_eq!(ColorMode::parse("always").unwrap(), ColorMode::Always);
        assert_eq!(ColorMode::parse("never").unwrap(), ColorMode::Never);
        assert!(ColorMode::parse("tty").is_err());
    }

    #[test]
    fn color_decision_matrix() {
        use ColorMode::*;
        // always/never はどの環境でも従う。
        assert!(color_decision(Always, false, false, true));
        assert!(!color_decision(Never, true, true, false));
        // auto: TTY で有効、パイプで無効。
        assert!(color_decision(Auto, true, false, false));
        assert!(!color_decision(Auto, false, false, false));
        // auto: NO_COLOR が最優先で無効化。
        assert!(!color_decision(Auto, true, false, true));
        assert!(!color_decision(Auto, true, true, true));
        // auto: SMCTL_FORCE_COLOR は非 TTY でも強制(Windows opt-in 兼パイプ検証用)。
        assert!(color_decision(Auto, false, true, false));
    }

    #[test]
    fn tag_and_level_colors() {
        assert_eq!(tag_color("im"), "\x1b[32m");
        assert_eq!(tag_color("sc"), "\x1b[35m");
        assert_eq!(tag_color("unknown-tag"), "");
        assert_eq!(level_color(Level::Error), "\x1b[31m");
        assert_eq!(level_color(Level::Warn), "\x1b[33m");
        assert_eq!(level_color(Level::Info), "");
    }

    #[test]
    fn log_file_records_all_levels_uncolored() {
        // FILE は OnceLock なのでプロセスで 1 回だけ。専用一時ファイルへ書く。
        let path = std::env::temp_dir().join(format!("smctl-log-test-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        init(Level::Info);
        init_file(&path);
        assert!(file_enabled());
        // 画面レベル(info)未満の trace 行もファイルには入る。
        logf!(Level::Trace, "tlv", "file-only trace line {}", 42);
        logf!(Level::Warn, "ctl", "warn line");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[tlv] file-only trace line 42"), "{text}");
        assert!(text.contains("[ctl] warn: warn line"), "{text}");
        // ファイルは常に無色(ESC が入らない)。
        assert!(!text.contains('\x1b'), "{text}");
        let _ = std::fs::remove_file(&path);
    }
}
