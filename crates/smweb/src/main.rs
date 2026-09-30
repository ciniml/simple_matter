//! `smweb` — PC 向け Web コントローラ(`docs/design/web-controller.md`)。
//!
//! Matter コントローラ機能を持つローカル HTTP サーバ。画面は同梱 HTML/JS、ブラウザからは
//! HTTP(JSON)/ WebSocket で状態取得・操作する。駆動コード(UDP/mDNS ランナー、
//! 状態ストア `~/.smctl`、クラスタ表、`Exec`)は `smctl` ライブラリを再利用する。
//!
//! W1: コントローラスレッド + `/api/info` `/api/nodes` `/api/nodes/{id}/connect`
//! `/api/nodes/{id}/attr/...` `/api/nodes/{id}/invoke/...` `/api/clusters` `/ws` + 最小 UI。
//! W2: Describe(汎用モデル)+ 種別判定 + 既定購読 / watch + 値キャッシュ + `Event::Attr` +
//! Dashboard / Devices / Log の単一ページ。
//!
//! `smctl` と同じ状態ディレクトリを共有するが、**同時実行は非サポート**(§4.4)。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use smctl::cli::Globals;
use smctl::log::Level;

/// smweb 自身のログ(smctl の `logf!` と同じ出力系、タグ `web`)。
macro_rules! wlog {
    ($lvl:expr, $($arg:tt)*) => {
        if smctl::log::enabled($lvl) {
            smctl::log::write($lvl, "web", format_args!($($arg)*));
        }
    };
}

mod api;
mod ctrl;
mod describe;
mod error;
mod model;
mod store;
mod value;
mod ws;

const USAGE: &str = "\
usage: smweb [options]

options:
  --bind <addr:port>             listen address (default 127.0.0.1:8080)
  --state-dir <dir>              smctl state directory (default ~/.smctl)
  --paa-trust-store-path <dir>   verify attestation against PAA certs (*.der)
  --bypass-attestation           skip device attestation entirely
  --timeout <secs>               per-operation timeout (default 20)
  --log <level>                  error|warn|info|debug|trace (default: $SMCTL_LOG or info)
  -h, --help                     show this help

Do not run smweb and smctl on the same state directory at the same time.";

/// 既定の待ち受けアドレス(ローカルのみ。認証・TLS 無し、§1.2)。
const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// 既定の操作タイムアウト(§6「既定 20 s」)。
const DEFAULT_TIMEOUT_S: f64 = 20.0;

/// コマンドライン引数。
struct Opts {
    bind: SocketAddr,
    globals: Globals,
}

/// 引数をパースする。`Ok(None)` は `--help`。
fn parse_args(args: &[String]) -> Result<Option<Opts>, String> {
    let mut g = Globals::defaults();
    g.timeout = Duration::from_secs_f64(DEFAULT_TIMEOUT_S);
    let mut bind: SocketAddr = DEFAULT_BIND.parse().expect("default bind");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (a.as_str(), None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match &inline {
                Some(v) => Ok(v.clone()),
                None => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("{name} requires a value")),
            }
        };
        match flag {
            "-h" | "--help" => return Ok(None),
            "--bind" => {
                let v = value(flag)?;
                bind = v
                    .parse()
                    .map_err(|_| format!("invalid --bind address {v:?} (expected ip:port)"))?;
            }
            "--state-dir" => g.state_dir = PathBuf::from(value(flag)?),
            "--paa-trust-store-path" => g.paa_trust_store_path = Some(PathBuf::from(value(flag)?)),
            "--bypass-attestation" => g.bypass_attestation = true,
            "--timeout" => {
                let v = value(flag)?;
                let s: f64 = v
                    .parse()
                    .ok()
                    .filter(|s: &f64| s.is_finite() && *s > 0.0)
                    .ok_or_else(|| format!("invalid --timeout {v:?} (seconds > 0)"))?;
                g.timeout = Duration::from_secs_f64(s);
            }
            "--log" | "--log-level" => g.log_level = Some(Level::parse(&value(flag)?)?),
            other => return Err(format!("unknown argument {other:?} (see --help)")),
        }
    }
    Ok(Some(Opts { bind, globals: g }))
}

fn level_name(l: Level) -> &'static str {
    match l {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&args) {
        Ok(Some(o)) => o,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("smweb: {e}");
            return ExitCode::FAILURE;
        }
    };

    // ログ: smctl と同じ stderr 出力(起動からの ms 付き)+ WebSocket への Event::Log。
    smctl::log::init(smctl::log::resolve(opts.globals.log_level));
    smctl::log::init_color(opts.globals.color);

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("smweb: tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    // 待ち受けを先に確保する。bind に失敗したらコントローラ(状態ディレクトリへの
    // アクセス・state.lock)は一切起動しない。
    let bind = opts.bind;
    let listener = match rt.block_on(tokio::net::TcpListener::bind(bind)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("smweb: bind {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (handle, thread) = ctrl::spawn(opts.globals.clone());
    {
        let events = handle.events.clone();
        smctl::log::set_hook(Box::new(move |l, tag, msg| {
            let _ = events.send(model::Event::Log {
                level: level_name(l),
                tag: tag.to_string(),
                msg: msg.to_string(),
                ts: model::unix_now_ms(),
            });
        }));
    }

    let r: Result<(), String> = rt.block_on(async move {
        if !bind.ip().is_loopback() {
            wlog!(
                Level::Warn,
                "listening on a non-loopback address without authentication/TLS"
            );
        }
        wlog!(Level::Info, "listening on http://{bind}/");
        let serve = axum::serve(listener, api::router(handle));
        tokio::select! {
            r = serve => r.map_err(|e| format!("http server: {e}")),
            _ = shutdown_signal() => {
                wlog!(Level::Info, "shutting down");
                Ok(())
            }
        }
    });
    // コントローラを止める(状態ファイルのロック区間は短いので、長いネットワーク待ちの
    // 途中なら待たずに抜ける)。
    if !thread.shutdown(Duration::from_secs(3)) {
        wlog!(Level::Debug, "controller thread still busy; exiting anyway");
    }
    rt.shutdown_timeout(Duration::from_millis(500));
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("smweb: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Ctrl-C(全 OS)/ SIGTERM(unix)。
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn defaults() {
        let o = parse_args(&[]).unwrap().unwrap();
        assert_eq!(o.bind.to_string(), "127.0.0.1:8080");
        assert_eq!(o.globals.timeout, Duration::from_secs(20));
        assert!(!o.globals.bypass_attestation);
    }

    #[test]
    fn flags() {
        let o = parse_args(&args(&[
            "--bind",
            "0.0.0.0:9000",
            "--state-dir=/tmp/x",
            "--timeout",
            "7.5",
            "--bypass-attestation",
            "--log",
            "debug",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(o.bind.port(), 9000);
        assert_eq!(o.globals.state_dir, PathBuf::from("/tmp/x"));
        assert_eq!(o.globals.timeout, Duration::from_millis(7500));
        assert!(o.globals.bypass_attestation);
        assert_eq!(o.globals.log_level, Some(Level::Debug));
        assert!(parse_args(&args(&["--help"])).unwrap().is_none());
        assert!(parse_args(&args(&["--bind", "nope"])).is_err());
        assert!(parse_args(&args(&["--timeout", "0"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["--state-dir"])).is_err());
    }
}
