//! バッチ実行モード(`smctl batch <file|->`)。
//!
//! 1 行 1 コマンド(文法は CLI と同一。`#` 以降はコメント、空行可)。全行を
//! **単一プロセス・単一 [`Exec`](crate::ops::Exec)** で順に実行するため、ノードごとの
//! CASE セッションと購読が行をまたいで共有される:
//!
//! - `subscribe` 行は購読のプライミング完了で次の行へ進む(非ブロッキング)。
//! - 以後の行の実行中・`wait <sec>` 中もデバイス発レポートを逐次表示する。
//! - EOF で購読ごとの受信レポート数を要約して終了する。
//!
//! これにより chip-tool の「subscribe と toggle が別プロセス = 購読が toggle 側の
//! 新規 CASE で破棄される」問題が、同一セッション共有により構造的に解消される。
//!
//! ```text
//! # demo.txt
//! pairing onnetwork 1 20202021
//! onoff subscribe on-off 0 10 1 1
//! wait 3
//! onoff toggle 1 1
//! wait 5
//! onoff read on-off 1 1
//! ```

use std::io::Read;

use crate::cli::{self, Cmd, Globals};
use crate::ops::Exec;
use crate::state::{ca as ca_state, StateDir};
use crate::OsRng;

/// バッチを実行する。`source` はファイルパスまたは `-`(stdin)。
///
/// 各行はパース段階で全量検証してから実行する(途中まで実行して文法エラーで
/// 止まる事故を防ぐ)。実行時エラーはその行で中断し、行番号を添えて返す。
pub fn run(g: &Globals, source: &str) -> Result<(), String> {
    let text = if source == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        buf
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("read {source}: {e}"))?
    };

    // 1) 全行パース(fail fast)。
    let mut program: Vec<(usize, Globals, Cmd)> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let tokens = tokenize(line).map_err(|e| format!("line {lineno}: {e}"))?;
        if tokens.iter().any(|t| t == "--state-dir") {
            return Err(format!(
                "line {lineno}: --state-dir cannot change inside a batch \
                 (pass it to `smctl batch` itself)"
            ));
        }
        let (lg, cmd) = cli::parse(&tokens, g).map_err(|e| format!("line {lineno}: {e}"))?;
        match cmd {
            Cmd::Batch { .. } => {
                return Err(format!("line {lineno}: nested batch is not supported"))
            }
            Cmd::PairBle { .. } => {
                return Err(format!(
                    "line {lineno}: pairing ble/ble-handoff is not supported inside a batch \
                     (commission over BLE first, then run the batch)"
                ))
            }
            _ => program.push((lineno, lg, cmd)),
        }
    }
    if program.is_empty() {
        return Err("batch is empty (no commands)".into());
    }

    // 2) 単一 Exec で順に実行。
    let state = StateDir::open(&g.state_dir)?;
    let crypto = simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let ca = {
        let _lock = state.lock()?;
        // バッチは pairing を含みうるので、CA が無ければ生成する。
        ca_state::load_or_create(&state.ca_path(), &crypto)?
    };
    let mut exec = Exec::new(g.clone(), state, &crypto, &ca, true)?;

    let total = program.len();
    for (step, (lineno, lg, cmd)) in program.into_iter().enumerate() {
        println!("[batch {}/{total}] line {lineno}", step + 1);
        exec.set_globals_for_line(lg);
        exec.run(&cmd).map_err(|e| {
            exec.summarize();
            format!("line {lineno}: {e}")
        })?;
    }

    // 3) EOF: 購読の受信数を要約して終了(購読はプロセス終了で破棄される。
    //    デバイス側は keep-alive 途絶で購読を掃除する)。
    exec.summarize();
    println!("[batch] done ({total} command(s))");
    Ok(())
}

/// `#` 以降を落とす(引用符内の `#` は保持)。
fn strip_comment(line: &str) -> &str {
    let mut in_sq = false;
    let mut in_dq = false;
    for (i, c) in line.char_indices() {
        match c {
            '\'' if !in_dq => in_sq = !in_sq,
            '"' if !in_sq => in_dq = !in_dq,
            '#' if !in_sq && !in_dq => return &line[..i],
            _ => {}
        }
    }
    line
}

/// 空白区切りトークナイザ(単一/二重引用符で空白を含むトークンを書ける)。
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut has_token = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    has_token = true;
                }
                c if c.is_whitespace() => {
                    if has_token {
                        out.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                c => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if quote.is_some() {
        return Err("unterminated quote".into());
    }
    if has_token {
        out.push(cur);
    }
    Ok(out)
}
