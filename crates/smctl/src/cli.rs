//! CLI 文法(設計 doc §1.3)とディスパッチ。手書きパーサ(clap 不採用、§2.3)。
//!
//! chip-tool の語順(`<cluster> <command|read|write|subscribe> ... <node-id> <endpoint>`)を
//! 踏襲した独自文法。名前は kebab-case 統一。ヘルプのクラスタ/属性/コマンド一覧は
//! クラスタレジストリ([`crate::clusters::CLUSTERS`])から生成する。

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use simple_matter::discovery::MATTER_PORT;

use crate::clusters::{self, ClusterDef};
use crate::ops::{self, parse_literal, parse_u64, Parsed, Target};

/// 共通オプション(全コマンドの前後どこに書いてもよい)。
pub struct Globals {
    /// 状態ディレクトリ(既定 `~/.smctl`)。
    pub state_dir: PathBuf,
    /// 操作全体のタイムアウト。
    pub timeout: Duration,
    /// `pairing` 時にアドレス帳へ付けるラベル。
    pub label: Option<String>,
}

/// 既定タイムアウト(コミッショニング + 運用往復)。
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn default_state_dir() -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match home {
        Some(h) => PathBuf::from(h).join(".smctl"),
        None => PathBuf::from(".smctl"),
    }
}

/// 引数列からフラグを抜き取り、(Globals, 位置引数) に分解する。
fn parse_globals(args: &[String]) -> Result<(Globals, Vec<String>), String> {
    let mut g = Globals {
        state_dir: default_state_dir(),
        timeout: DEFAULT_TIMEOUT,
        label: None,
    };
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state-dir" => {
                let v = it.next().ok_or("--state-dir requires a value")?;
                g.state_dir = PathBuf::from(v);
            }
            "--timeout" => {
                let v = it.next().ok_or("--timeout requires a value (seconds)")?;
                let secs: u64 = v.parse().map_err(|_| format!("invalid --timeout: {v:?}"))?;
                g.timeout = Duration::from_secs(secs);
            }
            "--label" => {
                let v = it.next().ok_or("--label requires a value")?;
                g.label = Some(v.clone());
            }
            "-h" | "--help" => {
                pos.clear();
                pos.push("help".to_string());
                // 以降は読み捨て(help を出して終わる)。
                break;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option {other:?} (see `smctl help`)"));
            }
            _ => pos.push(a.clone()),
        }
    }
    Ok((g, pos))
}

/// エントリポイント: 引数のパースとコマンドディスパッチ。
pub fn run(args: &[String]) -> Result<(), String> {
    let (g, pos) = parse_globals(args)?;
    let Some(cmd) = pos.first() else {
        print_help();
        return Ok(());
    };
    match cmd.as_str() {
        "help" => {
            print_help();
            Ok(())
        }
        "pairing" => run_pairing(&g, &pos[1..]),
        name => match clusters::by_name(name) {
            Some(def) => run_cluster(&g, def, &pos[1..]),
            None => Err(format!(
                "unknown command or cluster {name:?}; known clusters: {} (see `smctl help`)",
                cluster_names()
            )),
        },
    }
}

fn cluster_names() -> String {
    clusters::CLUSTERS
        .iter()
        .map(|c| c.name)
        .collect::<Vec<_>>()
        .join(", ")
}

// ==========================================================================
// pairing サブコマンド
// ==========================================================================

fn run_pairing(g: &Globals, args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "onnetwork" => {
            let [node, passcode] =
                expect_args(args, 1, 2, "pairing onnetwork <node-id> <passcode>")?[..]
            else {
                unreachable!()
            };
            ops::pair(
                g,
                parse_u64(node)?,
                parse_passcode(passcode)?,
                Target::Browse(None),
            )
        }
        "onnetwork-long" => {
            let [node, passcode, disc] = expect_args(
                args,
                1,
                3,
                "pairing onnetwork-long <node-id> <passcode> <discriminator>",
            )?[..] else {
                unreachable!()
            };
            let disc: u16 = disc
                .parse()
                .map_err(|_| format!("invalid discriminator: {disc:?}"))?;
            ops::pair(
                g,
                parse_u64(node)?,
                parse_passcode(passcode)?,
                Target::Browse(Some(disc)),
            )
        }
        "address" => {
            // pairing address <node-id> <passcode> <ip> [port]
            let rest = &args[1..];
            if rest.len() < 3 || rest.len() > 4 {
                return Err("usage: smctl pairing address <node-id> <passcode> <ip> [port]".into());
            }
            let ip: IpAddr = rest[2]
                .parse()
                .map_err(|_| format!("invalid ip: {:?}", rest[2]))?;
            let port: u16 = match rest.get(3) {
                Some(p) => p.parse().map_err(|_| format!("invalid port: {p:?}"))?,
                None => MATTER_PORT,
            };
            ops::pair(
                g,
                parse_u64(&rest[0])?,
                parse_passcode(&rest[1])?,
                Target::Addr(SocketAddr::new(ip, port)),
            )
        }
        "list" => ops::pairing_list(g),
        _ => Err(
            "usage: smctl pairing <onnetwork|onnetwork-long|address|list> ... (see `smctl help`)"
                .into(),
        ),
    }
}

fn parse_passcode(s: &str) -> Result<u32, String> {
    s.parse().map_err(|_| format!("invalid passcode: {s:?}"))
}

/// `args[skip..]` がちょうど `n` 個であることを検査して返す。
fn expect_args<'a>(
    args: &'a [String],
    skip: usize,
    n: usize,
    usage: &str,
) -> Result<Vec<&'a str>, String> {
    let rest = &args[skip.min(args.len())..];
    if rest.len() != n {
        return Err(format!("usage: smctl {usage}"));
    }
    Ok(rest.iter().map(String::as_str).collect())
}

// ==========================================================================
// クラスタ操作(read / write / subscribe / コマンド invoke)
// ==========================================================================

fn run_cluster(g: &Globals, def: &'static ClusterDef, args: &[String]) -> Result<(), String> {
    let Some(verb) = args.first() else {
        return Err(cluster_usage(def));
    };
    match verb.as_str() {
        "read" => {
            let [attr, node, ep] = expect_args(
                args,
                1,
                3,
                &format!("{} read <attr> <node-id> <endpoint>", def.name),
            )?[..] else {
                unreachable!()
            };
            let a = def
                .attr_by_name(attr)
                .ok_or_else(|| unknown_attr(def, attr))?;
            ops::read_attr(g, parse_u64(node)?, parse_ep(ep)?, def, a)
        }
        "write" => {
            let [attr, value, node, ep] = expect_args(
                args,
                1,
                4,
                &format!("{} write <attr> <value> <node-id> <endpoint>", def.name),
            )?[..] else {
                unreachable!()
            };
            let a = def
                .attr_by_name(attr)
                .ok_or_else(|| unknown_attr(def, attr))?;
            if !a.writable {
                return Err(format!("attribute {}/{} is not writable", def.name, a.name));
            }
            let v = parse_literal(a.kind, value)?;
            ops::write_attr(g, parse_u64(node)?, parse_ep(ep)?, def, a, v)
        }
        "subscribe" => run_subscribe(g, def, &args[1..]),
        name => {
            let cmd = def.cmd_by_name(name).ok_or_else(|| {
                format!(
                    "unknown command {name:?} for cluster {}; {}",
                    def.name,
                    cluster_usage(def)
                )
            })?;
            run_invoke(g, def, cmd, &args[1..])
        }
    }
}

/// `subscribe [<attr>] <min-interval> <max-interval> <node-id> <endpoint>`
///
/// `<attr>` 省略時はクラスタテーブルの先頭属性(onoff なら on-off)を購読する。
fn run_subscribe(g: &Globals, def: &'static ClusterDef, args: &[String]) -> Result<(), String> {
    let usage = format!(
        "usage: smctl {} subscribe [<attr>] <min-interval-s> <max-interval-s> <node-id> <endpoint>",
        def.name
    );
    // 先頭引数が数値なら <attr> 省略形とみなす(属性名は数字で始まらない)。
    let (attr, rest) = match args.first() {
        Some(a) if a.parse::<u16>().is_err() => {
            let attr = def.attr_by_name(a).ok_or_else(|| unknown_attr(def, a))?;
            (attr, &args[1..])
        }
        _ => {
            let attr = def
                .attrs
                .first()
                .ok_or_else(|| format!("cluster {} has no attributes in the table", def.name))?;
            (attr, args)
        }
    };
    if rest.len() != 4 {
        return Err(usage);
    }
    let min: u16 = rest[0]
        .parse()
        .map_err(|_| format!("invalid min interval: {:?}", rest[0]))?;
    let max: u16 = rest[1]
        .parse()
        .map_err(|_| format!("invalid max interval: {:?}", rest[1]))?;
    ops::subscribe_attr(
        g,
        parse_u64(&rest[2])?,
        parse_ep(&rest[3])?,
        def,
        attr,
        min,
        max,
    )
}

/// `<cmd> [<field-value>...] <node-id> <endpoint>`(フィールドはテーブル順の位置引数)。
fn run_invoke(
    g: &Globals,
    def: &'static ClusterDef,
    cmd: &'static crate::clusters::CmdDef,
    args: &[String],
) -> Result<(), String> {
    let required = cmd.fields.iter().filter(|f| !f.optional).count();
    let usage = || {
        let fields: String = cmd
            .fields
            .iter()
            .map(|f| {
                if f.optional {
                    format!(" [<{}:{}>]", f.name, f.kind.name())
                } else {
                    format!(" <{}:{}>", f.name, f.kind.name())
                }
            })
            .collect();
        format!(
            "usage: smctl {} {}{fields} <node-id> <endpoint>",
            def.name, cmd.name
        )
    };
    if args.len() < required + 2 || args.len() > cmd.fields.len() + 2 {
        return Err(usage());
    }
    let nvalues = args.len() - 2;
    let mut fields = Vec::with_capacity(nvalues);
    for (fd, v) in cmd.fields.iter().zip(&args[..nvalues]) {
        let parsed: Parsed = parse_literal(fd.kind, v)
            .map_err(|e| format!("field {}: {e}\n{}", fd.name, usage()))?;
        fields.push((fd.tag, fd.kind, parsed));
    }
    let node = parse_u64(&args[nvalues])?;
    let ep = parse_ep(&args[nvalues + 1])?;
    ops::invoke_cmd(g, node, ep, def, cmd, fields)
}

fn parse_ep(s: &str) -> Result<u16, String> {
    s.parse().map_err(|_| format!("invalid endpoint: {s:?}"))
}

fn unknown_attr(def: &ClusterDef, attr: &str) -> String {
    let known = def
        .attrs
        .iter()
        .map(|a| a.name)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "unknown attribute {attr:?} for cluster {}; known: {known}",
        def.name
    )
}

fn cluster_usage(def: &ClusterDef) -> String {
    format!(
        "usage: smctl {} <read|write|subscribe|{}> ... (see `smctl help`)",
        def.name,
        def.cmds
            .iter()
            .map(|c| c.name)
            .collect::<Vec<_>>()
            .join("|")
    )
}

// ==========================================================================
// ヘルプ(クラスタ一覧はレジストリから生成)
// ==========================================================================

fn print_help() {
    println!(
        "\
smctl — CLI Matter controller built on simple-matter (development tool;
device attestation is NOT verified)

USAGE:
  smctl pairing onnetwork       <node-id> <passcode>
  smctl pairing onnetwork-long  <node-id> <passcode> <discriminator>
  smctl pairing address         <node-id> <passcode> <ip> [port]
  smctl pairing list
  smctl <cluster> read       <attr> <node-id> <endpoint>
  smctl <cluster> write      <attr> <value> <node-id> <endpoint>
  smctl <cluster> subscribe  [<attr>] <min-s> <max-s> <node-id> <endpoint>
  smctl <cluster> <command>  [<field-value>...] <node-id> <endpoint>

OPTIONS:
  --state-dir <dir>   state directory (default ~/.smctl)
  --timeout <sec>     overall operation timeout (default 30)
  --label <text>      label recorded in the address book on pairing

ENVIRONMENT:
  SM_MDNS_TRACE=1     trace mDNS queries/answers on stderr

CLUSTERS:"
    );
    for def in clusters::CLUSTERS {
        println!("  {} ({:#06x})", def.name, def.id.0);
        for a in def.attrs {
            println!(
                "    attr {:<28} {:#06x}  {}{}",
                a.name,
                a.id.0,
                a.kind.name(),
                if a.writable { " (writable)" } else { "" }
            );
        }
        for c in def.cmds {
            let fields: String = c
                .fields
                .iter()
                .map(|f| format!(" <{}:{}>", f.name, f.kind.name()))
                .collect();
            println!("    cmd  {:<28} {:#04x} {fields}", c.name, c.id.0);
        }
    }
    println!(
        "\nEXAMPLES:
  smctl pairing onnetwork 1 20202021
  smctl onoff toggle 1 1
  smctl onoff read on-off 1 1
  smctl basic-information read vendor-id 1 0
  smctl onoff subscribe 0 10 1 1     # subscribe on-off; Ctrl-C to stop"
    );
}
