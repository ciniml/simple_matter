//! CLI 文法(設計 doc §1.3)とディスパッチ。手書きパーサ(clap 不採用、§2.3)。
//!
//! chip-tool の語順(`<cluster> <command|read|write|subscribe> ... <node-id> <endpoint>`)を
//! 踏襲した独自文法。名前は kebab-case 統一。ヘルプのクラスタ/属性/コマンド一覧は
//! クラスタレジストリ([`crate::clusters::CLUSTERS`])から生成する。
//!
//! C2 でパースと実行を分離した: [`parse`] が引数列を [`Cmd`] に落とし、実行は
//! [`crate::ops::Exec`] が担う。バッチ([`crate::batch`])は同じ [`parse`] を
//! 1 行ずつに適用する(CLI 文法とバッチ文法が定義から一致する)。

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use simple_matter::discovery::MATTER_PORT;
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId};

use crate::clusters::{self, ClusterDef, ValueKind};
use crate::ops::{parse_literal, parse_typed_literal, parse_u64, Parsed, Target};

/// 共通オプション(全コマンドの前後どこに書いてもよい)。
pub struct Globals {
    /// 状態ディレクトリ(既定 `~/.smctl`)。
    pub state_dir: PathBuf,
    /// 操作全体のタイムアウト。
    pub timeout: Duration,
    /// `pairing` 時にアドレス帳へ付けるラベル。
    pub label: Option<String>,
    /// `discover commissionable --discriminator N` のフィルタ。
    pub discriminator: Option<u16>,
    /// 機械可読 JSON 出力(1 行 1 オブジェクト)。情報行は stderr へ逃がす。
    pub json: bool,
    /// `admincommissioning open-window --passcode N`(省略時は乱数生成)。
    pub passcode: Option<u32>,
    /// `--timed <ms>`: invoke を timed interaction(TimedRequest → Invoke)で行う。
    pub timed_ms: Option<u16>,
    /// `--paa-trust-store-path <dir>`: 指定時、pairing で device attestation を検証する
    /// (ディレクトリ内の `*.der` を PAA 信頼ストアとして読む)。未指定は検証スキップ。
    pub paa_trust_store_path: Option<PathBuf>,
    /// `--at <ip>[,<ip>...]`: VPN 越しのユニキャスト mDNS 直叩き(matter-over-vpn.md V1/C1)。
    /// 指定時、mDNS 発見はマルチキャスト browse の代わりに各ホストの `:5353` へ QU クエリを
    /// ユニキャスト送信し、応答の A/AAAA でなく**クエリ宛先 IP** を接続先に採用する。
    /// discover commissionable/operational・pairing onnetwork[-long]・CASE 再解決に効く。
    pub at: Option<Vec<IpAddr>>,
}

impl Globals {
    /// 既定値。
    pub fn defaults() -> Self {
        Self {
            state_dir: default_state_dir(),
            timeout: DEFAULT_TIMEOUT,
            label: None,
            discriminator: None,
            json: false,
            passcode: None,
            timed_ms: None,
            paa_trust_store_path: None,
            at: None,
        }
    }
}

impl Clone for Globals {
    fn clone(&self) -> Self {
        Self {
            state_dir: self.state_dir.clone(),
            timeout: self.timeout,
            label: self.label.clone(),
            discriminator: self.discriminator,
            json: self.json,
            passcode: self.passcode,
            timed_ms: self.timed_ms,
            paa_trust_store_path: self.paa_trust_store_path.clone(),
            at: self.at.clone(),
        }
    }
}

/// パース済みの 1 コマンド。名前ベースの操作も ID ベースへ正規化済み
/// (表示時の名前引きは [`crate::clusters::by_id`] が行う)。
#[derive(Clone)]
pub enum Cmd {
    Help,
    PairingList,
    /// UDP コミッショニング(onnetwork / onnetwork-long / address)。
    Pair {
        node: u64,
        passcode: u32,
        target: Target,
    },
    /// BLE コミッショニング(`handoff` = 方向 B: AddNOC 後に運用 UDP へ遷移)。
    /// `wifi = Some((ssid, password))` は `pairing ble-wifi`: AddNOC 後に同 BLE 上で
    /// Wi-Fi をプロビジョンし、CASE 以降を運用 UDP で行う(handoff 相当の遷移込み)。
    /// feature `ble` 無効ビルドでもパースは通し、実行時にエラーを返す。
    #[cfg_attr(not(feature = "ble"), allow(dead_code))]
    PairBle {
        node: u64,
        passcode: u32,
        discriminator: Option<u16>,
        handoff: bool,
        wifi: Option<(String, String)>,
    },
    DiscoverCommissionable {
        discriminator: Option<u16>,
    },
    DiscoverOperational {
        node: u64,
    },
    /// 属性 Read(`attr = None` は属性ワイルドカード)。
    Read {
        node: u64,
        ep: u16,
        cluster: ClusterId,
        attr: Option<AttributeId>,
    },
    Write {
        node: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        kind: ValueKind,
        value: Parsed,
    },
    Invoke {
        node: u64,
        ep: u16,
        cluster: ClusterId,
        command: CommandId,
        fields: Vec<(u8, ValueKind, Parsed)>,
        /// コマンドフィールド struct 全体のエンコード済み TLV(`tlv:<hex>`)。
        raw_fields: Option<Vec<u8>>,
    },
    Subscribe {
        node: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        min_s: u16,
        max_s: u16,
    },
    /// バッチ組み込み: 購読レポートを受信しながら待つ。
    Wait {
        secs: f64,
    },
    /// AdministratorCommissioning: ECM 窓オープン(SPAKE2+ verifier 生成 + timed invoke。
    /// `docs/design/admin-commissioning.md` §6)。
    AdminOpenWindow {
        node: u64,
        timeout_s: u16,
        discriminator: u16,
        /// 省略時は乱数生成(無効パスコードを除外)。
        passcode: Option<u32>,
    },
    /// AdministratorCommissioning: RevokeCommissioning(timed invoke)。
    AdminRevoke {
        node: u64,
    },
    /// バッチ実行(`-` = stdin)。
    Batch {
        source: String,
    },
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
fn parse_globals(args: &[String], base: &Globals) -> Result<(Globals, Vec<String>), String> {
    let mut g = base.clone();
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
            "--discriminator" => {
                let v = it.next().ok_or("--discriminator requires a value")?;
                let d: u16 = v
                    .parse()
                    .map_err(|_| format!("invalid --discriminator: {v:?}"))?;
                g.discriminator = Some(d);
            }
            "--json" => g.json = true,
            "--passcode" => {
                let v = it.next().ok_or("--passcode requires a value")?;
                let p: u32 = v
                    .parse()
                    .map_err(|_| format!("invalid --passcode: {v:?}"))?;
                g.passcode = Some(p);
            }
            "--timed" => {
                let v = it.next().ok_or("--timed requires a value (milliseconds)")?;
                let ms: u16 = v.parse().map_err(|_| format!("invalid --timed: {v:?}"))?;
                g.timed_ms = Some(ms);
            }
            "--paa-trust-store-path" => {
                let v = it
                    .next()
                    .ok_or("--paa-trust-store-path requires a directory")?;
                g.paa_trust_store_path = Some(PathBuf::from(v));
            }
            "--at" => {
                let v = it.next().ok_or("--at requires <ip>[,<ip>...]")?;
                let mut ips = Vec::new();
                for part in v.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let ip: IpAddr = part
                        .parse()
                        .map_err(|_| format!("invalid --at ip: {part:?}"))?;
                    ips.push(ip);
                }
                if ips.is_empty() {
                    return Err("--at requires at least one ip".into());
                }
                g.at = Some(ips);
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

/// 引数列を (Globals, [`Cmd`]) にパースする(実行はしない)。
pub fn parse(args: &[String], base: &Globals) -> Result<(Globals, Cmd), String> {
    let (g, pos) = parse_globals(args, base)?;
    let Some(cmd) = pos.first() else {
        return Ok((g, Cmd::Help));
    };
    let cmd = match cmd.as_str() {
        "help" => Cmd::Help,
        "pairing" => parse_pairing(&pos[1..])?,
        "admincommissioning" => parse_admincommissioning(&g, &pos[1..])?,
        "discover" => parse_discover(&g, &pos[1..])?,
        "any" => parse_any(&pos[1..])?,
        "wait" => {
            let [secs] = expect_args(&pos, 1, 1, "wait <seconds>")?[..] else {
                unreachable!()
            };
            let secs: f64 = secs
                .parse()
                .map_err(|_| format!("invalid wait seconds: {secs:?}"))?;
            if !(0.0..=86_400.0).contains(&secs) {
                return Err(format!("wait seconds out of range: {secs}"));
            }
            Cmd::Wait { secs }
        }
        "batch" => {
            let [source] = expect_args(&pos, 1, 1, "batch <file|->")?[..] else {
                unreachable!()
            };
            Cmd::Batch {
                source: source.to_string(),
            }
        }
        name => match clusters::by_name(name) {
            Some(def) => parse_cluster(def, &pos[1..])?,
            None => {
                return Err(format!(
                    "unknown command or cluster {name:?}; known clusters: {} (see `smctl help`)",
                    cluster_names()
                ))
            }
        },
    };
    Ok((g, cmd))
}

/// エントリポイント: 引数のパースとコマンドディスパッチ。
pub fn run(args: &[String]) -> Result<(), String> {
    let (g, cmd) = parse(args, &Globals::defaults())?;
    dispatch(&g, cmd)
}

/// 単発コマンドのディスパッチ。
pub fn dispatch(g: &Globals, cmd: Cmd) -> Result<(), String> {
    crate::json::set_mode(g.json);
    match cmd {
        Cmd::Help => {
            print_help();
            Ok(())
        }
        Cmd::PairingList => crate::ops::pairing_list(g),
        Cmd::DiscoverCommissionable { discriminator } => {
            crate::ops::discover_commissionable(g, discriminator)
        }
        Cmd::DiscoverOperational { node } => crate::ops::discover_operational(g, node),
        Cmd::Batch { source } => crate::batch::run(g, &source),
        Cmd::Wait { .. } => Err("`wait` is a batch built-in (use it inside `smctl batch`)".into()),
        #[cfg(feature = "ble")]
        Cmd::PairBle {
            node,
            passcode,
            discriminator,
            handoff,
            wifi,
        } => crate::runner::ble::pair_ble(g, node, passcode, discriminator, handoff, wifi),
        #[cfg(not(feature = "ble"))]
        Cmd::PairBle { .. } => {
            Err("BLE support is not compiled in; rebuild with `--features ble`".into())
        }
        other => crate::ops::run_single(g, other),
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
// pairing / discover サブコマンド
// ==========================================================================

fn parse_pairing(args: &[String]) -> Result<Cmd, String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "onnetwork" => {
            let [node, passcode] =
                expect_args(args, 1, 2, "pairing onnetwork <node-id> <passcode>")?[..]
            else {
                unreachable!()
            };
            Ok(Cmd::Pair {
                node: parse_u64(node)?,
                passcode: parse_passcode(passcode)?,
                target: Target::Browse(None),
            })
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
            Ok(Cmd::Pair {
                node: parse_u64(node)?,
                passcode: parse_passcode(passcode)?,
                target: Target::Browse(Some(parse_disc(disc)?)),
            })
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
            Ok(Cmd::Pair {
                node: parse_u64(&rest[0])?,
                passcode: parse_passcode(&rest[1])?,
                target: Target::Addr(SocketAddr::new(ip, port)),
            })
        }
        "ble" | "ble-handoff" => {
            // pairing ble[-handoff] <node-id> <passcode> [discriminator]
            let rest = &args[1..];
            if rest.len() < 2 || rest.len() > 3 {
                return Err(format!(
                    "usage: smctl pairing {sub} <node-id> <passcode> [discriminator]"
                ));
            }
            let discriminator = match rest.get(2) {
                Some(d) => Some(parse_disc(d)?),
                None => None,
            };
            Ok(Cmd::PairBle {
                node: parse_u64(&rest[0])?,
                passcode: parse_passcode(&rest[1])?,
                discriminator,
                handoff: sub == "ble-handoff",
                wifi: None,
            })
        }
        "ble-wifi" => {
            // pairing ble-wifi <node-id> <passcode> <ssid> <password> [discriminator]
            let rest = &args[1..];
            if rest.len() < 4 || rest.len() > 5 {
                return Err(
                    "usage: smctl pairing ble-wifi <node-id> <passcode> <ssid> <password> \
                     [discriminator]"
                        .into(),
                );
            }
            let ssid = rest[2].clone();
            let password = rest[3].clone();
            if ssid.is_empty() || ssid.len() > 32 {
                return Err(format!("invalid ssid (1..=32 bytes): {ssid:?}"));
            }
            if password.len() > 64 {
                return Err("invalid wifi password (max 64 bytes)".into());
            }
            let discriminator = match rest.get(4) {
                Some(d) => Some(parse_disc(d)?),
                None => None,
            };
            Ok(Cmd::PairBle {
                node: parse_u64(&rest[0])?,
                passcode: parse_passcode(&rest[1])?,
                discriminator,
                handoff: false,
                wifi: Some((ssid, password)),
            })
        }
        "list" => Ok(Cmd::PairingList),
        _ => Err(
            "usage: smctl pairing <onnetwork|onnetwork-long|address|ble|ble-handoff|ble-wifi|\
             list> ... (see `smctl help`)"
                .into(),
        ),
    }
}

/// `admincommissioning <open-window|revoke>`(専用サブコマンド。汎用 invoke と違い
/// open-window は PAKE verifier の生成と manual pairing code の表示まで行う)。
fn parse_admincommissioning(g: &Globals, args: &[String]) -> Result<Cmd, String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "open-window" => {
            let [node, timeout, disc] = expect_args(
                args,
                1,
                3,
                "admincommissioning open-window <node-id> <timeout-s> <discriminator> \
                 [--passcode N]",
            )?[..] else {
                unreachable!()
            };
            let timeout_s: u16 = timeout
                .parse()
                .map_err(|_| format!("invalid timeout: {timeout:?}"))?;
            let discriminator = parse_disc(disc)?;
            if discriminator > 0x0FFF {
                return Err(format!(
                    "discriminator out of range (12-bit): {discriminator}"
                ));
            }
            Ok(Cmd::AdminOpenWindow {
                node: parse_u64(node)?,
                timeout_s,
                discriminator,
                passcode: g.passcode,
            })
        }
        "revoke" => {
            let [node] = expect_args(args, 1, 1, "admincommissioning revoke <node-id>")?[..] else {
                unreachable!()
            };
            Ok(Cmd::AdminRevoke {
                node: parse_u64(node)?,
            })
        }
        _ => Err(
            "usage: smctl admincommissioning <open-window|revoke> ... (see `smctl help`)".into(),
        ),
    }
}

fn parse_discover(g: &Globals, args: &[String]) -> Result<Cmd, String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "commissionable" => {
            if args.len() != 1 {
                return Err("usage: smctl discover commissionable [--discriminator N]".into());
            }
            Ok(Cmd::DiscoverCommissionable {
                discriminator: g.discriminator,
            })
        }
        "operational" => {
            let [node] = expect_args(args, 1, 1, "discover operational <node-id>")?[..] else {
                unreachable!()
            };
            Ok(Cmd::DiscoverOperational {
                node: parse_u64(node)?,
            })
        }
        _ => {
            Err("usage: smctl discover <commissionable|operational> ... (see `smctl help`)".into())
        }
    }
}

fn parse_passcode(s: &str) -> Result<u32, String> {
    s.parse().map_err(|_| format!("invalid passcode: {s:?}"))
}

fn parse_disc(s: &str) -> Result<u16, String> {
    s.parse()
        .map_err(|_| format!("invalid discriminator: {s:?}"))
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
// any(ID 直指定。テーブル未収載クラスタの escape hatch、設計 doc §1.3)
// ==========================================================================

fn parse_any(args: &[String]) -> Result<Cmd, String> {
    let sub = args.first().map(String::as_str).unwrap_or("");
    match sub {
        "read" => {
            let [node, ep, cid, aid] = expect_args(
                args,
                1,
                4,
                "any read <node-id> <endpoint> <cluster-id> <attribute-id|*>",
            )?[..] else {
                unreachable!()
            };
            let attr = if aid == "*" {
                None
            } else {
                Some(AttributeId(parse_id32(aid)?))
            };
            Ok(Cmd::Read {
                node: parse_u64(node)?,
                ep: parse_ep(ep)?,
                cluster: ClusterId(parse_id32(cid)?),
                attr,
            })
        }
        "write" => {
            let [node, ep, cid, aid, value] = expect_args(
                args,
                1,
                5,
                "any write <node-id> <endpoint> <cluster-id> <attribute-id> <type>:<value>",
            )?[..] else {
                unreachable!()
            };
            let (kind, value) = parse_typed_literal(value)?;
            Ok(Cmd::Write {
                node: parse_u64(node)?,
                ep: parse_ep(ep)?,
                cluster: ClusterId(parse_id32(cid)?),
                attr: AttributeId(parse_id32(aid)?),
                kind,
                value,
            })
        }
        "invoke" => {
            // any invoke <node> <ep> <cluster-id> <command-id> [<tag>=<type>:<value>... | tlv:<hex>]
            let rest = &args[1..];
            if rest.len() < 4 {
                return Err("usage: smctl any invoke <node-id> <endpoint> <cluster-id> \
                     <command-id> [<tag>=<type>:<value>... | tlv:<hex>]"
                    .into());
            }
            let mut fields = Vec::new();
            let mut raw_fields = None;
            for arg in &rest[4..] {
                if let Some(hex) = arg.strip_prefix("tlv:") {
                    if raw_fields.is_some() || !fields.is_empty() {
                        return Err(
                            "tlv:<hex> replaces the whole command-fields struct and cannot be \
                             combined with <tag>=<value> fields"
                                .into(),
                        );
                    }
                    match parse_typed_literal(&format!("tlv:{hex}"))? {
                        (_, Parsed::RawTlv(b)) => raw_fields = Some(b),
                        _ => unreachable!(),
                    }
                } else {
                    let (tag, lit) = arg.split_once('=').ok_or_else(|| {
                        format!("expected <tag>=<type>:<value> field, got {arg:?}")
                    })?;
                    let tag: u8 = tag
                        .parse()
                        .map_err(|_| format!("invalid field tag: {tag:?}"))?;
                    if raw_fields.is_some() {
                        return Err("cannot mix <tag>=<value> fields with tlv:<hex>".into());
                    }
                    let (kind, value) = parse_typed_literal(lit)?;
                    fields.push((tag, kind, value));
                }
            }
            Ok(Cmd::Invoke {
                node: parse_u64(&rest[0])?,
                ep: parse_ep(&rest[1])?,
                cluster: ClusterId(parse_id32(&rest[2])?),
                command: CommandId(parse_id32(&rest[3])?),
                fields,
                raw_fields,
            })
        }
        _ => Err("usage: smctl any <read|write|invoke> ... (see `smctl help`)".into()),
    }
}

fn parse_id32(s: &str) -> Result<u32, String> {
    let v = parse_u64(s)?;
    u32::try_from(v).map_err(|_| format!("id out of range: {s:?}"))
}

// ==========================================================================
// クラスタ操作(read / write / subscribe / コマンド invoke)
// ==========================================================================

fn parse_cluster(def: &'static ClusterDef, args: &[String]) -> Result<Cmd, String> {
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
            Ok(Cmd::Read {
                node: parse_u64(node)?,
                ep: parse_ep(ep)?,
                cluster: def.id,
                attr: Some(a.id),
            })
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
            Ok(Cmd::Write {
                node: parse_u64(node)?,
                ep: parse_ep(ep)?,
                cluster: def.id,
                attr: a.id,
                kind: a.kind,
                value: v,
            })
        }
        "subscribe" => parse_subscribe(def, &args[1..]),
        name => {
            let cmd = def.cmd_by_name(name).ok_or_else(|| {
                format!(
                    "unknown command {name:?} for cluster {}; {}",
                    def.name,
                    cluster_usage(def)
                )
            })?;
            parse_invoke(def, cmd, &args[1..])
        }
    }
}

/// `subscribe [<attr>] <min-interval> <max-interval> <node-id> <endpoint>`
///
/// `<attr>` 省略時はクラスタテーブルの先頭属性(onoff なら on-off)を購読する。
fn parse_subscribe(def: &'static ClusterDef, args: &[String]) -> Result<Cmd, String> {
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
    Ok(Cmd::Subscribe {
        node: parse_u64(&rest[2])?,
        ep: parse_ep(&rest[3])?,
        cluster: def.id,
        attr: attr.id,
        min_s: min,
        max_s: max,
    })
}

/// `<cmd> [<field-value>...] <node-id> <endpoint>`(フィールドはテーブル順の位置引数)。
fn parse_invoke(
    def: &'static ClusterDef,
    cmd: &'static crate::clusters::CmdDef,
    args: &[String],
) -> Result<Cmd, String> {
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
    Ok(Cmd::Invoke {
        node: parse_u64(&args[nvalues])?,
        ep: parse_ep(&args[nvalues + 1])?,
        cluster: def.id,
        command: cmd.id,
        fields,
        raw_fields: None,
    })
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

pub(crate) fn print_help() {
    println!(
        "\
smctl — CLI Matter controller built on simple-matter (development tool;
device attestation is verified only with --paa-trust-store-path, otherwise skipped)

USAGE:
  smctl pairing onnetwork       <node-id> <passcode>
  smctl pairing onnetwork-long  <node-id> <passcode> <discriminator>
  smctl pairing address         <node-id> <passcode> <ip> [port]
  smctl pairing ble             <node-id> <passcode> [discriminator]   (CASE over BLE)
  smctl pairing ble-handoff     <node-id> <passcode> [discriminator]   (AddNOC over BLE -> CASE over UDP)
  smctl pairing ble-wifi        <node-id> <passcode> <ssid> <password> [discriminator]
                                (BLE commissioning + WiFi provisioning -> CASE over UDP)
  smctl pairing list
  smctl admincommissioning open-window <node-id> <timeout-s> <discriminator> [--passcode N]
                                (open an enhanced commissioning window; prints the
                                 generated passcode + manual pairing code)
  smctl admincommissioning revoke <node-id>
  smctl discover commissionable [--discriminator N]
  smctl discover operational <node-id>
  smctl <cluster> read       <attr> <node-id> <endpoint>
  smctl <cluster> write      <attr> <value> <node-id> <endpoint>
  smctl <cluster> subscribe  [<attr>] <min-s> <max-s> <node-id> <endpoint>
  smctl <cluster> <command>  [<field-value>...] <node-id> <endpoint>
  smctl any read   <node-id> <endpoint> <cluster-id> <attribute-id|*>
  smctl any write  <node-id> <endpoint> <cluster-id> <attribute-id> <type>:<value>
  smctl any invoke <node-id> <endpoint> <cluster-id> <command-id>
                   [<tag>=<type>:<value>... | tlv:<hex>]
  smctl batch <file|->       one command per line (# comments); CASE sessions and
                             subscriptions are shared across lines; `wait <sec>`
                             receives subscription reports between commands

VALUE LITERALS (any):
  bool:true  u16:1234  i8:-3  f32:1.5  str:hello  hex:0a0b  null
  tlv:<hex>  pre-encoded TLV element (whole command-fields struct for invoke)

OPTIONS:
  --state-dir <dir>     state directory (default ~/.smctl)
  --timeout <sec>       overall operation timeout (default 30)
  --label <text>        label recorded in the address book on pairing
  --discriminator <n>   filter for `discover commissionable`
  --at <ip>[,<ip>...]   resolve over VPN by unicast mDNS instead of multicast:
                        send a QU query to each <ip>:5353 and adopt the query
                        destination IP (not the advertised A/AAAA) as the connect
                        address, with the port from the SRV reply. IPs may be v4
                        or v6 literals (fe80 gets its link-local scope filled).
                        Applies to discover commissionable/operational, pairing
                        onnetwork[-long], and CASE re-resolution (matter-over-vpn V1)
  --passcode <n>        passcode for `admincommissioning open-window` (default: random)
  --timed <ms>          send cluster command invokes as timed interactions
                        (TimedRequest -> Invoke); required by some commands
  --paa-trust-store-path <dir>
                        verify device attestation during pairing using the PAA
                        certificates (*.der) in <dir>; omit to skip verification
  --json                machine-readable output: one JSON object per line on
                        stdout (read/write/invoke/subscribe reports/discover);
                        human-readable progress moves to stderr. Works in
                        batch mode too (per-line override allowed)

ENVIRONMENT:
  SM_MDNS_TRACE=1     trace mDNS queries/answers on stderr
  SM_BTP_TRACE=1      trace BTP fragments on stderr (BLE)
  SM_BLE_ADAPTER=hciN BLE adapter for pairing ble/ble-handoff/ble-wifi

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
  smctl any read 1 0 0x0028 1                  # basic-information vendor-id by id
  smctl any invoke 1 1 0x0006 0x02             # onoff toggle by id
  smctl onoff subscribe 0 10 1 1               # subscribe on-off; Ctrl-C to stop
  smctl batch demo.txt                         # subscribe + toggle in one process"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    fn parse_ok(s: &str) -> (Globals, Cmd) {
        parse(&argv(s), &Globals::defaults()).expect(s)
    }

    fn parse_err(s: &str) -> String {
        match parse(&argv(s), &Globals::defaults()) {
            Ok(_) => panic!("expected error for {s:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn pairing_onnetwork() {
        let (_, cmd) = parse_ok("pairing onnetwork 1 20202021");
        match cmd {
            Cmd::Pair {
                node,
                passcode,
                target: Target::Browse(None),
            } => {
                assert_eq!(node, 1);
                assert_eq!(passcode, 20202021);
            }
            _ => panic!("wrong parse"),
        }
    }

    #[test]
    fn pairing_onnetwork_long_and_address() {
        let (_, cmd) = parse_ok("pairing onnetwork-long 2 20202021 3840");
        assert!(matches!(
            cmd,
            Cmd::Pair {
                node: 2,
                target: Target::Browse(Some(3840)),
                ..
            }
        ));
        let (_, cmd) = parse_ok("pairing address 3 20202021 192.168.1.5 5541");
        match cmd {
            Cmd::Pair {
                node: 3,
                target: Target::Addr(sa),
                ..
            } => assert_eq!(sa, "192.168.1.5:5541".parse().unwrap()),
            _ => panic!("wrong parse"),
        }
        // port omitted -> MATTER_PORT
        let (_, cmd) = parse_ok("pairing address 3 20202021 10.0.0.1");
        match cmd {
            Cmd::Pair {
                target: Target::Addr(sa),
                ..
            } => assert_eq!(sa.port(), MATTER_PORT),
            _ => panic!("wrong parse"),
        }
    }

    #[test]
    fn pairing_ble_variants() {
        let (_, cmd) = parse_ok("pairing ble 1 20202021 3840");
        assert!(matches!(
            cmd,
            Cmd::PairBle {
                node: 1,
                passcode: 20202021,
                discriminator: Some(3840),
                handoff: false,
                wifi: None,
            }
        ));
        let (_, cmd) = parse_ok("pairing ble-handoff 1 20202021");
        assert!(matches!(
            cmd,
            Cmd::PairBle {
                handoff: true,
                discriminator: None,
                wifi: None,
                ..
            }
        ));
        // ble-wifi: ssid/password 必須、discriminator は省略可。
        let (_, cmd) = parse_ok("pairing ble-wifi 1 20202021 iotap hogeFugapiyo 3840");
        match cmd {
            Cmd::PairBle {
                node: 1,
                passcode: 20202021,
                discriminator: Some(3840),
                handoff: false,
                wifi: Some((ssid, pw)),
            } => {
                assert_eq!(ssid, "iotap");
                assert_eq!(pw, "hogeFugapiyo");
            }
            _ => panic!("wrong parse"),
        }
        let (_, cmd) = parse_ok("pairing ble-wifi 1 20202021 iotap hogeFugapiyo");
        assert!(matches!(
            cmd,
            Cmd::PairBle {
                discriminator: None,
                wifi: Some(_),
                ..
            }
        ));
        assert!(parse_err("pairing ble-wifi 1 20202021 iotap").starts_with("usage:"));
        assert!(parse_err(&format!(
            "pairing ble-wifi 1 20202021 {} pw",
            "s".repeat(33)
        ))
        .contains("invalid ssid"));
    }

    #[test]
    fn global_flags_anywhere() {
        let (g, cmd) = parse_ok("--state-dir /tmp/x onoff toggle 7 1 --timeout 5 --json");
        assert_eq!(g.state_dir, PathBuf::from("/tmp/x"));
        assert_eq!(g.timeout, Duration::from_secs(5));
        assert!(g.json);
        match cmd {
            Cmd::Invoke {
                node,
                ep,
                cluster,
                command,
                ref fields,
                raw_fields: None,
            } => {
                assert_eq!((node, ep), (7, 1));
                assert_eq!(cluster, ClusterId(0x0006));
                assert_eq!(command, CommandId(0x02));
                assert!(fields.is_empty());
            }
            _ => panic!("wrong parse"),
        }
    }

    #[test]
    fn cluster_read_by_name() {
        let (_, cmd) = parse_ok("onoff read on-off 1 1");
        assert!(matches!(
            cmd,
            Cmd::Read {
                node: 1,
                ep: 1,
                cluster: ClusterId(0x0006),
                attr: Some(AttributeId(0x0000)),
            }
        ));
    }

    #[test]
    fn any_read_and_invoke_by_id() {
        let (_, cmd) = parse_ok("any read 1 0 0x0028 1");
        assert!(matches!(
            cmd,
            Cmd::Read {
                cluster: ClusterId(0x0028),
                attr: Some(AttributeId(1)),
                ..
            }
        ));
        let (_, cmd) = parse_ok("any read 1 0 0x0006 *");
        assert!(matches!(cmd, Cmd::Read { attr: None, .. }));
        let (_, cmd) = parse_ok("any invoke 1 1 0x0006 0x02");
        assert!(matches!(
            cmd,
            Cmd::Invoke {
                cluster: ClusterId(0x0006),
                command: CommandId(0x02),
                ..
            }
        ));
    }

    #[test]
    fn errors_are_reported() {
        assert!(parse_err("bogus-cluster toggle 1 1").contains("unknown command or cluster"));
        assert!(parse_err("onoff read bogus-attr 1 1").contains("unknown attribute"));
        assert!(parse_err("onoff bogus-cmd 1 1").contains("unknown command"));
        assert!(parse_err("pairing onnetwork 1").starts_with("usage:"));
        assert!(parse_err("--frobnicate onoff toggle 1 1").contains("unknown option"));
        assert!(parse_err("pairing onnetwork x 20202021").contains("invalid"));
    }

    #[test]
    fn admincommissioning_open_window_and_revoke() {
        let (_, cmd) = parse_ok("admincommissioning open-window 1 300 3841");
        assert!(matches!(
            cmd,
            Cmd::AdminOpenWindow {
                node: 1,
                timeout_s: 300,
                discriminator: 3841,
                passcode: None,
            }
        ));
        let (g, cmd) = parse_ok("admincommissioning open-window 1 300 3841 --passcode 12341234");
        assert!(matches!(
            cmd,
            Cmd::AdminOpenWindow {
                passcode: Some(12341234),
                ..
            }
        ));
        assert_eq!(g.passcode, Some(12341234));
        let (_, cmd) = parse_ok("admincommissioning revoke 7");
        assert!(matches!(cmd, Cmd::AdminRevoke { node: 7 }));
        assert!(parse_err("admincommissioning open-window 1 300 5000").contains("out of range"));
        assert!(parse_err("admincommissioning open-window 1").starts_with("usage:"));
        assert!(parse_err("admincommissioning bogus").starts_with("usage:"));
    }

    #[test]
    fn timed_flag_parses() {
        let (g, cmd) = parse_ok("--timed 10000 onoff toggle 1 1");
        assert_eq!(g.timed_ms, Some(10_000));
        assert!(matches!(cmd, Cmd::Invoke { .. }));
        assert!(parse_err("--timed x onoff toggle 1 1").contains("invalid --timed"));
    }

    #[test]
    fn at_flag_parses() {
        use std::net::IpAddr;
        // 単一 v4。
        let (g, _) = parse_ok("--at 100.64.0.1 discover commissionable");
        assert_eq!(g.at.as_deref(), Some(&["100.64.0.1".parse().unwrap()][..]));
        // 複数(v4 + v6 リテラル)、カンマ区切り。
        let (g, cmd) = parse_ok("discover operational 1 --at 100.64.0.1,fd7a::1,fe80::abcd");
        let want: Vec<IpAddr> = ["100.64.0.1", "fd7a::1", "fe80::abcd"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(g.at.as_deref(), Some(&want[..]));
        assert!(matches!(cmd, Cmd::DiscoverOperational { node: 1 }));
        // 不正な IP はエラー。
        assert!(parse_err("--at nope discover commissionable").contains("invalid --at ip"));
        // 値なしはエラー。
        assert!(parse_err("--at").contains("--at requires"));
    }

    #[test]
    fn help_paths() {
        assert!(matches!(parse_ok("").1, Cmd::Help));
        assert!(matches!(parse_ok("help").1, Cmd::Help));
        assert!(matches!(parse_ok("--help").1, Cmd::Help));
    }
}
