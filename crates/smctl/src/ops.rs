//! 高レベル操作(設計 doc §3): resolve → connect → execute の 3 段に正規化する。
//!
//! - `pairing`: mDNS ブラウズ or アドレス直指定 → [`Commissioner::commission`] を駆動 →
//!   CA 保存 + アドレス帳記帳。
//! - 運用コマンド: アドレス帳のキャッシュアドレスへまず CASE を試み、失敗したら
//!   operational mDNS で再解決 → 帳を更新([`with_case_session`])。
//!
//! 1 プロセス 1 コマンドの実行モデル(chip-tool と同じ)。

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use simple_matter::controller::ca::Ca;
use simple_matter::controller::{
    AttestationPolicy, Commissioner, ControllerCreds, Phase, CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::error::Result as MResult;
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::im::ImEvent;
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::tlv::{ContainerType, TlvElement, TlvReader, TlvTag, TlvValue, TlvWriter};
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};
use simple_matter::transport::session::SessionId;

use crate::cli::Globals;
use crate::clusters::{self, AttrDef, ClusterDef, CmdDef, ValueKind};
use crate::runner::udp::{
    drive_until_sc_event, open_dual_stack_udp, pump_commissioner, send_dir, settle, wait_im_event,
};
use crate::runner::{mdns, Backend, Ctrl};
use crate::state::{ca as ca_state, nodes, StateDir};
use crate::OsRng;

/// mDNS ブラウズの最低タイムアウト。デバイスの再 announce 間隔(既定 30 秒)より長く取る。
const BROWSE_TIMEOUT_MIN: Duration = Duration::from_secs(35);
/// operational mDNS 解決のタイムアウト。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(20);
/// キャッシュアドレスへの CASE 試行の窓(失敗したら mDNS 再解決へフォールバック)。
const CACHED_CASE_TIMEOUT: Duration = Duration::from_secs(5);
/// コマンド完了後に ACK を流し切るための静穏化の上限。
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// `pairing` の対象指定。
pub enum Target {
    /// mDNS ブラウズ(discriminator で絞り込み可)。
    Browse(Option<u16>),
    /// アドレス直指定。
    Addr(SocketAddr),
}

// ==========================================================================
// pairing
// ==========================================================================

/// コミッショニング(pairing onnetwork / onnetwork-long / address)。
///
/// 成功時に CA 状態(発行済み serial)を保存し、アドレス帳に記帳する。
pub fn pair(g: &Globals, node_id: u64, passcode: u32, target: Target) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let peer_addr = match target {
        Target::Addr(a) => {
            println!("[target] using explicit address {a}");
            a
        }
        Target::Browse(disc) => {
            println!("[discovery] browsing _matterc._udp.local via mDNS...");
            mdns::browse_commissionable(disc, g.timeout.max(BROWSE_TIMEOUT_MIN))?
        }
    };

    let crypto = RustCrypto::new(OsRng);
    let ca = {
        let _lock = state.lock()?;
        ca_state::load_or_create(&state.ca_path(), &crypto)?
    };
    println!(
        "[ca] fabric_id={:#018x} controller_node_id={:#018x}",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    let ctrl_creds = ControllerCreds::new(&ca, &crypto, 0);
    let sc_init = ScInitiator::new(&crypto, OsRng, ctrl_creds);
    let mut stack: Ctrl =
        simple_matter::controller::ControllerStack::new(&crypto, sc_init, ImClient::new());
    let mut comm = Commissioner::new(&ca, &crypto, AttestationPolicy::Skip);

    let socket = open_socket()?;
    let start = Instant::now();
    let deadline = start + g.timeout;
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];
    let mut last_phase = Phase::Idle;

    comm.commission(
        PeerAddr::Udp(peer_addr),
        passcode,
        node_id,
        start.elapsed().as_millis() as u64,
    )
    .map_err(|e| format!("commission() rejected: {e:?}"))?;
    println!("[commission] starting to {peer_addr} (device node_id={node_id:#x})");

    let case_session: SessionId = loop {
        if Instant::now() > deadline {
            return Err(format!("commissioning timed out in phase {last_phase:?}"));
        }
        let phase = pump_commissioner(
            &mut comm,
            &mut stack,
            &socket,
            start.elapsed().as_millis() as u64,
            &mut tx,
        );
        if phase != last_phase {
            report_phase(phase);
            last_phase = phase;
        }
        match phase {
            Phase::Done { session } => break session,
            Phase::Failed { stage, reason } => {
                return Err(format!("commissioning failed at stage {stage}: {reason:?}"));
            }
            _ => {}
        }
        // 発行したトランザクションの応答を受け切り、standalone ACK も含めて静穏化させて
        // から次フェーズへ進む(デバイスの IM responder は同時 1 トランザクションのため)。
        settle(&mut stack, &socket, &start, &mut rx, &mut tx, deadline)?;
    };
    println!(
        "[commission] COMPLETE. operational CASE session = {:#x}",
        case_session.as_raw()
    );
    let _ = settle(
        &mut stack,
        &socket,
        &start,
        &mut rx,
        &mut tx,
        Instant::now() + FLUSH_TIMEOUT,
    );

    // 発行済み serial を CA 状態に反映し、アドレス帳へ記帳する。
    {
        let _lock = state.lock()?;
        ca_state::save(&state.ca_path(), &ca)?;
        nodes::upsert(
            &state.nodes_path(),
            nodes::NodeEntry {
                node_id,
                label: g.label.clone().unwrap_or_default(),
                last_addr: peer_addr,
            },
        )?;
    }
    println!(
        "[pairing] node {node_id} recorded at {peer_addr} (state: {})",
        g.state_dir.display()
    );
    Ok(())
}

/// `pairing list`: アドレス帳の一覧表示。
pub fn pairing_list(g: &Globals) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let entries = {
        let _lock = state.lock()?;
        nodes::load(&state.nodes_path())?
    };
    if entries.is_empty() {
        println!("(no paired nodes; run `smctl pairing onnetwork <node-id> <passcode>`)");
        return Ok(());
    }
    println!("{:<12} {:<24} label", "node-id", "last-addr");
    for e in entries {
        println!(
            "{:<12} {:<24} {}",
            e.node_id,
            e.last_addr.to_string(),
            e.label
        );
    }
    Ok(())
}

// ==========================================================================
// 運用コマンド(CASE 接続 + execute)
// ==========================================================================

/// 保存済み CA + アドレス帳で対象ノードへ CASE を確立し、`f` を実行する。
///
/// キャッシュアドレスへの CASE が [`CACHED_CASE_TIMEOUT`] 内に確立しなければ、
/// operational mDNS で再解決して張り直し、成功したら帳のアドレスを更新する。
fn with_case_session<F>(g: &Globals, node_id: u64, f: F) -> Result<(), String>
where
    F: FnOnce(
        &mut Ctrl<'_>,
        &UdpSocket,
        &Instant,
        SessionId,
        &mut [u8],
        &mut [u8],
    ) -> Result<(), String>,
{
    let state = StateDir::open(&g.state_dir)?;
    let crypto = RustCrypto::new(OsRng);
    let (ca, entry) = {
        let _lock = state.lock()?;
        let ca = ca_state::load(&state.ca_path(), &crypto)?
            .ok_or("no CA state; commission a device first (`smctl pairing ...`)")?;
        let entries = nodes::load(&state.nodes_path())?;
        let entry = entries
            .into_iter()
            .find(|e| e.node_id == node_id)
            .ok_or_else(|| format!("node {node_id} not in address book (`smctl pairing list`)"))?;
        (ca, entry)
    };

    let socket = open_socket()?;
    let start = Instant::now();
    let mut tx = [0u8; MAX_RX_PACKET_SIZE];
    let mut rx = [0u8; MAX_RX_PACKET_SIZE];

    // 1) キャッシュアドレスへ CASE を試みる。
    let cached = entry.last_addr;
    let (mut stack, session, used_addr) = match try_case(
        &ca,
        &crypto,
        &socket,
        &start,
        cached,
        node_id,
        CACHED_CASE_TIMEOUT.min(g.timeout),
        &mut rx,
        &mut tx,
    ) {
        Ok((stack, session)) => (stack, session, cached),
        Err(e) => {
            // 2) mDNS で運用アドレスを再解決して張り直す。
            eprintln!("[case] cached address {cached} failed ({e}); re-resolving via mDNS");
            let resolved = mdns::resolve_operational(&ca, node_id, RESOLVE_TIMEOUT)?;
            eprintln!("[case] operational node resolved at {resolved}");
            let (stack, session) = try_case(
                &ca, &crypto, &socket, &start, resolved, node_id, g.timeout, &mut rx, &mut tx,
            )?;
            (stack, session, resolved)
        }
    };
    settle(
        &mut stack,
        &socket,
        &start,
        &mut rx,
        &mut tx,
        Instant::now() + g.timeout,
    )?;

    if used_addr != cached {
        let _lock = state.lock()?;
        nodes::update_addr(&state.nodes_path(), node_id, used_addr)?;
    }

    f(&mut stack, &socket, &start, session, &mut rx, &mut tx)
}

/// 1 回の CASE 試行。失敗・タイムアウトでスタックごと破棄する(再試行は作り直す)。
#[allow(clippy::too_many_arguments)]
fn try_case<'a>(
    ca: &'a Ca<Backend>,
    crypto: &'a Backend,
    socket: &UdpSocket,
    start: &Instant,
    addr: SocketAddr,
    node_id: u64,
    timeout: Duration,
    rx: &mut [u8],
    tx: &mut [u8],
) -> Result<(Ctrl<'a>, SessionId), String> {
    let ctrl_creds = ControllerCreds::new(ca, crypto, 0);
    let sc_init = ScInitiator::new(crypto, OsRng, ctrl_creds);
    let mut stack: Ctrl<'a> =
        simple_matter::controller::ControllerStack::new(crypto, sc_init, ImClient::new());
    let dir = stack
        .start_case(
            PeerAddr::Udp(addr),
            CONTROLLER_FABRIC_INDEX,
            node_id,
            start.elapsed().as_millis() as u64,
            tx,
        )
        .map_err(|e| format!("start_case: {e:?}"))?;
    send_dir(socket, tx, &dir);
    match drive_until_sc_event(&mut stack, socket, start, rx, tx, Instant::now() + timeout) {
        Some(ScEvent::CaseEstablished { session, resumed }) => {
            eprintln!(
                "[case] ESTABLISHED to {addr} (session={:#x}{})",
                session.as_raw(),
                if resumed { ", resumed" } else { "" }
            );
            Ok((stack, session))
        }
        Some(ev) => Err(format!("CASE failed: {ev:?}")),
        None => Err(format!("CASE to {addr} timed out after {timeout:?}")),
    }
}

/// 名前ベースの属性 Read。
pub fn read_attr(
    g: &Globals,
    node_id: u64,
    ep: u16,
    def: &ClusterDef,
    attr: &AttrDef,
) -> Result<(), String> {
    with_case_session(g, node_id, |stack, socket, start, session, rx, tx| {
        let path =
            AttributePath::concrete(simple_matter::dm::meta::EndpointId(ep), def.id, attr.id);
        let dir = stack
            .start_read(session, &[path], start.elapsed().as_millis() as u64, tx)
            .map_err(|e| format!("start_read: {e:?}"))?;
        send_dir(socket, tx, &dir);
        match wait_im_event(stack, socket, start, rx, tx, Instant::now() + g.timeout) {
            Some(ImEvent::ReadDone) => {}
            Some(ev) => return Err(format!("read failed: {ev:?}")),
            None => return Err("read timed out".into()),
        }
        print_reports(stack.read_reports(), "");
        flush(stack, socket, start, rx, tx);
        Ok(())
    })
}

/// 名前ベースの属性 Write。
pub fn write_attr(
    g: &Globals,
    node_id: u64,
    ep: u16,
    def: &ClusterDef,
    attr: &AttrDef,
    value: Parsed,
) -> Result<(), String> {
    with_case_session(g, node_id, |stack, socket, start, session, rx, tx| {
        let path =
            AttributePath::concrete(simple_matter::dm::meta::EndpointId(ep), def.id, attr.id);
        let kind = attr.kind;
        let dir = stack
            .start_write(
                session,
                &path,
                move |w, t| write_value(w, t, kind, &value),
                start.elapsed().as_millis() as u64,
                tx,
            )
            .map_err(|e| format!("start_write: {e:?}"))?;
        send_dir(socket, tx, &dir);
        match wait_im_event(stack, socket, start, rx, tx, Instant::now() + g.timeout) {
            Some(ImEvent::WriteDone { status }) if status.is_success() => {
                println!("[write] {}/{} OK", def.name, attr.name);
            }
            Some(ev) => return Err(format!("write failed: {ev:?}")),
            None => return Err("write timed out".into()),
        }
        flush(stack, socket, start, rx, tx);
        Ok(())
    })
}

/// 名前ベースのコマンド Invoke(フィールドは `(tag, kind, value)` のリスト)。
pub fn invoke_cmd(
    g: &Globals,
    node_id: u64,
    ep: u16,
    def: &ClusterDef,
    cmd: &CmdDef,
    fields: Vec<(u8, ValueKind, Parsed)>,
) -> Result<(), String> {
    with_case_session(g, node_id, |stack, socket, start, session, rx, tx| {
        let path = CommandPath::new(simple_matter::dm::meta::EndpointId(ep), def.id, cmd.id);
        let dir = stack
            .start_invoke(
                session,
                path,
                move |w, t| {
                    w.start_struct(t)?;
                    for (tag, kind, v) in &fields {
                        write_value(w, &TlvTag::ContextSpecific(*tag), *kind, v)?;
                    }
                    w.end_container()
                },
                start.elapsed().as_millis() as u64,
                tx,
            )
            .map_err(|e| format!("start_invoke: {e:?}"))?;
        send_dir(socket, tx, &dir);
        match wait_im_event(stack, socket, start, rx, tx, Instant::now() + g.timeout) {
            Some(ImEvent::InvokeDone { status }) if status.is_success() => {
                println!("[invoke] {} {} OK (status = Success)", def.name, cmd.name);
            }
            Some(ev) => return Err(format!("invoke failed: {ev:?}")),
            None => return Err("invoke timed out".into()),
        }
        flush(stack, socket, start, rx, tx);
        Ok(())
    })
}

/// 属性 Subscribe(常駐モード、controller.md §4.5.5 の CLI 推奨パターン)。
///
/// プライミング完了(SubscribeDone)後、デバイス発レポートを受信するたびに表示し続ける。
/// SubscriptionLost(keep-alive 途絶)で非 0 終了。Ctrl-C で停止するまで動き続ける。
pub fn subscribe_attr(
    g: &Globals,
    node_id: u64,
    ep: u16,
    def: &ClusterDef,
    attr: &AttrDef,
    min_s: u16,
    max_s: u16,
) -> Result<(), String> {
    with_case_session(g, node_id, |stack, socket, start, session, rx, tx| {
        let path =
            AttributePath::concrete(simple_matter::dm::meta::EndpointId(ep), def.id, attr.id);
        let dir = stack
            .start_subscribe(
                session,
                &[path],
                min_s,
                max_s,
                start.elapsed().as_millis() as u64,
                tx,
            )
            .map_err(|e| format!("start_subscribe: {e:?}"))?;
        send_dir(socket, tx, &dir);
        println!("[subscribe] SubscribeRequest sent (min={min_s}s max={max_s}s)");

        let (sub_id, neg_max) =
            match wait_im_event(stack, socket, start, rx, tx, Instant::now() + g.timeout) {
                Some(ImEvent::SubscribeDone {
                    subscription_id,
                    max_interval_s,
                }) => (subscription_id, max_interval_s),
                Some(ev) => return Err(format!("subscribe failed: {ev:?}")),
                None => return Err("subscribe timed out (no SubscribeResponse)".into()),
            };
        println!(
            "[subscribe] ESTABLISHED: subscription_id={sub_id} max_interval={neg_max}s \
             (Ctrl-C to stop)"
        );

        // レポートを受信し続ける(keep-alive 途絶 = SubscriptionLost で非 0 終了)。
        loop {
            match wait_im_event(
                stack,
                socket,
                start,
                rx,
                tx,
                Instant::now() + Duration::from_secs(3600),
            ) {
                Some(ImEvent::SubscriptionReport { subscription_id }) => {
                    let ts = start.elapsed().as_secs();
                    print_reports(
                        stack.sub_reports(),
                        &format!("[report +{ts}s sub={subscription_id}] "),
                    );
                }
                Some(ImEvent::SubscriptionLost { subscription_id }) => {
                    return Err(format!(
                        "subscription {subscription_id} LOST (no report within max interval + grace)"
                    ));
                }
                Some(ev) => return Err(format!("unexpected IM event: {ev:?}")),
                None => {} // 1 時間の枠を延長して待ち続ける
            }
        }
    })
}

/// コマンド完了後の ACK 流し切り(best effort)。
fn flush(stack: &mut Ctrl<'_>, socket: &UdpSocket, start: &Instant, rx: &mut [u8], tx: &mut [u8]) {
    let _ = settle(stack, socket, start, rx, tx, Instant::now() + FLUSH_TIMEOUT);
}

fn open_socket() -> Result<UdpSocket, String> {
    let socket = open_dual_stack_udp().map_err(|e| format!("bind controller socket: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    Ok(socket)
}

/// フェーズ遷移を人間可読に表示する。
fn report_phase(phase: Phase) {
    let name = match phase {
        Phase::Idle => "Idle",
        Phase::Pase => "PASE handshake",
        Phase::ArmFailSafe => "ArmFailSafe",
        Phase::Attestation => "Attestation (skipped)",
        Phase::Csr => "CSRRequest",
        Phase::AddTrustedRoot => "AddTrustedRootCertificate",
        Phase::AddNoc => "AddNOC",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    println!("[phase] {name}");
}

// ==========================================================================
// 値リテラル(入力)と TLV(出力)の変換
// ==========================================================================

/// パース済みの値リテラル。
#[derive(Debug, Clone)]
pub enum Parsed {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
}

/// 文字列リテラルを [`ValueKind`] に従ってパースする(設計 doc §5.2)。
pub fn parse_literal(kind: ValueKind, s: &str) -> Result<Parsed, String> {
    if s == "null" {
        return Ok(Parsed::Null);
    }
    let err = |what: &str| format!("invalid {what} literal: {s:?}");
    match kind {
        ValueKind::Bool => match s {
            "true" | "1" | "on" => Ok(Parsed::Bool(true)),
            "false" | "0" | "off" => Ok(Parsed::Bool(false)),
            _ => Err(err("bool")),
        },
        ValueKind::U8 | ValueKind::U16 | ValueKind::U32 | ValueKind::U64 => {
            let v = parse_u64(s).map_err(|_| err("unsigned"))?;
            let max = match kind {
                ValueKind::U8 => u8::MAX as u64,
                ValueKind::U16 => u16::MAX as u64,
                ValueKind::U32 => u32::MAX as u64,
                _ => u64::MAX,
            };
            if v > max {
                return Err(format!("value {v} out of range for {}", kind.name()));
            }
            Ok(Parsed::Unsigned(v))
        }
        ValueKind::I8 | ValueKind::I16 | ValueKind::I32 | ValueKind::I64 => {
            let v: i64 = s.parse().map_err(|_| err("signed"))?;
            Ok(Parsed::Signed(v))
        }
        ValueKind::F32 | ValueKind::F64 => {
            let v: f64 = s.parse().map_err(|_| err("float"))?;
            Ok(Parsed::Float(v))
        }
        ValueKind::Utf8 => Ok(Parsed::Str(s.to_string())),
        ValueKind::Bytes => {
            let hex = s.strip_prefix("hex:").unwrap_or(s);
            Ok(Parsed::Bytes(parse_hex(hex).map_err(|_| err("hex"))?))
        }
        ValueKind::Raw => Err("raw-typed values cannot be entered by name; \
             use `any` (planned for C2) with hex TLV"
            .into()),
    }
}

/// `0x` 前置の 16 進または 10 進の u64。
pub fn parse_u64(s: &str) -> Result<u64, String> {
    let r = if let Some(hexpart) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hexpart, 16)
    } else {
        s.parse()
    };
    r.map_err(|_| format!("invalid number: {s:?}"))
}

fn parse_hex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// パース済みリテラルを `kind` のワイヤ幅で TLV に書く。
fn write_value(w: &mut TlvWriter, tag: &TlvTag, kind: ValueKind, v: &Parsed) -> MResult<()> {
    match (kind, v) {
        (_, Parsed::Null) => w.write_null(tag),
        (ValueKind::Bool, Parsed::Bool(b)) => w.write_bool(tag, *b),
        (ValueKind::U8, Parsed::Unsigned(x)) => w.write_u8(tag, *x as u8),
        (ValueKind::U16, Parsed::Unsigned(x)) => w.write_u16(tag, *x as u16),
        (ValueKind::U32, Parsed::Unsigned(x)) => w.write_u32(tag, *x as u32),
        (ValueKind::U64, Parsed::Unsigned(x)) => w.write_u64(tag, *x),
        (ValueKind::I8, Parsed::Signed(x)) => w.write_i8(tag, *x as i8),
        (ValueKind::I16, Parsed::Signed(x)) => w.write_i16(tag, *x as i16),
        (ValueKind::I32, Parsed::Signed(x)) => w.write_i32(tag, *x as i32),
        (ValueKind::I64, Parsed::Signed(x)) => w.write_i64(tag, *x),
        (ValueKind::F32, Parsed::Float(x)) => w.write_f32(tag, *x as f32),
        (ValueKind::F64, Parsed::Float(x)) => w.write_f64(tag, *x),
        (ValueKind::Utf8, Parsed::Str(s)) => w.write_utf8(tag, s),
        (ValueKind::Bytes, Parsed::Bytes(b)) => w.write_bytes(tag, b),
        _ => Err(simple_matter::Error::InvalidState),
    }
}

// ==========================================================================
// レポート表示(名前テーブルは可読性を足すだけ。無くても生 TLV ダンプで常に成立)
// ==========================================================================

/// 属性レポート列を 1 行ずつ表示する。
fn print_reports<'a, I>(reports: I, prefix: &str)
where
    I: Iterator<Item = MResult<AttributeReportRef<'a>>>,
{
    let mut n = 0;
    for report in reports {
        n += 1;
        match report {
            Ok(AttributeReportRef::Data(d)) => {
                let path = format_path(&d.path);
                let mut r = d.value();
                let value = fmt_next_value(&mut r).unwrap_or_else(|| "<empty>".into());
                println!("{prefix}{path} = {value}");
            }
            Ok(AttributeReportRef::Status(s)) => {
                let path = format_path(&s.path);
                println!("{prefix}{path}: status {:?}", s.status);
            }
            Err(e) => println!("{prefix}<undecodable report: {e:?}>"),
        }
    }
    if n == 0 {
        println!("{prefix}(no attribute reports)");
    }
}

/// 属性パスを `cluster/attr (0xNNNN/0xNNNN) ep=N` 形式で表示する(名前はテーブルから)。
fn format_path(path: &AttributePath) -> String {
    let ep = path
        .endpoint
        .map(|e| e.0.to_string())
        .unwrap_or_else(|| "*".into());
    let (cname, aname) = match path.cluster {
        Some(cid) => match clusters::by_id(cid) {
            Some(def) => {
                let aname = path
                    .attribute
                    .and_then(|a| def.attr_by_id(a))
                    .map(|a| a.name.to_string());
                (Some(def.name.to_string()), aname)
            }
            None => (None, None),
        },
        None => (None, None),
    };
    let cid = path
        .cluster
        .map(|c| format!("{:#06x}", c.0))
        .unwrap_or_else(|| "*".into());
    let aid = path
        .attribute
        .map(|a| format!("{:#06x}", a.0))
        .unwrap_or_else(|| "*".into());
    match (cname, aname) {
        (Some(c), Some(a)) => format!("ep{ep} {c}/{a} ({cid}/{aid})"),
        (Some(c), None) => format!("ep{ep} {c}/{aid}"),
        _ => format!("ep{ep} {cid}/{aid}"),
    }
}

/// TLV の次の 1 要素を人間可読に整形する(コンテナは再帰ダンプ)。
fn fmt_next_value(r: &mut TlvReader) -> Option<String> {
    let e = r.read_next().ok()??;
    Some(fmt_element(r, &e))
}

fn fmt_element(r: &mut TlvReader, e: &TlvElement) -> String {
    match e.value {
        TlvValue::Boolean(b) => b.to_string(),
        TlvValue::UnsignedInteger(v) => v.to_string(),
        TlvValue::SignedInteger(v) => v.to_string(),
        TlvValue::Float(v) => v.to_string(),
        TlvValue::Double(v) => v.to_string(),
        TlvValue::Utf8String(s) => format!("{s:?}"),
        TlvValue::ByteString(b) => {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            format!("hex:{hex}")
        }
        TlvValue::Null => "null".into(),
        TlvValue::ContainerStart(t) => {
            let (open, close) = match t {
                ContainerType::Structure => ("{", "}"),
                ContainerType::Array => ("[", "]"),
                ContainerType::List => ("[[", "]]"),
            };
            let mut parts = Vec::new();
            loop {
                match r.read_next() {
                    Ok(Some(c)) if matches!(c.value, TlvValue::ContainerEnd) => break,
                    Ok(Some(c)) => {
                        let body = fmt_element(r, &c);
                        parts.push(match c.tag {
                            TlvTag::ContextSpecific(n) => format!("{n}: {body}"),
                            _ => body,
                        });
                    }
                    _ => break,
                }
            }
            format!("{open}{}{close}", parts.join(", "))
        }
        TlvValue::ContainerEnd => String::new(),
    }
}
