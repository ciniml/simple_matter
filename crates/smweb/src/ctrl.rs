//! コントローラスレッド(設計 doc §4)。
//!
//! `ControllerStack`(sans-IO・単一所有者)を専有する同期スレッド 1 本。駆動は
//! [`smctl::ops::Exec`](UDP recv 50ms → handle_rx → poll → 送信、CASE キャッシュ、
//! resumption、静穏化)をそのまま使う。HTTP 側とは次で橋渡しする(§2):
//!
//! - `std::sync::mpsc::sync_channel`(容量 [`QUEUE_CAP`]): [`Command`] の直列化。満杯は `busy`。
//! - `tokio::sync::oneshot`: 1 Command への Reply。
//! - `tokio::sync::broadcast`: [`Event`](WebSocket へ)。
//! - `Arc<RwLock<Snapshot>>`: REST が待たずに読む最新状態。

use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{json, Value};
use smctl::cli::Globals;
use smctl::clusters::{self, ValueKind};
use smctl::log::Level;
use smctl::ops::embed::ReadOutcome;
use smctl::ops::{Exec, Parsed};
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId, CommandId};
use smctl::state::{ca as ca_state, nodes, StateDir};
use smctl::OsRng;
use tokio::sync::{broadcast, oneshot};

use crate::error::{ApiError, ErrorCode};
use crate::model::{unix_now, Event, Info, NodeSnap, NodeState, Snapshot};
use crate::value::{raw_json, to_hex, value_json};

/// コマンドキューの容量(§6「キューが N(既定 32)を超えたら busy」)。
pub const QUEUE_CAP: usize = 32;
/// broadcast チャネルの容量(遅い WS クライアントは `lagged` になる)。
const EVENT_CAP: usize = 256;
/// Exec の操作タイムアウトに上乗せする HTTP 側の待ち時間。CASE 取得は
/// キャッシュアドレス試行(5 s)+ mDNS 再解決(6 s + 20 s)を操作タイムアウトの
/// 外で行い得るため、その分の余裕を取る。
const REPLY_MARGIN: Duration = Duration::from_secs(35);

/// コントローラへの要求(§4.2 の W1 部分集合)。
///
/// `GET /api/info` / `GET /api/nodes` はスナップショットを読むだけなので Command に
/// しない(§2「REST はそれを読むだけ」)。
#[derive(Debug)]
pub enum Command {
    /// 運用 mDNS 解決 + CASE(resumption 優先)。
    Connect { node_id: u64 },
    /// 属性 Read(1 属性)。
    Read {
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        /// 型付き値に加えて生 TLV も返す。
        raw: bool,
    },
    /// コマンド Invoke。`tlv` があればフィールド全体を生 TLV で、無ければ `fields`。
    Invoke {
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        cmd: CommandId,
        fields: Vec<(u8, ValueKind, Parsed)>,
        tlv: Option<Vec<u8>>,
        timed_ms: Option<u16>,
    },
    /// 属性 Write(W1 は未実装: `not_implemented`)。
    Write {
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        #[allow(dead_code)]
        value: Value,
    },
}

/// Command への応答。
pub type Reply = Result<Value, ApiError>;

struct Request {
    cmd: Command,
    reply: oneshot::Sender<Reply>,
}

/// HTTP 側が持つハンドル(clone して各ハンドラへ)。
#[derive(Clone)]
pub struct CtrlHandle {
    tx: SyncSender<Request>,
    pub events: broadcast::Sender<Event>,
    pub snapshot: Arc<RwLock<Snapshot>>,
    wait: Duration,
}

impl CtrlHandle {
    /// Command を投入して Reply を待つ(tokio 側はブロックしない)。
    pub async fn call(&self, cmd: Command) -> Reply {
        let (rtx, rrx) = oneshot::channel();
        match self.tx.try_send(Request { cmd, reply: rtx }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(ApiError::new(
                    ErrorCode::Busy,
                    format!("controller queue full ({QUEUE_CAP} pending)"),
                ))
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "controller thread is not running",
                ))
            }
        }
        match tokio::time::timeout(self.wait, rrx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(ApiError::new(
                ErrorCode::Internal,
                "controller dropped the request",
            )),
            Err(_) => Err(ApiError::new(
                ErrorCode::Timeout,
                "no reply from controller within the timeout",
            )),
        }
    }

    /// スナップショットの読み取り(毒化しても中身は使う)。
    pub fn snapshot(&self) -> Snapshot {
        match self.snapshot.read() {
            Ok(s) => s.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

/// スレッド間で共有する書き込み側。
#[derive(Clone)]
struct Shared {
    events: broadcast::Sender<Event>,
    snapshot: Arc<RwLock<Snapshot>>,
}

impl Shared {
    fn with<R>(&self, f: impl FnOnce(&mut Snapshot) -> R) -> R {
        let mut g = match self.snapshot.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut g)
    }

    /// ノード状態を更新し、変化(または明示要求)があれば `NodeState` を流す。
    fn set_state(&self, node_id: u64, state: NodeState, addr: Option<String>, force: bool) {
        let changed = self.with(|s| {
            let n = s.node_mut(node_id)?;
            let mut changed = n.state != state;
            if addr.is_some() && n.addr != addr {
                n.addr = addr.clone();
                changed = true;
            }
            n.state = state;
            if state == NodeState::Online {
                n.last_seen = Some(unix_now());
            }
            (changed || force).then(|| n.addr.clone())
        });
        if let Some(addr) = changed {
            let _ = self.events.send(Event::NodeState {
                node_id,
                state,
                addr,
            });
        }
    }
}

/// `last_addr` の表示形(未解決 sentinel は `None`)。
fn addr_string(a: std::net::SocketAddr) -> Option<String> {
    (a.port() != 0).then(|| a.to_string())
}

/// コントローラスレッドを起動し、ハンドルを返す。
///
/// `g` は smctl と同じ共通オプション(state_dir / timeout / attestation 関連)。
pub fn spawn(g: Globals) -> CtrlHandle {
    let (tx, rx) = mpsc::sync_channel::<Request>(QUEUE_CAP);
    let (events, _) = broadcast::channel(EVENT_CAP);
    let snapshot = Arc::new(RwLock::new(Snapshot {
        info: Info {
            version: env!("CARGO_PKG_VERSION"),
            state_dir: g.state_dir.display().to_string(),
            features: features(),
            ..Info::default()
        },
        nodes: Vec::new(),
    }));
    let shared = Shared {
        events: events.clone(),
        snapshot: snapshot.clone(),
    };
    let wait = g.timeout + REPLY_MARGIN;
    std::thread::Builder::new()
        .name("smweb-ctrl".into())
        .spawn(move || thread_main(g, rx, shared))
        .expect("spawn controller thread");
    CtrlHandle {
        tx,
        events,
        snapshot,
        wait,
    }
}

fn features() -> Vec<&'static str> {
    if cfg!(feature = "ble") {
        vec!["ble"]
    } else {
        Vec::new()
    }
}

/// コントローラスレッド本体。
fn thread_main(g: Globals, rx: Receiver<Request>, shared: Shared) {
    let fail = |msg: String| {
        wlog!(Level::Error, "controller unavailable: {msg}");
        shared.with(|s| s.info.error = Some(msg.clone()));
        serve_unavailable(&rx, &msg);
    };
    let state = match StateDir::open(&g.state_dir) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    // 1) アドレス帳 → スナップショット(全ノード Offline で開始、§4.3)。
    let entries = match state.lock().and_then(|_l| nodes::load(&state.nodes_path())) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    shared.with(|s| {
        s.nodes = entries
            .iter()
            .map(|e| NodeSnap {
                node_id: e.node_id,
                label: e.label.clone(),
                addr: addr_string(e.last_addr),
                state: NodeState::Offline,
                last_seen: None,
            })
            .collect();
    });
    wlog!(
        Level::Info,
        "loaded {} node(s) from {}",
        entries.len(),
        state.nodes_path().display()
    );

    // 2) CA(fabric)。W1 は pairing を持たないので、無ければ操作を受け付けない。
    let crypto = smctl::simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let ca = match state
        .lock()
        .and_then(|_l| ca_state::load(&state.ca_path(), &crypto))
    {
        Ok(Some(ca)) => ca,
        Ok(None) => {
            return fail(
                "no CA state in the state directory; commission a device first \
                 (`smctl pairing ...`)"
                    .into(),
            )
        }
        Err(e) => return fail(e),
    };
    shared.with(|s| {
        s.info.fabric_id = Some(format!("{:#018x}", ca.fabric_id()));
        s.info.controller_node_id = Some(format!("{:#018x}", ca.controller_node_id()));
    });

    // 3) 駆動コンテキスト(ソケット + ControllerStack)。
    let mut exec = match Exec::new(g, state, &crypto, &ca, true) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    shared.with(|s| s.info.ready = true);
    wlog!(
        Level::Info,
        "controller ready (fabric {:#x}, controller node {:#x})",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    // 4) ループ: Command があれば 1 件処理、無ければ IO 1 反復(最長 50ms)。
    loop {
        match rx.try_recv() {
            Ok(req) => {
                let reply = handle(&mut exec, &shared, req.cmd);
                let _ = req.reply.send(reply);
            }
            Err(TryRecvError::Empty) => {
                if let Err(e) = exec.idle() {
                    wlog!(Level::Warn, "io: {e}");
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Err(TryRecvError::Disconnected) => break,
        }
    }
}

/// 起動に失敗したとき: 全 Command にエラーを返し続ける。
fn serve_unavailable(rx: &Receiver<Request>, msg: &str) {
    while let Ok(req) = rx.recv() {
        let _ = req.reply.send(Err(ApiError::new(ErrorCode::Internal, msg)));
    }
}

/// 1 Command の処理。
fn handle(exec: &mut Exec<'_>, shared: &Shared, cmd: Command) -> Reply {
    let node_id = match &cmd {
        Command::Connect { node_id }
        | Command::Read { node_id, .. }
        | Command::Invoke { node_id, .. }
        | Command::Write { node_id, .. } => *node_id,
    };
    if shared.with(|s| s.node(node_id).is_none()) {
        return Err(ApiError::not_found(format!(
            "node {node_id:#x} is not in the address book"
        )));
    }
    let r = match cmd {
        Command::Connect { node_id } => connect(exec, shared, node_id),
        Command::Read {
            node_id,
            ep,
            cluster,
            attr,
            raw,
        } => read(exec, node_id, ep, cluster, attr, raw),
        Command::Invoke {
            node_id,
            ep,
            cluster,
            cmd,
            fields,
            tlv,
            timed_ms,
        } => invoke(exec, node_id, ep, cluster, cmd, fields, tlv, timed_ms),
        Command::Write {
            ep, cluster, attr, ..
        } => {
            return Err(ApiError::new(
                ErrorCode::NotImplemented,
                format!(
                "attribute write is not implemented yet (ep {ep}, cluster {:#06x}, attr {:#06x})",
                cluster.0, attr.0
            ),
            ))
        }
    };
    // 成功した操作は到達性の証拠(Online)、タイムアウトは Offline(§4.3)。
    match &r {
        Ok(_) => {
            let addr = current_addr(exec, node_id);
            shared.set_state(node_id, NodeState::Online, addr, false);
        }
        Err(e) if e.code == ErrorCode::ImStatus => {
            // デバイスは応答している。
            shared.set_state(node_id, NodeState::Online, None, false);
        }
        Err(e) if matches!(e.code, ErrorCode::Timeout | ErrorCode::Internal) => {
            wlog!(Level::Warn, "node {node_id:#x}: {}", e.message);
            shared.set_state(node_id, NodeState::Offline, None, false);
        }
        Err(_) => {}
    }
    r
}

/// アドレス帳から現在の運用アドレスを読む(CASE 成立時に Exec が更新している)。
fn current_addr(exec: &Exec<'_>, node_id: u64) -> Option<String> {
    let st = exec.state_dir();
    let _l = st.lock().ok()?;
    nodes::load(&st.nodes_path())
        .ok()?
        .into_iter()
        .find(|e| e.node_id == node_id)
        .and_then(|e| addr_string(e.last_addr))
}

fn connect(exec: &mut Exec<'_>, shared: &Shared, node_id: u64) -> Reply {
    let cached = exec.is_connected(node_id);
    if !cached {
        wlog!(Level::Info, "connecting to node {node_id:#x}...");
    }
    exec.connect(node_id).map_err(ApiError::from_exec)?;
    let addr = current_addr(exec, node_id);
    // 手動 connect は結果を明示的に通知する(状態が変わらなくても)。
    shared.set_state(node_id, NodeState::Online, addr.clone(), true);
    Ok(json!({
        "node_id": node_id,
        "state": NodeState::Online,
        "addr": addr,
        "cached_session": cached,
    }))
}

fn read(
    exec: &mut Exec<'_>,
    node_id: u64,
    ep: u16,
    cluster: ClusterId,
    attr: AttributeId,
    raw: bool,
) -> Reply {
    let items = exec
        .read_data(node_id, ep, cluster, Some(attr))
        .map_err(ApiError::from_exec)?;
    let item = items
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::new(ErrorCode::Internal, "no attribute report in response"))?;
    let cdef = clusters::by_id(cluster);
    let adef = cdef.and_then(|c| c.attr_by_id(attr));
    let mut out = json!({
        "node_id": node_id,
        "endpoint": ep,
        "cluster": cluster.0,
        "cluster_name": cdef.map(|c| c.name),
        "attribute": attr.0,
        "attribute_name": adef.map(|a| a.name),
        "kind": adef.map(|a| a.kind.name()),
    });
    match item.outcome {
        ReadOutcome::Data(bytes) => {
            out["value"] = value_json(adef.map(|a| a.kind), &bytes);
            out["data_version"] = json!(item.data_version);
            if raw {
                out["raw"] = raw_json(&bytes);
            }
            Ok(out)
        }
        ReadOutcome::Status {
            status,
            cluster_status,
        } => Err(ApiError::im_status(
            status.to_u8(),
            match cluster_status {
                Some(cs) => format!("read failed: {status:?} (cluster status {cs:#04x})"),
                None => format!("read failed: {status:?}"),
            },
        )),
        ReadOutcome::Undecodable(e) => Err(ApiError::new(
            ErrorCode::Internal,
            format!("undecodable report: {e}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn invoke(
    exec: &mut Exec<'_>,
    node_id: u64,
    ep: u16,
    cluster: ClusterId,
    cmd: CommandId,
    fields: Vec<(u8, ValueKind, Parsed)>,
    tlv: Option<Vec<u8>>,
    timed_ms: Option<u16>,
) -> Reply {
    let out = exec
        .invoke_data(node_id, ep, cluster, cmd, fields, tlv, timed_ms)
        .map_err(ApiError::from_exec)?;
    let cdef = clusters::by_id(cluster);
    let mdef = cdef.and_then(|c| c.cmds.iter().find(|m| m.id == cmd));
    if !out.status.is_success() {
        let mut msg = format!("invoke failed: {:?}", out.status);
        if let Some(cs) = out.cluster_status {
            msg.push_str(&format!(" (cluster status {cs:#04x})"));
        }
        return Err(ApiError::im_status(out.status.to_u8(), msg));
    }
    Ok(json!({
        "node_id": node_id,
        "endpoint": ep,
        "cluster": cluster.0,
        "cluster_name": cdef.map(|c| c.name),
        "command": cmd.0,
        "command_name": mdef.map(|m| m.name),
        "status": format!("{:?}", out.status),
        "status_code": out.status.to_u8(),
        "cluster_status": out.cluster_status,
        "response": if out.response.is_empty() {
            Value::Null
        } else {
            json!({
                "raw": to_hex(&out.response),
                "pretty": smctl::tlvfmt::pretty(&out.response).join("\n"),
            })
        },
    }))
}
