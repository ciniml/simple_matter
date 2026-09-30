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
//!
//! W2: 接続 = CASE → Describe(§5.1)→ 既定購読 + watch(§5.2、ノード 1 本)。購読レポートは
//! [`Exec::enable_sub_capture`] でデータとして回収し、値キャッシュ更新 + `Event::Attr`。
//! `SubscriptionLost` は `stale` にして再接続をバックオフ付きで予約する。自動(再)接続は
//! 先に別スレッドで運用 mDNS 解決(probe)してから CASE に進む — 生きていないノードの
//! mDNS 待ち(最大 ~26 s、その間 UDP を回せない)でコントローラを塞がないため。

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use smctl::cli::Globals;
use smctl::clusters::{self, ValueKind};
use smctl::log::Level;
use smctl::ops::embed::{ReadItem, ReadOutcome, SubEvent};
use smctl::ops::{Exec, Parsed};
use smctl::runner::mdns;
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use smctl::simple_matter::im::wire::AttributePath;
use smctl::simple_matter::transport::session::SessionId;
use smctl::state::{ca as ca_state, nodes, StateDir};
use smctl::OsRng;
use tokio::sync::{broadcast, oneshot};

use crate::describe::{self, backoff};
use crate::error::{ApiError, ErrorCode};
use crate::model::{
    unix_now, unix_now_ms, AttrPath, AttrValue, Event, Info, NodeKind, NodeSnap, NodeState,
    Snapshot,
};
use crate::store::Store;
use crate::value::{raw_json, to_hex, value_json};

/// コマンドキューの容量(§6「キューが N(既定 32)を超えたら busy」)。
pub const QUEUE_CAP: usize = 32;
/// broadcast チャネルの容量(遅い WS クライアントは `lagged` になる)。
const EVENT_CAP: usize = 1024;
/// Exec の操作タイムアウトに上乗せする HTTP 側の待ち時間。CASE 取得は
/// キャッシュアドレス試行(5 s)+ mDNS 再解決(6 s + 20 s)を操作タイムアウトの
/// 外で行い得るため、その分の余裕を取る。Connect は Describe(数回の Read)と
/// Subscribe も含むのでさらに長い。
const REPLY_MARGIN: Duration = Duration::from_secs(35);
/// Connect / Describe の HTTP 側待ち時間の上乗せ。
const CONNECT_MARGIN: Duration = Duration::from_secs(60);
/// 既定購読の min / max interval(§5.2)。
const SUB_MIN_S: u16 = 0;
const SUB_MAX_S: u16 = 60;
/// 1 Read あたりのパス数(デバイス側のパス上限に余裕を持たせる)。
const READ_CHUNK: usize = 6;
/// probe(運用 mDNS 解決)の窓。キャッシュホストへの QU 直叩き → マルチキャスト。
const PROBE_AT_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// コントローラへの要求(§4.2 の W2 部分集合)。
///
/// `GET /api/info` / `GET /api/nodes` はスナップショットを読むだけなので Command に
/// しない(§2「REST はそれを読むだけ」)。
#[derive(Debug)]
pub enum Command {
    /// 運用 mDNS 解決 + CASE(resumption 優先)+ Describe(未取得なら)+ 既定購読。
    Connect { node_id: u64 },
    /// Describe をやり直して購読を張り直す。
    Describe { node_id: u64 },
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
    /// 属性 Write(未実装: `not_implemented`)。
    Write {
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        #[allow(dead_code)]
        value: Value,
    },
    /// watch パスの追加 / 削除(`smweb.json` に保存し、接続中なら購読を張り直す)。
    Watch {
        node_id: u64,
        paths: Vec<AttrPath>,
        add: bool,
    },
}

impl Command {
    fn node_id(&self) -> u64 {
        match self {
            Command::Connect { node_id }
            | Command::Describe { node_id }
            | Command::Read { node_id, .. }
            | Command::Invoke { node_id, .. }
            | Command::Write { node_id, .. }
            | Command::Watch { node_id, .. } => *node_id,
        }
    }

    fn is_long(&self) -> bool {
        matches!(
            self,
            Command::Connect { .. } | Command::Describe { .. } | Command::Watch { .. }
        )
    }
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
        let wait = if cmd.is_long() {
            self.wait + CONNECT_MARGIN
        } else {
            self.wait
        };
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
        match tokio::time::timeout(wait, rrx).await {
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

/// コントローラスレッドの停止用ハンドル(main が保持)。
pub struct CtrlThread {
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl CtrlThread {
    /// 停止を要求し、最大 `wait` だけ終了を待つ。戻り値 = 終了したか。
    ///
    /// 状態ファイルのロックは読み書き区間(ms 単位)だけなので、ネットワーク待ちの
    /// 途中で打ち切ってもロックは残らない。
    pub fn shutdown(self, wait: Duration) -> bool {
        self.stop.store(true, Ordering::SeqCst);
        let until = Instant::now() + wait;
        while !self.join.is_finished() {
            if Instant::now() > until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.join.join();
        true
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

    fn with_node<R>(&self, node_id: u64, f: impl FnOnce(&mut NodeSnap) -> R) -> Option<R> {
        self.with(|s| s.node_mut(node_id).map(f))
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    /// 現在のノード状態を `NodeState` として流す。
    fn emit_state(&self, node_id: u64) {
        let ev = self.with(|s| {
            s.node(node_id).map(|n| Event::NodeState {
                node_id,
                state: n.state,
                addr: n.addr.clone(),
                error: n.error.clone(),
                next_retry: n.next_retry,
            })
        });
        if let Some(e) = ev {
            self.emit(e);
        }
    }

    /// ノード状態を更新し、変化(または明示要求)があれば `NodeState` を流す。
    fn set_state(&self, node_id: u64, state: NodeState, addr: Option<String>, force: bool) {
        let changed = self
            .with_node(node_id, |n| {
                let mut changed = n.state != state;
                if addr.is_some() && n.addr != addr {
                    n.addr = addr.clone();
                    changed = true;
                }
                n.state = state;
                if state == NodeState::Online {
                    n.last_seen = Some(unix_now());
                    n.error = None;
                    n.next_retry = None;
                }
                changed || force
            })
            .unwrap_or(false);
        if changed {
            self.emit_state(node_id);
        }
    }
}

/// `last_addr` の表示形(未解決 sentinel は `None`)。
fn addr_string(a: SocketAddr) -> Option<String> {
    (a.port() != 0).then(|| a.to_string())
}

/// コントローラスレッドを起動し、ハンドルを返す。
///
/// `g` は smctl と同じ共通オプション(state_dir / timeout / attestation 関連)。
pub fn spawn(g: Globals) -> (CtrlHandle, CtrlThread) {
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
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let join = std::thread::Builder::new()
        .name("smweb-ctrl".into())
        .spawn(move || thread_main(g, rx, shared, stop2))
        .expect("spawn controller thread");
    (
        CtrlHandle {
            tx,
            events,
            snapshot,
            wait,
        },
        CtrlThread { stop, join },
    )
}

fn features() -> Vec<&'static str> {
    if cfg!(feature = "ble") {
        vec!["ble"]
    } else {
        Vec::new()
    }
}

/// `smweb.json` を読む。壊れていれば `.bad` へ退避して空から始める。
fn load_store(path: &Path) -> Store {
    match Store::load(path) {
        Ok(s) => s,
        Err(e) => {
            let bad = path.with_extension("json.bad");
            wlog!(
                Level::Warn,
                "{e}; moving it to {} and starting empty",
                bad.display()
            );
            let _ = std::fs::rename(path, &bad);
            Store::default()
        }
    }
}

/// コントローラスレッド本体。
fn thread_main(g: Globals, rx: Receiver<Request>, shared: Shared, stop: Arc<AtomicBool>) {
    let fail = |msg: String| {
        wlog!(Level::Error, "controller unavailable: {msg}");
        shared.with(|s| s.info.error = Some(msg.clone()));
        serve_unavailable(&rx, &stop, &msg);
    };
    let state = match StateDir::open(&g.state_dir) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    // 1) アドレス帳 + smweb.json → スナップショット(全ノード Offline で開始、§4.3)。
    let entries = match state.lock().and_then(|_l| nodes::load(&state.nodes_path())) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let store_path = Store::path(&g.state_dir);
    let store = {
        let _l = state.lock();
        load_store(&store_path)
    };
    shared.with(|s| {
        s.nodes = entries
            .iter()
            .map(|e| {
                let mut n = NodeSnap::new(e.node_id, e.label.clone(), addr_string(e.last_addr));
                if let Some(st) = store.nodes.get(&e.node_id) {
                    n.kind = st.kind;
                    n.model = st.model.clone();
                    n.watch = st.watch.clone();
                }
                n
            })
            .collect();
    });
    wlog!(
        Level::Info,
        "loaded {} node(s) from {} ({} cached model(s) in {})",
        entries.len(),
        state.nodes_path().display(),
        store.nodes.values().filter(|n| n.model.is_some()).count(),
        store_path.display()
    );

    // 2) CA(fabric)。W2 は pairing を持たないので、無ければ操作を受け付けない。
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
    let mut exec = match Exec::new(g.clone(), state, &crypto, &ca, true) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    exec.enable_sub_capture();
    shared.with(|s| s.info.ready = true);
    wlog!(
        Level::Info,
        "controller ready (fabric {:#x}, controller node {:#x})",
        ca.fabric_id(),
        ca.controller_node_id()
    );

    let (probe_tx, probe_rx) = mpsc::channel();
    let mut ctl = Ctl {
        exec,
        shared,
        store,
        store_path,
        state_dir: g.state_dir.clone(),
        subs: Vec::new(),
        retry: BTreeMap::new(),
        ready: VecDeque::new(),
        described: Vec::new(),
        probe_tx,
        probe_rx,
    };

    // 4) 起動時の自動接続: 最後に接続できた順(未接続は後ろ)に全ノードを予約する。
    let mut order: Vec<(Option<u64>, u64)> = entries
        .iter()
        .map(|e| {
            (
                ctl.store.nodes.get(&e.node_id).and_then(|s| s.last_online),
                e.node_id,
            )
        })
        .collect();
    order.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let now = Instant::now();
    for (_, id) in order {
        ctl.retry.insert(
            id,
            Retry {
                attempt: 0,
                due: now,
                probing: false,
                seq: ctl.retry.len() as u32,
            },
        );
    }

    // 5) ループ: Command 優先 → probe 結果 → 予約接続 → 無ければ IO 1 反復(最長 50ms)。
    //    購読イベントは毎反復で回収する(待ち時間中に届いた分も含む)。
    while !stop.load(Ordering::SeqCst) {
        match rx.try_recv() {
            Ok(req) => {
                let reply = ctl.handle(req.cmd);
                let _ = req.reply.send(reply);
                ctl.pump_sub_events();
                continue;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        ctl.poll_probes();
        ctl.start_due_probes();
        if let Some(node_id) = ctl.ready.pop_front() {
            ctl.auto_connect(node_id);
            ctl.pump_sub_events();
            continue;
        }
        if let Err(e) = ctl.exec.idle() {
            wlog!(Level::Warn, "io: {e}");
            std::thread::sleep(Duration::from_millis(50));
        }
        ctl.pump_sub_events();
    }
    wlog!(Level::Info, "controller thread stopped");
}

/// 起動に失敗したとき: 全 Command にエラーを返し続ける。
fn serve_unavailable(rx: &Receiver<Request>, stop: &AtomicBool, msg: &str) {
    while !stop.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(req) => {
                let _ = req.reply.send(Err(ApiError::new(ErrorCode::Internal, msg)));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// 確立中の購読。
struct SubRec {
    node_id: u64,
    session: SessionId,
    sub_id: u32,
}

/// 自動(再)接続の予約。
struct Retry {
    /// 連続失敗回数(次の遅延 = `backoff(attempt)`)。
    attempt: u32,
    due: Instant,
    /// probe スレッドが走っている。
    probing: bool,
    /// 同時刻の予約の順序(起動時の接続順)。
    seq: u32,
}

type ProbeResult = (u64, Result<SocketAddr, String>);

/// コントローラの状態(スレッド内専有)。
struct Ctl<'a> {
    exec: Exec<'a>,
    shared: Shared,
    store: Store,
    store_path: PathBuf,
    state_dir: PathBuf,
    subs: Vec<SubRec>,
    retry: BTreeMap<u64, Retry>,
    /// probe 済みで CASE 待ちのノード(順に 1 件ずつ)。
    ready: VecDeque<u64>,
    /// 今回のプロセスで Describe 済みのノード。
    described: Vec<u64>,
    probe_tx: Sender<ProbeResult>,
    probe_rx: Receiver<ProbeResult>,
}

impl Ctl<'_> {
    // ------------------------------------------------------------------
    // Command
    // ------------------------------------------------------------------

    /// 1 Command の処理。
    fn handle(&mut self, cmd: Command) -> Reply {
        let node_id = cmd.node_id();
        if self.shared.with(|s| s.node(node_id).is_none()) {
            return Err(ApiError::not_found(format!(
                "node {node_id:#x} is not in the address book"
            )));
        }
        let r = match cmd {
            Command::Connect { node_id } => self.connect_full(node_id, false),
            Command::Describe { node_id } => self.connect_full(node_id, true),
            Command::Watch {
                node_id,
                paths,
                add,
            } => self.watch(node_id, paths, add),
            Command::Read {
                node_id,
                ep,
                cluster,
                attr,
                raw,
            } => self.read(node_id, ep, cluster, attr, raw),
            Command::Invoke {
                node_id,
                ep,
                cluster,
                cmd,
                fields,
                tlv,
                timed_ms,
            } => invoke(
                &mut self.exec,
                node_id,
                ep,
                cluster,
                cmd,
                fields,
                tlv,
                timed_ms,
            ),
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
        // 成功した操作は到達性の証拠(Online)、タイムアウト等は Offline(§4.3)。
        match &r {
            Ok(_) => {
                let addr = self.current_addr(node_id);
                self.shared
                    .set_state(node_id, NodeState::Online, addr, false);
            }
            Err(e) if e.code == ErrorCode::ImStatus => {
                // デバイスは応答している。
                self.shared
                    .set_state(node_id, NodeState::Online, None, false);
            }
            Err(e) if matches!(e.code, ErrorCode::Timeout | ErrorCode::Internal) => {
                self.connect_failed(node_id, &e.message);
            }
            Err(_) => {}
        }
        r
    }

    /// アドレス帳から現在の運用アドレスを読む(CASE 成立時に Exec が更新している)。
    fn current_addr(&self, node_id: u64) -> Option<String> {
        let st = self.exec.state_dir();
        let _l = st.lock().ok()?;
        nodes::load(&st.nodes_path())
            .ok()?
            .into_iter()
            .find(|e| e.node_id == node_id)
            .and_then(|e| addr_string(e.last_addr))
    }

    /// 接続(または操作)失敗: 購読が無ければ Offline にして再接続を予約する。
    fn connect_failed(&mut self, node_id: u64, msg: &str) {
        wlog!(Level::Warn, "node {node_id:#x}: {msg}");
        if self.subs.iter().any(|s| s.node_id == node_id) {
            // 購読は生きている可能性がある(レポートが来れば Online に戻る。
            // 本当に死んでいれば SubscriptionLost → 再接続)。
            self.shared
                .set_state(node_id, NodeState::Offline, None, false);
            return;
        }
        self.shared.with_node(node_id, |n| {
            n.state = NodeState::Offline;
            n.error = Some(msg.to_string());
        });
        self.schedule_retry(node_id);
    }

    /// 接続 = CASE → Describe(未取得 or `force`)→ 既定購読 + watch。
    fn connect_full(&mut self, node_id: u64, force_describe: bool) -> Reply {
        let cached = self.exec.is_connected(node_id);
        if !cached {
            wlog!(Level::Info, "connecting to node {node_id:#x}...");
        }
        self.exec.connect(node_id).map_err(ApiError::from_exec)?;
        let addr = self.current_addr(node_id);
        self.shared
            .set_state(node_id, NodeState::Online, addr.clone(), true);
        let has_model = self
            .shared
            .with_node(node_id, |n| n.model.is_some())
            .unwrap_or(false);
        if force_describe || !has_model || !self.described.contains(&node_id) {
            self.describe(node_id)?;
        }
        let sub_id = self.resubscribe(node_id)?;
        self.retry.remove(&node_id);
        self.store.node_mut(node_id).last_online = Some(unix_now());
        self.save_store();
        let kind = self.shared.with_node(node_id, |n| n.kind);
        Ok(json!({
            "node_id": node_id,
            "state": NodeState::Online,
            "addr": addr,
            "cached_session": cached,
            "kind": kind,
            "sub_id": sub_id,
        }))
    }

    /// 自動(再)接続(probe 成功後)。
    fn auto_connect(&mut self, node_id: u64) {
        if !self.retry.contains_key(&node_id) {
            return; // 手動 Connect 等で解決済み。
        }
        match self.connect_full(node_id, false) {
            Ok(_) => wlog!(Level::Info, "node {node_id:#x} connected"),
            Err(e) => self.connect_failed(node_id, &e.message),
        }
    }

    // ------------------------------------------------------------------
    // Describe(§5.1)
    // ------------------------------------------------------------------

    /// パス列を [`READ_CHUNK`] 本ずつ Read して結果を連結する。
    fn read_chunked(
        &mut self,
        node_id: u64,
        paths: &[AttrPath],
    ) -> Result<Vec<ReadItem>, ApiError> {
        let mut out = Vec::new();
        for chunk in paths.chunks(READ_CHUNK) {
            let ap: Vec<AttributePath> = chunk.iter().map(|p| concrete(*p)).collect();
            out.extend(
                self.exec
                    .read_paths(node_id, &ap)
                    .map_err(ApiError::from_exec)?,
            );
        }
        Ok(out)
    }

    fn describe(&mut self, node_id: u64) -> Result<(), ApiError> {
        use describe::*;
        wlog!(Level::Info, "describing node {node_id:#x}...");
        // 1) EP0 PartsList。
        let items = self.read_chunked(node_id, &[AttrPath::new(0, DESCRIPTOR, PARTS_LIST)])?;
        let parts: Vec<u16> = collect_lists(&items, DESCRIPTOR, PARTS_LIST, as_u32)
            .remove(&0)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| u16::try_from(p).ok())
            .collect();
        let mut eps: Vec<u16> = std::iter::once(0).chain(parts.iter().copied()).collect();
        eps.sort_unstable();
        eps.dedup();
        // 2) 各 EP の DeviceTypeList / ServerList。
        let paths: Vec<AttrPath> = eps
            .iter()
            .flat_map(|&ep| {
                [
                    AttrPath::new(ep, DESCRIPTOR, DEVICE_TYPE_LIST),
                    AttrPath::new(ep, DESCRIPTOR, SERVER_LIST),
                ]
            })
            .collect();
        let items = self.read_chunked(node_id, &paths)?;
        let device_types = collect_lists(&items, DESCRIPTOR, DEVICE_TYPE_LIST, device_type_of);
        let servers = collect_lists(&items, DESCRIPTOR, SERVER_LIST, as_u32);
        // 3) BasicInformation。
        let paths: Vec<AttrPath> = BASIC_ATTRS
            .iter()
            .map(|&a| AttrPath::new(0, BASIC_INFORMATION, a))
            .collect();
        let basic = basic_info(&self.read_chunked(node_id, &paths)?);
        // 4) クラスタ表にある (ep, cluster) の AttributeList。
        let pairs: Vec<(u16, u32)> = servers
            .iter()
            .flat_map(|(&ep, cl)| {
                cl.iter()
                    .filter(|&&c| clusters::by_id(ClusterId(c)).is_some())
                    .map(move |&c| (ep, c))
            })
            .collect();
        let paths: Vec<AttrPath> = pairs
            .iter()
            .map(|&(ep, c)| AttrPath::new(ep, c, ATTRIBUTE_LIST))
            .collect();
        let items = self.read_chunked(node_id, &paths)?;
        let mut attr_lists = BTreeMap::new();
        for &(ep, c) in &pairs {
            if let Some(l) = collect_lists(&items, c, ATTRIBUTE_LIST, as_u32).remove(&ep) {
                attr_lists.insert((ep, c), l);
            }
        }
        let model = build_model(
            &parts,
            &device_types,
            &servers,
            &attr_lists,
            basic,
            unix_now(),
        );
        let kind = classify(&model);
        wlog!(
            Level::Info,
            "node {node_id:#x}: {} endpoint(s), kind {kind:?}{}",
            model.endpoints.len(),
            model
                .basic
                .product_name
                .as_deref()
                .map(|p| format!(", product {p:?}"))
                .unwrap_or_default()
        );
        self.shared.with_node(node_id, |n| {
            n.kind = kind;
            n.model = Some(model.clone());
        });
        {
            let st = self.store.node_mut(node_id);
            st.kind = kind;
            st.model = Some(model.clone());
        }
        self.save_store();
        if !self.described.contains(&node_id) {
            self.described.push(node_id);
        }
        self.shared.emit(Event::Model {
            node_id,
            kind,
            model,
        });
        Ok(())
    }

    fn save_store(&self) {
        let st = self.exec.state_dir();
        let r = st.lock().and_then(|_l| self.store.save(&self.store_path));
        if let Err(e) = r {
            wlog!(Level::Warn, "save {}: {e}", self.store_path.display());
        }
    }

    // ------------------------------------------------------------------
    // 購読(§5.2)
    // ------------------------------------------------------------------

    /// ノードの購読をローカルで捨てる。
    fn drop_sub(&mut self, node_id: u64) {
        while let Some(pos) = self.subs.iter().position(|s| s.node_id == node_id) {
            let rec = self.subs.remove(pos);
            self.exec.unsubscribe_local(rec.session, rec.sub_id);
        }
        self.shared.with_node(node_id, |n| n.sub_id = None);
    }

    /// 既定パス + watch で購読を張り直す(ノード 1 本、旧購読は先に捨てる)。
    fn resubscribe(&mut self, node_id: u64) -> Result<Option<u32>, ApiError> {
        self.drop_sub(node_id);
        let (kind, model, watch) = self
            .shared
            .with_node(node_id, |n| (n.kind, n.model.clone(), n.watch.clone()))
            .unwrap_or((NodeKind::Other, None, Vec::new()));
        let defaults = model
            .as_ref()
            .map(|m| describe::default_paths(kind, m))
            .unwrap_or_default();
        let paths = describe::merge_paths(&defaults, &watch);
        self.shared
            .with_node(node_id, |n| n.sub_paths = paths.clone());
        if paths.is_empty() {
            return Ok(None);
        }
        let ap: Vec<AttributePath> = paths.iter().map(|p| concrete(*p)).collect();
        let out = self
            .exec
            .subscribe_data(node_id, &ap, SUB_MIN_S, SUB_MAX_S)
            .map_err(ApiError::from_exec)?;
        self.subs.push(SubRec {
            node_id,
            session: out.session,
            sub_id: out.subscription_id,
        });
        self.shared
            .with_node(node_id, |n| n.sub_id = Some(out.subscription_id));
        wlog!(
            Level::Info,
            "node {node_id:#x}: subscription {} established ({} path(s), max {}s)",
            out.subscription_id,
            paths.len(),
            out.max_interval_s
        );
        self.shared.emit(Event::SubReady {
            node_id,
            sub_id: out.subscription_id,
            max_interval_s: out.max_interval_s,
            paths,
        });
        self.apply_items(node_id, &out.priming);
        Ok(Some(out.subscription_id))
    }

    /// 溜まった購読イベントを処理する。
    fn pump_sub_events(&mut self) {
        for ev in self.exec.take_sub_events() {
            match ev {
                SubEvent::Report {
                    session,
                    subscription_id,
                    items,
                } => {
                    let Some(node_id) = self
                        .subs
                        .iter()
                        .find(|s| s.session == session && s.sub_id == subscription_id)
                        .map(|s| s.node_id)
                    else {
                        continue;
                    };
                    let st = self.shared.with_node(node_id, |n| n.state);
                    if st != Some(NodeState::Online) {
                        self.shared
                            .set_state(node_id, NodeState::Online, None, false);
                    }
                    self.apply_items(node_id, &items);
                }
                SubEvent::Lost {
                    session,
                    subscription_id,
                } => {
                    let Some(pos) = self
                        .subs
                        .iter()
                        .position(|s| s.session == session && s.sub_id == subscription_id)
                    else {
                        continue;
                    };
                    let rec = self.subs.remove(pos);
                    let node_id = rec.node_id;
                    wlog!(
                        Level::Warn,
                        "node {node_id:#x}: subscription {subscription_id} lost; reconnecting"
                    );
                    self.shared.with_node(node_id, |n| {
                        n.sub_id = None;
                        n.state = NodeState::Stale;
                    });
                    self.shared.emit(Event::SubLost {
                        node_id,
                        sub_id: subscription_id,
                    });
                    // セッションも死んでいる可能性が高い(デバイス再起動等)ので張り直す。
                    self.exec.forget_session(node_id);
                    self.schedule_retry(node_id);
                }
            }
        }
    }

    /// Read / レポートの結果を値キャッシュへ反映し `Event::Attr` を流す。
    fn apply_items(&mut self, node_id: u64, items: &[ReadItem]) {
        let ts = unix_now_ms();
        for it in items {
            if let Some(v) = item_value(it, ts) {
                let ev = Event::attr(node_id, &v);
                self.shared.with_node(node_id, |n| n.update_value(v));
                self.shared.emit(ev);
            }
        }
    }

    /// watch パスの追加 / 削除。
    fn watch(&mut self, node_id: u64, paths: Vec<AttrPath>, add: bool) -> Reply {
        let watch = self
            .shared
            .with_node(node_id, |n| {
                if add {
                    for p in &paths {
                        if !n.watch.contains(p) {
                            n.watch.push(*p);
                        }
                    }
                } else {
                    n.watch.retain(|p| !paths.contains(p));
                }
                n.watch.clone()
            })
            .unwrap_or_default();
        self.store.node_mut(node_id).watch = watch.clone();
        self.save_store();
        self.shared.emit(Event::Watch {
            node_id,
            watch: watch.clone(),
        });
        // 接続中なら張り直す(未接続なら次の接続で反映)。
        let online =
            self.exec.is_connected(node_id) || self.subs.iter().any(|s| s.node_id == node_id);
        let sub_id = if online {
            self.resubscribe(node_id)?
        } else {
            None
        };
        let sub_paths = self.shared.with_node(node_id, |n| n.sub_paths.clone());
        Ok(json!({
            "node_id": node_id,
            "watch": watch,
            "sub_id": sub_id,
            "sub_paths": sub_paths,
            "applied": online,
        }))
    }

    fn read(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        raw: bool,
    ) -> Reply {
        let items = self
            .exec
            .read_data(node_id, ep, cluster, Some(attr))
            .map_err(ApiError::from_exec)?;
        let item = items
            .first()
            .ok_or_else(|| ApiError::new(ErrorCode::Internal, "no attribute report in response"))?
            .clone();
        if matches!(item.outcome, ReadOutcome::Data(_)) {
            self.apply_items(node_id, &items);
        }
        read_reply(node_id, ep, cluster, attr, item, raw)
    }

    // ------------------------------------------------------------------
    // 自動(再)接続: probe(別スレッドで mDNS)→ CASE
    // ------------------------------------------------------------------

    /// 再接続を予約する(既に予約済みなら遅延を伸ばす)。
    fn schedule_retry(&mut self, node_id: u64) {
        let seq = self.retry.len() as u32;
        let r = self.retry.entry(node_id).or_insert(Retry {
            attempt: 0,
            due: Instant::now(),
            probing: false,
            seq,
        });
        if r.probing {
            return;
        }
        let delay = backoff(r.attempt);
        r.attempt = r.attempt.saturating_add(1);
        r.due = Instant::now() + delay;
        let at = unix_now() + delay.as_secs();
        self.ready.retain(|&n| n != node_id);
        self.shared.with_node(node_id, |n| n.next_retry = Some(at));
        wlog!(
            Level::Info,
            "node {node_id:#x}: reconnect in {}s",
            delay.as_secs()
        );
        self.shared.emit_state(node_id);
    }

    /// 期限の来た予約を probe に回す。
    fn start_due_probes(&mut self) {
        let now = Instant::now();
        let mut due: Vec<(u32, u64)> = self
            .retry
            .iter()
            .filter(|(_, r)| !r.probing && r.due <= now)
            .map(|(&id, r)| (r.seq, id))
            .collect();
        due.sort_unstable();
        for (_, node_id) in due {
            if self.ready.contains(&node_id) {
                continue;
            }
            // 既にセッションがあれば mDNS は不要(購読の張り直しだけ)。
            if self.exec.is_connected(node_id) {
                self.ready.push_back(node_id);
                continue;
            }
            if let Some(r) = self.retry.get_mut(&node_id) {
                r.probing = true;
            }
            let last = self
                .shared
                .with_node(node_id, |n| n.addr.as_deref().and_then(|a| a.parse().ok()))
                .flatten();
            self.shared.with_node(node_id, |n| n.next_retry = None);
            spawn_probe(self.state_dir.clone(), node_id, last, self.probe_tx.clone());
        }
    }

    /// probe 結果を回収する。
    fn poll_probes(&mut self) {
        while let Ok((node_id, res)) = self.probe_rx.try_recv() {
            let Some(r) = self.retry.get_mut(&node_id) else {
                continue; // 手動 Connect で解決済み。
            };
            r.probing = false;
            match res {
                Ok(addr) => {
                    self.note_resolved(node_id, addr);
                    if !self.ready.contains(&node_id) {
                        self.ready.push_back(node_id);
                    }
                }
                Err(e) => {
                    self.shared.with_node(node_id, |n| {
                        n.state = NodeState::Offline;
                        n.error = Some(e.clone());
                    });
                    wlog!(Level::Info, "node {node_id:#x}: not reachable ({e})");
                    self.schedule_retry(node_id);
                }
            }
        }
    }

    /// probe で解決したアドレスをアドレス帳へ反映する(次の CASE がキャッシュアドレスで
    /// 即座に当たるように。mDNS 再解決でコントローラを塞がない)。
    fn note_resolved(&mut self, node_id: u64, addr: SocketAddr) {
        let st = self.exec.state_dir();
        let r = st.lock().and_then(|_l| {
            let cur = nodes::load(&st.nodes_path())?
                .into_iter()
                .find(|e| e.node_id == node_id)
                .map(|e| e.last_addr);
            // nodes.tlv は scope を保存しないので scope 抜きで比較する。
            let bare = strip_scope(addr);
            if cur.map(strip_scope) != Some(bare) {
                nodes::update_addr(&st.nodes_path(), node_id, bare)?;
            }
            Ok(())
        });
        if let Err(e) = r {
            wlog!(Level::Warn, "update address of node {node_id:#x}: {e}");
        }
    }
}

fn strip_scope(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(mut v6) => {
            v6.set_scope_id(0);
            SocketAddr::V6(v6)
        }
        v4 => v4,
    }
}

/// 別スレッドで運用 mDNS 解決を行う(CA は読み取り専用で別途ロード)。
fn spawn_probe(
    state_dir: PathBuf,
    node_id: u64,
    last: Option<SocketAddr>,
    tx: Sender<ProbeResult>,
) {
    let r = std::thread::Builder::new()
        .name(format!("smweb-probe-{node_id:x}"))
        .spawn(move || {
            let r = probe(&state_dir, node_id, last);
            let _ = tx.send((node_id, r));
        });
    if let Err(e) = r {
        wlog!(Level::Warn, "spawn probe thread: {e}");
    }
}

fn probe(state_dir: &Path, node_id: u64, last: Option<SocketAddr>) -> Result<SocketAddr, String> {
    let crypto = smctl::simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let st = StateDir::open(state_dir)?;
    let ca = st
        .lock()
        .and_then(|_l| ca_state::load(&st.ca_path(), &crypto))?
        .ok_or("no CA state")?;
    if let Some(a) = last {
        if let Ok(x) = mdns::resolve_operational_at(&ca, node_id, &[a.ip()], PROBE_AT_TIMEOUT) {
            return Ok(x);
        }
    }
    mdns::resolve_operational(&ca, node_id, PROBE_TIMEOUT)
}

/// 具象属性パス。
fn concrete(p: AttrPath) -> AttributePath {
    AttributePath::concrete(EndpointId(p.ep), ClusterId(p.cluster), AttributeId(p.attr))
}

/// ReadItem → 値キャッシュ要素(具象パスのみ。list 追記チャンクは対象外)。
fn item_value(it: &ReadItem, ts: u64) -> Option<AttrValue> {
    let (Some(ep), Some(cluster), Some(attr)) = (it.endpoint, it.cluster, it.attribute) else {
        return None;
    };
    if it.list_append {
        return None;
    }
    let (value, raw_hex) = match &it.outcome {
        ReadOutcome::Data(raw) => {
            let kind = clusters::by_id(ClusterId(cluster))
                .and_then(|c| c.attr_by_id(AttributeId(attr)))
                .map(|a| a.kind);
            (value_json(kind, raw), to_hex(raw))
        }
        ReadOutcome::Status {
            status,
            cluster_status,
        } => (
            json!({
                "status": format!("{status:?}"),
                "status_code": status.to_u8(),
                "cluster_status": cluster_status,
            }),
            String::new(),
        ),
        ReadOutcome::Undecodable(_) => return None,
    };
    Some(AttrValue {
        ep,
        cluster,
        attr,
        value,
        raw_hex,
        data_version: it.data_version,
        ts,
    })
}

fn read_reply(
    node_id: u64,
    ep: u16,
    cluster: ClusterId,
    attr: AttributeId,
    item: ReadItem,
    raw: bool,
) -> Reply {
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

#[cfg(test)]
mod tests {
    use super::*;
    use smctl::simple_matter::tlv::{TlvTag, TlvWriter};

    #[test]
    fn item_to_cached_value() {
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_i16(&TlvTag::ContextSpecific(2), 2345).unwrap();
        let raw = w.written().to_vec();
        let it = ReadItem {
            endpoint: Some(2),
            cluster: Some(0x0402),
            attribute: Some(0),
            list_append: false,
            data_version: Some(9),
            outcome: ReadOutcome::Data(raw.clone()),
        };
        let v = item_value(&it, 42).unwrap();
        assert_eq!(v.value, json!(2345));
        assert_eq!(v.raw_hex, to_hex(&raw));
        assert_eq!(v.data_version, Some(9));
        assert_eq!(v.ts, 42);
        // list 追記チャンク・ワイルドカードは対象外。
        let mut a = it.clone();
        a.list_append = true;
        assert!(item_value(&a, 0).is_none());
        let mut w = it.clone();
        w.endpoint = None;
        assert!(item_value(&w, 0).is_none());
        // ステータスは status オブジェクト。
        let s = ReadItem {
            outcome: ReadOutcome::Status {
                status: smctl::simple_matter::im::wire::ImStatus::UnsupportedAttribute,
                cluster_status: None,
            },
            ..it
        };
        let v = item_value(&s, 0).unwrap();
        assert_eq!(v.value["status"], "UnsupportedAttribute");
        assert_eq!(v.raw_hex, "");
    }

    #[test]
    fn scope_stripping() {
        let a: SocketAddr = "[fe80::1%3]:5540".parse().unwrap();
        assert_eq!(strip_scope(a).to_string(), "[fe80::1]:5540");
        let b: SocketAddr = "192.168.8.163:5540".parse().unwrap();
        assert_eq!(strip_scope(b), b);
    }
}
