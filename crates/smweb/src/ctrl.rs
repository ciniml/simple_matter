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
//!
//! W3: Pair(UDP = `Exec::pair_addr`、BLE = `runner::ble::pair_ble_with_ca`)/ Unpair /
//! ラベル変更 / コミッショニングウィンドウ(Share)の開閉と状態。pairing は Command 1 件として
//! コントローラスレッドを専有する(その間は他の Command と UDP 受信が止まる)。UDP pairing 中は
//! 既存の購読をローカルで外しておく(コアの `Commissioner` は IM イベントを 1 本のキューから
//! 取り出すため、他ノードの購読レポートが割り込むとフェーズ機械が Protocol 失敗になる)。
//!
//! W5: `Event::Attr` を流すとき数値属性を [`History`] に積む(§9.1)。`Arc<RwLock<History>>`
//! を REST と共有し、60 秒ごと(変化があれば)とスレッド終了時に `smweb-history.bin` へ保存。
//! unpair で系列を消す。

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use smctl::runner::{mdns, Backend};
use smctl::simple_matter::controller::ca::Ca;
use smctl::simple_matter::controller::Phase;
use smctl::simple_matter::discovery::onboarding::random_discriminator;
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use smctl::simple_matter::im::wire::AttributePath;
use smctl::simple_matter::transport::session::SessionId;
use smctl::state::{ca as ca_state, nodes, StateDir};
use smctl::OsRng;
use tokio::sync::{broadcast, oneshot};

use crate::describe::{self, backoff};
use crate::error::{ApiError, ErrorCode};
use crate::history::{self, History};
use crate::model::{
    unix_now, unix_now_ms, AttrPath, AttrValue, Event, Info, NodeKind, NodeSnap, NodeState,
    Snapshot,
};
use crate::pairing::next_free_node_id;
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
/// UDP コミッショニング全体(PASE〜CommissioningComplete)の最低タイムアウト。
const PAIR_MIN_TIMEOUT: Duration = Duration::from_secs(60);
/// AdministratorCommissioning(0x003C)。
const ADMIN_COMMISSIONING: u32 = 0x003C;
/// 履歴の定期保存間隔(§9.1)。
const HISTORY_SAVE_EVERY: Duration = Duration::from_secs(60);

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
    /// コミッショニング(進捗は `Event::Progress{op_id}`、終端は HTTP 側が流す)。
    Pair { op_id: u64, job: PairJob },
    /// unpair(RemoveFabric + ローカル状態削除)。`force` はローカル状態だけ消す。
    Unpair { node_id: u64, force: bool },
    /// ラベル変更(`nodes.tlv` + `smweb.json`)。
    SetLabel { node_id: u64, label: String },
    /// ECM 窓オープン(Share)。
    OpenWindow {
        node_id: u64,
        timeout_s: u16,
        discriminator: Option<u16>,
        passcode: Option<u32>,
    },
    /// RevokeCommissioning。
    Revoke { node_id: u64 },
    /// 窓の状態(AdministratorCommissioning の WindowStatus 等を読む)。
    WindowStatus { node_id: u64 },
}

/// コミッショニング対象(mDNS 解決は HTTP 側で済ませてから投入する)。
#[derive(Debug, Clone)]
pub enum PairTarget {
    /// UDP(on-network / アドレス直指定)。
    Udp(SocketAddr),
    /// BLE(feature `ble`)。`wifi` / `thread` のどちらか。
    Ble {
        discriminator: Option<u16>,
        wifi: Option<(String, String)>,
        thread: Option<Vec<u8>>,
    },
}

/// `Command::Pair` の中身。
#[derive(Debug, Clone)]
pub struct PairJob {
    /// 明示 node ID(`None` = アドレス帳の次の空き番号)。
    pub node_id: Option<u64>,
    pub label: String,
    pub passcode: u32,
    pub target: PairTarget,
}

impl Command {
    /// 対象ノード(アドレス帳に存在することを要求する)。Pair は `None`。
    fn node_id(&self) -> Option<u64> {
        match self {
            Command::Connect { node_id }
            | Command::Describe { node_id }
            | Command::Read { node_id, .. }
            | Command::Invoke { node_id, .. }
            | Command::Write { node_id, .. }
            | Command::Watch { node_id, .. }
            | Command::Unpair { node_id, .. }
            | Command::SetLabel { node_id, .. }
            | Command::OpenWindow { node_id, .. }
            | Command::Revoke { node_id }
            | Command::WindowStatus { node_id } => Some(*node_id),
            Command::Pair { .. } => None,
        }
    }

    /// 結果をノードの到達性(Online / Offline)に反映する操作か。
    fn touches_device(&self) -> bool {
        match self {
            Command::Pair { .. } | Command::SetLabel { .. } => false,
            Command::Unpair { force, .. } => !*force,
            _ => true,
        }
    }

    fn is_long(&self) -> bool {
        matches!(
            self,
            Command::Connect { .. }
                | Command::Describe { .. }
                | Command::Watch { .. }
                | Command::Pair { .. }
                | Command::Unpair { .. }
                | Command::OpenWindow { .. }
                | Command::Revoke { .. }
                | Command::WindowStatus { .. }
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
    /// 属性値の履歴(§9。REST はコントローラを待たずに読む)。
    pub history: Arc<RwLock<History>>,
    history_path: PathBuf,
    wait: Duration,
    op_seq: Arc<AtomicU64>,
}

impl CtrlHandle {
    /// Command を投入して Reply を待つ(tokio 側はブロックしない)。
    pub async fn call(&self, cmd: Command) -> Reply {
        let wait = if cmd.is_long() {
            self.wait + CONNECT_MARGIN
        } else {
            self.wait
        };
        self.call_with(cmd, wait).await
    }

    /// 待ち時間を指定して Command を投入する(pairing のような長時間操作用)。
    pub async fn call_with(&self, cmd: Command, wait: Duration) -> Reply {
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

    /// 長時間操作の ID を払い出す(1 始まり)。
    pub fn next_op_id(&self) -> u64 {
        self.op_seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// イベントを流す(HTTP 側で完結する進捗用)。
    pub fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    /// スナップショットの読み取り(毒化しても中身は使う)。
    pub fn snapshot(&self) -> Snapshot {
        match self.snapshot.read() {
            Ok(s) => s.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// 履歴を読む(毒化しても中身は使う)。
    pub fn with_history<R>(&self, f: impl FnOnce(&History) -> R) -> R {
        match self.history.read() {
            Ok(h) => f(&h),
            Err(p) => f(&p.into_inner()),
        }
    }

    /// 履歴を(変化があれば)保存する。コントローラスレッドが終了時の保存に
    /// 間に合わなかったときの main 側の保険(保存処理は直列化されている)。
    pub fn save_history(&self) {
        if let Err(e) = history::save_shared(&self.history, &self.history_path) {
            wlog!(Level::Warn, "history: {e}");
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
    history: Arc<RwLock<History>>,
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

    fn with_history<R>(&self, f: impl FnOnce(&mut History) -> R) -> R {
        let mut g = match self.history.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        f(&mut g)
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
/// `history_points` は 1 系列あたりの履歴点数(`--history-points`、§9.1)。
pub fn spawn(g: Globals, history_points: usize) -> (CtrlHandle, CtrlThread) {
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
    let history = Arc::new(RwLock::new(History::new(history_points)));
    let history_path = history::path(&g.state_dir);
    let shared = Shared {
        events: events.clone(),
        snapshot: snapshot.clone(),
        history: history.clone(),
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
            history,
            history_path,
            wait,
            op_seq: Arc::new(AtomicU64::new(0)),
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
                // ラベルの正は nodes.tlv(smctl と共有)。smweb.json の控えは表示に使わない。
                if let Some(st) = store.nodes.get(&e.node_id) {
                    n.kind = st.kind;
                    n.model = st.model.clone();
                    n.watch = st.watch.clone();
                }
                n
            })
            .collect();
    });
    // 履歴(§9.1)。壊れていれば .bad へ退避して空から。アドレス帳に無いノードの系列は捨てる。
    let history_path = history::path(&g.state_dir);
    {
        let cap = shared.with_history(|h| h.cap());
        let (mut h, err) = History::load_or_quarantine(&history_path, cap);
        if let Some(e) = err {
            wlog!(
                Level::Warn,
                "history: {e}; moved it to {} and starting empty",
                history::bad_path(&history_path).display()
            );
        }
        let ids: Vec<u64> = entries.iter().map(|e| e.node_id).collect();
        let dropped = h.retain_nodes(&ids);
        wlog!(
            Level::Info,
            "history: {} series from {}{}",
            h.len(),
            history_path.display(),
            if dropped > 0 {
                format!(" ({dropped} series of removed nodes dropped)")
            } else {
                String::new()
            }
        );
        shared.with_history(|cur| *cur = h);
    }
    wlog!(
        Level::Info,
        "loaded {} node(s) from {} ({} cached model(s) in {})",
        entries.len(),
        state.nodes_path().display(),
        store.nodes.values().filter(|n| n.model.is_some()).count(),
        store_path.display()
    );

    // 2) CA(fabric)。無ければ smctl の pairing と同じく新規生成して保存する(W3: smweb
    //    自身が pairing できるので、空の状態ディレクトリからでも始められる)。
    let crypto = smctl::simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let ca = match state
        .lock()
        .and_then(|_l| ca_state::load_or_create(&state.ca_path(), &crypto))
    {
        Ok(ca) => ca,
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
        g: g.clone(),
        crypto: &crypto,
        ca: &ca,
        windows: BTreeMap::new(),
        shared,
        store,
        store_path,
        history_path,
        history_saved: Instant::now(),
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
        if ctl.history_saved.elapsed() >= HISTORY_SAVE_EVERY {
            ctl.save_history();
        }
    }
    ctl.save_history();
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
    /// 共通オプション(BLE pairing へ渡す)。
    g: Globals,
    crypto: &'a Backend,
    /// Exec と共有する CA(BLE pairing でも同じ serial カウンタを使う)。
    #[cfg_attr(not(feature = "ble"), allow(dead_code))]
    ca: &'a Ca<Backend>,
    /// このプロセスで開いた窓(node → 払い出し情報 JSON)。
    windows: BTreeMap<u64, Value>,
    shared: Shared,
    store: Store,
    store_path: PathBuf,
    /// `<state-dir>/smweb-history.bin`。
    history_path: PathBuf,
    /// 最後に履歴を保存(または保存を試行)した時刻。
    history_saved: Instant,
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
        let target = cmd.node_id();
        if let Some(node_id) = target {
            if self.shared.with(|s| s.node(node_id).is_none()) {
                return Err(ApiError::not_found(format!(
                    "node {node_id:#x} is not in the address book"
                )));
            }
        }
        let node_id = target.unwrap_or(0);
        let device = target.is_some() && cmd.touches_device();
        let r = match cmd {
            Command::Pair { op_id, job } => self.pair(op_id, job),
            Command::Unpair { node_id, force } => self.unpair(node_id, force),
            Command::SetLabel { node_id, label } => self.set_label(node_id, label),
            Command::OpenWindow {
                node_id,
                timeout_s,
                discriminator,
                passcode,
            } => self.open_window(node_id, timeout_s, discriminator, passcode),
            Command::Revoke { node_id } => self.revoke(node_id),
            Command::WindowStatus { node_id } => self.window_status(node_id),
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
        if !device {
            return r;
        }
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

    /// 履歴を(変化があれば)保存する。
    fn save_history(&mut self) {
        self.history_saved = Instant::now();
        match history::save_shared(&self.shared.history, &self.history_path) {
            Ok(true) => wlog!(
                Level::Debug,
                "history saved to {}",
                self.history_path.display()
            ),
            Ok(false) => {}
            Err(e) => wlog!(Level::Warn, "history: {e}"),
        }
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
                // 数値属性だけ履歴に積む(文字列・raw・ステータスは record が弾く、§9.1)。
                let path = AttrPath::new(v.ep, v.cluster, v.attr);
                self.shared
                    .with_history(|h| h.record(node_id, path, v.ts, &v.value));
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
    // Pair / Unpair / ラベル(W3)
    // ------------------------------------------------------------------

    fn progress(&self, op_id: u64, phase: &str, detail: impl Into<String>, node_id: Option<u64>) {
        self.shared
            .emit(Event::progress(op_id, phase, detail, node_id));
    }

    /// アドレス帳(nodes.tlv)とスナップショットにある node ID。
    fn known_node_ids(&self) -> Result<Vec<u64>, ApiError> {
        let st = self.exec.state_dir();
        let mut ids: Vec<u64> = st
            .lock()
            .and_then(|_l| nodes::load(&st.nodes_path()))
            .map_err(|e| ApiError::new(ErrorCode::Internal, e))?
            .iter()
            .map(|e| e.node_id)
            .collect();
        self.shared
            .with(|s| ids.extend(s.nodes.iter().map(|n| n.node_id)));
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }

    /// 購読をすべてローカルで外す(UDP pairing の前)。外したノードを返す。
    fn pause_subs(&mut self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.subs.iter().map(|s| s.node_id).collect();
        ids.sort_unstable();
        ids.dedup();
        for &id in &ids {
            self.drop_sub(id);
        }
        // slot に残っているレポートを捨てる(外した購読のものは照合で落ちる)。
        let _ = self.exec.idle();
        self.pump_sub_events();
        if !ids.is_empty() {
            wlog!(
                Level::Info,
                "pausing {} subscription(s) during commissioning",
                ids.len()
            );
        }
        ids
    }

    /// [`Self::pause_subs`] で外した購読を張り直す。
    fn resume_subs(&mut self, ids: Vec<u64>) {
        for id in ids {
            if let Err(e) = self.resubscribe(id) {
                self.connect_failed(id, &e.message);
            }
        }
    }

    /// コミッショニング → アドレス帳へ記帳(smctl と同じ)→ Connect(Describe + 既定購読)。
    fn pair(&mut self, op_id: u64, job: PairJob) -> Reply {
        let known = self.known_node_ids()?;
        let node_id = match job.node_id {
            Some(id) if known.contains(&id) => {
                return Err(ApiError::bad_request(format!(
                    "node id {id} ({id:#x}) is already in the address book (unpair it first \
                     or choose another id)"
                )))
            }
            Some(id) => id,
            None => next_free_node_id(&known),
        };
        let how = match &job.target {
            PairTarget::Udp(a) => format!("UDP {a}"),
            PairTarget::Ble { wifi: Some(_), .. } => "BLE + Wi-Fi".to_string(),
            PairTarget::Ble { .. } => "BLE + Thread".to_string(),
        };
        self.progress(
            op_id,
            "commissioning",
            format!("node id {node_id} ({node_id:#x}) via {how}"),
            Some(node_id),
        );
        wlog!(
            Level::Info,
            "pairing op {op_id}: node {node_id:#x} via {how}"
        );
        let shared = self.shared.clone();
        let prev = smctl::ops::set_phase_hook(Some(Box::new(move |p| {
            if let Some((phase, detail)) = phase_info(p) {
                shared.emit(Event::progress(op_id, phase, detail, Some(node_id)));
            }
        })));
        let r = match job.target {
            PairTarget::Udp(addr) => {
                let paused = self.pause_subs();
                let timeout = self.g.timeout.max(PAIR_MIN_TIMEOUT);
                let r = self
                    .exec
                    .pair_addr(node_id, job.passcode, addr, &job.label, timeout);
                self.resume_subs(paused);
                r
            }
            PairTarget::Ble {
                discriminator,
                wifi,
                thread,
            } => self.pair_ble(
                node_id,
                job.passcode,
                &job.label,
                discriminator,
                wifi,
                thread,
            ),
        };
        smctl::ops::set_phase_hook(prev);
        r.map_err(|e| ApiError::new(ErrorCode::Internal, e))?;

        // スナップショットと smweb.json に載せる(アドレスは smctl が記帳したもの)。
        let addr = self.current_addr(node_id);
        let snap = NodeSnap::new(node_id, job.label.clone(), addr.clone());
        self.shared.with(|s| {
            s.nodes.retain(|n| n.node_id != node_id);
            s.nodes.push(snap.clone());
            s.nodes.sort_by_key(|n| n.node_id);
        });
        self.store.nodes.remove(&node_id);
        self.store.node_mut(node_id).label = Some(job.label.clone());
        self.save_store();
        self.described.retain(|&n| n != node_id);
        self.shared.emit(Event::NodeAdded {
            node: Box::new(snap),
        });
        self.progress(
            op_id,
            "connect",
            format!(
                "commissioned{}; describing and subscribing",
                addr.as_deref()
                    .map(|a| format!(" at {a}"))
                    .unwrap_or_default()
            ),
            Some(node_id),
        );
        match self.connect_full(node_id, true) {
            Ok(v) => Ok(json!({ "node_id": node_id, "addr": addr, "connect": v })),
            Err(e) => {
                self.connect_failed(node_id, &e.message);
                Ok(json!({
                    "node_id": node_id,
                    "addr": addr,
                    "warning": format!("commissioned, but connecting failed: {}", e.message),
                }))
            }
        }
    }

    #[cfg(feature = "ble")]
    fn pair_ble(
        &mut self,
        node_id: u64,
        passcode: u32,
        label: &str,
        discriminator: Option<u16>,
        wifi: Option<(String, String)>,
        thread: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let mut g = self.g.clone();
        g.label = Some(label.to_string());
        smctl::runner::ble::pair_ble_with_ca(
            &g,
            self.crypto,
            self.ca,
            node_id,
            passcode,
            discriminator,
            false,
            wifi,
            thread,
        )
        .map(|_| ())
    }

    #[cfg(not(feature = "ble"))]
    fn pair_ble(
        &mut self,
        _node_id: u64,
        _passcode: u32,
        _label: &str,
        _discriminator: Option<u16>,
        _wifi: Option<(String, String)>,
        _thread: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let _ = self.crypto;
        Err("BLE not compiled in (rebuild smweb with `--features ble`)".into())
    }

    /// unpair。`force` = デバイスへは触らずローカル状態だけ消す。
    fn unpair(&mut self, node_id: u64, force: bool) -> Reply {
        let fabric_index = if force {
            self.drop_sub(node_id);
            self.exec
                .forget_local_node(node_id)
                .map_err(|e| ApiError::new(ErrorCode::Internal, e))?;
            None
        } else {
            let fi = self.exec.unpair_data(node_id).map_err(|e| {
                let mut a = ApiError::from_exec(e);
                a.message
                    .push_str(" (use ?force=1 to drop the local state only)");
                a
            })?;
            Some(fi)
        };
        self.remove_node_local(node_id);
        wlog!(
            Level::Info,
            "node {node_id:#x} {}",
            if force {
                "removed locally (device not contacted)"
            } else {
                "unpaired (RemoveFabric) and removed"
            }
        );
        Ok(json!({
            "node_id": node_id,
            "removed_from_device": !force,
            "fabric_index": fabric_index,
        }))
    }

    /// ノードを smweb の管理から外す(購読・予約・スナップショット・smweb.json)。
    fn remove_node_local(&mut self, node_id: u64) {
        self.drop_sub(node_id);
        self.exec.forget_session(node_id);
        self.retry.remove(&node_id);
        self.ready.retain(|&n| n != node_id);
        self.described.retain(|&n| n != node_id);
        self.windows.remove(&node_id);
        self.shared
            .with(|s| s.nodes.retain(|n| n.node_id != node_id));
        if self.store.nodes.remove(&node_id).is_some() {
            self.save_store();
        }
        // 履歴の系列も消す(§9.1)。消えたことをすぐファイルにも反映する。
        if self.shared.with_history(|h| h.remove_node(node_id)) > 0 {
            self.save_history();
        }
        self.shared.emit(Event::NodeRemoved { node_id });
    }

    /// ラベル変更(`nodes.tlv` が正、`smweb.json` に控え)。
    fn set_label(&mut self, node_id: u64, label: String) -> Reply {
        let st = self.exec.state_dir();
        st.lock()
            .and_then(|_l| {
                let path = st.nodes_path();
                let mut entries = nodes::load(&path)?;
                let e = entries
                    .iter_mut()
                    .find(|e| e.node_id == node_id)
                    .ok_or_else(|| format!("node {node_id} not in address book"))?;
                e.label = label.clone();
                nodes::save(&path, &entries)
            })
            .map_err(ApiError::from_exec)?;
        self.shared.with_node(node_id, |n| n.label = label.clone());
        self.store.node_mut(node_id).label = Some(label.clone());
        self.save_store();
        self.shared.emit(Event::NodeLabel {
            node_id,
            label: label.clone(),
        });
        Ok(json!({ "node_id": node_id, "label": label }))
    }

    // ------------------------------------------------------------------
    // Share: コミッショニングウィンドウ(Tab5 T9 相当)
    // ------------------------------------------------------------------

    fn open_window(
        &mut self,
        node_id: u64,
        timeout_s: u16,
        discriminator: Option<u16>,
        passcode: Option<u32>,
    ) -> Reply {
        let discriminator = match discriminator {
            Some(d) => d,
            None => random_discriminator(&mut OsRng)
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("rng: {e:?}")))?,
        };
        let (out, info) = self
            .exec
            .open_window_data(node_id, timeout_s, discriminator, passcode)
            .map_err(ApiError::from_exec)?;
        if !out.status.is_success() {
            return Err(ApiError::im_status(
                out.status.to_u8(),
                format!(
                    "OpenCommissioningWindow failed: {:?}{}",
                    out.status,
                    admin_cluster_status(out.cluster_status)
                ),
            ));
        }
        let now = unix_now();
        let v = window_json(node_id, &info, now);
        wlog!(
            Level::Info,
            "node {node_id:#x}: commissioning window open for {timeout_s}s \
             (discriminator {discriminator}, manual code {})",
            info.manual_code
        );
        self.windows.insert(node_id, v.clone());
        self.shared.emit(Event::Window {
            node_id,
            open: true,
            window: Some(v.clone()),
        });
        Ok(v)
    }

    fn revoke(&mut self, node_id: u64) -> Reply {
        let out = self
            .exec
            .revoke_data(node_id)
            .map_err(ApiError::from_exec)?;
        self.windows.remove(&node_id);
        self.shared.emit(Event::Window {
            node_id,
            open: false,
            window: None,
        });
        if !out.status.is_success() {
            return Err(ApiError::im_status(
                out.status.to_u8(),
                format!(
                    "RevokeCommissioning failed: {:?}{}",
                    out.status,
                    admin_cluster_status(out.cluster_status)
                ),
            ));
        }
        wlog!(
            Level::Info,
            "node {node_id:#x}: commissioning window revoked"
        );
        Ok(json!({ "node_id": node_id, "revoked": true }))
    }

    /// AdministratorCommissioning の WindowStatus / AdminFabricIndex / AdminVendorId を読み、
    /// このプロセスで開いた窓の情報(期限内なら)を添える。
    fn window_status(&mut self, node_id: u64) -> Reply {
        let items = self.read_chunked(
            node_id,
            &[
                AttrPath::new(0, ADMIN_COMMISSIONING, 0),
                AttrPath::new(0, ADMIN_COMMISSIONING, 1),
                AttrPath::new(0, ADMIN_COMMISSIONING, 2),
            ],
        )?;
        let status = item_uint(&items, ADMIN_COMMISSIONING, 0)
            .flatten()
            .ok_or_else(|| {
                ApiError::new(ErrorCode::Internal, "device did not report WindowStatus")
            })?;
        let open = status != 0;
        let now = unix_now();
        let cached = if open {
            self.windows
                .get(&node_id)
                .filter(|w| w["expires_at"].as_u64().is_some_and(|t| t > now))
                .cloned()
        } else {
            self.windows.remove(&node_id);
            None
        };
        let mut v = json!({
            "node_id": node_id,
            "open": open,
            "window_status": status,
            "window_status_name": match status {
                0 => "WindowNotOpen",
                1 => "EnhancedWindowOpen",
                2 => "BasicWindowOpen",
                _ => "Unknown",
            },
            "admin_fabric_index": item_uint(&items, ADMIN_COMMISSIONING, 1).flatten(),
            "admin_vendor_id": item_uint(&items, ADMIN_COMMISSIONING, 2).flatten(),
            "window": cached,
        });
        if let Some(t) = v["window"]["expires_at"].as_u64() {
            v["remaining_s"] = json!(t.saturating_sub(now));
        }
        Ok(v)
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
                    // mDNS では見つからないが保存済みアドレスで届くノードがある(OTBR 越しの Thread
                    // デバイス、mDNS が別インタフェースに出る多ホーム PC 等)。保存済みアドレスへ
                    // 1 回だけ CASE を試す(再解決なし、最長 5 秒)。
                    wlog!(
                        Level::Info,
                        "node {node_id:#x}: mDNS probe failed ({e}); trying the stored address"
                    );
                    self.exec.set_cached_only(true);
                    let r = self.connect_full(node_id, false);
                    self.exec.set_cached_only(false);
                    match r {
                        Ok(_) => wlog!(Level::Info, "node {node_id:#x} connected (stored address)"),
                        Err(e2) => {
                            self.shared.with_node(node_id, |n| {
                                n.state = NodeState::Offline;
                                n.error = Some(e.clone());
                            });
                            wlog!(
                                Level::Info,
                                "node {node_id:#x}: not reachable ({})",
                                e2.message
                            );
                            self.schedule_retry(node_id);
                        }
                    }
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

/// コミッショニングのフェーズ → 進捗イベントの `(phase, detail)`。
fn phase_info(p: Phase) -> Option<(&'static str, String)> {
    let (phase, detail) = match p {
        Phase::Idle => return None,
        Phase::Pase => ("pase", "PASE handshake".to_string()),
        Phase::ArmFailSafe => ("arm_fail_safe", "ArmFailSafe".to_string()),
        Phase::Attestation => ("attestation", "device attestation".to_string()),
        Phase::Csr => ("csr", "CSRRequest".to_string()),
        Phase::AddTrustedRoot => ("add_trusted_root", "AddTrustedRootCertificate".to_string()),
        Phase::AddNoc => ("add_noc", "AddNOC".to_string()),
        Phase::AddWifiNetwork => ("add_network", "AddOrUpdate network credentials".to_string()),
        Phase::ConnectNetwork => ("connect_network", "ConnectNetwork".to_string()),
        Phase::Case => ("case", "CASE handshake".to_string()),
        Phase::Complete => (
            "commissioning_complete",
            "CommissioningComplete".to_string(),
        ),
        Phase::Done { .. } => (
            "commissioned",
            "operational CASE session established".to_string(),
        ),
        Phase::Failed { stage, reason } => (
            "commission_failed",
            format!("failed at stage {stage}: {reason:?}"),
        ),
    };
    Some((phase, detail))
}

/// AdministratorCommissioning のクラスタ固有ステータスの説明。
fn admin_cluster_status(cs: Option<u8>) -> String {
    match cs {
        None => String::new(),
        Some(2) => " (Busy: a commissioning window is already open)".into(),
        Some(3) => " (PAKEParameterError)".into(),
        Some(4) => " (WindowNotOpen: no commissioning window is open)".into(),
        Some(c) => format!(" (cluster status {c:#04x})"),
    }
}

/// 窓オープン結果の JSON(`POST /api/nodes/{id}/window` の応答形)。
pub fn window_json(node_id: u64, w: &smctl::ops::embed::WindowInfo, now: u64) -> Value {
    json!({
        "node_id": node_id,
        "manual_code": w.manual_code,
        "qr_payload": w.qr_payload,
        "discriminator": w.discriminator,
        "passcode": w.passcode,
        "passcode_str": format!("{:08}", w.passcode),
        "timeout_s": w.timeout_s,
        "opened_at": now,
        "expires_at": now + w.timeout_s as u64,
        "vendor_id": w.vendor_id,
        "product_id": w.product_id,
    })
}

/// Read 結果から符号なし整数属性を取り出す(`None` = 報告なし、`Some(None)` = null / 非整数)。
fn item_uint(items: &[ReadItem], cluster: u32, attr: u32) -> Option<Option<u64>> {
    use smctl::simple_matter::tlv::{TlvReader, TlvValue};
    let it = items
        .iter()
        .find(|i| i.cluster == Some(cluster) && i.attribute == Some(attr))?;
    let ReadOutcome::Data(raw) = &it.outcome else {
        return Some(None);
    };
    let mut r = TlvReader::new(raw);
    Some(match r.read_next() {
        Ok(Some(e)) => match e.value {
            TlvValue::UnsignedInteger(v) => Some(v),
            _ => None,
        },
        _ => None,
    })
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
    fn window_response_shape() {
        let w = smctl::ops::embed::WindowInfo {
            timeout_s: 300,
            discriminator: 3840,
            passcode: 1234567,
            manual_code: "12345678901".into(),
            qr_payload: "MT:ABC".into(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };
        let v = window_json(33, &w, 1_000);
        for k in [
            "manual_code",
            "qr_payload",
            "discriminator",
            "passcode",
            "expires_at",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
        assert_eq!(v["expires_at"], 1_300);
        assert_eq!(v["passcode"], 1234567);
        assert_eq!(v["passcode_str"], "01234567");
        assert_eq!(v["discriminator"], 3840);
        assert_eq!(v["node_id"], 33);
    }

    #[test]
    fn uint_items_and_phase_names() {
        let mut buf = [0u8; 8];
        let mut w = TlvWriter::new(&mut buf);
        w.write_u8(&TlvTag::ContextSpecific(2), 1).unwrap();
        let raw = w.written().to_vec();
        let items = vec![ReadItem {
            endpoint: Some(0),
            cluster: Some(0x3C),
            attribute: Some(0),
            list_append: false,
            data_version: None,
            outcome: ReadOutcome::Data(raw),
        }];
        assert_eq!(item_uint(&items, 0x3C, 0), Some(Some(1)));
        assert_eq!(item_uint(&items, 0x3C, 1), None);
        assert_eq!(phase_info(Phase::Idle), None);
        assert_eq!(phase_info(Phase::Pase).unwrap().0, "pase");
        assert!(admin_cluster_status(Some(2)).contains("already open"));
        assert_eq!(admin_cluster_status(None), "");
    }

    #[test]
    fn scope_stripping() {
        let a: SocketAddr = "[fe80::1%3]:5540".parse().unwrap();
        assert_eq!(strip_scope(a).to_string(), "[fe80::1]:5540");
        let b: SocketAddr = "192.168.8.163:5540".parse().unwrap();
        assert_eq!(strip_scope(b), b);
    }
}
