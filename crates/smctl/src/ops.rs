//! 高レベル操作(設計 doc §3): resolve → connect → execute の 3 段に正規化する。
//!
//! C2 で実行モデルを「1 プロセス 1 コマンド」から [`Exec`](単一プロセス内でスタック・
//! ソケット・CASE セッション・購読を共有する実行コンテキスト)へ一般化した。
//!
//! - 単発コマンド([`run_single`]): Exec を作って 1 コマンド実行して捨てる(C1 と同じ挙動)。
//! - バッチ([`crate::batch`]): 1 つの Exec で全行を順に実行する。ノードごとの CASE
//!   セッションはキャッシュされ、`subscribe` は非ブロッキングに購読を張り、以後の行の
//!   実行中もデバイス発レポートを逐次表示する(chip-tool の「別プロセス実行で購読が
//!   破棄される」問題の同一セッション化による解消)。

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use simple_matter::controller::ca::Ca;
use simple_matter::controller::{AttestationPolicy, Commissioner, Phase, CONTROLLER_FABRIC_INDEX};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::error::Result as MResult;
use simple_matter::im::client::ImClient;
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::im::ImEvent;
use simple_matter::sc::initiator::ScEvent;
use simple_matter::tlv::{ContainerType, TlvElement, TlvReader, TlvTag, TlvValue, TlvWriter};
use simple_matter::transport::net::{PeerAddr, MAX_RX_PACKET_SIZE};
use simple_matter::transport::session::SessionId;

use crate::cli::{Cmd, Globals};
use crate::clusters::{self, ValueKind};
use crate::json::{self, info, Obj};
use crate::runner::udp::{open_dual_stack_udp, pump_commissioner, send_dir};
use crate::runner::{mdns, Backend, Ctrl};
use crate::state::{ca as ca_state, nodes, resume, StateDir};
use crate::OsRng;

/// mDNS ブラウズの最低タイムアウト。デバイスの再 announce 間隔(既定 30 秒)より長く取る。
const BROWSE_TIMEOUT_MIN: Duration = Duration::from_secs(35);
/// operational mDNS 解決のタイムアウト。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(20);
/// CASE 再解決フォールバックで last_addr ホストへ QU 直叩きする短めの窓
/// (失敗したらマルチキャスト再解決へ。matter-over-vpn V1)。
const RERESOLVE_AT_TIMEOUT: Duration = Duration::from_secs(6);
/// キャッシュアドレスへの CASE 試行の窓(失敗したら mDNS 再解決へフォールバック)。
const CACHED_CASE_TIMEOUT: Duration = Duration::from_secs(5);
/// コマンド完了後に ACK を流し切るための静穏化の上限。
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
/// 「静穏」とみなす期限の遠さ(ミリ秒)。
///
/// 購読確立後は keep-alive 途絶検出のため [`Ctrl::next_deadline`] が常に `Some`
/// (maxInterval + 5 秒猶予 ≧ 5 秒先)を返すので、`None` を静穏条件にできない。
/// MRP の再送/ACK 期限は近傍(数百 ms)に来るため、「残る期限がこれより遠い」を
/// もって送受信が静穏化したとみなす。
const QUIET_HORIZON_MS: u64 = 1500;

/// `pairing` の対象指定。
#[derive(Clone)]
pub enum Target {
    /// mDNS ブラウズ(discriminator で絞り込み可)。
    Browse(Option<u16>),
    /// アドレス直指定。
    Addr(SocketAddr),
}

/// 単発コマンドの実行(1 プロセス 1 コマンド、C1 と同じモデル)。
pub fn run_single(g: &Globals, cmd: Cmd) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let crypto = simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    // pairing は CA が無ければ生成する。運用コマンドは既存 CA を要求する。
    let ca = {
        let _lock = state.lock()?;
        match cmd {
            Cmd::Pair { .. } => ca_state::load_or_create(&state.ca_path(), &crypto)?,
            _ => ca_state::load(&state.ca_path(), &crypto)?
                .ok_or("no CA state; commission a device first (`smctl pairing ...`)")?,
        }
    };
    let mut exec = Exec::new(g.clone(), state, &crypto, &ca, false)?;
    exec.run(&cmd)
}

/// `pairing list`: アドレス帳の一覧表示。
pub fn pairing_list(g: &Globals) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let entries = {
        let _lock = state.lock()?;
        nodes::load(&state.nodes_path())?
    };
    if entries.is_empty() {
        info!("(no paired nodes; run `smctl pairing onnetwork <node-id> <passcode>`)");
        return Ok(());
    }
    info!("{:<12} {:<24} label", "node-id", "last-addr");
    for e in entries {
        let addr = if e.last_addr.port() == 0 {
            "(unresolved)".to_string()
        } else {
            e.last_addr.to_string()
        };
        if json::enabled() {
            let mut o = Obj::new("node").num("nodeId", e.node_id);
            if e.last_addr.port() != 0 {
                o = o.str("addr", &e.last_addr.to_string());
            }
            o.str("label", &e.label).emit();
        } else {
            println!("{:<12} {:<24} {}", e.node_id, addr, e.label);
        }
    }
    Ok(())
}

/// `discover commissionable`: ブラウズ期間中に見つかった commissionable ノードを一覧表示。
pub fn discover_commissionable(g: &Globals, discriminator: Option<u16>) -> Result<(), String> {
    let n = match &g.at {
        Some(targets) => mdns::browse_commissionable_list_at(discriminator, targets, g.timeout)?,
        None => mdns::browse_commissionable_list(discriminator, g.timeout)?,
    };
    if n == 0 {
        return Err("no commissionable device found (is the device in commissioning mode?)".into());
    }
    info!("[discover] {n} commissionable node(s) found");
    Ok(())
}

/// `discover operational <node-id>`: 保存済み CA の fabric で運用アドレスを解決して表示。
pub fn discover_operational(g: &Globals, node_id: u64) -> Result<(), String> {
    let state = StateDir::open(&g.state_dir)?;
    let crypto = simple_matter::crypto::rustcrypto::RustCrypto::new(OsRng);
    let ca = {
        let _lock = state.lock()?;
        ca_state::load(&state.ca_path(), &crypto)?
            .ok_or("no CA state; commission a device first (`smctl pairing ...`)")?
    };
    let addr = match &g.at {
        Some(targets) => {
            mdns::resolve_operational_at(&ca, node_id, targets, g.timeout.min(RESOLVE_TIMEOUT))?
        }
        None => mdns::resolve_operational(&ca, node_id, g.timeout.min(RESOLVE_TIMEOUT))?,
    };
    if json::enabled() {
        Obj::new("operational")
            .num("nodeId", node_id)
            .str("addr", &addr.to_string())
            .emit();
    } else {
        println!("[discover] operational node {node_id:#x} at {addr}");
    }
    Ok(())
}

// ==========================================================================
// Exec: 単一プロセス内でスタック / CASE セッション / 購読を共有する実行コンテキスト
// ==========================================================================

/// CASE 試行の失敗理由。
enum CaseAttempt {
    /// 期限内に決着しなかった(ハンドシェイク slot は使用中のまま)。
    Timeout,
    /// 明示的な失敗(開始拒否・SC エラーイベント・IO エラー)。
    Failed(String),
}

impl CaseAttempt {
    fn into_message(self, addr: SocketAddr) -> String {
        match self {
            CaseAttempt::Timeout => format!("CASE to {addr} timed out"),
            CaseAttempt::Failed(e) => e,
        }
    }
}

/// 確立済み購読の記録(バッチ終了時の要約用)。
struct SubStat {
    id: u32,
    node: u64,
    reports: u64,
    lost: bool,
}

/// 実行コンテキスト。
///
/// バッチでは 1 個の `Exec` が全行を実行する。CASE セッションは `(node_id, SessionId)`
/// でキャッシュされ、購読レポートはどの操作の待ち時間中でも逐次表示される。
pub struct Exec<'a> {
    /// 有効な共通オプション(バッチでは行ごとの `--timeout`/`--label` 上書きを反映)。
    g: Globals,
    state: StateDir,
    crypto: &'a Backend,
    ca: &'a Ca<Backend>,
    stack: Ctrl<'a>,
    socket: UdpSocket,
    start: Instant,
    rx: [u8; MAX_RX_PACKET_SIZE],
    tx: [u8; MAX_RX_PACKET_SIZE],
    /// ノードごとの確立済み CASE セッション。
    cases: Vec<(u64, SessionId)>,
    /// 確立済み購読(要約用)。
    subs: Vec<SubStat>,
    /// バッチモードか(`subscribe` の非ブロッキング化)。
    batch: bool,
    /// `--paa-trust-store-path` 由来の PAA 信頼ストア(X.509 DER)。空なら attestation は
    /// スキップ、非空なら `AttestationPolicy::Verify` で pairing する。
    paa_store: Vec<Vec<u8>>,
}

impl<'a> Exec<'a> {
    /// スタックとソケットを確保する。
    pub fn new(
        g: Globals,
        state: StateDir,
        crypto: &'a Backend,
        ca: &'a Ca<Backend>,
        batch: bool,
    ) -> Result<Self, String> {
        let socket = open_dual_stack_udp().map_err(|e| format!("bind controller socket: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| format!("set_read_timeout: {e}"))?;
        let ctrl_creds = simple_matter::controller::ControllerCreds::new(ca, crypto, 0);
        let sc_init = simple_matter::sc::initiator::ScInitiator::new(crypto, OsRng, ctrl_creds);
        let stack: Ctrl<'a> =
            simple_matter::controller::ControllerStack::new(crypto, sc_init, ImClient::new());
        let paa_store = match &g.paa_trust_store_path {
            Some(dir) => load_paa_store(dir)?,
            None => Vec::new(),
        };
        Ok(Self {
            g,
            state,
            crypto,
            ca,
            stack,
            socket,
            start: Instant::now(),
            rx: [0u8; MAX_RX_PACKET_SIZE],
            tx: [0u8; MAX_RX_PACKET_SIZE],
            cases: Vec::new(),
            subs: Vec::new(),
            batch,
            paa_store,
        })
    }

    /// バッチの行ごとの共通オプション(`--timeout`/`--label`/`--json` 上書き)を反映する。
    pub fn set_globals_for_line(&mut self, g: Globals) {
        crate::json::set_mode(g.json);
        self.g = g;
    }

    /// 1 コマンドを実行する(単発・バッチ共通のディスパッチ)。
    pub fn run(&mut self, cmd: &Cmd) -> Result<(), String> {
        match cmd {
            Cmd::Pair {
                node,
                passcode,
                target,
            } => self.pair(*node, *passcode, target),
            Cmd::Read {
                node,
                ep,
                cluster,
                attr,
            } => self.read(*node, *ep, *cluster, *attr),
            Cmd::Write {
                node,
                ep,
                cluster,
                attr,
                kind,
                value,
            } => self.write(*node, *ep, *cluster, *attr, *kind, value.clone()),
            Cmd::Invoke {
                node,
                ep,
                cluster,
                command,
                fields,
                raw_fields,
            } => self.invoke(
                *node,
                *ep,
                *cluster,
                *command,
                fields.clone(),
                raw_fields.clone(),
                self.g.timed_ms,
            ),
            Cmd::AdminOpenWindow {
                node,
                timeout_s,
                discriminator,
                passcode,
            } => self.admin_open_window(*node, *timeout_s, *discriminator, *passcode),
            Cmd::AdminRevoke { node } => self.admin_revoke(*node),
            Cmd::Subscribe {
                node,
                ep,
                cluster,
                attr,
                min_s,
                max_s,
            } => self.subscribe(*node, *ep, *cluster, *attr, *min_s, *max_s),
            Cmd::Wait { secs } => self.wait(*secs),
            // 以下はコンテキスト非依存(バッチ内でも独立に動く)。
            Cmd::PairingList => pairing_list(&self.g),
            Cmd::DiscoverCommissionable { discriminator } => {
                discover_commissionable(&self.g, *discriminator)
            }
            Cmd::DiscoverOperational { node } => discover_operational(&self.g, *node),
            Cmd::Help => {
                crate::cli::print_help();
                Ok(())
            }
            Cmd::PairBle { .. } => Err("pairing ble/ble-handoff cannot run inside a batch \
                 (run it as a standalone command first)"
                .into()),
            Cmd::Batch { .. } => Err("nested batch is not supported".into()),
        }
    }

    /// バッチ終了時の要約(購読ごとの受信レポート数)。
    pub fn summarize(&self) {
        if self.subs.is_empty() {
            return;
        }
        info!(
            "[summary] shutting down {} subscription(s):",
            self.subs.len()
        );
        for s in &self.subs {
            info!(
                "  sub={} node={} reports-received={}{}",
                s.id,
                s.node,
                s.reports,
                if s.lost { " (LOST)" } else { "" }
            );
        }
    }

    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    // ----------------------------------------------------------------------
    // イベントポンプ(購読レポートの逐次表示込み)
    // ----------------------------------------------------------------------

    /// 受信 1 回(最長 50ms)+ poll 排出。
    fn step_io(&mut self) -> Result<(), String> {
        match self.socket.recv_from(&mut self.rx) {
            Ok((n, src)) => {
                let now = self.now_ms();
                if let Some(dir) =
                    self.stack
                        .handle_rx(&mut self.rx[..n], PeerAddr::Udp(src), now, &mut self.tx)
                {
                    send_dir(&self.socket, &self.tx, &dir);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv: {e}")),
        }
        let now = self.now_ms();
        while let Some(dir) = self.stack.poll(now, &mut self.tx) {
            send_dir(&self.socket, &self.tx, &dir);
        }
        Ok(())
    }

    /// 購読系イベントを処理する(レポート表示 + 要約カウント)。
    fn on_sub_event(&mut self, ev: ImEvent) {
        match ev {
            ImEvent::SubscriptionReport { subscription_id } => {
                let ts = self.start.elapsed().as_secs();
                print_reports(
                    self.stack.sub_reports(),
                    &format!("[report +{ts}s sub={subscription_id}] "),
                    "report",
                    Some(subscription_id),
                );
                if let Some(s) = self.subs.iter_mut().find(|s| s.id == subscription_id) {
                    s.reports += 1;
                }
            }
            ImEvent::SubscriptionLost { subscription_id } => {
                if json::enabled() {
                    Obj::new("subscription-lost")
                        .num("subscriptionId", subscription_id)
                        .emit();
                }
                eprintln!(
                    "[subscribe] subscription {subscription_id} LOST \
                     (no report within max interval + grace)"
                );
                if let Some(s) = self.subs.iter_mut().find(|s| s.id == subscription_id) {
                    s.lost = true;
                }
            }
            other => eprintln!("[warn] unexpected IM event: {other:?}"),
        }
    }

    /// 溜まっている IM イベントを購読系として排出する(トランザクション待ちの外で使う)。
    fn drain_events(&mut self) {
        while let Some(ev) = self.stack.im_take_event() {
            self.on_sub_event(ev);
        }
    }

    /// トランザクション系 IM イベントを 1 件待つ。購読レポートは表示して待ち続ける。
    fn wait_txn_event(&mut self, until: Instant) -> Result<Option<ImEvent>, String> {
        loop {
            while let Some(ev) = self.stack.im_take_event() {
                match ev {
                    ImEvent::SubscriptionReport { .. } | ImEvent::SubscriptionLost { .. } => {
                        self.on_sub_event(ev)
                    }
                    other => return Ok(Some(other)),
                }
            }
            if Instant::now() > until {
                return Ok(None);
            }
            self.step_io()?;
        }
    }

    /// SC(CASE/PASE)イベントを 1 件待つ。待機中も購読レポートは流し続ける。
    fn wait_sc_event(&mut self, until: Instant) -> Result<Option<ScEvent>, String> {
        loop {
            if let Some(ev) = self.stack.sc_take_event() {
                return Ok(Some(ev));
            }
            self.drain_events();
            if Instant::now() > until {
                return Ok(None);
            }
            self.step_io()?;
        }
    }

    /// MRP 再送・standalone ACK を流し切って静穏化する。
    ///
    /// 購読確立後は `next_deadline` が keep-alive 途絶検出のため常に `Some` なので、
    /// 「残る期限が [`QUIET_HORIZON_MS`] より遠い」を静穏条件にする(examples の
    /// `settle` の購読対応版)。
    fn quiesce(&mut self, until: Instant) -> Result<(), String> {
        loop {
            self.step_io()?;
            // ここでは IM イベントを取り出さない: pairing 中は InvokeDone 等が
            // Commissioner の駆動材料であり、横取りするとフェーズ機械が止まる。
            // 購読イベントは専用 slot(最新 1 件)に留まり、次の wait/操作で排出される。
            let now = self.now_ms();
            let quiet = match self.stack.next_deadline(now) {
                None => true,
                Some(t) => {
                    self.stack.subscription_count() > 0 && t.saturating_sub(now) > QUIET_HORIZON_MS
                }
            };
            if quiet {
                return Ok(());
            }
            if Instant::now() > until {
                return Err("settle timed out (device unresponsive)".into());
            }
        }
    }

    /// コマンド完了後の ACK 流し切り(best effort)。
    fn flush(&mut self) {
        let _ = self.quiesce(Instant::now() + FLUSH_TIMEOUT);
    }

    // ----------------------------------------------------------------------
    // pairing(UDP)
    // ----------------------------------------------------------------------

    /// コミッショニング(pairing onnetwork / onnetwork-long / address)。
    ///
    /// 成功時に CA 状態(発行済み serial)を保存し、アドレス帳に記帳する。確立した
    /// 運用 CASE セッションはキャッシュされ、同一バッチ内の後続コマンドが再利用する。
    fn pair(&mut self, node_id: u64, passcode: u32, target: &Target) -> Result<(), String> {
        let peer_addr = match target {
            Target::Addr(a) => {
                // fe80 リテラルは scope_id 補完(mdns-ipv6.md §3 の規則)。
                let a = mdns::fill_link_local_scope(*a);
                info!("[target] using explicit address {a}");
                a
            }
            Target::Browse(disc) => match &self.g.at {
                Some(targets) => {
                    info!("[discovery] resolving commissionable via unicast mDNS (--at)...");
                    mdns::browse_commissionable_at(
                        *disc,
                        targets,
                        self.g.timeout.max(BROWSE_TIMEOUT_MIN),
                    )?
                }
                None => {
                    info!("[discovery] browsing _matterc._udp.local via mDNS...");
                    mdns::browse_commissionable(*disc, self.g.timeout.max(BROWSE_TIMEOUT_MIN))?
                }
            },
        };
        info!(
            "[ca] fabric_id={:#018x} controller_node_id={:#018x}",
            self.ca.fabric_id(),
            self.ca.controller_node_id()
        );

        // PAA 信頼ストアが空なら Skip、非空なら Verify(§3/§4)。ローカルへ複製してから
        // slice 群を作る(`comm` が `self` を借用したまま `self.quiesce` へ入るのを避ける)。
        let paa_owned: Vec<Vec<u8>> = self.paa_store.clone();
        let paa_slices: Vec<&[u8]> = paa_owned.iter().map(Vec::as_slice).collect();
        let policy = if paa_slices.is_empty() {
            info!("[attestation] skipped (no --paa-trust-store-path)");
            AttestationPolicy::Skip
        } else {
            info!(
                "[attestation] verifying DAC chain against {} PAA cert(s)",
                paa_slices.len()
            );
            AttestationPolicy::Verify {
                paa_store: &paa_slices,
            }
        };
        let mut comm = Commissioner::new(self.ca, self.crypto, policy);
        let deadline = Instant::now() + self.g.timeout;
        let mut last_phase = Phase::Idle;

        comm.commission(PeerAddr::Udp(peer_addr), passcode, node_id, self.now_ms())
            .map_err(|e| format!("commission() rejected: {e:?}"))?;
        info!("[commission] starting to {peer_addr} (device node_id={node_id:#x})");

        let case_session: SessionId = loop {
            if Instant::now() > deadline {
                return Err(format!("commissioning timed out in phase {last_phase:?}"));
            }
            let now = self.now_ms();
            let phase =
                pump_commissioner(&mut comm, &mut self.stack, &self.socket, now, &mut self.tx);
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
            self.quiesce(deadline)?;
        };
        info!(
            "[commission] COMPLETE. operational CASE session = {:#x}",
            case_session.as_raw()
        );
        self.flush();

        // 発行済み serial を CA 状態に反映し、アドレス帳へ記帳する。
        {
            let _lock = self.state.lock()?;
            ca_state::save(&self.state.ca_path(), self.ca)?;
            nodes::upsert(
                &self.state.nodes_path(),
                nodes::NodeEntry {
                    node_id,
                    label: self.g.label.clone().unwrap_or_default(),
                    last_addr: peer_addr,
                },
            )?;
        }
        info!(
            "[pairing] node {node_id} recorded at {peer_addr} (state: {})",
            self.g.state_dir.display()
        );
        self.cases.retain(|(n, _)| *n != node_id);
        self.cases.push((node_id, case_session));
        Ok(())
    }

    // ----------------------------------------------------------------------
    // CASE セッションの取得(キャッシュ → キャッシュアドレス → mDNS 再解決)
    // ----------------------------------------------------------------------

    /// ノードへの CASE セッションを返す(プロセス内キャッシュ優先)。
    fn case_session(&mut self, node_id: u64) -> Result<SessionId, String> {
        if let Some(&(_, s)) = self.cases.iter().find(|(n, _)| *n == node_id) {
            return Ok(s);
        }
        let entry = {
            let _lock = self.state.lock()?;
            nodes::load(&self.state.nodes_path())?
                .into_iter()
                .find(|e| e.node_id == node_id)
                .ok_or_else(|| {
                    format!("node {node_id} not in address book (`smctl pairing list`)")
                })?
        };

        // 0) 永続化済みの resumption 素材があれば取り込む(C4、設計 doc §4.3)。
        //    以後の start_case は Sigma1 に resumptionID + resumeMIC(ctx6/7)を付け、
        //    responder が受理すれば Sigma2_Resume で確立する。不成立(responder が
        //    素材を失っている等)はコアがフル CASE へフォールバックする。
        if self
            .stack
            .resumption_export(CONTROLLER_FABRIC_INDEX, node_id)
            .is_none()
        {
            if let Some(m) = resume::load(&self.state.resume_path(node_id)) {
                self.stack.resumption_import(
                    CONTROLLER_FABRIC_INDEX,
                    node_id,
                    &m.resumption_id,
                    &m.shared_secret,
                );
                info!("[case] resumption material loaded; will attempt session resumption");
            }
        }

        // 1) キャッシュアドレスへ CASE を試みる(未解決 sentinel はスキップ)。
        //    nodes.tlv は scope を保存しないため、fe80 には scope_id を補完しておく
        //    (resolve 経路と宛先比較を揃える。design §3)。
        let cached = mdns::fill_link_local_scope(entry.last_addr);
        let deadline = Instant::now() + self.g.timeout;
        let mut got: Option<(SessionId, SocketAddr)> = None;
        let mut pending_to: Option<SocketAddr> = None; // 送出済みで未決着の Sigma1 の宛先
        if cached.port() != 0 {
            match self.try_case(cached, node_id, CACHED_CASE_TIMEOUT.min(self.g.timeout)) {
                Ok(s) => got = Some((s, cached)),
                Err(CaseAttempt::Timeout) => {
                    // ハンドシェイク slot は使用中のまま(コアの HANDSHAKE_TIMEOUT は 60 秒)。
                    pending_to = Some(cached);
                    eprintln!(
                        "[case] cached address {cached} not responding; re-resolving via mDNS"
                    );
                }
                Err(CaseAttempt::Failed(e)) => {
                    eprintln!("[case] cached address {cached} failed ({e}); re-resolving via mDNS")
                }
            }
        }
        // 2) mDNS で運用アドレスを再解決して張り直す。
        let (session, used_addr) = match got {
            Some(x) => x,
            None => {
                let resolved = self.reresolve_operational(node_id, &entry)?;
                eprintln!("[case] operational node resolved at {resolved}");
                let s = if pending_to == Some(resolved) {
                    // アドレスは正しかった(デバイスが一時的に無応答なだけ)。新規
                    // ハンドシェイクは張れない(slot 使用中)ので、進行中の Sigma1 の
                    // MRP 再送に賭けて同じハンドシェイクを待ち続ける。
                    eprintln!("[case] address unchanged; keep waiting on the in-flight handshake");
                    self.await_case(resolved, deadline)
                        .map_err(|e| e.into_message(resolved))?
                } else {
                    if pending_to.is_some() {
                        // 別アドレスへ張り直したいが slot が塞がっている。前のハンドシェイクの
                        // 失敗確定(タイムアウト掃除)を待ってから開始する。
                        eprintln!(
                            "[case] waiting for the previous handshake attempt to be reaped..."
                        );
                        let _ = self.await_case(cached, deadline);
                    }
                    self.try_case(
                        resolved,
                        node_id,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .map_err(|e| e.into_message(resolved))?
                };
                (s, resolved)
            }
        };
        self.quiesce(Instant::now() + self.g.timeout)?;

        {
            let _lock = self.state.lock()?;
            if used_addr != cached {
                nodes::update_addr(&self.state.nodes_path(), node_id, used_addr)?;
            }
            // 確立で resumptionID はローテートするので、成立経路(フル/レジューム)に
            // かかわらず現行素材を書き出す。次回接続はこの素材で resumption を試みる。
            if let Some((rid, secret)) = self
                .stack
                .resumption_export(CONTROLLER_FABRIC_INDEX, node_id)
            {
                resume::save(
                    &self.state.resume_path(node_id),
                    &resume::ResumeMaterial {
                        resumption_id: rid,
                        shared_secret: secret,
                    },
                )?;
                info!("[case] resumption material saved for node {node_id}");
            }
        }
        self.cases.push((node_id, session));
        Ok(session)
    }

    /// CASE 再解決(キャッシュアドレスへの CASE 失敗後)。
    ///
    /// - `--at` 指定時: 指定ホスト群へ QU 直叩きで解決する(VPN 経路、matter-over-vpn V1)。
    /// - 未指定時: まず nodes.tlv の `last_addr` ホストへ QU ユニキャスト直叩きを試み
    ///   (マルチキャストが死んでいる VPN 環境でも last_addr が生きていれば当たる)、
    ///   失敗したら通常のマルチキャスト再解決へフォールバックする(design 案 C1/D)。
    fn reresolve_operational(
        &mut self,
        node_id: u64,
        entry: &nodes::NodeEntry,
    ) -> Result<SocketAddr, String> {
        if let Some(targets) = &self.g.at {
            return mdns::resolve_operational_at(self.ca, node_id, targets, RESOLVE_TIMEOUT);
        }
        // last_addr ホストへの QU 直叩き(短めの窓)を先に試す。
        if entry.last_addr.port() != 0 {
            let ip = entry.last_addr.ip();
            eprintln!("[case] trying unicast mDNS re-resolution to cached host {ip}");
            if let Ok(addr) =
                mdns::resolve_operational_at(self.ca, node_id, &[ip], RERESOLVE_AT_TIMEOUT)
            {
                return Ok(addr);
            }
            eprintln!("[case] unicast re-resolution failed; falling back to multicast mDNS");
        }
        mdns::resolve_operational(self.ca, node_id, RESOLVE_TIMEOUT)
    }

    /// 1 回の CASE 試行(Sigma1 送出 + 決着待ち)。
    ///
    /// タイムアウトした場合、ハンドシェイク slot は使用中のまま残る(コアの
    /// `HANDSHAKE_TIMEOUT_MS` = 60 秒の掃除待ち)ことに注意。呼び出し側は
    /// [`CaseAttempt::Timeout`] を見て「同じハンドシェイクを待ち続ける」か
    /// 「掃除を待ってから張り直す」かを選ぶ。
    fn try_case(
        &mut self,
        addr: SocketAddr,
        node_id: u64,
        timeout: Duration,
    ) -> Result<SessionId, CaseAttempt> {
        // fe80 リンクローカル(nodes.tlv は scope を保存しない・再解決分は解決時に付与済み)
        // へは scope_id を補完してから接続する(design §3)。
        let addr = mdns::fill_link_local_scope(addr);
        let now = self.now_ms();
        let dir = self
            .stack
            .start_case(
                PeerAddr::Udp(addr),
                CONTROLLER_FABRIC_INDEX,
                node_id,
                now,
                &mut self.tx,
            )
            .map_err(|e| CaseAttempt::Failed(format!("start_case: {e:?}")))?;
        send_dir(&self.socket, &self.tx, &dir);
        self.await_case(addr, Instant::now() + timeout)
    }

    /// 送出済みハンドシェイクの決着(確立 / 失敗 / 期限)を待つ。
    fn await_case(&mut self, addr: SocketAddr, until: Instant) -> Result<SessionId, CaseAttempt> {
        match self.wait_sc_event(until).map_err(CaseAttempt::Failed)? {
            Some(ScEvent::CaseEstablished { session, resumed }) => {
                eprintln!(
                    "[case] ESTABLISHED to {addr} (session={:#x}{})",
                    session.as_raw(),
                    if resumed { ", resumed" } else { "" }
                );
                Ok(session)
            }
            Some(ev) => Err(CaseAttempt::Failed(format!("CASE failed: {ev:?}"))),
            None => Err(CaseAttempt::Timeout),
        }
    }

    /// 操作タイムアウト時にノードのセッションキャッシュを無効化して Err を返す。
    fn op_timeout(&mut self, node_id: u64, what: &str) -> Result<(), String> {
        self.cases.retain(|(n, _)| *n != node_id);
        Err(format!(
            "{what} timed out (session invalidated; retry will re-establish CASE)"
        ))
    }

    // ----------------------------------------------------------------------
    // 運用コマンド(read / write / invoke / subscribe / wait)
    // ----------------------------------------------------------------------

    /// 属性 Read(`attr = None` は属性ワイルドカード)。
    fn read(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: Option<AttributeId>,
    ) -> Result<(), String> {
        let session = self.case_session(node_id)?;
        let path = AttributePath {
            endpoint: Some(EndpointId(ep)),
            cluster: Some(cluster),
            attribute: attr,
            list_index: None,
            list_append: false,
            enable_tag_compression: false,
        };
        let now = self.now_ms();
        let dir = self
            .stack
            .start_read(session, &[path], now, &mut self.tx)
            .map_err(|e| format!("start_read: {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::ReadDone) => {}
            Some(ev) => return Err(format!("read failed: {ev:?}")),
            None => return self.op_timeout(node_id, "read"),
        }
        print_reports(self.stack.read_reports(), "", "read", None);
        self.flush();
        Ok(())
    }

    /// 属性 Write。
    fn write(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        kind: ValueKind,
        value: Parsed,
    ) -> Result<(), String> {
        let session = self.case_session(node_id)?;
        let path = AttributePath::concrete(EndpointId(ep), cluster, attr);
        let now = self.now_ms();
        let dir = self
            .stack
            .start_write(
                session,
                &path,
                move |w, t| write_value(w, t, kind, &value),
                now,
                &mut self.tx,
            )
            .map_err(|e| format!("start_write: {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::WriteDone { status }) => {
                if json::enabled() {
                    Obj::new("write")
                        .num("node", node_id)
                        .num("endpoint", ep)
                        .num("cluster", cluster.0)
                        .num("attribute", attr.0)
                        .str("status", &format!("{status:?}"))
                        .num("statusCode", status.to_u8())
                        .emit();
                } else if status.is_success() {
                    println!("[write] {} OK", format_concrete(cluster, Some(attr), ep));
                }
                if !status.is_success() {
                    return Err(format!(
                        "write {} failed: status {status:?}",
                        format_concrete(cluster, Some(attr), ep)
                    ));
                }
            }
            Some(ev) => return Err(format!("write failed: {ev:?}")),
            None => return self.op_timeout(node_id, "write"),
        }
        self.flush();
        Ok(())
    }

    /// コマンド Invoke。`raw_fields` があればコマンドフィールド全体を生 TLV から転写する。
    ///
    /// `timed_ms` があれば timed interaction(TimedRequest → Invoke)として送る
    /// (`docs/design/admin-commissioning.md` §3)。
    #[allow(clippy::too_many_arguments)]
    fn invoke(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        command: CommandId,
        fields: Vec<(u8, ValueKind, Parsed)>,
        raw_fields: Option<Vec<u8>>,
        timed_ms: Option<u16>,
    ) -> Result<(), String> {
        let session = self.case_session(node_id)?;
        let path = CommandPath::new(EndpointId(ep), cluster, command);
        let now = self.now_ms();
        let write_fields = move |w: &mut TlvWriter<'_>, t: &TlvTag| match &raw_fields {
            Some(raw) => transcode_tlv(w, t, raw),
            None => {
                w.start_struct(t)?;
                for (tag, kind, v) in &fields {
                    write_value(w, &TlvTag::ContextSpecific(*tag), *kind, v)?;
                }
                w.end_container()
            }
        };
        let dir = match timed_ms {
            Some(ms) => self
                .stack
                .start_invoke_timed(session, ms, path, write_fields, now, &mut self.tx)
                .map_err(|e| format!("start_invoke_timed: {e:?}"))?,
            None => self
                .stack
                .start_invoke(session, path, write_fields, now, &mut self.tx)
                .map_err(|e| format!("start_invoke: {e:?}"))?,
        };
        send_dir(&self.socket, &self.tx, &dir);
        match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::InvokeDone { status }) => {
                if json::enabled() {
                    Obj::new("invoke")
                        .num("node", node_id)
                        .num("endpoint", ep)
                        .num("cluster", cluster.0)
                        .num("command", command.0)
                        .str("status", &format!("{status:?}"))
                        .num("statusCode", status.to_u8())
                        .emit();
                } else if status.is_success() {
                    println!(
                        "[invoke] {} cmd {:#04x} OK (status = Success)",
                        format_concrete(cluster, None, ep),
                        command.0
                    );
                }
                if !status.is_success() {
                    return Err(format!(
                        "invoke {} cmd {:#04x} failed: status {status:?}",
                        format_concrete(cluster, None, ep),
                        command.0
                    ));
                }
            }
            Some(ev) => return Err(format!("invoke failed: {ev:?}")),
            None => return self.op_timeout(node_id, "invoke"),
        }
        self.flush();
        Ok(())
    }

    /// `admincommissioning open-window`: ECM 窓オープン(設計 §6)。
    ///
    /// passcode(省略時は乱数)から SPAKE2+ verifier (w0 ‖ L) を導出し、
    /// OpenCommissioningWindow(0x003C/0x00)を timed invoke で送る。成功したら
    /// 2 人目のコントローラ向けに passcode / discriminator / manual pairing code を表示する。
    fn admin_open_window(
        &mut self,
        node_id: u64,
        timeout_s: u16,
        discriminator: u16,
        passcode: Option<u32>,
    ) -> Result<(), String> {
        use simple_matter::crypto::spake2p::compute_verifier;
        use simple_matter::crypto::Rng as _;

        let passcode = match passcode {
            Some(p) => {
                if !passcode_is_valid(p) {
                    return Err(format!("invalid setup passcode: {p}"));
                }
                p
            }
            None => random_passcode()?,
        };
        let mut salt = [0u8; 16];
        OsRng
            .fill_bytes(&mut salt)
            .map_err(|e| format!("rng: {e:?}"))?;
        const ITERATIONS: u32 = 1000;
        let v = compute_verifier(passcode, &salt, ITERATIONS)
            .map_err(|e| format!("compute_verifier: {e:?}"))?;
        let mut verifier = Vec::with_capacity(97);
        verifier.extend_from_slice(&v.w0);
        verifier.extend_from_slice(&v.l);

        let fields = vec![
            (0u8, ValueKind::U16, Parsed::Unsigned(timeout_s as u64)),
            (1u8, ValueKind::Bytes, Parsed::Bytes(verifier)),
            (2u8, ValueKind::U16, Parsed::Unsigned(discriminator as u64)),
            (3u8, ValueKind::U32, Parsed::Unsigned(ITERATIONS as u64)),
            (4u8, ValueKind::Bytes, Parsed::Bytes(salt.to_vec())),
        ];
        self.invoke(
            node_id,
            0,
            ClusterId(0x003C),
            CommandId(0x00),
            fields,
            None,
            Some(TIMED_INVOKE_TIMEOUT_MS),
        )?;

        let manual_code = manual_pairing_code(discriminator, passcode);
        if json::enabled() {
            Obj::new("openCommissioningWindow")
                .num("node", node_id)
                .num("timeoutSeconds", timeout_s as u64)
                .num("discriminator", discriminator as u64)
                .num("passcode", passcode as u64)
                .str("manualPairingCode", &manual_code)
                .emit();
        } else {
            println!("[admincommissioning] commissioning window open for {timeout_s}s");
            println!("  passcode:            {passcode:08}");
            println!("  discriminator:       {discriminator}");
            println!("  manual pairing code: {manual_code}");
            println!(
                "  second controller: smctl --state-dir <dir2> pairing onnetwork-long \
                 <node-id> {passcode} {discriminator}"
            );
        }
        Ok(())
    }

    /// `admincommissioning revoke`: RevokeCommissioning(timed invoke)。
    fn admin_revoke(&mut self, node_id: u64) -> Result<(), String> {
        self.invoke(
            node_id,
            0,
            ClusterId(0x003C),
            CommandId(0x02),
            Vec::new(),
            None,
            Some(TIMED_INVOKE_TIMEOUT_MS),
        )
    }

    /// 属性 Subscribe。
    ///
    /// - 単発モード: 常駐(レポートを表示し続け、SubscriptionLost で非 0 終了)。
    /// - バッチモード: プライミング完了で戻る(非ブロッキング)。以後のレポートは
    ///   後続コマンドの待ち時間・`wait` 中に逐次表示される。
    fn subscribe(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: AttributeId,
        min_s: u16,
        max_s: u16,
    ) -> Result<(), String> {
        let session = self.case_session(node_id)?;
        let path = AttributePath::concrete(EndpointId(ep), cluster, attr);
        let now = self.now_ms();
        let dir = self
            .stack
            .start_subscribe(session, &[path], min_s, max_s, now, &mut self.tx)
            .map_err(|e| format!("start_subscribe: {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        info!("[subscribe] SubscribeRequest sent (min={min_s}s max={max_s}s)");

        let (sub_id, neg_max) = match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::SubscribeDone {
                subscription_id,
                max_interval_s,
            }) => (subscription_id, max_interval_s),
            Some(ev) => return Err(format!("subscribe failed: {ev:?}")),
            None => return self.op_timeout(node_id, "subscribe"),
        };
        self.subs.push(SubStat {
            id: sub_id,
            node: node_id,
            reports: 0,
            lost: false,
        });
        if json::enabled() {
            Obj::new("subscribe")
                .num("node", node_id)
                .num("endpoint", ep)
                .num("cluster", cluster.0)
                .num("attribute", attr.0)
                .num("subscriptionId", sub_id)
                .num("maxIntervalS", neg_max)
                .emit();
        }
        info!(
            "[subscribe] ESTABLISHED: subscription_id={sub_id} max_interval={neg_max}s{}",
            if self.batch { "" } else { " (Ctrl-C to stop)" }
        );
        if self.batch {
            return Ok(()); // 非ブロッキング: レポートは以後のポンプで表示される。
        }

        // 常駐モード: レポートを受信し続ける(SubscriptionLost で非 0 終了)。
        loop {
            self.step_io()?;
            self.drain_events();
            if let Some(s) = self.subs.iter().find(|s| s.id == sub_id) {
                if s.lost {
                    return Err(format!(
                        "subscription {sub_id} LOST (no report within max interval + grace)"
                    ));
                }
            }
        }
    }

    /// `wait <sec>`: 指定時間、購読レポートを受信・表示しながら待つ(バッチ組み込み)。
    fn wait(&mut self, secs: f64) -> Result<(), String> {
        info!("[wait] {secs}s (receiving subscription reports)...");
        let until = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < until {
            self.step_io()?;
            self.drain_events();
        }
        Ok(())
    }
}

/// フェーズ遷移を人間可読に表示する。
/// timed invoke の TimedRequest タイムアウト(ミリ秒。chip-tool の既定 10 秒相当)。
const TIMED_INVOKE_TIMEOUT_MS: u16 = 10_000;

/// setup passcode の有効性(§5.1.7: 全 0 / 全同一数字 / 連番等の 12 値と範囲を除外)。
/// `--paa-trust-store-path <dir>` のディレクトリから PAA 証明書(`*.der`)を全部読む(§4)。
///
/// 各ファイルの生バイト列(X.509 DER)を返す。ディレクトリが読めない・`.der` が 1 つも
/// 無い場合はエラー(誤設定を検証スキップに退化させないため)。
fn load_paa_store(dir: &std::path::Path) -> Result<Vec<Vec<u8>>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("--paa-trust-store-path {}: {e}", dir.display()))?;
    let mut store = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("reading {}: {e}", dir.display()))?
            .path();
        if path.extension().and_then(|s| s.to_str()) != Some("der") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        store.push(bytes);
    }
    if store.is_empty() {
        return Err(format!(
            "--paa-trust-store-path {}: no *.der certificates found",
            dir.display()
        ));
    }
    Ok(store)
}

fn passcode_is_valid(p: u32) -> bool {
    const INVALID: [u32; 12] = [
        0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888,
        99999999, 12345678, 87654321,
    ];
    (1..=99_999_998).contains(&p) && !INVALID.contains(&p)
}

/// 有効な setup passcode を乱数生成する。
fn random_passcode() -> Result<u32, String> {
    use simple_matter::crypto::Rng as _;
    let mut b = [0u8; 4];
    for _ in 0..16 {
        OsRng
            .fill_bytes(&mut b)
            .map_err(|e| format!("rng: {e:?}"))?;
        let p = u32::from_le_bytes(b) % 99_999_998 + 1;
        if passcode_is_valid(p) {
            return Ok(p);
        }
    }
    Err("could not generate a valid passcode".into())
}

/// 11 桁 manual pairing code(§5.1.4.1、VID/PID なし・カスタムフローなし)。
///
/// - digit 1: `(VID_PID_present(0) << 2) | (discriminator >> 10)`
/// - digits 2-6: `((discriminator & 0x300) << 6) | (passcode & 0x3FFF)`
/// - digits 7-10: `passcode >> 14`
/// - digit 11: Verhoeff 検査数字
pub(crate) fn manual_pairing_code(discriminator: u16, passcode: u32) -> String {
    let d1 = (discriminator >> 10) as u32; // 上位 2 ビット(VID_PID_present = 0)
    let d2_6 = (((discriminator as u32) & 0x300) << 6) | (passcode & 0x3FFF);
    let d7_10 = passcode >> 14;
    let body = format!("{d1:01}{d2_6:05}{d7_10:04}");
    let check = verhoeff_check_digit(&body);
    format!("{body}{check}")
}

/// Verhoeff 検査数字(manual pairing code の末尾桁)。
fn verhoeff_check_digit(digits: &str) -> u8 {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
    let mut c: u8 = 0;
    for (i, ch) in digits.bytes().rev().enumerate() {
        let digit = ch - b'0';
        c = D[c as usize][P[(i + 1) % 8][digit as usize] as usize];
    }
    INV[c as usize]
}

pub(crate) fn report_phase(phase: Phase) {
    let name = match phase {
        Phase::Idle => "Idle",
        Phase::Pase => "PASE handshake",
        Phase::ArmFailSafe => "ArmFailSafe",
        Phase::Attestation => "Attestation",
        Phase::Csr => "CSRRequest",
        Phase::AddTrustedRoot => "AddTrustedRootCertificate",
        Phase::AddNoc => "AddNOC",
        Phase::AddWifiNetwork => "AddOrUpdateWiFiNetwork",
        Phase::ConnectNetwork => "ConnectNetwork",
        Phase::Case => "CASE handshake",
        Phase::Complete => "CommissioningComplete",
        Phase::Done { .. } => "Done",
        Phase::Failed { .. } => "Failed",
    };
    info!("[phase] {name}");
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
    /// エンコード済み TLV 要素 1 個(`tlv:<hex>`)。トップレベルのタグは書き込み時に
    /// 付け替え、内側は保存する(hex TLV 経路、設計 doc §1.3)。
    RawTlv(Vec<u8>),
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
        ValueKind::Raw => {
            Err("raw-typed values cannot be entered by name; use `any` with `tlv:<hex>`".into())
        }
    }
}

/// `<type>:<value>` 形式の型付きリテラルをパースする(`any` サブコマンド用)。
///
/// 型: `bool` `u8..u64` `i8..i64` `f32` `f64` `str` `hex`(byte string)
/// `tlv`(エンコード済み TLV 要素の hex、Raw)。`null` は型プレフィクス不要。
pub fn parse_typed_literal(s: &str) -> Result<(ValueKind, Parsed), String> {
    if s == "null" {
        return Ok((ValueKind::Raw, Parsed::Null));
    }
    let (ty, val) = s
        .split_once(':')
        .ok_or_else(|| format!("expected <type>:<value> literal (e.g. bool:true), got {s:?}"))?;
    let kind = match ty {
        "bool" => ValueKind::Bool,
        "u8" => ValueKind::U8,
        "u16" => ValueKind::U16,
        "u32" => ValueKind::U32,
        "u64" => ValueKind::U64,
        "i8" => ValueKind::I8,
        "i16" => ValueKind::I16,
        "i32" => ValueKind::I32,
        "i64" => ValueKind::I64,
        "f32" => ValueKind::F32,
        "f64" => ValueKind::F64,
        "str" => ValueKind::Utf8,
        "hex" => ValueKind::Bytes,
        "tlv" => {
            let bytes = parse_hex(val).map_err(|_| format!("invalid tlv hex literal: {val:?}"))?;
            return Ok((ValueKind::Raw, Parsed::RawTlv(bytes)));
        }
        _ => {
            return Err(format!(
                "unknown value type {ty:?} (known: bool u8 u16 u32 u64 i8 i16 i32 i64 \
                 f32 f64 str hex tlv, or `null`)"
            ))
        }
    };
    Ok((kind, parse_literal(kind, val)?))
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
        (ValueKind::Raw, Parsed::RawTlv(b)) => transcode_tlv(w, tag, b),
        _ => Err(simple_matter::Error::InvalidState),
    }
}

/// エンコード済み TLV 要素 1 個を `tag` に付け替えて `w` へ転写する。
///
/// コンテナは再帰転写し、内側のタグは保存する(`TlvWriter` に raw コピー API が
/// 無いためのデコード → 再エンコード。コア無改造の担保)。
fn transcode_tlv(w: &mut TlvWriter, tag: &TlvTag, raw: &[u8]) -> MResult<()> {
    let mut r = TlvReader::new(raw);
    let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
    transcode_element(w, tag, &e, &mut r)
}

fn transcode_element(
    w: &mut TlvWriter,
    tag: &TlvTag,
    e: &TlvElement,
    r: &mut TlvReader,
) -> MResult<()> {
    match e.value {
        TlvValue::Boolean(b) => w.write_bool(tag, b),
        TlvValue::UnsignedInteger(v) => w.write_u64(tag, v),
        TlvValue::SignedInteger(v) => w.write_i64(tag, v),
        TlvValue::Float(v) => w.write_f32(tag, v),
        TlvValue::Double(v) => w.write_f64(tag, v),
        TlvValue::Utf8String(s) => w.write_utf8(tag, s),
        TlvValue::ByteString(b) => w.write_bytes(tag, b),
        TlvValue::Null => w.write_null(tag),
        TlvValue::ContainerStart(t) => {
            w.start_container(tag, t)?;
            loop {
                let c = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
                if matches!(c.value, TlvValue::ContainerEnd) {
                    break;
                }
                let ctag = c.tag;
                transcode_element(w, &ctag, &c, r)?;
            }
            w.end_container()
        }
        TlvValue::ContainerEnd => Err(simple_matter::Error::Decode),
    }
}

// ==========================================================================
// レポート表示(名前テーブルは可読性を足すだけ。無くても生 TLV ダンプで常に成立)
// ==========================================================================

/// クラスタ/属性を名前テーブル付きで整形する(ログ用)。
fn format_concrete(cluster: ClusterId, attr: Option<AttributeId>, ep: u16) -> String {
    let cname = clusters::by_id(cluster)
        .map(|d| d.name.to_string())
        .unwrap_or_else(|| format!("{:#06x}", cluster.0));
    match attr {
        Some(a) => {
            let aname = clusters::by_id(cluster)
                .and_then(|d| d.attr_by_id(a))
                .map(|d| d.name.to_string())
                .unwrap_or_else(|| format!("{:#06x}", a.0));
            format!("ep{ep} {cname}/{aname}")
        }
        None => format!("ep{ep} {cname}"),
    }
}

/// 属性レポート列を 1 行ずつ表示する。
///
/// `--json` では人間可読行の代わりにレポート毎の 1 行 JSON
/// (`event` = `"read"` | `"report"`、購読なら `subscriptionId` 付き)を出す。
fn print_reports<'r, I>(reports: I, prefix: &str, event: &str, sub_id: Option<u32>)
where
    I: Iterator<Item = MResult<AttributeReportRef<'r>>>,
{
    let mut n = 0;
    for report in reports {
        n += 1;
        if json::enabled() {
            let mut o = Obj::new(event);
            if let Some(id) = sub_id {
                o = o.num("subscriptionId", id);
            }
            match report {
                Ok(AttributeReportRef::Data(d)) => {
                    let mut r = d.value();
                    let value = json_next_value(&mut r).unwrap_or_else(|| "null".into());
                    json_path(o, &d.path).raw("value", &value).emit();
                }
                Ok(AttributeReportRef::Status(s)) => {
                    o = json_path(o, &s.path)
                        .str("status", &format!("{:?}", s.status.status))
                        .num("statusCode", s.status.status.to_u8());
                    if let Some(cs) = s.status.cluster_status {
                        o = o.num("clusterStatus", cs);
                    }
                    o.emit();
                }
                Err(e) => o.str("error", &format!("undecodable report: {e:?}")).emit(),
            }
            continue;
        }
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
    if n == 0 && !json::enabled() {
        println!("{prefix}(no attribute reports)");
    }
}

/// 属性パスを JSON オブジェクトのフィールド群として追記する。
///
/// 数値 ID は常に出し、名前(`clusterName`/`attributeName`)はテーブルにあるときだけ
/// 添える(表示同様、テーブルは可読性を足すだけ)。ワイルドカード成分は省略する。
fn json_path(mut o: Obj, path: &AttributePath) -> Obj {
    if let Some(ep) = path.endpoint {
        o = o.num("endpoint", ep.0);
    }
    if let Some(c) = path.cluster {
        o = o.num("cluster", c.0);
        let def = clusters::by_id(c);
        if let Some(def) = def {
            o = o.str("clusterName", def.name);
        }
        if let Some(a) = path.attribute {
            o = o.num("attribute", a.0);
            if let Some(name) = def.and_then(|d| d.attr_by_id(a)).map(|a| a.name) {
                o = o.str("attributeName", name);
            }
        }
    } else if let Some(a) = path.attribute {
        o = o.num("attribute", a.0);
    }
    o
}

/// TLV の次の 1 要素を JSON 値に変換する(コンテナは再帰)。
///
/// 対応: bool/整数/浮動小数(非有限は `null`)/utf8/byte string(`"hex:..."` 文字列)/
/// null。struct は context タグ番号をキーにしたオブジェクト、array/list は配列。
fn json_next_value(r: &mut TlvReader) -> Option<String> {
    let e = r.read_next().ok()??;
    Some(json_element(r, &e))
}

fn json_element(r: &mut TlvReader, e: &TlvElement) -> String {
    match e.value {
        TlvValue::Boolean(b) => b.to_string(),
        TlvValue::UnsignedInteger(v) => v.to_string(),
        TlvValue::SignedInteger(v) => v.to_string(),
        TlvValue::Float(v) if v.is_finite() => v.to_string(),
        TlvValue::Double(v) if v.is_finite() => v.to_string(),
        TlvValue::Float(_) | TlvValue::Double(_) => "null".into(),
        TlvValue::Utf8String(s) => format!("\"{}\"", json::escape(s)),
        TlvValue::ByteString(b) => {
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            format!("\"hex:{hex}\"")
        }
        TlvValue::Null => "null".into(),
        TlvValue::ContainerStart(t) => {
            let object = matches!(t, ContainerType::Structure);
            let mut parts = Vec::new();
            let mut idx = 0u32;
            loop {
                match r.read_next() {
                    Ok(Some(c)) if matches!(c.value, TlvValue::ContainerEnd) => break,
                    Ok(Some(c)) => {
                        let body = json_element(r, &c);
                        if object {
                            // struct のキーは context タグ番号(無タグは通し番号)。
                            let key = match c.tag {
                                TlvTag::ContextSpecific(n) => n.to_string(),
                                _ => idx.to_string(),
                            };
                            parts.push(format!("\"{}\":{body}", json::escape(&key)));
                        } else {
                            parts.push(body);
                        }
                        idx += 1;
                    }
                    _ => break,
                }
            }
            if object {
                format!("{{{}}}", parts.join(","))
            } else {
                format!("[{}]", parts.join(","))
            }
        }
        TlvValue::ContainerEnd => "null".into(),
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

#[cfg(test)]
mod admin_tests {
    use super::*;

    #[test]
    fn manual_pairing_code_matches_chip_tool() {
        // chip-tool の既定テスト値(disc 3840 / passcode 20202021)の manual code。
        assert_eq!(manual_pairing_code(3840, 20202021), "34970112332");
    }

    #[test]
    fn passcode_validity() {
        assert!(passcode_is_valid(20202021));
        assert!(passcode_is_valid(1));
        assert!(passcode_is_valid(99_999_998));
        assert!(!passcode_is_valid(0));
        assert!(!passcode_is_valid(11111111));
        assert!(!passcode_is_valid(12345678));
        assert!(!passcode_is_valid(99_999_999));
    }

    #[test]
    fn random_passcode_is_valid() {
        for _ in 0..32 {
            assert!(passcode_is_valid(random_passcode().unwrap()));
        }
    }
}
