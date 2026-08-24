//! コントローラ(commissioner)側の C ABI シム(F7a、`docs/design/c-ffi-shim.md` §11)。
//!
//! デバイス側スタック([`crate`] ルートの `sm_*`)とは**独立したインスタンス**で、
//! C++/ESP-IDF アプリからコントローラ(Commissioner / ControllerStack / MdnsClient)を
//! 駆動する。コアのコントローラは no_std 実装済み(K1)で、smctl / s3-controller が
//! Rust 側の参照実装。
//!
//! # 設計方針(§11.1)
//!
//! - デバイス側と同じ **out-buffer ポンプ型** の `sm_ctrl_*` API 群。
//! - **メモリは呼び出し側供給**: [`sm_ctrl_init`] に C++ が確保した領域(PSRAM 可)を渡し、
//!   そこへ [`CtrlShim`] を in-place 構築する。必要サイズは [`sm_ctrl_context_size`]、
//!   要求アラインメントは [`sm_ctrl_context_align`]。
//! - CA / ノード帳の永続化は KVS コールバック(`b"cast"` = ca-state v1 /
//!   `b"nods"` = nodes.tlv v1。smctl / s3-controller と持ち運び可)。CASE resumption 素材は
//!   ノードごとに `b"rsm<node16hex>"`(ポートローカル 49B)。
//! - コミッショニング(F7a は UDP のみ): [`sm_ctrl_pair_start`] → pump
//!   ([`sm_ctrl_udp_rx`] / [`sm_ctrl_poll`] / [`sm_ctrl_next_deadline`])→
//!   [`sm_ctrl_take_event`](フェーズ進行 / COMPLETE / FAILED)。attestation は Skip。
//! - 運用操作: [`sm_ctrl_invoke`](引数なしコマンド、OnOff Toggle 用の最小)/
//!   [`sm_ctrl_read_scalar`](スカラ属性)。live セッションが無ければ内部で CASE
//!   (resumption 素材があれば Sigma2Resume)を自動確立してから実行する。
//! - 発見: [`sm_ctrl_resolve_start`](MdnsClient の operational 解決、QU ユニキャスト
//!   直指定 `--at` 相当)+ [`sm_ctrl_mdns_rx`]。
//!
//! # 契約
//!
//! v1 は **単一コントローラインスタンス・単線アクセス**(全 API は同一タスクから呼ぶ)。
//! 供給メモリは [`sm_ctrl_init`] から [`sm_ctrl_deinit`] まで移動・解放しないこと。

use core::ffi::c_void;
use core::mem::{align_of, size_of};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use core::ptr::{addr_of, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use simple_matter::controller::ca::{Ca, CA_STATE_MAX_LEN};
use simple_matter::controller::nodes as nodes_codec;
use simple_matter::controller::{
    AttestationPolicy, Commissioner, ControllerCreds, ControllerStack, Phase,
    CONTROLLER_FABRIC_INDEX,
};
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::discovery::client::MdnsClient;
use simple_matter::discovery::{MATTER_PORT, MDNS_PORT};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::client::{AttrReports, ImClient, ImEvent};
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath};
use simple_matter::kvs::Kvs;
use simple_matter::sc::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};
use simple_matter::sc::initiator::{ScEvent, ScInitiator};
use simple_matter::stack::{SendDirective, MAX_PACKET_SIZE};
use simple_matter::tlv::{TlvTag, TlvValue};
use simple_matter::transport::net::PeerAddr;
use simple_matter::transport::session::SessionId;

use crate::custom::{sm_attr_value_t, write_value};
use crate::{
    addr_to_peer, multicast_dst, peer_to_addr, sm_addr_t, CKvs, CRng, SmKvsDelete, SmKvsGet,
    SmKvsSet, SmRngFill, SM_NO_DEADLINE,
};

// BLE central 給餌(F7b、§11.4)。BTP central を C++ の NimBLE central から駆動する。
#[cfg(feature = "ble")]
use simple_matter::btp::gatt::AdvData;
#[cfg(feature = "ble")]
use simple_matter::btp::{Btp, BtpRole};
#[cfg(feature = "ble")]
use simple_matter::transport::net::{BtpConnId, MAX_RX_PACKET_SIZE};
// デバイス側と共有する BLE イベント種別(`sm_ble_event` と同じ ABI)。ble 無効ビルドでも
// `sm_ctrl_ble_event` の署名に現れるため無条件で import する(本体は SM_ERR を返す)。
use crate::sm_ble_event_kind_t;

// ==========================================================================
// サイジング(単一ノード運用 + コミッショニング時の揺らぎ。s3-controller と同値)
// ==========================================================================

/// 同時セッション数(運用 CASE + コミッショニング PASE/unsecured + 再確立の揺らぎ)。
const CTRL_SS: usize = 6;
/// 同時 exchange 数(連続トランザクション直後の未回収 exchange を見込む)。
const CTRL_EX: usize = 8;
/// TX バッファプール数(commissioner.rs と同値)。
const CTRL_TX: usize = 3;
/// IM 応答結果バッファ(単一属性 Read には十分。wildcard は使わない)。
const CTRL_RESULT: usize = 1280;
/// 管理ノード数の上限(ノード帳・resumption・セッション表のサイジング)。
const MAX_NODES: usize = 8;
/// 内部 TX キュー段数(コミッショナ駆動で 1 サイクルに複数の送信が生じるため)。
const TX_Q_CAP: usize = 4;
/// イベントリング容量(コミッショニングはフェーズごとにイベントを積む)。
const EV_CAP: usize = 16;
/// 1 回の invoke に渡せる引数(context tag 0..)の上限。
pub const MAX_OP_ARGS: usize = 4;
/// BTP central の window(コアの参照実装 `ble-commissioner.rs` / デバイス側シムと同じ 6)。
#[cfg(feature = "ble")]
const CTRL_BTP_WINDOW: usize = 6;
/// 保留中の BTP handshake request(central の Capabilities Request)を退避する上限。
#[cfg(feature = "ble")]
const HS_REQ_MAX: usize = 40;

/// 暗号バックエンド(C コールバック RNG)。
type CtrlBackend = RustCrypto<CRng>;
/// CASE creds(コントローラ自 fabric ビュー)。供給メモリ内 `owned` を `&'static` 借用。
type CCreds = ControllerCreds<'static, CtrlBackend>;
/// コントローラスタック。
type CStack =
    ControllerStack<'static, CtrlBackend, CRng, CCreds, CTRL_SS, CTRL_EX, CTRL_TX, CTRL_RESULT>;
/// コミッショナ(供給メモリ内 `owned.ca` / `owned.crypto` を `&'static` 借用)。
type CComm = Commissioner<'static, CtrlBackend>;

/// CASE resumption レコード(ポートローカル): `[version(1)][rid(16)][ss(32)]` = 49B。
const RESUMPTION_RECORD_VERSION: u8 = 1;
const RESUMPTION_RECORD_LEN: usize = 1 + CASE_RESUMPTION_ID_LEN + SHARED_SECRET_LEN;

// ==========================================================================
// C ABI 型(cbindgen が simple_matter.h に追記する)
// ==========================================================================

/// コントローラ初期化設定(`docs/design/c-ffi-shim.md` §11.1)。
#[repr(C)]
pub struct sm_ctrl_config_t {
    /// コントローラ fabric の FabricId(smctl / examples と同値を推奨。例 0xFAB0000000000001)。
    /// KVS に ca-state があればそちらが優先され、本値は無視される。
    pub fabric_id: u64,
    /// コントローラ自身の運用 NodeId(CaseAdminSubject / CASE identity)。同上。
    pub controller_node_id: u64,
    /// AdminVendorId(AddNOC に載せる)。
    pub vendor_id: u16,
    /// KVS get コールバック(NULL 可 = 永続化なし。`b"cast"`/`b"nods"`/`b"rsm*"` を委譲)。
    pub kvs_get: SmKvsGet,
    /// KVS set コールバック。
    pub kvs_set: SmKvsSet,
    /// KVS delete コールバック(冪等)。
    pub kvs_delete: SmKvsDelete,
    /// KVS コールバックの ctx。
    pub kvs_ctx: *mut c_void,
    /// RNG コールバック(必須。esp_fill_random / getrandom 等)。
    pub rng_fill: SmRngFill,
    /// RNG コールバックの ctx。
    pub rng_ctx: *mut c_void,
}

/// コントローライベント種別(`sm_ctrl_take_event` で取り出す)。
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// SM_CTRL_EV_NONE は C 側の ABI ゼロ値(memset 済み構造体の既定)。Rust では構築しない。
#[allow(dead_code)]
pub enum sm_ctrl_event_kind_t {
    /// イベント無し(ABI ゼロ値のセンチネル)。
    SM_CTRL_EV_NONE = 0,
    /// コミッショニングのフェーズが進んだ(`phase` = フェーズコード。§11.1)。
    SM_CTRL_EV_PAIR_PHASE = 1,
    /// コミッショニング完了(`node_id` = 対象ノード)。以降 invoke/read 可。
    SM_CTRL_EV_PAIR_COMPLETE = 2,
    /// コミッショニング失敗(`phase` = 失敗フェーズコード)。
    SM_CTRL_EV_PAIR_FAILED = 3,
    /// 運用 CASE セッションを確立した(`node_id`、`resumed` = Sigma2Resume 経由か)。
    SM_CTRL_EV_CASE_ESTABLISHED = 4,
    /// 運用 CASE 確立に失敗した(`node_id`)。
    SM_CTRL_EV_CASE_FAILED = 5,
    /// Invoke 完了(`node_id`、`status` = IM ステータス。0 = 成功)。
    SM_CTRL_EV_INVOKE_DONE = 6,
    /// Invoke 失敗(`node_id`、`status`)。
    SM_CTRL_EV_INVOKE_FAILED = 7,
    /// Read 完了(`node_id`、`value_u64` / `value_is_null` にスカラ値)。
    SM_CTRL_EV_READ_DONE = 8,
    /// Read 失敗(`node_id`)。
    SM_CTRL_EV_READ_FAILED = 9,
    /// operational 解決成功(`node_id`。アドレスは `sm_ctrl_node_addr` で取得)。
    SM_CTRL_EV_RESOLVE_DONE = 10,
    /// BLE コミッショニングフェーズ完了(§11.4)。`node_id` = 対象ノード。
    ///
    /// AddNOC + ネットワーク資格情報投入 + ConnectNetwork まで BTP 上で完了した。C++ は
    /// BLE を切断(`sm_ctrl_ble_event(DISCONNECTED)`)し、運用アドレスを解決
    /// ([`sm_ctrl_resolve_start`] / [`sm_ctrl_mdns_rx`])してから運用 UDP で pump を回す
    /// (CASE → CommissioningComplete → PAIR_COMPLETE。ble-commissioner `--udp-handoff` の流儀)。
    SM_CTRL_EV_BLE_DONE = 11,
    /// Write 完了(`node_id`、`status` = IM ステータス。0 = 成功)。
    SM_CTRL_EV_WRITE_DONE = 12,
    /// Write 失敗(`node_id`、`status`)。
    SM_CTRL_EV_WRITE_FAILED = 13,
    /// Subscribe のプライミングが完了した(`node_id`、`value_u64` = 購読 ID)。
    SM_CTRL_EV_SUBSCRIBE_DONE = 14,
    /// Subscribe 開始に失敗した(`node_id`)。
    SM_CTRL_EV_SUBSCRIBE_FAILED = 15,
    /// 購読レポートを受理した(`node_id`、`value_u64` / `value_is_null` に最新スカラ値)。
    SM_CTRL_EV_REPORT = 16,
}

/// コントローライベント(立った順にリングから取り出す)。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sm_ctrl_event_t {
    /// 種別。
    pub kind: sm_ctrl_event_kind_t,
    /// コミッショニングのフェーズコード(PAIR_PHASE / PAIR_FAILED)。
    /// 0=Idle 1=PASE 2=ArmFailSafe 3=Attestation 4=CSR 5=AddTrustedRoot 6=AddNOC
    /// 7=CASE 8=Complete 9=Done 10=AddWiFi 11=ConnectNetwork。
    pub phase: u8,
    /// IM/SC ステータスコード(INVOKE/READ 系。0 = 成功)。
    pub status: u8,
    /// 対象ノードの運用 NodeId。
    pub node_id: u64,
    /// Read スカラ値(READ_DONE。符号付きは 2 の補数ビットパターン)。
    pub value_u64: u64,
    /// Read 値が null(READ_DONE)。
    pub value_is_null: bool,
    /// CASE が resumption(Sigma2Resume)経由で確立したか(CASE_ESTABLISHED)。
    pub resumed: bool,
}

// ==========================================================================
// 内部状態
// ==========================================================================

/// 進行中の運用操作(live セッションが無いときは CASE 確立後に実行する)。
#[derive(Clone, Copy)]
enum PendingOp {
    Invoke {
        ep: u16,
        cluster: u32,
        cmd: u32,
    },
    Read {
        ep: u16,
        cluster: u32,
        attr: u32,
    },
    /// 単一属性 Write(値は `CtrlShim::op_args[0]`)。
    Write {
        ep: u16,
        cluster: u32,
        attr: u32,
    },
    /// 単一属性 Subscribe(プライミング完了で SUBSCRIBE_DONE)。
    Subscribe {
        ep: u16,
        cluster: u32,
        attr: u32,
        min_s: u16,
        max_s: u16,
    },
}

/// コントローラの活動状態(単一トランザクションを直列実行する)。
#[derive(Clone, Copy)]
enum Activity {
    /// アイドル(新規要求受付可)。
    Idle,
    /// コミッショニング進行中(`comm` が active)。
    Pairing { node_id: u64, addr: SocketAddr },
    /// 運用 CASE 確立中(確立後に `op` を実行する)。
    Connecting {
        node_id: u64,
        addr: SocketAddr,
        op: PendingOp,
    },
    /// 運用トランザクション(invoke/read)の応答待ち。
    AwaitOp { node_id: u64, op: PendingOp },
    /// BLE(BTP)コミッショニング進行中(§11.4)。PASE→AddNOC→ネットワーク投入→ConnectNetwork
    /// を BTP 上で駆動し、Phase::Case 直前で保留して [`SM_CTRL_EV_BLE_DONE`] を立てる。
    #[cfg(feature = "ble")]
    BlePairing { node_id: u64 },
    /// BLE フェーズ完了後、運用アドレス解決 → UDP 遷移(`set_peer` + `resume`)待ち(§11.4)。
    #[cfg(feature = "ble")]
    BleHandoff { node_id: u64 },
}

/// 管理ノード 1 台の実行時状態。
#[derive(Clone, Copy)]
struct NodeEntry {
    node_id: u64,
    addr: SocketAddr,
    session: Option<SessionId>,
}

/// 内部 TX キュー 1 段(コミッショナ/ポンプが産んだ送信を C++ の 1 回 1 送出契約へ橋渡し)。
struct TxItem {
    buf: [u8; MAX_PACKET_SIZE],
    len: usize,
    dst: sm_addr_t,
}

/// 供給メモリ内 `owned` が所有するテーブル(スタックが `&'static` で借用する)。
struct CtrlOwned {
    crypto: CtrlBackend,
    ca: Ca<CtrlBackend>,
}

/// コントローラシム(呼び出し側供給メモリに in-place 構築される単一インスタンス)。
struct CtrlShim {
    owned: CtrlOwned,
    stack: CStack,
    comm: Option<CComm>,
    activity: Activity,
    nodes: heapless::Vec<NodeEntry, MAX_NODES>,
    kvs: Option<CKvs>,
    events: heapless::Deque<sm_ctrl_event_t, EV_CAP>,
    txq: heapless::Deque<TxItem, TX_Q_CAP>,
    /// この fabric の compressed fabric id(operational 解決のインスタンス名素材)。
    compressed_fabric: [u8; 8],
    /// 直近に PAIR_PHASE として通知したフェーズコード(重複通知の抑止。pump は毎回呼ばれる)。
    last_pair_phase: u8,
    /// 進行中の operation の引数(invoke 引数 / write 値)。単一トランザクション直列なので 1 組。
    op_args: heapless::Vec<sm_attr_value_t, MAX_OP_ARGS>,
    /// 購読中のパス(SubscriptionReport の値抽出に使う)。
    sub_path: Option<(u16, u32, u32)>,
    // --- BLE central(F7b、§11.4)。BTP central を C++ の NimBLE central から給餌する ---
    /// BTP central 状態機械(同時 1 接続。デバイス側シムの鏡像)。
    #[cfg(feature = "ble")]
    btp: Btp<CTRL_BTP_WINDOW>,
    /// 現在の BLE 接続(1 本のみ)。
    #[cfg(feature = "ble")]
    ble_conn: Option<BtpConnId>,
    /// CONNECTED で渡された ATT MTU(0 = 不明)。
    #[cfg(feature = "ble")]
    ble_mtu: Option<u16>,
    /// C2 indication の subscribe が完了したか(central 自身の購読状態。情報用)。
    #[cfg(feature = "ble")]
    ble_subscribed: bool,
    /// 保留中の BTP handshake request(central の Capabilities Request)。`sm_ctrl_ble_poll`
    /// が最初に排出する(`start_handshake` は `process_outgoing` を経由しないため退避が要る)。
    #[cfg(feature = "ble")]
    ble_hs_out: heapless::Vec<u8, HS_REQ_MAX>,
}

// ==========================================================================
// 単一インスタンスのアクセス(供給メモリのポインタを static に保持)
// ==========================================================================

static CTRL: AtomicPtr<CtrlShim> = AtomicPtr::new(null_mut());
static CTRL_INITED: AtomicBool = AtomicBool::new(false);

/// 初期化済みシムへの排他参照(単線契約)。
///
/// # Safety
/// `CTRL_INITED` が true かつ単一タスクからのみ呼ぶこと。
unsafe fn ctrl_shim() -> &'static mut CtrlShim {
    &mut *CTRL.load(Ordering::Relaxed)
}

// ==========================================================================
// アドレス変換
// ==========================================================================

/// `sm_addr_t` を [`SocketAddr`] へ変換する。
fn smaddr_to_socket(a: &sm_addr_t) -> SocketAddr {
    if a.is_v6 {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(a.ip),
            a.port,
            0,
            a.scope_id,
        ))
    } else {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(a.ip[0], a.ip[1], a.ip[2], a.ip[3]),
            a.port,
        ))
    }
}

/// [`SocketAddr`] を `sm_addr_t` へ変換する。
fn socket_to_smaddr(sa: SocketAddr) -> sm_addr_t {
    peer_to_addr(PeerAddr::Udp(sa))
}

/// フェーズコード(`sm_ctrl_event_t::phase`。commissioner.rs の `stage_code` と同値)。
fn phase_code(p: Phase) -> u8 {
    match p {
        Phase::Idle => 0,
        Phase::Pase => 1,
        Phase::ArmFailSafe => 2,
        Phase::Attestation => 3,
        Phase::Csr => 4,
        Phase::AddTrustedRoot => 5,
        Phase::AddNoc => 6,
        Phase::Case => 7,
        Phase::Complete => 8,
        Phase::Done { .. } => 9,
        Phase::AddWifiNetwork => 10,
        Phase::ConnectNetwork => 11,
        Phase::Failed { stage, .. } => stage,
    }
}

// ==========================================================================
// イベント / TX ヘルパ
// ==========================================================================

impl CtrlShim {
    /// イベントをリングへ積む(満杯なら最古を落とす)。
    fn push_event(&mut self, ev: sm_ctrl_event_t) {
        if self.events.is_full() {
            let _ = self.events.pop_front();
        }
        let _ = self.events.push_back(ev);
    }

    fn ev(kind: sm_ctrl_event_kind_t) -> sm_ctrl_event_t {
        sm_ctrl_event_t {
            kind,
            phase: 0,
            status: 0,
            node_id: 0,
            value_u64: 0,
            value_is_null: false,
            resumed: false,
        }
    }

    /// 送信を内部 TX キューへ積む(満杯なら最古を落とす)。
    fn queue_tx(&mut self, payload: &[u8], dir: SendDirective) {
        let mut item = TxItem {
            buf: [0u8; MAX_PACKET_SIZE],
            len: dir.len.min(MAX_PACKET_SIZE),
            dst: peer_to_addr(dir.addr),
        };
        let n = item.len.min(payload.len());
        item.buf[..n].copy_from_slice(&payload[..n]);
        item.len = n;
        if self.txq.is_full() {
            let _ = self.txq.pop_front();
        }
        let _ = self.txq.push_back(item);
    }

    /// TX キューの先頭を `tx_out` へ書き出して長さを返す(空 / 容量不足は 0)。
    fn drain_one(&mut self, tx_out: *mut u8, tx_cap: usize, tx_dst: *mut sm_addr_t) -> usize {
        let Some(item) = self.txq.pop_front() else {
            return 0;
        };
        if item.len > tx_cap {
            return 0; // 容量不足(呼び出し側が MAX_PACKET_SIZE 以上を渡す契約)。
        }
        // SAFETY: caller が tx_cap バイトの tx_out を与える契約。
        unsafe { core::ptr::copy_nonoverlapping(item.buf.as_ptr(), tx_out, item.len) };
        if !tx_dst.is_null() {
            // SAFETY: 同上。
            unsafe { *tx_dst = item.dst };
        }
        item.len
    }

    /// ノードエントリを検索する。
    fn node_index(&self, node_id: u64) -> Option<usize> {
        self.nodes.iter().position(|n| n.node_id == node_id)
    }

    /// ノードのアドレス / セッションを記録する(無ければ追加)。
    fn set_node(&mut self, node_id: u64, addr: SocketAddr, session: Option<SessionId>) {
        if let Some(i) = self.node_index(node_id) {
            self.nodes[i].addr = addr;
            if session.is_some() {
                self.nodes[i].session = session;
            }
        } else {
            let _ = self.nodes.push(NodeEntry {
                node_id,
                addr,
                session,
            });
        }
    }

    // --- 永続化(KVS コールバック) ---

    /// CA 鍵素材を `b"cast"` へ保存する(v1 = smctl / s3-controller 互換)。
    fn persist_ca(&mut self) {
        let Some(mut kvs) = self.kvs else {
            return;
        };
        let mut rec = [0u8; CA_STATE_MAX_LEN];
        if let Ok(len) = self.owned.ca.encode_state(&mut rec) {
            let _ = kvs.set(b"cast", &rec[..len]);
        }
    }

    /// ノード帳を `b"nods"` へ保存する(v1 = smctl `nodes.tlv` 互換。全量書き換え)。
    fn persist_nodes(&mut self) {
        let Some(mut kvs) = self.kvs else {
            return;
        };
        let mut recs: heapless::Vec<nodes_codec::NodeRecord, MAX_NODES> = heapless::Vec::new();
        for n in &self.nodes {
            if let Ok(rec) = nodes_codec::NodeRecord::new(n.node_id, n.addr, "") {
                let _ = recs.push(rec);
            }
        }
        let mut buf = [0u8; nodes_codec::nodes_max_len(MAX_NODES)];
        if let Ok(len) = nodes_codec::encode_nodes(&mut buf, &recs) {
            let _ = kvs.set(b"nods", &buf[..len]);
        }
    }

    /// ノード `node_id` の CASE resumption 素材を `b"rsm<node16hex>"` へ保存する。
    fn persist_resumption(&mut self, node_id: u64) {
        let Some(mut kvs) = self.kvs else {
            return;
        };
        let mut key = [0u8; 19];
        resumption_key(node_id, &mut key);
        match self
            .stack
            .resumption_export(CONTROLLER_FABRIC_INDEX, node_id)
        {
            Some((rid, ss)) => {
                let mut rec = [0u8; RESUMPTION_RECORD_LEN];
                rec[0] = RESUMPTION_RECORD_VERSION;
                rec[1..1 + CASE_RESUMPTION_ID_LEN].copy_from_slice(&rid);
                rec[1 + CASE_RESUMPTION_ID_LEN..].copy_from_slice(&ss);
                let _ = kvs.set(&key, &rec);
            }
            None => {
                let _ = kvs.remove(&key);
            }
        }
    }
}

/// `b"rsm" + <node_id を 16 進大文字 16 桁>`(19 バイト)を `out` へ書く。
fn resumption_key(node_id: u64, out: &mut [u8; 19]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out[0] = b'r';
    out[1] = b's';
    out[2] = b'm';
    for i in 0..16 {
        let nib = (node_id >> (4 * (15 - i))) & 0xF;
        out[3 + i] = HEX[nib as usize];
    }
}

// ==========================================================================
// ポンプ(コミッショナ / CASE 確立 / 運用トランザクションの駆動)
// ==========================================================================

/// 現在の活動状態を 1 ステップ進める(rx / poll のたびに呼ぶ)。送信は TX キューへ積む。
fn pump(s: &mut CtrlShim, now: u64) {
    match s.activity {
        Activity::Idle => drain_subscription_reports(s),
        Activity::Pairing { node_id, addr } => drive_pairing(s, node_id, addr, now),
        Activity::Connecting { node_id, addr, op } => drive_connecting(s, node_id, addr, op, now),
        Activity::AwaitOp { node_id, op } => drive_awaitop(s, node_id, op),
        // BLE フェーズは BTP イベント駆動(`sm_ctrl_ble_event` 内の `ble_service`)。
        // UDP pump では進めない。handoff 後は Activity::Pairing に遷移し上の Pairing 腕が担う。
        #[cfg(feature = "ble")]
        Activity::BlePairing { .. } | Activity::BleHandoff { .. } => {}
    }
}

/// [`Phase::Failed`] の理由を粗いコードへ写す(`sm_ctrl_event_t::status`)。
fn commission_error_code(r: simple_matter::controller::CommissionError) -> u8 {
    use simple_matter::controller::CommissionError as E;
    match r {
        E::Sc(_) => 1,
        E::Im(s) => s.to_u8(),
        E::Status(_) => 3,
        E::Ca => 4,
        E::Csr => 5,
        E::Attestation(_) => 6,
        E::Stack(_) => 7,
        E::Protocol => 8,
    }
}

/// コミッショナを進捗が止まるまで駆動する(smctl `pump_commissioner` 相当)。
fn drive_pairing(s: &mut CtrlShim, node_id: u64, addr: SocketAddr, now: u64) {
    loop {
        let mut scratch = [0u8; MAX_PACKET_SIZE];
        // comm / stack は別フィールド(disjoint borrow)。out は Copy でブロック外へ返す。
        let (out, prev) = {
            let Some(comm) = s.comm.as_mut() else {
                s.activity = Activity::Idle;
                return;
            };
            let prev = comm.phase();
            let out = comm.drive(&mut s.stack, now, &mut scratch);
            (out, prev)
        };
        if let Some(dir) = out.send {
            s.queue_tx(&scratch[..dir.len], dir);
        }
        let code = phase_code(out.phase);
        if code != s.last_pair_phase {
            s.last_pair_phase = code;
            let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_PHASE);
            ev.phase = code;
            ev.node_id = node_id;
            s.push_event(ev);
        }
        match out.phase {
            Phase::Done { session } => {
                s.set_node(node_id, addr, Some(session));
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_COMPLETE);
                ev.node_id = node_id;
                s.push_event(ev);
                s.comm = None;
                s.activity = Activity::Idle;
                // issue_noc で next_serial が進んだ CA + ノード帳 + resumption を永続化。
                s.persist_ca();
                s.persist_nodes();
                s.persist_resumption(node_id);
                return;
            }
            Phase::Failed { stage, reason } => {
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_FAILED);
                ev.phase = stage;
                ev.status = commission_error_code(reason);
                ev.node_id = node_id;
                s.push_event(ev);
                s.comm = None;
                s.activity = Activity::Idle;
                return;
            }
            _ => {}
        }
        if out.send.is_none() && out.phase == prev {
            return; // 次はイベント待ち(rx が来るまで進めない)。
        }
    }
}

/// 運用 CASE の確立を待ち、確立後に保留中の操作を発行する。
fn drive_connecting(s: &mut CtrlShim, node_id: u64, addr: SocketAddr, op: PendingOp, now: u64) {
    match s.stack.sc_take_event() {
        Some(ScEvent::CaseEstablished { session, resumed }) => {
            s.set_node(node_id, addr, Some(session));
            s.persist_resumption(node_id);
            let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_ESTABLISHED);
            ev.node_id = node_id;
            ev.resumed = resumed;
            s.push_event(ev);
            launch_op(s, node_id, session, op, now);
        }
        Some(ScEvent::Failed { .. }) => {
            let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_FAILED);
            ev.node_id = node_id;
            s.push_event(ev);
            s.activity = Activity::Idle;
        }
        _ => {}
    }
}

/// 運用トランザクションの応答(IM イベント)を処理する。
fn drive_awaitop(s: &mut CtrlShim, node_id: u64, op: PendingOp) {
    let Some(ev) = s.stack.im_take_event() else {
        return;
    };
    match (op, ev) {
        (PendingOp::Invoke { .. }, ImEvent::InvokeDone { status }) => {
            let kind = if status.is_success() {
                sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_DONE
            } else {
                sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_FAILED
            };
            let mut e = CtrlShim::ev(kind);
            e.node_id = node_id;
            e.status = status.to_u8();
            s.push_event(e);
            s.activity = Activity::Idle;
        }
        (
            PendingOp::Read {
                ep, cluster, attr, ..
            },
            ImEvent::ReadDone,
        ) => {
            let mut e = match read_scalar_value(s, ep, cluster, attr) {
                Some((v, is_null)) => {
                    let mut e = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_READ_DONE);
                    e.value_u64 = v;
                    e.value_is_null = is_null;
                    e
                }
                None => CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_READ_FAILED),
            };
            e.node_id = node_id;
            s.push_event(e);
            s.activity = Activity::Idle;
        }
        (PendingOp::Write { .. }, ImEvent::WriteDone { status }) => {
            let kind = if status.is_success() {
                sm_ctrl_event_kind_t::SM_CTRL_EV_WRITE_DONE
            } else {
                sm_ctrl_event_kind_t::SM_CTRL_EV_WRITE_FAILED
            };
            let mut e = CtrlShim::ev(kind);
            e.node_id = node_id;
            e.status = status.to_u8();
            s.push_event(e);
            s.activity = Activity::Idle;
        }
        (
            PendingOp::Subscribe {
                ep, cluster, attr, ..
            },
            ImEvent::SubscribeDone {
                subscription_id, ..
            },
        ) => {
            s.sub_path = Some((ep, cluster, attr));
            let mut e = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_DONE);
            e.node_id = node_id;
            e.value_u64 = subscription_id as u64;
            // プライミングレポートの値を READ 同様に載せる(初期値の確認用)。
            if let Some((v, is_null)) = sub_scalar_value(s, ep, cluster, attr) {
                e.value_is_null = is_null;
                e.status = 0;
                let _ = v;
            }
            s.push_event(e);
            s.activity = Activity::Idle;
        }
        (op, ImEvent::Failed { status }) => {
            let mut e = CtrlShim::ev(op_failed_kind(op));
            e.node_id = node_id;
            e.status = status.to_u8();
            s.push_event(e);
            s.activity = Activity::Idle;
        }
        // 予期しないイベント: 失敗扱いで終端する。
        (op, _) => {
            let mut e = CtrlShim::ev(op_failed_kind(op));
            e.node_id = node_id;
            s.push_event(e);
            s.activity = Activity::Idle;
        }
    }
}

/// 確立済みセッション上で `op` を 1 本発行する(invoke/read/write/subscribe 共通)。
///
/// 引数(invoke)/ 値(write)は `s.op_args` から取る(単一トランザクション直列)。
fn issue_op(
    s: &mut CtrlShim,
    session: SessionId,
    op: PendingOp,
    now: u64,
    scratch: &mut [u8],
) -> simple_matter::error::Result<SendDirective> {
    // クロージャがスタックを可変借用するため、引数はローカルへコピーしてから渡す。
    let args = s.op_args.clone();
    match op {
        PendingOp::Invoke { ep, cluster, cmd } => s.stack.start_invoke(
            session,
            CommandPath::new(EndpointId(ep), ClusterId(cluster), CommandId(cmd)),
            |w, t| {
                w.start_struct(t)?;
                for (i, a) in args.iter().enumerate() {
                    write_value(w, &TlvTag::ContextSpecific(i as u8), a)?;
                }
                w.end_container()
            },
            now,
            scratch,
        ),
        PendingOp::Read { ep, cluster, attr } => s.stack.start_read(
            session,
            &[AttributePath::concrete(
                EndpointId(ep),
                ClusterId(cluster),
                AttributeId(attr),
            )],
            now,
            scratch,
        ),
        PendingOp::Write { ep, cluster, attr } => {
            let val = *args
                .first()
                .ok_or(simple_matter::error::Error::InvalidState)?;
            s.stack.start_write(
                session,
                &AttributePath::concrete(EndpointId(ep), ClusterId(cluster), AttributeId(attr)),
                |w, t| write_value(w, t, &val),
                now,
                scratch,
            )
        }
        PendingOp::Subscribe {
            ep,
            cluster,
            attr,
            min_s,
            max_s,
        } => s.stack.start_subscribe(
            session,
            &[AttributePath::concrete(
                EndpointId(ep),
                ClusterId(cluster),
                AttributeId(attr),
            )],
            min_s,
            max_s,
            now,
            scratch,
        ),
    }
}

/// `op` に対応する失敗イベント種別。
fn op_failed_kind(op: PendingOp) -> sm_ctrl_event_kind_t {
    match op {
        PendingOp::Invoke { .. } => sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_FAILED,
        PendingOp::Read { .. } => sm_ctrl_event_kind_t::SM_CTRL_EV_READ_FAILED,
        PendingOp::Write { .. } => sm_ctrl_event_kind_t::SM_CTRL_EV_WRITE_FAILED,
        PendingOp::Subscribe { .. } => sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_FAILED,
    }
}

/// 確立済みセッション上で `op` を発行し、応答待ちへ遷移する。
fn launch_op(s: &mut CtrlShim, node_id: u64, session: SessionId, op: PendingOp, now: u64) {
    let mut scratch = [0u8; MAX_PACKET_SIZE];
    let res = issue_op(s, session, op, now, &mut scratch);
    match res {
        Ok(dir) => {
            s.queue_tx(&scratch[..dir.len], dir);
            s.activity = Activity::AwaitOp { node_id, op };
        }
        Err(_) => {
            let mut e = CtrlShim::ev(op_failed_kind(op));
            e.node_id = node_id;
            s.push_event(e);
            s.activity = Activity::Idle;
        }
    }
}

/// 直近 Read 応答から対象属性のスカラ値を取り出す(u64 ビットパターン + null フラグ)。
fn sub_scalar_value(s: &CtrlShim, ep: u16, cluster: u32, attr: u32) -> Option<(u64, bool)> {
    scalar_from_reports(s.stack.sub_reports(), ep, cluster, attr)
}

/// アイドル中に届いた購読レポートを [`sm_ctrl_event_kind_t::SM_CTRL_EV_REPORT`] へ写す。
fn drain_subscription_reports(s: &mut CtrlShim) {
    while let Some(ev) = s.stack.im_take_event() {
        match ev {
            ImEvent::SubscriptionReport { subscription_id } => {
                let mut e = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_REPORT);
                e.phase = (subscription_id & 0xFF) as u8;
                if let Some((ep, cluster, attr)) = s.sub_path {
                    e.node_id = s.nodes.first().map(|n| n.node_id).unwrap_or(0);
                    if let Some((v, is_null)) = sub_scalar_value(s, ep, cluster, attr) {
                        e.value_u64 = v;
                        e.value_is_null = is_null;
                    }
                }
                s.push_event(e);
            }
            ImEvent::SubscriptionLost { .. } => {
                s.sub_path = None;
            }
            _ => {}
        }
    }
}

fn read_scalar_value(s: &CtrlShim, ep: u16, cluster: u32, attr: u32) -> Option<(u64, bool)> {
    scalar_from_reports(s.stack.read_reports(), ep, cluster, attr)
}

/// AttributeReportIB 列から指定パスのスカラ値を取り出す(read / subscribe 共通)。
fn scalar_from_reports(
    reports: AttrReports<'_>,
    ep: u16,
    cluster: u32,
    attr: u32,
) -> Option<(u64, bool)> {
    for report in reports {
        let Ok(AttributeReportRef::Data(d)) = report else {
            continue;
        };
        let Some(c) = d.path.to_concrete() else {
            continue;
        };
        if c.endpoint.0 != ep || c.cluster.0 != cluster || c.attribute.0 != attr {
            continue;
        }
        let mut v = d.value();
        if let Ok(Some(e)) = v.read_next() {
            return Some(scalar_from_tlv(&e.value));
        }
    }
    None
}

/// TLV 要素 1 個を `(value_u64, is_null)` に落とす(C ABI は u64 1 本のまま)。
///
/// 浮動小数点は **`f32::to_bits()` のビットパターン**を載せる(§12.2)。イベントに
/// 型情報は足さない(ABI 維持)ので、C++ 側は「このパスは f32」と知っている前提で
/// `memcpy` により下位 32bit を `f32` へ戻す。Double は f32 へ丸めてから載せる
/// (Matter の計測系属性は single 前提。C++ 側の読み替えを 1 通りに保つ)。
fn scalar_from_tlv(v: &TlvValue<'_>) -> (u64, bool) {
    match *v {
        TlvValue::Boolean(b) => (b as u64, false),
        TlvValue::UnsignedInteger(u) => (u, false),
        TlvValue::SignedInteger(i) => (i as u64, false),
        TlvValue::Float(f) => (f.to_bits() as u64, false),
        TlvValue::Double(d) => ((d as f32).to_bits() as u64, false),
        TlvValue::Null => (0, true),
        _ => (0, false),
    }
}

/// 運用操作を開始する(live セッションがあれば即発行、無ければ CASE 自動確立)。0=OK、負値=失敗。
fn start_operation(s: &mut CtrlShim, node_id: u64, op: PendingOp, now: u64) -> i32 {
    if !matches!(s.activity, Activity::Idle) {
        return -10; // busy(単一トランザクション直列)。
    }
    let Some(idx) = s.node_index(node_id) else {
        return -3; // 未知ノード(未コミッショニング)。
    };
    let addr = s.nodes[idx].addr;
    // live セッションがあれば直接発行を試みる。
    if let Some(session) = s.nodes[idx].session {
        let mut scratch = [0u8; MAX_PACKET_SIZE];
        let res = issue_op(s, session, op, now, &mut scratch);
        if let Ok(dir) = res {
            s.queue_tx(&scratch[..dir.len], dir);
            s.activity = Activity::AwaitOp { node_id, op };
            return 0;
        }
        // セッションが陳腐化(退避された等)→ CASE を張り直す。
        s.nodes[idx].session = None;
    }
    // CASE を自動確立してから op を実行する(resumption 素材があれば Sigma2Resume)。
    let mut scratch = [0u8; MAX_PACKET_SIZE];
    match s.stack.start_case(
        PeerAddr::Udp(addr),
        CONTROLLER_FABRIC_INDEX,
        node_id,
        now,
        &mut scratch,
    ) {
        Ok(dir) => {
            s.queue_tx(&scratch[..dir.len], dir);
            s.activity = Activity::Connecting { node_id, addr, op };
            0
        }
        Err(_) => -4, // CASE 開始失敗(exchange/session 枯渇等)。
    }
}

// ==========================================================================
// C API
// ==========================================================================

/// 供給メモリに構築する [`CtrlShim`] のバイトサイズ(`sm_ctrl_init` へ渡す `mem_len` の下限)。
#[no_mangle]
pub extern "C" fn sm_ctrl_context_size() -> usize {
    size_of::<CtrlShim>()
}

/// 供給メモリに要求するアラインメント(バイト)。`mem` はこの倍数でなければならない。
#[no_mangle]
pub extern "C" fn sm_ctrl_context_align() -> usize {
    align_of::<CtrlShim>()
}

/// コントローラを初期化する(供給メモリに in-place 構築 + KVS から CA/ノード帳/resumption 復元)。
///
/// 戻り値: 0=OK、-1=NULL 引数、-2=既に初期化済み、-3=`mem_len` 不足、
/// -4=`mem` アラインメント不正、-5=RNG コールバック未設定、-6=CA 生成失敗。
///
/// `mem` は [`sm_ctrl_context_size`] バイト以上・[`sm_ctrl_context_align`] アラインで、
/// [`sm_ctrl_deinit`] まで移動・解放しないこと(PSRAM 配置可)。
#[no_mangle]
pub extern "C" fn sm_ctrl_init(
    mem: *mut u8,
    mem_len: usize,
    cfg: *const sm_ctrl_config_t,
    _now_ms: u64,
) -> i32 {
    if mem.is_null() || cfg.is_null() {
        return -1;
    }
    if CTRL_INITED.load(Ordering::SeqCst) {
        return -2;
    }
    if mem_len < size_of::<CtrlShim>() {
        return -3;
    }
    if !(mem as usize).is_multiple_of(align_of::<CtrlShim>()) {
        return -4;
    }
    // SAFETY: cfg は有効な sm_ctrl_config_t を指す契約。
    let cfg = unsafe { &*cfg };
    let Some(rng_fill) = cfg.rng_fill else {
        return -5;
    };
    let rng = CRng {
        fill: rng_fill,
        ctx: cfg.rng_ctx,
    };
    let kvs = match (cfg.kvs_get, cfg.kvs_set, cfg.kvs_delete) {
        (Some(get), Some(set), Some(del)) => Some(CKvs {
            get,
            set,
            del,
            ctx: cfg.kvs_ctx,
        }),
        _ => None,
    };

    // CA: KVS(b"cast")から復元、無ければ生成する。
    let crypto_local = RustCrypto::new(rng);
    let mut ca_opt: Option<Ca<CtrlBackend>> = None;
    if let Some(mut k) = kvs {
        let mut rec = [0u8; CA_STATE_MAX_LEN];
        if let Ok(Some(len)) = k.get(b"cast", &mut rec) {
            if let Ok(ca) = Ca::decode_state(&crypto_local, &rec[..len], 0) {
                ca_opt = Some(ca);
            }
        }
    }
    let ca = match ca_opt {
        Some(ca) => ca,
        None => {
            let mut rng_gen = rng;
            match Ca::generate(
                &crypto_local,
                &mut rng_gen,
                cfg.fabric_id,
                cfg.controller_node_id,
                cfg.vendor_id,
                0,
            ) {
                Ok(ca) => ca,
                Err(_) => return -6,
            }
        }
    };

    // SAFETY: 供給メモリに単一インスタンスを in-place 構築する。mem は不動(契約)なので
    // owned フィールドへの &'static 参照は健全(deinit までプログラムに準ずる生存期間)。
    unsafe {
        let sp = mem as *mut CtrlShim;
        addr_of_mut!((*sp).owned).write(CtrlOwned {
            crypto: RustCrypto::new(rng),
            ca,
        });
        let owned: &'static CtrlOwned = &*addr_of!((*sp).owned);

        let creds = ControllerCreds::new(&owned.ca, &owned.crypto, 0);
        let sc = ScInitiator::new(&owned.crypto, rng, creds);
        let im = ImClient::new();
        let stack: CStack = ControllerStack::new(&owned.crypto, sc, im);
        addr_of_mut!((*sp).stack).write(stack);

        addr_of_mut!((*sp).comm).write(None);
        addr_of_mut!((*sp).activity).write(Activity::Idle);
        addr_of_mut!((*sp).nodes).write(heapless::Vec::new());
        addr_of_mut!((*sp).kvs).write(kvs);
        addr_of_mut!((*sp).events).write(heapless::Deque::new());
        addr_of_mut!((*sp).txq).write(heapless::Deque::new());
        let compressed = (*sp).owned.ca.compressed_fabric_id_bytes();
        addr_of_mut!((*sp).compressed_fabric).write(compressed);
        addr_of_mut!((*sp).last_pair_phase).write(u8::MAX);
        addr_of_mut!((*sp).op_args).write(heapless::Vec::new());
        addr_of_mut!((*sp).sub_path).write(None);
        #[cfg(feature = "ble")]
        {
            addr_of_mut!((*sp).btp).write(Btp::new(BtpRole::Central));
            addr_of_mut!((*sp).ble_conn).write(None);
            addr_of_mut!((*sp).ble_mtu).write(None);
            addr_of_mut!((*sp).ble_subscribed).write(false);
            addr_of_mut!((*sp).ble_hs_out).write(heapless::Vec::new());
        }

        CTRL.store(sp, Ordering::SeqCst);
        CTRL_INITED.store(true, Ordering::SeqCst);

        // ノード帳(b"nods")+ resumption 素材(b"rsm<node>")を復元する。
        (*sp).restore_from_kvs();
        // 新規生成の場合は CA を保存しておく(クラッシュ耐性)。
        (*sp).persist_ca();
    }
    0
}

impl CtrlShim {
    /// KVS からノード帳 + resumption 素材を復元する(sm_ctrl_init 末尾)。
    fn restore_from_kvs(&mut self) {
        let Some(mut kvs) = self.kvs else {
            return;
        };
        // ノード帳(b"nods")。
        let mut buf = [0u8; nodes_codec::nodes_max_len(MAX_NODES)];
        if let Ok(Some(len)) = kvs.get(b"nods", &mut buf) {
            let mut tmp: heapless::Vec<NodeEntry, MAX_NODES> = heapless::Vec::new();
            let _ = nodes_codec::decode_nodes(&buf[..len], |rec| {
                let _ = tmp.push(NodeEntry {
                    node_id: rec.node_id,
                    addr: rec.last_addr,
                    session: None,
                });
            });
            self.nodes = tmp;
        }
        // resumption 素材(ノードごと b"rsm<node16hex>")。
        for i in 0..self.nodes.len() {
            let node_id = self.nodes[i].node_id;
            let mut key = [0u8; 19];
            resumption_key(node_id, &mut key);
            let mut rec = [0u8; RESUMPTION_RECORD_LEN];
            if let Ok(Some(len)) = kvs.get(&key, &mut rec) {
                if len == RESUMPTION_RECORD_LEN && rec[0] == RESUMPTION_RECORD_VERSION {
                    let rid: [u8; CASE_RESUMPTION_ID_LEN] =
                        rec[1..1 + CASE_RESUMPTION_ID_LEN].try_into().unwrap();
                    let ss: [u8; SHARED_SECRET_LEN] =
                        rec[1 + CASE_RESUMPTION_ID_LEN..].try_into().unwrap();
                    self.stack
                        .resumption_import(CONTROLLER_FABRIC_INDEX, node_id, &rid, &ss);
                }
            }
        }
    }
}

/// コントローラを破棄する(供給メモリの `CtrlShim` を drop。以降 `mem` は解放してよい)。
///
/// 二重 init 防止フラグを解除する(同一プロセスでの再初期化 = プロセス再起動相当が可能になる)。
#[no_mangle]
pub extern "C" fn sm_ctrl_deinit() {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return;
    }
    let p = CTRL.swap(null_mut(), Ordering::SeqCst);
    CTRL_INITED.store(false, Ordering::SeqCst);
    if !p.is_null() {
        // SAFETY: p は sm_ctrl_init が構築した有効な CtrlShim。単線契約。
        unsafe { core::ptr::drop_in_place(p) };
    }
}

/// コミッショニングを開始する(UDP 直接 PASE。§11.1)。
///
/// 戻り値: 0=OK、-1=未初期化/NULL、-2=busy(他トランザクション進行中)、-3=commission 拒否。
/// 進行は [`sm_ctrl_take_event`] の PAIR_PHASE / PAIR_COMPLETE / PAIR_FAILED で観測する。
#[no_mangle]
pub extern "C" fn sm_ctrl_pair_start(
    node_id: u64,
    passcode: u32,
    addr: *const sm_addr_t,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) || addr.is_null() {
        return -1;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    if !matches!(s.activity, Activity::Idle) {
        return -2;
    }
    // SAFETY: caller が有効な sm_addr_t を与える契約。
    let sa = smaddr_to_socket(unsafe { &*addr });
    // 供給メモリは不動 → owned への &'static は健全(sm_ctrl_init と同じ根拠)。
    let owned: &'static CtrlOwned = unsafe { &*(addr_of!(s.owned)) };
    let mut comm = Commissioner::new(&owned.ca, &owned.crypto, AttestationPolicy::Skip);
    if comm
        .commission(PeerAddr::Udp(sa), passcode, node_id, now_ms)
        .is_err()
    {
        return -3;
    }
    s.comm = Some(comm);
    s.last_pair_phase = u8::MAX;
    s.activity = Activity::Pairing { node_id, addr: sa };
    pump(s, now_ms); // 最初の PBKDFParamRequest を TX キューへ積む。
    0
}

/// Matter UDP 受信を処理する。戻り値 = tx_out に書いた送信長(0 = 送信なし)。
///
/// C++ は 0 になるまで [`sm_ctrl_poll`] を続けて残りの送信を排出する。
#[no_mangle]
pub extern "C" fn sm_ctrl_udp_rx(
    datagram: *mut u8,
    len: usize,
    src: *const sm_addr_t,
    now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !CTRL_INITED.load(Ordering::SeqCst)
        || datagram.is_null()
        || src.is_null()
        || tx_out.is_null()
    {
        return 0;
    }
    // SAFETY: caller が有効なバッファ/アドレスを与える契約。
    let s = unsafe { ctrl_shim() };
    let dg = unsafe { core::slice::from_raw_parts_mut(datagram, len) };
    let peer = addr_to_peer(unsafe { &*src });
    let mut scratch = [0u8; MAX_PACKET_SIZE];
    // 受信処理は SC ハンドシェイクの継続メッセージ(PASE/CASE)を直接返す。IM 応答は
    // ここでは payload を返さず(initiator 側)、ACK は poll が産む。**コミッショナの
    // 駆動は poll に委ねる**: 受信応答の ACK を先に送出してから次のトランザクションを
    // 開始する順序を守るため(smctl の settle→drive 分離。デバイス IM responder は
    // 同時 1 トランザクション)。
    if let Some(dir) = s.stack.handle_rx(dg, peer, now_ms, &mut scratch) {
        s.queue_tx(&scratch[..dir.len], dir);
    }
    s.drain_one(tx_out, tx_cap, tx_dst)
}

/// 時間駆動の送出を 1 件排出する(コミッショナ発行・MRP 再送・standalone ACK)。0 になるまで回す。
#[no_mangle]
pub extern "C" fn sm_ctrl_poll(
    now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !CTRL_INITED.load(Ordering::SeqCst) || tx_out.is_null() {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    // 既に積まれた送信があれば先に排出する。
    if !s.txq.is_empty() {
        return s.drain_one(tx_out, tx_cap, tx_dst);
    }
    // 1) 下位トランスポートの ACK / 再送を先に流し切る(受信応答の ACK を優先送出)。
    let mut scratch = [0u8; MAX_PACKET_SIZE];
    if let Some(dir) = s.stack.poll(now_ms, &mut scratch) {
        s.queue_tx(&scratch[..dir.len], dir);
        return s.drain_one(tx_out, tx_cap, tx_dst);
    }
    // 2) **完全に静穏化**(next_deadline == None = 未達の standalone ACK・再送も無い)して
    //    はじめて、コミッショナ/運用トランザクションを 1 歩進める(次のリクエストを積む)。
    //    smctl の settle→drive 分離と同義: 受信応答の遅延 ACK を送り切ってから次の exchange
    //    を開始する(デバイス IM responder は同時 1 トランザクションのため、ACK 前に次の
    //    リクエストを送るとデバイスが busy で無応答になる = Timeout)。
    // 判定は **MRP 由来の期限だけ**(`transport_deadline`)で行う。`next_deadline` は購読
    // 確立後に keep-alive 期限で常に Some になり、pump に永久に到達しなくなる(実測)。
    if s.stack.transport_deadline().is_some() {
        return 0; // まだ保留中(ACK 期限など)。呼び出し側は期限まで待って再度 poll する。
    }
    pump(s, now_ms);
    s.drain_one(tx_out, tx_cap, tx_dst)
}

/// 次に [`sm_ctrl_poll`] を呼ぶべき時刻(ms)。`SM_NO_DEADLINE` = 期限なし。
///
/// TX キューに未排出があれば即時(`now_ms`)を返す。
#[no_mangle]
pub extern "C" fn sm_ctrl_next_deadline(now_ms: u64) -> u64 {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return SM_NO_DEADLINE;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    if !s.txq.is_empty() {
        return now_ms;
    }
    // UDP トランザクション進行中(BLE フェーズは除く)= コミッショナが次を発行できる状態。
    let udp_active = match s.activity {
        Activity::Idle => false,
        #[cfg(feature = "ble")]
        Activity::BlePairing { .. } | Activity::BleHandoff { .. } => false,
        _ => true,
    };
    let dl = match s.stack.next_deadline(now_ms) {
        Some(dl) => dl,
        // 静穏(ACK/再送なし)かつ UDP トランザクション進行中 = 即時に poll させて次を積ませる。
        None if udp_active => now_ms,
        None => SM_NO_DEADLINE,
    };
    // BTP の ACK / keep-alive / liveness 期限も併合する(§11.4、デバイス側 sm_next_deadline と同型)。
    #[cfg(feature = "ble")]
    let dl = match s.btp.next_deadline() {
        Some(btp_dl) => dl.min(btp_dl),
        None => dl,
    };
    dl
}

/// コントローライベントを立った順に 1 件取り出す。戻り値 = 取り出せたか。
#[no_mangle]
pub extern "C" fn sm_ctrl_take_event(out: *mut sm_ctrl_event_t) -> bool {
    if !CTRL_INITED.load(Ordering::SeqCst) || out.is_null() {
        return false;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    match s.events.pop_front() {
        Some(e) => {
            // SAFETY: caller が有効な out を与える契約。
            unsafe { *out = e };
            true
        }
        None => false,
    }
}

/// 運用ノードへ引数なしコマンドを invoke する(OnOff Toggle 等の最小。§11.1)。
///
/// live セッションが無ければ内部で CASE(resumption 可)を確立してから実行する。
/// 完了は [`sm_ctrl_take_event`] の INVOKE_DONE / INVOKE_FAILED で観測する。
/// 戻り値: 0=OK、-1=未初期化、-3=未知ノード、-4=CASE 開始失敗、-10=busy。
#[no_mangle]
pub extern "C" fn sm_ctrl_invoke(
    node_id: u64,
    endpoint: u16,
    cluster: u32,
    command: u32,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return -1;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    let rc = start_operation(
        s,
        node_id,
        PendingOp::Invoke {
            ep: endpoint,
            cluster,
            cmd: command,
        },
        now_ms,
    );
    if rc == 0 {
        pump(s, now_ms);
    }
    rc
}

/// 運用ノードのスカラ属性を read する(§11.1)。
///
/// live セッションが無ければ内部で CASE を確立してから実行する。値は
/// [`sm_ctrl_take_event`] の READ_DONE(`value_u64` / `value_is_null`)で返る。
/// 戻り値: 0=OK、-1=未初期化、-3=未知ノード、-4=CASE 開始失敗、-10=busy。
#[no_mangle]
pub extern "C" fn sm_ctrl_read_scalar(
    node_id: u64,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return -1;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    let rc = start_operation(
        s,
        node_id,
        PendingOp::Read {
            ep: endpoint,
            cluster,
            attr: attribute,
        },
        now_ms,
    );
    if rc == 0 {
        pump(s, now_ms);
    }
    rc
}

/// 引数付きコマンドを invoke する(LevelControl MoveToLevel 等。§11.1 の拡張)。
///
/// `args` は context tag 0..`n_args`-1 の順に平坦化されたスカラ列
/// ([`sm_attr_value_t`]。`sm_cluster_def_t` の invoke ハンドラと同じ表現)。`n_args` の
/// 上限は 4。`args` が NULL / `n_args` = 0 なら [`sm_ctrl_invoke`] と等価。
/// 完了は INVOKE_DONE / INVOKE_FAILED。
///
/// 戻り値: 0=OK、-1=未初期化、-3=未知ノード、-4=CASE 開始失敗、-5=引数過多、-10=busy。
#[no_mangle]
pub extern "C" fn sm_ctrl_invoke_args(
    node_id: u64,
    endpoint: u16,
    cluster: u32,
    command: u32,
    args: *const sm_attr_value_t,
    n_args: usize,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return -1;
    }
    if n_args > MAX_OP_ARGS || (n_args > 0 && args.is_null()) {
        return -5;
    }
    // SAFETY: 単線契約。args は n_args 要素を指す契約。
    let s = unsafe { ctrl_shim() };
    s.op_args.clear();
    for i in 0..n_args {
        let v = unsafe { *args.add(i) };
        let _ = s.op_args.push(v);
    }
    let rc = start_operation(
        s,
        node_id,
        PendingOp::Invoke {
            ep: endpoint,
            cluster,
            cmd: command,
        },
        now_ms,
    );
    if rc == 0 {
        pump(s, now_ms);
    }
    rc
}

/// 運用ノードのスカラ属性へ write する(§11.1 の拡張)。
///
/// 完了は [`sm_ctrl_take_event`] の WRITE_DONE / WRITE_FAILED(`status` = IM ステータス)。
/// 戻り値: 0=OK、-1=未初期化/NULL、-3=未知ノード、-4=CASE 開始失敗、-10=busy。
#[no_mangle]
pub extern "C" fn sm_ctrl_write_scalar(
    node_id: u64,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    value: *const sm_attr_value_t,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) || value.is_null() {
        return -1;
    }
    // SAFETY: 単線契約。value は有効な sm_attr_value_t を指す契約。
    let s = unsafe { ctrl_shim() };
    let v = unsafe { *value };
    s.op_args.clear();
    let _ = s.op_args.push(v);
    let rc = start_operation(
        s,
        node_id,
        PendingOp::Write {
            ep: endpoint,
            cluster,
            attr: attribute,
        },
        now_ms,
    );
    if rc == 0 {
        pump(s, now_ms);
    }
    rc
}

/// 運用ノードのスカラ属性を subscribe する(§11.1 の拡張)。
///
/// プライミング完了で SUBSCRIBE_DONE(`value_u64` = 購読 ID)、以降デバイス発レポートごとに
/// SM_CTRL_EV_REPORT(`value_u64` / `value_is_null` = 最新値)。購読は 1 本のみ保持する。
/// 戻り値: 0=OK、-1=未初期化、-3=未知ノード、-4=CASE 開始失敗、-10=busy。
#[no_mangle]
pub extern "C" fn sm_ctrl_subscribe(
    node_id: u64,
    endpoint: u16,
    cluster: u32,
    attribute: u32,
    min_interval_s: u16,
    max_interval_s: u16,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return -1;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    s.op_args.clear();
    let rc = start_operation(
        s,
        node_id,
        PendingOp::Subscribe {
            ep: endpoint,
            cluster,
            attr: attribute,
            min_s: min_interval_s,
            max_s: max_interval_s,
        },
        now_ms,
    );
    if rc == 0 {
        pump(s, now_ms);
    }
    rc
}

/// operational(`_matter._tcp`)解決クエリを生成する(§11.1)。戻り値 = クエリ長(0 = 失敗)。
///
/// `at` が非 NULL のときはそのアドレス(QU ユニキャスト直指定 = `--at` 相当)へ、NULL なら
/// mDNS マルチキャストへ。宛先ポートは常に 5353 に上書きする。C++ は返ったバイト列を
/// `tx_dst` 宛に mDNS ソケットで送り、応答を [`sm_ctrl_mdns_rx`] へ給餌する。
#[no_mangle]
pub extern "C" fn sm_ctrl_resolve_start(
    node_id: u64,
    at: *const sm_addr_t,
    _now_ms: u64,
    tx_out: *mut u8,
    tx_cap: usize,
    tx_dst: *mut sm_addr_t,
) -> usize {
    if !CTRL_INITED.load(Ordering::SeqCst) || tx_out.is_null() {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    let mut q = [0u8; 256];
    let Ok(len) =
        MdnsClient::build_resolve_operational(&mut q, &s.compressed_fabric, node_id, true)
    else {
        return 0;
    };
    if len > tx_cap {
        return 0;
    }
    // SAFETY: caller が tx_cap バイトの tx_out を与える契約。
    unsafe { core::ptr::copy_nonoverlapping(q.as_ptr(), tx_out, len) };
    if !tx_dst.is_null() {
        let mut dst = if at.is_null() {
            multicast_dst(false, 0)
        } else {
            // SAFETY: at 非 NULL のとき有効な sm_addr_t。
            unsafe { *at }
        };
        dst.port = MDNS_PORT;
        // SAFETY: 同上。
        unsafe { *tx_dst = dst };
    }
    len
}

/// mDNS 応答を給餌して operational アドレスを解決する。戻り値: 0=解決、-1=未初期化/NULL、-2=不一致。
///
/// 既知ノード(ノード帳)の運用アドレスを更新し、成功時に RESOLVE_DONE イベントを立てる。
#[no_mangle]
pub extern "C" fn sm_ctrl_mdns_rx(
    pkt: *const u8,
    len: usize,
    _src: *const sm_addr_t,
    now_ms: u64,
) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) || pkt.is_null() {
        return -1;
    }
    #[cfg(not(feature = "ble"))]
    let _ = now_ms; // handoff(now_ms 使用)は ble 有効時のみ。
                    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    let p = unsafe { core::slice::from_raw_parts(pkt, len) };
    let compressed = s.compressed_fabric;
    for i in 0..s.nodes.len() {
        let node_id = s.nodes[i].node_id;
        if let Some(node) = MdnsClient::parse_operational(p, &compressed, node_id) {
            // IPv4 優先、無ければ最初のアドレス。
            let ip = node
                .addrs
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| node.addrs.iter().next())
                .copied();
            if let Some(ip) = ip {
                let port = if node.port != 0 {
                    node.port
                } else {
                    MATTER_PORT
                };
                let addr = SocketAddr::new(ip, port);
                s.nodes[i].addr = addr;
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_RESOLVE_DONE);
                ev.node_id = node_id;
                s.push_event(ev);
                // BLE→UDP handoff(§11.4): BLE フェーズ完了後にこのノードを解決したら、
                // コミッショナのピアを運用 UDP に差し替え・保留解除し、UDP pump(drive_pairing)
                // に載せ替える。以降 C++ は sm_ctrl_udp_rx / sm_ctrl_poll で CASE→Complete を回す。
                #[cfg(feature = "ble")]
                if matches!(s.activity, Activity::BleHandoff { node_id: n } if n == node_id) {
                    if let Some(comm) = s.comm.as_mut() {
                        comm.set_peer(PeerAddr::Udp(addr));
                        comm.resume();
                    }
                    s.activity = Activity::Pairing { node_id, addr };
                    s.last_pair_phase = u8::MAX;
                    pump(s, now_ms); // sigma1(start_case)を TX キューへ積む。
                }
                return 0;
            }
        }
    }
    -2
}

/// 既知ノードの現在の運用アドレスを取得する。戻り値 = ノードが存在するか。
#[no_mangle]
pub extern "C" fn sm_ctrl_node_addr(node_id: u64, out: *mut sm_addr_t) -> bool {
    if !CTRL_INITED.load(Ordering::SeqCst) || out.is_null() {
        return false;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    match s.node_index(node_id) {
        Some(i) => {
            // SAFETY: caller が有効な out を与える契約。
            unsafe { *out = socket_to_smaddr(s.nodes[i].addr) };
            true
        }
        None => false,
    }
}

/// 既知ノードの運用アドレスを直接設定する(Thread/SRP 等、mDNS 以外の解決経路用)。
///
/// Thread では運用アドレス解決が mDNS ではなく SRP(ボーダー/ハブ自身が SRP サーバ)に
/// なるため、C++ 側が `otSrpServerGetNextHost()` 列挙などで得たアドレスをノード帳へ
/// 反映するための入口(F8b、docs/design/p4-thread-controller.md §3)。
/// 内部処理は [`sm_ctrl_mdns_rx`] の解決成功時と同じ(ノード帳更新 + RESOLVE_DONE)。
///
/// 戻り値: 0=OK、-1=未初期化/NULL、-2=ノード帳に `node_id` なし。
#[no_mangle]
pub extern "C" fn sm_ctrl_set_node_addr(node_id: u64, addr: *const sm_addr_t) -> i32 {
    if !CTRL_INITED.load(Ordering::SeqCst) || addr.is_null() {
        return -1;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    let Some(i) = s.node_index(node_id) else {
        return -2;
    };
    // SAFETY: caller が有効な sm_addr_t を与える契約。
    let mut a = unsafe { *addr };
    if a.port == 0 {
        a.port = MATTER_PORT; // port 省略は運用ポート 5540 とみなす。
    }
    s.nodes[i].addr = smaddr_to_socket(&a);
    let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_RESOLVE_DONE);
    ev.node_id = node_id;
    s.push_event(ev);
    s.persist_nodes();
    0
}

/// 現在の管理ノード数(ノード帳のエントリ数)。
#[no_mangle]
pub extern "C" fn sm_ctrl_node_count() -> usize {
    if !CTRL_INITED.load(Ordering::SeqCst) {
        return 0;
    }
    // SAFETY: 単線契約。
    let s = unsafe { ctrl_shim() };
    s.nodes.len()
}

// ==========================================================================
// BLE central 給餌(F7b、docs/design/c-ffi-shim.md §11.4)
//
// C++ 所有の BLE central(NimBLE central: scan/connect/C1 write/C2 subscribe/indication)
// から BTP central を給餌し、`pairing ble-wifi` / `ble-thread` を C コントローラで成立させる。
// デバイス側シム(§9)の鏡像。ヘッダは常時宣言し、ble 無効ビルドでは SM_ERR / 0 を返す。
// ==========================================================================

/// 再組立済み 1 SDU を `out` にコピーして長さを返す(`Btp::recv` の借用を切る)。
#[cfg(feature = "ble")]
fn take_sdu_ctrl(btp: &mut Btp<CTRL_BTP_WINDOW>, out: &mut [u8]) -> Option<usize> {
    let sdu = btp.recv()?;
    let n = sdu.len();
    out[..n].copy_from_slice(sdu);
    Some(n)
}

/// BTP 上でコミッショナを進捗が止まるまで駆動する(BLE 版 [`drive_pairing`])。
///
/// 送信は BTP へ載せる(排出は `sm_ctrl_ble_poll`)。AddNOC + ネットワーク投入 +
/// ConnectNetwork を経て Phase::Case 直前で保留(`suspend_before_case`)されると
/// [`SM_CTRL_EV_BLE_DONE`] を立て、`Activity::BleHandoff` へ遷移する(§11.4)。
#[cfg(feature = "ble")]
fn drive_ble_commission(s: &mut CtrlShim, node_id: u64, now: u64) {
    loop {
        let mut scratch = [0u8; MAX_PACKET_SIZE];
        // comm / stack は別フィールド(disjoint borrow)。out は Copy でブロック外へ返す。
        let (out, prev) = {
            let Some(comm) = s.comm.as_mut() else {
                s.activity = Activity::Idle;
                return;
            };
            let prev = comm.phase();
            let out = comm.drive(&mut s.stack, now, &mut scratch);
            (out, prev)
        };
        if let Some(dir) = out.send {
            // BLE フェーズの送信はすべて BTP 宛(commissioner の peer = Ble)。
            if matches!(dir.addr, PeerAddr::Ble(_)) {
                let _ = s.btp.send(&scratch[..dir.len], now);
            }
        }
        let code = phase_code(out.phase);
        if code != s.last_pair_phase {
            s.last_pair_phase = code;
            let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_PHASE);
            ev.phase = code;
            ev.node_id = node_id;
            s.push_event(ev);
        }
        match out.phase {
            // AddNOC + ネットワーク資格情報投入 + ConnectNetwork まで完了し、CASE を保留した。
            // BLE フェーズ完了。ノードを帳へ暫定登録(handoff の resolve/handle 対象)して
            // BLE_DONE を立てる。運用アドレスは handoff 後に確定する。
            Phase::Case if out.send.is_none() => {
                let placeholder =
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MATTER_PORT));
                s.set_node(node_id, placeholder, None);
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_BLE_DONE);
                ev.node_id = node_id;
                s.push_event(ev);
                s.activity = Activity::BleHandoff { node_id };
                // issue_noc で next_serial が進んだ CA を永続化(クラッシュ耐性)。
                s.persist_ca();
                return;
            }
            Phase::Done { session } => {
                // 稀: suspend 無しで CASE まで BLE 上で完走したケース(防御的に完了扱い)。
                let addr =
                    s.node_index(node_id)
                        .map(|i| s.nodes[i].addr)
                        .unwrap_or(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::UNSPECIFIED,
                            MATTER_PORT,
                        )));
                s.set_node(node_id, addr, Some(session));
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_COMPLETE);
                ev.node_id = node_id;
                s.push_event(ev);
                s.comm = None;
                s.activity = Activity::Idle;
                s.persist_ca();
                s.persist_nodes();
                s.persist_resumption(node_id);
                return;
            }
            Phase::Failed { stage, reason } => {
                let mut ev = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_FAILED);
                ev.phase = stage;
                ev.status = commission_error_code(reason);
                ev.node_id = node_id;
                s.push_event(ev);
                s.comm = None;
                s.activity = Activity::Idle;
                return;
            }
            _ => {}
        }
        if out.send.is_none() && out.phase == prev {
            return; // 次はイベント待ち(indication が来るまで進めない)。
        }
    }
}

/// BTP で受けた応答を捌き、コミッショナを進める(`sm_ctrl_ble_event(C2_INDICATION)` の後段)。
///
/// 1. 再組立済み SDU を `handle_rx` に配り、SC 継続応答を BTP へ載せる。
/// 2. BTP 確立後はコミッショナを駆動する(次のリクエストを BTP へ載せる)。
///
/// BLE では MRP を格下げ(unreliable)するため handle_rx は Matter 層 ACK を産まない。
/// よって 1 サイクルの BTP 送信は「SC 継続 応答」か「次リクエスト」のどちらか一方(排他)で、
/// `Btp::send`(1 SDU ずつ)の制約を満たす。
#[cfg(feature = "ble")]
fn ble_service(s: &mut CtrlShim, node_id: u64, now: u64) {
    let Some(conn) = s.ble_conn else {
        return;
    };
    let mut sdu = [0u8; MAX_RX_PACKET_SIZE];
    let mut txc = [0u8; MAX_RX_PACKET_SIZE];
    // take_sdu_ctrl は s.btp の借用を都度切る(次行で s.stack を可変借用するため)。
    while let Some(slen) = take_sdu_ctrl(&mut s.btp, &mut sdu) {
        if let Some(d) = s
            .stack
            .handle_rx(&mut sdu[..slen], PeerAddr::Ble(conn), now, &mut txc)
        {
            if matches!(d.addr, PeerAddr::Ble(_)) {
                let _ = s.btp.send(&txc[..d.len], now);
            }
        }
    }
    if s.btp.is_established() {
        drive_ble_commission(s, node_id, now);
    }
}

/// commissionable 広告の service data(0xFFF6、8 バイト)から discriminator を照合する(§11.4)。
///
/// `svc_data` は BlueZ/NimBLE が届ける 0xFFF6 service data payload(先頭 8 バイトを使う)。
/// 一致で `true`。ble 無効ビルドは常に `false`。初期化不要(純関数)。
#[no_mangle]
pub extern "C" fn sm_ctrl_match_adv(svc_data: *const u8, len: usize, discriminator: u16) -> bool {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (svc_data, len, discriminator);
        false
    }
    #[cfg(feature = "ble")]
    {
        if svc_data.is_null() || len < 8 {
            return false;
        }
        // SAFETY: caller が len バイトの svc_data を与える契約。
        let b = unsafe { core::slice::from_raw_parts(svc_data, len) };
        let mut sd = [0u8; 8];
        sd.copy_from_slice(&b[..8]);
        match AdvData::parse_service_data(&sd) {
            Ok(ad) => ad.discriminator == (discriminator & 0x0FFF),
            Err(_) => false,
        }
    }
}

/// BLE(BTP)コミッショニングを開始する(§11.4)。
///
/// `kind`: 0=WiFi(`cred1`=SSID、`cred2`=パスフレーズ)、1=Thread(`cred1`=dataset TLV、
/// `cred2` 未使用)。AddNOC 後にネットワーク資格情報を投入し ConnectNetwork まで BTP 上で
/// 進め、CASE 直前で保留して [`SM_CTRL_EV_BLE_DONE`] を立てる(以降 §11.4 の handoff)。
///
/// 呼び出し前に C++ は scan([`sm_ctrl_match_adv`])→ connect 済みであること。以降
/// CONNECTED/C2_SUBSCRIBED/C2_INDICATION を [`sm_ctrl_ble_event`] で、C1 write を
/// [`sm_ctrl_ble_poll`] で給餌する。
///
/// 戻り値: 0=OK、-1=未初期化/ble 無効、-2=busy、-3=資格情報不正、-4=commission 拒否。
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn sm_ctrl_ble_pair_start(
    node_id: u64,
    passcode: u32,
    kind: u8,
    cred1: *const u8,
    cred1_len: usize,
    cred2: *const u8,
    cred2_len: usize,
    now_ms: u64,
) -> i32 {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (
            node_id, passcode, kind, cred1, cred1_len, cred2, cred2_len, now_ms,
        );
        -1
    }
    #[cfg(feature = "ble")]
    {
        if !CTRL_INITED.load(Ordering::SeqCst) {
            return -1;
        }
        // SAFETY: 単線契約。
        let s = unsafe { ctrl_shim() };
        if !matches!(s.activity, Activity::Idle) {
            return -2;
        }
        // 供給メモリは不動 → owned への &'static は健全(sm_ctrl_pair_start と同じ根拠)。
        let owned: &'static CtrlOwned = unsafe { &*(addr_of!(s.owned)) };
        let mut comm = Commissioner::new(&owned.ca, &owned.crypto, AttestationPolicy::Skip);
        // ネットワーク資格情報を設定する(kind で WiFi / Thread を選ぶ)。
        match kind {
            0 => {
                if cred1.is_null() || cred2.is_null() {
                    return -3;
                }
                // SAFETY: caller が len バイトの cred1/cred2 を与える契約。
                let ssid = unsafe { core::slice::from_raw_parts(cred1, cred1_len) };
                let pass = unsafe { core::slice::from_raw_parts(cred2, cred2_len) };
                if comm.set_wifi_credentials(ssid, pass).is_err() {
                    return -3;
                }
            }
            1 => {
                if cred1.is_null() {
                    return -3;
                }
                // SAFETY: 同上(cred1 = dataset TLV)。
                let ds = unsafe { core::slice::from_raw_parts(cred1, cred1_len) };
                if comm.set_thread_dataset(ds).is_err() {
                    return -3;
                }
            }
            _ => return -3,
        }
        comm.suspend_before_case(); // AddNOC 後に CASE を保留(handoff で運用 UDP へ)。
        if comm
            .commission(PeerAddr::Ble(BtpConnId(0)), passcode, node_id, now_ms)
            .is_err()
        {
            return -4;
        }
        s.comm = Some(comm);
        s.last_pair_phase = u8::MAX;
        // BTP central をリセットし、接続待ちに入る(CONNECTED で handshake を開始する)。
        s.btp.reset();
        s.ble_conn = None;
        s.ble_mtu = None;
        s.ble_subscribed = false;
        s.ble_hs_out.clear();
        s.activity = Activity::BlePairing { node_id };
        0
    }
}

/// BLE central のイベントを給餌する(§11.4)。デバイス側 [`sm_ble_event`] の鏡像。
///
/// - `SM_BLE_CONNECTED`(arg=ATT MTU): BTP handshake を能動開始する(Capabilities Request は
///   `sm_ctrl_ble_poll` が排出する)。
/// - `SM_BLE_C2_SUBSCRIBED`: C2 indication の購読完了(central 自身の購読状態)。
/// - `SM_BLE_C2_INDICATION`(= `SM_BLE_C1_WRITE` の ABI 値を流用): 受信 1 フラグメント。
/// - `SM_BLE_DISCONNECTED`: 切断。BTP をリセットする(handoff は継続)。
///
/// 戻り値: 0=OK、-1=未初期化/NULL/ble 無効、-2=2 本目の接続拒否、-3=BTP 給餌失敗。
#[no_mangle]
pub extern "C" fn sm_ctrl_ble_event(
    kind: sm_ble_event_kind_t,
    arg: u16,
    data: *const u8,
    len: usize,
    now_ms: u64,
) -> i32 {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (kind, arg, data, len, now_ms);
        -1
    }
    #[cfg(feature = "ble")]
    {
        if !CTRL_INITED.load(Ordering::SeqCst) {
            return -1;
        }
        // SAFETY: 単線契約。
        let s = unsafe { ctrl_shim() };
        match kind {
            sm_ble_event_kind_t::SM_BLE_CONNECTED => {
                if s.ble_conn.is_some() {
                    return -2; // 同時 1 接続。C++ は 2 本目を切断する。
                }
                s.ble_conn = Some(BtpConnId(0));
                s.ble_mtu = if arg == 0 { None } else { Some(arg) };
                s.ble_subscribed = false;
                s.btp.reset();
                // central: handshake を能動開始し、Capabilities Request を退避する
                //(sm_ctrl_ble_poll が最初に C1 write として排出する)。
                let mut hs = [0u8; HS_REQ_MAX];
                s.ble_hs_out.clear();
                if let Ok(n) = s.btp.start_handshake(&mut hs, s.ble_mtu, now_ms) {
                    let _ = s.ble_hs_out.extend_from_slice(&hs[..n.min(HS_REQ_MAX)]);
                }
                0
            }
            sm_ble_event_kind_t::SM_BLE_DISCONNECTED => {
                s.ble_conn = None;
                s.ble_subscribed = false;
                s.ble_hs_out.clear();
                s.btp.reset();
                // BLE フェーズ(BLE_DONE 前)の切断は、このセッションでは回復できない
                // (C++ 側は再接続を試みない設計)。Activity を畳んで PAIR_FAILED を
                // 立てないと、以降の pair/invoke が永久に busy(-2/-10)で弾かれる
                // (T4 実機で発覚。BleHandoff は BLE 切断後が正常経路なので触らない)。
                if let Activity::BlePairing { node_id } = s.activity {
                    let mut e = CtrlShim::ev(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_FAILED);
                    e.node_id = node_id;
                    s.push_event(e);
                    s.activity = Activity::Idle;
                }
                0
            }
            sm_ble_event_kind_t::SM_BLE_C2_SUBSCRIBED => {
                s.ble_subscribed = true;
                0
            }
            // C2 indication(central 受信)。ABI 値はデバイス側 C1_WRITE と共有する(§11.4)。
            sm_ble_event_kind_t::SM_BLE_C1_WRITE => {
                if data.is_null() || s.ble_conn.is_none() {
                    return -1;
                }
                // SAFETY: caller が有効な data/len を与える契約。
                let frag = unsafe { core::slice::from_raw_parts(data, len) };
                if s.btp.process_incoming(frag, s.ble_mtu, now_ms).is_err() {
                    return -3;
                }
                let node_id = match s.activity {
                    Activity::BlePairing { node_id } => node_id,
                    _ => 0,
                };
                ble_service(s, node_id, now_ms);
                0
            }
        }
    }
}

/// C1 write で送るべき次の BTP フラグメントを取り出す(§11.4)。0 = なし。
///
/// 最初に handshake request(Capabilities Request)を、以降は `process_outgoing` の
/// データセグメント / standalone ACK を排出する。C++ は 0 になるまで呼んで C1 write する。
/// BTP の再送・keep-alive ACK もここから産まれる。ble 無効ビルドは常に 0。
#[no_mangle]
pub extern "C" fn sm_ctrl_ble_poll(now_ms: u64, frag_out: *mut u8, cap: usize) -> usize {
    #[cfg(not(feature = "ble"))]
    {
        let _ = (now_ms, frag_out, cap);
        0
    }
    #[cfg(feature = "ble")]
    {
        if !CTRL_INITED.load(Ordering::SeqCst) || frag_out.is_null() {
            return 0;
        }
        // SAFETY: 単線契約。
        let s = unsafe { ctrl_shim() };
        let out = unsafe { core::slice::from_raw_parts_mut(frag_out, cap) };
        // 1) 保留中の handshake request を先に排出する。
        if !s.ble_hs_out.is_empty() {
            let n = s.ble_hs_out.len();
            if n > cap {
                return 0;
            }
            out[..n].copy_from_slice(&s.ble_hs_out);
            s.ble_hs_out.clear();
            return n;
        }
        if s.ble_conn.is_none() {
            return 0;
        }
        s.btp.process_outgoing(out, s.ble_mtu, now_ms).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    //! コントローラ C FFI の単体テスト(context_size / init / イベントラウンドトリップ)。
    //!
    //! フルコミッショニング E2E は `ctest/controller.cpp`(POSIX、供給メモリ malloc)で
    //! 既存デバイスシム相手に検証する。ここでは C ABI 境界と供給メモリ経路・単一 static
    //! 契約(init → deinit → 再 init = プロセス再起動相当)を確かめる。

    use super::*;
    use std::alloc::{alloc, dealloc, Layout};
    use std::sync::Mutex;

    // --- テスト用インメモリ KVS(C コールバックから触る) ---
    static KVS: Mutex<Vec<(Vec<u8>, Vec<u8>)>> = Mutex::new(Vec::new());

    fn key_of(key: *const core::ffi::c_char) -> Vec<u8> {
        let mut out = Vec::new();
        let mut p = key as *const u8;
        // SAFETY: テストコールバックは NUL 終端 C 文字列を受け取る。
        unsafe {
            while *p != 0 {
                out.push(*p);
                p = p.add(1);
            }
        }
        out
    }

    extern "C" fn t_kvs_get(
        _ctx: *mut core::ffi::c_void,
        key: *const core::ffi::c_char,
        buf: *mut u8,
        cap: usize,
    ) -> i32 {
        let k = key_of(key);
        let store = KVS.lock().unwrap();
        match store.iter().find(|(kk, _)| *kk == k) {
            Some((_, v)) => {
                if v.len() <= cap {
                    // SAFETY: cap バイトの buf(呼び出し側契約)。
                    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), buf, v.len()) };
                }
                v.len() as i32
            }
            None => -1,
        }
    }

    extern "C" fn t_kvs_set(
        _ctx: *mut core::ffi::c_void,
        key: *const core::ffi::c_char,
        val: *const u8,
        len: usize,
        // extern "C" 署名は SmKvsSet と一致させる。
    ) -> i32 {
        let k = key_of(key);
        // SAFETY: len バイトの val。
        let v = unsafe { core::slice::from_raw_parts(val, len) }.to_vec();
        let mut store = KVS.lock().unwrap();
        if let Some(e) = store.iter_mut().find(|(kk, _)| *kk == k) {
            e.1 = v;
        } else {
            store.push((k, v));
        }
        0
    }

    extern "C" fn t_kvs_delete(_ctx: *mut core::ffi::c_void, key: *const core::ffi::c_char) -> i32 {
        let k = key_of(key);
        let mut store = KVS.lock().unwrap();
        store.retain(|(kk, _)| *kk != k);
        0
    }

    // --- テスト用 PRNG(P-256 鍵生成に有効なスカラを供給する) ---
    static RNG_STATE: Mutex<u64> = Mutex::new(0x1234_5678_9abc_def0);
    extern "C" fn t_rng(_ctx: *mut core::ffi::c_void, buf: *mut u8, len: usize) {
        let mut st = RNG_STATE.lock().unwrap();
        // SAFETY: len バイトの buf。
        let out = unsafe { core::slice::from_raw_parts_mut(buf, len) };
        for b in out.iter_mut() {
            // xorshift64。
            let mut x = *st;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *st = x;
            *b = (x >> 33) as u8;
        }
    }

    fn make_cfg() -> sm_ctrl_config_t {
        sm_ctrl_config_t {
            fabric_id: 0xFAB0_0000_0000_0001,
            controller_node_id: 0x0000_0000_1122_3344,
            vendor_id: 0xFFF1,
            kvs_get: Some(t_kvs_get),
            kvs_set: Some(t_kvs_set),
            kvs_delete: Some(t_kvs_delete),
            kvs_ctx: core::ptr::null_mut(),
            rng_fill: Some(t_rng),
            rng_ctx: core::ptr::null_mut(),
        }
    }

    fn ctx_layout() -> Layout {
        Layout::from_size_align(sm_ctrl_context_size(), sm_ctrl_context_align()).unwrap()
    }

    /// 単一 static 契約のため、全チェックを 1 本のテストに集約する(device tests.rs と同様)。
    #[test]
    fn ctrl_lifecycle_roundtrip() {
        KVS.lock().unwrap().clear();

        // context_size / align は非ゼロで妥当。
        let size = sm_ctrl_context_size();
        let align = sm_ctrl_context_align();
        assert!(size > 0);
        assert!(align.is_power_of_two());

        let layout = ctx_layout();
        // SAFETY: layout は非ゼロサイズ。
        let mem = unsafe { alloc(layout) };
        assert!(!mem.is_null());

        // アラインメント/サイズ不足の防御を確認(仮初期化はまだしない)。
        assert_eq!(
            sm_ctrl_init(core::ptr::null_mut(), size, core::ptr::null(), 0),
            -1
        );
        let cfg = make_cfg();
        assert_eq!(sm_ctrl_init(mem, size - 1, &cfg, 0), -3);

        // 供給メモリに初期化(CA を新規生成 → KVS へ保存)。
        assert_eq!(sm_ctrl_init(mem, size, &cfg, 0), 0);
        // 二重 init 拒否。
        assert_eq!(sm_ctrl_init(mem, size, &cfg, 0), -2);
        assert_eq!(sm_ctrl_node_count(), 0);
        // まだイベントは無い。
        let mut ev = sm_ctrl_event_t {
            kind: sm_ctrl_event_kind_t::SM_CTRL_EV_NONE,
            phase: 0,
            status: 0,
            node_id: 0,
            value_u64: 0,
            value_is_null: false,
            resumed: false,
        };
        assert!(!sm_ctrl_take_event(&mut ev));

        // ca-state が KVS に保存されたこと。
        assert!(KVS.lock().unwrap().iter().any(|(k, _)| k == b"cast"));

        // Idle かつ未知ノードへの invoke は -3(pairing 開始前に確認する)。
        assert_eq!(sm_ctrl_invoke(0xDEAD, 1, 0x0006, 0x02, 0), -3);

        // コミッショニング開始(ダミー宛先。実デバイスは不要 — PASE 第 1 メッセージの
        // 生成と PAIR_PHASE イベント/TX キュー投入を確かめる)。
        let dst = sm_addr_t {
            ip: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            is_v6: false,
            port: 5540,
            scope_id: 0,
        };
        let node_id = 0x0000_0000_AABB_CCDD;
        assert_eq!(sm_ctrl_pair_start(node_id, 20202021, &dst, 0), 0);
        // busy 中の 2 本目は拒否。
        assert_eq!(sm_ctrl_pair_start(node_id, 20202021, &dst, 0), -2);

        // PAIR_PHASE(PASE=1)イベントが立つ。
        assert!(sm_ctrl_take_event(&mut ev));
        assert_eq!(ev.kind, sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_PHASE);
        assert_eq!(ev.phase, phase_code(Phase::Pase));
        assert_eq!(ev.node_id, node_id);

        // TX キューに PbkdfParamRequest が積まれている(next_deadline は即時)。
        assert_eq!(sm_ctrl_next_deadline(1000), 1000);
        let mut tx = [0u8; MAX_PACKET_SIZE];
        let mut tx_dst = sm_addr_t {
            ip: [0; 16],
            is_v6: false,
            port: 0,
            scope_id: 0,
        };
        let n = sm_ctrl_poll(0, tx.as_mut_ptr(), tx.len(), &mut tx_dst);
        assert!(n > 0, "PbkdfParamRequest should be emitted");
        assert_eq!(tx_dst.port, 5540);
        assert!(!tx_dst.is_v6);

        // pairing 進行中(Idle でない)の新規要求は busy(-10)で拒否される。
        assert_eq!(sm_ctrl_invoke(0xDEAD, 1, 0x0006, 0x02, 0), -10);

        // deinit → 再 init(プロセス再起動相当)。CA/ノード帳を KVS から復元する。
        sm_ctrl_deinit();
        assert_eq!(sm_ctrl_node_count(), 0); // deinit 後は未初期化 → 0。

        // 再初期化: 保存済み ca-state(b"cast")から CA を復元する。
        assert_eq!(sm_ctrl_init(mem, size, &cfg, 0), 0);
        // ノード帳は空(コミッショニング完了していないため保存されていない)。
        assert_eq!(sm_ctrl_node_count(), 0);

        // --- F8b: sm_ctrl_set_node_addr(Thread/SRP 由来のアドレス直接設定) ---
        // 未知ノード / NULL の防御(この時点でノード帳は空)。
        assert_eq!(sm_ctrl_set_node_addr(node_id, &dst), -2);
        assert_eq!(sm_ctrl_set_node_addr(node_id, core::ptr::null()), -1);
        sm_ctrl_deinit();

        // ノード帳(b"nods")を仕込んで再 init → 既知ノードのアドレスを差し替える。
        {
            let mut recs: heapless::Vec<nodes_codec::NodeRecord, MAX_NODES> = heapless::Vec::new();
            let old = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 5540));
            recs.push(nodes_codec::NodeRecord::new(node_id, old, "").unwrap())
                .unwrap();
            let mut buf = [0u8; nodes_codec::nodes_max_len(MAX_NODES)];
            let len = nodes_codec::encode_nodes(&mut buf, &recs).unwrap();
            // NOTE: `c"nods"` リテラルは cbindgen の parser が読めない(ヘッダ生成が
            // 落ちる)ため、NUL 終端バイト列 + キャストで書く。
            #[allow(clippy::manual_c_str_literals)]
            t_kvs_set(
                core::ptr::null_mut(),
                b"nods\0".as_ptr() as *const core::ffi::c_char,
                buf.as_ptr(),
                len,
            );
        }
        assert_eq!(sm_ctrl_init(mem, size, &cfg, 0), 0);
        assert_eq!(sm_ctrl_node_count(), 1);
        // Thread の ML-EID 相当(IPv6 + scope_id、port は 0 = 既定 5540 とみなす)。
        let mut ip6 = [0u8; 16];
        ip6[0] = 0xfd;
        ip6[15] = 0x02;
        let thread_addr = sm_addr_t {
            ip: ip6,
            is_v6: true,
            port: 0,
            scope_id: 3,
        };
        assert_eq!(sm_ctrl_set_node_addr(node_id, &thread_addr), 0);
        assert_eq!(sm_ctrl_set_node_addr(0xDEAD, &thread_addr), -2);
        // ノード帳に反映され、port は 5540 に補完されている。
        let mut got = sm_addr_t {
            ip: [0; 16],
            is_v6: false,
            port: 0,
            scope_id: 0,
        };
        assert!(sm_ctrl_node_addr(node_id, &mut got));
        assert!(got.is_v6);
        assert_eq!(got.ip, ip6);
        assert_eq!(got.port, MATTER_PORT);
        // RESOLVE_DONE イベント(mDNS 解決成功時と同じ通知)。
        assert!(sm_ctrl_take_event(&mut ev));
        assert_eq!(ev.kind, sm_ctrl_event_kind_t::SM_CTRL_EV_RESOLVE_DONE);
        assert_eq!(ev.node_id, node_id);
        sm_ctrl_deinit();
        // 後続(BLE)ブロックのためにノード帳を消す。
        KVS.lock().unwrap().retain(|(k, _)| k != b"nods");

        // --- BLE central(F7b、§11.4)ハンドシェイク + PASE 発行のラウンドトリップ ---
        // 単一 static 契約のため本テストに集約する(device tests.rs と同方針)。
        #[cfg(feature = "ble")]
        {
            use simple_matter::btp::gatt::AdvData;
            use simple_matter::btp::{Btp, BtpRole};

            assert_eq!(sm_ctrl_init(mem, size, &cfg, 0), 0);

            // (1) match_adv: 0xFFF6 service data から discriminator を照合する。
            let ad = AdvData {
                discriminator: 3840,
                vendor_id: 0xFFF1,
                product_id: 0x8000,
                additional_data: false,
                ext_announcement: false,
            };
            let sd = ad.service_data();
            assert!(sm_ctrl_match_adv(sd.as_ptr(), sd.len(), 3840));
            assert!(!sm_ctrl_match_adv(sd.as_ptr(), sd.len(), 1234));
            assert!(!sm_ctrl_match_adv(sd.as_ptr(), 4, 3840)); // 短すぎ。
            let bad = [0xFFu8; 8]; // OpCode 不正。
            assert!(!sm_ctrl_match_adv(bad.as_ptr(), bad.len(), 3840));

            // (2) BLE コミッショニング開始(WiFi 資格情報)。
            let ssid = b"iotap";
            let pass = b"hogeFugapiyo";
            let node_id = 0x0000_0000_AABB_CCDD;
            assert_eq!(
                sm_ctrl_ble_pair_start(
                    node_id,
                    20202021,
                    0, // wifi
                    ssid.as_ptr(),
                    ssid.len(),
                    pass.as_ptr(),
                    pass.len(),
                    1000,
                ),
                0
            );
            // busy 中の 2 本目は拒否。
            assert_eq!(
                sm_ctrl_ble_pair_start(
                    node_id,
                    20202021,
                    0,
                    ssid.as_ptr(),
                    ssid.len(),
                    pass.as_ptr(),
                    pass.len(),
                    1000
                ),
                -2
            );

            // (3) CONNECTED(mtu=247)→ handshake request を ble_poll で排出する。
            let mtu: u16 = 247;
            assert_eq!(
                sm_ctrl_ble_event(
                    sm_ble_event_kind_t::SM_BLE_CONNECTED,
                    mtu,
                    core::ptr::null(),
                    0,
                    1000
                ),
                0
            );
            // 2 本目の接続は拒否。
            assert_eq!(
                sm_ctrl_ble_event(
                    sm_ble_event_kind_t::SM_BLE_CONNECTED,
                    mtu,
                    core::ptr::null(),
                    0,
                    1000
                ),
                -2
            );
            let mut frag = [0u8; 512];
            let hlen = sm_ctrl_ble_poll(1000, frag.as_mut_ptr(), frag.len());
            assert!(hlen > 0, "handshake request expected");

            // (4) peripheral 側 BTP で handshake を受けて応答を返す。
            let mut peripheral = Btp::<6>::new(BtpRole::Peripheral);
            peripheral
                .process_incoming(&frag[..hlen], Some(mtu), 1000)
                .unwrap();
            let mut resp = [0u8; 512];
            let rlen = peripheral
                .process_outgoing(&mut resp, Some(mtu), 1000)
                .unwrap();
            assert!(rlen > 0, "handshake response expected");

            // (5) central が subscribe 済みとして handshake response を給餌 → BTP 確立 →
            //     PASE 第 1 メッセージ(PBKDFParamRequest)が生成される。
            assert_eq!(
                sm_ctrl_ble_event(
                    sm_ble_event_kind_t::SM_BLE_C2_SUBSCRIBED,
                    0,
                    core::ptr::null(),
                    0,
                    1000
                ),
                0
            );
            assert_eq!(
                sm_ctrl_ble_event(
                    sm_ble_event_kind_t::SM_BLE_C1_WRITE, // ABI 値を C2_INDICATION に流用(§11.4)
                    0,
                    resp.as_ptr(),
                    rlen,
                    1000,
                ),
                0
            );
            // PAIR_PHASE(PASE)イベントが立つ。
            let mut ev = sm_ctrl_event_t {
                kind: sm_ctrl_event_kind_t::SM_CTRL_EV_NONE,
                phase: 0,
                status: 0,
                node_id: 0,
                value_u64: 0,
                value_is_null: false,
                resumed: false,
            };
            assert!(sm_ctrl_take_event(&mut ev));
            assert_eq!(ev.kind, sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_PHASE);
            assert_eq!(ev.phase, phase_code(Phase::Pase));
            assert_eq!(ev.node_id, node_id);
            // PASE 第 1 フラグメントが ble_poll で取り出せる。
            let plen = sm_ctrl_ble_poll(1000, frag.as_mut_ptr(), frag.len());
            assert!(plen > 0, "PBKDFParamRequest fragment expected");

            sm_ctrl_deinit();
        }

        // SAFETY: alloc と同じ layout で解放する。
        unsafe { dealloc(mem, layout) };
    }

    /// スカラ read の TLV → `value_u64` 変換(§12.2 の f32 対応を含む)。
    ///
    /// f32 属性(CO2 / PM2.5 の MeasuredValue)は `f32::to_bits()` のビットパターンが
    /// そのまま載り、C++ 側の `memcpy` で元の値に戻ること。
    #[test]
    fn scalar_from_tlv_covers_floats() {
        // 整数系・bool・null は従来どおり。
        assert_eq!(scalar_from_tlv(&TlvValue::Boolean(true)), (1, false));
        assert_eq!(
            scalar_from_tlv(&TlvValue::UnsignedInteger(4100)),
            (4100, false)
        );
        assert_eq!(
            scalar_from_tlv(&TlvValue::SignedInteger(-2650)),
            (-2650i64 as u64, false)
        );
        assert_eq!(scalar_from_tlv(&TlvValue::Null), (0, true));

        // f32: ビットパターンが下位 32bit に載り、C++ 側の memcpy で復元できる。
        let co2 = 812.5f32;
        let (bits, is_null) = scalar_from_tlv(&TlvValue::Float(co2));
        assert!(!is_null);
        assert_eq!(bits, co2.to_bits() as u64);
        assert_eq!(bits >> 32, 0, "上位 32bit は 0(C++ は下位 32bit だけ見る)");
        assert_eq!(f32::from_bits(bits as u32), co2);

        // f64 は f32 へ丸めてから載せる(読み替えを 1 通りに保つ)。
        let (bits, _) = scalar_from_tlv(&TlvValue::Double(3.25f64));
        assert_eq!(f32::from_bits(bits as u32), 3.25f32);

        // 対象外の型は従来どおり (0, false)。
        assert_eq!(scalar_from_tlv(&TlvValue::Utf8String("x")), (0, false));
    }
}
