//! コミッショニングフローの Mealy 状態機械([`Commissioner`])。
//!
//! `docs/design/controller.md` §6.1 に基づく。単一コントローラ・IP 直結・attestation スキップ可の
//! 前提で chip の commissioning stage 列を最小化する。**入力は SC / IM のイベント
//! ([`ScEvent`] / [`ImEvent`])、出力は次のトランザクション開始**([`ControllerStack`] の
//! `start_*` 呼び出し)であり、送受信も暗号も持たない(統合層 [`ControllerStack`] が担う)。
//!
//! ```text
//!  Pase ─ PaseEstablished ─► ArmFailSafe ─ InvokeDone ─► Attestation(Skip 素通し)
//!    ─► Csr ─ CSRResponse → parse_csr ─► AddTrustedRoot ─► AddNoc(NOC 発行)
//!    ─► Case ─ CaseEstablished ─► Complete ─ InvokeDone ─► Done { session }
//!  任意の失敗 ─► Failed { stage, reason }
//! ```
//!
//! 各遷移で `emit`(開始)と `consume`(イベント消費)を交互に行う。統合層は
//! `handle_rx` / `poll` の後に [`Commissioner::drive`] を呼び、返る [`DriveOutcome`] の
//! `send`(あれば)を送出、`phase` を進捗として観測する(§6.2)。

use crate::cert::parse_csr;
use crate::crypto::{Crypto, Rng};
use crate::dm::meta::{ClusterId, EndpointId};
use crate::error::{Error, Result};
use crate::im::client::ImEvent;
use crate::im::wire::{CommandId, CommandPath, ImStatus};
use crate::sc::case::creds::{FabricStore, NocResolver};
use crate::sc::initiator::{ScEvent, ScFailReason};
use crate::stack::SendDirective;
use crate::tlv::{ContainerType, TlvElement, TlvReader, TlvTag, TlvValue};
use crate::transport::net::PeerAddr;
use crate::transport::session::SessionId;

use super::ca::{Ca, CONTROLLER_FABRIC_INDEX};
use super::ControllerStack;

use crate::fabric::MAX_CERT_TLV_LEN;

// --- クラスタ / コマンド ID ---
const CLUSTER_GENERAL_COMMISSIONING: u32 = 0x0030;
const CLUSTER_OPERATIONAL_CREDENTIALS: u32 = 0x003E;
const CMD_ARM_FAIL_SAFE: u32 = 0x00;
const CMD_COMMISSIONING_COMPLETE: u32 = 0x04;
const CMD_CSR_REQUEST: u32 = 0x04;
const CMD_ADD_NOC: u32 = 0x06;
const CMD_ADD_TRUSTED_ROOT: u32 = 0x0B;

/// fail-safe タイマの有効秒数(ArmFailSafe に載せる)。
const FAIL_SAFE_EXPIRY_S: u16 = 120;

/// CSRRequest の nonce(自作デバイス・自己整合テスト向けに固定。デバイスは署名対象として扱う)。
const CSR_NONCE: [u8; 32] = [0x5Au8; 32];

/// attestation の扱い(§6.4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy {
    /// DAC/PAI/CD を取得も検証もしない(自作デバイス・開発フローの既定)。
    Skip,
}

/// コミッショニング失敗の理由(§6.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionError {
    /// SC(PASE/CASE)ハンドシェイクが失敗した。
    Sc(ScFailReason),
    /// IM トランザクションが非成功ステータスで終端した。
    Im(ImStatus),
    /// デバイスが返したコマンド応答の errorCode / statusCode が非ゼロだった。
    Status(u64),
    /// NOC 発行(CA)に失敗した。
    Ca,
    /// CSR 解析・公開鍵抽出・署名検証に失敗した。
    Csr,
    /// 統合層(`start_*`)がエラーを返した(exchange/session 枯渇等)。
    Stack(Error),
    /// 予期しないイベント順序・内部状態違反。
    Protocol,
}

/// コミッショニングのフェーズ(§6.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 未開始。
    Idle,
    /// PASE ハンドシェイク中。
    Pase,
    /// ArmFailSafe 実行中。
    ArmFailSafe,
    /// attestation(`Skip` では素通し)。
    Attestation,
    /// CSRRequest 実行中。
    Csr,
    /// AddTrustedRootCertificate 実行中。
    AddTrustedRoot,
    /// AddNOC 実行中。
    AddNoc,
    /// CASE ハンドシェイク中。
    Case,
    /// CommissioningComplete 実行中(CASE 上)。
    Complete,
    /// 完了。以降アプリはこの CASE セッションで invoke/read する。
    Done {
        /// 確立した運用(CASE)セッション。
        session: SessionId,
    },
    /// 失敗して終端した。
    Failed {
        /// 失敗時のフェーズ番号(観測用)。
        stage: u8,
        /// 失敗理由。
        reason: CommissionError,
    },
}

impl Phase {
    /// 終端(Done / Failed / Idle)なら `true`。
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Phase::Idle | Phase::Done { .. } | Phase::Failed { .. }
        )
    }

    /// フェーズ番号(Failed の stage 用)。
    fn stage_code(self) -> u8 {
        match self {
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
            Phase::Failed { stage, .. } => stage,
        }
    }
}

/// [`Commissioner::drive`] の帰結。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriveOutcome {
    /// 現フェーズ(Done / Failed で終端)。
    pub phase: Phase,
    /// このドライブで発生した送信(あれば呼び出し側が送出する)。
    pub send: Option<SendDirective>,
}

/// コミッショニングフローの Mealy 状態機械(§6.1)。
///
/// `ca`(NOC 発行)・`crypto`(CSR 検証)を共有借用し、フェーズと待機状態のみを持つ。送受信・
/// 暗号は持たないため、フェーズ遷移は入出力列だけで検証できる。
pub struct Commissioner<'a, C: Crypto> {
    ca: &'a Ca<C>,
    crypto: &'a C,
    policy: AttestationPolicy,
    phase: Phase,
    /// `true` = イベント待ち、`false` = 次の開始を発行する。
    awaiting: bool,
    peer: PeerAddr,
    passcode: u32,
    target_node_id: u64,
    pase_session: Option<SessionId>,
    case_session: Option<SessionId>,
    device_pubkey: [u8; 65],
    scratch: [u8; MAX_CERT_TLV_LEN],
    /// `true` の間、AddNOC 完了後の [`Phase::Case`] 開始(sigma1 送出)を保留する。
    ///
    /// BLE で AddNOC まで進めたあと、CASE を**別トランスポート(運用 UDP)**で行う
    /// 「方向 B」フロー用。呼び出し側は `drive` が `Phase::Case` を送信なしで返した時点で
    /// トランスポートを切り替え([`set_peer`](Self::set_peer))、[`resume`](Self::resume)で
    /// 保留を解除してから CASE を開始する。既定は `false`(従来どおり同一トランスポートで
    /// CASE まで連続実行)。
    suspend_before_case: bool,
}

impl<'a, C: Crypto> Commissioner<'a, C> {
    /// CA・crypto・attestation ポリシからコミッショナを作る(初期フェーズ = Idle)。
    pub fn new(ca: &'a Ca<C>, crypto: &'a C, policy: AttestationPolicy) -> Self {
        Self {
            ca,
            crypto,
            policy,
            phase: Phase::Idle,
            awaiting: false,
            peer: PeerAddr::Udp(core::net::SocketAddr::new(
                core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
                0,
            )),
            passcode: 0,
            target_node_id: 0,
            pase_session: None,
            case_session: None,
            device_pubkey: [0u8; 65],
            scratch: [0u8; MAX_CERT_TLV_LEN],
            suspend_before_case: false,
        }
    }

    /// AddNOC 完了後の CASE 開始を保留するようにする(方向 B: BLE→運用 UDP 遷移用)。
    ///
    /// [`commission`](Self::commission) の前後どちらでも呼べる。有効にすると `drive` は
    /// [`Phase::Case`] に到達しても sigma1 を送出せず、送信なしで `Phase::Case` を返す。
    /// 呼び出し側はそこで [`set_peer`](Self::set_peer) により運用アドレスへ切り替え、
    /// [`resume`](Self::resume) で保留を解除する。
    pub fn suspend_before_case(&mut self) {
        self.suspend_before_case = true;
    }

    /// [`suspend_before_case`](Self::suspend_before_case) の保留を解除し、次の `drive` で
    /// CASE(sigma1)を開始できるようにする。
    pub fn resume(&mut self) {
        self.suspend_before_case = false;
    }

    /// 以後のトランザクション(主に CASE の sigma1)の宛先ピアを差し替える。
    ///
    /// AddNOC まで BLE、CASE 以降を運用 UDP で行う方向 B フロー用。`Phase::Case` の
    /// `start_case` は本メソッドで設定したピアを使う。
    pub fn set_peer(&mut self, peer: PeerAddr) {
        self.peer = peer;
    }

    /// コミッショニングを開始する(Idle 以外では [`Error::InvalidState`] = Busy、§6.1)。
    ///
    /// 実際の PBKDFParamRequest 送出は最初の [`Commissioner::drive`] が行う。
    pub fn commission(
        &mut self,
        peer: PeerAddr,
        passcode: u32,
        node_id: u64,
        _now_ms: u64,
    ) -> Result<()> {
        if !matches!(self.phase, Phase::Idle) {
            return Err(Error::InvalidState);
        }
        self.peer = peer;
        self.passcode = passcode;
        self.target_node_id = node_id;
        self.phase = Phase::Pase;
        self.awaiting = false;
        Ok(())
    }

    /// 現フェーズ。
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// イベントを消費して 1 遷移進める(§6.1)。`stack` の `start_*` を呼ぶのはここだけ。
    ///
    /// `handle_rx` / `poll` のたびに呼ぶ。進展がなければ何もしない(同一フェーズを返す)。
    pub fn drive<R, F, const SS: usize, const EX: usize, const TX: usize, const RS: usize>(
        &mut self,
        stack: &mut ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> DriveOutcome
    where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        if self.phase.is_terminal() {
            return DriveOutcome {
                phase: self.phase,
                send: None,
            };
        }
        // attestation は `Skip` では即遷移(フェーズ表は常設、§6.4)。
        if matches!(self.phase, Phase::Attestation) {
            match self.policy {
                AttestationPolicy::Skip => {
                    self.phase = Phase::Csr;
                    self.awaiting = false;
                }
            }
        }

        // 方向 B: AddNOC 完了後、CASE 開始(sigma1)を保留する。呼び出し側が
        // トランスポートを運用 UDP に切り替え `resume()` するまで送信を出さない。
        if self.suspend_before_case && matches!(self.phase, Phase::Case) && !self.awaiting {
            return DriveOutcome {
                phase: self.phase,
                send: None,
            };
        }

        if self.awaiting {
            self.consume_event(stack);
            DriveOutcome {
                phase: self.phase,
                send: None,
            }
        } else {
            match self.emit_start(stack, now_ms, tx_out) {
                Ok(dir) => {
                    self.awaiting = true;
                    DriveOutcome {
                        phase: self.phase,
                        send: Some(dir),
                    }
                }
                Err(e) => {
                    self.enter_failed(e);
                    DriveOutcome {
                        phase: self.phase,
                        send: None,
                    }
                }
            }
        }
    }

    /// 現フェーズの開始(最初の送信)を発行する。
    fn emit_start<R, F, const SS: usize, const EX: usize, const TX: usize, const RS: usize>(
        &mut self,
        stack: &mut ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> core::result::Result<SendDirective, CommissionError>
    where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        match self.phase {
            Phase::Pase => stack
                .start_pase(self.peer, self.passcode, now_ms, tx_out)
                .map_err(CommissionError::Stack),
            Phase::ArmFailSafe => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_GENERAL_COMMISSIONING, CMD_ARM_FAIL_SAFE),
                        |w, t| {
                            w.start_struct(t)?;
                            w.write_u16(&cx(0), FAIL_SAFE_EXPIRY_S)?;
                            w.write_u64(&cx(1), 0)?; // breadcrumb
                            w.end_container()
                        },
                        now_ms,
                        tx_out,
                    )
                    .map_err(CommissionError::Stack)
            }
            Phase::Csr => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_OPERATIONAL_CREDENTIALS, CMD_CSR_REQUEST),
                        |w, t| {
                            w.start_struct(t)?;
                            w.write_bytes(&cx(0), &CSR_NONCE)?;
                            w.end_container()
                        },
                        now_ms,
                        tx_out,
                    )
                    .map_err(CommissionError::Stack)
            }
            Phase::AddTrustedRoot => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                let rcac = self.ca.rcac();
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_OPERATIONAL_CREDENTIALS, CMD_ADD_TRUSTED_ROOT),
                        move |w, t| {
                            w.start_struct(t)?;
                            w.write_bytes(&cx(0), rcac)?;
                            w.end_container()
                        },
                        now_ms,
                        tx_out,
                    )
                    .map_err(CommissionError::Stack)
            }
            Phase::AddNoc => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                let noc_len = self
                    .ca
                    .issue_noc(
                        self.crypto,
                        &self.device_pubkey,
                        self.target_node_id,
                        &mut self.scratch,
                    )
                    .map_err(|_| CommissionError::Ca)?;
                let noc = &self.scratch[..noc_len];
                let ipk = self.ca.ipk_epoch_key();
                let admin = self.ca.controller_node_id();
                let vendor = self.ca.vendor_id();
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_OPERATIONAL_CREDENTIALS, CMD_ADD_NOC),
                        move |w, t| {
                            w.start_struct(t)?;
                            w.write_bytes(&cx(0), noc)?; // NOCValue
                            w.write_bytes(&cx(2), ipk)?; // IPKValue(epoch key)
                            w.write_u64(&cx(3), admin)?; // CaseAdminSubject
                            w.write_u16(&cx(4), vendor)?; // AdminVendorId
                            w.end_container()
                        },
                        now_ms,
                        tx_out,
                    )
                    .map_err(CommissionError::Stack)
            }
            Phase::Case => stack
                .start_case(
                    self.peer,
                    CONTROLLER_FABRIC_INDEX,
                    self.target_node_id,
                    now_ms,
                    tx_out,
                )
                .map_err(CommissionError::Stack),
            Phase::Complete => {
                let session = self.case_session.ok_or(CommissionError::Protocol)?;
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_GENERAL_COMMISSIONING, CMD_COMMISSIONING_COMPLETE),
                        |w, t| {
                            w.start_struct(t)?;
                            w.end_container()
                        },
                        now_ms,
                        tx_out,
                    )
                    .map_err(CommissionError::Stack)
            }
            _ => Err(CommissionError::Protocol),
        }
    }

    /// SC / IM のイベントを消費してフェーズを進める。
    fn consume_event<R, F, const SS: usize, const EX: usize, const TX: usize, const RS: usize>(
        &mut self,
        stack: &mut ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
    ) where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        match self.phase {
            Phase::Pase => match stack.sc_take_event() {
                Some(ScEvent::PaseEstablished { session }) => {
                    self.pase_session = Some(session);
                    self.advance(Phase::ArmFailSafe);
                }
                Some(ScEvent::Failed { reason, .. }) => {
                    self.enter_failed(CommissionError::Sc(reason))
                }
                Some(ScEvent::CaseEstablished { .. }) => {
                    self.enter_failed(CommissionError::Protocol)
                }
                None => {}
            },
            Phase::Case => match stack.sc_take_event() {
                Some(ScEvent::CaseEstablished { session, .. }) => {
                    self.case_session = Some(session);
                    self.advance(Phase::Complete);
                }
                Some(ScEvent::Failed { reason, .. }) => {
                    self.enter_failed(CommissionError::Sc(reason))
                }
                Some(ScEvent::PaseEstablished { .. }) => {
                    self.enter_failed(CommissionError::Protocol)
                }
                None => {}
            },
            // 残りは IM トランザクション。
            _ => {
                let ev = stack.im_take_event();
                let done = match ev {
                    Some(ImEvent::InvokeDone { status }) => {
                        if status.is_success() {
                            true
                        } else {
                            self.enter_failed(CommissionError::Im(status));
                            return;
                        }
                    }
                    Some(ImEvent::Failed { status }) => {
                        self.enter_failed(CommissionError::Im(status));
                        return;
                    }
                    Some(_) => {
                        self.enter_failed(CommissionError::Protocol);
                        return;
                    }
                    None => return,
                };
                if !done {
                    return;
                }
                self.on_invoke_done(stack);
            }
        }
    }

    /// IM Invoke 応答が成功した各フェーズの後処理。
    fn on_invoke_done<R, F, const SS: usize, const EX: usize, const TX: usize, const RS: usize>(
        &mut self,
        stack: &ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
    ) where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        match self.phase {
            Phase::ArmFailSafe => match response_status_code(stack.im_result()) {
                Ok(0) => self.advance(Phase::Attestation),
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            Phase::Csr => match extract_csr_pubkey(self.crypto, stack.im_result()) {
                Ok(pk) => {
                    self.device_pubkey = pk;
                    self.advance(Phase::AddTrustedRoot);
                }
                Err(_) => self.enter_failed(CommissionError::Csr),
            },
            // AddTrustedRootCertificate はステータスのみの応答(command 応答ではない)。
            Phase::AddTrustedRoot => self.advance(Phase::AddNoc),
            Phase::AddNoc => match response_status_code(stack.im_result()) {
                Ok(0) => self.advance(Phase::Case),
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            Phase::Complete => match response_status_code(stack.im_result()) {
                Ok(0) => {
                    let session = self.case_session.unwrap_or_else(|| SessionId::from_raw(0));
                    self.phase = Phase::Done { session };
                    self.awaiting = false;
                }
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            _ => self.enter_failed(CommissionError::Protocol),
        }
    }

    fn advance(&mut self, next: Phase) {
        self.phase = next;
        self.awaiting = false;
    }

    fn enter_failed(&mut self, reason: CommissionError) {
        let stage = self.phase.stage_code();
        self.phase = Phase::Failed { stage, reason };
        self.awaiting = false;
    }
}

// ==========================================================================
// TLV ヘルパ(応答デコード。§6.1 の「小さなヘルパ関数群」)
// ==========================================================================

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

fn cmd_path(cluster: u32, command: u32) -> CommandPath {
    CommandPath::new(EndpointId(0), ClusterId(cluster), CommandId(command))
}

/// 現在のコンテナ内で context タグ `ctx` の要素を探して返す(不一致要素はスキップ)。
///
/// マッチがコンテナ開始の場合、リーダはそのコンテナ内部に位置した状態で返る。
fn find_ctx<'a>(r: &mut TlvReader<'a>, ctx: u8) -> Result<TlvElement<'a>> {
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        if matches!(e.value, TlvValue::ContainerEnd) {
            return Err(Error::Decode);
        }
        if e.tag == TlvTag::ContextSpecific(ctx) {
            return Ok(e);
        }
        r.skip(&e)?;
    }
}

/// InvokeResponse 結果(連結 `InvokeResponseIB`)の先頭コマンド応答フィールドの内側に降りる。
///
/// `InvokeResponseIB { cx0: CommandDataIB { cx0: path, cx1: fields } }` の `fields` 内部に
/// リーダを位置させて返す(CommandStatusIB(cx1)のみの応答は [`Error::Decode`])。
fn enter_command_fields<'a>(result: &'a [u8]) -> Result<TlvReader<'a>> {
    let mut r = TlvReader::new(result);
    let ib = r.read_next()?.ok_or(Error::Decode)?;
    if ib.value.as_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let cmd = find_ctx(&mut r, 0)?; // CommandDataIB
    if cmd.value.as_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let fields = find_ctx(&mut r, 1)?; // CommandFields
    if fields.value.as_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    Ok(r)
}

/// コマンド応答フィールドの cx0(errorCode / statusCode の uint)を返す。
fn response_status_code(result: &[u8]) -> Result<u64> {
    let mut r = enter_command_fields(result)?;
    find_ctx(&mut r, 0)?.value.as_unsigned()
}

/// CSRResponse の NOCSRElements 内 CSR を取り出し、公開鍵を抽出・署名検証して返す。
fn extract_csr_pubkey<C: Crypto>(crypto: &C, result: &[u8]) -> Result<[u8; 65]> {
    let mut r = enter_command_fields(result)?;
    // fields.cx0 = NOCSRElements(bytes)。
    let nocsr = find_ctx(&mut r, 0)?.value.as_bytes()?;
    // NOCSRElements = struct { cx1: csr, cx2: nonce, .. }。
    let mut nr = TlvReader::new(nocsr);
    if nr.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let csr = find_ctx(&mut nr, 1)?.value.as_bytes()?;
    parse_csr(crypto, csr)
}
