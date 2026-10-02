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
//!    ─► [AddWifiNetwork ─► ConnectNetwork](set_wifi_credentials 設定時のみ)
//!    ─► Case ─ CaseEstablished ─► Complete ─ InvokeDone ─► Done { session }
//!  任意の失敗 ─► Failed { stage, reason }
//! ```
//!
//! 各遷移で `emit`(開始)と `consume`(イベント消費)を交互に行う。統合層は
//! `handle_rx` / `poll` の後に [`Commissioner::drive`] を呼び、返る [`DriveOutcome`] の
//! `send`(あれば)を送出、`phase` を進捗として観測する(§6.2)。

use crate::cert::parse_csr;
use crate::cert::x509::{parse_x509, verify_signed_by};
use crate::crypto::{Crypto, P256PublicKey, Rng};
use crate::dm::meta::AttributeId;
use crate::dm::meta::{ClusterId, EndpointId};
use crate::error::{Error, Result};
use crate::im::client::ImEvent;
use crate::im::wire::{AttributePath, AttributeReportRef, CommandId, CommandPath, ImStatus};
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
const CLUSTER_NETWORK_COMMISSIONING: u32 = 0x0031;
const CLUSTER_OPERATIONAL_CREDENTIALS: u32 = 0x003E;
const CMD_ARM_FAIL_SAFE: u32 = 0x00;
const CMD_COMMISSIONING_COMPLETE: u32 = 0x04;
const CMD_CSR_REQUEST: u32 = 0x04;
const CMD_ATTESTATION_REQUEST: u32 = 0x00;
const CMD_CERT_CHAIN_REQUEST: u32 = 0x02;

/// CertificateChainRequest の certificateType(§11.17.5.3)。
const CERT_TYPE_DAC: u8 = 1;
/// CertificateChainRequest の certificateType(PAI)。
const CERT_TYPE_PAI: u8 = 2;
const CMD_ADD_NOC: u32 = 0x06;

/// Basic Information クラスタ(0x0028)と VendorID / ProductID 属性 ID。
///
/// 属性 ID は Matter 仕様(= コアの `basic_information.rs`)に従う:
/// VendorID=0x0002、ProductID=0x0004(0x0001/0x0002 は VendorName/VendorID)。
const CLUSTER_BASIC_INFORMATION: u32 = 0x0028;
const ATTR_BASIC_VENDOR_ID: u32 = 0x0002;
const ATTR_BASIC_PRODUCT_ID: u32 = 0x0004;
const CMD_ADD_TRUSTED_ROOT: u32 = 0x0B;
const CMD_ADD_OR_UPDATE_WIFI_NETWORK: u32 = 0x02;
const CMD_ADD_OR_UPDATE_THREAD_NETWORK: u32 = 0x03;
const CMD_CONNECT_NETWORK: u32 = 0x06;

/// [`Commissioner::set_wifi_credentials`] の SSID 最大長(Matter §11.8: 32 バイト)。
pub const MAX_WIFI_SSID_LEN: usize = 32;
/// [`Commissioner::set_wifi_credentials`] の資格情報最大長(WPA2/WPA3 パスフレーズ: 64 バイト)。
pub const MAX_WIFI_CREDENTIALS_LEN: usize = 64;
/// [`Commissioner::set_thread_dataset`] の Operational Dataset TLV 最大長(§11.8: 254 バイト)。
pub const MAX_THREAD_DATASET_LEN: usize = 254;

/// fail-safe タイマの有効秒数(ArmFailSafe に載せる)。
///
/// Thread(ble-thread)は attach 後の SRP 登録 → advertising proxy 反映まで実測で
/// 2 分近くかかることがあり(esp-radio 15.4 の TX 損失 + SRP リトライ)、120 秒だと
/// 運用解決中に fail-safe が切れて AddNOC が巻き戻る。スペック上限(900)内で余裕を取る。
const FAIL_SAFE_EXPIRY_S: u16 = 300;

/// CSRRequest の nonce(自作デバイス・自己整合テスト向けに固定。デバイスは署名対象として扱う)。
const CSR_NONCE: [u8; 32] = [0x5Au8; 32];

/// attestation の扱い(§6.4、`docs/design/attestation.md` §3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPolicy<'a> {
    /// DAC/PAI/CD を取得も検証もしない(自作デバイス・開発フローの既定)。
    Skip,
    /// DAC チェーン(DAC←PAI←PAA)+ attestation 署名 + nonce エコーを検証する。
    ///
    /// `paa_store` は信頼する PAA の X.509 DER のリスト(no_std / ヒープレス)。PAI の
    /// issuer と DER バイト一致する subject を持つ PAA を探し、その公開鍵で PAI 署名を
    /// 検証する。CD は presence チェックのみ(CMS 署名検証はスコープ外、§1)。
    Verify {
        /// 信頼する PAA の X.509 DER 群。
        paa_store: &'a [&'a [u8]],
    },
    /// PAA 信頼アンカーは要求しない最小検証(`docs/design/attestation.md` §8)。
    ///
    /// DAC←PAI の 1 段チェーン + attestation 署名 + nonce + CD(CMS 署名 +
    /// VID/PID クロスチェック)を検証し、さらに **DAC の VID/PID がデバイスの
    /// 報告する Basic Information の VendorID/ProductID と一致すること**を検証する
    /// (不一致は [`AttestationError::ReportedVidPidMismatch`])。PAI←PAA は
    /// 検証しないため PAA ストアは不要。smctl の既定(§8.4)。
    VerifyNoPaa,
}

/// device attestation 検証の失敗理由(`docs/design/attestation.md` §1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationError {
    /// DAC(X.509 DER)のパースに失敗した。
    DacParse,
    /// PAI(X.509 DER)のパースに失敗した。
    PaiParse,
    /// DAC が PAI で署名されていない(チェーン不成立)。
    DacChain,
    /// PAI の issuer と一致し、かつ PAI 署名を検証できる PAA が信頼ストアに無い。
    PaaNotFound,
    /// attestation 署名(elements ‖ challenge)が DAC 公開鍵で検証できない。
    Signature,
    /// elements 内の nonce が送信した nonce と一致しない。
    Nonce,
    /// elements 内の CD(cx1)が空、または elements の構造が不正。
    Cd,
    /// CD の CMS SignedData がパースできない(または非対応形状)。
    CdParse,
    /// CD の署名者(subjectKeyIdentifier)が既知の CD 署名鍵と一致しない。
    CdSignerUnknown,
    /// CD の CMS 署名が検証できない(改竄等)。
    CdSignature,
    /// CD の vendor_id / product_id_array が DAC の VID/PID と一致しない。
    CdVidPidMismatch,
    /// DAC の VID/PID がデバイスの報告する Basic Information の VendorID/ProductID と
    /// 一致しない(または報告値を Read できない)。`VerifyNoPaa`(§8)の主眼。
    ReportedVidPidMismatch,
    /// PASE セッションから attestation challenge を取得できない。
    Challenge,
    /// 暗号バックエンドが検証中にエラーを返した。
    Crypto,
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
    /// device attestation の検証に失敗した(`AttestationPolicy::Verify`)。
    Attestation(AttestationError),
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
    /// AddOrUpdateWiFiNetwork 実行中(Wi-Fi 資格情報設定時のみ、§6.5)。
    AddWifiNetwork,
    /// ConnectNetwork 実行中(Wi-Fi 資格情報設定時のみ、§6.5)。
    ConnectNetwork,
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
            // Wi-Fi フェーズは後付けのため、既存 stage 番号を保つよう末尾に足す。
            Phase::AddWifiNetwork => 10,
            Phase::ConnectNetwork => 11,
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
    policy: AttestationPolicy<'a>,
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
    /// [`set_wifi_credentials`](Self::set_wifi_credentials) で設定した Wi-Fi 資格情報。
    /// `Some` なら AddNOC 後に AddOrUpdateWiFiNetwork → ConnectNetwork を挿入する。
    wifi: Option<WifiCreds>,
    /// [`set_thread_dataset`](Self::set_thread_dataset) で設定した Thread dataset。
    /// `Some` なら AddNOC 後に AddOrUpdateThreadNetwork → ConnectNetwork を挿入する
    /// (`wifi` とは排他。両方設定時は `wifi` 優先)。
    thread: Option<ThreadDataset>,
    /// `Phase::Attestation`(`Verify`/`VerifyNoPaa`)のサブステップ: 0=DAC 要求,
    /// 1=PAI 要求, 2=AttestationRequest。`VerifyNoPaa` は続けて 3=Basic Info の
    /// VID/PID Read, 4=完了(§3 / §8.3)。`Skip` では未使用。
    att_step: u8,
    /// CertificateChainRequest(DAC)で捕捉した X.509 DER。
    dac_der: [u8; ATT_CERT_BUF],
    dac_len: usize,
    /// CertificateChainRequest(PAI)で捕捉した X.509 DER。
    pai_der: [u8; ATT_CERT_BUF],
    pai_len: usize,
    /// AttestationResponse の attestation_elements(TLV)。
    att_elements: [u8; ATT_ELEMENTS_BUF],
    att_elements_len: usize,
    /// AttestationResponse の signature(生 r‖s、64B)。
    att_sig: [u8; 64],
    /// AttestationRequest で送出した 32B nonce(エコー照合用)。
    att_nonce: [u8; 32],
}

/// 捕捉する DAC / PAI の X.509 DER 上限(chip 開発 DAC=491B / PAI=463B に余裕)。
const ATT_CERT_BUF: usize = 700;
/// 捕捉する attestation_elements の上限(CD 541B + nonce + timestamp、デバイス側と同値)。
const ATT_ELEMENTS_BUF: usize = 704;

/// AddOrUpdateWiFiNetwork / ConnectNetwork へ渡す Wi-Fi 資格情報(固定長バッファ)。
struct WifiCreds {
    ssid: [u8; MAX_WIFI_SSID_LEN],
    ssid_len: u8,
    credentials: [u8; MAX_WIFI_CREDENTIALS_LEN],
    credentials_len: u8,
}

impl WifiCreds {
    fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len as usize]
    }
    fn credentials(&self) -> &[u8] {
        &self.credentials[..self.credentials_len as usize]
    }
}

/// AddOrUpdateThreadNetwork / ConnectNetwork へ渡す Thread Operational Dataset(固定長バッファ)。
struct ThreadDataset {
    tlv: [u8; MAX_THREAD_DATASET_LEN],
    tlv_len: u8,
    /// dataset から抽出した Extended PAN ID(= NetworkID、ConnectNetwork の照合キー)。
    ext_pan_id: [u8; 8],
}

impl ThreadDataset {
    fn tlv(&self) -> &[u8] {
        &self.tlv[..self.tlv_len as usize]
    }
}

impl<'a, C: Crypto> Commissioner<'a, C> {
    /// CA・crypto・attestation ポリシからコミッショナを作る(初期フェーズ = Idle)。
    pub fn new(ca: &'a Ca<C>, crypto: &'a C, policy: AttestationPolicy<'a>) -> Self {
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
            wifi: None,
            thread: None,
            att_step: 0,
            dac_der: [0u8; ATT_CERT_BUF],
            dac_len: 0,
            pai_der: [0u8; ATT_CERT_BUF],
            pai_len: 0,
            att_elements: [0u8; ATT_ELEMENTS_BUF],
            att_elements_len: 0,
            att_sig: [0u8; 64],
            att_nonce: [0u8; 32],
        }
    }

    /// AddNOC 後に Wi-Fi をプロビジョンする(chip-tool `pairing ble-wifi` 相当、§6.5)。
    ///
    /// 設定すると AddNOC 成功後、CASE の前に **同一(PASE)セッション上で**
    /// AddOrUpdateWiFiNetwork(0x31/0x02: `{0: ssid, 1: credentials}`)→
    /// ConnectNetwork(0x31/0x06: `{0: networkID = ssid}`)を送る。デバイスは
    /// ConnectNetwork へ即 Success を返してバックグラウンドで join するため
    /// (`docs/design/port-esp32-device.md` §E5.2)、呼び出し側は通常
    /// [`suspend_before_case`](Self::suspend_before_case) と併用し、BLE を閉じて
    /// 運用 mDNS 解決 → UDP で CASE を再開する。
    ///
    /// `ssid` は最大 [`MAX_WIFI_SSID_LEN`]、`credentials` は最大
    /// [`MAX_WIFI_CREDENTIALS_LEN`] バイト。超過は [`Error::NoSpace`]、
    /// 空 SSID は [`Error::InvalidState`]。
    pub fn set_wifi_credentials(&mut self, ssid: &[u8], credentials: &[u8]) -> Result<()> {
        if ssid.is_empty() {
            return Err(Error::InvalidState);
        }
        if ssid.len() > MAX_WIFI_SSID_LEN || credentials.len() > MAX_WIFI_CREDENTIALS_LEN {
            return Err(Error::NoSpace);
        }
        let mut w = WifiCreds {
            ssid: [0u8; MAX_WIFI_SSID_LEN],
            ssid_len: ssid.len() as u8,
            credentials: [0u8; MAX_WIFI_CREDENTIALS_LEN],
            credentials_len: credentials.len() as u8,
        };
        w.ssid[..ssid.len()].copy_from_slice(ssid);
        w.credentials[..credentials.len()].copy_from_slice(credentials);
        self.wifi = Some(w);
        Ok(())
    }

    /// AddNOC 後に Thread をプロビジョンする(chip-tool `pairing ble-thread` 相当)。
    ///
    /// 設定すると AddNOC 成功後、CASE の前に **同一(PASE)セッション上で**
    /// AddOrUpdateThreadNetwork(0x31/0x03: `{0: operationalDataset, 1: breadcrumb}`)→
    /// ConnectNetwork(0x31/0x06: `{0: networkID = ExtPanID}`)を送る。デバイスは
    /// ConnectNetwork の応答を attach 完了まで遅延するため
    /// (`docs/design/thread-port.md` §4)、呼び出し側は通常
    /// [`suspend_before_case`](Self::suspend_before_case) と併用し、BLE を閉じて
    /// 運用アドレス解決 → UDP(Thread)で CASE を再開する。
    ///
    /// `tlv` は Thread Operational Dataset(TLV バイト列、最大
    /// [`MAX_THREAD_DATASET_LEN`])。Extended PAN ID(type=2)を含まない・
    /// 壊れている dataset は [`Error::Decode`]。
    pub fn set_thread_dataset(&mut self, tlv: &[u8]) -> Result<()> {
        if tlv.is_empty() {
            return Err(Error::InvalidState);
        }
        if tlv.len() > MAX_THREAD_DATASET_LEN {
            return Err(Error::NoSpace);
        }
        let ext_pan_id = crate::thread::extract_ext_pan_id(tlv).ok_or(Error::Decode)?;
        let mut t = ThreadDataset {
            tlv: [0u8; MAX_THREAD_DATASET_LEN],
            tlv_len: tlv.len() as u8,
            ext_pan_id,
        };
        t.tlv[..tlv.len()].copy_from_slice(tlv);
        self.thread = Some(t);
        Ok(())
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
        // attestation: `Skip` では即遷移(フェーズ表は常設、§6.4)。`Verify` は
        // 通常の emit/consume サイクルへ落とし、サブステップ(§3)を回す。
        if matches!(self.phase, Phase::Attestation)
            && matches!(self.policy, AttestationPolicy::Skip)
        {
            self.phase = Phase::Csr;
            self.awaiting = false;
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
            // attestation(`Verify`)のサブステップ(§3): DAC/PAI 取得 → AttestationRequest。
            Phase::Attestation => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                match self.att_step {
                    0 | 1 => {
                        let cert_type = if self.att_step == 0 {
                            CERT_TYPE_DAC
                        } else {
                            CERT_TYPE_PAI
                        };
                        stack
                            .start_invoke(
                                session,
                                cmd_path(CLUSTER_OPERATIONAL_CREDENTIALS, CMD_CERT_CHAIN_REQUEST),
                                move |w, t| {
                                    w.start_struct(t)?;
                                    w.write_u8(&cx(0), cert_type)?; // certificateType
                                    w.end_container()
                                },
                                now_ms,
                                tx_out,
                            )
                            .map_err(CommissionError::Stack)
                    }
                    2 => {
                        // AttestationRequest: 32B nonce を Rng から払い出して送る。
                        stack
                            .fill_random(&mut self.att_nonce)
                            .map_err(CommissionError::Stack)?;
                        let nonce = self.att_nonce;
                        stack
                            .start_invoke(
                                session,
                                cmd_path(CLUSTER_OPERATIONAL_CREDENTIALS, CMD_ATTESTATION_REQUEST),
                                move |w, t| {
                                    w.start_struct(t)?;
                                    w.write_bytes(&cx(0), &nonce)?; // attestationNonce
                                    w.end_container()
                                },
                                now_ms,
                                tx_out,
                            )
                            .map_err(CommissionError::Stack)
                    }
                    // att_step 3(`VerifyNoPaa` のみ): Basic Information の VendorID +
                    // ProductID を Read し、DAC の VID/PID と照合する(§8.3)。
                    _ => {
                        let paths = [
                            AttributePath::concrete(
                                EndpointId(0),
                                ClusterId(CLUSTER_BASIC_INFORMATION),
                                AttributeId(ATTR_BASIC_VENDOR_ID),
                            ),
                            AttributePath::concrete(
                                EndpointId(0),
                                ClusterId(CLUSTER_BASIC_INFORMATION),
                                AttributeId(ATTR_BASIC_PRODUCT_ID),
                            ),
                        ];
                        stack
                            .start_read(session, &paths, now_ms, tx_out)
                            .map_err(CommissionError::Stack)
                    }
                }
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
            Phase::AddWifiNetwork => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                if let Some(wifi) = self.wifi.as_ref() {
                    let ssid = wifi.ssid();
                    let creds = wifi.credentials();
                    stack
                        .start_invoke(
                            session,
                            cmd_path(
                                CLUSTER_NETWORK_COMMISSIONING,
                                CMD_ADD_OR_UPDATE_WIFI_NETWORK,
                            ),
                            move |w, t| {
                                w.start_struct(t)?;
                                w.write_bytes(&cx(0), ssid)?; // SSID
                                w.write_bytes(&cx(1), creds)?; // Credentials
                                w.write_u64(&cx(2), 0)?; // Breadcrumb
                                w.end_container()
                            },
                            now_ms,
                            tx_out,
                        )
                        .map_err(CommissionError::Stack)
                } else {
                    // Thread: AddOrUpdateThreadNetwork(0x03: {0: dataset, 1: breadcrumb})。
                    let thread = self.thread.as_ref().ok_or(CommissionError::Protocol)?;
                    let tlv = thread.tlv();
                    stack
                        .start_invoke(
                            session,
                            cmd_path(
                                CLUSTER_NETWORK_COMMISSIONING,
                                CMD_ADD_OR_UPDATE_THREAD_NETWORK,
                            ),
                            move |w, t| {
                                w.start_struct(t)?;
                                w.write_bytes(&cx(0), tlv)?; // OperationalDataset
                                w.write_u64(&cx(1), 0)?; // Breadcrumb
                                w.end_container()
                            },
                            now_ms,
                            tx_out,
                        )
                        .map_err(CommissionError::Stack)
                }
            }
            Phase::ConnectNetwork => {
                let session = self.pase_session.ok_or(CommissionError::Protocol)?;
                // NetworkID: Wi-Fi は SSID、Thread は Extended PAN ID(8B)。
                let network_id: &[u8] = if let Some(wifi) = self.wifi.as_ref() {
                    wifi.ssid()
                } else {
                    &self
                        .thread
                        .as_ref()
                        .ok_or(CommissionError::Protocol)?
                        .ext_pan_id
                };
                stack
                    .start_invoke(
                        session,
                        cmd_path(CLUSTER_NETWORK_COMMISSIONING, CMD_CONNECT_NETWORK),
                        move |w, t| {
                            w.start_struct(t)?;
                            w.write_bytes(&cx(0), network_id)?; // NetworkID
                            w.write_u64(&cx(1), 0)?; // Breadcrumb
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
        // `VerifyNoPaa` の att_step 3 は Basic Information の Read(ReadDone を待つ、§8.3)。
        // 他フェーズ・他ステップは Invoke / SC イベントなので通常経路へ落とす。
        if matches!(self.phase, Phase::Attestation) && self.att_step == 3 {
            match stack.im_take_event() {
                Some(ImEvent::ReadDone) => self.on_reported_vid_pid(stack),
                Some(ImEvent::Failed { status }) => self.enter_failed(CommissionError::Im(status)),
                Some(_) => self.enter_failed(CommissionError::Protocol),
                None => {}
            }
            return;
        }
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
                Ok(0) => {
                    self.att_step = 0;
                    self.advance(Phase::Attestation);
                }
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            Phase::Attestation => self.on_attestation_response(stack),
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
                Ok(0) => self.advance(if self.wifi.is_some() || self.thread.is_some() {
                    Phase::AddWifiNetwork
                } else {
                    Phase::Case
                }),
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            // NetworkConfigResponse / ConnectNetworkResponse とも cx0 = networkingStatus
            //(0 = Success、§11.8.5.1)。ConnectNetwork は「即 Success + バックグラウンド
            // join」方式(デバイス側 doc §E5.2)なので、join 完了はここでは待たない。
            Phase::AddWifiNetwork => match response_status_code(stack.im_result()) {
                Ok(0) => self.advance(Phase::ConnectNetwork),
                Ok(code) => self.enter_failed(CommissionError::Status(code)),
                Err(_) => self.enter_failed(CommissionError::Protocol),
            },
            Phase::ConnectNetwork => match response_status_code(stack.im_result()) {
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

    /// `Phase::Attestation`(`Verify`)の各サブステップ応答を処理する(§3)。
    fn on_attestation_response<
        R,
        F,
        const SS: usize,
        const EX: usize,
        const TX: usize,
        const RS: usize,
    >(
        &mut self,
        stack: &ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
    ) where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        match self.att_step {
            0 => match extract_cert_chain(stack.im_result()) {
                Ok(cert) if cert.len() <= ATT_CERT_BUF => {
                    self.dac_der[..cert.len()].copy_from_slice(cert);
                    self.dac_len = cert.len();
                    self.att_step = 1;
                    self.awaiting = false; // 同フェーズで PAI 要求を再発行する。
                }
                _ => self.enter_failed(CommissionError::Attestation(AttestationError::DacParse)),
            },
            1 => match extract_cert_chain(stack.im_result()) {
                Ok(cert) if cert.len() <= ATT_CERT_BUF => {
                    self.pai_der[..cert.len()].copy_from_slice(cert);
                    self.pai_len = cert.len();
                    self.att_step = 2;
                    self.awaiting = false; // 同フェーズで AttestationRequest を再発行する。
                }
                _ => self.enter_failed(CommissionError::Attestation(AttestationError::PaiParse)),
            },
            _ => {
                // AttestationResponse: elements + signature を捕捉して検証する。
                match extract_attestation(stack.im_result()) {
                    Ok((elements, sig)) if elements.len() <= ATT_ELEMENTS_BUF => {
                        self.att_elements[..elements.len()].copy_from_slice(elements);
                        self.att_elements_len = elements.len();
                        self.att_sig = sig;
                    }
                    _ => {
                        self.enter_failed(CommissionError::Attestation(
                            AttestationError::Signature,
                        ));
                        return;
                    }
                }
                // attestation challenge を PASE セッションから取得する。
                let challenge = match self
                    .pase_session
                    .and_then(|id| stack.sessions().get(id))
                    .and_then(|s| s.att_challenge())
                {
                    Some(c) => *c,
                    None => {
                        self.enter_failed(CommissionError::Attestation(
                            AttestationError::Challenge,
                        ));
                        return;
                    }
                };
                match self.verify_attestation(&challenge) {
                    Ok(()) => {
                        if matches!(self.policy, AttestationPolicy::VerifyNoPaa) {
                            // 同フェーズに留まり Basic Information の VID/PID Read を発行する(§8.3)。
                            self.att_step = 3;
                            self.awaiting = false;
                        } else {
                            self.att_step = 3;
                            self.advance(Phase::Csr);
                        }
                    }
                    Err(e) => self.enter_failed(CommissionError::Attestation(e)),
                }
            }
        }
    }

    /// 捕捉済みの DAC/PAI/elements/signature を検証する(§1)。
    fn verify_attestation(
        &self,
        challenge: &[u8; 16],
    ) -> core::result::Result<(), AttestationError> {
        // `Verify` は PAA 信頼ストアで PAI←PAA まで検証する。`VerifyNoPaa` は
        // PAA を辿らない(ストア不要、§8)。`Skip` はここへ来ない。
        let paa_store: Option<&[&[u8]]> = match self.policy {
            AttestationPolicy::Verify { paa_store } => Some(paa_store),
            AttestationPolicy::VerifyNoPaa => None,
            AttestationPolicy::Skip => return Err(AttestationError::PaaNotFound),
        };

        let dac =
            parse_x509(&self.dac_der[..self.dac_len]).map_err(|_| AttestationError::DacParse)?;
        let pai =
            parse_x509(&self.pai_der[..self.pai_len]).map_err(|_| AttestationError::PaiParse)?;

        // 1. DAC が PAI で署名されていること(チェーン 1 段)。
        if !verify_signed_by(self.crypto, &dac, &pai.spki_pubkey)
            .map_err(|_| AttestationError::Crypto)?
        {
            return Err(AttestationError::DacChain);
        }

        // 2. `Verify` のみ: PAI の issuer と DER 一致する subject を持つ PAA を信頼
        //    ストアから探し、その公開鍵で PAI 署名を検証する(`VerifyNoPaa` は省略)。
        if let Some(paa_store) = paa_store {
            let mut chain_ok = false;
            for paa_der in paa_store {
                let Ok(paa) = parse_x509(paa_der) else {
                    continue;
                };
                if paa.subject != pai.issuer {
                    continue;
                }
                if verify_signed_by(self.crypto, &pai, &paa.spki_pubkey)
                    .map_err(|_| AttestationError::Crypto)?
                {
                    chain_ok = true;
                    break;
                }
            }
            if !chain_ok {
                return Err(AttestationError::PaaNotFound);
            }
        }

        // 3. attestation 署名: elements ‖ challenge を DAC 公開鍵で検証(§1)。
        let elements = &self.att_elements[..self.att_elements_len];
        let mut tbs = [0u8; ATT_ELEMENTS_BUF + 16];
        let total = elements.len() + challenge.len();
        if total > tbs.len() {
            return Err(AttestationError::Signature);
        }
        tbs[..elements.len()].copy_from_slice(elements);
        tbs[elements.len()..total].copy_from_slice(challenge);
        let dac_key = self
            .crypto
            .p256_public_key_from_bytes(&dac.spki_pubkey)
            .map_err(|_| AttestationError::Crypto)?;
        if !dac_key
            .verify(&tbs[..total], &self.att_sig)
            .map_err(|_| AttestationError::Crypto)?
        {
            return Err(AttestationError::Signature);
        }

        // 4. CD presence + nonce エコー照合。
        let (cd, nonce) = parse_att_elements(elements).map_err(|_| AttestationError::Cd)?;
        if cd.is_empty() {
            return Err(AttestationError::Cd);
        }
        if nonce != self.att_nonce.as_slice() {
            return Err(AttestationError::Nonce);
        }

        // 5. CD の CMS SignedData 検証 + VID/PID クロスチェック(attestation.md §7)。
        //    既知署名者は chip と同じ(テスト CD 署名鍵 + CSA 公式 CD 署名鍵 001〜005)。
        let cms =
            crate::cert::cms::parse_cms_signed_data(cd).map_err(|_| AttestationError::CdParse)?;
        let signer_pubkey = crate::cert::cms::KNOWN_CD_SIGNERS
            .iter()
            .find(|(kid, _)| kid.as_slice() == cms.signer_kid)
            .map(|(_, pk)| *pk)
            .ok_or(AttestationError::CdSignerUnknown)?;
        if !crate::cert::cms::verify_cms_signature(self.crypto, &cms, signer_pubkey)
            .map_err(|_| AttestationError::Crypto)?
        {
            return Err(AttestationError::CdSignature);
        }
        // DAC subject の Matter VID/PID DN 属性と CD の vendor_id / product_id_array を照合。
        let (dac_vid, dac_pid) = crate::cert::x509::matter_vid_pid(dac.subject);
        let (Some(vid), Some(pid)) = (dac_vid, dac_pid) else {
            return Err(AttestationError::CdVidPidMismatch);
        };
        if !crate::cert::cms::cd_matches_vid_pid(cms.econtent, vid, pid)
            .map_err(|_| AttestationError::CdParse)?
        {
            return Err(AttestationError::CdVidPidMismatch);
        }
        Ok(())
    }

    /// `VerifyNoPaa` の att_step 3: Read した Basic Information の VendorID/ProductID を
    /// 取り出し、DAC の VID/PID と照合する(§8.3)。一致で `Phase::Csr` へ、
    /// 不一致(または読めない)で [`AttestationError::ReportedVidPidMismatch`]。
    fn on_reported_vid_pid<
        R,
        F,
        const SS: usize,
        const EX: usize,
        const TX: usize,
        const RS: usize,
    >(
        &mut self,
        stack: &ControllerStack<'_, C, R, F, SS, EX, TX, RS>,
    ) where
        R: Rng,
        F: FabricStore + NocResolver,
    {
        let mut reported_vid: Option<u16> = None;
        let mut reported_pid: Option<u16> = None;
        for rep in stack.read_reports() {
            let Ok(AttributeReportRef::Data(data)) = rep else {
                continue;
            };
            let Some(path) = data.path.to_concrete() else {
                continue;
            };
            if path.cluster.0 != CLUSTER_BASIC_INFORMATION {
                continue;
            }
            let mut vr = data.value();
            let value = match vr.read_next() {
                Ok(Some(e)) => match e.value.as_unsigned() {
                    Ok(v) => v,
                    Err(_) => continue,
                },
                _ => continue,
            };
            match path.attribute.0 {
                ATTR_BASIC_VENDOR_ID => reported_vid = Some(value as u16),
                ATTR_BASIC_PRODUCT_ID => reported_pid = Some(value as u16),
                _ => {}
            }
        }
        match (reported_vid, reported_pid) {
            (Some(vid), Some(pid)) => match self.verify_reported_vid_pid(vid, pid) {
                Ok(()) => {
                    self.att_step = 4;
                    self.advance(Phase::Csr);
                }
                Err(e) => self.enter_failed(CommissionError::Attestation(e)),
            },
            _ => self.enter_failed(CommissionError::Attestation(
                AttestationError::ReportedVidPidMismatch,
            )),
        }
    }

    /// DAC subject の VID/PID とデバイス報告の VendorID/ProductID を照合する(§8.2 手順 5)。
    fn verify_reported_vid_pid(
        &self,
        reported_vid: u16,
        reported_pid: u16,
    ) -> core::result::Result<(), AttestationError> {
        let dac =
            parse_x509(&self.dac_der[..self.dac_len]).map_err(|_| AttestationError::DacParse)?;
        let (dac_vid, dac_pid) = crate::cert::x509::matter_vid_pid(dac.subject);
        let (Some(vid), Some(pid)) = (dac_vid, dac_pid) else {
            return Err(AttestationError::ReportedVidPidMismatch);
        };
        if vid != reported_vid || pid != reported_pid {
            return Err(AttestationError::ReportedVidPidMismatch);
        }
        Ok(())
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

/// CertificateChainResponse の cx0(証明書 DER bytes)を借用で返す。
fn extract_cert_chain(result: &[u8]) -> Result<&[u8]> {
    let mut r = enter_command_fields(result)?;
    find_ctx(&mut r, 0)?.value.as_bytes()
}

/// AttestationResponse の cx0(elements bytes)と cx1(signature 64B)を返す。
fn extract_attestation(result: &[u8]) -> Result<(&[u8], [u8; 64])> {
    let mut r = enter_command_fields(result)?;
    let elements = find_ctx(&mut r, 0)?.value.as_bytes()?;
    let sig_b = find_ctx(&mut r, 1)?.value.as_bytes()?;
    if sig_b.len() != 64 {
        return Err(Error::Decode);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(sig_b);
    Ok((elements, sig))
}

/// AttestationElements(TLV struct `{ cx1: CD, cx2: nonce, cx3: ts }`)から
/// (CD, nonce) を借用で返す。
fn parse_att_elements(elements: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut r = TlvReader::new(elements);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let cd = find_ctx(&mut r, 1)?.value.as_bytes()?;
    let nonce = find_ctx(&mut r, 2)?.value.as_bytes()?;
    Ok((cd, nonce))
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

// ==========================================================================
// attestation 検証のユニットテスト(`VerifyNoPaa`、attestation.md §8.5 (c)/(d))
// ==========================================================================
//
// (a) 成功 /(b) 報告 VID/PID 不一致は正直なデバイスで縦通しできるため
// `stack/tests.rs` の E2E で検証する。ここでは正直なデバイスでは注入しにくい
// (c) DAC 署名改竄 と (d) nonce 不一致 を、キャプチャ済みバッファを直接組み立てて
// `verify_attestation` に食わせる形で検証する(同一モジュールなので私有フィールドに
// アクセスできる)。
#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::P256Keypair;
    use crate::dm::clusters::operational_credentials::dev_creds::{
        DEV_CD_FOR_ALL_EXAMPLES, DEV_DAC_CERT_FFF1_8001, DEV_DAC_PRIVKEY_FFF1_8001,
        DEV_PAI_CERT_FFF1,
    };
    use crate::tlv::TlvWriter;

    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for b in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }
    type Crb = RustCrypto<SeqRng>;

    const CHALLENGE: [u8; 16] = [0x11; 16];

    fn ca() -> Ca<Crb> {
        let crypto = RustCrypto::new(SeqRng(0xCA0F_0001));
        Ca::<Crb>::generate(&crypto, &mut SeqRng(0x9999), 0xFAB1, 0x1122, 0xFFF1, 0).unwrap()
    }

    /// dev DAC/PAI/CD で有効な attestation elements + signature を組み立て、
    /// `Commissioner` のキャプチャバッファへ詰める。`dac_der` は DAC 証明書(改竄可)、
    /// `embedded_nonce` は elements 内の nonce、`att_nonce` は送出済みとみなす nonce。
    fn commissioner_with<'a>(
        ca: &'a Ca<Crb>,
        crypto: &'a Crb,
        dac_der: &[u8],
        embedded_nonce: &[u8; 32],
        att_nonce: [u8; 32],
    ) -> Commissioner<'a, Crb> {
        let mut comm = Commissioner::new(ca, crypto, AttestationPolicy::VerifyNoPaa);
        comm.dac_der[..dac_der.len()].copy_from_slice(dac_der);
        comm.dac_len = dac_der.len();
        comm.pai_der[..DEV_PAI_CERT_FFF1.len()].copy_from_slice(&DEV_PAI_CERT_FFF1);
        comm.pai_len = DEV_PAI_CERT_FFF1.len();

        // AttestationElements TLV: struct { 1: CD, 2: nonce, 3: timestamp }。
        let mut elems = [0u8; ATT_ELEMENTS_BUF];
        let elems_len = {
            let mut w = TlvWriter::new(&mut elems);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&cx(1), &DEV_CD_FOR_ALL_EXAMPLES).unwrap();
            w.write_bytes(&cx(2), embedded_nonce).unwrap();
            w.write_u32(&cx(3), 0).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        comm.att_elements[..elems_len].copy_from_slice(&elems[..elems_len]);
        comm.att_elements_len = elems_len;

        // signature = ECDSA_sign(elements || challenge) を DAC 秘密鍵で。
        let keypair = crypto
            .p256_keypair_from_bytes(&DEV_DAC_PRIVKEY_FFF1_8001)
            .unwrap();
        let mut tbs = [0u8; ATT_ELEMENTS_BUF + 16];
        tbs[..elems_len].copy_from_slice(&elems[..elems_len]);
        tbs[elems_len..elems_len + 16].copy_from_slice(&CHALLENGE);
        let mut sig = [0u8; 64];
        keypair.sign(&tbs[..elems_len + 16], &mut sig).unwrap();
        comm.att_sig = sig;
        comm.att_nonce = att_nonce;
        comm
    }

    /// 正: 正しい DAC/PAI/CD + 一致 nonce なら `verify_attestation` は成功する
    /// (PAA ストア無し)。報告 VID/PID の照合は別段(Read 後)なのでここでは対象外。
    #[test]
    fn verify_no_paa_accepts_valid() {
        let crypto = RustCrypto::new(SeqRng(0x0001));
        let ca = ca();
        let nonce = [0x22u8; 32];
        let comm = commissioner_with(&ca, &crypto, &DEV_DAC_CERT_FFF1_8001, &nonce, nonce);
        assert!(comm.verify_attestation(&CHALLENGE).is_ok());
    }

    /// (c) DAC 署名改竄: DAC の signatureValue を 1 バイト反転すると DAC←PAI の
    /// チェーン検証に失敗し `DacChain` を返す。
    #[test]
    fn verify_no_paa_rejects_tampered_dac() {
        let crypto = RustCrypto::new(SeqRng(0x0002));
        let ca = ca();
        let nonce = [0x22u8; 32];
        let mut dac = DEV_DAC_CERT_FFF1_8001;
        let last = dac.len() - 1;
        dac[last] ^= 0x01; // signatureValue の末尾バイトを反転
        let comm = commissioner_with(&ca, &crypto, &dac, &nonce, nonce);
        assert_eq!(
            comm.verify_attestation(&CHALLENGE),
            Err(AttestationError::DacChain)
        );
    }

    /// (d) nonce 不一致: elements 内の nonce と Commissioner が送った nonce が食い違うと
    /// `Nonce` を返す(署名・CD は正しい)。
    #[test]
    fn verify_no_paa_rejects_nonce_mismatch() {
        let crypto = RustCrypto::new(SeqRng(0x0003));
        let ca = ca();
        let embedded = [0x22u8; 32];
        let sent = [0x33u8; 32]; // 送出 nonce ≠ elements の nonce
        let comm = commissioner_with(&ca, &crypto, &DEV_DAC_CERT_FFF1_8001, &embedded, sent);
        assert_eq!(
            comm.verify_attestation(&CHALLENGE),
            Err(AttestationError::Nonce)
        );
    }

    /// 報告 VID/PID 照合: DAC(FFF1/8001)に対し報告値の正/負を直接検証する。
    #[test]
    fn reported_vid_pid_matches_dac() {
        let crypto = RustCrypto::new(SeqRng(0x0004));
        let ca = ca();
        let nonce = [0x22u8; 32];
        let comm = commissioner_with(&ca, &crypto, &DEV_DAC_CERT_FFF1_8001, &nonce, nonce);
        assert!(comm.verify_reported_vid_pid(0xFFF1, 0x8001).is_ok());
        assert_eq!(
            comm.verify_reported_vid_pid(0xFFF1, 0x8007),
            Err(AttestationError::ReportedVidPidMismatch)
        );
        assert_eq!(
            comm.verify_reported_vid_pid(0xFFF2, 0x8001),
            Err(AttestationError::ReportedVidPidMismatch)
        );
    }
}
