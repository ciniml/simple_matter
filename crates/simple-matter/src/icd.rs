//! ICD(Intermittently Connected Device)コア状態機械(`docs/design/icd.md` §2)。
//!
//! sans-IO・no_std・alloc 非依存。ICD Management クラスタ(0x0046)が広告する
//! パラメータ([`IcdConfig`])と、「今 sleep してよいか + 次の起床期限」をアプリへ返す
//! 最小の active/idle 状態機械([`IcdState`])を提供する。ネットワークにも時刻源にも
//! 触れず、`now_ms`(単調ミリ秒)を引数で受け取る(`identify` の tick と同じ流儀)。
//!
//! # SIT(Short Idle Time)最小スコープ(I1a)
//!
//! Matter 1.3 の ICD Management クラスタで **SIT ICD に必須**なのは 3 属性だけ:
//! IdleModeDuration / ActiveModeDuration / ActiveModeThreshold。CheckInProtocolSupport
//! (CIP、RegisterClient / チェックイン)と LIT(LITS)は I1c へ切り出す(FeatureMap=0)。
//!
//! # active/idle の意味(Matter 1.3 §9.16 の SIT 挙動)
//!
//! - **ActiveModeThreshold**: 最後の通信(送受信)からこの時間だけ active を延長する。
//!   受信/送信のたびに [`IcdState::notify_activity`] で `now + threshold` へ延長する。
//! - **ActiveModeDuration**: idle → active に遷移した「起床」直後、最低この時間は active に
//!   留まる(閾値延長より短くならないための下限)。
//! - **IdleModeDuration**: idle でいられる最大時間(SIT ではポーリング/広告周期の素。
//!   LIT のチェックイン周期は I1c)。mDNS TXT の SII に反映する。
//!
//! アプリ(PC example / ports)は毎ループ [`IcdState::can_sleep`] を問い合わせ、true の間は
//! 受信を止めて「擬似 sleep」or 実 light-sleep に入り、[`IcdState::next_wake`] で起床期限を得る。
//! 状態機械はコアが持つが、**駆動はアプリが行う**(sans-IO 維持。`MatterStack` の
//! `next_deadline` と `min` を取って 1 つの起床期限にまとめる想定)。

use core::cell::RefCell;
use core::num::NonZeroU8;

use crate::crypto::{Crypto, AES_CCM_NONCE_LEN, AES_CCM_TAG_LEN, SHA256_LEN};
use crate::error::{Error, Result};
use crate::kvs::Kvs;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::fixed::FixedVec;

/// mDNS TXT / MRP の interval 上限(Matter 仕様、ミリ秒)。SII/SAI はこれを超えない。
pub const MAX_INTERVAL_MS: u32 = 3_600_000;

/// ICD Management クラスタ FeatureMap のビット(Matter 1.3 §9.16.4)。
pub mod feature {
    /// CheckInProtocolSupport(bit0)。RegisterClient / check-in / ICDCounter を有効化。
    pub const CIP: u32 = 1 << 0;
    /// UserActiveModeTrigger(bit1)。本実装では未対応。
    pub const UAT: u32 = 1 << 1;
    /// LongIdleTimeSupport(bit2)。LIT ICD(OperatingMode=LIT、long idle = check-in 周期)。
    pub const LITS: u32 = 1 << 2;
}

/// OperatingMode(0x0008、OperatingModeEnum、§9.16.5.5)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OperatingMode {
    /// SIT(Short Idle Time)。
    Sit = 0,
    /// LIT(Long Idle Time)。LITS feature 必須、ActiveModeThreshold ≥ 5000ms。
    Lit = 1,
}

/// ICD Management クラスタが広告する固定パラメータ(SIT 最小の 3 属性)。
///
/// 単位は Matter 1.3 準拠: **IdleModeDuration は秒**、ActiveModeDuration /
/// ActiveModeThreshold は**ミリ秒**(1.2 の *Interval*[ms] から 1.3 で名称・単位が変わった点に注意)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcdConfig {
    /// IdleModeDuration(0x0000、**秒**)。仕様レンジ 1..=64800。
    pub idle_mode_duration_s: u32,
    /// ActiveModeDuration(0x0001、**ミリ秒**)。仕様下限 300。
    pub active_mode_duration_ms: u32,
    /// ActiveModeThreshold(0x0002、**ミリ秒**)。SIT では小さめ、LIT は 5000 以上(I1c)。
    pub active_mode_threshold_ms: u16,
}

impl IcdConfig {
    /// SIT ICD の実用デフォルト。
    ///
    /// idle=2s / active=1000ms / threshold=500ms。idle を短めにしてあるのは、ホスト E2E で
    /// 「subscribe の maxInterval > IdleModeDuration」と idle/active 遷移を短時間で観察できる
    /// ようにするため(実機の電池運用ではより長い idle を選ぶ)。
    pub const fn sit_default() -> Self {
        Self {
            idle_mode_duration_s: 2,
            active_mode_duration_ms: 1000,
            active_mode_threshold_ms: 500,
        }
    }

    /// 値を検証する(仕様レンジ)。属性は FIXED なので生成時に 1 度だけ確認すればよい。
    pub const fn validate(&self) -> Result<()> {
        if self.idle_mode_duration_s < 1 || self.idle_mode_duration_s > 64_800 {
            return Err(Error::InvalidState);
        }
        if self.active_mode_duration_ms < 300 {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    /// mDNS TXT / MRP の SII(Session Idle Interval、ミリ秒)を導出する。
    ///
    /// SII = IdleModeDuration(秒 → ミリ秒)。ピア(コントローラ)は SII を見て、相手が
    /// idle のとき MRP の再送バックオフをこの周期に合わせる。上限 [`MAX_INTERVAL_MS`]。
    pub const fn advertised_sii_ms(&self) -> u32 {
        let ms = self.idle_mode_duration_s.saturating_mul(1000);
        if ms > MAX_INTERVAL_MS {
            MAX_INTERVAL_MS
        } else {
            ms
        }
    }

    /// mDNS TXT / MRP の SAI(Session Active Interval、ミリ秒)を導出する。
    ///
    /// SAI = ActiveModeDuration(ミリ秒)。active 中のピアが期待する応答周期。上限
    /// [`MAX_INTERVAL_MS`]。
    ///
    /// 注: より厳密には ActiveModeThreshold を TXT `SAT` キーとして別に広告できる
    /// (Matter 1.3 で追加)。本コアの `Operational`/`Commissionable` は SII/SAI のみを
    /// 持つため、SAT は I1c(LIT + discovery 拡張)へ回す。
    pub const fn advertised_sai_ms(&self) -> u32 {
        if self.active_mode_duration_ms > MAX_INTERVAL_MS {
            MAX_INTERVAL_MS
        } else {
            self.active_mode_duration_ms
        }
    }
}

impl Default for IcdConfig {
    fn default() -> Self {
        Self::sit_default()
    }
}

/// ICD の active/idle 状態機械(sans-IO、`now_ms` 駆動)。
///
/// 「active_until_ms までは active、それ以降は idle」という 1 変数のモデル。受信/送信で
/// [`notify_activity`](IcdState::notify_activity) が呼ばれ、active 窓を延長する。アプリは
/// [`can_sleep`](IcdState::can_sleep) と [`next_wake`](IcdState::next_wake) を問い合わせる。
#[derive(Debug, Clone, Copy)]
pub struct IcdState {
    cfg: IcdConfig,
    /// この時刻(ms)まで active。0 は「まだ一度も active になっていない = idle」。
    active_until_ms: u64,
}

impl IcdState {
    /// 設定を与えて idle 状態で作る。
    pub const fn new(cfg: IcdConfig) -> Self {
        Self {
            cfg,
            active_until_ms: 0,
        }
    }

    /// 広告パラメータ([`IcdConfig`])を返す。
    pub const fn config(&self) -> &IcdConfig {
        &self.cfg
    }

    /// Matter の通信(受信/送信・応答を要する交換)を通知し、active 窓を延長する。
    ///
    /// - idle → active の遷移(起床)では、最低 ActiveModeDuration は active に留まる。
    /// - すでに active でも idle でも、最後の通信から ActiveModeThreshold は必ず active。
    ///
    /// = `active_until = max(既存, now + threshold, (起床なら) now + duration)`。
    pub fn notify_activity(&mut self, now_ms: u64) {
        let by_threshold = now_ms.saturating_add(u64::from(self.cfg.active_mode_threshold_ms));
        if !self.is_active(now_ms) {
            // 起床: ActiveModeDuration の下限を敷く。
            let by_duration = now_ms.saturating_add(u64::from(self.cfg.active_mode_duration_ms));
            self.active_until_ms = by_duration;
        }
        if by_threshold > self.active_until_ms {
            self.active_until_ms = by_threshold;
        }
    }

    /// 現在 active か(`now < active_until`)。
    pub const fn is_active(&self, now_ms: u64) -> bool {
        now_ms < self.active_until_ms
    }

    /// 今 sleep してよいか(= active でない)。
    ///
    /// アプリはこれが true の間、受信を止めて擬似/実 sleep に入ってよい。
    pub const fn can_sleep(&self, now_ms: u64) -> bool {
        !self.is_active(now_ms)
    }

    /// 次に起床すべき時刻(ms)。
    ///
    /// - active 中: active 窓の終端(`active_until`)。そこで再評価して idle へ落とす。
    /// - idle 中: `now + IdleModeDuration`(SIT のポーリング/広告更新の周期)。
    ///
    /// アプリは `MatterStack::next_deadline` とこの値の `min` を取り、1 つの起床期限にする。
    pub const fn next_wake(&self, now_ms: u64) -> u64 {
        if self.is_active(now_ms) {
            self.active_until_ms
        } else {
            now_ms.saturating_add((self.cfg.idle_mode_duration_s as u64).saturating_mul(1000))
        }
    }

    /// StayActiveRequest(CIP、§9.16.7.4)に応じて active 窓を延長する。
    ///
    /// `requested_ms` の間、デバイスは active に留まることを約束する。実際に約束する
    /// 時間(promisedActiveDuration)を返す。要求より短い約束も許される(仕様)ので、
    /// [`STAY_ACTIVE_MAX_MS`] を上限にクランプする。現在の active 窓が約束より長ければ
    /// それを維持し、その残り時間を約束として返す(仕様: 既に active ならその残りが下限)。
    pub fn stay_active(&mut self, now_ms: u64, requested_ms: u32) -> u32 {
        let granted = requested_ms.min(STAY_ACTIVE_MAX_MS);
        let target = now_ms.saturating_add(u64::from(granted));
        if target > self.active_until_ms {
            self.active_until_ms = target;
        }
        // 約束時間 = 現在からの active 窓終端までの残り(既存の窓が長ければそれ)。
        self.active_until_ms
            .saturating_sub(now_ms)
            .min(u64::from(u32::MAX)) as u32
    }
}

/// StayActiveRequest で約束できる active 延長の上限(ミリ秒)。
///
/// 仕様上の上限は無いが、暴走した要求で無限に active を維持しないための実装上限。
pub const STAY_ACTIVE_MAX_MS: u32 = 30_000;

// ==========================================================================
// Check-In プロトコル(デバイス → 登録クライアント、Matter 1.3 §4.18.6)
// ==========================================================================
//
// **検証状態(重要)**: ローカルの chip チェックアウト(~/repos/connectedhomeip)は
// v1.1 系で `src/protocols/secure_channel/CheckinMessage.{h,cpp}` を**持たない**
// (check-in protocol 未実装)。よって **upstream のテストベクタが取得できない**。
// 本実装は Matter 1.3 spec §4.18.6 の構造(counter を AES-CCM で保護、nonce は平文
// plaintext の HMAC で導出して counter と束縛)に忠実だが、鍵導出の info ラベルは
// テストベクタ不在のため**本プロジェクト固有の選択**(下記)であり、chip との相互運用は
// 保証しない。正しさは「同一コードでの生成→復号ラウンドトリップ + counter 検証」の
// 自己テスト([`tests`])で固定する(`docs/design/icd.md` §6)。
//
// # Check-In メッセージ payload レイアウト
//
// ```text
// | Nonce (13B) | Ciphertext (4 + appDataLen) | MIC (16B) |
// ```
// - plaintext = ICDCounter(u32 LE, 4B) || appData
// - Nonce     = HMAC-SHA256(Khmac, plaintext)[0..13](counter を nonce に束縛)
// - Ciphertext||MIC = AES-128-CCM-Encrypt(Kaes, Nonce, aad=∅, plaintext)
//
// 復号側は Nonce を平文ヘッダから読み、AES-CCM 復号 → plaintext を得て、
// Nonce == HMAC(Khmac, plaintext)[0..13] を再検証する(改竄・counter すり替え検出)。

/// Check-In メッセージの nonce 長(= AES-CCM nonce、13 バイト)。
pub const CHECKIN_NONCE_LEN: usize = AES_CCM_NONCE_LEN;
/// Check-In メッセージの MIC 長(= AES-CCM tag、16 バイト)。
pub const CHECKIN_MIC_LEN: usize = AES_CCM_TAG_LEN;
/// Check-In counter のバイト長(u32 LE)。
pub const CHECKIN_COUNTER_LEN: usize = 4;
/// appData の実装上限(本実装は空 appData で運用。将来拡張の余地として確保)。
pub const CHECKIN_MAX_APP_DATA: usize = 16;
/// Check-In payload の最小長(nonce + counter + MIC、appData 空)。
pub const CHECKIN_MIN_LEN: usize = CHECKIN_NONCE_LEN + CHECKIN_COUNTER_LEN + CHECKIN_MIC_LEN;
/// Check-In payload の最大長。
pub const CHECKIN_MAX_LEN: usize =
    CHECKIN_NONCE_LEN + CHECKIN_COUNTER_LEN + CHECKIN_MAX_APP_DATA + CHECKIN_MIC_LEN;

/// 共有鍵(RegisterClient の key、16B)から AES 鍵を導出する HKDF info。
///
/// **本プロジェクト固有**(テストベクタ不在、上記モジュールコメント参照)。
const CHECKIN_AES_INFO: &[u8] = b"SimpleMatter ICD Check-In AES Key";
/// 共有鍵から HMAC 鍵を導出する HKDF info(本プロジェクト固有)。
const CHECKIN_HMAC_INFO: &[u8] = b"SimpleMatter ICD Check-In HMAC Key";

/// 共有鍵(16B)から check-in の AES 鍵 / HMAC 鍵を導出する。
///
/// HKDF-SHA256(salt=∅, ikm=shared_key, info=固有ラベル, L=16)を 2 本。
fn derive_checkin_keys<C: Crypto>(
    crypto: &C,
    shared_key: &[u8; 16],
) -> Result<([u8; 16], [u8; 16])> {
    let mut aes = [0u8; 16];
    let mut hmac = [0u8; 16];
    crypto.hkdf_sha256(&[], shared_key, CHECKIN_AES_INFO, &mut aes)?;
    crypto.hkdf_sha256(&[], shared_key, CHECKIN_HMAC_INFO, &mut hmac)?;
    Ok((aes, hmac))
}

/// Check-In メッセージ payload を生成し、`out` に書いた長さを返す。
///
/// `out` は少なくとも [`CHECKIN_MIN_LEN`] + `app_data.len()` バイト必要。`app_data` が
/// [`CHECKIN_MAX_APP_DATA`] を超える場合は [`Error::NoSpace`]。
pub fn generate_checkin<C: Crypto>(
    crypto: &C,
    shared_key: &[u8; 16],
    counter: u32,
    app_data: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    if app_data.len() > CHECKIN_MAX_APP_DATA {
        return Err(Error::NoSpace);
    }
    let pt_len = CHECKIN_COUNTER_LEN + app_data.len();
    let total = CHECKIN_NONCE_LEN + pt_len + CHECKIN_MIC_LEN;
    if out.len() < total {
        return Err(Error::NoSpace);
    }
    let (aes_key, hmac_key) = derive_checkin_keys(crypto, shared_key)?;

    // plaintext = counter(LE) || appData(スクラッチに組む)。
    let mut pt = [0u8; CHECKIN_COUNTER_LEN + CHECKIN_MAX_APP_DATA];
    pt[..CHECKIN_COUNTER_LEN].copy_from_slice(&counter.to_le_bytes());
    pt[CHECKIN_COUNTER_LEN..pt_len].copy_from_slice(app_data);
    let pt = &pt[..pt_len];

    // Nonce = HMAC(Khmac, plaintext)[0..13]。
    let mut mac = [0u8; SHA256_LEN];
    crypto.hmac_sha256(&hmac_key, pt, &mut mac)?;
    let mut nonce = [0u8; CHECKIN_NONCE_LEN];
    nonce.copy_from_slice(&mac[..CHECKIN_NONCE_LEN]);

    // AES-CCM: out[13..13+pt_len] に平文を置いて in-place 暗号化。
    out[CHECKIN_NONCE_LEN..CHECKIN_NONCE_LEN + pt_len].copy_from_slice(pt);
    crypto.aes_ccm_encrypt(
        &aes_key,
        &nonce,
        &[],
        &mut out[CHECKIN_NONCE_LEN..total],
        pt_len,
    )?;
    out[..CHECKIN_NONCE_LEN].copy_from_slice(&nonce);
    Ok(total)
}

/// Check-In メッセージ payload を復号・検証し、`(counter, app_data 長)` を返す。
///
/// `app_out` に appData を書き出す。Nonce 再計算が一致しない/AES-CCM 検証失敗は
/// [`Error::Crypto`]、長さ不正は [`Error::Decode`]。
pub fn open_checkin<C: Crypto>(
    crypto: &C,
    shared_key: &[u8; 16],
    msg: &[u8],
    app_out: &mut [u8],
) -> Result<(u32, usize)> {
    if msg.len() < CHECKIN_MIN_LEN || msg.len() > CHECKIN_MAX_LEN {
        return Err(Error::Decode);
    }
    let (aes_key, hmac_key) = derive_checkin_keys(crypto, shared_key)?;
    let mut nonce = [0u8; CHECKIN_NONCE_LEN];
    nonce.copy_from_slice(&msg[..CHECKIN_NONCE_LEN]);

    // ciphertext||MIC をスクラッチへ複製して in-place 復号。
    let ctmic = &msg[CHECKIN_NONCE_LEN..];
    let mut scratch = [0u8; CHECKIN_COUNTER_LEN + CHECKIN_MAX_APP_DATA + CHECKIN_MIC_LEN];
    scratch[..ctmic.len()].copy_from_slice(ctmic);
    let pt = crypto.aes_ccm_decrypt(&aes_key, &nonce, &[], &mut scratch[..ctmic.len()])?;
    let pt_len = pt.len();
    if pt_len < CHECKIN_COUNTER_LEN {
        return Err(Error::Decode);
    }
    // Nonce 再検証(counter が nonce に束縛されていること)。
    let mut mac = [0u8; SHA256_LEN];
    crypto.hmac_sha256(&hmac_key, pt, &mut mac)?;
    if mac[..CHECKIN_NONCE_LEN] != nonce {
        return Err(Error::Crypto);
    }
    let counter = u32::from_le_bytes([pt[0], pt[1], pt[2], pt[3]]);
    let app_len = pt_len - CHECKIN_COUNTER_LEN;
    if app_out.len() < app_len {
        return Err(Error::NoSpace);
    }
    app_out[..app_len].copy_from_slice(&pt[CHECKIN_COUNTER_LEN..]);
    Ok((counter, app_len))
}

// ==========================================================================
// 登録クライアントテーブル(fabric-scoped、KVS 永続化。ACL テーブルの流儀)
// ==========================================================================

/// fabric あたりの登録クライアント上限(ClientsSupportedPerFabric、仕様最小 1)。
pub const ICD_CLIENTS_PER_FABRIC: usize = 2;

/// 1 つの登録クライアント(MonitoringRegistrationStruct、§9.16.5.1、fabric-scoped)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcdRegistration {
    fabric_idx: NonZeroU8,
    check_in_node_id: u64,
    monitored_subject: u64,
    key: [u8; 16],
}

impl IcdRegistration {
    /// 登録エントリを作る。
    pub const fn new(
        fabric_idx: NonZeroU8,
        check_in_node_id: u64,
        monitored_subject: u64,
        key: [u8; 16],
    ) -> Self {
        Self {
            fabric_idx,
            check_in_node_id,
            monitored_subject,
            key,
        }
    }

    /// 所属 fabric。
    pub const fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }
    /// CheckInNodeID(check-in の宛先 NodeID)。
    pub const fn check_in_node_id(&self) -> u64 {
        self.check_in_node_id
    }
    /// MonitoredSubject。
    pub const fn monitored_subject(&self) -> u64 {
        self.monitored_subject
    }
    /// 共有 check-in 鍵(16B)。
    pub const fn key(&self) -> &[u8; 16] {
        &self.key
    }
}

/// 固定容量 `N` の登録クライアントテーブル + ICDCounter。
///
/// ACL テーブルと同じ流儀: 統合層が `RefCell<IcdRegistrationTable<N>>` を所有し、
/// ICDManagement クラスタと(RemoveFabric 連動用に)IM エンジンが共有参照する。
/// ICDCounter はデバイス単位で単調増加し、テーブルと同じ KVS レコードに永続化する。
pub struct IcdRegistrationTable<const N: usize> {
    entries: FixedVec<IcdRegistration, N>,
    icd_counter: u32,
    generation: u32,
}

impl<const N: usize> Default for IcdRegistrationTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> IcdRegistrationTable<N> {
    /// 空のテーブル(ICDCounter=0)を作る。
    pub const fn new() -> Self {
        Self {
            entries: FixedVec::new(),
            icd_counter: 0,
            generation: 0,
        }
    }

    /// 現在の登録数(全 fabric 合計)。
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// 登録が 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// テーブル容量(`N`)。
    pub const fn capacity(&self) -> usize {
        N
    }
    /// 変更世代番号(永続化フック。register / remove / counter bump で増加)。
    pub const fn generation(&self) -> u32 {
        self.generation
    }
    /// 現在の ICDCounter 値(RegisterClientResponse / 属性 0x0004)。
    pub const fn icd_counter(&self) -> u32 {
        self.icd_counter
    }
    /// 全エントリを走査する。
    pub fn iter(&self) -> impl Iterator<Item = &IcdRegistration> {
        self.entries.iter()
    }
    /// `fabric` のエントリのみ走査する。
    pub fn iter_fabric(&self, fabric: NonZeroU8) -> impl Iterator<Item = &IcdRegistration> {
        self.entries.iter().filter(move |e| e.fabric_idx == fabric)
    }
    /// `fabric` の登録数。
    pub fn fabric_len(&self, fabric: NonZeroU8) -> usize {
        self.iter_fabric(fabric).count()
    }

    /// `(fabric, check_in_node_id)` のエントリ index を探す。
    fn find(&self, fabric: NonZeroU8, check_in_node_id: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.fabric_idx == fabric && e.check_in_node_id == check_in_node_id)
    }

    /// 既存の check-in 鍵(RegisterClient/UnregisterClient の非 admin 検証用)を返す。
    pub fn key_of(&self, fabric: NonZeroU8, check_in_node_id: u64) -> Option<[u8; 16]> {
        self.find(fabric, check_in_node_id)
            .and_then(|i| self.entries.get(i))
            .map(|e| *e.key())
    }

    /// クライアントを登録(既存 CheckInNodeID は upsert = 鍵/subject 更新)する。
    ///
    /// per-fabric 上限超過は [`Error::NoSpace`]。
    pub fn register(&mut self, entry: IcdRegistration) -> Result<()> {
        if let Some(i) = self.find(entry.fabric_idx, entry.check_in_node_id) {
            self.entries[i] = entry;
        } else {
            if self.fabric_len(entry.fabric_idx) >= ICD_CLIENTS_PER_FABRIC {
                return Err(Error::NoSpace);
            }
            self.entries.push(entry).map_err(|_| Error::NoSpace)?;
        }
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// `(fabric, check_in_node_id)` を削除する。存在しなければ [`Error::InvalidState`]。
    pub fn unregister(&mut self, fabric: NonZeroU8, check_in_node_id: u64) -> Result<()> {
        let Some(i) = self.find(fabric, check_in_node_id) else {
            return Err(Error::InvalidState);
        };
        self.remove_at(i);
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// `fabric` の全エントリを削除し、削除数を返す(RemoveFabric 連動)。
    pub fn clear_fabric(&mut self, fabric: NonZeroU8) -> usize {
        let mut removed = 0;
        loop {
            let Some(i) = self.entries.iter().position(|e| e.fabric_idx == fabric) else {
                break;
            };
            self.remove_at(i);
            removed += 1;
        }
        if removed > 0 {
            self.generation = self.generation.wrapping_add(1);
        }
        removed
    }

    /// index 位置を順序を保って取り除く(左詰め)。
    fn remove_at(&mut self, index: usize) {
        let len = self.entries.len();
        if index >= len {
            return;
        }
        for i in index..len - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        let _ = self.entries.swap_remove(len - 1);
    }

    /// ICDCounter を 1 増やして新しい値を返す(check-in ラウンド送出ごとに 1 回)。
    ///
    /// generation を進めるので、統合層が KVS 保存を行い、再起動後も単調性を保つ。
    pub fn bump_counter(&mut self) -> u32 {
        self.icd_counter = self.icd_counter.wrapping_add(1);
        self.generation = self.generation.wrapping_add(1);
        self.icd_counter
    }

    /// fabric テーブルに存在しない fabric のエントリを落とす(復元後の整合)。
    pub fn retain_fabrics(&mut self, mut exists: impl FnMut(NonZeroU8) -> bool) {
        let mut i = 0;
        let mut removed = false;
        while i < self.entries.len() {
            if exists(self.entries[i].fabric_idx) {
                i += 1;
            } else {
                self.remove_at(i);
                removed = true;
            }
        }
        if removed {
            self.generation = self.generation.wrapping_add(1);
        }
    }
}

/// 永続化フォーマットの schema version。
pub const ICD_SCHEMA_VERSION: u8 = 1;
/// 登録テーブルレコードのキー。
const ICD_KEY: &[u8] = b"icdr";
/// レコードの TLV エンコード上限(バイト)。1 エントリ ≈ 40B、余裕を持たせた値。
pub const MAX_ICD_RECORD_LEN: usize = 1024;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

impl<const N: usize> IcdRegistrationTable<N> {
    /// テーブル + ICDCounter を `kvs` のキー `b"icdr"` へ保存する。
    pub fn save_to<K: Kvs>(&self, kvs: &mut K) -> Result<()> {
        let mut buf = [0u8; MAX_ICD_RECORD_LEN];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), ICD_SCHEMA_VERSION)?;
            w.write_u32(&cx(1), self.icd_counter)?;
            w.start_array(&cx(2))?;
            for e in self.entries.iter() {
                w.start_struct(&TlvTag::Anonymous)?;
                w.write_u8(&cx(1), e.fabric_idx.get())?;
                w.write_u64(&cx(2), e.check_in_node_id)?;
                w.write_u64(&cx(3), e.monitored_subject)?;
                w.write_bytes(&cx(4), &e.key)?;
                w.end_container()?;
            }
            w.end_container()?;
            w.end_container()?;
            w.len()
        };
        kvs.set(ICD_KEY, &buf[..len])
    }

    /// `kvs` からテーブル + ICDCounter を復元し、復元したエントリ数を返す。
    ///
    /// 空テーブルにのみ呼べる。レコードが無ければ `Ok(0)`(ICDCounter=0 のまま)。
    pub fn load_from<K: Kvs>(&mut self, kvs: &mut K) -> Result<usize> {
        if !self.entries.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut buf = [0u8; MAX_ICD_RECORD_LEN];
        let len = match kvs.get(ICD_KEY, &mut buf)? {
            Some(l) => l,
            None => return Ok(0),
        };
        let mut r = TlvReader::new(&buf[..len]);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut version: Option<u8> = None;
        let mut restored = 0usize;
        loop {
            let e = r.read_next()?.ok_or(Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => {
                    version = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                    if version != Some(ICD_SCHEMA_VERSION) {
                        return Err(Error::Decode);
                    }
                }
                (TlvTag::ContextSpecific(1), v) => {
                    self.icd_counter = v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?;
                }
                (TlvTag::ContextSpecific(2), TlvValue::ContainerStart(ContainerType::Array)) => {
                    loop {
                        let el = r.read_next()?.ok_or(Error::Decode)?;
                        match el.value {
                            TlvValue::ContainerEnd => break,
                            TlvValue::ContainerStart(ContainerType::Structure) => {
                                let entry = decode_registration(&mut r)?;
                                self.entries.push(entry).map_err(|_| Error::NoSpace)?;
                                restored += 1;
                            }
                            _ => return Err(Error::Decode),
                        }
                    }
                }
                _ => r.skip(&e)?,
            }
        }
        if version.is_none() {
            return Err(Error::Decode);
        }
        Ok(restored)
    }
}

/// 永続化レコードの 1 エントリを読む(構造体開始を消費済み)。
fn decode_registration(r: &mut TlvReader<'_>) -> Result<IcdRegistration> {
    let mut fabric: Option<u8> = None;
    let mut check_in: Option<u64> = None;
    let mut subject: Option<u64> = None;
    let mut key = [0u8; 16];
    let mut have_key = false;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => {
                fabric = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?)
            }
            (TlvTag::ContextSpecific(2), v) => check_in = Some(v.as_unsigned()?),
            (TlvTag::ContextSpecific(3), v) => subject = Some(v.as_unsigned()?),
            (TlvTag::ContextSpecific(4), v) => {
                let b = v.as_bytes()?;
                if b.len() != 16 {
                    return Err(Error::Decode);
                }
                key.copy_from_slice(b);
                have_key = true;
            }
            _ => r.skip(&e)?,
        }
    }
    let fabric = NonZeroU8::new(fabric.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    if !have_key {
        return Err(Error::Decode);
    }
    Ok(IcdRegistration::new(
        fabric,
        check_in.ok_or(Error::Decode)?,
        subject.ok_or(Error::Decode)?,
        key,
    ))
}

/// RemoveFabric 連動削除のための object-safe 境界(ACL の [`crate::acl::AclHandle`] と同じ流儀)。
///
/// `RefCell<IcdRegistrationTable<N>>` に実装する。IM エンジンは RemoveFabric / fabric 掃引で
/// この trait 越しに当該 fabric の登録を消す。
pub trait IcdRegistryHandle {
    /// `fabric` の登録エントリを全て削除する。
    fn remove_fabric(&self, fabric: NonZeroU8);
}

impl<const N: usize> IcdRegistryHandle for RefCell<IcdRegistrationTable<N>> {
    fn remove_fabric(&self, fabric: NonZeroU8) {
        self.borrow_mut().clear_fabric(fabric);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sit_default_is_valid_and_derives_intervals() {
        let c = IcdConfig::sit_default();
        assert!(c.validate().is_ok());
        // idle 2s → SII 2000ms、active 1000ms → SAI 1000ms。
        assert_eq!(c.advertised_sii_ms(), 2000);
        assert_eq!(c.advertised_sai_ms(), 1000);
    }

    #[test]
    fn validate_rejects_out_of_range() {
        assert!(IcdConfig {
            idle_mode_duration_s: 0,
            ..IcdConfig::sit_default()
        }
        .validate()
        .is_err());
        assert!(IcdConfig {
            idle_mode_duration_s: 100_000,
            ..IcdConfig::sit_default()
        }
        .validate()
        .is_err());
        assert!(IcdConfig {
            active_mode_duration_ms: 100,
            ..IcdConfig::sit_default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn intervals_are_clamped() {
        let c = IcdConfig {
            idle_mode_duration_s: 64_800, // 64_800_000 ms > 上限
            active_mode_duration_ms: 5_000_000,
            active_mode_threshold_ms: 500,
        };
        assert_eq!(c.advertised_sii_ms(), MAX_INTERVAL_MS);
        assert_eq!(c.advertised_sai_ms(), MAX_INTERVAL_MS);
    }

    #[test]
    fn starts_idle_can_sleep() {
        let s = IcdState::new(IcdConfig::sit_default());
        assert!(s.can_sleep(0));
        assert!(!s.is_active(0));
        // idle の起床は now + IdleModeDuration。
        assert_eq!(s.next_wake(0), 2000);
    }

    #[test]
    fn activity_enters_active_for_at_least_duration() {
        let mut s = IcdState::new(IcdConfig::sit_default()); // dur 1000, thr 500
        s.notify_activity(10_000);
        // 起床直後は最低 ActiveModeDuration(1000ms)active。
        assert!(s.is_active(10_500));
        assert!(s.is_active(10_999));
        assert!(!s.can_sleep(10_500));
        // active 窓終端で起床予定。
        assert_eq!(s.next_wake(10_500), 11_000);
        // 1000ms 後は idle に落ちる(その後の活動が無ければ)。
        assert!(s.can_sleep(11_000));
    }

    #[test]
    fn activity_while_active_extends_by_threshold() {
        let mut s = IcdState::new(IcdConfig::sit_default());
        s.notify_activity(0); // active_until = 1000(duration)
                              // 900ms 時点で再度通信 → threshold で 900+500=1400 まで延長。
        s.notify_activity(900);
        assert!(s.is_active(1000));
        assert!(s.is_active(1399));
        assert!(s.can_sleep(1400));
    }

    #[test]
    fn late_activity_uses_duration_floor_not_short_threshold() {
        let mut s = IcdState::new(IcdConfig::sit_default()); // dur 1000 > thr 500
                                                             // idle からの起床では threshold(500)ではなく duration(1000)が下限。
        s.notify_activity(5_000);
        assert!(s.is_active(5_900)); // 500ms(threshold)なら idle のはずが、duration で active
        assert!(s.can_sleep(6_000));
    }

    // ---- LIT: StayActiveRequest ----

    #[test]
    fn stay_active_extends_and_promises() {
        let mut s = IcdState::new(IcdConfig::sit_default());
        // idle 状態から 5s の stay-active を要求 → 約束 5000ms、5s 後まで active。
        let promised = s.stay_active(1_000, 5_000);
        assert_eq!(promised, 5_000);
        assert!(s.is_active(5_999));
        assert!(s.can_sleep(6_000));
    }

    #[test]
    fn stay_active_clamps_to_max() {
        let mut s = IcdState::new(IcdConfig::sit_default());
        let promised = s.stay_active(0, u32::MAX);
        assert_eq!(promised, STAY_ACTIVE_MAX_MS);
    }

    #[test]
    fn stay_active_keeps_longer_existing_window() {
        let mut s = IcdState::new(IcdConfig::sit_default());
        s.stay_active(0, 10_000); // active until 10_000
                                  // 短い要求(1000ms)は既存の長い窓を縮めない。約束は残り時間。
        let promised = s.stay_active(1_000, 1_000);
        assert_eq!(promised, 9_000);
        assert!(s.is_active(9_999));
    }

    // ---- check-in メッセージ ラウンドトリップ ----

    struct TestRng(u64);
    impl crate::crypto::Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for b in dest.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }
    fn backend() -> crate::crypto::rustcrypto::RustCrypto<TestRng> {
        crate::crypto::rustcrypto::RustCrypto::new(TestRng(0xDEAD_BEEF))
    }

    #[test]
    fn checkin_round_trip_recovers_counter() {
        let c = backend();
        let key = [0x11u8; 16];
        let mut msg = [0u8; CHECKIN_MAX_LEN];
        let n = generate_checkin(&c, &key, 0x0102_0304, &[], &mut msg).unwrap();
        assert_eq!(n, CHECKIN_MIN_LEN);
        let mut app = [0u8; CHECKIN_MAX_APP_DATA];
        let (counter, app_len) = open_checkin(&c, &key, &msg[..n], &mut app).unwrap();
        assert_eq!(counter, 0x0102_0304);
        assert_eq!(app_len, 0);
    }

    #[test]
    fn checkin_round_trip_with_app_data() {
        let c = backend();
        let key = [0x42u8; 16];
        let mut msg = [0u8; CHECKIN_MAX_LEN];
        let app_in = [0xAB, 0xCD, 0xEF];
        let n = generate_checkin(&c, &key, 7, &app_in, &mut msg).unwrap();
        let mut app = [0u8; CHECKIN_MAX_APP_DATA];
        let (counter, app_len) = open_checkin(&c, &key, &msg[..n], &mut app).unwrap();
        assert_eq!(counter, 7);
        assert_eq!(&app[..app_len], &app_in);
    }

    #[test]
    fn checkin_rejects_wrong_key() {
        let c = backend();
        let mut msg = [0u8; CHECKIN_MAX_LEN];
        let n = generate_checkin(&c, &[0x01u8; 16], 5, &[], &mut msg).unwrap();
        let mut app = [0u8; CHECKIN_MAX_APP_DATA];
        // 別の鍵では復号/検証に失敗する。
        assert!(open_checkin(&c, &[0x02u8; 16], &msg[..n], &mut app).is_err());
    }

    #[test]
    fn checkin_rejects_tampered_counter() {
        let c = backend();
        let key = [0x33u8; 16];
        let mut msg = [0u8; CHECKIN_MAX_LEN];
        let n = generate_checkin(&c, &key, 9, &[], &mut msg).unwrap();
        // 暗号文 1 バイトを改竄 → AES-CCM 検証 or nonce 再検証で必ず失敗。
        msg[CHECKIN_NONCE_LEN] ^= 0xFF;
        let mut app = [0u8; CHECKIN_MAX_APP_DATA];
        assert!(open_checkin(&c, &key, &msg[..n], &mut app).is_err());
    }

    // ---- 登録テーブル + 永続化 ----

    struct MemKvs {
        used: bool,
        val: [u8; MAX_ICD_RECORD_LEN],
        vlen: usize,
    }
    impl MemKvs {
        fn new() -> Self {
            Self {
                used: false,
                val: [0; MAX_ICD_RECORD_LEN],
                vlen: 0,
            }
        }
    }
    impl Kvs for MemKvs {
        fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
            assert_eq!(key, ICD_KEY);
            if !self.used {
                return Ok(None);
            }
            buf[..self.vlen].copy_from_slice(&self.val[..self.vlen]);
            Ok(Some(self.vlen))
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
            assert_eq!(key, ICD_KEY);
            self.val[..value.len()].copy_from_slice(value);
            self.vlen = value.len();
            self.used = true;
            Ok(())
        }
        fn remove(&mut self, _key: &[u8]) -> Result<()> {
            self.used = false;
            Ok(())
        }
    }

    fn f(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).unwrap()
    }

    #[test]
    fn register_upsert_and_per_fabric_limit() {
        let mut t: IcdRegistrationTable<8> = IcdRegistrationTable::new();
        t.register(IcdRegistration::new(f(1), 100, 100, [1; 16]))
            .unwrap();
        t.register(IcdRegistration::new(f(1), 101, 101, [2; 16]))
            .unwrap();
        assert_eq!(t.fabric_len(f(1)), ICD_CLIENTS_PER_FABRIC);
        // 3 つ目(異なる node)は per-fabric 上限で拒否。
        assert!(t
            .register(IcdRegistration::new(f(1), 102, 102, [3; 16]))
            .is_err());
        // 既存 node の upsert は許容(鍵更新)。
        t.register(IcdRegistration::new(f(1), 100, 100, [9; 16]))
            .unwrap();
        assert_eq!(t.key_of(f(1), 100), Some([9; 16]));
        assert_eq!(t.fabric_len(f(1)), ICD_CLIENTS_PER_FABRIC);
    }

    #[test]
    fn unregister_and_clear_fabric() {
        let mut t: IcdRegistrationTable<8> = IcdRegistrationTable::new();
        t.register(IcdRegistration::new(f(1), 100, 100, [1; 16]))
            .unwrap();
        t.register(IcdRegistration::new(f(2), 200, 200, [2; 16]))
            .unwrap();
        assert!(t.unregister(f(1), 999).is_err()); // 未登録
        t.unregister(f(1), 100).unwrap();
        assert_eq!(t.fabric_len(f(1)), 0);
        assert_eq!(t.clear_fabric(f(2)), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn persistence_round_trip_preserves_entries_and_counter() {
        let mut kvs = MemKvs::new();
        let mut t: IcdRegistrationTable<8> = IcdRegistrationTable::new();
        t.register(IcdRegistration::new(f(1), 0xAABB, 0xCCDD, [7; 16]))
            .unwrap();
        t.register(IcdRegistration::new(f(2), 0x1234, 0x5678, [8; 16]))
            .unwrap();
        assert_eq!(t.bump_counter(), 1);
        assert_eq!(t.bump_counter(), 2);
        t.save_to(&mut kvs).unwrap();

        let mut restored: IcdRegistrationTable<8> = IcdRegistrationTable::new();
        let n = restored.load_from(&mut kvs).unwrap();
        assert_eq!(n, 2);
        assert_eq!(restored.icd_counter(), 2);
        assert_eq!(restored.key_of(f(1), 0xAABB), Some([7; 16]));
        assert_eq!(restored.key_of(f(2), 0x1234), Some([8; 16]));
        // 再起動後も counter は単調増加を継続する。
        assert_eq!(restored.bump_counter(), 3);
    }

    #[test]
    fn counter_monotonic_across_reload() {
        let mut kvs = MemKvs::new();
        let mut t: IcdRegistrationTable<4> = IcdRegistrationTable::new();
        for _ in 0..5 {
            t.bump_counter();
            t.save_to(&mut kvs).unwrap();
        }
        assert_eq!(t.icd_counter(), 5);
        let mut r: IcdRegistrationTable<4> = IcdRegistrationTable::new();
        r.load_from(&mut kvs).unwrap();
        assert_eq!(r.icd_counter(), 5);
    }

    #[test]
    fn remove_fabric_via_handle() {
        let cell = RefCell::new({
            let mut t: IcdRegistrationTable<8> = IcdRegistrationTable::new();
            t.register(IcdRegistration::new(f(1), 100, 100, [1; 16]))
                .unwrap();
            t.register(IcdRegistration::new(f(2), 200, 200, [2; 16]))
                .unwrap();
            t
        });
        IcdRegistryHandle::remove_fabric(&cell, f(1));
        assert_eq!(cell.borrow().fabric_len(f(1)), 0);
        assert_eq!(cell.borrow().fabric_len(f(2)), 1);
    }
}
