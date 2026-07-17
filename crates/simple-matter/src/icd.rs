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

use crate::error::{Error, Result};

/// mDNS TXT / MRP の interval 上限(Matter 仕様、ミリ秒)。SII/SAI はこれを超えない。
pub const MAX_INTERVAL_MS: u32 = 3_600_000;

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
}
