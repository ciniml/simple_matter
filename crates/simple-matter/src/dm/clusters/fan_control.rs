//! Fan Control クラスタ(0x0202、`docs/design/basic-clusters.md` §2.2)。
//!
//! ファンの回転モード / 出力割合を担う。`FanMode`(enum8)と `PercentSetting`(nullable u8)は
//! 相互に連動し、`PercentCurrent`(u8)は [`ServerCluster::tick`](crate::dm::ServerCluster::tick)
//! で PercentSetting へランプ追従する(Level Control の遷移パターン簡略版、設計 §2.2)。
//!
//! FeatureMap=0、revision 4。SpeedSetting(SPD)/Rock/Wind/Auto はスコープ外(設計 §0-5)。
//!
//! # 連動(設計 §2.2)
//!
//! - FanMode write → PercentSetting へ写像(Off=0/Low=33/Med=66/High=100)。
//! - PercentSetting write → FanMode を再導出(0→Off / 1-33→Low / 34-66→Med / 67-100→High)。
//! - PercentSetting=null(Auto 相当)は AUTO feature 無しのため無効果(Success)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::AccessContext;
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;

/// FanMode = Off(0)。
const FAN_MODE_OFF: u8 = 0;
/// FanMode = High(3、受理する最大値)。
const FAN_MODE_HIGH: u8 = 3;
/// FanModeSequence 固定値(2 = Off/Low/Med/High、設計 §2.2)。
const FAN_MODE_SEQUENCE: u8 = 2;
/// PercentCurrent のランプ 1 刻み(ms)。10%/秒 = 1%/100ms(設計 §2.2)。
const TICK_STEP_MS: u64 = 100;

/// FanMode(0-3)を PercentSetting(%)へ写像する(設計 §2.2)。
const fn mode_to_percent(mode: u8) -> u8 {
    match mode {
        0 => 0,
        1 => 33,
        2 => 66,
        _ => 100,
    }
}

/// PercentSetting(%)から FanMode(0-3)を再導出する(設計 §2.2)。
const fn percent_to_mode(pct: u8) -> u8 {
    match pct {
        0 => 0,
        1..=33 => 1,
        34..=66 => 2,
        _ => 3,
    }
}

/// Fan Control クラスタ(0x0202)。
pub struct FanControlCluster {
    /// FanMode(0x0000、enum8、rw)。
    fan_mode: u8,
    /// PercentSetting(0x0002、nullable u8、rw)。
    percent_setting: Option<u8>,
    /// PercentCurrent(0x0003、u8、subscribe)。
    percent_current: u8,
    /// ランプ中フラグ。
    ramping: bool,
    /// 次にランプ処理する絶対時刻(ms)。
    next_tick_ms: u64,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// PercentCurrent 変化通知コールバック(任意。example の println/PWM 用)。
    on_change: Option<fn(u8)>,
}

impl FanControlCluster {
    /// 初期状態(Off / 0%)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            fan_mode: FAN_MODE_OFF,
            percent_setting: Some(0),
            percent_current: 0,
            ramping: false,
            next_tick_ms: 0,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// PercentCurrent 変化通知コールバックを登録する(level_control.rs と同型)。
    pub fn with_listener(mut self, cb: fn(u8)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の FanMode を返す(取得 API)。
    pub const fn fan_mode(&self) -> u8 {
        self.fan_mode
    }

    /// 現在の PercentSetting を返す(取得 API)。
    pub const fn percent_setting(&self) -> Option<u8> {
        self.percent_setting
    }

    /// 現在の PercentCurrent を返す(取得 API)。
    pub const fn percent_current(&self) -> u8 {
        self.percent_current
    }

    /// FanMode を適用し PercentSetting を写像する(設計 §2.2)。
    fn apply_fan_mode(&mut self, mode: u8, now: u64) {
        if self.fan_mode != mode {
            self.fan_mode = mode;
            self.dirty.mark();
        }
        let pct = mode_to_percent(mode);
        if self.percent_setting != Some(pct) {
            self.percent_setting = Some(pct);
            self.dirty.mark();
        }
        self.start_ramp(now);
    }

    /// PercentSetting を適用し FanMode を再導出する(設計 §2.2)。
    fn apply_percent_setting(&mut self, pct: u8, now: u64) {
        if self.percent_setting != Some(pct) {
            self.percent_setting = Some(pct);
            self.dirty.mark();
        }
        let mode = percent_to_mode(pct);
        if self.fan_mode != mode {
            self.fan_mode = mode;
            self.dirty.mark();
        }
        self.start_ramp(now);
    }

    /// PercentSetting へ向かうランプを開始する(現在値==目標なら何もしない、設計 §2.2)。
    fn start_ramp(&mut self, now: u64) {
        let target = self.percent_setting.unwrap_or(self.percent_current);
        if self.percent_current != target {
            self.ramping = true;
            self.next_tick_ms = now.saturating_add(TICK_STEP_MS);
            // 開始で dirty(設計 §2.2)。
            self.dirty.mark();
        } else {
            self.ramping = false;
        }
    }

    /// ランプエンジンの 1 ステップ(1%/100ms で PercentSetting へ追従、設計 §2.2)。
    ///
    /// dirty は 1% 変化ごと + 完了時に立てる。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if !self.ramping {
            return None;
        }
        let target = match self.percent_setting {
            Some(t) => t,
            None => {
                self.ramping = false;
                return None;
            }
        };
        let mut changed = false;
        while self.percent_current != target && now_ms >= self.next_tick_ms {
            if self.percent_current < target {
                self.percent_current += 1;
            } else {
                self.percent_current -= 1;
            }
            changed = true;
            self.next_tick_ms = self.next_tick_ms.saturating_add(TICK_STEP_MS);
        }
        if changed {
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(self.percent_current);
            }
        }
        if self.percent_current == target {
            self.ramping = false;
            // 完了で dirty。
            self.dirty.mark();
            return None;
        }
        Some(self.next_tick_ms)
    }

    // --- 属性 write ---

    /// FanMode(0x0000)。0-3 のみ受理、4-6(On/Auto/Smart)は AUTO 等 feature 無しのため
    /// ConstraintError(設計 §2.2)。
    fn write_fan_mode(&mut self, data: AttrWrite<'_>, now: u64) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > FAN_MODE_HIGH as u64 {
            return Err(ImStatus::ConstraintError);
        }
        self.apply_fan_mode(v as u8, now);
        Ok(())
    }

    /// PercentSetting(0x0002、nullable)。null(Auto 相当)は無効果 + Success、>100 は
    /// ConstraintError(設計 §2.2)。
    fn write_percent_setting(&mut self, data: AttrWrite<'_>, now: u64) -> Result<(), ImStatus> {
        if data.is_null() {
            // AUTO feature 無しのため無効果(Success)。
            return Ok(());
        }
        let v = data.as_unsigned()?;
        if v > 100 {
            return Err(ImStatus::ConstraintError);
        }
        self.apply_percent_setting(v as u8, now);
        Ok(())
    }
}

impl Default for FanControlCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    FanControlCluster {
        id: 0x0202,
        revision: 4,
        feature_map: 0,
        dirty: dirty,
        tick: on_tick,
        invoke: _,
        attributes: [
            0x0000 FanMode {
                access: View,
                quality: [NONVOLATILE],
                subscribe: true,
                read: (|c: &FanControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.fan_mode)),
                write: (Operate, |c: &mut FanControlCluster, data, acc: &AccessContext| c.write_fan_mode(data, acc.now_ms))
            },
            0x0001 FanModeSequence {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &FanControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(FAN_MODE_SEQUENCE)),
                write: _
            },
            0x0002 PercentSetting {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &FanControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_u8(c.percent_setting)),
                write: (Operate, |c: &mut FanControlCluster, data, acc: &AccessContext| c.write_percent_setting(data, acc.now_ms))
            },
            0x0003 PercentCurrent {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &FanControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.percent_current)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc(now_ms: u64) -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(now_ms, [0u8; 16])
    }

    fn encode_u8_value(buf: &mut [u8], v: u8) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_u8(&TlvTag::Anonymous, v).unwrap();
        w.len()
    }

    fn encode_null_value(buf: &mut [u8]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_null(&TlvTag::Anonymous).unwrap();
        w.len()
    }

    fn write_attr(
        c: &mut FanControlCluster,
        id: u16,
        buf: &[u8],
        now: u64,
    ) -> Result<(), ImStatus> {
        c.write_attribute(AttributeId(id as u32), AttrWrite::new(buf), &acc(now))
    }

    #[test]
    fn meta_and_reads() {
        let c = FanControlCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0202);
        assert_eq!(meta.revision, 4);
        assert_eq!(meta.feature_map, 0);
        // 固有属性 4 個、コマンド無し。
        assert_eq!(meta.attributes.len(), 4);
        assert!(meta.accepted_commands.is_empty());
        let mut buf = [0u8; 16];
        for am in meta.attributes {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            assert!(
                c.read_attribute(am.id, &mut e, &acc(0)).is_ok(),
                "attr {:#06x} read failed",
                am.id.0
            );
        }
    }

    #[test]
    fn fan_mode_maps_to_percent_setting() {
        let mut c = FanControlCluster::new();
        let mut buf = [0u8; 16];
        // FanMode=High(3)→ PercentSetting=100。
        let n = encode_u8_value(&mut buf, 3);
        write_attr(&mut c, 0x0000, &buf[..n], 0).unwrap();
        assert_eq!(c.fan_mode(), 3);
        assert_eq!(c.percent_setting(), Some(100));
        assert!(c.take_dirty());
        // FanMode=Med(2)→ 66。
        let n = encode_u8_value(&mut buf, 2);
        write_attr(&mut c, 0x0000, &buf[..n], 0).unwrap();
        assert_eq!(c.percent_setting(), Some(66));
    }

    #[test]
    fn percent_setting_re_derives_fan_mode() {
        let mut c = FanControlCluster::new();
        let mut buf = [0u8; 16];
        // PercentSetting=50 → FanMode=Med(2)。
        let n = encode_u8_value(&mut buf, 50);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        assert_eq!(c.percent_setting(), Some(50));
        assert_eq!(c.fan_mode(), 2);
        // 1 → Low(1)。
        let n = encode_u8_value(&mut buf, 1);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        assert_eq!(c.fan_mode(), 1);
        // 0 → Off(0)。
        let n = encode_u8_value(&mut buf, 0);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        assert_eq!(c.fan_mode(), 0);
    }

    #[test]
    fn constraint_errors() {
        let mut c = FanControlCluster::new();
        let mut buf = [0u8; 16];
        // FanMode=4(On)→ ConstraintError(feature 無し)。
        let n = encode_u8_value(&mut buf, 4);
        assert_eq!(
            write_attr(&mut c, 0x0000, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
        // PercentSetting=101 → ConstraintError。
        let n = encode_u8_value(&mut buf, 101);
        assert_eq!(
            write_attr(&mut c, 0x0002, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
    }

    #[test]
    fn percent_setting_null_is_no_op_success() {
        let mut c = FanControlCluster::new();
        let mut buf = [0u8; 16];
        // まず 100% にしておく。
        let n = encode_u8_value(&mut buf, 100);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        let _ = c.take_dirty();
        // null 書き込みは無効果 + Success。
        let n = encode_null_value(&mut buf);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        assert_eq!(c.percent_setting(), Some(100));
        assert_eq!(c.fan_mode(), 3);
        assert!(!c.take_dirty());
    }

    #[test]
    fn percent_current_ramps_to_setting() {
        let mut c = FanControlCluster::new();
        let mut buf = [0u8; 16];
        // PercentSetting=100 @ t=0 → PercentCurrent は 0 から 1%/100ms でランプ。
        let n = encode_u8_value(&mut buf, 100);
        write_attr(&mut c, 0x0002, &buf[..n], 0).unwrap();
        assert_eq!(c.percent_current(), 0);
        assert!(c.take_dirty()); // 開始で dirty

        // 500ms 経過 → 5%。
        assert!(c.tick(500).is_some());
        assert_eq!(c.percent_current(), 5);
        assert!(c.take_dirty());

        // 完了(10s)→ 100%、以降 tick は None。
        assert_eq!(c.tick(10_000), None);
        assert_eq!(c.percent_current(), 100);
        assert!(c.take_dirty());
        assert_eq!(c.tick(11_000), None);
    }
}
