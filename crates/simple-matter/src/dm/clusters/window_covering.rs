//! Window Covering クラスタ(0x0102、`docs/design/basic-clusters.md` §2.3)。
//!
//! ロールシェード等の昇降を担う。位置は percent100ths(0=全開/10000=全閉)で表し、
//! コマンドで目標位置を与えると [`ServerCluster::tick`](crate::dm::ServerCluster::tick) で
//! 1000(=10%)/秒の線形移動シムが Current を Target へ寄せる(設計 §2.3)。
//!
//! FeatureMap=LF|PA_LF=0x05、revision 5。Tilt / ABS はスコープ外(設計 §0-5)。
//!
//! # OperationalStatus(設計 §2.3)
//!
//! global bits0-1 + lift bits2-3 を同値で持つ。Opening=0b0101 / Closing=0b1010、停止で 0。
//! dirty は移動開始/停止/完了 + 位置 1%(=100 100ths)変化ごとに立てる(毎 tick スパムしない)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{AccessContext, CommandId};
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// Type = Rollershade(0)。
const TYPE_ROLLERSHADE: u8 = 0;
/// EndProductType = RollerShade(0)。
const END_PRODUCT_TYPE: u8 = 0;
/// ConfigStatus = Operational(bit0) | LiftPositionAware(bit3) = 0x09(設計 §2.3)。
const CONFIG_STATUS: u8 = 0x09;
/// 全開位置(percent100ths)。
const FULLY_OPEN: u16 = 0;
/// 全閉位置(percent100ths)。
const FULLY_CLOSED: u16 = 10_000;
/// OperationalStatus = Opening(global 0b01 | lift 0b01 = 0b0101)。
const OP_OPENING: u8 = 0b0101;
/// OperationalStatus = Closing(global 0b10 | lift 0b10 = 0b1010)。
const OP_CLOSING: u8 = 0b1010;
/// OperationalStatus = 停止。
const OP_STOPPED: u8 = 0;
/// 移動シムの 1 刻み(ms)。
const TICK_STEP_MS: u64 = 100;
/// 1 刻みの移動量(percent100ths)。1000/秒 × 0.1秒 = 100。
const STEP_PER_TICK: u16 = 100;
/// dirty を立てる位置変化のしきい値(percent100ths、= 1%)。
const DIRTY_THRESHOLD: u16 = 100;

/// Window Covering クラスタ(0x0102)。
pub struct WindowCoveringCluster {
    /// CurrentPositionLiftPercent100ths(0x000E、常に既知値としてシムする)。
    current_lift: u16,
    /// TargetPositionLiftPercent100ths(0x000B、nullable)。
    target_lift: Option<u16>,
    /// OperationalStatus(0x000A、map8)。
    operational_status: u8,
    /// Mode(0x0017、map8、rw、保持のみ)。
    mode: u8,
    /// 移動中フラグ。
    moving: bool,
    /// 次に移動処理する絶対時刻(ms)。
    next_tick_ms: u64,
    /// 最後に dirty を立てた位置(1% しきい値判定用)。
    last_dirty_lift: u16,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// 位置変化通知コールバック(任意。example の println/モータ用)。
    on_change: Option<fn(u16)>,
}

impl WindowCoveringCluster {
    /// 初期状態(全開 = 0、停止)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            current_lift: FULLY_OPEN,
            target_lift: None,
            operational_status: OP_STOPPED,
            mode: 0,
            moving: false,
            next_tick_ms: 0,
            last_dirty_lift: FULLY_OPEN,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// 位置変化通知コールバックを登録する(level_control.rs と同型)。
    pub fn with_listener(mut self, cb: fn(u16)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の CurrentPositionLiftPercent100ths を返す(取得 API)。
    pub const fn current_lift_100ths(&self) -> u16 {
        self.current_lift
    }

    /// 現在の OperationalStatus を返す(取得 API)。
    pub const fn operational_status(&self) -> u8 {
        self.operational_status
    }

    /// OperationalStatus を設定する。変化時のみ dirty を立てる。
    fn set_op_status(&mut self, v: u8) {
        if self.operational_status != v {
            self.operational_status = v;
            self.dirty.mark();
        }
    }

    /// 目標位置へ移動を開始する(設計 §2.3)。
    fn begin_move(&mut self, target: u16, now: u64) {
        self.target_lift = Some(target);
        // 目標更新で dirty(Target は subscribe 属性)。
        self.dirty.mark();
        if target == self.current_lift {
            self.moving = false;
            self.set_op_status(OP_STOPPED);
            return;
        }
        self.moving = true;
        // up(全開へ = 値を減らす)は Opening、down(全閉へ = 値を増やす)は Closing。
        let status = if target < self.current_lift {
            OP_OPENING
        } else {
            OP_CLOSING
        };
        self.set_op_status(status);
        self.next_tick_ms = now.saturating_add(TICK_STEP_MS);
        self.last_dirty_lift = self.current_lift;
    }

    /// 現在位置で停止する(StopMotion、設計 §2.3)。
    fn stop(&mut self) {
        self.moving = false;
        self.target_lift = Some(self.current_lift);
        self.set_op_status(OP_STOPPED);
        // 停止で dirty。
        self.dirty.mark();
    }

    /// 移動エンジンの 1 ステップ(設計 §2.3)。
    ///
    /// 100 100ths/tick(= 10%/秒)で Current を Target へ寄せる。1% 変化ごと + 完了で dirty。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if !self.moving {
            return None;
        }
        let target = match self.target_lift {
            Some(t) => t,
            None => {
                self.moving = false;
                return None;
            }
        };
        while self.current_lift != target && now_ms >= self.next_tick_ms {
            if self.current_lift < target {
                self.current_lift = self.current_lift.saturating_add(STEP_PER_TICK).min(target);
            } else {
                self.current_lift = self.current_lift.saturating_sub(STEP_PER_TICK).max(target);
            }
            self.next_tick_ms = self.next_tick_ms.saturating_add(TICK_STEP_MS);
        }
        // 1% 変化ごとに dirty(毎 tick スパムしないが本シムは 1 刻み = 1%)。
        if self.current_lift.abs_diff(self.last_dirty_lift) >= DIRTY_THRESHOLD {
            self.last_dirty_lift = self.current_lift;
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(self.current_lift);
            }
        }
        if self.current_lift == target {
            self.moving = false;
            self.set_op_status(OP_STOPPED);
            // 完了で dirty。
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(self.current_lift);
            }
            return None;
        }
        Some(self.next_tick_ms)
    }

    // --- 属性 write ---

    /// Mode(0x0017、map8、保持のみ)。
    fn write_mode(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > u8::MAX as u64 {
            return Err(ImStatus::ConstraintError);
        }
        self.mode = v as u8;
        self.dirty.mark();
        Ok(())
    }

    // --- コマンド ---

    /// GoToLiftPercentage(0x05): `{ 0: liftPercent100thsValue u16 }`。>10000 は ConstraintError。
    fn cmd_go_to_lift(&mut self, fields: &mut TlvReader<'_>, now: u64) -> Result<(), ImStatus> {
        let mut val: Option<u16> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                val = v.as_unsigned().ok().map(|x| x as u16);
            }
        }
        let val = val.ok_or(ImStatus::InvalidCommand)?;
        if val > FULLY_CLOSED {
            return Err(ImStatus::ConstraintError);
        }
        self.begin_move(val, now);
        Ok(())
    }

    /// コマンドディスパッチ(設計 §2.3)。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let now = acc.now_ms;
        match cmd.0 {
            0x00 => {
                self.begin_move(FULLY_OPEN, now);
                Ok(())
            }
            0x01 => {
                self.begin_move(FULLY_CLOSED, now);
                Ok(())
            }
            0x02 => {
                self.stop();
                Ok(())
            }
            0x05 => self.cmd_go_to_lift(fields, now),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for WindowCoveringCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    WindowCoveringCluster {
        id: 0x0102,
        revision: 5,
        // FeatureMap bit0 = Lift(LF) / bit2 = PositionAwareLift(PA_LF)(設計 §2.3)。
        feature_map: 0x05,
        dirty: dirty,
        tick: on_tick,
        invoke: (|c: &mut WindowCoveringCluster, cmd, fields, _resp, acc| {
            c.invoke_cmd(cmd, fields, acc)
        }),
        attributes: [
            0x0000 Type {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(TYPE_ROLLERSHADE)),
                write: _
            },
            0x0007 ConfigStatus {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(CONFIG_STATUS)),
                write: _
            },
            0x0008 CurrentPositionLiftPercentage {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_u8(Some((c.current_lift / 100) as u8))),
                write: _
            },
            0x000A OperationalStatus {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.operational_status)),
                write: _
            },
            0x000B TargetPositionLiftPercent100ths {
                access: View,
                quality: [SCENE],
                subscribe: true,
                read: (|c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_u16(c.target_lift)),
                write: _
            },
            0x000D EndProductType {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(END_PRODUCT_TYPE)),
                write: _
            },
            0x000E CurrentPositionLiftPercent100ths {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_u16(Some(c.current_lift))),
                write: _
            },
            0x0017 Mode {
                access: View,
                quality: [NONVOLATILE],
                subscribe: false,
                read: (|c: &WindowCoveringCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.mode)),
                write: (Operate, |c: &mut WindowCoveringCluster, data, _acc| c.write_mode(data))
            },
        ],
        accepted: [
            0x00 UpOrOpen,
            0x01 DownOrClose,
            0x02 StopMotion,
            0x05 GoToLiftPercentage,
        ],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{ContainerType, TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc(now_ms: u64) -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(now_ms, [0u8; 16])
    }

    fn build_lift(buf: &mut [u8], val: u16) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(0), val).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(
        c: &mut WindowCoveringCluster,
        cmd: u16,
        fields: &[u8],
        now_ms: u64,
    ) -> Result<(), ImStatus> {
        let mut scratch = [0u8; 128];
        let mut sw = TlvWriter::new(&mut scratch);
        let mut resp = CmdResponder::new(&mut sw);
        let mut fr = TlvReader::new(fields);
        c.invoke_command(CommandId(cmd as u32), &mut fr, &mut resp, &acc(now_ms))
    }

    #[test]
    fn meta_and_reads() {
        let c = WindowCoveringCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0102);
        assert_eq!(meta.revision, 5);
        assert_eq!(meta.feature_map, 0x05);
        // 固有属性 8 個、コマンド 4 個。
        assert_eq!(meta.attributes.len(), 8);
        assert_eq!(meta.accepted_commands.len(), 4);
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
    fn down_close_moves_and_completes() {
        let mut c = WindowCoveringCluster::new();
        // DownOrClose @ t=0 → target=10000、Closing。
        invoke(&mut c, 0x01, &[], 0).unwrap();
        assert_eq!(c.operational_status(), OP_CLOSING);
        assert!(c.take_dirty()); // 開始 dirty
        assert_eq!(c.current_lift_100ths(), 0);

        // 1 秒後 → 1000(10%)。
        assert!(c.tick(1_000).is_some());
        assert_eq!(c.current_lift_100ths(), 1000);
        assert!(c.take_dirty());

        // 完了(10 秒)→ 10000、停止。
        assert_eq!(c.tick(10_000), None);
        assert_eq!(c.current_lift_100ths(), 10_000);
        assert_eq!(c.operational_status(), OP_STOPPED);
        assert!(c.take_dirty());
    }

    #[test]
    fn up_open_reports_opening() {
        let mut c = WindowCoveringCluster::new();
        // まず全閉へ即時にしておく。
        invoke(&mut c, 0x01, &[], 0).unwrap();
        assert_eq!(c.tick(10_000), None);
        let _ = c.take_dirty();
        // UpOrOpen → target=0、Opening。
        invoke(&mut c, 0x00, &[], 10_000).unwrap();
        assert_eq!(c.operational_status(), OP_OPENING);
        assert!(c.tick(11_000).is_some());
        assert_eq!(c.current_lift_100ths(), 9000);
    }

    #[test]
    fn stop_motion_halts_at_current() {
        let mut c = WindowCoveringCluster::new();
        invoke(&mut c, 0x01, &[], 0).unwrap();
        assert!(c.tick(500).is_some());
        let mid = c.current_lift_100ths();
        assert!((0..10_000).contains(&mid));
        // StopMotion → 現在位置で停止。
        invoke(&mut c, 0x02, &[], 500).unwrap();
        assert_eq!(c.operational_status(), OP_STOPPED);
        // 以降 tick は進まない。
        assert_eq!(c.tick(1_000), None);
        assert_eq!(c.current_lift_100ths(), mid);
    }

    #[test]
    fn go_to_lift_percentage_and_constraint() {
        let mut c = WindowCoveringCluster::new();
        let mut buf = [0u8; 16];
        // GoToLiftPercentage(5000 = 50%)→ Closing(0 → 5000)。
        let n = build_lift(&mut buf, 5000);
        invoke(&mut c, 0x05, &buf[..n], 0).unwrap();
        assert_eq!(c.operational_status(), OP_CLOSING);
        assert_eq!(c.tick(5_000), None);
        assert_eq!(c.current_lift_100ths(), 5000);

        // >10000 は ConstraintError。
        let n = build_lift(&mut buf, 10_001);
        assert_eq!(
            invoke(&mut c, 0x05, &buf[..n], 6_000),
            Err(ImStatus::ConstraintError)
        );
    }

    #[test]
    fn mode_write_is_retained() {
        let mut c = WindowCoveringCluster::new();
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_u8(&TlvTag::Anonymous, 0x02).unwrap();
        let n = w.len();
        c.write_attribute(AttributeId(0x0017), AttrWrite::new(&buf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.mode, 0x02);
        assert!(c.take_dirty());
    }
}
