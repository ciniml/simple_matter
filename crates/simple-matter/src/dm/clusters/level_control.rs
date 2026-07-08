//! Level Control クラスタ(0x0008、`docs/design/interaction-model.md` §15.3)。
//!
//! Dimmable Light の調光を担う。`CurrentLevel`(nullable u8)を TransitionTime に沿って
//! 線形補間する遷移エンジンを [`ServerCluster::tick`](crate::dm::ServerCluster::tick) で駆動する
//! (invoke 後も時間とともに属性が変わる初のクラスタ。設計 §15.1)。
//!
//! FeatureMap=0x03(OnOff bit0 | Lighting bit1)、revision 6。LT に伴い MinLevel=1 /
//! MaxLevel=254 / StartUpCurrentLevel を持つ(設計 §15.3)。
//!
//! # OnOff 連動(設計 §15.3)
//!
//! クラスタ間結合は他クラスタ直参照を避け、アプリ(DataModel 実装)が仲介する契約にする。
//! Level → OnOff は [`take_on_off_request`](LevelControlCluster::take_on_off_request)、
//! OnOff → Level は [`notify_on_off`](LevelControlCluster::notify_on_off)、現在把握している
//! OnOff 状態は [`coupled_on`](LevelControlCluster::coupled_on) で受け渡す。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{AccessContext, CommandId};
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;
use crate::tlv::{TlvReader, TlvValue};

/// MinLevel(0x0002、LT 固定値)。
const MIN_LEVEL: u8 = 1;
/// MaxLevel(0x0003、LT 固定値)。
const MAX_LEVEL: u8 = 254;
/// 遷移中に返す tick 刻み幅(ms)。設計 §15.3: 残り時間から算出せず固定刻みで十分。
const TICK_STEP_MS: u64 = 50;
/// Options bit0 = ExecuteIfOff(Off 中でも実行する。§1.6.6.1)。
const OPT_EXECUTE_IF_OFF: u8 = 1 << 0;

/// 進行中の線形遷移(設計 §15.3)。
#[derive(Debug, Clone, Copy)]
struct Transition {
    /// 遷移開始時の CurrentLevel(null は MinLevel 起点に丸める)。
    start_level: u8,
    /// 目標 CurrentLevel(Min/Max へクランプ済み)。
    target: u8,
    /// 開始時刻(ms)。
    start_ms: u64,
    /// 完了時刻(ms)。
    end_ms: u64,
    /// WithOnOff 変種か(完了時の Off 要求判定に使う)。
    with_onoff: bool,
}

/// Level Control クラスタ(0x0008)。
pub struct LevelControlCluster {
    /// CurrentLevel(0x0000、nullable u8)。
    current_level: Option<u8>,
    /// RemainingTime(0x0001、0.1s 単位)。
    remaining_time: u16,
    /// Options(0x000F、map8)。
    options: u8,
    /// OnOffTransitionTime(0x0010、0.1s 単位)。
    on_off_transition_time: u16,
    /// OnLevel(0x0011、nullable u8)。
    on_level: Option<u8>,
    /// StartUpCurrentLevel(0x4000、nullable u8。保持のみ)。
    start_up_current_level: Option<u8>,
    /// 進行中の遷移(無ければ `None`)。
    transition: Option<Transition>,
    /// Level → OnOff の要求(WithOnOff 変種。アプリが [`take_on_off_request`] で取り出す)。
    ///
    /// [`take_on_off_request`]: LevelControlCluster::take_on_off_request
    on_off_request: Option<bool>,
    /// 現在把握している OnOff 状態(設計 §15.3)。
    coupled_on: bool,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// CurrentLevel 変化通知コールバック(任意。example の println/LED 用)。
    on_change: Option<fn(Option<u8>)>,
}

/// ms を 0.1s 単位へ切り上げる(RemainingTime。u16 飽和)。
fn ms_to_ds_ceil(ms: u64) -> u16 {
    (ms.saturating_add(99) / 100).min(u16::MAX as u64) as u16
}

impl LevelControlCluster {
    /// 初期状態(CurrentLevel=Some(1)、Off 連動 false)のクラスタを作る(設計 §15.3)。
    pub const fn new() -> Self {
        Self {
            current_level: Some(MIN_LEVEL),
            remaining_time: 0,
            options: 0,
            on_off_transition_time: 0,
            on_level: None,
            start_up_current_level: None,
            transition: None,
            on_off_request: None,
            coupled_on: false,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// CurrentLevel 変化通知コールバックを登録する(on_off.rs と同型)。
    pub fn with_listener(mut self, cb: fn(Option<u8>)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の CurrentLevel(取得 API)。
    pub const fn current_level(&self) -> Option<u8> {
        self.current_level
    }

    /// Level → OnOff の要求を取り出す(WithOnOff 変種。設計 §15.3)。
    pub fn take_on_off_request(&mut self) -> Option<bool> {
        self.on_off_request.take()
    }

    /// 現在把握している OnOff 状態を返す(設計 §15.3)。
    pub const fn coupled_on(&self) -> bool {
        self.coupled_on
    }

    /// OnOff → Level の変化通知(外部要因の On/Off。設計 §15.3)。
    ///
    /// `true`(外部の On コマンド等): OnLevel が非 null なら CurrentLevel=OnLevel を即時反映。
    /// `false`(外部の Off): 進行中の遷移を中断する。
    pub fn notify_on_off(&mut self, on: bool) {
        self.coupled_on = on;
        if on {
            if let Some(lvl) = self.on_level {
                self.transition = None;
                self.remaining_time = 0;
                self.set_level(Some(lvl));
            }
        } else if self.transition.is_some() {
            self.transition = None;
            self.remaining_time = 0;
            self.dirty.mark();
        }
    }

    /// CurrentLevel を設定する。変化時のみ dirty を立ててコールバックを呼ぶ。
    fn set_level(&mut self, level: Option<u8>) {
        if self.current_level != level {
            self.current_level = level;
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(level);
            }
        }
    }

    /// Level → OnOff の要求を積む。`coupled_on` も更新し、sync ループの余計な
    /// [`notify_on_off`](Self::notify_on_off) 再入を防ぐ(設計 §15.3)。
    fn request_on_off(&mut self, on: bool) {
        self.on_off_request = Some(on);
        self.coupled_on = on;
    }

    /// optionsMask/optionsOverride を適用した実効 Options(§1.6.6.1)。
    const fn effective_options(&self, mask: u8, over: u8) -> u8 {
        (self.options & !mask) | (over & mask)
    }

    /// 非 WithOnOff コマンドを実行してよいか(ExecuteIfOff 判定、設計 §15.3)。
    ///
    /// OnOff が On(`coupled_on`)なら常に実行。Off 中は実効 Options の ExecuteIfOff が
    /// 立っているときだけ実行する。
    const fn should_execute(&self, mask: u8, over: u8) -> bool {
        self.coupled_on || (self.effective_options(mask, over) & OPT_EXECUTE_IF_OFF != 0)
    }

    /// 遷移を開始する(設計 §15.3)。
    ///
    /// WithOnOff で目標 > MinLevel なら開始時に On 要求。`duration_ms == 0` または
    /// 開始値==目標なら即時完了。
    fn begin_transition(&mut self, target: u8, duration_ms: u64, now: u64, with_onoff: bool) {
        let start_level = self.current_level.unwrap_or(MIN_LEVEL);
        if with_onoff && target > MIN_LEVEL {
            self.request_on_off(true);
        }
        if duration_ms == 0 || start_level == target {
            self.finish_transition(target, with_onoff);
            return;
        }
        self.transition = Some(Transition {
            start_level,
            target,
            start_ms: now,
            end_ms: now.saturating_add(duration_ms),
            with_onoff,
        });
        // 遷移開始で RemainingTime を報告(dirty はここで立てる。設計 §15.3)。
        self.remaining_time = ms_to_ds_ceil(duration_ms);
        self.dirty.mark();
    }

    /// 遷移を完了する(目標確定 + RemainingTime=0、設計 §15.3)。
    fn finish_transition(&mut self, target: u8, with_onoff: bool) {
        self.set_level(Some(target));
        self.remaining_time = 0;
        self.transition = None;
        // 完了時は(値が変わっていなくても)報告する。
        self.dirty.mark();
        // WithOnOff で目標==MinLevel なら完了時に Off 要求。
        if with_onoff && target == MIN_LEVEL {
            self.request_on_off(false);
        }
    }

    /// MoveToLevel(0x00)/ MoveToLevelWithOnOff(0x04)。
    fn cmd_move_to_level(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
        with_onoff: bool,
    ) -> Result<(), ImStatus> {
        let mut level: Option<u8> = None;
        let mut ttime: Option<u16> = None;
        let mut mask = 0u8;
        let mut over = 0u8;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => level = v.as_unsigned().ok().map(|x| x as u8),
                1 => ttime = nullable_u16(v),
                2 => mask = v.as_unsigned().unwrap_or(0) as u8,
                3 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let level = level.ok_or(ImStatus::InvalidCommand)?;
        if !with_onoff && !self.should_execute(mask, over) {
            return Ok(());
        }
        let target = level.clamp(MIN_LEVEL, MAX_LEVEL);
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin_transition(target, duration_ms, now, with_onoff);
        Ok(())
    }

    /// Move(0x01)/ MoveWithOnOff(0x05)。
    fn cmd_move(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
        with_onoff: bool,
    ) -> Result<(), ImStatus> {
        let mut mode: Option<u8> = None;
        let mut rate: Option<u8> = None; // null / 0 は即時
        let mut mask = 0u8;
        let mut over = 0u8;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => mode = v.as_unsigned().ok().map(|x| x as u8),
                1 => rate = nullable_u8(v),
                2 => mask = v.as_unsigned().unwrap_or(0) as u8,
                3 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let mode = mode.ok_or(ImStatus::InvalidCommand)?;
        // moveMode 0=Up / 1=Down、それ以外 ConstraintError(設計 §15.3)。
        let target = match mode {
            0 => MAX_LEVEL,
            1 => MIN_LEVEL,
            _ => return Err(ImStatus::ConstraintError),
        };
        if !with_onoff && !self.should_execute(mask, over) {
            return Ok(());
        }
        let start_level = self.current_level.unwrap_or(MIN_LEVEL);
        // Rate(units/s)。null または 0 は即時(設計 §15.3)。
        let duration_ms = match rate {
            Some(r) if r > 0 => {
                let delta = (start_level as i32 - target as i32).unsigned_abs() as u64;
                delta * 1000 / r as u64
            }
            _ => 0,
        };
        self.begin_transition(target, duration_ms, now, with_onoff);
        Ok(())
    }

    /// Step(0x02)/ StepWithOnOff(0x06)。
    fn cmd_step(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
        with_onoff: bool,
    ) -> Result<(), ImStatus> {
        let mut mode: Option<u8> = None;
        let mut size: Option<u8> = None;
        let mut ttime: Option<u16> = None;
        let mut mask = 0u8;
        let mut over = 0u8;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => mode = v.as_unsigned().ok().map(|x| x as u8),
                1 => size = v.as_unsigned().ok().map(|x| x as u8),
                2 => ttime = nullable_u16(v),
                3 => mask = v.as_unsigned().unwrap_or(0) as u8,
                4 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let mode = mode.ok_or(ImStatus::InvalidCommand)?;
        let size = size.ok_or(ImStatus::InvalidCommand)?;
        if !with_onoff && !self.should_execute(mask, over) {
            return Ok(());
        }
        let start_level = self.current_level.unwrap_or(MIN_LEVEL);
        // stepMode 0=Up / 1=Down、それ以外 ConstraintError。Min/Max へクランプ。
        let target = match mode {
            0 => start_level.saturating_add(size).min(MAX_LEVEL),
            1 => start_level.saturating_sub(size).max(MIN_LEVEL),
            _ => return Err(ImStatus::ConstraintError),
        };
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin_transition(target, duration_ms, now, with_onoff);
        Ok(())
    }

    /// Stop(0x03)/ StopWithOnOff(0x07)。進行中の遷移を止め現在値で固定する。
    fn cmd_stop(&mut self, fields: &mut TlvReader<'_>, with_onoff: bool) -> Result<(), ImStatus> {
        let mut mask = 0u8;
        let mut over = 0u8;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => mask = v.as_unsigned().unwrap_or(0) as u8,
                1 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        if !with_onoff && !self.should_execute(mask, over) {
            return Ok(());
        }
        if self.transition.is_some() {
            self.transition = None;
            self.remaining_time = 0;
            self.dirty.mark();
        }
        Ok(())
    }

    /// コマンドディスパッチ(0x00-0x07)。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let now = acc.now_ms;
        match cmd.0 {
            0x00 => self.cmd_move_to_level(fields, now, false),
            0x01 => self.cmd_move(fields, now, false),
            0x02 => self.cmd_step(fields, now, false),
            0x03 => self.cmd_stop(fields, false),
            0x04 => self.cmd_move_to_level(fields, now, true),
            0x05 => self.cmd_move(fields, now, true),
            0x06 => self.cmd_step(fields, now, true),
            0x07 => self.cmd_stop(fields, true),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    /// 遷移エンジンの 1 ステップ(設計 §15.1/§15.3)。
    ///
    /// 完了していれば target を確定して `None`。進行中は線形補間して量子化後の CurrentLevel が
    /// 変わったときだけ dirty を立て、RemainingTime を毎回更新して次刻みを返す。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        let t = self.transition?;
        if now_ms >= t.end_ms {
            self.finish_transition(t.target, t.with_onoff);
            return None;
        }
        // 線形補間(整数演算、桁あふれ回避に i64)。
        let span = (t.end_ms - t.start_ms) as i64;
        let elapsed = (now_ms - t.start_ms) as i64;
        let delta = t.target as i64 - t.start_level as i64;
        let level = (t.start_level as i64 + delta * elapsed / span)
            .clamp(MIN_LEVEL as i64, MAX_LEVEL as i64) as u8;
        // 量子化後 CurrentLevel が変わったときのみ dirty(set_level 内)。
        self.set_level(Some(level));
        // RemainingTime は毎 tick 更新(dirty は立てない。設計 §15.3)。
        self.remaining_time = ms_to_ds_ceil(t.end_ms - now_ms);
        Some(now_ms.saturating_add(TICK_STEP_MS))
    }

    // --- 属性 read ---

    fn read_current_level(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_nullable_u8(self.current_level)
    }

    fn read_on_level(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_nullable_u8(self.on_level)
    }

    fn read_start_up(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_nullable_u8(self.start_up_current_level)
    }

    // --- 属性 write ---

    /// Options(0x000F)。0..=3 以外は ConstraintError(設計 §15.3)。
    fn write_options(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > 3 {
            return Err(ImStatus::ConstraintError);
        }
        self.options = v as u8;
        self.dirty.mark();
        Ok(())
    }

    /// OnOffTransitionTime(0x0010、0.1s 単位)。
    fn write_on_off_transition_time(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > u16::MAX as u64 {
            return Err(ImStatus::ConstraintError);
        }
        self.on_off_transition_time = v as u16;
        self.dirty.mark();
        Ok(())
    }

    /// OnLevel(0x0011、nullable)。1..=254 または null 以外は ConstraintError(設計 §15.3)。
    fn write_on_level(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        if data.is_null() {
            self.on_level = None;
        } else {
            let v = data.as_unsigned()?;
            if !(1..=254).contains(&v) {
                return Err(ImStatus::ConstraintError);
            }
            self.on_level = Some(v as u8);
        }
        self.dirty.mark();
        Ok(())
    }

    /// StartUpCurrentLevel(0x4000、nullable u8。保持のみ)。
    fn write_start_up(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        if data.is_null() {
            self.start_up_current_level = None;
        } else {
            let v = data.as_unsigned()?;
            if v > 254 {
                return Err(ImStatus::ConstraintError);
            }
            self.start_up_current_level = Some(v as u8);
        }
        self.dirty.mark();
        Ok(())
    }
}

impl Default for LevelControlCluster {
    fn default() -> Self {
        Self::new()
    }
}

/// nullable u8 フィールドを解釈する(null → `None`)。
fn nullable_u8(v: TlvValue<'_>) -> Option<u8> {
    match v {
        TlvValue::Null => None,
        other => other.as_unsigned().ok().map(|x| x as u8),
    }
}

/// nullable u16 フィールドを解釈する(null → `None`)。
fn nullable_u16(v: TlvValue<'_>) -> Option<u16> {
    match v {
        TlvValue::Null => None,
        other => other.as_unsigned().ok().map(|x| x as u16),
    }
}

cluster! {
    LevelControlCluster {
        id: 0x0008,
        revision: 6,
        // FeatureMap bit0 = OnOff / bit1 = Lighting(設計 §15.3)。
        feature_map: 0x03,
        dirty: dirty,
        tick: on_tick,
        invoke: (|c: &mut LevelControlCluster, cmd, fields, _resp, acc| {
            c.invoke_cmd(cmd, fields, acc)
        }),
        attributes: [
            0x0000 CurrentLevel {
                access: View,
                quality: [NONVOLATILE, SCENE],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| c.read_current_level(e)),
                write: _
            },
            0x0001 RemainingTime {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.remaining_time)),
                write: _
            },
            0x0002 MinLevel {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(MIN_LEVEL)),
                write: _
            },
            0x0003 MaxLevel {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(MAX_LEVEL)),
                write: _
            },
            0x000F Options {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.options)),
                write: (Operate, |c: &mut LevelControlCluster, data, _acc| c.write_options(data))
            },
            0x0010 OnOffTransitionTime {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.on_off_transition_time)),
                write: (Operate, |c: &mut LevelControlCluster, data, _acc| c.write_on_off_transition_time(data))
            },
            0x0011 OnLevel {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| c.read_on_level(e)),
                write: (Operate, |c: &mut LevelControlCluster, data, _acc| c.write_on_level(data))
            },
            0x4000 StartUpCurrentLevel {
                access: View,
                quality: [NONVOLATILE],
                subscribe: true,
                read: (|c: &LevelControlCluster, e: &mut AttrEncoder<'_, '_>| c.read_start_up(e)),
                write: (Operate, |c: &mut LevelControlCluster, data, _acc| c.write_start_up(data))
            },
        ],
        accepted: [
            0x00 MoveToLevel,
            0x01 Move,
            0x02 Step,
            0x03 Stop,
            0x04 MoveToLevelWithOnOff,
            0x05 MoveWithOnOff,
            0x06 StepWithOnOff,
            0x07 StopWithOnOff,
        ],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::{AttrWrite, ServerCluster};
    use crate::tlv::{ContainerType, TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc(now_ms: u64) -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(now_ms, [0u8; 16])
    }

    /// context タグ付きフィールド構造体を組む(u8/u16/null を書ける最小ビルダ)。
    enum FieldVal {
        U8(u8),
        U16(u16),
        Null,
    }

    fn build_fields(buf: &mut [u8], fields: &[(u8, FieldVal)]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        for (tag, v) in fields {
            let t = TlvTag::ContextSpecific(*tag);
            match v {
                FieldVal::U8(x) => w.write_u8(&t, *x).unwrap(),
                FieldVal::U16(x) => w.write_u16(&t, *x).unwrap(),
                FieldVal::Null => w.write_null(&t).unwrap(),
            }
        }
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(
        c: &mut LevelControlCluster,
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

    #[test]
    fn move_to_level_immediate() {
        let mut c = LevelControlCluster::new();
        let mut buf = [0u8; 64];
        // transitionTime = 0 → 即時。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(128)),
                (1, FieldVal::U16(0)),
                (2, FieldVal::U8(0)),
                (3, FieldVal::U8(0)),
            ],
        );
        // Off 中でも ExecuteIfOff 無しの MoveToLevel は無効果になるので、まず On 連動させる。
        c.notify_on_off(true);
        invoke(&mut c, 0x00, &buf[..n], 1_000).unwrap();
        assert_eq!(c.current_level(), Some(128));
        assert_eq!(c.remaining_time, 0);
        assert!(c.take_dirty());
        // 遷移は無いので tick は None。
        assert_eq!(c.on_tick(2_000), None);
    }

    #[test]
    fn move_to_level_timed_transition() {
        let mut c = LevelControlCluster::new();
        c.notify_on_off(true); // On にして非 WithOnOff を実行可能に
        let _ = c.take_dirty();
        let mut buf = [0u8; 64];
        // level=101, transitionTime=100(=10.0s)。start=1 → 100 段を 10s。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(101)), (1, FieldVal::U16(100))]);
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        // 開始で RemainingTime=100、dirty。
        assert_eq!(c.remaining_time, 100);
        assert!(c.take_dirty());
        assert_eq!(c.current_level(), Some(1));

        // 5s 経過 → 中間値 ~51。
        assert!(c.on_tick(5_000).is_some());
        assert_eq!(c.current_level(), Some(51));
        assert!(c.take_dirty()); // 値が変わったので dirty
                                 // RemainingTime は減衰(約 50)。
        assert_eq!(c.remaining_time, 50);

        // 完了。
        assert_eq!(c.on_tick(10_000), None);
        assert_eq!(c.current_level(), Some(101));
        assert_eq!(c.remaining_time, 0);
        assert!(c.take_dirty());
    }

    #[test]
    fn move_to_level_with_on_off_requests_on_then_off() {
        let mut c = LevelControlCluster::new();
        // Off から MoveToLevelWithOnOff 200(即時)→ On 要求。
        let mut buf = [0u8; 64];
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(200)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x04, &buf[..n], 0).unwrap();
        assert_eq!(c.take_on_off_request(), Some(true));
        assert_eq!(c.current_level(), Some(200));
        assert!(c.coupled_on());

        // MoveToLevelWithOnOff min(1) を時間遷移 → 完了時に Off 要求。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(1)), (1, FieldVal::U16(20))]);
        invoke(&mut c, 0x04, &buf[..n], 1_000).unwrap();
        // 開始時点では Off 要求なし。
        assert_eq!(c.take_on_off_request(), None);
        // 完了させる。
        assert_eq!(c.on_tick(3_000), None);
        assert_eq!(c.current_level(), Some(1));
        assert_eq!(c.take_on_off_request(), Some(false));
        assert!(!c.coupled_on());
    }

    #[test]
    fn notify_on_off_applies_on_level() {
        let mut c = LevelControlCluster::new();
        // OnLevel=Some(64) を書く。
        let mut wbuf = [0u8; 16];
        let n = encode_u8_value(&mut wbuf, 64);
        c.write_attribute(AttributeId(0x0011), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        let _ = c.take_dirty();
        // 外部 On → CurrentLevel=OnLevel。
        c.notify_on_off(true);
        assert_eq!(c.current_level(), Some(64));
        assert!(c.take_dirty());
        assert!(c.coupled_on());
    }

    #[test]
    fn execute_if_off_gating() {
        let mut c = LevelControlCluster::new();
        // Off(coupled_on=false)。MoveToLevel(非 WithOnOff)は無効果 + Success。
        let mut buf = [0u8; 64];
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(200)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.current_level(), Some(1)); // 変化なし
        assert!(!c.take_dirty());

        // optionsOverride で ExecuteIfOff を一時的に立てる(mask=1, override=1)。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(200)),
                (1, FieldVal::U16(0)),
                (2, FieldVal::U8(0x01)),
                (3, FieldVal::U8(0x01)),
            ],
        );
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.current_level(), Some(200));
    }

    #[test]
    fn move_step_stop_basic() {
        let mut c = LevelControlCluster::new();
        c.notify_on_off(true);
        let _ = c.take_dirty();
        let mut buf = [0u8; 64];

        // Move Up rate=None(即時)→ Max。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(0)), (1, FieldVal::Null)]);
        invoke(&mut c, 0x01, &buf[..n], 0).unwrap();
        assert_eq!(c.current_level(), Some(MAX_LEVEL));

        // Step Down size=54, transitionTime=10(=1s)。254 → 200。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(1)),
                (1, FieldVal::U8(54)),
                (2, FieldVal::U16(10)),
            ],
        );
        invoke(&mut c, 0x02, &buf[..n], 0).unwrap();
        assert!(c.remaining_time > 0);
        // 途中で Stop → 現在値で固定。
        assert!(c.on_tick(500).is_some());
        let mid = c.current_level().unwrap();
        assert!((200..=254).contains(&mid));
        invoke(&mut c, 0x03, &[], 500).unwrap(); // Stop(フィールド無し)
        assert_eq!(c.remaining_time, 0);
        // Stop 後は tick で進まない。
        assert_eq!(c.on_tick(1_000), None);
        assert_eq!(c.current_level(), Some(mid));

        // moveMode 不正 → ConstraintError。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(9)), (1, FieldVal::Null)]);
        assert_eq!(
            invoke(&mut c, 0x01, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
    }

    #[test]
    fn write_validation() {
        let mut c = LevelControlCluster::new();
        let mut wbuf = [0u8; 16];

        // Options 範囲外(4)→ ConstraintError。
        let n = encode_u8_value(&mut wbuf, 4);
        assert_eq!(
            c.write_attribute(AttributeId(0x000F), AttrWrite::new(&wbuf[..n]), &acc(0)),
            Err(ImStatus::ConstraintError)
        );
        // Options 3 は OK。
        let n = encode_u8_value(&mut wbuf, 3);
        c.write_attribute(AttributeId(0x000F), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();

        // OnLevel 範囲外(0)→ ConstraintError。
        let n = encode_u8_value(&mut wbuf, 0);
        assert_eq!(
            c.write_attribute(AttributeId(0x0011), AttrWrite::new(&wbuf[..n]), &acc(0)),
            Err(ImStatus::ConstraintError)
        );
        // OnLevel = null は OK。
        let n = encode_null_value(&mut wbuf);
        c.write_attribute(AttributeId(0x0011), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.on_level, None);
        // OnLevel = 254 は OK。
        let n = encode_u8_value(&mut wbuf, 254);
        c.write_attribute(AttributeId(0x0011), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.on_level, Some(254));
    }

    #[test]
    fn meta_feature_and_commands() {
        let c = LevelControlCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0008);
        assert_eq!(meta.revision, 6);
        assert_eq!(meta.feature_map, 0x03);
        // 固有属性 8 個(0/1/2/3/0F/10/11/4000)。
        assert_eq!(meta.attributes.len(), 8);
        // AcceptedCommandList 0x00-0x07。
        assert_eq!(meta.accepted_commands.len(), 8);
        for (i, cm) in meta.accepted_commands.iter().enumerate() {
            assert_eq!(cm.id.0, i as u32);
        }
        // 全属性が read 可能。
        let mut buf = [0u8; 32];
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
}
