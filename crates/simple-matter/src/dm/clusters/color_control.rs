//! Color Control クラスタ(0x0300、`docs/design/basic-clusters.md` §3)。
//!
//! Extended Color Light の色制御を担う。`CurrentHue`/`CurrentSaturation`(u8)と
//! `ColorTemperatureMireds`(u16)を TransitionTime に沿って線形補間する遷移エンジンを
//! [`ServerCluster::tick`](crate::dm::ServerCluster::tick) で駆動する
//! (Level Control の遷移パターン流用。設計 §3)。
//!
//! FeatureMap=0x11(HueSaturation bit0 | ColorTemperature bit4)、revision 6。
//! XY / EnhancedHue / ColorLoop はスコープ外(設計 §0-5)。
//!
//! # 色空間
//!
//! - Hue は 0x00-0xFE の円環(0xFF は不使用)。MoveToHue の direction で
//!   最短(0)/最長(1)/up(2)/down(3)の経路を選ぶ。
//! - Saturation は 0-254 の線形。
//! - ColorTemperatureMireds は物理 Min(153)/Max(500)へクランプ。
//! - HS 系コマンド成功で ColorMode/EnhancedColorMode=0、CT 系で =2 に遷移する。
//!
//! # OnOff 連動(設計 §3)
//!
//! Level Control と同じ契約。Options bit0(ExecuteIfOff)ゲートはアプリが
//! [`notify_on_off`](ColorControlCluster::notify_on_off) で現在の OnOff 状態を渡し、
//! [`coupled_on`](ColorControlCluster::coupled_on) で把握する。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{AccessContext, CommandId};
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// Hue 空間の要素数(0x00-0xFE の 255 値、0xFF 不使用。設計 §3)。
const HUE_SPACE: i32 = 255;
/// ColorTempPhysicalMinMireds(0x400B、固定値)。
const CT_PHYS_MIN: u16 = 153;
/// ColorTempPhysicalMaxMireds(0x400C、固定値)。
const CT_PHYS_MAX: u16 = 500;
/// CoupleColorTempToLevelMinMireds(0x400D、固定値)。
const COUPLE_CT_MIN: u16 = 153;
/// ColorCapabilities(0x400A、map16 = HS bit0 | CT bit4 = 0x0011)。
const COLOR_CAPABILITIES: u16 = 0x0011;
/// ColorMode / EnhancedColorMode = CurrentHueAndCurrentSaturation。
const COLOR_MODE_HS: u8 = 0;
/// ColorMode / EnhancedColorMode = ColorTemperatureMireds。
const COLOR_MODE_CT: u8 = 2;
/// 遷移中に返す tick 刻み幅(ms)。level_control.rs と同値(設計 §3)。
const TICK_STEP_MS: u64 = 50;
/// Options bit0 = ExecuteIfOff(Off 中でも実行する)。
const OPT_EXECUTE_IF_OFF: u8 = 1 << 0;

/// アプリ通知用の色状態スナップショット(任意のリスナへ渡す)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorState {
    /// CurrentHue(0-254)。
    pub current_hue: u8,
    /// CurrentSaturation(0-254)。
    pub current_saturation: u8,
    /// ColorTemperatureMireds。
    pub color_temperature_mireds: u16,
    /// ColorMode(0=HS / 2=CT)。
    pub color_mode: u8,
}

/// 進行中の線形遷移(設計 §3)。hue/sat/ct のうち非 `None` の成分を同時に補間する。
#[derive(Debug, Clone, Copy)]
struct Transition {
    /// 開始時刻(ms)。
    start_ms: u64,
    /// 完了時刻(ms)。
    end_ms: u64,
    /// Hue 遷移: (開始値, 符号付き delta)。円環経路を delta の符号/絶対値で表す。
    hue: Option<(u8, i32)>,
    /// Saturation 遷移: (開始値, 目標値)。
    sat: Option<(u8, u8)>,
    /// ColorTemperature 遷移: (開始値, 目標値)。
    ct: Option<(u16, u16)>,
}

/// Color Control クラスタ(0x0300)。
pub struct ColorControlCluster {
    /// CurrentHue(0x0000、u8)。
    current_hue: u8,
    /// CurrentSaturation(0x0001、u8)。
    current_saturation: u8,
    /// RemainingTime(0x0002、0.1s 単位)。
    remaining_time: u16,
    /// ColorTemperatureMireds(0x0007、u16)。
    color_temperature_mireds: u16,
    /// ColorMode(0x0008、enum8 {0=HS, 2=CT})。
    color_mode: u8,
    /// EnhancedColorMode(0x4001、enum8。ColorMode と同値で保持)。
    enhanced_color_mode: u8,
    /// Options(0x000F、map8)。
    options: u8,
    /// StartUpColorTemperatureMireds(0x4010、nullable u16。保持のみ)。
    start_up_color_temperature_mireds: Option<u16>,
    /// 進行中の遷移(無ければ `None`)。
    transition: Option<Transition>,
    /// 現在把握している OnOff 状態(ExecuteIfOff ゲート用。設計 §3)。
    coupled_on: bool,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// 状態変化通知コールバック(任意。example の println 用)。
    on_change: Option<fn(ColorState)>,
}

/// ms を 0.1s 単位へ切り上げる(RemainingTime。u16 飽和)。
fn ms_to_ds_ceil(ms: u64) -> u16 {
    (ms.saturating_add(99) / 100).min(u16::MAX as u64) as u16
}

/// Hue 値を 0x00-0xFE の円環へ正規化する(0xFF は不使用。設計 §3)。
fn norm_hue(v: i32) -> u8 {
    v.rem_euclid(HUE_SPACE) as u8
}

/// direction に応じた円環 hue の符号付き delta を求める(設計 §3)。
///
/// - 0=最短 / 1=最長 / 2=up(増加方向) / 3=down(減少方向)。
/// - up 距離 = (target - start) mod 255、down 距離 = 255 - up。
fn hue_delta(start: u8, target: u8, direction: u8) -> i32 {
    let up = (target as i32 - start as i32).rem_euclid(HUE_SPACE); // 0..=254(前進距離)
    match direction {
        // 最短: 前進/後退の短い方(タイは前進)。
        0 => {
            if up <= HUE_SPACE - up {
                up
            } else {
                up - HUE_SPACE
            }
        }
        // 最長: 短い方の逆。
        1 => {
            if up <= HUE_SPACE - up {
                up - HUE_SPACE
            } else {
                up
            }
        }
        // up(増加)。
        2 => up,
        // down(減少)。start==target は移動なし。
        _ => {
            if up == 0 {
                0
            } else {
                up - HUE_SPACE
            }
        }
    }
}

impl ColorControlCluster {
    /// 初期状態(Hue=0 / Sat=0 / CT=250 mireds / ColorMode=HS)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            current_hue: 0,
            current_saturation: 0,
            remaining_time: 0,
            color_temperature_mireds: 250,
            color_mode: COLOR_MODE_HS,
            enhanced_color_mode: COLOR_MODE_HS,
            options: 0,
            start_up_color_temperature_mireds: None,
            transition: None,
            coupled_on: false,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// 状態変化通知コールバックを登録する(level_control.rs と同型)。
    pub fn with_listener(mut self, cb: fn(ColorState)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の CurrentHue を返す(取得 API)。
    pub const fn current_hue(&self) -> u8 {
        self.current_hue
    }

    /// 現在の CurrentSaturation を返す(取得 API)。
    pub const fn current_saturation(&self) -> u8 {
        self.current_saturation
    }

    /// 現在の ColorTemperatureMireds を返す(取得 API)。
    pub const fn color_temperature(&self) -> u16 {
        self.color_temperature_mireds
    }

    /// 現在の ColorMode を返す(取得 API)。
    pub const fn color_mode(&self) -> u8 {
        self.color_mode
    }

    /// 現在把握している OnOff 状態を返す(設計 §3)。
    pub const fn coupled_on(&self) -> bool {
        self.coupled_on
    }

    /// OnOff → Color の変化通知(外部要因の On/Off。設計 §3)。
    ///
    /// `false`(外部の Off): 進行中の遷移を中断する。
    pub fn notify_on_off(&mut self, on: bool) {
        self.coupled_on = on;
        if !on && self.transition.is_some() {
            self.transition = None;
            self.remaining_time = 0;
            self.dirty.mark();
        }
    }

    /// 現在の色状態スナップショットを返す。
    const fn state(&self) -> ColorState {
        ColorState {
            current_hue: self.current_hue,
            current_saturation: self.current_saturation,
            color_temperature_mireds: self.color_temperature_mireds,
            color_mode: self.color_mode,
        }
    }

    /// 変化通知コールバックを(登録されていれば)呼ぶ。
    fn notify(&self) {
        if let Some(cb) = self.on_change {
            cb(self.state());
        }
    }

    fn set_hue(&mut self, hue: u8) {
        if self.current_hue != hue {
            self.current_hue = hue;
            self.dirty.mark();
            self.notify();
        }
    }

    fn set_saturation(&mut self, sat: u8) {
        if self.current_saturation != sat {
            self.current_saturation = sat;
            self.dirty.mark();
            self.notify();
        }
    }

    fn set_color_temperature(&mut self, ct: u16) {
        if self.color_temperature_mireds != ct {
            self.color_temperature_mireds = ct;
            self.dirty.mark();
            self.notify();
        }
    }

    /// ColorMode/EnhancedColorMode を設定する(変化時のみ dirty)。
    fn set_color_mode(&mut self, mode: u8) {
        if self.color_mode != mode || self.enhanced_color_mode != mode {
            self.color_mode = mode;
            self.enhanced_color_mode = mode;
            self.dirty.mark();
        }
    }

    /// optionsMask/optionsOverride を適用した実効 Options(§1.6.6.1)。
    const fn effective_options(&self, mask: u8, over: u8) -> u8 {
        (self.options & !mask) | (over & mask)
    }

    /// コマンドを実行してよいか(ExecuteIfOff 判定、設計 §3)。
    ///
    /// OnOff が On(`coupled_on`)なら常に実行。Off 中は実効 Options の ExecuteIfOff が
    /// 立っているときだけ実行する。
    const fn should_execute(&self, mask: u8, over: u8) -> bool {
        self.coupled_on || (self.effective_options(mask, over) & OPT_EXECUTE_IF_OFF != 0)
    }

    /// 遷移を開始する(`duration_ms == 0` なら即時完了。設計 §3)。
    fn begin(
        &mut self,
        hue: Option<(u8, i32)>,
        sat: Option<(u8, u8)>,
        ct: Option<(u16, u16)>,
        duration_ms: u64,
        now: u64,
    ) {
        let tr = Transition {
            start_ms: now,
            end_ms: now.saturating_add(duration_ms),
            hue,
            sat,
            ct,
        };
        if duration_ms == 0 {
            self.finish_transition(&tr);
            return;
        }
        self.transition = Some(tr);
        // 遷移開始で RemainingTime を報告(dirty はここで立てる。設計 §3)。
        self.remaining_time = ms_to_ds_ceil(duration_ms);
        self.dirty.mark();
    }

    /// 遷移を完了する(各成分の目標確定 + RemainingTime=0、設計 §3)。
    fn finish_transition(&mut self, tr: &Transition) {
        if let Some((start, delta)) = tr.hue {
            self.set_hue(norm_hue(start as i32 + delta));
        }
        if let Some((_, target)) = tr.sat {
            self.set_saturation(target);
        }
        if let Some((_, target)) = tr.ct {
            self.set_color_temperature(target);
        }
        self.remaining_time = 0;
        self.transition = None;
        // 完了時は(値が変わっていなくても)報告する。
        self.dirty.mark();
    }

    /// 遷移エンジンの 1 ステップ(設計 §3、level_control.rs と同型)。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        let tr = self.transition?;
        if now_ms >= tr.end_ms {
            self.finish_transition(&tr);
            return None;
        }
        // 線形補間(整数演算、桁あふれ回避に i64)。
        let span = (tr.end_ms - tr.start_ms) as i64;
        let elapsed = (now_ms - tr.start_ms) as i64;
        if let Some((start, delta)) = tr.hue {
            let v = start as i64 + delta as i64 * elapsed / span;
            self.set_hue(norm_hue(v as i32));
        }
        if let Some((s, t)) = tr.sat {
            let v = s as i64 + (t as i64 - s as i64) * elapsed / span;
            self.set_saturation(v as u8);
        }
        if let Some((s, t)) = tr.ct {
            let v = s as i64 + (t as i64 - s as i64) * elapsed / span;
            self.set_color_temperature(v as u16);
        }
        // RemainingTime は毎 tick 更新(dirty は立てない。設計 §3)。
        self.remaining_time = ms_to_ds_ceil(tr.end_ms - now_ms);
        Some(now_ms.saturating_add(TICK_STEP_MS))
    }

    // --- コマンド ---

    /// MoveToHue(0x00)。hue>254 / direction>3 は ConstraintError(設計 §3)。
    fn cmd_move_to_hue(&mut self, fields: &mut TlvReader<'_>, now: u64) -> Result<(), ImStatus> {
        let (mut hue, mut dir, mut ttime): (Option<u16>, Option<u16>, Option<u16>) =
            (None, None, None);
        let (mut mask, mut over) = (0u8, 0u8);
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => hue = v.as_unsigned().ok().map(|x| x as u16),
                1 => dir = v.as_unsigned().ok().map(|x| x as u16),
                2 => ttime = v.as_unsigned().ok().map(|x| x as u16),
                3 => mask = v.as_unsigned().unwrap_or(0) as u8,
                4 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let hue = hue.ok_or(ImStatus::InvalidCommand)?;
        let dir = dir.ok_or(ImStatus::InvalidCommand)?;
        if hue > 254 || dir > 3 {
            return Err(ImStatus::ConstraintError);
        }
        if !self.should_execute(mask, over) {
            return Ok(());
        }
        self.set_color_mode(COLOR_MODE_HS);
        let start = self.current_hue;
        let delta = hue_delta(start, hue as u8, dir as u8);
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin(Some((start, delta)), None, None, duration_ms, now);
        Ok(())
    }

    /// MoveToSaturation(0x03)。saturation>254 は ConstraintError(設計 §3)。
    fn cmd_move_to_saturation(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
    ) -> Result<(), ImStatus> {
        let (mut sat, mut ttime): (Option<u16>, Option<u16>) = (None, None);
        let (mut mask, mut over) = (0u8, 0u8);
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => sat = v.as_unsigned().ok().map(|x| x as u16),
                1 => ttime = v.as_unsigned().ok().map(|x| x as u16),
                2 => mask = v.as_unsigned().unwrap_or(0) as u8,
                3 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let sat = sat.ok_or(ImStatus::InvalidCommand)?;
        if sat > 254 {
            return Err(ImStatus::ConstraintError);
        }
        if !self.should_execute(mask, over) {
            return Ok(());
        }
        self.set_color_mode(COLOR_MODE_HS);
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin(
            None,
            Some((self.current_saturation, sat as u8)),
            None,
            duration_ms,
            now,
        );
        Ok(())
    }

    /// MoveToHueAndSaturation(0x06)。hue>254 / saturation>254 は ConstraintError。
    /// hue は最短経路(direction 相当 0)で補間する(設計 §3)。
    fn cmd_move_to_hue_and_saturation(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
    ) -> Result<(), ImStatus> {
        let (mut hue, mut sat, mut ttime): (Option<u16>, Option<u16>, Option<u16>) =
            (None, None, None);
        let (mut mask, mut over) = (0u8, 0u8);
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => hue = v.as_unsigned().ok().map(|x| x as u16),
                1 => sat = v.as_unsigned().ok().map(|x| x as u16),
                2 => ttime = v.as_unsigned().ok().map(|x| x as u16),
                3 => mask = v.as_unsigned().unwrap_or(0) as u8,
                4 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let hue = hue.ok_or(ImStatus::InvalidCommand)?;
        let sat = sat.ok_or(ImStatus::InvalidCommand)?;
        if hue > 254 || sat > 254 {
            return Err(ImStatus::ConstraintError);
        }
        if !self.should_execute(mask, over) {
            return Ok(());
        }
        self.set_color_mode(COLOR_MODE_HS);
        let start_hue = self.current_hue;
        let delta = hue_delta(start_hue, hue as u8, 0);
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin(
            Some((start_hue, delta)),
            Some((self.current_saturation, sat as u8)),
            None,
            duration_ms,
            now,
        );
        Ok(())
    }

    /// MoveToColorTemperature(0x0A)。目標を物理 Min/Max へクランプする(設計 §3)。
    fn cmd_move_to_color_temperature(
        &mut self,
        fields: &mut TlvReader<'_>,
        now: u64,
    ) -> Result<(), ImStatus> {
        let (mut ct, mut ttime): (Option<u16>, Option<u16>) = (None, None);
        let (mut mask, mut over) = (0u8, 0u8);
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => ct = v.as_unsigned().ok().map(|x| x as u16),
                1 => ttime = v.as_unsigned().ok().map(|x| x as u16),
                2 => mask = v.as_unsigned().unwrap_or(0) as u8,
                3 => over = v.as_unsigned().unwrap_or(0) as u8,
                _ => {}
            }
        }
        let ct = ct.ok_or(ImStatus::InvalidCommand)?;
        if !self.should_execute(mask, over) {
            return Ok(());
        }
        self.set_color_mode(COLOR_MODE_CT);
        let target = ct.clamp(CT_PHYS_MIN, CT_PHYS_MAX);
        let duration_ms = ttime.map_or(0, |t| t as u64 * 100);
        self.begin(
            None,
            None,
            Some((self.color_temperature_mireds, target)),
            duration_ms,
            now,
        );
        Ok(())
    }

    /// コマンドディスパッチ(設計 §3。Move/Step 系は非実装)。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let now = acc.now_ms;
        match cmd.0 {
            0x00 => self.cmd_move_to_hue(fields, now),
            0x03 => self.cmd_move_to_saturation(fields, now),
            0x06 => self.cmd_move_to_hue_and_saturation(fields, now),
            0x0A => self.cmd_move_to_color_temperature(fields, now),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    // --- 属性 write ---

    /// Options(0x000F、map8)。定義ビットは ExecuteIfOff(bit0)のみ → 0..=1 以外は
    /// ConstraintError(設計 §3)。
    fn write_options(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > 1 {
            return Err(ImStatus::ConstraintError);
        }
        self.options = v as u8;
        self.dirty.mark();
        Ok(())
    }

    /// StartUpColorTemperatureMireds(0x4010、nullable)。153-500 または null 以外は
    /// ConstraintError(設計 §3)。
    fn write_start_up_ct(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        if data.is_null() {
            self.start_up_color_temperature_mireds = None;
        } else {
            let v = data.as_unsigned()?;
            if !(CT_PHYS_MIN as u64..=CT_PHYS_MAX as u64).contains(&v) {
                return Err(ImStatus::ConstraintError);
            }
            self.start_up_color_temperature_mireds = Some(v as u16);
        }
        self.dirty.mark();
        Ok(())
    }

    fn read_start_up_ct(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_nullable_u16(self.start_up_color_temperature_mireds)
    }
}

impl Default for ColorControlCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    ColorControlCluster {
        id: 0x0300,
        revision: 6,
        // FeatureMap bit0 = HueSaturation / bit4 = ColorTemperature(設計 §3)。
        feature_map: 0x11,
        dirty: dirty,
        tick: on_tick,
        invoke: (|c: &mut ColorControlCluster, cmd, fields, _resp, acc| {
            c.invoke_cmd(cmd, fields, acc)
        }),
        attributes: [
            0x0000 CurrentHue {
                access: View,
                quality: [NONVOLATILE, SCENE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.current_hue)),
                write: _
            },
            0x0001 CurrentSaturation {
                access: View,
                quality: [NONVOLATILE, SCENE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.current_saturation)),
                write: _
            },
            0x0002 RemainingTime {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.remaining_time)),
                write: _
            },
            0x0007 ColorTemperatureMireds {
                access: View,
                quality: [NONVOLATILE, SCENE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.color_temperature_mireds)),
                write: _
            },
            0x0008 ColorMode {
                access: View,
                quality: [NONVOLATILE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.color_mode)),
                write: _
            },
            0x000F Options {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.options)),
                write: (Operate, |c: &mut ColorControlCluster, data, _acc| c.write_options(data))
            },
            0x0010 NumberOfPrimaries {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
            0x4001 EnhancedColorMode {
                access: View,
                quality: [NONVOLATILE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.enhanced_color_mode)),
                write: _
            },
            0x400A ColorCapabilities {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(COLOR_CAPABILITIES)),
                write: _
            },
            0x400B ColorTempPhysicalMinMireds {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(CT_PHYS_MIN)),
                write: _
            },
            0x400C ColorTempPhysicalMaxMireds {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(CT_PHYS_MAX)),
                write: _
            },
            0x400D CoupleColorTempToLevelMinMireds {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(COUPLE_CT_MIN)),
                write: _
            },
            0x4010 StartUpColorTemperatureMireds {
                access: View,
                quality: [NONVOLATILE],
                subscribe: true,
                read: (|c: &ColorControlCluster, e: &mut AttrEncoder<'_, '_>| c.read_start_up_ct(e)),
                write: (Operate, |c: &mut ColorControlCluster, data, _acc| c.write_start_up_ct(data))
            },
        ],
        accepted: [
            0x00 MoveToHue,
            0x03 MoveToSaturation,
            0x06 MoveToHueAndSaturation,
            0x0A MoveToColorTemperature,
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

    enum FieldVal {
        U8(u8),
        U16(u16),
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
            }
        }
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(
        c: &mut ColorControlCluster,
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

    fn encode_u16_value(buf: &mut [u8], v: u16) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_u16(&TlvTag::Anonymous, v).unwrap();
        w.len()
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
    fn meta_feature_and_commands() {
        let c = ColorControlCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0300);
        assert_eq!(meta.revision, 6);
        assert_eq!(meta.feature_map, 0x11);
        // 固有属性 13 個。
        assert_eq!(meta.attributes.len(), 13);
        // AcceptedCommandList = MoveToHue/Saturation/HueAndSaturation/ColorTemperature。
        assert_eq!(meta.accepted_commands.len(), 4);
        let expected = [0x00u32, 0x03, 0x06, 0x0A];
        for (cm, want) in meta.accepted_commands.iter().zip(expected.iter()) {
            assert_eq!(cm.id.0, *want);
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

    /// MoveToHue の最短経路(前進/後退/タイ)を direction=0 で確認する。
    #[test]
    fn move_to_hue_shortest_path() {
        // start=10, target=200: 前進 190 / 後退 65 → 後退(-65)を選ぶ。
        assert_eq!(hue_delta(10, 200, 0), -65);
        // start=10, target=60: 前進 50 / 後退 205 → 前進(+50)。
        assert_eq!(hue_delta(10, 60, 0), 50);
        // 補間の実挙動: 10 → 200 を 10s、5s 時点で 10-32=... 経由で円環正規化。
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        c.set_hue(10);
        let _ = c.take_dirty();
        let mut buf = [0u8; 64];
        // hue=200, direction=0(最短), transitionTime=100(=10s)。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(200)),
                (1, FieldVal::U8(0)),
                (2, FieldVal::U16(100)),
            ],
        );
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.color_mode(), COLOR_MODE_HS);
        assert_eq!(c.remaining_time, 100);
        // 5s 時点: 10 + (-65)*0.5 = -22.5 → norm(-22) = 233。
        assert!(c.on_tick(5_000).is_some());
        assert_eq!(c.current_hue(), norm_hue(10 - 32));
        // 完了: 200。
        assert_eq!(c.on_tick(10_000), None);
        assert_eq!(c.current_hue(), 200);
        assert_eq!(c.remaining_time, 0);
    }

    /// direction 別(up/down/最長)の delta を確認する。
    #[test]
    fn move_to_hue_direction_variants() {
        // up(2): 常に前進。10→200 は +190。
        assert_eq!(hue_delta(10, 200, 2), 190);
        // down(3): 常に後退。10→200 は -65。
        assert_eq!(hue_delta(10, 200, 3), -65);
        // 最長(1): 最短の逆。10→60 は前進 50 が短い → 最長は後退(50-255=-205)。
        assert_eq!(hue_delta(10, 60, 1), -205);
        // down で start==target は移動なし。
        assert_eq!(hue_delta(100, 100, 3), 0);
    }

    /// MoveToHueAndSaturation は 1 遷移で hue/sat を同時補間する。
    #[test]
    fn move_to_hue_and_saturation_simultaneous() {
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        c.set_hue(0);
        c.set_saturation(0);
        let _ = c.take_dirty();
        let mut buf = [0u8; 64];
        // hue=100, sat=200, transitionTime=100(=10s)。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(100)),
                (1, FieldVal::U8(200)),
                (2, FieldVal::U16(100)),
            ],
        );
        invoke(&mut c, 0x06, &buf[..n], 0).unwrap();
        // 5s 時点で両方が中間へ。
        assert!(c.on_tick(5_000).is_some());
        assert_eq!(c.current_hue(), 50);
        assert_eq!(c.current_saturation(), 100);
        // 完了で目標。
        assert_eq!(c.on_tick(10_000), None);
        assert_eq!(c.current_hue(), 100);
        assert_eq!(c.current_saturation(), 200);
    }

    /// MoveToColorTemperature は物理 Min/Max へクランプする。
    #[test]
    fn move_to_color_temperature_clamps() {
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        let mut buf = [0u8; 64];
        // 目標 1000 → Max(500) へクランプ、即時。
        let n = build_fields(&mut buf, &[(0, FieldVal::U16(1000)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x0A, &buf[..n], 0).unwrap();
        assert_eq!(c.color_temperature(), CT_PHYS_MAX);
        assert_eq!(c.color_mode(), COLOR_MODE_CT);
        // 目標 10 → Min(153)。
        let n = build_fields(&mut buf, &[(0, FieldVal::U16(10)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x0A, &buf[..n], 0).unwrap();
        assert_eq!(c.color_temperature(), CT_PHYS_MIN);
    }

    /// HS/CT コマンドで ColorMode/EnhancedColorMode が切り替わる。
    #[test]
    fn color_mode_switches() {
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        let mut buf = [0u8; 64];
        // CT へ。
        let n = build_fields(&mut buf, &[(0, FieldVal::U16(300)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x0A, &buf[..n], 0).unwrap();
        assert_eq!(c.color_mode(), COLOR_MODE_CT);
        assert_eq!(c.enhanced_color_mode, COLOR_MODE_CT);
        // MoveToSaturation で HS へ戻る。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(128)), (1, FieldVal::U16(0))]);
        invoke(&mut c, 0x03, &buf[..n], 0).unwrap();
        assert_eq!(c.color_mode(), COLOR_MODE_HS);
        assert_eq!(c.enhanced_color_mode, COLOR_MODE_HS);
        assert_eq!(c.current_saturation(), 128);
    }

    /// Options bit0(ExecuteIfOff)ゲート: Off 中は無効果、override で実行。
    #[test]
    fn execute_if_off_gating() {
        let mut c = ColorControlCluster::new();
        // Off(coupled_on=false)。MoveToHue は無効果 + Success。
        c.set_hue(0);
        let _ = c.take_dirty();
        let mut buf = [0u8; 64];
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(100)),
                (1, FieldVal::U8(0)),
                (2, FieldVal::U16(0)),
            ],
        );
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.current_hue(), 0);
        assert!(!c.take_dirty());
        // optionsMask/optionsOverride で ExecuteIfOff を一時的に立てる。
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(100)),
                (1, FieldVal::U8(0)),
                (2, FieldVal::U16(0)),
                (3, FieldVal::U8(0x01)),
                (4, FieldVal::U8(0x01)),
            ],
        );
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.current_hue(), 100);
    }

    /// notify_on_off(false) は進行中の遷移を中断する。
    #[test]
    fn off_cancels_transition() {
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        let mut buf = [0u8; 64];
        let n = build_fields(
            &mut buf,
            &[
                (0, FieldVal::U8(200)),
                (1, FieldVal::U8(2)),
                (2, FieldVal::U16(100)),
            ],
        );
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert!(c.transition.is_some());
        c.notify_on_off(false);
        assert!(c.transition.is_none());
        assert_eq!(c.remaining_time, 0);
    }

    /// ConstraintError: hue>254 / direction>3 / saturation>254。
    #[test]
    fn constraint_errors() {
        let mut c = ColorControlCluster::new();
        c.notify_on_off(true);
        let mut buf = [0u8; 64];
        // hue=255 → ConstraintError。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(255)), (1, FieldVal::U8(0))]);
        assert_eq!(
            invoke(&mut c, 0x00, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
        // direction=4 → ConstraintError。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(10)), (1, FieldVal::U8(4))]);
        assert_eq!(
            invoke(&mut c, 0x00, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
        // saturation=255 → ConstraintError。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(255)), (1, FieldVal::U16(0))]);
        assert_eq!(
            invoke(&mut c, 0x03, &buf[..n], 0),
            Err(ImStatus::ConstraintError)
        );
    }

    /// StartUpColorTemperatureMireds write: 153-500 または null のみ受理。
    #[test]
    fn write_start_up_ct_validation() {
        let mut c = ColorControlCluster::new();
        let mut wbuf = [0u8; 16];
        // 範囲外(100)→ ConstraintError。
        let n = encode_u16_value(&mut wbuf, 100);
        assert_eq!(
            c.write_attribute(AttributeId(0x4010), AttrWrite::new(&wbuf[..n]), &acc(0)),
            Err(ImStatus::ConstraintError)
        );
        // 範囲外(501)→ ConstraintError。
        let n = encode_u16_value(&mut wbuf, 501);
        assert_eq!(
            c.write_attribute(AttributeId(0x4010), AttrWrite::new(&wbuf[..n]), &acc(0)),
            Err(ImStatus::ConstraintError)
        );
        // 300 は OK。
        let n = encode_u16_value(&mut wbuf, 300);
        c.write_attribute(AttributeId(0x4010), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.start_up_color_temperature_mireds, Some(300));
        // null は OK。
        let n = encode_null_value(&mut wbuf);
        c.write_attribute(AttributeId(0x4010), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.start_up_color_temperature_mireds, None);
    }

    /// Options write: 0..=1 のみ受理(bit0 ExecuteIfOff)。
    #[test]
    fn write_options_validation() {
        let mut c = ColorControlCluster::new();
        let mut wbuf = [0u8; 16];
        // 2 → ConstraintError。
        let n = encode_u8_value(&mut wbuf, 2);
        assert_eq!(
            c.write_attribute(AttributeId(0x000F), AttrWrite::new(&wbuf[..n]), &acc(0)),
            Err(ImStatus::ConstraintError)
        );
        // 1 は OK。
        let n = encode_u8_value(&mut wbuf, 1);
        c.write_attribute(AttributeId(0x000F), AttrWrite::new(&wbuf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.options, 1);
    }
}
