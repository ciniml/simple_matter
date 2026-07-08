//! Thermostat クラスタ(0x0201、`docs/design/interaction-model.md` §15.4)。
//!
//! 冷暖房のセットポイント制御を担う複雑クラスタの型実証。signed(i16)属性・nullable 属性・
//! enum 検証・相互制約(deadband)・複合フィールドコマンド(SetpointRaiseLower)を一通り含む。
//!
//! FeatureMap=0x03(HEAT bit0 | COOL bit1)、revision 6。AUTO feature は持たないため
//! SystemMode の Auto(1)は拒否する(設計 §15.4)。
//!
//! `LocalTemperature`(0x0000)はクラスタ自身は値の器に徹し、擬似センサの駆動は example 側
//! (`on_tick`)が [`set_local_temperature`](ThermostatCluster::set_local_temperature) で注入する
//! (設計 §15.4)。tick は不要なので `cluster!` の `tick:` アームは持たない。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::CommandId;
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// MinHeatSetpointLimit(0x0015、FIXED。仕様既定 700 = 7.00℃)。
const MIN_HEAT: i16 = 700;
/// MaxHeatSetpointLimit(0x0016、FIXED。仕様既定 3000 = 30.00℃)。
const MAX_HEAT: i16 = 3000;
/// MinCoolSetpointLimit(0x0017、FIXED。仕様既定 1600 = 16.00℃)。
const MIN_COOL: i16 = 1600;
/// MaxCoolSetpointLimit(0x0018、FIXED。仕様既定 3200 = 32.00℃)。
const MAX_COOL: i16 = 3200;
/// deadband(0.01℃ 単位、2.5℃)。AUTO feature は持たないが型実証として
/// `heating <= cooling - DEADBAND` を強制する(仕様の AUTO 時制約の準用。設計 §15.4 の割り切り)。
const DEADBAND: i16 = 250;

/// Thermostat クラスタ(0x0201)。
pub struct ThermostatCluster {
    /// LocalTemperature(0x0000、nullable i16。外部注入 = 擬似センサ)。
    local_temperature: Option<i16>,
    /// OccupiedCoolingSetpoint(0x0011、i16。既定 2600)。
    occupied_cooling_setpoint: i16,
    /// OccupiedHeatingSetpoint(0x0012、i16。既定 2000)。
    occupied_heating_setpoint: i16,
    /// ControlSequenceOfOperation(0x001B、enum8。既定 4 = CoolingAndHeating)。
    control_sequence: u8,
    /// SystemMode(0x001C、enum8。既定 0 = Off)。
    system_mode: u8,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
}

impl ThermostatCluster {
    /// 初期状態のクラスタを作る(設計 §15.4 の既定値)。
    pub const fn new() -> Self {
        Self {
            local_temperature: None,
            occupied_cooling_setpoint: 2600,
            occupied_heating_setpoint: 2000,
            control_sequence: 4,
            system_mode: 0,
            dirty: Dirty::new(),
        }
    }

    // --- 外部 API(example の擬似センサ / 取得用)---

    /// LocalTemperature(0x0000)を外部注入する。値が変わったときのみ dirty(設計 §15.4)。
    pub fn set_local_temperature(&mut self, v: Option<i16>) {
        if self.local_temperature != v {
            self.local_temperature = v;
            self.dirty.mark();
        }
    }

    /// 現在の LocalTemperature(取得 API)。
    pub const fn local_temperature(&self) -> Option<i16> {
        self.local_temperature
    }

    /// 現在の OccupiedHeatingSetpoint(取得 API)。
    pub const fn occupied_heating_setpoint(&self) -> i16 {
        self.occupied_heating_setpoint
    }

    /// 現在の OccupiedCoolingSetpoint(取得 API)。
    pub const fn occupied_cooling_setpoint(&self) -> i16 {
        self.occupied_cooling_setpoint
    }

    /// 現在の SystemMode(取得 API)。
    pub const fn system_mode(&self) -> u8 {
        self.system_mode
    }

    // --- setpoint 更新(変化時のみ dirty)---

    fn set_heating(&mut self, v: i16) {
        if self.occupied_heating_setpoint != v {
            self.occupied_heating_setpoint = v;
            self.dirty.mark();
        }
    }

    fn set_cooling(&mut self, v: i16) {
        if self.occupied_cooling_setpoint != v {
            self.occupied_cooling_setpoint = v;
            self.dirty.mark();
        }
    }

    // --- 属性 write ---

    /// OccupiedCoolingSetpoint(0x0011)。Min/Max 範囲外・deadband 違反は ConstraintError
    /// (設計 §15.4)。
    fn write_cooling_setpoint(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let raw = data.as_i64()?;
        if !(MIN_COOL as i64..=MAX_COOL as i64).contains(&raw) {
            return Err(ImStatus::ConstraintError);
        }
        let v = raw as i16;
        // deadband: heating <= cooling - DEADBAND。cooling を下げすぎると違反する。
        if self.occupied_heating_setpoint > v - DEADBAND {
            return Err(ImStatus::ConstraintError);
        }
        self.set_cooling(v);
        Ok(())
    }

    /// OccupiedHeatingSetpoint(0x0012)。Min/Max 範囲外・deadband 違反は ConstraintError
    /// (設計 §15.4)。
    fn write_heating_setpoint(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let raw = data.as_i64()?;
        if !(MIN_HEAT as i64..=MAX_HEAT as i64).contains(&raw) {
            return Err(ImStatus::ConstraintError);
        }
        let v = raw as i16;
        // deadband: heating <= cooling - DEADBAND。heating を上げすぎると違反する。
        if v > self.occupied_cooling_setpoint - DEADBAND {
            return Err(ImStatus::ConstraintError);
        }
        self.set_heating(v);
        Ok(())
    }

    /// ControlSequenceOfOperation(0x001B)。0..=5 以外は ConstraintError(設計 §15.4)。
    fn write_control_sequence(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > 5 {
            return Err(ImStatus::ConstraintError);
        }
        self.control_sequence = v as u8;
        self.dirty.mark();
        Ok(())
    }

    /// SystemMode(0x001C)。{Off(0), Cool(3), Heat(4)} のみ許容(AUTO 無しなので Auto(1)は拒否)、
    /// かつ ControlSequenceOfOperation との整合を検証する(設計 §15.4)。違反は ConstraintError。
    fn write_system_mode(&mut self, data: AttrWrite<'_>) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        // 許容 enum 値の検証(Auto=1 は AUTO feature 未対応のため拒否)。
        if !matches!(v, 0 | 3 | 4) {
            return Err(ImStatus::ConstraintError);
        }
        let v = v as u8;
        // ControlSequenceOfOperation との整合:
        // 0..=1 = CoolingOnly 系 → Heat(4)拒否 / 2..=3 = HeatingOnly 系 → Cool(3)拒否。
        match self.control_sequence {
            0..=1 if v == 4 => return Err(ImStatus::ConstraintError),
            2..=3 if v == 3 => return Err(ImStatus::ConstraintError),
            _ => {}
        }
        self.system_mode = v;
        self.dirty.mark();
        Ok(())
    }

    // --- コマンド ---

    /// SetpointRaiseLower(0x00)を対象 setpoint に適用する(設計 §15.4)。
    ///
    /// heating を +delta(0.01℃)し、Min/Max と deadband 上限へクランプする。
    fn adjust_heating(&mut self, delta: i32) {
        // deadband 上限: heating <= cooling - DEADBAND。MAX_HEAT との小さい方が上限。
        let upper = (MAX_HEAT as i32).min(self.occupied_cooling_setpoint as i32 - DEADBAND as i32);
        let new =
            (self.occupied_heating_setpoint as i32 + delta).clamp(MIN_HEAT as i32, upper) as i16;
        self.set_heating(new);
    }

    /// cooling を +delta(0.01℃)し、Min/Max と deadband 下限へクランプする(設計 §15.4)。
    fn adjust_cooling(&mut self, delta: i32) {
        // deadband 下限: cooling >= heating + DEADBAND。MIN_COOL との大きい方が下限。
        let lower = (MIN_COOL as i32).max(self.occupied_heating_setpoint as i32 + DEADBAND as i32);
        let new =
            (self.occupied_cooling_setpoint as i32 + delta).clamp(lower, MAX_COOL as i32) as i16;
        self.set_cooling(new);
    }

    /// mode=Both: 両 setpoint に +delta(0.01℃)し、各 Min/Max へクランプ後に deadband を保つ
    /// (cooling を先に確定し、heating を cooling − DEADBAND 以下へクランプ。設計 §15.4)。
    fn adjust_both(&mut self, delta: i32) {
        let new_cool = (self.occupied_cooling_setpoint as i32 + delta)
            .clamp(MIN_COOL as i32, MAX_COOL as i32) as i16;
        let new_heat = (self.occupied_heating_setpoint as i32 + delta)
            .clamp(MIN_HEAT as i32, MAX_HEAT as i32) as i16;
        self.set_cooling(new_cool);
        // deadband を保つよう heating を cooling − DEADBAND 以下(かつ MIN_HEAT 以上)へクランプ。
        let heat = new_heat.min(new_cool - DEADBAND).max(MIN_HEAT);
        self.set_heating(heat);
    }

    /// SetpointRaiseLower(0x00): `{ 0: mode enum8, 1: amount i8 }`(複合フィールドコマンドの実証)。
    ///
    /// mode 0=Heat / 1=Cool / 2=Both(それ以外 ConstraintError)。amount は 0.1℃ 単位 → ×10 して加算し、
    /// Min/Max と deadband へクランプする(仕様どおりエラーにしない。設計 §15.4)。
    fn cmd_setpoint_raise_lower(&mut self, fields: &mut TlvReader<'_>) -> Result<(), ImStatus> {
        let mut mode: Option<u8> = None;
        let mut amount: Option<i8> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => mode = v.as_unsigned().ok().map(|x| x as u8),
                1 => amount = v.as_signed().ok().map(|x| x as i8),
                _ => {}
            }
        }
        let mode = mode.ok_or(ImStatus::InvalidCommand)?;
        let amount = amount.ok_or(ImStatus::InvalidCommand)?;
        // amount は 0.1℃ 単位 → 0.01℃ 単位へ(×10)。
        let delta = amount as i32 * 10;
        match mode {
            0 => self.adjust_heating(delta),
            1 => self.adjust_cooling(delta),
            2 => self.adjust_both(delta),
            _ => return Err(ImStatus::ConstraintError),
        }
        Ok(())
    }

    /// コマンドディスパッチ(0x00 のみ)。
    fn invoke_cmd(&mut self, cmd: CommandId, fields: &mut TlvReader<'_>) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.cmd_setpoint_raise_lower(fields),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for ThermostatCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    ThermostatCluster {
        id: 0x0201,
        revision: 6,
        // FeatureMap bit0 = HEAT / bit1 = COOL(設計 §15.4)。
        feature_map: 0x03,
        dirty: dirty,
        invoke: (|c: &mut ThermostatCluster, cmd, fields, _resp, _acc| {
            c.invoke_cmd(cmd, fields)
        }),
        attributes: [
            0x0000 LocalTemperature {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_i16(c.local_temperature)),
                write: _
            },
            0x0011 OccupiedCoolingSetpoint {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(c.occupied_cooling_setpoint)),
                write: (Operate, |c: &mut ThermostatCluster, data, _acc| c.write_cooling_setpoint(data))
            },
            0x0012 OccupiedHeatingSetpoint {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(c.occupied_heating_setpoint)),
                write: (Operate, |c: &mut ThermostatCluster, data, _acc| c.write_heating_setpoint(data))
            },
            0x0015 MinHeatSetpointLimit {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(MIN_HEAT)),
                write: _
            },
            0x0016 MaxHeatSetpointLimit {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(MAX_HEAT)),
                write: _
            },
            0x0017 MinCoolSetpointLimit {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(MIN_COOL)),
                write: _
            },
            0x0018 MaxCoolSetpointLimit {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_i16(MAX_COOL)),
                write: _
            },
            0x001B ControlSequenceOfOperation {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.control_sequence)),
                write: (Operate, |c: &mut ThermostatCluster, data, _acc| c.write_control_sequence(data))
            },
            0x001C SystemMode {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &ThermostatCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.system_mode)),
                write: (Operate, |c: &mut ThermostatCluster, data, _acc| c.write_system_mode(data))
            },
        ],
        accepted: [
            0x00 SetpointRaiseLower,
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

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    /// context タグ付きフィールド構造体を組む(u8/i8/欠落テスト用)。
    enum FieldVal {
        U8(u8),
        I8(i8),
    }

    fn build_fields(buf: &mut [u8], fields: &[(u8, FieldVal)]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        for (tag, v) in fields {
            let t = TlvTag::ContextSpecific(*tag);
            match v {
                FieldVal::U8(x) => w.write_u8(&t, *x).unwrap(),
                FieldVal::I8(x) => w.write_i8(&t, *x).unwrap(),
            }
        }
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(c: &mut ThermostatCluster, cmd: u16, fields: &[u8]) -> Result<(), ImStatus> {
        let mut scratch = [0u8; 128];
        let mut sw = TlvWriter::new(&mut scratch);
        let mut resp = CmdResponder::new(&mut sw);
        let mut fr = TlvReader::new(fields);
        c.invoke_command(CommandId(cmd as u32), &mut fr, &mut resp, &acc())
    }

    fn encode_i16_value(buf: &mut [u8], v: i16) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_i16(&TlvTag::Anonymous, v).unwrap();
        w.len()
    }

    fn encode_u8_value(buf: &mut [u8], v: u8) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_u8(&TlvTag::Anonymous, v).unwrap();
        w.len()
    }

    fn write_attr(c: &mut ThermostatCluster, id: u16, data: &[u8]) -> Result<(), ImStatus> {
        c.write_attribute(AttributeId(id as u32), AttrWrite::new(data), &acc())
    }

    #[test]
    fn setpoint_write_range_validation() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 16];

        // OccupiedCoolingSetpoint 範囲外(< MIN_COOL)→ ConstraintError。
        let n = encode_i16_value(&mut buf, 1500);
        assert_eq!(
            write_attr(&mut c, 0x0011, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // 範囲外(> MAX_COOL)。
        let n = encode_i16_value(&mut buf, 3300);
        assert_eq!(
            write_attr(&mut c, 0x0011, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // 範囲内は OK。
        let n = encode_i16_value(&mut buf, 2800);
        write_attr(&mut c, 0x0011, &buf[..n]).unwrap();
        assert_eq!(c.occupied_cooling_setpoint(), 2800);
        assert!(c.take_dirty());

        // OccupiedHeatingSetpoint 範囲外(< MIN_HEAT)。
        let n = encode_i16_value(&mut buf, 600);
        assert_eq!(
            write_attr(&mut c, 0x0012, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // 範囲外(> MAX_HEAT)。
        let n = encode_i16_value(&mut buf, 3100);
        assert_eq!(
            write_attr(&mut c, 0x0012, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
    }

    #[test]
    fn setpoint_write_deadband() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 16];
        // cooling=2600 の状態で heating=2400 は deadband 違反(2400 > 2600 − 250 = 2350)。
        let n = encode_i16_value(&mut buf, 2400);
        assert_eq!(
            write_attr(&mut c, 0x0012, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // heating=2350 は境界で OK。
        let n = encode_i16_value(&mut buf, 2350);
        write_attr(&mut c, 0x0012, &buf[..n]).unwrap();
        assert_eq!(c.occupied_heating_setpoint(), 2350);

        // 逆方向: heating=2350 の状態で cooling=2500 は deadband 違反(2350 > 2500 − 250 = 2250)。
        let n = encode_i16_value(&mut buf, 2500);
        assert_eq!(
            write_attr(&mut c, 0x0011, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // cooling=2600 は OK(境界 2350 = 2600 − 250)。
        let n = encode_i16_value(&mut buf, 2600);
        write_attr(&mut c, 0x0011, &buf[..n]).unwrap();
    }

    #[test]
    fn system_mode_enum_validation() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 16];
        // Auto(1)は AUTO feature 未対応で拒否。
        let n = encode_u8_value(&mut buf, 1);
        assert_eq!(
            write_attr(&mut c, 0x001C, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // 不正値(2)。
        let n = encode_u8_value(&mut buf, 2);
        assert_eq!(
            write_attr(&mut c, 0x001C, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // Heat(4)は既定 ControlSequence=4(CoolingAndHeating)で OK。
        let n = encode_u8_value(&mut buf, 4);
        write_attr(&mut c, 0x001C, &buf[..n]).unwrap();
        assert_eq!(c.system_mode(), 4);
        assert!(c.take_dirty());
        // Off(0)/Cool(3)も OK。
        let n = encode_u8_value(&mut buf, 3);
        write_attr(&mut c, 0x001C, &buf[..n]).unwrap();
        assert_eq!(c.system_mode(), 3);
    }

    #[test]
    fn system_mode_control_sequence_consistency() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 16];
        // ControlSequence=0(CoolingOnly)→ Heat(4)拒否 / Cool(3)許容。
        let n = encode_u8_value(&mut buf, 0);
        write_attr(&mut c, 0x001B, &buf[..n]).unwrap();
        let n = encode_u8_value(&mut buf, 4);
        assert_eq!(
            write_attr(&mut c, 0x001C, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        let n = encode_u8_value(&mut buf, 3);
        write_attr(&mut c, 0x001C, &buf[..n]).unwrap();

        // ControlSequence=2(HeatingOnly)→ Cool(3)拒否 / Heat(4)許容。
        let n = encode_u8_value(&mut buf, 2);
        write_attr(&mut c, 0x001B, &buf[..n]).unwrap();
        let n = encode_u8_value(&mut buf, 3);
        assert_eq!(
            write_attr(&mut c, 0x001C, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        let n = encode_u8_value(&mut buf, 4);
        write_attr(&mut c, 0x001C, &buf[..n]).unwrap();
    }

    #[test]
    fn control_sequence_write_validation() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 16];
        // 6 は範囲外(0..=5)→ ConstraintError。
        let n = encode_u8_value(&mut buf, 6);
        assert_eq!(
            write_attr(&mut c, 0x001B, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // 5 は OK。
        let n = encode_u8_value(&mut buf, 5);
        write_attr(&mut c, 0x001B, &buf[..n]).unwrap();
        assert!(c.take_dirty());
    }

    #[test]
    fn setpoint_raise_lower_heat_cool() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 32];
        // Heat +5(0.1℃)= +50(0.01℃)。heating 2000 → 2050。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(0)), (1, FieldVal::I8(5))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_heating_setpoint(), 2050);
        assert!(c.take_dirty());

        // Heat −10 = −100。heating 2050 → 1950。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(0)), (1, FieldVal::I8(-10))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_heating_setpoint(), 1950);

        // Cool +10 = +100。cooling 2600 → 2700。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(1)), (1, FieldVal::I8(10))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_cooling_setpoint(), 2700);
    }

    #[test]
    fn setpoint_raise_lower_both() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 32];
        // Both +100(=+1000 0.01℃)。heating 2000→3000 だが deadband/MAX_HEAT でクランプ、
        // cooling 2600→3200(=MAX_COOL)。heating は min(3000, 3200−250=2950) = 2950。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(2)), (1, FieldVal::I8(100))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_cooling_setpoint(), 3200);
        assert_eq!(c.occupied_heating_setpoint(), 2950);
        // deadband 維持を確認。
        assert!(c.occupied_heating_setpoint() <= c.occupied_cooling_setpoint() - DEADBAND);
    }

    #[test]
    fn setpoint_raise_lower_clamps_to_limits() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 32];
        // Cool −127(=−1270)。cooling 2600 → 1330 だが MIN_COOL(1600)へクランプ。
        // ただし heating(2000)+DEADBAND(250)=2250 が下限になるため 2250 へクランプ。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(1)), (1, FieldVal::I8(-127))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_cooling_setpoint(), 2250);

        // Heat +127(=+1270)。heating 2000 → 3270 だが deadband 上限(cooling 2250 − 250 = 2000)へ。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(0)), (1, FieldVal::I8(127))]);
        invoke(&mut c, 0x00, &buf[..n]).unwrap();
        assert_eq!(c.occupied_heating_setpoint(), 2000);
        assert!(c.occupied_heating_setpoint() <= c.occupied_cooling_setpoint() - DEADBAND);
    }

    #[test]
    fn setpoint_raise_lower_bad_mode_and_missing_field() {
        let mut c = ThermostatCluster::new();
        let mut buf = [0u8; 32];
        // mode=3 は不正 → ConstraintError。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(3)), (1, FieldVal::I8(1))]);
        assert_eq!(
            invoke(&mut c, 0x00, &buf[..n]),
            Err(ImStatus::ConstraintError)
        );
        // mode 欠落 → InvalidCommand。
        let n = build_fields(&mut buf, &[(1, FieldVal::I8(1))]);
        assert_eq!(
            invoke(&mut c, 0x00, &buf[..n]),
            Err(ImStatus::InvalidCommand)
        );
        // amount 欠落 → InvalidCommand。
        let n = build_fields(&mut buf, &[(0, FieldVal::U8(0))]);
        assert_eq!(
            invoke(&mut c, 0x00, &buf[..n]),
            Err(ImStatus::InvalidCommand)
        );
    }

    #[test]
    fn local_temperature_nullable_and_dirty() {
        let mut c = ThermostatCluster::new();
        // 初期は null。
        assert_eq!(c.local_temperature(), None);
        let mut buf = [0u8; 32];
        // null read が成功する。
        {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(0x0000), &mut e, &acc())
                .unwrap();
        }
        // 値注入で dirty、read も成功。
        c.set_local_temperature(Some(2150));
        assert!(c.take_dirty());
        assert_eq!(c.local_temperature(), Some(2150));
        // 同値の再注入では dirty を立てない。
        c.set_local_temperature(Some(2150));
        assert!(!c.take_dirty());
        {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(0x0000), &mut e, &acc())
                .unwrap();
        }
    }

    #[test]
    fn meta_feature_and_attributes() {
        let c = ThermostatCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0201);
        assert_eq!(meta.revision, 6);
        assert_eq!(meta.feature_map, 0x03);
        // 固有属性 9 個(0000/0011/0012/0015-0018/001B/001C)。
        assert_eq!(meta.attributes.len(), 9);
        // AcceptedCommandList = SetpointRaiseLower(0x00)のみ。
        assert_eq!(meta.accepted_commands.len(), 1);
        assert_eq!(meta.accepted_commands[0].id.0, 0x00);
        // 全属性が read 可能。
        let mut buf = [0u8; 32];
        for am in meta.attributes {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            assert!(
                c.read_attribute(am.id, &mut e, &acc()).is_ok(),
                "attr {:#06x} read failed",
                am.id.0
            );
        }
    }
}
