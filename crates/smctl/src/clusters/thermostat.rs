//! Thermostat クラスタ(0x0201)の名前テーブル(設計 §15.4)。
//!
//! 属性/コマンド名は chip-tool と同じ kebab-case。i16 属性(setpoint / limit / local-temperature)を
//! 持つ初のレジストリ収載クラスタ。
//!
//! 例: `smctl thermostat write occupied-heating-setpoint 2100 <node> 1`
//!     `smctl thermostat setpoint-raise-lower 0 5 <node> 1`(Heat を +0.5℃)

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0201, "thermostat") {
        attrs {
            0x0000 => "local-temperature": I16;
            0x0011 => "occupied-cooling-setpoint": I16 rw;
            0x0012 => "occupied-heating-setpoint": I16 rw;
            0x0015 => "min-heat-setpoint-limit": I16;
            0x0016 => "max-heat-setpoint-limit": I16;
            0x0017 => "min-cool-setpoint-limit": I16;
            0x0018 => "max-cool-setpoint-limit": I16;
            0x001B => "control-sequence-of-operation": U8 rw;
            0x001C => "system-mode": U8 rw;
        }
        cmds {
            0x00 => "setpoint-raise-lower" {
                0 => "mode": U8;
                1 => "amount": I8;
            }
        }
    }
}
