//! Occupancy Sensing クラスタ(0x0406、`docs/design/basic-clusters.md` §1.4)。
//!
//! 在室センサ(PIR 等)の在室状態を表す最小クラスタ。`Occupancy`(0x0000、map8 bit0)を保持し、
//! 変化時に dirty を立てる。`OccupancySensorType`(0x0001)/`OccupancySensorTypeBitmap`(0x0002)は
//! センサ種別を示す固定値(既定 PIR)。
//!
//! FeatureMap=0、revision 3。HoldTime / PIR 遅延系は任意 → 非実装。1.3 の rev 3 にはイベント無し。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;

/// OccupancySensorType = PIR(0)。
pub const SENSOR_TYPE_PIR: u8 = 0;
/// OccupancySensorType = Ultrasonic(1)。
pub const SENSOR_TYPE_ULTRASONIC: u8 = 1;
/// OccupancySensorType = PIRAndUltrasonic(2)。
pub const SENSOR_TYPE_PIR_AND_ULTRASONIC: u8 = 2;
/// OccupancySensorType = PhysicalContact(3)。
pub const SENSOR_TYPE_PHYSICAL_CONTACT: u8 = 3;

/// OccupancySensorTypeBitmap の PIR ビット(bit0)。
const SENSOR_BITMAP_PIR: u8 = 1 << 0;

/// Occupancy 属性の occupied ビット(bit0)。
const OCCUPIED_BIT: u8 = 1 << 0;

/// Occupancy Sensing クラスタ(0x0406)。
#[derive(Debug)]
pub struct OccupancySensingCluster {
    /// Occupancy(0x0000、map8。bit0 = occupied)。
    occupancy: u8,
    /// OccupancySensorType(0x0001、enum8、固定)。
    sensor_type: u8,
    /// OccupancySensorTypeBitmap(0x0002、map8、固定)。
    sensor_type_bitmap: u8,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
}

impl OccupancySensingCluster {
    /// 既定(PIR / bitmap bit0)のクラスタを作る(設計 §1.4)。
    pub const fn new() -> Self {
        Self {
            occupancy: 0,
            sensor_type: SENSOR_TYPE_PIR,
            sensor_type_bitmap: SENSOR_BITMAP_PIR,
            dirty: Dirty::new(),
        }
    }

    /// センサ種別と bitmap を指定してクラスタを作る。
    pub const fn with_sensor_type(sensor_type: u8, sensor_type_bitmap: u8) -> Self {
        Self {
            occupancy: 0,
            sensor_type,
            sensor_type_bitmap,
            dirty: Dirty::new(),
        }
    }

    /// 在室状態(Occupancy bit0)を設定する。変化時のみ dirty を立てる(設計 §1.4)。
    pub fn set_occupied(&mut self, occupied: bool) {
        let v = if occupied { OCCUPIED_BIT } else { 0 };
        if self.occupancy != v {
            self.occupancy = v;
            self.dirty.mark();
        }
    }

    /// 現在の在室状態を返す(取得 API)。
    pub const fn is_occupied(&self) -> bool {
        self.occupancy & OCCUPIED_BIT != 0
    }
}

impl Default for OccupancySensingCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    OccupancySensingCluster {
        id: 0x0406,
        revision: 3,
        feature_map: 0,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 Occupancy {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &OccupancySensingCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.occupancy)),
                write: _
            },
            0x0001 OccupancySensorType {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &OccupancySensingCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.sensor_type)),
                write: _
            },
            0x0002 OccupancySensorTypeBitmap {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &OccupancySensingCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.sensor_type_bitmap)),
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
    use crate::dm::meta::{AccessContext, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    #[test]
    fn set_occupied_dirty() {
        let mut c = OccupancySensingCluster::new();
        assert!(!c.is_occupied());
        // false → true: dirty。
        c.set_occupied(true);
        assert!(c.is_occupied());
        assert!(c.take_dirty());
        // 同値では dirty を立てない。
        c.set_occupied(true);
        assert!(!c.take_dirty());
        // true → false。
        c.set_occupied(false);
        assert!(!c.is_occupied());
        assert!(c.take_dirty());
    }

    #[test]
    fn meta_and_reads() {
        let c =
            OccupancySensingCluster::with_sensor_type(SENSOR_TYPE_PIR_AND_ULTRASONIC, 0b0000_0011);
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0406);
        assert_eq!(meta.revision, 3);
        assert_eq!(meta.feature_map, 0);
        // 固有属性 3 個(Occupancy / SensorType / SensorTypeBitmap)、コマンド無し。
        assert_eq!(meta.attributes.len(), 3);
        assert!(meta.accepted_commands.is_empty());
        // 全属性が read 可能。
        let mut buf = [0u8; 16];
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
