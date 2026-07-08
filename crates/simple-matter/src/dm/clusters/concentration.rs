//! Concentration Measurement 族(CO2/PM1/PM2.5/PM10/TVOC/NO2、`docs/design/airq-port.md` §4.2)。
//!
//! いずれも「MeasuredValue(f32、nullable、subscribe)+ Min/MaxMeasuredValue(固定)+
//! MeasurementUnit / MeasurementMedium(固定)」の同型パターン。
//! [`measurement_cluster!`](super::measurement) と同流儀の内部マクロ
//! [`concentration_cluster!`] で struct + API + [`cluster!`](crate::cluster) 呼び出しを
//! 1 宣言から生成し、族 6 種の重複を排除する。
//!
//! FeatureMap = **MEA(bit0、数値計測)のみ**。PEA/AVG(ピーク/平均)、LEV(レベル表示)、
//! Uncertainty(0x0007)は任意 → 非実装。MeasurementMedium は常に Air(0)。
//! コマンド・イベントは無い。
//!
//! 族の他メンバー(CO 0x040C、Ozone 0x0415、Formaldehyde 0x042B、Radon 0x042F)は
//! センサが無いため未宣言だが、マクロにより 1 宣言で追加できる(設計 §4.2)。
//!
//! **TVOC/NO2 の意味論**(設計 §4.3): Sensirion VOC/NOx index(無次元 1-500)を
//! これらのクラスタの MeasuredValue に入れてはならない(既存 esp-matter FW のバグ)。
//! index は Air Quality(0x005B)の AirQualityEnum 算出材料としてアプリ層で使う。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;

/// MeasurementUnitEnum(enum8、concentration-measurement-cluster.xml)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConcentrationUnit {
    /// PPM(parts per million)。
    Ppm = 0,
    /// PPB(parts per billion)。
    Ppb = 1,
    /// PPT(parts per trillion)。
    Ppt = 2,
    /// mg/m³。
    Mgm3 = 3,
    /// µg/m³。
    Ugm3 = 4,
    /// ng/m³。
    Ngm3 = 5,
    /// particles/m³。
    Pm3 = 6,
    /// Bq/m³(becquerel per cubic meter)。
    Bqm3 = 7,
}

/// MeasurementMediumEnum の Air(0)。本実装の族は空気中計測に固定する。
const MEDIUM_AIR: u8 = 0;

/// Concentration Measurement 族クラスタを 1 宣言から生成する内部マクロ(設計 §4.2)。
///
/// 引数: `型名, cluster id, revision, MeasurementUnit 既定値([`ConcentrationUnit`] の variant)`。
/// [`measurement_cluster!`](super::measurement) との差分は
/// (1) 値型が f32(TLV single)、(2) MeasurementUnit / MeasurementMedium の固定値属性、
/// (3) FeatureMap = MEA(1)。
macro_rules! concentration_cluster {
    (
        $(#[$meta:meta])*
        $ty:ident, $id:literal, $rev:literal, $unit:ident
    ) => {
        $(#[$meta])*
        pub struct $ty {
            /// MeasuredValue(0x0000、f32、nullable)。
            measured: Option<f32>,
            /// MinMeasuredValue(0x0001、nullable、固定)。
            min: Option<f32>,
            /// MaxMeasuredValue(0x0002、nullable、固定)。
            max: Option<f32>,
            /// MeasurementUnit(0x0008、固定)。
            unit: ConcentrationUnit,
            /// dirty フラグ(Subscribe 用)。
            dirty: Dirty,
        }

        impl $ty {
            /// 仕様上このクラスタで典型的な MeasurementUnit([`Self::new`] の既定値)。
            pub const DEFAULT_UNIT: ConcentrationUnit = ConcentrationUnit::$unit;

            /// Min/Max を指定してクラスタを作る(MeasuredValue は初期 null、単位は既定値)。
            pub const fn new(min: Option<f32>, max: Option<f32>) -> Self {
                Self {
                    measured: None,
                    min,
                    max,
                    unit: Self::DEFAULT_UNIT,
                    dirty: Dirty::new(),
                }
            }

            /// MeasurementUnit を差し替える(デバイスが別単位で報告する場合)。
            pub const fn with_unit(mut self, unit: ConcentrationUnit) -> Self {
                self.unit = unit;
                self
            }

            /// MeasuredValue を設定する。変化時のみ dirty を立てる(設計 §4.2)。
            ///
            /// NaN は「常に不等」なので毎回 dirty になる。計測値に NaN を渡さないこと
            /// (センサ無効時は `None` を使う)。
            pub fn set_measured(&mut self, v: Option<f32>) {
                if self.measured != v {
                    self.measured = v;
                    self.dirty.mark();
                }
            }

            /// 現在の MeasuredValue を返す(取得 API)。
            pub const fn measured(&self) -> Option<f32> {
                self.measured
            }

            /// MeasurementUnit を返す(取得 API)。
            pub const fn unit(&self) -> ConcentrationUnit {
                self.unit
            }
        }

        impl Default for $ty {
            fn default() -> Self {
                Self::new(None, None)
            }
        }

        cluster! {
            $ty {
                id: $id,
                revision: $rev,
                // MEA(bit0、数値計測)のみ。
                feature_map: 1,
                dirty: dirty,
                invoke: _,
                attributes: [
                    0x0000 MeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: true,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.write_nullable_f32(c.measured)),
                        write: _
                    },
                    0x0001 MinMeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.write_nullable_f32(c.min)),
                        write: _
                    },
                    0x0002 MaxMeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.write_nullable_f32(c.max)),
                        write: _
                    },
                    0x0008 MeasurementUnit {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.unit as u8)),
                        write: _
                    },
                    0x0009 MeasurementMedium {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|_c: &$ty, e: &mut AttrEncoder<'_, '_>| e.write_u8(MEDIUM_AIR)),
                        write: _
                    },
                ],
                accepted: [],
                generated: [],
            }
        }
    };
}

concentration_cluster! {
    /// Carbon Dioxide Concentration Measurement クラスタ(0x040D、ppm)。データ源: SCD40。
    CarbonDioxideConcentrationCluster, 0x040D, 3, Ppm
}

concentration_cluster! {
    /// PM1 Concentration Measurement クラスタ(0x042C、µg/m³)。データ源: SEN55。
    Pm1ConcentrationCluster, 0x042C, 3, Ugm3
}

concentration_cluster! {
    /// PM2.5 Concentration Measurement クラスタ(0x042A、µg/m³)。データ源: SEN55。
    Pm25ConcentrationCluster, 0x042A, 3, Ugm3
}

concentration_cluster! {
    /// PM10 Concentration Measurement クラスタ(0x042D、µg/m³)。データ源: SEN55。
    Pm10ConcentrationCluster, 0x042D, 3, Ugm3
}

concentration_cluster! {
    /// Total Volatile Organic Compounds Concentration Measurement クラスタ(0x042E、ppb)。
    ///
    /// **注意**(設計 §4.3): Sensirion VOC index(無次元)をそのまま入れないこと。
    /// 較正済み濃度を得られるセンサでのみ搭載する。
    TvocConcentrationCluster, 0x042E, 3, Ppb
}

concentration_cluster! {
    /// Nitrogen Dioxide Concentration Measurement クラスタ(0x0413、ppb)。
    ///
    /// **注意**(設計 §4.3): Sensirion NOx index(無次元)をそのまま入れないこと。
    NitrogenDioxideConcentrationCluster, 0x0413, 3, Ppb
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvReader, TlvTag, TlvValue, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    /// 属性を read して先頭要素の [`TlvValue`] 相当を返す(f32 は値、enum は u64)。
    fn read_attr<C: ServerCluster>(c: &C, id: u16) -> TlvValue<'static> {
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        c.read_attribute(AttributeId(id as u32), &mut e, &acc())
            .unwrap();
        let n = w.len();
        let mut r = TlvReader::new(&buf[..n]);
        match r.read_next().unwrap().unwrap().value {
            TlvValue::Float(v) => TlvValue::Float(v),
            TlvValue::UnsignedInteger(v) => TlvValue::UnsignedInteger(v),
            TlvValue::Null => TlvValue::Null,
            other => panic!("unexpected wire value {other:?}"),
        }
    }

    #[test]
    fn family_meta_ids_and_units() {
        // (id, DEFAULT_UNIT) が宣言どおりであること。
        let co2 = CarbonDioxideConcentrationCluster::new(Some(400.0), Some(10000.0));
        assert_eq!(co2.meta().id.0, 0x040D);
        assert_eq!(co2.unit(), ConcentrationUnit::Ppm);
        let pm1 = Pm1ConcentrationCluster::new(Some(0.0), Some(1000.0));
        assert_eq!(pm1.meta().id.0, 0x042C);
        assert_eq!(pm1.unit(), ConcentrationUnit::Ugm3);
        let pm25 = Pm25ConcentrationCluster::new(Some(0.0), Some(1000.0));
        assert_eq!(pm25.meta().id.0, 0x042A);
        let pm10 = Pm10ConcentrationCluster::new(Some(0.0), Some(1000.0));
        assert_eq!(pm10.meta().id.0, 0x042D);
        let tvoc = TvocConcentrationCluster::new(None, None);
        assert_eq!(tvoc.meta().id.0, 0x042E);
        assert_eq!(tvoc.unit(), ConcentrationUnit::Ppb);
        let no2 = NitrogenDioxideConcentrationCluster::new(None, None);
        assert_eq!(no2.meta().id.0, 0x0413);
        assert_eq!(no2.unit(), ConcentrationUnit::Ppb);
        // 共通形: revision 3、FeatureMap=MEA(1)、固有属性 5 個、コマンド無し。
        for meta in [
            co2.meta(),
            pm1.meta(),
            pm25.meta(),
            pm10.meta(),
            tvoc.meta(),
            no2.meta(),
        ] {
            assert_eq!(meta.revision, 3);
            assert_eq!(meta.feature_map, 1);
            assert_eq!(meta.attributes.len(), 5);
            assert!(meta.accepted_commands.is_empty());
            // MeasuredValue のみ subscribe 可。
            assert!(meta.attributes[0].subscribable);
            assert!(!meta.attributes[1].subscribable);
        }
    }

    #[test]
    fn measured_value_f32_wire_roundtrip() {
        let mut c = CarbonDioxideConcentrationCluster::new(Some(400.0), Some(10000.0));
        // 初期は null。
        assert!(matches!(read_attr(&c, 0x0000), TlvValue::Null));
        // f32 が TLV single としてワイヤを往復する(設計 R4 の単体側)。
        c.set_measured(Some(612.5));
        assert!(c.take_dirty());
        match read_attr(&c, 0x0000) {
            TlvValue::Float(v) => assert_eq!(v, 612.5),
            other => panic!("expected f32, got {other:?}"),
        }
        // Min/Max はコンストラクタ値。
        match read_attr(&c, 0x0001) {
            TlvValue::Float(v) => assert_eq!(v, 400.0),
            other => panic!("expected f32, got {other:?}"),
        }
        match read_attr(&c, 0x0002) {
            TlvValue::Float(v) => assert_eq!(v, 10000.0),
            other => panic!("expected f32, got {other:?}"),
        }
    }

    #[test]
    fn dirty_only_on_change_and_null_transition() {
        let mut c = Pm25ConcentrationCluster::new(Some(0.0), Some(1000.0));
        c.set_measured(Some(12.5));
        assert!(c.take_dirty());
        // 同値の再注入では dirty を立てない。
        c.set_measured(Some(12.5));
        assert!(!c.take_dirty());
        // null 化で dirty。
        c.set_measured(None);
        assert!(c.take_dirty());
        assert_eq!(c.measured(), None);
    }

    #[test]
    fn unit_and_medium_fixed_attributes() {
        // 単位はワイヤで enum8、medium は常に Air(0)。
        let pm25 = Pm25ConcentrationCluster::new(None, None);
        assert!(matches!(
            read_attr(&pm25, 0x0008),
            TlvValue::UnsignedInteger(4) // UGM3
        ));
        assert!(matches!(
            read_attr(&pm25, 0x0009),
            TlvValue::UnsignedInteger(0) // Air
        ));
        // with_unit で差し替えられる(例: CO2 を mg/m³ で報告するデバイス)。
        let co2 =
            CarbonDioxideConcentrationCluster::new(None, None).with_unit(ConcentrationUnit::Mgm3);
        assert!(matches!(
            read_attr(&co2, 0x0008),
            TlvValue::UnsignedInteger(3) // MGM3
        ));
    }
}
