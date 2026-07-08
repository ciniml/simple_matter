//! 計測系クラスタ(温度/気圧/流量/湿度/照度、`docs/design/basic-clusters.md` §1.3)。
//!
//! いずれも「MeasuredValue(nullable、subscribe)+ MinMeasuredValue / MaxMeasuredValue(固定)」の
//! 同型パターン。内部マクロ [`measurement_cluster!`] で struct + API + [`cluster!`](crate::cluster)
//! 呼び出しを 1 宣言から生成し、5 クラスタの重複を排除する(設計 §0.1)。
//!
//! Tolerance / ScaledValue(Pressure)/ LightSensorType(Illuminance)は任意 → 非実装。
//! FeatureMap はいずれも 0。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;

/// 計測系クラスタを 1 宣言から生成する内部マクロ(設計 §1.3)。
///
/// 引数: `型名, cluster id, revision, 値型(i16 or u16), エンコーダ関数`。
/// エンコーダ関数は [`AttrEncoder`] の nullable 書き込み(`write_nullable_i16` /
/// `write_nullable_u16`)を渡す。
macro_rules! measurement_cluster {
    (
        $(#[$meta:meta])*
        $ty:ident, $id:literal, $rev:literal, $val:ty, $enc:ident
    ) => {
        $(#[$meta])*
        pub struct $ty {
            /// MeasuredValue(0x0000、nullable)。
            measured: Option<$val>,
            /// MinMeasuredValue(0x0001、nullable、固定)。
            min: Option<$val>,
            /// MaxMeasuredValue(0x0002、nullable、固定)。
            max: Option<$val>,
            /// dirty フラグ(Subscribe 用)。
            dirty: Dirty,
        }

        impl $ty {
            /// Min/Max を指定してクラスタを作る(MeasuredValue は初期 null)。
            pub const fn new(min: Option<$val>, max: Option<$val>) -> Self {
                Self {
                    measured: None,
                    min,
                    max,
                    dirty: Dirty::new(),
                }
            }

            /// MeasuredValue を設定する。変化時のみ dirty を立てる(設計 §1.3)。
            pub fn set_measured(&mut self, v: Option<$val>) {
                if self.measured != v {
                    self.measured = v;
                    self.dirty.mark();
                }
            }

            /// 現在の MeasuredValue を返す(取得 API)。
            pub const fn measured(&self) -> Option<$val> {
                self.measured
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
                feature_map: 0,
                dirty: dirty,
                invoke: _,
                attributes: [
                    0x0000 MeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: true,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.$enc(c.measured)),
                        write: _
                    },
                    0x0001 MinMeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.$enc(c.min)),
                        write: _
                    },
                    0x0002 MaxMeasuredValue {
                        access: View,
                        quality: [],
                        subscribe: false,
                        read: (|c: &$ty, e: &mut AttrEncoder<'_, '_>| e.$enc(c.max)),
                        write: _
                    },
                ],
                accepted: [],
                generated: [],
            }
        }
    };
}

measurement_cluster! {
    /// Temperature Measurement クラスタ(0x0402、revision 4、i16、単位 0.01℃)。
    TemperatureMeasurementCluster, 0x0402, 4, i16, write_nullable_i16
}

measurement_cluster! {
    /// Pressure Measurement クラスタ(0x0403、revision 3、i16、単位 0.1kPa)。
    PressureMeasurementCluster, 0x0403, 3, i16, write_nullable_i16
}

measurement_cluster! {
    /// Flow Measurement クラスタ(0x0404、revision 3、u16、単位 0.1m³/h)。
    FlowMeasurementCluster, 0x0404, 3, u16, write_nullable_u16
}

measurement_cluster! {
    /// Relative Humidity Measurement クラスタ(0x0405、revision 3、u16、単位 0.01%)。
    RelativeHumidityMeasurementCluster, 0x0405, 3, u16, write_nullable_u16
}

measurement_cluster! {
    /// Illuminance Measurement クラスタ(0x0400、revision 3、u16、log10(lux)×10⁴)。
    IlluminanceMeasurementCluster, 0x0400, 3, u16, write_nullable_u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    /// 全属性が read できることを確認する(nullable も null で成功する)。
    fn assert_all_readable<C: ServerCluster>(c: &C) {
        let mut buf = [0u8; 32];
        for am in c.meta().attributes {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            assert!(
                c.read_attribute(am.id, &mut e, &acc()).is_ok(),
                "attr {:#06x} read failed",
                am.id.0
            );
        }
    }

    #[test]
    fn temperature_meta_and_set() {
        let mut c = TemperatureMeasurementCluster::new(Some(-4000), Some(12500));
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0402);
        assert_eq!(meta.revision, 4);
        assert_eq!(meta.feature_map, 0);
        // 固有属性 3 個(MeasuredValue / Min / Max)、コマンド無し。
        assert_eq!(meta.attributes.len(), 3);
        assert!(meta.accepted_commands.is_empty());
        // 初期は null、read 可能。
        assert_eq!(c.measured(), None);
        assert_all_readable(&c);
        // 値注入で dirty、read 可能。
        c.set_measured(Some(2150));
        assert!(c.take_dirty());
        assert_eq!(c.measured(), Some(2150));
        assert_all_readable(&c);
        // 同値の再注入では dirty を立てない。
        c.set_measured(Some(2150));
        assert!(!c.take_dirty());
        // null 化で dirty。
        c.set_measured(None);
        assert!(c.take_dirty());
        assert_eq!(c.measured(), None);
    }

    #[test]
    fn unsigned_measurements_meta() {
        // u16 系(revision 3)の ID を確認する。
        let flow = FlowMeasurementCluster::new(Some(0), Some(1000));
        assert_eq!(flow.meta().id.0, 0x0404);
        assert_eq!(flow.meta().revision, 3);
        let hum = RelativeHumidityMeasurementCluster::new(Some(0), Some(10000));
        assert_eq!(hum.meta().id.0, 0x0405);
        let illum = IlluminanceMeasurementCluster::new(Some(1), Some(0xFFFE));
        assert_eq!(illum.meta().id.0, 0x0400);
        let press = PressureMeasurementCluster::new(Some(0), Some(10000));
        assert_eq!(press.meta().id.0, 0x0403);
        assert_eq!(press.meta().feature_map, 0);
        assert_all_readable(&flow);
        assert_all_readable(&hum);
        assert_all_readable(&illum);
        assert_all_readable(&press);
    }

    #[test]
    fn min_max_reads_reflect_constructor() {
        let c = PressureMeasurementCluster::new(Some(300), Some(1100));
        // Min(0x0001)/ Max(0x0002)がコンストラクタ値を返す。
        let read = |id: u16| {
            let mut buf = [0u8; 16];
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(id as u32), &mut e, &acc())
                .unwrap();
        };
        read(0x0001);
        read(0x0002);
    }
}
