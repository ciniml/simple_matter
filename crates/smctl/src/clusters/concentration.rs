//! Concentration Measurement 族(CO2/PM1/PM2.5/PM10/TVOC/NO2)の名前テーブル。
//!
//! 6 クラスタとも同型(MeasuredValue f32 + Min/Max + MeasurementUnit/Medium enum8)
//! なので 1 ファイルに集約する(コア側 `dm/clusters/concentration.rs` と同じ割り方)。

use super::cluster_def;

/// 族共通の属性ブロックを 1 宣言から生成する(measured-value は f32/nullable)。
macro_rules! concentration_def {
    ( $def:ident, $cid:expr, $cname:literal ) => {
        cluster_def! {
            pub $def = cluster($cid, $cname) {
                attrs {
                    0x0000 => "measured-value": F32;
                    0x0001 => "min-measured-value": F32;
                    0x0002 => "max-measured-value": F32;
                    0x0008 => "measurement-unit": U8;
                    0x0009 => "measurement-medium": U8;
                }
                cmds {}
            }
        }
    };
}

concentration_def!(CO2_DEF, 0x040D, "carbon-dioxide-concentration");
concentration_def!(NO2_DEF, 0x0413, "nitrogen-dioxide-concentration");
concentration_def!(PM25_DEF, 0x042A, "pm25-concentration");
concentration_def!(PM1_DEF, 0x042C, "pm1-concentration");
concentration_def!(PM10_DEF, 0x042D, "pm10-concentration");
concentration_def!(TVOC_DEF, 0x042E, "tvoc-concentration");
