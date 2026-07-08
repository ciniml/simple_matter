//! Air Quality クラスタ(0x005B、`docs/design/airq-port.md` §4.2)。
//!
//! 空気質の総合評価 1 属性(`AirQuality`、enum8 0-6、subscribe)のみを持つ最小クラスタ。
//! FeatureMap = FAIR|MOD|VPOOR|XPOOR(0x0F、全レベル対応)、revision 1。コマンドは無い。
//!
//! [`AirQualityEnum`] の**算出**(CO2/PM2.5 等の計測値 → Good..ExtremelyPoor)は
//! クラスタではなくアプリ層(example / ファーム)の責務とする(閾値はデバイスポリシー。
//! 設計 §4.2)。コアは [`AirQualityCluster::set_air_quality`] を受けるだけ。
//! 既存 esp-matter FW が放置していた「総合評価の未更新(常に Unknown)」を
//! この契約で是正する(設計 §1.2)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;

/// AirQualityEnum(enum8、air-quality-cluster.xml)。
///
/// `Ord` 導出により「複数計測値からの worst-of 合成」(`max()`)がアプリ層で書ける。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum AirQualityEnum {
    /// 未知(初期値)。
    #[default]
    Unknown = 0,
    /// 良い。
    Good = 1,
    /// まあ良い。
    Fair = 2,
    /// 中程度。
    Moderate = 3,
    /// 悪い。
    Poor = 4,
    /// とても悪い。
    VeryPoor = 5,
    /// 極めて悪い。
    ExtremelyPoor = 6,
}

/// Air Quality クラスタ(0x005B)。
#[derive(Debug)]
pub struct AirQualityCluster {
    /// AirQuality(0x0000、enum8)。
    air_quality: AirQualityEnum,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
}

impl AirQualityCluster {
    /// 初期状態(AirQuality=Unknown)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            air_quality: AirQualityEnum::Unknown,
            dirty: Dirty::new(),
        }
    }

    /// AirQuality を設定する。変化時のみ dirty を立てる(設計 §4.2)。
    pub fn set_air_quality(&mut self, v: AirQualityEnum) {
        if self.air_quality != v {
            self.air_quality = v;
            self.dirty.mark();
        }
    }

    /// 現在の AirQuality を返す(取得 API)。
    pub const fn air_quality(&self) -> AirQualityEnum {
        self.air_quality
    }
}

impl Default for AirQualityCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    AirQualityCluster {
        id: 0x005B,
        revision: 1,
        // FAIR(bit0)| MOD(bit1)| VPOOR(bit2)| XPOOR(bit3)= 全レベル対応。
        feature_map: 0x0F,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 AirQuality {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &AirQualityCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.air_quality as u8)),
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
    use crate::tlv::{TlvReader, TlvTag, TlvValue, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    /// AirQuality(0x0000)を read してデコード済みの u64 を返す。
    fn read_air_quality(c: &AirQualityCluster) -> u64 {
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        c.read_attribute(AttributeId(0x0000), &mut e, &acc())
            .unwrap();
        let n = w.len();
        let mut r = TlvReader::new(&buf[..n]);
        match r.read_next().unwrap().unwrap().value {
            TlvValue::UnsignedInteger(v) => v,
            other => panic!("expected unsigned, got {other:?}"),
        }
    }

    #[test]
    fn meta_and_initial_state() {
        let c = AirQualityCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x005B);
        assert_eq!(meta.revision, 1);
        // FAIR|MOD|VPOOR|XPOOR。
        assert_eq!(meta.feature_map, 0x0F);
        // 固有属性 1 個(AirQuality)、コマンド無し。
        assert_eq!(meta.attributes.len(), 1);
        assert!(meta.attributes[0].subscribable);
        assert!(meta.accepted_commands.is_empty());
        assert_eq!(c.air_quality(), AirQualityEnum::Unknown);
        assert_eq!(read_air_quality(&c), 0);
    }

    #[test]
    fn set_air_quality_dirty_only_on_change() {
        let mut c = AirQualityCluster::new();
        // Unknown → Moderate: dirty + ワイヤ値 3。
        c.set_air_quality(AirQualityEnum::Moderate);
        assert!(c.take_dirty());
        assert_eq!(read_air_quality(&c), 3);
        // 同値の再設定では dirty を立てない。
        c.set_air_quality(AirQualityEnum::Moderate);
        assert!(!c.take_dirty());
        // ExtremelyPoor はワイヤ値 6。
        c.set_air_quality(AirQualityEnum::ExtremelyPoor);
        assert!(c.take_dirty());
        assert_eq!(read_air_quality(&c), 6);
    }

    #[test]
    fn enum_ordering_supports_worst_of() {
        // アプリ層の worst-of 合成(max)前提の順序性(設計 §4.2)。
        assert!(AirQualityEnum::Good < AirQualityEnum::Fair);
        assert!(AirQualityEnum::Poor < AirQualityEnum::ExtremelyPoor);
        assert_eq!(
            AirQualityEnum::Fair.max(AirQualityEnum::VeryPoor),
            AirQualityEnum::VeryPoor
        );
    }
}
