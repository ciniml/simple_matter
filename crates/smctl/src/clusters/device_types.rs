//! Matter 1.x 標準デバイスタイプの「名前だけの注釈テーブル」(設計 doc §11)。
//!
//! Descriptor(0x001D)の DeviceTypeList 要素(`{0: deviceType, 1: revision}`)の
//! deviceType ID を、`--names` 指定時に `0x0101(DimmableLight)` のように名前付きで
//! 表示するための ID→名前対応表。[`super::names`] のクラスタ名テーブルと同じ流儀
//! (仕様の CamelCase 名・ID 昇順 + 二分探索)。
//!
//! 採録元は Matter 1.x Device Library 仕様(Utility / App 両カテゴリの標準
//! デバイスタイプ)。未知の ID(vendor 域等)は `None` を返し、表示側は
//! 従来どおり数値のみになる(テーブルは可読性を足すだけで機能要件にしない)。

/// 標準デバイスタイプ ID → 仕様名(ID 昇順。[`device_type_name`] が二分探索する)。
static DEVICE_TYPE_NAMES: &[(u32, &str)] = &[
    (0x000A, "DoorLock"),
    (0x000B, "DoorLockController"),
    (0x000E, "Aggregator"),
    (0x000F, "GenericSwitch"),
    (0x0011, "PowerSource"),
    (0x0012, "OtaRequestor"),
    (0x0013, "BridgedNode"),
    (0x0014, "OtaProvider"),
    (0x0015, "ContactSensor"),
    (0x0016, "RootNode"),
    (0x0017, "SolarPower"),
    (0x0018, "BatteryStorage"),
    (0x0019, "SecondaryNetworkInterface"),
    (0x0022, "Speaker"),
    (0x0023, "CastingVideoPlayer"),
    (0x0024, "ContentApp"),
    (0x0027, "ModeSelect"),
    (0x0028, "BasicVideoPlayer"),
    (0x0029, "CastingVideoClient"),
    (0x002A, "VideoRemoteControl"),
    (0x002B, "Fan"),
    (0x002C, "AirQualitySensor"),
    (0x002D, "AirPurifier"),
    (0x0041, "WaterFreezeDetector"),
    (0x0042, "WaterValve"),
    (0x0043, "RainSensor"),
    (0x0044, "WaterLeakDetector"),
    (0x0070, "Refrigerator"),
    (0x0071, "TemperatureControlledCabinet"),
    (0x0072, "RoomAirConditioner"),
    (0x0073, "LaundryWasher"),
    (0x0074, "RoboticVacuumCleaner"),
    (0x0075, "Dishwasher"),
    (0x0076, "SmokeCoAlarm"),
    (0x0077, "Cooktop"),
    (0x0078, "CookSurface"),
    (0x0079, "MicrowaveOven"),
    (0x007A, "ExtractorHood"),
    (0x007B, "Oven"),
    (0x007C, "LaundryDryer"),
    (0x0100, "OnOffLight"),
    (0x0101, "DimmableLight"),
    (0x0103, "OnOffLightSwitch"),
    (0x0104, "DimmerSwitch"),
    (0x0105, "ColorDimmerSwitch"),
    (0x0106, "LightSensor"),
    (0x0107, "OccupancySensor"),
    (0x010A, "OnOffPlugInUnit"),
    (0x010B, "DimmablePlugInUnit"),
    (0x010C, "ColorTemperatureLight"),
    (0x010D, "ExtendedColorLight"),
    (0x0202, "WindowCovering"),
    (0x0203, "WindowCoveringController"),
    (0x0300, "HeatingCoolingUnit"),
    (0x0301, "Thermostat"),
    (0x0302, "TemperatureSensor"),
    (0x0303, "Pump"),
    (0x0304, "PumpController"),
    (0x0305, "PressureSensor"),
    (0x0306, "FlowSensor"),
    (0x0307, "HumiditySensor"),
    (0x0309, "HeatPump"),
    (0x050C, "Evse"),
    (0x050D, "DeviceEnergyManagement"),
    (0x050F, "WaterHeater"),
    (0x0510, "ElectricalSensor"),
    (0x0840, "ControlBridge"),
    (0x0850, "OnOffSensor"),
];

/// 標準デバイスタイプ ID を仕様名にする(未知の ID は `None`)。
pub fn device_type_name(id: u32) -> Option<&'static str> {
    DEVICE_TYPE_NAMES
        .binary_search_by_key(&id, |&(dt, _)| dt)
        .ok()
        .map(|i| DEVICE_TYPE_NAMES[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        // binary_search の前提。重複もここで検査する。
        for w in DEVICE_TYPE_NAMES.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "DEVICE_TYPE_NAMES must be sorted/unique: {:#06x} >= {:#06x}",
                w[0].0,
                w[1].0
            );
        }
        assert!(
            DEVICE_TYPE_NAMES.len() >= 40,
            "expect 40+ standard device types"
        );
    }

    #[test]
    fn device_type_name_lookup() {
        assert_eq!(device_type_name(0x0016), Some("RootNode"));
        assert_eq!(device_type_name(0x0011), Some("PowerSource"));
        assert_eq!(device_type_name(0x0100), Some("OnOffLight"));
        assert_eq!(device_type_name(0x0101), Some("DimmableLight"));
        assert_eq!(device_type_name(0x010D), Some("ExtendedColorLight"));
        assert_eq!(device_type_name(0x0301), Some("Thermostat"));
        assert_eq!(device_type_name(0x0850), Some("OnOffSensor"));
        // 未定義 ID・vendor 域は None(表示側は数値のみにフォールバック)。
        assert_eq!(device_type_name(0x0001), None);
        assert_eq!(device_type_name(0xFC00), None);
    }
}
