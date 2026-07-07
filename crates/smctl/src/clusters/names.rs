//! Matter 1.x 標準クラスタの「名前だけの注釈テーブル」(設計 doc §9.5)。
//!
//! クラスタレジストリ([`super::CLUSTERS`]、フル定義 = 型付き属性/コマンド)に
//! 未収載の ID でも、`[im]`/`[tlv]` ログや `any read` の出力で
//! `0x0033(GeneralDiagnostics)` のように名前を添えるための ID→名前対応表。
//!
//! - クラスタ名: Matter 1.x Application/Core 仕様の標準クラスタ ID 一覧から採録
//!   (CamelCase の仕様名のまま。レジストリ収載クラスタの kebab-case 名とは
//!   意図的に表記を変え、「フル定義あり(name(0xID))」と「名前注釈のみ
//!   (0xID(Name))」を見分けられるようにする)。
//! - 属性名: **global 属性(0xFFF8〜0xFFFD)のみ**解決する。クラスタ個別属性の
//!   フル定義(型付き)は従来どおりレジストリ収載分だけ。

use simple_matter::dm::meta::{AttributeId, ClusterId};

/// 標準クラスタ ID → 仕様名(ID 昇順。[`cluster_name`] が二分探索する)。
static CLUSTER_NAMES: &[(u32, &str)] = &[
    (0x0003, "Identify"),
    (0x0004, "Groups"),
    (0x0005, "Scenes"),
    (0x0006, "OnOff"),
    (0x0008, "LevelControl"),
    (0x001C, "PulseWidthModulation"),
    (0x001D, "Descriptor"),
    (0x001E, "Binding"),
    (0x001F, "AccessControl"),
    (0x0025, "Actions"),
    (0x0028, "BasicInformation"),
    (0x0029, "OtaSoftwareUpdateProvider"),
    (0x002A, "OtaSoftwareUpdateRequestor"),
    (0x002B, "LocalizationConfiguration"),
    (0x002C, "TimeFormatLocalization"),
    (0x002D, "UnitLocalization"),
    (0x002E, "PowerSourceConfiguration"),
    (0x002F, "PowerSource"),
    (0x0030, "GeneralCommissioning"),
    (0x0031, "NetworkCommissioning"),
    (0x0032, "DiagnosticLogs"),
    (0x0033, "GeneralDiagnostics"),
    (0x0034, "SoftwareDiagnostics"),
    (0x0035, "ThreadNetworkDiagnostics"),
    (0x0036, "WiFiNetworkDiagnostics"),
    (0x0037, "EthernetNetworkDiagnostics"),
    (0x0038, "TimeSynchronization"),
    (0x0039, "BridgedDeviceBasicInformation"),
    (0x003B, "Switch"),
    (0x003C, "AdministratorCommissioning"),
    (0x003E, "OperationalCredentials"),
    (0x003F, "GroupKeyManagement"),
    (0x0040, "FixedLabel"),
    (0x0041, "UserLabel"),
    (0x0045, "BooleanState"),
    (0x0046, "IcdManagement"),
    (0x0047, "Timer"),
    (0x0048, "OvenCavityOperationalState"),
    (0x0049, "OvenMode"),
    (0x004A, "LaundryDryerControls"),
    (0x0050, "ModeSelect"),
    (0x0051, "LaundryWasherMode"),
    (0x0052, "RefrigeratorAndTemperatureControlledCabinetMode"),
    (0x0053, "LaundryWasherControls"),
    (0x0054, "RvcRunMode"),
    (0x0055, "RvcCleanMode"),
    (0x0056, "TemperatureControl"),
    (0x0057, "RefrigeratorAlarm"),
    (0x0059, "DishwasherMode"),
    (0x005B, "AirQuality"),
    (0x005C, "SmokeCoAlarm"),
    (0x005D, "DishwasherAlarm"),
    (0x005E, "MicrowaveOvenMode"),
    (0x005F, "MicrowaveOvenControl"),
    (0x0060, "OperationalState"),
    (0x0061, "RvcOperationalState"),
    (0x0062, "ScenesManagement"),
    (0x0071, "HepaFilterMonitoring"),
    (0x0072, "ActivatedCarbonFilterMonitoring"),
    (0x0080, "BooleanStateConfiguration"),
    (0x0081, "ValveConfigurationAndControl"),
    (0x0090, "ElectricalPowerMeasurement"),
    (0x0091, "ElectricalEnergyMeasurement"),
    (0x0094, "WaterHeaterManagement"),
    (0x0096, "DemandResponseLoadControl"),
    (0x0097, "Messages"),
    (0x0098, "DeviceEnergyManagement"),
    (0x0099, "EnergyEvse"),
    (0x009B, "EnergyPreference"),
    (0x009C, "PowerTopology"),
    (0x009D, "EnergyEvseMode"),
    (0x009E, "WaterHeaterMode"),
    (0x009F, "DeviceEnergyManagementMode"),
    (0x0101, "DoorLock"),
    (0x0102, "WindowCovering"),
    (0x0200, "PumpConfigurationAndControl"),
    (0x0201, "Thermostat"),
    (0x0202, "FanControl"),
    (0x0204, "ThermostatUserInterfaceConfiguration"),
    (0x0300, "ColorControl"),
    (0x0301, "BallastConfiguration"),
    (0x0400, "IlluminanceMeasurement"),
    (0x0402, "TemperatureMeasurement"),
    (0x0403, "PressureMeasurement"),
    (0x0404, "FlowMeasurement"),
    (0x0405, "RelativeHumidityMeasurement"),
    (0x0406, "OccupancySensing"),
    (0x040C, "CarbonMonoxideConcentrationMeasurement"),
    (0x040D, "CarbonDioxideConcentrationMeasurement"),
    (0x0413, "NitrogenDioxideConcentrationMeasurement"),
    (0x0415, "OzoneConcentrationMeasurement"),
    (0x042A, "Pm25ConcentrationMeasurement"),
    (0x042B, "FormaldehydeConcentrationMeasurement"),
    (0x042C, "Pm1ConcentrationMeasurement"),
    (0x042D, "Pm10ConcentrationMeasurement"),
    (0x042E, "TotalVolatileOrganicCompoundsConcentrationMeasurement"),
    (0x042F, "RadonConcentrationMeasurement"),
    (0x0503, "WakeOnLan"),
    (0x0504, "Channel"),
    (0x0505, "TargetNavigator"),
    (0x0506, "MediaPlayback"),
    (0x0507, "MediaInput"),
    (0x0508, "LowPower"),
    (0x0509, "KeypadInput"),
    (0x050A, "ContentLauncher"),
    (0x050B, "AudioOutput"),
    (0x050C, "ApplicationLauncher"),
    (0x050D, "ApplicationBasic"),
    (0x050E, "AccountLogin"),
    (0x050F, "ContentControl"),
    (0x0510, "ContentAppObserver"),
];

/// 標準クラスタ ID を仕様名にする(未知の ID は `None`)。
pub fn cluster_name(id: ClusterId) -> Option<&'static str> {
    CLUSTER_NAMES
        .binary_search_by_key(&id.0, |&(cid, _)| cid)
        .ok()
        .map(|i| CLUSTER_NAMES[i].1)
}

/// global 属性(全クラスタ共通、Matter 1.x Core §7.13)の名前を引く。
pub fn global_attr_name(id: AttributeId) -> Option<&'static str> {
    match id.0 {
        0xFFF8 => Some("GeneratedCommandList"),
        0xFFF9 => Some("AcceptedCommandList"),
        0xFFFA => Some("EventList"),
        0xFFFB => Some("AttributeList"),
        0xFFFC => Some("FeatureMap"),
        0xFFFD => Some("ClusterRevision"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        // binary_search の前提。重複もここで検査する。
        for w in CLUSTER_NAMES.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "CLUSTER_NAMES must be sorted/unique: {:#06x} >= {:#06x}",
                w[0].0,
                w[1].0
            );
        }
        assert!(CLUSTER_NAMES.len() >= 50, "expect 50+ standard clusters");
    }

    #[test]
    fn cluster_name_lookup() {
        assert_eq!(cluster_name(ClusterId(0x0033)), Some("GeneralDiagnostics"));
        assert_eq!(cluster_name(ClusterId(0x0006)), Some("OnOff"));
        assert_eq!(cluster_name(ClusterId(0x0101)), Some("DoorLock"));
        assert_eq!(cluster_name(ClusterId(0x0510)), Some("ContentAppObserver"));
        assert_eq!(cluster_name(ClusterId(0x0001)), None);
        assert_eq!(cluster_name(ClusterId(0xFC00)), None); // vendor 域
    }

    #[test]
    fn global_attr_lookup() {
        assert_eq!(global_attr_name(AttributeId(0xFFFB)), Some("AttributeList"));
        assert_eq!(global_attr_name(AttributeId(0xFFFC)), Some("FeatureMap"));
        assert_eq!(
            global_attr_name(AttributeId(0xFFFD)),
            Some("ClusterRevision")
        );
        assert_eq!(global_attr_name(AttributeId(0x0000)), None);
    }
}
