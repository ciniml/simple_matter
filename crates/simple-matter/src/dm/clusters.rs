//! 具象クラスタ実装(`docs/design/interaction-model.md` §9)。
//!
//! いずれも [`crate::cluster!`] マクロを用いた combined 実装(logic/translation 分離なし)。
//! 属性ストレージと dirty フラグをクラスタ構造体が所有する。

pub mod access_control;
pub mod administrator_commissioning;
pub mod air_quality;
pub mod basic_information;
pub mod boolean_state;
pub(crate) mod cmd;
pub mod color_control;
pub mod concentration;
pub mod descriptor;
pub mod door_lock;
pub mod fan_control;
pub mod general_commissioning;
pub mod group_key_management;
pub mod groups;
pub mod identify;
pub mod level_control;
pub mod measurement;
pub mod network_commissioning;
pub mod occupancy_sensing;
pub mod on_off;
pub mod operational_credentials;
pub mod switch;
pub mod thermostat;
pub mod window_covering;

pub use access_control::AccessControlCluster;
pub use administrator_commissioning::{
    AdminCommissioningCluster, CommissioningWindow, WindowEvent,
};
pub use air_quality::{AirQualityCluster, AirQualityEnum};
pub use basic_information::{BasicInfoConfig, BasicInformationCluster};
pub use boolean_state::BooleanStateCluster;
pub use color_control::{ColorControlCluster, ColorState};
pub use concentration::{
    CarbonDioxideConcentrationCluster, ConcentrationUnit, NitrogenDioxideConcentrationCluster,
    Pm10ConcentrationCluster, Pm1ConcentrationCluster, Pm25ConcentrationCluster,
    TvocConcentrationCluster,
};
pub use descriptor::DescriptorCluster;
pub use door_lock::{DoorLockCluster, LockOperationEvent};
pub use fan_control::FanControlCluster;
pub use general_commissioning::{FailSafe, GeneralCommissioning};
pub use group_key_management::GroupKeyManagementCluster;
pub use groups::GroupsCluster;
pub use identify::IdentifyCluster;
pub use level_control::LevelControlCluster;
pub use measurement::{
    FlowMeasurementCluster, IlluminanceMeasurementCluster, PressureMeasurementCluster,
    RelativeHumidityMeasurementCluster, TemperatureMeasurementCluster,
};
pub use network_commissioning::{NetworkCommissioning, NetworkCommissioningWifi};
pub use occupancy_sensing::OccupancySensingCluster;
pub use on_off::OnOffCluster;
pub use operational_credentials::{DacProvider, OpCredsCluster, TestDacProvider};
pub use switch::{LatchingSwitchCluster, SwitchCluster, SwitchEvent};
pub use thermostat::ThermostatCluster;
pub use window_covering::WindowCoveringCluster;

#[cfg(all(test, feature = "rustcrypto"))]
mod commissioning_tests;
