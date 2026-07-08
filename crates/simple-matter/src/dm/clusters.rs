//! 具象クラスタ実装(`docs/design/interaction-model.md` §9)。
//!
//! いずれも [`crate::cluster!`] マクロを用いた combined 実装(logic/translation 分離なし)。
//! 属性ストレージと dirty フラグをクラスタ構造体が所有する。

pub mod access_control;
pub mod administrator_commissioning;
pub mod basic_information;
pub(crate) mod cmd;
pub mod descriptor;
pub mod general_commissioning;
pub mod level_control;
pub mod network_commissioning;
pub mod on_off;
pub mod operational_credentials;
pub mod thermostat;

pub use access_control::AccessControlCluster;
pub use administrator_commissioning::{
    AdminCommissioningCluster, CommissioningWindow, WindowEvent,
};
pub use basic_information::{BasicInfoConfig, BasicInformationCluster};
pub use descriptor::DescriptorCluster;
pub use general_commissioning::{FailSafe, GeneralCommissioning};
pub use level_control::LevelControlCluster;
pub use network_commissioning::{NetworkCommissioning, NetworkCommissioningWifi};
pub use on_off::OnOffCluster;
pub use operational_credentials::{DacProvider, OpCredsCluster, TestDacProvider};
pub use thermostat::ThermostatCluster;

#[cfg(all(test, feature = "rustcrypto"))]
mod commissioning_tests;
