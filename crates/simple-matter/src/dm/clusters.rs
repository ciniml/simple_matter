//! 具象クラスタ実装(`docs/design/interaction-model.md` §9)。
//!
//! いずれも [`crate::cluster!`] マクロを用いた combined 実装(logic/translation 分離なし)。
//! 属性ストレージと dirty フラグをクラスタ構造体が所有する。

pub mod basic_information;
pub(crate) mod cmd;
pub mod descriptor;
pub mod general_commissioning;
pub mod network_commissioning;
pub mod on_off;
pub mod operational_credentials;

pub use basic_information::{BasicInfoConfig, BasicInformationCluster};
pub use descriptor::DescriptorCluster;
pub use general_commissioning::{FailSafe, GeneralCommissioning};
pub use network_commissioning::NetworkCommissioning;
pub use on_off::OnOffCluster;
pub use operational_credentials::{DacProvider, OpCredsCluster, TestDacProvider};

#[cfg(all(test, feature = "rustcrypto"))]
mod commissioning_tests;
