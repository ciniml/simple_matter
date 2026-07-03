//! 具象クラスタ実装(`docs/design/interaction-model.md` §9)。
//!
//! いずれも [`crate::cluster!`] マクロを用いた combined 実装(logic/translation 分離なし)。
//! 属性ストレージと dirty フラグをクラスタ構造体が所有する。

pub mod basic_information;
pub mod descriptor;
pub mod on_off;

pub use basic_information::{BasicInfoConfig, BasicInformationCluster};
pub use descriptor::DescriptorCluster;
pub use on_off::OnOffCluster;
