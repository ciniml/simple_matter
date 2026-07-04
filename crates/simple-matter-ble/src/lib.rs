//! PC 向け BLE バックエンド:コア `simple-matter` の BTP 抽象 trait
//! ([`GattPeripheral`](simple_matter::btp::gatt::GattPeripheral) /
//! [`GattCentral`](simple_matter::btp::gatt::GattCentral))を、Linux の実 BLE スタックで
//! 実装する std クレート(`docs/design/ble-btp.md` §6 / フェーズ P4)。
//!
//! - `device` feature: [`bluer_peripheral::BluerPeripheral`]。BlueZ(bluer)で GATT
//!   **peripheral**(0xFFF6 広告 + C1 write / C2 indicate)を提供する。Linux 専用。
//! - `commissioner` feature: [`btleplug_central::BtleplugCentral`]。btleplug で GATT
//!   **central**(scan + connect + C1 write + C2 subscribe/indication 受信)を提供する。
//!
//! btleplug は central ロール専用のため、device 側 peripheral には使えない。よって
//! **device=bluer / commissioner=btleplug** の分担にする(設計 doc §6.1)。コア
//! (`simple-matter`)は executor 非依存だが、bluer / btleplug は tokio 前提のため
//! **このクレート内でのみ** tokio を使う。BTP 状態機械・handshake・window は無改造で
//! 共有され、ESP32 移植時はこの 2 trait を NimBLE 等で実装するだけでよい。

#[cfg(all(feature = "device", target_os = "linux"))]
pub mod bluer_peripheral;

#[cfg(feature = "commissioner")]
pub mod btleplug_central;

/// Matter BLE Service / C1 / C2 の 128bit UUID(コアの大端 16 バイト定数)を `u128` に組む。
/// バックエンドの UUID 型構築に使う。
#[cfg(any(all(feature = "device", target_os = "linux"), feature = "commissioner"))]
pub(crate) fn uuid_u128(bytes: &[u8; 16]) -> u128 {
    u128::from_be_bytes(*bytes)
}
