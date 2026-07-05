//! simple-matter: 小フットプリントな `no_std` の
//! Matter デバイス側(コントローリ/responder)プロトコル実装。
//! alloc は optional feature(定常データパスはヒープ確保しない)。
//!
//! レイヤ構成と設計原則は `docs/ARCHITECTURE.md` を参照。
//! 依存方向は下(error/tlv/crypto)→上(im/dm)の一方向のみとする。

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

/// BTP(Bluetooth Transport Protocol)コア。`ble` feature 有効時のみ。
///
/// `docs/design/ble-btp.md` §4。sans-IO no_std の BLE トランスポート状態機械で、
/// BLE 無効ビルドには一切コンパイルされない(フットプリント不変、設計 §7)。
#[cfg(feature = "ble")]
pub mod btp;
pub mod buf;
pub mod cert;
/// コントローラ(commissioner)側の統合層。`controller` + `rustcrypto` feature 有効時のみ。
///
/// `docs/design/controller.md` ピース D。デバイス(responder)専用ビルドには一切
/// コンパイルされない(フットプリント不変、設計 §2.3)。
#[cfg(all(feature = "controller", feature = "rustcrypto"))]
pub mod controller;
pub mod crypto;
pub mod discovery;
pub mod dm;
pub mod error;
pub mod exchange;
pub mod fabric;
pub mod im;
pub mod kvs;
pub mod sc;
#[cfg(feature = "rustcrypto")]
pub mod stack;
pub mod tlv;
pub mod transport;

pub use error::Error;
