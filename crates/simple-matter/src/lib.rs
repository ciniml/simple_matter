//! simple-matter: 小フットプリントな `no_std` の
//! Matter デバイス側(コントローリ/responder)プロトコル実装。
//! alloc は optional feature(定常データパスはヒープ確保しない)。
//!
//! レイヤ構成と設計原則は `docs/ARCHITECTURE.md` を参照。
//! 依存方向は下(error/tlv/crypto)→上(im/dm)の一方向のみとする。

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod error;
pub mod tlv;

pub use error::Error;
