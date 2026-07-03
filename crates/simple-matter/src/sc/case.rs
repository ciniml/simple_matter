//! CASE responder(Sigma1/2/3)。
//!
//! `docs/design/secure-channel.md` §7/§8 に基づく。
//!
//! - [`creds`] — 第4段階 fabric/credentials との **trait 境界**([`FabricStore`] /
//!   [`Fabric`] / [`NocResolver`])と、PASE 単独運用向けの空実装 [`creds::NoFabrics`]。
//!   暗号 backend に依存せず `--no-default-features` でも常時コンパイルされる。
//! - [`responder`] — CASE のプロトコルプリミティブ(Sigma1/2/3 の TLV codec と
//!   S2K/S3K/SEKeys 導出・TBE 暗号化/復号・TBS 組み立て)。往復をまたぐ Mealy 状態機械
//!   本体は [`crate::sc::SecureChannel`] に統合される(設計「SecureChannel ハンドラに統合」)。
//!   crypto を要するため `rustcrypto` feature でのみ有効。
//!
//! [`FabricStore`]: creds::FabricStore
//! [`Fabric`]: creds::Fabric
//! [`NocResolver`]: creds::NocResolver

pub mod creds;

#[cfg(feature = "rustcrypto")]
pub mod responder;
