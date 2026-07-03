//! CASE responder(Sigma1/2/3)。
//!
//! `docs/design/secure-channel.md` §7/§8 に基づく。本ピース(第4段階)では CASE の
//! state machine 本体は **未実装**であり、ここでは第4段階 fabric/credentials との
//! **trait 境界**([`creds`])のみを提供する。CASE state machine は次タスクで
//! [`creds`] の 3 つの trait だけに依存する形で追加する(依存性逆転)。
//!
//! # 配置についての判断
//!
//! 設計 §8 は「trait を `sc/case/creds.rs` に定義し、`fabric` モジュールが実装する」
//! ことを求める。CASE 本体が未実装の現状でも、この trait 境界だけは先に確定させて
//! おくことで、第4段階の [`crate::fabric`] は最終的な CASE の依存面(fabric の
//! 読み取りビュー)に向けて実装できる。trait 定義は暗号 backend に依存しないため
//! `--no-default-features` でも常時コンパイルされる(CASE state machine 本体は
//! crypto を要するため、追加時に `rustcrypto` feature で gate する)。

pub mod creds;
