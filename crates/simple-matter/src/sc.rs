//! sc 層(Secure Channel): Protocol ID 0x0000 の [`ProtocolHandler`] 実装。
//!
//! `docs/design/secure-channel.md` に基づく。本ピースは第3段階の中核である
//! **PASE responder**(デバイス側)を実装する。CASE・fabric/credentials・mDNS は
//! 本ピースのスコープ外(§7/§8 の trait 境界は CASE 追加時に導入する)。
//!
//! # 構成
//!
//! - [`status`] — StatusReport(終端語彙)。暗号非依存で常時コンパイル。
//! - [`OpCode`] — Secure Channel メッセージ種別。常時コンパイル。
//! - [`SecureChannel`] — 同期 Mealy 状態機械。1 メッセージ = 1 回の [`ProtocolHandler::handle`]
//!   呼び出しで、往復のまたぎは [`handshake::HandshakePool`] の slot に外出しする(§4)。
//!   crypto に依存するため `rustcrypto` feature でのみ有効。
//!
//! # exchange 層との接続(§4.3)
//!
//! ハンドラは応答 payload を `tx` に書き [`HandlerAction`] で宣言する。実送信は
//! [`ExchangeManager`](crate::exchange::ExchangeManager) の送信 API が行う。ハンドラは
//! `reserve`/`commit`(§6.5)のため [`SessionManager`] を受け取る。

pub mod status;

/// CASE responder と、第4段階 fabric/credentials との trait 境界(§8)。
///
/// 本ピースでは CASE state machine 本体は未実装で、[`case::creds`] の trait 境界のみを
/// 提供する。trait 定義は暗号 backend に依存しないため常時コンパイルされる。
pub mod case;

pub use status::{GeneralCode, ScStatusCode, StatusReport, PROTO_ID_SECURE_CHANNEL};

use crate::error::{Error, Result};

/// Secure Channel メッセージ種別(opcode)。仕様固定値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// メッセージカウンタ同期要求(group 用。初期スコープ外)。
    MsgCounterSyncReq = 0x00,
    /// メッセージカウンタ同期応答(group 用。初期スコープ外)。
    MsgCounterSyncResp = 0x01,
    /// MRP standalone ACK(exchange 層が生成・消費する)。
    MrpStandaloneAck = 0x10,
    /// PBKDFParamRequest(PASE responder 入口)。
    PbkdfParamRequest = 0x20,
    /// PBKDFParamResponse。
    PbkdfParamResponse = 0x21,
    /// PASEPake1(pA)。
    PasePake1 = 0x22,
    /// PASEPake2(pB, cB)。
    PasePake2 = 0x23,
    /// PASEPake3(cA)。
    PasePake3 = 0x24,
    /// CASE Sigma1(CASE responder 入口。初期スコープ外)。
    CaseSigma1 = 0x30,
    /// CASE Sigma2(初期スコープ外)。
    CaseSigma2 = 0x31,
    /// CASE Sigma3(初期スコープ外)。
    CaseSigma3 = 0x32,
    /// CASE Sigma2Resume(resumption。初期スコープ外)。
    CaseSigma2Resume = 0x33,
    /// StatusReport(終端語彙)。
    StatusReport = 0x40,
}

impl OpCode {
    /// 受信 opcode を判別する。未知は [`Error::Decode`]。
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x00 => Self::MsgCounterSyncReq,
            0x01 => Self::MsgCounterSyncResp,
            0x10 => Self::MrpStandaloneAck,
            0x20 => Self::PbkdfParamRequest,
            0x21 => Self::PbkdfParamResponse,
            0x22 => Self::PasePake1,
            0x23 => Self::PasePake2,
            0x24 => Self::PasePake3,
            0x30 => Self::CaseSigma1,
            0x31 => Self::CaseSigma2,
            0x32 => Self::CaseSigma3,
            0x33 => Self::CaseSigma2Resume,
            0x40 => Self::StatusReport,
            _ => return Err(Error::Decode),
        })
    }

    /// TLV ペイロードを持つか(StatusReport / StandaloneAck / MsgCounterSync は非 TLV)。
    pub const fn is_tlv(&self) -> bool {
        !matches!(
            self,
            Self::MrpStandaloneAck
                | Self::StatusReport
                | Self::MsgCounterSyncReq
                | Self::MsgCounterSyncResp
        )
    }

    /// このメッセージは信頼送信(R フラグ)か。StandaloneAck のみ false。
    pub const fn reliable(&self) -> bool {
        !matches!(self, Self::MrpStandaloneAck)
    }
}

#[cfg(feature = "rustcrypto")]
mod responder;

#[cfg(feature = "rustcrypto")]
pub mod handshake;

#[cfg(feature = "rustcrypto")]
pub mod pase;

#[cfg(feature = "rustcrypto")]
pub use responder::{PaseConfig, SecureChannel};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip_and_props() {
        assert_eq!(OpCode::from_u8(0x20).unwrap(), OpCode::PbkdfParamRequest);
        assert_eq!(OpCode::from_u8(0x40).unwrap(), OpCode::StatusReport);
        assert_eq!(OpCode::from_u8(0x99), Err(Error::Decode));

        assert!(OpCode::PbkdfParamRequest.is_tlv());
        assert!(!OpCode::StatusReport.is_tlv());
        assert!(!OpCode::MrpStandaloneAck.is_tlv());

        assert!(OpCode::PbkdfParamResponse.reliable());
        assert!(!OpCode::MrpStandaloneAck.reliable());
    }
}
