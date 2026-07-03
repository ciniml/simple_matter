//! Secure Channel の StatusReport(終端語彙)。
//!
//! `docs/design/secure-channel.md` §3 に基づく。Matter 仕様 "Appendix D: Status Report
//! Messages" の **非 TLV** 固定バイト列を扱う。成功・失敗・Busy などハンドシェイクの
//! すべての終端はこの 1 種のフレームで表現する。
//!
//! バイトレイアウト(すべてリトルエンディアン):
//!
//! ```text
//! | GeneralCode : u16 | ProtocolId : u32 | ProtocolCode : u16 | ProtocolData : [u8] |
//! ```
//!
//! 暗号/依存に触れないため常時コンパイルできる。

use crate::error::{Error, Result};

/// Secure Channel の Protocol ID(StatusReport の `proto_id` はこれ)。
pub const PROTO_ID_SECURE_CHANNEL: u16 = 0x0000;

/// StatusReport 汎用コード(Matter 仕様 Appendix D。抜粋)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum GeneralCode {
    /// 成功。
    Success = 0,
    /// 一般的な失敗。
    Failure = 1,
    /// 事前条件不成立。
    BadPrecondition = 2,
    /// 範囲外。
    OutOfRange = 3,
    /// 不正な要求。
    BadRequest = 4,
    /// 未対応。
    Unsupported = 5,
    /// 予期しない状態。
    Unexpected = 6,
    /// リソース枯渇。
    ResourceExhausted = 7,
    /// ビジー(後で再試行)。
    Busy = 8,
    /// タイムアウト。
    Timeout = 9,
    /// 継続。
    Continue = 10,
    /// 中断。
    Aborted = 11,
    /// 不正な引数。
    InvalidArgument = 12,
    /// 見つからない。
    NotFound = 13,
    /// 既に存在する。
    AlreadyExists = 14,
    /// 権限拒否。
    PermissionDenied = 15,
    /// データ損失。
    DataLoss = 16,
}

impl GeneralCode {
    /// ワイヤ値(u16)から [`GeneralCode`] を復元する。未知値は [`Error::Decode`]。
    pub fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            0 => Self::Success,
            1 => Self::Failure,
            2 => Self::BadPrecondition,
            3 => Self::OutOfRange,
            4 => Self::BadRequest,
            5 => Self::Unsupported,
            6 => Self::Unexpected,
            7 => Self::ResourceExhausted,
            8 => Self::Busy,
            9 => Self::Timeout,
            10 => Self::Continue,
            11 => Self::Aborted,
            12 => Self::InvalidArgument,
            13 => Self::NotFound,
            14 => Self::AlreadyExists,
            15 => Self::PermissionDenied,
            16 => Self::DataLoss,
            _ => return Err(Error::Decode),
        })
    }
}

/// Secure Channel プロトコルコード(chip `Constants.h` / rs-matter `SCStatusCodes` と一致)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ScStatusCode {
    /// セッション確立成功(PASE Pake3 / CASE Sigma3 検証成功)。
    SessionEstablishmentSuccess = 0x0000,
    /// 共有信頼根なし(CASE: destination-id 不一致)。
    NoSharedTrustRoots = 0x0001,
    /// パラメータ不正。
    InvalidParameter = 0x0002,
    /// 明示的セッション終了。
    CloseSession = 0x0003,
    /// ビジー(同時ハンドシェイク上限超過)。
    Busy = 0x0004,
    /// 進行中セッション不明。
    SessionNotFound = 0x0005,
}

impl ScStatusCode {
    /// ワイヤ値(u16)から [`ScStatusCode`] を復元する。未知値は [`Error::Decode`]。
    pub fn from_u16(v: u16) -> Result<Self> {
        Ok(match v {
            0x0000 => Self::SessionEstablishmentSuccess,
            0x0001 => Self::NoSharedTrustRoots,
            0x0002 => Self::InvalidParameter,
            0x0003 => Self::CloseSession,
            0x0004 => Self::Busy,
            0x0005 => Self::SessionNotFound,
            _ => return Err(Error::Decode),
        })
    }

    /// このコードに対応する [`GeneralCode`](secure-channel §3.3 のマップ)。
    pub const fn general_code(self) -> GeneralCode {
        match self {
            Self::SessionEstablishmentSuccess | Self::CloseSession => GeneralCode::Success,
            Self::Busy => GeneralCode::Busy,
            Self::InvalidParameter | Self::NoSharedTrustRoots | Self::SessionNotFound => {
                GeneralCode::Failure
            }
        }
    }

    /// 信頼送達(R フラグ)で送るべきか。
    ///
    /// `CloseSession` / `Busy` / `SessionNotFound` は「会話を続けない」通知のため
    /// R フラグを落とす(ACK 往復不要、§3.3)。
    pub const fn reliable(self) -> bool {
        !matches!(
            self,
            Self::CloseSession | Self::Busy | Self::SessionNotFound
        )
    }
}

/// StatusReport メッセージ(non-TLV 固定バイト列)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport<'a> {
    /// 汎用コード。
    pub general_code: GeneralCode,
    /// Protocol ID(SC 終端では [`PROTO_ID_SECURE_CHANNEL`] = 0)。
    pub proto_id: u32,
    /// プロトコルコード([`ScStatusCode`] のワイヤ値)。
    pub proto_code: u16,
    /// 追加データ(Busy では retry-delay の u16 LE 等)。
    pub proto_data: &'a [u8],
}

impl<'a> StatusReport<'a> {
    /// [`ScStatusCode`] と追加データから StatusReport を構成する。
    ///
    /// `general_code` と `proto_id` は [`ScStatusCode`] から一意に定まる。
    pub fn new(code: ScStatusCode, proto_data: &'a [u8]) -> Self {
        Self {
            general_code: code.general_code(),
            proto_id: PROTO_ID_SECURE_CHANNEL as u32,
            proto_code: code as u16,
            proto_data,
        }
    }

    /// バイト列を StatusReport としてデコードする(`le_u16, le_u32, le_u16, rest`)。
    ///
    /// 長さ不足・未知 GeneralCode は [`Error::Decode`]。
    pub fn decode(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(Error::Decode);
        }
        let general_code = GeneralCode::from_u16(u16::from_le_bytes([buf[0], buf[1]]))?;
        let proto_id = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let proto_code = u16::from_le_bytes([buf[6], buf[7]]);
        Ok(Self {
            general_code,
            proto_id,
            proto_code,
            proto_data: &buf[8..],
        })
    }

    /// StatusReport を `out` の先頭へエンコードし、書き込んだバイト長を返す。
    ///
    /// 空きが `8 + proto_data.len()` バイト未満なら [`Error::NoSpace`]。
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let total = 8 + self.proto_data.len();
        if out.len() < total {
            return Err(Error::NoSpace);
        }
        out[0..2].copy_from_slice(&(self.general_code as u16).to_le_bytes());
        out[2..6].copy_from_slice(&self.proto_id.to_le_bytes());
        out[6..8].copy_from_slice(&self.proto_code.to_le_bytes());
        out[8..total].copy_from_slice(self.proto_data);
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_round_trip() {
        let sr = StatusReport::new(ScStatusCode::SessionEstablishmentSuccess, &[]);
        assert_eq!(sr.general_code, GeneralCode::Success);
        assert_eq!(sr.proto_id, 0);
        assert_eq!(sr.proto_code, 0);

        let mut out = [0u8; 16];
        let n = sr.encode(&mut out).unwrap();
        assert_eq!(n, 8);
        // GeneralCode=0, proto_id=0, proto_code=0。
        assert_eq!(&out[..8], &[0, 0, 0, 0, 0, 0, 0, 0]);

        let dec = StatusReport::decode(&out[..n]).unwrap();
        assert_eq!(dec, sr);
    }

    #[test]
    fn busy_carries_retry_delay() {
        let delay = 500u16.to_le_bytes();
        let sr = StatusReport::new(ScStatusCode::Busy, &delay);
        assert_eq!(sr.general_code, GeneralCode::Busy);
        assert_eq!(sr.proto_code, 0x0004);

        let mut out = [0u8; 16];
        let n = sr.encode(&mut out).unwrap();
        assert_eq!(n, 10);
        let dec = StatusReport::decode(&out[..n]).unwrap();
        assert_eq!(dec.general_code, GeneralCode::Busy);
        assert_eq!(dec.proto_code, 0x0004);
        assert_eq!(dec.proto_data, &delay);
    }

    #[test]
    fn invalid_parameter_maps_to_failure() {
        let sr = StatusReport::new(ScStatusCode::InvalidParameter, &[]);
        assert_eq!(sr.general_code, GeneralCode::Failure);
        assert_eq!(sr.proto_code, 0x0002);
        // 失敗系だが R フラグは立てる。
        assert!(ScStatusCode::InvalidParameter.reliable());
        // Busy / CloseSession / SessionNotFound は R フラグを落とす。
        assert!(!ScStatusCode::Busy.reliable());
        assert!(!ScStatusCode::CloseSession.reliable());
        assert!(!ScStatusCode::SessionNotFound.reliable());
        assert!(ScStatusCode::SessionEstablishmentSuccess.reliable());
    }

    #[test]
    fn decode_rejects_short_and_unknown() {
        assert_eq!(StatusReport::decode(&[0, 0, 0]), Err(Error::Decode));
        // GeneralCode=0x00FF は未知。
        let bad = [0xff, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(StatusReport::decode(&bad), Err(Error::Decode));
    }

    #[test]
    fn code_round_trip_via_u16() {
        for code in [
            ScStatusCode::SessionEstablishmentSuccess,
            ScStatusCode::NoSharedTrustRoots,
            ScStatusCode::InvalidParameter,
            ScStatusCode::CloseSession,
            ScStatusCode::Busy,
            ScStatusCode::SessionNotFound,
        ] {
            assert_eq!(ScStatusCode::from_u16(code as u16).unwrap(), code);
        }
        assert_eq!(ScStatusCode::from_u16(0x1234), Err(Error::Decode));
    }
}
