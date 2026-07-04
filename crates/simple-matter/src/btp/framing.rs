//! BTP フレーミング:1 フラグメントの BTP ヘッダ([`BtpHeader`])の parse / encode。
//!
//! `docs/design/ble-btp.md` §2.3 に基づく。データ/ACK フラグメントのヘッダは
//!
//! ```text
//! [flags(1)] [ack(1, ACK ビット時のみ)] [seq(1)] [msglen(2, LE, Beginning 時のみ)] [payload]
//! ```
//!
//! の並び。handshake フラグメント(magic `0x65 0x6C` 始まり)は本モジュールでは扱わず、
//! [`handshake`](super::handshake) が専用に parse / encode する。フラグ値は chip
//! (`BtpEngine.h`)/ rs-matter(`packet.rs`)とワイヤ上一致する。
//!
//! `bitflags` クレートは使わず、`u8` を包む小さな値型([`HeaderFlags`])で手実装する
//! (依存追加を避ける、既存 `SecFlags` / `ExchFlags` と同じ流儀)。

use crate::error::{Error, Result};

/// BTP ヘッダのフラグビット(`u8`)。
///
/// | ビット | 名称 | 意味 |
/// |---|---|---|
/// | `0x01` | Beginning | メッセージ先頭フラグメント(この時のみ msglen を含む) |
/// | `0x02` | Continuing | 継続フラグメント |
/// | `0x04` | Ending | 最終フラグメント(単一なら Beginning と同時) |
/// | `0x08` | Ack | ack バイトを含む(piggyback / standalone) |
/// | `0x20` | Management | 管理フレーム(handshake で使用) |
/// | `0x40` | Handshake | Capabilities handshake フラグメント |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeaderFlags(u8);

impl HeaderFlags {
    /// メッセージ先頭フラグメント。
    pub const BEGINNING: u8 = 0x01;
    /// 継続フラグメント。
    pub const CONTINUING: u8 = 0x02;
    /// 最終フラグメント。
    pub const ENDING: u8 = 0x04;
    /// ack バイトを含む。
    pub const ACK: u8 = 0x08;
    /// 管理フレーム。
    pub const MANAGEMENT: u8 = 0x20;
    /// handshake フラグメント。
    pub const HANDSHAKE: u8 = 0x40;

    /// 空(全ビット 0)。
    pub const fn empty() -> Self {
        Self(0)
    }

    /// 生の `u8` から生成する。
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// 生の `u8` を返す。
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// 指定ビットを立てる。
    pub fn insert(&mut self, bit: u8) {
        self.0 |= bit;
    }

    /// 指定ビットが立っていれば `true`。
    pub const fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// データ(セグメント)フラグメントなら `true`(Beginning / Continuing / Ending のいずれか)。
    pub const fn has_data(self) -> bool {
        self.0 & (Self::BEGINNING | Self::CONTINUING | Self::ENDING) != 0
    }
}

/// 1 BTP フラグメントのヘッダ(データ / ACK 用)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtpHeader {
    /// フラグビット。
    pub flags: HeaderFlags,
    /// ACK 対象の受信 seq(ACK ビット時のみ)。
    pub ack: Option<u8>,
    /// このフラグメントの送信 seq。
    pub seq: u8,
    /// メッセージ全長(Beginning 時のみ、2 バイト LE)。
    pub msg_len: Option<u16>,
}

impl BtpHeader {
    /// ヘッダ最大長(flags + ack + seq + msglen)。
    pub const MAX_LEN: usize = 5;

    /// ヘッダを `out` の先頭に書き、書いた長さを返す。
    ///
    /// `ack` / `msg_len` が `Some` かどうかで対応するフラグを立て、そのバイトを含める。
    /// `out` が短ければ [`Error::NoSpace`]。
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut flags = self.flags;
        if self.ack.is_some() {
            flags.insert(HeaderFlags::ACK);
        }
        if self.msg_len.is_some() {
            flags.insert(HeaderFlags::BEGINNING);
        }

        let mut n = 0;
        let mut put = |b: u8, out: &mut [u8]| -> Result<()> {
            *out.get_mut(n).ok_or(Error::NoSpace)? = b;
            n += 1;
            Ok(())
        };
        put(flags.bits(), out)?;
        if let Some(a) = self.ack {
            put(a, out)?;
        }
        put(self.seq, out)?;
        if let Some(len) = self.msg_len {
            let le = len.to_le_bytes();
            put(le[0], out)?;
            put(le[1], out)?;
        }
        Ok(n)
    }

    /// `data` の先頭からデータ / ACK フラグメントのヘッダを読み、`(header, header_len)` を返す。
    ///
    /// ヘッダの直後(`data[header_len..]`)が payload。handshake フラグメント(Handshake
    /// ビット)はここでは扱わず [`Error::InvalidState`]。切り詰めは [`Error::Decode`]。
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        let mut n = 0;
        let mut take = |data: &[u8]| -> Result<u8> {
            let b = *data.get(n).ok_or(Error::Decode)?;
            n += 1;
            Ok(b)
        };
        let flags = HeaderFlags::from_bits(take(data)?);
        // handshake は magic 判定で別経路に振り分ける前提。ここに来たら不正。
        if flags.contains(HeaderFlags::HANDSHAKE) {
            return Err(Error::InvalidState);
        }
        // データ経路では管理 opcode は使わない(standalone ack / データのみ)。
        if flags.contains(HeaderFlags::MANAGEMENT) {
            return Err(Error::InvalidState);
        }
        let ack = if flags.contains(HeaderFlags::ACK) {
            Some(take(data)?)
        } else {
            None
        };
        // データ経路は常に seq を持つ。
        let seq = take(data)?;
        let msg_len = if flags.contains(HeaderFlags::BEGINNING) {
            let lo = take(data)?;
            let hi = take(data)?;
            Some(u16::from_le_bytes([lo, hi]))
        } else {
            None
        };
        Ok((
            Self {
                flags,
                ack,
                seq,
                msg_len,
            },
            n,
        ))
    }
}
