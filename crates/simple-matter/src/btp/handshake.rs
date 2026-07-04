//! BTP handshake(Capabilities Request / Response)と、ワイヤ定数一式。
//!
//! `docs/design/ble-btp.md` §2.2 / §4.3 に基づく。両参照実装(chip `BleLayer.cpp` /
//! rs-matter `session.rs`)から裏取りした値に厳密準拠する。
//!
//! handshake フラグメントは magic(check bytes)`0x65 0x6C` で始まる 2 種の固定長構造:
//!
//! - **Request(central → C1 write, 9 バイト)**:
//!   `magic(2)` ‖ `versions(4, LE u32・4bit ニブル×8)` ‖ `mtu(2, LE)` ‖ `window(1)`。
//! - **Response(peripheral → C2 indicate, 6 バイト)**:
//!   `magic(2)` ‖ `version(1)=4` ‖ `fragment(2, LE)` ‖ `window(1)`。
//!
//! magic の 1 バイト目 `0x65` は BTP ヘッダとして見ると
//! `Handshake|Management|Ending|Beginning`、2 バイト目 `0x6C` は管理 opcode に一致する
//! (rs-matter はこの見方で符号化する)。本実装は magic を直接照合する。

use crate::error::{Error, Result};

/// handshake の magic(check bytes)= ASCII "el"。
pub const BTP_MAGIC: [u8; 2] = [0x65, 0x6C];

/// 実装する唯一の BTP プロトコルバージョン。
pub const BTP_VERSION: u8 = 4;

/// フラグメント payload の上限(chip `sMaxFragmentSize`)。
pub const BTP_MAX_FRAGMENT: usize = 244;

/// フラグメント payload の下限(clamp 用)。
pub const BTP_MIN_FRAGMENT: usize = 6;

/// ATT_MTU が不明なときの既定フラグメントサイズ。
pub const BTP_DEFAULT_FRAGMENT: usize = 20;

/// BTP が要求する ATT_MTU の下限。
pub const BTP_MIN_ATT_MTU: u16 = 23;

/// GATT ATT の 3 バイトヘッダ(フラグメント計算で控除)。
pub const GATT_ATT_HEADER: usize = 3;

/// window の上限(chip `BLE_MAX_RECEIVE_WINDOW_SIZE`)。
pub const BTP_MAX_WINDOW: u8 = 6;

/// handshake request の長さ(バイト)。
pub const BTP_HANDSHAKE_REQ_LEN: usize = 9;

/// handshake response の長さ(バイト)。
pub const BTP_HANDSHAKE_RESP_LEN: usize = 6;

/// 未 ACK 放置でセッションを切断する ACK タイムアウト(ミリ秒)。
pub const BTP_ACK_TIMEOUT_MS: u64 = 15_000;

/// handshake 完了待ちのタイムアウト(ミリ秒)。
pub const BTP_CONN_RSP_TIMEOUT_MS: u64 = 15_000;

/// 無通信での接続 idle タイムアウト(ミリ秒)。
pub const BTP_IDLE_TIMEOUT_MS: u64 = 30_000;

/// 即時でない standalone ACK の遅延送出時間(ミリ秒)。
pub const BTP_ACK_SEND_DELAY_MS: u64 = 2_500;

/// ATT_MTU からフラグメント payload サイズを算出する(§2.2)。
///
/// `clamp(max(mtu, 23) - 3, 6, 244)`。MTU 不明時は既定 20。
pub fn fragment_size(att_mtu: Option<u16>) -> usize {
    match att_mtu {
        None => BTP_DEFAULT_FRAGMENT,
        Some(mtu) => {
            let mtu = mtu.max(BTP_MIN_ATT_MTU) as usize;
            (mtu - GATT_ATT_HEADER).clamp(BTP_MIN_FRAGMENT, BTP_MAX_FRAGMENT)
        }
    }
}

/// Capabilities Request(central が C1 に write する 9 バイト)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeReq {
    /// サポートするバージョン群(4bit ニブル×8 を詰めた LE u32)。
    pub versions: u32,
    /// central の ATT_MTU(LE)。
    pub mtu: u16,
    /// central が提示する window(≤ 6)。
    pub window: u8,
}

impl HandshakeReq {
    /// V4 のみをサポートする Request を組む(第 1 ニブルに V4)。
    pub const fn v4(mtu: u16, window: u8) -> Self {
        Self {
            versions: BTP_VERSION as u32,
            mtu,
            window,
        }
    }

    /// バージョン群のいずれかのニブルが V4 なら `true`。
    pub fn supports_v4(&self) -> bool {
        (0..8).any(|i| ((self.versions >> (i * 4)) & 0x0F) as u8 == BTP_VERSION)
    }

    /// 9 バイトの Request を `out` に書き、長さを返す。
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let buf = out
            .get_mut(..BTP_HANDSHAKE_REQ_LEN)
            .ok_or(Error::NoSpace)?;
        buf[0..2].copy_from_slice(&BTP_MAGIC);
        buf[2..6].copy_from_slice(&self.versions.to_le_bytes());
        buf[6..8].copy_from_slice(&self.mtu.to_le_bytes());
        buf[8] = self.window;
        Ok(BTP_HANDSHAKE_REQ_LEN)
    }

    /// magic 付き 9 バイトから Request を読む。magic/長さ不正は [`Error::Decode`]。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let buf = data.get(..BTP_HANDSHAKE_REQ_LEN).ok_or(Error::Decode)?;
        if buf[0..2] != BTP_MAGIC {
            return Err(Error::Decode);
        }
        Ok(Self {
            versions: u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]),
            mtu: u16::from_le_bytes([buf[6], buf[7]]),
            window: buf[8],
        })
    }
}

/// Capabilities Response(peripheral が C2 に indicate する 6 バイト)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResp {
    /// 選択したプロトコルバージョン(= 4)。
    pub version: u8,
    /// 選択したフラグメント payload サイズ(LE)。
    pub fragment: u16,
    /// 選択した window(≤ min(req, 6))。
    pub window: u8,
}

impl HandshakeResp {
    /// 6 バイトの Response を `out` に書き、長さを返す。
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let buf = out
            .get_mut(..BTP_HANDSHAKE_RESP_LEN)
            .ok_or(Error::NoSpace)?;
        buf[0..2].copy_from_slice(&BTP_MAGIC);
        buf[2] = self.version;
        buf[3..5].copy_from_slice(&self.fragment.to_le_bytes());
        buf[5] = self.window;
        Ok(BTP_HANDSHAKE_RESP_LEN)
    }

    /// magic 付き 6 バイトから Response を読む。magic/長さ不正は [`Error::Decode`]。
    pub fn decode(data: &[u8]) -> Result<Self> {
        let buf = data.get(..BTP_HANDSHAKE_RESP_LEN).ok_or(Error::Decode)?;
        if buf[0..2] != BTP_MAGIC {
            return Err(Error::Decode);
        }
        Ok(Self {
            version: buf[2],
            fragment: u16::from_le_bytes([buf[3], buf[4]]),
            window: buf[5],
        })
    }
}

/// フラグメント先頭バイト列が handshake(magic 始まり)なら `true`。
pub fn is_handshake(frag: &[u8]) -> bool {
    frag.len() >= 2 && frag[0] == BTP_MAGIC[0] && frag[1] == BTP_MAGIC[1]
}
