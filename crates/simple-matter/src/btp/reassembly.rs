//! RX 再組立([`Reassembler`])と TX セグメント化([`Segmenter`])。
//!
//! `docs/design/ble-btp.md` §4.4 に基づき、いずれも固定配列でヒープレス。RX は 1 Matter
//! メッセージ分(`MAX_RX_PACKET_SIZE` = 1583)、TX SDU は 1 本(`MAX_TX_PACKET_SIZE` = 1232)。
//!
//! - [`Reassembler`]: Beginning → Continuing → Ending の順で payload を貯め、Beginning の
//!   msglen(2 バイト LE)で全長を検証する。溢れ / 長さ不一致は [`Error`] で打ち切る。
//! - [`Segmenter`]: 1 SDU を、呼び出し側が指定する payload 上限で「先頭 / 継続 / 最終」
//!   セグメントへ切り出す。

use crate::error::{Error, Result};
use crate::transport::net::{MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE};

use super::framing::HeaderFlags;

/// RX 再組立バッファ(1 Matter メッセージ分)。
#[derive(Debug)]
pub struct Reassembler {
    buf: [u8; MAX_RX_PACKET_SIZE],
    /// Beginning で得た全長。
    expected: usize,
    /// これまでに貯めたバイト数。
    filled: usize,
    /// 組み立て途中(Beginning 済み・Ending 未)なら `true`。
    in_progress: bool,
    /// 1 メッセージが完成し未取り出しなら `true`。
    complete: bool,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// 空の再組立バッファを生成する。
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_RX_PACKET_SIZE],
            expected: 0,
            filled: 0,
            in_progress: false,
            complete: false,
        }
    }

    /// 1 メッセージが完成し未取り出しなら `true`。
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// 1 データフラグメントを投入する。
    ///
    /// - Beginning は `msg_len` 必須で全長を確定し、途中状態をリセットする。
    /// - 非 Beginning は組み立て中でなければ [`Error::InvalidState`]。
    /// - payload 累積が全長を超えたら [`Error::Decode`](溢れ打ち切り)。
    /// - Ending で `filled != expected` なら [`Error::Decode`](msglen 検証失敗)。
    /// - 全長が RX バッファを超えたら [`Error::NoSpace`]。
    pub fn push(&mut self, flags: HeaderFlags, msg_len: Option<u16>, payload: &[u8]) -> Result<()> {
        let beginning = flags.contains(HeaderFlags::BEGINNING);
        let ending = flags.contains(HeaderFlags::ENDING);

        if beginning {
            let total = msg_len.ok_or(Error::Decode)? as usize;
            if total > MAX_RX_PACKET_SIZE {
                return Err(Error::NoSpace);
            }
            self.expected = total;
            self.filled = 0;
            self.in_progress = true;
            self.complete = false;
        } else {
            if !self.in_progress {
                return Err(Error::InvalidState);
            }
            if msg_len.is_some() {
                // 非 Beginning は msglen を持たない(フラグと不整合)。
                return Err(Error::Decode);
            }
        }

        let end = self
            .filled
            .checked_add(payload.len())
            .ok_or(Error::Decode)?;
        if end > self.expected {
            return Err(Error::Decode);
        }
        self.buf[self.filled..end].copy_from_slice(payload);
        self.filled = end;

        if ending {
            if self.filled != self.expected {
                return Err(Error::Decode);
            }
            self.in_progress = false;
            self.complete = true;
        }
        Ok(())
    }

    /// 完成した 1 メッセージを取り出し、`complete` を落とす。未完成なら `None`。
    pub fn take(&mut self) -> Option<&[u8]> {
        if !self.complete {
            return None;
        }
        self.complete = false;
        Some(&self.buf[..self.expected])
    }

    /// 状態を初期化する(切断時など)。
    pub fn reset(&mut self) {
        self.expected = 0;
        self.filled = 0;
        self.in_progress = false;
        self.complete = false;
    }
}

/// TX セグメント化バッファ(送信待ちの 1 SDU)。
#[derive(Debug)]
pub struct Segmenter {
    buf: [u8; MAX_TX_PACKET_SIZE],
    len: usize,
    /// 送出済みバイト数。
    offset: usize,
    /// 送出待ちの SDU を保持中なら `true`。
    active: bool,
}

impl Default for Segmenter {
    fn default() -> Self {
        Self::new()
    }
}

impl Segmenter {
    /// 空のセグメント化バッファを生成する。
    pub const fn new() -> Self {
        Self {
            buf: [0u8; MAX_TX_PACKET_SIZE],
            len: 0,
            offset: 0,
            active: false,
        }
    }

    /// 送出待ちの SDU があれば `true`。
    pub const fn is_pending(&self) -> bool {
        self.active
    }

    /// まだ先頭セグメント(未送出)なら `true`。
    pub const fn at_beginning(&self) -> bool {
        self.offset == 0
    }

    /// SDU 全長。
    pub const fn total_len(&self) -> usize {
        self.len
    }

    /// 1 SDU を積む。保持中なら [`Error::InvalidState`]、長すぎれば [`Error::NoSpace`]。
    pub fn load(&mut self, sdu: &[u8]) -> Result<()> {
        if self.active {
            return Err(Error::InvalidState);
        }
        if sdu.len() > MAX_TX_PACKET_SIZE {
            return Err(Error::NoSpace);
        }
        self.buf[..sdu.len()].copy_from_slice(sdu);
        self.len = sdu.len();
        self.offset = 0;
        self.active = true;
        Ok(())
    }

    /// 次のセグメント payload(最大 `max` バイト)を `dst` に切り出す。
    ///
    /// `(is_beginning, is_ending, n)` を返す。全部送り切ると保持を解放する。
    /// `dst` は `max` バイト以上であること。`max` が 0 の場合も 1 バイトは進める
    /// (前進保証)。
    pub fn take_chunk(&mut self, max: usize, dst: &mut [u8]) -> (bool, bool, usize) {
        let beginning = self.offset == 0;
        let remaining = self.len - self.offset;
        let take = remaining.min(max.max(1)).min(dst.len());
        dst[..take].copy_from_slice(&self.buf[self.offset..self.offset + take]);
        self.offset += take;
        let ending = self.offset >= self.len;
        if ending {
            self.active = false;
        }
        (beginning, ending, take)
    }

    /// 状態を初期化する(切断時など)。
    pub fn reset(&mut self) {
        self.len = 0;
        self.offset = 0;
        self.active = false;
    }
}
