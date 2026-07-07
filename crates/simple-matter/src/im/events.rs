//! イベントログ(リングバッファ、`docs/design/interaction-model.md` §12 イベント最小実装)。
//!
//! Matter のイベント([Core Spec §8.4]/§10.6.9 EventDataIB)を保持する固定容量リング。
//! [`InteractionModel`](crate::im::engine::InteractionModel) が所有し、ReadRequest の
//! EventPaths に対して EventReportIB を返す元データになる。壁時計を持たないデバイス前提で
//! **SystemTimestamp**(起動からの単調増加ミリ秒)を採用する。
//!
//! # 割り切り(最小実装)
//!
//! - **永続化なし**: `event_number` は起動でリセットされる(仕様は永続カウンタだが、chip-tool の
//!   単発 read には実害なし)。
//! - **priority 別バッファなし**: 単一リングで priority を要素フィールドとして持つのみ。満杯時は
//!   priority に関わらず最古を追い出す。
//! - **payload 固定長**: 1 イベントのデータ TLV は [`EVENT_PAYLOAD_MAX`] バイトに収める
//!   (StartUp の `{ softwareVersion: u32 }` には十分)。

use crate::dm::meta::{ClusterId, EndpointId, EventId};
use crate::error::Result;
use crate::tlv::{TlvTag, TlvWriter};

/// 1 イベントのデータ TLV(EventDataIB.Data の値要素)を収める固定バッファ長。
pub const EVENT_PAYLOAD_MAX: usize = 32;

/// PriorityLevel::DEBUG(Matter Core Spec §8.4.1)。
pub const PRIORITY_DEBUG: u8 = 0;
/// PriorityLevel::INFO。
pub const PRIORITY_INFO: u8 = 1;
/// PriorityLevel::CRITICAL。
pub const PRIORITY_CRITICAL: u8 = 2;

/// リングに保持する 1 イベント。
///
/// `payload` は EventDataIB.Data(タグ 7)の**値要素**を anonymous タグで書いた生 TLV。
/// レポート時に [`transcribe`](crate::im::wire::transcribe) で context タグ 7 へ移し替える。
#[derive(Debug, Clone, Copy)]
pub struct EventRecord {
    /// 発生エンドポイント。
    pub endpoint: EndpointId,
    /// 発生クラスタ。
    pub cluster: ClusterId,
    /// イベント ID。
    pub event: EventId,
    /// グローバル単調増加のイベント番号(EventNumber)。
    pub number: u64,
    /// priority(DEBUG=0 / INFO=1 / CRITICAL=2)。
    pub priority: u8,
    /// SystemTimestamp(起動からの単調ミリ秒)。
    pub system_timestamp_ms: u64,
    payload: [u8; EVENT_PAYLOAD_MAX],
    payload_len: u8,
}

impl EventRecord {
    /// EventDataIB.Data の値要素の生 TLV(anonymous タグ付き)。
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }
}

/// 固定容量のイベントログ(リングバッファ)。
///
/// 満杯時は最古のイベントを追い出す。`event_number` は起動時 0 から単調増加する
/// (永続化なし、モジュールドキュメント参照)。
#[derive(Debug)]
pub struct EventLog<const N: usize = 8> {
    buf: [Option<EventRecord>; N],
    /// 最古エントリの索引。
    start: usize,
    /// 保持件数(`<= N`)。
    len: usize,
    /// 次に採番する EventNumber。
    next_number: u64,
}

impl<const N: usize> Default for EventLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> EventLog<N> {
    /// 空のイベントログを作る。
    pub const fn new() -> Self {
        Self {
            buf: [None; N],
            start: 0,
            len: 0,
            next_number: 0,
        }
    }

    /// 保持しているイベント数。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// イベントが 1 件も無いか。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 次に採番される EventNumber(まだ post していないイベントの番号)。
    pub const fn next_number(&self) -> u64 {
        self.next_number
    }

    /// イベントを 1 件積む(満杯なら最古を追い出す)。採番した EventNumber を返す。
    ///
    /// `write_data` は EventDataIB.Data の**値要素**を `tag`(anonymous 指定で渡す)で書く。
    /// StartUp なら `{ 0: softwareVersion }` の struct。payload が [`EVENT_PAYLOAD_MAX`] を
    /// 超える場合は [`Error::NoSpace`]。
    pub fn post(
        &mut self,
        endpoint: EndpointId,
        cluster: ClusterId,
        event: EventId,
        priority: u8,
        now_ms: u64,
        write_data: impl FnOnce(&mut TlvWriter<'_>, &TlvTag) -> Result<()>,
    ) -> Result<u64> {
        let mut payload = [0u8; EVENT_PAYLOAD_MAX];
        let payload_len = {
            let mut w = TlvWriter::new(&mut payload);
            write_data(&mut w, &TlvTag::Anonymous)?;
            w.len()
        };
        let number = self.next_number;
        self.next_number = self.next_number.wrapping_add(1);
        let rec = EventRecord {
            endpoint,
            cluster,
            event,
            number,
            priority,
            system_timestamp_ms: now_ms,
            payload,
            payload_len: payload_len as u8,
        };
        if N == 0 {
            return Ok(number);
        }
        let idx = (self.start + self.len) % N;
        self.buf[idx] = Some(rec);
        if self.len < N {
            self.len += 1;
        } else {
            // 満杯: 最古(= 今書いた位置)を上書きしたので start を前進させる。
            self.start = (self.start + 1) % N;
        }
        Ok(number)
    }

    /// 保持イベントを古い順にイテレートする。
    pub fn iter(&self) -> impl Iterator<Item = &EventRecord> + '_ {
        (0..self.len).filter_map(move |i| self.buf[(self.start + i) % N].as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post_n(log: &mut EventLog<4>, n: u64) {
        for i in 0..n {
            log.post(
                EndpointId(0),
                ClusterId(0x0028),
                EventId(0),
                PRIORITY_CRITICAL,
                i * 10,
                |w, tag| {
                    w.start_struct(tag)?;
                    w.write_u32(&TlvTag::ContextSpecific(0), i as u32)?;
                    w.end_container()
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn monotonic_numbers_and_ring_eviction() {
        let mut log = EventLog::<4>::new();
        post_n(&mut log, 6);
        // 容量 4 なので直近 4 件(number 2..=5)が残る。
        assert_eq!(log.len(), 4);
        let mut numbers = [0u64; 4];
        for (slot, rec) in numbers.iter_mut().zip(log.iter()) {
            *slot = rec.number;
        }
        assert_eq!(numbers, [2, 3, 4, 5]);
        assert_eq!(log.next_number(), 6);
    }
}
