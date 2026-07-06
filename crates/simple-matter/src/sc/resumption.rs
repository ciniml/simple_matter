//! CASE session resumption の状態保持(`docs/design/secure-channel.md` §7.4)。
//!
//! フル CASE で確立した `SharedSecret` と `resumptionID` を **メモリ内** の固定容量ストアに
//! 保持し、再接続時の Sigma2_Resume 経路(Matter 仕様 §4.14.4)に供する。KVS への永続化は
//! 今回スコープ外(プロセス再起動ではフル CASE にフォールバックする = 安全側)。
//!
//! - **キー**: `(fabric_index, peer_node_id)` で upsert(同一ピアは常に 1 レコード)。
//! - **容量と追い出し**: 既定 [`RESUMPTION_CACHE_LEN`] = 4 レコード。満杯時は挿入順が
//!   最も古いレコードを追い出す(FIFO。u32 単調 seq で判定)。追い出されたピアはフル CASE
//!   へフォールバックするだけで機能劣化はない。
//! - `shared_secret` は [`Zeroizing`] で drop 時にゼロ化する。

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::transport::session::fixed::FixedVec;

use super::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};

/// 既定のレコード容量(設計 §7.4。1 レコード ≈ 60 B)。
pub const RESUMPTION_CACHE_LEN: usize = 4;

/// 1 ピアぶんの resumption レコード。
pub struct ResumptionRecord {
    /// 所属 fabric(fabric が削除された場合、照合時に無効化される)。
    pub fabric_index: NonZeroU8,
    /// 相手の operational NodeId(fabric スコープ)。
    pub peer_node_id: u64,
    /// 現行 resumptionID(セッション確立ごとにローテートする)。
    pub resumption_id: [u8; CASE_RESUMPTION_ID_LEN],
    /// フル CASE の ECDH SharedSecret(resumption を繰り返しても不変)。
    pub shared_secret: Zeroizing<[u8; SHARED_SECRET_LEN]>,
    /// 挿入順(FIFO 追い出し判定)。
    seq: u32,
}

/// 固定容量の resumption レコードストア(メモリ内のみ)。
pub struct ResumptionStore<const N: usize = RESUMPTION_CACHE_LEN> {
    records: FixedVec<ResumptionRecord, N>,
    next_seq: u32,
}

impl<const N: usize> Default for ResumptionStore<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ResumptionStore<N> {
    /// 空のストアを生成する。
    pub const fn new() -> Self {
        Self {
            records: FixedVec::new(),
            next_seq: 0,
        }
    }

    /// 保持レコード数。
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// レコードが 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// `(fabric_index, peer_node_id)` で upsert する。
    ///
    /// 既存レコードがあれば resumptionID / SharedSecret を差し替える(ローテート)。
    /// 満杯なら挿入順が最も古いレコードを追い出して入れる(FIFO)。
    pub fn save(
        &mut self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
        resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
        shared_secret: &[u8; SHARED_SECRET_LEN],
    ) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let existing = self
            .records
            .iter()
            .position(|r| r.fabric_index == fabric_index && r.peer_node_id == peer_node_id);
        if let Some(r) = existing.and_then(|i| self.records.get_mut(i)) {
            r.resumption_id = *resumption_id;
            *r.shared_secret = *shared_secret;
            r.seq = seq;
            return;
        }
        let record = ResumptionRecord {
            fabric_index,
            peer_node_id,
            resumption_id: *resumption_id,
            shared_secret: Zeroizing::new(*shared_secret),
            seq,
        };
        if self.records.push(record).is_err() {
            // 満杯: 挿入順が最も古い(seq が next_seq から最も遠い)レコードを追い出す。
            // wrapping 距離で比較するため u32 ラップ後も正しく最古を選ぶ。
            if let Some(oldest) =
                (0..self.records.len()).max_by_key(|&i| seq.wrapping_sub(self.records[i].seq))
            {
                self.records[oldest] = ResumptionRecord {
                    fabric_index,
                    peer_node_id,
                    resumption_id: *resumption_id,
                    shared_secret: Zeroizing::new(*shared_secret),
                    seq,
                };
            }
        }
    }

    /// resumptionID でレコードを引く(responder の Sigma1 入口照合)。
    pub fn find_by_id(
        &self,
        resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    ) -> Option<&ResumptionRecord> {
        self.records
            .iter()
            .find(|r| r.resumption_id == *resumption_id)
    }

    /// `(fabric_index, peer_node_id)` でレコードを引く(initiator の `start_case`)。
    pub fn find_by_peer(
        &self,
        fabric_index: NonZeroU8,
        peer_node_id: u64,
    ) -> Option<&ResumptionRecord> {
        self.records
            .iter()
            .find(|r| r.fabric_index == fabric_index && r.peer_node_id == peer_node_id)
    }

    /// `fabric_index` に属するレコードをすべて破棄する(fabric 削除時の後始末用)。
    pub fn remove_fabric(&mut self, fabric_index: NonZeroU8) {
        loop {
            let pos = self
                .records
                .iter()
                .position(|r| r.fabric_index == fabric_index);
            match pos {
                Some(i) => {
                    let _ = self.records.swap_remove(i);
                }
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(n: u8) -> NonZeroU8 {
        NonZeroU8::new(n).unwrap()
    }

    #[test]
    fn save_find_and_rotate() {
        let mut store: ResumptionStore<2> = ResumptionStore::new();
        assert!(store.is_empty());
        store.save(fx(1), 0x1111, &[0xAA; 16], &[0x01; 32]);
        assert_eq!(store.len(), 1);
        let r = store.find_by_id(&[0xAA; 16]).unwrap();
        assert_eq!(r.peer_node_id, 0x1111);
        assert_eq!(&r.shared_secret[..], &[0x01; 32]);

        // 同一ピアの保存はローテート(件数不変・ID 差し替え)。
        store.save(fx(1), 0x1111, &[0xBB; 16], &[0x01; 32]);
        assert_eq!(store.len(), 1);
        assert!(store.find_by_id(&[0xAA; 16]).is_none());
        assert!(store.find_by_id(&[0xBB; 16]).is_some());
        assert!(store.find_by_peer(fx(1), 0x1111).is_some());
        assert!(store.find_by_peer(fx(2), 0x1111).is_none());
    }

    #[test]
    fn fifo_eviction_on_full() {
        let mut store: ResumptionStore<2> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        store.save(fx(1), 2, &[0x02; 16], &[0x02; 32]);
        // 3 件目で最古(peer=1)が追い出される。
        store.save(fx(1), 3, &[0x03; 16], &[0x03; 32]);
        assert_eq!(store.len(), 2);
        assert!(store.find_by_peer(fx(1), 1).is_none());
        assert!(store.find_by_peer(fx(1), 2).is_some());
        assert!(store.find_by_peer(fx(1), 3).is_some());
        // peer=2 をローテート(seq 更新)してから 4 件目 → 追い出しは peer=3。
        store.save(fx(1), 2, &[0x22; 16], &[0x02; 32]);
        store.save(fx(1), 4, &[0x04; 16], &[0x04; 32]);
        assert!(store.find_by_peer(fx(1), 3).is_none());
        assert!(store.find_by_peer(fx(1), 2).is_some());
        assert!(store.find_by_peer(fx(1), 4).is_some());
    }

    #[test]
    fn remove_fabric_clears_records() {
        let mut store: ResumptionStore<4> = ResumptionStore::new();
        store.save(fx(1), 1, &[0x01; 16], &[0x01; 32]);
        store.save(fx(2), 2, &[0x02; 16], &[0x02; 32]);
        store.save(fx(1), 3, &[0x03; 16], &[0x03; 32]);
        store.remove_fabric(fx(1));
        assert_eq!(store.len(), 1);
        assert!(store.find_by_peer(fx(2), 2).is_some());
    }
}
