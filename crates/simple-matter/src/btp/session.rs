//! seq / ack / window の状態機械([`SendWindow`] / [`RecvWindow`])。
//!
//! `docs/design/ble-btp.md` §2.4 / §4.3 に基づく。seq / ack は 8bit ローリング
//! (`wrapping_add`)。受信 seq は期待値と厳密一致を要求する。
//!
//! - [`SendWindow`]: 未 ACK フラグメントの本数を追跡し、交渉済み window を超えて送出しない
//!   フロー制御を担う。受信 ACK で未 ACK 区間を前進させる。BTP はフラグメント単位の
//!   再送を持たず(下位 GATT が信頼配送する)、未 ACK の放置はセッションの liveness
//!   タイムアウト(§2.5)で検知する。
//! - [`RecvWindow`]: 受信 seq の期待値・ACK 対象・local window(残り受信容量)を管理し、
//!   local window ≤ 1 で即時 standalone ACK、それ以外は遅延 ACK(2500ms)の期限を張る。

use crate::error::{Error, Result};

use super::handshake::BTP_ACK_SEND_DELAY_MS;

/// 送信 window(未 ACK フラグメントのフロー制御)。
#[derive(Debug)]
pub struct SendWindow {
    /// 交渉済み window サイズ(未 ACK 許容本数)。
    window_size: u8,
    /// 次に送出する seq。
    next_seq: u8,
    /// 未 ACK 区間の最古 seq。
    oldest_unacked: u8,
    /// 未 ACK フラグメント本数。
    unacked: u8,
    /// 最後にフラグメントを送出した時刻(liveness タイムアウト用)。
    last_tx_ms: Option<u64>,
}

impl SendWindow {
    /// 初期 seq(両 role とも 0。`Btp::new` のドキュメント参照)で生成する。
    pub const fn new(initial_seq: u8) -> Self {
        Self {
            window_size: 0,
            next_seq: initial_seq,
            oldest_unacked: initial_seq,
            unacked: 0,
            last_tx_ms: None,
        }
    }

    /// 交渉済み window を設定する(handshake 完了時)。
    pub fn set_window(&mut self, window_size: u8) {
        self.window_size = window_size;
    }

    /// もう 1 フラグメント送出できるなら `true`(window に空きがある)。
    pub const fn can_send(&self) -> bool {
        self.window_size > 0 && self.unacked < self.window_size
    }

    /// 未 ACK 本数。
    pub const fn unacked(&self) -> u8 {
        self.unacked
    }

    /// 最後に送出した時刻。
    pub const fn last_tx_ms(&self) -> Option<u64> {
        self.last_tx_ms
    }

    /// データセグメント送出に seq を払い出し、未 ACK に計上する。
    ///
    /// データは相手の ACK を要するため window 枠を 1 消費し、liveness 監視のため送出時刻を記録する。
    pub fn take_data_seq(&mut self, now_ms: u64) -> u8 {
        if self.unacked == 0 {
            self.oldest_unacked = self.next_seq;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.unacked = self.unacked.saturating_add(1);
        self.last_tx_ms = Some(now_ms);
        seq
    }

    /// standalone ACK 送出に seq を払い出す(未 ACK には計上しない)。
    ///
    /// 純粋 ACK は相手が ACK を返さない(本コアの簡略化、`mod.rs` 参照)ため window 枠を
    /// 消費せず、liveness 監視の対象にもしない。seq は連番性維持のため前進させる。
    pub fn take_ack_seq(&mut self) -> u8 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    /// 受信 ACK 値 `ack` で未 ACK 区間を前進させる。
    ///
    /// `ack` が未 ACK 区間 `[oldest_unacked, oldest+unacked)` の外なら**黙って無視**する。
    /// 本実装は standalone ACK を未 ACK に計上しない(`take_ack_seq`)が、chip は仕様
    /// どおり standalone ACK の seq にも ACK を返してくるため(chip-lighting-app 実機で
    /// 裏取り)、区間外 ACK をエラーにすると相互運用が壊れる。副作用として「未送 seq への
    /// ACK」というプロトコル違反も検出できなくなるが、寛容側に倒す。
    pub fn on_ack(&mut self, ack: u8) -> Result<()> {
        if self.unacked == 0 {
            return Ok(());
        }
        // oldest からの距離(0..=255)。ack が区間内なら距離 < unacked。
        let dist = (ack as u16).wrapping_sub(self.oldest_unacked as u16) & 0xFF;
        let acked = dist + 1;
        if acked > self.unacked as u16 {
            return Ok(());
        }
        self.unacked -= acked as u8;
        self.oldest_unacked = ack.wrapping_add(1);
        if self.unacked == 0 {
            self.last_tx_ms = None;
        }
        Ok(())
    }

    /// 状態を初期化する(切断時など)。
    pub fn reset(&mut self, initial_seq: u8) {
        self.window_size = 0;
        self.next_seq = initial_seq;
        self.oldest_unacked = initial_seq;
        self.unacked = 0;
        self.last_tx_ms = None;
    }
}

/// 受信 window(seq 期待値・ACK 生成・local window)。
#[derive(Debug)]
pub struct RecvWindow {
    /// 交渉済み window サイズ。
    window_size: u8,
    /// 次に受理する seq(厳密一致必須)。
    next_seq: u8,
    /// 最後に受理した seq(ACK 値に用いる)。
    newest_seq: u8,
    /// 残り受信容量。0/1 で即時 ACK を促す。
    level: u8,
    /// 未送出の ACK を保留中なら `true`。
    pending_ack: bool,
    /// standalone ACK を送るべき絶対時刻。
    ack_deadline_ms: Option<u64>,
}

impl RecvWindow {
    /// 初期 seq(両 role とも 0。`Btp::new` のドキュメント参照)で生成する。
    pub const fn new(initial_seq: u8) -> Self {
        Self {
            window_size: 0,
            next_seq: initial_seq,
            newest_seq: initial_seq.wrapping_sub(1),
            level: 0,
            pending_ack: false,
            ack_deadline_ms: None,
        }
    }

    /// 交渉済み window を設定し local window を満たす。
    pub fn set_window(&mut self, window_size: u8) {
        self.window_size = window_size;
        self.level = window_size;
    }

    /// 受信フラグメントの seq を検証し、期待値を進める。
    ///
    /// standalone ACK(payload なし)も seq を消費するため、データか否かに依らず本メソッドで
    /// 期待値を進める(相手の seq 採番と同期を保つ)。期待値不一致は [`Error::InvalidState`]。
    pub fn accept_seq(&mut self, seq: u8) -> Result<()> {
        if seq != self.next_seq {
            return Err(Error::InvalidState);
        }
        self.next_seq = self.next_seq.wrapping_add(1);
        self.newest_seq = seq;
        Ok(())
    }

    /// データ(セグメント)フラグメントを受理したときの ACK 武装。
    ///
    /// local window を 1 減らし、`level ≤ 1` なら即時(`now`)、それ以外は遅延(`now + 2500ms`)の
    /// standalone ACK 期限を張る。純粋な ACK フラグメントでは呼ばない(ACK の応酬を避ける)。
    pub fn arm_ack(&mut self, now_ms: u64) {
        self.pending_ack = true;
        if self.level > 0 {
            self.level -= 1;
        }
        self.ack_deadline_ms = Some(if self.level <= 1 {
            now_ms
        } else {
            self.ack_deadline_ms
                .unwrap_or(now_ms.saturating_add(BTP_ACK_SEND_DELAY_MS))
        });
    }

    /// 純粋 standalone ACK(keep-alive)受信時の ACK 武装。
    ///
    /// standalone ACK も seq を消費するため相手は当該 seq の ACK 受領を待つ
    /// (chip は ack-received タイマで未 ACK を検知して切断する)。データと違い
    /// local window は消費しないため `level` は減らさず、遅延(2500ms)期限のみ張る
    /// (既に保留があればそのまま)。これにより長アイドル(遅延 InvokeResponse の
    /// join 待ち等)でも 2.5s 周期の ACK 応酬で BTP リンクが維持される。
    pub fn arm_keepalive_ack(&mut self, now_ms: u64) {
        self.pending_ack = true;
        if self.ack_deadline_ms.is_none() {
            self.ack_deadline_ms = Some(now_ms.saturating_add(BTP_ACK_SEND_DELAY_MS));
        }
    }

    /// 保留 ACK があれば取り出し(piggyback / standalone 送出時)、local window を戻す。
    pub fn take_ack(&mut self) -> Option<u8> {
        if self.pending_ack {
            self.pending_ack = false;
            self.level = self.window_size;
            self.ack_deadline_ms = None;
            Some(self.newest_seq)
        } else {
            None
        }
    }

    /// standalone ACK を今送るべきなら `true`(保留があり期限到達)。
    pub fn ack_due(&self, now_ms: u64) -> bool {
        self.pending_ack && self.ack_deadline_ms.map(|d| now_ms >= d).unwrap_or(false)
    }

    /// ACK 保留中なら `true`。
    pub const fn is_ack_pending(&self) -> bool {
        self.pending_ack
    }

    /// standalone ACK の期限(あれば)。
    pub const fn ack_deadline(&self) -> Option<u64> {
        if self.pending_ack {
            self.ack_deadline_ms
        } else {
            None
        }
    }

    /// 状態を初期化する(切断時など)。
    pub fn reset(&mut self, initial_seq: u8) {
        self.window_size = 0;
        self.next_seq = initial_seq;
        self.newest_seq = initial_seq.wrapping_sub(1);
        self.level = 0;
        self.pending_ack = false;
        self.ack_deadline_ms = None;
    }
}
