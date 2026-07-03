//! MRP(Message Reliability Protocol):信頼送達の再送と ACK 管理。
//!
//! `docs/design/transport-exchange.md` §6 に基づき、Matter Core Specification の MRP を
//! 実装する。[`Mrp`] は [`Exchange`](crate::exchange::exchange::ExchangeState) に値として
//! 内包され、次を担う。
//!
//! - R(reliable)フラグ付き送信の再送スロット管理(指数バックオフ + jitter)。
//! - A(ack)フラグの piggyback と、受信 ACK による再送スロット解除。
//! - standalone ACK の遅延生成(200ms 期限)。
//! - 重複受信時の再 ACK 再武装。
//! - 再送回数上限到達での送信失敗(諦め)。
//!
//! # 時間ソース(sans-IO)
//!
//! 設計 §12 論点 1/5 の判断に従い、`embassy-time` へ依存せず外部注入方式にする。
//! 各メソッドは `now_ms`(単調増加するミリ秒)を受け取り、次に処理すべき時刻
//! ([`Mrp::next_deadline`])を返す。プラットフォーム(統合層)がその deadline まで
//! 待って [`crate::exchange::ExchangeManager::poll`] を再駆動する。これによりホスト
//! テストが決定的になる。
//!
//! # jitter の注入
//!
//! バックオフの jitter 乱数は `jitter_rand: u8` として注入する。統合層は
//! [`crate::crypto::Rng`] から 1 バイト供給し、テストは固定値(例: 0 = jitter なし)を
//! 渡して決定的に検証できる。

use crate::buf::BufferId;
use crate::error::{Error, Result};
use crate::transport::net::PeerAddr;

/// standalone ACK を送るまでの遅延(ミリ秒)。応答を piggyback できなかった信頼
/// メッセージに対し、この期限が来たら単独 ACK を送る(設計 §6・§12 論点 2)。
pub const MRP_STANDALONE_ACK_TIMEOUT_MS: u64 = 200;

/// 再送のベース間隔既定値(ミリ秒)。peer / 自機のいずれも SAI を広告しないときの既定。
const MRP_BASE_RETRY_INTERVAL_MS: u32 = 300;

/// 1 メッセージあたりの最大送信回数(初回 + 再送)。この回数を超えると送信失敗。
pub const MRP_MAX_TRANSMISSIONS: u16 = 10;

/// 指数バックオフを始める送信回数の閾値。これ以下の回数ではバックオフしない。
const MRP_BACKOFF_THRESHOLD: u16 = 1;

/// バックオフ倍率 1.6(分子, 分母)。
const MRP_BACKOFF_BASE: (u64, u64) = (16, 10);

/// jitter 係数 0.25(分子, 分母)。
const MRP_BACKOFF_JITTER: (u64, u64) = (25, 100);

/// マージン係数 1.1(分子, 分母)。
const MRP_BACKOFF_MARGIN: (u64, u64) = (11, 10);

/// SII(Session Idle Interval)既定値(ミリ秒)。
const MRP_DEFAULT_IDLE_INTERVAL_MS: u32 = 5000;

/// SAI(Session Active Interval)既定値(ミリ秒)。
const MRP_DEFAULT_ACTIVE_INTERVAL_MS: u32 = MRP_BASE_RETRY_INTERVAL_MS;

/// SAT(Session Active Threshold)既定値(ミリ秒)。
const MRP_DEFAULT_ACTIVE_THRESHOLD_MS: u16 = 4000;

/// MRP のタイミングパラメータ(peer が session parameters で広告 / 自機既定)。
///
/// 設計 §6 に従い、再送のベース間隔は SAI([`active_interval_ms`](Self::active_interval_ms))を
/// 用いる。`0` は無効値(タイトループ化を招く)として既定へフォールバックする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrpConfig {
    /// SII: Session Idle Interval(ミリ秒)。
    pub idle_interval_ms: u32,
    /// SAI: Session Active Interval(ミリ秒)。再送ベース間隔に用いる。
    pub active_interval_ms: u32,
    /// SAT: Session Active Threshold(ミリ秒)。
    pub active_threshold_ms: u16,
}

impl MrpConfig {
    /// 仕様デフォルトの MRP パラメータ。
    pub const DEFAULT: Self = Self {
        idle_interval_ms: MRP_DEFAULT_IDLE_INTERVAL_MS,
        active_interval_ms: MRP_DEFAULT_ACTIVE_INTERVAL_MS,
        active_threshold_ms: MRP_DEFAULT_ACTIVE_THRESHOLD_MS,
    };

    /// 再送のベース間隔(ミリ秒)を返す。SAI が 0(無効)なら既定へフォールバックする。
    const fn base_interval_ms(&self) -> u32 {
        if self.active_interval_ms > 0 {
            self.active_interval_ms
        } else {
            MRP_BASE_RETRY_INTERVAL_MS
        }
    }
}

impl Default for MrpConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// 指定送信回数 `tries` に対する(再)送信までの遅延(ミリ秒)を計算する。
///
/// `delay = base * MARGIN(1.1) * BASE(1.6)^(tries - THRESHOLD) + jitter(0.25)`。
/// `tries` は「これまでの送信回数」で、初回送信直後は 1。閾値以下ではバックオフしない。
fn delay_ms(base_interval_ms: u32, tries: u16, jitter_rand: u8) -> u64 {
    let mut delay = base_interval_ms as u64 * MRP_BACKOFF_MARGIN.0 / MRP_BACKOFF_MARGIN.1;
    if tries > MRP_BACKOFF_THRESHOLD {
        for _ in 0..(tries - MRP_BACKOFF_THRESHOLD) {
            delay = delay * MRP_BACKOFF_BASE.0 / MRP_BACKOFF_BASE.1;
        }
    }
    delay + (delay * jitter_rand as u64 * MRP_BACKOFF_JITTER.0) / (255 * MRP_BACKOFF_JITTER.1)
}

/// 未 ACK の信頼送信を保持する再送スロット。
#[derive(Debug)]
struct RetransSlot {
    /// バックオフのベース間隔(ミリ秒)。
    base_interval_ms: u32,
    /// ACK を待っている送信メッセージカウンタ。
    msg_ctr: u32,
    /// これまでの送信回数(初回送信で 1)。
    tries: u16,
    /// 暗号化済みの完全なワイヤパケットを保持する TX バッファ。
    buf: BufferId,
    /// `buf` 内の有効長(ワイヤバイト数)。
    len: usize,
    /// 再送先。
    addr: PeerAddr,
    /// 次に再送すべき絶対時刻(ミリ秒)。
    next_deadline_ms: u64,
}

/// 送るべき ACK(piggyback / standalone 用)。
#[derive(Debug, Clone, Copy)]
struct PendingAck {
    /// ACK すべき受信メッセージカウンタ。
    msg_ctr: u32,
    /// 少なくとも 1 度 ACK 済み(piggyback または standalone 送信済み)か。
    acknowledged: bool,
    /// standalone ACK を送る絶対時刻(ミリ秒)。
    deadline_ms: u64,
}

/// [`Mrp::post_recv`] の結果。
#[derive(Debug, Clone, Copy, Default)]
pub struct RecvOutcome {
    /// ACK により解放された再送 TX バッファ(呼び出し側がプールへ返す)。
    pub freed: Option<BufferId>,
    /// このメッセージは重複としてドロップすべき(上位でディスパッチしない)。
    pub duplicate: bool,
}

/// [`Mrp::take_due_retrans`] が返す再送アクション。
#[derive(Debug, Clone, Copy)]
pub enum RetransAction {
    /// 再送すべきものはない。
    None,
    /// `addr` へ `buf` の先頭 `len` バイトを再送する。
    Retransmit {
        /// 再送するワイヤパケットを保持する TX バッファ。
        buf: BufferId,
        /// 送信長(バイト)。
        len: usize,
        /// 再送先。
        addr: PeerAddr,
    },
    /// 再送上限に達した。`buf` を解放し exchange を失敗させる。
    GiveUp {
        /// 解放すべき TX バッファ。
        buf: BufferId,
    },
}

/// Exchange 単位の MRP 状態(再送 + ACK)。
#[derive(Debug, Default)]
pub struct Mrp {
    retrans: Option<RetransSlot>,
    ack: Option<PendingAck>,
}

impl Mrp {
    /// 空の MRP 状態を生成する。
    pub const fn new() -> Self {
        Self {
            retrans: None,
            ack: None,
        }
    }

    /// 未 ACK の再送が保留中なら `true`。
    pub const fn is_retrans_pending(&self) -> bool {
        self.retrans.is_some()
    }

    /// まだ送っていない ACK が保留中なら `true`。
    pub fn is_ack_pending(&self) -> bool {
        self.ack.map(|a| !a.acknowledged).unwrap_or(false)
    }

    /// 送信時に piggyback すべき ACK カウンタを取り出す(あれば ACK 済みに印を付ける)。
    ///
    /// 応答メッセージに ACK を相乗りさせるために用いる。取り出すと standalone ACK は
    /// 送られなくなる。
    pub fn take_ack_for_piggyback(&mut self) -> Option<u32> {
        match &mut self.ack {
            Some(ack) if !ack.acknowledged => {
                ack.acknowledged = true;
                Some(ack.msg_ctr)
            }
            _ => None,
        }
    }

    /// 信頼メッセージを送信した直後に呼び、再送スロットを登録する。
    ///
    /// `msg_ctr` は送信に用いたカウンタ、`buf`/`len`/`addr` は暗号化済みワイヤパケットの
    /// 保持バッファと長さ・宛先。`config` からベース間隔を、`jitter_rand` から jitter を得て
    /// 初回再送 deadline を `now_ms` 起点で決める。
    ///
    /// # Errors
    /// 既に再送スロットが埋まっている(同一 exchange で二重送信)場合は
    /// [`Error::InvalidState`]。
    #[allow(clippy::too_many_arguments)] // 再送スロット登録に必要な素の値群(束ねると不透明化)。
    pub fn on_reliable_sent(
        &mut self,
        msg_ctr: u32,
        buf: BufferId,
        len: usize,
        addr: PeerAddr,
        config: &MrpConfig,
        jitter_rand: u8,
        now_ms: u64,
    ) -> Result<()> {
        if self.retrans.is_some() {
            return Err(Error::InvalidState);
        }
        let base_interval_ms = config.base_interval_ms();
        let tries = 1;
        let next_deadline_ms =
            now_ms.saturating_add(delay_ms(base_interval_ms, tries, jitter_rand));
        self.retrans = Some(RetransSlot {
            base_interval_ms,
            msg_ctr,
            tries,
            buf,
            len,
            addr,
            next_deadline_ms,
        });
        Ok(())
    }

    /// 受信メッセージで再送/ACK 状態を更新する。
    ///
    /// - `rx_ack` に自分の待つカウンタが載っていれば再送スロットを解除し、その TX バッファを
    ///   [`RecvOutcome::freed`] で返す。カウンタ不一致は重複として `duplicate = true`。
    /// - `rx_reliable` が真なら、`rx_ctr` を ACK すべき保留 ACK として記録し、standalone ACK の
    ///   期限を `now_ms + 200ms` に張る。
    pub fn post_recv(
        &mut self,
        rx_ack: Option<u32>,
        rx_reliable: bool,
        rx_ctr: u32,
        now_ms: u64,
    ) -> RecvOutcome {
        let mut outcome = RecvOutcome::default();

        if let Some(ack_ctr) = rx_ack {
            if let Some(slot) = &self.retrans {
                if slot.msg_ctr == ack_ctr {
                    // 対応する再送を解除し、バッファを解放候補にする。
                    outcome.freed = Some(slot.buf);
                    self.retrans = None;
                } else {
                    // 古いカウンタへの ACK = ノイズの多い経路での重複。処理を打ち切る。
                    outcome.duplicate = true;
                }
            }
        }

        if rx_reliable {
            self.ack = Some(PendingAck {
                msg_ctr: rx_ctr,
                acknowledged: false,
                deadline_ms: now_ms.saturating_add(MRP_STANDALONE_ACK_TIMEOUT_MS),
            });
        }

        outcome
    }

    /// 重複受信した信頼メッセージに対し、ACK を即時再送するよう再武装する。
    ///
    /// リプレイ窓で弾かれた(既受理の)信頼メッセージは、こちらの ACK がロストした可能性が
    /// あるため再度 ACK する。`deadline` を `now_ms` にして次の [`poll`](crate::exchange::ExchangeManager::poll)
    /// で即送出させる。
    pub fn rearm_ack(&mut self, rx_ctr: u32, now_ms: u64) {
        self.ack = Some(PendingAck {
            msg_ctr: rx_ctr,
            acknowledged: false,
            deadline_ms: now_ms,
        });
    }

    /// standalone ACK の期限が来ていれば、その ACK カウンタを覗く(状態は変えない)。
    ///
    /// 実際に送出できたら [`mark_ack_sent`](Self::mark_ack_sent) を呼んで印を付ける。
    pub fn peek_expired_ack(&self, now_ms: u64) -> Option<u32> {
        match &self.ack {
            Some(ack) if !ack.acknowledged && now_ms >= ack.deadline_ms => Some(ack.msg_ctr),
            _ => None,
        }
    }

    /// standalone ACK を送出済みと印を付ける。
    pub fn mark_ack_sent(&mut self) {
        if let Some(ack) = &mut self.ack {
            ack.acknowledged = true;
        }
    }

    /// 再送 deadline が来ていれば再送アクションを返し、状態を進める。
    ///
    /// 送信上限([`MRP_MAX_TRANSMISSIONS`])に達していれば [`RetransAction::GiveUp`] を返す。
    /// まだ deadline でなければ [`RetransAction::None`]。
    pub fn take_due_retrans(&mut self, now_ms: u64, jitter_rand: u8) -> RetransAction {
        let Some(slot) = &mut self.retrans else {
            return RetransAction::None;
        };
        if now_ms < slot.next_deadline_ms {
            return RetransAction::None;
        }
        if slot.tries >= MRP_MAX_TRANSMISSIONS {
            // 上限到達。諦めて解放させる。
            let buf = slot.buf;
            self.retrans = None;
            return RetransAction::GiveUp { buf };
        }
        slot.tries += 1;
        slot.next_deadline_ms =
            now_ms.saturating_add(delay_ms(slot.base_interval_ms, slot.tries, jitter_rand));
        RetransAction::Retransmit {
            buf: slot.buf,
            len: slot.len,
            addr: slot.addr,
        }
    }

    /// 次に処理すべき絶対時刻(再送・standalone ACK のうち早い方)を返す。
    pub fn next_deadline(&self) -> Option<u64> {
        let retrans = self.retrans.as_ref().map(|s| s.next_deadline_ms);
        let ack = self.ack.filter(|a| !a.acknowledged).map(|a| a.deadline_ms);
        match (retrans, ack) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// 保持中の再送 TX バッファ(あれば)を返す。exchange 破棄時の解放に用いる。
    pub fn retrans_buffer(&self) -> Option<BufferId> {
        self.retrans.as_ref().map(|s| s.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr() -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5540,
        ))
    }

    // buf.rs から本物の BufferId を得るための最小プール。
    fn a_buf() -> BufferId {
        let mut pool: crate::buf::BufferPool<1, 4> = crate::buf::BufferPool::new();
        pool.acquire().unwrap()
    }

    #[test]
    fn delay_backoff_is_deterministic_without_jitter() {
        // base=300, margin 1.1 → 330。tries=1 はバックオフなし。
        assert_eq!(delay_ms(300, 1, 0), 330);
        // tries=2 → ×1.6 = 528。
        assert_eq!(delay_ms(300, 2, 0), 528);
        // tries=3 → ×1.6 again = 844(整数演算: 528*16/10)。
        assert_eq!(delay_ms(300, 3, 0), 844);
    }

    #[test]
    fn delay_jitter_adds_up_to_quarter() {
        // jitter_rand = 255(最大)→ +25%。330 + 330*255*25/(255*100) = 330 + 82 = 412。
        assert_eq!(delay_ms(300, 1, 255), 412);
        // jitter_rand = 0 → 加算なし。
        assert_eq!(delay_ms(300, 1, 0), 330);
    }

    #[test]
    fn retrans_backoff_intervals_and_giveup() {
        let cfg = MrpConfig::DEFAULT; // SAI=300
        let mut mrp = Mrp::new();
        let buf = a_buf();
        // 初回送信登録(tries=1)。次 deadline = 0 + 330。
        mrp.on_reliable_sent(7, buf, 10, addr(), &cfg, 0, 0)
            .unwrap();
        assert!(mrp.is_retrans_pending());
        assert_eq!(mrp.next_deadline(), Some(330));

        // deadline 前は何も起きない。
        assert!(matches!(mrp.take_due_retrans(329, 0), RetransAction::None));
        // deadline 到達 → 再送(tries=2)。次 deadline = 330 + 528 = 858。
        match mrp.take_due_retrans(330, 0) {
            RetransAction::Retransmit { buf: b, len, .. } => {
                assert_eq!(b, buf);
                assert_eq!(len, 10);
            }
            other => panic!("expected retransmit, got {other:?}"),
        }
        assert_eq!(mrp.next_deadline(), Some(330 + 528));

        // 送信回数上限まで進めて GiveUp を得る。tries を 10 まで押し上げる。
        let mut now = 858u64;
        loop {
            match mrp.take_due_retrans(now, 0) {
                RetransAction::Retransmit { .. } => {
                    now += 100_000; // 十分先へ
                }
                RetransAction::GiveUp { buf: b } => {
                    assert_eq!(b, buf);
                    break;
                }
                RetransAction::None => panic!("deadline should have passed"),
            }
        }
        // GiveUp 後は保留なし。
        assert!(!mrp.is_retrans_pending());
        assert_eq!(mrp.next_deadline(), None);
    }

    #[test]
    fn total_transmissions_capped_at_max() {
        let cfg = MrpConfig::DEFAULT;
        let mut mrp = Mrp::new();
        mrp.on_reliable_sent(1, a_buf(), 4, addr(), &cfg, 0, 0)
            .unwrap();
        // 初回送信で 1 回。以降 Retransmit の回数を数える。
        let mut sends = 1;
        let mut now = 0u64;
        loop {
            now += 1_000_000;
            match mrp.take_due_retrans(now, 0) {
                RetransAction::Retransmit { .. } => sends += 1,
                RetransAction::GiveUp { .. } => break,
                RetransAction::None => unreachable!(),
            }
        }
        assert_eq!(sends, MRP_MAX_TRANSMISSIONS);
    }

    #[test]
    fn ack_received_frees_retrans_buffer() {
        let cfg = MrpConfig::DEFAULT;
        let mut mrp = Mrp::new();
        let buf = a_buf();
        mrp.on_reliable_sent(42, buf, 8, addr(), &cfg, 0, 0)
            .unwrap();
        // 一致する ACK 受信 → 再送解除 + バッファ解放。
        let out = mrp.post_recv(Some(42), false, 5, 100);
        assert_eq!(out.freed, Some(buf));
        assert!(!out.duplicate);
        assert!(!mrp.is_retrans_pending());
    }

    #[test]
    fn ack_counter_mismatch_is_duplicate() {
        let cfg = MrpConfig::DEFAULT;
        let mut mrp = Mrp::new();
        mrp.on_reliable_sent(42, a_buf(), 8, addr(), &cfg, 0, 0)
            .unwrap();
        // 別カウンタの ACK → 重複扱い、再送は維持。
        let out = mrp.post_recv(Some(41), false, 5, 100);
        assert!(out.duplicate);
        assert_eq!(out.freed, None);
        assert!(mrp.is_retrans_pending());
    }

    #[test]
    fn reliable_recv_arms_standalone_ack_after_200ms() {
        let mut mrp = Mrp::new();
        // 信頼メッセージ ctr=9 を時刻 1000 に受信。
        let out = mrp.post_recv(None, true, 9, 1000);
        assert!(!out.duplicate);
        assert!(mrp.is_ack_pending());
        // 200ms 前は期限未到達。
        assert_eq!(mrp.peek_expired_ack(1199), None);
        // ちょうど 200ms で期限到達。
        assert_eq!(mrp.peek_expired_ack(1200), Some(9));
        assert_eq!(mrp.next_deadline(), Some(1200));
        // 送出後は保留解除。
        mrp.mark_ack_sent();
        assert!(!mrp.is_ack_pending());
        assert_eq!(mrp.peek_expired_ack(2000), None);
    }

    #[test]
    fn piggyback_ack_suppresses_standalone() {
        let mut mrp = Mrp::new();
        mrp.post_recv(None, true, 9, 1000);
        // 応答に相乗り → ACK 済みになり standalone は出ない。
        assert_eq!(mrp.take_ack_for_piggyback(), Some(9));
        assert_eq!(mrp.take_ack_for_piggyback(), None);
        assert_eq!(mrp.peek_expired_ack(5000), None);
    }

    #[test]
    fn rearm_ack_on_duplicate_makes_it_immediately_due() {
        let mut mrp = Mrp::new();
        mrp.post_recv(None, true, 9, 1000);
        mrp.take_ack_for_piggyback(); // 一度 ACK 済み
        assert!(!mrp.is_ack_pending());
        // 重複受信 → 即時再 ACK 武装。
        mrp.rearm_ack(9, 2000);
        assert!(mrp.is_ack_pending());
        assert_eq!(mrp.peek_expired_ack(2000), Some(9));
    }

    #[test]
    fn double_reliable_send_is_invalid_state() {
        let cfg = MrpConfig::DEFAULT;
        let mut mrp = Mrp::new();
        mrp.on_reliable_sent(1, a_buf(), 4, addr(), &cfg, 0, 0)
            .unwrap();
        assert_eq!(
            mrp.on_reliable_sent(2, a_buf(), 4, addr(), &cfg, 0, 0),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn zero_sai_falls_back_to_default_base() {
        let cfg = MrpConfig {
            active_interval_ms: 0,
            ..MrpConfig::DEFAULT
        };
        let mut mrp = Mrp::new();
        mrp.on_reliable_sent(1, a_buf(), 4, addr(), &cfg, 0, 0)
            .unwrap();
        // 0 は既定 300 に補正され、初回 deadline = 330。
        assert_eq!(mrp.next_deadline(), Some(330));
    }
}
