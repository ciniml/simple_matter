//! BTP(Bluetooth Transport Protocol)コア:sans-IO・no_std の状態機械。
//!
//! `docs/design/ble-btp.md` §4 に基づく。BLE 無線・GATT I/O には一切触れず、**バイト列
//! in / バイト列 out** と `now_ms: u64` 注入だけで、handshake・SDU のセグメント化(TX)/
//! 再組立(RX)・seq/ack/window・ACK/idle タイマを駆動する(MRP と同じ sans-IO 契約)。
//!
//! 上位(統合層)は [`Btp::recv`] で再組立済みの 1 Matter メッセージを取り出して
//! `handle_rx` に渡し、`SendDirective` の payload を [`Btp::send`] に積む。GATT 層は
//! [`Btp::process_incoming`](受信 1 フラグメント投入)/ [`Btp::process_outgoing`]
//! (送出 1 フラグメント取り出し)を C1 write / C2 indicate に配線するだけでよい。
//!
//! # 責務外
//!
//! - BLE 無線・GATT I/O は [`gatt`] の抽象 trait([`GattPeripheral`](gatt::GattPeripheral) /
//!   [`GattCentral`](gatt::GattCentral))へ逃がす。BTP コアは trait を呼ばず、バイト列
//!   in/out のみを扱う。
//! - フラグメント単位の再送は持たない(下位 GATT が信頼配送する)。未 ACK の放置は
//!   liveness タイムアウト([`Btp::is_timed_out`])で検知する。
//!
//! # 簡略化(参照実装との乖離、理由付き)
//!
//! - 純粋な standalone ACK フラグメント(payload なし)の受信では返信 ACK を武装しない。
//!   chip は受信 seq ごとに ACK 義務を負い 2.5s 間隔で ACK を往復させる keep-alive を持つが、
//!   本コアは「データを伴うフラグメントのみ ACK 対象」とし、seq 同期は保ちつつ ACK の
//!   無限応酬を避ける(決定的テストのため)。データ経路の信頼性・window 制御には影響しない。

pub mod framing;
pub mod gatt;
pub mod handshake;
pub mod reassembly;
pub mod session;

pub use gatt::AdvData;
pub use handshake::{HandshakeReq, HandshakeResp};

use crate::error::{Error, Result};

use framing::{BtpHeader, HeaderFlags};
use handshake::{
    fragment_size, is_handshake, BTP_ACK_TIMEOUT_MS, BTP_IDLE_TIMEOUT_MS, BTP_MAX_FRAGMENT,
    BTP_MAX_WINDOW, BTP_MIN_FRAGMENT, BTP_VERSION,
};
use reassembly::{Reassembler, Segmenter};
use session::{RecvWindow, SendWindow};

/// BTP セッションでの自役割。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtpRole {
    /// GATT peripheral(device): handshake req を受けて resp を返す。
    Peripheral,
    /// GATT central(controller): handshake req を能動送出する。
    Central,
}

/// 状態機械のフェーズ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// 未開始。
    Idle,
    /// handshake 進行中(central は req 送出済み、peripheral は req 待ち)。
    Handshaking,
    /// 確立済み(データ送受信可)。
    Established,
}

/// 単一 BTP セッションの状態機械(初期は同時 1 接続、§4.2)。
///
/// `WINDOW` は自分が提示/受理する window 上限(既定 6 = 仕様上限)。実際の window は
/// handshake で相手提示値と `min` を取って確定する。
#[derive(Debug)]
pub struct Btp<const WINDOW: usize = 6> {
    role: BtpRole,
    phase: Phase,
    /// 交渉済みフラグメント payload サイズ(バイト)。
    fragment: usize,
    /// 交渉済み window。
    window_size: u8,
    send: SendWindow,
    recv: RecvWindow,
    tx: Segmenter,
    rx: Reassembler,
    /// peripheral が handshake resp を送出待ちなら `true`。
    resp_pending: bool,
    /// 最後に何らかのフラグメントを送受信した時刻(idle タイムアウト用)。
    last_activity_ms: u64,
}

impl<const WINDOW: usize> Btp<WINDOW> {
    /// role 指定で新しい BTP を生成する。
    ///
    /// seq 初期値は仕様どおり role で分岐する(§2.4):
    /// central は `tx=1, rx=0`、peripheral は `tx=0, rx=1`。
    pub const fn new(role: BtpRole) -> Self {
        let (tx_seq, rx_seq) = match role {
            BtpRole::Central => (1u8, 0u8),
            BtpRole::Peripheral => (0u8, 1u8),
        };
        Self {
            role,
            phase: Phase::Idle,
            fragment: 0,
            window_size: 0,
            send: SendWindow::new(tx_seq),
            recv: RecvWindow::new(rx_seq),
            tx: Segmenter::new(),
            rx: Reassembler::new(),
            resp_pending: false,
            last_activity_ms: 0,
        }
    }

    /// 自分が提示する window(`min(WINDOW, 6)`)。
    fn local_window_cap() -> u8 {
        if WINDOW > BTP_MAX_WINDOW as usize {
            BTP_MAX_WINDOW
        } else {
            WINDOW as u8
        }
    }

    /// 交渉済みか(handshake 完了)。
    pub const fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established)
    }

    /// 交渉済みフラグメント payload サイズ。
    pub const fn fragment_size(&self) -> usize {
        self.fragment
    }

    /// 交渉済み window。
    pub const fn window(&self) -> u8 {
        self.window_size
    }

    /// central: handshake を能動開始し、最初の Capabilities Request を `out` に書く。
    ///
    /// 既に開始済みなら [`Error::InvalidState`]。role が peripheral なら [`Error::InvalidState`]。
    pub fn start_handshake(
        &mut self,
        out: &mut [u8],
        mtu: Option<u16>,
        now_ms: u64,
    ) -> Result<usize> {
        if self.role != BtpRole::Central || self.phase != Phase::Idle {
            return Err(Error::InvalidState);
        }
        // central は自分の ATT_MTU を提示する(不明なら下限を提示)。
        let req = HandshakeReq::v4(mtu.unwrap_or(handshake::BTP_MIN_ATT_MTU), Self::local_window_cap());
        let n = req.encode(out)?;
        self.phase = Phase::Handshaking;
        self.last_activity_ms = now_ms;
        Ok(n)
    }

    /// C1 write(peripheral)/ C2 indication(central)で受けた 1 フラグメントを投入する。
    ///
    /// handshake・ack・データ再組立を進める。1 メッセージが揃うと [`Btp::recv`] で取り出せる。
    pub fn process_incoming(&mut self, frag: &[u8], mtu: Option<u16>, now_ms: u64) -> Result<()> {
        if is_handshake(frag) {
            match self.role {
                BtpRole::Peripheral => self.on_handshake_req(frag, mtu)?,
                BtpRole::Central => self.on_handshake_resp(frag)?,
            }
            self.last_activity_ms = now_ms;
            return Ok(());
        }

        if self.phase != Phase::Established {
            return Err(Error::InvalidState);
        }

        let (hdr, hlen) = BtpHeader::decode(frag)?;
        let payload = frag.get(hlen..).ok_or(Error::Decode)?;

        // seq を検証・前進(standalone ack でも seq を消費する)。
        self.recv.accept_seq(hdr.seq)?;

        // piggyback / standalone ACK 処理。
        if let Some(ack) = hdr.ack {
            self.send.on_ack(ack)?;
        }

        // データ(セグメント)なら再組立し ACK を武装する。
        if hdr.flags.has_data() {
            self.rx.push(hdr.flags, hdr.msg_len, payload)?;
            self.recv.arm_ack(now_ms);
        } else if !payload.is_empty() {
            // 純粋 ACK は payload を持たない。
            return Err(Error::Decode);
        }

        self.last_activity_ms = now_ms;
        Ok(())
    }

    /// 送るべき 1 フラグメント(handshake resp / データセグメント / standalone ack)を
    /// `out` に書いて長さを返す。なければ `Ok(0)`。
    pub fn process_outgoing(
        &mut self,
        out: &mut [u8],
        _mtu: Option<u16>,
        now_ms: u64,
    ) -> Result<usize> {
        // 1. peripheral の handshake resp。
        if self.resp_pending {
            let resp = HandshakeResp {
                version: BTP_VERSION,
                fragment: self.fragment as u16,
                window: self.window_size,
            };
            let n = resp.encode(out)?;
            self.resp_pending = false;
            self.phase = Phase::Established;
            self.last_activity_ms = now_ms;
            return Ok(n);
        }

        if self.phase != Phase::Established {
            return Ok(0);
        }

        // 2. データセグメント(window に空きがあれば)。piggyback ACK を優先。
        if self.tx.is_pending() && self.send.can_send() {
            let beginning = self.tx.at_beginning();
            let ack = self.recv.take_ack();
            let header_len = 1 + usize::from(ack.is_some()) + 1 + usize::from(beginning) * 2;
            let max_payload = self.fragment.saturating_sub(header_len);

            let mut payload = [0u8; BTP_MAX_FRAGMENT];
            let (is_beg, is_end, n) = self.tx.take_chunk(max_payload, &mut payload);

            let mut flags = HeaderFlags::empty();
            if is_beg {
                flags.insert(HeaderFlags::BEGINNING);
            }
            if is_end {
                flags.insert(HeaderFlags::ENDING);
            }
            if !is_beg && !is_end {
                flags.insert(HeaderFlags::CONTINUING);
            }
            let msg_len = if is_beg {
                Some(self.tx.total_len() as u16)
            } else {
                None
            };
            let seq = self.send.take_data_seq(now_ms);
            let hdr = BtpHeader {
                flags,
                ack,
                seq,
                msg_len,
            };
            let written = self.emit(&hdr, &payload[..n], out)?;
            self.last_activity_ms = now_ms;
            return Ok(written);
        }

        // 3. standalone ACK(期限到達)。純粋 ACK は window 枠を消費しないので
        //    window 満杯でも送れる(ACK 応酬でのデッドロックを避ける)。
        if self.recv.ack_due(now_ms) {
            let ack = self.recv.take_ack();
            let seq = self.send.take_ack_seq();
            let hdr = BtpHeader {
                flags: HeaderFlags::empty(),
                ack,
                seq,
                msg_len: None,
            };
            let written = self.emit(&hdr, &[], out)?;
            self.last_activity_ms = now_ms;
            return Ok(written);
        }

        Ok(0)
    }

    /// ヘッダ + payload を `out` に連結して書き、総長を返す。
    fn emit(&self, hdr: &BtpHeader, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let hlen = hdr.encode(out)?;
        let end = hlen + payload.len();
        out.get_mut(hlen..end)
            .ok_or(Error::NoSpace)?
            .copy_from_slice(payload);
        Ok(end)
    }

    /// 上位が 1 Matter メッセージ(SDU)を送信キューに載せる。
    ///
    /// 前の SDU が未送出なら [`Error::InvalidState`](1 本ずつ)。未確立なら [`Error::InvalidState`]。
    /// 長すぎる SDU は [`Error::NoSpace`]。
    pub fn send(&mut self, sdu: &[u8], _now_ms: u64) -> Result<()> {
        if self.phase != Phase::Established {
            return Err(Error::InvalidState);
        }
        self.tx.load(sdu)
    }

    /// 送信キューが空(次の [`Btp::send`] を受けられる)なら `true`。
    pub const fn can_send(&self) -> bool {
        !self.tx.is_pending()
    }

    /// 再組立済みの 1 Matter メッセージを取り出す(なければ `None`)。取り出すと消費する。
    pub fn recv(&mut self) -> Option<&[u8]> {
        self.rx.take()
    }

    /// ACK / idle / liveness タイマの最も早い期限。統合層が `next_deadline` と `min` する。
    pub fn next_deadline(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        let mut merge = |d: Option<u64>| {
            if let Some(d) = d {
                earliest = Some(match earliest {
                    Some(e) => e.min(d),
                    None => d,
                });
            }
        };
        // standalone ACK 送出期限。
        merge(self.recv.ack_deadline());
        if matches!(self.phase, Phase::Established) {
            // idle タイムアウト。
            merge(Some(self.last_activity_ms.saturating_add(BTP_IDLE_TIMEOUT_MS)));
            // 未 ACK の liveness タイムアウト。
            if self.send.unacked() > 0 {
                if let Some(t) = self.send.last_tx_ms() {
                    merge(Some(t.saturating_add(BTP_ACK_TIMEOUT_MS)));
                }
            }
        }
        earliest
    }

    /// セッションが切断すべき状態(ACK / idle タイムアウト到達)なら `true`。
    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        if !matches!(self.phase, Phase::Established) {
            return false;
        }
        // 未 ACK 放置(ACK タイムアウト)。
        if self.send.unacked() > 0 {
            if let Some(t) = self.send.last_tx_ms() {
                if now_ms >= t.saturating_add(BTP_ACK_TIMEOUT_MS) {
                    return true;
                }
            }
        }
        // 無通信(idle タイムアウト)。
        now_ms >= self.last_activity_ms.saturating_add(BTP_IDLE_TIMEOUT_MS)
    }

    /// セッションを初期状態へ戻す(切断時)。
    pub fn reset(&mut self) {
        let (tx_seq, rx_seq) = match self.role {
            BtpRole::Central => (1u8, 0u8),
            BtpRole::Peripheral => (0u8, 1u8),
        };
        self.phase = Phase::Idle;
        self.fragment = 0;
        self.window_size = 0;
        self.send.reset(tx_seq);
        self.recv.reset(rx_seq);
        self.tx.reset();
        self.rx.reset();
        self.resp_pending = false;
        self.last_activity_ms = 0;
    }

    /// peripheral: handshake request を処理し、resp を送出待ちにする。
    fn on_handshake_req(&mut self, frag: &[u8], mtu: Option<u16>) -> Result<()> {
        if self.role != BtpRole::Peripheral || self.phase != Phase::Idle {
            return Err(Error::InvalidState);
        }
        let req = HandshakeReq::decode(frag)?;
        if !req.supports_v4() {
            return Err(Error::InvalidState);
        }
        // フラグメントは、自機 ATT_MTU(既知なら)と相手提示 MTU の小さい方から算出。
        let att_mtu = match mtu {
            Some(m) => m.min(req.mtu),
            None => req.mtu,
        };
        let fragment = if att_mtu == 0 {
            fragment_size(None)
        } else {
            fragment_size(Some(att_mtu))
        };
        let window = req.window.min(Self::local_window_cap()).max(1);
        self.negotiate(fragment, window);
        self.resp_pending = true;
        Ok(())
    }

    /// central: handshake response を処理し確立する。
    fn on_handshake_resp(&mut self, frag: &[u8]) -> Result<()> {
        if self.role != BtpRole::Central || self.phase != Phase::Handshaking {
            return Err(Error::InvalidState);
        }
        let resp = HandshakeResp::decode(frag)?;
        if resp.version != BTP_VERSION {
            return Err(Error::InvalidState);
        }
        let fragment = (resp.fragment as usize).clamp(BTP_MIN_FRAGMENT, BTP_MAX_FRAGMENT);
        let window = resp.window.min(Self::local_window_cap()).max(1);
        self.negotiate(fragment, window);
        self.phase = Phase::Established;
        Ok(())
    }

    /// 交渉結果(フラグメント / window)を両 window へ反映する。
    fn negotiate(&mut self, fragment: usize, window: u8) {
        self.fragment = fragment;
        self.window_size = window;
        self.send.set_window(window);
        self.recv.set_window(window);
    }
}

#[cfg(test)]
mod tests;
