//! セッション管理:固定容量セッションテーブルと、受信メッセージの二段デコード結合部。
//!
//! `docs/design/transport-exchange.md` §4 に基づく。
//!
//! # enum 判別(typestate ではない)
//!
//! セッション種別(Unsecured / PASE / CASE)は [`SessionMode`] enum で判別する。
//! 固定容量テーブルは同型要素の配列でなければ成立しないため、typestate ではなく
//! enum を選ぶ(§4.1)。typestate の安全性は「鍵取得 getter が `mode` を見て
//! [`Option`] を返す」ことで実質的に確保する(設計判断 1)。PlainText では鍵 getter が
//! `None` を返し、[`SecureCodec`](super::secure::SecureCodec) が復号をスキップする。
//!
//! # 二段デコードの型強制(§3.3)
//!
//! [`SessionManager::decode_rx`] が受信経路を 1 本にまとめる。手順は
//!
//! 1. [`PacketHeader::decode`] で Session ID を得る(復号不要)。
//! 2. Session を解決して鍵を取得する。
//! 3. [`SecureCodec::decrypt`](super::secure::SecureCodec::decrypt) に鍵を渡して
//!    初めて [`PayloadHeader`] が得られる。
//!
//! この順序により「セッション未解決のまま payload を読む」コードが書けない。
//!
//! # 時刻の扱い
//!
//! アクティビティ時刻(LRU 退避キー)は外部から `now_ms`(単調増加するミリ秒)として
//! 渡す。これにより本層は `embassy-time` 等の時間クレートに依存せず、std 上の
//! テストも容易になる(§12 論点 1、依存追加の回避)。

use core::num::NonZeroU8;

use crate::crypto::{Crypto, AES_CCM_KEY_LEN};
use crate::error::{Error, Result};
use crate::transport::header::{DstNodeId, PacketHeader, PayloadHeader};
use crate::transport::net::PeerAddr;
use crate::transport::secure::{AeadKeyRef, SecureCodec};
use crate::transport::util::ParseBuf;

pub mod fixed;
use fixed::FixedVec;

/// セッションの安定ハンドル。
///
/// 配列 slot の位置とは独立に、セッションの生存中は変わらない不透明な識別子。
/// rs-matter のような bit-packing はせず、単なる採番値として扱う(§5.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u32);

impl SessionId {
    /// 内部の生値を返す(ロギング用途など)。
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// 生値から [`SessionId`] を構築する。
    ///
    /// 通常は [`SessionManager`] が採番するが、上位層(exchange)がハンドルを合成する
    /// 用途やテストのために公開する。
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// セッション種別。鍵は常に struct に存在するが、getter が `mode` で gating する。
///
/// グループ(マルチキャスト)セッションは本ピースのスコープ外。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionMode {
    /// 非暗号(Unsecured)。PASE/CASE の第 1 メッセージ用。鍵 getter は `None`。
    #[default]
    PlainText,
    /// PASE セッション。fabric 未確定のため `fabric_idx = 0` で開始し、AddNOC で
    /// 1 度だけ昇格する。
    Pase {
        /// 所属 fabric インデックス(0 = 未確定)。
        fabric_idx: u8,
    },
    /// CASE(運用)セッション。確立時に fabric インデックスが確定している。
    Case {
        /// 所属 fabric インデックス(非ゼロ)。
        fabric_idx: NonZeroU8,
    },
}

impl SessionMode {
    /// この種別が暗号化されているなら `true`(= 鍵 getter が `Some` を返す)。
    pub const fn is_encrypted(self) -> bool {
        !matches!(self, SessionMode::PlainText)
    }

    /// 所属 fabric インデックスを返す(PlainText は 0)。
    pub const fn fabric_idx(self) -> u8 {
        match self {
            SessionMode::PlainText => 0,
            SessionMode::Pase { fabric_idx } => fabric_idx,
            SessionMode::Case { fabric_idx } => fabric_idx.get(),
        }
    }
}

/// テーブル slot の状態。
///
/// 退避(LRU)の優先順位に用いる。`Reserved` はハンドシェイク中で退避不可、
/// `Expired` は退避の最優先候補(§4.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// ハンドシェイク中に確保だけした未確定 slot(退避不可)。
    Reserved,
    /// 確立済みで通常運用中。
    Active,
    /// 期限切れ(fabric 削除等)。退避の最優先候補。
    Expired,
}

/// 1 セッションが保持できる CASE peer の CAT 最大数(NOC あたり最大 3、Matter 仕様)。
pub const MAX_SESSION_CATS: usize = 3;

/// セッション確立(または予約 slot への commit)に必要なパラメータ。
///
/// ハンドシェイク完了時に `sc` 層がこの値を作って [`SessionManager::insert`] または
/// [`SessionManager::commit`] へ渡す。PlainText セッションでは鍵は無視されるため
/// ゼロでよい。
#[derive(Debug, Clone)]
pub struct SessionInit {
    /// ピアのアドレス(返信先。正規化しない生アドレス)。
    pub peer_addr: PeerAddr,
    /// 自ノードの Node ID(TX nonce に用いる。Unsecured レスポンダでは 0)。
    pub local_node_id: u64,
    /// ピアの Node ID(RX nonce に用いる。未確定なら `None`)。
    pub peer_node_id: Option<u64>,
    /// ピア側が採番したワイヤ Session ID(TX 時に用いる宛先 Session ID)。
    pub peer_session_id: u16,
    /// 送信メッセージカウンタの初期値(仕様上は乱数推奨)。
    pub tx_ctr_start: u32,
    /// 受信リプレイ窓の初期最大カウンタ。
    pub rx_ctr_start: u32,
    /// セッション種別。
    pub mode: SessionMode,
    /// 送信(暗号化)鍵。PlainText では無視。
    pub enc_key: [u8; AES_CCM_KEY_LEN],
    /// 受信(復号)鍵。PlainText では無視。
    pub dec_key: [u8; AES_CCM_KEY_LEN],
    /// アテステーションチャレンジ(CASE/PASE で用いる 16 バイト)。
    pub att_challenge: [u8; 16],
}

impl SessionInit {
    /// 非暗号(Unsecured)セッション用の最小構成を作る。
    ///
    /// 鍵とチャレンジはゼロで、`mode` は [`SessionMode::PlainText`]。
    pub const fn plaintext(peer_addr: PeerAddr, peer_session_id: u16, tx_ctr_start: u32) -> Self {
        Self {
            peer_addr,
            local_node_id: 0,
            peer_node_id: None,
            peer_session_id,
            tx_ctr_start,
            rx_ctr_start: 0,
            mode: SessionMode::PlainText,
            enc_key: [0u8; AES_CCM_KEY_LEN],
            dec_key: [0u8; AES_CCM_KEY_LEN],
            att_challenge: [0u8; 16],
        }
    }
}

use crate::transport::counter::{LocalCounter, PeerWindow};

/// セッションテーブルの 1 エントリ。
///
/// enum 判別([`SessionMode`])で同型に格納する。鍵は常に保持するが、公開 getter は
/// `mode` で gating し、PlainText では `None` を返す(設計判断 1)。
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    peer_addr: PeerAddr,
    local_node_id: u64,
    peer_node_id: Option<u64>,
    /// CASE peer の NOC に含まれる CAT(ACL 照合用。先頭 `peer_cat_count` 件が有効)。
    peer_cats: [u32; MAX_SESSION_CATS],
    /// `peer_cats` の有効件数。
    peer_cat_count: u8,
    local_session_id: u16,
    peer_session_id: u16,
    enc_key: [u8; AES_CCM_KEY_LEN],
    dec_key: [u8; AES_CCM_KEY_LEN],
    att_challenge: [u8; 16],
    tx_ctr: LocalCounter,
    rx_window: PeerWindow,
    mode: SessionMode,
    last_use: u64,
    state: SlotState,
}

impl Session {
    /// 安定ハンドルを返す。
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// ピアのアドレス(返信先)を返す。
    pub const fn peer_addr(&self) -> PeerAddr {
        self.peer_addr
    }

    /// 自ノードの Node ID を返す。
    pub const fn local_node_id(&self) -> u64 {
        self.local_node_id
    }

    /// ピアの Node ID を返す(未確定なら `None`)。
    pub const fn peer_node_id(&self) -> Option<u64> {
        self.peer_node_id
    }

    /// CASE peer の CAT(CASE Authenticated Tag)群を返す(フル CASE 確立時のみ非空)。
    pub fn peer_cats(&self) -> &[u32] {
        &self.peer_cats[..self.peer_cat_count as usize]
    }

    /// CASE peer の CAT 群を設定する(Sigma3 検証後に sc 層が呼ぶ。先頭
    /// [`MAX_SESSION_CATS`] 件に丸める)。
    pub fn set_peer_cats(&mut self, cats: &[u32]) {
        let n = cats.len().min(MAX_SESSION_CATS);
        self.peer_cats[..n].copy_from_slice(&cats[..n]);
        self.peer_cat_count = n as u8;
    }

    /// ピアの Node ID が未確定の場合のみ設定する。
    ///
    /// 非セキュアセッションで、イニシエータの最初のパケットの source Node ID
    /// (エフェメラル ID)を記録するために使う。確定済みの値は上書きしない。
    pub fn set_peer_node_id_if_unset(&mut self, id: Option<u64>) {
        if self.peer_node_id.is_none() {
            self.peer_node_id = id;
        }
    }

    /// 自分側のワイヤ Session ID を返す。
    pub const fn local_session_id(&self) -> u16 {
        self.local_session_id
    }

    /// ピア側のワイヤ Session ID を返す(TX 時の宛先 Session ID)。
    pub const fn peer_session_id(&self) -> u16 {
        self.peer_session_id
    }

    /// セッション種別を返す。
    pub const fn mode(&self) -> SessionMode {
        self.mode
    }

    /// slot 状態を返す。
    pub const fn state(&self) -> SlotState {
        self.state
    }

    /// このセッションが暗号化されているなら `true`。
    pub const fn is_encrypted(&self) -> bool {
        self.mode.is_encrypted()
    }

    /// このセッションで MRP(R/A フラグ・再送・standalone ACK)を使うべきか。
    ///
    /// UDP のみ `true`。BTP は seq/ack/window による信頼トランスポートなので `false`
    /// (二重信頼を避ける)。chip の `Session::AllowsMRP()` の写像で、`peer_addr` から
    /// 分岐する(暗号種別に依らず unsecured/PASE/CASE すべてに一様に効く)。
    /// `feature = "ble"` 無効時は `PeerAddr` が UDP のみ = 常に `true` で、既存挙動と
    /// 完全一致する(`docs/design/ble-btp.md` §3.2)。
    pub const fn allows_mrp(&self) -> bool {
        match self.peer_addr {
            PeerAddr::Udp(_) => true,
            #[cfg(feature = "ble")]
            PeerAddr::Ble(_) => false,
        }
    }

    /// 復号鍵を返す。PlainText では `None`(= [`SecureCodec`] が復号スキップ)。
    ///
    /// [`SecureCodec`](super::secure::SecureCodec) に渡す唯一の鍵取得点で、未確立
    /// セッションで暗号鍵を使えない構造を担保する(設計判断 1)。
    pub fn dec_key(&self) -> Option<AeadKeyRef<'_>> {
        self.mode.is_encrypted().then_some(&self.dec_key)
    }

    /// 暗号化鍵を返す。PlainText では `None`。
    pub fn enc_key(&self) -> Option<AeadKeyRef<'_>> {
        self.mode.is_encrypted().then_some(&self.enc_key)
    }

    /// アテステーションチャレンジを返す(暗号セッションのみ)。
    pub fn att_challenge(&self) -> Option<&[u8; 16]> {
        self.mode.is_encrypted().then_some(&self.att_challenge)
    }

    /// 次の送信メッセージカウンタを払い出す。
    pub fn next_tx_ctr(&mut self) -> u32 {
        self.tx_ctr.next()
    }

    /// 次に払い出す送信カウンタを覗く(消費しない)。
    pub const fn peek_tx_ctr(&self) -> u32 {
        self.tx_ctr.peek()
    }

    /// 受信リプレイ窓への参照を返す。
    pub const fn rx_window(&self) -> &PeerWindow {
        &self.rx_window
    }

    /// 期限切れ(退避最優先)なら `true`。
    pub const fn is_expired(&self) -> bool {
        matches!(self.state, SlotState::Expired)
    }

    /// 予約中(退避不可)なら `true`。
    pub const fn is_reserved(&self) -> bool {
        matches!(self.state, SlotState::Reserved)
    }

    /// 最終利用時刻を `now_ms` に更新する。
    fn touch(&mut self, now_ms: u64) {
        self.last_use = now_ms;
    }

    /// 受信パケットがこのセッション宛かを判定する(ユニキャストのみ)。
    ///
    /// `exact_addr` が true ならピアアドレスの完全一致を要求する。false のときは、同じピアが
    /// 別の自アドレスから応答した場合に限りアドレス不一致を許容する(下記)。
    fn matches_rx(&self, peer: PeerAddr, pkt: &PacketHeader, exact_addr: bool) -> bool {
        if self.is_reserved() {
            return false;
        }
        // 暗号種別の一致(暗号セッションに平文パケットは来ない、逆も同様)。
        if self.is_encrypted() != pkt.is_encrypted() {
            return false;
        }
        // ワイヤ Session ID の一致。
        if self.local_session_id != pkt.session_id {
            return false;
        }
        // ピア Node ID の一致(いずれかが未確定なら不問)。
        let node_ok = match (self.peer_node_id, pkt.src_node_id) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        };
        if !node_ok {
            return false;
        }
        // Unsecured セッションは、宛先 Node ID の echo でも曖昧性を解消する。
        let mut echoed_local_node = false;
        if !self.is_encrypted() && self.local_node_id != 0 {
            if let DstNodeId::Unicast(dst) = pkt.dst {
                if dst != self.local_node_id {
                    return false;
                }
                echoed_local_node = true;
            }
        }
        // ピアアドレスの一致(IPv4-mapped IPv6 を吸収するため正規化して比較)。
        //
        // ただし複数の IPv6 アドレスを持つピアは、こちらが送った宛先とは別の自アドレスを送信元に
        // 選んで応答することがある(送信元アドレス選択は相手の宛先 = こちらの送信元との最長一致。
        // 実機: OTBR が WiFi 側に 2 つ目の ULA プレフィックスを広告した後、AirQ が Sigma1 への応答を
        // 別プレフィックスのアドレスから返し、コントローラが全て捨てて CASE が成立しなくなった)。
        // Matter のセッションはアドレスに束縛されない(chip も暗号セッションは Session ID + MIC、
        // 未認証セッションはエフェメラル Node ID で照合する)ので、同じトランスポート種別なら
        //   - 暗号セッション: ワイヤ Session ID の一致(このあと MIC で認証される)
        //   - Unsecured: こちらのエフェメラル Node ID が宛先に echo されている
        // の場合に限りアドレス不一致を許容する。送信先(`peer_addr`)は更新しない。
        if self.peer_addr.canonical() != peer.canonical() {
            if exact_addr {
                return false;
            }
            let same_transport = matches!(
                (&self.peer_addr, &peer),
                (PeerAddr::Udp(_), PeerAddr::Udp(_))
            );
            if !(same_transport && (self.is_encrypted() || echoed_local_node)) {
                return false;
            }
        }
        true
    }

    /// CASE 運用セッションが `(fabric, node)` に一致するなら `true`。
    fn matches_node(&self, fabric_idx: NonZeroU8, peer_node_id: u64) -> bool {
        !self.is_reserved()
            && self.is_encrypted()
            && self.mode.fabric_idx() == fabric_idx.get()
            && self.peer_node_id == Some(peer_node_id)
    }
}

/// 固定容量のセッションテーブル。
///
/// `SESSIONS` 個の [`Session`] を詰めて格納し、参照は安定な [`SessionId`] で行う
/// (配列 slot は削除時の swap_remove で不安定)。サイジングは const generic で指定する
/// (§8)。定常パスでヒープ確保しない。
#[derive(Debug)]
pub struct SessionManager<const SESSIONS: usize> {
    sessions: FixedVec<Session, SESSIONS>,
    /// 安定 [`SessionId`] の採番カウンタ(ラップ)。
    next_id: u32,
    /// ワイヤ Session ID の採番カウンタ(0 と使用中を回避)。
    next_local_sid: u16,
}

impl<const SESSIONS: usize> Default for SessionManager<SESSIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SESSIONS: usize> SessionManager<SESSIONS> {
    /// 空のセッションテーブルを生成する。
    pub const fn new() -> Self {
        Self {
            sessions: FixedVec::new(),
            next_id: 0,
            next_local_sid: 1,
        }
    }

    /// テーブルの最大容量(セッション数)を返す。
    pub const fn capacity(&self) -> usize {
        SESSIONS
    }

    /// 現在のセッション数を返す。
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// セッションが 1 つも無ければ `true`。
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// テーブルが満杯なら `true`。
    pub fn is_full(&self) -> bool {
        self.sessions.is_full()
    }

    /// 次の安定 [`SessionId`] を採番する。
    fn alloc_id(&mut self) -> SessionId {
        let id = SessionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// 使用中でない(0 でもない)ワイヤ Session ID を採番する。
    fn alloc_local_sid(&mut self) -> u16 {
        loop {
            let sid = self.next_local_sid;
            self.next_local_sid = self.next_local_sid.wrapping_add(1);
            if self.next_local_sid == 0 {
                self.next_local_sid = 1;
            }
            if self.sessions.iter().all(|s| s.local_session_id != sid) {
                return sid;
            }
        }
    }

    /// スライス index からセッション参照を得る内部ヘルパ。
    fn index_of(&self, id: SessionId) -> Option<usize> {
        self.sessions.iter().position(|s| s.id == id)
    }

    /// [`SessionId`] でセッションを取得する(参照)。
    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.index_of(id).map(|i| &self.sessions[i])
    }

    /// [`SessionId`] でセッションを取得し、最終利用時刻を更新する(可変)。
    pub fn get_mut(&mut self, id: SessionId, now_ms: u64) -> Option<&mut Session> {
        let i = self.index_of(id)?;
        self.sessions[i].touch(now_ms);
        Some(&mut self.sessions[i])
    }

    /// 受信パケット向けにセッションを解決し、最終利用時刻を更新する。
    ///
    /// ワイヤ Session ID・ピアアドレス・ピア Node ID で照合する(§4.3)。
    pub fn find_for_rx(
        &mut self,
        peer: PeerAddr,
        pkt: &PacketHeader,
        now_ms: u64,
    ) -> Option<&mut Session> {
        // アドレスまで一致するセッションを優先する。エフェメラル Node ID は同一スタックの複数の
        // Unsecured セッションで共有されうる(実機: 別ノード宛の古いハンドシェイク用セッションが
        // 残っていると、緩い照合だけでは応答をそちらへ取り違える)ため、緩い照合は完全一致が
        // 無いときのフォールバックに限る。
        let i = self
            .sessions
            .iter()
            .position(|s| s.matches_rx(peer, pkt, true))
            .or_else(|| {
                // 緩い照合の候補が複数あるときは、直近に使われたもの(= いま応答を待っている
                // ハンドシェイク)を選ぶ。
                self.sessions
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.matches_rx(peer, pkt, false))
                    .max_by_key(|(_, s)| s.last_use)
                    .map(|(i, _)| i)
            })?;
        self.sessions[i].touch(now_ms);
        Some(&mut self.sessions[i])
    }

    /// `(fabric, node)` の CASE 運用セッションを解決し、最終利用時刻を更新する。
    pub fn find_for_node(
        &mut self,
        fabric_idx: NonZeroU8,
        peer_node_id: u64,
        now_ms: u64,
    ) -> Option<&mut Session> {
        let i = self
            .sessions
            .iter()
            .position(|s| s.matches_node(fabric_idx, peer_node_id))?;
        self.sessions[i].touch(now_ms);
        Some(&mut self.sessions[i])
    }

    /// 退避(LRU)候補の index を選ぶ。
    ///
    /// Expired を最優先、次いで予約でない最古(`last_use` 最小)のセッションを選ぶ。
    /// いずれも無ければ `None`(= 全 slot が予約中で退避不可)。
    ///
    /// なお「生存 exchange を持たないこと」を退避条件に加えるのは ExchangeManager の
    /// 実装後(次ピース)。現段階では expired 優先 + LRU のみで判定する(§4.3、乖離)。
    fn eviction_candidate(&self) -> Option<usize> {
        let mut best: Option<(usize, u64)> = None;
        for (i, s) in self.sessions.iter().enumerate() {
            if s.is_reserved() {
                continue;
            }
            if s.is_expired() {
                // Expired は最優先。即決。
                return Some(i);
            }
            match best {
                Some((_, ts)) if s.last_use >= ts => {}
                _ => best = Some((i, s.last_use)),
            }
        }
        best.map(|(i, _)| i)
    }

    /// 満杯なら 1 セッションを退避してから push する内部ヘルパ。
    fn push_evicting(&mut self, session: Session) -> Result<SessionId> {
        if self.sessions.is_full() {
            let victim = self.eviction_candidate().ok_or(Error::NoSpace)?;
            self.sessions.swap_remove(victim);
        }
        let id = session.id;
        self.sessions.push(session).map_err(|_| Error::NoSpace)?;
        Ok(id)
    }

    /// 確立済みセッションを挿入する(ハンドシェイク完了時に `sc` 層が呼ぶ)。
    ///
    /// 満杯なら [`eviction_candidate`](Self::eviction_candidate) 方針で 1 つ退避する。
    /// 退避不可(全予約中)なら [`Error::NoSpace`]。
    pub fn insert(&mut self, init: SessionInit, now_ms: u64) -> Result<SessionId> {
        let id = self.alloc_id();
        // Unsecured セッションのワイヤ Session ID は常に 0(仕様)。暗号セッションのみ採番する。
        let local_session_id = if init.mode.is_encrypted() {
            self.alloc_local_sid()
        } else {
            0
        };
        let session = Session {
            id,
            peer_addr: init.peer_addr,
            local_node_id: init.local_node_id,
            peer_node_id: init.peer_node_id,
            peer_cats: [0; MAX_SESSION_CATS],
            peer_cat_count: 0,
            local_session_id,
            peer_session_id: init.peer_session_id,
            enc_key: init.enc_key,
            dec_key: init.dec_key,
            att_challenge: init.att_challenge,
            tx_ctr: LocalCounter::new(init.tx_ctr_start),
            rx_window: PeerWindow::new(init.rx_ctr_start),
            mode: init.mode,
            last_use: now_ms,
            state: SlotState::Active,
        };
        self.push_evicting(session)
    }

    /// 2 相コミットの第 1 相:予約 slot を確保して安定 ID とワイヤ Session ID を採番する。
    ///
    /// ハンドシェイク(PASE/CASE)開始時に容量を先取りし、「確立前に他要求でテーブルが
    /// 埋まる」競合を防ぐ(§4.3)。予約 slot は [`SlotState::Reserved`] で退避されない。
    /// 未 commit のまま不要になったら [`remove`](Self::remove) で解放する。
    pub fn reserve(&mut self, peer_addr: PeerAddr, now_ms: u64) -> Result<SessionId> {
        let id = self.alloc_id();
        let local_session_id = self.alloc_local_sid();
        let session = Session {
            id,
            peer_addr,
            local_node_id: 0,
            peer_node_id: None,
            peer_cats: [0; MAX_SESSION_CATS],
            peer_cat_count: 0,
            local_session_id,
            peer_session_id: 0,
            enc_key: [0u8; AES_CCM_KEY_LEN],
            dec_key: [0u8; AES_CCM_KEY_LEN],
            att_challenge: [0u8; 16],
            tx_ctr: LocalCounter::new(0),
            rx_window: PeerWindow::new(0),
            mode: SessionMode::PlainText,
            last_use: now_ms,
            state: SlotState::Reserved,
        };
        // 満杯時は insert と同じ方針で退避する(Expired 優先 → 予約以外の LRU)。
        // 新しいハンドシェイクは新鮮なピアの意思表示であり、古いセッションを残して
        // Busy を返し続けるより退避して受け入れる方が回復性が高い(chip も同様)。
        self.push_evicting(session)
    }

    /// 予約 slot に確立パラメータを書き込み [`SlotState::Active`] へ昇格する(第 2 相)。
    ///
    /// 予約時に採番したワイヤ Session ID は保持する(既にピアへ広告済みのため)。
    /// `id` が予約中でなければ [`Error::InvalidState`]、存在しなければ [`Error::NotFound`]。
    pub fn commit(&mut self, id: SessionId, init: SessionInit, now_ms: u64) -> Result<()> {
        let i = self.index_of(id).ok_or(Error::NotFound)?;
        let s = &mut self.sessions[i];
        if !s.is_reserved() {
            return Err(Error::InvalidState);
        }
        s.peer_addr = init.peer_addr;
        s.local_node_id = init.local_node_id;
        s.peer_node_id = init.peer_node_id;
        s.peer_cats = [0; MAX_SESSION_CATS];
        s.peer_cat_count = 0;
        s.peer_session_id = init.peer_session_id;
        s.enc_key = init.enc_key;
        s.dec_key = init.dec_key;
        s.att_challenge = init.att_challenge;
        s.tx_ctr = LocalCounter::new(init.tx_ctr_start);
        s.rx_window = PeerWindow::new(init.rx_ctr_start);
        s.mode = init.mode;
        s.state = SlotState::Active;
        s.touch(now_ms);
        Ok(())
    }

    /// PASE セッションを確定した fabric へ紐付ける(`docs/design/interaction-model.md` §9.4)。
    ///
    /// Operational Credentials の AddNOC 成功時に、`SessionMode::Pase { fabric_idx: 0 }`
    /// の未確定 PASE セッションを採番済み fabric インデックスへ 1 度だけ昇格する。
    /// これは sc の `commit`(予約→確立)と対称の 1 点変更で、IM が
    /// [`SessionManager`] を可変に触る唯一の箇所である(設計 §12 論点 5)。
    ///
    /// `id` が存在しなければ [`Error::NotFound`]、PASE でなければ [`Error::InvalidState`]。
    pub fn promote_pase_fabric(&mut self, id: SessionId, fabric_idx: NonZeroU8) -> Result<()> {
        let i = self.index_of(id).ok_or(Error::NotFound)?;
        let s = &mut self.sessions[i];
        match s.mode {
            SessionMode::Pase { .. } => {
                s.mode = SessionMode::Pase {
                    fabric_idx: fabric_idx.get(),
                };
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }

    /// セッションを削除して返す。存在しなければ `None`。
    pub fn remove(&mut self, id: SessionId) -> Option<Session> {
        let i = self.index_of(id)?;
        Some(self.sessions.swap_remove(i))
    }

    /// セッションを [`SlotState::Expired`] にする(退避最優先化)。存在すれば `true`。
    pub fn expire(&mut self, id: SessionId) -> bool {
        match self.index_of(id) {
            Some(i) => {
                self.sessions[i].state = SlotState::Expired;
                true
            }
            None => false,
        }
    }

    /// セッションを走査するイテレータ。
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }

    /// 受信メッセージの二段デコード結合部(§3.3)。
    ///
    /// `buf` は 1 datagram 全体を保持する [`ParseBuf`]。手順は
    ///
    /// 1. [`PacketHeader::decode`] で平文ヘッダを読む。
    /// 2. [`find_for_rx`](Self::find_for_rx) でセッションを解決し鍵を取得する。
    /// 3. [`SecureCodec::decrypt`] で復号し [`PayloadHeader`] を得る。
    /// 4. リプレイ窓([`PeerWindow`])で重複/リプレイを判定する。
    ///
    /// 成功時は解決した [`SessionId`] と [`PayloadHeader`] を返し、`buf` の残りが
    /// アプリケーション payload を指す。セッション不明は [`Error::NotFound`]、
    /// 復号失敗は [`Error::Crypto`]、リプレイ/重複は [`Error::Duplicate`]。
    ///
    /// exchange 層は重複メッセージでも再 ACK 判定のため PayloadHeader を必要とするため、
    /// 実処理は [`decode_rx_detailed`](Self::decode_rx_detailed) に委譲し、本関数はその
    /// 薄いラッパとして重複を [`Error::Duplicate`] に射影する(既存呼び出し互換)。
    ///
    /// # 設計との乖離(§10 のデータフロー順序)
    ///
    /// §10 の全体像スケッチはリプレイ判定を復号の**前**に置くが、本実装は参照実装
    /// (rs-matter は `decode_remaining` → `post_recv` の順)に倣い**復号後**に
    /// リプレイ窓を進める。MIC 検証を通過していないパケットで受信窓を汚染される
    /// (正当メッセージの取りこぼし)ことを防ぐためで、二段デコードの型強制(§3.3、
    /// セッション解決 → 鍵 → 復号の順)は保つ。
    pub fn decode_rx<C: Crypto>(
        &mut self,
        crypto: &C,
        peer: PeerAddr,
        now_ms: u64,
        buf: &mut ParseBuf<'_>,
    ) -> Result<(SessionId, PayloadHeader)> {
        let decoded = self.decode_rx_detailed(crypto, peer, now_ms, buf)?;
        if decoded.duplicate {
            return Err(Error::Duplicate);
        }
        Ok((decoded.session, decoded.header))
    }

    /// 二段デコードを行い、重複でも [`PayloadHeader`] を保持したまま結果を返す。
    ///
    /// [`decode_rx`](Self::decode_rx) と手順は同じだが、リプレイ窓で弾かれた場合でも
    /// エラーにせず [`DecodedRx::duplicate`] を `true` にして返す。exchange 層は重複した
    /// 信頼メッセージに対し ACK を再送する(こちらの ACK がロストした可能性への対処、
    /// 設計 §6)ため、重複時も Exchange ID や信頼フラグ・受信カウンタを知る必要がある。
    ///
    /// 窓は重複時には進めない([`PeerWindow::accept`] が `false` 時に状態を変えない)。
    /// セッション不明は [`Error::NotFound`]、復号失敗は [`Error::Crypto`]。
    pub fn decode_rx_detailed<C: Crypto>(
        &mut self,
        crypto: &C,
        peer: PeerAddr,
        now_ms: u64,
        buf: &mut ParseBuf<'_>,
    ) -> Result<DecodedRx> {
        // 1. 平文ヘッダ。
        let pkt = PacketHeader::decode(buf)?;

        // 2. セッション解決 → 鍵取得。鍵は借用の絡みを避けるためスタックへ複製する。
        let (id, key_copy, peer_node_id) = {
            let session = self
                .find_for_rx(peer, &pkt, now_ms)
                .ok_or(Error::NotFound)?;
            let key_copy = session.dec_key().copied();
            (session.id, key_copy, session.peer_node_id.unwrap_or(0))
        };

        // 3. 復号(暗号境界)。ここで初めて PayloadHeader が得られる。
        let phdr = SecureCodec::decrypt(crypto, key_copy.as_ref(), &pkt, peer_node_id, buf)?;

        // 4. リプレイ窓を復号後に進める(§10 との乖離、上記参照)。
        let session = self.get_mut(id, now_ms).ok_or(Error::NotFound)?;
        let encrypted = session.is_encrypted();
        let accepted = session.rx_window.accept(pkt.ctr, encrypted);

        Ok(DecodedRx {
            session: id,
            header: phdr,
            msg_ctr: pkt.ctr,
            duplicate: !accepted,
        })
    }
}

/// [`SessionManager::decode_rx_detailed`] の結果。
///
/// 復号済みの [`PayloadHeader`] に加え、ACK 生成に必要な受信メッセージカウンタと、
/// リプレイ窓による重複判定を持つ。
#[derive(Debug, Clone, Copy)]
pub struct DecodedRx {
    /// 解決したセッションの安定ハンドル。
    pub session: SessionId,
    /// 復号済みの暗号内ヘッダ。
    pub header: PayloadHeader,
    /// 受信メッセージカウンタ([`PacketHeader::ctr`])。ACK 対象として用いる。
    pub msg_ctr: u32,
    /// リプレイ窓で重複/窓外と判定された(受理はしていない)なら `true`。
    pub duplicate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::Rng;
    use crate::transport::header::{ExchFlags, PayloadHeader, SecFlags};
    use crate::transport::secure::SecureCodec;
    use crate::transport::util::WriteBuf;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    struct ZeroRng;
    impl Rng for ZeroRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            dest.fill(0);
            Ok(())
        }
    }
    fn crypto() -> RustCrypto<ZeroRng> {
        RustCrypto::new(ZeroRng)
    }

    fn addr(port: u16) -> PeerAddr {
        PeerAddr::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port,
        ))
    }

    fn secure_init(peer_addr: PeerAddr, key: [u8; 16], mode_fab: u8) -> SessionInit {
        let mode = SessionMode::Case {
            fabric_idx: NonZeroU8::new(mode_fab).unwrap(),
        };
        SessionInit {
            peer_addr,
            local_node_id: 0x1111_2222_3333_4444,
            peer_node_id: Some(0x5555_6666_7777_8888),
            peer_session_id: 0x00AA,
            tx_ctr_start: 100,
            rx_ctr_start: 0,
            mode,
            enc_key: key,
            dec_key: key,
            att_challenge: [0x33u8; 16],
        }
    }

    #[test]
    fn insert_allocates_distinct_ids_and_wire_sids() {
        let mut mgr: SessionManager<4> = SessionManager::new();
        let key = [0u8; 16];
        let a = mgr.insert(secure_init(addr(1), key, 1), 0).unwrap();
        let b = mgr.insert(secure_init(addr(2), key, 1), 0).unwrap();
        assert_ne!(a, b);
        let sid_a = mgr.get(a).unwrap().local_session_id();
        let sid_b = mgr.get(b).unwrap().local_session_id();
        assert_ne!(sid_a, sid_b);
        // 暗号セッションのワイヤ Session ID は 0 を避ける。
        assert_ne!(sid_a, 0);
        assert_ne!(sid_b, 0);
        // 非暗号セッションのワイヤ Session ID は常に 0。
        let p = mgr
            .insert(SessionInit::plaintext(addr(3), 0, 0), 0)
            .unwrap();
        assert_eq!(mgr.get(p).unwrap().local_session_id(), 0);
        assert_eq!(mgr.len(), 3);
    }

    #[test]
    fn wire_sid_allocation_skips_in_use_and_zero() {
        // next_local_sid を人工的に 0 付近・衝突付近へ持っていく。暗号セッションで検証。
        let mut mgr: SessionManager<4> = SessionManager::new();
        let key = [0u8; 16];
        // 1 個入れて local_sid=1 を消費、次は 2。
        let first = mgr.insert(secure_init(addr(1), key, 1), 0).unwrap();
        assert_eq!(mgr.get(first).unwrap().local_session_id(), 1);
        // カウンタを u16::MAX にして 0 スキップを踏ませる。
        mgr.next_local_sid = u16::MAX;
        let second = mgr.insert(secure_init(addr(2), key, 1), 0).unwrap();
        assert_eq!(mgr.get(second).unwrap().local_session_id(), u16::MAX);
        // 次は 0 を飛ばして 1 だが 1 は使用中 → 2 になる。
        let third = mgr.insert(secure_init(addr(3), key, 1), 0).unwrap();
        assert_eq!(mgr.get(third).unwrap().local_session_id(), 2);
    }

    #[test]
    fn key_getters_gate_on_mode() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        // 非暗号:鍵は None。
        let p = mgr
            .insert(SessionInit::plaintext(addr(1), 0, 0), 0)
            .unwrap();
        assert!(mgr.get(p).unwrap().dec_key().is_none());
        assert!(mgr.get(p).unwrap().enc_key().is_none());
        assert!(mgr.get(p).unwrap().att_challenge().is_none());
        // 暗号:鍵は Some。
        let key = [0x11u8; 16];
        let c = mgr.insert(secure_init(addr(2), key, 1), 0).unwrap();
        assert_eq!(mgr.get(c).unwrap().dec_key(), Some(&key));
        assert_eq!(mgr.get(c).unwrap().enc_key(), Some(&key));
        assert!(mgr.get(c).unwrap().att_challenge().is_some());
    }

    #[test]
    fn lookup_by_rx_and_node() {
        let mut mgr: SessionManager<4> = SessionManager::new();
        let key = [0x22u8; 16];
        let id = mgr.insert(secure_init(addr(5540), key, 2), 10).unwrap();
        let sid = mgr.get(id).unwrap().local_session_id();

        // RX 照合:ワイヤ Session ID + アドレス + ピア Node ID。
        let pkt = PacketHeader {
            session_id: sid,
            sec_flags: SecFlags::from_bits(0),
            ctr: 1,
            src_node_id: Some(0x5555_6666_7777_8888),
            dst: DstNodeId::None,
        };
        let found = mgr.find_for_rx(addr(5540), &pkt, 20).unwrap();
        assert_eq!(found.id(), id);

        // 暗号セッションはアドレスに束縛しない(複数アドレスを持つピアが別の送信元から応答しうる。
        // Session ID が一致すれば照合し、正当性は MIC で確認する)。
        assert_eq!(mgr.find_for_rx(addr(9999), &pkt, 20).unwrap().id(), id);
        // Session ID 違いは不一致。
        let other = PacketHeader {
            session_id: sid.wrapping_add(1),
            ..pkt
        };
        assert!(mgr.find_for_rx(addr(5540), &other, 20).is_none());

        // (fabric, node) 照合。
        let fab = NonZeroU8::new(2).unwrap();
        let by_node = mgr.find_for_node(fab, 0x5555_6666_7777_8888, 30).unwrap();
        assert_eq!(by_node.id(), id);
        assert!(mgr.find_for_node(fab, 0xDEAD, 30).is_none());
    }

    /// Unsecured セッション(initiator 側、エフェメラル Node ID あり)は、応答の宛先 Node ID に自分の
    /// エフェメラル ID が echo されていれば、送信元アドレスが違っても照合する(実機: 複数 ULA を持つ
    /// デバイスが Sigma1 の宛先とは別のアドレスから応答した)。echo が無い/違う場合は従来どおり不一致。
    #[test]
    fn unsecured_rx_matches_by_echoed_ephemeral_node_id_across_addresses() {
        let mut mgr: SessionManager<4> = SessionManager::new();
        let mut init = SessionInit::plaintext(addr(5540), 0, 0);
        init.local_node_id = 0x1122_3344_5566_7788;
        let id = mgr.insert(init, 0).unwrap();

        let reply = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr: 1,
            src_node_id: None,
            dst: DstNodeId::Unicast(0x1122_3344_5566_7788),
        };
        // 同じアドレス、別アドレスのどちらからでも照合する。
        assert_eq!(mgr.find_for_rx(addr(5540), &reply, 1).unwrap().id(), id);
        assert_eq!(mgr.find_for_rx(addr(7777), &reply, 1).unwrap().id(), id);

        // 同じエフェメラル ID の Unsecured セッションが複数あるときは、アドレス一致を優先する。
        let mut init2 = SessionInit::plaintext(addr(7777), 0, 0);
        init2.local_node_id = 0x1122_3344_5566_7788;
        let id2 = mgr.insert(init2, 0).unwrap();
        assert_eq!(mgr.find_for_rx(addr(7777), &reply, 1).unwrap().id(), id2);
        assert_eq!(mgr.find_for_rx(addr(5540), &reply, 1).unwrap().id(), id);
        assert!(mgr.remove(id2).is_some());

        // 宛先 Node ID が違えば不一致。
        let wrong = PacketHeader {
            dst: DstNodeId::Unicast(0xDEAD),
            ..reply
        };
        assert!(mgr.find_for_rx(addr(5540), &wrong, 1).is_none());

        // echo が無い平文パケットは、アドレスが違えば不一致(responder 側の新規ハンドシェイク等)。
        let no_echo = PacketHeader {
            dst: DstNodeId::None,
            ..reply
        };
        assert!(mgr.find_for_rx(addr(7777), &no_echo, 1).is_none());
        assert_eq!(mgr.find_for_rx(addr(5540), &no_echo, 1).unwrap().id(), id);
    }

    #[test]
    fn full_table_evicts_lru() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let a = mgr
            .insert(SessionInit::plaintext(addr(1), 0, 0), 100)
            .unwrap();
        let b = mgr
            .insert(SessionInit::plaintext(addr(2), 0, 0), 200)
            .unwrap();
        // a を触って新しくする → b が LRU。
        mgr.get_mut(a, 300);
        let c = mgr
            .insert(SessionInit::plaintext(addr(3), 0, 0), 400)
            .unwrap();
        assert_eq!(mgr.len(), 2);
        assert!(mgr.get(a).is_some());
        assert!(mgr.get(b).is_none(), "LRU の b が退避される");
        assert!(mgr.get(c).is_some());
    }

    #[test]
    fn expired_is_evicted_first() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let a = mgr
            .insert(SessionInit::plaintext(addr(1), 0, 0), 100)
            .unwrap();
        let b = mgr
            .insert(SessionInit::plaintext(addr(2), 0, 0), 200)
            .unwrap();
        // a を最新に、しかし b を expired 化 → b が退避される。
        mgr.get_mut(a, 50); // a を最古にしても
        assert!(mgr.expire(b));
        let c = mgr
            .insert(SessionInit::plaintext(addr(3), 0, 0), 400)
            .unwrap();
        assert!(mgr.get(a).is_some());
        assert!(mgr.get(b).is_none(), "expired の b が最優先で退避される");
        assert!(mgr.get(c).is_some());
    }

    #[test]
    fn reserved_slots_are_not_evicted() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let r = mgr.reserve(addr(1), 100).unwrap();
        let _a = mgr
            .insert(SessionInit::plaintext(addr(2), 0, 0), 200)
            .unwrap();
        // 満杯。予約 r は退避されず、退避候補は a のみ。
        assert!(mgr.is_full());
        let c = mgr
            .insert(SessionInit::plaintext(addr(3), 0, 0), 300)
            .unwrap();
        assert!(mgr.get(r).is_some(), "予約 slot は退避されない");
        assert!(mgr.get(c).is_some());
    }

    #[test]
    fn reserve_full_of_reserved_fails() {
        let mut mgr: SessionManager<1> = SessionManager::new();
        let _r = mgr.reserve(addr(1), 0).unwrap();
        // 全て予約中で退避不可 → NoSpace。
        assert_eq!(
            mgr.insert(SessionInit::plaintext(addr(2), 0, 0), 0),
            Err(Error::NoSpace)
        );
        // 予約自体も満杯なら失敗。
        assert_eq!(mgr.reserve(addr(3), 0), Err(Error::NoSpace));
    }

    #[test]
    fn reserve_then_commit_keeps_wire_sid() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let id = mgr.reserve(addr(1), 0).unwrap();
        let sid = mgr.get(id).unwrap().local_session_id();
        assert!(mgr.get(id).unwrap().is_reserved());
        let key = [0x44u8; 16];
        mgr.commit(id, secure_init(addr(1), key, 1), 10).unwrap();
        let s = mgr.get(id).unwrap();
        assert_eq!(s.state(), SlotState::Active);
        assert_eq!(s.local_session_id(), sid, "ワイヤ Session ID は保持される");
        assert_eq!(s.dec_key(), Some(&key));
        // 既に Active な slot への commit は不正状態。
        assert_eq!(
            mgr.commit(id, secure_init(addr(1), key, 1), 10),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn remove_and_expire_edge_cases() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let a = mgr
            .insert(SessionInit::plaintext(addr(1), 0, 0), 0)
            .unwrap();
        assert!(mgr.remove(a).is_some());
        assert!(mgr.remove(a).is_none());
        assert!(!mgr.expire(a));
    }

    /// 受信経路の二段デコード:平文セッション(復号なし)の自己往復。
    #[test]
    fn decode_rx_plaintext_round_trip() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        // 平文セッションを挿入(ワイヤ Session ID は 0)。
        let id = mgr.insert(SessionInit::plaintext(peer, 0, 0), 0).unwrap();
        assert_eq!(mgr.get(id).unwrap().local_session_id(), 0);

        // 平文メッセージを組み立てる(session_id=0、鍵なし)。
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr: 1,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let payload = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
            proto_opcode: 0x20,
            exch_id: 0x0001,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: None,
        };
        let app: &[u8] = &[0x15, 0x18];
        let mut wire = [0u8; 128];
        let n = {
            let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
            let mut store = [0u8; 128];
            let mut w = WriteBuf::new(&mut store, headroom).unwrap();
            w.append(app).unwrap();
            SecureCodec::encrypt(&crypto(), None, &pkt, &payload, 0, &mut w).unwrap();
            wire[..w.len()].copy_from_slice(w.as_slice());
            w.len()
        };

        let mut pb = ParseBuf::new(&mut wire[..n]);
        let (rid, ph) = mgr.decode_rx(&crypto(), peer, 10, &mut pb).unwrap();
        assert_eq!(rid, id);
        assert_eq!(ph.exch_id, 0x0001);
        assert_eq!(pb.as_slice(), app);
    }

    /// 受信経路の二段デコード:暗号セッションの自己往復と復号後リプレイ判定。
    #[test]
    fn decode_rx_encrypted_round_trip_and_replay() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        let key = [0x11u8; 16];
        let peer_node = 0x5555_6666_7777_8888u64;

        let mut init = secure_init(peer, key, 1);
        init.peer_addr = peer;
        init.peer_node_id = Some(peer_node);
        let id = mgr.insert(init, 0).unwrap();
        let sid = mgr.get(id).unwrap().local_session_id();

        // 暗号メッセージを組み立てる(nonce の src = peer_node)。
        let build = |ctr: u32, wire: &mut [u8]| -> usize {
            let pkt = PacketHeader {
                session_id: sid,
                sec_flags: SecFlags::from_bits(0),
                ctr,
                src_node_id: None,
                dst: DstNodeId::None,
            };
            let payload = PayloadHeader {
                exch_flags: ExchFlags::from_bits(ExchFlags::RELIABLE),
                proto_opcode: 0x05,
                exch_id: 0x9abc,
                proto_id: 0x0001,
                vendor_id: None,
                ack_ctr: None,
            };
            let app: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
            let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
            let mut store = [0u8; 128];
            let mut w = WriteBuf::new(&mut store, headroom).unwrap();
            w.append(app).unwrap();
            SecureCodec::encrypt(&crypto(), Some(&key), &pkt, &payload, peer_node, &mut w).unwrap();
            wire[..w.len()].copy_from_slice(w.as_slice());
            w.len()
        };

        // ctr=5 を受理。
        let mut wire = [0u8; 128];
        let n = build(5, &mut wire);
        let mut pb = ParseBuf::new(&mut wire[..n]);
        let (rid, ph) = mgr.decode_rx(&crypto(), peer, 10, &mut pb).unwrap();
        assert_eq!(rid, id);
        assert_eq!(ph.proto_opcode, 0x05);
        assert_eq!(pb.as_slice(), &[0xDE, 0xAD, 0xBE, 0xEF]);

        // 同じ ctr=5 の再送 = リプレイ。復号は成功するが窓が弾く。
        let mut wire2 = [0u8; 128];
        let n2 = build(5, &mut wire2);
        let mut pb2 = ParseBuf::new(&mut wire2[..n2]);
        assert_eq!(
            mgr.decode_rx(&crypto(), peer, 11, &mut pb2),
            Err(Error::Duplicate)
        );

        // ctr=6 は新規で受理。
        let mut wire3 = [0u8; 128];
        let n3 = build(6, &mut wire3);
        let mut pb3 = ParseBuf::new(&mut wire3[..n3]);
        assert!(mgr.decode_rx(&crypto(), peer, 12, &mut pb3).is_ok());
    }

    /// UDP セッションは MRP を許可し、BTP(BLE)セッションは許可しない(§3.2)。
    #[cfg(feature = "ble")]
    #[test]
    fn allows_mrp_is_true_for_udp_false_for_ble() {
        use crate::transport::net::BtpConnId;
        let mut mgr: SessionManager<2> = SessionManager::new();
        // UDP unsecured。
        let udp = mgr
            .insert(SessionInit::plaintext(addr(5540), 0, 0), 0)
            .unwrap();
        assert!(mgr.get(udp).unwrap().allows_mrp());
        // BTP unsecured。
        let ble_peer = PeerAddr::Ble(BtpConnId(3));
        let ble = mgr
            .insert(SessionInit::plaintext(ble_peer, 0, 0), 0)
            .unwrap();
        assert!(!mgr.get(ble).unwrap().allows_mrp());
    }

    #[test]
    fn decode_rx_unknown_session_is_not_found() {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let peer = addr(5540);
        // セッション未確立。適当な暗号ヘッダ(session_id=7)。
        let pkt = PacketHeader {
            session_id: 7,
            sec_flags: SecFlags::from_bits(0),
            ctr: 1,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let mut store = [0u8; 64];
        let n = {
            let mut w = WriteBuf::new(&mut store, 0).unwrap();
            pkt.encode(&mut w).unwrap();
            w.append(&[0u8; 20]).unwrap(); // ダミー暗号文
            w.len()
        };
        let mut pb = ParseBuf::new(&mut store[..n]);
        assert_eq!(
            mgr.decode_rx(&crypto(), peer, 0, &mut pb),
            Err(Error::NotFound)
        );
    }
}
