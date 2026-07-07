//! 統合層(スタック組み立て):単一 poll 駆動の Matter デバイススタック。
//!
//! `docs/design/transport-exchange.md` §9 の「DefaultStack・単一 poll 駆動」に基づき、
//! [`SessionManager`] + TX バッファプール + [`ExchangeManager`] + [`ProtocolMux`]
//! ([`SecureChannel`] + [`InteractionModel`])+ 共有 [`FabricTable`] を 1 つの型
//! [`MatterStack`] に束ねる。const generic のサイジングはプロファイル型エイリアス
//! [`DefaultStack`] で隠す。
//!
//! # 単一駆動 API(sans-IO 維持)
//!
//! ソケットには触れず、バイト列と時刻だけを扱う:
//!
//! - [`MatterStack::handle_rx`] — 受信 datagram を処理し、送るべき応答があれば
//!   [`SendDirective`] を返す(バイト列は呼び出し側の `tx_out` に書かれる)。
//! - [`MatterStack::poll`] — 時間駆動の送出(MRP 再送・standalone ACK・購読レポート)を
//!   1 件返す。[`SendDirective`] が `None` になるまで繰り返し呼ぶ。
//! - [`MatterStack::next_deadline`] — 次に [`poll`](MatterStack::poll) すべき絶対時刻。
//!
//! MRP 再送・standalone ACK・SC ハンドシェイクタイムアウト・fail-safe 期限・IM 購読レポートを
//! すべて 1 つの deadline/poll 系に統合する。
//!
//! # fabric テーブルの共有(統合の要)
//!
//! CASE responder([`SecureChannel`] の型引数 `F`)は AddNOC で追加された fabric を
//! Sigma2 で読む必要がある。OpCreds クラスタ([`InteractionModel`] 内)と CASE は同一の
//! [`ProtocolMux`] に格納されるため相互参照できない。よって [`FabricTable`] は**呼び出し側が
//! 所有する `RefCell`** に置き、CASE 側([`SharedFabricCreds`])と OpCreds 側
//! ([`OpCredsCluster::new_shared`](crate::dm::clusters::OpCredsCluster::new_shared))の
//! 両方が `&'s RefCell<FabricTable>` で参照する(自己参照を避ける、設計判断)。
//!
//! # コミッショニング窓(最小)
//!
//! 本統合層は「コミッショニング窓は常時開」を採る(最小構成)。PASE は
//! [`PaseConfig`](crate::sc::PaseConfig) が設定されている限り常に受理する。窓の開閉・タイムアウト
//! (OpenCommissioningWindow)は本ピースのスコープ外(discovery/platform 統合と連動、乖離)。

use core::cell::{Ref, RefCell};
use core::num::NonZeroU8;

use crate::buf::BufferPool;
use crate::crypto::{Crypto, Rng};
use crate::dm::DataModel;
use crate::exchange::{
    ExchangeId, ExchangeManager, HandlerAction, Outgoing, PollAction, ProtocolMux, SendTiming,
};
use crate::fabric::{FabricCredentials, FabricEntry, FabricTable};
use crate::im::engine::InteractionModel;
use crate::im::wire::{ImOpCode, PROTO_ID_INTERACTION_MODEL};
use crate::sc::case::creds::{Fabric, FabricStore, NocResolver, PeerIdentity};
use crate::sc::SecureChannel;
use crate::transport::header::{PacketHeader, PayloadHeader};
use crate::transport::net::PeerAddr;
use crate::transport::session::{SessionId, SessionInit, SessionManager};
use crate::transport::util::{ParseBuf, WriteBuf};

/// スタックが扱う 1 パケットの最大バイト数(TX バッファ・`tx_out` のサイズ目安)。
///
/// CASE Sigma2(responder NOC/ICAC を含む)を 1 datagram で送れるよう、ワイヤ上限
/// (`MAX_RX_PACKET_SIZE`)以上の余裕を取る。
pub const MAX_PACKET_SIZE: usize = 1600;

/// 統合層が返す送信指示。
///
/// バイト列は [`MatterStack::handle_rx`] / [`MatterStack::poll`] に渡した `tx_out` の先頭
/// [`len`](SendDirective::len) バイトに書かれる。呼び出し側はそれを [`addr`](SendDirective::addr)
/// へ 1 datagram として送る(ソケット操作は呼び出し側の責務、sans-IO)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendDirective {
    /// 送信先。
    pub addr: PeerAddr,
    /// `tx_out` に書かれた送信バイト数。
    pub len: usize,
}

/// PASE / CASE responder が話す Secure Channel(0x0000)ハンドラの型。
type Sc<'s, C, R, const NF: usize, const H: usize> =
    SecureChannel<'s, C, R, SharedFabricCreds<'s, C, NF>, H>;

/// スタックが用いる enum mux(SC + IM)。
type Mux<
    's,
    C,
    R,
    D,
    const NF: usize,
    const H: usize,
    const READS: usize,
    const SUBS: usize,
    const PATHS: usize,
> = ProtocolMux<Sc<'s, C, R, NF, H>, InteractionModel<D, READS, SUBS, PATHS>>;

/// 単一 poll 駆動の Matter デバイススタック(設計 §9)。
///
/// 型引数は `C`(暗号 backend)/ `R`(乱数)/ `D`(デバイス [`DataModel`])と、サイジングの
/// const generic。`'s` は共有する crypto と [`FabricTable`](`RefCell`)の借用寿命。数値は
/// プロファイルエイリアス [`DefaultStack`] で隠せる。
pub struct MatterStack<
    's,
    C: Crypto,
    R: Rng,
    D: DataModel,
    const NF: usize,
    const SESSIONS: usize,
    const EXCHANGES: usize,
    const TX_BUFS: usize,
    const HANDSHAKES: usize,
    const READS: usize,
    const SUBS: usize,
    const PATHS: usize,
> {
    crypto: &'s C,
    sessions: SessionManager<SESSIONS>,
    mgr: ExchangeManager<Mux<'s, C, R, D, NF, HANDSHAKES, READS, SUBS, PATHS>, EXCHANGES>,
    tx_pool: BufferPool<TX_BUFS, MAX_PACKET_SIZE>,
    /// ハンドラが応答 payload を書く作業バッファ(平文)。
    resp: [u8; MAX_PACKET_SIZE],
}

impl<
        's,
        C: Crypto,
        R: Rng,
        D: DataModel,
        const NF: usize,
        const SESSIONS: usize,
        const EXCHANGES: usize,
        const TX_BUFS: usize,
        const HANDSHAKES: usize,
        const READS: usize,
        const SUBS: usize,
        const PATHS: usize,
    > MatterStack<'s, C, R, D, NF, SESSIONS, EXCHANGES, TX_BUFS, HANDSHAKES, READS, SUBS, PATHS>
{
    /// crypto 参照・構築済み [`SecureChannel`] と [`InteractionModel`] からスタックを組む。
    ///
    /// `sc` の `F` は [`SharedFabricCreds`](CASE 用 fabric ビュー)、`im` の `D` は
    /// [`OpCredsCluster::new_shared`](crate::dm::clusters::OpCredsCluster::new_shared) で
    /// **同一の** `RefCell<FabricTable>` を参照するデバイスであること(fabric 共有の前提)。
    pub fn new(
        crypto: &'s C,
        sc: Sc<'s, C, R, NF, HANDSHAKES>,
        im: InteractionModel<D, READS, SUBS, PATHS>,
    ) -> Self {
        Self {
            crypto,
            sessions: SessionManager::new(),
            mgr: ExchangeManager::new(ProtocolMux::new(sc, im)),
            tx_pool: BufferPool::new(),
            resp: [0u8; MAX_PACKET_SIZE],
        }
    }

    /// セッションテーブルへの共有参照。
    pub const fn sessions(&self) -> &SessionManager<SESSIONS> {
        &self.sessions
    }

    /// IM エンジンへの共有参照(属性の読み取り等)。
    pub fn im(&self) -> &InteractionModel<D, READS, SUBS, PATHS> {
        &self.mgr.handler().im
    }

    /// IM エンジンへの可変参照(属性の変更・購読操作等)。
    pub fn im_mut(&mut self) -> &mut InteractionModel<D, READS, SUBS, PATHS> {
        &mut self.mgr.handler_mut().im
    }

    /// デバイス([`DataModel`])への共有参照。
    pub fn device(&self) -> &D {
        self.mgr.handler().im.data_model()
    }

    /// デバイス([`DataModel`])への可変参照(アプリからの状態変更)。
    pub fn device_mut(&mut self) -> &mut D {
        self.mgr.handler_mut().im.data_model_mut()
    }

    /// PASE 設定を差し替える(OpenCommissioningWindow の動的 verifier 注入。
    /// `docs/design/admin-commissioning.md` §4)。
    pub fn set_pase_config(&mut self, config: crate::sc::PaseConfig) {
        self.mgr.handler_mut().sc.set_pase_config(config);
    }

    /// PASE 受理ゲートを切り替える(コミッショニング窓の開閉)。
    ///
    /// `false` の間、新規 PBKDFParamRequest には Busy StatusReport が返る。確立済み
    /// セッションには影響しない。
    pub fn set_pase_enabled(&mut self, enabled: bool) {
        self.mgr.handler_mut().sc.set_pase_enabled(enabled);
    }

    /// 次に [`poll`](Self::poll) すべき最も早い絶対時刻(ミリ秒)。
    ///
    /// MRP 再送/ACK 期限([`ExchangeManager::next_deadline`])と IM 購読レポート期限
    /// ([`InteractionModel::next_deadline`])を min する。SC ハンドシェイクタイムアウトと
    /// fail-safe 期限は各 `handle_rx`/`poll` で掃引するため、ここには含めない(乖離、上記)。
    pub fn next_deadline(&self, now_ms: u64) -> Option<u64> {
        let a = self.mgr.next_deadline();
        let b = self.mgr.handler().im.next_deadline(now_ms);
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, None) => x,
            (None, y) => y,
        }
    }

    /// セッションを明示的に閉じ、IM の購読/継続をそれに紐づけて破棄する。
    ///
    /// fabric 削除・CloseSession 受信などで用いる。存在しないセッションは無視する。
    pub fn close_session(&mut self, session: SessionId) {
        self.sessions.remove(session);
        self.mgr.handler_mut().im.on_session_closed(session);
    }

    /// 時間駆動の内部掃引(SC ハンドシェイクタイムアウト・IM 掃除・fail-safe 期限)。
    fn drive_ticks(&mut self, now_ms: u64) {
        self.mgr
            .handler_mut()
            .sc
            .on_tick(&mut self.sessions, now_ms);
        self.mgr.handler_mut().im.on_tick(now_ms);
        let _ = self.mgr.handler_mut().im.data_model_mut().on_tick(now_ms);
    }

    /// 受信 datagram を処理し、送るべき応答があれば [`SendDirective`] を返す(sans-IO)。
    ///
    /// `datagram` は 1 datagram 全体(先頭が [`PacketHeader`])。`tx_out` は応答ワイヤバイト列を
    /// 書き出す呼び出し側バッファ([`MAX_PACKET_SIZE`] 以上)。不正入力(復号失敗・未知
    /// セッション・デコードエラー)は静かにドロップし `None` を返す(panic しない)。
    pub fn handle_rx(
        &mut self,
        datagram: &mut [u8],
        peer: PeerAddr,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        self.drive_ticks(now_ms);
        self.ensure_unsecured_session(datagram, peer, now_ms);

        let report = match self.mgr.recv(
            &mut self.sessions,
            self.crypto,
            peer,
            now_ms,
            datagram,
            &mut self.resp,
        ) {
            Ok(r) => r,
            Err(_) => return None,
        };

        if let Some(freed) = report.freed_tx {
            self.tx_pool.release(freed);
        }

        match report.action {
            HandlerAction::None => None,
            // 相手の終端メッセージを受理した(応答なし)。exchange を終端予約し、
            // 未送 ACK が流れ次第 poll が slot を回収する。
            HandlerAction::CloseSilent => {
                if let Some(ex) = report.exchange {
                    self.mgr.mark_closing(ex);
                }
                None
            }
            HandlerAction::Respond {
                opcode,
                proto_id,
                reliable,
                len,
            } => {
                let ex = report.exchange?;
                self.stage_response(ex, proto_id, opcode, reliable, len, now_ms, tx_out)
            }
            // Close も Respond と同じく送出するが、会話は終端予約(mark_closing)する。
            // 信頼送信の最終応答は ACK まで再送責務が残るため即時 close はせず、
            // MRP 静穏後に ExchangeManager::poll が slot を回収する。
            HandlerAction::Close {
                opcode,
                proto_id,
                reliable,
                len,
            } => {
                let ex = report.exchange?;
                let dir = self.stage_response(ex, proto_id, opcode, reliable, len, now_ms, tx_out);
                self.mgr.mark_closing(ex);
                dir
            }
        }
    }

    /// 時間駆動の送出を 1 件返す(MRP 再送・standalone ACK・購読レポート)。
    ///
    /// [`SendDirective`] が `None`(= やることなし)になるまで繰り返し呼ぶ。`tx_out` は
    /// [`MAX_PACKET_SIZE`] 以上。
    pub fn poll(&mut self, now_ms: u64, tx_out: &mut [u8]) -> Option<SendDirective> {
        self.drive_ticks(now_ms);

        loop {
            match self.mgr.poll(now_ms, now_ms as u8) {
                PollAction::Retransmit { buf, len, addr, .. } => {
                    let src = self.tx_pool.get(buf).ok()?;
                    if len > tx_out.len() || len > src.len() {
                        return None;
                    }
                    tx_out[..len].copy_from_slice(&src[..len]);
                    return Some(SendDirective { addr, len });
                }
                PollAction::SendAck { exchange, ack_ctr } => {
                    if let Some(d) = self.stage_standalone_ack(exchange, ack_ctr, now_ms, tx_out) {
                        return Some(d);
                    }
                    // ACK 構築に失敗した場合は次の poll 対象へ進む。
                }
                PollAction::Failed { freed_tx, .. } => {
                    self.tx_pool.release(freed_tx);
                    // 会話は除去済み。購読レポートの失敗は次段の poll_subscriptions が検知しない
                    // ため best-effort(乖離:exchange→subscription 逆引きは未実装)。
                }
                PollAction::Idle { .. } => break,
            }
        }

        if let Some(d) = self.stage_subscription_report(now_ms, tx_out) {
            return Some(d);
        }
        self.stage_deferred_invoke_response(now_ms, tx_out)
    }

    /// 未確立の unsecured セッションが必要なら(平文パケット・未登録の peer)先に確保する。
    ///
    /// PASE / CASE の第 1 メッセージは session_id=0 の平文で届く。responder はそれを受けるための
    /// unsecured セッションを 1 本持つ必要がある。既存があれば何もしない。
    fn ensure_unsecured_session(&mut self, datagram: &[u8], peer: PeerAddr, now_ms: u64) {
        // 平文ヘッダのみを覗く(復号しない)。`ParseBuf::new` は read-only 参照でよい。
        let mut scratch = [0u8; PacketHeader::MAX_LEN];
        let n = datagram.len().min(scratch.len());
        scratch[..n].copy_from_slice(&datagram[..n]);
        let mut pb = ParseBuf::new(&mut scratch[..n]);
        let hdr = match PacketHeader::decode(&mut pb) {
            Ok(h) => h,
            Err(_) => return,
        };
        if hdr.is_encrypted() {
            return;
        }
        if let Some(session) = self.sessions.find_for_rx(peer, &hdr, now_ms) {
            // 既存の平文セッションでもピア Node ID が未確定なら、受信ヘッダの
            // source Node ID で確定させる(以降の応答の宛先 echo に使う)。
            session.set_peer_node_id_if_unset(hdr.src_node_id);
            return;
        }
        let mut init = SessionInit::plaintext(peer, 0, 1);
        // イニシエータのエフェメラル source Node ID を記録し、応答時に宛先 Node ID
        // として echo する(chip 側の非セキュアパケット検証が source/destination の
        // いずれかを必須とするため)。
        init.peer_node_id = hdr.src_node_id;
        let _ = self.sessions.insert(init, now_ms);
    }

    /// ハンドラが `self.resp` に書いた応答 payload をワイヤ化して `tx_out` に置く。
    #[allow(clippy::too_many_arguments)]
    fn stage_response(
        &mut self,
        ex: ExchangeId,
        proto_id: u16,
        opcode: u8,
        reliable: bool,
        len: usize,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        if len > self.resp.len() {
            return None;
        }
        // BTP セッションでは reliable → unreliable へ格下げ(R フラグなし・再送スロット
        // 非登録)。信頼性は下位の BTP が担う(`docs/design/ble-btp.md` §3.3)。
        let reliable = reliable
            && self
                .sessions
                .get(ex.session())
                .map(|s| s.allows_mrp())
                .unwrap_or(true);
        let msg = Outgoing {
            proto_id,
            opcode,
            payload: &self.resp[..len],
        };
        if reliable {
            let sent = self
                .mgr
                .send_reliable(
                    &mut self.sessions,
                    self.crypto,
                    &mut self.tx_pool,
                    ex,
                    &msg,
                    SendTiming {
                        now_ms,
                        jitter_rand: now_ms as u8,
                    },
                )
                .ok()?;
            let src = self.tx_pool.get(sent.buf).ok()?;
            if sent.len > tx_out.len() || sent.len > src.len() {
                return None;
            }
            tx_out[..sent.len].copy_from_slice(&src[..sent.len]);
            Some(SendDirective {
                addr: sent.addr,
                len: sent.len,
            })
        } else {
            let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
            let (addr, start, end) = {
                let mut wb = WriteBuf::new(tx_out, headroom).ok()?;
                let addr = self
                    .mgr
                    .send_unreliable(&mut self.sessions, self.crypto, ex, &msg, &mut wb, now_ms)
                    .ok()?;
                (addr, wb.start(), wb.end())
            };
            tx_out.copy_within(start..end, 0);
            Some(SendDirective {
                addr,
                len: end - start,
            })
        }
    }

    /// standalone ACK(SC opcode 0x10)を組み立てて `tx_out` に置く。
    fn stage_standalone_ack(
        &mut self,
        ex: ExchangeId,
        ack_ctr: u32,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let (addr, start, end) = {
            let mut wb = WriteBuf::new(tx_out, headroom).ok()?;
            let addr = self
                .mgr
                .build_standalone_ack(
                    &mut self.sessions,
                    self.crypto,
                    ex,
                    ack_ctr,
                    &mut wb,
                    now_ms,
                )
                .ok()?;
            (addr, wb.start(), wb.end())
        };
        tx_out.copy_within(start..end, 0);
        Some(SendDirective {
            addr,
            len: end - start,
        })
    }

    /// 期限到達 or dirty の購読を 1 件レポートする(device 発、設計 §6.3)。
    fn stage_subscription_report(
        &mut self,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        let due = self.mgr.handler_mut().im.poll_subscriptions(now_ms)?;
        let ex = self.mgr.open_initiator(due.session).ok()?;
        let len = match self.mgr.handler_mut().im.build_report(
            due.subscription,
            ex,
            &mut self.resp,
            now_ms,
        ) {
            Ok(n) => n,
            Err(_) => {
                let _ = self.mgr.close(ex);
                return None;
            }
        };
        let msg = Outgoing {
            proto_id: PROTO_ID_INTERACTION_MODEL,
            opcode: ImOpCode::ReportData.to_u8(),
            payload: &self.resp[..len],
        };
        let sent = match self.mgr.send_reliable(
            &mut self.sessions,
            self.crypto,
            &mut self.tx_pool,
            ex,
            &msg,
            SendTiming {
                now_ms,
                jitter_rand: now_ms as u8,
            },
        ) {
            Ok(s) => s,
            Err(_) => {
                let _ = self.mgr.close(ex);
                return None;
            }
        };
        let src = self.tx_pool.get(sent.buf).ok()?;
        if sent.len > tx_out.len() || sent.len > src.len() {
            return None;
        }
        tx_out[..sent.len].copy_from_slice(&src[..sent.len]);
        Some(SendDirective {
            addr: sent.addr,
            len: sent.len,
        })
    }

    /// 保留中の遅延 InvokeResponse を **元の responder exchange** に送出する(設計 §E7.2)。
    ///
    /// cluster が完了(または締切超過)していれば InvokeResponse を組み立てて `send_reliable`
    /// し、`mark_closing` で終端予約する。まだ完了していなければ何もしない(次 poll で再試行)。
    /// exchange が消えていればスロットを破棄する。再送保留中(`send_reliable` の InvalidState)は
    /// ドロップせず後続の poll で再試行する。
    fn stage_deferred_invoke_response(
        &mut self,
        now_ms: u64,
        tx_out: &mut [u8],
    ) -> Option<SendDirective> {
        let ex = self.mgr.handler().im.poll_deferred_invoke(now_ms)?;
        // 送出先 exchange が消えていたらスロット破棄(セッション/会話が先に死んだ)。
        if !self.mgr.contains(ex) {
            self.mgr.handler_mut().im.drop_deferred();
            return None;
        }
        // 元応答の再送が保留中なら send_reliable は InvalidState。次 poll まで待つ
        //(応答はまだ組み立てない=スロット保持)。
        if self.mgr.is_retrans_pending(ex) {
            return None;
        }
        // 応答を組み立てる(スロットはここでは消さない。送信成功後に drop する)。
        let len = match self.mgr.handler_mut().im.build_deferred_invoke_response(
            ex,
            &mut self.resp,
            now_ms,
        ) {
            Ok(Some(n)) => n,
            // まだ完了していない(Pending かつ締切内)。
            Ok(None) => return None,
            // スロット不整合等。破棄して stall を避ける。
            Err(_) => {
                self.mgr.handler_mut().im.drop_deferred();
                return None;
            }
        };
        // 送出は即時応答と同じ `stage_response` に委譲する(BTP セッションでの
        // reliable→unreliable 格下げを含む。BTP に MRP 再送スロットを登録すると
        // ACK が来ず再送が閉じた BLE リンクへ飛ぶ)。失敗時はスロットを保持して
        // 次 poll で再試行する。
        let d = self.stage_response(
            ex,
            PROTO_ID_INTERACTION_MODEL,
            ImOpCode::InvokeResponse.to_u8(),
            true,
            len,
            now_ms,
            tx_out,
        )?;
        // 送信成功。スロットを消し、exchange を終端予約する(ACK 静穏後に回収)。
        self.mgr.handler_mut().im.drop_deferred();
        self.mgr.mark_closing(ex);
        Some(d)
    }
}

// ==========================================================================
// CASE 用の共有 fabric ビュー(FabricStore + NocResolver)
// ==========================================================================

/// CASE responder(SC の型引数 `F`)が参照する **共有 fabric ビュー**。
///
/// OpCreds クラスタと同一の外部所有 `RefCell<FabricTable>` を参照し、AddNOC で追加された fabric を
/// Sigma2/Sigma3 で読む(モジュールドキュメント参照)。[`FabricStore`] / [`NocResolver`] を
/// [`RefCell`] 越しに実装する(定常パスでヒープ確保しない)。
pub struct SharedFabricCreds<'s, C: Crypto, const N: usize> {
    fabrics: &'s RefCell<FabricTable<C, N>>,
    crypto: &'s C,
    now_secs: u32,
}

impl<'s, C: Crypto, const N: usize> SharedFabricCreds<'s, C, N> {
    /// 共有 fabric テーブル・crypto・検証時刻(エポック秒)からビューを作る。
    ///
    /// `now_secs` は相手 NOC の有効期間検証に用いる([`NocResolver`])。
    pub fn new(fabrics: &'s RefCell<FabricTable<C, N>>, crypto: &'s C, now_secs: u32) -> Self {
        Self {
            fabrics,
            crypto,
            now_secs,
        }
    }
}

/// [`SharedFabricCreds`] が返す 1 fabric のビュー(`RefCell` の借用ガードを保持)。
pub struct SharedFabric<'a, C: Crypto, const N: usize> {
    guard: Ref<'a, FabricTable<C, N>>,
    index: NonZeroU8,
}

impl<C: Crypto, const N: usize> SharedFabric<'_, C, N> {
    fn entry(&self) -> &FabricEntry<C> {
        // 構築時に有効な index のみを渡し、CASE の同期処理中はテーブルを変更しないため必ず存在する。
        self.guard
            .get(self.index)
            .expect("fabric index valid for lifetime of view")
    }
}

impl<C: Crypto, const N: usize> Fabric for SharedFabric<'_, C, N> {
    fn fabric_index(&self) -> NonZeroU8 {
        self.index
    }
    fn fabric_id(&self) -> u64 {
        self.entry().fabric_id()
    }
    fn node_id(&self) -> u64 {
        self.entry().node_id()
    }
    fn ipk(&self) -> &[u8; 16] {
        self.entry().ipk()
    }
    fn root_public_key(&self) -> &[u8; 65] {
        self.entry().root_public_key()
    }
    fn noc(&self) -> &[u8] {
        self.entry().noc()
    }
    fn icac(&self) -> Option<&[u8]> {
        self.entry().icac()
    }
    fn sign(&self, msg: &[u8], out: &mut [u8; 64]) -> crate::error::Result<()> {
        self.entry().sign(msg, out)
    }
}

/// [`SharedFabricCreds::iter`] のイテレータ(index を先に集め、要素ごとに借用しなおす)。
pub struct SharedFabricIter<'a, C: Crypto, const N: usize> {
    cell: &'a RefCell<FabricTable<C, N>>,
    idxs: [Option<NonZeroU8>; N],
    count: usize,
    pos: usize,
}

impl<'a, C: Crypto, const N: usize> Iterator for SharedFabricIter<'a, C, N> {
    type Item = SharedFabric<'a, C, N>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.count {
            return None;
        }
        let idx = self.idxs[self.pos]?;
        self.pos += 1;
        Some(SharedFabric {
            guard: self.cell.borrow(),
            index: idx,
        })
    }
}

impl<'s, C: Crypto, const N: usize> FabricStore for SharedFabricCreds<'s, C, N> {
    type Fabric<'a>
        = SharedFabric<'a, C, N>
    where
        Self: 'a;

    fn iter(&self) -> impl Iterator<Item = SharedFabric<'_, C, N>> {
        let mut idxs = [None; N];
        let mut count = 0;
        {
            let g = self.fabrics.borrow();
            for e in g.iter() {
                if count < N {
                    idxs[count] = Some(e.fabric_index());
                    count += 1;
                }
            }
        }
        SharedFabricIter {
            cell: self.fabrics,
            idxs,
            count,
            pos: 0,
        }
    }

    fn get(&self, idx: NonZeroU8) -> Option<SharedFabric<'_, C, N>> {
        if self.fabrics.borrow().get(idx).is_some() {
            Some(SharedFabric {
                guard: self.fabrics.borrow(),
                index: idx,
            })
        } else {
            None
        }
    }
}

impl<'s, C: Crypto, const N: usize> NocResolver for SharedFabricCreds<'s, C, N> {
    fn verify_peer_noc(
        &self,
        fabric_index: NonZeroU8,
        noc_tlv: &[u8],
        icac_tlv: Option<&[u8]>,
    ) -> crate::error::Result<PeerIdentity> {
        let guard = self.fabrics.borrow();
        let creds = FabricCredentials::new(&guard, self.crypto, self.now_secs);
        creds.verify_peer_noc(fabric_index, noc_tlv, icac_tlv)
    }
}

/// 標準プロファイル(数コントローラ + 並行 exchange)。設計 §8.1 の `DefaultStack`。
///
/// サイジング: fabric=5 / session=4 / exchange=4 / TX バッファ=3 / handshake=1 /
/// read=2 / subscribe=3 / paths=16。
///
/// paths は chip-tool のコミッショニング時 ReadCommissioningInfo が 1 リクエストで
/// 10 本前後の属性パスを送るため、余裕を持って 16 とする。
pub type DefaultStack<'s, C, R, D> = MatterStack<'s, C, R, D, 5, 4, 4, 3, 1, 2, 3, 16>;

/// 極小プロファイル(単一コントローラ・RAM 最小)。設計 §8.1 の `MinimalStack`。
///
/// paths=12 は chip-tool でのコミッショニングが通る下限に余裕を足した値。
pub type MinimalStack<'s, C, R, D> = MatterStack<'s, C, R, D, 2, 3, 3, 2, 1, 1, 2, 12>;

#[cfg(all(test, feature = "rustcrypto"))]
mod tests;
