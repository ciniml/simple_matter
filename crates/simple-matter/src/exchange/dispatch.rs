//! プロトコルディスパッチ:閉じたプロトコル集合(SC / IM)への enum mux 静的分岐。
//!
//! `docs/design/transport-exchange.md` §5.4 に基づく。デバイスが話すプロトコルは
//! Secure Channel(0x0000)と Interaction Model(0x0001)の2つ(将来 BDX)で閉じて
//! いるため、`dyn` でも巨大タプルチェインでもなく **閉じた enum(mux)** で静的に分岐する。
//! これにより vtable も alloc も不要で、exchange 層が見るハンドラ型は単一名になり、
//! 型パラメータの上位伝播(設計原則 7)を抑える。
//!
//! # 同期プレースホルダ
//!
//! SC / IM の本体は次段階の実装であり、本モジュールは配線と型消去境界のみを提供する。
//! ハンドラは同期([`ProtocolHandler::handle`])で、受信メッセージのビュー
//! [`RxMessage`] を受け取り [`HandlerAction`] を返す。応答生成の詳細は上位層が
//! [`ExchangeManager`](super::exchange::ExchangeManager) の送信 API を用いて行う。

use crate::error::{Error, Result};
use crate::transport::header::PayloadHeader;
use crate::transport::session::SessionManager;

use super::exchange::{ExchangeId, Role};

/// ハンドラへ渡す受信メッセージのビュー。
///
/// 復号済みの [`PayloadHeader`] とアプリケーション payload(平文)への参照、および
/// この会話を表す [`ExchangeId`] と自分側の [`Role`] を持つ。所有はせず借用のみ。
pub struct RxMessage<'a> {
    /// 復号済みの暗号内ヘッダ。
    pub header: &'a PayloadHeader,
    /// アプリケーション payload(PayloadHeader を除いた平文)。
    pub payload: &'a [u8],
    /// このメッセージが属する会話。
    pub exchange: ExchangeId,
    /// 自分側の役割。
    pub role: Role,
}

/// ハンドラがディスパッチ後に要求するアクション。
///
/// `docs/design/secure-channel.md` §4.3 に基づく。ハンドラは応答 payload を
/// 出力バッファ(`tx`)へ書き、その長さと送出パラメータを本 enum で宣言する。
/// 実際のヘッダ付与・暗号化・(信頼)送信は上位層が
/// [`ExchangeManager`](super::exchange::ExchangeManager) の送信 API で行う
/// (sans-IO の送受信分離と暗号境界 1 点を保つ)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandlerAction {
    /// 明示的な追加アクションなし(ACK 等は MRP が別途処理する)。
    #[default]
    None,
    /// ハンドラが `tx` に応答 payload を書いた。上位層はこの opcode / proto_id で
    /// `tx[..len]` を(`reliable` なら信頼)送信する。会話は継続する。
    Respond {
        /// 応答メッセージの Protocol Opcode。
        opcode: u8,
        /// 応答メッセージの Protocol ID。
        proto_id: u16,
        /// 信頼送達(R フラグ)で送るなら `true`。
        reliable: bool,
        /// `tx` に書き込まれた応答 payload のバイト長。
        len: usize,
    },
    /// 応答は無いが、これが会話の終端である(相手の終端メッセージ —
    /// 例: CASE resumption の成功 StatusReport — を受理した)。統合層は exchange を
    /// 終端予約(`mark_closing`)する。受信 reliable メッセージへの ACK は MRP が
    /// 流し切ってから slot が回収される(プール枯渇防止)。
    CloseSilent,
    /// [`Respond`](HandlerAction::Respond) と同じく `tx` に payload を書いたが、
    /// これがハンドシェイクの終端であり送出後に会話を閉じてよい(終端 StatusReport)。
    Close {
        /// 応答メッセージの Protocol Opcode。
        opcode: u8,
        /// 応答メッセージの Protocol ID。
        proto_id: u16,
        /// 信頼送達(R フラグ)で送るなら `true`。
        reliable: bool,
        /// `tx` に書き込まれた応答 payload のバイト長。
        len: usize,
    },
}

/// 各プロトコル(sc / im)が実装する受信ハンドラ。
///
/// `PROTOCOL_ID` はこのハンドラが処理する Matter Protocol ID。[`ProtocolMux`] は
/// この関連定数で静的に分岐する。
pub trait ProtocolHandler {
    /// このハンドラが処理する Protocol ID。
    const PROTOCOL_ID: u16;

    /// 受信メッセージを処理する。
    ///
    /// `tx` は応答 payload を書くための出力バッファ(上位層が用意)。ハンドラは
    /// 応答を `tx` に書き、[`HandlerAction::Respond`] / [`HandlerAction::Close`] で
    /// その長さと送出パラメータを宣言する。`sessions` はセッションテーブルで、
    /// ハンドシェイクの `reserve`/`commit`(secure-channel §6.5)に用いる。`now_ms` は
    /// 単調増加する現在時刻(ミリ秒)。
    ///
    /// 不正入力・状態違反・プール枯渇でも `panic` せず、応答なしなら
    /// [`HandlerAction::None`] を返すか [`Error`](crate::Error) を返す(silent drop)。
    fn handle<const S: usize>(
        &mut self,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction>;
}

/// Protocol ID による静的分岐(型消去境界)の抽象。
///
/// [`ExchangeManager`](super::exchange::ExchangeManager) は `H: Dispatcher` の単一型
/// パラメータのみを持ち、内側のハンドラ合成(クラスタのタプルチェイン等)を知らない。
/// これが設計 §9 の「境界で型消去する層を 1 枚挟む」の具体である。
pub trait Dispatcher {
    /// `proto_id` に対応するハンドラへ振り分ける。未対応の Protocol ID は
    /// [`Error::NotFound`](crate::Error::NotFound)。
    ///
    /// 引数の意味は [`ProtocolHandler::handle`] と同じ(`tx` 出力バッファ・
    /// `sessions` セッションテーブル・`now_ms` 現在時刻)。
    fn dispatch<const S: usize>(
        &mut self,
        proto_id: u16,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction>;
}

/// 閉じたプロトコル集合(Secure Channel / Interaction Model)を静的に分岐する mux。
///
/// BDX 追加時は型パラメータと分岐を 1 つ増やすだけで、[`ExchangeManager`](super::exchange::ExchangeManager)
/// 本体は不変。
pub struct ProtocolMux<Sc, Im> {
    /// Secure Channel(0x0000)ハンドラ。
    pub sc: Sc,
    /// Interaction Model(0x0001)ハンドラ。
    pub im: Im,
}

impl<Sc, Im> ProtocolMux<Sc, Im> {
    /// 2 つのハンドラから mux を生成する。
    pub const fn new(sc: Sc, im: Im) -> Self {
        Self { sc, im }
    }
}

impl<Sc: ProtocolHandler, Im: ProtocolHandler> Dispatcher for ProtocolMux<Sc, Im> {
    fn dispatch<const S: usize>(
        &mut self,
        proto_id: u16,
        rx: &RxMessage<'_>,
        tx: &mut [u8],
        sessions: &mut SessionManager<S>,
        now_ms: u64,
    ) -> Result<HandlerAction> {
        // 関連定数はパターンに使えないため `if` ガードで分岐する。
        if proto_id == Sc::PROTOCOL_ID {
            self.sc.handle(rx, tx, sessions, now_ms)
        } else if proto_id == Im::PROTOCOL_ID {
            self.im.handle(rx, tx, sessions, now_ms)
        } else {
            Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::header::{ExchFlags, PayloadHeader};
    use crate::transport::session::{SessionId, SessionManager};

    struct ScHandler {
        calls: u32,
    }
    impl ProtocolHandler for ScHandler {
        const PROTOCOL_ID: u16 = 0x0000;
        fn handle<const S: usize>(
            &mut self,
            _rx: &RxMessage<'_>,
            _tx: &mut [u8],
            _sessions: &mut SessionManager<S>,
            _now_ms: u64,
        ) -> Result<HandlerAction> {
            self.calls += 1;
            Ok(HandlerAction::None)
        }
    }

    struct ImHandler {
        calls: u32,
    }
    impl ProtocolHandler for ImHandler {
        const PROTOCOL_ID: u16 = 0x0001;
        fn handle<const S: usize>(
            &mut self,
            _rx: &RxMessage<'_>,
            _tx: &mut [u8],
            _sessions: &mut SessionManager<S>,
            _now_ms: u64,
        ) -> Result<HandlerAction> {
            self.calls += 1;
            Ok(HandlerAction::None)
        }
    }

    fn phdr(proto_id: u16) -> PayloadHeader {
        PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
            proto_opcode: 0x01,
            exch_id: 0x1234,
            proto_id,
            vendor_id: None,
            ack_ctr: None,
        }
    }

    fn rx<'a>(h: &'a PayloadHeader) -> RxMessage<'a> {
        RxMessage {
            header: h,
            payload: &[],
            exchange: ExchangeId::from_parts(SessionId::from_raw(0), 0x1234),
            role: Role::Responder,
        }
    }

    #[test]
    fn dispatch_routes_by_protocol_id() {
        let mut mux = ProtocolMux::new(ScHandler { calls: 0 }, ImHandler { calls: 0 });
        let mut sessions: SessionManager<1> = SessionManager::new();
        let mut tx = [0u8; 4];

        let sc = phdr(0x0000);
        mux.dispatch(0x0000, &rx(&sc), &mut tx, &mut sessions, 0)
            .unwrap();
        let im = phdr(0x0001);
        mux.dispatch(0x0001, &rx(&im), &mut tx, &mut sessions, 0)
            .unwrap();
        mux.dispatch(0x0001, &rx(&im), &mut tx, &mut sessions, 0)
            .unwrap();

        assert_eq!(mux.sc.calls, 1);
        assert_eq!(mux.im.calls, 2);
    }

    #[test]
    fn unknown_protocol_is_not_found() {
        let mut mux = ProtocolMux::new(ScHandler { calls: 0 }, ImHandler { calls: 0 });
        let mut sessions: SessionManager<1> = SessionManager::new();
        let mut tx = [0u8; 4];
        let other = phdr(0x0099);
        assert_eq!(
            mux.dispatch(0x0099, &rx(&other), &mut tx, &mut sessions, 0),
            Err(Error::NotFound)
        );
        assert_eq!(mux.sc.calls, 0);
        assert_eq!(mux.im.calls, 0);
    }
}
