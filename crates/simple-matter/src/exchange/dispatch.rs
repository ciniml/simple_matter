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
/// 現段階はプレースホルダで、応答は上位層が [`ExchangeManager`](super::exchange::ExchangeManager)
/// の送信 API 経由で別途行う。将来「応答を書いた」「StatusReport を返す」等の variant を
/// 増やせるよう enum にしてある。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandlerAction {
    /// 明示的な追加アクションなし(ACK 等は MRP が別途処理する)。
    #[default]
    None,
}

/// 各プロトコル(sc / im)が実装する受信ハンドラ。
///
/// `PROTOCOL_ID` はこのハンドラが処理する Matter Protocol ID。[`ProtocolMux`] は
/// この関連定数で静的に分岐する。
pub trait ProtocolHandler {
    /// このハンドラが処理する Protocol ID。
    const PROTOCOL_ID: u16;

    /// 受信メッセージを処理する。処理できない入力でも `panic` せずエラーを返すこと。
    fn handle(&mut self, rx: &RxMessage<'_>) -> Result<HandlerAction>;
}

/// Protocol ID による静的分岐(型消去境界)の抽象。
///
/// [`ExchangeManager`](super::exchange::ExchangeManager) は `H: Dispatcher` の単一型
/// パラメータのみを持ち、内側のハンドラ合成(クラスタのタプルチェイン等)を知らない。
/// これが設計 §9 の「境界で型消去する層を 1 枚挟む」の具体である。
pub trait Dispatcher {
    /// `proto_id` に対応するハンドラへ振り分ける。未対応の Protocol ID は
    /// [`Error::NotFound`](crate::Error::NotFound)。
    fn dispatch(&mut self, proto_id: u16, rx: &RxMessage<'_>) -> Result<HandlerAction>;
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
    fn dispatch(&mut self, proto_id: u16, rx: &RxMessage<'_>) -> Result<HandlerAction> {
        // 関連定数はパターンに使えないため `if` ガードで分岐する。
        if proto_id == Sc::PROTOCOL_ID {
            self.sc.handle(rx)
        } else if proto_id == Im::PROTOCOL_ID {
            self.im.handle(rx)
        } else {
            Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::header::{ExchFlags, PayloadHeader};
    use crate::transport::session::SessionId;

    struct ScHandler {
        calls: u32,
    }
    impl ProtocolHandler for ScHandler {
        const PROTOCOL_ID: u16 = 0x0000;
        fn handle(&mut self, _rx: &RxMessage<'_>) -> Result<HandlerAction> {
            self.calls += 1;
            Ok(HandlerAction::None)
        }
    }

    struct ImHandler {
        calls: u32,
    }
    impl ProtocolHandler for ImHandler {
        const PROTOCOL_ID: u16 = 0x0001;
        fn handle(&mut self, _rx: &RxMessage<'_>) -> Result<HandlerAction> {
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

        let sc = phdr(0x0000);
        mux.dispatch(0x0000, &rx(&sc)).unwrap();
        let im = phdr(0x0001);
        mux.dispatch(0x0001, &rx(&im)).unwrap();
        mux.dispatch(0x0001, &rx(&im)).unwrap();

        assert_eq!(mux.sc.calls, 1);
        assert_eq!(mux.im.calls, 2);
    }

    #[test]
    fn unknown_protocol_is_not_found() {
        let mut mux = ProtocolMux::new(ScHandler { calls: 0 }, ImHandler { calls: 0 });
        let other = phdr(0x0099);
        assert_eq!(mux.dispatch(0x0099, &rx(&other)), Err(Error::NotFound));
        assert_eq!(mux.sc.calls, 0);
        assert_eq!(mux.im.calls, 0);
    }
}
