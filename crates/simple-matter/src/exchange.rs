//! exchange 層:会話(Exchange)の管理、MRP 内包、プロトコルディスパッチ。
//!
//! `docs/design/transport-exchange.md` §5 / §6 に基づく。transport 層(session /
//! 暗号境界)の上に位置し、平文ペイロード + [`PayloadHeader`](crate::transport::header::PayloadHeader)
//! を扱う。下位境界(暗号文)には触れない。
//!
//! # モジュール構成(設計 §1)
//!
//! - [`exchange`] — [`ExchangeId`](exchange::ExchangeId)(ハンドル)/
//!   [`ExchangeState`](exchange::ExchangeState)(格納状態)/ [`Role`](exchange::Role) と、
//!   会話プール + 受信一本道 + 送信を束ねる [`ExchangeManager`](exchange::ExchangeManager)。
//! - [`mrp`] — 信頼送達 [`Mrp`](mrp::Mrp)(再送 + ACK)、[`MrpConfig`](mrp::MrpConfig)。
//! - [`dispatch`] — [`ProtocolHandler`](dispatch::ProtocolHandler) と enum mux
//!   [`ProtocolMux`](dispatch::ProtocolMux)(§5.4)。
//!
//! # 時間ソースと同期 API(確定した設計判断)
//!
//! session 層と同じく時間は外部注入(`now_ms`)で、embassy-time 等へは依存しない。
//! API は同期で、再送・standalone ACK の期限は「次に処理すべき時刻(deadline)」として
//! 返す([`ExchangeManager::poll`](exchange::ExchangeManager::poll))。async 統合(Network
//! trait の駆動)は将来の統合層の責務で、本層は単一の poll 駆動点で RX・再送タイマを
//! 処理できる sans-IO 構造にとどめる。設計 §5.3 の `Exchange<'a>`(スタック参照を持つ
//! async ハンドル)は採らず、不透明ハンドル [`ExchangeId`](exchange::ExchangeId) +
//! `ExchangeManager` メソッド経由で状態を操作する(乖離。理由は同期 sans-IO 化)。

pub mod dispatch;
#[allow(clippy::module_inception)] // 設計 §1 のファイル分割(exchange/exchange.rs)に忠実。
pub mod exchange;
pub mod mrp;

pub use dispatch::{Dispatcher, HandlerAction, ProtocolHandler, ProtocolMux, RxMessage};
pub use exchange::{
    ExchangeId, ExchangeManager, ExchangeState, Outgoing, PollAction, RecvReport, ReliableSent,
    Role, SendTiming, MRP_STANDALONE_ACK_OPCODE, SECURE_CHANNEL_PROTOCOL_ID,
};
pub use mrp::{Mrp, MrpConfig, RecvOutcome, RetransAction};
