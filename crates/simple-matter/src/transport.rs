//! transport 層:メッセージコーデックと暗号境界。
//!
//! `docs/design/transport-exchange.md` に基づく。本ピースでは Matter メッセージの
//! ワイヤ表現(ヘッダ)とメッセージカウンタ、そして暗号境界([`SecureCodec`])を
//! 実装する。Network trait / SessionManager / ExchangeManager / MRP は後続ピースで
//! 追加する。
//!
//! # モジュール構成(設計ドキュメント §1)
//!
//! - [`util`] — ヘッダ用の軽量バイトカーソル `ParseBuf` / `WriteBuf`。
//! - [`header`] — [`PacketHeader`](header::PacketHeader)(平文)/
//!   [`PayloadHeader`](header::PayloadHeader)(暗号内)の parse/encode。
//! - [`counter`] — 送信カウンタ [`LocalCounter`](counter::LocalCounter) と
//!   受信リプレイ窓 [`PeerWindow`](counter::PeerWindow)。
//! - [`secure`] — 唯一の暗号実行点 [`SecureCodec`](secure::SecureCodec)。
//!
//! `util` / `header` / `counter` は相互依存せず単体テスト可能。`secure` のみが
//! [`crate::crypto`] に依存し、暗号境界を物理的に 1 ファイルへ閉じ込める。

pub mod counter;
pub mod header;
pub mod secure;
pub mod util;
