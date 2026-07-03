//! 全レイヤ共通の統一エラー型。
//!
//! connectedhomeip の `CHIP_ERROR` に相当する役割を `Result<T, Error>` で担う。
//! ヒープレス前提のため、エラーはコピー可能な小さな enum に限定し、
//! 動的な文脈情報(メッセージ文字列等)は持たせない。

/// 全レイヤ共通のエラー型。
///
/// バリアントは実装の進行に合わせて追加する。ワイヤ上のステータスコード
/// (IM Status / Secure Channel StatusReport)への変換は各プロトコル層で行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 入力データのデコードに失敗した(TLV/DER/ヘッダ等)
    Decode,
    /// 固定容量バッファ/テーブルに空きがない
    NoSpace,
    /// 現在の状態では許可されない操作(プロトコル状態機械違反)
    InvalidState,
    /// 対象が見つからない
    NotFound,
}

/// 全レイヤ共通の `Result` 型。
pub type Result<T> = core::result::Result<T, Error>;
