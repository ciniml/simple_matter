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
    /// 受信メッセージが重複またはリプレイ窓外(リプレイ保護によるドロップ)。
    ///
    /// 復号(MIC 検証)は通過したが、受信メッセージカウンタが既受理または窓外で
    /// あった場合に返す(silent drop の合図)。
    Duplicate,
    /// 暗号処理に失敗した(鍵・点・署名・MIC の検証失敗、入力長の不正など)。
    ///
    /// AEAD 復号時のタグ不一致や不正な鍵形式など、安全性に関わる失敗を含む。
    /// panic せずこのバリアントで返す。
    Crypto,
    /// 証明書の検証ポリシに違反した(有効期限外・基本制約/鍵用途違反・
    /// 発行者鍵識別子の不一致・fabric-id 不整合など、チェーン検証の失敗)。
    ///
    /// TLV デコード自体の失敗は [`Error::Decode`]、署名検証の失敗は
    /// [`Error::Crypto`] を用い、証明書の「意味的な」検証失敗のみをここで表す。
    CertInvalid,
}

/// 全レイヤ共通の `Result` 型。
pub type Result<T> = core::result::Result<T, Error>;
