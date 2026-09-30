//! API エラー(設計 doc §6: `{ "error": { "code", "message", "im_status" } }`)。

use serde::Serialize;
use serde_json::{json, Value};

/// エラー種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// コマンドキュー満杯。
    Busy,
    /// 操作(またはコントローラ応答待ち)のタイムアウト。
    Timeout,
    /// デバイスが非成功の IM ステータスを返した。
    ImStatus,
    /// ノード等が見つからない。
    NotFound,
    /// リクエスト不正。
    BadRequest,
    /// 未実装(W1 の Write など)。
    NotImplemented,
    /// その他(CASE 失敗・IO エラー・CA 不在など)。
    Internal,
}

impl ErrorCode {
    /// 対応する HTTP ステータスコード。
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::Busy => 503,
            ErrorCode::Timeout => 504,
            ErrorCode::ImStatus => 502,
            ErrorCode::NotFound => 404,
            ErrorCode::BadRequest => 400,
            ErrorCode::NotImplemented => 501,
            ErrorCode::Internal => 500,
        }
    }
}

/// API エラー。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub im_status: Option<u8>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            im_status: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    pub fn im_status(status: u8, message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::ImStatus,
            message: message.into(),
            im_status: Some(status),
        }
    }

    /// `smctl::ops::Exec` の文字列エラーを分類する。
    ///
    /// Exec のエラーは人間向け文字列なので、既知の定型句だけで種別を決める
    /// (タイムアウト・mDNS 解決期限切れ / アドレス帳に無い)。それ以外は `internal`。
    pub fn from_exec(msg: String) -> Self {
        let code = if msg.contains("timed out") || msg.contains("not resolved within") {
            ErrorCode::Timeout
        } else if msg.contains("not in address book") {
            ErrorCode::NotFound
        } else {
            ErrorCode::Internal
        };
        Self::new(code, msg)
    }

    /// エラー本体の JSON(§6 の形)。
    pub fn to_json(&self) -> Value {
        let mut e = json!({
            "code": self.code,
            "message": self.message,
        });
        if let Some(s) = self.im_status {
            e["im_status"] = json!(s);
        }
        json!({ "error": e })
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_json_shape() {
        let v = ApiError::bad_request("bad id").to_json();
        assert_eq!(
            v,
            json!({"error": {"code": "bad_request", "message": "bad id"}})
        );
        let v = ApiError::im_status(0x81, "UnsupportedCommand").to_json();
        assert_eq!(v["error"]["code"], "im_status");
        assert_eq!(v["error"]["im_status"], 0x81);
        assert_eq!(v["error"]["message"], "UnsupportedCommand");
    }

    #[test]
    fn classify_exec_errors() {
        let e = ApiError::from_exec(
            "read timed out (session invalidated; retry will re-establish CASE)".into(),
        );
        assert_eq!(e.code, ErrorCode::Timeout);
        assert_eq!(e.code.http_status(), 504);
        let e = ApiError::from_exec("node 5 not in address book (`smctl pairing list`)".into());
        assert_eq!(e.code, ErrorCode::NotFound);
        let e = ApiError::from_exec("operational node 0x1 not resolved within 20s".into());
        assert_eq!(e.code, ErrorCode::Timeout);
        let e = ApiError::from_exec("CASE failed: Foo".into());
        assert_eq!(e.code, ErrorCode::Internal);
    }
}
