//! Matter TLV (Tag-Length-Value) コーデック。
//!
//! IM ペイロードと運用証明書(Matter Certificate)の両方で使う基盤。
//! 固定バッファ上のストリーミング Reader/Writer として実装し、
//! ヒープ確保・中間コピーを行わない。
//!
//! 実装予定(ロードマップ 1):
//! - `TlvReader`: `&[u8]` 上を走査するイテレータ型リーダ
//! - `TlvWriter`: `&mut [u8]` に書き込むライタ
//! - `FromTlv` / `ToTlv` derive による構造体マッピング(rs-matter の方式を踏襲)
