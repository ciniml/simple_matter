//! TLV プリティプリンタ(設計 doc §9.2 `[tlv]`)。
//!
//! コアの公開 [`TlvReader`] でエンコード済み TLV を歩き、インデント付きの
//! 人間可読な構造表示(1 要素 1 行)に変換する。コアは無改造
//! (no_std / sans-IO を汚さない)。
//!
//! 表示形式:
//!
//! ```text
//! AnonymousTag: struct {
//!   0: 1 (unsigned)
//!   1: array [
//!     true
//!   ]
//! }
//! ```
//!
//! - タグ: `AnonymousTag` / context タグは番号 / profile 系は種別付き。
//! - スカラ: 値 + 型注釈(bool/null/文字列は自明なので注釈なし)。
//! - byte string は hex + 長さ。長いものは先頭 32 バイトで省略する。

use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

/// byte string 表示の最大バイト数(超過分は `..` で省略)。
const MAX_BYTES_SHOWN: usize = 32;

/// エンコード済み TLV(要素列)をプリティプリントし、行のベクタを返す。
///
/// 不正な TLV は decode できたところまで表示し、`<decode error>` 行で打ち切る
/// (ログ用途なのでエラーにしない)。
pub fn pretty(raw: &[u8]) -> Vec<String> {
    let mut r = TlvReader::new(raw);
    let mut out = Vec::new();
    loop {
        match r.read_next() {
            Ok(Some(e)) => {
                if matches!(e.value, TlvValue::ContainerEnd) {
                    // トップレベルの余剰 end は不正だが、ログなので黙って打ち切る。
                    break;
                }
                let tag = e.tag;
                let value = e.value;
                element(&mut r, &tag, &value, 0, &mut out);
            }
            Ok(None) => break,
            Err(_) => {
                out.push("<decode error>".into());
                break;
            }
        }
    }
    out
}

/// 1 要素(コンテナは再帰)を `out` へ行として書き足す。
fn element(r: &mut TlvReader, tag: &TlvTag, value: &TlvValue, depth: usize, out: &mut Vec<String>) {
    let pad = "  ".repeat(depth);
    let tag_s = fmt_tag(tag);
    match value {
        TlvValue::ContainerStart(t) => {
            let (name, open, close) = match t {
                ContainerType::Structure => ("struct", "{", "}"),
                ContainerType::Array => ("array", "[", "]"),
                ContainerType::List => ("list", "[[", "]]"),
            };
            out.push(format!("{pad}{tag_s}{name} {open}"));
            loop {
                match r.read_next() {
                    Ok(Some(c)) if matches!(c.value, TlvValue::ContainerEnd) => break,
                    Ok(Some(c)) => {
                        let ctag = c.tag;
                        let cval = c.value;
                        element(r, &ctag, &cval, depth + 1, out);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        out.push(format!("{pad}  <decode error>"));
                        break;
                    }
                }
            }
            out.push(format!("{pad}{close}"));
        }
        v => out.push(format!("{pad}{tag_s}{}", fmt_scalar(v))),
    }
}

/// タグを `"<tag>: "` 形式(anonymous は `AnonymousTag: `)で整形する。
fn fmt_tag(tag: &TlvTag) -> String {
    match tag {
        TlvTag::Anonymous => "AnonymousTag: ".into(),
        TlvTag::ContextSpecific(n) => format!("{n}: "),
        TlvTag::CommonProfile16(n) => format!("common({n}): "),
        TlvTag::CommonProfile32(n) => format!("common({n}): "),
        TlvTag::ImplicitProfile16(n) => format!("implicit({n}): "),
        TlvTag::ImplicitProfile32(n) => format!("implicit({n}): "),
        TlvTag::FullyQualified48 {
            vendor_id,
            profile,
            tag,
        } => format!("full({vendor_id:#06x}:{profile}:{tag}): "),
        TlvTag::FullyQualified64 {
            vendor_id,
            profile,
            tag,
        } => format!("full({vendor_id:#06x}:{profile}:{tag}): "),
    }
}

/// スカラ値を整形する(型注釈付き)。
fn fmt_scalar(v: &TlvValue) -> String {
    match v {
        TlvValue::Boolean(b) => b.to_string(),
        TlvValue::UnsignedInteger(x) => format!("{x} (unsigned)"),
        TlvValue::SignedInteger(x) => format!("{x} (signed)"),
        TlvValue::Float(x) => format!("{x} (f32)"),
        TlvValue::Double(x) => format!("{x} (f64)"),
        TlvValue::Utf8String(s) => format!("{s:?}"),
        TlvValue::ByteString(b) => {
            let shown = &b[..b.len().min(MAX_BYTES_SHOWN)];
            let hex: String = shown.iter().map(|x| format!("{x:02x}")).collect();
            let ellipsis = if b.len() > MAX_BYTES_SHOWN { ".." } else { "" };
            format!("hex:{hex}{ellipsis} ({}B)", b.len())
        }
        TlvValue::Null => "null".into(),
        // コンテナは element() 側で処理済み。ここには来ない。
        TlvValue::ContainerStart(_) | TlvValue::ContainerEnd => "<container>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_matter::tlv::{TlvTag, TlvWriter};

    #[test]
    fn scalar_bool_known_bytes() {
        // anonymous bool true = 0x09
        assert_eq!(pretty(&[0x09]), vec!["AnonymousTag: true"]);
        // anonymous unsigned 1 (u8) = 0x04 0x01
        assert_eq!(pretty(&[0x04, 0x01]), vec!["AnonymousTag: 1 (unsigned)"]);
    }

    #[test]
    fn struct_with_fields_matches_expected_lines() {
        // { 0: u8=1, 1: [ true ] , 2: "on" } を TlvWriter で組む。
        let mut buf = [0u8; 64];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u8(&TlvTag::ContextSpecific(0), 1).unwrap();
            w.start_array(&TlvTag::ContextSpecific(1)).unwrap();
            w.write_bool(&TlvTag::Anonymous, true).unwrap();
            w.end_container().unwrap();
            w.write_utf8(&TlvTag::ContextSpecific(2), "on").unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let lines = pretty(&buf[..n]);
        assert_eq!(
            lines,
            vec![
                "AnonymousTag: struct {",
                "  0: 1 (unsigned)",
                "  1: array [",
                "    AnonymousTag: true",
                "  ]",
                "  2: \"on\"",
                "}",
            ]
        );
    }

    #[test]
    fn byte_string_truncated() {
        let mut buf = [0u8; 128];
        let payload = [0xAAu8; 40];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.write_bytes(&TlvTag::Anonymous, &payload).unwrap();
            w.len()
        };
        let lines = pretty(&buf[..n]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].ends_with(".. (40B)"), "{}", lines[0]);
        // 32 バイト分の hex = 64 文字が入っていること。
        assert!(lines[0].contains(&"aa".repeat(32)));
    }

    #[test]
    fn garbage_reports_decode_error() {
        // 0xFF は不正な TLV 制御バイト。
        let lines = pretty(&[0xFF, 0x00]);
        assert_eq!(lines, vec!["<decode error>"]);
    }
}
