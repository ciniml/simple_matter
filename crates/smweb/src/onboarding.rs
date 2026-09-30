//! オンボーディング払い出し情報の**解析**(QR payload `MT:...` / manual pairing code)。
//!
//! コア(`simple_matter::discovery::onboarding`)は生成側だけを持つので、Pair 画面で
//! 貼り付けられたコードを discriminator / passcode に戻す復号をここで持つ
//! (Matter 仕様 §5.1.3 QR / §5.1.4 manual code)。生成器と往復一致することをテストで担保する。

use serde::Serialize;
use smctl::simple_matter::discovery::onboarding::passcode_is_valid;

/// discriminator(QR は 12 ビット long、manual code は上位 4 ビットの short のみ)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Disc {
    /// 12 ビット long discriminator。
    Long(u16),
    /// 4 ビット short discriminator(long の上位 4 ビット = `long >> 8`)。
    Short(u8),
}

impl Disc {
    /// mDNS の TXT `D`(long)がこの discriminator に一致するか。
    pub fn matches(self, long: u16) -> bool {
        match self {
            Disc::Long(d) => d == (long & 0x0FFF),
            Disc::Short(s) => ((long & 0x0FFF) >> 8) as u8 == s,
        }
    }

    /// long discriminator(short なら `None`)。
    pub fn long(self) -> Option<u16> {
        match self {
            Disc::Long(d) => Some(d),
            Disc::Short(_) => None,
        }
    }
}

/// 解析結果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupCode {
    /// `"qr"` または `"manual"`。
    pub source: &'static str,
    pub discriminator: Disc,
    pub passcode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_id: Option<u16>,
    /// QR の discovery capabilities(bit0 SoftAP / bit1 BLE / bit2 on-network)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_caps: Option<u8>,
    /// QR の commissioning flow(0 = Standard)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<u8>,
}

/// QR payload(`MT:` 始まり)または manual pairing code(11 / 21 桁、`-` や空白可)を解析する。
pub fn parse_setup_code(s: &str) -> Result<SetupCode, String> {
    let t = s.trim();
    if t.len() >= 3 && t[..3].eq_ignore_ascii_case("MT:") {
        parse_qr(t)
    } else {
        parse_manual(t)
    }
}

const BASE38: &[u8; 38] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

fn base38_val(c: u8) -> Option<u32> {
    BASE38
        .iter()
        .position(|&b| b == c.to_ascii_uppercase())
        .map(|p| p as u32)
}

/// base38 → バイト列(5 文字 = 3 バイト、4 文字 = 2 バイト、2 文字 = 1 バイト)。
fn base38_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() * 3 / 5 + 2);
    let mut i = 0;
    while i < b.len() {
        let rem = b.len() - i;
        let (chars, bytes) = match rem {
            n if n >= 5 => (5, 3),
            4 => (4, 2),
            2 => (2, 1),
            _ => {
                return Err(format!(
                    "invalid QR payload length ({} base38 chars)",
                    b.len()
                ))
            }
        };
        let mut v: u64 = 0;
        for k in (0..chars).rev() {
            let d = base38_val(b[i + k])
                .ok_or_else(|| format!("invalid base38 character {:?}", b[i + k] as char))?;
            v = v * 38 + d as u64;
        }
        if v >> (8 * bytes) != 0 {
            return Err("invalid base38 chunk (value out of range)".into());
        }
        for k in 0..bytes {
            out.push((v >> (8 * k)) as u8);
        }
        i += chars;
    }
    Ok(out)
}

/// LSB 先頭のビットストリームから `width` ビット読む。
fn bits(buf: &[u8], off: usize, width: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..width {
        let bit = off + i;
        if (buf[bit / 8] >> (bit % 8)) & 1 == 1 {
            v |= 1 << i;
        }
    }
    v
}

fn parse_qr(t: &str) -> Result<SetupCode, String> {
    // 複数デバイスを連結した payload(`*` 区切り)は先頭だけ使う。
    let body = t[3..].split('*').next().unwrap_or("");
    let buf = base38_decode(body)?;
    if buf.len() < 11 {
        return Err(format!(
            "QR payload too short ({} bytes, need 11)",
            buf.len()
        ));
    }
    let version = bits(&buf, 0, 3);
    if version != 0 {
        return Err(format!("unsupported QR payload version {version}"));
    }
    let vendor_id = bits(&buf, 3, 16) as u16;
    let product_id = bits(&buf, 19, 16) as u16;
    let flow = bits(&buf, 35, 2) as u8;
    let caps = bits(&buf, 37, 8) as u8;
    let disc = bits(&buf, 45, 12) as u16;
    let passcode = bits(&buf, 57, 27) as u32;
    if !passcode_is_valid(passcode) {
        return Err(format!(
            "QR payload carries an invalid passcode ({passcode})"
        ));
    }
    Ok(SetupCode {
        source: "qr",
        discriminator: Disc::Long(disc),
        passcode,
        vendor_id: Some(vendor_id),
        product_id: Some(product_id),
        discovery_caps: Some(caps),
        flow: Some(flow),
    })
}

/// Verhoeff 検査: 検査数字込みの数字列が正しければ `true`。
fn verhoeff_ok(digits: &[u8]) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c = 0u8;
    for (i, &d) in digits.iter().rev().enumerate() {
        c = D[c as usize][P[i % 8][d as usize] as usize];
    }
    c == 0
}

fn num(d: &[u8]) -> u32 {
    d.iter().fold(0u32, |a, &x| a * 10 + x as u32)
}

fn parse_manual(t: &str) -> Result<SetupCode, String> {
    let mut digits = Vec::with_capacity(21);
    for c in t.chars() {
        match c {
            '0'..='9' => digits.push(c as u8 - b'0'),
            '-' | ' ' | '\t' => {}
            _ => {
                return Err(format!(
                    "not a setup code: expected a QR payload (MT:...) or an 11/21-digit \
                     manual pairing code, got {t:?}"
                ))
            }
        }
    }
    if digits.len() != 11 && digits.len() != 21 {
        return Err(format!(
            "manual pairing code must have 11 or 21 digits (got {})",
            digits.len()
        ));
    }
    if !verhoeff_ok(&digits) {
        return Err("manual pairing code check digit mismatch (typo?)".into());
    }
    let d1 = digits[0];
    if d1 > 7 {
        return Err(format!("invalid manual pairing code (leading digit {d1})"));
    }
    let vid_pid = (d1 >> 2) & 1 == 1;
    if vid_pid != (digits.len() == 21) {
        return Err(if vid_pid {
            "manual pairing code announces VID/PID but has only 11 digits".into()
        } else {
            "21-digit manual pairing code without the VID/PID flag".into()
        });
    }
    let chunk2 = num(&digits[1..6]);
    let chunk3 = num(&digits[6..10]);
    if chunk2 > 0xFFFF || chunk3 > 0x1FFF {
        return Err("invalid manual pairing code (field out of range)".into());
    }
    let short = (((d1 & 0x03) << 2) as u32 | ((chunk2 >> 14) & 0x03)) as u8;
    let passcode = (chunk3 << 14) | (chunk2 & 0x3FFF);
    if !passcode_is_valid(passcode) {
        return Err(format!(
            "manual pairing code carries an invalid passcode ({passcode})"
        ));
    }
    let (vendor_id, product_id) = if vid_pid {
        let v = num(&digits[10..15]);
        let p = num(&digits[15..20]);
        if v > 0xFFFF || p > 0xFFFF {
            return Err("invalid manual pairing code (VID/PID out of range)".into());
        }
        (Some(v as u16), Some(p as u16))
    } else {
        (None, None)
    };
    Ok(SetupCode {
        source: "manual",
        discriminator: Disc::Short(short),
        passcode,
        vendor_id,
        product_id,
        discovery_caps: None,
        flow: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smctl::simple_matter::discovery::onboarding::{
        manual_pairing_code, qr_payload, OnboardingPayload, DISCOVERY_CAP_BLE,
        DISCOVERY_CAP_ON_NETWORK, QR_PAYLOAD_MAX_LEN,
    };

    #[test]
    fn chip_tool_vectors() {
        let c = parse_setup_code("MT:-24J0AFN00KA0648G00").unwrap();
        assert_eq!(c.source, "qr");
        assert_eq!(c.discriminator, Disc::Long(3840));
        assert_eq!(c.passcode, 20202021);
        assert_eq!(c.vendor_id, Some(0xFFF1));
        assert_eq!(c.product_id, Some(0x8001));
        assert_eq!(c.discovery_caps, Some(DISCOVERY_CAP_ON_NETWORK));
        assert_eq!(c.flow, Some(0));

        let m = parse_setup_code("34970112332").unwrap();
        assert_eq!(m.source, "manual");
        assert_eq!(m.discriminator, Disc::Short(15));
        assert_eq!(m.passcode, 20202021);
        assert!(m.vendor_id.is_none());
        // 区切り文字・前後空白を許容。
        assert_eq!(parse_setup_code(" 3497-011-2332 ").unwrap(), m);
        // 小文字の mt: も受ける。
        assert_eq!(
            parse_setup_code("mt:-24J0AFN00KA0648G00").unwrap().passcode,
            20202021
        );
    }

    #[test]
    fn round_trip_with_core_generators() {
        for &(disc, pass, vid, pid) in &[
            (0u16, 1u32, 0u16, 0u16),
            (3840, 20202021, 0xFFF1, 0x8001),
            (0x0FFF, 99_999_998, 0xFFFF, 0xFFFF),
            (1234, 34567890, 0x131B, 0x0002),
        ] {
            let mut buf = [0u8; QR_PAYLOAD_MAX_LEN];
            let n = qr_payload(
                &OnboardingPayload {
                    vendor_id: vid,
                    product_id: pid,
                    discriminator: disc,
                    passcode: pass,
                    discovery_caps: DISCOVERY_CAP_BLE,
                },
                &mut buf,
            )
            .unwrap();
            let qr = std::str::from_utf8(&buf[..n]).unwrap();
            let c = parse_setup_code(qr).unwrap();
            assert_eq!(c.discriminator, Disc::Long(disc), "{qr}");
            assert_eq!(c.passcode, pass);
            assert_eq!((c.vendor_id, c.product_id), (Some(vid), Some(pid)));
            assert_eq!(c.discovery_caps, Some(DISCOVERY_CAP_BLE));

            let manual = manual_pairing_code(disc, pass);
            let m = parse_setup_code(std::str::from_utf8(&manual).unwrap()).unwrap();
            assert_eq!(m.discriminator, Disc::Short((disc >> 8) as u8));
            assert_eq!(m.passcode, pass);
            assert!(m.discriminator.matches(disc));
        }
    }

    #[test]
    fn rejects_bad_codes() {
        // 検査数字違い。
        assert!(parse_setup_code("34970112333")
            .unwrap_err()
            .contains("check digit"));
        // 桁数。
        assert!(parse_setup_code("3497011233").is_err());
        // 文字種。
        assert!(parse_setup_code("hello").is_err());
        // base38 範囲外の文字 / 長さ。
        assert!(parse_setup_code("MT:-24J0AFN00KA0648G0!").is_err());
        assert!(parse_setup_code("MT:-24J0AFN00KA0648G0").is_err());
        assert!(parse_setup_code("MT:").is_err());
        // passcode 無効(00000000 相当 = QR のゼロ埋め)。
        assert!(parse_setup_code("MT:00000000000000000000")
            .unwrap_err()
            .contains("passcode"));
    }

    #[test]
    fn disc_matching() {
        assert!(Disc::Long(3840).matches(3840));
        assert!(!Disc::Long(3840).matches(3841));
        assert!(Disc::Short(15).matches(3840));
        assert!(Disc::Short(15).matches(0x0FFF));
        assert!(!Disc::Short(14).matches(3840));
        assert_eq!(Disc::Short(3).long(), None);
        assert_eq!(Disc::Long(7).long(), Some(7));
    }
}
