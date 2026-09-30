//! `POST /api/pairing` の要求解析・検証(設計 doc §4.2 `Command::Pair` / §6)と
//! 既定 node ID の採番、窓オープン要求の検証。
//!
//! ネットワーク・BLE に触れない純粋関数だけを置く(ユニットテスト対象)。

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;
use smctl::simple_matter::discovery::onboarding::passcode_is_valid;
use smctl::simple_matter::discovery::MATTER_PORT;

use crate::error::ApiError;
use crate::onboarding::{parse_setup_code, Disc, SetupCode};
use crate::value::{from_hex, parse_id};

/// 運用 node ID の上限(0xFFFF_FFF0_0000_0000 以上はグループ/一時/予約。仕様 §2.5.5)。
pub const MAX_OPERATIONAL_NODE_ID: u64 = 0xFFFF_FFEF_FFFF_FFFF;
/// アドレス帳ラベルの上限(`nodes.tlv` の共有 codec の上限)。
pub const MAX_LABEL_LEN: usize = 64;
/// Thread Operational Dataset の上限(smctl `pairing ble-thread` と同じ)。
const MAX_DATASET_LEN: usize = 254;
/// 窓の許容秒数(OpenCommissioningWindow の仕様範囲)。
pub const WINDOW_TIMEOUT_RANGE: std::ops::RangeInclusive<u16> = 180..=900;

/// pairing の方式と方式固有の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairMethod {
    /// mDNS(`_matterc._udp`)で commissionable を探して UDP でコミッショニング。
    OnNetwork { disc: Option<Disc> },
    /// アドレス直指定の UDP コミッショニング。
    Address { addr: SocketAddr },
    /// BLE で PASE〜AddNOC + Wi-Fi 資格情報投入、CASE 以降は運用 UDP。
    BleWifi {
        disc: Option<Disc>,
        ssid: String,
        password: String,
    },
    /// BLE で PASE〜AddNOC + Thread dataset 投入、CASE 以降は運用 UDP。
    BleThread {
        disc: Option<Disc>,
        dataset: Vec<u8>,
    },
}

impl PairMethod {
    pub fn name(&self) -> &'static str {
        match self {
            PairMethod::OnNetwork { .. } => "onnetwork",
            PairMethod::Address { .. } => "address",
            PairMethod::BleWifi { .. } => "ble-wifi",
            PairMethod::BleThread { .. } => "ble-thread",
        }
    }
}

/// 検証済みの pairing 要求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairRequest {
    pub method: PairMethod,
    pub passcode: u32,
    /// 明示指定の node ID(`None` = アドレス帳の次の空き番号)。
    pub node_id: Option<u64>,
    pub label: String,
    /// `code` を解析した結果(プレビュー・ログ用)。
    pub code: Option<SetupCode>,
}

fn str_field<'a>(body: &'a Value, k: &str) -> Result<Option<&'a str>, ApiError> {
    match body.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(ApiError::bad_request(format!("`{k}` must be a string"))),
    }
}

/// 数値 or 10 進 / `0x` 文字列の整数フィールド。
fn int_field(body: &Value, k: &str) -> Result<Option<u64>, ApiError> {
    match body.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| ApiError::bad_request(format!("`{k}` must be a non-negative integer"))),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(Value::String(s)) => parse_id(s)
            .map(Some)
            .map_err(|_| ApiError::bad_request(format!("`{k}`: invalid number {s:?}"))),
        Some(_) => Err(ApiError::bad_request(format!("`{k}` must be a number"))),
    }
}

/// passcode(数値 or 数字列。先頭 0 可)。
fn passcode_field(body: &Value) -> Result<Option<u32>, ApiError> {
    let v = match body.get("passcode") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) if s.trim().is_empty() => return Ok(None),
        Some(Value::String(s)) => {
            let t: String = s.chars().filter(|c| *c != '-' && *c != ' ').collect();
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                t.parse().ok()
            }
        }
        Some(_) => None,
    };
    let p = v
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| ApiError::bad_request("`passcode` must be an 8-digit number"))?;
    if !passcode_is_valid(p) {
        return Err(ApiError::bad_request(format!(
            "invalid setup passcode {p} (1..=99999998, not a trivial value)"
        )));
    }
    Ok(Some(p))
}

/// discriminator(12 ビット)。
fn disc_field(body: &Value) -> Result<Option<u16>, ApiError> {
    match int_field(body, "discriminator")? {
        None => Ok(None),
        Some(d) if d <= 0x0FFF => Ok(Some(d as u16)),
        Some(d) => Err(ApiError::bad_request(format!(
            "discriminator {d} out of range (12-bit, 0..=4095)"
        ))),
    }
}

/// node ID の検証(0 と非運用範囲を拒否)。
pub fn check_node_id(id: u64) -> Result<u64, ApiError> {
    if id == 0 || id > MAX_OPERATIONAL_NODE_ID {
        return Err(ApiError::bad_request(format!(
            "node id {id:#x} is not an operational node id (1..={MAX_OPERATIONAL_NODE_ID:#x})"
        )));
    }
    Ok(id)
}

/// ラベルの検証(`nodes.tlv` の上限 64 バイト)。
pub fn check_label(label: &str) -> Result<String, ApiError> {
    let l = label.trim();
    if l.len() > MAX_LABEL_LEN {
        return Err(ApiError::bad_request(format!(
            "label too long ({} bytes, max {MAX_LABEL_LEN})",
            l.len()
        )));
    }
    if l.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "label must not contain control characters",
        ));
    }
    Ok(l.to_string())
}

/// `POST /api/pairing` の本文を検証する。`ble` = BLE 経路がビルドに含まれるか。
pub fn parse_pair_request(body: &Value, ble: bool) -> Result<PairRequest, ApiError> {
    if !body.is_object() {
        return Err(ApiError::bad_request("request body must be a JSON object"));
    }
    let method = str_field(body, "method")?
        .ok_or_else(|| {
            ApiError::bad_request("`method` is required (onnetwork|address|ble-wifi|ble-thread)")
        })?
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        method.as_str(),
        "onnetwork" | "address" | "ble-wifi" | "ble-thread"
    ) {
        return Err(ApiError::bad_request(format!(
            "unknown method {method:?} (onnetwork|address|ble-wifi|ble-thread)"
        )));
    }
    if method.starts_with("ble-") && !ble {
        return Err(ApiError::bad_request(
            "BLE not compiled in (rebuild smweb with `--features ble`)",
        ));
    }

    // 秘密: code か discriminator + passcode のどちらか。
    let code = str_field(body, "code")?
        .map(parse_setup_code)
        .transpose()
        .map_err(|e| ApiError::bad_request(format!("`code`: {e}")))?;
    let passcode = passcode_field(body)?;
    let disc = disc_field(body)?;
    let (passcode, disc) = match &code {
        Some(c) => {
            if passcode.is_some() || disc.is_some() {
                return Err(ApiError::bad_request(
                    "give either `code` or `discriminator` + `passcode`, not both",
                ));
            }
            (c.passcode, Some(c.discriminator))
        }
        None => (
            passcode.ok_or_else(|| {
                ApiError::bad_request(
                    "`code` (QR payload / manual pairing code) or `passcode` is required",
                )
            })?,
            disc.map(Disc::Long),
        ),
    };

    let method = match method.as_str() {
        "onnetwork" => PairMethod::OnNetwork { disc },
        "address" => {
            let ip_s = str_field(body, "ip")?
                .ok_or_else(|| ApiError::bad_request("`ip` is required for method address"))?;
            let ip_t = ip_s.trim().trim_start_matches('[').trim_end_matches(']');
            let ip: IpAddr = ip_t
                .parse()
                .map_err(|_| ApiError::bad_request(format!("invalid ip address {ip_s:?}")))?;
            let port = match int_field(body, "port")? {
                None => MATTER_PORT,
                Some(p) if (1..=u16::MAX as u64).contains(&p) => p as u16,
                Some(p) => return Err(ApiError::bad_request(format!("invalid port {p}"))),
            };
            PairMethod::Address {
                addr: SocketAddr::new(ip, port),
            }
        }
        "ble-wifi" => {
            let ssid = match body.get("ssid") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err(ApiError::bad_request("`ssid` is required for ble-wifi")),
            };
            if ssid.is_empty() || ssid.len() > 32 {
                return Err(ApiError::bad_request(format!(
                    "invalid ssid (1..=32 bytes): {ssid:?}"
                )));
            }
            let password = match body.get("password") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(s)) => s.clone(),
                Some(_) => return Err(ApiError::bad_request("`password` must be a string")),
            };
            if password.len() > 64 {
                return Err(ApiError::bad_request(
                    "invalid wifi password (max 64 bytes)",
                ));
            }
            PairMethod::BleWifi {
                disc,
                ssid,
                password,
            }
        }
        _ => {
            let hex = str_field(body, "dataset")?.ok_or_else(|| {
                ApiError::bad_request("`dataset` (Thread operational dataset TLV hex) is required")
            })?;
            let dataset = from_hex(hex).map_err(|_| {
                ApiError::bad_request("`dataset` must be an even-length hex string")
            })?;
            if dataset.is_empty() || dataset.len() > MAX_DATASET_LEN {
                return Err(ApiError::bad_request(format!(
                    "invalid dataset length {} bytes (1..={MAX_DATASET_LEN})",
                    dataset.len()
                )));
            }
            PairMethod::BleThread { disc, dataset }
        }
    };

    let node_id = int_field(body, "node_id")?.map(check_node_id).transpose()?;
    let label = check_label(str_field(body, "label")?.unwrap_or(""))?;
    Ok(PairRequest {
        method,
        passcode,
        node_id,
        label,
        code,
    })
}

/// 既定の node ID: 既存の最大 + 1(空なら 1)。運用範囲を超えるなら最小の空き番号。
pub fn next_free_node_id(existing: &[u64]) -> u64 {
    match existing.iter().copied().max() {
        None => 1,
        Some(m) if m < MAX_OPERATIONAL_NODE_ID => m + 1,
        Some(_) => (1..=MAX_OPERATIONAL_NODE_ID)
            .find(|id| !existing.contains(id))
            .unwrap_or(1),
    }
}

/// `POST /api/nodes/{id}/window` の本文: `(timeout_s, discriminator, passcode)`。
pub fn parse_window_request(body: &Value) -> Result<(u16, Option<u16>, Option<u32>), ApiError> {
    if !(body.is_null() || body.is_object()) {
        return Err(ApiError::bad_request("request body must be a JSON object"));
    }
    let timeout = int_field(body, "timeout_s")?.unwrap_or(900);
    let r = WINDOW_TIMEOUT_RANGE;
    if timeout < *r.start() as u64 || timeout > *r.end() as u64 {
        return Err(ApiError::bad_request(format!(
            "timeout_s {timeout} out of range ({}..={})",
            r.start(),
            r.end()
        )));
    }
    Ok((timeout as u16, disc_field(body)?, passcode_field(body)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ok(v: Value) -> PairRequest {
        parse_pair_request(&v, true).unwrap()
    }

    fn err(v: Value, ble: bool) -> String {
        parse_pair_request(&v, ble).unwrap_err().message
    }

    #[test]
    fn onnetwork_from_codes() {
        let r = ok(json!({"method": "onnetwork", "code": "MT:-24J0AFN00KA0648G00"}));
        assert_eq!(
            r.method,
            PairMethod::OnNetwork {
                disc: Some(Disc::Long(3840))
            }
        );
        assert_eq!(r.passcode, 20202021);
        assert_eq!(r.node_id, None);
        assert_eq!(r.label, "");
        assert_eq!(r.code.as_ref().unwrap().source, "qr");

        let r = ok(
            json!({"method": "onnetwork", "code": "3497-011-2332", "node_id": "0x22", "label": " AirQ "}),
        );
        assert_eq!(
            r.method,
            PairMethod::OnNetwork {
                disc: Some(Disc::Short(15))
            }
        );
        assert_eq!(r.node_id, Some(0x22));
        assert_eq!(r.label, "AirQ");

        // 明示の discriminator + passcode(文字列でも可)。
        let r = ok(json!({"method": "ONNETWORK", "discriminator": 3840, "passcode": "20202021"}));
        assert_eq!(
            r.method,
            PairMethod::OnNetwork {
                disc: Some(Disc::Long(3840))
            }
        );
        // discriminator 省略は「任意の commissionable」。
        let r = ok(json!({"method": "onnetwork", "passcode": 20202021}));
        assert_eq!(r.method, PairMethod::OnNetwork { disc: None });
    }

    #[test]
    fn field_checks() {
        assert!(err(json!({}), true).contains("method"));
        assert!(
            err(json!({"method": "nfc", "passcode": 20202021}), true).contains("unknown method")
        );
        assert!(err(json!({"method": "onnetwork"}), true).contains("required"));
        assert!(err(
            json!({"method": "onnetwork", "code": "34970112332", "passcode": 20202021}),
            true
        )
        .contains("either"));
        assert!(err(json!({"method": "onnetwork", "code": "34970112333"}), true).contains("code"));
        assert!(
            err(json!({"method": "onnetwork", "passcode": 12345678}), true).contains("passcode")
        );
        assert!(err(
            json!({"method": "onnetwork", "passcode": 20202021, "discriminator": 4096}),
            true
        )
        .contains("discriminator"));
        assert!(err(
            json!({"method": "onnetwork", "passcode": 20202021, "node_id": 0}),
            true
        )
        .contains("node id"));
        assert!(err(
            json!({"method": "onnetwork", "passcode": 20202021, "node_id": "0xFFFFFFFD00000001"}),
            true
        )
        .contains("node id"));
        assert!(err(
            json!({"method": "onnetwork", "passcode": 20202021, "label": "x".repeat(65)}),
            true
        )
        .contains("label"));
        assert!(err(json!([1, 2]), true).contains("object"));
    }

    #[test]
    fn address_method() {
        let r = ok(json!({"method": "address", "ip": "192.168.8.163", "passcode": 20202021}));
        assert_eq!(
            r.method,
            PairMethod::Address {
                addr: "192.168.8.163:5540".parse().unwrap()
            }
        );
        let r = ok(
            json!({"method": "address", "ip": "[fe80::1]", "port": 5541, "code": "34970112332"}),
        );
        assert_eq!(
            r.method,
            PairMethod::Address {
                addr: "[fe80::1]:5541".parse().unwrap()
            }
        );
        assert!(err(json!({"method": "address", "passcode": 20202021}), true).contains("ip"));
        assert!(err(
            json!({"method": "address", "ip": "nope", "passcode": 20202021}),
            true
        )
        .contains("ip"));
        assert!(err(
            json!({"method": "address", "ip": "10.0.0.1", "port": 0, "passcode": 20202021}),
            true
        )
        .contains("port"));
    }

    #[test]
    fn ble_methods() {
        let r = ok(
            json!({"method": "ble-wifi", "code": "MT:-24J0AFN00KA0648G00", "ssid": "iotap", "password": "pw"}),
        );
        assert_eq!(
            r.method,
            PairMethod::BleWifi {
                disc: Some(Disc::Long(3840)),
                ssid: "iotap".into(),
                password: "pw".into()
            }
        );
        assert!(err(json!({"method": "ble-wifi", "passcode": 20202021}), true).contains("ssid"));
        assert!(err(
            json!({"method": "ble-wifi", "passcode": 20202021, "ssid": "x".repeat(33)}),
            true
        )
        .contains("ssid"));
        let r = ok(json!({"method": "ble-thread", "passcode": 20202021, "dataset": "0e08 0000"}));
        assert_eq!(
            r.method,
            PairMethod::BleThread {
                disc: None,
                dataset: vec![0x0e, 0x08, 0, 0]
            }
        );
        assert!(
            err(json!({"method": "ble-thread", "passcode": 20202021}), true).contains("dataset")
        );
        assert!(err(
            json!({"method": "ble-thread", "passcode": 20202021, "dataset": "abc"}),
            true
        )
        .contains("dataset"));
        // BLE 無しビルド。
        assert!(err(
            json!({"method": "ble-wifi", "passcode": 20202021, "ssid": "a"}),
            false
        )
        .contains("BLE not compiled in"));
        // UDP 方式は BLE 無しでも通る。
        assert!(
            parse_pair_request(&json!({"method": "onnetwork", "passcode": 20202021}), false)
                .is_ok()
        );
    }

    #[test]
    fn next_free_id() {
        assert_eq!(next_free_node_id(&[]), 1);
        assert_eq!(next_free_node_id(&[33]), 34);
        assert_eq!(next_free_node_id(&[5, 1, 3]), 6);
        assert_eq!(next_free_node_id(&[1, MAX_OPERATIONAL_NODE_ID]), 2);
    }

    #[test]
    fn window_request() {
        assert_eq!(
            parse_window_request(&Value::Null).unwrap(),
            (900, None, None)
        );
        assert_eq!(
            parse_window_request(&json!({"timeout_s": 300})).unwrap(),
            (300, None, None)
        );
        assert_eq!(
            parse_window_request(
                &json!({"timeout_s": "180", "discriminator": 3840, "passcode": 20202021})
            )
            .unwrap(),
            (180, Some(3840), Some(20202021))
        );
        assert!(parse_window_request(&json!({"timeout_s": 60})).is_err());
        assert!(parse_window_request(&json!({"timeout_s": 901})).is_err());
        assert!(parse_window_request(&json!({"passcode": 11111111})).is_err());
        assert!(parse_window_request(&json!([1])).is_err());
    }

    #[test]
    fn label_check() {
        assert_eq!(check_label("  Living room ").unwrap(), "Living room");
        assert_eq!(check_label("").unwrap(), "");
        assert!(check_label(&"あ".repeat(22)).is_err()); // 66 bytes
        assert!(check_label("a\nb").is_err());
    }
}
