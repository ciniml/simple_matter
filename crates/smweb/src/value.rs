//! ID パースと値の JSON 化(設計 doc §5.3)。
//!
//! - パス中の ID は 10 進 / `0x` 16 進(クラスタ・属性・コマンドはクラスタ表の名前も可)。
//! - 属性値はクラスタ表の [`ValueKind`] に従って JSON スカラへ。表に無い属性・複合型は
//!   `{ "raw": "<hex>", "pretty": "<tlvfmt 出力>", "decoded": <汎用 JSON> }`。
//! - Invoke の `args`(JSON オブジェクト)はクラスタ表のフィールド定義で TLV 値に変換する
//!   (リテラル解釈は smctl の [`parse_literal`] を共有)。

use serde_json::{json, Map, Value};
use smctl::clusters::{self, ClusterDef, CmdDef, ValueKind};
use smctl::ops::{parse_literal, parse_u64, Parsed};
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId, CommandId};
use smctl::simple_matter::tlv::{ContainerType, TlvElement, TlvReader, TlvTag, TlvValue};

use crate::error::ApiError;

/// 10 進 / `0x` 16 進の u64。
pub fn parse_id(s: &str) -> Result<u64, ApiError> {
    parse_u64(s.trim()).map_err(ApiError::bad_request)
}

/// 範囲チェック付きの ID パース。
pub fn parse_id_max(s: &str, max: u64, what: &str) -> Result<u64, ApiError> {
    let v = parse_id(s)?;
    if v > max {
        return Err(ApiError::bad_request(format!(
            "{what} {v:#x} out of range (max {max:#x})"
        )));
    }
    Ok(v)
}

/// エンドポイント番号。
pub fn parse_endpoint(s: &str) -> Result<u16, ApiError> {
    Ok(parse_id_max(s, u16::MAX as u64, "endpoint")? as u16)
}

/// クラスタ(ID またはクラスタ表の名前)。表に載っていれば定義も返す。
pub fn resolve_cluster(s: &str) -> Result<(ClusterId, Option<&'static ClusterDef>), ApiError> {
    if let Some(def) = clusters::by_name(s) {
        return Ok((def.id, Some(def)));
    }
    let id =
        ClusterId(parse_id_max(s, u32::MAX as u64, "cluster").map_err(|_| {
            ApiError::bad_request(format!("unknown cluster {s:?} (id or table name)"))
        })? as u32);
    Ok((id, clusters::by_id(id)))
}

/// 属性(ID または表の名前)。
pub fn resolve_attr(def: Option<&'static ClusterDef>, s: &str) -> Result<AttributeId, ApiError> {
    if let Some(a) = def.and_then(|d| d.attr_by_name(s)) {
        return Ok(a.id);
    }
    parse_id_max(s, u32::MAX as u64, "attribute")
        .map(|v| AttributeId(v as u32))
        .map_err(|_| ApiError::bad_request(format!("unknown attribute {s:?} (id or table name)")))
}

/// コマンド(ID または表の名前)。表に載っていれば定義も返す。
pub fn resolve_cmd(
    def: Option<&'static ClusterDef>,
    s: &str,
) -> Result<(CommandId, Option<&'static CmdDef>), ApiError> {
    if let Some(c) = def.and_then(|d| d.cmd_by_name(s)) {
        return Ok((c.id, Some(c)));
    }
    let id =
        CommandId(parse_id_max(s, u32::MAX as u64, "command").map_err(|_| {
            ApiError::bad_request(format!("unknown command {s:?} (id or table name)"))
        })? as u32);
    let cdef = def.and_then(|d| d.cmds.iter().find(|c| c.id == id));
    Ok((id, cdef))
}

/// 16 進文字列(小文字)。
pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 16 進文字列のパース(空白・`hex:` 前置を許容)。
pub fn from_hex(s: &str) -> Result<Vec<u8>, ApiError> {
    let t: String = s.split_whitespace().collect();
    let t = t.strip_prefix("hex:").unwrap_or(&t);
    let err = || ApiError::bad_request(format!("invalid hex: {s:?}"));
    if !t.len().is_multiple_of(2) || !t.is_ascii() {
        return Err(err());
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).map_err(|_| err()))
        .collect()
}

/// 生 TLV の表示用 JSON(`raw` / `pretty` / `decoded`)。
pub fn raw_json(raw: &[u8]) -> Value {
    json!({
        "raw": to_hex(raw),
        "pretty": smctl::tlvfmt::pretty(raw).join("\n"),
        "decoded": generic_json(raw),
    })
}

/// 生 TLV(先頭 1 要素)を型注釈無しで JSON にする(struct は context タグ番号キー)。
pub fn generic_json(raw: &[u8]) -> Value {
    let mut r = TlvReader::new(raw);
    match r.read_next() {
        Ok(Some(e)) => element_json(&mut r, &e),
        _ => Value::Null,
    }
}

fn element_json(r: &mut TlvReader, e: &TlvElement) -> Value {
    match e.value {
        TlvValue::Boolean(b) => json!(b),
        TlvValue::UnsignedInteger(v) => json!(v),
        TlvValue::SignedInteger(v) => json!(v),
        TlvValue::Float(v) => float_json(v as f64),
        TlvValue::Double(v) => float_json(v),
        TlvValue::Utf8String(s) => json!(s),
        TlvValue::ByteString(b) => json!(to_hex(b)),
        TlvValue::Null => Value::Null,
        TlvValue::ContainerStart(t) => {
            let object = matches!(t, ContainerType::Structure);
            let mut obj = Map::new();
            let mut arr = Vec::new();
            let mut idx = 0u32;
            loop {
                match r.read_next() {
                    Ok(Some(c)) if matches!(c.value, TlvValue::ContainerEnd) => break,
                    Ok(Some(c)) => {
                        let v = element_json(r, &c);
                        if object {
                            let key = match c.tag {
                                TlvTag::ContextSpecific(n) => n.to_string(),
                                _ => idx.to_string(),
                            };
                            obj.insert(key, v);
                        } else {
                            arr.push(v);
                        }
                        idx += 1;
                    }
                    _ => break,
                }
            }
            if object {
                Value::Object(obj)
            } else {
                Value::Array(arr)
            }
        }
        TlvValue::ContainerEnd => Value::Null,
    }
}

fn float_json(v: f64) -> Value {
    serde_json::Number::from_f64(v)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

/// 属性値(生 TLV の先頭 1 要素)を [`ValueKind`] に従って JSON にする。
///
/// スカラ型で TLV 型が一致すれば JSON スカラ(nullable 属性の null は `null`)。
/// `Raw` / 表に無い(`kind = None`)/ 型不一致は [`raw_json`] のオブジェクト。
pub fn value_json(kind: Option<ValueKind>, raw: &[u8]) -> Value {
    let Some(kind) = kind else {
        return raw_json(raw);
    };
    let mut r = TlvReader::new(raw);
    let Ok(Some(e)) = r.read_next() else {
        return raw_json(raw);
    };
    let v = match (kind, &e.value) {
        (_, TlvValue::Null) if kind != ValueKind::Raw => Some(Value::Null),
        (ValueKind::Bool, TlvValue::Boolean(b)) => Some(json!(b)),
        (
            ValueKind::U8 | ValueKind::U16 | ValueKind::U32 | ValueKind::U64,
            TlvValue::UnsignedInteger(v),
        ) => Some(json!(v)),
        (
            ValueKind::I8 | ValueKind::I16 | ValueKind::I32 | ValueKind::I64,
            TlvValue::SignedInteger(v),
        ) => Some(json!(v)),
        (ValueKind::F32 | ValueKind::F64, TlvValue::Float(v)) => Some(float_json(*v as f64)),
        (ValueKind::F32 | ValueKind::F64, TlvValue::Double(v)) => Some(float_json(*v)),
        (ValueKind::Utf8, TlvValue::Utf8String(s)) => Some(json!(s)),
        (ValueKind::Bytes, TlvValue::ByteString(b)) => Some(json!(to_hex(b))),
        _ => None,
    };
    v.unwrap_or_else(|| raw_json(raw))
}

/// Invoke の `args`(JSON オブジェクト)をコマンドフィールドへ変換する。
///
/// キーはフィールド名(表)または context タグ番号。`args` が `null` / `{}` なら
/// フィールド無し(必須フィールドがあればエラー)。表に無いコマンドで非空の `args` は
/// エラー(`tlv` を使う)。
pub fn args_to_fields(
    cmd: Option<&'static CmdDef>,
    args: Option<&Value>,
) -> Result<Vec<(u8, ValueKind, Parsed)>, ApiError> {
    let empty = Map::new();
    let obj = match args {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(m)) => m,
        Some(_) => return Err(ApiError::bad_request("`args` must be a JSON object")),
    };
    let Some(cmd) = cmd else {
        if obj.is_empty() {
            return Ok(Vec::new());
        }
        return Err(ApiError::bad_request(
            "command not in cluster table; pass fields as `tlv` hex instead of `args`",
        ));
    };
    let mut used = 0usize;
    let mut out = Vec::new();
    for f in cmd.fields {
        let v = obj.get(f.name).or_else(|| obj.get(&f.tag.to_string()));
        let Some(v) = v else {
            if f.optional {
                continue;
            }
            return Err(ApiError::bad_request(format!(
                "missing required field {:?} (tag {}, {})",
                f.name,
                f.tag,
                f.kind.name()
            )));
        };
        used += 1;
        let lit = match v {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => n.to_string(),
            Value::String(s) => s.clone(),
            _ => {
                return Err(ApiError::bad_request(format!(
                    "field {:?}: nested values are not supported (use `tlv`)",
                    f.name
                )))
            }
        };
        let parsed = parse_literal(f.kind, &lit)
            .map_err(|e| ApiError::bad_request(format!("field {:?}: {e}", f.name)))?;
        out.push((f.tag, f.kind, parsed));
    }
    if used != obj.len() {
        let known: Vec<&str> = cmd.fields.iter().map(|f| f.name).collect();
        return Err(ApiError::bad_request(format!(
            "unknown field(s) in args for {:?} (known: {known:?})",
            cmd.name
        )));
    }
    Ok(out)
}

/// AirQuality.AirQuality(enum8)の表示名(0..=6)。
pub const AIR_QUALITY_NAMES: [&str; 7] = [
    "Unknown",
    "Good",
    "Fair",
    "Moderate",
    "Poor",
    "VeryPoor",
    "ExtremelyPoor",
];

/// 属性値の表示ヒント(§5.3: `unit` / `scale` / 列挙名)。smweb 側の表で持ち、
/// smctl のクラスタ表(CLI 出力)には手を入れない。
pub fn display_hint(cluster: u32, attr: u32) -> Option<Value> {
    let measured = attr <= 2; // MeasuredValue / Min / Max
    match cluster {
        0x005B if attr == 0 => Some(json!({ "enum": AIR_QUALITY_NAMES })),
        0x0402 if measured => Some(json!({ "unit": "°C", "scale": 0.01 })),
        0x0405 if measured => Some(json!({ "unit": "%", "scale": 0.01 })),
        0x0403 if measured => Some(json!({ "unit": "kPa", "scale": 0.1 })),
        0x0404 if measured => Some(json!({ "unit": "m³/h", "scale": 0.1 })),
        0x040D | 0x0413 if measured => Some(json!({ "unit": "ppm" })),
        0x042A | 0x042C | 0x042D if measured => Some(json!({ "unit": "µg/m³" })),
        // PowerSource: BatVoltage(mV)/ BatPercentRemaining(0.5 % 単位)/ BatChargeLevel(enum8)。
        0x002F if attr == 0x000B => Some(json!({ "unit": "mV" })),
        0x002F if attr == 0x000C => Some(json!({ "unit": "%", "scale": 0.5 })),
        0x002F if attr == 0x000E => Some(json!({ "enum": ["OK", "Warning", "Critical"] })),
        _ => None,
    }
}

/// クラスタ表全体を JSON にする(`GET /api/clusters`)。属性には表示ヒント
/// ([`display_hint`])の `unit` / `scale` / `enum` を足す。
pub fn clusters_json() -> Value {
    Value::Array(
        clusters::CLUSTERS
            .iter()
            .map(|c| {
                json!({
                    "id": c.id.0,
                    "name": c.name,
                    "attributes": c.attrs.iter().map(|a| {
                        let mut o = json!({
                            "id": a.id.0,
                            "name": a.name,
                            "kind": a.kind.name(),
                            "writable": a.writable,
                        });
                        if let Some(Value::Object(h)) = display_hint(c.id.0, a.id.0) {
                            for (k, v) in h {
                                o[k] = v;
                            }
                        }
                        o
                    }).collect::<Vec<_>>(),
                    "commands": c.cmds.iter().map(|m| json!({
                        "id": m.id.0,
                        "name": m.name,
                        "fields": m.fields.iter().map(|f| json!({
                            "tag": f.tag,
                            "name": f.name,
                            "kind": f.kind.name(),
                            "optional": f.optional,
                        })).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use smctl::simple_matter::tlv::TlvWriter;

    fn enc(f: impl FnOnce(&mut TlvWriter)) -> Vec<u8> {
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        f(&mut w);
        w.written().to_vec()
    }

    const T2: TlvTag = TlvTag::ContextSpecific(2);

    #[test]
    fn hex_parsing() {
        assert_eq!(from_hex("15 18").unwrap(), vec![0x15, 0x18]);
        assert_eq!(from_hex("hex:0aFF").unwrap(), vec![0x0a, 0xff]);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert_eq!(to_hex(&[0, 0xab]), "00ab");
    }

    #[test]
    fn id_parsing_decimal_and_hex() {
        assert_eq!(parse_id("42").unwrap(), 42);
        assert_eq!(parse_id("0x2A").unwrap(), 42);
        assert_eq!(parse_id("0x0000000000001234").unwrap(), 0x1234);
        assert!(parse_id("zz").is_err());
        assert!(parse_id("").is_err());
        assert_eq!(parse_endpoint("0x1").unwrap(), 1);
        assert!(parse_endpoint("65536").is_err());
    }

    #[test]
    fn cluster_attr_cmd_resolution() {
        let (id, def) = resolve_cluster("0x0006").unwrap();
        assert_eq!(id.0, 6);
        assert_eq!(def.unwrap().name, "onoff");
        let (id, def) = resolve_cluster("onoff").unwrap();
        assert_eq!(id.0, 6);
        assert_eq!(resolve_attr(def, "on-off").unwrap().0, 0);
        assert_eq!(resolve_attr(def, "0x4001").unwrap().0, 0x4001);
        let (cid, cdef) = resolve_cmd(def, "toggle").unwrap();
        assert_eq!(cid.0, 2);
        assert!(cdef.is_some());
        let (cid, cdef) = resolve_cmd(def, "1").unwrap();
        assert_eq!(cid.0, 1);
        assert_eq!(cdef.unwrap().name, "on");
        // 表に無いクラスタは ID だけ解決できる。
        let (id, def) = resolve_cluster("0xFC00").unwrap();
        assert_eq!(id.0, 0xFC00);
        assert!(def.is_none());
        assert!(resolve_cluster("no-such-cluster").is_err());
    }

    #[test]
    fn scalar_values_by_kind() {
        let b = enc(|w| w.write_bool(&T2, true).unwrap());
        assert_eq!(value_json(Some(ValueKind::Bool), &b), json!(true));
        let u = enc(|w| w.write_u16(&T2, 1234).unwrap());
        assert_eq!(value_json(Some(ValueKind::U16), &u), json!(1234));
        let i = enc(|w| w.write_i16(&T2, -250).unwrap());
        assert_eq!(value_json(Some(ValueKind::I16), &i), json!(-250));
        let s = enc(|w| w.write_utf8(&T2, "AirQ").unwrap());
        assert_eq!(value_json(Some(ValueKind::Utf8), &s), json!("AirQ"));
        let f = enc(|w| w.write_f32(&T2, 1.5).unwrap());
        assert_eq!(value_json(Some(ValueKind::F32), &f), json!(1.5));
        let by = enc(|w| w.write_bytes(&T2, &[0xde, 0xad]).unwrap());
        assert_eq!(value_json(Some(ValueKind::Bytes), &by), json!("dead"));
        let n = enc(|w| w.write_null(&T2).unwrap());
        assert_eq!(value_json(Some(ValueKind::I16), &n), Value::Null);
    }

    #[test]
    fn raw_fallback() {
        // 表に無い属性。
        let u = enc(|w| w.write_u8(&T2, 7).unwrap());
        let v = value_json(None, &u);
        assert_eq!(v["raw"], json!(to_hex(&u)));
        assert_eq!(v["decoded"], json!(7));
        assert!(v["pretty"].as_str().unwrap().contains('7'));
        // 型不一致(表は bool、実際は u8)も生表示へ落とす。
        assert!(value_json(Some(ValueKind::Bool), &u).get("raw").is_some());
        // Raw(list)。
        let l = enc(|w| {
            w.start_container(&T2, ContainerType::Array).unwrap();
            w.write_u16(&TlvTag::Anonymous, 6).unwrap();
            w.write_u16(&TlvTag::Anonymous, 8).unwrap();
            w.end_container().unwrap();
        });
        let v = value_json(Some(ValueKind::Raw), &l);
        assert_eq!(v["decoded"], json!([6, 8]));
    }

    #[test]
    fn invoke_args_conversion() {
        let def = clusters::by_name("onoff");
        let (_, toggle) = resolve_cmd(def, "toggle").unwrap();
        assert!(args_to_fields(toggle, None).unwrap().is_empty());
        assert!(args_to_fields(toggle, Some(&json!({}))).unwrap().is_empty());
        assert!(args_to_fields(toggle, Some(&json!({"x": 1}))).is_err());
        // 表に無いコマンド: 空 args のみ可。
        assert!(args_to_fields(None, Some(&json!({}))).unwrap().is_empty());
        assert!(args_to_fields(None, Some(&json!({"0": 1}))).is_err());
        assert!(args_to_fields(toggle, Some(&json!([1]))).is_err());
        // フィールド付き(level-control move-to-level があれば)。
        let lc = clusters::by_name("level-control");
        if let Some(cmd) = lc.and_then(|d| d.cmd_by_name("move-to-level")) {
            let first = &cmd.fields[0];
            let mut args = Map::new();
            for f in cmd.fields.iter().filter(|f| !f.optional) {
                args.insert(f.name.to_string(), json!(1));
            }
            let fields = args_to_fields(Some(cmd), Some(&Value::Object(args))).unwrap();
            assert_eq!(fields[0].0, first.tag);
        }
    }

    #[test]
    fn clusters_export_shape() {
        let v = clusters_json();
        let onoff = v.as_array().unwrap().iter().find(|c| c["id"] == 6).unwrap();
        assert_eq!(onoff["name"], "onoff");
        assert_eq!(onoff["attributes"][0]["kind"], "bool");
        assert!(onoff["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "toggle"));
        assert!(onoff["attributes"][0].get("unit").is_none());
        let find = |id: u32| {
            v.as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] == id)
                .unwrap()
                .clone()
        };
        let t = find(0x0402);
        assert_eq!(t["attributes"][0]["unit"], "°C");
        assert_eq!(t["attributes"][0]["scale"], 0.01);
        let aq = find(0x005B);
        assert_eq!(aq["attributes"][0]["enum"][5], "VeryPoor");
        assert_eq!(find(0x040D)["attributes"][0]["unit"], "ppm");
        assert_eq!(find(0x042A)["attributes"][0]["unit"], "µg/m³");
        assert_eq!(find(0x0405)["attributes"][0]["scale"], 0.01);
    }
}
