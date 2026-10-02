//! 汎用デバイスモデル(設計 doc §5.1 Describe / §5.2 種別判定と既定購読)の純粋部分。
//!
//! コントローラスレッドが Read した結果([`ReadItem`] 列)からモデルを組み立てる。
//! 通信はしない(単体テスト可能にするため、読み取り手順は `ctrl.rs` 側)。

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use smctl::clusters::{self, device_types, names};
use smctl::ops::embed::{ReadItem, ReadOutcome};
use smctl::simple_matter::dm::meta::{AttributeId, ClusterId};

use crate::model::{
    AttrModel, AttrPath, BasicInfo, ClusterModel, EndpointModel, NodeKind, NodeModel, Transport,
};
use crate::value::generic_json;

/// Descriptor クラスタ。
pub const DESCRIPTOR: u32 = 0x001D;
/// Descriptor.DeviceTypeList / ServerList / PartsList。
pub const DEVICE_TYPE_LIST: u32 = 0x0000;
pub const SERVER_LIST: u32 = 0x0001;
pub const PARTS_LIST: u32 = 0x0003;
/// BasicInformation クラスタ。
pub const BASIC_INFORMATION: u32 = 0x0028;
/// BasicInformation の Describe 対象属性(VendorName / ProductName / NodeLabel /
/// SoftwareVersionString / SerialNumber)。
pub const BASIC_ATTRS: [u32; 5] = [0x0001, 0x0003, 0x0005, 0x000A, 0x000F];
/// NetworkCommissioning クラスタ(FeatureMap で媒体を判定する)。
pub const NETWORK_COMMISSIONING: u32 = 0x0031;
/// グローバル属性 FeatureMap。
pub const FEATURE_MAP: u32 = 0xFFFC;
/// グローバル属性 AttributeList。
pub const ATTRIBUTE_LIST: u32 = 0xFFFB;

pub const ON_OFF: u32 = 0x0006;
pub const LEVEL_CONTROL: u32 = 0x0008;
pub const AIR_QUALITY: u32 = 0x005B;
pub const CO2: u32 = 0x040D;
pub const PM25: u32 = 0x042A;
pub const TEMPERATURE: u32 = 0x0402;
pub const HUMIDITY: u32 = 0x0405;
pub const BOOLEAN_STATE: u32 = 0x0045;
pub const POWER_SOURCE: u32 = 0x002F;
/// PowerSource.BatPercentRemaining(0.5 % 単位)。
pub const BAT_PERCENT_REMAINING: u32 = 0x000C;

/// SENSOR の既定購読クラスタ(いずれも属性 0: AirQuality / MeasuredValue)。
pub const SENSOR_CLUSTERS: [u32; 5] = [AIR_QUALITY, CO2, PM25, TEMPERATURE, HUMIDITY];

/// 1 購読あたりのパス上限(デバイス側 `PATHS` の既定 16 に合わせる)。
pub const MAX_SUB_PATHS: usize = 16;

/// グローバル属性の表示名・型(クラスタ表は持たないため)。
pub fn global_attr(id: u32) -> Option<(&'static str, &'static str)> {
    Some(match id {
        0xFFF8 => ("generated-command-list", "raw"),
        0xFFF9 => ("accepted-command-list", "raw"),
        0xFFFA => ("event-list", "raw"),
        0xFFFB => ("attribute-list", "raw"),
        0xFFFC => ("feature-map", "u32"),
        0xFFFD => ("cluster-revision", "u16"),
        _ => return None,
    })
}

/// 属性の表示モデル(表 → グローバル属性 → ID のみ)。
pub fn attr_model(cluster: u32, id: u32) -> AttrModel {
    let def = clusters::by_id(ClusterId(cluster)).and_then(|c| c.attr_by_id(AttributeId(id)));
    match def {
        Some(a) => AttrModel {
            id,
            name: Some(a.name.to_string()),
            kind: Some(a.kind.name().to_string()),
            writable: a.writable,
        },
        None => {
            let g = global_attr(id);
            AttrModel {
                id,
                name: g.map(|g| g.0.to_string()),
                kind: g.map(|g| g.1.to_string()),
                writable: false,
            }
        }
    }
}

/// 読み取り結果から `(ep, cluster, attr)` 一致の list 属性を `ep` ごとに集める。
///
/// 非 append の要素(配列)で list を置き換え、append 要素(ListIndex null のチャンク
/// 分割)は 1 要素として追記する。`map` は list 要素(汎用 JSON)→ u32。
pub fn collect_lists(
    items: &[ReadItem],
    cluster: u32,
    attr: u32,
    map: impl Fn(&Value) -> Option<u32>,
) -> BTreeMap<u16, Vec<u32>> {
    let mut out: BTreeMap<u16, Vec<u32>> = BTreeMap::new();
    for it in items {
        let (Some(ep), Some(c), Some(a)) = (it.endpoint, it.cluster, it.attribute) else {
            continue;
        };
        if c != cluster || a != attr {
            continue;
        }
        let ReadOutcome::Data(raw) = &it.outcome else {
            continue;
        };
        let v = generic_json(raw);
        if it.list_append {
            if let Some(x) = map(&v) {
                out.entry(ep).or_default().push(x);
            }
        } else if let Value::Array(a) = v {
            out.insert(ep, a.iter().filter_map(&map).collect());
        }
    }
    out
}

/// list 要素が整数(cluster ID / attribute ID / endpoint)。
pub fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|x| u32::try_from(x).ok())
}

/// DeviceTypeList の要素 `{0: deviceType, 1: revision}` → deviceType。
pub fn device_type_of(v: &Value) -> Option<u32> {
    v.get("0").and_then(as_u32)
}

/// 読み取り結果から `(cluster, attr)` 一致の UTF-8 文字列を取る(最初の ep)。
pub fn string_attr(items: &[ReadItem], cluster: u32, attr: u32) -> Option<String> {
    items.iter().find_map(|it| {
        if it.cluster != Some(cluster) || it.attribute != Some(attr) {
            return None;
        }
        match &it.outcome {
            ReadOutcome::Data(raw) => match generic_json(raw) {
                Value::String(s) => Some(s),
                _ => None,
            },
            _ => None,
        }
    })
}

/// BasicInformation の抜粋。
pub fn basic_info(items: &[ReadItem]) -> BasicInfo {
    let s = |a| string_attr(items, BASIC_INFORMATION, a);
    BasicInfo {
        vendor_name: s(0x0001),
        product_name: s(0x0003),
        node_label: s(0x0005).filter(|l| !l.is_empty()),
        software_version: s(0x000A),
        serial_number: s(0x000F),
    }
}

/// 読み取り結果の NetworkCommissioning FeatureMap から媒体一覧を作る(EP 昇順、重複なし)。
/// クラスタ無し / 読み取りエラー / 整数でない値は無視する(空 = 不明)。
pub fn transports(items: &[ReadItem]) -> Vec<Transport> {
    let mut maps: BTreeMap<u16, u32> = BTreeMap::new();
    for it in items {
        if it.cluster != Some(NETWORK_COMMISSIONING) || it.attribute != Some(FEATURE_MAP) {
            continue;
        }
        let (Some(ep), ReadOutcome::Data(raw)) = (it.endpoint, &it.outcome) else {
            continue;
        };
        if let Some(fm) = as_u32(&generic_json(raw)) {
            maps.insert(ep, fm);
        }
    }
    let mut out = Vec::new();
    for t in maps
        .values()
        .flat_map(|&fm| Transport::from_feature_map(fm))
    {
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// モデルを組み立てる。
///
/// - `parts`: EP0 の PartsList(EP0 自身は常に含める)。
/// - `device_types` / `servers`: EP ごとの DeviceTypeList / ServerList。
/// - `attr_lists`: `(ep, cluster)` ごとの AttributeList(読めたものだけ)。無いクラスタは
///   クラスタ表の属性、表にも無ければ空(ID のみ表示)。
pub fn build_model(
    parts: &[u16],
    device_types: &BTreeMap<u16, Vec<u32>>,
    servers: &BTreeMap<u16, Vec<u32>>,
    attr_lists: &BTreeMap<(u16, u32), Vec<u32>>,
    basic: BasicInfo,
    described_at: u64,
) -> NodeModel {
    let mut eps: Vec<u16> = std::iter::once(0).chain(parts.iter().copied()).collect();
    eps.sort_unstable();
    eps.dedup();
    let endpoints = eps
        .into_iter()
        .map(|ep| {
            let mut cl: Vec<u32> = servers.get(&ep).cloned().unwrap_or_default();
            cl.sort_unstable();
            cl.dedup();
            let clusters = cl
                .into_iter()
                .map(|cid| {
                    let def = clusters::by_id(ClusterId(cid));
                    let attrs = match attr_lists.get(&(ep, cid)) {
                        Some(ids) => {
                            let mut ids = ids.clone();
                            ids.sort_unstable();
                            ids.dedup();
                            ids.into_iter().map(|a| attr_model(cid, a)).collect()
                        }
                        None => def
                            .map(|d| d.attrs.iter().map(|a| attr_model(cid, a.id.0)).collect())
                            .unwrap_or_default(),
                    };
                    ClusterModel {
                        id: cid,
                        name: def.map(|d| d.name.to_string()),
                        spec_name: names::cluster_name(ClusterId(cid)).map(str::to_string),
                        attrs,
                    }
                })
                .collect();
            let dts = device_types.get(&ep).cloned().unwrap_or_default();
            EndpointModel {
                ep,
                device_type_names: dts
                    .iter()
                    .map(|&d| {
                        device_types::device_type_name(d)
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("{d:#06x}"))
                    })
                    .collect(),
                device_types: dts,
                clusters,
            }
        })
        .collect();
    NodeModel {
        endpoints,
        basic,
        described_at,
        transport: None,
        transports: Vec::new(),
    }
}

/// ノード種別(§5.2)。
pub fn classify(model: &NodeModel) -> NodeKind {
    if model.has_cluster(AIR_QUALITY) {
        NodeKind::Sensor
    } else if model.has_cluster(ON_OFF) {
        NodeKind::Light
    } else if model.has_cluster(BOOLEAN_STATE) {
        NodeKind::Contact
    } else {
        NodeKind::Other
    }
}

/// 種別ごとの既定購読パス(§5.2。存在する EP は Describe 結果から決める)。
pub fn default_paths(kind: NodeKind, model: &NodeModel) -> Vec<AttrPath> {
    let mut out = Vec::new();
    match kind {
        NodeKind::Sensor => {
            for c in SENSOR_CLUSTERS {
                out.extend(model.endpoints_with(c).map(|ep| AttrPath::new(ep, c, 0)));
            }
        }
        NodeKind::Light => {
            for ep in model.endpoints_with(ON_OFF) {
                out.push(AttrPath::new(ep, ON_OFF, 0));
                if model
                    .endpoints
                    .iter()
                    .any(|e| e.ep == ep && e.has_cluster(LEVEL_CONTROL))
                {
                    out.push(AttrPath::new(ep, LEVEL_CONTROL, 0));
                }
            }
        }
        NodeKind::Contact => {
            for ep in model.endpoints_with(BOOLEAN_STATE) {
                out.push(AttrPath::new(ep, BOOLEAN_STATE, 0));
            }
            // 電池残量。AttributeList が空のまま返すデバイス(Aqara Door and Window Sensor P2)
            // があるので、一覧が空なら載っているものとして購読する。
            for e in &model.endpoints {
                if let Some(c) = e.clusters.iter().find(|c| c.id == POWER_SOURCE) {
                    if c.attrs.is_empty() || c.attrs.iter().any(|a| a.id == BAT_PERCENT_REMAINING) {
                        out.push(AttrPath::new(e.ep, POWER_SOURCE, BAT_PERCENT_REMAINING));
                    }
                }
            }
        }
        NodeKind::Other => {}
    }
    out
}

/// 既定パス + watch パスを重複排除して上限までまとめる(順序は既定 → watch)。
pub fn merge_paths(defaults: &[AttrPath], watch: &[AttrPath]) -> Vec<AttrPath> {
    let mut out: Vec<AttrPath> = Vec::new();
    for p in defaults.iter().chain(watch) {
        if !out.contains(p) {
            out.push(*p);
        }
    }
    out.truncate(MAX_SUB_PATHS);
    out
}

/// 再接続のバックオフ(`attempt` = 連続失敗回数、0 始まり): 5 s → 60 s → 倍々 → 上限 10 分。
pub fn backoff(attempt: u32) -> Duration {
    const CAP: u64 = 600;
    let s = match attempt {
        0 => 5,
        n => 60u64.saturating_mul(1u64 << (n - 1).min(10)).min(CAP),
    };
    Duration::from_secs(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use smctl::simple_matter::tlv::{ContainerType, TlvTag, TlvWriter};

    fn enc(f: impl FnOnce(&mut TlvWriter)) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut w = TlvWriter::new(&mut buf);
        f(&mut w);
        w.written().to_vec()
    }

    const T2: TlvTag = TlvTag::ContextSpecific(2);

    fn u_list(v: &[u32]) -> Vec<u8> {
        enc(|w| {
            w.start_container(&T2, ContainerType::Array).unwrap();
            for x in v {
                w.write_u32(&TlvTag::Anonymous, *x).unwrap();
            }
            w.end_container().unwrap();
        })
    }

    fn item(ep: u16, cluster: u32, attr: u32, raw: Vec<u8>, append: bool) -> ReadItem {
        ReadItem {
            endpoint: Some(ep),
            cluster: Some(cluster),
            attribute: Some(attr),
            list_append: append,
            data_version: Some(1),
            outcome: ReadOutcome::Data(raw),
        }
    }

    /// AirQ 相当: EP1 AirQuality/CO2/PM2.5、EP2 温度、EP3 湿度。
    fn airq_model() -> NodeModel {
        let mut servers = BTreeMap::new();
        servers.insert(0, vec![DESCRIPTOR, BASIC_INFORMATION]);
        servers.insert(1, vec![DESCRIPTOR, PM25, AIR_QUALITY, CO2]);
        servers.insert(2, vec![DESCRIPTOR, TEMPERATURE]);
        servers.insert(3, vec![DESCRIPTOR, HUMIDITY]);
        let mut dts = BTreeMap::new();
        dts.insert(1, vec![0x002C]);
        let mut al = BTreeMap::new();
        al.insert((1, AIR_QUALITY), vec![0, 0xFFFD, 0xFFFC, 0x4242]);
        build_model(&[1, 2, 3], &dts, &servers, &al, BasicInfo::default(), 1)
    }

    #[test]
    fn list_collection_with_append_chunks() {
        let items = vec![
            item(0, DESCRIPTOR, SERVER_LIST, u_list(&[0x1D, 0x28]), false),
            item(1, DESCRIPTOR, SERVER_LIST, u_list(&[0x5B]), false),
            item(
                1,
                DESCRIPTOR,
                SERVER_LIST,
                enc(|w| w.write_u32(&T2, 0x40D).unwrap()),
                true,
            ),
            item(1, DESCRIPTOR, PARTS_LIST, u_list(&[9]), false),
        ];
        let m = collect_lists(&items, DESCRIPTOR, SERVER_LIST, as_u32);
        assert_eq!(m[&0], vec![0x1D, 0x28]);
        assert_eq!(m[&1], vec![0x5B, 0x40D]);
        assert_eq!(m.len(), 2);
        // DeviceTypeList(struct list)。
        let dtl = enc(|w| {
            w.start_container(&T2, ContainerType::Array).unwrap();
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u32(&TlvTag::ContextSpecific(0), 0x0016).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(1), 1).unwrap();
            w.end_container().unwrap();
            w.end_container().unwrap();
        });
        let m = collect_lists(
            &[item(0, DESCRIPTOR, DEVICE_TYPE_LIST, dtl, false)],
            DESCRIPTOR,
            DEVICE_TYPE_LIST,
            device_type_of,
        );
        assert_eq!(m[&0], vec![0x0016]);
    }

    #[test]
    fn basic_info_strings() {
        let s = |a, v: &str| {
            item(
                0,
                BASIC_INFORMATION,
                a,
                enc(|w| w.write_utf8(&T2, v).unwrap()),
                false,
            )
        };
        let b = basic_info(&[s(1, "Acme"), s(3, "AirQ"), s(5, ""), s(0x0F, "SN1")]);
        assert_eq!(b.vendor_name.as_deref(), Some("Acme"));
        assert_eq!(b.product_name.as_deref(), Some("AirQ"));
        assert_eq!(b.node_label, None);
        assert_eq!(b.serial_number.as_deref(), Some("SN1"));
        assert_eq!(b.software_version, None);
    }

    #[test]
    fn model_building_names_and_attrs() {
        let m = airq_model();
        assert_eq!(
            m.endpoints.iter().map(|e| e.ep).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        let ep1 = &m.endpoints[1];
        assert_eq!(ep1.device_types, vec![0x002C]);
        assert_eq!(ep1.device_type_names, vec!["AirQualitySensor".to_string()]);
        // クラスタは ID 昇順、表の名前付き。
        assert_eq!(
            ep1.clusters.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![DESCRIPTOR, AIR_QUALITY, CO2, PM25]
        );
        let aq = &ep1.clusters[1];
        assert_eq!(aq.name.as_deref(), Some("air-quality"));
        assert_eq!(aq.spec_name.as_deref(), Some("AirQuality"));
        // AttributeList 由来: 表外(0x4242)も列挙、グローバル属性は名前付き。
        let ids: Vec<u32> = aq.attrs.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![0, 0x4242, 0xFFFC, 0xFFFD]);
        assert_eq!(aq.attrs[0].name.as_deref(), Some("air-quality"));
        assert_eq!(aq.attrs[0].kind.as_deref(), Some("u8"));
        assert_eq!(aq.attrs[1].name, None);
        assert_eq!(aq.attrs[3].name.as_deref(), Some("cluster-revision"));
        // AttributeList が無い表クラスタは表の属性。
        let co2 = &ep1.clusters[2];
        assert!(co2
            .attrs
            .iter()
            .any(|a| a.name.as_deref() == Some("measured-value")));
    }

    #[test]
    fn node_kind_classification() {
        assert_eq!(classify(&airq_model()), NodeKind::Sensor);
        let mut servers = BTreeMap::new();
        servers.insert(1, vec![ON_OFF, LEVEL_CONTROL]);
        let light = build_model(
            &[1],
            &BTreeMap::new(),
            &servers,
            &BTreeMap::new(),
            BasicInfo::default(),
            0,
        );
        assert_eq!(classify(&light), NodeKind::Light);
        // OnOff と AirQuality の両方 → SENSOR 優先。
        servers.insert(2, vec![AIR_QUALITY]);
        let both = build_model(
            &[1, 2],
            &BTreeMap::new(),
            &servers,
            &BTreeMap::new(),
            BasicInfo::default(),
            0,
        );
        assert_eq!(classify(&both), NodeKind::Sensor);
        assert_eq!(classify(&NodeModel::default()), NodeKind::Other);
    }

    /// ドア・窓センサ(Aqara Door and Window Sensor P2 の構成): ep1 = ContactSensor(BooleanState)、
    /// ep2 = PowerSource(AttributeList が空)。CONTACT に分類し、状態値と電池残量を購読する。
    #[test]
    fn contact_sensor_kind_and_paths() {
        let mut servers = BTreeMap::new();
        servers.insert(1, vec![0x0003, BOOLEAN_STATE]);
        servers.insert(2, vec![POWER_SOURCE]);
        let mut attr_lists = BTreeMap::new();
        attr_lists.insert((2u16, POWER_SOURCE), Vec::new());
        let m = build_model(
            &[1, 2],
            &BTreeMap::new(),
            &servers,
            &attr_lists,
            BasicInfo::default(),
            0,
        );
        assert_eq!(classify(&m), NodeKind::Contact);
        assert_eq!(
            default_paths(NodeKind::Contact, &m),
            vec![
                AttrPath::new(1, BOOLEAN_STATE, 0),
                AttrPath::new(2, POWER_SOURCE, BAT_PERCENT_REMAINING),
            ]
        );
        // OnOff があれば LIGHT 優先(接点を持つスマートプラグ等)。
        servers.insert(3, vec![ON_OFF]);
        let plug = build_model(
            &[1, 2, 3],
            &BTreeMap::new(),
            &servers,
            &BTreeMap::new(),
            BasicInfo::default(),
            0,
        );
        assert_eq!(classify(&plug), NodeKind::Light);
    }

    #[test]
    fn default_path_derivation() {
        let m = airq_model();
        let p = default_paths(NodeKind::Sensor, &m);
        assert_eq!(
            p,
            vec![
                AttrPath::new(1, AIR_QUALITY, 0),
                AttrPath::new(1, CO2, 0),
                AttrPath::new(1, PM25, 0),
                AttrPath::new(2, TEMPERATURE, 0),
                AttrPath::new(3, HUMIDITY, 0),
            ]
        );
        let mut servers = BTreeMap::new();
        servers.insert(1, vec![ON_OFF, LEVEL_CONTROL]);
        servers.insert(2, vec![ON_OFF]);
        let light = build_model(
            &[1, 2],
            &BTreeMap::new(),
            &servers,
            &BTreeMap::new(),
            BasicInfo::default(),
            0,
        );
        assert_eq!(
            default_paths(NodeKind::Light, &light),
            vec![
                AttrPath::new(1, ON_OFF, 0),
                AttrPath::new(1, LEVEL_CONTROL, 0),
                AttrPath::new(2, ON_OFF, 0),
            ]
        );
        assert!(default_paths(NodeKind::Other, &m).is_empty());
        // watch の合成: 重複排除 + 上限。
        let w = vec![
            AttrPath::new(1, CO2, 0),
            AttrPath::new(0, BASIC_INFORMATION, 5),
        ];
        let merged = merge_paths(&p, &w);
        assert_eq!(merged.len(), 6);
        assert_eq!(merged[5], AttrPath::new(0, BASIC_INFORMATION, 5));
        let many: Vec<AttrPath> = (0..40).map(|i| AttrPath::new(1, 6, i)).collect();
        assert_eq!(merge_paths(&[], &many).len(), MAX_SUB_PATHS);
    }

    #[test]
    fn backoff_schedule() {
        let s: Vec<u64> = (0..8).map(|a| backoff(a).as_secs()).collect();
        assert_eq!(s, vec![5, 60, 120, 240, 480, 600, 600, 600]);
        assert_eq!(backoff(u32::MAX).as_secs(), 600);
    }

    #[test]
    fn transports_from_read_items() {
        let fm = |v: u32| enc(|w| w.write_u32(&T2, v).unwrap());
        // クラスタ無し。
        assert!(transports(&[]).is_empty());
        // WiFi(AirQ)/ Thread(NanoC6)。
        let wifi = [item(0, NETWORK_COMMISSIONING, FEATURE_MAP, fm(1), false)];
        assert_eq!(transports(&wifi), vec![Transport::Wifi]);
        let thread = [item(0, NETWORK_COMMISSIONING, FEATURE_MAP, fm(2), false)];
        assert_eq!(transports(&thread), vec![Transport::Thread]);
        // 複数 EP は EP 昇順で重複排除。他クラスタの FeatureMap は無視。
        let multi = [
            item(2, NETWORK_COMMISSIONING, FEATURE_MAP, fm(1), false),
            item(0, NETWORK_COMMISSIONING, FEATURE_MAP, fm(4), false),
            item(1, NETWORK_COMMISSIONING, FEATURE_MAP, fm(1), false),
            item(0, ON_OFF, FEATURE_MAP, fm(2), false),
        ];
        assert_eq!(
            transports(&multi),
            vec![Transport::Ethernet, Transport::Wifi]
        );
    }
}
