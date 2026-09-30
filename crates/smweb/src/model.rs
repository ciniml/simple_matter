//! 表示モデルとスナップショット(設計 doc §2「状態のスナップショット」/ §4.2 / §4.3 / §5)。
//!
//! コントローラスレッドが [`Snapshot`] を書き、REST / WS はそれを読むだけ
//! (コントローラの処理を待たない)。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};

/// ノードの接続状態(§4.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// CASE 確立済み(購読があれば生存中)。
    Online,
    /// 購読ロスト等で値が古い(再接続待ち)。
    Stale,
    /// 未接続 / 接続失敗 / 操作タイムアウト。
    Offline,
}

/// ノード種別(§5.2、Tab5 T4/T8 の判定を踏襲)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// どこかの EP に AirQuality(0x005B)。
    Sensor,
    /// OnOff(0x0006)あり。
    Light,
    /// 上記以外(既定購読なし。ユーザーの watch のみ)。
    #[default]
    Other,
}

/// 属性パス `(ep, cluster, attr)`(watch / 購読 / 値キャッシュのキー)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttrPath {
    pub ep: u16,
    pub cluster: u32,
    pub attr: u32,
}

impl AttrPath {
    pub const fn new(ep: u16, cluster: u32, attr: u32) -> Self {
        Self { ep, cluster, attr }
    }
}

/// 属性 1 個(Describe の AttributeList 由来。表にあれば名前・型付き)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttrModel {
    pub id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub writable: bool,
}

/// サーバクラスタ 1 個。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterModel {
    pub id: u32,
    /// クラスタ表の名前(API のパスに使える kebab-case)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 仕様名(CamelCase、表示用。表に無い標準クラスタにも付く)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_name: Option<String>,
    /// 属性一覧(AttributeList を読めなければクラスタ表の属性、表に無ければ空)。
    #[serde(default)]
    pub attrs: Vec<AttrModel>,
}

/// エンドポイント 1 個。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointModel {
    pub ep: u16,
    #[serde(default)]
    pub device_types: Vec<u32>,
    /// `device_types` と同順の仕様名(未知は `0x....`)。
    #[serde(default)]
    pub device_type_names: Vec<String>,
    #[serde(default)]
    pub clusters: Vec<ClusterModel>,
}

impl EndpointModel {
    pub fn has_cluster(&self, id: u32) -> bool {
        self.clusters.iter().any(|c| c.id == id)
    }
}

/// BasicInformation(0x0028)の表示用抜粋。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BasicInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
}

/// Describe の結果(§5.1。値は含めない)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NodeModel {
    pub endpoints: Vec<EndpointModel>,
    #[serde(default)]
    pub basic: BasicInfo,
    /// 取得時刻(UNIX 秒)。
    #[serde(default)]
    pub described_at: u64,
}

impl NodeModel {
    /// クラスタを持つエンドポイント(EP 昇順)。
    pub fn endpoints_with(&self, cluster: u32) -> impl Iterator<Item = u16> + '_ {
        self.endpoints
            .iter()
            .filter(move |e| e.has_cluster(cluster))
            .map(|e| e.ep)
    }

    pub fn has_cluster(&self, cluster: u32) -> bool {
        self.endpoints.iter().any(|e| e.has_cluster(cluster))
    }
}

/// 値キャッシュの 1 要素(§4.2 `Event::Attr` と同形)。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttrValue {
    pub ep: u16,
    pub cluster: u32,
    pub attr: u32,
    /// §5.3 の JSON 化(スカラ or `{raw, pretty, decoded}`)。
    pub value: Value,
    /// 値要素の生 TLV(hex)。
    pub raw_hex: String,
    pub data_version: Option<u32>,
    /// 受信時刻(UNIX ミリ秒)。
    pub ts: u64,
}

/// 値キャッシュ(`(ep, cluster, attr)` → 最新値)。JSON では配列。
pub type Values = BTreeMap<AttrPath, AttrValue>;

fn values_as_list<S: Serializer>(v: &Values, s: S) -> Result<S::Ok, S::Error> {
    s.collect_seq(v.values())
}

/// 1 ノード分のスナップショット。
#[derive(Debug, Clone, Serialize)]
pub struct NodeSnap {
    pub node_id: u64,
    pub label: String,
    /// 最終運用アドレス(未解決なら `None`)。
    pub addr: Option<String>,
    pub state: NodeState,
    /// 最後に成功した操作の時刻(UNIX 秒)。
    pub last_seen: Option<u64>,
    pub kind: NodeKind,
    /// Describe 結果(`smweb.json` のキャッシュ、または今回の Describe)。
    pub model: Option<NodeModel>,
    /// 最新値キャッシュ。
    #[serde(serialize_with = "values_as_list")]
    pub values: Values,
    /// 確立中の購読 ID。
    pub sub_id: Option<u32>,
    /// 購読中のパス(既定 + watch)。
    pub sub_paths: Vec<AttrPath>,
    /// ユーザーが選んだ watch パス(`smweb.json` に保存)。
    pub watch: Vec<AttrPath>,
    /// 最後のレポート受信時刻(UNIX ミリ秒)。
    pub last_report: Option<u64>,
    /// 直近の接続失敗理由。
    pub error: Option<String>,
    /// 次の自動再接続予定(UNIX 秒)。
    pub next_retry: Option<u64>,
}

impl NodeSnap {
    pub fn new(node_id: u64, label: String, addr: Option<String>) -> Self {
        Self {
            node_id,
            label,
            addr,
            state: NodeState::Offline,
            last_seen: None,
            kind: NodeKind::Other,
            model: None,
            values: Values::new(),
            sub_id: None,
            sub_paths: Vec::new(),
            watch: Vec::new(),
            last_report: None,
            error: None,
            next_retry: None,
        }
    }

    /// `GET /api/nodes` 用の要約(モデルと値を省く)。
    pub fn summary(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "label": self.label,
            "kind": self.kind,
            "addr": self.addr,
            "state": self.state,
            "last_seen": self.last_seen,
            "product": self.model.as_ref().and_then(|m| m.basic.product_name.clone()),
            "sub_id": self.sub_id,
            "last_report": self.last_report,
            "error": self.error,
            "next_retry": self.next_retry,
        })
    }

    /// 値キャッシュを更新する。戻り値 = 値(または data_version)が変わったか。
    pub fn update_value(&mut self, v: AttrValue) -> bool {
        let key = AttrPath::new(v.ep, v.cluster, v.attr);
        let changed = match self.values.get(&key) {
            Some(old) => old.raw_hex != v.raw_hex || old.data_version != v.data_version,
            None => true,
        };
        self.last_report = Some(v.ts);
        self.values.insert(key, v);
        changed
    }
}

/// コントローラ情報(`GET /api/info`)。
#[derive(Debug, Clone, Serialize, Default)]
pub struct Info {
    pub version: &'static str,
    pub state_dir: String,
    /// fabric ID(CA 未作成なら `None`)。
    pub fabric_id: Option<String>,
    /// controller node ID(CA 未作成なら `None`)。
    pub controller_node_id: Option<String>,
    pub features: Vec<&'static str>,
    /// コントローラスレッドが起動済みか。
    pub ready: bool,
    /// 起動失敗・CA 不在などの理由。
    pub error: Option<String>,
}

/// スナップショット全体。
#[derive(Debug, Clone, Serialize, Default)]
pub struct Snapshot {
    pub info: Info,
    pub nodes: Vec<NodeSnap>,
}

impl Snapshot {
    /// ノードを ID で引く。
    pub fn node(&self, node_id: u64) -> Option<&NodeSnap> {
        self.nodes.iter().find(|n| n.node_id == node_id)
    }

    /// ノードを ID で引く(可変)。
    pub fn node_mut(&mut self, node_id: u64) -> Option<&mut NodeSnap> {
        self.nodes.iter_mut().find(|n| n.node_id == node_id)
    }
}

/// WebSocket へ流すイベント(§4.2)。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    NodeState {
        node_id: u64,
        state: NodeState,
        addr: Option<String>,
        /// 直近の失敗理由(`offline` のとき)。
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// 次の自動再接続予定(UNIX 秒)。
        #[serde(skip_serializing_if = "Option::is_none")]
        next_retry: Option<u64>,
    },
    /// Describe 完了(モデルと種別の更新)。
    Model {
        node_id: u64,
        kind: NodeKind,
        model: NodeModel,
    },
    /// 属性値の更新(購読レポート / プライミング / 都度 Read)。
    Attr {
        node_id: u64,
        ep: u16,
        cluster: u32,
        attr: u32,
        value: Value,
        raw_hex: String,
        data_version: Option<u32>,
        /// UNIX ミリ秒。
        ts: u64,
    },
    /// 購読確立。
    SubReady {
        node_id: u64,
        sub_id: u32,
        max_interval_s: u16,
        paths: Vec<AttrPath>,
    },
    /// 購読ロスト(再接続をスケジュール済み)。
    SubLost { node_id: u64, sub_id: u32 },
    /// watch パスの変更。
    Watch { node_id: u64, watch: Vec<AttrPath> },
    /// 長時間操作(pairing)の進捗。`phase` が `done` / `failed` で終端。
    Progress {
        op_id: u64,
        phase: String,
        detail: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_id: Option<u64>,
        /// `failed` の理由。
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// `done` の結果(接続結果など)。
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        /// UNIX ミリ秒。
        ts: u64,
    },
    /// ノードの追加(pairing 成功)。
    NodeAdded { node: Box<NodeSnap> },
    /// ノードの削除(unpair)。
    NodeRemoved { node_id: u64 },
    /// ラベルの変更。
    NodeLabel { node_id: u64, label: String },
    /// コミッショニングウィンドウの開閉(Share)。
    Window {
        node_id: u64,
        open: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        window: Option<Value>,
    },
    Log {
        level: &'static str,
        tag: String,
        msg: String,
        /// UNIX ミリ秒。
        ts: u64,
    },
}

impl Event {
    /// 進捗イベント(途中経過)。
    pub fn progress(
        op_id: u64,
        phase: &str,
        detail: impl Into<String>,
        node_id: Option<u64>,
    ) -> Self {
        Event::Progress {
            op_id,
            phase: phase.to_string(),
            detail: detail.into(),
            node_id,
            error: None,
            result: None,
            ts: unix_now_ms(),
        }
    }

    /// 値キャッシュ要素から `Attr` を作る。
    pub fn attr(node_id: u64, v: &AttrValue) -> Self {
        Event::Attr {
            node_id,
            ep: v.ep,
            cluster: v.cluster,
            attr: v.attr,
            value: v.value.clone(),
            raw_hex: v.raw_hex.clone(),
            data_version: v.data_version,
            ts: v.ts,
        }
    }
}

/// 現在時刻(UNIX 秒)。
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 現在時刻(UNIX ミリ秒)。
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_shape() {
        let e = Event::NodeState {
            node_id: 5,
            state: NodeState::Online,
            addr: Some("[fe80::1]:5540".into()),
            error: None,
            next_retry: None,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "node_state");
        assert_eq!(v["state"], "online");
        assert_eq!(v["node_id"], 5);
        assert!(v.get("error").is_none());
    }

    #[test]
    fn progress_and_node_events_json() {
        let v =
            serde_json::to_value(Event::progress(7, "pase", "PASE handshake", Some(34))).unwrap();
        assert_eq!(v["type"], "progress");
        assert_eq!(v["op_id"], 7);
        assert_eq!(v["phase"], "pase");
        assert_eq!(v["node_id"], 34);
        assert!(v.get("error").is_none() && v.get("result").is_none());
        let v = serde_json::to_value(Event::NodeAdded {
            node: Box::new(NodeSnap::new(34, "AirQ".into(), None)),
        })
        .unwrap();
        assert_eq!(v["type"], "node_added");
        assert_eq!(v["node"]["node_id"], 34);
        assert_eq!(v["node"]["state"], "offline");
        let v = serde_json::to_value(Event::NodeLabel {
            node_id: 34,
            label: "Kitchen".into(),
        })
        .unwrap();
        assert_eq!(v["type"], "node_label");
        assert_eq!(v["label"], "Kitchen");
        let v = serde_json::to_value(Event::Window {
            node_id: 33,
            open: false,
            window: None,
        })
        .unwrap();
        assert_eq!(v["type"], "window");
        assert!(v.get("window").is_none());
    }

    fn av(
        ep: u16,
        cluster: u32,
        attr: u32,
        value: Value,
        raw: &str,
        dv: u32,
        ts: u64,
    ) -> AttrValue {
        AttrValue {
            ep,
            cluster,
            attr,
            value,
            raw_hex: raw.into(),
            data_version: Some(dv),
            ts,
        }
    }

    #[test]
    fn value_cache_update_and_json() {
        let mut n = NodeSnap::new(33, "AirQ".into(), None);
        assert!(n.update_value(av(1, 0x040D, 0, json!(812.0), "2a0000", 7, 1000)));
        // 同値・同 data_version は変化なし(時刻だけ進む)。
        assert!(!n.update_value(av(1, 0x040D, 0, json!(812.0), "2a0000", 7, 2000)));
        assert_eq!(n.last_report, Some(2000));
        assert!(n.update_value(av(1, 0x040D, 0, json!(900.0), "2a0001", 8, 3000)));
        assert!(n.update_value(av(2, 0x0402, 0, json!(2345), "292909", 1, 3000)));
        assert_eq!(n.values.len(), 2);
        let v = serde_json::to_value(&n).unwrap();
        let list = v["values"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        // BTreeMap 順(ep 昇順)。
        assert_eq!(list[0]["ep"], 1);
        assert_eq!(list[0]["cluster"], 0x040D);
        assert_eq!(list[0]["value"], json!(900.0));
        assert_eq!(list[0]["data_version"], 8);
        assert_eq!(list[1]["value"], json!(2345));
        let e =
            serde_json::to_value(Event::attr(33, &n.values[&AttrPath::new(2, 0x0402, 0)])).unwrap();
        assert_eq!(e["type"], "attr");
        assert_eq!(e["node_id"], 33);
        assert_eq!(e["raw_hex"], "292909");
        assert_eq!(e["ts"], 3000);
        let s = n.summary();
        assert_eq!(s["kind"], "other");
        assert!(s.get("values").is_none());
    }
}
