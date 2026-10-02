//! `smweb.json`(設計 doc §4.4 / §5.1): smweb 固有の永続情報。
//!
//! `nodes.tlv`(smctl と共有のアドレス帳)のフォーマットは触らず、Describe 結果の
//! キャッシュ(値は含めない)・種別・ユーザーの watch パス・最終接続時刻を別ファイルに置く。
//! 再起動時は接続前にこのキャッシュでページを描画できる。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::{AttrPath, NodeKind, NodeModel};

/// ファイル名(状態ディレクトリ直下)。
pub const FILE_NAME: &str = "smweb.json";
/// フォーマット版数。
pub const VERSION: u32 = 1;

/// ノード 1 個分の保存内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StoredNode {
    /// ラベル(`nodes.tlv` と同じ値の控え。`PATCH /api/nodes/{id}` / pairing で更新)。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub kind: NodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<NodeModel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watch: Vec<AttrPath>,
    /// 最後に接続(Describe/購読)に成功した時刻(UNIX 秒)。起動時の接続順に使う。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_online: Option<u64>,
}

/// `smweb.json` 全体。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    /// node ID(10 進文字列キー)→ 保存内容。
    #[serde(default)]
    pub nodes: BTreeMap<u64, StoredNode>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: VERSION,
            nodes: BTreeMap::new(),
        }
    }
}

impl Store {
    /// パス(`<state-dir>/smweb.json`)。
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(FILE_NAME)
    }

    /// 読む。無ければ空。壊れていればエラー(上書きで消さないため呼び出し側が判断)。
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(b) => Self::from_json(&b).map_err(|e| format!("parse {}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("read {}: {e}", path.display())),
        }
    }

    pub fn from_json(b: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(b)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }

    /// 書く(一時ファイル + rename で原子的に置き換える)。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, self.to_json())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
    }

    /// ノードの保存内容(無ければ作る)。
    pub fn node_mut(&mut self, node_id: u64) -> &mut StoredNode {
        self.nodes.entry(node_id).or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AttrModel, BasicInfo, ClusterModel, EndpointModel};

    fn sample() -> Store {
        let mut s = Store::default();
        let n = s.node_mut(33);
        n.kind = NodeKind::Sensor;
        n.model = Some(NodeModel {
            endpoints: vec![EndpointModel {
                ep: 1,
                device_types: vec![0x2C],
                device_type_names: vec!["AirQualitySensor".into()],
                clusters: vec![ClusterModel {
                    id: 0x5B,
                    name: Some("air-quality".into()),
                    spec_name: Some("AirQuality".into()),
                    attrs: vec![
                        AttrModel {
                            id: 0,
                            name: Some("air-quality".into()),
                            kind: Some("u8".into()),
                            writable: false,
                        },
                        AttrModel {
                            id: 0x4242,
                            name: None,
                            kind: None,
                            writable: false,
                        },
                    ],
                }],
            }],
            basic: BasicInfo {
                product_name: Some("AirQ".into()),
                ..BasicInfo::default()
            },
            described_at: 1_700_000_000,
            transport: Some(crate::model::Transport::Wifi),
            transports: vec![crate::model::Transport::Wifi],
        });
        n.watch = vec![AttrPath::new(0, 0x28, 5)];
        n.last_online = Some(1_700_000_001);
        s.node_mut(1);
        s
    }

    #[test]
    fn json_round_trip() {
        let s = sample();
        let text = s.to_json();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["nodes"]["33"]["kind"], "sensor");
        assert_eq!(v["nodes"]["33"]["watch"][0]["cluster"], 0x28);
        // 空の watch / model は省略される。
        assert!(v["nodes"]["1"].get("watch").is_none());
        assert!(v["nodes"]["1"].get("model").is_none());
        let back = Store::from_json(text.as_bytes()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn file_round_trip_and_missing() {
        let dir = std::env::temp_dir().join(format!("smweb-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = Store::path(&dir);
        let _ = std::fs::remove_file(&p);
        assert_eq!(Store::load(&p).unwrap(), Store::default());
        let s = sample();
        s.save(&p).unwrap();
        assert_eq!(Store::load(&p).unwrap(), s);
        std::fs::write(&p, "{not json").unwrap();
        assert!(Store::load(&p).is_err());
        // 最小形(nodes 省略)も読める。
        std::fs::write(&p, r#"{"version":1}"#).unwrap();
        assert!(Store::load(&p).unwrap().nodes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
