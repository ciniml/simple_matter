//! 表示モデルとスナップショット(設計 doc §2「状態のスナップショット」/ §4.2 / §4.3)。
//!
//! コントローラスレッドが [`Snapshot`] を書き、REST / WS はそれを読むだけ
//! (コントローラの処理を待たない)。

use serde::Serialize;

/// ノードの接続状態(§4.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// CASE 確立済み。
    Online,
    /// 購読ロスト等で値が古い(W2 以降で使用)。
    #[allow(dead_code)]
    Stale,
    /// 未接続 / 接続失敗 / 操作タイムアウト。
    Offline,
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

/// WebSocket へ流すイベント(§4.2。W1 は `NodeState` と `Log`)。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    NodeState {
        node_id: u64,
        state: NodeState,
        addr: Option<String>,
    },
    Log {
        level: &'static str,
        tag: String,
        msg: String,
        /// UNIX ミリ秒。
        ts: u64,
    },
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
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["type"], "node_state");
        assert_eq!(v["state"], "online");
        assert_eq!(v["node_id"], 5);
    }
}
