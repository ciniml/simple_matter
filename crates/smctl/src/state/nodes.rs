//! ノードアドレス帳 `nodes.tlv`(設計 doc §4.2)。
//!
//! codec は **コアの共有実装**(`simple_matter::controller::nodes`、v1 TLV)へ
//! 委譲する(esp32-controller.md K4 で S3 ハブと記録フォーマットを共有するため、
//! ca-state v1 と同じくコアへ移動した)。本モジュールはファイル I/O と
//! `Vec<NodeEntry>` への詰め替えの皮のみ。
//!
//! discriminator / passcode は保存しない(再コミッショニングに必要な秘密を残さない)。
//! CASE resumption 素材もここには混ぜない(§4.3、`resume/<node>.tlv` は C4)。
//!
//! 制約: ラベルは共有 codec の上限(`MAX_NODE_LABEL_LEN` = 64 バイト)まで。

use std::net::SocketAddr;
use std::path::Path;

use simple_matter::controller::nodes as codec;

/// アドレス帳の 1 エントリ。
#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// デバイスの運用 NodeId(`pairing` の引数で指定)。
    pub node_id: u64,
    /// 任意ラベル(`--label`。共有 codec の上限 64 バイトまで)。
    pub label: String,
    /// 最後に疎通したアドレス(キャッシュ。CASE 失敗時に mDNS 再解決で上書き)。
    pub last_addr: SocketAddr,
}

/// アドレス帳を読む。ファイルが無ければ空。
pub fn load(path: &Path) -> Result<Vec<NodeEntry>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let mut out = Vec::new();
    codec::decode_nodes(&bytes, |r| {
        out.push(NodeEntry {
            node_id: r.node_id,
            label: r.label().to_string(),
            last_addr: r.last_addr,
        });
    })
    .map_err(|e| format!("decode {}: {e:?}", path.display()))?;
    Ok(out)
}

/// アドレス帳を書く(全量書き換え)。
pub fn save(path: &Path, entries: &[NodeEntry]) -> Result<(), String> {
    let records: Vec<codec::NodeRecord> = entries
        .iter()
        .map(|e| {
            codec::NodeRecord::new(e.node_id, e.last_addr, &e.label).map_err(|_| {
                format!(
                    "node {} label too long (max {} bytes)",
                    e.node_id,
                    codec::MAX_NODE_LABEL_LEN
                )
            })
        })
        .collect::<Result<_, String>>()?;
    let mut buf = vec![0u8; codec::nodes_max_len(records.len())];
    let len =
        codec::encode_nodes(&mut buf, &records).map_err(|e| format!("encode nodes: {e:?}"))?;
    std::fs::write(path, &buf[..len]).map_err(|e| format!("write {}: {e}", path.display()))
}

/// 1 エントリを追記または node_id 一致で置き換える。
pub fn upsert(path: &Path, entry: NodeEntry) -> Result<(), String> {
    let mut entries = load(path)?;
    match entries.iter_mut().find(|e| e.node_id == entry.node_id) {
        Some(slot) => *slot = entry,
        None => entries.push(entry),
    }
    save(path, &entries)
}

/// `node_id` 一致のエントリを削除する(`pairing unpair`)。削除したら `Ok(true)`、
/// 該当エントリが無ければ `Ok(false)`。
pub fn remove(path: &Path, node_id: u64) -> Result<bool, String> {
    let mut entries = load(path)?;
    let before = entries.len();
    entries.retain(|e| e.node_id != node_id);
    if entries.len() == before {
        return Ok(false);
    }
    save(path, &entries)?;
    Ok(true)
}

/// キャッシュアドレスを更新する(エントリが無ければ何もしない)。
pub fn update_addr(path: &Path, node_id: u64, addr: SocketAddr) -> Result<(), String> {
    let mut entries = load(path)?;
    if let Some(e) = entries.iter_mut().find(|e| e.node_id == node_id) {
        e.last_addr = addr;
        save(path, &entries)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(node_id: u64, label: &str, addr: &str) -> NodeEntry {
        NodeEntry {
            node_id,
            label: label.to_string(),
            last_addr: addr.parse().unwrap(),
        }
    }

    #[test]
    fn upsert_and_remove_roundtrip() {
        let dir = std::env::temp_dir().join(format!("smctl-nodes-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes.tlv");

        // 空ファイルは空 Vec。
        assert!(load(&path).unwrap().is_empty());

        upsert(&path, entry(1, "one", "10.0.0.1:5540")).unwrap();
        upsert(&path, entry(2, "two", "10.0.0.2:5540")).unwrap();
        let got = load(&path).unwrap();
        assert_eq!(got.len(), 2);

        // 該当ノードだけ消える。存在しないノードは false。
        assert!(remove(&path, 1).unwrap());
        assert!(!remove(&path, 99).unwrap());
        let got = load(&path).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].node_id, 2);
        assert_eq!(got[0].label, "two");

        // 最後の 1 件も消せる。
        assert!(remove(&path, 2).unwrap());
        assert!(load(&path).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v6_and_long_label_edge_cases() {
        let dir = std::env::temp_dir().join(format!("smctl-nodes-v6-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes.tlv");

        // IPv6 アドレスも往復する。
        upsert(&path, entry(3, "v6", "[fe80::1]:5540")).unwrap();
        let got = load(&path).unwrap();
        assert_eq!(got[0].last_addr, "[fe80::1]:5540".parse().unwrap());

        // 共有 codec の上限(64 バイト)超のラベルは保存時に明示エラー。
        let long = "x".repeat(65);
        assert!(upsert(&path, entry(4, &long, "10.0.0.4:5540")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
