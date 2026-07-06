//! ノードアドレス帳 `nodes.tlv`(設計 doc §4.2)。
//!
//! versioned TLV(手書きエンコーダで依存追加なし):
//!
//! ```text
//! struct(anonymous) {
//!   0: u8   version (=1)
//!   1: array of struct {
//!        0: u64   node_id
//!        1: utf8  label(空文字可)
//!        2: bytes last_addr の IP(4 バイト = IPv4 / 16 バイト = IPv6)
//!        3: u16   last_addr のポート
//!      }
//! }
//! ```
//!
//! discriminator / passcode は保存しない(再コミッショニングに必要な秘密を残さない)。
//! CASE resumption 素材もここには混ぜない(§4.3、`resume/<node>.tlv` は C4)。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use simple_matter::error::Result as MResult;
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// アドレス帳レコードの schema version。
const NODES_VERSION: u8 = 1;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// アドレス帳の 1 エントリ。
#[derive(Clone, Debug)]
pub struct NodeEntry {
    /// デバイスの運用 NodeId(`pairing` の引数で指定)。
    pub node_id: u64,
    /// 任意ラベル(`--label`)。
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
    decode(&bytes).map_err(|e| format!("decode {}: {e:?}", path.display()))
}

/// アドレス帳を書く(全量書き換え)。
pub fn save(path: &Path, entries: &[NodeEntry]) -> Result<(), String> {
    let mut buf = vec![0u8; 64 + entries.len() * 96];
    let len = {
        let mut w = TlvWriter::new(&mut buf);
        encode(&mut w, entries).map_err(|e| format!("encode nodes: {e:?}"))?;
        w.len()
    };
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

/// キャッシュアドレスを更新する(エントリが無ければ何もしない)。
pub fn update_addr(path: &Path, node_id: u64, addr: SocketAddr) -> Result<(), String> {
    let mut entries = load(path)?;
    if let Some(e) = entries.iter_mut().find(|e| e.node_id == node_id) {
        e.last_addr = addr;
        save(path, &entries)?;
    }
    Ok(())
}

fn encode(w: &mut TlvWriter, entries: &[NodeEntry]) -> MResult<()> {
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_u8(&cx(0), NODES_VERSION)?;
    w.start_array(&cx(1))?;
    for e in entries {
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u64(&cx(0), e.node_id)?;
        w.write_utf8(&cx(1), &e.label)?;
        match e.last_addr.ip() {
            IpAddr::V4(ip) => w.write_bytes(&cx(2), &ip.octets())?,
            IpAddr::V6(ip) => w.write_bytes(&cx(2), &ip.octets())?,
        }
        w.write_u16(&cx(3), e.last_addr.port())?;
        w.end_container()?;
    }
    w.end_container()?;
    w.end_container()
}

fn decode(bytes: &[u8]) -> MResult<Vec<NodeEntry>> {
    let mut r = TlvReader::new(bytes);
    if r.enter_container()? != ContainerType::Structure {
        return Err(simple_matter::Error::Decode);
    }
    let mut version = 0u8;
    let mut out = Vec::new();
    loop {
        let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
            (TlvTag::ContextSpecific(1), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let item = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
                match item.value {
                    TlvValue::ContainerEnd => break,
                    TlvValue::ContainerStart(ContainerType::Structure) => {
                        out.push(decode_entry(&mut r)?);
                    }
                    _ => r.skip(&item)?,
                }
            },
            _ => r.skip(&e)?,
        }
    }
    if version != NODES_VERSION {
        return Err(simple_matter::Error::Decode);
    }
    Ok(out)
}

/// struct 開始を消費済みの状態から 1 エントリを読む。
fn decode_entry(r: &mut TlvReader) -> MResult<NodeEntry> {
    let mut node_id = 0u64;
    let mut label = String::new();
    let mut ip: Option<IpAddr> = None;
    let mut port = 0u16;
    loop {
        let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => node_id = v.as_unsigned()?,
            (TlvTag::ContextSpecific(1), v) => label = v.as_str()?.to_string(),
            (TlvTag::ContextSpecific(2), v) => {
                let b = v.as_bytes()?;
                ip = Some(match b.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(b).map_err(|_| simple_matter::Error::Decode)?,
                    )),
                    16 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(b).map_err(|_| simple_matter::Error::Decode)?,
                    )),
                    _ => return Err(simple_matter::Error::Decode),
                });
            }
            (TlvTag::ContextSpecific(3), v) => port = v.as_unsigned()? as u16,
            _ => r.skip(&e)?,
        }
    }
    let ip = ip.ok_or(simple_matter::Error::Decode)?;
    Ok(NodeEntry {
        node_id,
        label,
        last_addr: SocketAddr::new(ip, port),
    })
}
