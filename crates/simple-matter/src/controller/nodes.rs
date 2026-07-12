//! ノードアドレス帳(smctl `nodes.tlv` v1)の sans-IO codec。
//!
//! smctl(PC)と組込みコントローラ(ESP32-S3 ハブ)がコミッショニング済み
//! ノードの記録を**同一フォーマット**で永続化するための共有 codec
//! (`docs/design/esp32-controller.md` §7 K4 = ca-state v1 を `Ca::encode_state` /
//! `Ca::decode_state` として共有したのと同じ移動)。I/O は含まない: smctl は
//! ファイル(`nodes.tlv`)へ、S3 は flash KVS の 1 キーへ、この codec の
//! バイト列をそのまま置く。フォーマット(v1、smctl `state/nodes.rs` 由来):
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
//! discriminator / passcode は保存しない(再コミッショニングに必要な秘密を
//! 残さない)。CASE resumption 素材もここには混ぜない(smctl は
//! `resume/<node>.tlv`、S3 はポートローカルの別キー)。
//!
//! # 制約(no_std 化に伴う v1 の明文化)
//!
//! ラベルは [`MAX_NODE_LABEL_LEN`](64 バイト)まで。それより長いラベルを含む
//! レコードは encode 前([`NodeRecord::new`])/decode 時とも [`Error::NoSpace`]。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// アドレス帳レコードの schema version。
pub const NODES_VERSION: u8 = 1;

/// ラベルの最大バイト数(固定バッファ。UTF-8 のまま格納する)。
pub const MAX_NODE_LABEL_LEN: usize = 64;

/// 1 エントリの最大エンコード長(node_id 10B + label ヘッダ+64B + IP 19B +
/// port 4B + struct 開始/終了、切り上げ)。[`nodes_max_len`] の係数。
const MAX_ENTRY_LEN: usize = 112;

/// `n` エントリのアドレス帳の最大エンコード長(バッファサイジング用)。
pub const fn nodes_max_len(n: usize) -> usize {
    // 外側 struct + version + array の枠 ≈ 8B。
    8 + n * MAX_ENTRY_LEN
}

/// アドレス帳の 1 エントリ(固定長・ヒープレス)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    /// デバイスの運用 NodeId。
    pub node_id: u64,
    /// 最後に疎通した運用アドレス(キャッシュ。CASE 失敗時に mDNS 再解決で上書き)。
    pub last_addr: SocketAddr,
    label_len: u8,
    label: [u8; MAX_NODE_LABEL_LEN],
}

impl NodeRecord {
    /// エントリを作る。ラベルが [`MAX_NODE_LABEL_LEN`] を超えると [`Error::NoSpace`]。
    pub fn new(node_id: u64, last_addr: SocketAddr, label: &str) -> Result<Self> {
        let bytes = label.as_bytes();
        if bytes.len() > MAX_NODE_LABEL_LEN {
            return Err(Error::NoSpace);
        }
        let mut buf = [0u8; MAX_NODE_LABEL_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            node_id,
            last_addr,
            label_len: bytes.len() as u8,
            label: buf,
        })
    }

    /// ラベル(UTF-8)。
    pub fn label(&self) -> &str {
        // new / decode とも &str / as_str 経由なので常に有効な UTF-8。
        core::str::from_utf8(&self.label[..self.label_len as usize]).unwrap_or("")
    }
}

/// context-specific タグの略記。
fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// アドレス帳を v1 TLV へエンコードし、書いたバイト数を返す。
///
/// バッファは [`nodes_max_len`]`(nodes.len())` あれば必ず足りる。
pub fn encode_nodes(out: &mut [u8], nodes: &[NodeRecord]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_u8(&cx(0), NODES_VERSION)?;
    w.start_array(&cx(1))?;
    for e in nodes {
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u64(&cx(0), e.node_id)?;
        w.write_utf8(&cx(1), e.label())?;
        match e.last_addr.ip() {
            IpAddr::V4(ip) => w.write_bytes(&cx(2), &ip.octets())?,
            IpAddr::V6(ip) => w.write_bytes(&cx(2), &ip.octets())?,
        }
        w.write_u16(&cx(3), e.last_addr.port())?;
        w.end_container()?;
    }
    w.end_container()?;
    w.end_container()?;
    Ok(w.len())
}

/// v1 TLV のアドレス帳をデコードし、エントリごとにコールバックを呼ぶ。
/// 返り値はエントリ数。バージョン不一致・構造不正は [`Error::Decode`]。
///
/// コールバック方式なのは、呼び出し側の格納容器が異なるため
/// (smctl = `Vec`、S3 = 固定長配列)。
pub fn decode_nodes(bytes: &[u8], mut f: impl FnMut(&NodeRecord)) -> Result<usize> {
    let mut r = TlvReader::new(bytes);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut version = 0u8;
    let mut count = 0usize;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
            (TlvTag::ContextSpecific(1), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let item = r.read_next()?.ok_or(Error::Decode)?;
                match item.value {
                    TlvValue::ContainerEnd => break,
                    TlvValue::ContainerStart(ContainerType::Structure) => {
                        let rec = decode_entry(&mut r)?;
                        f(&rec);
                        count += 1;
                    }
                    _ => r.skip(&item)?,
                }
            },
            _ => r.skip(&e)?,
        }
    }
    if version != NODES_VERSION {
        return Err(Error::Decode);
    }
    Ok(count)
}

/// struct 開始を消費済みの状態から 1 エントリを読む。
fn decode_entry(r: &mut TlvReader) -> Result<NodeRecord> {
    let mut node_id = 0u64;
    let mut label_len = 0usize;
    let mut label = [0u8; MAX_NODE_LABEL_LEN];
    let mut ip: Option<IpAddr> = None;
    let mut port = 0u16;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => node_id = v.as_unsigned()?,
            (TlvTag::ContextSpecific(1), v) => {
                let s = v.as_str()?.as_bytes();
                if s.len() > MAX_NODE_LABEL_LEN {
                    return Err(Error::NoSpace);
                }
                label_len = s.len();
                label[..s.len()].copy_from_slice(s);
            }
            (TlvTag::ContextSpecific(2), v) => {
                let b = v.as_bytes()?;
                ip = Some(match b.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(b).map_err(|_| Error::Decode)?,
                    )),
                    16 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(b).map_err(|_| Error::Decode)?,
                    )),
                    _ => return Err(Error::Decode),
                });
            }
            (TlvTag::ContextSpecific(3), v) => port = v.as_unsigned()? as u16,
            _ => r.skip(&e)?,
        }
    }
    let ip = ip.ok_or(Error::Decode)?;
    Ok(NodeRecord {
        node_id,
        last_addr: SocketAddr::new(ip, port),
        label_len: label_len as u8,
        label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(node_id: u64, label: &str, addr: &str) -> NodeRecord {
        NodeRecord::new(node_id, addr.parse().unwrap(), label).unwrap()
    }

    #[test]
    fn roundtrip_v4_v6_labels() {
        let nodes = [
            rec(0xAABB_CCDD, "light", "10.0.0.1:5540"),
            rec(2, "", "[fe80::1]:5541"),
            rec(u64::MAX, "日本語ラベル", "192.168.2.14:65535"),
        ];
        let mut buf = [0u8; nodes_max_len(3)];
        let len = encode_nodes(&mut buf, &nodes).unwrap();

        let mut got: heapless_vec::Vec = Default::default();
        let n = decode_nodes(&buf[..len], |r| got.push(*r)).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&got.items[..got.len], &nodes);

        // 再 encode の冪等性(同一バイト列)。
        let mut buf2 = [0u8; nodes_max_len(3)];
        let len2 = encode_nodes(&mut buf2, &got.items[..got.len]).unwrap();
        assert_eq!(&buf[..len], &buf2[..len2]);
    }

    #[test]
    fn empty_book_roundtrips() {
        let mut buf = [0u8; nodes_max_len(0)];
        let len = encode_nodes(&mut buf, &[]).unwrap();
        let n = decode_nodes(&buf[..len], |_| panic!("no entries expected")).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn version_mismatch_is_decode_error() {
        let nodes = [rec(1, "x", "10.0.0.1:5540")];
        let mut buf = [0u8; nodes_max_len(1)];
        let len = encode_nodes(&mut buf, &nodes).unwrap();
        // version(cx0, u8)の値バイトを書き換える(anonymous struct 開始 1B +
        // cx0 ヘッダ 2B の直後)。
        buf[3] = 9;
        assert!(matches!(
            decode_nodes(&buf[..len], |_| {}),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn long_label_is_rejected() {
        let long = core::str::from_utf8(&[b'a'; MAX_NODE_LABEL_LEN + 1]).unwrap();
        assert!(matches!(
            NodeRecord::new(1, "10.0.0.1:5540".parse().unwrap(), long),
            Err(Error::NoSpace)
        ));
    }

    /// テスト用の素朴な固定長 Vec(コアの test-only ヘルパを増やさないため局所定義)。
    mod heapless_vec {
        use super::NodeRecord;
        pub struct Vec {
            pub items: [NodeRecord; 8],
            pub len: usize,
        }
        impl Default for Vec {
            fn default() -> Self {
                let dummy = NodeRecord::new(0, "0.0.0.0:0".parse().unwrap(), "").unwrap();
                Self {
                    items: [dummy; 8],
                    len: 0,
                }
            }
        }
        impl Vec {
            pub fn push(&mut self, r: NodeRecord) {
                self.items[self.len] = r;
                self.len += 1;
            }
        }
    }
}
