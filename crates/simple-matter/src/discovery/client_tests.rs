//! discovery クライアント(browse / resolve)のテスト。
//!
//! 検証方法:
//! - (a) 自前 [`MdnsResponder`] の広告出力(`handle_query` / `write_announce`)を
//!   [`MdnsClient`] が解析して commissionable / operational を発見できる往復。
//! - (b) 生成したクエリを既存 [`dns::Query`] パーサで読み戻すワイヤ形式検証。
//! - (c) 無関係レスポンスの無視、(d) 結果テーブル満杯、(e) discriminator フィルタ。

use super::*;

use crate::discovery::dns;
use crate::discovery::{
    Commissionable, CommissioningMode, Host, MdnsResponder, Operational, MATTER_PORT,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const HOST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
const HOST_V6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const HOST_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

fn test_host() -> Host {
    Host::from_mac(&HOST_MAC, Some(HOST_V6), Some(HOST_V4))
}

/// 指定 instance_id / discriminator の commissionable を広告するレスポンダに browse クエリを
/// 投げ、その応答パケットを `out` に得る(handle_query 経由の往復)。
fn commissionable_response(instance_id: u64, discriminator: u16, out: &mut [u8]) -> usize {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(Commissionable::new(
        instance_id,
        discriminator,
        0xFFF1,
        0x8001,
        CommissioningMode::Standard,
    )));
    let mut q = [0u8; 256];
    let qlen = MdnsClient::build_browse_commissionable(&mut q, false).unwrap();
    mdns.handle_query(&q[..qlen], out).unwrap()
}

// ---- (a) responder → client 直結ラウンドトリップ ----

#[test]
fn roundtrip_commissionable_via_handle_query() {
    let mut out = [0u8; 1400];
    let len = commissionable_response(0x0011_2233_4455_6677, 3840, &mut out);
    let disc = MdnsClient::parse_commissionable(&out[..len]).unwrap();

    assert_eq!(disc.instance(), b"0011223344556677._matterc._udp.local");
    assert_eq!(disc.port, MATTER_PORT);
    assert_eq!(disc.discriminator, Some(3840));
    assert_eq!(disc.vendor_product, Some((0xFFF1, 0x8001)));
    assert_eq!(disc.commissioning_mode, Some(1));

    // ホストの A/AAAA が両方集約される(additional records)。
    assert_eq!(disc.addrs.len(), 2);
    assert!(disc.addrs.iter().any(|a| *a == IpAddr::V6(HOST_V6)));
    assert!(disc.addrs.iter().any(|a| *a == IpAddr::V4(HOST_V4)));
}

#[test]
fn roundtrip_commissionable_via_announce() {
    // write_announce(全レコードが Answer セクション)でも解析できること。
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(Commissionable::new(
        0x00AA_BB00_CC00_DD00,
        250,
        0x1234,
        0x5678,
        CommissioningMode::Enhanced,
    )));
    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    let disc = MdnsClient::parse_commissionable(&out[..len]).unwrap();

    assert_eq!(disc.discriminator, Some(250));
    assert_eq!(disc.vendor_product, Some((0x1234, 0x5678)));
    assert_eq!(disc.commissioning_mode, Some(2));
    assert_eq!(disc.port, MATTER_PORT);
    assert_eq!(disc.addrs.len(), 2);
}

#[test]
fn roundtrip_operational_resolve() {
    let fabric: u64 = 0x2906_C908_D115_D362;
    let node: u64 = 0x8FC7_7724_02CC_9DB4;
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.add_operational(Operational::new(fabric, node))
        .unwrap();

    let cfid = fabric.to_be_bytes();
    let mut q = [0u8; 256];
    let qlen = MdnsClient::build_resolve_operational(&mut q, &cfid, node, false).unwrap();
    let mut out = [0u8; 1400];
    let len = mdns.handle_query(&q[..qlen], &mut out).unwrap();

    let n = MdnsClient::parse_operational(&out[..len], &cfid, node).unwrap();
    assert_eq!(n.port, MATTER_PORT);
    assert_eq!(n.addrs.len(), 2);
    assert!(n.addrs.iter().any(|a| *a == IpAddr::V4(HOST_V4)));

    // 別 fabric/node では解決しない。
    assert!(MdnsClient::parse_operational(&out[..len], &[0u8; 8], node).is_none());
    assert!(MdnsClient::parse_operational(&out[..len], &cfid, node ^ 1).is_none());
}

// ---- (b) クエリ生成のワイヤ形式検証(既存 Query パーサで読み戻す)----

#[test]
fn browse_commissionable_query_wire_format() {
    let mut q = [0u8; 256];
    let len = MdnsClient::build_browse_commissionable(&mut q, false).unwrap();
    let parsed = dns::Query::parse(&q[..len]).unwrap();
    let mut it = parsed.questions();
    let question = it.next().unwrap();
    assert_eq!(question.qtype, dns::T_PTR);
    assert!(question.name.eq_ci(&[b"_matterc", b"_udp", b"local"]));
    assert!(it.next().is_none());
}

#[test]
fn browse_discriminator_query_wire_format() {
    let mut q = [0u8; 256];
    let len = MdnsClient::build_browse_discriminator(&mut q, 3840, false).unwrap();
    let parsed = dns::Query::parse(&q[..len]).unwrap();
    let question = parsed.questions().next().unwrap();
    assert_eq!(question.qtype, dns::T_PTR);
    assert!(question
        .name
        .eq_ci(&[b"_L3840", b"_sub", b"_matterc", b"_udp", b"local"]));
}

#[test]
fn resolve_operational_query_wire_format() {
    let fabric: u64 = 0x2906_C908_D115_D362;
    let node: u64 = 0x8FC7_7724_02CC_9DB4;
    let mut q = [0u8; 256];
    let len = MdnsClient::build_resolve_operational(&mut q, &fabric.to_be_bytes(), node, false).unwrap();
    let parsed = dns::Query::parse(&q[..len]).unwrap();
    let question = parsed.questions().next().unwrap();
    assert_eq!(question.qtype, dns::T_SRV);
    assert!(question.name.eq_ci(&[
        b"2906C908D115D362-8FC7772402CC9DB4",
        b"_matter",
        b"_tcp",
        b"local",
    ]));
}

// ---- (c) 無関係レスポンスの無視 / 不正入力 ----

#[test]
fn ignores_unrelated_response() {
    // operational 広告は commissionable としては無関係。
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.add_operational(Operational::new(1, 2)).unwrap();
    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    assert!(MdnsClient::parse_commissionable(&out[..len]).is_none());

    let mut set: CommissionableSet<2> = CommissionableSet::new();
    assert_eq!(set.ingest(&out[..len]), Ingest::Ignored);
    assert!(set.is_empty());
}

#[test]
fn malformed_input_does_not_panic() {
    assert!(MdnsClient::parse_commissionable(&[]).is_none());
    assert!(MdnsClient::parse_commissionable(&[0u8; 3]).is_none());
    assert!(MdnsClient::parse_commissionable(&[0xFF; 12]).is_none());
    assert!(MdnsClient::parse_operational(&[0xFF; 12], &[0u8; 8], 0).is_none());

    // 出力バッファが小さすぎてもクエリ生成は panic せず Err。
    let mut tiny = [0u8; 4];
    assert!(MdnsClient::build_browse_commissionable(&mut tiny, false).is_err());
}

// ---- (d) 結果テーブル満杯 / 重複 ----

#[test]
fn result_table_full_and_dedup() {
    let mut set: CommissionableSet<1> = CommissionableSet::new();

    let mut a = [0u8; 1400];
    let la = commissionable_response(0x1111_1111_1111_1111, 100, &mut a);
    let mut b = [0u8; 1400];
    let lb = commissionable_response(0x2222_2222_2222_2222, 200, &mut b);

    assert_eq!(set.ingest(&a[..la]), Ingest::Added);
    assert_eq!(set.len(), 1);
    assert!(set.is_full());
    // 同一インスタンスの再取り込みは重複。
    assert_eq!(set.ingest(&a[..la]), Ingest::Duplicate);
    assert_eq!(set.len(), 1);
    // 別インスタンスは満杯で入らない。
    assert_eq!(set.ingest(&b[..lb]), Ingest::Full);
    assert_eq!(set.len(), 1);

    let found = set.iter().next().unwrap();
    assert_eq!(found.discriminator, Some(100));
}

// ---- (e) discriminator フィルタ ----

#[test]
fn discriminator_filter() {
    let mut out = [0u8; 1400];
    let len = commissionable_response(0x00DE_AD00_BE00_EF00, 1234, &mut out);

    let mut set: CommissionableSet<4> = CommissionableSet::new();
    // 不一致は Filtered。
    assert_eq!(set.ingest_filtered(&out[..len], 999), Ingest::Filtered);
    assert!(set.is_empty());
    // 一致は Added。
    assert_eq!(set.ingest_filtered(&out[..len], 1234), Ingest::Added);
    assert_eq!(set.len(), 1);
}

/// QU ビット(RFC 6762 §5.4)指定でクエリの QCLASS 最上位ビットが立つ
/// (Windows の 5353 非共有環境向けユニキャスト応答要求、port-windows-commissioner.md §3.2)。
#[test]
fn browse_query_sets_qu_bit_when_requested() {
    let mut q = [0u8; 128];

    // QU なし: QCLASS = IN(0x0001)。
    let len = MdnsClient::build_browse_commissionable(&mut q, false).unwrap();
    let qclass = u16::from_be_bytes([q[len - 2], q[len - 1]]);
    assert_eq!(qclass, 0x0001);

    // QU あり: 最上位ビットが立つ(0x8001)。名前・QTYPE 部分は同一。
    let mut qu = [0u8; 128];
    let len_qu = MdnsClient::build_browse_commissionable(&mut qu, true).unwrap();
    assert_eq!(len, len_qu);
    assert_eq!(&q[..len - 2], &qu[..len_qu - 2]);
    let qclass_qu = u16::from_be_bytes([qu[len_qu - 2], qu[len_qu - 1]]);
    assert_eq!(qclass_qu, 0x8001);

    // resolve / discriminator ビルダーも同じ QU 経路を通る。
    let mut r = [0u8; 128];
    let rlen = MdnsClient::build_resolve_operational(&mut r, &[0u8; 8], 1, true).unwrap();
    assert_eq!(u16::from_be_bytes([r[rlen - 2], r[rlen - 1]]), 0x8001);
    let mut d = [0u8; 128];
    let dlen = MdnsClient::build_browse_discriminator(&mut d, 3840, true).unwrap();
    assert_eq!(u16::from_be_bytes([d[dlen - 2], d[dlen - 1]]), 0x8001);
}
