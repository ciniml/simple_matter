//! discovery(mDNS)レコード生成・クエリ応答・announce タイミングのテスト。
//!
//! 検証方法: 生成した応答メッセージを [`dns::Response`] で再パースし、レコードの
//! オーナ名・種別・RDATA を rs-matter / chip のワイヤ形式(`_matterc._udp` / `_matter._tcp`、
//! TXT `D`/`VP`/`CM`、サブタイプ `_L`/`_S`/`_I` 等)と照合する。

use super::*;

const HOST_MAC: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

fn test_host() -> Host {
    Host::from_mac(
        &HOST_MAC,
        Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        Some(Ipv4Addr::new(192, 168, 1, 50)),
    )
}

fn test_commissionable() -> Commissionable {
    Commissionable {
        instance_id: 0x0011_2233_4455_6677,
        discriminator: 3840,
        vendor_id: 0xFFF1,
        product_id: 0x8001,
        device_type: Some(0x0100),
        device_name: Some("OnOffLight"),
        mode: CommissioningMode::Standard,
        sii: Some(5000),
        sai: Some(300),
    }
}

/// レコード集合の中に、指定オーナ名・種別のレコードが少なくとも 1 件あるか。
fn has_record(pkt: &[u8], owner: &[&[u8]], rtype: u16) -> bool {
    let resp = dns::Response::parse(pkt).unwrap();
    resp.records()
        .any(|r| r.rtype == rtype && r.name.eq_ci(owner))
}

/// 指定オーナ名・種別のレコードを 1 件返す。
fn find_record<'a>(pkt: &'a [u8], owner: &[&[u8]], rtype: u16) -> Option<dns::Record<'a>> {
    let resp = dns::Response::parse(pkt).unwrap();
    resp.records()
        .find(|r| r.rtype == rtype && r.name.eq_ci(owner))
}

#[test]
fn commissionable_announce_has_expected_records() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));

    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    let pkt = &out[..len];

    let host: &[&[u8]] = &[b"AABBCCDDEEFF", b"local"];
    let instance: &[&[u8]] = &[b"0011223344556677", b"_matterc", b"_udp", b"local"];
    let service_type: &[&[u8]] = &[b"_matterc", b"_udp", b"local"];

    // DNS-SD メタ PTR。
    assert!(has_record(
        pkt,
        &[b"_services", b"_dns-sd", b"_udp", b"local"],
        dns::T_PTR
    ));
    // サービス型 PTR -> instance。
    let ptr = find_record(pkt, service_type, dns::T_PTR).unwrap();
    assert!(ptr.rdata_name().unwrap().eq_ci(instance));

    // サブタイプ PTR(_L3840 / _S15 / _V65521 / _T256 / _CM)。
    assert!(has_record(
        pkt,
        &[b"_L3840", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR
    ));
    assert!(has_record(
        pkt,
        &[b"_S15", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR
    ));
    assert!(has_record(
        pkt,
        &[b"_V65521", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR
    ));
    assert!(has_record(
        pkt,
        &[b"_T256", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR
    ));
    assert!(has_record(
        pkt,
        &[b"_CM", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR
    ));

    // SRV instance -> host:5540。
    let (_, _, port, target) = find_record(pkt, instance, dns::T_SRV)
        .unwrap()
        .srv()
        .unwrap();
    assert_eq!(port, MATTER_PORT);
    assert!(target.eq_ci(host));

    // TXT の主要キー。
    let txt = find_record(pkt, instance, dns::T_TXT).unwrap();
    assert!(txt.txt_contains(b"D=3840"));
    assert!(txt.txt_contains(b"CM=1"));
    assert!(txt.txt_contains(b"VP=65521+32769"));
    assert!(txt.txt_contains(b"DT=256"));
    assert!(txt.txt_contains(b"DN=OnOffLight"));
    assert!(txt.txt_contains(b"SII=5000"));
    assert!(txt.txt_contains(b"SAI=300"));

    // AAAA / A(host)。
    assert!(has_record(pkt, host, dns::T_AAAA));
    assert!(has_record(pkt, host, dns::T_A));
}

#[test]
fn operational_announce_has_expected_records() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    let op = Operational {
        compressed_fabric_id: 0x2906_C908_D115_D362,
        node_id: 0x8FC7_7724_02CC_9DB4,
        sii: Some(5000),
        sai: Some(300),
    };
    mdns.add_operational(op).unwrap();

    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    let pkt = &out[..len];

    let instance: &[&[u8]] = &[
        b"2906C908D115D362-8FC7772402CC9DB4",
        b"_matter",
        b"_tcp",
        b"local",
    ];
    let service_type: &[&[u8]] = &[b"_matter", b"_tcp", b"local"];

    // サービス型 PTR -> instance。
    let ptr = find_record(pkt, service_type, dns::T_PTR).unwrap();
    assert!(ptr.rdata_name().unwrap().eq_ci(instance));

    // operational サブタイプ _I<compressedFabricId>。
    assert!(has_record(
        pkt,
        &[
            b"_I2906C908D115D362",
            b"_sub",
            b"_matter",
            b"_tcp",
            b"local"
        ],
        dns::T_PTR
    ));

    // SRV + TXT。
    let (_, _, port, _) = find_record(pkt, instance, dns::T_SRV)
        .unwrap()
        .srv()
        .unwrap();
    assert_eq!(port, MATTER_PORT);
    let txt = find_record(pkt, instance, dns::T_TXT).unwrap();
    assert!(txt.txt_contains(b"SII=5000"));
    assert!(txt.txt_contains(b"SAI=300"));
}

/// SRV/TXT/A/AAAA 権威レコードにはキャッシュフラッシュビットが立つこと。
#[test]
fn authoritative_records_set_cache_flush() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));
    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    let pkt = &out[..len];

    let instance: &[&[u8]] = &[b"0011223344556677", b"_matterc", b"_udp", b"local"];
    let srv = find_record(pkt, instance, dns::T_SRV).unwrap();
    assert_ne!(srv.class & dns::CACHE_FLUSH, 0);

    // 共有 PTR にはフラッシュビットを立てない。
    let ptr = find_record(pkt, &[b"_matterc", b"_udp", b"local"], dns::T_PTR).unwrap();
    assert_eq!(ptr.class & dns::CACHE_FLUSH, 0);
}

/// `_matterc._udp.local` の PTR クエリに対し、回答 PTR と追加情報 SRV/TXT を返す。
#[test]
fn responds_to_service_type_ptr_query() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));

    let query = build_query(&[b"_matterc", b"_udp", b"local"], dns::T_PTR);
    let mut out = [0u8; 1400];
    let len = mdns.handle_query(&query, &mut out).unwrap();
    let pkt = &out[..len];

    let resp = dns::Response::parse(pkt).unwrap();
    // 回答は PTR、追加情報に SRV/TXT/AAAA。
    assert!(resp.answer_count() >= 1);
    let instance: &[&[u8]] = &[b"0011223344556677", b"_matterc", b"_udp", b"local"];
    assert!(find_record(pkt, &[b"_matterc", b"_udp", b"local"], dns::T_PTR).is_some());
    assert!(find_record(pkt, instance, dns::T_SRV).is_some());
    assert!(find_record(pkt, instance, dns::T_TXT).is_some());
    assert!(has_record(pkt, &[b"AABBCCDDEEFF", b"local"], dns::T_AAAA));
}

/// サブタイプ `_L<disc>._sub._matterc._udp.local` の PTR クエリに応答する。
#[test]
fn responds_to_subtype_ptr_query() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));

    let query = build_query(
        &[b"_L3840", b"_sub", b"_matterc", b"_udp", b"local"],
        dns::T_PTR,
    );
    let mut out = [0u8; 1400];
    let len = mdns.handle_query(&query, &mut out).unwrap();
    let pkt = &out[..len];
    let instance: &[&[u8]] = &[b"0011223344556677", b"_matterc", b"_udp", b"local"];
    assert!(find_record(pkt, instance, dns::T_SRV).is_some());
}

/// operational インスタンスへの SRV クエリに応答する(CASE 再接続)。
#[test]
fn responds_to_operational_instance_srv_query() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.add_operational(Operational::new(
        0x2906_C908_D115_D362,
        0x8FC7_7724_02CC_9DB4,
    ))
    .unwrap();

    let query = build_query(
        &[
            b"2906C908D115D362-8FC7772402CC9DB4",
            b"_matter",
            b"_tcp",
            b"local",
        ],
        dns::T_SRV,
    );
    let mut out = [0u8; 1400];
    let len = mdns.handle_query(&query, &mut out).unwrap();
    let pkt = &out[..len];
    let instance: &[&[u8]] = &[
        b"2906C908D115D362-8FC7772402CC9DB4",
        b"_matter",
        b"_tcp",
        b"local",
    ];
    let (_, _, port, _) = find_record(pkt, instance, dns::T_SRV)
        .unwrap()
        .srv()
        .unwrap();
    assert_eq!(port, MATTER_PORT);
    assert!(has_record(pkt, &[b"AABBCCDDEEFF", b"local"], dns::T_AAAA));
}

/// 無関係なクエリ(別ドメイン)には応答しない。
#[test]
fn ignores_unrelated_query() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));

    let query = build_query(&[b"example", b"com"], dns::T_A);
    let mut out = [0u8; 1400];
    assert!(mdns.handle_query(&query, &mut out).is_none());
}

/// 応答メッセージ(QR=1)は無視する。
#[test]
fn ignores_response_packets() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));

    // handle_query に応答メッセージを食わせても None。
    let mut resp_out = [0u8; 1400];
    let len = mdns.write_announce(&mut resp_out).unwrap(); // QR=1 のメッセージ
    let mut out = [0u8; 1400];
    assert!(mdns.handle_query(&resp_out[..len], &mut out).is_none());
}

/// 不正・断片的な入力で panic しない。
#[test]
fn malformed_input_does_not_panic() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));
    let mut out = [0u8; 1400];
    assert!(mdns.handle_query(&[], &mut out).is_none());
    assert!(mdns.handle_query(&[0u8; 3], &mut out).is_none());
    assert!(mdns.handle_query(&[0xFF; 12], &mut out).is_none());
    // 出力バッファが小さすぎても panic しない。
    let mut tiny = [0u8; 4];
    let query = build_query(&[b"_matterc", b"_udp", b"local"], dns::T_PTR);
    assert!(mdns.handle_query(&query, &mut tiny).is_none());
}

/// announce タイミング: 起動時バースト → 定常再 announce。
#[test]
fn announce_timing_burst_then_periodic() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));
    let mut out = [0u8; 1400];

    // t=0 で即 announce。
    assert_eq!(mdns.next_announce_deadline(), 0);
    assert!(mdns.poll_announce(0, &mut out).is_some());
    // まだ次の締切には達していない。
    let d1 = mdns.next_announce_deadline();
    assert_eq!(d1, ANNOUNCE_BURST_INTERVAL_MS);
    assert!(mdns.poll_announce(500, &mut out).is_none());

    // バーストの残りを消化。
    assert!(mdns.poll_announce(d1, &mut out).is_some());
    let d2 = mdns.next_announce_deadline();
    assert!(mdns.poll_announce(d2, &mut out).is_some());
    // バースト後は定常間隔へ。
    let d3 = mdns.next_announce_deadline();
    assert_eq!(d3, d2 + REANNOUNCE_INTERVAL_MS);
}

/// notify_change でバーストが再開する。
#[test]
fn notify_change_restarts_burst() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.set_commissionable(Some(test_commissionable()));
    let mut out = [0u8; 1400];
    // バーストを消化して定常状態へ。
    for _ in 0..ANNOUNCE_BURST {
        let d = mdns.next_announce_deadline();
        mdns.poll_announce(d, &mut out);
    }
    // fabric 追加相当の変更。
    mdns.add_operational(Operational::new(1, 2)).unwrap();
    mdns.notify_change(100_000);
    assert_eq!(mdns.next_announce_deadline(), 100_000);
    assert!(mdns.poll_announce(100_000, &mut out).is_some());
    assert_eq!(
        mdns.next_announce_deadline(),
        100_000 + ANNOUNCE_BURST_INTERVAL_MS
    );
}

/// 広告するサービスが無ければ announce は生成されない。
#[test]
fn no_services_no_announce() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    let mut out = [0u8; 1400];
    assert!(mdns.write_announce(&mut out).is_none());
    assert!(mdns.poll_announce(0, &mut out).is_none());
}

/// operational の重複追加は無視され、set_operational で置き換えられる。
#[test]
fn operational_dedup_and_replace() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.add_operational(Operational::new(1, 2)).unwrap();
    mdns.add_operational(Operational::new(1, 2)).unwrap(); // 重複
    assert_eq!(mdns.operational_len(), 1);

    mdns.set_operational([Operational::new(3, 4), Operational::new(5, 6)]);
    assert_eq!(mdns.operational_len(), 2);

    mdns.clear_operational();
    assert_eq!(mdns.operational_len(), 0);
}

/// 空 SII/SAI の operational でも TXT は空(長さ 1 の空文字列)で有効。
#[test]
fn operational_empty_txt_is_valid() {
    let mut mdns: MdnsResponder<4> = MdnsResponder::new(test_host(), MATTER_PORT);
    mdns.add_operational(Operational::new(0xAABB, 0xCCDD))
        .unwrap();
    let mut out = [0u8; 1400];
    let len = mdns.write_announce(&mut out).unwrap();
    let pkt = &out[..len];
    let instance: &[&[u8]] = &[
        b"000000000000AABB-000000000000CCDD",
        b"_matter",
        b"_tcp",
        b"local",
    ];
    let txt = find_record(pkt, instance, dns::T_TXT).unwrap();
    // RDATA は 1 バイト(空文字列)。
    assert_eq!(txt.rdata, &[0u8]);
}

// -- テスト用クエリビルダ --

/// 単一質問のクエリメッセージを固定バッファに組み立てる。
fn build_query(name: &[&[u8]], qtype: u16) -> [u8; 256] {
    let mut buf = [0u8; 256];
    // header: id=0, flags=0(QR=0), qd=1
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());
    let mut pos = 12;
    for label in name {
        buf[pos] = label.len() as u8;
        pos += 1;
        buf[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
    }
    buf[pos] = 0;
    pos += 1;
    buf[pos..pos + 2].copy_from_slice(&qtype.to_be_bytes());
    pos += 2;
    buf[pos..pos + 2].copy_from_slice(&dns::C_IN.to_be_bytes());
    buf
}
