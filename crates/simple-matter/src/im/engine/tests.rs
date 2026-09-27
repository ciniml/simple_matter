//! IM エンジンの統合テスト(`docs/design/interaction-model.md` §5–§11)。
//!
//! `device!` で組んだ On/Off ライト(EP0: Basic Information + Descriptor、EP1: On/Off +
//! Descriptor)に対し、`im::wire` codec で client 側メッセージを組んで `handle` を駆動する:
//! ワイルドカード Read、チャンク化 + StatusResponse による継続、Invoke による属性変化、
//! NodeLabel Write、Subscribe プライミング + dirty + `poll_subscriptions`、不正パスの Status 応答。

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::num::NonZeroU8;

use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, OnOffCluster,
};
use crate::dm::meta::EndpointId;
use crate::exchange::{ExchangeId, HandlerAction, ProtocolHandler, Role, RxMessage};
use crate::im::engine::{InteractionModel, SubDue, REPORT_INFLIGHT_TIMEOUT_MS};
use crate::im::events::PRIORITY_CRITICAL;
use crate::im::wire::{
    encode_invoke_request, encode_read_request, encode_read_request_events,
    encode_subscribe_request, encode_subscribe_request_events, encode_write_request, AttributeId,
    AttributePath, AttributeReportRef, ClusterId, CommandId, CommandPath, EventId, EventPath,
    EventReportRef, ImOpCode, ImStatus, InvokeRequestHeader, InvokeResponseRef,
    InvokeResponseRefItem, ReportDataRef, StatusResponse, SubscribeResponse, WriteRequestHeader,
    WriteResponseRef,
};
use crate::tlv::{TlvTag, TlvValue, TlvWriter};
use crate::transport::header::{ExchFlags, PayloadHeader};
use crate::transport::net::PeerAddr;
use crate::transport::session::{SessionInit, SessionManager, SessionMode};

// ==========================================================================
// テスト用 On/Off ライト
// ==========================================================================

static CFG: BasicInfoConfig = BasicInfoConfig {
    vendor_name: "TestVendor",
    vendor_id: 0xFFF1,
    product_name: "TestLight",
    product_id: 0x8000,
    hardware_version: 1,
    hardware_version_string: "HW1",
    software_version: 0x0001_0000,
    software_version_string: "1.0.0",
    serial_number: "SN-0001",
};

struct Light {
    basic: BasicInformationCluster,
    desc0: DescriptorCluster,
    on_off: OnOffCluster,
    desc1: DescriptorCluster,
}

crate::device! {
    Light {
        endpoint 0 {
            device_types: [ (0x0016, 1) ],
            parts: [ 1 ],
            clusters: [ (0x0028, basic), (0x001D, desc0) ],
        }
        endpoint 1 {
            device_types: [ (0x0100, 3) ],
            parts: [],
            clusters: [ (0x0006, on_off), (0x001D, desc1) ],
        }
    }
}

impl Light {
    fn build() -> Self {
        Light {
            basic: BasicInformationCluster::new(&CFG),
            desc0: DescriptorCluster::new(
                EndpointId(0),
                Light::device_types(EndpointId(0)),
                Light::server_list(EndpointId(0)),
                &[],
                Light::parts(EndpointId(0)),
            ),
            on_off: OnOffCluster::new(),
            desc1: DescriptorCluster::new(
                EndpointId(1),
                Light::device_types(EndpointId(1)),
                Light::server_list(EndpointId(1)),
                &[],
                Light::parts(EndpointId(1)),
            ),
        }
    }
}

type Im = InteractionModel<Light, 2, 2, 8>;

// ==========================================================================
// テストハーネス
// ==========================================================================

const EXCH_ID: u16 = 0x1111;

fn addr() -> PeerAddr {
    PeerAddr::Udp(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        5540,
    ))
}

/// CASE セッション(fabric 1)を 1 本張ったマネージャと、その exchange を返す。
fn setup() -> (Im, SessionManager<2>, ExchangeId) {
    let mut mgr: SessionManager<2> = SessionManager::new();
    let init = SessionInit {
        peer_addr: addr(),
        local_node_id: 1,
        peer_node_id: Some(0x1234),
        peer_session_id: 1,
        tx_ctr_start: 1,
        rx_ctr_start: 0,
        mode: SessionMode::Case {
            fabric_idx: NonZeroU8::new(1).unwrap(),
        },
        enc_key: [0u8; 16],
        dec_key: [0u8; 16],
        att_challenge: [0u8; 16],
    };
    let sid = mgr.insert(init, 0).unwrap();
    let ex = ExchangeId::from_parts(sid, EXCH_ID);
    (Im::new(Light::build()), mgr, ex)
}

fn phdr(opcode: u8) -> PayloadHeader {
    PayloadHeader {
        exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
        proto_opcode: opcode,
        exch_id: EXCH_ID,
        proto_id: 0x0001,
        vendor_id: None,
        ack_ctr: None,
    }
}

fn rxm<'a>(h: &'a PayloadHeader, payload: &'a [u8], ex: ExchangeId) -> RxMessage<'a> {
    RxMessage {
        header: h,
        payload,
        exchange: ex,
        role: Role::Responder,
    }
}

/// (opcode, len, is_close) を取り出す。`None` は panic。
fn parts(a: HandlerAction) -> (u8, usize, bool) {
    match a {
        HandlerAction::Respond { opcode, len, .. } => (opcode, len, false),
        HandlerAction::Close { opcode, len, .. } => (opcode, len, true),
        HandlerAction::None | HandlerAction::CloseSilent => panic!("expected a response action"),
    }
}

/// ReportData 内の AttributeReportIB 数を数える。
fn count_reports(msg: &[u8]) -> usize {
    let rd = ReportDataRef::new(msg).unwrap();
    let mut n = 0;
    for r in rd.attr_reports().unwrap() {
        r.unwrap();
        n += 1;
    }
    n
}

fn onoff_cluster_path() -> AttributePath {
    AttributePath {
        endpoint: None,
        cluster: Some(ClusterId(0x0006)),
        attribute: None,
        list_index: None,
        list_append: false,
        enable_tag_compression: false,
    }
}

// ==========================================================================
// 1. ワイルドカード Read(全属性、単発)
// ==========================================================================

#[test]
fn wildcard_read_all_attributes() {
    let (mut im, mut mgr, ex) = setup();

    let mut req = [0u8; 64];
    let rlen = encode_read_request(&mut req, false, |p| p.push(&AttributePath::default())).unwrap();
    let h = phdr(ImOpCode::ReadRequest.to_u8());

    // 1 チャンクは送信 MTU 由来の上限(MAX_REPORT_CHUNK)に収まるため、全属性(45)は複数チャンクに
    // またがる。各チャンクを走査して内容を検証し、StatusResponse(SUCCESS)で続きを取り出す。
    let mut count = 0;
    let mut on_off_seen = false;
    let mut vendor_seen = false;
    let mut scan = |buf: &[u8]| -> bool {
        let rd = ReportDataRef::new(buf).unwrap();
        for r in rd.attr_reports().unwrap() {
            count += 1;
            if let AttributeReportRef::Data(d) = r.unwrap() {
                if d.path.cluster == Some(ClusterId(0x0006))
                    && d.path.attribute == Some(AttributeId(0x0000))
                {
                    let mut v = d.value();
                    assert_eq!(
                        v.read_next().unwrap().unwrap().value,
                        TlvValue::Boolean(false)
                    );
                    on_off_seen = true;
                }
                if d.path.cluster == Some(ClusterId(0x0028))
                    && d.path.attribute == Some(AttributeId(0x0001))
                {
                    let mut v = d.value();
                    assert_eq!(
                        v.read_next().unwrap().unwrap().value,
                        TlvValue::Utf8String("TestVendor")
                    );
                    vendor_seen = true;
                }
            }
        }
        rd.more_chunks().unwrap()
    };

    let mut tx = [0u8; 2048];
    let a = im
        .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    let mut more = scan(&tx[..len]);
    assert_eq!(
        is_close, !more,
        "exchange closes exactly with the final chunk"
    );

    let sh = phdr(ImOpCode::StatusResponse.to_u8());
    let mut guard = 0;
    while more {
        guard += 1;
        assert!(guard < 100, "chunk loop must terminate");
        let mut sbuf = [0u8; 16];
        let slen = StatusResponse::new(ImStatus::Success)
            .encode(&mut sbuf)
            .unwrap();
        let mut ctx = [0u8; 2048];
        let a = im
            .handle(&rxm(&sh, &sbuf[..slen], ex), &mut ctx, &mut mgr, 0)
            .unwrap();
        let (op, len, is_close) = parts(a);
        assert_eq!(op, ImOpCode::ReportData.to_u8());
        more = scan(&ctx[..len]);
        assert_eq!(
            is_close, !more,
            "exchange closes exactly with the final chunk"
        );
    }
    // ep0: basic(16)+desc(4)=20 固有 +10 global、ep1: on_off(1)+desc(4)=5 固有 +10 global → 45。
    assert_eq!(count, 45);
    assert!(on_off_seen && vendor_seen);
    assert_eq!(
        im.active_read_count(),
        0,
        "no continuation slot for a complete read"
    );
}

// ==========================================================================
// 2. チャンク化(小 tx バッファで強制)→ StatusResponse → 続き
// ==========================================================================

#[test]
fn chunked_read_resumes_on_status() {
    let (mut im, mut mgr, ex) = setup();

    let mut req = [0u8; 64];
    let rlen = encode_read_request(&mut req, false, |p| p.push(&AttributePath::default())).unwrap();
    let rh = phdr(ImOpCode::ReadRequest.to_u8());

    // 小さな tx バッファでチャンク化を強制。
    let mut tx = [0u8; 160];
    let a = im
        .handle(&rxm(&rh, &req[..rlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    assert!(!is_close, "chunked read keeps the exchange open");
    assert!(ReportDataRef::new(&tx[..len])
        .unwrap()
        .more_chunks()
        .unwrap());
    assert_eq!(im.active_read_count(), 1);

    let mut total = count_reports(&tx[..len]);
    assert!(total >= 1, "each chunk carries >= 1 report");

    // StatusResponse(SUCCESS) を送るたびに次チャンクが返る。
    let sh = phdr(ImOpCode::StatusResponse.to_u8());
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 100, "chunk loop must terminate");
        let mut sbuf = [0u8; 16];
        let slen = StatusResponse::new(ImStatus::Success)
            .encode(&mut sbuf)
            .unwrap();
        let mut ctx = [0u8; 160];
        let a = im
            .handle(&rxm(&sh, &sbuf[..slen], ex), &mut ctx, &mut mgr, 0)
            .unwrap();
        let (op, len, is_close) = parts(a);
        assert_eq!(op, ImOpCode::ReportData.to_u8());
        let more = ReportDataRef::new(&ctx[..len])
            .unwrap()
            .more_chunks()
            .unwrap();
        total += count_reports(&ctx[..len]);
        if more {
            assert!(!is_close);
        } else {
            assert!(is_close, "final chunk ends the exchange");
            break;
        }
    }
    assert_eq!(total, 45, "all attributes delivered across chunks");
    assert_eq!(im.active_read_count(), 0, "continuation slot freed");
}

// ==========================================================================
// 3. Invoke On → OnOff 属性変化 → Read 確認
// ==========================================================================

#[test]
fn invoke_on_changes_attribute() {
    let (mut im, mut mgr, ex) = setup();

    // On (0x01)。
    let mut req = [0u8; 64];
    let ilen = encode_invoke_request(&mut req, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
            None,
            None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
        )
    })
    .unwrap();
    let ih = phdr(ImOpCode::InvokeRequest.to_u8());

    let mut tx = [0u8; 128];
    let a = im
        .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::InvokeResponse.to_u8());
    assert!(is_close);

    let ir = InvokeResponseRef::new(&tx[..len]).unwrap();
    let mut n = 0;
    for item in ir.invoke_responses().unwrap() {
        n += 1;
        match item.unwrap() {
            InvokeResponseRefItem::Status(s) => {
                assert_eq!(s.status.status, ImStatus::Success);
                assert_eq!(s.path.command, CommandId(0x01));
            }
            InvokeResponseRefItem::Command(_) => panic!("On returns status only"),
        }
    }
    assert_eq!(n, 1);
    assert!(im.data_model().on_off.is_on(), "cluster state flipped on");

    // 具象 Read で OnOff = true を確認。
    let mut rreq = [0u8; 64];
    let rlen = encode_read_request(&mut rreq, false, |p| {
        p.push(&AttributePath::concrete(
            EndpointId(1),
            ClusterId(0x0006),
            AttributeId(0x0000),
        ))
    })
    .unwrap();
    let rh = phdr(ImOpCode::ReadRequest.to_u8());
    let mut tx2 = [0u8; 128];
    let a = im
        .handle(&rxm(&rh, &rreq[..rlen], ex), &mut tx2, &mut mgr, 0)
        .unwrap();
    let (_, len, _) = parts(a);
    let rd = ReportDataRef::new(&tx2[..len]).unwrap();
    let mut it = rd.attr_reports().unwrap();
    match it.next().unwrap().unwrap() {
        AttributeReportRef::Data(d) => {
            let mut v = d.value();
            assert_eq!(
                v.read_next().unwrap().unwrap().value,
                TlvValue::Boolean(true)
            );
        }
        AttributeReportRef::Status(_) => panic!("expected data report"),
    }
    assert!(it.next().is_none());
}

// ==========================================================================
// 4. NodeLabel Write
// ==========================================================================

#[test]
fn write_node_label() {
    let (mut im, mut mgr, ex) = setup();

    let mut req = [0u8; 96];
    let wlen = encode_write_request(&mut req, WriteRequestHeader::default(), |dw| {
        dw.push(
            None,
            &AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005)),
            |vw, t| vw.write_utf8(t, "Kitchen"),
        )
    })
    .unwrap();
    let wh = phdr(ImOpCode::WriteRequest.to_u8());

    let mut tx = [0u8; 128];
    let a = im
        .handle(&rxm(&wh, &req[..wlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::WriteResponse.to_u8());
    assert!(is_close);

    let wr = WriteResponseRef::new(&tx[..len]).unwrap();
    let mut n = 0;
    for s in wr.write_responses().unwrap() {
        n += 1;
        let s = s.unwrap();
        assert_eq!(s.status.status, ImStatus::Success);
        assert_eq!(s.path.attribute, Some(AttributeId(0x0005)));
    }
    assert_eq!(n, 1);
    assert_eq!(im.data_model().basic.node_label(), "Kitchen");
}

// ==========================================================================
// 5. Subscribe → プライミング → dirty → poll_subscriptions でレポート生成
// ==========================================================================

#[test]
fn subscribe_prime_then_report_on_dirty() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();

    // SubscribeRequest(OnOff クラスタ、min=1s, max=10s)。
    let mut req = [0u8; 64];
    let slen = encode_subscribe_request(&mut req, false, 1, 10, false, |p| {
        p.push(&onoff_cluster_path())
    })
    .unwrap();
    let sh = phdr(ImOpCode::SubscribeRequest.to_u8());

    let mut tx = [0u8; 2048];
    let a = im
        .handle(&rxm(&sh, &req[..slen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8(), "priming report first");
    assert!(!is_close);
    let rd = ReportDataRef::new(&tx[..len]).unwrap();
    assert!(!rd.more_chunks().unwrap());
    // プライミングレポートにも SubscriptionId を含める(chip の ReadClient は欠如を
    // Invalid argument で拒否する。実測、2026-07-08)。
    assert_eq!(
        rd.subscription_id().unwrap(),
        Some(1),
        "priming report carries the subscription id (chip 互換)"
    );
    // OnOff(false) が含まれる。
    assert!(rd
        .attr_reports()
        .unwrap()
        .filter_map(|r| r.ok())
        .any(|r| matches!(r, AttributeReportRef::Data(d)
            if d.path.attribute == Some(AttributeId(0x0000)))));
    assert_eq!(im.subscription_count(), 1);

    // StatusResponse(SUCCESS) → SubscribeResponse。
    let stath = phdr(ImOpCode::StatusResponse.to_u8());
    let mut stat = [0u8; 16];
    let stlen = StatusResponse::new(ImStatus::Success)
        .encode(&mut stat)
        .unwrap();
    let mut tx2 = [0u8; 64];
    let a = im
        .handle(&rxm(&stath, &stat[..stlen], ex), &mut tx2, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::SubscribeResponse.to_u8());
    assert!(is_close);
    let sub_resp = SubscribeResponse::decode(&tx2[..len]).unwrap();
    assert_eq!(sub_resp.max_interval_s, 10);
    let sub_id = sub_resp.subscription_id;
    assert_eq!(
        im.active_read_count(),
        0,
        "priming slot freed after SubscribeResponse"
    );

    // dirty にする(属性変化)。
    im.data_model_mut().on_off.set(true);

    // min interval(1s)前は due にならない。
    assert!(im.poll_subscriptions(500).is_none());

    // min 経過後は due。
    let due = im.poll_subscriptions(2_000);
    assert_eq!(
        due,
        Some(SubDue {
            subscription: sub_id,
            session: sid
        })
    );

    // device 発レポートを組み立てる。
    let ex2 = ExchangeId::from_parts(sid, 0x2222);
    let mut rtx = [0u8; 256];
    let rlen = im.build_report(sub_id, ex2, &mut rtx, 2_000).unwrap();
    let rd = ReportDataRef::new(&rtx[..rlen]).unwrap();
    assert_eq!(rd.subscription_id().unwrap(), Some(sub_id));
    assert!(rd
        .attr_reports()
        .unwrap()
        .filter_map(|r| r.ok())
        .any(|r| matches!(r, AttributeReportRef::Data(d)
            if d.path.attribute == Some(AttributeId(0x0000)))));

    // レポート後は dirty がクリアされ、max interval まで due でない。
    assert!(im.poll_subscriptions(2_000).is_none());
    // 終端 StatusResponse 待ち(in-flight)の間は max interval ではなく強制回収の期限が出る
    // (設計 §16.6 P1。in-flight ガードで due しない購読の締切を出しても意味がない)。
    assert_eq!(
        im.next_deadline(2_000),
        Some(2_000 + REPORT_INFLIGHT_TIMEOUT_MS + 1),
        "in-flight report: forced-reclaim deadline"
    );
    // 終端 StatusResponse(Success)で in-flight を解除 → 以降は max interval 期限。
    let mut tx3 = [0u8; 64];
    let a = im
        .handle(&rxm(&stath, &stat[..stlen], ex2), &mut tx3, &mut mgr, 2_100)
        .unwrap();
    assert!(matches!(a, HandlerAction::CloseSilent));
    assert_eq!(
        im.next_deadline(2_100),
        Some(12_000),
        "last_report(2000) + max(10s)"
    );

    // セッション切断で購読破棄。
    im.on_session_closed(sid);
    assert_eq!(im.subscription_count(), 0);
    assert!(im.next_deadline(2_000).is_none());
}

// ==========================================================================
// 6. 不正パスの Status 応答(UnsupportedEndpoint / Cluster / Attribute)
// ==========================================================================

#[test]
fn invalid_paths_report_status() {
    let (mut im, mut mgr, ex) = setup();

    let bad_ep = AttributePath::concrete(EndpointId(99), ClusterId(0x0006), AttributeId(0x0000));
    let bad_cl = AttributePath::concrete(EndpointId(0), ClusterId(0x1234), AttributeId(0x0000));
    let bad_at = AttributePath::concrete(EndpointId(1), ClusterId(0x0006), AttributeId(0x9999));

    let mut req = [0u8; 96];
    let rlen = encode_read_request(&mut req, false, |p| {
        p.push(&bad_ep)?;
        p.push(&bad_cl)?;
        p.push(&bad_at)
    })
    .unwrap();
    let rh = phdr(ImOpCode::ReadRequest.to_u8());

    let mut tx = [0u8; 256];
    let a = im
        .handle(&rxm(&rh, &req[..rlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, _) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8());

    let rd = ReportDataRef::new(&tx[..len]).unwrap();
    let mut statuses = [ImStatus::Success; 8];
    let mut n = 0;
    for r in rd.attr_reports().unwrap() {
        match r.unwrap() {
            AttributeReportRef::Status(s) => {
                statuses[n] = s.status.status;
                n += 1;
            }
            AttributeReportRef::Data(_) => panic!("nonexistent paths must yield status, not data"),
        }
    }
    assert_eq!(n, 3);
    assert!(statuses[..3].contains(&ImStatus::UnsupportedEndpoint));
    assert!(statuses[..3].contains(&ImStatus::UnsupportedCluster));
    assert!(statuses[..3].contains(&ImStatus::UnsupportedAttribute));
}

// ==========================================================================
// 7. Timed 相互作用(受理 → 期限内許可 / 期限切れ拒否 / フラグ不整合)
// ==========================================================================

#[test]
fn timed_write_paths() {
    use crate::im::wire::TimedRequest;

    // (a) TimedRequest → 期限内 Write は成功。
    {
        let (mut im, mut mgr, ex) = setup();
        let mut treq = [0u8; 16];
        let tlen = TimedRequest::new(1_000).encode(&mut treq).unwrap();
        let th = phdr(ImOpCode::TimedRequest.to_u8());
        let mut tx = [0u8; 32];
        let a = im
            .handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        let (op, _, is_close) = parts(a);
        assert_eq!(op, ImOpCode::StatusResponse.to_u8());
        assert!(!is_close, "TimedRequest is followed by the Write");

        let mut wreq = [0u8; 96];
        let wlen = encode_write_request(
            &mut wreq,
            WriteRequestHeader {
                suppress_response: false,
                timed_request: true,
            },
            |dw| {
                dw.push(
                    None,
                    &AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005)),
                    |vw, t| vw.write_utf8(t, "Timed"),
                )
            },
        )
        .unwrap();
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx2 = [0u8; 128];
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx2, &mut mgr, 500)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::WriteResponse.to_u8());
        let wr = WriteResponseRef::new(&tx2[..len]).unwrap();
        let s = wr.write_responses().unwrap().next().unwrap().unwrap();
        assert_eq!(s.status.status, ImStatus::Success);
        assert_eq!(im.data_model().basic.node_label(), "Timed");
    }

    // (b) 期限切れ Write は Timeout。
    {
        let (mut im, mut mgr, ex) = setup();
        let mut treq = [0u8; 16];
        let tlen = TimedRequest::new(100).encode(&mut treq).unwrap();
        let th = phdr(ImOpCode::TimedRequest.to_u8());
        let mut tx = [0u8; 32];
        im.handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();

        let mut wreq = [0u8; 96];
        let wlen = encode_write_request(
            &mut wreq,
            WriteRequestHeader {
                suppress_response: false,
                timed_request: true,
            },
            |dw| {
                dw.push(
                    None,
                    &AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005)),
                    |vw, t| vw.write_utf8(t, "Late"),
                )
            },
        )
        .unwrap();
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx2 = [0u8; 64];
        // now(5_000) > deadline(0+100)。
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx2, &mut mgr, 5_000)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::StatusResponse.to_u8());
        assert_eq!(
            StatusResponse::decode(&tx2[..len]).unwrap().status,
            ImStatus::Timeout
        );
        assert_eq!(
            im.data_model().basic.node_label(),
            "",
            "expired write rejected"
        );
    }

    // (c) TimedRequest 無しで timed フラグ付き Write は TimedRequestMismatch。
    {
        let (mut im, mut mgr, ex) = setup();
        let mut wreq = [0u8; 96];
        let wlen = encode_write_request(
            &mut wreq,
            WriteRequestHeader {
                suppress_response: false,
                timed_request: true,
            },
            |dw| {
                dw.push(
                    None,
                    &AttributePath::concrete(EndpointId(0), ClusterId(0x0028), AttributeId(0x0005)),
                    |vw, t| vw.write_utf8(t, "NoArm"),
                )
            },
        )
        .unwrap();
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx = [0u8; 64];
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::StatusResponse.to_u8());
        assert_eq!(
            StatusResponse::decode(&tx[..len]).unwrap().status,
            ImStatus::TimedRequestMismatch
        );
    }
}

// ==========================================================================
// 7b. timed 必須属性の強制(@timed 注釈付き属性 → NeedsTimedInteraction)
// ==========================================================================

/// timed write 必須の書き込み可能属性を 1 つ持つテスト用クラスタ(id 0xFC00)。
struct TimedAttrCluster {
    value: u8,
}

impl TimedAttrCluster {
    const fn new() -> Self {
        Self { value: 0 }
    }

    fn write_value(
        &mut self,
        data: crate::dm::AttrWrite<'_>,
        _acc: &crate::dm::meta::AccessContext,
    ) -> Result<(), ImStatus> {
        self.value = data.as_unsigned()? as u8;
        Ok(())
    }
}

crate::cluster! {
    TimedAttrCluster {
        id: 0xFC00,
        revision: 1,
        feature_map: 0,
        dirty: _,
        invoke: _,
        attributes: [
            0x0000 Value {
                access: View,
                quality: [],
                subscribe: false,
                read: (|c: &TimedAttrCluster, e: &mut crate::dm::codec::AttrEncoder<'_, '_>| e.write_u8(c.value)),
                write: (Operate, |c: &mut TimedAttrCluster, data, acc| c.write_value(data, acc))
            } @timed,
        ],
        accepted: [],
        generated: [],
    }
}

struct TimedDev {
    tc: TimedAttrCluster,
    desc0: DescriptorCluster,
}

crate::device! {
    TimedDev {
        endpoint 0 {
            device_types: [ (0x0016, 1) ],
            parts: [],
            clusters: [ (0xFC00, tc), (0x001D, desc0) ],
        }
    }
}

impl TimedDev {
    fn build() -> Self {
        TimedDev {
            tc: TimedAttrCluster::new(),
            desc0: DescriptorCluster::new(
                EndpointId(0),
                TimedDev::device_types(EndpointId(0)),
                TimedDev::server_list(EndpointId(0)),
                &[],
                TimedDev::parts(EndpointId(0)),
            ),
        }
    }
}

type TimedIm = InteractionModel<TimedDev, 2, 2, 8>;

fn setup_timed() -> (TimedIm, SessionManager<2>, ExchangeId) {
    let mut mgr: SessionManager<2> = SessionManager::new();
    let init = SessionInit {
        peer_addr: addr(),
        local_node_id: 1,
        peer_node_id: Some(0x1234),
        peer_session_id: 1,
        tx_ctr_start: 1,
        rx_ctr_start: 0,
        mode: SessionMode::Case {
            fabric_idx: NonZeroU8::new(1).unwrap(),
        },
        enc_key: [0u8; 16],
        dec_key: [0u8; 16],
        att_challenge: [0u8; 16],
    };
    let sid = mgr.insert(init, 0).unwrap();
    let ex = ExchangeId::from_parts(sid, EXCH_ID);
    (TimedIm::new(TimedDev::build()), mgr, ex)
}

/// 属性 0xFC00/0x0000 への WriteRequest を組む(timed フラグは引数)。
fn timed_attr_write(req: &mut [u8], value: u8, timed: bool) -> usize {
    encode_write_request(
        req,
        WriteRequestHeader {
            suppress_response: false,
            timed_request: timed,
        },
        |dw| {
            dw.push(
                None,
                &AttributePath::concrete(EndpointId(0), ClusterId(0xFC00), AttributeId(0x0000)),
                |vw, t| vw.write_u8(t, value),
            )
        },
    )
    .unwrap()
}

fn write_status(msg: &[u8]) -> ImStatus {
    let wr = WriteResponseRef::new(msg).unwrap();
    wr.write_responses()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .status
        .status
}

#[test]
fn timed_required_attribute_enforced() {
    use crate::im::wire::TimedRequest;

    // (a) TimedRequest 無しの直 write → NeedsTimedInteraction、値は不変。
    {
        let (mut im, mut mgr, ex) = setup_timed();
        let mut wreq = [0u8; 64];
        let wlen = timed_attr_write(&mut wreq, 42, false);
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx = [0u8; 128];
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::WriteResponse.to_u8());
        assert_eq!(write_status(&tx[..len]), ImStatus::NeedsTimedInteraction);
        assert_eq!(im.data_model().tc.value, 0, "non-timed write rejected");
    }

    // (b) TimedRequest → 窓内 timed write は成功。
    {
        let (mut im, mut mgr, ex) = setup_timed();
        let mut treq = [0u8; 16];
        let tlen = TimedRequest::new(1_000).encode(&mut treq).unwrap();
        let th = phdr(ImOpCode::TimedRequest.to_u8());
        let mut tx = [0u8; 32];
        im.handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();

        let mut wreq = [0u8; 64];
        let wlen = timed_attr_write(&mut wreq, 42, true);
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx2 = [0u8; 128];
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx2, &mut mgr, 500)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::WriteResponse.to_u8());
        assert_eq!(write_status(&tx2[..len]), ImStatus::Success);
        assert_eq!(im.data_model().tc.value, 42);
    }

    // (c) 窓 expire 後の timed write は Timeout、値は不変。
    {
        let (mut im, mut mgr, ex) = setup_timed();
        let mut treq = [0u8; 16];
        let tlen = TimedRequest::new(100).encode(&mut treq).unwrap();
        let th = phdr(ImOpCode::TimedRequest.to_u8());
        let mut tx = [0u8; 32];
        im.handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();

        let mut wreq = [0u8; 64];
        let wlen = timed_attr_write(&mut wreq, 7, true);
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx2 = [0u8; 64];
        // now(5_000) > deadline(0+100)。
        let a = im
            .handle(&rxm(&wh, &wreq[..wlen], ex), &mut tx2, &mut mgr, 5_000)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::StatusResponse.to_u8());
        assert_eq!(
            StatusResponse::decode(&tx2[..len]).unwrap().status,
            ImStatus::Timeout
        );
        assert_eq!(im.data_model().tc.value, 0, "expired timed write rejected");
    }
}

// ==========================================================================
// 8. full ACL(DataModel::acl = Some、docs/design/acl.md §3/§4/§8)
// ==========================================================================

mod acl_enforcement {
    use super::*;
    use crate::acl::{AclEntry, AclHandle, AclTable};
    use crate::dm::clusters::AccessControlCluster;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AccessContext, ClusterMeta, CommandMeta, EndpointMeta, Privilege};
    use crate::dm::{DataModel, ServerCluster};
    use crate::tlv::TlvReader;
    use core::cell::RefCell;

    /// AddNOC / RemoveFabric の副作用要求だけを再現するスタブクラスタ(0xFC01)。
    ///
    /// コマンド 0x00 = `request_case_admin_acl(fabric 1, subject 0xCAFE)`、
    /// 0x01 = `request_fabric_removed(fabric 1)`。
    struct EffectsStub;

    static STUB_CMDS: &[CommandMeta] = &[
        CommandMeta::new(CommandId(0x00), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x01), false, Privilege::Administer),
    ];
    static STUB_META: ClusterMeta = ClusterMeta::new(ClusterId(0xFC01), 1, 0, &[], STUB_CMDS, &[]);

    impl ServerCluster for EffectsStub {
        fn meta(&self) -> &'static ClusterMeta {
            &STUB_META
        }
        fn read_attribute(
            &self,
            _attr: AttributeId,
            _enc: &mut crate::dm::codec::AttrEncoder<'_, '_>,
            _acc: &AccessContext,
        ) -> Result<(), ImStatus> {
            Err(ImStatus::UnsupportedAttribute)
        }
        fn invoke_command(
            &mut self,
            cmd: CommandId,
            _fields: &mut TlvReader<'_>,
            resp: &mut CmdResponder<'_, '_>,
            _acc: &AccessContext,
        ) -> Result<(), ImStatus> {
            match cmd.0 {
                0x00 => {
                    resp.request_case_admin_acl(NonZeroU8::new(1).unwrap(), 0xCAFE);
                    Ok(())
                }
                0x01 => {
                    resp.request_fabric_removed(NonZeroU8::new(1).unwrap());
                    Ok(())
                }
                _ => Err(ImStatus::UnsupportedCommand),
            }
        }
    }

    /// full ACL 付きライト(EP0: AccessControl + スタブ、EP1: On/Off)。手書き DataModel。
    struct AclLight<'a> {
        acl: &'a RefCell<AclTable<8>>,
        ac: AccessControlCluster<'a, 8>,
        on_off: OnOffCluster,
        stub: EffectsStub,
    }

    static ACL_EP0: &[ClusterId] = &[ClusterId(0x001F), ClusterId(0xFC01)];
    static ACL_EP1: &[ClusterId] = &[ClusterId(0x0006)];

    impl DataModel for AclLight<'_> {
        fn endpoints(&self) -> &[EndpointMeta] {
            static EPS: &[EndpointMeta] = &[
                EndpointMeta::new(EndpointId(0), &[], ACL_EP0),
                EndpointMeta::new(EndpointId(1), &[], ACL_EP1),
            ];
            EPS
        }
        fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
            match ep.0 {
                0 => ACL_EP0,
                1 => ACL_EP1,
                _ => &[],
            }
        }
        fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
            match (ep.0, cl.0) {
                (0, 0x001F) => Some(&self.ac),
                (0, 0xFC01) => Some(&self.stub),
                (1, 0x0006) => Some(&self.on_off),
                _ => None,
            }
        }
        fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
            match (ep.0, cl.0) {
                (0, 0x001F) => Some(&mut self.ac),
                (0, 0xFC01) => Some(&mut self.stub),
                (1, 0x0006) => Some(&mut self.on_off),
                _ => None,
            }
        }
        fn acl(&self) -> Option<&dyn AclHandle> {
            Some(self.acl)
        }
    }

    type AclIm<'a> = InteractionModel<AclLight<'a>, 2, 2, 8>;

    /// CASE(fabric 1, subject 0x1234)セッションと IM を組む。
    fn setup_acl(acl: &RefCell<AclTable<8>>) -> (AclIm<'_>, SessionManager<2>, ExchangeId) {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let init = SessionInit {
            peer_addr: addr(),
            local_node_id: 1,
            peer_node_id: Some(0x1234),
            peer_session_id: 1,
            tx_ctr_start: 1,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: NonZeroU8::new(1).unwrap(),
            },
            enc_key: [0u8; 16],
            dec_key: [0u8; 16],
            att_challenge: [0u8; 16],
        };
        let sid = mgr.insert(init, 0).unwrap();
        let ex = ExchangeId::from_parts(sid, EXCH_ID);
        let light = AclLight {
            acl,
            ac: AccessControlCluster::new(acl),
            on_off: OnOffCluster::new(),
            stub: EffectsStub,
        };
        (AclIm::new(light), mgr, ex)
    }

    /// PASE セッションに差し替えた setup。
    fn setup_acl_pase(acl: &RefCell<AclTable<8>>) -> (AclIm<'_>, SessionManager<2>, ExchangeId) {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let mut init = SessionInit::plaintext(addr(), 1, 1);
        init.mode = SessionMode::Pase { fabric_idx: 0 };
        let sid = mgr.insert(init, 0).unwrap();
        let ex = ExchangeId::from_parts(sid, EXCH_ID);
        let light = AclLight {
            acl,
            ac: AccessControlCluster::new(acl),
            on_off: OnOffCluster::new(),
            stub: EffectsStub,
        };
        (AclIm::new(light), mgr, ex)
    }

    /// On/Off の On(0x01)を invoke し、応答の先頭 status を返す。
    fn invoke_on(im: &mut AclIm<'_>, mgr: &mut SessionManager<2>, ex: ExchangeId) -> ImStatus {
        let mut req = [0u8; 64];
        let ilen = encode_invoke_request(&mut req, InvokeRequestHeader::default(), |cw| {
            cw.push(
                &CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
                None,
                None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
            )
        })
        .unwrap();
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        let a = im
            .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, mgr, 0)
            .unwrap();
        let (_, len, _) = parts(a);
        let ir = InvokeResponseRef::new(&tx[..len]).unwrap();
        match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
            InvokeResponseRefItem::Status(s) => s.status.status,
            InvokeResponseRefItem::Command(_) => panic!("status expected"),
        }
    }

    #[test]
    fn case_without_entry_is_denied() {
        let acl = RefCell::new(AclTable::new());
        let (mut im, mut mgr, ex) = setup_acl(&acl);
        // ACL 空 → invoke は UnsupportedAccess、状態は変化しない。
        assert_eq!(
            invoke_on(&mut im, &mut mgr, ex),
            ImStatus::UnsupportedAccess
        );
        assert!(!im.data_model().on_off.is_on());

        // read も per-path の UnsupportedAccess StatusIB。
        let mut req = [0u8; 64];
        let rlen = encode_read_request(&mut req, false, |p| {
            p.push(&AttributePath::concrete(
                EndpointId(1),
                ClusterId(0x0006),
                AttributeId(0x0000),
            ))
        })
        .unwrap();
        let rh = phdr(ImOpCode::ReadRequest.to_u8());
        let mut tx = [0u8; 256];
        let a = im
            .handle(&rxm(&rh, &req[..rlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        let (_, len, _) = parts(a);
        let rd = ReportDataRef::new(&tx[..len]).unwrap();
        match rd.attr_reports().unwrap().next().unwrap().unwrap() {
            AttributeReportRef::Status(s) => {
                assert_eq!(s.status.status, ImStatus::UnsupportedAccess)
            }
            AttributeReportRef::Data(_) => panic!("expected access denial"),
        }
    }

    #[test]
    fn matching_admin_entry_grants_access() {
        let acl = RefCell::new(AclTable::new());
        acl.borrow_mut()
            .add(AclEntry::case_admin(NonZeroU8::new(1).unwrap(), 0x1234))
            .unwrap();
        let (mut im, mut mgr, ex) = setup_acl(&acl);
        assert_eq!(invoke_on(&mut im, &mut mgr, ex), ImStatus::Success);
        assert!(im.data_model().on_off.is_on());
    }

    #[test]
    fn entry_for_other_subject_is_denied() {
        let acl = RefCell::new(AclTable::new());
        acl.borrow_mut()
            .add(AclEntry::case_admin(NonZeroU8::new(1).unwrap(), 0xDEAD))
            .unwrap();
        let (mut im, mut mgr, ex) = setup_acl(&acl);
        assert_eq!(
            invoke_on(&mut im, &mut mgr, ex),
            ImStatus::UnsupportedAccess
        );
    }

    #[test]
    fn pase_has_implicit_administer() {
        let acl = RefCell::new(AclTable::new());
        // full ACL では PASE は implicit admin(エントリ不要、acl.md §3)。
        let (mut im, mut mgr, ex) = setup_acl_pase(&acl);
        assert_eq!(invoke_on(&mut im, &mut mgr, ex), ImStatus::Success);
        assert!(im.data_model().on_off.is_on());
    }

    /// ワイヤ表現の ACL エントリを書く(subjects のみ、targets null)。
    fn write_entry_fields(
        w: &mut TlvWriter<'_>,
        tag: &TlvTag,
        privilege: u8,
        subject: u64,
    ) -> crate::error::Result<()> {
        w.start_struct(tag)?;
        w.write_u8(&TlvTag::ContextSpecific(1), privilege)?;
        w.write_u8(&TlvTag::ContextSpecific(2), 2)?; // CASE
        w.start_array(&TlvTag::ContextSpecific(3))?;
        w.write_u64(&TlvTag::Anonymous, subject)?;
        w.end_container()?;
        w.write_null(&TlvTag::ContextSpecific(4))?;
        w.end_container()
    }

    /// WriteRequest を送って先頭 status を返す。
    fn do_write(
        im: &mut AclIm<'_>,
        mgr: &mut SessionManager<2>,
        ex: ExchangeId,
        req: &[u8],
    ) -> ImStatus {
        let wh = phdr(ImOpCode::WriteRequest.to_u8());
        let mut tx = [0u8; 256];
        let a = im.handle(&rxm(&wh, req, ex), &mut tx, mgr, 0).unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::WriteResponse.to_u8());
        let wr = WriteResponseRef::new(&tx[..len]).unwrap();
        wr.write_responses()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .status
            .status
    }

    #[test]
    fn acl_crud_via_im_write() {
        let acl = RefCell::new(AclTable::new());
        acl.borrow_mut()
            .add(AclEntry::case_admin(NonZeroU8::new(1).unwrap(), 0x1234))
            .unwrap();
        let (mut im, mut mgr, ex) = setup_acl(&acl);
        let path = AttributePath::concrete(EndpointId(0), ClusterId(0x001F), AttributeId(0x0000));

        // ReplaceAll: [admin(0x1234)](自分の admin を書き直す)。
        let mut req = [0u8; 256];
        let wlen = encode_write_request(&mut req, WriteRequestHeader::default(), |dw| {
            dw.push(None, &path, |vw, t| {
                vw.start_array(t)?;
                write_entry_fields(vw, &TlvTag::Anonymous, 5, 0x1234)?;
                vw.end_container()
            })
        })
        .unwrap();
        assert_eq!(
            do_write(&mut im, &mut mgr, ex, &req[..wlen]),
            ImStatus::Success
        );
        assert_eq!(acl.borrow().len(), 1);

        // Append(ListIndex null): Operate エントリを追記。
        let mut append_path = path;
        append_path.list_append = true;
        let wlen = encode_write_request(&mut req, WriteRequestHeader::default(), |dw| {
            dw.push(None, &append_path, |vw, t| {
                write_entry_fields(vw, t, 3, 0x5678)
            })
        })
        .unwrap();
        assert_eq!(
            do_write(&mut im, &mut mgr, ex, &req[..wlen]),
            ImStatus::Success
        );
        assert_eq!(acl.borrow().len(), 2);

        // 読み戻し(fabricFiltered)で 2 エントリ。
        let mut rreq = [0u8; 64];
        let rlen = encode_read_request(&mut rreq, true, |p| p.push(&path)).unwrap();
        let rh = phdr(ImOpCode::ReadRequest.to_u8());
        let mut tx = [0u8; 512];
        let a = im
            .handle(&rxm(&rh, &rreq[..rlen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        let (_, len, _) = parts(a);
        let rd = ReportDataRef::new(&tx[..len]).unwrap();
        match rd.attr_reports().unwrap().next().unwrap().unwrap() {
            AttributeReportRef::Data(d) => {
                // 配列 → 2 個の構造体。
                let mut r = d.value();
                r.read_next().unwrap();
                let mut structs = 0;
                let mut depth = 1;
                while depth > 0 {
                    let e = r.read_next().unwrap().unwrap();
                    match e.value {
                        TlvValue::ContainerStart(crate::tlv::ContainerType::Structure)
                            if depth == 1 =>
                        {
                            structs += 1;
                            depth += 1;
                        }
                        TlvValue::ContainerStart(_) => depth += 1,
                        TlvValue::ContainerEnd => depth -= 1,
                        _ => {}
                    }
                }
                assert_eq!(structs, 2);
            }
            AttributeReportRef::Status(_) => panic!("expected ACL data"),
        }

        // subject 0x5678(Operate)で新しい CASE セッションを張ると、
        // OnOff invoke は通るが ACL write は UnsupportedAccess。
        let init = SessionInit {
            peer_addr: addr(),
            local_node_id: 1,
            peer_node_id: Some(0x5678),
            peer_session_id: 2,
            tx_ctr_start: 1,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: NonZeroU8::new(1).unwrap(),
            },
            enc_key: [0u8; 16],
            dec_key: [0u8; 16],
            att_challenge: [0u8; 16],
        };
        let sid2 = mgr.insert(init, 0).unwrap();
        let ex2 = ExchangeId::from_parts(sid2, 0x2222);
        let h2 = PayloadHeader {
            exch_id: 0x2222,
            ..phdr(ImOpCode::InvokeRequest.to_u8())
        };
        let mut ireq = [0u8; 64];
        let ilen = encode_invoke_request(&mut ireq, InvokeRequestHeader::default(), |cw| {
            cw.push(
                &CommandPath::new(EndpointId(1), ClusterId(0x0006), CommandId(0x01)),
                None,
                None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
            )
        })
        .unwrap();
        let mut tx2 = [0u8; 128];
        let a = im
            .handle(&rxm(&h2, &ireq[..ilen], ex2), &mut tx2, &mut mgr, 0)
            .unwrap();
        let (_, len2, _) = parts(a);
        let ir = InvokeResponseRef::new(&tx2[..len2]).unwrap();
        match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
            InvokeResponseRefItem::Status(s) => assert_eq!(s.status.status, ImStatus::Success),
            _ => panic!(),
        }

        // ACL write(Administer 必要)は Operate では拒否。
        let wh2 = PayloadHeader {
            exch_id: 0x2222,
            ..phdr(ImOpCode::WriteRequest.to_u8())
        };
        let wlen = encode_write_request(&mut req, WriteRequestHeader::default(), |dw| {
            dw.push(None, &path, |vw, t| {
                vw.start_array(t)?;
                vw.end_container()
            })
        })
        .unwrap();
        let mut tx3 = [0u8; 256];
        let a = im
            .handle(&rxm(&wh2, &req[..wlen], ex2), &mut tx3, &mut mgr, 0)
            .unwrap();
        let (_, len3, _) = parts(a);
        let wr = WriteResponseRef::new(&tx3[..len3]).unwrap();
        assert_eq!(
            wr.write_responses()
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .status
                .status,
            ImStatus::UnsupportedAccess
        );
    }

    #[test]
    fn invoke_effects_bootstrap_admin_and_fabric_removal() {
        let acl = RefCell::new(AclTable::new());
        // PASE(implicit admin)からスタブ 0x00 → bootstrap admin エントリ生成。
        let (mut im, mut mgr, ex) = setup_acl_pase(&acl);
        let mut req = [0u8; 64];
        let ilen = encode_invoke_request(&mut req, InvokeRequestHeader::default(), |cw| {
            cw.push(
                &CommandPath::new(EndpointId(0), ClusterId(0xFC01), CommandId(0x00)),
                None,
                None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
            )
        })
        .unwrap();
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        assert_eq!(acl.borrow().len(), 1);
        let expected = AclEntry::case_admin(NonZeroU8::new(1).unwrap(), 0xCAFE);
        assert_eq!(*acl.borrow().iter().next().unwrap(), expected);

        // スタブ 0x01 → fabric 1 のエントリ連動削除。
        let ilen = encode_invoke_request(&mut req, InvokeRequestHeader::default(), |cw| {
            cw.push(
                &CommandPath::new(EndpointId(0), ClusterId(0xFC01), CommandId(0x01)),
                None,
                None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
            )
        })
        .unwrap();
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 0)
            .unwrap();
        assert_eq!(acl.borrow().len(), 0);
    }
}

// ==========================================================================
// 12. timed 必須コマンドの強制(AdminCommissioning OpenCommissioningWindow)
// ==========================================================================

/// AdminCommissioning クラスタだけを持つ最小デバイス(窓は外部所有 RefCell)。
struct AdminDev<'a> {
    admin: crate::dm::clusters::AdminCommissioningCluster<'a>,
}

impl crate::dm::DataModel for AdminDev<'_> {
    fn endpoints(&self) -> &[crate::dm::meta::EndpointMeta] {
        static DT: &[crate::dm::meta::DeviceType] = &[crate::dm::meta::DeviceType::new(0x0016, 1)];
        static CL: &[ClusterId] = &[ClusterId(0x003C)];
        static EPS: &[crate::dm::meta::EndpointMeta] =
            &[crate::dm::meta::EndpointMeta::new(EndpointId(0), DT, CL)];
        EPS
    }
    fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
        static CL: &[ClusterId] = &[ClusterId(0x003C)];
        if ep.0 == 0 {
            CL
        } else {
            &[]
        }
    }
    fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn crate::dm::ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x003C) => Some(&self.admin),
            _ => None,
        }
    }
    fn cluster_mut(
        &mut self,
        ep: EndpointId,
        cl: ClusterId,
    ) -> Option<&mut dyn crate::dm::ServerCluster> {
        match (ep.0, cl.0) {
            (0, 0x003C) => Some(&mut self.admin),
            _ => None,
        }
    }
}

/// OCW の InvokeRequest を組む(timed フラグは引数)。
fn ocw_request(req: &mut [u8], timed: bool) -> usize {
    encode_invoke_request(
        req,
        InvokeRequestHeader {
            suppress_response: false,
            timed_request: timed,
        },
        |cw| {
            cw.push(
                &CommandPath::new(EndpointId(0), ClusterId(0x003C), CommandId(0x00)),
                None,
                Some(|w: &mut TlvWriter<'_>, t: &TlvTag| {
                    w.start_struct(t)?;
                    w.write_u16(&TlvTag::ContextSpecific(0), 300)?;
                    w.write_bytes(&TlvTag::ContextSpecific(1), &[0xAB; 97])?;
                    w.write_u16(&TlvTag::ContextSpecific(2), 3841)?;
                    w.write_u32(&TlvTag::ContextSpecific(3), 1000)?;
                    w.write_bytes(&TlvTag::ContextSpecific(4), &[0x5A; 16])?;
                    w.end_container()
                }),
            )
        },
    )
    .unwrap()
}

/// InvokeResponse 先頭要素の StatusIB(status, cluster_status)を返す。
fn first_status(msg: &[u8]) -> (ImStatus, Option<u8>) {
    let ir = InvokeResponseRef::new(msg).unwrap();
    match ir.invoke_responses().unwrap().next().unwrap().unwrap() {
        InvokeResponseRefItem::Status(s) => (s.status.status, s.status.cluster_status),
        InvokeResponseRefItem::Command(_) => panic!("OCW returns status only"),
    }
}

#[test]
fn timed_required_command_enforced() {
    use crate::dm::clusters::administrator_commissioning::{status_code, window_status};
    use crate::dm::clusters::{AdminCommissioningCluster, CommissioningWindow};
    use crate::im::wire::TimedRequest;

    let window = core::cell::RefCell::new(CommissioningWindow::new());
    let (_, mut mgr, ex) = setup();
    let mut im: InteractionModel<AdminDev<'_>, 2, 2, 8> = InteractionModel::new(AdminDev {
        admin: AdminCommissioningCluster::new(&window),
    });

    // (a) timed 無しの OCW → NeedsTimedInteraction、窓は閉じたまま。
    let mut req = [0u8; 256];
    let ilen = ocw_request(&mut req, false);
    let ih = phdr(ImOpCode::InvokeRequest.to_u8());
    let mut tx = [0u8; 256];
    let a = im
        .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, _) = parts(a);
    assert_eq!(op, ImOpCode::InvokeResponse.to_u8());
    assert_eq!(
        first_status(&tx[..len]),
        (ImStatus::NeedsTimedInteraction, None)
    );
    assert_eq!(window.borrow().status(), window_status::WINDOW_NOT_OPEN);

    // (b) TimedRequest → timed フラグ付き OCW → Success、ECM 窓が開く。
    let mut treq = [0u8; 16];
    let tlen = TimedRequest::new(10_000).encode(&mut treq).unwrap();
    let th = phdr(ImOpCode::TimedRequest.to_u8());
    let a = im
        .handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, _, is_close) = parts(a);
    assert_eq!(op, ImOpCode::StatusResponse.to_u8());
    assert!(!is_close, "TimedRequest is followed by the Invoke");

    let ilen = ocw_request(&mut req, true);
    let a = im
        .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 100)
        .unwrap();
    let (op, len, _) = parts(a);
    assert_eq!(op, ImOpCode::InvokeResponse.to_u8());
    assert_eq!(first_status(&tx[..len]), (ImStatus::Success, None));
    assert_eq!(
        window.borrow().status(),
        window_status::ENHANCED_WINDOW_OPEN
    );
    assert_eq!(window.borrow().discriminator(), 3841);

    // (c) 窓オープン中の再 OCW(timed 経由)→ Failure + cluster status Busy。
    let a = im
        .handle(&rxm(&th, &treq[..tlen], ex), &mut tx, &mut mgr, 200)
        .unwrap();
    let (op, _, _) = parts(a);
    assert_eq!(op, ImOpCode::StatusResponse.to_u8());
    let ilen = ocw_request(&mut req, true);
    let a = im
        .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 300)
        .unwrap();
    let (_, len, _) = parts(a);
    assert_eq!(
        first_status(&tx[..len]),
        (ImStatus::Failure, Some(status_code::BUSY))
    );
}

// ==========================================================================
// 遅延 InvokeResponse(設計 port-esp32-device.md §E7.4)
// ==========================================================================

mod deferred_invoke {
    use super::*;
    use crate::dm::codec::{AttrEncoder, CmdResponder};
    use crate::dm::meta::{AccessContext, ClusterMeta, CommandMeta, EndpointMeta, Privilege};
    use crate::dm::{DataModel, DeferredPoll, ServerCluster};
    use crate::tlv::TlvReader;

    /// 応答を保留し、`ready`/`fail` で `poll_deferred` の分岐を制御するテストクラスタ(0x1234)。
    struct DeferCluster {
        /// `poll_deferred` が Ready を返すか(false なら Pending)。
        ready: bool,
        /// Ready 時にエラー status を返すか(true=Err(Failure)、false=生成レスポンス 0x02)。
        fail: bool,
    }

    static DEFER_CMDS: &[CommandMeta] =
        &[CommandMeta::new(CommandId(0x01), false, Privilege::Operate)];
    static DEFER_META: ClusterMeta =
        ClusterMeta::new(ClusterId(0x1234), 1, 0, &[], DEFER_CMDS, &[CommandId(0x02)]);

    impl ServerCluster for DeferCluster {
        fn meta(&self) -> &'static ClusterMeta {
            &DEFER_META
        }
        fn read_attribute(
            &self,
            _attr: AttributeId,
            _enc: &mut AttrEncoder<'_, '_>,
            _acc: &AccessContext,
        ) -> Result<(), ImStatus> {
            Err(ImStatus::UnsupportedAttribute)
        }
        fn invoke_command(
            &mut self,
            cmd: CommandId,
            _fields: &mut TlvReader<'_>,
            resp: &mut CmdResponder<'_, '_>,
            _acc: &AccessContext,
        ) -> Result<(), ImStatus> {
            match cmd.0 {
                0x01 => {
                    // 応答を保留する(join 開始に相当)。
                    resp.set_deferred();
                    Ok(())
                }
                _ => Err(ImStatus::UnsupportedCommand),
            }
        }
        fn poll_deferred(
            &mut self,
            _cmd: CommandId,
            resp: &mut CmdResponder<'_, '_>,
        ) -> DeferredPoll {
            if !self.ready {
                return DeferredPoll::Pending;
            }
            if self.fail {
                return DeferredPoll::Ready(Err(ImStatus::Failure));
            }
            // 生成レスポンス 0x02(空の匿名構造体フィールド)。
            resp.set_response(CommandId(0x02));
            let w = resp.writer();
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.end_container().unwrap();
            DeferredPoll::Ready(Ok(()))
        }
    }

    /// EP0 に DeferCluster(0x1234)を 1 個載せた手書き DataModel。
    struct DeferDev {
        dc: DeferCluster,
    }

    static DEFER_EP0: &[ClusterId] = &[ClusterId(0x1234)];

    impl DataModel for DeferDev {
        fn endpoints(&self) -> &[EndpointMeta] {
            static EPS: &[EndpointMeta] = &[EndpointMeta::new(EndpointId(0), &[], DEFER_EP0)];
            EPS
        }
        fn clusters_on(&self, ep: EndpointId) -> &[ClusterId] {
            match ep.0 {
                0 => DEFER_EP0,
                _ => &[],
            }
        }
        fn cluster(&self, ep: EndpointId, cl: ClusterId) -> Option<&dyn ServerCluster> {
            match (ep.0, cl.0) {
                (0, 0x1234) => Some(&self.dc),
                _ => None,
            }
        }
        fn cluster_mut(&mut self, ep: EndpointId, cl: ClusterId) -> Option<&mut dyn ServerCluster> {
            match (ep.0, cl.0) {
                (0, 0x1234) => Some(&mut self.dc),
                _ => None,
            }
        }
    }

    type DeferIm = InteractionModel<DeferDev, 2, 2, 8>;

    fn setup_defer() -> (DeferIm, SessionManager<2>, ExchangeId) {
        let mut mgr: SessionManager<2> = SessionManager::new();
        let init = SessionInit {
            peer_addr: addr(),
            local_node_id: 1,
            peer_node_id: Some(0x1234),
            peer_session_id: 1,
            tx_ctr_start: 1,
            rx_ctr_start: 0,
            mode: SessionMode::Case {
                fabric_idx: NonZeroU8::new(1).unwrap(),
            },
            enc_key: [0u8; 16],
            dec_key: [0u8; 16],
            att_challenge: [0u8; 16],
        };
        let sid = mgr.insert(init, 0).unwrap();
        let ex = ExchangeId::from_parts(sid, EXCH_ID);
        let im = DeferIm::new(DeferDev {
            dc: DeferCluster {
                ready: false,
                fail: false,
            },
        });
        (im, mgr, ex)
    }

    /// DeferCluster のコマンド 0x01 を invoke する InvokeRequest を作る。
    fn defer_request(buf: &mut [u8]) -> usize {
        encode_invoke_request(buf, InvokeRequestHeader::default(), |cw| {
            cw.push(
                &CommandPath::new(EndpointId(0), ClusterId(0x1234), CommandId(0x01)),
                None,
                None::<fn(&mut TlvWriter, &TlvTag) -> crate::error::Result<()>>,
            )
        })
        .unwrap()
    }

    /// InvokeResponse の先頭 item を (is_command, status) で返す(status は Command なら Success)。
    fn first_item(msg: &[u8]) -> (bool, ImStatus, Option<CommandId>) {
        let ir = InvokeResponseRef::new(msg).unwrap();
        let item = ir.invoke_responses().unwrap().next().unwrap().unwrap();
        match item {
            InvokeResponseRefItem::Command(c) => (true, ImStatus::Success, Some(c.path.command)),
            InvokeResponseRefItem::Status(s) => (false, s.status.status, Some(s.path.command)),
        }
    }

    #[test]
    fn deferral_returns_none_and_records_slot() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        // 保留成立: 応答アクション無し。
        let a = im
            .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();
        assert!(matches!(a, HandlerAction::None));
        assert_eq!(im.poll_deferred_invoke(1_000), Some(ex));
    }

    #[test]
    fn deferred_success_builds_generated_response() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();

        // driver 完了相当。build → 生成レスポンス 0x02。
        im.data_model_mut().dc.ready = true;
        let mut rtx = [0u8; 1280];
        let len = im
            .build_deferred_invoke_response(ex, &mut rtx, 1_500)
            .unwrap()
            .expect("ready → response built");
        let (is_cmd, _st, cmd) = first_item(&rtx[..len]);
        assert!(is_cmd, "generated ConnectNetworkResponse-like command");
        assert_eq!(cmd, Some(CommandId(0x02)));
        // スロットはまだ残る(統合層が送信成功後に drop する)。
        assert_eq!(im.poll_deferred_invoke(1_500), Some(ex));
        im.drop_deferred();
        assert_eq!(im.poll_deferred_invoke(1_500), None);
    }

    #[test]
    fn deferred_failure_builds_status() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();

        im.data_model_mut().dc.ready = true;
        im.data_model_mut().dc.fail = true;
        let mut rtx = [0u8; 1280];
        let len = im
            .build_deferred_invoke_response(ex, &mut rtx, 1_500)
            .unwrap()
            .expect("ready → status built");
        let (is_cmd, st, _cmd) = first_item(&rtx[..len]);
        assert!(!is_cmd);
        assert_eq!(st, ImStatus::Failure);
    }

    #[test]
    fn deferred_pending_then_deadline_timeout() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        // now=1000 → deadline=21000。cluster は ready=false(Connecting 相当)。
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();

        let mut rtx = [0u8; 1280];
        // 締切内は None(まだ返さない)。
        assert!(im
            .build_deferred_invoke_response(ex, &mut rtx, 5_000)
            .unwrap()
            .is_none());
        // 締切超過で Timeout status を返す。
        let len = im
            .build_deferred_invoke_response(ex, &mut rtx, 21_001)
            .unwrap()
            .expect("deadline → timeout response");
        let (is_cmd, st, _cmd) = first_item(&rtx[..len]);
        assert!(!is_cmd);
        assert_eq!(st, ImStatus::Timeout);
    }

    #[test]
    fn second_deferral_is_busy() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        // 1 本目: 保留成立。
        let a = im
            .handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();
        assert!(matches!(a, HandlerAction::None));

        // 2 本目(別 exchange): Busy status で即応答。
        let ex2 = ExchangeId::from_parts(ex.session(), 0x2222);
        let mut tx2 = [0u8; 128];
        let a = im
            .handle(&rxm(&ih, &req[..ilen], ex2), &mut tx2, &mut mgr, 1_100)
            .unwrap();
        let (_op, len, is_close) = parts(a);
        assert!(is_close);
        let (is_cmd, st, _cmd) = first_item(&tx2[..len]);
        assert!(!is_cmd);
        assert_eq!(st, ImStatus::Busy);
        // 1 本目のスロットは維持されている。
        assert_eq!(im.poll_deferred_invoke(1_100), Some(ex));
    }

    #[test]
    fn deferred_dropped_when_session_closes() {
        let (mut im, mut mgr, ex) = setup_defer();
        let mut req = [0u8; 64];
        let ilen = defer_request(&mut req);
        let ih = phdr(ImOpCode::InvokeRequest.to_u8());
        let mut tx = [0u8; 128];
        im.handle(&rxm(&ih, &req[..ilen], ex), &mut tx, &mut mgr, 1_000)
            .unwrap();
        assert_eq!(im.poll_deferred_invoke(1_000), Some(ex));

        // 宛先セッションが閉じたらスロット破棄。
        im.on_session_closed(ex.session());
        assert_eq!(im.poll_deferred_invoke(1_000), None);
        // build も NotFound。
        let mut rtx = [0u8; 1280];
        assert!(im
            .build_deferred_invoke_response(ex, &mut rtx, 1_000)
            .is_err());
    }
}

// ==========================================================================
// イベント(StartUp / EventPaths read / eventMin フィルタ、設計 §12)
// ==========================================================================

mod events {
    use super::*;

    /// StartUp イベントを積む(BasicInformation 0x0028 / event 0 / CRITICAL / { 0: sw })。
    fn post_startup(im: &mut Im, sw: u32, now_ms: u64) -> u64 {
        im.post_event(
            EndpointId(0),
            ClusterId(0x0028),
            EventId(0),
            PRIORITY_CRITICAL,
            now_ms,
            |w, tag| {
                w.start_struct(tag)?;
                w.write_u32(&TlvTag::ContextSpecific(0), sw)?;
                w.end_container()
            },
        )
        .unwrap()
    }

    /// EventReports を固定バッファに集めて (number, priority, softwareVersion) の件数を返す。
    fn collect_events(msg: &[u8], out: &mut [(u64, u8, u32)]) -> usize {
        let rd = ReportDataRef::new(msg).unwrap();
        let mut n = 0;
        for r in rd.event_reports().unwrap() {
            match r.unwrap() {
                EventReportRef::Data(d) => {
                    // Data(context 7)= struct { 0: softwareVersion }。
                    let mut v = d.value();
                    // 先頭は struct 開始(context 7)。
                    let e = v.read_next().unwrap().unwrap();
                    assert!(matches!(
                        e.value,
                        TlvValue::ContainerStart(crate::tlv::ContainerType::Structure)
                    ));
                    let sw = v.read_next().unwrap().unwrap().value.as_unsigned().unwrap() as u32;
                    out[n] = (d.number, d.priority, sw);
                    n += 1;
                }
                EventReportRef::Status(_) => panic!("unexpected event status"),
            }
        }
        n
    }

    #[test]
    fn startup_event_read_returns_report() {
        let (mut im, mut mgr, ex) = setup();
        let num = post_startup(&mut im, 0x0001_0000, 100);
        assert_eq!(num, 0);
        assert_eq!(im.events().len(), 1);

        // BasicInformation StartUp を具象パスで read(属性パスなし)。
        let mut req = [0u8; 96];
        let rlen = encode_read_request_events(
            &mut req,
            false,
            |_a| Ok(()),
            |e| {
                e.push(&EventPath::concrete(
                    EndpointId(0),
                    ClusterId(0x0028),
                    EventId(0),
                ))
            },
            None,
        )
        .unwrap();
        let h = phdr(ImOpCode::ReadRequest.to_u8());

        let mut tx = [0u8; 1024];
        let a = im
            .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 200)
            .unwrap();
        let (op, len, is_close) = parts(a);
        assert_eq!(op, ImOpCode::ReportData.to_u8());
        assert!(is_close);

        // 属性レポートは 0 件、イベントレポートは 1 件。
        assert_eq!(count_reports(&tx[..len]), 0);
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let n = collect_events(&tx[..len], &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], (0, PRIORITY_CRITICAL, 0x0001_0000));

        // イベントパスとタイムスタンプの検証。
        let rd = ReportDataRef::new(&tx[..len]).unwrap();
        let d = match rd.event_reports().unwrap().next().unwrap().unwrap() {
            EventReportRef::Data(d) => d,
            _ => panic!(),
        };
        assert_eq!(d.path.endpoint, Some(EndpointId(0)));
        assert_eq!(d.path.cluster, Some(ClusterId(0x0028)));
        assert_eq!(d.path.event, Some(EventId(0)));
        assert_eq!(d.system_timestamp_ms, Some(100));
        assert_eq!(d.epoch_timestamp_ms, None);
    }

    #[test]
    fn wildcard_event_path_matches() {
        let (mut im, mut mgr, ex) = setup();
        post_startup(&mut im, 7, 10);

        // 完全ワイルドカードのイベントパス(全 endpoint/cluster/event)。
        let mut req = [0u8; 64];
        let rlen = encode_read_request_events(
            &mut req,
            false,
            |_a| Ok(()),
            |e| e.push(&EventPath::default()),
            None,
        )
        .unwrap();
        let h = phdr(ImOpCode::ReadRequest.to_u8());
        let mut tx = [0u8; 1024];
        let a = im
            .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 20)
            .unwrap();
        let (_op, len, _close) = parts(a);
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let n = collect_events(&tx[..len], &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0].2, 7);
    }

    #[test]
    fn event_min_filter() {
        let (mut im, mut mgr, ex) = setup();
        // 3 件積む(number 0,1,2)。
        for i in 0..3u32 {
            post_startup(&mut im, i, (i as u64) * 10);
        }

        // eventMin = 1 → number 1,2 のみ。
        let mut req = [0u8; 64];
        let rlen = encode_read_request_events(
            &mut req,
            false,
            |_a| Ok(()),
            |e| e.push(&EventPath::default()),
            Some(1),
        )
        .unwrap();
        let h = phdr(ImOpCode::ReadRequest.to_u8());
        let mut tx = [0u8; 1024];
        let a = im
            .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 100)
            .unwrap();
        let (_op, len, _close) = parts(a);
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let n = collect_events(&tx[..len], &mut buf);
        assert_eq!(n, 2);
        assert_eq!(buf[0].0, 1);
        assert_eq!(buf[1].0, 2);
    }

    #[test]
    fn combined_attr_and_event_read() {
        let (mut im, mut mgr, ex) = setup();
        post_startup(&mut im, 42, 5);

        // On/Off クラスタ全属性 + StartUp イベント。
        let mut req = [0u8; 128];
        let rlen = encode_read_request_events(
            &mut req,
            false,
            |a| a.push(&onoff_cluster_path()),
            |e| {
                e.push(&EventPath::concrete(
                    EndpointId(0),
                    ClusterId(0x0028),
                    EventId(0),
                ))
            },
            None,
        )
        .unwrap();
        let h = phdr(ImOpCode::ReadRequest.to_u8());
        let mut tx = [0u8; 2048];
        let a = im
            .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 10)
            .unwrap();
        let (_op, len, is_close) = parts(a);
        assert!(is_close);
        // 属性(On/Off 固有 1 + global 10 = 11)とイベント 1 件が同一 ReportData に載る。
        assert!(count_reports(&tx[..len]) > 0);
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let n = collect_events(&tx[..len], &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], (0, PRIORITY_CRITICAL, 42));
    }

    /// StartUp イベントパス(BasicInformation 0x0028 / event 0)。
    fn startup_event_path() -> EventPath {
        EventPath::concrete(EndpointId(0), ClusterId(0x0028), EventId(0))
    }

    /// イベント購読のプライミングを完了させ、購読 ID を返す(属性パスとイベントパスを渡す)。
    fn prime_event_sub(
        im: &mut Im,
        mgr: &mut SessionManager<2>,
        ex: ExchangeId,
        attr: &[AttributePath],
        events: &[EventPath],
        now_ms: u64,
    ) -> (u32, usize) {
        let mut req = [0u8; 192];
        let slen = encode_subscribe_request_events(
            &mut req,
            false,
            1,
            10,
            false,
            |w| {
                for p in attr {
                    w.push(p)?;
                }
                Ok(())
            },
            |w| {
                for p in events {
                    w.push(p)?;
                }
                Ok(())
            },
            None,
        )
        .unwrap();
        let sh = phdr(ImOpCode::SubscribeRequest.to_u8());
        let mut tx = [0u8; 2048];
        let a = im
            .handle(&rxm(&sh, &req[..slen], ex), &mut tx, mgr, now_ms)
            .unwrap();
        let (op, len, _close) = parts(a);
        assert_eq!(op, ImOpCode::ReportData.to_u8(), "priming report first");
        // プライミングレポートに載った既存イベント数。
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let primed = collect_events(&tx[..len], &mut buf);

        // StatusResponse(SUCCESS) → SubscribeResponse。
        let stath = phdr(ImOpCode::StatusResponse.to_u8());
        let mut stat = [0u8; 16];
        let stlen = StatusResponse::new(ImStatus::Success)
            .encode(&mut stat)
            .unwrap();
        let mut tx2 = [0u8; 64];
        let a = im
            .handle(&rxm(&stath, &stat[..stlen], ex), &mut tx2, mgr, now_ms)
            .unwrap();
        let (op, len, _close) = parts(a);
        assert_eq!(op, ImOpCode::SubscribeResponse.to_u8());
        let sub_id = SubscribeResponse::decode(&tx2[..len])
            .unwrap()
            .subscription_id;
        (sub_id, primed)
    }

    // (a) EventRequests 付き subscribe → プライミングで既存イベント配信 + floor 記録。
    #[test]
    fn subscribe_event_priming_delivers_existing() {
        let (mut im, mut mgr, ex) = setup();
        post_startup(&mut im, 0xABCD, 5); // number 0

        let (sub_id, primed) =
            prime_event_sub(&mut im, &mut mgr, ex, &[], &[startup_event_path()], 0);
        assert_eq!(primed, 1, "既存 StartUp がプライミングで配信される");
        assert_eq!(im.subscription_count(), 1);

        // floor が記録され、新規イベントが無いので due にならない(max interval まで)。
        assert!(im.poll_subscriptions(2_000).is_none());
        let _ = sub_id;
    }

    // (b) post_event 後の poll_subscriptions で新イベントのみ配信、floor 前進。
    #[test]
    fn subscribe_event_new_event_reported_once() {
        let (mut im, mut mgr, ex) = setup();
        post_startup(&mut im, 1, 5); // number 0(プライミングで配信済み)

        let ex_sub = ExchangeId::from_parts(ex.session(), 0x55);
        let (sub_id, primed) =
            prime_event_sub(&mut im, &mut mgr, ex_sub, &[], &[startup_event_path()], 0);
        assert_eq!(primed, 1);

        // プライミング直後は新規イベント無し → due にならない。
        assert!(im.poll_subscriptions(2_000).is_none());

        // 新しいイベントを積む(number 1)。
        post_startup(&mut im, 2, 100);

        // min interval(1s)経過後、dirty → due。
        let due = im.poll_subscriptions(2_000);
        assert_eq!(
            due,
            Some(SubDue {
                subscription: sub_id,
                session: ex.session()
            })
        );

        // レポート生成: 新規イベント(number 1)のみが載る。
        let ex_rep = ExchangeId::from_parts(ex.session(), 0x66);
        let mut rtx = [0u8; 512];
        let rlen = im.build_report(sub_id, ex_rep, &mut rtx, 2_000).unwrap();
        let mut buf = [(0u64, 0u8, 0u32); 8];
        let n = collect_events(&rtx[..rlen], &mut buf);
        assert_eq!(n, 1, "新規イベントのみ(プライミング済みは再送しない)");
        assert_eq!(buf[0].0, 1, "number 1");
        assert_eq!(buf[0].2, 2, "softwareVersion=2");

        // 配信済み floor 前進 → 再 poll では due にならない。
        assert!(im.poll_subscriptions(2_000).is_none());
    }

    // (c) イベントのみ購読(属性パス 0 本)。
    #[test]
    fn subscribe_event_only_no_attributes() {
        let (mut im, mut mgr, ex) = setup();
        let (sub_id, primed) =
            prime_event_sub(&mut im, &mut mgr, ex, &[], &[startup_event_path()], 0);
        assert_eq!(primed, 0, "イベント未 post なのでプライミングは空");

        post_startup(&mut im, 9, 50); // number 0
        let due = im.poll_subscriptions(2_000);
        assert_eq!(due.map(|d| d.subscription), Some(sub_id));

        let ex_rep = ExchangeId::from_parts(ex.session(), 0x77);
        let mut rtx = [0u8; 512];
        let rlen = im.build_report(sub_id, ex_rep, &mut rtx, 2_000).unwrap();
        // 属性レポート 0 件、イベント 1 件。
        assert_eq!(count_reports(&rtx[..rlen]), 0);
        let mut buf = [(0u64, 0u8, 0u32); 8];
        assert_eq!(collect_events(&rtx[..rlen], &mut buf), 1);
        assert_eq!(buf[0].2, 9);
    }

    // (d) 属性 + イベント混在購読で両方届く。
    #[test]
    fn subscribe_event_and_attribute_both_reported() {
        let (mut im, mut mgr, ex) = setup();
        let (sub_id, _primed) = prime_event_sub(
            &mut im,
            &mut mgr,
            ex,
            &[onoff_cluster_path()],
            &[startup_event_path()],
            0,
        );

        // 属性変化 + 新イベントの両方を起こす。
        im.data_model_mut().on_off.set(true);
        post_startup(&mut im, 3, 100); // number 0

        let due = im.poll_subscriptions(2_000);
        assert_eq!(due.map(|d| d.subscription), Some(sub_id));

        let ex_rep = ExchangeId::from_parts(ex.session(), 0x88);
        let mut rtx = [0u8; 1024];
        let rlen = im.build_report(sub_id, ex_rep, &mut rtx, 2_000).unwrap();
        // 属性(On/Off 固有 + global)とイベント 1 件が同一 ReportData に載る。
        assert!(count_reports(&rtx[..rlen]) > 0, "属性レポートあり");
        let mut buf = [(0u64, 0u8, 0u32); 8];
        assert_eq!(collect_events(&rtx[..rlen], &mut buf), 1, "イベントも載る");
        assert_eq!(buf[0].2, 3);
    }
}

// ==========================================================================
// T8b §16.6: 購読レポートの in-flight タイムアウト / 失敗 StatusResponse
// ==========================================================================

/// 購読を 1 本確立し(OnOff クラスタ、min=1s / max=10s)、購読 ID を返す。
fn establish_subscription(im: &mut Im, mgr: &mut SessionManager<2>, ex: ExchangeId) -> u32 {
    let mut req = [0u8; 64];
    let slen = encode_subscribe_request(&mut req, false, 1, 10, false, |p| {
        p.push(&onoff_cluster_path())
    })
    .unwrap();
    let mut tx = [0u8; 2048];
    let a = im
        .handle(
            &rxm(&phdr(ImOpCode::SubscribeRequest.to_u8()), &req[..slen], ex),
            &mut tx,
            mgr,
            0,
        )
        .unwrap();
    assert_eq!(parts(a).0, ImOpCode::ReportData.to_u8());
    let mut stat = [0u8; 16];
    let stlen = StatusResponse::new(ImStatus::Success)
        .encode(&mut stat)
        .unwrap();
    let mut tx2 = [0u8; 64];
    let a = im
        .handle(
            &rxm(&phdr(ImOpCode::StatusResponse.to_u8()), &stat[..stlen], ex),
            &mut tx2,
            mgr,
            0,
        )
        .unwrap();
    let (op, len, _) = parts(a);
    assert_eq!(op, ImOpCode::SubscribeResponse.to_u8());
    SubscribeResponse::decode(&tx2[..len])
        .unwrap()
        .subscription_id
}

/// (1) 単一チャンクレポートの終端 StatusResponse が来ないまま
/// [`REPORT_INFLIGHT_TIMEOUT_MS`] を超えたら、購読を破棄してその exchange を返す
/// (設計 §16.6 P1。MRP ACK だけ届いた場合は `PollAction::Failed` が上がらないため、
/// この掃引が無いと購読が永久に due せず initiator exchange も 1 本リークする)。
#[test]
fn inflight_report_timeout_drops_subscription_and_returns_exchange() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();
    let sub_id = establish_subscription(&mut im, &mut mgr, ex);

    im.data_model_mut().on_off.set(true);
    assert!(im.poll_subscriptions(2_000).is_some());
    let ex2 = ExchangeId::from_parts(sid, 0x2222);
    let mut rtx = [0u8; 256];
    im.build_report(sub_id, ex2, &mut rtx, 2_000).unwrap();

    // StatusResponse が来ない限り、dirty でも max interval 超過でも due しない(in-flight ガード)。
    im.data_model_mut().on_off.set(false);
    assert!(im.poll_subscriptions(20_000).is_none());
    // 期限前は掃引しない。
    assert!(im
        .expire_stale_reports(2_000 + REPORT_INFLIGHT_TIMEOUT_MS)
        .is_none());
    // 期限超過で購読を破棄し、レポートを運んでいた exchange を返す(統合層が close する)。
    assert_eq!(
        im.expire_stale_reports(2_000 + REPORT_INFLIGHT_TIMEOUT_MS + 1),
        Some(ex2)
    );
    assert_eq!(im.subscription_count(), 0);
    assert_eq!(im.active_read_count(), 0);
    assert!(im
        .expire_stale_reports(2_000 + REPORT_INFLIGHT_TIMEOUT_MS + 1)
        .is_none());
    assert!(im.next_deadline(100_000).is_none());
}

/// (2) 単一チャンクレポートへの StatusResponse が **失敗ステータス**(InvalidSubscription =
/// 相手がこの購読を知らない)なら、購読ごと破棄する(設計 §16.6 P2)。
#[test]
fn failed_status_response_to_report_drops_subscription() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();
    let sub_id = establish_subscription(&mut im, &mut mgr, ex);

    im.data_model_mut().on_off.set(true);
    assert!(im.poll_subscriptions(2_000).is_some());
    let ex2 = ExchangeId::from_parts(sid, 0x2222);
    let mut rtx = [0u8; 256];
    im.build_report(sub_id, ex2, &mut rtx, 2_000).unwrap();
    assert_eq!(im.subscription_count(), 1);

    let mut stat = [0u8; 16];
    let stlen = StatusResponse::new(ImStatus::InvalidSubscription)
        .encode(&mut stat)
        .unwrap();
    let mut tx = [0u8; 64];
    let a = im
        .handle(
            &rxm(&phdr(ImOpCode::StatusResponse.to_u8()), &stat[..stlen], ex2),
            &mut tx,
            &mut mgr,
            2_100,
        )
        .unwrap();
    assert!(
        matches!(a, HandlerAction::CloseSilent),
        "exchange は終端予約して回収する"
    );
    assert_eq!(
        im.subscription_count(),
        0,
        "幽霊購読を残すと 60 秒ごとに無駄レポートを出し SUBS を食い潰す"
    );
    assert!(im.next_deadline(2_100).is_none());
}

// ==========================================================================
// 差分購読レポート(設計 §6.2、実機: Apple Home 2026-09-27)
// ==========================================================================

/// ワイルドカード購読のプライミング(複数チャンク)を完走させ、購読 ID を返す。
fn prime_wildcard_subscription(im: &mut Im, mgr: &mut SessionManager<2>, ex: ExchangeId) -> u32 {
    let mut req = [0u8; 64];
    let slen = encode_subscribe_request(&mut req, false, 1, 10, false, |p| {
        p.push(&AttributePath::default())
    })
    .unwrap();
    let sh = phdr(ImOpCode::SubscribeRequest.to_u8());
    let mut tx = [0u8; 2048];
    let a = im
        .handle(&rxm(&sh, &req[..slen], ex), &mut tx, mgr, 0)
        .unwrap();
    let (op, len, _) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    let mut more = ReportDataRef::new(&tx[..len])
        .unwrap()
        .more_chunks()
        .unwrap();
    let stath = phdr(ImOpCode::StatusResponse.to_u8());
    let mut guard = 0;
    loop {
        guard += 1;
        assert!(guard < 100);
        let mut stat = [0u8; 16];
        let stlen = StatusResponse::new(ImStatus::Success)
            .encode(&mut stat)
            .unwrap();
        let mut tx2 = [0u8; 2048];
        let a = im
            .handle(&rxm(&stath, &stat[..stlen], ex), &mut tx2, mgr, 0)
            .unwrap();
        let (op, len, _) = parts(a);
        if op == ImOpCode::SubscribeResponse.to_u8() {
            assert!(
                !more,
                "SubscribeResponse only after the final priming chunk"
            );
            return SubscribeResponse::decode(&tx2[..len])
                .unwrap()
                .subscription_id;
        }
        assert_eq!(op, ImOpCode::ReportData.to_u8());
        more = ReportDataRef::new(&tx2[..len])
            .unwrap()
            .more_chunks()
            .unwrap();
    }
}

/// レポート内の (cluster, endpoint) 別属性数を数える。
fn count_cluster_reports(buf: &[u8], cluster: u32) -> usize {
    let rd = ReportDataRef::new(buf).unwrap();
    rd.attr_reports()
        .unwrap()
        .filter_map(|r| r.ok())
        .filter(|r| matches!(r, AttributeReportRef::Data(d) if d.path.cluster == Some(ClusterId(cluster))))
        .count()
}

#[test]
fn wildcard_subscription_reports_only_dirty_cluster_then_empty_keepalive() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();
    let sub_id = prime_wildcard_subscription(&mut im, &mut mgr, ex);
    assert_eq!(im.active_read_count(), 0);

    // OnOff だけ変更 → レポートは OnOff クラスタ(ep1)の属性のみで 1 チャンクに収まる。
    im.data_model_mut().on_off.set(true);
    assert_eq!(
        im.poll_subscriptions(2_000),
        Some(SubDue {
            subscription: sub_id,
            session: sid
        })
    );
    let ex2 = ExchangeId::from_parts(sid, 0x2222);
    let mut rtx = [0u8; 2048];
    let rlen = im.build_report(sub_id, ex2, &mut rtx, 2_000).unwrap();
    let rd = ReportDataRef::new(&rtx[..rlen]).unwrap();
    assert!(
        !rd.more_chunks().unwrap(),
        "differential report fits one chunk"
    );
    assert!(
        count_cluster_reports(&rtx[..rlen], 0x0006) >= 1,
        "OnOff attributes present"
    );
    assert_eq!(
        count_cluster_reports(&rtx[..rlen], 0x0028),
        0,
        "untouched BasicInformation omitted"
    );
    assert_eq!(
        count_cluster_reports(&rtx[..rlen], 0x001D),
        0,
        "untouched Descriptor omitted"
    );
    assert_eq!(
        im.active_read_count(),
        0,
        "single-chunk report needs no continuation slot"
    );

    // 終端 StatusResponse で in-flight 解除。
    let stath = phdr(ImOpCode::StatusResponse.to_u8());
    let h2 = PayloadHeader {
        exch_id: 0x2222,
        ..stath
    };
    let mut stat = [0u8; 16];
    let stlen = StatusResponse::new(ImStatus::Success)
        .encode(&mut stat)
        .unwrap();
    let mut tx = [0u8; 64];
    let _ = im
        .handle(&rxm(&h2, &stat[..stlen], ex2), &mut tx, &mut mgr, 2_100)
        .unwrap();

    // 変更なしで max interval 到達 → キープアライブは属性を含まない空レポート。
    assert!(im.poll_subscriptions(5_000).is_none());
    let t = 2_000 + 10_000;
    assert_eq!(
        im.poll_subscriptions(t),
        Some(SubDue {
            subscription: sub_id,
            session: sid
        })
    );
    let ex3 = ExchangeId::from_parts(sid, 0x3333);
    let rlen = im.build_report(sub_id, ex3, &mut rtx, t).unwrap();
    let rd = ReportDataRef::new(&rtx[..rlen]).unwrap();
    assert!(!rd.more_chunks().unwrap());
    assert_eq!(
        rd.attr_reports().unwrap().count(),
        0,
        "keepalive report is empty"
    );
    assert_eq!(rd.subscription_id().unwrap(), Some(sub_id));
}

#[test]
fn subscription_report_waits_while_continuation_slots_are_full() {
    let (mut im, mut mgr, ex) = setup();
    let sid = ex.session();
    let sub_id = prime_wildcard_subscription(&mut im, &mut mgr, ex);

    // 継続 slot(READS=2)を、途中で放置した複数チャンク Read 2 本で埋める。
    for eid in [0x4444u16, 0x5555] {
        let mut req = [0u8; 64];
        let rlen =
            encode_read_request(&mut req, false, |p| p.push(&AttributePath::default())).unwrap();
        let h = PayloadHeader {
            exch_id: eid,
            ..phdr(ImOpCode::ReadRequest.to_u8())
        };
        let exr = ExchangeId::from_parts(sid, eid);
        let mut tx = [0u8; 2048];
        let a = im
            .handle(&rxm(&h, &req[..rlen], exr), &mut tx, &mut mgr, 100)
            .unwrap();
        let (op, len, _) = parts(a);
        assert_eq!(op, ImOpCode::ReportData.to_u8());
        assert!(ReportDataRef::new(&tx[..len])
            .unwrap()
            .more_chunks()
            .unwrap());
    }
    assert_eq!(im.active_read_count(), 2);

    // dirty でも slot 満杯中は due にしない(途中で閉じる不完全なチャンク列を送らない)。
    im.data_model_mut().on_off.set(true);
    assert!(im.poll_subscriptions(2_000).is_none());

    // Read のタイムアウト回収で slot が空けば due になる。
    im.on_tick(100 + 30_001);
    assert_eq!(im.active_read_count(), 0);
    assert_eq!(
        im.poll_subscriptions(31_000),
        Some(SubDue {
            subscription: sub_id,
            session: sid
        })
    );
}
