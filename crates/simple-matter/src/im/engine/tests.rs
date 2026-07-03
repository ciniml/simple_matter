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
use crate::im::engine::{InteractionModel, SubDue};
use crate::im::wire::{
    encode_invoke_request, encode_read_request, encode_subscribe_request, encode_write_request,
    AttributeId, AttributePath, AttributeReportRef, ClusterId, CommandId, CommandPath, ImOpCode,
    ImStatus, InvokeRequestHeader, InvokeResponseRef, InvokeResponseRefItem, ReportDataRef,
    StatusResponse, SubscribeResponse, WriteRequestHeader, WriteResponseRef,
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
        HandlerAction::None => panic!("expected a response action"),
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

    let mut tx = [0u8; 2048];
    let a = im
        .handle(&rxm(&h, &req[..rlen], ex), &mut tx, &mut mgr, 0)
        .unwrap();
    let (op, len, is_close) = parts(a);
    assert_eq!(op, ImOpCode::ReportData.to_u8());
    assert!(is_close, "single-shot read ends the exchange");

    let rd = ReportDataRef::new(&tx[..len]).unwrap();
    assert!(!rd.more_chunks().unwrap());

    let mut count = 0;
    let mut on_off_seen = false;
    let mut vendor_seen = false;
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
    // ep0: basic(11)+desc(4)=15 固有 +10 global、ep1: on_off(1)+desc(4)=5 固有 +10 global → 40。
    assert_eq!(count, 40);
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
    assert_eq!(total, 40, "all attributes delivered across chunks");
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
    assert_eq!(
        rd.subscription_id().unwrap(),
        None,
        "priming report has no sub id"
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
    assert_eq!(
        im.next_deadline(2_000),
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
