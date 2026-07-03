//! `im::wire` codec のテスト。
//!
//! # ワイヤ一致テストの出典
//!
//! `wire_bytes_*` テストの期待バイト列は Matter Core Spec §10(IM メッセージ)/ Appendix A(TLV)
//! の構造を、context タグ番号を参照実装で確認した上で手組みしたもの:
//! - タグ番号: `research/rs-matter/rs-matter/src/im/encoding/*.rs` の `*Tag` enum
//!   (`ReadReqTag`/`ReportDataRespTag`/`InvReqTag`/`AttrPathTag`/`CmdPathTag`/`AttrDataTag` 等)
//! - IB 構造: `research/connectedhomeip/src/app/MessageDef/*.h`
//!
//! 整数は Matter 推奨の最小幅で正規化される(既存 `tlv.rs` と同じ、spec 準拠)。
//! `decode_nonminimal_widths` は、コントローラが非最小幅(u16 等)で送ってきた実ワイヤも
//! 受理できることを確認する(相互運用)。

use super::*;

const REV: u8 = INTERACTION_MODEL_REVISION;

fn ep(n: u16) -> EndpointId {
    EndpointId(n)
}
fn cl(n: u32) -> ClusterId {
    ClusterId(n)
}
fn at(n: u32) -> AttributeId {
    AttributeId(n)
}

// ---------------------------------------------------------------------------
// OpCode / Status
// ---------------------------------------------------------------------------

#[test]
fn opcode_round_trip() {
    for (v, oc) in [
        (0x01, ImOpCode::StatusResponse),
        (0x02, ImOpCode::ReadRequest),
        (0x03, ImOpCode::SubscribeRequest),
        (0x04, ImOpCode::SubscribeResponse),
        (0x05, ImOpCode::ReportData),
        (0x06, ImOpCode::WriteRequest),
        (0x07, ImOpCode::WriteResponse),
        (0x08, ImOpCode::InvokeRequest),
        (0x09, ImOpCode::InvokeResponse),
        (0x0a, ImOpCode::TimedRequest),
    ] {
        assert_eq!(ImOpCode::from_u8(v).unwrap(), oc);
        assert_eq!(oc.to_u8(), v);
    }
    assert_eq!(ImOpCode::from_u8(0x00), Err(Error::Decode));
    assert_eq!(ImOpCode::from_u8(0x0b), Err(Error::Decode));
}

#[test]
fn opcode_transaction_start() {
    assert!(ImOpCode::ReadRequest.is_transaction_start());
    assert!(ImOpCode::InvokeRequest.is_transaction_start());
    assert!(ImOpCode::TimedRequest.is_transaction_start());
    assert!(!ImOpCode::StatusResponse.is_transaction_start());
    assert!(!ImOpCode::ReportData.is_transaction_start());
}

#[test]
fn status_round_trip() {
    for s in [
        ImStatus::Success,
        ImStatus::Failure,
        ImStatus::UnsupportedAttribute,
        ImStatus::UnsupportedCluster,
        ImStatus::Busy,
        ImStatus::NeedsTimedInteraction,
        ImStatus::NoCommandResponse,
    ] {
        assert_eq!(ImStatus::from_u8(s.to_u8()).unwrap(), s);
    }
    assert!(ImStatus::Success.is_success());
    assert!(!ImStatus::Failure.is_success());
    assert_eq!(ImStatus::from_u8(0x42), Err(Error::Decode));
}

// ---------------------------------------------------------------------------
// StatusResponse
// ---------------------------------------------------------------------------

#[test]
fn wire_bytes_status_response() {
    // struct{ 0: u8 status=Success, 0xFF: u8 revision } — rs-matter StatusResp と同一構造。
    let mut buf = [0u8; 32];
    let n = StatusResponse::new(ImStatus::Success)
        .encode(&mut buf)
        .unwrap();
    assert_eq!(&buf[..n], &[0x15, 0x24, 0x00, 0x00, 0x24, 0xFF, REV, 0x18]);
}

#[test]
fn status_response_round_trip() {
    let mut buf = [0u8; 32];
    for s in [ImStatus::Success, ImStatus::Busy, ImStatus::InvalidAction] {
        let n = StatusResponse::new(s).encode(&mut buf).unwrap();
        assert_eq!(StatusResponse::decode(&buf[..n]).unwrap().status, s);
    }
}

// ---------------------------------------------------------------------------
// TimedRequest / SubscribeResponse
// ---------------------------------------------------------------------------

#[test]
fn wire_bytes_timed_request() {
    let mut buf = [0u8; 32];
    let n = TimedRequest::new(1000).encode(&mut buf).unwrap();
    // struct{ 0: u16 1000 (0x03E8 LE), 0xFF: u8 rev }
    assert_eq!(
        &buf[..n],
        &[0x15, 0x25, 0x00, 0xE8, 0x03, 0x24, 0xFF, REV, 0x18]
    );
    assert_eq!(TimedRequest::decode(&buf[..n]).unwrap().timeout_ms, 1000);
}

#[test]
fn subscribe_response_round_trip() {
    let mut buf = [0u8; 32];
    let n = SubscribeResponse::new(0xDEAD_BEEF, 60)
        .encode(&mut buf)
        .unwrap();
    let d = SubscribeResponse::decode(&buf[..n]).unwrap();
    assert_eq!(d.subscription_id, 0xDEAD_BEEF);
    assert_eq!(d.max_interval_s, 60);
}

// ---------------------------------------------------------------------------
// ReadRequest
// ---------------------------------------------------------------------------

#[test]
fn wire_bytes_read_request() {
    let mut buf = [0u8; 64];
    let path = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let n = encode_read_request(&mut buf, false, |p| p.push(&path)).unwrap();
    // struct{ 0: array[ list{ 2:ep1, 3:cl6, 4:attr0 } ], 3: bool false, 0xFF: rev }
    assert_eq!(
        &buf[..n],
        &[
            0x15, // struct
            0x36, 0x00, // array ctx0
            0x17, // list (anon)
            0x24, 0x02, 0x01, // endpoint=1
            0x24, 0x03, 0x06, // cluster=6
            0x24, 0x04, 0x00, // attribute=0
            0x18, // end list
            0x18, // end array
            0x28, 0x03, // fabric_filtered=false
            0x24, 0xFF, REV,  // revision
            0x18, // end struct
        ]
    );
}

#[test]
fn read_request_decode() {
    let mut buf = [0u8; 128];
    let p0 = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let p1 = AttributePath {
        endpoint: None, // ワイルドカード endpoint
        cluster: Some(cl(0x001D)),
        attribute: None, // ワイルドカード attribute
        list_index: None,
        enable_tag_compression: false,
    };
    let n = encode_read_request(&mut buf, true, |p| {
        p.push(&p0)?;
        p.push(&p1)
    })
    .unwrap();

    let req = ReadRequestRef::new(&buf[..n]).unwrap();
    assert!(req.fabric_filtered().unwrap());
    let paths = req.attr_paths().unwrap().collect_paths();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], p0);
    assert_eq!(paths[1], p1);
    assert!(!paths[0].is_wildcard());
    assert!(paths[1].is_wildcard());
}

/// 非最小幅(endpoint を u16、cluster を u32 で符号化)で送られた実ワイヤも受理する。
#[test]
fn decode_nonminimal_widths() {
    // struct{ 0: array[ list{ 2: u16 ep=1, 3: u32 cl=6, 4: u16 attr=0 } ], 3: false }
    let msg = &[
        0x15, 0x36, 0x00, 0x17, //
        0x25, 0x02, 0x01, 0x00, // endpoint u16 = 1
        0x26, 0x03, 0x06, 0x00, 0x00, 0x00, // cluster u32 = 6
        0x25, 0x04, 0x00, 0x00, // attribute u16 = 0
        0x18, 0x18, 0x28, 0x03, 0x18,
    ];
    let req = ReadRequestRef::new(msg).unwrap();
    let mut it = req.attr_paths().unwrap();
    let p = it.next().unwrap().unwrap();
    assert_eq!(p.endpoint, Some(ep(1)));
    assert_eq!(p.cluster, Some(cl(6)));
    assert_eq!(p.attribute, Some(at(0)));
    assert!(it.next().is_none());
}

// ---------------------------------------------------------------------------
// SubscribeRequest
// ---------------------------------------------------------------------------

#[test]
fn subscribe_request_round_trip() {
    let mut buf = [0u8; 128];
    let path = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let n = encode_subscribe_request(&mut buf, false, 1, 60, true, |p| p.push(&path)).unwrap();

    let req = SubscribeRequestRef::new(&buf[..n]).unwrap();
    assert!(!req.keep_existing().unwrap());
    assert_eq!(req.min_interval_floor_s().unwrap(), 1);
    assert_eq!(req.max_interval_ceiling_s().unwrap(), 60);
    assert!(req.fabric_filtered().unwrap());
    let paths = req.attr_paths().unwrap().collect_paths();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], path);
}

// ---------------------------------------------------------------------------
// ReportData
// ---------------------------------------------------------------------------

#[test]
fn wire_bytes_report_data() {
    let mut buf = [0u8; 64];
    let path = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let n = encode_report_data(&mut buf, ReportDataHeader::default(), |rw| {
        rw.push_data(None, &path, |vw, t| vw.write_bool(t, true))
    })
    .unwrap();
    // struct{ 1: array[ struct{ 1: dataIB{ 1: path list, 2: bool true } } ], 0xFF: rev }
    assert_eq!(
        &buf[..n],
        &[
            0x15, // report struct
            0x36, 0x01, // AttributeReports array ctx1
            0x15, // AttributeReportIB struct (anon)
            0x35, 0x01, // AttributeDataIB struct ctx1
            0x37, 0x01, // path list ctx1
            0x24, 0x02, 0x01, // ep=1
            0x24, 0x03, 0x06, // cl=6
            0x24, 0x04, 0x00, // attr=0
            0x18, // end path list
            0x29, 0x02, // data ctx2 = bool true
            0x18, // end AttributeDataIB
            0x18, // end AttributeReportIB
            0x18, // end array
            0x24, 0xFF, REV,  // revision
            0x18, // end report struct
        ]
    );
}

#[test]
fn report_data_decode_data_and_status() {
    let mut buf = [0u8; 128];
    let p0 = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let p1 = AttributePath::concrete(ep(1), cl(0x0006), at(0x4000));
    let n = encode_report_data(&mut buf, ReportDataHeader::default(), |rw| {
        rw.push_data(Some(7), &p0, |vw, t| vw.write_bool(t, true))?;
        rw.push_status(&p1, &StatusIB::simple(ImStatus::UnsupportedAttribute))
    })
    .unwrap();

    let rd = ReportDataRef::new(&buf[..n]).unwrap();
    assert!(rd.subscription_id().unwrap().is_none());
    assert!(!rd.more_chunks().unwrap());

    let mut it = rd.attr_reports().unwrap();
    match it.next().unwrap().unwrap() {
        AttributeReportRef::Data(d) => {
            assert_eq!(d.data_version, Some(7));
            assert_eq!(
                d.path.to_concrete().unwrap(),
                ConcreteAttrPath::new(ep(1), cl(6), at(0))
            );
            // 値スライスを読む(先頭要素タグは context 2)。
            let mut vr = d.value();
            let e = vr.read_next().unwrap().unwrap();
            assert_eq!(e.value, TlvValue::Boolean(true));
        }
        AttributeReportRef::Status(_) => panic!("first should be Data"),
    }
    match it.next().unwrap().unwrap() {
        AttributeReportRef::Status(s) => {
            assert_eq!(s.status.status, ImStatus::UnsupportedAttribute);
            assert_eq!(s.path.attribute, Some(at(0x4000)));
        }
        AttributeReportRef::Data(_) => panic!("second should be Status"),
    }
    assert!(it.next().is_none());
}

#[test]
fn report_data_chunk_flags_round_trip() {
    let mut buf = [0u8; 64];
    let path = AttributePath::concrete(ep(1), cl(0x0006), at(0x0000));
    let header = ReportDataHeader {
        subscription_id: Some(0x1234_5678),
        more_chunks: true,
        suppress_response: false,
    };
    let n = encode_report_data(&mut buf, header, |rw| {
        rw.push_data(None, &path, |vw, t| vw.write_bool(t, false))
    })
    .unwrap();

    let rd = ReportDataRef::new(&buf[..n]).unwrap();
    assert_eq!(rd.subscription_id().unwrap(), Some(0x1234_5678));
    assert!(rd.more_chunks().unwrap());
    assert!(!rd.suppress_response().unwrap());
}

#[test]
fn report_data_transcribe_nested_value() {
    // 値が入れ子 struct のケース。デコードした生スライスを transcribe で別バッファへ転写し、
    // 意味的に一致することを確認する。
    let mut buf = [0u8; 128];
    let path = AttributePath::concrete(ep(1), cl(0x001D), at(0x0000));
    let n = encode_report_data(&mut buf, ReportDataHeader::default(), |rw| {
        rw.push_data(None, &path, |vw, t| {
            vw.start_struct(t)?;
            vw.write_u16(&TlvTag::ContextSpecific(0), 0x0100)?;
            vw.write_u16(&TlvTag::ContextSpecific(1), 3)?;
            vw.end_container()
        })
    })
    .unwrap();

    let rd = ReportDataRef::new(&buf[..n]).unwrap();
    let d = match rd.attr_reports().unwrap().next().unwrap().unwrap() {
        AttributeReportRef::Data(d) => d,
        AttributeReportRef::Status(_) => panic!(),
    };

    // 生スライスを別タグ(anonymous)へ転写。
    let mut out = [0u8; 64];
    let m = {
        let mut w = TlvWriter::new(&mut out);
        transcribe(d.data, &mut w, &TlvTag::Anonymous).unwrap();
        w.len()
    };
    let mut r = TlvReader::new(&out[..m]);
    assert_eq!(
        r.enter_container().unwrap(),
        crate::tlv::ContainerType::Structure
    );
    let f0 = r.read_next().unwrap().unwrap();
    assert_eq!(f0.tag, TlvTag::ContextSpecific(0));
    assert_eq!(f0.value, TlvValue::UnsignedInteger(0x0100));
    let f1 = r.read_next().unwrap().unwrap();
    assert_eq!(f1.tag, TlvTag::ContextSpecific(1));
    assert_eq!(f1.value, TlvValue::UnsignedInteger(3));
}

// ---------------------------------------------------------------------------
// WriteRequest / WriteResponse
// ---------------------------------------------------------------------------

#[test]
fn write_request_round_trip() {
    let mut buf = [0u8; 128];
    let path = AttributePath::concrete(ep(0), cl(0x0028), at(0x0005));
    let header = WriteRequestHeader {
        suppress_response: false,
        timed_request: true,
    };
    let n = encode_write_request(&mut buf, header, |dw| {
        dw.push(None, &path, |vw, t| vw.write_utf8(t, "Kitchen"))
    })
    .unwrap();

    let req = WriteRequestRef::new(&buf[..n]).unwrap();
    assert!(!req.suppress_response().unwrap());
    assert!(req.timed_request().unwrap());
    let mut it = req.write_requests().unwrap();
    let d = it.next().unwrap().unwrap();
    assert_eq!(d.path.attribute, Some(at(0x0005)));
    let mut vr = d.value();
    assert_eq!(
        vr.read_next().unwrap().unwrap().value,
        TlvValue::Utf8String("Kitchen")
    );
    assert!(it.next().is_none());
}

#[test]
fn write_response_round_trip() {
    let mut buf = [0u8; 128];
    let path = AttributePath::concrete(ep(0), cl(0x0028), at(0x0005));
    let n = encode_write_response(&mut buf, |sw| {
        sw.push(&path, &StatusIB::simple(ImStatus::Success))
    })
    .unwrap();

    let resp = WriteResponseRef::new(&buf[..n]).unwrap();
    let mut it = resp.write_responses().unwrap();
    let s = it.next().unwrap().unwrap();
    assert_eq!(s.status.status, ImStatus::Success);
    assert_eq!(s.path.attribute, Some(at(0x0005)));
    assert!(it.next().is_none());
}

// ---------------------------------------------------------------------------
// InvokeRequest / InvokeResponse
// ---------------------------------------------------------------------------

#[test]
fn wire_bytes_invoke_request() {
    let mut buf = [0u8; 64];
    let path = CommandPath::new(ep(1), cl(0x0006), CommandId(0x01)); // On
    let n = encode_invoke_request(&mut buf, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &path,
            None,
            None::<fn(&mut TlvWriter, &TlvTag) -> Result<()>>,
        )
    })
    .unwrap();
    // struct{ 0:false, 1:false, 2: array[ struct{ 0: cmdpath list{0:ep1,1:cl6,2:cmd1} } ], 0xFF }
    assert_eq!(
        &buf[..n],
        &[
            0x15, //
            0x28, 0x00, // suppress=false
            0x28, 0x01, // timed=false
            0x36, 0x02, // InvokeRequests array ctx2
            0x15, // CommandDataIB struct (anon)
            0x37, 0x00, // CommandPath list ctx0
            0x24, 0x00, 0x01, // ep=1
            0x24, 0x01, 0x06, // cl=6
            0x24, 0x02, 0x01, // cmd=1
            0x18, // end path
            0x18, // end CommandDataIB
            0x18, // end array
            0x24, 0xFF, REV, //
            0x18,
        ]
    );
}

#[test]
fn invoke_request_decode_with_fields() {
    let mut buf = [0u8; 128];
    let path = CommandPath::new(ep(1), cl(0x0008), CommandId(0x00)); // MoveToLevel
    let n = encode_invoke_request(&mut buf, InvokeRequestHeader::default(), |cw| {
        cw.push(
            &path,
            Some(9),
            Some(|vw: &mut TlvWriter, t: &TlvTag| {
                vw.start_struct(t)?;
                vw.write_u8(&TlvTag::ContextSpecific(0), 254)?; // Level
                vw.end_container()
            }),
        )
    })
    .unwrap();

    let req = InvokeRequestRef::new(&buf[..n]).unwrap();
    let mut it = req.invoke_requests().unwrap();
    let c = it.next().unwrap().unwrap();
    assert_eq!(c.path, path);
    assert_eq!(c.command_ref, Some(9));
    let fields = c.fields.expect("has fields");
    let mut fr = TlvReader::new(fields);
    // 先頭要素はタグ context 1 の struct。
    assert_eq!(
        fr.enter_container().unwrap(),
        crate::tlv::ContainerType::Structure
    );
    let lvl = fr.read_next().unwrap().unwrap();
    assert_eq!(lvl.value, TlvValue::UnsignedInteger(254));
    assert!(it.next().is_none());
}

#[test]
fn invoke_response_round_trip() {
    let mut buf = [0u8; 128];
    let cmd_path = CommandPath::new(ep(1), cl(0x0006), CommandId(0x04));
    let status_path = CommandPath::new(ep(1), cl(0x0006), CommandId(0x40));
    let n = encode_invoke_response(&mut buf, InvokeResponseHeader::default(), |rw| {
        rw.push_command(&cmd_path, None, |vw, t| {
            vw.start_struct(t)?;
            vw.write_u8(&TlvTag::ContextSpecific(0), 1)?;
            vw.end_container()
        })?;
        rw.push_status(
            &status_path,
            &StatusIB::simple(ImStatus::UnsupportedCommand),
            Some(2),
        )
    })
    .unwrap();

    let resp = InvokeResponseRef::new(&buf[..n]).unwrap();
    assert!(!resp.more_chunks().unwrap());
    let mut it = resp.invoke_responses().unwrap();
    match it.next().unwrap().unwrap() {
        InvokeResponseRefItem::Command(c) => {
            assert_eq!(c.path, cmd_path);
            assert!(c.fields.is_some());
        }
        InvokeResponseRefItem::Status(_) => panic!("first should be Command"),
    }
    match it.next().unwrap().unwrap() {
        InvokeResponseRefItem::Status(s) => {
            assert_eq!(s.path, status_path);
            assert_eq!(s.status.status, ImStatus::UnsupportedCommand);
            assert_eq!(s.command_ref, Some(2));
        }
        InvokeResponseRefItem::Command(_) => panic!("second should be Status"),
    }
    assert!(it.next().is_none());
}

// ---------------------------------------------------------------------------
// パス変換・ワイルドカード
// ---------------------------------------------------------------------------

#[test]
fn path_concrete_conversions() {
    let c = ConcreteAttrPath::new(ep(2), cl(0x0006), at(0x0000));
    let w = c.to_wire();
    assert_eq!(w.to_concrete(), Some(c));
    assert!(!w.is_wildcard());

    // ワイルドカードは to_concrete が None。
    let wild = AttributePath {
        endpoint: None,
        cluster: Some(cl(6)),
        attribute: Some(at(0)),
        list_index: None,
        enable_tag_compression: false,
    };
    assert_eq!(wild.to_concrete(), None);
    assert!(wild.is_wildcard());

    // list_index 付きは具象化しない。
    let indexed = AttributePath {
        list_index: Some(0),
        ..w
    };
    assert_eq!(indexed.to_concrete(), None);
}

#[test]
fn path_matches_wildcard() {
    let target = ConcreteAttrPath::new(ep(1), cl(0x0006), at(0x0000));
    // 全ワイルドカード → 何でもマッチ。
    let all = AttributePath::default();
    assert!(all.matches(target));
    // クラスタ限定。
    let cl_only = AttributePath {
        cluster: Some(cl(0x0006)),
        ..AttributePath::default()
    };
    assert!(cl_only.matches(target));
    let cl_other = AttributePath {
        cluster: Some(cl(0x001D)),
        ..AttributePath::default()
    };
    assert!(!cl_other.matches(target));
    // 具象一致。
    assert!(AttributePath::from_concrete(target).matches(target));
    // 具象不一致。
    assert!(!AttributePath::concrete(ep(2), cl(0x0006), at(0x0000)).matches(target));
}

#[test]
fn status_ib_cluster_status_round_trip() {
    let mut buf = [0u8; 32];
    let ib = StatusIB::new(ImStatus::Failure, Some(0x2A));
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        ib.encode(&mut w, &TlvTag::Anonymous).unwrap();
        w.len()
    };
    let mut r = TlvReader::new(&buf[..n]);
    let decoded = StatusIB::decode(&mut r).unwrap();
    assert_eq!(decoded, ib);
}

// ---------------------------------------------------------------------------
// 不正入力(panic しない・Err を返す)
// ---------------------------------------------------------------------------

#[test]
fn decode_rejects_non_struct_message() {
    // トップレベルが list(struct でない)。
    assert!(ReadRequestRef::new(&[0x17, 0x18]).is_err());
    // 空。
    assert!(ReadRequestRef::new(&[]).is_err());
}

#[test]
fn decode_rejects_truncated() {
    // struct 開始のみ(閉じられていない)で属性配列を辿ると Decode。
    let msg = &[0x15, 0x36, 0x00, 0x17]; // 配列の中の list が閉じない
    let req = ReadRequestRef::new(msg);
    // new は struct 開始のみ検査するので通るが、イテレートで Err。
    if let Ok(req) = req {
        let mut it = req.attr_paths().unwrap();
        assert!(matches!(it.next(), Some(Err(Error::Decode))));
    }
}

#[test]
fn decode_rejects_command_path_wildcard() {
    // CommandPath に endpoint が無い(ワイルドカード)→ Decode。
    // struct{ 0:false, 1:false, 2: array[ struct{ 0: list{ 1:cl6, 2:cmd1 } } ] }
    let msg = &[
        0x15, 0x28, 0x00, 0x28, 0x01, 0x36, 0x02, 0x15, 0x37, 0x00, //
        0x24, 0x01, 0x06, // cluster only
        0x24, 0x02, 0x01, // command only (no endpoint)
        0x18, 0x18, 0x18, 0x18,
    ];
    let req = InvokeRequestRef::new(msg).unwrap();
    let mut it = req.invoke_requests().unwrap();
    assert!(matches!(it.next(), Some(Err(Error::Decode))));
}

#[test]
fn encode_reports_nospace() {
    // バッファが極端に小さいと NoSpace(panic しない)。
    let mut buf = [0u8; 4];
    assert_eq!(
        StatusResponse::new(ImStatus::Success).encode(&mut buf),
        Err(Error::NoSpace)
    );
}

// ---------------------------------------------------------------------------
// テスト補助
// ---------------------------------------------------------------------------

/// 固定容量のパス収集(no_std・no-alloc のままイテレータを検証する)。
struct PathVec {
    items: [AttributePath; 8],
    len: usize,
}
impl PathVec {
    fn len(&self) -> usize {
        self.len
    }
}
impl core::ops::Index<usize> for PathVec {
    type Output = AttributePath;
    fn index(&self, i: usize) -> &AttributePath {
        &self.items[i]
    }
}

trait CollectPaths {
    fn collect_paths(self) -> PathVec;
}
impl<I: Iterator<Item = Result<AttributePath>>> CollectPaths for I {
    fn collect_paths(self) -> PathVec {
        let mut v = PathVec {
            items: [AttributePath::default(); 8],
            len: 0,
        };
        for p in self {
            v.items[v.len] = p.unwrap();
            v.len += 1;
        }
        v
    }
}
