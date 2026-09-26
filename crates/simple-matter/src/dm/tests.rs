//! dm 層のユニットテスト。
//!
//! `cluster!`/`device!` マクロ生成物、3 クラスタの read/write/invoke/dirty、
//! `PathExpandCursor` のワイルドカード展開、グローバル属性の自動応答、`&dyn` 合成を検証する。

use core::num::NonZeroU8;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::dm::clusters::{
    BasicInfoConfig, BasicInformationCluster, DescriptorCluster, LevelControlCluster, OnOffCluster,
};
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{
    AccessContext, AttributeId, ClusterId, CommandId, EndpointId, Privilege, SessionKind,
    ATTR_ACCEPTED_COMMAND_LIST, ATTR_ATTRIBUTE_LIST, ATTR_CLUSTER_REVISION, ATTR_FEATURE_MAP,
    ATTR_GENERATED_COMMAND_LIST,
};
use crate::dm::{read_global_attribute, DataModel, PathExpandCursor, ServerCluster};
use crate::im::wire::{AttributePath, ConcreteAttrPath, ImStatus};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

// ==========================================================================
// テスト用デバイス(2 エンドポイント合成)
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

struct TestDevice {
    basic: BasicInformationCluster,
    desc0: DescriptorCluster,
    on_off: OnOffCluster,
    desc1: DescriptorCluster,
}

crate::device! {
    TestDevice {
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

impl TestDevice {
    fn build() -> Self {
        TestDevice {
            basic: BasicInformationCluster::new(&CFG),
            desc0: DescriptorCluster::new(
                EndpointId(0),
                TestDevice::device_types(EndpointId(0)),
                TestDevice::server_list(EndpointId(0)),
                &[],
                TestDevice::parts(EndpointId(0)),
            ),
            on_off: OnOffCluster::new(),
            desc1: DescriptorCluster::new(
                EndpointId(1),
                TestDevice::device_types(EndpointId(1)),
                TestDevice::server_list(EndpointId(1)),
                &[],
                TestDevice::parts(EndpointId(1)),
            ),
        }
    }
}

// ==========================================================================
// デコードヘルパ
// ==========================================================================

/// 匿名タグの UTF-8 文字列値を `buf` に TLV エンコードする(write テスト用)。
fn encode_str_value(buf: &mut [u8], s: &str) -> usize {
    let mut w = TlvWriter::new(buf);
    w.write_utf8(&TlvTag::Anonymous, s).unwrap();
    w.len()
}

/// `read_attribute` を実行し、書き込み長と結果を返す。
fn read_attr(sc: &dyn ServerCluster, attr: u32, buf: &mut [u8]) -> (usize, Result<(), ImStatus>) {
    let mut w = TlvWriter::new(buf);
    let res = {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        sc.read_attribute(AttributeId(attr), &mut enc, &acc())
    };
    (w.len(), res)
}

/// グローバル属性を導出し、書き込み長を返す。
fn read_global(meta: &crate::dm::meta::ClusterMeta, attr: AttributeId, buf: &mut [u8]) -> usize {
    let mut w = TlvWriter::new(buf);
    {
        let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        read_global_attribute(meta, attr, &mut enc).unwrap();
    }
    w.len()
}

/// 先頭スカラー値を取り出す。
fn scalar(bytes: &[u8]) -> TlvValue<'_> {
    TlvReader::new(bytes).read_next().unwrap().unwrap().value
}

/// 符号なし整数配列をデコードする(要素数を返す)。
fn u_array(bytes: &[u8]) -> ([u64; 32], usize) {
    let mut out = [0u64; 32];
    let mut n = 0;
    let mut r = TlvReader::new(bytes);
    assert_eq!(r.enter_container().unwrap(), ContainerType::Array);
    while let Some(e) = r.read_next().unwrap() {
        match e.value {
            TlvValue::ContainerEnd => break,
            TlvValue::UnsignedInteger(v) => {
                out[n] = v;
                n += 1;
            }
            other => panic!("unexpected element {other:?}"),
        }
    }
    (out, n)
}

fn acc() -> AccessContext {
    AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
}

// ==========================================================================
// 1. cluster! マクロのメタ/dispatch 整合
// ==========================================================================

#[test]
fn macro_meta_matches_read_dispatch() {
    let dev = TestDevice::build();
    // 全 (ep, cluster) について、meta.attributes の各属性が read 可能で、
    // AttributeList(自動導出)が「固有属性 + グローバル属性」と一致することを確認。
    for em in dev.endpoints() {
        for &cl in em.clusters {
            let sc = dev.cluster(em.id, cl).expect("cluster must resolve");
            let meta = sc.meta();
            let mut buf = [0u8; 512];

            // 各固有属性は read 可能(dispatch が存在)。
            for am in meta.attributes {
                let (len, res) = read_attr(sc, am.id.0, &mut buf);
                assert!(res.is_ok(), "attr {:#06x} read failed: {res:?}", am.id.0);
                assert!(len > 0);
            }

            // AttributeList = 固有属性 ID + グローバル属性 ID(昇順)。
            let len = read_global(meta, ATTR_ATTRIBUTE_LIST, &mut buf);
            let (list, n) = u_array(&buf[..len]);
            let own = meta.attributes.len();
            assert_eq!(n, own + 5, "AttributeList length for {:#06x}", cl.0);
            for (i, am) in meta.attributes.iter().enumerate() {
                assert_eq!(list[i], am.id.0 as u64);
            }
            assert_eq!(list[own], 0xFFF8);
            assert_eq!(list[own + 1], 0xFFF9);
            assert_eq!(list[own + 2], 0xFFFB);
            assert_eq!(list[own + 3], 0xFFFC);
            assert_eq!(list[own + 4], 0xFFFD);
        }
    }
}

// ==========================================================================
// 2. On/Off の read / invoke / dirty
// ==========================================================================

static LISTENER_LAST: AtomicBool = AtomicBool::new(false);
static LISTENER_CALLED: AtomicBool = AtomicBool::new(false);

fn on_off_listener(v: bool) {
    LISTENER_CALLED.store(true, Ordering::SeqCst);
    LISTENER_LAST.store(v, Ordering::SeqCst);
}

#[test]
fn on_off_read_invoke_dirty() {
    let mut c = OnOffCluster::new().with_listener(on_off_listener);
    let mut buf = [0u8; 16];

    // 初期状態 false。
    let (_, res) = read_attr(&c, 0x0000, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::Boolean(false));
    assert!(!c.take_dirty());

    // On コマンド → true、dirty、コールバック。
    let a = acc();
    let mut fields = TlvReader::new(&[]);
    let mut respbuf = [0u8; 16];
    let mut w = TlvWriter::new(&mut respbuf);
    let mut resp = crate::dm::codec::CmdResponder::new(&mut w);
    c.invoke_command(CommandId(0x01), &mut fields, &mut resp, &a)
        .unwrap();
    assert!(c.is_on());
    assert!(c.take_dirty());
    assert!(LISTENER_CALLED.load(Ordering::SeqCst));
    assert!(LISTENER_LAST.load(Ordering::SeqCst));

    // dirty はクリア済み(再取得で false)。
    assert!(!c.take_dirty());

    // 同じ On を再送 → 変化なしなので dirty 立たず。
    let mut fields = TlvReader::new(&[]);
    let mut w = TlvWriter::new(&mut respbuf);
    let mut resp = crate::dm::codec::CmdResponder::new(&mut w);
    c.invoke_command(CommandId(0x01), &mut fields, &mut resp, &a)
        .unwrap();
    assert!(!c.take_dirty());

    // Toggle → false、dirty。
    let mut fields = TlvReader::new(&[]);
    let mut w = TlvWriter::new(&mut respbuf);
    let mut resp = crate::dm::codec::CmdResponder::new(&mut w);
    c.invoke_command(CommandId(0x02), &mut fields, &mut resp, &a)
        .unwrap();
    assert!(!c.is_on());
    assert!(c.take_dirty());

    // 未知コマンド。
    let mut fields = TlvReader::new(&[]);
    let mut w = TlvWriter::new(&mut respbuf);
    let mut resp = crate::dm::codec::CmdResponder::new(&mut w);
    let r = c.invoke_command(CommandId(0x99), &mut fields, &mut resp, &a);
    assert_eq!(r, Err(ImStatus::UnsupportedCommand));
}

// ==========================================================================
// 3. Basic Information の read / NodeLabel 書込
// ==========================================================================

#[test]
fn basic_info_read_and_node_label_write() {
    let mut c = BasicInformationCluster::new(&CFG);
    let mut buf = [0u8; 64];

    // VendorName / VendorID。
    let (_, res) = read_attr(&c, 0x0001, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::Utf8String("TestVendor"));
    let (_, res) = read_attr(&c, 0x0002, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::UnsignedInteger(0xFFF1));

    // NodeLabel 初期は空。
    let (_, res) = read_attr(&c, 0x0005, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::Utf8String(""));

    // NodeLabel 書込 → 反映 + dirty。
    let a = acc();
    let mut wbuf = [0u8; 64];
    let n = encode_str_value(&mut wbuf, "Kitchen");
    c.write_attribute(
        AttributeId(0x0005),
        crate::dm::AttrWrite::new(&wbuf[..n]),
        &a,
    )
    .unwrap();
    assert_eq!(c.node_label(), "Kitchen");
    assert!(c.take_dirty());
    let (_, res) = read_attr(&c, 0x0005, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::Utf8String("Kitchen"));

    // 読み取り専用属性への書込は UnsupportedWrite。
    let n = encode_str_value(&mut wbuf, "x");
    let r = c.write_attribute(
        AttributeId(0x0001),
        crate::dm::AttrWrite::new(&wbuf[..n]),
        &a,
    );
    assert_eq!(r, Err(ImStatus::UnsupportedWrite));

    // 長すぎる NodeLabel(> 32)は ConstraintError。
    let long = "0123456789012345678901234567890123"; // 34 文字
    let n = encode_str_value(&mut wbuf, long);
    let r = c.write_attribute(
        AttributeId(0x0005),
        crate::dm::AttrWrite::new(&wbuf[..n]),
        &a,
    );
    assert_eq!(r, Err(ImStatus::ConstraintError));

    // 型不一致の書込は InvalidDataType。
    let mut w = TlvWriter::new(&mut wbuf);
    w.write_u8(&TlvTag::Anonymous, 1).unwrap();
    let n = w.len();
    let r = c.write_attribute(
        AttributeId(0x0005),
        crate::dm::AttrWrite::new(&wbuf[..n]),
        &a,
    );
    assert_eq!(r, Err(ImStatus::InvalidDataType));
}

// ==========================================================================
// 4. Descriptor の自動導出(ServerList / PartsList / DeviceTypeList)
// ==========================================================================

#[test]
fn descriptor_derived_from_composition() {
    let dev = TestDevice::build();
    let mut buf = [0u8; 128];

    let d0 = dev.cluster(EndpointId(0), ClusterId(0x001D)).unwrap();
    // ServerList(0x0001) == clusters_on(ep0)。
    let (len, res) = read_attr(d0, 0x0001, &mut buf);
    res.unwrap();
    let (arr, n) = u_array(&buf[..len]);
    assert_eq!(n, 2);
    assert_eq!(arr[0], 0x0028);
    assert_eq!(arr[1], 0x001D);
    // ServerList は clusters_on(ep0) と一致(単一ソース)。
    let on = dev.clusters_on(EndpointId(0));
    assert_eq!(n, on.len());
    for (i, c) in on.iter().enumerate() {
        assert_eq!(arr[i], c.0 as u64);
    }

    // PartsList(0x0003): ep0 は [1]、ep1 は []。
    let (len, res) = read_attr(d0, 0x0003, &mut buf);
    res.unwrap();
    let (arr, n) = u_array(&buf[..len]);
    assert_eq!(n, 1);
    assert_eq!(arr[0], 1);

    let d1 = dev.cluster(EndpointId(1), ClusterId(0x001D)).unwrap();
    let (len, res) = read_attr(d1, 0x0003, &mut buf);
    res.unwrap();
    let (_, n) = u_array(&buf[..len]);
    assert_eq!(n, 0);

    // DeviceTypeList(0x0000): ep0 は 1 要素 { 0: 0x0016, 1: 1 }。
    let (len, res) = read_attr(d0, 0x0000, &mut buf);
    res.unwrap();
    let mut r = TlvReader::new(&buf[..len]);
    assert_eq!(r.enter_container().unwrap(), ContainerType::Array);
    assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
    let f0 = r.read_next().unwrap().unwrap();
    assert_eq!(f0.tag, TlvTag::ContextSpecific(0));
    assert_eq!(f0.value, TlvValue::UnsignedInteger(0x0016));
    let f1 = r.read_next().unwrap().unwrap();
    assert_eq!(f1.tag, TlvTag::ContextSpecific(1));
    assert_eq!(f1.value, TlvValue::UnsignedInteger(1));
}

// ==========================================================================
// 5. PathExpandCursor のワイルドカード展開
// ==========================================================================

/// カーソルを終端まで回して具象パスを集める。
fn expand_all(dev: &TestDevice, paths: &[AttributePath]) -> ([ConcreteAttrPath; 64], usize) {
    let mut out = [ConcreteAttrPath::new(EndpointId(0), ClusterId(0), AttributeId(0)); 64];
    let mut cur = PathExpandCursor::new();
    let mut n = 0;
    while let Some((p, _meta)) = cur.next(dev, paths) {
        out[n] = p;
        n += 1;
        assert!(n < 64, "expansion overflow");
    }
    (out, n)
}

#[test]
fn expand_full_wildcard() {
    let dev = TestDevice::build();
    // 全端点 × 全クラスタ × 全属性(固有 + グローバル 5)。
    let paths = [AttributePath::default()];
    let (_, n) = expand_all(&dev, &paths);
    // ep0: basic(16+5)+desc(4+5)=30、ep1: on_off(1+5)+desc(4+5)=15 → 45(BasicInformation は
    // Location/UniqueID/CapabilityMinima/SpecificationVersion/MaxPathsPerInvoke を含む 16 属性)。
    assert_eq!(n, 45);
}

#[test]
fn expand_specific_cluster() {
    let dev = TestDevice::build();
    // cluster=OnOff のみ(endpoint/attribute ワイルドカード)。
    let paths = [AttributePath {
        endpoint: None,
        cluster: Some(ClusterId(0x0006)),
        attribute: None,
        list_index: None,
        list_append: false,
        enable_tag_compression: false,
    }];
    let (out, n) = expand_all(&dev, &paths);
    // OnOff は ep1 のみ。固有 1 + グローバル 5 = 6。
    assert_eq!(n, 6);
    for p in &out[..n] {
        assert_eq!(p.endpoint, EndpointId(1));
        assert_eq!(p.cluster, ClusterId(0x0006));
    }
    // 先頭は固有属性 OnOff、末尾はグローバル ClusterRevision。
    assert_eq!(out[0].attribute, AttributeId(0x0000));
    assert_eq!(out[5].attribute, AttributeId(0xFFFD));
}

#[test]
fn expand_concrete_and_nonexistent() {
    let dev = TestDevice::build();

    // 具象で存在するパス → 1 件。
    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        AttributeId(0x0000),
    )];
    let (out, n) = expand_all(&dev, &paths);
    assert_eq!(n, 1);
    assert_eq!(
        out[0],
        ConcreteAttrPath::new(EndpointId(1), ClusterId(0x0006), AttributeId(0x0000))
    );

    // 存在しないエンドポイント → 0 件。
    let paths = [AttributePath {
        endpoint: Some(EndpointId(99)),
        cluster: None,
        attribute: None,
        list_index: None,
        list_append: false,
        enable_tag_compression: false,
    }];
    let (_, n) = expand_all(&dev, &paths);
    assert_eq!(n, 0);

    // 存在しないクラスタ → 0 件。
    let paths = [AttributePath {
        endpoint: Some(EndpointId(0)),
        cluster: Some(ClusterId(0x1234)),
        attribute: None,
        list_index: None,
        list_append: false,
        enable_tag_compression: false,
    }];
    let (_, n) = expand_all(&dev, &paths);
    assert_eq!(n, 0);

    // グローバル属性を具象指定 → 1 件(合成メタ)。
    let paths = [AttributePath::concrete(
        EndpointId(1),
        ClusterId(0x0006),
        ATTR_CLUSTER_REVISION,
    )];
    let (out, n) = expand_all(&dev, &paths);
    assert_eq!(n, 1);
    assert_eq!(out[0].attribute, ATTR_CLUSTER_REVISION);
}

// ==========================================================================
// 6. グローバル属性の自動応答
// ==========================================================================

#[test]
fn global_attributes_auto_derived() {
    let c = OnOffCluster::new();
    let meta = c.meta();
    let mut buf = [0u8; 64];

    // ClusterRevision = 6。
    let len = read_global(meta, ATTR_CLUSTER_REVISION, &mut buf);
    assert_eq!(scalar(&buf[..len]), TlvValue::UnsignedInteger(6));

    // FeatureMap = 0。
    let len = read_global(meta, ATTR_FEATURE_MAP, &mut buf);
    assert_eq!(scalar(&buf[..len]), TlvValue::UnsignedInteger(0));

    // AcceptedCommandList = [0, 1, 2]。
    let len = read_global(meta, ATTR_ACCEPTED_COMMAND_LIST, &mut buf);
    let (arr, n) = u_array(&buf[..len]);
    assert_eq!(n, 3);
    assert_eq!(&arr[..3], &[0, 1, 2]);

    // GeneratedCommandList = []。
    let len = read_global(meta, ATTR_GENERATED_COMMAND_LIST, &mut buf);
    let (_, n) = u_array(&buf[..len]);
    assert_eq!(n, 0);

    // グローバルでない属性は UnsupportedAttribute。
    let mut w = TlvWriter::new(&mut buf);
    let mut enc = AttrEncoder::new(&mut w, TlvTag::Anonymous);
    assert_eq!(
        read_global_attribute(meta, AttributeId(0x0000), &mut enc),
        Err(ImStatus::UnsupportedAttribute)
    );
}

// ==========================================================================
// 7. &dyn 合成での 2 エンドポイントデバイス
// ==========================================================================

#[test]
fn dyn_composition_two_endpoints() {
    let mut dev = TestDevice::build();

    // clusters_on の内容。
    let ep0 = dev.clusters_on(EndpointId(0));
    assert_eq!(ep0, &[ClusterId(0x0028), ClusterId(0x001D)]);
    let ep1 = dev.clusters_on(EndpointId(1));
    assert_eq!(ep1, &[ClusterId(0x0006), ClusterId(0x001D)]);

    // endpoints() の列挙。
    assert_eq!(dev.endpoints().len(), 2);

    // 存在しない (ep, cluster)。
    assert!(dev.cluster(EndpointId(9), ClusterId(0x0006)).is_none());
    assert!(dev.cluster(EndpointId(0), ClusterId(0x0006)).is_none());

    // cluster_mut 経由で OnOff を On にする。
    {
        let sc = dev.cluster_mut(EndpointId(1), ClusterId(0x0006)).unwrap();
        let a = acc();
        let mut fields = TlvReader::new(&[]);
        let mut respbuf = [0u8; 8];
        let mut w = TlvWriter::new(&mut respbuf);
        let mut resp = crate::dm::codec::CmdResponder::new(&mut w);
        sc.invoke_command(CommandId(0x01), &mut fields, &mut resp, &a)
            .unwrap();
    }
    assert!(dev.on_off.is_on());

    // 共有参照で読める。
    let sc = dev.cluster(EndpointId(1), ClusterId(0x0006)).unwrap();
    let mut buf = [0u8; 8];
    let (_, res) = read_attr(sc, 0x0000, &mut buf);
    res.unwrap();
    assert_eq!(scalar(&buf), TlvValue::Boolean(true));
}

// ==========================================================================
// 8. tick_clusters ヘルパ(設計 §15.1)
// ==========================================================================

/// Level Control を 1 個だけ載せた最小デバイス(tick_clusters 検証用)。
struct DimDevice {
    desc: DescriptorCluster,
    level: LevelControlCluster,
}

crate::device! {
    DimDevice {
        endpoint 1 {
            device_types: [ (0x0101, 3) ],
            parts: [],
            clusters: [ (0x001D, desc), (0x0008, level) ],
        }
    }
}

#[test]
fn tick_clusters_drives_level_transition() {
    let mut dev = DimDevice {
        desc: DescriptorCluster::new(
            EndpointId(1),
            DimDevice::device_types(EndpointId(1)),
            DimDevice::server_list(EndpointId(1)),
            &[],
            DimDevice::parts(EndpointId(1)),
        ),
        level: LevelControlCluster::new(),
    };

    // On にして MoveToLevel 201 を 10.0s(transitionTime=100)で開始する。
    dev.level.notify_on_off(true);
    let mut buf = [0u8; 64];
    let n = {
        let mut w = TlvWriter::new(&mut buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        w.write_u8(&TlvTag::ContextSpecific(0), 201).unwrap();
        w.write_u16(&TlvTag::ContextSpecific(1), 100).unwrap();
        w.end_container().unwrap();
        w.len()
    };
    {
        let sc = dev.cluster_mut(EndpointId(1), ClusterId(0x0008)).unwrap();
        let mut fr = TlvReader::new(&buf[..n]);
        let mut respbuf = [0u8; 16];
        let mut rw = TlvWriter::new(&mut respbuf);
        let mut resp = crate::dm::codec::CmdResponder::new(&mut rw);
        let a = AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16]);
        sc.invoke_command(CommandId(0x00), &mut fr, &mut resp, &a)
            .unwrap();
    }
    assert_eq!(dev.level.current_level(), Some(1));

    // tick_clusters を DataModel 経由(on_tick 既定実装)で刻む。返り値は次回時刻あり。
    let next = dev.on_tick(5_000);
    assert!(next.is_some());
    // 5s で中間値 ~101。
    assert_eq!(dev.level.current_level(), Some(101));

    // 完了まで進めると次回時刻は消える(遷移終了)。
    let next = dev.on_tick(10_000);
    assert_eq!(next, None);
    assert_eq!(dev.level.current_level(), Some(201));
}
