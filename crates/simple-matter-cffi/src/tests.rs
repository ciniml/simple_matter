//! FFI 境界のラウンドトリップ最小テスト(ホスト std ビルドでのみ走る)。
//!
//! 単一 static インスタンスを共有するため、初期化を要するチェックは 1 つの
//! `#[test]` に集約して直列実行する(並列テストによる二重初期化を避ける)。

use super::*;

/// 決定的な擬似乱数(テスト専用。暗号品質は問わない)。
extern "C" fn test_rng(_ctx: *mut c_void, buf: *mut u8, len: usize) {
    use core::sync::atomic::AtomicU64;
    static SEED: AtomicU64 = AtomicU64::new(0x1234_5678_9abc_def1);
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let mut s = SEED.load(Ordering::Relaxed);
    for b in slice.iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
    SEED.store(s, Ordering::Relaxed);
}

#[test]
fn addr_roundtrip_v4_v6() {
    // v4
    let a4 = sm_addr_t {
        ip: {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&[192, 168, 1, 42]);
            b
        },
        is_v6: false,
        port: 5540,
        scope_id: 0,
    };
    let back = peer_to_addr(addr_to_peer(&a4));
    assert!(!back.is_v6);
    assert_eq!(&back.ip[..4], &[192, 168, 1, 42]);
    assert_eq!(back.port, 5540);

    // v6 link-local + scope
    let mut ip6 = [0u8; 16];
    ip6[0] = 0xfe;
    ip6[1] = 0x80;
    ip6[15] = 0x01;
    let a6 = sm_addr_t {
        ip: ip6,
        is_v6: true,
        port: 5353,
        scope_id: 7,
    };
    let back = peer_to_addr(addr_to_peer(&a6));
    assert!(back.is_v6);
    assert_eq!(back.ip, ip6);
    assert_eq!(back.port, 5353);
    assert_eq!(back.scope_id, 7);
}

#[test]
fn event_ring_overflow_drops_oldest() {
    let mut r = EventRing::new();
    for i in 0..(EV_CAP as u8 + 3) {
        r.push(sm_event_kind_t::SM_EV_ONOFF_CHANGED, i);
    }
    // 容量 8: 最古 3 件が落ち、arg は 3..=10 が残る。
    let first = r.pop().unwrap();
    assert_eq!(first.arg, 3);
    let mut last = first;
    while let Some(e) = r.pop() {
        last = e;
    }
    assert_eq!(last.arg, EV_CAP as u8 + 2);
}

#[test]
fn ffi_lifecycle_roundtrip() {
    // デバイスは verifier のみを受け取る(passcode は保持しない)。dev 定数を渡す。
    let cfg = sm_config_t {
        discriminator: 3840,
        // passcode は verifier 指定時は無視される(0 でも動作する)。
        passcode: 0,
        vendor_id: 0xFFF1,
        product_id: 0x8001,
        device_name: core::ptr::null(),
        mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        kvs_get: None,
        kvs_set: None,
        kvs_delete: None,
        kvs_ctx: core::ptr::null_mut(),
        rng_fill: Some(test_rng),
        rng_ctx: core::ptr::null_mut(),
        // ble ビルドでは WiFi 構成(ble_checks が wifi_driver_mut を使う)。no-ble は
        // 種別を無視して Ethernet になる(後方互換)。
        network: sm_network_t::SM_NET_WIFI,
        verifier_iterations: simple_matter::dev_pase::DEV_ITERATIONS,
        verifier_salt: simple_matter::dev_pase::DEV_SALT.as_ptr(),
        verifier_salt_len: simple_matter::dev_pase::DEV_SALT.len(),
        verifier_w0_l: simple_matter::dev_pase::DEV_W0_L.as_ptr(),
        // DAC 未指定 = dev テスト DAC(後方互換)。
        dac_der: core::ptr::null(),
        dac_der_len: 0,
        pai_der: core::ptr::null(),
        pai_der_len: 0,
        cd_der: core::ptr::null(),
        cd_der_len: 0,
        dac_privkey: core::ptr::null(),
        dac_sign: None,
        dac_sign_ctx: core::ptr::null_mut(),
    };
    assert_eq!(sm_init(&cfg, 0), 0);
    // 二重初期化は拒否。
    assert_eq!(sm_init(&cfg, 0), -2);

    assert_eq!(sm_fabric_count(), 0);
    assert!(!sm_onoff_get());

    // ローカル OnOff 書き戻し → 状態 + イベント。
    sm_onoff_set(true, 10);
    assert!(sm_onoff_get());
    let mut ev = sm_event_t {
        kind: sm_event_kind_t::SM_EV_NONE,
        arg: 0,
    };
    assert!(sm_take_event(&mut ev));
    assert!(ev.kind == sm_event_kind_t::SM_EV_ONOFF_CHANGED);
    assert_eq!(ev.arg, 1);
    // リングは空。
    assert!(!sm_take_event(&mut ev));

    sm_onoff_set(false, 20);
    assert!(!sm_onoff_get());
    assert!(sm_take_event(&mut ev));
    assert!(ev.kind == sm_event_kind_t::SM_EV_ONOFF_CHANGED);
    assert_eq!(ev.arg, 0);

    // アドレス反映 → クラッシュしないこと。
    let v4 = [127u8, 0, 0, 1];
    sm_set_addrs(v4.as_ptr(), core::ptr::null());

    // ゴミ datagram を食わせても panic しない(黙って 0 応答)。
    let mut junk = [0xABu8; 64];
    let src = sm_addr_t {
        ip: {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&[127, 0, 0, 1]);
            b
        },
        is_v6: false,
        port: 55555,
        scope_id: 0,
    };
    let mut tx = [0u8; 1600];
    let mut dst = sm_addr_t {
        ip: [0; 16],
        is_v6: false,
        port: 0,
        scope_id: 0,
    };
    let n = sm_udp_rx(
        junk.as_mut_ptr(),
        junk.len(),
        &src,
        30,
        tx.as_mut_ptr(),
        tx.len(),
        &mut dst,
    );
    assert_eq!(n, 0);

    // mDNS 定期 announce は commissionable 広告のため何か返る。
    let n = sm_mdns_poll(40, tx.as_mut_ptr(), tx.len(), &mut dst);
    assert!(n > 0);
    assert!(!dst.is_v6);
    assert_eq!(dst.port, MDNS_PORT);

    // deadline は取得できる(announce 期限があるため NO_DEADLINE 未満)。
    let dl = sm_next_deadline(50);
    assert!(dl < NO_DEADLINE);

    // ---- F4b: sm_init 済みでのカスタム登録拒否(SM_ERR) ----
    let attrs = [custom::sm_attr_def_t {
        attr_id: 0x0000,
        r#type: custom::sm_attr_type_t::SM_T_U16,
        flags: custom::SM_ATTR_WRITABLE,
    }];
    let def = custom::sm_cluster_def_t {
        endpoint: 2,
        cluster_id: 0xFFF1_FC01,
        revision: 1,
        feature_map: 0,
        attrs: attrs.as_ptr(),
        n_attrs: 1,
        cmds: core::ptr::null(),
        n_cmds: 0,
        read: None,
        write: None,
        invoke: None,
        ctx: core::ptr::null_mut(),
    };
    assert_eq!(sm_cluster_register(&def), -2);
    assert_eq!(sm_endpoint_register(2, 0x0100, 1), -2);

    // ---- F3: BLE 給餌(この時点で fabric 0・commissionable。§9)----
    #[cfg(feature = "ble")]
    ble_checks();
}

/// F3 の BLE/WiFi API を初期化済みインスタンス上で検証する
/// (単一 static 共有のため `ffi_lifecycle_roundtrip` 末尾から呼ぶ)。
#[cfg(feature = "ble")]
fn ble_checks() {
    use simple_matter::btp::gatt::ADV_TOTAL_LEN;
    use simple_matter::btp::{Btp, BtpRole};

    // (1) 広告データ生成: commissionable 状態なので Flags+ServiceData 15 バイト。
    let mut adv = [0u8; 64];
    let n = sm_ble_adv_data(adv.as_mut_ptr(), adv.len());
    assert_eq!(n, ADV_TOTAL_LEN);
    assert_eq!(adv[0], 0x02); // Flags AD length
    assert_eq!(adv[4], 0x16); // Service Data - 16bit UUID
    assert_eq!(adv[7], 0x00); // commissionable OpCode
                              // discriminator(下位 12bit)= 3840 が service data に載る。
    let disc = u16::from_le_bytes([adv[8], adv[9]]) & 0x0FFF;
    assert_eq!(disc, 3840);
    // cap 不足は 0 返し。
    assert_eq!(sm_ble_adv_data(adv.as_mut_ptr(), 4), 0);

    // (2) BTP handshake フラグメントラウンドトリップ。
    let mtu: u16 = 247;
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_CONNECTED,
            mtu,
            core::ptr::null(),
            0,
            1000,
        ),
        0
    );
    // 2 本目の接続は拒否(-2)。
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_CONNECTED,
            mtu,
            core::ptr::null(),
            0,
            1000,
        ),
        -2
    );

    // central 側 BTP で handshake request を生成 → C1 write として給餌。
    let mut central = Btp::<6>::new(BtpRole::Central);
    let mut req = [0u8; 32];
    let rlen = central.start_handshake(&mut req, Some(mtu), 1000).unwrap();
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_C1_WRITE,
            0,
            req.as_ptr(),
            rlen,
            1001,
        ),
        0
    );
    // subscribe 前は indicate 不可(handshake resp も保留)。
    let mut frag = [0u8; 64];
    assert_eq!(sm_ble_poll(1002, frag.as_mut_ptr(), frag.len()), 0);

    // subscribe 後に handshake response フラグメントが取り出せる。
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_C2_SUBSCRIBED,
            0,
            core::ptr::null(),
            0,
            1003,
        ),
        0
    );
    let fl = sm_ble_poll(1004, frag.as_mut_ptr(), frag.len());
    assert!(fl > 0, "handshake response fragment expected");
    // central がその応答を取り込むと BTP セッションが確立する。
    central
        .process_incoming(&frag[..fl], Some(mtu), 1005)
        .unwrap();
    assert!(central.is_established(), "central BTP established");

    // 切断でセッションがリセットされ、再接続を受け付ける。
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_DISCONNECTED,
            0,
            core::ptr::null(),
            0,
            1006,
        ),
        0
    );
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_CONNECTED,
            0, // mtu 不明 = 既定 23 扱い
            core::ptr::null(),
            0,
            1007,
        ),
        0
    );
    sm_ble_event(
        sm_ble_event_kind_t::SM_BLE_DISCONNECTED,
        0,
        core::ptr::null(),
        0,
        1008,
    );

    // (3) WiFi request take: 保留がなければ 0。ドライバへ直接 connect を注入して take を確認。
    let mut ssid = [0u8; 32];
    let mut pass = [0u8; 64];
    let mut plen = 0usize;
    assert_eq!(
        sm_take_wifi_request(
            ssid.as_mut_ptr(),
            ssid.len(),
            pass.as_mut_ptr(),
            pass.len(),
            &mut plen,
        ),
        0
    );
    // WifiDriver::connect(コアが ConnectNetwork で呼ぶ経路)を直接叩いて要求を立てる。
    {
        use simple_matter::wifi::WifiDriver;
        // SAFETY: 単線・初期化済み。
        let s = unsafe { shim() };
        s.stack
            .device_mut()
            .net
            .wifi_driver_mut()
            .expect("wifi netcomm")
            .connect(b"iotap", b"hunter2xx");
    }
    let sn = sm_take_wifi_request(
        ssid.as_mut_ptr(),
        ssid.len(),
        pass.as_mut_ptr(),
        pass.len(),
        &mut plen,
    );
    assert_eq!(sn, 5);
    assert_eq!(&ssid[..5], b"iotap");
    assert_eq!(plen, 9);
    assert_eq!(&pass[..9], b"hunter2xx");
    // 取り出し後は保留なし。
    assert_eq!(
        sm_take_wifi_request(
            ssid.as_mut_ptr(),
            ssid.len(),
            pass.as_mut_ptr(),
            pass.len(),
            &mut plen,
        ),
        0
    );
    // 結果報告は panic しない(遅延応答の裏付け)。
    sm_wifi_status(true, 1009);
}

/// ble 無効ビルドでは BLE/WiFi API が SM_ERR(-1)/ 0 を返す(後方互換。§9.2)。
/// `cargo test -p simple-matter-cffi --no-default-features` でのみ走る。
#[cfg(not(feature = "ble"))]
#[test]
fn ble_disabled_returns_sm_err() {
    let mut buf = [0u8; 64];
    let mut plen = 0usize;
    assert_eq!(
        sm_ble_event(
            sm_ble_event_kind_t::SM_BLE_C1_WRITE,
            0,
            core::ptr::null(),
            0,
            0,
        ),
        -1
    );
    assert_eq!(sm_ble_poll(0, buf.as_mut_ptr(), buf.len()), 0);
    assert_eq!(sm_ble_adv_data(buf.as_mut_ptr(), buf.len()), 0);
    assert_eq!(
        sm_take_wifi_request(buf.as_mut_ptr(), 32, buf.as_mut_ptr(), 32, &mut plen),
        0
    );
    sm_wifi_status(true, 0); // no-op(panic しない)
}

// ==========================================================================
// F6: Thread take 方式ドライバ + ShimNetComm ディスパッチ(グローバル状態非依存)
// ==========================================================================

#[cfg(feature = "ble")]
mod thread_shim {
    use super::super::thread_driver::ShimThreadDriver;
    use super::super::{new_netcomm, sm_network_t, ShimNetComm};
    use simple_matter::dm::ServerCluster;
    use simple_matter::thread::{ThreadDriver, ThreadStatus};

    /// OTBR が払い出す実 dataset(先頭に Ext PAN ID = type 0x02, len 8)。
    const DATASET: &[u8] = &[
        0x02, 0x08, 0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43, // Ext PAN ID
        0x03, 0x0f, b'O', b'p', b'e', b'n', b'T', b'h', b'r', b'e', b'a', b'd', b'-', b'2', b'7',
        b'0', b'2', // Network Name
    ];

    /// take 方式の dataset ラウンドトリップ: set_dataset で退避 → connect で pending →
    /// take_dataset で降ろす → set_status で attach 反映。
    #[test]
    fn dataset_take_roundtrip() {
        let mut d = ShimThreadDriver::new();
        assert_eq!(d.status(), ThreadStatus::Idle);
        assert!(!d.has_pending());
        // dataset 投入は Ext PAN ID を返すが pending は立てない(AddOrUpdate 相当)。
        let id = d.set_dataset(DATASET).unwrap();
        assert_eq!(id, [0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43]);
        assert!(!d.has_pending());
        assert!(d.take_dataset().is_none());
        // connect(ConnectNetwork 相当)で attach 要求を立てる。
        d.connect();
        assert_eq!(d.status(), ThreadStatus::Attaching);
        assert!(d.has_pending());
        // take_dataset で dataset TLV をそのまま降ろす(pending クリア、状態は維持)。
        let taken = d.take_dataset().unwrap().to_vec();
        assert_eq!(taken.as_slice(), DATASET);
        assert!(!d.has_pending());
        assert_eq!(d.status(), ThreadStatus::Attaching);
        // 2 度目は None。
        assert!(d.take_dataset().is_none());
        // attach 結果報告。
        d.set_status(true);
        assert_eq!(d.status(), ThreadStatus::Attached);
        d.set_status(false);
        assert!(matches!(d.status(), ThreadStatus::Failed { .. }));
    }

    /// 不正 dataset(Ext PAN ID 無し)は Err で退避しない。
    #[test]
    fn dataset_without_ext_pan_id_rejected() {
        let mut d = ShimThreadDriver::new();
        assert!(d.set_dataset(&[0x03, 0x02, b'h', b'i']).is_err());
    }

    /// network 種別ごとに ShimNetComm のバリアント・FeatureMap・ドライバ有無が対応する。
    #[test]
    fn netcomm_variant_selection() {
        // Ethernet(FeatureMap EN=0x04)。ドライバ無し。
        let mut eth = new_netcomm(sm_network_t::SM_NET_ETHERNET);
        assert_eq!(eth.meta().feature_map, 0x04);
        assert!(eth.wifi_driver_mut().is_none());
        assert!(eth.thread_driver_mut().is_none());
        assert!(!eth.has_pending_wifi());
        assert!(!eth.has_pending_thread());

        // WiFi(FeatureMap WI=0x01)。wifi ドライバのみ。
        let mut wifi = new_netcomm(sm_network_t::SM_NET_WIFI);
        assert_eq!(wifi.meta().feature_map, 0x01);
        assert!(wifi.wifi_driver_mut().is_some());
        assert!(wifi.thread_driver_mut().is_none());

        // Thread(FeatureMap TH=0x02)。thread ドライバのみ。
        let mut thr = new_netcomm(sm_network_t::SM_NET_THREAD);
        assert_eq!(thr.meta().feature_map, 0x02);
        assert!(thr.thread_driver_mut().is_some());
        assert!(thr.wifi_driver_mut().is_none());

        // Thread 構成で connect → has_pending_thread が立つ(SM_EV_THREAD_ATTACH_REQUEST 契機)。
        thr.thread_driver_mut().unwrap().connect();
        assert!(thr.has_pending_thread());
        assert!(!thr.has_pending_wifi());
        // update_from_driver は attach 前は属性を変えないが panic しない。
        thr.update_from_driver();
        if let ShimNetComm::Thread(_) = &thr {
        } else {
            panic!("expected Thread variant");
        }
    }
}

// ==========================================================================
// F4b: カスタムクラスタ(CustomCluster レベルの単体テスト。グローバル状態非依存)
// ==========================================================================

mod custom_cluster {
    use super::super::custom::*;
    use core::ffi::c_void;
    use core::num::NonZeroU8;
    use simple_matter::dm::codec::{AttrEncoder, CmdResponder};
    use simple_matter::dm::meta::{AccessContext, AttributeId, CommandId, Privilege, SessionKind};
    use simple_matter::dm::{AttrWrite, ServerCluster};
    use simple_matter::im::wire::ImStatus;
    use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

    /// C++ 側の値所有を模した状態(ctx 経由で read/write/invoke が触る)。
    #[repr(C)]
    struct CState {
        u16v: u16,
        boolv: bool,
        i16v: Option<i16>,
        last_cmd_a: u8,
        last_cmd_b: u16,
        invoked: bool,
    }

    const A_U16: u32 = 0x0000; // U16 rw
    const A_BOOL: u32 = 0x0001; // BOOL ro
    const A_STR: u32 = 0x0002; // STRING ro
    const A_I16: u32 = 0x0003; // nullable i16 ro
    const C_SET: u32 = 0x0000; // 引数 (u8, u16)

    extern "C" fn cb_read(ctx: *mut c_void, attr_id: u32, out: *mut sm_attr_value_t) -> u8 {
        let s = unsafe { &*(ctx as *const CState) };
        let out = unsafe { &mut *out };
        match attr_id {
            A_U16 => {
                out.r#type = sm_attr_type_t::SM_T_U16;
                out.v.u = s.u16v as u64;
            }
            A_BOOL => {
                out.r#type = sm_attr_type_t::SM_T_BOOL;
                out.v.b = s.boolv;
            }
            A_STR => {
                out.r#type = sm_attr_type_t::SM_T_STRING;
                let bytes = b"hello";
                let mut b = sm_attr_bytes {
                    buf: [0u8; 64],
                    len: bytes.len() as u8,
                };
                b.buf[..bytes.len()].copy_from_slice(bytes);
                out.v.bytes = b;
            }
            A_I16 => {
                out.r#type = sm_attr_type_t::SM_T_I16;
                match s.i16v {
                    Some(v) => out.v.i = v as i64,
                    None => out.is_null = true,
                }
            }
            _ => return ImStatus::UnsupportedAttribute.to_u8(),
        }
        0
    }

    extern "C" fn cb_write(ctx: *mut c_void, attr_id: u32, val: *const sm_attr_value_t) -> u8 {
        let s = unsafe { &mut *(ctx as *mut CState) };
        let val = unsafe { &*val };
        if attr_id == A_U16 {
            s.u16v = unsafe { val.v.u } as u16;
            0
        } else {
            ImStatus::UnsupportedWrite.to_u8()
        }
    }

    extern "C" fn cb_invoke(
        ctx: *mut c_void,
        cmd_id: u32,
        args: *const sm_attr_value_t,
        n_args: usize,
        _now_ms: u64,
    ) -> u8 {
        let s = unsafe { &mut *(ctx as *mut CState) };
        if cmd_id == C_SET && n_args == 2 {
            let a = unsafe { &*args.add(0) };
            let b = unsafe { &*args.add(1) };
            s.last_cmd_a = unsafe { a.v.u } as u8;
            s.last_cmd_b = unsafe { b.v.u } as u16;
            s.invoked = true;
            0
        } else {
            ImStatus::InvalidCommand.to_u8()
        }
    }

    fn build_cluster(state: &mut CState) -> CustomCluster {
        let attrs = [
            sm_attr_def_t {
                attr_id: A_U16,
                r#type: sm_attr_type_t::SM_T_U16,
                flags: SM_ATTR_WRITABLE,
            },
            sm_attr_def_t {
                attr_id: A_BOOL,
                r#type: sm_attr_type_t::SM_T_BOOL,
                flags: 0,
            },
            sm_attr_def_t {
                attr_id: A_STR,
                r#type: sm_attr_type_t::SM_T_STRING,
                flags: 0,
            },
            sm_attr_def_t {
                attr_id: A_I16,
                r#type: sm_attr_type_t::SM_T_I16,
                flags: SM_ATTR_NULLABLE,
            },
        ];
        let cmds = [sm_cmd_def_t {
            cmd_id: C_SET,
            flags: SM_CMD_TIMED,
        }];
        let def = sm_cluster_def_t {
            endpoint: 2,
            cluster_id: 0xFFF1_FC01,
            revision: 3,
            feature_map: 0,
            attrs: attrs.as_ptr(),
            n_attrs: attrs.len(),
            cmds: cmds.as_ptr(),
            n_cmds: cmds.len(),
            read: Some(cb_read),
            write: Some(cb_write),
            invoke: Some(cb_invoke),
            ctx: state as *mut CState as *mut c_void,
        };
        let mut c = unsafe { CustomCluster::from_def(&def) }.expect("from_def");
        // meta 自己参照を確定(単体テストではその場で固定)。
        unsafe { c.finalize() };
        c
    }

    fn acc() -> AccessContext {
        AccessContext::new(
            SessionKind::Case,
            NonZeroU8::new(1),
            0,
            Privilege::Administer,
        )
        .with_env(1234, [0u8; 16])
    }

    fn read_attr(c: &CustomCluster, id: u32, buf: &mut [u8]) -> Result<usize, ImStatus> {
        let mut w = TlvWriter::new(buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(id), &mut e, &acc())?;
        }
        Ok(w.len())
    }

    fn decode_first(buf: &[u8]) -> TlvValue<'_> {
        let mut r = TlvReader::new(buf);
        r.read_next().unwrap().unwrap().value
    }

    #[test]
    fn read_dispatch_all_types() {
        let mut st = CState {
            u16v: 4242,
            boolv: true,
            i16v: Some(-100),
            last_cmd_a: 0,
            last_cmd_b: 0,
            invoked: false,
        };
        let c = build_cluster(&mut st);
        let mut buf = [0u8; 96];

        let n = read_attr(&c, A_U16, &mut buf).unwrap();
        assert_eq!(decode_first(&buf[..n]).as_unsigned().unwrap(), 4242);

        let n = read_attr(&c, A_BOOL, &mut buf).unwrap();
        assert!(decode_first(&buf[..n]).as_bool().unwrap());

        let n = read_attr(&c, A_STR, &mut buf).unwrap();
        assert_eq!(decode_first(&buf[..n]).as_str().unwrap(), "hello");

        let n = read_attr(&c, A_I16, &mut buf).unwrap();
        assert_eq!(decode_first(&buf[..n]).as_signed().unwrap(), -100);

        // 未知属性は UnsupportedAttribute。
        assert_eq!(
            read_attr(&c, 0x00FF, &mut buf),
            Err(ImStatus::UnsupportedAttribute)
        );
    }

    #[test]
    fn nullable_read_null() {
        let mut st = CState {
            u16v: 0,
            boolv: false,
            i16v: None,
            last_cmd_a: 0,
            last_cmd_b: 0,
            invoked: false,
        };
        let c = build_cluster(&mut st);
        let mut buf = [0u8; 16];
        let n = read_attr(&c, A_I16, &mut buf).unwrap();
        assert!(matches!(decode_first(&buf[..n]), TlvValue::Null));
    }

    #[test]
    fn write_dispatch_and_type_mismatch() {
        let mut st = CState {
            u16v: 0,
            boolv: false,
            i16v: None,
            last_cmd_a: 0,
            last_cmd_b: 0,
            invoked: false,
        };
        let mut c = build_cluster(&mut st);

        // 正常な U16 write → C ハンドラに届く + dirty。
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_u16(&TlvTag::Anonymous, 777).unwrap();
        let n = w.len();
        c.write_attribute(AttributeId(A_U16), AttrWrite::new(&buf[..n]), &acc())
            .unwrap();
        assert!(c.take_dirty());
        assert!(!c.take_dirty()); // クリアされる
        assert_eq!(st.u16v, 777);

        // 型不一致(bool を U16 属性へ)→ ConstraintError、C ハンドラ未到達。
        let mut c = build_cluster(&mut st);
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_bool(&TlvTag::Anonymous, true).unwrap();
        let n = w.len();
        assert_eq!(
            c.write_attribute(AttributeId(A_U16), AttrWrite::new(&buf[..n]), &acc()),
            Err(ImStatus::ConstraintError)
        );

        // 幅超過(U16 に 0x1_0000)→ ConstraintError。
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_u32(&TlvTag::Anonymous, 0x1_0000).unwrap();
        let n = w.len();
        assert_eq!(
            c.write_attribute(AttributeId(A_U16), AttrWrite::new(&buf[..n]), &acc()),
            Err(ImStatus::ConstraintError)
        );

        // read-only 属性への write は UnsupportedWrite。
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        w.write_bool(&TlvTag::Anonymous, true).unwrap();
        let n = w.len();
        assert_eq!(
            c.write_attribute(AttributeId(A_BOOL), AttrWrite::new(&buf[..n]), &acc()),
            Err(ImStatus::UnsupportedWrite)
        );
    }

    #[test]
    fn invoke_dispatch_flattens_args() {
        let mut st = CState {
            u16v: 0,
            boolv: false,
            i16v: None,
            last_cmd_a: 0,
            last_cmd_b: 0,
            invoked: false,
        };
        let mut c = build_cluster(&mut st);

        // フィールド構造体 { 0: u8=9, 1: u16=1000 }。
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        w.write_u8(&TlvTag::ContextSpecific(0), 9).unwrap();
        w.write_u16(&TlvTag::ContextSpecific(1), 1000).unwrap();
        w.end_container().unwrap();
        let n = w.len();

        let mut scratch = [0u8; 64];
        let mut sw = TlvWriter::new(&mut scratch);
        let mut resp = CmdResponder::new(&mut sw);
        let mut fr = TlvReader::new(&buf[..n]);
        c.invoke_command(CommandId(C_SET), &mut fr, &mut resp, &acc())
            .unwrap();
        assert!(st.invoked);
        assert_eq!(st.last_cmd_a, 9);
        assert_eq!(st.last_cmd_b, 1000);

        // 未知コマンドは UnsupportedCommand。
        let mut fr = TlvReader::new(&buf[..n]);
        assert_eq!(
            c.invoke_command(CommandId(0x99), &mut fr, &mut resp, &acc()),
            Err(ImStatus::UnsupportedCommand)
        );
    }

    #[test]
    fn meta_synthesis_and_timed_flags() {
        let mut st = CState {
            u16v: 0,
            boolv: false,
            i16v: None,
            last_cmd_a: 0,
            last_cmd_b: 0,
            invoked: false,
        };
        let c = build_cluster(&mut st);
        let meta = c.meta();
        assert_eq!(meta.id.0, 0xFFF1_FC01);
        assert_eq!(meta.revision, 3);
        assert_eq!(meta.attributes.len(), 4);
        assert_eq!(meta.accepted_commands.len(), 1);
        // U16 は writable/Operate、read=View。
        let m = meta.attribute(AttributeId(A_U16)).unwrap();
        assert!(m.writable);
        assert_eq!(m.access, Privilege::View);
        assert_eq!(m.write_access, Privilege::Operate);
        // コマンドは timed 必須(SM_CMD_TIMED)。
        assert!(meta.accepted_commands[0].timed);
    }

    #[test]
    fn from_def_capacity_rejected() {
        // 属性数が上限超過 → Err。
        let attrs = [sm_attr_def_t {
            attr_id: 0,
            r#type: sm_attr_type_t::SM_T_U8,
            flags: 0,
        }; MAX_ATTRS + 1];
        let def = sm_cluster_def_t {
            endpoint: 2,
            cluster_id: 0xFFF1_FC02,
            revision: 1,
            feature_map: 0,
            attrs: attrs.as_ptr(),
            n_attrs: attrs.len(),
            cmds: core::ptr::null(),
            n_cmds: 0,
            read: None,
            write: None,
            invoke: None,
            ctx: core::ptr::null_mut(),
        };
        assert!(unsafe { CustomCluster::from_def(&def) }.is_err());
    }

    #[test]
    fn timed_flag_on_attribute() {
        // SM_ATTR_TIMED を立てた属性は meta.timed=true。
        let attrs = [sm_attr_def_t {
            attr_id: 0x0000,
            r#type: sm_attr_type_t::SM_T_U16,
            flags: SM_ATTR_WRITABLE | SM_ATTR_TIMED,
        }];
        let def = sm_cluster_def_t {
            endpoint: 2,
            cluster_id: 0xFFF1_FC03,
            revision: 1,
            feature_map: 0,
            attrs: attrs.as_ptr(),
            n_attrs: 1,
            cmds: core::ptr::null(),
            n_cmds: 0,
            read: None,
            write: None,
            invoke: None,
            ctx: core::ptr::null_mut(),
        };
        let mut c = unsafe { CustomCluster::from_def(&def) }.unwrap();
        unsafe { c.finalize() };
        assert!(c.meta().attribute(AttributeId(0x0000)).unwrap().timed);
    }
}
