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
    let cfg = sm_config_t {
        discriminator: 3840,
        passcode: 20202021,
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
}
