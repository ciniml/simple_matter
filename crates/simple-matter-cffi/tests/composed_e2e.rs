//! composition モードのホスト E2E(Phase A、`docs/design/generic-firmware.md` §9.1)。
//!
//! 同一プロセスでデバイス側シム(`sm_*`、composition blob で EP1=dimmable light /
//! EP2=温湿度センサに合成)とコントローラ(`sm_ctrl_*`)を初期化し、UDP datagram を
//! メモリ渡しでループバックして
//! **commissioning → read / write / invoke → `on_cluster_change` 発火 →
//! `sm_attr_set_value` の subscribe 反映** までを検証する。
//!
//! デバイス側シムは単一 static インスタンスなので `sm_init` は 1 プロセス 1 回。
//! `src/tests.rs`(composition=NULL の従来構成)と衝突しないよう、本 E2E は
//! **独立した統合テストバイナリ**として置く(プロセス分離 = static 分離)。
//!
//! コントローラ FFI(`sm_ctrl_*`)を使うため `controller` feature 必須(既定で有効)。

#![cfg(feature = "controller")]

use std::alloc::{alloc, dealloc, Layout};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use simple_matter::tlv::{ContainerType, TlvTag, TlvWriter};
use simple_matter_cffi::compose::{CL_HUM, CL_LEVEL, CL_ONOFF, CL_TEMP};
use simple_matter_cffi::controller::*;
use simple_matter_cffi::*;

// ==========================================================================
// テストハーネス
// ==========================================================================

/// `on_cluster_change` が受けた変化(ep, cluster, attr, 値ビット, is_null)。
type Change = (u16, u32, u32, u64, bool);
static CHANGES: Mutex<Vec<Change>> = Mutex::new(Vec::new());

extern "C" fn on_change(
    _ctx: *mut std::ffi::c_void,
    ep: u16,
    cluster: u32,
    attr: u32,
    v: *const sm_attr_value_t,
) {
    // SAFETY: シムが有効な値を渡す契約。
    let v = unsafe { &*v };
    let bits = unsafe { v.v.u };
    CHANGES
        .lock()
        .unwrap()
        .push((ep, cluster, attr, bits, v.is_null));
}

/// 変化通知に (ep, cluster, attr) の記録があるか(値も返す)。
fn change_of(ep: u16, cluster: u32, attr: u32) -> Option<u64> {
    CHANGES
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|c| c.0 == ep && c.1 == cluster && c.2 == attr)
        .map(|c| c.3)
}

extern "C" fn rng_fill(_ctx: *mut std::ffi::c_void, buf: *mut u8, len: usize) {
    // 決定的で十分(暗号強度はテスト対象外。実行ごとに種を変えるため時刻を混ぜる)。
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let s0 = SEED.load(Ordering::Relaxed);
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let mut s = s0 ^ (Instant::now().elapsed().as_nanos() as u64);
    for b in slice.iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *b = (s >> 33) as u8;
    }
    SEED.store(s, Ordering::Relaxed);
}

fn addr(port: u16) -> sm_addr_t {
    let mut a = sm_addr_t {
        ip: [0u8; 16],
        is_v6: false,
        port,
        scope_id: 0,
    };
    a.ip[..4].copy_from_slice(&[127, 0, 0, 1]);
    a
}

fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// composition TLV blob(EP1 = dimmable light、EP2 = 温湿度センサ)。
fn composition(buf: &mut [u8]) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_container(&TlvTag::Anonymous, ContainerType::List)
        .unwrap();
    // EP1: dimmable light(0x0101 rev3)= Identify + Groups + OnOff + LevelControl。
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(0), 1).unwrap();
    w.write_u32(&TlvTag::ContextSpecific(1), 0x0101).unwrap();
    w.write_u8(&TlvTag::ContextSpecific(2), 3).unwrap();
    w.start_container(&TlvTag::ContextSpecific(3), ContainerType::Array)
        .unwrap();
    for id in [0x0003u32, 0x0004, 0x0006, 0x0008] {
        w.write_u32(&TlvTag::Anonymous, id).unwrap();
    }
    w.end_container().unwrap();
    w.end_container().unwrap();
    // EP2: 温湿度センサ(0x0302 rev2)= Temperature + RelativeHumidity(初期温度 23.50℃)。
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.write_u16(&TlvTag::ContextSpecific(0), 2).unwrap();
    w.write_u32(&TlvTag::ContextSpecific(1), 0x0302).unwrap();
    w.write_u8(&TlvTag::ContextSpecific(2), 2).unwrap();
    w.start_container(&TlvTag::ContextSpecific(3), ContainerType::Array)
        .unwrap();
    for id in [0x0402u32, 0x0405] {
        w.write_u32(&TlvTag::Anonymous, id).unwrap();
    }
    w.end_container().unwrap();
    w.start_container(&TlvTag::ContextSpecific(4), ContainerType::Array)
        .unwrap();
    w.start_struct(&TlvTag::Anonymous).unwrap();
    w.write_u32(&TlvTag::ContextSpecific(0), 0x0402).unwrap();
    w.write_u32(&TlvTag::ContextSpecific(1), 0x0000).unwrap();
    w.write_i16(&TlvTag::ContextSpecific(2), 2350).unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.end_container().unwrap();
    w.len()
}

fn null_event() -> sm_ctrl_event_t {
    sm_ctrl_event_t {
        kind: sm_ctrl_event_kind_t::SM_CTRL_EV_NONE,
        phase: 0,
        status: 0,
        node_id: 0,
        value_u64: 0,
        value_is_null: false,
        resumed: false,
    }
}

/// メモリ渡しの UDP ループバック(ble_loopback.cpp の `drain_queue` 相当)。
struct Loopback {
    dev: sm_addr_t,
    ctrl: sm_addr_t,
    queue: Vec<(Vec<u8>, bool)>, // (datagram, to_device)
}

impl Loopback {
    fn new() -> Self {
        Self {
            dev: addr(5540),
            ctrl: addr(55000),
            queue: Vec::new(),
        }
    }

    /// 両側の時間駆動送信を取り出してキューへ積む。
    fn emit(&mut self, now: u64) {
        let mut tx = [0u8; 2048];
        let mut dst = addr(0);
        loop {
            let n = sm_ctrl_poll(now, tx.as_mut_ptr(), tx.len(), &mut dst);
            if n == 0 {
                break;
            }
            self.queue.push((tx[..n].to_vec(), true));
        }
        loop {
            let n = sm_poll(now, tx.as_mut_ptr(), tx.len(), &mut dst);
            if n == 0 {
                break;
            }
            self.queue.push((tx[..n].to_vec(), false));
        }
    }

    /// キューを空になるまで相互配送する(応答は同じキューへ連鎖する)。
    fn drain(&mut self, now: u64) {
        let mut guard = 0;
        while !self.queue.is_empty() && guard < 4000 {
            guard += 1;
            let (mut buf, to_device) = self.queue.remove(0);
            if std::env::var_os("SM_E2E_DEBUG").is_some() {
                eprintln!(
                    "  [dg] -> {} {}B op={:#04x}",
                    if to_device { "dev" } else { "ctrl" },
                    buf.len(),
                    buf.get(1).copied().unwrap_or(0)
                );
            }
            let mut tx = [0u8; 2048];
            let mut dst = addr(0);
            if to_device {
                let n = sm_udp_rx(
                    buf.as_mut_ptr(),
                    buf.len(),
                    &self.ctrl,
                    now,
                    tx.as_mut_ptr(),
                    tx.len(),
                    &mut dst,
                );
                if n > 0 {
                    self.queue.push((tx[..n].to_vec(), false));
                }
            } else {
                let n = sm_ctrl_udp_rx(
                    buf.as_mut_ptr(),
                    buf.len(),
                    &self.dev,
                    now,
                    tx.as_mut_ptr(),
                    tx.len(),
                    &mut dst,
                );
                if n > 0 {
                    self.queue.push((tx[..n].to_vec(), true));
                }
            }
            self.emit(now);
        }
    }

    /// `want` イベントが立つまで(または `fail` / タイムアウトまで)駆動する。
    fn drive_until(
        &mut self,
        want: sm_ctrl_event_kind_t,
        fail: sm_ctrl_event_kind_t,
    ) -> Option<sm_ctrl_event_t> {
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            let now = now_ms();
            self.emit(now);
            self.drain(now);
            let mut ev = null_event();
            while sm_ctrl_take_event(&mut ev) {
                if std::env::var_os("SM_E2E_DEBUG").is_some() {
                    eprintln!(
                        "[ctrl] {:?} status={} phase={}",
                        ev.kind, ev.status, ev.phase
                    );
                }
                if ev.kind == want {
                    return Some(ev);
                }
                if ev.kind == fail {
                    panic!("unexpected {:?} (status={})", ev.kind, ev.status);
                }
            }
            // 次の期限まで実時計で待つ(MRP 再送 / standalone ACK / 購読レポート)。
            let cur = now_ms();
            let nd = sm_ctrl_next_deadline(cur).min(sm_next_deadline(cur));
            let wait = if nd == SM_NO_DEADLINE {
                2
            } else {
                nd.saturating_sub(cur).min(50)
            };
            std::thread::sleep(Duration::from_millis(wait.max(1)));
        }
        None
    }
}

/// 属性 read を 1 往復させて値を返す。
fn read_scalar(lb: &mut Loopback, node: u64, ep: u16, cluster: u32, attr: u32) -> (u64, bool) {
    assert_eq!(
        sm_ctrl_read_scalar(node, ep, cluster, attr, now_ms()),
        0,
        "read start"
    );
    let ev = lb
        .drive_until(
            sm_ctrl_event_kind_t::SM_CTRL_EV_READ_DONE,
            sm_ctrl_event_kind_t::SM_CTRL_EV_READ_FAILED,
        )
        .expect("READ_DONE");
    (ev.value_u64, ev.value_is_null)
}

fn u8v(v: u64) -> sm_attr_value_t {
    let mut x = sm_attr_value_t::zero();
    x.r#type = sm_attr_type_t::SM_T_U8;
    x.v.u = v;
    x
}

fn u16v(v: u64) -> sm_attr_value_t {
    let mut x = sm_attr_value_t::zero();
    x.r#type = sm_attr_type_t::SM_T_U16;
    x.v.u = v;
    x
}

fn i16v(v: i64) -> sm_attr_value_t {
    let mut x = sm_attr_value_t::zero();
    x.r#type = sm_attr_type_t::SM_T_I16;
    x.v.i = v;
    x
}

// ==========================================================================
// E2E
// ==========================================================================

#[test]
fn composed_device_commission_read_write_invoke_subscribe() {
    let node_id: u64 = 0x0000_0000_AABB_CCDD;

    // ---- デバイス: composition モードで初期化 ----
    let mut blob = [0u8; 256];
    let blob_len = composition(&mut blob);
    let cfg = sm_config_t {
        discriminator: 3840,
        passcode: 0,
        vendor_id: 0xFFF1,
        product_id: 0x8001,
        device_name: std::ptr::null(),
        mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x66],
        kvs_get: None,
        kvs_set: None,
        kvs_delete: None,
        kvs_ctx: std::ptr::null_mut(),
        rng_fill: Some(rng_fill),
        rng_ctx: std::ptr::null_mut(),
        network: sm_network_t::SM_NET_ETHERNET,
        verifier_iterations: simple_matter::dev_pase::DEV_ITERATIONS,
        verifier_salt: simple_matter::dev_pase::DEV_SALT.as_ptr(),
        verifier_salt_len: simple_matter::dev_pase::DEV_SALT.len(),
        verifier_w0_l: simple_matter::dev_pase::DEV_W0_L.as_ptr(),
        dac_der: std::ptr::null(),
        dac_der_len: 0,
        pai_der: std::ptr::null(),
        pai_der_len: 0,
        cd_der: std::ptr::null(),
        cd_der_len: 0,
        dac_privkey: std::ptr::null(),
        dac_sign: None,
        dac_sign_ctx: std::ptr::null_mut(),
        composition: blob.as_ptr(),
        composition_len: blob_len,
        on_cluster_change: Some(on_change),
        cluster_change_ctx: std::ptr::null_mut(),
    };
    assert_eq!(sm_init(&cfg, now_ms()), 0, "sm_init(composition)");
    let v4 = [127u8, 0, 0, 1];
    sm_set_addrs(v4.as_ptr(), std::ptr::null());

    // ---- 合成結果の即値確認(汎用値アクセス)----
    let mut out = sm_attr_value_t::zero();
    assert_eq!(sm_attr_get_value(2, CL_TEMP, 0x0000, &mut out), 0);
    assert_eq!(unsafe { out.v.i }, 2350, "options の初期温度");
    assert_eq!(sm_attr_get_value(2, CL_HUM, 0x0000, &mut out), 0);
    assert!(out.is_null, "湿度は初期 null");
    assert_eq!(sm_attr_get_value(1, CL_ONOFF, 0x0000, &mut out), 0);
    assert!(!unsafe { out.v.b });
    // 合成していない EP/クラスタは -2。
    assert_eq!(sm_attr_get_value(3, CL_ONOFF, 0x0000, &mut out), -2);
    assert!(!sm_onoff_get());

    // ---- コントローラ: 供給メモリに初期化 ----
    let size = sm_ctrl_context_size();
    let align = sm_ctrl_context_align();
    let layout = Layout::from_size_align(size, align).unwrap();
    // SAFETY: 非ゼロサイズ・有効なアラインメント。
    let mem = unsafe { alloc(layout) };
    assert!(!mem.is_null());
    let ccfg = sm_ctrl_config_t {
        fabric_id: 0xFAB0_0000_0000_0001,
        controller_node_id: 0x0000_0000_1122_3344,
        vendor_id: 0xFFF1,
        kvs_get: None,
        kvs_set: None,
        kvs_delete: None,
        kvs_ctx: std::ptr::null_mut(),
        rng_fill: Some(rng_fill),
        rng_ctx: std::ptr::null_mut(),
    };
    assert_eq!(sm_ctrl_init(mem, size, &ccfg, now_ms()), 0, "sm_ctrl_init");

    let mut lb = Loopback::new();

    // ---- コミッショニング(UDP PASE → CASE → CommissioningComplete)----
    let dev = addr(5540);
    assert_eq!(sm_ctrl_pair_start(node_id, 20202021, &dev, now_ms()), 0);
    lb.drive_until(
        sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_COMPLETE,
        sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_FAILED,
    )
    .expect("PAIR_COMPLETE");
    assert_eq!(sm_fabric_count(), 1);

    // ---- read: 合成した EP1 OnOff / EP2 温度 ----
    assert_eq!(
        read_scalar(&mut lb, node_id, 1, CL_ONOFF, 0x0000),
        (0, false)
    );
    assert_eq!(
        read_scalar(&mut lb, node_id, 2, CL_TEMP, 0x0000),
        (2350, false),
        "EP2 温度(options 初期値)"
    );
    // Descriptor の自動整合: EP1 の DeviceTypeList は blob 由来(スカラ read では
    // 引けないため、PartsList/ServerList はホスト単体テスト側で担保)。

    // ---- invoke: OnOff Toggle(引数なし)----
    CHANGES.lock().unwrap().clear();
    assert_eq!(sm_ctrl_invoke(node_id, 1, CL_ONOFF, 0x02, now_ms()), 0);
    lb.drive_until(
        sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_DONE,
        sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_FAILED,
    )
    .expect("INVOKE_DONE(Toggle)");
    assert!(sm_onoff_get(), "device 側 OnOff が On");
    assert_eq!(
        read_scalar(&mut lb, node_id, 1, CL_ONOFF, 0x0000),
        (1, false)
    );
    // on_cluster_change が IM コマンド由来の変化で発火する。
    assert_eq!(
        change_of(1, CL_ONOFF, 0x0000),
        Some(1),
        "on_cluster_change(OnOff)"
    );

    // ---- invoke(引数あり): LevelControl MoveToLevel(level=200, time=0)----
    CHANGES.lock().unwrap().clear();
    let args = [u8v(200), u16v(0)];
    assert_eq!(
        sm_ctrl_invoke_args(
            node_id,
            1,
            CL_LEVEL,
            0x0000,
            args.as_ptr(),
            args.len(),
            now_ms()
        ),
        0
    );
    lb.drive_until(
        sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_DONE,
        sm_ctrl_event_kind_t::SM_CTRL_EV_INVOKE_FAILED,
    )
    .expect("INVOKE_DONE(MoveToLevel)");
    assert_eq!(
        read_scalar(&mut lb, node_id, 1, CL_LEVEL, 0x0000),
        (200, false),
        "CurrentLevel"
    );
    assert_eq!(sm_attr_get_value(1, CL_LEVEL, 0x0000, &mut out), 0);
    assert_eq!(unsafe { out.v.u }, 200, "sm_attr_get_value(CurrentLevel)");
    assert_eq!(
        change_of(1, CL_LEVEL, 0x0000),
        Some(200),
        "on_cluster_change(CurrentLevel)"
    );

    // ---- write: LevelControl OnOffTransitionTime = 20(0.1s 単位)----
    let val = u16v(20);
    assert_eq!(
        sm_ctrl_write_scalar(node_id, 1, CL_LEVEL, 0x0010, &val, now_ms()),
        0
    );
    let ev = lb
        .drive_until(
            sm_ctrl_event_kind_t::SM_CTRL_EV_WRITE_DONE,
            sm_ctrl_event_kind_t::SM_CTRL_EV_WRITE_FAILED,
        )
        .expect("WRITE_DONE");
    assert_eq!(ev.status, 0);
    assert_eq!(
        read_scalar(&mut lb, node_id, 1, CL_LEVEL, 0x0010),
        (20, false),
        "write が反映される"
    );

    // ---- subscribe: EP2 温度 → sm_attr_set_value の push がレポートで届く ----
    assert_eq!(
        sm_ctrl_subscribe(node_id, 2, CL_TEMP, 0x0000, 0, 5, now_ms()),
        0
    );
    lb.drive_until(
        sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_DONE,
        sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_FAILED,
    )
    .expect("SUBSCRIBE_DONE");
    CHANGES.lock().unwrap().clear();
    // HAL 相当のセンサ値 push。
    let t = i16v(1234);
    assert_eq!(sm_attr_set_value(2, CL_TEMP, 0x0000, &t), 0);
    assert_eq!(sm_attr_get_value(2, CL_TEMP, 0x0000, &mut out), 0);
    assert_eq!(unsafe { out.v.i }, 1234);
    let rep = lb
        .drive_until(
            sm_ctrl_event_kind_t::SM_CTRL_EV_REPORT,
            sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_FAILED,
        )
        .expect("SM_CTRL_EV_REPORT");
    assert_eq!(rep.value_u64 as i16, 1234, "push した温度が購読で届く");
    // アプリ発の書き込みでは on_cluster_change は鳴らない(HAL ループ防止)。
    assert_eq!(change_of(2, CL_TEMP, 0x0000), None);

    // ---- 湿度 push も同じ経路で読める ----
    let h = u16v(6100);
    assert_eq!(sm_attr_set_value(2, CL_HUM, 0x0000, &h), 0);
    assert_eq!(
        read_scalar(&mut lb, node_id, 2, CL_HUM, 0x0000),
        (6100, false)
    );

    sm_ctrl_deinit();
    // SAFETY: alloc したレイアウトで解放する。
    unsafe { dealloc(mem, layout) };
}
