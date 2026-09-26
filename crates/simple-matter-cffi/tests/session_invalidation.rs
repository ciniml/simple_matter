//! 死んだ CASE セッションの無効化(§16.6 P6)の回帰テスト。
//!
//! 背景(AirQ 実機 2026-08-26): デバイスが再起動するとコントローラが握っている CASE
//! セッションは相手側に存在しなくなる。暗号化パケットは黙って捨てられるため応答が来ず、
//! コントローラが**セッションを握り続けたまま**だと以後の全 op がタイムアウトし続けた
//! (Tab5 を再起動するまで復帰しない)。修正は「応答が無かった相手のセッションは捨てて、
//! 次の op で CASE を張り直す」こと。本テストはその 3 経路を回帰として固定する:
//!
//! - (a1) IM トランザクションのタイムアウト(`drive_awaitop` の `Failed{Timeout}`)
//! - (a2) `sm_ctrl_abort_op`(C++ 側の待ちタイムアウトによる中断)
//! - (b)  `SubscriptionLost`(keep-alive 途絶)
//!
//! いずれも「次の op が `SM_CTRL_EV_CASE_ESTABLISHED` から始まる」ことで判定する。
//! セッション無効化が無い実装では CASE を張り直さずに古いセッションで送るため、この
//! イベントが立たず落ちる。
//!
//! ハーネスは `tests/composed_e2e.rs` と同じ「同一プロセスでデバイスシムとコントローラを
//! UDP ループバックさせる」流儀だが、**仮想時計**で駆動する(IM トランザクションの
//! タイムアウトは 30s、購読 keep-alive の猶予は 30s あり、実時計では待てないため)。
//! デバイスシムは単一 static のため本ファイルは独立した統合テストバイナリとして置く。

#![cfg(feature = "controller")]

use std::alloc::{alloc, dealloc, Layout};

use simple_matter::tlv::{ContainerType, TlvTag, TlvWriter};
use simple_matter_cffi::compose::{CL_ONOFF, CL_TEMP};
use simple_matter_cffi::controller::*;
use simple_matter_cffi::*;

// ==========================================================================
// テストハーネス(仮想時計 UDP ループバック)
// ==========================================================================

extern "C" fn rng_fill(_ctx: *mut std::ffi::c_void, buf: *mut u8, len: usize) {
    // 決定的な PRNG(暗号強度はテスト対象外)。
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    // SAFETY: シムは len バイトの有効な buf を渡す。
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let mut s = SEED.load(Ordering::Relaxed);
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

fn null_event() -> sm_ctrl_event_t {
    sm_ctrl_event_t {
        kind: sm_ctrl_event_kind_t::SM_CTRL_EV_NONE,
        phase: 0,
        status: 0,
        node_id: 0,
        value_u64: 0,
        value_is_null: false,
        resumed: false,
        endpoint: 0,
        cluster: 0,
        attribute: 0,
    }
}

/// composition TLV blob(EP1 = dimmable light、EP2 = 温湿度センサ)。
fn composition(buf: &mut [u8]) -> usize {
    let mut w = TlvWriter::new(buf);
    w.start_container(&TlvTag::Anonymous, ContainerType::List)
        .unwrap();
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

/// 仮想時計で駆動するメモリ渡しの UDP ループバック。
///
/// `link_up = false` の間はデバイス宛/コントローラ宛の datagram を捨てる
/// (= デバイスが再起動して無応答になった状態の模擬)。
struct Sim {
    now: u64,
    dev: sm_addr_t,
    ctrl: sm_addr_t,
    queue: Vec<(Vec<u8>, bool)>, // (datagram, to_device)
    link_up: bool,
    events: Vec<sm_ctrl_event_t>,
}

impl Sim {
    fn new() -> Self {
        Self {
            now: 1_000,
            dev: addr(5540),
            ctrl: addr(55000),
            queue: Vec::new(),
            link_up: true,
            events: Vec::new(),
        }
    }

    /// 両側の時間駆動送信をキューへ積む。
    fn emit(&mut self) {
        let mut tx = [0u8; 2048];
        let mut dst = addr(0);
        loop {
            let n = sm_ctrl_poll(self.now, tx.as_mut_ptr(), tx.len(), &mut dst);
            if n == 0 {
                break;
            }
            self.queue.push((tx[..n].to_vec(), true));
        }
        loop {
            let n = sm_poll(self.now, tx.as_mut_ptr(), tx.len(), &mut dst);
            if n == 0 {
                break;
            }
            self.queue.push((tx[..n].to_vec(), false));
        }
    }

    /// キューを空になるまで相互配送する(応答は同じキューへ連鎖する)。
    fn deliver(&mut self) {
        let mut guard = 0;
        while !self.queue.is_empty() && guard < 4000 {
            guard += 1;
            let (mut buf, to_device) = self.queue.remove(0);
            if !self.link_up {
                continue; // リンク断: 黙って捨てる(デバイス再起動時と同じ見え方)。
            }
            let mut tx = [0u8; 2048];
            let mut dst = addr(0);
            let n = if to_device {
                sm_udp_rx(
                    buf.as_mut_ptr(),
                    buf.len(),
                    &self.ctrl,
                    self.now,
                    tx.as_mut_ptr(),
                    tx.len(),
                    &mut dst,
                )
            } else {
                sm_ctrl_udp_rx(
                    buf.as_mut_ptr(),
                    buf.len(),
                    &self.dev,
                    self.now,
                    tx.as_mut_ptr(),
                    tx.len(),
                    &mut dst,
                )
            };
            if n > 0 {
                self.queue.push((tx[..n].to_vec(), !to_device));
            }
            self.emit();
        }
    }

    /// 積まれたコントローライベントを回収する。
    fn collect(&mut self) {
        let mut ev = null_event();
        while sm_ctrl_take_event(&mut ev) {
            if std::env::var_os("SM_E2E_DEBUG").is_some() {
                eprintln!(
                    "[{:>7}] {:?} status={} phase={:#04x} resumed={}",
                    self.now, ev.kind, ev.status, ev.phase, ev.resumed
                );
            }
            self.events.push(ev);
        }
    }

    /// 仮想時計を「次の期限」まで進める(期限が無ければ 100ms 刻み)。
    fn advance(&mut self) {
        let cur = self.now;
        let nd = sm_ctrl_next_deadline(cur).min(sm_next_deadline(cur));
        self.now = if nd == SM_NO_DEADLINE {
            cur + 100
        } else {
            nd.max(cur + 1)
        };
    }

    /// 1 ステップ(送信 → 配送 → イベント回収 → 時計を進める)。
    fn step(&mut self) {
        self.emit();
        self.deliver();
        self.collect();
        self.advance();
    }

    /// `kind` のイベントが立つまで(仮想時間 `budget_ms` を上限に)駆動する。
    fn run_until(&mut self, kind: sm_ctrl_event_kind_t, budget_ms: u64) -> sm_ctrl_event_t {
        let deadline = self.now + budget_ms;
        while self.now < deadline {
            self.step();
            if let Some(e) = self.events.iter().find(|e| e.kind == kind) {
                return *e;
            }
        }
        panic!(
            "timeout waiting for {kind:?} (events so far: {:?})",
            self.kinds()
        );
    }

    /// 収集済みイベントの種別一覧(失敗時の診断用)。
    fn kinds(&self) -> Vec<sm_ctrl_event_kind_t> {
        self.events.iter().map(|e| e.kind).collect()
    }

    fn has(&self, kind: sm_ctrl_event_kind_t) -> bool {
        self.events.iter().any(|e| e.kind == kind)
    }

    /// 収集済みイベントを捨てる(次のシナリオの観測を汚さないため)。
    fn clear_events(&mut self) {
        self.collect();
        self.events.clear();
    }

    /// 仮想時間を `ms` だけ進める(配送も回す)。
    fn idle_for(&mut self, ms: u64) {
        let until = self.now + ms;
        while self.now < until {
            self.emit();
            self.deliver();
            self.collect();
            let cur = self.now;
            let nd = sm_ctrl_next_deadline(cur).min(sm_next_deadline(cur));
            self.now = if nd == SM_NO_DEADLINE {
                (cur + 500).min(until)
            } else {
                nd.max(cur + 1).min(until)
            };
        }
    }

    /// リンク断の間に溜まった datagram を捨ててリンクを復旧する。
    fn link_restore(&mut self) {
        self.queue.clear();
        self.link_up = true;
    }
}

/// 属性 read を 1 往復させて値を返す(成功が前提)。
fn read_ok(sim: &mut Sim, node: u64, ep: u16, cluster: u32, attr: u32) -> u64 {
    assert_eq!(
        sm_ctrl_read_scalar(node, ep, cluster, attr, sim.now),
        0,
        "read start"
    );
    let ev = sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_READ_DONE, 60_000);
    assert!(
        !sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_READ_FAILED),
        "read failed"
    );
    ev.value_u64
}

// ==========================================================================
// 回帰テスト
// ==========================================================================

/// §16.6 P6: タイムアウト / abort / 購読ロストの後、次の op が CASE を張り直すこと。
///
/// 単一 static 契約(デバイスシム・コントローラとも static 1 本)のため、3 シナリオを
/// 1 本のテストに直列で収める(`src/controller.rs` の `mod tests` と同方針)。
#[test]
fn dead_session_is_invalidated_and_case_reestablished() {
    let node_id: u64 = 0x0000_0000_AABB_CCDD;

    // ---- デバイス初期化 ----
    let mut blob = [0u8; 256];
    let blob_len = composition(&mut blob);
    let cfg = sm_config_t {
        discriminator: 3840,
        passcode: 0,
        vendor_id: 0xFFF1,
        product_id: 0x8001,
        device_name: std::ptr::null(),
        mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x77],
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
        on_cluster_change: None,
        cluster_change_ctx: std::ptr::null_mut(),
        report_chunk_limit: 0,
        product_name: core::ptr::null(),
        serial_number: core::ptr::null(),
    };
    let mut sim = Sim::new();
    assert_eq!(sm_init(&cfg, sim.now), 0, "sm_init(composition)");
    let v4 = [127u8, 0, 0, 1];
    sm_set_addrs(v4.as_ptr(), std::ptr::null());

    // ---- コントローラ初期化 ----
    let size = sm_ctrl_context_size();
    let layout = Layout::from_size_align(size, sm_ctrl_context_align()).unwrap();
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
    assert_eq!(sm_ctrl_init(mem, size, &ccfg, sim.now), 0, "sm_ctrl_init");

    // ---- コミッショニング(PASE → CASE → CommissioningComplete)----
    let dev = addr(5540);
    assert_eq!(sm_ctrl_pair_start(node_id, 20202021, &dev, sim.now), 0);
    sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_COMPLETE, 120_000);
    assert!(!sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_PAIR_FAILED));
    assert_eq!(sm_fabric_count(), 1);
    sim.clear_events();

    // 対照: セッションが生きている間は CASE を張り直さない(以降の
    // 「CASE_ESTABLISHED が立つ」判定が常に真になっていないことの担保)。
    // コミッショニングで確立した CASE セッションがそのまま使われる。
    assert_eq!(read_ok(&mut sim, node_id, 1, CL_ONOFF, 0x0000), 0);
    assert!(
        !sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_ESTABLISHED),
        "live セッションがあれば CASE は張り直さない(対照)"
    );
    sim.clear_events();

    // ======================================================================
    // (a1) IM トランザクションのタイムアウト → セッション無効化
    // ======================================================================
    // デバイスを無応答にして read を出す(= デバイス再起動後に死んだセッションへ
    // 送っている状態)。CLIENT_TXN_TIMEOUT_MS(30s)で READ_FAILED(Timeout)。
    sim.link_up = false;
    assert_eq!(
        sm_ctrl_read_scalar(node_id, 1, CL_ONOFF, 0x0000, sim.now),
        0
    );
    let failed = sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_READ_FAILED, 180_000);
    assert_eq!(failed.node_id, node_id);
    assert_eq!(failed.phase, 0xF0, "IM Failed 経路(診断コード)");
    sim.clear_events();

    // デバイス復帰(実機ではここで再起動が完了している)。次の op は **新しい CASE** から
    // 始まらなければならない。セッション無効化が無いと CASE_ESTABLISHED が立たない。
    sim.link_restore();
    assert_eq!(read_ok(&mut sim, node_id, 1, CL_ONOFF, 0x0000), 0);
    assert!(
        sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_ESTABLISHED),
        "Timeout 後の op は CASE を張り直す(§16.6 P6)。events={:?}",
        sim.kinds()
    );
    sim.clear_events();

    // ======================================================================
    // (a2) sm_ctrl_abort_op(C++ 側の待ちタイムアウト)→ セッション無効化
    // ======================================================================
    sim.link_up = false;
    assert_eq!(
        sm_ctrl_read_scalar(node_id, 1, CL_ONOFF, 0x0000, sim.now),
        0
    );
    // リクエストを 1 発送出させてから中断する(AwaitOp 中の abort)。
    sim.emit();
    assert_eq!(sm_ctrl_abort_op(), 1, "進行中の op を中断した");
    assert_eq!(sm_ctrl_abort_op(), 0, "Idle なら 0(冪等)");
    sim.link_restore();
    sim.clear_events();

    assert_eq!(read_ok(&mut sim, node_id, 1, CL_ONOFF, 0x0000), 0);
    assert!(
        sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_ESTABLISHED),
        "abort_op 後の op は CASE を張り直す(§16.6 P6)。events={:?}",
        sim.kinds()
    );
    sim.clear_events();

    // ======================================================================
    // (b) SubscriptionLost(keep-alive 途絶)→ セッション無効化
    // ======================================================================
    assert!(!sm_ctrl_is_subscribed(node_id));
    assert_eq!(
        sm_ctrl_subscribe(node_id, 2, CL_TEMP, 0x0000, 0, 5, sim.now),
        0
    );
    let done = sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_DONE, 60_000);
    assert!(done.value_u64 > 0, "購読 ID");
    assert!(sm_ctrl_is_subscribed(node_id));
    sim.clear_events();

    // デバイスが落ちて keep-alive レポートが途絶 → maxInterval + 猶予(30s)で
    // SUBSCRIPTION_LOST。
    sim.link_up = false;
    let lost = sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIPTION_LOST, 180_000);
    assert_eq!(lost.node_id, node_id);
    assert_eq!(lost.value_u64, done.value_u64, "ロストした購読 ID");
    assert!(!sm_ctrl_is_subscribed(node_id), "テーブルから除去");
    sim.link_restore();
    // 溜まった再送/ACK を掃く(以降の観測を汚さない)。
    sim.idle_for(2_000);
    sim.clear_events();

    // 再購読は **新しい CASE** から始まる。
    assert_eq!(
        sm_ctrl_subscribe(node_id, 2, CL_TEMP, 0x0000, 0, 5, sim.now),
        0
    );
    sim.run_until(sm_ctrl_event_kind_t::SM_CTRL_EV_SUBSCRIBE_DONE, 60_000);
    assert!(
        sim.has(sm_ctrl_event_kind_t::SM_CTRL_EV_CASE_ESTABLISHED),
        "SUBSCRIPTION_LOST 後の再購読は CASE を張り直す(§16.6 P6)。events={:?}",
        sim.kinds()
    );
    assert!(sm_ctrl_is_subscribed(node_id));

    sm_ctrl_deinit();
    // SAFETY: alloc したレイアウトで解放する。
    unsafe { dealloc(mem, layout) };
}
