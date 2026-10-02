//! BTP コアの決定的ユニットテスト(すべて `now_ms` 注入・無線不要、§9.1)。
//!
//! - handshake 交渉(version / mtu / window)
//! - 単一 / 複数フラグメントのセグメント化・再組立・msglen 検証
//! - seq / ack / window とラップアラウンド
//! - ACK タイムアウト、遅延 ACK / 即時 ACK
//! - peripheral ⇔ central を直結したループバックでの双方向メッセージ交換

use super::framing::HeaderFlags;
use super::handshake::{fragment_size, HandshakeReq, HandshakeResp, BTP_MAGIC};
use super::reassembly::Reassembler;
use super::*;

const MTU: Option<u16> = Some(247);

/// central / peripheral を handshake で確立し、両インスタンスを返す。
fn establish<const W: usize>(mtu: Option<u16>) -> (Btp<W>, Btp<W>) {
    let mut central = Btp::<W>::new(BtpRole::Central);
    let mut peripheral = Btp::<W>::new(BtpRole::Peripheral);
    let mut buf = [0u8; 300];

    let n = central.start_handshake(&mut buf, mtu, 0).unwrap();
    peripheral.process_incoming(&buf[..n], mtu, 0).unwrap();
    let n = peripheral.process_outgoing(&mut buf, mtu, 0).unwrap();
    central.process_incoming(&buf[..n], mtu, 0).unwrap();

    assert!(central.is_established());
    assert!(peripheral.is_established());
    (central, peripheral)
}

/// `from` の送出フラグメントを尽きるまで `to` に投入し、届けた本数を返す。
fn drain<const W: usize>(from: &mut Btp<W>, to: &mut Btp<W>, mtu: Option<u16>, now: u64) -> usize {
    let mut buf = [0u8; 300];
    let mut count = 0;
    loop {
        let n = from.process_outgoing(&mut buf, mtu, now).unwrap();
        if n == 0 {
            break;
        }
        to.process_incoming(&buf[..n], mtu, now).unwrap();
        count += 1;
    }
    count
}

/// データ + ACK を双方向に流し切って静穏化する(遅延 ACK を焼くため時刻を進める)。
fn settle<const W: usize>(a: &mut Btp<W>, b: &mut Btp<W>, mtu: Option<u16>, now: u64) {
    let mut t = now;
    for _ in 0..64 {
        let moved = drain(a, b, mtu, t) + drain(b, a, mtu, t);
        if moved == 0 {
            break;
        }
        t += 3_000; // 遅延 ACK(2500ms)期限を越えて焼く
    }
}

// ==========================================================================
// handshake 交渉
// ==========================================================================

#[test]
fn handshake_negotiates_version_mtu_window() {
    // ATT_MTU 247 → fragment = clamp(247-3, 6, 244) = 244、window = 6。
    let (c, p) = establish::<6>(MTU);
    assert_eq!(c.fragment_size(), 244);
    assert_eq!(p.fragment_size(), 244);
    assert_eq!(c.window(), 6);
    assert_eq!(p.window(), 6);
}

#[test]
fn handshake_unknown_mtu_uses_default_fragment() {
    // MTU 不明 → fragment = 20。
    let (c, p) = establish::<6>(None);
    assert_eq!(c.fragment_size(), 20);
    assert_eq!(p.fragment_size(), 20);
}

#[test]
fn handshake_window_is_min_of_offer_and_cap() {
    // central が W=3 を提示 → 交渉済み window = 3(peripheral の cap 6 と min)。
    let (c, p) = establish::<3>(MTU);
    assert_eq!(c.window(), 3);
    assert_eq!(p.window(), 3);
}

#[test]
fn handshake_wire_lengths_and_magic() {
    let mut central = Btp::<6>::new(BtpRole::Central);
    let mut buf = [0u8; 32];
    let n = central.start_handshake(&mut buf, MTU, 0).unwrap();
    // Request は 9 バイト・magic 始まり。
    assert_eq!(n, 9);
    assert_eq!(&buf[0..2], &BTP_MAGIC);

    let mut peripheral = Btp::<6>::new(BtpRole::Peripheral);
    peripheral.process_incoming(&buf[..n], MTU, 0).unwrap();
    let n = peripheral.process_outgoing(&mut buf, MTU, 0).unwrap();
    // Response は 6 バイト・magic 始まり。
    assert_eq!(n, 6);
    assert_eq!(&buf[0..2], &BTP_MAGIC);
}

#[test]
fn handshake_req_resp_round_trip() {
    let req = HandshakeReq::v4(247, 6);
    assert!(req.supports_v4());
    let mut buf = [0u8; 16];
    let n = req.encode(&mut buf).unwrap();
    assert_eq!(n, 9);
    assert_eq!(HandshakeReq::decode(&buf[..n]).unwrap(), req);

    let resp = HandshakeResp {
        version: 4,
        fragment: 244,
        window: 6,
    };
    let n = resp.encode(&mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(HandshakeResp::decode(&buf[..n]).unwrap(), resp);
}

#[test]
fn fragment_size_clamps() {
    assert_eq!(fragment_size(None), 20);
    assert_eq!(fragment_size(Some(23)), 20); // 23-3 = 20
    assert_eq!(fragment_size(Some(10)), 20); // max(10,23)-3 = 20
    assert_eq!(fragment_size(Some(247)), 244);
    assert_eq!(fragment_size(Some(1000)), 244); // clamp 上限
}

// ==========================================================================
// セグメント化 / 再組立 / msglen 検証
// ==========================================================================

#[test]
fn single_fragment_message_round_trips() {
    let (mut c, mut p) = establish::<6>(MTU);
    let msg: &[u8] = b"hello matter over btp";
    c.send(msg, 0).unwrap();
    settle(&mut c, &mut p, MTU, 0);
    assert_eq!(p.recv().unwrap(), msg);
    assert!(p.recv().is_none());
}

#[test]
fn multi_fragment_message_reassembles() {
    // MTU 不明 → fragment = 20。50 バイトのメッセージは複数セグメントに分かれる。
    let (mut c, mut p) = establish::<6>(None);
    let msg: [u8; 50] = core::array::from_fn(|i| i as u8);
    c.send(&msg, 0).unwrap();
    settle(&mut c, &mut p, None, 0);
    assert_eq!(p.recv().unwrap(), &msg[..]);
}

#[test]
fn reassembler_validates_msglen_mismatch() {
    let mut r = Reassembler::new();
    // Beginning が全長 10 を宣言、payload 5 バイト。
    let beg = HeaderFlags::from_bits(HeaderFlags::BEGINNING);
    r.push(beg, Some(10), &[0; 5]).unwrap();
    // Ending だが累積 8 != 10 → msglen 検証失敗。
    let end = HeaderFlags::from_bits(HeaderFlags::ENDING);
    assert_eq!(r.push(end, None, &[0; 3]), Err(crate::Error::Decode));
}

#[test]
fn reassembler_rejects_overflow_and_orphan_continuation() {
    let mut r = Reassembler::new();
    // 宣言 4 バイトに 6 バイト payload → 溢れ。
    let beg = HeaderFlags::from_bits(HeaderFlags::BEGINNING | HeaderFlags::ENDING);
    assert_eq!(r.push(beg, Some(4), &[0; 6]), Err(crate::Error::Decode));

    // Beginning なしの継続は不正状態。
    let mut r2 = Reassembler::new();
    let cont = HeaderFlags::from_bits(HeaderFlags::CONTINUING);
    assert_eq!(
        r2.push(cont, None, &[0; 3]),
        Err(crate::Error::InvalidState)
    );
}

#[test]
fn send_rejects_second_sdu_while_pending() {
    let (mut c, _p) = establish::<6>(MTU);
    c.send(b"first", 0).unwrap();
    // まだ送出前(process_outgoing していない)なので 2 本目は拒否。
    assert_eq!(c.send(b"second", 0), Err(crate::Error::InvalidState));
}

// ==========================================================================
// seq / ack / window とラップアラウンド
// ==========================================================================

#[test]
fn many_messages_wrap_seq_and_ack() {
    // 1 メッセージ = 1 セグメント(大 MTU)。300 通で seq(8bit)がラップする。
    let (mut c, mut p) = establish::<6>(MTU);
    for i in 0..300u32 {
        let msg = [(i & 0xFF) as u8, (i >> 8) as u8, 0xAB, 0xCD];
        c.send(&msg, i as u64 * 100).unwrap();
        settle(&mut c, &mut p, MTU, i as u64 * 100);
        let got = p.recv().expect("message received across seq wrap");
        assert_eq!(got, &msg);
        // ラップ後も未 ACK が溜まらず(ACK が返り)次の送信ができる。
        assert!(c.can_send());
    }
}

#[test]
fn out_of_order_seq_is_rejected() {
    let (mut c, mut p) = establish::<6>(MTU);
    c.send(b"data", 0).unwrap();
    let mut buf = [0u8; 300];
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    // seq バイトを壊す。ヘッダは [flags, (ack), seq, ...] で、ACK ビット(0x08)の有無で
    // seq の位置が変わる(central の最初のデータは handshake 応答への ack=0 を piggyback
    // するため通常 ACK 付き)。
    let seq_idx = 1 + usize::from(buf[0] & 0x08 != 0);
    buf[seq_idx] = buf[seq_idx].wrapping_add(5);
    assert_eq!(
        p.process_incoming(&buf[..n], MTU, 0),
        Err(crate::Error::InvalidState)
    );
}

// ==========================================================================
// ACK タイムアウト / 遅延 ACK / 即時 ACK
// ==========================================================================

#[test]
fn unacked_send_times_out_after_ack_timeout() {
    let (mut c, _p) = establish::<6>(MTU);
    let mut buf = [0u8; 300];
    c.send(b"needs ack", 0).unwrap();
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    assert!(n > 0);
    // 未 ACK の liveness 期限 = 0 + 15000(idle 30000 より早い)。
    assert_eq!(c.next_deadline(), Some(15_000));
    assert!(!c.is_timed_out(14_999));
    assert!(c.is_timed_out(15_000));
}

#[test]
fn delayed_ack_fires_after_send_delay() {
    // window 6 → 1 データ受信で local window は 5(>1)→ 遅延 ACK(2500ms)。
    let (mut c, mut p) = establish::<6>(MTU);
    c.send(b"x", 0).unwrap();
    let mut buf = [0u8; 300];
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    p.process_incoming(&buf[..n], MTU, 0).unwrap();
    assert_eq!(p.recv().unwrap(), b"x");

    // 期限前は standalone ACK を出さない。
    assert_eq!(p.process_outgoing(&mut buf, MTU, 0).unwrap(), 0);
    assert_eq!(p.next_deadline(), Some(2_500));
    // 期限到達で standalone ACK を出す。
    assert!(p.process_outgoing(&mut buf, MTU, 2_500).unwrap() > 0);
}

#[test]
fn immediate_ack_when_local_window_low() {
    // window 2 → 1 データ受信で local window は 1(≤1)→ 即時 ACK。
    let (mut c, mut p) = establish::<2>(MTU);
    c.send(b"y", 0).unwrap();
    let mut buf = [0u8; 300];
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    p.process_incoming(&buf[..n], MTU, 0).unwrap();
    assert_eq!(p.recv().unwrap(), b"y");
    // 同一 now で standalone ACK が出る(遅延なし)。
    assert!(p.process_outgoing(&mut buf, MTU, 0).unwrap() > 0);
}

#[test]
fn piggyback_ack_on_reverse_data() {
    // peripheral が返信データを送るとき、保留 ACK が piggyback される。
    let (mut c, mut p) = establish::<6>(MTU);
    c.send(b"ping", 0).unwrap();
    let mut buf = [0u8; 300];
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    p.process_incoming(&buf[..n], MTU, 0).unwrap();
    assert_eq!(p.recv().unwrap(), b"ping");

    // peripheral 返信 → piggyback ACK(ACK フラグが立つ)。
    p.send(b"pong", 0).unwrap();
    let n = p.process_outgoing(&mut buf, MTU, 0).unwrap();
    let (hdr, _) = super::framing::BtpHeader::decode(&buf[..n]).unwrap();
    assert!(hdr.flags.contains(HeaderFlags::ACK));
    assert!(hdr.ack.is_some());
    // central が受理 → 未 ACK が解消され、返信も受け取れる。
    c.process_incoming(&buf[..n], MTU, 0).unwrap();
    assert_eq!(c.recv().unwrap(), b"pong");
    // これ以降 standalone ACK は不要(piggyback 済み)。
    assert_eq!(p.process_outgoing(&mut buf, MTU, 10_000).unwrap(), 0);
}

// ==========================================================================
// 双方向ループバック
// ==========================================================================

#[test]
fn bidirectional_loopback_exchange() {
    let (mut c, mut p) = establish::<6>(None); // 小 MTU で複数フラグメントも混ぜる
    let up: [u8; 40] = core::array::from_fn(|i| i as u8);
    let down: [u8; 35] = core::array::from_fn(|i| (0xFF - i) as u8);

    // central → peripheral
    c.send(&up, 0).unwrap();
    settle(&mut c, &mut p, None, 0);
    assert_eq!(p.recv().unwrap(), &up[..]);

    // peripheral → central
    p.send(&down, 100).unwrap();
    settle(&mut c, &mut p, None, 100);
    assert_eq!(c.recv().unwrap(), &down[..]);

    // もう一往復して seq/ack が破綻しないこと。
    c.send(&up, 200).unwrap();
    settle(&mut c, &mut p, None, 200);
    assert_eq!(p.recv().unwrap(), &up[..]);
}

// ==========================================================================
// 広告(AdvData)
// ==========================================================================

#[test]
fn adv_data_service_data_round_trips() {
    let adv = gatt::AdvData {
        discriminator: 0x0F00 | 0x0ABC & 0x0FFF, // 12bit
        vendor_id: 0xFFF1,
        product_id: 0x8000,
        additional_data: true,
        ext_announcement: false,
    };
    let sd = adv.service_data();
    assert_eq!(sd[0], gatt::AdvData::OPCODE_COMMISSIONABLE);
    let parsed = gatt::AdvData::parse_service_data(&sd).unwrap();
    assert_eq!(parsed.discriminator, adv.discriminator & 0x0FFF);
    assert_eq!(parsed.vendor_id, 0xFFF1);
    assert_eq!(parsed.product_id, 0x8000);
    assert!(parsed.additional_data);
    assert!(!parsed.ext_announcement);
}

// ==========================================================================
// GATT trait(§5):メモリ内実装が trait を満たし、&mut T ブランケットも成立する
// ことを型レベルで確認する(async trait を回すのは E2E で BTP 直結ポンプに任せ、
// ここは実装可能性 + blanket impl のコンパイル確認に絞る。詳細は本コミットの報告参照)。
// ==========================================================================

#[test]
fn gatt_traits_are_implementable_and_have_blanket_impls() {
    use super::gatt::{GattCentral, GattPeripheral, PeripheralEvent, ScanFilter, ScanResult};
    use crate::transport::net::BtpConnId;

    /// メモリ内テスト実装(async 本体は自明。ポーリングされない型レベル確認用)。
    struct MemPeripheral;
    impl GattPeripheral for MemPeripheral {
        async fn start_advertising(&mut self, _adv: &gatt::AdvData) -> crate::error::Result<()> {
            Ok(())
        }
        async fn stop_advertising(&mut self) -> crate::error::Result<()> {
            Ok(())
        }
        async fn next_event(&mut self, _buf: &mut [u8]) -> crate::error::Result<PeripheralEvent> {
            Ok(PeripheralEvent::Connected {
                conn: BtpConnId(0),
                att_mtu: None,
            })
        }
        async fn indicate(&mut self, _conn: BtpConnId, _frag: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        async fn disconnect(&mut self, _conn: BtpConnId) -> crate::error::Result<()> {
            Ok(())
        }
    }

    struct MemCentral;
    impl GattCentral for MemCentral {
        type PeerHandle = ();
        async fn scan(&mut self, _filter: ScanFilter) -> crate::error::Result<ScanResult<()>> {
            Ok(ScanResult {
                discriminator: 0xABC,
                vendor_id: 0xFFF1,
                product_id: 0x8000,
                handle: (),
            })
        }
        async fn connect(
            &mut self,
            _target: &ScanResult<()>,
        ) -> crate::error::Result<(BtpConnId, Option<u16>)> {
            Ok((BtpConnId(0), Some(247)))
        }
        async fn subscribe_c2(&mut self, _conn: BtpConnId) -> crate::error::Result<()> {
            Ok(())
        }
        async fn write_c1(&mut self, _conn: BtpConnId, _frag: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        async fn next_indication(
            &mut self,
            _conn: BtpConnId,
            _buf: &mut [u8],
        ) -> crate::error::Result<usize> {
            Ok(0)
        }
        async fn disconnect(&mut self, _conn: BtpConnId) -> crate::error::Result<()> {
            Ok(())
        }
    }

    fn assert_peripheral<P: GattPeripheral>(_: P) {}
    fn assert_central<C: GattCentral>(_: C) {}

    // 具象実装が trait を満たす。
    assert_peripheral(MemPeripheral);
    assert_central(MemCentral);
    // `&mut T` ブランケット実装も trait を満たす(合成に使える)。
    let mut p = MemPeripheral;
    let mut c = MemCentral;
    assert_peripheral(&mut p);
    assert_central(&mut c);
}

#[test]
fn adv_data_full_advertisement_layout() {
    let adv = gatt::AdvData {
        discriminator: 0xABC,
        vendor_id: 0xFFF1,
        product_id: 0x8000,
        additional_data: false,
        ext_announcement: false,
    };
    let mut out = [0u8; 32];
    let n = adv.encode_adv(&mut out).unwrap();
    assert_eq!(n, gatt::ADV_TOTAL_LEN);
    // Flags AD。
    assert_eq!(&out[0..3], &[0x02, 0x01, 0x06]);
    // Service Data AD: len=0x0B, type=0x16, UUID16 LE = F6 FF。
    assert_eq!(&out[3..7], &[0x0B, 0x16, 0xF6, 0xFF]);
    // discriminator(下位 12bit)LE。
    assert_eq!(u16::from_le_bytes([out[8], out[9]]) & 0x0FFF, 0xABC);
}

#[test]
fn large_message_spanning_more_than_window_fragments() {
    // window(6)を超えるフラグメント数のメッセージが、途中 ACK を挟んで再組立される
    // ことを確認する(E2E の AddNOC 等が踏む regime)。fragment=61, 500B ≈ 9 フラグメント。
    // さらに逆方向 1 通で受信側に piggyback ACK を owe させ、先頭フラグメントが ACK を
    // 運ぶ経路も同時に踏む。
    let (mut c, mut p) = establish::<6>(Some(64));
    assert_eq!(c.fragment_size(), 61);

    // 逆方向: p→c 小メッセージ。c は受信し ACK を保留する。
    p.send(b"reverse", 0).unwrap();
    let mut buf = [0u8; 300];
    loop {
        let n = p.process_outgoing(&mut buf, Some(64), 0).unwrap();
        if n == 0 {
            break;
        }
        c.process_incoming(&buf[..n], Some(64), 0).unwrap();
    }
    assert_eq!(c.recv().unwrap(), b"reverse");

    // c は今 p への ACK を保留中。window 超えの大メッセージを送る。
    let msg: [u8; 500] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    c.send(&msg, 0).unwrap();
    settle(&mut c, &mut p, Some(64), 0);
    assert_eq!(
        p.recv().expect("reassembled 500B across window boundary"),
        &msg[..]
    );
}

// ==========================================================================
// chip 互換の seq 規約(handshake 応答 = 暗黙の peripheral seq 0)
// ==========================================================================

/// chip-tool 実機で裏取りした seq 規約の固定化(2026-07-05):
/// handshake 応答は peripheral→central 方向の暗黙の seq 0 を消費するため、
/// central の最初のデータフラグメントは seq=0 + ack=0(応答への piggyback ACK)、
/// peripheral の最初のデータフラグメントは seq=1 になる。
#[test]
fn chip_compatible_initial_seq_and_resp_ack() {
    let (mut c, mut p) = establish::<6>(MTU);
    let mut buf = [0u8; 300];

    // central 最初のデータ: flags=Beginning|Ending|ACK, ack=0, seq=0(chip-tool 実ワイヤと一致)。
    c.send(b"hello", 10).unwrap();
    let n = c.process_outgoing(&mut buf, MTU, 10).unwrap();
    assert_eq!(buf[0], 0x01 | 0x04 | 0x08, "Beginning|Ending|ACK");
    assert_eq!(buf[1], 0, "ack=0(handshake 応答の暗黙 seq 0 への ACK)");
    assert_eq!(buf[2], 0, "central の最初のデータ seq は 0");
    p.process_incoming(&buf[..n], MTU, 10).unwrap();
    assert_eq!(p.recv().expect("SDU"), b"hello");

    // peripheral 最初のデータ: seq=1(seq 0 は handshake 応答が消費済み)。
    p.send(b"world", 20).unwrap();
    let n = p.process_outgoing(&mut buf, MTU, 20).unwrap();
    let has_ack = buf[0] & 0x08 != 0;
    let seq = if has_ack { buf[2] } else { buf[1] };
    assert_eq!(seq, 1, "peripheral の最初のデータ seq は 1");
    c.process_incoming(&buf[..n], MTU, 20).unwrap();
    assert_eq!(c.recv().expect("SDU"), b"world");
}

#[test]
fn keepalive_ack_exchange_sustains_idle_link() {
    // 純粋 standalone ACK(keep-alive)を受けた側は、遅延 2.5s で ACK を返す
    // (chip の ack-received タイマ対策。長アイドルでのリンク維持)。
    let (mut c, mut p) = establish::<6>(MTU);
    let mut buf = [0u8; 300];

    // c → p にデータ 1 本。p は遅延 ACK(2500ms)を standalone で返す。
    c.send(b"z", 0).unwrap();
    let n = c.process_outgoing(&mut buf, MTU, 0).unwrap();
    p.process_incoming(&buf[..n], MTU, 0).unwrap();
    assert_eq!(p.recv().unwrap(), b"z");
    let n = p.process_outgoing(&mut buf, MTU, 2_500).unwrap();
    assert!(n > 0, "p sends standalone ACK");

    // c はその standalone ACK(seq 消費)を受けて keep-alive ACK を武装し、
    // 2.5s 後に standalone ACK を返す(応酬 = keep-alive)。
    c.process_incoming(&buf[..n], MTU, 2_500).unwrap();
    assert_eq!(
        c.process_outgoing(&mut buf, MTU, 2_500).unwrap(),
        0,
        "not before the 2.5s delay"
    );
    assert_eq!(c.next_deadline(), Some(5_000));
    let n = c.process_outgoing(&mut buf, MTU, 5_000).unwrap();
    assert!(n > 0, "c returns keep-alive ACK");

    // 応酬が双方向に続く(p 側も同様に 2.5s 後へ武装)。
    p.process_incoming(&buf[..n], MTU, 5_000).unwrap();
    let n = p.process_outgoing(&mut buf, MTU, 7_500).unwrap();
    assert!(n > 0, "p keeps the exchange going");
    // リンクはアイドルタイムアウトしない(last_activity が更新され続ける)。
    assert!(!p.is_timed_out(7_501));
}

/// 相手の standalone ACK も受信 window を消費する(chip の BLEEndPoint と同じ数え方)。
/// window 5 で「ACK 1 + データ 3」を受けたら相手は送信停止しているので、即時 ACK が必要
/// (実機: Tapo P110M が 2.5 秒の遅延 ACK を待てず C1 書き込みを ATT 0x0E で拒否した)。
#[test]
fn peer_standalone_ack_counts_toward_window_and_forces_immediate_ack() {
    use crate::btp::session::RecvWindow;
    let mut w = RecvWindow::new(0);
    w.set_window(5);
    let t = 1_000;
    w.accept_seq(0).unwrap();
    w.arm_keepalive_ack(t); // 相手の standalone ACK
    assert!(
        !w.ack_due(t),
        "a lone keep-alive ACK is still acknowledged lazily"
    );
    for seq in 1..=2 {
        w.accept_seq(seq).unwrap();
        w.arm_ack(t);
    }
    assert!(
        !w.ack_due(t),
        "window still has room after ACK + 2 data fragments"
    );
    w.accept_seq(3).unwrap();
    w.arm_ack(t);
    assert!(
        w.ack_due(t),
        "ACK + 3 data fragments exhaust a window of 5: ack immediately"
    );
    assert_eq!(w.take_ack(), Some(3));
    // ACK を返すと window は戻り、単発の keep-alive は再び遅延 ACK。
    w.accept_seq(4).unwrap();
    w.arm_keepalive_ack(t);
    assert!(!w.ack_due(t));
}
