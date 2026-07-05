//! コアの [`GattPeripheral`] trait を TrouBLE(trouble-host)で実装する
//! (`docs/design/port-esp32-device.md` §2 の写像)。
//!
//! # 構成(PC 版 bluer 実装のパターンを embassy へ写像)
//!
//! PC 版(`simple-matter-ble/src/bluer_peripheral.rs`)は「コールバック/別タスク発の
//! 生イベント → channel → `next_event` が翻訳」という構造だった。TrouBLE は
//! コールバックではなく **単一 future 駆動**(`GattConnection::next()` をポーリング)
//! なので、本実装は次の 2 役に分割する:
//!
//! - [`gatt_worker`]: 広告 → 接続受理 → GATT イベントループを回す常駐 async 関数。
//!   受けた生イベントを [`GattChannels::events`] へ流し、[`GattChannels::cmd`] からの
//!   indicate / disconnect 要求を実行する。TrouBLE の `Peripheral` / GATT server を所有する。
//! - [`TroubleGattPeripheral`]: [`GattPeripheral`] trait の実装。channel の反対側を持ち、
//!   生イベントを [`PeripheralEvent`] へ翻訳する(bluer 版の `next_event` に相当)。
//!
//! 両者は同一 executor 上で `embassy_futures::join` により並走する(`Send` 境界なし・
//! 単一タスク前提という trait の契約どおり)。
//!
//! # 設計上の非自明な制約(ble-btp.md 由来)
//!
//! - **確立順序**: central(chip-tool / PC ble-commissioner)は「C1 write(handshake req)
//!   → C2 subscribe」の順で来る。handshake 応答の indicate は C2Subscribed 後まで
//!   統合層(pump)が保留する。本モジュールは順序を強制しない(イベントを順に流すだけ)。
//! - **接続数 1**: 現行スコープは同時 1 接続(ble-btp.md §11-2)。`BtpConnId` は
//!   bluer 版と同じく 1 起点で wrap 採番する。
//! - **indication は確認応答待ち**: ATT は 1 接続に同時 1 indication しか許さない。
//!   TrouBLE 0.6 の `Characteristic::indicate` は confirmation を待たない(PDU を
//!   キューするだけ)ため、[`gatt_worker`] が ATT Handle Value Confirmation の受信まで
//!   次の indicate 要求を受けない(その間も C1 write は events へ転送し続ける)。
//!
//! [`GattPeripheral`]: simple_matter::btp::gatt::GattPeripheral

// gatt_service マクロの生成コード(default 値の借用)がこの lint に掛かる。
// item 単位の #[allow] ではマクロ展開に届かないため、モジュール単位で許容する。
#![allow(clippy::needless_borrows_for_generic_args)]

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use esp_println::println;

use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams, LeSetScanResponseData};
use bt_hci::controller::ControllerCmdSync;
use trouble_host::att::AttClient;
use trouble_host::prelude::*;

use simple_matter::btp::gatt::{AdvData, GattPeripheral, PeripheralEvent, ADV_TOTAL_LEN};
// `Error` / `Result` は素の名前で import しない: gatt_server / gatt_service マクロの
// 生成コードが(prelude glob 経由の)`trouble_host::Error` を非修飾名で参照するため、
// 明示 import で shadowing するとマクロ内の型が食い違う。
use simple_matter::error::{Error as SmError, Result as SmResult};
use simple_matter::transport::net::BtpConnId;

/// 1 BTP フラグメントの最大バイト数(受け渡しバッファ長)。
///
/// BTP の交渉上限は 244(ble-btp.md §2.2)だが、ATT_MTU 251(TrouBLE の
/// default packet pool MTU)まで交渉された場合の write payload(MTU-3 = 248)を
/// 防御的に収容できるサイズにしておく。
pub const MAX_FRAG: usize = 248;

// ==========================================================================
// GATT サービス定義(Matter BLE Service 0xFFF6、C1 write / C2 indicate)
// ==========================================================================

/// Matter BTP の GATT サービス(ble-btp.md §2.1 の UUID)。
///
/// - C1(`...9D11`): central → peripheral の上り BTP フラグメント(Write / Write
///   Without Response)。
/// - C2(`...9D12`): peripheral → central の下り BTP フラグメント(Indicate)。
///   CCCD への書き込み(indication ビット 0x02)で subscribe を検知する。
///
/// C3(additional data, Read)は初期スコープ未使用(ble-btp.md §2.1)。
#[gatt_service(uuid = "0000fff6-0000-1000-8000-00805f9b34fb")]
pub struct MatterBtpService {
    /// C1: 上り BTP フラグメント。
    #[characteristic(uuid = "18ee2ef5-263d-4559-959f-4f9c429f9d11", write, write_without_response)]
    pub c1: heapless::Vec<u8, MAX_FRAG>,
    /// C2: 下り BTP フラグメント(indicate)。
    #[characteristic(uuid = "18ee2ef5-263d-4559-959f-4f9c429f9d12", indicate)]
    pub c2: heapless::Vec<u8, MAX_FRAG>,
}

/// GATT サーバ(GAP + Matter BTP サービス)。
#[gatt_server]
pub struct BtpGattServer {
    /// Matter BTP サービス(0xFFF6)。
    pub matter: MatterBtpService,
}

// ==========================================================================
// worker ⇔ trait 実装間の channel
// ==========================================================================

/// [`gatt_worker`] から [`TroubleGattPeripheral`] へ流れる生イベント。
///
/// 要素は固定長(`no_std`・ヒープレス)。C1 フラグメントは最大 [`MAX_FRAG`] バイト。
// ヒープレス方針のため Box 化せず、フラグメントを値で運ぶ(サイズ差は意図的)。
#[allow(clippy::large_enum_variant)]
pub enum RawEvent {
    /// central が接続し、最初の GATT 操作(C1 write / C2 subscribe)を行った。
    ///
    /// TrouBLE は接続直後の ATT_MTU 交渉が終わるまで正しい MTU を返せないため、
    /// bluer 版と同じく「最初の C1 write / subscribe を観測した時点」で発火する
    /// (その時点の negotiated ATT_MTU を添える)。
    Connected {
        /// 交渉済み ATT_MTU。
        att_mtu: Option<u16>,
    },
    /// C1 への write(上り BTP フラグメント)。
    C1Write {
        /// 有効長。
        len: usize,
        /// フラグメント本体(先頭 `len` バイトが有効)。
        data: [u8; MAX_FRAG],
    },
    /// central が C2 の CCCD に indication ビットを立てた(以降 indicate 可能)。
    C2Subscribed,
    /// 接続が切れた。
    Disconnected,
}

/// [`TroubleGattPeripheral`] から [`gatt_worker`] への要求。
// ヒープレス方針のため Box 化せず、フラグメントを値で運ぶ(サイズ差は意図的)。
#[allow(clippy::large_enum_variant)]
pub enum GattCmd {
    /// C2 indication で 1 フラグメントを送る(完了は `done` channel で返る)。
    Indicate {
        /// 有効長。
        len: usize,
        /// フラグメント本体。
        data: [u8; MAX_FRAG],
    },
    /// 現在の接続を切断する。
    Disconnect,
}

/// worker ⇔ trait 実装を繋ぐ channel 一式。
///
/// 呼び出し側(bin)が 1 つ生成し、[`gatt_worker`] と [`TroubleGattPeripheral::new`] の
/// 両方に貸す。executor 非依存(`NoopRawMutex` = 単一 executor 前提)。
pub struct GattChannels {
    /// worker → trait: 生イベント。容量 8(BTP window 上限 6 + 余裕。indication の
    /// confirmation 待ち中に central が window ぶん C1 write してきても詰まらない)。
    events: Channel<NoopRawMutex, RawEvent, 8>,
    /// trait → worker: indicate / disconnect 要求(直列化のため容量 1)。
    cmd: Channel<NoopRawMutex, GattCmd, 1>,
    /// worker → trait: 要求の完了通知。
    done: Channel<NoopRawMutex, SmResult<()>, 1>,
    /// trait → worker: 広告開始要求(最後の値を worker が使い回して再広告する)。
    adv: Signal<NoopRawMutex, AdvData>,
}

impl GattChannels {
    /// 全 channel を空で生成する。
    pub const fn new() -> Self {
        Self {
            events: Channel::new(),
            cmd: Channel::new(),
            done: Channel::new(),
            adv: Signal::new(),
        }
    }
}

impl Default for GattChannels {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================================================
// GattPeripheral trait 実装
// ==========================================================================

/// [`GattPeripheral`] の TrouBLE 実装(channel の trait 側)。
///
/// [`gatt_worker`] と同じ [`GattChannels`] を共有して生成し、統合層(pump)から
/// trait 経由で使う。`BtpConnId` は 1 起点 wrap 採番(bluer 版と同じ規約)。
pub struct TroubleGattPeripheral<'ch> {
    ch: &'ch GattChannels,
    /// 現在アクティブな接続ハンドル(単一接続スコープ)。
    conn: Option<BtpConnId>,
    /// 次に採番する接続 index。
    next_conn: u8,
}

impl<'ch> TroubleGattPeripheral<'ch> {
    /// channel 一式を共有して生成する。
    pub fn new(ch: &'ch GattChannels) -> Self {
        Self {
            ch,
            conn: None,
            next_conn: 1,
        }
    }
}

impl GattPeripheral for TroubleGattPeripheral<'_> {
    async fn start_advertising(&mut self, adv: &AdvData) -> SmResult<()> {
        // worker が Signal を拾って広告を開始する(切断後の再広告も worker が
        // 最後の AdvData で自動的に行う)。
        self.ch.adv.signal(*adv);
        Ok(())
    }

    async fn stop_advertising(&mut self) -> SmResult<()> {
        // E2 スコープでは未対応: legacy advertising は接続受理で自動停止し、
        // 本 FW は常時 commissionable なので明示停止の出番がない。
        Ok(())
    }

    async fn next_event(&mut self, buf: &mut [u8]) -> SmResult<PeripheralEvent> {
        loop {
            match self.ch.events.receive().await {
                RawEvent::Connected { att_mtu } => {
                    let id = BtpConnId(self.next_conn);
                    self.next_conn = self.next_conn.wrapping_add(1).max(1);
                    self.conn = Some(id);
                    return Ok(PeripheralEvent::Connected { conn: id, att_mtu });
                }
                RawEvent::C1Write { len, data } => {
                    // Connected 前の C1Write は worker 側の規約上発生しない
                    // (ensure_connected が先に Connected を流す)が、防御的に読み捨てる。
                    let Some(conn) = self.conn else { continue };
                    let dst = buf.get_mut(..len).ok_or(SmError::NoSpace)?;
                    dst.copy_from_slice(&data[..len]);
                    return Ok(PeripheralEvent::C1Write { conn, len });
                }
                RawEvent::C2Subscribed => {
                    let Some(conn) = self.conn else { continue };
                    return Ok(PeripheralEvent::C2Subscribed { conn });
                }
                RawEvent::Disconnected => {
                    let Some(conn) = self.conn.take() else { continue };
                    return Ok(PeripheralEvent::Disconnected { conn });
                }
            }
        }
    }

    async fn indicate(&mut self, _conn: BtpConnId, frag: &[u8]) -> SmResult<()> {
        if frag.len() > MAX_FRAG {
            return Err(SmError::NoSpace);
        }
        let mut data = [0u8; MAX_FRAG];
        data[..frag.len()].copy_from_slice(frag);
        self.ch
            .cmd
            .send(GattCmd::Indicate {
                len: frag.len(),
                data,
            })
            .await;
        // worker が indication 送出 + confirmation 受信まで待って完了を返す。
        self.ch.done.receive().await
    }

    async fn disconnect(&mut self, _conn: BtpConnId) -> SmResult<()> {
        self.conn = None;
        self.ch.cmd.send(GattCmd::Disconnect).await;
        self.ch.done.receive().await
    }
}

// ==========================================================================
// GATT ワーカー(TrouBLE 側)
// ==========================================================================

/// 1 接続ぶんの worker 内部状態。
struct ConnState {
    /// `Connected` イベントを events へ流したか(最初の C1 write / subscribe で発火)。
    announced: bool,
    /// C2 の CCCD に indication ビットが立っているか。
    subscribed: bool,
}

/// GATT イベント処理の継続/終了。
enum Flow {
    /// 接続継続。
    Continue,
    /// 切断済み(接続ループを抜けて再広告へ)。
    Disconnected,
}

/// 広告 → 接続受理 → GATT イベントループを回す常駐ワーカー。
///
/// bin 側で `runner.run()`・pump と並走させる(`embassy_futures::join`)。
/// 最初の [`GattPeripheral::start_advertising`] を待ってから広告を開始し、
/// 切断後は最後の [`AdvData`] で自動的に再広告する。
pub async fn gatt_worker<C>(
    peripheral: &mut Peripheral<'_, C, DefaultPacketPool>,
    server: &BtpGattServer<'_>,
    ch: &GattChannels,
) -> !
where
    C: Controller
        + for<'t> ControllerCmdSync<LeSetAdvData>
        + ControllerCmdSync<LeSetAdvParams>
        + for<'t> ControllerCmdSync<LeSetAdvEnable>
        + for<'t> ControllerCmdSync<LeSetScanResponseData>,
{
    // 最初の start_advertising(AdvData)を待つ。
    let mut adv = ch.adv.wait().await;
    let mut adv_buf = [0u8; ADV_TOTAL_LEN];
    loop {
        // start_advertising が再度呼ばれていたら AdvData を更新する。
        if let Some(next) = ch.adv.try_take() {
            adv = next;
        }
        // AdvData(0xFFF6 service data)の生成はコア側(sans-IO)。
        let n = match adv.encode_adv(&mut adv_buf) {
            Ok(n) => n,
            Err(_) => unreachable!("ADV_TOTAL_LEN buffer is always large enough"),
        };
        let params = AdvertisementParameters::default();
        let advertiser = match peripheral
            .advertise(
                &params,
                Advertisement::ConnectableScannableUndirected {
                    adv_data: &adv_buf[..n],
                    scan_data: &[],
                },
            )
            .await
        {
            Ok(a) => a,
            Err(_) => {
                println!("[ble] advertise failed; retrying in 1s");
                embassy_time::Timer::after_millis(1000).await;
                continue;
            }
        };
        println!("[ble] advertising (0xFFF6 service data)");

        let conn = match advertiser.accept().await {
            Ok(c) => c,
            Err(_) => {
                println!("[ble] accept failed; re-advertising");
                continue;
            }
        };
        println!("[ble] central connected");
        let gatt_conn = match conn.with_attribute_server(&server.server) {
            Ok(c) => c,
            Err(_) => {
                println!("[ble] attribute server attach failed; re-advertising");
                continue;
            }
        };

        run_connection(&gatt_conn, server, ch).await;
        println!("[ble] central disconnected; re-advertising");
    }
}

/// 1 接続ぶんの GATT イベント + コマンド処理ループ。切断で戻る。
async fn run_connection(
    gatt_conn: &GattConnection<'_, '_, DefaultPacketPool>,
    server: &BtpGattServer<'_>,
    ch: &GattChannels,
) {
    let mut st = ConnState {
        announced: false,
        subscribed: false,
    };
    loop {
        // 1 秒周期でリンク生存も確認する。trouble-host 0.6 の切断通知は内部で
        // `try_send`(connection_manager::disconnected)されるため、接続イベント
        // キューが埋まった瞬間の切断は **黙って落ちる**(Disconnected が届かず
        // 再広告できなくなる。実機で再現)。イベントに依存せず `is_connected()`
        // をポーリングして確実に回収する。
        match select3(
            gatt_conn.next(),
            ch.cmd.receive(),
            embassy_time::Timer::after_millis(1000),
        )
        .await
        {
            Either3::First(ev) => {
                if let Flow::Disconnected = on_conn_event(ev, gatt_conn, server, ch, &mut st).await
                {
                    return;
                }
            }
            Either3::Second(cmd) => match cmd {
                GattCmd::Indicate { len, data } => {
                    if let Flow::Disconnected =
                        send_indication(gatt_conn, server, ch, &mut st, &data[..len]).await
                    {
                        return;
                    }
                }
                GattCmd::Disconnect => {
                    gatt_conn.raw().disconnect();
                    ch.done.send(Ok(())).await;
                    // Disconnected イベントは gatt_conn.next() 側で観測される。
                }
            },
            Either3::Third(()) => {
                if !gatt_conn.raw().is_connected() {
                    println!("[gatt] link down (missed disconnect event); recovering");
                    ch.events.send(RawEvent::Disconnected).await;
                    return;
                }
            }
        }
    }
}

/// 接続イベント 1 件を処理する。
async fn on_conn_event(
    ev: GattConnectionEvent<'_, '_, DefaultPacketPool>,
    gatt_conn: &GattConnection<'_, '_, DefaultPacketPool>,
    server: &BtpGattServer<'_>,
    ch: &GattChannels,
    st: &mut ConnState,
) -> Flow {
    match ev {
        GattConnectionEvent::Disconnected { .. } => {
            ch.events.send(RawEvent::Disconnected).await;
            Flow::Disconnected
        }
        GattConnectionEvent::Gatt { event } => {
            on_att_event(event, gatt_conn, server, ch, st).await;
            Flow::Continue
        }
        // Phy / DataLength / ConnParams 更新等は BTP に影響しないため無視する。
        _ => Flow::Continue,
    }
}

/// ATT イベント 1 件を処理し、それが indication の confirmation なら `true` を返す。
///
/// C1 write は [`RawEvent::C1Write`] として events へ、C2 の CCCD 書き込み(indication
/// ビット)は [`RawEvent::C2Subscribed`] として events へ流す。**すべてのイベントを
/// `accept` して ATT 応答を返す**(accept が attribute server に write を反映させ、
/// CCCD の subscribe 状態もここで registrar に記録される)。
async fn on_att_event(
    event: GattEvent<'_, '_, DefaultPacketPool>,
    gatt_conn: &GattConnection<'_, '_, DefaultPacketPool>,
    server: &BtpGattServer<'_>,
    ch: &GattChannels,
    st: &mut ConnState,
) -> bool {
    let mut is_confirmation = false;
    match &event {
        GattEvent::Write(w) => {
            let handle = w.handle();
            if handle == server.matter.c1.handle {
                // 上り BTP フラグメント。accept 前にコピーして events へ。
                ensure_connected(gatt_conn, ch, st).await;
                let src = w.data();
                let len = src.len().min(MAX_FRAG);
                let mut data = [0u8; MAX_FRAG];
                data[..len].copy_from_slice(&src[..len]);
                ch.events.send(RawEvent::C1Write { len, data }).await;
            } else if Some(handle) == server.matter.c2.cccd_handle {
                // CCCD 書き込み = subscribe / unsubscribe(indication ビット 0x02)。
                let ind = w.data().first().is_some_and(|b| b & 0x02 != 0);
                if ind && !st.subscribed {
                    st.subscribed = true;
                    ensure_connected(gatt_conn, ch, st).await;
                    ch.events.send(RawEvent::C2Subscribed).await;
                } else if !ind {
                    st.subscribed = false;
                }
            }
        }
        GattEvent::Other(o) => {
            // ATT Handle Value Confirmation(indication の確認応答)を検知する。
            is_confirmation = matches!(o.payload().incoming(), AttClient::Confirmation(_));
        }
        _ => {}
    }
    // accept で attribute server に処理させ、ATT 応答(Write Response 等)を送る。
    match event.accept() {
        Ok(reply) => reply.send().await,
        Err(_) => println!("[ble] failed to accept ATT event"),
    }
    is_confirmation
}

/// まだなら `Connected`(negotiated ATT_MTU つき)を events へ流す。
///
/// TrouBLE では接続直後に MTU が未交渉のため、bluer 版と同じく「最初の GATT 操作を
/// 観測した時点」で発火する(その頃には ATT_MTU exchange が完了している)。
async fn ensure_connected(
    gatt_conn: &GattConnection<'_, '_, DefaultPacketPool>,
    ch: &GattChannels,
    st: &mut ConnState,
) {
    if !st.announced {
        st.announced = true;
        let att_mtu = gatt_conn.raw().att_mtu();
        ch.events
            .send(RawEvent::Connected {
                att_mtu: Some(att_mtu),
            })
            .await;
    }
}

/// C2 indication を 1 件送り、ATT Handle Value Confirmation まで待つ。
///
/// ATT は 1 接続に同時 1 indication しか許さないため、confirmation を受けるまで
/// 次の [`GattCmd::Indicate`] は受け付けない(cmd channel が直列化する)。
/// 待機中も C1 write 等は [`on_att_event`] 経由で events へ流れ続ける。
async fn send_indication(
    gatt_conn: &GattConnection<'_, '_, DefaultPacketPool>,
    server: &BtpGattServer<'_>,
    ch: &GattChannels,
    st: &mut ConnState,
    frag: &[u8],
) -> Flow {
    if !st.subscribed {
        // 未 subscribe の indicate は TrouBLE が黙って握りつぶす(confirmation も
        // 来ない)ため、ここで明示的にエラーを返す。統合層は C2Subscribed 後まで
        // indicate を保留する契約なので、通常この分岐には入らない。
        ch.done.send(Err(SmError::InvalidState)).await;
        return Flow::Continue;
    }
    let value: heapless::Vec<u8, MAX_FRAG> = match heapless::Vec::from_slice(frag) {
        Ok(v) => v,
        Err(_) => {
            ch.done.send(Err(SmError::NoSpace)).await;
            return Flow::Continue;
        }
    };
    if server.matter.c2.indicate(gatt_conn, &value).await.is_err() {
        ch.done.send(Err(SmError::InvalidState)).await;
        return Flow::Continue;
    }
    // confirmation まで待つ。間に来る他の ATT イベントは通常どおり処理する。
    // run_connection と同じ理由(切断通知の取りこぼし)でリンク生存もポーリングする。
    loop {
        match select(gatt_conn.next(), embassy_time::Timer::after_millis(1000)).await {
            Either::First(GattConnectionEvent::Disconnected { .. }) => {
                ch.events.send(RawEvent::Disconnected).await;
                ch.done.send(Err(SmError::InvalidState)).await;
                return Flow::Disconnected;
            }
            Either::First(GattConnectionEvent::Gatt { event }) => {
                if on_att_event(event, gatt_conn, server, ch, st).await {
                    ch.done.send(Ok(())).await;
                    return Flow::Continue;
                }
            }
            Either::First(_) => {}
            Either::Second(()) => {
                if !gatt_conn.raw().is_connected() {
                    println!("[gatt] link down while awaiting confirmation; recovering");
                    ch.events.send(RawEvent::Disconnected).await;
                    ch.done.send(Err(SmError::InvalidState)).await;
                    return Flow::Disconnected;
                }
            }
        }
    }
}
