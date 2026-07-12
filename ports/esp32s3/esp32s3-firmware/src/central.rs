//! コアの [`GattCentral`] trait を TrouBLE(trouble-host)で実装する
//! (`docs/design/esp32-controller.md` §3。device 側 [`crate::ble`] の鏡像)。
//!
//! # 構成(worker + channel。§3.2)
//!
//! TrouBLE の [`GattClient`] は `Stack` と `Connection` を借用し、さらに
//! `GattClient::task()`(ATT RX ポンプ)を並走させる必要がある。寿命の絡む一式を
//! [`central_worker`] に閉じ、[`GattCentral`] impl 本体([`TroubleGattCentral`])は
//! channel 越しの façade にする:
//!
//! ```text
//! TroubleGattCentral(GattCentral impl、channel façade)
//!    │  cmd: Scan/Connect/WriteC1/SubscribeC2   resp: 完了通知   ind: C2 フラグメント
//!    ▼
//! central_worker タスク(所有: Central / Scanner / Connection / GattClient)
//!    ├─ (bin 側) runner.run_with_handler(&MatterAdvHandler) … adv report → Signal
//!    ├─ gatt_client.task()                                  … ATT RX ポンプ
//!    └─ cmd ループ: scan → accept-list connect → discovery → write / subscribe
//! ```
//!
//! # 設計上の非自明な制約(スモーク + TrouBLE 0.6 ソースで確定)
//!
//! - **scan と connect は直列**(accept-list を両者が書き換える)。[`GattCentral`] の
//!   trait 契約(scan → connect)どおりに使う限り問題ない。
//! - **非拡張 `Scanner::scan` は FilterDuplicates 有効**(K3 スモークで実測)。同一
//!   デバイスの report はスキャンセッションあたり 1 回しか届かないため、フィルタ不一致で
//!   待ち続けるときの再 report はセッションを再開始して得る(スキャンタイムアウトで
//!   [`Error::Timeout`] を返し、呼び出し側のリトライで再セッションになる)。
//! - **`GattClient::new` は ATT MTU 交換応答を待ってブロック**する(リスク R4)。
//!   embassy-time の timeout でラップし、無応答ペアではエラーを返す。
//! - **indication の確認応答は自動でない**: [`NotificationListener::next`] で受けた後、
//!   `confirm_indication` を worker が明示的に送る(受領 → ind channel 投入 → confirm の
//!   順。confirm を返すまで peripheral は次の indication を送らないため、ind channel が
//!   詰まっても自然なフロー制御になる)。
//! - **切断は Signal で伝える**: worker のコマンド処理が ATT 応答待ちでブロック中でも
//!   façade の `disconnect` が効くように、切断要求は cmd channel ではなく
//!   [`CentralChannels::force_dc`](Signal)で worker の select を割り込む。切断の事実は
//!   [`CentralChannels::link_down`](Signal)で façade へ届き、以降の旧 conn 操作は
//!   即エラーになる。
//! - **コマンド応答の欠落防止**: worker は「cmd 受領 → 処理 → resp 送信」を対にするが、
//!   接続断(`task()` 終了 / force_dc)で処理途中の future が cancel されると resp が
//!   欠落する。worker は cmd 受領時に pending フラグを立て、接続スコープを抜けた後に
//!   pending が残っていれば失敗 resp を補填する(façade が永久待ちにならない)。
//!
//! [`GattCentral`]: simple_matter::btp::gatt::GattCentral

use core::cell::Cell;

use embassy_futures::select::{select, select3, Either, Either3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use embassy_time::{with_timeout, Duration};
use esp_println::println;

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{AddrKind, BdAddr};
use trouble_host::prelude::*;

use simple_matter::btp::gatt::{
    AdvData, GattCentral, ScanFilter, ScanResult, C1_UUID128, C2_UUID128, MATTER_SERVICE_UUID16,
};
use simple_matter::error::{Error as SmError, Result as SmResult};
use simple_matter::transport::net::BtpConnId;

pub use crate::ble::MAX_FRAG;

/// GATT service discovery の同時保持数(0xFFF6 の 1 サービスで足りるが余裕を持つ)。
const MAX_SERVICES: usize = 4;

/// 1 回のスキャンセッションのタイムアウト。超過は [`SmError::Timeout`] で返し、
/// 呼び出し側(統合層)のリトライに任せる(コア Error に Timeout は無いので NotFound)。
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
/// 接続確立(LE Create Connection)のタイムアウト。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// ATT MTU 交換([`GattClient::new`])のタイムアウト(リスク R4)。
const MTU_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// GATT discovery(service / characteristic)のタイムアウト。
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// スキャン結果のバックエンド固有ハンドル(connect の宛先)。
pub type PeerInfo = (AddrKind, BdAddr);

/// façade → worker のコマンド。
// ヒープレス方針のため Box 化せず、フラグメントを値で運ぶ(サイズ差は意図的)。
#[allow(clippy::large_enum_variant)]
enum CentralCmd {
    /// スキャンして条件一致の commissionable を 1 件返す。
    Scan { filter: ScanFilter },
    /// スキャン結果の相手へ接続し、MTU 交換 + C1/C2 discovery まで行う。
    Connect { peer: PeerInfo },
    /// C1 write(上り BTP フラグメント)。
    WriteC1 { len: usize, data: [u8; MAX_FRAG] },
    /// C2 の CCCD に indication ビットを立てる。
    SubscribeC2,
}

/// worker → façade のコマンド応答。
enum CentralResp {
    /// Scan の結果。
    Scanned(SmResult<ScanResult<PeerInfo>>),
    /// Connect の結果(negotiated ATT_MTU)。
    Connected(SmResult<Option<u16>>),
    /// WriteC1 / SubscribeC2 の結果。
    Done(SmResult<()>),
}

/// worker → façade の C2 indication 1 フラグメント。
struct Indication {
    len: usize,
    data: [u8; MAX_FRAG],
}

/// worker ⇔ façade を繋ぐ channel 一式(device 側 [`crate::ble::GattChannels`] の鏡像)。
///
/// 呼び出し側(bin)が 1 つ生成し、[`central_worker`] / [`MatterAdvHandler`] /
/// [`TroubleGattCentral::new`] に貸す。`NoopRawMutex` = 単一 executor 前提。
pub struct CentralChannels {
    /// façade → worker: コマンド(直列化のため容量 1)。
    cmd: Channel<NoopRawMutex, CentralCmd, 1>,
    /// worker → façade: コマンド応答。
    resp: Channel<NoopRawMutex, CentralResp, 1>,
    /// worker → façade: 受信 C2 フラグメント。容量 8(BTP window 上限 6 + 余裕)。
    ind: Channel<NoopRawMutex, Indication, 8>,
    /// worker → façade: リンク断通知(次の [`GattCentral::connect`] でリセット)。
    link_down: Signal<NoopRawMutex, ()>,
    /// façade → worker: 強制切断要求(ATT 応答待ち中でも効くよう Signal で割り込む)。
    force_dc: Signal<NoopRawMutex, ()>,
    /// adv report ハンドラ → worker: 直近の 0xFFF6 commissionable report。
    report: Signal<NoopRawMutex, ScanResult<PeerInfo>>,
}

impl CentralChannels {
    /// 全 channel を空で生成する。
    pub const fn new() -> Self {
        Self {
            cmd: Channel::new(),
            resp: Channel::new(),
            ind: Channel::new(),
            link_down: Signal::new(),
            force_dc: Signal::new(),
            report: Signal::new(),
        }
    }
}

impl Default for CentralChannels {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================================================
// adv report ハンドラ(bin が runner.run_with_handler に渡す)
// ==========================================================================

/// `Runner::run_with_handler` へ渡す adv report ハンドラ。
///
/// 0xFFF6 service data を持つ report を解析し、[`CentralChannels::report`] へ流す
/// (最新 1 件を Signal で上書き。フィルタ照合は worker 側)。
pub struct MatterAdvHandler<'ch> {
    ch: &'ch CentralChannels,
}

impl<'ch> MatterAdvHandler<'ch> {
    /// channel 一式を共有して生成する。
    pub fn new(ch: &'ch CentralChannels) -> Self {
        Self { ch }
    }
}

impl EventHandler for MatterAdvHandler<'_> {
    fn on_adv_reports(&self, mut reports: bt_hci::param::LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = reports.next() {
            for ad in AdStructure::decode(report.data).flatten() {
                // ServiceData16 の uuid は LE バイト列(0xFFF6 → [0xF6, 0xFF])。
                let AdStructure::ServiceData16 {
                    uuid: [0xF6, 0xFF],
                    data,
                } = ad
                else {
                    continue;
                };
                let Ok(sd): Result<[u8; 8], _> = data.try_into() else {
                    continue;
                };
                let Ok(adv) = AdvData::parse_service_data(&sd) else {
                    continue;
                };
                self.ch.report.signal(ScanResult {
                    discriminator: adv.discriminator,
                    vendor_id: adv.vendor_id,
                    product_id: adv.product_id,
                    handle: (report.addr_kind, report.addr),
                });
            }
        }
    }
}

// ==========================================================================
// GattCentral trait 実装(façade)
// ==========================================================================

/// [`GattCentral`] の TrouBLE 実装(channel の façade 側)。
///
/// [`central_worker`] と同じ [`CentralChannels`] を共有して生成し、統合層(bin)から
/// trait 経由で使う。`BtpConnId` は 1 起点 wrap 採番(peripheral 実装と同じ規約)。
pub struct TroubleGattCentral<'ch> {
    ch: &'ch CentralChannels,
    /// 現在アクティブな接続ハンドル(単一接続スコープ)。
    conn: Option<BtpConnId>,
    /// 次に採番する接続 index。
    next_conn: u8,
}

impl<'ch> TroubleGattCentral<'ch> {
    /// channel 一式を共有して生成する。
    pub fn new(ch: &'ch CentralChannels) -> Self {
        Self {
            ch,
            conn: None,
            next_conn: 1,
        }
    }

    /// 指定ハンドルが現接続か検査し、リンク断通知が来ていれば先に消化する。
    fn check_conn(&mut self, conn: BtpConnId) -> SmResult<()> {
        if self.ch.link_down.try_take().is_some() {
            self.conn = None;
        }
        if self.conn != Some(conn) {
            return Err(SmError::InvalidState);
        }
        Ok(())
    }
}

impl GattCentral for TroubleGattCentral<'_> {
    type PeerHandle = PeerInfo;

    async fn scan(&mut self, filter: ScanFilter) -> SmResult<ScanResult<PeerInfo>> {
        self.ch.cmd.send(CentralCmd::Scan { filter }).await;
        match self.ch.resp.receive().await {
            CentralResp::Scanned(r) => r,
            _ => Err(SmError::InvalidState),
        }
    }

    async fn connect(
        &mut self,
        target: &ScanResult<PeerInfo>,
    ) -> SmResult<(BtpConnId, Option<u16>)> {
        // 前接続の残骸(リンク断通知)を先に畳む。
        let _ = self.ch.link_down.try_take();
        self.conn = None;
        self.ch
            .cmd
            .send(CentralCmd::Connect {
                peer: target.handle,
            })
            .await;
        match self.ch.resp.receive().await {
            CentralResp::Connected(Ok(mtu)) => {
                let id = BtpConnId(self.next_conn);
                self.next_conn = self.next_conn.wrapping_add(1).max(1);
                self.conn = Some(id);
                Ok((id, mtu))
            }
            CentralResp::Connected(Err(e)) => Err(e),
            _ => Err(SmError::InvalidState),
        }
    }

    async fn write_c1(&mut self, conn: BtpConnId, frag: &[u8]) -> SmResult<()> {
        self.check_conn(conn)?;
        if frag.len() > MAX_FRAG {
            return Err(SmError::NoSpace);
        }
        let mut data = [0u8; MAX_FRAG];
        data[..frag.len()].copy_from_slice(frag);
        self.ch
            .cmd
            .send(CentralCmd::WriteC1 {
                len: frag.len(),
                data,
            })
            .await;
        match self.ch.resp.receive().await {
            CentralResp::Done(r) => r,
            _ => Err(SmError::InvalidState),
        }
    }

    async fn subscribe_c2(&mut self, conn: BtpConnId) -> SmResult<()> {
        self.check_conn(conn)?;
        self.ch.cmd.send(CentralCmd::SubscribeC2).await;
        match self.ch.resp.receive().await {
            CentralResp::Done(r) => r,
            _ => Err(SmError::InvalidState),
        }
    }

    async fn next_indication(&mut self, conn: BtpConnId, buf: &mut [u8]) -> SmResult<usize> {
        self.check_conn(conn)?;
        match select(self.ch.ind.receive(), self.ch.link_down.wait()).await {
            Either::First(ind) => {
                let dst = buf.get_mut(..ind.len).ok_or(SmError::NoSpace)?;
                dst.copy_from_slice(&ind.data[..ind.len]);
                Ok(ind.len)
            }
            Either::Second(()) => {
                self.conn = None;
                Err(SmError::InvalidState)
            }
        }
    }

    async fn disconnect(&mut self, _conn: BtpConnId) -> SmResult<()> {
        self.conn = None;
        self.ch.force_dc.signal(());
        Ok(())
    }
}

// ==========================================================================
// central ワーカー(TrouBLE 側)
// ==========================================================================

/// central ロールを駆動する常駐ワーカー。
///
/// bin 側で `runner.run_with_handler(&MatterAdvHandler)` と並走させる
/// (`embassy_futures::join`)。`stack` は [`GattClient::new`] の借用元
/// (`trouble_host::new(..)` の戻り値)を渡す。
pub async fn central_worker<'d, C>(
    stack: &'d Stack<'d, C, DefaultPacketPool>,
    mut central: Central<'d, C, DefaultPacketPool>,
    ch: &CentralChannels,
) -> !
where
    C: Controller
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdAsync<LeCreateConn>,
{
    loop {
        match ch.cmd.receive().await {
            CentralCmd::Scan { filter } => {
                let (c, result) = do_scan(central, ch, filter).await;
                central = c;
                ch.resp.send(CentralResp::Scanned(result)).await;
            }
            CentralCmd::Connect { peer } => {
                run_connection(stack, &mut central, ch, peer).await;
                // 接続スコープを抜けた = リンク断(正常切断含む)。façade へ通知する。
                ch.link_down.signal(());
            }
            // 未接続時の write / subscribe は契約違反(接続スコープ内で処理される)。
            CentralCmd::WriteC1 { .. } | CentralCmd::SubscribeC2 => {
                ch.resp
                    .send(CentralResp::Done(Err(SmError::InvalidState)))
                    .await;
            }
        }
    }
}

/// スキャンセッションを 1 回張り、フィルタ一致の report を待つ。
///
/// `Scanner` が `Central` を消費するため、所有権を受け取って返す。タイムアウトは
/// [`SCAN_TIMEOUT`](呼び出し側のリトライで再セッション = FilterDuplicates のリセット)。
async fn do_scan<'d, C>(
    central: Central<'d, C, DefaultPacketPool>,
    ch: &CentralChannels,
    filter: ScanFilter,
) -> (
    Central<'d, C, DefaultPacketPool>,
    SmResult<ScanResult<PeerInfo>>,
)
where
    C: Controller
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeSetScanEnable>,
{
    // 古い report(前セッションの残り)を捨てる。
    let _ = ch.report.try_take();
    let mut scanner = Scanner::new(central);
    let result = {
        // 既定 = active scan、interval 1s / window 1s(常時)。coex 中の WiFi との
        // 帯域折衝(R2)はコミッショニング時のみスキャンする統合層の方針で吸収する。
        let config = ScanConfig::default();
        match scanner.scan(&config).await {
            // _session の drop がスキャン停止(RAII)。
            Ok(_session) => {
                let matched = async {
                    loop {
                        let r = ch.report.wait().await;
                        let disc_ok = filter.discriminator.is_none_or(|d| d == r.discriminator);
                        let vp_ok = filter
                            .vendor_product
                            .is_none_or(|(v, p)| (v, p) == (r.vendor_id, r.product_id));
                        if disc_ok && vp_ok {
                            break r;
                        }
                    }
                };
                match with_timeout(SCAN_TIMEOUT, matched).await {
                    Ok(r) => Ok(r),
                    Err(_) => Err(SmError::NotFound),
                }
            }
            Err(_) => Err(SmError::InvalidState),
        }
    };
    (scanner.into_inner(), result)
}

/// 接続 1 本ぶんのスコープ: connect → MTU 交換 → discovery → コマンド/indication
/// 処理ループ。戻り = リンク断(呼び出し側が [`CentralChannels::link_down`] を送る)。
///
/// resp の欠落防止(モジュール doc 参照): cmd を消費したら `pending` を立て、resp を
/// 送ったら下ろす。cancel(接続断 / force_dc)でスコープを抜けた後、pending が残って
/// いれば失敗 resp を補填する。
async fn run_connection<'d, C>(
    stack: &'d Stack<'d, C, DefaultPacketPool>,
    central: &mut Central<'d, C, DefaultPacketPool>,
    ch: &CentralChannels,
    peer: PeerInfo,
) where
    C: Controller
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>,
{
    // 前接続の indication 残骸を捨てる(façade は connect 前に読み切らない)。
    while ch.ind.try_receive().is_ok() {}
    let _ = ch.force_dc.try_take();

    // --- LE 接続(accept-list 経由。空だと TrouBLE がエラーにする)---
    let (kind, addr) = peer;
    let list = [(kind, &addr)];
    let config = ConnectConfig {
        scan_config: ScanConfig {
            filter_accept_list: &list,
            ..Default::default()
        },
        connect_params: Default::default(),
    };
    let conn = match with_timeout(CONNECT_TIMEOUT, central.connect(&config)).await {
        Ok(Ok(c)) => c,
        Ok(Err(_)) => {
            ch.resp
                .send(CentralResp::Connected(Err(SmError::InvalidState)))
                .await;
            return;
        }
        Err(_) => {
            ch.resp
                .send(CentralResp::Connected(Err(SmError::InvalidState)))
                .await;
            return;
        }
    };

    // --- ATT MTU 交換(GattClient::new が応答までブロック。R4 = timeout でラップ)---
    let client: GattClient<'_, C, DefaultPacketPool, MAX_SERVICES> =
        match with_timeout(MTU_EXCHANGE_TIMEOUT, GattClient::new(stack, &conn)).await {
            Ok(Ok(c)) => c,
            Ok(Err(_)) | Err(_) => {
                conn.disconnect();
                ch.resp
                    .send(CentralResp::Connected(Err(SmError::InvalidState)))
                    .await;
                return;
            }
        };
    let att_mtu = conn.att_mtu();

    // 以降は GattClient::task()(ATT RX ポンプ)の並走が必須(discovery の応答も
    // これ経由)。force_dc はここで割り込む(コマンド処理がブロック中でも効く)。
    let pending: Cell<bool> = Cell::new(false);
    let session = async {
        // --- discovery: 0xFFF6 service → C1 / C2 characteristics ---
        let discovered = with_timeout(DISCOVERY_TIMEOUT, discover(&client)).await;
        let (c1, c2) = match discovered {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                ch.resp.send(CentralResp::Connected(Err(e))).await;
                return;
            }
            Err(_) => {
                ch.resp
                    .send(CentralResp::Connected(Err(SmError::InvalidState)))
                    .await;
                return;
            }
        };
        ch.resp
            .send(CentralResp::Connected(Ok(Some(att_mtu))))
            .await;

        // --- コマンド + indication 処理ループ(終了は外側 select の cancel のみ)---
        let mut listener: Option<NotificationListener<'_, 512>> = None;
        loop {
            match &mut listener {
                Some(l) => match select(ch.cmd.receive(), l.next()).await {
                    Either::First(cmd) => {
                        pending.set(true);
                        handle_cmd(&client, &c1, &c2, ch, &mut listener, cmd).await;
                        pending.set(false);
                    }
                    Either::Second(notif) => {
                        forward_indication(&client, ch, notif.as_ref()).await;
                    }
                },
                None => {
                    let cmd = ch.cmd.receive().await;
                    pending.set(true);
                    handle_cmd(&client, &c1, &c2, ch, &mut listener, cmd).await;
                    pending.set(false);
                }
            }
        }
    };

    match select3(client.task(), ch.force_dc.wait(), session).await {
        Either3::First(r) => {
            // ATT RX ポンプ終了 = リンク断(peripheral 側切断・監視タイムアウト)。
            println!("[central] link down ({:?})", r.err());
        }
        Either3::Second(()) => {
            println!("[central] disconnect requested");
            conn.disconnect();
        }
        Either3::Third(()) => {
            // discovery 失敗などスコープ内で完結した終了。
            conn.disconnect();
        }
    }
    // cancel されたコマンドの resp を補填する(façade の永久待ち防止)。
    if pending.get() {
        ch.resp
            .send(CentralResp::Done(Err(SmError::InvalidState)))
            .await;
    }
}

/// 0xFFF6 service と C1 / C2 characteristic を discovery する。
async fn discover<C: Controller>(
    client: &GattClient<'_, C, DefaultPacketPool, MAX_SERVICES>,
) -> SmResult<(Characteristic<[u8]>, Characteristic<[u8]>)> {
    let services = client
        .services_by_uuid(&Uuid::new_short(MATTER_SERVICE_UUID16))
        .await
        .map_err(|_| SmError::NotFound)?;
    let service = services.first().ok_or(SmError::NotFound)?.clone();
    let c1: Characteristic<[u8]> = client
        .characteristic_by_uuid(&service, &uuid128_le(&C1_UUID128))
        .await
        .map_err(|_| SmError::NotFound)?;
    let c2: Characteristic<[u8]> = client
        .characteristic_by_uuid(&service, &uuid128_le(&C2_UUID128))
        .await
        .map_err(|_| SmError::NotFound)?;
    Ok((c1, c2))
}

/// コアの UUID 定数(表示順 = ビッグエンディアン)を TrouBLE の [`Uuid`]
/// (ワイヤ順 = リトルエンディアン)へ変換する。
fn uuid128_le(be: &[u8; 16]) -> Uuid {
    let mut le = *be;
    le.reverse();
    Uuid::Uuid128(le)
}

/// 接続スコープ内のコマンド 1 件を処理する。
async fn handle_cmd<'a, C: Controller>(
    client: &'a GattClient<'_, C, DefaultPacketPool, MAX_SERVICES>,
    c1: &Characteristic<[u8]>,
    c2: &Characteristic<[u8]>,
    ch: &CentralChannels,
    listener: &mut Option<NotificationListener<'a, 512>>,
    cmd: CentralCmd,
) {
    match cmd {
        CentralCmd::WriteC1 { len, data } => {
            // ATT Write Request(応答待ち)。BTP はフラグメント順序が要なので
            // Write Without Response は使わない。
            let r = client
                .write_characteristic(c1, &data[..len])
                .await
                .map_err(|_| SmError::InvalidState);
            ch.resp.send(CentralResp::Done(r)).await;
        }
        CentralCmd::SubscribeC2 => {
            let r = match client.subscribe(c2, true).await {
                Ok(l) => {
                    *listener = Some(l);
                    Ok(())
                }
                Err(_) => Err(SmError::InvalidState),
            };
            ch.resp.send(CentralResp::Done(r)).await;
        }
        // 接続中の scan / connect は契約違反。
        CentralCmd::Scan { .. } => {
            ch.resp
                .send(CentralResp::Scanned(Err(SmError::InvalidState)))
                .await;
        }
        CentralCmd::Connect { .. } => {
            ch.resp
                .send(CentralResp::Connected(Err(SmError::InvalidState)))
                .await;
        }
    }
}

/// 受信 indication を façade へ転送し、ATT confirmation を返す。
///
/// 転送(`ind.send().await`)が先、confirm が後: ind channel が満杯でも confirm を
/// 遅らせるだけで、peripheral は次の indication を待つ(自然なフロー制御)。
async fn forward_indication<C: Controller>(
    client: &GattClient<'_, C, DefaultPacketPool, MAX_SERVICES>,
    ch: &CentralChannels,
    payload: &[u8],
) {
    let len = payload.len().min(MAX_FRAG);
    if payload.len() > MAX_FRAG {
        println!(
            "[central] oversized indication ({}B) truncated to {}B",
            payload.len(),
            MAX_FRAG
        );
    }
    let mut data = [0u8; MAX_FRAG];
    data[..len].copy_from_slice(&payload[..len]);
    ch.ind.send(Indication { len, data }).await;
    if client.confirm_indication().await.is_err() {
        println!("[central] confirm_indication failed");
    }
}
