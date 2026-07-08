//! コアの [`WifiDriver`] trait の esp-radio 実装(E5、doc §E5.4)。
//!
//! コアの `WifiDriver::connect` は同期・非ブロッキング(IM の invoke ハンドラから
//! 呼ばれる)だが、esp-radio の join(`WifiController::connect_async`)は async。
//! そこで実装を 2 つに割る:
//!
//! - [`EspWifiDriver`]: コア trait を実装するハンドル。`connect` は要求を
//!   [`Signal`] に置いて即返り、`status` は atomic な状態を読むだけ。
//! - [`wifi_task`]: `WifiController` を所有する常駐タスク(pump と並走)。要求を
//!   待って `set_config(Station)` → `connect_async()` を実行し、結果を状態へ
//!   書き戻す。切断時は同じネットワークへ自動再接続する。
//!
//! 状態は `AtomicU8`(+ 失敗理由の `AtomicI32`)で共有する(C6 = RV32IMAC は
//! ネイティブ atomic を持つ)。要求の SSID/パスフレーズは Signal のペイロードとして
//! 値渡しする(固定長バッファ、ヒープレス。esp-radio の `StationConfig` が要求する
//! `String` への変換は wifi_task 側でのみ行う)。

use core::cell::RefCell;
use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use alloc::string::String;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::Timer;
use esp_println::println;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config, WifiController, WifiError};

use simple_matter::wifi::{WifiDriver, WifiStatus};

extern crate alloc;

/// join 要求(ConnectNetwork で受けた実 SSID / パスフレーズ)。
#[derive(Clone, PartialEq, Eq)]
pub struct WifiRequest {
    ssid: [u8; 32],
    ssid_len: usize,
    pass: [u8; 64],
    pass_len: usize,
}

impl WifiRequest {
    /// 実効 SSID(有効長ぶんのスライス)。資格情報の永続化(統合層)にも使う。
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }
    /// 実効パスフレーズ(有効長ぶんのスライス)。資格情報の永続化(統合層)にも使う。
    pub fn pass(&self) -> &[u8] {
        &self.pass[..self.pass_len]
    }

    /// SSID / パスフレーズから要求を組む(長さは 32 / 64 バイトへ切り詰め)。
    ///
    /// [`EspWifiDriver::connect`] の内部組み立てと、KVS から復元した資格情報での
    /// 自動再 join(統合層)の両方が使う。
    pub fn new(ssid: &[u8], pass: &[u8]) -> Self {
        let mut req = WifiRequest {
            ssid: [0; 32],
            ssid_len: ssid.len().min(32),
            pass: [0; 64],
            pass_len: pass.len().min(64),
        };
        req.ssid[..req.ssid_len].copy_from_slice(&ssid[..req.ssid_len]);
        req.pass[..req.pass_len].copy_from_slice(&pass[..req.pass_len]);
        req
    }
}

/// 状態コード(`WIFI_STATE`)。[`WifiStatus`] への写像は [`EspWifiDriver::status`]。
const STATE_IDLE: u8 = 0;
const STATE_CONNECTING: u8 = 1;
const STATE_CONNECTED: u8 = 2;
const STATE_FAILED: u8 = 3;

/// ドライバハンドル(pump 内の cluster)→ [`wifi_task`] への join 要求。
static WIFI_REQUEST: Signal<CriticalSectionRawMutex, WifiRequest> = Signal::new();
/// 直近の join 要求の「永続化待ち」コピー(統合層が KVS 保存のために取り出す)。
///
/// [`WIFI_REQUEST`](Signal)とは別に持つ: Signal は wifi_task が consume するため、
/// 統合層(pump)が同じ要求を観測できない。こちらは [`take_pending_credentials`] が
/// 取り出すまで保持される(複数回 connect が来たら最新のみ残る = 保存すべきは最新)。
static WIFI_PENDING_SAVE: Mutex<CriticalSectionRawMutex, RefCell<Option<WifiRequest>>> =
    Mutex::new(RefCell::new(None));

/// 未保存の join 資格情報があれば取り出す(なければ `None`。取り出すと消える)。
///
/// 統合層(pump ループ)が poll し、KVS(キー `b"wifc"`)へ保存する。ConnectNetwork の
/// invoke ハンドラ(コア)には手を入れず、ポートローカルで資格情報の永続化を実現する。
pub fn take_pending_credentials() -> Option<WifiRequest> {
    WIFI_PENDING_SAVE.lock(|cell| cell.borrow_mut().take())
}
/// 現在 join 済み(または join 試行中)の要求。同一資格情報での再 join 要求を
/// no-op にする判定に使う([`EspWifiDriver::connect`] 参照)。
static WIFI_ACTIVE: Mutex<CriticalSectionRawMutex, RefCell<Option<WifiRequest>>> =
    Mutex::new(RefCell::new(None));
/// 現在の接続状態([`STATE_IDLE`] など)。
static WIFI_STATE: AtomicU8 = AtomicU8::new(STATE_IDLE);
/// 直近の失敗理由(esp-radio の DisconnectReason 由来のコード)。
static WIFI_FAIL_REASON: AtomicI32 = AtomicI32::new(0);

/// コアの [`WifiDriver`] を実装するハンドル(状態は上記 static と共有)。
///
/// ファームウェア全体で Wi-Fi station は 1 つなので、複数インスタンスを作っても
/// 同じ状態を指す(unit struct)。
#[derive(Debug, Default, Clone, Copy)]
pub struct EspWifiDriver;

impl WifiDriver for EspWifiDriver {
    fn connect(&mut self, ssid: &[u8], creds: &[u8]) {
        let req = WifiRequest::new(ssid, creds);
        // 統合層の永続化用コピー(take_pending_credentials で取り出す)。
        WIFI_PENDING_SAVE.lock(|cell| *cell.borrow_mut() = Some(req.clone()));
        // 同一資格情報で既に join 済み(または試行中)なら no-op。auto-join(KVS 復元)後の
        // 再コミッショニングで ConnectNetwork が同じ AP を指すケースで、接続済みリンクを
        // 落とさない(実測: BLE coex 中の re-join は失敗を繰り返し、ハングに至ることがある)。
        // status は Connected のままなので、遅延 ConnectNetworkResponse は即 Success になる。
        let state = WIFI_STATE.load(Ordering::Acquire);
        let same_active = WIFI_ACTIVE.lock(|cell| cell.borrow().as_ref() == Some(&req));
        if same_active && (state == STATE_CONNECTED || state == STATE_CONNECTING) {
            println!("[wifi] connect: same credentials already active; skipping re-join");
            return;
        }
        WIFI_ACTIVE.lock(|cell| *cell.borrow_mut() = Some(req.clone()));
        WIFI_STATE.store(STATE_CONNECTING, Ordering::Release);
        WIFI_REQUEST.signal(req);
    }

    fn status(&self) -> WifiStatus {
        match WIFI_STATE.load(Ordering::Acquire) {
            STATE_CONNECTING => WifiStatus::Connecting,
            STATE_CONNECTED => WifiStatus::Connected,
            STATE_FAILED => WifiStatus::Failed {
                reason: WIFI_FAIL_REASON.load(Ordering::Acquire),
            },
            _ => WifiStatus::Idle,
        }
    }
}

/// join 失敗の理由コード(LastConnectErrorValue へ反映される)。
fn error_code(e: &WifiError) -> i32 {
    match e {
        // DisconnectReason は fieldless enum なので判別値を素直に使う。
        WifiError::Disconnected(info) => info.reason as i32,
        _ => -1,
    }
}

/// Wi-Fi station を駆動する常駐タスク(pump と並走。doc §E5.4)。
///
/// [`EspWifiDriver::connect`] の要求を待ち、esp-radio の station 設定 → join を行う。
/// join 成功後は切断イベントを監視して自動再接続、失敗時は 3 秒後にリトライする。
/// いずれの待ちの間も新しい要求(別ネットワークへの re-join)を受け付ける。
pub async fn wifi_task(mut controller: WifiController<'_>) -> ! {
    let mut req = WIFI_REQUEST.wait().await;
    loop {
        WIFI_STATE.store(STATE_CONNECTING, Ordering::Release);
        let ssid_txt = core::str::from_utf8(req.ssid()).unwrap_or("<non-utf8>");
        println!("[wifi] connecting to \"{}\"...", ssid_txt);

        let config = Config::Station(
            StationConfig::default()
                .with_ssid(req.ssid())
                .with_password(String::from_utf8_lossy(req.pass()).into_owned()),
        );
        if let Err(e) = controller.set_config(&config) {
            println!("[wifi] set_config failed: {:?}", e);
            WIFI_FAIL_REASON.store(error_code(&e), Ordering::Release);
            WIFI_STATE.store(STATE_FAILED, Ordering::Release);
            req = WIFI_REQUEST.wait().await;
            continue;
        }

        match controller.connect_async().await {
            Ok(info) => {
                println!(
                    "[wifi] associated: ssid={:?} channel={}",
                    info.ssid, info.channel
                );
                WIFI_STATE.store(STATE_CONNECTED, Ordering::Release);
                // 切断イベント or 新しい join 要求を待つ。
                match select(WIFI_REQUEST.wait(), controller.wait_for_disconnect_async()).await {
                    Either::First(new_req) => req = new_req,
                    Either::Second(res) => {
                        println!("[wifi] disconnected: {:?}; rejoining", res);
                        // 同じネットワークへ再接続(req は保持したまま continue)。
                    }
                }
            }
            Err(e) => {
                println!("[wifi] join failed: {:?}", e);
                WIFI_FAIL_REASON.store(error_code(&e), Ordering::Release);
                WIFI_STATE.store(STATE_FAILED, Ordering::Release);
                // 3 秒後に同じネットワークへリトライ(間に新要求が来たら差し替え)。
                if let Either::First(new_req) =
                    select(WIFI_REQUEST.wait(), Timer::after_secs(3)).await
                {
                    req = new_req;
                }
            }
        }
    }
}
