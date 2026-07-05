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

use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use alloc::string::String;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::Timer;
use esp_println::println;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config, WifiController, WifiError};

use simple_matter::wifi::{WifiDriver, WifiStatus};

extern crate alloc;

/// join 要求(ConnectNetwork で受けた実 SSID / パスフレーズ)。
#[derive(Clone)]
pub struct WifiRequest {
    ssid: [u8; 32],
    ssid_len: usize,
    pass: [u8; 64],
    pass_len: usize,
}

impl WifiRequest {
    fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }
    fn pass(&self) -> &[u8] {
        &self.pass[..self.pass_len]
    }
}

/// 状態コード(`WIFI_STATE`)。[`WifiStatus`] への写像は [`EspWifiDriver::status`]。
const STATE_IDLE: u8 = 0;
const STATE_CONNECTING: u8 = 1;
const STATE_CONNECTED: u8 = 2;
const STATE_FAILED: u8 = 3;

/// ドライバハンドル(pump 内の cluster)→ [`wifi_task`] への join 要求。
static WIFI_REQUEST: Signal<CriticalSectionRawMutex, WifiRequest> = Signal::new();
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
        let mut req = WifiRequest {
            ssid: [0; 32],
            ssid_len: ssid.len().min(32),
            pass: [0; 64],
            pass_len: creds.len().min(64),
        };
        req.ssid[..req.ssid_len].copy_from_slice(&ssid[..req.ssid_len]);
        req.pass[..req.pass_len].copy_from_slice(&creds[..req.pass_len]);
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
                match select(
                    WIFI_REQUEST.wait(),
                    controller.wait_for_disconnect_async(),
                )
                .await
                {
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
