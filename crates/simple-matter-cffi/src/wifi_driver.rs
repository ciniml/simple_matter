//! WiFi プロビジョンの **take 方式** ドライバ(`docs/design/c-ffi-shim.md` §9.2)。
//!
//! コアの [`NetworkCommissioningWifi`](simple_matter::dm::clusters::NetworkCommissioningWifi) は
//! `ConnectNetwork` 受理で [`WifiDriver::connect`] を呼び「即 Success + バックグラウンド
//! join + 遅延 ConnectNetworkResponse」を行う。ESP-IDF 側の実 join(esp_wifi)は別タスク
//! だが、シムは単一インスタンス・単線契約なのでコールバックではなく **take 方式** で橋渡し
//! する:
//!
//! - `connect()`(IM ハンドラから同期呼び出し)は SSID/資格情報を内部に退避し、状態を
//!   [`WifiStatus::Connecting`] にして「未取り出しの要求」を立てる。統合層(housekeep)が
//!   これを見て `SM_EV_WIFI_CONNECT_REQUEST` イベントを立てる。
//! - C++ 側は [`crate::sm_take_wifi_request`] で SSID/pass を取り出し、esp_wifi で join する。
//! - join 結果は [`crate::sm_wifi_status`] が [`ShimWifiDriver::set_status`] を呼んで反映し、
//!   コアの `poll_deferred` が遅延 ConnectNetworkResponse を確定させる。

use simple_matter::wifi::{WifiDriver, WifiStatus};

/// take 方式の WiFi ドライバ(単線契約下でのみ使用)。
#[derive(Debug)]
pub struct ShimWifiDriver {
    ssid: [u8; 32],
    ssid_len: usize,
    creds: [u8; 64],
    creds_len: usize,
    /// C++ 側にまだ渡していない join 要求があるか(`sm_take_wifi_request` で降ろす)。
    pending: bool,
    /// 現在の join 状態(`sm_wifi_status` で更新)。
    status: WifiStatus,
}

impl ShimWifiDriver {
    /// 未接続・要求なしのドライバを作る。
    pub const fn new() -> Self {
        Self {
            ssid: [0u8; 32],
            ssid_len: 0,
            creds: [0u8; 64],
            creds_len: 0,
            pending: false,
            status: WifiStatus::Idle,
        }
    }

    /// C++ に渡していない join 要求があるか。
    pub fn has_pending(&self) -> bool {
        self.pending
    }

    /// 保留中の join 要求(SSID/資格情報)を取り出す。無ければ `None`。
    ///
    /// 取り出すと `pending` はクリアされる(状態 `Connecting` は維持。C++ の join 結果を待つ)。
    pub fn take_request(&mut self) -> Option<(&[u8], &[u8])> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        Some((&self.ssid[..self.ssid_len], &self.creds[..self.creds_len]))
    }

    /// C++ からの join 結果を反映する(`true`=Connected、`false`=Failed)。
    pub fn set_status(&mut self, connected: bool) {
        self.status = if connected {
            WifiStatus::Connected
        } else {
            // 失敗理由コードはプラットフォーム定義。take 方式では詳細を持たないため -1。
            WifiStatus::Failed { reason: -1 }
        };
    }
}

impl Default for ShimWifiDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiDriver for ShimWifiDriver {
    fn connect(&mut self, ssid: &[u8], creds: &[u8]) {
        let n = ssid.len().min(self.ssid.len());
        self.ssid[..n].copy_from_slice(&ssid[..n]);
        self.ssid_len = n;
        let m = creds.len().min(self.creds.len());
        self.creds[..m].copy_from_slice(&creds[..m]);
        self.creds_len = m;
        self.pending = true;
        self.status = WifiStatus::Connecting;
    }

    fn status(&self) -> WifiStatus {
        self.status
    }
}
