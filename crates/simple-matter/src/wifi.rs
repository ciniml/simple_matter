//! プラットフォーム Wi-Fi ドライバの最小抽象。
//!
//! `docs/design/port-esp32-device.md` §4 / §E5.1。NetworkCommissioning クラスタ
//! ([`crate::dm::clusters::NetworkCommissioningWifi`])がプラットフォームの実
//! Wi-Fi join を起動するための注入 trait。[`crate::kvs::Kvs`] /
//! [`crate::crypto::Rng`] と同じ「最小 trait + プラットフォーム注入」の流儀で、
//! trait 定義は依存ゼロ・no_std・alloc 非依存・feature ゲートなしで常時コンパイルされる。
//!
//! # 設計判断(doc §E5.1 / §E5.2)
//!
//! - **`connect` は開始のみ**(同期・非ブロッキング)。IM の invoke ハンドラは同期
//!   Mealy machine であり、join 完了(数秒)を待てない。実装は要求を記録して即返り、
//!   実際の association / DHCP はプラットフォーム側のタスクが進める。
//! - **エラーは `status()` に集約**する。`connect` は失敗しない(開始要求の記録に
//!   失敗する要素がない)。認証失敗・AP 不在などはすべて [`WifiStatus::Failed`] で
//!   後から観測される。
//! - ConnectNetworkResponse は「即 Success + バックグラウンド join」方式(doc §E5.2)。
//!   接続完了後の遅延応答は将来課題(現行 IM エンジンは 1 受信 1 応答)。

/// Wi-Fi 接続の現在状態([`WifiDriver::status`] が返す)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiStatus {
    /// 未接続(まだ `connect` が呼ばれていない、または切断済み)。
    Idle,
    /// join 進行中(association / DHCP 待ち)。
    Connecting,
    /// 接続済み(IP 到達可能)。
    Connected,
    /// join 失敗。`reason` はプラットフォーム定義のエラーコード
    /// (LastConnectErrorValue 属性へそのまま反映される)。
    Failed {
        /// プラットフォーム定義の失敗理由コード。
        reason: i32,
    },
}

/// WiFiSecurityBitmap(Matter Core Spec §11.8.5.2)の本実装で使う値。
///
/// [`WifiNetworkInfo::security`] / ScanNetworksResponse の
/// `WiFiInterfaceScanResultStruct.security`(tag 0、map8)に載る。
pub mod wifi_security {
    /// Unencrypted(bit 0)。
    pub const UNENCRYPTED: u8 = 0x01;
    /// WEP(bit 1)。
    pub const WEP: u8 = 0x02;
    /// WPA-Personal(bit 2)。
    pub const WPA_PERSONAL: u8 = 0x04;
    /// WPA2-Personal(bit 3)。既定の推定値。
    pub const WPA2_PERSONAL: u8 = 0x08;
    /// WPA3-Personal(bit 4)。
    pub const WPA3_PERSONAL: u8 = 0x10;
}

/// [`WifiDriver::current_network`] が情報を持たないときにクラスタが使う推定 RSSI(dBm)。
///
/// 「空の ScanNetworksResponse」よりコミッショナ(Alexa/Apple/Google)が先へ進める値
/// (`docs/design/airq-port.md` §9)。
pub const ESTIMATED_RSSI_DBM: i8 = -60;

/// 現在 join しているネットワークの情報([`WifiDriver::current_network`])。
///
/// ScanNetworksResponse の `WiFiInterfaceScanResultStruct`(§11.8.7.2)へそのまま
/// 写せる形。ヒープレス(固定長 SSID バッファ)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiNetworkInfo {
    /// SSID バイト列(先頭 `ssid_len` バイトが有効)。
    pub ssid: [u8; 32],
    /// `ssid` の有効長。
    pub ssid_len: usize,
    /// 接続先 AP の BSSID(不明なら `[0; 6]`)。
    pub bssid: [u8; 6],
    /// 動作チャネル(不明なら 0)。
    pub channel: u16,
    /// RSSI(dBm)。
    pub rssi: i8,
    /// WiFiSecurityBitmap([`wifi_security`])。
    pub security: u8,
}

impl WifiNetworkInfo {
    /// SSID + リンク情報から作る(SSID は 32 バイトへ切り詰め)。
    pub fn new(ssid: &[u8], bssid: [u8; 6], channel: u16, rssi: i8, security: u8) -> Self {
        let mut info = Self {
            ssid: [0u8; 32],
            ssid_len: ssid.len().min(32),
            bssid,
            channel,
            rssi,
            security,
        };
        info.ssid[..info.ssid_len].copy_from_slice(&ssid[..info.ssid_len]);
        info
    }

    /// ドライバがリンク情報を持たないときの推定エントリ
    /// (BSSID = 全 0、channel = 0、RSSI = [`ESTIMATED_RSSI_DBM`]、WPA2-Personal)。
    pub fn estimated(ssid: &[u8]) -> Self {
        Self::new(
            ssid,
            [0u8; 6],
            0,
            ESTIMATED_RSSI_DBM,
            wifi_security::WPA2_PERSONAL,
        )
    }

    /// 有効な SSID スライス。
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }
}

/// プラットフォームの Wi-Fi station ドライバ。
///
/// 実装例: ESP32 の esp-radio(要求を channel に置き、専用タスクが join を進める)、
/// PC の [`NullWifiDriver`](即 Connected のシム)。
pub trait WifiDriver {
    /// `ssid` / `creds`(WPA2/WPA3 パスフレーズ等)で join を**開始**する。
    ///
    /// 非ブロッキングであること(同期の IM ハンドラから呼ばれる)。完了・失敗は
    /// [`status`](WifiDriver::status) で観測する。接続中に再度呼ばれたら
    /// 新しいネットワークへ切り替える(re-join)。
    fn connect(&mut self, ssid: &[u8], creds: &[u8]);

    /// 現在の接続状態を返す。
    fn status(&self) -> WifiStatus;

    /// 現在 join しているネットワークの情報(SSID / BSSID / channel / RSSI)。
    ///
    /// NetworkCommissioning の `ScanNetworks` が、既に接続済みの AP を 1 件の
    /// `WiFiInterfaceScanResultStruct` として返すために使う(`docs/design/airq-port.md` §9)。
    /// 既定実装は `None`(未対応ドライバ)。`None` の場合でもクラスタは保持 SSID から
    /// 推定エントリ([`WifiNetworkInfo::estimated`])を組む。
    fn current_network(&self) -> Option<WifiNetworkInfo> {
        None
    }
}

impl<T: WifiDriver + ?Sized> WifiDriver for &mut T {
    fn connect(&mut self, ssid: &[u8], creds: &[u8]) {
        (**self).connect(ssid, creds)
    }
    fn status(&self) -> WifiStatus {
        (**self).status()
    }
    fn current_network(&self) -> Option<WifiNetworkInfo> {
        (**self).current_network()
    }
}

/// 「即 Connected」の Wi-Fi シムドライバ(実際には join しない)。
///
/// 用途は「BLE で PASE/CASE を張ったホストが、既に IP 到達可能なネットワーク上に
/// 居る」開発・相互運用シナリオ(PC の dual-transport example)。chip-tool の
/// AutoCommissioner が BLE 経由 commissionee に Wi-Fi/Thread を要求するポリシを
/// 満たすためだけのシムで、`connect` された瞬間に [`WifiStatus::Connected`] になる。
#[derive(Debug, Clone, Copy, Default)]
pub struct NullWifiDriver {
    connected: bool,
}

impl NullWifiDriver {
    /// 未接続状態のシムドライバを作る。
    pub const fn new() -> Self {
        Self { connected: false }
    }
}

impl WifiDriver for NullWifiDriver {
    fn connect(&mut self, _ssid: &[u8], _creds: &[u8]) {
        self.connected = true;
    }
    fn status(&self) -> WifiStatus {
        if self.connected {
            WifiStatus::Connected
        } else {
            WifiStatus::Idle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_driver_connects_immediately() {
        let mut d = NullWifiDriver::new();
        assert_eq!(d.status(), WifiStatus::Idle);
        d.connect(b"SSID", b"password");
        assert_eq!(d.status(), WifiStatus::Connected);
    }

    #[test]
    fn estimated_network_info_uses_documented_defaults() {
        let i = WifiNetworkInfo::estimated(b"iotap");
        assert_eq!(i.ssid(), b"iotap");
        assert_eq!(i.bssid, [0u8; 6]);
        assert_eq!(i.channel, 0);
        assert_eq!(i.rssi, ESTIMATED_RSSI_DBM);
        assert_eq!(i.security, wifi_security::WPA2_PERSONAL);
    }

    #[test]
    fn network_info_truncates_long_ssid() {
        let long = [b'a'; 48];
        let i = WifiNetworkInfo::new(
            &long,
            [1, 2, 3, 4, 5, 6],
            11,
            -42,
            wifi_security::WPA3_PERSONAL,
        );
        assert_eq!(i.ssid().len(), 32);
        assert_eq!(i.channel, 11);
        assert_eq!(i.rssi, -42);
    }

    /// 既定実装は `None`(未対応ドライバ)。
    #[test]
    fn null_driver_has_no_current_network() {
        let mut d = NullWifiDriver::new();
        d.connect(b"SSID", b"password");
        assert!(d.current_network().is_none());
    }

    /// `&mut T` へのブランケット実装が合成に使えることを型レベルで確認する。
    #[test]
    fn blanket_impl_compiles() {
        fn assert_driver(_: impl WifiDriver) {}
        let mut d = NullWifiDriver::new();
        assert_driver(&mut d);
    }
}
