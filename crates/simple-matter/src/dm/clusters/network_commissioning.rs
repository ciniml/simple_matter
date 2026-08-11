//! Network Commissioning クラスタ(0x0031、Matter Core Spec §11.8)。
//!
//! Ethernet / on-network 前提の最小実装。FeatureMap は Ethernet(bit 2 = `0x04`)のみを
//! 立て、`MaxNetworks = 1`、`Networks` は接続済みの単一 Ethernet インターフェースを表す
//! 1 エントリを返す。Wi-Fi/Thread 系コマンド(ScanNetworks / AddOrUpdateWiFiNetwork 等)は
//! Ethernet feature では非対応のため、受理コマンドを持たない(IM エンジンが
//! [`ImStatus::UnsupportedCommand`](crate::im::wire::ImStatus) を返す)。

use crate::cluster;
use crate::dm::clusters::cmd::{close_response, map_tlv, open_response, Fields};
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use crate::dm::{AttrWrite, DeferredPoll, ServerCluster};
use crate::im::wire::ImStatus;
use crate::thread::{NullThreadDriver, ThreadDriver, ThreadStatus};
use crate::tlv::{TlvReader, TlvTag};
use crate::wifi::{NullWifiDriver, WifiDriver, WifiStatus};

/// FeatureMap の Ethernet ビット(EN、bit 2)。
pub const FEATURE_ETHERNET: u32 = 0x04;

/// FeatureMap の Wi-Fi ビット(WI、bit 0)。
pub const FEATURE_WIFI: u32 = 0x01;

/// NetworkCommissioningStatusEnum(§11.8.5.1)。本実装で使う値のみ。
pub mod net_status {
    /// Success(0)。
    pub const SUCCESS: u8 = 0;
    /// NetworkIDNotFound(3)。
    pub const NETWORK_ID_NOT_FOUND: u8 = 3;
    /// OtherConnectionFailure(9)。ドライバの join 失敗を属性へ反映する際に使う。
    pub const OTHER_CONNECTION_FAILURE: u8 = 9;
}

/// Network Commissioning クラスタ(0x0031、Ethernet 最小)。
#[derive(Debug)]
pub struct NetworkCommissioning {
    /// Ethernet インターフェースの NetworkID(通常は MAC またはインターフェース名バイト)。
    network_id: &'static [u8],
    /// InterfaceEnabled(0x0004)。
    interface_enabled: bool,
}

impl NetworkCommissioning {
    /// Ethernet インターフェースの NetworkID を与えてクラスタを作る。
    pub const fn new(network_id: &'static [u8]) -> Self {
        Self {
            network_id,
            interface_enabled: true,
        }
    }

    /// InterfaceEnabled(0x0004)を書き込む。
    fn write_interface_enabled(
        &mut self,
        data: crate::dm::AttrWrite<'_>,
        _acc: &crate::dm::meta::AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data.as_bool()?;
        Ok(())
    }

    /// Networks(0x0001): NetworkInfoStruct `{ 0: networkID, 1: connected }` の配列。
    fn read_networks(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            a.push_struct(|s| {
                s.field_bytes(0, self.network_id)?;
                s.field_bool(1, true)
            })
        })
    }
}

cluster! {
    NetworkCommissioning {
        id: 0x0031,
        revision: 1,
        feature_map: 0x04,
        dirty: _,
        invoke: _,
        attributes: [
            0x0000 MaxNetworks {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_u8(1)),
                write: _
            },
            0x0001 Networks {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| c.read_networks(e)),
                write: _
            },
            0x0004 InterfaceEnabled {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_bool(c.interface_enabled)),
                write: (Administer, |c: &mut NetworkCommissioning, data, acc| c.write_interface_enabled(data, acc))
            },
            0x0005 LastNetworkingStatus {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
            0x0006 LastNetworkID {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
            0x0007 LastConnectErrorValue {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|_c: &NetworkCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_null()),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}

/// Network Commissioning クラスタ(0x0031、Wi-Fi。[`WifiDriver`] 注入型)。
///
/// FeatureMap は Wi-Fi(bit 0 = `0x01`)を立て、chip-tool の BLE→Wi-Fi コミッショニング
/// (`pairing ble-wifi`)が要求する NetworkCommissioning インターフェースを提供する。
/// 実際の無線 join はプラットフォーム注入の [`WifiDriver`] に委譲する
/// (`docs/design/port-esp32-device.md` §E5.3)。
///
/// # 応答タイミング(doc §E5.2)
///
/// `ConnectNetwork` は **`WifiDriver::connect()` を開始した上で即 Success を返す**
/// (バックグラウンド join)。現行 IM エンジンは 1 受信 1 応答の同期 Mealy machine で
/// 遅延 InvokeResponse を持たないため、join 完了後の応答は将来課題。join の失敗は
/// [`update_from_driver`](Self::update_from_driver) 経由で LastNetworkingStatus /
/// LastConnectErrorValue 属性に反映される。
///
/// # PC シム(既定型パラメータ)
///
/// 既定の `W = NullWifiDriver` は「即 Connected」のシム。用途は「BLE で PASE/CASE を
/// 張った PC が、既に IP 到達可能なネットワーク上に居る」開発・相互運用シナリオである。
/// chip-tool は BLE 経由の commissionee に対し Wi-Fi/Thread の NetworkCommissioning を
/// 要求する(`AutoCommissioner`: BLE→`mNeedsNetworkSetup=true`、
/// `IsSomeNetworkSupported` は wifi/thread のみ)ため、Ethernet feature だけでは
/// "does not support any network types" で失敗する。シムはこのポリシを満たすためだけの
/// 実装で、SSID / 資格情報は保存するが接続には使わない。
#[derive(Debug)]
pub struct NetworkCommissioningWifi<W: WifiDriver = NullWifiDriver> {
    /// AddOrUpdateWiFiNetwork で受理した SSID(NetworkID として使う)。最大 32 バイト。
    ssid: [u8; 32],
    /// `ssid` の有効長(0 なら未設定=ネットワーク無し)。
    ssid_len: usize,
    /// AddOrUpdateWiFiNetwork で受理した資格情報(WPA2/WPA3 パスフレーズ)。最大 64 バイト。
    creds: [u8; 64],
    /// `creds` の有効長。
    creds_len: usize,
    /// ConnectNetwork 済みか(Networks[].connected に反映)。
    connected: bool,
    /// InterfaceEnabled(0x0004)。
    interface_enabled: bool,
    /// LastNetworkingStatus(0x0005、未設定は null)。
    last_status: Option<u8>,
    /// LastConnectErrorValue(0x0007、未設定は null)。
    last_connect_error: Option<i32>,
    /// プラットフォーム Wi-Fi ドライバ(ConnectNetwork で join を開始する)。
    driver: W,
    /// 遅延 ConnectNetwork の残りリトライ回数(doc §E7.3)。
    ///
    /// 実機では BLE coex 中の最初の join 試行が過渡的に失敗しやすい
    /// (AuthenticationExpired 等。実測で 2 回目に成功)。`Failed` を 1 回観測しただけで
    /// 失敗応答を返すと chip-tool `pairing ble-wifi` が誤って失敗するため、
    /// `Failed` 観測時は残回数がある限り `driver.connect()` を再発行して `Pending` を
    /// 継続する。誤 SSID 等の恒常的失敗はリトライ消化後に失敗応答となる
    /// (2 リトライ ≒ 最悪 3 試行。エンジンの締切 20 秒に収まる)。
    connect_retries_left: u8,
}

/// 遅延 ConnectNetwork の join リトライ回数(初回試行を除く)。
const CONNECT_RETRIES: u8 = 2;

/// NetworkConfigResponse(0x05): `{ 0: networkingStatus, 2: networkIndex }`。
///
/// Wi-Fi / Thread 両クラスタで共有する(AddOrUpdate*/Remove*/Reorder の応答)。
fn write_network_config_response(
    resp: &mut CmdResponder<'_, '_>,
    status: u8,
    network_index: Option<u8>,
) -> Result<(), ImStatus> {
    let w = open_response(resp, 0x05)?;
    w.write_u8(&TlvTag::ContextSpecific(0), status)
        .map_err(map_tlv)?;
    if let Some(idx) = network_index {
        w.write_u8(&TlvTag::ContextSpecific(2), idx)
            .map_err(map_tlv)?;
    }
    close_response(w)
}

/// ConnectNetworkResponse(0x07): `{ 0: networkingStatus, 2: errorValue }`。
///
/// `error` が `Some(v)` なら errorValue=v(接続失敗理由)、`None` なら null(成功)。
/// errorValue は nullable かつ非 optional。Wi-Fi / Thread 両クラスタで共有する。
fn write_connect_response(
    resp: &mut CmdResponder<'_, '_>,
    status: u8,
    error: Option<i32>,
) -> Result<(), ImStatus> {
    let w = open_response(resp, 0x07)?;
    w.write_u8(&TlvTag::ContextSpecific(0), status)
        .map_err(map_tlv)?;
    match error {
        Some(v) => w
            .write_i32(&TlvTag::ContextSpecific(2), v)
            .map_err(map_tlv)?,
        None => w.write_null(&TlvTag::ContextSpecific(2)).map_err(map_tlv)?,
    }
    close_response(w)
}

/// ScanNetworksResponse(0x01): `{ 0: networkingStatus }`(空結果)。
///
/// Wi-Fi / Thread 両クラスタで共有する。
fn write_scan_response(resp: &mut CmdResponder<'_, '_>, status: u8) -> Result<(), ImStatus> {
    let w = open_response(resp, 0x01)?;
    w.write_u8(&TlvTag::ContextSpecific(0), status)
        .map_err(map_tlv)?;
    close_response(w)
}

impl Default for NetworkCommissioningWifi {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCommissioningWifi {
    /// Wi-Fi シミュレーションモード([`NullWifiDriver`])のクラスタを作る(ネットワーク未設定)。
    pub const fn new() -> Self {
        Self::with_driver(NullWifiDriver::new())
    }
}

impl<W: WifiDriver> NetworkCommissioningWifi<W> {
    /// プラットフォームの [`WifiDriver`] を注入してクラスタを作る(ネットワーク未設定)。
    pub const fn with_driver(driver: W) -> Self {
        Self {
            ssid: [0u8; 32],
            ssid_len: 0,
            creds: [0u8; 64],
            creds_len: 0,
            connected: false,
            interface_enabled: true,
            last_status: None,
            last_connect_error: None,
            driver,
            connect_retries_left: CONNECT_RETRIES,
        }
    }

    /// 注入されたドライバへの参照。
    pub fn driver(&self) -> &W {
        &self.driver
    }

    /// 注入されたドライバへの可変参照。
    pub fn driver_mut(&mut self) -> &mut W {
        &mut self.driver
    }

    /// ドライバの [`WifiDriver::status`] を属性へ反映する(統合層が定期的に呼ぶ)。
    ///
    /// ConnectNetworkResponse は即 Success で返すため(doc §E5.2)、バックグラウンド
    /// join の結果はこの経路でしか属性に現れない。`Connected` で Networks[].connected を
    /// 立て、`Failed` で LastNetworkingStatus=OtherConnectionFailure /
    /// LastConnectErrorValue=reason を記録する。
    pub fn update_from_driver(&mut self) {
        match self.driver.status() {
            WifiStatus::Connected => {
                self.connected = true;
            }
            WifiStatus::Failed { reason } => {
                self.connected = false;
                self.last_status = Some(net_status::OTHER_CONNECTION_FAILURE);
                self.last_connect_error = Some(reason);
            }
            WifiStatus::Idle | WifiStatus::Connecting => {}
        }
    }

    /// 現在保持している SSID(= NetworkID)スライス。
    fn network_id(&self) -> &[u8] {
        &self.ssid[..self.ssid_len]
    }

    /// 受理した SSID/NetworkID を保存する(最大 32 バイトに切り詰め)。
    fn set_ssid(&mut self, ssid: &[u8]) {
        let n = ssid.len().min(self.ssid.len());
        self.ssid[..n].copy_from_slice(&ssid[..n]);
        self.ssid_len = n;
    }

    /// 受理した資格情報を保存する(最大 64 バイトに切り詰め)。
    fn set_creds(&mut self, creds: &[u8]) {
        let n = creds.len().min(self.creds.len());
        self.creds[..n].copy_from_slice(&creds[..n]);
        self.creds_len = n;
    }

    /// InterfaceEnabled(0x0004)を書き込む。
    fn write_interface_enabled(
        &mut self,
        data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data.as_bool()?;
        Ok(())
    }

    /// Networks(0x0001): 設定済みなら `{ 0: SSID, 1: connected }` 1 エントリ、未設定は空配列。
    fn read_networks(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            if self.ssid_len > 0 {
                a.push_struct(|s| {
                    s.field_bytes(0, self.network_id())?;
                    s.field_bool(1, self.connected)
                })?;
            }
            Ok(())
        })
    }

    /// LastNetworkingStatus(0x0005、nullable enum8)。
    fn read_last_status(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.last_status {
            Some(v) => e.write_u8(v),
            None => e.write_null(),
        }
    }

    /// LastNetworkID(0x0006、nullable octstr)。
    fn read_last_network_id(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        if self.ssid_len > 0 {
            e.write_bytes(self.network_id())
        } else {
            e.write_null()
        }
    }

    /// LastConnectErrorValue(0x0007、nullable int32)。
    fn read_last_connect_error(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.last_connect_error {
            Some(v) => e.write_i32(v),
            None => e.write_null(),
        }
    }

    /// SupportedWiFiBands(0x0008): WiFiBandEnum の配列。2.4GHz(0)のみを提示する。
    fn read_supported_bands(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| a.push_u32(0))
    }

    /// 最初の context タグ付き octstr フィールド(tag=0)を取り出す。
    fn first_octstr<'a>(fields: &mut TlvReader<'a>) -> Option<&'a [u8]> {
        Self::octstr_fields(fields).0
    }

    /// context タグ 0(SSID/NetworkID)と 1(credentials)の octstr を取り出す。
    fn octstr_fields<'a>(fields: &mut TlvReader<'a>) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
        let mut ssid = None;
        let mut creds = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match tag {
                0 => ssid = v.as_bytes().ok(),
                1 => creds = v.as_bytes().ok(),
                _ => {}
            }
        }
        (ssid, creds)
    }

    /// コマンドを処理する。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            // ScanNetworks(0x00): シム。空結果で Success を返す(chip-tool は既定でスキップ)。
            0x00 => write_scan_response(resp, net_status::SUCCESS),
            // AddOrUpdateWiFiNetwork(0x02): SSID + credentials を保存し
            // NetworkConfigResponse(Success, idx 0)。join はまだ開始しない。
            0x02 => {
                let (ssid, creds) = Self::octstr_fields(fields);
                if let Some(ssid) = ssid {
                    self.set_ssid(ssid);
                }
                if let Some(creds) = creds {
                    self.set_creds(creds);
                }
                self.connected = false;
                self.last_status = Some(net_status::SUCCESS);
                write_network_config_response(resp, net_status::SUCCESS, Some(0))
            }
            // RemoveNetwork(0x04): 保持 SSID と一致すれば削除。最小実装。
            0x04 => {
                let matches = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.ssid_len > 0)
                    .unwrap_or(false);
                if matches {
                    self.ssid_len = 0;
                    self.connected = false;
                    write_network_config_response(resp, net_status::SUCCESS, Some(0))
                } else {
                    write_network_config_response(resp, net_status::NETWORK_ID_NOT_FOUND, None)
                }
            }
            // ConnectNetwork(0x06): ドライバの join を **開始** し、応答は **保留(遅延)** する
            // (doc §E7.3)。join 完了/失敗は poll_deferred で観測し、その時点で
            // ConnectNetworkResponse を返す。既知 SSID でない場合のみ即 NETWORK_ID_NOT_FOUND。
            0x06 => {
                let known = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.ssid_len > 0)
                    .unwrap_or(self.ssid_len > 0);
                if known {
                    self.driver
                        .connect(&self.ssid[..self.ssid_len], &self.creds[..self.creds_len]);
                    self.connect_retries_left = CONNECT_RETRIES;
                    // 応答は join 完了後(poll_deferred)。ここでは connected/last_status を触らない。
                    resp.set_deferred();
                    Ok(())
                } else {
                    self.last_status = Some(net_status::NETWORK_ID_NOT_FOUND);
                    write_connect_response(resp, net_status::NETWORK_ID_NOT_FOUND, None)
                }
            }
            // ReorderNetwork(0x08): 単一ネットワークなので常に Success。
            0x08 => write_network_config_response(resp, net_status::SUCCESS, Some(0)),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

/// [`NetworkCommissioningWifi`] のクラスタメタ(全 `W` で共有)。
///
/// `cluster!` マクロは非ジェネリック型専用のため、[`ServerCluster`] は
/// `OpCredsCluster` と同様に手書きで実装する(doc §E5.3)。属性・コマンドの宣言内容は
/// マクロ版シム(E5 以前)と同一。
static NETCOMM_WIFI_META: ClusterMeta = ClusterMeta::new(
    ClusterId(0x0031),
    1,
    FEATURE_WIFI,
    &[
        // 0x0000 MaxNetworks
        AttributeMeta::new(
            AttributeId(0x0000),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0001 Networks
        AttributeMeta::new(
            AttributeId(0x0001),
            Privilege::Administer,
            Quality::NONE,
            true,
            false,
            false,
        ),
        // 0x0002 ScanMaxTimeSeconds
        AttributeMeta::new(
            AttributeId(0x0002),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0003 ConnectMaxTimeSeconds
        AttributeMeta::new(
            AttributeId(0x0003),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0004 InterfaceEnabled(書き込み可、write は Administer)
        AttributeMeta::new(
            AttributeId(0x0004),
            Privilege::Administer,
            Quality::NONE,
            true,
            true,
            false,
        )
        .with_write_access(Privilege::Administer),
        // 0x0005 LastNetworkingStatus
        AttributeMeta::new(
            AttributeId(0x0005),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0006 LastNetworkID
        AttributeMeta::new(
            AttributeId(0x0006),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0007 LastConnectErrorValue
        AttributeMeta::new(
            AttributeId(0x0007),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0008 SupportedWiFiBands
        AttributeMeta::new(
            AttributeId(0x0008),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
    ],
    &[
        // ScanNetworks / AddOrUpdateWiFiNetwork / RemoveNetwork / ConnectNetwork / ReorderNetwork
        // (いずれも仕様 §11.8 の必要権限は Administer)
        CommandMeta::new(CommandId(0x00), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x02), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x04), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x06), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x08), false, Privilege::Administer),
    ],
    &[CommandId(0x01), CommandId(0x05), CommandId(0x07)],
);

impl<W: WifiDriver> ServerCluster for NetworkCommissioningWifi<W> {
    fn meta(&self) -> &'static ClusterMeta {
        &NETCOMM_WIFI_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => enc.write_u8(1),
            0x0001 => self.read_networks(enc),
            0x0002 => enc.write_u8(10),
            0x0003 => enc.write_u8(30),
            0x0004 => enc.write_bool(self.interface_enabled),
            0x0005 => self.read_last_status(enc),
            0x0006 => self.read_last_network_id(enc),
            0x0007 => self.read_last_connect_error(enc),
            0x0008 => self.read_supported_bands(enc),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: AttrWrite<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0004 => self.write_interface_enabled(data, acc),
            _ => Err(ImStatus::UnsupportedWrite),
        }
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.invoke_cmd(cmd, fields, resp, acc)
    }

    /// 遅延した ConnectNetwork の完了を問い合わせる(doc §E7.3)。
    ///
    /// driver の [`WifiStatus`] を見て:
    /// - `Connected` → ConnectNetworkResponse(Success)。`connected`/`last_status` も更新。
    /// - `Failed { reason }` → ConnectNetworkResponse(OtherConnectionFailure, errorValue=reason)。
    /// - `Connecting`(および `Idle`)→ [`DeferredPoll::Pending`]。
    fn poll_deferred(
        &mut self,
        command: CommandId,
        resp: &mut CmdResponder<'_, '_>,
    ) -> DeferredPoll {
        // ConnectNetwork(0x06)以外は遅延しないため、防御的に Failure で確定させる。
        if command.0 != 0x06 {
            return DeferredPoll::Ready(Err(ImStatus::Failure));
        }
        match self.driver.status() {
            WifiStatus::Connected => {
                self.connected = true;
                self.last_status = Some(net_status::SUCCESS);
                self.last_connect_error = None;
                match write_connect_response(resp, net_status::SUCCESS, None) {
                    Ok(()) => DeferredPoll::Ready(Ok(())),
                    Err(s) => DeferredPoll::Ready(Err(s)),
                }
            }
            WifiStatus::Failed { reason } => {
                // 過渡的失敗のリトライ(doc §E7.3): 残回数がある限り join を再発行して保留を続ける。
                if self.connect_retries_left > 0 {
                    self.connect_retries_left -= 1;
                    self.driver
                        .connect(&self.ssid[..self.ssid_len], &self.creds[..self.creds_len]);
                    return DeferredPoll::Pending;
                }
                self.connected = false;
                self.last_status = Some(net_status::OTHER_CONNECTION_FAILURE);
                self.last_connect_error = Some(reason);
                match write_connect_response(
                    resp,
                    net_status::OTHER_CONNECTION_FAILURE,
                    Some(reason),
                ) {
                    Ok(()) => DeferredPoll::Ready(Ok(())),
                    Err(s) => DeferredPoll::Ready(Err(s)),
                }
            }
            WifiStatus::Idle | WifiStatus::Connecting => DeferredPoll::Pending,
        }
    }
}

// ==========================================================================
// NetworkCommissioningThread(Thread。ThreadDriver 注入型)
// ==========================================================================

/// FeatureMap の Thread ビット(TH、bit 1)。
pub const FEATURE_THREAD: u32 = 0x02;

/// Network Commissioning クラスタ(0x0031、Thread。[`ThreadDriver`] 注入型)。
///
/// FeatureMap は Thread(bit 1 = `0x02`)を立て、chip-tool の BLE→Thread コミッショニング
/// (`pairing ble-thread`)が要求する NetworkCommissioning インターフェースを提供する。
/// 実際の MLE attach はプラットフォーム注入の [`ThreadDriver`] に委譲する
/// (`docs/design/thread-port.md` §4.2)。[`NetworkCommissioningWifi`] の兄弟で、
/// 差分は次のとおり:
///
/// - FeatureMap = `FEATURE_THREAD`。
/// - 追加コマンド 0x03 AddOrUpdateThreadNetwork(tag0 = OperationalDataset TLV)。
/// - NetworkID = Extended PAN ID(8B。dataset TLV から抽出)。
/// - 属性 0x0009 SupportedThreadFeatures / 0x000A ThreadVersion(0x0008 SupportedWiFiBands の代替)。
///
/// # 応答タイミング(Wi-Fi 版 §E5.2 と同じ)
///
/// `ConnectNetwork` は **`ThreadDriver::connect()` で attach を開始した上で応答を保留**
/// (deferred)し、attach 完了(role=Child/Router/Leader)を [`poll_deferred`] で観測して
/// ConnectNetworkResponse を返す。
///
/// [`poll_deferred`]: ServerCluster::poll_deferred
#[derive(Debug)]
pub struct NetworkCommissioningThread<D: ThreadDriver = NullThreadDriver> {
    /// AddOrUpdateThreadNetwork で受理した dataset の Extended PAN ID(NetworkID)。
    ext_pan_id: [u8; 8],
    /// ネットワークが設定済みか(`ext_pan_id` が有効か)。
    has_network: bool,
    /// ConnectNetwork 済みか(Networks[].connected に反映)。
    connected: bool,
    /// InterfaceEnabled(0x0004)。
    interface_enabled: bool,
    /// LastNetworkingStatus(0x0005、未設定は null)。
    last_status: Option<u8>,
    /// LastConnectErrorValue(0x0007、未設定は null)。
    last_connect_error: Option<i32>,
    /// プラットフォーム Thread ドライバ(ConnectNetwork で attach を開始する)。
    driver: D,
    /// 遅延 ConnectNetwork の残りリトライ回数(Wi-Fi 版 §E7.3 と同じ)。
    connect_retries_left: u8,
}

impl Default for NetworkCommissioningThread {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCommissioningThread {
    /// Thread シミュレーションモード([`NullThreadDriver`])のクラスタを作る(未設定)。
    pub const fn new() -> Self {
        Self::with_driver(NullThreadDriver::new())
    }
}

impl<D: ThreadDriver> NetworkCommissioningThread<D> {
    /// プラットフォームの [`ThreadDriver`] を注入してクラスタを作る(未設定)。
    pub const fn with_driver(driver: D) -> Self {
        Self {
            ext_pan_id: [0u8; 8],
            has_network: false,
            connected: false,
            interface_enabled: true,
            last_status: None,
            last_connect_error: None,
            driver,
            connect_retries_left: CONNECT_RETRIES,
        }
    }

    /// 注入されたドライバへの参照。
    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// 注入されたドライバへの可変参照。
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// ドライバの [`ThreadDriver::status`] を属性へ反映する(統合層が定期的に呼ぶ)。
    pub fn update_from_driver(&mut self) {
        match self.driver.status() {
            ThreadStatus::Attached => {
                self.connected = true;
            }
            ThreadStatus::Failed { reason } => {
                self.connected = false;
                self.last_status = Some(net_status::OTHER_CONNECTION_FAILURE);
                self.last_connect_error = Some(reason);
            }
            ThreadStatus::Idle | ThreadStatus::Attaching => {}
        }
    }

    /// 現在の NetworkID(= Extended PAN ID)スライス(未設定なら空)。
    fn network_id(&self) -> &[u8] {
        if self.has_network {
            &self.ext_pan_id
        } else {
            &[]
        }
    }

    /// InterfaceEnabled(0x0004)を書き込む。
    fn write_interface_enabled(
        &mut self,
        data: AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data.as_bool()?;
        Ok(())
    }

    /// Networks(0x0001): 設定済みなら `{ 0: ExtPanID, 1: connected }` 1 エントリ、未設定は空配列。
    fn read_networks(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            if self.has_network {
                a.push_struct(|s| {
                    s.field_bytes(0, self.network_id())?;
                    s.field_bool(1, self.connected)
                })?;
            }
            Ok(())
        })
    }

    /// LastNetworkingStatus(0x0005、nullable enum8)。
    fn read_last_status(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.last_status {
            Some(v) => e.write_u8(v),
            None => e.write_null(),
        }
    }

    /// LastNetworkID(0x0006、nullable octstr)。
    fn read_last_network_id(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        if self.has_network {
            e.write_bytes(self.network_id())
        } else {
            e.write_null()
        }
    }

    /// LastConnectErrorValue(0x0007、nullable int32)。
    fn read_last_connect_error(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.last_connect_error {
            Some(v) => e.write_i32(v),
            None => e.write_null(),
        }
    }

    /// 最初の context タグ 0(octstr)を取り出す(AddOrUpdateThreadNetwork の dataset /
    /// RemoveNetwork・ConnectNetwork の networkID)。
    fn first_octstr<'a>(fields: &mut TlvReader<'a>) -> Option<&'a [u8]> {
        let mut out = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                out = v.as_bytes().ok();
            }
        }
        out
    }

    /// コマンドを処理する。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            // ScanNetworks(0x00): シム。空結果で Success(chip-tool は既定でスキップ)。
            0x00 => write_scan_response(resp, net_status::SUCCESS),
            // AddOrUpdateThreadNetwork(0x03): dataset(tag0)を driver へ投入し ExtPanID を保存。
            // NetworkConfigResponse(Success, idx 0)。attach はまだ開始しない。
            0x03 => {
                let dataset = Self::first_octstr(fields);
                match dataset {
                    Some(tlv) => match self.driver.set_dataset(tlv) {
                        Ok(ext_pan_id) => {
                            self.ext_pan_id = ext_pan_id;
                            self.has_network = true;
                            self.connected = false;
                            self.last_status = Some(net_status::SUCCESS);
                            write_network_config_response(resp, net_status::SUCCESS, Some(0))
                        }
                        Err(_) => {
                            self.last_status = Some(net_status::OTHER_CONNECTION_FAILURE);
                            write_network_config_response(
                                resp,
                                net_status::OTHER_CONNECTION_FAILURE,
                                None,
                            )
                        }
                    },
                    None => write_network_config_response(
                        resp,
                        net_status::OTHER_CONNECTION_FAILURE,
                        None,
                    ),
                }
            }
            // RemoveNetwork(0x04): 保持 ExtPanID と一致すれば削除。
            0x04 => {
                let matches = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.has_network)
                    .unwrap_or(false);
                if matches {
                    self.has_network = false;
                    self.connected = false;
                    write_network_config_response(resp, net_status::SUCCESS, Some(0))
                } else {
                    write_network_config_response(resp, net_status::NETWORK_ID_NOT_FOUND, None)
                }
            }
            // ConnectNetwork(0x06): driver の attach を **開始** し、応答は **保留(遅延)**。
            // 照合キーは ExtPanID。未設定/不一致は即 NETWORK_ID_NOT_FOUND。
            0x06 => {
                let known = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.has_network)
                    .unwrap_or(self.has_network);
                if known {
                    self.driver.connect();
                    self.connect_retries_left = CONNECT_RETRIES;
                    resp.set_deferred();
                    Ok(())
                } else {
                    self.last_status = Some(net_status::NETWORK_ID_NOT_FOUND);
                    write_connect_response(resp, net_status::NETWORK_ID_NOT_FOUND, None)
                }
            }
            // ReorderNetwork(0x08): 単一ネットワークなので常に Success。
            0x08 => write_network_config_response(resp, net_status::SUCCESS, Some(0)),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

/// [`NetworkCommissioningThread`] のクラスタメタ(全 `D` で共有)。
///
/// Wi-Fi 版と同様に手書き。属性 0x0008 SupportedWiFiBands の代わりに 0x0009
/// SupportedThreadFeatures / 0x000A ThreadVersion を持ち、受理コマンドは
/// 0x02 の代わりに 0x03(AddOrUpdateThreadNetwork)。
static NETCOMM_THREAD_META: ClusterMeta = ClusterMeta::new(
    ClusterId(0x0031),
    1,
    FEATURE_THREAD,
    &[
        // 0x0000 MaxNetworks
        AttributeMeta::new(
            AttributeId(0x0000),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0001 Networks
        AttributeMeta::new(
            AttributeId(0x0001),
            Privilege::Administer,
            Quality::NONE,
            true,
            false,
            false,
        ),
        // 0x0002 ScanMaxTimeSeconds
        AttributeMeta::new(
            AttributeId(0x0002),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0003 ConnectMaxTimeSeconds
        AttributeMeta::new(
            AttributeId(0x0003),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x0004 InterfaceEnabled(書き込み可)
        AttributeMeta::new(
            AttributeId(0x0004),
            Privilege::Administer,
            Quality::NONE,
            true,
            true,
            false,
        )
        .with_write_access(Privilege::Administer),
        // 0x0005 LastNetworkingStatus
        AttributeMeta::new(
            AttributeId(0x0005),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0006 LastNetworkID
        AttributeMeta::new(
            AttributeId(0x0006),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0007 LastConnectErrorValue
        AttributeMeta::new(
            AttributeId(0x0007),
            Privilege::Administer,
            Quality::NULLABLE,
            true,
            false,
            false,
        ),
        // 0x0009 SupportedThreadFeatures(map16)
        AttributeMeta::new(
            AttributeId(0x0009),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
        // 0x000A ThreadVersion(uint16)
        AttributeMeta::new(
            AttributeId(0x000A),
            Privilege::Administer,
            Quality::FIXED,
            true,
            false,
            false,
        ),
    ],
    &[
        // ScanNetworks / AddOrUpdateThreadNetwork / RemoveNetwork / ConnectNetwork / ReorderNetwork
        CommandMeta::new(CommandId(0x00), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x03), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x04), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x06), false, Privilege::Administer),
        CommandMeta::new(CommandId(0x08), false, Privilege::Administer),
    ],
    &[CommandId(0x01), CommandId(0x05), CommandId(0x07)],
);

impl<D: ThreadDriver> ServerCluster for NetworkCommissioningThread<D> {
    fn meta(&self) -> &'static ClusterMeta {
        &NETCOMM_THREAD_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0000 => enc.write_u8(1),
            0x0001 => self.read_networks(enc),
            0x0002 => enc.write_u8(10),
            0x0003 => enc.write_u8(30),
            0x0004 => enc.write_bool(self.interface_enabled),
            0x0005 => self.read_last_status(enc),
            0x0006 => self.read_last_network_id(enc),
            0x0007 => self.read_last_connect_error(enc),
            // SupportedThreadFeatures: MTD rx-on(border-router/router/sleepy 非対応)= 0。
            0x0009 => enc.write_u16(0),
            // ThreadVersion: Thread 1.3 = 4。
            0x000A => enc.write_u16(4),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }

    fn write_attribute(
        &mut self,
        attr: AttributeId,
        data: AttrWrite<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x0004 => self.write_interface_enabled(data, acc),
            _ => Err(ImStatus::UnsupportedWrite),
        }
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.invoke_cmd(cmd, fields, resp, acc)
    }

    /// 遅延した ConnectNetwork の完了を問い合わせる(Wi-Fi 版 §E7.3 と同じ)。
    fn poll_deferred(
        &mut self,
        command: CommandId,
        resp: &mut CmdResponder<'_, '_>,
    ) -> DeferredPoll {
        if command.0 != 0x06 {
            return DeferredPoll::Ready(Err(ImStatus::Failure));
        }
        match self.driver.status() {
            ThreadStatus::Attached => {
                self.connected = true;
                self.last_status = Some(net_status::SUCCESS);
                self.last_connect_error = None;
                match write_connect_response(resp, net_status::SUCCESS, None) {
                    Ok(()) => DeferredPoll::Ready(Ok(())),
                    Err(s) => DeferredPoll::Ready(Err(s)),
                }
            }
            ThreadStatus::Failed { reason } => {
                // 過渡的失敗のリトライ: 残回数がある限り attach を再発行して保留を続ける。
                if self.connect_retries_left > 0 {
                    self.connect_retries_left -= 1;
                    self.driver.connect();
                    return DeferredPoll::Pending;
                }
                self.connected = false;
                self.last_status = Some(net_status::OTHER_CONNECTION_FAILURE);
                self.last_connect_error = Some(reason);
                match write_connect_response(
                    resp,
                    net_status::OTHER_CONNECTION_FAILURE,
                    Some(reason),
                ) {
                    Ok(()) => DeferredPoll::Ready(Ok(())),
                    Err(s) => DeferredPoll::Ready(Err(s)),
                }
            }
            ThreadStatus::Idle | ThreadStatus::Attaching => DeferredPoll::Pending,
        }
    }
}

#[cfg(test)]
mod wifi_tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AttributeId, Privilege, SessionKind};
    use crate::dm::{DeferredPoll, ServerCluster};
    use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, None, 0, Privilege::Administer)
    }

    /// フィールド構造体 `{ 0: ssid }`(context タグ 1 のコマンドフィールド構造体)を書く。
    fn write_ssid_fields(buf: &mut [u8], ssid: &[u8]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_struct(&TlvTag::ContextSpecific(1)).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(0), ssid).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    /// 応答匿名構造体から context タグ `t` の値を取り出す。
    fn resp_field(bytes: &[u8], t: u8) -> Option<TlvValue<'_>> {
        let mut r = TlvReader::new(bytes);
        let head = r.read_next().ok()??;
        assert!(matches!(
            head.value,
            TlvValue::ContainerStart(ContainerType::Structure)
        ));
        loop {
            let e = r.read_next().ok()??;
            match e.value {
                TlvValue::ContainerEnd => return None,
                v => {
                    if e.tag == TlvTag::ContextSpecific(t) {
                        return Some(v);
                    }
                }
            }
        }
    }

    fn invoke<W: WifiDriver>(
        net: &mut NetworkCommissioningWifi<W>,
        cmd: u32,
        ssid: &[u8],
    ) -> (u32, [u8; 64], usize) {
        let mut fbuf = [0u8; 96];
        let flen = write_ssid_fields(&mut fbuf, ssid);
        // フィールド構造体(context タグ 1)を指す reader を作る。
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(cmd), &mut fr, &mut resp, &acc())
            .unwrap();
        let rid = resp.response_command().unwrap().0;
        let wlen = w.len();
        (rid, out, wlen)
    }

    /// ConnectNetwork(0x06)を起動する。既知 SSID なら応答は **保留(deferred)** される
    /// (doc §E7.3)。deferred フラグと「即時応答が無い」ことを確認する。
    fn start_connect<W: WifiDriver>(net: &mut NetworkCommissioningWifi<W>, ssid: &[u8]) {
        let mut fbuf = [0u8; 96];
        let flen = write_ssid_fields(&mut fbuf, ssid);
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(0x06), &mut fr, &mut resp, &acc())
            .unwrap();
        assert!(resp.is_deferred(), "ConnectNetwork defers its response");
        assert!(
            resp.response_command().is_none(),
            "no immediate generated response"
        );
    }

    /// `poll_deferred` を 1 回呼ぶ。`Ready` なら `(rid, out, len)` を返す。
    fn poll_connect<W: WifiDriver>(
        net: &mut NetworkCommissioningWifi<W>,
    ) -> Option<(u32, [u8; 64], usize)> {
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        match net.poll_deferred(CommandId(0x06), &mut resp) {
            DeferredPoll::Pending => None,
            DeferredPoll::Ready(r) => {
                r.expect("deferred connect resolved with a generated response");
                let rid = resp.response_command().unwrap().0;
                let len = w.len();
                Some((rid, out, len))
            }
        }
    }

    #[test]
    fn feature_map_is_wifi() {
        let net = NetworkCommissioningWifi::new();
        assert_eq!(net.meta().feature_map, FEATURE_WIFI);
    }

    #[test]
    fn add_then_connect_marks_network_connected() {
        let mut net = NetworkCommissioningWifi::new();

        // AddOrUpdateWiFiNetwork → NetworkConfigResponse(0x05), status Success, networkIndex 0.
        let (rid, out, len) = invoke(&mut net, 0x02, b"TESTSSID");
        assert_eq!(rid, 0x05);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            0
        );
        assert_eq!(
            resp_field(&out[..len], 2).unwrap().as_unsigned().unwrap(),
            0
        );

        // Networks 属性: SSID 1 エントリ、connected=false(未接続)。
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x0001), &mut e, &acc())
                .unwrap();
        }
        // 配列 → 構造体 → { 0: ssid, 1: connected }。
        let mut r = TlvReader::new(&buf);
        assert!(matches!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerStart(ContainerType::Array)
        ));
        assert!(matches!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerStart(ContainerType::Structure)
        ));
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ByteString(b"TESTSSID")
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::Boolean(false)
        );

        // ConnectNetwork → 応答保留。NullWifiDriver は即 Connected なので poll_deferred が
        // 次の poll で ConnectNetworkResponse(0x07), status Success, errorValue null を返す。
        start_connect(&mut net, b"TESTSSID");
        let (rid, out, len) = poll_connect(&mut net).expect("NullWifiDriver ready immediately");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            0
        );
        assert!(matches!(resp_field(&out[..len], 2), Some(TlvValue::Null)));

        // 接続後は Networks[].connected=true。
        let mut buf2 = [0u8; 64];
        let mut w2 = TlvWriter::new(&mut buf2);
        {
            let mut e = AttrEncoder::new(&mut w2, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x0001), &mut e, &acc())
                .unwrap();
        }
        let mut r2 = TlvReader::new(&buf2);
        r2.read_next().unwrap(); // array
        r2.read_next().unwrap(); // struct
        r2.read_next().unwrap(); // ssid
        assert_eq!(
            r2.read_next().unwrap().unwrap().value,
            TlvValue::Boolean(true)
        );
    }

    /// 受けた connect 要求(ssid/creds)を記録するテスト用ドライバ。
    struct RecordingDriver {
        ssid: [u8; 32],
        ssid_len: usize,
        creds: [u8; 64],
        creds_len: usize,
        calls: usize,
        status: WifiStatus,
    }

    impl RecordingDriver {
        fn new() -> Self {
            Self {
                ssid: [0; 32],
                ssid_len: 0,
                creds: [0; 64],
                creds_len: 0,
                calls: 0,
                status: WifiStatus::Idle,
            }
        }
        fn ssid(&self) -> &[u8] {
            &self.ssid[..self.ssid_len]
        }
        fn creds(&self) -> &[u8] {
            &self.creds[..self.creds_len]
        }
    }

    impl WifiDriver for RecordingDriver {
        fn connect(&mut self, ssid: &[u8], creds: &[u8]) {
            self.ssid[..ssid.len()].copy_from_slice(ssid);
            self.ssid_len = ssid.len();
            self.creds[..creds.len()].copy_from_slice(creds);
            self.creds_len = creds.len();
            self.calls += 1;
            self.status = WifiStatus::Connecting;
        }
        fn status(&self) -> WifiStatus {
            self.status
        }
    }

    /// AddOrUpdateWiFiNetwork(ssid + credentials)→ ConnectNetwork でドライバに
    /// 実 SSID / パスフレーズが渡り、応答は即 Success(バックグラウンド join)。
    #[test]
    fn connect_starts_driver_join_with_stored_credentials() {
        let mut net = NetworkCommissioningWifi::with_driver(RecordingDriver::new());

        // AddOrUpdateWiFiNetwork: { 0: ssid, 1: credentials }。
        let mut fbuf = [0u8; 128];
        let mut w = TlvWriter::new(&mut fbuf);
        w.start_struct(&TlvTag::ContextSpecific(1)).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(0), b"iotap")
            .unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), b"hogeFugapiyo")
            .unwrap();
        w.end_container().unwrap();
        let flen = w.len();
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut ww = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut ww);
        net.invoke_command(CommandId(0x02), &mut fr, &mut resp, &acc())
            .unwrap();
        assert_eq!(resp.response_command().unwrap().0, 0x05);
        // AddOrUpdate では join を開始しない。
        assert_eq!(net.driver().calls, 0);

        // ConnectNetwork → ドライバに ssid/creds が渡り、応答は保留される。
        start_connect(&mut net, b"iotap");
        assert_eq!(net.driver().calls, 1);
        assert_eq!(net.driver().ssid(), b"iotap");
        assert_eq!(net.driver().creds(), b"hogeFugapiyo");

        // RecordingDriver は connect で Connecting になるため、最初の poll は Pending。
        assert!(
            poll_connect(&mut net).is_none(),
            "still Connecting → Pending"
        );

        // driver が Connected を報告したら poll_deferred が Success 応答を返す。
        net.driver_mut().status = WifiStatus::Connected;
        let (rid, out, len) = poll_connect(&mut net).expect("Connected → Ready");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::SUCCESS as u64
        );
        assert!(matches!(resp_field(&out[..len], 2), Some(TlvValue::Null)));
    }

    /// ドライバの Failed を update_from_driver が属性へ反映する。
    #[test]
    fn update_from_driver_reflects_failure() {
        let mut net = NetworkCommissioningWifi::with_driver(RecordingDriver::new());
        let (_, _, _) = invoke(&mut net, 0x02, b"iotap");
        start_connect(&mut net, b"iotap");
        net.driver_mut().status = WifiStatus::Failed { reason: -42 };
        net.update_from_driver();

        // LastNetworkingStatus = OtherConnectionFailure(9)。
        let mut buf = [0u8; 32];
        let mut w = TlvWriter::new(&mut buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x0005), &mut e, &acc())
                .unwrap();
        }
        let mut r = TlvReader::new(&buf);
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_unsigned().unwrap(),
            net_status::OTHER_CONNECTION_FAILURE as u64
        );

        // LastConnectErrorValue = -42。
        let mut buf2 = [0u8; 32];
        let mut w2 = TlvWriter::new(&mut buf2);
        {
            let mut e = AttrEncoder::new(&mut w2, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x0007), &mut e, &acc())
                .unwrap();
        }
        let mut r2 = TlvReader::new(&buf2);
        assert!(matches!(
            r2.read_next().unwrap().unwrap().value,
            TlvValue::SignedInteger(-42)
        ));
    }

    #[test]
    fn connect_unknown_network_reports_not_found() {
        let mut net = NetworkCommissioningWifi::new();
        // 未設定のまま特定 SSID を connect → 即 NetworkIDNotFound(遅延しない)。
        let mut fbuf = [0u8; 96];
        let flen = write_ssid_fields(&mut fbuf, b"NOPE");
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(0x06), &mut fr, &mut resp, &acc())
            .unwrap();
        assert!(!resp.is_deferred(), "unknown network is not deferred");
        assert_eq!(resp.response_command().unwrap().0, 0x07);
        let len = w.len();
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::NETWORK_ID_NOT_FOUND as u64
        );
    }

    // E7.4: poll_deferred の 3 分岐(Connecting → Pending、Connected → Success、
    // Failed → OtherConnectionFailure + errorValue)。

    #[test]
    fn poll_deferred_connecting_is_pending() {
        let mut net = NetworkCommissioningWifi::with_driver(RecordingDriver::new());
        let (_, _, _) = invoke(&mut net, 0x02, b"iotap");
        start_connect(&mut net, b"iotap");
        // RecordingDriver::connect → Connecting のまま。poll は Pending。
        assert!(poll_connect(&mut net).is_none());
    }

    #[test]
    fn poll_deferred_connected_returns_success() {
        let mut net = NetworkCommissioningWifi::with_driver(RecordingDriver::new());
        let (_, _, _) = invoke(&mut net, 0x02, b"iotap");
        start_connect(&mut net, b"iotap");
        net.driver_mut().status = WifiStatus::Connected;
        let (rid, out, len) = poll_connect(&mut net).expect("Connected → Ready");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::SUCCESS as u64
        );
        // errorValue は null。
        assert!(matches!(resp_field(&out[..len], 2), Some(TlvValue::Null)));
        // connected 属性が立つ。
        assert!(net.connected);
    }

    #[test]
    fn poll_deferred_failed_returns_other_connection_failure() {
        let mut net = NetworkCommissioningWifi::with_driver(RecordingDriver::new());
        let (_, _, _) = invoke(&mut net, 0x02, b"iotap");
        start_connect(&mut net, b"iotap");
        net.driver_mut().status = WifiStatus::Failed { reason: -7 };
        // 過渡的失敗のリトライ(doc §E7.3): CONNECT_RETRIES 回は connect を再発行して Pending
        // (RecordingDriver::connect は status を Connecting に戻すため、毎回 Failed を再注入)。
        for _ in 0..CONNECT_RETRIES {
            assert!(
                poll_connect(&mut net).is_none(),
                "Failed(リトライ中) → Pending"
            );
            net.driver_mut().status = WifiStatus::Failed { reason: -7 };
        }
        let (rid, out, len) = poll_connect(&mut net).expect("Failed → Ready");
        assert_eq!(rid, 0x07);
        // networkingStatus = OtherConnectionFailure(9)。
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::OTHER_CONNECTION_FAILURE as u64
        );
        // errorValue = reason(-7)。
        assert!(matches!(
            resp_field(&out[..len], 2),
            Some(TlvValue::SignedInteger(-7))
        ));
        // 失敗を属性へも反映。
        assert!(!net.connected);
        assert_eq!(net.last_status, Some(net_status::OTHER_CONNECTION_FAILURE));
        assert_eq!(net.last_connect_error, Some(-7));
    }
}

#[cfg(test)]
mod thread_tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AttributeId, Privilege, SessionKind};
    use crate::dm::{DeferredPoll, ServerCluster};
    use crate::thread::{ThreadDriver, ThreadStatus};
    use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

    /// テスト用 dataset TLV: Extended PAN ID(type 2, len 8)+ Network Name。
    const DATASET: &[u8] = &[
        0x02, 0x08, 0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43, // Ext PAN ID
        0x03, 0x02, b'h', b'i', // Network Name
    ];
    /// 上記 dataset の Extended PAN ID(= NetworkID)。
    const EXT_PAN_ID: &[u8] = &[0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43];

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, None, 0, Privilege::Administer)
    }

    /// フィールド構造体 `{ 0: octstr }`(context タグ 1 のコマンドフィールド構造体)を書く。
    fn write_octstr_fields(buf: &mut [u8], v: &[u8]) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_struct(&TlvTag::ContextSpecific(1)).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(0), v).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    /// 応答匿名構造体から context タグ `t` の値を取り出す。
    fn resp_field(bytes: &[u8], t: u8) -> Option<TlvValue<'_>> {
        let mut r = TlvReader::new(bytes);
        let head = r.read_next().ok()??;
        assert!(matches!(
            head.value,
            TlvValue::ContainerStart(ContainerType::Structure)
        ));
        loop {
            let e = r.read_next().ok()??;
            match e.value {
                TlvValue::ContainerEnd => return None,
                v => {
                    if e.tag == TlvTag::ContextSpecific(t) {
                        return Some(v);
                    }
                }
            }
        }
    }

    fn invoke<D: ThreadDriver>(
        net: &mut NetworkCommissioningThread<D>,
        cmd: u32,
        octstr: &[u8],
    ) -> (u32, [u8; 96], usize) {
        let mut fbuf = [0u8; 128];
        let flen = write_octstr_fields(&mut fbuf, octstr);
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 96];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(cmd), &mut fr, &mut resp, &acc())
            .unwrap();
        let rid = resp.response_command().unwrap().0;
        let wlen = w.len();
        (rid, out, wlen)
    }

    fn start_connect<D: ThreadDriver>(net: &mut NetworkCommissioningThread<D>, id: &[u8]) {
        let mut fbuf = [0u8; 128];
        let flen = write_octstr_fields(&mut fbuf, id);
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(0x06), &mut fr, &mut resp, &acc())
            .unwrap();
        assert!(resp.is_deferred(), "ConnectNetwork defers its response");
        assert!(resp.response_command().is_none());
    }

    fn poll_connect<D: ThreadDriver>(
        net: &mut NetworkCommissioningThread<D>,
    ) -> Option<(u32, [u8; 64], usize)> {
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        match net.poll_deferred(CommandId(0x06), &mut resp) {
            DeferredPoll::Pending => None,
            DeferredPoll::Ready(r) => {
                r.expect("deferred connect resolved with a generated response");
                let rid = resp.response_command().unwrap().0;
                let len = w.len();
                Some((rid, out, len))
            }
        }
    }

    #[test]
    fn feature_map_is_thread() {
        let net = NetworkCommissioningThread::new();
        assert_eq!(net.meta().feature_map, FEATURE_THREAD);
    }

    #[test]
    fn thread_version_is_1_3() {
        let net = NetworkCommissioningThread::new();
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x000A), &mut e, &acc())
                .unwrap();
        }
        let mut r = TlvReader::new(&buf);
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_unsigned().unwrap(),
            4
        );
    }

    #[test]
    fn add_then_connect_uses_ext_pan_id_as_network_id() {
        let mut net = NetworkCommissioningThread::new();

        // AddOrUpdateThreadNetwork(0x03) → NetworkConfigResponse(0x05), Success, idx 0.
        let (rid, out, len) = invoke(&mut net, 0x03, DATASET);
        assert_eq!(rid, 0x05);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            0
        );

        // Networks 属性: NetworkID = Ext PAN ID、connected=false。
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            net.read_attribute(AttributeId(0x0001), &mut e, &acc())
                .unwrap();
        }
        let mut r = TlvReader::new(&buf);
        assert!(matches!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerStart(ContainerType::Array)
        ));
        assert!(matches!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ContainerStart(ContainerType::Structure)
        ));
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::ByteString(EXT_PAN_ID)
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value,
            TlvValue::Boolean(false)
        );

        // ConnectNetwork(照合キー = Ext PAN ID)→ 応答保留。NullThreadDriver は即 Attached。
        start_connect(&mut net, EXT_PAN_ID);
        let (rid, out, len) = poll_connect(&mut net).expect("NullThreadDriver ready immediately");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            0
        );
        assert!(matches!(resp_field(&out[..len], 2), Some(TlvValue::Null)));
        assert!(net.connected);
    }

    /// 受けた connect 要求を記録するテスト用ドライバ。
    struct RecordingThreadDriver {
        dataset_len: usize,
        connect_calls: usize,
        status: ThreadStatus,
    }

    impl ThreadDriver for RecordingThreadDriver {
        fn set_dataset(&mut self, tlv: &[u8]) -> crate::error::Result<[u8; 8]> {
            self.dataset_len = tlv.len();
            crate::thread::extract_ext_pan_id(tlv).ok_or(crate::error::Error::Decode)
        }
        fn connect(&mut self) {
            self.connect_calls += 1;
            self.status = ThreadStatus::Attaching;
        }
        fn status(&self) -> ThreadStatus {
            self.status
        }
    }

    #[test]
    fn connect_starts_driver_attach() {
        let mut net = NetworkCommissioningThread::with_driver(RecordingThreadDriver {
            dataset_len: 0,
            connect_calls: 0,
            status: ThreadStatus::Idle,
        });
        // AddOrUpdateThreadNetwork は attach を開始しない。
        let (rid, _, _) = invoke(&mut net, 0x03, DATASET);
        assert_eq!(rid, 0x05);
        assert_eq!(net.driver().dataset_len, DATASET.len());
        assert_eq!(net.driver().connect_calls, 0);

        // ConnectNetwork → driver.connect() が呼ばれ、応答は保留。
        start_connect(&mut net, EXT_PAN_ID);
        assert_eq!(net.driver().connect_calls, 1);
        // Attaching のまま → Pending。
        assert!(poll_connect(&mut net).is_none());

        // Attached を報告したら Success 応答。
        net.driver_mut().status = ThreadStatus::Attached;
        let (rid, out, len) = poll_connect(&mut net).expect("Attached → Ready");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::SUCCESS as u64
        );
    }

    #[test]
    fn connect_unknown_network_reports_not_found() {
        let mut net = NetworkCommissioningThread::new();
        // 未設定のまま特定 ExtPanID を connect → 即 NetworkIDNotFound(遅延しない)。
        let mut fbuf = [0u8; 96];
        let flen = write_octstr_fields(&mut fbuf, EXT_PAN_ID);
        let mut fr = TlvReader::new(&fbuf[..flen]);
        let mut out = [0u8; 64];
        let mut w = TlvWriter::new(&mut out);
        let mut resp = CmdResponder::new(&mut w);
        net.invoke_command(CommandId(0x06), &mut fr, &mut resp, &acc())
            .unwrap();
        assert!(!resp.is_deferred());
        assert_eq!(resp.response_command().unwrap().0, 0x07);
        let len = w.len();
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::NETWORK_ID_NOT_FOUND as u64
        );
    }
}
