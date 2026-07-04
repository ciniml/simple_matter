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
use crate::dm::meta::{AccessContext, CommandId};
use crate::im::wire::ImStatus;
use crate::tlv::{TlvReader, TlvTag};

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
        data: crate::tlv::TlvElement<'_>,
        _acc: &crate::dm::meta::AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data
            .value
            .as_bool()
            .map_err(|_| ImStatus::InvalidDataType)?;
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
                write: (|c: &mut NetworkCommissioning, data, acc| c.write_interface_enabled(data, acc))
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

/// Network Commissioning クラスタ(0x0031、Wi-Fi **シミュレーション**)。
///
/// FeatureMap は Wi-Fi(bit 0 = `0x01`)を立て、chip-tool の BLE→Wi-Fi コミッショニング
/// (`pairing ble-wifi`)が要求する NetworkCommissioning インターフェースを提供する。
///
/// # シミュレーションである点(実際には Wi-Fi に参加しない)
///
/// 本実装は **実際の無線 join を一切行わない**。用途は「BLE で PASE/CASE を張った PC が、
/// 既に IP 到達可能なネットワーク上に居る」開発・相互運用シナリオである。chip-tool は
/// BLE 経由の commissionee に対し Wi-Fi/Thread の NetworkCommissioning を要求する
/// (`AutoCommissioner`: BLE→`mNeedsNetworkSetup=true`、`IsSomeNetworkSupported` は
/// wifi/thread のみ)ため、Ethernet feature だけでは "does not support any network types" で
/// 失敗する。そこで Wi-Fi feature を提示し、`AddOrUpdateWiFiNetwork` / `ConnectNetwork` に
/// **即 Success を返す**ことで、デバイスが既存 IP 経路(BLE と並走する UDP + 運用 mDNS)で
/// CASE→CommissioningComplete まで到達できるようにする。SSID / 資格情報は保存するが接続には使わない。
#[derive(Debug)]
pub struct NetworkCommissioningWifi {
    /// AddOrUpdateWiFiNetwork で受理した SSID(NetworkID として使う)。最大 32 バイト。
    ssid: [u8; 32],
    /// `ssid` の有効長(0 なら未設定=ネットワーク無し)。
    ssid_len: usize,
    /// ConnectNetwork 済みか(Networks[].connected に反映)。
    connected: bool,
    /// InterfaceEnabled(0x0004)。
    interface_enabled: bool,
    /// LastNetworkingStatus(0x0005、未設定は null)。
    last_status: Option<u8>,
    /// LastConnectErrorValue(0x0007、未設定は null)。
    last_connect_error: Option<i32>,
}

impl Default for NetworkCommissioningWifi {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkCommissioningWifi {
    /// Wi-Fi シミュレーションモードのクラスタを作る(ネットワーク未設定)。
    pub const fn new() -> Self {
        Self {
            ssid: [0u8; 32],
            ssid_len: 0,
            connected: false,
            interface_enabled: true,
            last_status: None,
            last_connect_error: None,
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

    /// InterfaceEnabled(0x0004)を書き込む。
    fn write_interface_enabled(
        &mut self,
        data: crate::tlv::TlvElement<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.interface_enabled = data
            .value
            .as_bool()
            .map_err(|_| ImStatus::InvalidDataType)?;
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

    /// NetworkConfigResponse(0x05): `{ 0: networkingStatus, 2: networkIndex }`。
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

    /// ConnectNetworkResponse(0x07): `{ 0: networkingStatus, 2: errorValue(null) }`。
    fn write_connect_response(resp: &mut CmdResponder<'_, '_>, status: u8) -> Result<(), ImStatus> {
        let w = open_response(resp, 0x07)?;
        w.write_u8(&TlvTag::ContextSpecific(0), status)
            .map_err(map_tlv)?;
        // errorValue は nullable かつ非 optional。Success では null を返す。
        w.write_null(&TlvTag::ContextSpecific(2)).map_err(map_tlv)?;
        close_response(w)
    }

    /// ScanNetworksResponse(0x01): `{ 0: networkingStatus }`(空結果)。
    fn write_scan_response(resp: &mut CmdResponder<'_, '_>, status: u8) -> Result<(), ImStatus> {
        let w = open_response(resp, 0x01)?;
        w.write_u8(&TlvTag::ContextSpecific(0), status)
            .map_err(map_tlv)?;
        close_response(w)
    }

    /// 最初の context タグ付き octstr フィールド(tag=0)を取り出す。
    fn first_octstr<'a>(fields: &mut TlvReader<'a>) -> Option<&'a [u8]> {
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                return v.as_bytes().ok();
            }
        }
        None
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
            0x00 => Self::write_scan_response(resp, net_status::SUCCESS),
            // AddOrUpdateWiFiNetwork(0x02): SSID を保存し NetworkConfigResponse(Success, idx 0)。
            0x02 => {
                if let Some(ssid) = Self::first_octstr(fields) {
                    self.set_ssid(ssid);
                }
                self.connected = false;
                self.last_status = Some(net_status::SUCCESS);
                Self::write_network_config_response(resp, net_status::SUCCESS, Some(0))
            }
            // RemoveNetwork(0x04): 保持 SSID と一致すれば削除。最小実装。
            0x04 => {
                let matches = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.ssid_len > 0)
                    .unwrap_or(false);
                if matches {
                    self.ssid_len = 0;
                    self.connected = false;
                    Self::write_network_config_response(resp, net_status::SUCCESS, Some(0))
                } else {
                    Self::write_network_config_response(
                        resp,
                        net_status::NETWORK_ID_NOT_FOUND,
                        None,
                    )
                }
            }
            // ConnectNetwork(0x06): シム join 成功。ConnectNetworkResponse(Success, errorValue=null)。
            0x06 => {
                let known = Self::first_octstr(fields)
                    .map(|id| id == self.network_id() && self.ssid_len > 0)
                    .unwrap_or(self.ssid_len > 0);
                if known {
                    self.connected = true;
                    self.last_status = Some(net_status::SUCCESS);
                    self.last_connect_error = None;
                    Self::write_connect_response(resp, net_status::SUCCESS)
                } else {
                    self.last_status = Some(net_status::NETWORK_ID_NOT_FOUND);
                    Self::write_connect_response(resp, net_status::NETWORK_ID_NOT_FOUND)
                }
            }
            // ReorderNetwork(0x08): 単一ネットワークなので常に Success。
            0x08 => Self::write_network_config_response(resp, net_status::SUCCESS, Some(0)),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

cluster! {
    NetworkCommissioningWifi {
        id: 0x0031,
        revision: 1,
        feature_map: 0x01,
        dirty: _,
        invoke: (|c: &mut NetworkCommissioningWifi, cmd, fields, resp, acc| c.invoke_cmd(cmd, fields, resp, acc)),
        attributes: [
            0x0000 MaxNetworks {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|_c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| e.write_u8(1)),
                write: _
            },
            0x0001 Networks {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| c.read_networks(e)),
                write: _
            },
            0x0002 ScanMaxTimeSeconds {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|_c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| e.write_u8(10)),
                write: _
            },
            0x0003 ConnectMaxTimeSeconds {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|_c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| e.write_u8(30)),
                write: _
            },
            0x0004 InterfaceEnabled {
                access: Administer, quality: [], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| e.write_bool(c.interface_enabled)),
                write: (|c: &mut NetworkCommissioningWifi, data, acc| c.write_interface_enabled(data, acc))
            },
            0x0005 LastNetworkingStatus {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| c.read_last_status(e)),
                write: _
            },
            0x0006 LastNetworkID {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| c.read_last_network_id(e)),
                write: _
            },
            0x0007 LastConnectErrorValue {
                access: Administer, quality: [NULLABLE], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| c.read_last_connect_error(e)),
                write: _
            },
            0x0008 SupportedWiFiBands {
                access: Administer, quality: [FIXED], subscribe: false,
                read: (|c: &NetworkCommissioningWifi, e: &mut AttrEncoder<'_, '_>| c.read_supported_bands(e)),
                write: _
            },
        ],
        accepted: [
            0x00 ScanNetworks,
            0x02 AddOrUpdateWiFiNetwork,
            0x04 RemoveNetwork,
            0x06 ConnectNetwork,
            0x08 ReorderNetwork,
        ],
        generated: [ 0x01, 0x05, 0x07 ],
    }
}

#[cfg(test)]
mod wifi_tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AttributeId, Privilege, SessionKind};
    use crate::dm::ServerCluster;
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

    fn invoke(net: &mut NetworkCommissioningWifi, cmd: u32, ssid: &[u8]) -> (u32, [u8; 64], usize) {
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
            net.read_attribute(AttributeId(0x0001), &mut e).unwrap();
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

        // ConnectNetwork → ConnectNetworkResponse(0x07), status Success, errorValue null。
        let (rid, out, len) = invoke(&mut net, 0x06, b"TESTSSID");
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
            net.read_attribute(AttributeId(0x0001), &mut e).unwrap();
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

    #[test]
    fn connect_unknown_network_reports_not_found() {
        let mut net = NetworkCommissioningWifi::new();
        // 未設定のまま特定 SSID を connect → NetworkIDNotFound。
        let (rid, out, len) = invoke(&mut net, 0x06, b"NOPE");
        assert_eq!(rid, 0x07);
        assert_eq!(
            resp_field(&out[..len], 0).unwrap().as_unsigned().unwrap(),
            net_status::NETWORK_ID_NOT_FOUND as u64
        );
    }
}
