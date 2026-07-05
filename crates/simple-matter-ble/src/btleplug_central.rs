//! controller 側 [`GattCentral`] を btleplug で実装する(`docs/design/ble-btp.md`
//! §5.2 / §6 / §8)。
//!
//! # 構成
//!
//! [`BtleplugCentral::new`] で最初の BLE adapter を掴む。[`scan`] は 0xFFF6 service data を
//! btleplug の広告プロパティから読み、コアの [`AdvData`] パーサで解析して discriminator /
//! vendor-product を照合する。[`connect`] で接続 → サービス探索 → C2 subscribe し、
//! notifications ストリームを保持する。[`write_c1`] は C1 に Write(with response)、
//! [`next_indication`] は C2 の indication を 1 件返す。
//!
//! btleplug は ATT_MTU を公開しないため [`connect`] の返す MTU は常に `None`(BTP は既定
//! フラグメント長で handshake する)。btleplug は central 専用なので device 側 peripheral
//! には使えない(設計 doc §6.1、そちらは bluer)。
//!
//! [`GattCentral`]: simple_matter::btp::gatt::GattCentral
//! [`scan`]: simple_matter::btp::gatt::GattCentral::scan
//! [`connect`]: simple_matter::btp::gatt::GattCentral::connect
//! [`write_c1`]: simple_matter::btp::gatt::GattCentral::write_c1
//! [`next_indication`]: simple_matter::btp::gatt::GattCentral::next_indication

use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter as BtleScanFilter,
    ValueNotification, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures::{Stream, StreamExt};
use uuid::Uuid;

use simple_matter::btp::gatt::{
    AdvData, GattCentral, ScanFilter, ScanResult, C1_UUID128, C2_UUID128, MATTER_SERVICE_UUID128,
};
use simple_matter::error::{Error, Result};
use simple_matter::transport::net::BtpConnId;

use crate::uuid_u128;

/// scan がデバイスを見つけられなかった場合に諦めるまでの総待ち時間。
const SCAN_TIMEOUT: Duration = Duration::from_secs(30);
/// scan のポーリング間隔。
const SCAN_POLL: Duration = Duration::from_millis(200);

/// 1 接続分の GATT 状態(単一接続スコープ、設計 doc §11-2)。
struct ConnState {
    peripheral: Peripheral,
    c1: Characteristic,
    c2: Characteristic,
    notifications: Pin<Box<dyn Stream<Item = ValueNotification> + Send>>,
}

/// [`GattCentral`] の btleplug 実装。
pub struct BtleplugCentral {
    adapter: Adapter,
    conns: HashMap<u8, ConnState>,
    next_conn: u8,
    matter_uuid: Uuid,
    c1_uuid: Uuid,
    c2_uuid: Uuid,
}

impl BtleplugCentral {
    /// btleplug の最初の adapter を掴んで生成する。
    pub async fn new() -> Result<Self> {
        Self::with_adapter(None).await
    }

    /// アダプタ名(例: `"hci1"`。`adapter_info()` の前方一致)を指定して生成する。
    ///
    /// 同一 PC で peripheral(bluer)と central(btleplug)を別アダプタに
    /// 割り当てる 2 アダプタ構成(設計 doc §9.2)のための選択肢。`None` は最初の adapter。
    pub async fn with_adapter(name: Option<&str>) -> Result<Self> {
        let manager = Manager::new().await.map_err(map_btle)?;
        let adapters = manager.adapters().await.map_err(map_btle)?;
        let adapter = match name {
            None => adapters.into_iter().next().ok_or(Error::NotFound)?,
            Some(n) => {
                let mut found = None;
                for a in adapters {
                    let info = a.adapter_info().await.map_err(map_btle)?;
                    if info.starts_with(n) {
                        found = Some(a);
                        break;
                    }
                }
                found.ok_or(Error::NotFound)?
            }
        };
        Ok(Self {
            adapter,
            conns: HashMap::new(),
            next_conn: 1,
            matter_uuid: Uuid::from_u128(uuid_u128(&MATTER_SERVICE_UUID128)),
            c1_uuid: Uuid::from_u128(uuid_u128(&C1_UUID128)),
            c2_uuid: Uuid::from_u128(uuid_u128(&C2_UUID128)),
        })
    }

    /// この central が使う adapter 情報(ログ用)。
    pub async fn adapter_info(&self) -> String {
        self.adapter
            .adapter_info()
            .await
            .unwrap_or_else(|_| "<unknown>".to_string())
    }

    fn alloc_conn(&mut self) -> BtpConnId {
        let id = BtpConnId(self.next_conn);
        self.next_conn = self.next_conn.wrapping_add(1).max(1);
        id
    }
}

impl GattCentral for BtleplugCentral {
    type PeerHandle = PeripheralId;

    async fn scan(&mut self, filter: ScanFilter) -> Result<ScanResult<Self::PeerHandle>> {
        // `SM_BLE_TRACE=1` で発見デバイスと照合判断を stderr に出す(実機切り分け用)。
        let trace = std::env::var_os("SM_BLE_TRACE").is_some();
        // BlueZ 側のサービス UUID フィルタ(SetDiscoveryFilter)は使わず、
        // 無フィルタでスキャンしてコード側で照合する。Matter の commissionable
        // 広告は「0xFFF6 の service data のみ」で Service UUID リスト AD を
        // 含まないため、UUID フィルタだと BlueZ のバージョン・キャッシュ状態に
        // よって報告されないことがある(実機で発見: Android の無フィルタ
        // スキャンでは見えるのに btleplug で見えない)。
        self.adapter
            .start_scan(BtleScanFilter::default())
            .await
            .map_err(map_btle)?;

        let mut reported: std::collections::HashSet<PeripheralId> =
            std::collections::HashSet::new();
        let deadline = std::time::Instant::now() + SCAN_TIMEOUT;
        loop {
            for p in self.adapter.peripherals().await.map_err(map_btle)? {
                let props = match p.properties().await.map_err(map_btle)? {
                    Some(props) => props,
                    None => continue,
                };
                let sd = props.service_data.get(&self.matter_uuid);
                if trace && reported.insert(p.id()) {
                    eprintln!(
                        "[ble-trace] seen {} name={:?} rssi={:?} service_data_uuids={:?} fff6={}",
                        props.address,
                        props.local_name,
                        props.rssi,
                        props.service_data.keys().collect::<Vec<_>>(),
                        sd.map(|d| format!("{}B", d.len()))
                            .unwrap_or_else(|| "none".into()),
                    );
                }
                let Some(sd) = sd else {
                    continue;
                };
                if sd.len() < 8 {
                    continue;
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&sd[..8]);
                let Ok(adv) = AdvData::parse_service_data(&b) else {
                    if trace {
                        eprintln!("[ble-trace] {} fff6 parse failed: {:02x?}", props.address, &b);
                    }
                    continue;
                };
                let disc_ok = filter
                    .discriminator
                    .is_none_or(|d| (d & 0x0FFF) == adv.discriminator);
                let vp_ok = filter
                    .vendor_product
                    .is_none_or(|(v, pi)| v == adv.vendor_id && pi == adv.product_id);
                if trace {
                    eprintln!(
                        "[ble-trace] {} matter adv: disc={} vid={:#06x} pid={:#06x} -> disc_ok={} vp_ok={}",
                        props.address, adv.discriminator, adv.vendor_id, adv.product_id, disc_ok, vp_ok,
                    );
                }
                if disc_ok && vp_ok {
                    self.adapter.stop_scan().await.map_err(map_btle)?;
                    return Ok(ScanResult {
                        discriminator: adv.discriminator,
                        vendor_id: adv.vendor_id,
                        product_id: adv.product_id,
                        handle: p.id(),
                    });
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = self.adapter.stop_scan().await;
                return Err(Error::NotFound);
            }
            tokio::time::sleep(SCAN_POLL).await;
        }
    }

    async fn connect(
        &mut self,
        target: &ScanResult<Self::PeerHandle>,
    ) -> Result<(BtpConnId, Option<u16>)> {
        let peripheral = self
            .adapter
            .peripheral(&target.handle)
            .await
            .map_err(map_btle)?;
        peripheral.connect().await.map_err(map_btle)?;
        peripheral.discover_services().await.map_err(map_btle)?;

        let chars = peripheral.characteristics();
        let c1 = chars
            .iter()
            .find(|c| c.uuid == self.c1_uuid)
            .cloned()
            .ok_or(Error::NotFound)?;
        let c2 = chars
            .iter()
            .find(|c| c.uuid == self.c2_uuid)
            .cloned()
            .ok_or(Error::NotFound)?;

        // notifications ストリームを subscribe より前に取得しておく(接続をまたいで有効)。
        // subscribe 自体は行わない(BTP の確立順序: handshake C1 write → subscribe_c2)。
        let notifications = peripheral.notifications().await.map_err(map_btle)?;

        let id = self.alloc_conn();
        self.conns.insert(
            id.0,
            ConnState {
                peripheral,
                c1,
                c2,
                notifications,
            },
        );
        // btleplug は ATT_MTU を公開しないため None(BTP は既定フラグメントで handshake)。
        Ok((id, None))
    }

    async fn subscribe_c2(&mut self, conn: BtpConnId) -> Result<()> {
        let st = self.conns.get(&conn.0).ok_or(Error::NotFound)?;
        st.peripheral.subscribe(&st.c2).await.map_err(map_btle)?;
        Ok(())
    }

    async fn write_c1(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()> {
        let st = self.conns.get(&conn.0).ok_or(Error::NotFound)?;
        st.peripheral
            .write(&st.c1, frag, WriteType::WithResponse)
            .await
            .map_err(map_btle)?;
        Ok(())
    }

    async fn next_indication(&mut self, conn: BtpConnId, buf: &mut [u8]) -> Result<usize> {
        let st = self.conns.get_mut(&conn.0).ok_or(Error::NotFound)?;
        loop {
            let n = st.notifications.next().await.ok_or(Error::InvalidState)?;
            if n.uuid != st.c2.uuid {
                continue; // C2 以外の通知は無視。
            }
            let len = n.value.len();
            let dst = buf.get_mut(..len).ok_or(Error::NoSpace)?;
            dst.copy_from_slice(&n.value);
            return Ok(len);
        }
    }

    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()> {
        if let Some(st) = self.conns.remove(&conn.0) {
            let _ = st.peripheral.disconnect().await;
        }
        Ok(())
    }
}

/// btleplug のエラーをコアの [`Error`] へ写す(詳細は stderr に出す)。コア Error には I/O 用
/// バリアントがないため [`Error::InvalidState`] に集約する。
fn map_btle(e: btleplug::Error) -> Error {
    eprintln!("[btleplug] error: {e}");
    Error::InvalidState
}
