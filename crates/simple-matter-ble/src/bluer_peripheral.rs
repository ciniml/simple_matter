//! device 側 [`GattPeripheral`] を BlueZ(bluer)で実装する(`docs/design/ble-btp.md`
//! §5.1 / §6)。Linux 専用。
//!
//! # 構成
//!
//! [`BluerPeripheral::new`] で BlueZ の default adapter を掴み、[`start_advertising`] で
//! (a)0xFFF6 service data の commissionable 広告と、(b)Matter GATT service
//! (C1 write / C2 indicate)を登録する。GATT のコールバック(C1 write / C2 subscribe)は
//! bluer 内部タスクから **tokio mpsc チャネル**へ生イベントを流し、[`next_event`] がそれを
//! [`PeripheralEvent`] へ翻訳する。接続の切断は対向デバイスの `Connected` プロパティ変化を
//! 監視するタスクが検知する。
//!
//! # BtpConnId 採番
//!
//! 初期スコープは同時 1 接続(設計 doc §11-2)。最初に C1 write / C2 subscribe を観測した
//! peer に `BtpConnId(1)` から採番し、切断で解放する。
//!
//! [`GattPeripheral`]: simple_matter::btp::gatt::GattPeripheral
//! [`start_advertising`]: simple_matter::btp::gatt::GattPeripheral::start_advertising
//! [`next_event`]: simple_matter::btp::gatt::GattPeripheral::next_event

use std::collections::VecDeque;
use std::sync::Arc;

use bluer::adv::{Advertisement, AdvertisementHandle};
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicNotifier, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, Service,
};
use bluer::{Adapter, Address, Session, Uuid};
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use simple_matter::btp::gatt::{
    AdvData, GattPeripheral, PeripheralEvent, C1_UUID128, C2_UUID128, MATTER_SERVICE_UUID128,
};
use simple_matter::error::{Error, Result};
use simple_matter::transport::net::BtpConnId;

use crate::uuid_u128;

/// bluer 内部タスクから届く GATT 生イベント。
enum RawEvent {
    /// C1 への write(上り BTP フラグメント)。`mtu` は交渉済み ATT_MTU。
    C1Write {
        addr: Address,
        mtu: u16,
        data: Vec<u8>,
    },
    /// central が C2 を subscribe した(以降 indicate 可能)。subscribe コールバックからは
    /// 対向アドレスが取れないため addr は持たない(接続確立は C1 write / 監視で解決)。
    C2Subscribed,
    /// 対向が切断した。
    Disconnected { addr: Address },
}

/// [`GattPeripheral`] の BlueZ 実装。
pub struct BluerPeripheral {
    adapter: Adapter,
    /// GATT コールバックからの生イベント受信端。
    raw_rx: mpsc::UnboundedReceiver<RawEvent>,
    /// [`start_advertising`](GattPeripheral::start_advertising) に渡すため保持する送信端。
    raw_tx: mpsc::UnboundedSender<RawEvent>,
    /// C2 通知セッション(subscribe で bluer が渡す [`CharacteristicNotifier`])。
    /// [`indicate`](GattPeripheral::indicate) が使う。
    notifier: Arc<AsyncMutex<Option<CharacteristicNotifier>>>,
    /// 広告ハンドル(drop で広告停止)。
    adv_handle: Option<AdvertisementHandle>,
    /// GATT アプリケーションハンドル(drop で登録解除)。
    app_handle: Option<ApplicationHandle>,
    /// 翻訳済みイベントの先読みキュー(1 生イベントが複数 [`PeripheralEvent`] を生む場合用)。
    pending: VecDeque<PeripheralEvent>,
    /// 現在アクティブな接続ハンドル(単一接続スコープ、subscribe / write のどちらかで採番)。
    conn_id: Option<BtpConnId>,
    /// 接続相手のアドレス(C1 write で判明。切断監視・disconnect に使う)。
    conn_addr: Option<Address>,
    /// 次に採番する接続 index。
    next_conn: u8,
}

impl BluerPeripheral {
    /// BlueZ の default adapter を掴んで生成し、電源を投入する。
    pub async fn new() -> Result<Self> {
        Self::with_adapter(None).await
    }

    /// アダプタ名(例: `"hci0"`)を指定して生成し、電源を投入する。
    ///
    /// 同一 PC で peripheral(bluer)と central(btleplug)を別アダプタに
    /// 割り当てる 2 アダプタ構成(設計 doc §9.2)のための選択肢。`None` は default。
    pub async fn with_adapter(name: Option<&str>) -> Result<Self> {
        let session = Session::new().await.map_err(map_bluer)?;
        let adapter = match name {
            Some(n) => session.adapter(n).map_err(map_bluer)?,
            None => session.default_adapter().await.map_err(map_bluer)?,
        };
        adapter.set_powered(true).await.map_err(map_bluer)?;
        let (raw_tx, raw_rx) = mpsc::unbounded_channel();
        Ok(Self {
            adapter,
            raw_rx,
            raw_tx,
            notifier: Arc::new(AsyncMutex::new(None)),
            adv_handle: None,
            app_handle: None,
            pending: VecDeque::new(),
            conn_id: None,
            conn_addr: None,
            next_conn: 1,
        })
    }

    /// この peripheral が使う BlueZ adapter 名(ログ用)。
    pub fn adapter_name(&self) -> &str {
        self.adapter.name()
    }

    /// まだ採番していなければ接続ハンドルを採番し、`Connected` を先読みキューへ積む。
    /// 既に採番済みならそれを返す。
    fn ensure_conn(&mut self, att_mtu: Option<u16>) -> BtpConnId {
        if let Some(id) = self.conn_id {
            return id;
        }
        let id = BtpConnId(self.next_conn);
        self.next_conn = self.next_conn.wrapping_add(1).max(1);
        self.conn_id = Some(id);
        self.pending
            .push_back(PeripheralEvent::Connected { conn: id, att_mtu });
        id
    }

    /// 対向デバイスの `Connected` プロパティを監視し、切断を [`RawEvent::Disconnected`] で通知する。
    fn spawn_disconnect_monitor(&self, addr: Address) {
        let tx = self.raw_tx.clone();
        if let Ok(device) = self.adapter.device(addr) {
            tokio::spawn(async move {
                if let Ok(mut events) = device.events().await {
                    use bluer::{DeviceEvent, DeviceProperty};
                    while let Some(ev) = events.next().await {
                        if let DeviceEvent::PropertyChanged(DeviceProperty::Connected(false)) = ev {
                            let _ = tx.send(RawEvent::Disconnected { addr });
                            break;
                        }
                    }
                }
            });
        }
    }
}

impl GattPeripheral for BluerPeripheral {
    async fn start_advertising(&mut self, adv: &AdvData) -> Result<()> {
        let service_uuid = Uuid::from_u128(uuid_u128(&MATTER_SERVICE_UUID128));
        let c1_uuid = Uuid::from_u128(uuid_u128(&C1_UUID128));
        let c2_uuid = Uuid::from_u128(uuid_u128(&C2_UUID128));

        // --- GATT service(C1 write / C2 indicate)---
        let raw_tx_w = self.raw_tx.clone();
        let raw_tx_n = self.raw_tx.clone();
        let notifier_slot = self.notifier.clone();

        let app = Application {
            services: vec![Service {
                uuid: service_uuid,
                primary: true,
                characteristics: vec![
                    // C1: client → server(Write / Write Without Response)。上り BTP。
                    Characteristic {
                        uuid: c1_uuid,
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(move |data, req| {
                                let tx = raw_tx_w.clone();
                                Box::pin(async move {
                                    let _ = tx.send(RawEvent::C1Write {
                                        addr: req.device_address,
                                        mtu: req.mtu,
                                        data,
                                    });
                                    Ok(())
                                })
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // C2: server → client(Indicate)。下り BTP。
                    Characteristic {
                        uuid: c2_uuid,
                        notify: Some(CharacteristicNotify {
                            // Matter は Indication(確認応答つき)を使う。
                            indicate: true,
                            notify: false,
                            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                                let tx = raw_tx_n.clone();
                                let slot = notifier_slot.clone();
                                Box::pin(async move {
                                    // notifier をスロットへ保管して indicate から使えるようにする。
                                    // device_address は notifier からは取れないため、C1 write /
                                    // 監視タスク側で解決する(subscribe 単独では addr 不明なので
                                    // ダミーを送らず、接続確立は最初の C1 write で行う)。
                                    *slot.lock().await = Some(notifier);
                                    let _ = tx.send(RawEvent::C2Subscribed);
                                })
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = self
            .adapter
            .serve_gatt_application(app)
            .await
            .map_err(map_bluer)?;
        self.app_handle = Some(app_handle);

        // --- 0xFFF6 service data の commissionable 広告 ---
        let mut service_data = std::collections::BTreeMap::new();
        service_data.insert(service_uuid, adv.service_data().to_vec());
        let le_adv = Advertisement {
            service_uuids: vec![service_uuid].into_iter().collect(),
            service_data,
            discoverable: Some(true),
            local_name: Some("simple-matter".to_string()),
            ..Default::default()
        };
        let adv_handle = self.adapter.advertise(le_adv).await.map_err(map_bluer)?;
        self.adv_handle = Some(adv_handle);
        Ok(())
    }

    async fn stop_advertising(&mut self) -> Result<()> {
        // ハンドルを drop すると BlueZ 側で広告 / GATT 登録が解除される。
        self.adv_handle = None;
        Ok(())
    }

    async fn next_event(&mut self, buf: &mut [u8]) -> Result<PeripheralEvent> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Ok(ev);
            }
            let raw = self.raw_rx.recv().await.ok_or(Error::InvalidState)?;
            match raw {
                RawEvent::C1Write { addr, mtu, data } => {
                    let conn = self.ensure_conn(Some(mtu));
                    // 相手アドレスが初めて判明したら切断監視を仕掛ける。
                    if self.conn_addr != Some(addr) {
                        self.conn_addr = Some(addr);
                        self.spawn_disconnect_monitor(addr);
                    }
                    let n = data.len();
                    let dst = buf.get_mut(..n).ok_or(Error::NoSpace)?;
                    dst.copy_from_slice(&data);
                    self.pending
                        .push_back(PeripheralEvent::C1Write { conn, len: n });
                }
                RawEvent::C2Subscribed => {
                    // subscribe 単独では対向アドレス・MTU が不明(MTU は後続の C1 write で
                    // 判明)。ここで接続ハンドルを確定し、Connected(att_mtu=None)→ C2Subscribed
                    // を積む。以降 indicate が可能になる。
                    let conn = self.ensure_conn(None);
                    self.pending
                        .push_back(PeripheralEvent::C2Subscribed { conn });
                }
                RawEvent::Disconnected { addr } => {
                    if self.conn_addr != Some(addr) {
                        continue; // 別デバイスの切断は無視。
                    }
                    let conn = self.conn_id.take().unwrap_or(BtpConnId(1));
                    self.conn_addr = None;
                    *self.notifier.lock().await = None;
                    self.pending
                        .push_back(PeripheralEvent::Disconnected { conn });
                }
            }
        }
    }

    async fn indicate(&mut self, _conn: BtpConnId, frag: &[u8]) -> Result<()> {
        let mut guard = self.notifier.lock().await;
        let notifier = guard.as_mut().ok_or(Error::InvalidState)?;
        notifier.notify(frag.to_vec()).await.map_err(map_bluer)?;
        Ok(())
    }

    async fn disconnect(&mut self, _conn: BtpConnId) -> Result<()> {
        self.conn_id = None;
        if let Some(addr) = self.conn_addr.take() {
            if let Ok(device) = self.adapter.device(addr) {
                let _ = device.disconnect().await;
            }
        }
        *self.notifier.lock().await = None;
        Ok(())
    }
}

/// bluer のエラーをコアの [`Error`] へ写す(詳細は stderr に出す)。コア Error には I/O 用
/// バリアントがないため [`Error::InvalidState`] に集約する。
fn map_bluer(e: bluer::Error) -> Error {
    eprintln!("[bluer] error: {e}");
    Error::InvalidState
}
