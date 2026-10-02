//! GATT の定数(UUID)・広告ビルダ [`AdvData`]・抽象 trait([`GattPeripheral`] /
//! [`GattCentral`])。
//!
//! `docs/design/ble-btp.md` §2.1 / §2.6 / §5 に基づく。UUID 定数と広告 service data の
//! 生成/解析(sans-IO)に加え、**BLE 無線・OS スタックへの依存性を逆転させる最小の
//! async trait 2 枚**を置く。UUID は chip `BleUUID.h` / rs-matter `gatt.rs` と一致する。
//!
//! # trait を 2 枚に分ける理由(§5.3)
//!
//! GATT ロール(peripheral / central)が非対称なため。device は advertise + C1 受信 +
//! C2 indicate、controller は scan + connect + C1 write + C2 受信で、要求メソッドが
//! 重ならない。1 枚にまとめると未使用メソッドが両実装に生えて移植負担が増える
//! (btleplug は central 専用、bluer は device 側に使う、という PC 事情とも整合)。
//!
//! # `UdpSend` / `UdpReceive` の流儀に合わせる
//!
//! [`crate::transport::net`] の trait 群と同じく、`async fn` in trait・`Send` 境界なし・
//! `&mut T` ブランケット実装とする(executor 非依存・単一タスク前提)。**ESP32 移植 =
//! この 2 trait を NimBLE / esp-idf BLE で実装するだけ**で、BTP 状態機械
//! ([`super::Btp`])・handshake・window は無改造で共有される。

use crate::error::{Error, Result};
use crate::transport::net::BtpConnId;

/// Matter BLE Service の 16bit UUID。
pub const MATTER_SERVICE_UUID16: u16 = 0xFFF6;

/// Matter BLE Service の 128bit UUID(`0000FFF6-0000-1000-8000-00805F9B34FB`)。
pub const MATTER_SERVICE_UUID128: [u8; 16] = [
    0x00, 0x00, 0xFF, 0xF6, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
];

/// C1(client→server, **Write**)の 128bit UUID(`18EE2EF5-263D-4559-959F-4F9C429F9D11`)。
pub const C1_UUID128: [u8; 16] = [
    0x18, 0xEE, 0x2E, 0xF5, 0x26, 0x3D, 0x45, 0x59, 0x95, 0x9F, 0x4F, 0x9C, 0x42, 0x9F, 0x9D, 0x11,
];

/// C2(server→client, **Indicate**)の 128bit UUID(`18EE2EF5-263D-4559-959F-4F9C429F9D12`)。
pub const C2_UUID128: [u8; 16] = [
    0x18, 0xEE, 0x2E, 0xF5, 0x26, 0x3D, 0x45, 0x59, 0x95, 0x9F, 0x4F, 0x9C, 0x42, 0x9F, 0x9D, 0x12,
];

/// C3(additional data, **Read**)の 128bit UUID(`64630238-8772-45F2-B87D-748A83218F04`)。
pub const C3_UUID128: [u8; 16] = [
    0x64, 0x63, 0x02, 0x38, 0x87, 0x72, 0x45, 0xF2, 0xB8, 0x7D, 0x74, 0x8A, 0x83, 0x21, 0x8F, 0x04,
];

/// 完全な commissionable 広告(Flags AD + Service Data AD)のバイト数。
pub const ADV_TOTAL_LEN: usize = 15;

/// 広告 service data(0xFFF6, 8 バイト)のビルダ / パーサ(§2.6)。
///
/// commissionable モード(OpCode `0x00`)の広告を組む。ワイヤ表現は 8 バイト・LE:
///
/// | バイト | フィールド |
/// |---|---|
/// | 0 | OpCode(commissionable = `0x00`) |
/// | 1-2 | Discriminator(下位 12bit、LE u16) |
/// | 3-4 | Vendor ID(LE) |
/// | 5-6 | Product ID(LE) |
/// | 7 | Additional Data Flag(bit0=C3 あり, bit1=extended announcement) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdvData {
    /// 12bit discriminator(下位 12bit のみ有効)。
    pub discriminator: u16,
    /// Vendor ID。
    pub vendor_id: u16,
    /// Product ID。
    pub product_id: u16,
    /// C3(additional data)を提供するなら `true`(bit0)。
    pub additional_data: bool,
    /// extended announcement なら `true`(bit1)。
    pub ext_announcement: bool,
}

impl AdvData {
    /// commissionable の OpCode。
    pub const OPCODE_COMMISSIONABLE: u8 = 0x00;

    /// 8 バイトの service data payload を生成する。
    pub fn service_data(&self) -> [u8; 8] {
        let disc = self.discriminator & 0x0FFF;
        let mut b = [0u8; 8];
        b[0] = Self::OPCODE_COMMISSIONABLE;
        b[1..3].copy_from_slice(&disc.to_le_bytes());
        b[3..5].copy_from_slice(&self.vendor_id.to_le_bytes());
        b[5..7].copy_from_slice(&self.product_id.to_le_bytes());
        b[7] = (self.additional_data as u8) | ((self.ext_announcement as u8) << 1);
        b
    }

    /// 8 バイトの service data payload を解析する。OpCode 不正は [`Error::Decode`]。
    pub fn parse_service_data(b: &[u8; 8]) -> Result<Self> {
        if b[0] != Self::OPCODE_COMMISSIONABLE {
            return Err(Error::Decode);
        }
        Ok(Self {
            discriminator: u16::from_le_bytes([b[1], b[2]]) & 0x0FFF,
            vendor_id: u16::from_le_bytes([b[3], b[4]]),
            product_id: u16::from_le_bytes([b[5], b[6]]),
            additional_data: b[7] & 0x01 != 0,
            ext_announcement: b[7] & 0x02 != 0,
        })
    }

    /// 完全な広告(Flags AD + Service Data AD)を `out` に書き、長さ([`ADV_TOTAL_LEN`])を返す。
    ///
    /// - Flags AD: `[len=2, 0x01, 0x06]`
    /// - Service Data AD: `[len=11, 0x16, UUID16(LE=F6 FF), payload(8)]`
    pub fn encode_adv(&self, out: &mut [u8]) -> Result<usize> {
        let buf = out.get_mut(..ADV_TOTAL_LEN).ok_or(Error::NoSpace)?;
        // Flags AD(LE General Discoverable | BR/EDR Not Supported = 0x06)。
        buf[0] = 0x02;
        buf[1] = 0x01;
        buf[2] = 0x06;
        // Service Data - 16bit UUID AD。
        buf[3] = 0x0B; // len = 1(type) + 2(uuid) + 8(payload)
        buf[4] = 0x16; // AD type: Service Data - 16bit UUID
        buf[5..7].copy_from_slice(&MATTER_SERVICE_UUID16.to_le_bytes());
        buf[7..15].copy_from_slice(&self.service_data());
        Ok(ADV_TOTAL_LEN)
    }
}

// ==========================================================================
// GATT 抽象 trait(§5)
// ==========================================================================

/// device 側(GATT **peripheral**)の BLE 抽象(§5.1)。
///
/// 統合層(pump ループ)がこの trait を叩いて BLE を制御し、受け取った上り BTP
/// フラグメントを [`Btp::process_incoming`](super::Btp::process_incoming) へ、
/// 吐き出す下りフラグメントを [`indicate`](GattPeripheral::indicate) へ配線する。
/// 本 trait は **BTP を一切知らない**(バイト列の運搬のみ)。
///
/// # バッファ所有
///
/// [`next_event`](GattPeripheral::next_event) の `buf` と [`indicate`](GattPeripheral::indicate)
/// の `frag` は **呼び出し側(統合層)が所有する**。実装側にヒープ確保を強制しない
/// (`UdpReceive::recv_from` と同じ契約)。
///
/// # ATT_MTU の意味
///
/// [`PeripheralEvent::Connected::att_mtu`] は当該 GATT 接続で交渉済みの ATT_MTU
/// (不明なら `None` = BTP は既定フラグメント 20 を使う)。1 回の
/// [`indicate`](GattPeripheral::indicate) で送るフラグメントは `ATT_MTU - 3` バイト
/// 以下でなければならない(ATT の 3 バイトヘッダ分)。この上限は BTP コアが
/// フラグメント境界で保証するため、実装側は渡されたバイト列をそのまま 1 indication
/// として送ればよい。
///
/// # `BtpConnId` の採番規約(§3.1 / §11-3)
///
/// **統合層が GATT 接続ごとに採番する不透明ハンドル**。実装は
/// [`PeripheralEvent::Connected`] で新規接続に割り当てた `conn` を以降のイベント・
/// [`indicate`](GattPeripheral::indicate)・[`disconnect`](GattPeripheral::disconnect)
/// で一貫して用いる。MAC のプライバシー変化とは独立(再接続時は別 `conn` でよい)。
#[allow(async_fn_in_trait)] // executor 非依存・単一タスク前提のため Send 境界は課さない(§5)。
pub trait GattPeripheral {
    /// [`AdvData`](AdvData)(0xFFF6 service data)で commissionable アドバタイズを開始する。
    async fn start_advertising(&mut self, adv: &AdvData) -> Result<()>;

    /// アドバタイズを停止する。
    async fn stop_advertising(&mut self) -> Result<()>;

    /// 次の GATT イベント(接続 / C1 write / C2 subscribe / 切断)を 1 件待つ。
    ///
    /// [`PeripheralEvent::C1Write`] のときのみ `buf[..len]` に上り BTP フラグメントが
    /// 書かれる(他イベントは `buf` を触らない)。
    async fn next_event(&mut self, buf: &mut [u8]) -> Result<PeripheralEvent>;

    /// C2 indication で 1 BTP フラグメント(`ATT_MTU - 3` バイト以内)を central へ送る。
    async fn indicate(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()>;

    /// 指定接続を切断する。
    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()>;
}

/// [`GattPeripheral::next_event`] が返す GATT イベント。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeripheralEvent {
    /// central が GATT 接続した(以降 `conn` で識別)。`att_mtu` は交渉済み MTU(不明なら `None`)。
    Connected {
        /// 統合層が割り当てた接続ハンドル。
        conn: BtpConnId,
        /// 交渉済み ATT_MTU(不明なら `None`)。
        att_mtu: Option<u16>,
    },
    /// C1 への write を受信した。`buf[..len]` に上り BTP フラグメントが入る。
    C1Write {
        /// 接続ハンドル。
        conn: BtpConnId,
        /// `buf` に書かれた上りフラグメント長。
        len: usize,
    },
    /// central が C2 を subscribe した(以降 [`GattPeripheral::indicate`] 可能)。
    C2Subscribed {
        /// 接続ハンドル。
        conn: BtpConnId,
    },
    /// 接続が切れた(BTP セッションをリセットする合図)。
    Disconnected {
        /// 接続ハンドル。
        conn: BtpConnId,
    },
}

/// controller 側(GATT **central**)の BLE 抽象(§5.2)。
///
/// 統合層が `scan → connect → write_c1(handshake req)→ next_indication` を配線し、
/// 受けた下り BTP フラグメントを [`Btp::process_incoming`](super::Btp::process_incoming)
/// へ、吐き出す上りフラグメントを [`write_c1`](GattCentral::write_c1) へ渡す。
///
/// # バッファ所有 / ATT_MTU / `BtpConnId`
///
/// [`GattPeripheral`] と同じ契約。[`connect`](GattCentral::connect) が返す `Option<u16>`
/// は交渉済み ATT_MTU(不明なら `None`)。`conn` は統合層が **接続先ごとに** 採番する
/// 不透明ハンドル。
///
/// # `PeerHandle` を associated type にした理由(§5.2 / §11 のオープン論点への解)
///
/// スキャンで見つけた相手を再指定する「バックエンド不透明ハンドル」を、u64 等の固定型
/// フィールドではなく **associated type** で持つ。理由:
///
/// - btleplug は peripheral を `PeripheralId`、bluer(BlueZ)は D-Bus オブジェクトパス /
///   `Address` で識別する。これらを u64 に押し込めると情報が落ち、バックエンドが
///   ハンドル ↔ u64 の対応表を別途持つ羽目になる。
/// - associated type なら各バックエンドが **自然な peer 識別子をそのまま** [`ScanResult`]
///   に載せられ、変換ゼロ。ESP32/NimBLE 移植でも `ble_addr_t` や接続 index を無理なく
///   埋められる。
/// - テスト実装は `type PeerHandle = ()` 等で自明に満たせる。
#[allow(async_fn_in_trait)] // executor 非依存・単一タスク前提のため Send 境界は課さない(§5)。
pub trait GattCentral {
    /// バックエンド固有の peer 識別子(スキャン結果を [`connect`](GattCentral::connect) で
    /// 再指定するためのハンドル)。
    type PeerHandle;

    /// commissionable デバイスをスキャンし、0xFFF6 service data を解析して 1 件返す。
    ///
    /// discriminator / vendor-product の照合は `filter` に従うが、最終判断は呼び出し側が
    /// [`ScanResult`] を見て行ってもよい(sans-IO 寄り)。
    async fn scan(&mut self, filter: ScanFilter) -> Result<ScanResult<Self::PeerHandle>>;

    /// スキャンで見つけた相手へ接続し、接続ハンドルと ATT_MTU を得る。
    ///
    /// C2 の subscribe は行わない。BTP の確立順序は
    /// 「handshake request の C1 write → C2 subscribe → 応答 indication 受信」であり
    /// (chip の peripheral は最初の C1 write で endpoint を作り、subscribe を契機に
    /// 応答を送る。逆順だと subscribe が捨てられ handshake がタイムアウトする。
    /// chip-lighting-app 実機で裏取り)、subscribe は
    /// [`GattCentral::subscribe_c2`] で明示的に行う。
    async fn connect(
        &mut self,
        target: &ScanResult<Self::PeerHandle>,
    ) -> Result<(BtpConnId, Option<u16>)>;

    /// C2 を subscribe する(以降 [`GattCentral::next_indication`] で下りを受けられる)。
    ///
    /// handshake request を C1 に書いた**後**に呼ぶこと(上記の確立順序)。
    async fn subscribe_c2(&mut self, conn: BtpConnId) -> Result<()>;

    /// C1 write で 1 BTP フラグメント(handshake req・上りセグメント)を送る。
    async fn write_c1(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()>;

    /// C2 indication を 1 件待ち、下り BTP フラグメントを `buf[..len]` に書いて `len` を返す。
    async fn next_indication(&mut self, conn: BtpConnId, buf: &mut [u8]) -> Result<usize>;

    /// 指定接続を切断する。
    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()>;
}

/// [`GattCentral::scan`] のフィルタ条件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanFilter {
    /// 照合する 12bit discriminator(`None` なら任意)。
    pub discriminator: Option<u16>,
    /// 照合する 4bit short discriminator(12bit の上位 4 ビット。11 桁の手動コードはこれしか
    /// 持たない)。`None` なら任意。
    pub short_discriminator: Option<u8>,
    /// 照合する (Vendor ID, Product ID)(`None` なら任意)。
    pub vendor_product: Option<(u16, u16)>,
}

/// [`GattCentral::scan`] が返す 1 件のスキャン結果。
///
/// 解析済み service data([`AdvData`] 相当)+ バックエンド固有ハンドル `handle`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult<H> {
    /// 12bit discriminator。
    pub discriminator: u16,
    /// Vendor ID。
    pub vendor_id: u16,
    /// Product ID。
    pub product_id: u16,
    /// バックエンド固有の peer ハンドル([`GattCentral::connect`] へ渡す)。
    pub handle: H,
}

impl<T: GattPeripheral + ?Sized> GattPeripheral for &mut T {
    async fn start_advertising(&mut self, adv: &AdvData) -> Result<()> {
        (**self).start_advertising(adv).await
    }
    async fn stop_advertising(&mut self) -> Result<()> {
        (**self).stop_advertising().await
    }
    async fn next_event(&mut self, buf: &mut [u8]) -> Result<PeripheralEvent> {
        (**self).next_event(buf).await
    }
    async fn indicate(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()> {
        (**self).indicate(conn, frag).await
    }
    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()> {
        (**self).disconnect(conn).await
    }
}

impl<T: GattCentral + ?Sized> GattCentral for &mut T {
    type PeerHandle = T::PeerHandle;
    async fn scan(&mut self, filter: ScanFilter) -> Result<ScanResult<Self::PeerHandle>> {
        (**self).scan(filter).await
    }
    async fn connect(
        &mut self,
        target: &ScanResult<Self::PeerHandle>,
    ) -> Result<(BtpConnId, Option<u16>)> {
        (**self).connect(target).await
    }
    async fn subscribe_c2(&mut self, conn: BtpConnId) -> Result<()> {
        (**self).subscribe_c2(conn).await
    }
    async fn write_c1(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()> {
        (**self).write_c1(conn, frag).await
    }
    async fn next_indication(&mut self, conn: BtpConnId, buf: &mut [u8]) -> Result<usize> {
        (**self).next_indication(conn, buf).await
    }
    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()> {
        (**self).disconnect(conn).await
    }
}
