//! GATT の定数(UUID)と広告ビルダ [`AdvData`]。
//!
//! `docs/design/ble-btp.md` §2.1 / §2.6 に基づく。GATT trait(`GattPeripheral` /
//! `GattCentral`)は P3 の範囲なので、本モジュールでは UUID 定数と広告 service data の
//! 生成/解析(sans-IO)のみを置く。UUID は chip `BleUUID.h` / rs-matter `gatt.rs` と一致する。

use crate::error::{Error, Result};

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
