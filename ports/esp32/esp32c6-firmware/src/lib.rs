//! ESP32-C6 ポートの共有部(no_std)。
//!
//! - [`EspRng`]: esp-hal の TRNG をコアの [`Rng`] trait へ橋渡しするアダプタ
//!   (E1 の `src/main.rs` と同じ実装。E2 以降の bin から共有するため lib に置く)。
//! - [`ble`]: コアの `GattPeripheral` trait を TrouBLE(trouble-host)で実装する
//!   [`ble::TroubleGattPeripheral`] と、その裏で GATT 接続を駆動するワーカー
//!   [`ble::gatt_worker`]。
//! - [`kvs`]: コアの `Kvs` trait を内蔵 flash(esp-storage + sequential-storage)で
//!   実装する [`kvs::EspKvs`](E4 の fabric 永続化バックエンド)。
//! - [`net`]: コアの UDP trait 群(`UdpSend`/`UdpReceive`/`UdpMulticast`)の
//!   embassy-net 実装 [`net::EspUdp`](E5。trait 実利用第 1 号)。
//! - [`wifi`]: コアの `WifiDriver` trait の esp-radio 実装
//!   ([`wifi::EspWifiDriver`] + 常駐 [`wifi::wifi_task`]、E5)。

#![no_std]

pub mod ble;
pub mod kvs;
pub mod net;
pub mod wifi;

use esp_hal::rng::Trng;
use simple_matter::crypto::Rng;
use simple_matter::error::Result;

/// esp-hal の TRNG([`Trng`])を、コアの [`Rng`] trait に橋渡しするアダプタ。
///
/// コアはエントロピー源を保持せず、この trait 経由でプラットフォームから注入される。
/// C6 の TRNG は `TrngSource`(SAR ADC を占有)が有効な間、真性乱数を供給する。
/// 呼び出し側は `TrngSource` をファームウェアの生存期間中保持し続けること
/// (drop すると擬似乱数に戻る)。
pub struct EspRng(pub Trng);

impl Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        // `Trng::read` はハードウェア RNG を必要バイト数ぶん読み出して buffer を満たす。
        self.0.read(dest);
        Ok(())
    }
}
