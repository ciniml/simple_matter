//! ESP32-C6 Thread ポートの共有部(no_std)。
//!
//! `docs/design/thread-port.md` §3.2 / §T2。esp32c6-firmware(Wi-Fi + coex)とは
//! **別パッケージ**(esp-radio が `ieee802154` と `wifi` の同時有効化を拒否するため)。
//! esp32c6-firmware の lib は wifi feature を引き込むので依存できず、BLE / KVS は
//! **コピーで共有**する(§3.2 の割り切り。将来 esp-radio 非依存の共有 crate へ切り出し検討)。
//!
//! - [`ble`]: コアの `GattPeripheral` の TrouBLE 実装(esp32c6-firmware からコピー、無改造)。
//! - [`kvs`]: コアの `Kvs` の flash 実装(esp32c6-firmware からコピー、無改造)。
//! - [`ot_udp`]: コアの `UdpSend`/`UdpReceive` の openthread ネイティブ UDP 実装(T2 新規)。
//! - [`ot_thread`]: コアの `ThreadDriver` の openthread 実装(T2 新規)。
//! - [`EspRng`]: esp-hal TRNG をコアの `Rng` へ橋渡し(esp32c6-firmware からコピー)。

#![no_std]

pub mod ble;
pub mod kvs;
pub mod ot_settings;
pub mod ot_thread;
pub mod ot_udp;

use esp_hal::rng::Trng;
use simple_matter::crypto::Rng;
use simple_matter::error::Result;

/// esp-hal の TRNG([`Trng`])を、コアの [`Rng`] trait に橋渡しするアダプタ。
///
/// esp32c6-firmware の `EspRng` と同一。`TrngSource`(SAR ADC を占有)が有効な間、
/// 真性乱数を供給する。呼び出し側は `TrngSource` をファームウェアの生存期間中保持すること。
pub struct EspRng(pub Trng);

impl Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.0.read(dest);
        Ok(())
    }
}
