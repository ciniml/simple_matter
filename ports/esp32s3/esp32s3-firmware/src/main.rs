//! ESP32-S3(M5Stack AirQ)向け simple-matter ポート — フェーズ A5 段階 1 の
//! スモークファームウェア(C6 ポートの E1 相当)。
//!
//! `docs/design/airq-port.md` §7.1 A5。このファームウェアが実機で証明すること:
//!
//! 1. espup の esp channel(rustc フォーク)+ build-std で Xtensa LX7 バイナリが
//!    ビルドでき、esp-hal(1.x, `esp32s3`)で AirQ(M5StampS3)が起動して
//!    esp-println でログが出る。
//! 2. esp-hal の **真性乱数(TRNG)** をコアの [`Rng`] trait へ橋渡しできる
//!    (C6 と同じ [`EspRng`] アダプタ)。
//! 3. その RNG で RustCrypto バックエンドが S3 上で **P-256 鍵ペアを生成**できる。
//!
//! 実機ログ・書き込み手順は `ports/esp32s3/README.md` を参照。
//!
//! [`Rng`]: simple_matter::crypto::Rng

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレースを提供する(リンクのために必要)。
use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};

use esp_println::println;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタを .rodata に埋め込む。
// これが無いとブートローダがアプリを起動できず TG0 WDT リセットループになる
// (C6 E1 で実機確認した罠。espflash 4.x は書き込み時に欠如を検出して拒否する)。
esp_bootloader_esp_idf::esp_app_desc!();

use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use simple_matter::error::Result;

/// esp-hal の TRNG([`Trng`])を、コアの [`Rng`] trait に橋渡しするアダプタ。
///
/// コアはエントロピー源を保持せず、この trait 経由でプラットフォームから注入される。
/// S3 の TRNG も C6 と同様、`TrngSource`(SAR ADC を占有)が有効な間だけ真性乱数を
/// 供給するため、ファームウェアの生存期間中 `TrngSource` を保持し続けること。
struct EspRng(Trng);

impl Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.0.read(dest);
        Ok(())
    }
}

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-S3 port (AirQ A5 stage-1 smoke)");
    println!(" target   : xtensa-esp32s3-none-elf (espup esp channel)");
    println!(" hal      : esp-hal 1.1.1");
    println!(" scope    : boot log + TRNG -> crypto::Rng + P-256 keygen");
    println!("======================================================");

    // --- TRNG(真性乱数)を有効化する ---
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TrngSource must be active before Trng::try_new()");
    println!("[trng] SAR ADC entropy source enabled; TRNG ready");

    let mut sample = [0u8; 8];
    trng.read(&mut sample);
    println!(
        "[trng] sample bytes: {:02x} {:02x} {:02x} {:02x} ...",
        sample[0], sample[1], sample[2], sample[3]
    );

    // --- コアの暗号バックエンドを、S3 の TRNG を注入して構築 ---
    let crypto = RustCrypto::new(EspRng(trng));
    println!("[crypto] RustCrypto backend built with EspRng (esp-hal TRNG)");

    match crypto.p256_generate_keypair() {
        Ok(keypair) => {
            let pk = keypair.public_key().to_bytes();
            println!(
                "[crypto] P-256 keypair generated. public key (SEC1) [{}B]:",
                pk.len()
            );
            println!(
                "[crypto]   {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} ...",
                pk[0], pk[1], pk[2], pk[3], pk[4], pk[5], pk[6], pk[7]
            );
            println!("[crypto]   SEC1 tag (expect 0x04): 0x{:02x}", pk[0]);
        }
        Err(_) => {
            println!("[crypto] ERROR: P-256 keypair generation failed");
        }
    }

    println!("[boot] stage-1 checks done. entering 1 Hz heartbeat loop.");

    let delay = Delay::new();
    let mut counter: u32 = 0;
    loop {
        println!("[heartbeat] tick {}", counter);
        counter = counter.wrapping_add(1);
        delay.delay_millis(1000);
    }
}
