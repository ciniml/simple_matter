//! ESP32-C6 向け simple-matter ポート — フェーズ E1 の骨格ファームウェア。
//!
//! `docs/design/port-esp32-device.md` §8「E1: ports 骨格 + Lチカ」の最小実装。
//! このファームウェアが実機で証明すること:
//!
//! 1. esp-hal(1.x, RISC-V/RV32IMAC)で C6 が起動し、esp-println でログが出る。
//! 2. esp-hal の **真性乱数(TRNG)** を、コア(`simple-matter`)の
//!    [`crypto::Rng`] trait に橋渡しするアダプタ（[`EspRng`]）で注入できる。
//! 3. その RNG を使って RustCrypto バックエンドが C6 上で **P-256 鍵ペアを生成**
//!    できる（= コアの暗号 + プラットフォーム TRNG が実チップ上で動く証明）。
//!
//! LED ピンはボード依存のため、点滅の代わりに 1 秒ごとのカウンタログを出す
//! (§スコープ 3: 「LED ピンはボード依存なのでログで可」)。
//!
//! 実機ログ・書き込み手順は `ports/esp32/README.md` を参照。

#![no_std]
#![no_main]

// panic ハンドラ + 例外ハンドラ + バックトレースを提供する（リンクのために必要）。
use esp_backtrace as _;

use esp_hal::clock::CpuClock;
use esp_hal::delay::Delay;
use esp_hal::main;
use esp_hal::rng::{Trng, TrngSource};

use esp_println::println;

// ESP-IDF 2nd stage bootloader が要求するアプリディスクリプタを .rodata に埋め込む。
// これが無いとブートローダがアプリを起動できず TG0 WDT リセットループになる
// (espflash 4.x は書き込み時に欠如を検出して拒否する)。
esp_bootloader_esp_idf::esp_app_desc!();

use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::{Crypto, P256Keypair, P256PublicKey, Rng};
use simple_matter::error::Result;

/// esp-hal の TRNG（[`Trng`]）を、コアの [`Rng`] trait に橋渡しするアダプタ。
///
/// コアはエントロピー源を保持せず、この trait 経由でプラットフォームから注入される
/// (`crates/simple-matter/src/crypto.rs` の設計方針)。C6 の TRNG は
/// [`TrngSource`]（SAR ADC を占有）が有効な間、真性乱数を供給する。
struct EspRng(Trng);

impl Rng for EspRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        // `Trng::read` はハードウェア RNG を必要バイト数ぶん読み出して buffer を満たす。
        // エントロピー源（TrngSource）は main で生存させているため失敗しない。
        self.0.read(dest);
        Ok(())
    }
}

#[main]
fn main() -> ! {
    // クロックを最大に設定して初期化。返り値は掴んだ周辺機器一式。
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    println!();
    println!("======================================================");
    println!(" simple-matter :: ESP32-C6 port (phase E1 skeleton)");
    println!(" target   : riscv32imac-unknown-none-elf (stable Rust)");
    println!(" hal      : esp-hal 1.1.1");
    println!(" scope    : boot log + TRNG -> crypto::Rng + P-256 keygen");
    println!("======================================================");

    // --- TRNG（真性乱数）を有効化する ---
    // TrngSource が SAR ADC のエントロピー源を有効化する。これが生存している間だけ
    // Trng は真性乱数になる（drop すると ADC が解放され擬似乱数に戻る）。よって
    // ファームウェアの生存期間中は _trng_source を保持し続ける。
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TrngSource must be active before Trng::try_new()");
    println!("[trng] SAR ADC entropy source enabled; TRNG ready");

    // 動作確認として乱数を 8 バイト読み、先頭バイトをログに出す。
    let mut sample = [0u8; 8];
    trng.read(&mut sample);
    println!(
        "[trng] sample bytes: {:02x} {:02x} {:02x} {:02x} ...",
        sample[0], sample[1], sample[2], sample[3]
    );

    // --- コアの暗号バックエンドを、C6 の TRNG を注入して構築 ---
    let crypto = RustCrypto::new(EspRng(trng));
    println!("[crypto] RustCrypto backend built with EspRng (esp-hal TRNG)");

    // P-256 鍵ペアを 1 つ生成し、公開鍵(SEC1 非圧縮 65B)の先頭バイトをログに出す。
    // これが「コアの暗号 + プラットフォーム TRNG が実チップ上で動く」証明。
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
            // 先頭バイトは非圧縮点マーカ 0x04 のはず（サニティチェック）。
            println!("[crypto]   SEC1 tag (expect 0x04): 0x{:02x}", pk[0]);
        }
        Err(_) => {
            println!("[crypto] ERROR: P-256 keypair generation failed");
        }
    }

    println!("[boot] E1 checks done. entering 1 Hz heartbeat loop.");

    // LED はボード依存のため、1 秒ごとのカウンタログで生存を示す。
    let delay = Delay::new();
    let mut counter: u32 = 0;
    loop {
        println!("[heartbeat] tick {}", counter);
        counter = counter.wrapping_add(1);
        delay.delay_millis(1000);
    }
}
