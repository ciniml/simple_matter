//! デバッグ用: write_csr が生成する PKCS#10 CSR を DER ファイルに書き出す。
//! `openssl req -inform DER -in /tmp/csr.der -text -verify` での検証に使う。

use simple_matter::cert::write_csr;
use simple_matter::crypto::rustcrypto::RustCrypto;
use simple_matter::crypto::{Crypto, Rng};

struct FixedRng(u8);
impl Rng for FixedRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
        for b in dest.iter_mut() {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *b = self.0;
        }
        Ok(())
    }
}

fn main() {
    let crypto = RustCrypto::new(FixedRng(42));
    let kp = crypto.p256_generate_keypair().expect("keypair");
    let _ = &crypto;
    let mut buf = [0u8; 512];
    let n = write_csr(&kp, &mut buf).expect("csr");
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/csr.der".into());
    std::fs::write(&path, &buf[..n]).expect("write");
    println!("wrote {n} bytes to {path}");
}
