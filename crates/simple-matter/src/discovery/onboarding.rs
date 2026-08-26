//! オンボーディング払い出し情報(manual pairing code / QR payload / setup passcode)。
//!
//! Matter 仕様 §5.1(Onboarding Payload)の**生成側**だけを実装する。用途は 2 つ:
//!
//! - コントローラが [`AdministratorCommissioning`](crate::dm::clusters::administrator_commissioning)
//!   の OpenCommissioningWindow(ECM)で払い出した passcode / discriminator を、2 人目の
//!   コントローラ(chip-tool / スマホアプリ)へ渡す文字列にする(`docs/design/p4-thread-controller.md` §17)。
//! - デバイス側 example が焼き込みパスコードの manual code / QR を表示する。
//!
//! `no_std` / ヒープ非依存(出力は呼び出し側のバッファ)。暗号にも依存しないため
//! `rustcrypto` feature 無効でもコンパイルされる。

use crate::crypto::Rng;
use crate::error::{Error, Result};

/// 11 桁 manual pairing code の長さ(ASCII 数字。§5.1.4.1)。
pub const MANUAL_CODE_LEN: usize = 11;

/// QR payload の最大長(`"MT:"` + base38 19 文字。§5.1.3)。
pub const QR_PAYLOAD_MAX_LEN: usize = 3 + 19;

/// discovery capabilities bitmask: SoftAP(bit0、§5.1.3.1)。
pub const DISCOVERY_CAP_SOFT_AP: u8 = 1 << 0;
/// discovery capabilities bitmask: BLE(bit1)。
pub const DISCOVERY_CAP_BLE: u8 = 1 << 1;
/// discovery capabilities bitmask: on-network(既にネットワーク上にいる。bit2)。
pub const DISCOVERY_CAP_ON_NETWORK: u8 = 1 << 2;

/// QR payload に載せる情報一式(§5.1.3)。
///
/// `version` = 0 / `commissioning flow` = Standard(0)固定。カスタムフロー・TLV 拡張
/// (§5.1.5)は生成しない(ECM で払い出す窓には不要)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnboardingPayload {
    /// VendorID(取得できなければ 0)。
    pub vendor_id: u16,
    /// ProductID(取得できなければ 0)。
    pub product_id: u16,
    /// 12 ビット discriminator(上位は捨てられる)。
    pub discriminator: u16,
    /// 27 ビット setup passcode。
    pub passcode: u32,
    /// discovery capabilities bitmask([`DISCOVERY_CAP_ON_NETWORK`] 等の OR)。
    pub discovery_caps: u8,
}

/// setup passcode の有効性(§5.1.7)。
///
/// 範囲 1..=99_999_998 で、仕様が禁じる 12 個の自明な値を除く。
pub const fn passcode_is_valid(p: u32) -> bool {
    const INVALID: [u32; 12] = [
        0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888,
        99999999, 12345678, 87654321,
    ];
    if p == 0 || p > 99_999_998 {
        return false;
    }
    let mut i = 0;
    while i < INVALID.len() {
        if INVALID[i] == p {
            return false;
        }
        i += 1;
    }
    true
}

/// 有効な setup passcode を乱数生成する(§5.1.7)。
///
/// 禁止値を引いたら引き直す(最大 16 回)。それでも取れなければ [`Error::Crypto`]。
pub fn random_passcode<R: Rng>(rng: &mut R) -> Result<u32> {
    let mut b = [0u8; 4];
    for _ in 0..16 {
        rng.fill_bytes(&mut b)?;
        let p = u32::from_le_bytes(b) % 99_999_998 + 1;
        if passcode_is_valid(p) {
            return Ok(p);
        }
    }
    Err(Error::Crypto)
}

/// 有効な 12 ビット discriminator を乱数生成する(全値が有効なので引き直しは無い)。
pub fn random_discriminator<R: Rng>(rng: &mut R) -> Result<u16> {
    let mut b = [0u8; 2];
    rng.fill_bytes(&mut b)?;
    Ok(u16::from_le_bytes(b) & 0x0FFF)
}

/// 11 桁 manual pairing code(§5.1.4.1、VID/PID なし・標準フロー)。
///
/// - digit 1: `(VID_PID_present(0) << 2) | (discriminator >> 10)`
/// - digits 2-6: `((discriminator & 0x300) << 6) | (passcode & 0x3FFF)`
/// - digits 7-10: `passcode >> 14`
/// - digit 11: Verhoeff 検査数字
///
/// 戻り値は ASCII 数字 11 バイト(NUL 終端なし)。
pub fn manual_pairing_code(discriminator: u16, passcode: u32) -> [u8; MANUAL_CODE_LEN] {
    let d1 = ((discriminator >> 10) & 0x03) as u32; // 上位 2 ビット(VID_PID_present = 0)
    let d2_6 = (((discriminator as u32) & 0x300) << 6) | (passcode & 0x3FFF);
    let d7_10 = passcode >> 14;

    let mut out = [b'0'; MANUAL_CODE_LEN];
    write_digits(&mut out[0..1], d1 as u64);
    write_digits(&mut out[1..6], d2_6 as u64);
    write_digits(&mut out[6..10], d7_10 as u64);
    out[10] = b'0' + verhoeff_check_digit(&out[..10]);
    out
}

/// `v` をゼロ詰め 10 進で `dst` へ書く(桁あふれは上位から捨てられる)。
fn write_digits(dst: &mut [u8], mut v: u64) {
    for slot in dst.iter_mut().rev() {
        *slot = b'0' + (v % 10) as u8;
        v /= 10;
    }
}

/// Verhoeff 検査数字(manual pairing code の末尾桁)。
fn verhoeff_check_digit(digits: &[u8]) -> u8 {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
    let mut c: u8 = 0;
    for (i, ch) in digits.iter().rev().enumerate() {
        let digit = ch.wrapping_sub(b'0');
        c = D[c as usize][P[(i + 1) % 8][(digit % 10) as usize] as usize];
    }
    INV[c as usize]
}

/// base38 のアルファベット(§5.1.3.2)。
const BASE38_ALPHABET: &[u8; 38] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

/// QR payload(`"MT:"` + base38、§5.1.3)を `out` へ書き、書いた長さを返す。
///
/// ビットレイアウト(LSB から順に詰める、合計 88 ビット = 11 バイト):
/// version(3) ‖ VendorID(16) ‖ ProductID(16) ‖ commissioning flow(2) ‖
/// discovery capabilities(8) ‖ discriminator(12) ‖ passcode(27) ‖ padding(4)。
///
/// バイト列は**リトルエンディアン**のビットストリーム(先頭バイトがビット 0..7)で、
/// これを 3 バイト = 5 文字 / 2 バイト = 4 文字 / 1 バイト = 2 文字の base38 で符号化する。
///
/// # 失敗
/// `out` が [`QR_PAYLOAD_MAX_LEN`] 未満なら [`Error::NoSpace`]。
pub fn qr_payload(p: &OnboardingPayload, out: &mut [u8]) -> Result<usize> {
    if out.len() < QR_PAYLOAD_MAX_LEN {
        return Err(Error::NoSpace);
    }
    // --- 88 ビットのパック ---
    let mut packed = [0u8; 11];
    let mut off = 0usize;
    let mut put = |value: u64, width: usize| {
        for i in 0..width {
            if (value >> i) & 1 == 1 {
                packed[(off + i) / 8] |= 1 << ((off + i) % 8);
            }
        }
        off += width;
    };
    put(0, 3); // version = 0
    put(p.vendor_id as u64, 16);
    put(p.product_id as u64, 16);
    put(0, 2); // commissioning flow = Standard
    put(p.discovery_caps as u64, 8);
    put((p.discriminator & 0x0FFF) as u64, 12);
    put((p.passcode & 0x07FF_FFFF) as u64, 27);
    put(0, 4); // padding
    debug_assert_eq!(off, 88);

    // --- base38 ---
    out[0] = b'M';
    out[1] = b'T';
    out[2] = b':';
    let mut n = 3;
    for chunk in packed.chunks(3) {
        let mut v: u32 = 0;
        for (i, b) in chunk.iter().enumerate() {
            v |= (*b as u32) << (8 * i);
        }
        let chars = match chunk.len() {
            3 => 5,
            2 => 4,
            _ => 2,
        };
        for _ in 0..chars {
            out[n] = BASE38_ALPHABET[(v % 38) as usize];
            v /= 38;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テストベクタの出典: chip-tool / connectedhomeip の既定オンボーディング値
    /// (`chip-tool payload parse-setup-payload MT:-24J0AFN00KA0648G00`。all-clusters-app の
    /// VID 0xFFF1 / PID 0x8001 / discriminator 3840 / passcode 20202021 / on-network)。
    /// ビットレイアウトは仕様 §5.1.3 から独立に組み、この既知値で照合した。
    #[test]
    fn qr_payload_matches_chip_tool_vectors() {
        let mut buf = [0u8; QR_PAYLOAD_MAX_LEN];

        // (1) 有名な all-clusters-app の QR(on-network、caps = 4)。
        let n = qr_payload(
            &OnboardingPayload {
                vendor_id: 0xFFF1,
                product_id: 0x8001,
                discriminator: 3840,
                passcode: 20202021,
                discovery_caps: DISCOVERY_CAP_ON_NETWORK,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..n], b"MT:-24J0AFN00KA0648G00");

        // (2) 設計 §17.2 の例(VID 0xFFF1 / PID 0x8000 / BLE、caps = 2)。
        let n = qr_payload(
            &OnboardingPayload {
                vendor_id: 0xFFF1,
                product_id: 0x8000,
                discriminator: 3840,
                passcode: 20202021,
                discovery_caps: DISCOVERY_CAP_BLE,
            },
            &mut buf,
        )
        .unwrap();
        assert_eq!(&buf[..n], b"MT:Y.K9042C00KA0648G00");
        assert_eq!(n, QR_PAYLOAD_MAX_LEN);
    }

    #[test]
    fn qr_payload_rejects_short_buffer() {
        let mut buf = [0u8; QR_PAYLOAD_MAX_LEN - 1];
        assert!(qr_payload(
            &OnboardingPayload {
                vendor_id: 0,
                product_id: 0,
                discriminator: 0,
                passcode: 1,
                discovery_caps: 0,
            },
            &mut buf,
        )
        .is_err());
    }

    /// discriminator / passcode の各ビットが所定の位置に載っていること(境界値)。
    #[test]
    fn qr_payload_uses_low_12_bits_of_discriminator() {
        let mut a = [0u8; QR_PAYLOAD_MAX_LEN];
        let mut b = [0u8; QR_PAYLOAD_MAX_LEN];
        let base = OnboardingPayload {
            vendor_id: 0xFFF1,
            product_id: 0x8001,
            discriminator: 3840,
            passcode: 20202021,
            discovery_caps: DISCOVERY_CAP_ON_NETWORK,
        };
        let n = qr_payload(&base, &mut a).unwrap();
        let m = qr_payload(
            &OnboardingPayload {
                discriminator: 3840 | 0xF000, // 上位 4 ビットは無視される
                ..base
            },
            &mut b,
        )
        .unwrap();
        assert_eq!(a[..n], b[..m]);
    }

    /// 出典: chip-tool の既定テスト値(discriminator 3840 / passcode 20202021)。
    /// smctl の `manual_pairing_code_matches_chip_tool` から移設。
    #[test]
    fn manual_pairing_code_matches_chip_tool() {
        assert_eq!(&manual_pairing_code(3840, 20202021), b"34970112332");
        // discriminator が 12 ビット全域でも 11 桁に収まる。
        let c = manual_pairing_code(0x0FFF, 99_999_998);
        assert_eq!(c.len(), MANUAL_CODE_LEN);
        assert!(c.iter().all(|b| b.is_ascii_digit()));
    }

    #[test]
    fn passcode_validity() {
        assert!(passcode_is_valid(20202021));
        assert!(passcode_is_valid(1));
        assert!(passcode_is_valid(99_999_998));
        assert!(!passcode_is_valid(0));
        assert!(!passcode_is_valid(11111111));
        assert!(!passcode_is_valid(12345678));
        assert!(!passcode_is_valid(87654321));
        assert!(!passcode_is_valid(99_999_999));
        assert!(!passcode_is_valid(100_000_000));
    }

    /// 決定的な擬似乱数(テスト用)。
    struct SeqRng(u64);
    impl Rng for SeqRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for b in dest.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn random_passcode_and_discriminator_are_in_range() {
        let mut rng = SeqRng(0x1234_5678_9ABC_DEF0);
        for _ in 0..64 {
            assert!(passcode_is_valid(random_passcode(&mut rng).unwrap()));
            assert!(random_discriminator(&mut rng).unwrap() <= 0x0FFF);
        }
    }
}
