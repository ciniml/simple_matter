//! 工場出荷データ(factory data)の読み出し(`factory-data` feature)。
//!
//! `esp-matter-mfg-tool`(connectedhomeip / esp-matter の製造フロー)が生成する
//! **factory NVS パーティション**(`chip-factory` namespace)を no_std・ヒープレスで
//! 読み、コミッショニング資格情報 — discriminator / SPAKE2+ verifier(salt /
//! iteration count / w0‖L)/ VID / PID / DAC・PAI 証明書 / DAC 秘密鍵 — を取り出す。
//!
//! # 使い方
//!
//! ```ignore
//! let fd = FactoryData::parse(flash_slice)?;
//! let pase = fd.pase_config()?;                 // デバイス側 PASE 設定
//! let dac  = fd.dac_provider(&crypto, cd_der)?; // BorrowedDacProvider(cd は別供給)
//! ```
//!
//! # NVS フォーマットの要点(実 mfg-tool 生成物で裏取り)
//!
//! - namespace は `chip-factory`。
//! - `discriminator` / `iteration-count` / `vendor-id` / `product-id`: `u32`。
//! - `salt` / `verifier`: **`string` 型で base64 エンコードされたテキスト**を格納する
//!   (デバイス側で base64 デコードして生バイトを得る)。verifier は 97 バイトの
//!   `w0‖L`、salt は 16..=32 バイト。
//! - `dac-cert` / `pai-cert` / `dac-key` / `dac-pub-key`: `blob`(バイナリ)。
//!   証明書は X.509 DER、`dac-key` は生 P-256 秘密鍵 32 バイト。
//!
//! # スコープ外
//!
//! - 暗号化 NVS([`nvs`] 参照)。
//! - Certification Declaration(CD)は factory パーティションに含まれない構成が多い
//!   (含める場合はキー `cert-dclrn`。[`FactoryData::cert_declaration`] で読める)。
//!   含まれない場合は呼び出し側が別途 CD を供給する。

pub mod nvs;

use crate::crypto::{Crypto, P256_SECRET_KEY_LEN};
use crate::dm::clusters::{BorrowedDacProvider, KeypairDacSigner};
use crate::sc::PaseConfig;
use nvs::NvsReader;

/// factory 読み出しのエラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactoryError {
    /// `chip-factory` namespace が見つからない(未 flash / 別フォーマット)。
    NoFactoryNamespace,
    /// 必須キーが欠落している。
    MissingKey(&'static str),
    /// 値のフォーマットが不正(base64 / 長さ)。
    BadValue(&'static str),
    /// 暗号バックエンドでの鍵復元に失敗した。
    Crypto,
}

/// `chip-factory` namespace 名。
const NS: &str = "chip-factory";

/// SPAKE2+ verifier(`w0‖L`)長。
const VERIFIER_LEN: usize = 97;
/// salt の最大長。
const SALT_MAX: usize = 32;

/// factory NVS パーティションのビュー。全ゲッターはゼロコピー/ヒープレス。
#[derive(Clone, Copy)]
pub struct FactoryData<'a> {
    nvs: NvsReader<'a>,
}

impl<'a> FactoryData<'a> {
    /// フラッシュ内容の `&[u8]` から factory データを開く。
    ///
    /// `chip-factory` namespace が存在しなければ [`FactoryError::NoFactoryNamespace`]。
    pub fn parse(flash: &'a [u8]) -> Result<Self, FactoryError> {
        let nvs = NvsReader::new(flash);
        if !nvs.has_namespace(NS) {
            return Err(FactoryError::NoFactoryNamespace);
        }
        Ok(Self { nvs })
    }

    /// discriminator(12 ビット)。
    pub fn discriminator(&self) -> Result<u16, FactoryError> {
        self.nvs
            .get_u32(NS, "discriminator")
            .map(|v| (v & 0x0FFF) as u16)
            .ok_or(FactoryError::MissingKey("discriminator"))
    }

    /// SPAKE2+ iteration count。
    pub fn iteration_count(&self) -> Result<u32, FactoryError> {
        self.nvs
            .get_u32(NS, "iteration-count")
            .ok_or(FactoryError::MissingKey("iteration-count"))
    }

    /// Vendor ID。
    pub fn vendor_id(&self) -> Result<u16, FactoryError> {
        self.nvs
            .get_u32(NS, "vendor-id")
            .map(|v| v as u16)
            .ok_or(FactoryError::MissingKey("vendor-id"))
    }

    /// Product ID。
    pub fn product_id(&self) -> Result<u16, FactoryError> {
        self.nvs
            .get_u32(NS, "product-id")
            .map(|v| v as u16)
            .ok_or(FactoryError::MissingKey("product-id"))
    }

    /// SPAKE2+ verifier の salt(base64 デコード後の生バイト)を `out` に書き、長さを返す。
    pub fn salt(&self, out: &mut [u8; SALT_MAX]) -> Result<usize, FactoryError> {
        let b64 = self
            .nvs
            .get_str(NS, "salt")
            .ok_or(FactoryError::MissingKey("salt"))?;
        base64_decode(b64, out).ok_or(FactoryError::BadValue("salt"))
    }

    /// SPAKE2+ verifier 本体 `w0‖L`(97 バイト、base64 デコード後)を `out` に書く。
    pub fn verifier(&self, out: &mut [u8; VERIFIER_LEN]) -> Result<(), FactoryError> {
        let b64 = self
            .nvs
            .get_str(NS, "verifier")
            .ok_or(FactoryError::MissingKey("verifier"))?;
        let n = base64_decode(b64, out).ok_or(FactoryError::BadValue("verifier"))?;
        if n != VERIFIER_LEN {
            return Err(FactoryError::BadValue("verifier"));
        }
        Ok(())
    }

    /// DAC 証明書(X.509 DER)スライス。
    pub fn dac_cert(&self) -> Result<&'a [u8], FactoryError> {
        self.nvs
            .get_blob(NS, "dac-cert")
            .ok_or(FactoryError::MissingKey("dac-cert"))
    }

    /// PAI 証明書(X.509 DER)スライス。
    pub fn pai_cert(&self) -> Result<&'a [u8], FactoryError> {
        self.nvs
            .get_blob(NS, "pai-cert")
            .ok_or(FactoryError::MissingKey("pai-cert"))
    }

    /// DAC 秘密鍵(生 P-256 スカラ 32 バイト)。
    pub fn dac_key(&self) -> Result<[u8; P256_SECRET_KEY_LEN], FactoryError> {
        let raw = self
            .nvs
            .get_blob(NS, "dac-key")
            .ok_or(FactoryError::MissingKey("dac-key"))?;
        if raw.len() != P256_SECRET_KEY_LEN {
            return Err(FactoryError::BadValue("dac-key"));
        }
        let mut k = [0u8; P256_SECRET_KEY_LEN];
        k.copy_from_slice(raw);
        Ok(k)
    }

    /// Certification Declaration(CMS DER)。factory に含まれない場合は `None`。
    pub fn cert_declaration(&self) -> Option<&'a [u8]> {
        self.nvs.get_blob(NS, "cert-dclrn")
    }

    /// factory の verifier / salt / iteration count から [`PaseConfig`] を構築する。
    ///
    /// デバイスは passcode を保持せず、この verifier だけで PASE を成立させる。
    pub fn pase_config(&self) -> Result<PaseConfig, FactoryError> {
        let mut w0l = [0u8; VERIFIER_LEN];
        self.verifier(&mut w0l)?;
        let params = crate::dev_pase::verifier_params_from_w0l(&w0l)
            .ok_or(FactoryError::BadValue("verifier"))?;
        let mut salt = [0u8; SALT_MAX];
        let salt_len = self.salt(&mut salt)?;
        let iters = self.iteration_count()?;
        PaseConfig::from_verifier(params, &salt[..salt_len], iters)
            .map_err(|_| FactoryError::BadValue("verifier"))
    }

    /// DAC / PAI(factory 由来)と CD(呼び出し側供給)から [`BorrowedDacProvider`] を作る。
    ///
    /// DAC 秘密鍵は factory の生鍵から `crypto` で鍵ペアに復元する。CD は factory に
    /// 含まれないのが一般的なため引数で受ける([`Self::cert_declaration`] で読めた場合は
    /// それを渡してよい)。返る provider は factory スライスを借用するため、`self` が指す
    /// フラッシュ内容が生存する間のみ有効。
    pub fn dac_provider<C: Crypto>(
        &self,
        crypto: &C,
        cd_der: &'a [u8],
    ) -> Result<BorrowedDacProvider<'a, KeypairDacSigner<C::Keypair>>, FactoryError> {
        let dac = self.dac_cert()?;
        let pai = self.pai_cert()?;
        let key = self.dac_key()?;
        BorrowedDacProvider::from_raw_key(crypto, dac, pai, cd_der, &key)
            .map_err(|_| FactoryError::Crypto)
    }
}

/// 標準アルファベットの base64 をデコードして `out` に書き、長さを返す。
///
/// パディング(`=`)対応。ヒープレス。`out` に収まらない・不正文字があれば `None`。
fn base64_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    // 末尾の空白・NUL は無視。
    let mut end = input.len();
    while end > 0 && matches!(input[end - 1], b'\0' | b'\n' | b'\r' | b' ') {
        end -= 1;
    }
    let input = &input[..end];

    let mut acc: u32 = 0;
    let mut nbits = 0;
    let mut written = 0;
    for &c in input {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break, // パディング以降は無視。
            _ => return None,
        };
        acc = (acc << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            let byte = (acc >> nbits) as u8;
            if written >= out.len() {
                return None;
            }
            out[written] = byte;
            written += 1;
        }
    }
    Some(written)
}

#[cfg(test)]
mod tests;
