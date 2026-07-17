//! examples 共有: 工場出荷データ(factory data)からの資格情報供給。
//!
//! 製造フロー(`esp-matter-mfg-tool`)が発行した DAC / PAI / DAC 秘密鍵 / SPAKE2+
//! verifier をホスト上の example に供給し、[`BorrowedDacProvider`] 経由の attestation
//! と factory verifier での PASE を実証する(docs/design/factory-data.md §5)。
//!
//! # 供給元(環境変数)
//!
//! - `SM_FACTORY_NVS=<path>`(**`factory-data` feature 必須**): mfg-tool 生成の factory
//!   NVS パーティション(`*-partition.bin`)を [`FactoryData`] でパースし、DAC/PAI/鍵 +
//!   verifier + discriminator + VID/PID を一括で得る。CD は NVS に含まれなければ
//!   `SM_FACTORY_CD`(DER ファイル)→ dev CD の順にフォールバック。
//! - `SM_FACTORY_DIR=<dir>`: DER ファイル群から DAC を供給する
//!   (`dac.der` / `pai.der` / `dac_key.bin`、CD は `cd.der` → dev CD)。verifier は
//!   `common_pase`(`SM_PASE_VERIFIER`)、discriminator は `SM_DISCRIMINATOR` を使う。
//!
//! いずれも未設定なら [`load`] は `None` を返し、呼び出し側は従来の dev 資格情報を使う。
//!
//! 読み込んだ DER / 鍵はプロセス生存期間 leak して `&'static` にする(example 専用の
//! 割り切り。[`BorrowedDacProvider`] は借用スライスを要求するため)。

#![allow(dead_code)]

use simple_matter::dm::clusters::operational_credentials::dev_creds::DEV_CD_FOR_ALL_EXAMPLES;
use simple_matter::sc::PaseConfig;

/// factory から供給する資格情報一式。
pub struct FactoryMaterials {
    /// factory verifier 由来の PASE 設定(NVS モードのみ。DIR モードは `None`)。
    pub pase: Option<PaseConfig>,
    /// factory discriminator(NVS モードのみ)。
    pub discriminator: Option<u16>,
    /// Vendor ID(NVS モードのみ)。
    pub vendor_id: Option<u16>,
    /// Product ID(NVS モードのみ)。
    pub product_id: Option<u16>,
    /// DAC 証明書(X.509 DER)。
    pub dac_der: &'static [u8],
    /// PAI 証明書(X.509 DER)。
    pub pai_der: &'static [u8],
    /// Certification Declaration(CMS DER)。
    pub cd_der: &'static [u8],
    /// DAC 生秘密鍵(P-256 スカラ 32 バイト)。
    pub dac_key: [u8; 32],
}

fn leak_file(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("factory: cannot read {path}: {e}"))
}

fn leaked(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// CD を `SM_FACTORY_CD`(DER ファイル)→ dev CD の順に解決する。
fn resolve_cd() -> &'static [u8] {
    match std::env::var("SM_FACTORY_CD") {
        Ok(p) if !p.trim().is_empty() => leaked(leak_file(&p)),
        _ => &DEV_CD_FOR_ALL_EXAMPLES,
    }
}

/// factory 資格情報を読み込む(環境変数未設定なら `None`)。
pub fn load() -> Option<FactoryMaterials> {
    if let Ok(nvs_path) = std::env::var("SM_FACTORY_NVS") {
        if !nvs_path.trim().is_empty() {
            return Some(load_nvs(&nvs_path));
        }
    }
    if let Ok(dir) = std::env::var("SM_FACTORY_DIR") {
        if !dir.trim().is_empty() {
            return Some(load_dir(&dir));
        }
    }
    None
}

/// `SM_FACTORY_DIR` の DER ファイル群から DAC を供給する。
fn load_dir(dir: &str) -> FactoryMaterials {
    let p = |name: &str| format!("{}/{}", dir.trim_end_matches('/'), name);
    let dac_der = leaked(leak_file(&p("dac.der")));
    let pai_der = leaked(leak_file(&p("pai.der")));
    let key_raw = leak_file(&p("dac_key.bin"));
    assert_eq!(key_raw.len(), 32, "dac_key.bin must be 32 raw bytes");
    let mut dac_key = [0u8; 32];
    dac_key.copy_from_slice(&key_raw);
    let cd_der = match std::fs::read(p("cd.der")) {
        Ok(b) => leaked(b),
        Err(_) => resolve_cd(),
    };
    eprintln!("[factory] loaded DAC/PAI from SM_FACTORY_DIR={dir}");
    FactoryMaterials {
        pase: None,
        discriminator: None,
        vendor_id: None,
        product_id: None,
        dac_der,
        pai_der,
        cd_der,
        dac_key,
    }
}

/// `SM_FACTORY_NVS` の NVS パーティションから資格情報一式を供給する。
#[cfg(feature = "factory-data")]
fn load_nvs(path: &str) -> FactoryMaterials {
    use simple_matter::factory::FactoryData;
    let flash: &'static [u8] = leaked(leak_file(path));
    let fd = FactoryData::parse(flash).unwrap_or_else(|e| panic!("factory: parse {path}: {e:?}"));
    let pase = fd.pase_config().expect("factory: pase config");
    let discriminator = fd.discriminator().expect("factory: discriminator");
    let vendor_id = fd.vendor_id().expect("factory: vendor-id");
    let product_id = fd.product_id().expect("factory: product-id");
    let dac_der = fd.dac_cert().expect("factory: dac-cert");
    let pai_der = fd.pai_cert().expect("factory: pai-cert");
    let dac_key = fd.dac_key().expect("factory: dac-key");
    // CD は NVS 内(cert-dclrn)→ SM_FACTORY_CD → dev CD の順。
    let cd_der = fd.cert_declaration().unwrap_or_else(|| resolve_cd());
    eprintln!(
        "[factory] loaded from SM_FACTORY_NVS={path}: VID={vendor_id:#06x} PID={product_id:#06x} \
         discriminator={discriminator} (DAC {} B, PAI {} B, CD {} B)",
        dac_der.len(),
        pai_der.len(),
        cd_der.len()
    );
    FactoryMaterials {
        pase: Some(pase),
        discriminator: Some(discriminator),
        vendor_id: Some(vendor_id),
        product_id: Some(product_id),
        dac_der,
        pai_der,
        cd_der,
        dac_key,
    }
}

/// `factory-data` feature 無効時に `SM_FACTORY_NVS` を使うとビルド時に気付けるよう panic する。
#[cfg(not(feature = "factory-data"))]
fn load_nvs(_path: &str) -> FactoryMaterials {
    panic!("SM_FACTORY_NVS requires building with --features factory-data");
}
