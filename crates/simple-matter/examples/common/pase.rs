//! examples 共有: 開発用 `PaseConfig` の構築(**デバイスコードに passcode を置かない**)。
//!
//! 既定は [`simple_matter::dev_pase`] の dev verifier 定数(passcode `20202021` 相当を
//! 事前計算した検証子)。環境変数 `SM_PASE_VERIFIER=<iterations>:<salt_hex>:<w0l_hex>` が
//! あればそれを使う(`smctl pase-verifier <passcode> ...` の出力をそのまま貼れる)。
//!
//! デバイスは passcode を保持しない(Matter セキュリティ要件)。passcode を扱うのは
//! コントローラ(prover)側だけ。各 example から `#[path = "common/pase.rs"]` で取り込む。

use simple_matter::crypto::spake2p::Spake2pVerifierParams;
use simple_matter::dev_pase;
use simple_matter::sc::PaseConfig;

/// 開発用 `PaseConfig` を作る(`SM_PASE_VERIFIER` があればそれを優先)。
#[allow(dead_code)]
pub fn config() -> PaseConfig {
    config_labeled().0
}

/// 開発用 `PaseConfig` と表示用ラベルを返す。
#[allow(dead_code)]
pub fn config_labeled() -> (PaseConfig, String) {
    match std::env::var("SM_PASE_VERIFIER") {
        Ok(s) if !s.trim().is_empty() => {
            let cfg = parse_env(&s).unwrap_or_else(|e| panic!("invalid SM_PASE_VERIFIER: {e}"));
            (cfg, "(verifier from SM_PASE_VERIFIER)".to_string())
        }
        _ => (
            dev_pase::dev_pase_config(),
            "(dev verifier for passcode 20202021)".to_string(),
        ),
    }
}

/// `SM_PASE_VERIFIER=<iterations>:<salt_hex>:<w0l_hex>` を `PaseConfig` に変換する。
#[allow(dead_code)]
fn parse_env(s: &str) -> Result<PaseConfig, String> {
    let mut it = s.trim().splitn(3, ':');
    let iters = it
        .next()
        .ok_or("expected <iterations>:<salt_hex>:<w0l_hex>")?;
    let salt_hex = it.next().ok_or("missing salt hex")?;
    let w0l_hex = it.next().ok_or("missing w0l hex")?;
    let iterations: u32 = iters
        .parse()
        .map_err(|_| format!("invalid iterations: {iters:?}"))?;
    let salt = hex(salt_hex)?;
    let w0l = hex(w0l_hex)?;
    let params: Spake2pVerifierParams = dev_pase::verifier_params_from_w0l(&w0l)
        .ok_or_else(|| format!("w0l must be 97 bytes, got {}", w0l.len()))?;
    PaseConfig::from_verifier(params, &salt, iterations).map_err(|e| format!("{e:?}"))
}

#[allow(dead_code)]
fn hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd-length hex: {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex: {s:?}")))
        .collect()
}
