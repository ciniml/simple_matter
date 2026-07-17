//! 開発専用の既定 SPAKE2+ verifier 定数。
//!
//! # なぜ verifier 定数を持つのか
//!
//! Matter のセキュリティ要件上、**デバイスは passcode を保持してはならない**。
//! デバイスが持ってよいのは SPAKE2+ の検証子 `(w0, L)` と `salt` / `iteration count`
//! だけで、passcode 自体は QR コード / ラベル(= コミッショナ側)にのみ存在する
//! (仕様 §3.10 / §6.3)。本モジュールはサンプル・移植先ファーム・C FFI シムが
//! `PaseConfig::from_passcode_default` を呼ばずに(= デバイスコードに passcode を
//! 置かずに)コミッショニングできるよう、**開発用の固定 verifier** を提供する。
//!
//! ここに埋め込む定数は passcode `20202021`(chip-tool 既定)・salt
//! `"SPAKE2P Key Salt"`・iteration count [`SPAKE2P_ITERATION_COUNT`] から事前計算した
//! ものである。コントローラ(prover)は passcode `20202021` を使い、デバイスは本定数
//! だけを持つ。両者の SPAKE2+ 計算が一致することで PASE が成立する。
//!
//! ## 再生成方法
//!
//! ```text
//! smctl pase-verifier 20202021 \
//!     --salt 5350414b453250204b65792053616c74 \
//!     --iterations 2000
//! ```
//!
//! (`5350...6c74` は `"SPAKE2P Key Salt"` の hex。出力の `w0_l` が [`DEV_W0_L`]。)
//!
//! # 本番では使わないこと
//!
//! 本定数は開発・CI・デモ専用。製品では機器ごとに固有の passcode を割り当て、工場で
//! `smctl pase-verifier`(またはそれ相当)で verifier を生成してデバイスへ書き込み、
//! [`PaseConfig::from_verifier`] で読み込む。

use crate::crypto::spake2p::{Spake2pVerifierParams, SPAKE2P_POINT_LEN, SPAKE2P_SCALAR_LEN};
use crate::sc::PaseConfig;

/// 開発用 dev verifier の salt(`"SPAKE2P Key Salt"`, 16 バイト)。
pub const DEV_SALT: [u8; 16] = *b"SPAKE2P Key Salt";

/// 開発用 dev verifier の iteration count(= [`SPAKE2P_ITERATION_COUNT`])。
pub const DEV_ITERATIONS: u32 = crate::sc::pase::SPAKE2P_ITERATION_COUNT;

/// 開発用 dev verifier の `w0 ‖ L`(97 バイト)。
///
/// passcode `20202021` / [`DEV_SALT`] / [`DEV_ITERATIONS`] から事前計算(モジュール
/// doc の `smctl pase-verifier` コマンド参照)。先頭 32 バイトが `w0`、続く 65 バイトが
/// `L`(SEC1 非圧縮点)。
pub const DEV_W0_L: [u8; SPAKE2P_SCALAR_LEN + SPAKE2P_POINT_LEN] = [
    0x7d, 0x04, 0x77, 0x6b, 0xb4, 0x69, 0xc4, 0x94, 0x92, 0x28, 0x30, 0x14, //
    0x4f, 0x3f, 0xa2, 0xf1, 0x9c, 0xfd, 0x82, 0xc0, 0x4d, 0x10, 0x8d, 0x8b, //
    0xa6, 0x35, 0x3f, 0xdd, 0x92, 0xc0, 0x1f, 0x93, 0x04, 0x51, 0x1b, 0x6c, //
    0x47, 0x65, 0xba, 0xb1, 0x47, 0x94, 0x9d, 0xd9, 0x42, 0xc4, 0x3b, 0x3d, //
    0x8d, 0xc6, 0x32, 0x30, 0x89, 0xca, 0x31, 0x89, 0xd9, 0xe4, 0xa5, 0x63, //
    0x6e, 0x16, 0xd8, 0x2f, 0x1a, 0xef, 0x72, 0x8b, 0x0d, 0x90, 0x2c, 0x1a, //
    0x9b, 0x0f, 0x7e, 0x96, 0x52, 0xab, 0x7f, 0x65, 0x78, 0x61, 0xb6, 0xbb, //
    0xac, 0xd6, 0xbf, 0xdf, 0x04, 0xf8, 0x07, 0x09, 0x24, 0x8b, 0x83, 0xde, //
    0xc7,
];

/// `w0 ‖ L` バイト列から [`Spake2pVerifierParams`] を作る。
///
/// `w0l` は `SPAKE2P_SCALAR_LEN + SPAKE2P_POINT_LEN`(97)バイト。長さが異なれば `None`。
pub fn verifier_params_from_w0l(w0l: &[u8]) -> Option<Spake2pVerifierParams> {
    if w0l.len() != SPAKE2P_SCALAR_LEN + SPAKE2P_POINT_LEN {
        return None;
    }
    let mut w0 = [0u8; SPAKE2P_SCALAR_LEN];
    let mut l = [0u8; SPAKE2P_POINT_LEN];
    w0.copy_from_slice(&w0l[..SPAKE2P_SCALAR_LEN]);
    l.copy_from_slice(&w0l[SPAKE2P_SCALAR_LEN..]);
    Some(Spake2pVerifierParams { w0, l })
}

/// 開発用 dev verifier の [`Spake2pVerifierParams`]。
pub fn dev_verifier_params() -> Spake2pVerifierParams {
    verifier_params_from_w0l(&DEV_W0_L).expect("DEV_W0_L is 97 bytes")
}

/// 開発用 dev verifier から [`PaseConfig`] を作る。
///
/// passcode を一切保持せずにデバイス側 PASE を成立させるための既定設定。上書きしたい
/// 場合は [`PaseConfig::from_verifier`] を直接呼ぶ(工場プロビジョニング相当)。
pub fn dev_pase_config() -> PaseConfig {
    PaseConfig::from_verifier(dev_verifier_params(), &DEV_SALT, DEV_ITERATIONS)
        .expect("dev verifier params are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dev 定数が passcode 20202021 から compute_verifier で導出した値と一致する
    /// (= コントローラの passcode 導出とデバイスの埋め込み verifier が整合)。
    #[test]
    fn dev_const_matches_passcode_derivation() {
        use crate::crypto::spake2p::compute_verifier;
        let derived = compute_verifier(20202021, &DEV_SALT, DEV_ITERATIONS).unwrap();
        let embedded = dev_verifier_params();
        assert_eq!(derived.w0, embedded.w0, "w0 mismatch");
        assert_eq!(derived.l, embedded.l, "L mismatch");
    }

    /// dev_pase_config が有効な PaseConfig を返す。
    #[test]
    fn dev_pase_config_builds() {
        let _cfg = dev_pase_config();
    }
}
