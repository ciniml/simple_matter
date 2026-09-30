//! `smctl` ライブラリ — chip-tool 風の CLI コントローラ(`docs/design/cli-controller.md`)の本体。
//!
//! バイナリ `smctl`(`main.rs`)はこのライブラリの [`cli::run`] を呼ぶだけの薄い層。
//! Web コントローラ `smweb`(`docs/design/web-controller.md` §3)も同じ駆動コード
//! (ランナー・状態ストア・クラスタ表・[`ops::Exec`])を再利用する。
//!
//! 以下、CLI としての沿革:
//!
//! - C1: UDP pairing(mDNS ブラウズ / アドレス直指定)+ 名前ベースのクラスタ操作
//!   (on-off / basic-information)+ Subscribe(レポート常駐表示)。
//! - C2: `any read/write/invoke`(ID 直指定 + 型付きリテラル + hex TLV)、`discover`、
//!   BLE pairing(feature `ble`: `pairing ble` / `pairing ble-handoff`)、
//!   バッチ実行(`smctl batch <file|->`、単一プロセスで CASE セッションと購読を共有)。
//! - C3: クラスタテーブル拡充(identify / level-control / descriptor /
//!   general-commissioning / network-commissioning / administrator-commissioning /
//!   operational-credentials)と `--json`(1 行 1 オブジェクトの機械可読出力)。
//!
//! 開発・自作デバイス用ツール。attestation は既定で PAA を辿らない最小検証
//! (`AttestationPolicy::VerifyNoPaa`: DAC←PAI + 署名 + nonce + CD + 報告 VID/PID)。
//! `--paa-trust-store-path <dir>` 指定時は PAA まで完全検証(`Verify`)、
//! `--bypass-attestation` で明示スキップ(`Skip`)する(`docs/design/attestation.md` §8)。

/// コア crate の再エクスポート(`smweb` が TLV 型等を同一バージョンで使うため)。
pub use simple_matter;

pub mod batch;
pub mod cli;
pub mod clusters;
pub mod json;
pub mod log;
pub mod ops;
pub mod runner;
pub mod state;
pub mod tlvfmt;
pub mod wire;

/// OS の CSPRNG による [`Rng`](simple_matter::crypto::Rng) 実装(設計 doc §2.5)。
///
/// examples の `DemoRng`(LCG)は持ち込まない。`getrandom` は Linux/Windows/macOS で
/// OS のエントロピー源(`getrandom(2)` / `BCryptGenRandom` 等)を叩く。
pub struct OsRng;

impl simple_matter::crypto::Rng for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> simple_matter::error::Result<()> {
        getrandom::fill(dest).map_err(|_| simple_matter::Error::Crypto)
    }
}
