//! CA 鍵素材の永続化(設計 doc §4.1)。
//!
//! `simple-matter-ble/examples/ble-commissioner.rs` の `ca-state.bin` **v1 フォーマットを
//! 変更なしで移植**した(互換ゲート: example で作った状態ファイルをそのまま持ち込める)。
//! codec 本体(v1 TLV の encode/decode)は S3 ハブ(`ports/esp32s3` の `EspKvs` キー
//! `b"cast"`)と共有するためコアの [`Ca::encode_state`] / [`Ca::decode_state`] に移した
//! (`docs/design/esp32-controller.md` §5.2)。本モジュールはファイル I/O の薄い皮のみ。
//! 復元は [`Ca::restore`](証明書は決定的署名により鍵から再生成)。

use std::path::Path;

use simple_matter::controller::ca::{Ca, CA_STATE_MAX_LEN};

use crate::runner::Backend;
use crate::OsRng;

// --- コントローラ fabric / ノード識別子(examples と同じ値。新規生成時のみ使用)---
const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
const VENDOR_ID: u16 = 0xFFF1;

/// CA の鍵素材を TLV でファイルへ保存する(v1 フォーマット)。
pub fn save(path: &Path, ca: &Ca<Backend>) -> Result<(), String> {
    let mut buf = [0u8; CA_STATE_MAX_LEN];
    let len = ca
        .encode_state(&mut buf)
        .map_err(|e| format!("encode CA state: {e:?}"))?;
    std::fs::write(path, &buf[..len]).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

/// 保存済み CA 状態からの復元。ファイルが無ければ `Ok(None)`。
pub fn load(path: &Path, crypto: &Backend) -> Result<Option<Ca<Backend>>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    Ca::decode_state(crypto, &bytes, 0)
        .map(Some)
        .map_err(|e| format!("restore CA from {}: {e:?}", path.display()))
}

/// CA を復元、無ければ新規生成して保存する。
pub fn load_or_create(path: &Path, crypto: &Backend) -> Result<Ca<Backend>, String> {
    if let Some(ca) = load(path, crypto)? {
        crate::log::logf!(
            crate::log::Level::Info,
            "ctl",
            "ca: restored from {}",
            path.display()
        );
        return Ok(ca);
    }
    let ca = Ca::<Backend>::generate(
        crypto,
        &mut OsRng,
        FABRIC_ID,
        CONTROLLER_NODE_ID,
        VENDOR_ID,
        0,
    )
    .map_err(|e| format!("CA generate failed: {e:?}"))?;
    save(path, &ca)?;
    crate::log::logf!(
        crate::log::Level::Info,
        "ctl",
        "ca: generated new CA; state saved to {}",
        path.display()
    );
    Ok(ca)
}
