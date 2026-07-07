//! CA 鍵素材の永続化(設計 doc §4.1)。
//!
//! `simple-matter-ble/examples/ble-commissioner.rs` の `ca-state.bin` **v1 フォーマットを
//! 変更なしで移植**した(互換ゲート: example で作った状態ファイルをそのまま持ち込める)。
//! version=1 の TLV struct に root 秘密鍵・コントローラ運用秘密鍵・IPK epoch key・
//! fabric_id・controller_node_id・vendor_id・next_serial を持つ。
//! 復元は [`Ca::restore`](証明書は決定的署名により鍵から再生成)。

use std::path::Path;

use simple_matter::controller::ca::Ca;
use simple_matter::error::Result as MResult;
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

use crate::runner::Backend;
use crate::OsRng;

/// CA 状態レコードの schema version(v1: ble-commissioner 互換)。
const CA_STATE_VERSION: u8 = 1;

// --- コントローラ fabric / ノード識別子(examples と同じ値。新規生成時のみ使用)---
const FABRIC_ID: u64 = 0xFAB0_0000_0000_0001;
const CONTROLLER_NODE_ID: u64 = 0x0000_0000_1122_3344;
const VENDOR_ID: u16 = 0xFFF1;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// CA の鍵素材を TLV でファイルへ保存する(v1 フォーマット)。
pub fn save(path: &Path, ca: &Ca<Backend>) -> Result<(), String> {
    let ctrl_key = ca
        .controller_key_bytes()
        .map_err(|e| format!("controller_key_bytes: {e:?}"))?;
    let mut buf = [0u8; 192];
    let len = {
        let mut w = TlvWriter::new(&mut buf);
        let write = |w: &mut TlvWriter| -> MResult<()> {
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), CA_STATE_VERSION)?;
            w.write_u64(&cx(1), ca.fabric_id())?;
            w.write_u64(&cx(2), ca.controller_node_id())?;
            w.write_u16(&cx(3), ca.vendor_id())?;
            w.write_bytes(&cx(4), ca.ipk_epoch_key())?;
            w.write_bytes(&cx(5), &ca.root_key_bytes())?;
            w.write_bytes(&cx(6), &ctrl_key)?;
            w.write_u32(&cx(7), ca.next_serial())?;
            w.end_container()
        };
        write(&mut w).map_err(|e| format!("encode CA state: {e:?}"))?;
        w.len()
    };
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
    let decode = || -> MResult<Ca<Backend>> {
        let mut r = TlvReader::new(&bytes);
        if r.enter_container()? != ContainerType::Structure {
            return Err(simple_matter::Error::Decode);
        }
        let mut version = 0u8;
        let mut fabric_id = 0u64;
        let mut node_id = 0u64;
        let mut vendor_id = 0u16;
        let mut ipk = [0u8; 16];
        let mut root_key = [0u8; 32];
        let mut ctrl_key = [0u8; 32];
        let mut next_serial = 0u32;
        loop {
            let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
                (TlvTag::ContextSpecific(1), v) => fabric_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(2), v) => node_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(3), v) => vendor_id = v.as_unsigned()? as u16,
                (TlvTag::ContextSpecific(4), v) => {
                    ipk = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(5), v) => {
                    root_key = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(6), v) => {
                    ctrl_key = v
                        .as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?
                }
                (TlvTag::ContextSpecific(7), v) => next_serial = v.as_unsigned()? as u32,
                _ => r.skip(&e)?,
            }
        }
        if version != CA_STATE_VERSION {
            return Err(simple_matter::Error::Decode);
        }
        Ca::restore(
            crypto,
            &root_key,
            &ctrl_key,
            ipk,
            fabric_id,
            node_id,
            vendor_id,
            next_serial,
            0,
        )
    };
    decode()
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
