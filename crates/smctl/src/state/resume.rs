//! CASE resumption 素材 `resume/<node-id>.tlv`(設計 doc §4.3)。
//!
//! 1 ノード 1 ファイル(部分更新・削除が単純)。versioned TLV(手書きエンコーダで
//! 依存追加なし、`nodes.tlv` と同じ流儀):
//!
//! ```text
//! struct(anonymous) {
//!   0: u8    version (=1)
//!   1: bytes resumption_id (16 バイト、現行 resumptionID)
//!   2: bytes shared_secret (32 バイト、フル CASE の ECDH SharedSecret)
//! }
//! ```
//!
//! 管理(置き場・ローテート・破棄)はアプリ層 = smctl、コアは
//! `ScInitiator::resumption_export/import` のみ(E4 と同じ分業)。
//! resumption 失敗時はコアがフル CASE へフォールバックし、確立後に新素材で上書きする。

use std::path::{Path, PathBuf};

use simple_matter::error::Result as MResult;
use simple_matter::sc::case::common::{CASE_RESUMPTION_ID_LEN, SHARED_SECRET_LEN};
use simple_matter::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// resumption レコードの schema version。
const RESUME_VERSION: u8 = 1;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// 永続化する resumption 素材(コアの export/import と 1:1)。
#[derive(Clone)]
pub struct ResumeMaterial {
    /// 現行 resumptionID(セッション確立ごとにローテート)。
    pub resumption_id: [u8; CASE_RESUMPTION_ID_LEN],
    /// フル CASE の ECDH SharedSecret(resumption を繰り返しても不変)。
    pub shared_secret: [u8; SHARED_SECRET_LEN],
}

/// `resume/<node-id>.tlv` のパス(node_id は 10 進)。
pub fn path_for(dir: &Path, node_id: u64) -> PathBuf {
    dir.join("resume").join(format!("{node_id}.tlv"))
}

/// resumption 素材を読む。ファイルが無ければ `None`(フル CASE へ)。
///
/// 壊れたファイル・版違いは Err にせず `None` を返して捨てる(素材はキャッシュであり、
/// フル CASE フォールバックで常に回復できるため。読めない素材で起動を止めない)。
pub fn load(path: &Path) -> Option<ResumeMaterial> {
    let bytes = std::fs::read(path).ok()?;
    decode(&bytes).ok()
}

/// resumption 素材を書く(全量書き換え。親ディレクトリは無ければ作る)。
pub fn save(path: &Path, m: &ResumeMaterial) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let mut buf = [0u8; 96];
    let len = {
        let mut w = TlvWriter::new(&mut buf);
        encode(&mut w, m).map_err(|e| format!("encode resume: {e:?}"))?;
        w.len()
    };
    std::fs::write(path, &buf[..len]).map_err(|e| format!("write {}: {e}", path.display()))
}

fn encode(w: &mut TlvWriter, m: &ResumeMaterial) -> MResult<()> {
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_u8(&cx(0), RESUME_VERSION)?;
    w.write_bytes(&cx(1), &m.resumption_id)?;
    w.write_bytes(&cx(2), &m.shared_secret)?;
    w.end_container()
}

fn decode(bytes: &[u8]) -> MResult<ResumeMaterial> {
    let mut r = TlvReader::new(bytes);
    if r.enter_container()? != ContainerType::Structure {
        return Err(simple_matter::Error::Decode);
    }
    let mut version = 0u8;
    let mut rid: Option<[u8; CASE_RESUMPTION_ID_LEN]> = None;
    let mut secret: Option<[u8; SHARED_SECRET_LEN]> = None;
    loop {
        let e = r.read_next()?.ok_or(simple_matter::Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
            (TlvTag::ContextSpecific(1), v) => {
                rid = Some(
                    v.as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?,
                );
            }
            (TlvTag::ContextSpecific(2), v) => {
                secret = Some(
                    v.as_bytes()?
                        .try_into()
                        .map_err(|_| simple_matter::Error::Decode)?,
                );
            }
            _ => r.skip(&e)?,
        }
    }
    if version != RESUME_VERSION {
        return Err(simple_matter::Error::Decode);
    }
    Ok(ResumeMaterial {
        resumption_id: rid.ok_or(simple_matter::Error::Decode)?,
        shared_secret: secret.ok_or(simple_matter::Error::Decode)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("smctl-resume-test-{}", std::process::id()));
        let path = path_for(&dir, 42);
        assert!(load(&path).is_none());
        let m = ResumeMaterial {
            resumption_id: [0xAB; CASE_RESUMPTION_ID_LEN],
            shared_secret: [0xCD; SHARED_SECRET_LEN],
        };
        save(&path, &m).unwrap();
        let got = load(&path).expect("load");
        assert_eq!(got.resumption_id, m.resumption_id);
        assert_eq!(got.shared_secret, m.shared_secret);
        // ローテート(上書き)。
        let m2 = ResumeMaterial {
            resumption_id: [0x11; CASE_RESUMPTION_ID_LEN],
            shared_secret: [0xCD; SHARED_SECRET_LEN],
        };
        save(&path, &m2).unwrap();
        assert_eq!(load(&path).unwrap().resumption_id, m2.resumption_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_or_wrong_version_is_none() {
        let dir = std::env::temp_dir().join(format!("smctl-resume-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("1.tlv");
        std::fs::write(&path, b"not tlv").unwrap();
        assert!(load(&path).is_none());
        // version=2 のファイルは捨てる。
        let m = ResumeMaterial {
            resumption_id: [0; CASE_RESUMPTION_ID_LEN],
            shared_secret: [0; SHARED_SECRET_LEN],
        };
        let mut buf = [0u8; 96];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_u8(&cx(0), 2).unwrap();
            w.write_bytes(&cx(1), &m.resumption_id).unwrap();
            w.write_bytes(&cx(2), &m.shared_secret).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        std::fs::write(&path, &buf[..len]).unwrap();
        assert!(load(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
