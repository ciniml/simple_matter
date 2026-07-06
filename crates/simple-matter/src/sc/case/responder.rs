//! CASE responder のプロトコルプリミティブのうち、**responder 方向固有**の外枠 codec。
//!
//! `docs/design/secure-channel.md` §7 / `docs/design/controller.md` §3.3 に基づく。
//! 両方向共用の部品(定数・S2K/S3K/SEKeys 導出・TBE 暗号化/復号・TBS 組み立て・
//! destination-id 計算)は [`super::common`] へ移動し、本モジュールは `pub use common::*`
//! で再エクスポートする(旧来の `case::responder::derive_sigma2_key` 等の呼び出しと
//! 既存テストを壊さない)。ここに残るのは responder 入口の [`Sigma1`] 解析と、responder が
//! 送る [`encode_sigma2`] / 受ける [`decode_sigma3`] の外枠のみである。
//!
//! TT へのフォールド順序(§7.1): Sigma2 の生バイトは TLV 直列化 **後**、Sigma3 の生バイトは
//! 証明書鎖・署名検証を **通過した後** に投入する(不正な Sigma3 で TT を汚さない)。

use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

pub use super::common::*;

/// Sigma1(initiator → responder)の解析結果(借用ビュー)。
#[derive(Debug, Clone, Copy)]
pub struct Sigma1<'a> {
    /// initiator の乱数(32 バイト)。
    pub initiator_random: &'a [u8],
    /// initiator が採番したワイヤ session id。
    pub initiator_sessid: u16,
    /// destination identifier(32 バイト)。
    pub destination_id: &'a [u8],
    /// initiator のエフェメラル公開鍵(SEC1 非圧縮 65 バイト)。
    pub initiator_eph_pub_key: &'a [u8],
    /// resumptionID(ctx6・16B。resumption 要求時のみ存在)。
    pub resumption_id: Option<&'a [u8]>,
    /// initiatorResumeMIC(ctx7・16B。resumption 要求時のみ存在)。
    pub resume_mic: Option<&'a [u8]>,
}

impl<'a> Sigma1<'a> {
    /// resumption 要求(ctx6/ctx7 とも存在)なら `true`。
    pub fn has_resumption(&self) -> bool {
        self.resumption_id.is_some() && self.resume_mic.is_some()
    }

    /// Sigma1 TLV payload を解析する。
    ///
    /// MRP `session_parameters`(ctx5)は読み飛ばす。resumption フィールド(ctx6/ctx7)は
    /// 値ごと借用で保持する(§7.4 の照合に用いる)。必須フィールド欠落・型不一致は
    /// [`Error::Decode`]。panic しない。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut initiator_random = None;
        let mut initiator_sessid = None;
        let mut destination_id = None;
        let mut initiator_eph_pub_key = None;
        let mut resumption_id = None;
        let mut resume_mic = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => initiator_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => initiator_sessid = Some(u16_of(&elem.value)?),
                TlvTag::ContextSpecific(3) => destination_id = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(4) => initiator_eph_pub_key = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(6) => resumption_id = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(7) => resume_mic = Some(elem.value.as_bytes()?),
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            initiator_random: initiator_random.ok_or(Error::Decode)?,
            initiator_sessid: initiator_sessid.ok_or(Error::Decode)?,
            destination_id: destination_id.ok_or(Error::Decode)?,
            initiator_eph_pub_key: initiator_eph_pub_key.ok_or(Error::Decode)?,
            resumption_id,
            resume_mic,
        })
    }
}

/// Sigma2 の外枠 TLV(responder → initiator)を `out` に直列化する。書き込み長を返す。
///
/// MRP responder `session_parameters`(ctx5)は初期スコープでは省略する(設計からの乖離:
/// optional フィールドのため相互運用に影響せず、テストでは両側を制御するため不要)。
pub fn encode_sigma2(
    out: &mut [u8],
    responder_random: &[u8],
    responder_sessid: u16,
    responder_eph_pub_key: &[u8],
    encrypted2: &[u8],
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), responder_random)?;
    w.write_u16(&TlvTag::ContextSpecific(2), responder_sessid)?;
    w.write_bytes(&TlvTag::ContextSpecific(3), responder_eph_pub_key)?;
    w.write_bytes(&TlvTag::ContextSpecific(4), encrypted2)?;
    w.end_container()?;
    Ok(w.len())
}

/// Sigma2_Resume の外枠 TLV(responder → initiator)を `out` に直列化する(§7.4)。
///
/// `{ ctx1: resumptionID(新規採番・16B), ctx2: sigma2ResumeMIC(16B),
/// ctx3: responderSessionID(u16) }`。MRP `session_parameters`(ctx4)はフル Sigma2 と
/// 同じ割り切りで省略する(optional)。書き込み長を返す。
pub fn encode_sigma2_resume(
    out: &mut [u8],
    new_resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    resume_mic: &[u8; RESUME_MIC_LEN],
    responder_sessid: u16,
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), new_resumption_id)?;
    w.write_bytes(&TlvTag::ContextSpecific(2), resume_mic)?;
    w.write_u16(&TlvTag::ContextSpecific(3), responder_sessid)?;
    w.end_container()?;
    Ok(w.len())
}

/// Sigma3(initiator → responder)を解析し、encrypted3(TBEData3 + tag)への借用を返す。
pub fn decode_sigma3(payload: &[u8]) -> Result<&[u8]> {
    let mut r = TlvReader::new(payload);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut encrypted3 = None;
    while let Some(elem) = r.read_next()? {
        if matches!(elem.value, TlvValue::ContainerEnd) {
            break;
        }
        match elem.tag {
            TlvTag::ContextSpecific(1) => encrypted3 = Some(elem.value.as_bytes()?),
            _ => r.skip(&elem)?,
        }
    }
    encrypted3.ok_or(Error::Decode)
}

/// TLV 値を `u16` として取り出す(範囲外は [`Error::Decode`])。
fn u16_of(v: &TlvValue<'_>) -> Result<u16> {
    u16::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma1_round_trip_and_resumption_flags() {
        let ir = [0x11u8; CASE_RANDOM_LEN];
        let dest = [0x22u8; CASE_DEST_ID_LEN];
        let epk = [0x04u8; CASE_EPH_PUBLIC_KEY_LEN];
        let mut buf = [0u8; 256];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &ir).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(2), 0x1234).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(3), &dest).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(4), &epk).unwrap();
            // resumption fields present.
            w.write_bytes(
                &TlvTag::ContextSpecific(6),
                &[0xAAu8; CASE_RESUMPTION_ID_LEN],
            )
            .unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(7), &[0xBBu8; 16])
                .unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let s1 = Sigma1::decode(&buf[..n]).unwrap();
        assert_eq!(s1.initiator_random, &ir);
        assert_eq!(s1.initiator_sessid, 0x1234);
        assert_eq!(s1.destination_id, &dest);
        assert_eq!(s1.initiator_eph_pub_key, &epk);
        assert_eq!(s1.resumption_id, Some(&[0xAAu8; 16][..]));
        assert_eq!(s1.resume_mic, Some(&[0xBBu8; 16][..]));
        assert!(s1.has_resumption());
    }

    /// chip-tool 実ワイヤ相当: MRP `session_parameters`(ctx5・ネスト struct)が
    /// resumption フィールド(ctx6/ctx7)の**前**に挟まっても正しく読める。
    #[test]
    fn sigma1_with_mrp_params_before_resumption_fields() {
        let ir = [0x11u8; CASE_RANDOM_LEN];
        let dest = [0x22u8; CASE_DEST_ID_LEN];
        let epk = [0x04u8; CASE_EPH_PUBLIC_KEY_LEN];
        let mut buf = [0u8; 320];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &ir).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(2), 0x1234).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(3), &dest).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(4), &epk).unwrap();
            // ctx5: MRP session params(ネスト struct)。
            w.start_struct(&TlvTag::ContextSpecific(5)).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(1), 500).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(2), 300).unwrap();
            w.write_u16(&TlvTag::ContextSpecific(4), 4000).unwrap();
            w.end_container().unwrap();
            w.write_bytes(
                &TlvTag::ContextSpecific(6),
                &[0xAAu8; CASE_RESUMPTION_ID_LEN],
            )
            .unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(7), &[0xBBu8; 16])
                .unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let s1 = Sigma1::decode(&buf[..n]).unwrap();
        assert!(s1.has_resumption());
        assert_eq!(s1.resumption_id, Some(&[0xAAu8; 16][..]));
    }

    #[test]
    fn sigma2_resume_encodes_expected_fields() {
        let rid = [0xCDu8; CASE_RESUMPTION_ID_LEN];
        let mic = [0xEFu8; RESUME_MIC_LEN];
        let mut buf = [0u8; 128];
        let n = encode_sigma2_resume(&mut buf, &rid, &mic, 0xBEEF).unwrap();
        let mut r = crate::tlv::TlvReader::new(&buf[..n]);
        r.enter_container().unwrap();
        let e1 = r.read_next().unwrap().unwrap();
        assert_eq!(e1.value.as_bytes().unwrap(), &rid);
        let e2 = r.read_next().unwrap().unwrap();
        assert_eq!(e2.value.as_bytes().unwrap(), &mic);
        let e3 = r.read_next().unwrap().unwrap();
        assert_eq!(e3.value.as_unsigned().unwrap(), 0xBEEF);
    }

    #[test]
    fn sigma3_and_tbe_round_trip() {
        // encrypted3 field round-trips.
        let enc = [0x99u8; 120];
        let mut buf = [0u8; 200];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &enc).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        assert_eq!(decode_sigma3(&buf[..n]).unwrap(), &enc[..]);

        // TBE certs struct round-trips (with ICAC) via re-exported common::decode_tbe_certs.
        let noc = [0x01u8; 40];
        let icac = [0x02u8; 30];
        let sig = [0x03u8; SIGNATURE_LEN];
        let mut tb = [0u8; 256];
        let m = {
            let mut w = TlvWriter::new(&mut tb);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &noc).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(2), &icac).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(3), &sig).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        let (dn, di, ds) = decode_tbe_certs(&tb[..m]).unwrap();
        assert_eq!(dn, &noc[..]);
        assert_eq!(di, Some(&icac[..]));
        assert_eq!(ds, &sig[..]);
    }
}
