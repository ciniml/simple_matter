//! CASE **initiator**(コミッショナ)方向の鏡像 codec と往復状態。
//!
//! `docs/design/controller.md` §3.3 / §3.4 に基づく。両方向共用の鍵導出・TBE・TBS は
//! [`crate::sc::case::common`] を再利用し、initiator にしか無い外枠 codec(Sigma1 エンコード・
//! Sigma2 デコード・Sigma3 エンコード・TBEData3 の暗号化)を足す。往復をまたぐ状態機械本体は
//! [`super::ScInitiator`](crate::sc::initiator::ScInitiator) が駆動する。

use core::num::NonZeroU8;

use zeroize::Zeroizing;

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::sc::case::common as case;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// Sigma1(initiator → responder)を `out` に直列化する。書き込み長を返す。
///
/// MRP `session_parameters`(ctx5)は初期スコープでは省略する(responder [`encode_sigma2`] と
/// 同じ乖離。optional のため相互運用に影響せず、テストは両側を制御する)。
///
/// `resumption` に `(resumptionID, initiatorResumeMIC)` を渡すと ctx6/ctx7 を付けて
/// session resumption を要求する(`docs/design/secure-channel.md` §7.4)。
///
/// [`encode_sigma2`]: crate::sc::case::responder::encode_sigma2
pub fn encode_sigma1(
    out: &mut [u8],
    initiator_random: &[u8; case::CASE_RANDOM_LEN],
    initiator_ssid: u16,
    destination_id: &[u8; case::CASE_DEST_ID_LEN],
    eph_pub: &[u8; case::CASE_EPH_PUBLIC_KEY_LEN],
    resumption: Option<(
        &[u8; case::CASE_RESUMPTION_ID_LEN],
        &[u8; case::RESUME_MIC_LEN],
    )>,
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), initiator_random)?;
    w.write_u16(&TlvTag::ContextSpecific(2), initiator_ssid)?;
    w.write_bytes(&TlvTag::ContextSpecific(3), destination_id)?;
    w.write_bytes(&TlvTag::ContextSpecific(4), eph_pub)?;
    if let Some((rid, mic)) = resumption {
        w.write_bytes(&TlvTag::ContextSpecific(6), rid)?;
        w.write_bytes(&TlvTag::ContextSpecific(7), mic)?;
    }
    w.end_container()?;
    Ok(w.len())
}

/// Sigma2(responder → initiator)の解析結果(借用ビュー)。
#[derive(Debug, Clone, Copy)]
pub struct Sigma2<'a> {
    /// responder の乱数(32 バイト)。
    pub responder_random: &'a [u8],
    /// responder が採番したワイヤ session id。
    pub responder_ssid: u16,
    /// responder のエフェメラル公開鍵(SEC1 非圧縮 65 バイト)。
    pub eph_pub: &'a [u8],
    /// TBEData2 の暗号文 + tag。
    pub encrypted2: &'a [u8],
}

impl<'a> Sigma2<'a> {
    /// Sigma2 TLV payload を解析する。必須フィールド欠落・型不一致は [`Error::Decode`]。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut responder_random = None;
        let mut responder_ssid = None;
        let mut eph_pub = None;
        let mut encrypted2 = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => responder_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => {
                    responder_ssid =
                        Some(u16::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
                }
                TlvTag::ContextSpecific(3) => eph_pub = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(4) => encrypted2 = Some(elem.value.as_bytes()?),
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            responder_random: responder_random.ok_or(Error::Decode)?,
            responder_ssid: responder_ssid.ok_or(Error::Decode)?,
            eph_pub: eph_pub.ok_or(Error::Decode)?,
            encrypted2: encrypted2.ok_or(Error::Decode)?,
        })
    }
}

/// Sigma2_Resume(responder → initiator)の解析結果(借用ビュー。§7.4)。
#[derive(Debug, Clone, Copy)]
pub struct Sigma2Resume<'a> {
    /// responder が新規採番した resumptionID(16 バイト)。
    pub resumption_id: &'a [u8],
    /// sigma2ResumeMIC(16 バイト)。
    pub resume_mic: &'a [u8],
    /// responder が採番したワイヤ session id。
    pub responder_ssid: u16,
}

impl<'a> Sigma2Resume<'a> {
    /// Sigma2_Resume TLV payload を解析する。
    ///
    /// MRP `session_parameters`(ctx4)は読み飛ばす。必須フィールド欠落・型不一致は
    /// [`Error::Decode`]。panic しない。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut resumption_id = None;
        let mut resume_mic = None;
        let mut responder_ssid = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => resumption_id = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => resume_mic = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(3) => {
                    responder_ssid =
                        Some(u16::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
                }
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            resumption_id: resumption_id.ok_or(Error::Decode)?,
            resume_mic: resume_mic.ok_or(Error::Decode)?,
            responder_ssid: responder_ssid.ok_or(Error::Decode)?,
        })
    }
}

/// Sigma3(initiator → responder)を `out` に直列化する。書き込み長を返す。
pub fn encode_sigma3(out: &mut [u8], encrypted3: &[u8]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), encrypted3)?;
    w.end_container()?;
    Ok(w.len())
}

/// TBEData3 平文 `{ NOC, ICAC?, signature }` を組み立て、S3K で AES-CCM 暗号化して `out` に
/// 書く。encrypted3(暗号文 + tag)の長さを返す([`encrypt_tbe2`] の鏡像。TBEData3 は
/// resumptionID を持たない)。
///
/// [`encrypt_tbe2`]: crate::sc::case::common::encrypt_tbe2
pub fn encrypt_tbe3<C: Crypto>(
    crypto: &C,
    key: &[u8; case::KEY_LEN],
    noc: &[u8],
    icac: Option<&[u8]>,
    signature: &[u8; case::SIGNATURE_LEN],
    out: &mut [u8],
) -> Result<usize> {
    let pt_len = {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_bytes(&TlvTag::ContextSpecific(1), noc)?;
        if let Some(icac) = icac {
            w.write_bytes(&TlvTag::ContextSpecific(2), icac)?;
        }
        w.write_bytes(&TlvTag::ContextSpecific(3), signature)?;
        w.end_container()?;
        w.len()
    };
    let ct = crypto.aes_ccm_encrypt(key, case::SIGMA3_NONCE, &[], out, pt_len)?;
    Ok(ct.len())
}

/// CASE initiator の往復フェーズ(`docs/design/controller.md` §3.4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasePhase {
    /// Sigma1 送信済み。Sigma2 待ち。
    Sigma1Sent,
    /// Sigma3 送信済み。成功/失敗 StatusReport 待ち。
    Sigma3Sent,
}

/// CASE initiator の往復進行状態(slot に外出しする)。
///
/// `shared_secret` は Sigma2 受信で確定する中間秘密のため [`Zeroizing`] で保持する。
pub struct CaseInitiator<C: Crypto> {
    /// 現在フェーズ。
    pub phase: CasePhase,
    /// エフェメラル鍵ペア(ECDH 用)。
    pub eph: C::Keypair,
    /// 進行中トランスクリプトハッシャ(Sigma1 → Sigma2 → Sigma3 を逐次投入)。
    pub tt: C::Sha256,
    /// ECDH 共有秘密(Sigma2 受信で確定)。
    pub shared_secret: Zeroizing<[u8; case::SHARED_SECRET_LEN]>,
    /// 自 fabric index([`crate::sc::case::creds::FabricStore`] 内)。
    pub fabric_idx: NonZeroU8,
    /// 相手(デバイス)の operational NodeId(destination-id / SessionInit に用いる)。
    pub peer_node_id: u64,
    /// responder が採番したワイヤ session id(commit 時に peer_session_id へ)。
    pub peer_ssid: u16,
    /// Sigma1 に載せた initiatorRandom(resumption の鍵導出・MIC 検証に用いる。§7.4)。
    pub initiator_random: [u8; case::CASE_RANDOM_LEN],
    /// Sigma1 で要求した resumption の旧 resumptionID(要求しなかった場合は [`None`])。
    ///
    /// [`Some`] のとき [`CaseInitiator::shared_secret`] は開始時点でレコードの
    /// SharedSecret に初期化されている(フル Sigma2 が来たら ECDH 結果で上書きされる)。
    pub attempted_resumption_id: Option<[u8; case::CASE_RESUMPTION_ID_LEN]>,
    /// フル CASE の Sigma2 TBE2 から取り出した相手採番の resumptionID(commit 時に保存)。
    pub peer_resumption_id: Option<[u8; case::CASE_RESUMPTION_ID_LEN]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma1_round_trips_into_responder_decoder() {
        let ir = [0x11u8; case::CASE_RANDOM_LEN];
        let dest = [0x22u8; case::CASE_DEST_ID_LEN];
        let epk = [0x04u8; case::CASE_EPH_PUBLIC_KEY_LEN];
        let mut buf = [0u8; 256];
        let n = encode_sigma1(&mut buf, &ir, 0x7777, &dest, &epk, None).unwrap();
        let s1 = crate::sc::case::responder::Sigma1::decode(&buf[..n]).unwrap();
        assert_eq!(s1.initiator_random, &ir);
        assert_eq!(s1.initiator_sessid, 0x7777);
        assert_eq!(s1.destination_id, &dest);
        assert_eq!(s1.initiator_eph_pub_key, &epk);
        assert!(!s1.has_resumption());

        // resumption フィールド付きも responder デコーダで往復する。
        let rid = [0x66u8; case::CASE_RESUMPTION_ID_LEN];
        let mic = [0x77u8; case::RESUME_MIC_LEN];
        let n2 = encode_sigma1(&mut buf, &ir, 0x7777, &dest, &epk, Some((&rid, &mic))).unwrap();
        let s1r = crate::sc::case::responder::Sigma1::decode(&buf[..n2]).unwrap();
        assert!(s1r.has_resumption());
        assert_eq!(s1r.resumption_id, Some(&rid[..]));
        assert_eq!(s1r.resume_mic, Some(&mic[..]));
    }

    #[test]
    fn sigma2_resume_decode_matches_responder_encoder() {
        let rid = [0x88u8; case::CASE_RESUMPTION_ID_LEN];
        let mic = [0x99u8; case::RESUME_MIC_LEN];
        let mut buf = [0u8; 128];
        let n =
            crate::sc::case::responder::encode_sigma2_resume(&mut buf, &rid, &mic, 0x4321).unwrap();
        let s2r = Sigma2Resume::decode(&buf[..n]).unwrap();
        assert_eq!(s2r.resumption_id, &rid);
        assert_eq!(s2r.resume_mic, &mic);
        assert_eq!(s2r.responder_ssid, 0x4321);
    }

    #[test]
    fn sigma2_decode_matches_responder_encoder() {
        let rr = [0x33u8; case::CASE_RANDOM_LEN];
        let epk = [0x04u8; case::CASE_EPH_PUBLIC_KEY_LEN];
        let enc = [0x99u8; 120];
        let mut buf = [0u8; 256];
        let n =
            crate::sc::case::responder::encode_sigma2(&mut buf, &rr, 0x4321, &epk, &enc).unwrap();
        let s2 = Sigma2::decode(&buf[..n]).unwrap();
        assert_eq!(s2.responder_random, &rr);
        assert_eq!(s2.responder_ssid, 0x4321);
        assert_eq!(s2.eph_pub, &epk);
        assert_eq!(s2.encrypted2, &enc);
    }

    #[test]
    fn sigma3_encode_matches_responder_decoder() {
        let enc = [0x77u8; 200];
        let mut buf = [0u8; 256];
        let n = encode_sigma3(&mut buf, &enc).unwrap();
        assert_eq!(
            crate::sc::case::responder::decode_sigma3(&buf[..n]).unwrap(),
            &enc[..]
        );
    }
}
