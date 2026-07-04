//! PASE **initiator**(コミッショナ)方向の鏡像 codec と往復状態。
//!
//! `docs/design/controller.md` §3.3 / §3.4 に基づく。既存 [`crate::sc::pase`] の型・
//! [`build_context`](crate::sc::pase::build_context) と、[`Spake2pProver`] を再利用し、
//! responder 方向にしか無かった 5 本の codec(PBKDFParamRequest エンコード・
//! PBKDFParamResponse デコード・PASEPake1 エンコード・PASEPake2 デコード・
//! PASEPake3 エンコード)を足す。往復をまたぐ状態機械本体は
//! [`super::ScInitiator`](crate::sc::initiator::ScInitiator) が駆動する。

use crate::crypto::spake2p::{Spake2pProver, Spake2pProverConfirm};
use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// PBKDFParamRequest の生バイトを退避しておく最大長(context 構成に用いる)。
///
/// `{ initiatorRandom(32), initiatorSessionId(u16), passcodeId(u16), hasPBKDFParameters(bool) }`
/// の TLV は 50 バイト未満。余裕をみて 64 とする。
pub const PBKDF_REQ_MAX: usize = 64;

/// PBKDFParamRequest(initiator → responder)を `out` に直列化する。書き込み長を返す。
///
/// `has_params = false` のとき responder が iterations/salt を [`PbkdfParamResp`] に載せる。
pub fn encode_pbkdf_param_req(
    out: &mut [u8],
    initiator_random: &[u8; 32],
    initiator_ssid: u16,
    passcode_id: u16,
    has_params: bool,
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), initiator_random)?;
    w.write_u16(&TlvTag::ContextSpecific(2), initiator_ssid)?;
    w.write_u16(&TlvTag::ContextSpecific(3), passcode_id)?;
    w.write_bool(&TlvTag::ContextSpecific(4), has_params)?;
    w.end_container()?;
    Ok(w.len())
}

/// PBKDFParamResponse(responder → initiator)の解析結果(借用ビュー)。
#[derive(Debug, Clone, Copy)]
pub struct PbkdfParamResp<'a> {
    /// エコーされた initiator の乱数(32 バイト)。
    pub initiator_random: &'a [u8],
    /// responder の乱数(32 バイト)。
    pub responder_random: &'a [u8],
    /// responder が採番したワイヤ session id。
    pub responder_ssid: u16,
    /// PBKDF パラメータ(iterations, salt)。initiator が has_params=false で要求した
    /// 場合に存在する。フルハンドシェイクには必須。
    pub iterations: u32,
    /// SPAKE2+ の salt。
    pub salt: &'a [u8],
}

impl<'a> PbkdfParamResp<'a> {
    /// PBKDFParamResponse TLV payload を解析する。
    ///
    /// `session_parameters`(ctx5)は読み飛ばす。必須フィールド(random 群 / params)欠落や
    /// 型不一致は [`Error::Decode`]。panic しない。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut initiator_random = None;
        let mut responder_random = None;
        let mut responder_ssid = None;
        let mut iterations = None;
        let mut salt = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => initiator_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => responder_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(3) => responder_ssid = Some(u16_of(&elem.value)?),
                TlvTag::ContextSpecific(4) => {
                    // pbkdf_parameters = { ctx1: iterations(u32), ctx2: salt(bytes) }。
                    if !matches!(
                        elem.value,
                        TlvValue::ContainerStart(ContainerType::Structure)
                    ) {
                        return Err(Error::Decode);
                    }
                    while let Some(inner) = r.read_next()? {
                        if matches!(inner.value, TlvValue::ContainerEnd) {
                            break;
                        }
                        match inner.tag {
                            TlvTag::ContextSpecific(1) => {
                                iterations = Some(
                                    u32::try_from(inner.value.as_unsigned()?)
                                        .map_err(|_| Error::Decode)?,
                                );
                            }
                            TlvTag::ContextSpecific(2) => salt = Some(inner.value.as_bytes()?),
                            _ => r.skip(&inner)?,
                        }
                    }
                }
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            initiator_random: initiator_random.ok_or(Error::Decode)?,
            responder_random: responder_random.ok_or(Error::Decode)?,
            responder_ssid: responder_ssid.ok_or(Error::Decode)?,
            iterations: iterations.ok_or(Error::Decode)?,
            salt: salt.ok_or(Error::Decode)?,
        })
    }
}

/// PASEPake1(initiator → responder, pA)を `out` に直列化する。書き込み長を返す。
pub fn encode_pake1(out: &mut [u8], pa: &[u8; 65]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), pa)?;
    w.end_container()?;
    Ok(w.len())
}

/// PASEPake2(responder → initiator)の解析結果(pB, cB への借用ビュー)。
#[derive(Debug, Clone, Copy)]
pub struct Pake2<'a> {
    /// verifier の共有点 pB(SEC1 非圧縮 65 バイト)。
    pub pb: &'a [u8],
    /// verifier の確認値 cB(HMAC-SHA256 32 バイト)。
    pub cb: &'a [u8],
}

impl<'a> Pake2<'a> {
    /// PASEPake2 TLV payload を解析する。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut pb = None;
        let mut cb = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => pb = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => cb = Some(elem.value.as_bytes()?),
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            pb: pb.ok_or(Error::Decode)?,
            cb: cb.ok_or(Error::Decode)?,
        })
    }
}

/// PASEPake3(initiator → responder, cA)を `out` に直列化する。書き込み長を返す。
pub fn encode_pake3(out: &mut [u8], ca: &[u8; 32]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), ca)?;
    w.end_container()?;
    Ok(w.len())
}

/// PASE initiator の往復フェーズ(`docs/design/controller.md` §3.4)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasePhase {
    /// PBKDFParamRequest 送信済み。PBKDFParamResponse 待ち。
    PbkdfReqSent,
    /// PASEPake1 送信済み。PASEPake2 待ち。
    Pake1Sent,
    /// PASEPake3 送信済み。成功/失敗 StatusReport 待ち。
    Pake3Sent,
}

/// PASE initiator の往復進行状態(slot に外出しする)。
pub struct PaseInitiator {
    /// 現在フェーズ。
    pub phase: PasePhase,
    /// パスコード(PBKDFParamResponse の salt/iterations 受領後に prover を構築)。
    pub passcode: u32,
    /// 送信した PBKDFParamRequest の生バイト(context = SHA256(prefix‖req‖resp) 用)。
    pub req: [u8; PBKDF_REQ_MAX],
    /// `req` の有効長。
    pub req_len: usize,
    /// 確定したトランスクリプトコンテキストハッシュ(PBKDFParamResponse 受信で確定)。
    pub context: [u8; 32],
    /// SPAKE2+ prover(PASEPake1 送信時に構築)。
    pub prover: Option<Spake2pProver>,
    /// PASEPake2 受信で確定する確認・共有鍵(cA 送出・Ke 取得に用いる)。
    pub confirm: Option<Spake2pProverConfirm>,
    /// responder が採番したワイヤ session id(commit 時に peer_session_id へ)。
    pub peer_ssid: u16,
}

/// TLV 値を `u16` として取り出す(範囲外は [`Error::Decode`])。
fn u16_of(v: &TlvValue<'_>) -> Result<u16> {
    u16::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sc::pase::encode_pbkdf_param_resp;

    #[test]
    fn pbkdf_req_round_trips_into_responder_decoder() {
        let ir = [0xAAu8; 32];
        let mut buf = [0u8; PBKDF_REQ_MAX];
        let n = encode_pbkdf_param_req(&mut buf, &ir, 0x1234, 0, false).unwrap();
        let req = crate::sc::pase::PbkdfParamReq::decode(&buf[..n]).unwrap();
        assert_eq!(req.initiator_random, &ir);
        assert_eq!(req.initiator_ssid, 0x1234);
        assert_eq!(req.passcode_id, 0);
        assert!(!req.has_params);
    }

    #[test]
    fn pbkdf_resp_decode_matches_responder_encoder() {
        let salt = [0x11u8; 16];
        let mut buf = [0u8; 128];
        let n = encode_pbkdf_param_resp(
            &mut buf,
            &[0xAAu8; 32],
            &[0xBBu8; 32],
            0x5678,
            Some((2000, &salt)),
        )
        .unwrap();
        let resp = PbkdfParamResp::decode(&buf[..n]).unwrap();
        assert_eq!(resp.initiator_random, &[0xAAu8; 32]);
        assert_eq!(resp.responder_random, &[0xBBu8; 32]);
        assert_eq!(resp.responder_ssid, 0x5678);
        assert_eq!(resp.iterations, 2000);
        assert_eq!(resp.salt, &salt);
    }

    #[test]
    fn pbkdf_resp_missing_params_is_decode_error() {
        let mut buf = [0u8; 128];
        let n =
            encode_pbkdf_param_resp(&mut buf, &[0xAAu8; 32], &[0xBBu8; 32], 0x5678, None).unwrap();
        assert_eq!(PbkdfParamResp::decode(&buf[..n]).err(), Some(Error::Decode));
    }

    #[test]
    fn pake1_encode_matches_responder_decoder() {
        let pa = [0x04u8; 65];
        let mut buf = [0u8; 96];
        let n = encode_pake1(&mut buf, &pa).unwrap();
        assert_eq!(crate::sc::pase::Pake1::decode(&buf[..n]).unwrap().pa, &pa);
    }

    #[test]
    fn pake2_decode_matches_responder_encoder() {
        let pb = [0x04u8; 65];
        let cb = [0xCCu8; 32];
        let mut buf = [0u8; 128];
        let n = crate::sc::pase::encode_pake2(&mut buf, &pb, &cb).unwrap();
        let p2 = Pake2::decode(&buf[..n]).unwrap();
        assert_eq!(p2.pb, &pb);
        assert_eq!(p2.cb, &cb);
    }

    #[test]
    fn pake3_encode_matches_responder_decoder() {
        let ca = [0xDDu8; 32];
        let mut buf = [0u8; 96];
        let n = encode_pake3(&mut buf, &ca).unwrap();
        assert_eq!(crate::sc::pase::Pake3::decode(&buf[..n]).unwrap().ca, &ca);
    }
}
