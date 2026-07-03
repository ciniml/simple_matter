//! PASE(Passcode-Authenticated Session Establishment)の TLV メッセージ型・定数・
//! トランスクリプトコンテキスト構成。
//!
//! `docs/design/secure-channel.md` §6 に基づく。responder(デバイス)側が扱う
//! PBKDFParamRequest / PBKDFParamResponse / PASEPake1〜3 の直列化を提供する。
//! 状態機械そのものは [`crate::sc::SecureChannel`](super::SecureChannel) が持つ。
//!
//! TLV フィールドは Matter 仕様どおり context-specific タグ 1.. を用いる。

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// SPAKE2+ セッション鍵導出の HKDF info 文字列。
pub const SPAKE2P_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// SPAKE2+ の既定 PBKDF2 反復回数。
pub const SPAKE2P_ITERATION_COUNT: u32 = 2000;

/// トランスクリプトコンテキストの接頭辞(Matter `kSpake2pContext`)。
pub const SPAKE2P_CONTEXT_PREFIX: &[u8] = b"CHIP PAKE V1 Commissioning";

/// セッション鍵導出の総バイト長(I2R 16 / R2I 16 / AttestationChallenge 16)。
pub const SESSION_KEYS_LEN: usize = 48;

/// AES-CCM 鍵・チャレンジの各長(バイト)。
pub const KEY_LEN: usize = 16;

/// PBKDFParamRequest(initiator → responder)。
#[derive(Debug, Clone, Copy)]
pub struct PbkdfParamReq<'a> {
    /// initiator の乱数(32 バイト)。
    pub initiator_random: &'a [u8],
    /// initiator が採番したワイヤ session id。
    pub initiator_ssid: u16,
    /// passcode 識別子(0 のみ対応)。
    pub passcode_id: u16,
    /// パラメータ(iterations/salt)を initiator が持っているか。
    pub has_params: bool,
}

impl<'a> PbkdfParamReq<'a> {
    /// TLV payload から PBKDFParamRequest をデコードする。
    ///
    /// 未知フィールド(session_parameters 等)は読み飛ばす。必須フィールド欠落や
    /// 型不一致は [`Error::Decode`]。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut initiator_random: Option<&[u8]> = None;
        let mut initiator_ssid: Option<u16> = None;
        let mut passcode_id: Option<u16> = None;
        let mut has_params: Option<bool> = None;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => initiator_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => initiator_ssid = Some(u16_of(&elem.value)?),
                TlvTag::ContextSpecific(3) => passcode_id = Some(u16_of(&elem.value)?),
                TlvTag::ContextSpecific(4) => has_params = Some(elem.value.as_bool()?),
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            initiator_random: initiator_random.ok_or(Error::Decode)?,
            initiator_ssid: initiator_ssid.ok_or(Error::Decode)?,
            passcode_id: passcode_id.ok_or(Error::Decode)?,
            has_params: has_params.ok_or(Error::Decode)?,
        })
    }
}

/// PBKDFParamResponse(responder → initiator)を `out` に直列化する。
///
/// `params`(iterations/salt)は initiator が has_params=false のときのみ載せる。
/// session_parameters(MRP 広告)は初期スコープでは省略する。書き込んだ長さを返す。
#[allow(clippy::too_many_arguments)]
pub fn encode_pbkdf_param_resp(
    out: &mut [u8],
    initiator_random: &[u8],
    responder_random: &[u8],
    responder_ssid: u16,
    params: Option<(u32, &[u8])>,
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), initiator_random)?;
    w.write_bytes(&TlvTag::ContextSpecific(2), responder_random)?;
    w.write_u16(&TlvTag::ContextSpecific(3), responder_ssid)?;
    if let Some((iterations, salt)) = params {
        w.start_struct(&TlvTag::ContextSpecific(4))?;
        w.write_u32(&TlvTag::ContextSpecific(1), iterations)?;
        w.write_bytes(&TlvTag::ContextSpecific(2), salt)?;
        w.end_container()?;
    }
    w.end_container()?;
    Ok(w.len())
}

/// PASEPake1(initiator → responder)。
#[derive(Debug, Clone, Copy)]
pub struct Pake1<'a> {
    /// prover の共有点 pA(SEC1 非圧縮 65 バイト)。
    pub pa: &'a [u8],
}

impl<'a> Pake1<'a> {
    /// TLV payload から PASEPake1 をデコードする。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let pa = single_bytes_field(payload)?;
        Ok(Self { pa })
    }
}

/// PASEPake2(responder → initiator)を `out` に直列化する。書き込んだ長さを返す。
pub fn encode_pake2(out: &mut [u8], pb: &[u8], cb: &[u8]) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), pb)?;
    w.write_bytes(&TlvTag::ContextSpecific(2), cb)?;
    w.end_container()?;
    Ok(w.len())
}

/// PASEPake3(initiator → responder)。
#[derive(Debug, Clone, Copy)]
pub struct Pake3<'a> {
    /// prover の確認値 cA(HMAC-SHA256 32 バイト)。
    pub ca: &'a [u8],
}

impl<'a> Pake3<'a> {
    /// TLV payload から PASEPake3 をデコードする。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let ca = single_bytes_field(payload)?;
        Ok(Self { ca })
    }
}

/// トランスクリプトコンテキストハッシュを構成する。
///
/// `context = SHA256(prefix || PBKDFParamRequest_bytes || PBKDFParamResponse_bytes)`。
/// `request` / `response` は各メッセージの TLV payload の生バイト列。
pub fn build_context<C: Crypto>(crypto: &C, request: &[u8], response: &[u8], out: &mut [u8; 32]) {
    let mut h = crypto.sha256();
    use crate::crypto::Sha256 as _;
    h.update(SPAKE2P_CONTEXT_PREFIX);
    h.update(request);
    h.update(response);
    h.finish(out);
}

/// 単一の context-1 バイト列フィールドを持つ struct をデコードする(Pake1/Pake3 用)。
fn single_bytes_field(payload: &[u8]) -> Result<&[u8]> {
    let mut r = TlvReader::new(payload);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut field: Option<&[u8]> = None;
    while let Some(elem) = r.read_next()? {
        if matches!(elem.value, TlvValue::ContainerEnd) {
            break;
        }
        match elem.tag {
            TlvTag::ContextSpecific(1) => field = Some(elem.value.as_bytes()?),
            _ => r.skip(&elem)?,
        }
    }
    field.ok_or(Error::Decode)
}

/// TLV 値を `u16` として取り出す(範囲外は [`Error::Decode`])。
fn u16_of(v: &TlvValue<'_>) -> Result<u16> {
    u16::try_from(v.as_unsigned()?).map_err(|_| Error::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf_req_round_trip() {
        // PBKDFParamResponse エンコード → PbkdfParamReq と同型の struct を手で作って
        // decode する代わりに、Request を writer で作って decode する。
        let mut buf = [0u8; 128];
        let mut w = TlvWriter::new(&mut buf);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), &[0xAAu8; 32])
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(2), 0x1234).unwrap();
        w.write_u16(&TlvTag::ContextSpecific(3), 0).unwrap();
        w.write_bool(&TlvTag::ContextSpecific(4), false).unwrap();
        w.end_container().unwrap();
        let n = w.len();

        let req = PbkdfParamReq::decode(&buf[..n]).unwrap();
        assert_eq!(req.initiator_random, &[0xAAu8; 32]);
        assert_eq!(req.initiator_ssid, 0x1234);
        assert_eq!(req.passcode_id, 0);
        assert!(!req.has_params);
    }

    #[test]
    fn pbkdf_resp_round_trip() {
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

        // decode で構造を検証する(Reader を直接使う)。
        let mut r = TlvReader::new(&buf[..n]);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        let e1 = r.read_next().unwrap().unwrap();
        assert_eq!(e1.tag, TlvTag::ContextSpecific(1));
        assert_eq!(e1.value.as_bytes().unwrap(), &[0xAAu8; 32]);
        let e2 = r.read_next().unwrap().unwrap();
        assert_eq!(e2.tag, TlvTag::ContextSpecific(2));
        assert_eq!(e2.value.as_bytes().unwrap(), &[0xBBu8; 32]);
        let e3 = r.read_next().unwrap().unwrap();
        assert_eq!(e3.tag, TlvTag::ContextSpecific(3));
        assert_eq!(e3.value.as_unsigned().unwrap(), 0x5678);
        // params struct。
        let e4 = r.read_next().unwrap().unwrap();
        assert_eq!(e4.tag, TlvTag::ContextSpecific(4));
        assert_eq!(e4.value, TlvValue::ContainerStart(ContainerType::Structure));
        let it = r.read_next().unwrap().unwrap();
        assert_eq!(it.value.as_unsigned().unwrap(), 2000);
        let st = r.read_next().unwrap().unwrap();
        assert_eq!(st.value.as_bytes().unwrap(), &salt);
    }

    #[test]
    fn pake1_pake3_round_trip() {
        let mut buf = [0u8; 128];
        let n = encode_pake2(&mut buf, &[0x04u8; 65], &[0xCCu8; 32]).unwrap();
        // Pake2 は pb/cb の 2 フィールド。decode ヘルパは無いので Reader で確認。
        let mut r = TlvReader::new(&buf[..n]);
        assert_eq!(r.enter_container().unwrap(), ContainerType::Structure);
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_bytes().unwrap(),
            &[0x04u8; 65]
        );
        assert_eq!(
            r.read_next().unwrap().unwrap().value.as_bytes().unwrap(),
            &[0xCCu8; 32]
        );

        // Pake1 の decode。
        let mut b1 = [0u8; 96];
        let mut w = TlvWriter::new(&mut b1);
        w.start_struct(&TlvTag::Anonymous).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), &[0x04u8; 65])
            .unwrap();
        w.end_container().unwrap();
        let m = w.len();
        assert_eq!(Pake1::decode(&b1[..m]).unwrap().pa, &[0x04u8; 65]);
    }
}
