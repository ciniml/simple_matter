//! CASE responder のプロトコルプリミティブ(Sigma1/2/3 の TLV codec と鍵導出パイプライン)。
//!
//! `docs/design/secure-channel.md` §7 に基づく。ここには **SecureChannel の私有状態に
//! 依存しない**純粋な部品(メッセージの直列化/解析、S2K/S3K/SEKeys の導出、TBE の
//! 暗号化/復号、TBS の署名対象組み立て)を置く。往復をまたぐ Mealy 状態機械そのもの
//! (slot・reserve/commit・StatusReport)は [`crate::sc::SecureChannel`] に統合される
//! (設計「SecureChannel ハンドラに統合」)。
//!
//! # 定数・info 文字列・nonce の出典
//!
//! 参照実装 rs-matter `sc/case/casep.rs` / connectedhomeip `CASESession.cpp` と一致:
//!
//! - S2K info = `"Sigma2"`(6B)、S3K info = `"Sigma3"`(6B)、SEKeys info = `"SessionKeys"`(11B)。
//! - TBE nonce = `"NCASE_Sigma2N"` / `"NCASE_Sigma3N"`(各 13B)。
//! - **S2K salt = IPK(16) ‖ responderRandom(32) ‖ responderEphPubKey(65) ‖ TThash(32) = 145B**、
//!   IKM = ECDH 共有秘密、出力 16B。
//! - **S3K salt = IPK(16) ‖ TThash(32) = 48B**、出力 16B。
//! - **SEKeys salt = IPK(16) ‖ TThash(32) = 48B**、出力 48B(I2R/R2I/att 各 16B。
//!   responder は I2R→dec, R2I→enc)。
//! - CASE random 32B、resumption id 16B。
//!
//! TT へのフォールド順序(§7.1): Sigma2 の生バイトは TLV 直列化 **後**、Sigma3 の生バイトは
//! 証明書鎖・署名検証を **通過した後** に投入する(不正な Sigma3 で TT を汚さない)。

use zeroize::Zeroizing;

use crate::crypto::{Crypto, AES_CCM_KEY_LEN, AES_CCM_NONCE_LEN};
use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// CASE エフェメラル公開鍵長(SEC1 非圧縮 65 バイト)。
pub const CASE_EPH_PUBLIC_KEY_LEN: usize = 65;

/// CASE random(initiatorRandom / responderRandom)長。
pub const CASE_RANDOM_LEN: usize = 32;

/// resumption ID 長。
pub const CASE_RESUMPTION_ID_LEN: usize = 16;

/// destination identifier 長(HMAC-SHA256 出力)。
pub const CASE_DEST_ID_LEN: usize = 32;

/// operational IPK 長(AES-128 鍵と同じ 16 バイト)。
pub const IPK_LEN: usize = 16;

/// ECDH 共有秘密長(P-256 共有点 X 座標)。
pub const SHARED_SECRET_LEN: usize = 32;

/// AES-CCM 鍵長(S2K/S3K・各セッション鍵)。
pub const KEY_LEN: usize = AES_CCM_KEY_LEN;

/// ECDSA 署名長(生 r‖s)。
pub const SIGNATURE_LEN: usize = 64;

/// トランスクリプトハッシュ長(SHA-256)。
pub const TT_HASH_LEN: usize = 32;

/// CASE セッション鍵の総長(I2R 16 / R2I 16 / AttestationChallenge 16)。
pub const CASE_SESSION_KEYS_LEN: usize = 48;

/// S2K 導出の HKDF info(`"Sigma2"`)。
pub const SIGMA2_KEY_INFO: &[u8] = b"Sigma2";
/// S3K 導出の HKDF info(`"Sigma3"`)。
pub const SIGMA3_KEY_INFO: &[u8] = b"Sigma3";
/// 最終セッション鍵導出の HKDF info(`"SessionKeys"`)。
pub const CASE_SESSION_KEYS_INFO: &[u8] = b"SessionKeys";

/// TBEData2 の AES-CCM nonce(`"NCASE_Sigma2N"`)。
pub const SIGMA2_NONCE: &[u8; AES_CCM_NONCE_LEN] = b"NCASE_Sigma2N";
/// TBEData3 の AES-CCM nonce(`"NCASE_Sigma3N"`)。
pub const SIGMA3_NONCE: &[u8; AES_CCM_NONCE_LEN] = b"NCASE_Sigma3N";

/// CASE の一時作業バッファ長(TBE の復号先・TBS 署名対象の組み立て用)。
///
/// 相手/自 NOC+ICAC(各 [`crate::fabric::MAX_CERT_TLV_LEN`]=400)+ 署名/公開鍵 + TLV
/// オーバヘッドを収める。slot には常駐させず呼び出しスタックに置く(§7.2)。
pub const CASE_SCRATCH_LEN: usize = 1024;

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
    /// resumptionID が存在したか(未対応。フルハンドシェイクへフォールバック)。
    pub has_resumption_id: bool,
    /// initiatorResumeMIC が存在したか。
    pub has_resume_mic: bool,
}

impl<'a> Sigma1<'a> {
    /// Sigma1 TLV payload を解析する。
    ///
    /// MRP `session_parameters`(ctx5)は読み飛ばす。resumption フィールド(ctx6/ctx7)は
    /// 存在有無のみ記録し、値は用いない(フルハンドシェイクへフォールバック)。必須
    /// フィールド欠落・型不一致は [`Error::Decode`]。panic しない。
    pub fn decode(payload: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(payload);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut initiator_random = None;
        let mut initiator_sessid = None;
        let mut destination_id = None;
        let mut initiator_eph_pub_key = None;
        let mut has_resumption_id = false;
        let mut has_resume_mic = false;
        while let Some(elem) = r.read_next()? {
            if matches!(elem.value, TlvValue::ContainerEnd) {
                break;
            }
            match elem.tag {
                TlvTag::ContextSpecific(1) => initiator_random = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(2) => initiator_sessid = Some(u16_of(&elem.value)?),
                TlvTag::ContextSpecific(3) => destination_id = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(4) => initiator_eph_pub_key = Some(elem.value.as_bytes()?),
                TlvTag::ContextSpecific(6) => {
                    has_resumption_id = true;
                    r.skip(&elem)?;
                }
                TlvTag::ContextSpecific(7) => {
                    has_resume_mic = true;
                    r.skip(&elem)?;
                }
                _ => r.skip(&elem)?,
            }
        }
        Ok(Self {
            initiator_random: initiator_random.ok_or(Error::Decode)?,
            initiator_sessid: initiator_sessid.ok_or(Error::Decode)?,
            destination_id: destination_id.ok_or(Error::Decode)?,
            initiator_eph_pub_key: initiator_eph_pub_key.ok_or(Error::Decode)?,
            has_resumption_id,
            has_resume_mic,
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

/// [`decode_tbe_certs`] の戻り値: (NOC, ICAC?, signature) への借用ビュー。
pub type TbeCerts<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8]);

/// 復号済み TBEData(TBEData2 / TBEData3)を解析し、(noc, icac, signature) を返す。
///
/// TBEData3 は `{ ctx1: NOC, ctx2: ICAC?, ctx3: signature }`。TBEData2 は末尾に
/// resumptionID(ctx4)を持つが、responder 側 Sigma3 処理では TBEData3 のみ解析する。
pub fn decode_tbe_certs(payload: &[u8]) -> Result<TbeCerts<'_>> {
    let mut r = TlvReader::new(payload);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    let mut noc = None;
    let mut icac = None;
    let mut signature = None;
    while let Some(elem) = r.read_next()? {
        if matches!(elem.value, TlvValue::ContainerEnd) {
            break;
        }
        match elem.tag {
            TlvTag::ContextSpecific(1) => noc = Some(elem.value.as_bytes()?),
            TlvTag::ContextSpecific(2) => icac = Some(elem.value.as_bytes()?),
            TlvTag::ContextSpecific(3) => signature = Some(elem.value.as_bytes()?),
            _ => r.skip(&elem)?,
        }
    }
    Ok((
        noc.ok_or(Error::Decode)?,
        icac,
        signature.ok_or(Error::Decode)?,
    ))
}

/// TBSData(署名対象 `{ NOC, ICAC?, senderEphPubKey, receiverEphPubKey }`)を `out` に
/// 組み立て、書き込み長を返す。
///
/// - Sigma2 TBS(自署名): sender = responder eph, receiver = initiator eph。
/// - Sigma3 TBS(相手署名の検証): sender = initiator eph, receiver = responder eph。
pub fn encode_tbs(
    out: &mut [u8],
    noc: &[u8],
    icac: Option<&[u8]>,
    sender_eph_pub_key: &[u8],
    receiver_eph_pub_key: &[u8],
) -> Result<usize> {
    let mut w = TlvWriter::new(out);
    w.start_struct(&TlvTag::Anonymous)?;
    w.write_bytes(&TlvTag::ContextSpecific(1), noc)?;
    if let Some(icac) = icac {
        w.write_bytes(&TlvTag::ContextSpecific(2), icac)?;
    }
    w.write_bytes(&TlvTag::ContextSpecific(3), sender_eph_pub_key)?;
    w.write_bytes(&TlvTag::ContextSpecific(4), receiver_eph_pub_key)?;
    w.end_container()?;
    Ok(w.len())
}

/// TBEData2 平文 `{ NOC, ICAC?, signature, resumptionID }` を組み立て、S2K で AES-CCM
/// 暗号化して `out` に書く。encrypted2(暗号文 + tag)の長さを返す。
#[allow(clippy::too_many_arguments)]
pub fn encrypt_tbe2<C: Crypto>(
    crypto: &C,
    key: &[u8; KEY_LEN],
    noc: &[u8],
    icac: Option<&[u8]>,
    signature: &[u8; SIGNATURE_LEN],
    resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
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
        w.write_bytes(&TlvTag::ContextSpecific(4), resumption_id)?;
        w.end_container()?;
        w.len()
    };
    let ct = crypto.aes_ccm_encrypt(key, SIGMA2_NONCE, &[], out, pt_len)?;
    Ok(ct.len())
}

/// encrypted3(TBEData3 + tag)を S3K で in-place 復号し、平文長(tag を除く)を返す。
///
/// `buffer` は「暗号文 ‖ tag(16B)」。復号後、平文が `buffer` の先頭に上書きされる。
/// AEAD 認証失敗は [`Error::Crypto`](panic しない)。
pub fn decrypt_tbe3<'m, C: Crypto>(
    crypto: &C,
    key: &[u8; KEY_LEN],
    buffer: &'m mut [u8],
) -> Result<&'m [u8]> {
    crypto.aes_ccm_decrypt(key, SIGMA3_NONCE, &[], buffer)
}

/// S2K = `HKDF(salt = IPK‖responderRandom‖responderEphPubKey‖TThash, ikm = sharedSecret,
/// info = "Sigma2", L = 16)`。
pub fn derive_sigma2_key<C: Crypto>(
    crypto: &C,
    ipk: &[u8; IPK_LEN],
    responder_random: &[u8; CASE_RANDOM_LEN],
    responder_eph_pub_key: &[u8; CASE_EPH_PUBLIC_KEY_LEN],
    tt_hash: &[u8; TT_HASH_LEN],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    out: &mut [u8; KEY_LEN],
) -> Result<()> {
    const SALT_LEN: usize = IPK_LEN + CASE_RANDOM_LEN + CASE_EPH_PUBLIC_KEY_LEN + TT_HASH_LEN;
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    let mut off = 0;
    salt[off..off + IPK_LEN].copy_from_slice(ipk);
    off += IPK_LEN;
    salt[off..off + CASE_RANDOM_LEN].copy_from_slice(responder_random);
    off += CASE_RANDOM_LEN;
    salt[off..off + CASE_EPH_PUBLIC_KEY_LEN].copy_from_slice(responder_eph_pub_key);
    off += CASE_EPH_PUBLIC_KEY_LEN;
    salt[off..off + TT_HASH_LEN].copy_from_slice(tt_hash);
    crypto.hkdf_sha256(&salt[..], shared_secret, SIGMA2_KEY_INFO, out)
}

/// IPK‖TThash を salt とする HKDF 導出(S3K / SEKeys 共通)。`out` の長さぶん導出する。
pub fn derive_ipk_tt_keyed<C: Crypto>(
    crypto: &C,
    ipk: &[u8; IPK_LEN],
    tt_hash: &[u8; TT_HASH_LEN],
    info: &[u8],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    out: &mut [u8],
) -> Result<()> {
    const SALT_LEN: usize = IPK_LEN + TT_HASH_LEN;
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    salt[..IPK_LEN].copy_from_slice(ipk);
    salt[IPK_LEN..].copy_from_slice(tt_hash);
    crypto.hkdf_sha256(&salt[..], shared_secret, info, out)
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
        assert!(s1.has_resumption_id);
        assert!(s1.has_resume_mic);
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

        // TBE certs struct round-trips (with ICAC).
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
