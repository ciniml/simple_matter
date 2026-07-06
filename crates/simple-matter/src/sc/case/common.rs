//! CASE の**両方向共用**プロトコルプリミティブ(定数・鍵導出・TBE 暗号化/復号・
//! TBS 組み立て・destination-id 計算)。
//!
//! `docs/design/controller.md` §3.3 に基づく。ここに置く部品は responder(デバイス)側
//! [`super::responder`] と initiator(コントローラ)側 [`crate::sc::initiator::case`] の
//! 双方から使われる。往復方向に依存しない純粋な計算のみを集約し、方向固有の外枠 codec
//! (`encode_sigma2`/`decode_sigma3` は responder、`encode_sigma1`/`Sigma2::decode`/
//! `encode_sigma3` は initiator)は各方向のモジュールに残す。
//!
//! 本モジュールは cfg なし(`controller` feature に依存しない)で、`rustcrypto` feature の
//! 下で常時コンパイルされる。旧来の呼び出し(`case::responder::derive_sigma2_key` 等)は
//! [`super::responder`] の `pub use common::*` により互換維持される(移動のみで挙動不変)。
//!
//! # 定数・info 文字列・nonce の出典
//!
//! 参照実装 rs-matter `sc/case/casep.rs` / connectedhomeip `CASESession.cpp` と一致:
//!
//! - S2K info = `"Sigma2"`(6B)、S3K info = `"Sigma3"`(6B)、SEKeys info = `"SessionKeys"`(11B)。
//! - **S2K salt = IPK(16) ‖ responderRandom(32) ‖ responderEphPubKey(65) ‖ TThash(32) = 145B**、
//!   IKM = ECDH 共有秘密、出力 16B。
//! - **S3K salt = IPK(16) ‖ TThash(32) = 48B**、出力 16B。
//! - **SEKeys salt = IPK(16) ‖ TThash(32) = 48B**、出力 48B(I2R/R2I/att 各 16B)。
//! - CASE random 32B、resumption id 16B。
//! - **destination identifier = HMAC-SHA256(IPK, initiatorRandom ‖ rootPublicKey(65) ‖
//!   fabricId(LE 8) ‖ nodeId(LE 8))**。

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

/// resumption MIC(initiatorResumeMIC / sigma2ResumeMIC)長 = AES-CCM タグ長。
pub const RESUME_MIC_LEN: usize = 16;
/// S1RK 導出の HKDF info(`"Sigma1_Resume"`)。
pub const SIGMA1_RESUME_KEY_INFO: &[u8] = b"Sigma1_Resume";
/// S2RK 導出の HKDF info(`"Sigma2_Resume"`)。
pub const SIGMA2_RESUME_KEY_INFO: &[u8] = b"Sigma2_Resume";
/// resumption セッション鍵導出の HKDF info(`"SessionResumptionKeys"`)。
pub const RESUMPTION_SESSION_KEYS_INFO: &[u8] = b"SessionResumptionKeys";
/// initiatorResumeMIC の AES-CCM nonce(`"NCASE_SigmaS1"`)。
pub const SIGMA1_RESUME_NONCE: &[u8; AES_CCM_NONCE_LEN] = b"NCASE_SigmaS1";
/// sigma2ResumeMIC の AES-CCM nonce(`"NCASE_SigmaS2"`)。
pub const SIGMA2_RESUME_NONCE: &[u8; AES_CCM_NONCE_LEN] = b"NCASE_SigmaS2";

/// CASE の一時作業バッファ長(TBE の復号先・TBS 署名対象の組み立て用)。
///
/// 相手/自 NOC+ICAC(各 [`crate::fabric::MAX_CERT_TLV_LEN`]=400)+ 署名/公開鍵 + TLV
/// オーバヘッドを収める。slot には常駐させず呼び出しスタックに置く。
pub const CASE_SCRATCH_LEN: usize = 1024;

/// [`decode_tbe_certs`] の戻り値: (NOC, ICAC?, signature) への借用ビュー。
pub type TbeCerts<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8]);

/// 復号済み TBEData(TBEData2 / TBEData3)を解析し、(noc, icac, signature) を返す。
///
/// TBEData3 は `{ ctx1: NOC, ctx2: ICAC?, ctx3: signature }`。TBEData2 は末尾に
/// resumptionID(ctx4)を持つが、証明書鎖・署名検証には (noc, icac, signature) のみ用いる。
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

/// 復号済み TBEData2 から resumptionID(ctx4・16B)を取り出す(§7.4)。
///
/// initiator がフル CASE 成功時に resumption レコードとして保存する。欠落・長さ不一致は
/// [`Error::Decode`](仕様上 TBEData2 に必須のフィールド)。
pub fn decode_tbe2_resumption_id(payload: &[u8]) -> Result<[u8; CASE_RESUMPTION_ID_LEN]> {
    let mut r = TlvReader::new(payload);
    if r.enter_container()? != ContainerType::Structure {
        return Err(Error::Decode);
    }
    while let Some(elem) = r.read_next()? {
        if matches!(elem.value, TlvValue::ContainerEnd) {
            break;
        }
        match elem.tag {
            TlvTag::ContextSpecific(4) => {
                let id: &[u8; CASE_RESUMPTION_ID_LEN] = elem
                    .value
                    .as_bytes()?
                    .try_into()
                    .map_err(|_| Error::Decode)?;
                return Ok(*id);
            }
            _ => r.skip(&elem)?,
        }
    }
    Err(Error::Decode)
}

/// TBSData(署名対象 `{ NOC, ICAC?, senderEphPubKey, receiverEphPubKey }`)を `out` に
/// 組み立て、書き込み長を返す。
///
/// - Sigma2 TBS: sender = responder eph, receiver = initiator eph。
/// - Sigma3 TBS: sender = initiator eph, receiver = responder eph。
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

/// S1RK / S2RK を導出する(§7.4)。
///
/// `SxRK = HKDF(salt = initiatorRandom(32) ‖ resumptionID(16), ikm = SharedSecret,
/// info = "Sigma1_Resume" | "Sigma2_Resume", L = 16)`。S1RK の resumptionID は Sigma1 に
/// 載せた(= 保存済みの)ID、S2RK は responder が新規採番した ID。
fn derive_resume_key<C: Crypto>(
    crypto: &C,
    initiator_random: &[u8; CASE_RANDOM_LEN],
    resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    info: &[u8],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    out: &mut [u8; KEY_LEN],
) -> Result<()> {
    const SALT_LEN: usize = CASE_RANDOM_LEN + CASE_RESUMPTION_ID_LEN;
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    salt[..CASE_RANDOM_LEN].copy_from_slice(initiator_random);
    salt[CASE_RANDOM_LEN..].copy_from_slice(resumption_id);
    crypto.hkdf_sha256(&salt[..], shared_secret, info, out)
}

/// resumption MIC(initiatorResumeMIC / sigma2ResumeMIC)を計算する(§7.4)。
///
/// SxRK で **空平文・空 AAD** を AES-CCM 暗号化したときの 16B タグが MIC。
/// `info` / `nonce` は S1(`SIGMA1_RESUME_KEY_INFO` / `SIGMA1_RESUME_NONCE`)か
/// S2(`SIGMA2_RESUME_KEY_INFO` / `SIGMA2_RESUME_NONCE`)の対で渡す。
pub fn compute_resume_mic<C: Crypto>(
    crypto: &C,
    initiator_random: &[u8; CASE_RANDOM_LEN],
    resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    info: &[u8],
    nonce: &[u8; AES_CCM_NONCE_LEN],
    out: &mut [u8; RESUME_MIC_LEN],
) -> Result<()> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    derive_resume_key(
        crypto,
        initiator_random,
        resumption_id,
        info,
        shared_secret,
        &mut key,
    )?;
    let mut buf = [0u8; RESUME_MIC_LEN];
    let ct = crypto.aes_ccm_encrypt(&key, nonce, &[], &mut buf, 0)?;
    if ct.len() != RESUME_MIC_LEN {
        return Err(Error::Crypto);
    }
    out.copy_from_slice(ct);
    Ok(())
}

/// resumption MIC を検証する(§7.4)。不一致・導出失敗は [`Error::Crypto`]。
pub fn verify_resume_mic<C: Crypto>(
    crypto: &C,
    initiator_random: &[u8; CASE_RANDOM_LEN],
    resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    info: &[u8],
    nonce: &[u8; AES_CCM_NONCE_LEN],
    mic: &[u8],
) -> Result<()> {
    if mic.len() != RESUME_MIC_LEN {
        return Err(Error::Crypto);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    derive_resume_key(
        crypto,
        initiator_random,
        resumption_id,
        info,
        shared_secret,
        &mut key,
    )?;
    let mut buf = [0u8; RESUME_MIC_LEN];
    buf.copy_from_slice(mic);
    // 空平文の AEAD 復号 = タグ検証のみ。
    let pt = crypto.aes_ccm_decrypt(&key, nonce, &[], &mut buf)?;
    if !pt.is_empty() {
        return Err(Error::Crypto);
    }
    Ok(())
}

/// resumption 経路のセッション鍵(I2R‖R2I‖AttestationChallenge = 48B)を導出する(§7.4)。
///
/// `salt = initiatorRandom ‖ resumptionID(**旧** = Sigma1 の ctx6)`、
/// `info = "SessionResumptionKeys"`。IPK もトランスクリプトハッシュも使わない。
pub fn derive_resumption_session_keys<C: Crypto>(
    crypto: &C,
    initiator_random: &[u8; CASE_RANDOM_LEN],
    old_resumption_id: &[u8; CASE_RESUMPTION_ID_LEN],
    shared_secret: &[u8; SHARED_SECRET_LEN],
    out: &mut [u8; CASE_SESSION_KEYS_LEN],
) -> Result<()> {
    const SALT_LEN: usize = CASE_RANDOM_LEN + CASE_RESUMPTION_ID_LEN;
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    salt[..CASE_RANDOM_LEN].copy_from_slice(initiator_random);
    salt[CASE_RANDOM_LEN..].copy_from_slice(old_resumption_id);
    crypto.hkdf_sha256(&salt[..], shared_secret, RESUMPTION_SESSION_KEYS_INFO, out)
}

/// destination identifier を計算する(§7.3 / `docs/design/controller.md` §3.4)。
///
/// `destinationMessage = initiatorRandom ‖ rootPublicKey(65) ‖ fabricId(LE 8) ‖ nodeId(LE 8)`、
/// `destinationIdentifier = HMAC-SHA256(key = IPK, destinationMessage)`。responder は全 fabric
/// 総当りで照合し(`responder.rs` 内蔵)、initiator は 1 fabric で 1 度計算する(本関数)。
pub fn compute_destination_id<C: Crypto>(
    crypto: &C,
    ipk: &[u8; IPK_LEN],
    initiator_random: &[u8; CASE_RANDOM_LEN],
    root_public_key: &[u8; CASE_EPH_PUBLIC_KEY_LEN],
    fabric_id: u64,
    node_id: u64,
    out: &mut [u8; CASE_DEST_ID_LEN],
) -> Result<()> {
    const MSG_LEN: usize = CASE_RANDOM_LEN + CASE_EPH_PUBLIC_KEY_LEN + 8 + 8;
    let mut msg = [0u8; MSG_LEN];
    msg[..CASE_RANDOM_LEN].copy_from_slice(initiator_random);
    msg[CASE_RANDOM_LEN..CASE_RANDOM_LEN + CASE_EPH_PUBLIC_KEY_LEN]
        .copy_from_slice(root_public_key);
    let mut off = CASE_RANDOM_LEN + CASE_EPH_PUBLIC_KEY_LEN;
    msg[off..off + 8].copy_from_slice(&fabric_id.to_le_bytes());
    off += 8;
    msg[off..off + 8].copy_from_slice(&node_id.to_le_bytes());
    crypto.hmac_sha256(ipk, &msg, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tbe_certs_round_trip_with_icac() {
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

    #[test]
    fn resume_mic_round_trip_and_mismatch() {
        use crate::crypto::rustcrypto::RustCrypto;
        use crate::crypto::Rng;
        struct Z;
        impl Rng for Z {
            fn fill_bytes(&mut self, d: &mut [u8]) -> Result<()> {
                d.fill(0);
                Ok(())
            }
        }
        let crypto = RustCrypto::new(Z);
        let ir = [0x11u8; CASE_RANDOM_LEN];
        let rid = [0x22u8; CASE_RESUMPTION_ID_LEN];
        let ss = [0x33u8; SHARED_SECRET_LEN];
        let mut mic = [0u8; RESUME_MIC_LEN];
        compute_resume_mic(
            &crypto,
            &ir,
            &rid,
            &ss,
            SIGMA1_RESUME_KEY_INFO,
            SIGMA1_RESUME_NONCE,
            &mut mic,
        )
        .unwrap();
        // 独立参照実装(python cryptography: HKDF-SHA256(salt=IR‖RID, info="Sigma1_Resume")
        // + AES-CCM(nonce="NCASE_SigmaS1", 空平文, tag16))の既知ベクタと一致する。
        assert_eq!(
            mic,
            [
                0x77, 0x15, 0xc1, 0x6c, 0x6c, 0xc7, 0xa5, 0xc0, 0x69, 0x26, 0xf7, 0x72, 0x7e, 0x2a,
                0x6f, 0xf1
            ]
        );
        // 正しい素材で検証が通る。
        verify_resume_mic(
            &crypto,
            &ir,
            &rid,
            &ss,
            SIGMA1_RESUME_KEY_INFO,
            SIGMA1_RESUME_NONCE,
            &mic,
        )
        .unwrap();
        // resumptionID 不一致は Crypto エラー。
        let other = [0x23u8; CASE_RESUMPTION_ID_LEN];
        assert!(verify_resume_mic(
            &crypto,
            &ir,
            &other,
            &ss,
            SIGMA1_RESUME_KEY_INFO,
            SIGMA1_RESUME_NONCE,
            &mic,
        )
        .is_err());
        // info(S1 と S2)の取り違えも検出する。
        assert!(verify_resume_mic(
            &crypto,
            &ir,
            &rid,
            &ss,
            SIGMA2_RESUME_KEY_INFO,
            SIGMA2_RESUME_NONCE,
            &mic,
        )
        .is_err());
    }

    #[test]
    fn resumption_session_keys_are_deterministic() {
        use crate::crypto::rustcrypto::RustCrypto;
        use crate::crypto::Rng;
        struct Z;
        impl Rng for Z {
            fn fill_bytes(&mut self, d: &mut [u8]) -> Result<()> {
                d.fill(0);
                Ok(())
            }
        }
        let crypto = RustCrypto::new(Z);
        let ir = [0x44u8; CASE_RANDOM_LEN];
        let rid = [0x55u8; CASE_RESUMPTION_ID_LEN];
        let ss = [0x66u8; SHARED_SECRET_LEN];
        let mut a = [0u8; CASE_SESSION_KEYS_LEN];
        let mut b = [0u8; CASE_SESSION_KEYS_LEN];
        derive_resumption_session_keys(&crypto, &ir, &rid, &ss, &mut a).unwrap();
        derive_resumption_session_keys(&crypto, &ir, &rid, &ss, &mut b).unwrap();
        assert_eq!(a, b);
        let rid2 = [0x56u8; CASE_RESUMPTION_ID_LEN];
        let mut c = [0u8; CASE_SESSION_KEYS_LEN];
        derive_resumption_session_keys(&crypto, &ir, &rid2, &ss, &mut c).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn tbe2_resumption_id_extraction() {
        let noc = [0x01u8; 40];
        let sig = [0x03u8; SIGNATURE_LEN];
        let rid = [0x77u8; CASE_RESUMPTION_ID_LEN];
        let mut tb = [0u8; 256];
        let m = {
            let mut w = TlvWriter::new(&mut tb);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &noc).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(3), &sig).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(4), &rid).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        assert_eq!(decode_tbe2_resumption_id(&tb[..m]).unwrap(), rid);
        // ctx4 欠落は Decode エラー。
        let m2 = {
            let mut w = TlvWriter::new(&mut tb);
            w.start_struct(&TlvTag::Anonymous).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(1), &noc).unwrap();
            w.write_bytes(&TlvTag::ContextSpecific(3), &sig).unwrap();
            w.end_container().unwrap();
            w.len()
        };
        assert!(decode_tbe2_resumption_id(&tb[..m2]).is_err());
    }

    #[test]
    fn destination_id_is_deterministic() {
        // hmac の決定性のみを確認する(既知ベクタは結合テストで担保)。
        struct FakeCrypto;
        // hmac_sha256 の代用に本物の RustCrypto を使えないため、ここでは長さ・決定性のみ
        // を rustcrypto backend で検証する。
        let _ = FakeCrypto;
        use crate::crypto::rustcrypto::RustCrypto;
        use crate::crypto::Rng;
        struct Z;
        impl Rng for Z {
            fn fill_bytes(&mut self, d: &mut [u8]) -> Result<()> {
                d.fill(0);
                Ok(())
            }
        }
        let crypto = RustCrypto::new(Z);
        let ipk = [0x11u8; IPK_LEN];
        let ir = [0x22u8; CASE_RANDOM_LEN];
        let root = [0x04u8; CASE_EPH_PUBLIC_KEY_LEN];
        let mut a = [0u8; CASE_DEST_ID_LEN];
        let mut b = [0u8; CASE_DEST_ID_LEN];
        compute_destination_id(&crypto, &ipk, &ir, &root, 0x1234, 0x5678, &mut a).unwrap();
        compute_destination_id(&crypto, &ipk, &ir, &root, 0x1234, 0x5678, &mut b).unwrap();
        assert_eq!(a, b);
        // node_id が変われば値も変わる。
        let mut c = [0u8; CASE_DEST_ID_LEN];
        compute_destination_id(&crypto, &ipk, &ir, &root, 0x1234, 0x9999, &mut c).unwrap();
        assert_ne!(a, c);
    }
}
