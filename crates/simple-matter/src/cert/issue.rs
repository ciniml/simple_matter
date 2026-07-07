//! Matter 運用証明書の**発行**(CA 側)と PKCS#10 CSR の解析。
//!
//! `docs/design/controller.md` §6.3 に基づく。`cert/tests.rs` / `stack/tests.rs` の
//! `write_cert`(TLV 証明書を組み立て → [`MatterCert::parse`] → [`MatterCert::to_be_signed`]
//! → ECDSA 署名 → 署名埋め戻し)を、コントローラ(`controller` feature)向けの公開 API
//! [`write_matter_cert`] として正式化したものである。手順・ワイヤ形式は実証済みコードと
//! 同一で、引数を構造化([`MatterCertSpec`])しただけである。
//!
//! [`parse_csr`] はデバイスの `CSRResponse`(NOCSRElements 内の PKCS#10 CSR)から
//! 運用公開鍵を取り出し、CSR の自己署名(所有証明)を検証する([`crate::cert::write_csr`]
//! の逆方向)。DER は最小限のトップダウン走査で読み、不正入力でも panic しない。

use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN};
use crate::error::{Error, Result};
use crate::tlv::{TlvTag, TlvWriter};

use super::{ext_key_usage, MatterCert, MAX_TBS_DER_LEN};

/// DN(Distinguished Name)属性 1 件(整数値)。
///
/// `tag` は Matter DN 属性のコンテキストタグ([`crate::cert::dn_attr`] 参照。
/// 例: `MATTER_NODE_ID` / `MATTER_FABRIC_ID` / `MATTER_RCAC_ID`)、`val` はその整数値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnAttr {
    /// DN 属性種別のコンテキストタグ。
    pub tag: u8,
    /// 属性の整数値。
    pub val: u64,
}

impl DnAttr {
    /// タグと値から属性を作る。
    pub const fn new(tag: u8, val: u64) -> Self {
        Self { tag, val }
    }
}

/// Matter TLV 証明書の発行仕様(`cert/tests.rs` の `write_cert` 引数列の構造化、§6.3)。
#[derive(Debug, Clone, Copy)]
pub struct MatterCertSpec<'a> {
    /// serial-number(生バイト列。DER INTEGER の内容オクテットとして扱う)。
    pub serial: &'a [u8],
    /// issuer DN(整数属性のみ)。RCAC は自己署名なので subject と同じ。
    pub issuer: &'a [DnAttr],
    /// subject DN(NOC は node-id + fabric-id、RCAC は rcac-id + fabric-id)。
    pub subject: &'a [DnAttr],
    /// not-before(Matter epoch 秒。0 も可)。
    pub not_before: u32,
    /// not-after(Matter epoch 秒。0 = 無期限)。
    pub not_after: u32,
    /// subject の EC 公開鍵(SEC1 非圧縮 65 バイト)。
    pub subject_pub: &'a [u8; P256_PUBLIC_KEY_LEN],
    /// basic-constraints.cA(RCAC/ICAC = true、NOC = false)。
    pub is_ca: bool,
    /// basic-constraints.pathLenConstraint(ICAC のみが持ちうる)。
    pub path_len: Option<u8>,
    /// key-usage ビット([`crate::cert::key_usage`])。
    pub key_usage: u16,
    /// extended-key-usage([`crate::cert::ext_key_usage`]。NOC は serverAuth + clientAuth)。
    pub eku: &'a [u8],
    /// subject-key-identifier(20 バイト)。
    pub skid: &'a [u8; 20],
    /// authority-key-identifier(発行者の skid。RCAC は自 skid)。
    pub akid: &'a [u8; 20],
}

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

fn write_dn(w: &mut TlvWriter<'_>, ctx: u8, attrs: &[DnAttr]) -> Result<()> {
    w.start_list(&cx(ctx))?;
    for a in attrs {
        w.write_u64(&cx(a.tag), a.val)?;
    }
    w.end_container()
}

/// [`MatterCertSpec`] の仕様どおり TLV 証明書を `out` に組み立て、DER TBS を再構築して
/// `issuer_kp` で ECDSA 署名し埋め戻す(§6.3。`write_cert` と同一手順)。
///
/// 戻りは証明書 TLV のバイト長。容量不足や符号化不能な入力は panic せずエラーを返す。
pub fn write_matter_cert<K: P256Keypair>(
    out: &mut [u8],
    spec: &MatterCertSpec<'_>,
    issuer_kp: &K,
) -> Result<usize> {
    // 1. プレースホルダ署名(0 埋め 64 バイト)で TLV 証明書を組み立てる。
    let len = {
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_bytes(&cx(1), spec.serial)?; // serial-number
        w.write_u8(&cx(2), 1)?; // signature-algorithm = ecdsa-with-SHA256
        write_dn(&mut w, 3, spec.issuer)?; // issuer
        w.write_u32(&cx(4), spec.not_before)?;
        w.write_u32(&cx(5), spec.not_after)?;
        write_dn(&mut w, 6, spec.subject)?; // subject
        w.write_u8(&cx(7), 1)?; // public-key-algorithm = ec-public-key
        w.write_u8(&cx(8), 1)?; // elliptic-curve-id = prime256v1
        w.write_bytes(&cx(9), spec.subject_pub)?;
        // extensions(cx10 リスト)。順序は正準(basic-constraints → key-usage →
        // extended-key-usage → subject-key-id → authority-key-id)。
        w.start_list(&cx(10))?;
        w.start_struct(&cx(1))?; // basic-constraints
        w.write_bool(&cx(1), spec.is_ca)?;
        if let Some(p) = spec.path_len {
            w.write_u8(&cx(2), p)?;
        }
        w.end_container()?;
        w.write_u16(&cx(2), spec.key_usage)?; // key-usage
        if !spec.eku.is_empty() {
            w.start_array(&cx(3))?; // extended-key-usage
            for e in spec.eku {
                w.write_u8(&TlvTag::Anonymous, *e)?;
            }
            w.end_container()?;
        }
        w.write_bytes(&cx(4), spec.skid)?; // subject-key-id
        w.write_bytes(&cx(5), spec.akid)?; // authority-key-id
        w.end_container()?; // extensions
        w.write_bytes(&cx(11), &[0u8; P256_SIGNATURE_LEN])?; // signature(プレースホルダ)
        w.end_container()?; // certificate
        w.len()
    };

    // 2. パースして DER TBS を再構築し、issuer 鍵で署名する。
    let mut tbs = [0u8; MAX_TBS_DER_LEN];
    let tbs_len = {
        let cert = MatterCert::parse(&out[..len])?;
        cert.to_be_signed(&mut tbs)?
    };
    let mut sig = [0u8; P256_SIGNATURE_LEN];
    issuer_kp.sign(&tbs[..tbs_len], &mut sig)?;

    // 3. 署名を証明書 TLV の signature フィールドへ埋め戻す。
    //    レイアウト: [.. | 0x30 0x40 sig(64) | 0x18(struct end)]。末尾 = ContainerEnd。
    let end = len.checked_sub(1).ok_or(Error::Decode)?;
    let start = end.checked_sub(P256_SIGNATURE_LEN).ok_or(Error::Decode)?;
    out.get_mut(start..end)
        .ok_or(Error::NoSpace)?
        .copy_from_slice(&sig);
    Ok(len)
}

/// NOC の extended-key-usage(serverAuth + clientAuth)。CA が NOC 発行で用いる定数。
pub const NOC_EKU: [u8; 2] = [ext_key_usage::SERVER_AUTH, ext_key_usage::CLIENT_AUTH];

// ---------------------------------------------------------------------------
// PKCS#10 CSR の解析
// ---------------------------------------------------------------------------

/// DER の 1 つの TLV を読み、`(tag, content_start, content_len, next)` を返す。
///
/// 長さは短形式と長形式(1〜2 バイト)のみ対応。範囲外・不正長は [`Error::Decode`]。
pub(crate) fn der_tlv(buf: &[u8], pos: usize) -> Result<(u8, usize, usize, usize)> {
    let tag = *buf.get(pos).ok_or(Error::Decode)?;
    let l0 = *buf.get(pos + 1).ok_or(Error::Decode)?;
    let (content_start, len) = if l0 < 0x80 {
        (pos + 2, usize::from(l0))
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 2 {
            return Err(Error::Decode);
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*buf.get(pos + 2 + i).ok_or(Error::Decode)?);
        }
        (pos + 2 + n, len)
    };
    let next = content_start.checked_add(len).ok_or(Error::Decode)?;
    if next > buf.len() {
        return Err(Error::Decode);
    }
    Ok((tag, content_start, len, next))
}

/// ビッグエンディアン整数 `be`(先頭 0 埋め・符号ビット対策の 0x00 前置を含みうる)を
/// 32 バイト右詰めで `out` に書く。有効桁が 32 を超えるなら [`Error::Decode`]。
fn copy_be_fixed(be: &[u8], out: &mut [u8]) -> Result<()> {
    let mut i = 0;
    while i < be.len() && be[i] == 0 {
        i += 1;
    }
    let v = &be[i..];
    if v.len() > out.len() {
        return Err(Error::Decode);
    }
    out.fill(0);
    let off = out.len() - v.len();
    out[off..].copy_from_slice(v);
    Ok(())
}

/// DER `ECDSA-Sig-Value ::= SEQUENCE { INTEGER r, INTEGER s }` を生 `r || s`(64 バイト)へ。
pub(crate) fn der_ecdsa_to_raw(der: &[u8]) -> Result<[u8; P256_SIGNATURE_LEN]> {
    let (tag, cs, cl, _) = der_tlv(der, 0)?;
    if tag != 0x30 {
        return Err(Error::Decode);
    }
    let content = &der[cs..cs + cl];
    let (tr, rcs, rcl, after_r) = der_tlv(content, 0)?;
    if tr != 0x02 {
        return Err(Error::Decode);
    }
    let (ts, scs, scl, _) = der_tlv(content, after_r)?;
    if ts != 0x02 {
        return Err(Error::Decode);
    }
    let mut out = [0u8; P256_SIGNATURE_LEN];
    copy_be_fixed(&content[rcs..rcs + rcl], &mut out[0..32])?;
    copy_be_fixed(&content[scs..scs + scl], &mut out[32..64])?;
    Ok(out)
}

/// CertificationRequestInfo の内容から subject 公開鍵(SEC1 非圧縮 65 バイト)を取り出す。
fn extract_csr_pubkey(cri: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_LEN]> {
    // CRI = SEQUENCE { INTEGER version, SEQUENCE subject, SEQUENCE subjectPKInfo, [0] attrs }
    let (t, _, _, after_ver) = der_tlv(cri, 0)?;
    if t != 0x02 {
        return Err(Error::Decode);
    }
    let (t, _, _, after_subj) = der_tlv(cri, after_ver)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let (t, pk_cs, pk_cl, _) = der_tlv(cri, after_subj)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    // subjectPKInfo = SEQUENCE { SEQUENCE algorithm, BIT STRING subjectPublicKey }
    let spki = &cri[pk_cs..pk_cs + pk_cl];
    let (t, _, _, after_algo) = der_tlv(spki, 0)?;
    if t != 0x30 {
        return Err(Error::Decode);
    }
    let (t, bs_cs, bs_cl, _) = der_tlv(spki, after_algo)?;
    if t != 0x03 {
        return Err(Error::Decode);
    }
    // BIT STRING 内容 = [unused_bits(0x00), 0x04, X(32), Y(32)]。
    let bits = &spki[bs_cs..bs_cs + bs_cl];
    let pk = bits.get(1..).ok_or(Error::Decode)?;
    if pk.len() != P256_PUBLIC_KEY_LEN || pk[0] != 0x04 {
        return Err(Error::Decode);
    }
    let mut out = [0u8; P256_PUBLIC_KEY_LEN];
    out.copy_from_slice(pk);
    Ok(out)
}

/// PKCS#10 CSR(DER)から subject 公開鍵を取り出し、CSR の自己署名を検証する(§6.3)。
///
/// デバイスの `CSRResponse`(NOCSRElements 内の `csr`)処理に用いる。署名が有効なら
/// 公開鍵(SEC1 非圧縮 65 バイト)を返す。デコード不正は [`Error::Decode`]、署名不正は
/// [`Error::Crypto`]。panic しない。
pub fn parse_csr<C: Crypto>(crypto: &C, csr: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_LEN]> {
    // CertificationRequest = SEQUENCE { CRI(SEQUENCE), sigAlg(SEQUENCE), signature(BIT STRING) }
    let (tag, cs, cl, _) = der_tlv(csr, 0)?;
    if tag != 0x30 {
        return Err(Error::Decode);
    }
    let outer = &csr[cs..cs + cl];

    // CertificationRequestInfo(= 署名対象)。
    let (t1, cri_cs, cri_cl, after_cri) = der_tlv(outer, 0)?;
    if t1 != 0x30 {
        return Err(Error::Decode);
    }
    let cri_full = &outer[0..after_cri]; // tag+len+content = 署名されたメッセージ。

    // signatureAlgorithm(読み飛ばし)。
    let (t2, _, _, after_alg) = der_tlv(outer, after_cri)?;
    if t2 != 0x30 {
        return Err(Error::Decode);
    }

    // signature(BIT STRING; 内容 = [unused_bits, DER ECDSA-Sig-Value])。
    let (t3, sig_cs, sig_cl, _) = der_tlv(outer, after_alg)?;
    if t3 != 0x03 {
        return Err(Error::Decode);
    }
    let sig_bits = &outer[sig_cs..sig_cs + sig_cl];
    let der_sig = sig_bits.get(1..).ok_or(Error::Decode)?;
    let raw_sig = der_ecdsa_to_raw(der_sig)?;

    let pubkey = extract_csr_pubkey(&outer[cri_cs..cri_cs + cri_cl])?;

    let key = crypto.p256_public_key_from_bytes(&pubkey)?;
    if key.verify(cri_full, &raw_sig)? {
        Ok(pubkey)
    } else {
        Err(Error::Crypto)
    }
}
