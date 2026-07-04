//! Matter 運用証明書(NOC / ICAC / RCAC)の TLV パースと検証。
//!
//! Matter Core Specification §6.5「Operational Certificate Encoding」で規定される
//! 証明書は、X.509 v3 証明書を Matter TLV 形式で表現したものである。本モジュールは
//! 入力バイト列(`&[u8]`, Matter TLV エンコーディング)から、CASE(§4.14)の
//! 署名検証・チェーン検証・destination identifier 計算に必要なフィールドへの
//! **借用ビュー**([`MatterCert`])を提供する。
//!
//! # alloc 方針
//!
//! `docs/ARCHITECTURE.md` 設計原則2に従い、証明書は固定バッファ上のストリーミング
//! TLV パースを基本とする。[`MatterCert`] は入力バイト列を **コピーせず借用**し、
//! ヒープを確保しない。DN リスト・拡張はいずれも入力バッファへの部分スライスとして
//! 保持する。署名対象(TBS)の DER TBSCertificate は署名検証時に呼び出し側の固定
//! バッファ上へ再構築する(下記「署名対象(TBS)についての設計判断」を参照)。
//!
//! # パースと暗号 backend の分離
//!
//! パース([`MatterCert::parse`])は暗号 backend に依存せず、`tlv` / `error` のみに
//! 依存する(`--no-default-features` でも動く)。署名検証([`MatterCert::verify_signature`])
//! とチェーン検証([`verify_chain`])のみが [`Crypto`] にジェネリックである。
//!
//! # 署名対象(TBS)についての設計判断
//!
//! Matter 仕様準拠の実 Matter 互換実装として、証明書署名は TLV 証明書を X.509
//! **DER** の TBSCertificate へ再構築したバイト列に対して検証する
//! (Matter Core Specification §6.5、connectedhomeip `CHIPCertToX509` の変換規則に
//! 準拠)。[`MatterCert::to_be_signed`] はパース済み [`MatterCert`] から
//! 呼び出し側バッファへ DER TBSCertificate をヒープなしで書き出す。
//!
//! 再構築する TBSCertificate は次のフィールドから成る(RFC 5280 / Matter §6.5):
//! version(v3)、serial-number、signature(ecdsa-with-SHA256)、issuer DN、
//! validity(Matter epoch 秒 → UTCTime/GeneralizedTime。`not-after = 0` は
//! 無期限を表し `99991231235959Z` の GeneralizedTime として符号化)、subject DN、
//! SubjectPublicKeyInfo(EC P-256)、extensions。Matter 固有 DN 属性は
//! `1.3.6.1.4.1.37244.1.*` の OID + 16 桁(CAT は 8 桁)大文字 16 進の UTF8String
//! として符号化する。DER 化は [`der`] の最小 DER ライタが担い、署名検証は
//! 再構築した TBS を SHA-256 でハッシュして P-256 ECDSA 検証する。
//!
//! 再構築後の DER TBSCertificate の上限は [`MAX_TBS_DER_LEN`](600 バイト)とする。
//! Matter 証明書の TLV 上限は約 400 バイト、DER 化後の上限は約 600 バイト級
//! (rs-matter `MAX_CERT_ASN1_LEN` と同値)であり、署名を含まない TBS はこれを
//! 下回る。

use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN};
use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

use self::der::DerWriter;

mod der;

/// 運用証明書の発行(CA)と CSR 解析。`controller` feature 有効時のみ。
#[cfg(feature = "controller")]
pub mod issue;

#[cfg(feature = "controller")]
pub use issue::{parse_csr, write_matter_cert, DnAttr, MatterCertSpec, NOC_EKU};

/// Matter epoch(2000-01-01T00:00:00Z)の Unix タイムスタンプ(秒)。
///
/// Matter 証明書の validity は Matter epoch 秒で表現される。DER の UTCTime/
/// GeneralizedTime へ変換する際にこの定数を加えて Unix 秒へ直す。
const MATTER_EPOCH_SECS: u64 = 946_684_800;

/// `not-after = 0`(無期限)を表す Matter epoch 秒。`99991231235959Z` に対応する。
const MATTER_CERT_DOESNT_EXPIRE: u64 = 252_455_615_999;

/// 再構築した DER TBSCertificate の最大バイト数。
///
/// Matter 証明書 TLV の上限は約 400 バイト、DER 化後(署名込みの完全な証明書)の
/// 上限は約 600 バイト級であり、署名を含まない TBSCertificate はこれを下回る。
/// [`MatterCert::to_be_signed`] はこのサイズのバッファに収まることを前提とする。
pub const MAX_TBS_DER_LEN: usize = 600;

// --- X.509 OID(DER 符号化済み内容オクテット)---

/// ecdsa-with-SHA256(1.2.840.10045.4.3.2)。
const OID_ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// id-ecPublicKey(1.2.840.10045.2.1)。
const OID_EC_PUBLIC_KEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// prime256v1 / secp256r1(1.2.840.10045.3.1.7)。
const OID_PRIME256V1: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// basic-constraints(2.5.29.19)。
const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
/// key-usage(2.5.29.15)。
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];
/// ext-key-usage(2.5.29.37)。
const OID_EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x25];
/// subject-key-identifier(2.5.29.14)。
const OID_SUBJECT_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x0E];
/// authority-key-identifier(2.5.29.35)。
const OID_AUTHORITY_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x23];

/// extended-key-usage の purpose(値 1..=6)に対応する OID。
const OID_EKU_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_EKU_CLIENT_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_EKU_CODE_SIGNING: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
const OID_EKU_EMAIL_PROTECTION: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
const OID_EKU_TIME_STAMPING: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
const OID_EKU_OCSP_SIGNING: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

// --- 証明書トップレベルのコンテキストタグ(§6.5.1)---

/// serial-num(コンテキストタグ 1)。
const TAG_SERIAL_NUM: u8 = 1;
/// signature-algorithm(コンテキストタグ 2)。
const TAG_SIG_ALGO: u8 = 2;
/// issuer(コンテキストタグ 3, DN リスト)。
const TAG_ISSUER: u8 = 3;
/// not-before(コンテキストタグ 4, Matter epoch 秒)。
const TAG_NOT_BEFORE: u8 = 4;
/// not-after(コンテキストタグ 5, Matter epoch 秒)。
const TAG_NOT_AFTER: u8 = 5;
/// subject(コンテキストタグ 6, DN リスト)。
const TAG_SUBJECT: u8 = 6;
/// public-key-algorithm(コンテキストタグ 7)。
const TAG_PUB_KEY_ALGO: u8 = 7;
/// elliptic-curve-id(コンテキストタグ 8)。
const TAG_EC_CURVE_ID: u8 = 8;
/// elliptic-curve-public-key(コンテキストタグ 9, SEC1 非圧縮 65 バイト)。
const TAG_EC_PUB_KEY: u8 = 9;
/// extensions(コンテキストタグ 10, リスト)。
const TAG_EXTENSIONS: u8 = 10;
/// signature(コンテキストタグ 11, 生 r||s 64 バイト)。
const TAG_SIGNATURE: u8 = 11;

// --- 拡張リストのコンテキストタグ(§6.5.11)---

const EXT_BASIC_CONSTRAINTS: u8 = 1;
const EXT_KEY_USAGE: u8 = 2;
const EXT_EXTENDED_KEY_USAGE: u8 = 3;
const EXT_SUBJECT_KEY_ID: u8 = 4;
const EXT_AUTHORITY_KEY_ID: u8 = 5;
const EXT_FUTURE_EXTENSIONS: u8 = 6;

// --- basic-constraints 構造体内タグ ---

const BC_IS_CA: u8 = 1;
const BC_PATH_LEN: u8 = 2;

/// DN(Distinguished Name)属性のコンテキストタグ。
///
/// Matter 固有 OID に対応する属性(node-id 等)と、標準 X.509 DN 属性の一部を含む。
/// 文字列値をとる標準属性は PrintableString 版でタグに `0x80` が加算される
/// (Matter TLV エンコーディング規約)。ここでは `& 0x7f` した属性種別を表す。
pub mod dn_attr {
    /// matter-node-id(NOC の subject に現れる、u64)。
    pub const MATTER_NODE_ID: u8 = 17;
    /// matter-firmware-signing-id(u64)。
    pub const MATTER_FIRMWARE_SIGNING_ID: u8 = 18;
    /// matter-icac-id(ICAC の subject に現れる、u64)。
    pub const MATTER_ICAC_ID: u8 = 19;
    /// matter-rcac-id(RCAC の subject に現れる、u64)。
    pub const MATTER_RCAC_ID: u8 = 20;
    /// matter-fabric-id(NOC/ICAC/RCAC の subject に現れうる、u64)。
    pub const MATTER_FABRIC_ID: u8 = 21;
    /// matter-noc-cat(CASE Authenticated Tag, u32)。
    pub const MATTER_NOC_CAT: u8 = 22;
}

/// Matter TLV エンコーディングにおける key-usage ビットフラグ(§6.5.11.2)。
///
/// X.509 DER の BIT STRING とはビット順が異なり、TLV では標準的な u16 ビット位置
/// (bit 0 = LSB)を用いる。
pub mod key_usage {
    /// digitalSignature。
    pub const DIGITAL_SIGNATURE: u16 = 0x0001;
    /// nonRepudiation。
    pub const NON_REPUDIATION: u16 = 0x0002;
    /// keyEncipherment。
    pub const KEY_ENCIPHERMENT: u16 = 0x0004;
    /// dataEncipherment。
    pub const DATA_ENCIPHERMENT: u16 = 0x0008;
    /// keyAgreement。
    pub const KEY_AGREEMENT: u16 = 0x0010;
    /// keyCertSign。
    pub const KEY_CERT_SIGN: u16 = 0x0020;
    /// cRLSign。
    pub const CRL_SIGN: u16 = 0x0040;
    /// encipherOnly。
    pub const ENCIPHER_ONLY: u16 = 0x0080;
    /// decipherOnly。
    pub const DECIPHER_ONLY: u16 = 0x0100;
}

/// extended-key-usage(§6.5.11.3)の小整数エンコーディング値。
pub mod ext_key_usage {
    /// serverAuth。
    pub const SERVER_AUTH: u8 = 1;
    /// clientAuth。
    pub const CLIENT_AUTH: u8 = 2;
    /// codeSigning。
    pub const CODE_SIGNING: u8 = 3;
    /// emailProtection。
    pub const EMAIL_PROTECTION: u8 = 4;
    /// timeStamping。
    pub const TIME_STAMPING: u8 = 5;
    /// ocspSigning。
    pub const OCSP_SIGNING: u8 = 6;
}

/// 署名アルゴリズム(§6.5.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ecdsa-with-SHA256(値 1)。Matter が定義する唯一のアルゴリズム。
    EcdsaWithSha256,
}

/// 公開鍵アルゴリズム(§6.5.7)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// EC Public Key(値 1)。
    EcPublicKey,
}

/// 楕円曲線 ID(§6.5.8)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurveId {
    /// prime256v1 / secp256r1 / P-256(値 1)。
    Prime256v1,
}

/// 証明書の種別。subject DN が持つ CA-id 属性から判定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// Root CA Certificate(subject に matter-rcac-id を持つ)。
    Rcac,
    /// Intermediate CA Certificate(subject に matter-icac-id を持つ)。
    Icac,
    /// Node Operational Certificate(subject に matter-node-id を持つ)。
    Noc,
}

/// basic-constraints 拡張の値(§6.5.11.1)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraints {
    /// cA フラグ。RCAC/ICAC は `true`、NOC は `false`。
    pub is_ca: bool,
    /// pathLenConstraint。存在する場合のみ `Some`(ICAC のみが値 0 を持ちうる)。
    pub path_len_constraint: Option<u8>,
}

/// DN リスト(issuer / subject)への借用ビュー。
///
/// 内部に DN リスト要素そのもの(`0x37 .. 0x18` の TLV リスト)のバイトスライスを
/// 保持し、アクセサ呼び出しごとにストリーミングで走査する。ヒープを確保しない。
/// 未知の DN 属性はスキップして走査を継続する。
#[derive(Debug, Clone, Copy)]
pub struct DnList<'a> {
    raw: &'a [u8],
}

/// DN 属性 1 件の値。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnValue<'a> {
    /// 整数値(matter-node-id 等)。
    Uint(u64),
    /// 文字列値(UTF8String / PrintableString。`printable` で区別)。
    Str(&'a str),
}

/// DN 属性 1 件(種別・PrintableString フラグ・値)。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DnAttribute<'a> {
    /// 属性種別(コンテキストタグを `& 0x7f` した値。[`dn_attr`] 参照)。
    pub attr_type: u8,
    /// PrintableString 版(タグに `0x80` が加算されていた)なら `true`。
    pub printable: bool,
    /// 属性値。
    pub value: DnValue<'a>,
}

/// [`DnList`] の属性を順に返すイテレータ。
///
/// 各要素は `Result<DnAttribute>` で、不正な TLV に遭遇した時点で
/// `Err(Error::Decode)` を返す(以降は `None`)。
#[derive(Debug, Clone)]
pub struct DnIter<'a> {
    reader: TlvReader<'a>,
    done: bool,
}

impl<'a> DnList<'a> {
    /// DN 属性を順に返すイテレータを生成する。
    pub fn iter(&self) -> DnIter<'a> {
        let mut reader = TlvReader::new(self.raw);
        // 先頭のリスト開始トークンを消費する。失敗しても最初の next で
        // Decode を返すため、ここでは結果を無視する。
        let _ = reader.read_next();
        DnIter {
            reader,
            done: false,
        }
    }

    /// 指定した属性種別の最初の整数値を返す。存在しなければ `Ok(None)`。
    fn find_uint(&self, attr_type: u8) -> Result<Option<u64>> {
        for attr in self.iter() {
            let attr = attr?;
            if attr.attr_type == attr_type {
                if let DnValue::Uint(v) = attr.value {
                    return Ok(Some(v));
                }
            }
        }
        Ok(None)
    }

    /// matter-node-id を返す(NOC の subject)。
    pub fn node_id(&self) -> Result<Option<u64>> {
        self.find_uint(dn_attr::MATTER_NODE_ID)
    }

    /// matter-fabric-id を返す。
    pub fn fabric_id(&self) -> Result<Option<u64>> {
        self.find_uint(dn_attr::MATTER_FABRIC_ID)
    }

    /// matter-icac-id を返す(ICAC の subject)。
    pub fn icac_id(&self) -> Result<Option<u64>> {
        self.find_uint(dn_attr::MATTER_ICAC_ID)
    }

    /// matter-rcac-id を返す(RCAC の subject)。
    pub fn rcac_id(&self) -> Result<Option<u64>> {
        self.find_uint(dn_attr::MATTER_RCAC_ID)
    }

    /// matter-noc-cat(CASE Authenticated Tag)群を `out` に書き出し、件数を返す。
    ///
    /// `out` に収まらない場合は [`Error::NoSpace`]。
    pub fn cats(&self, out: &mut [u32]) -> Result<usize> {
        let mut n = 0;
        for attr in self.iter() {
            let attr = attr?;
            if attr.attr_type == dn_attr::MATTER_NOC_CAT {
                if let DnValue::Uint(v) = attr.value {
                    *out.get_mut(n).ok_or(Error::NoSpace)? = v as u32;
                    n += 1;
                }
            }
        }
        Ok(n)
    }
}

impl<'a> Iterator for DnIter<'a> {
    type Item = Result<DnAttribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let elem = match self.reader.read_next() {
            Ok(Some(e)) => e,
            Ok(None) => {
                self.done = true;
                return None;
            }
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        };
        if elem.value == TlvValue::ContainerEnd {
            self.done = true;
            return None;
        }
        let ctx = match elem.tag {
            TlvTag::ContextSpecific(c) => c,
            _ => {
                self.done = true;
                return Some(Err(Error::Decode));
            }
        };
        let value = match elem.value {
            TlvValue::UnsignedInteger(v) => DnValue::Uint(v),
            TlvValue::SignedInteger(v) => DnValue::Uint(v as u64),
            TlvValue::Utf8String(s) => DnValue::Str(s),
            _ => {
                // 未知/未対応の値型(コンテナ等)はスキップして継続する。
                if self.reader.skip(&elem).is_err() {
                    self.done = true;
                    return Some(Err(Error::Decode));
                }
                return self.next();
            }
        };
        Some(Ok(DnAttribute {
            attr_type: ctx & 0x7f,
            printable: ctx >= 0x80,
            value,
        }))
    }
}

/// 証明書拡張(§6.5.11)への借用ビュー。
///
/// パース時に一度だけ走査し、各拡張値(またはその借用スライス)を保持する。
#[derive(Debug, Clone, Copy)]
pub struct Extensions<'a> {
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<u16>,
    extended_key_usage: Option<&'a [u8]>,
    subject_key_id: Option<&'a [u8]>,
    authority_key_id: Option<&'a [u8]>,
    future_extensions: Option<&'a [u8]>,
}

impl<'a> Extensions<'a> {
    /// basic-constraints 拡張の値。
    pub fn basic_constraints(&self) -> Option<BasicConstraints> {
        self.basic_constraints
    }

    /// key-usage ビット([`key_usage`] 参照)。
    pub fn key_usage(&self) -> Option<u16> {
        self.key_usage
    }

    /// subject-key-id(SHA-1 20 バイトが一般的)。
    pub fn subject_key_id(&self) -> Option<&'a [u8]> {
        self.subject_key_id
    }

    /// authority-key-id(発行者の subject-key-id と一致する)。
    pub fn authority_key_id(&self) -> Option<&'a [u8]> {
        self.authority_key_id
    }

    /// future-extensions が存在するか。
    ///
    /// 本モジュールは future-extensions の内容(DER サブ拡張)を解釈しない。
    /// critical フラグの検査は DER サポート導入時に追加する。
    pub fn has_future_extensions(&self) -> bool {
        self.future_extensions.is_some()
    }

    /// extended-key-usage が `required` の全 purpose を含むなら `true`。
    ///
    /// 拡張自体が存在しない場合や、いずれかの purpose を欠く場合は `Ok(false)`。
    pub fn extended_key_usage_has_all(&self, required: &[u8]) -> Result<bool> {
        let Some(raw) = self.extended_key_usage else {
            return Ok(false);
        };
        for need in required {
            let mut found = false;
            let mut r = TlvReader::new(raw);
            // array 開始トークンを消費。
            r.read_next()?;
            loop {
                let elem = r.read_next()?.ok_or(Error::Decode)?;
                if elem.value == TlvValue::ContainerEnd {
                    break;
                }
                if let TlvValue::UnsignedInteger(v) = elem.value {
                    if v as u8 == *need {
                        found = true;
                    }
                }
            }
            if !found {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Matter 運用証明書(NOC / ICAC / RCAC)への借用ビュー。
///
/// [`MatterCert::parse`] で入力バイト列から生成する。全フィールドは入力バッファを
/// 借用しており、コピー・ヒープ確保を行わない。
#[derive(Debug, Clone, Copy)]
pub struct MatterCert<'a> {
    serial_number: &'a [u8],
    signature_algorithm: SignatureAlgorithm,
    issuer: DnList<'a>,
    not_before: u32,
    not_after: u32,
    subject: DnList<'a>,
    public_key_algorithm: PublicKeyAlgorithm,
    ec_curve_id: EcCurveId,
    public_key: &'a [u8],
    extensions: Extensions<'a>,
    signature: &'a [u8],
}

impl<'a> MatterCert<'a> {
    /// Matter TLV 形式の証明書バイト列をパースして借用ビューを生成する。
    ///
    /// panic せず、不正な TLV・欠落フィールド・不正な型は [`Error::Decode`] を返す。
    pub fn parse(cert: &'a [u8]) -> Result<Self> {
        let mut r = TlvReader::new(cert);

        // トップレベルは anonymous な structure。
        let head = r.read_next()?.ok_or(Error::Decode)?;
        if head.value.as_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }

        let mut serial_number = None;
        let mut signature_algorithm = None;
        let mut issuer = None;
        let mut not_before = None;
        let mut not_after = None;
        let mut subject = None;
        let mut public_key_algorithm = None;
        let mut ec_curve_id = None;
        let mut public_key = None;
        let mut extensions = None;
        let mut signature = None;

        loop {
            let pos = r.position();
            let elem = r.read_next()?.ok_or(Error::Decode)?;
            if elem.value == TlvValue::ContainerEnd {
                break;
            }
            let ctx = match elem.tag {
                TlvTag::ContextSpecific(c) => c,
                _ => return Err(Error::Decode),
            };
            match ctx {
                TAG_SERIAL_NUM => serial_number = Some(elem.value.as_bytes()?),
                TAG_SIG_ALGO => {
                    signature_algorithm = Some(match elem.value.as_unsigned()? {
                        1 => SignatureAlgorithm::EcdsaWithSha256,
                        _ => return Err(Error::Decode),
                    });
                }
                TAG_ISSUER => {
                    elem.value.as_container()?;
                    r.exit_container()?;
                    issuer = Some(DnList {
                        raw: &cert[pos..r.position()],
                    });
                }
                TAG_NOT_BEFORE => {
                    not_before =
                        Some(u32::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
                }
                TAG_NOT_AFTER => {
                    not_after =
                        Some(u32::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
                }
                TAG_SUBJECT => {
                    elem.value.as_container()?;
                    r.exit_container()?;
                    subject = Some(DnList {
                        raw: &cert[pos..r.position()],
                    });
                }
                TAG_PUB_KEY_ALGO => {
                    public_key_algorithm = Some(match elem.value.as_unsigned()? {
                        1 => PublicKeyAlgorithm::EcPublicKey,
                        _ => return Err(Error::Decode),
                    });
                }
                TAG_EC_CURVE_ID => {
                    ec_curve_id = Some(match elem.value.as_unsigned()? {
                        1 => EcCurveId::Prime256v1,
                        _ => return Err(Error::Decode),
                    });
                }
                TAG_EC_PUB_KEY => {
                    let key = elem.value.as_bytes()?;
                    if key.len() != P256_PUBLIC_KEY_LEN {
                        return Err(Error::Decode);
                    }
                    public_key = Some(key);
                }
                TAG_EXTENSIONS => {
                    elem.value.as_container()?;
                    r.exit_container()?;
                    extensions = Some(parse_extensions(&cert[pos..r.position()])?);
                }
                TAG_SIGNATURE => {
                    let sig = elem.value.as_bytes()?;
                    if sig.len() != P256_SIGNATURE_LEN {
                        return Err(Error::Decode);
                    }
                    signature = Some(sig);
                }
                // 未知のトップレベルフィールドはスキップして継続する。
                _ => r.skip(&elem)?,
            }
        }

        Ok(Self {
            serial_number: serial_number.ok_or(Error::Decode)?,
            signature_algorithm: signature_algorithm.ok_or(Error::Decode)?,
            issuer: issuer.ok_or(Error::Decode)?,
            not_before: not_before.ok_or(Error::Decode)?,
            not_after: not_after.ok_or(Error::Decode)?,
            subject: subject.ok_or(Error::Decode)?,
            public_key_algorithm: public_key_algorithm.ok_or(Error::Decode)?,
            ec_curve_id: ec_curve_id.ok_or(Error::Decode)?,
            public_key: public_key.ok_or(Error::Decode)?,
            extensions: extensions.ok_or(Error::Decode)?,
            signature: signature.ok_or(Error::Decode)?,
        })
    }

    /// serial-number(生バイト列)。
    pub fn serial_number(&self) -> &'a [u8] {
        self.serial_number
    }

    /// 署名アルゴリズム。
    pub fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    /// issuer DN リスト。
    pub fn issuer(&self) -> &DnList<'a> {
        &self.issuer
    }

    /// not-before(Matter epoch = 2000-01-01T00:00:00Z 起点の秒)。
    pub fn not_before(&self) -> u32 {
        self.not_before
    }

    /// not-after(Matter epoch 秒。値 0 は「無期限」を表す)。
    pub fn not_after(&self) -> u32 {
        self.not_after
    }

    /// subject DN リスト。
    pub fn subject(&self) -> &DnList<'a> {
        &self.subject
    }

    /// 公開鍵アルゴリズム。
    pub fn public_key_algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key_algorithm
    }

    /// 楕円曲線 ID。
    pub fn ec_curve_id(&self) -> EcCurveId {
        self.ec_curve_id
    }

    /// subject の EC 公開鍵(SEC1 非圧縮 65 バイト)。
    pub fn public_key(&self) -> &'a [u8] {
        self.public_key
    }

    /// 証明書拡張。
    pub fn extensions(&self) -> &Extensions<'a> {
        &self.extensions
    }

    /// signature(生 r||s, 64 バイト)。
    pub fn signature(&self) -> &'a [u8] {
        self.signature
    }

    /// 署名対象(to-be-signed)の X.509 DER TBSCertificate を `out` に再構築し、
    /// 書き込んだバイト数を返す。
    ///
    /// パース済みフィールドから RFC 5280 / Matter §6.5 に従う TBSCertificate を
    /// DER 符号化する(モジュールドキュメント参照)。`out` は少なくとも
    /// [`MAX_TBS_DER_LEN`] バイトの容量が望ましい。容量不足は [`Error::NoSpace`]、
    /// 未対応の DN 属性など符号化不能な入力は [`Error::Decode`] を返し panic しない。
    pub fn to_be_signed(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = DerWriter::new(out);
        self.encode_tbs(&mut w)?;
        Ok(w.len())
    }

    /// TBSCertificate を `w` へ DER 符号化する。
    fn encode_tbs(&self, w: &mut DerWriter<'_>) -> Result<()> {
        w.start_seq()?; // TBSCertificate

        // version [0] { INTEGER 2 }(v3)。
        w.start_ctx(0)?;
        w.integer(&[2])?;
        w.end_container()?;

        // serialNumber。TLV の serial は DER INTEGER の内容オクテットそのもの。
        w.integer(self.serial_number)?;

        // signature(AlgorithmIdentifier)。
        w.start_seq()?;
        w.oid(&OID_ECDSA_WITH_SHA256)?;
        w.end_container()?;

        // issuer。
        encode_dn(w, &self.issuer)?;

        // validity。
        w.start_seq()?;
        encode_time(w, u64::from(self.not_before))?;
        if self.not_after == 0 {
            encode_time(w, MATTER_CERT_DOESNT_EXPIRE)?;
        } else {
            encode_time(w, u64::from(self.not_after))?;
        }
        w.end_container()?;

        // subject。
        encode_dn(w, &self.subject)?;

        // subjectPublicKeyInfo。
        w.start_seq()?;
        w.start_seq()?;
        w.oid(&OID_EC_PUBLIC_KEY)?;
        w.oid(&OID_PRIME256V1)?;
        w.end_container()?;
        w.bit_string(false, self.public_key)?;
        w.end_container()?;

        // extensions [3] { SEQUENCE { ... } }。
        encode_extensions(w, &self.extensions)?;

        w.end_container()?; // TBSCertificate
        Ok(())
    }

    /// subject DN から証明書種別を判定する。
    pub fn cert_type(&self) -> Result<CertType> {
        if self.subject.node_id()?.is_some() {
            Ok(CertType::Noc)
        } else if self.subject.icac_id()?.is_some() {
            Ok(CertType::Icac)
        } else if self.subject.rcac_id()?.is_some() {
            Ok(CertType::Rcac)
        } else {
            Err(Error::Decode)
        }
    }

    /// この証明書が自己署名(authority-key-id == subject-key-id)なら `true`。
    ///
    /// Matter の RCAC は常に自己署名される。両拡張のいずれかが欠ける場合は
    /// [`Error::Decode`]。
    pub fn is_self_signed(&self) -> Result<bool> {
        let akid = self.extensions.authority_key_id.ok_or(Error::Decode)?;
        let skid = self.extensions.subject_key_id.ok_or(Error::Decode)?;
        Ok(akid == skid)
    }

    /// 指定時刻 `now`(Matter epoch 秒)がこの証明書の有効期間内かを検査する。
    ///
    /// 期間外なら [`Error::CertInvalid`]。not-after が 0 の場合は上限なしとして扱う。
    pub fn check_validity(&self, now: u32) -> Result<()> {
        if now < self.not_before {
            return Err(Error::CertInvalid);
        }
        if self.not_after != 0 && now > self.not_after {
            return Err(Error::CertInvalid);
        }
        Ok(())
    }

    /// 発行者の公開鍵 `issuer_public_key`(SEC1, 65 バイト)でこの証明書の署名を検証する。
    ///
    /// TBS を SHA-256 でハッシュし P-256 ECDSA 検証する(ハッシュは backend 内部で行う)。
    /// 署名が無効なら [`Error::Crypto`]、鍵/署名の形式不正も [`Error::Crypto`]。
    pub fn verify_signature<C: Crypto>(&self, crypto: &C, issuer_public_key: &[u8]) -> Result<()> {
        let sig: &[u8; P256_SIGNATURE_LEN] =
            self.signature.try_into().map_err(|_| Error::Crypto)?;
        let mut tbs = [0u8; MAX_TBS_DER_LEN];
        let len = self.to_be_signed(&mut tbs)?;
        let key = crypto.p256_public_key_from_bytes(issuer_public_key)?;
        if key.verify(&tbs[..len], sig)? {
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }

    /// この証明書の種別と chain 上の深さに応じた基本制約・鍵用途ポリシを検査する。
    ///
    /// - NOC(depth 0): basic-constraints.cA=false、key-usage に digitalSignature、
    ///   extended-key-usage に serverAuth と clientAuth を要求。
    /// - ICAC/RCAC: basic-constraints.cA=true、key-usage に keyCertSign を要求。
    ///   pathLenConstraint がある場合、下位の中間証明書数(`depth - 1`)が超えないこと。
    fn verify_usage(&self, cert_type: CertType, depth: u8) -> Result<()> {
        let key_usage = self.extensions.key_usage.ok_or(Error::CertInvalid)?;
        match cert_type {
            CertType::Noc => {
                if depth != 0 {
                    return Err(Error::CertInvalid);
                }
                let bc = self
                    .extensions
                    .basic_constraints
                    .ok_or(Error::CertInvalid)?;
                if bc.is_ca {
                    return Err(Error::CertInvalid);
                }
                if key_usage & key_usage::DIGITAL_SIGNATURE == 0 {
                    return Err(Error::CertInvalid);
                }
                if !self.extensions.extended_key_usage_has_all(&[
                    ext_key_usage::SERVER_AUTH,
                    ext_key_usage::CLIENT_AUTH,
                ])? {
                    return Err(Error::CertInvalid);
                }
            }
            CertType::Icac | CertType::Rcac => {
                let bc = self
                    .extensions
                    .basic_constraints
                    .ok_or(Error::CertInvalid)?;
                if !bc.is_ca {
                    return Err(Error::CertInvalid);
                }
                if key_usage & key_usage::KEY_CERT_SIGN == 0 {
                    return Err(Error::CertInvalid);
                }
                if let Some(max_intermediates) = bc.path_len_constraint {
                    if depth > 0 && depth - 1 > max_intermediates {
                        return Err(Error::CertInvalid);
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLV → X.509 DER TBSCertificate 変換ヘルパ
// ---------------------------------------------------------------------------

/// DN 属性種別(`attr_type`)に対応する X.509 属性 OID と、整数属性の場合の
/// 16 進符号化桁数を返す。未対応の種別は `None`。
///
/// Matter 固有属性(17..=22)は `1.3.6.1.4.1.37244.1.*`、標準属性(1..=16)は
/// `2.5.4.*` 系または domainComponent。整数属性(node-id 等)は固定桁数の
/// 大文字 16 進 UTF8String として符号化する(桁数を `Some` で返す)。
fn dn_attr_oid(attr_type: u8) -> Option<(&'static [u8], Option<u8>)> {
    // 標準属性 OID(2.5.4.*)。
    const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    const OID_SURNAME: &[u8] = &[0x55, 0x04, 0x04];
    const OID_SERIAL_NUMBER: &[u8] = &[0x55, 0x04, 0x05];
    const OID_COUNTRY_NAME: &[u8] = &[0x55, 0x04, 0x06];
    const OID_LOCALITY_NAME: &[u8] = &[0x55, 0x04, 0x07];
    const OID_STATE_NAME: &[u8] = &[0x55, 0x04, 0x08];
    const OID_ORG_NAME: &[u8] = &[0x55, 0x04, 0x0A];
    const OID_ORG_UNIT_NAME: &[u8] = &[0x55, 0x04, 0x0B];
    const OID_TITLE: &[u8] = &[0x55, 0x04, 0x0C];
    const OID_NAME: &[u8] = &[0x55, 0x04, 0x29];
    const OID_GIVEN_NAME: &[u8] = &[0x55, 0x04, 0x2A];
    const OID_INITIALS: &[u8] = &[0x55, 0x04, 0x2B];
    const OID_GEN_QUALIFIER: &[u8] = &[0x55, 0x04, 0x2C];
    const OID_DN_QUALIFIER: &[u8] = &[0x55, 0x04, 0x2E];
    const OID_PSEUDONYM: &[u8] = &[0x55, 0x04, 0x41];
    const OID_DOMAIN_COMPONENT: &[u8] =
        &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19];
    // Matter 固有属性 OID(1.3.6.1.4.1.37244.1.*)。
    const OID_MATTER_NODE_ID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x01];
    const OID_MATTER_FW_SIGN_ID: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x02];
    const OID_MATTER_ICAC_ID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x03];
    const OID_MATTER_RCAC_ID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x04];
    const OID_MATTER_FABRIC_ID: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x05];
    const OID_MATTER_CASE_AUTH_TAG: &[u8] =
        &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x06];

    Some(match attr_type {
        1 => (OID_COMMON_NAME, None),
        2 => (OID_SURNAME, None),
        3 => (OID_SERIAL_NUMBER, None),
        4 => (OID_COUNTRY_NAME, None),
        5 => (OID_LOCALITY_NAME, None),
        6 => (OID_STATE_NAME, None),
        7 => (OID_ORG_NAME, None),
        8 => (OID_ORG_UNIT_NAME, None),
        9 => (OID_TITLE, None),
        10 => (OID_NAME, None),
        11 => (OID_GIVEN_NAME, None),
        12 => (OID_INITIALS, None),
        13 => (OID_GEN_QUALIFIER, None),
        14 => (OID_DN_QUALIFIER, None),
        15 => (OID_PSEUDONYM, None),
        16 => (OID_DOMAIN_COMPONENT, None),
        dn_attr::MATTER_NODE_ID => (OID_MATTER_NODE_ID, Some(16)),
        dn_attr::MATTER_FIRMWARE_SIGNING_ID => (OID_MATTER_FW_SIGN_ID, Some(16)),
        dn_attr::MATTER_ICAC_ID => (OID_MATTER_ICAC_ID, Some(16)),
        dn_attr::MATTER_RCAC_ID => (OID_MATTER_RCAC_ID, Some(16)),
        dn_attr::MATTER_FABRIC_ID => (OID_MATTER_FABRIC_ID, Some(16)),
        dn_attr::MATTER_NOC_CAT => (OID_MATTER_CASE_AUTH_TAG, Some(8)),
        _ => return None,
    })
}

/// `v` を大文字 16 進・幅 `width`(8 または 16)で `buf` に書き、そのスライスを返す。
fn hex_upper(v: u64, width: usize, buf: &mut [u8; 16]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, slot) in buf.iter_mut().enumerate().take(width) {
        let shift = (width - 1 - i) * 4;
        *slot = HEX[((v >> shift) & 0xf) as usize];
    }
    &buf[..width]
}

/// DN リスト(issuer / subject)を X.509 Name(`RDNSequence`)として符号化する。
fn encode_dn(w: &mut DerWriter<'_>, dn: &DnList<'_>) -> Result<()> {
    w.start_seq()?;
    for attr in dn.iter() {
        let attr = attr?;
        let (oid, int_width) = dn_attr_oid(attr.attr_type).ok_or(Error::Decode)?;
        w.start_set()?;
        w.start_seq()?;
        w.oid(oid)?;
        match attr.value {
            DnValue::Uint(v) => {
                let width = int_width.ok_or(Error::Decode)?;
                let mut buf = [0u8; 16];
                w.utf8_string(hex_upper(v, usize::from(width), &mut buf))?;
            }
            DnValue::Str(s) => {
                if attr.printable {
                    w.printable_string(s.as_bytes())?;
                } else {
                    w.utf8_string(s.as_bytes())?;
                }
            }
        }
        w.end_container()?; // SEQUENCE
        w.end_container()?; // SET
    }
    w.end_container()?; // SEQUENCE(RDNSequence)
    Ok(())
}

/// Matter epoch 秒 `matter_secs` を UTCTime / GeneralizedTime として符号化する。
///
/// RFC 5280 に従い 2050 年未満は UTCTime(`YYMMDDHHMMSSZ`)、以降は
/// GeneralizedTime(`YYYYMMDDHHMMSSZ`)を用いる。
fn encode_time(w: &mut DerWriter<'_>, matter_secs: u64) -> Result<()> {
    let unix = MATTER_EPOCH_SECS + matter_secs;
    let (year, month, day, hour, minute, second) = civil_from_unix(unix);

    /// 2 桁ゼロ詰め 10 進を書く。
    fn two(buf: &mut [u8], at: usize, v: u32) {
        buf[at] = b'0' + (v / 10) as u8;
        buf[at + 1] = b'0' + (v % 10) as u8;
    }

    if year >= 2050 {
        // GeneralizedTime: YYYYMMDDHHMMSSZ(15 バイト)。
        let mut b = [0u8; 15];
        two(&mut b, 0, (year / 100) as u32);
        two(&mut b, 2, (year % 100) as u32);
        two(&mut b, 4, u32::from(month));
        two(&mut b, 6, u32::from(day));
        two(&mut b, 8, u32::from(hour));
        two(&mut b, 10, u32::from(minute));
        two(&mut b, 12, u32::from(second));
        b[14] = b'Z';
        w.time(0x18, &b)
    } else {
        // UTCTime: YYMMDDHHMMSSZ(13 バイト)。
        let mut b = [0u8; 13];
        two(&mut b, 0, (year % 100) as u32);
        two(&mut b, 2, u32::from(month));
        two(&mut b, 4, u32::from(day));
        two(&mut b, 6, u32::from(hour));
        two(&mut b, 8, u32::from(minute));
        two(&mut b, 10, u32::from(second));
        b[12] = b'Z';
        w.time(0x17, &b)
    }
}

/// Unix 秒 → (年, 月, 日, 時, 分, 秒)。閏年・グレゴリオ暦対応
/// (Howard Hinnant の civil_from_days アルゴリズム)。
fn civil_from_unix(secs: u64) -> (i64, u8, u8, u8, u8, u8) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = (rem / 3600) as u8;
    let minute = ((rem % 3600) / 60) as u8;
    let second = (rem % 60) as u8;

    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    let year = y + i64::from(month <= 2);
    (year, month, day, hour, minute, second)
}

/// 拡張リストを X.509 extensions(`[3] { SEQUENCE OF Extension }`)として符号化する。
///
/// 符号化順序は Matter TLV の正準順(basic-constraints, key-usage, ext-key-usage,
/// subject-key-id, authority-key-id, future-extensions)に一致させる。
fn encode_extensions(w: &mut DerWriter<'_>, ext: &Extensions<'_>) -> Result<()> {
    w.start_ctx(3)?;
    w.start_seq()?;

    if let Some(bc) = ext.basic_constraints {
        w.start_seq()?;
        w.oid(&OID_BASIC_CONSTRAINTS)?;
        w.boolean(true)?; // critical
        w.start_octet_string()?;
        w.start_seq()?;
        if bc.is_ca {
            w.boolean(true)?;
        }
        if let Some(p) = bc.path_len_constraint {
            w.integer(&[p])?;
        }
        w.end_container()?; // SEQUENCE
        w.end_container()?; // OCTET STRING
        w.end_container()?; // Extension SEQUENCE
    }

    if let Some(ku) = ext.key_usage {
        w.start_seq()?;
        w.oid(&OID_KEY_USAGE)?;
        w.boolean(true)?; // critical
        w.start_octet_string()?;
        // X.509 の BIT STRING は各バイト内でビット順が反転する。
        let bits = [
            reverse_byte((ku & 0xff) as u8),
            reverse_byte((ku >> 8) as u8),
        ];
        w.bit_string(true, &bits)?;
        w.end_container()?; // OCTET STRING
        w.end_container()?; // Extension SEQUENCE
    }

    if let Some(raw) = ext.extended_key_usage {
        w.start_seq()?;
        w.oid(&OID_EXT_KEY_USAGE)?;
        w.boolean(true)?; // critical
        w.start_octet_string()?;
        w.start_seq()?;
        let mut r = TlvReader::new(raw);
        r.read_next()?; // array 開始トークン(context tag 3)を消費。
        loop {
            let elem = r.read_next()?.ok_or(Error::Decode)?;
            if elem.value == TlvValue::ContainerEnd {
                break;
            }
            let purpose = match elem.value {
                TlvValue::UnsignedInteger(v) => u8::try_from(v).map_err(|_| Error::Decode)?,
                _ => return Err(Error::Decode),
            };
            w.oid(eku_oid(purpose)?)?;
        }
        w.end_container()?; // SEQUENCE
        w.end_container()?; // OCTET STRING
        w.end_container()?; // Extension SEQUENCE
    }

    if let Some(skid) = ext.subject_key_id {
        w.start_seq()?;
        w.oid(&OID_SUBJECT_KEY_ID)?;
        // 非 critical。
        w.start_octet_string()?;
        w.octet_string(skid)?;
        w.end_container()?; // OCTET STRING
        w.end_container()?; // Extension SEQUENCE
    }

    if let Some(akid) = ext.authority_key_id {
        w.start_seq()?;
        w.oid(&OID_AUTHORITY_KEY_ID)?;
        // 非 critical。
        w.start_octet_string()?;
        w.start_seq()?;
        w.ctx_primitive(0, akid)?; // [0] keyIdentifier
        w.end_container()?; // SEQUENCE
        w.end_container()?; // OCTET STRING
        w.end_container()?; // Extension SEQUENCE
    }

    if let Some(fe) = ext.future_extensions {
        // future-extensions は DER 符号化済みの X.509 Extension をそのまま格納する。
        w.raw(fe)?;
    }

    w.end_container()?; // SEQUENCE OF Extension
    w.end_container()?; // [3]
    Ok(())
}

/// extended-key-usage の purpose 値(1..=6)に対応する OID を返す。
fn eku_oid(purpose: u8) -> Result<&'static [u8]> {
    Ok(match purpose {
        ext_key_usage::SERVER_AUTH => &OID_EKU_SERVER_AUTH,
        ext_key_usage::CLIENT_AUTH => &OID_EKU_CLIENT_AUTH,
        ext_key_usage::CODE_SIGNING => &OID_EKU_CODE_SIGNING,
        ext_key_usage::EMAIL_PROTECTION => &OID_EKU_EMAIL_PROTECTION,
        ext_key_usage::TIME_STAMPING => &OID_EKU_TIME_STAMPING,
        ext_key_usage::OCSP_SIGNING => &OID_EKU_OCSP_SIGNING,
        _ => return Err(Error::Decode),
    })
}

/// バイト内のビット順を反転する(X.509 KeyUsage BIT STRING 用)。
fn reverse_byte(byte: u8) -> u8 {
    const LOOKUP: [u8; 16] = [
        0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07,
        0x0f,
    ];
    (LOOKUP[(byte & 0x0f) as usize] << 4) | LOOKUP[(byte >> 4) as usize]
}

/// 拡張リスト要素(`&cert[..]` の部分スライス)をパースする。
fn parse_extensions(raw: &[u8]) -> Result<Extensions<'_>> {
    let mut r = TlvReader::new(raw);
    let head = r.read_next()?.ok_or(Error::Decode)?;
    // extensions は list。
    if head.value.as_container()? != ContainerType::List {
        return Err(Error::Decode);
    }

    let mut basic_constraints = None;
    let mut key_usage = None;
    let mut extended_key_usage = None;
    let mut subject_key_id = None;
    let mut authority_key_id = None;
    let mut future_extensions = None;

    loop {
        let pos = r.position();
        let elem = r.read_next()?.ok_or(Error::Decode)?;
        if elem.value == TlvValue::ContainerEnd {
            break;
        }
        let ctx = match elem.tag {
            TlvTag::ContextSpecific(c) => c,
            _ => return Err(Error::Decode),
        };
        match ctx {
            EXT_BASIC_CONSTRAINTS => {
                if elem.value.as_container()? != ContainerType::Structure {
                    return Err(Error::Decode);
                }
                basic_constraints = Some(parse_basic_constraints(&mut r)?);
            }
            EXT_KEY_USAGE => {
                key_usage =
                    Some(u16::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
            }
            EXT_EXTENDED_KEY_USAGE => {
                if elem.value.as_container()? != ContainerType::Array {
                    return Err(Error::Decode);
                }
                r.exit_container()?;
                extended_key_usage = Some(&raw[pos..r.position()]);
            }
            EXT_SUBJECT_KEY_ID => subject_key_id = Some(elem.value.as_bytes()?),
            EXT_AUTHORITY_KEY_ID => authority_key_id = Some(elem.value.as_bytes()?),
            EXT_FUTURE_EXTENSIONS => future_extensions = Some(elem.value.as_bytes()?),
            _ => r.skip(&elem)?,
        }
    }

    Ok(Extensions {
        basic_constraints,
        key_usage,
        extended_key_usage,
        subject_key_id,
        authority_key_id,
        future_extensions,
    })
}

/// basic-constraints 構造体の中身(既に struct 開始を消費済み)をパースする。
fn parse_basic_constraints(r: &mut TlvReader<'_>) -> Result<BasicConstraints> {
    let mut is_ca = false;
    let mut path_len_constraint = None;
    loop {
        let elem = r.read_next()?.ok_or(Error::Decode)?;
        if elem.value == TlvValue::ContainerEnd {
            break;
        }
        let ctx = match elem.tag {
            TlvTag::ContextSpecific(c) => c,
            _ => return Err(Error::Decode),
        };
        match ctx {
            BC_IS_CA => is_ca = elem.value.as_bool()?,
            BC_PATH_LEN => {
                path_len_constraint =
                    Some(u8::try_from(elem.value.as_unsigned()?).map_err(|_| Error::Decode)?);
            }
            _ => r.skip(&elem)?,
        }
    }
    Ok(BasicConstraints {
        is_ca,
        path_len_constraint,
    })
}

/// NOC → (ICAC) → RCAC の運用証明書チェーンを検証する。
///
/// 検証項目:
/// 1. 各証明書の種別(NOC / ICAC / RCAC)が期待どおりか。
/// 2. 各証明書が `now`(Matter epoch 秒)の時点で有効期間内か。
/// 3. 各証明書の基本制約・鍵用途ポリシ([`MatterCert::verify_usage`])。
/// 4. fabric-id の整合性(NOC は subject に fabric-id を持つ必要があり、ICAC/RCAC が
///    fabric-id を持つ場合は NOC のものと一致すること)。
/// 5. authority-key-id が発行者の subject-key-id と一致すること。
/// 6. 各リンクの署名(子の TBS を親の公開鍵で検証)。RCAC は自己署名。
///
/// いずれかの検査に失敗した場合、意味的な失敗は [`Error::CertInvalid`]、署名検証の
/// 失敗は [`Error::Crypto`]、TLV の不正は [`Error::Decode`] を返す。panic しない。
pub fn verify_chain<C: Crypto>(
    crypto: &C,
    noc: &MatterCert<'_>,
    icac: Option<&MatterCert<'_>>,
    rcac: &MatterCert<'_>,
    now: u32,
) -> Result<()> {
    // 1. 種別。
    if noc.cert_type()? != CertType::Noc {
        return Err(Error::CertInvalid);
    }
    if let Some(ic) = icac {
        if ic.cert_type()? != CertType::Icac {
            return Err(Error::CertInvalid);
        }
    }
    if rcac.cert_type()? != CertType::Rcac {
        return Err(Error::CertInvalid);
    }
    if !rcac.is_self_signed()? {
        return Err(Error::CertInvalid);
    }

    // 2. 有効期間。
    noc.check_validity(now)?;
    if let Some(ic) = icac {
        ic.check_validity(now)?;
    }
    rcac.check_validity(now)?;

    // 3. 基本制約・鍵用途ポリシ。RCAC の深さは ICAC の有無で変わる。
    noc.verify_usage(CertType::Noc, 0)?;
    let rcac_depth = if let Some(ic) = icac {
        ic.verify_usage(CertType::Icac, 1)?;
        2
    } else {
        1
    };
    rcac.verify_usage(CertType::Rcac, rcac_depth)?;

    // 4. fabric-id 整合性。
    let fabric_id = noc.subject.fabric_id()?.ok_or(Error::CertInvalid)?;
    if let Some(ic) = icac {
        if let Some(f) = ic.subject.fabric_id()? {
            if f != fabric_id {
                return Err(Error::CertInvalid);
            }
        }
    }
    if let Some(f) = rcac.subject.fabric_id()? {
        if f != fabric_id {
            return Err(Error::CertInvalid);
        }
    }

    // 5/6. authority 連鎖と署名。
    let noc_parent = icac.unwrap_or(rcac);
    verify_link(crypto, noc, noc_parent)?;
    if let Some(ic) = icac {
        verify_link(crypto, ic, rcac)?;
    }
    verify_link(crypto, rcac, rcac)?;

    Ok(())
}

/// `child` の authority-key-id が `parent` の subject-key-id と一致し、かつ
/// `child` の署名が `parent` の公開鍵で検証できることを確認する。
fn verify_link<C: Crypto>(
    crypto: &C,
    child: &MatterCert<'_>,
    parent: &MatterCert<'_>,
) -> Result<()> {
    let akid = child
        .extensions
        .authority_key_id
        .ok_or(Error::CertInvalid)?;
    let skid = parent.extensions.subject_key_id.ok_or(Error::CertInvalid)?;
    if akid != skid {
        return Err(Error::CertInvalid);
    }
    child.verify_signature(crypto, parent.public_key)
}

// ---------------------------------------------------------------------------
// PKCS#10 CSR(NOCSR)構築
// ---------------------------------------------------------------------------

/// CSR DER の最大バイト数(P-256 の空 subject CSR は約 250 バイト)。
pub const MAX_CSR_DER_LEN: usize = 320;

/// 運用鍵ペア `keypair` に対する PKCS#10 CertificationRequest(CSR)を DER で `out` に
/// 構築し、書き込んだバイト数を返す。
///
/// Matter の CSRRequest(Core Spec §11.17.5.6)が返す NOCSRElements の `csr` フィールドは、
/// 新規に生成した運用鍵ペアの公開鍵を含む PKCS#10 CSR(RFC 2986)で、その運用秘密鍵で
/// 自己署名される(所有証明)。subject は空 Name、attributes は空とする(chip
/// `NewNodeOperationalX509Cert` / rs-matter の CSR 構築と同様、運用 CSR に DN は不要)。
///
/// 署名は ECDSA-with-SHA256 で、生 `r||s`(64 バイト)を DER `SEQUENCE { INTEGER r,
/// INTEGER s }` へ変換して BIT STRING に格納する。`out` は [`MAX_CSR_DER_LEN`] 以上が望ましい。
/// 容量不足は [`Error::NoSpace`]。
pub fn write_csr<K: P256Keypair>(keypair: &K, out: &mut [u8]) -> Result<usize> {
    let pubkey = keypair.public_key().to_bytes();

    // 1. CertificationRequestInfo を独立バッファへ DER 化する(署名対象)。
    let mut cri = [0u8; 220];
    let cri_len = {
        let mut w = DerWriter::new(&mut cri);
        write_cert_req_info(&mut w, &pubkey)?;
        w.len()
    };

    // 2. 運用秘密鍵で署名する(内部で SHA-256)。
    let mut raw_sig = [0u8; P256_SIGNATURE_LEN];
    keypair.sign(&cri[..cri_len], &mut raw_sig)?;

    // 3. 生 r||s を DER ECDSA-Sig-Value に変換する。
    let mut der_sig = [0u8; 80];
    let der_sig_len = ecdsa_raw_to_der(&raw_sig, &mut der_sig)?;

    // 4. CertificationRequest 全体を組む。
    let mut w = DerWriter::new(out);
    w.start_seq()?; // CertificationRequest
    w.raw(&cri[..cri_len])?; // certificationRequestInfo
    w.start_seq()?; // signatureAlgorithm
    w.oid(&OID_ECDSA_WITH_SHA256)?;
    w.end_container()?;
    w.bit_string(false, &der_sig[..der_sig_len])?; // signature
    w.end_container()?;
    Ok(w.len())
}

/// CertificationRequestInfo(空 subject / 空 attributes / EC P-256 公開鍵)を DER 化する。
fn write_cert_req_info(w: &mut DerWriter<'_>, pubkey: &[u8; P256_PUBLIC_KEY_LEN]) -> Result<()> {
    w.start_seq()?; // CertificationRequestInfo
    w.integer(&[0x00])?; // version = 0
    w.start_seq()?; // subject = 空 RDNSequence
    w.end_container()?;
    w.start_seq()?; // subjectPKInfo
    w.start_seq()?; // algorithm
    w.oid(&OID_EC_PUBLIC_KEY)?;
    w.oid(&OID_PRIME256V1)?;
    w.end_container()?;
    w.bit_string(false, pubkey)?; // subjectPublicKey
    w.end_container()?;
    w.start_ctx(0)?; // attributes [0] = 空
    w.end_container()?;
    w.end_container()?;
    Ok(())
}

/// 生 ECDSA 署名 `r||s`(64 バイト)を DER `SEQUENCE { INTEGER r, INTEGER s }` へ変換する。
fn ecdsa_raw_to_der(raw: &[u8; P256_SIGNATURE_LEN], out: &mut [u8]) -> Result<usize> {
    let mut w = DerWriter::new(out);
    w.start_seq()?;
    der_uint(&mut w, &raw[..32])?;
    der_uint(&mut w, &raw[32..])?;
    w.end_container()?;
    Ok(w.len())
}

/// ビッグエンディアン整数 `be` を DER INTEGER として書く(先頭 0 除去 + 符号ビット対策)。
fn der_uint(w: &mut DerWriter<'_>, be: &[u8]) -> Result<()> {
    let mut i = 0;
    while i + 1 < be.len() && be[i] == 0 {
        i += 1;
    }
    let v = &be[i..];
    if v[0] & 0x80 != 0 {
        // 最上位ビットが立つと負とみなされるため 0x00 を前置する。
        let mut tmp = [0u8; 33];
        tmp[1..1 + v.len()].copy_from_slice(v);
        w.integer(&tmp[..1 + v.len()])
    } else {
        w.integer(v)
    }
}

#[cfg(test)]
mod tests;
