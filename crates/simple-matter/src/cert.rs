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
//! ヒープを確保しない。DN リスト・拡張・TBS(to-be-signed)範囲はいずれも入力
//! バッファへの部分スライスとして保持する。
//!
//! # パースと暗号 backend の分離
//!
//! パース([`MatterCert::parse`])は暗号 backend に依存せず、`tlv` / `error` のみに
//! 依存する(`--no-default-features` でも動く)。署名検証([`MatterCert::verify_signature`])
//! とチェーン検証([`verify_chain`])のみが [`Crypto`] にジェネリックである。
//!
//! # 署名対象(TBS)についての設計判断
//!
//! Matter 仕様準拠の完全な実装では、証明書署名は TLV を X.509 **DER** に再エンコード
//! した TBSCertificate に対して計算される。本タスクのスコープ(`docs/ARCHITECTURE.md`
//! ロードマップ第4段階前半)では DER 変換系 crate を持ち込まない方針のため、
//! 本モジュールは署名対象を **証明書 TLV の署名フィールド直前までのバイト列**
//! ([`MatterCert::to_be_signed`])と定義する自己完結スキームを採る。
//! DER ベースの署名検証(実 Matter コントローラとの相互運用)は DAC/CSR 段階での
//! DER サポート導入時に差し替える。この差し替えでパース・チェーン走査ロジックは
//! 変わらず、TBS 範囲の定義のみが変わる。

use crate::crypto::{Crypto, P256PublicKey, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN};
use crate::error::{Error, Result};
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue};

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
    tbs: &'a [u8],
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
        let mut tbs = None;

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
                    // 署名フィールド開始位置までが署名対象(TBS)。
                    tbs = Some(&cert[..pos]);
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
            tbs: tbs.ok_or(Error::Decode)?,
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

    /// 署名対象(to-be-signed)バイト列。
    ///
    /// 本モジュールの自己完結スキームでは、証明書 TLV の署名フィールド直前までの
    /// バイト列(struct 開始バイトを含む prefix)を指す。モジュールドキュメント参照。
    pub fn to_be_signed(&self) -> &'a [u8] {
        self.tbs
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
        let key = crypto.p256_public_key_from_bytes(issuer_public_key)?;
        if key.verify(self.tbs, sig)? {
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

#[cfg(test)]
mod tests;
