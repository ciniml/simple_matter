//! Matter 仕様 §3.10 の SPAKE2+(P-256 / SHA-256 / HKDF-SHA256 版)の
//! **デバイス側(verifier / responder)** に必要なプリミティブ。
//!
//! PASE(Passcode-Authenticated Session Establishment)の前提部品であり、本モジュールは
//! 暗号演算のみを提供する。PASE プロトコル自体(メッセージ形式・TLV・状態遷移)は
//! スコープ外で、上位の `sc::pase` 層が組み立てる。
//!
//! # 設計上の位置づけ(独立モジュールとした判断)
//!
//! [`crate::crypto::Crypto`] トレイトは「暗号境界は 1 点・抽象は薄く保つ」
//! (`docs/ARCHITECTURE.md` 設計原則 4/9)方針により、SHA-256/HMAC/HKDF/AES-CCM/
//! P-256(ECDH/ECDSA/鍵生成)のみを公開し、楕円曲線の**低レベル算術**(スカラの
//! mod n 還元・点の加算/スカラ倍/反転・生成元)は意図的に露出していない。
//! SPAKE2+ はこれらの低レベル算術を必要とし、かつ P-256 固有で低頻度(コミッショニング
//! 時のみ)のパスである。そのためトレイトを肥大化させず、`rustcrypto` バックエンドと
//! 同様に `p256` / `sha2` / `hmac` / `hkdf` を直接用いる**独立モジュール**として実装する。
//! したがって本モジュールは `rustcrypto` feature でのみ有効化される。
//!
//! # no_std / ヒープ
//!
//! すべて固定長配列とスタック上の演算で完結し、ヒープを確保しない。PBKDF2 は
//! 既存の `hmac` 依存のみで自前実装する(新規 crate を追加しない判断)。スカラの
//! mod n 還元は `p256` のスカラ体上の Horner 法で行い、`crypto-bigint` を直接依存に
//! 加えない。
//!
//! # ゼロ化
//!
//! 中間秘密(w0s/w1s、Ka)は使用後に [`zeroize`] で消去する。`p256::Scalar` は
//! Drop 時に自身をゼロ化するため、スカラ中間値の明示的な消去は行わない。
//!
//! # 失敗時の扱い
//!
//! 不正入力(曲線外の点・不正なスカラ・長さ不正)では panic せず
//! [`crate::Error::Crypto`] を返す。相手の共有点 `pA` は使用前に曲線上の正当な点かを
//! 検証する(RFC 9383 §4)。

use hmac::{Mac, SimpleHmac};
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Group;
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::Rng;
use crate::error::{Error, Result};

/// P-256 のスカラ長(w0/w1、バイト)。
pub const SPAKE2P_SCALAR_LEN: usize = 32;

/// P-256 の点の長さ(SEC1 非圧縮 `0x04 || X || Y`、バイト)。pA/pB/L の長さ。
pub const SPAKE2P_POINT_LEN: usize = 65;

/// SPAKE2+ の PBKDF2 中間値 w0s / w1s 各々の長さ(バイト)。
///
/// Matter 仕様の `CRYPTO_W_SIZE_BYTES = CRYPTO_GROUP_SIZE_BYTES + 8 = 40`。
pub const SPAKE2P_W_LEN: usize = 40;

/// 共有鍵 Ke の長さ(バイト)。
pub const SPAKE2P_KE_LEN: usize = 16;

/// 確認値 cA / cB(HMAC-SHA256)の長さ(バイト)。
pub const SPAKE2P_CONFIRMATION_LEN: usize = 32;

/// Matter のコミッショニング用コンテキスト接頭辞。
///
/// PASE 層はトランスクリプトのコンテキストを
/// `SHA256("CHIP PAKE V1 Commissioning" || PBKDFParamRequest || PBKDFParamResponse)` として
/// 構成し、その 32 バイトハッシュを本モジュールの `context` として渡す。コンテキストの
/// 構成自体は PASE 層(スコープ外)の責務であり、本定数はその接頭辞を提供するのみ。
pub const SPAKE2P_CONTEXT_PREFIX: &[u8] = b"CHIP PAKE V1 Commissioning";

/// 確認鍵導出に用いる HKDF info 文字列。
const KEY_CONFIRM_INFO: &[u8] = b"ConfirmationKeys";

/// Matter 仕様が定める固定点 M(SEC1 非圧縮)。
const MATTER_M: [u8; SPAKE2P_POINT_LEN] = [
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d,
    0x20,
];

/// Matter 仕様が定める固定点 N(SEC1 非圧縮)。
const MATTER_N: [u8; SPAKE2P_POINT_LEN] = [
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb,
    0xe7,
];

/// HMAC-SHA256 の具体型(可変長鍵を扱うため `SimpleHmac` を用いる)。
type HmacSha256 = SimpleHmac<Sha256>;

/// デバイスが保持する SPAKE2+ の検証子 (w0, L)。
///
/// デバイスはパスコード・salt・iteration count から本値を一度だけ導出して保管し、
/// PASE ハンドシェイクのたびに用いる(パスコード自体は保持しなくてよい)。
#[derive(Clone)]
pub struct Spake2pVerifierParams {
    /// スカラ w0(= w0s mod n)。ビッグエンディアン 32 バイト。
    pub w0: [u8; SPAKE2P_SCALAR_LEN],
    /// 点 L(= w1 * P)。SEC1 非圧縮 65 バイト。
    pub l: [u8; SPAKE2P_POINT_LEN],
}

/// パスコード・salt・iteration count からデバイスの検証子 (w0, L) を導出する。
///
/// 手順(Matter 仕様 §3.10):
/// 1. `w0s || w1s = PBKDF2-HMAC-SHA256(passcode_le, salt, iterations, 2 * 40 バイト)`
/// 2. `w0 = w0s mod n`, `w1 = w1s mod n`(n は P-256 の群位数)
/// 3. `L = w1 * P`
///
/// `passcode` は仕様どおり 4 バイトリトルエンディアンとして PBKDF2 に投入する。
///
/// # 失敗
/// `iterations` が 0 の場合や salt が不正な場合など、導出に失敗すると
/// [`Error::Crypto`] を返す(panic しない)。
pub fn compute_verifier(
    passcode: u32,
    salt: &[u8],
    iterations: u32,
) -> Result<Spake2pVerifierParams> {
    let (w0_scalar, w1_scalar) = compute_w0_w1(passcode, salt, iterations)?;

    let mut w0 = [0u8; SPAKE2P_SCALAR_LEN];
    w0.copy_from_slice(&w0_scalar.to_repr());

    let l_pt = ProjectivePoint::GENERATOR * w1_scalar;
    let l = encode_point(&l_pt)?;

    Ok(Spake2pVerifierParams { w0, l })
}

/// パスコードから w0・w1 のスカラを導出する(検証・テスト用の下位関数)。
fn compute_w0_w1(passcode: u32, salt: &[u8], iterations: u32) -> Result<(Scalar, Scalar)> {
    if iterations == 0 {
        return Err(Error::Crypto);
    }

    // w0s || w1s(各 40 バイト)を PBKDF2 で導出する。
    let mut w0s_w1s = Zeroizing::new([0u8; SPAKE2P_W_LEN * 2]);
    pbkdf2_hmac_sha256(&passcode.to_le_bytes(), salt, iterations, &mut w0s_w1s[..])?;

    let w0 = scalar_from_wide_be(&w0s_w1s[..SPAKE2P_W_LEN]);
    let w1 = scalar_from_wide_be(&w0s_w1s[SPAKE2P_W_LEN..]);

    Ok((w0, w1))
}

/// SPAKE2+ verifier(responder)側のステートフルなハンドシェイク状態。
///
/// 相手(prover)の共有点 `pA` を受けて `pB` を計算し、トランスクリプトから
/// Ke・cA・cB を導出して保持する。cA の検証に成功するまで共有鍵 Ke は確定利用しない。
///
/// 典型的な流れ:
/// 1. [`Spake2pVerifier::respond`] に `pA` を渡し `pB` を得て相手へ送る。
/// 2. [`Spake2pVerifier::confirmation_b`](cB)を相手へ送る。
/// 3. 相手から受信した cA を [`Spake2pVerifier::verify`] で検証する。
/// 4. 検証成功後、[`Spake2pVerifier::shared_secret`] で Ke を取り出しセッション鍵に用いる。
pub struct Spake2pVerifier {
    ke: Zeroizing<[u8; SPAKE2P_KE_LEN]>,
    ca: [u8; SPAKE2P_CONFIRMATION_LEN],
    cb: [u8; SPAKE2P_CONFIRMATION_LEN],
}

impl Spake2pVerifier {
    /// prover の共有点 `pA` を受けて verifier 側の計算を実行し、`pB` を返す。
    ///
    /// 乱数スカラ y を `rng` から生成し、`pB = y*P + w0*N` を計算する。続いて
    /// `Z = y*(pA - w0*M)`・`V = y*L` を求め、トランスクリプト TT から Ke・cA・cB を
    /// 導出して内部に保持する。識別子(prover/verifier identity)は Matter 仕様に従い
    /// 空とする。
    ///
    /// # 引数
    /// - `rng`: 乱数生成器(y の生成に用いる)。
    /// - `context`: トランスクリプトのコンテキスト(Matter では 32 バイトのコンテキスト
    ///   ハッシュ。PASE 層が構成する)。
    /// - `params`: デバイスの検証子 (w0, L)。
    /// - `pa`: prover の共有点 `pA`(SEC1 非圧縮 65 バイト)。
    ///
    /// # 戻り値
    /// verifier の共有点 `pB`(65 バイト)。cB は [`Spake2pVerifier::confirmation_b`] で得る。
    ///
    /// # 失敗
    /// `pA` が曲線上にない・無限遠点である等の不正な場合、または内部演算に失敗した場合は
    /// [`Error::Crypto`] を返す(panic しない)。
    pub fn respond<R: Rng>(
        rng: &mut R,
        context: &[u8],
        params: &Spake2pVerifierParams,
        pa: &[u8; SPAKE2P_POINT_LEN],
    ) -> Result<(Self, [u8; SPAKE2P_POINT_LEN])> {
        let y = generate_scalar(rng)?;
        Self::respond_with_scalar(context, &[], &[], params, pa, &y)
    }

    /// 識別子と乱数スカラ y を明示的に指定して verifier 計算を行う下位関数。
    ///
    /// 既知テストベクタ(識別子や y が固定)の検証と、[`Spake2pVerifier::respond`] からの
    /// 呼び出しの双方に用いる。
    fn respond_with_scalar(
        context: &[u8],
        prover_identity: &[u8],
        verifier_identity: &[u8],
        params: &Spake2pVerifierParams,
        pa: &[u8; SPAKE2P_POINT_LEN],
        y: &Scalar,
    ) -> Result<(Self, [u8; SPAKE2P_POINT_LEN])> {
        // RFC 9383 §4: prover の共有点 pA を使用前に検証する。曲線外・無限遠点は拒否。
        let pa_pt = decode_valid_point(pa)?;

        let w0 = scalar_from_repr(&params.w0)?;
        let l_pt = decode_valid_point(&params.l)?;
        let m_pt = decode_valid_point(&MATTER_M)?;
        let n_pt = decode_valid_point(&MATTER_N)?;

        // pB = y*P + w0*N
        let pb_pt = ProjectivePoint::GENERATOR * y + n_pt * w0;
        let pb = encode_point(&pb_pt)?;

        // Z = y*(pA - w0*M),  V = y*L
        let z_pt = (pa_pt - m_pt * w0) * y;
        let v_pt = l_pt * y;
        let z = encode_point(&z_pt)?;
        let v = encode_point(&v_pt)?;

        // トランスクリプト TT を構成し、その SHA-256 を計算する。
        let mut tt = Sha256::new();
        tt_add(&mut tt, context);
        tt_add(&mut tt, prover_identity);
        tt_add(&mut tt, verifier_identity);
        tt_add(&mut tt, &MATTER_M);
        tt_add(&mut tt, &MATTER_N);
        tt_add(&mut tt, pa);
        tt_add(&mut tt, &pb);
        tt_add(&mut tt, &z);
        tt_add(&mut tt, &v);
        tt_add(&mut tt, &params.w0);
        let tt_hash: [u8; 32] = tt.finalize().into();

        // Ka || Ke = TT(前半 16 バイトが Ka、後半 16 バイトが Ke)。
        let mut ka = Zeroizing::new([0u8; 16]);
        ka.copy_from_slice(&tt_hash[..16]);
        let mut ke = Zeroizing::new([0u8; SPAKE2P_KE_LEN]);
        ke.copy_from_slice(&tt_hash[16..]);

        // KcA || KcB = HKDF(salt=nil, IKM=Ka, info="ConfirmationKeys")。
        let mut kca_kcb = Zeroizing::new([0u8; 32]);
        hkdf_sha256(&[], &ka[..], KEY_CONFIRM_INFO, &mut kca_kcb[..])?;

        // cA = HMAC(KcA, pB),  cB = HMAC(KcB, pA)。
        let mut ca = [0u8; SPAKE2P_CONFIRMATION_LEN];
        hmac_sha256(&kca_kcb[..16], &pb, &mut ca)?;
        let mut cb = [0u8; SPAKE2P_CONFIRMATION_LEN];
        hmac_sha256(&kca_kcb[16..], pa, &mut cb)?;

        Ok((Self { ke, ca, cb }, pb))
    }

    /// prover へ送る確認値 cB(= HMAC(KcB, pA))を返す。
    pub fn confirmation_b(&self) -> &[u8; SPAKE2P_CONFIRMATION_LEN] {
        &self.cb
    }

    /// prover から受信した確認値 cA を定数時間で照合する。
    ///
    /// 一致すれば `Ok(())`、不一致なら [`Error::Crypto`] を返す(パスコード不一致を含む)。
    /// 検証成功後にのみ [`Spake2pVerifier::shared_secret`] を利用してよい。
    pub fn verify(&self, ca: &[u8; SPAKE2P_CONFIRMATION_LEN]) -> Result<()> {
        if self.ca.ct_eq(ca).into() {
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }

    /// 導出された共有鍵 Ke(16 バイト)を返す。
    ///
    /// [`Spake2pVerifier::verify`] が成功した後にのみ用いること。
    pub fn shared_secret(&self) -> &[u8; SPAKE2P_KE_LEN] {
        &self.ke
    }
}

/// SPAKE2+ prover(commissioner / initiator)側の演算。
///
/// デバイス(responder)実装の対向として、コミッショナ側の pA 生成と
/// cA / Ke 導出を提供する。本体は責務外(sc 層はデバイス側のみ)だが、PASE
/// フルハンドシェイクの結合テストやコントローラ用途のために対称なプリミティブを
/// 同一モジュール(楕円曲線算術が集約された箇所)に置く。
///
/// 典型的な流れ:
/// 1. [`Spake2pProver::from_passcode`] でパスコードから prover を作り、`pA` を得て送る。
/// 2. responder の `pB` を [`Spake2pProver::confirm`] に渡し確認値を計算する。
/// 3. [`Spake2pProverConfirm::confirmation_a`](cA)を送り、
///    [`Spake2pProverConfirm::verify_b`] で cB を検証する。
/// 4. [`Spake2pProverConfirm::shared_secret`](Ke)をセッション鍵に用いる。
pub struct Spake2pProver {
    w0: Scalar,
    w1: Scalar,
    x: Scalar,
    pa: [u8; SPAKE2P_POINT_LEN],
}

impl Spake2pProver {
    /// パスコード・salt・iteration count と乱数スカラ x から prover を構築する。
    ///
    /// `pA = x*P + w0*M` を計算して内部に保持する。
    ///
    /// # 失敗
    /// PBKDF2 導出や点算術に失敗した場合は [`Error::Crypto`] を返す(panic しない)。
    pub fn from_passcode<R: Rng>(
        rng: &mut R,
        passcode: u32,
        salt: &[u8],
        iterations: u32,
    ) -> Result<Self> {
        let (w0, w1) = compute_w0_w1(passcode, salt, iterations)?;
        let x = generate_scalar(rng)?;
        let m_pt = decode_valid_point(&MATTER_M)?;
        let pa_pt = ProjectivePoint::GENERATOR * x + m_pt * w0;
        let pa = encode_point(&pa_pt)?;
        Ok(Self { w0, w1, x, pa })
    }

    /// prover の共有点 `pA`(SEC1 非圧縮 65 バイト)を返す。
    pub fn share(&self) -> &[u8; SPAKE2P_POINT_LEN] {
        &self.pa
    }

    /// responder の共有点 `pB` を受けて確認値と共有鍵を導出する。
    ///
    /// `context` は verifier 側と同一のトランスクリプトコンテキスト(Matter では
    /// 32 バイトのコンテキストハッシュ)。識別子は Matter 仕様に従い空とする。
    ///
    /// # 失敗
    /// `pB` が不正な点である・内部演算に失敗した場合は [`Error::Crypto`] を返す。
    pub fn confirm(
        &self,
        context: &[u8],
        pb: &[u8; SPAKE2P_POINT_LEN],
    ) -> Result<Spake2pProverConfirm> {
        let n_pt = decode_valid_point(&MATTER_N)?;
        let pb_pt = decode_valid_point(pb)?;

        // Y* = pB - w0*N,  Z = x*Y*,  V = w1*Y*
        let y_star = pb_pt - n_pt * self.w0;
        let z_pt = y_star * self.x;
        let v_pt = y_star * self.w1;
        let z = encode_point(&z_pt)?;
        let v = encode_point(&v_pt)?;

        let mut w0_bytes = Zeroizing::new([0u8; SPAKE2P_SCALAR_LEN]);
        w0_bytes.copy_from_slice(&self.w0.to_repr());

        // TT を verifier と同一順序で構成する。
        let mut tt = Sha256::new();
        tt_add(&mut tt, context);
        tt_add(&mut tt, &[]);
        tt_add(&mut tt, &[]);
        tt_add(&mut tt, &MATTER_M);
        tt_add(&mut tt, &MATTER_N);
        tt_add(&mut tt, &self.pa);
        tt_add(&mut tt, pb);
        tt_add(&mut tt, &z);
        tt_add(&mut tt, &v);
        tt_add(&mut tt, &w0_bytes[..]);
        let tt_hash: [u8; 32] = tt.finalize().into();

        let mut ka = Zeroizing::new([0u8; 16]);
        ka.copy_from_slice(&tt_hash[..16]);
        let mut ke = Zeroizing::new([0u8; SPAKE2P_KE_LEN]);
        ke.copy_from_slice(&tt_hash[16..]);

        let mut kca_kcb = Zeroizing::new([0u8; 32]);
        hkdf_sha256(&[], &ka[..], KEY_CONFIRM_INFO, &mut kca_kcb[..])?;

        let mut ca = [0u8; SPAKE2P_CONFIRMATION_LEN];
        hmac_sha256(&kca_kcb[..16], pb, &mut ca)?;
        let mut cb = [0u8; SPAKE2P_CONFIRMATION_LEN];
        hmac_sha256(&kca_kcb[16..], &self.pa, &mut cb)?;

        Ok(Spake2pProverConfirm { ke, ca, cb })
    }
}

/// [`Spake2pProver::confirm`] の結果(確認値と共有鍵)。
pub struct Spake2pProverConfirm {
    ke: Zeroizing<[u8; SPAKE2P_KE_LEN]>,
    ca: [u8; SPAKE2P_CONFIRMATION_LEN],
    cb: [u8; SPAKE2P_CONFIRMATION_LEN],
}

impl Spake2pProverConfirm {
    /// responder へ送る確認値 cA(= HMAC(KcA, pB))を返す。
    pub fn confirmation_a(&self) -> &[u8; SPAKE2P_CONFIRMATION_LEN] {
        &self.ca
    }

    /// responder から受信した確認値 cB を定数時間で照合する。
    ///
    /// 一致すれば `Ok(())`、不一致なら [`Error::Crypto`]。
    pub fn verify_b(&self, cb: &[u8; SPAKE2P_CONFIRMATION_LEN]) -> Result<()> {
        if self.cb.ct_eq(cb).into() {
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }

    /// 導出された共有鍵 Ke(16 バイト)を返す。
    pub fn shared_secret(&self) -> &[u8; SPAKE2P_KE_LEN] {
        &self.ke
    }
}

/// トランスクリプト TT に 1 要素を追加する。
///
/// 各要素は「8 バイトリトルエンディアンの長さ || データ」として連結する
/// (Matter / RFC 9383 のエンコード)。
fn tt_add(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u64).to_le_bytes());
    if !data.is_empty() {
        hasher.update(data);
    }
}

/// 40 バイト等のビッグエンディアン整数を P-256 のスカラ体(mod n)へ還元する。
///
/// スカラ体上の Horner 法(`acc = acc*256 + byte`)で 1 バイトずつ畳み込む。
/// 各演算が mod n で行われるため、入力幅に依らず正しく `X mod n` を得る。
/// これにより `crypto-bigint` への直接依存を避ける。
fn scalar_from_wide_be(bytes: &[u8]) -> Scalar {
    let radix = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for &b in bytes {
        acc = acc * radix + Scalar::from(u64::from(b));
    }
    acc
}

/// 32 バイトビッグエンディアン表現から P-256 スカラを復元する(範囲外なら `Err`)。
fn scalar_from_repr(bytes: &[u8; SPAKE2P_SCALAR_LEN]) -> Result<Scalar> {
    let repr = p256::FieldBytes::from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(*repr)).ok_or(Error::Crypto)
}

/// SEC1 バイト列を復号し、曲線上の正当な(無限遠でない)点として検証して返す。
fn decode_valid_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Crypto)?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(Error::Crypto)?;
    let point = ProjectivePoint::from(affine);
    // 無限遠点(単位元)は正当な共有点ではないため拒否する。
    if point.is_identity().into() {
        return Err(Error::Crypto);
    }
    Ok(point)
}

/// 点を SEC1 非圧縮 65 バイトへエンコードする(無限遠点なら `Err`)。
fn encode_point(point: &ProjectivePoint) -> Result<[u8; SPAKE2P_POINT_LEN]> {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != SPAKE2P_POINT_LEN {
        // 無限遠点は 1 バイト(0x00)にエンコードされる。正常系では発生しない。
        return Err(Error::Crypto);
    }
    let mut out = [0u8; SPAKE2P_POINT_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// 乱数スカラ y ∈ [1, n-1] を生成する。
///
/// 32 バイトの乱数を mod n 還元し、0 になった場合のみ再試行する(発生確率は無視できる)。
fn generate_scalar<R: Rng>(rng: &mut R) -> Result<Scalar> {
    for _ in 0..16 {
        let mut bytes = Zeroizing::new([0u8; SPAKE2P_SCALAR_LEN]);
        rng.fill_bytes(&mut bytes[..])?;
        let s = scalar_from_wide_be(&bytes[..]);
        if !bool::from(s.is_zero()) {
            return Ok(s);
        }
    }
    Err(Error::Crypto)
}

/// HKDF-SHA256(抽出+展開)。`out` の長さぶんの鍵材料を導出する。
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).map_err(|_| Error::Crypto)
}

/// HMAC-SHA256 を計算し 32 バイトを `out` に書き込む。
fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; SPAKE2P_CONFIRMATION_LEN]) -> Result<()> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    mac.update(data);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(())
}

/// PBKDF2-HMAC-SHA256。`out` の長さぶんの鍵材料を導出する(ヒープ確保なし)。
///
/// 出力ブロックごとに `T_i = U_1 ^ U_2 ^ ... ^ U_c` を計算する。既存の `hmac` 依存のみで
/// 実装し、新規 crate を追加しない。
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    const HLEN: usize = 32;

    // 鍵は毎ブロック同一のため、初期 MAC を作って clone で使い回す。
    let base = <HmacSha256 as Mac>::new_from_slice(password).map_err(|_| Error::Crypto)?;

    for (block, chunk) in (1_u32..).zip(out.chunks_mut(HLEN)) {
        // U_1 = HMAC(password, salt || INT_BE(block))
        let mut u = {
            let mut mac = base.clone();
            mac.update(salt);
            mac.update(&block.to_be_bytes());
            let mut u = [0u8; HLEN];
            u.copy_from_slice(&mac.finalize().into_bytes());
            u
        };

        let mut t = u;

        // U_j = HMAC(password, U_{j-1}),  T ^= U_j
        for _ in 1..iterations {
            let mut mac = base.clone();
            mac.update(&u);
            u.copy_from_slice(&mac.finalize().into_bytes());
            for (t_b, u_b) in t.iter_mut().zip(u.iter()) {
                *t_b ^= *u_b;
            }
        }

        chunk.copy_from_slice(&t[..chunk.len()]);
        u.zeroize();
        t.zeroize();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用の決定的な擬似乱数生成器(xorshift64)。暗号用途ではない。
    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            for chunk in dest.chunks_mut(8) {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                let b = x.to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
            Ok(())
        }
    }

    fn from_hex_arr<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        assert_eq!(s.len(), N * 2);
        let bytes = s.as_bytes();
        for (i, o) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
        out
    }

    // ---- connectedhomeip / RFC 9383 の既知テストベクタ ----
    //
    // 出典: research/connectedhomeip/src/crypto/tests/SPAKE2P_RFC_test_vectors.h
    // (test_vector_16。rs-matter research/.../sc/pase/spake2p.rs の RFC_T[0] と同一値)。
    // context = "SPAKE2+-P256-SHA256-HKDF draft-01",
    // prover_identity = "client", verifier_identity = "server"。

    const RFC_CONTEXT: &[u8] = b"SPAKE2+-P256-SHA256-HKDF draft-01";
    const RFC_PROVER_ID: &[u8] = b"client";
    const RFC_VERIFIER_ID: &[u8] = b"server";

    fn rfc_w0() -> [u8; 32] {
        from_hex_arr("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c")
    }
    fn rfc_w1() -> [u8; 32] {
        from_hex_arr("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512")
    }
    fn rfc_l() -> [u8; 65] {
        from_hex_arr("0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9")
    }
    fn rfc_x_pub() -> [u8; 65] {
        from_hex_arr("04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e")
    }
    fn rfc_y_scalar() -> [u8; 32] {
        from_hex_arr("2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91")
    }
    fn rfc_y_pub() -> [u8; 65] {
        from_hex_arr("04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4")
    }
    fn rfc_ke() -> [u8; 16] {
        from_hex_arr("801db297654816eb4f02868129b9dc89")
    }
    fn rfc_ca() -> [u8; 32] {
        from_hex_arr("d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd")
    }
    fn rfc_cb() -> [u8; 32] {
        from_hex_arr("0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e")
    }

    fn scalar_bytes_to_scalar(b: &[u8; 32]) -> Scalar {
        scalar_from_repr(b).unwrap()
    }

    // 完全な verifier フローを既知ベクタで検証する。
    // 入力: w0, L, context, 識別子, pA(=X), y。
    // 期待: pB(=Y), cB, Ke、および cA(=MAC_KcA)の検証成功。
    #[test]
    fn rfc_vector_full_verifier_flow() {
        let params = Spake2pVerifierParams {
            w0: rfc_w0(),
            l: rfc_l(),
        };
        let y = scalar_bytes_to_scalar(&rfc_y_scalar());
        let pa = rfc_x_pub();

        let (verifier, pb) = Spake2pVerifier::respond_with_scalar(
            RFC_CONTEXT,
            RFC_PROVER_ID,
            RFC_VERIFIER_ID,
            &params,
            &pa,
            &y,
        )
        .unwrap();

        // pB は既知の Y と一致する。
        assert_eq!(pb, rfc_y_pub());
        // cB は既知の MAC_KcB と一致する。
        assert_eq!(verifier.confirmation_b(), &rfc_cb());
        // Ke は既知値と一致する。
        assert_eq!(verifier.shared_secret(), &rfc_ke());
        // 既知の cA(MAC_KcA)で検証が成功する。
        verifier.verify(&rfc_ca()).unwrap();
        // 改竄した cA は拒否される。
        let mut bad = rfc_ca();
        bad[0] ^= 0x01;
        assert_eq!(verifier.verify(&bad), Err(Error::Crypto));
    }

    // w0/w1/L 導出の各段を既知ベクタで検証する。
    // w0/w1 は RFC ベクタの既知スカラと一致し、L = w1*P も既知の L と一致する。
    #[test]
    fn rfc_vector_w0_w1_l_derivation() {
        // RFC ベクタは w0/w1 を直接与える(パスコード非依存)。ここでは
        // scalar_from_repr → L = w1*P の点算術が既知の L を再現することを確認する。
        let w1 = scalar_bytes_to_scalar(&rfc_w1());
        let l_pt = ProjectivePoint::GENERATOR * w1;
        assert_eq!(encode_point(&l_pt).unwrap(), rfc_l());

        // w0 の repr 往復が一致することも確認。
        let w0 = scalar_bytes_to_scalar(&rfc_w0());
        assert_eq!(&w0.to_repr()[..], &rfc_w0()[..]);
    }

    // PBKDF2 の既知ベクタ(chip-tool 実行時の PBKDFParamResponse 由来。
    // 出典: rs-matter research/.../sc/pase/spake2p.rs test_pbkdf2)。
    // passcode=123456, salt(16B), iterations=2000 -> w0s||w1s(80B)。
    #[test]
    fn pbkdf2_known_vector() {
        let salt: [u8; 16] = [
            0x04, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82,
            0x36, 0x00,
        ];
        let mut w0s_w1s = [0u8; SPAKE2P_W_LEN * 2];
        pbkdf2_hmac_sha256(&123456u32.to_le_bytes(), &salt, 2000, &mut w0s_w1s).unwrap();

        let expected: [u8; 80] = [
            0xc7, 0x89, 0x33, 0x9c, 0xc5, 0xeb, 0xbc, 0xf6, 0xdf, 0x04, 0xa9, 0x11, 0x11, 0x06,
            0x4c, 0x15, 0xac, 0x5a, 0xea, 0x67, 0x69, 0x9f, 0x32, 0x62, 0xcf, 0xc6, 0xe9, 0x19,
            0xe8, 0xa4, 0x0b, 0xb3, 0x42, 0xe8, 0xc6, 0x8e, 0xa9, 0x9a, 0x73, 0xe2, 0x59, 0xd1,
            0x17, 0xd8, 0xed, 0xcb, 0x72, 0x8c, 0xbf, 0x3b, 0xa9, 0x88, 0x02, 0xd8, 0x45, 0x4b,
            0xd0, 0x2d, 0xe5, 0xe4, 0x1c, 0xc3, 0xd7, 0x00, 0x03, 0x3c, 0x86, 0x20, 0x9a, 0x42,
            0x5f, 0x55, 0x96, 0x3b, 0x9f, 0x6f, 0x79, 0xef, 0xcb, 0x37,
        ];
        assert_eq!(w0s_w1s, expected);
    }

    // PBKDF2 -> compute_verifier が矛盾なく (w0, L) を導出できること(自己整合)。
    #[test]
    fn compute_verifier_self_consistent() {
        let salt: [u8; 16] = [
            0x04, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82,
            0x36, 0x00,
        ];
        let params = compute_verifier(123456, &salt, 2000).unwrap();
        // L は曲線上の正当な点として復号できる。
        decode_valid_point(&params.l).unwrap();
        // w0 は正当なスカラ表現である。
        scalar_from_repr(&params.w0).unwrap();

        // compute_w0_w1 と compute_verifier の w0 が一致する。
        let (w0, w1) = compute_w0_w1(123456, &salt, 2000).unwrap();
        assert_eq!(&w0.to_repr()[..], &params.w0[..]);
        assert_eq!(
            encode_point(&(ProjectivePoint::GENERATOR * w1)).unwrap(),
            params.l
        );
    }

    // ラウンドトリップ: respond で生成した pB を用い、正しい cA で verify が成功すること。
    // (prover 側の完全実装はスコープ外のため、RFC ベクタの cA 経路は上のテストで担保)。
    #[test]
    fn respond_generates_valid_point_and_rejects_bad_pa() {
        let params = Spake2pVerifierParams {
            w0: rfc_w0(),
            l: rfc_l(),
        };
        let mut rng = TestRng(0x0123_4567_89ab_cdef);
        let pa = rfc_x_pub();
        let (verifier, pb) = Spake2pVerifier::respond(&mut rng, RFC_CONTEXT, &params, &pa).unwrap();
        // pB は曲線上の正当な点。
        decode_valid_point(&pb).unwrap();
        // cB は 32 バイト。
        assert_eq!(verifier.confirmation_b().len(), 32);

        // 曲線外の pA(Y 座標末尾を反転)は拒否される。
        let mut bad_pa = rfc_x_pub();
        let last = bad_pa.len() - 1;
        bad_pa[last] ^= 0x01;
        assert_eq!(
            Spake2pVerifier::respond(&mut rng, RFC_CONTEXT, &params, &bad_pa).err(),
            Some(Error::Crypto)
        );
    }

    // prover(commissioner)と verifier(device)が同一パスコードから同じ Ke へ
    // 到達し、互いの確認値 cA / cB を検証できること(空識別子 = Matter モード)。
    #[test]
    fn prover_verifier_round_trip() {
        let salt: [u8; 16] = [
            0x04, 0xa1, 0xd2, 0xc6, 0x11, 0xf0, 0xbd, 0x36, 0x78, 0x67, 0x79, 0x7b, 0xfe, 0x82,
            0x36, 0x00,
        ];
        let passcode = 123456u32;
        let iterations = 2000u32;
        let context: &[u8] = b"unit-test-context-hash-32-bytes!";

        // device 側の検証子。
        let params = compute_verifier(passcode, &salt, iterations).unwrap();

        // commissioner 側 prover。pA を生成。
        let mut prover_rng = TestRng(0xdead_beef_0011_2233);
        let prover =
            Spake2pProver::from_passcode(&mut prover_rng, passcode, &salt, iterations).unwrap();
        let pa = *prover.share();

        // device 側 verifier が pB / cB を計算。
        let mut dev_rng = TestRng(0x0123_4567_89ab_cdef);
        let (verifier, pb) = Spake2pVerifier::respond(&mut dev_rng, context, &params, &pa).unwrap();

        // prover が pB を受けて cA / Ke を導出。
        let confirm = prover.confirm(context, &pb).unwrap();

        // 相互の確認値検証が成功する。
        verifier.verify(confirm.confirmation_a()).unwrap();
        confirm.verify_b(verifier.confirmation_b()).unwrap();

        // 共有鍵 Ke が一致する。
        assert_eq!(confirm.shared_secret(), verifier.shared_secret());

        // 誤ったパスコードの prover は cA 検証に失敗する。
        let mut bad_rng = TestRng(0x9999_8888_7777_6666);
        let bad_prover =
            Spake2pProver::from_passcode(&mut bad_rng, passcode + 1, &salt, iterations).unwrap();
        let bad_pa = *bad_prover.share();
        let (bad_verifier, bad_pb) =
            Spake2pVerifier::respond(&mut dev_rng, context, &params, &bad_pa).unwrap();
        let bad_confirm = bad_prover.confirm(context, &bad_pb).unwrap();
        assert_eq!(
            bad_verifier.verify(bad_confirm.confirmation_a()),
            Err(Error::Crypto)
        );
    }

    // scalar_from_wide_be が既知の還元(w < n はそのまま)を満たすこと。
    #[test]
    fn scalar_wide_reduction_identity_for_small() {
        // w0(< n)は 40 バイト表現(先頭 8 バイト 0 埋め)で還元しても同一値。
        let w0 = rfc_w0();
        let mut wide = [0u8; 40];
        wide[8..].copy_from_slice(&w0);
        let reduced = scalar_from_wide_be(&wide);
        assert_eq!(&reduced.to_repr()[..], &w0[..]);
    }

    // 不正なスカラ表現(全 0xFF は n 以上)は Err を返し panic しないこと。
    #[test]
    fn invalid_scalar_repr_errors() {
        assert_eq!(scalar_from_repr(&[0xffu8; 32]).err(), Some(Error::Crypto));
    }
}
