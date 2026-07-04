//! コントローラの CA(認証局): RCAC 自己署名・NOC 発行・IPK / fabric 識別子の管理。
//!
//! `docs/design/controller.md` §6.3 に基づく。新規 fabric 用の root 鍵ペア(RCAC)を生成し、
//! デバイス CSR の公開鍵に対して NOC を発行する。コントローラ自身の運用資格情報は実装済みの
//! [`FabricTable<C, 1>`](crate::fabric::FabricTable) を流用し(チェーン検証・CompressedFabricId・
//! operational IPK 導出を内蔵)、「自分が発行した証明書が自分の検証器を通る」ことを構築時に確認する。
//!
//! # 設計からの乖離(理由付き)
//!
//! - **`issue_noc` は `&self`(設計は `&mut self`)**。CASE initiator の creds([`FabricTable`])が
//!   `&Ca` を共有借用する間に NOC を発行できるよう、serial カウンタを [`Cell`] で内部可変にする。
//!   これにより `ControllerStack` の `ScInitiator` と `Commissioner` が同一 `Ca` を同時に共有借用
//!   できる(排他 `&mut` だと借用が衝突する)。
//! - **SKID / AKID = `SHA-256(subjectPublicKey)[..20]`**(仕様は SHA-1 が一般的)。[`Crypto`] trait は
//!   SHA-1 を持たず依存追加も禁止のため SHA-256 を切り詰める。チェーン検証は AKID==発行者 SKID の
//!   一致のみを見る([`crate::cert::verify_chain`])ため相互運用に影響しない。

use core::cell::Cell;
use core::num::NonZeroU8;

use crate::cert::key_usage;
use crate::cert::{dn_attr, write_matter_cert, DnAttr, MatterCertSpec, NOC_EKU};
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_PUBLIC_KEY_LEN};
use crate::error::{Error, Result};
use crate::fabric::{FabricTable, MAX_CERT_TLV_LEN};

/// コントローラの fabric インデックス(単一 fabric 固定なので常に 1)。
pub const CONTROLLER_FABRIC_INDEX: NonZeroU8 = match NonZeroU8::new(1) {
    Some(v) => v,
    None => unreachable!(),
};

/// subject-key-identifier(20 バイト)を公開鍵から導出する(`SHA-256(pubkey)[..20]`)。
fn key_id<C: Crypto>(crypto: &C, pubkey: &[u8; P256_PUBLIC_KEY_LEN]) -> [u8; 20] {
    let mut hash = [0u8; 32];
    crypto.sha256_oneshot(pubkey, &mut hash);
    let mut skid = [0u8; 20];
    skid.copy_from_slice(&hash[..20]);
    skid
}

/// コントローラの CA(§6.3)。
///
/// RCAC 秘密鍵(root 鍵ペア)・自己署名 RCAC(TLV)・IPK epoch key・fabric/rcac 識別子・
/// serial カウンタ・コントローラ自身の運用資格情報([`FabricTable<C, 1>`])を保持する。
pub struct Ca<C: Crypto> {
    root_kp: C::Keypair,
    rcac: [u8; MAX_CERT_TLV_LEN],
    rcac_len: usize,
    rcac_skid: [u8; 20],
    rcac_id: u64,
    fabric_id: u64,
    controller_node_id: u64,
    vendor_id: u16,
    ipk_epoch_key: [u8; 16],
    next_serial: Cell<u32>,
    creds: FabricTable<C, 1>,
}

impl<C: Crypto> Ca<C> {
    /// 新規 CA を生成する(§6.3)。
    ///
    /// root 鍵ペア + 自己署名 RCAC + IPK epoch key を作り、コントローラ自身の運用鍵ペアと NOC を
    /// 発行して [`FabricTable::add`](検証込み)まで行う。`controller_node_id` は自ノードの運用
    /// NodeId(AddNOC の CaseAdminSubject / CASE の自 identity)。証明書は not-before=0 /
    /// not-after=0(無期限)で発行する。
    pub fn generate<R: crate::crypto::Rng>(
        crypto: &C,
        rng: &mut R,
        fabric_id: u64,
        controller_node_id: u64,
        vendor_id: u16,
        now_epoch_s: u32,
    ) -> Result<Self> {
        // 1. root 鍵ペアと自己署名 RCAC(rcac-id は fabric-id を流用。値の一意性は検証に無関係)。
        let root_kp = crypto.p256_generate_keypair()?;
        let root_pub = root_kp.public_key().to_bytes();
        let rcac_skid = key_id(crypto, &root_pub);
        let rcac_id = fabric_id;
        let rcac_dn = [
            DnAttr::new(dn_attr::MATTER_RCAC_ID, rcac_id),
            DnAttr::new(dn_attr::MATTER_FABRIC_ID, fabric_id),
        ];
        let mut rcac = [0u8; MAX_CERT_TLV_LEN];
        let rcac_len = write_matter_cert(
            &mut rcac,
            &MatterCertSpec {
                serial: &[0x01],
                issuer: &rcac_dn,
                subject: &rcac_dn,
                not_before: 0,
                not_after: 0,
                subject_pub: &root_pub,
                is_ca: true,
                path_len: None,
                key_usage: key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
                eku: &[],
                skid: &rcac_skid,
                akid: &rcac_skid,
            },
            &root_kp,
        )?;

        // 2. IPK epoch key(乱数)。
        let mut ipk_epoch_key = [0u8; 16];
        rng.fill_bytes(&mut ipk_epoch_key)?;

        // 3. コントローラ自身の運用鍵ペア + NOC。
        let comm_kp = crypto.p256_generate_keypair()?;
        let comm_pub = comm_kp.public_key().to_bytes();
        let comm_skid = key_id(crypto, &comm_pub);
        let noc_dn = [
            DnAttr::new(dn_attr::MATTER_NODE_ID, controller_node_id),
            DnAttr::new(dn_attr::MATTER_FABRIC_ID, fabric_id),
        ];
        let mut noc = [0u8; MAX_CERT_TLV_LEN];
        let noc_len = write_matter_cert(
            &mut noc,
            &MatterCertSpec {
                serial: &[0x02],
                issuer: &rcac_dn,
                subject: &noc_dn,
                not_before: 0,
                not_after: 0,
                subject_pub: &comm_pub,
                is_ca: false,
                path_len: None,
                key_usage: key_usage::DIGITAL_SIGNATURE,
                eku: &NOC_EKU,
                skid: &comm_skid,
                akid: &rcac_skid,
            },
            &root_kp,
        )?;

        // 4. 自 fabric をテーブルへ追加(チェーン検証・IPK 導出込み)。
        let mut creds = FabricTable::new();
        creds.add(
            crypto,
            &rcac[..rcac_len],
            None,
            &noc[..noc_len],
            comm_kp,
            &ipk_epoch_key,
            vendor_id,
            now_epoch_s,
            "ctl",
        )?;

        Ok(Self {
            root_kp,
            rcac,
            rcac_len,
            rcac_skid,
            rcac_id,
            fabric_id,
            controller_node_id,
            vendor_id,
            ipk_epoch_key,
            next_serial: Cell::new(3),
            creds,
        })
    }

    /// デバイス CSR の公開鍵に対して NOC を発行する(`out` に TLV、戻りは長さ、§6.3)。
    ///
    /// serial は内部カウンタ([`Cell`])から採番する(`&self` で発行できる、乖離の理由は
    /// モジュールドキュメント参照)。
    pub fn issue_noc(
        &self,
        crypto: &C,
        subject_pub: &[u8; P256_PUBLIC_KEY_LEN],
        node_id: u64,
        out: &mut [u8],
    ) -> Result<usize> {
        let serial = self.next_serial.get();
        self.next_serial.set(serial.wrapping_add(1));
        let serial_be = serial.to_be_bytes();
        let skid = key_id(crypto, subject_pub);
        let issuer = [
            DnAttr::new(dn_attr::MATTER_RCAC_ID, self.rcac_id),
            DnAttr::new(dn_attr::MATTER_FABRIC_ID, self.fabric_id),
        ];
        let subject = [
            DnAttr::new(dn_attr::MATTER_NODE_ID, node_id),
            DnAttr::new(dn_attr::MATTER_FABRIC_ID, self.fabric_id),
        ];
        write_matter_cert(
            out,
            &MatterCertSpec {
                serial: &serial_be,
                issuer: &issuer,
                subject: &subject,
                not_before: 0,
                not_after: 0,
                subject_pub,
                is_ca: false,
                path_len: None,
                key_usage: key_usage::DIGITAL_SIGNATURE,
                eku: &NOC_EKU,
                skid: &skid,
                akid: &self.rcac_skid,
            },
            &self.root_kp,
        )
        .map_err(|_| Error::Crypto)
    }

    /// 自己署名 RCAC の TLV バイト列(AddTrustedRootCertificate に載せる)。
    pub fn rcac(&self) -> &[u8] {
        &self.rcac[..self.rcac_len]
    }

    /// IPK epoch key(AddNOC で配る 16 バイト)。
    pub fn ipk_epoch_key(&self) -> &[u8; 16] {
        &self.ipk_epoch_key
    }

    /// この fabric の FabricId。
    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    /// コントローラ自身の運用 NodeId(CaseAdminSubject / CASE identity)。
    pub fn controller_node_id(&self) -> u64 {
        self.controller_node_id
    }

    /// AdminVendorId(AddNOC に載せる)。
    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// コントローラの運用資格情報(CASE initiator の素材、§6.3)。
    pub fn creds(&self) -> &FabricTable<C, 1> {
        &self.creds
    }
}
