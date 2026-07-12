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
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

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
        // 鍵ペアと IPK epoch key を新規生成し、共通の構築(証明書発行 + creds 登録)に渡す。
        let root_kp = crypto.p256_generate_keypair()?;
        let comm_kp = crypto.p256_generate_keypair()?;
        let mut ipk_epoch_key = [0u8; 16];
        rng.fill_bytes(&mut ipk_epoch_key)?;
        Self::build(
            crypto,
            root_kp,
            comm_kp,
            ipk_epoch_key,
            fabric_id,
            controller_node_id,
            vendor_id,
            3,
            now_epoch_s,
        )
    }

    /// 保存済みの鍵素材から CA を復元する(**persistence 専用**、
    /// `docs/design/port-esp32-device.md` §E4.6)。
    ///
    /// RCAC / コントローラ NOC は保存せず、同じ鍵から**再生成**する。証明書の内容
    /// (serial 1/2・not-before/after = 0)は固定で、署名は決定的(RFC 6979)なので
    /// [`Ca::generate`] が発行したものと同一バイト列になる。`next_serial` は発行済み
    /// デバイス NOC との serial 重複を避けるために引き継ぐ。
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        crypto: &C,
        root_key: &[u8; crate::crypto::P256_SECRET_KEY_LEN],
        controller_key: &[u8; crate::crypto::P256_SECRET_KEY_LEN],
        ipk_epoch_key: [u8; 16],
        fabric_id: u64,
        controller_node_id: u64,
        vendor_id: u16,
        next_serial: u32,
        now_epoch_s: u32,
    ) -> Result<Self> {
        let root_kp = crypto.p256_keypair_from_bytes(root_key)?;
        let comm_kp = crypto.p256_keypair_from_bytes(controller_key)?;
        Self::build(
            crypto,
            root_kp,
            comm_kp,
            ipk_epoch_key,
            fabric_id,
            controller_node_id,
            vendor_id,
            next_serial,
            now_epoch_s,
        )
    }

    /// 鍵ペア・IPK から CA を組み立てる(generate / restore の共通部)。
    #[allow(clippy::too_many_arguments)]
    fn build(
        crypto: &C,
        root_kp: C::Keypair,
        comm_kp: C::Keypair,
        ipk_epoch_key: [u8; 16],
        fabric_id: u64,
        controller_node_id: u64,
        vendor_id: u16,
        next_serial: u32,
        now_epoch_s: u32,
    ) -> Result<Self> {
        // 1. 自己署名 RCAC(rcac-id は fabric-id を流用。値の一意性は検証に無関係)。
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

        // 2. コントローラ自身の NOC(運用鍵ペアは引数)。
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

        // 3. 自 fabric をテーブルへ追加(チェーン検証・IPK 導出込み)。
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
            next_serial: Cell::new(next_serial),
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

    /// この fabric の compressed fabric id(big-endian 8 バイト)。
    ///
    /// 運用 mDNS のインスタンス名 `<compressedFabricId>-<nodeId>._matter._tcp.local` を
    /// 組み立てて相手デバイスを解決するために使う(方向 B: BLE→運用 UDP 遷移)。
    pub fn compressed_fabric_id_bytes(&self) -> [u8; crate::fabric::COMPRESSED_FABRIC_ID_LEN] {
        self.creds
            .iter()
            .next()
            .map(|e| *e.compressed_fabric_id_bytes())
            .unwrap_or([0u8; crate::fabric::COMPRESSED_FABRIC_ID_LEN])
    }

    // ----------------------------------------------------------------------
    // persistence 用 accessor(`docs/design/port-esp32-device.md` §E4.6)。
    // 秘密鍵の取り出しは CA 状態の保存のためにのみ使うこと。
    // ----------------------------------------------------------------------

    /// root(RCAC)秘密鍵の生スカラ(**persistence 専用**)。
    pub fn root_key_bytes(&self) -> [u8; crate::crypto::P256_SECRET_KEY_LEN] {
        self.root_kp.to_bytes()
    }

    /// コントローラ運用鍵ペアの秘密スカラ(**persistence 専用**)。
    pub fn controller_key_bytes(&self) -> Result<[u8; crate::crypto::P256_SECRET_KEY_LEN]> {
        let entry = self.creds.iter().next().ok_or(Error::NotFound)?;
        Ok(entry.operational_key_bytes())
    }

    /// 次に発行する NOC の serial(保存して [`Ca::restore`] に渡す)。
    pub fn next_serial(&self) -> u32 {
        self.next_serial.get()
    }

    // ----------------------------------------------------------------------
    // CA 状態レコード(v1)の codec(`docs/design/esp32-controller.md` §5.2)
    // ----------------------------------------------------------------------

    /// CA 鍵素材を v1 TLV レコードへエンコードする(戻りは長さ)。
    ///
    /// フォーマットは `simple-matter-ble/examples/ble-commissioner.rs` 由来の
    /// **ca-state v1**(anonymous struct、cx0=version, cx1=fabric_id,
    /// cx2=controller_node_id, cx3=vendor_id, cx4=IPK epoch key,
    /// cx5=root 秘密鍵, cx6=コントローラ運用秘密鍵, cx7=next_serial)。
    /// smctl の `ca-state.bin` と S3 ハブの `EspKvs` レコード(キー `b"cast"`)が
    /// 同一バイト列を共有する(PC ↔ S3 の fabric 持ち運びが単純コピーになる)。
    /// 証明書は保存しない([`Ca::decode_state`] = [`Ca::restore`] が決定的署名で
    /// 同一バイト列を再生成する)。
    pub fn encode_state(&self, out: &mut [u8]) -> Result<usize> {
        let ctrl_key = self.controller_key_bytes()?;
        let mut w = TlvWriter::new(out);
        w.start_struct(&TlvTag::Anonymous)?;
        w.write_u8(&cx(0), CA_STATE_VERSION)?;
        w.write_u64(&cx(1), self.fabric_id())?;
        w.write_u64(&cx(2), self.controller_node_id())?;
        w.write_u16(&cx(3), self.vendor_id())?;
        w.write_bytes(&cx(4), self.ipk_epoch_key())?;
        w.write_bytes(&cx(5), &self.root_key_bytes())?;
        w.write_bytes(&cx(6), &ctrl_key)?;
        w.write_u32(&cx(7), self.next_serial())?;
        w.end_container()?;
        Ok(w.len())
    }

    /// v1 TLV レコードから CA を復元する([`Ca::encode_state`] の逆、
    /// [`Ca::restore`] への薄いフロント)。バージョン不一致・欠損は [`Error::Decode`]。
    pub fn decode_state(crypto: &C, bytes: &[u8], now_epoch_s: u32) -> Result<Self> {
        let mut r = TlvReader::new(bytes);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut version = 0u8;
        let mut fabric_id = 0u64;
        let mut node_id = 0u64;
        let mut vendor_id = 0u16;
        let mut ipk = [0u8; 16];
        let mut root_key = [0u8; crate::crypto::P256_SECRET_KEY_LEN];
        let mut ctrl_key = [0u8; crate::crypto::P256_SECRET_KEY_LEN];
        let mut next_serial = 0u32;
        loop {
            let e = r.read_next()?.ok_or(Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => version = v.as_unsigned()? as u8,
                (TlvTag::ContextSpecific(1), v) => fabric_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(2), v) => node_id = v.as_unsigned()?,
                (TlvTag::ContextSpecific(3), v) => vendor_id = v.as_unsigned()? as u16,
                (TlvTag::ContextSpecific(4), v) => {
                    ipk = v.as_bytes()?.try_into().map_err(|_| Error::Decode)?
                }
                (TlvTag::ContextSpecific(5), v) => {
                    root_key = v.as_bytes()?.try_into().map_err(|_| Error::Decode)?
                }
                (TlvTag::ContextSpecific(6), v) => {
                    ctrl_key = v.as_bytes()?.try_into().map_err(|_| Error::Decode)?
                }
                (TlvTag::ContextSpecific(7), v) => next_serial = v.as_unsigned()? as u32,
                _ => r.skip(&e)?,
            }
        }
        if version != CA_STATE_VERSION {
            return Err(Error::Decode);
        }
        Self::restore(
            crypto,
            &root_key,
            &ctrl_key,
            ipk,
            fabric_id,
            node_id,
            vendor_id,
            next_serial,
            now_epoch_s,
        )
    }
}

/// CA 状態レコードの schema version(v1: ble-commissioner / smctl `ca-state.bin` 互換)。
pub const CA_STATE_VERSION: u8 = 1;

/// [`Ca::encode_state`] の出力上限(v1 レコードは実測 ~130B。余裕込み)。
pub const CA_STATE_MAX_LEN: usize = 192;

/// context-specific タグの略記。
fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}
