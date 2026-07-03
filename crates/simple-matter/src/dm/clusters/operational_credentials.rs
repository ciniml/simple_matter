//! Operational Credentials クラスタ(0x003E、Matter Core Spec §11.17)。
//!
//! デバイスアテステーション(AttestationRequest / CertificateChainRequest)、運用鍵の
//! CSR 生成(CSRRequest = NOCSR)、fabric 参加(AddTrustedRootCertificate → AddNOC)、
//! fabric 管理(RemoveFabric / UpdateFabricLabel)を提供し、[`FabricTable`] を所有する。
//!
//! # `cluster!` マクロを使わない理由(設計からの乖離)
//!
//! 本クラスタは `C: Crypto` / `DAC: DacProvider` / `const N` にジェネリックだが、
//! `cluster!`/`device!` マクロはジェネリックな型に対する `impl` 節を生成できない
//! (非ジェネリック `impl Trait for Ty`)。よって [`ServerCluster`] 実装は手書きし、
//! メタデータは静的 `const`([`static@OPCREDS_META`])として単一ソース化する。
//!
//! # DAC / アテステーションの実装判断
//!
//! DAC(Device Attestation Certificate)/ PAI 証明書チェーンと DAC 秘密鍵署名は
//! [`DacProvider`] trait で抽象化する。デバイスは自身の DAC を**検証せず不透明な
//! octstr として転送**する(検証はコミッショナが PAA に対して行う、Core Spec §6.2.3)。
//! AttestationRequest / CSRRequest の署名は **DAC 秘密鍵**で
//! `sign(elements || attestationChallenge)` を計算する(§11.17.5.4–6、rs-matter
//! `add_attestation` / `add_csr` と一致)。テスト実装 [`TestDacProvider`] は chip の
//! **開発用** DAC チェーン([`dev_creds`](TestDacProvider) 参照)を用いる。実 X.509 DER
//! のため chip-tool が DAC 公開鍵を抽出して NOCSR 署名を検証できる(相互運用確認済み)。
//!
//! # fabric-scoped 属性の初期スコープ
//!
//! [`ServerCluster::read_attribute`] は [`AccessContext`] を受け取らないため、NOCs /
//! Fabrics は fabric フィルタせず全 fabric 行を返す(設計 §10 の割り切り。full ACL /
//! fabric-filtered read は後日)。CurrentFabricIndex も同様に 0 を返す。

use core::cell::RefCell;
use core::num::NonZeroU8;
use core::ops::{Deref, DerefMut};

use crate::cert;
use crate::crypto::{Crypto, P256Keypair, P256PublicKey, P256_SIGNATURE_LEN};
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::{close_response, map_tlv, open_response, Fields};
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{
    AccessContext, AttributeId, AttributeMeta, ClusterId, ClusterMeta, CommandId, CommandMeta,
    Privilege, Quality,
};
use crate::dm::ServerCluster;
use crate::error::Error;
use crate::fabric::{FabricTable, MAX_CERT_TLV_LEN};
use crate::im::wire::ImStatus;
use crate::tlv::{TlvReader, TlvTag, TlvValue, TlvWriter};

/// NOCStatus 列挙(§11.17.5.2、AddNOC/RemoveFabric 応答の statusCode)。
pub mod noc_status {
    /// 成功。
    pub const OK: u8 = 0;
    /// 公開鍵が不正(NOC 公開鍵と運用鍵の不一致)。
    pub const INVALID_PUBLIC_KEY: u8 = 1;
    /// NodeOperationalId が不正。
    pub const INVALID_NODE_OP_ID: u8 = 2;
    /// NOC が不正(チェーン検証失敗等)。
    pub const INVALID_NOC: u8 = 3;
    /// CSR が未生成(pending 運用鍵なし)。
    pub const MISSING_CSR: u8 = 4;
    /// fabric テーブル満杯。
    pub const TABLE_FULL: u8 = 5;
    /// ラベル重複。
    pub const LABEL_CONFLICT: u8 = 10;
    /// fabric インデックスが不正。
    pub const INVALID_FABRIC_INDEX: u8 = 11;
}

/// 証明書種別(CertificateChainRequest の certificateType、§11.17.5.3)。
pub mod cert_chain_type {
    /// DAC(Device Attestation Certificate)。
    pub const DAC: u8 = 1;
    /// PAI(Product Attestation Intermediate)。
    pub const PAI: u8 = 2;
}

/// DAC / PAI 証明書チェーンと DAC 秘密鍵署名を提供する抽象(§11.17)。
///
/// デバイスは自身の DAC/PAI を検証せず不透明な octstr として転送する。アテステーション
/// および NOCSR の署名は DAC 秘密鍵で行う。
pub trait DacProvider {
    /// DAC 証明書(X.509 DER)。
    fn dac_der(&self) -> &[u8];
    /// PAI 証明書(X.509 DER)。
    fn pai_der(&self) -> &[u8];
    /// Certification Declaration(CMS。AttestationElements に含める)。
    fn certification_declaration(&self) -> &[u8];
    /// DAC 秘密鍵で `msg` に ECDSA-SHA256 署名し、生 `r||s`(64 バイト)を `out` に書く。
    fn sign_with_dac(
        &self,
        msg: &[u8],
        out: &mut [u8; P256_SIGNATURE_LEN],
    ) -> crate::error::Result<()>;
}

// --- メタデータ(単一ソース。手書き ServerCluster 実装が参照)---

static OPCREDS_ATTRS: &[AttributeMeta] = &[
    AttributeMeta::new(
        AttributeId(0x00),
        Privilege::Administer,
        Quality::NONE,
        true,
        false,
        true,
    ),
    AttributeMeta::new(
        AttributeId(0x01),
        Privilege::View,
        Quality::NONE,
        true,
        false,
        true,
    ),
    AttributeMeta::new(
        AttributeId(0x02),
        Privilege::View,
        Quality::FIXED,
        true,
        false,
        false,
    ),
    AttributeMeta::new(
        AttributeId(0x03),
        Privilege::View,
        Quality::NONE,
        true,
        false,
        true,
    ),
    AttributeMeta::new(
        AttributeId(0x04),
        Privilege::View,
        Quality::NONE,
        true,
        false,
        true,
    ),
    AttributeMeta::new(
        AttributeId(0x05),
        Privilege::View,
        Quality::NONE,
        true,
        false,
        false,
    ),
];

static OPCREDS_CMDS: &[CommandMeta] = &[
    CommandMeta::new(CommandId(0x00), true, Privilege::Administer), // AttestationRequest
    CommandMeta::new(CommandId(0x02), true, Privilege::Administer), // CertificateChainRequest
    CommandMeta::new(CommandId(0x04), true, Privilege::Administer), // CSRRequest
    CommandMeta::new(CommandId(0x06), true, Privilege::Administer), // AddNOC
    CommandMeta::new(CommandId(0x09), true, Privilege::Administer), // UpdateFabricLabel
    CommandMeta::new(CommandId(0x0A), true, Privilege::Administer), // RemoveFabric
    CommandMeta::new(CommandId(0x0B), false, Privilege::Administer), // AddTrustedRootCertificate
];

static OPCREDS_GEN: &[CommandId] = &[
    CommandId(0x01), // AttestationResponse
    CommandId(0x03), // CertificateChainResponse
    CommandId(0x05), // CSRResponse
    CommandId(0x08), // NOCResponse
];

/// Operational Credentials クラスタの静的メタデータ。
static OPCREDS_META: ClusterMeta = ClusterMeta::new(
    ClusterId(0x003E),
    1,
    0,
    OPCREDS_ATTRS,
    OPCREDS_CMDS,
    OPCREDS_GEN,
);

/// context タグの短縮。
const fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

/// [`OpCredsCluster`] が [`FabricTable`] を保持する方法の抽象(統合層向け)。
///
/// クラスタ単独では [`FabricTable`] を **所有**(`RefCell<FabricTable>`)する。しかし CASE
/// responder([`crate::sc::SecureChannel`])と OpCreds が同一の fabric テーブルを共有する
/// 必要がある(片方が AddNOC で書き、もう片方が Sigma2 で読む)。両者は同一の
/// [`ProtocolMux`](crate::exchange::ProtocolMux) 内に格納されるため相互参照できず、fabric
/// テーブルは**外部所有の `RefCell`** を双方が参照する形にする(統合層 `stack` 参照)。
///
/// この trait は「所有(`RefCell<FabricTable>`)」と「共有参照(`&RefCell<FabricTable>`)」の
/// 両方を同じコードパスで扱うための内部境界で、いずれも `&self` 経由(内部可変性)で
/// 読み書きできる。既定の型引数は所有版なので、既存の `OpCredsCluster<C, DAC, N>` は不変。
pub trait FabricAccess<C: Crypto, const N: usize> {
    /// fabric テーブルへの共有アクセス。
    fn get(&self) -> impl Deref<Target = FabricTable<C, N>> + '_;
    /// fabric テーブルへの排他アクセス(内部可変性で `&self` から取得)。
    fn get_mut(&self) -> impl DerefMut<Target = FabricTable<C, N>> + '_;
}

impl<C: Crypto, const N: usize> FabricAccess<C, N> for RefCell<FabricTable<C, N>> {
    fn get(&self) -> impl Deref<Target = FabricTable<C, N>> + '_ {
        self.borrow()
    }
    fn get_mut(&self) -> impl DerefMut<Target = FabricTable<C, N>> + '_ {
        self.borrow_mut()
    }
}

impl<C: Crypto, const N: usize> FabricAccess<C, N> for &RefCell<FabricTable<C, N>> {
    fn get(&self) -> impl Deref<Target = FabricTable<C, N>> + '_ {
        (**self).borrow()
    }
    fn get_mut(&self) -> impl DerefMut<Target = FabricTable<C, N>> + '_ {
        (**self).borrow_mut()
    }
}

/// Operational Credentials クラスタ(0x003E)。
///
/// `C` は暗号 backend、`DAC` は [`DacProvider`]、`N` は最大 fabric 数。`FT` は fabric テーブルの
/// 保持方法([`FabricAccess`]、既定は所有 `RefCell<FabricTable<C, N>>`)。
pub struct OpCredsCluster<
    C: Crypto,
    DAC: DacProvider,
    const N: usize,
    FT = RefCell<FabricTable<C, N>>,
> {
    fabrics: FT,
    crypto: C,
    dac: DAC,
    /// AddTrustedRootCertificate で受理した pending root cert(TLV)。
    pending_root: [u8; MAX_CERT_TLV_LEN],
    pending_root_len: usize,
    /// CSRRequest で生成した pending 運用鍵ペア(AddNOC で消費)。
    pending_keypair: Option<C::Keypair>,
    dirty: Dirty,
}

impl<C: Crypto, DAC: DacProvider, const N: usize> OpCredsCluster<C, DAC, N> {
    /// crypto backend と DAC provider を与えて、fabric テーブルを**所有**する空のクラスタを作る。
    pub fn new(crypto: C, dac: DAC) -> Self {
        Self {
            fabrics: RefCell::new(FabricTable::new()),
            crypto,
            dac,
            pending_root: [0u8; MAX_CERT_TLV_LEN],
            pending_root_len: 0,
            pending_keypair: None,
            dirty: Dirty::new(),
        }
    }
}

impl<'f, C: Crypto, DAC: DacProvider, const N: usize>
    OpCredsCluster<C, DAC, N, &'f RefCell<FabricTable<C, N>>>
{
    /// **外部所有の** fabric テーブル(`RefCell`)を共有するクラスタを作る(統合層 `stack` 用)。
    ///
    /// CASE responder([`crate::sc::SecureChannel`])と同じ [`FabricTable`] を共有し、AddNOC で
    /// 追加した fabric を CASE が Sigma2 で読めるようにする。
    pub fn new_shared(fabrics: &'f RefCell<FabricTable<C, N>>, crypto: C, dac: DAC) -> Self {
        Self {
            fabrics,
            crypto,
            dac,
            pending_root: [0u8; MAX_CERT_TLV_LEN],
            pending_root_len: 0,
            pending_keypair: None,
            dirty: Dirty::new(),
        }
    }
}

impl<C: Crypto, DAC: DacProvider, const N: usize, FT: FabricAccess<C, N>>
    OpCredsCluster<C, DAC, N, FT>
{
    /// 背後の fabric テーブルへの参照(コミッショニング結果の検査用)。
    pub fn fabrics(&self) -> impl Deref<Target = FabricTable<C, N>> + '_ {
        self.fabrics.get()
    }

    /// fail-safe 期限切れで pending(root cert / 運用鍵)を破棄する(設計 §9.4)。
    pub fn on_failsafe_expired(&mut self) {
        self.pending_root_len = 0;
        self.pending_keypair = None;
    }

    // --- 属性読み取り ---

    fn read_nocs(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for f in self.fabrics.get().iter() {
                a.push_struct(|s| {
                    s.field_bytes(1, f.noc())?;
                    match f.icac() {
                        Some(ic) => s.field_bytes(2, ic)?,
                        None => s.field_null(2)?,
                    }
                    s.field_u8(254, f.fabric_index().get())
                })?;
            }
            Ok(())
        })
    }

    fn read_fabrics(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for f in self.fabrics.get().iter() {
                a.push_struct(|s| {
                    s.field_bytes(1, f.root_public_key())?;
                    s.field_u16(2, f.vendor_id())?;
                    s.field_u64(3, f.fabric_id())?;
                    s.field_u64(4, f.node_id())?;
                    s.field_str(5, f.label())?;
                    s.field_u8(254, f.fabric_index().get())
                })?;
            }
            Ok(())
        })
    }

    fn read_trusted_roots(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_array(|a| {
            for f in self.fabrics.get().iter() {
                a.push_bytes(f.rcac())?;
            }
            Ok(())
        })
    }

    // --- コマンド ---

    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.cmd_attestation_request(fields, resp, acc),
            0x02 => self.cmd_cert_chain_request(fields, resp),
            0x04 => self.cmd_csr_request(fields, resp, acc),
            0x06 => self.cmd_add_noc(fields, resp, acc),
            0x09 => self.cmd_update_fabric_label(fields, resp, acc),
            0x0A => self.cmd_remove_fabric(fields, resp),
            0x0B => self.cmd_add_trusted_root(fields),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    /// AttestationRequest(0x00)→ AttestationResponse(0x01)。
    fn cmd_attestation_request(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut nonce: &[u8] = &[];
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                if let TlvValue::ByteString(b) = v {
                    nonce = b;
                }
            }
        }
        if nonce.len() != 32 {
            return Err(ImStatus::ConstraintError);
        }

        // AttestationElements TLV: { 1: CD, 2: nonce, 3: timestamp }。
        // CD は CMS SignedData で大きい(chip 開発用 CD は 541B)。仕様の
        // RESP_MAX(900B)を上限の目安とする。
        let mut elems = [0u8; 704];
        let elems_len = {
            let mut w = TlvWriter::new(&mut elems);
            w.start_struct(&TlvTag::Anonymous).map_err(map_tlv)?;
            w.write_bytes(&cx(1), self.dac.certification_declaration())
                .map_err(map_tlv)?;
            w.write_bytes(&cx(2), nonce).map_err(map_tlv)?;
            w.write_u32(&cx(3), 0).map_err(map_tlv)?;
            w.end_container().map_err(map_tlv)?;
            w.len()
        };

        let sig = self.sign_tbs(&elems[..elems_len], &acc.att_challenge)?;

        let w = open_response(resp, 0x01)?;
        w.write_bytes(&cx(0), &elems[..elems_len])
            .map_err(map_tlv)?;
        w.write_bytes(&cx(1), &sig).map_err(map_tlv)?;
        close_response(w)
    }

    /// CertificateChainRequest(0x02)→ CertificateChainResponse(0x03)。
    fn cmd_cert_chain_request(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
    ) -> Result<(), ImStatus> {
        let mut cert_type: u8 = 0;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                cert_type = v.as_unsigned().unwrap_or(0) as u8;
            }
        }
        let cert = match cert_type {
            cert_chain_type::DAC => self.dac.dac_der(),
            cert_chain_type::PAI => self.dac.pai_der(),
            _ => return Err(ImStatus::ConstraintError),
        };
        let w = open_response(resp, 0x03)?;
        w.write_bytes(&cx(0), cert).map_err(map_tlv)?;
        close_response(w)
    }

    /// CSRRequest(0x04)→ CSRResponse(0x05)。運用鍵ペアを生成し pending 保持する。
    fn cmd_csr_request(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut csr_nonce: &[u8] = &[];
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                if let TlvValue::ByteString(b) = v {
                    csr_nonce = b;
                }
            }
        }
        if csr_nonce.len() != 32 {
            return Err(ImStatus::ConstraintError);
        }

        // 運用鍵ペア生成 + CSR 構築。
        let kp = self
            .crypto
            .p256_generate_keypair()
            .map_err(|_| ImStatus::Failure)?;
        let mut csr = [0u8; cert::MAX_CSR_DER_LEN];
        let csr_len = cert::write_csr(&kp, &mut csr).map_err(|_| ImStatus::Failure)?;
        self.pending_keypair = Some(kp);

        // NOCSRElements TLV: { 1: csr, 2: CSRNonce }。
        let mut nocsr = [0u8; 384];
        let nocsr_len = {
            let mut w = TlvWriter::new(&mut nocsr);
            w.start_struct(&TlvTag::Anonymous).map_err(map_tlv)?;
            w.write_bytes(&cx(1), &csr[..csr_len]).map_err(map_tlv)?;
            w.write_bytes(&cx(2), csr_nonce).map_err(map_tlv)?;
            w.end_container().map_err(map_tlv)?;
            w.len()
        };

        let sig = self.sign_tbs(&nocsr[..nocsr_len], &acc.att_challenge)?;

        let w = open_response(resp, 0x05)?;
        w.write_bytes(&cx(0), &nocsr[..nocsr_len])
            .map_err(map_tlv)?;
        w.write_bytes(&cx(1), &sig).map_err(map_tlv)?;
        close_response(w)
    }

    /// AddTrustedRootCertificate(0x0B)。pending root cert として保持する(status のみ)。
    fn cmd_add_trusted_root(&mut self, fields: &mut TlvReader<'_>) -> Result<(), ImStatus> {
        let mut root: &[u8] = &[];
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                if let TlvValue::ByteString(b) = v {
                    root = b;
                }
            }
        }
        if root.is_empty() || root.len() > MAX_CERT_TLV_LEN {
            return Err(ImStatus::ConstraintError);
        }
        self.pending_root[..root.len()].copy_from_slice(root);
        self.pending_root_len = root.len();
        Ok(())
    }

    /// AddNOC(0x06)→ NOCResponse(0x08)。[`FabricTable::add`] を呼ぶ(fabric.rs 接続点)。
    fn cmd_add_noc(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut noc: &[u8] = &[];
        let mut icac: Option<&[u8]> = None;
        let mut ipk: &[u8] = &[];
        let mut admin_vendor_id: u16 = 0;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match (tag, v) {
                (0, TlvValue::ByteString(b)) => noc = b,
                (1, TlvValue::ByteString(b)) => icac = Some(b),
                (2, TlvValue::ByteString(b)) => ipk = b,
                // 3: caseAdminSubject(u64)は初期スコープでは未使用(ACL クラスタ導入時に反映)。
                (4, val) => admin_vendor_id = val.as_unsigned().unwrap_or(0) as u16,
                _ => {}
            }
        }

        if self.pending_root_len == 0 {
            return write_noc_response(resp, noc_status::INVALID_NOC, None);
        }
        if self.pending_keypair.is_none() {
            return write_noc_response(resp, noc_status::MISSING_CSR, None);
        }
        if noc.is_empty() || ipk.len() != 16 {
            return write_noc_response(resp, noc_status::INVALID_NOC, None);
        }
        let mut ipk_arr = [0u8; 16];
        ipk_arr.copy_from_slice(ipk);

        // pending root をローカルへ複製し、self の借用を分離する。
        let mut root_buf = [0u8; MAX_CERT_TLV_LEN];
        let root_len = self.pending_root_len;
        root_buf[..root_len].copy_from_slice(&self.pending_root[..root_len]);

        let kp = self.pending_keypair.take().ok_or(ImStatus::Failure)?;
        let now_epoch = (acc.now_ms / 1000) as u32;

        let result = self.fabrics.get_mut().add(
            &self.crypto,
            &root_buf[..root_len],
            icac,
            noc,
            kp,
            &ipk_arr,
            admin_vendor_id,
            now_epoch,
            "",
        );

        match result {
            Ok(idx) => {
                self.pending_root_len = 0;
                self.dirty.mark();
                // PASE セッションを確定 fabric へ昇格する要求(設計 §9.4)。
                let _ = acc;
                resp.request_fabric_promotion(idx);
                write_noc_response(resp, noc_status::OK, Some(idx.get()))
            }
            Err(e) => {
                let status = match e {
                    Error::NoSpace => noc_status::TABLE_FULL,
                    Error::Crypto => noc_status::INVALID_PUBLIC_KEY,
                    _ => noc_status::INVALID_NOC,
                };
                write_noc_response(resp, status, None)
            }
        }
    }

    /// UpdateFabricLabel(0x09)→ NOCResponse(0x08)。アクセス元 fabric のラベルを更新する。
    fn cmd_update_fabric_label(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut label: &str = "";
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                if let TlvValue::Utf8String(s) = v {
                    label = s;
                }
            }
        }
        let Some(idx) = acc.fabric_idx else {
            return write_noc_response(resp, noc_status::INVALID_FABRIC_INDEX, None);
        };
        match self.fabrics.get_mut().update_label(idx, label) {
            Ok(()) => {
                self.dirty.mark();
                write_noc_response(resp, noc_status::OK, Some(idx.get()))
            }
            Err(Error::Duplicate) => write_noc_response(resp, noc_status::LABEL_CONFLICT, None),
            Err(_) => write_noc_response(resp, noc_status::INVALID_FABRIC_INDEX, None),
        }
    }

    /// RemoveFabric(0x0A)→ NOCResponse(0x08)。
    fn cmd_remove_fabric(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
    ) -> Result<(), ImStatus> {
        let mut fabric_index: u8 = 0;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                fabric_index = v.as_unsigned().unwrap_or(0) as u8;
            }
        }
        let Some(idx) = NonZeroU8::new(fabric_index) else {
            return write_noc_response(resp, noc_status::INVALID_FABRIC_INDEX, None);
        };
        match self.fabrics.get_mut().remove(idx) {
            Ok(()) => {
                self.dirty.mark();
                write_noc_response(resp, noc_status::OK, Some(idx.get()))
            }
            Err(_) => write_noc_response(resp, noc_status::INVALID_FABRIC_INDEX, None),
        }
    }

    /// `elements || attestationChallenge` を DAC 秘密鍵で署名する(§11.17.5.4）。
    fn sign_tbs(
        &self,
        elements: &[u8],
        challenge: &[u8; 16],
    ) -> Result<[u8; P256_SIGNATURE_LEN], ImStatus> {
        // AttestationElements(CD 541B 級)+ challenge 16B が収まる大きさ。
        let mut tbs = [0u8; 768];
        let total = elements.len() + challenge.len();
        if total > tbs.len() {
            return Err(ImStatus::ResourceExhausted);
        }
        tbs[..elements.len()].copy_from_slice(elements);
        tbs[elements.len()..total].copy_from_slice(challenge);
        let mut sig = [0u8; P256_SIGNATURE_LEN];
        self.dac
            .sign_with_dac(&tbs[..total], &mut sig)
            .map_err(|_| ImStatus::Failure)?;
        Ok(sig)
    }
}

/// NOCResponse(0x08)`{ 0: statusCode, 1?: fabricIndex, 2: debugText }` を書く。
fn write_noc_response(
    resp: &mut CmdResponder<'_, '_>,
    status_code: u8,
    fabric_index: Option<u8>,
) -> Result<(), ImStatus> {
    let w = open_response(resp, 0x08)?;
    w.write_u8(&cx(0), status_code).map_err(map_tlv)?;
    if let Some(idx) = fabric_index {
        w.write_u8(&cx(1), idx).map_err(map_tlv)?;
    }
    w.write_utf8(&cx(2), "").map_err(map_tlv)?;
    close_response(w)
}

impl<C: Crypto, DAC: DacProvider, const N: usize, FT: FabricAccess<C, N>> ServerCluster
    for OpCredsCluster<C, DAC, N, FT>
{
    fn meta(&self) -> &'static ClusterMeta {
        &OPCREDS_META
    }

    fn read_attribute(
        &self,
        attr: AttributeId,
        enc: &mut AttrEncoder<'_, '_>,
    ) -> Result<(), ImStatus> {
        match attr.0 {
            0x00 => self.read_nocs(enc),
            0x01 => self.read_fabrics(enc),
            0x02 => enc.write_u8(N as u8),
            0x03 => enc.write_u8(self.fabrics.get().len() as u8),
            0x04 => self.read_trusted_roots(enc),
            // CurrentFabricIndex: read_attribute は acc を持たないため 0(初期スコープ)。
            0x05 => enc.write_u8(0),
            _ => Err(ImStatus::UnsupportedAttribute),
        }
    }

    fn invoke_command(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        self.invoke_cmd(cmd, fields, resp, acc)
    }

    fn take_dirty(&mut self) -> bool {
        self.dirty.take()
    }
}

// ==========================================================================
// テスト用 DAC provider
// ==========================================================================

/// テスト/デモ用の [`DacProvider`] 実装。
///
/// chip(connectedhomeip)の**開発用** DAC チェーン(VID=0xFFF1 / PID=0x8001、
/// [`dev_creds`] 参照)を返す。実 X.509 DER のため、chip-tool 等の実コミッショナが
/// DAC をパースして NOCSR/アテステーション署名を DAC 公開鍵で検証できる。
/// 開発・テスト専用であり、製品では固有の DAC を持つ [`DacProvider`] 実装に差し替えること。
pub struct TestDacProvider<C: Crypto> {
    dac_keypair: C::Keypair,
}

pub mod dev_creds;
use dev_creds::{
    DEV_CD_FOR_ALL_EXAMPLES, DEV_DAC_CERT_FFF1_8001, DEV_DAC_PRIVKEY_FFF1_8001, DEV_PAI_CERT_FFF1,
};

impl<C: Crypto> TestDacProvider<C> {
    /// crypto backend から chip 開発用 DAC 秘密鍵を復元して provider を作る。
    pub fn new(crypto: &C) -> crate::error::Result<Self> {
        let dac_keypair = crypto.p256_keypair_from_bytes(&DEV_DAC_PRIVKEY_FFF1_8001)?;
        Ok(Self { dac_keypair })
    }

    /// DAC 公開鍵(SEC1 非圧縮 65 バイト。テストでの署名検証用)。
    pub fn dac_public_key(&self) -> [u8; 65] {
        self.dac_keypair.public_key().to_bytes()
    }
}

impl<C: Crypto> DacProvider for TestDacProvider<C> {
    fn dac_der(&self) -> &[u8] {
        &DEV_DAC_CERT_FFF1_8001
    }
    fn pai_der(&self) -> &[u8] {
        &DEV_PAI_CERT_FFF1
    }
    fn certification_declaration(&self) -> &[u8] {
        &DEV_CD_FOR_ALL_EXAMPLES
    }
    fn sign_with_dac(
        &self,
        msg: &[u8],
        out: &mut [u8; P256_SIGNATURE_LEN],
    ) -> crate::error::Result<()> {
        self.dac_keypair.sign(msg, out)
    }
}
