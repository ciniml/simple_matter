//! Administrator Commissioning クラスタ(0x003C、Matter Core Spec §11.19)。
//!
//! コミッショニング済みデバイスへ 2 人目以降の管理者を追加するための **コミッショニング窓**
//! を管理する(`docs/design/admin-commissioning.md`)。窓の状態は呼び出し側(example /
//! ポート層)が所有する [`RefCell<CommissioningWindow>`] をクラスタと app ループが共有する
//! (fabric テーブル共有と同じ「外部所有 RefCell」パターン、`stack` 参照)。
//!
//! - **OpenCommissioningWindow(ECM)**: PAKE verifier(w0‖L 97B)+ salt / iterations /
//!   discriminator を動的付与して窓を開く(mDNS は CM=2)。**timed invoke 必須**。
//! - **OpenBasicCommissioningWindow(BC)**: 焼き込みパスコードで窓を開く(CM=1)。
//! - **RevokeCommissioning**: 窓を即時クローズ。
//!
//! PASE 設定の差し替え・mDNS 再広告はコアでは行わない(sans-IO)。app ループが
//! [`CommissioningWindow::take_event`] をポーリングし、[`WindowEvent`] に応じて
//! `MatterStack::set_pase_config` / `set_pase_enabled` と mDNS の commissionable 広告を
//! 切り替える(設計 §4/§5)。

use core::cell::RefCell;
use core::num::NonZeroU8;

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{AccessContext, CommandId};
use crate::im::wire::ImStatus;
use crate::tlv::{TlvReader, TlvValue};

/// SPAKE2+ スカラ w0 の長さ(バイト)。`crate::crypto::spake2p::SPAKE2P_SCALAR_LEN` と同値
/// (spake2p モジュールは rustcrypto feature 付きのため、ここでは独立に定義する)。
const W0_LEN: usize = 32;
/// SPAKE2+ 点 L の長さ(バイト)。`SPAKE2P_POINT_LEN` と同値。
const L_LEN: usize = 65;

/// PAKEPasscodeVerifier フィールドの長さ(w0(32) ‖ L(65)、§11.19.8.1)。
pub const PAKE_VERIFIER_LEN: usize = W0_LEN + L_LEN;

/// 窓タイムアウトの下限(秒、§11.19.8.1)。
pub const MIN_WINDOW_TIMEOUT_S: u16 = 180;
/// 窓タイムアウトの上限(秒、§11.19.8.1)。
pub const MAX_WINDOW_TIMEOUT_S: u16 = 900;

/// salt の許容長(§3.10)。
const SALT_MIN_LEN: usize = 16;
const SALT_MAX_LEN: usize = 32;
/// PBKDF iteration count の許容範囲(§3.10)。
const ITERATIONS_MIN: u32 = 1000;
const ITERATIONS_MAX: u32 = 100_000;

/// WindowStatus 列挙(§11.19.7.1)。
pub mod window_status {
    /// 窓は閉じている。
    pub const WINDOW_NOT_OPEN: u8 = 0;
    /// ECM 窓(動的 verifier、CM=2)が開いている。
    pub const ENHANCED_WINDOW_OPEN: u8 = 1;
    /// BC 窓(焼き込みパスコード、CM=1)が開いている。
    pub const BASIC_WINDOW_OPEN: u8 = 2;
}

/// クラスタ固有ステータスコード(§11.19.6)。
pub mod status_code {
    /// 窓が既に開いている。
    pub const BUSY: u8 = 2;
    /// PAKE パラメータ(verifier / salt / iterations)不正。
    pub const PAKE_PARAMETER_ERROR: u8 = 3;
    /// 窓が開いていない(Revoke 対象なし)。
    pub const WINDOW_NOT_OPEN: u8 = 4;
}

/// 窓状態の変化イベント(1 深度、app ループが [`CommissioningWindow::take_event`] で取り出す)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEvent {
    /// ECM 窓が開いた。app は [`CommissioningWindow::pase_config`] を PASE に注入し、
    /// `discriminator` で CM=2 の commissionable 広告を出す。
    OpenedEnhanced {
        /// 窓の 12 ビット discriminator(mDNS の `D`/サブタイプに使う)。
        discriminator: u16,
    },
    /// BC 窓が開いた。app は焼き込みパスコードの PASE 設定と CM=1 広告に戻す。
    OpenedBasic,
    /// 窓が閉じた(Revoke / タイムアウト)。app は PASE を無効化し commissionable 広告を止める。
    Closed,
}

/// コミッショニング窓の状態機械(設計 §2)。
///
/// クラスタ(書き手)と app ループ(読み手 + イベント消費)が `RefCell` 越しに共有する。
pub struct CommissioningWindow {
    status: u8,
    deadline_ms: u64,
    admin_fabric_index: Option<NonZeroU8>,
    admin_vendor_id: Option<u16>,
    /// ECM で付与された SPAKE2+ 検証子(w0 ‖ L の生バイト列)。
    verifier: [u8; PAKE_VERIFIER_LEN],
    salt: [u8; SALT_MAX_LEN],
    salt_len: usize,
    iterations: u32,
    discriminator: u16,
    event: Option<WindowEvent>,
}

impl CommissioningWindow {
    /// 閉じた窓を作る。
    pub const fn new() -> Self {
        Self {
            status: window_status::WINDOW_NOT_OPEN,
            deadline_ms: 0,
            admin_fabric_index: None,
            admin_vendor_id: None,
            verifier: [0u8; PAKE_VERIFIER_LEN],
            salt: [0u8; SALT_MAX_LEN],
            salt_len: 0,
            iterations: 0,
            discriminator: 0,
            event: None,
        }
    }

    /// WindowStatus(§11.19.7.1)。
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// 窓が開いているか。
    pub const fn is_open(&self) -> bool {
        self.status != window_status::WINDOW_NOT_OPEN
    }

    /// 窓を開いた管理者の fabric index(閉時は `None`)。
    pub const fn admin_fabric_index(&self) -> Option<NonZeroU8> {
        self.admin_fabric_index
    }

    /// 窓を開いた管理者の Vendor ID(閉時・未解決は `None`)。
    pub const fn admin_vendor_id(&self) -> Option<u16> {
        self.admin_vendor_id
    }

    /// AdminVendorId を解決して書き込む(app が fabric テーブルから引く。設計 §7)。
    pub fn set_admin_vendor_id(&mut self, vid: u16) {
        if self.is_open() {
            self.admin_vendor_id = Some(vid);
        }
    }

    /// ECM 窓の discriminator(mDNS 広告用)。
    pub const fn discriminator(&self) -> u16 {
        self.discriminator
    }

    /// ECM 窓の生 verifier(w0 ‖ L)・salt・iterations。ECM 窓が開いていなければ `None`。
    pub fn pase_params(&self) -> Option<(&[u8; PAKE_VERIFIER_LEN], &[u8], u32)> {
        if self.status != window_status::ENHANCED_WINDOW_OPEN {
            return None;
        }
        Some((&self.verifier, &self.salt[..self.salt_len], self.iterations))
    }

    /// ECM 窓の PASE 設定(動的 verifier 由来)。ECM 窓が開いていなければ `None`。
    #[cfg(feature = "rustcrypto")]
    pub fn pase_config(&self) -> Option<crate::sc::PaseConfig> {
        use crate::crypto::spake2p::Spake2pVerifierParams;
        let (verifier, salt, iterations) = self.pase_params()?;
        let mut w0 = [0u8; W0_LEN];
        let mut l = [0u8; L_LEN];
        w0.copy_from_slice(&verifier[..W0_LEN]);
        l.copy_from_slice(&verifier[W0_LEN..]);
        crate::sc::PaseConfig::from_verifier(Spake2pVerifierParams { w0, l }, salt, iterations).ok()
    }

    /// 直近の窓状態変化(あれば)。取り出すとクリアされる(1 深度、最新優先)。
    pub fn take_event(&mut self) -> Option<WindowEvent> {
        self.event.take()
    }

    /// ECM 窓を開く(検証済みパラメータ前提。クラスタ内部用)。
    #[allow(clippy::too_many_arguments)]
    fn open_enhanced(
        &mut self,
        verifier: [u8; PAKE_VERIFIER_LEN],
        salt: &[u8],
        iterations: u32,
        discriminator: u16,
        timeout_s: u16,
        admin_fabric: Option<NonZeroU8>,
        now_ms: u64,
    ) {
        self.status = window_status::ENHANCED_WINDOW_OPEN;
        self.deadline_ms = now_ms.saturating_add((timeout_s as u64) * 1000);
        self.admin_fabric_index = admin_fabric;
        self.admin_vendor_id = None;
        self.verifier = verifier;
        self.salt[..salt.len()].copy_from_slice(salt);
        self.salt_len = salt.len();
        self.iterations = iterations;
        self.discriminator = discriminator;
        self.event = Some(WindowEvent::OpenedEnhanced { discriminator });
    }

    /// BC 窓を開く(クラスタ内部用)。
    fn open_basic(&mut self, timeout_s: u16, admin_fabric: Option<NonZeroU8>, now_ms: u64) {
        self.status = window_status::BASIC_WINDOW_OPEN;
        self.deadline_ms = now_ms.saturating_add((timeout_s as u64) * 1000);
        self.admin_fabric_index = admin_fabric;
        self.admin_vendor_id = None;
        self.event = Some(WindowEvent::OpenedBasic);
    }

    /// 窓を明示的に閉じる(統合層向け)。
    ///
    /// 窓経由のコミッショニング成功(fabric 追加)を検知した app ループが呼ぶ
    /// (§11.19.5: 窓はコミッショニング完了で閉じる)。閉じたら [`WindowEvent::Closed`] を積む。
    pub fn close_window(&mut self) {
        if self.is_open() {
            self.close();
        }
    }

    /// 窓を閉じる(Revoke / タイムアウト)。
    fn close(&mut self) {
        self.status = window_status::WINDOW_NOT_OPEN;
        self.deadline_ms = 0;
        self.admin_fabric_index = None;
        self.admin_vendor_id = None;
        self.event = Some(WindowEvent::Closed);
    }

    /// 期限超過なら窓を閉じる。閉じたら `true`。
    fn expire(&mut self, now_ms: u64) -> bool {
        if self.is_open() && now_ms > self.deadline_ms {
            self.close();
            true
        } else {
            false
        }
    }
}

impl Default for CommissioningWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// Administrator Commissioning クラスタ(0x003C)。
///
/// 窓状態 [`CommissioningWindow`] は外部所有の `RefCell` を共有する(モジュールドキュメント)。
pub struct AdminCommissioningCluster<'s> {
    window: &'s RefCell<CommissioningWindow>,
    dirty: Dirty,
}

impl<'s> AdminCommissioningCluster<'s> {
    /// 外部所有の窓状態を共有するクラスタを作る。
    pub fn new(window: &'s RefCell<CommissioningWindow>) -> Self {
        Self {
            window,
            dirty: Dirty::new(),
        }
    }

    /// 窓の期限超過を検出して自動クローズする(統合層の tick から呼ぶ)。閉じたら `true`。
    pub fn on_tick(&mut self, now_ms: u64) -> bool {
        if self.window.borrow_mut().expire(now_ms) {
            self.dirty.mark();
            true
        } else {
            false
        }
    }

    /// OpenCommissioningWindow(0x00、ECM)。
    fn open_commissioning_window(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut crate::dm::codec::CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut timeout_s: Option<u16> = None;
        let mut verifier: Option<[u8; PAKE_VERIFIER_LEN]> = None;
        let mut discriminator: Option<u16> = None;
        let mut iterations: Option<u32> = None;
        let mut salt_buf = [0u8; SALT_MAX_LEN];
        let mut salt_len: Option<usize> = None;
        let mut bad_pake = false;

        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            match (tag, v) {
                (0, v) => timeout_s = v.as_unsigned().ok().map(|x| x as u16),
                (1, TlvValue::ByteString(b)) => {
                    if b.len() == PAKE_VERIFIER_LEN {
                        let mut v = [0u8; PAKE_VERIFIER_LEN];
                        v.copy_from_slice(b);
                        verifier = Some(v);
                    } else {
                        bad_pake = true;
                    }
                }
                (2, v) => discriminator = v.as_unsigned().ok().map(|x| x as u16),
                (3, v) => iterations = v.as_unsigned().ok().map(|x| x as u32),
                (4, TlvValue::ByteString(b)) => {
                    if (SALT_MIN_LEN..=SALT_MAX_LEN).contains(&b.len()) {
                        salt_buf[..b.len()].copy_from_slice(b);
                        salt_len = Some(b.len());
                    } else {
                        bad_pake = true;
                    }
                }
                _ => {}
            }
        }

        // 窓が既に開いている → Busy(§11.19.8.1)。
        if self.window.borrow().is_open() {
            resp.set_cluster_status(status_code::BUSY);
            return Err(ImStatus::Failure);
        }
        // タイムアウト範囲(180–900 秒)は INVALID_COMMAND。
        let timeout_s = timeout_s.ok_or(ImStatus::InvalidCommand)?;
        if !(MIN_WINDOW_TIMEOUT_S..=MAX_WINDOW_TIMEOUT_S).contains(&timeout_s) {
            return Err(ImStatus::InvalidCommand);
        }
        // discriminator は 12 ビット。
        let discriminator = match discriminator {
            Some(d) if d <= 0x0FFF => d,
            _ => return Err(ImStatus::InvalidCommand),
        };
        // PAKE パラメータ不正 → PAKEParameterError(cluster status 3)。
        let iterations_ok =
            matches!(iterations, Some(i) if (ITERATIONS_MIN..=ITERATIONS_MAX).contains(&i));
        let (Some(verifier), Some(salt_len), true, false) =
            (verifier, salt_len, iterations_ok, bad_pake)
        else {
            resp.set_cluster_status(status_code::PAKE_PARAMETER_ERROR);
            return Err(ImStatus::Failure);
        };

        self.window.borrow_mut().open_enhanced(
            verifier,
            &salt_buf[..salt_len],
            iterations.unwrap_or(ITERATIONS_MIN),
            discriminator,
            timeout_s,
            acc.fabric_idx,
            acc.now_ms,
        );
        self.dirty.mark();
        Ok(())
    }

    /// OpenBasicCommissioningWindow(0x01、BC)。
    fn open_basic_commissioning_window(
        &mut self,
        fields: &mut TlvReader<'_>,
        resp: &mut crate::dm::codec::CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut timeout_s: Option<u16> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                timeout_s = v.as_unsigned().ok().map(|x| x as u16);
            }
        }
        if self.window.borrow().is_open() {
            resp.set_cluster_status(status_code::BUSY);
            return Err(ImStatus::Failure);
        }
        let timeout_s = timeout_s.ok_or(ImStatus::InvalidCommand)?;
        if !(MIN_WINDOW_TIMEOUT_S..=MAX_WINDOW_TIMEOUT_S).contains(&timeout_s) {
            return Err(ImStatus::InvalidCommand);
        }
        self.window
            .borrow_mut()
            .open_basic(timeout_s, acc.fabric_idx, acc.now_ms);
        self.dirty.mark();
        Ok(())
    }

    /// RevokeCommissioning(0x02)。
    fn revoke_commissioning(
        &mut self,
        resp: &mut crate::dm::codec::CmdResponder<'_, '_>,
    ) -> Result<(), ImStatus> {
        let mut w = self.window.borrow_mut();
        if !w.is_open() {
            resp.set_cluster_status(status_code::WINDOW_NOT_OPEN);
            return Err(ImStatus::Failure);
        }
        w.close();
        drop(w);
        self.dirty.mark();
        Ok(())
    }

    /// コマンドディスパッチ。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut crate::dm::codec::CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.open_commissioning_window(fields, resp, acc),
            0x01 => self.open_basic_commissioning_window(fields, resp, acc),
            0x02 => self.revoke_commissioning(resp),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }

    /// AdminFabricIndex(nullable fabric-idx)。
    fn read_admin_fabric_index(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.window.borrow().admin_fabric_index() {
            Some(idx) => e.write_u8(idx.get()),
            None => e.write_null(),
        }
    }

    /// AdminVendorId(nullable vendor-id)。
    fn read_admin_vendor_id(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        match self.window.borrow().admin_vendor_id() {
            Some(vid) => e.write_u16(vid),
            None => e.write_null(),
        }
    }
}

cluster! {
    AdminCommissioningCluster<'_> {
        id: 0x003C,
        revision: 1,
        // FeatureMap bit0 = Basic(OpenBasicCommissioningWindow 対応)。
        feature_map: 1,
        dirty: dirty,
        invoke: (|c: &mut AdminCommissioningCluster<'_>, cmd, fields, resp, acc| {
            c.invoke_cmd(cmd, fields, resp, acc)
        }),
        attributes: [
            0x0000 WindowStatus {
                access: View, quality: [], subscribe: true,
                read: (|c: &AdminCommissioningCluster<'_>, e: &mut AttrEncoder<'_, '_>| {
                    e.write_u8(c.window.borrow().status())
                }),
                write: _
            },
            0x0001 AdminFabricIndex {
                access: View, quality: [], subscribe: true,
                read: (|c: &AdminCommissioningCluster<'_>, e: &mut AttrEncoder<'_, '_>| {
                    c.read_admin_fabric_index(e)
                }),
                write: _
            },
            0x0002 AdminVendorId {
                access: View, quality: [], subscribe: true,
                read: (|c: &AdminCommissioningCluster<'_>, e: &mut AttrEncoder<'_, '_>| {
                    c.read_admin_vendor_id(e)
                }),
                write: _
            },
        ],
        accepted: [
            0x00 OpenCommissioningWindow => Administer @timed,
            0x01 OpenBasicCommissioningWindow => Administer @timed,
            0x02 RevokeCommissioning => Administer @timed,
        ],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AccessContext, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{ContainerType, TlvTag, TlvWriter};

    fn acc(now_ms: u64) -> AccessContext {
        AccessContext::new(
            SessionKind::Case,
            NonZeroU8::new(1),
            0x1122,
            Privilege::Administer,
        )
        .with_env(now_ms, [0u8; 16])
    }

    /// OCW のコマンドフィールド構造体を組む。
    fn ocw_fields(
        buf: &mut [u8],
        timeout: u16,
        verifier: &[u8],
        disc: u16,
        iterations: u32,
        salt: &[u8],
    ) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(0), timeout).unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(1), verifier)
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(2), disc).unwrap();
        w.write_u32(&TlvTag::ContextSpecific(3), iterations)
            .unwrap();
        w.write_bytes(&TlvTag::ContextSpecific(4), salt).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(
        cluster: &mut AdminCommissioningCluster<'_>,
        cmd: u16,
        fields: &[u8],
        now_ms: u64,
    ) -> (Result<(), ImStatus>, Option<u8>) {
        let mut scratch = [0u8; 256];
        let mut sw = TlvWriter::new(&mut scratch);
        let mut resp = CmdResponder::new(&mut sw);
        let mut fr = TlvReader::new(fields);
        let r = cluster.invoke_cmd(CommandId(cmd as u32), &mut fr, &mut resp, &acc(now_ms));
        let cs = resp.cluster_status();
        (r, cs)
    }

    #[test]
    fn ocw_opens_window_and_emits_event() {
        let window = RefCell::new(CommissioningWindow::new());
        let mut cl = AdminCommissioningCluster::new(&window);
        let verifier = [0xAB; PAKE_VERIFIER_LEN];
        let salt = [0x11; 16];
        let mut buf = [0u8; 256];
        let n = ocw_fields(&mut buf, 300, &verifier, 3841, 1000, &salt);

        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 1_000);
        assert_eq!(r, Ok(()));
        assert_eq!(cs, None);
        {
            let mut w = window.borrow_mut();
            assert_eq!(w.status(), window_status::ENHANCED_WINDOW_OPEN);
            assert_eq!(w.discriminator(), 3841);
            assert_eq!(w.admin_fabric_index(), NonZeroU8::new(1));
            assert_eq!(
                w.take_event(),
                Some(WindowEvent::OpenedEnhanced {
                    discriminator: 3841
                })
            );
            let cfg = w.pase_config().expect("ECM PASE config");
            let _ = cfg;
        }
        assert!(cl.take_dirty());

        // 二重オープン → Busy(cluster status 2)。
        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 2_000);
        assert_eq!(r, Err(ImStatus::Failure));
        assert_eq!(cs, Some(status_code::BUSY));
    }

    #[test]
    fn ocw_validates_parameters() {
        let window = RefCell::new(CommissioningWindow::new());
        let mut cl = AdminCommissioningCluster::new(&window);
        let salt = [0x11; 16];
        let mut buf = [0u8; 256];

        // タイムアウト範囲外 → INVALID_COMMAND。
        let n = ocw_fields(&mut buf, 100, &[0xAB; PAKE_VERIFIER_LEN], 3841, 1000, &salt);
        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 0);
        assert_eq!(r, Err(ImStatus::InvalidCommand));
        assert_eq!(cs, None);

        // verifier 長不正 → PAKEParameterError。
        let n = ocw_fields(&mut buf, 300, &[0xAB; 10], 3841, 1000, &salt);
        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 0);
        assert_eq!(r, Err(ImStatus::Failure));
        assert_eq!(cs, Some(status_code::PAKE_PARAMETER_ERROR));

        // iterations 範囲外 → PAKEParameterError。
        let n = ocw_fields(&mut buf, 300, &[0xAB; PAKE_VERIFIER_LEN], 3841, 999, &salt);
        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 0);
        assert_eq!(r, Err(ImStatus::Failure));
        assert_eq!(cs, Some(status_code::PAKE_PARAMETER_ERROR));

        // salt 短すぎ → PAKEParameterError。
        let n = ocw_fields(
            &mut buf,
            300,
            &[0xAB; PAKE_VERIFIER_LEN],
            3841,
            1000,
            &[1u8; 8],
        );
        let (r, cs) = invoke(&mut cl, 0x00, &buf[..n], 0);
        assert_eq!(r, Err(ImStatus::Failure));
        assert_eq!(cs, Some(status_code::PAKE_PARAMETER_ERROR));

        assert_eq!(window.borrow().status(), window_status::WINDOW_NOT_OPEN);
    }

    #[test]
    fn revoke_and_timeout_close_window() {
        let window = RefCell::new(CommissioningWindow::new());
        let mut cl = AdminCommissioningCluster::new(&window);

        // 閉じている窓の Revoke → WindowNotOpen(4)。
        let (r, cs) = invoke(&mut cl, 0x02, &[], 0);
        assert_eq!(r, Err(ImStatus::Failure));
        assert_eq!(cs, Some(status_code::WINDOW_NOT_OPEN));

        // 開いて Revoke。
        let mut buf = [0u8; 256];
        let n = ocw_fields(
            &mut buf,
            180,
            &[0xAB; PAKE_VERIFIER_LEN],
            77,
            1000,
            &[0x22; 16],
        );
        let (r, _) = invoke(&mut cl, 0x00, &buf[..n], 1_000);
        assert_eq!(r, Ok(()));
        let _ = window.borrow_mut().take_event();
        let (r, cs) = invoke(&mut cl, 0x02, &[], 2_000);
        assert_eq!(r, Ok(()));
        assert_eq!(cs, None);
        assert_eq!(window.borrow().status(), window_status::WINDOW_NOT_OPEN);
        assert_eq!(window.borrow_mut().take_event(), Some(WindowEvent::Closed));

        // 開いてタイムアウト(180s)。
        let (r, _) = invoke(&mut cl, 0x00, &buf[..n], 10_000);
        assert_eq!(r, Ok(()));
        let _ = window.borrow_mut().take_event();
        assert!(!cl.on_tick(10_000 + 180_000)); // ちょうど期限はまだ
        assert!(cl.on_tick(10_000 + 180_001));
        assert_eq!(window.borrow().status(), window_status::WINDOW_NOT_OPEN);
        assert_eq!(window.borrow_mut().take_event(), Some(WindowEvent::Closed));
        // AdminFabricIndex / AdminVendorId は null に戻る。
        assert_eq!(window.borrow().admin_fabric_index(), None);
        assert_eq!(window.borrow().admin_vendor_id(), None);
    }

    #[test]
    fn meta_marks_commands_timed_and_admin() {
        let window = RefCell::new(CommissioningWindow::new());
        let cl = AdminCommissioningCluster::new(&window);
        let meta = cl.meta();
        assert_eq!(meta.id.0, 0x003C);
        for cmd in meta.accepted_commands {
            assert!(cmd.timed, "command {:#x} must require timed", cmd.id.0);
            assert_eq!(cmd.access, Privilege::Administer);
        }
    }
}
