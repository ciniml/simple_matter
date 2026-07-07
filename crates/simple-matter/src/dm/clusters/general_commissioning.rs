//! General Commissioning クラスタ(0x0030、Matter Core Spec §11.9)。
//!
//! コミッショニングフローの入口となる fail-safe タイマ(ArmFailSafe)、地域設定
//! (SetRegulatoryConfig)、完了通知(CommissioningComplete)を提供する。fail-safe の
//! 期限は注入された時刻([`AccessContext::now_ms`](crate::dm::meta::AccessContext))から計算する。
//!
//! # fail-safe 機構の範囲(設計 §9.4/§12 論点 6 の初期スコープ)
//!
//! 本クラスタは fail-safe の**アーム状態・期限・Breadcrumb**を保持する。Operational
//! Credentials が保持する pending(root cert / 運用鍵)のロールバックは、cross-cluster
//! 共有を避けるため OpCreds 側([`crate::dm::clusters::OpCredsCluster::on_failsafe_expired`])が
//! 担い、統合層が期限超過時に両者を掃引する構成とする(初期スコープの簡略化)。
//! CommissioningComplete は仕様上 CASE セッション経由に限られるが、初期実装では
//! fail-safe 解除 + 成功応答の骨格とする。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::{close_response, map_tlv, open_response, Fields};
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{AccessContext, CommandId};
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// CommissioningError 列挙(§11.9.5.1)。
pub mod commissioning_error {
    /// OK(エラーなし)。
    pub const OK: u8 = 0;
    /// 値が範囲外。
    pub const VALUE_OUTSIDE_RANGE: u8 = 1;
    /// 認証が無効。
    pub const INVALID_AUTHENTICATION: u8 = 2;
    /// fail-safe が張られていない。
    pub const NO_FAIL_SAFE: u8 = 3;
    /// 他の管理者が処理中。
    pub const BUSY_WITH_OTHER_ADMIN: u8 = 4;
}

/// RegulatoryLocationType 列挙(§11.9.5.3)。
pub mod regulatory {
    /// 屋内。
    pub const INDOOR: u8 = 0;
    /// 屋外。
    pub const OUTDOOR: u8 = 1;
    /// 屋内/屋外。
    pub const INDOOR_OUTDOOR: u8 = 2;
}

/// fail-safe の状態(アーム/期限/Breadcrumb)。
#[derive(Debug, Clone, Copy)]
pub struct FailSafe {
    armed: bool,
    deadline_ms: u64,
    breadcrumb: u64,
    max_cumulative_s: u16,
    expiry_len_s: u16,
}

impl FailSafe {
    /// 未アームの fail-safe を作る。
    pub const fn new(expiry_len_s: u16, max_cumulative_s: u16) -> Self {
        Self {
            armed: false,
            deadline_ms: 0,
            breadcrumb: 0,
            max_cumulative_s,
            expiry_len_s,
        }
    }

    /// アーム中かを返す。
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// 現在の Breadcrumb 値。
    pub const fn breadcrumb(&self) -> u64 {
        self.breadcrumb
    }

    /// `now_ms` 時点で期限切れ(アーム済みかつ期限超過)なら `true`。
    pub const fn is_expired(&self, now_ms: u64) -> bool {
        self.armed && now_ms > self.deadline_ms
    }

    /// fail-safe をアーム/更新する。`expiry_s == 0` は解除。
    fn arm(&mut self, expiry_s: u16, breadcrumb: u64, now_ms: u64) {
        if expiry_s == 0 {
            self.armed = false;
            self.deadline_ms = 0;
            self.breadcrumb = 0;
        } else {
            self.armed = true;
            self.deadline_ms = now_ms.saturating_add((expiry_s as u64) * 1000);
            self.breadcrumb = breadcrumb;
        }
    }

    /// fail-safe を解除する(CommissioningComplete / 期限掃引)。
    pub fn disarm(&mut self) {
        self.armed = false;
        self.deadline_ms = 0;
        self.breadcrumb = 0;
    }
}

/// General Commissioning クラスタ(0x0030)。
#[derive(Debug)]
pub struct GeneralCommissioning {
    fail_safe: FailSafe,
    regulatory_config: u8,
    location_capability: u8,
    supports_concurrent_connection: bool,
    dirty: Dirty,
}

impl GeneralCommissioning {
    /// 既定設定でクラスタを作る。
    ///
    /// `fail_safe_expiry_s` / `max_cumulative_s` は BasicCommissioningInfo として広告する。
    /// `location_capability` は [`regulatory`] の値。
    pub const fn new(
        fail_safe_expiry_s: u16,
        max_cumulative_s: u16,
        location_capability: u8,
    ) -> Self {
        Self {
            fail_safe: FailSafe::new(fail_safe_expiry_s, max_cumulative_s),
            regulatory_config: regulatory::INDOOR_OUTDOOR,
            location_capability,
            supports_concurrent_connection: true,
            dirty: Dirty::new(),
        }
    }

    /// 標準的な既定(fail-safe 60s / cumulative 900s / IndoorOutdoor)。
    pub const fn default_config() -> Self {
        Self::new(60, 900, regulatory::INDOOR_OUTDOOR)
    }

    /// fail-safe 状態への参照。
    pub const fn fail_safe(&self) -> &FailSafe {
        &self.fail_safe
    }

    /// fail-safe が期限切れなら解除する(統合層が定期的に呼ぶ)。解除したら `true`。
    pub fn on_tick(&mut self, now_ms: u64) -> bool {
        if self.fail_safe.is_expired(now_ms) {
            self.fail_safe.disarm();
            true
        } else {
            false
        }
    }

    /// fail-safe を明示的に解除する(fail-safe クリーンアップフックの冪等な保険、Core Spec §11.10)。
    ///
    /// ArmFailSafe(0) / 期限切れ経路では既に解除済みだが、統合層の
    /// [`DataModel::on_failsafe_cleanup`](crate::dm::DataModel::on_failsafe_cleanup) が
    /// GC の解除を担保できるよう公開する(二重解除は冪等)。
    pub fn disarm(&mut self) {
        if self.fail_safe.is_armed() {
            self.fail_safe.disarm();
            self.dirty.mark();
        }
    }

    /// Breadcrumb(0x0000)を書き込む。
    fn write_breadcrumb(
        &mut self,
        data: crate::dm::AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        self.fail_safe.breadcrumb = v;
        self.dirty.mark();
        Ok(())
    }

    /// BasicCommissioningInfo(0x0001)を書く。
    fn read_basic_info(&self, e: &mut AttrEncoder<'_, '_>) -> Result<(), ImStatus> {
        e.write_struct(|s| {
            s.field_u16(0, self.fail_safe.expiry_len_s)?;
            s.field_u16(1, self.fail_safe.max_cumulative_s)
        })
    }

    /// エラーコード + debugText の応答を書く共通処理。
    fn write_error_response(
        resp: &mut CmdResponder<'_, '_>,
        response_id: u32,
        error_code: u8,
    ) -> Result<(), ImStatus> {
        let w = open_response(resp, response_id)?;
        w.write_u8(&crate::tlv::TlvTag::ContextSpecific(0), error_code)
            .map_err(map_tlv)?;
        w.write_utf8(&crate::tlv::TlvTag::ContextSpecific(1), "")
            .map_err(map_tlv)?;
        close_response(w)
    }

    /// コマンドを処理する。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            // ArmFailSafe → ArmFailSafeResponse(0x01)。
            0x00 => {
                let mut expiry_s: u16 = 0;
                let mut breadcrumb: u64 = 0;
                let mut f = Fields::new(fields);
                while let Some((tag, v)) = f.next() {
                    match tag {
                        0 => expiry_s = v.as_unsigned().unwrap_or(0) as u16,
                        1 => breadcrumb = v.as_unsigned().unwrap_or(0),
                        _ => {}
                    }
                }
                let was_armed = self.fail_safe.is_armed();
                self.fail_safe.arm(expiry_s, breadcrumb, acc.now_ms);
                self.dirty.mark();
                // ArmFailSafe(expiry=0) で armed 中の解除は「fail-safe クリーンアップ」と同じ
                // 巻き戻し(未 CommissioningComplete の fabric / ACL / セッション破棄)を伴う
                // (Core Spec §11.10)。統合層に掃除を要求する。
                if expiry_s == 0 && was_armed {
                    resp.request_failsafe_cleanup();
                }
                Self::write_error_response(resp, 0x01, commissioning_error::OK)
            }
            // SetRegulatoryConfig → SetRegulatoryConfigResponse(0x03)。
            0x02 => {
                let mut new_config: u8 = self.regulatory_config;
                let mut breadcrumb: Option<u64> = None;
                let mut f = Fields::new(fields);
                while let Some((tag, v)) = f.next() {
                    match tag {
                        0 => new_config = v.as_unsigned().unwrap_or(0) as u8,
                        // 1: countryCode(string) はスキップ。
                        2 => breadcrumb = Some(v.as_unsigned().unwrap_or(0)),
                        _ => {}
                    }
                }
                if new_config > regulatory::INDOOR_OUTDOOR {
                    return Self::write_error_response(
                        resp,
                        0x03,
                        commissioning_error::VALUE_OUTSIDE_RANGE,
                    );
                }
                self.regulatory_config = new_config;
                if let Some(b) = breadcrumb {
                    self.fail_safe.breadcrumb = b;
                }
                self.dirty.mark();
                Self::write_error_response(resp, 0x03, commissioning_error::OK)
            }
            // CommissioningComplete → CommissioningCompleteResponse(0x05)。
            0x04 => {
                let error = if self.fail_safe.is_armed() {
                    self.fail_safe.disarm();
                    // fail-safe 中に追加した fabric を確定する(以降 fail-safe で巻き戻さない、
                    // Core Spec §11.10)。統合層が OpCreds へ配線する。
                    resp.request_commissioning_complete();
                    commissioning_error::OK
                } else {
                    // fail-safe 未アームでも初期実装では成功応答を返す(骨格)。
                    commissioning_error::OK
                };
                self.dirty.mark();
                let _ = fields;
                Self::write_error_response(resp, 0x05, error)
            }
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for GeneralCommissioning {
    fn default() -> Self {
        Self::default_config()
    }
}

cluster! {
    GeneralCommissioning {
        id: 0x0030,
        revision: 1,
        feature_map: 0,
        dirty: dirty,
        invoke: (|c: &mut GeneralCommissioning, cmd, fields, resp, acc| c.invoke_cmd(cmd, fields, resp, acc)),
        attributes: [
            0x0000 Breadcrumb {
                access: View, quality: [], subscribe: true,
                read: (|c: &GeneralCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_u64(c.fail_safe.breadcrumb)),
                write: (Administer, |c: &mut GeneralCommissioning, data, acc| c.write_breadcrumb(data, acc))
            },
            0x0001 BasicCommissioningInfo {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &GeneralCommissioning, e: &mut AttrEncoder<'_, '_>| c.read_basic_info(e)),
                write: _
            },
            0x0002 RegulatoryConfig {
                access: View, quality: [], subscribe: false,
                read: (|c: &GeneralCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.regulatory_config)),
                write: _
            },
            0x0003 LocationCapability {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &GeneralCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.location_capability)),
                write: _
            },
            0x0004 SupportsConcurrentConnection {
                access: View, quality: [FIXED], subscribe: false,
                read: (|c: &GeneralCommissioning, e: &mut AttrEncoder<'_, '_>| e.write_bool(c.supports_concurrent_connection)),
                write: _
            },
        ],
        accepted: [ 0x00 ArmFailSafe => Administer, 0x02 SetRegulatoryConfig => Administer, 0x04 CommissioningComplete => Administer ],
        generated: [ 0x01, 0x03, 0x05 ],
    }
}
