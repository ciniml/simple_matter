//! Door Lock クラスタ(0x0101、`docs/design/basic-clusters.md` §6)。
//!
//! 最小実用構成(feature_map = 0): LockState / LockType / ActuatorEnabled /
//! OperatingMode / SupportedOperatingModes と、timed invoke 必須の LockDoor /
//! UnlockDoor、LockOperation イベント(pending キュー → アプリが
//! [`take_event`](DoorLockCluster::take_event) で `stack.post_event` へ運ぶ契約、
//! 設計 §0.2)を提供する。
//!
//! # スコープ外(設計 §6)
//!
//! credential 管理(SetCredential/SetUser 等の USR/PIN feature 系)、Schedule 系、
//! AutoRelockTime、DoorLockAlarm / LockOperationError / DoorStateChange イベント。
//! PINCode フィールドは受理して**無視**する(feature 無し構成では
//! requirePINforRemoteOperation が存在せず PIN なし操作が仕様上許可される。
//! chip door-lock-server.cpp の requirePin=false 経路)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::{AttrEncoder, CmdResponder};
use crate::dm::meta::{AccessContext, CommandId};
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// LockState: 完全施錠でない(ジャム等)。
pub const LOCK_STATE_NOT_FULLY_LOCKED: u8 = 0;
/// LockState: 施錠。
pub const LOCK_STATE_LOCKED: u8 = 1;
/// LockState: 解錠。
pub const LOCK_STATE_UNLOCKED: u8 = 2;

/// LockType: デッドボルト(既定)。
pub const LOCK_TYPE_DEAD_BOLT: u8 = 2;

/// OperatingMode: 通常。
pub const OPERATING_MODE_NORMAL: u8 = 0;

/// SupportedOperatingModes(map16、ビット反転表現 = 0 のビットがサポート)。XML 既定。
pub const SUPPORTED_OPERATING_MODES: u16 = 0xFFF6;

/// LockOperation イベント(0x02)の 1 件(`take_event` でアプリが回収する)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOperationEvent {
    /// LockOperationType(0=Lock / 1=Unlock)。
    pub lock_operation_type: u8,
    /// 操作元 fabric index(リモート操作の AccessContext から。無ければ None)。
    pub fabric_index: Option<u8>,
    /// 操作元 NodeId(同上)。
    pub source_node: Option<u64>,
}

/// pending イベントリングの容量(Lock+Unlock の連打でも十分)。
const EVENT_RING: usize = 4;

/// Door Lock クラスタ(0x0101)。
#[derive(Debug)]
pub struct DoorLockCluster {
    /// LockState(0x0000、nullable enum8。None = null)。
    lock_state: Option<u8>,
    /// LockType(0x0001、enum8、固定)。
    lock_type: u8,
    /// OperatingMode(0x0025、enum8 0-4、rw、保存のみ)。
    operating_mode: u8,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// 施錠/解錠の通知コールバック(任意。true = Locked)。
    on_change: Option<fn(bool)>,
    /// pending の LockOperation イベントリング(満杯時は最古を上書き)。
    events: [Option<LockOperationEvent>; EVENT_RING],
    /// リングの読み出し位置。
    rd: usize,
    /// リングの書き込み位置。
    wr: usize,
}

impl DoorLockCluster {
    /// 初期状態(Locked、DeadBolt、Normal)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            lock_state: Some(LOCK_STATE_LOCKED),
            lock_type: LOCK_TYPE_DEAD_BOLT,
            operating_mode: OPERATING_MODE_NORMAL,
            dirty: Dirty::new(),
            on_change: None,
            events: [None; EVENT_RING],
            rd: 0,
            wr: 0,
        }
    }

    /// LockType を指定した複製を返す(既定 2=DeadBolt)。
    pub const fn with_lock_type(mut self, lock_type: u8) -> Self {
        self.lock_type = lock_type;
        self
    }

    /// 施錠/解錠の通知コールバックを登録する(on_off.rs と同型。true = Locked)。
    pub fn with_listener(mut self, cb: fn(bool)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の LockState(None = null)。
    pub const fn lock_state(&self) -> Option<u8> {
        self.lock_state
    }

    /// 施錠中か。
    pub fn is_locked(&self) -> bool {
        self.lock_state == Some(LOCK_STATE_LOCKED)
    }

    /// pending の LockOperation イベントを 1 件取り出す(設計 §6)。
    ///
    /// アプリループが回収し、`stack.post_event(ep, 0x0101, 2, CRITICAL, ...)` へ運ぶ。
    pub fn take_event(&mut self) -> Option<LockOperationEvent> {
        let e = self.events[self.rd].take()?;
        self.rd = (self.rd + 1) % EVENT_RING;
        Some(e)
    }

    /// LockOperation イベントを積む(満杯時は最古を上書き)。
    fn push_event(&mut self, e: LockOperationEvent) {
        if self.events[self.wr].is_some() {
            // 上書き = 最古を破棄(読み出し位置も進める)。
            self.rd = (self.wr + 1) % EVENT_RING;
        }
        self.events[self.wr] = Some(e);
        self.wr = (self.wr + 1) % EVENT_RING;
    }

    /// Lock / Unlock の実処理(コマンド + アプリ操作の共通経路)。
    fn set_lock_state(&mut self, state: u8, acc: Option<&AccessContext>) {
        if self.lock_state != Some(state) {
            self.lock_state = Some(state);
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(state == LOCK_STATE_LOCKED);
            }
        }
        // 操作イベントは状態が同じでも発火する(施錠済みへの再施錠も操作、chip 同様)。
        self.push_event(LockOperationEvent {
            lock_operation_type: if state == LOCK_STATE_LOCKED { 0 } else { 1 },
            fabric_index: acc.and_then(|a| a.fabric_idx).map(|f| f.get()),
            source_node: acc.map(|a| a.subject),
        });
    }

    /// OperatingMode(0x0025)を書く(0-4 のみ、保存のみ)。
    fn write_operating_mode(
        &mut self,
        data: crate::dm::AttrWrite<'_>,
        _acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > 4 {
            return Err(ImStatus::ConstraintError);
        }
        if self.operating_mode != v as u8 {
            self.operating_mode = v as u8;
            self.dirty.mark();
        }
        Ok(())
    }

    /// コマンドを処理する(LockDoor 0x00 / UnlockDoor 0x01。PINCode は無視)。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        _fields: &mut TlvReader<'_>,
        _resp: &mut CmdResponder<'_, '_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => {
                self.set_lock_state(LOCK_STATE_LOCKED, Some(acc));
                Ok(())
            }
            0x01 => {
                self.set_lock_state(LOCK_STATE_UNLOCKED, Some(acc));
                Ok(())
            }
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for DoorLockCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    DoorLockCluster {
        id: 0x0101,
        revision: 7,
        feature_map: 0,
        dirty: dirty,
        invoke: (|c: &mut DoorLockCluster, cmd, fields, resp, acc| c.invoke_cmd(cmd, fields, resp, acc)),
        attributes: [
            0x0000 LockState {
                access: View,
                quality: [NULLABLE],
                subscribe: true,
                read: (|c: &DoorLockCluster, e: &mut AttrEncoder<'_, '_>| e.write_nullable_u8(c.lock_state)),
                write: _
            },
            0x0001 LockType {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &DoorLockCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.lock_type)),
                write: _
            },
            0x0002 ActuatorEnabled {
                access: View,
                quality: [],
                subscribe: false,
                read: (|_c: &DoorLockCluster, e: &mut AttrEncoder<'_, '_>| e.write_bool(true)),
                write: _
            },
            0x0025 OperatingMode {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &DoorLockCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.operating_mode)),
                write: (Manage, |c: &mut DoorLockCluster, data, acc| c.write_operating_mode(data, acc))
            },
            0x0026 SupportedOperatingModes {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|_c: &DoorLockCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(SUPPORTED_OPERATING_MODES)),
                write: _
            },
        ],
        accepted: [ 0x00 LockDoor @ timed, 0x01 UnlockDoor @ timed ],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::AttrEncoder;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::{AttrWrite, ServerCluster};
    use crate::tlv::{TlvReader, TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(
            SessionKind::Case,
            NonZeroU8::new(1),
            0x1B669,
            Privilege::Operate,
        )
        .with_env(0, [0u8; 16])
    }

    fn invoke(c: &mut DoorLockCluster, cmd: u32) -> Result<(), ImStatus> {
        let mut fr = TlvReader::new(&[]);
        let mut buf = [0u8; 64];
        let mut w = TlvWriter::new(&mut buf);
        let mut resp = CmdResponder::new(&mut w);
        c.invoke_command(CommandId(cmd), &mut fr, &mut resp, &acc())
    }

    #[test]
    fn lock_unlock_state_and_events() {
        let mut c = DoorLockCluster::new();
        assert!(c.is_locked());
        assert!(c.take_event().is_none());

        // Unlock → 状態変化 + dirty + イベント。
        invoke(&mut c, 0x01).unwrap();
        assert_eq!(c.lock_state(), Some(LOCK_STATE_UNLOCKED));
        assert!(c.take_dirty());
        let e = c.take_event().unwrap();
        assert_eq!(e.lock_operation_type, 1);
        assert_eq!(e.fabric_index, Some(1));
        assert_eq!(e.source_node, Some(0x1B669));

        // Lock。
        invoke(&mut c, 0x00).unwrap();
        assert!(c.is_locked());
        assert!(c.take_dirty());
        assert_eq!(c.take_event().unwrap().lock_operation_type, 0);

        // 同状態への再施錠: dirty は立たないがイベントは出る(操作イベント)。
        invoke(&mut c, 0x00).unwrap();
        assert!(!c.take_dirty());
        assert_eq!(c.take_event().unwrap().lock_operation_type, 0);
        assert!(c.take_event().is_none());
    }

    #[test]
    fn event_ring_overwrites_oldest() {
        let mut c = DoorLockCluster::new();
        for _ in 0..3 {
            invoke(&mut c, 0x00).unwrap();
            invoke(&mut c, 0x01).unwrap();
        }
        // 6 件発生 → リング 4 なので最古 2 件は破棄、残り 4 件が順に出る。
        let mut n = 0;
        while c.take_event().is_some() {
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn operating_mode_write_validation() {
        let mut c = DoorLockCluster::new();
        // 0-4 は受理。
        let mut buf = [0u8; 8];
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.write_u8(&TlvTag::Anonymous, 3).unwrap();
            w.len()
        };
        c.write_attribute(AttributeId(0x0025), AttrWrite::new(&buf[..n]), &acc())
            .unwrap();
        assert!(c.take_dirty());

        // 5 は ConstraintError。
        let n = {
            let mut w = TlvWriter::new(&mut buf);
            w.write_u8(&TlvTag::Anonymous, 5).unwrap();
            w.len()
        };
        assert_eq!(
            c.write_attribute(AttributeId(0x0025), AttrWrite::new(&buf[..n]), &acc()),
            Err(ImStatus::ConstraintError)
        );
    }

    #[test]
    fn meta_declares_timed_commands_and_nullable_state() {
        let c = DoorLockCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0101);
        assert_eq!(meta.revision, 7);
        assert_eq!(meta.feature_map, 0);
        // LockDoor / UnlockDoor は timed 必須。
        for cmd in meta.accepted_commands {
            assert!(cmd.timed, "cmd 0x{:02x} must be timed", cmd.id.0);
        }
        // LockState は読める(初期 Locked=1)。
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        {
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            c.read_attribute(AttributeId(0x0000), &mut e, &acc())
                .unwrap();
        }
        let len = w.len();
        let mut r = TlvReader::new(&buf[..len]);
        let el = r.read_next().unwrap().unwrap();
        assert_eq!(el.value.as_unsigned().unwrap(), 1);
    }
}
