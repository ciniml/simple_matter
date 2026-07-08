//! Identify クラスタ(0x0003、`docs/design/basic-clusters.md` §1.1)。
//!
//! コミッショナからの「識別要求」を受けて一定時間デバイスを目立たせる(LED 点滅等)ための
//! 最小クラスタ。`IdentifyTime`(0x0000、秒)を [`ServerCluster::tick`](crate::dm::ServerCluster::tick)
//! で 1 秒刻みに自減させ、識別中/終了をアプリへ [`with_listener`](IdentifyCluster::with_listener)
//! で通知する(example は println / LED)。
//!
//! FeatureMap=0、revision 4。TriggerEffect(0x40)は任意 → 非実装(設計 §1.1)。
//!
//! # dirty の方針(設計 §1.1)
//!
//! dirty は「識別の開始/終了」の遷移時のみ立てる。毎秒の減衰では立てない(Level Control の
//! RemainingTime と同じ方針)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::clusters::cmd::Fields;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::{AccessContext, CommandId};
use crate::dm::AttrWrite;
use crate::im::wire::ImStatus;
use crate::tlv::TlvReader;

/// IdentifyType の既定値(2 = VisibleIndicator。表示灯で識別する)。
const IDENTIFY_TYPE_VISIBLE_INDICATOR: u8 = 2;
/// 減衰の 1 刻み(ms)。IdentifyTime は秒単位なので 1000ms ごとに 1 減らす。
const TICK_STEP_MS: u64 = 1_000;

/// Identify クラスタ(0x0003)。
pub struct IdentifyCluster {
    /// IdentifyTime(0x0000、u16、秒)。
    identify_time: u16,
    /// IdentifyType(0x0001、enum8、固定値)。
    identify_type: u8,
    /// 次に減衰処理する絶対時刻(ms)。`identify_time > 0` の間だけ意味を持つ。
    next_tick_ms: u64,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// 識別中/終了の通知コールバック(任意。識別開始→true / 終了→false)。
    on_change: Option<fn(bool)>,
}

impl IdentifyCluster {
    /// 初期状態(IdentifyTime=0、IdentifyType=VisibleIndicator)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            identify_time: 0,
            identify_type: IDENTIFY_TYPE_VISIBLE_INDICATOR,
            next_tick_ms: 0,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// IdentifyType を指定した複製を返す(既定 2=VisibleIndicator。設計 §1.1)。
    pub const fn with_type(mut self, identify_type: u8) -> Self {
        self.identify_type = identify_type;
        self
    }

    /// 識別中/終了の通知コールバックを登録する(on_off.rs と同型)。
    pub fn with_listener(mut self, cb: fn(bool)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の IdentifyTime(取得 API)。
    pub const fn identify_time(&self) -> u16 {
        self.identify_time
    }

    /// 識別中か(取得 API)。
    pub const fn is_identifying(&self) -> bool {
        self.identify_time > 0
    }

    /// IdentifyTime を設定して識別を開始/更新/停止する(設計 §1.1)。
    ///
    /// `seconds > 0` は識別中、`0` は停止。dirty とコールバックは「開始/終了の遷移時のみ」
    /// 立てる(識別中に値だけ変える場合や毎秒の減衰では立てない)。
    fn set_identify_time(&mut self, seconds: u16, now_ms: u64) {
        let was_active = self.identify_time > 0;
        self.identify_time = seconds;
        if seconds > 0 {
            self.next_tick_ms = now_ms.saturating_add(TICK_STEP_MS);
            if !was_active {
                // 停止 → 識別中の遷移。
                self.dirty.mark();
                if let Some(cb) = self.on_change {
                    cb(true);
                }
            }
        } else if was_active {
            // 識別中 → 停止の遷移。
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(false);
            }
        }
    }

    /// 減衰エンジンの 1 ステップ(設計 §1.1/§15.1)。
    ///
    /// `identify_time > 0` の間、1 秒刻みで自減する。0 に到達したら終了として dirty +
    /// コールバック(false)。途中の減衰では dirty を立てない。
    fn on_tick(&mut self, now_ms: u64) -> Option<u64> {
        if self.identify_time == 0 {
            return None;
        }
        // now が複数秒進んでいれば必要分をまとめて減らす。
        while self.identify_time > 0 && now_ms >= self.next_tick_ms {
            self.identify_time -= 1;
            self.next_tick_ms = self.next_tick_ms.saturating_add(TICK_STEP_MS);
        }
        if self.identify_time == 0 {
            // 識別終了。
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(false);
            }
            return None;
        }
        Some(self.next_tick_ms)
    }

    // --- 属性 write ---

    /// IdentifyTime(0x0000)への write。仕様どおり識別開始として扱う(設計 §1.1)。
    fn write_identify_time(
        &mut self,
        data: AttrWrite<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let v = data.as_unsigned()?;
        if v > u16::MAX as u64 {
            return Err(ImStatus::ConstraintError);
        }
        self.set_identify_time(v as u16, acc.now_ms);
        Ok(())
    }

    // --- コマンド ---

    /// Identify(0x00): `{ 0: identifyTime u16 }`。IdentifyTime write と等価。
    fn cmd_identify(
        &mut self,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        let mut time: Option<u16> = None;
        let mut f = Fields::new(fields);
        while let Some((tag, v)) = f.next() {
            if tag == 0 {
                time = v.as_unsigned().ok().map(|x| x as u16);
            }
        }
        let time = time.ok_or(ImStatus::InvalidCommand)?;
        self.set_identify_time(time, acc.now_ms);
        Ok(())
    }

    /// コマンドディスパッチ(0x00 のみ)。
    fn invoke_cmd(
        &mut self,
        cmd: CommandId,
        fields: &mut TlvReader<'_>,
        acc: &AccessContext,
    ) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => self.cmd_identify(fields, acc),
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for IdentifyCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    IdentifyCluster {
        id: 0x0003,
        revision: 4,
        feature_map: 0,
        dirty: dirty,
        tick: on_tick,
        invoke: (|c: &mut IdentifyCluster, cmd, fields, _resp, acc| {
            c.invoke_cmd(cmd, fields, acc)
        }),
        attributes: [
            0x0000 IdentifyTime {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &IdentifyCluster, e: &mut AttrEncoder<'_, '_>| e.write_u16(c.identify_time)),
                write: (Operate, |c: &mut IdentifyCluster, data, acc| c.write_identify_time(data, acc))
            },
            0x0001 IdentifyType {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &IdentifyCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.identify_type)),
                write: _
            },
        ],
        accepted: [
            0x00 Identify,
        ],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::codec::CmdResponder;
    use crate::dm::meta::{AccessContext, AttributeId, Privilege, SessionKind};
    use crate::dm::{AttrWrite, ServerCluster};
    use crate::tlv::{ContainerType, TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc(now_ms: u64) -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(now_ms, [0u8; 16])
    }

    fn build_identify(buf: &mut [u8], time: u16) -> usize {
        let mut w = TlvWriter::new(buf);
        w.start_container(&TlvTag::Anonymous, ContainerType::Structure)
            .unwrap();
        w.write_u16(&TlvTag::ContextSpecific(0), time).unwrap();
        w.end_container().unwrap();
        w.len()
    }

    fn invoke(
        c: &mut IdentifyCluster,
        cmd: u16,
        fields: &[u8],
        now_ms: u64,
    ) -> Result<(), ImStatus> {
        let mut scratch = [0u8; 128];
        let mut sw = TlvWriter::new(&mut scratch);
        let mut resp = CmdResponder::new(&mut sw);
        let mut fr = TlvReader::new(fields);
        c.invoke_command(CommandId(cmd as u32), &mut fr, &mut resp, &acc(now_ms))
    }

    fn encode_u16_value(buf: &mut [u8], v: u16) -> usize {
        let mut w = TlvWriter::new(buf);
        w.write_u16(&TlvTag::Anonymous, v).unwrap();
        w.len()
    }

    #[test]
    fn identify_command_starts_and_decays() {
        let mut c = IdentifyCluster::new();
        assert!(!c.is_identifying());
        // Identify(3秒)開始 @ t=0。
        let mut buf = [0u8; 32];
        let n = build_identify(&mut buf, 3);
        invoke(&mut c, 0x00, &buf[..n], 0).unwrap();
        assert_eq!(c.identify_time(), 3);
        assert!(c.is_identifying());
        // 開始遷移で dirty + listener(true)。
        assert!(c.take_dirty());

        // 1 秒後 → 2、dirty は立たない。
        assert_eq!(c.tick(1_000), Some(2_000));
        assert_eq!(c.identify_time(), 2);
        assert!(!c.take_dirty());
        // 2 秒後 → 1。
        assert_eq!(c.tick(2_000), Some(3_000));
        assert_eq!(c.identify_time(), 1);
        assert!(!c.take_dirty());
        // 3 秒後 → 0(終了)、dirty が立ち tick は None。
        assert_eq!(c.tick(3_000), None);
        assert_eq!(c.identify_time(), 0);
        assert!(!c.is_identifying());
        assert!(c.take_dirty());
        // 停止後の tick は None。
        assert_eq!(c.tick(4_000), None);
    }

    #[test]
    fn tick_catches_up_multiple_seconds() {
        let mut c = IdentifyCluster::new();
        c.set_identify_time(10, 0);
        let _ = c.take_dirty();
        // 一気に 3.5 秒進む → 10 - 3 = 7。
        assert_eq!(c.tick(3_500), Some(4_000));
        assert_eq!(c.identify_time(), 7);
    }

    #[test]
    fn write_identify_time_starts_identify() {
        let mut c = IdentifyCluster::new();
        let mut buf = [0u8; 16];
        // IdentifyTime=5 を書く → 識別開始(dirty)。
        let n = encode_u16_value(&mut buf, 5);
        c.write_attribute(AttributeId(0x0000), AttrWrite::new(&buf[..n]), &acc(0))
            .unwrap();
        assert_eq!(c.identify_time(), 5);
        assert!(c.take_dirty());
        // 識別中に別の値へ更新しても遷移ではないので dirty は立てない(設計 §1.1)。
        let n = encode_u16_value(&mut buf, 8);
        c.write_attribute(AttributeId(0x0000), AttrWrite::new(&buf[..n]), &acc(1_000))
            .unwrap();
        assert_eq!(c.identify_time(), 8);
        assert!(!c.take_dirty());
        // 0 を書く → 停止遷移で dirty。
        let n = encode_u16_value(&mut buf, 0);
        c.write_attribute(AttributeId(0x0000), AttrWrite::new(&buf[..n]), &acc(2_000))
            .unwrap();
        assert_eq!(c.identify_time(), 0);
        assert!(c.take_dirty());
    }

    #[test]
    fn command_missing_field_is_invalid() {
        let mut c = IdentifyCluster::new();
        // フィールド無しの Identify → InvalidCommand。
        assert_eq!(invoke(&mut c, 0x00, &[], 0), Err(ImStatus::InvalidCommand));
        // 未知コマンド → UnsupportedCommand。
        let mut buf = [0u8; 32];
        let n = build_identify(&mut buf, 1);
        assert_eq!(
            invoke(&mut c, 0x40, &buf[..n], 0),
            Err(ImStatus::UnsupportedCommand)
        );
    }

    #[test]
    fn meta_and_reads() {
        let c = IdentifyCluster::new().with_type(2);
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0003);
        assert_eq!(meta.revision, 4);
        assert_eq!(meta.feature_map, 0);
        // 固有属性 2 個(IdentifyTime / IdentifyType)。
        assert_eq!(meta.attributes.len(), 2);
        // AcceptedCommandList = Identify(0x00)のみ。
        assert_eq!(meta.accepted_commands.len(), 1);
        assert_eq!(meta.accepted_commands[0].id.0, 0x00);
        // 全属性が read 可能。
        let mut buf = [0u8; 32];
        for am in meta.attributes {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            assert!(
                c.read_attribute(am.id, &mut e, &acc(0)).is_ok(),
                "attr {:#06x} read failed",
                am.id.0
            );
        }
    }
}
