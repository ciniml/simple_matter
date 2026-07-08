//! Switch クラスタ(0x003B、`docs/design/basic-clusters.md` §2.1)。
//!
//! Generic Switch(壁スイッチ・ボタン)の押下/ラッチ状態を表す。共通属性は
//! NumberOfPositions(0x0000)と CurrentPosition(0x0001)。イベントは「クラスタが積み、
//! アプリが [`stack.post_event`](crate::stack::MatterStack::post_event) へ運ぶ」契約
//! (設計 §0.2)で、pending は固定長リング(4)に積み [`take_event`] で回収する。
//!
//! FeatureMap は**型レベル定数**のため(設計 §0-3)、momentary と latching を別型で提供する。
//! 共通状態は [`SwitchCore`] に集約して重複を最小化する。
//!
//! - [`SwitchCluster`]: momentary(MS|MSR = 0x06)。`press`/`release` で InitialPress(0x01)/
//!   ShortRelease(0x03)を積む。
//! - [`LatchingSwitchCluster`]: latching(LS = 0x01)。`set_position` で SwitchLatched(0x00)を積む。
//!
//! MultiPress / LongPress(MSM/MSL feature)はスコープ外(設計 §0-5)。
//!
//! [`take_event`]: SwitchCluster::take_event

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::codec::AttrEncoder;
use crate::dm::meta::EventId;

/// SwitchLatched イベント ID(0x00)。
const EV_SWITCH_LATCHED: u32 = 0x00;
/// InitialPress イベント ID(0x01)。
const EV_INITIAL_PRESS: u32 = 0x01;
/// ShortRelease イベント ID(0x03)。
const EV_SHORT_RELEASE: u32 = 0x03;

/// pending イベントリングの固定長(設計 §2.1)。
const EVENT_RING: usize = 4;

/// クラスタが積み、アプリが回収する Switch イベント(設計 §2.1)。
///
/// `id` はイベント ID(SwitchLatched=0x00 / InitialPress=0x01 / ShortRelease=0x03)、
/// `position` は該当位置(newPosition もしくは previousPosition)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchEvent {
    /// イベント ID。
    pub id: EventId,
    /// イベントの位置引数(`{ 0: position }`)。
    pub position: u8,
}

/// pending イベントの固定長リング(容量 [`EVENT_RING`])。
///
/// 満杯時は最古を上書きする(FIFO のリングバッファ)。
#[derive(Debug)]
struct EventRing {
    buf: [Option<SwitchEvent>; EVENT_RING],
    head: usize,
    len: usize,
}

impl EventRing {
    const fn new() -> Self {
        Self {
            buf: [None; EVENT_RING],
            head: 0,
            len: 0,
        }
    }

    /// イベントを末尾に積む。満杯なら最古を捨てる。
    fn push(&mut self, ev: SwitchEvent) {
        let tail = (self.head + self.len) % EVENT_RING;
        self.buf[tail] = Some(ev);
        if self.len == EVENT_RING {
            self.head = (self.head + 1) % EVENT_RING;
        } else {
            self.len += 1;
        }
    }

    /// 最古のイベントを取り出す(FIFO)。空なら `None`。
    fn take(&mut self) -> Option<SwitchEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.buf[self.head].take();
        self.head = (self.head + 1) % EVENT_RING;
        self.len -= 1;
        ev
    }
}

/// momentary / latching が共有する Switch の内部状態(設計 §2.1)。
#[derive(Debug)]
struct SwitchCore {
    /// NumberOfPositions(0x0000、既定 2)。
    number_of_positions: u8,
    /// CurrentPosition(0x0001)。
    current_position: u8,
    /// pending イベントリング。
    events: EventRing,
}

impl SwitchCore {
    const fn new(number_of_positions: u8) -> Self {
        Self {
            number_of_positions,
            current_position: 0,
            events: EventRing::new(),
        }
    }

    /// CurrentPosition を設定する。変化した場合のみ `true` を返す(dirty はラッパが立てる)。
    fn set_position(&mut self, pos: u8) -> bool {
        if self.current_position != pos {
            self.current_position = pos;
            true
        } else {
            false
        }
    }

    /// イベントを積む。
    fn push(&mut self, id: u32, position: u8) {
        self.events.push(SwitchEvent {
            id: EventId(id),
            position,
        });
    }
}

/// Switch クラスタ(momentary、0x003B、FeatureMap=MS|MSR=0x06)。
#[derive(Debug)]
pub struct SwitchCluster {
    core: SwitchCore,
    dirty: Dirty,
}

impl SwitchCluster {
    /// 既定(NumberOfPositions=2)の momentary スイッチを作る。
    pub const fn new() -> Self {
        Self {
            core: SwitchCore::new(2),
            dirty: Dirty::new(),
        }
    }

    /// NumberOfPositions を指定して作る。
    pub const fn with_positions(number_of_positions: u8) -> Self {
        Self {
            core: SwitchCore::new(number_of_positions),
            dirty: Dirty::new(),
        }
    }

    /// 現在の CurrentPosition を返す(取得 API)。
    pub const fn current_position(&self) -> u8 {
        self.core.current_position
    }

    /// 押下する。CurrentPosition を `new_position` に更新し InitialPress(0x01、
    /// `{ 0: newPosition }`)を積む(設計 §2.1)。
    pub fn press(&mut self, new_position: u8) {
        if self.core.set_position(new_position) {
            self.dirty.mark();
        }
        self.core.push(EV_INITIAL_PRESS, new_position);
    }

    /// 離す。CurrentPosition を 0(中立)に戻し ShortRelease(0x03、
    /// `{ 0: previousPosition }`)を積む(設計 §2.1)。
    pub fn release(&mut self) {
        let previous = self.core.current_position;
        if self.core.set_position(0) {
            self.dirty.mark();
        }
        self.core.push(EV_SHORT_RELEASE, previous);
    }

    /// pending の [`SwitchEvent`] を回収する(アプリが `post_event` へ運ぶ、設計 §2.1)。
    pub fn take_event(&mut self) -> Option<SwitchEvent> {
        self.core.events.take()
    }
}

impl Default for SwitchCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    SwitchCluster {
        id: 0x003B,
        revision: 1,
        // FeatureMap bit1 = MomentarySwitch / bit2 = MomentarySwitchRelease(設計 §2.1)。
        feature_map: 0x06,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 NumberOfPositions {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &SwitchCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.core.number_of_positions)),
                write: _
            },
            0x0001 CurrentPosition {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &SwitchCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.core.current_position)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}

/// Latching Switch クラスタ(0x003B、FeatureMap=LS=0x01)。
#[derive(Debug)]
pub struct LatchingSwitchCluster {
    core: SwitchCore,
    dirty: Dirty,
}

impl LatchingSwitchCluster {
    /// 既定(NumberOfPositions=2)の latching スイッチを作る。
    pub const fn new() -> Self {
        Self {
            core: SwitchCore::new(2),
            dirty: Dirty::new(),
        }
    }

    /// NumberOfPositions を指定して作る。
    pub const fn with_positions(number_of_positions: u8) -> Self {
        Self {
            core: SwitchCore::new(number_of_positions),
            dirty: Dirty::new(),
        }
    }

    /// 現在の CurrentPosition を返す(取得 API)。
    pub const fn current_position(&self) -> u8 {
        self.core.current_position
    }

    /// 位置を切り替える。変化時のみ CurrentPosition を更新し SwitchLatched(0x00、
    /// `{ 0: newPosition }`)を積む(設計 §2.1)。
    pub fn set_position(&mut self, new_position: u8) {
        if self.core.set_position(new_position) {
            self.dirty.mark();
            self.core.push(EV_SWITCH_LATCHED, new_position);
        }
    }

    /// pending の [`SwitchEvent`] を回収する(アプリが `post_event` へ運ぶ、設計 §2.1)。
    pub fn take_event(&mut self) -> Option<SwitchEvent> {
        self.core.events.take()
    }
}

impl Default for LatchingSwitchCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    LatchingSwitchCluster {
        id: 0x003B,
        revision: 1,
        // FeatureMap bit0 = LatchingSwitch(設計 §2.1)。
        feature_map: 0x01,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 NumberOfPositions {
                access: View,
                quality: [FIXED],
                subscribe: false,
                read: (|c: &LatchingSwitchCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.core.number_of_positions)),
                write: _
            },
            0x0001 CurrentPosition {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &LatchingSwitchCluster, e: &mut AttrEncoder<'_, '_>| e.write_u8(c.core.current_position)),
                write: _
            },
        ],
        accepted: [],
        generated: [],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dm::meta::{AccessContext, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    fn assert_all_readable<C: ServerCluster>(c: &C) {
        let mut buf = [0u8; 16];
        for am in c.meta().attributes {
            let mut w = TlvWriter::new(&mut buf);
            let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
            assert!(
                c.read_attribute(am.id, &mut e, &acc()).is_ok(),
                "attr {:#06x} read failed",
                am.id.0
            );
        }
    }

    #[test]
    fn momentary_meta() {
        let c = SwitchCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x003B);
        assert_eq!(meta.revision, 1);
        assert_eq!(meta.feature_map, 0x06);
        // 固有属性 2 個(NumberOfPositions / CurrentPosition)、コマンド無し。
        assert_eq!(meta.attributes.len(), 2);
        assert!(meta.accepted_commands.is_empty());
        assert_all_readable(&c);
    }

    #[test]
    fn latching_meta() {
        let c = LatchingSwitchCluster::new();
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x003B);
        assert_eq!(meta.feature_map, 0x01);
        assert_eq!(meta.attributes.len(), 2);
        assert_all_readable(&c);
    }

    #[test]
    fn momentary_press_release_events() {
        let mut c = SwitchCluster::new();
        assert_eq!(c.take_event(), None);

        // press(1): CurrentPosition=1、dirty、InitialPress(0x01、{0:1})。
        c.press(1);
        assert_eq!(c.current_position(), 1);
        assert!(c.take_dirty());
        assert_eq!(
            c.take_event(),
            Some(SwitchEvent {
                id: EventId(EV_INITIAL_PRESS),
                position: 1
            })
        );

        // release(): CurrentPosition=0、dirty、ShortRelease(0x03、{0:1(previous)})。
        c.release();
        assert_eq!(c.current_position(), 0);
        assert!(c.take_dirty());
        assert_eq!(
            c.take_event(),
            Some(SwitchEvent {
                id: EventId(EV_SHORT_RELEASE),
                position: 1
            })
        );
        assert_eq!(c.take_event(), None);
    }

    #[test]
    fn latching_set_position_events() {
        let mut c = LatchingSwitchCluster::new();
        // 0 → 1: SwitchLatched(0x00、{0:1})。
        c.set_position(1);
        assert_eq!(c.current_position(), 1);
        assert!(c.take_dirty());
        assert_eq!(
            c.take_event(),
            Some(SwitchEvent {
                id: EventId(EV_SWITCH_LATCHED),
                position: 1
            })
        );
        // 同値の再設定ではイベントも dirty も立てない。
        c.set_position(1);
        assert!(!c.take_dirty());
        assert_eq!(c.take_event(), None);
        // 1 → 0。
        c.set_position(0);
        assert!(c.take_dirty());
        assert_eq!(
            c.take_event(),
            Some(SwitchEvent {
                id: EventId(EV_SWITCH_LATCHED),
                position: 0
            })
        );
    }

    #[test]
    fn event_ring_is_fifo_and_bounded() {
        let mut c = SwitchCluster::new();
        // 5 個積む(容量 4)→ 最古が捨てられ、残り 4 個が FIFO で取れる。
        for i in 1..=5u8 {
            c.press(i);
        }
        // 最古(press(1))が捨てられ、2,3,4,5 が残る。
        for i in 2..=5u8 {
            assert_eq!(
                c.take_event(),
                Some(SwitchEvent {
                    id: EventId(EV_INITIAL_PRESS),
                    position: i
                })
            );
        }
        assert_eq!(c.take_event(), None);
    }
}
