//! Boolean State クラスタ(0x0045、`docs/design/basic-clusters.md` §1.2)。
//!
//! 接点センサ(ドア開閉・水漏れ等)の 2 値状態を表す最小クラスタ。`StateValue`(0x0000、bool)を
//! 保持し、変化時に dirty を立てて `StateChange` イベントを pending キューへ積む。イベントは
//! 「クラスタが積み、アプリが [`stack.post_event`](crate::stack::MatterStack::post_event) へ運ぶ」
//! 契約(設計 §0.2)。
//!
//! FeatureMap=0、revision 1。コマンドは無い。

use crate::cluster;
use crate::dm::cluster::Dirty;

/// Boolean State クラスタ(0x0045)。
#[derive(Debug)]
pub struct BooleanStateCluster {
    /// StateValue(0x0000、bool)。
    state_value: bool,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// pending の StateChange イベント(アプリが [`take_state_change`] で回収する)。
    ///
    /// [`take_state_change`]: BooleanStateCluster::take_state_change
    pending_event: Option<bool>,
}

impl BooleanStateCluster {
    /// 初期状態(StateValue=false)のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            state_value: false,
            dirty: Dirty::new(),
            pending_event: None,
        }
    }

    /// 初期 StateValue を指定してクラスタを作る。
    pub const fn with_state(state: bool) -> Self {
        Self {
            state_value: state,
            dirty: Dirty::new(),
            pending_event: None,
        }
    }

    /// 現在の StateValue を返す(取得 API)。
    pub const fn state(&self) -> bool {
        self.state_value
    }

    /// StateValue を設定する。変化時のみ dirty を立て、StateChange を pending に積む(設計 §1.2)。
    pub fn set_state(&mut self, v: bool) {
        if self.state_value != v {
            self.state_value = v;
            self.dirty.mark();
            self.pending_event = Some(v);
        }
    }

    /// pending の StateChange(`{ 0: stateValue bool }`)を取り出す(設計 §1.2)。
    ///
    /// アプリループが本 API で回収し、`stack.post_event(ep, 0x0045, 0, INFO, ...)` へ運ぶ。
    pub fn take_state_change(&mut self) -> Option<bool> {
        self.pending_event.take()
    }
}

impl Default for BooleanStateCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    BooleanStateCluster {
        id: 0x0045,
        revision: 1,
        feature_map: 0,
        dirty: dirty,
        invoke: _,
        attributes: [
            0x0000 StateValue {
                access: View,
                quality: [],
                subscribe: true,
                read: (|c: &BooleanStateCluster, e: &mut crate::dm::codec::AttrEncoder<'_, '_>| e.write_bool(c.state_value)),
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
    use crate::dm::codec::AttrEncoder;
    use crate::dm::meta::{AccessContext, Privilege, SessionKind};
    use crate::dm::ServerCluster;
    use crate::tlv::{TlvTag, TlvWriter};
    use core::num::NonZeroU8;

    fn acc() -> AccessContext {
        AccessContext::new(SessionKind::Case, NonZeroU8::new(1), 0, Privilege::Operate)
            .with_env(0, [0u8; 16])
    }

    #[test]
    fn set_state_dirty_and_pending_event() {
        let mut c = BooleanStateCluster::new();
        assert!(!c.state());
        assert_eq!(c.take_state_change(), None);

        // false → true: dirty + pending イベント。
        c.set_state(true);
        assert!(c.state());
        assert!(c.take_dirty());
        assert_eq!(c.take_state_change(), Some(true));
        // 回収後は空。
        assert_eq!(c.take_state_change(), None);

        // 同値の再設定では dirty もイベントも立てない。
        c.set_state(true);
        assert!(!c.take_dirty());
        assert_eq!(c.take_state_change(), None);

        // true → false。
        c.set_state(false);
        assert!(c.take_dirty());
        assert_eq!(c.take_state_change(), Some(false));
    }

    #[test]
    fn meta_and_read() {
        let c = BooleanStateCluster::with_state(true);
        let meta = c.meta();
        assert_eq!(meta.id.0, 0x0045);
        assert_eq!(meta.revision, 1);
        assert_eq!(meta.feature_map, 0);
        // 固有属性 1 個(StateValue)。
        assert_eq!(meta.attributes.len(), 1);
        // コマンド無し。
        assert!(meta.accepted_commands.is_empty());
        // StateValue が read できる。
        let mut buf = [0u8; 16];
        let mut w = TlvWriter::new(&mut buf);
        let mut e = AttrEncoder::new(&mut w, TlvTag::Anonymous);
        c.read_attribute(crate::dm::meta::AttributeId(0x0000), &mut e, &acc())
            .unwrap();
    }
}
