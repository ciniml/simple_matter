//! On/Off クラスタ(0x0006、`docs/design/interaction-model.md` §9.1)。
//!
//! `OnOff` 属性(bool)と On/Off/Toggle コマンドを持つ最小構成。状態変更で dirty フラグを
//! 立て、アプリへの通知フック(取得 API [`OnOffCluster::is_on`] とコールバック
//! [`OnOffCluster::with_listener`])を提供する。FeatureMap=0(Lighting feature は後日)。

use crate::cluster;
use crate::dm::cluster::Dirty;
use crate::dm::meta::CommandId;
use crate::im::wire::ImStatus;

/// On/Off クラスタ(0x0006)。
#[derive(Debug)]
pub struct OnOffCluster {
    /// OnOff 属性(0x0000)。
    on_off: bool,
    /// dirty フラグ(Subscribe 用)。
    dirty: Dirty,
    /// 状態変更通知コールバック(任意)。
    on_change: Option<fn(bool)>,
}

impl OnOffCluster {
    /// Off 状態のクラスタを作る。
    pub const fn new() -> Self {
        Self {
            on_off: false,
            dirty: Dirty::new(),
            on_change: None,
        }
    }

    /// 状態変更通知コールバックを登録する。
    pub fn with_listener(mut self, cb: fn(bool)) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// 現在の OnOff 状態を返す(取得 API)。
    pub const fn is_on(&self) -> bool {
        self.on_off
    }

    /// 状態を設定する。変化時のみ dirty を立て、コールバックを呼ぶ。
    pub fn set(&mut self, v: bool) {
        if self.on_off != v {
            self.on_off = v;
            self.dirty.mark();
            if let Some(cb) = self.on_change {
                cb(v);
            }
        }
    }

    /// Off(0x00)/On(0x01)/Toggle(0x02)コマンドを処理する。
    fn invoke_cmd(&mut self, cmd: CommandId) -> Result<(), ImStatus> {
        match cmd.0 {
            0x00 => {
                self.set(false);
                Ok(())
            }
            0x01 => {
                self.set(true);
                Ok(())
            }
            0x02 => {
                self.set(!self.on_off);
                Ok(())
            }
            _ => Err(ImStatus::UnsupportedCommand),
        }
    }
}

impl Default for OnOffCluster {
    fn default() -> Self {
        Self::new()
    }
}

cluster! {
    OnOffCluster {
        id: 0x0006,
        revision: 6,
        feature_map: 0,
        dirty: dirty,
        invoke: (|c: &mut OnOffCluster, cmd, _f, _r, _a| c.invoke_cmd(cmd)),
        attributes: [
            0x0000 OnOff {
                access: View,
                quality: [NONVOLATILE, SCENE],
                subscribe: true,
                read: (|c: &OnOffCluster, e: &mut crate::dm::codec::AttrEncoder<'_, '_>| e.write_bool(c.on_off)),
                write: _
            },
        ],
        accepted: [ 0x0000 Off, 0x0001 On, 0x0002 Toggle ],
        generated: [],
    }
}
