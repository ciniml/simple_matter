//! Switch クラスタ(0x003B)の名前テーブル。
//!
//! momentary / latching 共通の名前表。イベントは simple_matter が press/release/set_position で
//! post する { 0: position(u8) }(設計 §2.1)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x003B, "switch") {
        attrs {
            0x0000 => "number-of-positions": U8;
            0x0001 => "current-position": U8;
        }
        cmds {}
        events {
            0x0000 => "switch-latched";
            0x0001 => "initial-press";
            0x0003 => "short-release";
        }
    }
}
