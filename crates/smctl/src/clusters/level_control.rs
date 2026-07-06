//! Level Control クラスタ(0x0008)の名前テーブル。
//!
//! コマンドフィールドは chip-tool と同じく全指定(nullable は `null` リテラルで書ける)。
//! 例: `smctl level-control move-to-level 128 0 0 0 <node> <ep>`

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0008, "level-control") {
        attrs {
            0x0000 => "current-level": U8;
            0x0001 => "remaining-time": U16;
            0x0002 => "min-level": U8;
            0x0003 => "max-level": U8;
            0x000F => "options": U8 rw;
            0x0010 => "on-off-transition-time": U16 rw;
            0x0011 => "on-level": U8 rw;
            0x4000 => "start-up-current-level": U8 rw;
        }
        cmds {
            0x00 => "move-to-level" {
                0 => "level": U8;
                1 => "transition-time": U16;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
            0x01 => "move" {
                0 => "move-mode": U8;
                1 => "rate": U8;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
            0x02 => "step" {
                0 => "step-mode": U8;
                1 => "step-size": U8;
                2 => "transition-time": U16;
                3 => "options-mask": U8;
                4 => "options-override": U8;
            }
            0x03 => "stop" {
                0 => "options-mask": U8;
                1 => "options-override": U8;
            }
            0x04 => "move-to-level-with-on-off" {
                0 => "level": U8;
                1 => "transition-time": U16;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
            0x05 => "move-with-on-off" {
                0 => "move-mode": U8;
                1 => "rate": U8;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
            0x06 => "step-with-on-off" {
                0 => "step-mode": U8;
                1 => "step-size": U8;
                2 => "transition-time": U16;
                3 => "options-mask": U8;
                4 => "options-override": U8;
            }
            0x07 => "stop-with-on-off" {
                0 => "options-mask": U8;
                1 => "options-override": U8;
            }
        }
    }
}
