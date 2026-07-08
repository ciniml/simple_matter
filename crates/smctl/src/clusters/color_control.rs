//! Color Control クラスタ(0x0300)の名前テーブル。
//!
//! コマンドフィールドは chip-tool と同じく全指定(kebab-case)。
//! 例: `smctl color-control move-to-hue-and-saturation 100 200 30 0 0 <node> <ep>`
//!     `smctl color-control move-to-color-temperature 300 30 0 0 <node> <ep>`

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0300, "color-control") {
        attrs {
            0x0000 => "current-hue": U8;
            0x0001 => "current-saturation": U8;
            0x0002 => "remaining-time": U16;
            0x0007 => "color-temperature-mireds": U16;
            0x0008 => "color-mode": U8;
            0x000F => "options": U8 rw;
            0x0010 => "number-of-primaries": U8;
            0x4001 => "enhanced-color-mode": U8;
            0x400A => "color-capabilities": U16;
            0x400B => "color-temp-physical-min-mireds": U16;
            0x400C => "color-temp-physical-max-mireds": U16;
            0x400D => "couple-color-temp-to-level-min-mireds": U16;
            0x4010 => "start-up-color-temperature-mireds": U16 rw;
        }
        cmds {
            0x00 => "move-to-hue" {
                0 => "hue": U8;
                1 => "direction": U8;
                2 => "transition-time": U16;
                3 => "options-mask": U8;
                4 => "options-override": U8;
            }
            0x03 => "move-to-saturation" {
                0 => "saturation": U8;
                1 => "transition-time": U16;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
            0x06 => "move-to-hue-and-saturation" {
                0 => "hue": U8;
                1 => "saturation": U8;
                2 => "transition-time": U16;
                3 => "options-mask": U8;
                4 => "options-override": U8;
            }
            0x0A => "move-to-color-temperature" {
                0 => "color-temperature-mireds": U16;
                1 => "transition-time": U16;
                2 => "options-mask": U8;
                3 => "options-override": U8;
            }
        }
    }
}
