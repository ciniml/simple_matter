//! Door Lock クラスタ(0x0101)の名前テーブル。
//!
//! LockDoor / UnlockDoor は timed invoke 必須のため `--timed <ms>` を付けて呼ぶ
//! (例: `smctl door-lock lock-door <node> <ep> --timed 1000`)。PINCode フィールドは
//! デバイス側最小実装(feature 無し)では不要のため未収載。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0101, "door-lock") {
        attrs {
            0x0000 => "lock-state": U8;
            0x0001 => "lock-type": U8;
            0x0002 => "actuator-enabled": Bool;
            0x0025 => "operating-mode": U8 rw;
            0x0026 => "supported-operating-modes": U16;
        }
        cmds {
            0x00 => "lock-door" {}
            0x01 => "unlock-door" {}
        }
        events {
            0x0002 => "lock-operation";
        }
    }
}
