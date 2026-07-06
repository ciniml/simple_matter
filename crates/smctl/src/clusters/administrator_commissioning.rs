//! Administrator Commissioning クラスタ(0x003C)の名前テーブル。
//!
//! open-commissioning-window 系は仕様上 timed invoke 必須。smctl は timed request
//! 未対応のため、デバイスによっては `NeedsTimedInteraction` が返る(既知の割り切り)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x003C, "administrator-commissioning") {
        attrs {
            0x0000 => "window-status": U8;
            0x0001 => "admin-fabric-index": U8;
            0x0002 => "admin-vendor-id": U16;
        }
        cmds {
            0x00 => "open-commissioning-window" {
                0 => "commissioning-timeout": U16;
                1 => "pake-passcode-verifier": Bytes;
                2 => "discriminator": U16;
                3 => "iterations": U32;
                4 => "salt": Bytes;
            }
            0x01 => "open-basic-commissioning-window" {
                0 => "commissioning-timeout": U16;
            }
            0x02 => "revoke-commissioning" {}
        }
    }
}
