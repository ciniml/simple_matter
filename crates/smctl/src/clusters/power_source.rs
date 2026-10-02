//! Power Source クラスタ(0x002F)の名前テーブル(電池・電源の状態)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x002F, "power-source") {
        attrs {
            0x0000 => "status": U8;
            0x0001 => "order": U8;
            0x0002 => "description": Utf8;
            0x000B => "bat-voltage": U32;
            // 0.5 % 単位(200 = 100 %)。
            0x000C => "bat-percent-remaining": U8;
            0x000D => "bat-time-remaining": U32;
            0x000E => "bat-charge-level": U8;
            0x000F => "bat-replacement-needed": Bool;
            0x0010 => "bat-replaceability": U8;
            0x0011 => "bat-present": Bool;
            0x0013 => "bat-replacement-description": Utf8;
            0x0014 => "bat-common-designation": U16;
            0x0015 => "bat-ansi-designation": Utf8;
            0x0016 => "bat-iec-designation": Utf8;
            0x0017 => "bat-approved-chemistry": U16;
            0x0018 => "bat-capacity": U32;
            0x0019 => "bat-quantity": U8;
            0x001A => "bat-charge-state": U8;
        }
        cmds {}
        events {}
    }
}
