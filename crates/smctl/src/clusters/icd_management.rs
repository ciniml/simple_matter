//! ICD Management クラスタ(0x0046)の名前テーブル(CIP / LITS 対応、icd.md §I1c)。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0046, "icd-management") {
        attrs {
            0x0000 => "idle-mode-duration": U32;
            0x0001 => "active-mode-duration": U32;
            0x0002 => "active-mode-threshold": U16;
            0x0003 => "registered-clients": Raw;
            0x0004 => "icd-counter": U32;
            0x0005 => "clients-supported-per-fabric": U16;
            0x0008 => "operating-mode": U8;
        }
        cmds {
            // RegisterClient → RegisterClientResponse{ 0: ICDCounter }。
            0x00 => "register-client" {
                0 => "check-in-node-id": U64;
                1 => "monitored-subject": U64;
                2 => "key": Bytes;
                3 => "verification-key": Bytes opt;
            }
            0x02 => "unregister-client" {
                0 => "check-in-node-id": U64;
                1 => "verification-key": Bytes opt;
            }
            // StayActiveRequest → StayActiveResponse{ 0: promisedActiveDuration }。
            0x03 => "stay-active-request" {
                0 => "stay-active-duration": U32;
            }
        }
    }
}
