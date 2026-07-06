//! Basic Information クラスタ(0x0028)の名前テーブル。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x0028, "basic-information") {
        attrs {
            0x0000 => "data-model-revision": U16;
            0x0001 => "vendor-name": Utf8;
            0x0002 => "vendor-id": U16;
            0x0003 => "product-name": Utf8;
            0x0004 => "product-id": U16;
            0x0005 => "node-label": Utf8 rw;
            0x0007 => "hardware-version": U16;
            0x0009 => "software-version": U32;
            0x000A => "software-version-string": Utf8;
            0x000F => "serial-number": Utf8;
        }
        cmds {
        }
    }
}
