//! Operational Credentials クラスタ(0x003E)の名前テーブル。
//!
//! `add-noc`/`update-noc` の `icac-value` は nullable。位置引数の途中なので
//! 省略可(`opt`)にせず、無い場合は `null` リテラルで埋める。

use super::cluster_def;

cluster_def! {
    pub DEF = cluster(0x003E, "operational-credentials") {
        attrs {
            0x0000 => "nocs": Raw;
            0x0001 => "fabrics": Raw;
            0x0002 => "supported-fabrics": U8;
            0x0003 => "commissioned-fabrics": U8;
            0x0004 => "trusted-root-certificates": Raw;
            0x0005 => "current-fabric-index": U8;
        }
        cmds {
            0x00 => "attestation-request" { 0 => "attestation-nonce": Bytes; }
            0x02 => "certificate-chain-request" { 0 => "certificate-type": U8; }
            0x04 => "csr-request" {
                0 => "csr-nonce": Bytes;
                1 => "is-for-update-noc": Bool opt;
            }
            0x06 => "add-noc" {
                0 => "noc-value": Bytes;
                1 => "icac-value": Bytes;
                2 => "ipk-value": Bytes;
                3 => "case-admin-subject": U64;
                4 => "admin-vendor-id": U16;
            }
            0x07 => "update-noc" {
                0 => "noc-value": Bytes;
                1 => "icac-value": Bytes opt;
            }
            0x09 => "update-fabric-label" { 0 => "label": Utf8; }
            0x0A => "remove-fabric" { 0 => "fabric-index": U8; }
            0x0B => "add-trusted-root-certificate" { 0 => "root-ca-certificate": Bytes; }
        }
    }
}
