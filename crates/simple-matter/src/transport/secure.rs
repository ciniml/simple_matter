//! 暗号境界:メッセージの AES-CCM 暗号化/復号を行う唯一の実行点。
//!
//! `docs/ARCHITECTURE.md` 設計原則 4「暗号境界は 1 点」および
//! `docs/design/transport-exchange.md` §3.3 に従い、AEAD の呼び出しは
//! [`SecureCodec`] にのみ存在する。transport 層より下は暗号文 + [`PacketHeader`]、
//! exchange 層より上は平文 + [`PayloadHeader`] を扱う。
//!
//! # nonce と AAD
//!
//! - nonce(13 バイト)= `Security Flags(1) || Message Counter(4, LE) || Source Node ID(8, LE)`。
//!   復号では source = ピア、暗号化では source = 自ノードの Node ID を用いる。
//! - AAD = 平文 [`PacketHeader`] のワイヤバイト列そのもの。
//!
//! # 二段デコード
//!
//! 1. [`PacketHeader::decode`] で Session ID を得る(復号不要)。
//! 2. 上位(SessionManager, 本ピースのスコープ外)が Session を解決して鍵を得る。
//! 3. [`SecureCodec::decrypt`] に鍵を渡して初めて [`PayloadHeader`] が得られる。
//!
//! `key` が `None` の経路は非暗号(Unsecured)セッション(PASE/CASE 第1メッセージ)を
//! 表し、復号/暗号化をスキップしてヘッダのみを扱う。これにより「セッション未解決の
//! まま payload を読む」コードが型の上で書けない。

use crate::crypto::{Crypto, AES_CCM_KEY_LEN, AES_CCM_NONCE_LEN, AES_CCM_TAG_LEN};
use crate::error::{Error, Result};
use crate::transport::header::{PacketHeader, PayloadHeader};
use crate::transport::util::{ParseBuf, WriteBuf};

/// AES-128-CCM の鍵参照。`None` は非暗号セッションを表す。
///
/// 設計ドキュメントの `AeadKeyRef` に相当するが、本クレートの [`Crypto`] trait が
/// 固定長配列で鍵を受け取るため、`&[u8; 16]` の借用として表現する。
pub type AeadKeyRef<'a> = &'a [u8; AES_CCM_KEY_LEN];

/// nonce = `sec_flags(1) || ctr(4, LE) || node_id(8, LE)` を組み立てる。
fn make_nonce(sec_flags: u8, ctr: u32, node_id: u64) -> [u8; AES_CCM_NONCE_LEN] {
    let mut nonce = [0u8; AES_CCM_NONCE_LEN];
    nonce[0] = sec_flags;
    nonce[1..5].copy_from_slice(&ctr.to_le_bytes());
    nonce[5..13].copy_from_slice(&node_id.to_le_bytes());
    nonce
}

/// メッセージの AES-CCM 暗号化/復号を担う唯一の型(暗号境界)。
pub struct SecureCodec;

impl SecureCodec {
    /// RX: PacketHeader をパース済みの `buf` をセッション鍵で復号し、[`PayloadHeader`] を返す。
    ///
    /// `buf` は `parsed_as_slice()` がちょうど PacketHeader のワイヤバイト列(AAD)、
    /// 残り(`as_slice()`)が「暗号文 || MIC」の状態で渡すこと。復号は in-place で行い、
    /// 復号後は `buf` の残りが payload になる。
    ///
    /// - `key` が `Some` なら復号 + MIC 検証を行う。MIC 不一致・鍵不正・長さ不足は
    ///   [`Error::Crypto`] を返し `panic` しない。
    /// - `key` が `None`(非暗号セッション)なら復号せずヘッダをデコードするのみ。
    /// - `peer_node_id` は nonce に用いる送信元(ピア)の Node ID。
    pub fn decrypt<C: Crypto>(
        crypto: &C,
        key: Option<AeadKeyRef<'_>>,
        pkt: &PacketHeader,
        peer_node_id: u64,
        buf: &mut ParseBuf<'_>,
    ) -> Result<PayloadHeader> {
        if let Some(key) = key {
            // AAD は消費済みの PacketHeader バイト列。可変借用と衝突しないよう複製する。
            let mut aad_buf = [0u8; PacketHeader::MAX_LEN];
            let parsed = buf.parsed_as_slice();
            let aad_len = parsed.len();
            if aad_len > aad_buf.len() {
                return Err(Error::Decode);
            }
            aad_buf[..aad_len].copy_from_slice(parsed);

            let nonce = make_nonce(pkt.sec_flags.bits(), pkt.ctr, peer_node_id);
            // in-place 復号(平文が先頭へ上書きされ、末尾 16 バイトが MIC の余り)。
            crypto.aes_ccm_decrypt(key, &nonce, &aad_buf[..aad_len], buf.as_mut_slice())?;
            // MIC 分を残り領域から切り落とす。
            buf.tail(AES_CCM_TAG_LEN)?;
        }

        PayloadHeader::decode(buf)
    }

    /// TX: payload を書き込み済みの `buf` に PayloadHeader を前置・暗号化し、PacketHeader を前置する。
    ///
    /// `buf` は先頭に `PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN` 以上の headroom を
    /// 空けて生成し(前置用)、payload を書き込んだ状態で渡すこと。末尾には MIC 用の
    /// 空きも必要。完了後、`buf.as_slice()` が
    /// 「PacketHeader || 暗号文(PayloadHeader + payload) || MIC」になる。
    ///
    /// - `key` が `Some` なら AES-CCM で暗号化し MIC を付す。
    /// - `key` が `None`(非暗号セッション)なら暗号化せずヘッダを前置するのみ。
    /// - `local_node_id` は nonce に用いる送信元(自ノード)の Node ID。
    /// - headroom / 末尾の空き不足は [`Error::NoSpace`]。
    pub fn encrypt<C: Crypto>(
        crypto: &C,
        key: Option<AeadKeyRef<'_>>,
        pkt: &PacketHeader,
        payload: &PayloadHeader,
        local_node_id: u64,
        buf: &mut WriteBuf<'_>,
    ) -> Result<()> {
        // 1. PayloadHeader を payload の直前へ前置する。
        let mut phdr_buf = [0u8; PayloadHeader::MAX_LEN];
        let phdr_len = {
            let mut w = WriteBuf::new(&mut phdr_buf, 0)?;
            payload.encode(&mut w)?;
            w.len()
        };
        buf.prepend(&phdr_buf[..phdr_len])?;

        // 2. PacketHeader をエンコードする(AAD かつワイヤ前置プレフィクス)。
        let mut pkt_buf = [0u8; PacketHeader::MAX_LEN];
        let pkt_len = {
            let mut w = WriteBuf::new(&mut pkt_buf, 0)?;
            pkt.encode(&mut w)?;
            w.len()
        };
        let aad = &pkt_buf[..pkt_len];

        // 3. 鍵があれば in-place 暗号化し MIC を付す。
        if let Some(key) = key {
            let pt_len = buf.len();
            // MIC 用の空きを末尾に確保する。
            buf.append(&[0u8; AES_CCM_TAG_LEN])?;
            let nonce = make_nonce(pkt.sec_flags.bits(), pkt.ctr, local_node_id);
            crypto.aes_ccm_encrypt(key, &nonce, aad, buf.as_mut_slice(), pt_len)?;
        }

        // 4. PacketHeader を先頭へ前置する。
        buf.prepend(aad)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rustcrypto::RustCrypto;
    use crate::crypto::Rng;
    use crate::transport::header::{DstNodeId, ExchFlags, PacketHeader, SecFlags};

    /// テスト用のダミー RNG。AES-CCM は乱数を使わないため実体は不要。
    struct ZeroRng;
    impl Rng for ZeroRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
            dest.fill(0);
            Ok(())
        }
    }

    fn crypto() -> RustCrypto<ZeroRng> {
        RustCrypto::new(ZeroRng)
    }

    // rs-matter transport::proto_hdr のテストと同じ、chip-tool 実行から採取した鍵。
    const ENC_KEY: [u8; 16] = [
        0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8, 0x1b,
        0x33,
    ];
    // 平文(PayloadHeader 6 バイト + payload 22 バイト)。
    const PLAIN_TEXT: &[u8] = &[
        5, 8, 0x58, 0x28, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01, 0x24,
        0x02, 0x06, 0x24, 0x03, 0x01, 0x18, 0x35, 0x01, 0x18, 0x18, 0x18, 0x18,
    ];
    // 期待される暗号文 + MIC(44 バイト)。
    const EXPECTED_CT: &[u8] = &[
        189, 83, 250, 121, 38, 87, 97, 17, 153, 78, 243, 20, 36, 11, 131, 142, 136, 165, 227, 107,
        204, 129, 193, 153, 42, 131, 138, 254, 22, 190, 76, 244, 116, 45, 156, 215, 229, 130, 215,
        147, 73, 21, 88, 216,
    ];
    // 期待される平文ヘッダ(PacketHeader 8 バイト)。
    const EXPECTED_PLAIN_HDR: &[u8] = &[0x0, 0x11, 0x0, 0x0, 0x29, 0x0, 0x0, 0x0];

    #[test]
    fn encrypt_matches_spec_vector() {
        let pkt = PacketHeader {
            session_id: 0x0011,
            sec_flags: SecFlags::from_bits(0),
            ctr: 41,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let payload = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
            proto_opcode: 0x08,
            exch_id: 0x2858,
            proto_id: 0x0001,
            vendor_id: None,
            ack_ctr: None,
        };
        let app_payload = &PLAIN_TEXT[6..];

        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut storage = [0u8; 128];
        let out_len;
        {
            let mut w = WriteBuf::new(&mut storage, headroom).unwrap();
            w.append(app_payload).unwrap();
            SecureCodec::encrypt(&crypto(), Some(&ENC_KEY), &pkt, &payload, 0, &mut w).unwrap();
            out_len = w.len();
            assert_eq!(&w.as_slice()[..8], EXPECTED_PLAIN_HDR);
            assert_eq!(&w.as_slice()[8..], EXPECTED_CT);
        }
        assert_eq!(out_len, 8 + EXPECTED_CT.len());
    }

    // rs-matter transport::proto_hdr の decrypt テストと同じ採取フレーム(71 バイト)。
    fn decrypt_input() -> [u8; 71] {
        [
            0x0, 0x2, 0x0, 0x0, 0xf2, 0x43, 0xe9, 0x0, 0x31, 0xb5, 0x66, 0xec, 0x8b, 0x5b, 0xf4,
            0x17, 0xe4, 0x80, 0xf3, 0xd5, 0x11, 0x59, 0x19, 0xb5, 0x23, 0x91, 0x35, 0x37, 0xb,
            0xf9, 0xbf, 0x69, 0x55, 0x11, 0x75, 0x87, 0x77, 0x19, 0xfc, 0xf3, 0x5d, 0x4b, 0x47,
            0x1f, 0xb0, 0x5e, 0xbe, 0xb5, 0x10, 0xad, 0xc6, 0x78, 0x94, 0x50, 0xe5, 0xd2, 0xe0,
            0x80, 0xef, 0xa8, 0x3a, 0xf0, 0xa6, 0xaf, 0x1b, 0x2, 0x35, 0xa7, 0xd1, 0xc6, 0x32,
        ]
    }
    const DEC_KEY: [u8; 16] = [
        0x66, 0x63, 0x31, 0x97, 0x43, 0x9c, 0x17, 0xb9, 0x7e, 0x10, 0xee, 0x47, 0xc8, 0x8, 0x80,
        0x4a,
    ];
    // 期待される平文(PayloadHeader 6 バイト + payload 41 バイト)。
    const EXPECTED_PT: &[u8] = &[
        0x5, 0x8, 0x70, 0x0, 0x1, 0x0, 0x15, 0x28, 0x0, 0x28, 0x1, 0x36, 0x2, 0x15, 0x37, 0x0,
        0x24, 0x0, 0x0, 0x24, 0x1, 0x30, 0x24, 0x2, 0x2, 0x18, 0x35, 0x1, 0x24, 0x0, 0x0, 0x2c,
        0x1, 0x2, 0x57, 0x57, 0x24, 0x2, 0x3, 0x25, 0x3, 0xb8, 0xb, 0x18, 0x18, 0x18, 0x18,
    ];

    #[test]
    fn decrypt_matches_spec_vector() {
        let mut input = decrypt_input();
        let mut buf = ParseBuf::new(&mut input);
        let pkt = PacketHeader::decode(&mut buf).unwrap();
        assert_eq!(pkt.session_id, 0x0002);
        assert_eq!(pkt.ctr, 15287282);

        let phdr = SecureCodec::decrypt(&crypto(), Some(&DEC_KEY), &pkt, 0, &mut buf).unwrap();
        assert_eq!(phdr.proto_opcode, 0x08);
        assert_eq!(phdr.exch_id, 0x0070);
        assert_eq!(phdr.proto_id, 0x0001);
        assert!(phdr.is_initiator());
        // 復号後の残りが payload(平文の PayloadHeader 6 バイトを除いた分)。
        assert_eq!(buf.as_slice(), &EXPECTED_PT[6..]);
    }

    #[test]
    fn decrypt_detects_mic_tampering() {
        let mut input = decrypt_input();
        input[70] ^= 0xff; // MIC を改竄
        let mut buf = ParseBuf::new(&mut input);
        let pkt = PacketHeader::decode(&mut buf).unwrap();
        assert_eq!(
            SecureCodec::decrypt(&crypto(), Some(&DEC_KEY), &pkt, 0, &mut buf),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let mut input = decrypt_input();
        let bad_key = [0xAAu8; 16];
        let mut buf = ParseBuf::new(&mut input);
        let pkt = PacketHeader::decode(&mut buf).unwrap();
        assert_eq!(
            SecureCodec::decrypt(&crypto(), Some(&bad_key), &pkt, 0, &mut buf),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn plaintext_session_round_trip_without_key() {
        // key = None(非暗号セッション)の往復。暗号化せずヘッダのみを前後する。
        let pkt = PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr: 7,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let payload = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR),
            proto_opcode: 0x20,
            exch_id: 0x0001,
            proto_id: 0x0000,
            vendor_id: None,
            ack_ctr: None,
        };
        let app_payload: &[u8] = &[0x15, 0x18];

        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut storage = [0u8; 128];
        let mut wire = [0u8; 128];
        let wire_len;
        {
            let mut w = WriteBuf::new(&mut storage, headroom).unwrap();
            w.append(app_payload).unwrap();
            SecureCodec::encrypt(&crypto(), None, &pkt, &payload, 0, &mut w).unwrap();
            wire_len = w.len();
            wire[..wire_len].copy_from_slice(w.as_slice());
        }

        let mut buf = ParseBuf::new(&mut wire[..wire_len]);
        let dpkt = PacketHeader::decode(&mut buf).unwrap();
        assert_eq!(dpkt, pkt);
        let dphdr = SecureCodec::decrypt(&crypto(), None, &dpkt, 0, &mut buf).unwrap();
        assert_eq!(dphdr.proto_opcode, 0x20);
        assert_eq!(dphdr.exch_id, 0x0001);
        assert_eq!(buf.as_slice(), app_payload);
    }

    #[test]
    fn encrypt_decrypt_round_trip_encrypted() {
        let key = [0x11u8; 16];
        let pkt = PacketHeader {
            session_id: 0x0042,
            sec_flags: SecFlags::from_bits(0),
            ctr: 123456,
            src_node_id: None,
            dst: DstNodeId::None,
        };
        let payload = PayloadHeader {
            exch_flags: ExchFlags::from_bits(ExchFlags::RELIABLE),
            proto_opcode: 0x05,
            exch_id: 0x9abc,
            proto_id: 0x0001,
            vendor_id: Some(0xFFF1),
            ack_ctr: Some(0x01020304),
        };
        let app_payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22];
        let peer = 0x1122_3344_5566_7788u64;

        let headroom = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN;
        let mut storage = [0u8; 128];
        let mut wire = [0u8; 128];
        let wire_len;
        {
            let mut w = WriteBuf::new(&mut storage, headroom).unwrap();
            w.append(app_payload).unwrap();
            // 送信元 = peer(自ノード)として暗号化。
            SecureCodec::encrypt(&crypto(), Some(&key), &pkt, &payload, peer, &mut w).unwrap();
            wire_len = w.len();
            wire[..wire_len].copy_from_slice(w.as_slice());
        }

        let mut buf = ParseBuf::new(&mut wire[..wire_len]);
        let dpkt = PacketHeader::decode(&mut buf).unwrap();
        // 復号側では同じ Node ID をピアとして nonce に用いる。
        let dphdr = SecureCodec::decrypt(&crypto(), Some(&key), &dpkt, peer, &mut buf).unwrap();
        assert_eq!(dphdr.vendor_id, Some(0xFFF1));
        assert_eq!(dphdr.ack_ctr, Some(0x01020304));
        assert_eq!(dphdr.proto_opcode, 0x05);
        assert_eq!(buf.as_slice(), app_payload);
    }
}
