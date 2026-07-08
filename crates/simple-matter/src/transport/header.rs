//! Matter メッセージヘッダのパースと生成。
//!
//! Matter Core Specification §4.4(Message Frame Format)に基づく。
//! 1 メッセージは
//! `[PacketHeader(平文)] [PayloadHeader(暗号内)] [payload] [MIC]`
//! の並びで構成される。本モジュールは前二者の型と codec を提供する。
//!
//! - [`PacketHeader`] は非暗号部(Session ID / Message Counter / Node ID)で、
//!   ネットワークから最初に読める。AEAD の AAD にもなる。
//! - [`PayloadHeader`] は暗号化される部(Protocol ID / Opcode / Exchange ID / Ack)で、
//!   復号後にのみ読める。
//!
//! すべての整数はリトルエンディアン。境界チェック済みで、不正入力に対しては
//! `panic` せず [`Error`](crate::Error) を返す。
//!
//! フラグは依存追加を避けるため `bitflags` クレートではなく、u8 を包む小さな
//! 値型([`SecFlags`] / [`ExchFlags`])で手実装する。派生可能な Message Flags
//! (S/DSIZ)は [`PacketHeader`] のフィールドから都度算出し、型としては公開しない。

use crate::error::{Error, Result};
use crate::transport::util::{ParseBuf, WriteBuf};

// --- Message Flags(平文ヘッダ先頭バイト)---

/// バージョン番号を取り出すシフト量(上位 4bit)。現行仕様の値は 0。
const MSG_VERSION_SHIFT: u8 = 4;
/// 送信元 Node ID present(S フラグ)。
const MSG_FLAG_SRC_PRESENT: u8 = 0x04;
/// 宛先サイズ(DSIZ, 下位 2bit)のマスク。
const MSG_DSIZ_MASK: u8 = 0x03;
/// DSIZ = 1: 宛先が 64bit Node ID(ユニキャスト)。
const MSG_DSIZ_UNICAST: u8 = 0x01;
/// DSIZ = 2: 宛先が 16bit Group ID。
const MSG_DSIZ_GROUP: u8 = 0x02;

/// メッセージの宛先識別子(Message Flags の DSIZ で選択される)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstNodeId {
    /// 宛先フィールドなし(DSIZ = 0)。
    None,
    /// ユニキャスト宛先 Node ID(DSIZ = 1, 64bit)。
    Unicast(u64),
    /// グループ宛先 Group ID(DSIZ = 2, 16bit)。
    Group(u16),
}

/// Security Flags(平文ヘッダの 1 バイト)。
///
/// 下位 2bit が Session Type(0 = ユニキャスト, 1 = グループ)、上位に
/// P(privacy)/ C(control)/ MX(message extensions)を持つ。本実装では
/// 個々のビットを解釈せずワイヤ上の全ビットを保持する。この 1 バイトは AEAD の
/// nonce 先頭にそのまま使われるため、未知ビットも改変せず往復させる必要がある。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecFlags(u8);

impl SecFlags {
    /// グループセッションビット(下位 Session Type = 1)。
    pub const GROUP_SESSION: u8 = 0x01;

    /// P(privacy)ビット。ヘッダの一部が難読化されている(本実装は非対応 = drop)。
    pub const PRIVACY: u8 = 0x80;

    /// C(control message)ビット(MCSP。本実装は非対応 = drop)。
    pub const CONTROL: u8 = 0x40;

    /// 生の 1 バイトから全ビットを保持して生成する。
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// 保持している生の 1 バイトを返す。
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// グループセッションであれば `true`。
    pub const fn is_group_session(self) -> bool {
        self.0 & Self::GROUP_SESSION != 0
    }

    /// privacy 難読化(P フラグ)されていれば `true`。
    pub const fn is_privacy(self) -> bool {
        self.0 & Self::PRIVACY != 0
    }

    /// control message(C フラグ)であれば `true`。
    pub const fn is_control(self) -> bool {
        self.0 & Self::CONTROL != 0
    }
}

/// 非暗号ヘッダ(PacketHeader)。
///
/// ネットワークから最初に読める部分で、復号なしに解釈できる。AEAD 復号時は
/// このヘッダのワイヤバイト列がそのまま AAD になる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// セッション ID(0 は非暗号=Unsecured セッション)。
    pub session_id: u16,
    /// Security Flags。
    pub sec_flags: SecFlags,
    /// メッセージカウンタ(32bit)。
    pub ctr: u32,
    /// 送信元 Node ID(S フラグが立つときのみ present)。
    pub src_node_id: Option<u64>,
    /// 宛先(DSIZ による)。
    pub dst: DstNodeId,
}

impl PacketHeader {
    /// PacketHeader のワイヤ上の最大長(バイト)。
    ///
    /// TCP 用のメッセージ長 2 バイト + フラグ 1 + Security Flags 1 + Session ID 2 +
    /// Message Counter 4 + 送信元 Node ID 8 + 宛先 Node ID 8。UDP 経路では先頭の
    /// TCP 長フィールドは書き出さないが、バッファ確保の上限としてこの値を用いる。
    pub const MAX_LEN: usize = 2 + 1 + 1 + 2 + 4 + 8 + 8;

    /// `buf` の現在位置から PacketHeader をデコードし、`buf` を消費して進める。
    ///
    /// デコード後、`buf` の消費済み領域(`parsed_as_slice`)がちょうどこのヘッダの
    /// ワイヤバイト列(= AAD)になる。バージョンが 0 以外・DSIZ 予約値・長さ不足は
    /// [`Error::Decode`]。
    pub fn decode(buf: &mut ParseBuf<'_>) -> Result<Self> {
        let msg_flags = buf.le_u8()?;
        if msg_flags >> MSG_VERSION_SHIFT != 0 {
            // 現行仕様のバージョンは 0。未知バージョンは受理しない。
            return Err(Error::Decode);
        }
        let session_id = buf.le_u16()?;
        let sec_flags = SecFlags::from_bits(buf.le_u8()?);
        let ctr = buf.le_u32()?;

        let src_node_id = if msg_flags & MSG_FLAG_SRC_PRESENT != 0 {
            Some(buf.le_u64()?)
        } else {
            None
        };

        let dst = match msg_flags & MSG_DSIZ_MASK {
            0 => DstNodeId::None,
            MSG_DSIZ_UNICAST => DstNodeId::Unicast(buf.le_u64()?),
            MSG_DSIZ_GROUP => DstNodeId::Group(buf.le_u16()?),
            // DSIZ = 3 は予約。
            _ => return Err(Error::Decode),
        };

        Ok(Self {
            session_id,
            sec_flags,
            ctr,
            src_node_id,
            dst,
        })
    }

    /// PacketHeader を `out` の末尾へエンコードする(UDP 経路: TCP 長は書かない)。
    ///
    /// 空き不足は [`Error::NoSpace`]。
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<()> {
        let mut msg_flags = 0u8; // version = 0
        if self.src_node_id.is_some() {
            msg_flags |= MSG_FLAG_SRC_PRESENT;
        }
        match self.dst {
            DstNodeId::None => {}
            DstNodeId::Unicast(_) => msg_flags |= MSG_DSIZ_UNICAST,
            DstNodeId::Group(_) => msg_flags |= MSG_DSIZ_GROUP,
        }

        out.le_u8(msg_flags)?;
        out.le_u16(self.session_id)?;
        out.le_u8(self.sec_flags.bits())?;
        out.le_u32(self.ctr)?;

        if let Some(src) = self.src_node_id {
            out.le_u64(src)?;
        }
        match self.dst {
            DstNodeId::None => {}
            DstNodeId::Unicast(id) => out.le_u64(id)?,
            DstNodeId::Group(id) => out.le_u16(id)?,
        }
        Ok(())
    }

    /// このメッセージが暗号化されている(Session ID 非 0 またはグループ)なら `true`。
    pub const fn is_encrypted(&self) -> bool {
        self.session_id != 0 || self.sec_flags.is_group_session()
    }
}

// --- Exchange Flags(暗号内ヘッダ先頭バイト)---

/// Exchange Flags(暗号内ヘッダの 1 バイト)。
///
/// I(initiator)/ A(acknowledgement)/ R(reliability)/ SX(secured extensions)/
/// V(vendor present)を表す。依存追加を避けるため u8 を包む値型として手実装する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExchFlags(u8);

impl ExchFlags {
    /// I: このメッセージの送信者が Exchange の initiator。
    pub const INITIATOR: u8 = 0x01;
    /// A: acknowledged message counter フィールドが present。
    pub const ACK: u8 = 0x02;
    /// R: 信頼送達(MRP による ACK)を要求する。
    pub const RELIABLE: u8 = 0x04;
    /// SX: secured extensions が present(本実装では未対応・保持のみ)。
    pub const SECURED_EXT: u8 = 0x08;
    /// V: protocol vendor ID フィールドが present。
    pub const VENDOR: u8 = 0x10;

    /// 生の 1 バイトから全ビットを保持して生成する。
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// 保持している生の 1 バイトを返す。
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// 指定ビットが立っていれば `true`。
    pub const fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// 指定ビットを立てる。
    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// 指定ビットを落とす。
    pub fn remove(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

/// 暗号内ヘッダ(PayloadHeader)。
///
/// AEAD 復号後にのみ読める。Protocol ID / Opcode / Exchange ID / Ack を保持する。
/// `vendor_id` と `ack_ctr` の present 有無は Exchange Flags の V / A ビットと一致する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadHeader {
    /// Exchange Flags。
    pub exch_flags: ExchFlags,
    /// Protocol Opcode(プロトコルごとのメッセージ種別)。
    pub proto_opcode: u8,
    /// Exchange ID。
    pub exch_id: u16,
    /// Protocol ID(0x0000 = Secure Channel, 0x0001 = Interaction Model 等)。
    pub proto_id: u16,
    /// Protocol Vendor ID(V フラグが立つときのみ present)。
    pub vendor_id: Option<u16>,
    /// Acknowledged Message Counter(A フラグが立つときのみ present)。
    pub ack_ctr: Option<u32>,
}

impl PayloadHeader {
    /// PayloadHeader のワイヤ上の最大長(バイト)。
    ///
    /// Exchange Flags 1 + Opcode 1 + Exchange ID 2 + Protocol ID 2 +
    /// (任意)Vendor ID 2 + (任意)Ack Counter 4。
    pub const MAX_LEN: usize = 1 + 1 + 2 + 2 + 2 + 4;

    /// 平文になった `buf` の現在位置から PayloadHeader をデコードし、`buf` を進める。
    ///
    /// デコード後の `buf` の残り(`as_slice`)がアプリケーション payload になる。
    /// 長さ不足は [`Error::Decode`]。
    pub fn decode(buf: &mut ParseBuf<'_>) -> Result<Self> {
        let exch_flags = ExchFlags::from_bits(buf.le_u8()?);
        let proto_opcode = buf.le_u8()?;
        let exch_id = buf.le_u16()?;
        let proto_id = buf.le_u16()?;

        let vendor_id = if exch_flags.contains(ExchFlags::VENDOR) {
            Some(buf.le_u16()?)
        } else {
            None
        };
        let ack_ctr = if exch_flags.contains(ExchFlags::ACK) {
            Some(buf.le_u32()?)
        } else {
            None
        };

        Ok(Self {
            exch_flags,
            proto_opcode,
            exch_id,
            proto_id,
            vendor_id,
            ack_ctr,
        })
    }

    /// PayloadHeader を `out` の末尾へエンコードする。
    ///
    /// Exchange Flags の V / A ビットは `vendor_id` / `ack_ctr` の有無に整合するよう
    /// 補正して書き出す。空き不足は [`Error::NoSpace`]。
    pub fn encode(&self, out: &mut WriteBuf<'_>) -> Result<()> {
        let mut flags = self.exch_flags;
        if self.vendor_id.is_some() {
            flags.insert(ExchFlags::VENDOR);
        } else {
            flags.remove(ExchFlags::VENDOR);
        }
        if self.ack_ctr.is_some() {
            flags.insert(ExchFlags::ACK);
        } else {
            flags.remove(ExchFlags::ACK);
        }

        out.le_u8(flags.bits())?;
        out.le_u8(self.proto_opcode)?;
        out.le_u16(self.exch_id)?;
        out.le_u16(self.proto_id)?;
        if let Some(v) = self.vendor_id {
            out.le_u16(v)?;
        }
        if let Some(a) = self.ack_ctr {
            out.le_u32(a)?;
        }
        Ok(())
    }

    /// このメッセージの送信者が Exchange の initiator なら `true`。
    pub const fn is_initiator(&self) -> bool {
        self.exch_flags.contains(ExchFlags::INITIATOR)
    }

    /// 信頼送達(R フラグ)を要求していれば `true`。
    pub const fn is_reliable(&self) -> bool {
        self.exch_flags.contains(ExchFlags::RELIABLE)
    }

    /// piggyback された acknowledged message counter を返す(なければ `None`)。
    pub const fn ack(&self) -> Option<u32> {
        self.ack_ctr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PacketHeader を往復させ、消費バイトが AAD として一致することを確かめる補助。
    fn packet_round_trip(hdr: &PacketHeader) {
        let mut buf = [0u8; PacketHeader::MAX_LEN];
        let encoded_len = {
            let mut w = WriteBuf::new(&mut buf, 0).unwrap();
            hdr.encode(&mut w).unwrap();
            w.len()
        };
        let mut store = buf;
        let mut p = ParseBuf::new(&mut store[..encoded_len]);
        let decoded = PacketHeader::decode(&mut p).unwrap();
        assert_eq!(&decoded, hdr);
        // ヘッダ全体が消費され、残りが無いこと。
        assert_eq!(p.remaining(), 0);
        assert_eq!(p.parsed_as_slice().len(), encoded_len);
    }

    #[test]
    fn packet_header_variants_round_trip() {
        packet_round_trip(&PacketHeader {
            session_id: 0,
            sec_flags: SecFlags::from_bits(0),
            ctr: 1,
            src_node_id: None,
            dst: DstNodeId::None,
        });
        packet_round_trip(&PacketHeader {
            session_id: 0x1234,
            sec_flags: SecFlags::from_bits(0),
            ctr: 0xDEAD_BEEF,
            src_node_id: Some(0x0102_0304_0506_0708),
            dst: DstNodeId::Unicast(0x1122_3344_5566_7788),
        });
        packet_round_trip(&PacketHeader {
            session_id: 0xFFFF,
            sec_flags: SecFlags::from_bits(SecFlags::GROUP_SESSION),
            ctr: 42,
            src_node_id: Some(7),
            dst: DstNodeId::Group(0xAB12),
        });
    }

    #[test]
    fn packet_header_known_bytes() {
        // rs-matter の decode 用テストベクタと同じ平文ヘッダ 8 バイト。
        // flags=0x00, session_id=0x0002, sec_flags=0x00, ctr=0x00e943f2。
        let mut bytes = [0x00u8, 0x02, 0x00, 0x00, 0xf2, 0x43, 0xe9, 0x00];
        let mut p = ParseBuf::new(&mut bytes);
        let hdr = PacketHeader::decode(&mut p).unwrap();
        assert_eq!(hdr.session_id, 0x0002);
        assert_eq!(hdr.ctr, 15287282);
        assert_eq!(hdr.src_node_id, None);
        assert_eq!(hdr.dst, DstNodeId::None);
        assert!(hdr.is_encrypted());
        assert_eq!(
            p.parsed_as_slice(),
            &[0x00, 0x02, 0x00, 0x00, 0xf2, 0x43, 0xe9, 0x00]
        );

        // 再エンコードで同じ 8 バイトが得られる。
        let mut out = [0u8; PacketHeader::MAX_LEN];
        let mut w = WriteBuf::new(&mut out, 0).unwrap();
        hdr.encode(&mut w).unwrap();
        assert_eq!(
            w.as_slice(),
            &[0x00, 0x02, 0x00, 0x00, 0xf2, 0x43, 0xe9, 0x00]
        );
    }

    #[test]
    fn packet_header_rejects_bad_version_and_dsiz() {
        // バージョン 1(上位ニブル)は拒否。
        let mut bad_ver = [0x10u8, 0, 0, 0, 0, 0, 0, 0];
        let mut p = ParseBuf::new(&mut bad_ver);
        assert_eq!(PacketHeader::decode(&mut p), Err(Error::Decode));

        // DSIZ = 3(予約)は拒否。
        let mut bad_dsiz = [0x03u8, 0, 0, 0, 0, 0, 0, 0];
        let mut p = ParseBuf::new(&mut bad_dsiz);
        assert_eq!(PacketHeader::decode(&mut p), Err(Error::Decode));
    }

    #[test]
    fn packet_header_truncated_is_decode_error() {
        let mut truncated = [0x00u8, 0x02, 0x00]; // ctr の途中で切れる
        let mut p = ParseBuf::new(&mut truncated);
        assert_eq!(PacketHeader::decode(&mut p), Err(Error::Decode));
    }

    #[test]
    fn payload_header_round_trip_all_options() {
        for vendor in [None, Some(0xFFF1u16)] {
            for ack in [None, Some(0x1234_5678u32)] {
                let hdr = PayloadHeader {
                    exch_flags: ExchFlags::from_bits(ExchFlags::INITIATOR | ExchFlags::RELIABLE),
                    proto_opcode: 0x20,
                    exch_id: 0xBEEF,
                    proto_id: 0x0001,
                    vendor_id: vendor,
                    ack_ctr: ack,
                };
                let mut buf = [0u8; PayloadHeader::MAX_LEN];
                let n = {
                    let mut w = WriteBuf::new(&mut buf, 0).unwrap();
                    hdr.encode(&mut w).unwrap();
                    w.len()
                };
                let mut store = buf;
                let mut p = ParseBuf::new(&mut store[..n]);
                let decoded = PayloadHeader::decode(&mut p).unwrap();
                assert_eq!(decoded.vendor_id, vendor);
                assert_eq!(decoded.ack_ctr, ack);
                assert_eq!(decoded.proto_id, 0x0001);
                assert_eq!(decoded.exch_id, 0xBEEF);
                assert!(decoded.is_initiator());
                assert!(decoded.is_reliable());
                assert_eq!(decoded.ack(), ack);
            }
        }
    }

    #[test]
    fn payload_header_known_bytes() {
        // rs-matter の復号済み平文の先頭 6 バイト(payload header)。
        // exch_flags=0x05(I|R), opcode=0x08, exch_id=0x0070, proto_id=0x0001。
        let mut bytes = [0x05u8, 0x08, 0x70, 0x00, 0x01, 0x00, 0x15, 0x28];
        let mut p = ParseBuf::new(&mut bytes);
        let hdr = PayloadHeader::decode(&mut p).unwrap();
        assert_eq!(hdr.proto_opcode, 0x08);
        assert_eq!(hdr.exch_id, 0x0070);
        assert_eq!(hdr.proto_id, 0x0001);
        assert!(hdr.is_initiator());
        assert!(hdr.is_reliable());
        assert_eq!(hdr.vendor_id, None);
        assert_eq!(hdr.ack_ctr, None);
        // 残りは payload。
        assert_eq!(p.as_slice(), &[0x15, 0x28]);
    }
}
