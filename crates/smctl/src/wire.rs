//! ワイヤ観測ログ(設計 doc §9.2 `[udp]`/`[ble]`/`[ex]`/`[sc]`)。
//!
//! 送受信バイト列からコアの公開 codec([`PacketHeader::decode`] /
//! [`PayloadHeader::decode`])で平文部をパースして要約を出す。
//!
//! - `[udp]`/`[ble]`(debug): 方向・サイズ・相手 + PacketHeader 要約
//!   (session/ctr/src/dst)。同一 (session, ctr) の再送出は `(retx)` を注釈([ex] の
//!   MRP 再送観測)。
//! - `[ex]`(debug): **非暗号メッセージのみ**(session_id = 0)PayloadHeader を
//!   パースし、exchange ID・I/R/A フラグ・ack counter・プロトコル/opcode 名を出す。
//!   暗号化メッセージのペイロードは復号しない(意味レベルは `[sc]`/`[im]` の
//!   イベント観測で出す)。
//! - `[sc]`(trace): 非暗号 SC ハンドシェイクの TLV ペイロードをプリティプリント。
//! - `[udp]`(trace): パケット全体の hex ダンプ。
//!
//! コア API 増分なし(`transport::header` は既公開)。

use std::sync::Mutex;

use simple_matter::transport::header::{DstNodeId, PacketHeader, PayloadHeader};
use simple_matter::transport::util::ParseBuf;

use crate::log::{logf, Level};

/// Secure Channel プロトコル ID。
const PROTO_SC: u16 = 0x0000;
/// Interaction Model プロトコル ID。
const PROTO_IM: u16 = 0x0001;

/// 再送検出用に覚える直近の送信 (session_id, ctr) の数。
const RETX_WINDOW: usize = 8;

/// 直近の送信 (session_id, ctr)(`(retx)` 注釈用)。
static RECENT_TX: Mutex<Vec<(u16, u32)>> = Mutex::new(Vec::new());

/// 送信メッセージを観測する(`transport` は `"udp"` / `"ble"`)。
pub fn log_tx(transport: &'static str, buf: &[u8], dest: &str) {
    log_msg(transport, true, buf, dest);
}

/// 受信メッセージを観測する。
pub fn log_rx(transport: &'static str, buf: &[u8], src: &str) {
    log_msg(transport, false, buf, src);
}

fn log_msg(transport: &'static str, tx: bool, buf: &[u8], peer: &str) {
    // stderr のレベル判定に加え、`--log-file`(常に trace 全量)も観測を要求する。
    if !crate::log::wants(Level::Debug) {
        return;
    }
    let (dir, arrow) = if tx { ("tx", "->") } else { ("rx", "<-") };
    // PacketHeader::decode は &mut [u8] を要求するのでローカルへ複製する
    // (受信バッファは後段の handle_rx が in-place 復号するため、観測は複製で行う)。
    let mut copy = [0u8; PacketHeader::MAX_LEN];
    let n = buf.len().min(PacketHeader::MAX_LEN);
    copy[..n].copy_from_slice(&buf[..n]);
    let mut pb = ParseBuf::new(&mut copy[..n]);
    let Ok(hdr) = PacketHeader::decode(&mut pb) else {
        logf!(
            Level::Debug,
            transport,
            "{dir} {}B {arrow} {peer} <bad packet header>",
            buf.len()
        );
        return;
    };
    let hdr_len = pb.parsed_as_slice().len();

    let retx = tx && note_tx(hdr.session_id, hdr.ctr);
    let mut line = format!(
        "{dir} {}B {arrow} {peer} session={:#06x} ctr={}",
        buf.len(),
        hdr.session_id,
        hdr.ctr
    );
    if let Some(src) = hdr.src_node_id {
        line.push_str(&format!(" src={src:#x}"));
    }
    match hdr.dst {
        DstNodeId::None => {}
        DstNodeId::Unicast(id) => line.push_str(&format!(" dst={id:#x}")),
        DstNodeId::Group(id) => line.push_str(&format!(" dst=group:{id:#x}")),
    }
    if hdr.is_encrypted() {
        line.push_str(" (encrypted)");
    }
    if retx {
        line.push_str(" (retx)");
    }
    logf!(Level::Debug, transport, "{line}");

    // 非暗号メッセージ: PayloadHeader(exchange/MRP/プロトコル)まで読める。
    if !hdr.is_encrypted() && buf.len() > hdr_len {
        let rest = &buf[hdr_len..];
        let mut pcopy = vec![0u8; rest.len()];
        pcopy.copy_from_slice(rest);
        let mut pb = ParseBuf::new(&mut pcopy);
        if let Ok(ph) = PayloadHeader::decode(&mut pb) {
            let mut flags = String::new();
            if ph.is_initiator() {
                flags.push('I');
            }
            if ph.is_reliable() {
                flags.push('R');
            }
            if ph.ack().is_some() {
                flags.push('A');
            }
            let ack = match ph.ack() {
                Some(a) => format!(" ack={a}"),
                None => String::new(),
            };
            logf!(
                Level::Debug,
                "ex",
                "{dir} exch={:#06x} flags={}{ack} {}",
                ph.exch_id,
                if flags.is_empty() { "-" } else { &flags },
                proto_opcode_name(ph.proto_id, ph.proto_opcode),
            );
            // SC ハンドシェイク(PBKDF/PASE/Sigma)の TLV ペイロードは trace で構造表示。
            let payload_off = hdr_len + pb.parsed_as_slice().len();
            if crate::log::wants(Level::Trace)
                && ph.proto_id == PROTO_SC
                && (0x20..=0x33).contains(&ph.proto_opcode)
                && buf.len() > payload_off
            {
                for l in crate::tlvfmt::pretty(&buf[payload_off..]) {
                    logf!(Level::Trace, "sc", "  {l}");
                }
            }
        }
    }

    // trace: パケット全体の hex ダンプ。
    if crate::log::wants(Level::Trace) {
        logf!(Level::Trace, transport, "  {}", hex(buf));
    }
}

/// 直近の送信 (session, ctr) を記録し、既出(= MRP 再送)なら `true`。
fn note_tx(session: u16, ctr: u32) -> bool {
    let mut recent = match RECENT_TX.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if recent.contains(&(session, ctr)) {
        return true;
    }
    recent.push((session, ctr));
    let len = recent.len();
    if len > RETX_WINDOW {
        recent.drain(..len - RETX_WINDOW);
    }
    false
}

/// hex 文字列(スペースなし)。
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// プロトコル ID + opcode を人間可読名にする(chip-tool のタグ相当の注釈)。
pub fn proto_opcode_name(proto_id: u16, opcode: u8) -> String {
    match proto_id {
        PROTO_SC => {
            let name = match opcode {
                0x00 => "MsgCounterSyncReq",
                0x01 => "MsgCounterSyncRsp",
                0x10 => "MRP:StandaloneAck",
                0x20 => "PASE:PBKDFParamRequest",
                0x21 => "PASE:PBKDFParamResponse",
                0x22 => "PASE:Pake1",
                0x23 => "PASE:Pake2",
                0x24 => "PASE:Pake3",
                0x30 => "CASE:Sigma1",
                0x31 => "CASE:Sigma2",
                0x32 => "CASE:Sigma3",
                0x33 => "CASE:Sigma2Resume",
                0x40 => "StatusReport",
                _ => return format!("SC:opcode={opcode:#04x}"),
            };
            format!("SC:{name}")
        }
        PROTO_IM => {
            let name = match opcode {
                0x01 => "StatusResponse",
                0x02 => "ReadRequest",
                0x03 => "SubscribeRequest",
                0x04 => "SubscribeResponse",
                0x05 => "ReportData",
                0x06 => "WriteRequest",
                0x07 => "WriteResponse",
                0x08 => "InvokeRequest",
                0x09 => "InvokeResponse",
                0x0A => "TimedRequest",
                _ => return format!("IM:opcode={opcode:#04x}"),
            };
            format!("IM:{name}")
        }
        other => format!("proto={other:#06x} opcode={opcode:#04x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_names() {
        assert_eq!(proto_opcode_name(0x0000, 0x30), "SC:CASE:Sigma1");
        assert_eq!(proto_opcode_name(0x0000, 0x33), "SC:CASE:Sigma2Resume");
        assert_eq!(proto_opcode_name(0x0000, 0x10), "SC:MRP:StandaloneAck");
        assert_eq!(proto_opcode_name(0x0001, 0x09), "IM:InvokeResponse");
        assert_eq!(proto_opcode_name(0x0001, 0x05), "IM:ReportData");
        assert_eq!(proto_opcode_name(0x0000, 0x7F), "SC:opcode=0x7f");
        assert_eq!(proto_opcode_name(0x1234, 0x01), "proto=0x1234 opcode=0x01");
    }

    #[test]
    fn retx_detection() {
        // グローバル状態を使うが (session, ctr) をテスト固有値にして衝突を避ける。
        assert!(!note_tx(0xFFEE, 111));
        assert!(note_tx(0xFFEE, 111));
        assert!(!note_tx(0xFFEE, 112));
    }
}
