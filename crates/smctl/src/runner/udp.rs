//! UDP 駆動ループ(examples/commissioner.rs の pump/settle/socket 群の移植)。
//!
//! sans-IO のコアはソケットに触れない。この層がバイト列と時刻の受け渡し
//! (受信 → `handle_rx`、期限 → `poll`、進行 → `Commissioner::drive`)を担う。

#[cfg(feature = "ble")]
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
#[cfg(feature = "ble")]
use std::time::Instant;

use simple_matter::controller::{Commissioner, Phase};
use simple_matter::stack::SendDirective;
#[cfg(feature = "ble")]
use simple_matter::transport::net::PeerAddr;

use super::{Backend, Ctrl};

/// デュアルスタック(v6only=false)の IPv6 UDP ソケットを任意ポートで開く。
///
/// chip 系デバイスは IPv6 のみを広告することがあるため、IPv4 宛は mapped アドレスで送る。
pub fn open_dual_stack_udp() -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    s.set_only_v6(false)?;
    s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())?;
    Ok(s.into())
}

/// IPv4 宛アドレスを IPv4-mapped IPv6 に変換する(デュアルスタックソケット用)。
fn map_to_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        v6 => v6,
    }
}

/// [`SendDirective`] を宛先 UDP に送出する(宛先が解決できないものは黙って捨てる)。
pub fn send_dir(socket: &UdpSocket, tx: &[u8], dir: &SendDirective) {
    if let Some(addr) = dir.addr.socket_addr() {
        crate::wire::log_tx("udp", &tx[..dir.len], &addr.to_string());
        let _ = socket.send_to(&tx[..dir.len], map_to_v6(addr));
    }
}

/// [`Commissioner::drive`] を進捗が止まるまで回し、送信を排出して現フェーズを返す。
///
/// `drive` は「開始発行(send=Some, phase 不変)」と「イベント消費(send=None, phase 遷移)」を
/// 交互に行うので、`send=None && phase 不変`(= 次はイベント待ち)になったら返す。
pub fn pump_commissioner(
    comm: &mut Commissioner<'_, Backend>,
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    now_ms: u64,
    tx: &mut [u8],
) -> Phase {
    loop {
        let prev = comm.phase();
        let out = comm.drive(stack, now_ms, tx);
        if let Some(dir) = out.send {
            send_dir(socket, tx, &dir);
        }
        if out.send.is_none() && out.phase == prev {
            return out.phase;
        }
        if matches!(out.phase, Phase::Done { .. } | Phase::Failed { .. }) {
            return out.phase;
        }
    }
}

/// 応答を受け切り、MRP 再送・standalone ACK を含めて完全に静穏化するまでネットワークを回す。
///
/// `next_deadline` が `None`(保留中の再送/ACK なし)になったら静穏とみなす。
/// フェーズ間・トランザクション間で必ず呼び、前応答の ACK を確実にデバイスへ届けてから
/// 次の新規 exchange を開始する(デバイス側 IM responder は同時 1 トランザクションのため)。
///
/// UDP 経路の [`Exec`](crate::ops::Exec) は購読対応版の `quiesce` を使うため、
/// 現在の利用者は BLE handoff の運用 UDP フェーズのみ。
#[cfg(feature = "ble")]
pub fn settle(
    stack: &mut Ctrl<'_>,
    socket: &UdpSocket,
    start: &Instant,
    rx: &mut [u8],
    tx: &mut [u8],
    until: Instant,
) -> Result<(), String> {
    loop {
        match socket.recv_from(rx) {
            Ok((n, src)) => {
                crate::wire::log_rx("udp", &rx[..n], &src.to_string());
                let now = start.elapsed().as_millis() as u64;
                if let Some(dir) = stack.handle_rx(&mut rx[..n], PeerAddr::Udp(src), now, tx) {
                    send_dir(socket, tx, &dir);
                }
                crate::wire::log_rx_drop("udp", stack.last_rx_drop(), stack.rx_diag());
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("recv: {e}")),
        }
        let now = start.elapsed().as_millis() as u64;
        while let Some(dir) = stack.poll(now, tx) {
            send_dir(socket, tx, &dir);
        }
        if stack
            .next_deadline(start.elapsed().as_millis() as u64)
            .is_none()
        {
            return Ok(());
        }
        if Instant::now() > until {
            return Err("settle timed out (device unresponsive)".into());
        }
    }
}
