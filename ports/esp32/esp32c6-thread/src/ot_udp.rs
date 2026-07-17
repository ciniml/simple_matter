//! コアの UDP trait(`UdpSend` / `UdpReceive`)の openthread ネイティブ UDP 実装。
//!
//! `docs/design/thread-port.md` §3.4。E5 の embassy-net 実装([`crate::net`] 相当の
//! `EspUdp`)に対し、Thread では第 2 の IP スタックを持たず openthread の
//! [`UdpSocket`] を直接コアの trait へ橋渡しする。
//!
//! - Thread は IPv6 のみ(IPv4 は存在しない)。宛先は `PeerAddr::Udp(SocketAddr::V6(_))` を
//!   期待し、V4 が来たら [`Error::InvalidState`](発生しない防御)。
//! - `UdpMulticast` は実装しない(mDNS を使わず SRP 運用広告のため。§3.4)。
//! - MTU: コアの `MAX_TX_PACKET_SIZE = 1232`(IPv6 最小 MTU 1280 − 40 − 8)は
//!   6LoWPAN(リンク MTU 1280 保証)に適合する。

use core::net::SocketAddr;

use openthread::UdpSocket;

use simple_matter::error::{Error, Result};
use simple_matter::transport::net::{PeerAddr, UdpReceive, UdpSend};

/// openthread の [`UdpSocket`] をコアの UDP trait 群へ橋渡しするアダプタ。
///
/// 送受信は同一ソケットで行う(`UdpSocket::send`/`recv` はいずれも `&self`)。
/// 統合層(pump)は select で recv を待ち、応答は select 復帰後に send する
/// (同時実行しない)ため単一所有で十分。
pub struct OtUdp<'a> {
    socket: UdpSocket<'a>,
}

impl<'a> OtUdp<'a> {
    /// bind 済みの openthread UDP ソケットからアダプタを作る。
    pub fn new(socket: UdpSocket<'a>) -> Self {
        Self { socket }
    }
}

impl UdpSend for OtUdp<'_> {
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<()> {
        match addr.socket_addr() {
            // local(送信元)は OT が選ぶ(mesh-local / OMR / link-local を自動選択)。
            Some(SocketAddr::V6(v6)) => self
                .socket
                .send(data, None, &v6)
                .await
                .map_err(|_| Error::NoSpace),
            _ => Err(Error::InvalidState),
        }
    }
}

impl UdpReceive for OtUdp<'_> {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)> {
        let (len, _local, remote) = self.socket.recv(buf).await.map_err(|_| Error::Decode)?;
        Ok((len, PeerAddr::Udp(SocketAddr::V6(remote))))
    }
}
