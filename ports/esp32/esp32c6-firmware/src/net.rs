//! コアの UDP trait 群(`UdpSend` / `UdpReceive` / `UdpMulticast`)の embassy-net 実装。
//!
//! `docs/design/port-esp32-device.md` §3 / §E5.5。コアの trait 定義
//! (`simple_matter::transport::net`)はこれまで**実装ゼロ**だった(PC examples は
//! `std::net::UdpSocket` 直書き)。本モジュールが実利用第 1 号で、esp-radio の
//! Wi-Fi `Interface`(embassy-net-driver)上の [`embassy_net::udp::UdpSocket`] を包む。
//!
//! # IPv4 のみ(doc §E5.5)
//!
//! smoltcp は `proto-ipv4` のみ有効(IPv6 は将来スコープ)。宛先が IPv6 の
//! [`PeerAddr`] は、IPv4-mapped IPv6(`::ffff:a.b.c.d`)であれば unmap して送り、
//! それ以外はエラーにする。[`UdpMulticast::join`] も同じ mapped 規約で IPv4
//! グループ(例: `::ffff:224.0.0.251`)を受け、smoltcp の IGMP join に渡す
//! (コア trait のシグネチャは IPv6 のみのため。`canonical_socket_addr` と同じ規約)。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use embassy_net::udp::UdpSocket;
use embassy_net::Stack;
use smoltcp_helpers::endpoint_v4;

use simple_matter::error::{Error, Result};
use simple_matter::transport::net::{
    canonical_socket_addr, PeerAddr, UdpMulticast, UdpReceive, UdpSend,
};

/// smoltcp 型変換の小さなヘルパ(embassy-net 経由で smoltcp の wire 型を使う)。
mod smoltcp_helpers {
    use super::*;
    use embassy_net::IpEndpoint;

    /// `SocketAddr` を IPv4 の [`IpEndpoint`] へ変換する(IPv4-mapped IPv6 は unmap)。
    ///
    /// IPv4 で表せないアドレスは `None`(proto-ipv4 のみのビルドでは送れない)。
    pub fn endpoint_v4(addr: SocketAddr) -> Option<IpEndpoint> {
        match canonical_socket_addr(addr) {
            SocketAddr::V4(v4) => Some(IpEndpoint::from(v4)),
            SocketAddr::V6(_) => None,
        }
    }
}

/// [`embassy_net::udp::UdpSocket`] をコアの UDP trait 群へ橋渡しするアダプタ。
///
/// マルチキャスト join はソケットではなくインターフェース(スタック)操作のため、
/// [`Stack`] のコピー(ハンドル)も保持する。
pub struct EspUdp<'a> {
    socket: UdpSocket<'a>,
    stack: Stack<'a>,
}

impl<'a> EspUdp<'a> {
    /// bind 済みソケットとスタックハンドルからアダプタを作る。
    pub fn new(socket: UdpSocket<'a>, stack: Stack<'a>) -> Self {
        Self { socket, stack }
    }
}

impl UdpSend for EspUdp<'_> {
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<()> {
        let sa = addr.socket_addr().ok_or(Error::InvalidState)?;
        let ep = endpoint_v4(sa).ok_or(Error::InvalidState)?;
        self.socket.send_to(data, ep).await.map_err(|_| Error::NoSpace)
    }
}

impl UdpReceive for EspUdp<'_> {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)> {
        let (n, meta) = self.socket.recv_from(buf).await.map_err(|_| Error::Decode)?;
        let sa: SocketAddr = meta.endpoint.into();
        Ok((n, PeerAddr::Udp(sa)))
    }
}

impl UdpMulticast for EspUdp<'_> {
    async fn join(&mut self, group: Ipv6Addr) -> Result<()> {
        let v4 = mapped_v4(group).ok_or(Error::InvalidState)?;
        self.stack
            .join_multicast_group(v4)
            .map_err(|_| Error::NoSpace)
    }

    async fn leave(&mut self, group: Ipv6Addr) -> Result<()> {
        let v4 = mapped_v4(group).ok_or(Error::InvalidState)?;
        self.stack
            .leave_multicast_group(v4)
            .map_err(|_| Error::NotFound)
    }
}

/// IPv4-mapped IPv6(`::ffff:a.b.c.d`)を IPv4 へ unmap する(mapped でなければ `None`)。
pub fn mapped_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    addr.to_ipv4_mapped()
}

/// IPv4 アドレスを mapped 規約([`UdpMulticast::join`] の引数)へ持ち上げる。
pub fn v4_as_mapped(addr: Ipv4Addr) -> Ipv6Addr {
    addr.to_ipv6_mapped()
}

/// IPv4 の `(addr, port)` を [`PeerAddr::Udp`] にする送信宛先ヘルパ。
pub fn peer_v4(addr: Ipv4Addr, port: u16) -> PeerAddr {
    PeerAddr::Udp(SocketAddr::V4(SocketAddrV4::new(addr, port)))
}

/// `IpAddr` が IPv4(または IPv4-mapped)であれば `Ipv4Addr` を返す。
pub fn ip_as_v4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}
