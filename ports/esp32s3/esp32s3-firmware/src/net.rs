//! コアの UDP trait 群(`UdpSend` / `UdpReceive` / `UdpMulticast`)の embassy-net 実装。
//!
//! `docs/design/port-esp32-device.md` §3 / §E5.5。コアの trait 定義
//! (`simple_matter::transport::net`)はこれまで**実装ゼロ**だった(PC examples は
//! `std::net::UdpSocket` 直書き)。本モジュールが実利用第 1 号で、esp-radio の
//! Wi-Fi `Interface`(embassy-net-driver)上の [`embassy_net::udp::UdpSocket`] を包む。
//!
//! # IPv4 + IPv6 リンクローカル(doc §E5.5 / docs/design/mdns-ipv6.md §4)
//!
//! smoltcp は `proto-ipv4` + `proto-ipv6`(link-local 静的設定)を有効化する。宛先は
//! `canonical_socket_addr` で正規化してから smoltcp の [`IpEndpoint`] に渡す。v4 ピアは
//! IPv4-mapped IPv6(`::ffff:a.b.c.d`)が正規化で v4 に戻り、fe80 リンクローカルは実 v6
//! endpoint として送る(単一インターフェースのため scope_id 不要)。
//! [`UdpMulticast::join`] は mapped v4 グループ(`::ffff:224.0.0.251` → IGMP)と実 v6
//! グループ(`ff02::fb` → MLD)の双方を受ける。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use embassy_net::udp::UdpSocket;
use embassy_net::{IpAddress, IpEndpoint, Stack};

use simple_matter::error::{Error, Result};
use simple_matter::transport::net::{
    canonical_socket_addr, PeerAddr, UdpMulticast, UdpReceive, UdpSend,
};

/// `SocketAddr` を smoltcp の [`IpEndpoint`] へ変換する(mapped v4 は正規化で unmap、
/// 実 v6 リンクローカルはそのまま)。proto-ipv4 + proto-ipv6 の双方を扱える。
fn endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::from(canonical_socket_addr(addr))
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
        let ep = endpoint(sa);
        self.socket
            .send_to(data, ep)
            .await
            .map_err(|_| Error::NoSpace)
    }
}

impl UdpReceive for EspUdp<'_> {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)> {
        let (n, meta) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|_| Error::Decode)?;
        let sa: SocketAddr = meta.endpoint.into();
        Ok((n, PeerAddr::Udp(sa)))
    }
}

impl UdpMulticast for EspUdp<'_> {
    async fn join(&mut self, group: Ipv6Addr) -> Result<()> {
        self.stack
            .join_multicast_group(multicast_group(group))
            .map_err(|_| Error::NoSpace)
    }

    async fn leave(&mut self, group: Ipv6Addr) -> Result<()> {
        self.stack
            .leave_multicast_group(multicast_group(group))
            .map_err(|_| Error::NotFound)
    }
}

/// コア trait の `Ipv6Addr` グループを smoltcp の [`IpAddress`] へ写像する。
/// IPv4-mapped(`::ffff:224.0.0.251`)は v4 グループ(IGMP)、実 v6(`ff02::fb`)は
/// v6 グループ(MLD)として join する。
fn multicast_group(group: Ipv6Addr) -> IpAddress {
    match mapped_v4(group) {
        Some(v4) => IpAddress::from(v4),
        None => IpAddress::from(group),
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

/// IPv6 の `(addr, port)` を [`PeerAddr::Udp`] にする送信宛先ヘルパ(scope_id=0。
/// 単一インターフェースのため scope 不要)。
pub fn peer_v6(addr: Ipv6Addr, port: u16) -> PeerAddr {
    PeerAddr::Udp(SocketAddr::V6(core::net::SocketAddrV6::new(
        addr, port, 0, 0,
    )))
}

/// `IpAddr` が IPv4(または IPv4-mapped)であれば `Ipv4Addr` を返す。
pub fn ip_as_v4(addr: IpAddr) -> Option<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}
