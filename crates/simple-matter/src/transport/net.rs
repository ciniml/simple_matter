//! Network 抽象:UDP 送受信の最小 async trait と、宛先アドレス型。
//!
//! `docs/design/transport-exchange.md` §2 に基づく。要件は no_std・async・
//! executor 非依存で、smoltcp / OS ソケット / OpenThread など任意のバックエンドへ
//! 差し替え可能なこと。この trait 群は `core::future::Future` にしか依存せず、
//! 時間(MRP タイマ)にも触れない。
//!
//! # 送信と受信を分ける理由
//!
//! RX ループと TX/MRP タイマループを別タスクに置けるようにするため、また実装が
//! 片方向しか持たない構成(例: TX は共有、RX は割り込み駆動)を許すため、送信と
//! 受信を別 trait([`UdpSend`] / [`UdpReceive`])に分ける。マルチキャストは
//! discovery / group messaging 専用として [`UdpMulticast`] に分離する。
//!
//! # `PeerAddr` を 1 枚挟む理由
//!
//! `SocketAddr` を全シグネチャへ直接使うと、将来 BTP(BLE)や TCP を足したときに
//! 全面改修になる。かといって最初から 3 分岐する enum は UDP 専用の現状では過剰で
//! ある。現状 variant 1 個の enum なら分岐コストはほぼゼロで、拡張点だけ確保できる。

use core::net::{IpAddr, SocketAddr};

use crate::error::Result;

/// UDP パケットのワイヤ上の最大サイズ(バイト)。
///
/// Matter Core Specification に基づく RX 側の上限。
pub const MAX_RX_PACKET_SIZE: usize = 1583;

/// UDP パケットのワイヤ上の最大サイズ(バイト)。
///
/// IPv6 ヘッダ 40 バイトと UDP ヘッダ 8 バイトを最小 MTU 1280 から控除した TX 側の上限。
pub const MAX_TX_PACKET_SIZE: usize = 1280 - 40 - 8;

/// Matter メッセージの宛先。
///
/// 現状は UDP のみだが、シグネチャを変えずに BTP / TCP へ拡張できるよう enum で包む。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    /// UDP ソケットアドレス(IPv4 / IPv6)。
    Udp(SocketAddr),
}

impl PeerAddr {
    /// 保持しているソケットアドレスを返す。
    ///
    /// UDP 以外のトランスポートを足した場合は `None` を返す variant が増える想定だが、
    /// 現状は常に `Some`。
    pub const fn socket_addr(self) -> Option<SocketAddr> {
        match self {
            PeerAddr::Udp(addr) => Some(addr),
        }
    }

    /// セッション照合用に正規化したアドレスを返す。
    ///
    /// dual-stack ソケットは IPv4 のピアを IPv4-mapped IPv6(`::ffff:a.b.c.d`)で
    /// 報告することがある。照合の**比較時のみ**この正規化を通すことで、格納した
    /// アドレス(返信の宛先に使う生アドレス)を壊さずに一致判定できる。
    pub fn canonical(self) -> Self {
        match self {
            PeerAddr::Udp(addr) => PeerAddr::Udp(canonical_socket_addr(addr)),
        }
    }
}

/// IPv4-mapped IPv6 アドレスを IPv4 へ畳み込んで正規化する。
///
/// それ以外のアドレスはそのまま返す。ポート番号は保持する。
pub fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// 1 Matter パケットを宛先へ送る送信側 trait。
///
/// パケット化(1 datagram = 1 Matter メッセージ)は UDP では自明なため、実装側は
/// `data` をそのまま 1 datagram として送ればよい。
#[allow(async_fn_in_trait)] // executor 非依存・単一タスク前提のため Send 境界は課さない(§2.2)。
pub trait UdpSend {
    /// `data` を `addr` 宛に 1 パケットとして送信する。
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<()>;
}

/// 1 Matter パケットを受信する受信側 trait。
///
/// `buf` は呼び出し側(Transport)が用意する共有 RX バッファで、実装側にヒープ確保を
/// 強制しない。受信バイト数と送信元アドレスを返す。
#[allow(async_fn_in_trait)] // executor 非依存・単一タスク前提のため Send 境界は課さない(§2.2)。
pub trait UdpReceive {
    /// 1 パケットを受信し `buf` 先頭へ書き込む。受信長と送信元を返す。
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)>;
}

/// IPv6 マルチキャストのグループ参加/離脱を行う trait。
///
/// 運用ディスカバリ(mDNS)とグループキャストのために用いる。初期スコープでは
/// discovery 層のみが使い、group messaging は feature gate。UDP 実装のみが提供すればよい。
#[allow(async_fn_in_trait)] // executor 非依存・単一タスク前提のため Send 境界は課さない(§2.2)。
pub trait UdpMulticast {
    /// マルチキャストグループ `group` に参加する。
    async fn join(&mut self, group: core::net::Ipv6Addr) -> Result<()>;

    /// マルチキャストグループ `group` から離脱する。
    async fn leave(&mut self, group: core::net::Ipv6Addr) -> Result<()>;
}

impl<T: UdpSend + ?Sized> UdpSend for &mut T {
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<()> {
        (**self).send_to(data, addr).await
    }
}

impl<T: UdpReceive + ?Sized> UdpReceive for &mut T {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)> {
        (**self).recv_from(buf).await
    }
}

impl<T: UdpMulticast + ?Sized> UdpMulticast for &mut T {
    async fn join(&mut self, group: core::net::Ipv6Addr) -> Result<()> {
        (**self).join(group).await
    }

    async fn leave(&mut self, group: core::net::Ipv6Addr) -> Result<()> {
        (**self).leave(group).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn canonicalizes_ipv4_mapped_ipv6() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 168, 1, 5).to_ipv6_mapped(),
            5540,
            0,
            0,
        ));
        let canon = canonical_socket_addr(mapped);
        assert_eq!(
            canon,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 5540))
        );
        // PeerAddr 経由でも同じ結果。
        assert_eq!(PeerAddr::Udp(mapped).canonical(), PeerAddr::Udp(canon));
    }

    #[test]
    fn leaves_native_addresses_untouched() {
        let v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234));
        assert_eq!(canonical_socket_addr(v4), v4);
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 0, 0));
        assert_eq!(canonical_socket_addr(v6), v6);
    }

    /// `&mut T` へのブランケット実装が合成に使えることを型レベルで確認する。
    #[test]
    fn blanket_impls_compile() {
        struct Loopback;
        impl UdpSend for Loopback {
            async fn send_to(&mut self, _data: &[u8], _addr: PeerAddr) -> Result<()> {
                Ok(())
            }
        }
        fn assert_send(_: impl UdpSend) {}
        let mut lb = Loopback;
        assert_send(&mut lb);
    }
}
