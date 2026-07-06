//! mDNS ブラウズ(commissionable 発見)と operational 解決。
//!
//! examples/commissioner.rs(browse)と simple-matter-ble/examples/ble-commissioner.rs
//! (operational 解決)の移植。Windows は W3 の成果(QU クエリ + エフェメラルポート、
//! `IP_MULTICAST_IF`/join の LAN 向き IF 固定、`SM_MDNS_TRACE`)を `#[cfg]` で吸収する。

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use simple_matter::controller::ca::Ca;
use simple_matter::discovery::client::{CommissionableSet, Ingest, MdnsClient};
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_PORT};

use super::Backend;

/// ブラウズ中にクエリを再送する間隔。
const MDNS_REQUERY_INTERVAL: Duration = Duration::from_secs(2);

/// `_matterc._udp.local` を PTR ブラウズし、最初に発見した commissionable ノードの
/// (アドレス, ポート)を返す。
///
/// `discriminator` 指定時は long discriminator サブタイプでクエリし、応答側も TXT `D` で
/// 照合する。タイムアウトはデバイスの再 announce 間隔(既定 30 秒)より長く取ること
/// (5353 共有で受信を取りこぼすデバイスでも定期 announce を確実に拾うため)。
pub fn browse_commissionable(
    discriminator: Option<u16>,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let trace = std::env::var_os("SM_MDNS_TRACE").is_some();
    let (socket, qu) = open_mdns_browse_socket().ok_or("open mDNS browse socket failed")?;

    let mut query = [0u8; 128];
    let qlen = match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(&mut query, d, qu),
        None => MdnsClient::build_browse_commissionable(&mut query, qu),
    }
    .map_err(|e| format!("build mDNS query: {e:?}"))?;

    let start = Instant::now();
    // 最初のクエリは即時送出(last_query を過去に置く)。
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
            last_query = Instant::now();
            if trace {
                eprintln!("[mdns-trace] browse query sent ({qlen}B, qu={qu})");
            }
        }
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let parsed = MdnsClient::parse_commissionable(&rx[..n]);
                if trace {
                    eprintln!(
                        "[mdns-trace] rx {n}B from {src} parse={}",
                        if parsed.is_some() {
                            "commissionable"
                        } else {
                            "no-match"
                        }
                    );
                }
                let Some(node) = parsed else { continue };
                // discriminator 指定時は TXT `D` の一致を要求する。
                if let Some(want) = discriminator {
                    if node.discriminator != Some(want) {
                        continue;
                    }
                }
                // IPv4 を優先(dual-stack ソケットで扱いやすい)、無ければ最初のアドレス。
                let picked = node
                    .addrs
                    .iter()
                    .find(|a| a.is_ipv4())
                    .or_else(|| node.addrs.iter().next())
                    .copied();
                if let Some(ip) = picked {
                    let port = if node.port != 0 {
                        node.port
                    } else {
                        MATTER_PORT
                    };
                    let disc = node
                        .discriminator
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "?".into());
                    eprintln!(
                        "[discovery] found commissionable node at {ip}:{port} (discriminator={disc})"
                    );
                    return Ok(SocketAddr::new(ip, port));
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("mDNS recv: {e}")),
        }
    }
    Err(format!(
        "no commissionable device found within {timeout:?} (is the device in commissioning mode?)"
    ))
}

/// `discover commissionable`: ブラウズ期間いっぱい待ち、見つかった commissionable ノードを
/// 発見のたびに 1 行ずつ表示して総数を返す(重複はインスタンス名で除去)。
///
/// [`browse_commissionable`](最初の 1 台で打ち切り)の一覧版。
pub fn browse_commissionable_list(
    discriminator: Option<u16>,
    timeout: Duration,
) -> Result<usize, String> {
    let trace = std::env::var_os("SM_MDNS_TRACE").is_some();
    let (socket, qu) = open_mdns_browse_socket().ok_or("open mDNS browse socket failed")?;

    let mut query = [0u8; 128];
    let qlen = match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(&mut query, d, qu),
        None => MdnsClient::build_browse_commissionable(&mut query, qu),
    }
    .map_err(|e| format!("build mDNS query: {e:?}"))?;

    eprintln!(
        "[discover] browsing _matterc._udp.local for {timeout:?} \
         (discriminator filter: {})...",
        discriminator
            .map(|d| d.to_string())
            .unwrap_or_else(|| "none".into())
    );

    let mut set: CommissionableSet<16> = CommissionableSet::default();
    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
            last_query = Instant::now();
        }
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let ingest = match discriminator {
                    Some(d) => set.ingest_filtered(&rx[..n], d),
                    None => set.ingest(&rx[..n]),
                };
                if trace {
                    eprintln!("[mdns-trace] rx {n}B from {src} ingest={ingest:?}");
                }
                if ingest == Ingest::Added {
                    if let Some(node) = set.iter().last() {
                        print_commissionable(node);
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("mDNS recv: {e}")),
        }
    }
    Ok(set.len())
}

/// commissionable ノード 1 件を 1 行で表示する(`--json` では 1 行 JSON)。
fn print_commissionable(node: &simple_matter::discovery::client::DiscoveredCommissionable) {
    let instance = String::from_utf8_lossy(node.instance()).into_owned();
    if crate::json::enabled() {
        let port = if node.port != 0 {
            node.port
        } else {
            MATTER_PORT
        };
        let addrs: Vec<String> = node
            .addrs
            .iter()
            .map(|a| format!("\"{}\"", crate::json::escape(&a.to_string())))
            .collect();
        let mut o = crate::json::Obj::new("commissionable")
            .str("instance", &instance)
            .num("port", port)
            .raw("addrs", &format!("[{}]", addrs.join(",")));
        if let Some(d) = node.discriminator {
            o = o.num("discriminator", d);
        }
        if let Some((v, p)) = node.vendor_product {
            o = o.num("vendorId", v).num("productId", p);
        }
        if let Some(cm) = node.commissioning_mode {
            o = o.num("commissioningMode", cm);
        }
        o.emit();
        return;
    }
    let disc = node
        .discriminator
        .map(|d| d.to_string())
        .unwrap_or_else(|| "?".into());
    let vp = node
        .vendor_product
        .map(|(v, p)| format!("{v:#06x}/{p:#06x}"))
        .unwrap_or_else(|| "?".into());
    let cm = node
        .commissioning_mode
        .map(|m| m.to_string())
        .unwrap_or_else(|| "?".into());
    let port = if node.port != 0 {
        node.port
    } else {
        MATTER_PORT
    };
    let addrs: Vec<String> = node.addrs.iter().map(|a| a.to_string()).collect();
    println!(
        "[found] {instance}  discriminator={disc} vid/pid={vp} cm={cm} port={port} addrs=[{}]",
        addrs.join(", ")
    );
}

/// `<compressedFabricId>-<nodeId>._matter._tcp.local` の SRV を解決し、
/// デバイスの (アドレス, ポート) を返す。
///
/// chip の Minimal mDNS は 5353 を掴む(avahi とも競合)ため、**QU(unicast-response)
/// ビット + エフェメラルポート**で応答を自ポートへのユニキャストで受ける
/// (RFC 6762 §5.4)。マルチキャスト announce も拾えるよう group join も行う。
pub fn resolve_operational(
    ca: &Ca<Backend>,
    node_id: u64,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let trace = std::env::var_os("SM_MDNS_TRACE").is_some();
    let compressed = ca.compressed_fabric_id_bytes();

    let (socket, qu) = open_mdns_query_socket().ok_or("open mDNS query socket failed")?;
    let mut query = [0u8; 128];
    let qlen = MdnsClient::build_resolve_operational(&mut query, &compressed, node_id, qu)
        .map_err(|e| format!("build_resolve_operational: {e:?}"))?;
    eprintln!(
        "[discovery] resolving _matter._tcp for {:016X}-{node_id:016X} (qu={qu})...",
        u64::from_be_bytes(compressed)
    );

    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            let _ = socket.send_to(&query[..qlen], (MDNS_IPV4, MDNS_PORT));
            last_query = Instant::now();
            if trace {
                eprintln!("[mdns-trace] operational query sent ({qlen}B, qu={qu})");
            }
        }
        match socket.recv_from(&mut rx) {
            Ok((n, src)) => {
                let parsed = MdnsClient::parse_operational(&rx[..n], &compressed, node_id);
                if trace {
                    eprintln!(
                        "[mdns-trace] rx {n}B from {src} parse={}",
                        if parsed.is_some() {
                            "operational"
                        } else {
                            "no-match"
                        }
                    );
                }
                if let Some(node) = parsed {
                    let picked = node
                        .addrs
                        .iter()
                        .find(|a| a.is_ipv4())
                        .or_else(|| node.addrs.iter().next())
                        .copied();
                    if let Some(ip) = picked {
                        let port = if node.port != 0 {
                            node.port
                        } else {
                            MATTER_PORT
                        };
                        return Ok(SocketAddr::new(ip, port));
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(format!("mDNS recv: {e}")),
        }
    }
    Err(format!(
        "operational node {node_id:#x} not resolved within {timeout:?}"
    ))
}

/// commissionable ブラウズ用ソケット。戻りの `bool` は「QU(unicast-response)モードか」。
///
/// - **Unix**: 224.0.0.251:5353 の共有 bind(SO_REUSEADDR で avahi と共存)。
///   マルチキャスト応答を受けるので QU 不要(`false`)。
/// - **Windows**: 5353 は内蔵 mDNS(Dnscache)が掴んでいるため、エフェメラルポート +
///   QU ビットで応答を自ポートへのユニキャストで受ける(RFC 6762 §5.4)。
fn open_mdns_browse_socket() -> Option<(UdpSocket, bool)> {
    #[cfg(unix)]
    {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .ok()?;
        // SO_REUSEADDR のみ(SO_REUSEPORT はマルチキャストを listener 間でロードバランス
        // して取りこぼす)。
        socket.set_reuse_address(true).ok()?;
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())
            .ok()?;
        let socket: UdpSocket = socket.into();
        socket
            .join_multicast_v4(&MDNS_IPV4, &Ipv4Addr::UNSPECIFIED)
            .ok()?;
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok()?;
        Some((socket, false))
    }
    #[cfg(not(unix))]
    {
        open_mdns_query_socket()
    }
}

/// mDNS 解決用ソケット(エフェメラルポート + QU)。戻りの `bool` は QU モード(常に true)。
///
/// 仮想アダプタ(WSL/Hyper-V/VPN)が多い環境ではインターフェース未指定だと
/// マルチキャストの送信/join が LAN 以外の既定 IF に張り付くことがあるため、
/// デフォルトルートのローカル IPv4 で LAN 向き IF に明示的に固定する。
fn open_mdns_query_socket() -> Option<(UdpSocket, bool)> {
    let if_ip = default_route_local_ipv4().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_reuse_address(true).ok()?;
    // 送信 IF の固定(未指定だと既定 IF から送出され LAN に届かないことがある)。
    let _ = socket.set_multicast_if_v4(&if_ip);
    socket
        .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    // マルチキャスト announce(QU を無視する responder 対策)も拾えるよう join(best effort)。
    let _ = socket.join_multicast_v4(&MDNS_IPV4, &if_ip);
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok()?;
    Some((socket, true))
}

/// デフォルトルートのローカル IPv4 を推定する(外部宛 UDP の `local_addr` から。
/// 実際にはパケットを送らない)。マルチキャストの送信/join インターフェース固定用。
fn default_route_local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
