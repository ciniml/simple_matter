//! mDNS ブラウズ(commissionable 発見)と operational 解決。
//!
//! examples/commissioner.rs(browse)と simple-matter-ble/examples/ble-commissioner.rs
//! (operational 解決)の移植。Windows は W3 の成果(QU クエリ + エフェメラルポート、
//! `IP_MULTICAST_IF`/join の LAN 向き IF 固定、`SM_MDNS_TRACE`)を `#[cfg]` で吸収する。

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::{Duration, Instant};

use simple_matter::controller::ca::Ca;
use simple_matter::discovery::client::{CommissionableSet, Ingest, MdnsClient};
#[cfg(unix)]
use simple_matter::discovery::MDNS_IPV6;
use simple_matter::discovery::{MATTER_PORT, MDNS_IPV4, MDNS_PORT};

use super::Backend;

/// mDNS トレースの有効判定: `--log-level trace`、後方互換の `SM_MDNS_TRACE=1`、
/// または `--log-file`(ファイルは常に trace 全量を記録する。設計 doc §9.1/§9.5)。
fn mdns_trace() -> bool {
    std::env::var_os("SM_MDNS_TRACE").is_some() || crate::log::wants(crate::log::Level::Trace)
}

/// `[dis]` トレース行([`mdns_trace`] 判定済みの箇所で使う)。stderr へは env 強制
/// またはグローバル trace のとき、ログファイルへは常に出す([`crate::log::trace_forced`])。
macro_rules! dis_trace {
    ($($arg:tt)*) => {
        crate::log::trace_forced(
            std::env::var_os("SM_MDNS_TRACE").is_some(),
            "dis",
            format_args!($($arg)*),
        )
    };
}

/// `[dis]` info 行。
macro_rules! dis_info {
    ($($arg:tt)*) => {
        crate::log::logf!(crate::log::Level::Info, "dis", $($arg)*)
    };
}

/// ブラウズ中にクエリを再送する間隔。
const MDNS_REQUERY_INTERVAL: Duration = Duration::from_secs(2);

/// nonblocking な複数ソケットを空回しするときの待機。
const MDNS_POLL_SLEEP: Duration = Duration::from_millis(20);

/// v6 リンクローカル(fe80::/10)か。
fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// 解決したアドレスを CASE 接続用の [`SocketAddr`] にする。fe80 リンクローカルには
/// `scope`(v6 mDNS join に使った if_index)を埋める(design §3)。
fn socket_addr_with_scope(ip: IpAddr, port: u16, scope: Option<u32>) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) if is_v6_link_local(v6) => {
            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope.unwrap_or(0)))
        }
        _ => SocketAddr::new(ip, port),
    }
}

/// 再接続時(nodes.tlv は scope を保存しない)に fe80 アドレスへ scope_id を補完する
/// (design §3)。scope 0 の v6 リンクローカルのみ対象。非 unix では既定 scope が
/// 得られず no-op。
pub fn fill_link_local_scope(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if is_v6_link_local(*v6.ip()) && v6.scope_id() == 0 {
            if let Some(scope) = default_v6_scope() {
                return SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, scope));
            }
        }
    }
    addr
}

/// v4 と(unix のみ)v6 の mDNS クエリソケットをまとめて扱う。
///
/// 各ソケットは (ソケット, QU モードか, マルチキャスト宛先) を持ち、応答は
/// ファミリ非依存の [`MdnsClient::parse_*`] に集約する(design §3)。
struct MdnsSockets {
    socks: Vec<MdnsSock>,
    /// v6 ソケットの scope_id(fe80 連絡先の補完に使う)。
    v6_scope: Option<u32>,
}

struct MdnsSock {
    sock: UdpSocket,
    /// unicast-response(QU)モードか(Windows のエフェメラルポート等)。
    qu: bool,
    /// QM 応答/クエリの送信先マルチキャストアドレス。
    mc_dst: SocketAddr,
}

impl MdnsSockets {
    /// v4(+ unix は v6)ソケットを開く。1 本も開けなければ `None`。
    fn open() -> Option<Self> {
        let mut socks = Vec::new();
        // v6 は unix のみ(下の cfg ブロック)。Windows では再代入されず mut が余る。
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut v6_scope = None;
        if let Some((sock, qu)) = open_mdns_browse_socket() {
            socks.push(MdnsSock {
                sock,
                qu,
                mc_dst: SocketAddr::from((MDNS_IPV4, MDNS_PORT)),
            });
        }
        #[cfg(unix)]
        if let Some((sock, scope)) = open_mdns_browse_socket_v6() {
            v6_scope = Some(scope);
            socks.push(MdnsSock {
                sock,
                qu: false,
                mc_dst: SocketAddr::V6(SocketAddrV6::new(MDNS_IPV6, MDNS_PORT, 0, scope)),
            });
        }
        if socks.is_empty() {
            None
        } else {
            Some(Self { socks, v6_scope })
        }
    }

    /// 各ソケットへ、その QU モードに合わせて組んだクエリを送る。
    fn send_query<F>(&self, build: F)
    where
        F: Fn(&mut [u8; 128], bool) -> Result<usize, simple_matter::Error>,
    {
        for s in &self.socks {
            let mut buf = [0u8; 128];
            if let Ok(len) = build(&mut buf, s.qu) {
                let _ = s.sock.send_to(&buf[..len], s.mc_dst);
            }
        }
    }

    /// いずれかのソケットから 1 パケット受信する(nonblocking、無ければ `None`)。
    fn recv(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        for s in &self.socks {
            match s.sock.recv_from(buf) {
                Ok(x) => return Some(x),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
        None
    }
}

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
    let trace = mdns_trace();
    let socks = MdnsSockets::open().ok_or("open mDNS browse socket failed")?;

    let build = |buf: &mut [u8; 128], qu: bool| match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(buf, d, qu),
        None => MdnsClient::build_browse_commissionable(buf, qu),
    };

    let start = Instant::now();
    // 最初のクエリは即時送出(last_query を過去に置く)。
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            socks.send_query(build);
            last_query = Instant::now();
            if trace {
                dis_trace!("browse query sent");
            }
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let parsed = MdnsClient::parse_commissionable(&rx[..n]);
                if trace {
                    let fam = if src.is_ipv6() { "v6" } else { "v4" };
                    dis_trace!(
                        "rx {n}B from {src} ({fam}) parse={}",
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
                    let addr = socket_addr_with_scope(ip, port, socks.v6_scope);
                    dis_info!("found commissionable node at {addr} (discriminator={disc})");
                    return Ok(addr);
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
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
    let trace = mdns_trace();
    let socks = MdnsSockets::open().ok_or("open mDNS browse socket failed")?;

    let build = |buf: &mut [u8; 128], qu: bool| match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(buf, d, qu),
        None => MdnsClient::build_browse_commissionable(buf, qu),
    };

    dis_info!(
        "browsing _matterc._udp.local for {timeout:?} \
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
            socks.send_query(build);
            last_query = Instant::now();
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let ingest = match discriminator {
                    Some(d) => set.ingest_filtered(&rx[..n], d),
                    None => set.ingest(&rx[..n]),
                };
                if trace {
                    let fam = if src.is_ipv6() { "v6" } else { "v4" };
                    dis_trace!("rx {n}B from {src} ({fam}) ingest={ingest:?}");
                }
                if ingest == Ingest::Added {
                    if let Some(node) = set.iter().last() {
                        print_commissionable(node, None);
                    }
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Ok(set.len())
}

/// commissionable ノード 1 件の所有データ([`browse_commissionable_nodes`] の結果)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommissionableInfo {
    /// DNS-SD インスタンス名。
    pub instance: String,
    /// TXT `D`(12 ビット long discriminator)。
    pub discriminator: Option<u16>,
    /// TXT `VP`(Vendor ID, Product ID)。
    pub vendor_product: Option<(u16, u16)>,
    /// TXT `CM`(commissioning mode)。
    pub commissioning_mode: Option<u8>,
    /// SRV ポート(0 なら既定の 5540 に補完済み)。
    pub port: u16,
    /// 接続用アドレス(fe80 は scope 付き)。IPv4 を先頭に並べる。
    pub addrs: Vec<SocketAddr>,
}

impl CommissionableInfo {
    /// 接続先として推す 1 アドレス(IPv4 優先。`browse_commissionable` と同じ規則)。
    pub fn preferred_addr(&self) -> Option<SocketAddr> {
        self.addrs.first().copied()
    }
}

/// 埋め込み用: `_matterc._udp.local` をブラウズし、見つかった commissionable ノードを
/// データとして返す(表示しない。重複はインスタンス名で除去)。
///
/// `discriminator` 指定時は long discriminator サブタイプでクエリし TXT `D` で絞る。
/// `stop` が `true` を返したノードが見つかった時点で打ち切る(常に `false` なら
/// `timeout` いっぱいブラウズする)。
pub fn browse_commissionable_nodes(
    discriminator: Option<u16>,
    timeout: Duration,
    mut stop: impl FnMut(&CommissionableInfo) -> bool,
) -> Result<Vec<CommissionableInfo>, String> {
    let trace = mdns_trace();
    let socks = MdnsSockets::open().ok_or("open mDNS browse socket failed")?;
    let build = |buf: &mut [u8; 128], qu: bool| match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(buf, d, qu),
        None => MdnsClient::build_browse_commissionable(buf, qu),
    };
    let mut set: CommissionableSet<16> = CommissionableSet::default();
    let mut out: Vec<CommissionableInfo> = Vec::new();
    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            socks.send_query(build);
            last_query = Instant::now();
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let ingest = match discriminator {
                    Some(d) => set.ingest_filtered(&rx[..n], d),
                    None => set.ingest(&rx[..n]),
                };
                if trace {
                    dis_trace!("rx {n}B from {src} ingest={ingest:?}");
                }
                if ingest != Ingest::Added {
                    continue;
                }
                let Some(node) = set.iter().last() else {
                    continue;
                };
                let port = if node.port != 0 {
                    node.port
                } else {
                    MATTER_PORT
                };
                // fe80 の scope は応答を受けた IF を優先する(マルチホームで既定経路と
                // 別の IF にいるデバイス。無ければ v6 ソケットの scope)。
                let scope = match src {
                    SocketAddr::V6(v6) if v6.scope_id() != 0 => Some(v6.scope_id()),
                    _ => socks.v6_scope,
                };
                let mut addrs: Vec<SocketAddr> = node
                    .addrs
                    .iter()
                    .map(|ip| socket_addr_with_scope(*ip, port, scope))
                    .collect();
                addrs.sort_by_key(|a| !a.is_ipv4());
                let info = CommissionableInfo {
                    instance: String::from_utf8_lossy(node.instance()).into_owned(),
                    discriminator: node.discriminator,
                    vendor_product: node.vendor_product,
                    commissioning_mode: node.commissioning_mode,
                    port,
                    addrs,
                };
                let done = stop(&info);
                out.push(info);
                if done {
                    break;
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Ok(out)
}

/// commissionable ノード 1 件を 1 行で表示する(`--json` では 1 行 JSON)。
///
/// `at` が `Some` のとき(`--at` 経由)は、広告の A/AAAA でなく採用したユニキャスト
/// 宛先アドレスを表示する(VPN 到達性のため)。
fn print_commissionable(
    node: &simple_matter::discovery::client::DiscoveredCommissionable,
    at: Option<SocketAddr>,
) {
    let instance = String::from_utf8_lossy(node.instance()).into_owned();
    if crate::json::enabled() {
        let port = if node.port != 0 {
            node.port
        } else {
            MATTER_PORT
        };
        let addrs: Vec<String> = match at {
            Some(a) => vec![format!("\"{}\"", crate::json::escape(&a.to_string()))],
            None => node
                .addrs
                .iter()
                .map(|a| format!("\"{}\"", crate::json::escape(&a.to_string())))
                .collect(),
        };
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
    let addrs: Vec<String> = match at {
        Some(a) => vec![a.to_string()],
        None => node.addrs.iter().map(|a| a.to_string()).collect(),
    };
    println!(
        "[found] {instance}  discriminator={disc} vid/pid={vp} cm={cm} port={port} addrs=[{}]",
        addrs.join(", ")
    );
}

/// `<compressedFabricId>-<nodeId>._matter._tcp.local` の SRV を解決し、
/// デバイスの (アドレス, ポート) を返す。
///
/// ソケットは browse と同じ platform 分岐([`open_mdns_browse_socket`])を使う:
///
/// - **Unix**: 5353 共有 bind(QM)。マルチキャスト応答に加えて**デバイスの定期
///   announce(30 秒間隔 + 起動時バースト)を受動的に拾える**。Wi-Fi AP / IGMP
///   snooping スイッチがホスト→デバイス方向のマルチキャストを落とす環境では
///   クエリ自体が届かないことがあり(実測: E5 NanoC6 + 家庭用 AP)、announce の
///   受動受信が唯一の到達経路になる。エフェメラルポートの QU ソケットは
///   announce(UDP dst 5353)を受けられないため使わない。
/// - **Windows**: 5353 は Dnscache が掴むため QU + エフェメラルポート(W3)。
pub fn resolve_operational(
    ca: &Ca<Backend>,
    node_id: u64,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let trace = mdns_trace();
    let compressed = ca.compressed_fabric_id_bytes();

    let socks = MdnsSockets::open().ok_or("open mDNS query socket failed")?;
    let build = |buf: &mut [u8; 128], qu: bool| {
        MdnsClient::build_resolve_operational(buf, &compressed, node_id, qu)
    };
    dis_info!(
        "resolving _matter._tcp for {:016X}-{node_id:016X}...",
        u64::from_be_bytes(compressed)
    );

    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            socks.send_query(build);
            last_query = Instant::now();
            if trace {
                dis_trace!("operational query sent");
            }
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let parsed = MdnsClient::parse_operational(&rx[..n], &compressed, node_id);
                if trace {
                    let fam = if src.is_ipv6() { "v6" } else { "v4" };
                    dis_trace!(
                        "rx {n}B from {src} ({fam}) parse={}",
                        if parsed.is_some() {
                            "operational"
                        } else {
                            "no-match"
                        }
                    );
                }
                if let Some(node) = parsed {
                    // IPv4 優先(design §3)、無ければ最初のアドレス。v6 リンクローカルは
                    // scope(v6 join に使った if_index)を埋めて CASE 接続可能にする。
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
                        return Ok(socket_addr_with_scope(ip, port, socks.v6_scope));
                    }
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Err(format!(
        "operational node {node_id:#x} not resolved within {timeout:?}"
    ))
}

// ==========================================================================
// --at: VPN 越しのユニキャスト mDNS 直叩き(matter-over-vpn.md V1 / 案 C1)
// ==========================================================================

/// `--at <ip>...` 用のユニキャスト QU クエリソケット群。
///
/// マルチキャスト browse の代わりに、指定ホスト群の `:5353` へ QU クエリを
/// **ユニキャスト**で送る。デバイスは W3 の QU 対応により送信元へユニキャスト応答するので、
/// 応答中の A/AAAA(デバイスの LAN アドレス。VPN からは到達できない)は捨て、
/// **クエリを送った宛先 IP** + 応答 SRV のポートを接続先に採用する(design §4 案 C1)。
struct UnicastAt {
    /// v4 宛先がある場合のエフェメラルポート v4 ソケット。
    v4: Option<UdpSocket>,
    /// v6 宛先がある場合のエフェメラルポート v6 ソケット。
    v6: Option<UdpSocket>,
    /// クエリ宛先(`:5353`、fe80 は scope 補完済み)。
    dests: Vec<SocketAddr>,
}

impl UnicastAt {
    /// 宛先 IP 群からソケットを開く。fe80 リテラルは scope を補完する。
    fn open(targets: &[IpAddr]) -> Result<Self, String> {
        let mut need_v4 = false;
        let mut need_v6 = false;
        let mut dests = Vec::with_capacity(targets.len());
        for &ip in targets {
            match ip {
                IpAddr::V4(_) => need_v4 = true,
                IpAddr::V6(_) => need_v6 = true,
            }
            // クエリは常に 5353 宛。fe80 は CASE 接続と揃うよう scope_id を補完する。
            dests.push(fill_link_local_scope(SocketAddr::new(ip, MDNS_PORT)));
        }
        let v4 = if need_v4 {
            let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|e| format!("bind unicast v4 socket: {e}"))?;
            s.set_nonblocking(true).ok();
            Some(s)
        } else {
            None
        };
        let v6 = if need_v6 {
            let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
                .map_err(|e| format!("bind unicast v6 socket: {e}"))?;
            s.set_nonblocking(true).ok();
            Some(s)
        } else {
            None
        };
        Ok(Self { v4, v6, dests })
    }

    /// QU クエリを各宛先へ送る(build は常に QU モードで組む)。
    fn send_query<F>(&self, build: F)
    where
        F: Fn(&mut [u8; 128]) -> Result<usize, simple_matter::Error>,
    {
        let mut buf = [0u8; 128];
        let Ok(len) = build(&mut buf) else { return };
        for dst in &self.dests {
            let sock = match dst {
                SocketAddr::V4(_) => self.v4.as_ref(),
                SocketAddr::V6(_) => self.v6.as_ref(),
            };
            if let Some(s) = sock {
                let _ = s.send_to(&buf[..len], dst);
            }
        }
    }

    /// いずれかのソケットから 1 パケット受信する(nonblocking)。
    fn recv(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        for s in [self.v4.as_ref(), self.v6.as_ref()].into_iter().flatten() {
            match s.recv_from(buf) {
                Ok(x) => return Some(x),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }
        None
    }

    /// 応答元に一致する**クエリ宛先**(scope 補完済み)を接続先として採用し、
    /// SRV ポートを差し込む。A/AAAA は使わない(VPN 到達性のため)。
    fn adopt(&self, src: SocketAddr, port: u16) -> SocketAddr {
        let mut addr = self
            .dests
            .iter()
            .find(|d| d.ip() == src.ip())
            .copied()
            .unwrap_or_else(|| fill_link_local_scope(src));
        addr.set_port(if port != 0 { port } else { MATTER_PORT });
        addr
    }
}

/// `--at`: 指定ホスト群へ QU 直叩きして operational ノードを解決する。
///
/// 応答 SRV のポート + クエリ宛先 IP を採用する(A/AAAA は無視)。
pub fn resolve_operational_at(
    ca: &Ca<Backend>,
    node_id: u64,
    targets: &[IpAddr],
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let trace = mdns_trace();
    let compressed = ca.compressed_fabric_id_bytes();
    let socks = UnicastAt::open(targets)?;
    let build = |buf: &mut [u8; 128]| {
        MdnsClient::build_resolve_operational(buf, &compressed, node_id, true)
    };
    dis_info!(
        "resolving _matter._tcp for {:016X}-{node_id:016X} via unicast mDNS \
         (at {} host(s))...",
        u64::from_be_bytes(compressed),
        targets.len()
    );

    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    // 2 段解決の状態: SRV のみ先に得られた場合の target ホスト名(先頭ラベル)とポート。
    //
    // OTBR の native mDNS publisher は SRV 応答の additional に AAAA を同梱しない
    // (Matter over Thread の advertising proxy 経由で実測)。その場合は
    // `<host>.local` の AAAA を追加クエリで解決し、**応答の AAAA(デバイスの
    // OMR/mesh-local アドレス)** へ接続する(プロキシ応答のため `src` への adopt は
    // 不可 — src は OTBR ホスト自身)。
    let mut srv_host = [0u8; 63];
    let mut srv: Option<(usize, u16)> = None;
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            match srv {
                None => socks.send_query(build),
                Some((hlen, _)) => {
                    let host = &srv_host[..hlen];
                    socks.send_query(|buf: &mut [u8; 128]| {
                        MdnsClient::build_resolve_host_aaaa(buf, host, true)
                    });
                }
            }
            last_query = Instant::now();
            if trace {
                dis_trace!(
                    "(at) {} query sent to {} host(s)",
                    if srv.is_none() {
                        "operational(SRV)"
                    } else {
                        "host(AAAA)"
                    },
                    targets.len()
                );
            }
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                // 1 パケット完結(SRV + AAAA 同梱)ならそのまま採用。
                let parsed = MdnsClient::parse_operational(&rx[..n], &compressed, node_id);
                if let Some(node) = parsed {
                    // アドレス付き応答: プロキシ応答(AAAA がデバイスのアドレス)を優先し、
                    // 無ければ従来どおり応答元へ adopt する。
                    //
                    // ただし**リンクローカル(fe80::/10)の AAAA は採用しない**: 応答パース
                    // 経由では scope_id が付かず、そのまま接続すると送信できず CASE が
                    // 黙って死ぬ(WiFi デバイスが GUA 取得前に fe80 だけ広告する起動直後の
                    // 窓で実測。generic-firmware.md P6)。その場合は問い合わせ先(= src、
                    // v4 なら v4、v6 なら scope 付き)へ adopt する。
                    if let Some(v6) = node.addrs.iter().find(|a| match a {
                        IpAddr::V6(v) => !is_v6_link_local(*v),
                        IpAddr::V4(_) => false,
                    }) {
                        let addr = SocketAddr::new(*v6, node.port);
                        dis_info!("(at) operational node resolved at {addr}");
                        return Ok(addr);
                    }
                    let addr = socks.adopt(src, node.port);
                    dis_info!("(at) operational node adopted at {addr}");
                    return Ok(addr);
                }
                // SRV のみの応答(OTBR native publisher)→ 2 段目(AAAA)へ移行。
                if srv.is_none() {
                    if let Some((hlen, port)) = MdnsClient::parse_operational_srv(
                        &rx[..n],
                        &compressed,
                        node_id,
                        &mut srv_host,
                    ) {
                        srv = Some((hlen, port));
                        dis_info!(
                            "(at) SRV-only answer: target={}.local port={port}; resolving AAAA...",
                            String::from_utf8_lossy(&srv_host[..hlen])
                        );
                        // 即座に AAAA クエリを撃つ。
                        last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
                        continue;
                    }
                }
                // 2 段目: AAAA 応答からデバイスアドレスを得る。
                if let Some((hlen, port)) = srv {
                    let addrs = MdnsClient::parse_host_addrs(&rx[..n], &srv_host[..hlen]);
                    // 1 段目と同じ理由でリンクローカルは採用しない。
                    let v6 = addrs
                        .iter()
                        .find(|a| match a {
                            IpAddr::V6(v) => !is_v6_link_local(*v),
                            IpAddr::V4(_) => false,
                        })
                        .copied();
                    if let Some(v6) = v6 {
                        let addr = SocketAddr::new(v6, port);
                        dis_info!("(at) operational node resolved at {addr} (two-step)");
                        return Ok(addr);
                    }
                }
                if trace {
                    dis_trace!("(at) rx {n}B from {src} parse=no-match");
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Err(format!(
        "operational node {node_id:#x} not resolved via unicast mDNS (--at) within {timeout:?}"
    ))
}

/// `--at`: QU 直叩きで最初に見つかった commissionable ノードの接続先を返す
/// (pairing onnetwork[-long] 用)。
pub fn browse_commissionable_at(
    discriminator: Option<u16>,
    targets: &[IpAddr],
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let trace = mdns_trace();
    let socks = UnicastAt::open(targets)?;
    let build = |buf: &mut [u8; 128]| match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(buf, d, true),
        None => MdnsClient::build_browse_commissionable(buf, true),
    };

    let start = Instant::now();
    let mut last_query = Instant::now() - MDNS_REQUERY_INTERVAL;
    let mut rx = [0u8; 1500];
    while start.elapsed() < timeout {
        if last_query.elapsed() >= MDNS_REQUERY_INTERVAL {
            socks.send_query(build);
            last_query = Instant::now();
            if trace {
                dis_trace!("(at) browse query sent to {} host(s)", targets.len());
            }
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let parsed = MdnsClient::parse_commissionable(&rx[..n]);
                if trace {
                    dis_trace!(
                        "(at) rx {n}B from {src} parse={}",
                        if parsed.is_some() {
                            "commissionable"
                        } else {
                            "no-match"
                        }
                    );
                }
                let Some(node) = parsed else { continue };
                if let Some(want) = discriminator {
                    if node.discriminator != Some(want) {
                        continue;
                    }
                }
                let disc = node
                    .discriminator
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "?".into());
                let addr = socks.adopt(src, node.port);
                dis_info!("(at) found commissionable node at {addr} (discriminator={disc})");
                return Ok(addr);
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Err(format!(
        "no commissionable device found via unicast mDNS (--at) within {timeout:?}"
    ))
}

/// `--at`: `discover commissionable` の一覧版。QU 直叩きで見つかった各ノードを、
/// 採用アドレス(クエリ宛先 IP + SRV ポート)付きで 1 行ずつ表示し総数を返す。
pub fn browse_commissionable_list_at(
    discriminator: Option<u16>,
    targets: &[IpAddr],
    timeout: Duration,
) -> Result<usize, String> {
    let trace = mdns_trace();
    let socks = UnicastAt::open(targets)?;
    let build = |buf: &mut [u8; 128]| match discriminator {
        Some(d) => MdnsClient::build_browse_discriminator(buf, d, true),
        None => MdnsClient::build_browse_commissionable(buf, true),
    };
    dis_info!(
        "unicast mDNS browse (at {} host(s)) for {timeout:?} \
         (discriminator filter: {})...",
        targets.len(),
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
            socks.send_query(build);
            last_query = Instant::now();
        }
        match socks.recv(&mut rx) {
            Some((n, src)) => {
                let ingest = match discriminator {
                    Some(d) => set.ingest_filtered(&rx[..n], d),
                    None => set.ingest(&rx[..n]),
                };
                if trace {
                    dis_trace!("(at) rx {n}B from {src} ingest={ingest:?}");
                }
                if ingest == Ingest::Added {
                    if let Some(node) = set.iter().last() {
                        let adopted = socks.adopt(src, node.port);
                        print_commissionable(node, Some(adopted));
                    }
                }
            }
            None => std::thread::sleep(MDNS_POLL_SLEEP),
        }
    }
    Ok(set.len())
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
        // 複数ソケット(v4 + v6)を 1 スレッドで多重化するため nonblocking にする。
        socket.set_nonblocking(true).ok()?;
        Some((socket, false))
    }
    #[cfg(not(unix))]
    {
        open_mdns_query_socket()
    }
}

/// IPv6(ff02::fb)mDNS クエリソケット(unix、5353 共有 bind + join)。戻りは
/// (ソケット, scope_id)。リンクローカルが取れなければ `None`。
#[cfg(unix)]
fn open_mdns_browse_socket_v6() -> Option<(UdpSocket, u32)> {
    let scope = default_v6_scope()?;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    socket.set_only_v6(true).ok()?;
    socket.set_reuse_address(true).ok()?;
    let _ = socket.set_reuse_port(true);
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, MDNS_PORT)).into())
        .ok()?;
    let socket: UdpSocket = socket.into();
    socket.join_multicast_v6(&MDNS_IPV6, scope).ok()?;
    socket.set_nonblocking(true).ok()?;
    Some((socket, scope))
}

/// 既定 v6 リンクローカル scope_id(if_index)を推定する。
///
/// `/proc/net/route` の既定経路 iface の fe80 行を優先(仮想 IF が先に並ぶ環境対策、
/// W3 の教訓)。無ければ最初の非 lo fe80 にフォールバック。非 Linux は `None`
/// (smctl の v6 は unix のみ、Windows は v4 のまま = 許容乖離)。
#[cfg(target_os = "linux")]
pub fn default_v6_scope() -> Option<u32> {
    let want_if = default_route_ifname_v6scope();
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    let mut fallback: Option<u32> = None;
    for line in text.lines() {
        let mut cols = line.split_whitespace();
        let _addr = cols.next()?;
        let if_index_hex = cols.next()?;
        let _prefix = cols.next()?;
        let scope_hex = cols.next()?;
        let _flags = cols.next()?;
        let ifname = cols.next()?;
        if ifname == "lo" {
            continue;
        }
        if u32::from_str_radix(scope_hex, 16).ok()? != 0x20 {
            continue;
        }
        let if_index = u32::from_str_radix(if_index_hex, 16).ok()?;
        match &want_if {
            Some(name) if name == ifname => return Some(if_index),
            _ => {
                if fallback.is_none() {
                    fallback = Some(if_index);
                }
            }
        }
    }
    fallback
}

/// `/proc/net/route` から IPv4 既定経路(Destination=00000000)の iface 名を得る。
#[cfg(target_os = "linux")]
fn default_route_ifname_v6scope() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let ifname = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(ifname.to_string());
        }
    }
    None
}

/// 非 Linux 向けフォールバック(v6 scope 発見なし)。
#[cfg(not(target_os = "linux"))]
pub fn default_v6_scope() -> Option<u32> {
    None
}

/// mDNS 解決用ソケット(エフェメラルポート + QU、Windows 用)。戻りの `bool` は
/// QU モード(常に true)。
///
/// 仮想アダプタ(WSL/Hyper-V/VPN)が多い環境ではインターフェース未指定だと
/// マルチキャストの送信/join が LAN 以外の既定 IF に張り付くことがあるため、
/// デフォルトルートのローカル IPv4 で LAN 向き IF に明示的に固定する。
#[cfg(not(unix))]
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
#[cfg(not(unix))]
fn default_route_local_ipv4() -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    s.connect((Ipv4Addr::new(8, 8, 8, 8), 53)).ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}
