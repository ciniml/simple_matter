//! discovery クライアント(コントローラ側 mDNS ブラウズ / 解決)。
//!
//! `docs/design/controller.md` §5 に基づく。[`MdnsResponder`](super::MdnsResponder) の
//! **鏡像**として、コントローラが commissionable / operational ノードを発見するための
//! クエリを生成し、受信レスポンスを解析・集約する。
//!
//! # sans-IO(§5.1)
//!
//! [`MdnsClient`] は状態レスな関数の名前空間で、行うのは 2 つだけ:
//!
//! - **クエリバイト列の生成**([`build_browse_commissionable`](MdnsClient::build_browse_commissionable)
//!   / [`build_browse_discriminator`](MdnsClient::build_browse_discriminator) /
//!   [`build_resolve_operational`](MdnsClient::build_resolve_operational))。
//! - **受信レスポンスの解析**([`parse_commissionable`](MdnsClient::parse_commissionable) /
//!   [`parse_operational`](MdnsClient::parse_operational))。
//!
//! ソケット・マルチキャスト join・リトライ・タイムアウト・キャッシュは持たず、すべて
//! 呼び出し側(アプリ / 統合層)の責務とする([`MdnsResponder`] と同じ分界)。同一パケット内で
//! 解決できる情報だけを返す(chip / rs-matter のレスポンダは PTR/SRV/TXT/A/AAAA を additional
//! 込みで 1 パケットに同梱するのが通例)。
//!
//! # 結果テーブル(§5.1)
//!
//! ブラウズで見つかったノードは固定容量 `N` の [`CommissionableSet`](const generic)に集約する。
//! 満杯・重複・フィルタ不一致は [`Ingest`] で通知し、ヒープ確保・panic を伴わない。

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Result;
use crate::transport::session::fixed::FixedVec;

use super::dns::{Name, QueryWriter, Response, T_A, T_AAAA, T_PTR, T_SRV, T_TXT};

/// 発見結果 1 件が保持するアドレスの最大数(A / AAAA)。
///
/// chip のノードは 1 ホストにつき IPv4(A)1 件 + IPv6(AAAA)複数件(link-local /
/// 1 つ以上の global)を広告することがある。到達可能なアドレス(特に IPv4)が先頭 2 件から
/// 溢れて捨てられると解決先が到達不能になりうる(方向 B の運用解決で実測)。全アドレスを
/// 取りこぼさないよう広めに取り、選択は呼び出し側に委ねる。
pub const MAX_ADDRS: usize = 6;

/// 発見した commissionable ノードのインスタンス名の最大バイト長(dotted 表記)。
pub const INSTANCE_CAP: usize = 64;

/// commissionable サービス型のラベル列(`_matterc._udp.local`)。
const SVC_COMMISSIONABLE: [&[u8]; 3] = [b"_matterc", b"_udp", b"local"];

/// 発見した commissionable ノード(1 パケット分)。
///
/// インスタンス名・ポート・アドレス・および TXT 由来の識別情報(discriminator / VID+PID /
/// commissioning mode)を保持する。TXT に無いキーは `None`。
#[derive(Debug)]
pub struct DiscoveredCommissionable {
    instance: [u8; INSTANCE_CAP],
    instance_len: usize,
    /// SRV レコードのポート(通常 [`MATTER_PORT`](super::MATTER_PORT))。
    pub port: u16,
    /// 同一パケット内で見つかった A / AAAA アドレス。
    pub addrs: FixedVec<IpAddr, MAX_ADDRS>,
    /// TXT `D`(12 ビット long discriminator)。
    pub discriminator: Option<u16>,
    /// TXT `VP`(Vendor ID, Product ID)。
    pub vendor_product: Option<(u16, u16)>,
    /// TXT `CM`(commissioning mode)。
    pub commissioning_mode: Option<u8>,
}

impl DiscoveredCommissionable {
    fn empty() -> Self {
        Self {
            instance: [0u8; INSTANCE_CAP],
            instance_len: 0,
            port: 0,
            addrs: FixedVec::new(),
            discriminator: None,
            vendor_product: None,
            commissioning_mode: None,
        }
    }

    /// インスタンス名(dotted 表記、再クエリ・重複判定に用いる)。
    pub fn instance(&self) -> &[u8] {
        &self.instance[..self.instance_len]
    }
}

/// operational 解決の結果(アドレスとポート)。
#[derive(Debug)]
pub struct DiscoveredNode {
    /// 同一パケット内で見つかった A / AAAA アドレス。
    pub addrs: FixedVec<IpAddr, MAX_ADDRS>,
    /// SRV レコードのポート。
    pub port: u16,
}

/// discovery クライアント(状態レスな関数の名前空間)。
pub struct MdnsClient;

impl MdnsClient {
    /// `_matterc._udp.local` の PTR クエリ(commissionable browse)を `out` に生成する。
    ///
    /// 戻りは書き込んだバイト長。`unicast_response` は QCLASS の QU ビット(RFC 6762
    /// §5.4)を立て、応答を送信元ポートへのユニキャストで要求する。5353 の共有 bind が
    /// できない環境(Windows の内蔵 mDNS と競合する場合等)向けのフォールバック
    /// (docs/design/port-windows-commissioner.md §3.2)。通常のマルチキャスト運用では
    /// `false` にする。
    pub fn build_browse_commissionable(out: &mut [u8], unicast_response: bool) -> Result<usize> {
        let mut w = QueryWriter::new(out)?;
        w.question(&SVC_COMMISSIONABLE, T_PTR, unicast_response)?;
        Ok(w.finish())
    }

    /// long discriminator サブタイプ(`_L<d>._sub._matterc._udp.local`)での絞り込み
    /// PTR クエリを `out` に生成する。
    /// `unicast_response` は [`build_browse_commissionable`](MdnsClient::build_browse_commissionable)
    /// と同じ QU ビット。
    pub fn build_browse_discriminator(
        out: &mut [u8],
        discriminator: u16,
        unicast_response: bool,
    ) -> Result<usize> {
        let mut sub = [0u8; 8]; // "_L" + 最大 5 桁
        let sub_len = fmt_subtype_l(discriminator, &mut sub);
        let mut w = QueryWriter::new(out)?;
        w.question(
            &[&sub[..sub_len], b"_sub", b"_matterc", b"_udp", b"local"],
            T_PTR,
            unicast_response,
        )?;
        Ok(w.finish())
    }

    /// operational 解決: `<compressed-fabric-id>-<node-id>._matter._tcp.local` の
    /// SRV クエリを `out` に生成する(応答の additional で A/AAAA が同梱される)。
    ///
    /// `compressed_fabric_id` は big-endian 8 バイト。
    /// `unicast_response` は [`build_browse_commissionable`](MdnsClient::build_browse_commissionable)
    /// と同じ QU ビット。
    pub fn build_resolve_operational(
        out: &mut [u8],
        compressed_fabric_id: &[u8; 8],
        node_id: u64,
        unicast_response: bool,
    ) -> Result<usize> {
        let mut inst = [0u8; 33];
        operational_instance_label(compressed_fabric_id, node_id, &mut inst);
        let mut w = QueryWriter::new(out)?;
        w.question(
            &[&inst, b"_matter", b"_tcp", b"local"],
            T_SRV,
            unicast_response,
        )?;
        Ok(w.finish())
    }

    /// 受信パケットから commissionable ノードを 1 件抽出する。
    ///
    /// `_matterc._udp.local` の PTR → インスタンス名 → SRV(ポート/ホスト)→ TXT(識別情報)
    /// → ホストの A/AAAA を同一パケット内で辿る。commissionable として解釈できなければ `None`。
    pub fn parse_commissionable(pkt: &[u8]) -> Option<DiscoveredCommissionable> {
        let resp = Response::parse(pkt)?;

        // 1. サービス型 PTR からインスタンス名を得る(4 ラベルのみ受理)。
        let mut instance: Option<Name> = None;
        for r in resp.records() {
            if r.rtype == T_PTR && r.name.eq_ci(&SVC_COMMISSIONABLE) {
                if let Some(n) = r.rdata_name() {
                    if n.len() == 4 {
                        instance = Some(n);
                        break;
                    }
                }
            }
        }
        let instance = instance?;

        let mut result = DiscoveredCommissionable::empty();
        result.instance_len = name_to_dotted(&instance, &mut result.instance);

        // 2. SRV: owner == instance → port + target host。
        let mut target: Option<Name> = None;
        for r in resp.records() {
            if r.rtype == T_SRV && name_eq(&r.name, &instance) {
                if let Some((_, _, port, tgt)) = r.srv() {
                    result.port = port;
                    target = Some(tgt);
                    break;
                }
            }
        }

        // 3. TXT: owner == instance → D / VP / CM。
        for r in resp.records() {
            if r.rtype == T_TXT && name_eq(&r.name, &instance) {
                for (k, v) in r.txt_entries() {
                    if k == b"D" {
                        result.discriminator = parse_u16(v);
                    } else if k == b"CM" {
                        result.commissioning_mode = parse_u8(v);
                    } else if k == b"VP" {
                        result.vendor_product = parse_vp(v);
                    }
                }
                break;
            }
        }

        // 4. ホストの A/AAAA を集約する。
        if let Some(tgt) = target {
            collect_addrs(&resp, &tgt, &mut result.addrs);
        }

        Some(result)
    }

    /// operational 解決レスポンスから (アドレス, ポート) を抽出する。
    ///
    /// `compressed_fabric_id`(big-endian 8 バイト)と `node_id` からインスタンス名を組み立て、
    /// 一致する SRV → ホストの A/AAAA を辿る。一致しない、またはアドレスが無ければ `None`。
    pub fn parse_operational(
        pkt: &[u8],
        compressed_fabric_id: &[u8; 8],
        node_id: u64,
    ) -> Option<DiscoveredNode> {
        let resp = Response::parse(pkt)?;
        let mut inst = [0u8; 33];
        operational_instance_label(compressed_fabric_id, node_id, &mut inst);

        let mut target: Option<Name> = None;
        let mut port = 0u16;
        for r in resp.records() {
            if r.rtype == T_SRV && r.name.eq_ci(&[&inst, b"_matter", b"_tcp", b"local"]) {
                if let Some((_, _, p, tgt)) = r.srv() {
                    port = p;
                    target = Some(tgt);
                    break;
                }
            }
        }
        let target = target?;

        let mut addrs = FixedVec::new();
        collect_addrs(&resp, &target, &mut addrs);
        if addrs.is_empty() {
            return None;
        }
        Some(DiscoveredNode { addrs, port })
    }

    /// operational SRV 応答から SRV target ホスト名(先頭ラベル)とポートだけを抽出する。
    ///
    /// mDNS 実装によっては SRV 応答の additional に A/AAAA を同梱しない
    /// (OTBR の native mDNS publisher で実測)。その場合は本関数で target を取り、
    /// [`build_resolve_host_aaaa`](MdnsClient::build_resolve_host_aaaa) の追加クエリで
    /// アドレスを解決する(2 段解決)。
    ///
    /// `host_out` に target の先頭ラベル(`<host>.local` の `<host>`)をコピーし、
    /// `Some((ラベル長, port))` を返す。
    pub fn parse_operational_srv(
        pkt: &[u8],
        compressed_fabric_id: &[u8; 8],
        node_id: u64,
        host_out: &mut [u8; 63],
    ) -> Option<(usize, u16)> {
        let resp = Response::parse(pkt)?;
        let mut inst = [0u8; 33];
        operational_instance_label(compressed_fabric_id, node_id, &mut inst);
        for r in resp.records() {
            if r.rtype == T_SRV && r.name.eq_ci(&[&inst, b"_matter", b"_tcp", b"local"]) {
                if let Some((_, _, port, tgt)) = r.srv() {
                    // `<host>.local` 形(2 ラベル)のみ対応(自レスポンダ / OTBR 双方この形)。
                    if tgt.len() != 2 {
                        return None;
                    }
                    let label = tgt.label(0);
                    if label.is_empty() || label.len() > host_out.len() {
                        return None;
                    }
                    host_out[..label.len()].copy_from_slice(label);
                    return Some((label.len(), port));
                }
            }
        }
        None
    }

    /// ホスト名 `<host>.local` の AAAA クエリを `out` に生成する(2 段解決の後段)。
    pub fn build_resolve_host_aaaa(
        out: &mut [u8],
        host_label: &[u8],
        unicast_response: bool,
    ) -> Result<usize> {
        let mut w = QueryWriter::new(out)?;
        w.question(&[host_label, b"local"], T_AAAA, unicast_response)?;
        Ok(w.finish())
    }

    /// `<host>.local` の A/AAAA 応答からアドレスを抽出する(2 段解決の後段)。
    pub fn parse_host_addrs(pkt: &[u8], host_label: &[u8]) -> FixedVec<IpAddr, MAX_ADDRS> {
        let mut addrs = FixedVec::new();
        let Some(resp) = Response::parse(pkt) else {
            return addrs;
        };
        for r in resp.records() {
            if r.rtype != T_A && r.rtype != T_AAAA {
                continue;
            }
            if !r.name.eq_ci(&[host_label, b"local"]) {
                continue;
            }
            if let Some(a) = r.a() {
                let _ = addrs.push(IpAddr::V4(Ipv4Addr::from(a)));
            } else if let Some(a) = r.aaaa() {
                let _ = addrs.push(IpAddr::V6(Ipv6Addr::from(a)));
            }
        }
        addrs
    }
}

/// [`CommissionableSet::ingest`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingest {
    /// 新規インスタンスを登録した。
    Added,
    /// 既知インスタンスの重複(無視した)。
    Duplicate,
    /// commissionable として解析できなかった(無関係パケット等)。
    Ignored,
    /// フィルタ(discriminator)に一致しなかった。
    Filtered,
    /// 結果テーブルが満杯で登録できなかった。
    Full,
}

/// 発見した commissionable ノードを集約する固定容量 `N` の結果テーブル(§5.1)。
///
/// 同一インスタンス名の重複は無視する。ヒープ確保・panic を伴わない。
pub struct CommissionableSet<const N: usize> {
    entries: FixedVec<DiscoveredCommissionable, N>,
}

impl<const N: usize> CommissionableSet<N> {
    /// 空の結果テーブルを生成する。
    pub const fn new() -> Self {
        Self {
            entries: FixedVec::new(),
        }
    }

    /// 登録件数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 空なら `true`。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 満杯なら `true`。
    pub fn is_full(&self) -> bool {
        self.entries.is_full()
    }

    /// 全消去する。
    pub fn clear(&mut self) {
        self.entries = FixedVec::new();
    }

    /// 登録済みノードを走査する。
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveredCommissionable> {
        self.entries.iter()
    }

    /// パケットを解析し、新規 commissionable インスタンスを登録する。
    pub fn ingest(&mut self, pkt: &[u8]) -> Ingest {
        match MdnsClient::parse_commissionable(pkt) {
            Some(d) => self.insert(d),
            None => Ingest::Ignored,
        }
    }

    /// パケットを解析し、`discriminator` に一致するもののみ登録する。
    pub fn ingest_filtered(&mut self, pkt: &[u8], discriminator: u16) -> Ingest {
        match MdnsClient::parse_commissionable(pkt) {
            Some(d) => {
                if d.discriminator != Some(discriminator) {
                    Ingest::Filtered
                } else {
                    self.insert(d)
                }
            }
            None => Ingest::Ignored,
        }
    }

    fn insert(&mut self, d: DiscoveredCommissionable) -> Ingest {
        for e in self.entries.iter() {
            if e.instance() == d.instance() {
                return Ingest::Duplicate;
            }
        }
        if self.entries.is_full() {
            return Ingest::Full;
        }
        let _ = self.entries.push(d);
        Ingest::Added
    }
}

impl<const N: usize> Default for CommissionableSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================================================
// 内部ヘルパ(ヒープ非依存・panic 非依存)
// ==========================================================================

/// レスポンス内で `owner` をオーナ名に持つ A/AAAA を `addrs` に追加する(容量超過分は無視)。
fn collect_addrs(resp: &Response<'_>, owner: &Name, addrs: &mut FixedVec<IpAddr, MAX_ADDRS>) {
    for r in resp.records() {
        if r.rtype != T_A && r.rtype != T_AAAA {
            continue;
        }
        if !name_eq(&r.name, owner) {
            continue;
        }
        if let Some(a) = r.a() {
            let _ = addrs.push(IpAddr::V4(Ipv4Addr::from(a)));
        } else if let Some(a) = r.aaaa() {
            let _ = addrs.push(IpAddr::V6(Ipv6Addr::from(a)));
        }
    }
}

/// 2 つの [`Name`] をラベル単位で ASCII 大文字小文字を無視して比較する。
fn name_eq(a: &Name, b: &Name) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if !a.label(i).eq_ignore_ascii_case(b.label(i)) {
            return false;
        }
    }
    true
}

/// [`Name`] を dotted 表記で `out` に書き、書き込んだ長さを返す(容量超過は切り詰め)。
fn name_to_dotted(n: &Name, out: &mut [u8]) -> usize {
    let mut len = 0;
    for i in 0..n.len() {
        if i > 0 {
            if len >= out.len() {
                break;
            }
            out[len] = b'.';
            len += 1;
        }
        let lab = n.label(i);
        let take = lab.len().min(out.len().saturating_sub(len));
        out[len..len + take].copy_from_slice(&lab[..take]);
        len += take;
        if take < lab.len() {
            break;
        }
    }
    len
}

/// operational インスタンスの先頭ラベル `<fab16hex>-<node16hex>`(33 バイト)を書く。
fn operational_instance_label(compressed_fabric_id: &[u8; 8], node_id: u64, out: &mut [u8; 33]) {
    let fab = u64::from_be_bytes(*compressed_fabric_id);
    hex16_upper(fab, &mut out[..16]);
    out[16] = b'-';
    hex16_upper(node_id, &mut out[17..33]);
}

/// `_L<decimal>` サブタイプラベルを `out` に書き、長さを返す。
fn fmt_subtype_l(discriminator: u16, out: &mut [u8]) -> usize {
    out[0] = b'_';
    out[1] = b'L';
    2 + fmt_dec(discriminator as u64, &mut out[2..])
}

/// `v` を 16 桁の大文字 hex(ゼロ埋め)で `out` の先頭 16 バイトに書く。
fn hex16_upper(v: u64, out: &mut [u8]) {
    for (i, slot) in out.iter_mut().enumerate().take(16) {
        let shift = (15 - i) * 4;
        *slot = hex_digit((v >> shift) as u8 & 0x0F);
    }
}

/// 4 ビット値を大文字 hex 数字にする。
fn hex_digit(nibble: u8) -> u8 {
    match nibble & 0x0F {
        d @ 0..=9 => b'0' + d,
        d => b'A' + (d - 10),
    }
}

/// `v` を 10 進で `out` に書き、桁数を返す。
fn fmt_dec(v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        if !out.is_empty() {
            out[0] = b'0';
        }
        return 1;
    }
    let mut tmp = v;
    let mut digits = 0;
    while tmp > 0 {
        digits += 1;
        tmp /= 10;
    }
    let digits = digits.min(out.len());
    let mut tmp = v;
    for i in (0..digits).rev() {
        out[i] = b'0' + (tmp % 10) as u8;
        tmp /= 10;
    }
    digits
}

/// 10 進バイト列を `u64` に解釈する(非数字・空・オーバフローは `None`)。
fn parse_dec_u64(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

fn parse_u16(v: &[u8]) -> Option<u16> {
    u16::try_from(parse_dec_u64(v)?).ok()
}

fn parse_u8(v: &[u8]) -> Option<u8> {
    u8::try_from(parse_dec_u64(v)?).ok()
}

/// TXT `VP` の値 `<vid>+<pid>`(10 進)を解釈する。
fn parse_vp(v: &[u8]) -> Option<(u16, u16)> {
    let pos = v.iter().position(|&b| b == b'+')?;
    let vid = parse_u16(&v[..pos])?;
    let pid = parse_u16(&v[pos + 1..])?;
    Some((vid, pid))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
