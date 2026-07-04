//! Matter デバイスの DNS-SD / mDNS ディスカバリ広告(`docs/ARCHITECTURE.md` の
//! `discovery` 層、ロードマップ第6段階)。
//!
//! commissionable(`_matterc._udp.local`)/ operational(`_matter._tcp.local`)の
//! 2 種の広告を、実コミッショナ(chip-tool 等)が発見できる形で生成する。
//!
//! # 依存判断(自前実装の根拠)
//!
//! 既存 no_std mDNS crate の採用可否を評価した結論として、本モジュールは**自前の
//! 最小 mDNS レスポンダ**を実装する(rs-matter builtin と同方式)。
//!
//! - `edge-mdns` / rs-matter builtin はいずれも内部で `domain` crate に依存する。
//!   `domain` は機能豊富だが依存ツリーが大きく、本プロジェクトの「最小フットプリント・
//!   最小依存」方針(`docs/ARCHITECTURE.md`)に反する。
//! - `edge-mdns` の API は「自前ソケットで駆動する async ランナ」を前提としており、
//!   本スタックの sans-IO 設計(バイト列と時刻だけを受け渡す純関数的 API)と噛み合わない。
//! - Matter が必要とする DNS レコードは `A`/`AAAA`/`PTR`/`SRV`/`TXT` の 5 種のみで、
//!   送信時に圧縮ポインタを省略すればエンコーダは数百行で収まる([`dns`] 参照)。
//!   受信クエリ解析は圧縮ポインタ追跡のみ対応すればよい。
//!
//! よって依存追加は行わず、[`dns`] に最小 DNS ワイヤ層を、本モジュールに Matter 固有の
//! レコード構成を実装する。
//!
//! # sans-IO 駆動 API
//!
//! スタック本体([`crate::stack`])と同じ純関数的パターンを採る。ソケットには触れない。
//!
//! - [`MdnsResponder::handle_query`] — 受信 mDNS クエリを解析し、自分のサービスに
//!   関係する質問があれば応答バイト列を生成する。
//! - [`MdnsResponder::poll_announce`] — `now_ms` を見て、起動時バースト / 定期の
//!   unsolicited announce を送出すべきタイミングで応答バイト列を生成する。
//! - [`MdnsResponder::next_announce_deadline`] — 次に [`poll_announce`] すべき時刻。
//!
//! マルチキャスト送受信(224.0.0.251 / ff02::fb の :5353)は呼び出し側の責務
//! ([`crate::transport::net::UdpMulticast`] / OS ソケット)。
//!
//! # fabric 追加/削除フック
//!
//! コミッショニング完了で fabric が増えたら [`MdnsResponder::set_operational`] で
//! operational 広告を登録し、[`MdnsResponder::notify_change`] で再 announce を促す。
//! commissionable 窓の開閉は [`MdnsResponder::set_commissionable`] で切り替える。

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::transport::session::fixed::FixedVec;

pub mod dns;

/// discovery クライアント(commissionable browse / operational 解決)。
///
/// `controller` feature 有効時のみコンパイルされる(`docs/design/controller.md` §5)。
/// sans-IO(クエリバイト列の生成とレスポンスの解析・集約のみ)で、ソケット・リトライ・
/// タイムアウトは呼び出し側の責務。
#[cfg(feature = "controller")]
pub mod client;

use dns::{Query, Section, CACHE_FLUSH, C_IN, T_A, T_AAAA, T_ANY, T_PTR};

/// mDNS の UDP ポート(RFC 6762)。
pub const MDNS_PORT: u16 = 5353;
/// mDNS の IPv4 マルチキャストアドレス(224.0.0.251)。
pub const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS の IPv6 マルチキャストアドレス(ff02::fb)。
pub const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// Matter の既定 UDP 運用ポート。
pub const MATTER_PORT: u16 = 5540;

/// レコードの既定 TTL(秒)。Matter 推奨のホスト/サービス TTL。
const TTL: u32 = 120;

/// commissionable のインスタンス名 hex 桁数(64 ビット)。
const COMMISSIONABLE_ID_HEX: usize = 16;

/// コミッショニングモード(TXT `CM` キー / `_CM` サブタイプ)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissioningMode {
    /// 未オープン(commissionable 広告を出さない)。
    Disabled,
    /// 標準コミッショニング窓(パスコード焼き込み、`CM=1`)。
    Standard,
    /// 強化コミッショニング窓(検証子を動的付与、`CM=2`)。
    Enhanced,
}

impl CommissioningMode {
    /// TXT `CM` の値(`"1"` / `"2"`)。`Disabled` は `None`。
    fn cm_value(self) -> Option<&'static [u8]> {
        match self {
            CommissioningMode::Disabled => None,
            CommissioningMode::Standard => Some(b"1"),
            CommissioningMode::Enhanced => Some(b"2"),
        }
    }
}

/// commissionable 広告(`_matterc._udp`)の材料。
#[derive(Debug, Clone, Copy)]
pub struct Commissionable {
    /// インスタンス名に使う 64 ビット識別子(ランダム / MAC 由来)。16 桁 hex になる。
    pub instance_id: u64,
    /// 12 ビット discriminator(TXT `D`、サブタイプ `_L`/`_S`)。
    pub discriminator: u16,
    /// Vendor ID(TXT `VP` の前半、サブタイプ `_V`)。
    pub vendor_id: u16,
    /// Product ID(TXT `VP` の後半)。
    pub product_id: u16,
    /// Device Type(TXT `DT`、サブタイプ `_T`)。
    pub device_type: Option<u32>,
    /// Device Name(TXT `DN`)。
    pub device_name: Option<&'static str>,
    /// コミッショニングモード(TXT `CM`)。
    pub mode: CommissioningMode,
    /// Session Idle Interval ミリ秒(TXT `SII`)。
    pub sii: Option<u32>,
    /// Session Active Interval ミリ秒(TXT `SAI`)。
    pub sai: Option<u32>,
}

impl Commissionable {
    /// 最小構成(discriminator / VID / PID / モードのみ)を作る。
    pub const fn new(
        instance_id: u64,
        discriminator: u16,
        vendor_id: u16,
        product_id: u16,
        mode: CommissioningMode,
    ) -> Self {
        Self {
            instance_id,
            discriminator: discriminator & 0x0FFF,
            vendor_id,
            product_id,
            device_type: None,
            device_name: None,
            mode,
            sii: None,
            sai: None,
        }
    }

    /// short discriminator(12 ビット中の上位 4 ビット)。
    fn short_discriminator(&self) -> u16 {
        (self.discriminator & 0x0F00) >> 8
    }
}

/// operational 広告(`_matter._tcp`)の材料。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operational {
    /// CompressedFabricId(64 ビット)。インスタンス名の前半・サブタイプ `_I`。
    pub compressed_fabric_id: u64,
    /// 自ノードの NodeId(64 ビット)。インスタンス名の後半。
    pub node_id: u64,
    /// Session Idle Interval ミリ秒(TXT `SII`)。
    pub sii: Option<u32>,
    /// Session Active Interval ミリ秒(TXT `SAI`)。
    pub sai: Option<u32>,
}

impl Operational {
    /// 識別子のみの最小構成を作る。
    pub const fn new(compressed_fabric_id: u64, node_id: u64) -> Self {
        Self {
            compressed_fabric_id,
            node_id,
            sii: None,
            sai: None,
        }
    }
}

/// ホスト情報(A/AAAA レコードとホスト名)。
///
/// ホスト名は Matter 仕様に従い MAC(48 ビット)/ EUI-64 の大文字 hex(12 or 16 桁)。
#[derive(Debug, Clone, Copy)]
pub struct Host {
    hostname: [u8; 16],
    hostname_len: usize,
    ipv6: Option<Ipv6Addr>,
    ipv4: Option<Ipv4Addr>,
}

impl Host {
    /// MAC / EUI-64 バイト列(6 or 8 バイト)からホストを作る。
    ///
    /// バイト列を大文字 hex 化してホスト名にする。6/8 バイト以外は先頭を切り詰めるか
    /// 0 埋めして最大 16 桁に収める(panic しない)。
    pub fn from_mac(mac: &[u8], ipv6: Option<Ipv6Addr>, ipv4: Option<Ipv4Addr>) -> Self {
        let mut hostname = [0u8; 16];
        let mut len = 0;
        for &b in mac.iter().take(8) {
            hostname[len] = hex_digit(b >> 4);
            hostname[len + 1] = hex_digit(b & 0x0F);
            len += 2;
        }
        if len == 0 {
            // 空 MAC を弾く: ダミーの "0" ラベルにする。
            hostname[0] = b'0';
            len = 1;
        }
        Self {
            hostname,
            hostname_len: len,
            ipv6,
            ipv4,
        }
    }

    /// ホスト名バイト列(hex ラベル)。
    fn hostname(&self) -> &[u8] {
        &self.hostname[..self.hostname_len]
    }
}

/// 固定容量 `NOPS` の sans-IO mDNS レスポンダ。
///
/// commissionable を 1 件(オプション)、operational を最大 `NOPS` 件広告する。
pub struct MdnsResponder<const NOPS: usize> {
    host: Host,
    port: u16,
    commissionable: Option<Commissionable>,
    operational: FixedVec<Operational, NOPS>,
    next_announce_ms: u64,
    announces_left: u8,
}

/// 起動時 announce バーストの回数(RFC 6762 §8.3 の複数回送出)。
const ANNOUNCE_BURST: u8 = 3;
/// バースト中の announce 間隔(ミリ秒)。
const ANNOUNCE_BURST_INTERVAL_MS: u64 = 1000;
/// 定常状態の再 announce 間隔(ミリ秒)。
const REANNOUNCE_INTERVAL_MS: u64 = 30_000;

impl<const NOPS: usize> MdnsResponder<NOPS> {
    /// ホストと Matter 運用ポートを与えてレスポンダを作る。
    ///
    /// 起動直後(`now_ms=0`)から announce バーストを始める。
    pub fn new(host: Host, port: u16) -> Self {
        Self {
            host,
            port,
            commissionable: None,
            operational: FixedVec::new(),
            next_announce_ms: 0,
            announces_left: ANNOUNCE_BURST,
        }
    }

    /// commissionable 広告を設定する(`None` で停止)。再 announce は行わない
    /// (必要なら [`notify_change`](Self::notify_change) を呼ぶ)。
    pub fn set_commissionable(&mut self, c: Option<Commissionable>) {
        self.commissionable = c;
    }

    /// 現在の commissionable 広告。
    pub fn commissionable(&self) -> Option<&Commissionable> {
        self.commissionable.as_ref()
    }

    /// operational 広告を 1 件追加する。満杯なら `Err` として値を返す。
    pub fn add_operational(&mut self, op: Operational) -> Result<(), Operational> {
        // 同一 (fabric, node) の重複は無視する。
        if self
            .operational
            .iter()
            .any(|e| e.compressed_fabric_id == op.compressed_fabric_id && e.node_id == op.node_id)
        {
            return Ok(());
        }
        self.operational.push(op)
    }

    /// operational 広告を全消去する。
    pub fn clear_operational(&mut self) {
        self.operational = FixedVec::new();
    }

    /// operational 広告の件数。
    pub fn operational_len(&self) -> usize {
        self.operational.len()
    }

    /// operational 広告をイテレータから一括設定する(既存を置き換える)。
    ///
    /// fabric テーブルの走査結果を渡す用途。容量超過分は無視する。
    pub fn set_operational(&mut self, ops: impl IntoIterator<Item = Operational>) {
        self.operational = FixedVec::new();
        for op in ops {
            if self.add_operational(op).is_err() {
                break;
            }
        }
    }

    /// 広告内容の変更を通知し、次回 [`poll_announce`](Self::poll_announce) で
    /// 起動時と同じ announce バーストを直ちに始める。
    pub fn notify_change(&mut self, now_ms: u64) {
        self.next_announce_ms = now_ms;
        self.announces_left = ANNOUNCE_BURST;
    }

    /// 次に [`poll_announce`](Self::poll_announce) すべき絶対時刻(ミリ秒)。
    pub fn next_announce_deadline(&self) -> u64 {
        self.next_announce_ms
    }

    /// announce 送出タイミングなら unsolicited 応答を `out` に生成して長さを返す。
    ///
    /// まだ時刻でない場合や広告するサービスが無い場合は `None`。呼び出し側は返った
    /// バイト列を mDNS マルチキャストへ送る。スケジューラは内部で前進する。
    pub fn poll_announce(&mut self, now_ms: u64, out: &mut [u8]) -> Option<usize> {
        if now_ms < self.next_announce_ms {
            return None;
        }
        let result = self.write_announce(out);
        if self.announces_left > 0 {
            self.announces_left -= 1;
        }
        self.next_announce_ms = now_ms
            + if self.announces_left > 0 {
                ANNOUNCE_BURST_INTERVAL_MS
            } else {
                REANNOUNCE_INTERVAL_MS
            };
        result
    }

    /// 全サービスの unsolicited announce(全レコードを回答セクションに)を生成する。
    ///
    /// 広告すべきサービスが無い、またはバッファ不足なら `None`。
    pub fn write_announce(&self, out: &mut [u8]) -> Option<usize> {
        if self.commissionable.is_none() && self.operational.is_empty() {
            return None;
        }
        let mut w = dns::MsgWriter::new(out).ok()?;
        let sec = Section::Answer;

        if let Some(c) = &self.commissionable {
            self.write_commissionable_records(&mut w, c, sec, true)
                .ok()?;
        }
        let mut host_written = self.commissionable.is_some();
        for op in self.operational.iter() {
            self.write_operational_records(&mut w, op, sec, true).ok()?;
            host_written = true;
        }
        if host_written {
            self.write_host_records(&mut w, sec).ok()?;
        }

        let len = w.finish();
        if len == 0 {
            None
        } else {
            Some(len)
        }
    }

    /// 受信 mDNS クエリを解析し、自サービスに関係する質問があれば応答を生成する。
    ///
    /// 応答すべき質問が 1 件も無い、または不正入力なら `None`(panic しない)。
    /// 応答は「マッチしたサービスの完全なレコード集合」を返す(PTR を回答、
    /// SRV/TXT/A/AAAA を追加情報に)。実コミッショナはこの形を受理できる。
    pub fn handle_query(&self, packet: &[u8], out: &mut [u8]) -> Option<usize> {
        let query = Query::parse(packet)?;

        // どのサービスに応答するかをまず判定する(回答→追加情報の 2 パスのため)。
        let mut emit_comm = false;
        let mut op_mask = [false; NOPS];
        let mut emit_host_only = false;

        for q in query.questions() {
            self.match_question(&q, &mut emit_comm, &mut op_mask, &mut emit_host_only);
        }

        if !emit_comm && !op_mask.iter().any(|b| *b) && !emit_host_only {
            return None;
        }

        let mut w = dns::MsgWriter::new(out).ok()?;

        // --- 回答セクション: PTR 群 ---
        if emit_comm {
            if let Some(c) = &self.commissionable {
                let _ = self.write_commissionable_ptrs(&mut w, c, Section::Answer);
            }
        }
        let mut dnssd_op_ptr = false;
        for (i, op) in self.operational.iter().enumerate() {
            if op_mask.get(i).copied().unwrap_or(false) {
                let _ = self.write_operational_ptrs(&mut w, op, Section::Answer, &mut dnssd_op_ptr);
            }
        }

        // --- 追加情報セクション: SRV / TXT / A / AAAA ---
        let mut any = emit_comm || emit_host_only;
        if emit_comm {
            if let Some(c) = &self.commissionable {
                let _ = self.write_commissionable_srv_txt(&mut w, c, Section::Additional);
            }
        }
        for (i, op) in self.operational.iter().enumerate() {
            if op_mask.get(i).copied().unwrap_or(false) {
                let _ = self.write_operational_srv_txt(&mut w, op, Section::Additional);
                any = true;
            }
        }
        if any {
            let _ = self.write_host_records(&mut w, Section::Additional);
        }

        let len = w.finish();
        if len == 0 {
            None
        } else {
            Some(len)
        }
    }

    /// 質問 1 件を自サービスと突き合わせ、応答すべきものにフラグを立てる。
    fn match_question(
        &self,
        q: &dns::Question,
        emit_comm: &mut bool,
        op_mask: &mut [bool; NOPS],
        emit_host_only: &mut bool,
    ) {
        let name = &q.name;
        let t = q.qtype;
        let want_ptr = t == T_PTR || t == T_ANY;

        // _services._dns-sd._udp.local (meta-query)
        if want_ptr && name.eq_ci(&[b"_services", b"_dns-sd", b"_udp", b"local"]) {
            if self.commissionable.is_some() {
                *emit_comm = true;
            }
            for m in op_mask.iter_mut() {
                *m = true;
            }
            return;
        }

        // --- commissionable ---
        if let Some(c) = &self.commissionable {
            let mut id_hex = [0u8; COMMISSIONABLE_ID_HEX];
            hex_u64_16(c.instance_id, &mut id_hex);

            // サービス型 PTR
            if want_ptr && name.eq_ci(&[b"_matterc", b"_udp", b"local"]) {
                *emit_comm = true;
            }
            // インスタンス(SRV/TXT/ANY/A/AAAA)
            if name.eq_ci(&[&id_hex, b"_matterc", b"_udp", b"local"]) {
                *emit_comm = true;
            }
            // サブタイプ PTR
            if want_ptr && self.commissionable_subtype_matches(c, name) {
                *emit_comm = true;
            }
        }

        // --- operational ---
        // サービス型 PTR は全 operational にマッチ。
        if want_ptr && name.eq_ci(&[b"_matter", b"_tcp", b"local"]) {
            for m in op_mask.iter_mut() {
                *m = true;
            }
        }
        for (i, op) in self.operational.iter().enumerate() {
            let mut inst = [0u8; 33];
            let inst_len = operational_instance(op, &mut inst);
            let inst_label = &inst[..inst_len];
            // インスタンス(SRV/TXT/ANY)
            if name.eq_ci(&[inst_label, b"_matter", b"_tcp", b"local"]) {
                if let Some(m) = op_mask.get_mut(i) {
                    *m = true;
                }
            }
            // operational サブタイプ _I<fab>
            if want_ptr {
                let mut sub = [0u8; 18];
                let sub_len = subtype_hex(b"_I", op.compressed_fabric_id, &mut sub);
                if name.eq_ci(&[&sub[..sub_len], b"_sub", b"_matter", b"_tcp", b"local"]) {
                    if let Some(m) = op_mask.get_mut(i) {
                        *m = true;
                    }
                }
            }
        }

        // --- host A/AAAA ---
        if (t == T_A || t == T_AAAA || t == T_ANY) && name.eq_ci(&[self.host.hostname(), b"local"])
        {
            *emit_host_only = true;
        }
    }

    /// commissionable のサブタイプ(`_L`/`_S`/`_V`/`_T`/`_CM`)にマッチするか。
    fn commissionable_subtype_matches(&self, c: &Commissionable, name: &dns::Name) -> bool {
        // name = [<sub>, _sub, _matterc, _udp, local]
        if name.len() != 5
            || !name.label(1).eq_ignore_ascii_case(b"_sub")
            || !name.label(2).eq_ignore_ascii_case(b"_matterc")
            || !name.label(3).eq_ignore_ascii_case(b"_udp")
            || !name.label(4).eq_ignore_ascii_case(b"local")
        {
            return false;
        }
        let sub = name.label(0);
        let mut buf = [0u8; 16];

        let l = subtype_dec(b"_L", c.discriminator as u64, &mut buf);
        if sub.eq_ignore_ascii_case(&buf[..l]) {
            return true;
        }
        let l = subtype_dec(b"_S", c.short_discriminator() as u64, &mut buf);
        if sub.eq_ignore_ascii_case(&buf[..l]) {
            return true;
        }
        let l = subtype_dec(b"_V", c.vendor_id as u64, &mut buf);
        if sub.eq_ignore_ascii_case(&buf[..l]) {
            return true;
        }
        if let Some(dt) = c.device_type {
            let l = subtype_dec(b"_T", dt as u64, &mut buf);
            if sub.eq_ignore_ascii_case(&buf[..l]) {
                return true;
            }
        }
        if sub.eq_ignore_ascii_case(b"_CM") {
            return true;
        }
        false
    }

    // -- レコード生成ヘルパ --

    fn write_commissionable_records(
        &self,
        w: &mut dns::MsgWriter,
        c: &Commissionable,
        sec: Section,
        _all: bool,
    ) -> crate::error::Result<()> {
        self.write_commissionable_ptrs(w, c, sec)?;
        self.write_commissionable_srv_txt(w, c, sec)?;
        Ok(())
    }

    fn write_commissionable_ptrs(
        &self,
        w: &mut dns::MsgWriter,
        c: &Commissionable,
        sec: Section,
    ) -> crate::error::Result<()> {
        let mut id_hex = [0u8; COMMISSIONABLE_ID_HEX];
        hex_u64_16(c.instance_id, &mut id_hex);
        let instance: [&[u8]; 4] = [&id_hex, b"_matterc", b"_udp", b"local"];

        // _services._dns-sd._udp.local -> _matterc._udp.local
        w.rr_ptr(
            sec,
            &[b"_services", b"_dns-sd", b"_udp", b"local"],
            C_IN,
            TTL,
            &[b"_matterc", b"_udp", b"local"],
        )?;
        // _matterc._udp.local -> instance
        w.rr_ptr(sec, &[b"_matterc", b"_udp", b"local"], C_IN, TTL, &instance)?;

        // サブタイプ PTR: _<sub>._sub._matterc._udp.local -> instance
        let mut buf = [0u8; 16];
        let l = subtype_dec(b"_L", c.discriminator as u64, &mut buf);
        w.rr_ptr(
            sec,
            &[&buf[..l], b"_sub", b"_matterc", b"_udp", b"local"],
            C_IN,
            TTL,
            &instance,
        )?;
        let mut buf_s = [0u8; 16];
        let l = subtype_dec(b"_S", c.short_discriminator() as u64, &mut buf_s);
        w.rr_ptr(
            sec,
            &[&buf_s[..l], b"_sub", b"_matterc", b"_udp", b"local"],
            C_IN,
            TTL,
            &instance,
        )?;
        let mut buf_v = [0u8; 16];
        let l = subtype_dec(b"_V", c.vendor_id as u64, &mut buf_v);
        w.rr_ptr(
            sec,
            &[&buf_v[..l], b"_sub", b"_matterc", b"_udp", b"local"],
            C_IN,
            TTL,
            &instance,
        )?;
        if let Some(dt) = c.device_type {
            let mut buf_t = [0u8; 16];
            let l = subtype_dec(b"_T", dt as u64, &mut buf_t);
            w.rr_ptr(
                sec,
                &[&buf_t[..l], b"_sub", b"_matterc", b"_udp", b"local"],
                C_IN,
                TTL,
                &instance,
            )?;
        }
        w.rr_ptr(
            sec,
            &[b"_CM", b"_sub", b"_matterc", b"_udp", b"local"],
            C_IN,
            TTL,
            &instance,
        )?;
        Ok(())
    }

    fn write_commissionable_srv_txt(
        &self,
        w: &mut dns::MsgWriter,
        c: &Commissionable,
        sec: Section,
    ) -> crate::error::Result<()> {
        let mut id_hex = [0u8; COMMISSIONABLE_ID_HEX];
        hex_u64_16(c.instance_id, &mut id_hex);
        let instance: [&[u8]; 4] = [&id_hex, b"_matterc", b"_udp", b"local"];

        // SRV instance -> host:port
        w.rr_srv(
            sec,
            &instance,
            C_IN | CACHE_FLUSH,
            TTL,
            0,
            0,
            self.port,
            &[self.host.hostname(), b"local"],
        )?;

        // TXT
        let mut d_buf = [0u8; 8];
        let d_len = dec_u64(c.discriminator as u64, &mut d_buf);
        let mut vp_buf = [0u8; 16];
        let vp_len = vid_pid(c.vendor_id, c.product_id, &mut vp_buf);
        let mut dt_buf = [0u8; 12];
        let mut sii_buf = [0u8; 12];
        let mut sai_buf = [0u8; 12];

        let mut kvs: [(&[u8], &[u8]); 8] = [(b"", b""); 8];
        let mut n = 0;
        kvs[n] = (b"D", &d_buf[..d_len]);
        n += 1;
        if let Some(cm) = c.mode.cm_value() {
            kvs[n] = (b"CM", cm);
            n += 1;
        }
        kvs[n] = (b"VP", &vp_buf[..vp_len]);
        n += 1;
        if let Some(dt) = c.device_type {
            let l = dec_u64(dt as u64, &mut dt_buf);
            kvs[n] = (b"DT", &dt_buf[..l]);
            n += 1;
        }
        if let Some(dn) = c.device_name {
            kvs[n] = (b"DN", dn.as_bytes());
            n += 1;
        }
        if let Some(sii) = c.sii {
            let l = dec_u64(sii as u64, &mut sii_buf);
            kvs[n] = (b"SII", &sii_buf[..l]);
            n += 1;
        }
        if let Some(sai) = c.sai {
            let l = dec_u64(sai as u64, &mut sai_buf);
            kvs[n] = (b"SAI", &sai_buf[..l]);
            n += 1;
        }
        w.rr_txt(sec, &instance, C_IN | CACHE_FLUSH, TTL, &kvs[..n])?;
        Ok(())
    }

    fn write_operational_records(
        &self,
        w: &mut dns::MsgWriter,
        op: &Operational,
        sec: Section,
        _all: bool,
    ) -> crate::error::Result<()> {
        let mut dnssd = false;
        self.write_operational_ptrs(w, op, sec, &mut dnssd)?;
        self.write_operational_srv_txt(w, op, sec)?;
        Ok(())
    }

    fn write_operational_ptrs(
        &self,
        w: &mut dns::MsgWriter,
        op: &Operational,
        sec: Section,
        dnssd_written: &mut bool,
    ) -> crate::error::Result<()> {
        let mut inst = [0u8; 33];
        let inst_len = operational_instance(op, &mut inst);
        let instance: [&[u8]; 4] = [&inst[..inst_len], b"_matter", b"_tcp", b"local"];

        if !*dnssd_written {
            w.rr_ptr(
                sec,
                &[b"_services", b"_dns-sd", b"_udp", b"local"],
                C_IN,
                TTL,
                &[b"_matter", b"_tcp", b"local"],
            )?;
            *dnssd_written = true;
        }
        // _matter._tcp.local -> instance
        w.rr_ptr(sec, &[b"_matter", b"_tcp", b"local"], C_IN, TTL, &instance)?;
        // _I<fab>._sub._matter._tcp.local -> instance
        let mut sub = [0u8; 18];
        let sub_len = subtype_hex(b"_I", op.compressed_fabric_id, &mut sub);
        w.rr_ptr(
            sec,
            &[&sub[..sub_len], b"_sub", b"_matter", b"_tcp", b"local"],
            C_IN,
            TTL,
            &instance,
        )?;
        Ok(())
    }

    fn write_operational_srv_txt(
        &self,
        w: &mut dns::MsgWriter,
        op: &Operational,
        sec: Section,
    ) -> crate::error::Result<()> {
        let mut inst = [0u8; 33];
        let inst_len = operational_instance(op, &mut inst);
        let instance: [&[u8]; 4] = [&inst[..inst_len], b"_matter", b"_tcp", b"local"];

        w.rr_srv(
            sec,
            &instance,
            C_IN | CACHE_FLUSH,
            TTL,
            0,
            0,
            self.port,
            &[self.host.hostname(), b"local"],
        )?;

        let mut sii_buf = [0u8; 12];
        let mut sai_buf = [0u8; 12];
        let mut kvs: [(&[u8], &[u8]); 2] = [(b"", b""); 2];
        let mut n = 0;
        if let Some(sii) = op.sii {
            let l = dec_u64(sii as u64, &mut sii_buf);
            kvs[n] = (b"SII", &sii_buf[..l]);
            n += 1;
        }
        if let Some(sai) = op.sai {
            let l = dec_u64(sai as u64, &mut sai_buf);
            kvs[n] = (b"SAI", &sai_buf[..l]);
            n += 1;
        }
        w.rr_txt(sec, &instance, C_IN | CACHE_FLUSH, TTL, &kvs[..n])?;
        Ok(())
    }

    fn write_host_records(&self, w: &mut dns::MsgWriter, sec: Section) -> crate::error::Result<()> {
        let host: [&[u8]; 2] = [self.host.hostname(), b"local"];
        if let Some(ip) = self.host.ipv6 {
            w.rr_aaaa(sec, &host, C_IN | CACHE_FLUSH, TTL, ip.octets())?;
        }
        if let Some(ip) = self.host.ipv4 {
            w.rr_a(sec, &host, C_IN | CACHE_FLUSH, TTL, ip.octets())?;
        }
        Ok(())
    }
}

// ==========================================================================
// 数値 / hex フォーマット(ヒープ非依存)
// ==========================================================================

/// 4 ビット値を大文字 hex 数字にする。
fn hex_digit(nibble: u8) -> u8 {
    match nibble & 0x0F {
        d @ 0..=9 => b'0' + d,
        d => b'A' + (d - 10),
    }
}

/// `v` を 16 桁の大文字 hex(ゼロ埋め)で `out` に書く。
fn hex_u64_16(v: u64, out: &mut [u8; 16]) {
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = (15 - i) * 4;
        *slot = hex_digit((v >> shift) as u8 & 0x0F);
    }
}

/// operational インスタンス名 `<fab16hex>-<node16hex>` を書き、長さ(33)を返す。
fn operational_instance(op: &Operational, out: &mut [u8; 33]) -> usize {
    let mut fab = [0u8; 16];
    hex_u64_16(op.compressed_fabric_id, &mut fab);
    let mut node = [0u8; 16];
    hex_u64_16(op.node_id, &mut node);
    out[..16].copy_from_slice(&fab);
    out[16] = b'-';
    out[17..33].copy_from_slice(&node);
    33
}

/// `v` を 10 進で `out` に書き、桁数を返す。
fn dec_u64(v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    // まず桁数を数える。
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

/// `<prefix><decimal>` を書き、長さを返す(サブタイプラベル `_L1234` 等)。
fn subtype_dec(prefix: &[u8], v: u64, out: &mut [u8]) -> usize {
    let p = prefix.len().min(out.len());
    out[..p].copy_from_slice(&prefix[..p]);
    p + dec_u64(v, &mut out[p..])
}

/// `<prefix><16hex>` を書き、長さを返す(operational サブタイプ `_I<fab>`)。
fn subtype_hex(prefix: &[u8], v: u64, out: &mut [u8]) -> usize {
    let p = prefix.len().min(out.len());
    out[..p].copy_from_slice(&prefix[..p]);
    let mut hex = [0u8; 16];
    hex_u64_16(v, &mut hex);
    let end = (p + 16).min(out.len());
    out[p..end].copy_from_slice(&hex[..end - p]);
    end
}

/// TXT `VP` の値 `<vid>+<pid>`(10 進)を書き、長さを返す。
fn vid_pid(vid: u16, pid: u16, out: &mut [u8]) -> usize {
    let mut n = dec_u64(vid as u64, out);
    if n < out.len() {
        out[n] = b'+';
        n += 1;
    }
    n + dec_u64(pid as u64, &mut out[n..])
}

#[cfg(test)]
mod tests;
