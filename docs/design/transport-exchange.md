# transport 層 + exchange 層 設計(ロードマップ第2段階)

対象: `docs/ARCHITECTURE.md` の「レイヤ構成」における `transport` と `exchange` の2層。
Matter デバイス(responder)専用・`no_std`・定常パス no-alloc・executor 非依存 async を前提とする。

- 上位境界: `exchange` 層は平文ペイロード + `PayloadHeader` を `sc`/`im` に渡す(プロトコルハンドラ)。
- 下位境界: `transport` 層は暗号文 + `PacketHeader` を `Network`(UDP)trait に渡す。
- **暗号境界はこの2層の内部に1点だけ置く**(設計原則4)。

本書はシグネチャスケッチを含むが、コンパイル可能性より設計判断の明確化を優先する。
参照実装は `research/rs-matter/rs-matter/src/transport/`(以下 rs-matter と略)、
`research/connectedhomeip/src/{transport,messaging}/`(以下 chip)、matter.js の `packages/protocol`。

---

## 0. サマリ(主要な設計判断)

1. **Network は send/recv を分離した2つの最小 async trait**。`core::net::SocketAddr` を直接使い、
   拡張余地のため薄い `PeerAddr` enum を1枚だけ挟む。executor には一切依存しない。
2. **セッションは enum 判別**(typestate ではない)。固定容量テーブルに同型で格納するため。
   typestate はハンドシェイク駆動(`sc` 層)に限定して使う。
3. **暗号境界 = `SecureCodec` 1モジュール**。二段デコード(平文ヘッダ→セッション解決→復号)で
   「session_id が分かってから鍵が引ける」順序を型で表現し、暗号呼び出し箇所を物理的に1つにする。
4. **プロトコルディスパッチは enum mux**(dyn でも巨大タプルでもない)。デバイスが話すプロトコルは
   SecureChannel と InteractionModel の2つ(+将来 BDX)で閉じているため、閉じた enum が最適。
   これが rs-matter の「型名が書けない」問題の直接的回避策。
5. **exchange は session とは別の固定プール**にし、`ExchangeId` で参照する(chip 的な層分離)。
   MRP は `Exchange` に値として内包。ハンドル(`Exchange<'_>`)は id + スタック参照だけを持ち、
   `.await` をまたいでセッションテーブルを借用しない(rs-matter の所有権トリックを踏襲)。
6. **サイジングは少数の const generic + プロファイル型エイリアス**。rs-matter の約100 feature を
   4パラメータに集約し、アプリはエイリアス名だけを書く。

---

## 1. モジュール構成と依存関係

`crates/simple-matter/src/` 配下(実コードは別エージェントが実装。本書は設計のみ)。

```
transport/
  mod.rs        Transport: RX/TX オーケストレーション、バッファ所有、暗号境界の呼び出し点
  net.rs        UdpSend / UdpReceive / UdpMulticast trait, PeerAddr
  header.rs     PacketHeader(平文) / PayloadHeader(暗号内) の parse/encode, MsgFlags/ExchFlags
  counter.rs    LocalCounter(送信・単調), PeerWindow(受信リプレイ窓 = dedup)
  session.rs    Session, SessionMode, SessionId, SessionManager(固定容量テーブル)
  secure.rs     SecureCodec: 唯一の encrypt/decrypt 実行点(暗号境界)
exchange/
  mod.rs        ExchangeManager: exchange プール + プロトコルディスパッチ配線
  exchange.rs   Exchange<'a>(ハンドル), ExchangeState(格納状態), ExchangeId, Role
  mrp.rs        Mrp(再送 + ack), MrpConfig(SII/SAI/SAT), 指数バックオフ
  dispatch.rs   ProtocolHandler trait, ProtocolMux(enum ディスパッチ)
buf.rs          BufferPool<N, SIZE>, PacketLease(RAII), 固定プール
```

### 依存方向(下→上の一方向)

```
error, tlv                                 … 既存(全層が横断利用)
   ▲
crypto (CryptoProvider trait)              … 第1段階成果物。secure.rs のみが利用
   ▲
transport/{net, header, counter}           … 相互依存なし
   ▲
transport/session ── transport/secure      … secure は session の鍵を読む
   ▲
transport/mod (Transport)                  … buf.rs を所有
   ▲
exchange/{mrp, exchange, dispatch}
   ▲
exchange/mod (ExchangeManager)
   ▲
sc / im (ProtocolHandler を実装する上位層 = 次段階)
```

- `net`/`header`/`counter` は互いに独立し、単体テスト可能(std 上)。
- `secure.rs` だけが `crypto` に依存する。`crypto` 依存が1ファイルに閉じることが暗号境界の物理的担保。
- `exchange` は `transport` の型(`SessionId`, `PacketLease`, `PayloadHeader`)に依存するが、
  `transport` は `exchange` を知らない(chip の messaging→transport 一方向依存と同じ)。

**rs-matter との差**: rs-matter は `transport.rs`(2610行)に session/exchange/MRP/dedup/mDNS を
同居させ、exchange を session の中に入れ子(`Session.exchanges: Vec<Option<ExchangeState>, N>`)にして
「ExchangeManager」を実質存在させていない。本設計は ARCHITECTURE の層境界(transport=session /
exchange=会話)に従い、**exchange プールを session テーブルから分離**する(§5.2 で根拠)。

---

## 2. Network 抽象(UDP)

要件: no_std、smoltcp / OS ソケット / OpenThread 等を差し替え可能、async、executor 非依存。

### 2.1 trait 定義

送信と受信を別 trait に分ける。理由は (a) RX ループと TX/MRP タイマループを別タスクに置けるようにするため、
(b) 実装が片方向しか持たない構成(例: TX は共有、RX は割り込み駆動)を許すため。rs-matter も
`NetworkSend`/`NetworkReceive`/`NetworkMulticast` の3分割で、これは踏襲する。

```rust
// transport/net.rs

/// UDP(将来 BTP/TCP)の宛先。今は Udp のみだが、シグネチャを変えずに拡張できるよう enum で包む。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    Udp(core::net::SocketAddr),
    // 将来: Btp(BtAddr),  ← feature gate
}

/// 1 Matter パケットを宛先へ送る。パケット化は実装側の責務(UDP は自明)。
pub trait UdpSend {
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<(), Error>;
}

/// 1 Matter パケットを受信する。`buf` は呼び出し側(Transport)が用意する共有 RX バッファ。
pub trait UdpReceive {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr), Error>;
}

/// 運用ディスカバリ(mDNS)とグループキャストのための IPv6 マルチキャスト。初期スコープでは
/// discovery 層のみが使う。group messaging は feature gate。UDP 実装のみが提供すればよい。
pub trait UdpMulticast {
    async fn join(&mut self, group: core::net::Ipv6Addr) -> Result<(), Error>;
    async fn leave(&mut self, group: core::net::Ipv6Addr) -> Result<(), Error>;
}
```

### 2.2 設計判断

- **async fn in trait を直接使う**(AFIT、Rust 1.75 で安定)。rs-matter と同じ。`&mut T` への
  ブランケット実装も付ける(合成しやすさ)。
- **executor 非依存**: この trait 群は `core::future::Future` にしか依存しない。時間(MRP タイマ)は
  §6 の通り `embassy-time` を採用するが、Network trait 自体は時間に触れない。
- **`recv_from` はバッファを引数で受け取る**(戻り値で確保しない)。Transport が共有 RX バッファを
  貸し出す所有権モデル(§7)に合わせ、実装側にヒープ確保を強制しない。
- **`PeerAddr` を1枚挟む理由**: `SocketAddr` を全シグネチャに直接使うと BTP 追加時に全面改修になる。
  かといって rs-matter の `Address`(UDP/TCP/BTP を最初から3分岐)は UDP 専用の今は過剰。
  現状 variant 1個の enum なら分岐コストはほぼゼロで、将来の拡張点だけ確保できる。
- **IPv4-mapped IPv6 の正規化**: dual-stack ソケットが IPv4 peer を `::ffff:a.b.c.d` で報告する問題
  (rs-matter `Address::canonical`)は、セッション照合時のみ正規化する小関数を `net.rs` に置く。
  返信は peer に届いた生アドレスへ送るため、格納アドレスは正規化しない。

### 2.3 マルチネットワーク合成

rs-matter の `ChainedNetwork`(UDP/TCP/BTP を `select` で束ねる)は初期スコープでは不要。
UDP 単一実装を前提とし、合成が要る段階で `UdpSend`/`UdpReceive` を実装する薄いラッパを足す。
**過剰な汎用化(最初から chain 構造)は避ける**(ARCHITECTURE: 抽象多重化の回避)。

---

## 3. メッセージコーデック

Matter メッセージ = `[PacketHeader(平文)] [PayloadHeader(暗号内)] [payload] [MIC]`。
`PacketHeader` は非暗号(session_id / counter / node id)、`PayloadHeader` は暗号内
(protocol id / opcode / exchange id / ack)。

### 3.1 ヘッダ型

```rust
// transport/header.rs

bitflags! { pub struct MsgFlags: u8 {
    const SRC_PRESENT = 0x04; const DST_UNICAST = 0x01; const DST_GROUP = 0x02;
}}
bitflags! { pub struct SecFlags: u8 { const GROUP_SESSION = 0x01; /* P/C ... */ }}

/// 非暗号ヘッダ。ネットワークから最初に読める部分。
pub struct PacketHeader {
    pub session_id: u16,
    pub sec_flags: SecFlags,
    pub ctr: u32,               // メッセージカウンタ
    pub src_node_id: Option<u64>,
    pub dst: DstNodeId,         // None / Unicast(u64) / Group(u16)
}
impl PacketHeader {
    pub const MAX_LEN: usize = 2 + 1 + 1 + 2 + 4 + 8 + 8; // TCP長 + flags + sec + sid + ctr + src + dst
    pub fn decode(buf: &mut ParseBuf) -> Result<Self, Error>;
    pub fn encode(&self, out: &mut WriteBuf) -> Result<(), Error>;
    pub fn is_encrypted(&self) -> bool { self.session_id != 0 || self.sec_flags.group() }
}

bitflags! { pub struct ExchFlags: u8 {
    const INITIATOR = 0x01; const ACK = 0x02; const RELIABLE = 0x04;
    const SECEX = 0x08; const VENDOR = 0x10;
}}

/// 暗号内ヘッダ。復号後にのみ読める。
pub struct PayloadHeader {
    pub exch_flags: ExchFlags,
    pub proto_opcode: u8,
    pub exch_id: u16,
    pub proto_id: u16,
    pub vendor_id: Option<u16>,
    pub ack_ctr: Option<u32>,
}
impl PayloadHeader {
    pub const MAX_LEN: usize = 1 + 1 + 2 + 2 + 2 + 4;
    pub fn decode(buf: &mut ParseBuf) -> Result<Self, Error>;
    pub fn encode(&self, out: &mut WriteBuf) -> Result<(), Error>;
    pub fn is_initiator(&self) -> bool;  pub fn is_reliable(&self) -> bool;
    pub fn ack(&self) -> Option<u32>;
}
```

`tlv.rs` の `TlvReader`/`TlvWriter` はスキーマ付き TLV 用。ヘッダは固定レイアウトのため
`ParseBuf`/`WriteBuf`(バイト列に対する LE 読み書き + カーソル)という別の軽量ユーティリティを
`buf.rs` か新設 `util` に置く(rs-matter `utils::storage::{ParseBuf, WriteBuf}` 相当)。

### 3.2 メッセージカウンタ

- **送信(local)**: セッションごとに単調増加する `u32`。Matter 仕様の28ビット範囲でなく **32ビット全域を
  使う**(仕様は counter を 32bit として扱い、`0x0fff_ffff` マスクは rs-matter が `ExchangeId` に
  session id を詰めるための都合。本設計は `ExchangeId` を別構成にする(§5.3)ため、counter を削る理由がない)。

  ```rust
  // transport/counter.rs
  pub struct LocalCounter(u32);
  impl LocalCounter {
      pub fn next(&mut self) -> u32 { let c = self.0; self.0 = self.0.wrapping_add(1); c }
  }
  ```
  非暗号(session_id=0)メッセージ用のグローバル送信カウンタも1本持つ。

- **受信(peer)リプレイ保護**: セッションごとにスライディング窓。rs-matter `RxCtrState`(`max_ctr` +
  `u16` ビットマップ)を採用。

  ```rust
  pub struct PeerWindow { max_ctr: u32, bitmap: u32 }  // 窓幅32
  impl PeerWindow {
      /// 新規なら true、重複/窓外なら false(= ドロップ)。
      /// encrypted=false のとき peer 再起動による後方大ジャンプを許容(unicast)。
      pub fn accept(&mut self, ctr: u32, encrypted: bool) -> bool;
  }
  ```
  窓幅は rs-matter の 16 でなく **32**(`u32` ビットマップ)にする。RAM 増は 2 バイト/セッションのみで、
  順序前後に強くなる。group 用のロールオーバー比較(modular)は group feature 有効時のみ別途。

### 3.3 暗号境界 = `SecureCodec`(唯一の暗号実行点)

暗号 AEAD(AES-CCM)の in-place 暗号化/復号は **ここだけ**で起こる。IV = `sec_flags(1) || ctr(4) ||
src_node_id(8)`、AAD = 平文 `PacketHeader` のバイト列。鍵はセッションから引く。

```rust
// transport/secure.rs
pub struct SecureCodec;
impl SecureCodec {
    /// RX: すでに PacketHeader をパース済みの ParseBuf を、セッション鍵で復号し PayloadHeader を返す。
    /// key=None(PlainText セッション)なら復号せずヘッダだけデコード。
    pub fn decrypt<C: CryptoProvider>(
        crypto: &C, key: Option<AeadKeyRef<'_>>,
        pkt: &PacketHeader, peer_node_id: u64, buf: &mut ParseBuf<'_>,
    ) -> Result<PayloadHeader, Error>;

    /// TX: payload を書き込み済みの WriteBuf に PayloadHeader を前置・暗号化し、PacketHeader を前置。
    pub fn encrypt<C: CryptoProvider>(
        crypto: &C, key: Option<AeadKeyRef<'_>>,
        pkt: &PacketHeader, payload: &PayloadHeader, local_node_id: u64, buf: &mut WriteBuf<'_>,
    ) -> Result<(), Error>;
}
```

**二段デコードで暗号境界を型で強制する**(chip の `SecureMessageCodec` + rs-matter の
`decode_plain_hdr` → `decode_remaining` の思想):

1. `PacketHeader::decode` で session_id を得る(復号不要)。
2. `SessionManager` で session を解決 → 鍵を取得。
3. `SecureCodec::decrypt` に鍵を渡して初めて `PayloadHeader` が得られる。

この順序により「セッション未解決のまま payload を読む」コードが書けない。`decrypt` の `key: Option` が
PlainText 経路(PASE/CASE 第1メッセージ)を表現し、分岐を1箇所に閉じる。

- **crypto は capability として渡す(フィールドに持たない)**。rs-matter と同じく `&C: CryptoProvider`
  を引数で受ける。`CryptoProvider` は GAT(`Aead<'a>`)を持つため `dyn` 化しづらく、ジェネリックが妥当。
  ただし `C` が波及するのは `secure.rs` と、それを呼ぶ `Transport` の RX/TX メソッドのみ(§9)。

---

## 4. SessionManager / Session

### 4.1 enum 判別 vs typestate — **enum を選ぶ**

セッション種別は Unauthenticated / Secure(PASE|CASE)。表現方法の選択:

| 案 | 長所 | 短所 |
|---|---|---|
| **typestate**(型で種別を区別) | 未確立セッションで鍵 API を呼べないことをコンパイル時保証 | 型が異なると**単一の固定容量配列に格納できない**(結局 enum へ消去が要る)。テーブル走査・LRU が書けない |
| **enum 判別**(1 struct + `mode` フィールド) | 同型で `[Session; N]` に格納、走査・退避・照合が素直 | 「PlainText で鍵取得」を実行時 `Option` で弾く(型では防げない) |

**判断: enum 判別**(rs-matter・chip と同じ)。理由は決定的で、**固定容量セッションテーブルは同型要素の
配列でなければ成立しない**。typestate の安全性は「鍵取得 API が `mode` を見て `Option<AeadKeyRef>` を
返す」ことで実質的に確保する(PlainText は `None` → §3.3 の `decrypt` が復号をスキップ)。

matter.js は継承(SecureSession 抽象基底 → NodeSession/UnsecuredSession)で表すが、これは GC 前提の
動的ディスパッチであり no_std の固定配列に載らない。research/matter-js.md はこれを「Rust では typestate が
良い」と示唆するが、それは**ハンドシェイク駆動の状態遷移**(Sigma1→2→3)に対して正しく、
**確立後のテーブル格納表現**には enum が正しい。両者を分けて使う:

- `sc` 層(次段階)の PASE/CASE **ハンドシェイク**は typestate で表現してよい(`Sigma1Sent` → `Sigma2Recv`
  のような型遷移で誤順序を防ぐ)。確立の瞬間に `SessionManager::promote()` で **enum の Secure に消去**する。
- `transport` 層の**テーブルエントリ**は常に enum。

### 4.2 型

```rust
// transport/session.rs

/// セッション種別。鍵は常に struct に存在するが、getter が mode で gating する。
pub enum SessionMode {
    PlainText,                          // = Unauthenticated(PASE/CASE 第1メッセージ用)
    Pase { fabric_idx: u8 },            // 0(fabric 未確定)で開始、AddNOC で1度だけ昇格
    Case { fabric_idx: core::num::NonZeroU8 },
    // Group { fabric_idx: NonZeroU8, group_id: u16 },  ← group feature
}

pub struct Session {
    id: SessionId,                      // 安定ハンドル(配列 slot とは独立、§4.3)
    peer_addr: PeerAddr,
    local_node_id: u64,
    peer_node_id: Option<u64>,
    local_session_id: u16,              // ワイヤ上の自分側 session id
    peer_session_id: u16,
    enc_key: AeadKey,                   // 送信用(dec/enc 命名で initiator/responder 混同を回避)
    dec_key: AeadKey,                   // 受信用
    att_challenge: [u8; 16],
    tx_ctr: LocalCounter,               // §3.2
    rx_window: PeerWindow,              // §3.2
    mode: SessionMode,
    mrp: PeerMrpParams,                 // SII/SAI/SAT(peer advertised)。§6
    last_use: Instant,                  // LRU 退避キー
    state: SlotState,                   // Reserved / Active / Expired
}
impl Session {
    /// PlainText なら None → SecureCodec が復号スキップ。
    pub fn dec_key(&self) -> Option<AeadKeyRef<'_>>;
    pub fn enc_key(&self) -> Option<AeadKeyRef<'_>>;
    pub fn next_tx_ctr(&mut self) -> u32 { self.tx_ctr.next() }
}
```

`Session` は `const fn new()` + `init() -> impl Init<Self>`(pinned-init)を持ち、16バイト鍵×2 を
スタックコピーせず `.bss` に in-place 初期化する(ARCHITECTURE 原則3、rs-matter 踏襲)。

### 4.3 SessionManager(固定容量テーブル)

```rust
pub struct SessionManager<const SESSIONS: usize> {
    sessions: FixedVec<Session, SESSIONS>,  // heapless 風、詰めて格納
    next_id: u32,                           // 安定 SessionId 採番(ラップ)
    next_local_sid: u16,                    // ワイヤ session id 採番(0 と使用中を回避)
}
```

- **固定容量 `const SESSIONS`**(§8)。`FixedVec`(自前の heapless 風 inline Vec)で詰めて格納し、
  削除は swap_remove。**配列 slot は不安定**なので、参照は安定な `SessionId`(下記)で行う。

  ```rust
  pub struct SessionId(u32);  // 単なる不透明ハンドル。rs-matter のような bit-packing はしない(§5.3)
  ```

- **照合**: `get(SessionId)`, `find_for_rx(addr, &PacketHeader)`(session_id または PASE の addr 照合),
  `find_for_node(fabric, node)`。いずれも `last_use` を更新。
- **退避(LRU)**: 満杯時、Expired を最優先、次いで**生存 exchange を持たない**最古の session を退避
  (chip の `SecureSessionTable` LRU)。exchange の生存有無は ExchangeManager に問い合わせる(§5)。
- **2相コミット予約**: ハンドシェイク中はデータが揃う前に容量を確保したい。RAII の `ReservedSession`
  (`reserve()` で `state=Reserved` の slot 確保 → `commit(keys, ids, mode)` → `Drop` で未 commit なら解放)。
  rs-matter の `ReservedSession` を踏襲。これで「PASE 中に他要求でテーブルが埋まる」競合を防ぐ。

---

## 5. ExchangeManager / Exchange

### 5.1 責務

- Exchange = 二ノード間の1会話(`(session, exchange_id, role)`)。
- MRP(信頼再送)を **Exchange に値として内包**(chip の `ExchangeContext : ReliableMessageContext`、
  rs-matter の `ExchangeState { mrp: ReliableMessage }` と同じ)。
- 受信メッセージを protocol_id でハンドラにディスパッチ(§5.4)。

### 5.2 exchange を session から分離する — **flat プールを選ぶ**

rs-matter は exchange を session の中に入れ子(`Session.exchanges: Vec<Option<ExchangeState>, N>`)にし、
ExchangeManager を実質持たない。本設計は **session テーブルと独立した flat な exchange プール**を持つ:

```rust
pub struct ExchangeManager<H, const EXCHANGES: usize> {
    exchanges: FixedVec<ExchangeState, EXCHANGES>,
    next_exch_id: u16,
    handler: H,                       // ProtocolMux(§5.4)。ジェネリックだが単一型
}
```

判断根拠:
- **ARCHITECTURE の層境界に忠実**(transport=session / exchange=会話 が別層)。chip も messaging と
  transport を別ディレクトリに分ける。
- **同時 exchange 数の上限を全体で1つ**にできる(入れ子だと「session あたり N」で、session×N の最悪確保)。
  デバイスは同時会話が少数なので、全体プール1本のほうが RAM を締められる。
- exchange から session へは `SessionId` で参照(所有ではない)。session 退避時に生存 exchange があるかは
  ExchangeManager が `SessionId` で走査して判定。

トレードオフ: 入れ子なら「session ごとの公平性」が自然に出る(1 session が全 exchange を食い潰さない)。
本設計は flat プールにするため、必要なら **session あたりの exchange 数に軽い上限**を別途チェックする
(オープン論点、§11)。

### 5.3 型: ハンドル/格納状態の分離

```rust
// exchange/exchange.rs

/// テーブルに格納される状態。
pub struct ExchangeState {
    exch_id: u16,
    session: SessionId,
    role: Role,
    mrp: Mrp,                 // §6。値で内包
}
pub enum Role { Initiator, Responder }   // responder のみ実装だが initiator も型は用意

/// exchange の不透明ハンドル。index は持たず id で解決する。
#[derive(Clone, Copy)]
pub struct ExchangeId { session: SessionId, exch_id: u16 }

/// ユーザ(sc/im ハンドラ)に渡す一時ハンドル。
pub struct Exchange<'a> {
    id: ExchangeId,
    stack: &'a MatterStack,   // スタック全体への共有参照
    rx: Option<PacketLease<'a>>,  // recv_fetch で保持中の RX(§7)
}
```

**重要な所有権トリック(rs-matter 踏襲)**: `Exchange<'a>` は **id + スタック参照だけ**を持ち、
session/exchange の状態を直接借用しない。各操作は `stack.with_state(|s| ...)`(内部 Mutex)経由で
その都度状態を再取得する。これにより **`.await` をまたいでセッションテーブルを `&mut` 借用しない**
= 複数 exchange が並行しても借用検査・エイリアスの問題が起きない。async no_std での要。

**`ExchangeId` に bit-packing しない**(rs-matter との差): rs-matter は `ExchangeId(u32) =
(index<<28) | session_id` と詰め、その副作用で「exchange は最大16」「session id は28bit」という
**人工的な上限が counter マスクにまで波及**している。本設計は `ExchangeId { SessionId, u16 }` と
素直な struct にし、上限は const generic(§8)だけで決める。counter を32bit 全域使えるのはこのため(§3.2)。

### 5.4 プロトコルディスパッチ — dyn vs enum vs generic

デバイスが話すプロトコルは **SecureChannel(0x0000)と InteractionModel(0x0001)の2つ**、将来 BDX(0x0002)。
**閉じた小集合**である点が選択を決める。

| 案 | 評価 |
|---|---|
| **generic タプルチェイン**(rs-matter `ChainedHandler`) | プロトコル/クラスタを足すたびに最上位型が変わり、`handler_chain_type!` マクロや長大型エイリアスが要る。**まさに回避対象** |
| **`&dyn ProtocolHandler`**(matter.js `ProtocolHandler`) | プラガブルで疎結合だが、`async fn` を持つ trait の `dyn` 化は no_std で非自明(`dyn*`/box が要る=alloc)。GAT があると更に困難 |
| **enum mux**(閉じた集合を enum で分岐) | vtable なし・alloc なし・**単一の型名**。プロトコルは閉じているので拡張性の損失が小さい |

**判断: enum mux**。

```rust
// exchange/dispatch.rs

/// 各プロトコル(sc / im)が実装する。exchange と受信 payload を受け、応答を書く。
pub trait ProtocolHandler {
    const PROTOCOL_ID: u16;
    async fn handle(&self, exch: &mut Exchange<'_>, rx: &RxMessage<'_>) -> Result<(), Error>;
}

/// 閉じたプロトコル集合を静的にディスパッチする。これが exchange 層が見る唯一のハンドラ型。
pub enum ProtocolMux<Sc, Im> {
    // 実体はフィールド1個ずつ持つ struct 的な mux(下記 dispatch)
}
impl<Sc: ProtocolHandler, Im: ProtocolHandler> ProtocolMux<Sc, Im> {
    pub async fn dispatch(&self, proto_id: u16, exch: &mut Exchange<'_>, rx: &RxMessage<'_>)
        -> Result<(), Error>
    {
        match proto_id {
            Sc::PROTOCOL_ID => self.sc.handle(exch, rx).await,
            Im::PROTOCOL_ID => self.im.handle(exch, rx).await,
            _ => Err(Error::NotFound),  // → StatusReport(protocol 未対応)
        }
    }
}
```

- matter.js の「protocol_id ごとにハンドラ登録、ExchangeManager は中身を知らない」プラガブル性を、
  **列挙による静的分岐**で再現(research/matter-js.md が示す「no_std では enum+match で ProtocolHandler を
  再現」に一致)。
- BDX 追加時は `ProtocolMux` に variant を1つ増やすだけ。**ExchangeManager 本体は不変**。
- **これが型爆発回避の核心**(§9): クラスタのタプルチェインは `Im` ハンドラの**内側**に隠れ、
  exchange 層は `Im` を1個の不透明な型パラメータとしてしか見ない。

### 5.5 受信時の exchange 照合

chip/rs-matter と同じ: 既存 exchange に照合(`exch_id` 一致かつ `rx.is_initiator() == (role==Responder)`)、
なければ「未応答メッセージ」として新規 responder exchange を生成しハンドラを呼ぶ。responder exchange は
**peer の exch_id を再利用**(自分では採番しない)。initiator exchange のみ `next_exch_id` から採番。

---

## 6. MRP(Message Reliability Protocol)

`exchange/mrp.rs`。Exchange に値内包。rs-matter `mrp.rs` をほぼ踏襲(仕様準拠で発明の余地が少ない)。

```rust
pub struct Mrp {
    retrans: Option<RetransSlot>,   // 未 ack の送信メッセージ
    ack: Option<PendingAck>,        // 送るべき ack(piggyback 用)
    received_at: Option<Instant>,
}
struct RetransSlot { base_interval_ms: u32, msg_ctr: u32, tries: u16 }
struct PendingAck { msg_ctr: u32, sent: bool }

pub struct MrpConfig {   // peer が session_parameters で広告 / 自 BasicInfo から既定
    pub idle_interval_ms: u32,      // SII: Session Idle Interval
    pub active_interval_ms: u32,    // SAI: Session Active Interval
    pub active_threshold_ms: u16,   // SAT: Session Active Threshold
}
```

- **再送タイマ + 指数バックオフ**: `delay = base * MARGIN(1.1) * BASE(1.6)^(tries-threshold) + jitter(0.25)`。
  最大 `MRP_MAX_TRANSMISSIONS=10` 回で `TxTimeout`。定数は仕様値(rs-matter と同一)。
- **ACK piggyback**: 送信時、未送 ack があれば `PayloadHeader.ack_ctr` に載せて同送(`pre_send`)。
- **バックオフの元値**は peer の SAI/SII から。peer 未広告なら自 `BasicInfoConfig` の SAI/SII、それも無ければ
  仕様デフォルト(SII=5000ms, SAT=4000ms, base=300ms)。`Some(0)` は `None` 扱い(0 だとタイトループ化)。
- **プロアクティブな standalone ACK**(200ms で単独 ack 送信)は rs-matter でも TODO。初期は **piggyback +
  応答時 ack のみ**とし、standalone ack は「応答を返せない/遅い場合」に限定(オープン論点、§11)。
- **信頼トランスポート上では R/A フラグを落とす**(`adjust_reliability`)。UDP のみの今は常に MRP 有効だが、
  将来 TCP/BTP のために境界コードは入れる。

再送ループ駆動: rs-matter の `Sender`/`OwnedSender`(同一 payload を冪等に再書き込みするループ)を採用。
1回のループ反復で「TX slot 取得 → 同じ payload を書く → 送信 → ack 待ち or タイムアウト」。
タイマ待ちは `embassy-time::Timer`(executor 非依存、ARCHITECTURE 原則8)。

---

## 7. バッファ戦略

### 7.1 所有権モデル(誰が確保し、いつ返すか)

- **バッファは Transport が所有**。session/exchange はバッファを**所有しない**(借用のみ)。
- **RX**: Transport の RX ループが RX バッファを1枚リースし、datagram を読み込み、`SecureCodec` で
  in-place 復号し、平文 payload の **view**(`RxMessage<'a>`)を exchange/ハンドラへ渡す。ハンドラ処理が
  終わってリースが drop されると自動的にプールへ返る(RAII)。
- **TX(非信頼)**: 応答は TX バッファをリースして書き込み、送信後に即 drop で返却。
- **TX(信頼 = MRP)**: **ここが唯一の長寿命所有**。ack されるまで**暗号化済み TX バッファを保持**して
  再送に使う必要がある。よって **`RetransSlot` が TX バッファのリースを所有**し、ack 受信 or 諦め時に返す。

```rust
// buf.rs
pub struct BufferPool<const N: usize, const SIZE: usize> {
    slots: [Buffer<SIZE>; N],
    free: BitSet<N>,           // 空き slot ビットマップ
    signal: Signal,            // embassy-sync。満杯時の非同期待ち
}
pub struct PacketLease<'a, const SIZE: usize> { /* pool への借用 + slot idx。Drop で返却 */ }
impl<const N: usize, const SIZE: usize> BufferPool<N, SIZE> {
    /// 空きが出るまで await。
    pub async fn acquire(&self) -> PacketLease<'_, SIZE>;
    /// 述語が満たされる(= 自分宛 RX が来た)まで await して貸す(*_awaits 相当、§7.2)。
    pub async fn acquire_if(&self, pred: impl Fn(&PacketHeader) -> bool) -> PacketLease<'_, SIZE>;
}
```

- **バッファサイズは固定 const**(ジェネリックだが値は固定): RX = `MAX_RX_PACKET_SIZE = 1583`、
  TX = `MAX_TX_PACKET_SIZE = 1280 - 40 - 8 = 1232`(IPv6+UDP ヘッダ控除、仕様値)。
- **ヘッダ headroom を確保して書く**: TX は `HDR_RESERVE = PacketHeader::MAX_LEN + PayloadHeader::MAX_LEN`
  を先頭に空け、payload を中央から書き、暗号化後にヘッダを左へ前置(rs-matter `PacketHdr` の
  prepend 方式)。末尾 `TAIL_RESERVE = AEAD_TAG_LEN` は MIC 用。

### 7.2 rs-matter の `*_awaits` 省バッファ最適化 — **概念は採用、実装は段階的**

rs-matter は極端に「**スタック全体で RX 1枚・TX 1枚**」まで削り、`acquire_if(pred)` で「自分宛の RX が
来るまで待つ」ことで多重確保を避ける。副作用として「RX を保持中は他 exchange が全て停止」する
(rs-matter も明記)。また `AsyncHandler::read_awaits/write_awaits` で「このハンドラは await しない」と
申告させ、request バッファに直接 response を書いて中間バッファを省く。

本設計の方針:
- **プール容量を小さな const(既定 RX=2, TX=2)にする**が、**1枚固定にはしない**。responder は
  基本 request→response の直列処理なので少数プールで足り、「1枚保持で全停止」の厳しさを避ける。
  極小 RAM プロファイルでは `RX=1, TX=1` を選べる(§8)。
- **`acquire_if(pred)` 述語待ち**は採用(自分宛でない RX で他 exchange のバッファを奪わない)。
- **「await しないハンドラは request/response 同一バッファ」最適化**は、`ProtocolHandler` に
  `const NEEDS_ASYNC_RESPONSE: bool`(既定 true)を持たせて表現できる形にするが、**まず正しさ優先で
  別バッファ実装**とし、この fast path は計測後に入れる(オープン論点、§11)。

### 7.3 アプリ payload バッファ

IM の TLV 組み立て等に使う大きめの作業バッファは、パケットバッファとは**別の小プール**にする
(rs-matter の `PooledBuffers<Buffer, N>` 相当、IM/BDX で共有)。これは exchange 層でなく im 層の
関心なので、本層では「Transport がパケットバッファを、上位が payload バッファを持つ」境界だけ定義する。

---

## 8. サイジング(少数の const generic へ集約)

rs-matter の約100 feature(`max-sessions-16` 等の ladder)を **4つの const generic** に集約する。

```rust
pub struct MatterStack<
    N,                        // Network 実装(1 型パラメータ)
    C,                        // CryptoProvider 実装(1 型パラメータ)
    const SESSIONS: usize,    // 同時セッション数
    const EXCHANGES: usize,   // 同時 exchange 数(全体プール)
    const RX_BUFS: usize,     // RX パケットバッファ枚数
    const TX_BUFS: usize,     // TX パケットバッファ枚数
> { /* ... */ }
```

バッファ**サイズ**(1583/1232)は const 固定でパラメータにしない(UDP 専用のため可変にする意味がない。
TCP large-buffers は feature gate で別途)。

### 8.1 プロファイル型エイリアスで数値を隠す

const generic は**名前を書ける型**なので rs-matter の「タプル型が書けない」問題は起きない。それでも
アプリが4数値を書くのは煩雑なので、**プロファイルをエイリアスで提供**:

```rust
/// 極小(単一コントローラ、RX/TX 各1枚)。RAM 最小。
pub type MinimalStack<N, C> = MatterStack<N, C, 3, 3, 1, 1>;
/// 標準(数コントローラ + 並行 exchange)。
pub type DefaultStack<N, C> = MatterStack<N, C, 4, 4, 2, 2>;
```

アプリは `DefaultStack<MyUdp, MyCrypto>` と書くだけ。数値は1箇所(エイリアス定義)に集約される。
これで「feature 100個 → プロファイル2〜3個 or const 4個」という ARCHITECTURE 原則3を満たす。

### 8.2 なぜ「assoc const を束ねる trait」にしないか

`trait Sizing { const SESSIONS: usize; ... }` で1型パラメータに束ねる案は魅力的だが、
`[T; S::SESSIONS]`(型パラメータの関連 const を配列長に使う)は **stable Rust では不可**
(`generic_const_exprs` 未安定)。よって配列を持つ格納構造体は**素の const generic**にせざるを得ない。
プロファイルエイリアスで表面的な1名前化を達成する方が現実的、というのが判断。

---

## 9. 型パラメータ伝播の抑制(設計原則7の本層での実現)

rs-matter の病巣は `InteractionModel<'a, Crypto, Buffers, (Node, Handler), Kv, Networks, NetCtl>` の
**7型パラメータ**、特に `(Node, Handler)` の**クラスタ数だけ育つタプル型**が最上位まで漏れ、
embassy-executor のタスク境界で「型名が書けない」ことだった。本層での回避策:

1. **ハンドラ合成を enum mux に閉じる**(§5.4)。exchange 層が見るハンドラ型は `ProtocolMux<Sc, Im>` の
   **単一名**。クラスタのタプルチェインは `Im` の内側に隠れ、この層には**漏れない**。これが
   「境界で型消去する層を1枚挟む」の具体。**型消去の境界 = `ProtocolHandler` trait**:
   `im` エンジンは `impl ProtocolHandler for ImEngine<...clusters...>` を提供し、exchange 層は
   `Im: ProtocolHandler` としか知らない。クラスタを1個足しても `Im` の**内部**が変わるだけで、
   exchange/transport のシグネチャは不変。
2. **型パラメータを `N`(Network)・`C`(Crypto)・const 4個に限定**。7個 → 実質2型 + 4 const。
   いずれも**名前を書ける**(タプルでない)。プロファイルエイリアスで更に隠す(§8)。
3. **`C: Crypto` の波及を `secure.rs` と Transport の暗号メソッドに閉じる**。exchange 層以上は暗号を
   知らない(暗号境界=1点、§3.3)ので `C` を持たない。ExchangeManager は `H`(=mux)だけを持つ。
4. **`ExchangeId` を bit-packing しない**(§5.3)ので、サイジング const がヘッダ counter 等の
   無関係な箇所へ波及しない。

結果として、最上位 `MatterStack<N, C, ...>` の型名は人間が書けるものに保たれ、`handler_chain_type!`
相当のマクロは不要になる。

---

## 10. 受信/送信データフロー(全体像)

**受信(暗号文 → 平文 → ハンドラ):**

```
UdpReceive::recv_from(rx_buf)                     … Transport RX ループ(rx_buf は BufferPool から)
 → PacketHeader::decode                           … 平文ヘッダ(復号不要)
 → SessionManager::find_for_rx(addr, &hdr)        … session_id/addr で session 解決
 → PeerWindow::accept(ctr)                         … リプレイ/重複ドロップ
 → SecureCodec::decrypt(dec_key, ...)  ★暗号境界★  … in-place 復号 → PayloadHeader
 → ExchangeManager::find_or_create(session, &phdr) … exchange 照合 or 新規 responder
 → Mrp::post_recv(&phdr)                           … ack 記録 / 再送解除 / 重複判定
 → ProtocolMux::dispatch(proto_id, &mut exch, rx)  … sc / im へ静的分岐
```

**送信(ハンドラ平文 → 暗号文 → ネット):**

```
ハンドラが Exchange::tx() で TX バッファ取得(headroom 確保済み)
 → payload を中央に書く(im/sc)
 → Mrp::pre_send(&mut phdr)                        … ack piggyback / retrans slot 登録
 → PayloadHeader::encode → SecureCodec::encrypt  ★暗号境界★ … 前置 + 暗号化 + MIC
 → PacketHeader::encode(前置)
 → UdpSend::send_to(buf, addr)
 → (信頼なら) RetransSlot が TX リースを保持し、ack まで再送ループ
```

暗号呼び出しが RX/TX 各1箇所(`SecureCodec`)に限定されていることが読み取れる。

---

## 11. rs-matter の課題と本設計の回避策(対応表)

| rs-matter の課題(research/rs-matter.md §8) | 本設計の回避策 |
|---|---|
| **7型パラメータの上位伝播**・`handler_chain_type!` | ハンドラを enum mux に閉じ、exchange 層は単一の `H` しか見ない。型パラメータを `N`/`C`/const 4個に限定(§5.4, §9) |
| **`ExchangeId` bit-pack による人工上限**(exch≤16, sid 28bit, counter マスク波及) | `ExchangeId { SessionId, u16 }` と素直に。上限は const generic だけで決め、counter は32bit 全域(§5.3, §3.2) |
| **transport.rs 2610行のモノリス**(session/exchange/MRP/mDNS 同居) | net/header/counter/session/secure/mrp/exchange/dispatch にファイル分割。層境界を module 境界に(§1) |
| **約100 個のサイジング feature** | const generic 4個 + プロファイルエイリアス 2〜3個(§8) |
| **exchange が session に入れ子**で ExchangeManager 不在 → 層が不明瞭 | exchange を flat プールに分離、transport/exchange を別層に(§5.2) |
| **no_std だが alloc 必須**(crypto/cert 起因) | 本層は alloc 不要(固定プール・固定テーブル・in-place init)。alloc 依存は crypto backend 選定の問題で本層外 |
| **`.await` またぎのセッション借用** | `Exchange<'a>` は id + スタック参照のみ、操作ごとに `with_state` で再取得(§5.3) |
| **RX/TX 1枚固定で全停止**(過度な省バッファ) | 既定は小プール(RX/TX 各2)+ 述語待ち。極小は 1/1 を選択可(§7.2) |

**chip / matter.js から借りるもの**: 暗号境界1点(`SecureMessageCodec`→`SecureCodec`)、
Packet/Payload ヘッダ分離、セッション enum 判別、MRP を Exchange に内包、protocol 語彙とエンジンの分離、
`ProtocolHandler` プラガブル性(ただし enum で静的化)。

---

## 12. オープンな論点

1. **時間ソースの抽象度**: MRP タイマは `embassy-time`(ARCHITECTURE 原則8)で確定だが、`embassy_time::Instant`
   を `Session`/`Mrp` に直接持たせるか、`Clock` trait で1枚抽象化して std テストを容易にするか。
   → 現状は embassy-time 直接 + テスト時 `embassy-time/std` を推奨。要確定。
2. **standalone ACK のプロアクティブ送信**(200ms): rs-matter でも TODO。応答を即返せないハンドラ
   (長い処理)への ack をいつ送るか。初期は piggyback のみで進め、subscribe/長処理を実装する段階で再検討。
3. **`*_awaits` 相当の request/response 同一バッファ最適化**を `ProtocolHandler` の const で表現するか。
   まず別バッファで正しく作り、bloat-check 計測後に導入するか。RAM 削減量と複雑性のトレードオフ。
4. **flat exchange プールでの session あたり公平性**: 1 session が全 exchange slot を占有するのを
   防ぐ軽い per-session 上限が要るか(§5.2)。DoS 耐性の観点。
5. **session 退避の判定コスト**: 退避時に「生存 exchange を持つか」を ExchangeManager 全走査で判定する
   コスト。exchange 数が少ないので O(EXCHANGES) で許容できる見込みだが、逆参照カウンタを持つ案もある。
6. **PeerWindow 窓幅**: 32 に広げる提案(§3.2)の妥当性。順序前後の実測が無いので、まず32、
   RAM が厳しければ16へ。
7. **group / multicast セッション**: 初期スコープ外だが、`SessionMode::Group` と group counter store
   (persist が要る)を後付けする際、session テーブルのエントリ形が変わらないか事前確認。
8. **CASE session resumption**(Sigma2Resume): スコープ外。resumption 用の session 復元情報を
   `Session` に持たせるかは、fabric/credentials 段階で判断。
9. **RX ループと MRP タイマループの並行構造**: 単一 `select` ループ(rs-matter `onoff_light` の
   `select4`)か、別タスクか。`UdpSend`/`UdpReceive` を分離した(§2.1)のは後者を可能にするためだが、
   共有状態の Mutex 競合を考えると初期は単一ループが無難か。executor 非依存のまま両対応にできる形が理想。
```

### 6.1 重複メッセージへの standalone ACK(2026-08-26 追記)

**問題**: `ExchangeManager::recv` はリプレイ窓で弾いた重複(`decoded.duplicate`)に対し、**会話がまだ存在する
ときだけ** `rearm_ack` する。会話が終端・回収済み(例: コントローラがデバイス発 ReportData に StatusResponse を
返して close 済み)の重複には **ACK を一切返さない**。送信側は ACK が来ないので再送を続け(最大 10 回・~34 秒)、
最終的に give-up → 送信側の会話が失敗扱いになる(デバイスの購読レポートなら `on_report_exchange_failed` で購読破棄)。
MRP 仕様(Matter Core §4.12)は「重複を受け取った受信者は改めて ACK を返さなければならない」であり、これは
仕様違反。P4 コントローラ実機で「ACK 済みなのに再送が 8 回続く」を観測(T8b 調査)。

**方針**: 会話の有無に関わらず、`R` フラグ付き重複には即時 standalone ACK を返す。

- `ExchangeManager` に `orphan_acks: FixedVec<OrphanAck, ORPHAN_ACKS>`(`ORPHAN_ACKS = 2`、溢れたら最古を捨てる)を
  追加。`OrphanAck { session: SessionId, exch_id: u16, peer_is_initiator: bool, ack_ctr: u32 }`。
- `recv` の重複分岐: `allows_mrp && phdr.is_reliable()` のとき、会話があれば従来どおり `rearm_ack`、無ければ
  `orphan_acks` に積む(同一 (session, exch_id, ack_ctr) は重複登録しない)。
- `poll` は closing 回収の後・再送処理の前に `orphan_acks` を 1 件取り出し、新設の
  `PollAction::SendOrphanAck { session, exch_id, peer_is_initiator, ack_ctr }` を返す(遅延なし。会話を持たないので
  200 ms の piggyback 待ちは意味がない)。
- `build_standalone_ack` の中身を `build_standalone_ack_raw(sessions, crypto, session, exch_id, i_flag, ack_ctr, out, now)`
  に切り出し、既存 API はそれを呼ぶ。I フラグ = `!peer_is_initiator`(自分の役割)。
- `MatterStack::poll` / `ControllerStack::poll` の `match` に `SendOrphanAck` を追加(`stage_standalone_ack` の raw 版)。
- `next_deadline`: `orphan_acks` が空でなければ `Some(now)` 相当(即時)。

**回帰テスト**: (1) exchange 層: 会話 close 後に同じ msg_ctr の reliable メッセージを再投入 → `recv` は
`duplicate=true`、直後の `poll` が `SendOrphanAck`(正しい session/exch_id/I フラグ/ack_ctr)、その後 Idle。
(2) 会話が生きている重複は従来どおり `rearm_ack` → `SendAck`(既存 `recv_duplicate_reliable_rearms_ack` 維持)。
(3) 統合(stack loopback ctrl↔dev): 実装時の実測で、コントローラの StatusResponse は `Close { reliable: true }`
で送られるため、それが落ちても自分の再送スロットを抱えて会話が生き続け、重複 ReportData は従来の `rearm_ack`
で ACK される(= T8b で見た「8 回」は実は ACK されていた)。問題が出るのは **会話が終端・回収済み**の後に遅延した
重複が届く経路なので、テストは「StatusResponse を 1 通落とす → デバイスの再送 datagram を保留 → StatusResponse の
再送でデバイス側が止まり ctrl 側会話が回収される → 保留していた重複を投入 → 修正前は沈黙、修正後は standalone ACK
1 通、両側の購読は生存」とした(`duplicate_report_after_closed_exchange_gets_standalone_ack`)。
