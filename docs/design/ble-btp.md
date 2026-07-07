# BLE コミッショニング(BTP)設計 — デバイス/コントローラ両側の BLE 対応

対象: `docs/ARCHITECTURE.md` 初期スコープで「BLE コミッショニングは feature で後日」と
された部分。本書は Matter の **BTP(Bluetooth Transport Protocol)** を追加し、UDP と並ぶ
第 2 のトランスポートとしてデバイス(peripheral / responder)とコントローラ(central /
commissioner)の双方に BLE 対応を入れるための設計である。前提は既存設計と同一:

> `no_std`・sans-IO(バイト列 + 時刻のみ、ソケット非依存)・定常データパス no-alloc・
> executor 非依存。加えて **BLE 制御部を後日 ESP32 等(NimBLE / esp-idf BLE)へ移植できるよう
> 抽象化する** ことを絶対条件とする。

- 上位境界: BTP は Matter メッセージ層(`transport` / `exchange`)の **下** に入る生
  トランスポートである。BTP が 1 つの Matter メッセージ(SDU = 先頭が `PacketHeader` の
  datagram)を再組立して返すと、それを既存の [`MatterStack::handle_rx`] /
  [`ControllerStack::handle_rx`] に `PeerAddr::Ble(..)` 付きでそのまま渡す。逆に
  `SendDirective { addr: PeerAddr::Ble(..), len }` を BTP がセグメント化して C2 indication で送る。
  **`MatterStack` / `ControllerStack` 本体は BTP を知らずに済む**(sans-IO・PeerAddr 抽象の果実)。
- 下位境界: BTP コアは **最小の GATT trait 1 枚** にのみ依存する(依存性逆転)。PC は
  Linux の bluer(BlueZ)/ btleplug がその trait を実装し、ESP32 移植時は NimBLE 実装を
  差し込むだけにする。

参照実装は `research/connectedhomeip/src/ble/`(`BtpEngine` / `BLEEndPoint` / `BleLayer` /
`BleUUID` / `CHIPBleServiceData`。以下 chip)、`research/rs-matter/rs-matter/src/transport/network/btp/`
(以下 rs-matter)、および Matter Core Specification の BTP 章。本書のワイヤ定数・UUID・
広告フォーマットは §2 で **両参照実装から裏取りした値** を用いる。

本書はシグネチャスケッチを含むが、コンパイル可能性より設計判断の明確化を優先する
(既存 4 設計 doc と同じ方針)。

---

## 0. サマリ(主要な設計判断)

1. **BTP はコアクレート内の sans-IO・no_std モジュール `src/btp/`(feature `ble`)として実装する**。
   フレーミング・handshake・seq/ack・ウィンドウ・セグメンテーション・keep-alive タイマの
   状態機械はすべてこのモジュールに閉じ、`embassy-time` にも依存せず `now_ms` 注入で駆動する
   (MRP と同じ sans-IO 契約、§4)。**BLE 無線・OS スタックには一切触れない**。
2. **GATT 層は最小の async trait 2 枚で依存性逆転する** — device 側 `GattPeripheral`、
   controller 側 `GattCentral`。`UdpSend`/`UdpReceive` の流儀(`async fn` in trait・`Send` 境界なし・
   `&mut T` ブランケット実装)に厳密に合わせる。**ESP32 移植 = この trait を NimBLE 等で実装するだけ**
   (§5)。rs-matter は trait を作らず OS 関数直呼びだが、本設計は移植性のため trait 境界を明示する。
3. **`PeerAddr::Ble(BtpConnId)` variant を 1 個追加する**。`BtpConnId` は 6 バイト MAC ではなく
   **不透明な接続ハンドル(u8 index)**。BTP セッションは接続ハンドルで識別し、
   `SessionManager` の照合・`Mrp` の宛先・`SendDirective` の宛先がそのまま BLE に流用される
   (§3)。既存 `net.rs` の `PeerAddr` は最初からこの拡張を見越して enum で包まれている。
4. **BTP 上のセッションでは MRP を無効化する。無効化は「セッション送信ファネル 1 点」で行う**。
   BTP はトランスポート層で seq/ack/window による信頼性を保証するため、Matter メッセージ層の
   R(RELIABLE)/A(ACK)フラグは不要かつ有害(二重信頼)。両参照実装とも
   `Session::AllowsMRP()`(chip)/ `Address::is_reliable()` + `adjust_reliability`(rs-matter)で
   **UDP 以外は MRP を落とす**。本設計は `Session::allows_mrp()` を追加し、
   スタックの送信ファネルが `reliable → unreliable` へ格下げ・再送スロット非登録・standalone ACK 抑止を
   行う。SC/IM ハンドラはトランスポート種別を知らないまま(§3.3)。
5. **BLE 制御(std 依存の重い crate)はコアに入れず、新ワークスペースクレートへ分離する**。
   `crates/simple-matter-ble`(std)に bluer(device peripheral)と btleplug(controller central)を
   **feature で分岐**して同居させ、examples もここに置く。btleplug は central 専用なので
   **device 側 PC バックエンドは bluer(BlueZ)、controller 側は btleplug** という分担にする(§6)。
6. **E2E は 3 段階**: (段階1)メモリ内ループバック GATT で BTP+PASE+コミッショニング全経路を
   無線なしで `cargo test`(CI 可)、(段階2)bluer device example ⇔ btleplug commissioner example を
   実 BLE で(BlueZ は同一アダプタで peripheral/central 同時可)、(段階3)chip-tool /
   chip サンプルアプリとの相互運用(既存の connectedhomeip 相互運用実績に接続、§9)。
7. **BLE→運用ネットワーク遷移は初期スコープでは「PASE-only / on-network 併走」で見せる**。
   NetworkCommissioning は既存実装のまま、初期 E2E は「BLE で PASE→CASE→CommissioningComplete まで
   通し、その後同一デバイスの UDP 運用アドレスへ CASE 再確立」で BLE→UDP 切替を可視化する(§9.4)。
8. **ウィンドウ/バッファは const generic + プロファイルに集約**。window は既定 6(仕様上限、
   chip `BLE_MAX_RECEIVE_WINDOW_SIZE`)、RX 再組立 = 1 Matter メッセージ、TX SDU = 1 本。
   コアの btp モジュールはヒープレス(固定バッファ)、PC バックエンドクレートは std で自由(§4.4)。

---

## 1. モジュール構成と依存関係

`(+)` = 新規、`(±)` = 既存への最小変更。**コア(`crates/simple-matter`)側**:

```
transport/
  net.rs        (±) PeerAddr に Ble(BtpConnId) variant を 1 個追加(#[cfg(feature="ble")])   … §3.1
  session.rs    (±) Session::allows_mrp() を追加(peer_addr で分岐。cfg なしで常時コンパイル可) … §3.2
btp/            (+) #[cfg(feature = "ble")] — sans-IO no_std BTP コア
  mod.rs            Btp<W>: 状態機械の外殻。process_incoming / process_outgoing / recv / send /
                    next_deadline / on_tick。GATT trait を呼ばない(バイト列 in/out のみ)
  framing.rs        BtpHeader(flags/seq/ack/msglen)の parse/encode、HeaderFlags
  handshake.rs      HandshakeReq / HandshakeResp の parse/encode(magic 0x65 0x6C, version 4)
  session.rs        BtpSession, SendWindow, RecvWindow(seq/ack/window の状態機械)
  reassembly.rs     RX 再組立(Beginning→Continuing→Ending、msglen 検証)+ TX セグメント化
  gatt.rs           GattPeripheral / GattCentral trait(§5)、AdvData(広告ビルダ)、UUID 定数
lib.rs          (±) #[cfg(feature = "ble")] pub mod btp; と数行
Cargo.toml      (±) [features] ble = [](依存クレート追加なし・default 無効)
```

**PC バックエンドクレート(新規、std)**:

```
crates/simple-matter-ble/         (+) std。simple-matter を features=["ble"](+ controller)で依存
  Cargo.toml                          [features] device=[dep:bluer] / commissioner=[dep:btleplug,"simple-matter/controller"]
  src/lib.rs                          共通ヘルパ(BtpConnId 割当、ポンプループの型)
  src/bluer_peripheral.rs             (feature device)  GattPeripheral を BlueZ で実装
  src/btleplug_central.rs             (feature commissioner) GattCentral を btleplug で実装
  examples/ble-onoff-light.rs         (device)     bluer + MatterStack、BLE でコミッショニング受理
  examples/ble-commissioner.rs        (commissioner) btleplug + ControllerStack、BLE で相手を commission
```

### 依存方向(下→上の一方向)

```
error, tlv, crypto                                        … 既存
   ▲
transport/net(PeerAddr::Ble ±), transport/session(allows_mrp ±)
   ▲
btp/{framing, handshake, session, reassembly}             … 相互に閉じた BTP 状態機械。上位を知らない
   ▲
btp/mod(Btp<W>)  ── btp/gatt(GattPeripheral/GattCentral trait, AdvData, UUID)
   ▲
exchange / stack / controller(既存。BTP を PeerAddr 経由で扱うだけで無改造)
   ▲
crates/simple-matter-ble(std: bluer / btleplug が GATT trait を実装、examples)
```

- **`btp` コアは `exchange`/`stack` を知らない**。BTP は「バイト列(SDU)↔ セグメント列」の
  変換器であり、Matter メッセージの中身(`PacketHeader` 以降)を一切解釈しない。統合層
  (`simple-matter-ble` の pump ループ、または実機の統合タスク)が
  `Btp::recv() → MatterStack::handle_rx()` と `SendDirective → Btp::send()` を配線する。
- **rs-matter との差**: rs-matter は `Btp` に `NetworkSend`/`NetworkReceive` を実装させて
  トランスポート合成(`ChainedNetwork`)に混ぜる。本設計の `MatterStack` は sans-IO で
  `handle_rx(datagram, PeerAddr)` を直接取るため、BTP を Network trait 実装にする必要がなく、
  **統合層が 2 本の呼び出しを繋ぐだけ**で足りる(transport-exchange §2.3 の「合成の過剰汎用化を避ける」に一致)。

---

## 2. 参照実装から抽出した BTP の事実(裏取り済み)

以下は chip(`src/ble/`)と rs-matter(`transport/network/btp/`)の双方を突き合わせて確定した値。
両者は内部名が違っても **ワイヤ上のビット/バイトは一致** する。

### 2.1 GATT UUID(chip `BleUUID.h` / rs-matter `gatt.rs` 一致)

| 役割 | 16bit | 128bit(full) |
|---|---|---|
| Matter BLE Service | `0xFFF6` | `0000FFF6-0000-1000-8000-00805F9B34FB` |
| **C1**(client→server, **Write**) | — | `18EE2EF5-263D-4559-959F-4F9C429F9D11` |
| **C2**(server→client, **Indicate**) | — | `18EE2EF5-263D-4559-959F-4F9C429F9D12` |
| **C3**(additional data, **Read**) | — | `64630238-8772-45F2-B87D-748A83218F04` |

- Central は C1 に **Write**(handshake req・以降の上り BTP フラグメント)、C2 を **Subscribe** して
  下り BTP フラグメント(handshake resp を含む)を **Indication** で受ける。C3 は追加コミッショニング
  データの Read で、初期スコープでは未使用でよい。

### 2.2 handshake(Capabilities Request / Response)

- **Magic(check bytes)** = `0x65 0x6C`(ASCII "el")。handshake フラグメントは BTP ヘッダの
  Handshake ビット(`0x40`)を立て、opcode バイト `0x6C` を含む(chip `BleLayer.cpp` /
  rs-matter `session.rs`)。
- **Request(central → C1 write, 9 バイト)**: `magic(2)=65 6C` ‖ `SupportedVersions(4)`
  (4bit ニブル×8、最上位に V4=0x04)‖ `ATT_MTU(2, LE)` ‖ `WindowSize(1)`。chip の
  `kCapabilitiesRequestLength = 9`、`req.mWindowSize = BLE_MAX_RECEIVE_WINDOW_SIZE(=6)`。
- **Response(peripheral → C2 indicate, 6 バイト)**: `magic(2)` ‖ `SelectedProtocolVersion(1)=4`
  ‖ `SelectedFragmentSize(2, LE)` ‖ `WindowSize(1)`。chip の `kCapabilitiesResponseLength = 6`。
- **プロトコルバージョンは V4 のみ**(`kBleTransportProtocolVersion_V4 = 4`)。両実装とも min=max=4。
- **fragment サイズ交渉**: `fragment = clamp(max(ATT_MTU,23) - 3, 6, 244)`(GATT ATT の 3 バイト
  ヘッダを控除)。ATT_MTU 不明なら既定 20。`sMaxFragmentSize = 244`。
- **window 交渉**: `window = min(req.window, 6)`。上限 `BLE_MAX_RECEIVE_WINDOW_SIZE = 6`、下限 3。

### 2.3 BTP フレーミング(SDU セグメント)

1 フラグメント = `[flags(1)] [ack(1, ACK ビット時のみ)] [seq(1)] [msglen(2, LE, Beginning 時のみ)] [payload]`。

**フラグビット(rs-matter `packet.rs`、chip `BtpEngine.h` — ワイヤ値一致)**:

| ビット | 名称 | 意味 |
|---|---|---|
| `0x01` | Beginning / StartMessage | メッセージ先頭フラグメント。**この時のみ msglen(2, LE)を含む** |
| `0x02` | Continuing / ContinueMessage | 継続フラグメント(msglen なし) |
| `0x04` | Ending / EndMessage | 最終フラグメント(単一パケットなら Beginning と同時に立つ) |
| `0x08` | Acknowledge / FragmentAck | ack バイトを含む(piggyback または standalone) |
| `0x20` | Management | 管理フレーム |
| `0x40` | Handshake | Capabilities handshake フラグメント |

- **セグメンテーション**: 先頭に Beginning + 2 バイト総メッセージ長。全体が 1 フラグメントに
  収まれば Beginning+Ending を同時に立てる。以降は Continuing(msglen なし = 3 バイトヘッダ上限)、
  最後に Ending。受信は先頭の msglen まで貯めて全長を検証。1 メッセージは 1 Matter パケット上限。
- **ヘッダ最大 5 バイト**(flags+ack+seq+msglen)、中間/standalone-ack ヘッダは 3 バイト。

### 2.4 seq / ack / window

- **seq/ack は 8bit ローリング**(`u8`, `(n+1) & 0xff`)。受信 seq は期待値と厳密一致必須。
- **初期化**: central 側は `tx_next=1, rx_next=0, expecting_ack=true`、peripheral 側は
  `tx_next=0, rx_next=1`(handshake 応答が最初の下りになるため)。
- **window**: 未 ACK フラグメントの許容数 = 交渉済み window(既定 6)。送信ごとに remote window を
  減算、ACK 送出で local window を max に戻す。chip: `BTP_WINDOW_NO_ACK_SEND_THRESHOLD = 1`
  (remote window ≤ 1 では ack を piggyback せずには送れない)、
  `BLE_CONFIG_IMMEDIATE_ACK_WINDOW_THRESHOLD = 1`(local window ≤ 1 で即 standalone ack)。
- **ack** は data フラグメントに piggyback(ACK ビット + ack バイト)、または standalone
  (`flags=0x08, ack, seq` の 3 バイト)。

### 2.5 タイマ / keep-alive

| 定数 | chip | rs-matter | 用途 |
|---|---|---|---|
| 接続応答(handshake)タイムアウト | `BTP_CONN_RSP_TIMEOUT_MS = 15000` | — | handshake 完了待ち |
| ACK タイムアウト(= 実質 idle) | `BTP_ACK_TIMEOUT_MS = 15000` | `BTP_ACK_TIMEOUT_SECS = 15` | 未 ACK 放置でセッション切断 |
| ACK 送信遅延 | `BTP_ACK_SEND_TIMEOUT_MS = 2500` | 1s ポーリング | 非即時 ack の遅延送出 |
| 接続 idle タイムアウト | — | `BTP_CONN_IDLE_TIMEOUT_SECS = 30` | 無通信での切断 |

- **専用の周期 PING keep-alive はない**。standalone ACK が idle 中の生存確認を兼ねる
  (ACK タイムアウト内に未 ACK が解消されなければ切断)。本設計もこれに倣い、独自 PING は持たない。

### 2.6 広告 service data(0xFFF6, commissionable)

AD 構造 = `[Flags: len,0x01,0x06]` ‖ `[Service Data: len,0x16, UUID16(LE=F6 FF), payload(8)]`。
payload(chip `CHIPBleServiceData.h` / rs-matter `gatt.rs` 一致、8 バイト・LE):

| バイト | フィールド |
|---|---|
| 0 | OpCode(commissionable = `0x00`) |
| 1-2 | Discriminator(下位 12bit)+ Advertisement Version(bit15:12)。LE u16、`disc & 0x0FFF` |
| 3-4 | Vendor ID(LE) |
| 5-6 | Product ID(LE) |
| 7 | Additional Data Flag(bit0 = C3 あり、bit1 = extended announcement) |

### 2.7 MRP の扱い(BTP 上では無効 — 最重要)

**両参照実装とも「BTP は信頼トランスポートなので Matter メッセージ層の MRP を無効化」する**。

- chip: `SecureSession::AllowsMRP()` / `UnauthenticatedSession::AllowsMRP()` が
  `GetPeerAddress().GetTransportType() == Type::kUdp` を返す(BLE/TCP は false)。
  `ExchangeContext` は `reliableTransmissionRequested = session->AllowsMRP() && ...` とし、
  `SetAutoRequestAck(session->AllowsMRP())`。BLE セッションは false なので**再送テーブルに登録されない**。
- rs-matter: `Address::is_reliable()` が TCP/BTP で true。`ProtoHdr::adjust_reliability(rx, addr)` が
  reliable transport なら **R フラグを落とし ACK counter を捨てる**(送受信の両方向で呼ぶ)。
  受信時に R/ACK が乗っていたら警告を出す(仕様違反検知)。
- **結論**: BTP 上のセッションでは Matter メッセージは R/A フラグを持たず、信頼性は BTP の
  seq/ack/window に委ねる。本設計の `Session::allows_mrp()` はこの `AllowsMRP` の写像である(§3.2)。

---

## 3. PeerAddr::Ble と transport / session / exchange への影響

### 3.1 `PeerAddr::Ble(BtpConnId)` の追加

`net.rs`(既存は `PeerAddr::Udp(SocketAddr)` の 1 variant)へ最小追加する:

```rust
// transport/net.rs

/// BTP 接続を識別する不透明ハンドル。6 バイト MAC ではなく、統合層が採番する接続 index。
/// device 側は GATT 接続ごと、controller 側は接続先ごとに 1 つ割り当てる。
#[cfg(feature = "ble")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtpConnId(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddr {
    Udp(SocketAddr),
    #[cfg(feature = "ble")]
    Ble(BtpConnId),
}
```

- **なぜ MAC でなく接続 index か**: (a) `PeerAddr` は `Copy` で固定サイズが望ましく、
  BLE MAC(+random address のプライバシー変化)を持ち回るより統合層が採番する小さな
  ハンドルの方が session 照合が単純。(b) device 側は「今 GATT でつながっている central」を
  index で指せれば十分。(c) rs-matter は `BtAddr([u8;6])` を使うが、それは BTP を
  Network trait 実装にして OS の接続情報をそのまま持つため。本設計は BTP を統合層で繋ぐので
  抽象ハンドルで足りる。
- `socket_addr()` は `Ble` で `None` を返す(既存 doc コメントが想定済み)。`canonical()` は
  `Ble` を素通し(IPv4-mapped 正規化は UDP のみ)。
- `MAX_TX_PACKET_SIZE` 等は UDP 前提だが、BTP は SDU を **BTP セッション側で再組立/分割** するため、
  Matter メッセージ長の上限は UDP と同じ(1 メッセージ ≤ 1 Matter パケット)で共有できる。

### 3.2 `Session::allows_mrp()` の追加

`session.rs` の `Session` に、`peer_addr` から MRP 可否を返す関数を足す(cfg なし・常時コンパイル)。

```rust
// transport/session.rs
impl Session {
    /// このセッションで MRP(R/A フラグ・再送)を使うべきか。
    /// UDP のみ true。BTP/TCP は信頼トランスポートなので false(chip AllowsMRP の写像)。
    pub const fn allows_mrp(&self) -> bool {
        match self.peer_addr {
            PeerAddr::Udp(_) => true,
            #[cfg(feature = "ble")]
            PeerAddr::Ble(_) => false,
        }
    }
}
```

`feature = "ble"` が無効なら `PeerAddr` は Udp のみ = 常に true = 既存挙動と完全一致。
**デバイス専用 UDP ビルドのフットプリント・挙動は 1 ビットも変わらない**(controller.md §2.3 と同じ規律)。

### 3.3 MRP 無効化を「送信ファネル 1 点」で行う

既存の信頼/非信頼の選択は **`HandlerAction::Respond { reliable, .. }` を見て
`stage_response` が `send_reliable` / `send_unreliable` を呼び分ける**(`stack.rs`)。
SC/IM ハンドラは `reliable: true`(handshake・IM の各要求)を宣言するが、
**ハンドラはトランスポート種別を知らない**。よって MRP 無効化は `stack.rs` の送信ファネルで行う:

```rust
// stack.rs / controller/mod.rs の stage_response 内(概念)
let allows_mrp = self.sessions.get(ex.session).map(|s| s.allows_mrp()).unwrap_or(true);
let reliable = reliable && allows_mrp;   // BTP セッションなら常に false へ格下げ
if reliable {
    // 従来どおり send_reliable(R フラグ・再送スロット登録)
} else {
    // send_unreliable(R フラグなし・再送なし)
}
```

さらに:

- **standalone ACK の抑止**: `poll` の `PollAction::SendAck` 経路は、BTP セッションでは
  そもそも `post_recv` が ACK を武装しないようにする。`ExchangeManager::recv` が
  `mrp.post_recv(..)` を呼ぶ前に `session.allows_mrp()` を確認し、false なら
  `rx_reliable=false, rx_ack=None` を渡す(= `adjust_reliability` の写像)。これで
  BTP 上の会話は再送も standalone ACK も一切発生しない。
- **受信 R/A の無視**: 仕様準拠の相手は BTP 上で R/A を立てないが、防御的に上記の格下げで吸収する。
- **`next_deadline`**: BTP セッションは MRP deadline を生まないので、`ExchangeManager::next_deadline` は
  BTP 会話について何も返さない(MRP スロットが空のまま)。BTP 自身の ACK/idle タイマは
  `Btp::next_deadline`(§4)が別系統で管理し、統合層がそちらも min に取る(§7)。

**この 1 点集約が設計の要**: `SecureChannel` / `InteractionModel` / `ScInitiator` / `ImClient` の
どのハンドラも無改造で BTP に載る。トランスポート差は session の 1 メソッドと stack ファネルの
数行に閉じる。

### 3.4 unsecured セッションの確保(BLE 第 1 メッセージ)

UDP では `MatterStack::ensure_unsecured_session` が平文ヘッダを覗いて peer ごとの unsecured
セッションを張る。BLE も同じ経路で機能する: BTP が再組立した SDU を
`handle_rx(sdu, PeerAddr::Ble(conn), ..)` に渡せば、`ensure_unsecured_session` が
`PeerAddr::Ble(conn)` で unsecured セッションを張る。**`ensure_unsecured_session` も
`SessionManager::find_for_rx` の `peer_addr` 照合も PeerAddr 全般で動くため変更不要**
(`matches_rx` は `self.peer_addr.canonical() != peer.canonical()` で比較、Ble は素通しで一致)。

---

## 4. BTP コアモジュール(`src/btp/`、sans-IO no_std)

### 4.1 責務と非責務

- **責務**: handshake の生成/解釈、SDU のセグメント化(TX)と再組立(RX)、seq/ack/window の
  管理、ACK/idle タイマの deadline 算出。すべて **バイト列 in / バイト列 out** で、
  `now_ms: u64` 注入で時間を扱う(`embassy-time` 非依存、MRP と同じ)。
- **非責務**: BLE 無線制御・GATT I/O(→ §5 の trait)、Matter メッセージの解釈(→ 上位層)。

### 4.2 外殻 `Btp<const WINDOW: usize>`

chip/rs-matter の `BtpEngine`/`Btp` に相当。単一 BTP セッション(初期は同時 1 接続)を持つ。

```rust
// btp/mod.rs
pub struct Btp<const WINDOW: usize = 6> {
    session: Option<BtpSession<WINDOW>>,   // handshake 完了で Some。1 接続固定(初期)
    rx: RecvWindow,                         // 再組立バッファ + ack 状態
    tx: SendWindow<WINDOW>,                 // 送出中フラグメントの未 ACK 管理
    out_sdu: OutSdu,                        // 送信待ちの 1 Matter メッセージ(セグメント化元)
    in_sdu_ready: bool,                     // 1 メッセージ再組立完了フラグ
    role: BtpRole,                          // Peripheral | Central
    ack_deadline_ms: Option<u64>,
    idle_deadline_ms: Option<u64>,
}

impl<const WINDOW: usize> Btp<WINDOW> {
    pub const fn new(role: BtpRole) -> Self;

    /// C1 write(peripheral)/ C2 indication(central)で受けた 1 フラグメントを投入する。
    /// handshake・ack・データ再組立を進める。1 メッセージが揃うと in_sdu_ready = true。
    pub fn process_incoming(&mut self, frag: &[u8], mtu: Option<u16>, now_ms: u64) -> Result<()>;

    /// 送るべき 1 フラグメント(handshake resp / データセグメント / standalone ack)を
    /// `out` に書いて長さを返す。なければ Ok(0)。GATT 層はこれを C2 indicate / C1 write で送る。
    pub fn process_outgoing(&mut self, out: &mut [u8], mtu: Option<u16>, now_ms: u64) -> Result<usize>;

    /// 上位(統合層)が 1 Matter メッセージ(SDU)を送信キューに載せる。
    /// 前の out_sdu が未送出なら Err(NoSpace)(1 本ずつ)。以降 process_outgoing がセグメント化して吐く。
    pub fn send(&mut self, sdu: &[u8], now_ms: u64) -> Result<()>;

    /// 再組立済みの 1 Matter メッセージを取り出す(なければ None)。取り出すと in_sdu_ready を落とす。
    pub fn recv<'a>(&'a mut self) -> Option<&'a [u8]>;

    /// ACK / idle タイマの最も早い期限。統合層が MatterStack::next_deadline と min する。
    pub fn next_deadline(&self) -> Option<u64>;

    /// central 用: handshake を能動開始し、最初の Capabilities Request を out に書く。
    pub fn start_handshake(&mut self, out: &mut [u8], mtu: Option<u16>, now_ms: u64) -> Result<usize>;
}
```

- **role で handshake の向きを分岐**: Peripheral は req を受けて resp を出す(seq 初期値
  `tx=0, rx=1`)。Central は `start_handshake` で req を出し resp を待つ(`tx=1, rx=0`)。
- **`recv()` が返すのは完全な Matter datagram**(先頭が `PacketHeader`)。統合層はこれを
  `handle_rx` にそのまま渡すだけ。

### 4.3 handshake / framing / window(内部)

```rust
// btp/handshake.rs
pub const BTP_MAGIC: [u8; 2] = [0x65, 0x6C];
pub const BTP_VERSION: u8 = 4;
pub const BTP_MAX_FRAGMENT: usize = 244;     // sMaxFragmentSize
pub const BTP_MIN_ATT_MTU: u16 = 23;
pub const GATT_ATT_HEADER: usize = 3;
pub const BTP_MAX_WINDOW: u8 = 6;            // BLE_MAX_RECEIVE_WINDOW_SIZE
pub const BTP_ACK_TIMEOUT_MS: u64 = 15_000;
pub const BTP_IDLE_TIMEOUT_MS: u64 = 30_000;
pub const BTP_ACK_SEND_DELAY_MS: u64 = 2_500;

pub struct HandshakeReq { pub versions: u32, pub mtu: u16, pub window: u8 }   // 9 バイト
pub struct HandshakeResp { pub version: u8, pub fragment: u16, pub window: u8 } // 6 バイト

// btp/framing.rs
bitflags! { pub struct HeaderFlags: u8 {
    const BEGINNING = 0x01; const CONTINUING = 0x02; const ENDING = 0x04;
    const ACK = 0x08; const MANAGEMENT = 0x20; const HANDSHAKE = 0x40;
}}
pub struct BtpHeader { pub flags: HeaderFlags, pub ack: Option<u8>, pub seq: u8, pub msg_len: Option<u16> }
```

- **fragment サイズ**は `clamp(mtu - 3, 6, 244)`。MTU 不明時 20。resp で確定した値を
  `BtpSession.fragment` に保持し、`process_outgoing` のセグメント境界に使う。
- **window**: `SendWindow<WINDOW>` は未 ACK seq の `[oldest, newest]` 区間を保持し、
  `newest - oldest < window` の間だけ送出可。ラップアラウンドは `Wrapping<u8>` 比較。
- **ACK 方針**: local window ≤ 1 なら即 standalone ack(`ack_deadline_ms = now`)、
  それ以外は piggyback を優先し、遅延 ack は `now + 2500ms`。idle は `now + 30000ms` で更新。
- **keep-alive ACK(2026-07-07 追加)**: 純粋 standalone ACK の受信でも遅延 2.5s の
  ACK を武装して返す(window は非消費)。かつては「データを伴うフラグメントのみ
  ACK 対象」と簡略化していたが、chip の ack-received タイマは standalone ACK が
  消費した seq の ACK も待つため、**長アイドル(IM 遅延 InvokeResponse の Wi-Fi join
  待ち等)で chip 側が BTP リンクを切断する**実機不具合となった(NanoC6 実測)。
  現在は chip と同じ 2.5s 周期の ACK 応酬でリンクを維持する。

### 4.4 バッファ戦略とヒープレス性(alloc 方針の遵守)

- **RX 再組立バッファ**: 1 Matter メッセージ分の固定配列。`MAX_RX_PACKET_SIZE`(1583)を
  基準にする(rs-matter は `MAX_MESSAGE_SIZE = MAX_RX_PACKET_SIZE * 2` と余裕を取るが、
  本設計は 1 メッセージ厳密 + オーバーフローは `Error` で打ち切りから始め、計測後に調整)。
- **TX SDU バッファ**: 1 本(`MAX_TX_PACKET_SIZE = 1232`)。送出完了まで次の `send` を拒否。
- **window は const generic `WINDOW`**(既定 6)。`SendWindow<WINDOW>` の未 ACK 記録配列長に使う。
- **コアの btp は完全ヒープレス**(固定配列・`Option`・const generic)。`ARCHITECTURE.md` の
  「定常データパスはヒープ確保しない」に従う。**PC バックエンドクレート(§6)は std で自由**。
- サイジングは `Btp<WINDOW>` の 1 パラメータ + 内部固定サイズ。プロファイルは当面不要
  (BLE は同時 1 接続)。将来複数接続を許すなら `Btp<WINDOW, CONNS>` へ拡張(オープン論点 §11)。

---

## 5. GATT 抽象 trait(ESP32 移植の継ぎ目)

`btp/gatt.rs`。device / controller で役割が異なるため trait を 2 枚に分ける。**イベント駆動の
async trait** とし、`UdpSend`/`UdpReceive` の流儀(`#[allow(async_fn_in_trait)]`・`Send` 境界なし・
`&mut T` ブランケット実装)に合わせる。

### 5.1 device 側 `GattPeripheral`

要求機能(ユーザ要求): advertise 開始/停止、C1 書き込み受信、C2 subscribe 通知、C2 indicate 送信、切断。

```rust
// btp/gatt.rs
#[allow(async_fn_in_trait)]
pub trait GattPeripheral {
    /// AdvData(0xFFF6 service data)で commissionable アドバタイズを開始する。
    async fn start_advertising(&mut self, adv: &AdvData) -> Result<()>;
    async fn stop_advertising(&mut self) -> Result<()>;

    /// 次の GATT イベント(C1 write / C2 subscribe / disconnect)を 1 件待つ。
    /// data は呼び出し側(統合層)が用意するバッファに書き、種別と長さ・接続を返す。
    async fn next_event(&mut self, buf: &mut [u8]) -> Result<PeripheralEvent>;

    /// C2 indication で 1 BTP フラグメントを central へ送る(ATT_MTU 内)。
    async fn indicate(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()>;

    /// 指定接続を切断する。
    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()>;
}

pub enum PeripheralEvent {
    Connected { conn: BtpConnId, att_mtu: Option<u16> },
    C1Write   { conn: BtpConnId, len: usize },   // buf[..len] に上り BTP フラグメント
    C2Subscribed { conn: BtpConnId },            // 以降 indicate 可能
    Disconnected { conn: BtpConnId },
}
```

### 5.2 controller 側 `GattCentral`

要求機能: スキャン(Matter service data から discriminator 照合)、接続、C2 subscribe、C1 write、
indication 受信。

```rust
#[allow(async_fn_in_trait)]
pub trait GattCentral {
    /// commissionable デバイスをスキャンし、0xFFF6 service data を解析して 1 件返す。
    /// discriminator 照合は呼び出し側が ScanResult を見て行う(sans-IO 寄り)。
    async fn scan(&mut self, filter: ScanFilter) -> Result<ScanResult>;

    /// スキャンで見つけた相手へ接続し、C2 を subscribe して接続ハンドルを得る。
    async fn connect(&mut self, target: &ScanResult) -> Result<(BtpConnId, Option<u16>)>; // (conn, att_mtu)

    /// C1 write で 1 BTP フラグメント(handshake req・上りセグメント)を送る。
    async fn write_c1(&mut self, conn: BtpConnId, frag: &[u8]) -> Result<()>;

    /// C2 indication を 1 件待つ(下りセグメント)。buf[..len] に書く。
    async fn next_indication(&mut self, conn: BtpConnId, buf: &mut [u8]) -> Result<usize>;

    async fn disconnect(&mut self, conn: BtpConnId) -> Result<()>;
}

pub struct ScanFilter { pub discriminator: Option<u16>, pub vendor_product: Option<(u16, u16)> }
pub struct ScanResult { /* peer 識別子(バックエンド不透明)+ 解析済み service data */
    pub discriminator: u16, pub vendor_id: u16, pub product_id: u16, /* backend handle */ }
```

### 5.3 設計判断

- **trait を 2 枚に分ける理由**: device は advertise + C1 受信 + C2 送信、controller は scan +
  connect + C1 送信 + C2 受信で、**GATT ロール(peripheral/central)が非対称**。1 枚に無理に
  まとめると未使用メソッドが両実装に生えて移植負担が増える。btleplug は central のみ、bluer は
  両対応だが本設計では device 側に使う、という PC 事情とも整合(§6)。
- **`AdvData` はコア(`btp/gatt.rs`)に置く**(rs-matter 同様、広告バイト列生成は sans-IO)。
  バックエンドは生成済みバイト列を OS の advertise API へ渡すだけ。
- **ESP32 移植 = この 2 trait を NimBLE / esp-idf BLE で実装するのみ**。BTP 状態機械
  (`Btp<WINDOW>`)・handshake・window は無改造で共有される。これが「BLE 制御部を抽象化して
  後で移植」というユーザ要求の技術的担保。
- **rs-matter との差**: rs-matter は trait を作らず `run_peripheral` 自由関数が BlueZ を直接叩く。
  本設計は移植性のため trait 境界を明示するが、コア(`Btp`)が sans-IO である点は同一。

---

## 6. PC バックエンド構成(bluer / btleplug)

### 6.1 crate 分割 — **単一 std crate に 2 バックエンドを feature で同居**

- **重要な制約**: **btleplug は central ロールのみ対応**。デバイス側(peripheral / GATT server)を
  PC で動かすには **Linux では bluer(BlueZ)が必要**。よって PC バックエンドは
  **device 側 = bluer、controller 側 = btleplug** という分担にする(ユーザ要求の明記事項)。
- `crates/simple-matter-ble`(std)を新設し、`simple-matter` を `features=["ble"]` で依存。
  bluer / btleplug は **このクレートの feature 下でのみ** 依存に入る(コアには一切入らない。
  ARCHITECTURE の「std 依存の重い crate はコアに入れない」に従う)。

```toml
# crates/simple-matter-ble/Cargo.toml(概略)
[dependencies]
simple-matter = { path = "../simple-matter", features = ["ble"] }
bluer    = { version = "0.17", optional = true, features = ["bluetoothd"] }
btleplug = { version = "0.11", optional = true }
tokio    = { version = "1", features = ["rt", "macros", "time"] }  # PC ホストの executor

[features]
device      = ["dep:bluer"]                                   # GattPeripheral(BlueZ)
commissioner = ["dep:btleplug", "simple-matter/controller"]   # GattCentral(btleplug)
```

- **crate をさらに device/controller に割るか**: 初期は 1 crate + feature で足りる(依存は
  feature で完全分離される)。ビルド衝突や依存の重さが問題化したら 2 crate に割る(オープン論点 §11)。
- **executor**: コアは executor 非依存だが、PC バックエンドは bluer/btleplug が tokio 前提のため
  **このクレート内でのみ tokio を使う**(コアの executor 非依存性は保たれる)。

### 6.2 統合(pump)ループ

device example のループ(`ble-onoff-light.rs`)は既存 `onoff-light.rs`(UDP)の BLE 版:

```
GattPeripheral で advertise 開始
loop select {
    ev = gatt.next_event(buf):
        C1Write{conn,len}    → btp.process_incoming(&buf[..len], mtu, now);
                               while (f=btp.process_outgoing(out,mtu,now))>0 { gatt.indicate(conn,out) }
                               if let Some(sdu)=btp.recv() {
                                   if let Some(dir)=stack.handle_rx(sdu, PeerAddr::Ble(conn), now, tx) {
                                       btp.send(&tx[..dir.len], now);
                                       while (f=btp.process_outgoing(out,mtu,now))>0 { gatt.indicate(conn,out) }
                                   }
                               }
        C2Subscribed         → (handshake resp を process_outgoing → indicate)
        Disconnected{conn}   → stack.close_session(<conn の session>); btp をリセット
    _ = timer(min(stack.next_deadline, btp.next_deadline)):
        stack.poll(now,tx) を SendDirective が尽きるまで → btp.send → indicate
        btp.process_outgoing(out,..)>0 の standalone ack/idle 処理 → indicate
}
```

controller example(`ble-commissioner.rs`)は `GattCentral` で
`scan(discriminator) → connect → subscribe C2 → start_handshake(C1 write)` の後、同じ pump で
`ControllerStack` + `Commissioner`(controller.md §6)を駆動する。**`Commissioner::drive` は
無改造**(トランスポート差は §3.3 のファネルが吸収)。

---

## 7. デバイス側スタック統合(既存 MatterStack 無改造)

- **`MatterStack` / `ControllerStack` は変更不要**(§0-4, §3.3 のとおり)。BLE 対応の実体は
  (a) `PeerAddr::Ble` variant、(b) `Session::allows_mrp()`、(c) stack 送信ファネルの数行、
  (d) `btp` モジュール、(e) `GattPeripheral`/`GattCentral` trait とその PC 実装。
- **deadline の統合**: 統合層が `min(stack.next_deadline(now), btp.next_deadline())` を待って、
  期限側に応じて `stack.poll` と `btp.process_outgoing` を回す(§6.2)。BTP の ACK/idle は
  MatterStack の MRP deadline とは独立に共存する(BTP 会話では MRP deadline が生じないため衝突しない)。
- **フットプリント不変の担保**: `ble` feature は default 無効・依存クレート追加なし。
  無効時 `PeerAddr` は Udp のみ・`allows_mrp` は常に true・`btp` モジュール未コンパイルで、
  **UDP 専用デバイスビルドは 1 バイトも変わらない**。controller.md §2.3 と同じ
  「feature on/off で flash-probe セクションサイズ一致」を CI で機械検証する対象に加える。

---

## 8. コントローラ(central)側

- **btleplug で `GattCentral` を実装**(§5.2, §6)。スキャンで 0xFFF6 service data を
  `AdvData` パーサ(コア共有)で解析し、`ScanFilter.discriminator` と照合。接続後 C2 subscribe →
  `Btp::start_handshake` で Capabilities Request を C1 write → resp を C2 indication で受けて
  fragment/window 確定。
- 以降は §6.2 の pump で `ControllerStack`(controller.md §7)を駆動。`Commissioner` の
  フェーズ列(PASE → ArmFailSafe → CSR → AddTrustedRoot → AddNOC → CASE →
  CommissioningComplete)はそのまま。BLE 上では PASE/CASE の各メッセージが BTP セグメントに乗り、
  MRP は §3.3 で無効化されている。
- **CASE 以降の運用遷移**: コミッショニング完了後、デバイスは運用ネットワーク(Wi-Fi/Ethernet)へ
  移り UDP で mDNS 広告する。コントローラは BLE 接続を閉じ、operational discovery(UDP mDNS)→
  `start_case` で運用 CASE を張り直す(§9.4)。

---

## 9. E2E テスト計画

### 9.1 段階1: メモリ内ループバック GATT(無線不要・CI 可)

- `GattPeripheral` / `GattCentral` の **テスト実装**(メモリ内チャネル)を用意し、
  device 側 `Btp<Peripheral>` と controller 側 `Btp<Central>` のフラグメントを相互の
  `process_incoming` へ直接渡すループバックを組む。
- `crates/simple-matter/src/btp/tests.rs`: handshake(req/resp・version/mtu/window 交渉)・
  セグメント化と再組立(単一/複数フラグメント・msglen 検証)・seq/ack/window・
  ラップアラウンド・ACK タイムアウトを単体テスト(`now_ms` 注入で決定的)。
- **全経路結合テスト** `controller/tests.rs` の `controller_end_to_end`(controller.md §9.1)を
  **BLE 版に拡張**: 2 スタックの `SendDirective` を UDP ではなく **BTP ループバック経由** で
  相互の `handle_rx` に渡すポンプにし、`PeerAddr::Ble(conn)` で PASE→CASE→CommissioningComplete→
  On/Off Toggle を無線なしで通す。**MRP が無効(R/A フラグが立たない・再送スロットが空)である**
  ことをアサートする(BTP 側で信頼性が担保されることの確認)。CI で回す。

### 9.2 段階2: 実 BLE(bluer device ⇔ btleplug commissioner)

- `examples/ble-onoff-light.rs`(bluer, device)を 1 台で起動 → advertise。
  `examples/ble-commissioner.rs`(btleplug, commissioner)で scan → connect → commission。
- **PC 1 台の同一アダプタで可能か**: **BlueZ は同一アダプタで peripheral / central を同時に
  持てる**ため、1 台での同時起動は原理的に可能。ただし btleplug(central)と bluer(peripheral)が
  同一 hci を奪い合う実運用リスクがあるため、まずは **2 アダプタ(内蔵 + USB ドングル)** または
  **2 台の PC** を推奨構成とし、単一アダプタ同時は追試扱いにする。
- 検証: On/Off Toggle が device 側の属性に反映されること、Read で読み戻せること。BLE 特有の
  window/ack 挙動は Wireshark(nRF sniffer / btmon)で BTP フラグメントを確認。

### 9.3 段階3: chip-tool / chip サンプルとの相互運用

- 既存の connectedhomeip 相互運用実績(git log: `chip-lighting-app` を端から端まで
  commission 済み)に接続する:
  - **本デバイス(bluer)⇔ chip-tool の BLE ペアリング**: `chip-tool pairing ble-thread` /
    `ble-wifi`(運用 NW 認証情報を渡す)、または PASE-only の `code`/`ble` 経路で、本デバイスの
    0xFFF6 広告 → BTP handshake → PASE → CASE → CommissioningComplete が通ること。
  - **本コントローラ(btleplug)⇔ chip サンプルデバイス**: `chip-lighting-app` を
    `--discriminator 3840 --passcode 20202021` 等で BLE 広告させ、本 commissioner で commission。
- 突き合わせ: chip-tool でのキャプチャ(Wireshark Matter dissector + BTP dissector)と本実装の
  handshake バイト列・discriminator・PASE session parameters・Sigma1 destination-id を比較。

### 9.4 BLE 後の運用ネットワーク遷移

- **初期スコープ**: NetworkCommissioning クラスタは既存実装のまま。PC E2E では次で BLE→UDP 切替を可視化する:
  - デバイス側は BLE(BTP)と UDP を **併走** させ、コミッショニングを BLE で完了(段階1/2)。
  - CommissioningComplete 後、コントローラは BLE を切断し、**同一デバイスの UDP 運用アドレス**へ
    `start_case`(operational)で CASE を張り直し、On/Off を UDP 上で invoke する。
  - これで「BLE でコミッショニング → UDP で運用」という Matter の標準遷移を、PC 上で
    トランスポート差(`PeerAddr::Ble` → `PeerAddr::Udp`)として明示的に見せられる。
- **Wi-Fi/Thread の実 join**(NetworkCommissioning で SSID/creds を渡してデバイスが実ネットワークへ
  参加)は将来スコープ。PC では on-network(既に UDP 到達可能)前提で遷移だけを扱う。

---

## 10. 実装フェーズ分割と検証ゲート

各フェーズ完了条件に「既存 UDP テスト回帰 green」と「`ble` feature on/off で flash-probe
セクションサイズ一致(controller.md §2.3 の CI)」を含める。

| フェーズ | 範囲 | 検証ゲート |
|---|---|---|
| **P1: PeerAddr + MRP 無効化** | `PeerAddr::Ble` variant、`Session::allows_mrp()`、stack 送信ファネルの格下げ、`recv` の R/A 無視、`ble` feature 追加、CI footprint 不変ジョブ | `cargo test`(既存全 green)+ ユニット: BTP セッション相当のダミー peer で reliable→unreliable 格下げ・再送非登録・standalone ack 抑止を確認 |
| **P2: BTP コア(sans-IO)** | `btp/{framing, handshake, session, reassembly, mod}`、`Btp<WINDOW>`、`AdvData` | `btp/tests.rs`: handshake・セグメント化/再組立・seq/ack/window・ラップ・ACK タイムアウト(すべて `now_ms` 注入で決定的、無線不要) |
| **P3: GATT trait + ループバック E2E** | `GattPeripheral`/`GattCentral` trait、メモリ内テスト実装、`controller_end_to_end` の BLE 版 | 段階1(§9.1): BTP ループバックで PASE→CASE→CommissioningComplete→On/Off が通り、MRP 無効をアサート。CI 可 |
| **P4: PC バックエンド + 実 BLE** | `crates/simple-matter-ble`(bluer device / btleplug commissioner)、examples 2 本 | 段階2(§9.2): 実 BLE で bluer device ⇔ btleplug commissioner が commission 成功。Wireshark で BTP 確認 |
| **P5: chip 相互運用 + 運用遷移** | chip-tool / chip サンプルとの相互運用、BLE→UDP 遷移 example | 段階3(§9.3)+ §9.4: 双方向の相互運用成功、BLE 完了後 UDP 運用 CASE 再確立 |

推奨順序 **P1 → P2 → P3 → P4 → P5**。P1/P2 はコア(no_std)で無線なしに完結し CI で守れる。
P3 まででロジックは全証明でき、P4/P5 は実機・相互運用の担保。

---

## 11. オープンな論点

1. **RX 再組立バッファのサイズ**(§4.4)。1 メッセージ厳密(1583)で始め、chip/rs-matter が
   余裕を取る理由(連続メッセージのパイプライン)を計測後に反映するか。溢れは `Error` 打ち切りで足りるか。
2. **同時 BLE 接続数**。初期は 1 接続固定(`Btp<WINDOW>` 単一 session)。複数 central からの
   同時コミッショニングを許すなら `Btp<WINDOW, CONNS>` へ拡張し、`BtpConnId` を実 index として
   複数 session を管理する。session テーブル・広告の CM(commissioning mode)との整合を要確認。
3. **`BtpConnId` の採番と寿命**。統合層が接続ごとに index を割り当て、切断で回収する規約の明文化。
   MAC ランダム化(privacy)との独立性は保てるが、再接続時の同一性判定をどうするか。
4. **standalone ACK / idle keep-alive の駆動**。MatterStack の poll とは別系統の
   `Btp::next_deadline` を統合層が min に取る前提。単一 select ループでの取り回し(§6.2)を
   実機タスク構成でどう固めるか(executor 非依存のまま両対応)。
   **P3 での確定事項**: BTP 経由でも統合層は両スタックの `poll()` を必ず定期的に呼ぶこと。
   閉じた exchange の回収は `ExchangeManager::poll` の quiescent sweep でのみ行われ、
   BLE では MRP が無効なため poll を怠ると exchange プールが数往復で `NoSpace` 枯渇する
   (`stack/tests.rs` の BLE E2E ポンプで実証)。§6.2 の pump 実装は
   `min(stack.next_deadline, btp.next_deadline)` 待ちに加えイテレーション毎の poll を要する。
5. **単一アダプタでの peripheral/central 同時**(§9.2)。BlueZ 上での hci 競合の実挙動確認。
   CI 相当の自動実機テストは 2 アダプタ前提にするか。
6. **crate 分割の粒度**(§6.1)。bluer と btleplug を 1 crate feature 同居のままにするか、
   device/controller で 2 crate に割るか。依存の重さ・ビルド時間・feature 衝突で判断。
7. **ATT_MTU 更新イベント**。接続後に MTU が上がる(ATT_MTU exchange)ケースで fragment サイズを
   再交渉するか。chip の relaxed_mtu_nego(rs-matter)に相当する扱い。初期は handshake 時点の
   MTU 固定で始めるか。
8. **NetworkCommissioning の実 join**(§9.4)。Wi-Fi/Thread 認証情報でデバイスを実ネットワークへ
   参加させる経路は将来スコープ。BLE→実 NW→UDP の完全遷移をどの段階で実機検証するか。
9. **BTP バージョン**。V4 のみ実装(両参照実装と同じ)。将来版が出た際の versions ニブル交渉の拡張余地。

---

## 12. 参照実装との対応表

| 論点 | chip(`src/ble/`) | rs-matter(`transport/network/btp/`) | 本設計 |
|---|---|---|---|
| BTP 状態機械 | `BtpEngine` + `BLEEndPoint`(OS 統合と密) | `Btp` + `Session`/`SendWindow`/`RecvWindow`(sans-IO) | `Btp<WINDOW>` + 内部 session(sans-IO・`now_ms` 注入、§4) |
| GATT 抽象 | `BleLayer` + platform delegate | trait なし・`run_peripheral` 自由関数が BlueZ 直呼び | **`GattPeripheral`/`GattCentral` trait 2 枚**で依存性逆転(移植の継ぎ目、§5) |
| アドレス | `PeerAddress`(Type::kBle) | `Address::Btp(BtAddr[6])` | `PeerAddr::Ble(BtpConnId=u8)`(不透明ハンドル、§3.1) |
| MRP 無効化 | `Session::AllowsMRP()==kUdp` → 再送非登録 | `Address::is_reliable` + `adjust_reliability`(R/ACK 除去) | `Session::allows_mrp()` + **送信ファネル 1 点で格下げ**(§3.2/§3.3) |
| Network 統合 | `Transport::raw::BLE` | `Btp` が `NetworkSend`/`NetworkReceive` 実装 | 統合層が `Btp::recv/send` ↔ `handle_rx`/`SendDirective` を配線(sans-IO、§7) |
| PC バックエンド | platform(BlueZ/Android/…) | bluer / bluez(自由関数) | **device=bluer / controller=btleplug**、別 std crate(§6) |
| 広告 | `CHIPBleServiceData`(8B) | `AdvData`(gatt.rs) | `AdvData`(コア共有、§2.6/§4.3) |

**借りるもの**: BTP のワイヤ定数一式(magic/version/フラグ/UUID/window/タイマ/広告、§2 で裏取り)、
MRP 無効化の判断(信頼トランスポートでは R/A を落とす)、sans-IO の BTP エンジン構造(rs-matter)。
**変える点**: GATT を trait で明示して ESP32 移植の継ぎ目を作る、BTP を Network trait 実装にせず
統合層で `handle_rx` に繋ぐ(既存 sans-IO 契約を汚さない)、MRP 無効化を session 1 メソッド +
stack ファネル数行に集約(ハンドラ無改造)、PC は central=btleplug / peripheral=bluer に分担。
いずれも本プロジェクトの既存規律(sans-IO・PeerAddr 抽象・フットプリント不変・型爆発回避)からの
必然的帰結である。
