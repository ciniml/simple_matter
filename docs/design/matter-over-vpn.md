# Matter over VPN(tailscale / WireGuard)設計検討

status: draft(2026-07-07)/ 本書は検討 doc のみ。コード変更は含まない
(OpenCommissioningWindow 実装が並行中のため)。

## 0. 目的とスコープ

Matter の運用・コミッショニングを tailscale / WireGuard 等の L3 VPN 越しに行う
場合の問題点を分解し、解決アプローチを比較して本プロジェクトの推奨案と
フェーズ計画を示す。

前提となるユーザ仮説: 「Matter は UDP なので、Thread Border Router のように
DNS-SD マルチキャストを中継するブローカーがあれば理論上可能なはず」。
本書の結論はこの仮説を**概ね支持**する — ただし「マルチキャストの中継」よりも
「**ユニキャスト mDNS(QU)の直叩き/仲介**」の方が本スタックには適合が良い
(§4 案 C)。理由は、W3 で実装済みの QU クエリ+ユニキャスト応答パスが
そのまま VPN 上のユニキャスト経路に乗るため。

## 1. 問題の分解

Matter over IP は 2 つの独立したプレーンから成る。VPN で壊れるのは主に (a) 発見。

### (a) 発見(mDNS/DNS-SD)はリンクローカルマルチキャストで、L3 VPN を越えない

- mDNS は `224.0.0.251` / `ff02::fb` 宛、TTL=1(RFC 6762)。ルーテッド VPN は
  そもそもマルチキャストを転送しない。
- **WireGuard**: cryptokey routing の `allowed-ips` にマルチキャスト範囲
  (`224.0.0.0/4`, `ff00::/8`)を持つピアが存在しないため、送信時点でカーネルが
  **errno 126 `ENOKEY`(Required key not available)** で弾く(§2 で実測)。
  I/F フラグも `POINTOPOINT,NOARP` で `MULTICAST` なし。
- **tailscale**: `tailscale0` は `MULTICAST` フラグを持ち **socket レベルの送信は
  成功する**が、tailscaled はユニキャスト(各ピア /32・/128 ルート)しか運ばず、
  マルチキャストは対向に配送されない(tailscale の公知仕様。本開発機では対向
  ピアが全てオフラインのため E2E 未検証 — 推論として区別する)。

### (b) 運用ユニキャスト UDP(5540)は素通しのはず

- PASE/CASE/IM は全て発見後のユニキャスト UDP。VPN はまさにこれを運ぶ。
- socket レベルの送信は wg_test / tailscale0 とも成功を実測(§2)。
- 裏付けとなる既存実績: W3/W4(`docs/design/port-windows-commissioner.md`
  §3.2b, フェーズ表)では、mDNS が死んでいる環境でも **IP 直指定の UDP フル
  コミッショニング(PASE→AddNOC→CASE→Toggle)が完走**している。VPN も
  「mDNS だけ死んでいてユニキャストは通る」同型の環境であり、同じ結論が
  期待できる(要 E2E 検証、§6 検証項目)。
- 要検証観点: NAT 越え(tailscale は自前で解決)、MTU(§1(f))、
  双方向到達性(デバイス→コントローラの MRP ack / subscription report)。

### (c) MRP タイムアウト / セッションアイドルへの RTT 影響

本スタックの既定値(`crates/simple-matter/src/exchange/mrp.rs`):

| 定数 | 値 |
|---|---|
| `MRP_BASE_RETRY_INTERVAL_MS` / SAI 既定 | 300 ms |
| `MRP_DEFAULT_IDLE_INTERVAL_MS`(SII) | 5000 ms |
| `MRP_DEFAULT_ACTIVE_THRESHOLD_MS` | 4000 ms |
| `MRP_MAX_TRANSMISSIONS` | 10 |
| backoff: base 1.6×, margin 1.1×, jitter +0〜25% | — |

- アクティブ時の初回再送は約 300×1.1 = **330 ms**。tailscale が direct path なら
  RTT は LAN+α(数〜数十 ms)で問題ないが、**DERP リレー経由に落ちると RTT
  100〜300 ms+** になり得て、330 ms を食い潰し**偽再送**が増える(切断はしない:
  10 回再送 × 指数バックオフで総計 ~20 秒程度の猶予がある)。
- direct↔DERP の切替は動的なので RTT が突然変動する点が tailscale 特有。
- 対策の口は既にある: mDNS TXT の `SII`/`SAI` を
  `discovery.rs`(`Commissionable.sii/sai`, `Operational.sii/sai`, 既定 `None`)で
  広告できる。VPN 運用を想定するデバイスは **SAI ≥ 500 ms** 程度を広告する、
  もしくはコントローラ側 `MrpConfig` を設定可能にするのが低コストな緩和策。

### (d) 広告アドレス問題 — デバイスは自分の LAN アドレスを広告する

- `examples/onoff-light.rs` は `discover_local_ipv4()`(`connect(8.8.8.8:53)` で
  既定経路の自 IPv4 を得る)で **LAN アドレス 1 個だけ**を
  `Host::from_mac(mac, None, Some(ipv4))` に入れて A レコードで広告する。
- 仮に mDNS 応答が VPN を越えて届いたとしても、**中身の A/AAAA が
  192.168.x.x では VPN 対向から到達できない**。tailscale の 100.x(CGNAT 域)
  アドレスは mDNS 広告には載らない。
- つまり発見の解決策は「パケットを届ける」だけでは足りず、
  **(i) アドレス書き換え、(ii) 応答の送信元アドレスを信じる、
  (iii) LAN サブネットを VPN でルーティングする(tailscale subnet router)**の
  いずれかとセットで考える必要がある。
- 付随論点: `smctl` の `nodes.tlv`(`crates/smctl/src/state/nodes.rs`)は素の
  `SocketAddr` を保持し scope_id を持たないため、IPv6 リンクローカルはそもそも
  キャッシュ経由で再利用できない。VPN アドレス(100.x / 10.x / fd7a::)は
  グローバルスコープ扱いなのでこの制約に当たらない — VPN 運用ではむしろ
  キャッシュとの相性が良い。

### (e) WireGuard I/F はマルチキャスト非対応

(a) の再掲だが独立の含意がある: mDNS リフレクタ類(案 A)を「VPN I/F に
ぶら下げる」構成は WireGuard では**送信自体が ENOKEY で失敗**するため成立
しない。リフレクタ間を結ぶ経路は必ずユニキャストトンネルになる。

### (f) MTU(実測で判明した追加論点)

- Matter の UDP ペイロード上限は 1280 バイト。`tailscale0` の MTU は **1280**
  (IPv4 なら IP+UDP ヘッダ 28 バイトはみ出す)。実測では DF 付き 1280 B 送信が
  **EMSGSIZE で失敗**、DF なしはカーネルが IP フラグメントして送信成功。
  wg_test(MTU 1420)は素通し。
- 通常の UDP 送信(DF なし)ならフラグメントで動くが、PMTUD 前提の実装や
  フラグメント落ちには注意。フルサイズに近いメッセージ(CASE の証明書
  チェーン等)が境界ケース。設計上は「1280 MTU の I/F ではフラグメント発生を
  許容する」と明記しておく。

## 2. 本開発機での実観測(2026-07-07)

環境: `enp5s0` 192.168.2.14(LAN)、`tailscale0` 100.78.36.24/32(MTU 1280、
`MULTICAST` フラグあり)、`wg_test` 10.0.0.1/24(MTU 1420、`POINTOPOINT,NOARP`、
`MULTICAST` なし)。tailscale の対向ピアは全てオフラインのため、**E2E(対向で
受かるか)は未検証**。以下は socket レベルの送信可否の実測。

| 実験 | 結果 |
|---|---|
| IPv4 mDNS マルチキャスト送信(224.0.0.251:5353)@ wg_test | **失敗 errno=126 ENOKEY(Required key not available)** |
| 同 @ tailscale0 | 送信 OK(ただし tailnet 上では配送されない — 推論) |
| 同 @ enp5s0(LAN) | 送信 OK |
| IPv6 マルチキャスト(ff02::fb)@ wg_test | 失敗 errno=99(IPv6 アドレスなし) |
| 同 @ tailscale0 | 送信 OK(配送は同上の推論) |
| ユニキャスト UDP 5540 送信 @ wg_test / tailscale0 | 両方 OK |
| 1280 B ペイロード + DF @ tailscale0(MTU1280) | **失敗 EMSGSIZE**(DF なしはフラグメントで OK) |
| 1280 B ペイロード + DF @ wg_test(MTU1420) | OK |

過去ログとの突合: chip-tool 系アプリのログ
(scratchpad `chip-app*.log`)に
`Attempt to mDNS broadcast failed on wg_test: src/inet/UDPEndPointImplSockets.cpp:417: OS Error 0x0200007E: Required key not available`
が全ログ計 100 回超記録されており、上の wg_test 実測(errno 126)と**同一原因**
(cryptokey routing にマルチキャスト宛のピアが無い)で説明できる。chip の
minimal mDNS は全 I/F に broadcast しようとして WireGuard I/F で必ずこれを踏む。

## 3. 本スタックの資産(chip 系に対する優位点)

- **sans-IO mDNS**: `MdnsResponder`(`crates/simple-matter/src/discovery.rs`)と
  `MdnsClient`(`discovery/client.rs`)はソケットを持たず、送受信先の決定は
  呼び出し側の自由。トランスポートを VPN ユニキャストに差し替えるのが構造的に
  容易。
- **QU(unicast-response)対称サポート(W3 実装済み)**:
  - querier: `build_browse_commissionable / build_browse_discriminator /
    build_resolve_operational` は全て `unicast_response: bool`(QU ビット)を取る。
  - responder: `query_wants_unicast()` で QU を検出し、example
    (`onoff-light.rs` ほか)は**クエリ送信元へユニキャスト応答**する。
  - つまり「エフェメラルポートから QU クエリを**ユニキャストで** デバイスの
    5353 へ直接送る → デバイスが送信元へユニキャストで返す」というパスは、
    デバイス側は**追加実装ゼロ**で成立する見込み(RFC 6762 §5.5 の
    direct unicast query に相当。応答は既に src 宛なので QU/非 QU どちらでも
    ユニキャストで返る)。
- **直指定パス**: `smctl pairing address <node> <passcode> <ip> [port]`
  (`Target::Addr`)が既にあり、mDNS なしのコミッショニングが可能。
- **アドレス帳 + 再解決**: `nodes.tlv` が `last_addr` をキャッシュし、CASE は
  (1) キャッシュへ dial → (2) 失敗時のみ `resolve_operational` で mDNS 再解決
  (`crates/smctl/src/ops.rs`)。resumption 素材は `resume/<node>.tlv` に分離済み。

## 4. 解決アプローチの比較

### 案 A: mDNS リフレクタ / プロキシ(avahi `enable-reflector`, mdns-repeater)

VPN 両端のホストでマルチキャストを別 I/F へ再送する既製ソフトを使う。

- WireGuard I/F へは送信不可(ENOKEY、§2)なので、リフレクタ同士をユニキャスト
  で結ぶ形にしかならない(= 実質ブローカー構成)。avahi の reflector は同一
  ホストの複数 I/F 間中継が前提で、VPN 越えには追加の仕掛けが要る。
- **アドレス書き換え不能**が致命的: 広告に載る A/AAAA は LAN ローカルのまま。
  tailscale **subnet router** で対向 LAN サブネットを広告すればアドレス到達性は
  解決するが、それなら発見だけの問題に戻り、案 C/D の方が軽い。
- 無差別に全サービスを反射するためノイズ・ループ・キャッシュ汚染の運用リスク。

### 案 B: DNS-SD over unicast DNS(RFC 6763)

Matter 仕様は運用発見に unicast DNS 経由の DNS-SD を許容している(Thread
Border Router の SRP + `default.service.arpa` 相当)。サイト側に DNS サーバを
置き、デバイスの SRV/TXT/AAAA を登録、コントローラは tailscale の
**MagicDNS split DNS** で当該ゾーンをサイト DNS に向ける。

- 仕様適合性は最も高く、スケールもする。運用発見(`_matter._tcp`)向き。
- ただし登録経路(SRP 相当のデーモンか、mDNS→DNS ゲートウェイ)と DNS サーバ
  という**インフラが 2 つ**必要。コミッショナブル発見(CM フラグの動的変化)
  との相性も悪い。本プロジェクトの規模には過剰。

### 案 C: アプリ層ブローカー / ユニキャスト mDNS(ユーザ仮説の精緻化)

我々の sans-IO MdnsClient/Responder をそのまま使い、mDNS パケットを VPN 上の
ユニキャストで運ぶ。2 段階に分けられる:

- **C1: 直叩き(リレー不要)** — コントローラが「候補ホストの VPN アドレス」を
  知っている前提で、QU クエリを `<vpn-ip>:5353` へ**ユニキャスト送信**する。
  デバイスは W3 実装により送信元へユニキャスト応答する。応答中の A レコード
  (LAN アドレス)は**信用せず捨て**、**クエリを送った宛先 IP** + 応答中の
  SRV port / TXT(discriminator, CM, SII/SAI)を採用する — これでアドレス
  書き換え問題を回避できる。変更は smctl の `runner/mdns.rs` にユニキャスト
  送信先オプションを足すだけで、**コア変更ゼロ**。
  適用範囲: commissionable / operational 両方。制約: デバイス自身が VPN
  アドレスを持つ(デバイスで tailscale が動く)か、subnet router で LAN
  アドレスに到達できること。デバイスの 5353 は `0.0.0.0` bind 済みなので
  VPN からのユニキャスト受信は可能(要 E2E 検証)。
- **C2: サイトリレー(真の発見が要る場合)** — 対向 LAN に候補列挙まで任せる
  軽量デーモン(新 bin、`smctl` サブコマンドでも可)。リレーはサイト側で通常の
  マルチキャスト browse を行い、結果(instance, SRV, TXT, 実アドレス)を VPN
  ユニキャストで返す。アドレスは「リレーから見た到達可能アドレス」+
  subnet router、または C1 同様リレー経由で QU 直叩きに切り替える。
  mDNS ワイヤフォーマットをそのまま UDP ユニキャストで運べば、コントローラ側
  は既存の `parse_commissionable / parse_operational` が無改造で使える。

### 案 D: アドレス帳直指定 + resumption で発見自体を省略

- コミッショニング: `pairing address <node> <passcode> <vpn-ip>`(**実装済み**)。
- 運用: `nodes.tlv` の `last_addr` に VPN アドレスがキャッシュされ、CASE は
  まずキャッシュへ dial する(**実装済み**)。tailscale アドレスはノードに
  対して安定なので、キャッシュが陳腐化しにくく好相性。resumption 素材も
  `resume/<node>.tlv` に保持済みで、再接続は resumption で軽くなる。
- 弱点: キャッシュミス時のフォールバックが mDNS 再解決(VPN では失敗)しか
  ない。ここに C1 を繋ぐと欠点が消える。

### 比較表

| 案 | 適用範囲 | 仕様適合 | アドレス問題 | 追加インフラ | 実装コスト | 判定 |
|---|---|---|---|---|---|---|
| A リフレクタ | 両方 | mDNS としては適合 | **未解決**(subnet router 必須) | 両端デーモン | 小(既製)〜中 | ノイズ多・書換不能で非推奨 |
| B unicast DNS-SD | 主に運用 | **最高**(TBR 同型) | DNS 登録時に解決 | DNS サーバ+登録経路 | 大 | 将来案。今は過剰 |
| C1 QU 直叩き | 両方 | RFC 6762 直ユニキャストクエリの範囲 | クエリ宛先 IP を採用して回避 | なし | **小**(smctl のみ) | **推奨** |
| C2 サイトリレー | 両方(列挙可) | プロキシとして許容範囲 | リレーが解決/併用 | 対向に 1 デーモン | 中 | C1 の次の段 |
| D 直指定+キャッシュ | 両方(発見なし) | 適合(発見は必須でない) | ユーザが VPN IP を指定 | なし | **ゼロ**(実装済み) | **即日可能な運用解** |

## 5. 推奨とフェーズ計画

推奨: **D(現状のまま運用可)→ C1(smctl resolver 拡張、小)→ C2(リレー bin、
必要になったら)**。B は本プロジェクトの規模では見送り、A は不採用。

| フェーズ | 内容 | 変更箇所 | 工数感 |
|---|---|---|---|
| **V0: 運用解(コード変更なし)** | ランブック整備: `pairing address <node> <pass> <vpn-ip>` でコミッショニング、以後は `nodes.tlv` キャッシュ+resumption で運用。tailscale なら subnet router か デバイス側 tailscale 常駐を前提化。E2E 検証(§6)込み | docs のみ | 0.5 日 |
| **V1: C1 = ユニキャスト mDNS 直叩き** | `runner/mdns.rs` に「指定ホスト群へ QU クエリをユニキャスト送信し、応答の A/AAAA でなく**宛先 IP を採用**する」解決モードを追加。CLI: `discover commissionable --at <ip>[,<ip>…]` / `pairing onnetwork --at <ip>` / CASE 再解決フォールバックに `nodes.tlv` の `last_addr` ホストへの QU 直叩きを挿入。デバイス側変更なし | `crates/smctl`(runner/mdns.rs, cli.rs, ops.rs) | 1〜1.5 日 |
| **V2: MRP チューニング口** | コントローラ `MrpConfig` を CLI/env で可変に。VPN 運用ガイドとして SAI ≥ 500 ms を広告する example オプション(TXT `SII`/`SAI` は広告実装済み・値が `None` なだけ) | smctl + examples | 0.5 日 |
| **V3: C2 = サイトリレー(必要時)** | `smctl mdns-proxy`(または新 bin): サイト側でマルチキャスト browse、mDNS ワイヤフォーマットのまま VPN ユニキャストで往復。コントローラは `--at <relay-ip>` の C1 経路をそのまま流用 | 新サブコマンド/新 bin | 2〜3 日 |
| (見送り) B unicast DNS-SD | MagicDNS split DNS + サイト DNS + 登録デーモン | — | 大 |

## 6. E2E 検証項目(実 VPN 対向が用意できたとき)

1. **(b) の裏取り**: onoff-light を LAN 側で起動し、VPN 対向から
   `smctl pairing address` → `onoff toggle` が完走するか(wg / tailscale 両方、
   tailscale は direct と DERP 強制の両方)。
2. **C1 の前提**: VPN 対向から `<device-ip>:5353` への QU ユニキャストクエリに
   デバイスがユニキャスト応答を返すか(`SM_MDNS_TRACE=1` で確認。W3 の
   socket レベル検証はローカルのみのため)。
3. **MTU**: DERP 経由・MTU1280 で 1200 B 級メッセージ(CASE Sigma2 等)が
   フラグメントを含めて通るか。
4. **MRP**: DERP 経由の RTT で偽再送の頻度、`MrpConfig` 調整の効果。
5. tailscale の direct↔DERP 切替中にセッションが生き残るか(送信元アドレスは
   100.x のまま不変のはずなので、セッション同定は保たれる — 推論)。

## 7. 参照

- 実測ログ・手順: 本書 §2(2026-07-07、開発機。socket レベルのみ)
- W3 QU モード実装記録: `docs/design/port-windows-commissioner.md` §3.0–§3.2c
- mDNS コア: `crates/simple-matter/src/discovery.rs`, `discovery/client.rs`
- smctl 発見/アドレス帳: `crates/smctl/src/runner/mdns.rs`,
  `crates/smctl/src/state/nodes.rs`, `crates/smctl/src/ops.rs`
- MRP 定数: `crates/simple-matter/src/exchange/mrp.rs`
- chip 系の wg_test 失敗ログ: scratchpad `chip-app*.log`
  (`OS Error 0x0200007E: Required key not available`)
