# IPv6 mDNS(運用発見)設計

status: 設計確定(2026-07-07)。chip 系スタックは IPv6 本流のため、運用 mDNS を
IPv6(ff02::fb / リンクローカル)でも提供する。コアの sans-IO responder/client は
既に AAAA を生成/解釈できる(`discovery.rs` / `discovery/client.rs`)ので、本作業は
**アドレス供給とソケット層(examples / smctl / ESP32)**が主体。

## 1. スコープと方針

- **AAAA にはリンクローカル(fe80::/10)を載せる**。グローバル v6 の有無に依存せず
  同一リンクの発見が成立する(chip-tool も lladdr を優先的に使う)。`Host.ipv6` は
  従来どおり単一 `Option<Ipv6Addr>` のまま(link-local 1 本で E2E 要件を満たす。
  複数 AAAA への拡張は将来)。
- responder はソケット非依存(sans-IO)なので**無変更**。クエリが届いたソケット
  (v4/v6)へ応答を返すのはアプリ層の責務。
- **デバイスの Matter UDP(5540)はデュアルスタック化**(`Domain::IPV6` +
  `set_only_v6(false)`)。AAAA で解決したコントローラが v6 で CASE を張るため。
  セッション照合は既存の `canonical_socket_addr`(::ffff: 正規化)で吸収済み。

## 2. PC examples(onoff-light / ble-onoff-light)

- `discover_local_ipv6()` を追加: 既存 `discover_local_ipv4()` と同様に
  「default route の iface」を特定し、その **リンクローカル v6 と scope_id
  (if_index)** を得る。Linux は `/proc/net/if_inet6` を parse(iface 名は
  v4 connect トリックで得たアドレスから `getifaddrs` 相当…は std に無いので、
  `/proc/net/if_inet6` の fe80 行と `/sys/class/net/<if>/ifindex` を使う。
  実装簡素化のため「fe80 を持つ最初の非 lo iface」で可、乖離時は理由明記)。
- mDNS ソケットを 2 本に: 既存 v4(5353 共有 + join 224.0.0.251)に加え、
  **v6 ソケット**(`Domain::IPV6`、`set_only_v6(true)`、`SO_REUSEADDR`+
  (unix)`SO_REUSEPORT`、bind `[::]:5353`、`join_multicast_v6(ff02::fb, scope_id)`)。
  受信ループは両ソケットを poll し、**届いたソケット側へ**応答(QU はソース宛
  ユニキャスト、QM はマルチキャスト。v6 のマルチキャスト送信先は
  `[ff02::fb%scope]:5353`)。
- `Host::from_mac(mac, Some(fe80_lladdr), Some(v4))` で AAAA を広告。
- 定期 announce も両ファミリへ送る。

## 3. smctl resolver(+commissioner example は同型)

- `resolve_operational` / `browse_commissionable` に v6 クエリソケットを追加
  (unix: 5353 共有 bind + join。Windows: 既存 v4 と同じ QU +
  `set_multicast_if_v6(if_index)` 方式)。v4/v6 の応答を同一の
  `MdnsClient::parse_*` に集約(client はファミリ非依存)。
- **アドレス選好は現状維持(IPv4 優先)**: 既定経路の互換性を守る。v6 のみ
  広告のデバイスは既存 fallback(`or_else(first)`)で v6 を使う。
  `--prefer-ipv6`(または V1 の `--at` に v6 リテラル)で明示切替可能にはしない
  (YAGNI。バックログ 4 の `--at` が v6 リテラルを受ければ十分)。
- **scope_id の扱い**: fe80 宛に connect する際、`SocketAddrV6::scope_id == 0`
  なら「クエリを受けた iface(= join に使った if_index)」を補完する。
  nodes.tlv は 16B アドレスのみで scope_id を持たない(スキーマ不変)ため、
  再解決/再接続時も同じ規則で補完する。
- smctl の運用 UDP ソケットは既にデュアルスタック(controller 側)なので不変。

## 4. ESP32(e5-light)

- embassy-net 0.9 / smoltcp 0.13 は `proto-ipv6` + MLD(`join_multicast_group` の
  v6 group)をサポート → **e5-light も IPv6 対応する**。
  - `embassy-net` features に `proto-ipv6` を追加。
  - stack config に link-local を設定(smoltcp は EUI-64/静的 fe80 を
    `ConfigV6::Static` 相当で与える。SLAAC は不要 — link-local のみで良い)。
  - `net.rs` の「IPv4-mapped のみ」ガードを解除し、実 v6 endpoint の
    send/recv と `join(ff02::fb)` を通す。
  - `Host::from_mac(mac, Some(fe80), Some(v4))` で AAAA 広告。
- RAM/flash 増分は E6 比で計測して README の表に追記。smoltcp の制約で
  不成立の場合は本節に理由を記録してスキップ可(タスク合意済み)。

## 5. 検証ゲート

- 単体: 既存 responder/client テストは AAAA 済み。追加は
  「Host が v6 のみでも announce/query 応答が正しい」程度(必要なら)。
- 実機 E2E:
  1. PC onoff-light + chip-tool `pairing onnetwork`: chip-tool のログで
     **IPv6(fe80)へ CASE 接続**していることを確認(`[fe80::…]:5540`)。
     toggle まで。
  2. smctl: v6 のみ広告デバイス(または v6 応答)を resolve → toggle。
  3. NanoC6 e5-light + chip-tool `pairing ble-wifi`(実 AP): 運用解決が
     v6/v4 いずれでも完走すること(AAAA 広告後のリグレッション確認)。

## 6. 実装メモ(2026-07-07、実機で確定)

- **iface 選定は「最初の fe80」では不可**: 本開発機のように仮想 IF
  (tailscale/docker/incus)が多数ある環境では、`/proc/net/if_inet6` の先頭 fe80 が
  LAN に届かないアドレスになる(W3 の IF 未指定問題と同根)。実装は
  `/proc/net/route` の **IPv4 既定経路の iface** の fe80 を採り、無い場合のみ
  先頭 fe80 にフォールバックする。
- **smctl の fe80 scope 補完**: `pairing address` の明示 fe80 リテラル・nodes.tlv
  復元(16B のみ、scope 無し)・mDNS 解決結果の 3 経路すべてで scope_id==0 の
  fe80 に既定 scope を補完する。
- **BTP keep-alive ACK が前提**(ble-btp.md §4.3): NanoC6 の E2E で、ConnectNetwork
  遅延応答の join 待ち中に chip-tool が BTP を切断する事象の根本原因は BTP の
  standalone ACK 省略だった。IPv6 とは独立の修正だが本作業で顕在化・解消。
- **ESP32 ヒープ**: proto-ipv6 追加後に BLE+coex の大型応答で ATT エラーが再発、
  ヒープ 112→144KiB で解消(ports/esp32/README 参照)。
- E2E 実測: chip-tool は AAAA(fe80)を優先し、PC onoff-light / NanoC6 e5-light の
  両方で `UDP:[fe80::…]:5540` に CASE を確立(toggle 成功)。smctl は fe80 リテラル
  への pairing / キャッシュ fe80 での再接続 / v6 ソケットでの mDNS 送受を確認。
