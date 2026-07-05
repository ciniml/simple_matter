# コミッショナーの Windows 対応 — 調査と移植設計

対象: `crates/simple-matter-ble` の commissioner 側(`BtleplugCentral` + `ble-commissioner`)
および UDP コミッショナ(`examples/commissioner.rs` 相当の機能)を **Windows 10/11 ネイティブ**で
動かすための調査。本書は調査・設計のみでコード変更を含まない。

前提となる現状(2026-07-05 時点、Linux 実機で実証済み):

- BLE central は btleplug 0.11(Linux では BlueZ バックエンド)。`GattCentral` trait は
  `connect`(subscribe しない)→ `write_c1`(handshake)→ `subscribe_c2` → `next_indication`
  の順で呼ぶ契約(chip 互換の確立順序、ble-btp.md 参照)。
- chip-tool / chip-lighting-app との BTP ワイヤ互換は実証済み。ATT_MTU は btleplug が
  公開しないため fragment=20 で動く(遅いが正しい)。
- UDP 側(運用 CASE / mDNS ブラウズ)は sans-IO(`MdnsClient` はバイト列 in/out)で、
  ソケットは examples が `std::net::UdpSocket` + socket2 で直接扱う。
  **mDNS は現状 IPv4(224.0.0.251)のみ**を実利用。
- コア(`simple-matter`)は no_std・OS 非依存。`bluer`(Linux 専用)は
  `#[cfg(all(feature = "device", target_os = "linux"))]` で隔離済みのため、
  **`commissioner` feature のみなら Windows でビルド可能な構成が既にできている**。

---

## 0. サマリ

1. **コアと crate 構成は既に Windows-ready**。`simple-matter` は OS 非依存、
   `simple-matter-ble --features commissioner`(btleplug + tokio + futures)は
   Windows 対応 crate のみで構成される。bluer は cfg で除外済み。
2. **btleplug は WinRT バックエンドで central ロールをサポート**する
   (`BluetoothLEAdvertisementWatcher` でスキャン、GATT クライアント操作)。
   本プロジェクトが使う操作(scan → connect → write with response → subscribe indicate →
   notification stream)はすべて btleplug の公開 API 内で、プラットフォーム分岐は不要。
3. **最大の未知数は 3 点**(§4): (a) スキャン結果に 0xFFF6 の **service data** が
   載るか(WinRT の advertisement 解析)、(b) **subscribe 前の write** が WinRT で
   通るか(chip 互換の確立順序の要)、(c) mDNS の **5353 ポートを Windows 内蔵 mDNS
   (svchost)と共有**できるか。いずれも設計は回避策込みで用意する(要実機確認)。
4. **mDNS はフォールバック戦略を持つ**: 5353 共有 bind が不安定な場合、
   エフェメラルポートから QU(unicast-response)クエリを 224.0.0.251:5353 へ送り、
   応答をユニキャストで受ける legacy resolver モードを `MdnsClient` の呼び出し側
   (example)に用意する(sans-IO 側は無改造)。
5. 検証は **ネイティブ Windows + USB BT ドングル**で行う(WSL2 は BLE 不可。
   usbipd-win で USB ドングルを WSL2 に渡す手はあるが、カーネル再構築が要り本筋にしない)。
   CI は `x86_64-pc-windows-msvc` の **ビルドチェックのみ**を先行導入する。

---

## 1. 現状の依存関係と Windows 適合性

| 依存 | 用途 | Windows 対応 | 備考 |
|---|---|---|---|
| btleplug 0.11 | GATT central | ○(WinRT) | central 専用。要検証項目は §4 |
| tokio(rt-multi-thread, macros, time, sync) | BLE crate の executor | ○ | |
| futures 0.3 | notification stream | ○ | |
| uuid 1 | UUID 型 | ○ | |
| bluer 0.17 | GATT peripheral | ×(Linux 専用) | cfg 隔離済み。Windows では `device` feature 不可 |
| socket2 0.5 | mDNS/UDP ソケット | ○ | ただし SO_REUSEPORT は Linux 専用(§3) |
| simple-matter(コア) | プロトコル | ○(no_std) | OS API 非依存 |

`ble-commissioner` example は BLE のみで完結し(現状は CASE も BLE 上で試みる)、
UDP を使わない。よって **BLE コミッショナの最小 Windows 移植は「btleplug が動けば動く」**。
一方、chip デバイス相手のフルパスに必要な「BLE→UDP 運用遷移」(AddNOC 後に運用 mDNS →
CASE over UDP)を実装する際は §3 の mDNS/UDP 論点が効いてくる。

## 2. BLE(btleplug / WinRT)の論点

### 2.1 スキャンと service data(未確認・最重要)

- 我々のスキャンは「0xFFF6 の **service data** を読み `AdvData::parse_service_data` で
  discriminator を照合」する(`BtleplugCentral::scan`)。
- WinRT の `BluetoothLEAdvertisementReceivedEventArgs` は advertisement の
  DataSections を公開しており、btleplug の WinRT バックエンドはここから
  `PeripheralProperties::service_data` を埋める実装になっている。
  **原理的には取れるはずだが、(a) パッシブ/アクティブスキャンの別、(b) scan response
  との合成、(c) 16bit UUID の service data(AD type 0x16)の解釈、は実機確認が必要**。
- 対応策(取れなかった場合): `ScanFilter` を UUID フィルタに緩め、接続後に C3
  (additional data, Read)ではなく handshake まで進めてから discriminator 照合……は
  仕様上正しくないため採らない。btleplug の `manufacturer_data`/`services` は取れる
  ことが多いので、**最悪 btleplug へのパッチ(service data 対応)を上流に出す**ことも
  視野に入れる。実機確認を移植フェーズ W1 の最初のゲートにする(§5)。

### 2.2 確立順序(write → subscribe)(未確認)

- chip 互換のため `connect`(subscribe なし)→ handshake の `write_c1` → `subscribe_c2`
  の順で呼ぶ(GattCentral の契約)。WinRT では write と CCCD 書き込み
  (`WriteClientCharacteristicConfigurationDescriptorAsync`)に順序制約はないはずだが、
  **サービス探索キャッシュとの絡みで最初の write が失敗する報告が WinRT には散見される**。
  リトライ(1 回、100ms backoff)を `write_c1` の Windows 実装ノートとして用意する。
- BlueZ で踏んだ「亡霊 GATT キャッシュ」問題は Windows にも等価物がある
  (デバイスのペアリング済みキャッシュ)。検証手順に「設定 → Bluetooth → デバイス削除」を含める。

### 2.3 ATT_MTU / bonding / その他

- btleplug は MTU を公開しない → Linux 同様 fragment=20 で動く(機能上問題なし、性能のみ)。
  WinRT 自体は `GattSession.MaxPduSize` を持つので、将来 btleplug が公開すれば自動で改善する。
  **fragment=20 で chip-tool 相当のフロー(AddNOC 含む)が Linux 実機で通ることは実証済み**なので、
  Windows でも機能リスクにはならない。
- Matter の C1/C2 は暗号化・認証を要求しない characteristic なので、**WinRT が自動で
  ペアリング(bonding)ダイアログを出すことはないはず**(要実機確認)。もし
  `Insufficient Authentication` が返る場合は相手デバイス側の設定問題。
- `BtpConnId` 採番・`ScanResult<PeerHandle>`(associated type)は btleplug の
  `PeripheralId` をそのまま使うため、Windows でも型レベルの変更は不要。

## 3. UDP / mDNS の論点(BLE→UDP 遷移・運用 CASE 用)

### 3.1 ソケットオプション

- 現 examples の `open_mdns_socket()` は socket2 で **SO_REUSEADDR** → 5353 bind →
  `join_multicast_v4`。Linux では avahi と共存するために SO_REUSEPORT 相当の挙動を
  期待しているが、**Windows に SO_REUSEPORT はない**。Windows の SO_REUSEADDR は
  Linux の REUSEPORT に近い「完全共有」を許す(セキュリティ的にはむしろ緩い)ため、
  bind 自体は通る見込み。
- ただし **マルチキャスト受信の配送**は「同一グループに join した全ソケット」に届くのが
  原則だが、Windows 内蔵 mDNS(Dnscache が 5353 を掴む、Win10 1703+)や Bonjour
  (iTunes 等が入れる mDNSResponder)との共存時の実挙動は環境依存(未確認)。

### 3.2 フォールバック: QU クエリ + ユニキャスト応答

- `MdnsClient` は sans-IO なので、ソケット戦略は example 側で選べる。5353 共有が
  不安定な場合の代替として、**エフェメラルポートから QU ビット付きクエリを
  224.0.0.251:5353 へ送り、応答をユニキャストで自ポートに受ける** legacy モードを
  用意する(RFC 6762 §5.1。多くの responder が対応、avahi/chip とも応答実績のある方式)。
  `MdnsClient::build_browse_*` に QU ビットを立てるオプションを足すだけ(コア変更は
  クエリビット 1 個で、ワイヤ互換の回帰テストで守る)。
- 運用解決(`_matter._tcp`)だけなら対象ノードは既知の 1 台なので、この方式で十分。

### 3.3 IPv6

- 現状 IPv4 のみ実利用(`MDNS_IPV6 = ff02::fb` は定数のみ)。Windows の Matter
  エコシステム(HomeHub 系)は IPv6 前提のことが多いが、**chip デバイスは IPv4 でも
  応答・到達可能なことを Linux で実証済み**。Windows 対応の初期スコープも IPv4 とし、
  IPv6 mDNS は ESP32 側と合わせて別トラック(port-esp32-device.md §5 参照)にする。

## 4. リスク一覧(未確認事項)

| # | リスク | 影響 | 確認方法 / 回避策 |
|---|---|---|---|
| R1 | WinRT スキャンで 0xFFF6 service data が取れない | discriminator 照合不能(致命) | **解消(2026-07-05 W1 実機確認)**: Windows 実機で scan → discriminator 照合が動作 |
| R2 | subscribe 前 write が WinRT で失敗 | handshake 不能(致命) | **解消(2026-07-05 W1 実機確認)**: BTP handshake 確立まで動作 |
| R3 | 5353 共有 bind / マルチキャスト受信が Windows 内蔵 mDNS と競合 | 運用ディスカバリ不能 | QU+ユニキャスト応答モード(§3.2)へフォールバック |
| R4 | WinRT の GATT キャッシュによる接続不安定 | 再現性低下 | デバイス削除手順を README に明記、`disconnect` の確実な実行 |
| R5 | fragment=20 の性能(コミッショニング所要時間) | UX のみ | 許容(Linux 実測で完走)。btleplug の MTU 公開を追う |

## 5. 実装フェーズ分割

| フェーズ | 範囲 | 検証ゲート | 工数感 |
|---|---|---|---|
| **W0: ビルド整備** ✅(2026-07-05) | CI に windows-commissioner ジョブ追加、bluer を Linux target 依存化。Linux からは cargo-xwin で .exe をクロスビルド(gnu/gnullvm は import lib 不足で不可) | Windows ターゲットで check/clippy green | S |
| **W1: BLE スモーク** ✅(2026-07-05 実機確認) | Windows 実機で `ble-commissioner.exe` を実行し R1/R2 とも問題なし | `[btp] established` が出る(SM_BTP_TRACE で確認) | S(問題なければ)〜M(btleplug パッチ要の場合) |
| **W2: BLE コミッショニング** ✅(2026-07-05 実機確認) | Windows 実機の `ble-commissioner.exe` → Linux 側 `ble-onoff-light` に対し、PASE→AddNOC→CASE→CommissioningComplete→OnOff Toggle まで**フル完走**(デバイス側で属性反映・正常切断を確認)。fragment=20(btleplug が MTU 非公開のため)で 115 フラグメント往復 | commissioner ログで AddNOC 完了 | S |
| **W3: mDNS/UDP** | 運用 mDNS ブラウズ + CASE over UDP を Windows で。R3 に応じて QU モード実装 | Windows から Linux デバイスへ UDP コミッショニング(既存 `commissioner` example 相当)完走 | M |
| **W4: フルパス** | BLE→UDP 遷移(commissioner 側の運用遷移が実装され次第)を Windows で chip-lighting-app 相手に | chip デバイスへのフルコミッショニング + Toggle | M(遷移実装自体は別トラック) |

**総工数感: M**(R1/R2 が素直に通れば W0-W2 は小さく、mDNS 共存が主戦場)。

## 6. 検証環境メモ

- WSL2 は BLE スタックを持たない。usbipd-win で USB ドングルを WSL2 に attach し
  WSL2 カーネルを BlueZ 対応で再構築する経路は存在するが、それは「Linux 環境の再現」で
  あって Windows 対応の検証にならないため使わない。
- 推奨検証機材: Windows 11 + 外付け USB BT ドングル(内蔵radioでも可)。対向デバイスは
  Linux 機の `ble-onoff-light`(chip-tool 相互運用実績のある構成)を基準にする。
- ログ: `SM_BTP_TRACE=1` は Windows でもそのまま動く(std env var)。パケットレベルは
  Wireshark + WinRT ETW トレース(`btetl`)が使える。
