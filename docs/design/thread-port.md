# Thread ポート設計(ESP32-C6 + esp-rs/openthread)

対象: `ports/esp32`(ESP32-C6)に Matter over Thread の運用トランスポートを追加する。
前提: コア(`crates/simple-matter`)は sans-IO・トランスポート非依存(`UdpSend`/`UdpReceive` +
`PeerAddr`)であり、**コアは無改造**(唯一の追加は `ThreadDriver` trait と
NetworkCommissioning の Thread 版クラスタ。§4)。コミッショニングは既存の
BLE/BTP(`pairing ble-thread`)を流用する。

関連 doc: `port-esp32-device.md`(C6 ポートの土台)、`mdns-ipv6.md`(Wi-Fi 側の運用広告。
Thread では SRP に置き換える)、`ble-btp.md`。

## 0. サマリ(推奨路線と設計判断)

- **openthread クレート(esp-rs 公式、0.2.0)を採用する。** 自前 Thread スタックは論外
  (Thread 1.3 は MLE/6LoWPAN/DTLS/メッシュルーティングの塊)、esp-idf(C)ポートは
  no_std 路線(port-esp32-device.md §1 の判断)と矛盾する。openthread クレートは
  OpenThread C ライブラリの async Rust バインディングで、**riscv32imac 向けプリビルト
  ライブラリ + 事前生成バインディング**を同梱するため、既存 C6 ポートと同じ
  **stable rustc だけでビルドできる**(検証済み。§2)。rs-matter が同クレートで
  Thread 運用まで動かしている前例もある。
- **UDP はコアの `UdpSend`/`UdpReceive` に OT ネイティブ UDP ソケット
  (`openthread::UdpSocket`)を接続する**(§3.4)。embassy-net 統合
  (`embassy-net-driver-channel`)も存在するが、第 2 の IP スタックを抱える意味が無い。
- **運用広告は mDNS ではなく SRP client**(§5)。openthread クレートに SRP client API
  (TXT レコード対応)が完備しているため**自前 sans-IO 実装は不要**。OTBR の
  advertising proxy が SRP 登録を LAN 側 mDNS へ変換するので、コントローラ側は無改造。
- **コアへの追加は `ThreadDriver` trait + `NetworkCommissioningThread` クラスタのみ**
  (`WifiDriver`/`NetworkCommissioningWifi` の兄弟。同じ「connect は開始のみ +
  status ポーリング + DeferredPoll」パターン。§4)。
- **重大な制約(検証で確定): esp-radio 0.18 は `ieee802154` と `wifi` feature の同時
  有効化を build.rs で拒否する。** Wi-Fi と Thread は同一ファームウェアに共存できない。
  このため Thread 系 bin は新パッケージ `ports/esp32/esp32c6-thread` に分離した
  (`ieee802154` + `ble` は共存可 = `pairing ble-thread` は成立する)。§2.3。
- 検証環境は「RCP 構成」: ESP32-C6 ボードに esp-idf の ot_rcp FW を書き、ホスト PC の
  OTBR docker(openthread/otbr)が Border Router になる(§6、`scripts/otbr/`)。

## 1. フェーズ T1 の検証ビルド結果(2026-07-14、ホストで確定)

`cargo build -p esp32c6-thread --release`(ports/esp32、stable rustc、
riscv32imac-unknown-none-elf)は **green**。確定した事実:

| 項目 | 結果 |
|---|---|
| openthread 0.2.0 のビルド | ✅ プリビルト .a + 事前生成バインディングが使われ、clang/CMake/Ninja/bindgen 不要 |
| リンク | ✅ tinyrlibc(utoa/strtoul)+ `isupper` feature で undefined symbol なし |
| MbedTLS | `mbedtls-rs-sys` feature **必須**(無いと `mbedtls_sha256_*` 等が undefined。0.2.0 のプリビルト .a は MbedTLS 非同梱で、外部の mbedtls-rs-sys 0.1.0(こちらもプリビルト .a 同梱)にリンクする) |
| esp-radio `ieee802154`×`wifi` | ❌ build.rs が「802.15.4 and Wi-Fi won't work together」で panic → パッケージ分離(§2.3) |
| esp-radio `ieee802154`+`ble` | ✅ ビルド可(esp-radio build.rs は禁止していない。実機での同時動作は T2 ゲート) |
| フットプリント | thread-smoke のアプリイメージ **332 KiB**(参考: e5-light = simple-matter + Wi-Fi + BLE で 1,132 KiB)。4 MiB flash に対し余裕 |
| バージョン整合 | esp-hal 1.1.1 / esp-rtos 0.3 / esp-radio 0.18 / embassy-time 0.5 / heapless 0.9 — **既存 C6 ポートと完全一致**(openthread の examples/esp と同じ組合せ) |

## 2. esp-rs/openthread 調査

### 2.1 クレート構成(crates.io / GitHub esp-rs/openthread)

- `openthread` **0.2.0**(2026-06-25 リリース。0.0.0 は名前予約)/ `openthread-sys` 0.2.1。
  「Platform-agnostic, async Rust bindings for OpenThread」。MSRV 1.84、no_std。
- radio は `Radio` trait 1 個が接点。同梱実装は **`EspRadio`**(feature `esp-radio` →
  esp-radio 0.18 の `ieee802154`。**ESP32-C6/H2 対応**)と nRF(`embassy-nrf`)。
  将来: Spinel RCP ホスト(`rcp` feature、0.2.0 に既にあり)・sleepy end-device(予定)。
- 統合面: embassy ベース(embassy-time/sync/futures)。`OpenThread` ハンドルは
  `Clone` 可で、`ot.run(radio)` を 1 タスクで回し他タスクから API を呼ぶ構造
  (esp-rtos の thread-mode executor でそのまま動く。検証済み)。
- **UDP API あり**: `UdpSocket::bind(ot, &SocketAddrV6)` / `send(data, Some(&local), &remote)`
  / `recv(buf) -> (len, local, remote)`(async)。リソースは
  `OtUdpResources<MAX_SOCKETS, BUF>` を 'static で事前確保(ヒープレス)。
- **SRP client API あり**(feature `srp`): `srp_set_conf(SrpConf { host_name, .. })`、
  `srp_add_service(SrpService { name, instance_name, port, txt_entries, .. })`
  (**TXT 対応**)、`srp_autostart()`(SRP サーバ自動発見)、`srp_wait_changed()` 等。
  リソースは `OtSrpResources<MAX_SERVICES, BUF>`。
- dataset API: `set_active_dataset_tlv(&[u8])` / `set_active_dataset_tlv_hexstr(&str)`
  (**chip-tool が渡す Operational Dataset TLV をそのまま食える**)、構造体版
  `set_active_dataset(&OperationalDataset)`、`get_tlv_pan_ids()`(TLV から PAN ID 抽出)。
- 状態 API: `net_status() -> NetStatus { role, ext_pan_id, ip6_enabled }`、
  `wait_changed()`、`ipv6_addrs(cb)`、`scan()`(active scan。ScanNetworks 用)。
- 永続化: `Settings` trait(key: u16、indexed multi-value。OT の
  `otPlatSettings*` 相当)。同梱は `SimpleRamSettings`(揮発)。**KVS 裏打ちの実装を
  ポート側で書けば dataset/ネットワークキーを OT 自身が永続化する**(§5.3)。
- 乱数: `OtRngCore` = rand_core 0.9 の `RngCore`(esp-hal 1.1 の `Rng`/`Trng` が実装)。
- feature 注意(0.2.0): default = `matter` バンドル + `mbedtls-rs-sys`。`srp` は
  git main で `srp-client` に改名済み(**0.2.0 では `srp`**)。`ftd`(router 可)は
  オプトイン、既定は MTD。Border Router 機能は non-goal(OTBR は別途必要)。

### 2.2 ビルド機構(openthread-sys / mbedtls-rs-sys)

- プリビルト対象: `riscv32imac-unknown-none-elf`(C6/H2)、`thumbv7em-none-eabi`、
  `thumbv6m-none-eabi`。mbedtls-rs-sys は加えて xtensa 系(esp32/s2/s3)も同梱。
  この場合 **ホストに C ツールチェーン不要**(検証済み — 本リポジトリの前提
  「stable rustc のみ」が保てる)。
- `force-generate-bindings` を立てた場合のみ CMake + Ninja + 新しめの Clang
  (+ bindgen)で OpenThread C をソースビルドする。`use-gcc` / `force-esp-riscv-gcc`
  で GCC も選べる。プリビルト .a と feature の組合せが合わない構成
  (例: `ftd` 以外の capability feature の変更)ではソースビルドに落ちる点に注意。
- mbedtls-rs-sys は SHA-1/SHA-256/SHA-512/exp-mod を **Rust 実装(RustCrypto の
  sha1/sha2 crate)へフック**する構成(nohook-* feature で解除可)。本リポジトリの
  rustcrypto バックエンドと同じ crate を共有するのでコード重複は限定的。
  **注意**: OT の DTLS/暗号は MbedTLS(C)側で完結し、コアの `Crypto` trait とは独立
  (コアは無改造のまま)。逆に、将来別の場所で mbedtls-rs-sys を使う場合は二重リンク
  禁止(upstream の警告)。
- OT 内部ヒープは固定バッファ(`heap-int-<N>` feature でサイズ変更、
  `heap-ext-ot` でグローバルアロケータへ委譲可)。esp-alloc と併用可能。

### 2.3 esp-radio の排他制約(確定事項)

esp-radio 0.18 の build.rs は

```text
if ieee802154 && (wifi || wifi-eap) => panic!("802.15.4 and Wi-Fi won't work together")
```

を明示する(C6 は HW 的に 2.4GHz PHY を共有し、esp-radio に Wi-Fi/15.4 コエグジスタンス
実装が無い)。`ieee802154` + `ble` は許可。帰結:

1. **Thread 系 bin は `esp32c6-firmware`(wifi+coex 有効)と同一パッケージにできない**
   → 新パッケージ `ports/esp32/esp32c6-thread` に分離。ワークスペースの
   `default-members` から外し、`cargo build -p esp32c6-thread` でビルドする
   (`cargo build --workspace` は feature 統一で panic するので**使用禁止**。
   ports/esp32/Cargo.toml のコメント参照)。
2. 製品像としても「Wi-Fi 版 FW」と「Thread 版 FW」は別イメージになる
   (Matter デバイスとしては一般的な構成)。
3. `pairing ble-thread`(BLE コミッショニング + Thread 運用)は `ieee802154`+`ble` で
   成立する見込み。**実行時の BLE/15.4 同時動作(コエグジスタンス)は未検証** — T2 の
   最初のゲート(リスク R2)。

## 3. アーキテクチャ

### 3.1 全体像

```
                     コア(無改造領域)
  MatterStack ── UdpSend/UdpReceive(PeerAddr::Udp)── ports 側 pump
      │                                                   │
      │ ThreadDriver trait(コアに追加、WifiDriver の兄弟)│
      │ NetworkCommissioningThread(コアに追加)           │
      └───────────────┬───────────────────────────────────┘
                      ports/esp32/esp32c6-thread
        OtUdp(UdpSocket)   OtThreadDriver    SRP 登録タスク
                  └──────── openthread(OpenThread ハンドル)────────┐
                            ot.run(EspRadio(Ieee802154))     KvsSettings(flash)
```

- BTP(BLE)は既存のまま(`TroubleGattPeripheral`)。commissionable 広告は BLE のみ
  (Thread デバイスは Wi-Fi 版と違い _matterc._udp の mDNS を出す先が無い。
  OTBR 経由の広告は運用系のみで仕様上も BLE 広告が本線)。
- mDNS レスポンダ(`discovery.rs`)は Thread 版では**使わない**(SRP に置換)。

### 3.2 パッケージ / ビルド構成(T1 で確定済み)

- `ports/esp32/esp32c6-thread`: esp-hal 1.1.1(unstable)+ esp-rtos 0.3(embassy)+
  esp-radio 0.18(`ieee802154`,`ble`,`unstable`)+ openthread 0.2.0
  (`udp`,`srp`,`esp-radio`,`isupper`,`log`,`mbedtls-rs-sys`)+ tinyrlibc 0.5
  (`utoa`,`strtoul`)。リンカ/ランナ設定は既存 `.cargo/config.toml` を共有。
- libc シム: OT が呼ぶ `str*`/`mem*` は tinyrlibc で充足(検証済み)。追加シンボルが
  必要になったら tinyrlibc の feature を足す(全部入りにしない — ROM 関数と衝突しうる)。
- T2 で simple-matter コアを載せる際は `default-features=false, features=["rustcrypto","ble"]`
  を同 features で追加する(e3/e4 系と同じ。Wi-Fi 系モジュール `wifi.rs`/`net.rs` は
  使わない。`esp32c6_firmware` lib への依存は wifi feature を引き込むため不可 —
  `ble.rs`/`kvs.rs` は当面コピーし、後で共有 crate への切り出しを検討)。

### 3.3 タスク構成(esp-rtos thread-mode executor、e5-light の pump と同型)

1. `ot.run(EspRadio)`: OT スタック駆動(専有タスク)。
2. Matter pump: 既存の `stack.poll`/`handle_datagram` ループ。ソケットが
   `EspUdp`(embassy-net)から `OtUdp`(openthread UdpSocket)に替わるだけ。
3. SRP/状態監視: `wait_changed()` で role/アドレス変化を拾い、attach 完了時に
   SRP 登録・`ThreadDriver` の status 更新。
4. BLE(gatt_worker): 既存のまま。

### 3.4 UDP マッピング(コアの `UdpSend`/`UdpReceive` → OT UdpSocket)

```rust
// ports/esp32/esp32c6-thread 側(T2)
struct OtUdpTx<'a>(openthread::UdpSocket<'a>);  // 実際は送受で参照を分ける
impl UdpSend for OtUdpTx<'_> {
    async fn send_to(&mut self, data: &[u8], addr: PeerAddr) -> Result<()> {
        let PeerAddr::Udp(SocketAddr::V6(v6)) = addr else { return Err(...) };
        self.0.send(data, None, &v6).await  // local は OT が選ぶ
    }
}
impl UdpReceive for OtUdpRx<'_> {
    async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, PeerAddr)> {
        let (len, _local, remote) = self.0.recv(buf).await?;
        Ok((len, PeerAddr::Udp(SocketAddr::V6(remote))))
    }
}
```

- ポート 5540 を 1 ソケット bind(`OtUdpResources<2, 1280>`)。IPv6 のみ
  (Thread に IPv4 は無い。`PeerAddr::canonical()` の v4 折り畳みは素通り)。
- MTU: コアの `MAX_TX_PACKET_SIZE = 1232` は IPv6 最小 MTU 1280 − 40 − 8 で、
  Thread(6LoWPAN フラグメンテーションあり、リンク MTU 1280 保証)に適合。
  matter-over-vpn.md で実証済みの MTU1280 経路と同じ前提。
- `UdpMulticast` は実装しない(mDNS を使わないため不要。コアの trait は
  ソケット別なので未実装でよい)。Matter グループメッセージング(ff35::/16 の
  site-local multicast)は将来課題(§7 T3 の注記)。

### 3.5 コミッショニングフロー(`pairing ble-thread`)

```
chip-tool pairing ble-thread <node-id> hex:<dataset-tlv> 20202021 3840
  1. BLE/BTP + PASE                     … 既存(無改造)
  2. ArmFailSafe / CSR / NOC 注入        … 既存(無改造)
  3. AddOrUpdateThreadNetwork(dataset)  … NetworkCommissioningThread(§4)
  4. ConnectNetwork(networkID)          … ThreadDriver.connect → OT attach(deferred)
  5. CommissioningComplete               … CASE は Thread(UDP)側で確立
       └ コントローラは OTBR の advertising proxy が LAN に流す
         _matter._tcp(SRP 由来)で運用アドレスを解決
```

## 4. コアへの追加(唯一の改造点)

### 4.1 `ThreadDriver` trait(`crates/simple-matter/src/thread.rs` 新規)

`WifiDriver`(wifi.rs)と同じ設計原則: IM の invoke ハンドラは同期 Mealy 機械なので
**connect は「開始」だけ**、結果は `status()` ポーリング(DeferredPoll)で回収する。

```rust
pub enum ThreadStatus {
    Idle,
    Attaching,
    Attached,                    // child/router/leader(role の詳細はポート側ログで)
    Failed { reason: i32 },
}

pub trait ThreadDriver {
    /// Operational Dataset(TLV バイト列)を保存する(AddOrUpdateThreadNetwork)。
    /// 戻り値: dataset から抜いた Extended PAN ID(8B)= NetworkID。
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]>;
    /// attach を開始する(ConnectNetwork。非ブロッキング)。
    fn connect(&mut self);
    fn status(&self) -> ThreadStatus;
}
```

- `NullThreadDriver`(即 Attached)を用意し、PC 上の IM テストを可能にする
  (NullWifiDriver と同型)。
- Ext PAN ID の抽出は Thread TLV(type=2, len=8)の線形走査で 10 行程度
  (dataset TLV は type(1B)+len(1B)+value の並び)。openthread 到達前に
  コア単体でテスト可能なのでコア側 util に置く。

### 4.2 `NetworkCommissioningThread<D: ThreadDriver>` クラスタ

`NetworkCommissioningWifi` の兄弟(network_commissioning.rs に追加)。差分:

| 項目 | Wi-Fi 版 | Thread 版 |
|---|---|---|
| FeatureMap | `FEATURE_WIFI = 0x01` | **`FEATURE_THREAD = 0x02`**(新設) |
| 追加コマンド | 0x02 AddOrUpdateWiFiNetwork(ssid tag0, creds tag1) | **0x03 AddOrUpdateThreadNetwork**(tag0 = OperationalDataset octstr ≤254B、tag1 = Breadcrumb) |
| NetworkID | SSID | **Extended PAN ID(8B)** — Networks 属性・LastNetworkID・ConnectNetwork の照合キー |
| 0x06 ConnectNetwork | driver.connect(ssid,creds) + deferred | driver.connect() + deferred(照合は ExtPanID) |
| 0x00 ScanNetworks | 空応答シム | 空応答シム(T3 で `ot.scan()` 接続を検討) |
| 属性 | 0x0008 SupportedWiFiBands | **0x0009 SupportedThreadFeatures**(bitmap: MTD なら isThreadDevice+isSleepyEndDevice 相当のビット構成に注意)、**0x000A ThreadVersion**(Thread 1.3 = 4) |

- dataset 保持は `heapless::Vec<u8, 254>`(octstr 最大長)。fail-safe 中の巻き戻し
  (ArmFailSafe(0) / 期限切れ)は既存機構に乗る(fail-safe cleanup が
  NetworkCommissioning の pending をどう扱うかは既存 Wi-Fi 版と同じ扱いに合わせる)。
- 実装は Wi-Fi 版同様 hand-written `ServerCluster`(cluster! マクロは非ジェネリック)。

### 4.3 ports 側 `OtThreadDriver`

```rust
// esp32c6-thread 側。OpenThread ハンドル(Clone)を保持
impl ThreadDriver for OtThreadDriver<'_> {
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]> {
        self.ot.set_active_dataset_tlv(tlv)?;   // OT 側へ即時投入
        extract_ext_pan_id(tlv)                  // コア util
    }
    fn connect(&mut self) {
        let _ = self.ot.enable_ipv6(true);
        let _ = self.ot.enable_thread(true);     // attach 開始(非ブロッキング)
    }
    fn status(&self) -> ThreadStatus {
        match self.ot.net_status().role { ... }  // Child/Router/Leader → Attached
    }
}
```

## 5. 運用広告(SRP)と永続化

### 5.1 SRP 登録(mdns-ipv6.md の `set_operational` 相当)

attach 完了後(`status = Attached` になったら):

```rust
ot.srp_set_conf(&SrpConf { host_name: <"SM-" + MAC hex 等 一意名>, ..SrpConf::new() })?;
ot.srp_add_service(&SrpService {
    name: "_matter._tcp",
    instance_name: &format!("{fab16hex}-{node16hex}"),  // 既存 Operational と同じ命名
    port: 5540,
    txt_entries: [("SII","5000"),("SAI","300"),("T","0")],  // 既存 TXT 方針に合わせる
    priority: 0, weight: 0, lease_secs: 0, key_lease_secs: 0,
})?;
ot.srp_autostart()?;   // SRP サーバ(OTBR)を netdata から自動発見
```

- fabric 追加/削除時(`FabricTable::generation()` 変化)に `srp_remove_service` /
  `srp_add_service` で作り直す(mDNS 版の `set_operational` 再実行と同じ流儀)。
- ホスト名・インスタンス名バッファは `OtSrpResources` に収まる(MAX_SERVICES =
  NOPS 相当 = 当面 2)。
- 検証: OTBR 側 `avahi-browse -r _matter._tcp` ないし LAN の chip-tool
  `discover commissionables/operational` で見えること。

### 5.2 commissionable 広告

Thread 版では BLE 広告のみ(既存 AdvData)。`pairing ble-thread` は BLE 発見なので
十分。(SRP で _matterc._udp を出す選択肢は「未コミッショニング時は Thread に
参加していない」ため原理的に不可。)

### 5.3 永続化(KVS ⇔ OT Settings)

- **方針: openthread の `Settings` trait を `EspKvs` で実装する**(`KvsSettings`)。
  OT は dataset・ネットワークキー・SRP client key・子テーブル等を自分の key 空間
  (u16)で永続化するので、**リブート後は dataset 再注入なしで自動 re-attach** する
  (NetworkCommissioning の Networks 属性は OT から dataset を読み戻して再構成)。
- key マッピング: OT key(u16)→ `pack_key` の短キー(例: `b"ot" + u16 LE`)。
  OT の一部 key は indexed multi-value(SLAAC IID 等)だが MTD で実際に使うのは
  数個 — `sequential-storage` の Map に「key+index」で平坦化して格納する。
- フラッシュ書き込みは BLE/15.4 動作中のキャッシュ停止に注意(kvs.rs の既知課題)。
  OT の settings 書き込みは attach 時に集中するため、T2 で実測して問題なら
  write キューイング(idle 時 flush)を入れる。

## 6. 検証環境(RCP + OTBR。`scripts/otbr/` に準備済み・ホスト検証済み)

構成: **ESP32-C6 ボード×2**(RCP 用 + DUT 用)+ ホスト PC(Linux, docker)。

- **RCP FW(ot_rcp)**: `scripts/otbr/build-ot-rcp.sh` — esp-idf docker
  (espressif/idf:release-v5.4)で `examples/openthread/ot_rcp` を esp32c6 向けに
  ビルドし、`dist/ot_rcp/merged_ot_rcp.bin`(0x0 一発書き)を出力する。
  **ホスト上でビルド成功を確認済み**(ローカル IDF 不要。release-v6.0 でも可)。
  Espressif プリビルトは配布形態が安定しないため、ビルドスクリプト方式を正とする。
- **OTBR**: `openthread/otbr:latest`(pull 済み、otbr-agent 0.3.0 起動確認済み)。
  `start-otbr.sh` が `--network host --privileged` + IPv6/forwarding sysctl +
  `--radio-url spinel+hdlc+uart://<dev>?uart-baudrate=460800` で起動し、wpan0(TUN)
  を作る。host network なので **LAN への mDNS(advertising proxy)とホスト上
  chip-tool からの wpan0 到達が素で効く**。dataset は named volume `otbr-data` に永続。
- **ネットワーク form / dataset 払い出し**: `form-network.sh`(ot-ctl
  `dataset init new → commit → ifconfig up → thread start`、TLV hex を出力)。
  `get-dataset.sh` で再取得。この hex を thread-smoke(`THREAD_DATASET` 環境変数)と
  chip-tool(`hex:` 引数)の両方に使う。
- **プリフライト**: `check-env.sh` — docker/イメージ/otbr-agent/chip-tool
  (/snap/bin/chip-tool 導入済み)/dev/net/tun を確認。**全項目 OK を確認済み**
  (RCP 未接続でも実行可)。
- 手順書: `scripts/otbr/README.md`(T1 join スモーク〜chip-tool pairing まで)。

## 7. 実装フェーズ

### T1: Thread join スモーク(**完了 2026-07-17。全ゲート PASS**)

**最終結果**: R9(RX 沈黙)を TX キックワークアラウンド(リスク表 R9 参照)で解消し、
①role 遷移(Detached→Child)②OTBR child table 可視 ③**ping 疎通(無送信 225 秒
ソーク後も 100%)** ④**UDP echo 双方向**(`ot-ctl udp send <ML-EID> 11095 hello_thread`
→ DUT `[echo]` → OTBR 側で echo 受信)の T1 全ゲートを実測 green。
R9 の切り分け過程(TX プローブ / heartbeat / ble feature / ログレベルの bisect)は
main.rs に診断コード(5 秒 heartbeat、`SM_TX_PROBE=<addr>` 環境変数ゲートの
周期送信タスク)として残してある。

- 内容: `ports/esp32/esp32c6-thread`(bin `thread-smoke`)。コンパイル時定数の
  dataset で join → role 遷移ログ(Detached→Child)→ mesh-local アドレス表示 →
  UDP echo(:11095)。OTBR 環境スクリプト一式。
- 済み: ビルド green(§1)、OTBR/イメージ/RCP FW ビルド、プリフライト。
- 検証ゲート: ① role が Child/Router に遷移 ② OTBR から mesh-local へ ping 応答
  ③ `ot-ctl udp send` に echo 応答 ④ 既存全ビルド・全テスト回帰なし(済)。

#### T1 実機結果(2026-07-17、NanoC6×2: RCP=/dev/ttyACM5, DUT=/dev/ttyACM1)

- **R3(RCP over USB-Serial-JTAG)= 当初不成立 → 再ビルドで解決(最重要成果)。**
  既定の esp-idf `ot_rcp`(v5.4)は `CONFIG_OPENTHREAD_RCP_UART=y` で spinel を
  **ハードウェア UART(GPIO)**に出すため、UART ブリッジの無い NanoC6 の USB ポート
  (/dev/ttyACM5 = USB-Serial-JTAG)には spinel が流れない。OTBR は
  `spinel_driver.cpp:87: Init() Failure` で radio を開けなかった。
  **解決**: `ot_rcp` を `CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y`(+ `RCP_UART=n`)で
  再ビルドして spinel を USB CDC に出す(esp-idf の RCP transport 選択肢に存在。
  依存 `ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG` は既定で満たされる)。
  再ビルド後 OTBR は正常起動し、`ot-ctl rcp version` が round-trip
  (`openthread-esp32/...; esp32c6; ...`)= **spinel over USB-Serial-JTAG は成立**。
  → `build-ot-rcp.sh` に `RCP_OVER_USB=1`(既定)を実装。**外付け UART / DevKitC は不要**。
- **ゲート① role 遷移 = PASS。** DUT ログ: `Role disabled -> detached -> child`、
  `RLOC16 fffe -> 1403`、eui64 `404ccafffe5b2fe0`(DUT MAC と一致)、dataset
  (extpanid `c933e160a23d1143`, panid `0x2702`)投入、mesh-local + ML-EID 取得、
  `UDP echo listening on port 11095`。
- **ゲート② OTBR 可視化 = PASS。** `ot-ctl child table` に DUT が Child として出現
  (RLOC 0x1403/…、Ext MAC `ca45e5a6d824c492` = DUT ログの extended address と一致、
  Mode `r`=rx-on MTD, LQ 3, RSSI -43〜-53)。`childip` に DUT の ML-EID 登録あり。
- **ゲート③ ping / UDP echo = FAIL(データパス未達)。** OTBR→DUT の ICMPv6 ping・
  UDP(:11095)いずれも **無応答**(0 received、DUT シリアルに `[echo]` 出ず)。
  child の Age が attach 後に単調増加(88→108→128…、240s タイムアウトへ)し、
  **DUT は attach 数秒後に上り MLE キープアライブも停止** = 送受信とも止まる。
  切り分け: (a) コンソール drain 継続下でも echo せず、(b) 停止済み DUT にリーダ
  (cat)を付けても復帰せず出力ゼロ → **USB-Serial-JTAG の println ブロックによる
  ストールではない**。attach 直後に OT スタック/無線サービス(`ot.run`/esp-radio
  ieee802154/executor)が丸ごと停止していると推定。root-cause は T2 の最初の課題。
  候補: `ot.run` タスク飢餓、15.4 IRQ 処理停止、ヒープ(96KiB)枯渇、OT alarm/timer
  ロックアップ。**注**: attach 自体は双方向ユニキャスト(Parent/Child ID 交換)を要する
  ため無線 TX/RX は attach 時点までは機能している。
- 手順補正(実施済み・スクリプト反映): docker 28.x は `--network host` で `net.*`
  sysctl 指定を拒否 → `start-otbr.sh` はホスト側 sysctl を確認する方式に変更。
  ホストに `ip6table_filter` が無く otbr の firewall init が die → `OTBR_FIREWALL`
  (既定 0)で無効化可能に。DUT モニタは `stty + timeout cat`(espflash monitor 不使用)。
- 未回帰: 既存ビルド/テストは無改造(コア変更なし。T1 はポート bin と scripts のみ)。

### T2: Matter over Thread 最小 E2E(コミッショニング + On/Off)— **完了 2026-07-17、全ゲート PASS(実測)**

- コア: `ThreadDriver` + `NullThreadDriver` + ExtPanID 抽出 util +
  `NetworkCommissioningThread`(§4)+ ホストテスト(IM レベルで
  AddOrUpdateThreadNetwork/ConnectNetwork の wire を検証)。
- ports: bin `t2-light`(e4-ble-light をベースに Wi-Fi 抜き / OtUdp pump /
  OtThreadDriver / KvsSettings / SRP 登録)。
- 検証ゲート: ① BLE+15.4 同時動作(pairing 中に 15.4 attach)②
  `chip-tool pairing ble-thread` 完走 ③ `chip-tool onoff toggle`(CASE over Thread)
  ④ リブート後 re-attach + CASE 再確立(KvsSettings)⑤ OTBR の advertising proxy
  経由で `_matter._tcp` が LAN に見える。
- 規模感: コア ~400 行 + テスト、ports ~600 行(見積り。pump は e5-light 流用)。

#### T2 実機結果(2026-07-17、NanoC6×2: RCP=/dev/ttyACM5 + OTBR docker、DUT=/dev/ttyACM1)

**全ゲート green(②③は smctl 代替 — chip-tool は環境の mDNS 5353 競合で発見不能、下記)**:

- **ゲート①(R2: BLE+15.4 同時動作)= PASS。** BLE(BTP)接続を維持したまま 15.4
  attach(Detached→Child)が成立し、遅延 ConnectNetworkResponse も BLE 上で配送された
  (時分割不要)。**ただし運用フェーズは時分割**: esp-radio に BLE/15.4 コエグジスタンス
  調停が無く、常時 BLE 広告が 15.4 の RX/TX を恒常的に劣化させることを実測
  (CASE over Thread が成立しない)。コミッショニング完了(fabric 保有 + BLE 切断)後は
  BLE 広告を停止して 15.4 に無線を明け渡す(`GattChannels::set_adv_enabled`。
  コミッショニング済みで起動した場合は最初から広告しない)。
- **ゲート②(コミッショニング完走)= PASS(smctl)。**
  `smctl pairing ble-thread 1 20202021 <dataset-hex> 3840 --at <OTBRホストIP>` で
  BLE/BTP → PASE → CSR/AddNOC → AddOrUpdateThreadNetwork → ConnectNetwork(遅延応答、
  attach 後)→ BLE close → 運用解決(QU ユニキャスト)→ **CASE over Thread(full
  Sigma1/2/3)→ CommissioningComplete** まで完走(`COMPLETE over UDP. session=0x3`)。
  コアの `Commissioner` に `set_thread_dataset`(AddOrUpdateThreadNetwork 0x03 +
  NetworkID=ExtPanID)を追加し、smctl に `pairing ble-thread` を実装した。
  **chip-tool は運用発見で不成立(環境問題)**: この otbr イメージは avahi ではなく
  otbr-agent 内蔵の native mDNS publisher を使い、ホストでは avahi + chip-tool +
  otbr の 3 者が 5353 を共有(SO_REUSEPORT)する。publisher はエフェメラルポートからの
  QU クエリには正しく応答する(実測)が、5353 同士の QM 経路が届かず chip-tool の
  resolve が 100% タイムアウトする。さらに chip-tool の mDNS ブロードキャストは
  wpan0 経由でメッシュへ流入し、RCP を圧迫して otbr-agent ごと落とした事例あり
  (`HandleRcpTimeout` → 死亡。stop→start で復旧)。
- **ゲート③(toggle、CASE over Thread)= PASS。** `smctl --timeout 90 onoff toggle 1 1`
  → `CASE ESTABLISHED (full handshake)` → `onoff cmd 0x02 OK`。
- **ゲート④(リブート永続化)= PASS。** リブート後: fabric/resumption 復元(EspKvs)+
  dataset 自前永続化(`otds` キー)による自動 re-attach → CASE **full** 再確立 + toggle OK
  → 2 回目の toggle は **`Sigma2Resume`(resumption)で 1.4 秒**で確立し toggle OK。
- **ゲート⑤(SRP → LAN mDNS)= PASS。** SRP 登録(host `SM<MAC>` /
  instance `<fab16>-<node16>` / TXT SII,SAI,T)が OTBR SRP server に受理され、
  advertising proxy 経由で LAN の avahi-browse に `_matter._tcp` PTR が見える。
  SRV/AAAA は QU ユニキャストで解決可能(上記 5353 問題により QM は不可)。

#### T2 で確定した重要な技術的知見(ワークアラウンド込み)

1. **OMR アドレスの手動生成が必須**(発見不能の根本原因の一つ)。プリビルト
   libopenthread.a は SLAAC 無効ビルド(`otIp6SetSlaacEnabled` 未リンク)で、DUT は
   link-local + mesh-local しか持たず、SRP auto host address が mesh-local に落ちて
   advertising proxy が AAAA を出さない。vendored openthread に
   `add_unicast_address`(`otIp6AddUnicastAddress`)を追加し、attach 後に netdata の
   SLAAC prefix + EUI64 IID で OMR アドレスを合成・追加する(`maybe_add_omr_address`)。
2. **多フラグメント TX のペーシングが必須**(CASE sigma2 ~900B 不达の根本原因)。
   RCP(ot_rcp、spinel over USB-CDC)は back-to-back の 6LoWPAN 断片を HW auto-ack
   した後 spinel 側で取りこぼす(OTBR の `Dropping rx frag frame`(先頭/中間断片欠落)
   で実測。ACK 済みのため OT は再送しない)。vendored `EspRadio::transmit` に
   「64B 超フレームの送信成功後 8ms 待つ」ペーシングを実装して解消。
3. **TX 完了イベント喪失のリカバリ**(R9 拡張)。esp-radio 0.18 は tx_done/tx_failed を
   取りこぼすことがあり、`TX_SIGNAL.wait()` が永久に完了せず OT radio タスク全体が停止
   する(sigma2 送信バーストで実機再現)。`transmit` に 500ms タイムアウト + 同一 PSDU
   再送出(tx_init の stop_current_operation で状態機械ごと復帰)を実装。
4. **KVS 裏打ちの OT Settings は T2 では不成立(リスク R6 の実測)**。attach 時の
   flash 書き込みバースト(フレッシュ NVS では領域初期化 erase 込み)が 15.4 radio を
   R9 の TX キックでも回復不能な形で停止させる(ping 100% loss、executor は生存)。
   T2 は RAM settings + dataset 自前永続化(doc §5.3 の許容フォールバック)。実装は
   `ot_settings.rs`(KvsSettings)に残置 — T3 で write キューイング/安全窓 flush と
   共に再導入。**帰結**: SRP ECDSA 鍵が揮発のため、リブート後の SRP 再登録は
   サーバに残る旧登録(key-lease 既定 ~7.8 日)と鍵衝突し得る(検証では OTBR 再起動で
   回避。運用 CASE は resumption + 既知アドレスで疎通するため toggle は影響なし)。
5. **SRP client の登録がバックオフで数分沈黙し得る** → pump に「attach 済み・未登録の
   まま 30 秒毎に `srp_stop` → `srp_autostart` 再発行」の再キックを実装。加えて遅延
   ConnectNetworkResponse は「SRP サーバ確認済み or attach+5 秒」まで保留する
   (IM の deferred 締切 20 秒と attach ~10 秒に収める)。
6. **コミッショナ側の余裕**: `Commissioner` の fail-safe を 120→300 秒(SRP 反映待ちで
   運用解決中に fail-safe が切れて AddNOC が巻き戻る事故の防止)、smctl の運用解決
   タイムアウトを 60→120 秒に拡大。smctl の `--at` ユニキャスト解決に **2 段解決**
   (SRV-only 応答 → `<host>.local` AAAA 追加クエリ)を実装(otbr native publisher は
   SRV 応答に AAAA を同梱しない)。
7. **リンク品質**: 本環境の 15.4 リンクはフレーム損失が大きく(ping loss 30-50% の
   時間帯あり、R9 キックで回復する RX 沈黙窓を含む)、CASE 確立はリトライ前提
   (`--timeout 90` 推奨)。T3 の安定化課題。

#### 残課題(T3 へ)

- chip-tool での発見成立(otbr を avahi 連携ビルドにする / ホスト avahi 停止 /
  ネットワーク名前空間分離のいずれか)。smctl パスは green。
- KvsSettings(write キューイング)による OT 自己永続化と SRP 鍵の保持。
- 15.4 リンク品質の改善(esp-radio 0.18 の RX 沈黙・イベント喪失は upstream 報告候補。
  ペーシング 8ms の削減・調整、RCP 側フロー制御)。
- 診断ログ(`[udp] rx` / 大フレーム TX/RX)の整理(T2 検証用に残置)。

### T3: 運用強化(E2E 安定化)

- Subscribe/イベント配信の Thread 経由確認、MRP パラメータ(SII/SAI の実測反映。
  Thread は Wi-Fi よりレイテンシ大 — SAI を実測で調整)、SRP lease 更新の長時間試験、
  fabric 削除→SRP 更新、`ScanNetworks` の実装(`ot.scan()`)、smctl からの操作確認。
- 注記: グループメッセージング(IPv6 multicast ff35::/16)は OT UDP の
  multicast join API 確認込みで T3 では**スコープ外**(必要になった時点で
  `UdpMulticast` の Thread 実装を検討)。
- 検証ゲート: 24h 連続運用(subscribe 維持・SRP lease 更新)+ chip-tool
  基本操作一式。

#### T3 実機結果(2026-07-17、NanoC6 DUT=/dev/ttyACM1 + RCP=/dev/ttyACM5 + OTBR docker)

DUT は T2 と同じ t2-light bin(compressed fabric `9D4D94DDDE8BB05B`、host `SM404CCA5B2FE0`)。
実施項目ごとの結果(done / partial / carried-over):

- **item 1: KvsSettings 再導入(R6 解決)= DONE(実機ゲート PASS)。**
  T2 は「attach 時の flash 書き込みバーストが 15.4 radio を回復不能停止させる」ため RAM
  settings に割り切っていた。T3 は **write-back(RAM 権威 + idle 時 flush)** で再導入した
  (`ot_settings.rs` を全面書き換え)。OT の `Settings` 呼び出し(get/add/remove/set/clear)は
  すべて RAM の `SettingsStore`(フラットバッファ、`RamSettings` と同一レイアウト)で即応し
  **flash に一切触れない**。書き込みは dirty フラグを立てるだけで、pump が **radio 静穏窓**
  (①直近 UDP から 4s 経過 ②attach から 10s 経過 ③前回 flush から 60s 経過)でのみ、RAM 権威を
  **1 つの KVS アイテム(`otset`)として丸ごと 1 回 store** する。実測:
  `[kvs] flushed OT settings (323 bytes) at idle t=10s` の直後も role=Child 維持(radio 生存)=
  R6 の顕在化(ping 100% loss)を根治。リブート後は `[kvs] restored OT settings (323 bytes)` で
  dataset / NetworkInfo / **SRP ECDSA 鍵** を復元 → 同一 host `SM404CCA5B2FE0` で SRP を再登録し、
  OTBR に残る同鍵の登録が **鍵衝突せず refresh 受理**(remaining lease が満了前に戻る)。
  = **T2 割り切り「SRP 残留登録衝突」を根治**。**移行時の注意**: T2(揮発鍵)→T3 の初回だけは
  OTBR に残る旧鍵登録と新鍵が衝突する(RESPONSE_TIMEOUT ではなく登録が通らない)。OTBR の
  `srp server disable/enable` で旧登録をクリアすれば以降は永続鍵で安定。

- **item 3: Subscribe over Thread + SII/SAI 反映 = DONE(実機ゲート PASS)。**
  SRP TXT の MRP パラメータを Thread 実測に合わせて拡大: **SAI 300→1000ms、SII 5000→10000ms**
  (Thread はメッシュ多ホップ + 6LoWPAN 断片化 + 8ms TX ペーシング + TX 完了 500ms リカバリで
  往復レイテンシ大。Wi-Fi の SAI=300ms だとコントローラが応答到達前に再送し輻輳)。OTBR の
  SRP service に `TXT: [SII=10000, SAI=1000, T=0]` として登録されることを実測。`smctl onoff
  subscribe 5 20 1 1` で **CASE ESTABLISHED → SubscribeRequest → ESTABLISHED(subscription_id 付き)
  → `[report +20s] ep1 onoff/on-off = false`**(周期レポートが Thread/UDP 経由で到達)を実測。
  min=5/max=20s は安定、min=2/max=8s は priming が損失窓に当たると失敗しリトライ前提。

- **item 4: リンク品質改善 = DONE(数値改善あり)。**
  切り分けで **RESPONSE_TIMEOUT(OT err 28)** が SRP/Matter 応答取りこぼしの主因と判明
  (SRP はサーバ側で登録成功=fresh lease + 新 TXT が付くのに、DUT が応答を受けられず再送ループ→
  radio 負荷増→更なる沈黙→**~70 秒で executor ごとハング**)。RX 沈黙は自局 TX 直後に起きやすい
  (esp-radio 0.18 の 15.4 状態機械が TxAck 系 state から RX 再アーム不能に座礁、R9)。
  **改善策 = vendored `EspRadio::receive` の RX 再キック閾値を 5s → 1s に短縮**(`esp.rs`)。
  沈黙開始から 1s 以内に imm-ACK TX 経由で RX をフル再アームできるため、RTT<1s の応答取りこぼしが
  激減。**結果: ハングまでの生存が ~70s → 220s+ に延伸(ソーク継続中)、RESPONSE_TIMEOUT の再送
  churn がほぼ消滅、toggle/subscribe が成立**。副作用は静穏時 1s 毎 ~200µs airtime(デューティ
  ~0.02%)。根本修正は esp-radio 側(upstream 報告候補)。加えて T2 診断の毎 TX/RX の
  `info!("...large frame...")` は **USB-Serial-JTAG コンソールを飽和させリーダ未接続時に println で
  executor を止める**(ソーク不能の一因)ため `debug!` へ格下げ(コンソール flood 解消)。
  **残る損失**: 30-50% のフレーム損失は環境要因(距離/干渉、RCP 側ドロップ)込みで残り、CASE/
  subscribe は依然リトライ前提(`--timeout` 大 + 数回リトライ)。TX パワー/CCA/8ms ペーシングは
  今回は変更せず(ペーシング短縮は RCP 側ドロップとのトレードオフで T2 の結論を維持)。

- **item 2: fabric 増減時の SRP 再登録 = DONE(コード)/ carried-over(実機ゲート)。**
  pump に `resync_srp`(fabric generation 変化を検知 → `srp_remove_all` + 現行先頭 fabric で
  再登録、全 fabric 削除なら `srp_stop` で撤去)を実装。初回登録の後に AddNOC(追加 fabric)/
  RemoveFabric で instance 名(`<compressedFabricId>-<nodeId>`)が変わる場合に反応する。
  実機ゲートは 2 fabric 目のコミッショニング or RemoveFabric を要し(単一 fabric 削除は
  デコミッション = 稼働中ソークを壊す)、稼働系を保全するため今回は未実施(コードは build/clippy green)。

- **item 5: ScanNetworks(`ot.scan()`)= carried-over(未実装)。**
  `openthread::OpenThread::scan()` は **async(チャネルごと ~300ms、走査中は運用チャネルを離れる)**
  で、同期 Mealy machine の IM invoke から直接駆動できない。ConnectNetwork と同じ deferred 機構で
  「start_scan → poll_deferred で結果を ThreadInterfaceScanResult 配列にエンコード」する設計は
  ThreadDriver trait(コア)+ cluster(コア)+ pump の async 協調(port)の追加を要し、
  **検証済みのコア/運用系を壊すリスクが実装価値(chip-tool は既定でスキップ、現状は空成功シムで
  仕様上有効)を上回る**と判断し carried-over。現状は `ScanNetworks` は空結果 Success を返す。

- **item 6: chip-tool 相互 = carried-over(症状記録)。**
  ブロッカーは T2 で確定済みの **ホスト 5353 競合**(avahi + chip-tool + otbr native mDNS
  publisher が SO_REUSEPORT で 5353 共有 → QM 経路不達)。回避案(otbr を `OTBR_MDNS=avahi` で
  起動 / chip-tool の interface 制限)はいずれも **OTBR コンテナの再起動を要し、稼働中の DUT 接続と
  ソークを切断する**ため、稼働系保全を優先して今回は未実施。smctl パスは全ゲート green のため
  運用検証はカバー済み。推奨: 次回のメンテ窓で `OTBR_MDNS=avahi` ビルドの otbr を試す
  (RCP 圧迫 = HandleRcpTimeout の再発に注意)。

- **item 7: ソーク準備 = DONE(起動状態で残置)。**
  `scripts/otbr/soak.sh`(+ `soak-stop.sh`)を追加。①DUT シリアル取り込み ②`smctl onoff subscribe`
  を切断時 30s リトライで維持(セッション境界をログ)③10 分毎に OTBR の SRP server host lease と
  運用 read を観測 ―― を `soak-logs/<stamp>/` へ記録し続ける。stable firmware で起動済み
  (24h 判定は後日ログで)。リンク損失窓では subscribe が CASE Sigma1 段で落ち smctl が mDNS
  fallback(5353 で失敗)に回るため、良好窓を掴むまでリトライを繰り返す挙動。

**検証ゲート集計**: item 1(リブート永続化 + SRP 鍵保持)PASS、item 3(subscribe + SII/SAI)PASS、
item 4(RX 再キック 1s 化で 70s→220s+ 安定・数値改善)PASS、CASE over Thread(toggle, resumption)
再確認 PASS。item 2 コード done / 実機 carried-over、item 5 carried-over、item 6 症状記録。
ルート workspace test/clippy/riscv クロス + t2-light/thread-smoke/e5-light ビルド回帰 green。
コア(`crates/simple-matter`)は **T3 では無改造**(全変更は port + vendored openthread + scripts)。

**リスク表更新**: R6 は **解決**(write-back + idle flush で顕在化を根治)。R9 は RX 再キックの
1s 化で運用安定性が実用域に改善(根本は esp-radio、upstream 報告候補のまま)。

### I1(将来): ICD / Sleepy End Device

- openthread クレート側の sleepy 対応は「予定」段階(upstream)。`set_link_mode` で
  rx_on_when_idle=false にする MTD 運用 + Matter ICD cluster(LIT/SIT)を載せる。
  esp-radio 側の 15.4 省電力 API 成熟待ち。着手条件: upstream の sleepy support
  リリース + T3 完了。

## 8. リスク一覧

| # | リスク | 影響 | 緩和 |
|---|---|---|---|
| R1 | openthread 0.2.0 は若い(0.2 が実質初リリース)。API 改名進行中(srp→srp-client 等)、プリビルト .a と feature 組合せの罠 | 中 | バージョン固定(=0.2.0)。upstream の rs-matter 実績が同系統。改名は追従容易 |
| R2 | ~~**BLE + 802.15.4 の実行時同時動作が未検証**~~ **→ T2 実測で確定(2026-07-17)**: コミッショニング中の同時動作は**成立**(BLE/BTP 維持のまま attach + 遅延 ConnectNetworkResponse 配送)。ただし**常時 BLE 広告は 15.4 の RX/TX を恒常的に劣化させ、運用フェーズの CASE over Thread が成立しない** | 中(部分的に顕在化) | **運用フェーズは時分割**: コミッショニング完了(fabric 保有 + BLE 切断)後に BLE 広告を停止(`GattChannels::set_adv_enabled(false)`)。コミッショニング済み起動時は広告自体を抑止 |
| R3 | ~~**RCP ボードの USB-Serial-JTAG 問題**: ot_rcp 既定は UART。NanoC6 等 UART ブリッジ無しボードでは USB ポート越しに spinel が通らない~~ **→ 解決済み(T1 実測 2026-07-17)** | ~~中~~ 解消 | **`ot_rcp` を `CONFIG_OPENTHREAD_RCP_USB_SERIAL_JTAG=y` で再ビルドすれば spinel が USB-Serial-JTAG に出て NanoC6 の USB ポート越しに OTBR が接続できる**(`build-ot-rcp.sh` の `RCP_OVER_USB=1` 既定に実装)。外付け UART / DevKitC は不要。詳細は §7 T1 実機結果 |
| R9 | ~~**DUT が attach 数秒後に停止**(role→Child まで到達後、無線が止まる。T1 で発見)~~ **→ 実測で特定・ワークアラウンド済み(2026-07-17)**: 停止は **RX 方向のみ**(TX は正常 — 周期 UDP 送信は OTBR に届き続ける)。executor/embassy-time/OT 状態機械は全て生存(heartbeat 継続・role=Child 維持)。回復手段は**実 TX のみ**(tx_init の stop_current_operation → 完了後 next_operation の rx_init+enable_rx フル再初期化)。`start_receive()`(state==Receive/TxAck では no-op)や `ensure_receive_enabled`(RxStart 再発行)の周期実行では回復しないことを実測 → esp-radio 0.18 の 15.4 状態機械が RX 再アーム不能な状態に座礁している(TxAck 系 state の event 取りこぼしが有力。coex/ble feature・ログレベルは無関係と bisect 済み) | ~~高~~ 解消(暫定) | **vendored openthread(`ports/esp32/vendor/openthread`、[patch.crates-io])の `EspRadio::receive` に TX キックを実装**: RX シグナル 5 秒無音で宛先なし imm-ACK(3 バイト、他ノードは UnexpectedAck として破棄)を送出し TX 完了経路で RX を再初期化。無送信ソーク 225 秒 + ping / UDP echo / MLE keepalive 全て green を実測。**根本修正は esp-radio 側 = upstream 報告候補**(再現手順と切り分けログは §7 T1 実機結果)。**T2 追加**: ①tx_done/tx_failed イベント喪失で `transmit` が永久待ちになり radio タスク全体が停止する事象を発見 → 500ms タイムアウト + 同一 PSDU 再送出で回復。②RCP(spinel over USB-CDC)が back-to-back の 6LoWPAN 断片を auto-ack 後に取りこぼす(ACK 済みのため OT 再送なし)→ 64B 超フレーム送信後 8ms のペーシングで解消(§T2 実機結果) |
| R4 | Wi-Fi と Thread の同一 FW 共存不可(esp-radio 0.18 制約。§2.3) | 低(設計で吸収済み) | パッケージ分離済み。SKU 分割は製品慣行に一致 |
| R5 | フットプリント: OT + MbedTLS + simple-matter + BLE の合算が未計測(smoke 332KiB、e5-light 1.13MiB — 単純合算なら ~1.4MiB) | 低〜中 | 4MiB flash に対し余裕はあるが、T2 でサイズレポートを取り bloat-check の監視対象に追加 |
| R6 | ~~KvsSettings の flash 書き込みが 15.4/BLE 動作中のキャッシュ停止と干渉~~ ~~T2 実測で顕在化: attach 時の OT settings 書き込みバーストが 15.4 radio を回復不能停止させる(ping 100% loss)~~ **→ T3 で解決(2026-07-17)** | ~~高~~ 解消 | **write-back(RAM 権威 + idle 時 flush)で再導入(§T3 実機結果 item 1)**: OT の settings は RAM の `SettingsStore` で即応し flash に触れず、pump が radio 静穏窓(直近 UDP から 4s / attach から 10s / 前回から 60s)で **1 KVS アイテム(`otset`)を丸ごと 1 回 store** する。attach 時の書き込みバーストを RAM で吸収 = radio を止めない。リブート後は 323B を復元し dataset/NetworkInfo/**SRP ECDSA 鍵**を保持 → SRP 残留登録衝突を根治。実測: flush 直後も role=Child 維持 |
| R7 | OT 内部ヒープ(固定バッファ)の枯渇(SRP + UDP + DTLS 併用時) | 低 | `heap-int-<N>` で増量可。`buffer_info()` 相当の診断ログを T2 に仕込む |
| R8 | embassy-sync 二重化(既存 0.7 = trouble-host 系 / openthread 内部 0.8) | 低 | 型は互いに漏れない(検証済みビルド green)。トラブル時は trouble-host 更新と合わせ 0.8 系へ統一検討 |

## 9. 実機フェーズでユーザに依頼すること

1. **ボード 2 枚の確定と接続**: RCP 用 C6(UART ブリッジ有無を教えてください —
   NanoC6 なら R3 の確認から)+ DUT 用 C6。それぞれのポート名(/dev/ttyACM?)。
2. RCP 書き込み: `espflash write-bin 0x0 scripts/otbr/dist/ot_rcp/merged_ot_rcp.bin --port <RCP ポート>`
   (実行はこちらで可能。ポート名の指定と、書き込み許可だけください)。
3. OTBR 起動〜join スモーク(`scripts/otbr/README.md` の手順 3〜5)は
   こちらで実施 → T1 ゲート判定。
