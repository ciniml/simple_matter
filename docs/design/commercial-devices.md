# 市販 Matter デバイス対応 設計・計画

status: **検討のみ(コード未変更)**、2026-08-27

対象コントローラ: simple_matter コア(`crates/simple-matter`)+ C-FFI シム
(`crates/simple-matter-cffi`)+ Tab5 アプリ
(`ports/esp-idf/examples/tab5_ctrl_app`)。

対象デバイス:

- **(a) TP-Link Tapo P110M** — Matter over Wi-Fi のスマートプラグ(OnOff +
  電力/電力量計測)
- **(b) Aqara Door and Window Sensor P2** — Matter over Thread の電池駆動
  開閉センサ(BooleanState、ICD/sleepy end device)

---

## 0. 結論(サマリ)

1. **アテステーションは障害にならない。** 本作業では方針として
   **DAC/PAI/CD を一切検証しない**。コアには `AttestationPolicy::Skip` が既にあり、
   Skip では AttestationRequest / CertificateChainRequest を**発行すらしない**
   (`commissioner.rs:477-482`)。そして **シム(= Tab5 の全経路)は既に
   `Skip` 固定**(`crates/simple-matter-cffi/src/controller.rs:1653, 2630`)。
   → **差分ゼロ。DCL からの PAA 取り込みも PAA トラストストアの組み込みも不要。**
   むしろ「シムから `Verify` を選べないこと」が今回は好都合であり、**変更しない**
   ことが最小差分である(§4.1)。

2. **P110M(先行)を阻む実質的なギャップは 4 点**で、いずれも小〜中規模:
   - **オンボーディング情報の入力経路**: 市販機は QR / 11 桁 manual code でしか
     passcode を配布しない。コアに**デコーダが無い**(生成側だけ)。さらに manual
     code は **4 ビットの short discriminator** しか含まないので、BLE 広告の
     照合を 12 ビット完全一致から short 一致へ拡張する必要がある。
   - **ConnectNetwork の遅延応答**: IM トランザクションが一律 30 秒
     (`im/client.rs:61 CLIENT_TXN_TIMEOUT_MS`)。市販 Wi-Fi 機は
     ConnectNetworkResponse を**接続完了後**に返すため 30 秒では足りないことがある。
   - **SetRegulatoryConfig 未送信**(コントローラは一度も送らない)。仕様上は
     コミッショナが送るべきステップで、市販機が RegulatoryConfig 既定値のままだと
     Wi-Fi の規制動作が未確定になる。低コストで足すべき。
   - **電力/電力量クラスタ(0x0090 / 0x0091)がコア・シム・Tab5 のどこにも無い**。
     特に **0x0091 の値は struct** なので、シムの `sm_ctrl_read_scalar` では
     **原理的に読めない**(スカラ専用)。シムに struct/list 対応の読み口が要る。

3. **P2(後続)の本丸は ICD ではなく MRP パラメータ。**
   P2 は DCL 上 **Matter 1.0 認証(SW 1.0.0)の SIT 系 SED** で、slow poll ≤ 15 秒で
   常時到達可能なため、**check-in / RegisterClient を実装しなくても登録・購読は
   成立するはず**。一方コアは **SII/SAI/SAT を mDNS/SRP TXT からも Sigma1/Sigma2
   からも読まず、全ピアに対して SAI=300ms 固定で再送する**
   (`exchange/mrp.rs`、`ExchangeManager::set_config` は**呼び出し元ゼロ**)。
   これは SED 相手に致命的(過剰再送 → 子の受信キュー溢れ・電池消耗・誤タイムアウト)。
   **P2 対応 = MRP パラメータの読み取りと適用**が第一項目。

4. **種別判定は当たり判定 probe から Descriptor 読取へ切り替えるべき。**
   現状 `resolve_node_kind`(`ctrl_pump.cpp:1039`)は「AirQuality が読めれば
   SENSOR / OnOff が読めれば LIGHT / それ以外 UNKNOWN」。市販機は
   PLUG(0x010A)も CONTACT(0x0015)も **UNKNOWN に落ちて UI に出ない**。
   Descriptor(0x001D)の PartsList / DeviceTypeList を読む方式に変えるのが本筋で、
   これも **list/struct 読み口**(2 の 4 番目)と同じ基盤を共有する。

5. 工数の目安(§6): **P110M で 6〜9 人日、P2 で 5〜8 人日**。共通基盤(list/struct
   読み口 + Descriptor 判定)が 3〜4 人日でその大半を占める。

---

## 1. デバイス調査

### 1.1 TP-Link Tapo P110M

DCL(CSA Distributed Compliance Ledger)の一次データ:

| 項目 | 値 | 出典 |
|---|---|---|
| Vendor ID | **5010(0x1392)** "TP-Link" | `https://on.dcl.csa-iot.org/dcl/model/models`(partNumber=`P110M`) |
| Product ID | **257〜268 の連番**(0x0101〜0x010C。地域別 SKU) | 同上 |
| DeviceTypeId | **266 = 0x010A(On/Off Plug-in Unit)** | 同上 |
| 認証 SW | 1.0.0(2023-03-16)/ **1.3.0(2025-03-05)** | `https://on.dcl.csa-iot.org/dcl/compliance/compliance-info/5010/261/66304/matter` |
| specificationVersion | **0x01030000 = Matter 1.3**(SW 1.3.0) | 同上 |
| transport | **`wi-fi,bluetooth`** | 同上 |
| CD 証明書 ID | `CSA2510DMAT45151-24`、certificationRoute `portfolio` | 同上 |
| commissioningCustomFlow | **0(標準フロー)** | model レコード |
| commissioningModeInitialStepsInstruction | `"10"`(ボタン 10 秒長押しで工場出荷 → 広告) | 同上 |
| userManualUrl(pid 261) | `https://www.tp-link.com/hk/support/faq/3520/` | 同上 |

クラスタ構成(Matter Alpha の認証情報ページ、および DCL の deviceTypeId):

- Endpoint 数 **1**、EP1 に **On/Off(0x0006)**、Groups(0x0004)、
  **ElectricalPowerMeasurement(0x0090)**、
  **ElectricalEnergyMeasurement(0x0091)**、AccessControl、GeneralDiagnostics。
  出典: `https://www.matteralpha.com/tapo/tapo-smart-plug-energy-monitoring-p110m-p231`
- ただし **0x0090 / 0x0091 は SW 1.3.0(Matter 1.3)ファームでのみ現れる**。
  1.0.x / 1.1.x 出荷個体には**電力系クラスタが無い**という実測報告がある:
  「デバイス側も新規の Electrical Power Measurement (0x0090) および
  Electrical Energy Measurement (0x0091) クラスタを備えていません」
  出典: `https://community.home-assistant.io/t/tapo-p110m-energy-monitoring/736975`
- 電力系エンドポイントの見え方には個体差の報告がある(Home Assistant で
  Power 側エンドポイントがセンサ化されず、Total Energy / Energy Exported /
  Power(W)しか出ない、RMS 電圧・電流・周波数が出ない):
  出典: `https://github.com/home-assistant/core/issues/149847`

コミッショニング経路:

- **BLE 必須**。「automatically detect via Bluetooth for initial configuration and
  connect to your home's 2.4 GHz Wi-Fi network」
  出典: `https://www.tp-link.com/us/home-networking/smart-plug/tapo-p110m/`
- **2.4 GHz Wi-Fi のみ**(5 GHz 不可)。同上。
- QR コード + manual code が同梱。「scanning the included code with any
  Matter-compatible app」出典: `https://us.store.tapo.com/products/tapo-p110m-4-pack`

既知の癖:

- ファームウェアが Matter 1.3 に上がるまで電力系クラスタが無い
  (`community.home-assistant.io/t/736975`)。**実機で先に Descriptor を読んで
  ServerList を確認するのが確実**。
- Home Assistant 2026.1 以降、個体によってエネルギー値が出なくなる報告:
  `https://community.home-assistant.io/t/matter-smart-plugs-losing-energy-reporting-capability/972984`

### 1.2 Aqara Door and Window Sensor P2

DCL の一次データ:

| 項目 | 値 | 出典 |
|---|---|---|
| Vendor ID | **4447(0x115F)** "Aqara"(Lumi United Technology) | `https://on.dcl.csa-iot.org/dcl/vendorinfo/vendors` |
| Product ID | **8194(0x2002)**、partNumber `AS056` | `https://on.dcl.csa-iot.org/dcl/model/models` |
| DeviceTypeId | **21 = 0x0015(Contact Sensor)** | 同上 |
| 登録 SW バージョン | 1000 / 1011 / 1020 | `https://on.dcl.csa-iot.org/dcl/model/versions/4447/8194` |
| 認証済み SW | **1000(= "1.0.0.0")のみ**。1011 / 1020 は compliance-info **not found** | `https://on.dcl.csa-iot.org/dcl/compliance/compliance-info/4447/8194/1000/matter` |
| specificationVersion | **0x01000000 = Matter 1.0**、認証日 2022-11-03、`fullTested` | 同上 |
| transport | **`thread,bluetooth`** | 同上 |
| icdUserActiveModeTriggerHint | **0**(DCL に登録なし) | model レコード |

デバイス特性:

- Thread 上の **電池駆動 end device**。「It sleeps to save battery, so it can't
  route for other Thread devices」
  出典: `https://community.home-assistant.io/t/aqara-p2-sensors-status-changes-to-unavailable/739099`
- **Thread Border Router + Matter コントローラが必須**。
  出典: `https://us.aqara.com/products/door-and-window-sensor-p2`
- コミッショニング経路は **BLE**(DCL transport に `bluetooth`)+ Thread dataset。
  QR / manual code 同梱。

ICD の種別(重要な推定):

- 認証が **Matter 1.0** である以上、**LIT(Long Idle Time)ではありえない**。
  LIT ICD は Matter 1.3 で機能が入り、**1.4 で認証可能**になった機能である。
  「Long Idle Time ICDs are ready for integration in the Matter 1.3 release …
  LIT ICDs should be certifiable with the Matter 1.4 release」
  出典: `https://docs.silabs.com/matter/latest/matter-overview-guides/matter-icd`
- したがって P2 は **SIT ICD(= 従来の SED)**。SIT の要件は
  「transport slow poll configuration must be smaller or equal to 15s」(同上)。
  → **常時到達可能**であり、Check-In Protocol / RegisterClient を実装しなくても
  CASE・Read・Subscribe は成立する。
- ただし **出荷ファーム 1011 / 1020 は DCL に compliance-info が無い**ため、
  仕様バージョンが上がっている可能性は否定できない。**実機の
  ICDManagement(0x0046)FeatureMap を読んで CIP/LITS ビットを確認する**のを
  P2 着手時の最初のゲートにする(§6.2 G1)。

既知の癖:

- Home Assistant で **頻繁に unavailable になる**:
  `https://github.com/home-assistant/core/issues/117386`、
  `https://community.home-assistant.io/t/aqara-door-and-window-sensor-p2-with-thread-and-matter-becomes-unavailable-and-comes-back-als-the-time/590222`
- ログに `Previous subscription failed with Error: 50, re-subscribing` が出る =
  **購読の liveness タイムアウト**。原因は Thread メッシュのカバレッジと、
  コントローラ側の購読タイムアウト設定であるとされる:
  `https://community.home-assistant.io/t/aqara-p2-sensors-status-changes-to-unavailable/739099`
  → **我々の `SUBSCRIPTION_GRACE_MS = 30_000` と max_interval の選び方が直接効く**
  (§4.4)。
- **電池が数日で消耗する**報告:
  `https://forum.aqara.com/t/p2-sensor-dies-quickly-no-battery-within-days-matter-apple-home-assistant/65130`
  → コントローラ側の過剰再送・過剰な購読再確立が電池を焼く。**MRP パラメータの
  尊重が電池寿命に直結する**(§4.3)。

### 1.3 コミッショニングの標準ステップ(照合基準)

chip(connectedhomeip)の `CommissioningStage` 列挙を基準表とする。
出典: `https://raw.githubusercontent.com/project-chip/connectedhomeip/master/src/controller/CommissioningDelegate.h`

`kSecurePairing` → `kReadCommissioningInfo` → `kArmFailsafe` →
`kConfigRegulatory` → `kConfigureUTCTime` / `kConfigureTimeZone` /
`kConfigureDSTOffset` / `kConfigureDefaultNTP` → `kSendPAICertificateRequest` →
`kSendDACCertificateRequest` → `kSendAttestationRequest` →
`kAttestationVerification` → `kSendOpCertSigningRequest` → `kValidateCSR` →
`kGenerateNOCChain` → `kSendTrustedRootCert` → `kSendNOC` →
`kICDGetRegistrationInfo` → `kICDRegistration` →
`kWiFiNetworkSetup` / `kThreadNetworkSetup` →
`kFailsafeBeforeWiFiEnable` / `kFailsafeBeforeThreadEnable` →
`kWiFiNetworkEnable` / `kThreadNetworkEnable` →
`kFindOperationalForCommissioningComplete` → `kSendComplete` →
`kICDSendStayActive` → `kCleanup`

---

## 2. 現状のコントローラ実装(コードで確認した事実)

### 2.1 コミッショニング状態機械

`crates/simple-matter/src/controller/commissioner.rs`。`Phase`(L146-181):

```
Idle → Pase → ArmFailSafe → Attestation(Skip は素通し) → Csr
     → AddTrustedRoot → AddNoc
     → [AddWifiNetwork → ConnectNetwork]   (Wi-Fi/Thread 資格情報があるときのみ)
     → Case → Complete → Done{session}
```

- `ArmFailSafe`: `FAIL_SAFE_EXPIRY_S = 300`(L71)、breadcrumb=0(L543)。
- `AddNoc`(L630-661): cx0=NOC、cx2=IPK、cx3=CaseAdminSubject、cx4=AdminVendorId。
  **cx1(ICACValue)は送らない**= ICAC 無しの 2 階層 PKI。
- `AddWifiNetwork` フェーズは **Thread の AddOrUpdateThreadNetwork にも流用**
  (L686-706。名前だけ Wi-Fi)。NetworkID は Wi-Fi=SSID、Thread=ExtPanID。
- `ConnectNetwork` 応答は `networkingStatus==0` を見るだけで、
  **「即 Success + バックグラウンド join」を前提**とコメントされている(L864-866)。
- **ACL 書き込みはコントローラからは行わない。** デバイス側が AddNOC の
  caseAdminSubject から bootstrap admin ACL を生成する
  (`dm/clusters/operational_credentials.rs:552-604`)。これは仕様どおりで
  chip-tool も同じ。**市販機も同様に自動生成するので追加作業不要。**
- 失敗時に **ArmFailSafe(expiry=0)を送らない**。`enter_failed`(L1068)は
  フェーズを `Failed` にするだけで、デバイス側の 300 秒期限切れ待ち。

**未実装**: SetRegulatoryConfig / ScanNetworks / TimeSync(SetUTCTime 等) /
ReadCommissioningInfo 相当の wildcard read / BasicCommissioningInfo 読取 /
Breadcrumb のステージ運用 / RemoveFabric ロールバック。

### 2.2 アテステーション

- `AttestationPolicy { Skip, Verify { paa_store } }`(L78-90)。
- **`Skip` は AttestationRequest / CertificateChainRequest を発行しない**
  (L477-482 でフェーズを素通し)。
- **シムは `Skip` 固定**: `controller.rs:1653`(`sm_ctrl_pair_start`)、
  `controller.rs:2630`(`sm_ctrl_ble_pair_start`)。`Verify` はシムの API 表面に
  露出していない。
- `Verify` 側(smctl 専用)は DAC←PAI←PAA 検証・attestation 署名・nonce エコー・
  CD の CMS 署名・VID/PID 一致まで実装済みだが、PAA は呼び出し側が DER 配列で
  渡す設計で、**本番 PAA は 1 枚も同梱していない**。CD 署名者テーブル
  `KNOWN_CD_SIGNERS`(`cert/cms.rs:60`)も chip テスト鍵 + CSA "Signing Key 001"
  の 2 本のみ。

### 2.3 ICD

- `crates/simple-matter/src/icd.rs`(1033 行)+
  `dm/clusters/icd_management.rs` は **全てデバイス側**。
  `controller/` と `simple-matter-cffi/src/controller.rs` に ICD の文字列は
  **1 件も無い**。
- コントローラ側にあるのは smctl の検査コマンドのみ:
  `smctl icd checkin-listen`(UDP を listen して check-in を復号し ICDCounter 表示)、
  `smctl icd-management register-client`(手動 RegisterClient)。
- check-in の **鍵導出 info ラベルが独自**(`b"SimpleMatter ICD Check-In AES/HMAC Key"`、
  `docs/design/icd.md:330-339`)ため、**chip 互換性は未保証**。
  → 市販 ICD の check-in を受けるには、まずこのラベルを仕様準拠にする必要がある。

### 2.4 MRP

- `exchange/mrp.rs`: `MrpConfig { idle_interval_ms, active_interval_ms,
  active_threshold_ms }`。既定は idle=5000ms / active=300ms。
  再送のベース間隔には **`active_interval_ms` しか使っていない**(L64-84)。
- 適用口 `ExchangeManager::set_config`(`exchange/exchange.rs:339`)の
  **呼び出し元がリポジトリ内にゼロ**。
- `discovery.rs` の SII/SAI は **広告(送信)専用**。TXT の**パース側に
  SII/SAI/SAT の処理が無い**。
- Sigma1 の MRP session parameters(cx5)も**読み飛ばしているだけ**
  (`sc/case/responder.rs:188`)。

→ **全ピアに SAI=300ms 固定**。最大 10 送信・累計 ~34 秒(`im/client.rs:79`)。

### 2.5 購読

- コア `im/client.rs`: `MAX_CLIENT_SUBSCRIPTIONS = 4`(L72)、
  `CLIENT_TXN_TIMEOUT_MS = 30_000`(L61)、
  **`SUBSCRIPTION_GRACE_MS = 30_000`**(L80)。
  ロスト判定 = `last_report + max_interval_s*1000 + GRACE`。
- シム: `sm_ctrl_subscribe` / `sm_ctrl_subscribe_paths` / `sm_ctrl_unsubscribe` /
  `sm_ctrl_is_subscribed`、イベント `SM_CTRL_EV_SUBSCRIPTION_LOST`。
- Tab5(`ctrl_pump.cpp:1056 do_subscribe_node`): LIGHT は OnOff 1 パス
  `min=0 / max=60`、SENSOR は 5 パス `min=1 / max=60`。
- `sm_ctrl_unsubscribe` は**デバイスへ何も送らない**ローカル破棄
  (デバイス側は max_interval で自然消滅を待つ)。

### 2.6 Tab5 の種別判定と UI

- `app_state.hpp:66-72`: `SM_UI_KIND_UNKNOWN=0 / LIGHT=1 / SENSOR=2` の **3 種のみ**。
- `probe_node_kind`(`ctrl_pump.cpp:1023`): EP1/0x005B/0 が読めれば SENSOR、
  EP1/0x0006/0 が読めれば LIGHT、両方失敗で UNKNOWN。
  **Descriptor(0x001D)は一切読まない。**
- センサスロットは `SENSOR_ATTRS`(`ctrl_pump.cpp:174`)の 5 本固定
  (AQ / CO2 / PM2.5 / 温度 / 湿度)。
- シムの読み口 `sm_ctrl_read_scalar`(`controller.rs:1834`)は
  **パスは任意だが値はスカラのみ**(list / struct は返せない)。
- 種別は NVS にキャッシュ(`kind_cache_set`、`ctrl_pump.cpp:594`)。

### 2.7 Thread

- `ot_hub.cpp/hpp`: Tab5(ESP32-P4)+ Unit Gateway H2 の **RCP over UART**。
  `sm_ot_hub_form_network()` で **Tab5 自身が leader**、**SRP サーバも有効化**。
- BLE-Thread 導線(`ctrl_pump.cpp:1937 do_pair_ble`):
  `sm_ot_hub_dataset_hex()` で active dataset TLV を取り出し、hex→バイトにして
  `sm_ctrl_ble_pair_start(node_id, passcode, kind=1, dataset, len, …)` へ渡す。
- handoff(`ctrl_pump.cpp:2085-2102`): BLE 切断後 `sm_ot_hub_srp_lookup()` を
  2 秒間隔で最大 60 回(~120 秒)。取れたら `feed_addr_as_mdns()` で
  **SRP の結果を「mDNS 応答の形」に仕立ててシムへ食わせる**(シムに SRP 経路が
  無いためのアダプタ)。
- Thread 経路では mDNS ソケットを開かない(`ctrl_pump.cpp:2049-2051`)。

### 2.8 クラスタ定義

| クラスタ | コア(サーバ) | smctl(クライアント) | シム/Tab5 |
|---|---|---|---|
| OnOff 0x0006 | あり | あり | Tab5 が直接パス指定で使用 |
| BooleanState 0x0045 | あり | あり | **未使用** |
| Descriptor 0x001D | あり | あり | **未使用** |
| ElectricalPowerMeasurement 0x0090 | **無し** | **名前のみ**(`clusters/names.rs:79`) | 無し |
| ElectricalEnergyMeasurement 0x0091 | **無し** | **名前のみ**(`names.rs:80`) | 無し |
| PowerSource 0x002F(電池残量) | 未確認/無し | 無し | 無し |

**汎用の属性読み取り経路は 3 層とも存在する**(`ControllerStack::start_read` /
`smctl any read` / `sm_ctrl_read_scalar`)。ただし **シム層だけスカラ限定**。

---

## 3. ギャップ表

凡例: ◎ = そのまま使える / △ = 小改修 / ✕ = 新規実装

### 3.1 共通 / P110M(Wi-Fi プラグ)

| # | 要件 | 現状 | 差分 | 対応箇所 |
|---|---|---|---|---|
| C1 | **アテステーションを検証せず登録できる** | `AttestationPolicy::Skip` が既定、シムは Skip 固定(`controller.rs:1653, 2630`)。Skip では要求すら出さない | ◎ **差分なし**。方針として `Verify` をシムに露出しない | — |
| C2 | QR / manual code から passcode・discriminator を得る | `onboarding.rs` は **生成のみ**(`manual_pairing_code` / `qr_payload`)。**デコーダ無し**。Tab5 UI は数値手入力(`ui.cpp:380-395`) | ✕ manual code(11/21 桁)デコーダ、任意で QR base38 デコーダ | `discovery/onboarding.rs`、シム `sm_ctrl_parse_onboarding`、`ui.cpp` |
| C3 | **short discriminator(4 bit)での BLE 広告照合** | `sm_ctrl_match_adv` は 12 bit 完全一致 | △ 上位 4 bit のみの照合モードを追加 | `controller.rs sm_ctrl_match_adv`、`ble_central.cpp` |
| C4 | SetRegulatoryConfig(0x0030/0x02) | **未送信** | ✕ `Phase::SetRegulatory` を ArmFailSafe と Attestation の間に追加。`{0:location=Indoor(0), 1:countryCode="JP", 2:breadcrumb}` | `commissioner.rs`(Phase 追加 + emit + consume) |
| C5 | BasicCommissioningInfo を読んで FailSafe 秒をクランプ | 300 秒ハードコード | △ 省略可(300 ≤ 仕様上限 900)。読むなら struct 読みが必要 | `commissioner.rs:71` |
| C6 | **ConnectNetwork の遅延応答**(接続完了後に応答) | IM 一律 30 秒(`im/client.rs:61`)、MRP 最大 10 送信 ≈34 秒 | ✕ フェーズ別タイムアウト。ConnectNetwork は **60〜90 秒** | `im/client.rs`(`start_invoke` に timeout 引数)、`commissioner.rs` |
| C7 | ScanNetworks | **未送信** | ◎ **不要**。SSID/パスフレーズは Tab5 が既に持っている | — |
| C8 | TimeSync(SetUTCTime) | **未実装** | ◎ P110M は TimeSynchronization を持たない(DCL/Matter Alpha のクラスタ一覧に無い)ので**不要**。ただし §7 R4 参照 | — |
| C9 | ACL の書き込み | コントローラからは書かない。デバイスが AddNOC から自動生成 | ◎ **不要**(仕様どおり、chip-tool と同じ) | — |
| C10 | 失敗時の FailSafe 明示解除 | 送らない(300 秒待ち) | △ 望ましいが必須でない。**再試行が 5 分待ちになる**運用上の痛み | `commissioner.rs enter_failed` |
| C11 | **Descriptor による種別判定** | 当たり判定 probe(`probe_node_kind`)。PLUG も CONTACT も UNKNOWN | ✕ EP0 PartsList → 各 EP の DeviceTypeList を読む | `ctrl_pump.cpp`、シムに list 読み口 |
| C12 | **list / struct 属性の読み取り** | シムは **スカラのみ**(`sm_ctrl_read_scalar`) | ✕ list-of-u32 / struct-field 読み口の追加 | `simple-matter-cffi/src/controller.rs` |
| C13 | ElectricalPowerMeasurement 0x0090 の ActivePower(0x0008、int64 mW) | クラスタ定義なし。ただし**パス直指定でスカラ読みは可能** | △ Tab5 側のスロット・単位・表示追加のみ | `app_state.hpp`、`ctrl_pump.cpp`、`ui.cpp` |
| C14 | ElectricalEnergyMeasurement 0x0091 の CumulativeEnergyImported(0x0001) | **struct(EnergyMeasurementStruct)** なので `read_scalar` では**読めない** | ✕ C12 の struct 読み口が前提 | 同上 + シム |
| C15 | PLUG 種別の UI(On/Off トグル + W / kWh 表示) | LIGHT のトグルは既存 | △ `SM_UI_KIND_PLUG` 追加、スロット拡張 | `app_state.hpp:66`、`ui.cpp:797, 959-1014` |
| C16 | 購読パス数 | `SM_UI_SLOT_COUNT = 5`、`MAX_CLIENT_SUBSCRIPTIONS = 4` | △ プラグは OnOff + ActivePower + Energy の 3 パス。**ノード数 4 で購読が枯れる**点に注意 | `im/client.rs:72` |

### 3.2 P2(Thread / SIT ICD 開閉センサ)

| # | 要件 | 現状 | 差分 | 対応箇所 |
|---|---|---|---|---|
| T1 | BLE-Thread コミッショニング(dataset 渡し) | 実装済み・実機実績あり(`do_pair_ble` + `sm_ot_hub_dataset_hex`) | ◎ **そのまま使えるはず** | — |
| T2 | SRP による運用アドレス解決 | `sm_ot_hub_srp_lookup` + `feed_addr_as_mdns` | ◎ 市販機も SRP に登録するので同じ経路。**インスタンス名の照合ロジックが node_id 16 hex 前提**な点だけ要確認 | `ot_hub.cpp`、`ctrl_pump.cpp:1752` |
| T3 | **MRP パラメータ(SII/SAI/SAT)の尊重** | mDNS/SRP TXT も Sigma も**読まない**。SAI=300ms 固定。`set_config` 呼び出し元ゼロ | ✕ **最重要**。TXT パース + Sigma1/2 の session params パース + `set_config` 配線 + **idle/active の切替**(応答受領前は idle、`active_threshold_ms` 内は active) | `discovery.rs`(パース)、`sc/case/*`、`exchange/mrp.rs`、`exchange/exchange.rs:339`、`controller/mod.rs` |
| T4 | Thread SED が Tab5 に子として attach | Tab5 は leader(router)なので親になれる | △ `otThreadSetChildTimeout` / child table 容量を確認。RCP(H2)側のバッファも | `ot_hub.cpp` |
| T5 | ICD RegisterClient / check-in 受信 | コントローラ側ゼロ。check-in の鍵導出ラベルが**独自 = chip 非互換** | ◎→△ **P2 が SIT なら不要**(§1.2)。実機で CIP/LITS が立っていたら ✕(ラベル修正 + 受信配線) | `icd.rs:293/339`、`controller/`、シム |
| T6 | **sleepy device 向けの購読 interval** | Tab5 は max=60 固定、GRACE=30s | ✕ CONTACT は `min=0 / max=600〜1800`。デバイスが返す `max_interval_s`(`SubscribeDone`)を**採用してロスト判定に使う**(既にイベントで返っている) | `ctrl_pump.cpp:1056`、`im/client.rs:179` |
| T7 | BooleanState 0x0045 / StateValue(0x0000、bool) | コアにサーバ実装あり、クライアント側は汎用 read で可 | △ Tab5 のスロット・表示のみ。**Contact Sensor では StateValue=TRUE が「閉(接触あり)」**である点に注意 | `app_state.hpp`、`ui.cpp` |
| T8 | CONTACT 種別の判定 | UNKNOWN に落ちる | ✕ C11 と同じ(Descriptor 判定) | `ctrl_pump.cpp:1039` |
| T9 | 電池残量(PowerSource 0x002F / BatPercentRemaining 0x000C) | 実装なし | △ スカラ読みで可(u8、0.5% 単位) | Tab5 |
| T10 | 購読ロスト時の再確立 | LOST → CASE 無効化 → 再購読(`5db6c2d`) | △ **SED では再確立が高コスト**。バックオフ(指数、上限 10 分)を入れないと HA と同じ電池消耗を再現する | `ctrl_pump.cpp`、`im/client.rs` |

---

## 4. 設計

### 4.1 アテステーション: 「検証しない」を明示的な既定として固定する

- **コード差分なし。** シムは既に `AttestationPolicy::Skip` を渡している。
- `Skip` はコミッショニング手順から attestation ステップ自体を落とすが、
  **これは仕様上コミッショナ側の裁量**であり、デバイスは AttestationRequest が
  来ないことを理由に拒否しない(市販機も同じ)。
- **やること**は 2 点だけ:
  1. `docs/design/attestation.md` に「市販機の登録では Skip を既定とする」旨の
     追記(本 doc への参照)。
  2. Tab5 の登録完了ログに「attestation: skipped」を出す(誤解防止)。
     — 任意、`ctrl_pump.cpp` 1 行。
- **やらないこと**: DCL からの PAA 取得、PAA トラストストアの組み込み、
  CD 署名者テーブルの拡張、シムへの `Verify` 露出。
- 参考(将来必要になったときの手順のみ記録): chip の
  `fetch-paa-certs-from-dcl.py` が本番 PAA を `credentials/production/paa-root-certs`
  に落とし、`--paa-trust-store-path` で指す。
  出典: `https://github.com/project-chip/connectedhomeip/blob/master/examples/chip-tool/README.md`

### 4.2 コミッショニング手順の補完

`Phase` を 2 つ足す(既存 `stage_code` の末尾に採番して観測互換を保つ):

```
Pase → ArmFailSafe → SetRegulatory(新) → Attestation(Skip 素通し) → Csr
     → AddTrustedRoot → AddNoc
     → [AddWifiNetwork → ConnectNetwork(タイムアウト延長)]
     → Case → Complete → Done
```

- **SetRegulatoryConfig**(0x0030/0x02):
  `{0: NewRegulatoryConfig=Indoor(0), 1: CountryCode="JP", 2: Breadcrumb=0}`。
  応答は `{0: ErrorCode, 1: DebugText}`。ErrorCode≠0 は**警告に留めて続行**
  (国コード非対応機で止めない)。カントリコードは Kconfig で可変に。
- **ConnectNetwork のタイムアウト**: `ControllerStack::start_invoke` に
  `txn_timeout_ms` を追加(既定 `CLIENT_TXN_TIMEOUT_MS`)、ConnectNetwork では
  **90_000** を渡す。あわせて MRP 再送は「応答待ちの間も継続」で問題ないが、
  `FAIL_SAFE_EXPIRY_S=300` の範囲に収まることを確認する。
- **失敗時の FailSafe 解除**(任意、C10): `enter_failed` の前に PASE セッションが
  生きていれば ArmFailSafe(expiry=0) を best-effort で 1 発撃つ。撃てなければ従来どおり。

### 4.3 MRP パラメータの読み取りと適用(P2 の本丸)

3 つの入口すべてを埋める:

1. **mDNS / SRP TXT のパース**: `discovery.rs` の Operational レコード解釈に
   `SII`(idle interval ms)/ `SAI`(active interval ms)/ `SAT`(active threshold ms)
   の読み取りを追加。現状は広告側にしかコードが無い。
2. **CASE Sigma1 / Sigma2 の session parameters(cx5)**: 現状「読み飛ばす」処理を
   「読み取って保持する」に変える(`sc/case/*`)。TXT より優先度が高い(より新しい)。
3. **適用**: `ControllerStack` が CASE 確立時に
   `ExchangeManager::set_config(exchange_id, MrpConfig{..})` を呼ぶ。
   現状 `set_config` は**呼び出し元ゼロ**なので、ここが初の利用者になる。

あわせて **`mrp.rs` の再送間隔選択を仕様準拠に**する:

- 直近にピアからメッセージを受けてから `active_threshold_ms` 以内 → `active_interval_ms`
- それ以外 → **`idle_interval_ms`**(現状は常に active を使っている)

SII が 15000ms(SIT の上限)の P2 に対しては、初回送信の再送が 15 秒間隔になり、
子のポーリング周期と噛み合う。これで「過剰再送 → 子の受信キュー溢れ → 電池消耗」
が解消するはず。

**副作用の注意**: 既存の自作デバイス(ESP32-C6 など)は SII/SAI を広告している
可能性があるため、**適用後に Tab5 の既存 pump のレイテンシが変わる**。
既存機の実測(§6 のゲート)で回帰確認する。

### 4.4 購読の設計(sleepy device 対応)

- **max_interval はデバイスが決める**。`SubscribeResponse` の
  `max_interval_s` は既に `ImEvent::SubscribeDone { subscription_id, max_interval_s }`
  で返ってきている(`im/client.rs:863`)。**ロスト判定にこの値を使う**
  (現在は購読要求時の ceiling を使っている疑いがあるので要確認・修正)。
- Tab5 の要求値:

  | 種別 | パス | min | max |
  |---|---|---|---|
  | LIGHT | OnOff | 0 | 60 |
  | SENSOR | 5 パス | 1 | 60 |
  | **PLUG(新)** | OnOff / ActivePower / CumulativeEnergyImported | 0 | 60 |
  | **CONTACT(新)** | BooleanState.StateValue(+ BatPercentRemaining) | 0 | **900** |

- `SUBSCRIPTION_GRACE_MS = 30_000` は現状 SED には短い。
  **`max(30s, max_interval_s * 1000 / 2)`** のような相対グレースにする。
- **再購読のバックオフ**: LOST → 即再購読を繰り返すと SED の電池を焼く。
  `1s → 2s → 4s → … → 600s` の指数バックオフ(ノード単位)を `ctrl_pump.cpp` に入れる。
- `MAX_CLIENT_SUBSCRIPTIONS = 4` は PLUG(3 パスだが購読は 1 本)を足しても
  **ノード 4 台で枯れる**。Tab5 の想定台数に応じて 8 へ引き上げる(RAM 影響を計測)。

### 4.5 list / struct 属性の読み口(シム)

Tab5 が Descriptor と ElectricalEnergyMeasurement を扱うために必須。
`sm_ctrl_read_scalar` と同じ非同期 op モデルで 2 本足す:

```c
/* list<u32> を読む(Descriptor.PartsList=list<endpoint-no>,
   Descriptor.DeviceTypeList=list<struct{0:DeviceType u32, 1:Revision u16}>)。
   struct 要素のときは field_tag で取り出すフィールドを指定する。
   field_tag < 0 なら要素そのものをスカラとして扱う。 */
int32_t sm_ctrl_read_list_u32(uint64_t node_id, uint16_t endpoint,
                              uint32_t cluster, uint32_t attribute,
                              int32_t field_tag, uint64_t now_ms);
/* 結果は SM_CTRL_EV_LIST_U32 で最大 N 要素を返す(N=16 程度) */

/* struct の 1 フィールドを i64 として読む
   (ElectricalEnergyMeasurement.CumulativeEnergyImported の cx0 = energy mWh) */
int32_t sm_ctrl_read_struct_i64(uint64_t node_id, uint16_t endpoint,
                                uint32_t cluster, uint32_t attribute,
                                uint32_t field_tag, uint64_t now_ms);
```

コア側は `ControllerStack::start_read` がそのまま使える(汎用パス)。
デコードはシムの Rust 側で TLV を歩くだけなので、**コアには手を入れない**。

### 4.6 種別判定を Descriptor ベースへ

`resolve_node_kind` の新方式:

1. EP0 / 0x001D / **PartsList(0x0003)** を `sm_ctrl_read_list_u32` で読む
   → 存在するエンドポイント一覧。
2. 各 EP について EP / 0x001D / **DeviceTypeList(0x0000)** を
   `field_tag=0` で読む → DeviceType の u32 一覧。
3. マッピング:

   | DeviceType | 種別 |
   |---|---|
   | 0x010A On/Off Plug-in Unit、0x010B Dimmable Plug-in、0x0510 Electrical Sensor 併設 | **`SM_UI_KIND_PLUG`** |
   | 0x0100 On/Off Light、0x0101 Dimmable Light、0x010C/0x010D | `SM_UI_KIND_LIGHT` |
   | 0x0015 Contact Sensor | **`SM_UI_KIND_CONTACT`** |
   | 0x002C Air Quality Sensor、0x0302 Temperature、0x0307 Humidity | `SM_UI_KIND_SENSOR` |
   | それ以外 | UNKNOWN |

4. **フォールバックとして既存の probe を残す**(Descriptor が読めない自作機・
   応答が壊れている機器のため)。段階移行のリスクを下げる。
5. **判定と同時に「どのパスを購読するか」を決める**: 種別に加えて
   「電力系クラスタが載っている EP」を覚える(P110M の SW によって有無が変わるため、
   ServerList(0x0001)も読んで 0x0090 / 0x0091 の有無を確認するのが確実)。
6. NVS キャッシュ(`kind_cache_set`)は種別だけでなく **EP 割り当ても保存**する
   ように拡張する(毎回 Descriptor を読むと SED では高コスト)。

### 4.7 Tab5 の表示

`app_state.hpp` に種別 2 つとスロットを追加:

```c
SM_UI_KIND_UNKNOWN = 0, LIGHT = 1, SENSOR = 2,
SM_UI_KIND_PLUG    = 3,   /* OnOff + W + kWh */
SM_UI_KIND_CONTACT = 4,   /* 開/閉 + 電池 */
```

| 新スロット | パス | 表示 |
|---|---|---|
| `SM_UI_SLOT_POWER_W` | EP*/0x0090/0x0008 ActivePower(int64 mW) | `1234 W`(mW/1000) |
| `SM_UI_SLOT_ENERGY_WH` | EP*/0x0091/0x0001 cx0(int64 mWh) | `12.34 kWh` |
| `SM_UI_SLOT_CONTACT` | EP*/0x0045/0x0000 StateValue(bool) | **true=閉 / false=開** |
| `SM_UI_SLOT_BATTERY` | EP*/0x002F/0x000C BatPercentRemaining(u8) | `%`(値/2) |

`ui.cpp` の `sensor` 判定(L797, 959, 990, 1014)は
`kind == SENSOR` の直値比較なので、**「値カードを持つ種別か」**を返す
ヘルパに置き換える。PLUG はトグル + 値カードの両方を持つ。

### 4.8 Thread(P2)

- **dataset の渡し方は既存導線のまま**(`sm_ot_hub_dataset_hex` → hex デコード →
  `sm_ctrl_ble_pair_start(kind=1, …)`)。市販機も同じ AddOrUpdateThreadNetwork を
  受ける。
- **確認事項**: `sm_ot_hub_srp_lookup` は「インスタンス名に node_id の 16 hex を
  含むサービス」を探す実装。市販機も運用インスタンス名は
  `<compressed-fabric-id>-<node-id>` 形式なので同じ規則で当たるはずだが、
  **大文字/小文字とゼロ埋めの扱い**を実機ログで確認する。
- **子として attach させる**: Tab5 は leader なので P2 の親になれる。
  `otThreadSetChildTimeout`(既定 240 秒)と child table の空きを確認。
  SED のポーリング周期(SII)が長い場合、child timeout を伸ばす必要がある。
- ConnectNetwork 応答は Thread 側では attach 完了まで遅延する設計
  (`docs/design/thread-port.md:476`)だが、これは**自作デバイス側**の話。
  市販機も遅延応答なので §4.2 のタイムアウト延長がここでも効く。

---

## 5. 実装の並び(ファイル単位)

| 作業 | 主なファイル |
|---|---|
| A. manual code / QR デコーダ | `crates/simple-matter/src/discovery/onboarding.rs`、`crates/simple-matter-cffi/src/controller.rs`、`ports/.../ui.cpp` |
| B. short discriminator 照合 | `crates/simple-matter-cffi/src/controller.rs`(`sm_ctrl_match_adv`)、`ports/.../ble_central.cpp` |
| C. SetRegulatoryConfig フェーズ | `crates/simple-matter/src/controller/commissioner.rs` |
| D. フェーズ別トランザクションタイムアウト | `crates/simple-matter/src/im/client.rs`、`crates/simple-matter/src/controller/mod.rs`、`commissioner.rs` |
| E. list/struct 読み口 | `crates/simple-matter-cffi/src/controller.rs`(+ ヘッダ) |
| F. Descriptor 種別判定 | `ports/.../ctrl_pump.cpp`、`app_state.hpp` |
| G. PLUG / CONTACT の UI | `ports/.../app_state.hpp`、`ui.cpp`、`ctrl_pump.cpp` |
| H. MRP パラメータの読み取り・適用 | `crates/simple-matter/src/discovery.rs`、`sc/case/*`、`exchange/mrp.rs`、`exchange/exchange.rs`、`controller/mod.rs` |
| I. 購読 interval / グレース / バックオフ | `crates/simple-matter/src/im/client.rs`、`ports/.../ctrl_pump.cpp` |
| J.(条件付き)ICD check-in ラベル修正 + 受信配線 | `crates/simple-matter/src/icd.rs`、`controller/`、シム |

---

## 6. 段階計画

### フェーズ P110M-0: 偵察(0.5 人日)

コード変更なし。**smctl(PC)から P110M を 1 台登録して構成を採取する**。

1. 手元の QR / manual code から passcode・discriminator を手で復号(オンライン
   デコーダまたは電卓)。
2. `smctl` の BLE-WiFi 経路で `AttestationPolicy::Skip` のまま登録を試す。
3. 成功したら `smctl descriptor read --names` で EP と DeviceTypeList / ServerList、
   `smctl any read <node> 1 0x0090 0x0008` / `... 0x0091 0x0001` を採取。
4. 失敗したらどのフェーズで落ちたか(`Phase::Failed{stage}`)を記録。

**このフェーズの結果で C4/C6 の要否が確定する。** 実装より先に必ずやる。

### フェーズ P110M-1: 登録できる(2〜3 人日)

作業 A / B / C / D。ゲート **G1**:

- Tab5 で QR(または manual code)を入力 → BLE-WiFi で P110M が登録できる
- 再起動後も CASE が張り直せる(ノード帳の永続化は既存)

### フェーズ P110M-2: 操作・表示できる(3〜4 人日)

作業 E / F / G。ゲート **G2**:

- Tab5 のリストに **PLUG** として出る(Descriptor 判定)
- トグルで実機がカチッと切り替わる
- W と kWh が表示される(0x0090/0x0091 が無いファームなら「—」表示で落ちない)
- OnOff / ActivePower の購読が張れ、外部(Tapo アプリや物理ボタン)からの
  変化が Tab5 に反映される

**リグレッションゲート**: 既存の自作 OnOff ライト・AirQuality センサが従来どおり
LIGHT / SENSOR として判定・購読できること(Descriptor フォールバック経路)。

### フェーズ P2-0: 偵察(0.5 人日)

1. smctl(または Tab5 の既存 BLE-Thread 導線)で P2 を登録。
2. **EP0 / 0x0046 / FeatureMap を読む** → CIP(bit0)/ LITS(bit2)の有無を確認。
   → LIT なら §7 R5 のリスクが顕在化(作業 J が必須になる)。
3. EP0 / 0x0046 の IdleModeDuration / ActiveModeDuration / ActiveModeThreshold、
   および SRP/mDNS TXT の SII/SAI/SAT を採取。
4. Descriptor の EP / DeviceTypeList / ServerList を採取。

### フェーズ P2-1: MRP を尊重する(3〜4 人日)

作業 H。ゲート **G3**:

- P2 に対する CASE 確立と Read が **1 回で通る**(再送嵐が起きない)
- パケットキャプチャまたはログで、再送間隔が SII/SAI 由来の値になっている
- **既存の自作デバイス(C6 / S3)で Tab5 の応答レイテンシが劣化していない**

### フェーズ P2-2: 開閉が見える(2〜3 人日)

作業 F(CONTACT マッピング)/ G / I。ゲート **G4**:

- Tab5 に **CONTACT** として出る
- ドアを開閉すると数秒以内に表示が変わる(購読レポート)
- 一晩(8 時間以上)放置して **unavailable に落ちない / 落ちても自動復帰する**
- 電池残量が表示される

### フェーズ P2-3(条件付き): ICD check-in(3〜5 人日)

**P2-0 で CIP/LITS が立っていた場合のみ。** 作業 J。

- `icd.rs:293/339` の鍵導出 info ラベルを仕様準拠に修正
  (現状は独自文字列で chip 非互換。`docs/design/icd.md:330-339`)
- コミッショニング中の RegisterClient(check-in キー払い出し)
- check-in メッセージの受信 → CASE 再確立 → 購読復元

### 合計

| フェーズ | 工数 |
|---|---|
| P110M-0 偵察 | 0.5 |
| P110M-1 登録 | 2〜3 |
| P110M-2 操作・表示 | 3〜4 |
| **P110M 小計** | **6〜8 人日** |
| P2-0 偵察 | 0.5 |
| P2-1 MRP | 3〜4 |
| P2-2 開閉表示 | 2〜3 |
| **P2 小計(ICD 不要の場合)** | **5.5〜7.5 人日** |
| P2-3 ICD(条件付き) | +3〜5 |

---

## 7. リスクと切り分け

### R1: 登録が途中で失敗する(フェーズ不明)

**切り分け手段**:
- `Phase::Failed { stage, reason }` の `stage` が既に観測できる
  (`commissioner.rs:193-207` の `stage_code`)。Tab5 のログに必ず出す。
- 先に **smctl(PC)で同じ機器を登録**して切り分ける。smctl は
  `any read` / 生 TLV ダンプが使えるので原因特定が桁違いに速い。
- BLE 段で落ちる場合は `sm_ctrl_ble_event` / `ble_central.cpp` のログ、
  PASE で落ちる場合は iterations/salt の値をログに出す
  (`sc/initiator/pase.rs:110` で既にパース済み)。
- **アテステーションは Skip なので容疑者から外れる**。これは切り分けを大幅に
  簡単にする(本方針の副次的な利点)。

### R2: ConnectNetwork がタイムアウトする(P110M)

最も可能性が高い失敗モード。30 秒固定(`im/client.rs:61`)。
**切り分け**: 失敗の `stage` が ConnectNetwork(=11)で、かつ
デバイスが Wi-Fi に**繋がってはいる**(ルータの DHCP に出る)なら確定。
**対処**: §4.2 のタイムアウト延長。暫定回避として
`CLIENT_TXN_TIMEOUT_MS` をグローバルに 90 秒へ上げても動くが、
他の op のハング検出が鈍るので恒久策はフェーズ別。

### R3: SetRegulatoryConfig 無しで CommissioningComplete が拒否される

可能性は低い(仕様上 CommissioningComplete の前提条件ではない)が、
実装が厳しい機器はありうる。**P110M-0 の偵察で判明する。**
判明したら C4 を P110M-1 の最優先に上げる。

### R4: TimeSynchronization を要求する機種

P110M は DCL/Matter Alpha のクラスタ一覧に TimeSync が無いので不要。
ただし将来の他機種では、chip の `kConfigureUTCTime` に相当する
**「TimeSync クラスタがあれば SetUTCTime を送る」**が必要になる。
リポジトリ全体に TimeSynchronization の実装は無い
(`smctl/src/clusters/names.rs:44` に名前だけ)。
**今回はスコープ外**とし、実装するなら Descriptor の ServerList を見て
条件分岐する形(§4.6 の 5 と同じ仕組み)。

### R5: P2 が実は LIT ICD(ファーム 1011/1020)

DCL には SW 1000(Matter 1.0)しか認証情報が無いが、出荷個体は
1011 / 1020 の可能性がある。LIT なら:
- IdleModeDuration が最大 60 分になり、**購読だけでは状態を追えない**
- Check-In Protocol の実装(作業 J)が必須
- 我々の check-in 鍵導出ラベルが独自なので **chip 互換の修正が前提**

**切り分け**: P2-0 で ICDManagement FeatureMap を読む。これだけで確定する。
**回避策**: LIT でも `StayActiveRequest` で一時的に起こせるが、電池を焼くので
運用解にはならない。

### R6: MRP 変更による既存デバイスの回帰

`set_config` は現在**呼び出し元ゼロ**なので、配線した瞬間に**全ピアの再送挙動が
変わる**。自作デバイス(C6/S3)が SII/SAI をどう広告しているかによっては、
Tab5 の応答が遅くなる可能性がある。
**対処**: Kconfig で「MRP パラメータ尊重」を on/off できるようにして
段階導入する。G3 で既存機の実測を必ず取る。

### R7: 未解決の Tab5 pump 間欠停止(既知課題)

`MEMORY.md` に記録のある未解決問題。市販機を足すと再現条件が増えるため、
**本作業の前に切り分けを進めておく**のが望ましい。特に P2 の購読は
long max_interval で走るので、pump 停止と「SED が単に寝ている」の区別が
つきにくくなる。**pump のステップ計測(`f244b28` で追加済み)を活かして
「pump は回っているがレポートが来ない」を区別できるログにしておく。**

### R8: 購読テーブルの枯渇

`MAX_CLIENT_SUBSCRIPTIONS = 4`(`im/client.rs:72`)。
市販機を混ぜて 5 台以上運用すると即座に枯れる。
**対処**: 8 へ引き上げ、`sm_ctrl_pool_stats` で RAM 影響を実測。

### R9: 電力/エネルギークラスタが載っていないファーム

P110M の SW 1.0.x / 1.1.x は 0x0090/0x0091 を持たない
(`community.home-assistant.io/t/736975`)。
**対処**: Descriptor の ServerList を見て**あるものだけ購読・表示する**設計
(§4.6 の 5)。無い場合は「W / kWh 非対応」と表示して落ちない。
ファーム更新は Tapo アプリ側でしかできない(OTA Provider は我々が持たない)。

---

## 8. 参考にした一次情報(URL 一覧)

- CSA DCL(REST API、機種の VID/PID・DeviceType・認証仕様バージョン・transport):
  - `https://on.dcl.csa-iot.org/dcl/vendorinfo/vendors`
  - `https://on.dcl.csa-iot.org/dcl/model/models`
  - `https://on.dcl.csa-iot.org/dcl/model/versions/4447/8194`
  - `https://on.dcl.csa-iot.org/dcl/compliance/compliance-info/5010/261/66304/matter`
  - `https://on.dcl.csa-iot.org/dcl/compliance/compliance-info/4447/8194/1000/matter`
- chip コミッショニングのステージ列挙:
  `https://raw.githubusercontent.com/project-chip/connectedhomeip/master/src/controller/CommissioningDelegate.h`
- chip-tool の PAA トラストストア:
  `https://github.com/project-chip/connectedhomeip/blob/master/examples/chip-tool/README.md`
- Matter ICD(SIT/LIT、Check-In Protocol、ICDManagement 属性、コントローラ側要件):
  `https://docs.silabs.com/matter/latest/matter-overview-guides/matter-icd`
- Tapo P110M 製品仕様(BLE 経由セットアップ、2.4 GHz のみ):
  `https://www.tp-link.com/us/home-networking/smart-plug/tapo-p110m/`
  / `https://us.store.tapo.com/products/tapo-p110m-4-pack`
- Tapo P110M のクラスタ構成・Matter 1.3 認証:
  `https://www.matteralpha.com/tapo/tapo-smart-plug-energy-monitoring-p110m-p231`
- Tapo P110M のエネルギー計測の実測・既知の癖:
  `https://community.home-assistant.io/t/tapo-p110m-energy-monitoring/736975`
  / `https://github.com/home-assistant/core/issues/149847`
  / `https://community.home-assistant.io/t/matter-smart-plugs-losing-energy-reporting-capability/972984`
- Aqara Door and Window Sensor P2 製品仕様:
  `https://us.aqara.com/products/door-and-window-sensor-p2`
- Aqara P2 の既知の癖(unavailable、購読エラー、電池消耗):
  `https://github.com/home-assistant/core/issues/117386`
  / `https://community.home-assistant.io/t/aqara-door-and-window-sensor-p2-with-thread-and-matter-becomes-unavailable-and-comes-back-als-the-time/590222`
  / `https://community.home-assistant.io/t/aqara-p2-sensors-status-changes-to-unavailable/739099`
  / `https://forum.aqara.com/t/p2-sensor-dies-quickly-no-battery-within-days-matter-apple-home-assistant/65130`
