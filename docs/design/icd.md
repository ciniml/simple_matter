# ICD(Intermittently Connected Device)対応設計

対象: Matter の ICD Management クラスタ(0x0046)と、電池駆動デバイス(特に Thread SED)の
前提となる active/idle 省電力モデルを `crates/simple-matter` コアへ載せる。コアは sans-IO の
まま(`docs/ARCHITECTURE.md`)、状態機械はコアが持つが**駆動はアプリ/ポートが行う**。

関連 doc: `thread-port.md`(§I1 に ICD の位置づけ。Thread 電池デバイスの前提技術)、
`interaction-model.md`(クラスタ実装・tick・now_ms 契約)、`mdns-ipv6.md`(SII/SAI 広告)。

## 0. サマリ(設計判断)

- **フェーズ I1a(本 doc の実装対象)= コア ICDM(SIT 最小)+ ホスト E2E。** ICD Management
  クラスタ 0x0046 を SIT(Short Idle Time)最小構成 = 必須 3 属性(IdleModeDuration /
  ActiveModeDuration / ActiveModeThreshold)+ FeatureMap=0 で実装する。CheckInProtocol(CIP)・
  RegisterClient・LIT は I1c へ。
- **コアに `IcdState`(sans-IO 状態機械)と `IcdConfig`(広告パラメータ)を追加**
  (`crates/simple-matter/src/icd.rs`)。`identify` の tick と同じく `now_ms` 引数駆動・
  alloc 非依存・no_std。アプリは毎ループ `can_sleep(now)` / `next_wake(now)` を問い合わせ、
  受信で `notify_activity(now)` を呼ぶ。**MatterStack は無改造**(コアの `next_deadline` と
  `IcdState::next_wake` の `min` をアプリが取る = sans-IO 維持)。
- **mDNS TXT の SII/SAI は ICD パラメータから導出**する(`IcdConfig::advertised_sii_ms/sai_ms`)。
  既存 `Operational`/`Commissionable` の SII/SAI フィールドへそのまま流す(discovery.rs 無改造)。
- **Thread SED(rx-off-when-idle MTD)は実現性調査のみ(I1b)**。openthread 0.2.0(vendored)は
  `set_link_mode(rx_on_when_idle=false)` を持つが、`EspRadio::CAPS` の `RX_ON_WHEN_IDLE` が
  coex 依存で**コメントアウト**(=無線 RX を物理的に落とす実装が未成熟)。MLE レベルの SED は
  成立し得るが真の省電力は upstream 待ち。CSL/SSED は upstream 未対応(§3)。
- **ホスト E2E は loopback ユニキャストのみで実施**(`smctl pairing address` + キャッシュ
  アドレス運用 + `SM_NO_MDNS`)。稼働中の Thread 24h ソーク(wpan0/otbr/avahi)へ
  マルチキャストを一切漏らさないため(§5 検証)。

## 1. SIT / LIT の要件整理(Matter 1.3 §9.16)

### 1.1 ICD Management クラスタ 0x0046(revision 3)

| 属性 | ID | 型 | 単位 | 必須性 | 備考 |
|---|---|---|---|---|---|
| IdleModeDuration | 0x0000 | uint32 | **秒** | 必須 | 1..=64800。idle でいられる最大時間 |
| ActiveModeDuration | 0x0001 | uint32 | **ms** | 必須 | ≥300。起床後に最低 active でいる時間 |
| ActiveModeThreshold | 0x0002 | uint16 | **ms** | 必須 | 最後の通信からの active 延長。LIT は≥5000 |
| RegisteredClients | 0x0003 | list | — | CIP | チェックイン登録先(I1c) |
| ICDCounter | 0x0004 | uint32 | — | CIP | チェックインカウンタ(I1c) |
| ClientsSupportedPerFabric | 0x0005 | uint16 | — | CIP | I1c |
| UserActiveModeTriggerHint | 0x0006 | map32 | — | UAT | I1c |
| UserActiveModeTriggerInstruction | 0x0007 | string | — | UAT | I1c |
| OperatingMode | 0x0008 | enum8 | — | LITS | SIT=0/LIT=1(I1c) |
| MaximumCheckInBackOff | 0x0009 | uint32 | 秒 | CIP | I1c |

> **単位の罠**: Matter 1.2 の *IdleModeInterval*(ms)/ *ActiveModeInterval*(ms)は 1.3 で
> *IdleModeDuration*(**秒**)/ *ActiveModeDuration*(ms)に名称・単位が変わった。本実装は 1.3。

FeatureMap のビット: **CIP**(bit0、Check-In Protocol)/ **UAT**(bit1、User Active Mode
Trigger)/ **LITS**(bit2、Long Idle Time Support)。

### 1.2 SIT 最小構成で必要なもの(= I1a)

- **属性**: 必須 3 属性のみ。全て read-only(FIXED)。
- **FeatureMap = 0**(CIP/UAT/LITS 全て無効)。SIT ICD は LITS を立てなければ SIT。
  CIP 無しの SIT ICD は仕様上有効(チェックインは LIT のためのもの)。
- **コマンド**: なし。StayActiveRequest(CIP/LIT)・RegisterClient/UnregisterClient(CIP)は
  受理コマンドに含めない → IM エンジンが `UnsupportedCommand` を返す。
- **GlobalAttributes**: `cluster!` マクロが自動導出(FeatureMap=0 / ClusterRevision=3 /
  AttributeList = {0x0000,0x0001,0x0002} + グローバル / Accepted・Generated は空)。

### 1.3 LIT フェーズ(I1c)へ切り出すもの

- CheckInProtocolSupport(CIP)= RegisterClient / UnregisterClient / ICDCounter /
  RegisteredClients / チェックインプロトコル(check-in メッセージ = ICD が idle から
  「起きたよ」を登録クライアントへ ASN.1 の Counter で通知)。
- LITS(OperatingMode=LIT、ActiveModeThreshold≥5000、long idle time = チェックイン周期)。
- UAT(ユーザ操作での強制 active)。
- discovery TXT の `ICD`(=1 で LIT ICD)キーと、それに伴うコントローラ側の登録フロー。

## 2. コア設計(sans-IO)

### 2.1 `IcdConfig`(広告パラメータ)

```rust
pub struct IcdConfig {
    pub idle_mode_duration_s: u32,      // 秒(仕様 1..=64800)
    pub active_mode_duration_ms: u32,   // ms(仕様 ≥300)
    pub active_mode_threshold_ms: u16,  // ms
}
impl IcdConfig {
    pub const fn sit_default() -> Self;             // idle 2s / active 1000ms / thr 500ms
    pub const fn validate(&self) -> Result<()>;     // 仕様レンジ検査
    pub const fn advertised_sii_ms(&self) -> u32;   // = idle_s*1000(≤3_600_000)
    pub const fn advertised_sai_ms(&self) -> u32;   // = active_ms(≤3_600_000)
}
```

### 2.2 `IcdState`(active/idle 状態機械、`now_ms` 駆動)

「`active_until_ms` までは active、以降は idle」という 1 変数モデル。

| API | 意味 |
|---|---|
| `notify_activity(now)` | 受信/送信(応答を要する交換)を通知し active 窓を延長。idle→active の起床では最低 ActiveModeDuration、以後は最後の通信から ActiveModeThreshold |
| `is_active(now)` / `can_sleep(now)` | 現在 active か / 今 sleep してよいか |
| `next_wake(now)` | active 中: 窓終端。idle 中: `now + IdleModeDuration`(SIT のポーリング/広告更新周期) |

延長規則(`notify_activity`):
`active_until = max(既存, now + threshold, (起床なら) now + active_mode_duration)`。
起床時に ActiveModeDuration を下限として敷くことで「短い threshold で即 idle に戻る」ことを防ぐ
(Matter 1.3 の「Active Mode に入ったら最低 ActiveModeDuration」の要件)。

### 2.3 MatterStack への統合(アプリが問い合わせる形)

sans-IO を維持するため、`IcdState` は `MatterStack` に**埋め込まない**。アプリループ(PC example /
ports pump)が次の 3 点を担う:

1. 受信のたびに `icd.notify_activity(now)` を呼ぶ(= active 延長のトリガ)。
2. `icd.can_sleep(now)` が真の間、受信を止めて擬似/実 sleep に入る。
3. 起床期限 = `min(stack.next_deadline(now), icd.next_wake(now))`。既存の
   `next_deadline`(MRP 再送・購読レポート・fail-safe)と統合して 1 つの sleep 期限にする。

MRP 再送・購読レポートは `stack.poll(now)` が引き続き吐く(ICD は idle 中も自分の送信予定
= 購読レポート/ポーリングで「起きて送る」)。

### 2.4 mDNS TXT / MRP パラメータへの反映

- SII(Session Idle Interval)= IdleModeDuration(ms 換算)。ピア(コントローラ)は SII を見て、
  相手 idle 時の MRP 再送バックオフをこの周期へ合わせる(= idle 中の偽再送輻輳を抑える)。
- SAI(Session Active Interval)= ActiveModeDuration。active 中にピアが期待する応答周期。
- **SAT**(Session Active Threshold = ActiveModeThreshold)は Matter 1.3 で追加された別 TXT キー。
  本コアの `Operational`/`Commissionable` は SII/SAI のみを持つため、SAT の TXT 出力は I1c
  (discovery 拡張)へ回す(SIT の相互運用には SII/SAI で十分)。
- ヘルパ `IcdConfig::advertised_sii_ms/sai_ms` が導出。アプリは `Operational.sii/sai` へ流す。

### 2.5 Subscribe の maxInterval と idle 期間

- SIT ICD は「idle 中も自分の購読レポートは maxInterval で送る」。**maxInterval > IdleModeDuration**
  は正常構成(chip の SIT 挙動でも subscribe は成立する)。idle 中に発生した属性変化(toggle 等)の
  データ変化レポートは、デバイスが次に active になった窓で配送される(idle 中は受信も送信も
  抑制されるため、min-interval 内でなく「次の active 窓」で届く = 実測で確認、§5)。
- コントローラ側(chip-tool / smctl)は SII を見て MRP を緩めるので、idle 遅延分の再送は吸収される。

## 3. Thread SED の実現性調査(設計のみ、I1b の計画)

**結論: MLE レベルの SED(rx-off-when-idle MTD)は openthread 0.2.0 の API 上は可能だが、
真の無線省電力は esp-radio / esp-hal 側が未成熟で upstream 待ち。** 実装は I1b。

### 3.1 openthread 0.2.0(vendored)の SED 面

- `OpenThread::set_link_mode(rx_on_when_idle: bool, full_thread_device: bool,
  receive_full_network_data: bool)` を提供(`ports/esp32/vendor/openthread/src/lib.rs`)。
  `rx_on_when_idle=false` で MLE の rx-on-when-idle ビットを落とし、親が子宛フレームをバッファ、
  子はデータポーリング(802.15.4 Data Request)で回収する **Sleepy End Device** になる。
- プラットフォーム hook `plat_radio_set_rx_on_when_idle(on)` も配線済み(role 変化まで
  適用を遅延する `pending_rx_when_idle`)。
- **ポーリング周期の明示制御 API(`otLinkSetPollPeriod`)は vendored バインディングに未露出**。
  現状は OpenThread 既定(child timeout から導出)。SII に合わせた poll 周期の調整は
  binding 追加が要る(I1b の作業項目)。
- **CSL / SSED(Synchronized Sleepy End Device、Thread 1.2+)は upstream 未対応**
  (thread-port.md 記載の openthread issue #104)。低レイテンシ受信(CSL receiver)は不可。
  SED のデータポーリング方式のみが対象。

### 3.2 esp-radio(EspRadio)側の制約 ← **I1b の本丸**

- `EspRadio::CAPS` は `RX_ON_WHEN_IDLE` を**コメントアウト**している
  (`ports/esp32/vendor/openthread/src/esp.rs`: `// .union(Capabilities::RX_ON_WHEN_IDLE)
  TODO: Depends on coex being off in ESP-IDF`)。この cap が無いと OpenThread の MAC は
  ソフトウェアでポーリングを回すが、**esp-radio は物理 RX を落とさない**(受信機は on のまま)。
  = MLE 上は SED でも実消費電力は下がらない。真の省電力には esp-radio に「idle 時 RX off +
  Data Request 時のみ RX」実装が要る(coex/15.4 の RX ゲーティング)。
- 加えて thread-port.md R9(esp-radio 0.18 の 15.4 状態機械が RX 再アーム不能に座礁)を
  vendored の TX キック/RX 再キックで回避している現状は、RX を積極的に落とす SED 運用と
  相性が悪い(RX off↔on の遷移が R9 を誘発しやすい)。SED 化は R9 の upstream 解決と
  セットで進めるのが安全。

### 3.3 esp-hal の light sleep

- esp-hal は RTC 経由の light-sleep(`Rtc::sleep_light` 相当、GPIO/timer wakeup ソース)を
  提供する。ただし ICD の idle 窓で light-sleep へ入るには、① `ot.run` タスク・esp-radio・
  embassy-time タイマを安全に park し、② Data Request のポーリング周期(または SII 周期)で
  timer wakeup を仕込む協調が要る。EspRadio が RX-off-when-idle を持たない現状では
  「sleep 中に親宛フレームを取りこぼす」ため、§3.2 の解決が前提。
- I1b では「light-sleep 無し(CPU idle のみ)の SED」→「RX ゲーティング付き SED」→
  「light-sleep 協調」の段階導入を計画する。

### 3.4 I1b 計画(実装しない)

1. `otLinkSetPollPeriod` binding 追加 + `IcdConfig` から poll 周期を導出。
2. EspRadio に RX-off-when-idle(cap 有効化 + idle RX ゲーティング)。R9 と併せて upstream 追従。
3. `ot.set_link_mode(false, ..)` を attach 後に適用(pump)。SII/SAI を SRP TXT へ反映
   (thread-port.md の SRP 登録に ICD 値を流す)。
4. esp-hal light-sleep 協調(timer wakeup = poll 周期)。実測で消費電流を確認。

## 4. フェーズ分割とゲート

| フェーズ | 内容 | ゲート |
|---|---|---|
| **I1a**(本 doc) | コア ICDM(SIT)+ `IcdState` + SII/SAI 導出 + PC example(擬似 sleep)+ smctl | ①test/clippy/クロス/bloat green ②ホスト E2E: pairing→ICDM 属性 read→subscribe(max>idle)→idle/active 遷移→toggle |
| **I1b** | Thread SED 実機(rx-off-when-idle MTD + poll 周期 + light-sleep) | ①`set_link_mode(false)` で attach 維持 ②SED として親 child table に載る ③subscribe/toggle が SED 経由で成立 ④消費電流の実測低下 |
| **I1c** | LIT + check-in protocol + RegisterClient/UnregisterClient + CIP/LITS 属性 + discovery `ICD` キー | ①chip-tool の ICD 登録(pairing 時)②check-in メッセージ配送 ③StayActiveRequest ④LIT の long idle 実機 |

## 5. I1a 完了記録(2026-07-17)

### 5.1 追加/変更ファイル

- コア新規: `crates/simple-matter/src/icd.rs`(`IcdConfig` / `IcdState` + 単体テスト 8 本)、
  `crates/simple-matter/src/dm/clusters/icd_management.rs`(`IcdManagementCluster` 0x0046 +
  テスト 3 本)。
- コア配線: `lib.rs`(`pub mod icd`)、`dm/clusters.rs`(module + re-export)。
- smctl: `crates/smctl/src/clusters/icd_management.rs`(`icd-management` 名前テーブル)+
  `clusters/mod.rs` レジストリ 1 行。
- PC example: `crates/simple-matter/examples/onoff-light.rs` に ICDM クラスタ(EP0)+ SIT ICD の
  擬似 sleep(`SM_ICD`)+ SII/SAI 導出 + マルチキャスト無効化(`SM_NO_MDNS`)+ ICD 設定 env
  (`SM_ICD_IDLE_S` / `SM_ICD_ACTIVE_MS` / `SM_ICD_THRESHOLD_MS`)。
- bloat-check: `crates/bloat-check/src/lib.rs` の参照デバイスに ICDM を追加(フットプリント追跡)。

### 5.2 ゲート 1(自動検査)

- `cargo test --workspace --all-features`: **green**(simple-matter 546 / smctl 59 ほか)。
  新規: icd 8 + icd_management 3。
- `cargo clippy --all-targets --all-features`: **0 warning**。
- クロスチェック: `thumbv6m-none-eabi` / `riscv32imc-unknown-none-elf` の `cargo check -p
  simple-matter --all-features`、および `--no-default-features` すべて **green**。
- **フットプリント増分**(Cortex-M4F、`flash-probe` に ICDM を載せた参照デバイスで実測):
  - flash: Total 102,259 → **102,531 B(+272 B)**、`.text` 95,284 → 95,440(+156 B)。
    増分は SIT の read-only 3 属性 + 静的 `ClusterMeta`(rodata)+ dispatch アーム。
  - RAM: `IcdManagementCluster` = **12 B**(`IcdConfig`= u32+u32+u16 のパディング込み)。
    デバイスモデル内(MatterStack 所有)なので DEVICE RAM TOTAL に +12 B。
  - controller-feature 不変性: delta 8 B(≤128 B 閾値内)を維持。
  - 非 ICD デバイスへの影響は**ゼロ**(未参照コードは `--gc-sections` で除去)。

### 5.3 ゲート 2(ホスト E2E、loopback ユニキャストのみ)

**方針**: 稼働中の Thread 24h ソーク(/dev/ttyACM1・/dev/ttyACM5・otbr コンテナ)を絶対に
乱さないため、E2E は**マルチキャストを一切出さない loopback**で実施した。デバイスは
`SM_NO_MDNS=1`(mDNS ソケットを開かない)+ `SM_MATTER_PORT=15540`、コミッショニングは
`smctl pairing address ::1 15540`(明示アドレス = ディスカバリ不要)、運用は smctl の
キャッシュアドレス直叩き(CASE 再解決も QU 無し)。専用 `--state-dir` で CA/アドレス帳も分離。

実測(`SM_ICD=1 SM_ICD_IDLE_S=3 SM_ICD_ACTIVE_MS=1000 SM_ICD_THRESHOLD_MS=500`):

- **pairing = PASS**。`commissioning COMPLETE. operational CASE session = 0x2`(PASE→ArmFailSafe→
  CSR→AddNOC→CASE→CommissioningComplete が loopback で完走)。**コミッショニング中はデバイスを
  常時 active に保つ**(仕様どおり)= 未 fabric の間は擬似 sleep しない、を実装で担保。
- **ICDM 属性 read(smctl over CASE)= PASS**:
  `ep0 icd-management/idle-mode-duration (0x0046/0x0000) = 3`、
  `active-mode-duration (0x0001) = 1000`、`active-mode-threshold (0x0002) = 500`。
  設定値と一致。SII/SAI 広告ログ: `SII=Some(3000)ms SAI=Some(1000)ms`。
- **subscribe(maxInterval > IdleModeDuration)= PASS**: `SubscribeRequest sent (min=2s max=8s)` →
  `ESTABLISHED: subscription_id=1 max_interval=8s`(8s > IdleModeDuration 3s)。周期レポート
  `[report +8s] on-off=false` / `[report +16s]=false`、および toggle 後のデータ変化レポート
  `[report +18s] on-off=true`(idle デバイスが次の active 窓で配送)。
- **idle/active 遷移 = PASS**(デバイスログ、コミッショニング完了後):
  `[icd] -> IDLE (radio off; next poll in ~3s)` ↔ `[icd] -> ACTIVE (radio on)` が ~3s 周期で
  交互に出力。コミッショニング完了行(`[window] initial commissioning done`)の**後**から
  sleepy 化する(それ以前は active 維持)。
- **toggle(active window 外)= PASS**: 擬似 sleep 中のデバイスに対する
  `smctl onoff toggle 1 1` が `CASE ESTABLISHED (resumed via Sigma2Resume)` → `onoff cmd 0x02 OK`。
  デバイスは `[onoff] light is now ON` を処理。idle 窓中の Sigma1 は listen 窓 or MRP 再送で拾われ、
  変化は購読者へ次 active 窓で配送(上記 `+18s` レポート)= 「次の active で成立」を実測。
- パニック/エラー: デバイスログに 0 件。

**chip-tool での属性 read は本タスクでは未実施(意図的な保留)。** chip-tool の運用発見は
マルチキャスト mDNS を全 IF(wpan0 含む)へブロードキャストし、thread-port.md T2 で
**otbr-agent を落とした実績**がある(`HandleRcpTimeout`)。稼働中ソークの保全を最優先し、
loopback に閉じられない chip-tool の live 実行は次のメンテ窓へ回す。相当の検証(属性 read /
subscribe / toggle / idle-active)は smctl パスで全て green。参考コマンド(メンテ窓用):

```
chip-tool pairing already-discovered 1 20202021 ::1 15540
chip-tool icdmanagement read idle-mode-duration 1 0
chip-tool icdmanagement read active-mode-duration 1 0
chip-tool icdmanagement read active-mode-threshold 1 0
chip-tool onoff subscribe on-off 2 8 1 1
chip-tool onoff toggle 1 1
```

### 5.4 発見した問題 / 割り切り

- **擬似 sleep とコミッショニングの両立**: 初期実装は起動直後から sleepy 化し PASE が
  タイムアウトした。→ **未コミッショニング(fabric 空)の間は常時 active**(仕様の
  「ICD はコミッショニング中 Active Mode」に一致)へ修正。
- **idle 中の受信窓**: 単発ポーリング(1 ループ = 20ms)では MRP 再送を取りこぼしやすいため、
  idle の周期起床時に `ICD_LISTEN_MS = 600ms` の listen 窓を開いて再送を確実に拾う
  (SED が親をポーリングして短時間 RX する挙動の擬似)。
- **SAT TXT キー未対応**: SII/SAI のみ広告(§2.4)。SAT は I1c。
- **SII/SAI の厳密なマッピング**は最新仕様 PDF で再確認の価値あり(本実装は SII=IdleModeDuration、
  SAI=ActiveModeDuration を採用。参照した chip チェックアウトは v1.1 系で ICDM が旧仕様
  =裏取り不足。定義は Matter 1.3 spec §9.16 の記憶知識に依拠)。
