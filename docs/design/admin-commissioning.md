# Administrator Commissioning クラスタ(0x003C)と コミッショニング窓

対象: `crates/simple-matter/src/dm/clusters/administrator_commissioning.rs` /
`sc/responder.rs`(PASE 設定の動的注入)/ `im`(timed invoke)/ `smctl`(ECM 窓オープン)。
関連: `docs/design/interaction-model.md` §5.5(Timed)、`docs/design/secure-channel.md`(PASE)。

## 1. 目的と範囲

コミッショニング済みデバイスへ **2 人目以降の管理者** を追加する経路を提供する
(Matter Core Spec §11.19 Administrator Commissioning Cluster)。

- OpenCommissioningWindow(ECM): PAKE verifier を動的付与し CM=2 で窓を開く。
- OpenBasicCommissioningWindow(BC): 焼き込みパスコードで CM=1 の窓を開く(FeatureMap bit0)。
- RevokeCommissioning: 窓の即時クローズ。
- WindowStatus / AdminFabricIndex / AdminVendorId 属性。
- 窓タイムアウト(180–900 秒)での自動クローズ。

## 2. 窓状態機械(CommissioningWindow)

呼び出し側(example / ポート層)が所有する `RefCell<CommissioningWindow>` を
クラスタと統合層(app ループ)が共有する。fabric テーブルの共有
(`docs/design/transport-exchange.md` §9)と同じ「外部所有 RefCell」パターン。

```
            OpenCommissioningWindow(timed, verifier/salt/iterations/discriminator)
  Closed ──────────────────────────────────────────────────────────────▶ EnhancedOpen
    ▲  ▲      OpenBasicCommissioningWindow(timed, timeout)                   │
    │  └────────────────────────────────────────────────────▶ BasicOpen      │
    │                                                             │          │
    └── RevokeCommissioning(timed) / タイムアウト(on_tick) ◀─────┴──────────┘
```

- `WindowStatus`: 0=WindowNotOpen / 1=EnhancedWindowOpen / 2=BasicWindowOpen(§11.19.7.1)。
- 開時に `admin_fabric_index`(呼び出し元 CASE セッションの fabric)と
  `admin_vendor_id`(同 fabric の VendorID)を記録、閉時に null へ戻す。
- 期限は `AccessContext::now_ms` 基準の絶対ミリ秒。`DataModel::on_tick`(統合層の
  drive_ticks から毎回呼ばれる)で期限超過を検出して自動クローズする。
- 状態変化は 1 深度イベント `WindowEvent { Opened / Closed }` として蓄積し、app ループが
  `take_event()` でポーリングする(sans-IO: コアは mDNS もソケットも触らない)。

### クラスタ固有ステータス(§11.19.6)

| code | 名前 | 返す場面 |
|---|---|---|
| 2 | Busy | 窓が既に開いている |
| 3 | PAKEParameterError | verifier/salt/iterations の形式不正 |
| 4 | WindowNotOpen | Revoke 時に窓が閉じている |

`CmdResponder::set_cluster_status(u8)` を追加し、クラスタが `Err(ImStatus::Failure)` と
併用して IM エンジンが `StatusIB { status, cluster_status }` に写す。

## 3. Timed invoke

- デバイス側は TimedRequest → StatusResponse → Invoke(timedRequest=true)の window 検証を
  既に実装済み(engine §5.5)。本ピースで **「timed 必須コマンド」の強制** を追加する:
  `CommandMeta.timed: bool`(`cluster!` の accepted 行に `@timed` 注釈)。timed 未経由の
  invoke には `NeedsTimedInteraction(0xC6)` を CommandStatusIB で返す。
- コントローラ側は `ImClient::start_invoke_timed` を追加する。2 相:
  1. InvokeRequest(timedRequest=true)を先にエンコードして client 内部バッファ(result)に
     退避し、TimedRequest を送る。
  2. StatusResponse(Success) 受信時に退避した InvokeRequest を同 exchange の応答
     (`HandlerAction::Respond`)として返す(契約への追加ゼロ)。
  `ControllerStack::start_invoke_timed` が配線する。

## 3b. Timed write

Matter 仕様では TimedRequest の後続は Invoke でも Write でもよい。同じ window 機構を
Write に拡張する:

- デバイス側: `AttributeMeta.timed: bool`(`cluster!` の属性ブロック直後に `@timed` 注釈。
  コマンドの `@timed` と同流儀)。`engine::write` は invoke と同じ `check_timed` で window を
  検証し(TimedRequest の窓状態スロットは invoke と共用、opcode 分岐のみ追加)、`write_one` が
  timed 未経由の timed 必須属性への write に `NeedsTimedInteraction(0xC6)` を AttributeStatusIB
  で返す。窓外/フラグ不整合は invoke と同じく `Timeout`/`TimedRequestMismatch`。
  (既存クラスタで timed 必須の属性は無い。フラグの利用例はテスト用クラスタのみ。)
- コントローラ側: `ImClient::start_write_timed`(start_invoke_timed の write 版)。退避バッファ
  (`pending_invoke_len`)を共用し、StatusResponse(Success) 受信時に退避済み WriteRequest を
  進行中トランザクション種別(`TxnKind::Write`)に応じた opcode で送出する。
  `ControllerStack::start_write_timed` が配線する。

## 4. PASE verifier の動的注入と窓ゲート

- `PaseConfig::from_verifier(w0, L, salt, iterations)` は既存。OCW の
  PAKEPasscodeVerifier フィールド(97B = w0(32) ‖ L(65))をそのまま写す。
- `SecureChannel::set_pase_config()` / `set_pase_enabled(bool)` を追加し、
  `MatterStack::set_pase_config()` / `set_pase_enabled()` で公開する。
- `pase_enabled == false` の間、PBKDFParamRequest には StatusReport Busy を返す
  (chip はリトライ可能エラーとして扱う。窓が開けば受理される)。
- 適用は app ループが行う: `WindowEvent::Opened` → `set_pase_config(verifier 由来)` +
  `set_pase_enabled(true)` + mDNS CM=2 再広告。`Closed` → `set_pase_enabled(false)` +
  commissionable 広告停止。**セッション確立済みの PASE/CASE には影響しない**
  (新規ハンドシェイクだけをゲートする)。

## 5. mDNS 連動(app ループ、sans-IO 境界の外)

- 初期状態(fabric 0 個): 従来どおり CM=1 で commissionable 広告 + 焼き込みパスコード。
- 初回コミッショニングで fabric が増えたら(generation 変化)、窓が開いていなければ
  commissionable 広告を止め PASE を無効化する(announcement 窓の終了)。
- `WindowEvent::Opened { discriminator, enhanced }` で `Commissionable`(CM=2、新
  discriminator)を再設定し `notify_change`。`Closed` で `set_commissionable(None)`。

## 6. smctl(コントローラ側)

```
smctl admincommissioning open-window <node-id> <timeout-s> <discriminator> [--passcode N]
smctl admincommissioning revoke <node-id>
smctl invoke ... [--timed <ms>]      # 汎用 invoke にも timed を開放
smctl write  ... [--timed <ms>]      # 汎用 write にも timed を開放(TimedRequest → Write)
```

- open-window(ECM): passcode 未指定なら乱数生成(1..=99999998、無効値 8 種を除外)。
  salt 16B 乱数・iterations 1000 で `crypto::spake2p::compute_verifier` により
  (w0, L) を導出し、97B verifier として OCW を timed invoke(timeout 10s)する。
  成功時に passcode / discriminator / manual pairing code(11 桁、Verhoeff 検査数字)を
  表示する。
- 2 人目のコントローラは別 state-dir(別 CA)で `pairing onnetwork-long <node> <passcode>
  <discriminator>` を実行すれば ECM 窓から入れる(既存経路)。

## 7. 乖離・割り切り

- AdminVendorId は開いた fabric の VendorID(FabricTable 由来)。NOC に vendor id が
  無い場合は AddNOC の adminVendorId をそのまま使う(既存 FabricEntry の値)。
- OCW の salt は仕様上 16–32B。iterations は 1000–100000 を検証する。
- タイムアウト範囲は 180–900 秒を強制(chip-tool の既定 300 は範囲内)。
- Busy 応答(窓ゲート中の PBKDFParamRequest)はスペック上 BUSY StatusReport +
  retry delay。chip-tool はコミッショニング開始時にリトライする。
- MaxCumulativeFailsafeSeconds 連動や NOC 経由 VendorID 抽出は行わない。
