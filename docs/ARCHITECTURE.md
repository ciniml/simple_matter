# simple_matter 設計方針

小フットプリント・`no_std` 前提の Matter コントローリ(デバイス側/responder)実装。
本方針は 3 実装の構造調査([rs-matter](research/rs-matter.md) /
[matter.js](research/matter-js.md) / [connectedhomeip](research/connectedhomeip.md))から抽出した
課題と示唆の統合である。

## 前提と目標

- 言語: Rust、`#![no_std]`
- 対象: Matter デバイス(コントローリ/responder)。コントローラは将来スコープ
- 動機: connectedhomeip の肥大(クラスタ 120 個・codegen 二重化・client/server 同居・
  抽象多重化)への対処。rs-matter ですら公称下限 1MB flash / 256KB RAM であり、
  それを下回るターゲットを狙う

## alloc の利用方針

Matter が動く現実的なターゲット(Wi-Fi/Thread 付き MCU、おおむね 256KB〜 RAM)では
alloc の利用は許容する。ただし rs-matter の教訓(問題は alloc そのものではなく、
依存 crate が深部で強制する制御不能なヒープ使用)から、次の規律を守る。

- コアクレートは alloc を **必須にしない**。`alloc` は Cargo feature とし、
  無効でもコアのプロトコル処理が成立する構造を保つ
- **定常状態のデータパス**(メッセージ送受信・セッション処理・IM 処理)は
  ヒープ確保しない。固定バッファ・静的確保を使う(断片化・予測可能性のため)
- alloc を使ってよいのは: 初期化時の一括確保、低頻度パス(コミッショニング時の
  証明書チェーン検証・一時バッファ等)、および std 前提のプラットフォーム実装クレート
- 依存 crate 選定時は「alloc を使うか」ではなく「定常パスで無制限に確保するか・
  feature で切れるか」を基準にする

## 3 実装から得た核心的知見

| 実装 | 借りるもの | 避けるもの |
|---|---|---|
| connectedhomeip | レイヤ境界と概念語彙(Session/Exchange+MRP/暗号境界 1 点/`DataModel::Provider` 抽象/code-driven クラスタ) | 各層の「幅」: 全クラスタ生成、codegen 二重化、Ember 互換層、client 同居、抽象多重化 |
| rs-matter | `pinned-init` による `.bss` in-place 初期化、heapless 固定容量、crypto trait + const generics、executor 非依存 async、bloat-check | crypto/cert の alloc 依存、416KB IDL 全クラスタ生成、7 型パラメータの上位伝播、initiator/responder 同居、~100 個のサイジング feature |
| matter.js | 一方向依存 DAG と依存性逆転(プロトコル本体はプラットフォーム trait のみに依存)、プラガブルな ProtocolHandler、宣言的モデル→生成の発想 | 実行時 conformance DSL パーサ、全 283+ クラスタ常時生成、動的レジストリ(Symbol/Map) |

## 設計原則

1. **デバイス(responder)専用** — PASE/CASE は responder 側のみ。IM は
   Read/Write/Invoke/Subscribe のハンドラ側のみ。client 状態機械
   (ReadClient/CommandSender 相当)は作らない。
2. **alloc に依存しない核を保つ** — rs-matter を流用できない最大要因が crypto/cert の
   強制 alloc 依存(x509-cert・ccm 起因)。証明書は固定バッファ上のストリーミング
   TLV/DER パースを基本とし、暗号はスタック完結のバックエンドを優先する。
   alloc は上記「alloc の利用方針」の範囲で許容する。
3. **静的確保** — 単一の state 構造体 + `pinned-init` 方式の in-place 初期化 +
   heapless 固定容量コンテナ。サイジングは feature 乱立ではなく
   **少数の const generic パラメータ(またはプロファイル 2〜3 個)** に集約。
4. **暗号境界は 1 点** — connectedhomeip の `SecureMessageCodec` 相当。
   transport 以下は暗号文 + PacketHeader、exchange 以上は平文 + PayloadHeader。
5. **メタデータとハンドラの単一ソース化** — rs-matter の `Node`(const) と
   `ChainedHandler` の二重管理を避け、1 つのクラスタ宣言から dispatch と
   メタデータ列挙の両方を導出する(derive マクロ or const 評価)。
6. **クラスタは手書き + 最小セット、combined 実装** — codegen は使うとしても
   「実装するクラスタのみ」を対象にした軽量なもの。conformance/constraint は
   コンパイル時に確定させ、実行時パーサを持たない。
7. **型パラメータ伝播の抑制** — ハンドラ合成の静的ディスパッチは踏襲しつつ、
   境界で型消去する層を 1 枚挟み、最上位に巨大タプル型を漏らさない。
8. **executor 非依存 async** — embassy-sync/embassy-time/embassy-futures を利用。
   特定 executor には依存しない。
9. **プラットフォーム抽象は最小 trait + 単一バックエンド** — Network(UDP)/Crypto/
   KVS/Clock を trait 化(依存性逆転)。CRTP 多層 Generic 相当の抽象多重化はしない。
   mDNS は既存 no_std crate の活用を優先。
10. **bloat-check を day 1 から** — `size_of_val` によるコンポーネント別 RAM 計測と
    実 MCU クロスビルドを早期に CI へ。

## レイヤ構成(モジュール境界)

依存は下→上の一方向。connectedhomeip の「正しい継ぎ目」を trait/module 境界にマップする。

```
error      : 統一エラー型
tlv        : TLV Reader/Writer(証明書・IM ペイロード共用。自前実装必須)
crypto     : CryptoProvider trait(Spake2p, P256, HKDF, AES-CCM, SHA-256)+ backend 1 つ
transport  : Network(UDP) trait, SessionManager, SecureSession(PASE|CASE), 暗号境界, counter
exchange   : ExchangeManager, ExchangeContext(+MRP 内包), プロトコルディスパッチ
sc         : Secure Channel — PASE / CASE(responder のみ)。メッセージ ↔ ハンドラ 1:1
im         : Interaction Model — wire 定数と server エンジン(Read/Write/Invoke/Subscribe)
dm         : DataModelProvider trait + Endpoint/Cluster/Attribute メタデータ + クラスタ実装
fabric     : FabricTable, NOC/ICAC/RCAC, DAC/PAI/CD(Device Attestation)
platform   : KVS/Clock 等の最小 trait
discovery  : commissionable / operational mDNS(既存 crate 活用)
```

## 初期スコープ(最小縦通し)

「IP コミッショニング + PASE/CASE + IM + On/Off ライト」を最短で通す。

- トランスポート: UDP のみ(BLE コミッショニングは feature で後日)
- クラスタ: Basic Information, Descriptor, Identify, On/Off,
  General Commissioning, Network Commissioning, Operational Credentials,
  General Diagnostics 程度の必須最小
- スコープ外(feature gate で将来): BDX/OTA、group messaging、session resumption、
  ICD、UDC、TCP、コントローラ側

## ロードマップ

1. **基盤**: error / tlv / crypto trait + テスト(std 上でユニットテスト)
2. **transport + exchange**: セッション管理・MRP・暗号境界
3. **sc**: PASE(Spake2+)→ CASE(Sigma1/2/3)responder
4. **fabric/credentials**: FabricTable、証明書のヒープレスパース
5. **im + dm**: IM エンジンと最小クラスタ、On/Off ライト縦通し
6. **discovery/platform 統合**: mDNS、実機(Embassy)ポート、bloat-check CI
