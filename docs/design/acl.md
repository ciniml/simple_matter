# ACL(Access Control)設計

full ACL(Access Control クラスタ 0x001F + IM 経路での per-entry 権限評価)の設計。
`docs/design/interaction-model.md` §10 の「最小近似(CASE=fabric メンバに Administer、
PASE=コミッショニングクラスタのみ)」を置き換える。Matter Core Spec §6.6(Access
Control)/ §9.10(Access Control Cluster)に基づく。

## 1. スコープと解消する割り切り

### 解消するもの

| 従来の割り切り | 本設計 |
|---|---|
| per-entry ACL 照合なし(CASE=一律 Administer) | ACL テーブル([`AclTable`])を評価し、subject(NodeId/CAT)× target(endpoint/cluster)× privilege で判定 |
| PASE はコミッショニングクラスタ(0x0028/0x0030/0x0031/0x003E)のみ許可 | 仕様どおり **PASE = implicit Administer(全 target)**(§6.6.2.9。chip の implicit PASE entry と同じ) |
| AccessControl クラスタ(0x001F)なし | read/write(ReplaceAll + chunked Append)対応で実装 |
| AddNOC の caseAdminSubject(tag 3)を無視 | AddNOC 成功時に当該 fabric の **bootstrap admin エントリ**(privilege=Administer, authMode=CASE, subjects=[caseAdminSubject])を自動生成(§11.17.6.8) |
| `CurrentFabricIndex` が常に 0 | `ServerCluster::read_attribute` に `AccessContext` を渡し、セッションの fabric index を返す |
| セッションが peer CAT を保持しない | CASE 確立時に NOC の CAT を `SessionState` に保存し、`AccessContext.cats` として ACL 判定に使う |
| 属性の write 権限が read 権限と同一 | `AttributeMeta.write_access` を分離(Breadcrumb = read View / write Administer 等) |
| コマンド権限が一律 Operate | `cluster!` の accepted 行に `=> Privilege` を書ける(GC / NetComm = Administer) |

### 残す割り切り(理由付き)

- **OpCreds の NOCs / Fabrics / TrustedRootCertificates の fabric フィルタ**:
  `fabric_filtered=true` の read では自 fabric 行のみ返すが、`false` のときの
  「他 fabric 行の редact(機微フィールド落とし)」はしない(全行そのまま)。ACL 実装
  に必須ではないため。
- **ACL target の deviceType 指定**: エントリとして受理・保存はするが、判定では
  マッチしない(deviceType → endpoint 解決は DataModel 参照が要る。chip-tool は使わない)。
- **CASE resumption 後の CAT**: resumption レコードに CAT を保存しないため、resumption
  で確立したセッションの CAT は空(NodeId subject は保持)。CAT ベースの ACL を使う場合
  のみ影響。
- **Extension 属性(0x0001)**: optional のため未実装。
- **AccessControlEntryChanged イベント**: イベント基盤ごと初期スコープ外。
- **ports/esp32 のバイナリ**: `DataModel::acl()` の既定(`None` = 従来近似)のまま。
  ESP32 側の full ACL 化は別タスク(コアはビルド green を維持)。

## 2. データモデル

`src/acl.rs`(no_std / no-alloc / 固定容量)。

```rust
pub const MAX_ACL_SUBJECTS: usize = 4;   // SubjectsPerAccessControlEntry(仕様最小値)
pub const MAX_ACL_TARGETS: usize = 3;    // TargetsPerAccessControlEntry(仕様最小値)
pub const ACL_ENTRIES_PER_FABRIC: usize = 4; // AccessControlEntriesPerFabric(仕様最小値)

pub enum AuthMode { Pase = 1, Case = 2, Group = 3 }

pub struct AclTarget {         // 少なくとも 1 フィールド Some、endpoint と device_type は排他
    pub cluster: Option<u32>,
    pub endpoint: Option<u16>,
    pub device_type: Option<u32>,
}

pub struct AclEntry {          // fabric-scoped
    fabric_idx: NonZeroU8,
    privilege: Privilege,      // dm::meta::Privilege(View < Operate < Manage < Administer)
    auth_mode: AuthMode,
    subjects: [u64; MAX_ACL_SUBJECTS], nsubjects: u8,   // 空 = 全 subject
    targets: [AclTarget; MAX_ACL_TARGETS], ntargets: u8, // 空 = 全 target
}

pub struct AclTable<const E: usize> {
    entries: FixedVec<AclEntry, E>,
    generation: u32,           // 永続化フック(FabricTable と同じ流儀)
}
```

- 容量 `E` はアプリ選択(例: fabric 5 × 4 エントリ = 20、PC example は 8)。
  加えて **per-fabric 上限 `ACL_ENTRIES_PER_FABRIC`** を `add` で強制する。
- エントリ検証(write / 復元時共通):
  - `privilege = Administer` は `auth_mode = Case` のみ(Group への Administer 付与禁止)。
  - `auth_mode = Pase` のエントリは受理しない(implicit 専用、§9.10.5.3)。
  - target は「少なくとも 1 フィールド非 null、endpoint/deviceType 排他」。
  - 違反は `ConstraintError`。

### CAT subject

subject が `0xFFFF_FFFD_xxxx_xxxx`(NodeId の CASE Authenticated Tag 領域)の場合は
CAT 照合: 上位 16 bit(identifier)一致かつ **セッション CAT の version ≥ エントリの
version** で一致(§6.6.2.5)。セッション側 CAT は CASE Sigma3 の NOC subject から取り
(`PeerIdentity::cats`)、`SessionState.peer_cats` に保存する。

## 3. 権限評価(IM 経路)

evaluation は object-safe trait 越しにエンジンから呼ぶ:

```rust
pub trait AclHandle {   // impl for RefCell<AclTable<E>>(内部可変性、fabric と同じ共有流儀)
    fn check(&self, acc: &AccessContext, ep: EndpointId, cl: ClusterId, required: Privilege) -> bool;
    fn add_case_admin(&self, fabric: NonZeroU8, subject: u64) -> Result<()>;  // AddNOC bootstrap
    fn remove_fabric(&self, fabric: NonZeroU8);                                // RemoveFabric 連動
}

pub trait DataModel {
    ...
    /// このデバイスの ACL(なければ従来近似: PASE=コミッショニングクラスタ、CASE=Administer)
    fn acl(&self) -> Option<&dyn AclHandle> { None }
}
```

- **判定規則**(`AclTable::check`):
  1. `SessionKind::Pase` → **implicit Administer**(常に許可)。仕様 §6.6.2.9 / chip の
     implicit PASE entry と同じ。旧実装の「コミッショニングクラスタ限定」より緩くなる
     (仕様準拠方向)。
  2. `SessionKind::Case` → `acc.fabric_idx` 必須(無ければ拒否)。自 fabric のエントリを
     走査し、`auth_mode == Case` かつ `privilege が required 以上` かつ subject 一致
     (空=全、NodeId 完全一致 or CAT 照合)かつ target 一致(空=全、cluster/endpoint
     一致。deviceType は不一致扱い)なら許可。
- **必要権限**:
  - 属性 read = `AttributeMeta.access`(グローバル属性は View)。
  - 属性 write = `AttributeMeta.write_access`(新設。既定 Operate、Breadcrumb/ACL は Administer)。
  - コマンド invoke = `CommandMeta.access`(`cluster!` の `=> Privilege` 注釈。既定 Operate)。
- **拒否時の StatusCode**: read はパスごとの `UnsupportedAccess` StatusIB、write/invoke も
  `UnsupportedAccess`(§8.4.3.2)。パス不存在チェック(UnsupportedEndpoint/Cluster/
  Attribute/Command)を**先**に、ACL を**後**に評価する(存在の秘匿はしない。chip と同じ)。
- **購読レポート**: プライミング時の `AccessContext`(subject/CAT 込み)を購読エントリに
  保存し、定期レポートの再評価に使う(従来は fabric_idx のみ保持で Administer 固定)。

## 4. AccessControl クラスタ(0x001F)

`dm/clusters/access_control.rs`。`OpCredsCluster` と同様に**手書き ServerCluster**
(`RefCell<AclTable<E>>` への共有参照を保持。ジェネリクスのため `cluster!` 不可)。

| 属性 | ID | 型 | access |
|---|---|---|---|
| ACL | 0x0000 | list[AccessControlEntryStruct]、fabric-scoped | read Administer / write Administer |
| SubjectsPerAccessControlEntry | 0x0002 | u16 = 4 | View |
| TargetsPerAccessControlEntry | 0x0003 | u16 = 3 | View |
| AccessControlEntriesPerFabric | 0x0004 | u16 = 4 | View |

- エントリ TLV(§9.10.5.3): `{ 1: privilege(u8), 2: authMode(u8), 3: subjects(array<u64>|null),
  4: targets(array<struct{0:cluster|null,1:endpoint|null,2:deviceType|null}>|null), 254: fabricIndex }`。
  空 subjects/targets は null で書く(chip と同じ)。
- privilege のワイヤ値: View=1, ProxyView=2(未対応→ConstraintError), Operate=3,
  Manage=4, Administer=5。
- **read**: `fabric_filtered`(ReadRequest フラグ→`AccessContext.fabric_filtered` に伝搬)
  なら自 fabric 行のみ、それ以外は全行。
- **write**(fabric-scoped): 書き込み元 fabric のエントリのみ操作。fabric 無し(PASE
  未昇格)は `UnsupportedAccess`。
  - **ReplaceAll**(パスに ListIndex 無し、値=array): 自 fabric 行を全消去して並べ直す。
  - **Append**(パスの ListIndex = null): 1 エントリ追加。chip-tool の chunked list write
    (先頭 IB=空配列、以降 IB=ListIndex null の per-item append)がこの経路。
  - 容量超過 = `ResourceExhausted`、検証違反 = `ConstraintError`。
  - 書かれたエントリの fabricIndex フィールドは無視し、アクセス元 fabric を強制。
- 自分の Administer エントリを消す write も**受理**する(仕様どおり。管理権喪失は
  コミッショナの責任)。

### ワイヤ変更(im/wire)

- `AttributePath` に `list_append: bool` を追加。AttributePathIB の ListIndex(tag 5)が
  **null** の場合に立てる(chip の「append/modify マーカ」)。u16 の индекс指定 write は
  非対応のまま(`to_concrete` は従来どおり None → InvalidAction)。
- `ServerCluster::write_attribute` のデータは `TlvElement`(先頭要素のみ)から
  **`AttrWrite<'_>`(値サブツリー全体の生 TLV + `ListOp::{ReplaceAll, AppendItem}`)** に
  変更。コンテナ(list 属性)の中身をクラスタが自分で iterate できる。

## 5. subject 解決(セッション → AccessContext)

- `SessionInit` / `SessionState` に `peer_cats: [u32; 3]` + 件数を追加。
  - フル CASE: Sigma3 の `PeerIdentity::cats()` を保存。
  - PASE / resumption / plaintext: 空。
- `AccessContext` に `cats: [u32; 3]` / `cat_count` / `fabric_filtered` を追加。
  `access_from_session` がセッションから写す。`privilege` フィールドは従来近似
  (acl() == None)経路でのみ意味を持つ。

## 6. KVS 永続化

fabric(`docs/design/port-esp32-device.md` §E4)と同じ分業:

- コアは `AclTable::save_to(&self, kvs)` / `load_from(&mut self, kvs)` を提供。
  いつ呼ぶかは統合層が `AclTable::generation()` の変化で決める(sans-IO 維持)。
- レコード(キー `b"aclt"`、schema version 1): 単一 TLV
  `struct { cx0: version(u8)=1, cx1: array<entry> }`。エントリは
  `struct { cx1: fabric(u8), cx2: privilege(u8), cx3: authMode(u8), cx4: subjects(array<u64>),
  cx5: targets(array<struct>) }`(ワイヤ表現と同じ target 構造)。
- 復元時は write と同じエントリ検証を行い、違反レコードは `Error::Decode` で中断。
- fabric 復元との整合: `load_from` 後、fabric テーブルに存在しない fabric のエントリは
  捨てる(呼び出し側が fabric 復元→ACL 復元の順で呼ぶ)。

## 7. サイジング / no-alloc

- `AclEntry` ≈ 96B(subjects 4×8 + targets 3×16 + ヘッダ)。`E=8` で ≈ 800B .bss。
- 判定は自 fabric エントリの線形走査(≤ E)。定常パスにヒープ確保なし。
- 評価はすべて `no_std` コア内。feature ゲートなし(常時コンパイル)。

## 8. テスト計画

- acl.rs 単体: エントリ検証(PASE authMode 拒否、Group Administer 拒否、target 制約)、
  per-fabric 容量、CAT 照合(identifier 一致 + version 順序)、fabric 分離、
  save/load ラウンドトリップ。
- engine 単体: ACL 付き DataModel で
  - 権限不足の read/write/invoke が `UnsupportedAccess`
  - PASE implicit admin(OnOff invoke が通る — 旧テストの反転)
  - AddNOC → bootstrap admin エントリ生成 → CASE subject で invoke 成功
  - ACL エントリ CRUD(ReplaceAll / Append / 読み戻し、fabric フィルタ)
  - RemoveFabric でエントリ連動削除
- E2E(chip-tool / Linux UDP): コミッショニング(bootstrap admin)→ toggle →
  `accesscontrol read acl 1 0` → ACL write(privilege 降格/削除)→ 再 invoke 拒否。
