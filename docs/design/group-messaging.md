# Group messaging 設計 — Groups 0x0004 / GroupKeyManagement 0x003F / groupcast 受信

対象: `crates/simple-matter/src/groups.rs`(新規、group ストア + 鍵導出 + マルチキャストアドレス)、
`src/dm/clusters/{groups,group_key_management}.rs`(新規)、`src/acl.rs` / `src/dm/meta.rs`
(Group 認証)、`src/im/engine.rs`(group invoke 配送)、`src/stack.rs`(groupcast 受信経路)、
`examples/onoff-light.rs`、`crates/smctl/src/clusters/`。

仕様ソース: Matter Core Spec §4.15(Group Key Management)/ §2.5.6(Group multicast
アドレス)/ §4.6.2(groupcast メッセージ)/ §9.9(Groups)/ §11.2(Group Key Management
Cluster)。chip 参照実装の対応箇所は本文中に付記(調査は 2026-07-09、
`research/connectedhomeip`(1.4 系)+ `~/repos/connectedhomeip`(1.1 系)+
chip-tool snap v1.5.1 の CLI 実測)。

## 0. サマリ(主要な設計判断)

1. **受信側のみ実装**(送信 = controller 側 groupcast はスコープ外)。E2E の送信側は
   chip-tool(単発 CLI で groupcast 送信可能なことを確認済み: `groupsettings` でローカル
   鍵設定 → `chip-tool onoff toggle 0xffffffffffff<gid> 1`)。smctl からの groupcast 送信は
   将来課題として §8 に手順を記す。
2. **group セッションはセッションテーブルに入れない**。ワイヤ session id = GKH(Group Key
   Hash)は鍵から決まる値で、ピア単位の状態を持たないため、`SessionMode::Group` を追加する
   のではなく **`MatterStack::handle_rx` にユニキャストと独立した groupcast 分岐**を設ける
   (chip も group 受信は SecureSession と別経路)。受信状態(送信元別カウンタ)は
   スタック所有の小さな固定テーブルに持つ。
3. **鍵ストアは fabric/ACL と同型の共有 `RefCell<GroupStore>`**: fabric-scoped 固定容量、
   `generation()` で永続化トリガ、`save_to`/`load_from`(キー `b"grpt"`)、
   `retain_fabrics`/`clear_fabric` で fabric 削除連動。クラスタ(EP0 GroupKeyManagement /
   EP1 Groups)と transport(復号)とアプリ(マルチキャスト join)が共有する。
4. **Privacy(P フラグ)非対応**: chip の groupcast 送信は 1.1〜1.4 系とも P=0
   (`SessionManager::PrepareMessage` の kGroupOutgoing 分岐に SetPrivacy なし)。P=1 の
   受信はドロップ(将来: PrivacyKey = HKDF(op key, "PrivacyKey") + AES-CTR ヘッダ難読化)。
5. **ACL は AuthMode::Group を正実装**: subject は **group node id 形式**
   `0xFFFF_FFFF_FFFF_0000 | group_id`(chip `AccessControl.cpp` は `IsGroupId(subject)` で
   この形式のみ受理、照合は `subject == NodeIdFromGroupId(gid)` の等値)。Administer の
   Group 付与禁止は実装済み(acl.rs)。
6. **応答なし invoke**: groupcast は ACK 禁止・応答禁止。IM は既存の suppress-response
   経路(`HandlerAction::None`)を流用し、exchange/MRP を作らず配送する。
7. **エンドポイント展開は DataModel 契約**: group invoke の CommandPath は endpoint を
   持たない。`DataModel::group_endpoints(fabric, group_id, idx)`(既定 `None` = group 非対応)
   を追加し、デバイスが GroupStore のメンバーシップへ委譲する。コアの他契約は不変。
8. **グループ名は非対応**(GN feature off、NameSupport=0x00、名前は保存しない)。
   ヒープレス維持のための割り切り(chip-tool の add-group は名前引数を要求するが、
   デバイス側が名前を保存しない構成は仕様上合法)。

## 1. groups.rs — GroupStore と鍵導出

### 1.1 鍵導出(仕様 §4.15.3、chip `CHIPCryptoPAL.cpp` L758-842 と一致させる)

すべて `Crypto::hkdf_sha256` で実装(既存 API のみ、crypto trait 変更なし):

- **operational group key** = `HKDF(salt = CompressedFabricId(8B), ikm = EpochKey(16B),
  info = "GroupKey v1.0", L=16)`。既存 `fabric::derive_operational_ipk` と同一式
  (IPK は epoch key を同式に通した特例)。groups.rs に `derive_operational_group_key` を
  公開し、fabric.rs の私有関数は将来これへ委譲してよい(乖離しないこと)。
- **GKH(Group Session ID)** = `HKDF(salt = [], ikm = OperationalGroupKey,
  info = "GroupKeyHash", L=2)` の 2 バイトを **big-endian u16** として読む
  (chip `DeriveGroupSessionId`)。
- テストベクタ(chip `TestGroupDataProvider.cpp` L844-882、仕様 §4.15.3 の値):
  epoch key `235bf7e62823d358dca4ba50b1535f4b` + compressed fabric id
  `87e1b004e235a130` → operational key `a6f5306baf6d050af23ba4bd6b9dd960`。
  このベクタと、operational key → GKH の値(実装時に chip の
  `TestGroupDataProvider` の kGroupKeys ベクタから採取して固定)を単体テストにする。

### 1.2 データ構造(fabric-scoped 固定容量、acl.rs と同型)

```rust
pub struct GroupStore<const KS: usize, const GM: usize, const GT: usize> {
    keysets: FixedVec<KeySetEntry, KS>,   // KeySetWrite の結果(IPK keyset 0 は含まない)
    maps: FixedVec<MapEntry, GM>,         // GroupKeyMap 属性(group ↔ keyset)
    groups: FixedVec<GroupEntry, GT>,     // Groups クラスタのメンバーシップ(GroupTable 属性)
    generation: u32,
}
struct KeySetEntry {
    fabric_idx: NonZeroU8,
    id: u16,                              // 0 は格納しない(IPK は FabricTable 所有)
    policy: u8,                           // 0 = TrustFirst のみ受理
    epochs: [Epoch; 3], nepochs: u8,
}
struct Epoch { key: [u8; 16], start_time_us: u64, op_key: [u8; 16], gkh: u16 }
struct MapEntry { fabric_idx: NonZeroU8, group_id: u16, key_set_id: u16 }
struct GroupEntry { fabric_idx: NonZeroU8, group_id: u16, endpoints: [u16; 4], neps: u8 }
```

- per-fabric 上限(add で強制): keyset 3 本(`MAX_GROUP_KEYSETS_PER_FABRIC`)、
  map 4 行(= 属性 MaxGroupsPerFabric の公称値 4)、group メンバーシップ 4 行。
  既定サイジング(型エイリアス `DefaultGroupStore`)は KS=6 / GM=8 / GT=8。
- 導出鍵(op_key/gkh)は KeySetWrite 時に計算して格納(受信ホットパスで HKDF しない)。
  PrivacyKey は導出しない(P 非対応)。
- API(クラスタ/transport/アプリが使う):
  - `set_keyset(fabric, id, policy, epochs, crypto, compressed_fabric_id) -> Result<()>`
  - `keyset(fabric, id)` / `remove_keyset(fabric, id)`(map が参照中でも削除可 = chip 同様)
  - `keyset_ids(fabric, idx) -> Option<u16>`(KeySetReadAllIndices 用)
  - `set_map(fabric, entries)` / `map_iter(fabric)`(GroupKeyMap の ReplaceAll/Append)
  - `add_member(fabric, gid, ep)` / `remove_member` / `remove_all_members(fabric, ep)` /
    `member_endpoints(fabric, gid)` / `groups_iter(fabric)`
  - `has_key_for_group(fabric, gid) -> bool`(AddGroup の UnsupportedAccess 判定)
  - **復号候補**: `key_candidate(gkh: u16, gid: u16, idx: usize) -> Option<(NonZeroU8, [u8;16])>`
    = 「map で gid に紐づく keyset の epoch のうち gkh 一致」を index 順に返す
    (呼び出し側が idx 0.. で試行復号)。
  - `generation()` / `save_to(kvs)` / `load_from(kvs)`(キー `b"grpt"`、versioned TLV、
    導出済み op_key/gkh も保存して単独復元可能にする)/ `clear_fabric` / `retain_fabrics`。

### 1.3 マルチキャストアドレス導出(§2.5.6、chip `PeerAddress.h` L212)

```
group_multicast_addr(fabric_id: u64, group_id: u16) -> Ipv6Addr
= FF35:0040:FD<fabric_id[63:8]> : <fabric_id[7:0]> 00 <group_id>
  (バイト列: FF 35 00 40 FD || fabric_id BE 8B || 00 || group_id BE 2B ではなく、
   FD の後に fabric_id の上位 56bit、続くバイトに fabric_id 下位 8bit、00、group_id 16bit)
```
単体テストは chip の式(`prefix = 0xfd00000000000000 | (fabric >> 8)`、
`group32 = ((fabric << 24) & 0xff000000) | group`)との一致を数ベクタで固定する。
scope は site-local(0x5)固定、port 5540 固定。なお 1.4 以降の chip には固定
IANA アドレス `FF05::FA` へ送る mcast policy もあるが、**既定は per-group アドレス**
(`GroupInfo::kFlagsDefault = kMcastAddrPolicy`)のため per-group のみ対応(割り切り §9)。

## 2. GroupKeyManagement クラスタ 0x003F(EP0、revision 2)

`dm/clusters/group_key_management.rs`。`new_shared(&RefCell<GroupStore>, &RefCell<FabricTable>,
crypto)`(OpCreds と同じ共有パターン。KeySetWrite の導出に compressed fabric id と crypto が
必要)。revision は Matter 1.3 時点の 2 を採用(1.4 系 XML は 4。GroupcastAdoption 等の
1.4+ 追加は非対応)。feature_map = 0。

- 属性: GroupKeyMap 0x0000(list、**rw、write 権限 Manage**、fabric-scoped、
  ReplaceAll + chunked Append = access_control.rs の ListOp パターン)、GroupTable 0x0001
  (list、RO、fabric-scoped。GroupStore.groups から GroupInfoMapStruct
  {1: groupId, 2: endpoints[], (3: groupName 省略)} + fabricIndex(254))、
  MaxGroupsPerFabric 0x0002 = 4、MaxGroupKeysPerFabric 0x0003 = 3。
- GroupKeyMap 行 = GroupKeyMapStruct {1: groupId, 2: groupKeySetID} + fabricIndex(254)。
  検証: groupKeySetID == 0 は ConstraintError(IPK へのマップ禁止、chip L217/L232)、
  groupId == 0 は ConstraintError。fabric read フィルタは acc.fabric_filtered。
- コマンド(**全て Administer**、fabric 必須 = acc.fabric_idx が None なら
  UnsupportedAccess):
  - 0x00 KeySetWrite {0: GroupKeySetStruct}: 検証は chip `group-key-mgmt-server.cpp`
    L303-376 と一致させる — EpochKey0 null/空 or EpochStartTime0 null/0 → InvalidCommand、
    policy 未知(0/1 以外)→ ConstraintError、CacheAndSync(1)→ InvalidCommand(MCSP
    非対応)、EpochKey1 非 null なら StartTime1 > StartTime0 必須、EpochKey2 非 null なら
    EpochKey1 非 null かつ StartTime2 > StartTime1 必須(違反 InvalidCommand)、
    epoch key 長 ≠ 16 → ConstraintError。**GroupKeySetID == 0 は fabric の IPK 更新**
    (`FabricTable::rotate_ipk(epoch_key0)`。epoch 1/2 は無視、割り切り §9)。
    それ以外は `GroupStore::set_keyset`(導出込み)。満杯 → ResourceExhausted。
  - 0x01 KeySetRead {0: id} → 0x02 KeySetReadResponse {0: GroupKeySetStruct}:
    **EpochKey0-2 は常に null** で返す(chip L453-475)。StartTime は保持値
    (id==0 は StartTime0=0 のみの 1 epoch 構成で返す)。未知 id → NotFound。
  - 0x03 KeySetRemove {0: id}: id==0 → InvalidCommand(IPK 削除禁止)。未知 → NotFound。
    削除時に当該 keyset を参照する GroupKeyMap 行も削除(chip 同様)。
  - 0x04 KeySetReadAllIndices → 0x05 Response {0: [ids]}: 自 fabric の keyset id 列 +
    先頭に 0(IPK)を含める。

## 3. Groups クラスタ 0x0004(機能 EP、revision 4、feature_map 0)

`dm/clusters/groups.rs`。`new_shared(&RefCell<GroupStore>, endpoint_id)`(インスタンスは
EP ごと、自 EP の id を保持)。NameSupport 0x0000(map8)= 0x00(GN off、§0-8)。

- コマンド(Add/Remove 系 = **Manage**、View/GetMembership = Operate。全て fabric 必須):
  - 0x00 AddGroup {0: gid, 1: name} → 0x00 AddGroupResponse {0: status, 1: gid}:
    gid == 0 → status ConstraintError。`!has_key_for_group(fabric, gid)` →
    status UnsupportedAccess(chip groups-server L82)。満杯 → ResourceExhausted。
    成功 = メンバーシップに (fabric, gid, self.ep) を追加(名前は破棄)。
  - 0x01 ViewGroup {0: gid} → 0x01 ViewGroupResponse {0: status, 1: gid, 2: name=""}:
    無効 gid → ConstraintError、自 EP 非所属 → NotFound。
  - 0x02 GetGroupMembership {0: [gids]} → 0x02 Response {0: capacity(nullable、null で
    返す = 容量不定)、1: [gids]}: 空リスト = 自 EP の全所属、非空 = 交差。
  - 0x03 RemoveGroup {0: gid} → 0x03 Response {0: status, 1: gid}: 自 EP を外し、
    EP が空になったエントリは削除。非所属 → NotFound。
  - 0x04 RemoveAllGroups(応答なしコマンド、status Success のみ): 自 EP を全エントリから外す。
  - 0x05 AddGroupIfIdentifying {0: gid, 1: name}(応答なし): **識別中のみ** AddGroup 相当。
    識別状態は `set_identifying(bool)` でアプリが仲介(Identify クラスタの listener から
    配線。take_on_off_request と同じクラスタ↔アプリ契約)。非識別中は無視(Success)。
    エラー(無効 gid 等)は status で返す。
- 状態変更はすべて GroupStore の generation を進める(アプリの永続化 + join 同期トリガ)。

## 4. ACL — AuthMode::Group の正実装

- `dm/meta.rs`: `SessionKind::Group` を追加。groupcast の `AccessContext` は
  `kind=Group, fabric_idx=Some(解決 fabric), subject = 0xFFFF_FFFF_FFFF_0000 | gid,
  cats=[], fabric_filtered=false`。
- `acl.rs AclTable::check` に Group 分岐: `auth_mode == Group` のエントリのみ対象、
  subject 照合は**等値**(entry subject == acc.subject。CAT 照合はしない)。subjects 空は
  全 group にマッチ(chip の subjectCount==0 と同じ)。target/privilege 判定は共通。
- エントリ検証(`AclEntry::is_valid` 拡張): Group エントリの subject は
  group node id 形式(上位 48bit = 0xFFFF_FFFF_FFFF かつ下位 16bit != 0)のみ有効
  (chip `IsValidGroupNodeId`)。CASE エントリに group node id subject は不可、の
  相互制約は**警告レベル(受理)**に留める(chip は AccessControl 層で INCORRECT_STATE
  だが、書込み時検証は subjects の形式チェックのみ。乖離時は理由明記)。
- `im/engine.rs` の `allowed` フォールバック(`dm.acl() == None`)は Group を
  **Operate 近似で許可**(CASE の近似と整合。full ACL デバイスでは per-entry 判定)。

## 5. transport / stack — groupcast 受信経路

### 5.1 受信分岐(`MatterStack::handle_rx`)

`ensure_unsecured_session` と同様に平文ヘッダを覗き、
`sec_flags.is_group_session()` なら `handle_group_rx`(新設、private)へ分岐して
ユニキャスト経路(`mgr.recv`)には入れない。

`handle_group_rx` の手順:
1. ヘッダ検証: S フラグ(src_node_id)必須、`dst == DstNodeId::Group(gid)` 必須、
   P フラグ(sec_flags bit7)は非対応 → drop。C フラグ(control message)→ drop。
2. **試行復号**: `GroupKeyResolver::key_candidate(pkt.session_id, gid, idx)` を idx 0.. で
   引き、各鍵で `SecureCodec::decrypt`(nonce の node id = src_node_id)。ヘッダの
   AAD/暗号文は試行ごとに再利用が必要なので、datagram をローカルへコピーして試す
   (最大長 1583B のスタックバッファ 1 本。試行本数は高々 keyset×epoch = 数本)。
3. **カウンタ検証(trust-first)**: スタック所有の
   `FixedVec<GroupPeer { fabric_idx, node_id, window: PeerWindow }, GROUP_PEERS=8>` で
   (fabric, src node) を引き、未知ピアは受信 ctr で窓を初期化して受理(trust-first)、
   既知は `PeerWindow::accept(ctr, true)`。満杯は LRU 上書き。重複/窓外 → drop。
   (chip の `VerifyOrTrustFirstGroup` のロールオーバー緩和は近似 = 割り切り §9)
4. **PayloadHeader 検証**: `proto_id == IM` かつ opcode == InvokeRequest のみ受理
   (WriteRequest の groupcast は非対応 = 割り切り)。R フラグ(reliable)付き
   groupcast は仕様違反 → drop(chip L946 同様)。A フラグも無視。
5. **IM 配送**: `InteractionModel::invoke_group(payload, gid, fabric_idx, now_ms)`(新設)。
   応答は生成しない(戻り値なし、`HandlerAction::None` 相当)。

スタックへの鍵供給は object-safe trait で注入する(const generic の伝播を避ける):

```rust
pub trait GroupKeyResolver {
    fn key_candidate(&self, gkh: u16, group_id: u16, idx: usize)
        -> Option<(NonZeroU8, [u8; AES_CCM_KEY_LEN])>;
}
impl<...> GroupKeyResolver for RefCell<GroupStore<...>> { ... }
// MatterStack::set_group_keys(&'s dyn GroupKeyResolver)(既定 None = groupcast 無効)
```

### 5.2 IM 側(`invoke_group`)

- InvokeRequest をパースし(SuppressResponse フラグ値に関わらず**常に応答なし**)、
  各 CommandDataIB について: CommandPath の endpoint は無視(chip は
  group invoke で endpoint を省略/無視)。
- **展開**: `DataModel::group_endpoints(fabric, gid, idx)`(新設、既定 None)で
  所属 EP を列挙し、各 EP × path.cluster に対し `allowed(..., SessionKind::Group)` →
  `invoke_one`。応答書き込みはスクラッチ(suppress 経路と同じく encode 結果を破棄)。
  timed 必須コマンド(@timed)は groupcast では常に拒否(NeedsTimedInteraction 相当で
  スキップ。応答は出さない)。
- InvokeEffects(fabric 昇格等)は group では発生しない前提で無視する
  (AddNOC 等 Administer コマンドは ACL 制約(Group に Administer 不可)で到達しない)。

### 5.3 マルチキャスト join(アプリ層)

- PC examples: メインループで `GroupStore::generation()` の変化を検知し、
  全 GroupEntry について fabric idx → `FabricTable::fabric_id` → `group_multicast_addr` を
  計算し、Matter UDP ソケット(5540)へ `join_multicast_v6(&addr, ifindex)` する
  (mDNS の join パターンに倣い、既定経路 iface + loopback の両方。重複 join の
  AddrInUse 系エラーは無視)。leave は行わない(割り切り §9)。
- ESP32(e5-light)は今回スコープ外(doc 記載のみ。embassy-net の join_multicast_group
  は将来課題)。

## 6. DataModel 契約の変更(最小)

- `DataModel::group_endpoints(&self, fabric: NonZeroU8, group_id: u16, idx: usize)
  -> Option<EndpointId>`(既定 `None`)。GroupStore 保有デバイスは
  `store.borrow().member_endpoints(...)` へ委譲。
- `device!` マクロは変更しない(group 対応デバイスは手書き DataModel か、
  impl ブロックでのメソッド上書きで対応)。

## 7. examples / smctl

- **onoff-light を group 対応化**(On/Off Light デバイスタイプの必須クラスタ充足も兼ねる):
  EP0 に GroupKeyManagement、EP1 に Groups を追加し、`GroupStore` + join 同期 +
  `SM_STATE_DIR` 永続化(キー `grpt`)を配線。Identify listener → Groups の
  `set_identifying` 配線。
- smctl: `clusters/groups.rs` / `group_key_management.rs` の cluster_def! を追加
  (KeySetWrite の GroupKeySetStruct はネスト struct のため、フィールドは
  cluster_def! の表現力の範囲で収載。困難なら cmds は主要コマンドのみ + any invoke
  --raw-fields の手順を doc 化)。**smctl からの groupcast 送信は今回非対応**。

## 8. E2E(chip-tool snap v1.5.1 + smctl)

デバイス: `MATTER_DEBUG=1 SM_STATE_DIR=... cargo run --release --example onoff-light`

1. `chip-tool pairing already-discovered 1 20202021 127.0.0.1 5540
   --paa-trust-store-path ~/snap/chip-tool/common/paa-certs`
2. デバイスへ鍵設定(over the air):
   - `chip-tool groupkeymanagement key-set-write '{"groupKeySetID": 42,
     "groupKeySecurityPolicy": 0, "epochKey0": "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
     "epochStartTime0": 2220000, "epochKey1": null, "epochStartTime1": null,
     "epochKey2": null, "epochStartTime2": null}' 1 0`
   - `chip-tool groupkeymanagement write group-key-map
     '[{"groupId": 257, "groupKeySetID": 42}]' 1 0`
   - `chip-tool groups add-group 0x0101 Light 1 1`
   - ACL に Group エントリ追加(既存 admin エントリを壊さないよう read → 全置換):
     `chip-tool accesscontrol write acl '[{...既存 admin...}, {"fabricIndex": 1,
     "privilege": 3, "authMode": 3, "subjects": [18446744073709486337],
     "targets": null}]' 1 0`(subjects = 0xFFFFFFFFFFFF0101 = group node id)
3. chip-tool ローカル側の group 設定:
   - `chip-tool groupsettings add-group Light 0x0042`
   - `chip-tool groupsettings add-keysets 0x002A 0 0x000000000021dfe0
     hex:d0d1d2d3d4d5d6d7d8d9dadbdcdddedf`
   - `chip-tool groupsettings bind-keyset 0x0042 0x002A`
   - **罠(実測 2026-07-09)**: chip-tool は初期状態で group 0x0101-0x0103
     (`Group #1..#3`)が keyset 0x1a1-0x1a3(既定 epoch 鍵)に bind 済みで、
     `bind-keyset` の追加 bind より**既存 bind の keyset が送信に使われる**
     (GKH 不一致でデバイス側は復号候補なし = 黙って drop)。E2E は既定 bind の無い
     group id(例 0x0042)を使うこと。
4. **groupcast 送信**: `chip-tool onoff toggle 0xffffffffffff0042 1`(単発 CLI、
   マルチキャスト 1 パケット送出で exit)→ デバイスの OnOff がトグルすることを
   ログ + `chip-tool onoff read on-off 1 1` で確認。
5. smctl(ユニキャスト CRUD): `smctl groupkeymanagement key-set-read-all-indices`、
   `smctl groups add-group/view-group`、`smctl any read <node> 0 0x003F 0x0001`
   (group-table)。key-set-write / group-key-map はネスト struct のため
   `smctl any invoke ... tlv:<hex>` / `any write ... tlv:<hex>` で送る(cluster_def!
   の表現力の割り切り)。
6. GroupTable/GroupKeyMap の read、KeySetRead の epoch key null 化、
   KeySetRemove 後の groupcast 不達(復号候補なしで drop)も確認。

セルフテスト(stack::tests): 運用 group key を手計算で導出し、groupcast datagram
(session id = GKH、DSIZ=Group、S フラグ、AES-CCM)をバイト列で組んで `handle_rx` に
与え、(a) OnOff が反転し応答が None、(b) 同一 ctr の再送が drop(trust-first 窓)、
(c) ACL に Group エントリが無ければ不変、を固定する。

## 9. 割り切り一覧(実装後に追記)

### 実装時の追記(2026-07-09)

- GroupKeyManagement の GroupKeyMap AppendItem は同一 groupId の既存行を**上書き**する
  (chip は複数 keyset への多重 bind を許すが、本実装は group ↔ keyset を 1:1 に限定。
  MaxGroupsPerFabric = map 行数 4 の解釈と整合)。
- KeySetWrite 成功系(実 fabric の compressed fabric id が必要)のユニットテストは
  stack の `groupcast_toggle_end_to_end` と実機 E2E で担保(クラスタ単体テストは
  検証規則の失敗系のみ)。
- smctl の cluster_def! は groups / groupkeymanagement を収載するが、
  `key-set-write`(ネスト struct)と `get-group-membership` の group-list(list 引数)は
  マクロの表現力外 → `any invoke ... tlv:<hex>` で送る(§8-5)。
- GroupsCluster の識別状態(AddGroupIfIdentifying)は `DataModel::on_tick` で
  `IdentifyCluster::is_identifying()` を毎 tick 写す(listener 直結ではなく 1 tick 遅延)。

- Privacy(P フラグ)受信非対応(chip 送信既定が P=0。P=1 は drop)。
- groupcast の WriteRequest 非対応(InvokeRequest のみ)。
- GroupKeySecurityPolicy は TrustFirst のみ(CacheAndSync = MCSP 非対応、chip 同様)。
- グループ名非保存(GN feature off、ViewGroupResponse の name は空文字)。
- 固定 IANA マルチキャストアドレス(FF05::FA、1.4+ の mcast policy)非対応
  (chip 既定は per-group アドレスのため相互運用に影響なし)。
- マルチキャスト leave 省略(グループ削除後も join したまま。復号鍵が無いため実害なし)。
- グループカウンタ窓はセッション窓(PeerWindow)の流用近似(chip の
  VerifyOrTrustFirstGroup のロールオーバー緩和は未実装)。ピアテーブル 8 本 LRU。
- KeySetWrite(id=0) は EpochKey0 のみで IPK ローテーション(epoch 1/2 無視)。
- ESP32 ファームへの配線なし(コアは no_std 維持でビルドのみ通す)。
- controller/smctl からの groupcast 送信は将来課題(手順は §8 の chip-tool 相当:
  ローカル鍵ストア + 試行なし単発送信 + IPv6 マルチキャスト送出)。

## 10. 検証ゲート(共通)

1. `cargo fmt --check`
2. `cargo test --all-features` + `cargo test -p smctl --all-features`
3. `cargo clippy --all-targets --all-features -- -D warnings`
4. `cargo check -p simple-matter --all-features --target thumbv6m-none-eabi` /
   `--target riscv32imc-unknown-none-elf` / `--no-default-features`
5. ports/esp32 ビルド(`cargo build --release`)
6. bloat-check(flash-probe / ram-report)でフットプリント記録
7. §8 の実機 E2E
