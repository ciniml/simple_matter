//! グループメッセージングの鍵ストアと鍵導出(`docs/design/group-messaging.md` §1)。
//!
//! Matter Core Spec §4.15(Group Key Management)/ §2.5.6(Group multicast アドレス)の
//! fabric-scoped 固定容量テーブル [`GroupStore`] と、運用グループ鍵導出
//! ([`derive_operational_group_key`] / [`derive_group_session_id`])・グループ
//! マルチキャストアドレス導出([`group_multicast_addr`])を提供する。
//!
//! # 設計判断
//!
//! - **fabric-scoped・no-alloc**: keyset / map / group メンバーシップは const generic の
//!   [`FixedVec`] に持ち、加えて仕様の per-fabric 上限([`MAX_GROUP_KEYSETS_PER_FABRIC`] /
//!   [`MAX_GROUPS_PER_FABRIC`])を強制する([`crate::acl::AclTable`] と同型)。
//! - **導出鍵は書き込み時に計算**: 運用グループ鍵(`op_key`)とグループセッション ID
//!   (`gkh` = Group Key Hash)は [`GroupStore::set_keyset`] 時に導出して格納し、受信ホット
//!   パスでは HKDF を回さない。
//! - **共有は `RefCell`**: [`crate::fabric::FabricTable`] / [`crate::acl::AclTable`] と同じ
//!   流儀で、統合層が所有する `RefCell<GroupStore<..>>` を GroupKeyManagement / Groups
//!   クラスタと transport(復号)が共有する。[`GroupKeyResolver`] は
//!   `RefCell<GroupStore<..>>` に実装する(内部可変性)。
//! - **永続化**: [`GroupStore::save_to`] / [`GroupStore::load_from`](キー `b"grpt"`、単一
//!   versioned TLV レコード)。導出済み `op_key` / `gkh` も保存して単独復元できる。
//!
//! # 鍵導出の出典(テストベクタ)
//!
//! - **operational group key** = `HKDF-SHA256(salt = CompressedFabricId(8), ikm =
//!   EpochKey(16), info = "GroupKey v1.0", L = 16)`(Matter Core Spec §4.15.3、
//!   chip `Crypto::DeriveGroupOperationalCredentials`)。[`crate::fabric`] の IPK 導出と同一式。
//! - **GKH(Group Session ID)** = `HKDF-SHA256(salt = [], ikm = OperationalGroupKey,
//!   info = "GroupKeyHash", L = 2)` の 2 バイトを big-endian u16 として読む
//!   (chip `Crypto::DeriveGroupSessionId`)。
//! - 既知ベクタ(chip `TestGroupDataProvider.cpp`、仕様 §4.15.3): epoch key
//!   `235bf7e62823d358dca4ba50b1535f4b` + compressed fabric id `87e1b004e235a130`
//!   → operational key `a6f5306baf6d050af23ba4bd6b9dd960`。

use core::cell::RefCell;
use core::net::Ipv6Addr;
use core::num::NonZeroU8;

use crate::crypto::{Crypto, AES_CCM_KEY_LEN};
use crate::error::{Error, Result};
use crate::fabric::COMPRESSED_FABRIC_ID_LEN;
use crate::kvs::Kvs;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};
use crate::transport::session::fixed::FixedVec;

/// epoch key / operational group key のバイト長(16 バイト = [`AES_CCM_KEY_LEN`])。
pub const GROUP_KEY_LEN: usize = AES_CCM_KEY_LEN;

/// 1 keyset の epoch key 数上限(EpochKey0..2、仕様固定 3)。
pub const MAX_EPOCHS_PER_KEYSET: usize = 3;

/// fabric あたりの keyset 数上限(MaxGroupKeysPerFabric、仕様最小値)。
pub const MAX_GROUP_KEYSETS_PER_FABRIC: usize = 3;

/// fabric あたりの group 数上限(MaxGroupsPerFabric、仕様公称値)。
///
/// GroupKeyMap 行数・group メンバーシップ行数の双方に適用する。
pub const MAX_GROUPS_PER_FABRIC: usize = 4;

/// 1 group メンバーシップに紐づくエンドポイント数上限。
pub const MAX_ENDPOINTS_PER_GROUP: usize = 4;

/// 運用グループ鍵導出の HKDF info(`"GroupKey v1.0"`, 13 バイト)。
const GROUP_KEY_INFO: &[u8] = b"GroupKey v1.0";

/// GKH 導出の HKDF info(`"GroupKeyHash"`, 12 バイト)。
const GROUP_KEY_HASH_INFO: &[u8] = b"GroupKeyHash";

/// group node id の上位 48 ビット定数(`0xFFFF_FFFF_FFFF_0000`、§2.5.5)。
const GROUP_NODE_ID_PREFIX: u64 = 0xFFFF_FFFF_FFFF_0000;

/// group id を group node id(`0xFFFF_FFFF_FFFF_0000 | gid`)へ変換する。
pub const fn group_node_id(group_id: u16) -> u64 {
    GROUP_NODE_ID_PREFIX | group_id as u64
}

// ==========================================================================
// 鍵導出(§1.1)
// ==========================================================================

/// operational group key = `HKDF-SHA256(salt = CompressedFabricId, ikm = epochKey, info =
/// "GroupKey v1.0", L = 16)`(Matter Core Spec §4.15.3)。
///
/// [`crate::fabric`] の IPK 導出と同一式(IPK は epoch key を同式に通した特例)。
pub fn derive_operational_group_key<C: Crypto>(
    crypto: &C,
    epoch_key: &[u8; GROUP_KEY_LEN],
    compressed_fabric_id: &[u8; COMPRESSED_FABRIC_ID_LEN],
) -> Result<[u8; GROUP_KEY_LEN]> {
    let mut out = [0u8; GROUP_KEY_LEN];
    crypto.hkdf_sha256(compressed_fabric_id, epoch_key, GROUP_KEY_INFO, &mut out)?;
    Ok(out)
}

/// GKH(Group Session ID)= `HKDF-SHA256(salt = [], ikm = op_key, info = "GroupKeyHash",
/// L = 2)` の 2 バイトを big-endian u16 として読む(chip `DeriveGroupSessionId`)。
pub fn derive_group_session_id<C: Crypto>(crypto: &C, op_key: &[u8; GROUP_KEY_LEN]) -> Result<u16> {
    let mut out = [0u8; 2];
    crypto.hkdf_sha256(&[], op_key, GROUP_KEY_HASH_INFO, &mut out)?;
    Ok(u16::from_be_bytes(out))
}

// ==========================================================================
// マルチキャストアドレス導出(§1.3)
// ==========================================================================

/// group マルチキャストアドレスを導出する(§2.5.6、chip `PeerAddress.h`)。
///
/// バイト列 = `FF 35 00 40 FD || FabricId(BE 8) || 00 || GroupId(BE 2)`
/// (scope = site-local(0x5)固定、prefix len = 64)。RFC 3306 unicast-prefix-based
/// multicast の形で、`prefix = 0xfd00_0000_0000_0000 | (fabric >> 8)`、
/// `group32 = ((fabric << 24) & 0xff00_0000) | group` に一致する。
pub fn group_multicast_addr(fabric_id: u64, group_id: u16) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xff;
    octets[1] = 0x35; // 3 = multicast(flags 0), 5 = site-local scope
    octets[2] = 0x00;
    octets[3] = 0x40; // prefix length 64
    octets[4] = 0xfd; // ULA prefix 先頭
    octets[5..13].copy_from_slice(&fabric_id.to_be_bytes());
    octets[13] = 0x00;
    octets[14..16].copy_from_slice(&group_id.to_be_bytes());
    Ipv6Addr::from(octets)
}

// ==========================================================================
// データ構造(§1.2)
// ==========================================================================

/// 1 epoch(鍵素材 + 開始時刻 + 導出済み運用鍵 / GKH)。
#[derive(Debug, Clone, Copy)]
pub struct Epoch {
    key: [u8; GROUP_KEY_LEN],
    start_time_us: u64,
    op_key: [u8; GROUP_KEY_LEN],
    gkh: u16,
}

impl Epoch {
    /// EpochStartTime(マイクロ秒)。
    pub const fn start_time_us(&self) -> u64 {
        self.start_time_us
    }

    /// 導出済み運用グループ鍵(16 バイト)。
    pub const fn op_key(&self) -> &[u8; GROUP_KEY_LEN] {
        &self.op_key
    }

    /// 導出済み GKH(Group Session ID)。
    pub const fn gkh(&self) -> u16 {
        self.gkh
    }
}

/// KeySetWrite 由来の 1 keyset(IPK keyset 0 は含まない = FabricTable 所有)。
#[derive(Debug, Clone)]
pub struct KeySetEntry {
    fabric_idx: NonZeroU8,
    id: u16,
    policy: u8,
    epochs: [Epoch; MAX_EPOCHS_PER_KEYSET],
    nepochs: u8,
}

impl KeySetEntry {
    /// 所属 fabric。
    pub const fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    /// GroupKeySetID(0 以外)。
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// GroupKeySecurityPolicy(0 = TrustFirst)。
    pub const fn policy(&self) -> u8 {
        self.policy
    }

    /// 有効な epoch 一覧(先頭から `nepochs` 件)。
    pub fn epochs(&self) -> &[Epoch] {
        &self.epochs[..self.nepochs as usize]
    }
}

/// GroupKeyMap 属性の 1 行(group ↔ keyset)。
#[derive(Debug, Clone, Copy)]
pub struct MapEntry {
    fabric_idx: NonZeroU8,
    group_id: u16,
    key_set_id: u16,
}

impl MapEntry {
    /// 所属 fabric。
    pub const fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    /// GroupId。
    pub const fn group_id(&self) -> u16 {
        self.group_id
    }

    /// GroupKeySetID。
    pub const fn key_set_id(&self) -> u16 {
        self.key_set_id
    }
}

/// Groups クラスタのメンバーシップ 1 行(GroupTable 属性の元)。
#[derive(Debug, Clone, Copy)]
pub struct GroupEntry {
    fabric_idx: NonZeroU8,
    group_id: u16,
    endpoints: [u16; MAX_ENDPOINTS_PER_GROUP],
    neps: u8,
}

impl GroupEntry {
    /// 所属 fabric。
    pub const fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    /// GroupId。
    pub const fn group_id(&self) -> u16 {
        self.group_id
    }

    /// 所属エンドポイント一覧。
    pub fn endpoints(&self) -> &[u16] {
        &self.endpoints[..self.neps as usize]
    }

    /// `ep` が所属するか。
    pub fn contains_endpoint(&self, ep: u16) -> bool {
        self.endpoints().contains(&ep)
    }
}

/// KeySetWrite に渡す 1 epoch の入力(鍵 + 開始時刻)。
#[derive(Debug, Clone, Copy)]
pub struct EpochKeyInput {
    /// EpochKey(16 バイト)。
    pub key: [u8; GROUP_KEY_LEN],
    /// EpochStartTime(マイクロ秒)。
    pub start_time_us: u64,
}

// ==========================================================================
// GroupStore
// ==========================================================================

/// fabric-scoped 固定容量のグループ鍵 / メンバーシップストア。
///
/// `KS` = keyset 容量、`GM` = GroupKeyMap 行容量、`GT` = group メンバーシップ行容量。
/// いずれも per-fabric 上限([`MAX_GROUP_KEYSETS_PER_FABRIC`] / [`MAX_GROUPS_PER_FABRIC`])を
/// 別途強制するため、テーブル全体容量は `上限 × 想定 fabric 数` を目安に選ぶ。
pub struct GroupStore<const KS: usize, const GM: usize, const GT: usize> {
    keysets: FixedVec<KeySetEntry, KS>,
    maps: FixedVec<MapEntry, GM>,
    groups: FixedVec<GroupEntry, GT>,
    generation: u32,
}

impl<const KS: usize, const GM: usize, const GT: usize> Default for GroupStore<KS, GM, GT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const KS: usize, const GM: usize, const GT: usize> GroupStore<KS, GM, GT> {
    /// 空のストアを作る。
    pub const fn new() -> Self {
        Self {
            keysets: FixedVec::new(),
            maps: FixedVec::new(),
            groups: FixedVec::new(),
            generation: 0,
        }
    }

    /// 変更世代番号(永続化 + マルチキャスト join 同期のトリガ)。
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    // --- keyset ---

    /// `fabric` の keyset 数。
    pub fn keyset_len(&self, fabric: NonZeroU8) -> usize {
        self.keysets
            .iter()
            .filter(|k| k.fabric_idx == fabric)
            .count()
    }

    /// keyset を書き込む(導出込み)。既存 `id` は上書き更新する。
    ///
    /// `id == 0`(IPK)は格納しない([`Error::InvalidState`])。`epochs` は 1..=3 本、policy は
    /// 0(TrustFirst)のみ受理する。per-fabric 上限超過は [`Error::NoSpace`]。
    pub fn set_keyset<C: Crypto>(
        &mut self,
        fabric: NonZeroU8,
        id: u16,
        policy: u8,
        epochs: &[EpochKeyInput],
        crypto: &C,
        compressed_fabric_id: &[u8; COMPRESSED_FABRIC_ID_LEN],
    ) -> Result<()> {
        if id == 0 {
            return Err(Error::InvalidState);
        }
        if epochs.is_empty() || epochs.len() > MAX_EPOCHS_PER_KEYSET {
            return Err(Error::Decode);
        }
        let mut entry = KeySetEntry {
            fabric_idx: fabric,
            id,
            policy,
            epochs: [Epoch {
                key: [0u8; GROUP_KEY_LEN],
                start_time_us: 0,
                op_key: [0u8; GROUP_KEY_LEN],
                gkh: 0,
            }; MAX_EPOCHS_PER_KEYSET],
            nepochs: 0,
        };
        for (i, ek) in epochs.iter().enumerate() {
            let op_key = derive_operational_group_key(crypto, &ek.key, compressed_fabric_id)?;
            let gkh = derive_group_session_id(crypto, &op_key)?;
            entry.epochs[i] = Epoch {
                key: ek.key,
                start_time_us: ek.start_time_us,
                op_key,
                gkh,
            };
        }
        entry.nepochs = epochs.len() as u8;

        // 既存 id は上書き(`if let` の scrutinee 一時借用を避けるため先に bind する)。
        let existing = self
            .keysets
            .iter()
            .position(|k| k.fabric_idx == fabric && k.id == id);
        if let Some(pos) = existing {
            self.keysets[pos] = entry;
            self.bump();
            return Ok(());
        }
        if self.keyset_len(fabric) >= MAX_GROUP_KEYSETS_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        self.keysets.push(entry).map_err(|_| Error::NoSpace)?;
        self.bump();
        Ok(())
    }

    /// `(fabric, id)` の keyset を引く。
    pub fn keyset(&self, fabric: NonZeroU8, id: u16) -> Option<&KeySetEntry> {
        self.keysets
            .iter()
            .find(|k| k.fabric_idx == fabric && k.id == id)
    }

    /// `(fabric, id)` の keyset を削除し、参照中の GroupKeyMap 行も削除する(chip 同様)。
    ///
    /// 対象なしは [`Error::NotFound`]。
    pub fn remove_keyset(&mut self, fabric: NonZeroU8, id: u16) -> Result<()> {
        let pos = self
            .keysets
            .iter()
            .position(|k| k.fabric_idx == fabric && k.id == id)
            .ok_or(Error::NotFound)?;
        remove_at(&mut self.keysets, pos);
        // 当該 keyset を参照する map 行も削除。
        loop {
            let Some(mp) = self
                .maps
                .iter()
                .position(|m| m.fabric_idx == fabric && m.key_set_id == id)
            else {
                break;
            };
            remove_at(&mut self.maps, mp);
        }
        self.bump();
        Ok(())
    }

    /// `fabric` の `idx` 番目の keyset id(挿入順、KeySetReadAllIndices 用)。
    pub fn keyset_id_at(&self, fabric: NonZeroU8, idx: usize) -> Option<u16> {
        self.keysets
            .iter()
            .filter(|k| k.fabric_idx == fabric)
            .nth(idx)
            .map(|k| k.id)
    }

    // --- GroupKeyMap ---

    /// `fabric` の GroupKeyMap 行を走査する。
    pub fn map_iter(&self, fabric: NonZeroU8) -> impl Iterator<Item = &MapEntry> {
        self.maps.iter().filter(move |m| m.fabric_idx == fabric)
    }

    /// 全 fabric の GroupKeyMap 行を走査する(GroupKeyMap 属性の read 用)。
    pub fn map_iter_all(&self) -> impl Iterator<Item = &MapEntry> {
        self.maps.iter()
    }

    /// `fabric` の GroupKeyMap 行数。
    pub fn map_len(&self, fabric: NonZeroU8) -> usize {
        self.map_iter(fabric).count()
    }

    /// `fabric` の GroupKeyMap を `entries`(= (group_id, key_set_id))で全置換する
    /// (write ReplaceAll)。上限超過は [`Error::NoSpace`]。
    pub fn set_map(&mut self, fabric: NonZeroU8, entries: &[(u16, u16)]) -> Result<()> {
        if entries.len() > MAX_GROUPS_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        self.clear_maps(fabric);
        for &(group_id, key_set_id) in entries {
            self.maps
                .push(MapEntry {
                    fabric_idx: fabric,
                    group_id,
                    key_set_id,
                })
                .map_err(|_| Error::NoSpace)?;
        }
        self.bump();
        Ok(())
    }

    /// GroupKeyMap 行を 1 つ追記する(write AppendItem)。
    ///
    /// 同一 group_id の行は上書きする。per-fabric 上限超過は [`Error::NoSpace`]。
    pub fn add_map(&mut self, fabric: NonZeroU8, group_id: u16, key_set_id: u16) -> Result<()> {
        let existing = self
            .maps
            .iter()
            .position(|m| m.fabric_idx == fabric && m.group_id == group_id);
        if let Some(pos) = existing {
            self.maps[pos].key_set_id = key_set_id;
            self.bump();
            return Ok(());
        }
        if self.map_len(fabric) >= MAX_GROUPS_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        self.maps
            .push(MapEntry {
                fabric_idx: fabric,
                group_id,
                key_set_id,
            })
            .map_err(|_| Error::NoSpace)?;
        self.bump();
        Ok(())
    }

    fn clear_maps(&mut self, fabric: NonZeroU8) {
        loop {
            let Some(pos) = self.maps.iter().position(|m| m.fabric_idx == fabric) else {
                break;
            };
            remove_at(&mut self.maps, pos);
        }
    }

    /// `(fabric, gid)` に有効な鍵(map が存在し、その keyset が epoch を持つ)があるか。
    ///
    /// Groups クラスタ AddGroup の UnsupportedAccess 判定に使う。
    pub fn has_key_for_group(&self, fabric: NonZeroU8, gid: u16) -> bool {
        self.maps
            .iter()
            .filter(|m| m.fabric_idx == fabric && m.group_id == gid)
            .any(|m| {
                self.keyset(fabric, m.key_set_id)
                    .is_some_and(|k| k.nepochs > 0)
            })
    }

    // --- group メンバーシップ ---

    /// `fabric` の group メンバーシップ行を走査する。
    pub fn groups_iter(&self, fabric: NonZeroU8) -> impl Iterator<Item = &GroupEntry> {
        self.groups.iter().filter(move |g| g.fabric_idx == fabric)
    }

    /// 全 fabric の group メンバーシップ行を走査する(GroupTable 属性の read /
    /// マルチキャスト join 同期用)。
    pub fn groups_iter_all(&self) -> impl Iterator<Item = &GroupEntry> {
        self.groups.iter()
    }

    /// `(fabric, gid)` の所属エンドポイント一覧(無ければ `None`)。
    pub fn member_endpoints(&self, fabric: NonZeroU8, gid: u16) -> Option<&[u16]> {
        self.groups
            .iter()
            .find(|g| g.fabric_idx == fabric && g.group_id == gid)
            .map(GroupEntry::endpoints)
    }

    /// `ep` が `(fabric, gid)` に所属するか。
    pub fn is_member(&self, fabric: NonZeroU8, gid: u16, ep: u16) -> bool {
        self.groups
            .iter()
            .any(|g| g.fabric_idx == fabric && g.group_id == gid && g.contains_endpoint(ep))
    }

    /// `(fabric, gid)` に `ep` をメンバー登録する(既存なら no-op)。
    ///
    /// 新規 group 行の per-fabric 上限超過・エンドポイント上限超過は [`Error::NoSpace`]。
    pub fn add_member(&mut self, fabric: NonZeroU8, gid: u16, ep: u16) -> Result<()> {
        let existing = self
            .groups
            .iter()
            .position(|g| g.fabric_idx == fabric && g.group_id == gid);
        if let Some(pos) = existing {
            let g = &mut self.groups[pos];
            if g.contains_endpoint(ep) {
                return Ok(());
            }
            if (g.neps as usize) >= MAX_ENDPOINTS_PER_GROUP {
                return Err(Error::NoSpace);
            }
            g.endpoints[g.neps as usize] = ep;
            g.neps += 1;
            self.bump();
            return Ok(());
        }
        if self.groups_iter(fabric).count() >= MAX_GROUPS_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        let mut entry = GroupEntry {
            fabric_idx: fabric,
            group_id: gid,
            endpoints: [0u16; MAX_ENDPOINTS_PER_GROUP],
            neps: 0,
        };
        entry.endpoints[0] = ep;
        entry.neps = 1;
        self.groups.push(entry).map_err(|_| Error::NoSpace)?;
        self.bump();
        Ok(())
    }

    /// `(fabric, gid)` から `ep` を外す。行が空になれば削除する。
    ///
    /// 外した(所属していた)なら `true`。
    pub fn remove_member(&mut self, fabric: NonZeroU8, gid: u16, ep: u16) -> bool {
        let Some(pos) = self
            .groups
            .iter()
            .position(|g| g.fabric_idx == fabric && g.group_id == gid)
        else {
            return false;
        };
        if !remove_endpoint(&mut self.groups[pos], ep) {
            return false;
        }
        if self.groups[pos].neps == 0 {
            remove_at(&mut self.groups, pos);
        }
        self.bump();
        true
    }

    /// `fabric` の全 group から `ep` を外す(Groups RemoveAllGroups)。
    pub fn remove_all_members(&mut self, fabric: NonZeroU8, ep: u16) {
        let mut changed = false;
        let mut i = 0;
        while i < self.groups.len() {
            let g = &mut self.groups[i];
            if g.fabric_idx == fabric && remove_endpoint(g, ep) {
                changed = true;
                if self.groups[i].neps == 0 {
                    remove_at(&mut self.groups, i);
                    continue;
                }
            }
            i += 1;
        }
        if changed {
            self.bump();
        }
    }

    // --- 復号候補(§1.2 / §5.1)---

    /// `gkh` / `gid` に一致する復号候補 `(fabric, op_key)` を `idx` 順に返す。
    ///
    /// 「map で `gid` に紐づく keyset の epoch のうち `gkh` 一致」を挿入順に列挙する。
    /// 呼び出し側は `idx` を 0.. と進めて試行復号する。
    pub fn key_candidate(
        &self,
        gkh: u16,
        gid: u16,
        idx: usize,
    ) -> Option<(NonZeroU8, [u8; GROUP_KEY_LEN])> {
        let mut n = 0;
        for m in self.maps.iter().filter(|m| m.group_id == gid) {
            let Some(ks) = self.keyset(m.fabric_idx, m.key_set_id) else {
                continue;
            };
            for e in ks.epochs() {
                if e.gkh == gkh {
                    if n == idx {
                        return Some((m.fabric_idx, e.op_key));
                    }
                    n += 1;
                }
            }
        }
        None
    }

    // --- fabric 連動 ---

    /// `fabric` の keyset / map / group を全て削除する(fabric 削除連動)。
    pub fn clear_fabric(&mut self, fabric: NonZeroU8) {
        let mut removed = false;
        loop {
            let Some(pos) = self.keysets.iter().position(|k| k.fabric_idx == fabric) else {
                break;
            };
            remove_at(&mut self.keysets, pos);
            removed = true;
        }
        loop {
            let Some(pos) = self.maps.iter().position(|m| m.fabric_idx == fabric) else {
                break;
            };
            remove_at(&mut self.maps, pos);
            removed = true;
        }
        loop {
            let Some(pos) = self.groups.iter().position(|g| g.fabric_idx == fabric) else {
                break;
            };
            remove_at(&mut self.groups, pos);
            removed = true;
        }
        if removed {
            self.bump();
        }
    }

    /// `exists(fabric)` が `false` の行を全種別から落とす(復元後の整合)。
    pub fn retain_fabrics(&mut self, mut exists: impl FnMut(NonZeroU8) -> bool) {
        let mut removed = false;
        let mut i = 0;
        while i < self.keysets.len() {
            if exists(self.keysets[i].fabric_idx) {
                i += 1;
            } else {
                remove_at(&mut self.keysets, i);
                removed = true;
            }
        }
        let mut i = 0;
        while i < self.maps.len() {
            if exists(self.maps[i].fabric_idx) {
                i += 1;
            } else {
                remove_at(&mut self.maps, i);
                removed = true;
            }
        }
        let mut i = 0;
        while i < self.groups.len() {
            if exists(self.groups[i].fabric_idx) {
                i += 1;
            } else {
                remove_at(&mut self.groups, i);
                removed = true;
            }
        }
        if removed {
            self.bump();
        }
    }
}

/// `FixedVec` の `index` 位置を挿入順を保って取り除く(左詰めして末尾を落とす)。
fn remove_at<T: Clone, const N: usize>(v: &mut FixedVec<T, N>, index: usize) {
    let len = v.len();
    if index >= len {
        return;
    }
    for i in index..len - 1 {
        v[i] = v[i + 1].clone();
    }
    let _ = v.swap_remove(len - 1);
}

/// group エントリから `ep` を左詰めで外す。外したら `true`。
fn remove_endpoint(g: &mut GroupEntry, ep: u16) -> bool {
    let Some(pos) = g.endpoints[..g.neps as usize].iter().position(|&e| e == ep) else {
        return false;
    };
    for i in pos..(g.neps as usize - 1) {
        g.endpoints[i] = g.endpoints[i + 1];
    }
    g.neps -= 1;
    true
}

// ==========================================================================
// GroupKeyResolver(transport への object-safe 境界、§5.1)
// ==========================================================================

/// transport(groupcast 復号)が const generic 伝播を避けて鍵を引くための object-safe 境界。
///
/// [`RefCell<GroupStore<..>>`] に実装する(内部可変性で `&self` から読める)。統合層は
/// `RefCell` を所有し、クラスタと transport の双方へ共有参照を渡す。
pub trait GroupKeyResolver {
    /// `gkh` / `group_id` に一致する復号候補 `(fabric, op_key)` を `idx` 順に返す。
    fn key_candidate(
        &self,
        gkh: u16,
        group_id: u16,
        idx: usize,
    ) -> Option<(NonZeroU8, [u8; AES_CCM_KEY_LEN])>;
}

impl<const KS: usize, const GM: usize, const GT: usize> GroupKeyResolver
    for RefCell<GroupStore<KS, GM, GT>>
{
    fn key_candidate(
        &self,
        gkh: u16,
        group_id: u16,
        idx: usize,
    ) -> Option<(NonZeroU8, [u8; AES_CCM_KEY_LEN])> {
        self.borrow().key_candidate(gkh, group_id, idx)
    }
}

// ==========================================================================
// KVS 永続化(fabric / ACL と同じ分業、§1.2)
// ==========================================================================

/// 永続化フォーマットの schema version。
pub const GROUP_SCHEMA_VERSION: u8 = 1;

/// group ストアレコードのキー。
const GROUP_KEY: &[u8] = b"grpt";

/// group ストアレコードの TLV エンコード上限(バイト)。
///
/// keyset `KS`×(epoch 3×約 55B)+ map `GM`×約 15B + group `GT`×約 25B に外枠を加えた
/// 既定サイジング(KS=6/GM=8/GT=8)で十分な値。
pub const MAX_GROUP_RECORD_LEN: usize = 2048;

fn cx(n: u8) -> TlvTag {
    TlvTag::ContextSpecific(n)
}

impl<const KS: usize, const GM: usize, const GT: usize> GroupStore<KS, GM, GT> {
    /// ストア全体を `kvs` のキー `b"grpt"` へ保存する。
    ///
    /// 呼び出しタイミングは統合層の責務([`GroupStore::generation`] の変化検知)。
    pub fn save_to<K: Kvs>(&self, kvs: &mut K) -> Result<()> {
        let mut buf = [0u8; MAX_GROUP_RECORD_LEN];
        let len = {
            let mut w = TlvWriter::new(&mut buf);
            w.start_struct(&TlvTag::Anonymous)?;
            w.write_u8(&cx(0), GROUP_SCHEMA_VERSION)?;
            // keysets
            w.start_array(&cx(1))?;
            for k in self.keysets.iter() {
                w.start_struct(&TlvTag::Anonymous)?;
                w.write_u8(&cx(1), k.fabric_idx.get())?;
                w.write_u16(&cx(2), k.id)?;
                w.write_u8(&cx(3), k.policy)?;
                w.start_array(&cx(4))?;
                for e in k.epochs() {
                    w.start_struct(&TlvTag::Anonymous)?;
                    w.write_bytes(&cx(0), &e.key)?;
                    w.write_u64(&cx(1), e.start_time_us)?;
                    w.write_bytes(&cx(2), &e.op_key)?;
                    w.write_u16(&cx(3), e.gkh)?;
                    w.end_container()?;
                }
                w.end_container()?;
                w.end_container()?;
            }
            w.end_container()?;
            // maps
            w.start_array(&cx(2))?;
            for m in self.maps.iter() {
                w.start_struct(&TlvTag::Anonymous)?;
                w.write_u8(&cx(1), m.fabric_idx.get())?;
                w.write_u16(&cx(2), m.group_id)?;
                w.write_u16(&cx(3), m.key_set_id)?;
                w.end_container()?;
            }
            w.end_container()?;
            // groups
            w.start_array(&cx(3))?;
            for g in self.groups.iter() {
                w.start_struct(&TlvTag::Anonymous)?;
                w.write_u8(&cx(1), g.fabric_idx.get())?;
                w.write_u16(&cx(2), g.group_id)?;
                w.start_array(&cx(3))?;
                for &ep in g.endpoints() {
                    w.write_u16(&TlvTag::Anonymous, ep)?;
                }
                w.end_container()?;
                w.end_container()?;
            }
            w.end_container()?;
            w.end_container()?;
            w.len()
        };
        kvs.set(GROUP_KEY, &buf[..len])
    }

    /// `kvs` からストアを復元する。
    ///
    /// - 空ストアにのみ呼べる(非空は [`Error::InvalidState`])。
    /// - レコードが無ければ初回起動として `Ok(())`。
    /// - schema 不一致・破損は [`Error`] で中断する。
    pub fn load_from<K: Kvs>(&mut self, kvs: &mut K) -> Result<()> {
        if !self.keysets.is_empty() || !self.maps.is_empty() || !self.groups.is_empty() {
            return Err(Error::InvalidState);
        }
        let mut buf = [0u8; MAX_GROUP_RECORD_LEN];
        let len = match kvs.get(GROUP_KEY, &mut buf)? {
            Some(l) => l,
            None => return Ok(()),
        };
        let mut r = TlvReader::new(&buf[..len]);
        if r.enter_container()? != ContainerType::Structure {
            return Err(Error::Decode);
        }
        let mut version: Option<u8> = None;
        loop {
            let e = r.read_next()?.ok_or(Error::Decode)?;
            match (e.tag, e.value) {
                (_, TlvValue::ContainerEnd) => break,
                (TlvTag::ContextSpecific(0), v) => {
                    version = Some(v.as_unsigned()?.try_into().map_err(|_| Error::Decode)?);
                    if version != Some(GROUP_SCHEMA_VERSION) {
                        return Err(Error::Decode);
                    }
                }
                (TlvTag::ContextSpecific(1), TlvValue::ContainerStart(ContainerType::Array)) => {
                    self.load_keysets(&mut r)?;
                }
                (TlvTag::ContextSpecific(2), TlvValue::ContainerStart(ContainerType::Array)) => {
                    self.load_maps(&mut r)?;
                }
                (TlvTag::ContextSpecific(3), TlvValue::ContainerStart(ContainerType::Array)) => {
                    self.load_groups(&mut r)?;
                }
                _ => r.skip(&e)?,
            }
        }
        if version.is_none() {
            return Err(Error::Decode);
        }
        Ok(())
    }

    fn load_keysets(&mut self, r: &mut TlvReader<'_>) -> Result<()> {
        loop {
            let el = r.read_next()?.ok_or(Error::Decode)?;
            match el.value {
                TlvValue::ContainerEnd => break,
                TlvValue::ContainerStart(ContainerType::Structure) => {
                    let k = decode_keyset(r)?;
                    self.keysets.push(k).map_err(|_| Error::NoSpace)?;
                }
                _ => return Err(Error::Decode),
            }
        }
        Ok(())
    }

    fn load_maps(&mut self, r: &mut TlvReader<'_>) -> Result<()> {
        loop {
            let el = r.read_next()?.ok_or(Error::Decode)?;
            match el.value {
                TlvValue::ContainerEnd => break,
                TlvValue::ContainerStart(ContainerType::Structure) => {
                    let m = decode_map(r)?;
                    self.maps.push(m).map_err(|_| Error::NoSpace)?;
                }
                _ => return Err(Error::Decode),
            }
        }
        Ok(())
    }

    fn load_groups(&mut self, r: &mut TlvReader<'_>) -> Result<()> {
        loop {
            let el = r.read_next()?.ok_or(Error::Decode)?;
            match el.value {
                TlvValue::ContainerEnd => break,
                TlvValue::ContainerStart(ContainerType::Structure) => {
                    let g = decode_group(r)?;
                    self.groups.push(g).map_err(|_| Error::NoSpace)?;
                }
                _ => return Err(Error::Decode),
            }
        }
        Ok(())
    }
}

fn read_u16(v: TlvValue<'_>) -> Result<u16> {
    v.as_unsigned()?.try_into().map_err(|_| Error::Decode)
}

fn read_u8(v: TlvValue<'_>) -> Result<u8> {
    v.as_unsigned()?.try_into().map_err(|_| Error::Decode)
}

fn read_key16(v: TlvValue<'_>) -> Result<[u8; GROUP_KEY_LEN]> {
    let TlvValue::ByteString(b) = v else {
        return Err(Error::Decode);
    };
    if b.len() != GROUP_KEY_LEN {
        return Err(Error::Decode);
    }
    let mut out = [0u8; GROUP_KEY_LEN];
    out.copy_from_slice(b);
    Ok(out)
}

/// keyset 構造体を読む(構造体開始を消費済み)。
fn decode_keyset(r: &mut TlvReader<'_>) -> Result<KeySetEntry> {
    let mut fabric: Option<u8> = None;
    let mut id: Option<u16> = None;
    let mut policy: u8 = 0;
    let mut epochs = [Epoch {
        key: [0u8; GROUP_KEY_LEN],
        start_time_us: 0,
        op_key: [0u8; GROUP_KEY_LEN],
        gkh: 0,
    }; MAX_EPOCHS_PER_KEYSET];
    let mut nepochs = 0usize;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => fabric = Some(read_u8(v)?),
            (TlvTag::ContextSpecific(2), v) => id = Some(read_u16(v)?),
            (TlvTag::ContextSpecific(3), v) => policy = read_u8(v)?,
            (TlvTag::ContextSpecific(4), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let el = r.read_next()?.ok_or(Error::Decode)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    TlvValue::ContainerStart(ContainerType::Structure) => {
                        if nepochs >= MAX_EPOCHS_PER_KEYSET {
                            return Err(Error::Decode);
                        }
                        epochs[nepochs] = decode_epoch(r)?;
                        nepochs += 1;
                    }
                    _ => return Err(Error::Decode),
                }
            },
            _ => r.skip(&e)?,
        }
    }
    let fabric = NonZeroU8::new(fabric.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    let id = id.ok_or(Error::Decode)?;
    if id == 0 || nepochs == 0 {
        return Err(Error::Decode);
    }
    Ok(KeySetEntry {
        fabric_idx: fabric,
        id,
        policy,
        epochs,
        nepochs: nepochs as u8,
    })
}

/// epoch 構造体を読む(構造体開始を消費済み)。
fn decode_epoch(r: &mut TlvReader<'_>) -> Result<Epoch> {
    let mut key = [0u8; GROUP_KEY_LEN];
    let mut op_key = [0u8; GROUP_KEY_LEN];
    let mut start_time_us = 0u64;
    let mut gkh = 0u16;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(0), v) => key = read_key16(v)?,
            (TlvTag::ContextSpecific(1), v) => start_time_us = v.as_unsigned()?,
            (TlvTag::ContextSpecific(2), v) => op_key = read_key16(v)?,
            (TlvTag::ContextSpecific(3), v) => gkh = read_u16(v)?,
            _ => r.skip(&e)?,
        }
    }
    Ok(Epoch {
        key,
        start_time_us,
        op_key,
        gkh,
    })
}

/// map 構造体を読む(構造体開始を消費済み)。
fn decode_map(r: &mut TlvReader<'_>) -> Result<MapEntry> {
    let mut fabric: Option<u8> = None;
    let mut group_id: Option<u16> = None;
    let mut key_set_id: Option<u16> = None;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => fabric = Some(read_u8(v)?),
            (TlvTag::ContextSpecific(2), v) => group_id = Some(read_u16(v)?),
            (TlvTag::ContextSpecific(3), v) => key_set_id = Some(read_u16(v)?),
            _ => r.skip(&e)?,
        }
    }
    let fabric = NonZeroU8::new(fabric.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    Ok(MapEntry {
        fabric_idx: fabric,
        group_id: group_id.ok_or(Error::Decode)?,
        key_set_id: key_set_id.ok_or(Error::Decode)?,
    })
}

/// group 構造体を読む(構造体開始を消費済み)。
fn decode_group(r: &mut TlvReader<'_>) -> Result<GroupEntry> {
    let mut fabric: Option<u8> = None;
    let mut group_id: Option<u16> = None;
    let mut endpoints = [0u16; MAX_ENDPOINTS_PER_GROUP];
    let mut neps = 0usize;
    loop {
        let e = r.read_next()?.ok_or(Error::Decode)?;
        match (e.tag, e.value) {
            (_, TlvValue::ContainerEnd) => break,
            (TlvTag::ContextSpecific(1), v) => fabric = Some(read_u8(v)?),
            (TlvTag::ContextSpecific(2), v) => group_id = Some(read_u16(v)?),
            (TlvTag::ContextSpecific(3), TlvValue::ContainerStart(ContainerType::Array)) => loop {
                let el = r.read_next()?.ok_or(Error::Decode)?;
                match el.value {
                    TlvValue::ContainerEnd => break,
                    v => {
                        if neps >= MAX_ENDPOINTS_PER_GROUP {
                            return Err(Error::Decode);
                        }
                        endpoints[neps] = read_u16(v)?;
                        neps += 1;
                    }
                }
            },
            _ => r.skip(&e)?,
        }
    }
    let fabric = NonZeroU8::new(fabric.ok_or(Error::Decode)?).ok_or(Error::Decode)?;
    Ok(GroupEntry {
        fabric_idx: fabric,
        group_id: group_id.ok_or(Error::Decode)?,
        endpoints,
        neps: neps as u8,
    })
}

/// 既定サイジングの [`GroupStore`](KS=6 / GM=8 / GT=8)。
pub type DefaultGroupStore = GroupStore<6, 8, 8>;

#[cfg(all(test, feature = "rustcrypto"))]
mod tests;
