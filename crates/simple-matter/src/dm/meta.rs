//! データモデルのメタデータ型と ID 新型(`docs/design/interaction-model.md` §7.3)。
//!
//! クラスタ/属性/コマンドの静的メタデータを `const` で構築できる形で提供する。
//! すべて `Copy` かつヒープ非依存で、`.rodata` に置ける(RAM を消費しない)。
//! ID 新型([`EndpointId`] 等)は設計上ここ(`dm::meta`)を正典とし、`im::wire` からは
//! 再エクスポートする。
//!
//! # 参照
//!
//! 属性/コマンド ID・リビジョンは Matter Core / Application Cluster 仕様に基づき、
//! `research/connectedhomeip/src/app/zap-templates/zcl/data-model/chip/*.xml` で確認した。

// ==========================================================================
// ID 新型(設計上の正典。im::wire は再エクスポート)
// ==========================================================================

/// エンドポイント ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EndpointId(pub u16);

/// クラスタ ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ClusterId(pub u32);

/// 属性 ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AttributeId(pub u32);

/// コマンド ID。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CommandId(pub u32);

/// イベント ID(型のみ。codec は初期スコープ外)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct EventId(pub u32);

// ==========================================================================
// グローバル属性 ID(Matter Core Spec §7.13、全クラスタ共通)
// ==========================================================================

/// GeneratedCommandList(サーバ→クライアントの生成コマンド ID 一覧)。
pub const ATTR_GENERATED_COMMAND_LIST: AttributeId = AttributeId(0xFFF8);
/// AcceptedCommandList(クライアント→サーバの受理コマンド ID 一覧)。
pub const ATTR_ACCEPTED_COMMAND_LIST: AttributeId = AttributeId(0xFFF9);
/// AttributeList(グローバル属性を含む全属性 ID 一覧)。
pub const ATTR_ATTRIBUTE_LIST: AttributeId = AttributeId(0xFFFB);
/// FeatureMap(feature ビットマップ)。
pub const ATTR_FEATURE_MAP: AttributeId = AttributeId(0xFFFC);
/// ClusterRevision(クラスタリビジョン)。
pub const ATTR_CLUSTER_REVISION: AttributeId = AttributeId(0xFFFD);

/// グローバル属性 ID 一覧(昇順)。ワイルドカード展開と AttributeList 導出で使う。
pub const GLOBAL_ATTRIBUTE_IDS: &[AttributeId] = &[
    ATTR_GENERATED_COMMAND_LIST,
    ATTR_ACCEPTED_COMMAND_LIST,
    ATTR_ATTRIBUTE_LIST,
    ATTR_FEATURE_MAP,
    ATTR_CLUSTER_REVISION,
];

/// 指定 ID がグローバル属性かを返す。
pub const fn is_global_attribute(id: AttributeId) -> bool {
    matches!(id.0, 0xFFF8 | 0xFFF9 | 0xFFFB | 0xFFFC | 0xFFFD)
}

// ==========================================================================
// アクセス制御(最小スコープ、設計 §10)
// ==========================================================================

/// アクセス権限レベル(Matter Core Spec §6.6.2)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Privilege {
    /// 読み取りのみ。
    View,
    /// 通常操作(コマンド起動・可書き属性の書き込み)。
    Operate,
    /// 管理操作。
    Manage,
    /// 全権(コミッショニング等)。
    Administer,
}

/// セッション種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// PASE(コミッショニング中の一時セッション)。
    Pase,
    /// CASE(運用セッション)。
    Case,
}

/// 1 セッションが保持できる CASE Authenticated Tag(CAT)の最大数。
///
/// Matter 仕様上、1 つの NOC に付与できる CAT は最大 3(`crate::sc::case::creds::MAX_PEER_CATS`
/// と同値。依存方向のため独立に定義する)。
pub const MAX_ACCESS_CATS: usize = 3;

/// アクセス文脈(read/write/invoke に渡す最小限の呼び出し元情報、設計 §10 / `docs/design/acl.md` §5)。
///
/// 設計 §1 では `im/access.rs` に置く型だが、`dm::clusters` が `im` エンジンを知らずに
/// 参照できるよう(依存方向の維持)、本ピースでは `dm::meta` に定義する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessContext {
    /// セッション種別。
    pub kind: SessionKind,
    /// fabric インデックス(CASE なら `Some`、PASE コミッショニングは `None`)。
    pub fabric_idx: Option<core::num::NonZeroU8>,
    /// CASE の subject NodeId(ACL 照合に使う)。
    pub subject: u64,
    /// CASE セッションの peer NOC に含まれる CAT(先頭 `cat_count` 件が有効)。
    ///
    /// ACL エントリの CAT subject(`0xFFFF_FFFD_xxxx_xxxx`)照合に使う(`docs/design/acl.md` §2)。
    pub cats: [u32; MAX_ACCESS_CATS],
    /// `cats` の有効件数。
    pub cat_count: u8,
    /// このアクセスに付与された権限。
    ///
    /// full ACL(`DataModel::acl` が `Some`)経路では per-entry 照合が権限を決めるため
    /// 使われない。従来近似(`acl() == None`)経路でのみ意味を持つ。
    pub privilege: Privilege,
    /// リクエストの fabricFiltered フラグ(ReadRequest / SubscribeRequest 由来)。
    ///
    /// fabric-scoped list 属性(ACL 等)の read で自 fabric 行のみ返すかの判定に使う。
    /// write/invoke では常に `false`。
    pub fabric_filtered: bool,
    /// このアクセスの発生時刻(注入された単調増加ミリ秒)。
    ///
    /// General Commissioning の fail-safe 期限計算や Operational Credentials の
    /// 証明書検証時刻(Matter epoch 秒 = `now_ms / 1000`)に用いる
    /// (`docs/design/interaction-model.md` §1「期限(now_ms 注入)」)。
    pub now_ms: u64,
    /// セッションのアテステーションチャレンジ(暗号セッションのみ有効、16 バイト)。
    ///
    /// Operational Credentials の AttestationRequest / CSRRequest 応答署名は
    /// `sign(elements || attestationChallenge)` を計算するため、セッションから
    /// 注入する(Matter Core Spec §11.17.5)。PlainText では全 0。
    pub att_challenge: [u8; 16],
}

impl AccessContext {
    /// 新しい [`AccessContext`] を作る(`now_ms`/`att_challenge` はゼロ既定)。
    ///
    /// セッション由来の環境値を伴う場合は [`AccessContext::with_env`] で上書きする。
    pub const fn new(
        kind: SessionKind,
        fabric_idx: Option<core::num::NonZeroU8>,
        subject: u64,
        privilege: Privilege,
    ) -> Self {
        Self {
            kind,
            fabric_idx,
            subject,
            cats: [0; MAX_ACCESS_CATS],
            cat_count: 0,
            privilege,
            fabric_filtered: false,
            now_ms: 0,
            att_challenge: [0u8; 16],
        }
    }

    /// 時刻とアテステーションチャレンジを注入した複製を返す。
    pub const fn with_env(mut self, now_ms: u64, att_challenge: [u8; 16]) -> Self {
        self.now_ms = now_ms;
        self.att_challenge = att_challenge;
        self
    }

    /// CASE peer の CAT 群を注入した複製を返す(`cats` の先頭 [`MAX_ACCESS_CATS`] 件に丸める)。
    pub fn with_cats(mut self, cats: &[u32]) -> Self {
        let n = cats.len().min(MAX_ACCESS_CATS);
        self.cats[..n].copy_from_slice(&cats[..n]);
        self.cat_count = n as u8;
        self
    }

    /// リクエストの fabricFiltered フラグを注入した複製を返す。
    pub const fn with_fabric_filtered(mut self, filtered: bool) -> Self {
        self.fabric_filtered = filtered;
        self
    }

    /// 権限が `required` 以上あれば `true`。
    pub const fn has_privilege(&self, required: Privilege) -> bool {
        (self.privilege as u8) >= (required as u8)
    }
}

// ==========================================================================
// 属性の quality(bitflags)
// ==========================================================================

/// 属性の quality(Matter Core Spec §7.18.2、`N`/`X`/`S`/`F` 等)。
///
/// bit フラグの newtype。`const` で `union` して組み合わせる。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Quality(pub u8);

impl Quality {
    /// quality 無し。
    pub const NONE: Quality = Quality(0);
    /// Nullable(null 許容)。
    pub const NULLABLE: Quality = Quality(1 << 0);
    /// Nonvolatile(不揮発。再起動で保持)。
    pub const NONVOLATILE: Quality = Quality(1 << 1);
    /// Scene(シーン対象)。
    pub const SCENE: Quality = Quality(1 << 2);
    /// Fixed(固定値。変化しない)。
    pub const FIXED: Quality = Quality(1 << 3);

    /// 2 つの quality を合成する(`const`)。
    pub const fn union(self, other: Quality) -> Quality {
        Quality(self.0 | other.0)
    }

    /// `flag` を含むか。
    pub const fn contains(self, flag: Quality) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

// ==========================================================================
// 属性メタデータ
// ==========================================================================

/// 属性のメタデータ(`const` 構築可能、設計 §7.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeMeta {
    /// 属性 ID。
    pub id: AttributeId,
    /// 読み取りに必要な権限。
    pub access: Privilege,
    /// 書き込みに必要な権限(`writable == false` なら未使用)。
    ///
    /// 仕様の既定は Operate。Breadcrumb / ACL のように read と write で権限が異なる
    /// 属性のため read(`access`)と分離する(`docs/design/acl.md` §3)。
    pub write_access: Privilege,
    /// quality フラグ。
    pub quality: Quality,
    /// 読み取り可能か。
    pub readable: bool,
    /// 書き込み可能か。
    pub writable: bool,
    /// 購読可能か。
    pub subscribable: bool,
}

impl AttributeMeta {
    /// 新しい [`AttributeMeta`] を作る(write 権限は既定の Operate)。
    pub const fn new(
        id: AttributeId,
        access: Privilege,
        quality: Quality,
        readable: bool,
        writable: bool,
        subscribable: bool,
    ) -> Self {
        Self {
            id,
            access,
            write_access: Privilege::Operate,
            quality,
            readable,
            writable,
            subscribable,
        }
    }

    /// write 権限を上書きした複製を返す(`const` チェーン用)。
    pub const fn with_write_access(mut self, write_access: Privilege) -> Self {
        self.write_access = write_access;
        self
    }

    /// グローバル属性 `id` の合成メタデータ(全て View 読み取り専用)を作る。
    pub const fn global(id: AttributeId) -> Self {
        Self::new(id, Privilege::View, Quality::NONE, true, false, false)
    }
}

// ==========================================================================
// コマンドメタデータ
// ==========================================================================

/// 受理コマンドのメタデータ(設計 §7.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandMeta {
    /// コマンド ID。
    pub id: CommandId,
    /// 生成レスポンス(応答コマンド)を返すか。`false` は status のみ。
    pub response: bool,
    /// 起動に必要な権限。
    pub access: Privilege,
    /// timed invoke 必須か(TimedRequest 未経由なら NeedsTimedInteraction)。
    pub timed: bool,
}

impl CommandMeta {
    /// 新しい [`CommandMeta`] を作る(timed 不要が既定)。
    pub const fn new(id: CommandId, response: bool, access: Privilege) -> Self {
        Self {
            id,
            response,
            access,
            timed: false,
        }
    }

    /// timed invoke 必須フラグを設定する(builder)。
    pub const fn with_timed(mut self, timed: bool) -> Self {
        self.timed = timed;
        self
    }
}

// ==========================================================================
// クラスタメタデータ
// ==========================================================================

/// クラスタのメタデータ(`const`、単一ソースの中核。設計 §7.3/§8)。
///
/// グローバル属性([`GLOBAL_ATTRIBUTE_IDS`])は含めない。エンジン/[`crate::dm::read_global_attribute`]
/// が本メタから自動導出する。
#[derive(Debug, Clone, Copy)]
pub struct ClusterMeta {
    /// クラスタ ID。
    pub id: ClusterId,
    /// クラスタリビジョン(ClusterRevision グローバル属性の値)。
    pub revision: u16,
    /// feature ビットマップ(FeatureMap グローバル属性の値)。
    pub feature_map: u32,
    /// クラスタ固有属性メタ(グローバル属性を除く)。
    pub attributes: &'static [AttributeMeta],
    /// 受理コマンドメタ(AcceptedCommandList の元)。
    pub accepted_commands: &'static [CommandMeta],
    /// 生成コマンド ID(GeneratedCommandList の元)。
    pub generated_commands: &'static [CommandId],
}

impl ClusterMeta {
    /// 新しい [`ClusterMeta`] を作る。
    pub const fn new(
        id: ClusterId,
        revision: u16,
        feature_map: u32,
        attributes: &'static [AttributeMeta],
        accepted_commands: &'static [CommandMeta],
        generated_commands: &'static [CommandId],
    ) -> Self {
        Self {
            id,
            revision,
            feature_map,
            attributes,
            accepted_commands,
            generated_commands,
        }
    }

    /// クラスタ固有属性 `id` のメタを探す。無ければ `None`。
    pub fn attribute(&self, id: AttributeId) -> Option<AttributeMeta> {
        let mut i = 0;
        while i < self.attributes.len() {
            if self.attributes[i].id.0 == id.0 {
                return Some(self.attributes[i]);
            }
            i += 1;
        }
        None
    }
}

// ==========================================================================
// エンドポイント/デバイスタイプ
// ==========================================================================

/// デバイスタイプ(Descriptor の DeviceTypeList 要素)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceType {
    /// デバイスタイプ ID(`devtype_id`)。
    pub id: u32,
    /// デバイスタイプリビジョン(>= 1)。
    pub revision: u16,
}

impl DeviceType {
    /// 新しい [`DeviceType`] を作る。
    pub const fn new(id: u32, revision: u16) -> Self {
        Self { id, revision }
    }
}

/// エンドポイントのメタデータ(ワイルドカード展開の起点、設計 §7.3)。
#[derive(Debug, Clone, Copy)]
pub struct EndpointMeta {
    /// エンドポイント ID。
    pub id: EndpointId,
    /// デバイスタイプ一覧。
    pub device_types: &'static [DeviceType],
    /// このエンドポイントに載るサーバクラスタ ID 一覧(昇順)。
    pub clusters: &'static [ClusterId],
}

impl EndpointMeta {
    /// 新しい [`EndpointMeta`] を作る。
    pub const fn new(
        id: EndpointId,
        device_types: &'static [DeviceType],
        clusters: &'static [ClusterId],
    ) -> Self {
        Self {
            id,
            device_types,
            clusters,
        }
    }
}
