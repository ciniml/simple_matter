//! 属性値/コマンドレスポンスの TLV 書き込みラッパ(`docs/design/interaction-model.md` §7.2)。
//!
//! [`AttrEncoder`] はクラスタの `read_attribute` が属性値を書くための、タグを固定した
//! [`TlvWriter`] ラッパである。バッファ満杯([`Error::NoSpace`])は
//! [`ImStatus::ResourceExhausted`] に写像して返す(チャンク境界判定の合図を保つ)。
//!
//! # 設計との差
//!
//! 設計 §7.2 の `AttrEncoder` は `Result<(), Full>` を返すが、本実装は
//! `Result<(), ImStatus>` を返す。これによりクラスタ実装の `?` 連結が簡潔になり
//! (`ImStatus::ResourceExhausted` が「満杯」の合図を兼ねる)、`ServerCluster` の
//! 戻り値型と一致する。ロールバック(試し書き→巻き戻し)は IM エンジン側(次ピース)の
//! 責務として、本ピースでは提供しない。

use crate::dm::meta::CommandId;
use crate::error::Error;
use crate::im::wire::ImStatus;
use crate::tlv::{TlvTag, TlvWriter};

/// [`Error::NoSpace`] を [`ImStatus::ResourceExhausted`]、その他を
/// [`ImStatus::Failure`] に写像する。
fn map_err(e: Error) -> ImStatus {
    match e {
        Error::NoSpace => ImStatus::ResourceExhausted,
        _ => ImStatus::Failure,
    }
}

/// 属性値を 1 つ書くためのエンコーダ。値要素のタグは生成時に固定する。
///
/// クラスタの `read_attribute` に `&mut AttrEncoder` として渡す。単純型は各 `write_*`、
/// 配列(list 型属性)は [`AttrEncoder::write_array`] を使う。
#[derive(Debug)]
pub struct AttrEncoder<'w, 'b> {
    writer: &'w mut TlvWriter<'b>,
    tag: TlvTag,
    wrote: bool,
}

impl<'w, 'b> AttrEncoder<'w, 'b> {
    /// `writer` に `tag` 付きで値を書くエンコーダを作る。
    pub fn new(writer: &'w mut TlvWriter<'b>, tag: TlvTag) -> Self {
        Self {
            writer,
            tag,
            wrote: false,
        }
    }

    /// 値を 1 つでも書いたかを返す。
    pub const fn wrote(&self) -> bool {
        self.wrote
    }

    /// 真偽値を書く。
    pub fn write_bool(&mut self, v: bool) -> Result<(), ImStatus> {
        self.writer.write_bool(&self.tag, v).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// `u8` を書く。
    pub fn write_u8(&mut self, v: u8) -> Result<(), ImStatus> {
        self.write_u64(v as u64)
    }

    /// `u16` を書く。
    pub fn write_u16(&mut self, v: u16) -> Result<(), ImStatus> {
        self.write_u64(v as u64)
    }

    /// `u32` を書く。
    pub fn write_u32(&mut self, v: u32) -> Result<(), ImStatus> {
        self.write_u64(v as u64)
    }

    /// `u64` を書く。
    pub fn write_u64(&mut self, v: u64) -> Result<(), ImStatus> {
        self.writer.write_u64(&self.tag, v).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// `i64` を書く。
    pub fn write_i64(&mut self, v: i64) -> Result<(), ImStatus> {
        self.writer.write_i64(&self.tag, v).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// UTF-8 文字列を書く。
    pub fn write_str(&mut self, s: &str) -> Result<(), ImStatus> {
        self.writer.write_utf8(&self.tag, s).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// バイト列を書く。
    pub fn write_bytes(&mut self, b: &[u8]) -> Result<(), ImStatus> {
        self.writer.write_bytes(&self.tag, b).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// null を書く。
    pub fn write_null(&mut self) -> Result<(), ImStatus> {
        self.writer.write_null(&self.tag).map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// `i32` を書く。
    pub fn write_i32(&mut self, v: i32) -> Result<(), ImStatus> {
        self.write_i64(v as i64)
    }

    /// 配列(TLV array)属性を書く。`f` に [`ArrayEncoder`] を渡して要素を積む。
    pub fn write_array<F>(&mut self, f: F) -> Result<(), ImStatus>
    where
        F: FnOnce(&mut ArrayEncoder<'_, 'b>) -> Result<(), ImStatus>,
    {
        self.writer.start_array(&self.tag).map_err(map_err)?;
        {
            let mut ae = ArrayEncoder {
                writer: self.writer,
            };
            f(&mut ae)?;
        }
        self.writer.end_container().map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }

    /// 構造体(TLV structure)属性を書く。`f` に [`StructEncoder`] を渡してフィールドを積む。
    ///
    /// General Commissioning の BasicCommissioningInfo など、単一構造体値の属性に使う。
    pub fn write_struct<F>(&mut self, f: F) -> Result<(), ImStatus>
    where
        F: FnOnce(&mut StructEncoder<'_, 'b>) -> Result<(), ImStatus>,
    {
        self.writer.start_struct(&self.tag).map_err(map_err)?;
        {
            let mut se = StructEncoder {
                writer: self.writer,
            };
            f(&mut se)?;
        }
        self.writer.end_container().map_err(map_err)?;
        self.wrote = true;
        Ok(())
    }
}

/// 配列属性の要素を積むエンコーダ(要素はタグ無し=anonymous)。
#[derive(Debug)]
pub struct ArrayEncoder<'w, 'b> {
    writer: &'w mut TlvWriter<'b>,
}

impl<'b> ArrayEncoder<'_, 'b> {
    /// `u16` 要素を追加する。
    pub fn push_u16(&mut self, v: u16) -> Result<(), ImStatus> {
        self.writer
            .write_u16(&TlvTag::Anonymous, v)
            .map_err(map_err)
    }

    /// `u32` 要素を追加する。
    pub fn push_u32(&mut self, v: u32) -> Result<(), ImStatus> {
        self.writer
            .write_u32(&TlvTag::Anonymous, v)
            .map_err(map_err)
    }

    /// バイト列要素を追加する(TrustedRootCertificates など octstr の配列)。
    pub fn push_bytes(&mut self, v: &[u8]) -> Result<(), ImStatus> {
        self.writer
            .write_bytes(&TlvTag::Anonymous, v)
            .map_err(map_err)
    }

    /// `u64` 要素を追加する(ACL の subjects など)。
    pub fn push_u64(&mut self, v: u64) -> Result<(), ImStatus> {
        self.writer
            .write_u64(&TlvTag::Anonymous, v)
            .map_err(map_err)
    }

    /// 匿名構造体要素を追加する。`f` に [`StructEncoder`] を渡してフィールドを書く。
    pub fn push_struct<F>(&mut self, f: F) -> Result<(), ImStatus>
    where
        F: FnOnce(&mut StructEncoder<'_, 'b>) -> Result<(), ImStatus>,
    {
        self.writer
            .start_struct(&TlvTag::Anonymous)
            .map_err(map_err)?;
        {
            let mut se = StructEncoder {
                writer: self.writer,
            };
            f(&mut se)?;
        }
        self.writer.end_container().map_err(map_err)
    }
}

/// 構造体要素のフィールドを書くエンコーダ(フィールドは context タグ付き)。
#[derive(Debug)]
pub struct StructEncoder<'w, 'b> {
    writer: &'w mut TlvWriter<'b>,
}

impl StructEncoder<'_, '_> {
    /// context タグ `ctx` の `u8` フィールドを書く。
    pub fn field_u8(&mut self, ctx: u8, v: u8) -> Result<(), ImStatus> {
        self.writer
            .write_u8(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の `u16` フィールドを書く。
    pub fn field_u16(&mut self, ctx: u8, v: u16) -> Result<(), ImStatus> {
        self.writer
            .write_u16(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の `u32` フィールドを書く。
    pub fn field_u32(&mut self, ctx: u8, v: u32) -> Result<(), ImStatus> {
        self.writer
            .write_u32(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の `u64` フィールドを書く。
    pub fn field_u64(&mut self, ctx: u8, v: u64) -> Result<(), ImStatus> {
        self.writer
            .write_u64(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の真偽値フィールドを書く。
    pub fn field_bool(&mut self, ctx: u8, v: bool) -> Result<(), ImStatus> {
        self.writer
            .write_bool(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` のバイト列(octstr)フィールドを書く。
    pub fn field_bytes(&mut self, ctx: u8, v: &[u8]) -> Result<(), ImStatus> {
        self.writer
            .write_bytes(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の UTF-8 文字列フィールドを書く。
    pub fn field_str(&mut self, ctx: u8, v: &str) -> Result<(), ImStatus> {
        self.writer
            .write_utf8(&TlvTag::ContextSpecific(ctx), v)
            .map_err(map_err)
    }

    /// context タグ `ctx` の null フィールドを書く。
    pub fn field_null(&mut self, ctx: u8) -> Result<(), ImStatus> {
        self.writer
            .write_null(&TlvTag::ContextSpecific(ctx))
            .map_err(map_err)
    }

    /// context タグ `ctx` の配列フィールドを書く(ACL エントリの subjects/targets 等)。
    pub fn field_array<F>(&mut self, ctx: u8, f: F) -> Result<(), ImStatus>
    where
        F: FnOnce(&mut ArrayEncoder<'_, '_>) -> Result<(), ImStatus>,
    {
        self.writer
            .start_array(&TlvTag::ContextSpecific(ctx))
            .map_err(map_err)?;
        {
            let mut ae = ArrayEncoder {
                writer: self.writer,
            };
            f(&mut ae)?;
        }
        self.writer.end_container().map_err(map_err)
    }
}

/// Invoke の生成レスポンスを書くレスポンダ(設計 §7.2)。
///
/// 本ピースの 3 クラスタは status のみを返す(生成レスポンス無し)ため最小実装。
/// クラスタは応答コマンド ID を [`CmdResponder::set_response`] で宣言し、フィールドを
/// [`CmdResponder::writer`] に書く。IM エンジン(次ピース)が InvokeResponseIB の外枠を組む。
#[derive(Debug)]
pub struct CmdResponder<'w, 'b> {
    writer: &'w mut TlvWriter<'b>,
    response: Option<CommandId>,
    promote_fabric: Option<core::num::NonZeroU8>,
    case_admin_acl: Option<(core::num::NonZeroU8, u64)>,
    removed_fabric: Option<core::num::NonZeroU8>,
}

impl<'w, 'b> CmdResponder<'w, 'b> {
    /// フィールド書き込み先 `writer` を与えてレスポンダを作る。
    pub fn new(writer: &'w mut TlvWriter<'b>) -> Self {
        Self {
            writer,
            response: None,
            promote_fabric: None,
            case_admin_acl: None,
            removed_fabric: None,
        }
    }

    /// 生成レスポンスのコマンド ID を宣言する。
    ///
    /// クラスタは本メソッドで応答コマンド ID を宣言し、その**フィールドを匿名構造体
    /// 1 要素**として [`CmdResponder::writer`] に書く。IM エンジンは書かれた要素を
    /// InvokeResponseIB の CommandDataIB フィールドへ転写する。
    pub fn set_response(&mut self, id: CommandId) {
        self.response = Some(id);
    }

    /// 宣言済みの生成レスポンスコマンド ID(あれば)。
    pub const fn response_command(&self) -> Option<CommandId> {
        self.response
    }

    /// AddNOC 成功時に、呼び出し元 PASE セッションを確定 fabric へ昇格するよう要求する
    /// (`docs/design/interaction-model.md` §9.4)。IM エンジンが invoke 後に
    /// [`SessionManager::promote_pase_fabric`](crate::transport::session::SessionManager::promote_pase_fabric)
    /// を呼ぶ。
    pub fn request_fabric_promotion(&mut self, fabric_idx: core::num::NonZeroU8) {
        self.promote_fabric = Some(fabric_idx);
    }

    /// 要求された fabric 昇格(あれば)。
    pub const fn requested_promotion(&self) -> Option<core::num::NonZeroU8> {
        self.promote_fabric
    }

    /// AddNOC 成功時に、caseAdminSubject への bootstrap admin ACL エントリ生成を要求する
    /// (§11.17.6.8、`docs/design/acl.md` §3)。IM エンジンが invoke 後に
    /// [`crate::acl::AclHandle::add_case_admin`] を呼ぶ。
    pub fn request_case_admin_acl(&mut self, fabric_idx: core::num::NonZeroU8, subject: u64) {
        self.case_admin_acl = Some((fabric_idx, subject));
    }

    /// 要求された bootstrap admin ACL(あれば)。
    pub const fn requested_case_admin_acl(&self) -> Option<(core::num::NonZeroU8, u64)> {
        self.case_admin_acl
    }

    /// RemoveFabric 成功時に、当該 fabric の ACL エントリ連動削除を要求する。
    /// IM エンジンが invoke 後に [`crate::acl::AclHandle::remove_fabric`] を呼ぶ。
    pub fn request_fabric_removed(&mut self, fabric_idx: core::num::NonZeroU8) {
        self.removed_fabric = Some(fabric_idx);
    }

    /// 要求された fabric 連動削除(あれば)。
    pub const fn requested_fabric_removed(&self) -> Option<core::num::NonZeroU8> {
        self.removed_fabric
    }

    /// レスポンスフィールドを書くための下位 [`TlvWriter`] を返す。
    pub fn writer(&mut self) -> &mut TlvWriter<'b> {
        self.writer
    }
}
