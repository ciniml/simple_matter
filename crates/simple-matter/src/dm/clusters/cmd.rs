//! コミッショニング系クラスタ共通のコマンドフィールド解析/応答補助
//! (`docs/design/interaction-model.md` §9.4)。
//!
//! [`ServerCluster::invoke_command`](crate::dm::ServerCluster::invoke_command) に渡る
//! `fields: &mut TlvReader` は、コマンドフィールド構造体(context タグ 1)を指す。
//! [`Fields`] はその構造体を開いて context タグ付きスカラフィールドを順に返す軽量イテレータ。
//! 生成レスポンスは [`open_response`]/[`close_response`] で匿名構造体として書く
//! (IM エンジンが InvokeResponseIB へ転写する)。

use crate::dm::codec::CmdResponder;
use crate::dm::meta::CommandId;
use crate::error::Error;
use crate::im::wire::ImStatus;
use crate::tlv::{ContainerType, TlvReader, TlvTag, TlvValue, TlvWriter};

/// TLV 書き込みエラーを [`ImStatus::ResourceExhausted`] に写像する。
pub(crate) fn map_tlv(_e: Error) -> ImStatus {
    ImStatus::ResourceExhausted
}

/// コマンドフィールド構造体を走査するイテレータ。
///
/// スカラ/文字列/バイト列フィールドのみを対象とする(コミッショニング系コマンドの
/// フィールドは入れ子コンテナを持たない)。
pub(crate) struct Fields<'a> {
    r: TlvReader<'a>,
    open: bool,
}

impl<'a> Fields<'a> {
    /// `fr`(フィールド構造体を指す)を複製して走査を開始する。
    pub(crate) fn new(fr: &TlvReader<'a>) -> Self {
        let mut r = fr.clone();
        let open = matches!(
            r.read_next(),
            Ok(Some(e)) if matches!(e.value, TlvValue::ContainerStart(ContainerType::Structure))
        );
        Self { r, open }
    }

    /// 次の `(context タグ, 値)` を返す。構造体終端で `None`。
    pub(crate) fn next(&mut self) -> Option<(u8, TlvValue<'a>)> {
        if !self.open {
            return None;
        }
        match self.r.read_next() {
            Ok(Some(e)) => match e.value {
                TlvValue::ContainerEnd => {
                    self.open = false;
                    None
                }
                v => match e.tag {
                    TlvTag::ContextSpecific(t) => Some((t, v)),
                    // タグなし要素は 0xFF(非該当)として返す。
                    _ => Some((0xFF, v)),
                },
            },
            _ => {
                self.open = false;
                None
            }
        }
    }
}

/// 生成レスポンスの匿名構造体を開き、フィールド書き込み用 [`TlvWriter`] を返す。
pub(crate) fn open_response<'w, 'b>(
    resp: &'w mut CmdResponder<'_, 'b>,
    response_id: u32,
) -> Result<&'w mut TlvWriter<'b>, ImStatus> {
    resp.set_response(CommandId(response_id));
    let w = resp.writer();
    w.start_struct(&TlvTag::Anonymous).map_err(map_tlv)?;
    Ok(w)
}

/// [`open_response`] で開いた構造体を閉じる。
pub(crate) fn close_response(w: &mut TlvWriter<'_>) -> Result<(), ImStatus> {
    w.end_container().map_err(map_tlv)
}
