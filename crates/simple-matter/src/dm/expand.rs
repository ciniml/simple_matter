//! ワイルドカード属性パスの展開カーソル(`docs/design/interaction-model.md` §5.2)。
//!
//! [`PathExpandCursor`] はワイルドカード可の [`AttributePath`] 列を、`DataModel` の
//! メタデータと突き合わせて具象パス([`ConcreteAttrPath`])へ 1 つずつ展開する。
//! インデックスのみの `Copy` な再開カーソルで(借用イテレータではない)、IM エンジン
//! (次ピース)がチャンク中 Read の slot に格納して再開に使う。
//!
//! # 設計との差
//!
//! 設計 §1 はカーソルを `im/engine/read.rs` に置くが、本ピース(dm 層)がメタデータ walk の
//! 一部として提供する。IM エンジン実装時にそのまま利用できる(`DataModel` にのみ依存)。

use crate::dm::meta::{AttributeMeta, GLOBAL_ATTRIBUTE_IDS};
use crate::dm::DataModel;
use crate::im::wire::{AttributePath, ConcreteAttrPath};

/// ワイルドカード展開の再開カーソル(`u16` × 4、8 バイト。`Copy`)。
///
/// 展開順序は endpoint → cluster → attribute の宣言順(各クラスタは固有属性→グローバル属性)で
/// 決定的。[`PathExpandCursor::next`] を呼ぶたびに次の具象パスとそのメタを返し、位置を進める。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathExpandCursor {
    /// リクエストパス列の走査位置。
    path_idx: u16,
    /// `DataModel::endpoints()` の走査位置。
    ep_idx: u16,
    /// 当該エンドポイントのクラスタ列の走査位置。
    cl_idx: u16,
    /// 当該クラスタの属性(固有+グローバル)の走査位置。
    at_idx: u16,
}

impl PathExpandCursor {
    /// 先頭位置のカーソルを作る。
    pub const fn new() -> Self {
        Self {
            path_idx: 0,
            ep_idx: 0,
            cl_idx: 0,
            at_idx: 0,
        }
    }

    /// 現在処理中のリクエストパスの添字を返す。
    pub const fn path_index(&self) -> u16 {
        self.path_idx
    }

    /// 次の (具象パス, 属性メタ) を返す。全パス消化で `None`。
    ///
    /// `paths` はワイルドカード可のリクエストパス列。`dm` のメタと突き合わせ、存在しない
    /// endpoint/cluster/attribute はスキップする(不正入力で panic しない)。グローバル属性
    /// (`GLOBAL_ATTRIBUTE_IDS`)も列挙し、合成メタ([`AttributeMeta::global`])を返す。
    pub fn next<D: DataModel + ?Sized>(
        &mut self,
        dm: &D,
        paths: &[AttributePath],
    ) -> Option<(ConcreteAttrPath, AttributeMeta)> {
        loop {
            // リクエストパスを消化しきったら終了。
            let p = paths.get(self.path_idx as usize)?;

            let eps = dm.endpoints();
            let Some(ep) = eps.get(self.ep_idx as usize) else {
                // このパスのエンドポイント走査完了 → 次パスへ。
                self.path_idx += 1;
                self.ep_idx = 0;
                self.cl_idx = 0;
                self.at_idx = 0;
                continue;
            };

            // エンドポイントのワイルドカードフィルタ。
            if let Some(want) = p.endpoint {
                if want != ep.id {
                    self.advance_endpoint();
                    continue;
                }
            }

            let Some(&cl) = ep.clusters.get(self.cl_idx as usize) else {
                self.advance_endpoint();
                continue;
            };

            // クラスタのワイルドカードフィルタ。
            if let Some(want) = p.cluster {
                if want != cl {
                    self.advance_cluster();
                    continue;
                }
            }

            // クラスタ実装が無ければスキップ(メタ列挙不能)。
            let Some(sc) = dm.cluster(ep.id, cl) else {
                self.advance_cluster();
                continue;
            };
            let meta = sc.meta();
            let own = meta.attributes;
            let total = own.len() + GLOBAL_ATTRIBUTE_IDS.len();

            let Some((attr_meta, _)) = self.current_attribute(own, total) else {
                self.advance_cluster();
                continue;
            };

            // 属性のワイルドカードフィルタ。
            if let Some(want) = p.attribute {
                if want != attr_meta.id {
                    self.at_idx += 1;
                    continue;
                }
            }

            self.at_idx += 1;
            return Some((ConcreteAttrPath::new(ep.id, cl, attr_meta.id), attr_meta));
        }
    }

    /// `at_idx` が指す属性メタ(固有→グローバルの順)を返す。範囲外は `None`。
    fn current_attribute(
        &self,
        own: &'static [AttributeMeta],
        total: usize,
    ) -> Option<(AttributeMeta, ())> {
        let idx = self.at_idx as usize;
        if idx >= total {
            return None;
        }
        if idx < own.len() {
            Some((own[idx], ()))
        } else {
            let gid = GLOBAL_ATTRIBUTE_IDS[idx - own.len()];
            Some((AttributeMeta::global(gid), ()))
        }
    }

    /// 次のエンドポイントへ(クラスタ/属性位置をリセット)。
    fn advance_endpoint(&mut self) {
        self.ep_idx += 1;
        self.cl_idx = 0;
        self.at_idx = 0;
    }

    /// 次のクラスタへ(属性位置をリセット)。
    fn advance_cluster(&mut self) {
        self.cl_idx += 1;
        self.at_idx = 0;
    }
}
