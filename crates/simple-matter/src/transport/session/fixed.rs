//! 固定容量のインライン Vec(heapless 風・自前実装)。
//!
//! `docs/design/transport-exchange.md` §4.3 の `FixedVec` に相当する。要素を先頭から
//! 詰めて格納し、削除は `swap_remove`(末尾と入れ替えて取り出す)で行う。ヒープ確保・
//! `unsafe`・要素の `Default` 境界のいずれも不要になるよう `[Option<T>; N]` を土台にし、
//! `[0, len)` の範囲は常に `Some` という不変条件を保つ。
//!
//! 汎用コンテナだが、本ピースではセッションテーブルの格納にのみ用いる。

use core::ops::{Index, IndexMut};

/// 容量 `N` のインライン Vec。
#[derive(Debug)]
pub struct FixedVec<T, const N: usize> {
    /// `[0, len)` は常に `Some`、それ以外は `None`。
    items: [Option<T>; N],
    len: usize,
}

impl<T, const N: usize> FixedVec<T, N> {
    /// 空の `FixedVec` を生成する。
    pub const fn new() -> Self {
        Self {
            items: [const { None }; N],
            len: 0,
        }
    }

    /// 現在の要素数を返す。
    pub const fn len(&self) -> usize {
        self.len
    }

    /// 空なら `true`。
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 満杯なら `true`。
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// 末尾へ要素を追加する。満杯なら `Err(value)` として値を返す。
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.len >= N {
            return Err(value);
        }
        self.items[self.len] = Some(value);
        self.len += 1;
        Ok(())
    }

    /// `index` の要素を末尾要素と入れ替えて取り出す(O(1))。
    ///
    /// # Panics
    /// `index >= len` の場合。呼び出し側で範囲を保証すること。
    pub fn swap_remove(&mut self, index: usize) -> T {
        assert!(index < self.len, "swap_remove index out of bounds");
        let last = self.len - 1;
        self.items.swap(index, last);
        let value = self.items[last].take();
        self.len = last;
        // 不変条件より `[0, len)` は Some。
        value.expect("packed slot must be Some")
    }

    /// `index` の要素への参照(範囲外は `None`)。
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            self.items[index].as_ref()
        } else {
            None
        }
    }

    /// `index` の要素への可変参照(範囲外は `None`)。
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len {
            self.items[index].as_mut()
        } else {
            None
        }
    }

    /// 要素を走査するイテレータ。
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items[..self.len].iter().map(|slot| {
            // 不変条件より Some。
            slot.as_ref().expect("packed slot must be Some")
        })
    }
}

impl<T, const N: usize> Default for FixedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Index<usize> for FixedVec<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &T {
        self.get(index).expect("index out of bounds")
    }
}

impl<T, const N: usize> IndexMut<usize> for FixedVec<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut T {
        self.get_mut(index).expect("index out of bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_until_full() {
        let mut v: FixedVec<u32, 3> = FixedVec::new();
        assert!(v.is_empty());
        assert_eq!(v.push(10), Ok(()));
        assert_eq!(v.push(20), Ok(()));
        assert_eq!(v.push(30), Ok(()));
        assert!(v.is_full());
        assert_eq!(v.push(40), Err(40));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn swap_remove_keeps_packed() {
        let mut v: FixedVec<u32, 4> = FixedVec::new();
        for i in 0..4 {
            v.push(i).unwrap();
        }
        // index 1 を除去 → 末尾 3 が index 1 へ。
        assert_eq!(v.swap_remove(1), 1);
        assert_eq!(v.len(), 3);
        let got: [u32; 3] = [v[0], v[1], v[2]];
        assert_eq!(got, [0, 3, 2]);
        // 残りが全て有効(None が混ざらない)。
        assert_eq!(v.iter().count(), 3);
    }

    #[test]
    fn get_and_index() {
        let mut v: FixedVec<u32, 4> = FixedVec::new();
        v.push(5).unwrap();
        v.push(6).unwrap();
        assert_eq!(v.get(1), Some(&6));
        assert_eq!(v.get(2), None);
        assert_eq!(v[0], 5);
        v[0] = 9;
        assert_eq!(v[0], 9);
    }
}
