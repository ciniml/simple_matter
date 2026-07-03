//! 固定サイズ・固定本数のパケットバッファプール。
//!
//! `docs/design/transport-exchange.md` §7 に基づく。定常データパスでヒープを確保
//! しないため、`SIZE` バイトのバッファを `N` 本だけ静的に確保し、リースして使い回す。
//!
//! # 所有権モデル
//!
//! バッファは Transport / 統合層が [`BufferPool`] として所有する。session / exchange
//! はバッファを所有せず、[`BufferId`] で参照するだけである。
//!
//! - RX / 非信頼 TX は、[`acquire`](BufferPool::acquire) でリースして使い、送信後に
//!   [`release`](BufferPool::release) で返す。
//! - 信頼送信(MRP)は唯一の長寿命保持で、ACK されるまで暗号化済みの TX バッファを
//!   保持して再送に使う。再送スロット([`crate::exchange::mrp`])が [`BufferId`] を保持し、
//!   ACK 受信または諦め時に返す。
//!
//! # 時間・executor 非依存
//!
//! 設計 §12 論点 1/5 の判断に従い、本層は同期 API とする。「空きが出るまで `await`」
//! する非同期取得は将来の統合層の責務で、ここでは [`acquire`](BufferPool::acquire) が
//! 即座に [`Option`] を返す(枯渇時は `None`)。
//!
//! # 安全性
//!
//! [`unsafe`] を用いず `[[u8; SIZE]; N]` を土台にする。[`BufferId`] はプールが内部で
//! 採番したスロット番号のみを表す不透明トークンで、外部入力にはならない。不正な二重
//! 返却は [`release`](BufferPool::release) が使用中フラグを見て無視するため `panic` しない。

use crate::error::{Error, Result};

/// プール内のバッファスロットを指す不透明ハンドル。
///
/// [`BufferPool::acquire`] のみが生成する。スロット番号そのものを表すが、外部で
/// 構築・改変できないよう内部値は非公開にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BufferId(usize);

impl BufferId {
    /// 内部のスロット番号を返す(ロギング用途など)。
    pub const fn index(self) -> usize {
        self.0
    }
}

/// `SIZE` バイトのバッファを `N` 本持つ固定容量プール。
///
/// サイジングは const generic で与える(設計 §8)。定常パスでヒープ確保しない。
#[derive(Debug)]
pub struct BufferPool<const N: usize, const SIZE: usize> {
    slots: [[u8; SIZE]; N],
    used: [bool; N],
    in_use: usize,
}

impl<const N: usize, const SIZE: usize> BufferPool<N, SIZE> {
    /// 全スロットが空のプールを生成する。
    pub const fn new() -> Self {
        Self {
            slots: [[0u8; SIZE]; N],
            used: [false; N],
            in_use: 0,
        }
    }

    /// プールの本数(容量)を返す。
    pub const fn capacity(&self) -> usize {
        N
    }

    /// 1 本あたりのバッファサイズ(バイト)を返す。
    pub const fn buffer_size(&self) -> usize {
        SIZE
    }

    /// 現在リース中の本数を返す。
    pub const fn in_use(&self) -> usize {
        self.in_use
    }

    /// 空きの本数を返す。
    pub const fn available(&self) -> usize {
        N - self.in_use
    }

    /// 空きが 1 本も無ければ `true`。
    pub const fn is_full(&self) -> bool {
        self.in_use == N
    }

    /// 空きスロットを 1 本確保して [`BufferId`] を返す。枯渇時は `None`。
    ///
    /// 内容は前回利用時のまま(ゼロ埋めしない)。呼び出し側が必要分を書き込む。
    pub fn acquire(&mut self) -> Option<BufferId> {
        for (i, used) in self.used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.in_use += 1;
                return Some(BufferId(i));
            }
        }
        None
    }

    /// リースを返却する。既に空きのスロットや範囲外の [`BufferId`] は無視する(二重返却で `panic` しない)。
    pub fn release(&mut self, id: BufferId) {
        if id.0 < N && self.used[id.0] {
            self.used[id.0] = false;
            self.in_use -= 1;
        }
    }

    /// [`BufferId`] が現在リース中(有効)なら `true`。
    pub fn is_allocated(&self, id: BufferId) -> bool {
        id.0 < N && self.used[id.0]
    }

    /// リース中バッファへの参照を返す。
    ///
    /// # Errors
    /// [`BufferId`] が無効(未確保・範囲外)なら [`Error::NotFound`]。
    pub fn get(&self, id: BufferId) -> Result<&[u8; SIZE]> {
        if self.is_allocated(id) {
            Ok(&self.slots[id.0])
        } else {
            Err(Error::NotFound)
        }
    }

    /// リース中バッファへの可変参照を返す(その場書き込み・暗号化に用いる)。
    ///
    /// # Errors
    /// [`BufferId`] が無効(未確保・範囲外)なら [`Error::NotFound`]。
    pub fn get_mut(&mut self, id: BufferId) -> Result<&mut [u8; SIZE]> {
        if self.is_allocated(id) {
            Ok(&mut self.slots[id.0])
        } else {
            Err(Error::NotFound)
        }
    }
}

impl<const N: usize, const SIZE: usize> Default for BufferPool<N, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_until_exhausted_then_none() {
        let mut pool: BufferPool<2, 8> = BufferPool::new();
        assert_eq!(pool.capacity(), 2);
        assert_eq!(pool.available(), 2);
        let a = pool.acquire().unwrap();
        let b = pool.acquire().unwrap();
        assert_ne!(a, b);
        assert!(pool.is_full());
        // 枯渇時は panic せず None。
        assert!(pool.acquire().is_none());
        assert_eq!(pool.in_use(), 2);
    }

    #[test]
    fn release_makes_slot_available_again() {
        let mut pool: BufferPool<2, 8> = BufferPool::new();
        let a = pool.acquire().unwrap();
        let _b = pool.acquire().unwrap();
        assert!(pool.acquire().is_none());
        pool.release(a);
        assert_eq!(pool.available(), 1);
        // 返却後は再確保できる。
        let c = pool.acquire().unwrap();
        assert!(pool.is_full());
        // 二重返却は無視される(パニックしない・カウンタも狂わない)。
        pool.release(c);
        pool.release(c);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn get_after_release_is_error_not_panic() {
        let mut pool: BufferPool<1, 4> = BufferPool::new();
        let a = pool.acquire().unwrap();
        pool.get_mut(a).unwrap().copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(pool.get(a).unwrap(), &[1, 2, 3, 4]);
        pool.release(a);
        // 返却後の参照取得はエラー。
        assert!(!pool.is_allocated(a));
        assert_eq!(pool.get(a).err(), Some(Error::NotFound));
    }
}
