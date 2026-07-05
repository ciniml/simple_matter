//! プラットフォーム KVS(key-value store)の最小抽象。
//!
//! `docs/design/port-esp32-device.md` §E4.1。fabric 永続化([`crate::fabric`] の
//! `save_to` / `load_from`)が使う、プラットフォーム注入型の永続ストレージ trait。
//! [`crate::crypto::Rng`] と同じ「最小 trait + 単一バックエンド注入」の流儀で、
//! trait 定義は依存ゼロ・no_std・alloc 非依存・feature ゲートなしで常時コンパイルされる。
//!
//! # 設計判断(doc §E4.1)
//!
//! - **同期(blocking)API**。flash 書き込みは低頻度パス(fabric 変更時のみ)であり、
//!   コアの executor 非依存を保つ。非同期ドライバはプラットフォーム実装側で吸収する。
//! - **`&mut self`**。flash ドライバは本質的に排他アクセスであるため。共有が必要な
//!   統合層は外側で `RefCell` 等に包む。
//! - キー・値ともに borrowed slice で受け渡し、ヒープを確保しない。

use crate::error::Result;

/// プラットフォームの永続 key-value store。
///
/// 実装例: ESP32 の flash(esp-storage + sequential-storage)、PC のファイル、
/// テスト用のインメモリ map。キーは短いバイト列(実装は最低 8 バイトのキー長を
/// 受け付けること)、値は数 KiB 程度までを想定する(fabric レコードは
/// [`crate::fabric::MAX_FABRIC_RECORD_LEN`] 以下)。
pub trait Kvs {
    /// `key` の値を `buf` の先頭へコピーし、その長さを返す。
    ///
    /// - キーが存在しなければ `Ok(None)`。
    /// - `buf` が値より小さい場合は [`crate::Error::NoSpace`]。
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>>;

    /// `key` に `value` を格納する(既存値は上書き)。
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>;

    /// `key` を削除する。**キーが存在しなくても `Ok`**(冪等)。
    ///
    /// 呼び出し側(fabric の `save_to` 等)が「空きスロットのキーを無条件に消す」
    /// パターンで使うため、不在をエラーにしない。
    fn remove(&mut self, key: &[u8]) -> Result<()>;
}

impl<T: Kvs + ?Sized> Kvs for &mut T {
    fn get(&mut self, key: &[u8], buf: &mut [u8]) -> Result<Option<usize>> {
        (**self).get(key, buf)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        (**self).set(key, value)
    }
    fn remove(&mut self, key: &[u8]) -> Result<()> {
        (**self).remove(key)
    }
}
