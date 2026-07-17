//! openthread の [`Settings`] trait を **RAM 権威 + idle 時 flush** で実装する(リスク R6 解決)。
//!
//! `docs/design/thread-port.md` §5.3 / リスク R6。T2 の実測で「attach 時の OT settings
//! 書き込みバースト(フレッシュ NVS では領域初期化 erase 込み)が 15.4 radio を回復不能に
//! 停止させる」ことが判明した(ping 100% loss、executor は生存)。esp-storage の flash
//! erase/write 中はキャッシュが停止し、15.4 ISR / OT radio タスクと衝突するのが原因。
//!
//! # 設計: write-back(RAM 権威 + 遅延 flush)
//!
//! OT の [`Settings`] 呼び出し(get/add/remove/set/clear)は **すべて RAM 上の
//! [`SettingsStore`](フラットバッファ)で即応**し、**flash には一切触れない**。書き込みが
//! あると `dirty` フラグだけ立てる。実際の flash 反映は統合層(pump)が **radio が静穏な
//! idle 窓**(直近に UDP 送受が無く、attach が落ち着いた後)でまとめて 1 回書く。これで:
//!
//! - attach 時の書き込みバーストは RAM で吸収され、15.4 radio を止めない(R6 根治)。
//! - dataset・NetworkInfo・**SRP client の ECDSA 鍵**が永続化される。リブート後は OT が
//!   settings から自動復元 → **SRP 鍵が保たれる** → SRP サーバに残る旧登録
//!   (key-lease 既定 ~7.8 日)と鍵衝突せず、同一ホストで再登録できる(T2 割り切りの根治)。
//!
//! # 永続化フォーマット
//!
//! [`SettingsStore`] のフラットバッファ(`[key_le(2) | len_le(2) | value]` の連結。
//! openthread の `RamSettings` と同一レイアウト)を **丸ごと 1 つの KVS アイテム**
//! (キー `otset`)として保存する。OT の MTD 実使用 settings(ActiveDataset ~100B +
//! NetworkInfo + ParentInfo + SrpEcdsaKey + SrpClientInfo 等)は合計でも数百バイトに収まり、
//! [`EspKvs`] の作業バッファ(1.5KiB)に 1 アイテムで入る。単一アイテムなので **flush は
//! 1 回の store_item** で済み、flash 書き込み量(= キャッシュ停止時間)を最小化できる。
//!
//! # 共有(RefCell)
//!
//! [`SettingsStore`] は `'static` な `RefCell` に置き、OT 側の [`KvsSettings`](OT が
//! `&mut dyn Settings` として保持)と pump 側の flush が同じ store を参照する。すべての
//! 利用は同一 thread-mode executor 上の同期スコープ(await を跨がない)なので二重借用は
//! 起きない(`kvs.rs` の `RefCell<EspKvs>` 共有と同じ流儀)。

use core::cell::RefCell;

use openthread::{Settings, SettingsError};

use crate::kvs::EspKvs;
use simple_matter::kvs::Kvs;

/// RAM 権威バッファの容量(openthread の `SimpleRamSettings` と同じ 1KiB)。
/// MTD の実使用 settings 合計を十分上回る。
const STORE_CAP: usize = 1024;

/// 設定エントリ 1 件のヘッダ長(key u16 LE + value 長 u16 LE)。
const HDR_LEN: usize = 4;

/// 永続化した settings ブロブの KVS キー(ポートローカル。`otds`(dataset 自前保存)と別)。
pub const SETTINGS_KVS_KEY: &[u8] = b"otset";

/// OT settings の RAM 権威ストア(フラットバッファ。write-back の 1 次記憶)。
///
/// レイアウトは openthread `RamSettings` と同一の `[key_le(2) | len_le(2) | value]` 連結。
/// 変更(add/remove/set/clear)があると [`dirty`](Self::dirty) を立てる。pump が idle 窓で
/// [`flush`] してクリアする。
pub struct SettingsStore {
    buf: [u8; STORE_CAP],
    len: usize,
    /// 直近の flush 以降に RAM が変更されたか(pump が観測して flush 契機にする)。
    dirty: bool,
}

impl Default for SettingsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsStore {
    /// 空のストアを作る。
    pub const fn new() -> Self {
        Self {
            buf: [0u8; STORE_CAP],
            len: 0,
            dirty: false,
        }
    }

    /// 未 flush の変更があるか。
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// 権威バッファの中身(`[..len]`)。flush が KVS へ丸ごと書く。
    pub fn raw(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// KVS から読み戻したブロブでバッファを初期化する(boot 時 1 回)。dirty は立てない。
    ///
    /// `data` が容量を超える場合は失敗(`false`)。
    pub fn load_raw(&mut self, data: &[u8]) -> bool {
        if data.len() > self.buf.len() {
            return false;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.len = data.len();
        self.dirty = false;
        true
    }

    /// エントリを走査するイテレータ(内部用。`(key, value)`)。
    fn iter(&self) -> StoreIter<'_> {
        StoreIter {
            buf: &self.buf[..self.len],
        }
    }

    /// key/index の値を buf へ読む(実長を返す。buf が短ければ切り詰めるが実長を返す)。
    fn get(&self, key: u16, index: usize, out: &mut [u8]) -> Option<usize> {
        let mut cur = 0usize;
        for (k, v) in self.iter() {
            if k == key {
                if cur == index {
                    let n = v.len().min(out.len());
                    out[..n].copy_from_slice(&v[..n]);
                    return Some(v.len());
                }
                cur += 1;
            }
        }
        None
    }

    /// key に新しい index として value を追記する。
    fn add(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        let need = HDR_LEN + value.len();
        if self.buf.len() - self.len < need {
            return Err(SettingsError::NoBufs);
        }
        let at = self.len;
        self.buf[at..at + 2].copy_from_slice(&key.to_le_bytes());
        self.buf[at + 2..at + 4].copy_from_slice(&(value.len() as u16).to_le_bytes());
        self.buf[at + 4..at + need].copy_from_slice(value);
        self.len += need;
        self.dirty = true;
        Ok(())
    }

    /// key(の指定 index、または全 index)を削除して前詰めする。削除有無を返す。
    fn remove(&mut self, key: u16, index: Option<usize>) -> bool {
        let mut found = false;
        let mut cur = 0usize; // 対象 key の出現番号
        let mut pos = 0usize; // バッファ走査位置
        while pos + HDR_LEN <= self.len {
            let k = u16::from_le_bytes([self.buf[pos], self.buf[pos + 1]]);
            let vlen = u16::from_le_bytes([self.buf[pos + 2], self.buf[pos + 3]]) as usize;
            let entry_len = HDR_LEN + vlen;
            let matches = k == key && index.map(|i| i == cur).unwrap_or(true);
            if k == key {
                // 出現番号は「元の順序での index」。削除しても進めることで、
                // Some(index) は元の index に一致した 1 件だけを消す(openthread RamSettings と同義)。
                cur += 1;
            }
            if matches {
                // [pos+entry_len..len] を pos へ詰める(次エントリが同じ pos に来る)。
                self.buf.copy_within(pos + entry_len..self.len, pos);
                self.len -= entry_len;
                self.dirty = true;
                found = true;
                continue;
            }
            pos += entry_len;
        }
        found
    }

    /// key を全消去してから value を index 0 として書く(OT の update 意味論)。
    fn set(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        self.remove(key, None);
        self.add(key, value)
    }

    /// 全消去。
    fn clear(&mut self) {
        self.len = 0;
        self.dirty = true;
    }
}

/// [`SettingsStore`] のフラットバッファを走査する `(key, value)` イテレータ。
struct StoreIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for StoreIter<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < HDR_LEN {
            return None;
        }
        let key = u16::from_le_bytes([self.buf[0], self.buf[1]]);
        let vlen = u16::from_le_bytes([self.buf[2], self.buf[3]]) as usize;
        let end = HDR_LEN + vlen;
        if end > self.buf.len() {
            return None;
        }
        let value = &self.buf[HDR_LEN..end];
        self.buf = &self.buf[end..];
        Some((key, value))
    }
}

/// OT が `&mut dyn Settings` として保持する薄いハンドル(RAM 権威 [`SettingsStore`] を叩く)。
///
/// flash には一切触れない(write-back。R6 対策)。実体は共有 [`SettingsStore`]。
pub struct KvsSettings {
    store: &'static RefCell<SettingsStore>,
}

impl KvsSettings {
    /// 共有ストア(`'static` な `RefCell`)から作る。
    pub fn new(store: &'static RefCell<SettingsStore>) -> Self {
        Self { store }
    }
}

impl Settings for KvsSettings {
    fn init(&mut self, _sensitive_keys: &[u16]) {}

    fn get(
        &mut self,
        key: u16,
        index: usize,
        buf: &mut [u8],
    ) -> Result<Option<usize>, SettingsError> {
        Ok(self.store.borrow().get(key, index, buf))
    }

    fn add(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        self.store.borrow_mut().add(key, value)
    }

    fn remove(&mut self, key: u16, index: Option<usize>) -> Result<bool, SettingsError> {
        Ok(self.store.borrow_mut().remove(key, index))
    }

    fn set(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        self.store.borrow_mut().set(key, value)
    }

    fn clear(&mut self) -> Result<(), SettingsError> {
        self.store.borrow_mut().clear();
        Ok(())
    }

    fn deinit(&mut self) {}
}

/// boot 時に KVS の永続ブロブから RAM ストアを復元する(OT 構築前に呼ぶ)。
///
/// 成功で復元バイト数を返す。永続ブロブが無ければ `Ok(0)`。エラーは KVS I/O 失敗か
/// 容量超過のみで、呼び出し側は「空から開始」に落とすだけなので unit error で十分。
#[allow(clippy::result_unit_err)]
pub fn restore(store: &RefCell<SettingsStore>, kvs: &RefCell<EspKvs>) -> Result<usize, ()> {
    let mut tmp = [0u8; STORE_CAP];
    let read = kvs.borrow_mut().get(SETTINGS_KVS_KEY, &mut tmp);
    match read {
        Ok(Some(len)) => {
            if store.borrow_mut().load_raw(&tmp[..len]) {
                Ok(len)
            } else {
                Err(())
            }
        }
        Ok(None) => Ok(0),
        Err(_) => Err(()),
    }
}

/// dirty なら RAM ストアを KVS へ 1 アイテムで書き出し、dirty をクリアする。
///
/// **radio が静穏な idle 窓で呼ぶこと**(pump が gating する)。flash 書き込み中は
/// キャッシュが停止するため、attach 中や UDP 通信直後には呼んではならない(R6)。
/// 書き込んだら `true`、dirty でなければ `false`。
pub fn flush(store: &RefCell<SettingsStore>, kvs: &RefCell<EspKvs>) -> bool {
    // 権威バッファをローカルへ複製して borrow を落としてから flash を叩く
    // (block_on の flash は executor を占有するが、借用は最小に保つ)。
    let mut blob = [0u8; STORE_CAP];
    let n;
    {
        let s = store.borrow();
        if !s.is_dirty() {
            return false;
        }
        let raw = s.raw();
        n = raw.len();
        blob[..n].copy_from_slice(raw);
    }
    match kvs.borrow_mut().set(SETTINGS_KVS_KEY, &blob[..n]) {
        Ok(()) => {
            // 書き込み成功後に dirty を落とす(失敗時は次の idle 窓で再試行)。
            store.borrow_mut().dirty = false;
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_get_roundtrip_multi_index() {
        let mut s = SettingsStore::new();
        s.add(3, b"aaa").unwrap();
        s.add(3, b"bbbb").unwrap();
        s.add(7, b"z").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(s.get(3, 0, &mut out), Some(3));
        assert_eq!(&out[..3], b"aaa");
        assert_eq!(s.get(3, 1, &mut out), Some(4));
        assert_eq!(&out[..4], b"bbbb");
        assert_eq!(s.get(7, 0, &mut out), Some(1));
        assert_eq!(s.get(7, 1, &mut out), None);
        assert!(s.is_dirty());
    }

    #[test]
    fn set_replaces_all_indices() {
        let mut s = SettingsStore::new();
        s.add(3, b"aaa").unwrap();
        s.add(3, b"bbbb").unwrap();
        s.set(3, b"new").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(s.get(3, 0, &mut out), Some(3));
        assert_eq!(&out[..3], b"new");
        assert_eq!(s.get(3, 1, &mut out), None);
    }

    #[test]
    fn remove_specific_index_shifts() {
        let mut s = SettingsStore::new();
        s.add(5, b"one").unwrap();
        s.add(5, b"two").unwrap();
        s.add(5, b"three").unwrap();
        assert!(s.remove(5, Some(1)));
        let mut out = [0u8; 16];
        assert_eq!(s.get(5, 0, &mut out), Some(3));
        assert_eq!(&out[..3], b"one");
        assert_eq!(s.get(5, 1, &mut out), Some(5));
        assert_eq!(&out[..5], b"three");
        assert_eq!(s.get(5, 2, &mut out), None);
    }

    #[test]
    fn remove_all_indices() {
        let mut s = SettingsStore::new();
        s.add(5, b"one").unwrap();
        s.add(5, b"two").unwrap();
        s.add(6, b"keep").unwrap();
        assert!(s.remove(5, None));
        let mut out = [0u8; 16];
        assert_eq!(s.get(5, 0, &mut out), None);
        assert_eq!(s.get(6, 0, &mut out), Some(4));
    }

    #[test]
    fn load_raw_roundtrip_via_iter() {
        let mut s = SettingsStore::new();
        s.add(1, b"active-dataset").unwrap();
        s.add(9, b"srp-ecdsa-key-bytes").unwrap();
        let mut snapshot = [0u8; STORE_CAP];
        let slen = s.raw().len();
        snapshot[..slen].copy_from_slice(s.raw());
        // 別インスタンスへ load_raw して同じ内容が読めること。
        let mut s2 = SettingsStore::new();
        assert!(s2.load_raw(&snapshot[..slen]));
        assert!(!s2.is_dirty());
        let mut out = [0u8; 64];
        assert_eq!(s2.get(1, 0, &mut out), Some(14));
        assert_eq!(&out[..14], b"active-dataset");
        assert_eq!(s2.get(9, 0, &mut out), Some(19));
    }

    #[test]
    fn clear_empties() {
        let mut s = SettingsStore::new();
        s.add(1, b"x").unwrap();
        s.clear();
        let mut out = [0u8; 4];
        assert_eq!(s.get(1, 0, &mut out), None);
        assert_eq!(s.raw().len(), 0);
    }
}
