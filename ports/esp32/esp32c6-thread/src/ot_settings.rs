//! openthread の [`Settings`] trait を flash KVS([`EspKvs`])で実装する。
//!
//! `docs/design/thread-port.md` §5.3。OT は dataset・ネットワークキー・SRP client の
//! ECDSA 鍵等を自分の key 空間(u16)で永続化する。これを [`EspKvs`] に裏打ちすることで:
//!
//! - リブート後は dataset 再注入なしで **OT 自身が自動 re-attach** する
//!   (NetworkInfo / ActiveDataset が flash に残る)。
//! - **SRP client の鍵が保たれる** — RAM settings だと毎起動で鍵が変わり、SRP サーバに
//!   残る同名ホストの登録(key-lease 既定 ~7.8 日)と鍵不一致で衝突・登録失敗する
//!   (T2 実測でリブート永続化の妨げになる)。
//!
//! # 共有(RefCell)
//!
//! flash(nvs 領域)は fabric / resumption / dataset 永続化(pump)と共有するため、
//! [`EspKvs`] は `RefCell` で包んで貸し借りする。すべての利用箇所は同一 thread-mode
//! executor 上の同期スコープ(await を跨がない)なので二重借用は起きない。
//!
//! # key 写像
//!
//! OT key(u16)+ index(u8)を KVS の短キー `[b'o', b't', key_lo, key_hi, index]`
//! (5 バイト ≤ EspKvs の 7 バイト上限)に平坦化する。OT の indexed multi-value は
//! 「index 0..N-1 が連続して存在する」規約で扱い、`add` は最初の空き index へ、
//! `remove(idx)` は後続を前詰めする(`RamSettings` と同じ意味論)。MTD で実際に使う
//! key はほぼ単一値(NetworkInfo / ParentInfo / ActiveDataset / SrpEcdsaKey 等)なので
//! index 上限は [`MAX_INDEXES`] で十分。
//!
//! # 書き込みタイミング(リスク R6)
//!
//! OT の settings 書き込みは attach 時とキーロール時に集中する。flash 書き込み中の
//! キャッシュ停止が BLE/15.4 と干渉する可能性は既知課題(kvs.rs)— fabric 保存
//! (同じ EspKvs)と同様、T2 実測では問題は観測されていない。

use core::cell::RefCell;

use openthread::{Settings, SettingsError};

use crate::kvs::EspKvs;
use simple_matter::kvs::Kvs;

/// 1 つの OT key が持てる index 数の上限(MTD の実使用は 1〜2)。
const MAX_INDEXES: u8 = 4;

/// OT settings 値の最大長(ActiveDataset TLV が最大 ~254B)。
const MAX_VALUE_LEN: usize = 260;

/// [`EspKvs`] 裏打ちの OT [`Settings`] 実装(pump と flash を共有する)。
pub struct KvsSettings {
    kvs: &'static RefCell<EspKvs>,
}

impl KvsSettings {
    /// 共有 KVS(`'static` な `RefCell`)から settings を作る。
    pub fn new(kvs: &'static RefCell<EspKvs>) -> Self {
        Self { kvs }
    }

    /// OT key + index → KVS 短キー。
    fn kvs_key(key: u16, index: u8) -> [u8; 5] {
        let k = key.to_le_bytes();
        [b'o', b't', k[0], k[1], index]
    }

    /// 指定 index の値を読む。
    fn read(&self, key: u16, index: u8, buf: &mut [u8]) -> Option<usize> {
        self.kvs
            .borrow_mut()
            .get(&Self::kvs_key(key, index), buf)
            .ok()
            .flatten()
    }

    /// key の現在の index 数(連続規約)。
    fn count(&self, key: u16) -> u8 {
        let mut tmp = [0u8; MAX_VALUE_LEN];
        let mut n = 0;
        while n < MAX_INDEXES {
            if self.read(key, n, &mut tmp).is_none() {
                break;
            }
            n += 1;
        }
        n
    }
}

impl Settings for KvsSettings {
    fn init(&mut self, _sensitive_keys: &[u16]) {
        // 暗号化ストレージは持たない(nvs 領域にそのまま格納)。
    }

    fn get(
        &mut self,
        key: u16,
        index: usize,
        buf: &mut [u8],
    ) -> Result<Option<usize>, SettingsError> {
        if index >= MAX_INDEXES as usize {
            return Ok(None);
        }
        let mut tmp = [0u8; MAX_VALUE_LEN];
        match self.read(key, index as u8, &mut tmp) {
            Some(len) => {
                let n = len.min(buf.len());
                buf[..n].copy_from_slice(&tmp[..n]);
                // OT の規約: buf が短い場合も実長を返す(呼び出し側が切り詰めを検知)。
                Ok(Some(len))
            }
            None => Ok(None),
        }
    }

    fn add(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        let n = self.count(key);
        if n >= MAX_INDEXES {
            return Err(SettingsError::NoBufs);
        }
        self.kvs
            .borrow_mut()
            .set(&Self::kvs_key(key, n), value)
            .map_err(|_| SettingsError::NoBufs)
    }

    fn remove(&mut self, key: u16, index: Option<usize>) -> Result<bool, SettingsError> {
        let n = self.count(key);
        if n == 0 {
            return Ok(false);
        }
        match index {
            None => {
                // 全 index を削除。
                for i in 0..n {
                    let _ = self.kvs.borrow_mut().remove(&Self::kvs_key(key, i));
                }
                Ok(true)
            }
            Some(idx) => {
                if idx >= n as usize {
                    return Ok(false);
                }
                // 後続を前詰めして連続規約を保つ。
                let mut tmp = [0u8; MAX_VALUE_LEN];
                for i in (idx as u8)..n - 1 {
                    if let Some(len) = self.read(key, i + 1, &mut tmp) {
                        let _ = self
                            .kvs
                            .borrow_mut()
                            .set(&Self::kvs_key(key, i), &tmp[..len]);
                    }
                }
                let _ = self.kvs.borrow_mut().remove(&Self::kvs_key(key, n - 1));
                Ok(true)
            }
        }
    }

    fn set(&mut self, key: u16, value: &[u8]) -> Result<(), SettingsError> {
        // 既存の全 index を消してから index 0 に書く(OT の update 意味論)。
        let _ = self.remove(key, None);
        self.kvs
            .borrow_mut()
            .set(&Self::kvs_key(key, 0), value)
            .map_err(|_| SettingsError::NoBufs)
    }

    fn clear(&mut self) -> Result<(), SettingsError> {
        // OT が使う予約 key は小さい昇順の enum(0x01..=0x0D 程度)。余裕を持って
        // 0..=0x20 を走査削除する(factory reset 相当。頻度は極低)。
        for key in 0u16..=0x20 {
            let _ = self.remove(key, None);
        }
        Ok(())
    }

    fn deinit(&mut self) {}
}
