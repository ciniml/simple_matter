//! プラットフォーム Thread ドライバの最小抽象([`crate::wifi`] の兄弟)。
//!
//! `docs/design/thread-port.md` §4。NetworkCommissioning クラスタ
//! ([`crate::dm::clusters::NetworkCommissioningThread`])がプラットフォームの実
//! Thread attach(openthread の `enable_thread`)を起動するための注入 trait。
//! [`crate::wifi::WifiDriver`] と同じ「最小 trait + プラットフォーム注入」の流儀で、
//! trait 定義は依存ゼロ・no_std・alloc 非依存・feature ゲートなしで常時コンパイルされる。
//!
//! # 設計判断(doc §4.1、Wi-Fi 版 §E5.1 と同型)
//!
//! - **`connect` は開始のみ**(同期・非ブロッキング)。IM の invoke ハンドラは同期
//!   Mealy machine であり、attach 完了(数秒)を待てない。実装は要求を記録して即返り、
//!   実際の MLE attach はプラットフォーム側のタスク(`ot.run`)が進める。
//! - **dataset は `set_dataset` で受け取り、NetworkID = Extended PAN ID を返す**。
//!   openthread に即時投入(`set_active_dataset_tlv`)し、TLV から抜いた 8 バイトの
//!   Ext PAN ID を Networks 属性・ConnectNetwork の照合キーにする。
//! - **エラーは `status()` に集約**する。attach 失敗は [`ThreadStatus::Failed`] で
//!   後から観測される。

use crate::error::{Error, Result};

/// Thread Operational Dataset TLV の Extended PAN ID タイプ(Thread Spec、Meshcop TLV)。
const EXT_PAN_ID_TLV_TYPE: u8 = 0x02;
/// Extended PAN ID の長さ(8 バイト)。
const EXT_PAN_ID_LEN: usize = 8;

/// Thread attach の現在状態([`ThreadDriver::status`] が返す)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStatus {
    /// 未 attach(まだ `connect` が呼ばれていない、または detached)。
    Idle,
    /// attach 進行中(MLE、Detached → Child 待ち)。
    Attaching,
    /// attach 済み(Child / Router / Leader のいずれか。role の詳細はポート側ログで)。
    Attached,
    /// attach 失敗。`reason` はプラットフォーム定義のエラーコード
    /// (LastConnectErrorValue 属性へそのまま反映される)。
    Failed {
        /// プラットフォーム定義の失敗理由コード。
        reason: i32,
    },
}

/// プラットフォームの Thread ドライバ(openthread の薄いラッパ)。
///
/// 実装例: ESP32-C6 の openthread(`OtThreadDriver`。dataset を OT に投入し
/// `enable_thread` で attach を開始する)、PC の [`NullThreadDriver`](即 Attached のシム)。
pub trait ThreadDriver {
    /// Operational Dataset(TLV バイト列)を保存する(AddOrUpdateThreadNetwork)。
    ///
    /// 非ブロッキングであること。戻り値は dataset から抜いた Extended PAN ID(8B)=
    /// NetworkID。TLV に Ext PAN ID が無い場合は [`Error::Decode`]。
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]>;

    /// attach を**開始**する(ConnectNetwork。非ブロッキング)。
    ///
    /// 完了・失敗は [`status`](ThreadDriver::status) で観測する。
    fn connect(&mut self);

    /// 現在の attach 状態を返す。
    fn status(&self) -> ThreadStatus;
}

impl<T: ThreadDriver + ?Sized> ThreadDriver for &mut T {
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]> {
        (**self).set_dataset(tlv)
    }
    fn connect(&mut self) {
        (**self).connect()
    }
    fn status(&self) -> ThreadStatus {
        (**self).status()
    }
}

/// Thread Operational Dataset TLV から Extended PAN ID(8 バイト)を抽出する。
///
/// dataset TLV は `type(1B) + len(1B) + value(len)` の線形の並び。Ext PAN ID は
/// type=0x02・len=8。見つからない(または長さ不正)なら `None`。
pub fn extract_ext_pan_id(tlv: &[u8]) -> Option<[u8; 8]> {
    let mut i = 0;
    while i + 2 <= tlv.len() {
        let ty = tlv[i];
        let len = tlv[i + 1] as usize;
        let val_start = i + 2;
        let val_end = val_start.checked_add(len)?;
        if val_end > tlv.len() {
            // 壊れた TLV(宣言長がバッファを超える)。
            return None;
        }
        if ty == EXT_PAN_ID_TLV_TYPE && len == EXT_PAN_ID_LEN {
            let mut out = [0u8; EXT_PAN_ID_LEN];
            out.copy_from_slice(&tlv[val_start..val_end]);
            return Some(out);
        }
        i = val_end;
    }
    None
}

/// 「即 Attached」の Thread シムドライバ(実際には attach しない)。
///
/// 用途は PC 上の IM テスト([`NullWifiDriver`](crate::wifi::NullWifiDriver) と同型)。
/// `connect` された瞬間に [`ThreadStatus::Attached`] になる。dataset の Ext PAN ID
/// 抽出だけは本物と同じロジックで行う(コア単体テスト用)。
#[derive(Debug, Clone, Copy, Default)]
pub struct NullThreadDriver {
    attached: bool,
}

impl NullThreadDriver {
    /// 未 attach 状態のシムドライバを作る。
    pub const fn new() -> Self {
        Self { attached: false }
    }
}

impl ThreadDriver for NullThreadDriver {
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]> {
        extract_ext_pan_id(tlv).ok_or(Error::Decode)
    }
    fn connect(&mut self) {
        self.attached = true;
    }
    fn status(&self) -> ThreadStatus {
        if self.attached {
            ThreadStatus::Attached
        } else {
            ThreadStatus::Idle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OTBR が払い出す実 dataset(先頭に Ext PAN ID を含む)。
    const REAL_DATASET: &[u8] = &[
        0x02, 0x08, 0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43, // Ext PAN ID
        0x03, 0x0f, b'O', b'p', b'e', b'n', b'T', b'h', b'r', b'e', b'a', b'd', b'-', b'2', b'7',
        b'0', b'2', // Network Name
    ];

    #[test]
    fn extracts_ext_pan_id() {
        assert_eq!(
            extract_ext_pan_id(REAL_DATASET),
            Some([0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43])
        );
    }

    #[test]
    fn ext_pan_id_absent_is_none() {
        // Network Name TLV のみ(Ext PAN ID 無し)。
        let tlv = &[0x03, 0x02, b'h', b'i'];
        assert_eq!(extract_ext_pan_id(tlv), None);
    }

    #[test]
    fn malformed_tlv_does_not_panic() {
        // 宣言長がバッファを超える。
        assert_eq!(extract_ext_pan_id(&[0x02, 0x08, 0x00]), None);
        // 空。
        assert_eq!(extract_ext_pan_id(&[]), None);
        // Ext PAN ID タイプだが長さが 8 でない。
        assert_eq!(extract_ext_pan_id(&[0x02, 0x04, 1, 2, 3, 4]), None);
    }

    #[test]
    fn null_driver_attaches_immediately() {
        let mut d = NullThreadDriver::new();
        assert_eq!(d.status(), ThreadStatus::Idle);
        let id = d.set_dataset(REAL_DATASET).unwrap();
        assert_eq!(id, [0xc9, 0x33, 0xe1, 0x60, 0xa2, 0x3d, 0x11, 0x43]);
        // set_dataset は attach しない。
        assert_eq!(d.status(), ThreadStatus::Idle);
        d.connect();
        assert_eq!(d.status(), ThreadStatus::Attached);
    }

    #[test]
    fn null_driver_rejects_dataset_without_ext_pan_id() {
        let mut d = NullThreadDriver::new();
        assert!(d.set_dataset(&[0x03, 0x02, b'h', b'i']).is_err());
    }

    /// `&mut T` へのブランケット実装が合成に使えることを型レベルで確認する。
    #[test]
    fn blanket_impl_compiles() {
        fn assert_driver(_: impl ThreadDriver) {}
        let mut d = NullThreadDriver::new();
        assert_driver(&mut d);
    }
}
