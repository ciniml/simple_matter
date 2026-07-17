//! Thread プロビジョンの **take 方式** ドライバ(`docs/design/c-ffi-shim.md` §10.2)。
//!
//! [`crate::wifi_driver::ShimWifiDriver`] の鏡像。コアの
//! [`NetworkCommissioningThread`](simple_matter::dm::clusters::NetworkCommissioningThread) は
//! `AddOrUpdateThreadNetwork` で dataset TLV を [`ThreadDriver::set_dataset`] に渡し、
//! `ConnectNetwork` 受理で [`ThreadDriver::connect`] を呼び「attach 開始 + 遅延
//! ConnectNetworkResponse」を行う。ESP-IDF 側の実 attach(esp_openthread)は別タスクだが、
//! シムは単一インスタンス・単線契約なのでコールバックではなく **take 方式** で橋渡しする:
//!
//! - `set_dataset()`(IM ハンドラから同期呼び出し)は dataset TLV を内部に退避し、
//!   Ext PAN ID を抽出して返す(NetworkID)。
//! - `connect()`(IM ハンドラから同期呼び出し)は状態を [`ThreadStatus::Attaching`] にして
//!   「未取り出しの dataset 投入要求」を立てる。統合層(housekeep)がこれを見て
//!   `SM_EV_THREAD_ATTACH_REQUEST` イベントを立てる。
//! - C++ 側は [`crate::sm_take_thread_dataset`] で dataset TLV を取り出し、esp_openthread へ
//!   投入して attach を開始する。
//! - attach 結果は [`crate::sm_thread_status`] が [`ShimThreadDriver::set_status`] を呼んで
//!   反映し、コアの `poll_deferred` が遅延 ConnectNetworkResponse を確定させる。

use simple_matter::error::{Error, Result};
use simple_matter::thread::{extract_ext_pan_id, ThreadDriver, ThreadStatus};

/// Thread Operational Dataset TLV の保持上限(Matter は最大 254 バイト)。
const DATASET_CAP: usize = 256;

/// take 方式の Thread ドライバ(単線契約下でのみ使用)。
#[derive(Debug)]
pub struct ShimThreadDriver {
    /// AddOrUpdateThreadNetwork で受理した dataset TLV。
    dataset: [u8; DATASET_CAP],
    /// `dataset` の有効長(0 なら未設定)。
    dataset_len: usize,
    /// C++ 側にまだ渡していない attach 要求(dataset 投入)があるか。
    pending: bool,
    /// 現在の attach 状態(`sm_thread_status` で更新)。
    status: ThreadStatus,
}

impl ShimThreadDriver {
    /// 未 attach・要求なしのドライバを作る。
    pub const fn new() -> Self {
        Self {
            dataset: [0u8; DATASET_CAP],
            dataset_len: 0,
            pending: false,
            status: ThreadStatus::Idle,
        }
    }

    /// C++ に渡していない attach 要求(dataset 投入)があるか。
    pub fn has_pending(&self) -> bool {
        self.pending
    }

    /// 保留中の dataset TLV を取り出す。無ければ `None`。
    ///
    /// 取り出すと `pending` はクリアされる(状態 `Attaching` は維持。C++ の attach 結果を待つ)。
    pub fn take_dataset(&mut self) -> Option<&[u8]> {
        if !self.pending {
            return None;
        }
        self.pending = false;
        Some(&self.dataset[..self.dataset_len])
    }

    /// C++ からの attach 結果を反映する(`true`=Attached、`false`=Failed)。
    pub fn set_status(&mut self, attached: bool) {
        self.status = if attached {
            ThreadStatus::Attached
        } else {
            // 失敗理由コードはプラットフォーム定義。take 方式では詳細を持たないため -1。
            ThreadStatus::Failed { reason: -1 }
        };
    }
}

impl Default for ShimThreadDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadDriver for ShimThreadDriver {
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]> {
        // Ext PAN ID を先に検証(不正な dataset は保存しない)。
        let ext_pan_id = extract_ext_pan_id(tlv).ok_or(Error::Decode)?;
        let n = tlv.len().min(self.dataset.len());
        self.dataset[..n].copy_from_slice(&tlv[..n]);
        self.dataset_len = n;
        Ok(ext_pan_id)
    }

    fn connect(&mut self) {
        self.pending = true;
        self.status = ThreadStatus::Attaching;
    }

    fn status(&self) -> ThreadStatus {
        self.status
    }
}
