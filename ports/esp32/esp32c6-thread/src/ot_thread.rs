//! コアの [`ThreadDriver`] trait の openthread 実装。
//!
//! `docs/design/thread-port.md` §4.3。[`NetworkCommissioningThread`] クラスタが
//! `AddOrUpdateThreadNetwork` / `ConnectNetwork` で Thread attach を起動するための
//! プラットフォーム注入型。[`OpenThread`] ハンドル(`Clone`)を保持し、
//!
//! - `set_dataset`: `otDatasetSetActiveTlvs`(dataset TLV を即時投入)+ Ext PAN ID 抽出。
//! - `connect`: `otIp6SetEnabled(true)` → `otThreadSetEnabled(true)`(attach 開始、非ブロッキング)。
//! - `status`: `otThreadGetDeviceRole` を [`ThreadStatus`] へ写像する。
//!
//! [`NetworkCommissioningThread`]: simple_matter::dm::clusters::NetworkCommissioningThread

use openthread::{DeviceRole, OpenThread};

use simple_matter::error::{Error, Result};
use simple_matter::thread::{extract_ext_pan_id, ThreadDriver, ThreadStatus};

/// openthread ハンドルを保持する [`ThreadDriver`] 実装。
///
/// `OpenThread` は `Clone` 可(内部状態は `'static` に固定確保済み)。同一インスタンスの
/// クローンを `ot.run` タスク・UDP ソケット・SRP 登録・本ドライバで共有する。ドライバの
/// メソッドはすべて同期(await しない)なので、`ot.run` の await 間に協調的に実行される
/// 単一 executor 上で安全に呼べる(`activate()` の RefCell 借用を跨がない)。
pub struct OtThreadDriver<'a> {
    ot: OpenThread<'a>,
    /// `connect`(attach 開始)が一度でも呼ばれたか。Detached 中の Idle/Attaching を区別する。
    connect_requested: bool,
    /// 運用広告(SRP)がサーバ確認済み(= コントローラが operational を mDNS で解決可能)か。
    ///
    /// pump が SRP 登録の完了(host/service = Registered)を観測して立てる。
    /// `status()` はこれが立つまで [`ThreadStatus::Attached`] を返さない = 遅延
    /// ConnectNetworkResponse を **SRP 登録が OTBR advertising proxy に反映されるまで保留**する。
    /// これが無いと chip-tool の operational discovery(~30s)が SRP→mDNS 伝搬に
    /// 先行してタイムアウトする(T2 実測)。pump 側にフォールバック期限あり。
    operational_ready: bool,
    /// `set_dataset` で受け取った dataset TLV のコピー(統合層が KVS へ永続化するために取り出す)。
    ///
    /// dataset は cluster → driver へ直接流れ pump からは見えないため、ここに退避して
    /// pump が [`take_pending_dataset`](Self::take_pending_dataset) で回収し flash に書く
    /// (`docs/design/thread-port.md` §5.3 の割り切り: OT Settings は RAM、dataset は自前永続化)。
    pending_dataset: Option<heapless::Vec<u8, 254>>,
}

impl<'a> OtThreadDriver<'a> {
    /// openthread ハンドルからドライバを作る。
    pub fn new(ot: OpenThread<'a>) -> Self {
        Self {
            ot,
            connect_requested: false,
            operational_ready: false,
            pending_dataset: None,
        }
    }

    /// `connect_requested` を立てる(リブート時の自動再 attach 復元用。attach は呼び出し側が起動する)。
    pub fn mark_connect_requested(&mut self) {
        self.connect_requested = true;
    }

    /// 運用広告(SRP)のサーバ確認済みフラグを設定する(pump が観測して立てる)。
    pub fn set_operational_ready(&mut self, ready: bool) {
        self.operational_ready = ready;
    }

    /// 直近の `set_dataset` で受けた dataset TLV を取り出す(未取得なら `None`)。
    ///
    /// 統合層(pump)が毎周ポーリングし、返ってきた TLV を KVS に保存する。
    pub fn take_pending_dataset(&mut self) -> Option<heapless::Vec<u8, 254>> {
        self.pending_dataset.take()
    }
}

impl ThreadDriver for OtThreadDriver<'_> {
    fn set_dataset(&mut self, tlv: &[u8]) -> Result<[u8; 8]> {
        // dataset TLV を OT のアクティブ dataset として即時投入する。
        self.ot
            .set_active_dataset_tlv(tlv)
            .map_err(|_| Error::InvalidState)?;
        // NetworkID = Extended PAN ID(コア util で TLV から抽出)。
        let ext_pan_id = extract_ext_pan_id(tlv).ok_or(Error::Decode)?;
        // pump が KVS へ永続化するために dataset TLV を退避する(254B 上限に収まる)。
        self.pending_dataset = heapless::Vec::from_slice(tlv).ok();
        Ok(ext_pan_id)
    }

    fn connect(&mut self) {
        // IPv6 インターフェースを上げてから Thread を有効化(attach 開始、非ブロッキング)。
        let _ = self.ot.enable_ipv6(true);
        let _ = self.ot.enable_thread(true);
        self.connect_requested = true;
    }

    fn status(&self) -> ThreadStatus {
        match self.ot.net_status().role {
            DeviceRole::Child | DeviceRole::Router | DeviceRole::Leader => {
                // attach 済みでも SRP 登録がサーバ確認されるまでは Attaching を維持する
                // (遅延 ConnectNetworkResponse の送出タイミングを mDNS 可視化に同期)。
                if self.operational_ready {
                    ThreadStatus::Attached
                } else {
                    ThreadStatus::Attaching
                }
            }
            DeviceRole::Detached => {
                if self.connect_requested {
                    ThreadStatus::Attaching
                } else {
                    ThreadStatus::Idle
                }
            }
            DeviceRole::Disabled | DeviceRole::Other(_) => ThreadStatus::Idle,
        }
    }
}
