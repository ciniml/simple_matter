//! 埋め込み用 API: 結果を stdout へ表示せず**データとして返す** [`Exec`] の操作群
//! (`docs/design/web-controller.md` §3 / §4、`smweb` のコントローラスレッドが使う)。
//!
//! CLI 経路([`Exec::run`])の挙動・出力には一切関与しない(追加のみ)。CASE 取得
//! (キャッシュ → キャッシュアドレス → mDNS 再解決 → resumption 保存)、トランザクション
//! 待ち、静穏化はすべて CLI と同じ内部実装を共有する。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use simple_matter::controller::ca::Ca;
use simple_matter::controller::{OpenWindowParams, DEFAULT_WINDOW_ITERATIONS};
use simple_matter::discovery::onboarding::{
    manual_pairing_code, passcode_is_valid, qr_payload, random_passcode, OnboardingPayload,
    DISCOVERY_CAP_ON_NETWORK, QR_PAYLOAD_MAX_LEN,
};
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath, ImStatus};
use simple_matter::im::ImEvent;
use simple_matter::tlv::{TlvTag, TlvWriter};
use simple_matter::transport::session::SessionId;

use super::{decode_noc_status_code, transcode_tlv, write_value, Exec, Parsed, Target};
use crate::clusters::ValueKind;
use crate::log::{logf, Level};
use crate::runner::udp::send_dir;
use crate::runner::Backend;
use crate::state::{nodes, resume, StateDir};
use crate::OsRng;

/// Read 結果の 1 要素(AttributeReportIB 1 個)。
#[derive(Debug, Clone)]
pub struct ReadItem {
    /// 報告されたパスのエンドポイント。
    pub endpoint: Option<u16>,
    /// 報告されたパスのクラスタ ID。
    pub cluster: Option<u32>,
    /// 報告されたパスの属性 ID。
    pub attribute: Option<u32>,
    /// ListIndex が null(list 追記チャンク: 値は list の 1 要素)。
    pub list_append: bool,
    /// クラスタ DataVersion(あれば)。
    pub data_version: Option<u32>,
    /// 値またはステータス。
    pub outcome: ReadOutcome,
}

/// [`ReadItem`] の中身。
#[derive(Debug, Clone)]
pub enum ReadOutcome {
    /// 値要素の生 TLV(元の context タグ 2 付きの 1 要素)。
    Data(Vec<u8>),
    /// AttributeStatusIB(非成功ステータス)。
    Status {
        /// IM ステータス。
        status: ImStatus,
        /// クラスタ固有ステータス。
        cluster_status: Option<u8>,
    },
    /// デコード不能なレポート。
    Undecodable(String),
}

/// Invoke の結果。
#[derive(Debug, Clone)]
pub struct InvokeOutcome {
    /// 応答の総合ステータス。
    pub status: ImStatus,
    /// クラスタ固有ステータス(あれば)。
    pub cluster_status: Option<u8>,
    /// 応答 payload(InvokeResponseIB 連結の生 TLV)。
    pub response: Vec<u8>,
}

/// 購読系イベント(埋め込み用、[`Exec::enable_sub_capture`] 有効時に溜まる)。
#[derive(Debug, Clone)]
pub enum SubEvent {
    /// デバイス発の購読レポート 1 件(AttributeReportIB 列)。
    Report {
        /// 購読が乗るセッション。
        session: SessionId,
        /// 購読 ID(デバイス採番。`(session, id)` で一意)。
        subscription_id: u32,
        /// レポート本文。
        items: Vec<ReadItem>,
    },
    /// 購読ロスト(maxInterval + 猶予を超えて途絶。client 側 slot は破棄済み)。
    Lost {
        /// 購読が乗っていたセッション。
        session: SessionId,
        /// 購読 ID。
        subscription_id: u32,
    },
}

/// Subscribe の結果(プライミング完了 = 購読確立)。
#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    /// 購読が乗るセッション。
    pub session: SessionId,
    /// デバイスが採番した購読 ID。
    pub subscription_id: u32,
    /// ネゴシエート済み最大レポート間隔(秒)。
    pub max_interval_s: u16,
    /// プライミングレポート(購読パスの初期値)。
    pub priming: Vec<ReadItem>,
}

/// OpenCommissioningWindow で払い出した窓の情報([`Exec::open_window_data`])。
#[derive(Debug, Clone)]
pub struct WindowInfo {
    /// 窓を開けておく秒数。
    pub timeout_s: u16,
    /// 窓の 12 ビット discriminator。
    pub discriminator: u16,
    /// 払い出した setup passcode。
    pub passcode: u32,
    /// 11 桁 manual pairing code。
    pub manual_code: String,
    /// QR payload(`MT:...`。VID/PID は BasicInformation から best-effort、取れなければ 0)。
    pub qr_payload: String,
    /// QR に載せた VendorID。
    pub vendor_id: u16,
    /// QR に載せた ProductID。
    pub product_id: u16,
}

/// AttributeReportIB 列を所有データへ写す。
fn collect_items<'r, E: core::fmt::Debug>(
    it: impl Iterator<Item = Result<AttributeReportRef<'r>, E>>,
) -> Vec<ReadItem> {
    it.map(|r| match r {
        Ok(AttributeReportRef::Data(d)) => ReadItem {
            endpoint: d.path.endpoint.map(|e| e.0),
            cluster: d.path.cluster.map(|c| c.0),
            attribute: d.path.attribute.map(|a| a.0),
            list_append: d.path.list_append,
            data_version: d.data_version,
            outcome: ReadOutcome::Data(d.data.to_vec()),
        },
        Ok(AttributeReportRef::Status(s)) => ReadItem {
            endpoint: s.path.endpoint.map(|e| e.0),
            cluster: s.path.cluster.map(|c| c.0),
            attribute: s.path.attribute.map(|a| a.0),
            list_append: false,
            data_version: None,
            outcome: ReadOutcome::Status {
                status: s.status.status,
                cluster_status: s.status.cluster_status,
            },
        },
        Err(e) => ReadItem {
            endpoint: None,
            cluster: None,
            attribute: None,
            list_append: false,
            data_version: None,
            outcome: ReadOutcome::Undecodable(format!("{e:?}")),
        },
    })
    .collect()
}

impl<'a> Exec<'a> {
    /// 購読系イベントを表示せずに溜めるモードへ切り替える(以後 CLI 表示はしない)。
    ///
    /// 溜まったイベントは [`Self::take_sub_events`] で取り出す。レポート本文はコアの
    /// 「最新 1 件」slot から到着ごとに所有データへ写すので、取り出しが遅れても失われない。
    pub fn enable_sub_capture(&mut self) {
        if self.sub_capture.is_none() {
            self.sub_capture = Some(Vec::new());
        }
    }

    /// 溜まった購読系イベントを取り出す(到着順)。
    pub fn take_sub_events(&mut self) -> Vec<SubEvent> {
        self.sub_capture
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// `on_sub_event` の捕捉版(`sub_capture` 有効時に呼ばれる)。
    pub(super) fn capture_sub_event(&mut self, ev: ImEvent) {
        let captured = match ev {
            ImEvent::SubscriptionReport {
                session,
                subscription_id,
            } => SubEvent::Report {
                session,
                subscription_id,
                items: collect_items(self.stack.sub_reports()),
            },
            ImEvent::SubscriptionLost {
                session,
                subscription_id,
            } => SubEvent::Lost {
                session,
                subscription_id,
            },
            other => {
                logf!(Level::Warn, "im", "unexpected IM event: {other:?}");
                return;
            }
        };
        if let Some(q) = self.sub_capture.as_mut() {
            q.push(captured);
        }
    }

    /// ノードの確立済み CASE セッション(キャッシュに無ければ `None`)。
    pub fn session_of(&self, node_id: u64) -> Option<SessionId> {
        self.cases
            .iter()
            .find(|(n, _)| *n == node_id)
            .map(|(_, s)| *s)
    }

    /// client 側の購読 `(session, id)` を捨てる(デバイス側の旧購読は次のレポートに
    /// `InvalidSubscription` を返した時点で掃除される)。戻り値 = 実際に消したか。
    pub fn unsubscribe_local(&mut self, session: SessionId, subscription_id: u32) -> bool {
        self.stack.im_remove_subscription(session, subscription_id)
    }

    /// 複数パスの属性 Subscribe(1 本、`keepSubscriptions=false`)。プライミング完了で戻る。
    ///
    /// 以後のレポートは [`Self::enable_sub_capture`] 有効時は [`SubEvent`] として溜まる。
    pub fn subscribe_data(
        &mut self,
        node_id: u64,
        paths: &[AttributePath],
        min_s: u16,
        max_s: u16,
    ) -> Result<SubscribeOutcome, String> {
        let session = self.case_session(node_id)?;
        let now = self.now_ms();
        let dir = self
            .stack
            .start_subscribe(session, paths, min_s, max_s, now, &mut self.tx)
            .map_err(|e| format!("start_subscribe: {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        let out = match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::SubscribeDone {
                session,
                subscription_id,
                max_interval_s,
            }) => SubscribeOutcome {
                session,
                subscription_id,
                max_interval_s,
                priming: collect_items(self.stack.read_reports()),
            },
            Some(ev) => return Err(format!("subscribe failed: {ev:?}")),
            None => {
                return Err(self
                    .op_timeout(node_id, "subscribe")
                    .err()
                    .unwrap_or_else(|| "subscribe timed out".into()))
            }
        };
        self.flush();
        Ok(out)
    }

    /// ノードへの CASE セッションを確立する(キャッシュ済みなら何もしない)。
    ///
    /// 成功時、アドレス帳の `last_addr` と resumption 素材は CLI と同じく更新される。
    pub fn connect(&mut self, node_id: u64) -> Result<(), String> {
        self.case_session(node_id).map(|_| ())
    }

    /// ノードの CASE セッションがプロセス内キャッシュにあるか。
    pub fn is_connected(&self, node_id: u64) -> bool {
        self.cases.iter().any(|(n, _)| *n == node_id)
    }

    /// ノードの CASE セッションキャッシュを捨てる(次の操作で張り直す)。
    pub fn forget_session(&mut self, node_id: u64) {
        self.cases.retain(|(n, _)| *n != node_id);
    }

    /// 待機中の 1 反復: 受信 1 回(最長 50ms)+ poll 排出 + 溜まった IM イベントの排出。
    pub fn idle(&mut self) -> Result<(), String> {
        self.step_io()?;
        self.drain_events();
        Ok(())
    }

    /// 状態ディレクトリ。
    pub fn state_dir(&self) -> &StateDir {
        &self.state
    }

    /// CA(fabric ID / controller node ID の参照用)。
    pub fn ca(&self) -> &Ca<Backend> {
        self.ca
    }

    /// 属性 Read(`attr = None` は属性ワイルドカード)。結果をデータとして返す。
    pub fn read_data(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        attr: Option<AttributeId>,
    ) -> Result<Vec<ReadItem>, String> {
        let path = AttributePath {
            endpoint: Some(EndpointId(ep)),
            cluster: Some(cluster),
            attribute: attr,
            list_index: None,
            list_append: false,
            enable_tag_compression: false,
        };
        self.read_paths(node_id, &[path])
    }

    /// 複数パス(ワイルドカード可)の属性 Read を 1 トランザクションで行う。
    pub fn read_paths(
        &mut self,
        node_id: u64,
        paths: &[AttributePath],
    ) -> Result<Vec<ReadItem>, String> {
        let session = self.case_session(node_id)?;
        let now = self.now_ms();
        let dir = self
            .stack
            .start_read(session, paths, now, &mut self.tx)
            .map_err(|e| format!("start_read: {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::ReadDone) => {}
            Some(ev) => return Err(format!("read failed: {ev:?}")),
            None => {
                return Err(self
                    .op_timeout(node_id, "read")
                    .err()
                    .unwrap_or_else(|| "read timed out".into()))
            }
        }
        let items = collect_items(self.stack.read_reports());
        self.flush();
        Ok(items)
    }

    /// コマンド Invoke。結果をデータとして返す(非成功ステータスも `Ok` で返す)。
    ///
    /// `raw_fields` があればコマンドフィールド全体を生 TLV から転写し(先頭要素の
    /// タグは問わない)、無ければ `fields` から struct を組み立てる。
    #[allow(clippy::too_many_arguments)]
    pub fn invoke_data(
        &mut self,
        node_id: u64,
        ep: u16,
        cluster: ClusterId,
        command: CommandId,
        fields: Vec<(u8, ValueKind, Parsed)>,
        raw_fields: Option<Vec<u8>>,
        timed_ms: Option<u16>,
    ) -> Result<InvokeOutcome, String> {
        let session = self.case_session(node_id)?;
        let path = CommandPath::new(EndpointId(ep), cluster, command);
        let now = self.now_ms();
        let write_fields = move |w: &mut TlvWriter<'_>, t: &TlvTag| match &raw_fields {
            Some(raw) => transcode_tlv(w, t, raw),
            None => {
                w.start_struct(t)?;
                for (tag, kind, v) in &fields {
                    write_value(w, &TlvTag::ContextSpecific(*tag), *kind, v)?;
                }
                w.end_container()
            }
        };
        let dir = match timed_ms {
            Some(ms) => self
                .stack
                .start_invoke_timed(session, ms, path, write_fields, now, &mut self.tx)
                .map_err(|e| format!("start_invoke_timed: {e:?}"))?,
            None => self
                .stack
                .start_invoke(session, path, write_fields, now, &mut self.tx)
                .map_err(|e| format!("start_invoke: {e:?}"))?,
        };
        send_dir(&self.socket, &self.tx, &dir);
        let out = match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::InvokeDone { status }) => InvokeOutcome {
                status,
                cluster_status: self.stack.im_last_cluster_status(),
                response: self.stack.im_result().to_vec(),
            },
            Some(ev) => return Err(format!("invoke failed: {ev:?}")),
            None => {
                return Err(self
                    .op_timeout(node_id, "invoke")
                    .err()
                    .unwrap_or_else(|| "invoke timed out".into()))
            }
        };
        self.flush();
        Ok(out)
    }

    // ------------------------------------------------------------------
    // pairing / 窓 / unpair(W3、CLI 経路の表示を伴わないデータ版)
    // ------------------------------------------------------------------

    /// アドレス直指定の UDP コミッショニング(`pairing address` と同じ内部実装)。
    ///
    /// `label` / `timeout` はこの呼び出しに限って共通オプションを上書きする。成功時は
    /// CLI と同じく CA 状態(発行済み serial)を保存し、アドレス帳に記帳し、確立した
    /// 運用 CASE セッションをキャッシュする。フェーズ遷移は [`super::set_phase_hook`] の
    /// フックへ通知される。
    pub fn pair_addr(
        &mut self,
        node_id: u64,
        passcode: u32,
        addr: SocketAddr,
        label: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let saved_label = self.g.label.replace(label.to_string());
        let saved_timeout = std::mem::replace(&mut self.g.timeout, timeout);
        let r = self.pair(node_id, passcode, &Target::Addr(addr));
        self.g.label = saved_label;
        self.g.timeout = saved_timeout;
        r
    }

    /// ECM 窓オープン(`admincommissioning open-window` のデータ版)。
    ///
    /// passcode 省略時は乱数生成。VID/PID は BasicInformation から best-effort で読む。
    /// 戻り値の [`InvokeOutcome`] が非成功(窓が既に開いている = Failure + cluster
    /// status 2(Busy)等)なら [`WindowInfo`] は無効。
    pub fn open_window_data(
        &mut self,
        node_id: u64,
        timeout_s: u16,
        discriminator: u16,
        passcode: Option<u32>,
    ) -> Result<(InvokeOutcome, WindowInfo), String> {
        use simple_matter::crypto::Rng as _;

        let passcode = match passcode {
            Some(p) if !passcode_is_valid(p) => {
                return Err(format!("invalid setup passcode: {p}"));
            }
            Some(p) => p,
            None => random_passcode(&mut OsRng).map_err(|e| format!("rng: {e:?}"))?,
        };
        let mut salt = [0u8; 16];
        OsRng
            .fill_bytes(&mut salt)
            .map_err(|e| format!("rng: {e:?}"))?;
        let session = self.case_session(node_id)?;
        let vendor_id = self.read_basic_u16(session, 0x0002).unwrap_or(0);
        let product_id = self.read_basic_u16(session, 0x0004).unwrap_or(0);
        let params = OpenWindowParams {
            timeout_s,
            discriminator,
            passcode,
            salt,
            iterations: DEFAULT_WINDOW_ITERATIONS,
        };
        let now = self.now_ms();
        let dir = self
            .stack
            .start_open_commissioning_window(session, &params, now, &mut self.tx)
            .map_err(|e| format!("start_open_commissioning_window: {e:?}"))?;
        let out = self.finish_invoke_data(node_id, dir, "open commissioning window")?;

        let manual = manual_pairing_code(discriminator, passcode);
        let mut qr_buf = [0u8; QR_PAYLOAD_MAX_LEN];
        let qr = qr_payload(
            &OnboardingPayload {
                vendor_id,
                product_id,
                discriminator,
                passcode,
                discovery_caps: DISCOVERY_CAP_ON_NETWORK,
            },
            &mut qr_buf,
        )
        .map(|n| String::from_utf8_lossy(&qr_buf[..n]).into_owned())
        .unwrap_or_default();
        Ok((
            out,
            WindowInfo {
                timeout_s,
                discriminator,
                passcode,
                manual_code: String::from_utf8_lossy(&manual).into_owned(),
                qr_payload: qr,
                vendor_id,
                product_id,
            },
        ))
    }

    /// RevokeCommissioning(`admincommissioning revoke` のデータ版)。
    pub fn revoke_data(&mut self, node_id: u64) -> Result<InvokeOutcome, String> {
        let session = self.case_session(node_id)?;
        let now = self.now_ms();
        let dir = self
            .stack
            .start_revoke_commissioning(session, now, &mut self.tx)
            .map_err(|e| format!("start_revoke_commissioning: {e:?}"))?;
        self.finish_invoke_data(node_id, dir, "revoke commissioning")
    }

    /// 送出済み invoke の応答を待って結果をデータで返す(表示なし)。
    fn finish_invoke_data(
        &mut self,
        node_id: u64,
        dir: simple_matter::stack::SendDirective,
        what: &str,
    ) -> Result<InvokeOutcome, String> {
        send_dir(&self.socket, &self.tx, &dir);
        let out = match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::InvokeDone { status }) => InvokeOutcome {
                status,
                cluster_status: self.stack.im_last_cluster_status(),
                response: self.stack.im_result().to_vec(),
            },
            Some(ev) => return Err(format!("{what} failed: {ev:?}")),
            None => {
                return Err(self
                    .op_timeout(node_id, what)
                    .err()
                    .unwrap_or_else(|| format!("{what} timed out")))
            }
        };
        self.flush();
        Ok(out)
    }

    /// `pairing unpair` のデータ版: 自 fabric を RemoveFabric で削除し、成功したら
    /// ローカル状態(アドレス帳エントリ + resumption 素材)を消す。戻り値 = 削除した
    /// fabric index(デバイス視点)。失敗時はローカル状態を温存する(CLI と同じ)。
    pub fn unpair_data(&mut self, node_id: u64) -> Result<u8, String> {
        let session = self.case_session(node_id)?;
        let fabric_index = self.read_current_fabric_index(node_id, session)?;
        let path = CommandPath::new(EndpointId(0), ClusterId(0x003E), CommandId(0x0A));
        let now = self.now_ms();
        let dir = self
            .stack
            .start_invoke(
                session,
                path,
                move |w: &mut TlvWriter<'_>, t: &TlvTag| {
                    w.start_struct(t)?;
                    w.write_u8(&TlvTag::ContextSpecific(0), fabric_index)?;
                    w.end_container()
                },
                now,
                &mut self.tx,
            )
            .map_err(|e| format!("start_invoke(RemoveFabric): {e:?}"))?;
        send_dir(&self.socket, &self.tx, &dir);
        match self.wait_txn_event(Instant::now() + self.g.timeout)? {
            Some(ImEvent::InvokeDone { status }) => {
                if !status.is_success() {
                    return Err(format!(
                        "RemoveFabric failed: IM status {status:?} (local state kept)"
                    ));
                }
                if let Some(code) = decode_noc_status_code(self.stack.im_result()) {
                    if code != 0 {
                        return Err(format!(
                            "RemoveFabric returned NOCResponse statusCode={code} \
                             (0=Ok; local state kept)"
                        ));
                    }
                }
            }
            Some(ev) => return Err(format!("RemoveFabric failed: {ev:?} (local state kept)")),
            None => {
                return Err(self
                    .op_timeout(node_id, "unpair (RemoveFabric)")
                    .err()
                    .unwrap_or_else(|| "unpair timed out".into()))
            }
        }
        self.cases.retain(|(n, _)| *n != node_id);
        self.forget_local_node(node_id)?;
        Ok(fabric_index)
    }

    /// ローカル状態だけを消す(アドレス帳エントリ + resumption 素材 + CASE キャッシュ)。
    /// デバイスに到達できないノードを手元から外すとき(`smweb` の force unpair)に使う。
    /// 戻り値 = アドレス帳にエントリがあったか。
    pub fn forget_local_node(&mut self, node_id: u64) -> Result<bool, String> {
        self.cases.retain(|(n, _)| *n != node_id);
        let _lock = self.state.lock()?;
        let removed = nodes::remove(&self.state.nodes_path(), node_id)?;
        resume::remove(&self.state.resume_path(node_id))?;
        Ok(removed)
    }
}
