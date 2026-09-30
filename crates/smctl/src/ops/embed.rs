//! 埋め込み用 API: 結果を stdout へ表示せず**データとして返す** [`Exec`] の操作群
//! (`docs/design/web-controller.md` §3 / §4、`smweb` のコントローラスレッドが使う)。
//!
//! CLI 経路([`Exec::run`])の挙動・出力には一切関与しない(追加のみ)。CASE 取得
//! (キャッシュ → キャッシュアドレス → mDNS 再解決 → resumption 保存)、トランザクション
//! 待ち、静穏化はすべて CLI と同じ内部実装を共有する。

use std::time::Instant;

use simple_matter::controller::ca::Ca;
use simple_matter::dm::meta::{AttributeId, ClusterId, CommandId, EndpointId};
use simple_matter::im::wire::{AttributePath, AttributeReportRef, CommandPath, ImStatus};
use simple_matter::im::ImEvent;
use simple_matter::tlv::{TlvTag, TlvWriter};
use simple_matter::transport::session::SessionId;

use super::{transcode_tlv, write_value, Exec, Parsed};
use crate::clusters::ValueKind;
use crate::log::{logf, Level};
use crate::runner::udp::send_dir;
use crate::runner::Backend;
use crate::state::StateDir;

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
}
