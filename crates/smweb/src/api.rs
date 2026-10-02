//! REST ハンドラ(設計 doc §6)と同梱 UI の配信。
//!
//! W3: `POST /api/pairing`(即 `{op_id}` を返し、進捗は WS の `progress`)、
//! `DELETE/PATCH /api/nodes/{id}`(unpair / ラベル)、`/api/nodes/{id}/window`(Share)、
//! `GET /api/discover/commissionable`。mDNS ブラウズは ControllerStack を使わないので
//! コントローラスレッドを塞がないよう `spawn_blocking` で行う。
//!
//! W5: `GET /api/nodes/{id}/history`(系列一覧 / `?ep=&cluster=&attr=&since=&limit=` の点列、
//! §9.2)。履歴は共有の `RwLock<History>` を読むだけでコントローラを待たない。

use std::collections::HashMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use smctl::runner::mdns::{self, CommissionableInfo};

use crate::model::AttrPath;
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::ctrl::{Command, CtrlHandle, PairJob, PairTarget};
use crate::error::{ApiError, ErrorCode};
use crate::model::Event;
use crate::onboarding::Disc;
use crate::pairing::{check_label, parse_pair_request, parse_window_request, PairMethod};
use crate::value::{
    args_to_fields, clusters_json, from_hex, parse_endpoint, parse_id, resolve_attr,
    resolve_cluster, resolve_cmd,
};
use smctl::log::Level;

type ApiResult = Result<Json<Value>, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.to_json())).into_response()
    }
}

const INDEX_HTML: &str = include_str!("static/index.html");
const APP_JS: &str = include_str!("static/app.js");
const APP_CSS: &str = include_str!("static/app.css");
const QRCODE_JS: &str = include_str!("static/qrcode.js");
const CHART_JS: &str = include_str!("static/chart.js");

/// pairing の HTTP 側待ち時間(BLE-WiFi は scan + BLE 90 s + join 待ち 120 s + UDP 30 s)。
const PAIR_WAIT: Duration = Duration::from_secs(600);
/// on-network pairing の commissionable ブラウズ窓(デバイスの再 announce 30 s を拾える長さ)。
const PAIR_BROWSE_TIMEOUT: Duration = Duration::from_secs(35);
/// `GET /api/discover/commissionable` の既定スキャン秒数。
const DISCOVER_DEFAULT_S: u64 = 5;

/// ルータを組み立てる。
pub fn router(h: CtrlHandle) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/info", get(info))
        .route("/api/nodes", get(list_nodes))
        .route("/qrcode.js", get(qrcode_js))
        .route("/chart.js", get(chart_js))
        .route(
            "/api/nodes/:id",
            get(get_node).delete(unpair).patch(patch_node),
        )
        .route(
            "/api/nodes/:id/window",
            get(window_status).post(open_window).delete(revoke_window),
        )
        .route("/api/pairing", post(pairing))
        .route("/api/discover/commissionable", get(discover_commissionable))
        .route("/api/nodes/:id/connect", post(connect))
        .route("/api/nodes/:id/describe", post(describe))
        .route("/api/nodes/:id/watch", post(watch_add).delete(watch_remove))
        .route("/api/nodes/:id/history", get(history))
        .route(
            "/api/nodes/:id/attr/:ep/:cluster/:attr",
            get(read_attr).put(write_attr),
        )
        .route("/api/nodes/:id/invoke/:ep/:cluster/:cmd", post(invoke))
        .route("/api/clusters", get(clusters))
        .route("/ws", get(crate::ws::handler))
        .fallback(not_found)
        .with_state(h)
}

async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn app_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn qrcode_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        QRCODE_JS,
    )
}

async fn chart_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        CHART_JS,
    )
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such endpoint")
}

async fn info(State(h): State<CtrlHandle>) -> ApiResult {
    Ok(Json(json!(h.snapshot().info)))
}

async fn list_nodes(State(h): State<CtrlHandle>) -> ApiResult {
    Ok(Json(Value::Array(
        h.snapshot().nodes.iter().map(|n| n.summary()).collect(),
    )))
}

async fn get_node(State(h): State<CtrlHandle>, Path(id): Path<String>) -> ApiResult {
    let node_id = parse_id(&id)?;
    let snap = h.snapshot();
    let n = snap.node(node_id).ok_or_else(|| {
        ApiError::not_found(format!("node {node_id:#x} is not in the address book"))
    })?;
    Ok(Json(json!(n)))
}

async fn connect(State(h): State<CtrlHandle>, Path(id): Path<String>) -> ApiResult {
    let node_id = parse_id(&id)?;
    h.call(Command::Connect { node_id }).await.map(Json)
}

async fn describe(State(h): State<CtrlHandle>, Path(id): Path<String>) -> ApiResult {
    let node_id = parse_id(&id)?;
    h.call(Command::Describe { node_id }).await.map(Json)
}

/// ID(数値 or 10 進 / `0x` 文字列 or クラスタ表の名前)の JSON 値を文字列にする。
fn id_text(v: Option<&Value>, what: &str) -> Result<String, ApiError> {
    match v {
        Some(Value::Number(n)) => Ok(n.to_string()),
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(ApiError::bad_request(format!(
            "path.{what} must be a number or string"
        ))),
    }
}

/// `{ "paths": [ {ep, cluster, attr} ] }` をパースする。
pub fn parse_watch_body(body: &Value) -> Result<Vec<AttrPath>, ApiError> {
    let list = body
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::bad_request("body must be {\"paths\": [{ep, cluster, attr}]}"))?;
    let mut out = Vec::new();
    for p in list {
        let ep = parse_endpoint(&id_text(p.get("ep").or_else(|| p.get("endpoint")), "ep")?)?;
        let (cluster, def) = resolve_cluster(&id_text(p.get("cluster"), "cluster")?)?;
        let attr = resolve_attr(
            def,
            &id_text(p.get("attr").or_else(|| p.get("attribute")), "attr")?,
        )?;
        out.push(AttrPath::new(ep, cluster.0, attr.0));
    }
    if out.is_empty() {
        return Err(ApiError::bad_request("`paths` is empty"));
    }
    Ok(out)
}

async fn watch_add(State(h): State<CtrlHandle>, Path(id): Path<String>, body: Bytes) -> ApiResult {
    watch(h, id, body, true).await
}

async fn watch_remove(
    State(h): State<CtrlHandle>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    watch(h, id, body, false).await
}

async fn watch(h: CtrlHandle, id: String, body: Bytes, add: bool) -> ApiResult {
    let node_id = parse_id(&id)?;
    let paths = parse_watch_body(&parse_body(&body)?)?;
    h.call(Command::Watch {
        node_id,
        paths,
        add,
    })
    .await
    .map(Json)
}

/// `?raw=1` / `?raw=true` を真とみなす。
fn flag(q: &HashMap<String, String>, k: &str) -> bool {
    matches!(
        q.get(k).map(String::as_str),
        Some("1" | "true" | "yes" | "")
    )
}

async fn read_attr(
    State(h): State<CtrlHandle>,
    Path((id, ep, cluster, attr)): Path<(String, String, String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    let ep = parse_endpoint(&ep)?;
    let (cluster, def) = resolve_cluster(&cluster)?;
    let attr = resolve_attr(def, &attr)?;
    h.call(Command::Read {
        node_id,
        ep,
        cluster,
        attr,
        raw: flag(&q, "raw"),
    })
    .await
    .map(Json)
}

/// 空ボディは `null`、それ以外は JSON。
fn parse_body(body: &Bytes) -> Result<Value, ApiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))
}

async fn write_attr(
    State(h): State<CtrlHandle>,
    Path((id, ep, cluster, attr)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    let ep = parse_endpoint(&ep)?;
    let (cluster, def) = resolve_cluster(&cluster)?;
    let attr = resolve_attr(def, &attr)?;
    let value = parse_body(&body)?;
    h.call(Command::Write {
        node_id,
        ep,
        cluster,
        attr,
        value,
    })
    .await
    .map(Json)
}

async fn invoke(
    State(h): State<CtrlHandle>,
    Path((id, ep, cluster, cmd)): Path<(String, String, String, String)>,
    body: Bytes,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    let ep = parse_endpoint(&ep)?;
    let (cluster, def) = resolve_cluster(&cluster)?;
    let (cmd, cmd_def) = resolve_cmd(def, &cmd)?;
    let body = parse_body(&body)?;
    if !(body.is_null() || body.is_object()) {
        return Err(ApiError::bad_request("request body must be a JSON object"));
    }
    let tlv = match body.get("tlv").or_else(|| body.get("tlv_hex")) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.trim().is_empty() => None,
        Some(Value::String(s)) => Some(from_hex(s)?),
        Some(_) => return Err(ApiError::bad_request("`tlv` must be a hex string")),
    };
    let args = body.get("args");
    let fields = if tlv.is_some() {
        if args.is_some_and(|a| !(a.is_null() || a.as_object().is_some_and(|o| o.is_empty()))) {
            return Err(ApiError::bad_request(
                "give either `args` or `tlv`, not both",
            ));
        }
        Vec::new()
    } else {
        args_to_fields(cmd_def, args)?
    };
    let timed_ms = match body.get("timed_ms") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|&ms| (1..=u16::MAX as u64).contains(&ms))
                .ok_or_else(|| ApiError::bad_request("`timed_ms` must be 1..=65535"))?
                as u16,
        ),
    };
    h.call(Command::Invoke {
        node_id,
        ep,
        cluster,
        cmd,
        fields,
        tlv,
        timed_ms,
    })
    .await
    .map(Json)
}

/// `/history` のクエリ: 系列の指定(全部無し = 一覧)と `since` / `limit`。
#[derive(Debug, PartialEq)]
pub enum HistoryQuery {
    List,
    Series {
        path: AttrPath,
        since: u64,
        limit: usize,
    },
}

/// `?ep=&cluster=&attr=&since=&limit=` をパースする(cluster / attr は表の名前も可)。
pub fn parse_history_query(
    q: &HashMap<String, String>,
    default_limit: usize,
) -> Result<HistoryQuery, ApiError> {
    let get = |k: &str| q.get(k).map(|s| s.trim()).filter(|s| !s.is_empty());
    let (ep, cluster, attr) = (get("ep"), get("cluster"), get("attr"));
    if ep.is_none() && cluster.is_none() && attr.is_none() {
        return Ok(HistoryQuery::List);
    }
    let (Some(ep), Some(cluster), Some(attr)) = (ep, cluster, attr) else {
        return Err(ApiError::bad_request(
            "give all of ep, cluster and attr (or none to list the series)",
        ));
    };
    let ep = parse_endpoint(ep)?;
    let (cluster, def) = resolve_cluster(cluster)?;
    let attr = resolve_attr(def, attr)?;
    let since = match get("since") {
        None => 0,
        Some(s) => s
            .parse::<u64>()
            .map_err(|_| ApiError::bad_request("since must be unix milliseconds"))?,
    };
    let limit = match get("limit") {
        None => default_limit,
        Some(s) => s
            .parse::<usize>()
            .ok()
            .filter(|n| *n >= 1)
            .ok_or_else(|| ApiError::bad_request("limit must be a positive integer"))?,
    };
    Ok(HistoryQuery::Series {
        path: AttrPath::new(ep, cluster.0, attr.0),
        since,
        limit,
    })
}

/// `GET /api/nodes/{id}/history[?ep=&cluster=&attr=&since=&limit=]`(§9.2)。
/// 履歴を読むだけ(コントローラを待たない)。
async fn history(
    State(h): State<CtrlHandle>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    if h.snapshot
        .read()
        .map(|s| s.node(node_id).is_none())
        .unwrap_or(false)
    {
        return Err(ApiError::not_found(format!(
            "node {node_id:#x} is not in the address book"
        )));
    }
    let q = parse_history_query(&q, crate::history::DEFAULT_POINTS)?;
    Ok(Json(h.with_history(|hist| match q {
        HistoryQuery::List => crate::history::list_json(hist, node_id),
        HistoryQuery::Series { path, since, limit } => {
            crate::history::query_json(hist, node_id, path, since, limit)
        }
    })))
}

async fn clusters() -> ApiResult {
    Ok(Json(clusters_json()))
}

// ---------------------------------------------------------------------------
// W3: unpair / label / Share / pairing / discover
// ---------------------------------------------------------------------------

/// `DELETE /api/nodes/{id}[?force=1]`: RemoveFabric + ローカル状態削除。`force` は
/// デバイスへ触らずにローカル状態(nodes.tlv / resume / smweb.json)だけを消す。
async fn unpair(
    State(h): State<CtrlHandle>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    h.call(Command::Unpair {
        node_id,
        force: flag(&q, "force"),
    })
    .await
    .map(Json)
}

/// `PATCH /api/nodes/{id}` `{label}`。
pub fn parse_label_body(body: &Value) -> Result<String, ApiError> {
    match body.get("label") {
        Some(Value::String(s)) => check_label(s),
        Some(Value::Null) => Ok(String::new()),
        _ => Err(ApiError::bad_request("body must be {\"label\": \"...\"}")),
    }
}

async fn patch_node(State(h): State<CtrlHandle>, Path(id): Path<String>, body: Bytes) -> ApiResult {
    let node_id = parse_id(&id)?;
    let label = parse_label_body(&parse_body(&body)?)?;
    h.call(Command::SetLabel { node_id, label }).await.map(Json)
}

async fn window_status(State(h): State<CtrlHandle>, Path(id): Path<String>) -> ApiResult {
    let node_id = parse_id(&id)?;
    h.call(Command::WindowStatus { node_id }).await.map(Json)
}

async fn open_window(
    State(h): State<CtrlHandle>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult {
    let node_id = parse_id(&id)?;
    let (timeout_s, discriminator, passcode) = parse_window_request(&parse_body(&body)?)?;
    h.call(Command::OpenWindow {
        node_id,
        timeout_s,
        discriminator,
        passcode,
    })
    .await
    .map(Json)
}

async fn revoke_window(State(h): State<CtrlHandle>, Path(id): Path<String>) -> ApiResult {
    let node_id = parse_id(&id)?;
    h.call(Command::Revoke { node_id }).await.map(Json)
}

/// commissionable ノード 1 件の JSON。
fn commissionable_json(c: &CommissionableInfo) -> Value {
    json!({
        "instance": c.instance,
        "discriminator": c.discriminator,
        "vendor_id": c.vendor_product.map(|v| v.0),
        "product_id": c.vendor_product.map(|v| v.1),
        "commissioning_mode": c.commissioning_mode,
        "port": c.port,
        "addrs": c.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
    })
}

/// `GET /api/discover/commissionable[?timeout=5][&discriminator=N]`。
async fn discover_commissionable(Query(q): Query<HashMap<String, String>>) -> ApiResult {
    let secs = match q.get("timeout").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => DISCOVER_DEFAULT_S,
        Some(s) => s
            .parse::<u64>()
            .ok()
            .filter(|t| (1..=60).contains(t))
            .ok_or_else(|| ApiError::bad_request("timeout must be 1..=60 seconds"))?,
    };
    let disc = match q
        .get("discriminator")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        None => None,
        Some(s) => Some(
            parse_id(s)
                .ok()
                .filter(|d| *d <= 0x0FFF)
                .ok_or_else(|| ApiError::bad_request("discriminator must be 0..=4095"))?
                as u16,
        ),
    };
    let list = tokio::task::spawn_blocking(move || {
        mdns::browse_commissionable_nodes(disc, Duration::from_secs(secs), |_| false)
    })
    .await
    .map_err(|e| ApiError::new(ErrorCode::Internal, format!("discover task: {e}")))?
    .map_err(|e| ApiError::new(ErrorCode::Internal, e))?;
    Ok(Json(json!({
        "timeout_s": secs,
        "nodes": list.iter().map(commissionable_json).collect::<Vec<_>>(),
    })))
}

/// `POST /api/pairing`: 検証してすぐ `{op_id}` を返す。進捗は WS の `progress`。
async fn pairing(State(h): State<CtrlHandle>, body: Bytes) -> ApiResult {
    let req = parse_pair_request(&parse_body(&body)?, cfg!(feature = "ble"))?;
    if let Some(id) = req.node_id {
        if h.snapshot().node(id).is_some() {
            return Err(ApiError::bad_request(format!(
                "node id {id} ({id:#x}) is already in the address book"
            )));
        }
    }
    let op_id = h.next_op_id();
    let resp = json!({
        "op_id": op_id,
        "method": req.method.name(),
        "node_id": req.node_id,
        "code": req.code,
    });
    tokio::spawn(run_pairing(h, op_id, req));
    Ok(Json(resp))
}

/// on-network pairing の commissionable 探索(ブロッキング)。
fn find_commissionable(disc: Option<Disc>) -> Result<CommissionableInfo, String> {
    let want = |c: &CommissionableInfo| {
        !c.addrs.is_empty()
            && match disc {
                None => true,
                Some(d) => c.discriminator.is_some_and(|x| d.matches(x)),
            }
    };
    let found =
        mdns::browse_commissionable_nodes(disc.and_then(Disc::long), PAIR_BROWSE_TIMEOUT, |c| {
            want(c)
        })?;
    found.into_iter().find(|c| want(c)).ok_or_else(|| {
        format!(
            "no commissionable device{} found within {}s (is the device in commissioning mode?)",
            match disc {
                Some(Disc::Long(d)) => format!(" with discriminator {d}"),
                Some(Disc::Short(s)) => format!(" with short discriminator {s}"),
                None => String::new(),
            },
            PAIR_BROWSE_TIMEOUT.as_secs()
        )
    })
}

/// pairing の非同期本体: (on-network なら)探索 → Command::Pair → 終端イベント。
async fn run_pairing(h: CtrlHandle, op_id: u64, req: crate::pairing::PairRequest) {
    let fail = |h: &CtrlHandle, msg: String, node_id: Option<u64>| {
        wlog!(Level::Warn, "pairing op {op_id} failed: {msg}");
        h.emit(Event::Progress {
            op_id,
            phase: "failed".into(),
            detail: msg.clone(),
            node_id,
            error: Some(msg),
            result: None,
            ts: crate::model::unix_now_ms(),
        });
    };
    wlog!(
        Level::Info,
        "pairing op {op_id}: {} requested",
        req.method.name()
    );
    h.emit(Event::progress(
        op_id,
        "queued",
        format!("pairing ({})", req.method.name()),
        req.node_id,
    ));
    let target = match req.method {
        PairMethod::OnNetwork { disc } => {
            h.emit(Event::progress(
                op_id,
                "discover",
                match disc {
                    Some(Disc::Long(d)) => {
                        format!("browsing _matterc._udp for discriminator {d}...")
                    }
                    Some(Disc::Short(s)) => {
                        format!("browsing _matterc._udp for short discriminator {s}...")
                    }
                    None => "browsing _matterc._udp for any commissionable device...".into(),
                },
                req.node_id,
            ));
            match tokio::task::spawn_blocking(move || find_commissionable(disc)).await {
                Ok(Ok(c)) => {
                    let addr = c.preferred_addr().expect("filtered on non-empty addrs");
                    wlog!(
                        Level::Info,
                        "pairing op {op_id}: found commissionable {} at {addr}",
                        c.instance
                    );
                    h.emit(Event::progress(
                        op_id,
                        "found",
                        format!(
                            "{} at {addr} (discriminator {}{})",
                            c.instance,
                            c.discriminator
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "?".into()),
                            c.vendor_product
                                .map(|(v, p)| format!(", vid/pid {v:#06x}/{p:#06x}"))
                                .unwrap_or_default()
                        ),
                        req.node_id,
                    ));
                    PairTarget::Udp(addr)
                }
                Ok(Err(e)) => return fail(&h, e, req.node_id),
                Err(e) => return fail(&h, format!("discover task: {e}"), req.node_id),
            }
        }
        PairMethod::Address { addr } => PairTarget::Udp(addr),
        PairMethod::BleWifi {
            disc,
            ssid,
            password,
        } => PairTarget::Ble {
            discriminator: ble_disc(&h, op_id, disc, req.node_id),
            wifi: Some((ssid, password)),
            thread: None,
        },
        PairMethod::BleThread { disc, dataset } => PairTarget::Ble {
            discriminator: ble_disc(&h, op_id, disc, req.node_id),
            wifi: None,
            thread: Some(dataset),
        },
    };
    let job = PairJob {
        node_id: req.node_id,
        label: req.label,
        passcode: req.passcode,
        target,
    };
    match h.call_with(Command::Pair { op_id, job }, PAIR_WAIT).await {
        Ok(v) => {
            let node_id = v["node_id"].as_u64();
            wlog!(Level::Info, "pairing op {op_id}: done ({v})");
            let detail = match v["warning"].as_str() {
                Some(w) => w.to_string(),
                None => format!(
                    "node {} commissioned and online",
                    node_id.map(|n| n.to_string()).unwrap_or_default()
                ),
            };
            h.emit(Event::Progress {
                op_id,
                phase: "done".into(),
                detail,
                node_id,
                error: None,
                result: Some(v),
                ts: crate::model::unix_now_ms(),
            });
        }
        Err(e) => fail(&h, e.message, req.node_id),
    }
}

/// BLE スキャンの discriminator(long のみ。manual code の short は照合できないので任意)。
fn ble_disc(h: &CtrlHandle, op_id: u64, disc: Option<Disc>, node_id: Option<u64>) -> Option<u16> {
    match disc {
        Some(Disc::Long(d)) => Some(d),
        Some(Disc::Short(s)) => {
            h.emit(Event::progress(
                op_id,
                "note",
                format!(
                    "manual code carries only the short discriminator ({s}); the BLE scan \
                     accepts the first commissionable device"
                ),
                node_id,
            ));
            None
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_body_parsing() {
        assert_eq!(
            parse_label_body(&json!({"label": " Kitchen "})).unwrap(),
            "Kitchen"
        );
        assert_eq!(parse_label_body(&json!({"label": null})).unwrap(), "");
        assert!(parse_label_body(&json!({})).is_err());
        assert!(parse_label_body(&json!({"label": 3})).is_err());
        assert!(parse_label_body(&json!({"label": "x".repeat(65)})).is_err());
    }

    #[test]
    fn commissionable_entry_json() {
        let c = CommissionableInfo {
            instance: "ABCDEF0123456789".into(),
            discriminator: Some(3840),
            vendor_product: Some((0xFFF1, 0x8001)),
            commissioning_mode: Some(2),
            port: 5540,
            addrs: vec!["192.168.8.163:5540".parse().unwrap()],
        };
        let v = commissionable_json(&c);
        assert_eq!(v["discriminator"], 3840);
        assert_eq!(v["vendor_id"], 0xFFF1);
        assert_eq!(v["product_id"], 0x8001);
        assert_eq!(v["addrs"][0], "192.168.8.163:5540");
        assert_eq!(v["commissioning_mode"], 2);
    }

    #[test]
    fn history_query_parsing() {
        let q = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(
            parse_history_query(&q(&[]), 2880).unwrap(),
            HistoryQuery::List
        );
        assert_eq!(
            parse_history_query(&q(&[("since", "5")]), 2880).unwrap(),
            HistoryQuery::List
        );
        assert_eq!(
            parse_history_query(
                &q(&[("ep", "1"), ("cluster", "0x040D"), ("attr", "0")]),
                2880
            )
            .unwrap(),
            HistoryQuery::Series {
                path: AttrPath::new(1, 0x040D, 0),
                since: 0,
                limit: 2880
            }
        );
        assert_eq!(
            parse_history_query(
                &q(&[
                    ("ep", "2"),
                    ("cluster", "temperature-measurement"),
                    ("attr", "measured-value"),
                    ("since", "1700000000000"),
                    ("limit", "10"),
                ]),
                2880
            )
            .unwrap(),
            HistoryQuery::Series {
                path: AttrPath::new(2, 0x0402, 0),
                since: 1_700_000_000_000,
                limit: 10
            }
        );
        assert!(parse_history_query(&q(&[("ep", "1"), ("cluster", "6")]), 2880).is_err());
        let base = [("ep", "1"), ("cluster", "6"), ("attr", "0")];
        let with = |k: &'static str, v: &'static str| {
            let mut m = q(&base);
            m.insert(k.into(), v.into());
            m
        };
        assert!(parse_history_query(&with("limit", "0"), 2880).is_err());
        assert!(parse_history_query(&with("limit", "x"), 2880).is_err());
        assert!(parse_history_query(&with("since", "-1"), 2880).is_err());
    }

    #[test]
    fn watch_body_parsing() {
        let v = json!({"paths": [
            {"ep": 1, "cluster": 91, "attr": 0},
            {"ep": "0x2", "cluster": "temperature-measurement", "attr": "measured-value"},
            {"endpoint": 0, "cluster": "0x0028", "attribute": "0x5"},
        ]});
        let p = parse_watch_body(&v).unwrap();
        assert_eq!(
            p,
            vec![
                AttrPath::new(1, 0x5B, 0),
                AttrPath::new(2, 0x0402, 0),
                AttrPath::new(0, 0x0028, 5),
            ]
        );
        assert!(parse_watch_body(&json!({})).is_err());
        assert!(parse_watch_body(&json!({"paths": []})).is_err());
        assert!(parse_watch_body(&json!({"paths": [{"ep": 1, "cluster": 6}]})).is_err());
        assert!(
            parse_watch_body(&json!({"paths": [{"ep": 70000, "cluster": 6, "attr": 0}]})).is_err()
        );
    }
}
