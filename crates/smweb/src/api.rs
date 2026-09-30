//! REST ハンドラ(設計 doc §6 の W1 部分集合)と同梱 UI の配信。

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::ctrl::{Command, CtrlHandle};
use crate::error::ApiError;
use crate::value::{
    args_to_fields, clusters_json, from_hex, parse_endpoint, parse_id, resolve_attr,
    resolve_cluster, resolve_cmd,
};

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

/// ルータを組み立てる。
pub fn router(h: CtrlHandle) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        .route("/api/info", get(info))
        .route("/api/nodes", get(list_nodes))
        .route("/api/nodes/:id", get(get_node))
        .route("/api/nodes/:id/connect", post(connect))
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

async fn not_found() -> ApiError {
    ApiError::not_found("no such endpoint")
}

async fn info(State(h): State<CtrlHandle>) -> ApiResult {
    Ok(Json(json!(h.snapshot().info)))
}

async fn list_nodes(State(h): State<CtrlHandle>) -> ApiResult {
    Ok(Json(json!(h.snapshot().nodes)))
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

async fn clusters() -> ApiResult {
    Ok(Json(clusters_json()))
}
