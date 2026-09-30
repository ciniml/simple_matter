//! WebSocket `/ws`(設計 doc §6): 接続直後に `{"type":"snapshot", ...}` を 1 回送り、
//! 以後 broadcast された [`Event`](crate::model::Event) を JSON で流す。

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::ctrl::CtrlHandle;

pub async fn handler(ws: WebSocketUpgrade, State(h): State<CtrlHandle>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| session(socket, h))
}

async fn session(mut socket: WebSocket, h: CtrlHandle) {
    // 取りこぼし防止のため、スナップショットを取る前に購読しておく。
    let mut rx = h.events.subscribe();
    let snap = h.snapshot();
    let first = json!({ "type": "snapshot", "info": snap.info, "nodes": snap.nodes });
    if socket.send(Message::Text(first.to_string())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            ev = rx.recv() => {
                let text = match ev {
                    Ok(e) => match serde_json::to_string(&e) {
                        Ok(t) => t,
                        Err(_) => continue,
                    },
                    Err(RecvError::Lagged(n)) => json!({ "type": "lagged", "missed": n }).to_string(),
                    Err(RecvError::Closed) => break,
                };
                if socket.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => match msg {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {} // クライアント発メッセージは W1 では無視(ping は axum が応答)。
            },
        }
    }
}
