//! Sui GraphQL Subscriptions 事件订阅
//!
//! 通过 WebSocket 连接 Sui GraphQL RPC 端点，使用 `graphql-ws` 子协议订阅链上事件。
//! 相比 gRPC SubscribeCheckpoints，GraphQL Subscriptions 在公共端点（如 MystenLabs 官方
//! `wss://sui-{network}.mystenlabs.com/graphql`）上直接可用，无需付费节点。
//!
//! 协议参考：https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md
//! Sui GraphQL Subscriptions 文档：https://docs.sui.io/develop/accessing-data/graphql/graphql-rpc

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::Message;

use crate::config::Config;
use crate::handlers::AppState;
use crate::sui_events::{parse_chain_event, SuiChainEvent};

/// GraphQL WebSocket 子协议标识符
const GRAPHQL_WS_PROTOCOL: &str = "graphql-transport-ws";

/// 根据 sui_network 配置返回对应的 GraphQL WebSocket URL
fn graphql_ws_url(config: &Config) -> Result<String, String> {
    // 优先使用环境变量 SUI_GRAPHQL_WS_URL 覆盖
    if let Ok(url) = std::env::var("SUI_GRAPHQL_WS_URL") {
        if !url.is_empty() {
            return Ok(url);
        }
    }
    match config.sui_network.as_str() {
        "mainnet" => Ok("wss://public-rpc.sui-mainnet.mystenlabs.com/graphql".to_string()),
        "testnet" => Ok("wss://public-rpc.sui-testnet.mystenlabs.com/graphql".to_string()),
        "devnet" => Ok("wss://public-rpc.sui-devnet.mystenlabs.com/graphql".to_string()),
        other => Err(format!("Unknown sui_network: {}", other)),
    }
}

// ============================================================
// graphql-ws 协议消息
// ============================================================

/// 客户端 -> 服务端消息
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// 连接初始化握手
    ConnectionInit { payload: Option<Value> },
    /// 启动订阅
    Subscribe {
        id: String,
        payload: SubscribePayload,
    },
    /// 取消订阅
    Complete { id: String },
    /// 心跳响应
    Pong,
}

/// Subscribe 消息的 payload（GraphQL 请求体）
#[derive(Serialize)]
struct SubscribePayload {
    query: String,
    variables: Value,
}

/// 服务端 -> 客户端消息
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    /// 连接确认
    ConnectionAck,
    /// 心跳请求
    Ping,
    /// 心跳响应
    Pong,
    /// 订阅推送数据
    Next { id: String, payload: NextPayload },
    /// 订阅错误
    Error { id: String, payload: Value },
    /// 订阅完成
    Complete { id: String },
}

/// `Next` 消息的 payload（GraphQL 返回数据）
#[derive(Deserialize, Debug)]
struct NextPayload {
    data: Value,
}

// ============================================================
// 订阅主循环
// ============================================================

/// 订阅事件流，断线自动重连
pub async fn subscribe_with_reconnect(config: Config, state: Arc<AppState>) {
    let mut retry_delay = std::time::Duration::from_secs(1);
    let max_retry_delay = std::time::Duration::from_secs(60);

    loop {
        match subscribe_once(&config, state.clone()).await {
            Ok(()) => {
                tracing::warn!(
                    "[sui_graphql_sub] subscription stream ended normally, reconnecting..."
                );
                retry_delay = std::time::Duration::from_secs(1);
            }
            Err(e) => {
                tracing::error!(
                    "[sui_graphql_sub] subscription error: {}, reconnecting in {:?}",
                    e,
                    retry_delay
                );
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_retry_delay);
    }
}

/// 执行一次订阅，直到连接断开或发生错误
async fn subscribe_once(config: &Config, state: Arc<AppState>) -> Result<(), String> {
    let ws_url = graphql_ws_url(config)?;
    let origin_package_id = &config.sui_origin_package_id;
    if origin_package_id.is_empty() {
        return Err("SUI_ORIGIN_PACKAGE_ID not configured".to_string());
    }

    tracing::info!("[sui_graphql_sub] connecting to {}", ws_url);

    // 构造 WebSocket 握手请求，带 graphql-transport-ws 子协议
    let request = Request::builder()
        .method("GET")
        .uri(&ws_url)
        .header("Host", host_header(&ws_url)?)
        .header("Upgrade", "websocket")
        .header("Connection", "upgrade")
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", GRAPHQL_WS_PROTOCOL)
        .header("Origin", &ws_url)
        .header("User-Agent", "texas-sui-graphql-sub/0.1")
        .header("Content-Length", "0")
        .body(())
        .map_err(|e| format!("Failed to build WS request: {}", e))?;

    // 建立 WebSocket 连接（使用 native-tls 处理 wss://）
    let (mut ws_stream, response) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, None)
            .await
            .map_err(|e| format!("WebSocket connect failed: {}", e))?;

    // 校验子协议协商结果
    let negotiated = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !negotiated.contains(GRAPHQL_WS_PROTOCOL) {
        tracing::warn!(
            "[sui_graphql_sub] server did not negotiate graphql-transport-ws protocol (got '{}'), continuing anyway",
            negotiated
        );
    }

    tracing::info!(
        "[sui_graphql_sub] WebSocket connected, negotiating graphql-ws handshake"
    );

    // 1. 发送 ConnectionInit
    let init_msg = serde_json::to_string(&ClientMessage::ConnectionInit { payload: None })
        .map_err(|e| format!("Failed to serialize ConnectionInit: {}", e))?;
    ws_stream
        .send(Message::Text(init_msg.into()))
        .await
        .map_err(|e| format!("Failed to send ConnectionInit: {}", e))?;

    // 2. 等待 ConnectionAck
    let acked = wait_for_ack(&mut ws_stream).await?;
    if !acked {
        return Err("Did not receive ConnectionAck from server".to_string());
    }
    tracing::info!("[sui_graphql_sub] handshake acknowledged, subscribing to events");

    // 3. 发送 Subscribe 请求
    // 使用 emittingPackage 过滤目标 package 的事件
    // 字段对齐 Sui GraphQL schema：events { type { repr } json timestamp transactionBlock { digest } }
    let subscription_query = r#"
        subscription SubscribeToPackageEvents($package: SuiAddress!) {
            events(filter: { emittingPackage: $package }) {
                type { repr }
                json
                timestamp
                transactionBlock { digest }
            }
        }
    "#;
    let variables = serde_json::json!({
        "package": origin_package_id,
    });
    let sub_payload = SubscribePayload {
        query: subscription_query.to_string(),
        variables,
    };
    let sub_msg = serde_json::to_string(&ClientMessage::Subscribe {
        id: "sui-events-1".to_string(),
        payload: sub_payload,
    })
    .map_err(|e| format!("Failed to serialize Subscribe: {}", e))?;
    ws_stream
        .send(Message::Text(sub_msg.into()))
        .await
        .map_err(|e| format!("Failed to send Subscribe: {}", e))?;

    tracing::info!(
        "[sui_graphql_sub] subscription request sent for package {}",
        origin_package_id
    );

    // 4. 主循环：接收事件
    let mut last_ping = tokio::time::Instant::now();
    while let Some(msg_result) = ws_stream.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => return Err(format!("WebSocket read error: {}", e)),
        };

        match msg {
            Message::Text(text) => {
                let server_msg: ServerMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        tracing::warn!(
                            "[sui_graphql_sub] failed to parse server message: {}, raw: {}",
                            e,
                            text.chars().take(500).collect::<String>()
                        );
                        continue;
                    }
                };

                match server_msg {
                    ServerMessage::ConnectionAck => {
                        // 迟到的 ack，忽略
                        tracing::debug!("[sui_graphql_sub] received late ConnectionAck");
                    }
                    ServerMessage::Ping => {
                        // 响应心跳
                        if let Err(e) = ws_stream
                            .send(Message::Text(
                                serde_json::to_string(&ClientMessage::Pong)
                                    .unwrap_or_default()
                                    .into(),
                            ))
                            .await
                        {
                            tracing::warn!("[sui_graphql_sub] failed to send Pong: {}", e);
                        }
                        last_ping = tokio::time::Instant::now();
                    }
                    ServerMessage::Pong => {
                        last_ping = tokio::time::Instant::now();
                    }
                    ServerMessage::Next { id, payload } => {
                        if id != "sui-events-1" {
                            tracing::debug!(
                                "[sui_graphql_sub] received Next for unknown id: {}",
                                id
                            );
                            continue;
                        }
                        handle_subscription_payload(&payload.data, &state).await;
                    }
                    ServerMessage::Error { id, payload } => {
                        tracing::error!(
                            "[sui_graphql_sub] subscription error for id={}: {}",
                            id,
                            payload
                        );
                        // 错误后服务端通常会关闭流，退出主循环触发重连
                        return Err(format!("Subscription error: {}", payload));
                    }
                    ServerMessage::Complete { id } => {
                        tracing::warn!(
                            "[sui_graphql_sub] subscription completed by server for id={}",
                            id
                        );
                        return Ok(());
                    }
                }
            }
            Message::Binary(b) => {
                tracing::debug!(
                    "[sui_graphql_sub] received binary message ({} bytes), ignoring",
                    b.len()
                );
            }
            Message::Close(reason) => {
                tracing::warn!(
                    "[sui_graphql_sub] server closed connection: {:?}",
                    reason
                );
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) => {
                // tungstenite 自动处理 WebSocket 层心跳
            }
            Message::Frame(_) => {}
        }

        // 心跳超时检测：超过 60 秒没收到 Ping/Pong，认为连接已死
        if last_ping.elapsed() > std::time::Duration::from_secs(60) {
            return Err("Heartbeat timeout (no Ping/Pong in 60s)".to_string());
        }
    }

    Ok(())
}

/// 等待 ConnectionAck，超时 10 秒
async fn wait_for_ack(
    ws_stream: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| "ConnectionAck timeout (10s)".to_string())?;

        match tokio::time::timeout(remaining, ws_stream.next()).await {
            Ok(Some(Ok(msg))) => match msg {
                Message::Text(t) => {
                    let parsed: ServerMessage = match serde_json::from_str(&t) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(
                                "[sui_graphql_sub] failed to parse handshake message: {}, raw: {}",
                                e,
                                t.chars().take(200).collect::<String>()
                            );
                            continue;
                        }
                    };
                    match parsed {
                        ServerMessage::ConnectionAck => return Ok(true),
                        ServerMessage::Ping => {
                            // 握手期间也可能收到 Ping，响应 Pong 后继续等
                            let _ = ws_stream
                                .send(Message::Text(
                                    serde_json::to_string(&ClientMessage::Pong)
                                        .unwrap_or_default()
                                        .into(),
                                ))
                                .await;
                            continue;
                        }
                        other => {
                            tracing::warn!(
                                "[sui_graphql_sub] unexpected message during handshake: {:?}",
                                other
                            );
                            continue;
                        }
                    }
                }
                Message::Close(reason) => {
                    return Err(format!(
                        "Connection closed during handshake: {:?}",
                        reason
                    ))
                }
                _ => continue,
            },
            Ok(Some(Err(e))) => return Err(format!("WS error during handshake: {}", e)),
            Ok(None) => return Err("WS stream ended during handshake".to_string()),
            Err(_) => return Err("ConnectionAck timeout (10s)".to_string()),
        }
    }
}

/// 处理订阅推送的事件数据
async fn handle_subscription_payload(data: &Value, state: &Arc<AppState>) {
    // data 结构: { "events": { "type": { "repr": "0x...::module::EventName" }, "json": {...}, "timestamp": "...", "transactionBlock": { "digest": "..." } } }
    let event = match data.get("events") {
        Some(e) => e,
        None => {
            tracing::warn!(
                "[sui_graphql_sub] payload missing 'events' field: {:?}",
                data
            );
            return;
        }
    };

    let event_type = event
        .get("type")
        .and_then(|t| t.get("repr"))
        .and_then(|r| r.as_str())
        .unwrap_or("");
    if event_type.is_empty() {
        tracing::warn!("[sui_graphql_sub] event missing type.repr: {:?}", event);
        return;
    }

    let json_data = event
        .get("json")
        .cloned()
        .unwrap_or(Value::Null);

    let tx_digest = event
        .get("transactionBlock")
        .and_then(|t| t.get("digest"))
        .and_then(|d| d.as_str())
        .unwrap_or("");

    tracing::info!(
        "[sui_graphql_sub] received event: type={}, tx={}",
        event_type,
        tx_digest
    );

    // 复用 parse_chain_event 解析事件
    let chain_event = match parse_chain_event(event_type, &json_data) {
        Some(e) => e,
        None => {
            tracing::warn!(
                "[sui_graphql_sub] failed to parse event: {}",
                event_type
            );
            return;
        }
    };

    handle_graphql_event(chain_event, state, if tx_digest.is_empty() { None } else { Some(tx_digest) }).await;
}

/// 处理解析后的链上事件（与 sui_grpc::handle_grpc_event 等价）
async fn handle_graphql_event(event: SuiChainEvent, state: &Arc<AppState>, tx_digest: Option<&str>) {
    match &event {
        SuiChainEvent::PlayerJoined { table_id, player, buy_in, .. } => {
            tracing::info!(
                "[sui_graphql_sub] PlayerJoined: table={}, player={}, buy_in={}",
                table_id,
                player,
                buy_in
            );
        }
        SuiChainEvent::PlayerLeft { table_id, player, .. } => {
            tracing::info!(
                "[sui_graphql_sub] PlayerLeft: table={}, player={}",
                table_id,
                player
            );
        }
        SuiChainEvent::HandSettled { table_id, pot, .. } => {
            tracing::info!(
                "[sui_graphql_sub] HandSettled: table={}, pot={}",
                table_id,
                pot
            );
        }
        _ => {
            tracing::debug!("[sui_graphql_sub] event: {:?}", event);
        }
    }

    let summary = crate::relayer::process_event(
        &state.config.fullnode_url,
        &state.config.sui_package_id,
        &event,
    )
    .await;
    crate::relayer::apply_event_to_socket(state, &event, summary.as_ref(), tx_digest).await;
}

/// 从 wss:// URL 提取 Host 头
fn host_header(url: &str) -> Result<String, String> {
    let stripped = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .ok_or_else(|| format!("Invalid WebSocket URL: {}", url))?;
    let host = stripped.split('/').next().unwrap_or(stripped);
    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_header_extraction() {
        assert_eq!(
            host_header("wss://sui-testnet.mystenlabs.com/graphql").unwrap(),
            "sui-testnet.mystenlabs.com"
        );
        assert_eq!(
            host_header("wss://example.com:8080/path").unwrap(),
            "example.com:8080"
        );
        assert!(host_header("http://invalid").is_err());
    }

    #[test]
    fn test_client_message_serialization() {
        let init = serde_json::to_string(&ClientMessage::ConnectionInit { payload: None }).unwrap();
        assert!(init.contains("\"type\":\"connection_init\""));
    }
}
