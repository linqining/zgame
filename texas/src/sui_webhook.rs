use axum::{
    body::Body,
    extract::Extension,
    http::{HeaderMap, StatusCode, Request},
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

use crate::handlers::AppState;
use crate::sui_events::{parse_chain_event, InodraWebhookPayload};

type HmacSha256 = Hmac<Sha256>;

/// Webhook 时间戳允许的最大偏差（秒），超过则拒绝。
const WEBHOOK_TIMESTAMP_TOLERANCE_SECS: i64 = 300;
/// processed_webhook_ids 的最大容量，超过后清空重建。
const MAX_PROCESSED_WEBHOOK_IDS: usize = 10000;

/// 验证 Inodra Webhook 的 HMAC-SHA256 签名
fn verify_hmac(payload: &[u8], signature: &str, secret: &str) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(payload);
    let expected = mac.finalize().into_bytes();

    // 签名可能是 hex 编码
    if let Ok(bytes) = hex::decode(signature.trim()) {
        return constant_time_eq(&bytes, &expected);
    }
    // 也尝试 base64 编码
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(signature.trim()) {
        return constant_time_eq(&bytes, &expected);
    }
    false
}

/// 简单的常量时间比较，防止时序攻击
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Inodra Webhook 接收端点
/// POST /api/sui/webhook
pub async fn inodra_webhook(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[sui_webhook] failed to read request body");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid body"}))).into_response();
        }
    };

    // 验证 HMAC 签名（如果配置了 secret）
    if !state.config.inodra_webhook_secret.is_empty() {
        let signature = headers
            .get("x-inodra-signature")
            .or_else(|| headers.get("X-Inodra-Signature"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if signature.is_empty() {
            tracing::warn!("[sui_webhook] missing signature header");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Missing signature"}))).into_response();
        }

        if !verify_hmac(&body, signature, &state.config.inodra_webhook_secret) {
            tracing::warn!("[sui_webhook] invalid HMAC signature");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid signature"}))).into_response();
        }
    }

    // 解析事件载荷
    let payload: InodraWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("[sui_webhook] failed to parse payload: {}", e);
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid JSON"}))).into_response();
        }
    };

    // C3 修复：时间窗口校验（5 分钟内），防止重放攻击
    let now = chrono::Utc::now().timestamp();
    let payload_ts = payload.timestamp as i64;
    if (now - payload_ts).abs() > WEBHOOK_TIMESTAMP_TOLERANCE_SECS {
        tracing::warn!(
            "[sui_webhook] timestamp out of range: now={}, payload={}, diff={}",
            now,
            payload_ts,
            now - payload_ts
        );
        return (StatusCode::UNAUTHORIZED, "Webhook timestamp out of range").into_response();
    }

    // C3 修复：基于事件 ID 的去重检查，防止重复处理
    {
        let processed = state.processed_webhook_ids.read().await;
        if processed.contains(&payload.id) {
            tracing::debug!("[sui_webhook] duplicate event id={}, skipping", payload.id);
            return (StatusCode::OK, Json(serde_json::json!({"status": "duplicate"}))).into_response();
        }
    }

    // F22 修复：校验 package_id，忽略非目标合约的事件
    if !state.config.sui_package_id.is_empty()
        && payload.package_id != state.config.sui_package_id
    {
        tracing::debug!(
            "[sui_webhook] package_id mismatch: payload={}, expected={}, ignoring",
            payload.package_id,
            state.config.sui_package_id
        );
        return (StatusCode::OK, Json(serde_json::json!({"status": "ignored"}))).into_response();
    }

    tracing::info!(
        "[sui_webhook] received event: type={}, tx={}, checkpoint={}, id={}",
        payload.event_type,
        payload.transaction_digest,
        payload.checkpoint_seq,
        payload.id
    );

    // 解析为内部事件类型
    let chain_event = match parse_chain_event(&payload.event_type, &payload.data) {
        Some(event) => event,
        None => {
            tracing::warn!("[sui_webhook] failed to parse event: {}", payload.event_type);
            // 即使解析失败也标记为已处理，避免重复投递
            mark_webhook_processed(&state, &payload.id).await;
            return (StatusCode::OK, Json(serde_json::json!({"status": "ignored"}))).into_response();
        }
    };

    tracing::info!("[sui_webhook] parsed chain event: {:?}", chain_event);

    // 标记为已处理（在处理前标记，避免并发重复处理；处理失败也不会重复投递）
    mark_webhook_processed(&state, &payload.id).await;

    // 处理链上事件
    crate::relayer::dispatch::handle_parsed_chain_event(
        &state,
        &chain_event,
        if payload.transaction_digest.is_empty() { None } else { Some(payload.transaction_digest.as_str()) },
        "sui_webhook",
    )
    .await;

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

/// C3 修复：将 webhook 事件 ID 标记为已处理，并控制集合大小。
async fn mark_webhook_processed(state: &Arc<AppState>, event_id: &str) {
    let mut processed = state.processed_webhook_ids.write().await;
    if processed.len() >= MAX_PROCESSED_WEBHOOK_IDS {
        processed.clear();
    }
    processed.insert(event_id.to_string());
}
