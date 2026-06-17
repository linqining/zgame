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

    tracing::info!(
        "[sui_webhook] received event: type={}, tx={}, checkpoint={}",
        payload.event_type,
        payload.transaction_digest,
        payload.checkpoint_seq
    );

    // 解析为内部事件类型
    let chain_event = match parse_chain_event(&payload.event_type, &payload.data) {
        Some(event) => event,
        None => {
            tracing::warn!("[sui_webhook] failed to parse event: {}", payload.event_type);
            return (StatusCode::OK, Json(serde_json::json!({"status": "ignored"}))).into_response();
        }
    };

    tracing::info!("[sui_webhook] parsed chain event: {:?}", chain_event);

    // 处理链上事件
    handle_chain_event(chain_event, &state).await;

    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

/// 处理解析后的链上事件
/// 当前仅记录日志，后续可根据事件类型触发游戏逻辑
async fn handle_chain_event(event: crate::sui_events::SuiChainEvent, state: &Arc<AppState>) {
    match &event {
        crate::sui_events::SuiChainEvent::PlayerJoined { table_id, player, buy_in, .. } => {
            tracing::info!(
                "[sui_webhook] PlayerJoined: table={}, player={}, buy_in={}",
                table_id, player, buy_in
            );
            // TODO: 同步链上玩家入座到游戏状态
        }
        crate::sui_events::SuiChainEvent::PlayerLeft { table_id, player, .. } => {
            tracing::info!(
                "[sui_webhook] PlayerLeft: table={}, player={}",
                table_id, player
            );
            // TODO: 同步链上玩家离座到游戏状态
        }
        crate::sui_events::SuiChainEvent::HandSettled { table_id, pot } => {
            tracing::info!(
                "[sui_webhook] HandSettled: table={}, pot={}",
                table_id, pot
            );
            // TODO: 同步链上结算结果到游戏状态
        }
        _ => {
            tracing::debug!("[sui_webhook] unhandled event: {:?}", event);
        }
    }

    crate::relayer::process_event(&state.relayer_state, &state.config.fullnode_url, &event).await;
}
