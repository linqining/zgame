use std::sync::Arc;

use crate::handlers::AppState;
use crate::sui_events::SuiChainEvent;

/// 处理已解析的链上事件：记录日志 → 调用 [`process_event`] 获取 summary →
/// 调用 [`apply_event_to_socket`] 应用到 socket。
///
/// 这是 `sui_grpc::handle_grpc_event`、`sui_graphql_sub::handle_graphql_event`、
/// `sui_webhook::handle_chain_event` 三处重复逻辑的统一入口。
///
/// `source` 用于日志前缀（如 `"sui_grpc"`、`"sui_graphql_sub"`、`"sui_webhook"`），
/// 以保留各调用方原有的日志来源标识。
///
/// [`process_event`]: crate::relayer::process_event
/// [`apply_event_to_socket`]: crate::relayer::apply_event_to_socket
pub async fn handle_parsed_chain_event(
    state: &Arc<AppState>,
    event: &SuiChainEvent,
    tx_digest: Option<&str>,
    source: &str,
) {
    match event {
        SuiChainEvent::PlayerJoined { table_id, player, buy_in, .. } => {
            tracing::info!(
                "[{}] PlayerJoined: table={}, player={}, buy_in={}",
                source, table_id, player, buy_in
            );
        }
        SuiChainEvent::PlayerLeft { table_id, player, .. } => {
            tracing::info!(
                "[{}] PlayerLeft: table={}, player={}",
                source, table_id, player
            );
        }
        SuiChainEvent::HandSettled { table_id, pot, .. } => {
            tracing::info!(
                "[{}] HandSettled: table={}, pot={}",
                source, table_id, pot
            );
        }
        _ => {
            tracing::debug!("[{}] event: {:?}", source, event);
        }
    }

    let summary = crate::relayer::process_event(
        &state.config.fullnode_url,
        &state.config.sui_package_id,
        event,
    )
    .await;
    crate::relayer::apply_event_to_socket(state, event, summary.as_ref(), tx_digest).await;
}
