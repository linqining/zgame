//! Reconstruct 事件同步函数。
//!
//! 将链上 ReconstructInitiated / ReconstructDeckSubmitted /
//! ReconstructComplete / ReconstructTimeout 事件同步到内存 Table，
//! 并通过 socket 广播通知前端。

use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::table::events::CryptoEventType;
use crate::socket::{broadcast, game_loop, get_socket_io};

use crate::relayer::locate_socket_table_by_chain_id;

/// Task 8: 将链上 ReconstructInitiated 事件同步为 reconstruct notice 广播。
pub(crate) async fn apply_reconstruct_initiated_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::reconstruct] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reconstruct] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3. 广播 reconstruct_notice
    game_loop::broadcast_reconstruct_notice_if_active(&io, &app_state.socket_state, socket_table_id)
        .await;
}

/// Task 20: ReconstructDeckSubmitted 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reconstruct", verified=true）。
pub(crate) async fn apply_reconstruct_deck_submitted_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reconstruct_submit] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 获取 pk_hex（用于广播）
    let pk_hex = {
        let gs = app_state.socket_state.state.read().await;
        gs.tables
            .get(&socket_table_id)
            .map(|table| {
                let seats = table.seats();
                seats.get(&(seat_index as u32))
                    .and_then(|seat| seat.player.as_ref())
                    .map(|p| p.pk_hex.to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    };

    // 3. 广播 CRYPTO_EVENT（event_type="reconstruct", verified=true）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::Reconstruct,
            pk_hex,
            None,
            true,
            Some("reconstruct deck submitted".to_string()),
            None,
        )
        .await;
}

/// Task 20: ReconstructComplete 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
pub(crate) async fn apply_reconstruct_complete_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::reconstruct_complete] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reconstruct_complete] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Reconstruct complete"),
    )
    .await;
}

/// Task 20: ReconstructTimeout 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reconstruct", verified=false, message="timeout"）。
pub(crate) async fn apply_reconstruct_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reconstruct_timeout] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 CRYPTO_EVENT（event_type="reconstruct", verified=false, message="timeout"）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::Reconstruct,
            String::new(),
            None,
            false,
            Some("timeout".to_string()),
            None,
        )
        .await;
}
