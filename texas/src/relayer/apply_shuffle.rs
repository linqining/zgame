//! Shuffle 事件同步函数。
//!
//! 将链上 ShuffleComplete / ShuffleVerified / ShuffleTurn / ShuffleTimeout 事件
//! 同步到内存 Table，并通过 socket 广播通知前端。

use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::table::events::CryptoEventType;
use crate::socket::{broadcast, get_socket_io};

use crate::relayer::locate_socket_table_by_chain_id;

/// Task 7: 将链上 ShuffleComplete 事件同步到内存 Table。
///
/// 若 shuffle_state 活跃，调用 table.advance_shuffle() 推进 shuffle，
/// 发送 shuffle_notice，广播 TABLE_UPDATED。
pub(crate) async fn apply_shuffle_complete_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::shuffle_complete] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::shuffle_complete] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3. 若 shuffle_state 活跃 → advance_shuffle
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            if table.shuffle_state.is_active() {
                tracing::info!(
                    "[bridge::shuffle_complete] advancing shuffle for table {}",
                    socket_table_id
                );
                table.advance_shuffle();
            }
        }
    } // 写锁释放

    // 4. 发送 shuffle_notice + 广播 TABLE_UPDATED
    app_state.socket_state.send_shuffle_notice(socket_table_id).await;
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Shuffle complete"),
    )
    .await;
}

/// Task 20: ShuffleVerified 事件处理器。
///
/// 标记玩家在 `shuffle_state.completed_players` 中（通过 seat_index → pk_hex），
/// 广播 `CRYPTO_EVENT`（event_type="shuffle", verified=true）。
pub(crate) async fn apply_shuffle_verified_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::shuffle_verified] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 标记玩家在 shuffle_state.completed_players 中
    let pk_hex = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // 通过 seat_index 查找 pk_hex
        let pk_hex = table
            .seats()
            .get(&(seat_index as u32))
            .and_then(|seat| seat.player.as_ref())
            .map(|p| p.pk_hex.clone());

        if let Some(pk) = &pk_hex {
            if !table.shuffle_state.completed_players.contains(pk) {
                table.shuffle_state.completed_players.push(pk.clone());
                tracing::info!(
                    "[bridge::shuffle_verified] table {} seat {} marked shuffle completed (pk={})",
                    socket_table_id,
                    seat_index,
                    pk
                );
            }
        } else {
            tracing::debug!(
                "[bridge::shuffle_verified] no pk_hex found for seat {} in table {}",
                seat_index,
                socket_table_id
            );
        }
        pk_hex
    }; // 写锁释放

    // 3. 广播 CRYPTO_EVENT（event_type="shuffle", verified=true）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::Shuffle,
            pk_hex.map(|p| p.to_string()).unwrap_or_default(),
            None,
            true,
            Some("shuffle verified".to_string()),
            None,
        )
        .await;
}

/// Task 20: ShuffleTurn 事件处理器。
///
/// 更新 `shuffle_state.current_player_pk`（通过 seat_index → pk_hex），
/// 广播 `SHUFFLE_NOTICE`（复用 send_shuffle_notice）。
pub(crate) async fn apply_shuffle_turn_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::shuffle_turn] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 更新 shuffle_state.current_player_pk
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            let pk_hex = table
                .seats()
                .get(&(seat_index as u32))
                .and_then(|seat| seat.player.as_ref())
                .map(|p| p.pk_hex.clone());

            if let Some(pk) = pk_hex {
                if table.shuffle_state.current_player_pk.as_ref() != Some(&pk) {
                    table.shuffle_state.current_player_pk = Some(pk.clone());
                    tracing::info!(
                        "[bridge::shuffle_turn] table {} current_shuffler set to seat {} (pk={})",
                        socket_table_id,
                        seat_index,
                        pk
                    );
                }
            } else {
                tracing::debug!(
                    "[bridge::shuffle_turn] no pk_hex found for seat {} in table {}",
                    seat_index,
                    socket_table_id
                );
            }
        }
    } // 写锁释放

    // 3. 广播 SHUFFLE_NOTICE（复用 send_shuffle_notice）
    app_state.socket_state.send_shuffle_notice(socket_table_id).await;
}

/// Task 20: ShuffleTimeout 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="shuffle", verified=false, message="timeout"）。
pub(crate) async fn apply_shuffle_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::shuffle_timeout] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 CRYPTO_EVENT（event_type="shuffle", verified=false, message="timeout"）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::Shuffle,
            String::new(),
            None,
            false,
            Some("timeout".to_string()),
            None,
        )
        .await;
}
