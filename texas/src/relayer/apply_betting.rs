//! Betting 事件同步函数。
//!
//! 将链上 BettingRoundStarted / PotCollected / RoundAdvanced /
//! WinnerAwarded / HandEndedWithoutShowdown 事件同步到内存 Table，
//! 并通过 socket 广播通知前端。

use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::actions;
use crate::pokergame::player::truncate_name;
use crate::socket::{broadcast, get_socket_io, table_room_name};
use crate::sui_events::TableSummaryV2;

use crate::relayer::locate_socket_table_by_chain_id;

/// Task 20: BettingRoundStarted 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
pub(crate) async fn apply_betting_round_started_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::betting_start] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::betting_start] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Betting round started"),
    )
    .await;
}

/// Task 20: PotCollected 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
pub(crate) async fn apply_pot_collected_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::pot_collected] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::pot_collected] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Pot collected"),
    )
    .await;
}

/// Task 20: RoundAdvanced 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
pub(crate) async fn apply_round_advanced_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::round_advanced] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::round_advanced] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Round advanced"),
    )
    .await;
}

/// Task 20: WinnerAwarded 事件处理器。
///
/// 写入 `table.win_messages`（若 hand_rank 非 None 则包含手牌等级名称），
/// 广播 `TABLE_UPDATED` 和 `WINNER`。
pub(crate) async fn apply_winner_awarded_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    player: &str,
    amount: u64,
    hand_rank: Option<&u64>,
) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::winner] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::winner] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 1. 写入 table.win_messages
    let win_message = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // 获取玩家名称（优先使用 seat 中的 name，回退到 player 参数）
        let player_name = table
            .seats()
            .get(&(seat_index as u32))
            .and_then(|seat| seat.player.as_ref())
            .map(|p| p.name.clone())
            .unwrap_or_else(|| truncate_name(player, 12));

        // 构造赢牌消息（包含 hand_rank 名称如果非 None）
        let win_message = if let Some(hr) = hand_rank {
            let rank_name = hand_rank_category_name(*hr);
            format!("{} wins ${:.2} with {}", player_name, amount, rank_name)
        } else {
            format!("{} wins ${:.2}", player_name, amount)
        };

        table.summary.win_messages.push(win_message.clone());
        tracing::info!(
            "[bridge::winner] table {} seat {} awarded {} (player={})",
            socket_table_id,
            seat_index,
            amount,
            player
        );
        win_message
    }; // 写锁释放

    // 2. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Winner awarded"),
    )
    .await;

    // 3. 广播 WINNER
    let payload = serde_json::json!({
        "table_id": socket_table_id,
        "seat_index": seat_index,
        "player": player,
        "amount": amount,
        "message": win_message,
    });
    if let Err(e) = io
        .to(table_room_name(socket_table_id))
        .emit(actions::WINNER, &payload)
        .await
    {
        tracing::warn!(
            "[bridge::winner] WINNER emit failed for table {}: {:?}",
            socket_table_id,
            e
        );
    }
}

/// Task 20: HandEndedWithoutShowdown 事件处理器。
///
/// HandEndedWithoutShowdown 隐含 handreset 逻辑：Move 合约 `end_without_showdown`
/// 内部已调用 `reset_for_next_hand`，链上 `community_cards` / `deck_state.encrypted` /
/// `shuffle_state` / `reveal_token_state` / `reconstruct_state` 等均已清空。
/// 本地需镜像调用 `table.reset_for_next_hand()` 清空 `mental_poker_game`
/// （旧公共牌、旧底牌、旧洗牌结果）、`seat.hand` 等，避免下一手开局时前端
/// 仍展示上一手的牌。
///
/// 顺序要点：
/// - 先用最新 `summary` 同步本地 `summary.meta/state`，确保 `reset_for_next_hand`
///   的 broke_seats 检查（基于 `self.seats()`，读取 `summary.meta.seat_stacks`）
///   能看到 winner 已含 pot 的 stack，避免 all-in winner 被误判为破产而移除；
/// - `reset_for_next_hand` 会 `clear_win_messages`，故在 reset 之后再写本手
///   的 `win_message`。
///
/// 最后广播 `TABLE_UPDATED` 和 `WINNER`。
pub(crate) async fn apply_hand_ended_without_showdown_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    winner_seat: u64,
    winner_player: &str,
    pot: u64,
    summary: Option<&TableSummaryV2>,
) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::no_showdown] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::no_showdown] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 1. 同步最新 summary + reset_for_next_hand + 写入 table.win_messages
    let win_message = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        if let Some(s) = summary {
            if table.summary.meta != s.meta {
                table.summary.meta = s.meta.clone();
            }
            if table.summary.state != s.state {
                table.summary.state = s.state.clone();
            }
        }

        table.reset_for_next_hand();
        tracing::info!(
            "[bridge::no_showdown] table {} reset for next hand before writing win message",
            socket_table_id
        );

        let player_name = table
            .seats()
            .get(&(winner_seat as u32))
            .and_then(|seat| seat.player.as_ref())
            .map(|p| p.name.clone())
            .unwrap_or_else(|| truncate_name(winner_player, 12));

        let win_message = format!("{} wins ${:.2}", player_name, pot);
        table.summary.win_messages.push(win_message.clone());
        tracing::info!(
            "[bridge::no_showdown] table {} seat {} wins {} without showdown",
            socket_table_id,
            winner_seat,
            pot
        );
        win_message
    }; // 写锁释放

    // 2. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Hand ended without showdown"),
    )
    .await;

    // 3. 广播 WINNER
    let payload = serde_json::json!({
        "table_id": socket_table_id,
        "seat_index": winner_seat,
        "player": winner_player,
        "amount": pot,
        "message": win_message,
    });
    if let Err(e) = io
        .to(table_room_name(socket_table_id))
        .emit(actions::WINNER, &payload)
        .await
    {
        tracing::warn!(
            "[bridge::no_showdown] WINNER emit failed for table {}: {:?}",
            socket_table_id,
            e
        );
    }
}

/// Task 20: 将链上 hand_rank u64 转换为手牌等级名称。
///
/// Move 合约中 HandRank.to_u64 编码：category 占 bits 0-7。
/// Category 值：0=High Card, 1=One Pair, 2=Two Pair, 3=Three of a Kind,
/// 4=Straight, 5=Flush, 6=Full House, 7=Four of a Kind,
/// 8=Straight Flush, 9=Royal Flush。
fn hand_rank_category_name(hand_rank_u64: u64) -> &'static str {
    let category = (hand_rank_u64 & 0xFF) as u8;
    match category {
        0 => "High Card",
        1 => "One Pair",
        2 => "Two Pair",
        3 => "Three of a Kind",
        4 => "Straight",
        5 => "Flush",
        6 => "Full House",
        7 => "Four of a Kind",
        8 => "Straight Flush",
        9 => "Royal Flush",
        _ => "Unknown",
    }
}
