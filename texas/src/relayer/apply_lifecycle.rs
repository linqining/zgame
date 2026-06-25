//! Hand 生命周期事件同步函数。
//!
//! 将链上 HandStarted / HandSettled / HandReset / BlindsPosted /
//! ShowdownHoleCardsRevealed / TimeoutConfigUpdated / DeckRebuilt /
//! CurrentTurnChanged 事件同步到内存 Table，并通过 socket 广播通知前端。

use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::deck::Card;
use crate::socket::{broadcast, get_socket_io};
use crate::sui_events::TableSummaryV2;

use crate::relayer::locate_socket_table_by_chain_id;
use crate::relayer::util::now_ms;

/// Task 6: 将链上 HandStarted 事件同步到内存 Table。
///
/// 确保 game loop 已启动，广播 TABLE_UPDATED。
pub(crate) async fn apply_hand_started_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::hand_start] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::hand_start] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3. 若 game loop 未运行，启动 game loop
    //    start_game_loop 内部会检查是否已运行，重复调用是安全的
    app_state
        .socket_state
        .start_game_loop(io.clone(), app_state.socket_state.clone(), socket_table_id)
        .await;

    // 4. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Hand started"),
    )
    .await;
}

/// Task 20: HandSettled 事件处理器。
///
/// HandSettled 隐含 handreset 逻辑：Move 合约 `settle_hand` 内部已调用
/// `reset_for_next_hand`，链上 `community_cards` / `deck_state.encrypted` /
/// `shuffle_state` / `reveal_token_state` / `reconstruct_state` 等均已清空。
/// 本地需镜像调用 `table.reset_for_next_hand()` 清空 `mental_poker_game`
/// （旧公共牌、旧底牌、旧洗牌结果）、`seat.hand` 等，避免下一手开局时前端
/// 仍展示上一手的牌。`WinnerAwarded` 事件先于 `HandSettled` 到达并写入
/// `win_messages`，而 `reset_for_next_hand` 会 `clear_win_messages`，故先
/// 取出再还原，确保玩家能看到本手结算结果。
pub(crate) async fn apply_hand_settled_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    summary: Option<&TableSummaryV2>,
) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::settled] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::settled] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 用最新 summary 同步本地 summary.meta/state，确保 reset_for_next_hand 的
    // broke_seats 检查（基于 self.seats()，读取 summary.meta.seat_stacks）能看到
    // winner 已含 pot 的 stack，避免 all-in winner 被误判为破产而移除。
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            if let Some(s) = summary {
                if table.summary.meta != s.meta {
                    table.summary.meta = s.meta.clone();
                }
                if table.summary.state != s.state {
                    table.summary.state = s.state.clone();
                }
            }

            let preserved_win_messages = std::mem::take(&mut table.summary.win_messages);
            table.reset_for_next_hand();
            table.summary.win_messages = preserved_win_messages;
            tracing::info!(
                "[bridge::settled] table {} reset for next hand (win_messages preserved={})",
                socket_table_id,
                table.summary.win_messages.len()
            );
        }
    }

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Hand settled"),
    )
    .await;
}

/// Task 20: HandReset 事件处理器。
///
/// 调用 `table.reset_for_next_hand()`，广播 `TABLE_UPDATED`。
pub(crate) async fn apply_hand_reset_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::hand_reset] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::hand_reset] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 1. 调用 table.reset_for_next_hand()
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            table.reset_for_next_hand();
            tracing::info!(
                "[bridge::hand_reset] table {} reset for next hand",
                socket_table_id
            );
        }
    } // 写锁释放

    // 2. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Hand reset"),
    )
    .await;
}

/// Task 20: BlindsPosted 事件处理器。
///
/// 调用 `table.set_blinds_from_chain()`，广播 `TABLE_UPDATED`。
pub(crate) async fn apply_blinds_posted_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    sb_seat: u64,
    bb_seat: u64,
    sb_amount: u64,
    bb_amount: u64,
    first_to_act: u64,
) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::blinds] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::blinds] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 1. 调用 table.set_blinds_from_chain()
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            table.set_blinds_from_chain(sb_seat, bb_seat, sb_amount, bb_amount, first_to_act);
            tracing::info!(
                "[bridge::blinds] table {} blinds posted: sb_seat={} sb_amount={} bb_seat={} bb_amount={} first_to_act={}",
                socket_table_id,
                sb_seat,
                sb_amount,
                bb_seat,
                bb_amount,
                first_to_act
            );
        }
    } // 写锁释放

    // 2. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Blinds posted"),
    )
    .await;
}

/// Task 20: ShowdownHoleCardsRevealed 事件处理器。
///
/// 写入 `seat.hand`（card_ranks/card_suits 转换为 Card），
/// 广播 `HAND_REVEAL_RESULT`（复用 broadcast_hand_reveal_result）。
pub(crate) async fn apply_showdown_hole_cards_revealed_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    card_ranks: &[u8],
    card_suits: &[u8],
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::showdown] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 写入 seat.hand（card_ranks/card_suits → Card）
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            if let Some(seat) = table.local_seats.get_mut(&(seat_index as u32)) {
                let mut hand: Vec<Card> = Vec::with_capacity(card_ranks.len());
                for (rank, suit) in card_ranks.iter().zip(card_suits.iter()) {
                    if let Some(card) = chain_card_to_card(*rank, *suit) {
                        hand.push(card);
                    } else {
                        tracing::warn!(
                            "[bridge::showdown] invalid card rank={} suit={} for table {} seat {}",
                            rank,
                            suit,
                            socket_table_id,
                            seat_index
                        );
                    }
                }
                seat.hand = hand;
                tracing::info!(
                    "[bridge::showdown] table {} seat {} hand set ({} cards)",
                    socket_table_id,
                    seat_index,
                    card_ranks.len()
                );
            } else {
                tracing::warn!(
                    "[bridge::showdown] seat {} not found in table {}",
                    seat_index,
                    socket_table_id
                );
            }
        }
    } // 写锁释放

    // 3. 广播 HAND_REVEAL_RESULT（复用 broadcast_hand_reveal_result）
    app_state.socket_state.broadcast_hand_reveal_result(socket_table_id).await;
}

/// Task 20: TimeoutConfigUpdated 事件处理器。
///
/// 更新 table 的超时配置字段（存储在 summary.state 中），
/// 无需广播（内部状态，下次 sync_table_state 会拉取最新值）。
pub(crate) async fn apply_timeout_config_updated_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    betting_timeout_ms: u64,
    shuffle_timeout_ms: u64,
    reveal_timeout_ms: u64,
    reconstruct_timeout_ms: u64,
    showdown_display_ms: u64,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::timeout_config] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 更新 table.summary.state 中的超时字段
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            table.summary.state.betting_timeout_ms = betting_timeout_ms;
            table.summary.state.shuffle_timeout_ms = shuffle_timeout_ms;
            table.summary.state.reveal_timeout_ms = reveal_timeout_ms;
            table.summary.state.reconstruct_timeout_ms = reconstruct_timeout_ms;
            table.summary.state.showdown_display_ms = showdown_display_ms;
            tracing::info!(
                "[bridge::timeout_config] table {} timeout config updated: betting={}ms shuffle={}ms reveal={}ms reconstruct={}ms showdown={}ms",
                socket_table_id,
                betting_timeout_ms,
                shuffle_timeout_ms,
                reveal_timeout_ms,
                reconstruct_timeout_ms,
                showdown_display_ms
            );
        }
    } // 写锁释放
}

/// Task 20: DeckRebuilt 事件处理器。
///
/// 无需广播（内部状态，下次 sync_table_state 会无条件同步 crypto 字段，
/// 包括 deck_encrypted / deck_plaintext 等）。
pub(crate) async fn apply_deck_rebuilt_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table（仅用于日志）
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::debug!(
                "[bridge::deck_rebuilt] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 仅记日志，实际 deck 同步由 sync_table_state 处理
    //    （sync_table_state 已重构为无条件同步 crypto 字段）
    tracing::info!(
        "[bridge::deck_rebuilt] table {} deck rebuilt, will be synced by next sync_table_state",
        socket_table_id
    );
}

/// CurrentTurnChanged 事件处理器。
///
/// 链上 current_turn 变更时立即同步本地状态，避免玩家基于过期 turn 构建 PTB
/// 导致 Shinami sponsor 阶段 MoveAbort(ENotPlayerTurn) 502。
///
/// 直接从事件 payload 读取 new_turn，无需等待完整快照 fetch，最小化状态滞后窗口。
/// 随后的 sync_table_state 会用完整快照覆盖（一致即可）。
pub(crate) async fn apply_current_turn_changed_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    old_turn: Option<u64>,
    new_turn: Option<u64>,
    round_state: u8,
) {
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::turn] socket.io not initialized, skip");
            return;
        }
    };

    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::turn] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 1. 立即同步 current_turn 与 seat.turn
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            let prev_turn = table.turn();
            let new_turn_u32 = new_turn.map(|t| t as u32);
            table.set_turn(new_turn_u32);
            // 同步 seat.turn：前端依赖 seat.turn 显示行动面板和倒计时
            for (seat_id, seat) in table.local_seats.iter_mut() {
                seat.turn = new_turn_u32 == Some(*seat_id);
            }
            // 进入下注轮且 betting_started_at 未设置时，初始化计时器
            if new_turn_u32.is_some() && table.betting_started_at() == 0 {
                table.set_betting_started_at(now_ms());
            }
            tracing::info!(
                "[bridge::turn] table {} current_turn changed: {:?} -> {:?} (prev_local={:?}, round_state={})",
                socket_table_id,
                old_turn,
                new_turn,
                prev_turn,
                round_state
            );
        }
    } // 写锁释放

    // 2. 广播 TABLE_UPDATED，让前端立即刷新行动面板
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Current turn changed"),
    )
    .await;
}

/// Task 20: 将链上 card_rank/card_suit (u8) 转换为 Card。
///
/// Move 合约编码：
/// - card_rank: 2-14（2=Two, 14=Ace）
/// - card_suit: 0-3（0=Club, 1=Diamond, 2=Heart, 3=Spade）
///
/// Card 结构：
/// - suit: String ("s", "h", "d", "c")
/// - rank: String ("2"-"10", "J", "Q", "K", "A")
fn chain_card_to_card(rank: u8, suit: u8) -> Option<Card> {
    let rank_str = match rank {
        2 => "2",
        3 => "3",
        4 => "4",
        5 => "5",
        6 => "6",
        7 => "7",
        8 => "8",
        9 => "9",
        10 => "10",
        11 => "J",
        12 => "Q",
        13 => "K",
        14 => "A",
        _ => return None,
    };
    let suit_str = match suit {
        0 => "c", // Club
        1 => "d", // Diamond
        2 => "h", // Heart
        3 => "s", // Spade
        _ => return None,
    };
    Some(Card {
        suit: suit_str.to_string(),
        rank: rank_str.to_string(),
    })
}
