// 子模块声明
pub mod apply_betting;  // Betting 事件同步
pub mod apply_lifecycle;  // Hand 生命周期事件同步
pub mod apply_player;  // 玩家生命周期与行动事件同步
pub mod apply_reconstruct;  // Reconstruct 事件同步
pub mod apply_reveal;  // Reveal 事件同步
pub mod apply_shuffle;  // Shuffle 事件同步
pub mod dispatch;   // 链上事件统一分发（Task 2: 消除三处重复的事件处理逻辑）
pub mod event_classify;  // 事件分类与去重辅助
pub mod proof_bytes;  // Task 2: proof 序列化辅助
pub mod ptb;        // Task 4 实现
pub mod retry;      // Task 10: 玩家行动事件重试队列
pub mod submit;     // Task 5 实现
pub mod sync;       // Task 12: 链上状态同步
pub mod tick;      // Task 6 实现
pub mod util;      // 共享工具函数

use std::collections::HashMap;
use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::{truncate_name, GamePkHex, GamePlayer, WalletAddress};
use crate::pokergame::seat::Seat;
use crate::pokergame::table::events::{CryptoEventType, TableEvent};
use crate::pokergame::table::{ActionRequest, RoundState};
use crate::socket::{broadcast, game_loop, get_socket_io, table_room_name, MIN_START_NUM};
use crate::sui_events::{SuiChainEvent, TableSummaryV2};
use crate::sui_query::fetch_table_summary;

// 重新导出 event_classify 中的公开 API，保持外部调用兼容
pub use event_classify::build_event_dedup_key;
// 重新导出 retry 中的公开 API，保持外部调用兼容
pub use retry::{run_action_retry_loop, PendingAction};
// 重新导出 sync 中的公开 API，保持外部调用兼容
pub use sync::sync_all_tables_from_chain;
// 重新导出 sync 中的模块内部 API，供 apply_* / retry 子模块通过 crate::relayer:: 路径访问
pub(crate) use sync::{
    build_seat_pk_map, populate_seats_from_summary, seat_indices_to_pk_hex,
    sync_single_table_seats_from_chain, sync_table_state,
};
// 模块内部使用的辅助函数
use apply_betting::{
    apply_betting_round_started_to_socket, apply_hand_ended_without_showdown_to_socket,
    apply_pot_collected_to_socket, apply_round_advanced_to_socket, apply_winner_awarded_to_socket,
};
use apply_lifecycle::{
    apply_blinds_posted_to_socket, apply_current_turn_changed_to_socket,
    apply_deck_rebuilt_to_socket, apply_hand_reset_to_socket, apply_hand_settled_to_socket,
    apply_hand_started_to_socket, apply_showdown_hole_cards_revealed_to_socket,
    apply_timeout_config_updated_to_socket,
};
use apply_player::{
    apply_player_action_to_socket, apply_player_joined_to_socket, apply_player_kicked_to_socket,
    apply_player_left_to_socket, apply_player_refund_to_socket, handle_player_action_event,
};
use apply_reconstruct::{
    apply_reconstruct_complete_to_socket, apply_reconstruct_deck_submitted_to_socket,
    apply_reconstruct_initiated_to_socket, apply_reconstruct_timeout_to_socket,
};
use apply_reveal::{
    apply_card_is_identity_to_socket, apply_community_card_revealed_to_socket,
    apply_identity_redeal_to_socket, apply_reveal_phase_complete_to_socket,
    apply_reveal_phase_evt_to_socket, apply_reveal_timeout_to_socket,
    apply_reveal_token_submitted_to_socket,
};
use apply_shuffle::{
    apply_shuffle_complete_to_socket, apply_shuffle_timeout_to_socket, apply_shuffle_turn_to_socket,
    apply_shuffle_verified_to_socket,
};
use event_classify::{event_type_name, is_key_event, round_state_from_event, table_id_from_event};
use retry::push_action_retry;

/// 当前时间的毫秒时间戳。
use util::now_ms;

/// 处理链上事件，拉取 TableSummaryV2 快照并返回。
///
/// 本函数只负责 fetch + 返回，不再做任何缓存。
/// - `TableCreated`：fetch 成功返回 `Some(summary)`，失败返回 `None`。
/// - `HandReset`：fetch 成功后若 `active_count == 0` 返回 `None`（牌桌已空），
///   否则返回 `Some(summary)`；fetch 失败返回 `None`。
/// - `HandSettled` 且 `active_count == 0`：返回 `None`。
/// - 其他事件：fetch 成功返回 `Some(summary)`，失败返回 `None`。
pub async fn process_event(
    fullnode_url: &str,
    package_id: &str,
    event: &SuiChainEvent,
) -> Option<TableSummaryV2> {
    let table_id = table_id_from_event(event);

    match event {
        SuiChainEvent::TableCreated { .. } => {
            tracing::info!(
                table_id = table_id,
                "TableCreated event received, fetching full snapshot"
            );
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    tracing::info!(table_id = table_id, "TableCreated summary fetched");
                    Some(summary)
                }
                Err(e) => {
                    tracing::error!(
                        table_id = table_id,
                        error = %e,
                        "Failed to fetch table summary on TableCreated event"
                    );
                    None
                }
            }
        }
        // Task 12: HandReset 即使 active_count == 0 也返回 Some(summary)，
        // 让 sync_table_state 处理空桌清理（合约是真理之源）。
        SuiChainEvent::HandReset { .. } => {
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    tracing::info!(
                        table_id = table_id,
                        active_count = summary.meta.active_count,
                        "HandReset received, table snapshot refreshed"
                    );
                    Some(summary)
                }
                Err(e) => {
                    tracing::warn!(
                        table_id = table_id,
                        error = %e,
                        "HandReset fetch failed"
                    );
                    None
                }
            }
        }
        _ => {
            tracing::debug!(
                table_id = table_id,
                "Event received, fetching snapshot"
            );
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    // Task 12: HandSettled 即使 active_count == 0 也返回 Some(summary)，
                    // 让 sync_table_state 处理空桌清理（合约是真理之源）。
                    if matches!(event, SuiChainEvent::HandSettled { .. }) {
                        tracing::info!(
                            table_id = table_id,
                            active_count = summary.meta.active_count,
                            "HandSettled received, table snapshot refreshed"
                        );
                    } else {
                        tracing::debug!(table_id = table_id, "Table summary fetched");
                    }
                    Some(summary)
                }
                Err(e) => {
                    tracing::warn!(
                        table_id = table_id,
                        error = %e,
                        "Failed to fetch table summary"
                    );
                    None
                }
            }
        }
    }
}

/// 将链上事件同步到内存游戏状态（SocketState / GameState）。
///
/// 当 relayer 收到玩家行动类事件（PlayerFolded / PlayerChecked / PlayerCalled /
/// PlayerRaised / PlayerAllIn）时，通过 `summary` 参数解析出对应钱包地址，
/// 再在 GameState 中找到对应 table 与 pk_hex，最终通过 game loop 的
/// ActionRequest 通道触发行动，复用既有游戏循环逻辑完成行动 + 轮次推进 + 广播。
///
/// 对所有事件，额外调用 sync_table_state 将链上 round_state / shuffle_state /
/// reveal_token_state / reconstruct_state 同步到 GameState，保持状态一致。
pub async fn apply_event_to_socket(
    app_state: &Arc<AppState>,
    event: &SuiChainEvent,
    summary: Option<&TableSummaryV2>,
    tx_digest: Option<&str>,
) {

    // 1. 处理玩家行动事件：转发到 game loop 的 ActionRequest 通道
    //    C2 修复：在 Both 模式下，gRPC 和 webhook 可能同时投递同一事件，
    //    通过 AppState.processed_actions 去重，避免重复触发行动。
    match event {
        SuiChainEvent::PlayerFolded { table_id, seat_index, round_state, .. } => {
            handle_player_action_event(
                app_state, event, table_id, *seat_index, *round_state, summary, "fold", "PlayerFolded", None,
            ).await;
        }
        SuiChainEvent::PlayerChecked { table_id, seat_index, round_state } => {
            handle_player_action_event(
                app_state, event, table_id, *seat_index, *round_state, summary, "check", "PlayerChecked", None,
            ).await;
        }
        SuiChainEvent::PlayerCalled { table_id, seat_index, call_delta, round_state } => {
            handle_player_action_event(
                app_state, event, table_id, *seat_index, *round_state, summary, "call", "PlayerCalled", Some(*call_delta),
            ).await;
        }
        SuiChainEvent::PlayerRaised { table_id, seat_index, total_bet, round_state, .. } => {
            handle_player_action_event(
                app_state, event, table_id, *seat_index, *round_state, summary, "raise", "PlayerRaised", Some(*total_bet),
            ).await;
        }
        SuiChainEvent::PlayerAllIn { table_id, seat_index, amount, round_state, .. } => {
            handle_player_action_event(
                app_state, event, table_id, *seat_index, *round_state, summary, "allin", "PlayerAllIn", Some(*amount),
            ).await;
        }
        // Task 9: 玩家生命周期事件 + 手牌阶段事件同步到内存 Table
        // 玩家生命周期事件（join/leave/kick/refund）不使用 check_and_mark_action 去重：
        // 原因：check_and_mark_action 在函数执行前标记，若函数因 RPC 快照过期等
        // 原因早返回，事件会被永久跳过。改为依赖 apply_*_to_socket 内部的 seat 级幂等检查。
        SuiChainEvent::PlayerJoined { table_id, seat_index, player, buy_in, is_waiting, active_count_after } => {
            tracing::info!(
                "[bridge] PlayerJoined event: table={}, seat={}, player={}, buy_in={}, active_count_after={}",
                table_id, seat_index, player, buy_in, active_count_after
            );
            if let Some(s) = summary {
                apply_player_joined_to_socket(app_state, table_id, *seat_index, player, *buy_in, *is_waiting, *active_count_after, s, tx_digest).await;
            } else {
                tracing::warn!(
                    "[bridge::join] PlayerJoined summary is None, push to retry queue: table={}, seat={}",
                    table_id,
                    seat_index
                );
                push_action_retry(app_state, event.clone());
            }
        }
        SuiChainEvent::PlayerLeft { table_id, seat_index, player } => {
            tracing::info!(
                "[bridge] PlayerLeft event: table={}, seat={}, player={}",
                table_id, seat_index, player
            );
            // 不再调用 check_and_mark_action：其 key 为 {table}_{seat}_leave_0，
            // 不含 player 钱包，不同玩家复用同一座位时会误拦。
            // 事件级去重（build_event_dedup_key 已含 player）足以避免重复处理。
            apply_player_left_to_socket(app_state, table_id, *seat_index, player).await;
        }
        SuiChainEvent::PlayerKicked { table_id, seat_index, player, reason } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "kick", *reason)
            {
                apply_player_kicked_to_socket(app_state, table_id, *seat_index, player, *reason as u64).await;
            }
        }
        SuiChainEvent::PlayerRefund { table_id, seat_index, player, amount, refund_type } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "refund", *refund_type)
            {
                apply_player_refund_to_socket(app_state, table_id, *seat_index, player, *amount, *refund_type as u64).await;
            }
        }
        // 手牌阶段事件（无需去重，直接同步）
        SuiChainEvent::HandStarted { table_id, .. } => {
            apply_hand_started_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::ShuffleComplete { table_id, .. } => {
            apply_shuffle_complete_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::RevealPhaseEvt { table_id, phase, .. } => {
            apply_reveal_phase_evt_to_socket(app_state, table_id, *phase, summary).await;
        }
        SuiChainEvent::ReconstructInitiated { table_id, .. } => {
            apply_reconstruct_initiated_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::CommunityCardRevealed { table_id, .. } => {
            apply_community_card_revealed_to_socket(app_state, table_id).await;
        }
        // Task 20: 洗牌事件
        SuiChainEvent::ShuffleVerified { table_id, seat_index, .. } => {
            apply_shuffle_verified_to_socket(app_state, table_id, *seat_index).await;
        }
        SuiChainEvent::ShuffleTurn { table_id, seat_index, .. } => {
            apply_shuffle_turn_to_socket(app_state, table_id, *seat_index).await;
        }
        SuiChainEvent::ShuffleTimeout { table_id, .. } => {
            apply_shuffle_timeout_to_socket(app_state, table_id).await;
        }
        // Task 20: Reveal 事件
        SuiChainEvent::RevealTokenSubmitted { table_id, seat_index, card_index, .. } => {
            apply_reveal_token_submitted_to_socket(app_state, table_id, *seat_index, *card_index, tx_digest).await;
        }
        SuiChainEvent::RevealPhaseComplete { table_id, phase, .. } => {
            apply_reveal_phase_complete_to_socket(app_state, table_id, *phase, summary).await;
        }
        SuiChainEvent::CardIsIdentity { table_id, card_index, .. } => {
            apply_card_is_identity_to_socket(app_state, table_id, *card_index).await;
        }
        SuiChainEvent::IdentityRedeal { table_id, .. } => {
            apply_identity_redeal_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::RevealTimeout { table_id, .. } => {
            apply_reveal_timeout_to_socket(app_state, table_id).await;
        }
        // Task 20: 下注事件
        SuiChainEvent::BettingRoundStarted { table_id, .. } => {
            apply_betting_round_started_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::PotCollected { table_id, .. } => {
            apply_pot_collected_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::RoundAdvanced { table_id, .. } => {
            apply_round_advanced_to_socket(app_state, table_id).await;
        }
        // Task 20: 结算事件
        SuiChainEvent::WinnerAwarded { table_id, seat_index, player, amount, hand_rank, .. } => {
            apply_winner_awarded_to_socket(app_state, table_id, *seat_index, player, *amount, hand_rank.as_ref()).await;
        }
        SuiChainEvent::HandEndedWithoutShowdown { table_id, winner_seat, winner_player, pot } => {
            apply_hand_ended_without_showdown_to_socket(app_state, table_id, *winner_seat, winner_player, *pot).await;
        }
        SuiChainEvent::HandSettled { table_id, .. } => {
            apply_hand_settled_to_socket(app_state, table_id).await;
        }
        // Task 20: Reconstruct 事件
        SuiChainEvent::ReconstructDeckSubmitted { table_id, seat_index, .. } => {
            apply_reconstruct_deck_submitted_to_socket(app_state, table_id, *seat_index).await;
        }
        SuiChainEvent::ReconstructComplete { table_id, .. } => {
            apply_reconstruct_complete_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::ReconstructTimeout { table_id, .. } => {
            apply_reconstruct_timeout_to_socket(app_state, table_id).await;
        }
        // Task 20: Reset 事件
        SuiChainEvent::HandReset { table_id, .. } => {
            apply_hand_reset_to_socket(app_state, table_id).await;
        }
        // Task 20: Move 合约新增事件
        SuiChainEvent::BlindsPosted { table_id, sb_seat, bb_seat, sb_amount, bb_amount, first_to_act } => {
            apply_blinds_posted_to_socket(app_state, table_id, *sb_seat, *bb_seat, *sb_amount, *bb_amount, *first_to_act).await;
        }
        SuiChainEvent::ShowdownHoleCardsRevealed { table_id, seat_index, card_ranks, card_suits, .. } => {
            apply_showdown_hole_cards_revealed_to_socket(app_state, table_id, *seat_index, card_ranks, card_suits).await;
        }
        SuiChainEvent::TimeoutConfigUpdated { table_id, betting_timeout_ms, shuffle_timeout_ms, reveal_timeout_ms, reconstruct_timeout_ms, showdown_display_ms } => {
            apply_timeout_config_updated_to_socket(app_state, table_id, *betting_timeout_ms, *shuffle_timeout_ms, *reveal_timeout_ms, *reconstruct_timeout_ms, *showdown_display_ms).await;
        }
        SuiChainEvent::DeckRebuilt { table_id, .. } => {
            apply_deck_rebuilt_to_socket(app_state, table_id).await;
        }
        SuiChainEvent::CurrentTurnChanged { table_id, old_turn, new_turn, round_state } => {
            apply_current_turn_changed_to_socket(app_state, table_id, *old_turn, *new_turn, *round_state).await;
        }
        _ => tracing::warn!(target: "relayer", "unknown event: {:?}", event),
    }

    // 1.5 Trick: 玩家行动事件后，直接从 summary 读取 current_turn 同步本地状态。
    //     链上合约在 call/check/raise/fold 后已更新 current_turn 到下一个玩家，
    //     但 CurrentTurnChanged 事件可能缺失或延迟。此处不依赖该事件，
    //     直接用 summary 中的 current_turn 同步，确保前端行动面板及时刷新。
    let is_player_action = matches!(
        event,
        SuiChainEvent::PlayerFolded { .. }
            | SuiChainEvent::PlayerChecked { .. }
            | SuiChainEvent::PlayerCalled { .. }
            | SuiChainEvent::PlayerRaised { .. }
            | SuiChainEvent::PlayerAllIn { .. }
    );
    if is_player_action {
        if let Some(s) = summary {
            let sui_tid = table_id_from_event(event);
            let new_turn = s.meta.current_turn;
            let round_state = round_state_from_event(event).unwrap_or(0);
            apply_current_turn_changed_to_socket(
                app_state,
                sui_tid,
                None, // old_turn 未知，日志中显示 None
                new_turn,
                round_state,
            )
            .await;
        }
    }

    // 2. 对所有事件同步 table 整体状态（round_state / shuffle / reveal / reconstruct）
    let sui_table_id = table_id_from_event(event);
    // D4 修复：玩家行动事件由 game_loop 负责下注状态，sync_table_state 跳过下注同步
    let is_player_action = matches!(
        event,
        SuiChainEvent::PlayerFolded { .. }
            | SuiChainEvent::PlayerChecked { .. }
            | SuiChainEvent::PlayerCalled { .. }
            | SuiChainEvent::PlayerRaised { .. }
            | SuiChainEvent::PlayerAllIn { .. }
    );
    // 牌组变化事件：涉及 deck / shuffle / reveal / reconstruct 状态变更，
    // 需要无条件同步 table.summary.crypto 字段，避免因 shuffle_active /
    // chain_reconstruct_active 条件不满足而跳过 crypto 同步。
    let is_deck_change_event = matches!(
        event,
        SuiChainEvent::ShuffleVerified { .. }
            | SuiChainEvent::ShuffleComplete { .. }
            | SuiChainEvent::ShuffleTurn { .. }
            | SuiChainEvent::ShuffleTimeout { .. }
            | SuiChainEvent::RevealTokenSubmitted { .. }
            | SuiChainEvent::RevealPhaseComplete { .. }
            | SuiChainEvent::RevealPhaseEvt { .. }
            | SuiChainEvent::CardIsIdentity { .. }
            | SuiChainEvent::IdentityRedeal { .. }
            | SuiChainEvent::CommunityCardRevealed { .. }
            | SuiChainEvent::RevealTimeout { .. }
            | SuiChainEvent::ReconstructInitiated { .. }
            | SuiChainEvent::ReconstructDeckSubmitted { .. }
            | SuiChainEvent::ReconstructComplete { .. }
            | SuiChainEvent::ReconstructTimeout { .. }
            | SuiChainEvent::RedealRequested { .. }
    );
    if let Some(s) = summary {
        sync_table_state(app_state, sui_table_id, is_player_action, is_deck_change_event, s).await;
    } else {
        tracing::debug!(
            "[bridge::sync] summary is None, skip sync_table_state for table {}",
            sui_table_id
        );
    }
}

// ============================================================================
// 链上事件 → 内存 Table 同步函数（Task 2 ~ Task 8）
//
// 以下函数将链上事件同步到内存 Table 的 players / seats / pk_to_seat，
// 并通过 socket 广播通知前端。仅在 on-chain 模式下由 apply_event_to_socket
// 调用（Task 9 负责在 match 中集成）。
// ============================================================================

/// 在 GameState 中通过 chain_table_id 精确匹配定位 socket table。
/// 复用 sync_table_state 中的定位逻辑。返回 socket_table_id。
pub(crate) async fn locate_socket_table_by_chain_id(
    app_state: &Arc<AppState>,
    chain_table_id: &str,
) -> Option<u32> {
    let gs = app_state.socket_state.state.read().await;
    gs.tables
        .iter()
        .find(|(_, table)| table.chain_table_id.as_deref() == Some(chain_table_id))
        .map(|(tid, _)| *tid)
}

/// 从 G1 compressed bytes 反序列化为 GamePkHex（复用 build_seat_pk_map 逻辑）。
pub(crate) fn deserialize_pk_hex(pk_bytes: &[u8]) -> Option<GamePkHex> {
    use poker_protocol::crypto::curve::CurvePoint;
    use poker_protocol::crypto::DefaultCurve;
    type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

    if pk_bytes.is_empty() {
        return None;
    }
    <P as CurvePoint>::from_compressed(pk_bytes).map(|pt| {
        GamePkHex::new(poker_protocol::z_poker::convert::ecpoint_to_hex(&pt))
    })
}

/// 规范化钱包地址为小写 0x 前缀 hex 字符串。
pub(crate) fn normalize_wallet(addr: &str) -> String {
    addr.to_lowercase()
}


#[cfg(test)]
mod tests {
    use super::*;

    // ========== table_id_from_event 测试 ==========

    #[test]
    fn test_table_id_from_event() {
        let tid = "0xdeadbeef";

        let cases: Vec<(SuiChainEvent, &str)> = vec![
            (
                SuiChainEvent::TableCreated {
                    table_id: tid.to_string(),
                    name: "n".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerJoined {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                    buy_in: 0,
                    is_waiting: false,
                    active_count_after: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerLeft {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::HandStarted {
                    table_id: tid.to_string(),
                    button: 0,
                    small_blind: 10,
                    big_blind: 20,
                    participants: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleVerified {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleComplete {
                    table_id: tid.to_string(),
                    phase: 0,
                    participant_count: 0,
                    deck_size: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleTurn {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    pending_count: 0,
                    completed_count: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleTimeout {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    phase: 0,
                    started_at: 0,
                    timeout_ms: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealTokenSubmitted {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    card_index: 0,
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealPhaseComplete {
                    table_id: tid.to_string(),
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealPhaseEvt {
                    table_id: tid.to_string(),
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::CardIsIdentity {
                    table_id: tid.to_string(),
                    card_index: 0,
                    assignment_index: 0,
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::IdentityRedeal {
                    table_id: tid.to_string(),
                    identity_card_indices: vec![],
                    redeal_count: 0,
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::CommunityCardRevealed {
                    table_id: tid.to_string(),
                    phase: 0,
                    card_indices: vec![],
                    card_ranks: vec![],
                    card_suits: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::RevealTimeout {
                    table_id: tid.to_string(),
                    phase: 0,
                    pending_players: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::BettingRoundStarted {
                    table_id: tid.to_string(),
                    round_state: 0,
                    current_bet: 0,
                    min_raise: 0,
                    first_to_act: 0,
                    pot_before: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerFolded {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    reason: 0,
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerChecked {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerCalled {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    call_delta: 0,
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerRaised {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    raise_delta: 0,
                    total_bet: 0,
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerAllIn {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    trigger_action: 0,
                    amount: 0,
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PotCollected {
                    table_id: tid.to_string(),
                    round_state: 0,
                    pot_after: 0,
                    collected_from_seats: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::RoundAdvanced {
                    table_id: tid.to_string(),
                    from_round: 0,
                    to_round: 0,
                    pot: 0,
                    community_cards_count: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::WinnerAwarded {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                    amount: 0,
                    pot_type: 0,
                    hand_rank: None,
                },
                tid,
            ),
            (
                SuiChainEvent::HandEndedWithoutShowdown {
                    table_id: tid.to_string(),
                    winner_seat: 0,
                    winner_player: "p".to_string(),
                    pot: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::HandSettled {
                    table_id: tid.to_string(),
                    pot: 0,
                    winners: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructInitiated {
                    table_id: tid.to_string(),
                    expected_players: vec![],
                    round_state: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructDeckSubmitted {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructComplete {
                    table_id: tid.to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructTimeout {
                    table_id: tid.to_string(),
                    pending_players: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::RedealRequested {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    card_indices: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerKicked {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                    reason: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerRefund {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                    amount: 0,
                    refund_type: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::HandReset {
                    table_id: tid.to_string(),
                    reason: 0,
                    round_state: 0,
                },
                tid,
            ),
        ];

        // 验证所有变体全部覆盖（实际为 34 个变体）
        assert_eq!(cases.len(), 34, "should cover all SuiChainEvent variants");

        for (event, expected) in cases {
            assert_eq!(table_id_from_event(&event), expected);
        }
    }

    // ========== process_event 测试 ==========

    /// 验证 process_event 处理非 TableCreated 事件在网络失败时返回 None 且不崩溃。
    #[tokio::test]
    async fn test_process_event_player_folded_network_failure() {
        // 使用一个无效的 URL，确保 fetch_table_summary 失败
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::PlayerFolded {
            table_id: "0xpre".to_string(),
            seat_index: 1,
            reason: 0,
            round_state: 0,
        };

        // 调用 process_event，应不 panic，且网络失败时返回 None
        let result = process_event(invalid_url, "0xpackage", &event).await;
        assert!(result.is_none());
    }

    /// 验证 process_event 处理 TableCreated 事件在网络失败时不崩溃、返回 None。
    #[tokio::test]
    async fn test_process_event_table_created_network_failure() {
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::TableCreated {
            table_id: "0xnew".to_string(),
            name: "TestTable".to_string(),
        };

        // 调用 process_event，应不 panic，网络失败时返回 None
        let result = process_event(invalid_url, "0xpackage", &event).await;
        assert!(result.is_none());
    }

    /// 验证 process_event 处理未缓存 table 的非 TableCreated 事件在网络失败时不崩溃。
    #[tokio::test]
    async fn test_process_event_uncached_table_network_failure() {
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::HandSettled {
            table_id: "0xuncached".to_string(),
            pot: 100,
            winners: vec![],
        };

        // 调用 process_event，应不 panic，网络失败时返回 None
        let result = process_event(invalid_url, "0xpackage", &event).await;
        assert!(result.is_none());
    }

    // ========== build_seat_pk_map / seat_indices_to_pk_hex 测试 ==========

    #[test]
    fn test_build_seat_pk_map_empty() {
        // 全空 seat_pks → 空映射
        let seat_pks: Vec<Vec<u8>> = vec![vec![], vec![], vec![]];
        let map = build_seat_pk_map(&seat_pks);
        assert!(map.is_empty());
    }

    #[test]
    fn test_build_seat_pk_map_with_valid_pks() {
        use poker_protocol::crypto::curve::CurvePoint;
        use poker_protocol::crypto::DefaultCurve;
        type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

        // 生成两个有效的 G1 点
        let pt1 = P::identity();
        let pt2 = P::random(&mut rand::thread_rng());
        let pk1_bytes = pt1.compress().as_ref().to_vec();
        let pk2_bytes = pt2.compress().as_ref().to_vec();

        let seat_pks = vec![pk1_bytes.clone(), vec![], pk2_bytes.clone()];
        let map = build_seat_pk_map(&seat_pks);

        // seat 0 和 seat 2 有 pk，seat 1 为空被跳过
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&0));
        assert!(!map.contains_key(&1));
        assert!(map.contains_key(&2));

        // 验证 hex 值正确
        let expected_hex1 = poker_protocol::z_poker::convert::ecpoint_to_hex(&pt1);
        assert_eq!(map.get(&0).unwrap().as_str(), expected_hex1);
    }

    #[test]
    fn test_build_seat_pk_map_invalid_bytes() {
        // 无效的 G1 bytes → 跳过该 seat
        let seat_pks = vec![vec![0xFF; 48], vec![]];
        let map = build_seat_pk_map(&seat_pks);
        assert!(map.is_empty());
    }

    #[test]
    fn test_seat_indices_to_pk_hex() {
        use poker_protocol::crypto::curve::CurvePoint;
        use poker_protocol::crypto::DefaultCurve;
        type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

        let pt1 = P::random(&mut rand::thread_rng());
        let pt2 = P::random(&mut rand::thread_rng());
        let pk1_bytes = pt1.compress().as_ref().to_vec();
        let pk2_bytes = pt2.compress().as_ref().to_vec();

        let seat_pks = vec![pk1_bytes, vec![], pk2_bytes];
        let map = build_seat_pk_map(&seat_pks);

        // 转换 seat_index 列表 [0, 1, 2, 3] → pk_hex 列表
        // seat 1 为空（不在 map 中），seat 3 越界 → 都应被跳过
        let indices = vec![0u64, 1, 2, 3];
        let pk_hex_list = seat_indices_to_pk_hex(&indices, &map);
        assert_eq!(pk_hex_list.len(), 2); // 只有 seat 0 和 seat 2

        // 空列表
        let empty_indices: Vec<u64> = vec![];
        let empty_result = seat_indices_to_pk_hex(&empty_indices, &map);
        assert!(empty_result.is_empty());
    }
}
