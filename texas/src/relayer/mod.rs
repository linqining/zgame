// 子模块声明
pub mod proof_bytes;  // Task 2: proof 序列化辅助
pub mod ptb;        // Task 4 实现
pub mod submit;     // Task 5 实现
pub mod tick;      // Task 6 实现

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

/// Task 10: 待重试的玩家行动事件。
///
/// 当玩家行动事件因 `summary=None` 或 game_loop 通道关闭而无法立即处理时，
/// 会被推入 `AppState.action_retry_queue` 等待重试。
#[derive(Clone)]
pub struct PendingAction {
    pub event: SuiChainEvent,
    pub retry_count: u8,
    pub next_retry_at: u64, // timestamp ms
}

/// 当前时间的毫秒时间戳。
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Task 16: 返回 SuiChainEvent 变体的简短名称（用于去重 key）。
fn event_type_name(event: &SuiChainEvent) -> &'static str {
    match event {
        SuiChainEvent::TableCreated { .. } => "TableCreated",
        SuiChainEvent::PlayerJoined { .. } => "PlayerJoined",
        SuiChainEvent::PlayerLeft { .. } => "PlayerLeft",
        SuiChainEvent::HandStarted { .. } => "HandStarted",
        SuiChainEvent::BlindsPosted { .. } => "BlindsPosted",
        SuiChainEvent::ShuffleVerified { .. } => "ShuffleVerified",
        SuiChainEvent::ShuffleComplete { .. } => "ShuffleComplete",
        SuiChainEvent::ShuffleTurn { .. } => "ShuffleTurn",
        SuiChainEvent::ShuffleTimeout { .. } => "ShuffleTimeout",
        SuiChainEvent::RevealTokenSubmitted { .. } => "RevealTokenSubmitted",
        SuiChainEvent::RevealPhaseComplete { .. } => "RevealPhaseComplete",
        SuiChainEvent::RevealPhaseEvt { .. } => "RevealPhaseEvt",
        SuiChainEvent::CardIsIdentity { .. } => "CardIsIdentity",
        SuiChainEvent::IdentityRedeal { .. } => "IdentityRedeal",
        SuiChainEvent::CommunityCardRevealed { .. } => "CommunityCardRevealed",
        SuiChainEvent::RevealTimeout { .. } => "RevealTimeout",
        SuiChainEvent::BettingRoundStarted { .. } => "BettingRoundStarted",
        SuiChainEvent::PlayerFolded { .. } => "PlayerFolded",
        SuiChainEvent::PlayerChecked { .. } => "PlayerChecked",
        SuiChainEvent::PlayerCalled { .. } => "PlayerCalled",
        SuiChainEvent::PlayerRaised { .. } => "PlayerRaised",
        SuiChainEvent::PlayerAllIn { .. } => "PlayerAllIn",
        SuiChainEvent::PotCollected { .. } => "PotCollected",
        SuiChainEvent::RoundAdvanced { .. } => "RoundAdvanced",
        SuiChainEvent::WinnerAwarded { .. } => "WinnerAwarded",
        SuiChainEvent::HandEndedWithoutShowdown { .. } => "HandEndedWithoutShowdown",
        SuiChainEvent::ShowdownHoleCardsRevealed { .. } => "ShowdownHoleCardsRevealed",
        SuiChainEvent::HandSettled { .. } => "HandSettled",
        SuiChainEvent::ReconstructInitiated { .. } => "ReconstructInitiated",
        SuiChainEvent::ReconstructDeckSubmitted { .. } => "ReconstructDeckSubmitted",
        SuiChainEvent::ReconstructComplete { .. } => "ReconstructComplete",
        SuiChainEvent::ReconstructTimeout { .. } => "ReconstructTimeout",
        SuiChainEvent::RedealRequested { .. } => "RedealRequested",
        SuiChainEvent::DeckRebuilt { .. } => "DeckRebuilt",
        SuiChainEvent::PlayerKicked { .. } => "PlayerKicked",
        SuiChainEvent::PlayerRefund { .. } => "PlayerRefund",
        SuiChainEvent::HandReset { .. } => "HandReset",
        SuiChainEvent::TimeoutConfigUpdated { .. } => "TimeoutConfigUpdated",
        SuiChainEvent::CurrentTurnChanged { .. } => "CurrentTurnChanged",
    }
}

/// Task 16: 为任意 SuiChainEvent 构建去重 key。
///
/// - 带 seat_index 的事件：`evt:{table_id}:{event_type}:{seat_index}:{phase_or_round}:{card_index_or_zero}`
/// - 不带 seat_index 的事件：`evt:{table_id}:{event_type}:{content_hash}`
///   （tx_digest 不易获取，使用事件内容哈希作为去重依据）
pub fn build_event_dedup_key(event: &SuiChainEvent) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let table_id = table_id_from_event(event);
    let etype = event_type_name(event);

    match event {
        // 含 player 钱包地址的座位事件：必须把 player 纳入 key，
        // 否则不同玩家复用同一座位时去重 key 碰撞（A 离开 seat 1 后 B 加入又离开，
        // 两次 PlayerLeft 的 key 相同，第二次被错误跳过，B 永远不会被移除）。
        SuiChainEvent::PlayerJoined { seat_index, player, .. }
        | SuiChainEvent::PlayerLeft { seat_index, player, .. }
        | SuiChainEvent::PlayerKicked { seat_index, player, .. }
        | SuiChainEvent::PlayerRefund { seat_index, player, .. } => {
            format!("evt:{}:{}:{}:{}:0", table_id, etype, seat_index, player)
        }
        // 其他带 seat_index 的事件（无 player 字段）
        SuiChainEvent::ShuffleVerified { seat_index, .. }
        | SuiChainEvent::ShuffleTurn { seat_index, .. }
        | SuiChainEvent::ShuffleTimeout { seat_index, .. }
        | SuiChainEvent::ReconstructDeckSubmitted { seat_index, .. }
        | SuiChainEvent::RedealRequested { seat_index, .. }
        | SuiChainEvent::ShowdownHoleCardsRevealed { seat_index, .. }
        | SuiChainEvent::WinnerAwarded { seat_index, .. } => {
            format!("evt:{}:{}:{}:0:0", table_id, etype, seat_index)
        }
        // 带 seat_index + round_state 的行动事件
        SuiChainEvent::PlayerFolded { seat_index, round_state, .. }
        | SuiChainEvent::PlayerChecked { seat_index, round_state, .. }
        | SuiChainEvent::PlayerCalled { seat_index, round_state, .. }
        | SuiChainEvent::PlayerRaised { seat_index, round_state, .. }
        | SuiChainEvent::PlayerAllIn { seat_index, round_state, .. } => {
            format!("evt:{}:{}:{}:{}:0", table_id, etype, seat_index, round_state)
        }
        // 带 seat_index + card_index 的事件
        SuiChainEvent::RevealTokenSubmitted { seat_index, card_index, phase, .. } => {
            format!("evt:{}:{}:{}:{}:{}", table_id, etype, seat_index, phase, card_index)
        }
        // CardIsIdentity 有 card_index 但无 seat_index
        SuiChainEvent::CardIsIdentity { card_index, phase, .. } => {
            format!("evt:{}:{}:0:{}:{}", table_id, etype, phase, card_index)
        }
        // 带 phase 的事件（无 seat_index）
        SuiChainEvent::ShuffleComplete { phase, .. }
        | SuiChainEvent::RevealPhaseComplete { phase, .. }
        | SuiChainEvent::RevealPhaseEvt { phase, .. }
        | SuiChainEvent::IdentityRedeal { phase, .. }
        | SuiChainEvent::CommunityCardRevealed { phase, .. }
        | SuiChainEvent::RevealTimeout { phase, .. } => {
            format!("evt:{}:{}:0:{}:0", table_id, etype, phase)
        }
        // 带 round_state 的事件（无 seat_index）
        SuiChainEvent::BettingRoundStarted { round_state, .. }
        | SuiChainEvent::PotCollected { round_state, .. }
        | SuiChainEvent::ReconstructInitiated { round_state, .. }
        | SuiChainEvent::HandReset { round_state, .. } => {
            format!("evt:{}:{}:0:{}:0", table_id, etype, round_state)
        }
        // 其他无 seat_index 的事件：使用内容哈希
        _ => {
            let mut hasher = DefaultHasher::new();
            if let Ok(s) = serde_json::to_string(event) {
                s.hash(&mut hasher);
            } else {
                format!("{:?}", event).hash(&mut hasher);
            }
            format!("evt:{}:{}:{:016x}", table_id, etype, hasher.finish())
        }
    }
}

/// 从 SuiChainEvent 中提取 table_id
fn table_id_from_event(event: &SuiChainEvent) -> &str {
    match event {
        SuiChainEvent::TableCreated { table_id, .. } => table_id,
        SuiChainEvent::PlayerJoined { table_id, .. } => table_id,
        SuiChainEvent::PlayerLeft { table_id, .. } => table_id,
        SuiChainEvent::HandStarted { table_id, .. } => table_id,
        SuiChainEvent::BlindsPosted { table_id, .. } => table_id,
        SuiChainEvent::ShuffleVerified { table_id, .. } => table_id,
        SuiChainEvent::ShuffleComplete { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTurn { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTimeout { table_id, .. } => table_id,
        SuiChainEvent::RevealTokenSubmitted { table_id, .. } => table_id,
        SuiChainEvent::RevealPhaseComplete { table_id, .. } => table_id,
        SuiChainEvent::RevealPhaseEvt { table_id, .. } => table_id,
        SuiChainEvent::CardIsIdentity { table_id, .. } => table_id,
        SuiChainEvent::IdentityRedeal { table_id, .. } => table_id,
        SuiChainEvent::CommunityCardRevealed { table_id, .. } => table_id,
        SuiChainEvent::RevealTimeout { table_id, .. } => table_id,
        SuiChainEvent::BettingRoundStarted { table_id, .. } => table_id,
        SuiChainEvent::PlayerFolded { table_id, .. } => table_id,
        SuiChainEvent::PlayerChecked { table_id, .. } => table_id,
        SuiChainEvent::PlayerCalled { table_id, .. } => table_id,
        SuiChainEvent::PlayerRaised { table_id, .. } => table_id,
        SuiChainEvent::PlayerAllIn { table_id, .. } => table_id,
        SuiChainEvent::PotCollected { table_id, .. } => table_id,
        SuiChainEvent::RoundAdvanced { table_id, .. } => table_id,
        SuiChainEvent::WinnerAwarded { table_id, .. } => table_id,
        SuiChainEvent::HandEndedWithoutShowdown { table_id, .. } => table_id,
        SuiChainEvent::ShowdownHoleCardsRevealed { table_id, .. } => table_id,
        SuiChainEvent::HandSettled { table_id, .. } => table_id,
        SuiChainEvent::ReconstructInitiated { table_id, .. } => table_id,
        SuiChainEvent::ReconstructDeckSubmitted { table_id, .. } => table_id,
        SuiChainEvent::ReconstructComplete { table_id, .. } => table_id,
        SuiChainEvent::ReconstructTimeout { table_id, .. } => table_id,
        SuiChainEvent::RedealRequested { table_id, .. } => table_id,
        SuiChainEvent::DeckRebuilt { table_id, .. } => table_id,
        SuiChainEvent::PlayerKicked { table_id, .. } => table_id,
        SuiChainEvent::PlayerRefund { table_id, .. } => table_id,
        SuiChainEvent::HandReset { table_id, .. } => table_id,
        SuiChainEvent::TimeoutConfigUpdated { table_id, .. } => table_id,
        SuiChainEvent::CurrentTurnChanged { table_id, .. } => table_id,
    }
}

/// 判断事件是否为关键事件（状态变更类），需要 fetch 完整快照。
/// 非关键事件（如 ShuffleTurn / RevealTokenSubmitted 等中间过程事件）
/// 在缓存已存在且非 stale 时跳过 fetch，减少冗余 RPC。
fn is_key_event(event: &SuiChainEvent) -> bool {
    // G2 修复：PlayerJoined/PlayerLeft 改变了 seat_players 映射，必须刷新缓存
    matches!(
        event,
        SuiChainEvent::TableCreated { .. }
            | SuiChainEvent::PlayerJoined { .. }
            | SuiChainEvent::PlayerLeft { .. }
            | SuiChainEvent::HandStarted { .. }
            | SuiChainEvent::ShuffleComplete { .. }
            | SuiChainEvent::RevealPhaseComplete { .. }
            | SuiChainEvent::BettingRoundStarted { .. }
            | SuiChainEvent::RoundAdvanced { .. }
            | SuiChainEvent::HandSettled { .. }
            | SuiChainEvent::HandReset { .. }
            | SuiChainEvent::ReconstructInitiated { .. }
            | SuiChainEvent::ReconstructComplete { .. }
            | SuiChainEvent::PlayerFolded { .. }
            | SuiChainEvent::PlayerCalled { .. }
            | SuiChainEvent::PlayerRaised { .. }
            | SuiChainEvent::PlayerAllIn { .. }
            | SuiChainEvent::PotCollected { .. }
            | SuiChainEvent::CurrentTurnChanged { .. }
    )
}

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

/// Task 10: 将失败的玩家行动事件推入重试队列。
///
/// 初始 `retry_count=0`，`next_retry_at=now_ms()`（立即可重试）。
fn push_action_retry(app_state: &Arc<AppState>, event: SuiChainEvent) {
    let pending = PendingAction {
        event,
        retry_count: 0,
        next_retry_at: now_ms(),
    };
    match app_state.action_retry_queue.lock() {
        Ok(mut q) => {
            q.push(pending);
            tracing::debug!(
                "[bridge::retry] event pushed to retry queue, queue_len={}",
                q.len()
            );
        }
        Err(e) => {
            tracing::error!(
                "[bridge::retry] failed to lock action_retry_queue: {}",
                e
            );
        }
    }
}

/// Task 10: 后台重试循环 - 每 5 秒调用 `process_action_retry_queue`。
pub async fn run_action_retry_loop(app_state: Arc<AppState>) {
    let interval = std::time::Duration::from_secs(5);
    tracing::info!("[bridge::retry] action retry loop started (interval=5s)");
    loop {
        tokio::time::sleep(interval).await;
        process_action_retry_queue(&app_state).await;
    }
}

/// Task 10: 处理重试队列中的待重试事件。
///
/// - 取出队列中所有事件
/// - 过滤掉 `retry_count >= 3` 的事件（log error + 触发 sync_table_state 作为兜底）
/// - 对 `next_retry_at <= now_ms()` 的事件重新尝试处理（不调用 check_and_mark_action）
/// - 处理失败的事件：retry_count += 1，next_retry_at = now_ms() + 5000
/// - 仍需重试的事件放回队列
pub async fn process_action_retry_queue(app_state: &Arc<AppState>) {
    // 1. 取出队列中所有事件（锁内操作，快速释放）
    let pending: Vec<PendingAction> = {
        match app_state.action_retry_queue.lock() {
            Ok(mut q) => std::mem::take(&mut *q),
            Err(e) => {
                tracing::error!(
                    "[bridge::retry] failed to lock action_retry_queue: {}",
                    e
                );
                return;
            }
        }
    };

    if pending.is_empty() {
        return;
    }

    let now = now_ms();
    let mut still_pending: Vec<PendingAction> = Vec::new();

    for mut item in pending {
        // 2. 过滤掉重试次数超限的事件
        if item.retry_count >= 3 {
            tracing::error!(
                "[bridge::retry] event exhausted retries (count={}): {:?}, triggering full sync_table_state fallback",
                item.retry_count,
                item.event
            );
            // 兜底：重新拉取 summary 并调用 sync_table_state
            let table_id = table_id_from_event(&item.event).to_string();
            let summary = crate::relayer::process_event(
                &app_state.config.fullnode_url,
                &app_state.config.sui_package_id,
                &item.event,
            )
            .await;
            if let Some(s) = summary {
                sync_table_state(app_state, &table_id, false, false, &s).await;
            }
            continue;
        }

        // 3. 仅处理到期的重试事件
        if item.next_retry_at > now {
            still_pending.push(item);
            continue;
        }

        // 4. 重新尝试处理（不调用 check_and_mark_action，因为首次已标记）
        let reprocessed = retry_apply_player_action(app_state, &item.event).await;

        if reprocessed {
            tracing::info!(
                "[bridge::retry] event reprocessed successfully: type={}",
                event_type_name(&item.event)
            );
        } else {
            // 5. 处理失败：增加重试计数，设置下次重试时间
            item.retry_count += 1;
            item.next_retry_at = now_ms() + 5000;
            tracing::warn!(
                "[bridge::retry] event retry failed (count={}), will retry at {}: type={}",
                item.retry_count,
                item.next_retry_at,
                event_type_name(&item.event)
            );
            still_pending.push(item);
        }
    }

    // 6. 将仍需重试的事件放回队列
    if !still_pending.is_empty() {
        match app_state.action_retry_queue.lock() {
            Ok(mut q) => {
                // 注意：在重试处理期间可能有新事件推入队列，这里 append 而非替换
                q.extend(still_pending);
            }
            Err(e) => {
                tracing::error!(
                    "[bridge::retry] failed to lock action_retry_queue for writeback: {}",
                    e
                );
            }
        }
    }
}

/// Task 10: 重试单个玩家行动事件或 PlayerJoined 事件。
///
/// 重新拉取 summary，若成功则调用对应的 apply_*_to_socket。
/// 返回 `true` 表示处理成功（或事件非行动事件），`false` 表示仍需重试。
async fn retry_apply_player_action(
    app_state: &Arc<AppState>,
    event: &SuiChainEvent,
) -> bool {
    // PlayerJoined: 重新拉取 summary，调用 apply_player_joined_to_socket
    if let SuiChainEvent::PlayerJoined { table_id, seat_index, player, buy_in, is_waiting, active_count_after } = event {
        let summary = match crate::relayer::process_event(
            &app_state.config.fullnode_url,
            &app_state.config.sui_package_id,
            event,
        )
        .await
        {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "[bridge::retry] PlayerJoined summary still None for table={}",
                    table_id
                );
                return false;
            }
        };
        apply_player_joined_to_socket(
            app_state,
            table_id,
            *seat_index,
            player,
            *buy_in,
            *is_waiting,
            *active_count_after,
            &summary,
            None,
        )
        .await;
        return true;
    }

    // 仅处理玩家行动事件
    let (table_id, seat_index, action, amount) = match event {
        SuiChainEvent::PlayerFolded { table_id, seat_index, .. } => {
            (table_id.clone(), *seat_index, "fold", None)
        }
        SuiChainEvent::PlayerChecked { table_id, seat_index, .. } => {
            (table_id.clone(), *seat_index, "check", None)
        }
        SuiChainEvent::PlayerCalled { table_id, seat_index, call_delta, .. } => {
            (table_id.clone(), *seat_index, "call", Some(*call_delta))
        }
        SuiChainEvent::PlayerRaised { table_id, seat_index, total_bet, .. } => {
            (table_id.clone(), *seat_index, "raise", Some(*total_bet))
        }
        SuiChainEvent::PlayerAllIn { table_id, seat_index, amount, .. } => {
            (table_id.clone(), *seat_index, "allin", Some(*amount))
        }
        _ => {
            // 非行动事件不重试
            return true;
        }
    };

    // 重新拉取 summary
    let summary = match crate::relayer::process_event(
        &app_state.config.fullnode_url,
        &app_state.config.sui_package_id,
        event,
    )
    .await
    {
        Some(s) => s,
        None => {
            tracing::warn!(
                "[bridge::retry] summary still None for table={}",
                table_id
            );
            return false;
        }
    };

    // 调用 apply_player_action_to_socket（不调用 check_and_mark_action）
    apply_player_action_to_socket(
        app_state,
        &table_id,
        seat_index,
        action,
        amount,
        &summary,
        Some(event),
    )
    .await;

    // apply_player_action_to_socket 内部会处理 game_loop 关闭的情况，
    // 若 game_loop 仍关闭会再次推入队列。这里假设成功返回即处理完成。
    true
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
    // Task 16: 全事件去重 - 在 match 之前对所有 SuiChainEvent 变体去重。
    // Both 模式下 gRPC 和 webhook 可能同时投递同一事件，统一去重避免重复处理。
    // 行动事件仍保留下方 match 内的 check_and_mark_action 调用以维持兼容。
    if !app_state.check_and_mark_event(event) {
        tracing::debug!(
            "[bridge::dedup] duplicate event skipped: type={}",
            event_type_name(event)
        );
        return;
    }

    // 1. 处理玩家行动事件：转发到 game loop 的 ActionRequest 通道
    //    C2 修复：在 Both 模式下，gRPC 和 webhook 可能同时投递同一事件，
    //    通过 AppState.processed_actions 去重，避免重复触发行动。
    match event {
        SuiChainEvent::PlayerFolded { table_id, seat_index, round_state, .. } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "fold", *round_state)
            {
                if let Some(s) = summary {
                    apply_player_action_to_socket(app_state, table_id, *seat_index, "fold", None, s, Some(event)).await;
                } else {
                    tracing::warn!(
                        "[bridge::action] PlayerFolded summary is None, push to retry queue: table={}, seat={}",
                        table_id,
                        seat_index
                    );
                    push_action_retry(app_state, event.clone());
                }
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerFolded event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
        }
        SuiChainEvent::PlayerChecked { table_id, seat_index, round_state } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "check", *round_state)
            {
                if let Some(s) = summary {
                    apply_player_action_to_socket(app_state, table_id, *seat_index, "check", None, s, Some(event)).await;
                } else {
                    tracing::warn!(
                        "[bridge::action] PlayerChecked summary is None, push to retry queue: table={}, seat={}",
                        table_id,
                        seat_index
                    );
                    push_action_retry(app_state, event.clone());
                }
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerChecked event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
        }
        SuiChainEvent::PlayerCalled { table_id, seat_index, call_delta, round_state } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "call", *round_state)
            {
                if let Some(s) = summary {
                    apply_player_action_to_socket(app_state, table_id, *seat_index, "call", Some(*call_delta), s, Some(event)).await;
                } else {
                    tracing::warn!(
                        "[bridge::action] PlayerCalled summary is None, push to retry queue: table={}, seat={}",
                        table_id,
                        seat_index
                    );
                    push_action_retry(app_state, event.clone());
                }
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerCalled event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
        }
        SuiChainEvent::PlayerRaised { table_id, seat_index, total_bet, round_state, .. } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "raise", *round_state)
            {
                if let Some(s) = summary {
                    apply_player_action_to_socket(app_state, table_id, *seat_index, "raise", Some(*total_bet), s, Some(event)).await;
                } else {
                    tracing::warn!(
                        "[bridge::action] PlayerRaised summary is None, push to retry queue: table={}, seat={}",
                        table_id,
                        seat_index
                    );
                    push_action_retry(app_state, event.clone());
                }
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerRaised event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
        }
        SuiChainEvent::PlayerAllIn { table_id, seat_index, amount, round_state, .. } => {
            if app_state
                .check_and_mark_action(table_id, *seat_index, "allin", *round_state)
            {
                if let Some(s) = summary {
                    apply_player_action_to_socket(app_state, table_id, *seat_index, "allin", Some(*amount), s, Some(event)).await;
                } else {
                    tracing::warn!(
                        "[bridge::action] PlayerAllIn summary is None, push to retry queue: table={}, seat={}",
                        table_id,
                        seat_index
                    );
                    push_action_retry(app_state, event.clone());
                }
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerAllIn event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
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
        SuiChainEvent::RevealPhaseComplete { table_id, .. } => {
            apply_reveal_phase_complete_to_socket(app_state, table_id).await;
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

/// relayer 启动后拉取全量桌子的 TableSummaryV2 快照并同步到内存。
///
/// 遍历 GameState 中所有已绑定 `chain_table_id` 的 table，逐个调用
/// `fetch_table_summary` 拉取链上最新快照，再通过 `sync_table_state`
/// 同步到内存（包括 meta / state / crypto 全字段，`force_sync_crypto=true`）。
///
/// 用于 relayer 启动时建立内存与链上状态的初始一致性，避免启动后内存
/// table.summary 为空导致后续事件处理时 crypto 字段缺失。
pub async fn sync_all_tables_from_chain(app_state: &Arc<AppState>) {
    let fullnode_url = app_state.config.fullnode_url.as_str();
    let package_id = app_state.config.sui_package_id.as_str();

    // 1. 收集所有已绑定 chain_table_id 的 (socket_table_id, chain_table_id) 列表
    let chain_tables: Vec<(u32, String)> = {
        let gs = app_state.socket_state.state.read().await;
        gs.tables
            .iter()
            .filter_map(|(tid, table)| {
                table.chain_table_id.as_ref().map(|cid| (*tid, cid.clone()))
            })
            .collect()
    };

    if chain_tables.is_empty() {
        tracing::info!("[bridge::startup] no tables with chain_table_id, skip initial snapshot sync");
        return;
    }

    tracing::info!(
        "[bridge::startup] syncing initial TableSummaryV2 snapshot for {} tables",
        chain_tables.len()
    );

    // 2. 逐个拉取并同步（串行，避免启动时并发 RPC 风暴）
    let mut success_count = 0u32;
    let mut fail_count = 0u32;
    for (socket_table_id, chain_table_id) in chain_tables {
        match fetch_table_summary(fullnode_url, package_id, &chain_table_id).await {
            Ok(summary) => {
                // force_sync_crypto=true：启动快照必须同步 crypto 字段
                sync_table_state(app_state, &chain_table_id, false, true, &summary).await;
                // 从快照填充 players / seats / pk_to_seat（relayer 重启后内存为空）
                populate_seats_from_summary(&app_state.socket_state, socket_table_id, &summary).await;
                success_count += 1;
                tracing::info!(
                    "[bridge::startup] table {} (chain={}) initial snapshot synced (round_state={}, active_count={}, deck_encrypted_len={})",
                    socket_table_id,
                    chain_table_id,
                    summary.meta.round_state,
                    summary.meta.active_count,
                    summary.crypto.deck_encrypted.len()
                );
            }
            Err(e) => {
                fail_count += 1;
                tracing::warn!(
                    "[bridge::startup] table {} (chain={}) initial snapshot fetch failed: {}",
                    socket_table_id,
                    chain_table_id,
                    e
                );
            }
        }
    }

    tracing::info!(
        "[bridge::startup] initial snapshot sync complete: {} success, {} failed",
        success_count,
        fail_count
    );
}

/// 从链上同步单个 table 的玩家/座位状态。
///
/// 用于 JOIN_TABLE 时确保内存状态与链上一致：on-chain 模式下 SIT_DOWN_V2
/// 不直接更新内存，玩家数据由 relayer 异步同步。如果 relayer 尚未处理
/// PlayerJoined 事件，内存 table 中会缺少新玩家，导致刷新页面也看不到。
/// 本函数拉取链上 TableSummaryV2 快照，补齐缺失的玩家/座位。
pub(crate) async fn sync_single_table_seats_from_chain(
    socket_state: &crate::socket::SocketState,
    socket_table_id: u32,
) {
    let chain_table_id = {
        let gs = socket_state.state.read().await;
        gs.tables.get(&socket_table_id)
            .and_then(|t| t.chain_table_id.clone())
    };
    let Some(chain_table_id) = chain_table_id else {
        tracing::debug!("[sync_single_table] table {} has no chain_table_id, skip", socket_table_id);
        return;
    };

    let summary = match crate::sui_query::fetch_table_summary(
        &socket_state.config.fullnode_url,
        &socket_state.config.sui_package_id,
        &chain_table_id,
    ).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "[sync_single_table] table {} fetch_table_summary failed: {}",
                socket_table_id, e
            );
            return;
        }
    };

    populate_seats_from_summary(socket_state, socket_table_id, &summary).await;
}

/// 从链上 TableSummaryV2 快照填充内存 table 的 players / seats / pk_to_seat。
///
/// relayer 重启后，链上已有玩家但内存 table.players / table.seats 为空（因为没有
/// 收到 PlayerJoined 事件）。本函数遍历 summary 中所有 occupied seat，为缺失的
/// 玩家创建 GamePlayer + Seat 并加入 table.players / pk_to_seat / seats，
/// 同时同步 stack / bet / folded / is_waiting 等字段。
///
/// 已存在的 seat 仅更新字段，不重复创建。shuffle_state.completed_players 也会
/// 补齐（链上 join_and_shuffle 已包含 shuffle）。
pub(crate) async fn populate_seats_from_summary(
    socket_state: &crate::socket::SocketState,
    socket_table_id: u32,
    summary: &TableSummaryV2,
) {
    use crate::pokergame::player::{GamePlayer, WalletAddress};
    use crate::pokergame::seat::Seat;

    let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

    // 先以不可变读锁收集 wallet → name 映射，避免与 table 写锁冲突
    let wallet_to_name: HashMap<String, String> = {
        let gs = socket_state.state.read().await;
        gs.players
            .values()
            .map(|p| (normalize_wallet(&p.wallet_address.0), p.name.clone()))
            .collect()
    };

    let mut added_count = 0u32;
    let mut updated_count = 0u32;

    {
        let mut gs = socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        for (seat_idx, &occupied) in summary.meta.seats_occupied.iter().enumerate() {
            if !occupied {
                continue;
            }
            let seat_id = seat_idx as u32;

            // 从 seat_players 获取 wallet
            let wallet = match summary.meta.seat_players.get(seat_idx) {
                Some(sp) if !sp.iter().all(|&b| b == 0) => {
                    normalize_wallet(&format!("0x{}", hex::encode(sp)))
                }
                _ => {
                    tracing::debug!(
                        "[bridge::populate] seat {} has empty wallet, skip",
                        seat_idx
                    );
                    continue;
                }
            };

            // 从 seat_pk_map 获取 pk_hex
            let pk_hex = match seat_pk_map.get(&(seat_idx as u64)) {
                Some(pk) => pk.clone(),
                None => {
                    tracing::warn!(
                        "[bridge::populate] seat {} pk deserialization failed, skip",
                        seat_idx
                    );
                    continue;
                }
            };

            // 检查 seat 是否已存在且 player 匹配
            let already_populated = table
                .seats()
                .get(&seat_id)
                .and_then(|s| s.player.as_ref())
                .map(|p| p.pk_hex == pk_hex)
                .unwrap_or(false);

            if already_populated {
                // 仅更新字段
                if let Some(seat) = table.local_seats.get_mut(&seat_id) {
                    let chain_stack = summary.meta.seat_stacks.get(seat_idx).copied().unwrap_or(0);
                    let chain_bet = summary.meta.seat_bets.get(seat_idx).copied().unwrap_or(0);
                    let chain_total_bet = summary.meta.seat_total_bets.get(seat_idx).copied().unwrap_or(0);
                    let chain_folded = summary.meta.seat_folded.get(seat_idx).copied().unwrap_or(false);
                    let chain_waiting = summary.meta.seat_is_waiting.get(seat_idx).copied().unwrap_or(false);
                    if seat.stack != chain_stack { seat.stack = chain_stack; }
                    if seat.bet != chain_bet { seat.bet = chain_bet; }
                    if seat.total_bet != chain_total_bet { seat.total_bet = chain_total_bet; }
                    if seat.folded != chain_folded { seat.folded = chain_folded; }
                    if seat.is_waiting != chain_waiting { seat.is_waiting = chain_waiting; }
                }
                updated_count += 1;
                continue;
            }

            // 创建新 GamePlayer + Seat
            let player_name = wallet_to_name
                .get(&wallet)
                .cloned()
                .unwrap_or_else(|| truncate_name(&wallet, 12));

            let chain_stack = summary.meta.seat_stacks.get(seat_idx).copied().unwrap_or(0);
            let chain_bet = summary.meta.seat_bets.get(seat_idx).copied().unwrap_or(0);
            let chain_total_bet = summary.meta.seat_total_bets.get(seat_idx).copied().unwrap_or(0);
            let chain_folded = summary.meta.seat_folded.get(seat_idx).copied().unwrap_or(false);
            let chain_waiting = summary.meta.seat_is_waiting.get(seat_idx).copied().unwrap_or(false);

            let game_player = GamePlayer {
                name: truncate_name(&player_name, 12),
                bankroll: 0,
                pk_hex: pk_hex.clone(),
                readable_hands: vec![],
                wallet_address: WalletAddress::new(wallet.clone()),
            };

            let mut seat = Seat::new(seat_id, Some(game_player), chain_stack, chain_stack);
            seat.bet = chain_bet;
            seat.total_bet = chain_total_bet;
            seat.folded = chain_folded;
            seat.is_waiting = chain_waiting;

            // 加入 table.players / pk_to_seat / seats
            let _ = table.add_player(pk_hex.clone(), WalletAddress::new(wallet.clone()));
            table.pk_to_seat.insert(pk_hex.clone(), seat_id);
            table.local_seats.insert(seat_id, seat);

            // 补齐 shuffle_state.completed_players（链上 join_and_shuffle 已包含 shuffle）
            if !table.shuffle_state.completed_players.contains(&pk_hex) {
                table.shuffle_state.completed_players.push(pk_hex);
            }

            added_count += 1;
            tracing::info!(
                "[bridge::populate] table {} seat {} populated from chain: wallet={}",
                socket_table_id,
                seat_idx,
                wallet
            );
        }
    } // 写锁释放

    if added_count > 0 || updated_count > 0 {
        tracing::info!(
            "[bridge::populate] table {} seats populated: {} added, {} updated",
            socket_table_id,
            added_count,
            updated_count
        );
    }
}

/// 将链上玩家行动事件同步到 GameState 中对应玩家。
///
/// 解析路径：sui_table_id + seat_index → summary 参数 → seat_players[seat_index]
/// → 钱包地址（规范化为小写）→ GameState 中扫描 table →
/// get_pk_hex_by_wallet_address → pk_hex → ActionRequest 通道 → game loop process_action。
///
/// 问题9（TOCTOU）说明：本函数在释放 GameState 读锁后再通过 channel 触发行动，
/// 理论上存在 TOCTOU 窗口；但 game loop 单线程串行消费 ActionRequest，且在
/// process_action 内部会再次校验当前轮次 / 玩家 / 行动合法性，因此接受现状。
///
/// 问题13（幂等）：通过 seat.folded 检查避免重复触发已 fold 玩家的行动，
/// 避免重复 actions_taken 自增。
async fn apply_player_action_to_socket(
    app_state: &Arc<AppState>,
    sui_table_id: &str,
    seat_index: u64,
    action: &str,
    amount: Option<u64>,
    summary: &TableSummaryV2,
    original_event: Option<&SuiChainEvent>,
) {
    // 1. 从 summary 参数中根据 seat_index 解析玩家钱包地址
    let wallet = {
        let idx = seat_index as usize;
        if idx >= summary.meta.seat_players.len() {
            tracing::warn!(
                "[bridge::action] seat_index {} out of range (len={}) for table {}",
                seat_index,
                summary.meta.seat_players.len(),
                sui_table_id
            );
            return;
        }
        // 问题12: 钱包地址规范化为小写，避免大小写不匹配
        // seat_players 现为 [u8; 32]（Move address），需转为 0x 前缀的 hex 字符串
        format!("0x{}", hex::encode(&summary.meta.seat_players[idx])).to_lowercase()
    };

    if wallet.is_empty() {
        tracing::warn!(
            "[bridge::action] empty wallet at seat {} table {}",
            seat_index,
            sui_table_id
        );
        return;
    }

    // 2. 在 GameState 中定位包含该钱包的 table，解析 pk_hex 并做幂等检查
    let (socket_table_id, pk_hex) = {
        let gs = app_state.socket_state.state.read().await;
        let mut found = None;
        for (tid, table) in gs.tables.iter() {
            if let Some(pk) = table.get_pk_hex_by_wallet_address(&wallet) {
                // 问题13: 幂等检查，避免重复触发已 fold 玩家的行动
                if let Some(seat) = table.find_player_by_pk(&pk) {
                    match action {
                        "fold" if seat.folded => {
                            tracing::debug!(
                                "[bridge::action] player {} already folded, skip fold",
                                wallet
                            );
                            return;
                        }
                        "check" | "call" | "raise" | "allin" if seat.folded => {
                            tracing::debug!(
                                "[bridge::action] player {} folded, skip {}",
                                wallet,
                                action
                            );
                            return;
                        }
                        _ => {}
                    }
                }
                found = Some((*tid, pk));
                break;
            }
        }
        match found {
            Some(v) => v,
            None => {
                tracing::warn!(
                    "[bridge::action] wallet {} not found in any socket table",
                    wallet
                );
                return;
            }
        }
    };

    // 3. 通过 game loop 的 ActionRequest 通道触发行动，
    //    复用 process_action 完成的行动 + handle_turn_advance + broadcast 全流程
    match app_state.socket_state.get_action_sender(socket_table_id).await {
        Some(sender) => match sender
            .send(ActionRequest {
                pk_hex,
                action: action.to_string(),
                amount,
            })
            .await
        {
            Ok(()) => {
                tracing::info!(
                    "[bridge::action] forwarded {} to game loop: table={}, wallet={}",
                    action,
                    socket_table_id,
                    wallet
                );
            }
            Err(e) => {
                // Task 11: game_loop 通道关闭 - 不丢弃事件，回退到纯同步模式
                tracing::warn!(
                    "[bridge::action] game loop channel closed for table={}, {} falling back to pure sync: {}",
                    socket_table_id,
                    action,
                    e
                );
                // 强制同步下注状态（bypass is_player_action 跳过）
                sync_table_state(app_state, sui_table_id, false, false, summary).await;
                // 推入重试队列，等待 game_loop 恢复后重试
                if let Some(evt) = original_event {
                    push_action_retry(app_state, evt.clone());
                }
            }
        },
        None => {
            // Task 11: game_loop 未运行 - 不丢弃事件，回退到纯同步模式
            tracing::warn!(
                "[bridge::action] no game loop running for table={}, {} falling back to pure sync (no active hand)",
                socket_table_id,
                action
            );
            // 强制同步下注状态（bypass is_player_action 跳过）
            sync_table_state(app_state, sui_table_id, false, false, summary).await;
            // 推入重试队列，等待 game_loop 启动后重试
            if let Some(evt) = original_event {
                push_action_retry(app_state, evt.clone());
            }
        }
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
async fn locate_socket_table_by_chain_id(
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

/// Task 2: 将链上 PlayerJoined 事件同步到内存 Table。
///
/// 从 `summary` 参数读取 TableSummaryV2，反序列化 seat_pks[seat_index] → GamePkHex，
/// 在 GameState 中定位 socket table（通过 chain_table_id），将玩家加入 table.players /
/// seats / pk_to_seat，标记 shuffle 完成，广播 player_update + TABLE_UPDATED，
/// 若所有玩家完成 shuffle 且 >= MIN_START_NUM 则启动 game loop。
async fn apply_player_joined_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    player_wallet: &str,
    buy_in: u64,
    is_waiting: bool,
    _active_count_after: u64,
    summary: &TableSummaryV2,
    tx_digest: Option<&str>,
) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::join] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 从 summary 参数读取 TableSummaryV2（已通过参数传入）

    // 3. 从 summary.crypto.seat_pks[seat_index] 反序列化 G1 compressed bytes → GamePkHex
    let idx = seat_index as usize;
    tracing::info!(
        "[bridge::join] table={} seat_pks.len()={}, seat_index={}, seat_players.len()={}",
        table_id,
        summary.crypto.seat_pks.len(),
        seat_index,
        summary.meta.seat_players.len()
    );
    if idx >= summary.crypto.seat_pks.len() {
        tracing::warn!(
            "[bridge::join] seat_index {} out of range (seat_pks len={}) for table {}",
            seat_index,
            summary.crypto.seat_pks.len(),
            table_id
        );
        return;
    }
    let pk_hex = match deserialize_pk_hex(&summary.crypto.seat_pks[idx]) {
        Some(pk) => pk,
        None => {
            tracing::warn!(
                "[bridge::join] seat {} pk deserialization failed for table {}",
                seat_index,
                table_id
            );
            return;
        }
    };

    // 4. 从 summary.meta.seat_players[seat_index] 获取 wallet address（规范化为小写）
    let wallet = if idx < summary.meta.seat_players.len() {
        let sp = &summary.meta.seat_players[idx];
        if sp.iter().all(|&b| b == 0) {
            // 全零地址表示空座位，回退到 player_wallet 参数
            normalize_wallet(player_wallet)
        } else {
            normalize_wallet(&format!("0x{}", hex::encode(sp)))
        }
    } else {
        normalize_wallet(player_wallet)
    };

    // 5. 定位 socket table + 6. 幂等检查（seat 级：同 seat 同 pk_hex 视为已处理）
    let socket_table_id = {
        let gs = app_state.socket_state.state.read().await;
        let mut found = None;
        for (tid, table) in gs.tables.iter() {
            if table.chain_table_id.as_deref() == Some(table_id) {
                found = Some(*tid);
                break;
            }
        }
        match found {
            Some(tid) => {
                // 幂等：若该 seat 已被同一 pk_hex 占用，跳过
                if let Some(table) = gs.tables.get(&tid) {
                    if let Some(seat) = table.seats().get(&(seat_index as u32)) {
                        if seat.player.as_ref().map(|p| p.pk_hex.as_str()) == Some(pk_hex.as_str()) {
                            tracing::debug!(
                                "[bridge::join] seat {} already occupied by same pk_hex in table {}, skip",
                                seat_index,
                                tid
                            );
                            return;
                        }
                    }
                }
                tid
            }
            None => {
                tracing::warn!(
                    "[bridge::join] socket table not found for chain_table_id={}, available tables={:?}",
                    table_id,
                    gs.tables.iter()
                        .filter_map(|(tid, t)| t.chain_table_id.as_ref().map(|c| (tid, c)))
                        .collect::<Vec<_>>()
                );
                return;
            }
        }
    };

    // 7. 从 gs.players 查找 Player（含 name / bankroll）；若未找到，从 DB 查找
    let player_info = {
        let gs = app_state.socket_state.state.read().await;
        gs.players
            .values()
            .find(|p| normalize_wallet(&p.wallet_address.0) == wallet)
            .map(|p| (p.name.clone(), p.bankroll))
        // 释放读锁后处理 None 分支（避免跨 await 持锁）
    };
    let (player_name, player_bankroll) = if let Some((n, b)) = player_info {
        (n, b)
    } else {
        // 从 DB 查找
        match app_state.db.find_user_by_address(&wallet).await {
            Some(user) => (user.name, 0),
            None => {
                // 创建最小 Player：用 wallet 地址作为 name
                (truncate_name(&wallet, 12), 0)
            }
        }
    };

    // 8-12. 修改内存 Table（写锁）
    let all_shuffled = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => {
                tracing::warn!(
                    "[bridge::join] table {} disappeared during write lock",
                    socket_table_id
                );
                return;
            }
        };

        // 8. 调用 table.add_player 加入 table.players
        let _ = table.add_player(pk_hex.clone(), WalletAddress::new(wallet.clone()));

        // 9. 设置 table.pk_to_seat
        table.pk_to_seat.insert(pk_hex.clone(), seat_index as u32);

        // 10. 初始化 table.seats[seat_index]
        let game_player = GamePlayer {
            name: truncate_name(&player_name, 12),
            bankroll: player_bankroll,
            pk_hex: pk_hex.clone(),
            readable_hands: vec![],
            wallet_address: WalletAddress::new(wallet.clone()),
        };
        let mut seat = Seat::new(seat_index as u32, Some(game_player), buy_in, buy_in);
        seat.is_waiting = is_waiting;
        table.local_seats.insert(seat_index as u32, seat);

        // 11. 标记 shuffle 完成（链上 join_and_shuffle 已包含 shuffle）
        if !table.shuffle_state.completed_players.contains(&pk_hex) {
            table.shuffle_state.completed_players.push(pk_hex.clone());
        }

        // 12. 同步 chain_table_id（若未设置）
        if table.chain_table_id.is_none() {
            table.chain_table_id = Some(table_id.to_string());
        }

        // 12b. 同步 summary.meta / summary.crypto 到 table.summary
        // 必须在 broadcast_to_table 之前同步，否则 table.players() 从旧 summary
        // 读取玩家列表，新加入的玩家不在广播范围内，前端收不到 TABLE_UPDATED。
        if table.summary.meta != summary.meta {
            table.summary.meta = summary.meta.clone();
        }
        if table.summary.crypto != summary.crypto {
            table.summary.crypto = summary.crypto.clone();
        }

        // 检查是否所有活跃玩家都已完成 shuffle 且 >= MIN_START_NUM
        let all_shuffled = table.shuffle_state.pending_players.is_empty()
            && table.shuffle_state.completed_players.len() >= MIN_START_NUM as usize;

        // tracing::info!(
        //     "[bridge::join] player {} joined table {} seat {}, all_shuffled={}",
        //     wallet,
        //     socket_table_id,
        //     seat_index,
        //     all_shuffled
        // );

        all_shuffled
    }; // 写锁释放

    // 13. 广播 player_update（action=join）
    broadcast::broadcast_player_update(
        &io,
        socket_table_id as u64,
        "join",
        seat_index,
        pk_hex.to_string(),
        wallet.clone(),
        buy_in,
        0,
        format!("Player joined seat {}", seat_index),
    )
    .await;

    // 14. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Player joined"),
    )
    .await;

    // 15. ZK 可视化：shuffle 证明验证成功（链上 join_and_shuffle 已包含 shuffle）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::Shuffle,
            pk_hex.to_string(),
            None,
            true,
            Some("shuffle verified".to_string()),
            tx_digest.map(|s| s.to_string()),
        )
        .await;

    // 16. 若所有玩家完成 shuffle 且 >= MIN_START_NUM → 启动 game loop
    if all_shuffled {
        tracing::info!(
            "[bridge::join] all players shuffled, starting game loop for table {}",
            socket_table_id
        );
        app_state
            .socket_state
            .start_game_loop(io, app_state.socket_state.clone(), socket_table_id)
            .await;
    }
}

/// Task 3: 将链上 PlayerLeft 事件同步到内存 Table。
///
/// 通过 seat_index 查找 pk_hex，调用 table.leave_talbe_and_clear_shuffle 移除玩家，
/// 广播 player_update（action=leave）+ TABLE_UPDATED，
/// 若剩余活跃玩家 <= 1 则停止 game loop + clear_for_one_player。
async fn apply_player_left_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    player_wallet: &str,
) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::leave] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::leave] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3-5. 查找 pk_hex + 幂等检查 + 移除玩家
    let (pk_hex, wallet, should_stop) = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // 3. 通过 seat_index 查找 pk_hex
        let pk_hex = table
            .seats()
            .get(&(seat_index as u32))
            .and_then(|seat| seat.player.as_ref())
            .map(|p| p.pk_hex.clone())
            .or_else(|| {
                table
                    .pk_to_seat
                    .iter()
                    .find(|(_, sid)| **sid == seat_index as u32)
                    .map(|(pk, _)| pk.clone())
            });

        let pk_hex = match pk_hex {
            Some(pk) => pk,
            None => {
                tracing::debug!(
                    "[bridge::leave] no pk_hex found for seat {} in table {}",
                    seat_index,
                    socket_table_id
                );
                return;
            }
        };

        // 4. 幂等：若 pk_hex 不在 table.players 中，跳过
        if !table.players().contains_key(&pk_hex) {
            tracing::debug!(
                "[bridge::leave] pk_hex {} not in table {}, skip",
                pk_hex,
                socket_table_id
            );
            return;
        }

        let wallet = table
            .players()
            .get(&pk_hex)
            .map(|w| w.0.clone())
            .unwrap_or_else(|| normalize_wallet(player_wallet));

        // 5. 调用 table.leave_talbe_and_clear_shuffle 移除玩家
        table.leave_talbe_and_clear_shuffle(&pk_hex);

        // 检查剩余活跃玩家是否 <= 1
        let should_stop = table.active_players().len() <= 1;

        (pk_hex, wallet, should_stop)
    }; // 写锁释放

    // 6. 广播 player_update（action=leave）
    broadcast::broadcast_player_update(
        &io,
        socket_table_id as u64,
        "leave",
        seat_index,
        pk_hex.to_string(),
        wallet,
        0,
        0,
        "Player left".to_string(),
    )
    .await;

    // 7. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Player left"),
    )
    .await;

    // 8. 若活跃玩家 <= 1 → 停止 game loop + clear_for_one_player
    if should_stop {
        tracing::info!(
            "[bridge::leave] active players <= 1, stopping game loop for table {}",
            socket_table_id
        );
        app_state.socket_state.stop_game_loop(socket_table_id).await;
        game_loop::clear_for_one_player(&io, app_state.socket_state.clone(), socket_table_id).await;
    }
}

/// Task 4: 将链上 PlayerKicked 事件同步到内存 Table。
///
/// 复用 Task 3 的定位与移除逻辑，广播 player_update（action=kick, reason）。
async fn apply_player_kicked_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    player_wallet: &str,
    reason: u64,
) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::kick] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::kick] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3-5. 查找 pk_hex + 幂等检查 + 移除玩家
    let (pk_hex, wallet, should_stop) = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // 3. 通过 seat_index 查找 pk_hex
        let pk_hex = table
            .seats()
            .get(&(seat_index as u32))
            .and_then(|seat| seat.player.as_ref())
            .map(|p| p.pk_hex.clone())
            .or_else(|| {
                table
                    .pk_to_seat
                    .iter()
                    .find(|(_, sid)| **sid == seat_index as u32)
                    .map(|(pk, _)| pk.clone())
            });

        let pk_hex = match pk_hex {
            Some(pk) => pk,
            None => {
                tracing::debug!(
                    "[bridge::kick] no pk_hex found for seat {} in table {}",
                    seat_index,
                    socket_table_id
                );
                return;
            }
        };

        // 4. 幂等：若 pk_hex 不在 table.players 中，跳过
        if !table.players().contains_key(&pk_hex) {
            tracing::debug!(
                "[bridge::kick] pk_hex {} not in table {}, skip",
                pk_hex,
                socket_table_id
            );
            return;
        }

        let wallet = table
            .players()
            .get(&pk_hex)
            .map(|w| w.0.clone())
            .unwrap_or_else(|| normalize_wallet(player_wallet));

        // 5. 调用 table.leave_talbe_and_clear_shuffle 移除玩家
        table.leave_talbe_and_clear_shuffle(&pk_hex);

        // 检查剩余活跃玩家是否 <= 1
        let should_stop = table.active_players().len() <= 1;

        (pk_hex, wallet, should_stop)
    }; // 写锁释放

    // 6. 广播 player_update（action=kick, reason）
    broadcast::broadcast_player_update(
        &io,
        socket_table_id as u64,
        "kick",
        seat_index,
        pk_hex.to_string(),
        wallet,
        0,
        reason,
        format!("Player kicked (reason={})", reason),
    )
    .await;

    // 7. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Player kicked"),
    )
    .await;

    // 8. 若活跃玩家 <= 1 → 停止 game loop + clear_for_one_player
    if should_stop {
        tracing::info!(
            "[bridge::kick] active players <= 1, stopping game loop for table {}",
            socket_table_id
        );
        app_state.socket_state.stop_game_loop(socket_table_id).await;
        game_loop::clear_for_one_player(&io, app_state.socket_state.clone(), socket_table_id).await;
    }
}

/// Task 5 / Task 18: 将链上 PlayerRefund 事件同步到内存 Table。
///
/// Task 18 修复：在广播前修改内存 Table 的 seat.stack（所有 refund_type 均增加 stack），
/// 并同步 summary.meta.seat_stacks[seat_index]。广播 player_update（action=refund）。
async fn apply_player_refund_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    player_wallet: &str,
    amount: u64,
    refund_type: u64,
) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::refund] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table（用于获取 socket_table_id 进行广播）
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::refund] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // Task 18: 3. 修改内存 Table.seat.stack（所有 refund_type: 0=stack_only, 1=stack_and_bet, 2=bet_only 均增加 stack）
    {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            let seat_id = seat_index as u32;
            if let Some(seat) = table.local_seats.get_mut(&seat_id) {
                let old_stack = seat.stack;
                seat.stack += amount;
                tracing::info!(
                    "[bridge::refund] table {} seat {} stack: {} -> {} (amount={}, refund_type={})",
                    socket_table_id,
                    seat_index,
                    old_stack,
                    seat.stack,
                    amount,
                    refund_type
                );
            } else {
                tracing::warn!(
                    "[bridge::refund] seat {} not found in table {}, skip stack update",
                    seat_index,
                    socket_table_id
                );
            }

            // 同步 summary.meta.seat_stacks[seat_index]
            let idx = seat_index as usize;
            if idx < table.summary.meta.seat_stacks.len() {
                let old = table.summary.meta.seat_stacks[idx];
                table.summary.meta.seat_stacks[idx] = old + amount;
                tracing::debug!(
                    "[bridge::refund] table {} summary.meta.seat_stacks[{}]: {} -> {}",
                    socket_table_id,
                    idx,
                    old,
                    table.summary.meta.seat_stacks[idx]
                );
            }
        }
    } // 写锁释放

    // 4. 广播 player_update（action=refund, buy_in=amount, reason=refund_type）
    broadcast::broadcast_player_update(
        &io,
        socket_table_id as u64,
        "refund",
        seat_index,
        String::new(),
        normalize_wallet(player_wallet),
        amount,
        refund_type,
        "Player refunded".to_string(),
    )
    .await;
}

/// Task 6: 将链上 HandStarted 事件同步到内存 Table。
///
/// 确保 game loop 已启动，广播 TABLE_UPDATED。
async fn apply_hand_started_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 7: 将链上 ShuffleComplete 事件同步到内存 Table。
///
/// 若 shuffle_state 活跃，调用 table.advance_shuffle() 推进 shuffle，
/// 发送 shuffle_notice，广播 TABLE_UPDATED。
async fn apply_shuffle_complete_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 8: 将链上 RevealPhaseEvt 事件同步为 reveal notice 广播。
///
/// 当链上 RevealPhaseEvt 到达时，本地可能尚未调用 start_*_reveal_phase
/// （例如最后一个玩家的 shuffle 在链上完成，本地 advance_shuffle 未触发），
/// 导致 reveal_token_state.phase 已由 sync 同步但 pending_players/player_assignments 为空。
///
/// 修复方案：参考 Move 合约 start_preflop_reveal_phase / start_community_reveal_phase /
/// start_showdown_reveal_phase 的分配逻辑，从链上 summary 重建 player_assignments
/// （按用户拆分），确保广播携带完整数据，玩家可据此提交 REVEAL_TOKEN。
async fn apply_reveal_phase_evt_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    chain_phase: u8,
    summary: Option<&TableSummaryV2>,
) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::reveal] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reveal] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3. 若 reveal_token_state 已激活但 pending_players 为空，说明本地未执行 start_*_reveal_phase，
    //    需根据链上 summary 重建 assignments（按用户拆分），否则前端收到的 REVEAL_NOTICE 无数据。
    let need_populate = {
        let gs = app_state.socket_state.state.read().await;
        gs.tables
            .get(&socket_table_id)
            .map(|t| t.reveal_token_state.is_active() && t.reveal_token_state.pending_players.is_empty())
            .unwrap_or(false)
    };

    if need_populate {
        // 3a. 获取 summary：优先用事件携带的 summary，否则从 table.summary 读取（已由 sync 同步）
        let summary_owned: TableSummaryV2;
        let summary_ref: &TableSummaryV2 = if let Some(s) = summary {
            s
        } else {
            let gs = app_state.socket_state.state.read().await;
            if let Some(table) = gs.tables.get(&socket_table_id) {
                summary_owned = table.summary.clone();
                &summary_owned
            } else {
                tracing::warn!(
                    "[bridge::reveal] table {} not found for summary fallback, skip populate",
                    socket_table_id
                );
                game_loop::broadcast_reveal_notice_if_active(&io, &app_state.socket_state, socket_table_id).await;
                return;
            }
        };

        // 3b. 从 summary 重建 reveal_token_state
        let rust_phase = RevealPhase::from_chain_u8(chain_phase);
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            match rust_phase {
                Some(RevealPhase::HandReveal) => {
                    if let Err(e) = rebuild_hand_reveal_from_summary(table, summary_ref, chain_phase) {
                        tracing::warn!("[bridge::reveal] rebuild HandReveal failed: {}", e);
                    } else {
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for HandReveal, pending={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.player_assignments.len()
                        );
                    }
                }
                Some(RevealPhase::CommunityReveal) => {
                    if let Err(e) = rebuild_community_reveal_from_summary(table, summary_ref, chain_phase) {
                        tracing::warn!("[bridge::reveal] rebuild CommunityReveal failed: {}", e);
                    } else {
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for CommunityReveal, pending={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.player_assignments.len()
                        );
                    }
                }
                Some(RevealPhase::ShowdownReveal) => {
                    if let Err(e) = rebuild_showdown_reveal_from_summary(table, summary_ref) {
                        tracing::warn!("[bridge::reveal] rebuild ShowdownReveal failed: {}", e);
                    } else {
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for ShowdownReveal, pending={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.player_assignments.len()
                        );
                    }
                }
                Some(RevealPhase::RedealReveal) => {
                    tracing::warn!(
                        "[bridge::reveal] RedealReveal phase cannot be auto-populated (requires redeal context), chain_phase={}",
                        chain_phase
                    );
                }
                Some(RevealPhase::None) | None => {
                    tracing::warn!(
                        "[bridge::reveal] inactive or unknown chain phase: {}, skipping populate",
                        chain_phase
                    );
                }
            }
        }
    }

    // 4. 广播 reveal_notice
    game_loop::broadcast_reveal_notice_if_active(&io, &app_state.socket_state, socket_table_id).await;
}

/// 从链上 summary 重建 HandReveal（preflop）阶段的 reveal_token_state。
///
/// 对齐 Move `start_preflop_reveal_phase`：
/// - 活跃座位 = seats_occupied[i] && !seat_is_waiting[i]
/// - 每个活跃玩家发 2 张牌，从 cards_dealt - active_count*2 开始
/// - 每个玩家的 pending = 所有活跃玩家（牌主需为自己以外的牌提交 token）
/// - player_assignments[pk] = 其他所有活跃玩家的手牌密文（不含自己的牌）
fn rebuild_hand_reveal_from_summary(
    table: &mut crate::pokergame::table::Table,
    summary: &TableSummaryV2,
    _chain_phase: u8,
) -> Result<(), String> {
    use crate::pokergame::game_state::{PlayerRevealAssignment, RevealTokenState};

    const CARDS_PER_PLAYER: usize = 2;

    // 1. 获取活跃座位列表（对齐 Move get_active_seat_indices）
    let active_seats: Vec<u64> = active_seat_indices_from_summary(&summary.meta);
    if active_seats.is_empty() {
        return Err("no active seats for HandReveal".to_string());
    }

    // 2. 构建 seat_index -> GamePkHex 映射
    let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

    // 3. 获取加密牌组（优先从 summary.crypto.deck_encrypted 反序列化）
    let deck = table.deck_encrypted();
    if deck.is_empty() {
        return Err("deck_encrypted is empty".to_string());
    }

    // 4. 计算手牌起始索引：cards_dealt - active_count * cards_per_player
    let active_count = active_seats.len() as u64;
    let cards_dealt = summary.state.cards_dealt;
    if cards_dealt < active_count * CARDS_PER_PLAYER as u64 {
        return Err(format!(
            "cards_dealt {} < active_count*{} = {}",
            cards_dealt,
            CARDS_PER_PLAYER,
            active_count * CARDS_PER_PLAYER as u64
        ));
    }
    let hand_start = (cards_dealt - active_count * CARDS_PER_PLAYER as u64) as usize;

    // 5. 按 Move 逻辑为每个活跃玩家分配手牌索引
    //    active_seats[0] 的牌在 [hand_start, hand_start+2)
    //    active_seats[1] 的牌在 [hand_start+2, hand_start+4)
    //    ...
    let mut seat_hand_cards: HashMap<u64, Vec<poker_protocol::crypto::ElGamalCiphertext>> = HashMap::new();
    for (order, &seat_idx) in active_seats.iter().enumerate() {
        let base = hand_start + order * CARDS_PER_PLAYER;
        let mut cards = Vec::with_capacity(CARDS_PER_PLAYER);
        for i in 0..CARDS_PER_PLAYER {
            if base + i < deck.len() {
                cards.push(deck[base + i].clone());
            } else {
                return Err(format!(
                    "card index {} out of deck range {}",
                    base + i,
                    deck.len()
                ));
            }
        }
        seat_hand_cards.insert(seat_idx, cards);
    }

    // 6. 构建 pending_players（所有活跃玩家的 pk）
    let pending_players: Vec<GamePkHex> = active_seats
        .iter()
        .filter_map(|&seat_idx| seat_pk_map.get(&seat_idx).cloned())
        .collect();

    // 7. 构建 player_assignments：每个玩家的 assignment = 其他所有活跃玩家的手牌
    //    （对齐 Rust start_preflop_reveal_phase：pk 需为其他玩家的牌提交 reveal token）
    let mut player_assignments: HashMap<GamePkHex, PlayerRevealAssignment> = HashMap::new();
    for &my_seat in &active_seats {
        let my_pk = match seat_pk_map.get(&my_seat) {
            Some(pk) => pk.clone(),
            None => continue,
        };
        let mut hand_card = Vec::new();
        for &other_seat in &active_seats {
            if other_seat == my_seat {
                continue;
            }
            if let Some(cards) = seat_hand_cards.get(&other_seat) {
                hand_card.extend(cards.iter().cloned());
            }
        }
        player_assignments.insert(my_pk, PlayerRevealAssignment {
            hand_card,
            community_card: vec![],
        });
    }

    // 8. 写入 reveal_token_state
    table.reveal_token_state = RevealTokenState {
        phase: RevealPhase::HandReveal,
        current_card_index: 0,
        total_cards_per_player: CARDS_PER_PLAYER,
        total_community_cards: 5,
        timeout_start: Some(std::time::Instant::now()),
        timeout_seconds: 10,
        completed_players: Vec::new(),
        pending_players,
        player_assignments,
    };

    Ok(())
}

/// 从链上 summary 重建 CommunityReveal（flop/turn/river）阶段的 reveal_token_state。
///
/// 对齐 Move `start_community_reveal_phase`：
/// - 活跃座位 = seats_occupied[i] && !seat_is_waiting[i]
/// - 发 count 张公共牌（flop=3, turn=1, river=1），从 cards_dealt - count 开始
/// - 每张公共牌的 pending = 所有活跃玩家
/// - player_assignments[pk] = 本阶段发出的所有公共牌密文（所有玩家相同）
fn rebuild_community_reveal_from_summary(
    table: &mut crate::pokergame::table::Table,
    summary: &TableSummaryV2,
    chain_phase: u8,
) -> Result<(), String> {
    use crate::pokergame::game_state::{PlayerRevealAssignment, RevealTokenState};

    // 1. 获取活跃座位列表
    let active_seats: Vec<u64> = active_seat_indices_from_summary(&summary.meta);
    if active_seats.is_empty() {
        return Err("no active seats for CommunityReveal".to_string());
    }

    // 2. 构建 seat_index -> GamePkHex 映射
    let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

    // 3. 获取加密牌组
    let deck = table.deck_encrypted();
    if deck.is_empty() {
        return Err("deck_encrypted is empty".to_string());
    }

    // 4. 计算本阶段公共牌数量：flop=3, turn=1, river=1
    let count: usize = match chain_phase {
        3 => 3, // flop
        4 => 1, // turn
        5 => 1, // river
        _ => return Err(format!("invalid community chain_phase: {}", chain_phase)),
    };

    // 5. 计算公共牌起始索引：cards_dealt - count
    let cards_dealt = summary.state.cards_dealt;
    if cards_dealt < count as u64 {
        return Err(format!(
            "cards_dealt {} < count {}",
            cards_dealt, count
        ));
    }
    let comm_start = (cards_dealt - count as u64) as usize;

    // 6. 提取本阶段的公共牌密文
    let mut community_cards: Vec<poker_protocol::crypto::ElGamalCiphertext> = Vec::with_capacity(count);
    for i in 0..count {
        if comm_start + i < deck.len() {
            community_cards.push(deck[comm_start + i].clone());
        } else {
            return Err(format!(
                "community card index {} out of deck range {}",
                comm_start + i,
                deck.len()
            ));
        }
    }

    // 7. 构建 pending_players（所有活跃玩家的 pk）
    let pending_players: Vec<GamePkHex> = active_seats
        .iter()
        .filter_map(|&seat_idx| seat_pk_map.get(&seat_idx).cloned())
        .collect();

    // 8. 构建 player_assignments：每个玩家的 assignment = 本阶段所有公共牌
    //    （对齐 Rust start_community_reveal_phase：所有玩家需为公共牌提交 reveal token）
    let mut player_assignments: HashMap<GamePkHex, PlayerRevealAssignment> = HashMap::new();
    for &seat_idx in &active_seats {
        let pk = match seat_pk_map.get(&seat_idx) {
            Some(pk) => pk.clone(),
            None => continue,
        };
        player_assignments.insert(pk, PlayerRevealAssignment {
            hand_card: vec![],
            community_card: community_cards.clone(),
        });
    }

    // 9. 写入 reveal_token_state
    table.reveal_token_state = RevealTokenState {
        phase: RevealPhase::CommunityReveal,
        current_card_index: 0,
        total_cards_per_player: 0,
        total_community_cards: 5,
        timeout_start: Some(std::time::Instant::now()),
        timeout_seconds: 10,
        completed_players: Vec::new(),
        pending_players,
        player_assignments,
    };

    Ok(())
}

/// 从链上 summary 重建 ShowdownReveal 阶段的 reveal_token_state。
///
/// 对齐 Move `start_showdown_reveal_phase`：
/// - 仅未 fold 的活跃玩家参与
/// - 每个玩家的手牌需揭示，pending = 牌主自己（只有牌主需提交 token）
/// - player_assignments[pk] = pk 自己的手牌密文
///
/// 注意：ShowdownReveal 使用部分解密密文（decrypted_cards），summary 中不直接包含
/// 这些数据。此处从 deck_encrypted 中按手牌索引重建（近似处理），若 mental_poker_game
/// 已有 hand_encrypted 则优先使用。
fn rebuild_showdown_reveal_from_summary(
    table: &mut crate::pokergame::table::Table,
    summary: &TableSummaryV2,
) -> Result<(), String> {
    use crate::pokergame::game_state::{PlayerRevealAssignment, RevealTokenState};

    const CARDS_PER_PLAYER: usize = 2;

    // 1. 获取未 fold 的活跃座位列表
    let active_seats: Vec<u64> = active_seat_indices_from_summary(&summary.meta);
    let non_folded_seats: Vec<u64> = active_seats
        .iter()
        .filter(|&&seat_idx| {
            let i = seat_idx as usize;
            i < summary.meta.seat_folded.len() && !summary.meta.seat_folded[i]
        })
        .copied()
        .collect();
    if non_folded_seats.is_empty() {
        return Err("no non-folded active seats for ShowdownReveal".to_string());
    }

    // 2. 构建 seat_index -> GamePkHex 映射
    let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

    // 3. 优先从 mental_poker_game 获取手牌（部分解密密文）
    //    若 mental_poker_game 无数据，则从 deck_encrypted 按索引重建
    let active_count = active_seats.len() as u64;
    let cards_dealt = summary.state.cards_dealt;
    let deck = table.deck_encrypted();

    let hand_start = if cards_dealt >= active_count * CARDS_PER_PLAYER as u64 {
        (cards_dealt - active_count * CARDS_PER_PLAYER as u64) as usize
    } else {
        return Err(format!(
            "cards_dealt {} < active_count*{} for showdown",
            cards_dealt,
            CARDS_PER_PLAYER
        ));
    };

    // 4. 构建 pending_players（所有未 fold 的活跃玩家）
    let pending_players: Vec<GamePkHex> = non_folded_seats
        .iter()
        .filter_map(|&seat_idx| seat_pk_map.get(&seat_idx).cloned())
        .collect();

    // 5. 构建 player_assignments：每个玩家的 assignment = 自己的手牌
    //    （对齐 Rust start_showdown_reveal_phase：牌主需为自己的牌提交 reveal token）
    let mut player_assignments: HashMap<GamePkHex, PlayerRevealAssignment> = HashMap::new();
    for (order, &seat_idx) in active_seats.iter().enumerate() {
        // 只为未 fold 的玩家构建 assignment
        if !non_folded_seats.contains(&seat_idx) {
            continue;
        }
        let pk = match seat_pk_map.get(&seat_idx) {
            Some(pk) => pk.clone(),
            None => continue,
        };

        // 优先从 mental_poker_game 获取手牌
        let hand_card: Vec<poker_protocol::crypto::ElGamalCiphertext> =
            if let Some(mp_player) = table.mental_poker_game.players.get(pk.0.as_str()) {
                if !mp_player.hand_encrypted.is_empty() {
                    mp_player.hand_encrypted.iter().map(|f| f.encrypted_card.clone()).collect()
                } else {
                    // mental_poker_game 无手牌，从 deck_encrypted 按索引重建
                    extract_hand_from_deck(&deck, hand_start, order, CARDS_PER_PLAYER)?
                }
            } else {
                // mental_poker_game 无该玩家，从 deck_encrypted 按索引重建
                extract_hand_from_deck(&deck, hand_start, order, CARDS_PER_PLAYER)?
            };

        player_assignments.insert(pk, PlayerRevealAssignment {
            hand_card,
            community_card: vec![],
        });
    }

    // 6. 写入 reveal_token_state
    table.reveal_token_state = RevealTokenState {
        phase: RevealPhase::ShowdownReveal,
        current_card_index: 0,
        total_cards_per_player: CARDS_PER_PLAYER,
        total_community_cards: 5,
        timeout_start: Some(std::time::Instant::now()),
        timeout_seconds: 10,
        completed_players: Vec::new(),
        pending_players,
        player_assignments,
    };

    Ok(())
}

/// 从 summary.meta 提取活跃座位索引列表（对齐 Move get_active_seat_indices）。
///
/// 活跃 = seats_occupied[i] && !seat_is_waiting[i]
fn active_seat_indices_from_summary(meta: &crate::sui_events::TableSummaryMeta) -> Vec<u64> {
    let mut result = Vec::new();
    for i in 0..meta.seats_occupied.len() {
        if meta.seats_occupied[i] && !meta.seat_is_waiting[i] {
            result.push(i as u64);
        }
    }
    result
}

/// 从 deck_encrypted 中按 order 提取指定玩家的手牌。
fn extract_hand_from_deck(
    deck: &[poker_protocol::crypto::ElGamalCiphertext],
    hand_start: usize,
    order: usize,
    cards_per_player: usize,
) -> Result<Vec<poker_protocol::crypto::ElGamalCiphertext>, String> {
    let base = hand_start + order * cards_per_player;
    let mut cards = Vec::with_capacity(cards_per_player);
    for i in 0..cards_per_player {
        if base + i < deck.len() {
            cards.push(deck[base + i].clone());
        } else {
            return Err(format!(
                "hand card index {} out of deck range {}",
                base + i,
                deck.len()
            ));
        }
    }
    Ok(cards)
}

/// Task 8: 将链上 ReconstructInitiated 事件同步为 reconstruct notice 广播。
async fn apply_reconstruct_initiated_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 8: 将链上 CommunityCardRevealed 事件同步为 community reveal 广播。
async fn apply_community_card_revealed_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::community] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 community cards（broadcast_community_cards 内部获取 io）
    app_state.socket_state.broadcast_community_cards(socket_table_id).await;
}

// ============================================================================
// Task 20: 新增事件处理器
//
// 以下函数为 Task 20 新增，处理之前落入 `_ => {}` catch-all 的事件。
// 所有广播复用 actions.rs 中已有的 socket 事件常量，不新增常量。
// ============================================================================

/// Task 20: ShuffleVerified 事件处理器。
///
/// 标记玩家在 `shuffle_state.completed_players` 中（通过 seat_index → pk_hex），
/// 广播 `CRYPTO_EVENT`（event_type="shuffle", verified=true）。
async fn apply_shuffle_verified_to_socket(
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
async fn apply_shuffle_turn_to_socket(
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
async fn apply_shuffle_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 20: RevealTokenSubmitted 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reveal_token", card_index from event, verified=true）。
async fn apply_reveal_token_submitted_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    seat_index: u64,
    card_index: u64,
    tx_digest: Option<&str>,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reveal_token] socket table not found for chain_table_id={}",
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

    // 3. 广播 CRYPTO_EVENT（event_type="reveal_token", card_index, verified=true）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::RevealToken,
            pk_hex,
            Some(card_index as u32),
            true,
            Some("reveal token submitted".to_string()),
            tx_digest.map(|s| s.to_string()),
        )
        .await;
}

/// Task 20: RevealPhaseComplete 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
async fn apply_reveal_phase_complete_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 获取 SocketIo 实例
    let io = match get_socket_io() {
        Some(io) => io,
        None => {
            tracing::debug!("[bridge::reveal_complete] socket.io not initialized, skip");
            return;
        }
    };

    // 2. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reveal_complete] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 3. 广播 TABLE_UPDATED
    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Reveal phase complete"),
    )
    .await;
}

/// Task 20: CardIsIdentity 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reveal_token", message="identity_card"）。
async fn apply_card_is_identity_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    card_index: u64,
) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::card_identity] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 CRYPTO_EVENT（event_type="reveal_token", message="identity_card"）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::RevealToken,
            String::new(),
            Some(card_index as u32),
            true,
            Some("identity_card".to_string()),
            None,
        )
        .await;
}

/// Task 20: IdentityRedeal 事件处理器。
///
/// 广播 `REDEAL_NOTICE`（复用 broadcast_redeal_notice）。
async fn apply_identity_redeal_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::identity_redeal] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 REDEAL_NOTICE（复用 broadcast_redeal_notice）
    app_state.socket_state.broadcast_redeal_notice(socket_table_id).await;
}

/// Task 20: RevealTimeout 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reveal_token", verified=false, message="timeout"）。
async fn apply_reveal_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
    // 1. 定位 socket table
    let socket_table_id = match locate_socket_table_by_chain_id(app_state, table_id).await {
        Some(tid) => tid,
        None => {
            tracing::warn!(
                "[bridge::reveal_timeout] socket table not found for chain_table_id={}",
                table_id
            );
            return;
        }
    };

    // 2. 广播 CRYPTO_EVENT（event_type="reveal_token", verified=false, message="timeout"）
    app_state
        .socket_state
        .broadcast_crypto_event(
            socket_table_id,
            CryptoEventType::RevealToken,
            String::new(),
            None,
            false,
            Some("timeout".to_string()),
            None,
        )
        .await;
}

/// Task 20: BettingRoundStarted 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
async fn apply_betting_round_started_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_pot_collected_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_round_advanced_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_winner_awarded_to_socket(
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
/// 写入 `table.win_messages`，广播 `TABLE_UPDATED` 和 `WINNER`。
async fn apply_hand_ended_without_showdown_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    winner_seat: u64,
    winner_player: &str,
    pot: u64,
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

    // 1. 写入 table.win_messages
    let win_message = {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

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

/// Task 20: HandSettled 事件处理器。
///
/// 广播 `TABLE_UPDATED`。
async fn apply_hand_settled_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

    broadcast::broadcast_to_table(
        &io,
        &app_state.socket_state,
        socket_table_id,
        Some("Hand settled"),
    )
    .await;
}

/// Task 20: ReconstructDeckSubmitted 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reconstruct", verified=true）。
async fn apply_reconstruct_deck_submitted_to_socket(
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
async fn apply_reconstruct_complete_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_reconstruct_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 20: HandReset 事件处理器。
///
/// 调用 `table.reset_for_next_hand()`，广播 `TABLE_UPDATED`。
async fn apply_hand_reset_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_blinds_posted_to_socket(
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
async fn apply_showdown_hole_cards_revealed_to_socket(
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
async fn apply_timeout_config_updated_to_socket(
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
async fn apply_deck_rebuilt_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
async fn apply_current_turn_changed_to_socket(
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

/// 构建 seat_index → GamePkHex 映射表。
///
/// 遍历链上 `seat_pks`（每个座位的 G1 compressed bytes），将非空 pk 转换为
/// hex 字符串（GamePkHex），返回 `seat_index → GamePkHex` 映射。
/// 空 pk（未入座或已离开的座位）会被跳过。
pub(crate) fn build_seat_pk_map(seat_pks: &[Vec<u8>]) -> HashMap<u64, crate::pokergame::player::GamePkHex> {
    use poker_protocol::crypto::curve::CurvePoint;
    use poker_protocol::crypto::DefaultCurve;
    type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

    let mut map = HashMap::new();
    for (idx, pk_bytes) in seat_pks.iter().enumerate() {
        if pk_bytes.is_empty() {
            continue;
        }
        // G1 compressed bytes → EcPoint → hex string
        match <P as CurvePoint>::from_compressed(pk_bytes) {
            Some(pt) => {
                let hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&pt);
                map.insert(idx as u64, crate::pokergame::player::GamePkHex::new(hex));
            }
            None => {
                tracing::warn!(
                    "[bridge::sync] seat {} pk deserialization failed (invalid G1 bytes), skipping",
                    idx
                );
            }
        }
    }
    map
}

/// 将 seat_index 列表转换为 GamePkHex 列表。
///
/// 使用 `build_seat_pk_map` 生成的映射表，将链上的 `vector<u64>`（seat_index 列表）
/// 转换为 `Vec<GamePkHex>`。映射中不存在的 index 会被跳过。
fn seat_indices_to_pk_hex(
    indices: &[u64],
    seat_pk_map: &HashMap<u64, crate::pokergame::player::GamePkHex>,
) -> Vec<crate::pokergame::player::GamePkHex> {
    indices
        .iter()
        .filter_map(|&idx| seat_pk_map.get(&idx).cloned())
        .collect()
}

/// 将链上 TableSummary 快照同步到 GameState 中的对应 table。
///
/// `is_player_action` 为 `true` 时，跳过下注状态（pot / seat_bets / seat_stacks /
/// betting_round）的同步，避免与 game_loop 的 process_action 产生双重应用竞态（D4）。
/// round_state / shuffle / reveal / reconstruct 等阶段状态仍会同步。
///
/// `force_sync_crypto` 为 `true` 时，无条件同步 `table.summary.crypto` 字段，
/// 用于牌组变化事件（ShuffleTurn / RevealPhaseEvt / ReconstructInitiated 等），
/// 避免因 shuffle_active / chain_reconstruct_active 条件不满足而跳过 crypto 同步。
async fn sync_table_state(
    app_state: &Arc<AppState>,
    sui_table_id: &str,
    is_player_action: bool,
    force_sync_crypto: bool,
    summary: &TableSummaryV2,
) {
    // 1. 链上快照通过 summary 参数传入

    // 2. 将链上 round_state (u8) 映射为本地 RoundState 枚举
    let chain_round = RoundState::from_u8(summary.meta.round_state).unwrap_or(RoundState::Waiting);

    // 3. 在 GameState 中定位 socket table
    // 问题8: 优先用 chain_table_id 精确匹配，回退到钱包重叠匹配（避免多桌玩家误匹配）
    // 问题12: 钱包匹配时统一 to_lowercase()
    let socket_table_id = {
        let gs = app_state.socket_state.state.read().await;
        // 3a. 精确匹配 chain_table_id
        let mut found = None;
        for (tid, table) in gs.tables.iter() {
            if table.chain_table_id.as_deref() == Some(sui_table_id) {
                found = Some(*tid);
                break;
            }
        }
        // 3b. 回退：钱包重叠匹配（仅当精确匹配未命中时）
        if found.is_none() {
            for (tid, table) in gs.tables.iter() {
                let has_match = table.players().values().any(|w| {
                    !w.0.is_empty()
                        && summary
                            .meta
                            .seat_players
                            .iter()
                            .any(|sp| format!("0x{}", hex::encode(sp)).to_lowercase() == w.0.to_lowercase())
                });
                if has_match {
                    found = Some(*tid);
                    break;
                }
            }
        }
        match found {
            Some(id) => id,
            None => return,
        }
    };

    // Task 13: 检查 game_loop 是否运行（用于决定是否跳过玩家行动的下注同步）
    // 在 GameState 写锁外获取，避免与 start_game_loop 的锁顺序产生死锁。
    let game_loop_running = {
        let registry = app_state.socket_state.game_loop_registry.read().await;
        registry.contains(socket_table_id)
    };
    // active_count == 0 时需要在写锁释放后停止 game_loop
    let mut should_stop_game_loop = false;

    // 4. 同步状态（写锁）
    {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // active_count == 0 时仅停止 game_loop（牌局已结束，无活跃玩家）。
        // 不清空 players/seats/pk_to_seat：链上 active_count 仅统计
        // `player != @0x0 && !left_during_hand && !is_waiting` 的座位，
        // 坐庄外等待下一局的玩家仍应保留。
        // 玩家移除由 PlayerLeft/PlayerKicked 事件驱动，或由下方 seat 同步清理。
        if summary.meta.active_count == 0 {
            should_stop_game_loop = true;
        }

        // 4a-0. 同步 chain_table_id（上链模式下用户操作构建 PTB 时需要）
        if table.chain_table_id.as_deref() != Some(sui_table_id) {
            tracing::info!(
                "[bridge::sync] table {} chain_table_id set to {}",
                socket_table_id,
                sui_table_id
            );
            table.chain_table_id = Some(sui_table_id.to_string());
        }

        // 4a-0b. 批量同步 summary.meta 和 summary.state（链上是权威数据源）
        // 重构后 players() / seats() 访问器从 summary.meta.seat_* 派生数据，
        // 必须将链上 meta 完整同步到 table.summary.meta，否则访问器读到的是空数据。
        // state 同理：deck_plaintext() / 各类 timestamp 访问器依赖 summary.state。
        if table.summary.meta != summary.meta {
            table.summary.meta = summary.meta.clone();
        }
        if table.summary.state != summary.state {
            table.summary.state = summary.state.clone();
        }

        // 4a. 同步 round_state
        if table.round_state() != chain_round {
            tracing::info!(
                "[bridge::sync] table {} round_state: socket={:?} -> chain={:?}",
                socket_table_id,
                table.round_state(),
                chain_round
            );
            // 使用 transition_to_forced：链上 round_state 已由 Move 合约验证，
            // 跳过本地状态机校验，避免本地与链上状态分歧时卡死。
            table.transition_to_forced(chain_round);
        }

        // 4b. 同步 shuffle_state.phase
        // TableSummaryState 不再包含 shuffle_phase 字段（兼容性升级约束），
        // 改为通过 infer_shuffle_phase 从其他字段推断。
        let chain_shuffle_phase_u8 = crate::sui_query::infer_shuffle_phase(
            chain_round.to_u8(),
            summary.state.shuffle_pending_count,
            summary.state.shuffle_completed_count,
            summary.state.shuffle_current_shuffler,
        );
        let chain_shuffle_phase = crate::pokergame::game_state::ShufflePhase::from_u8(chain_shuffle_phase_u8)
            .unwrap_or(crate::pokergame::game_state::ShufflePhase::None);
        if table.shuffle_state.phase != chain_shuffle_phase {
            tracing::info!(
                "[bridge::sync] table {} shuffle_state.phase: {} -> {}",
                socket_table_id,
                table.shuffle_state.phase,
                chain_shuffle_phase
            );
            table.shuffle_state.phase = chain_shuffle_phase;
        }

        // // 通知前端 shuffle 状态已从链上同步
        // table.emit_event(TableEvent::CryptoEvent {
        //     event_type: CryptoEventType::Shuffle,
        //     player_pk: String::new(),
        //     card_index: None,
        //     verified: true,
        //     message: Some("shuffle state synced from chain".to_string()),
        // });

        // 4c. 同步 reveal_token_state.phase（对齐 Move reveal_phase）
        // 链上 reveal_phase != 0 表示活跃
        let should_reveal_active = summary.state.reveal_phase != 0;
        if should_reveal_active {
            if !table.reveal_token_state.is_active() {
                // phase 将在下面设置，此处仅标记需要激活
            }
            if let Some(chain_phase) = RevealPhase::from_chain_u8(summary.state.reveal_phase) {
                if table.reveal_token_state.phase != chain_phase {
                    tracing::info!(
                        "[bridge::sync] table {} reveal_phase: {:?} -> {:?}",
                        socket_table_id,
                        table.reveal_token_state.phase,
                        chain_phase
                    );
                    table.reveal_token_state.phase = chain_phase;
                }
            }
        } else if table.reveal_token_state.is_active() {
            tracing::info!(
                "[bridge::sync] table {} reveal_token_state deactivated (chain round={:?})",
                socket_table_id,
                chain_round
            );
            table.reveal_token_state.reset();
        }

        // // 通知前端 reveal token 状态已从链上同步
        // table.emit_event(TableEvent::CryptoEvent {
        //     event_type: CryptoEventType::RevealToken,
        //     player_pk: String::new(),
        //     card_index: None,
        //     verified: true,
        //     message: Some("reveal state synced from chain".to_string()),
        // });

        // 4d. 同步 reconstruct_state
        // 链上 reconstruct_phase: 0=None, 1=Collecting, 2=Complete
        // 活跃: Collecting(1)；非活跃: None(0) / Complete(2)
        let chain_reconstruct_active = summary.state.reconstruct_phase == 1;

        // 4d-1. 同步 deck_plaintext（从链上 G1 compressed bytes 反序列化为 EcPoint）
        // 必须在 start_reconstruct 之前完成，否则 reconstruct 使用的牌组与链上不一致，
        // 提交链上验证会失败。
        if !summary.state.deck_plaintext.is_empty() {
            use poker_protocol::crypto::curve::CurvePoint;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;
            let mut synced_deck: Vec<P> = Vec::with_capacity(summary.state.deck_plaintext.len());
            let mut all_ok = true;
            for bytes in &summary.state.deck_plaintext {
                match <P as CurvePoint>::from_compressed(bytes) {
                    Some(pt) => synced_deck.push(pt),
                    None => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if all_ok {
                // Task 15: 强制覆盖本地 deck_plaintext（即使长度不匹配）。
                // 合约是真理之源，长度不匹配通常意味着本地状态过期。
                if table.mental_poker_game.deck_plaintext != synced_deck {
                    tracing::info!(
                        "[bridge::sync] table {} deck_plaintext force overwritten from chain (local={} chain={})",
                        socket_table_id,
                        table.mental_poker_game.deck_plaintext.len(),
                        synced_deck.len()
                    );
                    table.mental_poker_game.deck_plaintext = synced_deck;
                }
            } else {
                // Task 15: 反序列化失败时保留本地值（最后手段回退）
                tracing::warn!(
                    "[bridge::sync] table {} deck_plaintext deserialization failed, keeping local value (len={})",
                    socket_table_id,
                    table.mental_poker_game.deck_plaintext.len()
                );
            }
        }

        // 4d-2. 同步加密状态（deck_encrypted / aggregated_pk / shuffle 玩家列表）
        // 仅在 shuffle 活跃时同步，避免非活跃阶段用空数据覆盖本地状态
        let shuffle_active = summary.state.shuffle_pending_count > 0
            || summary.state.shuffle_completed_count > 0
            || summary.state.shuffle_current_shuffler.is_some();

        // 4d-1b. 整体同步 summary.crypto 到 table.summary.crypto（上链模式权威数据源）
        // Task 14: 无条件同步 crypto（合约是真理之源，crypto 数据已在 summary 中，无额外 RPC 开销）
        if table.summary.crypto != summary.crypto {
            tracing::info!(
                "[bridge::sync] table {} crypto synced from chain (force={}, shuffle_active={}, reconstruct_active={})",
                socket_table_id,
                force_sync_crypto,
                shuffle_active,
                chain_reconstruct_active
            );
            table.summary.crypto = summary.crypto.clone();
        }

        if shuffle_active {
            // 构建 seat_index → pk_hex 映射表（供 shuffle/reconstruct 玩家列表转换用）
            let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

            // 同步 deck_encrypted（96 bytes: c1 || c2 → ElGamalCiphertext）
            if !summary.crypto.deck_encrypted.is_empty() {
                use poker_protocol::crypto::curve::CurvePoint;
                use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
                type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

                let mut synced_deck: Vec<ElGamalCiphertext> =
                    Vec::with_capacity(summary.crypto.deck_encrypted.len());
                let mut all_ok = true;
                for ct_bytes in &summary.crypto.deck_encrypted {
                    if ct_bytes.len() != 96 {
                        all_ok = false;
                        break;
                    }
                    let (c1_bytes, c2_bytes) = ct_bytes.split_at(48);
                    match (
                        <P as CurvePoint>::from_compressed(c1_bytes),
                        <P as CurvePoint>::from_compressed(c2_bytes),
                    ) {
                        (Some(c1), Some(c2)) => synced_deck.push(ElGamalCiphertext { c1, c2 }),
                        _ => {
                            all_ok = false;
                            break;
                        }
                    }
                }
                if all_ok {
                    if table.mental_poker_game.deck_encrypted != synced_deck {
                        tracing::info!(
                            "[bridge::sync] table {} deck_encrypted synced from chain ({} cards)",
                            socket_table_id,
                            synced_deck.len()
                        );
                        table.mental_poker_game.deck_encrypted = synced_deck;
                    }
                } else {
                    tracing::warn!(
                        "[bridge::sync] table {} deck_encrypted sync failed: invalid ciphertext bytes",
                        socket_table_id
                    );
                }
            }

            // 同步 aggregated_pk（48 bytes G1 compressed → EcPoint → key_manager）
            if !summary.crypto.aggregated_pk.is_empty() {
                use poker_protocol::crypto::curve::CurvePoint;
                use poker_protocol::crypto::DefaultCurve;
                type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

                if let Some(pk) =
                    <P as CurvePoint>::from_compressed(&summary.crypto.aggregated_pk)
                {
                    let current_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
                    if current_pk != pk {
                        tracing::info!(
                            "[bridge::sync] table {} aggregated_pk synced from chain",
                            socket_table_id
                        );
                        table.mental_poker_game.key_manager.set_aggregated_pk(pk);
                    }
                } else {
                    tracing::warn!(
                        "[bridge::sync] table {} aggregated_pk deserialization failed",
                        socket_table_id
                    );
                }
            }

            // 同步 shuffle_pending_players / shuffle_completed_players（seat_index → pk_hex）
            let chain_pending =
                seat_indices_to_pk_hex(&summary.crypto.shuffle_pending_players, &seat_pk_map);
            let chain_completed = seat_indices_to_pk_hex(
                &summary.crypto.shuffle_completed_players,
                &seat_pk_map,
            );
            if table.shuffle_state.pending_players != chain_pending {
                tracing::info!(
                    "[bridge::sync] table {} shuffle_pending_players synced from chain ({} players)",
                    socket_table_id,
                    chain_pending.len()
                );
                table.shuffle_state.pending_players = chain_pending;
            }
            if table.shuffle_state.completed_players != chain_completed {
                tracing::info!(
                    "[bridge::sync] table {} shuffle_completed_players synced from chain ({} players)",
                    socket_table_id,
                    chain_completed.len()
                );
                table.shuffle_state.completed_players = chain_completed;
            }
        }

        if chain_reconstruct_active && !table.reconstruct_state.is_active {
            tracing::info!(
                "[bridge::sync] table {} reconstruct activating (chain phase={})",
                socket_table_id,
                summary.state.reconstruct_phase
            );
            if let Err(e) = table.start_reconstruct() {
                tracing::warn!(
                    "[bridge::sync] table {} start_reconstruct failed: {}",
                    socket_table_id,
                    e
                );
            }
        } else if !chain_reconstruct_active && table.reconstruct_state.is_active {
            tracing::info!(
                "[bridge::sync] table {} reconstruct deactivating (chain phase={})",
                socket_table_id,
                summary.state.reconstruct_phase
            );
            table.reconstruct_state.reset();
        }

        // 4d-3. 同步 reconstruct 加密状态（coefficient / pending / completed 玩家列表）
        // 仅在 reconstruct 活跃（phase != 0）时同步，避免覆盖
        if summary.state.reconstruct_phase != 0 {
            let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

            // 同步 reconstruct_coefficient（32 bytes scalar → Scalar）
            if !summary.crypto.reconstruct_coefficient.is_empty() {
                use poker_protocol::crypto::CurveScalar;
                use poker_protocol::crypto::DefaultCurve;
                type S = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar;

                let scalar = S::from_bytes_mod_order(&summary.crypto.reconstruct_coefficient);
                // 比较前先获取当前值的 bytes（Scalar 是 Copy，无 PartialEq 比较直接用 as_bytes）
                let current_bytes = table.reconstruct_state.coefficient.as_bytes();
                if current_bytes != scalar.as_bytes() {
                    tracing::info!(
                        "[bridge::sync] table {} reconstruct_coefficient synced from chain",
                        socket_table_id
                    );
                    table.reconstruct_state.coefficient = scalar;
                }
            }

            // 同步 reconstruct_pending_players / reconstruct_completed_players
            let chain_pending = seat_indices_to_pk_hex(
                &summary.crypto.reconstruct_pending_players,
                &seat_pk_map,
            );
            let chain_completed = seat_indices_to_pk_hex(
                &summary.crypto.reconstruct_completed_players,
                &seat_pk_map,
            );
            if table.reconstruct_state.pending_players != chain_pending {
                tracing::info!(
                    "[bridge::sync] table {} reconstruct_pending_players synced from chain ({} players)",
                    socket_table_id,
                    chain_pending.len()
                );
                table.reconstruct_state.pending_players = chain_pending;
            }
            if table.reconstruct_state.completed_players != chain_completed {
                tracing::info!(
                    "[bridge::sync] table {} reconstruct_completed_players synced from chain ({} players)",
                    socket_table_id,
                    chain_completed.len()
                );
                table.reconstruct_state.completed_players = chain_completed;
            }
        }

        // // 通知前端 reconstruct 状态已从链上同步
        // table.emit_event(TableEvent::CryptoEvent {
        //     event_type: CryptoEventType::Reconstruct,
        //     player_pk: String::new(),
        //     card_index: None,
        //     verified: true,
        //     message: Some("reconstruct state synced from chain".to_string()),
        // });

        // 4e. 同步下注状态（pot / button / current_turn / betting_round_* / seat 级别字段）
        // Task 13: 在所有 round_state 下同步下注状态（包括 Waiting / HandComplete），
        // 合约是真理之源。
        // D4 修复：仅在玩家行动事件且 game_loop 运行时跳过，避免与 process_action 竞态。
        // 若 game_loop 未运行，则无条件同步（即使 is_player_action==true）。
        if !is_player_action || !game_loop_running {
            // pot
            if table.pot() != summary.meta.pot {
                tracing::info!(
                    "[bridge::sync] table {} pot: {} -> {}",
                    socket_table_id,
                    table.pot(),
                    summary.meta.pot
                );
                table.set_pot(summary.meta.pot);
            }
            // button
            let chain_button = summary.meta.button as u32;
            if table.button() != Some(chain_button) {
                table.set_button(Some(chain_button));
            }
            // current_turn
            let prev_turn = table.turn();
            table.set_turn(summary.meta.current_turn.map(|t| t as u32));
            // 同步 seat.turn：前端依赖 seat.turn 显示行动面板和倒计时。
            // set_turn 仅更新 summary.meta.current_turn，不会自动同步 seat.turn，
            // 因此在此处显式同步，确保链上轮到行动的玩家 seat.turn = true。
            let current_turn = table.turn();
            for (seat_id, seat) in table.local_seats.iter_mut() {
                seat.turn = current_turn == Some(*seat_id);
            }
            // 进入下注轮且 betting_started_at 未设置时，初始化计时器。
            // 链上 betting_started_at 由 tick 函数延迟设置，事件到达时可能仍为 0，
            // 导致 check_betting_timeout 跳过超时检查、前端无倒计时。
            if current_turn.is_some() && table.betting_started_at() == 0 {
                table.set_betting_started_at(now_ms());
                tracing::info!(
                    "[bridge::sync] table {} betting_started_at initialized (turn={:?}, prev={:?})",
                    socket_table_id,
                    current_turn,
                    prev_turn
                );
            }
            // betting round
            table.summary.call_amount = if summary.meta.betting_round_current_bet > 0 {
                Some(summary.meta.betting_round_current_bet)
            } else {
                None
            };
            table.set_min_raise(summary.meta.betting_round_min_raise);
            table.summary.min_bet = summary.meta.betting_round_big_blind;

            // D3 修复：同步 betting_round 对象
            // 根据 betting_round_exists 创建/更新/销毁 table.betting_round
            if summary.meta.betting_round_exists {
                if table.betting_round.is_none() {
                    table.betting_round = Some(crate::pokergame::betting::BettingRound::new(
                        summary.meta.betting_round_big_blind,
                    ));
                    tracing::info!(
                        "[bridge::sync] table {} betting_round created (big_blind={})",
                        socket_table_id,
                        summary.meta.betting_round_big_blind
                    );
                }
                // BettingRound 的字段是私有的，无法直接赋值；通过 reset + 重建同步关键字段。
                // 这里采用销毁后重建的方式，确保与链上状态一致。
                let new_br = crate::pokergame::betting::BettingRound::new(
                    summary.meta.betting_round_big_blind,
                );
                table.betting_round = Some(new_br);
            } else {
                if table.betting_round.is_some() {
                    tracing::info!(
                        "[bridge::sync] table {} betting_round removed (chain reports no active betting round)",
                        socket_table_id
                    );
                }
                table.betting_round = None;
            }

            // seat 级别同步
            // 收集需要清理的本地座位（链上已清空 player=0x0 的座位）
            let mut pks_to_remove: Vec<crate::pokergame::player::GamePkHex> = Vec::new();
            let mut seats_to_remove: Vec<u32> = Vec::new();

            for (seat_idx, &chain_occupied) in summary.meta.seats_occupied.iter().enumerate() {
                let seat_id = seat_idx as u32;
                if !chain_occupied {
                    // 检查链上该座位是否已完全清空（player == 0x0）
                    // seats_occupied=false 可能是被踢玩家(left_during_hand)或空座位，
                    // 仅当 seat_players 也为 0x0 时才清理本地座位（被踢玩家保留到 reset_for_next_hand 后才清空）
                    let chain_player_empty = summary.meta.seat_players.get(seat_idx)
                        .map(|sp| sp.iter().all(|&b| b == 0))
                        .unwrap_or(true);
                    if chain_player_empty {
                        if let Some(seat) = table.local_seats.get(&seat_id) {
                            if let Some(player) = &seat.player {
                                pks_to_remove.push(player.pk_hex.clone());
                            }
                        }
                        seats_to_remove.push(seat_id);
                    }
                    continue;
                }
                if let Some(seat) = table.local_seats.get_mut(&seat_id) {
                    // stack
                    let chain_stack = summary.meta.seat_stacks.get(seat_idx).copied().unwrap_or(0);
                    if seat.stack != chain_stack {
                        seat.stack = chain_stack;
                    }
                    // bet
                    let chain_bet = summary.meta.seat_bets.get(seat_idx).copied().unwrap_or(0);
                    if seat.bet != chain_bet {
                        seat.bet = chain_bet;
                    }
                    // folded
                    let chain_folded = summary.meta.seat_folded.get(seat_idx).copied().unwrap_or(false);
                    if seat.folded != chain_folded {
                        seat.folded = chain_folded;
                    }
                    // is_waiting
                    let chain_waiting =
                        summary.meta.seat_is_waiting.get(seat_idx).copied().unwrap_or(false);
                    if seat.is_waiting != chain_waiting {
                        seat.is_waiting = chain_waiting;
                    }
                }
            }

            // 执行清理：移除链上已清空的本地座位
            for pk in &pks_to_remove {
                table.pk_to_seat.remove(pk);
            }
            for seat_id in &seats_to_remove {
                table.local_seats.remove(seat_id);
            }
            if !seats_to_remove.is_empty() {
                tracing::info!(
                    "[bridge::sync] table {} cleaned up {} zombie seats from local state",
                    socket_table_id,
                    seats_to_remove.len()
                );
            }
        }
    } // 写锁释放

    // Task 12: active_count == 0 时停止 game_loop（在写锁释放后执行，避免锁竞争）
    if should_stop_game_loop {
        tracing::info!(
            "[bridge::sync] table {} active_count=0, stopping game loop",
            socket_table_id
        );
        app_state.socket_state.stop_game_loop(socket_table_id).await;
    }
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
