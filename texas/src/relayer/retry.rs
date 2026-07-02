//! 玩家行动事件重试队列。
//!
//! 当玩家行动事件因 `summary=None` 或 game_loop 通道关闭而无法立即处理时，
//! 会被推入 `AppState.action_retry_queue` 等待重试。
//!
//! 主要入口：
//! - [`run_action_retry_loop`]：后台循环，每 5 秒调用 `process_action_retry_queue`
//! - [`process_action_retry_queue`]：处理到期事件，最多重试 3 次
//! - [`push_action_retry`]：将失败事件推入队列（由 `apply_event_to_socket` 调用）

use std::sync::Arc;

use crate::handlers::AppState;
use crate::relayer::event_classify::{event_type_name, table_id_from_event};
use crate::relayer::util::now_ms;
use crate::sui_events::SuiChainEvent;

/// 重试队列后台循环的间隔（毫秒）= 5 秒。
const ACTION_RETRY_INTERVAL_MS: u64 = 5000;
/// 单个事件的最大重试次数，超过后触发 sync_table_state 兜底。
const ACTION_MAX_RETRIES: u8 = 3;

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

/// Task 10: 将失败的玩家行动事件推入重试队列。
///
/// 初始 `retry_count=0`，`next_retry_at=now_ms()`（立即可重试）。
pub(crate) fn push_action_retry(app_state: &Arc<AppState>, event: SuiChainEvent) {
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
        if item.retry_count >= ACTION_MAX_RETRIES {
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
                crate::relayer::sync_table_state(app_state, &table_id, false, false, &s).await;
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
            item.next_retry_at = now_ms() + ACTION_RETRY_INTERVAL_MS;
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
        crate::relayer::apply_player_joined_to_socket(
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
    // 传 None 作为 original_event：避免内部再次推入重试队列造成死循环，
    // 由本函数的返回值决定是否递增 retry_count 继续重试。
    crate::relayer::apply_player_action_to_socket(
        app_state,
        &table_id,
        seat_index,
        action,
        amount,
        &summary,
        None,
    )
    .await
}
