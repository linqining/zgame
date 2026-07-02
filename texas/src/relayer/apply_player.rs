//! 玩家生命周期与行动事件同步函数。
//!
//! 将链上 PlayerJoined / PlayerLeft / PlayerKicked / PlayerRefund 事件
//! 以及玩家行动事件（Fold / Check / Call / Raise / AllIn）同步到内存 Table，
//! 并通过 socket 广播通知前端。

use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::player::{truncate_name, GamePlayer, WalletAddress};
use crate::pokergame::seat::Seat;
use crate::pokergame::table::events::CryptoEventType;
use crate::pokergame::table::ActionRequest;
use crate::socket::{broadcast, game_loop, get_socket_io, MIN_START_NUM};
use crate::sui_events::{SuiChainEvent, TableSummaryV2};

use crate::relayer::{
    deserialize_pk_hex, locate_socket_table_by_chain_id, normalize_wallet, push_action_retry,
    sync_table_state,
};

/// 处理玩家行动事件（PlayerFolded / PlayerChecked / PlayerCalled / PlayerRaised /
/// PlayerAllIn）的统一入口。
///
/// 这五种事件的处理逻辑高度相似：先通过 `check_and_mark_action` 去重，
/// 再调用 `apply_player_action_to_socket` 触发行动；若 summary 缺失则推入重试队列。
/// 本函数将差异点（`action_str` / `amount` / `event_name`）参数化，消除重复代码。
///
/// 行为与原 `apply_event_to_socket` 中五个内联 arm 完全一致：
/// - 去重命中：调用 `apply_player_action_to_socket`（summary 存在）或推入重试队列（summary 缺失）。
/// - 去重未命中：打印 debug 日志后跳过。
pub(crate) async fn handle_player_action_event(
    app_state: &Arc<AppState>,
    event: &SuiChainEvent,
    table_id: &str,
    seat_index: u64,
    round_state: u8,
    summary: Option<&TableSummaryV2>,
    action_str: &str,
    event_name: &str,
    amount: Option<u64>,
) {
    if app_state
        .check_and_mark_action(table_id, seat_index, action_str, round_state)
    {
        if let Some(s) = summary {
            apply_player_action_to_socket(
                app_state,
                table_id,
                seat_index,
                action_str,
                amount,
                s,
                Some(event),
            )
            .await;
        } else {
            tracing::warn!(
                "[bridge::action] {} summary is None, push to retry queue: table={}, seat={}",
                event_name,
                table_id,
                seat_index
            );
            push_action_retry(app_state, event.clone());
        }
    } else {
        tracing::debug!(
            "[bridge::action] duplicate {} event skipped: table={}, seat={}",
            event_name,
            table_id,
            seat_index
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
pub(crate) async fn apply_player_action_to_socket(
    app_state: &Arc<AppState>,
    sui_table_id: &str,
    seat_index: u64,
    action: &str,
    amount: Option<u64>,
    summary: &TableSummaryV2,
    original_event: Option<&SuiChainEvent>,
) -> bool {
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
            return true;
        }
        let sp = &summary.meta.seat_players[idx];
        // 全零地址表示空座位（summary 过期或玩家已离开），
        // 无法定位玩家，跳过避免误查 0x0000...0000。
        if sp.iter().all(|&b| b == 0) {
            tracing::warn!(
                "[bridge::action] seat {} in table {} has zero address in summary (stale snapshot or player left), skip {}",
                seat_index,
                sui_table_id,
                action
            );
            return true;
        }
        // 问题12: 钱包地址规范化为小写，避免大小写不匹配
        // seat_players 现为 [u8; 32]（Move address），需转为 0x 前缀的 hex 字符串
        format!("0x{}", hex::encode(sp)).to_lowercase()
    };

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
                            return true;
                        }
                        "check" | "call" | "raise" | "allin" if seat.folded => {
                            tracing::debug!(
                                "[bridge::action] player {} folded, skip {}",
                                wallet,
                                action
                            );
                            return true;
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
                return true;
            }
        }
    };

    // 3. 通过 game loop 的 ActionRequest 通道触发行动，
    //    复用 process_action 完成的行动 + handle_turn_advance + broadcast 全流程
    // 返回值约定：true = 已处理（含提前跳过 / 已转发 / 已推入重试队列），
    //             false = game_loop 不可用且未自行推入重试队列，由调用方决定是否重试。
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
                true
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
                    true
                } else {
                    false
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
                true
            } else {
                false
            }
        }
    }
}

/// Task 2: 将链上 PlayerJoined 事件同步到内存 Table。
///
/// 从 `summary` 参数读取 TableSummaryV2，反序列化 seat_pks[seat_index] → GamePkHex，
/// 在 GameState 中定位 socket table（通过 chain_table_id），将玩家加入 table.players /
/// seats / pk_to_seat，标记 shuffle 完成，广播 player_update + TABLE_UPDATED，
/// 若所有玩家完成 shuffle 且 >= MIN_START_NUM 则启动 game loop。
pub(crate) async fn apply_player_joined_to_socket(
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
pub(crate) async fn apply_player_left_to_socket(
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
pub(crate) async fn apply_player_kicked_to_socket(
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
pub(crate) async fn apply_player_refund_to_socket(
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
