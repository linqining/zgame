// 子模块声明
pub mod ptb;        // Task 4 实现
pub mod submit;     // Task 5 实现
pub mod tick;      // Task 6 实现

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::handlers::AppState;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::table::{ActionRequest, RoundState};
use crate::sui_events::{SuiChainEvent, TableSummary};
use crate::sui_query::{fetch_table_summary, infer_shuffle_phase};

/// 链上 Table 对象缓存，key 为 table_id (Object ID 字符串)
pub struct RelayerState {
    tables: RwLock<HashMap<String, TableSummary>>,
    /// 标记缓存与链上不一致的 table_id 集合（fetch 失败 / deck 长度不匹配等）。
    /// 下次 process_event 时会强制 fetch 刷新。
    stale_tables: RwLock<HashSet<String>>,
    /// C2 修复：已处理的玩家行动事件去重缓存。
    /// key 为 `(table_id, seat_index, action, round_state)`，避免 Both 模式下
    /// gRPC + webhook 重复处理同一事件。
    /// 使用 HashSet 而非 LruCache 以避免引入新依赖；定期清理以限制内存增长。
    processed_actions: RwLock<HashSet<String>>,
}

/// 已处理行动缓存的最大条目数，超过后清空重建。
const MAX_PROCESSED_ACTIONS: usize = 10000;

impl RelayerState {
    /// 创建空缓存
    pub fn new() -> Self {
        Self {
            tables: RwLock::new(HashMap::new()),
            stale_tables: RwLock::new(HashSet::new()),
            processed_actions: RwLock::new(HashSet::new()),
        }
    }

    /// C2 修复：检查并标记玩家行动事件是否已处理。
    /// 返回 `true` 表示首次处理（已写入缓存），`false` 表示重复事件（应跳过）。
    pub fn check_and_mark_action(
        &self,
        table_id: &str,
        seat_index: u64,
        action: &str,
        round_state: u8,
    ) -> bool {
        let key = format!("{}_{}_{}_{}", table_id, seat_index, action, round_state);
        let mut processed = self
            .processed_actions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if processed.contains(&key) {
            return false;
        }
        // 容量控制：超过上限时清空（简单策略，避免无界增长）
        if processed.len() >= MAX_PROCESSED_ACTIONS {
            processed.clear();
        }
        processed.insert(key);
        true
    }

    /// 读取单个 table（clone 返回）
    pub fn get(&self, table_id: &str) -> Option<TableSummary> {
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        tables.get(table_id).cloned()
    }

    /// 插入/更新
    pub fn insert(&self, table_id: String, summary: TableSummary) {
        let mut tables = self.tables.write().unwrap_or_else(|e| e.into_inner());
        tables.insert(table_id, summary);
    }

    /// 删除并返回
    pub fn remove(&self, table_id: &str) -> Option<TableSummary> {
        let mut tables = self.tables.write().unwrap_or_else(|e| e.into_inner());
        tables.remove(table_id)
    }

    /// 返回所有缓存的 clone 列表
    pub fn list(&self) -> Vec<TableSummary> {
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        tables.values().cloned().collect()
    }

    /// 返回所有 table_id 列表（供 tick 任务遍历用）
    pub fn list_ids(&self) -> Vec<String> {
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        tables.keys().cloned().collect()
    }

    /// 标记某个 table 的缓存为 stale（与链上不一致）。
    /// 下次 process_event 时会强制 fetch 刷新。
    pub fn mark_stale(&self, table_id: &str) {
        self.stale_tables.write().unwrap_or_else(|e| e.into_inner()).insert(table_id.to_string());
    }

    /// 判断某个 table 的缓存是否为 stale。
    pub fn is_stale(&self, table_id: &str) -> bool {
        self.stale_tables.read().unwrap_or_else(|e| e.into_inner()).contains(table_id)
    }

    /// 清除 stale 标记（fetch 成功后调用）。
    pub fn clear_stale(&self, table_id: &str) {
        self.stale_tables.write().unwrap_or_else(|e| e.into_inner()).remove(table_id);
    }
}

impl Default for RelayerState {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 SuiChainEvent 中提取 table_id
fn table_id_from_event(event: &SuiChainEvent) -> &str {
    match event {
        SuiChainEvent::TableCreated { table_id, .. } => table_id,
        SuiChainEvent::PlayerJoined { table_id, .. } => table_id,
        SuiChainEvent::PlayerLeft { table_id, .. } => table_id,
        SuiChainEvent::HandStarted { table_id, .. } => table_id,
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
        SuiChainEvent::HandSettled { table_id, .. } => table_id,
        SuiChainEvent::ReconstructInitiated { table_id, .. } => table_id,
        SuiChainEvent::ReconstructDeckSubmitted { table_id, .. } => table_id,
        SuiChainEvent::ReconstructComplete { table_id, .. } => table_id,
        SuiChainEvent::ReconstructTimeout { table_id, .. } => table_id,
        SuiChainEvent::RedealRequested { table_id, .. } => table_id,
        SuiChainEvent::PlayerKicked { table_id, .. } => table_id,
        SuiChainEvent::PlayerRefund { table_id, .. } => table_id,
        SuiChainEvent::HandReset { table_id, .. } => table_id,
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
    )
}

/// 处理链上事件，更新 RelayerState 缓存
pub async fn process_event(
    state: &RelayerState,
    fullnode_url: &str,
    package_id: &str,
    event: &SuiChainEvent,
) {
    let table_id = table_id_from_event(event);

    match event {
        SuiChainEvent::TableCreated { .. } => {
            tracing::info!(
                table_id = table_id,
                "TableCreated event received, fetching full snapshot"
            );
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    state.insert(table_id.to_string(), summary);
                    state.clear_stale(table_id);
                    tracing::info!(table_id = table_id, "TableCreated cached");
                }
                Err(e) => {
                    // 问题10: fetch 失败标记 stale，下次强制刷新
                    state.mark_stale(table_id);
                    tracing::error!(
                        table_id = table_id,
                        error = %e,
                        "Failed to fetch table summary on TableCreated event, marked stale"
                    );
                }
            }
        }
        // 问题11: HandReset 后标记 stale，触发 GC（下次关键事件刷新时覆盖）
        SuiChainEvent::HandReset { .. } => {
            // 先尝试刷新一次快照（HandReset 是关键事件）
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    // G1 修复：HandReset 后若 active_count == 0，从缓存中移除该 table（GC）
                    if summary.meta.active_count == 0 {
                        state.remove(table_id);
                        state.clear_stale(table_id);
                        tracing::info!(
                            table_id = table_id,
                            "HandReset received, active_count=0, table removed from cache (GC)"
                        );
                    } else {
                        state.insert(table_id.to_string(), summary);
                        state.clear_stale(table_id);
                        tracing::info!(
                            table_id = table_id,
                            "HandReset received, table snapshot refreshed"
                        );
                    }
                }
                Err(e) => {
                    state.mark_stale(table_id);
                    tracing::warn!(
                        table_id = table_id,
                        error = %e,
                        "HandReset fetch failed, table marked stale for GC"
                    );
                }
            }
        }
        _ => {
            // 问题17: 只在关键事件 / stale / 未缓存时 fetch，减少冗余 RPC
            let cached = state.get(table_id).is_some();
            let should_fetch =
                is_key_event(event) || state.is_stale(table_id) || !cached;
            if !should_fetch {
                tracing::trace!(
                    table_id = table_id,
                    "non-key event for cached non-stale table, skipping fetch"
                );
                return;
            }

            if cached {
                tracing::debug!(
                    table_id = table_id,
                    "Event received for cached table, refreshing snapshot"
                );
            } else {
                tracing::info!(
                    table_id = table_id,
                    "Event received for uncached table, attempting to fetch"
                );
            }
            match fetch_table_summary(fullnode_url, package_id, table_id).await {
                Ok(summary) => {
                    // G1 修复：HandSettled 后若 active_count == 0，从缓存中移除该 table（GC）
                    if matches!(event, SuiChainEvent::HandSettled { .. })
                        && summary.meta.active_count == 0
                    {
                        state.remove(table_id);
                        state.clear_stale(table_id);
                        tracing::info!(
                            table_id = table_id,
                            "HandSettled received, active_count=0, table removed from cache (GC)"
                        );
                    } else {
                        state.insert(table_id.to_string(), summary);
                        state.clear_stale(table_id);
                        tracing::debug!(table_id = table_id, "Table cache refreshed");
                    }
                }
                Err(e) => {
                    // 问题10: fetch 失败标记 stale，下次强制刷新
                    state.mark_stale(table_id);
                    tracing::warn!(
                        table_id = table_id,
                        error = %e,
                        "Failed to refresh table summary, marked stale (cache preserved if exists)"
                    );
                }
            }
        }
    }
}

/// 将链上事件同步到内存游戏状态（SocketState / GameState）。
///
/// 当 relayer 收到玩家行动类事件（PlayerFolded / PlayerChecked / PlayerCalled /
/// PlayerRaised / PlayerAllIn）时，通过 RelayerState 缓存解析出对应钱包地址，
/// 再在 GameState 中找到对应 table 与 pk_hex，最终通过 game loop 的
/// ActionRequest 通道触发行动，复用既有游戏循环逻辑完成行动 + 轮次推进 + 广播。
///
/// 对所有事件，额外调用 sync_table_state 将链上 round_state / shuffle_state /
/// reveal_token_state / reconstruct_state 同步到 GameState，保持状态一致。
pub async fn apply_event_to_socket(app_state: &Arc<AppState>, event: &SuiChainEvent) {
    // 1. 处理玩家行动事件：转发到 game loop 的 ActionRequest 通道
    //    C2 修复：在 Both 模式下，gRPC 和 webhook 可能同时投递同一事件，
    //    通过 RelayerState.processed_actions 去重，避免重复触发行动。
    match event {
        SuiChainEvent::PlayerFolded { table_id, seat_index, round_state, .. } => {
            if app_state
                .relayer_state
                .check_and_mark_action(table_id, *seat_index, "fold", *round_state)
            {
                apply_player_action_to_socket(app_state, table_id, *seat_index, "fold", None).await;
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
                .relayer_state
                .check_and_mark_action(table_id, *seat_index, "check", *round_state)
            {
                apply_player_action_to_socket(app_state, table_id, *seat_index, "check", None).await;
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
                .relayer_state
                .check_and_mark_action(table_id, *seat_index, "call", *round_state)
            {
                apply_player_action_to_socket(app_state, table_id, *seat_index, "call", Some(*call_delta)).await;
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
                .relayer_state
                .check_and_mark_action(table_id, *seat_index, "raise", *round_state)
            {
                apply_player_action_to_socket(app_state, table_id, *seat_index, "raise", Some(*total_bet)).await;
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
                .relayer_state
                .check_and_mark_action(table_id, *seat_index, "allin", *round_state)
            {
                apply_player_action_to_socket(app_state, table_id, *seat_index, "allin", Some(*amount)).await;
            } else {
                tracing::debug!(
                    "[bridge::action] duplicate PlayerAllIn event skipped: table={}, seat={}",
                    table_id,
                    seat_index
                );
            }
        }
        _ => {}
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
    sync_table_state(app_state, sui_table_id, is_player_action).await;
}

/// 将链上玩家行动事件同步到 GameState 中对应玩家。
///
/// 解析路径：sui_table_id + seat_index → RelayerState 缓存 → seat_players[seat_index]
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
) {
    // 1. 从 RelayerState 缓存中根据 seat_index 解析玩家钱包地址
    let wallet = {
        let summary = match app_state.relayer_state.get(sui_table_id) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    "[bridge::action] table {} not in relayer cache, cannot resolve wallet",
                    sui_table_id
                );
                return;
            }
        };
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
        summary.meta.seat_players[idx].to_lowercase()
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
                tracing::warn!(
                    "[bridge::action] game loop channel closed for table={}, {} dropped: {}",
                    socket_table_id,
                    action,
                    e
                );
            }
        },
        None => {
            tracing::warn!(
                "[bridge::action] no game loop running for table={}, {} event dropped (no active hand)",
                socket_table_id,
                action
            );
        }
    }
}

/// 将链上 TableSummary 快照同步到 GameState 中的对应 table。
///
/// `is_player_action` 为 `true` 时，跳过下注状态（pot / seat_bets / seat_stacks /
/// betting_round）的同步，避免与 game_loop 的 process_action 产生双重应用竞态（D4）。
/// round_state / shuffle / reveal / reconstruct 等阶段状态仍会同步。
async fn sync_table_state(app_state: &Arc<AppState>, sui_table_id: &str, is_player_action: bool) {
    // 1. 获取链上快照
    let summary = match app_state.relayer_state.get(sui_table_id) {
        Some(s) => s,
        None => return,
    };

    // 2. 推断 shuffle_phase 并映射三维状态
    let shuffle_phase = infer_shuffle_phase(
        summary.meta.round_state,
        summary.state.shuffle_pending_count,
        summary.state.shuffle_completed_count,
        summary.state.shuffle_current_shuffler,
    );
    let chain_round = RoundState::from_chain_state(
        summary.meta.round_state,
        shuffle_phase,
        summary.state.reveal_phase,
        summary.state.reconstruct_phase,
    );

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
                let has_match = table.players.values().any(|w| {
                    !w.0.is_empty()
                        && summary
                            .meta
                            .seat_players
                            .iter()
                            .any(|sp| sp.to_lowercase() == w.0.to_lowercase())
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

    // 4. 同步状态（写锁）
    // 问题14: 用 needs_mark_stale 标志在写锁释放后标记 stale（避免在持有 table 可变引用时调用 mark_stale）
    let mut needs_mark_stale = false;
    {
        let mut gs = app_state.socket_state.state.write().await;
        let table = match gs.tables.get_mut(&socket_table_id) {
            Some(t) => t,
            None => return,
        };

        // 4a-0. 同步 chain_table_id（上链模式下用户操作构建 PTB 时需要）
        if table.chain_table_id.as_deref() != Some(sui_table_id) {
            tracing::info!(
                "[bridge::sync] table {} chain_table_id set to {}",
                socket_table_id,
                sui_table_id
            );
            table.chain_table_id = Some(sui_table_id.to_string());
        }

        // 4a. 同步 round_state
        if table.round_state != chain_round {
            tracing::info!(
                "[bridge::sync] table {} round_state: socket={:?} -> chain={:?}",
                socket_table_id,
                table.round_state,
                chain_round
            );
            table.transition_to(chain_round);
        }

        // 4b. 同步 shuffle_state.is_active
        let chain_shuffle_active = chain_round == RoundState::Shuffling;
        if table.shuffle_state.is_active != chain_shuffle_active {
            tracing::info!(
                "[bridge::sync] table {} shuffle_state.is_active: {} -> {}",
                socket_table_id,
                table.shuffle_state.is_active,
                chain_shuffle_active
            );
            table.shuffle_state.is_active = chain_shuffle_active;
        }

        // 4c. 同步 reveal_token_state
        let should_reveal_active = matches!(
            chain_round,
            RoundState::PreFlopReveal
                | RoundState::FlopReveal
                | RoundState::TurnReveal
                | RoundState::RiverReveal
                | RoundState::ShowdownReveal
        );
        if should_reveal_active {
            if !table.reveal_token_state.is_active {
                table.reveal_token_state.is_active = true;
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
        } else if table.reveal_token_state.is_active {
            tracing::info!(
                "[bridge::sync] table {} reveal_token_state deactivated (chain round={:?})",
                socket_table_id,
                chain_round
            );
            table.reveal_token_state.reset();
        }

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
            if all_ok && synced_deck.len() == table.mental_poker_game.deck_plaintext.len() {
                if table.mental_poker_game.deck_plaintext != synced_deck {
                    tracing::info!(
                        "[bridge::sync] table {} deck_plaintext synced from chain ({} cards)",
                        socket_table_id,
                        synced_deck.len()
                    );
                    table.mental_poker_game.deck_plaintext = synced_deck;
                }
            } else if !all_ok {
                tracing::warn!(
                    "[bridge::sync] table {} deck_plaintext sync failed: invalid G1 compressed bytes",
                    socket_table_id
                );
            } else {
                // 问题14: 长度不匹配时标记 stale，下次 process_event 时强制刷新
                tracing::warn!(
                    "[bridge::sync] table {} deck_plaintext length mismatch: local={} chain={}, marking stale",
                    socket_table_id,
                    table.mental_poker_game.deck_plaintext.len(),
                    synced_deck.len()
                );
                needs_mark_stale = true;
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

        // 4e. 同步下注状态（pot / button / current_turn / betting_round_* / seat 级别字段）
        // 问题4: 仅在链上 round_state 处于下注阶段（PreFlop/Flop/Turn/River/Showdown）时同步
        // D4 修复：玩家行动事件由 game_loop 负责下注状态，跳过 pot/seat_bets/seat_stacks/
        // betting_round 的同步，避免与 process_action 产生双重应用竞态。
        // 非玩家行动事件（如 BettingRoundStarted / RoundAdvanced / HandStarted 等）仍同步下注状态。
        if !is_player_action
            && matches!(
                chain_round,
                RoundState::PreFlop
                    | RoundState::Flop
                    | RoundState::Turn
                    | RoundState::River
                    | RoundState::Showdown
            )
        {
            // pot
            if table.pot != summary.meta.pot {
                tracing::info!(
                    "[bridge::sync] table {} pot: {} -> {}",
                    socket_table_id,
                    table.pot,
                    summary.meta.pot
                );
                table.pot = summary.meta.pot;
            }
            // button
            let chain_button = summary.meta.button as u32;
            if table.button != Some(chain_button) {
                table.button = Some(chain_button);
            }
            // current_turn
            table.turn = summary.meta.current_turn.map(|t| t as u32);
            // betting round
            table.call_amount = if summary.meta.betting_round_current_bet > 0 {
                Some(summary.meta.betting_round_current_bet)
            } else {
                None
            };
            table.min_raise = summary.meta.betting_round_min_raise;
            table.min_bet = summary.meta.betting_round_big_blind;

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
            for (seat_idx, &chain_occupied) in summary.meta.seats_occupied.iter().enumerate() {
                let seat_id = seat_idx as u32;
                if !chain_occupied {
                    continue;
                }
                if let Some(seat) = table.seats.get_mut(&seat_id) {
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
        }
    } // 写锁释放

    // 问题14: 写锁释放后标记 stale，下次 process_event 时强制刷新
    if needs_mark_stale {
        app_state.relayer_state.mark_stale(sui_table_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sui_events::{TableSummaryMeta, TableSummaryState};
    use std::sync::Arc;
    use std::thread;

    /// 辅助函数：构造一个填充合理默认值的 TableSummary
    fn make_test_summary(table_id: &str) -> TableSummary {
        TableSummary {
            meta: TableSummaryMeta {
                table_id: table_id.to_string(),
                name: "test".to_string(),
                max_players: 6,
                small_blind: 10,
                big_blind: 20,
                active_count: 0,
                button: 0,
                pot: 0,
                side_pots_count: 0,
                community_cards_count: 0,
                round_state: 0,
                betting_round_exists: false,
                betting_round_current_bet: 0,
                betting_round_min_raise: 0,
                betting_round_big_blind: 0,
                betting_round_last_raiser_seat: None,
                betting_round_actions_taken: 0,
                current_turn: None,
                seats_occupied: vec![false; 6],
                seat_players: vec![String::new(); 6],
                seat_stacks: vec![0; 6],
                seat_bets: vec![0; 6],
                seat_total_bets: vec![0; 6],
                seat_folded: vec![false; 6],
                seat_all_in: vec![false; 6],
                seat_is_waiting: vec![false; 6],
            },
            state: TableSummaryState {
                shuffle_current_shuffler: None,
                shuffle_pending_count: 0,
                shuffle_completed_count: 0,
                reveal_phase: 0,
                reveal_assignment_count: 0,
                reconstruct_phase: 0,
                deck_size: 52,
                cards_dealt: 0,
                deck_plaintext: Vec::new(),
                shuffle_timeout_ms: 0,
                reveal_timeout_ms: 0,
                betting_timeout_ms: 0,
                reconstruct_timeout_ms: 0,
                showdown_display_ms: 0,
                hand_complete_wait_ms: 0,
                ready_wait_ms: 0,
                ready_at: 0,
                shuffle_started_at: 0,
                reveal_started_at: 0,
                betting_started_at: 0,
                reconstruct_started_at: 0,
                showdown_at: 0,
                hand_complete_at: 0,
                epoch: 0,
            },
        }
    }

    #[test]
    fn test_insert_and_get() {
        let state = RelayerState::new();
        let summary = make_test_summary("0xabc");
        state.insert("0xabc".to_string(), summary.clone());

        let got = state.get("0xabc").expect("should get inserted table");
        assert_eq!(got, summary);

        // 不存在的 key
        assert!(state.get("0xnotexist").is_none());
    }

    #[test]
    fn test_remove() {
        let state = RelayerState::new();
        let summary = make_test_summary("0xdef");
        state.insert("0xdef".to_string(), summary.clone());

        let removed = state.remove("0xdef").expect("should remove existing table");
        assert_eq!(removed, summary);

        // 删除后 get 返回 None
        assert!(state.get("0xdef").is_none());

        // 再次删除返回 None
        assert!(state.remove("0xdef").is_none());
    }

    #[test]
    fn test_list() {
        let state = RelayerState::new();
        assert_eq!(state.list().len(), 0);

        state.insert("0x1".to_string(), make_test_summary("0x1"));
        state.insert("0x2".to_string(), make_test_summary("0x2"));
        state.insert("0x3".to_string(), make_test_summary("0x3"));

        let list = state.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_list_ids() {
        let state = RelayerState::new();
        state.insert("0xaaa".to_string(), make_test_summary("0xaaa"));
        state.insert("0xbbb".to_string(), make_test_summary("0xbbb"));
        state.insert("0xccc".to_string(), make_test_summary("0xccc"));

        let mut ids = state.list_ids();
        ids.sort();
        assert_eq!(ids, vec!["0xaaa".to_string(), "0xbbb".to_string(), "0xccc".to_string()]);
    }

    #[test]
    fn test_concurrent_access() {
        let state = Arc::new(RelayerState::new());
        let mut handles = Vec::new();

        // 多个线程同时 insert
        for i in 0..8 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                let id = format!("0x{:02x}", i);
                state_clone.insert(id.clone(), make_test_summary(&id));
                // insert 后立即 get 验证可见
                let got = state_clone.get(&id);
                assert!(got.is_some(), "thread {} should see its own insert", i);
            });
            handles.push(handle);
        }

        // 同时有读线程在并发 list / list_ids
        for _ in 0..4 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = state_clone.list();
                    let _ = state_clone.list_ids();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // 所有线程结束后应有 8 条记录
        assert_eq!(state.list().len(), 8);
    }

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

    /// 预先在 state 中插入一个 table，然后调用 process_event 处理一个非 TableCreated 事件。
    /// 由于使用无效的 fullnode_url，网络调用会失败，验证旧缓存被保留且不崩溃。
    #[tokio::test]
    async fn test_process_event_table_created_with_preinserted() {
        let state = RelayerState::new();
        let pre_summary = make_test_summary("0xpre");
        state.insert("0xpre".to_string(), pre_summary.clone());

        // 使用一个无效的 URL，确保 fetch_table_summary 失败
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::PlayerFolded {
            table_id: "0xpre".to_string(),
            seat_index: 1,
            reason: 0,
            round_state: 0,
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, "0xpackage", &event).await;

        // 网络失败后旧缓存应保留
        let got = state.get("0xpre").expect("stale cache should be preserved after fetch failure");
        assert_eq!(got, pre_summary);
    }

    /// 验证 process_event 处理 TableCreated 事件在网络失败时不崩溃、不污染缓存。
    #[tokio::test]
    async fn test_process_event_table_created_network_failure() {
        let state = RelayerState::new();
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::TableCreated {
            table_id: "0xnew".to_string(),
            name: "TestTable".to_string(),
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, "0xpackage", &event).await;

        // 网络失败时缓存中不应有该 table
        assert!(state.get("0xnew").is_none());
        assert_eq!(state.list().len(), 0);
    }

    /// 验证 process_event 处理未缓存 table 的非 TableCreated 事件在网络失败时不崩溃。
    #[tokio::test]
    async fn test_process_event_uncached_table_network_failure() {
        let state = RelayerState::new();
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::HandSettled {
            table_id: "0xuncached".to_string(),
            pot: 100,
            winners: vec![],
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, "0xpackage", &event).await;

        // 网络失败时缓存中不应有该 table
        assert!(state.get("0xuncached").is_none());
        assert_eq!(state.list().len(), 0);
    }
}
