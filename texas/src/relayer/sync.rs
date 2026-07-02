//! 链上状态同步函数。
//!
//! 将链上 TableSummaryV2 快照同步到内存 GameState 中的对应 table，
//! 包括 meta / state / crypto 全字段同步、座位/玩家填充、game_loop 生命周期管理。
//!
//! 主要入口：
//! - `sync_all_tables_from_chain`：relayer 启动时全量同步
//! - `sync_single_table_seats_from_chain`：JOIN_TABLE 时单桌座位同步
//! - `sync_table_state`：事件处理时增量同步（由 apply_event_to_socket 调用）

use std::collections::HashMap;
use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::{truncate_name, GamePkHex};
use crate::pokergame::table::{RoundState, Table};
use crate::sui_events::TableSummaryV2;
use crate::sui_query::fetch_table_summary;

use crate::relayer::normalize_wallet;
use crate::relayer::util::now_ms;

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

/// 构建 seat_index → GamePkHex 映射表。
///
/// 遍历链上 `seat_pks`（每个座位的 G1 compressed bytes），将非空 pk 转换为
/// hex 字符串（GamePkHex），返回 `seat_index → GamePkHex` 映射。
/// 空 pk（未入座或已离开的座位）会被跳过。
pub(crate) fn build_seat_pk_map(seat_pks: &[Vec<u8>]) -> HashMap<u64, GamePkHex> {
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
                map.insert(idx as u64, GamePkHex::new(hex));
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
pub(crate) fn seat_indices_to_pk_hex(
    indices: &[u64],
    seat_pk_map: &HashMap<u64, GamePkHex>,
) -> Vec<GamePkHex> {
    indices
        .iter()
        .filter_map(|&idx| seat_pk_map.get(&idx).cloned())
        .collect()
}

/// 从链上 deck_encrypted bytes (96 bytes: c1 || c2) 反序列化为 ElGamalCiphertext 列表。
///
/// 每个元素必须是 96 bytes (48 bytes c1 + 48 bytes c2)，使用 G1 compressed 格式。
/// 反序列化失败时返回 Err。
pub(crate) fn deserialize_deck_encrypted(
    deck_bytes: &[Vec<u8>],
) -> Result<Vec<poker_protocol::crypto::ElGamalCiphertext>, String> {
    use poker_protocol::crypto::curve::CurvePoint;
    use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
    type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

    let mut result: Vec<ElGamalCiphertext> = Vec::with_capacity(deck_bytes.len());
    for (i, ct_bytes) in deck_bytes.iter().enumerate() {
        if ct_bytes.len() != 96 {
            return Err(format!(
                "deck_encrypted[{}] has invalid length {} (expected 96)",
                i,
                ct_bytes.len()
            ));
        }
        let (c1_bytes, c2_bytes) = ct_bytes.split_at(48);
        match (
            <P as CurvePoint>::from_compressed(c1_bytes),
            <P as CurvePoint>::from_compressed(c2_bytes),
        ) {
            (Some(c1), Some(c2)) => result.push(ElGamalCiphertext { c1, c2 }),
            _ => {
                return Err(format!(
                    "deck_encrypted[{}] deserialization failed (invalid G1 compressed bytes)",
                    i
                ))
            }
        }
    }
    Ok(result)
}

/// 同步 round_state：将链上 round_state (u8) 映射为本地 RoundState 枚举并同步。
///
/// 使用 `transition_to_forced` 跳过本地状态机校验，因为链上 round_state 已由
/// Move 合约验证，避免本地与链上状态分歧时卡死。
fn sync_round_state(summary: &TableSummaryV2, table: &mut Table, socket_table_id: u32) {
    // 2. 将链上 round_state (u8) 映射为本地 RoundState 枚举
    let chain_round = match RoundState::from_u8(summary.meta.round_state) {
        Some(rs) => rs,
        None => {
            tracing::warn!(
                value = summary.meta.round_state,
                table_id = socket_table_id,
                "unexpected round_state from chain, falling back to Waiting"
            );
            RoundState::Waiting
        }
    };

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
}

/// 同步 shuffle_state.phase。
///
/// TableSummaryState 不再包含 shuffle_phase 字段（兼容性升级约束），
/// 改为通过 `infer_shuffle_phase` 从其他字段推断。
fn sync_shuffle_state(summary: &TableSummaryV2, table: &mut Table, socket_table_id: u32) {
    let chain_round = match RoundState::from_u8(summary.meta.round_state) {
        Some(rs) => rs,
        None => {
            tracing::warn!(
                value = summary.meta.round_state,
                table_id = socket_table_id,
                "unexpected round_state from chain, falling back to Waiting"
            );
            RoundState::Waiting
        }
    };

    // 4b. 同步 shuffle_state.phase
    // TableSummaryState 不再包含 shuffle_phase 字段（兼容性升级约束），
    // 改为通过 infer_shuffle_phase 从其他字段推断。
    let chain_shuffle_phase_u8 = crate::sui_query::infer_shuffle_phase(
        chain_round.to_u8(),
        summary.state.shuffle_pending_count,
        summary.state.shuffle_completed_count,
        summary.state.shuffle_current_shuffler,
    );
    let chain_shuffle_phase = match crate::pokergame::game_state::ShufflePhase::from_u8(chain_shuffle_phase_u8) {
        Some(p) => p,
        None => {
            tracing::warn!(
                value = chain_shuffle_phase_u8,
                table_id = socket_table_id,
                "unexpected shuffle_phase from chain, falling back to None"
            );
            crate::pokergame::game_state::ShufflePhase::None
        }
    };
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
}

/// 同步 reveal_token_state.phase（对齐 Move reveal_phase）。
///
/// 链上 reveal_phase != 0 表示活跃。
fn sync_reveal_token_state(summary: &TableSummaryV2, table: &mut Table, socket_table_id: u32) {
    let chain_round = match RoundState::from_u8(summary.meta.round_state) {
        Some(rs) => rs,
        None => {
            tracing::warn!(
                value = summary.meta.round_state,
                table_id = socket_table_id,
                "unexpected round_state from chain, falling back to Waiting"
            );
            RoundState::Waiting
        }
    };

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
}

/// 同步 deck 状态：deck_plaintext / crypto / deck_encrypted / aggregated_pk / shuffle 玩家列表。
///
/// - `deck_plaintext`：从链上 G1 compressed bytes 反序列化为 EcPoint，强制覆盖本地。
///   必须在 start_reconstruct 之前完成，否则 reconstruct 使用的牌组与链上不一致，
///   提交链上验证会失败。
/// - `summary.crypto`：整体同步到 `table.summary.crypto`（仅供 `players()` 读取 `seat_pks`）。
/// - `deck_encrypted` / `aggregated_pk`：**无条件**同步到 `mental_poker_game`（单一真理之源），
///   不再受 `shuffle_active` 条件限制。
/// - `shuffle_pending_players` / `shuffle_completed_players`：仅在 shuffle 活跃时同步。
fn sync_deck_state(
    summary: &TableSummaryV2,
    table: &mut Table,
    socket_table_id: u32,
    force_sync_crypto: bool,
) {
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

    // 4d-2a. 无条件同步 deck_encrypted（mental_poker_game 是单一真理之源）
    // Task: Phase 2 — 不再受 shuffle_active 条件限制，链上有数据就同步
    if !summary.crypto.deck_encrypted.is_empty() {
        match deserialize_deck_encrypted(&summary.crypto.deck_encrypted) {
            Ok(synced_deck) => {
                if table.mental_poker_game.deck_encrypted != synced_deck {
                    tracing::info!(
                        "[bridge::sync] table {} deck_encrypted synced from chain ({} cards, shuffle_active={})",
                        socket_table_id,
                        synced_deck.len(),
                        shuffle_active
                    );
                    table.mental_poker_game.deck_encrypted = synced_deck;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[bridge::sync] table {} deck_encrypted sync failed: {}",
                    socket_table_id,
                    e
                );
            }
        }
    }

    // 4d-2b. 无条件同步 aggregated_pk（mental_poker_game 是单一真理之源）
    if !summary.crypto.aggregated_pk.is_empty() {
        use poker_protocol::crypto::curve::CurvePoint;
        use poker_protocol::crypto::DefaultCurve;
        type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

        if let Some(pk) = <P as CurvePoint>::from_compressed(&summary.crypto.aggregated_pk) {
            let current_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
            if current_pk != pk {
                tracing::info!(
                    "[bridge::sync] table {} aggregated_pk synced from chain (shuffle_active={})",
                    socket_table_id,
                    shuffle_active
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

    // 4d-2c. shuffle_pending_players / shuffle_completed_players 仅在 shuffle 活跃时同步
    if shuffle_active {
        // 构建 seat_index → pk_hex 映射表（供 shuffle 玩家列表转换用）
        let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

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
}

/// 同步 reconstruct_state：激活/停用 reconstruct，同步 coefficient / pending / completed 玩家列表。
///
/// 链上 reconstruct_phase: 0=None, 1=Collecting, 2=Complete。
/// 活跃: Collecting(1)；非活跃: None(0) / Complete(2)。
fn sync_reconstruct_state(summary: &TableSummaryV2, table: &mut Table, socket_table_id: u32) {
    let chain_reconstruct_active = summary.state.reconstruct_phase == 1;

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
}

/// 同步下注状态（pot / button / current_turn / betting_round_* / seat 级别字段）。
///
/// Task 13: 在所有 round_state 下同步下注状态（包括 Waiting / HandComplete），
/// 合约是真理之源。
fn sync_betting_state(summary: &TableSummaryV2, table: &mut Table, socket_table_id: u32) {
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
    let mut pks_to_remove: Vec<GamePkHex> = Vec::new();
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
    // 同步清理 pk_to_seat / local_players / local_seats（对齐 reset_for_next_hand 的清理策略）
    for pk in &pks_to_remove {
        table.pk_to_seat.remove(pk);
        table.local_players.remove(pk);
    }
    for seat_id in &seats_to_remove {
        table.local_seats.remove(seat_id);
    }
    if !seats_to_remove.is_empty() {
        tracing::info!(
            "[bridge::sync] table {} cleaned up {} zombie seats from local state (pks removed: {})",
            socket_table_id,
            seats_to_remove.len(),
            pks_to_remove.len()
        );
    }
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
pub(crate) async fn sync_table_state(
    app_state: &Arc<AppState>,
    sui_table_id: &str,
    is_player_action: bool,
    force_sync_crypto: bool,
    summary: &TableSummaryV2,
) {
    // 1. 链上快照通过 summary 参数传入

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
        sync_round_state(summary, table, socket_table_id);

        // 4b. 同步 shuffle_state
        sync_shuffle_state(summary, table, socket_table_id);

        // 4c. 同步 reveal_token_state
        sync_reveal_token_state(summary, table, socket_table_id);

        // 4d. 同步 deck 状态（deck_plaintext / crypto / deck_encrypted / aggregated_pk / shuffle 玩家列表）
        sync_deck_state(summary, table, socket_table_id, force_sync_crypto);

        // 4d. 同步 reconstruct_state
        sync_reconstruct_state(summary, table, socket_table_id);

        // 4e. 同步下注状态（pot / button / current_turn / betting_round_* / seat 级别字段）
        // Task 13: 在所有 round_state 下同步下注状态（包括 Waiting / HandComplete），
        // 合约是真理之源。
        // D4 修复：仅在玩家行动事件且 game_loop 运行时跳过，避免与 process_action 竞态。
        // 若 game_loop 未运行，则无条件同步（即使 is_player_action==true）。
        if !is_player_action || !game_loop_running {
            sync_betting_state(summary, table, socket_table_id);
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
