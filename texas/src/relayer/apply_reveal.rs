//! Reveal 事件同步函数。
//!
//! 将链上 RevealPhaseEvt / RevealTokenSubmitted / RevealPhaseComplete /
//! CardIsIdentity / IdentityRedeal / RevealTimeout / CommunityCardRevealed 事件
//! 同步到内存 Table，并通过 socket 广播通知前端。
//!
//! 同时包含从链上 summary 重建 reveal_token_state 的辅助函数：
//! - rebuild_hand_reveal_from_summary
//! - rebuild_community_reveal_from_summary
//! - rebuild_showdown_reveal_from_summary
//! - active_seat_indices_from_summary
//! - extract_hand_from_deck

use std::collections::HashMap;
use std::sync::Arc;

use crate::handlers::AppState;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::GamePkHex;
use crate::pokergame::table::events::CryptoEventType;
use crate::socket::{broadcast, game_loop, get_socket_io};
use crate::sui_events::TableSummaryV2;

use crate::relayer::{build_seat_pk_map, locate_socket_table_by_chain_id, sync_table_state};

/// Task 8: 将链上 RevealPhaseEvt 事件同步为 reveal notice 广播。
///
/// 当链上 RevealPhaseEvt 到达时，本地可能尚未调用 start_*_reveal_phase
/// （例如最后一个玩家的 shuffle 在链上完成，本地 advance_shuffle 未触发），
/// 导致 reveal_token_state.phase 已由 sync 同步但 pending_players/player_assignments 为空。
///
/// 修复方案：参考 Move 合约 start_preflop_reveal_phase / start_community_reveal_phase /
/// start_showdown_reveal_phase 的分配逻辑，从链上 summary 重建 player_assignments
/// （按用户拆分），确保广播携带完整数据，玩家可据此提交 REVEAL_TOKEN。
pub(crate) async fn apply_reveal_phase_evt_to_socket(
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

    // 3. 判定是否需要从链上 summary 重建 player_assignments。
    //    关键：本函数在 sync_table_state 之前运行（见 relayer/mod.rs apply_event_to_socket），
    //    此时本地 reveal_token_state.phase 可能仍为上一手 reset 后的 None，
    //    因此不能用本地 is_active() 判定，必须用链上 summary.state.reveal_phase。
    //
    //    重要修复：始终在 chain_reveal_active 时从链上重建 player_assignments。
    //    此前仅当本地 pending_players 为空时才重建，但本地 advance_shuffle 可能在
    //    sync_table_state 之前运行（game loop tick），使用 mental_poker_game 中可能过期的
    //    hand_encrypted 构建 assignments → 前端基于错误牌组生成 reveal_token →
    //    链上 plaintext_to_playing_card 匹配失败 → EInvalidCardIndex。
    //    修复后：始终以链上 summary 为权威源重建，同时保留已完成的 completed_players
    //    避免要求已提交的玩家重复提交。
    let chain_reveal_active = summary.map(|s| s.state.reveal_phase != 0).unwrap_or(false);
    let need_populate = chain_reveal_active;

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

        // 3c. ShowdownReveal 阶段需从链上获取 decrypted_cards_info，用 owner_seat_index
        //     精确匹配每个牌主的手牌（对齐 Move start_showdown_reveal_phase）
        let decrypted_cards_info: Vec<crate::sui_query::DecryptedCardInfoBcs> =
            if matches!(rust_phase, Some(RevealPhase::ShowdownReveal)) {
                match crate::sui_query::fetch_decrypted_cards_info(
                    &app_state.socket_state.config.fullnode_url,
                    &app_state.socket_state.config.sui_package_id,
                    &app_state.socket_state.config.sui_origin_package_id,
                    table_id,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(
                            "[bridge::reveal] fetch_decrypted_cards_info failed for ShowdownReveal: {}, fallback to deck position",
                            e
                        );
                        Vec::new()
                    }
                }
            } else {
                Vec::new()
            };

        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            // 3d. 保存已完成的玩家列表，rebuild 后恢复，避免要求已提交的玩家重复提交
            let preserved_completed = table.reveal_token_state.completed_players.clone();

            match rust_phase {
                Some(RevealPhase::HandReveal) => {
                    if let Err(e) = rebuild_hand_reveal_from_summary(table, summary_ref, chain_phase) {
                        tracing::warn!("[bridge::reveal] rebuild HandReveal failed: {}", e);
                    } else {
                        // 恢复已完成的玩家，从 pending 中移除
                        table.reveal_token_state.completed_players = preserved_completed.clone();
                        table.reveal_token_state.pending_players.retain(|pk| !preserved_completed.contains(pk));
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for HandReveal, pending={}, completed={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.completed_players.len(),
                            table.reveal_token_state.player_assignments.len()
                        );
                    }
                }
                Some(RevealPhase::CommunityReveal) => {
                    if let Err(e) = rebuild_community_reveal_from_summary(table, summary_ref, chain_phase) {
                        tracing::warn!("[bridge::reveal] rebuild CommunityReveal failed: {}", e);
                    } else {
                        table.reveal_token_state.completed_players = preserved_completed.clone();
                        table.reveal_token_state.pending_players.retain(|pk| !preserved_completed.contains(pk));
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for CommunityReveal, pending={}, completed={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.completed_players.len(),
                            table.reveal_token_state.player_assignments.len()
                        );
                    }
                }
                Some(RevealPhase::ShowdownReveal) => {
                    if let Err(e) = rebuild_showdown_reveal_from_summary(table, summary_ref, &decrypted_cards_info) {
                        tracing::warn!("[bridge::reveal] rebuild ShowdownReveal failed: {}", e);
                    } else {
                        table.reveal_token_state.completed_players = preserved_completed.clone();
                        table.reveal_token_state.pending_players.retain(|pk| !preserved_completed.contains(pk));
                        tracing::info!(
                            "[bridge::reveal] rebuilt reveal_token_state from summary for ShowdownReveal, pending={}, completed={}, assignments={}",
                            table.reveal_token_state.pending_players.len(),
                            table.reveal_token_state.completed_players.len(),
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

    // 3. 获取加密牌组（直接从 summary.crypto.deck_encrypted 反序列化，避免依赖可能被 reset 清空的 mental_poker_game）
    let deck = crate::relayer::sync::deserialize_deck_encrypted(&summary.crypto.deck_encrypted)
        .map_err(|e| format!("deck_encrypted deserialization failed: {}", e))?;
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

    // 3. 获取加密牌组（直接从 summary.crypto.deck_encrypted 反序列化，避免依赖可能被 reset 清空的 mental_poker_game）
    let deck = crate::relayer::sync::deserialize_deck_encrypted(&summary.crypto.deck_encrypted)
        .map_err(|e| format!("deck_encrypted deserialization failed: {}", e))?;
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
    decrypted_cards_info: &[crate::sui_query::DecryptedCardInfoBcs],
) -> Result<(), String> {
    use crate::pokergame::game_state::{PlayerRevealAssignment, RevealTokenState};
    use poker_protocol::crypto::curve::{CurvePoint, Curve};

    const CARDS_PER_PLAYER: usize = 2;

    let active_seats: Vec<u64> = active_seat_indices_from_summary(&summary.meta);
    if active_seats.is_empty() {
        return Err("no active seats for ShowdownReveal".to_string());
    }

    // 2. 构建 seat_index -> GamePkHex 映射
    let seat_pk_map = build_seat_pk_map(&summary.crypto.seat_pks);

    // 3. 获取加密牌组（直接从 summary.crypto.deck_encrypted 反序列化，避免依赖可能被 reset 清空的 mental_poker_game）
    let deck = crate::relayer::sync::deserialize_deck_encrypted(&summary.crypto.deck_encrypted)
        .map_err(|e| format!("deck_encrypted deserialization failed: {}", e))?;
    if deck.is_empty() {
        return Err("deck_encrypted is empty".to_string());
    }

    // 4. 构建 pending_players（所有活跃玩家）
    let pending_players: Vec<GamePkHex> = active_seats
        .iter()
        .filter_map(|&seat_idx| seat_pk_map.get(&seat_idx).cloned())
        .collect();

    // 5. 构建 player_assignments：每个牌主提交自己手牌的 reveal token
    //    对齐 Move start_showdown_reveal_phase (table.move#L2976-3000)：
    //    - 遍历 decrypted_cards，找 owner_seat_index == s && ciphertext_bytes.len() > 0
    //    - pending_players = [owner]（只有牌主提交）
    //    - 用 ciphertext_bytes 的 c1（前 48 bytes）匹配 deck_encrypted 找到原始加密牌
    let mut player_assignments: HashMap<GamePkHex, PlayerRevealAssignment> = HashMap::new();

    if !decrypted_cards_info.is_empty() {
        // 链上模式：用 decrypted_cards_info 按 owner_seat_index 精确匹配
        type P = <poker_protocol::crypto::DefaultCurve as Curve>::Point;

        for &seat_idx in &active_seats {
            let pk = match seat_pk_map.get(&seat_idx) {
                Some(pk) => pk.clone(),
                None => continue,
            };

            // 从 decrypted_cards_info 按 owner_seat_index 匹配
            let mut hand_card: Vec<poker_protocol::crypto::ElGamalCiphertext> = Vec::new();
            for dc in decrypted_cards_info {
                if dc.owner_seat_index != seat_idx || dc.ciphertext_bytes.is_empty() {
                    continue;
                }
                // ciphertext_bytes = c1(48) + c2'(48)，用 c1 匹配 deck_encrypted
                let dc_c1_bytes = &dc.ciphertext_bytes[..48];
                for card in &deck {
                    let card_c1_compressed = card.c1.compress();
                    let card_c1_bytes: &[u8] = card_c1_compressed.as_ref();
                    if card_c1_bytes == dc_c1_bytes {
                        hand_card.push(card.clone());
                        break;
                    }
                }
            }

            if !hand_card.is_empty() {
                player_assignments.insert(pk, PlayerRevealAssignment {
                    hand_card,
                    community_card: vec![],
                });
            }
        }
    } else {
        // 降级：decrypted_cards_info 为空，从 deck_encrypted 按索引重建
        let active_count = active_seats.len() as u64;
        let cards_dealt = summary.state.cards_dealt;
        let hand_start = if cards_dealt >= active_count * CARDS_PER_PLAYER as u64 {
            (cards_dealt - active_count * CARDS_PER_PLAYER as u64) as usize
        } else {
            return Err(format!(
                "cards_dealt {} < active_count*{} for showdown",
                cards_dealt,
                CARDS_PER_PLAYER
            ));
        };
        for (order, &seat_idx) in active_seats.iter().enumerate() {
            let pk = match seat_pk_map.get(&seat_idx) {
                Some(pk) => pk.clone(),
                None => continue,
            };

            let hand_card: Vec<poker_protocol::crypto::ElGamalCiphertext> =
                if let Some(mp_player) = table.mental_poker_game.players.get(pk.0.as_str()) {
                    if !mp_player.hand_encrypted.is_empty() {
                        mp_player.hand_encrypted.iter().map(|f| f.encrypted_card.clone()).collect()
                    } else {
                        extract_hand_from_deck(&deck, hand_start, order, CARDS_PER_PLAYER)?
                    }
                } else {
                    extract_hand_from_deck(&deck, hand_start, order, CARDS_PER_PLAYER)?
                };

            player_assignments.insert(pk, PlayerRevealAssignment {
                hand_card,
                community_card: vec![],
            });
        }
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

/// Task 8: 将链上 CommunityCardRevealed 事件同步为 community reveal 广播。
pub(crate) async fn apply_community_card_revealed_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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

/// Task 20: RevealTokenSubmitted 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reveal_token", card_index from event, verified=true）。
pub(crate) async fn apply_reveal_token_submitted_to_socket(
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

    // 2. 获取 pk_hex 并标记玩家已完成 reveal（不触发 on_reveal_complete，
    //    on-chain 模式下 phase 转换由链上事件驱动）。
    //    这防止 RevealPhaseEvt 重建时仍将玩家列入 pending_players，
    //    导致重复 REVEAL_NOTICE 和重复提交。
    let pk_hex = {
        let mut gs = app_state.socket_state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&socket_table_id) {
            let pk_owned = table
                .seats()
                .get(&(seat_index as u32))
                .and_then(|seat| seat.player.as_ref())
                .map(|p| p.pk_hex.clone());

            if let Some(ref pk) = pk_owned {
                if table.reveal_token_state.is_active()
                    && !table.reveal_token_state.completed_players.contains(pk)
                {
                    table.reveal_token_state.completed_players.push(pk.clone());
                    table.reveal_token_state.pending_players.retain(|p| p != pk);
                    tracing::info!(
                        "[bridge::reveal_token] table {} seat {} marked reveal completed (pk={}), pending={}",
                        socket_table_id, seat_index, pk, table.reveal_token_state.pending_players.len()
                    );
                }
            }
            pk_owned.map(|p| p.to_string()).unwrap_or_default()
        } else {
            String::new()
        }
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
/// 广播 `TABLE_UPDATED`，并根据 `phase` 广播对应的 RevealResult：
/// - phase 1 (Preflop/HandReveal) → `HAND_REVEAL_RESULT`
/// - phase 2 (Redeal) → `REDEAL_RESULT`
/// - phase 3/4/5 (Flop/Turn/River/CommunityReveal) → `COMMUNITY_REVEAL_RESULT`
/// - phase 6 (Showdown) → `broadcast_showdown_result`
///
/// 广播 RevealResult 前先调用 `sync_table_state` 同步链上最新 crypto 状态
/// （deck_encrypted / deck_plaintext / summary.crypto），确保 `HandRevealResultPayload`
/// 中的 `readable_cards` 与 `deck_plaintext` 反映链上 RevealPhaseComplete 后的最新数据。
pub(crate) async fn apply_reveal_phase_complete_to_socket(
    app_state: &Arc<AppState>,
    table_id: &str,
    phase: u8,
    summary: Option<&TableSummaryV2>,
) {
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

    // 4. 广播 RevealResult 前先同步链上 crypto 状态
    //    apply_event_to_socket 末尾的 sync_table_state 在本函数返回后才执行，
    //    而 broadcast_hand_reveal_result 等需要读取 deck_plaintext /
    //    player_readable_tokens，必须先同步才能拿到 RevealPhaseComplete 后的最新数据。
    if let Some(s) = summary {
        sync_table_state(app_state, table_id, false, true, s).await;
    } else {
        tracing::warn!(
            "[bridge::reveal_complete] summary is None, table_id={}, skip crypto sync before reveal result broadcast",
            table_id
        );
    }

    // 5. 根据 phase 广播对应的 RevealResult
    // Move 合约 reveal_phase 常量：1=Preflop, 2=Redeal, 3=Flop, 4=Turn, 5=River, 6=Showdown
    // 链上模式 mental_poker_game 无玩家数据，手牌/重发阶段使用 from_summary 版本
    // 直接从 summary.crypto.deck_encrypted 构造 HandRevealResultPayload。
    match phase {
        1 => {
            if let Some(s) = summary {
                tracing::debug!(
                    "[bridge::reveal_complete] phase 1, table_id={}, broadcast hand reveal result from summary",
                    socket_table_id
                );
                app_state.socket_state
                    .broadcast_hand_reveal_result_from_summary(socket_table_id, s)
                    .await;
            } else {
                app_state.socket_state.broadcast_hand_reveal_result(socket_table_id).await;
            }
        }
        2 => {
            if let Some(s) = summary {
                app_state.socket_state
                    .broadcast_redeal_result_from_summary(socket_table_id, s)
                    .await;
            } else {
                app_state.socket_state.broadcast_redeal_result(socket_table_id).await;
            }
        }
        3 | 4 | 5 => {
            // flop, turn, river, community reveal
            // 链上模式 mental_poker_game 无公共牌数据，使用 from_summary 版本
            // 从链上 decrypted_cards_info 的 plaintext_bytes 解析公共牌。
            if let Some(s) = summary {
                app_state.socket_state
                    .broadcast_community_cards_from_summary(socket_table_id, s)
                    .await;
            } else {
                app_state.socket_state.broadcast_community_cards(socket_table_id).await;
            }
        }
        6 => {
            // showdown：链上模式从链上 `seat_hand` 读取玩家底牌后广播
            if let Some(s) = summary {
                app_state.socket_state
                    .broadcast_showdown_result_from_summary(socket_table_id, s)
                    .await;
            } else {
                app_state.socket_state.broadcast_showdown_result(socket_table_id).await;
            }
        }
        _ => {
            tracing::warn!(
                "[bridge::reveal_complete] unknown phase={}, table_id={}, skip reveal result broadcast",
                phase,
                socket_table_id
            );
        }
    }
}

/// Task 20: CardIsIdentity 事件处理器。
///
/// 广播 `CRYPTO_EVENT`（event_type="reveal_token", message="identity_card"）。
pub(crate) async fn apply_card_is_identity_to_socket(
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
pub(crate) async fn apply_identity_redeal_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
pub(crate) async fn apply_reveal_timeout_to_socket(app_state: &Arc<AppState>, table_id: &str) {
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
