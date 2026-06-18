use std::sync::Arc;

use super::*;

pub(crate) async fn game_loop_task(io: SocketIo, state: Arc<SocketState>, table_id: u32, mut action_rx: tokio::sync::mpsc::Receiver<ActionRequest>, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
    tracing::info!("[GAME-LOOP] Started for table {}", table_id);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !process_tick(&io, &state, table_id).await {
                    tracing::info!("[GAME-LOOP] Table {} process_tick signaled stop", table_id);
                    break;
                }
            }
            action = action_rx.recv() => {
                match action {
                    Some(req) => {
                        tracing::info!("[GAME-LOOP] Table {} received action: {} from {}", table_id, req.action, req.pk_hex);
                        process_action(&io, &state, table_id, req).await;
                    }
                    None => {
                        tracing::info!("[GAME-LOOP] Channel closed for table {}", table_id);
                        break;
                    }
                }
            }
            _ = stop_rx.changed() => {
                tracing::info!("[GAME-LOOP] Stop signal received for table {}", table_id);
                break;
            }
        };
    }

    {
        let mut registry = state.game_loop_registry.write().await;
        registry.remove(table_id);
    }
    tracing::info!("[GAME-LOOP] Stopped for table {}", table_id);
}

pub(crate) async fn handle_interrupts(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, reconstruct_active: bool, shuffle_active: bool, reveal_active: bool) -> Option<bool> {
    if reconstruct_active {
        let reconstruct_result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                if table.execute_reconstruct_if_completed() {
                    Some((true, Vec::new()))
                } else if let Some(timed_out_pks) = table.check_reconstruct_timeout() {
                    Some((false, timed_out_pks))
                } else {
                    None
                }
            } else { None }
        };
        if let Some((completed, timed_out_pks)) = reconstruct_result {
            if completed {
                broadcast::broadcast_to_table(io, state, table_id, Some("Reconstruct completed")).await;

                // Start shuffle phase after reconstruct completes
                {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        let _ = table.start_shuffle();
                    }
                }

                let reconstruct_payload = ReconstructResultPayload {
                    table_id,
                    completed_players: vec![],
                    reconstructed: true,
                };
                let _ = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;

                state.send_shuffle_notice(table_id).await;
            } else {
                // Reconstruct timeout: players in timed_out_pks have already been removed by check_reconstruct_timeout
                let msg = if timed_out_pks.is_empty() {
                    "Reconstruct timed out".to_string()
                } else {
                    format!("Reconstruct timed out, {} player(s) removed", timed_out_pks.len())
                };
                broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;

                // Check if we should reset the hand (not enough players)
                let should_reset = {
                    let gs = state.state.read().await;
                    gs.tables.get(&table_id).map(|t| t.active_players().len() < MIN_START_NUM as usize).unwrap_or(true)
                };
                if should_reset {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.transition_to(RoundState::Waiting);
                    }
                }
            }
            return Some(true);
        }
    }

    if shuffle_active {
        let shuffle_complete = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id).map(|t| t.is_all_players_shuffled()).unwrap_or(false)
        };
        if shuffle_complete {
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.reset();
                    table.transition_to(RoundState::ShuffleComplete);
                    tracing::info!("[ShuffleComplete] Table {} shuffle complete", table_id);
                }
            }
            return Some(true);
        }
        let timeout_result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_shuffle_timeout()
            } else { None }
        };
        if let Some(timed_out_pk) = timeout_result {
            tracing::info!("[TICK] Table {} shuffle timeout for player {}", table_id, timed_out_pk);
            let should_stop_early = {
                let mut gs = state.state.write().await;
                let should_stop = if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.remove_player_by_pk(&timed_out_pk);
                    table.shuffle_state.pending_players.retain(|pk| *pk != timed_out_pk);

                    if table.active_players().len() < MIN_START_NUM as usize {
                        table.transition_to(RoundState::Waiting);
                        table.shuffle_state.is_active = false;
                        true
                    } else {
                        false
                    }
                } else { false };

                if !should_stop {
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.complete_or_continue_next_shuffler();
                    }
                }
                should_stop
            };
            if should_stop_early {
                return Some(true);
            }
            state.send_shuffle_notice(table_id).await;
            broadcast::broadcast_to_table(io, state, table_id, None).await;
            return Some(true);
        }
    }

    if reveal_active {
        // 检查是否是 redeal reveal 阶段
        let is_redeal_reveal = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id).map(|t| t.reveal_token_state.phase == RevealPhase::RedealReveal).unwrap_or(false)
        };

        let timeout_result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_reveal_timeout()
            } else { None }
        };
        if let Some(timed_out_pks) = timeout_result {
            tracing::info!("[TICK] Table {} reveal token timeout for player {:?}", table_id, timed_out_pks);

            if is_redeal_reveal {
                // redeal reveal 超时：踢掉超时玩家，重置 reveal state，游戏继续
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    for timed_out_pk in &timed_out_pks {
                        table.remove_player_by_pk(timed_out_pk);
                    }
                    table.reveal_token_state.reset();
                    if table.active_players().len() < MIN_START_NUM as usize {
                        table.transition_to(RoundState::Waiting);
                    }
                }
                broadcast::broadcast_to_table(io, state, table_id, Some("Redeal reveal timed out")).await;
                return Some(true);
            }

            let current_tables = state.get_current_tables().await;
            let should_reset_hand = {
                let mut gs = state.state.write().await;
                if !gs.tables.contains_key(&table_id) {
                    return None;
                }

                for timed_out_pk in &timed_out_pks {
                    if let Some(socket_id) = gs.remove_player_by_pk(table_id, timed_out_pk) {
                        if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                            if let Some(socket) = io.get_socket(sid) {
                                socket.leave(table_room_name(table_id));
                                let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: current_tables.clone(), table_id });
                            }
                        }
                    }
                }
                let mut should_reset = false;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    if table.active_players().len() < MIN_START_NUM as usize {
                        table.transition_to(RoundState::Waiting);
                        table.reveal_token_state.reset();
                        tracing::info!("[TICK] Table {} reset for next hand", table_id);
                        return Some(true);
                    }

                    if table.round_state == RoundState::PreFlopReveal {
                        // 没有用户开到过牌，直接重开牌
                        table.reset_for_next_hand();
                        should_reset = true;
                        tracing::info!("[TICK] Table {} reset for next hand", table_id);
                    } else {
                        tracing::info!("[TICK] Table {} start reconstruct", table_id);
                        let _ = table.start_reconstruct();
                    }
                }
                should_reset
            };

            // 在锁外广播，避免死锁
            if should_reset_hand {
                broadcast::broadcast_to_table(io, state, table_id, Some("Player timed out reset hand")).await;
                return Some(true);
            }

            let reconstruct_notice = {
                let gs = state.state.read().await;
                gs.tables.get(&table_id).map(|t| {
                    let completed_players = t.reconstruct_state.completed_players.clone();
                    let pending_players = t.reconstruct_state.pending_players.clone();
                    let cards = t.reconstruct_state.cards.iter().map(|c| ecpoint_to_hex(c)).collect();
                    let coefficient_hex = scalar_to_hex(&t.reconstruct_state.coefficient);
                    let player_readable_cards = t.reconstruct_state.player_readable_cards.iter().map(|(k, v)| {
                        (k.clone(), PlayerReadableCardJson {
                            readable_cards: v.readable_cards.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                        })
                    }).collect();
                    ReconstructNoticePayload { table_id,  completed_players, pending_players, cards, coefficient_hex, player_readable_cards }
                })
            };
            tracing::info!("[TICK] Table {} reconstruct notice {:?}", table_id, reconstruct_notice);
            if let Some(notice) = reconstruct_notice {
                let result = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_NOTICE, &notice).await;
                tracing::info!("[TICK] Table {} reconstruct notice result {:?}", table_id, result);
            }

            broadcast::broadcast_to_table(io, state, table_id, Some(&format!("Player  timed out on reveal", ))).await;
            return Some(true);
        }
    }

    if reconstruct_active || shuffle_active || reveal_active {
        Some(true)
    } else {
        None
    }
}

pub(crate) async fn handle_reveal_phase(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, next_state: RoundState, is_preflop: bool) {
    {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.reveal_token_state.is_active {
                return;
            }
            if next_state == RoundState::Showdown{
                table.start_showdown_reveal_phase();
            }else{
                if is_preflop {
                    table.start_preflop_reveal_phase();
                } else {
                    table.start_community_reveal_phase();
                }
            }
        }else{
            return;
        }
    }
    let reveal_notice = {
        let gs = state.state.read().await;
        gs.tables.get(&table_id).map(|t| {
            let phase = t.reveal_token_state.phase.clone();
            let pending = t.reveal_token_state.pending_players.clone();
            let completed = t.reveal_token_state.completed_players.clone();
            let player_assignments = t.reveal_token_state.player_assignments.clone();
            RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
        })
    };
    if let Some(notice) = reveal_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::REVEAL_NOTICE, &notice).await;
    }
    broadcast::broadcast_to_table(io, state, table_id, None).await;
}

pub(crate) async fn process_tick(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    let (round_state, active_count, _betting_timeout, hand_complete_at, ready_at, showdown_at,
         shuffle_active, reveal_active, reconstruct_active) = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            (table.round_state, table.active_players().len(), table.betting_timeout_start, table.hand_complete_at, table.ready_at, table.showdown_at,
             table.shuffle_state.is_active, table.reveal_token_state.is_active, table.reconstruct_state.is_active)
        } else { return false }
    };

    if active_count == 0 {
        tracing::info!("[TICK] Table {} has no active players, stopping game loop", table_id);
        return false;
    }

    if let Some(result) = handle_interrupts(io, state, table_id, reconstruct_active, shuffle_active, reveal_active).await {
        return result;
    }

    match round_state {
        RoundState::Waiting => {
            if active_count >= MIN_START_NUM as usize {
                let io_c = io.clone();
                let state_c = state.clone();
                if let Some(ready_at) = ready_at {
                    let elapsed = ready_at.elapsed().as_secs();
                    if elapsed <= state.config.ready_countdown_secs {
                        tracing::debug!("[TICK] Table {} Waiting: {} active, ready countdown {}/5s", table_id, active_count, elapsed);
                        return true;
                    }
                    tracing::info!("[TICK] Table {} Waiting → starting hand ({} active)", table_id, active_count);

                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            if table.active_players().len() >= MIN_START_NUM as usize {
                                let _ = table.start_shuffle();
                            }
                        }
                    }
                    state_c.send_shuffle_notice(table_id).await;
                    broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("--- New hand started ---")).await;
                } else {
                    tracing::info!("[TICK] Table {} Waiting: setting ready_at, starting 5s countdown", table_id);
                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.ready_at = Some(std::time::Instant::now());
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, Some("---New hand starting in 5 seconds---")).await;
                }
            } else {
                tracing::info!("[TICK] Table {} Waiting: only {} active, stopping game loop", table_id, active_count);
                return false;
            }
        }
        RoundState::Shuffling => {
            if active_count < MIN_START_NUM as usize {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.transition_to(RoundState::Waiting);
                }
            }
            let all_shuffled = {
                let gs = state.state.read().await;
                gs.tables.get(&table_id).map(|t| t.is_all_players_shuffled()).unwrap_or(false)
            };
            if all_shuffled {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.transition_to(RoundState::ShuffleComplete);
                }
            }
        }
        RoundState::ShuffleComplete => {
            if active_count < MIN_START_NUM as usize {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.transition_to(RoundState::Waiting);
                }
            }
            tracing::info!("[TICK] Table {} ShuffleComplete, resetting shuffle and starting hand", table_id);
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.reset_shuffle();
                    table.start_hand();
                    //todo 这里使得start_hand会触发PreFlopReveal状态有点混乱
                    table.transition_to(RoundState::PreFlopReveal);
                }
            }

            broadcast::broadcast_to_table(io, state, table_id, Some("Shuffle complete, dealing cards")).await;
        }
        RoundState::PreFlopReveal => {
            tracing::info!("[TICK] Table {} PreFlopReveal, starting preflop reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::PreFlop, true).await;
        }
        RoundState::FlopReveal => {
            tracing::info!("[TICK] Table {} FlopReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Flop, false).await;
        }
        RoundState::TurnReveal => {
            tracing::info!("[TICK] Table {} TurnReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Turn, false).await;
        }
        RoundState::RiverReveal => {
            tracing::info!("[TICK] Table {} RiverReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::River, false).await;
        }
        RoundState::ShowdownReveal => {
            tracing::info!("[TICK] Table {} ShowdownReveal, starting showdown reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Showdown, false).await;
        }
        RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River => {
            let timeout_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.check_betting_timeout(state.config.betting_timeout_secs)
                } else { None }
            };
            if let Some(res) = timeout_result {
                tracing::info!("[TICK] Table {} {:?}: betting timeout → {}", table_id, round_state, res.message);
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                handle_turn_advance(io, state, table_id).await;
                return true;
            }

            handle_auto_fold(io, state, table_id).await;

            let is_complete = {
                let gs = state.state.read().await;
                if let Some(table) = gs.tables.get(&table_id) {
                    table.is_betting_round_complete()
                } else { false }
            };

            if is_complete {
                tracing::info!("[TICK] Table {} {:?}: betting round complete, advancing", table_id, round_state);
                handle_turn_advance(io, state, table_id).await;
            }
        }
        RoundState::Showdown => {
            if let Some(sa) = showdown_at {
                let elapsed = sa.elapsed().as_secs();
                if elapsed >= state.config.showdown_display_secs {
                    tracing::info!("[TICK] Table {} Showdown: 3s elapsed, finishing showdown", table_id);
                    {
                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.finish_showdown();
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, None).await;
                } else {
                    tracing::debug!("[TICK] Table {} Showdown: displaying results {}/3s", table_id, elapsed);
                }
            } else {
                tracing::warn!("[TICK] Table {} Showdown: showdown_at is None, finishing immediately", table_id);
                {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.finish_showdown();
                    }
                }
                broadcast::broadcast_to_table(io, state, table_id, None).await;
            }
        }
        RoundState::HandComplete => {
            if let Some(complete_at) = hand_complete_at {
                let elapsed = complete_at.elapsed().as_secs();
                if elapsed >= state.config.hand_complete_wait_secs {
                    let (active, removed_players) = {
                        // First pass: collect wallet->player_id mappings with read lock
                        let wallet_to_player_id: std::collections::HashMap<String, String> = {
                            let gs = state.state.read().await;
                            let mut map = std::collections::HashMap::new();
                            if let Some(table) = gs.tables.get(&table_id) {
                                for seat in table.seats.values() {
                                    let is_broke = seat.stack == 0;
                                    let is_sitting_out = seat.sitting_out;
                                    if is_broke || is_sitting_out {
                                        if let Some(player) = &seat.player {
                                            if let Some(p) = gs.players.values().find(|p| p.wallet_address.0 == player.wallet_address.0) {
                                                map.insert(player.wallet_address.to_string(), p.id.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            map
                        };

                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            let mut to_remove = Vec::new();
                            for seat in table.seats.values_mut() {
                                let is_broke = seat.stack == 0;
                                let is_sitting_out = seat.sitting_out;
                                if is_broke || is_sitting_out {
                                    if let Some(player) = &seat.player {
                                        let stack = if is_sitting_out { seat.stack } else { 0 };
                                        to_remove.push((player.wallet_address.to_string(), stack));
                                    }
                                }
                            }
                            // Return chips to sitting_out players
                            for (address, stack) in to_remove.iter() {
                                if *stack > 0 {
                                    tracing::info!("return chips to sitting_out player: {} stack: {}", address, stack);
                                    if let Some(pid) = wallet_to_player_id.get(address) {
                                        let _ = state.db.update_chips(pid, *stack as i64).await;
                                    }
                                }
                            }
                            // Remove players from table
                            for (wallet_addr,_) in to_remove.iter() {
                                tracing::info!("remove_player_by_pk: {}", wallet_addr);
                                if let Some(pk_hex) = table.get_pk_hex_by_wallet_address(wallet_addr) {
                                    table.remove_player_by_pk(&pk_hex);
                                }
                            }
                            table.reset_for_next_hand();
                            (table.active_players().len(), to_remove)
                        } else { (0, Vec::new()) }
                    };

                    let tables_info = state.get_current_tables().await;
                    let players_info = state.get_current_players().await;
                    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;


                    for (wallet_address, _) in removed_players.iter() {
                        let gs = state.state.read().await;
                        let socket_id = gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.socket_id.clone());
                        drop(gs);
                        if let Some(sid_str) = socket_id {
                            if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                                if let Some(socket) = io.get_socket(sid) {
                                    let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info.clone(), table_id });
                                }
                            }
                        }
                    }

                    for (wallet_address, _) in removed_players.iter() {
                        let player_name = {
                            let gs = state.state.read().await;
                            gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.name.clone())
                        };
                        if let Some(name) = player_name {
                            broadcast::broadcast_to_table(&io, &state, table_id, Some(&format!("{} left the table.", name))).await;
                        }
                    }

                    tracing::info!("[TICK] Table {} HandComplete: {} active after reset, {} players removed", table_id, active, removed_players.len());
                    if active < MIN_START_NUM as usize {
                        broadcast::broadcast_to_table(io, state, table_id, Some("Waiting for more players")).await;
                        return false;
                    } else {
                        broadcast::broadcast_to_table(io, state, table_id, None).await;
                    }
                }
            } else {
                tracing::info!("Table {} HandComplete: no active players", table_id);
            }
        }
    }
    true
}

pub(crate) async fn handle_auto_fold(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let auto_fold = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            if let Some(turn_id) = table.turn {
                table.seats.get(&turn_id)
                    .and_then(|seat| {
                        if seat.disconnected && !seat.folded {
                            seat.player.as_ref().map(|p| p.pk_hex.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(pk_hex) = auto_fold {
        let fold_result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.handle_fold(&pk_hex)
            } else {
                None
            }
        };
        if let Some(res) = fold_result {
            broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
            handle_turn_advance(io, state, table_id).await;
        }
    }
}

pub(crate) async fn handle_turn_advance(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.unfolded_players().len() <= 1 {
                table.end_without_showdown();
            } else if table.is_betting_round_complete() {
                table.advance_to_next_phase();
                if table.round_state != RoundState::ShowdownReveal {
                    table.turn = table.next_unfolded_player(table.button.unwrap_or(1), 1);
                    table.betting_timeout_start = Some(std::time::Instant::now());
                    for i in 1..=table.max_players {
                        if let Some(seat) = table.seats.get_mut(&i) {
                            seat.turn = table.turn == Some(i);
                        }
                    }
                }
            } else {
                let last_turn = table.turn.unwrap_or(1);
                table.turn = table.next_unfolded_player(last_turn, 1);
                table.betting_timeout_start = Some(std::time::Instant::now());
                for i in 1..=table.max_players {
                    if let Some(seat) = table.seats.get_mut(&i) {
                        seat.turn = table.turn == Some(i);
                    }
                }
            }
            Some(())
        } else { None }
    };
    if result.is_some() {
        broadcast::broadcast_to_table(io, state, table_id, None).await;
    }
}

pub(crate) async fn process_action(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, req: ActionRequest) {
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            // F8 fix: validate that it's the requesting player's turn and
            // the game is in a betting phase before processing any action.
            let is_betting_phase = matches!(table.round_state,
                RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River);
            let is_valid_turn = is_betting_phase && table.turn.map_or(false, |turn_id| {
                table.seats.get(&turn_id).map_or(false, |seat| {
                    seat.player.as_ref().map_or(false, |p| p.pk_hex == req.pk_hex)
                        && !seat.folded
                        && !seat.sitting_out
                        && seat.stack > 0
                })
            });

            if !is_valid_turn {
                tracing::warn!(
                    "[process_action] Rejected action {} from pk={}: not their turn or not betting phase (turn={:?}, state={:?})",
                    req.action, req.pk_hex, table.turn, table.round_state
                );
                None
            } else {
                // F9 fix: only clear sitting_out after turn validation passes.
                // (A valid turn implies the player is not sitting_out, but we
                // keep this for safety in case of race conditions.)
                if let Some(seat) = table.find_player_by_pk_mut(&req.pk_hex) {
                    seat.sitting_out = false;
                }
                match req.action.as_str() {
                    "fold" => table.handle_fold(&req.pk_hex),
                    "check" => table.handle_check(&req.pk_hex),
                    "call" => table.handle_call(&req.pk_hex),
                    "raise" => table.handle_raise(&req.pk_hex, req.amount.unwrap_or(0)),
                    "allin" => table.handle_allin(&req.pk_hex), // D2 fix
                    _ => None,
                }
            }
        } else { None }
    };
    if let Some(res) = result {
        broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
        handle_turn_advance(io, state, table_id).await;
    }
}

pub(crate) async fn clear_for_one_player(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.clear_win_messages();
        }
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut gs = state_c.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.clear_seat_hands();
                table.reset_board_and_pot();
            }
        }

        broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("Waiting for more players")).await;
    });
}
