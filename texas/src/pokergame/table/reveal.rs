use super::*;

impl Table {
    pub fn start_preflop_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active(){
            return;
        }
        let player_pks: Vec<GamePkHex> = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            let mut hand_cards = Vec::new();
            for (other_pk, state) in &self.mental_poker_game.players {
                if pk.0 == *other_pk { continue; }
                for card in &state.hand_encrypted {
                    hand_cards.push(card.encrypted_card.clone());
                }
            }
            player_assignments.insert(pk.clone(), PlayerRevealAssignment {
                hand_card: hand_cards,
                community_card: vec![],
            });
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::HandReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 5,
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Hand reveal phase started for {} players",
            player_pks.len());
    }

    pub fn start_community_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_community_reveal_phase] Reveal phase already active");
            return;
        }

        let player_pks: Vec<GamePkHex> = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();

        let unreveal_cards = self.mental_poker_game.list_unreveal_community_cards_encrypted();
        let community_cards: Vec<ElGamalCiphertext> = unreveal_cards.iter().map(|c| c.encrypted_card.clone()).collect();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            player_assignments.insert(pk.clone(), PlayerRevealAssignment {
                hand_card: vec![],
                community_card: community_cards.clone(),
            });
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::CommunityReveal,
            current_card_index: 0,
            // G6 修复：community reveal 阶段不揭示玩家手牌，total_cards_per_player 应为 0
            total_cards_per_player: 0,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Community reveal phase started for {} players ({} community cards)",
            player_pks.len(), self.mental_poker_game.community_cards_encrypted.len());
    }

    pub fn start_showdown_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        // F4 fix: only include players who are actually in the mental poker game,
        // so pending_players stays consistent with player_assignments.
        let player_pks: Vec<GamePkHex> = self.seats().values()
            .filter(|s| !s.folded )
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .filter(|pk| self.mental_poker_game.players.contains_key(pk.as_str()))
            .collect();
        let mut player_assignments = HashMap::new();
        for seat in self.seats().values() {
            if seat.folded { continue; }
            if let Some(player) = &seat.player {
                if let Some(men_player) = self.mental_poker_game.players.get(player.pk_hex.as_str()) {
                    let hand_cards = men_player.hand_encrypted.iter().map(|f| f.encrypted_card.clone()).collect();
                    player_assignments.insert(player.pk_hex.clone(), PlayerRevealAssignment {
                        hand_card: hand_cards,
                        community_card: vec![],
                    });
                }
            }
        }
        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::ShowdownReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: player_pks,
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Hand card reveal (showdown) phase started");
    }

    pub fn mark_player_reveal_complete(&mut self, player_pk: &GamePkHex) -> bool {
        if !self.reveal_token_state.is_active() { return false; }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) { return false; }

        self.reveal_token_state.completed_players.push(player_pk.clone());
        self.reveal_token_state.pending_players.retain(|p| p != player_pk);

        tracing::info!("[REVEAL-TOKEN] Player {} completed {} phase, remaining: {}",
            player_pk, self.reveal_token_state.phase,
            self.reveal_token_state.pending_players.len());

        if self.reveal_token_state.pending_players.is_empty() {
            self.on_reveal_complete();
            return true;
        }
        false
    }

    /// 镜像 Move on_reveal_complete：所有 pending 玩家完成后的状态转换
    pub fn on_reveal_complete(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        if !self.reveal_token_state.pending_players.is_empty() {
            return;
        }

        let phase = self.reveal_token_state.phase;
        self.reveal_token_state.reset();

        match phase {
            RevealPhase::None => {
                // 不应到达（is_active 已检查），防御性处理
                tracing::warn!("[on_reveal_complete] reached with None phase");
            }
            RevealPhase::HandReveal => {
                // 翻牌前手牌揭牌完成 → 进入 PreFlop 下注轮
                // 对齐 Move check_reveal_phase_complete: post_blinds THEN start_betting_round(true)
                // set_blinds 已包含首行动作设置（对齐 Move post_blinds），无需再调用 init_turn
                self.set_blinds();
                self.start_betting_round(true);
            }
            RevealPhase::CommunityReveal => {
                // 公共牌揭牌完成 → 进入对应下注轮
                self.start_betting_round(false);
            }
            RevealPhase::ShowdownReveal => {
                // 摊牌揭牌完成 → 判定赢家
                // 对齐 Move settle_hand: 先 calculate_side_pots(total_bet) 再分配
                self.calculate_side_pots();
                self.determine_side_pot_winners();
                self.determine_main_pot_winner();
            }
            RevealPhase::RedealReveal => {
                // 重新发牌揭牌完成，保持当前 round_state 不变
                tracing::info!("[on_reveal_complete] Redeal reveal complete, round_state stays {:?}", self.round_state());
            }
        }

        // 仅在下注轮开始时同步 seat.turn（ShowdownReveal 后无行动者，不需要同步）
        if phase != RevealPhase::ShowdownReveal {
            let current_turn = self.turn();
            for i in 1..=self.max_players() {
                if let Some(seat) = self.local_seats.get_mut(&i) {
                    seat.turn = current_turn == Some(i);
                }
            }
        }
        tracing::info!("[REVEAL-TOKEN] All reveal phases complete, switch round state to {:?}", self.round_state());
        // 通知前端 reveal 完成
        self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
            message: None,
        });
    }

    /// 镜像 Move on_reveal_timeout：处理揭牌超时
    pub fn on_reveal_timeout(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        let timed_out_pks = self.reveal_token_state.pending_players.clone();
        tracing::warn!("[REVEAL-TOKEN] Timeout for players: {:?}", timed_out_pks);

        let is_preflop = self.round_state() == RoundState::PreFlop;

        // 对齐 Move clear_reveal_timeout_player：踢出所有超时玩家
        // kick_player_internal 会处理退款/pot/状态清理，可能触发 reset_for_next_hand
        for pk in &timed_out_pks {
            self.remove_player_by_pk(pk);
        }

        // kick 可能已触发 reset_for_next_hand（活跃玩家不足）
        if self.round_state() == RoundState::Waiting {
            return;
        }

        let active_count = self.active_players().len();

        if is_preflop {
            // PreFlop reveal 超时：重开整手
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 退还未被踢玩家的筹码，重开整手
            self.refund_all_bets();
            self.reset_for_next_hand();
        } else {
            // 其他阶段超时：启动 reconstruct
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 启动 reconstruct
            let _ = self.start_reconstruct();
        }
    }

    /// 镜像 Move start_betting_round：启动下注轮。
    /// 对齐 Move: 创建 BettingRound + 重置 acted_this_round + 设置首行动作。
    pub fn start_betting_round(&mut self, is_preflop: bool) {
        // C5 修复扩展到 preflop：当所有活跃玩家已 all-in 时，跳过下注轮。
        // preflop 时盲注已下，若全员 all-in 则无人可行动，直接推进。
        // postflop 同理：find_next_active_seat 在全员 all-in 时会返回 None，需先检查。
        if !self.has_actionable_player() {
            self.betting_round = None;
            self.advance_to_next_phase();
            return;
        }

        if is_preflop {
            // PreFlop: 盲注已由调用方发布（set_blinds），bet 保留盲注金额。
            // 仅重置 has_acted（对齐 Move: seat.acted_this_round = false）
            for seat in self.local_seats.values_mut() {
                seat.has_acted = false;
            }
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new_preflop(self.summary.min_bet * 2));
            // preflop 的 current_turn 已由 set_blinds 设置，无需再设
        } else {
            // PostFlop: 重置下注 + 创建下注轮（对齐 Move: seat.bet = 0, acted_this_round = false）
            self.reset_bets_and_actions();
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new(self.summary.min_bet * 2));

            // 对齐 Move start_betting_round: 设置 postflop 首行动作
            let first = self.next_unfolded_player(self.button().unwrap_or(1), 1);
            self.set_turn(first);
        }
        self.set_betting_started_at(now_ms());
    }

    /// 对齐 Move has_actionable_player：是否存在可行动的玩家（非 fold、非 all-in、非 waiting）
    pub fn has_actionable_player(&self) -> bool {
        self.seats().values().any(|s| {
            !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0
        })
    }

    pub fn check_reveal_timeout(&mut self) -> Option<Vec<GamePkHex>> {
        if !self.reveal_token_state.is_active() {
            return None;
        }
        let timeout_start = match self.reveal_token_state.timeout_start {
            Some(t) => t,
            None => return None,
        };
        if timeout_start.elapsed().as_secs() >= self.reveal_token_state.timeout_seconds {
            if self.reveal_token_state.pending_players.is_empty() {
                return None;
            }
            let time_out_pks = self.reveal_token_state.pending_players.clone();
            self.reveal_token_state.reset();
            tracing::info!("[REVEAL-TOKEN] timeout {:?} players, clear reveal state", time_out_pks.len());
            return Some(time_out_pks);
        }
        None
    }

    pub fn submit_player_reveal_tokens(
        &mut self,
        player_pk: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        if !self.reveal_token_state.is_active() {
            return Err("Reveal token phase not active".to_string());
        }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) {
            return Err("Player already submitted or not pending".to_string());
        }

        let assign = match self.reveal_token_state.player_assignments.get(player_pk) {
            Some(a) => a,
            None => return Err(format!("No assignment found for player {}", player_pk)),
        };
        tracing::info!("[REVEAL-TOKEN] Player {} submitted token ({}) num {:?}",
            player_pk, self.reveal_token_state.phase, tokens.len());

        for token in tokens {
            let cards = match self.reveal_token_state.phase {
                RevealPhase::None => {
                    return Err("Reveal token phase not active".to_string());
                }
                RevealPhase::HandReveal => &assign.hand_card,
                RevealPhase::CommunityReveal => &assign.community_card,
                RevealPhase::ShowdownReveal => &assign.hand_card,
                RevealPhase::RedealReveal => &assign.hand_card,
            };
            if !cards.iter().any(|pct| pct == &token.encrypted_card) {
                return Err(format!("Invalid token in {} phase", self.reveal_token_state.phase));
            }
            if let Err(e) = self.mental_poker_game.submit_reveal_token(token.clone(), player_pk) {
                tracing::error!("[REVEAL-TOKEN] Token submission failed: {:?}", e);
                return Err(format!("Token submission failed: {:?}", e));
            }
        }
        Ok(())
    }

    pub fn get_reveal_token_public_state(&self) -> Option<RevealTokenPublicState> {
        if self.reveal_token_state.is_active() {
            Some(RevealTokenPublicState {
                phase: self.reveal_token_state.phase.to_string(),
                completed_players: self.reveal_token_state.completed_players.clone(),
                pending_players: self.reveal_token_state.pending_players.clone(),
                player_assignments: self.reveal_token_state.player_assignments.clone(),
            })
        } else {
            None
        }
    }
}
