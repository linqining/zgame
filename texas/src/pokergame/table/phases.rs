use super::*;
use crate::pokergame::game_state::{PlayerRevealAssignment, RevealPhase, RevealTokenState};
use poker_protocol::crypto::ElGamalCiphertext;

impl Table {
    pub fn start_hand(&mut self) {
        self.went_to_showdown = false;
        self.reset_board_and_pot();
        self.reset_bets_and_actions();
        self.unfold_players();
        self.history = vec![];
        if self.active_players().len() > 1 {
            self.button = self.next_active_player(self.button.unwrap_or(1), 1);
            self.set_turn();
            self.deal_preflop();
            // G5 修复：移除块内重复的 update_history() 调用，仅保留块外的统一调用
            self.set_blinds();
            self.hand_over = false;
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new_preflop(self.min_bet * 2));
        }

        self.update_history();
    }

    pub fn unfold_players(&mut self) {
        for seat in self.seats.values_mut() {
            seat.folded = seat.sitting_out;
        }
    }

    pub fn set_turn(&mut self) {
        let active = self.active_players();
        self.turn = if active.len() <= 3 {
            self.button
        } else {
            self.next_active_player(self.button.unwrap_or(1), 3)
        };
    }

    pub fn set_blinds(&mut self) {
        let is_heads_up = self.active_players().len() == 2;
        let button = self.button.unwrap_or(1);

        self.small_blind = if is_heads_up {
            Some(button)
        } else {
            self.next_active_player(button, 1)
        };
        self.big_blind = if is_heads_up {
            self.next_active_player(button, 1)
        } else {
            self.next_active_player(button, 2)
        };

        let mut sb_amount: u64 = 0;
        let mut bb_amount: u64 = 0;

        if let Some(sb) = self.small_blind {
            if let Some(seat) = self.seats.get_mut(&sb) {
                let actual_sb = seat.place_blind(self.min_bet);
                sb_amount = actual_sb;
            }
        }
        if let Some(bb) = self.big_blind {
            if let Some(seat) = self.seats.get_mut(&bb) {
                let actual_bb = seat.place_blind(self.min_bet * 2);
                bb_amount = actual_bb;
            }
        }

        self.pot += sb_amount + bb_amount;
        self.call_amount = Some(self.min_bet * 2);
        self.min_raise = self.min_bet * 2; // = big_blind; minimum re-raise equals the big blind
    }

    pub fn deal_preflop(&mut self) {
        let max = self.max_players;
        let button = self.button.unwrap_or(1);
        let order: Vec<u32> = (button..=max).chain(1..button).collect();

        for _ in 0..2 {
            for &seat_id in &order {
                if let Some(seat) = self.seats.get_mut(&seat_id) {
                    if let Some(player) = &seat.player{
                        if !seat.sitting_out {
                            tracing::info!("player {} is not sitting out,deal to {}", player.name, seat_id);
                            if let Err(e) = self.mental_poker_game.deal_to_player(&player.pk_hex.clone(), 1) {
                                tracing::error!("[deal_preflop] deal_to_player failed for player {} seat {}: {:?}", player.name, seat_id, e);
                            }
                            seat.turn = self.turn == Some(seat_id);
                        }else{
                            tracing::info!("player {} is sitting out,no deal", player.name);
                        }
                    }
                }
            }
        }
    }

    pub fn deal_flop(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(3);
    }

    pub fn deal_turn_or_river(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(1);
    }

    /// 为解密失败的玩家重新发牌（不验证 plaintext，信任客户端报告）
    /// 返回重新发的牌索引列表
    pub fn redeal_cards_for_player(&mut self, player_pk: &GamePkHex, failed_indices: Vec<usize>) -> Result<Vec<usize>, String> {
        if !self.mental_poker_game.players.contains_key(&**player_pk) {
            return Err("Player not found".to_string());
        }

        let mut redealt = Vec::new();
        for idx in failed_indices {
            match self.mental_poker_game.redeal_to_player_unchecked(&**player_pk, idx) {
                Ok(_) => {
                    tracing::info!("Redealt card at index {} for player {}", idx, player_pk);
                    redealt.push(idx);
                }
                Err(e) => {
                    tracing::warn!("Redeal failed for player {} index {}: {:?}", player_pk, idx, e);
                }
            }
        }

        Ok(redealt)
    }

    /// 启动 redeal reveal 阶段，为重新发的牌收集所有玩家的 reveal token
    /// 不改变 round_state，保持 PreFlop，通过 reveal_token_state 追踪 redeal 进度
    pub fn start_redeal_reveal_phase(&mut self, redealt_player_pk: &GamePkHex, _redealt_indices: Vec<usize>) {
        if self.reveal_token_state.is_active {
            return;
        }

        let player_pks = self.mental_poker_game.players.keys().cloned().collect::<Vec<String>>();
        let mut player_assignments = HashMap::new();

        // 只需要为重新发牌的玩家收集 reveal token，其他玩家需要为新牌生成 token
        if let Some(player) = self.mental_poker_game.players.get(&**redealt_player_pk) {
            let redealt_cards: Vec<ElGamalCiphertext> = player.hand_encrypted.iter()
                .map(|c| c.encrypted_card.clone())
                .collect();
            for pk in &player_pks {
                if pk == &**redealt_player_pk { continue; }
                player_assignments.insert(GamePkHex::new(pk.clone()), PlayerRevealAssignment {
                    hand_card: redealt_cards.clone(),
                    community_card: vec![],
                });
            }
        }

        self.reveal_token_state = RevealTokenState {
            is_active: true,
            phase: RevealPhase::RedealReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 0,
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: player_pks.iter()
                .filter(|pk| *pk != &**redealt_player_pk)
                .map(|pk| GamePkHex::new(pk.clone()))
                .collect(),
            player_assignments,
        };

        tracing::info!("[REDEAL] Redeal reveal phase started for player {}, {} pending",
            redealt_player_pk, self.reveal_token_state.pending_players.len());
    }

    // 相当于原来的deal_next_street
    pub fn advance_to_next_phase(&mut self) {
        self.calculate_side_pots();
        self.reset_bets_and_actions();
        match self.round_state {
            RoundState::PreFlop => {
                // deal three community card
                self.deal_flop();
                // start reveal community card
                self.transition_to(RoundState::FlopReveal);
            }
            RoundState::Flop => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::TurnReveal);
            }
            RoundState::Turn => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::RiverReveal);
            }
            RoundState::River => {
                self.transition_to(RoundState::ShowdownReveal);
            }
            _ => {
                tracing::warn!("[advance_to_next_phase] unexpected round state: {:?}", self.round_state);
            }
        }
        self.update_history();
    }
}
