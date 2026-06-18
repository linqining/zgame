use super::*;

impl Table {
    pub fn start_preflop_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active{
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
            is_active: true,
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
        if self.reveal_token_state.is_active {
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
            is_active: true,
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
        if self.reveal_token_state.is_active {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        // F4 fix: only include players who are actually in the mental poker game,
        // so pending_players stays consistent with player_assignments.
        let player_pks: Vec<GamePkHex> = self.seats.values()
            .filter(|s| !s.folded )
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .filter(|pk| self.mental_poker_game.players.contains_key(pk.as_str()))
            .collect();
        let mut player_assignments = HashMap::new();
        for seat in self.seats.values() {
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
            is_active: true,
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
        if !self.reveal_token_state.is_active { return false; }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) { return false; }

        self.reveal_token_state.completed_players.push(player_pk.clone());
        self.reveal_token_state.pending_players.retain(|p| p != player_pk);

        tracing::info!("[REVEAL-TOKEN] Player {} completed {} phase, remaining: {}",
            player_pk, self.reveal_token_state.phase,
            self.reveal_token_state.pending_players.len());

        if self.reveal_token_state.pending_players.is_empty() {
            self.reveal_token_state.reset();
            match self.round_state {
                RoundState::PreFlopReveal => {
                    self.transition_to(RoundState::PreFlop);
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::FlopReveal => {
                    self.transition_to(RoundState::Flop);
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::TurnReveal => {
                    self.transition_to(RoundState::Turn);
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::RiverReveal => {
                    self.transition_to(RoundState::River);
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::ShowdownReveal => {
                    // determine_main_pot_winner 内部会将 round_state 设为 Showdown 并设置 showdown_at
                    self.determine_side_pot_winners();
                    self.determine_main_pot_winner();
                }
                _ => {
                    tracing::error!("[mark_player_reveal_complete] Invalid round state: {:?}", self.round_state);
                }
            }
            // Ensure seat.turn is consistent with table.turn when entering a betting state
            for i in 1..=self.max_players {
                if let Some(seat) = self.seats.get_mut(&i) {
                    seat.turn = self.turn == Some(i);
                }
            }
            tracing::info!("[REVEAL-TOKEN] All reveal phases complete, switch round state to {:?}", self.round_state);
            return true;
        }
        false
    }

    pub fn check_reveal_timeout(&mut self) -> Option<Vec<GamePkHex>> {
        if !self.reveal_token_state.is_active {
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
        if !self.reveal_token_state.is_active {
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
        if self.reveal_token_state.is_active {
            Some(RevealTokenPublicState {
                is_active: true,
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
