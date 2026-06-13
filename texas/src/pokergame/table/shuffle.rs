use super::*;
use crate::pokergame::player::truncate_name;
use merlin::Transcript;

impl Table {
    pub fn is_all_players_shuffled(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn is_pending_shuffle_player_empty(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn complete_shuffle_player_count(&self) -> usize {
        self.shuffle_state.completed_players.len()
    }

    pub fn start_shuffle(&mut self) -> Result<(), String> {
        if self.round_state == RoundState::Shuffling {
            return Ok(());
        }
        self.reset_shuffle();
        self.transition_to(RoundState::Shuffling);
        self.shuffle_state.is_active = true;

        let already_completed: std::collections::HashSet<GamePkHex> =
            self.shuffle_state.completed_players.iter().cloned().collect();

        self.remove_inactive_players();
        self.register_waiting_players();
        self.clear_waiting_flags();
        self.init_pending_players(&already_completed);

        self.shuffle_state.timeout_seconds = 10;
        Ok(())
    }

    pub fn remove_inactive_players(&mut self) {
        let active_pks: std::collections::HashSet<String> = self.active_players()
            .iter()
            .filter_map(|p| p.player.as_ref())
            .map(|p| p.pk_hex.0.clone())
            .collect();

        let remove_pks: Vec<GamePkHex> = self.mental_poker_game.players.iter()
            .filter(|(_, player_state)| !active_pks.contains(&player_state.pk_hex))
            .map(|(_, player_state)| GamePkHex::new(player_state.pk_hex.clone()))
            .collect();

        for pk in remove_pks {
            let _ = self.mental_poker_game.leave_player(&pk);
        }
    }

    pub fn register_waiting_players(&mut self) {
        let active_pk_hexs: std::collections::HashSet<String> = self.seats.values()
            .filter_map(|seat| seat.player.as_ref())
            .map(|player| player.pk_hex.0.clone())
            .collect();

        let waiting_players_to_register: Vec<(GamePkHex, PlayerWithProof)> = self.waiting_players.iter().map(|(k,v)| (k.clone(), v.clone())).collect();
        for (pk_hex, waiting_info) in waiting_players_to_register {
            if active_pk_hexs.contains(&pk_hex.to_string()) {
                self.mental_poker_game.register_player(
                    pk_hex.to_string(),
                    waiting_info.pk,
                    waiting_info.pk_proof,
                );
                tracing::info!("[SHUFFLE] Waiting player {} registered to mental_poker_game", pk_hex);
            } else {
                tracing::info!("[SHUFFLE] Waiting player {} left the table, skipping registration", pk_hex);
            }
        }
        self.waiting_players.clear();
    }

    pub fn clear_waiting_flags(&mut self) {
        for seat in self.seats.values_mut() {
            if seat.is_waiting {
                seat.is_waiting = false;
                if let Some(player) = &seat.player {
                    tracing::info!("[SHUFFLE] Player {} is_waiting cleared, registered to shuffle", player.pk_hex);
                }
            }
        }
    }

    pub fn init_pending_players(&mut self, already_completed: &std::collections::HashSet<GamePkHex>) {
        // todo sitting_out 回来的玩家再加入洗牌(假如在洗牌阶段)
        self.shuffle_state.pending_players = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .filter(|pk| !already_completed.contains(pk))
            .collect();
        tracing::info!("[SHUFFLE] Init pending players: {:?}", self.shuffle_state.pending_players);
        if self.shuffle_state.pending_players.is_empty() {
            tracing::warn!("[SHUFFLE] Init pending players is empty");
            return;
        }
        if let Some(first_pk) = self.shuffle_state.pending_players.first() {
            self.set_current_shuffler(first_pk.clone());
        } else if self.complete_shuffle_player_count() >= MIN_START_NUM as usize {
            self.shuffle_state.is_active = false;
            self.transition_to(RoundState::ShuffleComplete);
            tracing::info!("[SHUFFLE] All players already completed shuffle, skipping");
        }
    }

    pub fn reset_shuffle(&mut self) {
        tracing::info!("[SHUFFLE] === Shuffle reset ===");
        tracing::info!("[SHUFFLE] Total active players: {}", self.active_players().len());
        self.shuffle_state.reset();
        tracing::info!("[SHUFFLE] Shuffle order: {:?}, current: {:?}",
            self.shuffle_state.pending_players, self.shuffle_state.current_player_pk);
    }

    pub fn set_current_shuffler(&mut self, player_pk: GamePkHex) {
        self.shuffle_state.current_player_pk = Some(player_pk);
        self.shuffle_state.timeout_start = Some(std::time::Instant::now());
        tracing::info!("[SHUFFLE] Now waiting for player {} to shuffle (timeout: {}s)",
            self.shuffle_state.current_player_pk.as_ref().unwrap(), self.shuffle_state.timeout_seconds);
    }

    pub fn check_shuffle_timeout(&mut self) -> Option<GamePkHex> {
        if !self.shuffle_state.is_active {
            return None;
        }
        let timeout_start = match self.shuffle_state.timeout_start {
            Some(t) => t,
            None => return None,
        };
        if timeout_start.elapsed().as_secs() >= self.shuffle_state.timeout_seconds {
            let timed_out_pk = self.shuffle_state.current_player_pk.clone()?;
            tracing::warn!("[SHUFFLE] Player {} timed out after {}s!",
                timed_out_pk, self.shuffle_state.timeout_seconds);
            Some(timed_out_pk)
        } else {
            None
        }
    }

    pub fn join_player_and_shuffle(
        &mut self,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: MaskAndShuffleRoundJson,
        seat_id: u32,
        amount: u64,
    ) -> Result<JoinResult, JoinError> {
        let wallet_address = player.wallet_address.0.clone();
        let pk_hex=ecpoint_to_hex(&player_pk);

        let player_for_seat = player.clone();

        if self.seats.values().any(|seat| {
            seat.player.as_ref().map_or(false, |p| p.pk_hex.0 == pk_hex)
        }) {
            tracing::info!("Player {} is already in game", pk_hex);
            return Err(JoinError::PlayerAlreadyInGame);
        }

        let actual_seat_id = if seat_id == 0 {
            self.find_random_empty_seat().ok_or(JoinError::InvalidSeatId)?
        } else {
            if seat_id < 1 || seat_id > self.max_players {
                return Err(JoinError::InvalidSeatId);
            }
            if self.seats.contains_key(&seat_id) {
                return Err(JoinError::SeatAlreadyOccupied);
            }
            seat_id
        };

        // Waiting/Shuffling 阶段玩家可以加入游戏并洗牌
        // ShuffleComplete 及之后阶段，玩家只能等待下一手加入
        let is_join_before_start = matches!(self.round_state, RoundState::Waiting | RoundState::Shuffling);

        let pk_proof = pk_proof_json.to_proof().map_err(|e| JoinError::Crypto(e))?;
        if !pk_proof.verify(&player_pk) {
            return Err(JoinError::InvalidPkProof);
        }
        tracing::info!("[SHUFFLE] Player {} joined and shuffled, sat at seat {}, round state {:?}",
            pk_hex, actual_seat_id,self.round_state);
        let player_for_seat = GamePlayer {
            name: truncate_name(&player.name, 12),
            bankroll: player.bankroll,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: player.wallet_address.clone(),
        };

        if is_join_before_start {
            let round = round_json.to_mask_and_shuffle_round().map_err(|e| JoinError::Crypto(e))?;
            let mut transcript = Transcript::new(b"poker_protocol_mask_shuffle");
            let input_cards = self.mental_poker_game.deck_encrypted.iter().map(|c| c.clone()).collect::<Vec<_>>();
            if !round.remask_proof.verify( &input_cards,
            &round.mask_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
             &player_pk, &mut transcript) {
                return Err(JoinError::InvalidRemaskProof);
            }

            let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
            let share_pk = current_agg_pk + &player_pk;
            if round.proof.verify(
                &round.mask_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
                &round.output_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
                &share_pk,
                &mut transcript,
            ).is_err() {
                return Err(JoinError::InvalidShuffleProof);
            }

            let pk_hex_game = GamePkHex::new(pk_hex.clone());
            self.mental_poker_game.register_player(pk_hex.clone(), player_pk, pk_proof);
            self.mental_poker_game.deck_encrypted = round.output_cards;
            self.add_player(GamePkHex::new(pk_hex.clone()), player.wallet_address.clone());
            self.sit_player(player_for_seat, actual_seat_id, amount, false);

            if self.shuffle_state.is_active {
                self.shuffle_state.completed_players.push(pk_hex_game.clone());
                self.shuffle_state.pending_players.retain(|p| *p != pk_hex_game);
            }
            tracing::info!("[SHUFFLE] Player {} joined and shuffled, sat at seat {}", pk_hex, actual_seat_id);
            Ok(JoinResult::JoinedAndShuffled)
        } else {
            let player_for_proof = Player {
                socket_id: player.socket_id.clone(),
                id: player.wallet_address.0.clone(),
                name: player.wallet_address.0.clone(),
                bankroll: player.bankroll,
                wallet_address: player.wallet_address.clone(),
            };
            self.waiting_players.insert(GamePkHex::new(pk_hex.clone()), PlayerWithProof {
                player: player_for_proof,
                pk: player_pk,
                pk_proof,
            });
            self.add_player(GamePkHex::new(pk_hex.clone()), player.wallet_address.clone());
            self.sit_player(player_for_seat, actual_seat_id, amount, true);
            tracing::info!("[SHUFFLE] Player {} joined as waiting, sat at seat {}, will join next hand roundState{:?}", pk_hex, actual_seat_id,self.round_state);
            Ok(JoinResult::JoinedWaiting)
        }
    }

    pub fn submit_verified_shuffle(
        &mut self,
        player_pk_hex: &GamePkHex,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: ShuffleProofJson,
    ) -> Result<(), String> {
        if !self.shuffle_state.is_active {
            return Err("Shuffle not active".to_string());
        }
        if self.shuffle_state.current_player_pk != Some(player_pk_hex.clone()) {
            return Err("Not current player".to_string());
        }

        let _ = self.mental_poker_game.players.get(&**player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        let output_cards = output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let proof = shuffle_proof.to_proof()?;
        let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let input_cards = self.mental_poker_game.deck_encrypted.clone();
        let mut transcript = Transcript::new(b"poker_protocol_player_shuffle");
        if proof.verify(
            &input_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
            &output_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
            &current_agg_pk,
            &mut transcript,
        ).is_err() {
            return Err("Invalid shuffle proof".to_string());
        }
        self.mental_poker_game.deck_encrypted = output_cards;
        self.shuffle_state.completed_players.push(player_pk_hex.clone());
        self.shuffle_state.pending_players.retain(|p| p != player_pk_hex);
        Ok(())
    }

    pub fn complete_or_continue_next_shuffler(&mut self) {
        if self.shuffle_state.pending_players.is_empty() && self.complete_shuffle_player_count() >= MIN_START_NUM as usize {
            self.transition_to(RoundState::ShuffleComplete);
        } else if let Some(next_pk) = self.shuffle_state.pending_players.first() {
            let next_pk_clone = next_pk.clone();
            self.set_current_shuffler(next_pk_clone);
        }
    }

    pub fn get_shuffle_public_state(&self) -> Option<ShufflePublicState> {
        if self.shuffle_state.is_active {
            Some(ShufflePublicState {
                is_active: true,
                current_player_pk: self.shuffle_state.current_player_pk.clone(),
                completed_players: self.shuffle_state.completed_players.clone(),
                pending_players: self.shuffle_state.pending_players.clone(),
                deck_encrypted: self.mental_poker_game.deck_encrypted
                    .iter()
                    .map(ElGamalCiphertextJson::from_ciphertext)
                    .collect(),
                aggregate_pk: ecpoint_to_hex(&self.mental_poker_game.key_manager.get_aggregated_pk()),
            })
        } else {
            None
        }
    }
}
