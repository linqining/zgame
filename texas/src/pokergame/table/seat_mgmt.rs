use super::*;
use poker_protocol::crypto::EcPoint;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};
use crate::pokergame::game_state::LeaveGameRoundJson;

impl Table {
    pub fn add_player(&mut self, game_pk: GamePkHex, wallet_addr: WalletAddress) -> Result<(), JoinError> {
        if self.players.contains_key(&game_pk) {
            tracing::info!("Player {} is already in game add_player", *game_pk);
            return Ok(());
        }
        self.players.insert(game_pk, wallet_addr);
        Ok(())
    }

    pub fn remove_player_by_pk(&mut self, pk: &GamePkHex) {
        self.players.remove(pk);
        tracing::info!("remove_player_by_pk stand_player_by_pk: {}", pk);
        self.stand_player_by_pk(pk);
        let _ = self.mental_poker_game.leave_player(pk);
    }

    pub fn leave_talbe_and_clear_shuffle(&mut self, pk: &GamePkHex){
        self.remove_player_by_pk(pk);
        self.shuffle_state.completed_players.retain(|p| p != pk);
        self.shuffle_state.pending_players.retain(|p| p != pk);
        if self.shuffle_state.current_player_pk.as_ref() == Some(pk) {
            self.shuffle_state.current_player_pk = None;
        }
        self.waiting_players.remove(pk);
    }

    pub fn leave_player_with_proof(
        &mut self,
        pk: &GamePkHex,
        player_pk: &EcPoint,
        leave_round_json: &LeaveGameRoundJson,
    ) -> Result<(), String> {
        // Verify the player is in the game
        if !self.players.contains_key(pk) {
            return Err("Player not found".to_string());
        }

        // Convert JSON to native types
        let leave_round = leave_round_json.to_leave_game_round()?;

        // Verify input_cards match current deck
        let current_deck = &self.mental_poker_game.deck_encrypted;
        if leave_round.input_cards.len() != current_deck.len() {
            return Err("Input cards length mismatch".to_string());
        }
        for (i, input_ct) in leave_round.input_cards.iter().enumerate() {
            if input_ct.c1 != current_deck[i].c1 || input_ct.c2 != current_deck[i].c2 {
                return Err(format!("Input card {} does not match current deck", i));
            }
        }

        // Verify the LeaveProof
        let mut transcript = MerlinTranscript::new(b"poker_protocol_leave");
        if !leave_round.leave_proof.verify(&leave_round.input_cards, &leave_round.output_cards, player_pk, &mut transcript) {
            return Err("Invalid leave proof".to_string());
        }

        // Update the deck with the leave output
        self.mental_poker_game.deck_encrypted = leave_round.output_cards;
        tracing::info!("leave_player_with_proof pk: {}", pk);
        self.shuffle_state.completed_players.retain(|p| p != pk);
        self.shuffle_state.pending_players.retain(|p| p != pk);
        if self.shuffle_state.current_player_pk.as_ref() == Some(pk) {
            self.shuffle_state.current_player_pk = None;
        }
        self.waiting_players.remove(pk);

        // Remove the player
        self.players.remove(pk);
        self.pk_to_seat.remove(pk);
        tracing::info!("leave_player_with_proof: {}", pk);
        self.stand_player_by_pk(pk);
        let _ = self.mental_poker_game.leave_player(&**pk);

        Ok(())
    }



    pub fn find_random_empty_seat(&self) -> Option<u32> {
        let empty_seats: Vec<u32> = (1..=self.max_players)
            .filter(|&seat_id| !self.seats.contains_key(&seat_id))
            .collect();

        if empty_seats.is_empty() {
            None
        } else {
            use rand::seq::SliceRandom;
            empty_seats.choose(&mut rand::thread_rng()).copied()
        }
    }

    pub fn sit_player(&mut self, player: GamePlayer, seat_id: u32, amount: u64, is_waiting: bool) {
        if seat_id < 1 || seat_id > self.max_players {
            return;
        }
        if self.seats.contains_key(&seat_id) {
            return;
        }
        let pk_hex = player.pk_hex.clone();
        let mut seat = Seat::new(seat_id, Some(player), amount, amount);
        seat.is_waiting = is_waiting;
        let first_player = self.seats.is_empty();
        self.seats.insert(seat_id, seat);
        self.pk_to_seat.insert(pk_hex, seat_id);
        if first_player {
            self.button = Some(seat_id);
        }
    }

    pub fn rebuy_player(&mut self, seat_id: u32, amount: u64) {
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.stack += amount;
        }
    }

    pub fn stand_player_by_pk(&mut self, pk: &GamePkHex) {
        self.pk_to_seat.remove(pk);
        let mut seat_to_remove: Option<u32> = None;
        for (id, seat) in self.seats.iter() {
            if seat.player.as_ref().map_or(false, |p| &p.pk_hex == pk) {
                seat_to_remove = Some(*id);
                break;
            }
        }
        if let Some(id) = seat_to_remove {
            self.seats.remove(&id);
        }
        if self.is_playing() && self.seats.len() == 1 {
            self.end_without_showdown();
            // end_without_showdown 已将 round_state 设为 HandComplete，
            // 由 game loop 的 HandComplete 分支自然流转到 Waiting
        }
        if self.seats.is_empty() {
            self.reset_empty_table();
        }
    }

    pub fn find_player_by_pk(&self, pk: &GamePkHex) -> Option<&Seat> {
        self.pk_to_seat.get(pk).and_then(|&seat_id| self.seats.get(&seat_id))
    }

    pub fn find_player_by_pk_mut(&mut self, pk: &GamePkHex) -> Option<&mut Seat> {
        if let Some(&seat_id) = self.pk_to_seat.get(pk) {
            self.seats.get_mut(&seat_id)
        } else {
            None
        }
    }

    pub fn find_player_by_wallet(&self, wallet: &str) -> Option<&Seat> {
        for seat in self.seats.values() {
            if seat.player.as_ref().map_or(false, |p| p.wallet_address.0 == wallet) {
                return Some(seat);
            }
        }
        None
    }

    pub fn unfolded_players(&self) -> Vec<&Seat> {
        self.seats.values().filter(|s| !s.folded).collect()
    }

    pub fn active_players(&self) -> Vec<&Seat> {
        self.seats.values().filter(|s| !s.sitting_out && !s.is_waiting).collect()
    }

    pub fn next_player_by_filter<F>(&self, player: u32, places: u32, filter: F) -> u32
    where
        F: Fn(&Seat) -> bool,
    {
        let mut count = 0u32;
        let mut current = player;
        let mut iterations = 0u32;
        while count < places {
            current = if current >= self.max_players { 1 } else { current + 1 };
            if let Some(seat) = self.seats.get(&current) {
                if filter(seat) {
                    count += 1;
                }
            }
            iterations += 1;
            if iterations > self.max_players * 2 {
                tracing::warn!("[next_player_by_filter] infinite loop detected, breaking");
                return current;
            }
        }
        current
    }

    pub fn next_unfolded_player(&self, player: u32, places: u32) -> u32 {
        self.next_player_by_filter(player, places, |seat| !seat.folded && !seat.sitting_out)
    }

    pub fn next_active_player(&self, player: u32, places: u32) -> u32 {
        self.next_player_by_filter(player, places, |seat| !seat.sitting_out && !seat.is_waiting)
    }

    pub fn mark_player_disconnected(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let is_turn = seat.turn;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.disconnected = true;
            seat.disconnected_at = Some(now);
            seat.sitting_out = true;
        }
        if is_turn {
            if let Some(ref betting) = self.betting_round {
                let seat_ref = self.seats.get(&seat_id);
                if let Some(seat_ref) = seat_ref {
                    if betting.validate_fold(seat_ref).is_ok() {
                        if let Some(seat) = self.seats.get_mut(&seat_id) {
                            seat.fold();
                        }
                        if let Some(ref mut betting) = self.betting_round {
                            betting.update_after_fold();
                        }
                        return Some(ActionResult {
                            seat_id,
                            message: format!("{} auto-folds (disconnected)", player_name),
                        });
                    }
                }
            }
        }
        None
    }

    pub fn reconnect_player(&mut self, wallet_address: &str) -> bool {
        for seat in self.seats.values_mut() {
            if seat.player.as_ref().map_or(false, |p| p.wallet_address.0 == wallet_address) {
                if let Some(player) = seat.player.as_mut() {
                    tracing::info!("reconnect_player: {}", player.name.clone());
                }
                seat.disconnected = false;
                seat.disconnected_at = None;
                seat.sitting_out = false;
                return true;
            }
        }
        false
    }

    pub fn is_player_disconnected_by_pk(&self, pk: &GamePkHex) -> bool {
        self.seats.values()
            .any(|s| s.player.as_ref().map_or(false, |p| &p.pk_hex == pk) && s.disconnected)
    }
}
