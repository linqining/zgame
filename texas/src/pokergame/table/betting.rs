use super::*;
use crate::pokergame::actions;

impl Table {
    pub fn handle_fold(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_fold(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.fold();
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_fold();
        }
        Some(ActionResult { seat_id, message: format!("{} folds", player_name) })
    }

    pub fn handle_call(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let call_amount = self.call_amount?;
        let added_to_pot = if call_amount > seat.stack + seat.bet { seat.stack } else { call_amount - seat.bet };
        if let Some(ref betting) = self.betting_round {
            if betting.validate_call(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.call_raise(call_amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_call();
        }
        self.add_to_pot(added_to_pot);
        Some(ActionResult { seat_id, message: format!("{} calls ${:.2}", player_name, added_to_pot) })
    }

    pub fn handle_check(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_check(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.check();
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_check();
        }
        Some(ActionResult { seat_id, message: format!("{} checks", player_name) })
    }

    pub fn handle_raise(&mut self, pk: &GamePkHex, amount: u64) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            let raise_amount = amount.saturating_sub(betting.current_bet());
            if betting.validate_raise(&seat, raise_amount).is_err() {
                return None;
            }
        }
        let added_to_pot = amount - seat.bet;
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.raise(amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_raise(amount, seat_id);
        }
        self.add_to_pot(added_to_pot);
        self.min_raise = {
            // min_raise stores the minimum total bet for the next raise.
            // Standard rule: next minimum raise = current bet + last raise increment.
            let raise_increment = amount.saturating_sub(self.call_amount.unwrap_or(0));
            amount + raise_increment
        };
        self.call_amount = Some(amount);
        // Reset has_acted for all other active players — they must respond to the raise.
        for seat in self.seats.values_mut() {
            if seat.id != seat_id && !seat.folded && !seat.sitting_out && seat.stack > 0 {
                seat.has_acted = false;
            }
        }
        Some(ActionResult { seat_id, message: format!("{} raises to ${:.2}", player_name, amount) })
    }

    /// D2 fix: handle all-in action. An all-in is a call or raise with all
    /// remaining chips. If the player's total (bet + stack) exceeds the
    /// current call amount, it acts as a raise; otherwise it's a call.
    pub fn handle_allin(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let stack = seat.stack;
        let current_bet_total = seat.bet + seat.stack; // total bet after going all-in
        let added_to_pot = stack;

        if stack == 0 {
            return None; // nothing to all-in
        }

        // Determine if this all-in is a raise or just a call
        let call_amount = self.call_amount.unwrap_or(0);
        let is_raise = current_bet_total > call_amount;

        // Move all chips into bet
        if let Some(seat) = self.seats.get_mut(&seat_id) {
            seat.bet += seat.stack;
            seat.stack = 0;
            seat.turn = false;
            seat.has_acted = true;
            seat.last_action = Some(actions::RAISE.to_string());
        }

        if is_raise {
            // All-in raise: update call_amount and min_raise
            if let Some(ref mut betting) = self.betting_round {
                betting.update_after_raise(current_bet_total, seat_id);
            }
            let raise_increment = current_bet_total.saturating_sub(call_amount);
            // min_raise only increases if the raise meets the minimum;
            // incomplete all-in raises don't increase min_raise.
            if raise_increment >= self.min_raise.saturating_sub(call_amount) {
                self.min_raise = current_bet_total + raise_increment;
            }
            self.call_amount = Some(current_bet_total);
            // Reset has_acted for other active players
            for seat in self.seats.values_mut() {
                if seat.id != seat_id && !seat.folded && !seat.sitting_out && seat.stack > 0 {
                    seat.has_acted = false;
                }
            }
        } else {
            // All-in call
            if let Some(ref mut betting) = self.betting_round {
                betting.update_after_call();
            }
        }

        self.add_to_pot(added_to_pot);
        Some(ActionResult { seat_id, message: format!("{} goes all-in for ${:.2}", player_name, added_to_pot) })
    }

    pub fn add_to_pot(&mut self, amount: u64) {
        // New bets always go to self.pot, never to existing side_pots (B4 fix).
        // side_pots are only populated by calculate_side_pots() at end of round.
        self.pot += amount;
    }

    pub fn is_betting_round_complete(&self) -> bool {
        let active: Vec<&Seat> = self.seats.values()
            .filter(|s| !s.folded && !s.sitting_out && s.stack > 0)
            .collect();
        if active.is_empty() {
            return true;
        }
        // Every active player must have acted at least once this round.
        // This prevents the BB's option from being skipped and ensures
        // that folds don't cause premature round completion.
        if active.iter().any(|s| !s.has_acted) {
            return false;
        }
        // All active players must have matched the current bet (or are all-in).
        if let Some(ref betting) = self.betting_round {
            let current_bet = betting.current_bet();
            for seat in &active {
                if seat.bet < current_bet {
                    return false;
                }
            }
        }
        true
    }

    pub fn players_all_in_this_turn(&self) -> Vec<&Seat> {
        self.seats.values()
            .filter(|s| !s.folded && s.bet > 0 && s.stack == 0)
            .collect()
    }

    pub fn check_betting_timeout(&mut self, timeout_secs: u64) -> Option<ActionResult> {
        let timeout_start = self.betting_timeout_start?;
        if timeout_start.elapsed().as_secs() < timeout_secs {
            return None;
        }
        let turn_seat_id = self.turn?;
        // Extract only the needed info to avoid cloning the entire Seat
        let (folded, sitting_out, stack, bet, pk_hex) = {
            let seat = self.seats.get(&turn_seat_id)?;
            (
                seat.folded,
                seat.sitting_out,
                seat.stack,
                seat.bet,
                seat.player.as_ref().map(|p| p.pk_hex.clone()),
            )
        };
        if folded || sitting_out || stack == 0 {
            // Turn is on a player who can't act — skip them and advance turn.
            // Return a special marker so the caller knows to re-advance.
            self.turn = self.next_unfolded_player(turn_seat_id, 1);
            self.betting_timeout_start = Some(std::time::Instant::now());
            for i in 1..=self.max_players {
                if let Some(seat) = self.seats.get_mut(&i) {
                    seat.turn = self.turn == Some(i);
                }
            }
            return None;
        }
        let needs_to_call = self.call_amount.map_or(false, |ca| ca > bet);
        let pk = pk_hex?;
        if needs_to_call {
            self.handle_fold(&pk)
        } else {
            self.handle_check(&pk)
        }
    }
}
