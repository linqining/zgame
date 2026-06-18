use super::*;

impl Table {
    pub fn end_hand(&mut self) {
        self.clear_seat_turns();
        self.hand_over = true;
        self.clear_seat_hands();
        self.transition_to(RoundState::HandComplete);
        self.hand_complete_at = Some(std::time::Instant::now());
        self.sit_out_felted_players();
    }

    pub fn sit_out_felted_players(&mut self) {
        for seat in self.seats.values_mut() {
            if seat.stack == 0 {
                seat.sitting_out = true;
            }
        }
    }

    pub fn end_without_showdown(&mut self) {
        let unfolded = self.unfolded_players();
        if let Some(winner) = unfolded.first() {
            // Total win includes main pot + all side pots (B3 fix)
            let total_win = self.pot + self.side_pots.iter().map(|sp| sp.amount).sum::<u64>();
            let winner_id = winner.id;
            let player_name = winner.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
            if let Some(seat) = self.seats.get_mut(&winner_id) {
                seat.win_hand(total_win);
            }
            self.win_messages.push(format!("{} wins ${:.2}", player_name, total_win));
        }
        self.end_hand();
    }

    pub fn reset_empty_table(&mut self) {
        self.button = None;
        self.turn = None;
        self.hand_over = true;
        self.went_to_showdown = false;
        self.mental_poker_game.reset();
        self.reset_board_and_pot();
        self.clear_win_messages();
        self.clear_seats();
        self.pk_to_seat.clear();
    }

    pub fn reset_board_and_pot(&mut self) {
        self.pot = 0;
        self.main_pot = 0;
        self.side_pots = vec![];
    }

    pub fn clear_seats(&mut self) {
        self.seats.clear();
    }

    pub fn clear_seat_hands(&mut self) {
        for seat in self.seats.values_mut() {
            seat.hand.clear();
        }
    }

    pub fn clear_seat_turns(&mut self) {
        for seat in self.seats.values_mut() {
            seat.turn = false;
        }
    }

    pub fn clear_win_messages(&mut self) {
        self.win_messages = vec![];
    }

    pub fn reset_bets_and_actions(&mut self) {
        for seat in self.seats.values_mut() {
            seat.bet = 0;
            seat.checked = false;
            seat.last_action = None;
            seat.has_acted = false;
        }
        self.call_amount = None;
        self.min_raise = self.min_bet * 2;
        if let Some(ref mut betting) = self.betting_round {
            betting.reset();
        }
    }

    pub fn reset_for_next_hand(&mut self) {
        self.transition_to(RoundState::Waiting);
        self.hand_complete_at = None;
        self.betting_timeout_start = None;
        self.clear_win_messages();
        self.shuffle_state.reset();
        self.reveal_token_state.reset();
        self.reconstruct_state.reset();
        self.mental_poker_game.reset();
    }
}
