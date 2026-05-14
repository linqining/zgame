use crate::pokergame::seat::Seat;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct BettingRound {
    current_bet: u64,
    min_raise: u64,
    big_blind: u64,
    last_raiser_seat_id: Option<u32>,
    actions_taken: usize,
}

#[allow(dead_code)]
impl BettingRound {
    pub fn new(big_blind: u64) -> Self {
        Self {
            current_bet: 0,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat_id: None,
            actions_taken: 0,
        }
    }

    pub fn new_preflop(big_blind: u64) -> Self {
        Self {
            current_bet: big_blind,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat_id: None,
            actions_taken: 0,
        }
    }

    pub fn current_bet(&self) -> u64 {
        self.current_bet
    }

    pub fn min_raise(&self) -> u64 {
        self.min_raise
    }

    pub fn validate_fold(&self, _seat: &Seat) -> Result<(), String> {
        Ok(())
    }

    pub fn validate_check(&self, seat: &Seat) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call > 0 {
            return Err(format!("cannot check: must call {} or fold", chips_to_call));
        }
        Ok(())
    }

    pub fn validate_call(&self, seat: &Seat) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call == 0 {
            return Err("nothing to call - use check instead".to_string());
        }
        Ok(())
    }

    pub fn validate_raise(&self, seat: &Seat, raise_amount: u64) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call + raise_amount > seat.stack {
            return Err(format!(
                "not enough chips: need {}, have {}",
                chips_to_call + raise_amount,
                seat.stack
            ));
        }
        if raise_amount < self.min_raise {
            return Err(format!(
                "minimum raise is {}, got {}",
                self.min_raise, raise_amount
            ));
        }
        Ok(())
    }

    pub fn process_fold(&mut self) -> Result<(), String> {
        self.actions_taken += 1;
        Ok(())
    }

    pub fn process_check(&mut self) -> Result<(), String> {
        self.actions_taken += 1;
        Ok(())
    }

    pub fn process_call(&mut self, seat: &mut Seat) -> Result<u64, String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call == 0 {
            return Err("nothing to call - use check instead".to_string());
        }
        let actual = if chips_to_call > seat.stack { seat.stack } else { chips_to_call };
        seat.call_raise(self.current_bet);
        self.actions_taken += 1;
        Ok(actual)
    }

    pub fn process_raise(&mut self, seat: &mut Seat, total_bet: u64, seat_id: u32) -> Result<u64, String> {
        let raise_amount = total_bet.saturating_sub(self.current_bet);
        self.validate_raise(seat, raise_amount)?;
        seat.raise(total_bet);
        self.min_raise = raise_amount;
        self.current_bet = seat.bet;
        self.last_raiser_seat_id = Some(seat_id);
        self.actions_taken += 1;
        Ok(raise_amount)
    }

    pub fn is_complete(&self, seats: &[Option<&Seat>]) -> bool {
        let active_players: Vec<&&Seat> = seats
            .iter()
            .filter(|s| s.is_some())
            .map(|s| s.as_ref().unwrap())
            .filter(|s| !s.folded && !s.sitting_out && s.stack > 0)
            .collect();

        if active_players.is_empty() {
            return true;
        }
        if self.actions_taken < active_players.len() {
            return false;
        }
        active_players.iter().all(|s| s.bet == self.current_bet || s.stack == 0)
    }

    pub fn update_after_raise(&mut self, total_bet: u64, seat_id: u32) {
        let raise_amount = total_bet.saturating_sub(self.current_bet);
        if raise_amount >= self.min_raise {
            self.min_raise = raise_amount;
        }
        self.current_bet = total_bet;
        self.last_raiser_seat_id = Some(seat_id);
        self.actions_taken += 1;
    }

    pub fn update_after_call(&mut self) {
        self.actions_taken += 1;
    }

    pub fn update_after_check(&mut self) {
        self.actions_taken += 1;
    }

    pub fn update_after_fold(&mut self) {
        self.actions_taken += 1;
    }

    pub fn reset(&mut self) {
        self.current_bet = 0;
        self.min_raise = self.big_blind;
        self.last_raiser_seat_id = None;
        self.actions_taken = 0;
    }

    pub fn available_actions(&self, seat: &Seat) -> Vec<String> {
        if seat.folded || seat.sitting_out || seat.stack == 0 {
            return Vec::new();
        }
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        let mut actions = Vec::new();
        actions.push("fold".to_string());
        if chips_to_call == 0 {
            actions.push("check".to_string());
        } else {
            actions.push("call".to_string());
        }
        if seat.stack > chips_to_call {
            let max_raise = seat.stack - chips_to_call;
            if max_raise >= self.min_raise {
                actions.push("raise".to_string());
            }
        }
        actions
    }
}
