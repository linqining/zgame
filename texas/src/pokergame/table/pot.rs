use super::*;
use crate::pokergame::hand_rank::{vin_card_to_eval_card, EvalCard, HandRank};
use crate::pokergame::evaluator::best_hand;

impl Table {
    pub fn calculate_side_pots(&mut self) {
        // Collect (seat_id, bet, folded) for ALL players with bets, including folded.
        // Folded players' chips are included in pot amounts (they contributed),
        // but only unfolded players are eligible to win.
        let mut player_bets: Vec<(u32, u64, bool)> = self.seats.values()
            .filter(|s| s.bet > 0)
            .map(|s| (s.id, s.bet, s.folded))
            .collect();

        if player_bets.is_empty() {
            return;
        }

        // Sort by bet ascending — the foundation of the layered pot algorithm.
        player_bets.sort_by_key(|(_, bet, _)| *bet);

        // Don't clear side_pots — preserve side pots from previous rounds.
        // New side pots from this round are appended.
        let mut prev_level: u64 = 0;
        let mut new_side_pots_total: u64 = 0;
        let mut is_first_layer = true;

        for i in 0..player_bets.len() {
            let current_bet = player_bets[i].1;
            if current_bet > prev_level {
                let increment = current_bet - prev_level;
                // All players at or above this bet level contributed to this layer.
                let contributors: Vec<u32> = player_bets[i..].iter().map(|(id, _, _)| *id).collect();
                let pot_amount = increment * contributors.len() as u64;
                // Only unfolded contributors are eligible to win this layer.
                let eligible: Vec<u32> = player_bets[i..].iter()
                    .filter(|(_, _, folded)| !*folded)
                    .map(|(id, _, _)| *id)
                    .collect();

                if is_first_layer {
                    // First layer = main pot. The amount is already in self.pot
                    // via add_to_pot() during betting — don't add again (B1 fix).
                    // G3 修复：同步更新 main_pot 字段，使其与实际主底池金额一致
                    self.main_pot = pot_amount;
                    is_first_layer = false;
                } else if !eligible.is_empty() {
                    // Side pot layer — move amount from self.pot to side_pots.
                    self.side_pots.push(SidePot { amount: pot_amount, players: eligible });
                    new_side_pots_total += pot_amount;
                }
                prev_level = current_bet;
            }
        }
        // Move new side pot amounts out of self.pot so that self.pot holds
        // only the main pot. Total pot = self.pot + sum(side_pots).
        self.pot = self.pot.saturating_sub(new_side_pots_total);
    }



    pub fn determine_side_pot_winners(&mut self) {
        if self.side_pots.is_empty() { return; }
        // Collect (amount, eligible_ids) pairs first to avoid cloning side_pots
        let pot_info: Vec<(u64, Vec<u32>)> = self.side_pots.iter()
            .map(|sp| {
                let eligible: Vec<u32> = sp.players.iter()
                    .filter(|id| self.seats.get(id).map_or(false, |s| !s.folded))
                    .copied()
                    .collect();
                (sp.amount, eligible)
            })
            .collect();
        for (amount, eligible_ids) in pot_info {
            if eligible_ids.is_empty() { continue; }
            self.determine_winner_by_ids(amount, &eligible_ids);
        }
    }

    pub fn determine_main_pot_winner(&mut self) {
        let unfolded_ids: Vec<u32> = self.seats.values()
            .filter(|s| !s.folded)
            .map(|s| s.id)
            .collect();
        self.determine_winner_by_ids(self.pot, &unfolded_ids);
        self.went_to_showdown = true;
        self.transition_to(RoundState::Showdown);
        self.showdown_at = Some(std::time::Instant::now());
    }

    pub fn finish_showdown(&mut self) {
        self.clear_seat_turns();
        self.hand_over = true;
        self.transition_to(RoundState::HandComplete);
        self.hand_complete_at = Some(std::time::Instant::now());
        self.sit_out_felted_players();
    }

    pub fn evaluate_player_hands(&self) -> Vec<(u32, HandRank)> {
        let mut results = Vec::new();
        let (player_revealed_map, comm_revealed_cards) = self.mental_poker_game.list_revealed_cards();
        if comm_revealed_cards.len() < 5 { return results; }
        tracing::info!("comm_revealed_cards: {:?}", comm_revealed_cards);
        for seat in self.seats.values() {
            let seat_player = match seat.player.as_ref() {
                Some(p) => p,
                None => continue,
            };
            let revealed_cards = match player_revealed_map.get(&seat_player.pk_hex.0){
                Some(rc) => rc,
                None => continue,
            };

            if !seat.folded && !seat.sitting_out && revealed_cards.len() >= 2 {
                let mut eval_cards: Vec<EvalCard> = Vec::new();
                for card in revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                for card in &comm_revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                tracing::info!("evaluate_player_hands eval_cards: {:?}", eval_cards);
                if eval_cards.len() >= 5 {
                    let (hand_rank, _) = best_hand(&eval_cards);
                    results.push((seat.id, hand_rank));
                }
            }
        }
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    pub fn determine_winner_by_ids(&mut self, amount: u64, eligible_ids: &[u32]) {
        if eligible_ids.is_empty() { return; }
        if eligible_ids.len() == 1 {
            let winner_id = eligible_ids[0];
            let win_amount = amount;
            if let Some(seat) = self.seats.get_mut(&winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount);
                if win_amount > 0 {
                    self.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount));
                }
            }
            self.update_history();
            return;
        }
        let hand_results = self.evaluate_player_hands();
        let eligible_results: Vec<(u32, HandRank)> = hand_results
            .into_iter()
            .filter(|(id, _)| eligible_ids.contains(id))
            .collect();
        if eligible_results.is_empty() {
            // F5 fix: No reveal cards available — split evenly among all eligible
            // instead of silently dropping the pot.
            let win_amount = amount / eligible_ids.len() as u64;
            let remainder = amount % eligible_ids.len() as u64;
            for (idx, winner_id) in eligible_ids.iter().enumerate() {
                let extra = if idx < remainder as usize { 1 } else { 0 };
                if let Some(seat) = self.seats.get_mut(winner_id) {
                    let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                    seat.win_hand(win_amount + extra);
                    if win_amount + extra > 0 {
                        self.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount + extra));
                    }
                }
            }
            self.update_history();
            return;
        }
        let best_rank = &eligible_results[0].1;
        let winners: Vec<u32> = eligible_results
            .iter()
            .filter(|(_, rank)| rank == best_rank)
            .map(|(id, _)| *id)
            .collect();
        let win_amount = amount / winners.len() as u64;
        let remainder = amount % winners.len() as u64;
        for (idx, winner_id) in winners.iter().enumerate() {
            let extra = if idx < remainder as usize { 1 } else { 0 };
            if let Some(seat) = self.seats.get_mut(winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount + extra);
                if win_amount + extra > 0 {
                    self.win_messages.push(format!("{} wins ${:.2} with {}", player_name, win_amount + extra, best_rank.name()));
                }
            }
        }
        self.update_history();
    }
}
