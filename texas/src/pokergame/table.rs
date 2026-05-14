use std::collections::HashMap;
use crate::pokergame::hand_rank::{vin_card_to_eval_card, EvalCard, HandRank};
use crate::pokergame::evaluator::best_hand;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pokergame::deck::{Card, Deck};
use crate::pokergame::player::Player;
use crate::pokergame::seat::Seat;
use crate::pokergame::side_pot::SidePot;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub seat_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: Vec<Player>,
    pub seats: HashMap<u32, Option<Seat>>,
    pub board: Vec<Card>,
    pub deck: Option<Deck>,
    pub button: Option<u32>,
    pub turn: Option<u32>,
    pub pot: u64,
    pub main_pot: u64,
    pub call_amount: Option<u64>,
    pub min_bet: u64,
    pub min_raise: u64,
    pub small_blind: Option<u32>,
    pub big_blind: Option<u32>,
    pub hand_over: bool,
    pub win_messages: Vec<String>,
    pub went_to_showdown: bool,
    pub side_pots: Vec<SidePot>,
    pub history: Vec<serde_json::Value>,
    #[serde(skip)]
    pub betting_round: Option<crate::pokergame::betting::BettingRound>,
}

impl Table {
    pub fn new(id: u32, name: String, limit: u64, max_players: u32) -> Self {
        let seats = Self::init_seats(max_players);
        Self {
            id,
            name,
            limit,
            max_players,
            players: vec![],
            seats,
            board: vec![],
            deck: None,
            button: None,
            turn: None,
            pot: 0,
            main_pot: 0,
            call_amount: None,
            min_bet: limit / 200,
            min_raise: limit / 100,
            small_blind: None,
            big_blind: None,
            hand_over: true,
            win_messages: vec![],
            went_to_showdown: false,
            side_pots: vec![],
            history: vec![],
            betting_round: None,
        }
    }

    pub fn init_seats(max_players: u32) -> HashMap<u32, Option<Seat>> {
        let mut seats = HashMap::new();
        for i in 1..=max_players {
            seats.insert(i, None);
        }
        seats
    }

    pub fn add_player(&mut self, player: Player) {
        if !self.players.iter().any(|p| p.socket_id == player.socket_id) {
            self.players.push(player);
        }
    }

    pub fn remove_player(&mut self, socket_id: &str) {
        self.players.retain(|p| p.socket_id != socket_id);
        self.stand_player(socket_id);
    }

    pub fn sit_player(&mut self, player: Player, seat_id: u32, amount: u64) {
        if seat_id < 1 || seat_id > self.max_players {
            return;
        }
        if self.seats.get(&seat_id).map_or(false, |s| s.is_some()) {
            return;
        }
        let seat = Seat::new(seat_id, Some(player), amount, amount);
        let first_player = self.seats.values().filter(|s| s.is_some()).count() == 0;
        self.seats.insert(seat_id, Some(seat));
        if first_player {
            self.button = Some(seat_id);
        }
    }

    pub fn rebuy_player(&mut self, seat_id: u32, amount: u64) {
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.stack += amount;
        }
    }

    pub fn stand_player(&mut self, socket_id: &str) {
        for (_id, seat_opt) in self.seats.iter_mut() {
            if let Some(seat) = seat_opt {
                if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                    *seat_opt = None;
                }
            }
        }
        let sat_count = self.seats.values().filter(|s| s.is_some()).count();
        if sat_count == 1 {
            self.end_without_showdown();
        }
        if sat_count == 0 {
            self.reset_empty_table();
        }
    }

    pub fn find_player_by_socket_id(&self, socket_id: &str) -> Option<&Seat> {
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                    return Some(seat);
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn find_player_by_socket_id_mut(&mut self, socket_id: &str) -> Option<&mut Seat> {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                    return Some(seat);
                }
            }
        }
        None
    }

    pub fn unfolded_players(&self) -> Vec<&Seat> {
        self.seats.values().filter_map(|s| s.as_ref()).filter(|s| !s.folded).collect()
    }

    pub fn active_players(&self) -> Vec<&Seat> {
        self.seats.values().filter_map(|s| s.as_ref()).filter(|s| !s.sitting_out).collect()
    }

    pub fn next_unfolded_player(&self, player: u32, places: u32) -> u32 {
        let mut count = 0u32;
        let mut current = player;
        while count < places {
            current = if current >= self.max_players { 1 } else { current + 1 };
            if let Some(Some(seat)) = self.seats.get(&current) {
                if !seat.folded {
                    count += 1;
                }
            }
        }
        current
    }

    pub fn next_active_player(&self, player: u32, places: u32) -> u32 {
        let mut count = 0u32;
        let mut current = player;
        while count < places {
            current = if current >= self.max_players { 1 } else { current + 1 };
            if let Some(Some(seat)) = self.seats.get(&current) {
                if !seat.sitting_out {
                    count += 1;
                }
            }
        }
        current
    }

    pub fn start_hand(&mut self) {
        self.deck = Some(Deck::new());
        self.went_to_showdown = false;
        self.reset_board_and_pot();
        self.clear_seat_hands();
        self.reset_bets_and_actions();
        self.unfold_players();
        self.history = vec![];
        if self.active_players().len() > 1 {
            self.button = Some(self.next_active_player(self.button.unwrap_or(1), 1));
            self.set_turn();
            self.deal_preflop();
            self.update_history();
            self.set_blinds();
            self.hand_over = false;
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new_preflop(self.min_bet * 2));
        }
        self.update_history();
    }

    pub fn unfold_players(&mut self) {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                seat.folded = seat.sitting_out;
            }
        }
    }

    pub fn set_turn(&mut self) {
        let active = self.active_players();
        self.turn = if active.len() <= 3 {
            self.button
        } else {
            Some(self.next_active_player(self.button.unwrap_or(1), 3))
        };
    }

    pub fn set_blinds(&mut self) {
        let is_heads_up = self.active_players().len() == 2;
        let button = self.button.unwrap_or(1);

        self.small_blind = Some(if is_heads_up {
            button
        } else {
            self.next_active_player(button, 1)
        });
        self.big_blind = Some(if is_heads_up {
            self.next_active_player(button, 1)
        } else {
            self.next_active_player(button, 2)
        });

        if let Some(sb) = self.small_blind {
            if let Some(Some(seat)) = self.seats.get_mut(&sb) {
                seat.place_blind(self.min_bet);
            }
        }
        if let Some(bb) = self.big_blind {
            if let Some(Some(seat)) = self.seats.get_mut(&bb) {
                seat.place_blind(self.min_bet * 2);
            }
        }

        self.pot += self.min_bet * 3;
        self.call_amount = Some(self.min_bet * 2);
        self.min_raise = self.min_bet * 4;
    }

    pub fn clear_seats(&mut self) {
        for seat_opt in self.seats.values_mut() {
            *seat_opt = None;
        }
    }

    pub fn clear_seat_hands(&mut self) {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                seat.hand = vec![];
            }
        }
    }

    pub fn clear_seat_turns(&mut self) {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                seat.turn = false;
            }
        }
    }

    pub fn clear_win_messages(&mut self) {
        self.win_messages = vec![];
    }

    pub fn end_hand(&mut self) {
        self.clear_seat_turns();
        self.hand_over = true;
        self.sit_out_felted_players();
    }

    pub fn sit_out_felted_players(&mut self) {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                if seat.stack <= 0 {
                    seat.sitting_out = true;
                }
            }
        }
    }

    pub fn end_without_showdown(&mut self) {
        let unfolded = self.unfolded_players();
        if let Some(winner) = unfolded.first() {
            let win_amount = self.pot;
            let winner_id = winner.id;
            let player_name = winner.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
            if let Some(Some(seat)) = self.seats.get_mut(&winner_id) {
                seat.win_hand(win_amount);
            }
            self.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount));
        }
        self.end_hand();
    }

    pub fn reset_empty_table(&mut self) {
        self.button = None;
        self.turn = None;
        self.hand_over = true;
        self.deck = None;
        self.went_to_showdown = false;
        self.reset_board_and_pot();
        self.clear_win_messages();
        self.clear_seats();
    }

    pub fn reset_board_and_pot(&mut self) {
        self.board = vec![];
        self.pot = 0;
        self.main_pot = 0;
        self.side_pots = vec![];
    }

    pub fn update_history(&mut self) {
        self.history.push(json!({
            "pot": self.pot,
            "mainPot": self.main_pot,
            "sidePots": self.side_pots,
            "board": self.board,
            "seats": self.clean_seats_for_history(),
            "button": self.button,
            "turn": self.turn,
            "winMessages": self.win_messages,
        }));
    }

    pub fn clean_seats_for_history(&self) -> serde_json::Value {
        let mut clean = serde_json::Map::new();
        for (id, seat_opt) in &self.seats {
            match seat_opt {
                Some(seat) => {
                    clean.insert(id.to_string(), json!({
                        "player": { "id": seat.player.as_ref().map(|p| p.id.clone()), "username": seat.player.as_ref().map(|p| p.name.clone()) },
                        "bet": seat.bet,
                        "stack": seat.stack,
                    }));
                }
                None => {
                    clean.insert(id.to_string(), serde_json::Value::Null);
                }
            }
        }
        serde_json::Value::Object(clean)
    }

    pub fn change_turn(&mut self, last_turn: u32) {
        self.update_history();
        if self.unfolded_players().len() == 1 {
            self.end_without_showdown();
            return;
        }
        if self.is_betting_round_complete() {
            self.calculate_side_pots();
            self.deal_next_street();
            self.turn = if self.hand_over {
                None
            } else {
                Some(self.next_unfolded_player(self.button.unwrap_or(1), 1))
            };
        } else {
            self.turn = Some(self.next_unfolded_player(last_turn, 1));
        }
        for i in 1..=self.max_players {
            if let Some(Some(seat)) = self.seats.get_mut(&i) {
                seat.turn = self.turn == Some(i);
            }
        }
    }

    pub fn is_betting_round_complete(&self) -> bool {
        let active: Vec<&Seat> = self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded && !s.sitting_out && s.stack > 0)
            .collect();
        if active.is_empty() {
            return true;
        }
        let all_in_count = self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded && s.stack == 0)
            .count();
        if all_in_count > 0 && active.len() == 1 {
            return true;
        }
        for seat in &active {
            if let Some(call_amount) = self.call_amount {
                if seat.bet < call_amount {
                    return false;
                }
            } else if !seat.checked {
                return false;
            }
        }
        true
    }

    pub fn players_all_in_this_turn(&self) -> Vec<&Seat> {
        self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded && s.bet > 0 && s.stack == 0)
            .collect()
    }

    pub fn calculate_side_pots(&mut self) {
        let all_in_players = self.players_all_in_this_turn();
        let unfolded = self.unfolded_players();
        if all_in_players.is_empty() {
            return;
        }
        let mut sorted: Vec<&Seat> = all_in_players.clone();
        sorted.sort_by(|a, b| a.bet.partial_cmp(&b.bet).unwrap());
        if sorted.len() > 1 && sorted.len() == unfolded.len() {
            sorted.pop();
        }
        let all_in_seat_ids: Vec<u32> = sorted.iter().map(|s| s.id).collect();
        for seat_id in &all_in_seat_ids {
            let all_in_bet = match self.seats.get(seat_id) {
                Some(Some(s)) => s.bet,
                _ => continue,
            };
            let mut side_pot = SidePot::new();
            if all_in_bet > 0 {
                for i in 1..=self.max_players {
                    if i == *seat_id { continue; }
                    if let Some(Some(seat)) = self.seats.get(&i) {
                        if !seat.folded {
                            if seat.bet > all_in_bet {
                                let amount_over = seat.bet - all_in_bet;
                                if !self.side_pots.is_empty() {
                                    let last_idx = self.side_pots.len() - 1;
                                    self.side_pots[last_idx].amount -= amount_over;
                                } else {
                                    self.pot -= amount_over;
                                }
                                side_pot.amount += amount_over;
                                side_pot.players.push(i);
                            }
                        }
                    }
                }
                if let Some(Some(seat)) = self.seats.get_mut(seat_id) {
                    seat.bet = 0;
                }
                self.side_pots.push(side_pot);
            }
        }
    }

    pub fn deal_next_street(&mut self) {
        let length = self.board.len();
        self.reset_bets_and_actions();
        self.main_pot = self.pot;
        match length {
            0 => self.deal_flop(),
            3 | 4 => self.deal_turn_or_river(),
            5 => {
                self.determine_side_pot_winners();
                self.determine_main_pot_winner();
            }
            _ => {}
        }
    }

    pub fn determine_side_pot_winners(&mut self) {
        if self.side_pots.is_empty() { return; }
        let side_pots_clone = self.side_pots.clone();
        for side_pot in &side_pots_clone {
            if side_pot.players.is_empty() { continue; }
            let eligible_ids: Vec<u32> = side_pot.players.iter()
                .filter(|id| self.seats.get(id).and_then(|s| s.as_ref()).map_or(false, |s| !s.folded))
                .cloned()
                .collect();
            self.determine_winner_by_ids(side_pot.amount, &eligible_ids);
        }
    }

    pub fn determine_main_pot_winner(&mut self) {
        let unfolded_ids: Vec<u32> = self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded)
            .map(|s| s.id)
            .collect();
        self.determine_winner_by_ids(self.pot, &unfolded_ids);
        self.went_to_showdown = true;
        self.end_hand();
    }

    pub fn evaluate_player_hands(&self) -> Vec<(u32, HandRank)> {
        let mut results = Vec::new();
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if !seat.folded && !seat.sitting_out && seat.hand.len() >= 2 {
                    let mut eval_cards: Vec<EvalCard> = Vec::new();
                    for card in &seat.hand {
                        if let Some(ec) = vin_card_to_eval_card(&card.suit, &card.rank) {
                            eval_cards.push(ec);
                        }
                    }
                    for card in &self.board {
                        if let Some(ec) = vin_card_to_eval_card(&card.suit, &card.rank) {
                            eval_cards.push(ec);
                        }
                    }
                    if eval_cards.len() >= 5 {
                        let (hand_rank, _) = best_hand(&eval_cards);
                        results.push((seat.id, hand_rank));
                    }
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
            if let Some(Some(seat)) = self.seats.get_mut(&winner_id) {
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
        if eligible_results.is_empty() { return; }
        let best_rank = &eligible_results[0].1;
        let winners: Vec<u32> = eligible_results
            .iter()
            .filter(|(_, rank)| rank == best_rank)
            .map(|(id, _)| *id)
            .collect();
        let win_amount = amount / winners.len() as u64;
        for winner_id in &winners {
            if let Some(Some(seat)) = self.seats.get_mut(winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount);
                if win_amount > 0 {
                    self.win_messages.push(format!("{} wins ${:.2} with {}", player_name, win_amount, best_rank.name()));
                }
            }
        }
        self.update_history();
    }

    #[allow(dead_code)]
    pub fn map_cards_for_poker_solver(&self, cards: &[Card]) -> Vec<String> {
        cards.iter().map(|card| {
            let suit = &card.suit[..1];
            let rank = if card.rank == "10" { "T" } else if card.rank.len() > 1 { &card.rank[..1] } else { &card.rank };
            format!("{}{}", rank, suit)
        }).collect()
    }

    pub fn reset_bets_and_actions(&mut self) {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                seat.bet = 0;
                seat.checked = false;
                seat.last_action = None;
            }
        }
        self.call_amount = None;
        self.min_raise = self.min_bet * 2;
        if let Some(ref mut betting) = self.betting_round {
            betting.reset();
        }
    }

    pub fn deal_preflop(&mut self) {
        let max = self.max_players;
        let button = self.button.unwrap_or(1);
        let order: Vec<u32> = (button..=max).chain(1..button).collect();
        if let Some(ref mut deck) = self.deck {
            for _ in 0..2 {
                for &seat_id in &order {
                    if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
                        if !seat.sitting_out {
                            if let Some(card) = deck.draw() {
                                seat.hand.push(card);
                            }
                            seat.turn = self.turn == Some(seat_id);
                        }
                    }
                }
            }
        }
    }

    pub fn deal_flop(&mut self) {
        if let Some(ref mut deck) = self.deck {
            for _ in 0..3 {
                if let Some(card) = deck.draw() {
                    self.board.push(card);
                }
            }
        }
    }

    pub fn deal_turn_or_river(&mut self) {
        if let Some(ref mut deck) = self.deck {
            if let Some(card) = deck.draw() {
                self.board.push(card);
            }
        }
    }

    pub fn handle_fold(&mut self, socket_id: &str) -> Option<ActionResult> {
        let seat = self.find_player_by_socket_id(socket_id)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_fold(&seat).is_err() {
                return None;
            }
        }
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.fold();
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_fold();
        }
        Some(ActionResult { seat_id, message: format!("{} folds", player_name) })
    }

    pub fn handle_call(&mut self, socket_id: &str) -> Option<ActionResult> {
        let seat = self.find_player_by_socket_id(socket_id)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let call_amount = self.call_amount?;
        let added_to_pot = if call_amount > seat.stack + seat.bet { seat.stack } else { call_amount - seat.bet };
        if let Some(ref betting) = self.betting_round {
            if betting.validate_call(&seat).is_err() {
                return None;
            }
        }
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.call_raise(call_amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_call();
        }
        if !self.side_pots.is_empty() {
            let last_idx = self.side_pots.len() - 1;
            self.side_pots[last_idx].amount += added_to_pot;
        } else {
            self.pot += added_to_pot;
        }
        Some(ActionResult { seat_id, message: format!("{} calls ${:.2}", player_name, added_to_pot) })
    }

    pub fn handle_check(&mut self, socket_id: &str) -> Option<ActionResult> {
        let seat = self.find_player_by_socket_id(socket_id)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_check(&seat).is_err() {
                return None;
            }
        }
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.check();
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_check();
        }
        Some(ActionResult { seat_id, message: format!("{} checks", player_name) })
    }

    pub fn handle_raise(&mut self, socket_id: &str, amount: u64) -> Option<ActionResult> {
        let seat = self.find_player_by_socket_id(socket_id)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            let raise_amount = amount.saturating_sub(betting.current_bet());
            if betting.validate_raise(&seat, raise_amount).is_err() {
                return None;
            }
        }
        let added_to_pot = amount - seat.bet;
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.raise(amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_raise(amount, seat_id);
        }
        if !self.side_pots.is_empty() {
            let last_idx = self.side_pots.len() - 1;
            self.side_pots[last_idx].amount += added_to_pot;
        } else {
            self.pot += added_to_pot;
        }
        self.min_raise = if let Some(ca) = self.call_amount {
            ca + (amount - ca) * 2
        } else {
            amount * 2
        };
        self.call_amount = Some(amount);
        Some(ActionResult { seat_id, message: format!("{} raises to ${:.2}", player_name, amount) })
    }

    pub fn mark_player_disconnected(&mut self, socket_id: &str) -> Option<ActionResult> {
        let seat = self.find_player_by_socket_id(socket_id)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let is_turn = seat.turn;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
            seat.disconnected = true;
            seat.disconnected_at = Some(now);
            seat.sitting_out = true;
        }
        if is_turn {
            if let Some(ref betting) = self.betting_round {
                let seat_ref = self.seats.get(&seat_id).and_then(|s| s.as_ref());
                if let Some(seat_ref) = seat_ref {
                    if betting.validate_fold(seat_ref).is_ok() {
                        if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
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

    pub fn reconnect_player(&mut self, old_socket_id: &str, new_socket_id: &str) -> bool {
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                if seat.player.as_ref().map_or(false, |p| p.socket_id == old_socket_id) && seat.disconnected {
                    if let Some(player) = seat.player.as_mut() {
                        player.socket_id = new_socket_id.to_string();
                    }
                    seat.disconnected = false;
                    seat.disconnected_at = None;
                    seat.sitting_out = false;
                    return true;
                }
            }
        }
        false
    }

    pub fn is_player_disconnected(&self, socket_id: &str) -> bool {
        self.seats.values()
            .filter_map(|s| s.as_ref())
            .any(|s| s.player.as_ref().map_or(false, |p| p.socket_id == socket_id) && s.disconnected)
    }

    #[allow(dead_code)]
    pub fn find_disconnected_socket_by_user_id(&self, user_id: &str) -> Option<String> {
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if seat.disconnected && seat.player.as_ref().map_or(false, |p| p.id == user_id) {
                    return seat.player.as_ref().map(|p| p.socket_id.clone());
                }
            }
        }
        None
    }
}
