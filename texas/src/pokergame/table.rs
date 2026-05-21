use std::collections::HashMap;
use crate::pokergame::hand_rank::{vin_card_to_eval_card, EvalCard, HandRank};
use crate::pokergame::evaluator::best_hand;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ExpelPhase,ShuffleProofJson,
     ExpelPublicState, MaskAndShuffleRoundJson,
     PkProofJson, PlayerRevealAssignment, RevealPhase, RevealTokenPublicState, ShufflePublicState, ShuffleState, RevealTokenState, ExpelState};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pokergame::deck::{Card, Deck, EncryptedDeck};
use crate::pokergame::player::{Player, PlayerWithProof};
use crate::pokergame::seat::{ClientSeat,Seat};
use crate::pokergame::side_pot::SidePot;
use poker_protocol::z_poker::{MentalPokerGame, GameConfig, PKOwnershipProof};
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext};
use sui_sdk::sui_crypto::SuiVerifier;
use poker_protocol::z_poker::convert::ecpoint_to_hex;



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub seat_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinResult {
    JoinedAndShuffled,
    JoinedWaiting,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoundState {
    Waiting,
    Shuffling,
    ShuffleComplete,
    PreFlopReveal,
    PreFlop,
    FlopReveal,
    Flop,
    TurnReveal,
    Turn,
    RiverReveal,
    River,
    ShowdownReveal,
    Showdown,
    HandComplete,
}

#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub socket_id: String,
    pub action: String,
    pub amount: Option<u64>,
}

#[derive(Debug, Serialize,Clone,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTable {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: Vec<Player>,
    pub seats: HashMap<u32, Option<ClientSeat>>,
    pub board: Vec<Card>,
    pub deck: Option<EncryptedDeck>,
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
    pub round_state: RoundState,
    pub shuffle_state: Option<ShufflePublicState>,
    pub reveal_token_state: Option<RevealTokenPublicState>,
    pub expel_state: Option<ExpelPublicState>,
}



#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: Vec<Player>,
    pub seats: HashMap<u32, Option<Seat>>,
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
    pub round_state: RoundState,
    #[serde(skip)]
    pub shuffle_state: ShuffleState,
    #[serde(skip)]
    pub reveal_token_state: RevealTokenState,
    #[serde(skip)]
    pub expel_state: ExpelState,
    #[serde(skip)]
    pub betting_timeout_start: Option<std::time::Instant>,
    #[serde(skip)]
    pub hand_complete_at: Option<std::time::Instant>,
    #[serde(skip)]
    pub ready_at: Option<std::time::Instant>,
    #[serde(skip)]
    pub showdown_at: Option<std::time::Instant>,
    #[serde(skip)]
    pub betting_round: Option<crate::pokergame::betting::BettingRound>,
    #[serde(skip)]
    pub mental_poker_game: MentalPokerGame,
    #[serde(skip)]
    pub waiting_players: HashMap<String, PlayerWithProof>,
}

impl Table {
    pub fn to_client(&self) -> ClientTable {
        let mut client_seats = HashMap::new();
        for (seat_id, seat) in self.seats.iter() {
            if let Some(seat) = seat {
                let client_seat = seat.to_client();
                // todo get card decrypted
                client_seats.insert(*seat_id, Some(client_seat.clone()));
            }
        }
        let encrypted_deck = EncryptedDeck{
            cards: self.mental_poker_game.deck_encrypted.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
        };
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        ClientTable {
            id: self.id,
            name: self.name.clone(),
            limit: self.limit,
            max_players: self.max_players,
            players: self.players.clone(),
            seats: client_seats,
            board: board,
            deck: Some(encrypted_deck.clone()),
            button: self.button,
            turn: self.turn,
            pot: self.pot,
            main_pot: self.main_pot,
            call_amount: self.call_amount,
            min_bet: self.min_bet,
            min_raise: self.min_raise,
            small_blind: self.small_blind,
            big_blind: self.big_blind,
            hand_over: self.hand_over,
            win_messages: self.win_messages.clone(),
            went_to_showdown: self.went_to_showdown,
            side_pots: self.side_pots.clone(),
            history: self.history.clone(),
            round_state: self.round_state,
            shuffle_state: self.get_shuffle_public_state(),
            reveal_token_state: self.get_reveal_token_public_state(),
            expel_state: self.get_expel_public_state(),
        }
    }

    pub fn new(id: u32, name: String, limit: u64, max_players: u32) -> Self {
        let seats = Self::init_seats(max_players);
        Self {
            id,
            name,
            limit,
            max_players,
            players: vec![],
            seats,
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
            round_state: RoundState::Waiting,
            shuffle_state: ShuffleState::new(),
            reveal_token_state: RevealTokenState::new(2, 5),
            expel_state: ExpelState::new(),
            betting_timeout_start: None,
            hand_complete_at: None,
            ready_at: None,
            showdown_at: None,
            betting_round: None,
            mental_poker_game: MentalPokerGame::new(GameConfig {
                num_players: max_players as usize,
                cards_per_player: 2,
                community_cards: 5,
            }),
            waiting_players: HashMap::new(),
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

    pub fn is_playing(&self) -> bool {
        !matches!(self.round_state, RoundState::Waiting | RoundState::HandComplete)
    }

    pub fn remove_player(&mut self, socket_id: &str) {
        let pk = if let Some(player) = self.players.iter().find(|p| p.socket_id == socket_id){
            player.pk_hex.clone()
        } else {
            return;
        };
        self.players.retain(|p| p.socket_id != socket_id);
        tracing::info!("remove_player stand_player: {}", socket_id);
        self.stand_player(socket_id);
        self.mental_poker_game.leave_player(&pk);
    }

    pub fn remove_player_by_pk(&mut self, pk: &str) {
        let socket_id = if let Some(player) = self.players.iter().find(|p| p.pk_hex == pk){
           player.socket_id.clone()
        } else {
            return;
        };
        self.players.retain(|p| p.pk_hex != pk);
        tracing::info!("remove_player_by_pk stand_player: {}", pk);
        self.stand_player(&socket_id);
        self.mental_poker_game.leave_player(pk);
    }



    pub fn find_random_empty_seat(&self) -> Option<u32> {
        let empty_seats: Vec<u32> = (1..=self.max_players)
            .filter(|&seat_id| self.seats.get(&seat_id).map_or(true, |s| s.is_none()))
            .collect();
        
        if empty_seats.is_empty() {
            None
        } else {
            use rand::seq::SliceRandom;
            empty_seats.choose(&mut rand::thread_rng()).copied()
        }
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

    pub fn sit_player_with_waiting(&mut self, player: Player, seat_id: u32, amount: u64) {
        if seat_id < 1 || seat_id > self.max_players {
            return;
        }
        if self.seats.get(&seat_id).map_or(false, |s| s.is_some()) {
            return;
        }
        let mut seat = Seat::new(seat_id, Some(player), amount, amount);
        seat.is_waiting = true;
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
        self.seats.values().filter_map(|s| s.as_ref()).filter(|s| !s.sitting_out && !s.is_waiting).collect()
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
        self.went_to_showdown = false;
        self.reset_board_and_pot();
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
                seat.hand.clear();
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
        self.clear_seat_hands();
        self.round_state = RoundState::HandComplete;
        self.hand_complete_at = Some(std::time::Instant::now());
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
        self.round_state = RoundState::HandComplete;
        self.hand_complete_at = Some(std::time::Instant::now());
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
    }

    pub fn reset_board_and_pot(&mut self) {
        self.pot = 0;
        self.main_pot = 0;
        self.side_pots = vec![];
    }

    pub fn update_history(&mut self) {
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        self.history.push(json!({
            "pot": self.pot,
            "mainPot": self.main_pot,
            "sidePots": self.side_pots,
            "board":board,
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

    pub fn is_betting_round_complete(&self) -> bool {
        let active: Vec<&Seat> = self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded && !s.sitting_out && s.stack > 0)
            .collect();
        if active.is_empty() {
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
        self.round_state = RoundState::Showdown;
        self.showdown_at = Some(std::time::Instant::now());
    }

    pub fn finish_showdown(&mut self) {
        self.clear_seat_turns();
        self.hand_over = true;
        self.round_state = RoundState::HandComplete;
        self.hand_complete_at = Some(std::time::Instant::now());
        self.sit_out_felted_players();
    }

    pub fn evaluate_player_hands(&self) -> Vec<(u32, HandRank)> {
        let mut results = Vec::new();
        let (player_revealed_map, comm_revealed_cards) = self.mental_poker_game.list_revealed_cards();
        if comm_revealed_cards.len() < 5 { return results; }
        tracing::info!("comm_revealed_cards: {:?}", comm_revealed_cards);
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if seat.player.is_none() { continue; }
                let seat_player = seat.player.as_ref().unwrap();
                let revealed_cards = match player_revealed_map.get(&seat_player.pk_hex){
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

        for _ in 0..2 {
            for &seat_id in &order {
                if let Some(Some(seat)) = self.seats.get_mut(&seat_id) {
                    if let Some(player) = &seat.player{
                        if !seat.sitting_out {
                            tracing::info!("player {} is not sitting out,deal to {}", player.name, seat_id);
                            self.mental_poker_game.deal_to_player(&player.pk_hex.clone(), 1).unwrap();
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

    // 相当于原来的deal_next_street
    pub fn advance_to_next_phase(&mut self) {
        self.calculate_side_pots();
        self.reset_bets_and_actions();
        match self.round_state {
            RoundState::PreFlop => {
                // deal three community card 
                self.deal_flop();
                // start reveal community card
                self.round_state = RoundState::FlopReveal;
            }
            RoundState::Flop => {
                self.deal_turn_or_river();
                self.round_state = RoundState::TurnReveal;
            }
            RoundState::Turn => {
                self.deal_turn_or_river();
                self.round_state = RoundState::RiverReveal;
            }
            _ => {}
        }
        self.update_history();
    }

    pub fn check_betting_timeout(&mut self, timeout_secs: u64) -> Option<ActionResult> {
        let timeout_start = self.betting_timeout_start?;
        if timeout_start.elapsed().as_secs() < timeout_secs {
            return None;
        }
        let turn_seat_id = self.turn?;
        let seat = match self.seats.get(&turn_seat_id) {
            Some(Some(s)) => s.clone(),
            _ => return None,
        };
        if seat.folded || seat.stack <= 0 {
            self.betting_timeout_start = Some(std::time::Instant::now());
            return None;
        }
        let needs_to_call = self.call_amount.map_or(false, |ca| ca > seat.bet);
        if needs_to_call {
            self.handle_fold(&seat.player.as_ref().map(|p| p.socket_id.clone()).unwrap_or_default())
        } else {
            self.handle_check(&seat.player.as_ref().map(|p| p.socket_id.clone()).unwrap_or_default())
        }
    }

    pub fn reset_for_next_hand(&mut self) {
        self.round_state = RoundState::Waiting;
        self.hand_complete_at = None;
        self.betting_timeout_start = None;
        self.clear_win_messages();
        self.shuffle_state.reset();
        self.reveal_token_state.reset();
        self.expel_state.reset();
        self.mental_poker_game.reset();
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
                if seat.player.as_ref().map_or(false, |p| p.socket_id == old_socket_id) {
                    if let Some(player) = seat.player.as_mut() {
                        player.socket_id = new_socket_id.to_string();
                        tracing::info!("reconnect_player: {}", player.name.clone());
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

    pub fn find_disconnected_socket_by_user_id(&self, user_id: &str) -> Option<String> {
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                tracing::info!("find_disconnected_socket_by_user_id: {:?}", seat);
                if  seat.player.as_ref().map_or(false, |p| p.id == user_id) {
                    return seat.player.as_ref().map(|p| p.socket_id.clone());
                }
            }
        }
        None
    }

    // ==================== Shuffle State Methods ====================

    pub fn is_all_players_shuffled(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn is_pending_shuffle_palyer_empty(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn complete_shuffle_palyer_count(&self) -> usize {
        self.shuffle_state.completed_players.len()
    }

    pub fn start_shuffle(&mut self) -> Result<(), String> {
        let active_count = self.active_players().len();
        if active_count < 2 {
            return Err("Need at least 2 players to start".to_string());
        }
        if self.round_state == RoundState::Shuffling {
            return Ok(());
        }
        self.reset_shuffle();
        self.round_state = RoundState::Shuffling;
        self.shuffle_state.is_active = true;

        let already_completed: std::collections::HashSet<String> =
            self.shuffle_state.completed_players.iter().cloned().collect();
        
        let active_pks = self.active_players().iter().filter(|p| p.player.is_some()).map(|p| p.player.as_ref().unwrap().pk_hex.clone()).collect::<Vec<_>>();

        
        let remove_pks = self.mental_poker_game.players.iter().filter(|(pk,player_state)| !active_pks.contains(&player_state.pk_hex)).map(|p| p.1.pk_hex.clone()).collect::<Vec<_>>();
        for pk in remove_pks{
            // 移除不参与洗牌的玩家
            // todo 每局初始化一个更简单
            self.mental_poker_game.leave_player(&pk);
        }

        // 注册 waiting 玩家到 mental_poker_game（仅当玩家仍在座位上时）
        let waiting_players_to_register: Vec<PlayerWithProof> = self.waiting_players.values().cloned().collect();
        let active_pk_hexs: std::collections::HashSet<String> = self.seats.values()
            .filter_map(|seat_opt| seat_opt.as_ref())
            .filter_map(|seat| seat.player.as_ref())
            .map(|player| player.pk_hex.clone())
            .collect();
        
        for waiting_info in waiting_players_to_register {
            if active_pk_hexs.contains(&waiting_info.player.pk_hex) {
                self.mental_poker_game.register_player(waiting_info.player.pk_hex.clone(), waiting_info.pk, waiting_info.pk_proof);
                tracing::info!("[SHUFFLE] Waiting player {} registered to mental_poker_game", waiting_info.player.pk_hex);
            } else {
                tracing::info!("[SHUFFLE] Waiting player {} left the table, skipping registration", waiting_info.player.pk_hex);
            }
        }
        self.waiting_players.clear();

        // 清除 is_waiting 标记
        for seat_opt in self.seats.values_mut() {
            if let Some(seat) = seat_opt {
                if seat.is_waiting {
                    seat.is_waiting = false;
                    if let Some(player) = &seat.player {
                        tracing::info!("[SHUFFLE] Player {} is_waiting cleared, registered to shuffle", player.pk_hex);
                    }
                }
            }
        }

        // todo sitting_out 回来的玩家再加入洗牌(假如在洗牌阶段)
        self.shuffle_state.pending_players = self.mental_poker_game.players.keys()
            .cloned()
            .filter(|pk| !already_completed.contains(pk))
            .collect();

        if let Some(first_pk) = self.shuffle_state.pending_players.first() {
            self.set_current_shuffler(first_pk.clone());
        } else {
            if self.complete_shuffle_palyer_count()>=2{
                self.shuffle_state.is_active = false;
                self.round_state = RoundState::ShuffleComplete;
                tracing::info!("[SHUFFLE] All players already completed shuffle, skipping");
            }
        }
        self.shuffle_state.timeout_seconds = 10;
        Ok(())
    }

    pub fn reset_shuffle(&mut self) {
        tracing::info!("[SHUFFLE] === Shuffle reset ===");
        tracing::info!("[SHUFFLE] Total active players: {}", self.active_players().len());
        self.shuffle_state.reset();
        tracing::info!("[SHUFFLE] Shuffle order: {:?}, current: {:?}",
            self.shuffle_state.pending_players, self.shuffle_state.current_player_pk);
    }

    pub fn set_current_shuffler(&mut self, player_pk: String) {
        self.shuffle_state.current_player_pk = Some(player_pk);
        self.shuffle_state.timeout_start = Some(std::time::Instant::now());
        tracing::info!("[SHUFFLE] Now waiting for player {} to shuffle (timeout: {}s)",
            self.shuffle_state.current_player_pk.as_ref().unwrap(), self.shuffle_state.timeout_seconds);
    }

    pub fn check_shuffle_timeout(&mut self) -> Option<String> {
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
    ) -> Result<JoinResult, String> {
        let pk_hex = player.pk_hex.clone();
        let player_for_seat = player.clone();

        if self.seats.values().any(|seat_opt| {
            seat_opt.as_ref().map_or(false, |seat| {
                seat.player.as_ref().map_or(false, |p| p.pk_hex == pk_hex)
            })
        }) {
            return Err("Player already in game".to_string());
        }

        let actual_seat_id = if seat_id == 0 {
            self.find_random_empty_seat().ok_or("No empty seat available")?
        } else {
            if seat_id < 1 || seat_id > self.max_players {
                return Err("Invalid seat_id".to_string());
            }
            if self.seats.get(&seat_id).map_or(false, |s| s.is_some()) {
                return Err("Seat already occupied".to_string());
            }
            seat_id
        };

        let can_join_now = matches!(self.round_state, RoundState::Waiting);

        if can_join_now {
            let pk_proof = pk_proof_json.to_pk_proof()?;
            if !pk_proof.verify(&player_pk) {
                return Err("Invalid PK proof".to_string());
            }

            let round = round_json.to_mask_and_shuffle_round()?;
            let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
            let share_pk = current_agg_pk + &player_pk;
            if !round.proof.verify(&round.mask_cards, &round.output_cards, &share_pk) {
                return Err("Invalid shuffle proof".to_string());
            }

            self.mental_poker_game.register_player(pk_hex.clone(), player_pk, pk_proof);
            self.mental_poker_game.deck_encrypted = round.output_cards;

            self.add_player(player);
            self.sit_player(player_for_seat, actual_seat_id, amount);

            if self.shuffle_state.is_active {
                self.shuffle_state.completed_players.push(pk_hex.clone());
                self.shuffle_state.pending_players.retain(|p| *p != pk_hex);
            }
            tracing::info!("[SHUFFLE] Player {} joined and shuffled, sat at seat {}", pk_hex, actual_seat_id);
            Ok(JoinResult::JoinedAndShuffled)
        } else {
            let pk_proof = pk_proof_json.to_pk_proof()?;
            if !pk_proof.verify(&player_pk) {
                return Err("Invalid PK proof".to_string());
            }
            
            self.waiting_players.insert(pk_hex.clone(), PlayerWithProof {
                player: player.clone(),
                pk: player_pk,
                pk_proof,
            });
            
            self.add_player(player);
            self.sit_player_with_waiting(player_for_seat, actual_seat_id, amount);
            tracing::info!("[SHUFFLE] Player {} joined as waiting, sat at seat {}, will join next hand roundState{:?}", pk_hex, actual_seat_id,self.round_state);
            Ok(JoinResult::JoinedWaiting)
        }
    }

    pub fn submit_verified_shuffle(
        &mut self,
        player_pk_hex: &str,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: ShuffleProofJson,
    ) -> Result<(), String> {
        if !self.shuffle_state.is_active {
            return Err("Shuffle not active".to_string());
        }
        if self.shuffle_state.current_player_pk != Some(player_pk_hex.to_string()) {
            return Err("Not current player".to_string());
        }

        let _ = self.mental_poker_game.players.get(player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        let output_cards = output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let proof = shuffle_proof.to_proof()?;
        let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let input_cards = self.mental_poker_game.deck_encrypted.clone();
        if !proof.verify(&input_cards,&output_cards, &current_agg_pk) {
            return Err("Invalid shuffle proof".to_string());
        }
        self.mental_poker_game.deck_encrypted = output_cards;
        self.shuffle_state.completed_players.push(player_pk_hex.to_string());
        self.shuffle_state.pending_players.retain(|p| *p != player_pk_hex);
        Ok(())
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

    pub fn get_expel_public_state(&self) -> Option<ExpelPublicState> {
        if self.expel_state.is_active {
            Some(ExpelPublicState {
                is_active: true,
                phase: self.expel_state.phase.to_string(),
                voted_players: self.expel_state.completed_players.clone(),
                expel_records_count: self.expel_state.expel_records_count,
            })
        } else {
            None
        }
    }

    pub fn complete_or_continue_next_shuffler(&mut self) {
        if self.shuffle_state.pending_players.is_empty() && self.complete_shuffle_palyer_count() >= 2 {
            self.round_state = RoundState::ShuffleComplete;
        } else if let Some(next_pk) = self.shuffle_state.pending_players.first() {
            let next_pk_clone = next_pk.clone();
            self.set_current_shuffler(next_pk_clone);
        }
    }

    // ==================== Reveal Token State Methods ====================

    pub fn start_preflop_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active{
            return;
        }
        let player_pks = self.mental_poker_game.players.keys().cloned().collect::<Vec<String>>();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            let mut hand_cards = Vec::new();
            for (other_pk, state) in &self.mental_poker_game.players {
                if pk == other_pk { continue; }
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

        let player_pks = self.mental_poker_game.players.keys().cloned().collect::<Vec<String>>();

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
            total_cards_per_player: 2,
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

    pub fn start_hand_card_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        let player_pks: Vec<String> = self.mental_poker_game.players.keys().cloned().collect();
        

        let mut player_assignments = HashMap::new();
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if let Some(player) = &seat.player {
                    let mut hand_cards = vec![];
                    for men_player in self.mental_poker_game.players.values() {
                        if men_player.pk_hex == player.pk_hex{
                            continue;
                        }
                        hand_cards.extend(men_player.hand_encrypted.iter().map(|f| f.encrypted_card.clone()));
                    }
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

    pub fn start_showdown_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        let player_pks: Vec<String> = self.seats.values()
            .filter_map(|s| s.as_ref())
            .filter(|s| !s.folded )
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();
        let mut player_assignments = HashMap::new();
        for seat_opt in self.seats.values() {
            if let Some(seat) = seat_opt {
                if seat.folded { continue; }
                if let Some(player) = &seat.player {
                    if !self.mental_poker_game.players.contains_key(player.pk_hex.as_str()) {
                        continue;
                    }
                    let men_player = self.mental_poker_game.players.get(player.pk_hex.as_str()).unwrap();
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

    pub fn mark_player_reveal_complete(&mut self, player_pk: &str) -> bool {
        if !self.reveal_token_state.is_active { return false; }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) { return false; }

        self.reveal_token_state.completed_players.push(player_pk.to_string());
        self.reveal_token_state.pending_players.retain(|p| p.as_str() != player_pk);

        tracing::info!("[REVEAL-TOKEN] Player {} completed {} phase, remaining: {}",
            player_pk, self.reveal_token_state.phase,
            self.reveal_token_state.pending_players.len());

        if self.reveal_token_state.pending_players.is_empty() {
            self.reveal_token_state.reset();
            match self.round_state {
                RoundState::PreFlopReveal => {
                    self.round_state = RoundState::PreFlop;
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::FlopReveal => {
                    self.round_state = RoundState::Flop;
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::TurnReveal => {
                    self.round_state = RoundState::Turn;
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::RiverReveal => {
                    self.round_state = RoundState::River;
                    self.betting_timeout_start = Some(std::time::Instant::now());
                }
                RoundState::ShowdownReveal => {
                    self.determine_side_pot_winners();
                    self.determine_main_pot_winner();
                    // self.round_state = RoundState::Showdown;
                    // self.showdown_at = Some(std::time::Instant::now());
                }
                _ => {
                    tracing::error!("[mark_player_reveal_complete] Invalid round state");
                }
            }
            tracing::info!("[REVEAL-TOKEN] All reveal phases complete, switch round state to PreFlop");
            return true;
        }
        false
    }

    pub fn check_reveal_timeout(&mut self) -> Option<Vec<String>> {
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
            tracing::info!("[REVEAL-TOKEN] All reveal phases complete, clear reveal state");
            return Some(time_out_pks);
        }
        None
    }

    pub fn reset_reveal_state(&mut self) {
        self.reveal_token_state.reset();
        tracing::info!("[REVEAL-TOKEN] Reveal state reset");
    }

    pub fn submit_player_reveal_tokens(
        &mut self,
        player_pk: &str,
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

    // ==================== Expel State Methods ====================

    // 用户发起
    pub fn start_expel(&mut self) -> Result<(), String> {
        if self.expel_state.is_active {
            return Err("Expel already in progress".to_string());
        }
        self.expel_state.is_active = true;
        self.expel_state.phase = ExpelPhase::Voting;
        self.expel_state.timeout_start = Some(std::time::Instant::now());
        
        self.expel_state.pending_players = self.mental_poker_game.players.keys().cloned().collect();      

        self.expel_state.expel_deck = poker_protocol::z_poker::protocol::INITIAL_ENCRYPTED_DECK.iter().map(|c| ElGamalCiphertextJson::from_ciphertext(c)).collect::<Vec<_>>();
        
        tracing::info!("[EXPEL] Expel initiated for player");
        Ok(())
    }

    fn get_seat_player_pks(&self) -> Vec<String> {
        self.seats.values().enumerate().filter(|(i,s)| s.is_some() && !s.as_ref().unwrap().is_waiting && s.as_ref().unwrap().player.is_some()).map(|(i,s)| s.as_ref().unwrap().player.as_ref().unwrap().pk_hex.clone()).collect::<Vec<_>>()
    }

    pub fn vote_expel(&mut self, voter_pk: &str, vote: bool) -> Result<ExpelPhase, String> {
        if !self.expel_state.is_active {
            return Err("No expel in progress".to_string());
        }
        if self.expel_state.completed_players.contains(&voter_pk.to_string()) {
            return Err("Player already voted".to_string());
        }

        if vote {
            self.expel_state.completed_players.push(voter_pk.to_string());
            tracing::info!("[EXPEL] Player {} voted to expel, votes: {}",
                voter_pk, self.expel_state.completed_players.len());

            if self.expel_state.completed_players.len() >= self.expel_state.pending_players.len() {
                self.expel_state.phase = ExpelPhase::Completed;
                tracing::info!("[EXPEL] Vote passed, expelling player {}",
                    self.expel_state.pending_players.join(","));
                return Ok(ExpelPhase::Completed);
            }
        } else {
            self.expel_state.phase = ExpelPhase::Initiated;
            self.expel_state.reset();
            tracing::info!("[EXPEL] Vote rejected by {}", voter_pk);
            return Ok(ExpelPhase::Initiated);
        }

        Ok(ExpelPhase::Voting)
    }

    pub fn force_expel(&mut self, target_pk: &str) -> Result<(), String> {
        self.expel_state.phase = ExpelPhase::Forced;
        self.expel_state.expel_records_count += 1;
        self.stand_player(target_pk);
        self.expel_state.reset();
        tracing::info!("[EXPEL] Player {} forcefully expelled", target_pk);
        Ok(())
    }

    pub fn check_expel_timeout(&mut self) -> Option<String> {
        if !self.expel_state.is_active {
            return None;
        }
        let timeout_start = match self.expel_state.timeout_start {
            Some(t) => t,
            None => return None,
        };
        
        if timeout_start.elapsed().as_secs() >= self.expel_state.timeout_seconds {
            let mut not_voted = Vec::new();
            for player_pk in self.expel_state.pending_players.iter() {
                if !self.expel_state.completed_players.contains(&player_pk.clone()) {
                    not_voted.push(player_pk.clone());
                }
            }
            tracing::warn!("[EXPEL] Expel vote timed out for player {:?}", not_voted.join(","));
            for player_pk in not_voted {
                self.remove_player_by_pk(&player_pk);
            }
            //todo 通知玩家被踢出
            self.expel_state.reset();
            return None;
        }
        None
    }

    pub fn execute_expel_if_completed(&mut self) -> bool {
        if self.expel_state.phase == ExpelPhase::Completed {
            self.expel_state.reset();
        }
        false
    }
}
