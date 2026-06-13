use std::collections::HashMap;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ReconstructPhase, ShuffleProofJson,
     ReconstructPublicState, MaskAndShuffleRoundJson, ReconstructState, ReconstructProofJson, PlayerReadableCard,
     PkProofJson, PlayerReadableCardJson, PlayerRevealAssignment, RevealPhase, RevealTokenPublicState, ShufflePublicState, ShuffleState, RevealTokenState,
     LeaveGameRoundJson};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pokergame::deck::{Card, EncryptedDeck};
use crate::pokergame::player::{GamePlayer, Player, PlayerWithProof, WalletAddress, GamePkHex};
use crate::pokergame::seat::{ClientSeat,Seat};
use crate::pokergame::side_pot::SidePot;
use poker_protocol::z_poker::{MentalPokerGame, GameConfig};
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Scalar};
use poker_protocol::z_poker::convert::{ecpoint_to_hex, scalar_to_hex};
use merlin::Transcript;
use poker_protocol::crypto::CurvePoint;
use poker_protocol::crypto::CurveScalar;
const MIN_START_NUM: u32 = 3;

pub mod shuffle;
pub mod reveal;
pub mod reconstruct;
pub mod seat_mgmt;
pub mod betting;
pub mod pot;
pub mod phases;
pub mod lifecycle;

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

pub use crate::pokergame::error::JoinError;

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
    pub pk_hex: GamePkHex,
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
    pub players: HashMap<GamePkHex, WalletAddress>,
    pub seats: HashMap<u32, ClientSeat>,
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
    pub reconstruct_state: Option<ReconstructPublicState>,
}



#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: HashMap<GamePkHex, WalletAddress>,
    pub seats: HashMap<u32, Seat>,
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
    pub reconstruct_state: ReconstructState,
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
    pub waiting_players: HashMap<GamePkHex, PlayerWithProof>,
    #[serde(skip)]
    pub pk_to_seat: HashMap<GamePkHex, u32>,
}

impl Table {
    pub fn to_client(&self) -> ClientTable {
        let mut client_seats = HashMap::new();
        for (seat_id, seat) in self.seats.iter() {
            let client_seat = seat.to_client();
            client_seats.insert(*seat_id, client_seat);
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
            reconstruct_state: self.get_reconstruct_public_state(),
        }
    }

    /// Transition to a new round state with validity checking.
    /// Logs a warning if the transition is not in the valid transition table.
    pub fn transition_to(&mut self, new_state: RoundState) {
        let from = self.round_state;
        let valid = matches!((from, new_state),
            // Normal game flow
            (RoundState::Waiting, RoundState::Shuffling) |
            (RoundState::Shuffling, RoundState::ShuffleComplete) |
            (RoundState::ShuffleComplete, RoundState::PreFlopReveal | RoundState::Waiting) |
            (RoundState::PreFlopReveal, RoundState::PreFlop) |
            (RoundState::PreFlop, RoundState::FlopReveal) |
            (RoundState::FlopReveal, RoundState::Flop) |
            (RoundState::Flop, RoundState::TurnReveal) |
            (RoundState::TurnReveal, RoundState::Turn) |
            (RoundState::Turn, RoundState::RiverReveal) |
            (RoundState::RiverReveal, RoundState::River) |
            (RoundState::River, RoundState::ShowdownReveal) |
            (RoundState::ShowdownReveal, RoundState::Showdown) |
            (RoundState::Showdown, RoundState::HandComplete) |
            (RoundState::HandComplete, RoundState::Waiting) |
            // Early termination (all but one player folds/leaves)
            (RoundState::PreFlop | RoundState::PreFlopReveal |
             RoundState::Flop | RoundState::FlopReveal |
             RoundState::Turn | RoundState::TurnReveal |
             RoundState::River | RoundState::RiverReveal |
             RoundState::ShowdownReveal, RoundState::HandComplete) |
            // Exception/timeout paths
            (RoundState::Shuffling, RoundState::Waiting) |
            (RoundState::ShuffleComplete, RoundState::ShuffleComplete) |
            (RoundState::PreFlopReveal, RoundState::Waiting) |
            (RoundState::PreFlop, RoundState::Waiting) |
            (RoundState::Flop, RoundState::Waiting) |
            (RoundState::Turn, RoundState::Waiting) |
            (RoundState::River, RoundState::Waiting) |
            (RoundState::ShowdownReveal, RoundState::Waiting)
        );
        tracing::info!("Transition from {:?} to {:?}", from, new_state);
        if !valid {
            tracing::warn!("Invalid state transition: {:?} -> {:?}", from, new_state);
        }
        self.round_state = new_state;
    }

    pub fn new(id: u32, name: String, limit: u64, max_players: u32) -> Self {
        let seats = Self::init_seats(max_players);
        Self {
            id,
            name,
            limit,
            max_players,
            players: HashMap::new(),
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
            reconstruct_state: ReconstructState::new(),
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
            pk_to_seat: HashMap::new(),
        }
    }

    pub fn init_seats(_max_players: u32) -> HashMap<u32, Seat> {
        HashMap::new()
    }

    pub fn is_playing(&self) -> bool {
        !matches!(self.round_state, RoundState::Waiting | RoundState::HandComplete|RoundState::Shuffling|RoundState::ShuffleComplete)
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
        for (id, seat) in &self.seats {
            clean.insert(id.to_string(), json!({
                "player": { "id": seat.player.as_ref().map(|p| p.wallet_address.0.clone()), "username": seat.player.as_ref().map(|p| p.name.clone()) },
                "bet": seat.bet,
                "stack": seat.stack,
            }));
        }
        serde_json::Value::Object(clean)
    }

    pub fn get_pk_hex_by_wallet_address(&self,wallet: &str)->Option<GamePkHex>{
        self.players.iter().find(|(pk_hex,wallet_addr)| wallet_addr.0 == wallet).map(|(pk_hex,_)|pk_hex.clone())
    }
}
