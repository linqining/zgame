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
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
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

impl RoundState {
    /// 将链上 u8 round_state 转换为 RoundState 枚举。
    /// 判别值与枚举声明顺序一致（0=Waiting, 1=Shuffling, ... 13=HandComplete）。
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RoundState::Waiting),
            1 => Some(RoundState::Shuffling),
            2 => Some(RoundState::ShuffleComplete),
            3 => Some(RoundState::PreFlopReveal),
            4 => Some(RoundState::PreFlop),
            5 => Some(RoundState::FlopReveal),
            6 => Some(RoundState::Flop),
            7 => Some(RoundState::TurnReveal),
            8 => Some(RoundState::Turn),
            9 => Some(RoundState::RiverReveal),
            10 => Some(RoundState::River),
            11 => Some(RoundState::ShowdownReveal),
            12 => Some(RoundState::Showdown),
            13 => Some(RoundState::HandComplete),
            _ => None,
        }
    }

    /// 将 Move 合约的三维并行状态组合映射为 Rust 内部单一维度 RoundState 枚举。
    ///
    /// Move 三维状态:
    /// - round_state: 0=WAITING, 2=PREFLOP, 3=FLOP, 4=TURN, 5=RIVER, 6=SHOWDOWN
    /// - shuffle_phase: 0=NONE, 1=WAITING, 2=RECONSTRUCT, 3=BEFORE_PREFLOP
    /// - reveal_phase: 0=NONE, 1=PREFLOP, 2=REDEAL, 3=FLOP, 4=TURN, 5=RIVER, 6=SHOWDOWN
    /// - reconstruct_phase: 0=NONE, 1=COLLECTING, 2=COMPLETE
    pub fn from_chain_state(
        round_u8: u8,
        shuffle_phase_u8: u8,
        reveal_phase_u8: u8,
        reconstruct_phase_u8: u8,
    ) -> RoundState {
        // 0. 优先判断 reconstruct 阶段（reconstruct_phase=1 表示正在收集）
        //    reconstruct 期间不应映射为 Shuffling
        if reconstruct_phase_u8 == 1 {
            // reconstruct 期间保持当前 round_state 对应的状态
            // 不映射为 Shuffling
            return match round_u8 {
                0 => RoundState::Waiting,
                2 => RoundState::PreFlop,
                3 => RoundState::Flop,
                4 => RoundState::Turn,
                5 => RoundState::River,
                6 => RoundState::Showdown,
                _ => RoundState::Waiting,
            };
        }

        // 1. Shuffle phase 优先（仅 BEFORE_PREFLOP=3 → Shuffling）
        //    RECONSTRUCT=2 不再映射为 Shuffling（由步骤 0 处理）
        if shuffle_phase_u8 == 3 {
            return RoundState::Shuffling;
        }

        // 2. Reveal phase 非 NONE 时映射到对应 *Reveal 状态
        if reveal_phase_u8 != 0 {
            return match reveal_phase_u8 {
                1 => RoundState::PreFlopReveal,
                2 => {
                    // REDEAL: 根据当前 round_state 返回对应 *Reveal
                    match round_u8 {
                        2 => RoundState::PreFlopReveal,
                        3 => RoundState::FlopReveal,
                        4 => RoundState::TurnReveal,
                        5 => RoundState::RiverReveal,
                        6 => RoundState::ShowdownReveal,
                        _ => RoundState::Waiting, // round_u8=0 或未知值时返回 Waiting
                    }
                }
                3 => RoundState::FlopReveal,
                4 => RoundState::TurnReveal,
                5 => RoundState::RiverReveal,
                6 => RoundState::ShowdownReveal,
                _ => RoundState::Waiting,
            };
        }

        // 3. 正常 round_state 映射（shuffle_phase=0 且 reveal_phase=0）
        match round_u8 {
            0 => RoundState::Waiting,
            2 => RoundState::PreFlop,
            3 => RoundState::Flop,
            4 => RoundState::Turn,
            5 => RoundState::River,
            6 => RoundState::Showdown,
            _ => RoundState::Waiting,
        }
    }
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
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    /// 由 relayer 在 `sync_table_state` 中匹配到链上 table 后设置。
    /// 上链模式下用户操作构建 PTB 时需要此字段；为 None 表示尚未与链上 table 关联。
    #[serde(skip)]
    pub chain_table_id: Option<String>,
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
    /// G4 修复：对严重非法转换（如 Waiting → Showdown）直接 panic，
    /// 其他非法转换在 debug 构建中 panic，release 中仅记录 warn。
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
            // 严重非法转换：从 Waiting 直接跳到 Showdown/HandComplete 等终局状态，
            // 这类转换不可能由正常游戏流程触发，直接 panic 暴露 bug。
            let severe = matches!((from, new_state),
                (RoundState::Waiting, RoundState::Showdown | RoundState::HandComplete) |
                (RoundState::HandComplete, RoundState::Showdown | RoundState::PreFlop |
                 RoundState::Flop | RoundState::Turn | RoundState::River) |
                (RoundState::Showdown, RoundState::PreFlop | RoundState::Flop |
                 RoundState::Turn | RoundState::River)
            );
            if severe {
                panic!("[transition_to] severe illegal state transition: {:?} -> {:?}", from, new_state);
            }
            tracing::warn!("Invalid state transition: {:?} -> {:?}", from, new_state);
            // debug 构建中对所有非法转换 panic，便于开发期及早发现状态机 bug
            debug_assert!(valid, "Invalid state transition: {:?} -> {:?}", from, new_state);
        }
        self.round_state = new_state;
    }

    pub fn new(id: u32, name: String, limit: u64, max_players: u32, chain_table_id: String) -> Self {
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
            chain_table_id: Some(chain_table_id),
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
