use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::player::Player;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seat {
    pub id: u32,
    pub player: Option<Player>,
    pub buyin: u64,
    pub stack: u64,
    pub hand: Vec<Card>,
    pub bet: u64,
    pub turn: bool,
    pub checked: bool,
    pub folded: bool,
    pub last_action: Option<String>,
    pub sitting_out: bool,
    #[serde(default)]
    pub disconnected: bool,
    #[serde(skip)]
    pub disconnected_at: Option<u64>,
}

impl Seat {
    pub fn new(id: u32, player: Option<Player>, buyin: u64, stack: u64) -> Self {
        Self {
            id,
            player,
            buyin,
            stack,
            hand: vec![],
            bet: 0,
            turn: false,
            checked: true,
            folded: true,
            last_action: None,
            sitting_out: false,
            disconnected: false,
            disconnected_at: None,
        }
    }

    pub fn fold(&mut self) {
        self.bet = 0;
        self.folded = true;
        self.last_action = Some(actions::FOLD.to_string());
        self.turn = false;
    }

    pub fn check(&mut self) {
        self.checked = true;
        self.last_action = Some(actions::CHECK.to_string());
        self.turn = false;
    }

    pub fn raise(&mut self, amount: u64) {
        let re_raise_amount = amount - self.bet;
        if re_raise_amount > self.stack {
            return;
        }
        self.bet = amount;
        self.stack -= re_raise_amount;
        self.turn = false;
        self.last_action = Some(actions::RAISE.to_string());
    }

    pub fn place_blind(&mut self, amount: u64) {
        self.bet = amount;
        self.stack -= amount;
    }

    pub fn call_raise(&mut self, amount: u64) {
        let mut amount_called = amount - self.bet;
        if amount_called >= self.stack {
            amount_called = self.stack;
        }
        self.bet += amount_called;
        self.stack -= amount_called;
        self.turn = false;
        self.last_action = Some(actions::CALL.to_string());
    }

    pub fn win_hand(&mut self, amount: u64) {
        self.bet = 0;
        self.stack += amount;
        self.turn = false;
        self.last_action = Some(actions::WINNER.to_string());
    }
}
