use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShuffleState {
    pub is_active: bool,
    pub current_player_pk: Option<String>,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
}

impl ShuffleState {
    pub fn new() -> Self {
        Self {
            is_active: true,
            current_player_pk: None,
            timeout_start: None,
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.is_active = false;
        self.current_player_pk = None;
        self.timeout_start = None;
        self.timeout_seconds = 0;
        self.completed_players.clear();
        self.pending_players.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevealPhase {
    #[default]
    HandReveal,
    CommunityReveal,
    ShowDownReveal,
}

impl std::fmt::Display for RevealPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevealPhase::HandReveal => write!(f, "hand_reveal"),
            RevealPhase::CommunityReveal => write!(f, "community_reveal"),
            RevealPhase::ShowDownReveal => write!(f, "show_down_reveal"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealTokenState {
    pub is_active: bool,
    pub phase: RevealPhase,
    pub current_card_index: usize,
    pub total_cards_per_player: usize,
    pub total_community_cards: usize,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
    pub player_assignments: HashMap<String, PlayerRevealAssignment>,
}

impl RevealTokenState {
    pub fn new(cards_per_player: usize, community_cards: usize) -> Self {
        Self {
            is_active: false,
            phase: RevealPhase::HandReveal,
            current_card_index: 0,
            total_cards_per_player: cards_per_player,
            total_community_cards: community_cards,
            timeout_start: None,
            timeout_seconds: 10,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
            player_assignments: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.is_active = false;
        self.current_card_index = 0;
        self.timeout_start = None;
        self.completed_players.clear();
        self.pending_players.clear();
        self.player_assignments.clear();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerRevealAssignment {
    pub hand_card_indices: Vec<usize>,
    pub community_card_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExpelPhase {
    #[default]
    Initiated,
    Voting,
    Completed,
    Forced,
}

impl std::fmt::Display for ExpelPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpelPhase::Initiated => write!(f, "initiated"),
            ExpelPhase::Voting => write!(f, "voting"),
            ExpelPhase::Completed => write!(f, "completed"),
            ExpelPhase::Forced => write!(f, "forced"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpelState {
    pub is_active: bool,
    pub phase: ExpelPhase,
    pub target_player_pk: Option<String>,
    pub initiator_pk: Option<String>,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub voted_players: Vec<String>,
    pub required_votes: usize,
    pub expelled_players: Vec<String>,
    pub expel_records_count: usize,
}

impl ExpelState {
    pub fn new() -> Self {
        Self {
            is_active: false,
            phase: ExpelPhase::Initiated,
            target_player_pk: None,
            initiator_pk: None,
            timeout_start: None,
            timeout_seconds: 60,
            voted_players: Vec::new(),
            required_votes: 2,
            expelled_players: Vec::new(),
            expel_records_count: 0,
        }
    }

    pub fn reset(&mut self) {
        self.is_active = false;
        self.phase = ExpelPhase::Initiated;
        self.target_player_pk = None;
        self.initiator_pk = None;
        self.timeout_start = None;
        self.voted_players.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShufflePublicState {
    pub is_active: bool,
    pub current_player_pk: Option<String>,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
}
