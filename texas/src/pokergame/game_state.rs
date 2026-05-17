use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use poker_protocol::z_poker::convert::ecpoint_to_hex;
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Scalar};
use poker_protocol::z_poker::PKOwnershipProof;
use poker_protocol::z_poker::protocol::MaskAndShuffleRound;
use poker_protocol::zk_shuffle::remask_proof::RemaskProof;
use poker_protocol::zk_shuffle::{ShuffleProof, ZKConsistencyProof};
use poker_protocol::crypto::{TripleDLEqProof, ProductArgumentV2};
use group::GroupEncoding;
use ff::PrimeField;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
pub struct PlayerRevealAssignment {
    pub hand_card_indices: Vec<usize>,
    pub community_card_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
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
pub struct RevealTokenPublicState {
    pub is_active: bool,
    pub phase: String,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
    pub player_assignments: HashMap<String, PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpelPublicState {
    pub is_active: bool,
    pub phase: String,
    pub target_player_pk: Option<String>,
    pub initiator_pk: Option<String>,
    pub voted_players: Vec<String>,
    pub required_votes: usize,
    pub expelled_players: Vec<String>,
    pub expel_records_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertextJson {
    pub c1_hex: String,
    pub c2_hex: String,
    pub c3_hex: String,
}

impl ElGamalCiphertextJson {
    pub fn from_ciphertext(ct: &poker_protocol::crypto::ElGamalCiphertext) -> Self {
        Self {
            c1_hex: ecpoint_to_hex(&ct.c1),
            c2_hex: ecpoint_to_hex(&ct.c2),
            c3_hex: ecpoint_to_hex(&ct.c3),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShufflePublicState {
    pub is_active: bool,
    pub current_player_pk: Option<String>,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
    pub deck_encrypted: Vec<ElGamalCiphertextJson>,
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    match EcPoint::from_bytes(bytes.as_slice().into()).into_option() {
        Some(p) => Ok(p),
        None => Err("Invalid EC point".to_string())
    }
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    match Scalar::from_repr(arr.into()).into_option() {
        Some(s) => Ok(s),
        None => Err("Invalid scalar value".to_string())
    }
}

impl ElGamalCiphertextJson {
    pub fn to_ciphertext(&self) -> Result<ElGamalCiphertext, String> {
        Ok(ElGamalCiphertext {
            c1: hex_to_ecpoint(&self.c1_hex)?,
            c2: hex_to_ecpoint(&self.c2_hex)?,
            c3: hex_to_ecpoint(&self.c3_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PkProofJson {
    pub commitment_hex: String,
    pub response_hex: String,
}

impl PkProofJson {
    pub fn to_pk_proof(&self) -> Result<PKOwnershipProof, String> {
        Ok(PKOwnershipProof {
            commitment: hex_to_ecpoint(&self.commitment_hex)?,
            response: hex_to_scalar(&self.response_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemaskProofJson {
    pub a_hex: String,
    pub b_hex: String,
    pub sum_c1_hex: String,
    pub sum_d2_hex: String,
    pub s_hex: String,
    pub nonce_hex: String,
}

impl RemaskProofJson {
    pub fn to_remask_proof(&self) -> Result<RemaskProof, String> {
        Ok(RemaskProof {
            A: hex_to_ecpoint(&self.a_hex)?,
            B: hex_to_ecpoint(&self.b_hex)?,
            sum_c1: hex_to_ecpoint(&self.sum_c1_hex)?,
            sum_d2: hex_to_ecpoint(&self.sum_d2_hex)?,
            s: hex_to_scalar(&self.s_hex)?,
            nonce: hex_to_scalar(&self.nonce_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZKConsistencyProofJson {
    pub d1_hex: String,
    pub d2_hex: String,
    pub a_g_hex: String,
    pub a_pk_hex: String,
    pub s_hex: String,
}

impl ZKConsistencyProofJson {
    pub fn to_proof(&self) -> Result<ZKConsistencyProof, String> {
        Ok(ZKConsistencyProof {
            d1: hex_to_ecpoint(&self.d1_hex)?,
            d2: hex_to_ecpoint(&self.d2_hex)?,
            a_g: hex_to_ecpoint(&self.a_g_hex)?,
            a_pk: hex_to_ecpoint(&self.a_pk_hex)?,
            s: hex_to_scalar(&self.s_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TripleDLEqProofJson {
    pub a_g_hex: String,
    pub a_pk_hex: String,
    pub a_h_hex: String,
    pub s_hex: String,
}

impl TripleDLEqProofJson {
    pub fn to_proof(&self) -> Result<TripleDLEqProof, String> {
        Ok(TripleDLEqProof {
            A_g: hex_to_ecpoint(&self.a_g_hex)?,
            A_pk: hex_to_ecpoint(&self.a_pk_hex)?,
            A_h: hex_to_ecpoint(&self.a_h_hex)?,
            s: hex_to_scalar(&self.s_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProductArgumentV2Json {
    pub a_hex: String,
    pub b_hex: String,
    pub c_hex: String,
    pub d_hex: String,
    pub t_hex: String,
    pub s_hex: String,
}

impl ProductArgumentV2Json {
    pub fn to_argument(&self) -> Result<ProductArgumentV2, String> {
        Ok(ProductArgumentV2 {
            A: hex_to_ecpoint(&self.a_hex)?,
            B: hex_to_ecpoint(&self.b_hex)?,
            C: hex_to_ecpoint(&self.c_hex)?,
            D: hex_to_ecpoint(&self.d_hex)?,
            t: hex_to_scalar(&self.t_hex)?,
            s: hex_to_scalar(&self.s_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShuffleProofJson {
    pub zk_consistency: ZKConsistencyProofJson,
    pub triple_dleq: TripleDLEqProofJson,
    pub product_arg: ProductArgumentV2Json,
    pub global_challenge_hex: String,
    pub nonce_hex: String,
}

impl ShuffleProofJson {
    pub fn to_proof(&self) -> Result<ShuffleProof, String> {
        Ok(ShuffleProof {
            zk_consistency: self.zk_consistency.to_proof()?,
            triple_dleq: self.triple_dleq.to_proof()?,
            product_arg: self.product_arg.to_argument()?,
            global_challenge: hex_to_scalar(&self.global_challenge_hex)?,
            nonce: hex_to_scalar(&self.nonce_hex)?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MaskAndShuffleRoundJson {
    pub mask_cards: Vec<ElGamalCiphertextJson>,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub remask_proof: RemaskProofJson,
    pub shuffle_proof: ShuffleProofJson,
}

impl MaskAndShuffleRoundJson {
    pub fn to_mask_and_shuffle_round(&self) -> Result<MaskAndShuffleRound, String> {
        let mask_cards = self.mask_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let output_cards = self.output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MaskAndShuffleRound {
            mask_cards,
            output_cards,
            proof: self.shuffle_proof.to_proof()?,
            remask_proof: self.remask_proof.to_remask_proof()?,
        })
    }
}
