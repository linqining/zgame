use std::collections::HashMap;

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, hex_to_scalar, scalar_to_hex};

use poker_protocol::crypto::{CurveScalar, ElGamalCiphertext, Plaintext, Scalar};
use poker_protocol::z_poker::key_manager::PKOwnershipProof;
use poker_protocol::z_poker::protocol::MaskAndShuffleRound;
use poker_protocol::z_poker::protocol::LeaveGameRound;
use poker_protocol::zk_shuffle::remask_proof::RemaskProof;
use poker_protocol::zk_shuffle::leave_proof::LeaveProof;
use poker_protocol::crypto::DefaultCurve;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::reconstruction::{ReconstructProof, SwapOutCardProof, ReconstructionDLEQProof, ChaumPedersenDLEQProof};

use crate::pokergame::player::GamePkHex;

/// Macro to generate a JSON proof adapter struct and its conversion method.
/// Reduces boilerplate for structs where all fields are hex strings mapping to EcPoint or Scalar.
///
/// - `point` fields: hex string → EcPoint via `hex_to_ecpoint`
/// - `scalar` fields: hex string → Scalar via `hex_to_scalar`
/// - `scalar_vec` fields: Vec<String> → Vec<Scalar> via mapping `hex_to_scalar`
macro_rules! hex_proof_adapter {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => [$($target:tt)+] {
            $($pfield:ident : $ptarget:ident),* $(,)?
        }
        scalar { $($sfield:ident : $starget:ident),* $(,)? }
        $(scalar_vec { $($svfield:ident : $svtarget:ident),* $(,)? })?
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $($pfield: String,)*
            $($sfield: String,)*
            $($($svfield: Vec<String>,)*)?
        }

        impl $name {
            pub fn to_proof(&self) -> Result<$($target)+, String> {
                Ok($($target)+ {
                    $($ptarget: hex_to_ecpoint(&self.$pfield)?,)*
                    $($starget: hex_to_scalar(&self.$sfield)?,)*
                    $($($svtarget: self.$svfield.iter()
                        .map(|h| hex_to_scalar(h))
                        .collect::<Result<Vec<_>, _>>()?,)*)?
                })
            }
        }
    };
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShuffleState {
    pub is_active: bool,
    pub current_player_pk: Option<GamePkHex>,
    #[serde(skip)]
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
}

impl ShuffleState {
    pub fn new() -> Self {
        Self {
            is_active: false,
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
    ShowdownReveal,
    RedealReveal,
}

impl std::fmt::Display for RevealPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevealPhase::HandReveal => write!(f, "hand_reveal"),
            RevealPhase::CommunityReveal => write!(f, "community_reveal"),
            RevealPhase::ShowdownReveal => write!(f, "show_down_reveal"),
            RevealPhase::RedealReveal => write!(f, "redeal_reveal"),
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
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, PlayerRevealAssignment>,
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

#[derive(Debug, Clone, Default)]
pub struct PlayerRevealAssignment {
    pub hand_card: Vec<ElGamalCiphertext>,
    pub community_card: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone, Default)]
pub struct PlayerReadableCard {
    pub readable_cards: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlayerReadableCardJson {
    pub readable_cards: Vec<ElGamalCiphertextJson>,
}

impl Serialize for PlayerRevealAssignment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        let hand_card_jsons: Vec<ElGamalCiphertextJson> = self.hand_card.iter().map(|c_uint|ElGamalCiphertextJson::from_ciphertext(c_uint)).collect();
        map.serialize_entry("hand_card", &hand_card_jsons)?;
        let community_card_jsons:Vec<ElGamalCiphertextJson> = self.community_card.iter().map(|c_uint|ElGamalCiphertextJson::from_ciphertext(c_uint)).collect();
        map.serialize_entry("community_card", &community_card_jsons)?;
        map.end()
    }   
}

impl<'de> Deserialize<'de> for PlayerRevealAssignment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            hand_card: Vec<ElGamalCiphertextJson>,
            community_card: Vec<ElGamalCiphertextJson>,
        }

        let helper = Helper::deserialize(deserializer)?;
        let hand_card = helper.hand_card.into_iter()
            .map(|json| json.to_ciphertext().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        let community_card = helper.community_card.into_iter()
            .map(|json| json.to_ciphertext().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            hand_card,
            community_card,
        })
    }
}




#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub enum ReconstructPhase {
    #[default]
    Initiated,
    Voting,
    Completed,
    Forced,
}

impl std::fmt::Display for ReconstructPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconstructPhase::Initiated => write!(f, "initiated"),
            ReconstructPhase::Voting => write!(f, "voting"),
            ReconstructPhase::Completed => write!(f, "completed"),
            ReconstructPhase::Forced => write!(f, "forced"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReconstructState {
    pub is_active: bool,
    // pub phase: ReconstructPhase,
    pub timeout_start: Option<std::time::Instant>,
    pub timeout_seconds: u64,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,// 发起时的玩家列表
    pub cards: Vec<Plaintext>,
    pub coefficient: Scalar, //公共变量
    pub player_readable_cards: HashMap<GamePkHex, PlayerReadableCard>,
    pub player_deck: HashMap<GamePkHex, Vec<ElGamalCiphertext>>,
}

impl ReconstructState {
    pub fn new() -> Self {
        Self {
            is_active: false,
            timeout_start: None,
            timeout_seconds: 60,
            completed_players: Vec::new(),
            pending_players: Vec::new(),
            cards: Vec::new(),
            coefficient: Scalar::zero(),
            player_readable_cards: HashMap::new(),
            player_deck: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.is_active = false;
        self.timeout_start = None;
        self.completed_players.clear();
        self.pending_players.clear();
        self.cards.clear();
        self.coefficient = Scalar::zero();
        self.player_readable_cards.clear();
        self.player_deck.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealTokenPublicState {
    pub is_active: bool,
    pub phase: String,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructPublicState {
    pub is_active: bool,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub cards: Vec<String>,
    pub coefficient_hex: String, //公共变量
    pub player_readable_cards: HashMap<GamePkHex, PlayerReadableCardJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertextJson {
    pub c1_hex: String,
    pub c2_hex: String,
}

impl ElGamalCiphertextJson {
    pub fn from_ciphertext(ct: &poker_protocol::crypto::ElGamalCiphertext) -> Self {
        Self {
            c1_hex: ecpoint_to_hex(&ct.c1),
            c2_hex: ecpoint_to_hex(&ct.c2),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShufflePublicState {
    pub is_active: bool,
    pub current_player_pk: Option<GamePkHex>,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub deck_encrypted: Vec<ElGamalCiphertextJson>,
    pub aggregate_pk: String,
}



impl ElGamalCiphertextJson {
    pub fn to_ciphertext(&self) -> Result<ElGamalCiphertext, String> {
        Ok(ElGamalCiphertext {
            c1: hex_to_ecpoint(&self.c1_hex)?,
            c2: hex_to_ecpoint(&self.c2_hex)?,
        })
    }
}

hex_proof_adapter!(
    #[derive(Debug, Clone, Deserialize)]
    pub struct PkProofJson => [PKOwnershipProof] {
        commitment_hex : commitment,
    }
    scalar { response_hex : response }
);

#[derive(Debug, Clone, Deserialize)]
pub struct RemaskProofJson {
    pub per_card_commitments_hex: Vec<String>,
    pub commitment_pk_hex: String,
    pub response_hex: String,
    pub nonce_hex: String,
}

impl RemaskProofJson {
    pub fn to_remask_proof(&self) -> Result<RemaskProof<DefaultCurve>, String> {
        Ok(RemaskProof::from_parts(
            self.per_card_commitments_hex.iter()
                .map(|h| hex_to_ecpoint(h))
                .collect::<Result<Vec<_>, _>>()?,
            hex_to_ecpoint(&self.commitment_pk_hex)?,
            hex_to_scalar(&self.response_hex)?,
            hex_to_scalar(&self.nonce_hex)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveProofJson {
    pub per_card_commitments_hex: Vec<String>,
    pub commitment_pk_hex: String,
    pub response_hex: String,
    pub nonce_hex: String,
}

impl LeaveProofJson {
    pub fn to_leave_proof(&self) -> Result<LeaveProof<DefaultCurve>, String> {
        Ok(LeaveProof::from_parts(
            self.per_card_commitments_hex.iter()
                .map(|h| hex_to_ecpoint(h))
                .collect::<Result<Vec<_>, _>>()?,
            hex_to_ecpoint(&self.commitment_pk_hex)?,
            hex_to_scalar(&self.response_hex)?,
            hex_to_scalar(&self.nonce_hex)?,
        ))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaveGameRoundJson {
    pub input_cards: Vec<ElGamalCiphertextJson>,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub leave_proof: LeaveProofJson,
}

impl LeaveGameRoundJson {
    pub fn to_leave_game_round(&self) -> Result<LeaveGameRound, String> {
        let input_cards = self.input_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let output_cards = self.output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LeaveGameRound {
            input_cards,
            output_cards,
            leave_proof: self.leave_proof.to_leave_proof()?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralizedSchnorrProofJson {
    pub commitment_hex: String,
    pub responses_hex: Vec<String>,
}

impl GeneralizedSchnorrProofJson {
    pub fn to_proof(&self) -> Result<poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<DefaultCurve>, String> {
        let responses = self.responses_hex.iter()
            .map(|h| hex_to_scalar(h))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof {
            commitment: hex_to_ecpoint(&self.commitment_hex)?,
            responses,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOutCardProofJson {
    pub user_readable_card: ElGamalCiphertextJson,
    pub swap_out_card: ElGamalCiphertextJson,
    pub chaum_pedersen_proof: ChaumPedersenDLEQProofJson,
}

impl SwapOutCardProofJson {
    pub fn to_proof(&self) -> Result<SwapOutCardProof<DefaultCurve>, String> {
        Ok(SwapOutCardProof {
            user_readable_card: self.user_readable_card.to_ciphertext()?,
            swap_out_card: self.swap_out_card.to_ciphertext()?,
            chaum_pedersen_proof: self.chaum_pedersen_proof.to_proof()?,
        })
    }
}

hex_proof_adapter!(
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ChaumPedersenDLEQProofJson => [ChaumPedersenDLEQProof::<DefaultCurve>] {
        commitment_a_hex : commitment_a, commitment_b_hex : commitment_b,
    }
    scalar { response_hex : response }
);

hex_proof_adapter!(
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ReconstructionDLEQProofJson => [ReconstructionDLEQProof::<DefaultCurve>] {
        commitment_hex : commitment,
    }
    scalar { response_hex : response, nonce_hex : nonce }
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructProofJson {
    pub swap_out_cards_proofs: Vec<SwapOutCardProofJson>,
    pub sum_c1_r_commit_hex: String,
    pub sum_c2_r_commit_hex: String,
    pub swap_sum_c1_commit_hex: String,
    pub swap_sum_c2_commit_hex: String,
    pub nonce_hex: String,
    pub blind_dleq_proof: ReconstructionDLEQProofJson,
    pub total_dleq_proof: ChaumPedersenDLEQProofJson,
    pub swap_combined_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProofJson,
}

impl ReconstructProofJson {
    pub fn to_proof(&self) -> Result<ReconstructProof<DefaultCurve>, String> {
        Ok(ReconstructProof {
            swap_out_cards_proofs: self.swap_out_cards_proofs.iter()
                .map(|p| p.to_proof())
                .collect::<Result<Vec<_>, _>>()?,
            sum_c1_r_commit: hex_to_ecpoint(&self.sum_c1_r_commit_hex)?,
            sum_c2_r_commit: hex_to_ecpoint(&self.sum_c2_r_commit_hex)?,
            swap_sum_c1_commit: hex_to_ecpoint(&self.swap_sum_c1_commit_hex)?,
            swap_sum_c2_commit: hex_to_ecpoint(&self.swap_sum_c2_commit_hex)?,
            nonce: hex_to_scalar(&self.nonce_hex)?,
            blind_dleq_proof: self.blind_dleq_proof.to_proof()?,
            total_dleq_proof: self.total_dleq_proof.to_proof()?,
            swap_combined_schnorr_proof: self.swap_combined_schnorr_proof.to_proof()?,
            sum_swap_out_c1_schnorr_proof: self.sum_swap_out_c1_schnorr_proof.to_proof()?,
            sum_swap_out_c2_schnorr_proof: self.sum_swap_out_c2_schnorr_proof.to_proof()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShuffleProofJson {
    pub sum_c1_commit_hex: String,
    pub sum_c2_commit_hex: String,
    pub combined_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProofJson,
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProofJson,
    pub nonce_hex: String,
}

impl ShuffleProofJson {
    pub fn to_proof(&self) -> Result<ShuffleProof, String> {
        Ok(ShuffleProof {
            sum_c1_commit: hex_to_ecpoint(&self.sum_c1_commit_hex)?,
            sum_c2_commit: hex_to_ecpoint(&self.sum_c2_commit_hex)?,
            combined_schnorr_proof: self.combined_schnorr_proof.to_proof()?,
            sum_c1_schnorr_proof: self.sum_c1_schnorr_proof.to_proof()?,
            sum_c2_schnorr_proof: self.sum_c2_schnorr_proof.to_proof()?,
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

#[derive(Debug, Clone, Deserialize,Serialize)]
pub struct RevealTokenProofJson {
    pub user_public_key_hex: String,
    pub commitment_t1_hex: String,
    pub commitment_t2_hex: String,
    pub response_s_hex: String,
}

impl RevealTokenProofJson {
    pub fn to_proof(&self) -> Result<RevealTokenProof<DefaultCurve>, String> {
        Ok(RevealTokenProof {
            user_public_key: hex_to_ecpoint(&self.user_public_key_hex)?,
            commitment_t1: hex_to_ecpoint(&self.commitment_t1_hex)?,
            commitment_t2: hex_to_ecpoint(&self.commitment_t2_hex)?,
            response_s: hex_to_scalar(&self.response_s_hex)?,
        })
    }
    pub fn from_proof(proof: RevealTokenProof<DefaultCurve>) -> Self {
        Self {
            user_public_key_hex: ecpoint_to_hex(&proof.user_public_key),
            commitment_t1_hex: ecpoint_to_hex(&proof.commitment_t1),
            commitment_t2_hex: ecpoint_to_hex(&proof.commitment_t2),
            response_s_hex: scalar_to_hex(&proof.response_s),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitRevealTokenJson {
    pub encrypted_card: ElGamalCiphertextJson,
    pub reveal_token_proof: RevealTokenProofJson,
    pub reveal_token_hex: String,
}
