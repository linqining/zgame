use serde::{Deserialize, Serialize};

use crate::pokergame::game_state::ElGamalCiphertextJson;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Player {
    pub socket_id: String,
    pub id: String,
    pub name: String,
    pub bankroll: i64,
    pub pk_hex: String,
    pub readable_hands: Vec<ElGamalCiphertextJson>
}

#[derive(Debug, Clone)]
pub struct PlayerWithProof {
    pub player: Player,
    pub pk: poker_protocol::crypto::EcPoint,
    pub pk_proof: poker_protocol::z_poker::PKOwnershipProof,
}
