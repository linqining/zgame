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
