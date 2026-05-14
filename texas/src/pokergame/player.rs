use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Player {
    pub socket_id: String,
    pub id: String,
    pub name: String,
    pub bankroll: i64,
}
