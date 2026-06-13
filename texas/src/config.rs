#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub jwt_secret: String,
    pub initial_chips_amount: i64,
    pub jwt_token_expires_in: u64,
    pub mongodb_uri: String,
    pub mongodb_db_name: String,
    pub betting_timeout_secs: u64,
    pub showdown_display_secs: u64,
    pub hand_complete_wait_secs: u64,
    pub ready_countdown_secs: u64,
    pub free_chips_threshold: i64,
    pub free_chips_cooldown_secs: i64,
    pub max_players_per_table: u32,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001),
            jwt_secret: std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev_secret".to_string()),
            initial_chips_amount: 30000,
            jwt_token_expires_in: 86400000,
            mongodb_uri: std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            mongodb_db_name: std::env::var("MONGODB_DB_NAME").unwrap_or_else(|_| "vintage_poker".to_string()),
            betting_timeout_secs: std::env::var("BETTING_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(15),
            showdown_display_secs: std::env::var("SHOWDOWN_DISPLAY_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3),
            hand_complete_wait_secs: std::env::var("HAND_COMPLETE_WAIT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            ready_countdown_secs: std::env::var("READY_COUNTDOWN_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            free_chips_threshold: std::env::var("FREE_CHIPS_THRESHOLD").ok().and_then(|s| s.parse().ok()).unwrap_or(1000),
            free_chips_cooldown_secs: std::env::var("FREE_CHIPS_COOLDOWN_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3600),
            max_players_per_table: std::env::var("MAX_PLAYERS_PER_TABLE").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
        }
    }
}
