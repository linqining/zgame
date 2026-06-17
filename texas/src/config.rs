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
    // Sponsored transaction config
    pub sponsor_private_key: String,
    pub sponsor_gas_budget: u64,
    pub fullnode_url: String,
    // zkLogin salt secret
    pub zklogin_salt_secret: String,
    // Sui event listener config
    pub inodra_webhook_secret: String,
    pub sui_package_id: String,
    pub sui_network: String,
    pub sui_event_provider: String,
    // Sui tick task config
    pub sui_tick_interval_ms: u64,
    pub sui_clock_object_id: String,
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
            sponsor_private_key: std::env::var("SPONSOR_PRIVATE_KEY").unwrap_or_else(|_| "".to_string()),
            sponsor_gas_budget: std::env::var("SPONSOR_GAS_BUDGET").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000_000),
            fullnode_url: std::env::var("FULLNODE_URL").unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string()),
            zklogin_salt_secret: std::env::var("ZKLOGIN_SALT_SECRET").unwrap_or_else(|_| "zklogin_salt_dev_secret".to_string()),
            inodra_webhook_secret: std::env::var("INODRA_WEBHOOK_SECRET").unwrap_or_else(|_| "".to_string()),
            sui_package_id: std::env::var("SUI_PACKAGE_ID").unwrap_or_else(|_| "".to_string()),
            sui_network: std::env::var("SUI_NETWORK").unwrap_or_else(|_| "testnet".to_string()),
            sui_event_provider: std::env::var("SUI_EVENT_PROVIDER").unwrap_or_else(|_| "grpc".to_string()),
            sui_tick_interval_ms: std::env::var("SUI_TICK_INTERVAL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(1000),
            sui_clock_object_id: std::env::var("SUI_CLOCK_OBJECT_ID").unwrap_or_else(|_| "0x6".to_string()),
        }
    }
}
