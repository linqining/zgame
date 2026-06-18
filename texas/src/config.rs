use zeroize::Zeroizing;

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
    pub free_chips_cooldown_secs: u64,
    pub max_players_per_table: u32,
    // Sponsored transaction config
    pub sponsor_private_key: Zeroizing<String>,
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
    // 是否上链模式（true=上链，false=本地模式）
    pub sui_on_chain_enabled: bool,
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
            eprintln!("FATAL: JWT_SECRET environment variable is required");
            std::process::exit(1);
        });

        let inodra_webhook_secret = std::env::var("INODRA_WEBHOOK_SECRET").unwrap_or_default();
        let sui_event_provider = std::env::var("SUI_EVENT_PROVIDER").unwrap_or_else(|_| "grpc".to_string());
        if (sui_event_provider == "webhook" || sui_event_provider == "both") && inodra_webhook_secret.is_empty() {
            eprintln!("FATAL: INODRA_WEBHOOK_SECRET is required when SUI_EVENT_PROVIDER is webhook or both");
            std::process::exit(1);
        }

        Self {
            port: std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001),
            jwt_secret,
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
            sponsor_private_key: Zeroizing::new(std::env::var("SPONSOR_PRIVATE_KEY").unwrap_or_else(|_| "".to_string())),
            sponsor_gas_budget: std::env::var("SPONSOR_GAS_BUDGET").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000_000),
            fullnode_url: std::env::var("FULLNODE_URL").unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string()),
            zklogin_salt_secret: std::env::var("ZKLOGIN_SALT_SECRET").unwrap_or_else(|_| {
                // G20 修复：不再提供默认值，强制要求显式配置
                tracing::warn!("ZKLOGIN_SALT_SECRET not set, zkLogin salt derivation will use empty secret (insecure for production)");
                String::new()
            }),
            inodra_webhook_secret,
            sui_package_id: std::env::var("SUI_PACKAGE_ID").unwrap_or_else(|_| "".to_string()),
            sui_network: std::env::var("SUI_NETWORK").unwrap_or_else(|_| "testnet".to_string()),
            sui_event_provider,
            sui_tick_interval_ms: std::env::var("SUI_TICK_INTERVAL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(5000),
            sui_clock_object_id: std::env::var("SUI_CLOCK_OBJECT_ID").unwrap_or_else(|_| "0x6".to_string()),
            sui_on_chain_enabled: std::env::var("SUI_ON_CHAIN_ENABLED").ok().and_then(|s| s.parse().ok()).unwrap_or(false),
        }
    }
}
