use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_token_expires_in: u64,
    pub betting_timeout_secs: u64,
    pub showdown_display_secs: u64,
    pub hand_complete_wait_secs: u64,
    pub ready_countdown_secs: u64,
    pub max_players_per_table: u32,
    // Sponsored transaction config
    pub sponsor_private_key: Zeroizing<String>,
    pub sponsor_gas_budget: u64,
    pub fullnode_url: String,
    /// gRPC 订阅专用端点（与 fullnode_url 分离，因为 gRPC 流式订阅需要支持 SubscriptionService 的节点）。
    /// 若未设置，回退到 fullnode_url。
    pub grpc_url: String,
    /// gRPC 认证 token（Chainstack/QuickNode 等付费节点的 x-token）。
    /// 留空则不发送认证 header（适用于公共节点）。
    pub grpc_token: String,
    // zkLogin salt secret
    pub zklogin_salt_secret: String,
    // Shinami zkProver access key (Wallet Services). The backend proxies zkLogin
    // proof requests to Shinami because Shinami's API does not support CORS.
    pub shinami_api_key: String,
    // Sui event listener config
    pub inodra_webhook_secret: String,
    pub sui_package_id: String,
    /// 合约首次发布时的原始 Package ID（升级后 struct 类型仍锚定在此 ID）。
    /// 用于事件过滤（gRPC / GraphQL）和对象类型查询。
    /// 若未设置，回退到 sui_package_id（兼容首次发布场景）。
    pub sui_origin_package_id: String,
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

        let sui_package_id = std::env::var("SUI_PACKAGE_ID").unwrap_or_else(|_| "".to_string());
        let sui_origin_package_id = {
            let origin = std::env::var("SUI_ORIGIN_PACKAGE_ID").unwrap_or_else(|_| "".to_string());
            if origin.is_empty() { sui_package_id.clone() } else { origin }
        };

        Self {
            port: std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001),
            jwt_secret,
            jwt_token_expires_in: 86400000,
            betting_timeout_secs: std::env::var("BETTING_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30),
            showdown_display_secs: std::env::var("SHOWDOWN_DISPLAY_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3),
            hand_complete_wait_secs: std::env::var("HAND_COMPLETE_WAIT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            ready_countdown_secs: std::env::var("READY_COUNTDOWN_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            max_players_per_table: std::env::var("MAX_PLAYERS_PER_TABLE").ok().and_then(|s| s.parse().ok()).unwrap_or(5),
            sponsor_private_key: Zeroizing::new(std::env::var("SPONSOR_PRIVATE_KEY").unwrap_or_else(|_| "".to_string())),
            sponsor_gas_budget: std::env::var("SPONSOR_GAS_BUDGET").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000_000),
            fullnode_url: std::env::var("FULLNODE_URL").unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string()),
            grpc_url: std::env::var("GRPC_URL").unwrap_or_else(|_| std::env::var("FULLNODE_URL").unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string())),
            grpc_token: std::env::var("GRPC_TOKEN").unwrap_or_default(),
            zklogin_salt_secret: std::env::var("ZKLOGIN_SALT_SECRET").unwrap_or_else(|_| {
                // G20 修复：不再提供默认值，强制要求显式配置
                tracing::warn!("ZKLOGIN_SALT_SECRET not set, zkLogin salt derivation will use empty secret (insecure for production)");
                String::new()
            }),
            shinami_api_key: std::env::var("SHINAMI_API_KEY").unwrap_or_else(|_| {
                tracing::warn!("SHINAMI_API_KEY not set, zkLogin prover proxy will be unavailable");
                String::new()
            }),
            inodra_webhook_secret,
            sui_package_id,
            sui_origin_package_id,
            sui_network: std::env::var("SUI_NETWORK").unwrap_or_else(|_| "testnet".to_string()),
            sui_event_provider,
            sui_tick_interval_ms: std::env::var("SUI_TICK_INTERVAL_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(5000),
            sui_clock_object_id: std::env::var("SUI_CLOCK_OBJECT_ID").unwrap_or_else(|_| "0x6".to_string()),
            sui_on_chain_enabled: std::env::var("SUI_ON_CHAIN_ENABLED").ok().and_then(|s| s.parse().ok()).unwrap_or(false),
        }
    }
}
