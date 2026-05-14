#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub jwt_secret: String,
    pub initial_chips_amount: i64,
    pub jwt_token_expires_in: u64,
    pub mongodb_uri: String,
    pub mongodb_db_name: String,
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
        }
    }
}
