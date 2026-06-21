mod config;
mod models;
mod auth;
mod handlers;
mod wallet_auth;
mod sponsor;
mod pokergame;
mod socket;
mod sui_events;
mod sui_webhook;
mod sui_listener;
mod sui_grpc;
mod sui_graphql_sub;
mod sui_query;
mod relayer;
#[cfg(test)]
mod move_verify_tests;
#[cfg(test)]
mod join_and_shuffle_testnet;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{routing, Router};
use socket::SocketState;
use socketioxide::SocketIo;
use tower::ServiceBuilder;

use config::Config;
use handlers::AppState;
use models::Database;
use pokergame::table::Table;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,texas=debug".into())
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(true)
        .init();

    let config = Config::from_env();
    let port = config.port;

    let db = Database::new();

    let mut initial_tables = HashMap::new();
    initial_tables.insert(1, Table::new(1, "Table 1".to_string(), 10000, config.max_players_per_table, "0x706e7909f6a9614fc7912b28902091a0fc178c6ed0a90a1e6cbceaff40ff9749".to_string()));
    // initial_tables.insert(2, Table::new(2, "Table 2".to_string(), 20000, config.max_players_per_table, "".to_string()));
    // initial_tables.insert(3, Table::new(3, "Table 3".to_string(), 50000, config.max_players_per_table, "".to_string()));
    for table in initial_tables.values_mut() {
        table.start_shuffle();
    }

    let config_for_socket = config.clone();

    let socket_state = Arc::new(SocketState::new(db, initial_tables, config_for_socket));

    let (layer, io) = SocketIo::builder()
        .with_state(socket_state.clone())
        .build_layer();

    socket::set_socket_io(io.clone());
    socket_state.init_table_event_channels(io.clone()).await;
    socket::register_handlers(&io);

    let app_state = Arc::new(AppState {
        db: socket_state.db.clone(),
        config: config.clone(),
        socket_state: socket_state.clone(),
        processed_actions: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        processed_webhook_ids: Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())),
        action_retry_queue: Arc::new(std::sync::Mutex::new(Vec::new())),
    });

    // 克隆用于 Sui 监听器后台任务
    let listener_state = app_state.clone();
    // 克隆用于 relayer tick 后台任务
    let tick_state = app_state.clone();
    // 克隆用于 action retry 后台任务（Task 10）
    let retry_state = app_state.clone();

    let api_routes = Router::new()
        .route("/auth",routing::get(handlers::get_current_user))
        .route("/auth/wallet", routing::post(handlers::wallet_login))
        .route("/auth/wallet/logout", routing::post(handlers::wallet_logout))
        .route("/auth/zklogin", routing::post(sponsor::zklogin_auth))
        .route("/auth/zklogin/salt", routing::post(sponsor::get_zklogin_salt))
        .route("/auth/zklogin/prover", routing::post(sponsor::post_zklogin_prover))
        .route("/sui/balance", routing::get(handlers::get_sui_balance))
        .route("/tables/:table_id", routing::get(handlers::get_table))
        .route("/sponsor/transaction", routing::post(sponsor::sponsor_transaction))
        .route("/sui/webhook", routing::post(sui_webhook::inodra_webhook))
        .route("/sui/tables", routing::get(handlers::list_sui_tables))
        .route("/sui/tables/:table_id", routing::get(handlers::get_sui_table))
        .route("/sui/tables/:table_id/refresh", routing::post(handlers::refresh_sui_table))
        .route("/sui/tables/:table_id/tick", routing::post(handlers::manual_tick))
        .route("/sui/action/build", routing::post(handlers::build_action_ptb))
        .route("/games/:game_id/join", routing::post(handlers::join_game))
        .route("/games/:game_id/action", routing::post(handlers::player_action))
        .route("/games/:game_id/reveal-token", routing::post(handlers::submit_reveal_token));

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/", routing::get(|| async { "Welcome to Secret Poker (Rust)!" }))
        // G17 TODO: 当前未实现 API 速率限制（rate limiting）。生产环境应引入
        // tower_governor 或类似中间件对 /api/* 路由（尤其是 /auth/*、/chips/free、
        // /sponsor/* 等敏感端点）添加 per-IP / per-user 限流，防止暴力破解与滥用。
        .layer(
            ServiceBuilder::new()
                .map_request(move |mut req: axum::http::Request<axum::body::Body>| {
                    let state = app_state.clone();
                    req.extensions_mut().insert(state);
                    req
                })
                .into_inner(),
        )
        .layer(layer)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::HeaderName::from_static("x-auth-token")])
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Secret Poker Server (Rust) starting on port {}", port);
    tracing::info!("Using in-memory user storage (MongoDB removed). SUI wallet balance = chip balance (1 SUI = 10000 chips).");

    // 启动 Sui 事件监听器后台任务（历史回填）
    tokio::spawn(async move {
        sui_listener::start_sui_listener(listener_state).await;
    });

    // 启动 relayer 定时 tick 后台任务（处理链上超时）
    tokio::spawn(async move {
        relayer::tick::run_tick_loop(tick_state).await;
    });

    // 启动 action retry 后台任务（Task 10：重试失败的玩家行动事件）
    tokio::spawn(async move {
        relayer::run_action_retry_loop(retry_state).await;
    });

    axum::serve(listener, app).await
}
