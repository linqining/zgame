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
mod sui_query;
mod relayer;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{routing, Router};
use mongodb::Client as MongoClient;
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
                .unwrap_or_else(|_| "debug,tokio_runtime=info".into())
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(true)
        .init();

    let config = Config::from_env();
    let port = config.port;

    let mongo_client = match MongoClient::with_uri_str(&config.mongodb_uri).await {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("Failed to connect to MongoDB at {}: {}", config.mongodb_uri, e);
            std::process::exit(1);
        }
    };
    let mongo_db = mongo_client.database(&config.mongodb_db_name);
    let db = Database::new(&mongo_db).await;

    let mut initial_tables = HashMap::new();
    initial_tables.insert(1, Table::new(1, "Table 1".to_string(), 10000, config.max_players_per_table));
    initial_tables.insert(2, Table::new(2, "Table 2".to_string(), 20000, config.max_players_per_table));
    initial_tables.insert(3, Table::new(3, "Table 3".to_string(), 50000, config.max_players_per_table));
    for table in initial_tables.values_mut() {
        table.start_shuffle();
    }

    let config_for_socket = config.clone();

    let socket_state = Arc::new(SocketState::new(db, initial_tables, config_for_socket));

    let (layer, io) = SocketIo::builder()
        .with_state(socket_state.clone())
        .build_layer();

    socket::set_socket_io(io.clone());
    socket::register_handlers(&io);

    let relayer_state = Arc::new(relayer::RelayerState::new());

    let app_state = Arc::new(AppState {
        db: socket_state.db.clone(),
        config: config.clone(),
        socket_state: socket_state.clone(),
        relayer_state: relayer_state.clone(),
    });

    // 克隆用于 Sui 监听器后台任务
    let listener_state = app_state.clone();
    // 克隆用于 relayer tick 后台任务
    let tick_state = app_state.clone();

    let api_routes = Router::new()
        .route("/auth",routing::get(handlers::get_current_user).post(handlers::login))
        .route("/auth/wallet", routing::post(handlers::wallet_login))
        .route("/auth/wallet/logout", routing::post(handlers::wallet_logout))
        .route("/auth/zklogin", routing::post(sponsor::zklogin_auth))
        .route("/auth/zklogin/salt", routing::post(sponsor::get_zklogin_salt))
        .route("/users", routing::post(handlers::register))
        .route("/chips/free", routing::get(handlers::free_chips))
        .route("/tables/:table_id", routing::get(handlers::get_table))
        .route("/sponsor/transaction", routing::post(sponsor::sponsor_transaction))
        .route("/sponsor/gas-info", routing::get(sponsor::get_gas_info))
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
        .route("/", routing::get(|| async { "Welcome to Vintage Poker (Rust)!" }))
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
    tracing::info!("Vintage Poker Server (Rust) starting on port {}", port);
    tracing::info!("Connected to MongoDB: {}@{}", socket_state.config.mongodb_db_name, socket_state.config.mongodb_uri);

    // 启动 Sui 事件监听器后台任务（历史回填）
    tokio::spawn(async move {
        sui_listener::start_sui_listener(listener_state).await;
    });

    // 启动 relayer 定时 tick 后台任务（处理链上超时）
    tokio::spawn(async move {
        relayer::tick::run_tick_loop(tick_state).await;
    });

    axum::serve(listener, app).await
}
