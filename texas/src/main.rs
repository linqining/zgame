mod config;
mod models;
mod auth;
mod handlers;
mod pokergame;
mod socket;

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
    initial_tables.insert(1, Table::new(1, "Table 1".to_string(), 10000, 5));
    initial_tables.insert(2, Table::new(2, "Table 2".to_string(), 20000, 5));
    initial_tables.insert(3, Table::new(3, "Table 3".to_string(), 50000, 5));

    let config_for_socket = config.clone();

    let socket_state = Arc::new(SocketState::new(db, initial_tables, config_for_socket));

    let (layer, io) = SocketIo::builder()
        .with_state(socket_state.clone())
        .build_layer();

    socket::register_handlers(&io);

    let app_state = Arc::new(AppState {
        db: socket_state.db.clone(),
        config: config.clone(),
    });

    let api_routes = Router::new()
        .route(
            "/auth",
            routing::get(handlers::get_current_user).post(handlers::login),
        )
        .route("/users", routing::post(handlers::register))
        .route("/chips/free", routing::get(handlers::free_chips));

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
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Vintage Poker Server (Rust) starting on port {}", port);
    tracing::info!("Connected to MongoDB: {}@{}", socket_state.config.mongodb_db_name, socket_state.config.mongodb_uri);

    axum::serve(listener, app).await
}
