use axum::{
    body::Body,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode, Request},
    response::IntoResponse,
    response::Response,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::auth;
use crate::config::Config;
use crate::models::{Database, UserResponse};
use crate::pokergame::player::Player;
use crate::socket::SocketState;
use poker_protocol::z_poker::protocol::ClientPlayer;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub socket_state: Arc<SocketState>,
}

#[derive(Deserialize,Debug)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    name: String,
    email: String,
    password: String,
}

fn get_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-auth-token")
        .and_then(|t| t.to_str().ok())
        .map(|s| s.to_string())
}

fn user_to_response(user: &crate::models::User) -> serde_json::Value {
    let resp = UserResponse {
        id: user.id.clone(),
        name: user.name.clone(),
        email: user.email.clone(),
        chips_amount: user.chips_amount,
        user_type: user.user_type,
        created: user.created.clone(),
    };
    serde_json::to_value(&resp).unwrap()
}

pub async fn get_current_user(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    let token = match get_token_from_headers(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response(),
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => match state.db.find_user_by_id(&claims.user.id).await {
            Some(user) => (StatusCode::OK, Json(user_to_response(&user))).into_response(),
            None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "User not found"}))).into_response(),
        },
        Err(_) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response(),
    }
}

#[derive(Deserialize)]
struct JoinGameRequest {
    name: String,
    pk_hex: String,
}

#[derive(Deserialize)]
struct ShuffleRequest {
    pk_hex: String,
    shuffle_data: serde_json::Value,
}

#[derive(Deserialize)]
struct JoinAndShuffleRequest {
    pk_hex: String,
    name: String,
    shuffle_data: serde_json::Value,
}

#[derive(Deserialize)]
struct ActionRequestHttp {
    pk_hex: String,
    action: String,
    amount: Option<u64>,
}

#[derive(Deserialize)]
struct RevealTokenRequest {
    pk_hex: String,
    reveal_tokens: Vec<serde_json::Value>,
}

fn parse_game_id(game_id: &str) -> Option<u32> {
    game_id.parse::<u32>().ok()
}

fn err_resp(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({"error": msg}))).into_response()
}

pub async fn join_game(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body: JoinGameRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id"),
    };

    if let Some(_existing) = state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        return err_resp(StatusCode::BAD_REQUEST, "Player already in game");
    }

    let socket_id = format!("http_{}", body.pk_hex);
    let player = Player {
        socket_id: socket_id.clone(),
        id: body.pk_hex.clone(),
        name: body.name.clone(),
        bankroll: 0,
        pk_hex: body.pk_hex.clone(),
    };

    if state.socket_state.add_player_to_table(table_id, player).is_err() {
        return err_resp(StatusCode::NOT_FOUND, "Table not found");
    }

    (StatusCode::CREATED, Json(serde_json::json!({
        "player": {"id": body.pk_hex},
        "message": "Joined game successfully"
    }))).into_response()
}

pub async fn shuffle(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body: ShuffleRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id"),
    };

    let socket_id = match state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        Some(id) => id,
        None => return err_resp(StatusCode::NOT_FOUND, "Player not found"),
    };

    let result = match state.socket_state.submit_shuffle_for_pk(table_id, &socket_id) {
        Ok(status) => status,
        Err(e) if e == "Table not found" => return err_resp(StatusCode::NOT_FOUND, &e),
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
    };

    (StatusCode::OK, Json(serde_json::json!({
        "status": result,
        "message": "Shuffle submitted"
    }))).into_response()
}

pub async fn join_game_and_shuffle(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("join_game_and_shuffle: {:?}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body: JoinAndShuffleRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id"),
    };
    


    if let Some(existing_sid) = state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        match state.socket_state.submit_shuffle_for_pk(table_id, &existing_sid) {
            Ok(_) => {},
            Err(e) if e == "Table not found" => return err_resp(StatusCode::NOT_FOUND, &e),
            Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
        }

        return (StatusCode::OK, Json(serde_json::json!({
            "player": {"id": body.pk_hex},
            "message": "Joined and shuffled successfully (existing player)"
        }))).into_response();
    }

    let socket_id = format!("http_{}", body.pk_hex);
    let player = Player {
        socket_id: socket_id.clone(),
        id: body.pk_hex.clone(),
        name: body.name.clone(),
        bankroll: 0,
        pk_hex: body.pk_hex.clone(),
    };

    if state.socket_state.add_player_to_table(table_id, player).is_err() {
        return err_resp(StatusCode::NOT_FOUND, "Table not found");
    }

    let shuffle_result = match state.socket_state.submit_shuffle_for_pk(table_id, &socket_id) {
        Ok(status) => status,
        Err(e) if e == "Table not found" => "no_table".to_string(),
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
    };

    (StatusCode::OK, Json(serde_json::json!({
        "player": {"id": body.pk_hex},
        "shuffle_status": shuffle_result,
        "message": "Joined and shuffled successfully"
    }))).into_response()
}

pub async fn player_action(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body: ActionRequestHttp = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id"),
    };

    let socket_id = match state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        Some(id) => id,
        None => return err_resp(StatusCode::NOT_FOUND, "Player not found"),
    };

    let sender = match state.socket_state.get_action_sender(table_id).await {
        Some(s) => s,
        None => return err_resp(StatusCode::NOT_FOUND, "Game loop not running"),
    };

    let action_request = crate::pokergame::table::ActionRequest {
        socket_id,
        action: body.action.clone(),
        amount: body.amount,
    };

    match sender.send(action_request).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "message": format!("Action {} submitted", body.action)
        }))).into_response(),
        Err(_) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send action"),
    }
}

pub async fn submit_reveal_token(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body: RevealTokenRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id"),
    };

    let socket_id = match state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        Some(id) => id,
        None => return err_resp(StatusCode::NOT_FOUND, "Player not found"),
    };

    let all_complete = match state.socket_state.mark_reveal_complete_for_pk(table_id, &socket_id) {
        Ok(result) => result,
        Err(e) => return err_resp(StatusCode::NOT_FOUND, &e),
    };

    (StatusCode::OK, Json(serde_json::json!({
        "message": format!("{} reveal tokens submitted", body.reveal_tokens.len()),
        "player_pk": body.pk_hex,
        "reveal_phase_complete": all_complete,
    }))).into_response()
}

pub async fn login(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request body"}]}))).into_response(),
    };
    let body: LoginRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid JSON"}]}))).into_response(),
    };
    
    let Some(user) = state.db.find_user_by_email(&body.email).await else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response();
    };

    match bcrypt::verify(&body.password, &user.password) {
        Ok(true) => match auth::create_token(&user.id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
            Ok(token) => (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response(),
        },
        _ => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response(),
    }
}

pub async fn register(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request body"}]}))).into_response(),
    };
    let body: RegisterRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid JSON"}]}))).into_response(),
    };

    if state.db.find_user_by_email(&body.email).await.is_some()
        || state.db.find_user_by_name(&body.name).await.is_some()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response();
    }

    let Ok(hashed) = bcrypt::hash(&body.password, 10) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response();
    };
    
    let client_player = ClientPlayer::new();
    let (sk_hex, pk_hex) = client_player.get_sk_and_pk_hex();
    println!("sk_hex: {}", sk_hex);
    let user = crate::models::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        email: body.email.clone(),
        password: hashed,
        chips_amount: state.config.initial_chips_amount,
        user_type: 0,
        created: chrono::Utc::now().to_rfc3339(),
        sk_hex,
        pk_hex,
    };

    let user_id = user.id.clone();
    if state.db.save_user(&user).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response();
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response(),
    }
}

pub async fn free_chips(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    let token = match get_token_from_headers(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response(),
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => match state.db.find_user_by_id(&claims.user.id).await {
            Some(user) if user.chips_amount < 1000 => {
                state.db.set_chips(&user.id, state.config.initial_chips_amount).await;
                match state.db.find_user_by_id(&user.id).await {
                    Some(updated) => (StatusCode::OK, Json(user_to_response(&updated))).into_response(),
                    None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
            Some(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request"}]}))).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        Err(_) => (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response(),
    }
}
