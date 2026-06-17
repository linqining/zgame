use axum::{
    body::Body,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode, Request},
    response::IntoResponse,
    response::Response,
    Json,
};
use base64::Engine;
use serde::Deserialize;
use std::sync::Arc;

use crate::auth;
use crate::config::Config;
use crate::models::{Database, UserResponse};
use crate::pokergame::player::{Player, WalletAddress};
use crate::pokergame::game_state::SubmitRevealTokenJson;
use crate::relayer::RelayerState;
use crate::socket::SocketState;
use crate::pokergame::game_state::RevealPhase;

use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::convert::hex_to_ecpoint;

use crate::wallet_auth;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub socket_state: Arc<SocketState>,
    pub relayer_state: Arc<RelayerState>,
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

pub fn get_token_from_headers(headers: &HeaderMap) -> Option<String> {
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
    tracing::debug!("[get_current_user] request received");
    let token = match get_token_from_headers(&headers) {
        Some(t) => {
            tracing::debug!("[get_current_user] token found in headers");
            t
        }
        None => {
            tracing::warn!("[get_current_user] no x-auth-token header found");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response();
        }
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => {
            tracing::debug!("[get_current_user] token verified, user_id={}", claims.user.id);
            match state.db.find_user_by_id(&claims.user.id).await {
                Some(user) => {
                    tracing::debug!("[get_current_user] user found, id={}, name={}", user.id, user.name);
                    (StatusCode::OK, Json(user_to_response(&user))).into_response()
                }
                None => {
                    tracing::warn!("[get_current_user] user not found in db, id={}", claims.user.id);
                    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "User not found"}))).into_response()
                }
            }
        }
        Err(_) => {
            tracing::warn!("[get_current_user] token verification failed");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct JoinGameRequest {
    name: String,
    pk_hex: String,
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
    reveal_tokens: Vec<SubmitRevealTokenJson>,
}

fn parse_id(id: &str) -> Option<u32> {
    id.parse::<u32>().ok()
}

pub fn err_resp(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({"error": msg}))).into_response()
}

fn verify_auth(headers: &HeaderMap, jwt_secret: &str) -> Result<crate::auth::Claims, Response> {
    let token = match get_token_from_headers(headers) {
        Some(t) => t,
        None => {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response());
        }
    };
    match auth::verify_token(&token, jwt_secret) {
        Ok(claims) => Ok(claims),
        Err(_) => Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()),
    }
}

pub async fn get_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    tracing::debug!("[get_table] request received, table_id={}", table_id);
    let table_id = match parse_id(&table_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[get_table] invalid table_id: {}", table_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id");
        }
    };

    match state.socket_state.get_client_table(table_id).await {
        Some(client_table) => {
            tracing::debug!("[get_table] table found, table_id={}", table_id);
            (StatusCode::OK, Json(serde_json::to_value(client_table).unwrap())).into_response()
        }
        None => {
            tracing::warn!("[get_table] table not found, table_id={}", table_id);
            err_resp(StatusCode::NOT_FOUND, "Table not found")
        }
    }
}

pub async fn join_game(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    if let Err(resp) = verify_auth(&headers, &state.config.jwt_secret) {
        return resp;
    }
    tracing::debug!("[join_game] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[join_game] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<JoinGameRequest>(&body) {
        Ok(v) => {
            tracing::info!("[join_game] parsed body, pk_hex={}, name={}", v.pk_hex, v.name);
            v
        }
        Err(_) => {
            tracing::warn!("[join_game] failed to parse JSON body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[join_game] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    let pk_hex = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());

    if state.socket_state.is_player_in_seat(&pk_hex).await {
        tracing::warn!("[join_game] player already in seat, pk_hex={}", pk_hex);
        return err_resp(StatusCode::BAD_REQUEST, "Player already in game");
    }

    let player = match state.socket_state.find_player_by_pk(table_id, &pk_hex).await {
        Some(p) => {
            tracing::debug!("[join_game] found existing player by pk_hex, socket_id={}", p.socket_id);
            p
        }
        None => {
            tracing::debug!("[join_game] no existing player found for pk_hex, creating http player");
            Player {
                socket_id: format!("http_{}", body.pk_hex),
                id: body.pk_hex.clone(),
                name: body.name.clone(),
                bankroll: 0,
                wallet_address: WalletAddress::new(""),
            }
        }
    };

    if state.socket_state.add_player_to_table(table_id, player, &pk_hex).await.is_err() {
        tracing::warn!("[join_game] table not found, table_id={}", table_id);
        return err_resp(StatusCode::NOT_FOUND, "Table not found");
    }

    tracing::debug!("[join_game] player joined successfully, pk_hex={}, table_id={}", body.pk_hex, table_id);
    (StatusCode::CREATED, Json(serde_json::json!({
        "player": {"id": body.pk_hex},
        "message": "Joined game successfully"
    }))).into_response()
}



pub async fn player_action(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::debug!("[player_action] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[player_action] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<ActionRequestHttp>(&body) {
        Ok(v) => {
            tracing::debug!("[player_action] parsed body, pk_hex={}, action={}, amount={:?}", v.pk_hex, v.action, v.amount);
            v
        }
        Err(_) => {
            tracing::warn!("[player_action] failed to parse JSON body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[player_action] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    // Verify that the authenticated user owns the pk_hex
    let _user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[player_action] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };


    let sender = match state.socket_state.get_action_sender(table_id).await {
        Some(s) => {
            tracing::debug!("[player_action] got action sender for table_id={}", table_id);
            s
        }
        None => {
            tracing::warn!("[player_action] game loop not running, table_id={}", table_id);
            return err_resp(StatusCode::NOT_FOUND, "Game loop not running");
        }
    };

    let action_request = crate::pokergame::table::ActionRequest {
        pk_hex: crate::pokergame::player::GamePkHex::new(body.pk_hex.clone()),
        action: body.action.clone(),
        amount: body.amount,
    };

    match sender.send(action_request).await {
        Ok(()) => {
            tracing::debug!("[player_action] action sent successfully, pk_hex={}, action={}, table_id={}", body.pk_hex, body.action, table_id);
            (StatusCode::OK, Json(serde_json::json!({
                "message": format!("Action {} submitted", body.action)
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[player_action] failed to send action, pk_hex={}, action={}, table_id={}", body.pk_hex, body.action, table_id);
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send action")
        }
    }
}

pub async fn submit_reveal_token(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    if let Err(resp) = verify_auth(&headers, &state.config.jwt_secret) {
        return resp;
    }
    tracing::debug!("[submit_reveal_token] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[submit_reveal_token] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<RevealTokenRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[submit_reveal_token] parsed body, pk_hex={}, reveal_tokens_count={}", v.pk_hex, v.reveal_tokens.len());
            v
        }
        Err(e) => {
            tracing::warn!("[submit_reveal_token] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[submit_reveal_token] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    let player_pk = match hex_to_ecpoint(&body.pk_hex) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("[submit_reveal_token] invalid player_pk: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid player_pk: {}", e));
        }
    };

    let tokens_len = body.reveal_tokens.len();
    if tokens_len == 0 {
        tracing::warn!("[submit_reveal_token] no reveal tokens provided");
        return err_resp(StatusCode::BAD_REQUEST, "No reveal tokens provided");
    }

    let tokens: Result<Vec<_>, String> = body.reveal_tokens.iter()
        .enumerate()
        .map(|(idx, item)| {
            let encrypted_card = item.encrypted_card.to_ciphertext()
                .map_err(|e| format!("Token[{}]: Invalid encrypted_card: {}", idx, e))?;
            let reveal_token = hex_to_ecpoint(&item.reveal_token_hex)
                .map_err(|e| format!("Token[{}]: Invalid reveal_token_hex: {}", idx, e))?;
            let proof = item.reveal_token_proof.to_proof()
                .map_err(|e| format!("Token[{}]: Invalid reveal_token_proof: {}", idx, e))?;

            Ok(poker_protocol::z_poker::protocol::RevealToken {
                user_public_key: player_pk,
                encrypted_card,
                proof,
                reveal_token,
            })
        })
        .collect();

    let tokens = match tokens {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("[submit_reveal_token] token parse error: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &e);
        }
    };

    let reveal_phase = state.socket_state.get_reveal_phase_for_table(table_id).await.unwrap_or_default();

    let pk_hex = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());

    if let Err(e) = state.socket_state.submit_reveal_tokens_for_pk(table_id, &pk_hex, tokens).await {
        tracing::warn!("[submit_reveal_token] submit failed, table_id={}, pk_hex={}, error={}", table_id, pk_hex, e);
        return err_resp(StatusCode::BAD_REQUEST, &e);
    }

    // todo 发送完成通知
    let all_complete = match state.socket_state.mark_reveal_complete_for_pk(table_id, &pk_hex).await {
        Ok(result) => {
            tracing::info!("[submit_reveal_token] reveal marked, table_id={}, pk_hex={}, all_complete={}", table_id, body.pk_hex, result);
            result
        }
        Err(e) => {
            tracing::warn!("[submit_reveal_token] mark reveal failed, table_id={}, pk_hex={}, error={}", table_id, body.pk_hex, e);
            return err_resp(StatusCode::NOT_FOUND, &e);
        }
    };

    if all_complete {
        match reveal_phase {
            RevealPhase::HandReveal  => {
                state.socket_state.broadcast_hand_reveal_result(table_id).await;
            }
            RevealPhase::ShowdownReveal => {
                state.socket_state.broadcast_showdown_result(table_id).await;
            }
            RevealPhase::CommunityReveal => {
                state.socket_state.broadcast_community_cards(table_id).await;
            }
            RevealPhase::RedealReveal => {
                state.socket_state.broadcast_redeal_result(table_id).await;
            }
        }
    }


    tracing::debug!("[submit_reveal_token] success, pk_hex={}, reveal_tokens_count={}, all_complete={}", body.pk_hex, tokens_len, all_complete);
    (StatusCode::OK, Json(serde_json::json!({
        "message": format!("{} reveal tokens submitted", tokens_len),
        "player_pk": body.pk_hex,
        "phase": format!("{:?}", reveal_phase),
        "reveal_phase_complete": all_complete,
    }))).into_response()
}

pub async fn login(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("[login] request received");
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[login] failed to read request body");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request body"}]}))).into_response();
        }
    };
    let body = match serde_json::from_slice::<LoginRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[login] parsed body, email={}", v.email);
            v
        }
        Err(_) => {
            tracing::warn!("[login] failed to parse JSON body");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid JSON"}]}))).into_response();
        }
    };
    
    let Some(user) = state.db.find_user_by_email(&body.email).await else {
        tracing::warn!("[login] user not found, email={}", body.email);
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response();
    };

    match bcrypt::verify(&body.password, &user.password) {
        Ok(true) => {
            tracing::debug!("[login] password verified, user_id={}", user.id);
            match auth::create_token(&user.id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
                Ok(token) => {
                    tracing::debug!("[login] token created, user_id={}", user.id);
                    (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response()
                }
                Err(_) => {
                    tracing::error!("[login] failed to create token, user_id={}", user.id);
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
                }
            }
        }
        _ => {
            tracing::warn!("[login] password verification failed, email={}", body.email);
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response()
        }
    }
}

#[derive(Deserialize, Debug)]
struct WalletLoginRequest {
    address: String,
    signature: sui_sdk_types::UserSignature,
    message: String,
}

pub async fn wallet_login(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("[wallet_login] request received");
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[wallet_login] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<WalletLoginRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[wallet_login] parsed body, address={}", v.address);
            v
        }
        Err(e) => {
            tracing::warn!("[wallet_login] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e));
        }
    };

    let (address, pk_hex) = match wallet_auth::verify_sui_wallet_signature(&body.message, &body.signature, &body.address).await {
        Ok(result) => {
            tracing::debug!("[wallet_login] wallet signature verified, address={}", result.0);
            result
        }
        Err(e) => {
            tracing::warn!("[wallet_login] wallet signature verification failed, address={}, error={}", body.address, e);
            return err_resp(StatusCode::UNAUTHORIZED, &e);
        }
    };

    let user_id = format!("wallet:{}", address);

    if state.db.find_user_by_id(&user_id).await.is_none() {
        tracing::debug!("[wallet_login] new wallet user, creating user_id={}, address={}", user_id, address);
        let user = crate::models::User {
            id: user_id.clone(),
            name: address.clone(),
            email: format!("{}@wallet", address),
            password: bcrypt::hash(&uuid::Uuid::new_v4().to_string(), 10).unwrap_or_default(),
            chips_amount: state.config.initial_chips_amount,
            user_type: 1,
            created: chrono::Utc::now().to_rfc3339(),
            address: address.clone(),
            last_free_chips_at: None,
        };
        if let Err(e) = state.db.save_user(&user).await {
            tracing::error!("[wallet_login] failed to save wallet user, user_id={}, error={}", user_id, e);
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save wallet user: {}", e));
        }
        tracing::debug!("[wallet_login] wallet user saved, user_id={}, pk_hex={}", user_id, pk_hex.clone());
    } else {
        if state.db.update_address(&user_id, &address).await {
            tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, pk_hex.clone());
        } else {
            tracing::warn!("[wallet_login] failed to update wallet user pk, user_id={}", user_id);
        }
        tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, pk_hex.clone());
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            tracing::debug!("[wallet_login] token created, user_id={}, address={}", user_id, address);
            (StatusCode::OK, Json(serde_json::json!({
                "token": token,
                "address": address,
                "pk_hex": pk_hex.clone(),
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[wallet_login] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
        }
    }
}

pub async fn wallet_logout(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    tracing::debug!("[wallet_logout] request received");

    let token = match get_token_from_headers(&headers) {
        Some(t) => t,
        None => {
            tracing::warn!("[wallet_logout] no x-auth-token header found");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response();
        }
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => {
            tracing::debug!("[wallet_logout] token verified, user_id={}", claims.user.id);
            if !claims.user.id.starts_with("wallet:") {
                tracing::warn!("[wallet_logout] not a wallet user, user_id={}", claims.user.id);
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"msg": "Not a wallet user"}))).into_response();
            }

            match state.db.find_user_by_id(&claims.user.id).await {
                Some(_) => {
                    tracing::debug!("[wallet_logout] wallet logout successful, user_id={}", claims.user.id);
                    (StatusCode::OK, Json(serde_json::json!({"msg": "Wallet logout successful"}))).into_response()
                }
                None => {
                    tracing::warn!("[wallet_logout] user not found, user_id={}", claims.user.id);
                    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "User not found"}))).into_response()
                }
            }
        }
        Err(_) => {
            tracing::warn!("[wallet_logout] invalid token");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Invalid token"}))).into_response()
        }
    }
}

pub async fn register(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("[register] request received");
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[register] failed to read request body");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request body"}]}))).into_response();
        }
    };
    let body = match serde_json::from_slice::<RegisterRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[register] parsed body, name={}, email={}", v.name, v.email);
            v
        }
        Err(_) => {
            tracing::warn!("[register] failed to parse JSON body");
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid JSON"}]}))).into_response();
        }
    };

    if state.db.find_user_by_email(&body.email).await.is_some()
        || state.db.find_user_by_name(&body.name).await.is_some()
    {
        tracing::warn!("[register] email or name already exists, name={}, email={}", body.name, body.email);
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid credentials"}]}))).into_response();
    }

    let Ok(hashed) = bcrypt::hash(&body.password, 10) else {
        tracing::error!("[register] failed to hash password");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response();
    };
    
    let client_player = ClientPlayer::new();
    let (_sk_hex, pk_hex) = client_player.get_sk_and_pk_hex();
    tracing::debug!("[register] generated keys, pk_hex={}", pk_hex);
    let user = crate::models::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        email: body.email.clone(),
        password: hashed,
        chips_amount: state.config.initial_chips_amount,
        user_type: 0,
        created: chrono::Utc::now().to_rfc3339(),
        address: pk_hex,
        last_free_chips_at: None,
    };

    let user_id = user.id.clone();
    if state.db.save_user(&user).await.is_err() {
        tracing::error!("[register] failed to save user, user_id={}", user_id);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response();
    }
    tracing::debug!("[register] user saved, user_id={}", user_id);

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            tracing::debug!("[register] token created, user_id={}", user_id);
            (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response()
        }
        Err(_) => {
            tracing::error!("[register] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
        }
    }
}

pub async fn free_chips(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    tracing::debug!("[free_chips] request received");
    let token = match get_token_from_headers(&headers) {
        Some(t) => {
            tracing::debug!("[free_chips] token found in headers");
            t
        }
        None => {
            tracing::warn!("[free_chips] no x-auth-token header found");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response();
        }
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => {
            tracing::debug!("[free_chips] token verified, user_id={}", claims.user.id);
            match state.db.find_user_by_id(&claims.user.id).await {
                Some(user) if user.chips_amount < 1000 => {
                    // Check cooldown: 1 hour between free chips
                    if let Some(last_at) = &user.last_free_chips_at {
                        if let Ok(last_time) = last_at.parse::<chrono::DateTime<chrono::Utc>>() {
                            let elapsed = chrono::Utc::now() - last_time;
                            if elapsed.num_seconds() < 3600 {
                                tracing::warn!("[free_chips] cooldown active, user_id={}, last_at={}", user.id, last_at);
                                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Please wait before claiming free chips again"}]}))).into_response();
                            }
                        }
                    }
                    tracing::debug!("[free_chips] user eligible, user_id={}, current_chips={}", user.id, user.chips_amount);
                    state.db.set_chips_with_cooldown(&user.id, state.config.initial_chips_amount).await;
                    match state.db.find_user_by_id(&user.id).await {
                        Some(updated) => {
                            tracing::debug!("[free_chips] chips updated, user_id={}, new_chips={}", updated.id, updated.chips_amount);
                            (StatusCode::OK, Json(user_to_response(&updated))).into_response()
                        }
                        None => {
                            tracing::error!("[free_chips] failed to reload user after chips update, user_id={}", user.id);
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                }
                Some(user) => {
                    tracing::warn!("[free_chips] user has enough chips, user_id={}, chips={}", user.id, user.chips_amount);
                    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"errors": [{"msg": "Invalid request"}]}))).into_response()
                }
                None => {
                    tracing::warn!("[free_chips] user not found after token verification, user_id={}", claims.user.id);
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        }
        Err(_) => {
            tracing::warn!("[free_chips] token verification failed");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Sui table 缓存查询 / 刷新
// ---------------------------------------------------------------------------

/// GET /api/sui/tables — 返回所有缓存的 TableSummary 列表
pub async fn list_sui_tables(Extension(state): Extension<Arc<AppState>>) -> Response {
    let tables = state.relayer_state.list();
    (StatusCode::OK, Json(tables)).into_response()
}

/// GET /api/sui/tables/:table_id — 获取单个缓存的 TableSummary
pub async fn get_sui_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    match state.relayer_state.get(&table_id) {
        Some(summary) => (StatusCode::OK, Json(summary)).into_response(),
        None => err_resp(StatusCode::NOT_FOUND, &format!("Table {} not cached", table_id)),
    }
}

/// POST /api/sui/tables/:table_id/refresh — 从链上重新拉取 TableSummary 并更新缓存
pub async fn refresh_sui_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    match crate::sui_query::fetch_table_summary(&state.config.fullnode_url, &table_id).await {
        Ok(summary) => {
            state.relayer_state.insert(table_id, summary.clone());
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(e) => err_resp(StatusCode::BAD_GATEWAY, &format!("Failed to fetch table: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Sui action PTB 构建
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct BuildActionRequest {
    action: String,
    table_id: String,
    seat_index: u64,
    // raise 特有
    total_bet: Option<u64>,
    // join_and_shuffle 特有
    buy_in: Option<u64>,
    pk: Option<String>,
    pk_ownership_proof: Option<String>,
    output_cards: Option<String>,
    remask_proof_bytes: Option<String>,
    shuffle_proof_bytes: Option<String>,
}

/// 解码 hex 或 base64 字符串为 Vec<u8>。
/// 优先尝试 hex（支持可选 `0x` 前缀），失败后回退到 base64。
fn decode_hex_or_base64(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if let Ok(bytes) = hex::decode(hex_str) {
        return Ok(bytes);
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| format!("Failed to decode as hex or base64: {}", e))
}

/// POST /api/sui/action/build — 根据请求体构建 PTB 并返回 base64 编码的 TransactionKind
pub async fn build_action_ptb(
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    let body = match axum::body::to_bytes(req, 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let req: BuildActionRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    let package_id = &state.config.sui_package_id;
    let table_id = &req.table_id;
    let seat_index = req.seat_index;

    let ptb_result: Result<_, String> = match req.action.as_str() {
        "fold" => Ok(crate::relayer::ptb::build_fold_ptb(package_id, table_id, seat_index)),
        "check" => Ok(crate::relayer::ptb::build_check_ptb(package_id, table_id, seat_index)),
        "call" => Ok(crate::relayer::ptb::build_call_ptb(package_id, table_id, seat_index)),
        "raise" => {
            let total_bet = match req.total_bet {
                Some(v) => v,
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing total_bet for raise action"),
            };
            Ok(crate::relayer::ptb::build_raise_ptb(package_id, table_id, seat_index, total_bet))
        }
        "join_and_shuffle" => {
            let buy_in = match req.buy_in {
                Some(v) => v,
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing buy_in for join_and_shuffle action"),
            };
            let pk = match req.pk.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid pk: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing pk for join_and_shuffle action"),
            };
            let pk_ownership_proof = match req.pk_ownership_proof.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid pk_ownership_proof: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing pk_ownership_proof for join_and_shuffle action"),
            };
            let output_cards = match req.output_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid output_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing output_cards for join_and_shuffle action"),
            };
            let remask_proof_bytes = match req.remask_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid remask_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing remask_proof_bytes for join_and_shuffle action"),
            };
            let shuffle_proof_bytes = match req.shuffle_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid shuffle_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing shuffle_proof_bytes for join_and_shuffle action"),
            };
            Ok(crate::relayer::ptb::build_join_and_shuffle_ptb(
                package_id,
                table_id,
                seat_index,
                buy_in,
                pk,
                pk_ownership_proof,
                output_cards,
                remask_proof_bytes,
                shuffle_proof_bytes,
            ))
        }
        other => {
            return err_resp(StatusCode::BAD_REQUEST, &format!("Unknown action: {}", other));
        }
    };

    let ptb = match ptb_result {
        Ok(p) => p,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
    };

    match crate::relayer::ptb::serialize_tx_kind(ptb) {
        Ok(tx_kind) => (StatusCode::OK, Json(serde_json::json!({ "tx_kind": tx_kind }))).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to serialize tx_kind: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// 手动触发 tick
// ---------------------------------------------------------------------------

/// POST /api/sui/tables/:table_id/tick — 手动提交 tick 交易
pub async fn manual_tick(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    match crate::relayer::submit::submit_tick_tx(&state.config, &table_id).await {
        Ok(digest) => (StatusCode::OK, Json(serde_json::json!({ "digest": digest }))).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Tick failed: {}", e)),
    }
}
