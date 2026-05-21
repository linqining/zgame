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
use crate::pokergame::game_state::{MaskAndShuffleRoundJson, PkProofJson, SubmitRevealTokenJson};
use crate::socket::SocketState;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::table::JoinResult;
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::crypto::EcPoint;
use poker_protocol::z_poker::convert::hex_to_ecpoint;
use group::{GroupEncoding, Group};
use sui_sdk::sui_crypto::SuiVerifier;

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
struct ShuffleRequest {
    pk_hex: String,
    mask_and_shuffle_round: MaskAndShuffleRoundJson,
}

#[derive(Deserialize)]
struct JoinAndShuffleRequest {
    pk_hex: String,
    name: String,
    pk_proof: PkProofJson,
    mask_and_shuffle_round: MaskAndShuffleRoundJson,
    seat_id: u32,
    amount: u64,
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

fn parse_game_id(game_id: &str) -> Option<u32> {
    game_id.parse::<u32>().ok()
}

fn parse_table_id(table_id: &str) -> Option<u32> {
    table_id.parse::<u32>().ok()
}

fn err_resp(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({"error": msg}))).into_response()
}

pub async fn get_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    tracing::debug!("[get_table] request received, table_id={}", table_id);
    let table_id = match parse_game_id(&table_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[get_table] invalid table_id: {}", table_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id");
        }
    };

    match state.socket_state.get_client_table(table_id) {
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
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
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
            tracing::debug!("[join_game] parsed body, pk_hex={}, name={}", v.pk_hex, v.name);
            v
        }
        Err(_) => {
            tracing::warn!("[join_game] failed to parse JSON body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[join_game] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    if state.socket_state.is_player_in_seat(&body.pk_hex) {
        tracing::warn!("[join_game] player already in seat, pk_hex={}", body.pk_hex);
        return err_resp(StatusCode::BAD_REQUEST, "Player already in game");
    }

    let player = match state.socket_state.find_player_by_pk(&body.pk_hex) {
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
                pk_hex: body.pk_hex.clone(),
                readable_hands: vec![],
            }
        }
    };

    if state.socket_state.add_player_to_table(table_id, player).is_err() {
        tracing::warn!("[join_game] table not found, table_id={}", table_id);
        return err_resp(StatusCode::NOT_FOUND, "Table not found");
    }

    tracing::debug!("[join_game] player joined successfully, pk_hex={}, table_id={}", body.pk_hex, table_id);
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
    tracing::debug!("[shuffle] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[shuffle] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<ShuffleRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[shuffle] parsed body, pk_hex={}", v.pk_hex);
            v
        }
        Err(e) => {
            tracing::warn!("[shuffle] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e));
        }
    };

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[shuffle] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    match state.socket_state.submit_verified_shuffle_with_round(table_id, &body.pk_hex, body.mask_and_shuffle_round) {
        Ok(_) => {
            tracing::debug!("[shuffle] shuffle submitted and verified, pk_hex={}, table_id={}", body.pk_hex, table_id);
            (StatusCode::OK, Json(serde_json::json!({
                "message": "Shuffle submitted and verified"
            }))).into_response()
        }
        Err(e) if e.as_str() == "Table not found" => {
            tracing::warn!("[shuffle] table not found, table_id={}", table_id);
            err_resp(StatusCode::NOT_FOUND, &e)
        }
        Err(e) => {
            tracing::warn!("[shuffle] shuffle verification failed, pk_hex={}, table_id={}, error={}", body.pk_hex, table_id, e);
            err_resp(StatusCode::BAD_REQUEST, &e)
        }
    }
}

pub async fn join_game_and_shuffle(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("[join_game_and_shuffle] request received, table_id={}", table_id);
    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[join_game_and_shuffle] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };

    let body = match serde_json::from_slice::<JoinAndShuffleRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[join_game_and_shuffle] parsed body, pk_hex={}, name={}", v.pk_hex, v.name);
            v
        }
        Err(e) => {
            tracing::warn!("[join_game_and_shuffle] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e));
        }
    };
    tracing::debug!("[join_game_and_shuffle] parsed body: {:?}", body.pk_proof);

    let table_id = match parse_table_id(&table_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[join_game_and_shuffle] invalid table_id: {}", table_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id");
        }
    };

    let player_pk = match hex::decode(&body.pk_hex)
        .ok()
        .and_then(|bytes| EcPoint::from_bytes(bytes.as_slice().into()).into_option())
    {
        Some(pk) => {
            tracing::debug!("[join_game_and_shuffle] pk_hex decoded to EcPoint successfully");
            pk
        }
        None => {
            tracing::warn!("[join_game_and_shuffle] invalid pk_hex, cannot decode to EcPoint: {}", body.pk_hex);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid pk_hex");
        }
    };

    let player_id = match state.db.find_user_by_pk_hex(&body.pk_hex).await {
        Some(user) => {
            tracing::debug!("[join_game_and_shuffle] found existing user by pk_hex, user_id={}", user.id);
            user.id
        }
        None => {
            let id = format!("wallet:{}", body.pk_hex);
            tracing::debug!("[join_game_and_shuffle] no user found for pk_hex, using generated id={}", id);
            id
        }
    };

    let player = match state.socket_state.find_player_by_pk(&body.pk_hex) {
        Some(p) => {
            tracing::debug!("[join_game_and_shuffle] found existing player by pk_hex, socket_id={}", p.socket_id);
            p
        }
        None => {
            tracing::debug!("[join_game_and_shuffle] no existing player found for pk_hex, creating http player", );
            Player {
                socket_id: format!("http_{}", body.pk_hex),
                id: player_id,
                name: body.name.clone(),
                bankroll: 0,
                pk_hex: body.pk_hex.clone(),
                readable_hands: vec![],
            }
        }
    };

    match state.socket_state.join_player_and_shuffle(table_id, player, player_pk, body.pk_proof, body.mask_and_shuffle_round, body.seat_id, body.amount) {
        Ok((should_start_game_loop, join_result)) => {
            match join_result {
                JoinResult::JoinedAndShuffled => {
                    tracing::debug!("[join_game_and_shuffle] joined and shuffled successfully, pk_hex={}, table_id={}, should_start_game_loop={}", body.pk_hex, table_id, should_start_game_loop);
                    if should_start_game_loop {
                        tracing::info!("[join_game_and_shuffle] all players shuffled, starting game loop for table_id={}", table_id);
                        state.socket_state.start_game_loop_sync(state.socket_state.clone(), table_id);
                    }
                    (StatusCode::OK, Json(serde_json::json!({
                        "player": {"id": body.pk_hex},
                        "message": "Joined and shuffled successfully",
                        "status": "joinedAndShuffled"
                    }))).into_response()
                }
                JoinResult::JoinedWaiting => {
                    tracing::debug!("[join_game_and_shuffle] joined as waiting, pk_hex={}, table_id={}", body.pk_hex, table_id);
                    (StatusCode::OK, Json(serde_json::json!({
                        "player": {"id": body.pk_hex},
                        "message": "Joined, waiting for next hand",
                        "status": "joinedWaiting"
                    }))).into_response()
                }
            }
        }
        Err(e) if e.as_str() == "Table not found" => {
            tracing::warn!("[join_game_and_shuffle] table not found, table_id={}", table_id);
            err_resp(StatusCode::NOT_FOUND, &e)
        }
        Err(e) => {
            tracing::warn!("[join_game_and_shuffle] join and shuffle failed, pk_hex={}, table_id={}, error={}", body.pk_hex, table_id, e);
            err_resp(StatusCode::BAD_REQUEST, &e)
        }
    }
}

pub async fn player_action(
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
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

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[player_action] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    let socket_id = match state.socket_state.find_socket_id_by_pk(&body.pk_hex) {
        Some(id) => {
            tracing::debug!("[player_action] found socket_id={} for pk_hex={}", id, body.pk_hex);
            id
        }
        None => {
            tracing::warn!("[player_action] player not found, pk_hex={}", body.pk_hex);
            return err_resp(StatusCode::NOT_FOUND, "Player not found");
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
        socket_id,
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
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
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

    let table_id = match parse_game_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[submit_reveal_token] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    if body.pk_hex == "03b5ceedfbd1044748e8d77d9f142f4af6a5554b6d2ce4a4235367fb93ba97298e" {
        tracing::warn!("[submit_reveal_token] reject token");
        return err_resp(StatusCode::BAD_REQUEST, "Dumpy reject token");
    }

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

    let reveal_phase = state.socket_state.get_reveal_phase_for_table(table_id).unwrap_or_default();

    if let Err(e) = state.socket_state.submit_reveal_tokens_for_pk(table_id, &body.pk_hex, tokens) {
        tracing::warn!("[submit_reveal_token] submit failed, table_id={}, pk_hex={}, error={}", table_id, body.pk_hex, e);
        return err_resp(StatusCode::BAD_REQUEST, &e);
    }

    // todo 发送完成通知
    let all_complete = match state.socket_state.mark_reveal_complete_for_pk(table_id, &body.pk_hex) {
        Ok(result) => {
            tracing::debug!("[submit_reveal_token] reveal marked, table_id={}, pk_hex={}, all_complete={}", table_id, body.pk_hex, result);
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
                state.socket_state.broadcast_hand_reveal_result(table_id);
            }
            RevealPhase::ShowdownReveal => {
                state.socket_state.broadcast_showdown_result(table_id).await;
            }
            RevealPhase::CommunityReveal => {
                state.socket_state.broadcast_community_cards(table_id);
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

fn verify_sui_wallet_signature(
    message: &str,
    signature: &sui_sdk_types::UserSignature,
    expected_address: &str,
) -> Result<(String, String), String> {
    tracing::debug!("[verify_sui_wallet_signature] verifying signature, expected_address={}", expected_address);
    let personal_msg = sui_sdk_types::PersonalMessage(message.as_bytes().into());
    let verifier = sui_sdk::sui_crypto::secp256k1::Secp256k1Verifier::new();
    verifier.verify_personal_message(&personal_msg, signature)
        .map_err(|e| {
            tracing::warn!("[verify_sui_wallet_signature] signature verification failed: {}", e);
            format!("Signature verification failed: {}", e)
        })?;

    let pk_bytes = match signature {
        sui_sdk_types::UserSignature::Simple(sui_sdk_types::SimpleSignature::Secp256k1 { public_key, .. }) => {
            tracing::debug!("[verify_sui_wallet_signature] secp256k1 signature detected");
            public_key.as_bytes()
        }
        _ => {
            tracing::warn!("[verify_sui_wallet_signature] unsupported signature scheme");
            return Err("Unsupported signature scheme".to_string());
        }
    };

    let mut hasher = blake2b_simd::Params::new().hash_length(32).to_state();
    hasher.update(&[0x01]);
    hasher.update(pk_bytes);
    let hash = hasher.finalize();
    let derived_address = format!("0x{}", hex::encode(hash.as_bytes()));

    if derived_address != expected_address {
        tracing::warn!("[verify_sui_wallet_signature] address mismatch: derived={} expected={}", derived_address, expected_address);
        return Err(format!(
            "Address mismatch: derived {} but expected {}",
            derived_address, expected_address
        ));
    }

    let ecpoint = poker_protocol::crypto::EcPoint::from_bytes(pk_bytes.into());
    let pk_hex = match Option::<poker_protocol::crypto::EcPoint>::from(ecpoint) {
        Some(point) => {
            let hex = hex::encode(point.to_affine().to_bytes());
            tracing::debug!("[verify_sui_wallet_signature] derived pk_hex={}", hex);
            hex
        }
        None => {
            tracing::warn!("[verify_sui_wallet_signature] invalid EC point from public key");
            return Err("Invalid EC point from public key".to_string());
        }
    };

    tracing::debug!("[verify_sui_wallet_signature] verification successful, address={}, pk_hex={}", derived_address, pk_hex);
    Ok((derived_address, pk_hex))
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

    let (address, pk_hex) = match verify_sui_wallet_signature(&body.message, &body.signature, &body.address) {
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
            password: String::new(),
            chips_amount: state.config.initial_chips_amount,
            user_type: 1,
            created: chrono::Utc::now().to_rfc3339(),
            // sk_hex: String::new(),
            pk_hex: body.message.clone(),
        };
        if state.db.save_user(&user).await.is_err() {
            tracing::error!("[wallet_login] failed to save wallet user, user_id={}", user_id);
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save wallet user");
        }
        tracing::debug!("[wallet_login] wallet user saved, user_id={}, pk_hex={}", user_id, body.message.clone());
    } else {
        if state.db.update_user_pk(&user_id, &body.message.clone()).await {
            tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, body.message.clone());
        } else {
            tracing::warn!("[wallet_login] failed to update wallet user pk, user_id={}", user_id);
        }
        tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, body.message.clone());
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            tracing::debug!("[wallet_login] token created, user_id={}, address={}", user_id, address);
            (StatusCode::OK, Json(serde_json::json!({
                "token": token,
                "address": address,
                "pk_hex": body.message.clone(),
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[wallet_login] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
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
    let (sk_hex, pk_hex) = client_player.get_sk_and_pk_hex();
    tracing::debug!("[register] generated keys, pk_hex={}", pk_hex);
    let user = crate::models::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        email: body.email.clone(),
        password: hashed,
        chips_amount: state.config.initial_chips_amount,
        user_type: 0,
        created: chrono::Utc::now().to_rfc3339(),
        // sk_hex,
        pk_hex,
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
                    tracing::debug!("[free_chips] user eligible, user_id={}, current_chips={}", user.id, user.chips_amount);
                    state.db.set_chips(&user.id, state.config.initial_chips_amount).await;
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
