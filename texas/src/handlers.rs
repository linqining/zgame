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
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

use crate::auth;
use crate::config::Config;
use crate::models::{chips_from_mist, Database, UserResponse};
use crate::pokergame::player::{Player, WalletAddress};
use crate::pokergame::game_state::SubmitRevealTokenJson;
use crate::socket::SocketState;
use crate::socket::broadcast::CryptoEventType;
use crate::pokergame::game_state::RevealPhase;

use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::convert::hex_to_ecpoint;

use crate::wallet_auth;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub socket_state: Arc<SocketState>,
    /// C2 去重：已处理的玩家行动事件去重缓存。
    /// key 为 `(table_id, seat_index, action, round_state)`。
    pub processed_actions: Arc<std::sync::RwLock<HashSet<String>>>,
    /// C3 修复：已处理的 webhook 事件 ID 集合，用于重放保护。
    /// 使用 tokio RwLock 因为 webhook handler 是 async 且需要持有锁跨越 await。
    pub processed_webhook_ids: Arc<TokioRwLock<HashSet<String>>>,
    /// Task 10: 玩家行动事件重试队列。
    /// 当行动事件因 `summary=None` 或 game_loop 通道关闭而无法立即处理时，
    /// 推入此队列由后台任务定期重试。使用 std::sync::Mutex 因为锁内操作很短
    /// （仅 push/pop），实际的 async 工作在释放锁后执行。
    pub action_retry_queue: Arc<std::sync::Mutex<Vec<crate::relayer::PendingAction>>>,
}

/// processed_webhook_ids 的最大容量，超过后清空重建。
const MAX_PROCESSED_WEBHOOK_IDS: usize = 10000;

/// processed_actions 的最大容量，超过后清空重建。
const MAX_PROCESSED_ACTIONS: usize = 10000;

impl AppState {
    /// C2 修复：检查并标记玩家行动事件是否已处理。
    /// 返回 `true` 表示首次处理（已写入缓存），`false` 表示重复事件（应跳过）。
    pub fn check_and_mark_action(
        &self,
        table_id: &str,
        seat_index: u64,
        action: &str,
        round_state: u8,
    ) -> bool {
        let key = format!("{}_{}_{}_{}", table_id, seat_index, action, round_state);
        let mut processed = self
            .processed_actions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if processed.contains(&key) {
            return false;
        }
        // 容量控制：超过上限时清空（简单策略，避免无界增长）
        if processed.len() >= MAX_PROCESSED_ACTIONS {
            tracing::warn!("dedup cache overflow, clearing all entries");
            processed.clear();
        }
        processed.insert(key);
        true
    }

    /// Task 16: 全事件去重 - 对所有 SuiChainEvent 变体进行去重。
    ///
    /// 与 `check_and_mark_action` 不同，本方法对所有事件类型（不仅是行动事件）
    /// 进行去重。key 由 `build_event_dedup_key` 生成，带 `evt:` 前缀以与
    /// 行动事件的 key 区分。返回 `true` 表示首次处理，`false` 表示重复事件。
    pub fn check_and_mark_event(&self, event: &crate::sui_events::SuiChainEvent) -> bool {
        let key = crate::relayer::build_event_dedup_key(event);
        let mut processed = self
            .processed_actions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if processed.contains(&key) {
            return false;
        }
        if processed.len() >= MAX_PROCESSED_ACTIONS {
            tracing::warn!("dedup cache overflow, clearing all entries");
            processed.clear();
        }
        processed.insert(key);
        true
    }
}

pub fn get_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-auth-token")
        .and_then(|t| t.to_str().ok())
        .map(|s| s.to_string())
}

fn user_to_response(user: &crate::models::User, sui_balance_mist: u64) -> serde_json::Value {
    let chips_amount = chips_from_mist(sui_balance_mist) - user.locked_chips;
    let resp = UserResponse {
        id: user.id.clone(),
        name: user.name.clone(),
        address: user.address.clone(),
        chips_amount,
        sui_balance: sui_balance_mist,
        created: user.created.clone(),
    };
    serde_json::to_value(&resp).unwrap_or_else(|_| serde_json::json!({}))
}

pub async fn get_current_user(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    // tracing::debug!("[get_current_user] request received");
    let token = match get_token_from_headers(&headers) {
        Some(t) => {
            // tracing::debug!("[get_current_user] token found in headers");
            t
        }
        None => {
            // tracing::warn!("[get_current_user] no x-auth-token header found");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response();
        }
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => {
            // tracing::debug!("[get_current_user] token verified, user_id={}", claims.user.id);
            match state.db.find_user_by_id(&claims.user.id).await {
                Some(user) => {
                    let sui_balance = match crate::sui_query::fetch_sui_balance(&state.config.fullnode_url, &user.address).await {
                        Ok(b) => b,
                        Err(e) => {
                            // tracing::warn!("[get_current_user] failed to fetch SUI balance for {}: {}", user.address, e);
                            0
                        }
                    };
                    (StatusCode::OK, Json(user_to_response(&user, sui_balance))).into_response()
                }
                None => {
                    // tracing::warn!("[get_current_user] user not found in db, id={}", claims.user.id);
                    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "User not found"}))).into_response()
                }
            }
        }
        Err(_) => {
            // tracing::warn!("[get_current_user] token verification failed");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()
        }
    }
}

/// GET /api/sui/balance — 返回当前认证用户的 SUI 余额和筹码余额
pub async fn get_sui_balance(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => return err_resp(StatusCode::NOT_FOUND, "User not found"),
    };

    let sui_balance = match crate::sui_query::fetch_sui_balance(&state.config.fullnode_url, &user.address).await {
        Ok(b) => b,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, &format!("Failed to fetch SUI balance: {}", e)),
    };

    let chips_amount = chips_from_mist(sui_balance) - user.locked_chips;
    (StatusCode::OK, Json(serde_json::json!({
        "suiBalance": sui_balance,
        "chipsAmount": chips_amount,
        "lockedChips": user.locked_chips,
        "address": user.address,
    }))).into_response()
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
            (StatusCode::OK, Json(serde_json::to_value(client_table).unwrap_or_else(|_| serde_json::json!({})))).into_response()
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
    // A2 修复：join_game 也需要验证认证，并校验 pk_hex 归属
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
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

    // A2 修复：加载用户并验证 pk_hex 归属
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[join_game] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };
    // A2 修复：在本地（非上链）模式下，校验 pk_hex 归属，防止用户冒用他人 pk_hex 入座。
    // 上链模式下 pk_hex 是 Mental Poker G1 公钥（与钱包地址不同），归属由链上逻辑校验，跳过此检查。
    if !state.config.sui_on_chain_enabled {
        let normalize = |s: &str| -> String {
            s.strip_prefix("0x").unwrap_or(s).to_lowercase()
        };
        let user_pk = normalize(&user.address);
        let req_pk = normalize(&body.pk_hex);
        if user_pk != req_pk {
            tracing::warn!(
                "[join_game] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
                claims.user.id,
                user_pk,
                req_pk
            );
            return err_resp(StatusCode::FORBIDDEN, "pk_hex does not match authenticated wallet");
        }
    }

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
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[player_action] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };

    // A2 修复：验证请求中的 pk_hex 属于已认证用户
    // User.address 存储的是用户绑定的 pk_hex（钱包登录时为 pk_hex，注册时为生成的 pk_hex）
    // let user_pk = crate::pokergame::player::GamePkHex::new(user.address.clone());
    // let req_pk = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());
    // if user_pk != req_pk {
    //     tracing::warn!(
    //         "[player_action] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
    //         claims.user.id,
    //         user_pk,
    //         req_pk
    //     );
    //     return err_resp(StatusCode::FORBIDDEN, "pk_hex does not belong to authenticated user");
    // }


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
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
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

    // A2 修复：验证请求中的 pk_hex 属于已认证用户
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[submit_reveal_token] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };
    //todo find game pk
    // let user_pk = crate::pokergame::player::GamePkHex::new(user.address.clone());
    // let req_pk = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());
    // if user_pk != req_pk {
    //     tracing::warn!(
    //         "[submit_reveal_token] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
    //         claims.user.id,
    //         user_pk,
    //         req_pk
    //     );
    //     return err_resp(StatusCode::FORBIDDEN, "pk_hex does not belong to authenticated user");
    // }

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
        // ZK 可视化：reveal_token 证明验证失败
        state.socket_state.broadcast_crypto_event(
            table_id,
            CryptoEventType::RevealToken,
            body.pk_hex.clone(),
            None,
            false,
            Some(format!("reveal_token proof verification failed: {}", e)),
            None,
        ).await;
        return err_resp(StatusCode::BAD_REQUEST, &e);
    }

    // ZK 可视化：reveal_token 证明验证成功
    // 注意：reveal_token 为批量提交（一次多个 token），card_index 暂传 null。
    state.socket_state.broadcast_crypto_event(
        table_id,
        CryptoEventType::RevealToken,
        body.pk_hex.clone(),
        None,
        true,
        Some("reveal_token proof verified".to_string()),
        None,
    ).await;

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
            RevealPhase::None => {
                tracing::warn!("[submit_reveal_token] all_complete but reveal_phase is None, table_id={}", table_id);
            }
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
    Extension(_state): Extension<Arc<AppState>>,
    _req: Request<Body>,
) -> Response {
    // 钱包登录模式下已禁用邮箱/密码登录
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Email/password login is disabled. Please use wallet login."}))).into_response()
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

    let (address, pk_hex) = match wallet_auth::verify_sui_wallet_signature(&body.message, &body.signature, &body.address, &state.config.sui_network).await {
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
            address: address.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            locked_chips: 0,
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
    Extension(_state): Extension<Arc<AppState>>,
    _req: Request<Body>,
) -> Response {
    // 钱包登录模式下已禁用注册
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Registration is disabled. Please use wallet login."}))).into_response()
}

pub async fn free_chips(
    _headers: HeaderMap,
    Extension(_state): Extension<Arc<AppState>>,
) -> Response {
    // 钱包登录模式下筹码由 SUI 余额决定，不再提供免费筹码
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Free chips is disabled. Chips are derived from SUI wallet balance (1 SUI = 10000 chips)."}))).into_response()
}

// ---------------------------------------------------------------------------
// Sui table 缓存查询 / 刷新
// ---------------------------------------------------------------------------

/// GET /api/sui/tables — 返回所有缓存的 TableSummary 列表
pub async fn list_sui_tables(Extension(state): Extension<Arc<AppState>>) -> Response {
    let gs = state.socket_state.state.read().await;
    let tables: Vec<crate::sui_events::TableSummaryV2> = gs.tables.values()
        .filter(|t| t.chain_table_id.is_some())
        .map(|t| t.summary.clone())
        .collect();
    (StatusCode::OK, Json(tables)).into_response()
}

/// GET /api/sui/tables/:table_id — 获取单个缓存的 TableSummary
pub async fn get_sui_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    let gs = state.socket_state.state.read().await;
    let found = gs.tables.values()
        .find(|t| t.chain_table_id.as_deref() == Some(&table_id))
        .map(|t| t.summary.clone());
    match found {
        Some(summary) => (StatusCode::OK, Json(summary)).into_response(),
        None => err_resp(StatusCode::NOT_FOUND, &format!("Table {} not found", table_id)),
    }
}

/// POST /api/sui/tables/:table_id/refresh — 从链上重新拉取 TableSummary 并更新 GameState
pub async fn refresh_sui_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    match crate::sui_query::fetch_table_summary(&state.config.fullnode_url, &state.config.sui_package_id, &table_id).await {
        Ok(summary) => {
            let mut gs = state.socket_state.state.write().await;
            if let Some(table) = gs.tables.values_mut().find(|t| t.chain_table_id.as_deref() == Some(&table_id)) {
                table.summary = summary.clone();
            }
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
    // join_and_shuffle_verified 特有
    /// 买入用的 SUI Coin 对象 ID (hex)，合约已改为接收 Coin<SUI>
    coin_object_id: Option<String>,
    /// 买入筹码数量（1 chip = 100_000 MIST），用于 SplitCoins 精确拆分
    amount: Option<u64>,
    pk: Option<String>,
    pk_ownership_proof: Option<String>,
    mask_cards: Option<String>,
    output_cards: Option<String>,
    remask_proof_bytes: Option<String>,
    shuffle_proof_bytes: Option<String>,
    // Task 7: reconstruct 特有
    swap_cards: Option<String>,
    user_readable_cards: Option<String>,
    reconstruct_proof_bytes: Option<String>,
    // Task 7: reveal 特有
    // assignment_indices 为逗号分隔的 u64 列表（如 "0,1,2"）
    assignment_indices: Option<String>,
    // reveal_tokens / reveal_proof_bytes_list 为分号分隔的 hex/base64 列表（如 "aabb;ccdd"）
    reveal_tokens: Option<String>,
    reveal_proof_bytes_list: Option<String>,
    // leave_with_proof_verified 特有
    /// leave 证明字节（hex 或 base64），对应 Move 合约的 leave_proof_bytes 参数
    leave_proof_bytes: Option<String>,
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
        "fold" => crate::relayer::ptb::build_fold_ptb(package_id, table_id, seat_index),
        "check" => crate::relayer::ptb::build_check_ptb(package_id, table_id, seat_index),
        "call" => crate::relayer::ptb::build_call_ptb(package_id, table_id, seat_index),
        "raise" => {
            let total_bet = match req.total_bet {
                Some(v) => v,
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing total_bet for raise action"),
            };
            crate::relayer::ptb::build_raise_ptb(package_id, table_id, seat_index, total_bet)
        }
        "join_and_shuffle_verified" => {
            let coin_object_id = match req.coin_object_id {
                Some(v) => v,
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing coin_object_id for join_and_shuffle_verified action"),
            };
            let pk = match req.pk.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid pk: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing pk for join_and_shuffle_verified action"),
            };
            let pk_ownership_proof = match req.pk_ownership_proof.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid pk_ownership_proof: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing pk_ownership_proof for join_and_shuffle_verified action"),
            };
            let mask_cards = match req.mask_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid mask_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing mask_cards for join_and_shuffle_verified action"),
            };
            let output_cards = match req.output_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid output_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing output_cards for join_and_shuffle_verified action"),
            };
            let remask_proof_bytes = match req.remask_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid remask_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing remask_proof_bytes for join_and_shuffle_verified action"),
            };
            let shuffle_proof_bytes = match req.shuffle_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid shuffle_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing shuffle_proof_bytes for join_and_shuffle_verified action"),
            };
            let amount_mist = match req.amount {
                Some(v) => v * 100_000, // chips → MIST
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing amount for join_and_shuffle_verified action"),
            };
            crate::relayer::ptb::build_join_and_shuffle_ptb(
                package_id,
                table_id,
                seat_index,
                &coin_object_id,
                amount_mist,
                pk,
                pk_ownership_proof,
                mask_cards,
                output_cards,
                remask_proof_bytes,
                shuffle_proof_bytes,
            )
        }
        "shuffle" => {
            let output_cards = match req.output_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid output_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing output_cards for shuffle action"),
            };
            let shuffle_proof_bytes = match req.shuffle_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid shuffle_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing shuffle_proof_bytes for shuffle action"),
            };
            crate::relayer::ptb::build_submit_shuffle_ptb(
                package_id,
                table_id,
                output_cards,
                shuffle_proof_bytes,
            )
        }
        "reconstruct" => {
            let output_cards = match req.output_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid output_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing output_cards for reconstruct action"),
            };
            let swap_cards = match req.swap_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid swap_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing swap_cards for reconstruct action"),
            };
            let user_readable_cards = match req.user_readable_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid user_readable_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing user_readable_cards for reconstruct action"),
            };
            let reconstruct_proof_bytes = match req.reconstruct_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid reconstruct_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing reconstruct_proof_bytes for reconstruct action"),
            };
            crate::relayer::ptb::build_submit_reconstruct_deck_ptb(
                package_id,
                table_id,
                output_cards,
                swap_cards,
                user_readable_cards,
                reconstruct_proof_bytes,
            )
        }
        "reveal" => {
            // assignment_indices: 逗号分隔的 u64 列表
            let assignment_indices: Vec<u64> = match req.assignment_indices.as_deref() {
                Some(s) => {
                    let parsed: Result<Vec<u64>, _> = s
                        .split(',')
                        .map(|p| p.trim().parse::<u64>())
                        .collect();
                    match parsed {
                        Ok(v) => v,
                        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid assignment_indices: {}", e)),
                    }
                }
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing assignment_indices for reveal action"),
            };
            // reveal_tokens: 分号分隔的 hex/base64 列表
            let reveal_tokens: Vec<Vec<u8>> = match req.reveal_tokens.as_deref() {
                Some(s) => {
                    let parsed: Result<Vec<Vec<u8>>, String> = s
                        .split(';')
                        .map(decode_hex_or_base64)
                        .collect();
                    match parsed {
                        Ok(v) => v,
                        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
                    }
                }
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing reveal_tokens for reveal action"),
            };
            // reveal_proof_bytes_list: 分号分隔的 hex/base64 列表
            let reveal_proof_bytes_list: Vec<Vec<u8>> = match req.reveal_proof_bytes_list.as_deref() {
                Some(s) => {
                    let parsed: Result<Vec<Vec<u8>>, String> = s
                        .split(';')
                        .map(decode_hex_or_base64)
                        .collect();
                    match parsed {
                        Ok(v) => v,
                        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
                    }
                }
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing reveal_proof_bytes_list for reveal action"),
            };
            crate::relayer::ptb::build_submit_reveal_tokens_ptb(
                package_id,
                table_id,
                assignment_indices,
                reveal_tokens,
                reveal_proof_bytes_list,
            )
        }
        "leave_with_proof_verified" => {
            let output_cards = match req.output_cards.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid output_cards: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing output_cards for leave_with_proof_verified action"),
            };
            let leave_proof_bytes = match req.leave_proof_bytes.as_deref().map(decode_hex_or_base64) {
                Some(Ok(v)) => v,
                Some(Err(e)) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid leave_proof_bytes: {}", e)),
                None => return err_resp(StatusCode::BAD_REQUEST, "Missing leave_proof_bytes for leave_with_proof_verified action"),
            };
            crate::relayer::ptb::build_leave_with_proof_ptb(
                package_id,
                table_id,
                seat_index,
                output_cards,
                leave_proof_bytes,
            )
        }
        "leave_table" => {
            crate::relayer::ptb::build_leave_table_ptb(
                package_id,
                table_id,
                seat_index,
            )
        }
        other => {
            return err_resp(StatusCode::BAD_REQUEST, &format!("Unknown action: {}", other));
        }
    };

    let ptb = match ptb_result {
        Ok(p) => p,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &e),
    };

    // Resolve shared object initial_shared_version for Shinami Gas Station compatibility.
    // Shinami does not resolve version 0 automatically (unlike Sui fullnode RPC).
    let http = crate::sponsor::shared_http_client();
    let ptb = match crate::relayer::ptb::resolve_shared_object_versions(
        http,
        &state.config.fullnode_url,
        ptb,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to resolve shared object versions: {}", e),
            )
        }
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
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    // A5: 添加认证校验
    if let Err(resp) = verify_auth(&headers, &state.config.jwt_secret) {
        return resp;
    }

    // 检查 active_count，空桌或单桌不提交 tick，避免浪费 gas
    let active_count = {
        let gs = state.socket_state.state.read().await;
        gs.tables.values()
            .find(|t| t.chain_table_id.as_deref() == Some(&table_id))
            .map(|t| t.summary.meta.active_count)
            .unwrap_or(0)
    };
    if active_count < 2 {
        return err_resp(
            StatusCode::OK,
            &format!("Skip tick: active_count={} (< 2)", active_count),
        );
    }

    match crate::relayer::submit::submit_tick_tx(&state.config, &table_id).await {
        Ok(digest) => (StatusCode::OK, Json(serde_json::json!({ "digest": digest }))).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Tick failed: {}", e)),
    }
}
