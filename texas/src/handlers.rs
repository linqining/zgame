use axum::{
    body::Body,
    extract::Extension,
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

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
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

    let user = crate::models::User {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name.clone(),
        email: body.email.clone(),
        password: hashed,
        chips_amount: state.config.initial_chips_amount,
        user_type: 0,
        created: chrono::Utc::now().to_rfc3339(),
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
