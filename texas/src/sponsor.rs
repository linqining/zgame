use axum::{
    body::Body,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth;
use crate::config::Config;
use crate::handlers::{err_resp, get_token_from_headers, AppState};

// ============================================================
// zkLogin Salt Service
// ============================================================

#[derive(Deserialize)]
pub struct SaltRequest {
    jwt: String,
}

#[derive(Serialize)]
pub struct SaltResponse {
    salt: String,
}

/// Derive a deterministic salt for a zkLogin user.
/// Salt = blake2b(jwt_iss || jwt_sub || server_secret), truncated to 16 bytes (128 bits),
/// returned as a decimal string (u128) as required by the Sui zkLogin prover.
fn derive_zklogin_salt(iss: &str, sub: &str, secret: &str) -> String {
    use blake2b_simd::blake2b;
    let input = format!("{}:{}:{}", iss, sub, secret);
    let hash = blake2b(input.as_bytes());
    // Take first 16 bytes (128 bits) and convert to u128 decimal string
    let bytes: [u8; 16] = hash.as_bytes()[..16].try_into().expect("slice has correct length");
    let salt_val = u128::from_be_bytes(bytes);
    salt_val.to_string()
}

/// POST /api/auth/zklogin/salt
pub async fn get_zklogin_salt(
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    let body = match axum::body::to_bytes(req, 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let body = match serde_json::from_slice::<SaltRequest>(&body) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    let (iss, sub) = match decode_jwt_payload_unverified(&body.jwt) {
        Ok((iss, sub)) => (iss, sub),
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JWT: {}", e)),
    };

    let salt = derive_zklogin_salt(&iss, &sub, &state.config.zklogin_salt_secret);
    tracing::debug!("[get_zklogin_salt] salt derived for iss={}, sub={}", iss, sub);

    (StatusCode::OK, Json(SaltResponse { salt })).into_response()
}

/// Decode JWT payload without verification to extract iss and sub.
fn decode_jwt_payload_unverified(jwt: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }

    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(parts[1]).map_err(|e| format!("Base64 decode error: {}", e))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let iss = payload.get("iss")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'iss' claim")?
        .to_string();
    let sub = payload.get("sub")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'sub' claim")?
        .to_string();

    Ok((iss, sub))
}

// ============================================================
// zkLogin Backend Authentication
// ============================================================

#[derive(Deserialize)]
pub struct ZkLoginAuthRequest {
    address: String,
    signature: String,
    message: String,
    provider: Option<String>,
    email: Option<String>,
}

/// POST /api/auth/zklogin
pub async fn zklogin_auth(
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    tracing::debug!("[zklogin_auth] request received");
    let body = match axum::body::to_bytes(req, 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body = match serde_json::from_slice::<ZkLoginAuthRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[zklogin_auth] parsed body, address={}", v.address);
            v
        }
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    let address = body.address.clone();
    let user_id = format!("zklogin:{}", address);

    if state.db.find_user_by_id(&user_id).await.is_none() {
        tracing::debug!("[zklogin_auth] new zkLogin user, creating user_id={}", user_id);
        let name = body.email.clone().unwrap_or_else(|| address.clone());
        let user = crate::models::User {
            id: user_id.clone(),
            name,
            email: body.email.clone().unwrap_or_else(|| format!("{}@zklogin", address)),
            password: bcrypt::hash(&uuid::Uuid::new_v4().to_string(), 10).unwrap_or_default(),
            chips_amount: state.config.initial_chips_amount,
            user_type: 2,
            created: chrono::Utc::now().to_rfc3339(),
            address: address.clone(),
            last_free_chips_at: None,
        };
        if let Err(e) = state.db.save_user(&user).await {
            tracing::error!("[zklogin_auth] failed to save zkLogin user, user_id={}, error={}", user_id, e);
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save user: {}", e));
        }
    } else {
        let _ = state.db.update_address(&user_id, &address).await;
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            tracing::debug!("[zklogin_auth] token created, user_id={}", user_id);
            (StatusCode::OK, Json(serde_json::json!({
                "token": token,
                "address": address,
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[zklogin_auth] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
        }
    }
}

// ============================================================
// Sponsored Transaction Service
// ============================================================
//
// Two-endpoint approach:
// 1. GET /api/sponsor/gas-info  - Returns sponsor's gas coin details for the frontend
// 2. POST /api/sponsor/transaction - Signs the complete transaction bytes
//
// The frontend builds the complete TransactionData (with gas info) and sends
// it to the backend for signing. This avoids TransactionKind deserialization
// on the backend and sidesteps type compatibility issues between sui_sdk
// and sui_sdk_types crates.

#[derive(Serialize)]
pub struct GasInfoResponse {
    pub(crate) sponsor_address: String,
    pub(crate) gas_coin_id: String,
    pub(crate) gas_coin_version: String,
    pub(crate) gas_coin_digest: String,
    pub(crate) gas_price: String,
    pub(crate) gas_budget: u64,
}

/// GET /api/sponsor/gas-info
/// Returns the sponsor's gas coin details so the frontend can build
/// a complete sponsored transaction.
pub async fn get_gas_info(
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    if state.config.sponsor_private_key.is_empty() {
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "Sponsor service not configured");
    }

    match fetch_gas_info(&state.config).await {
        Ok(info) => (StatusCode::OK, Json(info)).into_response(),
        Err(e) => {
            tracing::error!("[get_gas_info] failed: {}", e);
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to fetch gas info: {}", e))
        }
    }
}

pub(crate) async fn fetch_gas_info(config: &Config) -> Result<GasInfoResponse, String> {
    let private_key = parse_sponsor_private_key(&config.sponsor_private_key)?;
    let public_key = private_key.public_key();
    let sponsor_address: sui_sdk_types::Address = public_key.derive_address();
    let sponsor_address_str = sponsor_address.to_string();

    let http = reqwest::Client::new();

    // Get gas coins via JSON-RPC
    let coins_resp = sui_jsonrpc(
        &http,
        &config.fullnode_url,
        "suix_getCoins",
        vec![serde_json::to_value(&sponsor_address).map_err(|e| format!("{}", e))?],
    ).await?;

    let coins = coins_resp.get("data")
        .and_then(|v| v.as_array())
        .ok_or("Invalid gas coins response")?;

    if coins.is_empty() {
        return Err("Sponsor has no gas coins".to_string());
    }

    let coin = &coins[0];
    let gas_coin_id = coin["coinObjectId"].as_str().unwrap_or("").to_string();
    let gas_coin_version = coin["version"].as_str().unwrap_or("0").to_string();
    let gas_coin_digest = coin["digest"].as_str().unwrap_or("").to_string();

    // Get gas price via JSON-RPC
    let price_resp = sui_jsonrpc(
        &http,
        &config.fullnode_url,
        "suix_getReferenceGasPrice",
        vec![],
    ).await?;

    let gas_price = price_resp.as_str()
        .and_then(|s| s.parse::<String>().ok())
        .or_else(|| price_resp.as_u64().map(|v| v.to_string()))
        .ok_or("Invalid gas price response")?;

    Ok(GasInfoResponse {
        sponsor_address: sponsor_address_str,
        gas_coin_id,
        gas_coin_version,
        gas_coin_digest,
        gas_price,
        gas_budget: config.sponsor_gas_budget,
    })
}

#[derive(Deserialize)]
pub struct SponsorTransactionRequest {
    /// Base64-encoded complete TransactionData bytes (with gas info already filled in)
    tx_bytes: String,
}

#[derive(Serialize)]
pub struct SponsorTransactionResponse {
    /// The sponsor's signature over the transaction
    gas_signature: String,
}

/// POST /api/sponsor/transaction
/// Signs a complete transaction as the sponsor (gas owner).
/// The frontend builds the full TransactionData with gas info from /api/sponsor/gas-info,
/// then sends it here for the sponsor's signature.
pub async fn sponsor_transaction(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    let _claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if state.config.sponsor_private_key.is_empty() {
        tracing::warn!("[sponsor_transaction] sponsor not configured");
        return err_resp(StatusCode::SERVICE_UNAVAILABLE, "Sponsor service not configured");
    }

    let body = match axum::body::to_bytes(req, 1024 * 256).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let body = match serde_json::from_slice::<SponsorTransactionRequest>(&body) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    match sign_transaction_as_sponsor(&state.config, &body.tx_bytes).await {
        Ok(signature) => {
            tracing::debug!("[sponsor_transaction] sponsorship successful");
            (StatusCode::OK, Json(SponsorTransactionResponse {
                gas_signature: signature,
            })).into_response()
        }
        Err(e) => {
            tracing::error!("[sponsor_transaction] failed: {}", e);
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Sponsorship failed: {}", e))
        }
    }
}

/// Sign a complete transaction as the sponsor.
///
/// Uses `sui_crypto::ed25519::Ed25519PrivateKey` which implements
/// `Signer<UserSignature>`. We compute the Sui signing digest
/// (blake2b of intent + tx_bytes) and sign it, then serialize
/// the result as a Sui signature (flag + sig + pubkey in base64).
pub(crate) async fn sign_transaction_as_sponsor(
    config: &Config,
    tx_bytes_b64: &str,
) -> Result<String, String> {
    let private_key = parse_sponsor_private_key(&config.sponsor_private_key)?;

    // Decode the transaction bytes
    let tx_bytes = base64_decode(tx_bytes_b64)?;

    // Compute the signing digest
    // Intent for Sui transaction: [purpose=0, scope=0, version=0, app_id=0]
    let intent_bytes: [u8; 4] = [0, 0, 0, 0];
    let mut signing_input = Vec::with_capacity(4 + tx_bytes.len());
    signing_input.extend_from_slice(&intent_bytes);
    signing_input.extend_from_slice(&tx_bytes);

    let digest = blake2b_simd::blake2b(&signing_input);
    let digest_bytes = digest.as_bytes();

    // Sign using sui_crypto's Ed25519PrivateKey
    use sui_crypto::Signer;
    use sui_sdk_types::UserSignature;
    let user_signature: UserSignature = private_key
        .try_sign(digest_bytes)
        .map_err(|e| format!("Signing failed: {}", e))?;

    // Serialize the UserSignature to bytes (Sui wire format)
    let sig_bytes = bcs::to_bytes(&user_signature)
        .map_err(|e| format!("Signature serialization failed: {}", e))?;

    Ok(base64_encode(&sig_bytes))
}

// ============================================================
// Helper functions
// ============================================================

/// Parse the sponsor's Ed25519 private key from a string.
///
/// Supports two formats:
/// 1. `suiprivkey<base64>` - Sui CLI export format (flag byte + 32-byte key)
/// 2. Raw base64 of 32-byte Ed25519 private key
pub(crate) fn parse_sponsor_private_key(private_key: &str) -> Result<sui_crypto::ed25519::Ed25519PrivateKey, String> {
    // Handle suiprivkey prefix
    let key_str = private_key.strip_prefix("suiprivkey").unwrap_or(private_key);
    let key_bytes = base64_decode(key_str)?;

    // The key bytes should be either:
    // - 33 bytes: 1 flag byte (0x00 for Ed25519) + 32 private key bytes
    // - 32 bytes: raw Ed25519 private key
    let pk_bytes: [u8; 32] = if key_bytes.len() == 33 {
        if key_bytes[0] != 0 {
            return Err(format!("Unsupported key flag: {} (only Ed25519=0 is supported)", key_bytes[0]));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes[1..33]);
        arr
    } else if key_bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes[..32]);
        arr
    } else {
        return Err(format!("Invalid private key length: {} bytes (expected 32 or 33)", key_bytes.len()));
    };

    Ok(sui_crypto::ed25519::Ed25519PrivateKey::new(pk_bytes))
}

pub(crate) async fn sui_jsonrpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let resp = client.post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let result: serde_json::Value = resp.json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = result.get("error") {
        return Err(format!("JSON-RPC error: {}", error));
    }

    result.get("result").cloned().ok_or("Missing result in JSON-RPC response".to_string())
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(input).map_err(|e| format!("Base64 decode error: {}", e))
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(input)
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
