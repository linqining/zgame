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
use crate::wallet_auth;

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

/// Normalize the zkLogin issuer to match the Sui SDK's `normalizeZkLoginIssuer`.
///
/// The SDK normalizes `accounts.google.com` to `https://accounts.google.com`
/// when deriving the zkLogin address (see `@mysten/sui/zklogin/utils.ts`).
/// The salt derivation MUST use the same normalization, otherwise the same
/// OAuth user can receive different salts (and therefore different zkLogin
/// addresses) across logins if the provider returns different `iss` formats.
fn normalize_zklogin_issuer(iss: &str) -> &str {
    if iss == "accounts.google.com" {
        "https://accounts.google.com"
    } else {
        iss
    }
}

/// Derive a deterministic salt for a zkLogin user.
/// Salt = blake2b(normalized_iss || sub || server_secret), truncated to 16 bytes (128 bits),
/// returned as a decimal string (u128) as required by the Sui zkLogin prover.
///
/// The `iss` is normalized via `normalize_zklogin_issuer` to stay consistent
/// with the Sui SDK's address derivation, guaranteeing a stable salt (and
/// therefore a stable zkLogin address) for the same OAuth user across logins.
fn derive_zklogin_salt(iss: &str, sub: &str, secret: &str) -> String {
    use blake2b_simd::blake2b;
    let normalized_iss = normalize_zklogin_issuer(iss);
    let input = format!("{}:{}:{}", normalized_iss, sub, secret);
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
    tracing::info!(
        "[get_zklogin_salt] iss={}, normalized_iss={}, sub={}, salt_prefix={}",
        iss,
        normalize_zklogin_issuer(&iss),
        sub,
        &salt[..salt.len().min(8)]
    );

    (StatusCode::OK, Json(SaltResponse { salt })).into_response()
}

// ============================================================
// zkLogin Prover Proxy (Shinami)
// ============================================================
//
// Shinami's zkProver does not support CORS and requires an X-API-Key header,
// so the frontend cannot call it directly. This endpoint receives the proof
// inputs from the frontend, forwards them to Shinami's JSON-RPC prover, and
// returns the resulting zkProof. Shinami's prover works with any salt
// (Shinami-managed, self-managed, or third-party), so we keep using the salt
// derived by derive_zklogin_salt above — the user's zkLogin address stays
// stable.

const SHINAMI_ZKPROVER_URL: &str = "https://api.us1.shinami.com/sui/zkprover/v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ZkProverRequest {
    jwt: String,
    extended_ephemeral_public_key: String,
    max_epoch: String,
    jwt_randomness: String,
    salt: String,
}

/// POST /api/auth/zklogin/prover
pub async fn post_zklogin_prover(
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    if state.config.shinami_api_key.is_empty() {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shinami prover not configured (SHINAMI_API_KEY missing)",
        );
    }

    let body = match axum::body::to_bytes(req, 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let req_body = match serde_json::from_slice::<ZkProverRequest>(&body) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    let http = shared_http_client();
    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "shinami_zkp_createZkLoginProof",
        "params": [
            req_body.jwt,
            req_body.max_epoch,
            req_body.extended_ephemeral_public_key,
            req_body.jwt_randomness,
            req_body.salt,
        ],
        "id": 1,
    });

    let resp = match http
        .post(SHINAMI_ZKPROVER_URL)
        .header("X-API-Key", &state.config.shinami_api_key)
        .json(&rpc_payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[post_zklogin_prover] Shinami request failed: {}", e);
            return err_resp(StatusCode::BAD_GATEWAY, &format!("Prover request failed: {}", e));
        }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("[post_zklogin_prover] failed to parse Shinami response: {}", e);
            return err_resp(StatusCode::BAD_GATEWAY, &format!("Invalid prover response: {}", e));
        }
    };

    if let Some(error) = json.get("error") {
        tracing::warn!("[post_zklogin_prover] Shinami error: {}", error);
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": error }))).into_response();
    }

    let zk_proof = match json.pointer("/result/zkProof") {
        Some(v) => v.clone(),
        None => {
            tracing::error!("[post_zklogin_prover] missing zkProof in Shinami response: {}", json);
            return err_resp(StatusCode::BAD_GATEWAY, "Missing zkProof in prover response");
        }
    };

    (StatusCode::OK, Json(zk_proof)).into_response()
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
    signature: sui_sdk_types::UserSignature,
    message: String,
    provider: Option<String>,
    email: Option<String>,
}

/// POST /api/auth/zklogin
pub async fn zklogin_auth(
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    // tracing::debug!("[zklogin_auth] request received");
    let body = match axum::body::to_bytes(req, 1024 * 64).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };
    let body = match serde_json::from_slice::<ZkLoginAuthRequest>(&body) {
        Ok(v) => {
            // tracing::debug!("[zklogin_auth] parsed body, address={}", v.address);
            v
        }
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    // 验证签名：确保 signature 对 message 有效，且签名地址与 body.address 一致
    match wallet_auth::verify_sui_wallet_signature(&body.message, &body.signature, &body.address, &state.config.sui_network).await {
        Ok(_) => {
            // tracing::debug!("[zklogin_auth] signature verified, address={}", body.address);
        }
        Err(e) => {
            // tracing::warn!("[zklogin_auth] signature verification failed, address={}, error={}", body.address, e);
            return err_resp(StatusCode::UNAUTHORIZED, &e);
        }
    }

    let address = body.address.clone();
    let user_id = format!("zklogin:{}", address);

    if state.db.find_user_by_id(&user_id).await.is_none() {
        // tracing::debug!("[zklogin_auth] new zkLogin user, creating user_id={}", user_id);
        let name = body.email.clone().unwrap_or_else(|| address.clone());
        let user = crate::models::User {
            id: user_id.clone(),
            name,
            address: address.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            locked_chips: 0,
        };
        if let Err(e) = state.db.save_user(&user).await {
            // tracing::error!("[zklogin_auth] failed to save zkLogin user, user_id={}, error={}", user_id, e);
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save user: {}", e));
        }
    } else {
        let _ = state.db.update_address(&user_id, &address).await;
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            // tracing::debug!("[zklogin_auth] token created, user_id={}", user_id);
            (StatusCode::OK, Json(serde_json::json!({
                "token": token,
                "address": address,
            }))).into_response()
        }
        Err(_) => {
            // tracing::error!("[zklogin_auth] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
        }
    }
}

// ============================================================
// Sponsored Transaction Service (Shinami Gas Station)
// ============================================================
//
// Single-endpoint approach using Shinami's Gas Station API:
// POST /api/sponsor/transaction - Forwards a gasless transaction to Shinami,
//                                 returns the sponsored txBytes + gas signature.
//
// Flow:
// 1. Frontend builds a gasless transaction (TransactionKind + sender, no gas info)
// 2. Frontend POSTs it to this endpoint
// 3. Backend forwards to Shinami Gas Station (gas_sponsorTransactionBlock)
// 4. Shinami returns fully-sponsored txBytes + gas owner signature
// 5. Backend returns them to the frontend
// 6. Frontend signs the sponsored txBytes with zkLogin and submits both signatures
//
// The gas-info endpoint is no longer needed — Shinami selects gas coins.

const SHINAMI_GAS_STATION_URL: &str = "https://api.us1.shinami.com/sui/gas/v1";

#[derive(Deserialize)]
pub struct SponsorTransactionRequest {
    /// Base64-encoded TransactionKind bytes (no gas info)
    tx_kind: String,
    /// Sender address (hex, e.g. 0x...)
    sender: String,
    /// Optional gas budget. If omitted, Shinami estimates it.
    gas_budget: Option<u64>,
}

#[derive(Serialize)]
pub struct SponsorTransactionResponse {
    /// Base64-encoded complete TransactionData bytes (with gas info filled in by Shinami)
    tx_bytes: String,
    /// Gas owner's (Shinami's) signature over the transaction
    signature: String,
    /// Transaction digest, can be used to query sponsorship status
    tx_digest: String,
}

/// POST /api/sponsor/transaction
/// Proxies a gasless transaction to Shinami's Gas Station for sponsorship.
/// The frontend sends a TransactionKind + sender; Shinami returns sponsored
/// txBytes + gas signature. The frontend then signs the txBytes with zkLogin
/// and submits both signatures to the Sui network.
pub async fn sponsor_transaction(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    req: Body,
) -> Response {
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    if state.config.shinami_api_key.is_empty() {
        return err_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            "Shinami Gas Station not configured (SHINAMI_API_KEY missing)",
        );
    }

    let body = match axum::body::to_bytes(req, 1024 * 256).await {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "Invalid request body"),
    };

    let req = match serde_json::from_slice::<SponsorTransactionRequest>(&body) {
        Ok(v) => v,
        Err(e) => return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e)),
    };

    // Verify sender matches the JWT-authenticated user
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => return err_resp(StatusCode::UNAUTHORIZED, "User not found"),
    };
    let expected_sender = match wallet_auth::normalize_address(&user.address) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[sponsor_transaction] invalid user address: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid user address");
        }
    };
    let actual_sender = match wallet_auth::normalize_address(&req.sender) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[sponsor_transaction] invalid sender address: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid sender address");
        }
    };
    if actual_sender != expected_sender {
        tracing::warn!(
            "[sponsor_transaction] sender mismatch: tx_sender={}, user_address={}",
            actual_sender, expected_sender
        );
        return err_resp(StatusCode::FORBIDDEN, "Sender mismatch");
    }

    // Enforce gas budget cap if provided
    if let Some(budget) = req.gas_budget {
        if budget > state.config.sponsor_gas_budget {
            tracing::warn!(
                "[sponsor_transaction] gas budget too high: {} > {}",
                budget, state.config.sponsor_gas_budget
            );
            return err_resp(StatusCode::FORBIDDEN, "Gas budget too high");
        }
    }

    // Forward to Shinami Gas Station: gas_sponsorTransactionBlock(txKind, sender, gasBudget?, gasPrice?)
    let http = shared_http_client();
    let mut params = vec![
        serde_json::Value::String(req.tx_kind.clone()),
        serde_json::Value::String(req.sender.clone()),
    ];
    if let Some(budget) = req.gas_budget {
        params.push(serde_json::Value::Number(serde_json::Number::from(budget)));
    }
    // gasPrice omitted — Shinami uses the reference gas price

    let rpc_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "gas_sponsorTransactionBlock",
        "params": params,
        "id": 1,
    });

    let resp = match http
        .post(SHINAMI_GAS_STATION_URL)
        .header("X-API-Key", &state.config.shinami_api_key)
        .json(&rpc_payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[sponsor_transaction] Shinami request failed: {}", e);
            return err_resp(
                StatusCode::BAD_GATEWAY,
                &format!("Gas station request failed: {}", e),
            );
        }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("[sponsor_transaction] failed to parse Shinami response: {}", e);
            return err_resp(
                StatusCode::BAD_GATEWAY,
                &format!("Invalid gas station response: {}", e),
            );
        }
    };

    if let Some(error) = json.get("error") {
        tracing::warn!("[sponsor_transaction] Shinami error: {}", error);
        return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": error })))
            .into_response();
    }

    let result = match json.get("result") {
        Some(v) => v,
        None => {
            tracing::error!(
                "[sponsor_transaction] missing result in Shinami response: {}",
                json
            );
            return err_resp(StatusCode::BAD_GATEWAY, "Missing result in gas station response");
        }
    };

    let tx_bytes = match result.get("txBytes").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return err_resp(
                StatusCode::BAD_GATEWAY,
                "Missing txBytes in gas station response",
            )
        }
    };
    let signature = match result.get("signature").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return err_resp(
                StatusCode::BAD_GATEWAY,
                "Missing signature in gas station response",
            )
        }
    };
    let tx_digest = match result.get("txDigest").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return err_resp(
                StatusCode::BAD_GATEWAY,
                "Missing txDigest in gas station response",
            )
        }
    };

    tracing::debug!(
        "[sponsor_transaction] sponsorship successful, tx_digest={}",
        tx_digest
    );

    (
        StatusCode::OK,
        Json(SponsorTransactionResponse {
            tx_bytes,
            signature,
            tx_digest,
        }),
    )
        .into_response()
}


// ============================================================
// Relayer-internal gas info helpers (backend-only, not exposed via HTTP)
// ============================================================
//
// These helpers are kept for the relayer's tick/sponsored submission flow
// (relayer/submit.rs), which still uses the sponsor's own private key to
// sign as sender for tick transactions. The frontend-facing sponsor flow
// now goes through Shinami Gas Station (see sponsor_transaction above).

#[derive(Serialize)]
pub struct GasInfoResponse {
    pub(crate) sponsor_address: String,
    pub(crate) gas_coin_id: String,
    pub(crate) gas_coin_version: String,
    pub(crate) gas_coin_digest: String,
    pub(crate) gas_price: String,
    pub(crate) gas_budget: u64,
}

pub(crate) async fn fetch_gas_info(config: &Config) -> Result<GasInfoResponse, String> {
    let private_key = parse_sponsor_private_key(&config.sponsor_private_key)?;
    let public_key = private_key.public_key();
    let sponsor_address = public_key.derive_address();
    let sponsor_address_str = sponsor_address.to_string();

    let http = shared_http_client();

    let coins_resp = sui_jsonrpc(
        &http,
        &config.fullnode_url,
        "suix_getCoins",
        vec![serde_json::to_value(&sponsor_address).map_err(|e| format!("{}", e))?],
    )
    .await?;

    let coins = coins_resp
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or("Invalid gas coins response")?;

    if coins.is_empty() {
        return Err("Sponsor has no gas coins".to_string());
    }

    let coin = &coins[0];
    let gas_coin_id = coin["coinObjectId"].as_str().unwrap_or("").to_string();
    let gas_coin_version = coin["version"].as_str().unwrap_or("0").to_string();
    let gas_coin_digest = coin["digest"].as_str().unwrap_or("").to_string();

    let price_resp = sui_jsonrpc(
        &http,
        &config.fullnode_url,
        "suix_getReferenceGasPrice",
        vec![],
    )
    .await?;

    let gas_price = price_resp
        .as_str()
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

// ============================================================
// Helper functions
// ============================================================

/// G9 修复：全局复用 reqwest::Client，避免每次调用都创建新实例
/// （每次新建 Client 都会建立连接池、TLS 上下文，开销显著）。
static HTTP_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

pub(crate) fn shared_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

pub(crate) async fn sign_transaction_as_sponsor(
    config: &Config,
    tx_bytes_b64: &str,
) -> Result<String, String> {
    use sui_crypto::SuiSigner;

    let private_key = parse_sponsor_private_key(&config.sponsor_private_key)?;
    let tx_bytes = base64_decode(tx_bytes_b64)?;

    // 反序列化为 sui_sdk_types::Transaction
    let tx_data: sui_sdk_types::Transaction = bcs::from_bytes(&tx_bytes)
        .map_err(|e| format!("Transaction deserialization failed: {}", e))?;

    // 使用官方标准 API: SuiSigner::sign_transaction
    // 内部自动计算 blake2b(Intent::sui_transaction() || BCS(tx_data)) 并签名
    let user_signature = private_key
        .sign_transaction(&tx_data)
        .map_err(|e| format!("Signing failed: {}", e))?;

    // 关键修复：使用 `UserSignature::to_bytes()` 获取原始签名字节
    // （flag + sig + pubkey，例如 Ed25519 为 1+64+32=97 字节），
    // 而非 `bcs::to_bytes(&sig)`，后者会额外附加 ULEB128 长度前缀，
    // 导致 `sui_executeTransactionBlock` 报错 -32602 "Invalid value was given to the function"。
    let sig_bytes = user_signature.to_bytes();

    Ok(base64_encode(&sig_bytes))
}

/// Parse the sponsor's Ed25519 private key from a string.
///
/// Supports two formats:
/// 1. `suiprivkey1<base64>` - Sui CLI export format (flag byte + 32-byte key)
/// 2. Raw base64 of 32-byte Ed25519 private key
pub(crate) fn parse_sponsor_private_key(private_key: &str) -> Result<sui_crypto::ed25519::Ed25519PrivateKey, String> {
    // Sui keystore format: suiprivkey1<bech32-data>
    let key_bytes = if private_key.starts_with("suiprivkey1") {
        let (hrp, data_u5, _variant) = bech32::decode(private_key)
            .map_err(|e| format!("Bech32 decode error: {}", e))?;
        if hrp != "suiprivkey" {
            return Err(format!("Unexpected bech32 HRP: {} (expected suiprivkey)", hrp));
        }
        bech32::FromBase32::from_base32(&data_u5)
            .map_err(|e| format!("Bech32 data convert error: {:?}", e))?
    } else {
        let key_str = private_key.strip_prefix("suiprivkey").unwrap_or(private_key);
        let key_str = key_str.trim_start_matches(|c: char| c == '1' || c == '_');
        base64_decode(key_str)?
    };

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
    let std = base64::engine::general_purpose::STANDARD;
    // Sui keys/transactions may use base64url (- and _ instead of + and /),
    // so fall back to URL_SAFE_NO_PAD if STANDARD fails.
    std.decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .map_err(|e| format!("Base64 decode error: {}", e))
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
