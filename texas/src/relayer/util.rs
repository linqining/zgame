//! Shared utility functions for the relayer and related modules.
//!
//! Consolidates previously-duplicated helpers for address parsing, BCS encoding,
//! timestamp generation, base64 (de)serialization, and Sui JSON-RPC calls.

use base64::Engine;
use sui_sdk_types::Address;

/// Parse a hex-encoded Sui [`Address`], returning an error on invalid input.
///
/// Callers are expected to pass valid hex addresses (e.g. `"0x6"` for the Clock,
/// or a 64-char hex string for a package/table object id).
pub fn parse_address(s: &str) -> Result<Address, String> {
    s.parse::<Address>()
        .map_err(|e| format!("invalid address '{}': {}", s, e))
}

/// BCS-encode a serializable value into a `Vec<u8>` suitable for `Input::Pure`.
pub fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bcs::to_bytes(value).map_err(|e| format!("BCS serialization failed: {}", e))
}

/// Current time in milliseconds since the UNIX epoch.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Base64-decode using STANDARD, falling back to URL_SAFE_NO_PAD and URL_SAFE.
///
/// Sui keys/transactions may use base64url (`-` and `_` instead of `+` and `/`),
/// so the URL-safe variants are tried when STANDARD fails.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let std = base64::engine::general_purpose::STANDARD;
    std.decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .map_err(|e| format!("Base64 decode error: {}", e))
}

/// Base64-encode using STANDARD.
pub fn base64_encode(input: &[u8]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(input)
}

/// Call a Sui JSON-RPC method and return the `result` field.
pub async fn sui_jsonrpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = result.get("error") {
        return Err(format!("JSON-RPC error: {}", error));
    }

    result
        .get("result")
        .cloned()
        .ok_or_else(|| "Missing result in JSON-RPC response".to_string())
}
