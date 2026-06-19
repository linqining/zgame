//! 赞助交易提交模块。
//!
//! 提供 [`submit_sponsored_tx`] 和 [`submit_tick_tx`] 两个入口，分别用于：
//! - 提交用户发起、sponsor 支付 gas 的赞助交易
//! - 提交 sponsor 自身发起并支付 gas 的 tick 交易
//!
//! 两个函数都会构建完整的 [`Transaction`]（即 Sui 的 `TransactionData`），
//! 由 sponsor 签名后通过 JSON-RPC `sui_executeTransactionBlock` 提交到 Sui 网络。

use base64::Engine;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;
use sui_sdk_types::GasPayment;
use sui_sdk_types::ObjectReference;
use sui_sdk_types::Transaction;
use sui_sdk_types::TransactionExpiration;
use sui_sdk_types::TransactionKind;

use crate::config::Config;
use crate::relayer::ptb;
use crate::sponsor;

// ---------------------------------------------------------------------------
// 内部辅助函数
// ---------------------------------------------------------------------------

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(input)
        .map_err(|e| format!("Base64 decode error: {}", e))
}

fn base64_encode(input: &[u8]) -> String {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.encode(input)
}

/// G9 修复：复用 sponsor 模块的全局 reqwest::Client，避免每次调用都创建新实例。
fn shared_http_client() -> &'static reqwest::Client {
    sponsor::shared_http_client()
}

/// 通过 Sui JSON-RPC 获取当前 epoch，用于设置交易过期时间。
///
/// 优先使用 `sui_getLatestSuiSystemState`；若节点不支持（公共 testnet 节点
/// 可能返回 -32601 Method not found），回退到 `sui_getCheckpoints` 取最新
/// checkpoint 的 epoch 字段。
async fn get_current_epoch(config: &Config) -> Result<u64, String> {
    let http = shared_http_client();

    // 尝试 sui_getLatestSuiSystemState
    match sponsor::sui_jsonrpc(http, &config.fullnode_url, "sui_getLatestSuiSystemState", vec![]).await {
        Ok(result) => {
            let epoch = result
                .get("epoch")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| result.get("epoch").and_then(|v| v.as_u64()))
                .ok_or("Missing epoch in system state")?;
            return Ok(epoch);
        }
        Err(e) => {
            tracing::debug!("[submit] sui_getLatestSuiSystemState failed ({}), falling back to sui_getCheckpoints", e);
        }
    }

    // 回退：sui_getCheckpoints（取最新 checkpoint 的 epoch）
    let result = sponsor::sui_jsonrpc(
        http,
        &config.fullnode_url,
        "sui_getCheckpoints",
        vec![
            serde_json::Value::Null,
            serde_json::json!(1),
            serde_json::json!(true), // descending = 最新
        ],
    )
    .await?;

    let epoch = result
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|arr| arr.first())
        .and_then(|cp| cp.get("epoch"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            result
                .get("data")
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|cp| cp.get("epoch"))
                .and_then(|v| v.as_u64())
        })
        .ok_or("Missing epoch in checkpoint response")?;
    Ok(epoch)
}

/// 从 `GasInfoResponse` 构建 [`GasPayment`]。
///
/// `owner` 由调用方决定：赞助交易中为 sponsor 地址，tick 交易中为 sender（即 sponsor）。
fn build_gas_payment(
    gas_info: &sponsor::GasInfoResponse,
    owner: Address,
    budget: u64,
) -> Result<GasPayment, String> {
    let gas_object_id: Address = gas_info
        .gas_coin_id
        .parse()
        .map_err(|e| format!("Invalid gas coin id: {}", e))?;
    let gas_version: u64 = gas_info
        .gas_coin_version
        .parse()
        .map_err(|e| format!("Invalid gas coin version: {}", e))?;
    let gas_digest: Digest = gas_info
        .gas_coin_digest
        .parse()
        .map_err(|e| format!("Invalid gas coin digest: {}", e))?;
    let gas_price: u64 = gas_info
        .gas_price
        .parse()
        .map_err(|e| format!("Invalid gas price: {}", e))?;

    Ok(GasPayment {
        objects: vec![ObjectReference::new(gas_object_id, gas_version, gas_digest)],
        owner,
        price: gas_price,
        budget,
    })
}

/// 从 base64 编码的 `TransactionKind` 字节解码出 [`TransactionKind`]。
fn decode_tx_kind(tx_kind_b64: &str) -> Result<TransactionKind, String> {
    let tx_kind_bytes = base64_decode(tx_kind_b64)?;
    bcs::from_bytes(&tx_kind_bytes)
        .map_err(|e| format!("Failed to deserialize TransactionKind: {}", e))
}

/// 通过 `sui_executeTransactionBlock` 提交交易并检查执行状态，返回交易 digest。
async fn execute_tx(
    config: &Config,
    tx_bytes_b64: &str,
    signatures: Vec<String>,
) -> Result<String, String> {
    let http = shared_http_client();
    let sigs_array: Vec<serde_json::Value> = signatures
        .into_iter()
        .map(serde_json::Value::String)
        .collect();

    let result = sponsor::sui_jsonrpc(
        &http,
        &config.fullnode_url,
        "sui_executeTransactionBlock",
        vec![
            serde_json::Value::String(tx_bytes_b64.to_string()),
            serde_json::Value::Array(sigs_array),
            serde_json::json!({ "showEffects": true, "showEvents": true }),
        ],
    )
    .await?;

    // 检查执行状态
    let status = result
        .get("effects")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.get("status"))
        .and_then(|s| s.as_str())
        .ok_or("Missing execution status in response")?;

    if status != "success" {
        let error = result
            .get("effects")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Transaction execution failed: {}", error));
    }

    // 返回交易 digest
    let digest = result
        .get("digest")
        .and_then(|d| d.as_str())
        .ok_or("Missing transaction digest in response")?;

    Ok(digest.to_string())
}

// ---------------------------------------------------------------------------
// 公开 API
// ---------------------------------------------------------------------------

/// 提交赞助交易（用户为 sender，sponsor 为 gas owner）。
///
/// 流程：
/// 1. 从 `tx_kind_b64` 解码出 [`TransactionKind`]
/// 2. 获取 sponsor gas 信息（复用 [`sponsor::fetch_gas_info`]）
/// 3. 构建完整 [`Transaction`]（sender=用户地址，gas_owner=sponsor 地址）
/// 4. sponsor 签名（复用 [`sponsor::sign_transaction_as_sponsor`]）
/// 5. 提交到 Sui 网络（`sui_executeTransactionBlock`）
/// 6. 检查执行状态
///
/// # 参数
/// - `config`：包含 sponsor 私钥、gas budget、fullnode URL 等配置
/// - `tx_kind_b64`：base64 编码的 BCS 序列化 `TransactionKind` 字节
/// - `user_address`：用户地址（hex 字符串，如 `0x...`）
/// - `user_signature_b64`：用户对完整 `Transaction` 的签名（base64 编码的 Sui 签名）
///
/// # 返回
/// 成功时返回交易 digest 字符串。
pub async fn submit_sponsored_tx(
    config: &Config,
    tx_kind_b64: &str,
    user_address: &str,
    user_signature_b64: &str,
) -> Result<String, String> {
    if config.sponsor_private_key.is_empty() {
        return Err("Sponsor service not configured".to_string());
    }

    // 1. 解码 TransactionKind
    let tx_kind = decode_tx_kind(tx_kind_b64)?;

    // 2. 获取 sponsor gas 信息
    let gas_info = sponsor::fetch_gas_info(config).await?;

    // 3. 解析地址
    let sender: Address = user_address
        .parse()
        .map_err(|e| format!("Invalid user address: {}", e))?;
    let gas_owner: Address = gas_info
        .sponsor_address
        .parse()
        .map_err(|e| format!("Invalid sponsor address: {}", e))?;

    // 4. 构建 GasPayment
    let gas_payment = build_gas_payment(&gas_info, gas_owner, config.sponsor_gas_budget)?;

    // F14: 获取当前 epoch，设置交易过期时间（当前 epoch + 2），避免交易无过期被重放
    let current_epoch = get_current_epoch(config).await?;

    // 5. 构建完整 Transaction
    let transaction = Transaction {
        kind: tx_kind,
        sender,
        gas_payment,
        expiration: TransactionExpiration::Epoch(current_epoch + 2),
    };

    // 6. BCS 序列化
    let tx_bytes = bcs::to_bytes(&transaction)
        .map_err(|e| format!("Transaction BCS serialization failed: {}", e))?;
    let tx_bytes_b64 = base64_encode(&tx_bytes);

    // 7. sponsor 签名
    let sponsor_signature =
        sponsor::sign_transaction_as_sponsor(config, &tx_bytes_b64).await?;

    // 8. 提交（用户签名 + sponsor 签名）
    execute_tx(config, &tx_bytes_b64, vec![user_signature_b64.to_string(), sponsor_signature]).await
}

/// 提交 tick 交易（sponsor 同时为 sender 与 gas owner）。
///
/// 流程：
/// 1. 构建 tick PTB（复用 [`ptb::build_tick_ptb`]）
/// 2. 序列化为 `TransactionKind`（复用 [`ptb::serialize_tx_kind`]）
/// 3. 获取 sponsor gas 信息（复用 [`sponsor::fetch_gas_info`]）
/// 4. 构建完整 [`Transaction`]（sender=sponsor, gas_owner=sponsor）
/// 5. sponsor 签名（复用 [`sponsor::sign_transaction_as_sponsor`]）
/// 6. 提交到 Sui 网络（`sui_executeTransactionBlock`）
/// 7. 检查执行状态
///
/// # 参数
/// - `config`：包含 sponsor 私钥、package id、clock object id 等配置
/// - `table_id`：链上 Table 对象的 Object ID（hex 字符串）
///
/// # 返回
/// 成功时返回交易 digest 字符串。
pub async fn submit_tick_tx(
    config: &Config,
    table_id: &str,
) -> Result<String, String> {
    if config.sponsor_private_key.is_empty() {
        return Err("Sponsor service not configured".to_string());
    }

    // 1. 构建 tick PTB
    let pt = ptb::build_tick_ptb(
        &config.sui_package_id,
        table_id,
        &config.sui_clock_object_id,
    )?;

    // 1.5 解析 shared object 的 initial_shared_version（placeholder 0 → 真实版本）。
    //     公共 Sui 全节点的 sui_executeTransactionBlock 不会自动解析 version 0，
    //     必须显式解析，否则返回 -32602 "Invalid value was given to the function"。
    let http = shared_http_client();
    let pt = ptb::resolve_shared_object_versions(http, &config.fullnode_url, pt).await?;

    // 2. 序列化为 TransactionKind (base64)
    let tx_kind_b64 = ptb::serialize_tx_kind(pt)?;

    // 3. 解码 TransactionKind
    let tx_kind = decode_tx_kind(&tx_kind_b64)?;

    // 4. 获取 sponsor gas 信息
    let gas_info = sponsor::fetch_gas_info(config).await
        .map_err(|e| format!("fetch_gas_info: {}", e))?;

    // 5. 解析 sponsor 地址（sender = gas_owner = sponsor）
    let sender: Address = gas_info
        .sponsor_address
        .parse()
        .map_err(|e| format!("Invalid sponsor address: {}", e))?;

    // 6. 构建 GasPayment（owner = sponsor）
    let gas_payment = build_gas_payment(&gas_info, sender, config.sponsor_gas_budget)?;

    // F14: 获取当前 epoch，设置交易过期时间（当前 epoch + 2），避免交易无过期被重放
    let current_epoch = get_current_epoch(config).await
        .map_err(|e| format!("get_current_epoch: {}", e))?;

    // 7. 构建完整 Transaction
    let transaction = Transaction {
        kind: tx_kind,
        sender,
        gas_payment,
        expiration: TransactionExpiration::Epoch(current_epoch + 2),
    };

    // 8. BCS 序列化
    let tx_bytes = bcs::to_bytes(&transaction)
        .map_err(|e| format!("Transaction BCS serialization failed: {}", e))?;
    let tx_bytes_b64 = base64_encode(&tx_bytes);

    // 9. sponsor 签名（sponsor 同时是 sender 和 gas owner，只需一个签名）
    let sponsor_signature =
        sponsor::sign_transaction_as_sponsor(config, &tx_bytes_b64).await?;

    // 10. 提交（只需 sponsor 一个签名）
    execute_tx(config, &tx_bytes_b64, vec![sponsor_signature]).await
        .map_err(|e| format!("execute_tx: {}", e))
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 sponsor_private_key 为空的 Config，用于验证错误路径。
    fn make_empty_config() -> Config {
        Config {
            port: 9001,
            jwt_secret: String::new(),
            jwt_token_expires_in: 0,
            betting_timeout_secs: 0,
            showdown_display_secs: 0,
            hand_complete_wait_secs: 0,
            ready_countdown_secs: 0,
            max_players_per_table: 0,
            sponsor_private_key: zeroize::Zeroizing::new(String::new()),
            sponsor_gas_budget: 0,
            fullnode_url: String::new(),
            grpc_url: String::new(),
            zklogin_salt_secret: String::new(),
            inodra_webhook_secret: String::new(),
            sui_package_id: String::new(),
            sui_origin_package_id: String::new(),
            sui_network: String::new(),
            sui_event_provider: String::new(),
            sui_tick_interval_ms: 0,
            sui_clock_object_id: "0x6".to_string(),
            sui_on_chain_enabled: false,
            shinami_api_key: String::new(),
        }
    }

    #[tokio::test]
    #[ignore = "requires network access and valid sponsor config"]
    async fn test_submit_tick_tx_invalid_config() {
        let config = make_empty_config();
        let result = submit_tick_tx(&config, "0x1234").await;
        assert!(result.is_err(), "should fail with empty sponsor_private_key");
        let err = result.unwrap_err();
        assert!(
            err.contains("Sponsor service not configured"),
            "error should mention sponsor not configured, got: {}",
            err
        );
    }

    #[tokio::test]
    #[ignore = "requires network access and valid sponsor config"]
    async fn test_submit_sponsored_tx_invalid_config() {
        let config = make_empty_config();
        let result =
            submit_sponsored_tx(&config, "AAAA", "0x1234", "AAAA").await;
        assert!(result.is_err(), "should fail with empty sponsor_private_key");
        let err = result.unwrap_err();
        assert!(
            err.contains("Sponsor service not configured"),
            "error should mention sponsor not configured, got: {}",
            err
        );
    }
}
