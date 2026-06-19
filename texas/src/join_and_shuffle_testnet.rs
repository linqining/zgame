//! 端到端测试：模拟客户端生成证明并调用测试网合约的 `join_and_shuffle` 方法。
//!
//! # 运行方式
//!
//! ```sh
//! SENDER_PRIVATE_KEY=suiprivkey1... cargo test --package texas \
//!     join_and_shuffle_testnet --nocapture --ignored
//! ```
//!
//! # 前置条件
//!
//! - 发送方地址在测试网上有足够 SUI 余额（用于支付 gas）
//! - 目标 Table 对象处于 `round_waiting` 状态且目标座位空闲

use base64::Engine;
use poker_protocol::crypto::curve::{CurvePoint, CurveScalar};
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Scalar};
use poker_protocol::z_poker::protocol::ClientPlayer;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_crypto::SuiSigner;
use sui_sdk_types::{
    Address, Argument, Command, Digest, GasPayment, Identifier, Input, MoveCall,
    ObjectReference, ProgrammableTransaction, SharedInput, Transaction, TransactionExpiration,
    TransactionKind,
};

// ============================================================================
// 常量
// ============================================================================

/// 测试网已发布的 texas_poker_move 合约包 ID（published-at, version 2）
const PACKAGE_ID: &str = "0x9cdd1d17521d526e8a22e6fcb7ad3815575fbdda4eb5a32116b85f604c193a76";

/// 目标 Table 对象 ID
const TABLE_ID: &str = "0x93cfaad65a8582694bef8d695b052277b5e3b5cfe20d64a139f749af5f88ffc9";

/// 测试网 JSON-RPC 端点
const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";

/// Gas budget（MIST），join_and_shuffle 涉及大量 ZK 验证，需要较高预算
const GAS_BUDGET: u64 = 5_000_000_000; // 5 SUI

/// 加入的座位索引
const SEAT_INDEX: u64 = 0;

/// 买入金额（MIST）
const BUY_IN: u64 = 10_000_000_000; // 10 SUI

// ============================================================================
// 序列化辅助函数（与 move_verify_tests.rs / proof_bytes.rs 一致）
// ============================================================================

fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    p.compress().as_ref().to_vec()
}

fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.as_bytes()
}

fn ciphertexts_to_bytes(cts: &[ElGamalCiphertext]) -> Vec<u8> {
    cts.iter()
        .flat_map(|ct| {
            let mut buf = Vec::with_capacity(96);
            buf.extend_from_slice(&g1_to_bytes(&ct.c1));
            buf.extend_from_slice(&g1_to_bytes(&ct.c2));
            buf
        })
        .collect()
}

fn append_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.push((val & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
}

/// 序列化 PKOwnershipProof 为 80 字节：commitment(48) + response(32)
fn serialize_pk_ownership_proof(
    commitment: &EcPoint,
    response: &Scalar,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&g1_to_bytes(commitment));
    buf.extend_from_slice(&scalar_to_bytes(response));
    buf
}

/// 序列化 GeneralizedSchnorrProof：commitment(48) + u16(count) + count*scalar(32)
fn serialize_schnorr_proof(
    commitment: &EcPoint,
    responses: &[Scalar],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(commitment));
    let count = responses.len() as u16;
    append_u16_le(&mut buf, count);
    for resp in responses {
        buf.extend_from_slice(&scalar_to_bytes(resp));
    }
    buf
}

/// 序列化 ZKShuffleProof：sum_c1(48) + sum_c2(48) + nonce(32) + 3*schnorr_proof
fn serialize_shuffle_proof(
    sum_c1_commit: &EcPoint,
    sum_c2_commit: &EcPoint,
    nonce: &Scalar,
    combined_schnorr: (&EcPoint, &[Scalar]),
    sum_c1_schnorr: (&EcPoint, &[Scalar]),
    sum_c2_schnorr: (&EcPoint, &[Scalar]),
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(sum_c1_commit));
    buf.extend_from_slice(&g1_to_bytes(sum_c2_commit));
    buf.extend_from_slice(&scalar_to_bytes(nonce));
    buf.extend_from_slice(&serialize_schnorr_proof(
        combined_schnorr.0,
        combined_schnorr.1,
    ));
    buf.extend_from_slice(&serialize_schnorr_proof(
        sum_c1_schnorr.0,
        sum_c1_schnorr.1,
    ));
    buf.extend_from_slice(&serialize_schnorr_proof(
        sum_c2_schnorr.0,
        sum_c2_schnorr.1,
    ));
    buf
}

/// 序列化 DLEqProof (RemaskProof)：u16(count) + count*G1(48) + commitment_pk(48) + response(32) + nonce(32)
fn serialize_remask_proof(
    per_card_commitments: &[EcPoint],
    commitment_pk: &EcPoint,
    response: &Scalar,
    nonce: &Scalar,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let count = per_card_commitments.len() as u16;
    append_u16_le(&mut buf, count);
    for c in per_card_commitments {
        buf.extend_from_slice(&g1_to_bytes(c));
    }
    buf.extend_from_slice(&g1_to_bytes(commitment_pk));
    buf.extend_from_slice(&scalar_to_bytes(response));
    buf.extend_from_slice(&scalar_to_bytes(nonce));
    buf
}

// ============================================================================
// Sui JSON-RPC 辅助函数
// ============================================================================

async fn sui_jsonrpc(
    client: &reqwest::Client,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let resp = client
        .post(TESTNET_RPC)
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

/// 从 JSON 数组中提取 Vec<u8>
fn json_array_to_bytes(arr: &[serde_json::Value]) -> Vec<u8> {
    arr.iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect()
}

/// 从 Table 对象 JSON 中解析加密牌组
fn parse_encrypted_deck(data: &serde_json::Value) -> Result<Vec<ElGamalCiphertext>, String> {
    let encrypted = data["data"]["content"]["fields"]["deck_state"]["fields"]["encrypted"]
        .as_array()
        .ok_or("Missing encrypted deck in table data")?;

    let mut deck = Vec::with_capacity(encrypted.len());
    for (i, card) in encrypted.iter().enumerate() {
        let c1_bytes = json_array_to_bytes(
            card["fields"]["c1"]["fields"]["bytes"]
                .as_array()
                .ok_or_else(|| format!("Missing c1 bytes for card {}", i))?,
        );
        let c2_bytes = json_array_to_bytes(
            card["fields"]["c2"]["fields"]["bytes"]
                .as_array()
                .ok_or_else(|| format!("Missing c2 bytes for card {}", i))?,
        );

        let c1 = <EcPoint as CurvePoint>::from_compressed(&c1_bytes)
            .ok_or_else(|| format!("Failed to decompress c1 for card {}", i))?;
        let c2 = <EcPoint as CurvePoint>::from_compressed(&c2_bytes)
            .ok_or_else(|| format!("Failed to decompress c2 for card {}", i))?;

        deck.push(ElGamalCiphertext { c1, c2 });
    }
    Ok(deck)
}

/// 从 Table 对象 JSON 中提取 initial_shared_version
fn parse_initial_shared_version(data: &serde_json::Value) -> Result<u64, String> {
    let version = data["data"]["owner"]["Shared"]["initial_shared_version"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            data["data"]["owner"]["Shared"]["initial_shared_version"]
                .as_u64()
        })
        .ok_or("Missing initial_shared_version")?;
    Ok(version)
}

// ============================================================================
// 私钥解析
// ============================================================================

/// 解析 Sui CLI 导出的 Ed25519 私钥（suiprivkey1... bech32 格式）
fn parse_private_key(key_str: &str) -> Result<Ed25519PrivateKey, String> {
    let key_bytes: Vec<u8> = if key_str.starts_with("suiprivkey1") {
        let (hrp, data_u5, _variant) = bech32::decode(key_str)
            .map_err(|e| format!("Bech32 decode error: {}", e))?;
        if hrp != "suiprivkey" {
            return Err(format!("Unexpected bech32 HRP: {} (expected suiprivkey)", hrp));
        }
        bech32::FromBase32::from_base32(&data_u5)
            .map_err(|e| format!("Bech32 data convert error: {:?}", e))?
    } else {
        return Err("Private key must be in suiprivkey1... format".to_string());
    };

    let pk_bytes: [u8; 32] = if key_bytes.len() == 33 {
        if key_bytes[0] != 0 {
            return Err(format!(
                "Unsupported key flag: {} (only Ed25519=0 is supported)",
                key_bytes[0]
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes[1..33]);
        arr
    } else if key_bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes[..32]);
        arr
    } else {
        return Err(format!(
            "Invalid private key length: {} bytes (expected 32 or 33)",
            key_bytes.len()
        ));
    };

    Ok(Ed25519PrivateKey::new(pk_bytes))
}

// ============================================================================
// PTB 构建
// ============================================================================

fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bcs::to_bytes(value).map_err(|e| format!("BCS serialization failed: {}", e))
}

/// 构建 join_and_shuffle PTB（使用真实的 initial_shared_version）
fn build_join_and_shuffle_ptb(
    package_id: &str,
    table_id: &str,
    initial_shared_version: u64,
    seat_index: u64,
    buy_in: u64,
    pk: Vec<u8>,
    pk_ownership_proof: Vec<u8>,
    mask_cards: Vec<u8>,
    output_cards: Vec<u8>,
    remask_proof_bytes: Vec<u8>,
    shuffle_proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let table_addr: Address = table_id
        .parse()
        .map_err(|e| format!("invalid table_id '{}': {}", table_id, e))?;
    let package: Address = package_id
        .parse()
        .map_err(|e| format!("invalid package_id '{}': {}", package_id, e))?;

    let inputs = vec![
        // Input(0): &mut Table (shared, mutable, with real initial_shared_version)
        Input::Shared(SharedInput::new(table_addr, initial_shared_version, true)),
        // Input(1): seat_index: u64
        Input::Pure(bcs_encode(&seat_index)?),
        // Input(2): buy_in: u64
        Input::Pure(bcs_encode(&buy_in)?),
        // Input(3): pk: vector<u8>
        Input::Pure(bcs_encode(&pk)?),
        // Input(4): pk_ownership_proof: vector<u8>
        Input::Pure(bcs_encode(&pk_ownership_proof)?),
        // Input(5): mask_cards: vector<u8>
        Input::Pure(bcs_encode(&mask_cards)?),
        // Input(6): output_cards: vector<u8>
        Input::Pure(bcs_encode(&output_cards)?),
        // Input(7): remask_proof_bytes: vector<u8>
        Input::Pure(bcs_encode(&remask_proof_bytes)?),
        // Input(8): shuffle_proof_bytes: vector<u8>
        Input::Pure(bcs_encode(&shuffle_proof_bytes)?),
    ];

    let arguments = vec![0u16, 1, 2, 3, 4, 5, 6, 7, 8]
        .into_iter()
        .map(Argument::Input)
        .collect();
    let commands = vec![Command::MoveCall(MoveCall {
        package,
        module: Identifier::new("table").map_err(|e| format!("invalid module: {}", e))?,
        function: Identifier::new("join_and_shuffle_verified")
            .map_err(|e| format!("invalid function: {}", e))?,
        type_arguments: Vec::new(),
        arguments,
    })];

    Ok(ProgrammableTransaction { inputs, commands })
}

// ============================================================================
// Gas 与交易提交
// ============================================================================

struct GasCoinInfo {
    coin_id: Address,
    version: u64,
    digest: Digest,
}

/// 获取发送方的第一个 gas coin 信息
async fn fetch_gas_coin(
    http: &reqwest::Client,
    sender: &Address,
) -> Result<GasCoinInfo, String> {
    let coins_resp = sui_jsonrpc(
        http,
        "suix_getCoins",
        vec![serde_json::to_value(sender).map_err(|e| format!("{}", e))?],
    )
    .await?;

    let coins = coins_resp
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or("No gas coins found")?;

    if coins.is_empty() {
        return Err("Sender has no gas coins".to_string());
    }

    // 选择余额最大的 coin
    let coin = coins
        .iter()
        .max_by_key(|c| {
            c["balance"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        })
        .ok_or("Failed to select gas coin")?;

    let coin_id: Address = coin["coinObjectId"]
        .as_str()
        .ok_or("Missing coinObjectId")?
        .parse()
        .map_err(|e| format!("Invalid coin id: {}", e))?;
    let version: u64 = coin["version"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| coin["version"].as_u64())
        .ok_or("Missing version")?;
    let digest: Digest = coin["digest"]
        .as_str()
        .ok_or("Missing digest")?
        .parse()
        .map_err(|e| format!("Invalid digest: {}", e))?;

    Ok(GasCoinInfo {
        coin_id,
        version,
        digest,
    })
}

/// 获取参考 gas price
async fn fetch_reference_gas_price(http: &reqwest::Client) -> Result<u64, String> {
    let resp = sui_jsonrpc(http, "suix_getReferenceGasPrice", vec![]).await?;
    resp.as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| resp.as_u64())
        .ok_or_else(|| "Failed to parse reference gas price".to_string())
}

/// 提交交易并返回 digest
async fn execute_tx(
    http: &reqwest::Client,
    tx_bytes_b64: &str,
    signature_b64: &str,
) -> Result<serde_json::Value, String> {
    let result = sui_jsonrpc(
        http,
        "sui_executeTransactionBlock",
        vec![
            serde_json::Value::String(tx_bytes_b64.to_string()),
            serde_json::Value::Array(vec![serde_json::Value::String(
                signature_b64.to_string(),
            )]),
            serde_json::json!({
                "showEffects": true,
                "showEvents": true,
                "showObjectChanges": true,
            }),
        ],
    )
    .await?;

    let status = result["effects"]["status"]["status"]
        .as_str()
        .ok_or("Missing execution status")?;

    if status != "success" {
        let error = result["effects"]["status"]["error"]
            .as_str()
            .unwrap_or("unknown error");
        return Err(format!("Transaction execution failed: {}", error));
    }

    Ok(result)
}

// ============================================================================
// 主测试
// ============================================================================

#[tokio::test]
#[ignore = "requires testnet access and funded wallet (set SENDER_PRIVATE_KEY env var)"]
async fn test_join_and_shuffle_on_testnet() {
    // ---- 1. 读取发送方私钥 ----
    let key_str = std::env::var("SENDER_PRIVATE_KEY").expect(
        "Set SENDER_PRIVATE_KEY env var to a suiprivkey1... private key with testnet SUI",
    );
    let private_key = parse_private_key(&key_str).expect("Failed to parse private key");
    let public_key = private_key.public_key();
    let sender = public_key.derive_address();
    println!("Sender address: {}", sender);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap();

    // ---- 2. 获取 Table 对象状态 ----
    println!("Fetching table {} from testnet...", TABLE_ID);
    let table_data = sui_jsonrpc(
        &http,
        "sui_getObject",
        vec![
            serde_json::Value::String(TABLE_ID.to_string()),
            serde_json::json!({
                "showType": true,
                "showOwner": true,
                "showContent": true,
            }),
        ],
    )
    .await
    .expect("Failed to fetch table");

    let initial_shared_version = parse_initial_shared_version(&table_data)
        .expect("Failed to parse initial_shared_version");
    println!("initial_shared_version: {}", initial_shared_version);

    // ---- 3. 解析链上加密牌组 ----
    let input_cards = parse_encrypted_deck(&table_data).expect("Failed to parse encrypted deck");
    println!("Parsed {} encrypted cards from table", input_cards.len());
    assert_eq!(input_cards.len(), 52, "Expected 52 cards in deck");

    // ---- 4. 生成 ElGamal 密钥对与证明 ----
    println!("Generating ElGamal keypair and ZK proofs...");
    let player = ClientPlayer::new();
    let pk_hex = hex::encode(player.pk.compress().as_ref());
    println!("Player pk: {}", pk_hex);

    // aggregated_pk 为空，curr_share_pk = identity，share_pk = identity + pk = pk
    let curr_share_pk = EcPoint::identity();
    let join_round = player.join_game_and_shuffle(&input_cards, &curr_share_pk);

    // 序列化各字段为 Move 合约期望的字节格式
    let pk_bytes = g1_to_bytes(&player.pk);
    assert_eq!(pk_bytes.len(), 48, "pk must be 48 bytes");

    let pk_ownership_proof_bytes = serialize_pk_ownership_proof(
        &join_round.pk_ownership_proof.commitment,
        &join_round.pk_ownership_proof.response,
    );
    assert_eq!(
        pk_ownership_proof_bytes.len(),
        80,
        "pk_ownership_proof must be 80 bytes"
    );

    let output_cards_bytes = ciphertexts_to_bytes(&join_round.mask_and_shuffle_round.output_cards);
    assert_eq!(
        output_cards_bytes.len(),
        52 * 96,
        "output_cards must be 52*96 bytes"
    );

    let mask_cards_bytes = ciphertexts_to_bytes(&join_round.mask_and_shuffle_round.mask_cards);
    assert_eq!(
        mask_cards_bytes.len(),
        52 * 96,
        "mask_cards must be 52*96 bytes"
    );

    let remask_proof_bytes = serialize_remask_proof(
        &join_round.mask_and_shuffle_round.remask_proof.per_card_commitments,
        &join_round.mask_and_shuffle_round.remask_proof.commitment_pk,
        &join_round.mask_and_shuffle_round.remask_proof.response,
        &join_round.mask_and_shuffle_round.remask_proof.nonce,
    );

    let shuffle_proof = &join_round.mask_and_shuffle_round.proof;
    let shuffle_proof_bytes = serialize_shuffle_proof(
        &shuffle_proof.sum_c1_commit,
        &shuffle_proof.sum_c2_commit,
        &shuffle_proof.nonce,
        (
            &shuffle_proof.combined_schnorr_proof.commitment,
            &shuffle_proof.combined_schnorr_proof.responses,
        ),
        (
            &shuffle_proof.sum_c1_schnorr_proof.commitment,
            &shuffle_proof.sum_c1_schnorr_proof.responses,
        ),
        (
            &shuffle_proof.sum_c2_schnorr_proof.commitment,
            &shuffle_proof.sum_c2_schnorr_proof.responses,
        ),
    );

    println!("pk_bytes: {} bytes", pk_bytes.len());
    println!("pk_ownership_proof: {} bytes", pk_ownership_proof_bytes.len());
    println!("mask_cards: {} bytes", mask_cards_bytes.len());
    println!("output_cards: {} bytes", output_cards_bytes.len());
    println!("remask_proof: {} bytes", remask_proof_bytes.len());
    println!("shuffle_proof: {} bytes", shuffle_proof_bytes.len());

    // ---- 5. 构建 PTB ----
    println!("Building PTB...");
    let pt = build_join_and_shuffle_ptb(
        PACKAGE_ID,
        TABLE_ID,
        initial_shared_version,
        SEAT_INDEX,
        BUY_IN,
        pk_bytes,
        pk_ownership_proof_bytes,
        mask_cards_bytes,
        output_cards_bytes,
        remask_proof_bytes,
        shuffle_proof_bytes,
    )
    .expect("Failed to build PTB");

    let tx_kind = TransactionKind::ProgrammableTransaction(pt);

    // ---- 6. 获取 gas 信息 ----
    println!("Fetching gas info for sender...");
    let gas_coin = fetch_gas_coin(&http, &sender)
        .await
        .expect("Failed to fetch gas coin");
    let gas_price = fetch_reference_gas_price(&http)
        .await
        .expect("Failed to fetch gas price");

    println!(
        "Gas coin: {} (version {}, price {})",
        gas_coin.coin_id, gas_coin.version, gas_price
    );

    // ---- 7. 构建完整 Transaction ----
    let gas_payment = GasPayment {
        objects: vec![ObjectReference::new(
            gas_coin.coin_id,
            gas_coin.version,
            gas_coin.digest,
        )],
        owner: sender,
        price: gas_price,
        budget: GAS_BUDGET,
    };

    let transaction = Transaction {
        kind: tx_kind,
        sender,
        gas_payment,
        expiration: TransactionExpiration::None,
    };

    let tx_bytes = bcs::to_bytes(&transaction).expect("Failed to BCS-serialize transaction");
    let engine = base64::engine::general_purpose::STANDARD;
    let tx_bytes_b64 = engine.encode(&tx_bytes);
    println!("Transaction bytes: {} bytes (base64)", tx_bytes.len());

    // ---- 8. 签名 ----
    println!("Signing transaction...");
    let user_signature = private_key
        .sign_transaction(&transaction)
        .expect("Failed to sign transaction");
    let sig_bytes = user_signature.to_bytes();
    let sig_b64 = engine.encode(&sig_bytes);

    // ---- 8a. Dry Run 验证交易 ----
    println!("Dry-running transaction to validate...");
    let dry_run_result = sui_jsonrpc(
        &http,
        "sui_dryRunTransactionBlock",
        vec![serde_json::Value::String(tx_bytes_b64.clone())],
    )
    .await;

    match &dry_run_result {
        Ok(dr) => {
            let status = dr["effects"]["status"]["status"]
                .as_str()
                .unwrap_or("unknown");
            println!("Dry run status: {}", status);
            if status != "success" {
                let error = dr["effects"]["status"]["error"]
                    .as_str()
                    .unwrap_or("unknown");
                println!("Dry run error: {}", error);
            }
            if let Some(gas_used) = dr["effects"]["gasUsed"].as_object() {
                let computation = gas_used["computationCost"]
                    .as_str()
                    .or_else(|| gas_used["computationCost"].as_u64().map(|_| "n"))
                    .unwrap_or("?");
                let storage = gas_used["storageCost"]
                    .as_str()
                    .unwrap_or("?");
                println!(
                    "Gas estimate: computation={}, storage={}",
                    computation, storage
                );
            }
        }
        Err(e) => {
            println!("Dry run failed (non-fatal): {}", e);
        }
    }

    // ---- 9. 提交交易 ----
    println!("Submitting transaction to testnet...");
    let result = execute_tx(&http, &tx_bytes_b64, &sig_b64)
        .await
        .expect("Transaction submission failed");

    let digest = result["digest"].as_str().unwrap_or("unknown");
    println!("=================================================");
    println!("Transaction digest: {}", digest);
    println!("=================================================");

    // 打印事件
    if let Some(events) = result["events"].as_array() {
        println!("\nEvents ({}):", events.len());
        for (i, event) in events.iter().enumerate() {
            let event_type = event["type"].as_str().unwrap_or("unknown");
            println!("  [{}] {}", i, event_type);
            if let Some(parsed_json) = event.get("parsedJson") {
                println!("       {:?}", parsed_json);
            }
        }
    }

    // 验证执行效果
    let status = result["effects"]["status"]["status"]
        .as_str()
        .unwrap_or("unknown");
    assert_eq!(status, "success", "Transaction should succeed");

    println!("\njoin_and_shuffle completed successfully!");
    println!("Player {} joined seat {} with buy_in {}", sender, SEAT_INDEX, BUY_IN);
}
