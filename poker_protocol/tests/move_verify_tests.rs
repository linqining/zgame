//! 链上合约 verify 方法端到端测试
//!
//! 本模块通过 `sui_devInspectTransactionBlock` 调用测试网上已发布的 Move 合约
//! (`0x9cdd1d17521d526e8a22e6fcb7ad3815575fbdda4eb5a32116b85f604c193a76`)
//! 中的各个 verify 方法，验证 Rust 端生成的真实证明能被 Move 合约正确验证。
//!
//! # 运行方式
//!
//! 所有测试标记为 `#[ignore]`（需要网络访问），运行方式：
//! ```sh
//! cargo test --package poker_protocol --test move_verify_tests --nocapture --ignored
//! ```
//!
//! # 测试覆盖
//!
//! | 测试函数 | Move verify 方法 | 对应 Rust 证明 |
//! |---------|-----------------|---------------|
//! | `test_verify_pk_ownership_on_testnet` | `zk_verifier::verify_pk_ownership` | `PKOwnershipProof` |
//! | `test_verify_shuffle_on_testnet` | `zk_verifier::verify_shuffle` | `ZKShuffleProof` |
//! | `test_verify_remask_on_testnet` | `zk_verifier::verify_remask` | `DLEqProof<RemaskKind>` |
//! | `test_verify_leave_on_testnet` | `zk_verifier::verify_leave` | `DLEqProof<LeaveKind>` |
//! | `test_verify_reveal_token_on_testnet` | `zk_verifier::verify_reveal_token` | `RevealTokenProof` |
//! | `test_verify_reconstruct_on_testnet` | `zk_verifier::verify_reconstruct` | `ReconstructProof` |

use base64::Engine;
use group::Group;
use poker_protocol::crypto::{
    DefaultCurve, EcPoint, ElGamalCiphertext, Scalar,
};
use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol::zk_shuffle::dleq_proof::DLEqProof;
use poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
use poker_protocol::zk_shuffle::reconstruction::{
    ChaumPedersenDLEQProof, ReconstructionDLEQProof, ReconstructProof, SwapOutCardProof,
};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::z_poker::protocol::new_plain_text;
use rand::rngs::OsRng;
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
    TransactionKind,
};

// ============================================================================
// 常量
// ============================================================================

/// 测试网已发布的 texas_poker_move 合约包 ID
/// （第四版：g1_msm 使用 g1_mul 循环 + deserialize_g1_points 函数）
const PACKAGE_ID: &str = "0x9cdd1d17521d526e8a22e6fcb7ad3815575fbdda4eb5a32116b85f604c193a76";

/// 测试网 JSON-RPC 端点
const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";

/// ElGamal 密文字节数（c1:48 + c2:48）
const CIPHERTEXT_SIZE: usize = 96;

// ============================================================================
// 序列化辅助函数
// ============================================================================

/// 将 G1 点序列化为 48 字节压缩格式
fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    p.compress().as_ref().to_vec()
}

/// 将标量序列化为 32 字节
fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.as_bytes()
}

/// 将 ElGamal 密文序列化为 96 字节（c1:48 + c2:48）
fn ciphertext_to_bytes(ct: &ElGamalCiphertext) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CIPHERTEXT_SIZE);
    buf.extend_from_slice(&g1_to_bytes(&ct.c1));
    buf.extend_from_slice(&g1_to_bytes(&ct.c2));
    buf
}

/// 将密文数组序列化为 flat bytes
fn ciphertexts_to_bytes(cts: &[ElGamalCiphertext]) -> Vec<u8> {
    cts.iter().flat_map(ciphertext_to_bytes).collect()
}

/// 将 u16 以小端序写入 buffer
fn append_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.push((val & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
}

/// 序列化 GeneralizedSchnorrProof 为 Move 合约期望的字节格式
/// 格式: commitment(48) + u16(count) + count*scalar(32)
fn serialize_schnorr_proof(proof: &GeneralizedSchnorrProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    let count = proof.responses.len() as u16;
    append_u16_le(&mut buf, count);
    for resp in &proof.responses {
        buf.extend_from_slice(&scalar_to_bytes(resp));
    }
    buf
}

/// 序列化 ZKShuffleProof 为 Move 合约期望的字节格式
/// 格式: sum_c1(48) + sum_c2(48) + nonce(32) + 3*schnorr_proof
fn serialize_shuffle_proof(proof: &ZKShuffleProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c1_commit));
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c2_commit));
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.combined_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_c1_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_c2_schnorr_proof));
    buf
}

/// 序列化 DLEqProof (RemaskProof/LeaveProof) 为 Move 合约期望的字节格式
/// 格式: u16(count) + count*G1(48) + commitment_pk(48) + response(32) + nonce(32)
fn serialize_dleq_proof<C: Curve, K: poker_protocol::zk_shuffle::dleq_proof::DLEqProofKind<C>>(
    proof: &DLEqProof<C, K>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let count = proof.per_card_commitments.len() as u16;
    append_u16_le(&mut buf, count);
    for c in &proof.per_card_commitments {
        buf.extend_from_slice(&c.compress().as_ref());
    }
    buf.extend_from_slice(&proof.commitment_pk.compress().as_ref());
    buf.extend_from_slice(&proof.response.as_bytes());
    buf.extend_from_slice(&proof.nonce.as_bytes());
    buf
}

/// 序列化 RevealTokenProof 为 Move 合约期望的字节格式
/// 格式: user_pk(48) + t1(48) + t2(48) + response_s(32) + nonce(32)
/// M4 修复：包含 nonce 字段（对齐 Move reveal_token_proof.move）
fn serialize_reveal_token_proof(proof: &RevealTokenProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.user_public_key));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t1));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t2));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response_s));
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    buf
}

/// 序列化 ChaumPedersenDLEQProof 为字节
/// 格式: commitment_a(48) + commitment_b(48) + response(32)
fn serialize_chaum_pedersen(proof: &ChaumPedersenDLEQProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_a));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_b));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf
}

/// 序列化 ReconstructionDLEQProof 为字节
/// 格式: commitment(48) + response(32) + nonce(32)
fn serialize_recon_dleq(proof: &ReconstructionDLEQProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    buf
}

/// 序列化 SwapOutCardProof 为字节
/// 格式: user_readable_card(96) + swap_out_card(96) + chaum_pedersen(48+48+32)
fn serialize_swap_out_proof(proof: &SwapOutCardProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.user_readable_card.c1));
    buf.extend_from_slice(&g1_to_bytes(&proof.user_readable_card.c2));
    buf.extend_from_slice(&g1_to_bytes(&proof.swap_out_card.c1));
    buf.extend_from_slice(&g1_to_bytes(&proof.swap_out_card.c2));
    buf.extend_from_slice(&serialize_chaum_pedersen(&proof.chaum_pedersen_proof));
    buf
}

/// 序列化 ReconstructProof 为 Move 合约期望的字节格式
fn serialize_reconstruct_proof(proof: &ReconstructProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    // swap_out_proofs
    let swap_count = proof.swap_out_cards_proofs.len() as u16;
    append_u16_le(&mut buf, swap_count);
    for sop in &proof.swap_out_cards_proofs {
        buf.extend_from_slice(&serialize_swap_out_proof(sop));
    }
    // 4 个 G1 commit
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c1_r_commit));
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c2_r_commit));
    buf.extend_from_slice(&g1_to_bytes(&proof.swap_sum_c1_commit));
    buf.extend_from_slice(&g1_to_bytes(&proof.swap_sum_c2_commit));
    // nonce
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    // blind_dleq_proof
    buf.extend_from_slice(&serialize_recon_dleq(&proof.blind_dleq_proof));
    // total_dleq_proof
    buf.extend_from_slice(&serialize_chaum_pedersen(&proof.total_dleq_proof));
    // 3 个 schnorr proof
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.swap_combined_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_swap_out_c1_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_swap_out_c2_schnorr_proof));
    buf
}

// ============================================================================
// PTB 构建辅助函数
// ============================================================================

fn parse_address(s: &str) -> Result<Address, String> {
    s.parse::<Address>()
        .map_err(|e| format!("invalid address '{}': {}", s, e))
}

fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bcs::to_bytes(value).map_err(|e| format!("BCS serialization failed: {}", e))
}

/// 创建 Pure 输入（BCS 编码的 vector<u8>）
fn pure_bytes(bytes: Vec<u8>) -> Input {
    Input::Pure(bcs_encode(&bytes).expect("BCS encode vector<u8> should not fail"))
}

/// 创建 Pure 输入（直接传入原始字节，不做 BCS 编码）
/// 用于当 Input::Pure 的内容已经是 BCS 编码的 Move 值时
#[allow(dead_code)]
fn pure_raw(bytes: Vec<u8>) -> Input {
    Input::Pure(bytes)
}

/// 将 ProgrammableTransaction 序列化为 base64 编码的 TransactionKind
fn serialize_tx_kind(pt: ProgrammableTransaction) -> Result<String, String> {
    let tx_kind = TransactionKind::ProgrammableTransaction(pt);
    let bytes = bcs::to_bytes(&tx_kind)
        .map_err(|e| format!("TransactionKind BCS serialization failed: {}", e))?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(engine.encode(&bytes))
}

// ============================================================================
// Dev Inspect 辅助函数
// ============================================================================

/// 通过 `sui_devInspectTransactionBlock` 调用测试网合约
///
/// 返回 (执行是否成功, 最后一个 command 的 bool 返回值)
/// 如果最后一个 command 返回的不是 bool，则 bool 部分为 None
async fn dev_inspect(pt: ProgrammableTransaction) -> Result<(bool, Option<bool>), String> {
    let tx_kind_b64 = serialize_tx_kind(pt)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_devInspectTransactionBlock",
        "params": [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            tx_kind_b64,
            null,
            null,
            {
                "show_effects": true,
                "show_input": true,
                "show_object_changes": true,
                "show_raw_input": false,
                "show_raw_effects": false
            }
        ]
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(TESTNET_RPC)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    let result = resp
        .get("result")
        .ok_or("No result in dev inspect response")?;

    // 检查执行状态
    let status = result
        .get("effects")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.get("status"))
        .and_then(|s| s.as_str())
        .ok_or("Missing execution status in dev inspect response")?;

    if status != "success" {
        let error = result
            .get("effects")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Dev inspect execution failed: {}", error));
    }

    // 尝试从最后一个 command 的 returnValues[0] 提取 bool
    // BCS 编码的 bool: 0x00 = false, 0x01 = true
    // returnValues 格式: [[bytes_array, type_string], ...]
    // bytes_array 可能是 base64 字符串或数字数组
    let results_arr = result.get("results").and_then(|r| r.as_array());

    let bool_result = results_arr
        .and_then(|results| results.last())
        .and_then(|last| last.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .and_then(|val| val.get(0))
        .and_then(|v| {
            // 尝试解析为数字数组
            if let Some(arr) = v.as_array() {
                let bytes: Vec<u8> = arr.iter().filter_map(|n| n.as_u64().map(|b| b as u8)).collect();
                Some(bytes)
            } else if let Some(b64) = v.as_str() {
                // 也尝试 base64 解码
                let engine = base64::engine::general_purpose::STANDARD;
                engine.decode(b64).ok()
            } else {
                None
            }
        })
        .and_then(|bytes| {
            if bytes.len() == 1 {
                Some(bytes[0] != 0)
            } else {
                None
            }
        });

    Ok((true, bool_result))
}

/// 通过 dev inspect 调用测试网合约，提取最后一个 command 的 bool 返回值
async fn dev_inspect_verify(pt: ProgrammableTransaction) -> Result<bool, String> {
    let (success, bool_val) = dev_inspect(pt).await?;
    if !success {
        return Err("Dev inspect execution failed".to_string());
    }
    match bool_val {
        Some(v) => Ok(v),
        None => Err("Last command did not return a 1-byte bool value".to_string()),
    }
}

// ============================================================================
// 测试数据生成辅助
// ============================================================================

/// 生成 52 张明文牌
fn make_plaintext_cards() -> Vec<EcPoint> {
    new_plain_text()
}

/// 用随机密钥加密 52 张牌
fn make_encrypted_deck(pk: &EcPoint) -> Vec<ElGamalCiphertext> {
    make_plaintext_cards()
        .iter()
        .map(|pt| ElGamalCiphertext::encrypt(pt, pk, &Scalar::random(&mut OsRng)))
        .collect()
}

// ============================================================================
// 测试用例
// ============================================================================

/// 测试 `zk_verifier::verify_pk_ownership` 能验证 Rust 生成的 PKOwnershipProof
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_pk_ownership_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let proof = player.generate_pk_proof();

    // 2. 序列化为字节
    let pk_bytes = g1_to_bytes(&player.pk);
    let commitment_bytes = g1_to_bytes(&proof.commitment);
    let response_bytes = scalar_to_bytes(&proof.response);
    eprintln!("pk_bytes first byte: {:02x}", pk_bytes[0]);
    eprintln!("commitment_bytes first byte: {:02x}", commitment_bytes[0]);
    eprintln!("response_bytes first byte: {:02x}", response_bytes[0]);

    // 验证 commitment 可以被本地反序列化
    let recovered: Option<<DefaultCurve as Curve>::Point> = CurvePoint::from_compressed(commitment_bytes.as_slice());
    assert!(recovered.is_some(), "commitment should be locally deserializable as G1 point");
    // 验证 commitment 的压缩格式正确（最高位 = 1）
    eprintln!("commitment first byte: {:02x} (should have MSB=1 for compressed)", commitment_bytes[0]);
    assert!(commitment_bytes[0] & 0x80 != 0, "commitment first byte should have MSB set (compressed format)");

    let mut proof_bytes = Vec::with_capacity(80);
    proof_bytes.extend_from_slice(&commitment_bytes);
    proof_bytes.extend_from_slice(&response_bytes);
    assert_eq!(proof_bytes.len(), 80, "pk_ownership_proof must be 80 bytes");

    // 3. 构建 PTB — 先单独测试 deserialize_pk
    // 验证 G1 generator 压缩字节与 Sui 框架一致
    let g = <DefaultCurve as Curve>::Point::generator();
    let g_bytes = g1_to_bytes(&g);
    eprintln!("Rust G1 generator bytes: {}", hex::encode(&g_bytes));
    // Sui G1_GENERATOR_BYTES: 151,241,211,167,49,151,215,148,38,149,99,140,79,169,172,15,195,104,140,79,151,116,185,5,161,78,58,63,23,27,172,88,108,85,232,63,249,122,26,239,251,58,240,10,219,34,198,187
    let sui_generator: [u8; 48] = [151,241,211,167,49,151,215,148,38,149,99,140,79,169,172,15,195,104,140,79,151,116,185,5,161,78,58,63,23,27,172,88,108,85,232,63,249,122,26,239,251,58,240,10,219,34,198,187];
    eprintln!("Sui  G1 generator bytes: {}", hex::encode(&sui_generator[..]));
    assert_eq!(g_bytes.as_slice(), &sui_generator[..], "G1 generator bytes must match Sui framework");

    let inputs = vec![
        pure_bytes(pk_bytes.clone()),    // Input(0): pk
    ];
    let commands = vec![
        // Command 0: deserialize pk
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网 — deserialize_pk 应该成功执行
    let (success, _) = dev_inspect(pt).await.expect("deserialize_pk dev inspect should succeed");
    assert!(success, "deserialize_pk should execute successfully");

    // 5. 测试 commitment_bytes 能否被 deserialize_pk 反序列化
    let inputs = vec![
        pure_bytes(commitment_bytes.clone()),    // Input(0): commitment_bytes
    ];
    let commands = vec![
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };
    let (success, _) = dev_inspect(pt).await.expect("deserialize_pk(commitment) should succeed");
    assert!(success, "deserialize_pk(commitment) should execute successfully");
    eprintln!("deserialize_pk(commitment) succeeded!");

    // 6. 测试 proof_bytes 传入后能否正确拆分
    // 先测试：把 proof_bytes 传入，然后只调用 deserialize_pk(proof_bytes[0..48])
    // 但 Move 不支持切片，所以我们直接测试 verify_pk_ownership 的内部逻辑
    // 改为：直接把 commitment_bytes 和 response_bytes 分别传入，验证它们都能被反序列化
    // 同时测试：把 proof_bytes 传入 deserialize_pk 看前48字节是否有效
    // 注意：deserialize_pk 接收 48 字节，而 proof_bytes 是 80 字节，会失败
    // 所以我们换一种方式：直接测试完整的 verify_pk_ownership

    // 7. 现在测试完整的 verify_pk_ownership
    // 先在 Rust 端验证证明
    assert!(proof.verify(&player.pk), "PKOwnershipProof should verify locally");

    // 调试：通过 dev inspect 获取 Move 端 g1_to_bytes(pk) 的结果
    let inputs = vec![
        pure_bytes(pk_bytes.clone()),    // Input(0): pk
    ];
    let commands = vec![
        // Command 0: deserialize pk
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        // Command 1: g1_to_bytes(pk) — 获取 Move 端序列化的 pk 字节
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("bls_scalar"),
            function: Identifier::from_static("g1_to_bytes"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Result(0)],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };
    let (success, _) = dev_inspect(pt).await.expect("g1_to_bytes should succeed");
    assert!(success, "g1_to_bytes should execute successfully");

    // 使用 pure_bytes 传入 BCS 编码的 vector<u8>
    let pk_bcs = bcs_encode(&pk_bytes).expect("BCS encode pk_bytes");
    let proof_bcs = bcs_encode(&proof_bytes).expect("BCS encode proof_bytes");
    eprintln!("pk_bcs len={}, first byte={:02x}", pk_bcs.len(), pk_bcs[0]);
    eprintln!("proof_bcs len={}, first byte={:02x}", proof_bcs.len(), proof_bcs[0]);
    // BCS 编码 vector<u8>: ULEB128(len) + data
    // pk_bytes 48字节 -> ULEB128(48)=0x30 + 48字节 = 49字节
    // proof_bytes 80字节 -> ULEB128(80)=0x50 + 80字节 = 81字节
    assert_eq!(pk_bcs.len(), 49, "BCS encoded pk_bytes should be 49 bytes");
    assert_eq!(proof_bcs.len(), 81, "BCS encoded proof_bytes should be 81 bytes");

    let inputs = vec![
        Input::Pure(pk_bcs),    // Input(0): pk (BCS 编码的 vector<u8>)
        Input::Pure(proof_bcs), // Input(1): proof_bytes (BCS 编码的 vector<u8>)
    ];
    let commands = vec![
        // Command 0: deserialize pk
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        // Command 1: verify_pk_ownership
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_pk_ownership"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Result(0), Argument::Input(1)],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 6. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 7. 断言
    assert!(result, "verify_pk_ownership should return true for honest proof");
    println!("[PASS] verify_pk_ownership on testnet");
}

/// 测试 `zk_verifier::verify_shuffle` 能验证 Rust 生成的 ZKShuffleProof
///
/// 注意：当前 Sui testnet 的 `internal_multi_scalar_mul` 对 52 张牌的 MSM 会 abort
/// （ENotSupported, code 0），可能是 gas 或计算量限制。
/// 使用少量牌（N_CARDS=2）来验证证明逻辑正确性。
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_shuffle_on_testnet() {
    // 1. 生成真实证明（使用少量牌避免 MSM 计算量限制）
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let pk = player.pk.clone();

    // 生成 2 张牌的加密密文和 shuffle 证明
    let n_cards = 2usize;
    let plaintexts: Vec<EcPoint> = (0..n_cards)
        .map(|i| DefaultCurve::base_h() * Scalar::from_u64(i as u64))
        .collect();
    let input_cards: Vec<ElGamalCiphertext> = plaintexts
        .iter()
        .map(|pt| ElGamalCiphertext::encrypt(pt, &pk, &Scalar::random(&mut OsRng)))
        .collect();

    let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v1");

    // 手动执行 shuffle
    let mut rng = OsRng;
    let permute: Vec<usize> = {
        let mut arr: Vec<usize> = (0..n_cards).collect();
        use rand::seq::SliceRandom;
        arr.shuffle(&mut rng);
        arr
    };
    let mut r_values = Vec::with_capacity(n_cards);
    let mut output_cards = Vec::with_capacity(n_cards);
    for j in 0..n_cards {
        let r_j = Scalar::random(&mut rng);
        r_values.push(r_j);
        let i = permute[j];
        output_cards.push(input_cards[i].re_encrypt(&pk, &r_j));
    }

    let proof = ZKShuffleProof::prove(
        &input_cards, &output_cards, &permute, &r_values, &pk, &mut rng, &mut transcript,
    ).expect("shuffle prove failed");

    // 2. 序列化为字节
    let input_bytes = ciphertexts_to_bytes(&input_cards);
    let output_bytes = ciphertexts_to_bytes(&output_cards);
    let pk_bytes = g1_to_bytes(&pk);
    let proof_bytes = serialize_shuffle_proof(&proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(input_bytes),  // Input(0)
        pure_bytes(output_bytes), // Input(1)
        pure_bytes(pk_bytes),     // Input(2)
        pure_bytes(proof_bytes),  // Input(3)
    ];
    let commands = vec![
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(1)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_shuffle_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(3)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_shuffle"),
            type_arguments: Vec::new(),
            arguments: vec![
                Argument::Result(0),
                Argument::Result(1),
                Argument::Result(2),
                Argument::Result(3),
            ],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_shuffle should return true for honest proof");
    println!("[PASS] verify_shuffle on testnet");
}

/// 测试 `zk_verifier::verify_remask` 能验证 Rust 生成的 RemaskProof
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_remask_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let input_cards = make_encrypted_deck(&player.pk);

    // 直接使用 RemaskProof::prove 配合 Move 合约的 transcript label
    // （不使用 MaskAndShuffleRound::execute，因为它用共享 transcript "zk_mask_shuffle_proof_v1"，
    //   而 Move 端 verify_remask 使用独立的 "zk_remask_proof_v1"）
    let mask_cards: Vec<ElGamalCiphertext> = input_cards
        .iter()
        .map(|ct| poker_protocol::zk_shuffle::remask_proof::remask_ciphertext(ct, &player.sk, &player.pk, &mut OsRng).unwrap())
        .collect();
    let mut transcript = FiatShamirTranscript::new(b"zk_remask_proof_v1");
    let remask_proof = DLEqProof::<DefaultCurve, poker_protocol::zk_shuffle::dleq_proof::RemaskKind>::prove(
        &input_cards, &mask_cards, &player.sk, &player.pk, &mut transcript,
    );

    // 2. 序列化为字节
    let input_bytes = ciphertexts_to_bytes(&input_cards);
    let output_bytes = ciphertexts_to_bytes(&mask_cards);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_dleq_proof(&remask_proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(input_bytes),  // Input(0)
        pure_bytes(output_bytes), // Input(1)
        pure_bytes(pk_bytes),     // Input(2)
        pure_bytes(proof_bytes),  // Input(3)
    ];
    let commands = vec![
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(1)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_remask_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(3)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_remask"),
            type_arguments: Vec::new(),
            arguments: vec![
                Argument::Result(0),
                Argument::Result(1),
                Argument::Result(2),
                Argument::Result(3),
            ],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_remask should return true for honest proof");
    println!("[PASS] verify_remask on testnet");
}

/// 测试 `zk_verifier::verify_leave` 能验证 Rust 生成的 LeaveProof
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_leave_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let input_cards = make_encrypted_deck(&player.pk);

    let round = poker_protocol::z_poker::protocol::LeaveGameRound::execute(
        &input_cards,
        &player.sk,
        &player.pk,
    );

    // 2. 序列化为字节
    let input_bytes = ciphertexts_to_bytes(&round.input_cards);
    let output_bytes = ciphertexts_to_bytes(&round.output_cards);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_dleq_proof(&round.leave_proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(input_bytes),  // Input(0)
        pure_bytes(output_bytes), // Input(1)
        pure_bytes(pk_bytes),     // Input(2)
        pure_bytes(proof_bytes),  // Input(3)
    ];
    let commands = vec![
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(1)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_leave_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(3)],
        }),
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_leave"),
            type_arguments: Vec::new(),
            arguments: vec![
                Argument::Result(0),
                Argument::Result(1),
                Argument::Result(2),
                Argument::Result(3),
            ],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_leave should return true for honest proof");
    println!("[PASS] verify_leave on testnet");
}

/// 测试 `zk_verifier::verify_reveal_token` 能验证 Rust 生成的 RevealTokenProof
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_reveal_token_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let plaintext = make_plaintext_cards()[0];
    let ct = ElGamalCiphertext::encrypt(&plaintext, &player.pk, &Scalar::random(&mut OsRng));

    let token = player.generate_reveal_token(&ct);

    // 2. 序列化为字节
    let c1_bytes = g1_to_bytes(&ct.c1);
    let c2_bytes = g1_to_bytes(&ct.c2);
    let reveal_token_bytes = g1_to_bytes(&token.reveal_token);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_reveal_token_proof(&token.proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(c1_bytes),           // Input(0): c1
        pure_bytes(c2_bytes),           // Input(1): c2
        pure_bytes(reveal_token_bytes), // Input(2): reveal_token
        pure_bytes(pk_bytes),           // Input(3): pk
        pure_bytes(proof_bytes),        // Input(4): proof
    ];
    let commands = vec![
        // Command 0: deserialize c1
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        // Command 1: deserialize c2
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(1)],
        }),
        // Command 2: construct ElGamalCiphertext
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("bls_elgamal"),
            function: Identifier::from_static("new_ciphertext"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Result(0), Argument::Result(1)],
        }),
        // Command 3: deserialize reveal_token
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        // Command 4: deserialize pk
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(3)],
        }),
        // Command 5: deserialize RevealTokenProof
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_reveal_token_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(4)],
        }),
        // Command 6: verify_reveal_token
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_reveal_token"),
            type_arguments: Vec::new(),
            arguments: vec![
                Argument::Result(2),
                Argument::Result(3),
                Argument::Result(4),
                Argument::Result(5),
            ],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_reveal_token should return true for honest proof");
    println!("[PASS] verify_reveal_token on testnet");
}

/// 测试 `zk_verifier::verify_reconstruct` 能验证 Rust 生成的 ReconstructProof
///
/// verify_reconstruct 签名（6 参数）:
///   verify_reconstruct(cards, output_cards, swap_out_cards, user_readable_cards, user_pk, proof)
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_reconstruct_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let plaintext_cards = make_plaintext_cards();

    // 加密牌组（模拟用户可读牌）
    let coefficient = Scalar::random(&mut OsRng);
    let user_readable_cards: Vec<ElGamalCiphertext> = plaintext_cards
        .iter()
        .take(2) // 取前 2 张作为用户可读牌
        .map(|pt| ElGamalCiphertext::encrypt(pt, &player.pk, &Scalar::random(&mut OsRng)))
        .collect();

    let reconstruct_deck = player
        .reconstruct(&plaintext_cards, &user_readable_cards, &coefficient)
        .expect("reconstruct should succeed");

    // 2. 序列化为字节
    let output_bytes = ciphertexts_to_bytes(&reconstruct_deck.output_cards);
    let swap_cards: Vec<ElGamalCiphertext> = reconstruct_deck.swap_cards.clone();
    let swap_out_bytes = ciphertexts_to_bytes(&swap_cards);
    let user_readable_bytes = ciphertexts_to_bytes(&user_readable_cards);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_reconstruct_proof(&reconstruct_deck.proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(output_bytes),        // Input(0): output_cts
        pure_bytes(swap_out_bytes),      // Input(1): swap_out_cts
        pure_bytes(user_readable_bytes), // Input(2): user_readable_cts
        pure_bytes(pk_bytes),            // Input(3): user_pk
        pure_bytes(proof_bytes),         // Input(4): proof
    ];
    let commands = vec![
        // Command 0: generate plaintext cards (52 张明文牌点)
        // Rust 端 new_plain_text() 已使用与 Move 一致的 DST，两边产生相同牌点
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("bls_scalar"),
            function: Identifier::from_static("generate_plaintext_cards"),
            type_arguments: Vec::new(),
            arguments: vec![],
        }),
        // Command 1: deserialize output_cts
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(0)],
        }),
        // Command 2: deserialize swap_out_cts
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(1)],
        }),
        // Command 3: deserialize user_readable_cts
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        // Command 4: deserialize user_pk
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(3)],
        }),
        // Command 5: deserialize ReconstructProof
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_reconstruct_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(4)],
        }),
        // Command 6: verify_reconstruct (6 参数)
        // verify_reconstruct(cards, output_cards, swap_out_cards, user_readable_cards, user_pk, proof)
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_reconstruct"),
            type_arguments: Vec::new(),
            arguments: vec![
                Argument::Result(0), // cards
                Argument::Result(1), // output_cards
                Argument::Result(2), // swap_out_cards
                Argument::Result(3), // user_readable_cards
                Argument::Result(4), // user_pk
                Argument::Result(5), // proof
            ],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_reconstruct should return true for honest proof");
    println!("[PASS] verify_reconstruct on testnet");
}
