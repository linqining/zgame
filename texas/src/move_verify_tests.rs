//! 测试网合约 verify 方法端到端测试
//!
//! 本模块通过 `sui_devInspectTransactionBlock` 调用测试网上已发布的 Move 合约
//! (`0x2cbd00a8784ba16db3ebc29f6f23a94ab02948d843bfd28644ba660fcb7e4c04`)
//! 中的各个 verify 方法，验证 Rust 端生成的真实证明能被 Move 合约正确验证。
//!
//! # 运行方式
//!
//! 所有测试标记为 `#[ignore]`（需要网络访问），运行方式：
//! ```sh
//! cargo test --package texas -- move_verify_tests --nocapture --ignored
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
use poker_protocol::crypto::{
    DefaultCurve, EcPoint, ElGamalCiphertext, Scalar,
};
use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol::zk_shuffle::dleq_proof::DLEqProof;
use poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
use poker_protocol::zk_shuffle::reconstruction::{ChaumPedersenDLEQProof, ReconstructionDLEQProof, ReconstructProof, SwapOutCardProof};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::z_poker::protocol::new_plain_text;
use rand::rngs::OsRng;
use sui_sdk_types::{Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction, TransactionKind};

// ============================================================================
// 常量
// ============================================================================

/// 测试网已发布的 texas_poker_move 合约包 ID
const PACKAGE_ID: &str = "0x2cbd00a8784ba16db3ebc29f6f23a94ab02948d843bfd28644ba660fcb7e4c04";

/// 测试网 JSON-RPC 端点
const TESTNET_RPC: &str = "https://fullnode.testnet.sui.io:443";

/// G1 压缩点字节数（BLS12-381 G1 compressed）
const G1_POINT_SIZE: usize = 48;

/// BLS 标量字节数
const SCALAR_SIZE: usize = 32;

/// ElGamal 密文字节数（c1:48 + c2:48）
const CIPHERTEXT_SIZE: usize = 96;

// ============================================================================
// 序列化辅助函数
// ============================================================================

/// 将 G1 点序列化为 48 字节压缩格式
fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    use poker_protocol::crypto::curve::CurvePoint;
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
/// 格式: user_pk(48) + t1(48) + t2(48) + response_s(32)
fn serialize_reveal_token_proof(proof: &RevealTokenProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.user_public_key));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t1));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t2));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response_s));
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
    // user_readable_card as generic ciphertext
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
/// 用于测试 Sui runtime 是否期望原始字节
#[allow(dead_code)]
fn pure_raw_bytes(bytes: Vec<u8>) -> Input {
    Input::Pure(bytes)
}

/// 构建 MoveCall command
#[allow(dead_code)]
fn move_call(
    package_id: &str,
    module: &str,
    function: &str,
    arg_indices: &[u16],
) -> Result<Command, String> {
    let package = parse_address(package_id)?;
    let arguments = arg_indices.iter().copied().map(Argument::Input).collect();
    Ok(Command::MoveCall(MoveCall {
        package,
        module: Identifier::new(module).map_err(|e| format!("invalid module: {}", e))?,
        function: Identifier::new(function).map_err(|e| format!("invalid function: {}", e))?,
        type_arguments: Vec::new(),
        arguments,
    }))
}

/// 构建 Result argument（引用前一个 command 的返回值）
#[allow(dead_code)]
fn result(n: u16) -> Argument {
    Argument::Result(n)
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

/// 通过 `sui_devInspectTransactionBlock` 调用测试网合约，返回 bool 结果
async fn dev_inspect_verify(pt: ProgrammableTransaction) -> Result<bool, String> {
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

    // 从 results[0].returnValues[0] 提取 bool
    // BCS 编码的 bool: 0x00 = false, 0x01 = true
    let return_value = result
        .get("results")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .ok_or("No return values in dev inspect response")?;

    let bcs_b64 = return_value
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or("Missing BCS bytes in return value")?;

    let engine = base64::engine::general_purpose::STANDARD;
    let bcs_bytes = engine
        .decode(bcs_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    if bcs_bytes.len() != 1 {
        return Err(format!(
            "Expected 1 byte for bool return, got {} bytes",
            bcs_bytes.len()
        ));
    }

    Ok(bcs_bytes[0] != 0)
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
///
/// PTB 结构:
/// 1. Input(0): pk_bytes (48 bytes)
/// 2. Input(1): proof_bytes (80 bytes)
/// 3. Command 0: zk_verifier::deserialize_pk(Input(0)) → Element<G1>
/// 4. Command 1: zk_verifier::verify_pk_ownership(Result(0), Input(1)) → bool
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
    let mut proof_bytes = Vec::with_capacity(80);
    proof_bytes.extend_from_slice(&commitment_bytes);
    proof_bytes.extend_from_slice(&response_bytes);
    assert_eq!(proof_bytes.len(), 80, "pk_ownership_proof must be 80 bytes");

    // 调试: 打印字节以诊断反序列化问题
    println!("pk_bytes ({}): {}", pk_bytes.len(), hex::encode(&pk_bytes));
    println!("commitment_bytes ({}): {}", commitment_bytes.len(), hex::encode(&commitment_bytes));
    println!("response_bytes ({}): {}", response_bytes.len(), hex::encode(&response_bytes));

    // 验证 commitment 可以被本地反序列化
    use poker_protocol::crypto::curve::CurvePoint;
    let recovered: Option<<DefaultCurve as Curve>::Point> = CurvePoint::from_compressed(commitment_bytes.as_slice());
    assert!(recovered.is_some(), "commitment should be locally deserializable");
    println!("commitment locally verified OK");

    // 3. 构建 PTB
    // 调试: 先单独测试 commitment_bytes 能否被 deserialize_pk 反序列化
    let inputs = vec![
        pure_bytes(pk_bytes),               // Input(0): pk
        pure_bytes(proof_bytes),            // Input(1): proof_bytes
        pure_bytes(commitment_bytes.clone()), // Input(2): commitment_bytes (for debugging)
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
        // Command 1: deserialize commitment (debug - test if this works)
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_pk"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(2)],
        }),
        // Command 2: verify_pk_ownership
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("verify_pk_ownership"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Result(0), Argument::Input(1)],
        }),
    ];
    let pt = ProgrammableTransaction { inputs, commands };

    // 4. 调用测试网
    let result = dev_inspect_verify(pt).await.expect("dev inspect should succeed");

    // 5. 断言
    assert!(result, "verify_pk_ownership should return true for honest proof");
    println!("[PASS] verify_pk_ownership on testnet");
}

/// 测试 `zk_verifier::verify_shuffle` 能验证 Rust 生成的 ZKShuffleProof
///
/// PTB 结构:
/// 1. Input(0): input_cts_bytes (96*N bytes)
/// 2. Input(1): output_cts_bytes (96*N bytes)
/// 3. Input(2): pk_bytes (48 bytes)
/// 4. Input(3): proof_bytes
/// 5. Command 0: zk_verifier::deserialize_ciphertexts(Input(0)) → vector<ElGamalCiphertext>
/// 6. Command 1: zk_verifier::deserialize_ciphertexts(Input(1)) → vector<ElGamalCiphertext>
/// 7. Command 2: zk_verifier::deserialize_pk(Input(2)) → Element<G1>
/// 8. Command 3: table_serialization::deserialize_shuffle_proof(Input(3)) → ShuffleProof
/// 9. Command 4: zk_verifier::verify_shuffle(Result(0), Result(1), Result(2), Result(3)) → bool
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_shuffle_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let input_cards = make_encrypted_deck(&player.pk);

    let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v1");
    let round = poker_protocol::z_poker::protocol::ShuffleRound::execute(
        &input_cards,
        &player.pk,
        &mut transcript,
        &mut OsRng,
    );

    // 2. 序列化为字节
    let input_bytes = ciphertexts_to_bytes(&round.input_cards);
    let output_bytes = ciphertexts_to_bytes(&round.output_cards);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_shuffle_proof(&round.proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(input_bytes),    // Input(0)
        pure_bytes(output_bytes),   // Input(1)
        pure_bytes(pk_bytes),       // Input(2)
        pure_bytes(proof_bytes),    // Input(3)
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
            arguments: vec![Argument::Result(0), Argument::Result(1), Argument::Result(2), Argument::Result(3)],
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
///
/// PTB 结构:
/// 1. Input(0): input_cts_bytes
/// 2. Input(1): output_cts_bytes (mask_cards)
/// 3. Input(2): player_pk_bytes
/// 4. Input(3): proof_bytes
/// 5. Command 0-3: deserialize
/// 6. Command 4: verify_remask → bool
#[tokio::test]
#[ignore = "requires testnet network access"]
async fn test_verify_remask_on_testnet() {
    // 1. 生成真实证明
    let player = poker_protocol::z_poker::protocol::ClientPlayer::new();
    let input_cards = make_encrypted_deck(&player.pk);

    let round = poker_protocol::z_poker::protocol::MaskAndShuffleRound::execute(
        &input_cards,
        &player.pk,
        player.sk.clone(),
        &player.pk,
        &mut OsRng,
    );

    // 2. 序列化为字节
    let input_bytes = ciphertexts_to_bytes(&input_cards);
    let output_bytes = ciphertexts_to_bytes(&round.mask_cards);
    let pk_bytes = g1_to_bytes(&player.pk);
    let proof_bytes = serialize_dleq_proof(&round.remask_proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(input_bytes),    // Input(0)
        pure_bytes(output_bytes),   // Input(1)
        pure_bytes(pk_bytes),       // Input(2)
        pure_bytes(proof_bytes),    // Input(3)
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
            arguments: vec![Argument::Result(0), Argument::Result(1), Argument::Result(2), Argument::Result(3)],
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
        pure_bytes(input_bytes),    // Input(0)
        pure_bytes(output_bytes),   // Input(1)
        pure_bytes(pk_bytes),       // Input(2)
        pure_bytes(proof_bytes),    // Input(3)
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
            arguments: vec![Argument::Result(0), Argument::Result(1), Argument::Result(2), Argument::Result(3)],
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
///
/// PTB 结构:
/// 1. Input(0): c1_bytes (48)
/// 2. Input(1): c2_bytes (48)
/// 3. Input(2): reveal_token_bytes (48)
/// 4. Input(3): pk_bytes (48)
/// 5. Input(4): proof_bytes
/// 6. Command 0: deserialize_pk(Input(0)) → c1
/// 7. Command 1: deserialize_pk(Input(1)) → c2
/// 8. Command 2: bls_elgamal::new_ciphertext(Result(0), Result(1)) → ElGamalCiphertext
/// 9. Command 3: deserialize_pk(Input(2)) → reveal_token
/// 10. Command 4: deserialize_pk(Input(3)) → pk
/// 11. Command 5: deserialize_reveal_token_proof(Input(4)) → RevealTokenProof
/// 12. Command 6: verify_reveal_token(Result(2), Result(3), Result(4), Result(5)) → bool
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
            arguments: vec![Argument::Result(2), Argument::Result(3), Argument::Result(4), Argument::Result(5)],
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
/// PTB 结构:
/// 1. Input(0): cards_bytes (52 * 48 bytes, plaintext card points)
/// 2. Input(1): output_cts_bytes
/// 3. Input(2): swap_out_cts_bytes
/// 4. Input(3): user_readable_cts_bytes
/// 5. Input(4): user_pk_bytes
/// 6. Input(5): encrypted_deck_bytes (= swap_out_cts_bytes, for M-B3 check)
/// 7. Input(6): proof_bytes
/// 8. Command 0: bls_scalar::generate_plaintext_cards() → vector<Element<G1>>
/// 9. Command 1-5: deserialize ciphertexts and pk
/// 10. Command 6: deserialize_reconstruct_proof
/// 11. Command 7: verify_reconstruct → bool
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
    // encrypted_deck: 传入 swap_out_cards 本身，使 M-B3 检查通过
    let encrypted_deck_bytes = swap_out_bytes.clone();
    let proof_bytes = serialize_reconstruct_proof(&reconstruct_deck.proof);

    // 3. 构建 PTB
    let inputs = vec![
        pure_bytes(output_bytes),          // Input(0): output_cts
        pure_bytes(swap_out_bytes),        // Input(1): swap_out_cts
        pure_bytes(user_readable_bytes),   // Input(2): user_readable_cts
        pure_bytes(pk_bytes),              // Input(3): user_pk
        pure_bytes(encrypted_deck_bytes),  // Input(4): encrypted_deck
        pure_bytes(proof_bytes),           // Input(5): proof
    ];
    let commands = vec![
        // Command 0: generate plaintext cards (52 张明文牌点)
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
        // Command 5: deserialize encrypted_deck
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("zk_verifier"),
            function: Identifier::from_static("deserialize_ciphertexts"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(4)],
        }),
        // Command 6: deserialize ReconstructProof
        Command::MoveCall(MoveCall {
            package: parse_address(PACKAGE_ID).unwrap(),
            module: Identifier::from_static("table_serialization"),
            function: Identifier::from_static("deserialize_reconstruct_proof"),
            type_arguments: Vec::new(),
            arguments: vec![Argument::Input(5)],
        }),
        // Command 7: verify_reconstruct
        // verify_reconstruct(cards, output_cards, swap_out_cards, user_readable_cards, user_pk, encrypted_deck, proof)
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
                Argument::Result(5), // encrypted_deck
                Argument::Result(6), // proof
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
