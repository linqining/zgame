//! Sui 链上 Move 合约序列化格式转换工具。
//!
//! Move 合约（`table_serialization.move`）期望 flat bytes 格式（非 BCS）。
//! 本 crate 将 hex JSON 格式的加密数据转换为 Move 合约期望的字节序列，
//! 供前端（WASM）和后端（relayer）共用。
//!
//! # 关键常量（与 `table_serialization.move` 保持一致）
//!
//! | 常量              | 值 | 说明                       |
//! |-------------------|----|----------------------------|
//! | `G1_POINT_SIZE`   | 48 | BLS12-381 G1 compressed    |
//! | `SCALAR_SIZE`     | 32 | BLS 标量                   |
//! | `CIPHERTEXT_SIZE` | 96 | ElGamal 密文 (c1:48 + c2:48) |

use serde_json::Value;

/// G1 点压缩后的字节数（BLS12-381 G1 compressed）。
pub const G1_POINT_SIZE: usize = 48;

/// BLS 标量的字节数。
pub const SCALAR_SIZE: usize = 32;

/// ElGamal 密文的字节数（c1:48 + c2:48）。
pub const CIPHERTEXT_SIZE: usize = 96;

// ===========================================================================
// 内部辅助函数
// ===========================================================================

/// 将 hex 字符串解码为字节，验证长度。
fn hex_to_bytes_fixed(hex_str: &str, expected_len: usize, field_name: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex for {}: {}", field_name, e))?;
    if bytes.len() != expected_len {
        return Err(format!("{} must be {} bytes, got {}", field_name, expected_len, bytes.len()));
    }
    Ok(bytes)
}

/// 将 G1 点的 hex 字符串（48 bytes compressed）追加到 buffer。
fn append_g1_point(buf: &mut Vec<u8>, hex_str: &str, field_name: &str) -> Result<(), String> {
    let bytes = hex_to_bytes_fixed(hex_str, G1_POINT_SIZE, field_name)?;
    buf.extend_from_slice(&bytes);
    Ok(())
}

/// 将 scalar 的 hex 字符串（32 bytes）追加到 buffer。
fn append_scalar(buf: &mut Vec<u8>, hex_str: &str, field_name: &str) -> Result<(), String> {
    let bytes = hex_to_bytes_fixed(hex_str, SCALAR_SIZE, field_name)?;
    buf.extend_from_slice(&bytes);
    Ok(())
}

/// 将 u16 以小端序追加到 buffer。
fn append_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.push((val & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
}

/// 从 JSON 值中提取字符串字段。
fn json_get_str<'a>(val: &'a Value, field: &str) -> Result<&'a str, String> {
    val.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing string field: {}", field))
}

/// 从 JSON 值中提取数组字段。
fn json_get_array<'a>(val: &'a Value, field: &str) -> Result<&'a Vec<Value>, String> {
    val.get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("Missing array field: {}", field))
}

/// 序列化 SchnorrProof 为 Move 合约期望的字节格式。
///
/// 格式: `commitment(48) + u16(count) + count*scalar(32)`
fn serialize_schnorr_proof_to_bytes(proof: &Value, field_name: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    append_g1_point(
        &mut buf,
        json_get_str(proof, "commitment_hex")?,
        &format!("{}.commitment", field_name),
    )?;
    let responses = json_get_array(proof, "responses_hex")?;
    let count = responses.len();
    if count > u16::MAX as usize {
        return Err(format!("{}.responses count exceeds u16", field_name));
    }
    append_u16_le(&mut buf, count as u16);
    for (i, resp) in responses.iter().enumerate() {
        let resp_hex = resp
            .as_str()
            .ok_or_else(|| format!("{}.responses[{}] must be string", field_name, i))?;
        append_scalar(&mut buf, resp_hex, &format!("{}.responses[{}]", field_name, i))?;
    }
    Ok(buf)
}

// ===========================================================================
// 公开 API
// ===========================================================================

/// 序列化 pk（G1 compressed 48 bytes）为 Move 合约期望的字节格式。
///
/// # 参数
/// - `pk_hex`: pk 的 hex 字符串（48 bytes）
///
/// # 返回
/// 48 字节的 `Vec<u8>`。
///
/// # 对应 Move 函数
/// `zk_verifier::deserialize_pk` → `bls12381::g1_from_bytes(pk_bytes)`
pub fn serialize_pk_to_move_bytes(pk_hex: &str) -> Result<Vec<u8>, String> {
    hex_to_bytes_fixed(pk_hex, G1_POINT_SIZE, "pk")
}

/// 序列化 pk_ownership_proof 为 Move 合约期望的字节格式。
///
/// # 参数
/// - `proof_json`: JSON 字符串，格式 `{"commitment_hex":"...","response_hex":"..."}`
///
/// # 返回
/// 80 字节的 `Vec<u8>` = `commitment(48) + response(32)`。
///
/// # 对应 Move 函数
/// `zk_verifier::verify_pk_ownership` — proof_bytes 格式: commitment(48) + response(32)
pub fn serialize_pk_ownership_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut buf = Vec::new();
    append_g1_point(&mut buf, json_get_str(&val, "commitment_hex")?, "commitment")?;
    append_scalar(&mut buf, json_get_str(&val, "response_hex")?, "response")?;
    Ok(buf)
}

/// 序列化 ElGamalCiphertext 数组为 Move 合约期望的 flat bytes 格式。
///
/// # 参数
/// - `cts_json`: JSON 字符串，格式 `[{"c1_hex":"...","c2_hex":"..."}, ...]`
///
/// # 返回
/// flat bytes，每张牌 96 bytes = `c1(48) + c2(48)`。
///
/// # 对应 Move 函数
/// `zk_verifier::deserialize_ciphertexts` — `data.length() / 96` 张牌
pub fn serialize_ciphertexts_to_move_bytes(cts_json: &str) -> Result<Vec<u8>, String> {
    let arr: Vec<Value> = serde_json::from_str(cts_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut buf = Vec::with_capacity(arr.len() * CIPHERTEXT_SIZE);
    for (i, ct) in arr.iter().enumerate() {
        append_g1_point(&mut buf, json_get_str(ct, "c1_hex")?, &format!("ciphertexts[{}].c1", i))?;
        append_g1_point(&mut buf, json_get_str(ct, "c2_hex")?, &format!("ciphertexts[{}].c2", i))?;
    }
    Ok(buf)
}

/// 序列化 RemaskProof 为 Move 合约期望的字节格式。
///
/// # 参数
/// - `proof_json`: JSON 字符串，格式：
///   ```json
///   {
///     "per_card_commitments_hex": ["...", ...],
///     "commitment_pk_hex": "...",
///     "response_hex": "...",
///     "nonce_hex": "..."
///   }
///   ```
///
/// # 返回
/// `u16(count) + count*48 + 48 + 32 + 32`
///
/// # 对应 Move 函数
/// `table_serialization::deserialize_remask_proof`
pub fn serialize_remask_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut buf = Vec::new();
    let per_card = json_get_array(&val, "per_card_commitments_hex")?;
    let count = per_card.len();
    if count > u16::MAX as usize {
        return Err("per_card_commitments count exceeds u16".to_string());
    }
    append_u16_le(&mut buf, count as u16);
    for (i, c) in per_card.iter().enumerate() {
        let c_hex = c
            .as_str()
            .ok_or_else(|| format!("per_card_commitments[{}] must be string", i))?;
        append_g1_point(&mut buf, c_hex, &format!("per_card_commitments[{}]", i))?;
    }
    append_g1_point(&mut buf, json_get_str(&val, "commitment_pk_hex")?, "commitment_pk")?;
    append_scalar(&mut buf, json_get_str(&val, "response_hex")?, "response")?;
    append_scalar(&mut buf, json_get_str(&val, "nonce_hex")?, "nonce")?;
    Ok(buf)
}

/// 序列化 ShuffleProof 为 Move 合约期望的字节格式。
///
/// # 参数
/// - `proof_json`: JSON 字符串，格式：
///   ```json
///   {
///     "sum_c1_commit_hex": "...",
///     "sum_c2_commit_hex": "...",
///     "combined_schnorr_proof": {...},
///     "sum_c1_schnorr_proof": {...},
///     "sum_c2_schnorr_proof": {...},
///     "nonce_hex": "..."
///   }
///   ```
///
/// # 返回
/// `48 + 48 + 32 + 3*schnorr_proof`，
/// 其中 `schnorr_proof = 48(commitment) + u16(count) + count*32(responses)`。
///
/// # 对应 Move 函数
/// `table_serialization::deserialize_shuffle_proof`
pub fn serialize_shuffle_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut buf = Vec::new();
    append_g1_point(&mut buf, json_get_str(&val, "sum_c1_commit_hex")?, "sum_c1_commit")?;
    append_g1_point(&mut buf, json_get_str(&val, "sum_c2_commit_hex")?, "sum_c2_commit")?;
    append_scalar(&mut buf, json_get_str(&val, "nonce_hex")?, "nonce")?;

    let combined = serialize_schnorr_proof_to_bytes(
        val.get("combined_schnorr_proof")
            .ok_or_else(|| "Missing combined_schnorr_proof".to_string())?,
        "combined_schnorr_proof",
    )?;
    buf.extend_from_slice(&combined);

    let sum_c1 = serialize_schnorr_proof_to_bytes(
        val.get("sum_c1_schnorr_proof")
            .ok_or_else(|| "Missing sum_c1_schnorr_proof".to_string())?,
        "sum_c1_schnorr_proof",
    )?;
    buf.extend_from_slice(&sum_c1);

    let sum_c2 = serialize_schnorr_proof_to_bytes(
        val.get("sum_c2_schnorr_proof")
            .ok_or_else(|| "Missing sum_c2_schnorr_proof".to_string())?,
        "sum_c2_schnorr_proof",
    )?;
    buf.extend_from_slice(&sum_c2);

    Ok(buf)
}

/// 序列化 LeaveProof 为 Move 合约期望的字节格式（与 RemaskProof 格式相同）。
///
/// # 参数
/// - `proof_json`: JSON 字符串，格式同 [`serialize_remask_proof_to_move_bytes`]
///
/// # 返回
/// `u16(count) + count*48 + 48 + 32 + 32`
///
/// # 对应 Move 函数
/// `table_serialization::deserialize_leave_proof`
pub fn serialize_leave_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    serialize_remask_proof_to_move_bytes(proof_json)
}

/// `serialize_join_and_shuffle_to_move_bytes` 的返回值。
///
/// 所有字段均为 base64 编码的字节，方便跨语言传递。
#[derive(Debug, Clone, serde::Serialize)]
pub struct JoinAndShuffleMoveBytes {
    /// base64(48 bytes) — 玩家公钥
    pub pk: String,
    /// base64(80 bytes) — pk 所有权证明
    pub pk_ownership_proof: String,
    /// base64(96*N bytes) — 输出牌组 (flat ciphertexts)
    pub output_cards: String,
    /// base64(...) — remask 证明
    pub remask_proof_bytes: String,
    /// base64(...) — shuffle 证明
    pub shuffle_proof_bytes: String,
}

/// 一次性将 `join_game_and_shuffle` 的完整结果转换为 Move 合约期望的字节格式。
///
/// # 参数
/// - `join_result_json`: `join_game_and_shuffle` 返回的 JSON 字符串，格式：
///   ```json
///   {
///     "pk_ownership_proof": {"commitment_hex":"...","response_hex":"..."},
///     "pk_hex": "...",
///     "mask_and_shuffle_round": {
///       "mask_cards": [...],
///       "remask_proof": {...},
///       "output_cards": [...],
///       "shuffle_proof": {...}
///     }
///   }
///   ```
///
/// # 返回
/// [`JoinAndShuffleMoveBytes`]，包含 5 个 base64 编码的字段。
pub fn serialize_join_and_shuffle_to_move_bytes(
    join_result_json: &str,
) -> Result<JoinAndShuffleMoveBytes, String> {
    let val: Value = serde_json::from_str(join_result_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let pk_hex = json_get_str(&val, "pk_hex")?;
    let pk_bytes = serialize_pk_to_move_bytes(pk_hex)?;

    let pk_proof_json = val
        .get("pk_ownership_proof")
        .ok_or_else(|| "Missing pk_ownership_proof".to_string())?
        .to_string();
    let pk_ownership_proof_bytes = serialize_pk_ownership_proof_to_move_bytes(&pk_proof_json)?;

    let ms = val
        .get("mask_and_shuffle_round")
        .ok_or_else(|| "Missing mask_and_shuffle_round".to_string())?;

    let output_cards_json = ms
        .get("output_cards")
        .ok_or_else(|| "Missing output_cards".to_string())?
        .to_string();
    let output_cards_bytes = serialize_ciphertexts_to_move_bytes(&output_cards_json)?;

    let remask_proof_json = ms
        .get("remask_proof")
        .ok_or_else(|| "Missing remask_proof".to_string())?
        .to_string();
    let remask_proof_bytes = serialize_remask_proof_to_move_bytes(&remask_proof_json)?;

    let shuffle_proof_json = ms
        .get("shuffle_proof")
        .ok_or_else(|| "Missing shuffle_proof".to_string())?
        .to_string();
    let shuffle_proof_bytes = serialize_shuffle_proof_to_move_bytes(&shuffle_proof_json)?;

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    Ok(JoinAndShuffleMoveBytes {
        pk: b64.encode(&pk_bytes),
        pk_ownership_proof: b64.encode(&pk_ownership_proof_bytes),
        output_cards: b64.encode(&output_cards_bytes),
        remask_proof_bytes: b64.encode(&remask_proof_bytes),
        shuffle_proof_bytes: b64.encode(&shuffle_proof_bytes),
    })
}

// ===========================================================================
// 单元测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成 48 字节的 hex 字符串（全 0x11）
    fn fake_g1_hex() -> String {
        hex::encode(&[0x11u8; G1_POINT_SIZE])
    }

    /// 生成 32 字节的 hex 字符串（全 0x22）
    fn fake_scalar_hex() -> String {
        hex::encode(&[0x22u8; SCALAR_SIZE])
    }

    #[test]
    fn test_serialize_pk() {
        let pk_hex = fake_g1_hex();
        let bytes = serialize_pk_to_move_bytes(&pk_hex).unwrap();
        assert_eq!(bytes.len(), G1_POINT_SIZE);
        assert_eq!(bytes, vec![0x11u8; G1_POINT_SIZE]);
    }

    #[test]
    fn test_serialize_pk_ownership_proof() {
        let proof_json = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            fake_g1_hex(),
            fake_scalar_hex()
        );
        let bytes = serialize_pk_ownership_proof_to_move_bytes(&proof_json).unwrap();
        assert_eq!(bytes.len(), G1_POINT_SIZE + SCALAR_SIZE); // 48 + 32 = 80
        // 前 48 字节是 commitment
        assert_eq!(&bytes[0..G1_POINT_SIZE], &[0x11u8; G1_POINT_SIZE]);
        // 后 32 字节是 response
        assert_eq!(&bytes[G1_POINT_SIZE..], &[0x22u8; SCALAR_SIZE]);
    }

    #[test]
    fn test_serialize_ciphertexts() {
        let ct_json = format!(
            r#"[{{"c1_hex":"{}","c2_hex":"{}"}},{{"c1_hex":"{}","c2_hex":"{}"}}]"#,
            fake_g1_hex(),
            fake_g1_hex(),
            fake_g1_hex(),
            fake_g1_hex()
        );
        let bytes = serialize_ciphertexts_to_move_bytes(&ct_json).unwrap();
        assert_eq!(bytes.len(), 2 * CIPHERTEXT_SIZE); // 2 * 96 = 192
    }

    #[test]
    fn test_serialize_remask_proof() {
        let proof_json = format!(
            r#"{{"per_card_commitments_hex":["{}","{}"],"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            fake_g1_hex(),
            fake_g1_hex(),
            fake_g1_hex(),
            fake_scalar_hex(),
            fake_scalar_hex()
        );
        let bytes = serialize_remask_proof_to_move_bytes(&proof_json).unwrap();
        // u16(2) + 2*48 + 48 + 32 + 32 = 2 + 96 + 48 + 32 + 32 = 210
        assert_eq!(bytes.len(), 2 + 2 * G1_POINT_SIZE + G1_POINT_SIZE + 2 * SCALAR_SIZE);
        // 检查 count = 2 (小端)
        assert_eq!(bytes[0], 2);
        assert_eq!(bytes[1], 0);
    }

    #[test]
    fn test_serialize_shuffle_proof() {
        let schnorr = format!(
            r#"{{"commitment_hex":"{}","responses_hex":["{}","{}"]}}"#,
            fake_g1_hex(),
            fake_scalar_hex(),
            fake_scalar_hex()
        );
        let proof_json = format!(
            r#"{{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}"#,
            fake_g1_hex(),
            fake_g1_hex(),
            schnorr,
            schnorr,
            schnorr,
            fake_scalar_hex()
        );
        let bytes = serialize_shuffle_proof_to_move_bytes(&proof_json).unwrap();
        // 48 + 48 + 32 + 3*(48 + 2 + 2*32) = 128 + 3*114 = 128 + 342 = 470
        let schnorr_size = G1_POINT_SIZE + 2 + 2 * SCALAR_SIZE; // 48 + 2 + 64 = 114
        assert_eq!(bytes.len(), 2 * G1_POINT_SIZE + SCALAR_SIZE + 3 * schnorr_size);
    }

    #[test]
    fn test_invalid_pk_length() {
        let short_hex = hex::encode(&[0x11u8; 10]);
        let result = serialize_pk_to_move_bytes(&short_hex);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 48 bytes"));
    }

    #[test]
    fn test_join_and_shuffle() {
        let schnorr = format!(
            r#"{{"commitment_hex":"{}","responses_hex":["{}"]}}"#,
            fake_g1_hex(),
            fake_scalar_hex()
        );
        let join_result = format!(
            r#"{{
                "pk_ownership_proof": {{"commitment_hex":"{}","response_hex":"{}"}},
                "pk_hex": "{}",
                "mask_and_shuffle_round": {{
                    "mask_cards": [{{"c1_hex":"{}","c2_hex":"{}"}}],
                    "remask_proof": {{"per_card_commitments_hex":["{}"],"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}},
                    "output_cards": [{{"c1_hex":"{}","c2_hex":"{}"}}],
                    "shuffle_proof": {{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}
                }}
            }}"#,
            fake_g1_hex(), fake_scalar_hex(),  // pk_ownership_proof
            fake_g1_hex(),                       // pk_hex
            // mask_and_shuffle_round
            fake_g1_hex(), fake_g1_hex(),       // mask_cards
            // remask_proof
            fake_g1_hex(), fake_g1_hex(), fake_scalar_hex(), fake_scalar_hex(),
            // output_cards
            fake_g1_hex(), fake_g1_hex(),
            // shuffle_proof
            fake_g1_hex(), fake_g1_hex(),
            schnorr, schnorr, schnorr,
            fake_scalar_hex()
        );

        let result = serialize_join_and_shuffle_to_move_bytes(&join_result).unwrap();
        // 验证所有字段都是有效的 base64
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        assert!(b64.decode(&result.pk).unwrap().len() == G1_POINT_SIZE);
        assert!(b64.decode(&result.pk_ownership_proof).unwrap().len() == G1_POINT_SIZE + SCALAR_SIZE);
        assert!(b64.decode(&result.output_cards).unwrap().len() == CIPHERTEXT_SIZE);
        assert!(b64.decode(&result.remask_proof_bytes).unwrap().len() > 0);
        assert!(b64.decode(&result.shuffle_proof_bytes).unwrap().len() > 0);
    }
}
