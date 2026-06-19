module texas_poker::reveal_token_proof;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::Self;
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== 证明结构体 ==========

/// Chaum-Pedersen DLEq 证明：log_G(pk) == log_c1(reveal_token) == sk
/// 证明持有者知道 sk 使得 pk = G * sk 且 reveal_token = c1 * sk
public struct RevealTokenProof has store, copy, drop {
    user_public_key: vector<u8>,   // pk bytes
    commitment_t1: vector<u8>,     // T1 = G * omega (G1 compressed bytes)
    commitment_t2: vector<u8>,     // T2 = c1 * omega (G1 compressed bytes)
    response_s: vector<u8>,        // s = omega + c * sk (scalar bytes)
    nonce: vector<u8>,             // M4 修复：anti-replay nonce (scalar bytes)
}

// ========== 访问器 ==========

public fun user_public_key(proof: &RevealTokenProof): &vector<u8> { &proof.user_public_key }
public fun commitment_t1(proof: &RevealTokenProof): &vector<u8> { &proof.commitment_t1 }
public fun commitment_t2(proof: &RevealTokenProof): &vector<u8> { &proof.commitment_t2 }
public fun response_s(proof: &RevealTokenProof): &vector<u8> { &proof.response_s }
public fun nonce(proof: &RevealTokenProof): &vector<u8> { &proof.nonce }

// ========== 构造函数 ==========

public fun new(
    user_public_key: vector<u8>,
    commitment_t1: vector<u8>,
    commitment_t2: vector<u8>,
    response_s: vector<u8>,
    nonce: vector<u8>,
): RevealTokenProof {
    RevealTokenProof { user_public_key, commitment_t1, commitment_t2, response_s, nonce }
}

// ========== 验证 ==========

/// 验证 RevealTokenProof
/// 证明 log_G(pk) == log_c1(reveal_token)，即两者离散对数相同
public fun verify(
    proof: &RevealTokenProof,
    encrypted_card: &ElGamalCiphertext,
    reveal_token: &group_ops::Element<G1>,
    expected_pk: &group_ops::Element<G1>,
): bool {
    // 1. 检查密文有效（c1 和 c2 都不是恒等元）
    if (!bls_elgamal::is_valid(encrypted_card)) {
        return false
    };

    // 2. 检查 reveal_token 不是恒等元
    if (bls_scalar::g1_is_identity(reveal_token)) {
        return false
    };

    // 3. 检查 proof.user_public_key 与 expected_pk 一致
    if (proof.user_public_key != bls_scalar::g1_to_bytes(expected_pk)) {
        return false
    };

    // 4. 创建独立 transcript
    // M4 修复：将 nonce 加入 transcript，防止同一 proof 在不同上下文重放
    let mut t = bls_transcript::new(&b"reveal_token_proof_v3");

    // M4 修复：追加 nonce 到 transcript
    bls_transcript::append_message(&mut t, &b"reveal_token_nonce", &proof.nonce);

    // 反序列化证明元素
    let t1 = bls12381::g1_from_bytes(&proof.commitment_t1);
    let t2 = bls12381::g1_from_bytes(&proof.commitment_t2);
    let s = bls12381::scalar_from_bytes(&proof.response_s);

    // M-P17: 校验反序列化后的承诺点非 identity——identity 承诺意味着零承诺，
    // 可能让等式 G * s == T1 + pk * c 在 s == c * sk 时平凡成立，削弱证明安全性。
    if (bls_scalar::g1_is_identity(&t1) || bls_scalar::g1_is_identity(&t2)) {
        return false
    };

    // 5. 追加到 transcript: pk, c1, c2, reveal_token, t1, t2
    bls_transcript::append_point(&mut t, &b"pk", expected_pk);
    bls_transcript::append_point(&mut t, &b"c1", bls_elgamal::c1(encrypted_card));
    bls_transcript::append_point(&mut t, &b"c2", bls_elgamal::c2(encrypted_card));
    bls_transcript::append_point(&mut t, &b"reveal_token", reveal_token);
    bls_transcript::append_point(&mut t, &b"t1", &t1);
    bls_transcript::append_point(&mut t, &b"t2", &t2);

    // 6. 提取挑战 c
    let c = bls_transcript::challenge(&mut t, &b"challenge");

    // 7. 验证第一组 DLEq: G * s == T1 + pk * c
    let lhs1 = bls12381::g1_mul(&s, &bls12381::g1_generator());
    let pk_c = bls12381::g1_mul(&c, expected_pk);
    let rhs1 = bls12381::g1_add(&t1, &pk_c);
    if (!bls_scalar::g1_equal(&lhs1, &rhs1)) {
        return false
    };

    // 8. 验证第二组 DLEq: c1 * s == T2 + reveal_token * c
    let lhs2 = bls12381::g1_mul(&s, bls_elgamal::c1(encrypted_card));
    let token_c = bls12381::g1_mul(&c, reveal_token);
    let rhs2 = bls12381::g1_add(&t2, &token_c);
    bls_scalar::g1_equal(&lhs2, &rhs2)
}
