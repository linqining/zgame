module texas_poker::chaum_pedersen;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};

// ========== 证明结构体 ==========

/// Chaum-Pedersen DLEq 证明
/// 证明知道 x 使得 p1 = g1 * x 且 p2 = g2 * x
/// 即 log_{g1}(p1) == log_{g2}(p2)
public struct ChaumPedersenProof has store, copy, drop {
    commitment_a: vector<u8>,  // A = w * g1 的 G1 压缩字节
    commitment_b: vector<u8>,  // B = w * g2 的 G1 压缩字节
    response: vector<u8>,      // s = w + c * x 的标量字节
}

// ========== 访问器 ==========

public fun commitment_a(proof: &ChaumPedersenProof): &vector<u8> { &proof.commitment_a }
public fun commitment_b(proof: &ChaumPedersenProof): &vector<u8> { &proof.commitment_b }
public fun response(proof: &ChaumPedersenProof): &vector<u8> { &proof.response }

// ========== 构造函数 ==========

public fun new(
    commitment_a: vector<u8>,
    commitment_b: vector<u8>,
    response: vector<u8>,
): ChaumPedersenProof {
    ChaumPedersenProof { commitment_a, commitment_b, response }
}

// ========== 验证 ==========

/// 验证 Chaum-Pedersen DLEq 证明
/// g1: 第一个基点
/// g2: 第二个基点
/// p1: g1 * x（第一个公钥点）
/// p2: g2 * x（第二个公钥点）
/// t: Fiat-Shamir transcript
public fun verify(
    proof: &ChaumPedersenProof,
    g1: &group_ops::Element<G1>,
    g2: &group_ops::Element<G1>,
    p1: &group_ops::Element<G1>,
    p2: &group_ops::Element<G1>,
    t: &mut Transcript,
): bool {
    // 1. 拒绝恒等元基点
    if (bls_scalar::g1_is_identity(g1) || bls_scalar::g1_is_identity(g2)) {
        return false
    };

    // 2. 反序列化证明元素
    let comm_a = bls12381::g1_from_bytes(&proof.commitment_a);
    let comm_b = bls12381::g1_from_bytes(&proof.commitment_b);
    let s = bls12381::scalar_from_bytes(&proof.response);

    // 3. Transcript 追加
    bls_transcript::append_point(t, &b"cp_G1", g1);
    bls_transcript::append_point(t, &b"cp_G2", g2);
    bls_transcript::append_point(t, &b"cp_P1", p1);
    bls_transcript::append_point(t, &b"cp_P2", p2);
    bls_transcript::append_point(t, &b"cp_commitment_a", &comm_a);
    bls_transcript::append_point(t, &b"cp_commitment_b", &comm_b);

    // 4. 提取挑战 c
    let c = bls_transcript::challenge(t, &b"cp_challenge");

    // 5. 验证第一组 DLEq: g1 * s == comm_a + p1 * c
    let lhs1 = bls12381::g1_mul(&s, g1);
    let p1_c = bls12381::g1_mul(&c, p1);
    let rhs1 = bls12381::g1_add(&comm_a, &p1_c);
    if (!bls_scalar::g1_equal(&lhs1, &rhs1)) {
        return false
    };

    // 6. 验证第二组 DLEq: g2 * s == comm_b + p2 * c
    let lhs2 = bls12381::g1_mul(&s, g2);
    let p2_c = bls12381::g1_mul(&c, p2);
    let rhs2 = bls12381::g1_add(&comm_b, &p2_c);
    bls_scalar::g1_equal(&lhs2, &rhs2)
}
