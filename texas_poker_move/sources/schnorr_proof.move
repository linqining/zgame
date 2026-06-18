module texas_poker::schnorr_proof;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};

// ========== 证明结构体 ==========

/// 广义 Schnorr 证明
/// 证明知道 k_1, ..., k_n 使得 R = sum(k_i * G_i)
public struct GeneralizedSchnorrProof has store, copy, drop {
    commitment: vector<u8>,          // T = sum(r_i * G_i) 的 G1 压缩字节
    responses: vector<vector<u8>>,   // s_i = r_i + c * k_i 的标量字节
}

// ========== 访问器 ==========

public fun commitment(proof: &GeneralizedSchnorrProof): &vector<u8> {
    &proof.commitment
}

public fun responses(proof: &GeneralizedSchnorrProof): &vector<vector<u8>> {
    &proof.responses
}

// ========== 构造函数 ==========

public fun new(
    commitment: vector<u8>,
    responses: vector<vector<u8>>,
): GeneralizedSchnorrProof {
    GeneralizedSchnorrProof { commitment, responses }
}

// ========== 验证 ==========

/// 验证广义 Schnorr 证明
/// base_points: 基点数组 G_1, ..., G_n
/// r_point: 声称的线性组合点 R = sum(k_i * G_i)
/// t: Fiat-Shamir transcript
public fun verify(
    proof: &GeneralizedSchnorrProof,
    base_points: &vector<group_ops::Element<G1>>,
    r_point: &group_ops::Element<G1>,
    t: &mut Transcript,
): bool {
    let n = proof.responses.length();
    // 1. 检查长度一致
    if (n != base_points.length()) {
        return false
    };
    // 2. 检查 R 不是恒等元
    if (bls_scalar::g1_is_identity(r_point)) {
        return false
    };
    // 3. 检查所有 base_points 不是恒等元
    let mut i = 0;
    while (i < n) {
        if (bls_scalar::g1_is_identity(vector::borrow(base_points, i))) {
            return false
        };
        i = i + 1;
    };

    // 4. Transcript 追加
    // 追加 n（u64 小端8字节）
    let mut n_bytes = vector[];
    let mut val = n;
    let mut j = 0;
    while (j < 8) {
        n_bytes.push_back((val & 0xFF) as u8);
        val = val >> 8;
        j = j + 1;
    };
    let n_label = &b"gen_schnorr_n";
    bls_transcript::append_message(t, n_label, &n_bytes);

    // 追加每个 base_point
    let base_label = &b"gen_schnorr_base";
    i = 0;
    while (i < n) {
        bls_transcript::append_point(t, base_label, vector::borrow(base_points, i));
        i = i + 1;
    };

    // 追加 R
    let r_label = &b"gen_schnorr_R";
    bls_transcript::append_point(t, r_label, r_point);

    // 追加 commitment
    let commit_label = &b"gen_schnorr_commitment";
    let commitment_point = bls12381::g1_from_bytes(&proof.commitment);
    // M-P17: 校验承诺点非 identity——identity 承诺削弱证明安全性
    if (bls_scalar::g1_is_identity(&commitment_point)) {
        return false
    };
    bls_transcript::append_point(t, commit_label, &commitment_point);

    // 5. 提取挑战标量 c
    let challenge_label = &b"gen_schnorr_challenge";
    let c = bls_transcript::challenge(t, challenge_label);

    // 6. 计算 LHS = g1_msm(responses, base_points) = sum(s_i * G_i)
    let mut response_scalars = vector[];
    i = 0;
    while (i < n) {
        response_scalars.push_back(bls12381::scalar_from_bytes(vector::borrow(&proof.responses, i)));
        i = i + 1;
    };
    let lhs = bls_scalar::g1_msm(&response_scalars, base_points);

    // 7. 计算 RHS = commitment + c * R
    let c_r = bls12381::g1_mul(&c, r_point);
    let rhs = bls12381::g1_add(&commitment_point, &c_r);

    // 8. 验证 LHS == RHS
    bls_scalar::g1_equal(&lhs, &rhs)
}
