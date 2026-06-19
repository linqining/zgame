module texas_poker::leave_proof;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== 证明结构体 ==========

/// LeaveProof：证明 leave 操作 (c2 -= c1 * sk) 被正确执行
/// 即证明知道 sk 使得 pk = G * sk，且 output.c2 = input.c2 - input.c1 * sk
/// 与 RemaskProof 结构相同，但 d2 计算方向相反
public struct LeaveProof has store, copy, drop {
    per_card_commitments: vector<vector<u8>>,  // A_i = input_cts[i].c1 * omega (G1 bytes each)
    commitment_pk: vector<u8>,                 // B = G * omega (G1 bytes)
    response: vector<u8>,                      // s = omega + c * sk (scalar bytes)
    nonce: vector<u8>,                         // anti-replay nonce (scalar bytes)
}

// ========== 访问器 ==========

public fun per_card_commitments(proof: &LeaveProof): &vector<vector<u8>> {
    &proof.per_card_commitments
}

public fun commitment_pk(proof: &LeaveProof): &vector<u8> {
    &proof.commitment_pk
}

public fun response(proof: &LeaveProof): &vector<u8> {
    &proof.response
}

public fun nonce(proof: &LeaveProof): &vector<u8> {
    &proof.nonce
}

// ========== 构造函数 ==========

public fun new(
    per_card_commitments: vector<vector<u8>>,
    commitment_pk: vector<u8>,
    response: vector<u8>,
    nonce: vector<u8>,
): LeaveProof {
    LeaveProof { per_card_commitments, commitment_pk, response, nonce }
}

// ========== 验证 ==========

/// 验证 LeaveProof
/// input_cts: leave 前的密文
/// output_cts: leave 后的密文
/// player_pk: 玩家公钥 G * sk
/// t: Fiat-Shamir transcript
public fun verify(
    proof: &LeaveProof,
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    t: &mut Transcript,
): bool {
    let n = proof.per_card_commitments.length();

    // M-P15: 空输入校验——n == 0 时无任何牌需要 leave，proof 无意义，拒绝验证。
    if (n == 0) {
        return false
    };

    // 1. 检查长度一致
    if (n != input_cts.length()) {
        return false
    };
    if (n != output_cts.length()) {
        return false
    };

    // M6 修复：拒绝恒等元 player_pk——sk=0 时 d2=0，证明平凡成立但 leave 操作为 no-op
    if (bls_scalar::g1_is_identity(player_pk)) {
        return false
    };

    // 2. 检查 c1 不变性：leave 只修改 c2，c1 保持不变
    // 3. 计算 d2_i = input_cts[i].c2 - output_cts[i].c2（注意方向与 remask 相反）
    // M7 修复：校验输入密文有效性（c1/c2 非 identity）
    let mut d2s = vector[];
    let mut i = 0;
    while (i < n) {
        let input_ct = vector::borrow(input_cts, i);
        let output_ct = vector::borrow(output_cts, i);
        if (!bls_elgamal::is_valid(input_ct)) { return false };
        if (!bls_scalar::g1_equal(bls_elgamal::c1(input_ct), bls_elgamal::c1(output_ct))) {
            return false
        };
        // leave: d2 = input.c2 - output.c2 (c2 was decreased by c1*sk)
        let d2_i = bls12381::g1_sub(bls_elgamal::c2(input_ct), bls_elgamal::c2(output_ct));
        d2s.push_back(d2_i);
        i = i + 1;
    };

    // 4. 反序列化证明元素
    let comm_pk = bls12381::g1_from_bytes(&proof.commitment_pk);
    let s = bls12381::scalar_from_bytes(&proof.response);
    let nonce_scalar = bls12381::scalar_from_bytes(&proof.nonce);

    // M-P17: 校验承诺点非 identity——identity 承诺削弱证明安全性
    if (bls_scalar::g1_is_identity(&comm_pk)) {
        return false
    };

    // 5. 构建 challenge：追加到 transcript
    bls_transcript::append_point(t, &b"leave_pk", player_pk);

    i = 0;
    while (i < n) {
        let input_ct = vector::borrow(input_cts, i);
        bls_transcript::append_point(t, &b"leave_input_c1", bls_elgamal::c1(input_ct));
        bls_transcript::append_point(t, &b"leave_input_c2", bls_elgamal::c2(input_ct));
        i = i + 1;
    };

    i = 0;
    while (i < n) {
        let output_ct = vector::borrow(output_cts, i);
        bls_transcript::append_point(t, &b"leave_output_c1", bls_elgamal::c1(output_ct));
        bls_transcript::append_point(t, &b"leave_output_c2", bls_elgamal::c2(output_ct));
        i = i + 1;
    };

    i = 0;
    while (i < n) {
        let comm_i = bls12381::g1_from_bytes(vector::borrow(&proof.per_card_commitments, i));
        bls_transcript::append_point(t, &b"leave_per_card_commitment", &comm_i);
        i = i + 1;
    };

    bls_transcript::append_point(t, &b"leave_commitment_pk", &comm_pk);

    i = 0;
    while (i < n) {
        let d2_ref = vector::borrow(&d2s, i);
        bls_transcript::append_point(t, &b"leave_d2", d2_ref);
        i = i + 1;
    };

    bls_transcript::append_scalar(t, &b"leave_nonce", &nonce_scalar);

    // 6. 提取挑战标量 c
    let c = bls_transcript::challenge(t, &b"leave_challenge");

    // 7. 验证 pk DLEq: G * s == commitment_pk + pk * c
    let g = bls12381::g1_generator();
    let lhs_pk = bls12381::g1_mul(&s, &g);
    let pk_c = bls12381::g1_mul(&c, player_pk);
    let rhs_pk = bls12381::g1_add(&comm_pk, &pk_c);
    if (!bls_scalar::g1_equal(&lhs_pk, &rhs_pk)) {
        return false
    };

    // 8. 对每张牌验证 per-card DLEq: input_cts[i].c1 * s == per_card_commitments[i] + d2_i * c
    i = 0;
    while (i < n) {
        let input_ct = vector::borrow(input_cts, i);
        let comm_i = bls12381::g1_from_bytes(vector::borrow(&proof.per_card_commitments, i));
        let d2_i = vector::borrow(&d2s, i);

        let lhs_i = bls12381::g1_mul(&s, bls_elgamal::c1(input_ct));
        let d2_c = bls12381::g1_mul(&c, d2_i);
        let rhs_i = bls12381::g1_add(&comm_i, &d2_c);
        if (!bls_scalar::g1_equal(&lhs_i, &rhs_i)) {
            return false
        };
        i = i + 1;
    };

    true
}
