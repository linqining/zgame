module texas_poker::shuffle_proof;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};
use texas_poker::schnorr_proof::{Self, GeneralizedSchnorrProof};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== 证明结构体 ==========

/// ShuffleProof: ZK proof that a player correctly shuffled and re-encrypted a deck
/// Uses 3 layers of GeneralizedSchnorrProof to prevent permutation mapping attacks
public struct ShuffleProof has store, copy, drop {
    sum_c1_commit: vector<u8>,                        // sum of rho_i * input_c1_i (G1 bytes)
    sum_c2_commit: vector<u8>,                        // sum of rho_i * input_c2_i (G1 bytes)
    combined_schnorr_proof: GeneralizedSchnorrProof,  // combined c1+c2 proof
    sum_c1_schnorr_proof: GeneralizedSchnorrProof,    // c1-only proof
    sum_c2_schnorr_proof: GeneralizedSchnorrProof,    // c2-only proof
    nonce: vector<u8>,                                // anti-replay nonce (scalar bytes)
}

// ========== 访问器 ==========

public fun sum_c1_commit(proof: &ShuffleProof): &vector<u8> {
    &proof.sum_c1_commit
}

public fun sum_c2_commit(proof: &ShuffleProof): &vector<u8> {
    &proof.sum_c2_commit
}

public fun combined_schnorr_proof(proof: &ShuffleProof): &GeneralizedSchnorrProof {
    &proof.combined_schnorr_proof
}

public fun sum_c1_schnorr_proof(proof: &ShuffleProof): &GeneralizedSchnorrProof {
    &proof.sum_c1_schnorr_proof
}

public fun sum_c2_schnorr_proof(proof: &ShuffleProof): &GeneralizedSchnorrProof {
    &proof.sum_c2_schnorr_proof
}

public fun nonce(proof: &ShuffleProof): &vector<u8> {
    &proof.nonce
}

// ========== 构造函数 ==========

public fun new(
    sum_c1_commit: vector<u8>,
    sum_c2_commit: vector<u8>,
    combined_schnorr_proof: GeneralizedSchnorrProof,
    sum_c1_schnorr_proof: GeneralizedSchnorrProof,
    sum_c2_schnorr_proof: GeneralizedSchnorrProof,
    nonce: vector<u8>,
): ShuffleProof {
    ShuffleProof {
        sum_c1_commit,
        sum_c2_commit,
        combined_schnorr_proof,
        sum_c1_schnorr_proof,
        sum_c2_schnorr_proof,
        nonce,
    }
}

// ========== 验证 ==========

/// 验证 ShuffleProof
/// input_cts: 洗牌前的密文数组
/// output_cts: 洗牌后的密文数组
/// pk: 玩家公钥 G * sk
/// t: Fiat-Shamir transcript
public fun verify(
    proof: &ShuffleProof,
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    pk: &group_ops::Element<G1>,
    t: &mut Transcript,
): bool {
    let n = input_cts.length();

    // 0. 检查长度一致
    if (n != output_cts.length()) {
        return false
    };
    if (n == 0) {
        return false
    };

    // 1. Append nonce to transcript
    let nonce_scalar = bls12381::scalar_from_bytes(&proof.nonce);
    bls_transcript::append_scalar(t, &b"shuffle_nonce", &nonce_scalar);

    // 2. Derive batch coefficients rho_i
    // For each input_ct: append c1 with label "input c1", append c2 with label "input c2"
    let mut i = 0;
    while (i < n) {
        let input_ct = vector::borrow(input_cts, i);
        bls_transcript::append_point(t, &b"input c1", bls_elgamal::c1(input_ct));
        bls_transcript::append_point(t, &b"input c2", bls_elgamal::c2(input_ct));
        i = i + 1;
    };

    // For each output_ct: append c1 with label "output c1", append c2 with label "output c2"
    i = 0;
    while (i < n) {
        let output_ct = vector::borrow(output_cts, i);
        bls_transcript::append_point(t, &b"output c1", bls_elgamal::c1(output_ct));
        bls_transcript::append_point(t, &b"output c2", bls_elgamal::c2(output_ct));
        i = i + 1;
    };

    // Generate N rho_i scalars
    let rho = bls_transcript::challenge_vec(t, &b"rho_challenge", n);

    // 3. Recompute sum commitments and verify they match
    // Extract input c1s and c2s
    let mut input_c1s = vector[];
    let mut input_c2s = vector[];
    i = 0;
    while (i < n) {
        let input_ct = vector::borrow(input_cts, i);
        input_c1s.push_back(*bls_elgamal::c1(input_ct));
        input_c2s.push_back(*bls_elgamal::c2(input_ct));
        i = i + 1;
    };

    // sum_input_c1 = g1_msm(rho, input_c1s)
    let sum_input_c1 = bls_scalar::g1_msm(&rho, &input_c1s);
    // sum_input_c2 = g1_msm(rho, input_c2s)
    let sum_input_c2 = bls_scalar::g1_msm(&rho, &input_c2s);

    // Verify they match proof commitments
    let proof_sum_c1 = bls12381::g1_from_bytes(&proof.sum_c1_commit);
    let proof_sum_c2 = bls12381::g1_from_bytes(&proof.sum_c2_commit);

    if (!bls_scalar::g1_equal(&sum_input_c1, &proof_sum_c1)) {
        return false
    };
    if (!bls_scalar::g1_equal(&sum_input_c2, &proof_sum_c2)) {
        return false
    };

    // 4. Verify combined Schnorr proof (prevents c1/c2 swap attack)
    // Build combined base_points: [output[0].c1, output[0].c2, output[1].c1, output[1].c2, ..., G, pk]
    let mut combined_base_points = vector[];
    i = 0;
    while (i < n) {
        let output_ct = vector::borrow(output_cts, i);
        combined_base_points.push_back(*bls_elgamal::c1(output_ct));
        combined_base_points.push_back(*bls_elgamal::c2(output_ct));
        i = i + 1;
    };
    combined_base_points.push_back(bls12381::g1_generator());
    combined_base_points.push_back(*pk);

    // R = sum_c1_commit + sum_c2_commit
    let combined_r = bls12381::g1_add(&proof_sum_c1, &proof_sum_c2);

    if (!schnorr_proof::verify(&proof.combined_schnorr_proof, &combined_base_points, &combined_r, t)) {
        return false
    };

    // 5. Verify c1-only Schnorr proof
    // Build c1 base_points: [output[0].c1, output[1].c1, ..., G]
    let mut c1_base_points = vector[];
    i = 0;
    while (i < n) {
        let output_ct = vector::borrow(output_cts, i);
        c1_base_points.push_back(*bls_elgamal::c1(output_ct));
        i = i + 1;
    };
    c1_base_points.push_back(bls12381::g1_generator());

    // R = sum_c1_commit
    if (!schnorr_proof::verify(&proof.sum_c1_schnorr_proof, &c1_base_points, &proof_sum_c1, t)) {
        return false
    };

    // 6. Verify c2-only Schnorr proof
    // Build c2 base_points: [output[0].c2, output[1].c2, ..., pk]
    let mut c2_base_points = vector[];
    i = 0;
    while (i < n) {
        let output_ct = vector::borrow(output_cts, i);
        c2_base_points.push_back(*bls_elgamal::c2(output_ct));
        i = i + 1;
    };
    c2_base_points.push_back(*pk);

    // R = sum_c2_commit
    if (!schnorr_proof::verify(&proof.sum_c2_schnorr_proof, &c2_base_points, &proof_sum_c2, t)) {
        return false
    };

    // 7. All checks pass
    true
}
