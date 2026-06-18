module texas_poker::reconstruct_proof;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};
use texas_poker::schnorr_proof::{Self, GeneralizedSchnorrProof};
use texas_poker::chaum_pedersen::{Self, ChaumPedersenProof};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== 证明结构体 ==========

/// SwapOutCardProof：证明单张 swap-out 操作的正确性
/// 证明 log_{delta_c1}(delta_c2) == log_G(user_pk) == user_sk
public struct SwapOutCardProof has store, copy, drop {
    user_readable_card: vector<u8>,       // serialized ElGamalCiphertext (96 bytes: c1+c2)
    swap_out_card: vector<u8>,            // serialized ElGamalCiphertext (96 bytes: c1+c2)
    chaum_pedersen_proof: ChaumPedersenProof,
}

/// ReconstructionDLEQProof：盲化 DLEQ 证明
/// 证明 points_out[i] = points_in[i] * blind（同一 blind）
public struct ReconstructionDLEQProof has store, copy, drop {
    commitment: vector<u8>,   // A = sum_point_total * w (G1 bytes)
    response: vector<u8>,     // s = w + a * c (scalar bytes)
    nonce: vector<u8>,        // anti-replay nonce (scalar bytes)
}

/// ReconstructProof：重建证明
/// 验证玩家从加密牌组中正确重建了可读牌
public struct ReconstructProof has store, copy, drop {
    swap_out_proofs: vector<SwapOutCardProof>,
    sum_c1_r_commit: vector<u8>,                      // blinded weighted sum of output c1 (G1 bytes)
    sum_c2_r_commit: vector<u8>,                      // blinded weighted sum of (output c2 - card) (G1 bytes)
    swap_sum_c1_commit: vector<u8>,                   // weighted sum of swap_out c1 (G1 bytes)
    swap_sum_c2_commit: vector<u8>,                   // weighted sum of swap_out c2 (G1 bytes)
    nonce: vector<u8>,                                // anti-replay nonce (scalar bytes)
    blind_dleq_proof: ReconstructionDLEQProof,
    total_dleq_proof: ChaumPedersenProof,
    swap_combined_schnorr_proof: GeneralizedSchnorrProof,
    sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
    sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
}

// ========== 访问器 ==========

public fun user_readable_card(proof: &SwapOutCardProof): &vector<u8> { &proof.user_readable_card }
public fun swap_out_card(proof: &SwapOutCardProof): &vector<u8> { &proof.swap_out_card }
public fun chaum_pedersen_proof(proof: &SwapOutCardProof): &ChaumPedersenProof {
    &proof.chaum_pedersen_proof
}

public fun commitment(proof: &ReconstructionDLEQProof): &vector<u8> { &proof.commitment }
public fun response(proof: &ReconstructionDLEQProof): &vector<u8> { &proof.response }
public fun nonce(proof: &ReconstructionDLEQProof): &vector<u8> { &proof.nonce }

public fun swap_out_proofs(proof: &ReconstructProof): &vector<SwapOutCardProof> {
    &proof.swap_out_proofs
}
public fun sum_c1_r_commit(proof: &ReconstructProof): &vector<u8> { &proof.sum_c1_r_commit }
public fun sum_c2_r_commit(proof: &ReconstructProof): &vector<u8> { &proof.sum_c2_r_commit }
public fun swap_sum_c1_commit(proof: &ReconstructProof): &vector<u8> { &proof.swap_sum_c1_commit }
public fun swap_sum_c2_commit(proof: &ReconstructProof): &vector<u8> { &proof.swap_sum_c2_commit }
public fun reconstruct_nonce(proof: &ReconstructProof): &vector<u8> { &proof.nonce }
public fun blind_dleq_proof(proof: &ReconstructProof): &ReconstructionDLEQProof {
    &proof.blind_dleq_proof
}
public fun total_dleq_proof(proof: &ReconstructProof): &ChaumPedersenProof {
    &proof.total_dleq_proof
}
public fun swap_combined_schnorr_proof(proof: &ReconstructProof): &GeneralizedSchnorrProof {
    &proof.swap_combined_schnorr_proof
}
public fun sum_swap_out_c1_schnorr_proof(proof: &ReconstructProof): &GeneralizedSchnorrProof {
    &proof.sum_swap_out_c1_schnorr_proof
}
public fun sum_swap_out_c2_schnorr_proof(proof: &ReconstructProof): &GeneralizedSchnorrProof {
    &proof.sum_swap_out_c2_schnorr_proof
}

// ========== 构造函数 ==========

public fun new_swap_out_card_proof(
    user_readable_card: vector<u8>,
    swap_out_card: vector<u8>,
    chaum_pedersen_proof: ChaumPedersenProof,
): SwapOutCardProof {
    SwapOutCardProof { user_readable_card, swap_out_card, chaum_pedersen_proof }
}

public fun new_reconstruction_dleq_proof(
    commitment: vector<u8>,
    response: vector<u8>,
    nonce: vector<u8>,
): ReconstructionDLEQProof {
    ReconstructionDLEQProof { commitment, response, nonce }
}

public fun new(
    swap_out_proofs: vector<SwapOutCardProof>,
    sum_c1_r_commit: vector<u8>,
    sum_c2_r_commit: vector<u8>,
    swap_sum_c1_commit: vector<u8>,
    swap_sum_c2_commit: vector<u8>,
    nonce: vector<u8>,
    blind_dleq_proof: ReconstructionDLEQProof,
    total_dleq_proof: ChaumPedersenProof,
    swap_combined_schnorr_proof: GeneralizedSchnorrProof,
    sum_swap_out_c1_schnorr_proof: GeneralizedSchnorrProof,
    sum_swap_out_c2_schnorr_proof: GeneralizedSchnorrProof,
): ReconstructProof {
    ReconstructProof {
        swap_out_proofs,
        sum_c1_r_commit,
        sum_c2_r_commit,
        swap_sum_c1_commit,
        swap_sum_c2_commit,
        nonce,
        blind_dleq_proof,
        total_dleq_proof,
        swap_combined_schnorr_proof,
        sum_swap_out_c1_schnorr_proof,
        sum_swap_out_c2_schnorr_proof,
    }
}

// ========== 辅助函数 ==========

/// 从字节反序列化 ElGamalCiphertext（96 bytes = 48 c1 + 48 c2）
public fun ciphertext_from_bytes(data: &vector<u8>): ElGamalCiphertext {
    // M-P16: 校验输入长度为 96 字节（48 c1 + 48 c2），防止越界访问
    assert!(data.length() == 96, 0);
    let mut c1_bytes = vector[];
    let mut c2_bytes = vector[];
    let mut i = 0;
    while (i < 48) {
        c1_bytes.push_back(*(vector::borrow(data, i)));
        i = i + 1;
    };
    i = 48;
    while (i < 96) {
        c2_bytes.push_back(*(vector::borrow(data, i)));
        i = i + 1;
    };
    bls_elgamal::new_ciphertext(
        bls12381::g1_from_bytes(&c1_bytes),
        bls12381::g1_from_bytes(&c2_bytes),
    )
}

// ========== 验证 ==========

/// 验证 ReconstructProof
/// cards: 明文牌点
/// output_cards: 重建后的输出密文
/// swap_out_cards: swap-out 牌密文
/// user_readable_cards: 用户可读牌密文
/// user_pk: 用户公钥
/// t: Fiat-Shamir transcript
public fun verify(
    proof: &ReconstructProof,
    cards: &vector<group_ops::Element<G1>>,           // plaintext card points
    output_cards: &vector<ElGamalCiphertext>,          // reconstructed output ciphertexts
    swap_out_cards: &vector<ElGamalCiphertext>,        // swap-out card ciphertexts
    user_readable_cards: &vector<ElGamalCiphertext>,   // user's readable card ciphertexts
    user_pk: &group_ops::Element<G1>,                  // user's public key
    t: &mut Transcript,
): bool {
    let n = proof.swap_out_proofs.length();
    let g = bls12381::g1_generator();

    // ===== Step 1: Verify swap_out_proofs =====
    if (n != user_readable_cards.length()) {
        return false
    };
    if (swap_out_cards.length() != n) {
        return false
    };

    let mut i = 0;
    while (i < n) {
        let sop = vector::borrow(&proof.swap_out_proofs, i);
        // 反序列化
        let deser_readable = ciphertext_from_bytes(&sop.user_readable_card);
        let deser_swap_out = ciphertext_from_bytes(&sop.swap_out_card);

        // 验证反序列化的 user_readable_card == user_readable_cards[i]
        let expected_readable = vector::borrow(user_readable_cards, i);
        if (bls_scalar::g1_to_bytes(bls_elgamal::c1(&deser_readable))
            != bls_scalar::g1_to_bytes(bls_elgamal::c1(expected_readable))) {
            return false
        };
        if (bls_scalar::g1_to_bytes(bls_elgamal::c2(&deser_readable))
            != bls_scalar::g1_to_bytes(bls_elgamal::c2(expected_readable))) {
            return false
        };

        // 验证反序列化的 swap_out_card == swap_out_cards[i]
        let expected_swap = vector::borrow(swap_out_cards, i);
        if (bls_scalar::g1_to_bytes(bls_elgamal::c1(&deser_swap_out))
            != bls_scalar::g1_to_bytes(bls_elgamal::c1(expected_swap))) {
            return false
        };
        if (bls_scalar::g1_to_bytes(bls_elgamal::c2(&deser_swap_out))
            != bls_scalar::g1_to_bytes(bls_elgamal::c2(expected_swap))) {
            return false
        };

        // 计算 delta_c1 = swap_out_card.c1 - user_readable_card.c1
        let delta_c1 = bls12381::g1_sub(
            bls_elgamal::c1(&deser_swap_out),
            bls_elgamal::c1(&deser_readable),
        );
        // 计算 delta_c2 = swap_out_card.c2 - user_readable_card.c2
        let delta_c2 = bls12381::g1_sub(
            bls_elgamal::c2(&deser_swap_out),
            bls_elgamal::c2(&deser_readable),
        );

        // 验证 Chaum-Pedersen: log_{delta_c1}(delta_c2) == log_G(user_pk)
        if (!chaum_pedersen::verify(
            &sop.chaum_pedersen_proof,
            &delta_c1,
            &g,
            &delta_c2,
            user_pk,
            t,
        )) {
            return false
        };

        i = i + 1;
    };

    // ===== Step 2: Generate rho_i random scalars =====
    // 追加所有 cards 到 transcript
    i = 0;
    while (i < cards.length()) {
        bls_transcript::append_point(t, &b"reconstruct_card", vector::borrow(cards, i));
        i = i + 1;
    };
    // 追加所有 output_cards c1
    i = 0;
    while (i < output_cards.length()) {
        bls_transcript::append_point(
            t,
            &b"reconstruct_output_c1",
            bls_elgamal::c1(vector::borrow(output_cards, i)),
        );
        i = i + 1;
    };
    // 追加所有 output_cards c2
    i = 0;
    while (i < output_cards.length()) {
        bls_transcript::append_point(
            t,
            &b"reconstruct_output_c2",
            bls_elgamal::c2(vector::borrow(output_cards, i)),
        );
        i = i + 1;
    };
    // 生成 rho_i
    let rho = bls_transcript::challenge_vec(t, &b"reconstruct_rho", output_cards.length());

    // ===== Step 3: Compute weighted sums =====
    // sum_output_c1 = g1_msm(rho, output_c1s)
    let mut output_c1s = vector[];
    i = 0;
    while (i < output_cards.length()) {
        output_c1s.push_back(*bls_elgamal::c1(vector::borrow(output_cards, i)));
        i = i + 1;
    };
    let sum_output_c1 = bls_scalar::g1_msm(&rho, &output_c1s);

    // 计算 (output_c2 - card) for each, then sum_output_c2_minus_cards = g1_msm(rho, c2_minus_cards)
    let mut c2_minus_cards = vector[];
    i = 0;
    while (i < output_cards.length()) {
        let c2_i = bls_elgamal::c2(vector::borrow(output_cards, i));
        let card_i = vector::borrow(cards, i);
        let diff = bls12381::g1_sub(c2_i, card_i);
        c2_minus_cards.push_back(diff);
        i = i + 1;
    };
    let sum_output_c2_minus_cards = bls_scalar::g1_msm(&rho, &c2_minus_cards);

    // ===== Step 4: Verify blind_dleq_proof =====
    let points_in_0 = sum_output_c1;
    let points_in_1 = sum_output_c2_minus_cards;
    let points_out_0 = bls12381::g1_from_bytes(&proof.sum_c1_r_commit);
    let points_out_1 = bls12381::g1_from_bytes(&proof.sum_c2_r_commit);

    // 4.1 追加 nonce 标量到 transcript
    let blind_nonce = bls12381::scalar_from_bytes(&proof.blind_dleq_proof.nonce);
    bls_transcript::append_scalar(t, &b"reconstruct_blind_nonce", &blind_nonce);

    // 4.2 追加 points_in 和 points_out 到 transcript
    bls_transcript::append_point(t, &b"reconstruct_blind_in_0", &points_in_0);
    bls_transcript::append_point(t, &b"reconstruct_blind_in_1", &points_in_1);
    bls_transcript::append_point(t, &b"reconstruct_blind_out_0", &points_out_0);
    bls_transcript::append_point(t, &b"reconstruct_blind_out_1", &points_out_1);

    // 4.3 提取 base_coefficient
    let base_coeff = bls_transcript::challenge(t, &b"reconstruct_base_coeff");

    // 4.4 计算 sum_point_in_total = points_in[0] + points_in[1] * base_coeff
    let points_in_1_scaled = bls12381::g1_mul(&base_coeff, &points_in_1);
    let sum_point_in_total = bls12381::g1_add(&points_in_0, &points_in_1_scaled);

    // 4.5 计算 sum_point_out_total = points_out[0] + points_out[1] * base_coeff
    let points_out_1_scaled = bls12381::g1_mul(&base_coeff, &points_out_1);
    let sum_point_out_total = bls12381::g1_add(&points_out_0, &points_out_1_scaled);

    // 4.6 追加 commitment 到 transcript
    let blind_commitment = bls12381::g1_from_bytes(&proof.blind_dleq_proof.commitment);
    // M-P17: 校验承诺点非 identity——identity 承诺削弱证明安全性
    if (bls_scalar::g1_is_identity(&blind_commitment)) {
        return false
    };
    bls_transcript::append_point(t, &b"reconstruct_blind_commitment", &blind_commitment);

    // 4.7 提取挑战 c
    let blind_c = bls_transcript::challenge(t, &b"reconstruct_blind_challenge");

    // 4.8 验证: sum_point_in_total * response == commitment + sum_point_out_total * c
    let blind_s = bls12381::scalar_from_bytes(&proof.blind_dleq_proof.response);
    let blind_lhs = bls12381::g1_mul(&blind_s, &sum_point_in_total);
    let blind_rhs_part2 = bls12381::g1_mul(&blind_c, &sum_point_out_total);
    let blind_rhs = bls12381::g1_add(&blind_commitment, &blind_rhs_part2);
    if (!bls_scalar::g1_equal(&blind_lhs, &blind_rhs)) {
        return false
    };

    // ===== Step 5: Verify swap Schnorr proofs (3 layers) =====

    // 5.1 swap combined: base_points = [swap_out[0].c1, swap_out[0].c2, swap_out[1].c1, swap_out[1].c2, ...]
    // R = swap_sum_c1_commit + swap_sum_c2_commit
    let mut combined_base_points = vector[];
    i = 0;
    while (i < swap_out_cards.length()) {
        let ct = vector::borrow(swap_out_cards, i);
        combined_base_points.push_back(*bls_elgamal::c1(ct));
        combined_base_points.push_back(*bls_elgamal::c2(ct));
        i = i + 1;
    };
    let swap_sum_c1_commit_pt = bls12381::g1_from_bytes(&proof.swap_sum_c1_commit);
    let swap_sum_c2_commit_pt = bls12381::g1_from_bytes(&proof.swap_sum_c2_commit);
    // M-P17: 校验承诺点非 identity——identity 承诺削弱证明安全性
    if (bls_scalar::g1_is_identity(&swap_sum_c1_commit_pt) || bls_scalar::g1_is_identity(&swap_sum_c2_commit_pt)) {
        return false
    };
    let combined_r = bls12381::g1_add(&swap_sum_c1_commit_pt, &swap_sum_c2_commit_pt);

    if (!schnorr_proof::verify(
        &proof.swap_combined_schnorr_proof,
        &combined_base_points,
        &combined_r,
        t,
    )) {
        return false
    };

    // 5.2 c1 Schnorr: base_points = [swap_out[0].c1, swap_out[1].c1, ...]
    // R = swap_sum_c1_commit
    let mut c1_base_points = vector[];
    i = 0;
    while (i < swap_out_cards.length()) {
        c1_base_points.push_back(*bls_elgamal::c1(vector::borrow(swap_out_cards, i)));
        i = i + 1;
    };
    if (!schnorr_proof::verify(
        &proof.sum_swap_out_c1_schnorr_proof,
        &c1_base_points,
        &swap_sum_c1_commit_pt,
        t,
    )) {
        return false
    };

    // 5.3 c2 Schnorr: base_points = [swap_out[0].c2, swap_out[1].c2, ...]
    // R = swap_sum_c2_commit
    let mut c2_base_points = vector[];
    i = 0;
    while (i < swap_out_cards.length()) {
        c2_base_points.push_back(*bls_elgamal::c2(vector::borrow(swap_out_cards, i)));
        i = i + 1;
    };
    if (!schnorr_proof::verify(
        &proof.sum_swap_out_c2_schnorr_proof,
        &c2_base_points,
        &swap_sum_c2_commit_pt,
        t,
    )) {
        return false
    };

    // ===== Step 6: Verify total_dleq_proof =====
    // c1_total = sum_c1_r_commit + swap_sum_c1_commit
    let c1_total = bls12381::g1_add(&points_out_0, &swap_sum_c1_commit_pt);
    // c2_total = sum_c2_r_commit + swap_sum_c2_commit
    let c2_total = bls12381::g1_add(&points_out_1, &swap_sum_c2_commit_pt);

    // 验证 log_G(user_pk) == log_{c1_total}(c2_total)
    if (!chaum_pedersen::verify(
        &proof.total_dleq_proof,
        &g,
        user_pk,
        &c1_total,
        &c2_total,
        t,
    )) {
        return false
    };

    true
}
