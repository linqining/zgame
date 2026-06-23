module texas_poker::zk_verifier;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript::{Self, Transcript};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};
use texas_poker::reveal_token_proof::{Self, RevealTokenProof};
use texas_poker::remask_proof::{Self, RemaskProof};
use texas_poker::leave_proof::{Self, LeaveProof};
use texas_poker::shuffle_proof::{Self, ShuffleProof};
use texas_poker::reconstruct_proof::{Self, ReconstructProof};

// ========== 错误码 ==========
#[error]
const EShuffleProofFailed: vector<u8> = b"Shuffle proof verification failed";
#[error]
const ERemaskProofFailed: vector<u8> = b"Remask proof verification failed";
#[error]
const ELeaveProofFailed: vector<u8> = b"Leave proof verification failed";
#[error]
const ERevealTokenProofFailed: vector<u8> = b"Reveal token proof verification failed";
#[error]
const EReconstructProofFailed: vector<u8> = b"Reconstruct proof verification failed";
#[error]
const EPkOwnershipProofFailed: vector<u8> = b"PK ownership proof verification failed";

// ========== Transcript 工厂 ==========

/// 创建洗牌证明的 Transcript
public fun new_shuffle_transcript(): Transcript {
    let label = b"zk_shuffle_proof_v1";
    bls_transcript::new(&label)
}

/// 创建重掩码证明的 Transcript
public fun new_remask_transcript(): Transcript {
    let label = b"zk_remask_proof_v1";
    bls_transcript::new(&label)
}

/// 创建离场证明的 Transcript
public fun new_leave_transcript(): Transcript {
    let label = b"zk_leave_proof_v1";
    bls_transcript::new(&label)
}

/// 创建重建证明的 Transcript
public fun new_reconstruct_transcript(): Transcript {
    let label = b"zk_reconstruct_proof_v1";
    bls_transcript::new(&label)
}

/// 创建 remask + shuffle 共享 Transcript（与 Rust 端 poker_protocol_mask_shuffle 对应）
public fun new_mask_shuffle_transcript(): Transcript {
    let label = b"zk_mask_shuffle_proof_v1";
    bls_transcript::new(&label)
}

// ========== 验证入口 ==========

/// 验证洗牌证明
public fun verify_shuffle(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    pk: &group_ops::Element<G1>,
    proof: &ShuffleProof,
): bool {
    let mut t = new_shuffle_transcript();
    shuffle_proof::verify(proof, input_cts, output_cts, pk, &mut t)
}

/// 验证洗牌证明（断言版本，失败则 abort）
public fun verify_shuffle_or_abort(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    pk: &group_ops::Element<G1>,
    proof: &ShuffleProof,
) {
    assert!(verify_shuffle(input_cts, output_cts, pk, proof), EShuffleProofFailed);
}

/// 验证洗牌证明（使用外部 Transcript，用于 remask+shuffle 共享 transcript 场景）
public fun verify_shuffle_with_transcript(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    pk: &group_ops::Element<G1>,
    proof: &ShuffleProof,
    transcript: &mut Transcript,
): bool {
    shuffle_proof::verify(proof, input_cts, output_cts, pk, transcript)
}

/// 验证洗牌证明（使用外部 Transcript，断言版本）
public fun verify_shuffle_with_transcript_or_abort(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    pk: &group_ops::Element<G1>,
    proof: &ShuffleProof,
    transcript: &mut Transcript,
) {
    assert!(verify_shuffle_with_transcript(input_cts, output_cts, pk, proof, transcript), EShuffleProofFailed);
}

/// 验证重掩码证明
public fun verify_remask(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &RemaskProof,
): bool {
    let mut t = new_remask_transcript();
    remask_proof::verify(proof, input_cts, output_cts, player_pk, &mut t)
}

/// 验证重掩码证明（断言版本）
public fun verify_remask_or_abort(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &RemaskProof,
) {
    assert!(verify_remask(input_cts, output_cts, player_pk, proof), ERemaskProofFailed);
}

/// 验证重掩码证明（使用外部 Transcript，用于 remask+shuffle 共享 transcript 场景）
public fun verify_remask_with_transcript(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &RemaskProof,
    transcript: &mut Transcript,
): bool {
    remask_proof::verify(proof, input_cts, output_cts, player_pk, transcript)
}

/// 验证重掩码证明（使用外部 Transcript，断言版本）
public fun verify_remask_with_transcript_or_abort(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &RemaskProof,
    transcript: &mut Transcript,
) {
    assert!(verify_remask_with_transcript(input_cts, output_cts, player_pk, proof, transcript), ERemaskProofFailed);
}

/// 验证离场证明
public fun verify_leave(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &LeaveProof,
): bool {
    let mut t = new_leave_transcript();
    leave_proof::verify(proof, input_cts, output_cts, player_pk, &mut t)
}

/// 验证离场证明（断言版本）
public fun verify_leave_or_abort(
    input_cts: &vector<ElGamalCiphertext>,
    output_cts: &vector<ElGamalCiphertext>,
    player_pk: &group_ops::Element<G1>,
    proof: &LeaveProof,
) {
    assert!(verify_leave(input_cts, output_cts, player_pk, proof), ELeaveProofFailed);
}

/// 验证揭牌令牌证明
public fun verify_reveal_token(
    encrypted_card: &ElGamalCiphertext,
    reveal_token: &group_ops::Element<G1>,
    expected_pk: &group_ops::Element<G1>,
    proof: &RevealTokenProof,
): bool {
    reveal_token_proof::verify(proof, encrypted_card, reveal_token, expected_pk)
}

/// 验证揭牌令牌证明（断言版本）
public fun verify_reveal_token_or_abort(
    encrypted_card: &ElGamalCiphertext,
    reveal_token: &group_ops::Element<G1>,
    expected_pk: &group_ops::Element<G1>,
    proof: &RevealTokenProof,
) {
    assert!(verify_reveal_token(encrypted_card, reveal_token, expected_pk, proof), ERevealTokenProofFailed);
}

/// 验证重建证明
public fun verify_reconstruct(
    cards: &vector<group_ops::Element<G1>>,
    output_cards: &vector<ElGamalCiphertext>,
    swap_out_cards: &vector<ElGamalCiphertext>,
    user_readable_cards: &vector<ElGamalCiphertext>,
    user_pk: &group_ops::Element<G1>,
    proof: &ReconstructProof,
): bool {
    let mut t = new_reconstruct_transcript();
    reconstruct_proof::verify(proof, cards, output_cards, swap_out_cards, user_readable_cards, user_pk, &mut t)
}

/// 验证重建证明（断言版本）
public fun verify_reconstruct_or_abort(
    cards: &vector<group_ops::Element<G1>>,
    output_cards: &vector<ElGamalCiphertext>,
    swap_out_cards: &vector<ElGamalCiphertext>,
    user_readable_cards: &vector<ElGamalCiphertext>,
    user_pk: &group_ops::Element<G1>,
    proof: &ReconstructProof,
) {
    assert!(verify_reconstruct(cards, output_cards, swap_out_cards, user_readable_cards, user_pk, proof), EReconstructProofFailed);
}

// ========== 密文辅助 ==========

/// 从字节反序列化密文数组
/// 每个密文 96 字节（48 c1 + 48 c2）
public fun deserialize_ciphertexts(data: &vector<u8>): vector<ElGamalCiphertext> {
    // m3 修复：校验数据长度为 96 的整数倍，防止截断数据被静默解析
    assert!(data.length() % 96 == 0, EShuffleProofFailed);
    let n = data.length() / 96;
    let mut result = vector[];
    let mut i = 0;
    while (i < n) {
        let mut c1_bytes = vector[];
        let mut c2_bytes = vector[];
        let mut j = 0;
        while (j < 48) {
            c1_bytes.push_back(*(vector::borrow(data, i * 96 + j)));
            j = j + 1;
        };
        j = 48;
        while (j < 96) {
            c2_bytes.push_back(*(vector::borrow(data, i * 96 + j)));
            j = j + 1;
        };
        result.push_back(bls_elgamal::new_ciphertext(
            bls12381::g1_from_bytes(&c1_bytes),
            bls12381::g1_from_bytes(&c2_bytes),
        ));
        i = i + 1;
    };
    result
}

/// 从字节反序列化公钥
public fun deserialize_pk(pk_bytes: &vector<u8>): group_ops::Element<G1> {
    bls12381::g1_from_bytes(pk_bytes)
}

/// 从字节反序列化多个 G1 点（兼容性保留：原始发布版本包含此函数）
public fun deserialize_g1_points(data: &vector<u8>): vector<group_ops::Element<G1>> {
    let mut result = vector[];
    let mut i = 0;
    let len = data.length();
    // 每个 G1 compressed 点为 48 字节
    while (i + 48 <= len) {
        let mut point_bytes = vector[];
        let mut j = 0;
        while (j < 48) {
            vector::push_back(&mut point_bytes, data[i + j]);
            j = j + 1;
        };
        vector::push_back(&mut result, bls12381::g1_from_bytes(&point_bytes));
        i = i + 48;
    };
    result
}

// ========== PK 所有权证明 ==========

/// 验证 PK 所有权证明 (Schnorr proof of knowledge of sk where pk = G * sk)
/// proof_bytes 格式: commitment (48 bytes G1) + response (32 bytes scalar)
/// 使用 hash_to_scalar 进行挑战派生，清除高位确保 < 曲线阶
public fun verify_pk_ownership(pk: &group_ops::Element<G1>, proof_bytes: &vector<u8>): bool {
    // M-D11 修复：拒绝恒等元公钥
    if (bls_scalar::g1_is_identity(pk)) {
        return false
    };

    // 检查长度: 48 (commitment) + 32 (response) = 80
    if (proof_bytes.length() != 80) {
        return false
    };

    // 拒绝恒等元公钥
    let g = bls12381::g1_generator();
    let pk_bytes = bls_scalar::g1_to_bytes(pk);
    let g_bytes = bls_scalar::g1_to_bytes(&g);

    // 反序列化 commitment 和 response
    let mut commitment_bytes = vector[];
    let mut i = 0;
    while (i < 48) {
        commitment_bytes.push_back(*(vector::borrow(proof_bytes, i)));
        i = i + 1;
    };
    let mut response_bytes = vector[];
    i = 48;
    while (i < 80) {
        response_bytes.push_back(*(vector::borrow(proof_bytes, i)));
        i = i + 1;
    };

    let commitment = bls12381::g1_from_bytes(&commitment_bytes);
    let response = bls12381::scalar_from_bytes(&response_bytes);

    // 拒绝恒等元 commitment
    if (bls_scalar::g1_is_identity(&commitment)) {
        return false
    };

    // M-D12 修复：使用 hash_to_scalar 替代原始 SHA2-256，清除高位确保 < 曲线阶
    // challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)
    let mut hash_input = vector[];
    let mut j = 0;
    while (j < g_bytes.length()) {
        hash_input.push_back(g_bytes[j]);
        j = j + 1;
    };
    j = 0;
    while (j < pk_bytes.length()) {
        hash_input.push_back(pk_bytes[j]);
        j = j + 1;
    };
    j = 0;
    while (j < commitment_bytes.length()) {
        hash_input.push_back(commitment_bytes[j]);
        j = j + 1;
    };
    let challenge = bls_scalar::hash_to_scalar(&hash_input);

    // 验证: G * response == commitment + pk * challenge
    bls_scalar::verify_dleq(&g, pk, &commitment, &response, &challenge)
}

/// 验证 PK 所有权证明（断言版本）
public fun verify_pk_ownership_or_abort(pk: &group_ops::Element<G1>, proof_bytes: &vector<u8>) {
    assert!(verify_pk_ownership(pk, proof_bytes), EPkOwnershipProofFailed);
}
