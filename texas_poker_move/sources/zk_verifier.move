module texas_poker::zk_verifier;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::bls_transcript::{Self, Transcript};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};
use texas_poker::reveal_token_proof::{Self, RevealTokenProof};
use texas_poker::remask_proof::{Self, RemaskProof};
use texas_poker::shuffle_proof::{Self, ShuffleProof};
use texas_poker::reconstruct_proof::{Self, ReconstructProof};

// ========== 错误码 ==========
#[error]
const EShuffleProofFailed: vector<u8> = b"Shuffle proof verification failed";
#[error]
const ERemaskProofFailed: vector<u8> = b"Remask proof verification failed";
#[error]
const ERevealTokenProofFailed: vector<u8> = b"Reveal token proof verification failed";
#[error]
const EReconstructProofFailed: vector<u8> = b"Reconstruct proof verification failed";

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

/// 创建重建证明的 Transcript
public fun new_reconstruct_transcript(): Transcript {
    let label = b"zk_reconstruct_proof_v1";
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
