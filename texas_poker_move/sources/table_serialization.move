module texas_poker::table_serialization;

/// 证明反序列化和 BLS 工具函数
/// 从 table.move 中提取的纯函数，不依赖 Table 结构体

use sui::bls12381;
use sui::group_ops;
use texas_poker::bls_scalar;
use texas_poker::schnorr_proof::{Self, GeneralizedSchnorrProof};
use texas_poker::shuffle_proof::ShuffleProof;
use texas_poker::remask_proof::RemaskProof;
use texas_poker::leave_proof::LeaveProof;
use texas_poker::reveal_token_proof::RevealTokenProof;
use texas_poker::reconstruct_proof::ReconstructProof;
use texas_poker::chaum_pedersen;

// ========== 常量 ==========
const G1_POINT_SIZE: u64 = 48;
const SCALAR_SIZE: u64 = 32;
const CIPHERTEXT_SIZE: u64 = 96;

// ========== BLS 公钥聚合 ==========

/// 将 pk 加到聚合公钥上
public fun add_pk_to_aggregated(aggregated: &vector<u8>, pk: &vector<u8>): vector<u8> {
    let agg_point = if (aggregated.length() == 0) {
        bls12381::g1_identity()
    } else {
        bls12381::g1_from_bytes(aggregated)
    };
    let pk_point = bls12381::g1_from_bytes(pk);
    let new_agg = bls12381::g1_add(&agg_point, &pk_point);
    bls_scalar::g1_to_bytes(&new_agg)
}

/// 从聚合公钥中减去 pk
public fun remove_pk_from_aggregated(aggregated: &vector<u8>, pk: &vector<u8>): vector<u8> {
    let agg_point = bls12381::g1_from_bytes(aggregated);
    let pk_point = bls12381::g1_from_bytes(pk);
    let new_agg = bls12381::g1_sub(&agg_point, &pk_point);
    bls_scalar::g1_to_bytes(&new_agg)
}

// ========== 字节读取辅助 ==========

public fun read_bytes(data: &vector<u8>, offset: u64, len: u64): vector<u8> {
    let mut result = vector[];
    let mut i = 0;
    while (i < len) {
        result.push_back(*vector::borrow(data, offset + i));
        i = i + 1;
    };
    result
}

public fun read_u16(data: &vector<u8>, offset: u64): u64 {
    let lo = (*vector::borrow(data, offset) as u64);
    let hi = (*vector::borrow(data, offset + 1) as u64);
    lo + (hi << 8)
}

public fun read_g1_point(data: &vector<u8>, offset: u64): vector<u8> {
    read_bytes(data, offset, G1_POINT_SIZE)
}

public fun read_scalar(data: &vector<u8>, offset: u64): vector<u8> {
    read_bytes(data, offset, SCALAR_SIZE)
}

// ========== 证明反序列化 ==========

public fun deserialize_schnorr_proof(data: &vector<u8>, mut offset: u64): (GeneralizedSchnorrProof, u64) {
    let commitment = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut responses = vector[];
    let mut i = 0;
    while (i < count) {
        responses.push_back(read_scalar(data, offset));
        offset = offset + SCALAR_SIZE;
        i = i + 1;
    };
    (schnorr_proof::new(commitment, responses), offset)
}

public fun deserialize_shuffle_proof(data: &vector<u8>): ShuffleProof {
    let mut offset = 0;
    let sum_c1_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let sum_c2_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let (combined_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_c1_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_c2_schnorr_proof, _offset) = deserialize_schnorr_proof(data, offset);
    texas_poker::shuffle_proof::new(
        sum_c1_commit,
        sum_c2_commit,
        combined_schnorr_proof,
        sum_c1_schnorr_proof,
        sum_c2_schnorr_proof,
        nonce,
    )
}

public fun deserialize_remask_proof(data: &vector<u8>): RemaskProof {
    let mut offset = 0;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut per_card_commitments = vector[];
    let mut i = 0;
    while (i < count) {
        per_card_commitments.push_back(read_g1_point(data, offset));
        offset = offset + G1_POINT_SIZE;
        i = i + 1;
    };
    let commitment_pk = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let nonce = read_scalar(data, offset);
    texas_poker::remask_proof::new(per_card_commitments, commitment_pk, response, nonce)
}

/// 由合约生成 52 张明文牌，序列化为 G1 compressed bytes
public fun generate_plaintext_bytes(): vector<vector<u8>> {
    let cards = bls_scalar::generate_plaintext_cards();
    let mut result = vector[];
    let mut i = 0;
    while (i < cards.length()) {
        result.push_back(*group_ops::bytes(&cards[i]));
        i = i + 1;
    };
    result
}

public fun deserialize_leave_proof(data: &vector<u8>): LeaveProof {
    let mut offset = 0;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut per_card_commitments = vector[];
    let mut i = 0;
    while (i < count) {
        per_card_commitments.push_back(read_g1_point(data, offset));
        offset = offset + G1_POINT_SIZE;
        i = i + 1;
    };
    let commitment_pk = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let nonce = read_scalar(data, offset);
    texas_poker::leave_proof::new(per_card_commitments, commitment_pk, response, nonce)
}

public fun deserialize_reveal_token_proof(data: &vector<u8>): RevealTokenProof {
    let mut offset = 0;
    let user_public_key = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let commitment_t1 = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let commitment_t2 = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response_s = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    // M4 修复：读取 nonce 字段
    let nonce = read_scalar(data, offset);
    texas_poker::reveal_token_proof::new(user_public_key, commitment_t1, commitment_t2, response_s, nonce)
}

public fun deserialize_reconstruct_proof(data: &vector<u8>): ReconstructProof {
    let mut offset = 0;
    // swap_out_cards_proofs
    let swap_out_count = read_u16(data, offset);
    offset = offset + 2;
    let mut swap_out_proofs = vector[];
    let mut i = 0;
    while (i < swap_out_count) {
        // user_readable_card: 96 bytes
        let user_readable_card = read_bytes(data, offset, CIPHERTEXT_SIZE);
        offset = offset + CIPHERTEXT_SIZE;
        // swap_out_card: 96 bytes
        let swap_out_card = read_bytes(data, offset, CIPHERTEXT_SIZE);
        offset = offset + CIPHERTEXT_SIZE;
        // chaum_pedersen: commitment_a(48) + commitment_b(48) + response(32)
        let cp_commitment_a = read_g1_point(data, offset);
        offset = offset + G1_POINT_SIZE;
        let cp_commitment_b = read_g1_point(data, offset);
        offset = offset + G1_POINT_SIZE;
        let cp_response = read_scalar(data, offset);
        offset = offset + SCALAR_SIZE;
        let cp_proof = chaum_pedersen::new(cp_commitment_a, cp_commitment_b, cp_response);
        swap_out_proofs.push_back(
            texas_poker::reconstruct_proof::new_swap_out_card_proof(user_readable_card, swap_out_card, cp_proof)
        );
        i = i + 1;
    };
    let sum_c1_r_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let sum_c2_r_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let swap_sum_c1_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let swap_sum_c2_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    // blind_dleq_proof: commitment(48) + response(32) + nonce(32)
    let blind_commitment = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let blind_response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let blind_nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let blind_dleq_proof = texas_poker::reconstruct_proof::new_reconstruction_dleq_proof(
        blind_commitment, blind_response, blind_nonce
    );
    // total_dleq_proof: commitment_a(48) + commitment_b(48) + response(32)
    let total_commitment_a = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let total_commitment_b = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let total_response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let total_dleq_proof = chaum_pedersen::new(total_commitment_a, total_commitment_b, total_response);
    // schnorr proofs
    let (swap_combined_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_swap_out_c1_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_swap_out_c2_schnorr_proof, _offset) = deserialize_schnorr_proof(data, offset);
    texas_poker::reconstruct_proof::new(
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
    )
}
