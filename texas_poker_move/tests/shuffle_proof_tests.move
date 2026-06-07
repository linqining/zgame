#[test_only]
module texas_poker::shuffle_proof_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::shuffle_proof;
use texas_poker::schnorr_proof;
use texas_poker::bls_scalar;
use texas_poker::bls_elgamal;
use texas_poker::bls_transcript;
use std::unit_test::assert_eq;

// ========== 辅助函数 ==========

fun make_keys(): (group_ops::Element<bls12381::Scalar>, group_ops::Element<G1>) {
    let sk = bls_scalar::scalar_from_u64(123);
    let pk = bls12381::g1_mul(&sk, &bls12381::g1_generator());
    (sk, pk)
}

fun make_g1_point(seed: vector<u8>): group_ops::Element<G1> {
    bls12381::hash_to_g1(&seed)
}

fun make_dummy_schnorr_proof(): schnorr_proof::GeneralizedSchnorrProof {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));
    schnorr_proof::new(commitment, responses)
}

// ========== 构造函数和访问器测试 ==========

#[test]
fun new_and_accessors() {
    let sum_c1_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1"));
    let sum_c2_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2"));
    let combined = make_dummy_schnorr_proof();
    let c1_proof = make_dummy_schnorr_proof();
    let c2_proof = make_dummy_schnorr_proof();
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));

    let proof = shuffle_proof::new(
        sum_c1_commit,
        sum_c2_commit,
        combined,
        c1_proof,
        c2_proof,
        nonce,
    );

    assert_eq!(*shuffle_proof::sum_c1_commit(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1")));
    assert_eq!(*shuffle_proof::sum_c2_commit(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2")));
    assert_eq!(*shuffle_proof::nonce(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42)));
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_empty_input() {
    let sum_c1_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1"));
    let sum_c2_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2"));
    let combined = make_dummy_schnorr_proof();
    let c1_proof = make_dummy_schnorr_proof();
    let c2_proof = make_dummy_schnorr_proof();
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = shuffle_proof::new(
        sum_c1_commit, sum_c2_commit, combined, c1_proof, c2_proof, nonce,
    );

    let input_cts = vector[];
    let output_cts = vector[];
    let (_sk, pk) = make_keys();
    let mut t = bls_transcript::new(&b"test");
    let result = shuffle_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    // Empty input → n == 0 → should reject
    assert!(!result);
}

#[test]
fun verify_rejects_length_mismatch() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // 2 input ciphertexts
    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    // 1 output ciphertext → length mismatch
    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt3"), &pk, &r));

    let sum_c1_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1"));
    let sum_c2_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2"));
    let combined = make_dummy_schnorr_proof();
    let c1_proof = make_dummy_schnorr_proof();
    let c2_proof = make_dummy_schnorr_proof();
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = shuffle_proof::new(
        sum_c1_commit, sum_c2_commit, combined, c1_proof, c2_proof, nonce,
    );

    let mut t = bls_transcript::new(&b"test");
    let result = shuffle_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_wrong_proof_data() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    // Wrong commitment data
    let sum_c1_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_c1"));
    let sum_c2_commit = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_c2"));
    let combined = make_dummy_schnorr_proof();
    let c1_proof = make_dummy_schnorr_proof();
    let c2_proof = make_dummy_schnorr_proof();
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = shuffle_proof::new(
        sum_c1_commit, sum_c2_commit, combined, c1_proof, c2_proof, nonce,
    );

    let mut t = bls_transcript::new(&b"test");
    let result = shuffle_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    // Wrong commitments → recomputed sum won't match → should reject
    assert!(!result);
}

#[test]
fun verify_rejects_mismatched_sum_commitments() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    // Use identity as sum commitments → won't match recomputed values
    let sum_c1_commit = bls_scalar::g1_to_bytes(&bls12381::g1_identity());
    let sum_c2_commit = bls_scalar::g1_to_bytes(&bls12381::g1_identity());
    let combined = make_dummy_schnorr_proof();
    let c1_proof = make_dummy_schnorr_proof();
    let c2_proof = make_dummy_schnorr_proof();
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = shuffle_proof::new(
        sum_c1_commit, sum_c2_commit, combined, c1_proof, c2_proof, nonce,
    );

    let mut t = bls_transcript::new(&b"test");
    let result = shuffle_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    assert!(!result);
}
