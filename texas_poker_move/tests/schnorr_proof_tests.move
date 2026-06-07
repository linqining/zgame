#[test_only]
module texas_poker::schnorr_proof_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::schnorr_proof;
use texas_poker::bls_scalar;
use texas_poker::bls_transcript;
use std::unit_test::assert_eq;

// ========== 辅助函数 ==========

fun make_g1_point(seed: vector<u8>): group_ops::Element<G1> {
    bls12381::hash_to_g1(&seed)
}

fun make_scalar(val: u64): group_ops::Element<bls12381::Scalar> {
    bls_scalar::scalar_from_u64(val)
}

// ========== 构造函数和访问器测试 ==========

#[test]
fun new_and_accessors() {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(100)));
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(200)));

    let proof = schnorr_proof::new(commitment, responses);

    assert_eq!(*schnorr_proof::commitment(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"commitment")));
    assert_eq!(schnorr_proof::responses(&proof).length(), 2);
}

#[test]
fun new_with_empty_responses() {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let responses = vector[];
    let proof = schnorr_proof::new(commitment, responses);
    assert_eq!(schnorr_proof::responses(&proof).length(), 0);
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_length_mismatch() {
    // responses has 2 elements, base_points has 1 → length mismatch
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(100)));
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(200)));

    let proof = schnorr_proof::new(commitment, responses);

    let mut base_points = vector[];
    base_points.push_back(make_g1_point(b"base1"));

    let r_point = make_g1_point(b"r_point");
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_identity_r_point() {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(100)));

    let proof = schnorr_proof::new(commitment, responses);

    let mut base_points = vector[];
    base_points.push_back(make_g1_point(b"base1"));

    // R = identity → should reject
    let r_point = bls12381::g1_identity();
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_identity_base_point() {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(100)));

    let proof = schnorr_proof::new(commitment, responses);

    // base_point = identity → should reject
    let mut base_points = vector[];
    base_points.push_back(bls12381::g1_identity());

    let r_point = make_g1_point(b"r_point");
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_wrong_proof_data() {
    // Construct a proof with garbage commitment that doesn't match the Schnorr equation
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(999)));

    let proof = schnorr_proof::new(commitment, responses);

    let mut base_points = vector[];
    base_points.push_back(bls12381::g1_generator());

    let r_point = make_g1_point(b"r_point");
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    // Wrong proof data should fail verification
    assert!(!result);
}

#[test]
fun verify_rejects_empty_base_points() {
    // 0 responses, 0 base_points → R is identity check will fail
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let responses = vector[];
    let proof = schnorr_proof::new(commitment, responses);

    let base_points = vector[];
    let r_point = make_g1_point(b"r_point");
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    // With 0 base_points and 0 responses, length matches (both 0),
    // but R is not identity, and all base_points pass (none to check).
    // Then MSM of 0 elements = identity, commitment + c*R != identity → false
    assert!(!result);
}

#[test]
fun verify_with_multiple_base_points() {
    // 3 base points, 3 responses, but wrong data → should fail
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let mut responses = vector[];
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(10)));
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(20)));
    responses.push_back(bls_scalar::scalar_to_bytes(&make_scalar(30)));

    let proof = schnorr_proof::new(commitment, responses);

    let mut base_points = vector[];
    base_points.push_back(make_g1_point(b"base1"));
    base_points.push_back(make_g1_point(b"base2"));
    base_points.push_back(make_g1_point(b"base3"));

    let r_point = make_g1_point(b"r_point");
    let mut t = bls_transcript::new(&b"test");
    let result = schnorr_proof::verify(&proof, &base_points, &r_point, &mut t);
    assert!(!result);
}
