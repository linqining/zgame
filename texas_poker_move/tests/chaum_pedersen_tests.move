#[test_only]
module texas_poker::chaum_pedersen_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::chaum_pedersen;
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
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(42));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    assert_eq!(*chaum_pedersen::commitment_a(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a")));
    assert_eq!(*chaum_pedersen::commitment_b(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b")));
    assert_eq!(*chaum_pedersen::response(&proof), bls_scalar::scalar_to_bytes(&make_scalar(42)));
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_identity_g1() {
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(42));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    // g1 = identity → should reject
    let g1 = bls12381::g1_identity();
    let g2 = make_g1_point(b"g2");
    let p1 = make_g1_point(b"p1");
    let p2 = make_g1_point(b"p2");
    let mut t = bls_transcript::new(&b"test");
    let result = chaum_pedersen::verify(&proof, &g1, &g2, &p1, &p2, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_identity_g2() {
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(42));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    // g2 = identity → should reject
    let g1 = make_g1_point(b"g1");
    let g2 = bls12381::g1_identity();
    let p1 = make_g1_point(b"p1");
    let p2 = make_g1_point(b"p2");
    let mut t = bls_transcript::new(&b"test");
    let result = chaum_pedersen::verify(&proof, &g1, &g2, &p1, &p2, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_wrong_proof_data() {
    // Construct proof with wrong data → DLEq equations won't hold
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(999));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    let g1 = bls12381::g1_generator();
    let g2 = make_g1_point(b"g2");
    let p1 = make_g1_point(b"p1");
    let p2 = make_g1_point(b"p2");
    let mut t = bls_transcript::new(&b"test");
    let result = chaum_pedersen::verify(&proof, &g1, &g2, &p1, &p2, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_both_identity_bases() {
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(42));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    // Both g1 and g2 = identity → should reject
    let g1 = bls12381::g1_identity();
    let g2 = bls12381::g1_identity();
    let p1 = make_g1_point(b"p1");
    let p2 = make_g1_point(b"p2");
    let mut t = bls_transcript::new(&b"test");
    let result = chaum_pedersen::verify(&proof, &g1, &g2, &p1, &p2, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_with_generator_as_base() {
    // Even with valid base points, wrong proof data should fail
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"random_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"random_b"));
    let resp = bls_scalar::scalar_to_bytes(&make_scalar(12345));

    let proof = chaum_pedersen::new(comm_a, comm_b, resp);

    let g1 = bls12381::g1_generator();
    let g2 = bls_scalar::base_h();
    let x = make_scalar(77);
    let p1 = bls12381::g1_mul(&x, &g1);
    let p2 = bls12381::g1_mul(&x, &g2);
    let mut t = bls_transcript::new(&b"test");
    let result = chaum_pedersen::verify(&proof, &g1, &g2, &p1, &p2, &mut t);
    assert!(!result);
}
