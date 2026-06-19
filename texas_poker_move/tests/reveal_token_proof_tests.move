#[test_only]
module texas_poker::reveal_token_proof_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::reveal_token_proof;
use texas_poker::bls_scalar;
use texas_poker::bls_elgamal;
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

// ========== 构造函数和访问器测试 ==========

#[test]
fun new_and_accessors() {
    let pk_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"pk"));
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"t2"));
    let s = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));

    assert_eq!(*reveal_token_proof::user_public_key(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"pk")));
    assert_eq!(*reveal_token_proof::commitment_t1(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"t1")));
    assert_eq!(*reveal_token_proof::commitment_t2(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"t2")));
    assert_eq!(*reveal_token_proof::response_s(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42)));
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_invalid_ciphertext() {
    let (sk, pk) = make_keys();
    let pk_bytes = bls_scalar::g1_to_bytes(&pk);
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"t2"));
    let s = bls_scalar::scalar_to_bytes(&sk);

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));

    // Placeholder ciphertext (c1=c2=identity) → invalid
    let ct = bls_elgamal::new_placeholder_card();
    let reveal_token = make_g1_point(b"reveal_token");
    let result = reveal_token_proof::verify(&proof, &ct, &reveal_token, &pk);
    assert!(!result);
}

#[test]
fun verify_rejects_identity_reveal_token() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);

    let pk_bytes = bls_scalar::g1_to_bytes(&pk);
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"t2"));
    let s = bls_scalar::scalar_to_bytes(&sk);

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));

    // reveal_token = identity → should reject
    let reveal_token = bls12381::g1_identity();
    let result = reveal_token_proof::verify(&proof, &ct, &reveal_token, &pk);
    assert!(!result);
}

#[test]
fun verify_rejects_pk_mismatch() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);

    // Use wrong pk_bytes (different from expected_pk)
    let wrong_pk = make_g1_point(b"wrong_pk");
    let pk_bytes = bls_scalar::g1_to_bytes(&wrong_pk);
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"t2"));
    let s = bls_scalar::scalar_to_bytes(&sk);

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));

    let reveal_token = bls_elgamal::gen_reveal_token(&ct, &sk);
    let result = reveal_token_proof::verify(&proof, &ct, &reveal_token, &pk);
    // pk_bytes != expected_pk bytes → should reject
    assert!(!result);
}

#[test]
fun verify_rejects_wrong_proof_data() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);

    let pk_bytes = bls_scalar::g1_to_bytes(&pk);
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t2"));
    let s = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999));

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));

    let reveal_token = make_g1_point(b"reveal_token");
    let result = reveal_token_proof::verify(&proof, &ct, &reveal_token, &pk);
    // Wrong proof data → DLEq equations won't hold
    assert!(!result);
}

#[test]
fun verify_rejects_c1_identity_only() {
    // Create a ciphertext where c1 is identity but c2 is not
    let (_sk, pk) = make_keys();
    let ct = bls_elgamal::new_ciphertext(
        bls12381::g1_identity(),
        make_g1_point(b"c2_value"),
    );

    let pk_bytes = bls_scalar::g1_to_bytes(&pk);
    let t1 = bls_scalar::g1_to_bytes(&make_g1_point(b"t1"));
    let t2 = bls_scalar::g1_to_bytes(&make_g1_point(b"t2"));
    let s = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));

    let proof = reveal_token_proof::new(pk_bytes, t1, t2, s, bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));
    let reveal_token = make_g1_point(b"reveal_token");
    let result = reveal_token_proof::verify(&proof, &ct, &reveal_token, &pk);
    // c1 = identity → is_valid returns false
    assert!(!result);
}
