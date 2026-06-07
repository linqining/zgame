#[test_only]
module texas_poker::bls_scalar_tests;

use texas_poker::bls_scalar;
use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use std::unit_test::assert_eq;

#[test]
fun hash_to_scalar_produces_consistent_results() {
    let data = b"test_data";
    let s1 = bls_scalar::hash_to_scalar(&data);
    let s2 = bls_scalar::hash_to_scalar(&data);
    assert_eq!(bls_scalar::scalar_to_bytes(&s1), bls_scalar::scalar_to_bytes(&s2));
}

#[test]
fun hash_to_scalar_different_data_different_results() {
    let data1 = b"test_data_1";
    let data2 = b"test_data_2";
    let s1 = bls_scalar::hash_to_scalar(&data1);
    let s2 = bls_scalar::hash_to_scalar(&data2);
    assert!(bls_scalar::scalar_to_bytes(&s1) != bls_scalar::scalar_to_bytes(&s2));
}

#[test]
fun scalar_zero_is_zero() {
    let z = bls_scalar::scalar_zero();
    let bytes = bls_scalar::scalar_to_bytes(&z);
    let mut expected: vector<u8> = vector[];
    let mut i = 0;
    while (i < bytes.length()) {
        expected.push_back(0);
        i = i + 1;
    };
    assert_eq!(bytes, expected);
}

#[test]
fun scalar_one_is_one() {
    let one = bls_scalar::scalar_one();
    let from_u64 = bls_scalar::scalar_from_u64(1);
    assert_eq!(bls_scalar::scalar_to_bytes(&one), bls_scalar::scalar_to_bytes(&from_u64));
}

#[test]
fun scalar_add_commutative() {
    let a = bls_scalar::scalar_from_u64(7);
    let b = bls_scalar::scalar_from_u64(13);
    let ab = bls_scalar::scalar_add(&a, &b);
    let ba = bls_scalar::scalar_add(&b, &a);
    assert_eq!(bls_scalar::scalar_to_bytes(&ab), bls_scalar::scalar_to_bytes(&ba));
}

#[test]
fun scalar_mul_identity() {
    let a = bls_scalar::scalar_from_u64(42);
    let one = bls_scalar::scalar_one();
    let result = bls_scalar::scalar_mul(&a, &one);
    assert_eq!(bls_scalar::scalar_to_bytes(&result), bls_scalar::scalar_to_bytes(&a));
}

#[test]
fun scalar_add_zero() {
    let a = bls_scalar::scalar_from_u64(42);
    let z = bls_scalar::scalar_zero();
    let result = bls_scalar::scalar_add(&a, &z);
    assert_eq!(bls_scalar::scalar_to_bytes(&result), bls_scalar::scalar_to_bytes(&a));
}

#[test]
fun g1_identity_is_identity() {
    let id = bls12381::g1_identity();
    assert!(bls_scalar::g1_is_identity(&id));
}

#[test]
fun g1_generator_not_identity() {
    let gen = bls12381::g1_generator();
    assert!(!bls_scalar::g1_is_identity(&gen));
}

#[test]
fun g1_msm_empty_returns_identity() {
    let scalars: vector<group_ops::Element<Scalar>> = vector[];
    let points: vector<group_ops::Element<bls12381::G1>> = vector[];
    let result = bls_scalar::g1_msm(&scalars, &points);
    assert!(bls_scalar::g1_is_identity(&result));
}

#[test]
fun g1_msm_single_pair() {
    let s = bls_scalar::scalar_from_u64(5);
    let p = bls12381::g1_generator();
    let scalars = vector[s];
    let points = vector[p];
    let msm_result = bls_scalar::g1_msm(&scalars, &points);
    let mul_result = bls12381::g1_mul(vector::borrow(&scalars, 0), vector::borrow(&points, 0));
    assert!(bls_scalar::g1_equal(&msm_result, &mul_result));
}

#[test]
fun generate_plaintext_cards_returns_52() {
    let cards = bls_scalar::generate_plaintext_cards();
    assert_eq!(cards.length(), 52);
}

#[test]
fun base_h_not_identity() {
    let h = bls_scalar::base_h();
    assert!(!bls_scalar::g1_is_identity(&h));
}

#[test]
fun u64_to_ascii_works() {
    assert_eq!(bls_scalar::u64_to_ascii(0), vector[48]);
    assert_eq!(bls_scalar::u64_to_ascii(10), vector[49, 48]);
    assert_eq!(bls_scalar::u64_to_ascii(255), vector[50, 53, 53]);
}

#[test]
fun g1_equal_symmetric() {
    let a = bls12381::g1_generator();
    let b = bls_scalar::base_h();
    assert_eq!(bls_scalar::g1_equal(&a, &b), bls_scalar::g1_equal(&b, &a));
}

#[test]
fun scalar_neg_double_cancel() {
    let a = bls_scalar::scalar_from_u64(42);
    let neg_a = bls_scalar::scalar_neg(&a);
    let neg_neg_a = bls_scalar::scalar_neg(&neg_a);
    assert_eq!(bls_scalar::scalar_to_bytes(&neg_neg_a), bls_scalar::scalar_to_bytes(&a));
}

#[test]
fun derive_scalar_from_card_and_sk_deterministic() {
    let c1_sk = b"c1_sk_data";
    let c2_sk = b"c2_sk_data";
    let s1 = bls_scalar::derive_scalar_from_card_and_sk(&c1_sk, &c2_sk);
    let s2 = bls_scalar::derive_scalar_from_card_and_sk(&c1_sk, &c2_sk);
    assert_eq!(bls_scalar::scalar_to_bytes(&s1), bls_scalar::scalar_to_bytes(&s2));
}
