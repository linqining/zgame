#[test_only]
module texas_poker::bls_elgamal_tests;

use sui::bls12381;
use sui::bls12381::Scalar;
use sui::group_ops;
use texas_poker::bls_elgamal;
use texas_poker::bls_scalar;
use std::unit_test::assert_eq;

// ========== 辅助函数 ==========

fun make_keys(): (group_ops::Element<Scalar>, group_ops::Element<bls12381::G1>) {
    let sk = bls_scalar::scalar_from_u64(123);
    let pk = bls12381::g1_mul(&sk, &bls12381::g1_generator());
    (sk, pk)
}

// ========== 测试用例 ==========

#[test]
fun encrypt_and_decrypt_roundtrip() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = bls12381::hash_to_g1(&b"test_plaintext");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);
    let decrypted = bls_elgamal::decrypt(&ct, &sk);
    assert!(bls_scalar::g1_equal(&decrypted, &plaintext));
}

#[test]
fun re_encrypt_changes_ciphertext() {
    let (_sk, pk) = make_keys();
    let r1 = bls_scalar::scalar_from_u64(100);
    let plaintext = bls12381::hash_to_g1(&b"test_re_encrypt");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r1);

    let r2 = bls_scalar::scalar_from_u64(200);
    let ct2 = bls_elgamal::re_encrypt(&ct, &pk, &r2);

    // c1 and c2 should both change after re-encryption
    assert!(!bls_scalar::g1_equal(bls_elgamal::c1(&ct), bls_elgamal::c1(&ct2)));
    assert!(!bls_scalar::g1_equal(bls_elgamal::c2(&ct), bls_elgamal::c2(&ct2)));
}

#[test]
fun re_encrypt_decrypt_roundtrip() {
    let (sk, pk) = make_keys();
    let r1 = bls_scalar::scalar_from_u64(100);
    let plaintext = bls12381::hash_to_g1(&b"test_re_encrypt_decrypt");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r1);

    let r2 = bls_scalar::scalar_from_u64(200);
    let ct2 = bls_elgamal::re_encrypt(&ct, &pk, &r2);

    let decrypted = bls_elgamal::decrypt(&ct2, &sk);
    assert!(bls_scalar::g1_equal(&decrypted, &plaintext));
}

#[test]
fun gen_reveal_token_works() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = bls12381::hash_to_g1(&b"test_reveal_token");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);

    let token = bls_elgamal::gen_reveal_token(&ct, &sk);
    let expected = bls12381::g1_mul(&sk, bls_elgamal::c1(&ct));
    assert!(bls_scalar::g1_equal(&token, &expected));
}

#[test]
fun remask_changes_c2_only() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = bls12381::hash_to_g1(&b"test_remask");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);

    let remask_sk = bls_scalar::scalar_from_u64(789);
    let ct2 = bls_elgamal::remask(&ct, &remask_sk);

    // c1 should be unchanged
    assert!(bls_scalar::g1_equal(bls_elgamal::c1(&ct), bls_elgamal::c1(&ct2)));
    // c2 should be different
    assert!(!bls_scalar::g1_equal(bls_elgamal::c2(&ct), bls_elgamal::c2(&ct2)));
}

#[test, expected_failure(abort_code = bls_elgamal::EC1IsIdentity)]
fun remask_abort_on_identity_c1() {
    let placeholder = bls_elgamal::new_placeholder_card();
    let sk = bls_scalar::scalar_from_u64(999);
    let _ct = bls_elgamal::remask(&placeholder, &sk);
}

#[test]
fun is_valid_rejects_identity() {
    let placeholder = bls_elgamal::new_placeholder_card();
    assert!(!bls_elgamal::is_valid(&placeholder));
}

#[test]
fun is_valid_accepts_real_ciphertext() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let plaintext = bls12381::hash_to_g1(&b"test_valid");
    let ct = bls_elgamal::encrypt(&plaintext, &pk, &r);
    assert!(bls_elgamal::is_valid(&ct));
}

#[test]
fun encrypt_batch_produces_correct_count() {
    let (_sk, pk) = make_keys();
    let mut plaintexts = vector[];
    let mut randoms = vector[];
    let mut i = 0;
    while (i < 3) {
        plaintexts.push_back(bls12381::hash_to_g1(&b"batch_pt"));
        randoms.push_back(bls_scalar::scalar_from_u64(100 + i));
        i = i + 1;
    };
    let cts = bls_elgamal::encrypt_batch(&plaintexts, &pk, &randoms);
    assert_eq!(cts.length(), 3);
}

#[test]
fun remask_batch_correct_count() {
    let (_sk, pk) = make_keys();
    let mut plaintexts = vector[];
    let mut randoms = vector[];
    let mut i = 0;
    while (i < 3) {
        plaintexts.push_back(bls12381::hash_to_g1(&b"remask_batch_pt"));
        randoms.push_back(bls_scalar::scalar_from_u64(200 + i));
        i = i + 1;
    };
    let cts = bls_elgamal::encrypt_batch(&plaintexts, &pk, &randoms);
    let remask_sk = bls_scalar::scalar_from_u64(789);
    let remasked = bls_elgamal::remask_batch(&cts, &remask_sk);
    assert_eq!(remasked.length(), 3);
}

#[test]
fun extract_c1s_c2s_correct() {
    let (_sk, pk) = make_keys();
    let mut plaintexts = vector[];
    let mut randoms = vector[];
    let mut i = 0;
    while (i < 2) {
        plaintexts.push_back(bls12381::hash_to_g1(&b"extract_pt"));
        randoms.push_back(bls_scalar::scalar_from_u64(300 + i));
        i = i + 1;
    };
    let cts = bls_elgamal::encrypt_batch(&plaintexts, &pk, &randoms);
    let c1s = bls_elgamal::extract_c1s(&cts);
    let c2s = bls_elgamal::extract_c2s(&cts);
    assert_eq!(c1s.length(), 2);
    assert_eq!(c2s.length(), 2);
}

#[test]
fun new_ciphertext_roundtrip() {
    let pt1 = bls12381::hash_to_g1(&b"c1_value");
    let pt2 = bls12381::hash_to_g1(&b"c2_value");
    let ct = bls_elgamal::new_ciphertext(pt1, pt2);
    assert!(bls_scalar::g1_equal(bls_elgamal::c1(&ct), &pt1));
    assert!(bls_scalar::g1_equal(bls_elgamal::c2(&ct), &pt2));
}
