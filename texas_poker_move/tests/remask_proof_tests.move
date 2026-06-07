#[test_only]
module texas_poker::remask_proof_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::remask_proof;
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

// ========== 构造函数和访问器测试 ==========

#[test]
fun new_and_accessors() {
    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm1")));
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm2")));
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk"));
    let resp = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(99));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    assert_eq!(remask_proof::per_card_commitments(&proof).length(), 2);
    assert_eq!(*remask_proof::commitment_pk(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk")));
    assert_eq!(*remask_proof::response(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42)));
    assert_eq!(*remask_proof::nonce(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(99)));
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_length_mismatch_input() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // Create 2 input ciphertexts
    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    // Create 2 output ciphertexts
    let remask_sk = bls_scalar::scalar_from_u64(789);
    let output_cts = bls_elgamal::remask_batch(&input_cts, &remask_sk);

    // But proof has 1 per_card_commitment → length mismatch
    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm1")));
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk"));
    let resp = bls_scalar::scalar_to_bytes(&sk);
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    let mut t = bls_transcript::new(&b"test");
    let result = remask_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_length_mismatch_output() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // Create 2 input ciphertexts
    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    // Create only 1 output ciphertext → length mismatch with input
    let remask_sk = bls_scalar::scalar_from_u64(789);
    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::remask(vector::borrow(&input_cts, 0), &remask_sk));

    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm1")));
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm2")));
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk"));
    let resp = bls_scalar::scalar_to_bytes(&sk);
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    let mut t = bls_transcript::new(&b"test");
    let result = remask_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_c1_changed() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // Create input ciphertext
    let input_ct = bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r);

    // Create output with different c1 (violates c1 invariance)
    let output_ct = bls_elgamal::new_ciphertext(
        make_g1_point(b"wrong_c1"),
        make_g1_point(b"wrong_c2"),
    );

    let mut input_cts = vector[];
    input_cts.push_back(input_ct);
    let mut output_cts = vector[];
    output_cts.push_back(output_ct);

    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"comm1")));
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk"));
    let resp = bls_scalar::scalar_to_bytes(&sk);
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    let mut t = bls_transcript::new(&b"test");
    let result = remask_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    // c1 changed → should reject
    assert!(!result);
}

#[test]
fun verify_rejects_wrong_proof_data() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let remask_sk = bls_scalar::scalar_from_u64(789);
    let output_cts = bls_elgamal::remask_batch(&input_cts, &remask_sk);

    // Wrong proof data
    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_comm")));
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_pk_comm"));
    let resp = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999));
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    let mut t = bls_transcript::new(&b"test");
    let result = remask_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    assert!(!result);
}

#[test]
fun verify_rejects_empty_cards() {
    let (_sk, pk) = make_keys();

    let input_cts = vector[];
    let output_cts = vector[];

    let per_card_comm = vector[];
    let comm_pk = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_pk"));
    let resp = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let proof = remask_proof::new(per_card_comm, comm_pk, resp, nonce);

    let mut t = bls_transcript::new(&b"test");
    let result = remask_proof::verify(&proof, &input_cts, &output_cts, &pk, &mut t);
    // Empty cards → 0 per_card_commitments, 0 input_cts, 0 output_cts
    // Lengths match (all 0), no c1 invariance to check, no per-card DLEq to check
    // But pk DLEq will fail with wrong data
    assert!(!result);
}
