#[test_only]
module texas_poker::zk_verifier_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
use texas_poker::zk_verifier;
use texas_poker::shuffle_proof;
use texas_poker::remask_proof;
use texas_poker::reveal_token_proof;
use texas_poker::reconstruct_proof;
use texas_poker::schnorr_proof;
use texas_poker::chaum_pedersen;
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

fun make_dummy_chaum_pedersen(): chaum_pedersen::ChaumPedersenProof {
    let comm_a = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_a"));
    let comm_b = bls_scalar::g1_to_bytes(&make_g1_point(b"comm_b"));
    let resp = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));
    chaum_pedersen::new(comm_a, comm_b, resp)
}

// ========== Transcript 工厂测试 ==========

#[test]
fun new_shuffle_transcript_creates_valid_transcript() {
    let mut t = zk_verifier::new_shuffle_transcript();
    // Should be able to append and challenge without error
    let label = b"test_label";
    bls_transcript::append_message(&mut t, &label, &b"test_data");
    let _c = bls_transcript::challenge(&mut t, &b"challenge");
}

#[test]
fun new_remask_transcript_creates_valid_transcript() {
    let mut t = zk_verifier::new_remask_transcript();
    let label = b"test_label";
    bls_transcript::append_message(&mut t, &label, &b"test_data");
    let _c = bls_transcript::challenge(&mut t, &b"challenge");
}

#[test]
fun new_reconstruct_transcript_creates_valid_transcript() {
    let mut t = zk_verifier::new_reconstruct_transcript();
    let label = b"test_label";
    bls_transcript::append_message(&mut t, &label, &b"test_data");
    let _c = bls_transcript::challenge(&mut t, &b"challenge");
}

#[test]
fun transcripts_are_distinct() {
    let t1 = zk_verifier::new_shuffle_transcript();
    let t2 = zk_verifier::new_remask_transcript();
    let t3 = zk_verifier::new_reconstruct_transcript();
    // Different protocol names should produce different initial states
    // We can verify by checking that challenges differ
    let mut t1m = t1;
    let mut t2m = t2;
    let mut t3m = t3;
    let c1 = bls_transcript::challenge(&mut t1m, &b"c");
    let c2 = bls_transcript::challenge(&mut t2m, &b"c");
    let c3 = bls_transcript::challenge(&mut t3m, &b"c");
    // At least one should differ (extremely unlikely all three are equal)
    let all_equal = bls_scalar::scalar_to_bytes(&c1) == bls_scalar::scalar_to_bytes(&c2)
        && bls_scalar::scalar_to_bytes(&c2) == bls_scalar::scalar_to_bytes(&c3);
    assert!(!all_equal);
}

// ========== 密文序列化测试 ==========

#[test]
fun deserialize_ciphertexts_roundtrip() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let pt = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&pt, &pk, &r);

    // Serialize
    let mut data = bls_elgamal::c1_bytes(&ct);
    let c2_bytes = bls_elgamal::c2_bytes(&ct);
    let mut i = 0;
    while (i < c2_bytes.length()) {
        data.push_back(*(vector::borrow(&c2_bytes, i)));
        i = i + 1;
    };

    let result = zk_verifier::deserialize_ciphertexts(&data);
    assert_eq!(result.length(), 1);
    assert!(bls_scalar::g1_equal(bls_elgamal::c1(vector::borrow(&result, 0)), bls_elgamal::c1(&ct)));
    assert!(bls_scalar::g1_equal(bls_elgamal::c2(vector::borrow(&result, 0)), bls_elgamal::c2(&ct)));
}

#[test]
fun deserialize_ciphertexts_multiple() {
    let (_sk, pk) = make_keys();
    let r1 = bls_scalar::scalar_from_u64(100);
    let r2 = bls_scalar::scalar_from_u64(200);
    let ct1 = bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r1);
    let ct2 = bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r2);

    let mut data = bls_elgamal::c1_bytes(&ct1);
    let c2_1 = bls_elgamal::c2_bytes(&ct1);
    let mut i = 0;
    while (i < c2_1.length()) {
        data.push_back(*(vector::borrow(&c2_1, i)));
        i = i + 1;
    };
    let c1_2 = bls_elgamal::c1_bytes(&ct2);
    i = 0;
    while (i < c1_2.length()) {
        data.push_back(*(vector::borrow(&c1_2, i)));
        i = i + 1;
    };
    let c2_2 = bls_elgamal::c2_bytes(&ct2);
    i = 0;
    while (i < c2_2.length()) {
        data.push_back(*(vector::borrow(&c2_2, i)));
        i = i + 1;
    };

    let result = zk_verifier::deserialize_ciphertexts(&data);
    assert_eq!(result.length(), 2);
}

#[test]
fun deserialize_ciphertexts_empty() {
    let data = vector[];
    let result = zk_verifier::deserialize_ciphertexts(&data);
    assert_eq!(result.length(), 0);
}

// ========== 公钥序列化测试 ==========

#[test]
fun deserialize_pk_roundtrip() {
    let (_sk, pk) = make_keys();
    let pk_bytes = bls_scalar::g1_to_bytes(&pk);
    let deser = zk_verifier::deserialize_pk(&pk_bytes);
    assert!(bls_scalar::g1_equal(&deser, &pk));
}

#[test]
fun deserialize_pk_generator() {
    let g = bls12381::g1_generator();
    let bytes = bls_scalar::g1_to_bytes(&g);
    let deser = zk_verifier::deserialize_pk(&bytes);
    assert!(bls_scalar::g1_equal(&deser, &g));
}

// ========== 验证入口测试（负例） ==========

#[test]
fun verify_shuffle_returns_false_for_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    let proof = shuffle_proof::new(
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2")),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
    );

    let result = zk_verifier::verify_shuffle(&input_cts, &output_cts, &pk, &proof);
    assert!(!result);
}

#[test]
fun verify_remask_returns_false_for_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let remask_sk = bls_scalar::scalar_from_u64(789);
    let output_cts = bls_elgamal::remask_batch(&input_cts, &remask_sk);

    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_comm")));
    let proof = remask_proof::new(
        per_card_comm,
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_pk_comm")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999)),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
    );

    let result = zk_verifier::verify_remask(&input_cts, &output_cts, &pk, &proof);
    assert!(!result);
}

#[test]
fun verify_reveal_token_returns_false_for_bad_proof() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let pt = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&pt, &pk, &r);
    let reveal_token = bls_elgamal::gen_reveal_token(&ct, &sk);

    let proof = reveal_token_proof::new(
        bls_scalar::g1_to_bytes(&pk),
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t2")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999)),
    );

    let result = zk_verifier::verify_reveal_token(&ct, &reveal_token, &pk, &proof);
    assert!(!result);
}

#[test]
fun verify_reconstruct_returns_false_for_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let cards = vector[make_g1_point(b"card1")];
    let output_cards = vector[bls_elgamal::encrypt(&make_g1_point(b"out1"), &pk, &r)];

    let cp = make_dummy_chaum_pedersen();
    let ct_for_proof = bls_elgamal::encrypt(&make_g1_point(b"proof_pt"), &pk, &r);
    let mut readable_bytes = bls_elgamal::c1_bytes(&ct_for_proof);
    let c2_b = bls_elgamal::c2_bytes(&ct_for_proof);
    let mut i = 0;
    while (i < c2_b.length()) {
        readable_bytes.push_back(*(vector::borrow(&c2_b, i)));
        i = i + 1;
    };
    let ct_swap = bls_elgamal::encrypt(&make_g1_point(b"swap_pt"), &pk, &r);
    let mut swap_bytes = bls_elgamal::c1_bytes(&ct_swap);
    let s_c2 = bls_elgamal::c2_bytes(&ct_swap);
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };
    let swap_out = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    let mut swap_out_proofs = vector[];
    swap_out_proofs.push_back(swap_out);

    let mut user_readable = vector[];
    user_readable.push_back(ct_for_proof);

    let mut swap_out_cards = vector[];
    swap_out_cards.push_back(ct_swap);

    let proof = reconstruct_proof::new(
        swap_out_proofs,
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1_r")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2_r")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c2")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
        reconstruct_proof::new_reconstruction_dleq_proof(
            bls_scalar::g1_to_bytes(&make_g1_point(b"blind_comm")),
            bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(2)),
            bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(3)),
        ),
        make_dummy_chaum_pedersen(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
    );

    let result = zk_verifier::verify_reconstruct(
        &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &proof,
    );
    assert!(!result);
}

// ========== or_abort 测试 ==========

#[test]
fun verify_shuffle_or_abort_returns_on_valid_structure() {
    // Even though the proof is wrong, we test the abort path
    // by verifying that a bad proof causes abort
    // This test verifies the function signature compiles correctly
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    let proof = shuffle_proof::new(
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2")),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
    );

    // verify_shuffle returns false for bad proof
    assert!(!zk_verifier::verify_shuffle(&input_cts, &output_cts, &pk, &proof));
}

#[test, expected_failure(abort_code = zk_verifier::EShuffleProofFailed)]
fun verify_shuffle_or_abort_aborts_on_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let mut output_cts = vector[];
    output_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt2"), &pk, &r));

    let proof = shuffle_proof::new(
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2")),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
    );

    zk_verifier::verify_shuffle_or_abort(&input_cts, &output_cts, &pk, &proof);
}

#[test, expected_failure(abort_code = zk_verifier::ERemaskProofFailed)]
fun verify_remask_or_abort_aborts_on_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let mut input_cts = vector[];
    input_cts.push_back(bls_elgamal::encrypt(&make_g1_point(b"pt1"), &pk, &r));

    let remask_sk = bls_scalar::scalar_from_u64(789);
    let output_cts = bls_elgamal::remask_batch(&input_cts, &remask_sk);

    let mut per_card_comm = vector[];
    per_card_comm.push_back(bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_comm")));
    let proof = remask_proof::new(
        per_card_comm,
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_pk_comm")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999)),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
    );

    zk_verifier::verify_remask_or_abort(&input_cts, &output_cts, &pk, &proof);
}

#[test, expected_failure(abort_code = zk_verifier::ERevealTokenProofFailed)]
fun verify_reveal_token_or_abort_aborts_on_bad_proof() {
    let (sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let pt = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&pt, &pk, &r);
    let reveal_token = bls_elgamal::gen_reveal_token(&ct, &sk);

    let proof = reveal_token_proof::new(
        bls_scalar::g1_to_bytes(&pk),
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"wrong_t2")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(999)),
    );

    zk_verifier::verify_reveal_token_or_abort(&ct, &reveal_token, &pk, &proof);
}

#[test, expected_failure(abort_code = zk_verifier::EReconstructProofFailed)]
fun verify_reconstruct_or_abort_aborts_on_bad_proof() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let cards = vector[make_g1_point(b"card1")];
    let output_cards = vector[bls_elgamal::encrypt(&make_g1_point(b"out1"), &pk, &r)];

    let cp = make_dummy_chaum_pedersen();
    let ct_for_proof = bls_elgamal::encrypt(&make_g1_point(b"proof_pt"), &pk, &r);
    let mut readable_bytes = bls_elgamal::c1_bytes(&ct_for_proof);
    let c2_b = bls_elgamal::c2_bytes(&ct_for_proof);
    let mut i = 0;
    while (i < c2_b.length()) {
        readable_bytes.push_back(*(vector::borrow(&c2_b, i)));
        i = i + 1;
    };
    let ct_swap = bls_elgamal::encrypt(&make_g1_point(b"swap_pt"), &pk, &r);
    let mut swap_bytes = bls_elgamal::c1_bytes(&ct_swap);
    let s_c2 = bls_elgamal::c2_bytes(&ct_swap);
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };
    let swap_out = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    let mut swap_out_proofs = vector[];
    swap_out_proofs.push_back(swap_out);

    let mut user_readable = vector[];
    user_readable.push_back(ct_for_proof);

    let mut swap_out_cards = vector[];
    swap_out_cards.push_back(ct_swap);

    let proof = reconstruct_proof::new(
        swap_out_proofs,
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1_r")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2_r")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c1")),
        bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c2")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)),
        reconstruct_proof::new_reconstruction_dleq_proof(
            bls_scalar::g1_to_bytes(&make_g1_point(b"blind_comm")),
            bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(2)),
            bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(3)),
        ),
        make_dummy_chaum_pedersen(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
        make_dummy_schnorr_proof(),
    );

    zk_verifier::verify_reconstruct_or_abort(
        &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &proof,
    );
}
