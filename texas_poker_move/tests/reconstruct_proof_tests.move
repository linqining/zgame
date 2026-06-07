#[test_only]
module texas_poker::reconstruct_proof_tests;

use sui::bls12381;
use sui::bls12381::G1;
use sui::group_ops;
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

// ========== ciphertext_from_bytes 测试 ==========

#[test]
fun ciphertext_from_bytes_roundtrip() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);
    let pt = make_g1_point(b"test_pt");
    let ct = bls_elgamal::encrypt(&pt, &pk, &r);

    // Serialize: c1_bytes || c2_bytes
    let mut data = bls_elgamal::c1_bytes(&ct);
    let c2_bytes = bls_elgamal::c2_bytes(&ct);
    let mut i = 0;
    while (i < c2_bytes.length()) {
        data.push_back(*(vector::borrow(&c2_bytes, i)));
        i = i + 1;
    };

    // Deserialize
    let deser = reconstruct_proof::ciphertext_from_bytes(&data);

    // Verify roundtrip
    assert!(bls_scalar::g1_equal(bls_elgamal::c1(&deser), bls_elgamal::c1(&ct)));
    assert!(bls_scalar::g1_equal(bls_elgamal::c2(&deser), bls_elgamal::c2(&ct)));
}

#[test]
fun ciphertext_from_bytes_with_generator() {
    // Use generator as c1 and base_h as c2
    let c1 = bls12381::g1_generator();
    let c2 = bls_scalar::base_h();
    let ct = bls_elgamal::new_ciphertext(c1, c2);

    let mut data = bls_scalar::g1_to_bytes(&c1);
    let c2_bytes = bls_scalar::g1_to_bytes(&c2);
    let mut i = 0;
    while (i < c2_bytes.length()) {
        data.push_back(*(vector::borrow(&c2_bytes, i)));
        i = i + 1;
    };

    let deser = reconstruct_proof::ciphertext_from_bytes(&data);
    assert!(bls_scalar::g1_equal(bls_elgamal::c1(&deser), &c1));
    assert!(bls_scalar::g1_equal(bls_elgamal::c2(&deser), &c2));
}

// ========== SwapOutCardProof 构造和访问器 ==========

#[test]
fun swap_out_card_proof_new_and_accessors() {
    let mut readable_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c1"));
    let r_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c2"));
    let mut i = 0;
    while (i < r_c2.length()) {
        readable_bytes.push_back(*(vector::borrow(&r_c2, i)));
        i = i + 1;
    };

    let mut swap_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c1"));
    let s_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c2"));
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };

    let cp = make_dummy_chaum_pedersen();
    let proof = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    assert_eq!(reconstruct_proof::user_readable_card(&proof).length(), 96);
    assert_eq!(reconstruct_proof::swap_out_card(&proof).length(), 96);
}

// ========== ReconstructionDLEQProof 构造和访问器 ==========

#[test]
fun reconstruction_dleq_proof_new_and_accessors() {
    let commitment = bls_scalar::g1_to_bytes(&make_g1_point(b"commitment"));
    let response = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42));
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(99));

    let proof = reconstruct_proof::new_reconstruction_dleq_proof(commitment, response, nonce);

    assert_eq!(*reconstruct_proof::commitment(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"commitment")));
    assert_eq!(*reconstruct_proof::response(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(42)));
    assert_eq!(*reconstruct_proof::nonce(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(99)));
}

// ========== ReconstructProof 构造和访问器 ==========

#[test]
fun reconstruct_proof_new_and_accessors() {
    let cp = make_dummy_chaum_pedersen();

    let mut readable_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c1"));
    let r_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c2"));
    let mut i = 0;
    while (i < r_c2.length()) {
        readable_bytes.push_back(*(vector::borrow(&r_c2, i)));
        i = i + 1;
    };

    let mut swap_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c1"));
    let s_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c2"));
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };

    let swap_out = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    let mut swap_out_proofs = vector[];
    swap_out_proofs.push_back(swap_out);

    let sum_c1_r = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1_r"));
    let sum_c2_r = bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2_r"));
    let swap_sum_c1 = bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c1"));
    let swap_sum_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"swap_c2"));
    let nonce = bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1));

    let blind_dleq = reconstruct_proof::new_reconstruction_dleq_proof(
        bls_scalar::g1_to_bytes(&make_g1_point(b"blind_comm")),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(2)),
        bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(3)),
    );

    let total_dleq = make_dummy_chaum_pedersen();
    let swap_combined = make_dummy_schnorr_proof();
    let sum_c1_schnorr = make_dummy_schnorr_proof();
    let sum_c2_schnorr = make_dummy_schnorr_proof();

    let proof = reconstruct_proof::new(
        swap_out_proofs,
        sum_c1_r,
        sum_c2_r,
        swap_sum_c1,
        swap_sum_c2,
        nonce,
        blind_dleq,
        total_dleq,
        swap_combined,
        sum_c1_schnorr,
        sum_c2_schnorr,
    );

    assert_eq!(reconstruct_proof::swap_out_proofs(&proof).length(), 1);
    assert_eq!(*reconstruct_proof::sum_c1_r_commit(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c1_r")));
    assert_eq!(*reconstruct_proof::sum_c2_r_commit(&proof), bls_scalar::g1_to_bytes(&make_g1_point(b"sum_c2_r")));
    assert_eq!(*reconstruct_proof::reconstruct_nonce(&proof), bls_scalar::scalar_to_bytes(&bls_scalar::scalar_from_u64(1)));
}

// ========== 验证边界条件测试 ==========

#[test]
fun verify_rejects_length_mismatch_readable() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // Create 1 swap_out_proof but 2 user_readable_cards
    let cp = make_dummy_chaum_pedersen();
    let mut readable_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c1"));
    let r_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c2"));
    let mut i = 0;
    while (i < r_c2.length()) {
        readable_bytes.push_back(*(vector::borrow(&r_c2, i)));
        i = i + 1;
    };
    let mut swap_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c1"));
    let s_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c2"));
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };
    let swap_out = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    let mut swap_out_proofs = vector[];
    swap_out_proofs.push_back(swap_out);

    let mut user_readable = vector[];
    user_readable.push_back(bls_elgamal::encrypt(&make_g1_point(b"ur1"), &pk, &r));
    user_readable.push_back(bls_elgamal::encrypt(&make_g1_point(b"ur2"), &pk, &r));

    let mut swap_out_cards = vector[];
    swap_out_cards.push_back(bls_elgamal::encrypt(&make_g1_point(b"so1"), &pk, &r));

    let cards = vector[make_g1_point(b"card1")];
    let output_cards = vector[bls_elgamal::encrypt(&make_g1_point(b"out1"), &pk, &r)];

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

    let mut t = bls_transcript::new(&b"test");
    let result = reconstruct_proof::verify(
        &proof, &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &mut t,
    );
    // n=1 swap_out_proofs but user_readable_cards.length=2 → mismatch
    assert!(!result);
}

#[test]
fun verify_rejects_length_mismatch_swap_out() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    let cp = make_dummy_chaum_pedersen();
    let mut readable_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c1"));
    let r_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"r_c2"));
    let mut i = 0;
    while (i < r_c2.length()) {
        readable_bytes.push_back(*(vector::borrow(&r_c2, i)));
        i = i + 1;
    };
    let mut swap_bytes = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c1"));
    let s_c2 = bls_scalar::g1_to_bytes(&make_g1_point(b"s_c2"));
    i = 0;
    while (i < s_c2.length()) {
        swap_bytes.push_back(*(vector::borrow(&s_c2, i)));
        i = i + 1;
    };
    let swap_out = reconstruct_proof::new_swap_out_card_proof(readable_bytes, swap_bytes, cp);

    let mut swap_out_proofs = vector[];
    swap_out_proofs.push_back(swap_out);

    let mut user_readable = vector[];
    user_readable.push_back(bls_elgamal::encrypt(&make_g1_point(b"ur1"), &pk, &r));

    // swap_out_cards has 2 but swap_out_proofs has 1 → mismatch
    let mut swap_out_cards = vector[];
    swap_out_cards.push_back(bls_elgamal::encrypt(&make_g1_point(b"so1"), &pk, &r));
    swap_out_cards.push_back(bls_elgamal::encrypt(&make_g1_point(b"so2"), &pk, &r));

    let cards = vector[make_g1_point(b"card1")];
    let output_cards = vector[bls_elgamal::encrypt(&make_g1_point(b"out1"), &pk, &r)];

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

    let mut t = bls_transcript::new(&b"test");
    let result = reconstruct_proof::verify(
        &proof, &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &mut t,
    );
    assert!(!result);
}

#[test]
fun verify_rejects_deserialized_readable_mismatch() {
    let (_sk, pk) = make_keys();
    let r = bls_scalar::scalar_from_u64(456);

    // swap_out_proof contains bytes for one ciphertext, but user_readable_cards has a different one
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

    // Different user_readable_card than what's in the proof
    let mut user_readable = vector[];
    user_readable.push_back(bls_elgamal::encrypt(&make_g1_point(b"different_pt"), &pk, &r));

    let mut swap_out_cards = vector[];
    swap_out_cards.push_back(ct_swap);

    let cards = vector[make_g1_point(b"card1")];
    let output_cards = vector[bls_elgamal::encrypt(&make_g1_point(b"out1"), &pk, &r)];

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

    let mut t = bls_transcript::new(&b"test");
    let result = reconstruct_proof::verify(
        &proof, &cards, &output_cards, &swap_out_cards, &user_readable, &pk, &mut t,
    );
    // Deserialized readable card != user_readable_cards[0] → should reject
    assert!(!result);
}
