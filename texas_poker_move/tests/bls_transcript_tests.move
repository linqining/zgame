#[test_only]
module texas_poker::bls_transcript_tests;

use texas_poker::bls_transcript;
use texas_poker::bls_scalar;
use sui::bls12381;
use sui::group_ops;
use std::unit_test::assert_eq;

#[test]
fun new_creates_transcript_with_state() {
    let t = bls_transcript::new(&b"test_protocol");
    let s = bls_transcript::state(&t);
    assert_eq!(s.length(), 32);
}

#[test]
fun append_message_changes_state() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let state_before = *bls_transcript::state(&t);
    bls_transcript::append_message(&mut t, &b"label", &b"hello");
    let state_after = *bls_transcript::state(&t);
    assert_eq!(state_before == state_after, false);
}

#[test]
fun append_point_changes_state() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let state_before = *bls_transcript::state(&t);
    let point = bls12381::g1_generator();
    bls_transcript::append_point(&mut t, &b"point_label", &point);
    let state_after = *bls_transcript::state(&t);
    assert_eq!(state_before == state_after, false);
}

#[test]
fun append_scalar_changes_state() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let state_before = *bls_transcript::state(&t);
    let scalar = bls_scalar::scalar_one();
    bls_transcript::append_scalar(&mut t, &b"scalar_label", &scalar);
    let state_after = *bls_transcript::state(&t);
    assert_eq!(state_before == state_after, false);
}

#[test]
fun challenge_produces_scalar() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let c = bls_transcript::challenge(&mut t, &b"challenge_label");
    let zero = bls_scalar::scalar_zero();
    assert_eq!(group_ops::equal(&c, &zero), false);
}

#[test]
fun challenge_vec_produces_n_scalars() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let challenges = bls_transcript::challenge_vec(&mut t, &b"batch_label", 5);
    assert_eq!(challenges.length(), 5);
}

#[test]
fun different_labels_different_challenges() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let c1 = bls_transcript::challenge(&mut t, &b"label_a");
    let c2 = bls_transcript::challenge(&mut t, &b"label_b");
    assert_eq!(group_ops::equal(&c1, &c2), false);
}

#[test]
fun sequential_challenges_differ() {
    let mut t = bls_transcript::new(&b"test_protocol");
    let c1 = bls_transcript::challenge(&mut t, &b"same_label");
    let c2 = bls_transcript::challenge(&mut t, &b"same_label");
    assert_eq!(group_ops::equal(&c1, &c2), false);
}
