#[test_only]
module texas_poker::hand_evaluator_tests;

use texas_poker::card;
use texas_poker::hand_evaluator;
use std::unit_test::assert_eq;

// 辅助：构造7张牌
fun make7(
    s0: u8, r0: u8, s1: u8, r1: u8, s2: u8, r2: u8,
    s3: u8, r3: u8, s4: u8, r4: u8, s5: u8, r5: u8, s6: u8, r6: u8,
): vector<card::Card> {
    vector[
        card::new(s0, r0), card::new(s1, r1), card::new(s2, r2),
        card::new(s3, r3), card::new(s4, r4), card::new(s5, r5), card::new(s6, r6),
    ]
}

#[test]
fun royal_flush_beats_straight_flush() {
    let royal = make7(0,14, 0,13, 0,12, 0,11, 0,10, 1,2, 1,3);
    let sf = make7(1,13, 1,12, 1,11, 1,10, 1,9, 0,2, 0,3);
    let r1 = hand_evaluator::best_hand(&royal);
    let r2 = hand_evaluator::best_hand(&sf);
    assert_eq!(hand_evaluator::category(&r1), 9);
    assert_eq!(hand_evaluator::category(&r2), 8);
    assert_eq!(hand_evaluator::compare(&r1, &r2), 2);
}

#[test]
fun four_of_a_kind_detected() {
    let cards = make7(0,13, 1,13, 2,13, 3,13, 0,2, 1,2, 2,2);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 7);
}

#[test]
fun full_house_detected() {
    let cards = make7(0,14, 1,14, 2,14, 0,13, 1,13, 0,12, 1,12);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 6);
}

#[test]
fun flush_detected() {
    let cards = make7(0,14, 0,10, 0,8, 0,6, 0,4, 1,13, 1,12);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 5);
}

#[test]
fun straight_detected() {
    let cards = make7(0,10, 1,11, 2,12, 3,13, 0,14, 1,2, 2,3);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 4);
}

#[test]
fun wheel_straight_a2345_detected() {
    let cards = make7(0,14, 1,2, 2,3, 3,4, 0,5, 1,10, 2,11);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 4);
    let kickers = hand_evaluator::kickers(&hr);
    assert_eq!(kickers[0], 5);
}

#[test]
fun three_of_a_kind_detected() {
    let cards = make7(0,11, 1,11, 2,11, 0,8, 1,5, 2,3, 3,2);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 3);
}

#[test]
fun two_pair_detected() {
    let cards = make7(0,13, 1,13, 0,9, 1,9, 2,5, 3,3, 0,2);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 2);
}

#[test]
fun one_pair_detected() {
    let cards = make7(0,7, 1,7, 0,12, 1,10, 2,5, 3,3, 0,2);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 1);
}

#[test]
fun high_card_detected() {
    let cards = make7(0,14, 1,10, 2,8, 3,6, 0,4, 1,2, 2,11);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 0);
}

#[test]
fun compare_four_of_a_kind_by_kicker() {
    let cards1 = make7(0,13, 1,13, 2,13, 3,13, 0,2, 1,3, 2,4);
    let cards2 = make7(0,13, 1,13, 2,13, 3,13, 0,5, 1,6, 2,7);
    let h1 = hand_evaluator::best_hand(&cards1);
    let h2 = hand_evaluator::best_hand(&cards2);
    assert_eq!(hand_evaluator::compare(&h1, &h2), 0);
}

#[test]
fun best_hand_selects_best_5_from_7() {
    let cards = make7(0,14, 1,14, 2,14, 0,13, 1,13, 0,5, 1,6);
    let hr = hand_evaluator::best_hand(&cards);
    assert_eq!(hand_evaluator::category(&hr), 6);
}
