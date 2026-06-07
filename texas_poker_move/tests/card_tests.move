#[test_only]
module texas_poker::card_tests;

use texas_poker::card;
use std::unit_test::assert_eq;

#[test]
fun new_creates_valid_card() {
    let c = card::new(card::spades(), card::ace());
    assert_eq!(card::suit(&c), card::spades());
    assert_eq!(card::rank(&c), card::ace());
}

#[test]
fun is_valid_suit_works() {
    assert!(card::is_valid_suit(0));
    assert!(card::is_valid_suit(1));
    assert!(card::is_valid_suit(2));
    assert!(card::is_valid_suit(3));
    assert!(!card::is_valid_suit(4));
}

#[test]
fun is_valid_rank_works() {
    assert!(!card::is_valid_rank(1));
    assert!(card::is_valid_rank(2));
    assert!(card::is_valid_rank(14));
    assert!(!card::is_valid_rank(15));
}

#[test]
fun equals_works() {
    let a = card::new(card::hearts(), card::king());
    let b = card::new(card::hearts(), card::king());
    let c = card::new(card::hearts(), card::queen());
    assert!(card::equals(&a, &b));
    assert!(!card::equals(&a, &c));
}

#[test, expected_failure(abort_code = card::EInvalidSuit)]
fun new_rejects_invalid_suit() {
    let _c = card::new(5, card::ace());
}

#[test, expected_failure(abort_code = card::EInvalidRank)]
fun new_rejects_invalid_rank() {
    let _c = card::new(card::spades(), 1);
}
