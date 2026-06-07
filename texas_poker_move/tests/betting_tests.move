#[test_only]
module texas_poker::betting_tests;

use texas_poker::betting;
use std::unit_test::assert_eq;

#[test]
fun new_preflop_sets_current_bet_to_big_blind() {
    let round = betting::new_preflop(100);
    assert_eq!(betting::current_bet(&round), 100);
    assert_eq!(betting::min_raise(&round), 100);
}

#[test]
fun new_postflop_starts_at_zero() {
    let round = betting::new_postflop(100);
    assert_eq!(betting::current_bet(&round), 0);
}

#[test]
fun can_check_when_no_bet() {
    let round = betting::new_postflop(100);
    assert!(betting::can_check(&round, 0));
    // seat_bet=50 > current_bet=0, chips_to_call=0, can still check
    assert!(betting::can_check(&round, 50));
    // preflop: current_bet=100, seat_bet=0, cannot check
    let preflop = betting::new_preflop(100);
    assert!(!betting::can_check(&preflop, 0));
    assert!(betting::can_check(&preflop, 100));
}

#[test]
fun can_call_when_bet_exists() {
    let round = betting::new_preflop(100);
    assert!(betting::can_call(&round, 0, 1000));
    assert!(!betting::can_call(&round, 100, 1000));
}

#[test]
fun process_call_returns_correct_amount() {
    let mut round = betting::new_preflop(100);
    let amount = betting::process_call(&mut round, 0, 1000);
    assert_eq!(amount, 100);
}

#[test]
fun process_call_all_in() {
    let mut round = betting::new_preflop(100);
    let amount = betting::process_call(&mut round, 0, 50);
    assert_eq!(amount, 50);
}

#[test]
fun process_raise_updates_state() {
    let mut round = betting::new_preflop(100);
    let needed = betting::process_raise(&mut round, 300, 0, 0, 1000);
    assert_eq!(needed, 300);
    assert_eq!(betting::current_bet(&round), 300);
    assert_eq!(betting::min_raise(&round), 200);
}

#[test]
fun process_check_succeeds_when_no_bet() {
    let mut round = betting::new_postflop(100);
    betting::process_check(&mut round, 0);
}

#[test, expected_failure(abort_code = betting::ECannotCheck)]
fun process_check_aborts_when_bet_exists() {
    let mut round = betting::new_preflop(100);
    betting::process_check(&mut round, 0);
}

#[test]
fun chips_to_call_works() {
    let round = betting::new_preflop(100);
    assert_eq!(betting::chips_to_call(&round, 0), 100);
    assert_eq!(betting::chips_to_call(&round, 50), 50);
    assert_eq!(betting::chips_to_call(&round, 100), 0);
}

#[test]
fun available_actions_includes_correct_options() {
    let round = betting::new_preflop(100);
    let actions = betting::available_actions(&round, 0, 1000);
    assert!((actions & betting::action_fold()) != 0);
    assert!((actions & betting::action_call()) != 0);
    assert!((actions & betting::action_raise()) != 0);
    assert!((actions & betting::action_check()) == 0);
}
