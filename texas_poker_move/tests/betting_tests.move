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

// ========== 补充: 边界情况测试 ==========

#[test]
fun process_fold_increments_actions() {
    let mut round = betting::new_preflop(100);
    let actions_before = betting::actions_taken(&round);
    betting::process_fold(&mut round);
    assert!(betting::actions_taken(&round) == actions_before + 1);
}

#[test]
fun process_call_exact_stack_all_in() {
    let mut round = betting::new_preflop(100);
    // stack exactly equals to_call
    let amount = betting::process_call(&mut round, 0, 100);
    assert!(amount == 100);
}

#[test]
fun multiple_raises_update_min_raise() {
    let mut round = betting::new_preflop(100); // BB=100, current=100, min_raise=100
    // First raise to 300
    let needed1 = betting::process_raise(&mut round, 300, 0, 0, 1000);
    assert!(needed1 == 300);
    assert!(betting::current_bet(&round) == 300);
    assert!(betting::min_raise(&round) == 200);
    // Second raise to 600 (raise_amount = 300 >= min_raise 200)
    let needed2 = betting::process_raise(&mut round, 600, 1, 300, 1000);
    assert!(needed2 == 300); // 600 - 300 (already bet)
    assert!(betting::current_bet(&round) == 600);
    assert!(betting::min_raise(&round) == 300);
}

#[test]
fun can_raise_requires_min_raise_above_call() {
    let round = betting::new_preflop(100);
    // stack=150, to_call=100, remaining=50 < min_raise=100
    assert!(!betting::can_raise(&round, 0, 150));
    // stack=250, to_call=100, remaining=150 >= min_raise=100
    assert!(betting::can_raise(&round, 0, 250));
}

#[test, expected_failure(abort_code = betting::ECannotCall)]
fun process_call_aborts_when_nothing_to_call() {
    let mut round = betting::new_postflop(100);
    betting::process_call(&mut round, 0, 1000);
}

#[test, expected_failure(abort_code = betting::EInvalidRaiseAmount)]
fun process_raise_aborts_when_below_min_raise() {
    let mut round = betting::new_preflop(100);
    // raise to 150, raise_amount=50 < min_raise=100
    betting::process_raise(&mut round, 150, 0, 0, 1000);
}

#[test]
fun last_raiser_seat_tracked() {
    let mut round = betting::new_preflop(100);
    betting::process_raise(&mut round, 300, 5, 0, 1000);
    let last = betting::last_raiser_seat(&round);
    assert!(last.is_some());
    assert!(*last.borrow() == 5);
}

#[test]
fun postflop_can_check_with_no_bet() {
    let round = betting::new_postflop(100);
    let actions = betting::available_actions(&round, 0, 1000);
    assert!((actions & betting::action_check()) != 0);
    assert!((actions & betting::action_call()) == 0);
}
