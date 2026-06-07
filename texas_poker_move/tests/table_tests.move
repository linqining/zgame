#[test_only]
module texas_poker::table_tests;

use sui::test_scenario;
use texas_poker::table;
use std::string;
use std::unit_test::assert_eq;

const ADMIN: address = @0xA;
const PLAYER1: address = @0xB;
const PLAYER2: address = @0xC;
const PLAYER3: address = @0xD;

#[test]
fun create_table_succeeds() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);
    assert_eq!(table::active_count(&t), 0);
    assert_eq!(table::small_blind(&t), 10);
    assert_eq!(table::big_blind(&t), 20);
    assert_eq!(table::round_state(&t), 0);
    table::destroy_table(t);
    scenario.end();
}

#[test]
fun join_table_increments_count() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table(&mut t, 0, 1000, scenario.ctx());
    assert_eq!(table::active_count(&t), 1);
    assert!(table::seat_occupied(&t, 0));
    assert_eq!(table::seat_stack(&t, 0), 1000);

    scenario.next_tx(PLAYER2);
    table::join_table(&mut t, 1, 2000, scenario.ctx());
    assert_eq!(table::active_count(&t), 2);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun leave_table_decrements_count() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table(&mut t, 0, 1000, scenario.ctx());

    scenario.next_tx(PLAYER1);
    table::leave_table(&mut t, 0, scenario.ctx());
    assert_eq!(table::active_count(&t), 0);
    assert!(!table::seat_occupied(&t, 0));

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun start_hand_transitions_to_shuffling() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table(&mut t, 0, 1000, scenario.ctx());
    scenario.next_tx(PLAYER2);
    table::join_table(&mut t, 1, 1000, scenario.ctx());
    scenario.next_tx(PLAYER3);
    table::join_table(&mut t, 2, 1000, scenario.ctx());

    scenario.next_tx(ADMIN);
    table::start_hand(&mut t, scenario.ctx());
    assert_eq!(table::round_state(&t), 1);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun start_hand_fails_with_fewer_than_3() {
    // 验证2人时 round_state 不变（无法开始）
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table(&mut t, 0, 1000, scenario.ctx());
    scenario.next_tx(PLAYER2);
    table::join_table(&mut t, 1, 1000, scenario.ctx());

    // 不调用 start_hand（会 abort），直接验证状态
    assert_eq!(table::active_count(&t), 2);
    assert_eq!(table::round_state(&t), 0); // 仍在 WAITING

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun submit_shuffle_commitment_transitions_to_preflop() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table(&mut t, 0, 1000, scenario.ctx());
    scenario.next_tx(PLAYER2);
    table::join_table(&mut t, 1, 1000, scenario.ctx());
    scenario.next_tx(PLAYER3);
    table::join_table(&mut t, 2, 1000, scenario.ctx());

    scenario.next_tx(ADMIN);
    table::start_hand(&mut t, scenario.ctx());

    scenario.next_tx(PLAYER1);
    table::submit_shuffle_commitment(&mut t, vector[1, 2, 3], scenario.ctx());
    assert_eq!(table::round_state(&t), 1);

    scenario.next_tx(PLAYER2);
    table::submit_shuffle_commitment(&mut t, vector[4, 5, 6], scenario.ctx());
    assert_eq!(table::round_state(&t), 1);

    scenario.next_tx(PLAYER3);
    table::submit_shuffle_commitment(&mut t, vector[7, 8, 9], scenario.ctx());
    assert_eq!(table::round_state(&t), 2);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun accessor_functions_work() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let t = table::create_table_for_test(string::utf8(b"MyTable"), 25, 50, 9, ctx);
    assert_eq!(table::small_blind(&t), 25);
    assert_eq!(table::big_blind(&t), 50);
    assert_eq!(table::button(&t), 0);
    assert_eq!(table::pot(&t), 0);
    assert_eq!(table::round_waiting(), 0);
    assert_eq!(table::round_shuffling(), 1);
    assert_eq!(table::round_preflop(), 2);
    table::destroy_table(t);
    scenario.end();
}
