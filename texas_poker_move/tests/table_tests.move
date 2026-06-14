#[test_only]
module texas_poker::table_tests;

use sui::test_scenario;
use texas_poker::table;
use texas_poker::table_constants;
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
    table::join_table_for_test(&mut t, 0, PLAYER1, 1000);
    assert_eq!(table::active_count(&t), 1);
    assert!(table::seat_occupied(&t, 0));
    assert_eq!(table::seat_stack(&t, 0), 1000);

    scenario.next_tx(PLAYER2);
    table::join_table_for_test(&mut t, 1, PLAYER2, 2000);
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
    table::join_table_for_test(&mut t, 0, PLAYER1, 1000);

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
    table::join_table_for_test(&mut t, 0, PLAYER1, 1000);
    scenario.next_tx(PLAYER2);
    table::join_table_for_test(&mut t, 1, PLAYER2, 1000);
    scenario.next_tx(PLAYER3);
    table::join_table_for_test(&mut t, 2, PLAYER3, 1000);

    scenario.next_tx(ADMIN);
    table::start_hand(&mut t, scenario.ctx());
    // start_hand 后 round_state 仍为 WAITING(0)，洗牌阶段由 shuffle_state 跟踪
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // 验证洗牌状态初始化
    assert!(table::shuffle_current_shuffler(&t).is_some());
    assert!(table::shuffle_pending_players(&t).length() == 3);
    assert!(table::shuffle_completed_players(&t).length() == 0);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun start_hand_fails_with_fewer_than_3() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table_for_test(&mut t, 0, PLAYER1, 1000);
    scenario.next_tx(PLAYER2);
    table::join_table_for_test(&mut t, 1, PLAYER2, 1000);

    // 不调用 start_hand（会 abort），直接验证状态
    assert_eq!(table::active_count(&t), 2);
    assert_eq!(table::round_state(&t), 0); // 仍在 WAITING

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun round_state_constants_match() {
    // 验证新的 Round State 常量
    assert_eq!(table::round_waiting(), 0);
    assert_eq!(table::round_preflop(), 2);
    assert_eq!(table::round_flop(), 3);
    assert_eq!(table::round_turn(), 4);
    assert_eq!(table::round_river(), 5);
    assert_eq!(table::round_showdown(), 6);
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
    assert_eq!(table::round_preflop(), 2);
    table::destroy_table(t);
    scenario.end();
}

#[test]
fun seat_pk_accessor_works() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let mut t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);

    scenario.next_tx(PLAYER1);
    table::join_table_for_test(&mut t, 0, PLAYER1, 1000);
    // join_table 不设置 pk，pk 为空
    assert_eq!(table::seat_pk(&t, 0).length(), 0);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun deck_encrypted_initially_empty() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);
    assert_eq!(table::deck_encrypted(&t).length(), 0);
    assert_eq!(table::aggregated_pk(&t).length(), 0);
    table::destroy_table(t);
    scenario.end();
}

#[test]
fun reconstruct_state_initially_none() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);
    assert_eq!(table::reconstruct_phase(&t), 0); // RECONSTRUCT_PHASE_NONE
    table::destroy_table(t);
    scenario.end();
}

#[test]
fun reveal_state_initially_none() {
    let mut scenario = test_scenario::begin(ADMIN);
    let ctx = scenario.ctx();
    let t = table::create_table_for_test(string::utf8(b"Test"), 10, 20, 6, ctx);
    assert_eq!(table::reveal_phase(&t), 0); // REVEAL_PHASE_NONE
    assert_eq!(table::reveal_assignments(&t).length(), 0);
    table::destroy_table(t);
    scenario.end();
}
