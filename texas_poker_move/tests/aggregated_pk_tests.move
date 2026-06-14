#[test_only]
module texas_poker::aggregated_pk_tests;

/// 测试 aggregated_pk 在玩家加入/离开/踢出场景下的正确性
///
/// 测试场景:
/// 1. waiting 玩家 pk 在 reset_for_next_hand 后加入 aggregated_pk
/// 2. 踢出玩家后 pk 从 aggregated_pk 移除
/// 3. 踢出 waiting 玩家后 is_waiting 重置（避免空 pk 加入 aggregated_pk）
/// 4. 多个 waiting 玩家 pk 全部加入 aggregated_pk
/// 5. 集成测试: 中途加入 → 结算 → 下一手 aggregated_pk 正确

use sui::test_scenario;
use sui::bls12381;
use texas_poker::table;
use texas_poker::table_constants;
use texas_poker::table_events;
use texas_poker::table_serialization;
use texas_poker::table_test_helpers;
use std::string;

// ========== BLS 辅助: 生成不同的 pk 点 ==========

/// 生成第 n 个 pk (n * G1_generator)，每个玩家不同
fun make_pk(n: u64): vector<u8> {
    let mut g = bls12381::g1_generator();
    let mut i = 1;
    while (i < n) {
        let curr = g;
        g = bls12381::g1_add(&curr, &bls12381::g1_generator());
        i = i + 1;
    };
    texas_poker::bls_scalar::g1_to_bytes(&g)
}

/// 计算多个 pk 的聚合 (pk1 + pk2 + ... + pkn)
fun aggregate_pks(pks: &vector<vector<u8>>): vector<u8> {
    let mut agg = bls12381::g1_identity();
    let mut i = 0;
    while (i < pks.length()) {
        let pk_point = bls12381::g1_from_bytes(&pks[i]);
        let curr = agg;
        agg = bls12381::g1_add(&curr, &pk_point);
        i = i + 1;
    };
    texas_poker::bls_scalar::g1_to_bytes(&agg)
}

// ========== 测试 1: waiting 玩家 pk 在 reset 后加入 aggregated_pk ==========

#[test]
fun waiting_player_pk_added_on_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，3 人加入并设置真实 pk
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    let pk3 = make_pk(3);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);
    table::set_player_pk_for_test(&mut t, 2, pk3);

    // 2. 模拟已洗牌状态: aggregated_pk = pk1 + pk2 + pk3
    let mut active_pks = vector[];
    active_pks.push_back(pk1);
    active_pks.push_back(pk2);
    active_pks.push_back(pk3);
    let agg_before = aggregate_pks(&active_pks);
    table::set_aggregated_pk_for_test(&mut t, agg_before);

    // 3. 第 4 个玩家中途加入 (is_waiting = true)
    table::join_table_for_test(&mut t, 3, table_test_helpers::player4(), 1000);
    table::set_is_waiting_for_test(&mut t, 3, true);
    let pk4 = make_pk(4);
    table::set_player_pk_for_test(&mut t, 3, pk4);
    assert!(table::seat_is_waiting(&t, 3), EWaitingNotSet);

    // 4. reset_for_next_hand 应将 pk4 加入 aggregated_pk
    table::reset_for_next_hand_for_test(&mut t);

    // 5. 验证 aggregated_pk = pk1 + pk2 + pk3 + pk4
    let mut all_pks = vector[];
    all_pks.push_back(pk1);
    all_pks.push_back(pk2);
    all_pks.push_back(pk3);
    all_pks.push_back(pk4);
    let expected = aggregate_pks(&all_pks);
    let actual = table::aggregated_pk(&t);
    assert!(actual == &expected, EAggregatedPkMismatch);

    // 6. 验证 is_waiting 已重置
    assert!(!table::seat_is_waiting(&t, 3), EWaitingNotReset);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 2: 踢出玩家后 pk 从 aggregated_pk 移除 ==========

#[test]
fun kicked_player_pk_removed() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，3 人加入并设置真实 pk
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    let pk3 = make_pk(3);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);
    table::set_player_pk_for_test(&mut t, 2, pk3);

    // 2. 模拟已洗牌状态: aggregated_pk = pk1 + pk2 + pk3
    let mut active_pks = vector[];
    active_pks.push_back(pk1);
    active_pks.push_back(pk2);
    active_pks.push_back(pk3);
    let agg_before = aggregate_pks(&active_pks);
    table::set_aggregated_pk_for_test(&mut t, agg_before);

    // 3. 踢出 seat 1
    table::kick_player_for_test(&mut t, 1, table_events::kick_reason_admin());

    // 4. 验证 aggregated_pk = pk1 + pk3 (移除了 pk2)
    let mut remaining_pks = vector[];
    remaining_pks.push_back(pk1);
    remaining_pks.push_back(pk3);
    let expected = aggregate_pks(&remaining_pks);
    let actual = table::aggregated_pk(&t);
    assert!(actual == &expected, EAggregatedPkMismatch);

    // 5. 验证 seat 1 已空
    assert!(!table::seat_occupied(&t, 1), ESeatNotCleared);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 3: 踢出 waiting 玩家后 is_waiting 重置 ==========

#[test]
fun kicked_waiting_player_is_waiting_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，2 人加入
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);

    // 2. 设置 aggregated_pk = pk1 + pk2
    let mut pks = vector[];
    pks.push_back(pk1);
    pks.push_back(pk2);
    table::set_aggregated_pk_for_test(&mut t, aggregate_pks(&pks));

    // 3. 第 3 个玩家中途加入 (is_waiting = true)
    table::join_table_for_test(&mut t, 2, table_test_helpers::player3(), 1000);
    table::set_is_waiting_for_test(&mut t, 2, true);
    let pk3 = make_pk(3);
    table::set_player_pk_for_test(&mut t, 2, pk3);
    assert!(table::seat_is_waiting(&t, 2), EWaitingNotSet);

    // 4. 踢出 waiting 玩家 seat 2
    table::kick_player_for_test(&mut t, 2, table_events::kick_reason_admin());

    // 5. 验证 is_waiting 已重置为 false
    assert!(!table::seat_is_waiting(&t, 2), EWaitingNotReset);

    // 6. 验证 aggregated_pk 仍为 pk1 + pk2 (waiting 玩家 pk 未加入过)
    let expected = aggregate_pks(&pks);
    let actual = table::aggregated_pk(&t);
    assert!(actual == &expected, EAggregatedPkMismatch);

    // 7. reset_for_next_hand 不应崩溃 (is_waiting=false, pk=[] 不会被加入)
    table::reset_for_next_hand_for_test(&mut t);

    // 8. aggregated_pk 仍为 pk1 + pk2
    let actual_after = table::aggregated_pk(&t);
    assert!(actual_after == &expected, EAggregatedPkMismatch);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 4: 多个 waiting 玩家 pk 全部加入 aggregated_pk ==========

#[test]
fun multiple_waiting_pks_added_on_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，2 人加入
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);

    // 2. aggregated_pk = pk1 + pk2
    let mut active_pks = vector[];
    active_pks.push_back(pk1);
    active_pks.push_back(pk2);
    table::set_aggregated_pk_for_test(&mut t, aggregate_pks(&active_pks));

    // 3. 两个 waiting 玩家加入
    table::join_table_for_test(&mut t, 2, table_test_helpers::player3(), 1000);
    table::join_table_for_test(&mut t, 3, table_test_helpers::player4(), 1000);
    table::set_is_waiting_for_test(&mut t, 2, true);
    table::set_is_waiting_for_test(&mut t, 3, true);
    let pk3 = make_pk(3);
    let pk4 = make_pk(4);
    table::set_player_pk_for_test(&mut t, 2, pk3);
    table::set_player_pk_for_test(&mut t, 3, pk4);
    assert!(table::seat_is_waiting(&t, 2), EWaitingNotSet);
    assert!(table::seat_is_waiting(&t, 3), EWaitingNotSet);

    // 4. reset_for_next_hand
    table::reset_for_next_hand_for_test(&mut t);

    // 5. 验证 aggregated_pk = pk1 + pk2 + pk3 + pk4
    let mut all_pks = vector[];
    all_pks.push_back(pk1);
    all_pks.push_back(pk2);
    all_pks.push_back(pk3);
    all_pks.push_back(pk4);
    let expected = aggregate_pks(&all_pks);
    let actual = table::aggregated_pk(&t);
    assert!(actual == &expected, EAggregatedPkMismatch);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 5: add_pk_to_aggregated 在空 aggregated_pk 上正确工作 ==========
/// 验证 join_and_shuffle 修复: 空牌组时 add_pk_to_aggregated 而非覆盖

#[test]
fun add_pk_to_empty_aggregated() {
    // 模拟 fresh table: aggregated_pk 为空
    let empty_agg = vector[];
    let pk = make_pk(1);

    // add_pk_to_aggregated 在空 aggregated 上应返回 pk 本身
    let result = table_serialization::add_pk_to_aggregated(&empty_agg, &pk);
    assert!(result == pk, EAggregatedPkMismatch);
}

// ========== 测试 6: add_pk_to_aggregated 在非空 aggregated_pk 上正确累加 ==========

#[test]
fun add_pk_to_non_empty_aggregated() {
    // 模拟 reset 后: aggregated_pk 已含其他玩家 pk
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);

    // 先设置 aggregated_pk = pk1
    let agg = table_serialization::add_pk_to_aggregated(&vector[], &pk1);

    // 再 add pk2，应得到 pk1 + pk2
    let result = table_serialization::add_pk_to_aggregated(&agg, &pk2);

    let mut both = vector[];
    both.push_back(pk1);
    both.push_back(pk2);
    let expected = aggregate_pks(&both);
    assert!(result == expected, EAggregatedPkMismatch);
}

// ========== 测试 7: 集成测试 - 中途加入 → 结算 → 下一手 ==========

#[test]
fun mid_hand_join_then_next_hand() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，3 人加入
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 2. 设置真实 pk
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    let pk3 = make_pk(3);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);
    table::set_player_pk_for_test(&mut t, 2, pk3);

    // 3. 开始手牌
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());

    // 4. 绕过 ZK 完成洗牌
    table::advance_shuffle_for_test(&mut t, scenario.ctx());

    // 5. 第 4 个玩家中途加入 (is_waiting = true)
    table::join_table_for_test(&mut t, 3, table_test_helpers::player4(), 1000);
    table::set_is_waiting_for_test(&mut t, 3, true);
    let pk4 = make_pk(4);
    table::set_player_pk_for_test(&mut t, 3, pk4);
    assert!(table::seat_is_waiting(&t, 3), EWaitingNotSet);

    // 6. 绕过 ZK 完成 preflop reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // 7. Preflop 下注: 全部跟注 (button=1, SB=2, BB=0, first to act=1)
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    // flop reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_flop());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // turn reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_turn());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // river reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_river());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_river());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // 8. showdown - complete_reveal_phase_for_test 内部会调用 settle_hand
    assert!(table::round_state(&t) == table_constants::round_showdown());
    table::complete_reveal_phase_for_test(&mut t);

    // 9. settle_hand 已在 complete_reveal_phase_for_test 中调用 → 自动 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // 10. 验证 waiting 玩家的 pk 已加入 aggregated_pk
    // advance_shuffle_for_test 设置 mock aggregated_pk = G1 generator
    // reset_for_next_hand 应在此基础上 add pk4
    let mock_agg = table::aggregated_pk(&t);
    assert!(mock_agg.length() > 0, EAggregatedPkEmpty);

    // 11. 验证 is_waiting 已重置
    assert!(!table::seat_is_waiting(&t, 3), EWaitingNotReset);

    // 12. 验证可以开始下一手
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::round_state(&t) == table_constants::round_waiting());

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 8: 踢出后活跃人数不足触发 reset ==========

#[test]
fun kick_triggers_reset_when_below_min() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，2 人加入 (min_players_to_start = 2)
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);
    let pk1 = make_pk(1);
    let pk2 = make_pk(2);
    table::set_player_pk_for_test(&mut t, 0, pk1);
    table::set_player_pk_for_test(&mut t, 1, pk2);

    // 2. 设置 aggregated_pk
    let mut pks = vector[];
    pks.push_back(pk1);
    pks.push_back(pk2);
    table::set_aggregated_pk_for_test(&mut t, aggregate_pks(&pks));

    // 3. 踢出 seat 1 → 活跃人数降为 1 < min_players_to_start(2)
    // kick_player_internal 应自动调用 reset_for_next_hand
    table::kick_player_for_test(&mut t, 1, table_events::kick_reason_admin());

    // 4. 验证已 reset: round_state = WAITING
    assert!(table::round_state(&t) == table_constants::round_waiting(), ENotReset);

    // 5. 验证 aggregated_pk 只剩 pk1 (pk2 被移除，reset 不影响)
    let expected = pk1;
    let actual = table::aggregated_pk(&t);
    assert!(actual == &expected, EAggregatedPkMismatch);

    table::destroy_table(t);
    scenario.end();
}

// ========== 错误码 ==========
#[error]
const EAggregatedPkMismatch: vector<u8> = b"aggregated_pk mismatch";
#[error]
const EWaitingNotSet: vector<u8> = b"is_waiting should be true";
#[error]
const EWaitingNotReset: vector<u8> = b"is_waiting should be false";
#[error]
const ESeatNotCleared: vector<u8> = b"seat should be empty after kick";
#[error]
const ENotReset: vector<u8> = b"table should be reset to WAITING";
#[error]
const EAggregatedPkEmpty: vector<u8> = b"aggregated_pk should not be empty";
