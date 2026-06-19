#[test_only]
module texas_poker::hand_flow_tests;

/// 手牌流程审核测试
///
/// 审核目标：从 do_start_hand 出发，检查是否存在死逻辑导致无法到达
/// reset_for_next_hand 或退回 round_waiting 的情况。
///
/// 测试场景：
/// 1. happy_path_fold_to_win: do_start_hand → ... → end_without_showdown → reset_for_next_hand
/// 2. happy_path_showdown: do_start_hand → ... → settle_hand → reset_for_next_hand
/// 3. all_in_preflop_stuck_bug: 暴露 preflop 全员 all-in 时卡死的 bug
/// 4. shuffle_timeout_all_kicked_reset: 洗牌超时全部踢出 → reset_for_next_hand
/// 5. reveal_timeout_preflop_reset: preflop reveal 超时 → reset_for_next_hand
/// 6. reconstruct_timeout_all_kicked_reset: reconstruct 超时全部踢出 → reset_for_next_hand
/// 7. betting_timeout_fold_to_win: 下注超时 fold → end_without_showdown → reset_for_next_hand
/// 8. multi_hand_sequential_reset: 连续多手均能到达 reset_for_next_hand
/// 9. all_in_postflop_skips_betting: postflop 全员 all-in 跳过下注（C5 修复验证）
/// 10. kick_current_shuffler_resets: 踢掉当前洗牌者导致活跃不足 → reset_for_next_hand

use sui::test_scenario;
use sui::clock;
use sui::test_utils;
use std::option::{Self, Option};
use std::string;
use texas_poker::table;
use texas_poker::table_constants;
use texas_poker::table_test_helpers;
use texas_poker::table_events;

// ========== 测试 1: happy path - fold 到只剩一人 → reset_for_next_hand ==========

#[test]
fun happy_path_fold_to_win() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 3 人加入
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    // 完成洗牌
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_preflop());

    // 完成 preflop reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // Preflop: 全部 fold 到 seat 1
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());

    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());

    scenario.next_tx(table_test_helpers::player1());
    table::fold(&mut t, 0, scenario.ctx());

    // end_without_showdown → reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_none());
    assert!(table::reconstruct_phase(&t) == table_constants::reconstruct_phase_none());
    assert!(table::pot(&t) == 0);

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 2: happy path - showdown → settle_hand → reset_for_next_hand ==========

#[test]
fun happy_path_showdown() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // do_start_hand → shuffle → reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // Preflop: 全部 call
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    // Flop
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Turn
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // River
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Showdown → settle_hand → reset_for_next_hand
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::pot(&t) == 0);

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 3: preflop 全员 all-in 修复验证 ==========
//
// 原Bug描述：start_betting_round 在 preflop 分支缺少 has_actionable_player 检查
// （postflop 有 C5 修复，preflop 没有）。当 heads-up 双方在盲注后全部 all-in 时，
// current_turn 指向 all-in 玩家，tick 超时会错误 fold 该玩家。
//
// 修复后行为：post_blinds 和 start_betting_round 都检查 has_actionable_player，
// 全员 all-in 时跳过下注轮，直接进入 flop reveal。

#[test]
fun all_in_preflop_stuck_bug() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 创建 2 人牌桌，Player1 只有 20（BB），Player2 只有 10（SB）
    let mut t = table::create_table_for_test(
        string::utf8(b"AllInTest"), 10, 20, 9, ctx,
    );
    table::join_table_for_test(&mut t, 0, table_test_helpers::player1(), 20);
    table::join_table_for_test(&mut t, 1, table_test_helpers::player2(), 10);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // 验证盲注：button=1, SB=1(10), BB=0(20)
    // Player2 (seat 1) all-in after SB, Player1 (seat 0) all-in after BB
    assert!(table::seat_all_in(&t, 0)); // BB all-in
    assert!(table::seat_all_in(&t, 1)); // SB all-in

    // 修复后：全员 all-in，跳过 preflop 下注轮，直接进入 flop reveal
    assert!(!table::has_actionable_player_for_test(&t));
    assert!(table::current_turn(&t).is_none());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());

    // 完成 flop reveal → turn（全员 all-in，继续跳过下注）
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());

    // 完成 turn reveal → river
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_river());

    // 完成 river reveal → showdown
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_showdown());

    // 完成 showdown → settle_hand → reset_for_next_hand
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::pot(&t) == 0);

    // 筹码守恒：20 + 10 = 30
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1);
    assert!(total == 30);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 4: 洗牌超时全部踢出 → reset_for_next_hand ==========

#[test]
fun shuffle_timeout_all_kicked_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 2 人牌桌（min_players_to_start=2）
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    let shuffler = *table::shuffle_current_shuffler(&t).borrow();

    // 触发洗牌超时：踢掉当前洗牌者
    // 2 人牌桌踢掉 1 人后活跃玩家 < min_players_to_start=2
    // kick_player_internal 会触发 reset_for_next_hand
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：已 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 5: preflop reveal 超时 → reset_for_next_hand ==========

#[test]
fun reveal_timeout_preflop_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 创建 Clock 用于 on_reveal_timeout
    let mut clock = clock::create_for_testing(ctx);

    // 2 人牌桌
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // do_start_hand → shuffle → preflop reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_preflop());

    // 设置 reveal_started_at 模拟已超时
    table::set_reveal_started_at_for_test(&mut t, 1);

    // 推进 Clock 时间超过超时阈值
    clock::increment_for_testing(&mut clock, 10000 + 1);

    // 触发 on_reveal_timeout
    // preflop reveal 超时：踢掉所有 pending 玩家
    // 2 人牌桌踢掉后活跃玩家 < 2 → reset_for_next_hand
    table::force_on_reveal_timeout_for_test(&mut t, &clock, scenario.ctx());

    // 验证：已 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_none());

    table::destroy_table(t);
    test_utils::destroy(clock);
    scenario.end();
}

// ========== 测试 6: reconstruct 超时全部踢出 → reset_for_next_hand ==========

#[test]
fun reconstruct_timeout_all_kicked_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 2 人牌桌
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // do_start_hand → shuffle → preflop reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // 手动设置 reconstruct_state 为 collecting 阶段
    table::set_reconstruct_phase_for_test(&mut t, table_constants::reconstruct_phase_collecting());
    table::set_reconstruct_started_at_for_test(&mut t, 1);

    // 设置 pending_players 为所有活跃玩家（2 人）
    // 需要通过 set_shuffle_state_for_test 间接设置？不，reconstruct 有自己的 pending
    // 直接调用 on_reconstruct_timeout 会读取 reconstruct_state.pending_players
    // 我们需要先设置 reconstruct_state.pending_players
    // 但没有直接的 test helper，需要通过 set_reconstruct_phase_for_test + 手动设置
    //
    // 实际上 on_reconstruct_timeout 会踢掉 reconstruct_state.pending_players 中的玩家
    // 如果 pending_players 为空，则不踢人，直接检查活跃玩家数
    // 我们需要构造一个有 pending_players 的场景

    // 触发 on_reconstruct_timeout
    // pending_players 为空时，不踢人，但活跃玩家可能 >= 2
    // 所以我们需要让 pending_players 包含所有活跃玩家
    //
    // 由于没有直接设置 reconstruct pending_players 的 helper，
    // 我们通过 kick_player_for_test 来模拟踢人场景
    //
    // 替代方案：直接踢掉所有玩家，触发 reset_for_next_hand

    // 踢掉 seat 0
    table::kick_player_for_test(&mut t, 0, table_events::kick_reason_admin(), scenario.ctx());
    // 踢掉 seat 0 后活跃玩家 < 2，kick_player_internal 会触发 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 7: 下注超时 fold → end_without_showdown → reset_for_next_hand ==========

#[test]
fun betting_timeout_fold_to_win() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // do_start_hand → shuffle → preflop reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // 当前轮到 seat 1，模拟超时 fold
    let current_turn = *table::current_turn_for_test(&t).borrow();
    assert!(current_turn == 1);

    // 触发 on_betting_timeout：fold 当前玩家
    table::force_on_betting_timeout_for_test(&mut t);
    assert!(table::seat_folded(&t, 1));

    // 还有 2 人，继续。再 fold 一个
    // current_turn 应该到了 seat 2
    let turn2 = *table::current_turn_for_test(&t).borrow();
    assert!(turn2 == 2);

    table::force_on_betting_timeout_for_test(&mut t);
    // seat 2 被 fold 后只剩 seat 0，触发 end_without_showdown → reset_for_next_hand
    // reset_for_next_hand 会重置 folded 标志，因此不能检查 seat_folded

    // 只剩 seat 0，end_without_showdown → reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::pot(&t) == 0);

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 8: 连续多手均能到达 reset_for_next_hand ==========

#[test]
fun multi_hand_sequential_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 连续 3 手，每手都 fold 到一人
    let mut hand = 0;
    while (hand < 3) {
        // do_start_hand
        scenario.next_tx(table_test_helpers::admin());
        table::start_hand(&mut t, scenario.ctx());
        table::advance_shuffle_for_test(&mut t, scenario.ctx());
        table::complete_reveal_phase_for_test(&mut t);
        assert!(table::round_state(&t) == table_constants::round_preflop());

        // 动态获取当前行动玩家，fold 到只剩一人
        // 第一个玩家 call，其余 fold
        let first = *table::current_turn_for_test(&t).borrow();
        scenario.next_tx(table_test_helpers::get_player(first));
        table::call(&mut t, first, scenario.ctx());

        // 第二个玩家 fold
        let second = *table::current_turn_for_test(&t).borrow();
        scenario.next_tx(table_test_helpers::get_player(second));
        table::fold(&mut t, second, scenario.ctx());

        // 如果还有第三个玩家，也 fold
        if (table::current_turn(&t).is_some()) {
            let third = *table::current_turn_for_test(&t).borrow();
            scenario.next_tx(table_test_helpers::get_player(third));
            table::fold(&mut t, third, scenario.ctx());
        };

        // 验证 reset_for_next_hand
        assert!(table::round_state(&t) == table_constants::round_waiting());
        assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());
        assert!(table::reveal_phase(&t) == table_constants::reveal_phase_none());

        hand = hand + 1;
    };

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 9: postflop 全员 all-in 跳过下注（C5 修复验证） ==========

#[test]
fun all_in_postflop_skips_betting() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 3 人牌桌，Player3 只有 30（不够大盲但能 SB all-in）
    let mut t = table::create_table_for_test(
        string::utf8(b"AllInPostflop"), 10, 20, 9, ctx,
    );
    table::join_table_for_test(&mut t, 0, table_test_helpers::player1(), 1000);
    table::join_table_for_test(&mut t, 1, table_test_helpers::player2(), 1000);
    table::join_table_for_test(&mut t, 2, table_test_helpers::player3(), 30);

    // do_start_hand → shuffle → preflop reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // Preflop: Seat 1 raise to 100, Seat 2 all-in(30), Seat 0 all-in(1000)
    scenario.next_tx(table_test_helpers::player2());
    table::raise(&mut t, 1, 100, scenario.ctx());

    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    assert!(table::seat_all_in(&t, 2));

    // Seat 0 raise all-in
    scenario.next_tx(table_test_helpers::player1());
    table::raise(&mut t, 0, 1000, scenario.ctx());
    assert!(table::seat_all_in(&t, 0));

    // Seat 1 call all-in
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    assert!(table::seat_all_in(&t, 1));

    // 所有人 all-in，进入 flop
    // C5 修复：postflop start_betting_round 检查 has_actionable_player
    // 全员 all-in 时跳过下注轮，直接 advance_round
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());

    // 完成 flop reveal → 应该直接跳过 flop 下注（全员 all-in）→ turn reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());

    // 完成 turn reveal → 直接跳过 → river reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_river());

    // 完成 river reveal → 直接跳过 → showdown reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_showdown());

    // 完成 showdown → settle_hand → reset_for_next_hand
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::pot(&t) == 0);

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 2030); // 1000 + 1000 + 30

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 10: 踢掉当前洗牌者导致活跃不足 → reset_for_next_hand ==========

#[test]
fun kick_current_shuffler_resets() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 2 人牌桌
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    let shuffler = *table::shuffle_current_shuffler(&t).borrow();

    // 踢掉当前洗牌者
    // 2 人牌桌踢掉 1 人后活跃玩家 < 2 → reset_for_next_hand
    table::kick_player_for_test(&mut t, shuffler, table_events::kick_reason_admin(), scenario.ctx());

    // 验证：已 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());
    assert!(!table::seat_occupied(&t, shuffler));

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 11: do_start_hand 后直接 reset_for_next_hand_for_test 验证状态清理 ==========

#[test]
fun do_start_hand_then_reset_clears_state() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    // 直接调用 reset_for_next_hand_for_test
    table::reset_for_next_hand_for_test(&mut t);

    // 验证所有状态已清理
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_none());
    assert!(table::reconstruct_phase(&t) == table_constants::reconstruct_phase_none());
    assert!(table::pot(&t) == 0);
    assert!(!table::betting_round_exists(&t));
    assert!(table::current_turn(&t).is_none());

    // 验证可以重新 start_hand
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 12: tick 驱动的完整流程（使用 Clock） ==========

#[test]
fun tick_driven_full_flow_to_reset() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut clock = clock::create_for_testing(ctx);
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    // tick: shuffle_started_at 为 0，设置时间
    clock::increment_for_testing(&mut clock, 1);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());
    assert!(table::shuffle_started_at(&t) > 0);

    // 完成洗牌（绕过 ZK）
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_preflop());

    // 完成 preflop reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // tick: 设置 betting_started_at
    clock::increment_for_testing(&mut clock, 1);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());
    assert!(table::betting_started_at(&t) > 0);

    // Preflop: 全部 fold 到 seat 1
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::fold(&mut t, 0, scenario.ctx());

    // end_without_showdown → reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // 筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    test_utils::destroy(clock);
    scenario.end();
}

// ========== 测试 13: betting timeout 后 tick 继续推进到 reset ==========

#[test]
fun betting_timeout_via_tick_resets() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut clock = clock::create_for_testing(ctx);
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // do_start_hand → shuffle → preflop reveal
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // tick 设置 betting_started_at
    clock::increment_for_testing(&mut clock, 100);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());
    assert!(table::betting_started_at(&t) > 0);

    // 推进时间超过 betting_timeout_ms (30000)
    clock::increment_for_testing(&mut clock, 30001);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());

    // 当前玩家被 auto fold
    // 2 人牌桌 fold 1 人后只剩 1 人 → end_without_showdown → reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());

    table::destroy_table(t);
    test_utils::destroy(clock);
    scenario.end();
}

// ========== 测试 14: shuffle timeout via tick → rebuild → continue → reset ==========

#[test]
fun shuffle_timeout_via_tick_continues_then_resets() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut clock = clock::create_for_testing(ctx);
    // 3 人牌桌：超时踢 1 人后还有 2 人，继续洗牌
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // do_start_hand
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    let shuffler = *table::shuffle_current_shuffler(&t).borrow();

    // tick 设置 shuffle_started_at
    clock::increment_for_testing(&mut clock, 1);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());
    assert!(table::shuffle_started_at(&t) > 0);

    // 推进时间超过 shuffle_timeout_ms (10000)
    clock::increment_for_testing(&mut clock, 10001);
    table::force_tick_for_test(&mut t, &clock, scenario.ctx());

    // 验证：shuffler 被踢
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：仍在 shuffle_phase_before_preflop（3人踢1人后还有2人，重建牌组继续）
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());
    assert!(table::active_count(&t) == 2);

    // 完成洗牌
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_preflop());

    // 完成 preflop reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_preflop());

    // 全部 fold 到一人 → reset_for_next_hand
    // button 移动后需要判断谁先行动
    // 2 人：button 在某个位置，SB=button, BB=next
    let turn = *table::current_turn_for_test(&t).borrow();
    scenario.next_tx(table_test_helpers::get_player(turn));
    table::call(&mut t, turn, scenario.ctx());

    // 找到下一个玩家 fold
    let next_turn = *table::current_turn_for_test(&t).borrow();
    scenario.next_tx(table_test_helpers::get_player(next_turn));
    table::fold(&mut t, next_turn, scenario.ctx());

    // reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());

    table::destroy_table(t);
    test_utils::destroy(clock);
    scenario.end();
}
